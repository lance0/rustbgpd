//! rustbgpd — API-first BGP daemon
//!
//! Binary entry point. Loads config, wires components, starts runtime.

#![cfg_attr(
    not(any(feature = "jemalloc", feature = "dhat-heap")),
    deny(unsafe_code)
)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]

#[cfg(feature = "dhat-heap")]
#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

#[cfg(all(feature = "jemalloc", not(feature = "dhat-heap")))]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

mod bfd_runtime;
mod blackhole;
mod config;
mod config_persister;
mod config_transaction_control;
mod confirm_journal;
mod evpn_ack;
mod evpn_dataplane;
mod evpn_es_drain;
mod evpn_es_link_drain;
mod evpn_imet;
mod evpn_l3_originator;
mod evpn_originator;
mod evpn_plan_decomposer;
mod evpn_runtime_converger;
mod evpn_segment;
mod evpn_svi;
mod fib;
mod fib_common;
mod fib_runtime;
mod fib_table_control;
mod gnmi_set_bridge;
mod kernel_route_notify;
mod metrics_server;
mod peer_manager;
mod policy_admin;
mod reload;
#[cfg(test)]
mod test_support;

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{Read as _, Write as _};
use std::net::{Ipv4Addr, SocketAddr};
use std::os::unix::fs::DirBuilderExt as _;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};
use std::process;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant as StdInstant, SystemTime, UNIX_EPOCH};

use rustbgpd_mrt::codec::WarmSnapshotBudget;
use rustbgpd_mrt::{
    MAX_WARM_BUNDLE_SNAPSHOT_BYTES, WarmBundleDirectory, WarmBundleFamilyV1, WarmBundleIdentityV1,
    WarmBundlePolicyInputV1, WarmBundleViewKindV1, WarmBundleViewV1,
    resolved_import_policy_digest_v1, write_warm_bundle_bounded,
};
use rustbgpd_rib::{RibManager, RibUpdate, WarmMrtSnapshotBudget, WarmMrtSnapshotView};
use rustbgpd_telemetry::{BgpMetrics, init_logging};
use rustbgpd_transport::{
    BgpListener, ListenerSocketOptions, TcpAoAlgorithm, TcpAoConfig as TransportTcpAoConfig,
    TcpAoKeyring, TcpAoListenerKey, TcpAoListenerOwnerKind,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use tokio::sync::{broadcast, mpsc, oneshot, watch};
use tokio::task::JoinHandle;
use tracing::{error, info, warn};

use crate::config::{
    Config, GrpcAccessMode, GrpcEnforcementConfig, GrpcListener, GrpcMaxTier, GrpcRoleConfig,
};
use crate::config_persister::{ConfigMutation, ConfigPersister};
use crate::peer_manager::PeerManager;
use crate::reload::{
    apply_reload_outcome, reload_config_with_tcp_ao, run_config_bridge, runtime_config_snapshot,
};
use rustbgpd_api::health_probe::DaemonGate;
use rustbgpd_api::peer_types::{
    ImportValidationDependency, PeerManagerCommand, PeerManagerNeighborConfig,
    PeerManagerReadinessQuery, WarmCheckpointCapture, WarmCheckpointSession,
};
use rustbgpd_api::server::{
    AccessMode as GrpcServerAccessMode, ConfigMutationGateFn, ListenerConfig as GrpcListenerConfig,
    ListenerEndpoint, ServeConfig,
};
use rustbgpd_wire::{Afi, Safi};

const GR_RESTART_MARKER_V1: u8 = 1;
const GR_RESTART_MARKER_V2: u8 = 2;
const GR_RESTART_MARKER_V3: u8 = 3;
const GR_RESTART_MARKER_FILE: &str = "gr-restart.toml";
const WARM_BUNDLE_DIRECTORY: &str = "warm-bundle-v1";
const MAX_GR_RESTART_MARKER_BYTES: u64 = 4096;
const MAX_CHECKPOINT_GENERATION_BYTES: usize = 128;
const WARM_CHECKPOINT_DEADLINE: Duration = Duration::from_secs(30);
static MARKER_TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);
static WARM_CHECKPOINT_REVISION: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct ManagedNetdevMetricLabel {
    class: &'static str,
    name: String,
    desired: bool,
    state: &'static str,
}

fn update_managed_netdev_metrics(
    metrics: &BgpMetrics,
    previous: &mut BTreeSet<ManagedNetdevMetricLabel>,
    rows: &[rustbgpd_evpn::ManagedNetdevStatus],
) {
    let mut current = BTreeSet::new();
    for row in rows {
        let label = ManagedNetdevMetricLabel {
            class: row.class.as_str(),
            name: row.name.clone(),
            desired: row.desired,
            state: row.state.as_str(),
        };
        metrics.set_evpn_managed_netdev_state(
            label.class,
            &label.name,
            label.desired,
            label.state,
            1,
        );
        current.insert(label);
    }

    for stale in previous.difference(&current) {
        metrics.remove_evpn_managed_netdev_state(
            stale.class,
            &stale.name,
            stale.desired,
            stale.state,
        );
    }
    *previous = current;
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct GrRestartMarker {
    version: u8,
    expires_at_unix: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    checkpoint_generation: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    boot_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    time_namespace_dev: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    time_namespace_ino: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    boottime_offset_secs: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    boottime_offset_nanos: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    expires_at_boottime_ms: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct GrRestartClockSample {
    boot_id: String,
    time_namespace_dev: u64,
    time_namespace_ino: u64,
    boottime_offset_secs: i64,
    boottime_offset_nanos: u32,
    boottime_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct GrRestartClockDomain {
    boot_id: String,
    time_namespace_dev: u64,
    time_namespace_ino: u64,
    boottime_offset_secs: i64,
    boottime_offset_nanos: u32,
    expires_at_boottime_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ValidGrRestartMarker {
    version: u8,
    expires_at: SystemTime,
    /// Present for generation-bound marker v2 or v3. Checkpoint publication
    /// records this binding, but startup has no cache load or route-serving
    /// behavior.
    checkpoint_generation: Option<String>,
    clock_domain: Option<GrRestartClockDomain>,
    /// SHA-256 of the exact bounded bytes read from the pinned marker entry.
    /// `None` only for values validated directly in unit tests before storage.
    storage_sha256: Option<[u8; 32]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct GrRestartMarkerWriteOutcome {
    version: u8,
    checkpoint_generation: Option<String>,
    degraded_reason: Option<String>,
}

#[derive(Debug)]
struct GrRestartMarkerWriteError {
    error: std::io::Error,
    visible_outcome: Option<GrRestartMarkerWriteOutcome>,
}

impl std::fmt::Display for GrRestartMarkerWriteError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.error.fmt(formatter)
    }
}

impl std::error::Error for GrRestartMarkerWriteError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}

impl From<std::io::Error> for GrRestartMarkerWriteError {
    fn from(error: std::io::Error) -> Self {
        Self {
            error,
            visible_outcome: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GrRestartMarkerDurability {
    DirectorySynced,
    VisibleDirectorySyncUncertain,
}

impl GrRestartMarkerDurability {
    const fn as_str(self) -> &'static str {
        match self {
            Self::DirectorySynced => "directory_synced",
            Self::VisibleDirectorySyncUncertain => "visible_directory_sync_uncertain",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct VisibleGrRestartMarker {
    outcome: GrRestartMarkerWriteOutcome,
    durability: GrRestartMarkerDurability,
}

#[derive(Debug)]
struct GrRestartMarkerPublicationResult {
    visible: Option<VisibleGrRestartMarker>,
    initial_error: Option<GrRestartMarkerWriteError>,
    fallback_error: Option<GrRestartMarkerWriteError>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GrRestartExpiryAuthority {
    Boottime,
    Wall,
}

impl GrRestartExpiryAuthority {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Boottime => "boottime",
            Self::Wall => "wall_fallback",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct GrRestartMarkerResolution {
    remaining: Duration,
    authority: GrRestartExpiryAuthority,
    fallback_reason: Option<String>,
}

#[derive(Debug)]
struct WarmCheckpointPlan {
    views: Vec<WarmBundleViewV1>,
    rib_views: Vec<WarmMrtSnapshotView>,
    policy_inputs: Vec<WarmBundlePolicyInputV1>,
    add_path_receive: Vec<rustbgpd_mrt::codec::MrtAddPathReceiveProfile>,
}

/// Owner-verified runtime-state directory pinned for the daemon lifetime.
/// Marker and bundle publication are both descriptor-relative beneath this
/// authority, so replacing a pathname or planting a final symlink cannot
/// redirect shutdown state.
#[derive(Debug)]
struct PinnedRuntimeStateDirectory {
    file: File,
    display_path: PathBuf,
}

impl PinnedRuntimeStateDirectory {
    fn prepare(path: &Path) -> Result<Self, String> {
        use nix::fcntl::{OFlag, open};
        use nix::sys::stat::Mode;
        use nix::unistd::geteuid;

        match std::fs::symlink_metadata(path) {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let mut builder = std::fs::DirBuilder::new();
                builder.recursive(true).mode(0o700);
                builder.create(path).map_err(|error| {
                    format!(
                        "failed to create runtime-state directory {}: {error}",
                        path.display()
                    )
                })?;
            }
            Err(error) => {
                return Err(format!(
                    "failed to inspect runtime-state directory {}: {error}",
                    path.display()
                ));
            }
        }
        let fd = open(
            path,
            OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|error| {
            format!(
                "failed to pin runtime-state directory {}: {}",
                path.display(),
                std::io::Error::from_raw_os_error(error as i32)
            )
        })?;
        let file = File::from(fd);
        let metadata = file.metadata().map_err(|error| {
            format!(
                "failed to validate runtime-state directory {}: {error}",
                path.display()
            )
        })?;
        if !metadata.is_dir()
            || metadata.uid() != geteuid().as_raw()
            || metadata.mode() & 0o022 != 0
        {
            return Err(format!(
                "runtime-state directory {} has unsafe type, owner, or mode (is_dir={}, uid={}, expected_uid={}, mode={:o})",
                path.display(),
                metadata.is_dir(),
                metadata.uid(),
                geteuid().as_raw(),
                metadata.mode() & 0o7777
            ));
        }
        Ok(Self {
            file,
            display_path: path.to_path_buf(),
        })
    }

    fn prepare_warm_bundle(&self) -> Result<WarmBundleDirectory, String> {
        use nix::errno::Errno;
        use nix::sys::stat::{Mode, mkdirat};

        match mkdirat(
            &self.file,
            WARM_BUNDLE_DIRECTORY,
            Mode::from_bits_truncate(0o700),
        ) {
            Ok(()) | Err(Errno::EEXIST) => {}
            Err(error) => {
                return Err(format!(
                    "failed to create warm checkpoint directory {}: {}",
                    self.display_path.join(WARM_BUNDLE_DIRECTORY).display(),
                    std::io::Error::from_raw_os_error(error as i32)
                ));
            }
        }
        WarmBundleDirectory::open_at(&self.file, &self.display_path, WARM_BUNDLE_DIRECTORY)
            .map_err(|error| error.to_string())
    }
}

/// Serialized descriptor-relative restart marker I/O. The shared lock closes
/// the boot-expiry versus coordinated-shutdown publication race inside this
/// process; exact identity comparison prevents an inherited timer from
/// deleting a replacement marker.
#[derive(Debug, Clone)]
struct GrRestartMarkerStore {
    directory: Arc<PinnedRuntimeStateDirectory>,
    io_lock: Arc<Mutex<()>>,
}

impl GrRestartMarkerStore {
    fn new(directory: Arc<PinnedRuntimeStateDirectory>) -> Self {
        Self {
            directory,
            io_lock: Arc::new(Mutex::new(())),
        }
    }

    fn display_path(&self) -> PathBuf {
        self.directory.display_path.join(GR_RESTART_MARKER_FILE)
    }

    fn read(&self) -> Result<Option<ValidGrRestartMarker>, String> {
        let _guard = self
            .io_lock
            .lock()
            .map_err(|_| "restart-marker I/O lock was poisoned".to_string())?;
        self.read_locked()
    }

    fn read_locked(&self) -> Result<Option<ValidGrRestartMarker>, String> {
        use nix::errno::Errno;
        use nix::fcntl::{OFlag, openat};
        use nix::sys::stat::Mode;
        use nix::unistd::geteuid;

        let fd = match openat(
            &self.directory.file,
            GR_RESTART_MARKER_FILE,
            OFlag::O_RDONLY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
            Mode::empty(),
        ) {
            Ok(fd) => fd,
            Err(Errno::ENOENT) => return Ok(None),
            Err(error) => return Err(error.to_string()),
        };
        let file = File::from(fd);
        let metadata = file.metadata().map_err(|error| error.to_string())?;
        if !metadata.is_file()
            || metadata.uid() != geteuid().as_raw()
            || metadata.mode() & 0o022 != 0
        {
            return Err("restart marker has unsafe type, owner, or mode".to_string());
        }
        if metadata.len() > MAX_GR_RESTART_MARKER_BYTES {
            return Err(format!(
                "restart marker exceeds the {MAX_GR_RESTART_MARKER_BYTES}-byte cap"
            ));
        }
        let mut content = String::new();
        file.take(MAX_GR_RESTART_MARKER_BYTES.saturating_add(1))
            .read_to_string(&mut content)
            .map_err(|error| error.to_string())?;
        if u64::try_from(content.len()).unwrap_or(u64::MAX) > MAX_GR_RESTART_MARKER_BYTES {
            return Err(format!(
                "restart marker exceeds the {MAX_GR_RESTART_MARKER_BYTES}-byte cap"
            ));
        }
        let marker: GrRestartMarker = toml::from_str(&content).map_err(|e| e.to_string())?;
        let mut validated = validate_gr_restart_marker(marker)?;
        validated.storage_sha256 = Some(Sha256::digest(content.as_bytes()).into());
        Ok(Some(validated))
    }

    fn write_selected(
        &self,
        restart_duration: Duration,
        checkpoint_generation: Option<&str>,
    ) -> Result<GrRestartMarkerWriteOutcome, GrRestartMarkerWriteError> {
        self.write_inner(
            restart_duration,
            checkpoint_generation,
            MarkerFaultPoint::None,
        )
    }

    fn write_inner(
        &self,
        restart_duration: Duration,
        checkpoint_generation: Option<&str>,
        fault: MarkerFaultPoint,
    ) -> Result<GrRestartMarkerWriteOutcome, GrRestartMarkerWriteError> {
        let wall_now = SystemTime::now();
        let clock_sample = sample_gr_restart_clock();
        self.write_inner_with_sample(
            restart_duration,
            checkpoint_generation,
            fault,
            wall_now,
            clock_sample,
        )
    }

    fn write_inner_with_sample(
        &self,
        restart_duration: Duration,
        checkpoint_generation: Option<&str>,
        fault: MarkerFaultPoint,
        wall_now: SystemTime,
        clock_sample: Result<GrRestartClockSample, String>,
    ) -> Result<GrRestartMarkerWriteOutcome, GrRestartMarkerWriteError> {
        use nix::fcntl::{OFlag, openat, renameat};
        use nix::sys::stat::Mode;
        use nix::unistd::{UnlinkatFlags, unlinkat};

        if checkpoint_generation.is_some_and(|generation| !valid_checkpoint_generation(generation))
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "invalid checkpoint generation",
            )
            .into());
        }
        let expires_at = wall_now
            .checked_add(restart_duration)
            .ok_or_else(|| std::io::Error::other("marker wall expiry overflows system clock"))?;
        let expires_at_unix = expires_at
            .duration_since(UNIX_EPOCH)
            .map_err(|e| std::io::Error::other(e.to_string()))?
            .as_secs();
        let (marker, outcome) = build_gr_restart_marker(
            expires_at_unix,
            restart_duration,
            checkpoint_generation,
            clock_sample,
        );
        let encoded =
            toml::to_string(&marker).map_err(|error| std::io::Error::other(error.to_string()))?;
        let sequence = MARKER_TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let temp_name = format!(
            ".{GR_RESTART_MARKER_FILE}.tmp.{}.{}",
            std::process::id(),
            sequence
        );
        let _guard = self
            .io_lock
            .lock()
            .map_err(|_| std::io::Error::other("restart-marker I/O lock was poisoned"))?;
        let mut renamed = false;
        let result = (|| -> std::io::Result<()> {
            marker_fail_if(fault, MarkerFaultPoint::Write)?;
            let fd = openat(
                &self.directory.file,
                temp_name.as_str(),
                OFlag::O_WRONLY
                    | OFlag::O_CREAT
                    | OFlag::O_EXCL
                    | OFlag::O_CLOEXEC
                    | OFlag::O_NOFOLLOW,
                Mode::from_bits_truncate(0o600),
            )
            .map_err(|error| std::io::Error::from_raw_os_error(error as i32))?;
            let mut temp = File::from(fd);
            temp.write_all(encoded.as_bytes())?;
            marker_fail_if(fault, MarkerFaultPoint::FileSync)?;
            temp.sync_all()?;
            drop(temp);
            marker_fail_if(fault, MarkerFaultPoint::Rename)?;
            renameat(
                &self.directory.file,
                temp_name.as_str(),
                &self.directory.file,
                GR_RESTART_MARKER_FILE,
            )
            .map_err(|error| std::io::Error::from_raw_os_error(error as i32))?;
            renamed = true;
            marker_fail_if(fault, MarkerFaultPoint::DirectorySync)?;
            self.directory.file.sync_all()
        })();
        if result.is_err() {
            let _ = unlinkat(
                &self.directory.file,
                temp_name.as_str(),
                UnlinkatFlags::NoRemoveDir,
            );
        }
        result
            .map(|()| outcome.clone())
            .map_err(|error| GrRestartMarkerWriteError {
                error,
                visible_outcome: renamed.then_some(outcome),
            })
    }

    fn remove(&self) -> std::io::Result<()> {
        let _guard = self
            .io_lock
            .lock()
            .map_err(|_| std::io::Error::other("restart-marker I/O lock was poisoned"))?;
        self.remove_locked()
    }

    fn remove_if_matches(&self, expected: &ValidGrRestartMarker) -> std::io::Result<bool> {
        let _guard = self
            .io_lock
            .lock()
            .map_err(|_| std::io::Error::other("restart-marker I/O lock was poisoned"))?;
        let current = self.read_locked().map_err(std::io::Error::other)?;
        // Compare the exact file-byte identity, not just parsed semantics. A
        // replacement marker can deliberately carry the same expiry and
        // generation with different bytes; it belongs to a newer publisher
        // and must survive this inherited timer.
        if expected.storage_sha256.is_none()
            || current.as_ref().and_then(|marker| marker.storage_sha256) != expected.storage_sha256
        {
            return Ok(false);
        }
        self.remove_locked()?;
        Ok(true)
    }

    fn remove_locked(&self) -> std::io::Result<()> {
        use nix::errno::Errno;
        use nix::unistd::{UnlinkatFlags, unlinkat};

        match unlinkat(
            &self.directory.file,
            GR_RESTART_MARKER_FILE,
            UnlinkatFlags::NoRemoveDir,
        ) {
            Ok(()) | Err(Errno::ENOENT) => Ok(()),
            Err(error) => Err(std::io::Error::from_raw_os_error(error as i32)),
        }
    }
}

fn publish_gr_restart_marker_with_fallback<F>(
    checkpoint_generation: Option<&str>,
    mut publish: F,
) -> GrRestartMarkerPublicationResult
where
    F: FnMut(Option<&str>) -> Result<GrRestartMarkerWriteOutcome, GrRestartMarkerWriteError>,
{
    match publish(checkpoint_generation) {
        Ok(outcome) => GrRestartMarkerPublicationResult {
            visible: Some(VisibleGrRestartMarker {
                outcome,
                durability: GrRestartMarkerDurability::DirectorySynced,
            }),
            initial_error: None,
            fallback_error: None,
        },
        Err(initial_error) => {
            let initial_visible = initial_error.visible_outcome.clone();
            if checkpoint_generation.is_none() {
                return GrRestartMarkerPublicationResult {
                    visible: initial_visible.map(|outcome| VisibleGrRestartMarker {
                        outcome,
                        durability: GrRestartMarkerDurability::VisibleDirectorySyncUncertain,
                    }),
                    initial_error: Some(initial_error),
                    fallback_error: None,
                };
            }

            match publish(None) {
                Ok(outcome) => GrRestartMarkerPublicationResult {
                    visible: Some(VisibleGrRestartMarker {
                        outcome,
                        durability: GrRestartMarkerDurability::DirectorySynced,
                    }),
                    initial_error: Some(initial_error),
                    fallback_error: None,
                },
                Err(fallback_error) => {
                    let final_visible = fallback_error.visible_outcome.clone().or(initial_visible);
                    GrRestartMarkerPublicationResult {
                        visible: final_visible.map(|outcome| VisibleGrRestartMarker {
                            outcome,
                            durability: GrRestartMarkerDurability::VisibleDirectorySyncUncertain,
                        }),
                        initial_error: Some(initial_error),
                        fallback_error: Some(fallback_error),
                    }
                }
            }
        }
    }
}

struct BmpRuntime {
    control_tx: mpsc::Sender<rustbgpd_bmp::BmpControlEvent>,
    manager_handle: JoinHandle<()>,
    client_handles: Vec<JoinHandle<()>>,
}

impl From<GrpcAccessMode> for GrpcServerAccessMode {
    fn from(value: GrpcAccessMode) -> Self {
        match value {
            GrpcAccessMode::ReadOnly => Self::ReadOnly,
            GrpcAccessMode::ReadWrite => Self::ReadWrite,
        }
    }
}

const fn grpc_max_tier_to_auth_tier(value: GrpcMaxTier) -> rustbgpd_api::authz::AuthTier {
    match value {
        GrpcMaxTier::Read => rustbgpd_api::authz::AuthTier::Read,
        GrpcMaxTier::SensitiveRead => rustbgpd_api::authz::AuthTier::SensitiveRead,
        GrpcMaxTier::Mutating => rustbgpd_api::authz::AuthTier::Mutating,
        GrpcMaxTier::OperatorOnly => rustbgpd_api::authz::AuthTier::OperatorOnly,
    }
}

fn fib_runtime_event_to_bgp_event(
    event: fib_runtime::FibRuntimeEvent,
) -> rustbgpd_api::proto::BgpEvent {
    let (event_type, action, severity) = match event.kind {
        fib_runtime::FibRuntimeEventKind::Installed => (
            rustbgpd_api::proto::BgpEventType::DataplaneRouteInstalled,
            "installed",
            rustbgpd_api::proto::EventSeverity::Info,
        ),
        fib_runtime::FibRuntimeEventKind::Withdrawn => (
            rustbgpd_api::proto::BgpEventType::DataplaneRouteWithdrawn,
            "withdrawn",
            rustbgpd_api::proto::EventSeverity::Info,
        ),
        fib_runtime::FibRuntimeEventKind::Failed => (
            rustbgpd_api::proto::BgpEventType::DataplaneRouteFailed,
            "failed",
            rustbgpd_api::proto::EventSeverity::Warning,
        ),
    };
    let prefix = event.prefix.addr_string();
    let prefix_length = u32::from(event.prefix.prefix_len());
    let next_hop = event.next_hop.map_or_else(String::new, |ip| ip.to_string());
    let peer_address = event.peer.map_or_else(String::new, |ip| ip.to_string());
    let afi_safi = match event.prefix {
        rustbgpd_wire::Prefix::V4(_) => rustbgpd_api::proto::AddressFamily::Ipv4Unicast,
        rustbgpd_wire::Prefix::V6(_) => rustbgpd_api::proto::AddressFamily::Ipv6Unicast,
    } as i32;
    let route = rustbgpd_api::proto::DataplaneRouteEvent {
        source: "fib".to_string(),
        action: action.to_string(),
        table_name: event.table_name.clone(),
        table_id: event.table_id,
        metric: event.metric,
        prefix: prefix.clone(),
        prefix_length,
        next_hop,
        peer_address: peer_address.clone(),
        timestamp: event.timestamp.clone(),
        reason: event.reason.clone(),
    };

    rustbgpd_api::proto::BgpEvent {
        timestamp: event.timestamp,
        category: rustbgpd_api::proto::EventCategory::Dataplane as i32,
        event_type: event_type as i32,
        severity: severity as i32,
        peer_address,
        previous_peer_address: String::new(),
        prefix: prefix.clone(),
        prefix_length,
        afi_safi,
        summary: format!(
            "dataplane fib route {action} {prefix}/{prefix_length}: {}",
            event.reason
        ),
        target_peer_address: String::new(),
        event_id: None,
        payload: Some(rustbgpd_api::proto::bgp_event::Payload::DataplaneRoute(
            route,
        )),
    }
}

fn spawn_fib_dataplane_event_bridge(
    mut fib_events: broadcast::Receiver<fib_runtime::FibRuntimeEvent>,
    bgp_events: broadcast::Sender<rustbgpd_api::proto::BgpEvent>,
    event_history: Option<rustbgpd_event_history::EventHistoryHandle>,
    metrics: rustbgpd_telemetry::BgpMetrics,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            match fib_events.recv().await {
                Ok(event) => {
                    // Capture the typed peer before consuming `event`
                    // into the proto converter. The proto envelope's
                    // peer field is a stringified IpAddr, so parsing
                    // it back is wasted work when the source struct
                    // already carries `Option<IpAddr>` directly.
                    let envelope_peer = event.peer;
                    let proto_event = fib_runtime_event_to_bgp_event(event);
                    // ADR-0072 PR-FU1: durable outbox enqueue. The
                    // legacy `bgp_events` broadcast (consumed by
                    // WatchEvents) stays unchanged. Per-route FIB
                    // events carry peer (when sourced from a
                    // BGP path) and prefix on the envelope so
                    // collectors can filter by either.
                    if let Some(handle) = &event_history {
                        let envelope = rustbgpd_api::event_history_sinks::envelope_from_bgp_event(
                            &proto_event,
                            rustbgpd_event_history::Category::Dataplane,
                            envelope_peer,
                            None,
                        );
                        rustbgpd_api::event_history_sinks::try_send_envelope(
                            handle, &metrics, envelope,
                        );
                    }
                    let _ = bgp_events.send(proto_event);
                }
                Err(broadcast::error::RecvError::Lagged(missed)) => {
                    // The bridge consumes `fib_events` via a bounded
                    // tokio broadcast; if the bridge falls behind the
                    // FIB runtime, those `missed` events never reach
                    // the bridge body and therefore never reach EHM.
                    // When EHM is the durable producer for this
                    // category, that's a real cursor gap — call
                    // `record_source_lag` so the drop counter, the
                    // Prometheus degraded gauge, AND EHM's in-process
                    // degraded state are all flipped together. When
                    // EHM is disabled the lag is purely a live-stream
                    // concern (matches pre-ADR-0072 behavior); leave
                    // the bookkeeping alone in that case.
                    warn!(
                        missed,
                        "FIB dataplane event bridge lagged; dropping stale route events"
                    );
                    if let Some(handle) = &event_history {
                        rustbgpd_api::event_history_sinks::record_source_lag(
                            handle,
                            &metrics,
                            "dataplane",
                            missed,
                        );
                    }
                }
                Err(broadcast::error::RecvError::Closed) => break,
            }
        }
    })
}

/// Convert a BFD actor state-change event into a unified gRPC `BgpEvent`
/// (ADR-0067 step 3b). Up → `BfdSessionUp`, any down (Down/`AdminDown`) →
/// `BfdSessionDown`, otherwise `BfdSessionStateChanged`; the full old/new
/// states are always carried in the `BfdSessionEvent` payload.
fn bfd_runtime_event_to_bgp_event(
    event: &bfd_runtime::BfdRuntimeEvent,
) -> rustbgpd_api::proto::BgpEvent {
    use rustbgpd_api::proto;
    let (event_type, severity) = match event.new_state {
        rustbgpd_bfd::SessionState::Up => (
            proto::BgpEventType::BfdSessionUp,
            proto::EventSeverity::Info,
        ),
        rustbgpd_bfd::SessionState::Down | rustbgpd_bfd::SessionState::AdminDown => (
            proto::BgpEventType::BfdSessionDown,
            proto::EventSeverity::Warning,
        ),
        rustbgpd_bfd::SessionState::Init => (
            proto::BgpEventType::BfdSessionStateChanged,
            proto::EventSeverity::Info,
        ),
    };
    let timestamp = rustbgpd_rib::event::unix_timestamp_now();
    let peer_address = event.peer.to_string();
    let old_state = bfd_session_state_to_proto(event.old_state);
    let new_state = bfd_session_state_to_proto(event.new_state);
    let diagnostic = bfd_diagnostic_to_str(event.diagnostic).to_string();
    let summary = format!("bfd {peer_address} {old_state:?} → {new_state:?} ({diagnostic})");
    proto::BgpEvent {
        timestamp: timestamp.clone(),
        category: proto::EventCategory::Bfd as i32,
        event_type: event_type as i32,
        severity: severity as i32,
        peer_address: peer_address.clone(),
        previous_peer_address: String::new(),
        prefix: String::new(),
        prefix_length: 0,
        afi_safi: proto::AddressFamily::Unspecified as i32,
        summary,
        target_peer_address: String::new(),
        event_id: None,
        payload: Some(proto::bgp_event::Payload::Bfd(proto::BfdSessionEvent {
            event_type: event_type as i32,
            peer_address,
            timestamp,
            old_state: old_state as i32,
            new_state: new_state as i32,
            diagnostic,
            reason: String::new(),
        })),
    }
}

/// Translate the operator-facing `[event_history]` TOML block into
/// the `EventHistoryConfig` shape the `rustbgpd-event-history` crate
/// understands. The validation pass on the parent `Config` has
/// already enforced the field invariants (synchronous / overflow
/// values, positive sizes).
fn build_event_history_config(
    config: &Config,
    metrics: &BgpMetrics,
) -> rustbgpd_event_history::EventHistoryConfig {
    let block = &config.event_history;
    let synchronous = if block.synchronous.eq_ignore_ascii_case("normal") {
        rustbgpd_event_history::SynchronousMode::Normal
    } else {
        rustbgpd_event_history::SynchronousMode::Full
    };
    rustbgpd_event_history::EventHistoryConfig {
        path: config.event_history_db_path(),
        max_events: block.max_events,
        max_bytes: block.max_bytes,
        synchronous,
        required: block.required,
        queue_capacity: block.queue_capacity,
        batch_size: block.batch_size,
        batch_interval: std::time::Duration::from_millis(block.batch_interval_ms),
        metrics: Some(metrics.clone()),
        ..rustbgpd_event_history::EventHistoryConfig::default()
    }
}

fn spawn_bfd_event_bridge(
    mut bfd_events: broadcast::Receiver<bfd_runtime::BfdRuntimeEvent>,
    bgp_events: broadcast::Sender<rustbgpd_api::proto::BgpEvent>,
    event_history: Option<rustbgpd_event_history::EventHistoryHandle>,
    metrics: rustbgpd_telemetry::BgpMetrics,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            match bfd_events.recv().await {
                Ok(event) => {
                    let proto_event = bfd_runtime_event_to_bgp_event(&event);
                    // ADR-0072 durable outbox enqueue. The legacy live
                    // `bgp_events` broadcast (consumed by WatchEvents +
                    // the EVPN service) stays unchanged.
                    if let Some(handle) = &event_history {
                        let envelope = rustbgpd_api::event_history_sinks::envelope_from_bgp_event(
                            &proto_event,
                            rustbgpd_event_history::Category::Bfd,
                            // BFD events are keyed by peer address;
                            // pull it from the proto envelope so the
                            // payload->envelope mapping stays in one
                            // place (the proto field is the source of
                            // truth for outbox-side filtering by peer).
                            proto_event.peer_address.parse().ok(),
                            None,
                        );
                        rustbgpd_api::event_history_sinks::try_send_envelope(
                            handle, &metrics, envelope,
                        );
                    }
                    let _ = bgp_events.send(proto_event);
                }
                Err(broadcast::error::RecvError::Lagged(missed)) => {
                    // See FIB bridge above: when EHM is the durable
                    // producer for this category, broadcast lag at
                    // the bridge boundary is a real cursor gap.
                    // `record_source_lag` flips the drop counter,
                    // the Prometheus degraded gauge, AND EHM's
                    // in-process degraded state together. Pre-PR
                    // behavior (no EHM) leaves the bookkeeping
                    // alone.
                    warn!(
                        missed,
                        "BFD event bridge lagged; dropping stale session events"
                    );
                    if let Some(handle) = &event_history {
                        rustbgpd_api::event_history_sinks::record_source_lag(
                            handle, &metrics, "bfd", missed,
                        );
                    }
                }
                Err(broadcast::error::RecvError::Closed) => break,
            }
        }
    })
}

const fn grpc_enforcement_to_auth_enforcement(
    value: GrpcEnforcementConfig,
) -> rustbgpd_api::authz::AuthEnforcement {
    match value {
        GrpcEnforcementConfig::Legacy => rustbgpd_api::authz::AuthEnforcement::Legacy,
        GrpcEnforcementConfig::Tier => rustbgpd_api::authz::AuthEnforcement::Tier,
    }
}

const fn grpc_role_to_principal_role(value: GrpcRoleConfig) -> rustbgpd_api::authz::PrincipalRole {
    match value {
        GrpcRoleConfig::Observer => rustbgpd_api::authz::PrincipalRole::Observer,
        GrpcRoleConfig::Automation => rustbgpd_api::authz::PrincipalRole::Automation,
        GrpcRoleConfig::Operator => rustbgpd_api::authz::PrincipalRole::Operator,
    }
}

fn grpc_principal_roles(config: &Config) -> BTreeMap<String, rustbgpd_api::authz::PrincipalRole> {
    config
        .security
        .grpc
        .roles
        .iter()
        .map(|(principal, role)| (principal.clone(), grpc_role_to_principal_role(*role)))
        .collect()
}

fn raw_max_gr_restart_time_secs(config: &Config) -> Option<u64> {
    config
        .neighbors
        .iter()
        .filter(|neighbor| neighbor.graceful_restart.unwrap_or(true))
        .map(|neighbor| u64::from(neighbor.gr_restart_time.unwrap_or(120)))
        .filter(|seconds| *seconds > 0)
        .max()
}

fn max_gr_restart_time_secs(config: &Config) -> Option<u64> {
    match config.resolved_neighbors() {
        Ok(neighbors) => neighbors
            .iter()
            .filter(|neighbor| neighbor.transport_config.peer.graceful_restart)
            .map(|neighbor| u64::from(neighbor.transport_config.peer.gr_restart_time))
            .filter(|seconds| *seconds > 0)
            .max(),
        Err(error) => {
            warn!(
                %error,
                "failed to resolve effective neighbors while computing the planned-restart window; falling back to raw neighbor GR settings"
            );
            raw_max_gr_restart_time_secs(config)
        }
    }
}

fn gr_restart_marker_remaining_time(
    expires_at: SystemTime,
    now: SystemTime,
    max_restart_time_secs: Option<u64>,
) -> Option<Duration> {
    let maximum = max_restart_time_secs.filter(|maximum| *maximum > 0)?;
    let remaining = expires_at.duration_since(now).ok()?;
    if remaining.is_zero() {
        return None;
    }
    Some(remaining.min(Duration::from_secs(maximum)))
}

fn resolve_gr_restart_marker(
    marker: &ValidGrRestartMarker,
    wall_now: SystemTime,
    clock_sample: Result<GrRestartClockSample, String>,
    max_restart_time_secs: Option<u64>,
) -> Option<GrRestartMarkerResolution> {
    let maximum = max_restart_time_secs.filter(|maximum| *maximum > 0)?;
    let Some(domain) = marker.clock_domain.as_ref() else {
        return gr_restart_marker_remaining_time(marker.expires_at, wall_now, Some(maximum)).map(
            |remaining| GrRestartMarkerResolution {
                remaining,
                authority: GrRestartExpiryAuthority::Wall,
                fallback_reason: Some("legacy marker has no boottime clock domain".to_string()),
            },
        );
    };

    let fallback_reason = match clock_sample {
        Ok(sample) => match gr_restart_clock_domain_mismatch(domain, &sample) {
            None => {
                let remaining_ms = domain
                    .expires_at_boottime_ms
                    .checked_sub(sample.boottime_ms)?;
                if remaining_ms == 0 {
                    return None;
                }
                let maximum_ms = maximum.saturating_mul(1_000);
                return Some(GrRestartMarkerResolution {
                    remaining: Duration::from_millis(remaining_ms.min(maximum_ms)),
                    authority: GrRestartExpiryAuthority::Boottime,
                    fallback_reason: None,
                });
            }
            Some(reason) => reason,
        },
        Err(error) => format!("boottime clock sample unavailable: {error}"),
    };

    gr_restart_marker_remaining_time(marker.expires_at, wall_now, Some(maximum)).map(|remaining| {
        GrRestartMarkerResolution {
            remaining,
            authority: GrRestartExpiryAuthority::Wall,
            fallback_reason: Some(fallback_reason),
        }
    })
}

fn gr_restart_clock_domain_mismatch(
    domain: &GrRestartClockDomain,
    sample: &GrRestartClockSample,
) -> Option<String> {
    if domain.boot_id != sample.boot_id {
        Some("boot ID changed".to_string())
    } else if domain.time_namespace_dev != sample.time_namespace_dev {
        Some("time namespace device changed".to_string())
    } else if domain.time_namespace_ino != sample.time_namespace_ino {
        Some("time namespace inode changed".to_string())
    } else if domain.boottime_offset_secs != sample.boottime_offset_secs {
        Some("time namespace boottime seconds offset changed".to_string())
    } else if domain.boottime_offset_nanos != sample.boottime_offset_nanos {
        Some("time namespace boottime nanoseconds offset changed".to_string())
    } else {
        None
    }
}

fn build_gr_restart_marker(
    expires_at_unix: u64,
    restart_duration: Duration,
    checkpoint_generation: Option<&str>,
    clock_sample: Result<GrRestartClockSample, String>,
) -> (GrRestartMarker, GrRestartMarkerWriteOutcome) {
    let legacy_version = if checkpoint_generation.is_some() {
        GR_RESTART_MARKER_V2
    } else {
        GR_RESTART_MARKER_V1
    };
    let mut marker = GrRestartMarker {
        version: legacy_version,
        expires_at_unix,
        checkpoint_generation: checkpoint_generation.map(str::to_string),
        boot_id: None,
        time_namespace_dev: None,
        time_namespace_ino: None,
        boottime_offset_secs: None,
        boottime_offset_nanos: None,
        expires_at_boottime_ms: None,
    };

    let domain = clock_sample.and_then(|sample| {
        canonical_boot_id(&sample.boot_id)?;
        if sample.boottime_offset_nanos >= 1_000_000_000 {
            return Err("boottime offset nanoseconds are outside 0..1,000,000,000".to_string());
        }
        let duration_ms = u64::try_from(restart_duration.as_millis())
            .map_err(|_| "restart duration does not fit boottime milliseconds".to_string())?;
        let expires_at_boottime_ms = sample
            .boottime_ms
            .checked_add(duration_ms)
            .ok_or_else(|| "boottime expiry overflows milliseconds".to_string())?;
        let time_namespace_dev = i64::try_from(sample.time_namespace_dev)
            .map_err(|_| "time namespace device exceeds TOML's signed integer range".to_string())?;
        let time_namespace_ino = i64::try_from(sample.time_namespace_ino)
            .map_err(|_| "time namespace inode exceeds TOML's signed integer range".to_string())?;
        let expires_at_boottime_ms = i64::try_from(expires_at_boottime_ms)
            .map_err(|_| "boottime expiry exceeds TOML's signed integer range".to_string())?;
        Ok((
            GrRestartClockDomain {
                boot_id: sample.boot_id,
                time_namespace_dev: sample.time_namespace_dev,
                time_namespace_ino: sample.time_namespace_ino,
                boottime_offset_secs: sample.boottime_offset_secs,
                boottime_offset_nanos: sample.boottime_offset_nanos,
                expires_at_boottime_ms: u64::try_from(expires_at_boottime_ms)
                    .expect("checked nonnegative boottime expiry"),
            },
            time_namespace_dev,
            time_namespace_ino,
            expires_at_boottime_ms,
        ))
    });

    match domain {
        Ok((domain, time_namespace_dev, time_namespace_ino, expires_at_boottime_ms)) => {
            marker.version = GR_RESTART_MARKER_V3;
            marker.boot_id = Some(domain.boot_id);
            marker.time_namespace_dev = Some(time_namespace_dev);
            marker.time_namespace_ino = Some(time_namespace_ino);
            marker.boottime_offset_secs = Some(domain.boottime_offset_secs);
            marker.boottime_offset_nanos = Some(domain.boottime_offset_nanos);
            marker.expires_at_boottime_ms = Some(expires_at_boottime_ms);
            (
                marker,
                GrRestartMarkerWriteOutcome {
                    version: GR_RESTART_MARKER_V3,
                    checkpoint_generation: checkpoint_generation.map(str::to_string),
                    degraded_reason: None,
                },
            )
        }
        Err(reason) => (
            marker,
            GrRestartMarkerWriteOutcome {
                version: legacy_version,
                checkpoint_generation: checkpoint_generation.map(str::to_string),
                degraded_reason: Some(reason),
            },
        ),
    }
}

fn canonical_boot_id(value: &str) -> Result<String, String> {
    let parsed =
        uuid::Uuid::parse_str(value).map_err(|error| format!("invalid boot ID: {error}"))?;
    let canonical = parsed.hyphenated().to_string();
    if value != canonical {
        return Err("boot ID is not canonical lowercase hyphenated UUID text".to_string());
    }
    Ok(canonical)
}

fn parse_boottime_offset(content: &str) -> Result<(i64, u32), String> {
    let mut boottime = None;
    for line in content.lines() {
        let mut fields = line.split_whitespace();
        let Some(clock) = fields.next() else {
            continue;
        };
        if clock != "boottime" {
            continue;
        }
        if boottime.is_some() {
            return Err("time namespace offsets contain duplicate boottime lines".to_string());
        }
        let seconds = fields
            .next()
            .ok_or_else(|| "time namespace boottime offset is missing seconds".to_string())?
            .parse::<i64>()
            .map_err(|error| format!("invalid boottime offset seconds: {error}"))?;
        let nanoseconds = fields
            .next()
            .ok_or_else(|| "time namespace boottime offset is missing nanoseconds".to_string())?
            .parse::<u32>()
            .map_err(|error| format!("invalid boottime offset nanoseconds: {error}"))?;
        if fields.next().is_some() {
            return Err("time namespace boottime offset has extra fields".to_string());
        }
        if nanoseconds >= 1_000_000_000 {
            return Err(
                "time namespace boottime nanoseconds are outside 0..1,000,000,000".to_string(),
            );
        }
        boottime = Some((seconds, nanoseconds));
    }
    boottime.ok_or_else(|| "time namespace offsets do not contain boottime".to_string())
}

#[cfg(target_os = "linux")]
fn sample_gr_restart_clock() -> Result<GrRestartClockSample, String> {
    use nix::time::{ClockId, clock_gettime};

    let raw_boot_id = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .map_err(|error| format!("failed to read boot ID: {error}"))?;
    let boot_id = canonical_boot_id(raw_boot_id.trim())?;
    let metadata = std::fs::metadata("/proc/self/ns/time")
        .map_err(|error| format!("failed to inspect time namespace: {error}"))?;
    let offsets = std::fs::read_to_string("/proc/self/timens_offsets")
        .map_err(|error| format!("failed to read time namespace offsets: {error}"))?;
    let (boottime_offset_secs, boottime_offset_nanos) = parse_boottime_offset(&offsets)?;
    let boottime = clock_gettime(ClockId::CLOCK_BOOTTIME)
        .map_err(|error| format!("failed to sample CLOCK_BOOTTIME: {error}"))?;
    let seconds = u64::try_from(boottime.tv_sec())
        .map_err(|_| "CLOCK_BOOTTIME returned negative seconds".to_string())?;
    let nanoseconds = u32::try_from(boottime.tv_nsec())
        .map_err(|_| "CLOCK_BOOTTIME returned invalid nanoseconds".to_string())?;
    if nanoseconds >= 1_000_000_000 {
        return Err("CLOCK_BOOTTIME nanoseconds are outside 0..1,000,000,000".to_string());
    }
    let boottime_ms = seconds
        .checked_mul(1_000)
        .and_then(|milliseconds| milliseconds.checked_add(u64::from(nanoseconds / 1_000_000)))
        .ok_or_else(|| "CLOCK_BOOTTIME overflows milliseconds".to_string())?;

    Ok(GrRestartClockSample {
        boot_id,
        time_namespace_dev: metadata.dev(),
        time_namespace_ino: metadata.ino(),
        boottime_offset_secs,
        boottime_offset_nanos,
        boottime_ms,
    })
}

#[cfg(not(target_os = "linux"))]
fn sample_gr_restart_clock() -> Result<GrRestartClockSample, String> {
    Err("boottime clock-domain sampling is supported only on Linux".to_string())
}

fn valid_checkpoint_generation(generation: &str) -> bool {
    !generation.is_empty()
        && generation.len() <= MAX_CHECKPOINT_GENERATION_BYTES
        && !generation.chars().any(char::is_control)
}

fn validate_gr_restart_marker(marker: GrRestartMarker) -> Result<ValidGrRestartMarker, String> {
    let clock_fields = [
        marker.boot_id.is_some(),
        marker.time_namespace_dev.is_some(),
        marker.time_namespace_ino.is_some(),
        marker.boottime_offset_secs.is_some(),
        marker.boottime_offset_nanos.is_some(),
        marker.expires_at_boottime_ms.is_some(),
    ];
    let has_any_clock_field = clock_fields.iter().any(|present| *present);
    let has_all_clock_fields = clock_fields.iter().all(|present| *present);
    match marker.version {
        GR_RESTART_MARKER_V1 if marker.checkpoint_generation.is_none() && !has_any_clock_field => {}
        GR_RESTART_MARKER_V1 => {
            return Err(
                "restart marker v1 must not carry a checkpoint generation or v3 clock fields"
                    .to_string(),
            );
        }
        GR_RESTART_MARKER_V2 if !has_any_clock_field => {
            let generation = marker
                .checkpoint_generation
                .as_deref()
                .ok_or_else(|| "restart marker v2 is missing checkpoint_generation".to_string())?;
            if !valid_checkpoint_generation(generation) {
                return Err("restart marker v2 has an invalid checkpoint_generation".to_string());
            }
        }
        GR_RESTART_MARKER_V2 => {
            return Err("restart marker v2 must not carry v3 clock fields".to_string());
        }
        GR_RESTART_MARKER_V3 if !has_all_clock_fields => {
            return Err("restart marker v3 requires all clock-domain fields".to_string());
        }
        GR_RESTART_MARKER_V3 => {
            if marker
                .checkpoint_generation
                .as_deref()
                .is_some_and(|generation| !valid_checkpoint_generation(generation))
            {
                return Err("restart marker v3 has an invalid checkpoint_generation".to_string());
            }
        }
        version => {
            return Err(format!(
                "unsupported marker version {version} (expected {GR_RESTART_MARKER_V1}, {GR_RESTART_MARKER_V2}, or {GR_RESTART_MARKER_V3})"
            ));
        }
    }
    let expires_at = UNIX_EPOCH
        .checked_add(Duration::from_secs(marker.expires_at_unix))
        .ok_or_else(|| "marker expiry overflows system clock".to_string())?;
    let clock_domain = if marker.version == GR_RESTART_MARKER_V3 {
        let boot_id = marker.boot_id.expect("v3 field presence checked");
        canonical_boot_id(&boot_id)?;
        let time_namespace_dev = u64::try_from(
            marker
                .time_namespace_dev
                .expect("v3 field presence checked"),
        )
        .map_err(|_| "restart marker v3 time namespace device must be nonnegative")?;
        let time_namespace_ino = u64::try_from(
            marker
                .time_namespace_ino
                .expect("v3 field presence checked"),
        )
        .map_err(|_| "restart marker v3 time namespace inode must be nonnegative")?;
        let boottime_offset_nanos = marker
            .boottime_offset_nanos
            .expect("v3 field presence checked");
        let expires_at_boottime_ms = u64::try_from(
            marker
                .expires_at_boottime_ms
                .expect("v3 field presence checked"),
        )
        .map_err(|_| "restart marker v3 boottime expiry must be nonnegative")?;
        if boottime_offset_nanos >= 1_000_000_000 {
            return Err("restart marker v3 has invalid boottime offset nanoseconds".to_string());
        }
        Some(GrRestartClockDomain {
            boot_id,
            time_namespace_dev,
            time_namespace_ino,
            boottime_offset_secs: marker
                .boottime_offset_secs
                .expect("v3 field presence checked"),
            boottime_offset_nanos,
            expires_at_boottime_ms,
        })
    } else {
        None
    };
    Ok(ValidGrRestartMarker {
        version: marker.version,
        expires_at,
        checkpoint_generation: marker.checkpoint_generation,
        clock_domain,
        storage_sha256: None,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MarkerFaultPoint {
    None,
    Write,
    FileSync,
    Rename,
    DirectorySync,
}

fn marker_fail_if(selected: MarkerFaultPoint, current: MarkerFaultPoint) -> std::io::Result<()> {
    if selected == current {
        Err(std::io::Error::other(format!(
            "injected restart-marker failure at {current:?}"
        )))
    } else {
        Ok(())
    }
}

fn resolve_grpc_listeners(config: &Config) -> Result<Vec<GrpcListenerConfig>, String> {
    use rustbgpd_api::credentials::{CredentialSource, CredentialStore, TlsSource};
    let enforcement = grpc_enforcement_to_auth_enforcement(config.security.grpc.enforcement);
    let roles = Arc::new(grpc_principal_roles(config));
    let declared = config.grpc_listeners();
    let sources = declared
        .iter()
        .map(|listener| match listener {
            GrpcListener::Tcp {
                token_file, tls, ..
            } => CredentialSource {
                token_file: token_file.clone(),
                tls: tls.as_ref().map(|paths| TlsSource {
                    cert_file: paths.cert_file.clone(),
                    key_file: paths.key_file.clone(),
                    client_ca_file: paths.client_ca_file.clone(),
                }),
            },
            GrpcListener::Uds { token_file, .. } => CredentialSource {
                token_file: token_file.clone(),
                tls: None,
            },
        })
        .collect();
    let credential_store = CredentialStore::stage(sources)?;
    declared
        .into_iter()
        .enumerate()
        .map(|(credential_index, listener)| match listener {
            GrpcListener::Tcp {
                addr,
                access_mode,
                max_tier,
                token_file: _,
                principal,
                tls,
            } => {
                let _ = tls;
                Ok(GrpcListenerConfig {
                    endpoint: ListenerEndpoint::Tcp(addr),
                    access_mode: access_mode.into(),
                    max_tier: grpc_max_tier_to_auth_tier(max_tier),
                    enforcement,
                    roles: Arc::clone(&roles),
                    credential_store: credential_store.clone(),
                    credential_index,
                    principal,
                })
            }
            GrpcListener::Uds {
                path,
                mode,
                access_mode,
                max_tier,
                token_file: _,
                principal,
            } => Ok(GrpcListenerConfig {
                endpoint: ListenerEndpoint::Uds { path, mode },
                access_mode: access_mode.into(),
                max_tier: grpc_max_tier_to_auth_tier(max_tier),
                enforcement,
                roles: Arc::clone(&roles),
                credential_store: credential_store.clone(),
                credential_index,
                principal,
            }),
        })
        .collect()
}

const fn warm_bundle_family_v1(afi: Afi, safi: Safi) -> Option<WarmBundleFamilyV1> {
    match (afi, safi) {
        (Afi::Ipv4, Safi::Unicast) => Some(WarmBundleFamilyV1::Ipv4Unicast),
        (Afi::Ipv6, Safi::Unicast) => Some(WarmBundleFamilyV1::Ipv6Unicast),
        (Afi::L2Vpn, Safi::Evpn) => Some(WarmBundleFamilyV1::L2vpnEvpn),
        _ => None,
    }
}

fn build_warm_checkpoint_plan(
    sessions: &[WarmCheckpointSession],
) -> Result<WarmCheckpointPlan, String> {
    let mut views = Vec::new();
    let mut rib_views = Vec::new();
    let mut policy_inputs = Vec::new();
    let mut add_path_receive = Vec::new();

    for session in sessions {
        if session.peer.interface.is_some() {
            return Err(format!(
                "scoped peer {} reached the numbered-only warm checkpoint planner",
                session.peer
            ));
        }
        let peer = session.peer.address;
        for &(afi, safi) in &session.peer_gr_families {
            if !session.negotiated_families.contains(&(afi, safi)) {
                continue;
            }
            let Some(family) = warm_bundle_family_v1(afi, safi) else {
                continue;
            };
            let receives_add_path = session.add_path_receive_families.contains(&(afi, safi));
            // TABLE_DUMP_V2 has Add-Path subtypes only for unicast. V1
            // deliberately excludes an EVPN/Add-Path profile rather than
            // serializing it under ambiguous RIB_GENERIC framing.
            if family == WarmBundleFamilyV1::L2vpnEvpn && receives_add_path {
                continue;
            }
            let view = WarmBundleViewV1 {
                kind: WarmBundleViewKindV1::AdjRibInPrePolicy,
                peer,
                peer_asn: session.peer_asn,
                peer_router_id: session.peer_router_id,
                family,
                add_path_receive: receives_add_path,
            };
            policy_inputs.push(WarmBundlePolicyInputV1 {
                view: view.clone(),
                canonical_policy: session.canonical_import_policy.clone(),
            });
            views.push(view);
            rib_views.push(WarmMrtSnapshotView {
                peer,
                session_id: session.session_id,
                peer_asn: session.peer_asn,
                peer_router_id: session.peer_router_id,
                afi,
                safi,
                add_path_receive: receives_add_path,
            });
            if receives_add_path {
                add_path_receive.push(rustbgpd_mrt::codec::MrtAddPathReceiveProfile {
                    peer,
                    afi,
                    safi,
                });
            }
        }
    }

    views.sort();
    if views.is_empty() {
        return Err("warm checkpoint has no eligible peer/family views".to_string());
    }
    if views.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err("warm checkpoint views are not unique".to_string());
    }
    policy_inputs.sort_by(|left, right| left.view.cmp(&right.view));
    rib_views.sort_by_key(WarmMrtSnapshotView::sort_key);
    add_path_receive.sort_by_key(|profile| (profile.peer, profile.afi as u16, profile.safi as u8));

    Ok(WarmCheckpointPlan {
        views,
        rib_views,
        policy_inputs,
        add_path_receive,
    })
}

fn effective_config_sha256(effective_redacted_toml: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(effective_redacted_toml.as_bytes());
    format!("{:x}", digest.finalize())
}

async fn publish_warm_checkpoint(
    capture: WarmCheckpointCapture,
    rib_query_tx: &mpsc::Sender<RibUpdate>,
    directory: Arc<WarmBundleDirectory>,
    deadline: StdInstant,
) -> Result<String, String> {
    publish_warm_checkpoint_bounded(
        capture,
        rib_query_tx,
        directory,
        deadline,
        usize::try_from(MAX_WARM_BUNDLE_SNAPSHOT_BYTES).unwrap_or(usize::MAX),
    )
    .await
}

async fn publish_warm_checkpoint_bounded(
    capture: WarmCheckpointCapture,
    rib_query_tx: &mpsc::Sender<RibUpdate>,
    directory: Arc<WarmBundleDirectory>,
    deadline: StdInstant,
    max_snapshot_bytes: usize,
) -> Result<String, String> {
    let plan = build_warm_checkpoint_plan(&capture.sessions)?;

    let (rib_reply, rib_rx) = oneshot::channel();
    let cancelled = Arc::new(AtomicBool::new(false));
    let mut cancel_on_drop = CancelWarmSnapshotOnDrop {
        cancelled: Arc::clone(&cancelled),
        armed: true,
    };
    rib_query_tx
        .send(RibUpdate::QueryWarmMrtSnapshot {
            views: plan.rib_views,
            budget: WarmMrtSnapshotBudget {
                deadline,
                cancelled,
                max_materialized_bytes: max_snapshot_bytes,
            },
            reply: rib_reply,
        })
        .await
        .map_err(|_| "RIB actor exited before warm checkpoint query".to_string())?;
    let snapshot = rib_rx
        .await
        .map_err(|_| "RIB actor dropped warm checkpoint query".to_string())??;
    let now_seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| format!("system clock precedes Unix epoch: {error}"))?
        .as_secs();
    let created_at_utc_seconds = i64::try_from(now_seconds)
        .map_err(|_| "warm checkpoint timestamp exceeds i64".to_string())?;
    let mrt_timestamp = u32::try_from(now_seconds)
        .map_err(|_| "warm checkpoint timestamp exceeds MRT u32".to_string())?;
    let snapshot_revision = WARM_CHECKPOINT_REVISION
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |revision| {
            revision.checked_add(1)
        })
        .map(|prior| prior + 1)
        .map_err(|_| "warm checkpoint revision exhausted".to_string())?;
    let checkpoint_generation = uuid::Uuid::new_v4().simple().to_string();
    let identity = WarmBundleIdentityV1 {
        checkpoint_generation: checkpoint_generation.clone(),
        created_at_utc_seconds,
        snapshot_revision,
        local_asn: capture.local_asn,
        local_router_id: capture.local_router_id,
        peer_index_table_view: checkpoint_generation.clone(),
        config_sha256: effective_config_sha256(&capture.effective_config_toml),
        resolved_import_policy: resolved_import_policy_digest_v1(&plan.policy_inputs)
            .map_err(|error| error.to_string())?,
        views: plan.views,
    };
    let local_router_id = capture.local_router_id;
    let view_name = checkpoint_generation.clone();
    let writer_budget = WarmSnapshotBudget::new(
        deadline,
        Arc::clone(&cancel_on_drop.cancelled),
        max_snapshot_bytes,
    );
    let (writer_reply, writer_rx) = oneshot::channel();
    // Do not use Tokio's blocking pool here. A timed-out spawn_blocking task
    // cannot be cancelled and the runtime waits for it during shutdown,
    // defeating the 30-second terminal bound. This dedicated OS thread is
    // detached if the coordinator deadline fires; dropping this future flips
    // the shared cancellation token. Encoding, validation, hashing, and
    // chunked writes observe that token and the same monotonic deadline, so a
    // late worker stops bounded work and can never bind its generation into a
    // restart marker.
    std::thread::Builder::new()
        .name("warm-checkpoint-writer".to_string())
        .spawn(move || {
            let result = (|| {
                let encoded = rustbgpd_mrt::codec::encode_warm_snapshot_bounded(
                    local_router_id,
                    &view_name,
                    &snapshot.peers,
                    &snapshot.routes,
                    &snapshot.evpn_routes,
                    mrt_timestamp,
                    &plan.add_path_receive,
                    &writer_budget,
                )
                .map_err(|error| error.to_string())?;
                writer_budget.check().map_err(|error| error.to_string())?;
                write_warm_bundle_bounded(directory.as_ref(), identity, &encoded, &writer_budget)
                    .map_err(|error| error.to_string())?;
                Ok::<(), String>(())
            })();
            let _ = writer_reply.send(result);
        })
        .map_err(|error| format!("failed to spawn warm checkpoint writer: {error}"))?;
    writer_rx
        .await
        .map_err(|_| "warm checkpoint writer exited without a result".to_string())??;
    cancel_on_drop.armed = false;
    Ok(checkpoint_generation)
}

struct CancelWarmSnapshotOnDrop {
    cancelled: Arc<AtomicBool>,
    armed: bool,
}

impl Drop for CancelWarmSnapshotOnDrop {
    fn drop(&mut self) {
        if self.armed {
            self.cancelled.store(true, Ordering::Release);
        }
    }
}

async fn query_warm_checkpoint_capture(
    peer_mgr_tx: &mpsc::Sender<PeerManagerCommand>,
) -> Result<WarmCheckpointCapture, String> {
    let (reply, rx) = oneshot::channel();
    peer_mgr_tx
        .send(PeerManagerCommand::QueryWarmCheckpointCapture { reply })
        .await
        .map_err(|_| "peer manager exited before warm checkpoint query".to_string())?;
    rx.await
        .map_err(|_| "peer manager dropped warm checkpoint query".to_string())?
}

fn tcp_ao_listener_key_for_neighbor(
    listen_addr: SocketAddr,
    neighbor: &config::ResolvedNeighbor,
) -> Option<TcpAoListenerKey> {
    let tcp_ao = neighbor.transport_config.tcp_ao.as_ref()?;
    let peer = neighbor.transport_config.remote_addr.ip();
    if listen_addr.is_ipv4() != peer.is_ipv4() {
        return None;
    }
    Some(TcpAoListenerKey {
        owner: TcpAoListenerOwnerKind::Static,
        peer,
        prefix_len: if peer.is_ipv4() { 32 } else { 128 },
        config: tcp_ao.clone(),
    })
}

fn tcp_ao_listener_key_for_dynamic_range(
    listen_addr: SocketAddr,
    range: &config::DynamicNeighborConfig,
) -> Option<TcpAoListenerKey> {
    let tcp_ao = range.tcp_ao.as_ref()?;
    let (peer, prefix_len) = config::effective_prefix_str(&range.prefix)?;
    if listen_addr.is_ipv4() != peer.is_ipv4() {
        return None;
    }
    Some(TcpAoListenerKey {
        owner: TcpAoListenerOwnerKind::Dynamic,
        peer,
        prefix_len,
        config: TcpAoKeyring(
            tcp_ao
                .iter()
                .map(|key| TransportTcpAoConfig {
                    key: key.key.clone().into(),
                    send_id: key.send_id,
                    recv_id: key.recv_id,
                    algorithm: TcpAoAlgorithm::from_linux_name(&key.algorithm)
                        .expect("validated in Config::load"),
                    preferred: key.preferred,
                    deprecated: key.deprecated,
                })
                .collect(),
        ),
    })
}

fn print_config_diff(diff: &config::ConfigDiff) {
    use owo_colors::OwoColorize;

    let reload_header = "Reload-applied changes:".green().to_string();
    let restart_header = "Restart-required changes:".yellow().to_string();
    let add_marker = "+".green().to_string();
    let remove_marker = "-".red().to_string();
    let change_marker = "~".yellow().to_string();
    let restart_marker = "!".yellow().to_string();
    let style = config::ConfigDiffTextStyle {
        reload_header: reload_header.into(),
        restart_header: restart_header.into(),
        add_marker: add_marker.into(),
        remove_marker: remove_marker.into(),
        change_marker: change_marker.into(),
        restart_marker: restart_marker.into(),
        no_changes: "No changes.".into(),
    };
    print!("{}", config::format_config_diff_with_style(diff, &style));
}

async fn trigger_import_validation_refresh(
    peer_mgr_tx: &mpsc::Sender<PeerManagerCommand>,
    dependency: ImportValidationDependency,
) {
    let (reply_tx, reply_rx) = oneshot::channel();
    if peer_mgr_tx
        .send(PeerManagerCommand::SoftResetImportValidationDependents {
            dependency,
            reply: reply_tx,
        })
        .await
        .is_err()
    {
        warn!(
            ?dependency,
            "peer manager unavailable while forwarding validation-cache update"
        );
        return;
    }

    match reply_rx.await {
        Ok(Ok(())) => {}
        Ok(Err(error)) => warn!(
            ?dependency,
            error = %error,
            "validation-cache import refresh reported failures"
        ),
        Err(error) => warn!(
            ?dependency,
            error = %error,
            "validation-cache import refresh reply dropped"
        ),
    }
}

fn print_startup_banner(config: &Config, grpc_listeners: &[GrpcListenerConfig]) {
    let ebgp = config
        .neighbors
        .iter()
        .filter(|n| n.remote_asn != config.global.asn)
        .count();
    let ibgp = config.neighbors.len() - ebgp;
    let peer_groups = config.peer_groups.len();
    let policies = config.policy.definitions.len();
    let neighbor_sets = config.policy.neighbor_sets.len();

    eprintln!();
    eprintln!(
        "  rustbgpd {} | AS {} | router-id {}",
        env!("CARGO_PKG_VERSION"),
        config.global.asn,
        config.global.router_id,
    );

    // Peers
    let mut peer_parts = Vec::new();
    if ebgp > 0 {
        peer_parts.push(format!("{ebgp} eBGP"));
    }
    if ibgp > 0 {
        peer_parts.push(format!("{ibgp} iBGP"));
    }
    let peer_summary = if peer_parts.is_empty() {
        "0 peers (dynamic-only)".to_string()
    } else {
        format!(
            "{} peers ({})",
            config.neighbors.len(),
            peer_parts.join(", ")
        )
    };
    let pg_suffix = if peer_groups > 0 {
        format!(
            " in {peer_groups} peer group{}",
            if peer_groups == 1 { "" } else { "s" }
        )
    } else {
        String::new()
    };
    eprintln!("  |- {peer_summary}{pg_suffix}");

    // Policy
    if policies > 0 || neighbor_sets > 0 {
        let mut parts = Vec::new();
        if policies > 0 {
            parts.push(format!(
                "{policies} named polic{}",
                if policies == 1 { "y" } else { "ies" }
            ));
        }
        if neighbor_sets > 0 {
            parts.push(format!(
                "{neighbor_sets} neighbor set{}",
                if neighbor_sets == 1 { "" } else { "s" }
            ));
        }
        eprintln!("  |- {}", parts.join(", "));
    }
    // Listeners
    for listener in grpc_listeners {
        let label = match &listener.endpoint {
            ListenerEndpoint::Tcp(addr) => format!("grpc: tcp://{addr}"),
            ListenerEndpoint::Uds { path, .. } => format!("grpc: unix://{}", path.display()),
        };
        let auth = if listener.auth_enabled() {
            " (token auth)"
        } else {
            ""
        };
        let access = match listener.access_mode {
            GrpcServerAccessMode::ReadOnly => " (read-only)",
            GrpcServerAccessMode::ReadWrite => "",
        };
        eprintln!("  |- {label}{access}{auth}");
    }

    // Metrics
    if let Some(addr) = config.prometheus_addr() {
        eprintln!("  |- metrics: http://{addr}/metrics");
    }

    // Optional subsystems
    if let Some(ref rpki) = config.rpki {
        let n = rpki.cache_servers.len();
        if n > 0 {
            eprintln!("  |- rpki: {n} cache{}", if n == 1 { "" } else { "s" });
        }
    }
    if let Some(ref bmp) = config.bmp {
        let n = bmp.collectors.len();
        if n > 0 {
            eprintln!("  |- bmp: {n} collector{}", if n == 1 { "" } else { "s" });
        }
    }
    if let Some(ref mrt) = config.mrt {
        eprintln!("  |- mrt: {}", mrt.output_dir);
    }

    eprintln!();
}

fn fatal_startup_error(message: &'static str, error: impl std::fmt::Display) -> ! {
    error!(error = %error, "{message}");
    process::exit(1);
}

/// Map a BFD session state to its gRPC proto enum (ADR-0067).
fn bfd_session_state_to_proto(
    state: rustbgpd_bfd::SessionState,
) -> rustbgpd_api::proto::BfdSessionState {
    use rustbgpd_api::proto::BfdSessionState;
    match state {
        rustbgpd_bfd::SessionState::AdminDown => BfdSessionState::AdminDown,
        rustbgpd_bfd::SessionState::Down => BfdSessionState::Down,
        rustbgpd_bfd::SessionState::Init => BfdSessionState::Init,
        rustbgpd_bfd::SessionState::Up => BfdSessionState::Up,
    }
}

/// Stable `snake_case` name for a BFD diagnostic (RFC 5880 §4.1), for the gRPC
/// surface. Mirrors the names documented on `BfdSession.diagnostic`.
fn bfd_diagnostic_to_str(diag: rustbgpd_bfd::Diagnostic) -> &'static str {
    use rustbgpd_bfd::Diagnostic;
    match diag {
        Diagnostic::None => "none",
        Diagnostic::ControlDetectionTimeExpired => "control_detection_time_expired",
        Diagnostic::EchoFailed => "echo_function_failed",
        Diagnostic::NeighborSignaledDown => "neighbor_signaled_session_down",
        Diagnostic::ForwardingPlaneReset => "forwarding_plane_reset",
        Diagnostic::PathDown => "path_down",
        Diagnostic::ConcatenatedPathDown => "concatenated_path_down",
        Diagnostic::AdministrativelyDown => "administratively_down",
        Diagnostic::ReverseConcatenatedPathDown => "reverse_concatenated_path_down",
        Diagnostic::Reserved(_) => "reserved",
    }
}

/// The `rustbgpd(8)` man page, hand-maintained roff. The daemon's arg
/// parser is hand-rolled (no clap), so this mirrors the `--help` text
/// above — keep the two in sync when adding a flag.
fn man_page() -> String {
    format!(
        r#".TH RUSTBGPD 8 "" "rustbgpd {version}" "System Administration"
.SH NAME
rustbgpd \- API\-first BGP daemon with gRPC control plane
.SH SYNOPSIS
.B rustbgpd
[\fIOPTIONS\fR] [\fICONFIG_PATH\fR]
.SH DESCRIPTION
.B rustbgpd
is a BGP daemon managed through its gRPC API. It loads a TOML
configuration file at startup, speaks BGP on the configured listen
port (179 by default), and exposes a gRPC control plane plus
Prometheus metrics. Day\-to\-day inspection and runtime changes go
through the
.BR rbgp (1)
CLI.
.SH ARGUMENTS
.TP
\fICONFIG_PATH\fR
Path to the TOML config file. Defaults to
\fI/etc/rustbgpd/config.toml\fR.
.SH OPTIONS
.TP
\fB\-\-check\fR
Validate the config and exit without starting the daemon.
.TP
\fB\-\-diff\fR \fIPATH\fR
Compare the config against \fIPATH\fR and show what SIGHUP would
change.
.TP
\fB\-\-json\fR
Output the diff as JSON (only with \fB\-\-diff\fR).
.TP
\fB\-\-init\-config\fR \fIPROFILE\fR
Print a starter config to stdout and exit (requires
\fB\-\-stdout\fR). Profiles: lab, edge.
.TP
\fB\-\-stdout\fR
Write \fB\-\-init\-config\fR output to stdout (the only target for
now).
.TP
\fB\-\-dump\-config\-schema\fR
Print the config JSON Schema to stdout and exit.
.TP
\fB\-\-man\fR
Print this man page (roff) to stdout and exit.
.TP
\fB\-\-version\fR, \fB\-V\fR
Print version and exit.
.TP
\fB\-\-help\fR, \fB\-h\fR
Print the help message.
.SH SIGNALS
.TP
\fBSIGHUP\fR
Reload the configuration file and hot\-apply the changes.
.TP
\fBSIGTERM\fR
Shut down gracefully.
.SH FILES
.TP
\fI/etc/rustbgpd/config.toml\fR
Default configuration file.
.SH SEE ALSO
.BR rbgp (1)
"#,
        version = env!("CARGO_PKG_VERSION")
    )
}

#[expect(clippy::too_many_lines)]
fn main() {
    let args: Vec<String> = std::env::args().collect();

    // Handle --version / -V before anything else.
    if args.iter().any(|a| a == "--version" || a == "-V") {
        println!("rustbgpd {}", env!("CARGO_PKG_VERSION"));
        return;
    }

    // Handle --man: print the roff man page (section 8) to stdout and
    // exit. Render with `rustbgpd --man | man -l -` or install with
    // `rustbgpd --man > /usr/local/share/man/man8/rustbgpd.8`.
    if args.iter().any(|a| a == "--man") {
        print!("{}", man_page());
        return;
    }

    // Handle --help / -h.
    if args.iter().any(|a| a == "--help" || a == "-h") {
        println!(
            "rustbgpd {} — API-first BGP daemon\n\n\
             Usage: rustbgpd [OPTIONS] [CONFIG_PATH]\n\n\
             Arguments:\n  \
               CONFIG_PATH  Path to TOML config file [default: /etc/rustbgpd/config.toml]\n\n\
             Options:\n  \
               --check               Validate config and exit without starting the daemon\n  \
               --diff PATH           Compare config against PATH and show what SIGHUP would change\n  \
               --json                Output diff as JSON (only with --diff)\n  \
               --init-config PROFILE Print a starter config to stdout and exit (needs --stdout).\n                        \
                                     Profiles: lab, edge\n  \
               --stdout              Write --init-config output to stdout (the only target for now)\n  \
               --dump-config-schema  Print the config JSON Schema to stdout and exit\n  \
               --man                 Print the man page (roff) to stdout and exit\n  \
               --version             Print version and exit\n  \
               --help                Print this help message",
            env!("CARGO_PKG_VERSION")
        );
        return;
    }

    // Parse flags and config path from remaining args.
    let mut check_only = false;
    let mut diff_path: Option<String> = None;
    let mut json_output = false;
    let mut init_profile: Option<String> = None;
    let mut to_stdout = false;
    let mut dump_schema = false;
    let mut config_path = "/etc/rustbgpd/config.toml".to_string();
    let mut expect_diff_path = false;
    let mut expect_init_profile = false;
    for arg in &args[1..] {
        if expect_diff_path {
            diff_path = Some(arg.clone());
            expect_diff_path = false;
        } else if expect_init_profile {
            init_profile = Some(arg.clone());
            expect_init_profile = false;
        } else if arg == "--check" {
            check_only = true;
        } else if arg == "--diff" {
            expect_diff_path = true;
        } else if arg == "--json" {
            json_output = true;
        } else if arg == "--init-config" {
            expect_init_profile = true;
        } else if arg == "--stdout" {
            to_stdout = true;
        } else if arg == "--dump-config-schema" {
            dump_schema = true;
        } else if !arg.starts_with('-') {
            config_path.clone_from(arg);
        } else {
            eprintln!("error: unknown option: {arg}");
            eprintln!(
                "usage: rustbgpd [--check] [--diff PATH] [--json] [--init-config PROFILE --stdout] [--dump-config-schema] [--version] [CONFIG_PATH]"
            );
            process::exit(1);
        }
    }
    if expect_diff_path {
        eprintln!("error: --diff requires a path argument");
        process::exit(2);
    }
    if expect_init_profile {
        eprintln!(
            "error: --init-config requires a profile name (one of: {})",
            crate::config::profiles::PROFILE_NAMES.join(", ")
        );
        process::exit(2);
    }
    if json_output && diff_path.is_none() {
        eprintln!("error: --json can only be used with --diff");
        process::exit(2);
    }
    // `--stdout` is only the `--init-config` output target. Without it,
    // a bare `--stdout` would otherwise fall through to normal daemon
    // startup (silently, on a box with /etc/rustbgpd/config.toml).
    if to_stdout && init_profile.is_none() {
        eprintln!("error: --stdout can only be used with --init-config");
        process::exit(2);
    }
    // `--init-config` is a standalone mode, not a modifier on a daemon
    // run — reject combining it with the other one-shot modes rather
    // than silently letting init win and ignoring them.
    if init_profile.is_some() && (check_only || diff_path.is_some()) {
        eprintln!("error: --init-config cannot be combined with --check or --diff");
        process::exit(2);
    }
    // `--dump-config-schema` is a standalone mode, like `--init-config`:
    // reject combining it rather than silently letting one mode win.
    if dump_schema {
        if check_only || diff_path.is_some() || init_profile.is_some() || to_stdout {
            eprintln!("error: --dump-config-schema cannot be combined with other modes");
            process::exit(2);
        }
        print!("{}", config::config_json_schema());
        return;
    }

    // `--init-config PROFILE --stdout` prints a curated starter config and
    // exits — handled before loading any runtime config, since config
    // generation must work before a config file (or daemon) exists.
    if let Some(profile) = init_profile {
        if !to_stdout {
            eprintln!(
                "error: --init-config currently requires --stdout (file output is not yet supported)"
            );
            process::exit(2);
        }
        let Some(toml) = crate::config::profiles::profile_toml(&profile) else {
            eprintln!(
                "error: unknown profile {profile:?}; available: {}",
                crate::config::profiles::PROFILE_NAMES.join(", ")
            );
            process::exit(2);
        };
        // Self-check: the built-in template must validate. A failure here
        // is a bug in the profile, not operator error — fail loud so it's
        // never emitted as broken bootstrap.
        if let Err(diagnostic) =
            Config::load_toml_with_diagnostics(toml, &format!("--init-config {profile}"))
        {
            eprintln!(
                "internal error: built-in profile {profile:?} failed validation:\n{diagnostic}"
            );
            process::exit(70);
        }
        print!("{toml}");
        return;
    }

    // Removed escape hatch: fail loudly rather than silently ignoring it,
    // so automation still setting the variable can't restart into changed
    // adoption behavior unnoticed. Any value (even "0") is an error.
    if std::env::var_os("RUSTBGPD_EVPN_ADOPTION_ACCEPT_LEGACY").is_some() {
        eprintln!(
            "error: RUSTBGPD_EVPN_ADOPTION_ACCEPT_LEGACY is set, but this escape hatch \
             has been removed: the EVPN L3 legacy-adoption migration window closed at \
             v0.38.0 (ADR-0082). Unset the variable; for the skip-version upgrade path \
             see docs/evpn-vtep-troubleshooting.md, \"Crash-restart adoption across \
             upgrades (ADR-0082)\"."
        );
        process::exit(1);
    }

    let mut config = match Config::load_with_diagnostics(&config_path) {
        Ok(c) => c,
        Err(diagnostic) => {
            eprintln!("{diagnostic}");
            process::exit(1);
        }
    };

    if check_only {
        println!("config OK: {config_path}");
        return;
    }

    if let Some(ref diff_target) = diff_path {
        let new_config = match Config::load_with_diagnostics(diff_target) {
            Ok(c) => c,
            Err(diagnostic) => {
                eprintln!("{diagnostic}");
                process::exit(2);
            }
        };
        let diff = config::diff_config(&config, &new_config);
        if json_output {
            let output = config::config_diff_json_value(&diff);
            match serde_json::to_string_pretty(&output) {
                Ok(json) => println!("{json}"),
                Err(e) => {
                    eprintln!("error: failed to serialize diff: {e}");
                    process::exit(2);
                }
            }
        } else {
            print_config_diff(&diff);
        }
        process::exit(i32::from(diff.has_actionable_changes()));
    }

    // Durable commit-confirm (ADR-0076 Decision 6): if the last run stopped
    // inside a commit-confirmed window, an unconfirmed revert journal exists
    // and the on-disk config is the unconfirmed candidate. Revert BEFORE the
    // daemon adopts it — otherwise a config bad enough to crash the daemon
    // would become permanent via the crash ("confirmed-by-restart"). A
    // journal that exists but cannot drive a revert refuses boot (fail
    // closed). Runs only for real daemon startup: --check/--diff returned
    // above and must never mutate config files.
    let boot_revert_notice = match confirm_journal::boot_revert_check(
        &confirm_journal::journal_path(&config.runtime_state_dir()),
        Path::new(&config_path),
    ) {
        Ok(None) => None,
        Ok(Some(revert)) => {
            config = *revert.config;
            Some(revert.notice)
        }
        Err(message) => {
            eprintln!("error: {message}");
            process::exit(1);
        }
    };

    let log_directives = config.per_peer_log_directives();
    if let Err(e) = init_logging(&log_directives) {
        eprintln!("error: failed to initialize logging: {e}");
        process::exit(1);
    }

    // Panic hygiene: write a bounded, secret-free crash report under
    // `<runtime_state_dir>/crash/` for `rbgp doctor` to sweep into
    // support bundles. Installed after config resolution so reports
    // land under the operator's runtime_state_dir.
    install_panic_hook(config.runtime_state_dir().join("crash"));

    #[cfg(feature = "dhat-heap")]
    let profiler = Some(
        dhat::Profiler::builder()
            .file_name("dhat-heap.json")
            .build(),
    );
    #[cfg(not(feature = "dhat-heap"))]
    let profiler: Option<()> = None;

    let worker_threads = resolve_worker_threads(config.global.worker_threads);
    info!(worker_threads, "initializing tokio runtime");
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(worker_threads)
        .enable_all()
        .build()
        .unwrap_or_else(|e| fatal_startup_error("failed to create tokio runtime", e));
    rt.block_on(run(config, boot_revert_notice, profiler));
}

/// Number of panic reports retained in `<runtime_state_dir>/crash/`;
/// older reports are pruned on every write.
const PANIC_REPORTS_KEPT: usize = 10;

/// Shape of one `crash/panic-<ts>.toml` report (human-panic pattern:
/// message, location, thread, version, timestamp only — never env vars
/// or argv, which could carry secrets).
#[derive(Serialize)]
struct PanicReport<'a> {
    message: &'a str,
    location: &'a str,
    thread: &'a str,
    version: &'a str,
    timestamp_unix_seconds: u64,
}

/// Install a global panic hook that writes a panic report under
/// `crash_dir` before delegating to the previous hook (the default
/// stderr backtrace). `rbgp doctor` sweeps these reports into support
/// bundles.
fn install_panic_hook(crash_dir: std::path::PathBuf) {
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let message = info
            .payload()
            .downcast_ref::<&str>()
            .map(|s| (*s).to_string())
            .or_else(|| info.payload().downcast_ref::<String>().cloned())
            .unwrap_or_else(|| "non-string panic payload".to_string());
        let location = info.location().map(ToString::to_string).unwrap_or_default();
        let thread = std::thread::current()
            .name()
            .unwrap_or("unnamed")
            .to_string();
        // Best-effort: a failing report write must never mask the panic.
        let _ = write_panic_report(&crash_dir, &message, &location, &thread);
        previous(info);
    }));
}

/// Write one panic report and prune the crash directory to the most
/// recent [`PANIC_REPORTS_KEPT`] reports.
fn write_panic_report(
    crash_dir: &Path,
    message: &str,
    location: &str,
    thread: &str,
) -> std::io::Result<()> {
    std::fs::create_dir_all(crash_dir)?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let report = PanicReport {
        message,
        location,
        thread,
        version: env!("CARGO_PKG_VERSION"),
        timestamp_unix_seconds: now.as_secs(),
    };
    let body = toml::to_string(&report).map_err(std::io::Error::other)?;
    // Zero-padded seconds + millisecond suffix: lexicographic order is
    // chronological, and near-simultaneous panicking threads rarely
    // clobber each other (last write wins if they do).
    let path = crash_dir.join(format!(
        "panic-{:010}-{:03}.toml",
        now.as_secs(),
        now.subsec_millis()
    ));
    std::fs::write(path, body)?;
    prune_panic_reports(crash_dir);
    Ok(())
}

/// Remove the oldest `panic-*.toml` reports beyond [`PANIC_REPORTS_KEPT`].
fn prune_panic_reports(crash_dir: &Path) {
    let Ok(entries) = std::fs::read_dir(crash_dir) else {
        return;
    };
    let mut names: Vec<String> = entries
        .flatten()
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|n| {
            n.starts_with("panic-")
                && Path::new(n)
                    .extension()
                    .is_some_and(|ext| ext.eq_ignore_ascii_case("toml"))
        })
        .collect();
    names.sort();
    while names.len() > PANIC_REPORTS_KEPT {
        let oldest = names.remove(0);
        let _ = std::fs::remove_file(crash_dir.join(oldest));
    }
}

/// Default tokio worker-thread cap when neither env nor config specifies one.
const DEFAULT_WORKER_THREAD_CAP: usize = 8;

/// Resolve the tokio worker-thread count: `RUSTBGPD_WORKER_THREADS` (if a
/// positive integer) overrides the `[global] worker_threads` config field,
/// which in turn overrides the default of `min(available parallelism, 8)`.
/// A zero or unparseable value is ignored in favor of the next source. The
/// cap right-sizes the async runtime for an I/O-bound daemon — reducing
/// virtual-address reservation and scheduler footprint (it is RSS-neutral)
/// rather than spawning one worker per core on high-core-count hosts.
fn resolve_worker_threads(configured: Option<usize>) -> usize {
    let env = match std::env::var("RUSTBGPD_WORKER_THREADS") {
        Ok(value) => Some(value),
        Err(std::env::VarError::NotPresent) => None,
        Err(std::env::VarError::NotUnicode(_)) => {
            warn!("ignoring non-unicode RUSTBGPD_WORKER_THREADS");
            None
        }
    };
    resolve_worker_threads_from(env, configured)
}

/// Pure core of [`resolve_worker_threads`] with the environment value injected,
/// so the precedence (env > config > capped default) is unit-testable without
/// touching process-global env state.
fn resolve_worker_threads_from(env: Option<String>, configured: Option<usize>) -> usize {
    if let Some(raw) = env {
        match raw.trim().parse::<usize>() {
            Ok(n) if n > 0 => return n,
            // An explicit `0` means "unset" — fall through silently.
            Ok(_) => {}
            Err(_) => warn!(
                value = %raw,
                "ignoring invalid RUSTBGPD_WORKER_THREADS (expected a positive integer)"
            ),
        }
    }
    if let Some(n) = configured.filter(|n| *n > 0) {
        return n;
    }
    std::thread::available_parallelism()
        .map_or(1, std::num::NonZeroUsize::get)
        .min(DEFAULT_WORKER_THREAD_CAP)
}

/// Production capacity of the transport→RIB update channel. ADR-0078
/// made overflow a pacing knob (session tasks block, never drop), so
/// this bounds in-flight inbound work, not correctness.
const RIB_CHANNEL_CAPACITY: usize = 4096;

/// Test-only override for [`RIB_CHANNEL_CAPACITY`] (ADR-0078 fault
/// injection). Filling the production 4096-slot channel against a real
/// peer would need thousands of in-flight UPDATE batches; the M63
/// interop smoke shrinks the channel so a modest stalled flood
/// saturates it deterministically and the block-never-drop path is
/// observable. Never set this in production. Read once at startup;
/// unset, zero, or unparseable values keep the production capacity.
const TEST_RIB_CHANNEL_CAPACITY_ENV: &str = "RUSTBGPD_TEST_RIB_CHANNEL_CAPACITY";

/// Resolve the RIB channel capacity: [`TEST_RIB_CHANNEL_CAPACITY_ENV`]
/// (if a positive integer) overrides the production default.
fn resolve_rib_channel_capacity() -> usize {
    let env = match std::env::var(TEST_RIB_CHANNEL_CAPACITY_ENV) {
        Ok(value) => Some(value),
        Err(std::env::VarError::NotPresent) => None,
        Err(std::env::VarError::NotUnicode(_)) => {
            warn!("ignoring non-unicode {TEST_RIB_CHANNEL_CAPACITY_ENV}");
            None
        }
    };
    let capacity = resolve_rib_channel_capacity_from(env.as_deref());
    if capacity != RIB_CHANNEL_CAPACITY {
        warn!(
            capacity,
            "{TEST_RIB_CHANNEL_CAPACITY_ENV} active: RIB channel capacity overridden \
             (ADR-0078 fault injection — test use only, never set in production)"
        );
    }
    capacity
}

/// Pure core of [`resolve_rib_channel_capacity`] with the environment
/// value injected, so the parse rule (positive usize → override,
/// anything else → production default) is unit-testable without
/// touching process-global env state.
fn resolve_rib_channel_capacity_from(env: Option<&str>) -> usize {
    if let Some(raw) = env {
        match raw.trim().parse::<usize>() {
            Ok(n) if n > 0 => return n,
            Ok(_) => {}
            Err(_) => warn!(
                value = %raw,
                "ignoring invalid {TEST_RIB_CHANNEL_CAPACITY_ENV} (expected a positive integer)"
            ),
        }
    }
    RIB_CHANNEL_CAPACITY
}

#[expect(clippy::too_many_lines)]
async fn run<T>(
    mut config: Config,
    boot_revert_notice: Option<confirm_journal::BootRevertNotice>,
    profiler: Option<T>,
) {
    // Snapshot the gRPC listener config as it was at process start.
    // The live TCP/UDS listeners bind once and are not rebuilt on
    // SIGHUP; this snapshot is what they're actually serving. Reload
    // compares the new declared config against THIS snapshot (not
    // against the in-memory mutable `config`) so drift between
    // declared listener config and live state stays visible across
    // every reload, not just the first one. The runtime config is
    // patched on reload to keep these two listener fields equal to
    // the live state — no other reload semantics change.
    let live_grpc_tcp = config.global.telemetry.grpc_tcp.clone();
    let live_grpc_uds = config.global.telemetry.grpc_uds.clone();

    let start_time = tokio::time::Instant::now();
    let gr_restart_marker_path = config.gr_restart_marker_path();
    let runtime_state_path = config.runtime_state_dir();
    // Pin the shared authority before either marker or bundle access. Unsafe
    // owner/mode or a final symlink disables both paths fail closed.
    let runtime_state_directory = match PinnedRuntimeStateDirectory::prepare(&runtime_state_path) {
        Ok(directory) => Some(Arc::new(directory)),
        Err(error) => {
            warn!(
                path = %runtime_state_path.display(),
                %error,
                "runtime-state marker/checkpoint storage unavailable"
            );
            None
        }
    };
    let gr_restart_marker_store = runtime_state_directory
        .as_ref()
        .map(|directory| GrRestartMarkerStore::new(Arc::clone(directory)));
    // This knob and child name are restart-required. Open the bundle relative
    // to the same verified descriptor as the marker.
    let warm_checkpoint_on_shutdown = config.global.warm_cache_checkpoint_on_shutdown;
    let warm_bundle_path = config.warm_bundle_dir();
    let warm_bundle_directory = if warm_checkpoint_on_shutdown {
        match runtime_state_directory
            .as_ref()
            .ok_or_else(|| "runtime-state directory is unavailable".to_string())
            .and_then(|directory| directory.prepare_warm_bundle())
        {
            Ok(directory) => {
                match directory.scavenge_owned_entries() {
                    Ok(report) if report.failed() > 0 => {
                        warn!(
                            path = %warm_bundle_path.display(),
                            removed = report.removed(),
                            failed = report.failed(),
                            first_error = %report
                                .first_failure()
                                .expect("failed cleanup has a first error"),
                            "warm checkpoint startup cleanup left some stale entries"
                        );
                    }
                    Ok(report) if report.removed() > 0 => {
                        info!(
                            path = %warm_bundle_path.display(),
                            removed = report.removed(),
                            "removed stale warm checkpoint entries at startup"
                        );
                    }
                    Ok(_) => {}
                    Err(error) => {
                        warn!(
                            path = %warm_bundle_path.display(),
                            %error,
                            "warm checkpoint startup cleanup was skipped; shutdown publication remains available"
                        );
                    }
                }
                info!(
                    path = %warm_bundle_path.display(),
                    "prepared daemon-private warm checkpoint directory"
                );
                Some(Arc::new(directory))
            }
            Err(error) => {
                warn!(
                    path = %warm_bundle_path.display(),
                    %error,
                    "warm checkpoint publication unavailable; coordinated shutdown will retain a generationless GR marker"
                );
                None
            }
        }
    } else {
        None
    };
    let mut inherited_gr_restart_marker = None;
    let local_gr_restart_until = match gr_restart_marker_store
        .as_ref()
        .map_or(Ok(None), GrRestartMarkerStore::read)
    {
        Ok(Some(marker)) => {
            let max_restart_time_secs = max_gr_restart_time_secs(&config);
            if let Some(resolution) = resolve_gr_restart_marker(
                &marker,
                SystemTime::now(),
                sample_gr_restart_clock(),
                max_restart_time_secs,
            ) {
                let deadline = StdInstant::now() + resolution.remaining;
                info!(
                    marker = %gr_restart_marker_path.display(),
                    marker_version = marker.version,
                    restart_time_secs = resolution.remaining.as_secs(),
                    expiry_clock = resolution.authority.as_str(),
                    clock_fallback_reason = resolution.fallback_reason.as_deref().unwrap_or("none"),
                    checkpoint_generation = marker.checkpoint_generation.as_deref().unwrap_or("none"),
                    "detected GR restart marker — static peers will advertise R=1 until the restart window expires"
                );
                inherited_gr_restart_marker = Some(marker);
                Some(deadline)
            } else {
                info!(
                    marker = %gr_restart_marker_path.display(),
                    "ignoring expired or unusable GR restart marker"
                );
                if let Some(store) = gr_restart_marker_store.as_ref()
                    && let Err(e) = store.remove()
                {
                    warn!(
                        marker = %gr_restart_marker_path.display(),
                        error = %e,
                        "failed to remove expired or unusable GR restart marker"
                    );
                }
                None
            }
        }
        Ok(None) => None,
        Err(e) => {
            warn!(
                marker = %gr_restart_marker_path.display(),
                error = %e,
                "ignoring invalid GR restart marker — starting without restarting-speaker mode"
            );
            if let Some(store) = gr_restart_marker_store.as_ref()
                && let Err(remove_err) = store.remove()
            {
                warn!(
                    marker = %gr_restart_marker_path.display(),
                    error = %remove_err,
                    "failed to remove malformed GR restart marker"
                );
            }
            None
        }
    };

    if let (Some(deadline), Some(expected_marker)) =
        (local_gr_restart_until, inherited_gr_restart_marker)
    {
        let marker_store = gr_restart_marker_store
            .as_ref()
            .expect("a read marker always has a pinned store")
            .clone();
        let marker_path = marker_store.display_path();
        let sleep_for = deadline.saturating_duration_since(StdInstant::now());
        tokio::spawn(async move {
            tokio::time::sleep(sleep_for).await;
            match marker_store.remove_if_matches(&expected_marker) {
                Ok(true) => {}
                Ok(false) => info!(
                    marker = %marker_path.display(),
                    "retained replacement GR restart marker after inherited expiry"
                ),
                Err(e) => {
                    warn!(
                        marker = %marker_path.display(),
                        error = %e,
                        "failed to remove expired GR restart marker"
                    );
                }
            }
        });
    }

    info!(
        version = env!("CARGO_PKG_VERSION"),
        asn = config.global.asn,
        router_id = %config.global.router_id,
        neighbors = config.neighbors.len(),
        "starting rustbgpd"
    );
    config.warn_if_legacy_grpc_enforcement();

    let metrics = BgpMetrics::new();
    let grpc_listeners = resolve_grpc_listeners(&config).unwrap_or_else(|e| {
        error!(error = %e, "invalid gRPC listener configuration");
        process::exit(1);
    });
    let grpc_credentials = grpc_listeners
        .first()
        .map(GrpcListenerConfig::credential_store);

    // Startup banner — human-friendly topology summary on stderr.
    print_startup_banner(&config, &grpc_listeners);
    if let Some(notice) = &boot_revert_notice {
        // Boot-time revert of an unconfirmed commit-confirmed transaction
        // (ADR-0076 Decision 6). Loud on purpose: the operator's last change
        // was undone and its candidate saved aside.
        error!(
            confirm_id = %notice.confirm_id,
            unconfirmed_candidate = %notice.backup_path.display(),
            rollback_failed = notice.rollback_failed,
            "commit-confirmed transaction was never confirmed before the last shutdown — reverted to the pre-transaction config at boot; the unconfirmed candidate config was saved aside"
        );
        eprintln!(
            "!! commit-confirm boot revert: transaction {:?} was never confirmed before the last shutdown.",
            notice.confirm_id
        );
        if notice.rollback_failed {
            // The journal recorded a live rollback FAILURE for this
            // transaction: before this restart the runtime, the on-disk
            // config, and the journal were three-way inconsistent.
            eprintln!(
                "!! A live rollback of this transaction FAILED before the restart, so the pre-restart on-disk state was uncertain."
            );
        }
        eprintln!(
            "!! Booted from the pre-transaction config; the unconfirmed candidate was saved to {}.",
            notice.backup_path.display()
        );
        // A `BootRevertNotice` only exists when the revert fully succeeded
        // (config restored AND journal consumed); a journal-cleanup failure
        // fails startup upstream (LAN-219), so there is no failure branch here.
        metrics.record_config_transaction_lifecycle("boot_revert", "success");
    }
    let router_id: Ipv4Addr = config.global.router_id.parse().unwrap_or_else(|e| {
        error!(
            router_id = %config.global.router_id,
            error = %e,
            "invalid router-id after configuration validation"
        );
        process::exit(1);
    });
    // Resolve the complete static-peer set before the RIB actor or any BGP
    // session starts. RFC 4724 restarting-speaker deferral must freeze this
    // roster up front; discovering peers incrementally after the first EoR
    // can release selection prematurely in a multi-peer topology.
    let peer_configs = config.resolved_neighbors().unwrap_or_else(|e| {
        error!("invalid policy configuration: {e}");
        process::exit(1);
    });

    // ── ADR-0072: Durable event outbox (EventHistoryManager) ───────
    //
    // Spawned before any producer so the handle is available when
    // constructing the RIB sink + plumbing into PeerManager,
    // EventService, and the BFD bridge. On start failure the
    // behavior depends on `[event_history].required`: required=true
    // bails out; required=false logs an error, flips the degraded
    // gauge, and continues in live-only mode (SubscribeFromEvent
    // returns FAILED_PRECONDITION while the rest of the live
    // surface keeps working).
    let (event_history_manager, event_history_handle) = if config.event_history.enabled {
        let ehm_config = build_event_history_config(&config, &metrics);
        match rustbgpd_event_history::EventHistoryManager::start(ehm_config).await {
            Ok(mgr) => {
                let handle = mgr.handle();
                info!(
                    path = %config.event_history_db_path().display(),
                    "event history manager started",
                );
                (Some(mgr), Some(handle))
            }
            Err(e) if config.event_history.required => {
                error!(
                    error = %e,
                    path = %config.event_history_db_path().display(),
                    "[event_history].required = true but EHM failed to start"
                );
                process::exit(1);
            }
            Err(e) => {
                error!(
                    error = %e,
                    path = %config.event_history_db_path().display(),
                    "event_history open failed; continuing in live-only mode"
                );
                metrics.record_event_outbox_open_failure();
                (None, None)
            }
        }
    } else {
        info!("event history disabled via [event_history].enabled = false");
        (None, None)
    };

    // Build global export policy chain for RIB manager fallback
    let export_policy = config.export_chain().unwrap_or_else(|e| {
        error!("invalid global export policy: {e}");
        process::exit(1);
    });

    // Spawn RIB manager. When EHM is enabled, install an EHM-backed
    // event sink so route + EVPN events flow into the durable
    // outbox alongside the existing process-local ring + broadcast.
    let cluster_id = config.cluster_id();
    let (rib_tx, rib_rx) = mpsc::channel::<RibUpdate>(resolve_rib_channel_capacity());
    let (rib_query_tx, rib_query_rx) = mpsc::channel::<RibUpdate>(256);
    let (rib_readiness_tx, rib_readiness_rx) = mpsc::channel::<rustbgpd_rib::RibReadinessQuery>(64);

    // Spawn BMP subsystem (manager + per-collector clients). Spawned
    // before the RIB manager so the RFC 9069 Loc-RIB tap and the
    // collector-connect table-dump forwarder can be wired into both.
    let mut bmp_runtime: Option<BmpRuntime> = None;
    let mut bmp_loc_rib_tx: Option<mpsc::Sender<rustbgpd_bmp::BmpEvent>> = None;
    let bmp_tx = if let Some(ref bmp_config) = config.bmp
        && !bmp_config.collectors.is_empty()
    {
        let (bmp_event_tx, bmp_event_rx) = mpsc::channel(4096);
        let (bmp_control_tx, bmp_control_rx) = mpsc::channel(256);
        let sys_name = bmp_config.sys_name.clone();
        let sys_descr = if bmp_config.sys_descr.is_empty() {
            format!("rustbgpd {}", env!("CARGO_PKG_VERSION"))
        } else {
            bmp_config.sys_descr.clone()
        };

        let mut collectors: Vec<(
            std::net::SocketAddr,
            mpsc::Sender<bytes::Bytes>,
            rustbgpd_bmp::BmpMonitorFilter,
            rustbgpd_bmp::BmpVersion,
        )> = Vec::new();
        let mut client_handles = Vec::new();
        for collector in &bmp_config.collectors {
            let addr: std::net::SocketAddr = match collector.address.parse() {
                Ok(a) => a,
                Err(e) => {
                    error!(
                        address = %collector.address,
                        error = %e,
                        "invalid BMP collector address — skipping"
                    );
                    continue;
                }
            };
            let (msg_tx, msg_rx) = mpsc::channel(4096);
            let collector_id = collectors.len();
            let filter = rustbgpd_bmp::BmpMonitorFilter {
                rib_in_pre: collector
                    .monitor
                    .contains(&config::BmpMonitorView::RibInPre),
                rib_out_post: collector
                    .monitor
                    .contains(&config::BmpMonitorView::RibOutPost),
                loc_rib: collector.monitor.contains(&config::BmpMonitorView::LocRib),
            };
            // Validation pins collector.version to 3 | 4.
            let version = if collector.version == 4 {
                rustbgpd_bmp::BmpVersion::V4
            } else {
                rustbgpd_bmp::BmpVersion::V3
            };
            collectors.push((addr, msg_tx, filter, version));
            let client = rustbgpd_bmp::BmpClient::new(
                rustbgpd_bmp::BmpClientConfig {
                    collector_id,
                    collector_addr: addr,
                    reconnect_interval: collector.reconnect_interval,
                    version,
                },
                msg_rx,
                sys_name.clone(),
                sys_descr.clone(),
                Some(bmp_control_tx.clone()),
                metrics.clone(),
            );
            info!(collector = %addr, "spawning BMP client");
            client_handles.push(tokio::spawn(client.run()));
        }

        let loc_rib_enabled = collectors.iter().any(|(_, _, filter, _)| filter.loc_rib);
        let mut mgr = rustbgpd_bmp::BmpManager::new(
            bmp_event_rx,
            bmp_control_rx,
            collectors,
            metrics.clone(),
        );
        if loc_rib_enabled {
            // RFC 9069 Loc-RIB monitoring: fabricate the emulated
            // instance-peer identity and bridge the manager's
            // collector-connect dump requests onto the RIB manager's
            // priority query channel.
            let open_pdu = rustbgpd_rib::bmp_sync::loc_rib_open_pdu(config.global.asn, router_id);
            let (dump_tx, mut dump_rx) = mpsc::channel::<rustbgpd_bmp::BmpDumpRequest>(8);
            let dump_rib_tx = rib_query_tx.clone();
            tokio::spawn(async move {
                while let Some(request) = dump_rx.recv().await {
                    if dump_rib_tx
                        .send(RibUpdate::QueryBmpLocRibDump {
                            cursor: request.cursor,
                            reply: request.reply,
                        })
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
            });
            mgr = mgr.with_loc_rib(
                rustbgpd_bmp::BmpLocRibConfig {
                    local_asn: config.global.asn,
                    router_id,
                    open_pdu,
                },
                dump_tx,
            );
            bmp_loc_rib_tx = Some(bmp_event_tx.clone());
        }
        let manager_handle = tokio::spawn(mgr.run());
        bmp_runtime = Some(BmpRuntime {
            control_tx: bmp_control_tx,
            manager_handle,
            client_handles,
        });

        Some(bmp_event_tx)
    } else {
        None
    };

    let mut rib_manager = RibManager::new(
        rib_rx,
        rib_query_rx,
        export_policy,
        cluster_id,
        metrics.clone(),
    )
    .with_readiness_queries(rib_readiness_rx);
    if let Some(deadline) = local_gr_restart_until {
        let waiters = peer_configs
            .iter()
            .filter(|neighbor| neighbor.transport_config.peer.graceful_restart)
            .map(|neighbor| rustbgpd_rib::SelectionDeferralWaiterConfig {
                peer: neighbor.transport_config.remote_addr.ip(),
                families: neighbor
                    .transport_config
                    .peer
                    .effective_families()
                    .into_iter()
                    .filter(|family| rustbgpd_fsm::graceful_restart_preserves_family(*family))
                    .collect(),
            })
            .collect();
        rib_manager = rib_manager.with_selection_deferral(rustbgpd_rib::SelectionDeferralConfig {
            timeout: deadline.saturating_duration_since(StdInstant::now()),
            waiters,
        });
    }
    if let Some(tx) = bmp_loc_rib_tx {
        rib_manager = rib_manager.with_bmp_tx(tx);
    }
    if let Some(handle) = event_history_handle.clone() {
        rib_manager = rib_manager.with_event_sink(
            rustbgpd_api::event_history_sinks::make_rib_event_sink(handle, metrics.clone()),
        );
    }
    tokio::spawn(rib_manager.run());

    // Validation snapshot channel: broadcast VRP + ASPA tables to transport
    // sessions for import-time route validation.  Starts empty — sessions fall
    // back to NotFound/Unknown until the first cache update arrives.
    let (validation_watch_tx, validation_watch_rx) =
        tokio::sync::watch::channel(rustbgpd_rpki::ValidationSnapshot::default());

    let (peer_mgr_tx, peer_mgr_rx) = mpsc::channel::<PeerManagerCommand>(64);
    let (peer_mgr_readiness_tx, peer_mgr_readiness_rx) =
        mpsc::channel::<PeerManagerReadinessQuery>(64);
    let (peer_mgr_internal_tx, peer_mgr_internal_rx) = mpsc::unbounded_channel();

    // Spawn RPKI subsystem (VRP manager + per-cache RTR clients)
    if let Some(ref rpki_config) = config.rpki
        && !rpki_config.cache_servers.is_empty()
    {
        let (vrp_update_tx, vrp_update_rx) = mpsc::channel(256);
        let (rpki_table_tx, mut rpki_table_rx) = mpsc::channel(16);

        // ASPA table channel (VrpManager → RIB)
        let (aspa_table_tx, mut aspa_table_rx) = mpsc::channel(16);

        // Spawn VRP + ASPA manager
        let vrp_mgr = rustbgpd_rpki::VrpManager::new(vrp_update_rx, rpki_table_tx)
            .with_aspa_tx(aspa_table_tx);
        tokio::spawn(vrp_mgr.run());

        // Forward VRP table updates to RIB manager + validation watch
        let rpki_rib_tx = rib_tx.clone();
        let rpki_peer_mgr_tx = peer_mgr_tx.clone();
        let validation_tx_vrp = validation_watch_tx.clone();
        tokio::spawn(async move {
            while let Some(update) = rpki_table_rx.recv().await {
                validation_tx_vrp.send_modify(|snapshot| {
                    snapshot.vrp_table = Some(std::sync::Arc::clone(&update.table));
                });
                let _ = rpki_rib_tx
                    .send(RibUpdate::RpkiCacheUpdate {
                        table: update.table,
                    })
                    .await;
                trigger_import_validation_refresh(
                    &rpki_peer_mgr_tx,
                    ImportValidationDependency::Rpki,
                )
                .await;
            }
        });

        // Forward ASPA table updates to RIB manager + validation watch
        let aspa_rib_tx = rib_tx.clone();
        let aspa_peer_mgr_tx = peer_mgr_tx.clone();
        let validation_tx_aspa = validation_watch_tx.clone();
        tokio::spawn(async move {
            while let Some(update) = aspa_table_rx.recv().await {
                validation_tx_aspa.send_modify(|snapshot| {
                    snapshot.aspa_table = Some(std::sync::Arc::clone(&update.table));
                });
                let _ = aspa_rib_tx
                    .send(RibUpdate::AspaTableUpdate {
                        table: update.table,
                    })
                    .await;
                trigger_import_validation_refresh(
                    &aspa_peer_mgr_tx,
                    ImportValidationDependency::Aspa,
                )
                .await;
            }
        });

        // Spawn one RTR client per configured cache server
        for server in &rpki_config.cache_servers {
            let addr: std::net::SocketAddr = match server.address.parse() {
                Ok(a) => a,
                Err(e) => {
                    error!(
                        address = %server.address,
                        error = %e,
                        "invalid RPKI cache server address — skipping"
                    );
                    continue;
                }
            };
            let client_config = rustbgpd_rpki::RtrClientConfig {
                server_addr: addr,
                refresh_interval: server.refresh_interval,
                retry_interval: server.retry_interval,
                expire_interval: server.expire_interval,
            };
            let client = rustbgpd_rpki::RtrClient::new(client_config, vrp_update_tx.clone());
            info!(server = %addr, "spawning RTR client for RPKI cache");
            tokio::spawn(client.run());
        }
    }

    // Spawn MRT manager (periodic TABLE_DUMP_V2 snapshots)
    let mrt_trigger_tx: Option<mpsc::Sender<oneshot::Sender<Result<std::path::PathBuf, String>>>> =
        if let Some(ref mrt_config) = config.mrt {
            let writer_config = rustbgpd_mrt::MrtWriterConfig {
                output_dir: std::path::PathBuf::from(&mrt_config.output_dir),
                dump_interval: mrt_config.dump_interval,
                compress: mrt_config.compress,
                file_prefix: mrt_config.file_prefix.clone(),
            };
            let (trigger_tx, trigger_rx) = mpsc::channel(16);
            let mgr =
                rustbgpd_mrt::MrtManager::new(writer_config, rib_tx.clone(), trigger_rx, router_id);
            info!(
                output_dir = %mrt_config.output_dir,
                interval = mrt_config.dump_interval,
                "spawning MRT dump manager"
            );
            tokio::spawn(mgr.run());
            Some(trigger_tx)
        } else {
            None
        };

    // Spawn PeerManager (keep JoinHandle for coordinated shutdown)
    // ADR-0067 step 4 — BFD/BGP coupling channels. Created here so PeerManager
    // (the desired-set owner) can take the sender + state-change receiver; the
    // BFD actor takes the matching receiver + sender when it spawns below.
    let bfd_initial = bfd_runtime::BfdRuntimeConfig::from_config(&config);
    let (bfd_desired_tx, bfd_desired_rx) = tokio::sync::watch::channel(bfd_initial.clone());
    let (bfd_state_change_tx, bfd_state_change_rx) = bfd_runtime::state_change_channel();

    let peer_mgr = PeerManager::new_with_config(
        peer_mgr_rx,
        peer_mgr_internal_rx,
        config.global.asn,
        router_id,
        cluster_id,
        local_gr_restart_until,
        metrics.clone(),
        rib_tx.clone(),
        bmp_tx,
        Some(validation_watch_rx),
        config.clone(),
    )
    .with_readiness_queries(peer_mgr_readiness_rx)
    .with_event_history(event_history_handle.clone())
    .with_transport_event_sink(event_history_handle.clone().map(|handle| {
        rustbgpd_api::event_history_sinks::make_transport_event_sink(handle, metrics.clone())
    }));
    // Wire BFD coupling only when BFD is configured; otherwise the unused ends
    // are dropped (the actor won't spawn either). PeerManager holds the desired
    // sender for life and never recreates it (the actor treats sender drop as
    // shutdown).
    let peer_mgr = if bfd_initial.enabled() {
        let configured: std::collections::HashMap<_, _> = bfd_initial
            .sessions
            .iter()
            .map(|s| (s.peer, s.clone()))
            .collect();
        peer_mgr.with_bfd_coupling(bfd_desired_tx, bfd_state_change_rx, configured)
    } else {
        drop(bfd_desired_tx);
        drop(bfd_state_change_rx);
        peer_mgr
    };
    let peer_mgr_handle = tokio::spawn(peer_mgr.run());

    // Spawn config persister (converts gRPC config events → disk writes).
    //
    // Two inputs feed the persister:
    //   * `event_tx` — gRPC layer pushes per-mutation `ConfigEvent`s;
    //     the bridge applies each onto its locally held snapshot and
    //     then forwards a full `ReplaceConfig` to the persister.
    //   * `bridge_replace_tx` — the SIGHUP path pushes the desired
    //     reloaded TOML snapshot. The bridge swaps it into its
    //     locally held snapshot and refreshes the persister base
    //     without writing it back to disk. Runtime may stay pinned for
    //     restart-required fields; disk must preserve the operator's
    //     edit-then-restart intent.
    //
    // The replace path MUST go through the bridge (not directly to
    // the persister) so the bridge's snapshot stays consistent with
    // what's on disk. Otherwise the next gRPC mutation would apply
    // to a stale pre-reload snapshot and overwrite the persisted
    // file with `stale_pre_reload + one_mutation`.
    let (config_event_tx, bridge_replace_tx) = if let Some(ref path) = config.file_path {
        let (event_tx, event_rx) = mpsc::channel::<rustbgpd_api::peer_types::ConfigEvent>(64);
        let (mutation_tx, mutation_rx) = mpsc::channel::<ConfigMutation>(64);
        let (bridge_replace_tx, bridge_replace_rx) = mpsc::unbounded_channel::<Box<Config>>();
        let persister = ConfigPersister::new(mutation_rx, path.clone(), config.clone());
        tokio::spawn(persister.run());
        tokio::spawn(run_config_bridge(
            event_rx,
            bridge_replace_rx,
            mutation_tx,
            config.clone(),
        ));
        (Some(event_tx), Some(bridge_replace_tx))
    } else {
        (None, None)
    };

    // Shutdown channels:
    // - grpc_shutdown: signals all tonic listeners to stop
    // - rpc_shutdown: given to ControlService so Shutdown RPC can trigger exit
    let (grpc_shutdown_tx, grpc_shutdown_rx) = oneshot::channel::<()>();
    let (rpc_shutdown_tx, mut rpc_shutdown_rx) = watch::channel(false);

    for listener in &grpc_listeners {
        match &listener.endpoint {
            ListenerEndpoint::Tcp(addr) => {
                info!(
                    %addr,
                    auth_enabled = listener.auth_enabled(),
                    "configured gRPC TCP listener"
                );
                if !addr.ip().is_loopback() && !listener.auth_enabled() {
                    warn!(
                        %addr,
                        "gRPC TCP listener bound to a non-loopback address without authentication; prefer UDS for local administration or a proxy with mTLS for remote access"
                    );
                } else if !addr.ip().is_loopback() {
                    warn!(
                        %addr,
                        "gRPC TCP listener bound to a non-loopback address with bearer authentication but no transport encryption; prefer a proxy with mTLS for remote access"
                    );
                }
            }
            ListenerEndpoint::Uds { path, mode } => {
                info!(
                    path = %path.display(),
                    mode = format_args!("{mode:o}"),
                    auth_enabled = listener.auth_enabled(),
                    "configured gRPC UDS listener"
                );
            }
        }
    }

    // Resolve declared EVPN instances once at startup and hand the
    // gRPC layer a shared `Arc`. The validation pass at config load
    // already proved this resolution succeeds, so a second failure
    // here would be a programming error rather than operator input,
    // but we still surface it as a daemon-fatal diagnostic to avoid
    // silently dropping instances if a future code path skips validation.
    let evpn_instances = std::sync::Arc::new(config.resolve_evpn_instances().unwrap_or_else(|e| {
        fatal_startup_error(
            "EVPN instances failed to re-resolve after configuration validation",
            e,
        );
    }));

    // Gate 9 IP-VRFs (`[[evpn_ip_vrfs]]`). Same fatal-after-validate
    // pattern as `evpn_instances`. Empty for any deployment without
    // Gate 9 config; the dataplane short-circuits `probe_ip_vrfs` when
    // empty so L2-only and RR-only deployments incur zero added cost.
    let evpn_ip_vrfs = std::sync::Arc::new(config.resolve_evpn_ip_vrfs().unwrap_or_else(|e| {
        fatal_startup_error(
            "EVPN IP-VRFs failed to re-resolve after configuration validation",
            e,
        );
    }));

    // ADR-0091 managed EVPN netdev desired state. Empty by default;
    // configured rows opt into class-scoped Linux link lifecycle.
    let evpn_managed_netdevs =
        std::sync::Arc::new(config.resolve_managed_netdevs().unwrap_or_else(|e| {
            fatal_startup_error(
                "managed EVPN netdevs failed to re-resolve after configuration validation",
                e,
            );
        }));

    let (evpn_duplicate_mac_quarantine_tx, evpn_duplicate_mac_quarantine_rx) =
        tokio::sync::watch::channel(std::sync::Arc::new(std::collections::BTreeSet::<
            rustbgpd_evpn::DuplicateMacKey,
        >::new()));

    // EVPN Linux dataplane reconciler (Gate 7b). Returns None when
    // [[evpn_instances]] is empty — RR-only deployments don't open a
    // netlink socket and don't spawn the actor. The handle is moved
    // into the coordinated shutdown block at the bottom of main where
    // we await its bounded drain.
    let evpn_dataplane_shutdown = tokio_util::sync::CancellationToken::new();
    let supervisor_config = {
        let mut cfg = evpn_dataplane::SupervisorConfig::default();
        cfg.actor_config.apply_bum_enforcement = config.apply_bum_enforcement;
        cfg
    };
    let mut evpn_dataplane_handle = evpn_dataplane::spawn_with_quarantine(
        supervisor_config,
        &evpn_instances,
        &evpn_ip_vrfs,
        &evpn_managed_netdevs,
        rib_tx.clone(),
        metrics.clone(),
        evpn_dataplane_shutdown.clone(),
        evpn_duplicate_mac_quarantine_rx,
    )
    .await;
    let evpn_dataplane_runtime_control = evpn_dataplane_handle
        .as_ref()
        .map(evpn_dataplane::EvpnDataplaneHandle::runtime_control);

    // EVPN local-MAC originator (Gate 7b+1). Spawned alongside the
    // dataplane supervisor under the same `[[evpn_instances]]` gate.
    // Consumes the upward `LocalMacObservation` channel surfaced by
    // the dataplane (Phase D); kernel-learned MACs become BGP EVPN
    // Type 2 originations per RFC 7432 §15.1. RR-only deployments
    // skip this entirely — `evpn_dataplane::spawn` returned `None`
    // and `local_mac_rx` is therefore `None`.
    let evpn_originator_shutdown = tokio_util::sync::CancellationToken::new();
    let evpn_originated_local_mac_counts = evpn_originator::OriginatedLocalMacCounts::default();
    // Resolve `[[ethernet_segments]]` early so the originator can
    // attach the right ESI to Type 2 routes for MACs learned on
    // multi-homed VNIs (Gate 8b ESI-aware MAC origination). The
    // same resolved table is consumed by `evpn_segment::spawn`
    // below.
    let ethernet_segments = config.resolve_ethernet_segments().unwrap_or_else(|e| {
        fatal_startup_error(
            "Ethernet segments failed to re-resolve after configuration validation",
            e,
        );
    });
    let vni_to_esi = evpn_runtime_converger::evpn_vni_to_esi_map(&ethernet_segments);
    // ADR-0063 EVPN runtime coordinator. The public API validates full
    // candidates through this handle and commits only after daemon
    // actor convergence accepts the planned mutation. SIGHUP remains
    // restart-required for EVPN edits.
    let evpn_runtime_coordinator =
        Arc::new(Mutex::new(rustbgpd_evpn::EvpnRuntimeCoordinator::new(
            evpn_instances.clone(),
            evpn_ip_vrfs.clone(),
            ethernet_segments.clone(),
        )));
    let evpn_originator_handle = if let Some(handle) = evpn_dataplane_handle.as_mut() {
        evpn_originator::spawn_with_quarantine(
            evpn_originator::OriginatorConfig::default(),
            &evpn_instances,
            rib_tx.clone(),
            handle.local_mac_rx.take(),
            metrics.clone(),
            evpn_originated_local_mac_counts.clone(),
            evpn_originator_shutdown.clone(),
            vni_to_esi.clone(),
            evpn_duplicate_mac_quarantine_tx.clone(),
        )
    } else {
        None
    };
    let evpn_originator_runtime_control = evpn_originator_handle
        .as_ref()
        .map(evpn_originator::EvpnOriginatorHandle::runtime_control);

    // EVPN Type 3 IMET origination (Gate 7b+1 phase F). One Type 3
    // per L2VNI announcing this VTEP's BGP-level VNI membership; not
    // conditioned on kernel readiness. Originated at startup, with
    // controller-owned keys retained for shutdown-time withdraw.
    // RR-only paths (empty `evpn_instances`) skip origination entirely
    // — IMET requires a VTEP IP, which an RR doesn't have.
    let evpn_imet_controller =
        Arc::new(tokio::sync::Mutex::new(evpn_imet::EvpnImetController::new()));
    if !evpn_instances.is_empty() {
        evpn_imet_controller
            .lock()
            .await
            .originate_all(evpn_instances.iter().cloned().collect::<Vec<_>>(), &rib_tx)
            .await;
    }

    // EVPN SVI-MAC origination (RFC 9135 §6.1) — gated on any
    // instance setting `advertise_svi_mac = true`. Subscribes to the
    // dataplane handle's report broadcast and originates a Type 2
    // for each Ready bridge's own MAC. `evpn_svi::spawn` returns
    // `None` when no instance opts in, so RR-only and SVI-MAC-off
    // deployments incur zero cost.
    let evpn_svi_shutdown = tokio_util::sync::CancellationToken::new();
    let evpn_svi_handle = if let Some(handle) = evpn_dataplane_handle.as_ref() {
        evpn_svi::spawn(
            &evpn_instances,
            rib_tx.clone(),
            handle.subscribe_reports(),
            metrics.clone(),
            evpn_originated_local_mac_counts.clone(),
            evpn_svi_shutdown.clone(),
        )
    } else {
        None
    };
    let evpn_svi_runtime_control = evpn_svi_handle
        .as_ref()
        .map(evpn_svi::EvpnSviHandle::runtime_control);

    // ADR-0085: resolved [[ethernet_segments]] interface bindings.
    // Initial value from the startup config; the reload apply
    // republishes on every committed config advance. Two consumers:
    // the link-drain coordinator (spawned further below) and the
    // segment actor (bound-ness is the "locally attached" half of the
    // decision 5 bias-eligibility condition).
    let initial_es_link_bindings = config.resolve_es_link_bindings().unwrap_or_else(|error| {
        // Unreachable: the config passed full validation at load.
        warn!(%error, "failed to resolve Ethernet Segment interface bindings at startup");
        std::collections::BTreeMap::new()
    });
    let (es_link_bindings_tx, es_link_bindings_rx) =
        watch::channel::<evpn_es_link_drain::EsLinkBindings>(Arc::new(initial_es_link_bindings));
    let es_link_bindings_tx = Arc::new(es_link_bindings_tx);

    // EVPN Ethernet Segment orchestrator (Gate 8 multihoming
    // foundation — observable DF election, no enforcement). Spawned
    // when `[[ethernet_segments]]` has at least one entry and at
    // least one configured `[[evpn_instances]]` exists for the
    // member-VNI table to resolve against. Returns `None` for
    // single-homed deployments and route reflectors.
    let evpn_segment_shutdown = tokio_util::sync::CancellationToken::new();
    // `ethernet_segments` was resolved upstream so the originator
    // could build its `vni_to_esi` lookup before we got here.
    let evpn_segment_handle = if ethernet_segments.is_empty() {
        None
    } else {
        let bum_enforcement_tx = evpn_dataplane_handle
            .as_ref()
            .map(evpn_dataplane::EvpnDataplaneHandle::bum_enforcement_sender);
        // ADR-0085 decision 5: the segment actor publishes the
        // same-ESI bias-eligibility snapshot toward the dataplane
        // supervisor (alongside the BUM-enforcement flow) and consumes
        // the binding watch for the bound-ESI projection.
        let same_esi_bias_tx = evpn_dataplane_handle
            .as_ref()
            .map(evpn_dataplane::EvpnDataplaneHandle::same_esi_bias_sender);
        evpn_segment::spawn_with_local_bias(
            &evpn_instances,
            ethernet_segments,
            rib_tx.clone(),
            bum_enforcement_tx,
            same_esi_bias_tx,
            Some(es_link_bindings_tx.subscribe()),
            metrics.clone(),
            evpn_segment_shutdown.clone(),
        )
    };
    let evpn_segment_runtime_control = evpn_segment_handle
        .as_ref()
        .map(evpn_segment::EvpnSegmentHandle::runtime_control);

    // Latest snapshot of `DataplaneReport.ip_vrf_status` rows for the
    // gRPC `ListIpVrfs` / `GetIpVrf` surface (Gate 9 slice 5). Backed
    // by a `tokio::sync::watch` so gRPC handlers can read the latest
    // value lock-free (`.borrow().clone()`) without blocking a tokio
    // worker; the subscriber task replaces the value on every
    // dataplane report. RR-only deployments
    // (`evpn_dataplane_handle.is_none()`) leave the initial empty Vec
    // in place — `probe_ip_vrfs` would short-circuit to empty even if
    // the actor ran, so the gRPC surface stays consistent without any
    // wiring.
    let (evpn_ip_vrf_status_tx, evpn_ip_vrf_status_rx) =
        tokio::sync::watch::channel(Vec::<rustbgpd_evpn::IpVrfDataplaneStatus>::new());

    // Latest snapshot of `DataplaneReport.instance_status` rows for
    // the gRPC / CLI `ListEvpnInstances` L2 readiness surface. Empty
    // means either cold start before the first reconcile report or an
    // RR-only / dataplane-disabled deployment.
    let (evpn_instance_status_tx, evpn_instance_status_rx) =
        tokio::sync::watch::channel(Vec::<rustbgpd_evpn::InstanceDataplaneStatus>::new());

    // Latest ADR-0091 managed-netdev status rows for
    // `EvpnService.ListManagedNetdevs`.
    let (evpn_managed_netdev_status_tx, evpn_managed_netdev_status_rx) =
        tokio::sync::watch::channel(Vec::<rustbgpd_evpn::ManagedNetdevStatus>::new());

    // Latest snapshot of `DataplaneReport.ip_vrf_routes.observations`
    // for the Gate 9 slice 6b L3 originator subscriber and for
    // Prometheus gauge updates. Stays empty on RR-only deployments and
    // when `[[evpn_ip_vrfs]]` is unset — `dump_ip_vrf_routes`
    // short-circuits in both cases.
    let (evpn_ip_vrf_routes_tx, evpn_ip_vrf_routes_rx) =
        tokio::sync::watch::channel(std::sync::Arc::new(std::collections::HashMap::<
            rustbgpd_evpn::IpVrfId,
            Vec<rustbgpd_evpn::LocalIpRouteObservation>,
        >::new()));

    // Latest per-VRF installed-route counts (Gate 9 slice 6c). The
    // reconcile actor's L3 install pipeline emits these on every
    // report; the daemon mirrors them onto a watch channel that the
    // gRPC `IpVrfState.installed_routes_count` field reads
    // lock-free.
    let (evpn_ip_vrf_installed_routes_tx, evpn_ip_vrf_installed_routes_rx) =
        tokio::sync::watch::channel(std::sync::Arc::new(std::collections::HashMap::<
            rustbgpd_evpn::IpVrfId,
            u32,
        >::new()));
    // Latest owned FDB nexthop-group state (ADR-0059). The reconciler
    // publishes the actor-owned group/refcount snapshot on every
    // report; gRPC reads this watch channel lock-free for
    // `EvpnService.ListEvpnNexthops`.
    let (evpn_fdb_nexthops_tx, evpn_fdb_nexthops_rx) =
        tokio::sync::watch::channel(rustbgpd_evpn::FdbNexthopDataplaneStatus::default());
    let evpn_bum_enforcement_rx = evpn_dataplane_handle.as_ref().map_or_else(
        || {
            let (_, rx) = tokio::sync::watch::channel(std::sync::Arc::new(
                rustbgpd_evpn::BumEnforcementTable::new(),
            ));
            rx
        },
        |handle| handle.bum_enforcement_sender().subscribe(),
    );
    let evpn_same_esi_bias_rx = evpn_dataplane_handle.as_ref().map_or_else(
        || {
            let (_, rx) = tokio::sync::watch::channel(std::sync::Arc::new(
                rustbgpd_evpn::SameEsiBiasTable::new(),
            ));
            rx
        },
        |handle| handle.same_esi_bias_sender().subscribe(),
    );
    let evpn_remote_ip_prefix_drop_counts_rx = evpn_dataplane_handle.as_ref().map_or_else(
        || {
            let (_, rx) = tokio::sync::watch::channel(std::sync::Arc::new(
                evpn_dataplane::RemoteIpPrefixDropCounts::new(),
            ));
            rx
        },
        evpn_dataplane::EvpnDataplaneHandle::remote_prefix_drop_counts_receiver,
    );
    if let Some(handle) = evpn_dataplane_handle.as_ref() {
        let mut reports = handle.subscribe_reports();
        // Resolve IpVrfId → operator-facing name for the metric labels
        // — same labelling the gRPC surface uses.
        let vrf_id_to_name: std::collections::HashMap<rustbgpd_evpn::IpVrfId, String> =
            evpn_ip_vrfs
                .iter()
                .map(|v| (v.id, v.name.clone()))
                .collect();
        let metrics_for_routes = metrics.clone();
        tokio::spawn(async move {
            let mut managed_netdev_metric_labels = BTreeSet::new();
            loop {
                match reports.recv().await {
                    Ok(report) => {
                        // `send_replace` is the no-await write —
                        // updates the value in place and wakes any
                        // pending watchers. Safe to call from inside
                        // a tokio task without blocking the worker.
                        evpn_instance_status_tx.send_replace(report.instance_status);
                        evpn_fdb_nexthops_tx.send_replace(report.fdb_nexthops);
                        evpn_ip_vrf_status_tx.send_replace(report.ip_vrf_status);
                        update_managed_netdev_metrics(
                            &metrics_for_routes,
                            &mut managed_netdev_metric_labels,
                            &report.managed_netdevs,
                        );
                        evpn_managed_netdev_status_tx.send_replace(report.managed_netdevs);
                        // Slice 6a: publish per-VRF observed-routes
                        // gauge values and bump filtered-routes
                        // counters by the per-pass deltas. The
                        // observations themselves are forwarded onto
                        // a watch channel for the L3 originator
                        // (slice 6b) to subscribe to.
                        //
                        // `ip_vrf_routes = None` signals a transient
                        // kernel-dump failure (ADR-0054 §6). Preserve
                        // the watch's last-good value and do not
                        // increment Prometheus counters — the next
                        // successful reconcile pass will re-publish
                        // and bump filter counts from a fresh dump.
                        if let Some(dump) = report.ip_vrf_routes {
                            for (vrf_id, observations) in &dump.observations {
                                let label = vrf_id_to_name
                                    .get(vrf_id)
                                    .cloned()
                                    .unwrap_or_else(|| vrf_id.as_u32().to_string());
                                metrics_for_routes.set_evpn_ip_vrf_observed_routes(
                                    &label,
                                    i64::try_from(observations.len()).unwrap_or(i64::MAX),
                                );
                            }
                            for ((vrf_id, reason), delta) in &dump.filter_counts {
                                let label = vrf_id_to_name
                                    .get(vrf_id)
                                    .cloned()
                                    .unwrap_or_else(|| vrf_id.as_u32().to_string());
                                metrics_for_routes.add_evpn_ip_vrf_observed_routes_filtered(
                                    &label,
                                    reason.label(),
                                    *delta,
                                );
                            }
                            evpn_ip_vrf_routes_tx
                                .send_replace(std::sync::Arc::new(dump.observations));
                        } else {
                            tracing::debug!(
                                "ip-vrf route dump failed this reconcile pass; preserving \
                                 last-good observation snapshot"
                            );
                        }
                        // Slice 6c: publish installed-route counts to
                        // the watch channel + Prometheus gauge. The
                        // reconcile actor populates
                        // `report.ip_vrf_installed_routes` from its
                        // L3 owned set on every pass; this is
                        // authoritative (no `Option` wrap needed
                        // because a kernel dump failure during L3
                        // install just leaves the count at its prior
                        // value — the owned set itself doesn't
                        // change on failure).
                        for (vrf_id, count) in &report.ip_vrf_installed_routes {
                            let label = vrf_id_to_name
                                .get(vrf_id)
                                .cloned()
                                .unwrap_or_else(|| vrf_id.as_u32().to_string());
                            metrics_for_routes
                                .set_evpn_ip_vrf_installed_routes(&label, i64::from(*count));
                        }
                        evpn_ip_vrf_installed_routes_tx
                            .send_replace(std::sync::Arc::new(report.ip_vrf_installed_routes));
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                        // The reconcile actor emits at most one report
                        // per pass (5 s default); if this subscriber
                        // fell behind that bound, the broadcast buffer
                        // already replaced the missed entries with
                        // newer ones. Keep going — the next received
                        // report supersedes whatever we missed.
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => return,
                }
            }
        });
    }

    // EVPN Type 5 originator (Gate 9 slice 6b). Subscribes to the
    // route-observation watch channel populated above and the slice-5
    // IP-VRF status watch. Returns `None` when no `[[evpn_ip_vrfs]]`
    // are configured, so L2-only and RR-only deployments incur zero
    // cost. The shared `OriginatedIpVrfRouteCounts` is read-only on
    // the gRPC side (below) so handlers can surface
    // `originated_routes_count` without coordinating with the actor.
    let evpn_l3_originator_shutdown = tokio_util::sync::CancellationToken::new();
    let evpn_originated_ip_vrf_route_counts =
        evpn_l3_originator::OriginatedIpVrfRouteCounts::default();
    let evpn_l3_originator_handle = evpn_l3_originator::spawn(evpn_l3_originator::SpawnConfig {
        ip_vrfs: evpn_ip_vrfs.clone(),
        rib_tx: rib_tx.clone(),
        route_observations_rx: evpn_ip_vrf_routes_rx.clone(),
        ip_vrf_status_rx: evpn_ip_vrf_status_rx.clone(),
        metrics: metrics.clone(),
        originated_counts: evpn_originated_ip_vrf_route_counts.clone(),
        shutdown: evpn_l3_originator_shutdown.clone(),
    });
    let evpn_l3_originator_runtime_control = evpn_l3_originator_handle
        .as_ref()
        .map(evpn_l3_originator::EvpnL3OriginatorHandle::runtime_control);
    let evpn_runtime_apply_lock = Arc::new(tokio::sync::Mutex::new(()));
    // ADR-0084 runtime ES drain: shared in-memory drained set, reason-
    // keyed since ADR-0085 (operator | link). The converger consults it
    // on every originator-model publish and GCs it on segment-set
    // replace; the gRPC SetEthernetSegmentDrain hook below and the
    // ADR-0085 link coordinator both mutate it under the same apply
    // lock. Built with the metrics handle so every committed mutation
    // syncs the evpn_es_drained{esi, reason} gauge.
    let evpn_es_drain_state = evpn_es_drain::EvpnEsDrainState::with_metrics(metrics.clone());
    let evpn_runtime_converger = Arc::new(evpn_runtime_converger::EvpnRuntimeActorConverger::new(
        rib_tx.clone(),
        evpn_imet_controller.clone(),
        evpn_dataplane_runtime_control,
        evpn_originator_runtime_control.clone(),
        evpn_svi_runtime_control,
        evpn_l3_originator_runtime_control,
        evpn_segment_runtime_control.clone(),
        evpn_es_drain_state.clone(),
    ));
    let evpn_runtime_reload_apply = evpn_runtime_converger::EvpnRuntimeReloadApply::new(
        evpn_runtime_coordinator.clone(),
        evpn_runtime_apply_lock.clone(),
        evpn_runtime_converger.clone(),
        config.clone(),
    )
    .with_metrics(metrics.clone())
    .with_es_link_bindings_publisher(es_link_bindings_tx.clone());

    // RFC 7999 BLACKHOLE kernel-discard reconciler (ADR-0060 FIB
    // slice). Completely opt-in: `install_blackhole_discard = true`
    // is effective only alongside `honor_blackhole = true`, and the
    // actor itself still enforces host-prefix-only by default.
    let (blackhole_status_tx, blackhole_status_rx) =
        tokio::sync::watch::channel(Vec::<blackhole::BlackholeStatus>::new());
    let blackhole_shutdown = tokio_util::sync::CancellationToken::new();
    let blackhole_handle = blackhole::spawn(
        blackhole::BlackholeConfig {
            enabled: config.global.honor_blackhole && config.global.install_blackhole_discard,
            allow_broad_prefixes: config.global.allow_blackhole_broad_prefixes,
        },
        rib_tx.clone(),
        metrics.clone(),
        blackhole_status_tx,
        blackhole_shutdown.clone(),
    );

    // ADR-0061 general unicast FIB reconciler. Completely opt-in:
    // an empty `[[fib_tables]]` list returns `None` and leaves
    // route-server / route-reflector deployments control-plane-only.
    let (fib_status_tx, fib_status_rx) =
        tokio::sync::watch::channel(Vec::<fib_runtime::FibRuntimeStatus>::new());
    let (fib_event_tx, fib_event_rx) =
        tokio::sync::broadcast::channel::<fib_runtime::FibRuntimeEvent>(4096);
    let (fib_bgp_event_tx, _) =
        tokio::sync::broadcast::channel::<rustbgpd_api::proto::BgpEvent>(4096);
    let _fib_event_bridge_handle = spawn_fib_dataplane_event_bridge(
        fib_event_rx,
        fib_bgp_event_tx.clone(),
        event_history_handle.clone(),
        metrics.clone(),
    );
    let fib_runtime_shutdown = tokio_util::sync::CancellationToken::new();
    let fib_runtime_handle = fib_runtime::spawn(
        fib_runtime::FibRuntimeConfig {
            tables: config.fib_tables.clone(),
            owned_state_path: Some(config.runtime_state_dir().join("fib-owned.json")),
            multipath_relax: config.global.multipath_relax,
            link_bandwidth_weighted: config.global.link_bandwidth_weighted,
        },
        rib_tx.clone(),
        rib_query_tx.clone(),
        metrics.clone(),
        fib_status_tx,
        fib_event_tx,
        fib_runtime_shutdown.clone(),
    );
    // Command sender for runtime `[[fib_tables]]` hot-swap (SIGHUP reload now;
    // gRPC CRUD later). `Some` iff the FIB reconciler actually spawned at
    // startup (≥1 table, Linux, netlink ok).
    let fib_cmd_tx = fib_runtime_handle
        .as_ref()
        .map(fib_runtime::FibRuntimeHandle::command_sender);

    // Spawn the BFD actor (single-hop async, ADR-0067). Runs the sessions in the
    // PeerManager-owned desired set, publishes their state, and emits state
    // changes that PeerManager couples to BGP (non-strict RFC 5882 teardown).
    // No-op when no neighbor has BFD configured (or off Linux).
    let (bfd_status_tx, bfd_status_rx) =
        tokio::sync::watch::channel(Vec::<bfd_runtime::BfdStatus>::new());
    // Actor state-change events (ADR-0067 step 3b): the actor broadcasts
    // BfdRuntimeEvent; a bridge converts each to a proto BgpEvent that
    // EventService surfaces over WatchEvents. The proto `bfd_bgp_event_tx`
    // (held in ServeConfig) is the long-lived sink, so the WatchEvents BFD
    // stream stays open even when no sessions are configured. The actor event
    // channel (`bfd_event_tx`) is dropped if the actor doesn't start (no
    // sessions / off Linux), which simply ends the bridge task.
    let (bfd_event_tx, bfd_event_rx) =
        tokio::sync::broadcast::channel::<bfd_runtime::BfdRuntimeEvent>(1024);
    let (bfd_bgp_event_tx, _) =
        tokio::sync::broadcast::channel::<rustbgpd_api::proto::BgpEvent>(1024);
    let _bfd_event_bridge = spawn_bfd_event_bridge(
        bfd_event_rx,
        bfd_bgp_event_tx.clone(),
        event_history_handle.clone(),
        metrics.clone(),
    );
    // The desired-set receiver + state-change sender are the actor's ends of the
    // coupling channels created above (PeerManager owns the other ends).
    let bfd_runtime_shutdown = tokio_util::sync::CancellationToken::new();
    let bfd_runtime_handle = bfd_runtime::spawn(
        bfd_desired_rx,
        metrics.clone(),
        bfd_status_tx,
        bfd_event_tx,
        bfd_state_change_tx,
        bfd_runtime_shutdown.clone(),
    );

    // Spawn gRPC API server (keep JoinHandle for supervision)
    let grpc_rib_tx = rib_tx.clone();
    let grpc_rib_query_tx = rib_query_tx.clone();
    let grpc_peer_mgr_tx = peer_mgr_tx.clone();
    let evpn_duplicate_mac_clear = evpn_originator_handle.as_ref().map(|handle| {
        let control = handle.control();
        Arc::new(move |vni, mac| {
            let control = control.clone();
            Box::pin(async move {
                match control
                    .clear_duplicate_mac_quarantine(rustbgpd_evpn::DuplicateMacKey::new(vni, mac))
                    .await
                {
                    Ok(evpn_originator::ClearDuplicateMacQuarantineResult::Cleared) => {
                        Ok(rustbgpd_api::evpn_service::DuplicateMacClearOutcome { cleared: true })
                    }
                    Ok(evpn_originator::ClearDuplicateMacQuarantineResult::NotActive) => {
                        Ok(rustbgpd_api::evpn_service::DuplicateMacClearOutcome { cleared: false })
                    }
                    Ok(evpn_originator::ClearDuplicateMacQuarantineResult::UnknownVni) => Err(
                        rustbgpd_api::evpn_service::DuplicateMacClearError::NotFound(format!(
                            "no EVPN instance configured for VNI {vni}"
                        )),
                    ),
                    Err(evpn_originator::EvpnOriginatorControlError::Closed) => Err(
                        rustbgpd_api::evpn_service::DuplicateMacClearError::Unavailable(
                            "EVPN originator control channel is closed".to_string(),
                        ),
                    ),
                    Err(evpn_originator::EvpnOriginatorControlError::ReplyDropped) => Err(
                        rustbgpd_api::evpn_service::DuplicateMacClearError::Unavailable(
                            "EVPN originator control response channel dropped".to_string(),
                        ),
                    ),
                }
            }) as rustbgpd_api::evpn_service::DuplicateMacClearFuture
        }) as rustbgpd_api::evpn_service::DuplicateMacClearFn
    });
    // ADR-0084 SetEthernetSegmentDrain hook. Only offered when the
    // segment actor is running (no [[ethernet_segments]] → no actor →
    // every ESI is NotFound anyway, so the hook stays absent and the
    // RPC fails closed). The hook validates against the committed
    // coordinator model and pushes the mutation to BOTH actors through
    // the shared `apply_ethernet_segment_drain` primitive, serialized
    // by the EVPN runtime apply lock.
    let evpn_es_drain = evpn_segment_runtime_control.as_ref().map(|_| {
        let apply_lock = evpn_runtime_apply_lock.clone();
        let coordinator = evpn_runtime_coordinator.clone();
        let drain_state = evpn_es_drain_state.clone();
        let segment_control = evpn_segment_runtime_control.clone();
        let originator_control = evpn_originator_runtime_control.clone();
        Arc::new(
            move |esi: rustbgpd_wire::EthernetSegmentIdentifier, drained: bool| {
                let apply_lock = apply_lock.clone();
                let coordinator = coordinator.clone();
                let drain_state = drain_state.clone();
                let segment_control = segment_control.clone();
                let originator_control = originator_control.clone();
                Box::pin(async move {
                    match evpn_es_drain::apply_ethernet_segment_drain(
                        esi,
                        // The RPC owns exactly the Operator reason
                        // (ADR-0085 decision 2); the Link reason
                        // belongs to the interface-binding
                        // coordinator.
                        evpn_es_drain::EsDrainReason::Operator,
                        drained,
                        &apply_lock,
                        &coordinator,
                        &drain_state,
                        segment_control.as_ref(),
                        originator_control.as_ref(),
                    )
                    .await
                    {
                        Ok(outcome) => {
                            Ok(rustbgpd_api::evpn_service::EthernetSegmentDrainOutcome {
                                drained: outcome.drained,
                                changed: outcome.changed,
                                member_vni_count: outcome.member_vni_count,
                                reasons: outcome
                                    .reasons
                                    .iter()
                                    .map(|reason| reason.as_str().to_string())
                                    .collect(),
                            })
                        }
                        Err(evpn_es_drain::EsDrainError::UnknownEsi(message)) => Err(
                            rustbgpd_api::evpn_service::EthernetSegmentDrainError::NotFound(
                                message,
                            ),
                        ),
                        Err(evpn_es_drain::EsDrainError::Unavailable(message)) => Err(
                            rustbgpd_api::evpn_service::EthernetSegmentDrainError::Unavailable(
                                message,
                            ),
                        ),
                    }
                }) as rustbgpd_api::evpn_service::EthernetSegmentDrainFuture
            },
        ) as rustbgpd_api::evpn_service::EthernetSegmentDrainFn
    });
    // ADR-0085 link-driven drain coordinator. Spawned whenever the
    // segment actor runs (the drain target): bindings may be empty at
    // startup and arrive later via SIGHUP / ApplyEvpnRuntime — the
    // coordinator lazily spawns the kernel carrier monitor when the
    // first binding appears and drops it when the last one goes. All
    // its drain mutations go through the shared ADR-0084 primitive
    // under the same EVPN runtime apply lock.
    let evpn_es_link_drain_shutdown = tokio_util::sync::CancellationToken::new();
    let _evpn_es_link_drain_task = evpn_segment_runtime_control
        .as_ref()
        .map(|segment_control| {
            evpn_es_link_drain::spawn(
                es_link_bindings_rx,
                evpn_es_link_drain::CarrierFeed::Kernel,
                evpn_es_link_drain::EsLinkDrainDeps {
                    apply_lock: evpn_runtime_apply_lock.clone(),
                    coordinator: evpn_runtime_coordinator.clone(),
                    drain_state: evpn_es_drain_state.clone(),
                    segment: Some(segment_control.clone()),
                    originator: evpn_originator_runtime_control.clone(),
                },
                evpn_es_link_drain_shutdown.clone(),
            )
        });
    // Coordinator lock serializing persisted runtime config mutations with
    // SIGHUP reload. FIB-table CRUD, dynamic-neighbor CRUD, policy/peer-group
    // catalog CRUD, and the SIGHUP reload path hold it across their
    // read/apply/persist sequence so stale TOML snapshots cannot clobber
    // accepted runtime changes.
    let runtime_config_lock = std::sync::Arc::new(tokio::sync::Mutex::new(()));
    let config_transaction_controller =
        config_transaction_control::ConfigTransactionController::new(
            fib_table_control::FibTableControlDeps {
                fib_cmd_tx: fib_cmd_tx.clone(),
                peer_mgr_tx: peer_mgr_tx.clone(),
                config_tx: config_event_tx.clone(),
                lock: runtime_config_lock.clone(),
                config_mutation_gate: None,
                startup_tables: config.fib_tables.clone(),
                confirm_journal_path: Some(confirm_journal::journal_path(
                    &config.runtime_state_dir(),
                )),
            },
            metrics.clone(),
        );
    // Process-wide availability gate (LAN-286): BGP-listener bind failure
    // turns readiness red; coordinated shutdown turns readiness red AND
    // stops admitting persisted config mutations and inbound BGP sessions.
    let daemon_gate = DaemonGate::new();
    let config_mutation_gate: ConfigMutationGateFn = {
        let inner = config_transaction_controller.mutation_gate_fn();
        let gate = daemon_gate.clone();
        Arc::new(move |operation| {
            let inner = inner.clone();
            let gate = gate.clone();
            Box::pin(async move {
                if gate.is_shutting_down() {
                    return Err(format!("{operation} rejected: daemon is shutting down"));
                }
                inner(operation).await
            })
        })
    };
    let serve_config = ServeConfig {
        asn: config.global.asn,
        router_id: config.global.router_id.clone(),
        listen_port: u32::from(config.global.listen_port),
        metrics: metrics.clone(),
        start_time,
        peer_mgr_readiness_tx: peer_mgr_readiness_tx.clone(),
        rib_readiness_tx: rib_readiness_tx.clone(),
        mrt_trigger_tx,
        evpn_originated_local_mac_count: {
            let counts = evpn_originated_local_mac_counts.clone();
            Arc::new(move |vni| {
                rustbgpd_evpn::EvpnInstanceId::new(vni).map_or(0, |id| counts.count(id))
            })
        },
        evpn_instance_status_snapshot: {
            let rx = evpn_instance_status_rx.clone();
            Arc::new(move || rx.borrow().clone())
        },
        evpn_managed_netdev_status_snapshot: {
            let rx = evpn_managed_netdev_status_rx.clone();
            Arc::new(move || rx.borrow().clone())
        },
        evpn_ip_vrf_status_snapshot: {
            // `borrow()` on a watch receiver is lock-free (internal
            // seqlock); cloning the Vec releases the borrow before
            // the gRPC handler returns.
            let rx = evpn_ip_vrf_status_rx.clone();
            Arc::new(move || rx.borrow().clone())
        },
        evpn_originated_ip_vrf_route_count: {
            let counts = evpn_originated_ip_vrf_route_counts.clone();
            Arc::new(move |vni| rustbgpd_evpn::IpVrfId::new(vni).map_or(0, |id| counts.count(id)))
        },
        evpn_installed_ip_vrf_route_count: {
            let rx = evpn_ip_vrf_installed_routes_rx.clone();
            Arc::new(move |vni| {
                rustbgpd_evpn::IpVrfId::new(vni).map_or(0, |id| {
                    u64::from(rx.borrow().get(&id).copied().unwrap_or(0))
                })
            })
        },
        evpn_remote_ip_prefix_drop_counts: {
            let rx = evpn_remote_ip_prefix_drop_counts_rx.clone();
            Arc::new(move || {
                rx.borrow()
                    .iter()
                    .map(|((vrf, reason), count)| {
                        rustbgpd_api::evpn_service::RemoteIpPrefixDropCount {
                            vrf: vrf.clone(),
                            reason: reason.clone(),
                            count: *count,
                        }
                    })
                    .collect()
            })
        },
        evpn_fdb_nexthop_snapshot: {
            let rx = evpn_fdb_nexthops_rx.clone();
            Arc::new(move || rx.borrow().clone())
        },
        evpn_bum_enforcement_snapshot: {
            let rx = evpn_bum_enforcement_rx.clone();
            Arc::new(move || rx.borrow().clone())
        },
        evpn_same_esi_bias_snapshot: {
            let rx = evpn_same_esi_bias_rx.clone();
            Arc::new(move || rx.borrow().clone())
        },
        evpn_es_drain_reasons: {
            let drain_state = evpn_es_drain_state.clone();
            Arc::new(move |esi| {
                drain_state
                    .reasons_for(esi)
                    .iter()
                    .map(|reason| reason.as_str().to_string())
                    .collect()
            })
        },
        evpn_runtime_model: {
            let coordinator = evpn_runtime_coordinator.clone();
            Arc::new(move || match coordinator.lock() {
                Ok(guard) => guard.model().clone(),
                Err(poisoned) => poisoned.into_inner().model().clone(),
            })
        },
        evpn_runtime_apply: {
            let reload_apply = evpn_runtime_reload_apply.clone();
            Some(Arc::new(move |request| {
                let reload_apply = reload_apply.clone();
                Box::pin(async move { reload_apply.apply_request(&request).await })
                    as rustbgpd_api::evpn_service::EvpnRuntimeApplyFuture
            })
                as rustbgpd_api::evpn_service::EvpnRuntimeApplyFn)
        },
        evpn_duplicate_mac_clear,
        evpn_es_drain,
        blackhole_discard_snapshot: {
            let rx = blackhole_status_rx.clone();
            Arc::new(move || {
                rx.borrow()
                    .iter()
                    .map(|status| rustbgpd_api::proto::BlackholeDiscard {
                        prefix: status.prefix.addr_string(),
                        prefix_length: u32::from(status.prefix.prefix_len()),
                        peer_address: status.peer.to_string(),
                        state: match status.state {
                            blackhole::BlackholeState::Installed => {
                                rustbgpd_api::proto::BlackholeDiscardState::Installed as i32
                            }
                            blackhole::BlackholeState::Rejected => {
                                rustbgpd_api::proto::BlackholeDiscardState::Rejected as i32
                            }
                            blackhole::BlackholeState::Failed => {
                                rustbgpd_api::proto::BlackholeDiscardState::Failed as i32
                            }
                        },
                        reason: status.reason.clone(),
                    })
                    .collect()
            })
        },
        fib_route_snapshot: {
            let rx = fib_status_rx.clone();
            Arc::new(move || {
                rx.borrow()
                    .iter()
                    .map(|status| {
                        let sampling = status.sampling.as_ref();
                        rustbgpd_api::proto::FibRouteStatus {
                            table_name: status.table_name.clone(),
                            table_id: status.table_id,
                            metric: status.metric,
                            prefix: status.prefix.addr_string(),
                            prefix_length: u32::from(status.prefix.prefix_len()),
                            next_hop: status
                                .next_hop
                                .map_or_else(String::new, |ip| ip.to_string()),
                            next_hops: status.next_hops.iter().map(ToString::to_string).collect(),
                            peer_address: status.peer.map_or_else(String::new, |ip| ip.to_string()),
                            state: match status.state {
                                fib_runtime::FibRuntimeState::Installed => {
                                    rustbgpd_api::proto::FibRouteState::Installed as i32
                                }
                                fib_runtime::FibRuntimeState::Rejected => {
                                    rustbgpd_api::proto::FibRouteState::Rejected as i32
                                }
                                fib_runtime::FibRuntimeState::Failed => {
                                    rustbgpd_api::proto::FibRouteState::Failed as i32
                                }
                            },
                            reason: status.reason.clone(),
                            sampling_sampled_rows: sampling.map_or(0, |s| s.sampled_rows),
                            sampling_suppressed_rows: sampling.map_or(0, |s| s.suppressed_rows),
                            sampling_total_rows: sampling.map_or(0, |s| s.total_rows),
                            sampling_max_routes: sampling.map_or(0, |s| s.max_routes),
                            sampling_sample_limit: sampling.map_or(0, |s| s.sample_limit),
                            sampling_complete: sampling.is_some_and(|s| s.suppressed_rows == 0),
                        }
                    })
                    .collect()
            })
        },
        fib_table_control: Some(fib_table_control::make_fib_table_control_fn(
            fib_table_control::FibTableControlDeps {
                fib_cmd_tx: fib_cmd_tx.clone(),
                peer_mgr_tx: peer_mgr_tx.clone(),
                config_tx: config_event_tx.clone(),
                lock: runtime_config_lock.clone(),
                config_mutation_gate: Some(config_mutation_gate.clone()),
                startup_tables: config.fib_tables.clone(),
                // FIB CRUD never journals; only the transaction controller
                // above owns commit-confirm durability.
                confirm_journal_path: None,
            },
        )),
        gnmi_set: Some(config_transaction_controller.gnmi_set_fn()),
        config_transaction_apply: Some(config_transaction_controller.apply_fn()),
        config_transaction_confirm: Some(config_transaction_controller.confirm_fn()),
        config_transaction_abort: Some(config_transaction_controller.abort_fn()),
        config_transaction_status: Some(config_transaction_controller.status_fn()),
        config_mutation_gate: Some(config_mutation_gate.clone()),
        runtime_config_lock: runtime_config_lock.clone(),
        dataplane_route_events: Some(fib_bgp_event_tx),
        bfd_session_snapshot: {
            let rx = bfd_status_rx.clone();
            Arc::new(move || {
                rx.borrow()
                    .iter()
                    .map(|status| rustbgpd_api::proto::BfdSession {
                        peer_address: status.peer.to_string(),
                        state: bfd_session_state_to_proto(status.state) as i32,
                        diagnostic: bfd_diagnostic_to_str(status.diagnostic).to_string(),
                        strict: status.strict,
                    })
                    .collect()
            })
        },
        bfd_events: Some(bfd_bgp_event_tx),
        event_history: event_history_handle.clone(),
    };
    let mut grpc_handle = tokio::spawn(async move {
        rustbgpd_api::server::serve(
            grpc_listeners,
            grpc_rib_tx,
            grpc_rib_query_tx,
            grpc_peer_mgr_tx,
            serve_config,
            grpc_shutdown_rx,
            rpc_shutdown_tx,
            config_event_tx,
        )
        .await;
    });

    // Spawn BGP inbound TCP listener. The current daemon opens one
    // listener socket from `Config::listen_addr()`; only install TCP-AO
    // MKTs whose peer family can match that socket. Outbound active-open
    // sockets still install their per-neighbor key independently below.
    let listen_addr = config.listen_addr();
    let listener_options = ListenerSocketOptions {
        tcp_ao_keys: peer_configs
            .iter()
            .filter_map(|neighbor| tcp_ao_listener_key_for_neighbor(listen_addr, neighbor))
            .chain(
                config
                    .dynamic_neighbors
                    .iter()
                    .filter_map(|range| tcp_ao_listener_key_for_dynamic_range(listen_addr, range)),
            )
            .collect(),
    };

    let tcp_ao_listener_required = !listener_options.tcp_ao_keys.is_empty();
    let (accept_tx, mut accept_rx) = mpsc::channel::<rustbgpd_transport::AcceptedConnection>(64);
    let mut tcp_ao_listener_handle = None;
    match BgpListener::bind_with_options(listen_addr, accept_tx, listener_options).await {
        Ok(listener) => {
            tcp_ao_listener_handle = Some(listener.tcp_ao_rotation_handle());
            let listener_peer_mgr_tx = peer_mgr_tx.clone();
            let listener_gate = daemon_gate.clone();
            tokio::spawn(async move {
                while let Some(conn) = accept_rx.recv().await {
                    // Coordinated shutdown has begun: drop (close) the
                    // socket instead of admitting a session into teardown.
                    if listener_gate.is_shutting_down() {
                        info!(
                            peer = %conn.peer_addr,
                            "rejecting inbound BGP connection: daemon is shutting down"
                        );
                        continue;
                    }
                    if let Err(e) = listener_peer_mgr_tx
                        .send(PeerManagerCommand::AcceptInbound {
                            stream: conn.stream,
                            peer_addr: conn.peer_addr,
                            tcp_ao_info: conn.tcp_ao_info,
                            tcp_ao_generation: conn.tcp_ao_generation,
                        })
                        .await
                    {
                        warn!(error = %e, "failed to forward inbound connection to peer manager");
                    }
                }
            });
            tokio::spawn(listener.run());
        }
        Err(e) => {
            if tcp_ao_listener_required {
                error!(
                    %listen_addr,
                    error = %e,
                    "failed to start BGP listener with TCP-AO-protected peers configured; refusing to run partially protected"
                );
                process::exit(1);
            }
            // The daemon can still open outbound sessions, but it is
            // unreachable for inbound peers — surface that on /readyz
            // instead of running silently unreachable.
            error!(
                %listen_addr,
                error = %e,
                "failed to bind BGP listener; inbound BGP sessions cannot be accepted — \
                 readiness reports not-ready until the daemon is restarted"
            );
            daemon_gate.mark_not_ready("BGP listener failed to bind");
        }
    }

    // Add initial peers from config via PeerManager
    for neighbor in peer_configs {
        let transport_config = neighbor.transport_config;
        let label = neighbor.label;
        let import_policy = neighbor.import_policy;
        let export_policy = neighbor.export_policy;
        let peer_group = neighbor.peer_group;
        info!(
            peer = %transport_config.remote_addr,
            label = %label,
            remote_asn = transport_config.peer.remote_asn,
            "adding peer from config"
        );
        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        let _ = peer_mgr_tx
            .send(PeerManagerCommand::AddPeer {
                config: PeerManagerNeighborConfig {
                    address: transport_config.remote_addr.ip(),
                    interface: transport_config.peer_interface.clone(),
                    scope_id: transport_config.peer_scope_id,
                    remote_asn: transport_config.peer.remote_asn,
                    description: label.clone(),
                    peer_group,
                    hold_time: Some(transport_config.peer.hold_time),
                    send_hold_time: Some(transport_config.peer.send_hold_time),
                    max_prefixes: transport_config.max_prefixes,
                    md5_password: transport_config
                        .md5_password
                        .as_ref()
                        .map(|secret| secret.as_ref().to_owned()),
                    tcp_ao: transport_config.tcp_ao.clone(),
                    ttl_security: transport_config.ttl_security,
                    families: transport_config.peer.families.clone(),
                    graceful_restart: transport_config.peer.graceful_restart,
                    gr_restart_time: transport_config.peer.gr_restart_time,
                    gr_stale_routes_time: transport_config.gr_stale_routes_time,
                    llgr_stale_time: transport_config.llgr_stale_time,
                    gr_restart_eligible: true,
                    local_ipv6_nexthop: transport_config.local_ipv6_nexthop,
                    route_reflector_client: transport_config.route_reflector_client,
                    orr_vantage: transport_config.orr_vantage,
                    route_server_client: transport_config.route_server_client,
                    per_client_best: transport_config.per_client_best,
                    remove_private_as: transport_config.remove_private_as,
                    add_path_receive: transport_config.peer.add_path_receive,
                    add_path_send: transport_config.peer.add_path_send,
                    add_path_send_max: transport_config.peer.add_path_send_max,
                    paths_limit_receive_max: transport_config.peer.paths_limit_receive_max,
                    local_role: transport_config.peer.local_role,
                    strict_role: transport_config.peer.strict_role,
                    prefix_orf_receive: transport_config.peer.prefix_orf_receive,
                    disable_ipv4_unicast: transport_config.peer.disable_ipv4_unicast,
                    import_policy,
                    export_policy,
                },
                sync_config_snapshot: false,
                reply: reply_tx,
            })
            .await;
        match reply_rx.await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => error!(label = %label, error = %e, "failed to add peer"),
            Err(e) => error!(label = %label, error = %e, "peer manager reply dropped"),
        }
    }

    // Spawn telemetry HTTP server (if configured). `/metrics` serves
    // Prometheus text; `/livez` and `/readyz` provide minimal probe bodies.
    // Spawn after startup wiring and initial peer registration so readiness
    // cannot go green while initialization is still in progress.
    if let Some(prometheus_addr) = config.prometheus_addr() {
        let metrics_clone = metrics.clone();
        let readiness_probe = rustbgpd_api::health_probe::CoreReadinessProbe::new(
            peer_mgr_tx.clone(),
            rib_query_tx.clone(),
        )
        .with_peer_manager_readiness(peer_mgr_readiness_tx.clone())
        .with_rib_readiness(rib_readiness_tx.clone())
        .with_gate(daemon_gate.clone());
        tokio::spawn(async move {
            metrics_server::serve_metrics(prometheus_addr, metrics_clone, readiness_probe).await;
        });
    }

    // Signal handlers (unix-only, which is our target)
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .unwrap_or_else(|e| fatal_startup_error("failed to register SIGTERM handler", e));
    let mut sighup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
        .unwrap_or_else(|e| fatal_startup_error("failed to register SIGHUP handler", e));

    // Wait for shutdown signal: SIGINT, SIGTERM, Shutdown RPC, unexpected gRPC exit, or SIGHUP
    //
    // SIGHUP runs `reload_config` on a dedicated tokio task so the
    // signal-arm dispatch returns immediately. Without this, the SIGHUP
    // arm's inline `.await` would block the same `select!` from
    // observing SIGINT/SIGTERM for the duration of the reload (up to
    // ~7 round-trip commands × 500 ms `PEER_POLICY_UPDATE_TIMEOUT` plus
    // reconcile round-trip). Operators hitting Ctrl-C mid-reload should
    // see the daemon respond.
    //
    // Concurrency invariant: at most one reload in flight. Concurrent
    // reloads would race on `peer_mgr_tx` ordering (interleaved
    // SetPolicy / ReconcilePeers commands) and double-fire the
    // post-reload sync. A SIGHUP that arrives while a reload is still
    // running is logged and dropped — the operator-facing back-pressure
    // surface.
    let mut reload_in_flight: Option<
        tokio::task::JoinHandle<Option<Result<Config, &'static str>>>,
    > = None;
    loop {
        tokio::select! {
            result = tokio::signal::ctrl_c() => {
                match result {
                    Ok(()) => info!("received SIGINT"),
                    Err(e) => error!(error = %e, "failed to listen for SIGINT"),
                }
                break;
            }
            _ = sigterm.recv() => {
                info!("received SIGTERM");
                break;
            }
            changed = rpc_shutdown_rx.changed() => {
                if changed.is_err() || !*rpc_shutdown_rx.borrow() {
                    continue;
                }
                info!("shutdown initiated via gRPC");
                break;
            }
            result = &mut grpc_handle => {
                error!(?result, "gRPC server exited unexpectedly");
                info!("initiating shutdown due to gRPC server failure");
                break;
            }
            _ = sighup.recv() => {
                if reload_in_flight.is_some() {
                    warn!("SIGHUP received while previous reload still in flight; ignoring");
                    continue;
                }
                info!("SIGHUP received, reloading configuration");
                let path = config.file_path.as_ref().map(|p| p.to_string_lossy().to_string()).unwrap_or_default();
                let live_tcp = live_grpc_tcp.clone();
                let live_uds = live_grpc_uds.clone();
                let pm_tx = peer_mgr_tx.clone();
                let fib_cmd = fib_cmd_tx.clone();
                let evpn_runtime_reload_apply = evpn_runtime_reload_apply.clone();
                // Hold the runtime-config coordinator lock across BOTH the
                // reload and the outcome application (peer-manager +
                // config-bridge snapshot refresh), so concurrent persisted
                // runtime CRUD can't slip into the gap and have its
                // applied/persisted state clobbered by a stale reload snapshot.
                let runtime_config_lock = runtime_config_lock.clone();
                let config_transaction_controller = config_transaction_controller.clone();
                let pm_internal = peer_mgr_internal_tx.clone();
                let bridge_replace = bridge_replace_tx.clone();
                let grpc_credentials = grpc_credentials.clone();
                let reload_metrics = metrics.clone();
                let tcp_ao_listener = tcp_ao_listener_handle.clone();
                reload_in_flight = Some(tokio::spawn(async move {
                    let _runtime_config_guard = runtime_config_lock.lock().await;
                    if let Err(error) = config_transaction_controller
                        .reject_if_pending("SIGHUP reload")
                        .await
                    {
                        warn!(
                            error = %error,
                            "SIGHUP reload ignored while confirmed config transaction is applying or pending"
                        );
                        return None;
                    }
                    if let Some(credentials) = grpc_credentials {
                        match credentials.reload() {
                            Ok(generation) => {
                                reload_metrics.record_grpc_credential_reload("success");
                                info!(generation, "gRPC credential generation reloaded");
                            }
                            Err(error) => {
                                reload_metrics.record_grpc_credential_reload("failure");
                                error!(error = %error, "gRPC credential reload rejected; last-known-good generation remains active");
                            }
                        }
                    }
                    let snapshot = match runtime_config_snapshot(&pm_tx).await {
                        Ok(snapshot) => snapshot,
                        Err(error) => {
                            error!(
                                error = %error,
                                "failed to read live runtime config snapshot for SIGHUP reload"
                            );
                            return None;
                        }
                    };
                    let reloaded = reload_config_with_tcp_ao(
                        &path,
                        &snapshot,
                        live_tcp.as_ref(),
                        live_uds.as_ref(),
                        &pm_tx,
                        fib_cmd.as_ref(),
                        Some(&evpn_runtime_reload_apply),
                        tcp_ao_listener.as_ref(),
                    )
                    .await?;
                    Some(apply_reload_outcome(reloaded, &pm_internal, bridge_replace.as_ref()).await)
                }));
            }
            // Only polled when a reload is in flight. Standard tokio
            // idiom: `std::future::pending().await` parks the arm
            // forever in the no-handle case so `select!` ignores it.
            // The `take()` drops the borrow before we touch
            // `reload_in_flight` again in the body, sidestepping the
            // borrow-across-await complaint.
            outcome = async {
                match reload_in_flight.as_mut() {
                    Some(handle) => handle.await,
                    None => std::future::pending().await,
                }
            } => {
                reload_in_flight = None;
                match outcome {
                    Ok(Some(Ok(advanced))) => config = advanced,
                    Ok(Some(Err(stage))) => error!(
                        stage,
                        "post-reload sync failed mid-flight; in-memory config not advanced — next SIGHUP will retry"
                    ),
                    Ok(None) => {
                        // reload_config returned None (failure) or short-circuited.
                    }
                    Err(e) => error!(error = %e, "reload task panicked"),
                }
            }
        }
    }

    // If a reload is still in flight at shutdown, abort it before
    // tearing down the peer manager. Letting it run would race the
    // peer manager's Shutdown command and potentially queue commands
    // against an already-draining manager. An EVPN runtime apply the
    // reload already started keeps running on its ADR-0080 detached
    // task; the apply-lock fence below serializes with it.
    if let Some(handle) = reload_in_flight.take() {
        handle.abort();
        let _ = handle.await;
    }

    // Drop the profiler now while all data structures are still alive,
    // so the heap snapshot captures the live working set.
    drop(profiler);

    // Coordinated shutdown:
    // 0. Flip the availability gate FIRST: readiness goes red, persisted
    //    config mutations are rejected, and new inbound BGP sessions are
    //    dropped — nothing new is admitted into the teardown below.
    // 1. Tell PeerManager to shut down (sends NOTIFICATIONs to all peers)
    daemon_gate.begin_shutdown();
    info!("initiating coordinated shutdown");
    let mut restart_time_secs = max_gr_restart_time_secs(&config);
    let mut checkpoint_generation = None;
    let mut checkpoint_failure = None;
    let mut _runtime_config_fence = None;
    let mut evpn_apply_fence = None;

    if warm_checkpoint_on_shutdown {
        if let Some(directory) = warm_bundle_directory.clone() {
            let deadline = tokio::time::Instant::now() + WARM_CHECKPOINT_DEADLINE;
            match tokio::time::timeout_at(deadline, runtime_config_lock.lock()).await {
                Ok(guard) => _runtime_config_fence = Some(guard),
                Err(_) => {
                    checkpoint_failure = Some(
                        "timed out acquiring the authoritative runtime-config fence".to_string(),
                    );
                }
            }
            if checkpoint_failure.is_none() {
                match tokio::time::timeout_at(deadline, evpn_runtime_apply_lock.lock()).await {
                    Ok(guard) => evpn_apply_fence = Some(guard),
                    Err(_) => {
                        checkpoint_failure =
                            Some("timed out waiting for the EVPN runtime-apply fence".to_string());
                    }
                }
            }
            if checkpoint_failure.is_none() {
                match tokio::time::timeout_at(deadline, query_warm_checkpoint_capture(&peer_mgr_tx))
                    .await
                {
                    Ok(Ok(capture)) => {
                        // Marker expiry and bundle identity come from this same
                        // actor-consistent capture. Main's Config can lag
                        // accepted runtime CRUD and is only the generationless
                        // compatibility fallback when capture itself fails.
                        restart_time_secs = capture.restart_time_secs;
                        if restart_time_secs.is_some() {
                            match tokio::time::timeout_at(
                                deadline,
                                publish_warm_checkpoint(
                                    capture,
                                    &rib_query_tx,
                                    directory,
                                    deadline.into_std(),
                                ),
                            )
                            .await
                            {
                                Ok(Ok(generation)) => {
                                    checkpoint_generation = Some(generation);
                                }
                                Ok(Err(error)) => checkpoint_failure = Some(error),
                                Err(_) => {
                                    checkpoint_failure = Some(format!(
                                        "warm checkpoint exceeded its {}s terminal deadline",
                                        WARM_CHECKPOINT_DEADLINE.as_secs()
                                    ));
                                }
                            }
                        }
                    }
                    Ok(Err(error)) => checkpoint_failure = Some(error),
                    Err(_) => {
                        checkpoint_failure = Some(format!(
                            "warm checkpoint capture exceeded its {}s terminal deadline",
                            WARM_CHECKPOINT_DEADLINE.as_secs()
                        ));
                    }
                }
            }
        } else {
            checkpoint_failure = Some(format!(
                "warm checkpoint directory {} was unavailable at startup",
                warm_bundle_path.display()
            ));
        }
    }

    if let Some(error) = checkpoint_failure.as_deref() {
        warn!(
            %error,
            "warm checkpoint publication failed; retaining a generationless GR marker"
        );
    }

    if let Some(restart_time_secs) = restart_time_secs {
        let restart_duration = Duration::from_secs(restart_time_secs);
        let publication = publish_gr_restart_marker_with_fallback(
            checkpoint_generation.as_deref(),
            |generation| {
                gr_restart_marker_store.as_ref().map_or_else(
                    || {
                        Err(std::io::Error::other(
                            "pinned runtime-state marker storage is unavailable",
                        )
                        .into())
                    },
                    |store| store.write_selected(restart_duration, generation),
                )
            },
        );
        if let Some(error) = publication.initial_error.as_ref() {
            warn!(
                marker = %gr_restart_marker_path.display(),
                marker_visible = error.visible_outcome.is_some(),
                %error,
                "initial GR restart marker publication did not reach directory-synced durability"
            );
        }
        if let Some(error) = publication.fallback_error.as_ref() {
            warn!(
                marker = %gr_restart_marker_path.display(),
                marker_visible = error.visible_outcome.is_some(),
                %error,
                "generationless GR restart marker fallback did not reach directory-synced durability"
            );
        }
        if let Some(visible) = publication.visible {
            let outcome = visible.outcome;
            if visible.durability == GrRestartMarkerDurability::VisibleDirectorySyncUncertain {
                warn!(
                    marker = %gr_restart_marker_path.display(),
                    marker_version = outcome.version,
                    checkpoint_generation = outcome.checkpoint_generation.as_deref().unwrap_or("none"),
                    publication_durability = visible.durability.as_str(),
                    "GR restart marker is visible but parent-directory durability is unconfirmed"
                );
            }
            if let Some(reason) = outcome.degraded_reason.as_deref() {
                warn!(
                    marker = %gr_restart_marker_path.display(),
                    marker_version = outcome.version,
                    %reason,
                    "published GR restart marker with wall-clock fallback because boottime protection was unavailable"
                );
            }
            info!(
                marker = %gr_restart_marker_path.display(),
                restart_time_secs,
                checkpoint_generation = outcome.checkpoint_generation.as_deref().unwrap_or("none"),
                marker_version = outcome.version,
                publication_durability = visible.durability.as_str(),
                "finished GR restart marker publication for coordinated shutdown"
            );
        } else {
            warn!(
                marker = %gr_restart_marker_path.display(),
                "neither publication attempt made a new GR restart marker visible — restarting-speaker mode is not guaranteed on the next start"
            );
        }
    } else if let Some(store) = gr_restart_marker_store.as_ref()
        && let Err(e) = store.remove()
    {
        warn!(
            marker = %gr_restart_marker_path.display(),
            error = %e,
            "failed to clear GR restart marker"
        );
    }
    // ADR-0080: fence in-flight EVPN runtime applies out of the teardown.
    // Applies run on detached tasks (a dropped or aborted caller cannot
    // cancel them mid-converge), so taking the apply lock here waits for
    // any such task to finish before we withdraw routes and drain actors —
    // and holding it for the rest of shutdown blocks a late apply from
    // re-originating routes after the withdraw-all sweep. Bounded so a
    // wedged converge cannot stall daemon exit.
    if evpn_apply_fence.is_none() {
        evpn_apply_fence = tokio::time::timeout(
            Duration::from_secs(10),
            evpn_runtime_apply_lock.lock(),
        )
        .await
        .inspect_err(|_| {
            warn!(
                "EVPN runtime apply still in flight after 10s; proceeding with shutdown teardown"
            );
        })
        .ok();
    }
    let _evpn_apply_fence_guard = evpn_apply_fence;

    // 1.9a-pre Stop the ADR-0085 link-drain coordinator before the
    // EVPN actors drain: a carrier edge arriving mid-teardown must
    // not race the orchestrated withdraws (any in-flight apply still
    // serializes on the EVPN runtime apply lock).
    evpn_es_link_drain_shutdown.cancel();

    // 1.9a Drain the EVPN local-MAC originator first — BEFORE the
    // peer manager shutdown — so its Type 2 Withdraws ride the still-
    // open BGP sessions to peers. `RibUpdate::WithdrawEvpn` recomputes
    // and stages outbound updates before replying, so the transport
    // path picks them up if (and only if) the peer sessions are still
    // alive. Doing this after `PeerManagerCommand::Shutdown` would
    // leave peers with stale Type 2 routes on their LocRib until our
    // hold-timer expired on their side.
    //
    // Bounded 5 s drain — the originator's `drain_to_withdraws`
    // emits one Withdraw per still-advertised MAC.
    if let Some(handle) = evpn_originator_handle {
        info!("draining EVPN originator");
        handle.shutdown().await;
    }

    // 1.9a' Drain the SVI-MAC originator first — same ordering
    // rationale as the local-MAC originator: SVI Type 2 withdraws
    // must land while peer sessions are still up.
    if let Some(handle) = evpn_svi_handle {
        info!("draining EVPN SVI-MAC originator");
        handle.shutdown().await;
    }

    // 1.9a''' Drain the EVPN L3 (Type 5) originator. Same ordering
    // rationale: Type 5 withdraws must reach peers before BGP
    // sessions tear down so remote VTEPs flush their kernel FIBs
    // cleanly. The originator's diff loop emits one
    // `RibUpdate::WithdrawEvpn` per currently-originated prefix.
    if let Some(handle) = evpn_l3_originator_handle {
        info!("draining EVPN L3 originator");
        handle.shutdown().await;
    }

    // 1.9a'' Drain the EVPN segment orchestrator — withdraws all
    // Type 4 ES + Type 1 EAD-per-ES + Type 1 EAD-per-EVI routes
    // before peer sessions tear down. Same ordering rationale as
    // the originator + SVI tasks.
    if let Some(handle) = evpn_segment_handle {
        info!("draining EVPN segment orchestrator");
        handle.shutdown().await;
    }

    // 1.9b Withdraw the Type 3 IMET routes we originated at startup
    // so peers cleanly remove us from their ingress-replication
    // lists. Same ordering rationale as the Type 2 drain — must land
    // before peer sessions tear down.
    let mut imet_controller = evpn_imet_controller.lock().await;
    if !imet_controller.is_empty() {
        info!(
            count = imet_controller.len(),
            "withdrawing EVPN Type 3 IMET routes"
        );
        imet_controller.withdraw_all(&rib_tx).await;
    }
    drop(imet_controller);

    let _ = peer_mgr_tx.send(PeerManagerCommand::Shutdown).await;

    // 2. Wait for PeerManager to finish draining all peers
    if let Err(e) = peer_mgr_handle.await {
        error!(error = %e, "peer manager task panicked");
    }

    // 2.4 Drain daemon-owned BLACKHOLE discard routes. This is local
    // kernel state only, so it does not need live BGP sessions. The
    // actor removes only prefixes it successfully installed during
    // this daemon lifetime.
    if let Some(handle) = blackhole_handle {
        info!("draining BLACKHOLE discard routes");
        handle.shutdown().await;
    }

    // 2.45 Drain daemon-owned ADR-0061 general FIB routes. This is
    // local kernel state only, so it does not need live BGP sessions.
    if let Some(handle) = fib_runtime_handle {
        info!("draining general FIB routes");
        handle.shutdown().await;
    }

    // Drain BFD sessions (emits AdminDown so peers go Down promptly).
    if let Some(handle) = bfd_runtime_handle {
        info!("draining BFD sessions");
        handle.shutdown().await;
    }

    // 2.5 Drain the EVPN Linux dataplane reconciler. The actor
    // withdraws every owned remote-MAC FDB entry under a bounded
    // 5 s drain (ADR-0054 §7) and exits; foreign entries
    // (kernel-learned local MACs, operator-static FDB entries) are
    // structurally untouched by the diff loop and survive the drain.
    // This runs after the peer manager because the kernel-side FDB
    // teardown does not need an active BGP session.
    if let Some(handle) = evpn_dataplane_handle {
        info!("draining EVPN dataplane");
        handle.shutdown().await;
    }

    // 3. Shut down BMP subsystem (send explicit shutdown and await bounded drain)
    if let Some(mut bmp_runtime) = bmp_runtime {
        if let Err(e) = bmp_runtime
            .control_tx
            .send(rustbgpd_bmp::BmpControlEvent::Shutdown)
            .await
        {
            warn!(error = %e, "failed to send BMP shutdown control event");
        }

        match tokio::time::timeout(Duration::from_secs(2), &mut bmp_runtime.manager_handle).await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => warn!(error = %e, "BMP manager task panicked during shutdown"),
            Err(_) => {
                warn!("BMP manager did not exit within 2s; aborting task");
                bmp_runtime.manager_handle.abort();
            }
        }

        for mut handle in bmp_runtime.client_handles {
            match tokio::time::timeout(Duration::from_secs(2), &mut handle).await {
                Ok(Ok(())) => {}
                Ok(Err(e)) => warn!(error = %e, "BMP client task panicked during shutdown"),
                Err(_) => {
                    warn!("BMP client did not exit within 2s; aborting task");
                    handle.abort();
                }
            }
        }
    }

    // 4. Stop the gRPC server
    let _ = grpc_shutdown_tx.send(());

    // 5. Shut down the durable event outbox (ADR-0072) after the
    // producers and gRPC have drained. EHM owns its own bounded
    // 5-second hard timeout on the storage thread; we don't await
    // unconditionally because a wedged SQLite must not stall the
    // daemon exit. Holding EHM alive across the producer + gRPC
    // drain means any final SubscribeFromEvent observers see their
    // last committed events and any in-flight `try_send` reaches
    // disk before shutdown.
    if let Some(manager) = event_history_manager {
        info!("flushing event history outbox");
        manager.shutdown().await;
    }

    info!("rustbgpd exiting");
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    fn unique_temp_path(name: &str) -> PathBuf {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("rustbgpd-{name}-{suffix}.toml"))
    }

    fn marker_store() -> (tempfile::TempDir, GrRestartMarkerStore) {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let pinned = PinnedRuntimeStateDirectory::prepare(dir.path()).unwrap();
        (dir, GrRestartMarkerStore::new(Arc::new(pinned)))
    }

    fn test_clock_sample(boottime_ms: u64) -> GrRestartClockSample {
        GrRestartClockSample {
            boot_id: "12345678-1234-4abc-8def-1234567890ab".to_string(),
            time_namespace_dev: 17,
            time_namespace_ino: 23,
            boottime_offset_secs: -4,
            boottime_offset_nanos: 500_000_000,
            boottime_ms,
        }
    }

    fn write_test_marker(
        store: &GrRestartMarkerStore,
        restart_duration: Duration,
        checkpoint_generation: Option<&str>,
        fault: MarkerFaultPoint,
        wall_now: SystemTime,
        clock_sample: Result<GrRestartClockSample, String>,
    ) -> Result<GrRestartMarkerWriteOutcome, GrRestartMarkerWriteError> {
        store.write_inner_with_sample(
            restart_duration,
            checkpoint_generation,
            fault,
            wall_now,
            clock_sample,
        )
    }

    fn write_test_v3(
        store: &GrRestartMarkerStore,
        checkpoint_generation: Option<&str>,
    ) -> Result<GrRestartMarkerWriteOutcome, GrRestartMarkerWriteError> {
        write_test_marker(
            store,
            Duration::from_mins(2),
            checkpoint_generation,
            MarkerFaultPoint::None,
            UNIX_EPOCH + Duration::from_hours(10),
            Ok(test_clock_sample(10_000)),
        )
    }

    fn write_test_legacy(
        store: &GrRestartMarkerStore,
        restart_duration: Duration,
        checkpoint_generation: Option<&str>,
        wall_now: SystemTime,
    ) -> Result<GrRestartMarkerWriteOutcome, GrRestartMarkerWriteError> {
        write_test_marker(
            store,
            restart_duration,
            checkpoint_generation,
            MarkerFaultPoint::None,
            wall_now,
            Err("injected clock sample failure".to_string()),
        )
    }

    fn valid_test_v3(expires_at: SystemTime, expires_at_boottime_ms: u64) -> ValidGrRestartMarker {
        ValidGrRestartMarker {
            version: GR_RESTART_MARKER_V3,
            expires_at,
            checkpoint_generation: None,
            clock_domain: Some(GrRestartClockDomain {
                boot_id: "12345678-1234-4abc-8def-1234567890ab".to_string(),
                time_namespace_dev: 17,
                time_namespace_ino: 23,
                boottime_offset_secs: -4,
                boottime_offset_nanos: 500_000_000,
                expires_at_boottime_ms,
            }),
            storage_sha256: None,
        }
    }

    fn publish_test_marker_schedule(
        store: &GrRestartMarkerStore,
        checkpoint_generation: Option<&str>,
        faults: &[MarkerFaultPoint],
    ) -> GrRestartMarkerPublicationResult {
        let mut faults = faults.iter().copied();
        publish_gr_restart_marker_with_fallback(checkpoint_generation, |generation| {
            write_test_marker(
                store,
                Duration::from_mins(2),
                generation,
                faults.next().unwrap_or(MarkerFaultPoint::None),
                UNIX_EPOCH + Duration::from_hours(10),
                Ok(test_clock_sample(10_000)),
            )
        })
    }

    fn assert_test_v3_on_disk(store: &GrRestartMarkerStore, checkpoint_generation: Option<&str>) {
        let marker = store.read().unwrap().unwrap();
        assert_eq!(marker.version, GR_RESTART_MARKER_V3);
        assert_eq!(
            marker.checkpoint_generation.as_deref(),
            checkpoint_generation
        );
        assert_eq!(
            marker.clock_domain,
            Some(GrRestartClockDomain {
                boot_id: "12345678-1234-4abc-8def-1234567890ab".to_string(),
                time_namespace_dev: 17,
                time_namespace_ino: 23,
                boottime_offset_secs: -4,
                boottime_offset_nanos: 500_000_000,
                expires_at_boottime_ms: 130_000,
            })
        );
    }

    fn v3_marker_toml() -> String {
        [
            "version = 3",
            "expires_at_unix = 36000",
            "boot_id = \"12345678-1234-4abc-8def-1234567890ab\"",
            "time_namespace_dev = 17",
            "time_namespace_ino = 23",
            "boottime_offset_secs = -4",
            "boottime_offset_nanos = 500000000",
            "expires_at_boottime_ms = 130000",
            "",
        ]
        .join("\n")
    }

    fn load_config_from_toml(name: &str, toml: &str) -> Config {
        let path = unique_temp_path(name);
        std::fs::write(&path, toml).unwrap();
        let config = Config::load_with_diagnostics(path.to_str().unwrap()).unwrap();
        std::fs::remove_file(&path).ok();
        config
    }

    #[test]
    fn panic_report_has_expected_shape_and_no_env_or_args() {
        let dir = tempfile::tempdir().unwrap();
        write_panic_report(
            dir.path(),
            "explicit panic for shape test",
            "src/main.rs:1:1",
            "main",
        )
        .unwrap();

        let report_path = std::fs::read_dir(dir.path())
            .unwrap()
            .flatten()
            .map(|e| e.path())
            .find(|p| {
                let name = p.file_name().unwrap().to_str().unwrap();
                name.starts_with("panic-")
                    && Path::new(name)
                        .extension()
                        .is_some_and(|ext| ext.eq_ignore_ascii_case("toml"))
            })
            .expect("one panic report written");
        let body = std::fs::read_to_string(report_path).unwrap();
        let value: toml::Value = toml::from_str(&body).expect("report is valid TOML");

        assert_eq!(
            value.get("message").and_then(toml::Value::as_str),
            Some("explicit panic for shape test")
        );
        assert_eq!(
            value.get("location").and_then(toml::Value::as_str),
            Some("src/main.rs:1:1")
        );
        assert_eq!(
            value.get("thread").and_then(toml::Value::as_str),
            Some("main")
        );
        assert_eq!(
            value.get("version").and_then(toml::Value::as_str),
            Some(env!("CARGO_PKG_VERSION"))
        );
        assert!(
            value.get("timestamp_unix_seconds").is_some(),
            "timestamp recorded"
        );
        // Human-panic pattern: never environment or argv material.
        assert!(value.get("env").is_none());
        assert!(value.get("args").is_none());
    }

    #[test]
    fn panic_reports_are_pruned_to_retention_keeping_newest() {
        let dir = tempfile::tempdir().unwrap();
        // Seed 12 pre-existing reports older than anything written now.
        for i in 0..12 {
            std::fs::write(
                dir.path().join(format!("panic-{i:010}-000.toml")),
                "message = \"old\"\n",
            )
            .unwrap();
        }
        write_panic_report(dir.path(), "newest", "src/main.rs:1:1", "main").unwrap();

        let mut names: Vec<String> = std::fs::read_dir(dir.path())
            .unwrap()
            .flatten()
            .filter_map(|e| e.file_name().into_string().ok())
            .collect();
        names.sort();
        assert_eq!(names.len(), PANIC_REPORTS_KEPT, "pruned to retention");
        // The newest report (largest timestamp) survives the prune.
        let newest = std::fs::read_to_string(dir.path().join(names.last().unwrap())).unwrap();
        assert!(newest.contains("newest"));
        // The oldest seeded reports were removed first.
        assert!(!names.contains(&"panic-0000000000-000.toml".to_string()));
        assert!(!names.contains(&"panic-0000000001-000.toml".to_string()));
    }

    #[test]
    fn man_page_is_roff_and_documents_the_flags() {
        let man = man_page();
        assert!(man.starts_with(".TH RUSTBGPD 8"), "missing roff .TH header");
        for flag in [
            r"\-\-check",
            r"\-\-diff",
            r"\-\-json",
            r"\-\-init\-config",
            r"\-\-stdout",
            r"\-\-dump\-config\-schema",
            r"\-\-man",
            r"\-\-version",
            r"\-\-help",
        ] {
            assert!(man.contains(flag), "man page missing {flag}");
        }
        assert!(man.contains("SIGHUP"));
    }

    fn tcp_ao_neighbor_toml(address: &str) -> String {
        format!(
            r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
log_format = "json"

[[neighbors]]
address = "{address}"
remote_asn = 65002
tcp_ao = {{ key = "secret", send_id = 1, recv_id = 1, algorithm = "hmac(sha256)" }}
"#
        )
    }

    #[test]
    fn worker_thread_resolution_precedence() {
        // env (positive) wins over config and default.
        assert_eq!(
            resolve_worker_threads_from(Some("4".to_string()), Some(2)),
            4
        );
        // config wins when env is absent; an explicit value is NOT capped.
        assert_eq!(resolve_worker_threads_from(None, Some(16)), 16);
        // zero / unparseable env is ignored, falling through to config.
        assert_eq!(
            resolve_worker_threads_from(Some("0".to_string()), Some(3)),
            3
        );
        assert_eq!(
            resolve_worker_threads_from(Some("nope".to_string()), Some(3)),
            3
        );
        // zero config is ignored, falling through to the capped default.
        let default_zero = resolve_worker_threads_from(None, Some(0));
        assert!((1..=DEFAULT_WORKER_THREAD_CAP).contains(&default_zero));
        // no env, no config → capped default in [1, 8].
        let default = resolve_worker_threads_from(None, None);
        assert!((1..=DEFAULT_WORKER_THREAD_CAP).contains(&default));
    }

    #[test]
    fn rib_channel_capacity_override_parse_rules() {
        // Unset → production default.
        assert_eq!(
            resolve_rib_channel_capacity_from(None),
            RIB_CHANNEL_CAPACITY
        );
        // Valid positive integer → override, whitespace tolerated.
        assert_eq!(resolve_rib_channel_capacity_from(Some("2")), 2);
        assert_eq!(resolve_rib_channel_capacity_from(Some(" 16 ")), 16);
        // Zero, garbage, and empty values keep the production default.
        assert_eq!(
            resolve_rib_channel_capacity_from(Some("0")),
            RIB_CHANNEL_CAPACITY
        );
        assert_eq!(
            resolve_rib_channel_capacity_from(Some("")),
            RIB_CHANNEL_CAPACITY
        );
        assert_eq!(
            resolve_rib_channel_capacity_from(Some("tiny")),
            RIB_CHANNEL_CAPACITY
        );
        assert_eq!(
            resolve_rib_channel_capacity_from(Some("-1")),
            RIB_CHANNEL_CAPACITY
        );
    }

    #[test]
    fn gr_restart_marker_v3_round_trips_with_and_without_generation() {
        let (_dir, store) = marker_store();
        for generation in [None, Some("checkpoint-0007")] {
            let outcome = write_test_v3(&store, generation).unwrap();
            assert_eq!(outcome.version, GR_RESTART_MARKER_V3);
            assert_eq!(outcome.checkpoint_generation.as_deref(), generation);
            assert_eq!(outcome.degraded_reason, None);

            let read_back = store.read().unwrap().unwrap();
            assert_eq!(read_back.version, GR_RESTART_MARKER_V3);
            assert_eq!(read_back.checkpoint_generation.as_deref(), generation);
            assert_eq!(
                read_back.clock_domain,
                Some(GrRestartClockDomain {
                    boot_id: "12345678-1234-4abc-8def-1234567890ab".to_string(),
                    time_namespace_dev: 17,
                    time_namespace_ino: 23,
                    boottime_offset_secs: -4,
                    boottime_offset_nanos: 500_000_000,
                    expires_at_boottime_ms: 130_000,
                })
            );
        }
        store.remove().unwrap();
    }

    #[test]
    fn gr_restart_marker_v1_and_v2_remain_compatible() {
        let (_dir, store) = marker_store();
        let wall_now = UNIX_EPOCH + Duration::from_hours(10);
        for (generation, version) in [
            (None, GR_RESTART_MARKER_V1),
            (Some("checkpoint-0007"), GR_RESTART_MARKER_V2),
        ] {
            let outcome =
                write_test_legacy(&store, Duration::from_mins(2), generation, wall_now).unwrap();
            assert_eq!(outcome.version, version);
            assert!(outcome.degraded_reason.is_some());
            let read_back = store.read().unwrap().unwrap();
            assert_eq!(read_back.version, version);
            assert_eq!(read_back.checkpoint_generation.as_deref(), generation);
            assert_eq!(read_back.clock_domain, None);
            assert_eq!(read_back.expires_at, wall_now + Duration::from_mins(2));
        }
        store.remove().unwrap();
    }

    #[test]
    fn marker_builder_downgrades_sampling_overflow_and_serializer_range_failures_atomically() {
        let (_dir, store) = marker_store();
        let wall_now = UNIX_EPOCH + Duration::from_hours(10);
        let cases = [
            Err("sample unavailable".to_string()),
            Ok(GrRestartClockSample {
                boottime_ms: u64::MAX,
                ..test_clock_sample(0)
            }),
            Ok(GrRestartClockSample {
                time_namespace_dev: u64::MAX,
                ..test_clock_sample(0)
            }),
            Ok(GrRestartClockSample {
                time_namespace_ino: u64::MAX,
                ..test_clock_sample(0)
            }),
            Ok(GrRestartClockSample {
                boottime_ms: i64::MAX.unsigned_abs(),
                ..test_clock_sample(0)
            }),
        ];

        for (generation, expected_version) in [
            (None, GR_RESTART_MARKER_V1),
            (Some("generation"), GR_RESTART_MARKER_V2),
        ] {
            for sample in cases.clone() {
                let outcome = write_test_marker(
                    &store,
                    Duration::from_millis(1),
                    generation,
                    MarkerFaultPoint::None,
                    wall_now,
                    sample,
                )
                .unwrap();
                assert_eq!(outcome.version, expected_version);
                assert_eq!(outcome.checkpoint_generation.as_deref(), generation);
                assert!(outcome.degraded_reason.is_some());

                let encoded = std::fs::read_to_string(store.display_path()).unwrap();
                for field in [
                    "boot_id",
                    "time_namespace_dev",
                    "time_namespace_ino",
                    "boottime_offset_secs",
                    "boottime_offset_nanos",
                    "expires_at_boottime_ms",
                ] {
                    assert!(!encoded.contains(field), "unexpected {field} in {encoded}");
                }
                let marker = store.read().unwrap().unwrap();
                assert_eq!(marker.version, expected_version);
                assert_eq!(marker.clock_domain, None);
            }
        }
        store.remove().unwrap();
    }

    #[test]
    fn legacy_decoder_rejects_v3_unknown_clock_fields() {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct LegacyMarker {
            #[allow(dead_code)]
            version: u8,
            #[allow(dead_code)]
            expires_at_unix: u64,
            #[allow(dead_code)]
            #[serde(default)]
            checkpoint_generation: Option<String>,
        }

        let (_dir, store) = marker_store();
        write_test_v3(&store, Some("generation")).unwrap();
        let encoded = std::fs::read_to_string(store.display_path()).unwrap();
        assert!(toml::from_str::<LegacyMarker>(&encoded).is_err());

        // The older process treats the unknown v3 shape as one cold start and
        // removes it; subsequent starts see no marker to reject again.
        store.remove().unwrap();
        assert!(store.read().unwrap().is_none());
    }

    #[test]
    fn gr_restart_marker_invalid_shapes_are_rejected() {
        use std::os::unix::fs::PermissionsExt as _;

        let (_dir, store) = marker_store();
        let path = store.display_path();
        std::fs::write(&path, "version = 3\nexpires_at_unix = 1\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let err = store.read().unwrap_err();
        assert!(err.contains("requires all clock-domain fields"));
        std::fs::write(&path, "version = 2\nexpires_at_unix = 1\n").unwrap();
        let err = store.read().unwrap_err();
        assert!(err.contains("missing checkpoint_generation"));
        std::fs::write(
            &path,
            "version = 1\nexpires_at_unix = 1\ncheckpoint_generation = \"unexpected\"\n",
        )
        .unwrap();
        let err = store.read().unwrap_err();
        assert!(err.contains("v1 must not carry"));
        store.remove().unwrap();
    }

    #[test]
    fn gr_restart_marker_v3_requires_exact_clock_field_set() {
        let complete = v3_marker_toml();
        let parsed: GrRestartMarker = toml::from_str(&complete).unwrap();
        assert!(validate_gr_restart_marker(parsed).is_ok());

        for field in [
            "boot_id",
            "time_namespace_dev",
            "time_namespace_ino",
            "boottime_offset_secs",
            "boottime_offset_nanos",
            "expires_at_boottime_ms",
        ] {
            let partial = complete
                .lines()
                .filter(|line| !line.starts_with(&format!("{field} =")))
                .collect::<Vec<_>>()
                .join("\n");
            let marker: GrRestartMarker = toml::from_str(&partial).unwrap();
            let error = validate_gr_restart_marker(marker).unwrap_err();
            assert!(
                error.contains("requires all clock-domain fields"),
                "missing {field}: {error}"
            );
        }

        for version in [GR_RESTART_MARKER_V1, GR_RESTART_MARKER_V2] {
            let generation = if version == GR_RESTART_MARKER_V2 {
                "checkpoint_generation = \"legacy\"\n"
            } else {
                ""
            };
            let encoded = format!(
                "version = {version}\nexpires_at_unix = 1\n{generation}boot_id = \"12345678-1234-4abc-8def-1234567890ab\"\n"
            );
            let marker: GrRestartMarker = toml::from_str(&encoded).unwrap();
            assert!(validate_gr_restart_marker(marker).is_err());
        }
        let unknown = format!("{complete}unexpected_clock_field = 1\n");
        assert!(toml::from_str::<GrRestartMarker>(&unknown).is_err());
    }

    #[test]
    fn gr_restart_marker_v3_validates_uuid_offsets_and_signed_integer_domain() {
        let uppercase = v3_marker_toml().replace(
            "12345678-1234-4abc-8def-1234567890ab",
            "12345678-1234-4ABC-8DEF-1234567890AB",
        );
        let marker: GrRestartMarker = toml::from_str(&uppercase).unwrap();
        assert!(
            validate_gr_restart_marker(marker)
                .unwrap_err()
                .contains("canonical")
        );

        let bad_nanos = v3_marker_toml().replace("500000000", "1000000000");
        let marker: GrRestartMarker = toml::from_str(&bad_nanos).unwrap();
        assert!(
            validate_gr_restart_marker(marker)
                .unwrap_err()
                .contains("nanoseconds")
        );

        let negative_offset: GrRestartMarker = toml::from_str(&v3_marker_toml()).unwrap();
        assert_eq!(
            validate_gr_restart_marker(negative_offset)
                .unwrap()
                .clock_domain
                .unwrap()
                .boottime_offset_secs,
            -4
        );

        let out_of_range = v3_marker_toml().replace(
            "time_namespace_dev = 17",
            "time_namespace_dev = 9223372036854775808",
        );
        assert!(toml::from_str::<GrRestartMarker>(&out_of_range).is_err());

        let negative_device =
            v3_marker_toml().replace("time_namespace_dev = 17", "time_namespace_dev = -1");
        let marker: GrRestartMarker = toml::from_str(&negative_device).unwrap();
        assert!(
            validate_gr_restart_marker(marker)
                .unwrap_err()
                .contains("nonnegative")
        );
    }

    #[test]
    fn boottime_offset_parser_is_strict_and_accepts_negative_seconds() {
        assert_eq!(
            parse_boottime_offset("monotonic 0 0\nboottime -9 42\n").unwrap(),
            (-9, 42)
        );
        for invalid in [
            "monotonic 0 0\n",
            "boottime 0\n",
            "boottime 0 0 extra\n",
            "boottime 0 1000000000\n",
            "boottime 0 0\nboottime 0 0\n",
        ] {
            assert!(parse_boottime_offset(invalid).is_err(), "{invalid:?}");
        }
    }

    #[test]
    fn gr_restart_marker_precommit_failures_preserve_previous_generation() {
        let (_dir, store) = marker_store();
        write_test_v3(&store, Some("committed")).unwrap();

        for fault in [
            MarkerFaultPoint::Write,
            MarkerFaultPoint::FileSync,
            MarkerFaultPoint::Rename,
        ] {
            let result = write_test_marker(
                &store,
                Duration::from_mins(2),
                Some("uncommitted"),
                fault,
                UNIX_EPOCH + Duration::from_hours(10),
                Ok(test_clock_sample(10_000)),
            );
            assert!(result.is_err(), "fault {fault:?} must fail");
            let marker = store.read().unwrap().unwrap();
            assert_eq!(marker.version, GR_RESTART_MARKER_V3);
            assert!(marker.clock_domain.is_some());
            assert_eq!(
                marker.checkpoint_generation.as_deref(),
                Some("committed"),
                "fault {fault:?} must preserve the prior committed marker"
            );
        }
        store.remove().unwrap();
    }

    #[test]
    fn generationless_retry_reports_the_marker_it_actually_committed() {
        let (_dir, store) = marker_store();
        let failed = write_test_marker(
            &store,
            Duration::from_mins(2),
            Some("uncommitted"),
            MarkerFaultPoint::Write,
            UNIX_EPOCH + Duration::from_hours(10),
            Ok(test_clock_sample(10_000)),
        );
        assert!(failed.is_err());

        let outcome = write_test_v3(&store, None).unwrap();
        assert_eq!(outcome.version, GR_RESTART_MARKER_V3);
        assert_eq!(outcome.checkpoint_generation, None);
        assert_eq!(outcome.degraded_reason, None);
        let marker = store.read().unwrap().unwrap();
        assert_eq!(marker.version, GR_RESTART_MARKER_V3);
        assert_eq!(marker.checkpoint_generation, None);
        store.remove().unwrap();
    }

    #[test]
    fn gr_restart_marker_postrename_failure_exposes_only_complete_v3() {
        let (_dir, store) = marker_store();
        write_test_v3(&store, Some("old")).unwrap();

        let result = write_test_marker(
            &store,
            Duration::from_mins(2),
            Some("new"),
            MarkerFaultPoint::DirectorySync,
            UNIX_EPOCH + Duration::from_hours(10),
            Ok(test_clock_sample(10_000)),
        );
        assert!(result.is_err());
        let marker = store.read().unwrap().unwrap();
        assert_eq!(marker.version, GR_RESTART_MARKER_V3);
        assert!(marker.clock_domain.is_some());
        assert_eq!(marker.checkpoint_generation.as_deref(), Some("new"));
        store.remove().unwrap();
    }

    #[test]
    fn generationless_postrename_failure_reports_visible_uncertain_marker() {
        let (_dir, store) = marker_store();
        let publication =
            publish_test_marker_schedule(&store, None, &[MarkerFaultPoint::DirectorySync]);

        assert!(
            publication
                .initial_error
                .as_ref()
                .is_some_and(|error| error.visible_outcome.is_some())
        );
        assert!(publication.fallback_error.is_none());
        let visible = publication.visible.unwrap();
        assert_eq!(
            visible.durability,
            GrRestartMarkerDurability::VisibleDirectorySyncUncertain
        );
        assert_eq!(visible.outcome.version, GR_RESTART_MARKER_V3);
        assert_eq!(visible.outcome.checkpoint_generation, None);
        assert_test_v3_on_disk(&store, None);
    }

    #[test]
    fn generation_bound_postrename_failure_then_fallback_success_reports_synced_generationless() {
        let (_dir, store) = marker_store();
        let publication = publish_test_marker_schedule(
            &store,
            Some("generation"),
            &[MarkerFaultPoint::DirectorySync, MarkerFaultPoint::None],
        );

        assert!(publication.initial_error.is_some());
        assert!(publication.fallback_error.is_none());
        let visible = publication.visible.unwrap();
        assert_eq!(
            visible.durability,
            GrRestartMarkerDurability::DirectorySynced
        );
        assert_eq!(visible.outcome.version, GR_RESTART_MARKER_V3);
        assert_eq!(visible.outcome.checkpoint_generation, None);
        assert_test_v3_on_disk(&store, None);
    }

    #[test]
    fn fallback_precommit_failure_retains_visible_generation_bound_marker() {
        let (_dir, store) = marker_store();
        let publication = publish_test_marker_schedule(
            &store,
            Some("generation"),
            &[MarkerFaultPoint::DirectorySync, MarkerFaultPoint::Write],
        );

        assert!(publication.initial_error.is_some());
        assert!(
            publication
                .fallback_error
                .as_ref()
                .is_some_and(|error| error.visible_outcome.is_none())
        );
        let visible = publication.visible.unwrap();
        assert_eq!(
            visible.durability,
            GrRestartMarkerDurability::VisibleDirectorySyncUncertain
        );
        assert_eq!(visible.outcome.version, GR_RESTART_MARKER_V3);
        assert_eq!(
            visible.outcome.checkpoint_generation.as_deref(),
            Some("generation")
        );
        assert_test_v3_on_disk(&store, Some("generation"));
    }

    #[test]
    fn fallback_postrename_failure_reports_visible_generationless_marker() {
        let (_dir, store) = marker_store();
        let publication = publish_test_marker_schedule(
            &store,
            Some("generation"),
            &[
                MarkerFaultPoint::DirectorySync,
                MarkerFaultPoint::DirectorySync,
            ],
        );

        assert!(publication.initial_error.is_some());
        assert!(
            publication
                .fallback_error
                .as_ref()
                .is_some_and(|error| error.visible_outcome.is_some())
        );
        let visible = publication.visible.unwrap();
        assert_eq!(
            visible.durability,
            GrRestartMarkerDurability::VisibleDirectorySyncUncertain
        );
        assert_eq!(visible.outcome.version, GR_RESTART_MARKER_V3);
        assert_eq!(visible.outcome.checkpoint_generation, None);
        assert_test_v3_on_disk(&store, None);
    }

    #[test]
    fn inherited_marker_expiry_cannot_remove_replacement_generation() {
        let (_dir, store) = marker_store();
        write_test_v3(&store, Some("old")).unwrap();
        let inherited = store.read().unwrap().unwrap();

        write_test_v3(&store, Some("new")).unwrap();
        assert!(!store.remove_if_matches(&inherited).unwrap());
        assert_eq!(
            store
                .read()
                .unwrap()
                .unwrap()
                .checkpoint_generation
                .as_deref(),
            Some("new")
        );
    }

    #[test]
    fn inherited_marker_expiry_compares_exact_bytes_not_parsed_semantics() {
        let (_dir, store) = marker_store();
        write_test_legacy(
            &store,
            Duration::from_hours(500_000),
            Some("same"),
            UNIX_EPOCH,
        )
        .unwrap();
        let inherited = store.read().unwrap().unwrap();

        // Same parsed marker, different exact stored bytes and therefore a
        // distinct publisher identity.
        std::fs::write(
            store.display_path(),
            "# replacement\ncheckpoint_generation = \"same\"\nexpires_at_unix = 1800000000\nversion = 2\n",
        )
        .unwrap();
        assert!(!store.remove_if_matches(&inherited).unwrap());
        assert!(store.display_path().exists());
        assert_eq!(
            store
                .read()
                .unwrap()
                .unwrap()
                .checkpoint_generation
                .as_deref(),
            Some("same")
        );
    }

    #[test]
    fn pinned_marker_and_bundle_ignore_runtime_path_replacement() {
        use std::os::unix::fs::{PermissionsExt as _, symlink};

        let parent = tempfile::tempdir().unwrap();
        let runtime = parent.path().join("runtime");
        std::fs::create_dir(&runtime).unwrap();
        std::fs::set_permissions(&runtime, std::fs::Permissions::from_mode(0o700)).unwrap();
        let pinned = Arc::new(PinnedRuntimeStateDirectory::prepare(&runtime).unwrap());
        let store = GrRestartMarkerStore::new(Arc::clone(&pinned));

        let original = parent.path().join("original");
        std::fs::rename(&runtime, &original).unwrap();
        let attacker = parent.path().join("attacker");
        std::fs::create_dir(&attacker).unwrap();
        symlink(&attacker, &runtime).unwrap();

        store
            .write_selected(Duration::from_mins(2), Some("pinned"))
            .unwrap();
        pinned.prepare_warm_bundle().unwrap();
        assert!(original.join(GR_RESTART_MARKER_FILE).is_file());
        assert!(original.join(WARM_BUNDLE_DIRECTORY).is_dir());
        assert!(!attacker.join(GR_RESTART_MARKER_FILE).exists());
        assert!(!attacker.join(WARM_BUNDLE_DIRECTORY).exists());
    }

    #[test]
    fn marker_storage_rejects_symlinks_and_unsafe_modes() {
        use std::os::unix::fs::{PermissionsExt as _, symlink};

        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let target = dir.path().join("target");
        std::fs::write(&target, "version = 1\nexpires_at_unix = 1\n").unwrap();
        symlink(&target, dir.path().join(GR_RESTART_MARKER_FILE)).unwrap();
        let store = GrRestartMarkerStore::new(Arc::new(
            PinnedRuntimeStateDirectory::prepare(dir.path()).unwrap(),
        ));
        assert!(
            store.read().is_err(),
            "final marker symlink must be rejected"
        );

        std::fs::remove_file(dir.path().join(GR_RESTART_MARKER_FILE)).unwrap();
        std::fs::write(
            dir.path().join(GR_RESTART_MARKER_FILE),
            "version = 1\nexpires_at_unix = 1\n",
        )
        .unwrap();
        std::fs::set_permissions(
            dir.path().join(GR_RESTART_MARKER_FILE),
            std::fs::Permissions::from_mode(0o666),
        )
        .unwrap();
        assert!(
            store
                .read()
                .unwrap_err()
                .contains("unsafe type, owner, or mode")
        );

        let unsafe_dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(unsafe_dir.path(), std::fs::Permissions::from_mode(0o777))
            .unwrap();
        assert!(PinnedRuntimeStateDirectory::prepare(unsafe_dir.path()).is_err());
    }

    #[test]
    fn gr_restart_marker_remaining_time_clamps_backward_clock_step() {
        let marker_written_at = UNIX_EPOCH + Duration::from_hours(2);
        let expires_at = marker_written_at + Duration::from_mins(2);
        let clock_after_backward_step = marker_written_at - Duration::from_hours(1);

        assert_eq!(
            gr_restart_marker_remaining_time(expires_at, clock_after_backward_step, Some(120))
                .unwrap(),
            Duration::from_mins(2)
        );
    }

    #[test]
    fn gr_restart_marker_remaining_time_preserves_normal_and_expired_cases() {
        let now = UNIX_EPOCH + Duration::from_hours(2);

        assert_eq!(
            gr_restart_marker_remaining_time(now + Duration::from_secs(30), now, Some(120))
                .unwrap(),
            Duration::from_secs(30)
        );
        assert!(
            gr_restart_marker_remaining_time(
                now + Duration::from_mins(2),
                now + Duration::from_hours(1),
                Some(120),
            )
            .is_none()
        );
    }

    #[test]
    fn gr_restart_marker_remaining_time_rejects_missing_and_zero_maximum() {
        let now = UNIX_EPOCH + Duration::from_hours(2);
        let expires_at = now + Duration::from_mins(2);

        assert_eq!(
            gr_restart_marker_remaining_time(expires_at, now, None),
            None
        );
        assert_eq!(
            gr_restart_marker_remaining_time(expires_at, now, Some(0)),
            None
        );
    }

    #[test]
    fn v3_same_domain_uses_boottime_across_wall_clock_steps() {
        let wall_written = UNIX_EPOCH + Duration::from_hours(10);
        let marker = valid_test_v3(wall_written + Duration::from_mins(2), 130_000);

        for wall_now in [
            wall_written - Duration::from_hours(1),
            wall_written + Duration::from_hours(1),
        ] {
            let resolution = resolve_gr_restart_marker(
                &marker,
                wall_now,
                Ok(test_clock_sample(40_000)),
                Some(120),
            )
            .unwrap();
            assert_eq!(resolution.remaining, Duration::from_secs(90));
            assert_eq!(resolution.authority, GrRestartExpiryAuthority::Boottime);
            assert_eq!(resolution.fallback_reason, None);
        }
    }

    #[test]
    fn v1_and_v2_resolution_use_bounded_wall_fallback() {
        let (_dir, store) = marker_store();
        let wall_now = UNIX_EPOCH + Duration::from_hours(10);
        for generation in [None, Some("generation")] {
            write_test_legacy(&store, Duration::from_secs(30), generation, wall_now).unwrap();
            let marker = store.read().unwrap().unwrap();
            let resolution = resolve_gr_restart_marker(
                &marker,
                wall_now,
                Ok(test_clock_sample(100_000)),
                Some(20),
            )
            .unwrap();
            assert_eq!(resolution.remaining, Duration::from_secs(20));
            assert_eq!(resolution.authority, GrRestartExpiryAuthority::Wall);
            assert!(
                resolution
                    .fallback_reason
                    .unwrap()
                    .contains("legacy marker")
            );
        }
        store.remove().unwrap();
    }

    #[test]
    fn v3_boottime_resolution_handles_normal_equal_expired_and_clamped_deadlines() {
        let wall_now = UNIX_EPOCH + Duration::from_hours(10);
        let marker = valid_test_v3(wall_now + Duration::from_hours(1), 130_000);
        let resolution =
            resolve_gr_restart_marker(&marker, wall_now, Ok(test_clock_sample(100_000)), Some(120))
                .unwrap();
        assert_eq!(resolution.remaining, Duration::from_secs(30));

        for current_ms in [130_000, 130_001] {
            assert_eq!(
                resolve_gr_restart_marker(
                    &marker,
                    wall_now,
                    Ok(test_clock_sample(current_ms)),
                    Some(120),
                ),
                None
            );
        }

        let far = valid_test_v3(wall_now + Duration::from_hours(1), 1_000_000);
        assert_eq!(
            resolve_gr_restart_marker(&far, wall_now, Ok(test_clock_sample(100_000)), Some(120),)
                .unwrap()
                .remaining,
            Duration::from_mins(2)
        );
    }

    #[test]
    fn v3_domain_mismatches_and_sample_failure_use_bounded_wall_fallback() {
        let wall_now = UNIX_EPOCH + Duration::from_hours(10);
        let marker = valid_test_v3(wall_now + Duration::from_secs(30), 130_000);
        let mut mismatches = Vec::new();

        let mut sample = test_clock_sample(100_000);
        sample.boot_id = "87654321-4321-4abc-8def-ba0987654321".to_string();
        mismatches.push(sample);
        let mut sample = test_clock_sample(100_000);
        sample.time_namespace_dev += 1;
        mismatches.push(sample);
        let mut sample = test_clock_sample(100_000);
        sample.time_namespace_ino += 1;
        mismatches.push(sample);
        let mut sample = test_clock_sample(100_000);
        sample.boottime_offset_secs += 1;
        mismatches.push(sample);
        let mut sample = test_clock_sample(100_000);
        sample.boottime_offset_nanos += 1;
        mismatches.push(sample);

        for sample in mismatches {
            let resolution =
                resolve_gr_restart_marker(&marker, wall_now, Ok(sample), Some(20)).unwrap();
            assert_eq!(resolution.remaining, Duration::from_secs(20));
            assert_eq!(resolution.authority, GrRestartExpiryAuthority::Wall);
            assert!(resolution.fallback_reason.is_some());
        }

        let unavailable =
            resolve_gr_restart_marker(&marker, wall_now, Err("injected".to_string()), Some(20))
                .unwrap();
        assert_eq!(unavailable.remaining, Duration::from_secs(20));
        assert_eq!(unavailable.authority, GrRestartExpiryAuthority::Wall);
        assert!(unavailable.fallback_reason.unwrap().contains("unavailable"));
    }

    #[test]
    fn gr_restart_marker_remaining_time_rejects_or_clamps_valid_far_future_v2_marker() {
        let (_dir, store) = marker_store();
        let far_future_secs = i64::MAX.unsigned_abs();
        write_test_legacy(
            &store,
            Duration::from_secs(far_future_secs),
            Some("far-future-generation"),
            UNIX_EPOCH,
        )
        .unwrap();
        let marker = store.read().unwrap().unwrap();
        assert_eq!(
            marker.checkpoint_generation.as_deref(),
            Some("far-future-generation")
        );

        assert_eq!(
            gr_restart_marker_remaining_time(marker.expires_at, UNIX_EPOCH, None),
            None
        );
        assert_eq!(
            gr_restart_marker_remaining_time(marker.expires_at, UNIX_EPOCH, Some(120)).unwrap(),
            Duration::from_mins(2)
        );
        store.remove().unwrap();
    }

    #[test]
    fn authoritative_capture_restart_window_controls_marker_expiry() {
        let (_dir, store) = marker_store();
        // Represents a live runtime-config capture that advanced from a stale
        // startup value to 17 seconds. Production overwrites the fallback with
        // `capture.restart_time_secs` before publishing the restart marker.
        let captured_restart_time_secs = 17;
        let before = SystemTime::now();
        write_test_legacy(
            &store,
            Duration::from_secs(captured_restart_time_secs),
            Some("captured-generation"),
            before,
        )
        .unwrap();

        let marker = store.read().unwrap().unwrap();
        assert_eq!(
            marker.checkpoint_generation.as_deref(),
            Some("captured-generation")
        );
        let retention = marker.expires_at.duration_since(before).unwrap();
        assert!(retention >= Duration::from_secs(16));
        assert!(retention <= Duration::from_secs(17));
        store.remove().unwrap();
    }

    #[test]
    fn failed_or_timed_out_writer_selects_v1_without_generation_reference() {
        let (_dir, store) = marker_store();
        write_test_legacy(&store, Duration::from_mins(2), None, SystemTime::now()).unwrap();

        let marker = store.read().unwrap().unwrap();
        assert_eq!(marker.checkpoint_generation, None);
        store.remove().unwrap();
    }

    #[tokio::test]
    async fn oversized_checkpoint_publishes_no_bundle_or_v2_marker() {
        use std::os::unix::fs::PermissionsExt as _;

        let temp = tempfile::tempdir().unwrap();
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let pinned = Arc::new(PinnedRuntimeStateDirectory::prepare(temp.path()).unwrap());
        let directory = Arc::new(pinned.prepare_warm_bundle().unwrap());
        let marker_store = GrRestartMarkerStore::new(pinned);
        let session = checkpoint_plan_session();
        let capture = WarmCheckpointCapture {
            local_asn: 65_001,
            local_router_id: Ipv4Addr::new(192, 0, 2, 1),
            effective_config_toml: "[global]\nasn = 65001\n".to_string(),
            restart_time_secs: Some(120),
            sessions: vec![session.clone()],
        };
        let (rib_tx, mut rib_rx) = mpsc::channel(1);
        let responder = tokio::spawn(async move {
            let update = rib_rx.recv().await.expect("warm query sent");
            let RibUpdate::QueryWarmMrtSnapshot { budget, reply, .. } = update else {
                panic!("unexpected RIB query");
            };
            assert_eq!(budget.max_materialized_bytes, 32);
            reply
                .send(Ok(rustbgpd_rib::MrtSnapshotData {
                    peers: vec![rustbgpd_rib::MrtPeerEntry {
                        peer_addr: session.peer.address,
                        peer_bgp_id: session.peer_router_id,
                        peer_asn: session.peer_asn,
                    }],
                    routes: vec![],
                    evpn_routes: vec![],
                }))
                .expect("coordinator still waiting");
        });

        let result = publish_warm_checkpoint_bounded(
            capture,
            &rib_tx,
            Arc::clone(&directory),
            StdInstant::now() + Duration::from_mins(1),
            32,
        )
        .await;
        responder.await.unwrap();
        assert!(
            result
                .as_ref()
                .is_err_and(|error| error.contains("32-byte cap"))
        );
        assert_eq!(
            std::fs::read_dir(temp.path().join(WARM_BUNDLE_DIRECTORY))
                .unwrap()
                .count(),
            0,
            "oversized encoding must not publish an artifact, manifest, or temp file"
        );

        marker_store
            .write_selected(Duration::from_mins(2), result.ok().as_deref())
            .unwrap();
        let marker = marker_store.read().unwrap().unwrap();
        assert_eq!(
            marker.checkpoint_generation, None,
            "failed publication must retain a generationless marker"
        );
        marker_store.remove().unwrap();
    }

    fn checkpoint_plan_session() -> WarmCheckpointSession {
        WarmCheckpointSession {
            peer: rustbgpd_api::peer_types::PeerKey::new("10.0.0.2".parse().unwrap(), None),
            session_id: 41,
            peer_asn: 65002,
            peer_router_id: Ipv4Addr::new(192, 0, 2, 2),
            negotiated_families: vec![(Afi::Ipv4, Safi::Unicast)],
            peer_gr_families: vec![(Afi::Ipv4, Safi::Unicast), (Afi::Ipv6, Safi::Unicast)],
            add_path_receive_families: vec![(Afi::Ipv4, Safi::Unicast)],
            canonical_import_policy: b"canonical-policy-v1".to_vec(),
        }
    }

    #[test]
    fn warm_checkpoint_plan_intersects_gr_with_negotiated_family() {
        let plan = build_warm_checkpoint_plan(&[checkpoint_plan_session()]).unwrap();
        assert_eq!(plan.views.len(), 1);
        assert_eq!(plan.views[0].family, WarmBundleFamilyV1::Ipv4Unicast);
        assert!(plan.views[0].add_path_receive);
        assert_eq!(plan.rib_views[0].session_id, 41);
        assert_eq!(plan.policy_inputs[0].view, plan.views[0]);
        assert_eq!(
            plan.policy_inputs[0].canonical_policy,
            b"canonical-policy-v1"
        );
        assert_eq!(plan.add_path_receive.len(), 1);
    }

    #[test]
    fn no_eligible_checkpoint_plan_retains_v1_fallback() {
        let (_dir, store) = marker_store();
        let mut session = checkpoint_plan_session();
        session.peer_gr_families.clear();
        assert!(build_warm_checkpoint_plan(&[session]).is_err());

        store.write_selected(Duration::from_mins(2), None).unwrap();
        let marker = store.read().unwrap().unwrap();
        assert_eq!(marker.checkpoint_generation, None);
        store.remove().unwrap();
    }

    #[test]
    fn effective_config_digest_rejects_runtime_config_mismatch() {
        let before = effective_config_sha256("asn = 65001\n");
        let after = effective_config_sha256("asn = 65001\nhonor_blackhole = true\n");
        assert_eq!(before.len(), 64);
        assert_ne!(before, after);
    }

    #[test]
    fn tcp_ao_listener_key_includes_peer_matching_listener_family() {
        let config = load_config_from_toml("listener-tcp-ao-v4", &tcp_ao_neighbor_toml("10.0.0.2"));
        let peer = config.resolved_neighbors().unwrap().pop().unwrap();

        let key = tcp_ao_listener_key_for_neighbor(config.listen_addr(), &peer).unwrap();

        assert_eq!(key.peer.to_string(), "10.0.0.2");
    }

    #[test]
    fn tcp_ao_listener_key_skips_peer_outside_listener_family() {
        let config =
            load_config_from_toml("listener-tcp-ao-v6", &tcp_ao_neighbor_toml("2001:db8::2"));
        let peer = config.resolved_neighbors().unwrap().pop().unwrap();

        assert!(tcp_ao_listener_key_for_neighbor(config.listen_addr(), &peer).is_none());
    }

    #[test]
    fn tcp_ao_listener_key_preserves_dynamic_v4_and_v6_prefix_lengths() {
        let range = |prefix: &str| config::DynamicNeighborConfig {
            prefix: prefix.to_string(),
            peer_group: "dynamic".to_string(),
            remote_asn: 0,
            description: None,
            tcp_ao: Some(
                config::TcpAoConfig {
                    key: "secret".to_string(),
                    send_id: 7,
                    recv_id: 9,
                    algorithm: "hmac(sha256)".to_string(),
                    preferred: false,
                    deprecated: false,
                }
                .into(),
            ),
        };

        let v4 = tcp_ao_listener_key_for_dynamic_range(
            "0.0.0.0:179".parse().unwrap(),
            &range("192.0.2.0/24"),
        )
        .unwrap();
        let v6 = tcp_ao_listener_key_for_dynamic_range(
            "[::]:179".parse().unwrap(),
            &range("2001:db8::/48"),
        )
        .unwrap();
        assert_eq!(
            (v4.peer.to_string(), v4.prefix_len),
            ("192.0.2.0".to_string(), 24)
        );
        assert_eq!(
            (v6.peer.to_string(), v6.prefix_len),
            ("2001:db8::".to_string(), 48)
        );
    }

    #[test]
    #[expect(clippy::too_many_lines)]
    fn max_gr_restart_time_uses_largest_enabled_peer() {
        let config = crate::config::Config {
            global: crate::config::Global {
                asn: 65001,
                router_id: "10.0.0.1".to_string(),
                listen_port: 179,
                cluster_id: None,
                runtime_state_dir: "/tmp".to_string(),
                telemetry: crate::config::TelemetryConfig {
                    prometheus_addr: Some("127.0.0.1:9179".to_string()),
                    log_format: "json".to_string(),
                    grpc_tcp: None,
                    grpc_uds: None,
                },
                dynamic_neighbor_limit: None,
                worker_threads: None,
                honor_graceful_shutdown: false,
                honor_blackhole: false,
                multipath_relax: false,
                link_bandwidth_weighted: false,
                install_blackhole_discard: false,
                allow_blackhole_broad_prefixes: false,
                warm_cache_checkpoint_on_shutdown: false,
            },
            security: crate::config::SecurityConfig::default(),
            neighbors: vec![
                crate::config::Neighbor {
                    address: "10.0.0.2".to_string(),
                    interface: None,
                    remote_asn: 65002,
                    description: None,
                    peer_group: None,
                    hold_time: None,
                    send_hold_time: None,
                    max_prefixes: None,
                    md5_password: None,
                    tcp_ao: None,
                    bfd: None,
                    ttl_security: Some(false),
                    families: Vec::new(),
                    graceful_restart: Some(true),
                    gr_restart_time: Some(90),
                    gr_stale_routes_time: None,
                    llgr_stale_time: None,
                    local_ipv6_nexthop: None,
                    route_reflector_client: Some(false),
                    orr_vantage: None,
                    route_server_client: Some(false),
                    per_client_best: None,
                    role: None,
                    strict_role: None,
                    prefix_orf_receive: None,
                    disable_ipv4_unicast: None,
                    remove_private_as: None,
                    add_path: None,
                    import_policy: Vec::new(),
                    export_policy: Vec::new(),
                    import_policy_chain: Vec::new(),
                    export_policy_chain: Vec::new(),
                    log_level: None,
                },
                crate::config::Neighbor {
                    address: "10.0.0.3".to_string(),
                    interface: None,
                    remote_asn: 65003,
                    description: None,
                    peer_group: None,
                    hold_time: None,
                    send_hold_time: None,
                    max_prefixes: None,
                    md5_password: None,
                    tcp_ao: None,
                    bfd: None,
                    ttl_security: Some(false),
                    families: Vec::new(),
                    graceful_restart: Some(true),
                    gr_restart_time: Some(180),
                    gr_stale_routes_time: None,
                    llgr_stale_time: None,
                    local_ipv6_nexthop: None,
                    route_reflector_client: Some(false),
                    orr_vantage: None,
                    route_server_client: Some(false),
                    per_client_best: None,
                    role: None,
                    strict_role: None,
                    prefix_orf_receive: None,
                    disable_ipv4_unicast: None,
                    remove_private_as: None,
                    add_path: None,
                    import_policy: Vec::new(),
                    export_policy: Vec::new(),
                    import_policy_chain: Vec::new(),
                    export_policy_chain: Vec::new(),
                    log_level: None,
                },
                crate::config::Neighbor {
                    address: "10.0.0.4".to_string(),
                    interface: None,
                    remote_asn: 65004,
                    description: None,
                    peer_group: None,
                    hold_time: None,
                    send_hold_time: None,
                    max_prefixes: None,
                    md5_password: None,
                    tcp_ao: None,
                    bfd: None,
                    ttl_security: Some(false),
                    families: Vec::new(),
                    graceful_restart: Some(false),
                    gr_restart_time: Some(300),
                    gr_stale_routes_time: None,
                    llgr_stale_time: None,
                    local_ipv6_nexthop: None,
                    route_reflector_client: Some(false),
                    orr_vantage: None,
                    route_server_client: Some(false),
                    per_client_best: None,
                    role: None,
                    strict_role: None,
                    prefix_orf_receive: None,
                    disable_ipv4_unicast: None,
                    remove_private_as: None,
                    add_path: None,
                    import_policy: Vec::new(),
                    export_policy: Vec::new(),
                    import_policy_chain: Vec::new(),
                    export_policy_chain: Vec::new(),
                    log_level: None,
                },
            ],
            peer_groups: std::collections::HashMap::new(),
            policy: crate::config::PolicyConfig::default(),
            rpki: None,
            bmp: None,
            mrt: None,
            file_path: None,
            dynamic_neighbors: Vec::new(),
            evpn_instances: Vec::new(),
            ethernet_segments: Vec::new(),
            evpn_ip_vrfs: Vec::new(),
            managed_netdevs: crate::config::ManagedNetdevsConfig::default(),
            fib_tables: Vec::new(),
            bfd_profiles: Vec::new(),
            apply_bum_enforcement: false,
            event_history: crate::config::EventHistoryConfig::default(),
        };

        assert_eq!(max_gr_restart_time_secs(&config), Some(180));

        let mut unresolved = config.clone();
        unresolved.neighbors[0].address = "fe80::1".to_string();
        unresolved.neighbors[0].interface = Some("rbgp-definitely-missing0".to_string());
        assert!(unresolved.resolved_neighbors().is_err());
        assert_eq!(
            max_gr_restart_time_secs(&unresolved),
            Some(180),
            "resolution failure must retain the previous raw-config marker fallback"
        );
    }
}
