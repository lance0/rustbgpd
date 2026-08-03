//! gRPC server startup and wiring.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use futures::StreamExt as FuturesStreamExt;
use futures::{Future, Stream};
use tokio::net::{TcpListener, UnixListener};
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::JoinSet;
use tokio_rustls::TlsAcceptor;
use tokio_stream::wrappers::{TcpListenerStream, UnixListenerStream};
use tonic::service::Interceptor;
use tonic::transport::Server;
use tonic::{Request, Status};
use tracing::{error, info, warn};

use crate::authz::{
    AuthEnforcement, AuthTier, LOCAL_OPERATOR_PRINCIPAL, PrincipalRole, uds_mode_is_owner_only,
};
use crate::authz_runtime::{GrpcAuthAuditContext, GrpcAuthnKind, GrpcAuthzLayer};
use crate::bfd_service::BfdService;
use crate::config_service::ConfigService;
use crate::connect_info::RustbgpdTcpStream;
use crate::control_service::{ControlService, MrtTriggerTx};
use crate::credentials::CredentialStore;
use crate::credentials::PinnedCredentialGeneration;
use crate::event_service::{DataplaneEventBroadcaster, EventService, dataplane_event_broadcaster};
use crate::evpn_service::{
    BumEnforcementSnapshotFn, DuplicateMacClearFn, EthernetSegmentDrainReasonsFn,
    EvpnRuntimeApplyFn, EvpnRuntimeModelFn, EvpnService, InstanceStatusSnapshotFn,
    ManagedNetdevStatusSnapshotFn, OriginatedLocalMacCountFn, SameEsiBiasSnapshotFn,
};
use crate::global_service::GlobalService;
use crate::gnmi::g_nmi_server::GNmiServer;
use crate::gnmi_service::GnmiService;
use crate::injection_service::InjectionService;
use crate::neighbor_service::NeighborService;
use crate::peer_group_service::PeerGroupService;
use crate::peer_types::{
    CatalogMutationError, ConfigEvent, PeerManagerCommand, PeerManagerReadinessQuery,
};
use crate::policy_service::PolicyService;
use crate::proto::bfd_service_server::BfdServiceServer;
use crate::proto::config_service_server::ConfigServiceServer;
use crate::proto::control_service_server::ControlServiceServer;
use crate::proto::event_service_server::EventServiceServer;
use crate::proto::evpn_service_server::EvpnServiceServer;
use crate::proto::global_service_server::GlobalServiceServer;
use crate::proto::injection_service_server::InjectionServiceServer;
use crate::proto::neighbor_service_server::NeighborServiceServer;
use crate::proto::peer_group_service_server::PeerGroupServiceServer;
use crate::proto::policy_service_server::PolicyServiceServer;
use crate::proto::rib_service_server::RibServiceServer;
use crate::rib_service::RibService;
use rustbgpd_rib::{RibReadinessQuery, RibUpdate};
use rustbgpd_telemetry::BgpMetrics;

const MAX_CONCURRENT_GRPC_TLS_HANDSHAKES: usize = 64;
const GRPC_TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

fn bounded_handshakes<S, F, T, E>(incoming: S) -> impl Stream<Item = Result<T, E>>
where
    S: Stream<Item = F>,
    F: Future<Output = Option<Result<T, E>>>,
{
    FuturesStreamExt::filter_map(
        FuturesStreamExt::buffer_unordered(incoming, MAX_CONCURRENT_GRPC_TLS_HANDSHAKES),
        std::future::ready,
    )
}

/// Error returned by the daemon-owned config transaction apply hook.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConfigTransactionApplyError {
    /// Candidate or request validation failed.
    InvalidArgument(String),
    /// The request targets a stale runtime snapshot or an unavailable runtime
    /// precondition such as missing persisted config.
    FailedPrecondition(String),
    /// Required runtime actor or persistence channel is unavailable.
    Unavailable(String),
    /// Internal actor/rollback failure.
    Internal(String),
}

impl ConfigTransactionApplyError {
    pub(crate) fn into_status(self) -> Status {
        match self {
            Self::InvalidArgument(message) => Status::invalid_argument(message),
            Self::FailedPrecondition(message) => Status::failed_precondition(message),
            Self::Unavailable(message) => Status::unavailable(message),
            Self::Internal(message) => Status::internal(message),
        }
    }
}

impl std::fmt::Display for ConfigTransactionApplyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidArgument(message)
            | Self::FailedPrecondition(message)
            | Self::Unavailable(message)
            | Self::Internal(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for ConfigTransactionApplyError {}

pub(crate) fn catalog_mutation_error_to_status(error: &CatalogMutationError) -> Status {
    match error {
        CatalogMutationError::NotFound(_) => Status::not_found(error.to_string()),
        CatalogMutationError::StillReferenced { .. } => {
            Status::failed_precondition(error.to_string())
        }
        CatalogMutationError::Invalid(_) => Status::invalid_argument(error.to_string()),
        CatalogMutationError::RestartRequired(_) => Status::failed_precondition(error.to_string()),
        CatalogMutationError::Internal(_) => Status::internal(error.to_string()),
    }
}

/// Error returned by the daemon-owned gNMI Set bridge hook.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GnmiSetError {
    /// The Set request is malformed or carries an invalid value.
    InvalidArgument(String),
    /// The path or operation is valid gNMI/OpenConfig but outside rustbgpd's
    /// supported Set surface.
    Unimplemented(String),
    /// A runtime precondition, such as a pending confirmed transaction, failed.
    FailedPrecondition(String),
    /// Required runtime actor or persistence channel is unavailable.
    Unavailable(String),
    /// Internal actor/rollback failure.
    Internal(String),
}

impl GnmiSetError {
    pub(crate) fn into_status(self) -> Status {
        match self {
            Self::InvalidArgument(message) => Status::invalid_argument(message),
            Self::Unimplemented(message) => Status::unimplemented(message),
            Self::FailedPrecondition(message) => Status::failed_precondition(message),
            Self::Unavailable(message) => Status::unavailable(message),
            Self::Internal(message) => Status::internal(message),
        }
    }
}

impl std::fmt::Display for GnmiSetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidArgument(message)
            | Self::Unimplemented(message)
            | Self::FailedPrecondition(message)
            | Self::Unavailable(message)
            | Self::Internal(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for GnmiSetError {}

/// One normalized gNMI Set operation in the wire-mandated application order.
#[derive(Clone, PartialEq)]
pub enum GnmiSetOperation {
    /// Delete the subtree at this path.
    Delete(crate::gnmi::Path),
    /// Replace the path/value carried in this update.
    Replace(crate::gnmi::Update),
    /// Merge/update the path/value carried in this update.
    Update(crate::gnmi::Update),
}

/// Parsed gNMI commit-confirmed extension action.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GnmiSetCommitAction {
    /// Start a confirmed commit with the supplied ID and optional timeout.
    Commit {
        confirm_id: String,
        confirm_timeout_seconds: u32,
    },
    /// Confirm a pending confirmed commit.
    Confirm { confirm_id: String },
    /// Cancel and roll back a pending confirmed commit.
    Cancel { confirm_id: String },
    /// Reset the rollback timer for a pending confirmed commit.
    SetRollbackDuration {
        confirm_id: String,
        confirm_timeout_seconds: u32,
    },
}

/// A normalized gNMI Set request passed to the daemon-owned transaction bridge.
#[derive(Clone, PartialEq)]
pub struct GnmiSetTransaction {
    /// Common prefix from the original request.
    pub prefix: Option<crate::gnmi::Path>,
    /// Operations after prefix expansion and gNMI operation ordering.
    pub operations: Vec<GnmiSetOperation>,
    /// Optional parsed commit-confirmed extension action.
    pub commit_action: Option<GnmiSetCommitAction>,
}

/// Successful gNMI Set bridge result.
#[derive(Clone, Default, PartialEq)]
pub struct GnmiSetOutcome {
    /// Response extensions to attach to `SetResponse`.
    pub extensions: Vec<crate::gnmi_ext::Extension>,
}

/// Future returned by the daemon-owned gNMI Set bridge hook.
pub type GnmiSetFuture =
    Pin<Box<dyn std::future::Future<Output = Result<GnmiSetOutcome, GnmiSetError>> + Send>>;

/// Daemon-owned hook for `gnmi.gNMI/Set`.
///
/// The binary crate owns this because `OpenConfig` Set must translate into
/// complete candidate TOML and then use the ADR-0076 transaction controller.
pub type GnmiSetFn = Arc<dyn Fn(GnmiSetTransaction) -> GnmiSetFuture + Send + Sync + 'static>;

/// Future returned by the daemon-owned config transaction apply hook.
pub type ConfigTransactionApplyFuture = Pin<
    Box<
        dyn std::future::Future<
                Output = Result<
                    crate::proto::ConfigTransactionApplyResponse,
                    ConfigTransactionApplyError,
                >,
            > + Send,
    >,
>;

/// Daemon-owned hook for `ConfigService.ApplyConfigTransaction`.
///
/// The binary crate owns this because config transactions need runtime actor
/// senders, config persistence, and the shared SIGHUP/runtime-CRUD lock.
pub type ConfigTransactionApplyFn = Arc<
    dyn Fn(crate::proto::ApplyConfigTransactionRequest) -> ConfigTransactionApplyFuture
        + Send
        + Sync
        + 'static,
>;

/// Future returned by the daemon-owned config transaction confirm hook.
pub type ConfigTransactionConfirmFuture = Pin<
    Box<
        dyn std::future::Future<
                Output = Result<
                    crate::proto::ConfirmConfigTransactionResponse,
                    ConfigTransactionApplyError,
                >,
            > + Send,
    >,
>;

/// Daemon-owned hook for `ConfigService.ConfirmConfigTransaction`.
pub type ConfigTransactionConfirmFn = Arc<
    dyn Fn(crate::proto::ConfirmConfigTransactionRequest) -> ConfigTransactionConfirmFuture
        + Send
        + Sync
        + 'static,
>;

/// Future returned by the daemon-owned config transaction abort hook.
pub type ConfigTransactionAbortFuture = Pin<
    Box<
        dyn std::future::Future<
                Output = Result<
                    crate::proto::AbortConfigTransactionResponse,
                    ConfigTransactionApplyError,
                >,
            > + Send,
    >,
>;

/// Daemon-owned hook for `ConfigService.AbortConfigTransaction`.
pub type ConfigTransactionAbortFn = Arc<
    dyn Fn(crate::proto::AbortConfigTransactionRequest) -> ConfigTransactionAbortFuture
        + Send
        + Sync
        + 'static,
>;

/// Future returned by the daemon-owned config transaction status hook.
pub type ConfigTransactionStatusFuture = Pin<
    Box<
        dyn std::future::Future<
                Output = Result<
                    crate::proto::ConfigTransactionStatusResponse,
                    ConfigTransactionApplyError,
                >,
            > + Send,
    >,
>;

/// Daemon-owned hook for `ConfigService.GetConfigTransactionStatus`.
pub type ConfigTransactionStatusFn = Arc<
    dyn Fn(crate::proto::GetConfigTransactionStatusRequest) -> ConfigTransactionStatusFuture
        + Send
        + Sync
        + 'static,
>;

/// Future returned by the daemon-owned config history list hook.
pub type ConfigHistoryListFuture = Pin<
    Box<
        dyn std::future::Future<
                Output = Result<
                    crate::proto::ListConfigHistoryResponse,
                    ConfigTransactionApplyError,
                >,
            > + Send,
    >,
>;

/// Daemon-owned hook for `ConfigService.ListConfigHistory`.
///
/// The binary crate owns this because the applied-config history lives under
/// its `runtime_state_dir`.
pub type ConfigHistoryListFn = Arc<
    dyn Fn(crate::proto::ListConfigHistoryRequest) -> ConfigHistoryListFuture
        + Send
        + Sync
        + 'static,
>;

/// Future returned by the daemon-owned config rollback hook.
pub type ConfigRollbackFuture = Pin<
    Box<
        dyn std::future::Future<
                Output = Result<
                    crate::proto::ConfigTransactionApplyResponse,
                    ConfigTransactionApplyError,
                >,
            > + Send,
    >,
>;

/// Daemon-owned hook for `ConfigService.RollbackConfigTransaction`.
///
/// The binary crate owns this because rollback resolves the retained history
/// entry and routes it through the same transaction executor as
/// `ApplyConfigTransaction`.
pub type ConfigRollbackFn = Arc<
    dyn Fn(crate::proto::RollbackConfigTransactionRequest) -> ConfigRollbackFuture
        + Send
        + Sync
        + 'static,
>;

/// Future returned by a daemon-owned runtime config mutation gate.
pub type ConfigMutationGateFuture =
    Pin<Box<dyn std::future::Future<Output = Result<(), String>> + Send>>;

/// Hook used by persisted runtime-config mutators to fail closed while a
/// confirmed config transaction is applying or awaiting confirmation.
pub type ConfigMutationGateFn =
    Arc<dyn Fn(&'static str) -> ConfigMutationGateFuture + Send + Sync + 'static>;

/// Check an optional runtime-config mutation gate and map its failure to gRPC.
///
/// # Errors
///
/// Returns `FAILED_PRECONDITION` when the daemon-owned gate rejects `operation`,
/// for example while a confirmed config transaction is applying or pending.
pub async fn check_config_mutation_gate(
    gate: &Option<ConfigMutationGateFn>,
    operation: &'static str,
) -> Result<(), Status> {
    if let Some(gate) = gate {
        gate(operation).await.map_err(Status::failed_precondition)?;
    }
    Ok(())
}

/// A durable config write that is written and fsynced but not yet published.
///
/// Holding one means the persistence failure modes an operator actually hits
/// — an unwritable config directory, a read-only mount, a full filesystem —
/// have already been ruled out. Committing it is a rename; dropping it
/// discards the write with no trace.
#[must_use = "a staged config write must be committed or explicitly dropped"]
pub(crate) struct StagedConfigWrite {
    commit_tx: tokio::sync::oneshot::Sender<tokio::sync::oneshot::Sender<Result<(), String>>>,
}

impl StagedConfigWrite {
    /// Publish the staged write. Call only once the runtime change landed.
    ///
    /// # Errors
    ///
    /// Returns `INTERNAL` if publishing fails after the runtime change was
    /// already applied: runtime and disk have drifted and only SIGHUP or a
    /// restart reconciles them.
    pub(crate) async fn commit(self) -> Result<(), Status> {
        let (ack_tx, ack_rx) = tokio::sync::oneshot::channel();
        self.commit_tx
            .send(ack_tx)
            .map_err(|_| Status::internal(COMMIT_LOST))?;
        ack_rx
            .await
            .map_err(|_| Status::internal(COMMIT_LOST))?
            .map_err(|error| {
                Status::internal(format!(
                    "config persistence commit failed after the runtime change was applied \
                     (runtime and persisted config have drifted — SIGHUP or restart to \
                     reconcile): {error}"
                ))
            })
    }
}

const COMMIT_LOST: &str = "config bridge dropped the staged config write after the runtime change \
                           was applied (runtime and persisted config have drifted — SIGHUP or \
                           restart to reconcile)";

/// Reserve the on-disk write for a runtime-config event *before* the caller
/// mutates anything.
///
/// Shared by every persisted runtime CRUD path (neighbors, dynamic ranges,
/// policy/peer-group catalogs). The config bridge folds the event onto the
/// config snapshot, serializes it, and durably stages the result next to the
/// config file; this returns once that succeeded. Nothing is observable on
/// disk or on the wire yet.
///
/// That ordering is the contract: `FAILED_PRECONDITION` from a mutating RPC
/// means the request did nothing. Applying first and compensating afterwards
/// cannot honour it — re-adding a deleted neighbor produces a *new* session
/// with a new identity, a zeroed uptime, zeroed counters, and a fresh metric
/// series, and the teardown never even appears in the operator's flap count.
///
/// The caller holds the shared runtime-config lock across the whole
/// stage/apply/commit window, so a SIGHUP reload cannot read a stale TOML in
/// the middle of it.
///
/// # Errors
///
/// Returns `FAILED_PRECONDITION` when the candidate cannot be written. The
/// caller has not mutated anything at that point, and must not.
pub(crate) async fn stage_runtime_config_event(
    permit: tokio::sync::mpsc::OwnedPermit<crate::peer_types::ConfigEvent>,
    build_event: impl FnOnce(crate::peer_types::ConfigPersistAck) -> crate::peer_types::ConfigEvent,
) -> Result<StagedConfigWrite, Status> {
    let (staged_tx, staged_rx) = tokio::sync::oneshot::channel();
    let (commit_tx, commit_rx) = tokio::sync::oneshot::channel();
    permit.send(build_event(crate::peer_types::ConfigPersistAck {
        staged: staged_tx,
        commit: Some(commit_rx),
    }));
    staged_rx
        .await
        .map_err(|_| Status::internal("config bridge dropped persistence acknowledgement"))?
        .map_err(|error| match error {
            crate::peer_types::ConfigPersistError::Rejected(error) => {
                catalog_mutation_error_to_status(&error)
            }
            crate::peer_types::ConfigPersistError::Write(message) => {
                Status::failed_precondition(format!("config persistence failed: {message}"))
            }
        })?;
    Ok(StagedConfigWrite { commit_tx })
}

/// Stage a runtime-config event, run `apply`, then publish the write.
///
/// A staging failure returns before `apply` runs at all; an `apply` failure
/// drops the stage, so the config file is never written. `persist_permit` is
/// `None` when the daemon has no config file to persist to, in which case
/// only `apply` runs.
pub(crate) async fn persist_then_apply<F, Fut>(
    persist_permit: Option<tokio::sync::mpsc::OwnedPermit<crate::peer_types::ConfigEvent>>,
    build_event: impl FnOnce(crate::peer_types::ConfigPersistAck) -> crate::peer_types::ConfigEvent,
    apply: F,
) -> Result<(), Status>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = Result<(), Status>>,
{
    let Some(permit) = persist_permit else {
        return apply().await;
    };
    let staged = stage_runtime_config_event(permit, build_event).await?;
    // `staged` drops here on an apply failure, discarding the write.
    apply().await?;
    staged.commit().await
}

/// Run a persisted catalog mutation on a detached task: take the shared
/// runtime-config lock, check the config-transaction mutation gate
/// inside it, then run `body` (read prior state, apply, persist with
/// acknowledgement, roll back on persist failure).
///
/// The detached task is the ADR-0080 cancellation shield — a client
/// that disconnects mid-RPC loses only the response, never the
/// runtime-vs-disk consistency of the mutation. Holding the lock across
/// the body serializes catalog mutations with SIGHUP reload, FIB-table
/// and neighbor CRUD, and config transactions; it also makes the
/// read-prior-then-apply sequence inside `body` race-free, because
/// every catalog writer takes this same lock.
///
/// # Errors
///
/// Returns the gate's `FAILED_PRECONDITION`, the body's error, or
/// `INTERNAL` if the detached task is lost.
pub(crate) async fn run_shielded_catalog_mutation<F, Fut>(
    runtime_config_lock: Arc<tokio::sync::Mutex<()>>,
    config_mutation_gate: Option<ConfigMutationGateFn>,
    operation: &'static str,
    body: F,
) -> Result<(), Status>
where
    F: FnOnce() -> Fut + Send + 'static,
    Fut: std::future::Future<Output = Result<(), Status>> + Send,
{
    let join = tokio::spawn(async move {
        let _guard = runtime_config_lock.lock().await;
        check_config_mutation_gate(&config_mutation_gate, operation).await?;
        body().await
    });
    join.await
        .map_err(|_| Status::internal(format!("{operation} task did not complete")))?
}

/// Send a peer-manager command built around a oneshot reply channel and
/// await the reply.
pub(crate) async fn peer_manager_request<R>(
    peer_mgr_tx: &mpsc::Sender<PeerManagerCommand>,
    build_command: impl FnOnce(oneshot::Sender<R>) -> PeerManagerCommand,
) -> Result<R, Status> {
    let (reply_tx, reply_rx) = oneshot::channel();
    peer_mgr_tx
        .send(build_command(reply_tx))
        .await
        .map_err(|_| Status::internal("peer manager unavailable"))?;
    reply_rx
        .await
        .map_err(|_| Status::internal("peer manager dropped reply"))
}

/// Send a catalog mutation command to the peer manager and map its
/// typed failure onto the gRPC status surface.
pub(crate) async fn apply_catalog_mutation(
    peer_mgr_tx: &mpsc::Sender<PeerManagerCommand>,
    build_command: impl FnOnce(oneshot::Sender<Result<(), CatalogMutationError>>) -> PeerManagerCommand,
) -> Result<(), Status> {
    peer_manager_request(peer_mgr_tx, build_command)
        .await?
        .map_err(|error| catalog_mutation_error_to_status(&error))
}

/// Configuration for the gRPC server beyond basic connectivity.
#[derive(Clone)]
pub struct ServeConfig {
    /// Local autonomous system number.
    pub asn: u32,
    /// Local BGP router ID (dotted-quad string).
    pub router_id: String,
    /// BGP listen port (typically 179).
    pub listen_port: u32,
    /// Shared metrics registry for Prometheus exposition.
    pub metrics: BgpMetrics,
    /// Daemon start time for uptime calculation.
    pub start_time: tokio::time::Instant,
    /// Dedicated read-only peer-manager lane used only by core readiness.
    pub peer_mgr_readiness_tx: mpsc::Sender<PeerManagerReadinessQuery>,
    /// Dedicated type-narrow RIB lane used only by core readiness.
    pub rib_readiness_tx: mpsc::Sender<RibReadinessQuery>,
    /// Optional MRT dump trigger channel (None if MRT not configured).
    pub mrt_trigger_tx: Option<MrtTriggerTx>,
    /// Live count provider for locally-originated Type 2 MAC routes
    /// accepted by the RIB, keyed by VNI.
    pub evpn_originated_local_mac_count: OriginatedLocalMacCountFn,
    /// Live snapshot reader for the most recent
    /// `DataplaneReport.instance_status` rows. Returns an empty Vec
    /// before the reconcile actor's first pass or when the dataplane
    /// actor is absent.
    pub evpn_instance_status_snapshot: InstanceStatusSnapshotFn,
    /// Live snapshot reader for the most recent ADR-0091
    /// managed-netdev status rows.
    pub evpn_managed_netdev_status_snapshot: ManagedNetdevStatusSnapshotFn,
    /// Live snapshot reader for the most recent
    /// `DataplaneReport.ip_vrf_status` rows. Returns an empty Vec
    /// when no IP-VRFs are configured or before the reconcile
    /// actor's first pass.
    pub evpn_ip_vrf_status_snapshot: crate::evpn_service::IpVrfStatusSnapshotFn,
    /// Live count provider for locally-originated Type 5 routes per
    /// IP-VRF (Gate 9 slice 6b). Returns 0 when the originator is
    /// not running (RR-only deployments without `[[evpn_ip_vrfs]]`).
    pub evpn_originated_ip_vrf_route_count: crate::evpn_service::OriginatedIpVrfRouteCountFn,
    /// Live count provider for installed remote Type 5 routes per
    /// IP-VRF (Gate 9 slice 6c). Returns 0 when no `[[evpn_ip_vrfs]]`
    /// are configured.
    pub evpn_installed_ip_vrf_route_count: crate::evpn_service::InstalledIpVrfRouteCountFn,
    /// Live snapshot reader for current remote Type 5 projection-drop
    /// counts by bounded `(vrf, reason)` labels.
    pub evpn_remote_ip_prefix_drop_counts: crate::evpn_service::RemoteIpPrefixDropCountSnapshotFn,
    /// Live snapshot reader for ADR-0059 FDB nexthop-group owned
    /// state. Returns an empty summary when the dataplane actor is
    /// not running.
    pub evpn_fdb_nexthop_snapshot: crate::evpn_service::FdbNexthopSnapshotFn,
    /// Live snapshot reader for current EVPN BUM/AC-gate enforcement
    /// intent. Returns an empty table when the segment actor has not
    /// published yet or is absent.
    pub evpn_bum_enforcement_snapshot: BumEnforcementSnapshotFn,
    /// Live snapshot reader for ADR-0085 same-ESI local-bias
    /// eligibility.
    pub evpn_same_esi_bias_snapshot: SameEsiBiasSnapshotFn,
    /// Live read of composed Ethernet Segment drain reasons.
    pub evpn_es_drain_reasons: EthernetSegmentDrainReasonsFn,
    /// Live model reader for the committed ADR-0063 EVPN runtime
    /// generation. Generation 1 is the startup snapshot; later
    /// coordinator slices publish newer committed models here.
    pub evpn_runtime_model: EvpnRuntimeModelFn,
    /// Optional EVPN runtime apply hook. Present only on the daemon
    /// path that owns the ADR-0063 coordinator.
    pub evpn_runtime_apply: Option<EvpnRuntimeApplyFn>,
    /// Optional duplicate-MAC quarantine manual-clear hook. Present
    /// only when the EVPN originator actor is running.
    pub evpn_duplicate_mac_clear: Option<DuplicateMacClearFn>,
    /// Optional ADR-0084 Ethernet Segment drain hook. Present only
    /// when the EVPN segment actor is running.
    pub evpn_es_drain: Option<crate::evpn_service::EthernetSegmentDrainFn>,
    /// Live snapshot reader for RFC 7999 BLACKHOLE kernel discard
    /// install state. Returns an empty list when the discard actor is
    /// disabled or has not observed any BLACKHOLE best routes.
    pub blackhole_discard_snapshot: crate::rib_service::BlackholeDiscardSnapshotFn,
    /// Live snapshot reader for ADR-0061 general unicast FIB route
    /// install state. Returns an empty list when no `[[fib_tables]]`
    /// are configured or before the actor's first reconcile pass.
    pub fib_route_snapshot: crate::rib_service::FibRouteSnapshotFn,
    /// Daemon hook for runtime `[[fib_tables]]` CRUD (gRPC `SetFibTable` /
    /// `DeleteFibTable` / `ListFibTables`). `None` disables the mutating RPCs
    /// (they return `FAILED_PRECONDITION`). Wired in `main.rs` where the
    /// FIB actor sender, validator, and config persistence are visible.
    pub fib_table_control: Option<crate::rib_service::FibTableControlFn>,
    /// Daemon hook for gNMI Set. `None` keeps gNMI Set closed with
    /// `UNIMPLEMENTED`.
    pub gnmi_set: Option<GnmiSetFn>,
    /// Daemon hook for config transaction apply. `None` fails closed with
    /// `FAILED_PRECONDITION`.
    pub config_transaction_apply: Option<ConfigTransactionApplyFn>,
    /// Daemon hook for confirmed config transaction confirmation.
    pub config_transaction_confirm: Option<ConfigTransactionConfirmFn>,
    /// Daemon hook for confirmed config transaction abort/rollback.
    pub config_transaction_abort: Option<ConfigTransactionAbortFn>,
    /// Daemon hook for confirmed config transaction status.
    pub config_transaction_status: Option<ConfigTransactionStatusFn>,
    /// Daemon hook for listing the applied-config history. `None` fails
    /// closed with `FAILED_PRECONDITION`.
    pub config_history_list: Option<ConfigHistoryListFn>,
    /// Daemon hook for rolling back to a retained applied config through the
    /// transaction executor. `None` fails closed with `FAILED_PRECONDITION`.
    pub config_rollback: Option<ConfigRollbackFn>,
    /// Daemon hook used to reject persisted runtime-config mutations while a
    /// confirmed transaction is pending.
    pub config_mutation_gate: Option<ConfigMutationGateFn>,
    /// Shared serialization lock for persisted runtime config mutations and
    /// SIGHUP reload. The daemon wires this to dynamic-neighbor CRUD and
    /// FIB-table CRUD so accepted runtime mutations cannot be clobbered by a
    /// reload that read stale TOML before the persistence acknowledgement.
    pub runtime_config_lock: Arc<tokio::sync::Mutex<()>>,
    /// Live ADR-0061 per-route FIB dataplane event source. This is
    /// separate from the aggregate dataplane poller so route events
    /// are not delayed by snapshot polling.
    pub dataplane_route_events: Option<tokio::sync::broadcast::Sender<crate::proto::BgpEvent>>,
    /// Live snapshot reader for ADR-0067 single-hop BFD session state.
    /// Returns an empty list when no BFD sessions are configured or off Linux.
    pub bfd_session_snapshot: crate::bfd_service::BfdSessionSnapshotFn,
    /// Live ADR-0067 BFD session-event source (state transitions) for the
    /// unified `WatchEvents` stream. `None` disables the BFD event stream.
    pub bfd_events: Option<tokio::sync::broadcast::Sender<crate::proto::BgpEvent>>,
    /// Cloneable handle to the durable event outbox (ADR-0072). When
    /// `Some`, `EventService::subscribe_from_event` returns a real
    /// cursor stream. When `None`, the new RPC returns
    /// `Status::failed_precondition` — the legacy live surfaces are
    /// not affected.
    pub event_history: Option<rustbgpd_event_history::EventHistoryHandle>,
}

/// Resolved gRPC listener configuration.
#[derive(Clone, Debug)]
pub struct ListenerConfig {
    pub endpoint: ListenerEndpoint,
    pub access_mode: AccessMode,
    /// Effective ADR-0064 listener method-tier ceiling.
    pub max_tier: AuthTier,
    /// ADR-0064 principal-role enforcement mode.
    pub enforcement: AuthEnforcement,
    /// Global principal-to-role map used when `enforcement = tier`.
    pub roles: Arc<BTreeMap<String, PrincipalRole>>,
    pub credential_store: CredentialStore,
    pub credential_index: usize,
    /// Optional stable principal label for audit records. Bearer-token
    /// and UDS listeners may use it to avoid placeholder identities in
    /// `grpc_authz` logs; mTLS listeners derive their audit principal
    /// from the peer certificate instead.
    pub principal: Option<String>,
}

impl ListenerConfig {
    #[must_use]
    pub fn auth_enabled(&self) -> bool {
        self.credential_store
            .load()
            .listener(self.credential_index)
            .bearer
            .is_some()
    }

    #[must_use]
    pub fn credential_store(&self) -> CredentialStore {
        self.credential_store.clone()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AccessMode {
    ReadOnly,
    ReadWrite,
}

impl AccessMode {
    const fn as_str(self) -> &'static str {
        match self {
            Self::ReadOnly => "read_only",
            Self::ReadWrite => "read_write",
        }
    }
}

/// Listener transport.
#[derive(Clone, Debug)]
pub enum ListenerEndpoint {
    Tcp(SocketAddr),
    Uds { path: PathBuf, mode: u32 },
}

#[derive(Clone)]
struct RuntimeAuthzConfig {
    enforcement: AuthEnforcement,
    roles: Arc<BTreeMap<String, PrincipalRole>>,
}

fn tcp_audit_context(
    addr: SocketAddr,
    access_mode: AccessMode,
    max_tier: AuthTier,
    role_config: RuntimeAuthzConfig,
    bearer_enabled: bool,
    tls_enabled: bool,
    configured_principal: Option<&str>,
) -> GrpcAuthAuditContext {
    // `bearer_enabled` reflects the resolved credential generation —
    // static token *or* the dynamic credential store. TCP listeners are
    // always fed by the dynamic store (`.with_dynamic_bearer` below), so
    // the audit label must key off this flag, not a static token.
    let (authn, principal) = if tls_enabled {
        (GrpcAuthnKind::Mtls, "mtls-unresolved".to_string())
    } else if bearer_enabled {
        (
            GrpcAuthnKind::BearerToken,
            configured_principal.unwrap_or("bearer-token").to_string(),
        )
    } else {
        (GrpcAuthnKind::None, "unauthenticated".to_string())
    };
    let context = GrpcAuthAuditContext::new(
        format!("tcp://{addr}"),
        access_mode.as_str(),
        max_tier,
        authn,
        principal,
    )
    .with_role_enforcement(role_config.enforcement, role_config.roles);
    if tls_enabled {
        context.with_mtls_peer_principal()
    } else {
        context
    }
}

fn uds_audit_context(
    path: &Path,
    mode: u32,
    access_mode: AccessMode,
    max_tier: AuthTier,
    role_config: RuntimeAuthzConfig,
    auth_token: Option<&str>,
    configured_principal: Option<&str>,
) -> GrpcAuthAuditContext {
    let auth_enabled = auth_token.is_some();
    let (authn, principal, implicit_operator) = if let Some(principal) = configured_principal {
        (
            if auth_enabled {
                GrpcAuthnKind::BearerToken
            } else {
                GrpcAuthnKind::Uds
            },
            principal.to_string(),
            false,
        )
    } else if uds_mode_is_owner_only(mode) {
        // ADR-0064 amendment: the owner-only socket mode is the
        // authentication, so clients are authorized as the implicit
        // `local-operator` operator identity without a roles entry.
        (
            GrpcAuthnKind::UdsOwner,
            LOCAL_OPERATOR_PRINCIPAL.to_string(),
            true,
        )
    } else if auth_enabled {
        (
            GrpcAuthnKind::BearerToken,
            "bearer-token".to_string(),
            false,
        )
    } else {
        (GrpcAuthnKind::Uds, format!("uds:{}", path.display()), false)
    };
    let context = GrpcAuthAuditContext::new(
        format!("unix://{}", path.display()),
        access_mode.as_str(),
        max_tier,
        authn,
        principal,
    )
    .with_role_enforcement(role_config.enforcement, role_config.roles)
    .with_bearer_token(auth_token);
    if implicit_operator {
        context.with_implicit_local_operator()
    } else {
        context
    }
}

#[derive(Clone, Debug)]
struct AuthInterceptor {
    credential_store: Option<CredentialStore>,
    credential_index: usize,
    static_bearer: Option<crate::authz_runtime::BearerAuthSecret>,
}

impl AuthInterceptor {
    fn new(credential_store: CredentialStore, credential_index: usize) -> Self {
        Self {
            credential_store: Some(credential_store),
            credential_index,
            static_bearer: None,
        }
    }

    #[cfg(test)]
    fn from_token(token: Option<&str>) -> Self {
        Self {
            credential_store: None,
            credential_index: 0,
            static_bearer: token.map(crate::authz_runtime::BearerAuthSecret::from_token),
        }
    }
}

pub(crate) fn read_only_rejection(access_mode: AccessMode) -> Option<Status> {
    if access_mode == AccessMode::ReadOnly {
        Some(Status::permission_denied(
            "listener is read-only; mutating RPCs are not permitted",
        ))
    } else {
        None
    }
}

impl Interceptor for AuthInterceptor {
    fn call(&mut self, request: Request<()>) -> Result<Request<()>, Status> {
        if let Some(store) = &self.credential_store {
            let pinned = request
                .extensions()
                .get::<PinnedCredentialGeneration>()
                .cloned();
            let generation = pinned.is_none().then(|| store.load());
            let bearer_auth = pinned
                .as_ref()
                .and_then(PinnedCredentialGeneration::bearer)
                .or_else(|| {
                    generation.as_ref().and_then(|generation| {
                        generation.listener(self.credential_index).bearer.as_ref()
                    })
                });
            if let Some(bearer_auth) = bearer_auth {
                bearer_auth.authenticate_metadata(request.metadata())?;
            }
        } else if let Some(bearer_auth) = &self.static_bearer {
            bearer_auth.authenticate_metadata(request.metadata())?;
        }
        Ok(request)
    }
}

/// Start all configured gRPC listeners. Runs until the shutdown signal fires
/// or a listener exits unexpectedly.
///
/// # Panics
///
/// Panics if the dataplane event broadcaster mutex is poisoned —
/// a `Mutex` is poisoned when a thread panics while holding the
/// guard, not on `.await`. The dataplane code paths that lock
/// this mutex do trivial assignments and don't call any code
/// that could panic mid-guard, so poisoning is not expected in
/// practice; expressing the failure as a panic rather than a
/// fallback matches the broader daemon convention for "should
/// be unreachable" lock acquisitions on startup paths.
#[expect(clippy::too_many_arguments, reason = "startup wiring for gRPC server")]
pub async fn serve(
    listeners: Vec<ListenerConfig>,
    rib_tx: mpsc::Sender<RibUpdate>,
    rib_query_tx: mpsc::Sender<RibUpdate>,
    peer_mgr_tx: mpsc::Sender<PeerManagerCommand>,
    config: ServeConfig,
    shutdown_rx: oneshot::Receiver<()>,
    rpc_shutdown_tx: watch::Sender<bool>,
    config_tx: Option<mpsc::Sender<ConfigEvent>>,
) {
    let (listener_shutdown_tx, listener_shutdown_rx) = watch::channel(false);
    let mut listener_tasks = JoinSet::new();
    let dataplane_events = dataplane_event_broadcaster();

    // ADR-0072 PR-FU1: when the durable outbox is enabled, eagerly
    // spawn the dataplane poller so SubscribeFromEvent collectors
    // see dataplane summaries from the first tick — independent of
    // whether any WatchEvents subscriber ever attaches. Without
    // this, a collector that goes straight to the cursor stream
    // would see an empty dataplane category.
    if let Some(handle) = config.event_history.as_ref() {
        let (tx, _) = tokio::sync::broadcast::channel(16);
        {
            let mut guard = dataplane_events
                .lock()
                .expect("dataplane event broadcaster mutex poisoned");
            *guard = Some(tx.clone());
        }
        crate::event_service::dataplane::spawn_dataplane_poller(
            tx,
            dataplane_events.clone(),
            config.blackhole_discard_snapshot.clone(),
            config.fib_route_snapshot.clone(),
            Some(handle.clone()),
            config.metrics.clone(),
        );
    }

    for listener in listeners {
        let rib_tx = rib_tx.clone();
        let rib_query_tx = rib_query_tx.clone();
        let peer_mgr_tx = peer_mgr_tx.clone();
        let config = config.clone();
        let dataplane_events = dataplane_events.clone();
        let rpc_shutdown_tx = rpc_shutdown_tx.clone();
        let config_tx = config_tx.clone();
        let shutdown_rx = listener_shutdown_rx.clone();
        listener_tasks.spawn(async move {
            Box::pin(run_listener(
                listener,
                rib_tx,
                rib_query_tx,
                peer_mgr_tx,
                config,
                dataplane_events,
                shutdown_rx,
                rpc_shutdown_tx,
                config_tx,
            ))
            .await
        });
    }

    tokio::select! {
        () = async {
            let _ = shutdown_rx.await;
        } => {
            let _ = listener_shutdown_tx.send(true);
        }
        result = listener_tasks.join_next() => {
            match result {
                Some(Ok(Err(err))) => error!(error = %err, "gRPC listener exited unexpectedly"),
                Some(Err(err)) => error!(error = %err, "gRPC listener task panicked"),
                Some(Ok(Ok(()))) | None => error!("gRPC listener exited unexpectedly"),
            }
            let _ = listener_shutdown_tx.send(true);
        }
    }

    while let Some(result) = listener_tasks.join_next().await {
        match result {
            Ok(Ok(())) => {}
            Ok(Err(err)) => error!(error = %err, "gRPC listener exit during shutdown"),
            Err(err) => error!(error = %err, "gRPC listener task panicked during shutdown"),
        }
    }
}

#[expect(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "startup wiring for one listener"
)]
async fn run_listener(
    listener: ListenerConfig,
    rib_tx: mpsc::Sender<RibUpdate>,
    rib_query_tx: mpsc::Sender<RibUpdate>,
    peer_mgr_tx: mpsc::Sender<PeerManagerCommand>,
    config: ServeConfig,
    dataplane_events: DataplaneEventBroadcaster,
    shutdown_rx: watch::Receiver<bool>,
    rpc_shutdown_tx: watch::Sender<bool>,
    config_tx: Option<mpsc::Sender<ConfigEvent>>,
) -> Result<(), String> {
    let asn = config.asn;
    let router_id = config.router_id;
    let listen_port = config.listen_port;
    let metrics = config.metrics;
    let start_time = config.start_time;
    let peer_mgr_readiness_tx = config.peer_mgr_readiness_tx;
    let rib_readiness_tx = config.rib_readiness_tx;
    let mrt_trigger_tx = config.mrt_trigger_tx;
    let evpn_originated_local_mac_count = config.evpn_originated_local_mac_count;
    let evpn_instance_status_snapshot = config.evpn_instance_status_snapshot;
    let evpn_managed_netdev_status_snapshot = config.evpn_managed_netdev_status_snapshot;
    let evpn_ip_vrf_status_snapshot = config.evpn_ip_vrf_status_snapshot;
    let evpn_originated_ip_vrf_route_count = config.evpn_originated_ip_vrf_route_count;
    let evpn_installed_ip_vrf_route_count = config.evpn_installed_ip_vrf_route_count;
    let evpn_remote_ip_prefix_drop_counts = config.evpn_remote_ip_prefix_drop_counts;
    let evpn_fdb_nexthop_snapshot = config.evpn_fdb_nexthop_snapshot;
    let evpn_bum_enforcement_snapshot = config.evpn_bum_enforcement_snapshot;
    let evpn_same_esi_bias_snapshot = config.evpn_same_esi_bias_snapshot;
    let evpn_es_drain_reasons = config.evpn_es_drain_reasons;
    let evpn_runtime_model = config.evpn_runtime_model;
    let evpn_runtime_apply = config.evpn_runtime_apply;
    let evpn_duplicate_mac_clear = config.evpn_duplicate_mac_clear;
    let evpn_es_drain = config.evpn_es_drain;
    let blackhole_discard_snapshot = config.blackhole_discard_snapshot;
    let fib_route_snapshot = config.fib_route_snapshot;
    let fib_table_control = config.fib_table_control;
    let gnmi_set = config.gnmi_set;
    let config_transaction_apply = config.config_transaction_apply;
    let config_transaction_confirm = config.config_transaction_confirm;
    let config_transaction_abort = config.config_transaction_abort;
    let config_transaction_status = config.config_transaction_status;
    let config_history_list = config.config_history_list;
    let config_rollback = config.config_rollback;
    let config_mutation_gate = config.config_mutation_gate;
    let runtime_config_lock = config.runtime_config_lock;
    let dataplane_route_events = config.dataplane_route_events;
    let bfd_session_snapshot = config.bfd_session_snapshot;
    let bfd_events = config.bfd_events;
    let event_history = config.event_history;
    let ListenerConfig {
        endpoint,
        access_mode,
        max_tier,
        enforcement,
        roles,
        credential_store,
        credential_index,
        principal,
    } = listener;

    match endpoint {
        ListenerEndpoint::Tcp(addr) => {
            Box::pin(run_tcp_listener(
                addr,
                access_mode,
                max_tier,
                enforcement,
                roles,
                credential_store,
                credential_index,
                principal,
                rib_tx,
                rib_query_tx,
                rib_readiness_tx,
                peer_mgr_tx,
                peer_mgr_readiness_tx,
                asn,
                router_id,
                listen_port,
                metrics,
                start_time,
                mrt_trigger_tx,
                evpn_originated_local_mac_count,
                evpn_instance_status_snapshot,
                evpn_managed_netdev_status_snapshot,
                evpn_ip_vrf_status_snapshot,
                evpn_originated_ip_vrf_route_count,
                evpn_installed_ip_vrf_route_count,
                evpn_remote_ip_prefix_drop_counts,
                evpn_fdb_nexthop_snapshot,
                evpn_bum_enforcement_snapshot,
                evpn_same_esi_bias_snapshot,
                evpn_es_drain_reasons,
                evpn_runtime_model,
                evpn_runtime_apply,
                evpn_duplicate_mac_clear,
                evpn_es_drain.clone(),
                blackhole_discard_snapshot,
                fib_route_snapshot,
                fib_table_control,
                gnmi_set,
                config_transaction_apply,
                config_transaction_confirm,
                config_transaction_abort,
                config_transaction_status,
                config_history_list,
                config_rollback,
                config_mutation_gate,
                runtime_config_lock,
                dataplane_route_events,
                bfd_session_snapshot,
                bfd_events,
                dataplane_events,
                event_history.clone(),
                shutdown_rx,
                rpc_shutdown_tx,
                config_tx,
            ))
            .await
        }
        ListenerEndpoint::Uds { path, mode } => {
            Box::pin(run_uds_listener(
                path,
                mode,
                access_mode,
                max_tier,
                enforcement,
                roles,
                credential_store,
                credential_index,
                principal,
                rib_tx,
                rib_query_tx,
                rib_readiness_tx,
                peer_mgr_tx,
                peer_mgr_readiness_tx,
                asn,
                router_id,
                listen_port,
                metrics,
                start_time,
                mrt_trigger_tx,
                evpn_originated_local_mac_count,
                evpn_instance_status_snapshot,
                evpn_managed_netdev_status_snapshot,
                evpn_ip_vrf_status_snapshot,
                evpn_originated_ip_vrf_route_count,
                evpn_installed_ip_vrf_route_count,
                evpn_remote_ip_prefix_drop_counts,
                evpn_fdb_nexthop_snapshot,
                evpn_bum_enforcement_snapshot,
                evpn_same_esi_bias_snapshot,
                evpn_es_drain_reasons,
                evpn_runtime_model,
                evpn_runtime_apply,
                evpn_duplicate_mac_clear,
                evpn_es_drain,
                blackhole_discard_snapshot,
                fib_route_snapshot,
                fib_table_control,
                gnmi_set,
                config_transaction_apply,
                config_transaction_confirm,
                config_transaction_abort,
                config_transaction_status,
                config_history_list,
                config_rollback,
                config_mutation_gate,
                runtime_config_lock,
                dataplane_route_events,
                bfd_session_snapshot,
                bfd_events,
                dataplane_events,
                event_history,
                shutdown_rx,
                rpc_shutdown_tx,
                config_tx,
            ))
            .await
        }
    }
}

#[expect(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "startup wiring for one listener"
)]
async fn run_tcp_listener(
    addr: SocketAddr,
    access_mode: AccessMode,
    max_tier: AuthTier,
    enforcement: AuthEnforcement,
    roles: Arc<BTreeMap<String, PrincipalRole>>,
    credential_store: CredentialStore,
    credential_index: usize,
    principal: Option<String>,
    rib_tx: mpsc::Sender<RibUpdate>,
    rib_query_tx: mpsc::Sender<RibUpdate>,
    rib_readiness_tx: mpsc::Sender<RibReadinessQuery>,
    peer_mgr_tx: mpsc::Sender<PeerManagerCommand>,
    peer_mgr_readiness_tx: mpsc::Sender<PeerManagerReadinessQuery>,
    asn: u32,
    router_id: String,
    listen_port: u32,
    metrics: BgpMetrics,
    start_time: tokio::time::Instant,
    mrt_trigger_tx: Option<MrtTriggerTx>,
    evpn_originated_local_mac_count: OriginatedLocalMacCountFn,
    evpn_instance_status_snapshot: InstanceStatusSnapshotFn,
    evpn_managed_netdev_status_snapshot: ManagedNetdevStatusSnapshotFn,
    evpn_ip_vrf_status_snapshot: crate::evpn_service::IpVrfStatusSnapshotFn,
    evpn_originated_ip_vrf_route_count: crate::evpn_service::OriginatedIpVrfRouteCountFn,
    evpn_installed_ip_vrf_route_count: crate::evpn_service::InstalledIpVrfRouteCountFn,
    evpn_remote_ip_prefix_drop_counts: crate::evpn_service::RemoteIpPrefixDropCountSnapshotFn,
    evpn_fdb_nexthop_snapshot: crate::evpn_service::FdbNexthopSnapshotFn,
    evpn_bum_enforcement_snapshot: BumEnforcementSnapshotFn,
    evpn_same_esi_bias_snapshot: SameEsiBiasSnapshotFn,
    evpn_es_drain_reasons: EthernetSegmentDrainReasonsFn,
    evpn_runtime_model: EvpnRuntimeModelFn,
    evpn_runtime_apply: Option<EvpnRuntimeApplyFn>,
    evpn_duplicate_mac_clear: Option<DuplicateMacClearFn>,
    evpn_es_drain: Option<crate::evpn_service::EthernetSegmentDrainFn>,
    blackhole_discard_snapshot: crate::rib_service::BlackholeDiscardSnapshotFn,
    fib_route_snapshot: crate::rib_service::FibRouteSnapshotFn,
    fib_table_control: Option<crate::rib_service::FibTableControlFn>,
    gnmi_set: Option<GnmiSetFn>,
    config_transaction_apply: Option<ConfigTransactionApplyFn>,
    config_transaction_confirm: Option<ConfigTransactionConfirmFn>,
    config_transaction_abort: Option<ConfigTransactionAbortFn>,
    config_transaction_status: Option<ConfigTransactionStatusFn>,
    config_history_list: Option<ConfigHistoryListFn>,
    config_rollback: Option<ConfigRollbackFn>,
    config_mutation_gate: Option<ConfigMutationGateFn>,
    runtime_config_lock: Arc<tokio::sync::Mutex<()>>,
    dataplane_route_events: Option<tokio::sync::broadcast::Sender<crate::proto::BgpEvent>>,
    bfd_session_snapshot: crate::bfd_service::BfdSessionSnapshotFn,
    bfd_events: Option<tokio::sync::broadcast::Sender<crate::proto::BgpEvent>>,
    dataplane_events: DataplaneEventBroadcaster,
    event_history: Option<rustbgpd_event_history::EventHistoryHandle>,
    shutdown_rx: watch::Receiver<bool>,
    rpc_shutdown_tx: watch::Sender<bool>,
    config_tx: Option<mpsc::Sender<ConfigEvent>>,
) -> Result<(), String> {
    let initial_generation = credential_store.load();
    let credentials = initial_generation.listener(credential_index);
    let tls_enabled = credentials.tls.is_some();
    let auth_enabled = credentials.bearer.is_some();
    let tcp_listener = TcpListener::bind(addr)
        .await
        .map_err(|e| format!("failed to bind gRPC TCP listener {addr}: {e}"))?;
    let bound_addr = tcp_listener.local_addr().unwrap_or(addr);
    info!(
        %bound_addr,
        requested_addr = %addr,
        access_mode = ?access_mode,
        auth_enabled,
        tls_enabled,
        "starting gRPC TCP listener"
    );
    let audit_context = tcp_audit_context(
        bound_addr,
        access_mode,
        max_tier,
        RuntimeAuthzConfig { enforcement, roles },
        auth_enabled,
        tls_enabled,
        principal.as_deref(),
    );
    let audit_context =
        audit_context.with_dynamic_bearer(credential_store.clone(), credential_index);
    let interceptor = AuthInterceptor::new(credential_store.clone(), credential_index);
    let builder = Server::builder();
    let mut builder = builder.layer(GrpcAuthzLayer::new(audit_context, metrics.clone()));
    let incoming = FuturesStreamExt::map(TcpListenerStream::new(tcp_listener), move |accepted| {
        let generation = credential_store.load();
        async move {
            let stream = match accepted {
                Ok(stream) => stream,
                Err(error) => return Some(Err(error)),
            };
            if let Some(tls) = generation.listener(credential_index).tls.clone() {
                match tokio::time::timeout(
                    GRPC_TLS_HANDSHAKE_TIMEOUT,
                    TlsAcceptor::from(tls).accept(stream),
                )
                .await
                {
                    Ok(Ok(stream)) => Some(Ok(RustbgpdTcpStream::from_tls(stream))),
                    Ok(Err(error)) => {
                        warn!(%error, "rejected gRPC mTLS handshake");
                        None
                    }
                    Err(_) => {
                        warn!(
                            timeout_seconds = GRPC_TLS_HANDSHAKE_TIMEOUT.as_secs(),
                            "timed out gRPC mTLS handshake"
                        );
                        None
                    }
                }
            } else {
                Some(Ok(RustbgpdTcpStream::new(stream)))
            }
        }
    });
    let incoming = bounded_handshakes(incoming);
    let mut routes = tonic::service::Routes::builder();
    routes.add_service(RibServiceServer::with_interceptor(
        RibService::with_status_snapshots_and_metrics(
            rib_query_tx.clone(),
            blackhole_discard_snapshot.clone(),
            fib_route_snapshot.clone(),
            metrics.clone(),
        )
        .with_fib_table_control(access_mode, fib_table_control.clone()),
        interceptor.clone(),
    ));
    routes.add_service(EventServiceServer::with_interceptor(
        EventService::with_dataplane_snapshots_broadcaster_and_metrics(
            rib_tx.clone(),
            peer_mgr_tx.clone(),
            blackhole_discard_snapshot.clone(),
            fib_route_snapshot.clone(),
            dataplane_events,
            dataplane_route_events,
            bfd_events,
            metrics.clone(),
        )
        .with_event_history(event_history.clone()),
        interceptor.clone(),
    ));
    routes.add_service(BfdServiceServer::with_interceptor(
        BfdService::with_snapshot(bfd_session_snapshot),
        interceptor.clone(),
    ));
    routes.add_service(InjectionServiceServer::with_interceptor(
        InjectionService::new(rib_tx, access_mode),
        interceptor.clone(),
    ));
    routes.add_service(NeighborServiceServer::with_interceptor(
        NeighborService::with_runtime_config_lock(
            asn,
            access_mode,
            peer_mgr_tx.clone(),
            rib_query_tx.clone(),
            config_tx.clone(),
            runtime_config_lock.clone(),
            config_mutation_gate.clone(),
        ),
        interceptor.clone(),
    ));
    routes.add_service(PeerGroupServiceServer::with_interceptor(
        PeerGroupService::with_runtime_config_lock(
            access_mode,
            peer_mgr_tx.clone(),
            config_tx.clone(),
            config_mutation_gate.clone(),
            runtime_config_lock.clone(),
        ),
        interceptor.clone(),
    ));
    routes.add_service(PolicyServiceServer::with_interceptor(
        PolicyService::with_runtime_config_lock(
            access_mode,
            peer_mgr_tx.clone(),
            config_tx.clone(),
            config_mutation_gate.clone(),
            runtime_config_lock,
        )
        .with_rib_query(rib_query_tx.clone()),
        interceptor.clone(),
    ));
    routes.add_service(GlobalServiceServer::with_interceptor(
        GlobalService::new(asn, router_id.clone(), listen_port),
        interceptor.clone(),
    ));
    routes.add_service(ConfigServiceServer::with_interceptor(
        ConfigService::new(peer_mgr_tx.clone()).with_transaction_hooks(
            config_transaction_apply.clone(),
            config_transaction_confirm.clone(),
            config_transaction_abort.clone(),
            config_transaction_status.clone(),
            config_history_list.clone(),
            config_rollback.clone(),
        ),
        interceptor.clone(),
    ));
    routes.add_service(EvpnServiceServer::with_interceptor(
        EvpnService::with_full_surface_runtime_and_duplicate_mac_control(
            evpn_originated_local_mac_count,
            evpn_ip_vrf_status_snapshot,
            evpn_originated_ip_vrf_route_count,
            evpn_installed_ip_vrf_route_count,
            evpn_fdb_nexthop_snapshot,
            evpn_runtime_model,
            evpn_runtime_apply,
            access_mode,
            evpn_duplicate_mac_clear,
        )
        .with_instance_status_snapshot(evpn_instance_status_snapshot)
        .with_managed_netdev_status_snapshot(evpn_managed_netdev_status_snapshot)
        .with_remote_ip_prefix_drop_counts(evpn_remote_ip_prefix_drop_counts)
        .with_ethernet_segment_state(
            evpn_bum_enforcement_snapshot,
            evpn_same_esi_bias_snapshot,
            evpn_es_drain_reasons,
        )
        .with_ethernet_segment_drain(evpn_es_drain),
        interceptor.clone(),
    ));
    routes.add_service(ControlServiceServer::with_interceptor(
        ControlService::new(
            access_mode,
            start_time,
            metrics.clone(),
            peer_mgr_tx.clone(),
            rib_query_tx,
            rpc_shutdown_tx,
            mrt_trigger_tx,
        )
        .with_peer_manager_readiness(peer_mgr_readiness_tx)
        .with_rib_readiness(rib_readiness_tx),
        interceptor.clone(),
    ));
    if tls_enabled {
        routes.add_service(GNmiServer::with_interceptor(
            GnmiService::new(asn, router_id.clone(), peer_mgr_tx.clone())
                .with_set_handler(gnmi_set.clone())
                .with_event_history(event_history.clone()),
            interceptor.clone(),
        ));
    }
    Box::pin(
        builder
            .add_routes(routes.routes())
            .serve_with_incoming_shutdown(incoming, await_shutdown(shutdown_rx)),
    )
    .await
    .map_err(|e| format!("TCP listener {bound_addr} failed: {e}"))
}

#[expect(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "startup wiring for one listener"
)]
async fn run_uds_listener(
    path: PathBuf,
    mode: u32,
    access_mode: AccessMode,
    max_tier: AuthTier,
    enforcement: AuthEnforcement,
    roles: Arc<BTreeMap<String, PrincipalRole>>,
    credential_store: CredentialStore,
    credential_index: usize,
    principal: Option<String>,
    rib_tx: mpsc::Sender<RibUpdate>,
    rib_query_tx: mpsc::Sender<RibUpdate>,
    rib_readiness_tx: mpsc::Sender<RibReadinessQuery>,
    peer_mgr_tx: mpsc::Sender<PeerManagerCommand>,
    peer_mgr_readiness_tx: mpsc::Sender<PeerManagerReadinessQuery>,
    asn: u32,
    router_id: String,
    listen_port: u32,
    metrics: BgpMetrics,
    start_time: tokio::time::Instant,
    mrt_trigger_tx: Option<MrtTriggerTx>,
    evpn_originated_local_mac_count: OriginatedLocalMacCountFn,
    evpn_instance_status_snapshot: InstanceStatusSnapshotFn,
    evpn_managed_netdev_status_snapshot: ManagedNetdevStatusSnapshotFn,
    evpn_ip_vrf_status_snapshot: crate::evpn_service::IpVrfStatusSnapshotFn,
    evpn_originated_ip_vrf_route_count: crate::evpn_service::OriginatedIpVrfRouteCountFn,
    evpn_installed_ip_vrf_route_count: crate::evpn_service::InstalledIpVrfRouteCountFn,
    evpn_remote_ip_prefix_drop_counts: crate::evpn_service::RemoteIpPrefixDropCountSnapshotFn,
    evpn_fdb_nexthop_snapshot: crate::evpn_service::FdbNexthopSnapshotFn,
    evpn_bum_enforcement_snapshot: BumEnforcementSnapshotFn,
    evpn_same_esi_bias_snapshot: SameEsiBiasSnapshotFn,
    evpn_es_drain_reasons: EthernetSegmentDrainReasonsFn,
    evpn_runtime_model: EvpnRuntimeModelFn,
    evpn_runtime_apply: Option<EvpnRuntimeApplyFn>,
    evpn_duplicate_mac_clear: Option<DuplicateMacClearFn>,
    evpn_es_drain: Option<crate::evpn_service::EthernetSegmentDrainFn>,
    blackhole_discard_snapshot: crate::rib_service::BlackholeDiscardSnapshotFn,
    fib_route_snapshot: crate::rib_service::FibRouteSnapshotFn,
    fib_table_control: Option<crate::rib_service::FibTableControlFn>,
    gnmi_set: Option<GnmiSetFn>,
    config_transaction_apply: Option<ConfigTransactionApplyFn>,
    config_transaction_confirm: Option<ConfigTransactionConfirmFn>,
    config_transaction_abort: Option<ConfigTransactionAbortFn>,
    config_transaction_status: Option<ConfigTransactionStatusFn>,
    config_history_list: Option<ConfigHistoryListFn>,
    config_rollback: Option<ConfigRollbackFn>,
    config_mutation_gate: Option<ConfigMutationGateFn>,
    runtime_config_lock: Arc<tokio::sync::Mutex<()>>,
    dataplane_route_events: Option<tokio::sync::broadcast::Sender<crate::proto::BgpEvent>>,
    bfd_session_snapshot: crate::bfd_service::BfdSessionSnapshotFn,
    bfd_events: Option<tokio::sync::broadcast::Sender<crate::proto::BgpEvent>>,
    dataplane_events: DataplaneEventBroadcaster,
    event_history: Option<rustbgpd_event_history::EventHistoryHandle>,
    shutdown_rx: watch::Receiver<bool>,
    rpc_shutdown_tx: watch::Sender<bool>,
    config_tx: Option<mpsc::Sender<ConfigEvent>>,
) -> Result<(), String> {
    let uds_listener = bind_uds_listener(&path, mode)?;
    let auth_enabled = credential_store
        .load()
        .listener(credential_index)
        .bearer
        .is_some();
    let audit_context = uds_audit_context(
        &path,
        mode,
        access_mode,
        max_tier,
        RuntimeAuthzConfig { enforcement, roles },
        None,
        principal.as_deref(),
    );
    info!(
        path = %path.display(),
        access_mode = ?access_mode,
        auth_enabled,
        "starting gRPC UDS listener"
    );
    let audit_context =
        audit_context.with_dynamic_bearer(credential_store.clone(), credential_index);
    let interceptor = AuthInterceptor::new(credential_store, credential_index);
    let mut routes = tonic::service::Routes::builder();
    routes.add_service(RibServiceServer::with_interceptor(
        RibService::with_status_snapshots_and_metrics(
            rib_query_tx.clone(),
            blackhole_discard_snapshot.clone(),
            fib_route_snapshot.clone(),
            metrics.clone(),
        )
        .with_fib_table_control(access_mode, fib_table_control.clone()),
        interceptor.clone(),
    ));
    routes.add_service(EventServiceServer::with_interceptor(
        EventService::with_dataplane_snapshots_broadcaster_and_metrics(
            rib_tx.clone(),
            peer_mgr_tx.clone(),
            blackhole_discard_snapshot.clone(),
            fib_route_snapshot.clone(),
            dataplane_events,
            dataplane_route_events,
            bfd_events,
            metrics.clone(),
        )
        .with_event_history(event_history.clone()),
        interceptor.clone(),
    ));
    routes.add_service(BfdServiceServer::with_interceptor(
        BfdService::with_snapshot(bfd_session_snapshot),
        interceptor.clone(),
    ));
    routes.add_service(InjectionServiceServer::with_interceptor(
        InjectionService::new(rib_tx, access_mode),
        interceptor.clone(),
    ));
    routes.add_service(NeighborServiceServer::with_interceptor(
        NeighborService::with_runtime_config_lock(
            asn,
            access_mode,
            peer_mgr_tx.clone(),
            rib_query_tx.clone(),
            config_tx.clone(),
            runtime_config_lock.clone(),
            config_mutation_gate.clone(),
        ),
        interceptor.clone(),
    ));
    routes.add_service(PeerGroupServiceServer::with_interceptor(
        PeerGroupService::with_runtime_config_lock(
            access_mode,
            peer_mgr_tx.clone(),
            config_tx.clone(),
            config_mutation_gate.clone(),
            runtime_config_lock.clone(),
        ),
        interceptor.clone(),
    ));
    routes.add_service(PolicyServiceServer::with_interceptor(
        PolicyService::with_runtime_config_lock(
            access_mode,
            peer_mgr_tx.clone(),
            config_tx.clone(),
            config_mutation_gate.clone(),
            runtime_config_lock,
        )
        .with_rib_query(rib_query_tx.clone()),
        interceptor.clone(),
    ));
    routes.add_service(GlobalServiceServer::with_interceptor(
        GlobalService::new(asn, router_id.clone(), listen_port),
        interceptor.clone(),
    ));
    routes.add_service(ConfigServiceServer::with_interceptor(
        ConfigService::new(peer_mgr_tx.clone()).with_transaction_hooks(
            config_transaction_apply.clone(),
            config_transaction_confirm.clone(),
            config_transaction_abort.clone(),
            config_transaction_status.clone(),
            config_history_list.clone(),
            config_rollback.clone(),
        ),
        interceptor.clone(),
    ));
    routes.add_service(EvpnServiceServer::with_interceptor(
        EvpnService::with_full_surface_runtime_and_duplicate_mac_control(
            evpn_originated_local_mac_count,
            evpn_ip_vrf_status_snapshot,
            evpn_originated_ip_vrf_route_count,
            evpn_installed_ip_vrf_route_count,
            evpn_fdb_nexthop_snapshot,
            evpn_runtime_model,
            evpn_runtime_apply,
            access_mode,
            evpn_duplicate_mac_clear,
        )
        .with_instance_status_snapshot(evpn_instance_status_snapshot)
        .with_managed_netdev_status_snapshot(evpn_managed_netdev_status_snapshot)
        .with_remote_ip_prefix_drop_counts(evpn_remote_ip_prefix_drop_counts)
        .with_ethernet_segment_state(
            evpn_bum_enforcement_snapshot,
            evpn_same_esi_bias_snapshot,
            evpn_es_drain_reasons,
        )
        .with_ethernet_segment_drain(evpn_es_drain),
        interceptor.clone(),
    ));
    routes.add_service(ControlServiceServer::with_interceptor(
        ControlService::new(
            access_mode,
            start_time,
            metrics.clone(),
            peer_mgr_tx.clone(),
            rib_query_tx,
            rpc_shutdown_tx,
            mrt_trigger_tx,
        )
        .with_peer_manager_readiness(peer_mgr_readiness_tx)
        .with_rib_readiness(rib_readiness_tx),
        interceptor.clone(),
    ));
    routes.add_service(GNmiServer::with_interceptor(
        GnmiService::new(asn, router_id, peer_mgr_tx.clone())
            .with_set_handler(gnmi_set)
            .with_event_history(event_history.clone()),
        interceptor,
    ));

    let result = Server::builder()
        .layer(GrpcAuthzLayer::new(audit_context, metrics.clone()))
        .add_routes(routes.routes())
        .serve_with_incoming_shutdown(
            UnixListenerStream::new(uds_listener),
            await_shutdown(shutdown_rx),
        )
        .await
        .map_err(|e| format!("UDS listener {} failed: {e}", path.display()));

    if let Err(err) = cleanup_uds_socket(&path) {
        warn!(path = %path.display(), error = %err, "failed to remove gRPC UDS socket");
    }

    result
}

fn bind_uds_listener(path: &Path, mode: u32) -> Result<UnixListener, String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("failed to create UDS parent {}: {e}", parent.display()))?;
    }

    if path.exists() {
        let metadata = std::fs::symlink_metadata(path)
            .map_err(|e| format!("failed to stat existing UDS path {}: {e}", path.display()))?;
        if metadata.file_type().is_socket() {
            std::fs::remove_file(path).map_err(|e| {
                format!("failed to remove stale UDS socket {}: {e}", path.display())
            })?;
        } else {
            return Err(format!(
                "refusing to replace non-socket file at {}",
                path.display()
            ));
        }
    }

    let listener = UnixListener::bind(path)
        .map_err(|e| format!("failed to bind UDS listener {}: {e}", path.display()))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).map_err(|e| {
        format!(
            "failed to set permissions on UDS listener {}: {e}",
            path.display()
        )
    })?;
    Ok(listener)
}

fn cleanup_uds_socket(path: &Path) -> Result<(), String> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(format!(
            "failed to remove UDS socket {}: {e}",
            path.display()
        )),
    }
}

async fn await_shutdown(mut shutdown_rx: watch::Receiver<bool>) {
    if *shutdown_rx.borrow() {
        return;
    }
    while shutdown_rx.changed().await.is_ok() {
        if *shutdown_rx.borrow() {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Seek, Write};

    use super::*;
    use crate::credentials::CredentialSource;
    use crate::peer_types::SessionLifecycleEventType;
    use crate::proto::GetGlobalRequest;
    use crate::proto::event_service_client::EventServiceClient;
    use crate::proto::global_service_client::GlobalServiceClient;
    use crate::proto::{EventCategory, WatchEventsRequest};
    use crate::test_support::{session_event, spawn_fake_peer_manager, spawn_fake_rib};

    fn tier_authz(principal: &str) -> RuntimeAuthzConfig {
        RuntimeAuthzConfig {
            enforcement: AuthEnforcement::Tier,
            roles: Arc::new(BTreeMap::from([(
                principal.to_string(),
                PrincipalRole::Operator,
            )])),
        }
    }

    /// Mutation proof: restoring the old Legacy test builder or dropping its
    /// principal mapping makes one of these exact assertions red.
    #[test]
    fn test_authz_builder_uses_tier_operator_role() {
        let config = tier_authz("rustbgpd://operator/api-test");
        assert_eq!(config.enforcement, AuthEnforcement::Tier);
        assert_eq!(
            config.roles.get("rustbgpd://operator/api-test"),
            Some(&PrincipalRole::Operator)
        );
    }

    #[test]
    fn catalog_mutation_errors_map_by_variant() {
        let cases = [
            (
                CatalogMutationError::not_found("missing policy"),
                tonic::Code::NotFound,
            ),
            (
                CatalogMutationError::StillReferenced {
                    kind: "policy",
                    name: "keep".into(),
                    references: vec!["global import_chain".into()],
                },
                tonic::Code::FailedPrecondition,
            ),
            (
                CatalogMutationError::invalid("bad policy"),
                tonic::Code::InvalidArgument,
            ),
            (
                CatalogMutationError::RestartRequired("tcp_ao delta".into()),
                tonic::Code::FailedPrecondition,
            ),
            (
                CatalogMutationError::internal("runtime apply failed"),
                tonic::Code::Internal,
            ),
        ];

        for (error, code) in cases {
            assert_eq!(catalog_mutation_error_to_status(&error).code(), code);
        }
    }

    #[test]
    fn auth_interceptor_allows_unprotected_requests() {
        let mut interceptor = AuthInterceptor::from_token(None);
        assert!(interceptor.call(Request::new(())).is_ok());
    }

    #[test]
    fn auth_interceptor_rejects_missing_token() {
        let mut interceptor = AuthInterceptor::from_token(Some("secret"));
        let err = interceptor.call(Request::new(())).unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
    }

    #[test]
    fn auth_interceptor_accepts_matching_token() {
        let mut interceptor = AuthInterceptor::from_token(Some("secret"));
        let mut request = Request::new(());
        request
            .metadata_mut()
            .insert("authorization", "Bearer secret".parse().unwrap());
        assert!(interceptor.call(request).is_ok());
    }

    #[test]
    fn auth_interceptor_rejects_wrong_token() {
        let mut interceptor = AuthInterceptor::from_token(Some("secret"));
        let mut request = Request::new(());
        request
            .metadata_mut()
            .insert("authorization", "Bearer wrong".parse().unwrap());
        let err = interceptor.call(request).unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
    }

    #[test]
    fn dynamic_interceptor_applies_rotation_to_next_rpc_on_same_instance() {
        let mut token = tempfile::NamedTempFile::new().unwrap();
        token.write_all(b"old").unwrap();
        token.flush().unwrap();
        let store = CredentialStore::stage(vec![CredentialSource {
            token_file: Some(token.path().to_path_buf()),
            tls: None,
        }])
        .unwrap();
        let mut interceptor = AuthInterceptor::new(store.clone(), 0);
        let mut old = Request::new(());
        old.metadata_mut()
            .insert("authorization", "Bearer old".parse().unwrap());
        assert!(interceptor.call(old).is_ok());

        token.as_file_mut().set_len(0).unwrap();
        token.rewind().unwrap();
        token.write_all(b"new").unwrap();
        token.flush().unwrap();
        store.reload().unwrap();
        let mut old = Request::new(());
        old.metadata_mut()
            .insert("authorization", "Bearer old".parse().unwrap());
        assert!(interceptor.call(old).is_err());
        let mut new = Request::new(());
        new.metadata_mut()
            .insert("authorization", "Bearer new".parse().unwrap());
        assert!(interceptor.call(new).is_ok());
    }

    #[tokio::test]
    async fn bounded_handshakes_do_not_serialize_behind_stalled_client() {
        type TestHandshake = Pin<Box<dyn Future<Output = Option<Result<u8, ()>>> + Send>>;
        let stalled = Box::pin(std::future::pending::<Option<Result<u8, ()>>>());
        let ready = Box::pin(std::future::ready(Some(Ok(7))));
        let futures: Vec<TestHandshake> = vec![stalled, ready];
        let mut admitted = bounded_handshakes(tokio_stream::iter(futures));
        let result = tokio::time::timeout(Duration::from_millis(100), admitted.next())
            .await
            .expect("ready handshake must not queue behind stalled handshake");
        assert_eq!(result, Some(Ok(7)));
    }

    #[tokio::test]
    async fn live_http2_channel_uses_rotated_token_on_each_rpc() {
        let mut token = tempfile::NamedTempFile::new().unwrap();
        token.write_all(b"old").unwrap();
        token.flush().unwrap();
        let store = CredentialStore::stage(vec![CredentialSource {
            token_file: Some(token.path().to_path_buf()),
            tls: None,
        }])
        .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let incoming = FuturesStreamExt::map(TcpListenerStream::new(listener), |stream| {
            stream.map(RustbgpdTcpStream::new)
        });
        let (rib_tx, _) = spawn_fake_rib();
        let (peer_tx, session_events, _) = spawn_fake_peer_manager();
        let context = tcp_audit_context(
            addr,
            AccessMode::ReadOnly,
            AuthTier::SensitiveRead,
            tier_authz("test"),
            true,
            false,
            Some("test"),
        )
        .with_dynamic_bearer(store.clone(), 0);
        let interceptor = AuthInterceptor::new(store.clone(), 0);
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let server = tokio::spawn(async move {
            Server::builder()
                .layer(GrpcAuthzLayer::new(context, BgpMetrics::new()))
                .add_service(GlobalServiceServer::with_interceptor(
                    GlobalService::new(65000, "192.0.2.1".into(), 179),
                    interceptor.clone(),
                ))
                .add_service(EventServiceServer::with_interceptor(
                    EventService::new(rib_tx, peer_tx),
                    interceptor,
                ))
                .serve_with_incoming_shutdown(incoming, async {
                    let _ = shutdown_rx.await;
                })
                .await
                .unwrap();
        });
        let channel = tonic::transport::Endpoint::from_shared(format!("http://{addr}"))
            .unwrap()
            .connect()
            .await
            .unwrap();
        let mut client = GlobalServiceClient::new(channel.clone());
        let mut request = Request::new(GetGlobalRequest {});
        request
            .metadata_mut()
            .insert("authorization", "Bearer old".parse().unwrap());
        client.get_global(request).await.unwrap();
        let mut events = EventServiceClient::new(channel);
        let mut watch = Request::new(WatchEventsRequest {
            categories: vec![EventCategory::Session as i32],
            ..Default::default()
        });
        watch
            .metadata_mut()
            .insert("authorization", "Bearer old".parse().unwrap());
        let mut stream = events.watch_events(watch).await.unwrap().into_inner();

        token.as_file_mut().set_len(0).unwrap();
        token.rewind().unwrap();
        token.write_all(b"new").unwrap();
        token.flush().unwrap();
        store.reload().unwrap();
        let mut old = Request::new(GetGlobalRequest {});
        old.metadata_mut()
            .insert("authorization", "Bearer old".parse().unwrap());
        assert_eq!(
            client.get_global(old).await.unwrap_err().code(),
            tonic::Code::Unauthenticated
        );
        let mut new = Request::new(GetGlobalRequest {});
        new.metadata_mut()
            .insert("authorization", "Bearer new".parse().unwrap());
        client.get_global(new).await.unwrap();
        session_events
            .send(session_event(
                "192.0.2.9".parse().unwrap(),
                SessionLifecycleEventType::Established,
            ))
            .unwrap();
        let event = tokio::time::timeout(Duration::from_secs(1), stream.message())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(event.peer_address, "192.0.2.9");
        drop(stream);
        drop(events);
        drop(client);
        let _ = shutdown_tx.send(());
        server.await.unwrap();
    }

    #[test]
    fn tcp_audit_context_uses_configured_bearer_principal() {
        let context = tcp_audit_context(
            "127.0.0.1:50051".parse().unwrap(),
            AccessMode::ReadWrite,
            AuthTier::OperatorOnly,
            tier_authz("automation.example"),
            true,
            false,
            Some("automation.example"),
        );
        assert_eq!(context.authn(), GrpcAuthnKind::BearerToken);
        assert_eq!(context.principal(), "automation.example");
        assert_eq!(context.max_tier(), AuthTier::OperatorOnly);
    }

    #[test]
    fn tcp_audit_context_dynamic_bearer_keeps_configured_principal() {
        // Regression: a bearer listener whose token is served by the
        // dynamic credential store has no static token, yet is still
        // bearer-authenticated (`bearer_enabled = true`). It must carry
        // the configured principal so tier role-mapping resolves — not
        // the "unauthenticated" placeholder, which denies every RPC as
        // principal_unmapped.
        let context = tcp_audit_context(
            "127.0.0.1:50051".parse().unwrap(),
            AccessMode::ReadWrite,
            AuthTier::OperatorOnly,
            tier_authz("rustbgpd://operator/ci"),
            true,
            false,
            Some("rustbgpd://operator/ci"),
        );
        assert_eq!(context.authn(), GrpcAuthnKind::BearerToken);
        assert_eq!(context.principal(), "rustbgpd://operator/ci");
    }

    #[test]
    fn tcp_audit_context_uses_mtls_fallback_until_request_cert_available() {
        let context = tcp_audit_context(
            "127.0.0.1:50051".parse().unwrap(),
            AccessMode::ReadWrite,
            AuthTier::Mutating,
            tier_authz("mtls-unresolved"),
            true,
            true,
            Some("automation.example"),
        );
        assert_eq!(context.authn(), GrpcAuthnKind::Mtls);
        assert_eq!(context.principal(), "mtls-unresolved");
        assert_eq!(context.max_tier(), AuthTier::Mutating);
    }

    #[test]
    fn uds_audit_context_uses_configured_principal() {
        let context = uds_audit_context(
            Path::new("/run/rustbgpd/grpc.sock"),
            0o600,
            AccessMode::ReadWrite,
            AuthTier::SensitiveRead,
            tier_authz("local-admin"),
            None,
            Some("local-admin"),
        );
        assert_eq!(context.authn(), GrpcAuthnKind::Uds);
        assert_eq!(context.principal(), "local-admin");
        assert_eq!(context.max_tier(), AuthTier::SensitiveRead);
    }

    #[test]
    fn uds_audit_context_owner_only_socket_resolves_implicit_local_operator() {
        // Red proof: dropping the implicit-identity resolution turns the
        // principal back into the unmapped `uds:<path>` placeholder and
        // fails these assertions (and the zero-config boot smoke).
        let context = uds_audit_context(
            Path::new("/run/rustbgpd/grpc.sock"),
            0o600,
            AccessMode::ReadWrite,
            AuthTier::OperatorOnly,
            RuntimeAuthzConfig {
                enforcement: AuthEnforcement::Tier,
                roles: Arc::new(BTreeMap::new()),
            },
            None,
            None,
        );
        assert_eq!(context.authn(), GrpcAuthnKind::UdsOwner);
        assert_eq!(context.principal(), LOCAL_OPERATOR_PRINCIPAL);
    }

    #[test]
    fn uds_audit_context_group_accessible_socket_stays_unmapped() {
        // Red proof: widening the owner-only check to accept group
        // bits (e.g. 0o660) makes this listener resolve the implicit
        // identity and fails this test.
        let context = uds_audit_context(
            Path::new("/run/rustbgpd/grpc.sock"),
            0o660,
            AccessMode::ReadWrite,
            AuthTier::OperatorOnly,
            RuntimeAuthzConfig {
                enforcement: AuthEnforcement::Tier,
                roles: Arc::new(BTreeMap::new()),
            },
            None,
            None,
        );
        assert_eq!(context.authn(), GrpcAuthnKind::Uds);
        assert_eq!(context.principal(), "uds:/run/rustbgpd/grpc.sock");
    }
}
