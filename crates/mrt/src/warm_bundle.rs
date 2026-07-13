//! Durable, fail-closed warm-checkpoint bundle storage.
//!
//! This module stops at storage and identity validation. It never restores a
//! route, mutates the RIB, runs selection, releases RFC 4724 deferral, or
//! advertises a recovered candidate. A later boot coordinator must keep all
//! recovered candidates behind that gate.
//!
//! The caller creates the bundle directory before dropping privileges, gives
//! it to the daemon user, and keeps it non-group/world-writable. [`WarmBundleDirectory::open`]
//! pins that directory as a verified file descriptor. Every subsequent read,
//! create, rename, unlink, and fsync is relative to the descriptor, so path
//! replacement and symlink races cannot redirect publication or loading.
//!
//! Publication fsyncs and renames the content-addressed MRT artifact before it
//! atomically replaces `manifest.json`, the commit point, then fsyncs the
//! directory. A failure before the manifest rename leaves the previous commit
//! authoritative. A failure after it can expose only the complete new commit.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{self, Read as _, Seek as _, SeekFrom, Write as _};
use std::net::{IpAddr, Ipv4Addr};
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use nix::fcntl::{OFlag, open, openat, renameat};
use nix::sys::stat::Mode;
use nix::unistd::{UnlinkatFlags, geteuid, unlinkat};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::{ReadError, SnapshotNlri, SnapshotReader};

/// On-disk format understood by this implementation.
pub const WARM_BUNDLE_FORMAT_VERSION: u32 = 1;
/// Version of the deterministic resolved import-policy digest framing.
pub const WARM_BUNDLE_POLICY_DIGEST_VERSION: u32 = 1;
/// Fixed manifest file name within a bundle directory.
pub const WARM_BUNDLE_MANIFEST_FILE: &str = "manifest.json";
/// Maximum manifest bytes accepted before JSON parsing (8 MiB).
///
/// Compact V1 manifests use about 250 bytes per peer/family view. This cap
/// leaves room for more than 10,000 dual-stack RR peers while bounding boot
/// allocation and rejecting unreasonable JSON before parsing.
pub const MAX_WARM_BUNDLE_MANIFEST_BYTES: u64 = 8 * 1024 * 1024;
/// Maximum MRT artifact bytes accepted by V1 (512 MiB).
///
/// V1 currently hands verified bytes to the later restore coordinator as one
/// allocation. Keep that allocation operationally bounded; raising this cap
/// requires a fully streaming restore consumer rather than reusing the much
/// larger decompression-format ceiling from [`crate::reader`].
pub const MAX_WARM_BUNDLE_SNAPSHOT_BYTES: u64 = 512 * 1024 * 1024;

const MAX_OPAQUE_GENERATION_BYTES: usize = 128;
const MAX_PIT_VIEW_BYTES: usize = u16::MAX as usize;
const STREAM_BUFFER_BYTES: usize = 16 * 1024;
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Address family represented by one cached peer view.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WarmBundleFamilyV1 {
    /// IPv4 unicast (`AFI=1`, `SAFI=1`).
    Ipv4Unicast,
    /// IPv6 unicast (`AFI=2`, `SAFI=1`).
    Ipv6Unicast,
    /// L2VPN EVPN (`AFI=25`, `SAFI=70`).
    L2vpnEvpn,
}

/// Semantic route view carried by a warm checkpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WarmBundleViewKindV1 {
    /// Routes received from the peer before import policy.
    AdjRibInPrePolicy,
}

/// Exact eligible peer/family view identity bound by the snapshot.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WarmBundleViewV1 {
    /// V1 semantic view. Loc-RIB and Adj-RIB-Out are never accepted.
    pub kind: WarmBundleViewKindV1,
    /// Configured peer address.
    pub peer: IpAddr,
    /// Configured peer ASN.
    pub peer_asn: u32,
    /// Peer BGP identifier from the `PEER_INDEX_TABLE`.
    pub peer_router_id: Ipv4Addr,
    /// Address family represented by the bundle, including an empty view.
    pub family: WarmBundleFamilyV1,
    /// Whether Add-Path receive was negotiated for this view.
    pub add_path_receive: bool,
}

/// Versioned digest of all resolved import policies covering the snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WarmBundlePolicyDigestV1 {
    /// Canonical framing version.
    pub version: u32,
    /// Lowercase SHA-256 of the domain-separated canonical policy inventory.
    pub sha256: String,
}

/// One input to [`resolved_import_policy_digest_v1`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WarmBundlePolicyInputV1 {
    /// View whose fully resolved policy follows.
    pub view: WarmBundleViewV1,
    /// Stable, canonical bytes of the effective policy, not a process counter.
    pub canonical_policy: Vec<u8>,
}

/// Deterministically digest strictly sorted resolved import-policy inputs.
///
/// The framing includes a domain/version prefix and length-prefixes both the
/// canonical JSON view identity and caller-produced canonical policy bytes.
/// This makes the digest stable across processes and unambiguous.
///
/// # Errors
///
/// Returns [`WarmBundleError::NonCanonicalPolicyInputs`] unless inputs are
/// strictly ordered by view and cover no view twice.
pub fn resolved_import_policy_digest_v1(
    inputs: &[WarmBundlePolicyInputV1],
) -> Result<WarmBundlePolicyDigestV1, WarmBundleError> {
    if inputs.is_empty() || inputs.windows(2).any(|pair| pair[0].view >= pair[1].view) {
        return Err(WarmBundleError::NonCanonicalPolicyInputs);
    }
    let mut digest = Sha256::new();
    digest.update(b"rustbgpd/warm-bundle/resolved-import-policy\0");
    digest.update(WARM_BUNDLE_POLICY_DIGEST_VERSION.to_be_bytes());
    for input in inputs {
        let view = serde_json::to_vec(&input.view).map_err(WarmBundleError::CorruptManifest)?;
        update_len_prefixed(&mut digest, &view);
        update_len_prefixed(&mut digest, &input.canonical_policy);
    }
    Ok(WarmBundlePolicyDigestV1 {
        version: WARM_BUNDLE_POLICY_DIGEST_VERSION,
        sha256: digest_hex(digest.finalize()),
    })
}

/// Identity and manifest-authored metadata committed with one checkpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WarmBundleIdentityV1 {
    /// Opaque generation issued by the checkpoint coordinator.
    pub checkpoint_generation: String,
    /// UTC Unix seconds at which the snapshot was committed.
    pub created_at_utc_seconds: i64,
    /// Monotonic revision of the snapshot operation.
    pub snapshot_revision: u64,
    /// Local ASN at snapshot time.
    pub local_asn: u32,
    /// Local router ID, also bound to the MRT collector BGP ID.
    pub local_router_id: Ipv4Addr,
    /// Exact `PEER_INDEX_TABLE` view name/generation.
    pub peer_index_table_view: String,
    /// SHA-256 of the canonical effective configuration.
    pub config_sha256: String,
    /// Deterministic digest of all fully resolved import policies.
    pub resolved_import_policy: WarmBundlePolicyDigestV1,
    /// Strictly sorted, duplicate-free peer/family views.
    pub views: Vec<WarmBundleViewV1>,
}

/// Current boot contract derived without trusting manifest-authored metadata.
///
/// The restart marker supplies only `checkpoint_generation`; every other field
/// comes from current validated configuration and, for negotiated view fields,
/// the current session before candidate adoption. Snapshot time/revision and
/// the `PEER_INDEX_TABLE` view remain manifest-authored and are validated
/// through freshness and MRT semantic checks instead of being copied here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WarmBundleExpectedV1 {
    /// Exact generation referenced by the independently validated marker.
    pub checkpoint_generation: String,
    /// Current local ASN.
    pub local_asn: u32,
    /// Current local router ID.
    pub local_router_id: Ipv4Addr,
    /// SHA-256 of the current canonical effective configuration.
    pub config_sha256: String,
    /// Deterministic digest of current fully resolved import policies.
    pub resolved_import_policy: WarmBundlePolicyDigestV1,
    /// Current eligible static peer/family/session identity and Add-Path views.
    pub views: Vec<WarmBundleViewV1>,
}

/// Caller-supplied wall-clock freshness policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WarmBundleFreshnessV1 {
    /// Current UTC Unix seconds, supplied by the boot coordinator.
    pub now_utc_seconds: i64,
    /// Maximum accepted checkpoint age.
    pub max_age_seconds: u64,
    /// Maximum accepted clock skew into the future.
    pub max_future_skew_seconds: u64,
}

/// Content-addressed MRT artifact descriptor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WarmBundleArtifactV1 {
    /// Single path component relative to the trusted directory descriptor.
    pub path: String,
    /// Exact artifact size.
    pub size_bytes: u64,
    /// Lowercase SHA-256 of the artifact bytes.
    pub sha256: String,
}

/// V1 on-disk manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WarmBundleManifestV1 {
    /// Must equal [`WARM_BUNDLE_FORMAT_VERSION`].
    pub format_version: u32,
    /// Exact boot identity for fail-closed adoption.
    pub identity: WarmBundleIdentityV1,
    /// Integrity and path binding for the MRT artifact.
    pub snapshot: WarmBundleArtifactV1,
    /// Exact route counts aligned with sorted `identity.views`, including zero.
    pub view_route_counts: Vec<u64>,
}

/// A fully byte- and semantically-verified bundle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WarmBundleV1 {
    /// Parsed and validated manifest.
    pub manifest: WarmBundleManifestV1,
    /// Verified MRT bytes. No route has been restored or selected.
    pub snapshot: Vec<u8>,
}

/// An owner-verified, pinned bundle directory descriptor.
#[derive(Debug)]
pub struct WarmBundleDirectory {
    file: File,
    display_path: PathBuf,
}

impl WarmBundleDirectory {
    /// Open a preexisting directory without following its final symlink.
    ///
    /// The directory must be owned by the daemon's effective UID and must not
    /// be writable by group or other. This function never creates or chmods it.
    ///
    /// # Errors
    ///
    /// Returns a typed filesystem rejection or I/O error.
    pub fn open(path: &Path) -> Result<Self, WarmBundleError> {
        let fd = open(
            path,
            OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|source| nix_io(path, source))?;
        let file = File::from(fd);
        validate_owner_mode(&file, path, "directory", true)?;
        Ok(Self {
            file,
            display_path: path.to_path_buf(),
        })
    }

    /// Open a single child directory relative to an already pinned parent.
    ///
    /// This is used by the daemon to keep the restart marker and bundle below
    /// the same owner-verified runtime-state directory authority. `name` must
    /// be exactly one ordinary path component; the child itself is opened with
    /// `O_NOFOLLOW` and receives the same owner/mode validation as [`Self::open`].
    ///
    /// # Errors
    ///
    /// Returns a typed validation or descriptor-relative I/O error.
    pub fn open_at(
        parent: &File,
        parent_display_path: &Path,
        name: &str,
    ) -> Result<Self, WarmBundleError> {
        let component = Path::new(name);
        if component.components().count() != 1
            || component.file_name().and_then(|value| value.to_str()) != Some(name)
            || matches!(name, "" | "." | "..")
        {
            return Err(WarmBundleError::InvalidSnapshotPath {
                path: name.to_string(),
            });
        }
        let display_path = parent_display_path.join(name);
        let fd = openat(
            parent,
            name,
            OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|source| nix_io(&display_path, source))?;
        let file = File::from(fd);
        validate_owner_mode(&file, &display_path, "directory", true)?;
        Ok(Self { file, display_path })
    }
}

/// Warm-bundle storage or validation failure.
#[derive(Debug, Error)]
pub enum WarmBundleError {
    /// A filesystem operation failed.
    #[error("warm bundle I/O at {path}: {source}")]
    Io {
        /// Path or logical directory entry involved.
        path: PathBuf,
        /// Underlying filesystem error.
        #[source]
        source: io::Error,
    },
    /// Directory/file ownership or permissions were unsafe.
    #[error("warm bundle {role} has unsafe owner or mode: {path}")]
    UnsafePermissions {
        /// Logical role.
        role: &'static str,
        /// Display-only path.
        path: PathBuf,
    },
    /// An opened object was not the required regular file/directory.
    #[error("warm bundle {role} has unsafe filesystem type: {path}")]
    UnsafeFileType {
        /// Logical role.
        role: &'static str,
        /// Display-only path.
        path: PathBuf,
    },
    /// A file exceeded its hard read cap.
    #[error("warm bundle {role} is {actual} bytes, exceeding the {cap}-byte cap")]
    FileTooLarge {
        /// Logical role.
        role: &'static str,
        /// Observed or declared length.
        actual: u64,
        /// Maximum accepted length.
        cap: u64,
    },
    /// A bounded artifact could not be allocated without risking process abort.
    #[error("warm bundle {role} could not reserve {requested} bytes")]
    AllocationFailed {
        /// Logical role.
        role: &'static str,
        /// Requested allocation size.
        requested: u64,
    },
    /// JSON was torn, malformed, or not the exact V1 shape.
    #[error("warm bundle manifest is torn or corrupt: {0}")]
    CorruptManifest(#[source] serde_json::Error),
    /// Unsupported on-disk version.
    #[error("unsupported warm bundle format version {found}; expected {expected}")]
    UnsupportedVersion {
        /// Version found.
        found: u32,
        /// Implemented version.
        expected: u32,
    },
    /// A digest field was not canonical lowercase SHA-256.
    #[error("warm bundle {field} is not a lowercase 64-character SHA-256 digest")]
    InvalidDigest {
        /// Invalid field.
        field: &'static str,
    },
    /// Policy inputs were empty, duplicate, or unsorted.
    #[error("resolved import-policy inputs must be strictly sorted and duplicate-free")]
    NonCanonicalPolicyInputs,
    /// At least one view is required.
    #[error("warm bundle identity contains no peer/family views")]
    EmptyViews,
    /// Views must be deterministic and unambiguous.
    #[error(
        "warm bundle peer/family views must be strictly sorted, duplicate-free, and identify one profile per peer/family"
    )]
    NonCanonicalViews,
    /// A view profile cannot be represented by the V1 MRT subset.
    #[error("unsupported warm bundle view profile: {reason}")]
    UnsupportedViewProfile {
        /// Why the profile is unsupported.
        reason: &'static str,
    },
    /// An opaque string was empty, oversized, or contained controls.
    #[error("warm bundle {field} is not a valid bounded opaque identifier")]
    InvalidOpaqueIdentity {
        /// Invalid field.
        field: &'static str,
    },
    /// The manifest attempted to select an unsafe artifact name.
    #[error("invalid warm bundle snapshot path {path:?}")]
    InvalidSnapshotPath {
        /// Rejected value.
        path: String,
    },
    /// Current boot identity differs from checkpoint identity.
    #[error("warm bundle {field} does not match current boot identity")]
    IdentityMismatch {
        /// Component that differed.
        field: &'static str,
    },
    /// Checkpoint is older than the caller's freshness window.
    #[error("warm bundle checkpoint is too old")]
    Expired,
    /// Checkpoint timestamp exceeds allowed future skew.
    #[error("warm bundle checkpoint timestamp is too far in the future")]
    FutureTimestamp,
    /// Artifact metadata did not match the opened file.
    #[error("warm bundle snapshot size mismatch: manifest={declared}, file={actual}")]
    SnapshotSizeMismatch {
        /// Size recorded in manifest.
        declared: u64,
        /// Size read.
        actual: u64,
    },
    /// Artifact content did not match its digest.
    #[error("warm bundle snapshot SHA-256 mismatch")]
    SnapshotHashMismatch,
    /// MRT framing or content was malformed/incomplete.
    #[error("warm bundle MRT validation failed: {0}")]
    InvalidMrt(#[source] ReadError),
    /// An EVPN NLRI was structurally framed but not semantically decodable.
    #[error("warm bundle MRT EVPN NLRI validation failed: {0}")]
    InvalidEvpnNlri(#[source] rustbgpd_wire::error::DecodeError),
    /// MRT contained a record type the recovery path would skip.
    #[error("warm bundle MRT contains {count} skipped or unknown records")]
    SkippedMrtRecords {
        /// Number skipped by [`SnapshotReader`].
        count: u64,
    },
    /// MRT semantic inventory did not exactly match the manifest.
    #[error("warm bundle MRT {field} does not match the manifest")]
    MrtIdentityMismatch {
        /// Mismatched semantic field.
        field: &'static str,
    },
}

/// Atomically publish a V1 warm-checkpoint bundle.
///
/// The directory must already be pinned by [`WarmBundleDirectory::open`].
/// The snapshot is semantically validated before any filesystem mutation.
///
/// # Errors
///
/// Returns a typed validation, MRT, or durable I/O error.
pub fn write_warm_bundle(
    directory: &WarmBundleDirectory,
    identity: WarmBundleIdentityV1,
    snapshot: &[u8],
) -> Result<WarmBundleManifestV1, WarmBundleError> {
    write_warm_bundle_inner(directory, identity, snapshot, FaultPoint::None)
}

/// Load only an exact, fresh, byte- and semantically-valid bundle.
///
/// `expected` must be derived independently from current configuration and
/// checkpoint coordination, never copied from the manifest under inspection.
/// This function drains the entire [`SnapshotReader`] but restores no routes.
///
/// # Errors
///
/// Any mismatch is a cold-boot result for the caller.
pub fn load_warm_bundle(
    directory: &WarmBundleDirectory,
    expected: &WarmBundleExpectedV1,
    freshness: WarmBundleFreshnessV1,
) -> Result<WarmBundleV1, WarmBundleError> {
    validate_expected(expected)?;
    let manifest_bytes = read_entry_bounded(
        directory,
        WARM_BUNDLE_MANIFEST_FILE,
        "manifest",
        MAX_WARM_BUNDLE_MANIFEST_BYTES,
    )?;
    let manifest: WarmBundleManifestV1 =
        serde_json::from_slice(&manifest_bytes).map_err(WarmBundleError::CorruptManifest)?;
    validate_manifest(&manifest, expected, freshness)?;
    let snapshot = read_verified_snapshot(directory, &manifest.snapshot)?;
    let actual_counts = validate_snapshot_semantics(&snapshot, &manifest.identity)?;
    if actual_counts != manifest.view_route_counts {
        return Err(WarmBundleError::MrtIdentityMismatch {
            field: "per-view route counts",
        });
    }
    Ok(WarmBundleV1 { manifest, snapshot })
}

fn write_warm_bundle_inner(
    directory: &WarmBundleDirectory,
    identity: WarmBundleIdentityV1,
    snapshot: &[u8],
    fault: FaultPoint,
) -> Result<WarmBundleManifestV1, WarmBundleError> {
    validate_identity(&identity)?;
    let size_bytes = u64::try_from(snapshot.len()).unwrap_or(u64::MAX);
    if size_bytes > MAX_WARM_BUNDLE_SNAPSHOT_BYTES {
        return Err(WarmBundleError::FileTooLarge {
            role: "snapshot",
            actual: size_bytes,
            cap: MAX_WARM_BUNDLE_SNAPSHOT_BYTES,
        });
    }
    let view_route_counts = validate_snapshot_semantics(snapshot, &identity)?;
    let sha256 = sha256_hex(snapshot);
    let manifest = WarmBundleManifestV1 {
        format_version: WARM_BUNDLE_FORMAT_VERSION,
        identity,
        snapshot: WarmBundleArtifactV1 {
            path: snapshot_name(&sha256),
            size_bytes,
            sha256,
        },
        view_route_counts,
    };
    let mut encoded = serde_json::to_vec(&manifest).map_err(WarmBundleError::CorruptManifest)?;
    encoded.push(b'\n');
    let manifest_size = u64::try_from(encoded.len()).unwrap_or(u64::MAX);
    if manifest_size > MAX_WARM_BUNDLE_MANIFEST_BYTES {
        return Err(WarmBundleError::FileTooLarge {
            role: "manifest",
            actual: manifest_size,
            cap: MAX_WARM_BUNDLE_MANIFEST_BYTES,
        });
    }
    write_atomic_at(
        directory,
        &manifest.snapshot.path,
        snapshot,
        AtomicRole::Artifact,
        fault,
    )?;
    write_atomic_at(
        directory,
        WARM_BUNDLE_MANIFEST_FILE,
        &encoded,
        AtomicRole::Manifest,
        fault,
    )?;
    Ok(manifest)
}

fn validate_manifest(
    manifest: &WarmBundleManifestV1,
    expected: &WarmBundleExpectedV1,
    freshness: WarmBundleFreshnessV1,
) -> Result<(), WarmBundleError> {
    if manifest.format_version != WARM_BUNDLE_FORMAT_VERSION {
        return Err(WarmBundleError::UnsupportedVersion {
            found: manifest.format_version,
            expected: WARM_BUNDLE_FORMAT_VERSION,
        });
    }
    validate_identity(&manifest.identity)?;
    validate_digest("snapshot SHA-256", &manifest.snapshot.sha256)?;
    validate_snapshot_path(&manifest.snapshot)?;
    validate_view_route_counts(manifest)?;
    if manifest.snapshot.size_bytes > MAX_WARM_BUNDLE_SNAPSHOT_BYTES {
        return Err(WarmBundleError::FileTooLarge {
            role: "snapshot",
            actual: manifest.snapshot.size_bytes,
            cap: MAX_WARM_BUNDLE_SNAPSHOT_BYTES,
        });
    }
    compare_identity(&manifest.identity, expected)?;
    validate_freshness(manifest.identity.created_at_utc_seconds, freshness)
}

fn validate_identity(identity: &WarmBundleIdentityV1) -> Result<(), WarmBundleError> {
    validate_opaque(
        "checkpoint generation",
        &identity.checkpoint_generation,
        MAX_OPAQUE_GENERATION_BYTES,
    )?;
    validate_opaque(
        "PEER_INDEX_TABLE view",
        &identity.peer_index_table_view,
        MAX_PIT_VIEW_BYTES,
    )?;
    if identity.created_at_utc_seconds < 0 {
        return Err(WarmBundleError::InvalidOpaqueIdentity {
            field: "created-at UTC seconds",
        });
    }
    validate_digest("config SHA-256", &identity.config_sha256)?;
    if identity.resolved_import_policy.version != WARM_BUNDLE_POLICY_DIGEST_VERSION {
        return Err(WarmBundleError::IdentityMismatch {
            field: "resolved import-policy digest version",
        });
    }
    validate_digest(
        "resolved import-policy SHA-256",
        &identity.resolved_import_policy.sha256,
    )?;
    validate_views(&identity.views)
}

fn validate_expected(expected: &WarmBundleExpectedV1) -> Result<(), WarmBundleError> {
    validate_opaque(
        "checkpoint generation",
        &expected.checkpoint_generation,
        MAX_OPAQUE_GENERATION_BYTES,
    )?;
    validate_digest("config SHA-256", &expected.config_sha256)?;
    if expected.resolved_import_policy.version != WARM_BUNDLE_POLICY_DIGEST_VERSION {
        return Err(WarmBundleError::IdentityMismatch {
            field: "resolved import-policy digest version",
        });
    }
    validate_digest(
        "resolved import-policy SHA-256",
        &expected.resolved_import_policy.sha256,
    )?;
    validate_views(&expected.views)
}

fn validate_views(views: &[WarmBundleViewV1]) -> Result<(), WarmBundleError> {
    if views.is_empty() {
        return Err(WarmBundleError::EmptyViews);
    }
    if views.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(WarmBundleError::NonCanonicalViews);
    }
    let mut peer_families = BTreeSet::new();
    let mut peer_identities = BTreeMap::new();
    for view in views {
        // One established session has exactly one negotiated receive profile
        // for a peer/family. Add-Path therefore cannot distinguish two views.
        if !peer_families.insert((view.peer, view.family)) {
            return Err(WarmBundleError::NonCanonicalViews);
        }
        // Static neighbors are unique by transport address in the current
        // config/RIB model; ASN and router ID cannot vary by family.
        let identity = (view.peer_asn, view.peer_router_id);
        if peer_identities
            .insert(view.peer, identity)
            .is_some_and(|prior| prior != identity)
        {
            return Err(WarmBundleError::NonCanonicalViews);
        }
    }
    if views
        .iter()
        .any(|view| view.family == WarmBundleFamilyV1::L2vpnEvpn && view.add_path_receive)
    {
        return Err(WarmBundleError::UnsupportedViewProfile {
            reason: "V1 RIB_GENERIC EVPN has no Add-Path subtype",
        });
    }
    Ok(())
}

fn compare_identity(
    actual: &WarmBundleIdentityV1,
    expected: &WarmBundleExpectedV1,
) -> Result<(), WarmBundleError> {
    macro_rules! exact {
        ($field:ident, $label:literal) => {
            if actual.$field != expected.$field {
                return Err(WarmBundleError::IdentityMismatch { field: $label });
            }
        };
    }
    exact!(checkpoint_generation, "checkpoint generation");
    exact!(local_asn, "local ASN");
    exact!(local_router_id, "local router ID");
    exact!(config_sha256, "config SHA-256");
    exact!(resolved_import_policy, "resolved import-policy digest");
    exact!(views, "peer/family views");
    Ok(())
}

fn validate_freshness(
    created: i64,
    freshness: WarmBundleFreshnessV1,
) -> Result<(), WarmBundleError> {
    let future = created.saturating_sub(freshness.now_utc_seconds);
    if future > i64::try_from(freshness.max_future_skew_seconds).unwrap_or(i64::MAX) {
        return Err(WarmBundleError::FutureTimestamp);
    }
    let age = freshness.now_utc_seconds.saturating_sub(created);
    if age > i64::try_from(freshness.max_age_seconds).unwrap_or(i64::MAX) {
        return Err(WarmBundleError::Expired);
    }
    Ok(())
}

fn validate_view_route_counts(manifest: &WarmBundleManifestV1) -> Result<(), WarmBundleError> {
    if manifest.view_route_counts.len() != manifest.identity.views.len() {
        return Err(WarmBundleError::MrtIdentityMismatch {
            field: "route-count view inventory",
        });
    }
    Ok(())
}

fn validate_snapshot_semantics(
    snapshot: &[u8],
    identity: &WarmBundleIdentityV1,
) -> Result<Vec<u64>, WarmBundleError> {
    let mut reader = SnapshotReader::new(snapshot).map_err(WarmBundleError::InvalidMrt)?;
    if reader.collector_bgp_id() != identity.local_router_id {
        return Err(WarmBundleError::MrtIdentityMismatch {
            field: "collector BGP ID",
        });
    }
    if reader.view_name() != identity.peer_index_table_view {
        return Err(WarmBundleError::MrtIdentityMismatch {
            field: "PEER_INDEX_TABLE view",
        });
    }
    let expected_peers: BTreeSet<_> = identity
        .views
        .iter()
        .map(|view| (view.peer, view.peer_asn, view.peer_router_id))
        .collect();
    let actual_peers: BTreeSet<_> = reader
        .peers()
        .iter()
        .map(|peer| (peer.peer_addr, peer.peer_asn, peer.peer_bgp_id))
        .collect();
    if actual_peers.len() != reader.peers().len() || actual_peers != expected_peers {
        return Err(WarmBundleError::MrtIdentityMismatch {
            field: "peer inventory",
        });
    }
    let expected_views: BTreeSet<_> = identity.views.iter().cloned().collect();
    let mut route_counts: BTreeMap<_, u64> = identity
        .views
        .iter()
        .cloned()
        .map(|view| (view, 0))
        .collect();
    for decoded in &mut reader {
        let entry = decoded.map_err(WarmBundleError::InvalidMrt)?;
        let family = match &entry.nlri {
            SnapshotNlri::Unicast(rustbgpd_wire::Prefix::V4(_)) => WarmBundleFamilyV1::Ipv4Unicast,
            SnapshotNlri::Unicast(rustbgpd_wire::Prefix::V6(_)) => WarmBundleFamilyV1::Ipv6Unicast,
            SnapshotNlri::Generic {
                afi: 25,
                safi: 70,
                nlri,
            } => {
                let routes = rustbgpd_wire::decode_evpn_nlri(nlri)
                    .map_err(WarmBundleError::InvalidEvpnNlri)?;
                if routes.len() != 1 {
                    return Err(WarmBundleError::MrtIdentityMismatch {
                        field: "supported EVPN NLRI",
                    });
                }
                WarmBundleFamilyV1::L2vpnEvpn
            }
            SnapshotNlri::Generic { .. } => {
                return Err(WarmBundleError::MrtIdentityMismatch {
                    field: "address family",
                });
            }
        };
        if entry.link_local_next_hop.is_some() || entry.next_hop.is_some_and(is_ipv6_link_local) {
            return Err(WarmBundleError::UnsupportedViewProfile {
                reason: "V1 cannot recover a scoped or link-local next-hop identity",
            });
        }
        let view = WarmBundleViewV1 {
            kind: WarmBundleViewKindV1::AdjRibInPrePolicy,
            peer: entry.peer.peer_addr,
            peer_asn: entry.peer.peer_asn,
            peer_router_id: entry.peer.peer_bgp_id,
            family,
            add_path_receive: entry.add_path,
        };
        if !expected_views.contains(&view) {
            return Err(WarmBundleError::MrtIdentityMismatch {
                field: "peer/family/Add-Path view",
            });
        }
        let count = route_counts
            .get_mut(&view)
            .expect("membership checked against the same view inventory");
        *count = count
            .checked_add(1)
            .ok_or(WarmBundleError::MrtIdentityMismatch {
                field: "per-view route count overflow",
            })?;
    }
    if reader.skipped_records() != 0 {
        return Err(WarmBundleError::SkippedMrtRecords {
            count: reader.skipped_records(),
        });
    }
    Ok(identity
        .views
        .iter()
        .map(|view| route_counts[view])
        .collect())
}

fn is_ipv6_link_local(address: IpAddr) -> bool {
    matches!(address, IpAddr::V6(address) if address.segments()[0] & 0xffc0 == 0xfe80)
}

fn validate_snapshot_path(snapshot: &WarmBundleArtifactV1) -> Result<(), WarmBundleError> {
    if snapshot.path.contains(['/', '\\'])
        || snapshot.path == "."
        || snapshot.path == ".."
        || snapshot.path != snapshot_name(&snapshot.sha256)
    {
        return Err(WarmBundleError::InvalidSnapshotPath {
            path: snapshot.path.clone(),
        });
    }
    Ok(())
}

fn validate_opaque(field: &'static str, value: &str, max: usize) -> Result<(), WarmBundleError> {
    if value.is_empty() || value.len() > max || value.chars().any(char::is_control) {
        Err(WarmBundleError::InvalidOpaqueIdentity { field })
    } else {
        Ok(())
    }
}

fn validate_digest(field: &'static str, digest: &str) -> Result<(), WarmBundleError> {
    if digest.len() == 64
        && digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(WarmBundleError::InvalidDigest { field })
    }
}

fn snapshot_name(sha256: &str) -> String {
    format!("snapshot-{sha256}.mrt")
}

fn update_len_prefixed(digest: &mut Sha256, bytes: &[u8]) {
    digest.update(u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_be_bytes());
    digest.update(bytes);
}

fn sha256_hex(bytes: &[u8]) -> String {
    digest_hex(Sha256::digest(bytes))
}

fn digest_hex(digest: impl AsRef<[u8]>) -> String {
    let mut output = String::with_capacity(64);
    for byte in digest.as_ref() {
        use std::fmt::Write as _;
        write!(output, "{byte:02x}").expect("writing to a String cannot fail");
    }
    output
}

fn validate_owner_mode(
    file: &File,
    path: &Path,
    role: &'static str,
    directory: bool,
) -> Result<(), WarmBundleError> {
    let metadata = file.metadata().map_err(|source| io_error(path, source))?;
    if metadata.is_dir() != directory || metadata.is_file() == directory {
        return Err(WarmBundleError::UnsafeFileType {
            role,
            path: path.to_path_buf(),
        });
    }
    if metadata.uid() != geteuid().as_raw() || metadata.mode() & 0o022 != 0 {
        return Err(WarmBundleError::UnsafePermissions {
            role,
            path: path.to_path_buf(),
        });
    }
    Ok(())
}

fn open_entry(
    directory: &WarmBundleDirectory,
    name: &str,
    role: &'static str,
    flags: OFlag,
    mode: Mode,
) -> Result<File, WarmBundleError> {
    let display = directory.display_path.join(name);
    let fd = openat(
        &directory.file,
        name,
        flags | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
        mode,
    )
    .map_err(|source| nix_io(&display, source))?;
    let file = File::from(fd);
    validate_owner_mode(&file, &display, role, false)?;
    Ok(file)
}

fn read_entry_bounded(
    directory: &WarmBundleDirectory,
    name: &str,
    role: &'static str,
    cap: u64,
) -> Result<Vec<u8>, WarmBundleError> {
    let display = directory.display_path.join(name);
    let file = open_entry(directory, name, role, OFlag::O_RDONLY, Mode::empty())?;
    let len = file
        .metadata()
        .map_err(|source| io_error(&display, source))?
        .len();
    if len > cap {
        return Err(WarmBundleError::FileTooLarge {
            role,
            actual: len,
            cap,
        });
    }
    let capacity = usize::try_from(len).map_err(|_| WarmBundleError::AllocationFailed {
        role,
        requested: len,
    })?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(capacity)
        .map_err(|_| WarmBundleError::AllocationFailed {
            role,
            requested: len,
        })?;
    let mut limited = file.take(cap.saturating_add(1));
    let mut chunk = [0_u8; STREAM_BUFFER_BYTES];
    loop {
        let read = limited
            .read(&mut chunk)
            .map_err(|source| io_error(&display, source))?;
        if read == 0 {
            break;
        }
        bytes
            .try_reserve(read)
            .map_err(|_| WarmBundleError::AllocationFailed {
                role,
                requested: u64::try_from(bytes.len().saturating_add(read)).unwrap_or(u64::MAX),
            })?;
        bytes.extend_from_slice(&chunk[..read]);
    }
    let actual = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    if actual > cap {
        return Err(WarmBundleError::FileTooLarge { role, actual, cap });
    }
    Ok(bytes)
}

fn read_verified_snapshot(
    directory: &WarmBundleDirectory,
    artifact: &WarmBundleArtifactV1,
) -> Result<Vec<u8>, WarmBundleError> {
    let role = "snapshot";
    let display = directory.display_path.join(&artifact.path);
    let mut file = open_entry(
        directory,
        &artifact.path,
        role,
        OFlag::O_RDONLY,
        Mode::empty(),
    )?;
    let metadata_len = file
        .metadata()
        .map_err(|source| io_error(&display, source))?
        .len();
    if metadata_len > MAX_WARM_BUNDLE_SNAPSHOT_BYTES {
        return Err(WarmBundleError::FileTooLarge {
            role,
            actual: metadata_len,
            cap: MAX_WARM_BUNDLE_SNAPSHOT_BYTES,
        });
    }
    if metadata_len != artifact.size_bytes {
        return Err(WarmBundleError::SnapshotSizeMismatch {
            declared: artifact.size_bytes,
            actual: metadata_len,
        });
    }

    // Reject a corrupt large or sparse file before reserving its declared size.
    let (streamed_len, streamed_sha256) =
        hash_file_bounded(&mut file, &display, role, MAX_WARM_BUNDLE_SNAPSHOT_BYTES)?;
    if streamed_len != artifact.size_bytes {
        return Err(WarmBundleError::SnapshotSizeMismatch {
            declared: artifact.size_bytes,
            actual: streamed_len,
        });
    }
    if streamed_sha256 != artifact.sha256 {
        return Err(WarmBundleError::SnapshotHashMismatch);
    }

    file.seek(SeekFrom::Start(0))
        .map_err(|source| io_error(&display, source))?;
    let snapshot = read_open_file_bounded(
        file,
        &display,
        role,
        MAX_WARM_BUNDLE_SNAPSHOT_BYTES,
        artifact.size_bytes,
    )?;
    let actual = u64::try_from(snapshot.len()).unwrap_or(u64::MAX);
    if actual != artifact.size_bytes {
        return Err(WarmBundleError::SnapshotSizeMismatch {
            declared: artifact.size_bytes,
            actual,
        });
    }
    // Recheck after the second pass so an in-place same-UID mutation between
    // hash and read cannot substitute different bytes on the pinned file.
    if sha256_hex(&snapshot) != artifact.sha256 {
        return Err(WarmBundleError::SnapshotHashMismatch);
    }
    Ok(snapshot)
}

fn hash_file_bounded(
    file: &mut File,
    display: &Path,
    role: &'static str,
    cap: u64,
) -> Result<(u64, String), WarmBundleError> {
    let mut digest = Sha256::new();
    let mut total = 0_u64;
    let mut chunk = [0_u8; STREAM_BUFFER_BYTES];
    loop {
        let read = file
            .read(&mut chunk)
            .map_err(|source| io_error(display, source))?;
        if read == 0 {
            break;
        }
        total = total.saturating_add(u64::try_from(read).unwrap_or(u64::MAX));
        if total > cap {
            return Err(WarmBundleError::FileTooLarge {
                role,
                actual: total,
                cap,
            });
        }
        digest.update(&chunk[..read]);
    }
    Ok((total, digest_hex(digest.finalize())))
}

fn read_open_file_bounded(
    file: File,
    display: &Path,
    role: &'static str,
    cap: u64,
    expected_len: u64,
) -> Result<Vec<u8>, WarmBundleError> {
    let capacity =
        usize::try_from(expected_len).map_err(|_| WarmBundleError::AllocationFailed {
            role,
            requested: expected_len,
        })?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(capacity)
        .map_err(|_| WarmBundleError::AllocationFailed {
            role,
            requested: expected_len,
        })?;
    let mut limited = file.take(cap.saturating_add(1));
    let mut chunk = [0_u8; STREAM_BUFFER_BYTES];
    loop {
        let read = limited
            .read(&mut chunk)
            .map_err(|source| io_error(display, source))?;
        if read == 0 {
            break;
        }
        bytes
            .try_reserve(read)
            .map_err(|_| WarmBundleError::AllocationFailed {
                role,
                requested: u64::try_from(bytes.len().saturating_add(read)).unwrap_or(u64::MAX),
            })?;
        bytes.extend_from_slice(&chunk[..read]);
    }
    let actual = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    if actual > cap {
        return Err(WarmBundleError::FileTooLarge { role, actual, cap });
    }
    Ok(bytes)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AtomicRole {
    Artifact,
    Manifest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FaultPoint {
    None,
    ArtifactWrite,
    ArtifactFileSync,
    ArtifactRename,
    ArtifactDirSync,
    ManifestWrite,
    ManifestFileSync,
    ManifestRename,
    ManifestDirSync,
}

fn stage(role: AtomicRole, ordinal: u8) -> FaultPoint {
    match (role, ordinal) {
        (AtomicRole::Artifact, 0) => FaultPoint::ArtifactWrite,
        (AtomicRole::Artifact, 1) => FaultPoint::ArtifactFileSync,
        (AtomicRole::Artifact, 2) => FaultPoint::ArtifactRename,
        (AtomicRole::Artifact, _) => FaultPoint::ArtifactDirSync,
        (AtomicRole::Manifest, 0) => FaultPoint::ManifestWrite,
        (AtomicRole::Manifest, 1) => FaultPoint::ManifestFileSync,
        (AtomicRole::Manifest, 2) => FaultPoint::ManifestRename,
        (AtomicRole::Manifest, _) => FaultPoint::ManifestDirSync,
    }
}

fn fail_if(selected: FaultPoint, current: FaultPoint) -> io::Result<()> {
    if selected == current {
        Err(io::Error::other(format!("injected failure at {current:?}")))
    } else {
        Ok(())
    }
}

fn write_atomic_at(
    directory: &WarmBundleDirectory,
    name: &str,
    bytes: &[u8],
    role: AtomicRole,
    fault: FaultPoint,
) -> Result<(), WarmBundleError> {
    let display = directory.display_path.join(name);
    let (temp_name, mut file) = create_temp(directory, name)?;
    let result = (|| -> io::Result<()> {
        fail_if(fault, stage(role, 0))?;
        file.write_all(bytes)?;
        fail_if(fault, stage(role, 1))?;
        file.sync_all()?;
        drop(file);
        fail_if(fault, stage(role, 2))?;
        renameat(&directory.file, temp_name.as_str(), &directory.file, name).map_err(errno_io)?;
        fail_if(fault, stage(role, 3))?;
        directory.file.sync_all()
    })();
    if result.is_err() {
        let _ = unlinkat(
            &directory.file,
            temp_name.as_str(),
            UnlinkatFlags::NoRemoveDir,
        );
    }
    result.map_err(|source| io_error(&display, source))
}

fn create_temp(
    directory: &WarmBundleDirectory,
    name: &str,
) -> Result<(String, File), WarmBundleError> {
    for _ in 0..128 {
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let temp = format!(".{name}.tmp.{}.{}", std::process::id(), sequence);
        match open_entry(
            directory,
            &temp,
            "temporary file",
            OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_EXCL,
            Mode::from_bits_truncate(0o600),
        ) {
            Ok(file) => return Ok((temp, file)),
            Err(WarmBundleError::Io { source, .. })
                if source.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error),
        }
    }
    Err(io_error(
        &directory.display_path,
        io::Error::new(
            io::ErrorKind::AlreadyExists,
            "could not allocate an unused atomic temp entry",
        ),
    ))
}

fn errno_io(error: nix::errno::Errno) -> io::Error {
    io::Error::from_raw_os_error(error as i32)
}

fn nix_io(path: &Path, error: nix::errno::Errno) -> WarmBundleError {
    io_error(path, errno_io(error))
}

fn io_error(path: &Path, source: io::Error) -> WarmBundleError {
    WarmBundleError::Io {
        path: path.to_path_buf(),
        source,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::fs::OpenOptions;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::os::unix::fs::{PermissionsExt as _, symlink};

    const SHA: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const NOW: i64 = 1_800_000_000;

    fn v4_view(peer: u8, add_path: bool) -> WarmBundleViewV1 {
        WarmBundleViewV1 {
            kind: WarmBundleViewKindV1::AdjRibInPrePolicy,
            peer: IpAddr::V4(Ipv4Addr::new(192, 0, 2, peer)),
            peer_asn: 64_500 + u32::from(peer),
            peer_router_id: Ipv4Addr::new(10, 0, 0, peer),
            family: WarmBundleFamilyV1::Ipv4Unicast,
            add_path_receive: add_path,
        }
    }

    fn v6_view(peer: u8, add_path: bool) -> WarmBundleViewV1 {
        WarmBundleViewV1 {
            family: WarmBundleFamilyV1::Ipv6Unicast,
            ..v4_view(peer, add_path)
        }
    }

    fn identity_with(mut views: Vec<WarmBundleViewV1>) -> WarmBundleIdentityV1 {
        views.sort();
        WarmBundleIdentityV1 {
            checkpoint_generation: "boot-41".to_string(),
            created_at_utc_seconds: NOW,
            snapshot_revision: 41,
            local_asn: 64_500,
            local_router_id: Ipv4Addr::new(10, 255, 0, 1),
            peer_index_table_view: "warm-generation-41".to_string(),
            config_sha256: SHA.to_string(),
            resolved_import_policy: WarmBundlePolicyDigestV1 {
                version: WARM_BUNDLE_POLICY_DIGEST_VERSION,
                sha256: SHA.to_string(),
            },
            views,
        }
    }

    fn identity() -> WarmBundleIdentityV1 {
        identity_with(vec![v4_view(1, false), v6_view(2, true)])
    }

    fn expected(identity: &WarmBundleIdentityV1) -> WarmBundleExpectedV1 {
        WarmBundleExpectedV1 {
            checkpoint_generation: identity.checkpoint_generation.clone(),
            local_asn: identity.local_asn,
            local_router_id: identity.local_router_id,
            config_sha256: identity.config_sha256.clone(),
            resolved_import_policy: identity.resolved_import_policy.clone(),
            views: identity.views.clone(),
        }
    }

    fn freshness() -> WarmBundleFreshnessV1 {
        WarmBundleFreshnessV1 {
            now_utc_seconds: NOW + 10,
            max_age_seconds: 60,
            max_future_skew_seconds: 5,
        }
    }

    fn opened(dir: &tempfile::TempDir) -> WarmBundleDirectory {
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        WarmBundleDirectory::open(dir.path()).unwrap()
    }

    fn record(output: &mut Vec<u8>, subtype: u16, payload: &[u8]) {
        output.extend_from_slice(&u32::try_from(NOW).unwrap().to_be_bytes());
        output.extend_from_slice(&13_u16.to_be_bytes());
        output.extend_from_slice(&subtype.to_be_bytes());
        output.extend_from_slice(&u32::try_from(payload.len()).unwrap().to_be_bytes());
        output.extend_from_slice(payload);
    }

    fn valid_snapshot(identity: &WarmBundleIdentityV1) -> Vec<u8> {
        let peers: Vec<_> = identity
            .views
            .iter()
            .map(|view| (view.peer, view.peer_asn, view.peer_router_id))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let mut pit = Vec::new();
        pit.extend_from_slice(&identity.local_router_id.octets());
        pit.extend_from_slice(
            &u16::try_from(identity.peer_index_table_view.len())
                .unwrap()
                .to_be_bytes(),
        );
        pit.extend_from_slice(identity.peer_index_table_view.as_bytes());
        pit.extend_from_slice(&u16::try_from(peers.len()).unwrap().to_be_bytes());
        for (peer, asn, router_id) in &peers {
            let peer_type = if peer.is_ipv6() { 3_u8 } else { 2_u8 };
            pit.push(peer_type);
            pit.extend_from_slice(&router_id.octets());
            match peer {
                IpAddr::V4(addr) => pit.extend_from_slice(&addr.octets()),
                IpAddr::V6(addr) => pit.extend_from_slice(&addr.octets()),
            }
            pit.extend_from_slice(&asn.to_be_bytes());
        }
        let mut output = Vec::new();
        record(&mut output, 1, &pit);
        for (sequence, view) in identity.views.iter().enumerate() {
            let peer_index =
                u16::try_from(peers.iter().position(|peer| peer.0 == view.peer).unwrap()).unwrap();
            let mut payload = Vec::new();
            payload.extend_from_slice(&u32::try_from(sequence).unwrap().to_be_bytes());
            let subtype = match view.family {
                WarmBundleFamilyV1::Ipv4Unicast => {
                    payload.push(24);
                    payload.extend_from_slice(&[203, 0, u8::try_from(sequence % 256).unwrap()]);
                    if view.add_path_receive { 8 } else { 2 }
                }
                WarmBundleFamilyV1::Ipv6Unicast => {
                    payload.push(48);
                    payload.extend_from_slice(&Ipv6Addr::LOCALHOST.octets()[..6]);
                    if view.add_path_receive { 9 } else { 4 }
                }
                WarmBundleFamilyV1::L2vpnEvpn => {
                    payload.extend_from_slice(&25_u16.to_be_bytes());
                    payload.push(70);
                    // Valid Type 3 IMET: RD(8), Ethernet Tag(4), IPv4 length,
                    // and originator address.
                    payload.extend_from_slice(&[3, 17]);
                    payload.extend_from_slice(&[0; 12]);
                    payload.push(32);
                    payload.extend_from_slice(&[192, 0, 2, 1]);
                    6
                }
            };
            payload.extend_from_slice(&1_u16.to_be_bytes());
            if view.add_path_receive {
                payload.extend_from_slice(&u32::try_from(sequence + 1).unwrap().to_be_bytes());
            }
            payload.extend_from_slice(&peer_index.to_be_bytes());
            payload.extend_from_slice(&u32::try_from(NOW).unwrap().to_be_bytes());
            payload.extend_from_slice(&0_u16.to_be_bytes());
            record(&mut output, subtype, &payload);
        }
        output
    }

    fn last_record_offset(snapshot: &[u8]) -> usize {
        let mut offset = 0;
        let mut last = 0;
        while offset < snapshot.len() {
            last = offset;
            let payload_len =
                u32::from_be_bytes(snapshot[offset + 8..offset + 12].try_into().unwrap());
            offset += 12 + usize::try_from(payload_len).unwrap();
        }
        assert_eq!(offset, snapshot.len());
        last
    }

    fn without_last_record(mut snapshot: Vec<u8>) -> Vec<u8> {
        let last = last_record_offset(&snapshot);
        snapshot.truncate(last);
        snapshot
    }

    fn with_unscoped_link_local_next_hop(mut snapshot: Vec<u8>) -> Vec<u8> {
        let record_offset = last_record_offset(&snapshot);
        let payload_len = u32::from_be_bytes(
            snapshot[record_offset + 8..record_offset + 12]
                .try_into()
                .unwrap(),
        );
        let mut attributes = vec![0x80, 14, 17, 16];
        attributes.extend_from_slice(&"fe80::1".parse::<Ipv6Addr>().unwrap().octets());
        let attr_len_offset = snapshot.len() - 2;
        snapshot[attr_len_offset..]
            .copy_from_slice(&u16::try_from(attributes.len()).unwrap().to_be_bytes());
        snapshot[record_offset + 8..record_offset + 12].copy_from_slice(
            &(payload_len + u32::try_from(attributes.len()).unwrap()).to_be_bytes(),
        );
        snapshot.extend_from_slice(&attributes);
        snapshot
    }

    fn with_invalid_pit_utf8(identity: &WarmBundleIdentityV1) -> (WarmBundleIdentityV1, Vec<u8>) {
        let mut invalid_identity = identity.clone();
        let suffix = invalid_identity.peer_index_table_view[1..].to_string();
        invalid_identity.peer_index_table_view = format!("\u{fffd}{suffix}");
        let mut snapshot = valid_snapshot(identity);
        // Common header (12) + collector ID (4) + view length (2).
        snapshot[18] = 0xff;
        (invalid_identity, snapshot)
    }

    fn install_raw_bundle(
        temp: &tempfile::TempDir,
        identity: WarmBundleIdentityV1,
        snapshot: &[u8],
        view_route_counts: Vec<u64>,
    ) {
        let sha256 = sha256_hex(snapshot);
        let artifact = WarmBundleArtifactV1 {
            path: snapshot_name(&sha256),
            size_bytes: u64::try_from(snapshot.len()).unwrap(),
            sha256,
        };
        let artifact_path = temp.path().join(&artifact.path);
        fs::write(&artifact_path, snapshot).unwrap();
        fs::set_permissions(&artifact_path, fs::Permissions::from_mode(0o600)).unwrap();
        let manifest = WarmBundleManifestV1 {
            format_version: WARM_BUNDLE_FORMAT_VERSION,
            identity,
            snapshot: artifact,
            view_route_counts,
        };
        let manifest_path = temp.path().join(WARM_BUNDLE_MANIFEST_FILE);
        fs::write(&manifest_path, serde_json::to_vec(&manifest).unwrap()).unwrap();
        fs::set_permissions(&manifest_path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    fn publish(dir: &WarmBundleDirectory, identity: &WarmBundleIdentityV1) {
        write_warm_bundle(dir, identity.clone(), &valid_snapshot(identity)).unwrap();
    }

    fn rewrite_manifest(temp: &tempfile::TempDir, mutate: impl FnOnce(&mut WarmBundleManifestV1)) {
        let path = temp.path().join(WARM_BUNDLE_MANIFEST_FILE);
        let mut manifest: WarmBundleManifestV1 =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        mutate(&mut manifest);
        fs::write(path, serde_json::to_vec(&manifest).unwrap()).unwrap();
    }

    #[test]
    fn roundtrip_drains_and_semantically_validates_mrt() {
        let temp = tempfile::tempdir().unwrap();
        let dir = opened(&temp);
        let id = identity();
        publish(&dir, &id);
        let loaded = load_warm_bundle(&dir, &expected(&id), freshness()).unwrap();
        assert_eq!(loaded.manifest.identity, id);
        assert_eq!(loaded.snapshot, valid_snapshot(&id));
    }

    #[test]
    fn public_write_and_load_reject_invalid_pit_utf8() {
        let temp = tempfile::tempdir().unwrap();
        let dir = opened(&temp);
        let (invalid_identity, invalid_snapshot) = with_invalid_pit_utf8(&identity());
        assert!(matches!(
            write_warm_bundle(&dir, invalid_identity.clone(), &invalid_snapshot),
            Err(WarmBundleError::InvalidMrt(ReadError::Malformed { .. }))
        ));

        install_raw_bundle(
            &temp,
            invalid_identity.clone(),
            &invalid_snapshot,
            vec![1, 1],
        );
        let error = load_warm_bundle(&dir, &expected(&invalid_identity), freshness()).unwrap_err();
        assert!(
            matches!(
                error,
                WarmBundleError::InvalidMrt(ReadError::Malformed { .. })
            ),
            "{error:?}"
        );
    }

    #[test]
    fn public_write_and_load_reject_impossible_view_profiles() {
        let temp = tempfile::tempdir().unwrap();
        let dir = opened(&temp);
        let valid = identity();
        let valid_snapshot = valid_snapshot(&valid);

        let mut dual_add_path = valid.clone();
        let mut conflicting = dual_add_path.views[0].clone();
        conflicting.add_path_receive = !conflicting.add_path_receive;
        dual_add_path.views.push(conflicting);
        dual_add_path.views.sort();
        assert!(matches!(
            write_warm_bundle(&dir, dual_add_path, &valid_snapshot),
            Err(WarmBundleError::NonCanonicalViews)
        ));

        publish(&dir, &valid);
        rewrite_manifest(&temp, |manifest| {
            let mut conflicting = manifest.identity.views[0].clone();
            conflicting.add_path_receive = !conflicting.add_path_receive;
            manifest.identity.views.push(conflicting);
            manifest.identity.views.sort();
            manifest.view_route_counts.push(0);
        });
        assert!(matches!(
            load_warm_bundle(&dir, &expected(&valid), freshness()),
            Err(WarmBundleError::NonCanonicalViews)
        ));

        let mut inconsistent_peer = valid;
        inconsistent_peer.views[1].peer = inconsistent_peer.views[0].peer;
        inconsistent_peer.views[1].peer_asn += 1;
        inconsistent_peer.views.sort();
        assert!(matches!(
            write_warm_bundle(&dir, inconsistent_peer, &valid_snapshot),
            Err(WarmBundleError::NonCanonicalViews)
        ));
    }

    #[test]
    fn explicit_zero_route_view_roundtrips_and_count_tampering_fails() {
        let temp = tempfile::tempdir().unwrap();
        let dir = opened(&temp);
        let id = identity_with(vec![v4_view(1, false), v6_view(1, true)]);
        let snapshot = without_last_record(valid_snapshot(&id));
        let manifest = write_warm_bundle(&dir, id.clone(), &snapshot).unwrap();
        assert_eq!(manifest.view_route_counts.len(), 2);
        assert_eq!(manifest.view_route_counts[0], 1);
        assert_eq!(manifest.view_route_counts[1], 0);
        assert!(load_warm_bundle(&dir, &expected(&id), freshness()).is_ok());

        rewrite_manifest(&temp, |manifest| {
            manifest.view_route_counts[1] = 1;
        });
        assert!(matches!(
            load_warm_bundle(&dir, &expected(&id), freshness()),
            Err(WarmBundleError::MrtIdentityMismatch {
                field: "per-view route counts"
            })
        ));
    }

    #[test]
    fn malformed_evpn_and_unscoped_link_local_next_hops_are_rejected() {
        let temp = tempfile::tempdir().unwrap();
        let dir = opened(&temp);

        let evpn_id = identity_with(vec![WarmBundleViewV1 {
            family: WarmBundleFamilyV1::L2vpnEvpn,
            ..v4_view(1, false)
        }]);
        let valid_evpn = valid_snapshot(&evpn_id);
        assert!(write_warm_bundle(&dir, evpn_id.clone(), &valid_evpn).is_ok());
        let mut malformed_evpn = valid_evpn;
        let record_offset = last_record_offset(&malformed_evpn);
        // Replace valid Type 3 with Type 2 while retaining the 17-byte body;
        // Type 2 requires at least 25 bytes and must fail semantic decoding.
        malformed_evpn[record_offset + 12 + 7] = 2;
        assert!(matches!(
            write_warm_bundle(&dir, evpn_id, &malformed_evpn),
            Err(WarmBundleError::InvalidEvpnNlri(_))
        ));

        let v6_id = identity_with(vec![v6_view(1, false)]);
        let link_local = with_unscoped_link_local_next_hop(valid_snapshot(&v6_id));
        assert!(matches!(
            write_warm_bundle(&dir, v6_id, &link_local),
            Err(WarmBundleError::UnsupportedViewProfile { .. })
        ));
    }

    #[test]
    fn policy_digest_is_versioned_deterministic_and_order_sensitive() {
        let inputs = vec![
            WarmBundlePolicyInputV1 {
                view: v4_view(1, false),
                canonical_policy: b"permit prefix 192.0.2.0/24".to_vec(),
            },
            WarmBundlePolicyInputV1 {
                view: v6_view(2, true),
                canonical_policy: b"deny default".to_vec(),
            },
        ];
        let first = resolved_import_policy_digest_v1(&inputs).unwrap();
        assert_eq!(first, resolved_import_policy_digest_v1(&inputs).unwrap());
        assert_eq!(first.version, WARM_BUNDLE_POLICY_DIGEST_VERSION);
        let mut reversed = inputs;
        reversed.reverse();
        assert!(matches!(
            resolved_import_policy_digest_v1(&reversed),
            Err(WarmBundleError::NonCanonicalPolicyInputs)
        ));
    }

    #[test]
    fn identity_and_freshness_mismatches_fail_closed() {
        let temp = tempfile::tempdir().unwrap();
        let dir = opened(&temp);
        let id = identity();
        publish(&dir, &id);
        let mut wrong = expected(&id);
        wrong.local_asn += 1;
        assert!(matches!(
            load_warm_bundle(&dir, &wrong, freshness()),
            Err(WarmBundleError::IdentityMismatch { field: "local ASN" })
        ));
        assert!(matches!(
            load_warm_bundle(
                &dir,
                &expected(&id),
                WarmBundleFreshnessV1 {
                    now_utc_seconds: NOW + 61,
                    ..freshness()
                }
            ),
            Err(WarmBundleError::Expired)
        ));
        assert!(matches!(
            load_warm_bundle(
                &dir,
                &expected(&id),
                WarmBundleFreshnessV1 {
                    now_utc_seconds: NOW - 6,
                    ..freshness()
                }
            ),
            Err(WarmBundleError::FutureTimestamp)
        ));
    }

    #[test]
    fn independently_derived_identity_components_compare_exactly() {
        let actual = identity();
        let base = expected(&actual);
        let mut cases: Vec<(WarmBundleExpectedV1, &'static str)> = Vec::new();
        let mut changed = base.clone();
        changed.checkpoint_generation.push_str("-other");
        cases.push((changed, "checkpoint generation"));
        let mut changed = base.clone();
        changed.local_asn += 1;
        cases.push((changed, "local ASN"));
        let mut changed = base.clone();
        changed.local_router_id = Ipv4Addr::new(10, 255, 0, 2);
        cases.push((changed, "local router ID"));
        let mut changed = base.clone();
        changed.config_sha256 = "f".repeat(64);
        cases.push((changed, "config SHA-256"));
        let mut changed = base.clone();
        changed.resolved_import_policy.sha256 = "f".repeat(64);
        cases.push((changed, "resolved import-policy digest"));
        let mut changed = base.clone();
        changed.views[0].add_path_receive = !changed.views[0].add_path_receive;
        changed.views.sort();
        cases.push((changed, "peer/family views"));

        for (expected, field) in cases {
            assert!(matches!(
                compare_identity(&actual, &expected),
                Err(WarmBundleError::IdentityMismatch { field: found }) if found == field
            ));
        }

        let mut manifest_authored = actual;
        manifest_authored.created_at_utc_seconds += 1;
        manifest_authored.snapshot_revision += 1;
        manifest_authored.peer_index_table_view.push_str("-other");
        assert!(compare_identity(&manifest_authored, &base).is_ok());
    }

    #[test]
    fn load_uses_marker_and_current_contract_without_copying_manifest_metadata() {
        let temp = tempfile::tempdir().unwrap();
        let dir = opened(&temp);
        let baseline = identity();
        let current = expected(&baseline);
        let mut authored = baseline;
        authored.created_at_utc_seconds = NOW - 5;
        authored.snapshot_revision = 7_003;
        authored.peer_index_table_view = "writer-owned-pit-generation".to_string();
        publish(&dir, &authored);
        assert!(load_warm_bundle(&dir, &current, freshness()).is_ok());
    }

    #[test]
    fn malformed_manifest_version_path_size_and_digest_fail_closed() {
        let temp = tempfile::tempdir().unwrap();
        let dir = opened(&temp);
        let id = identity();
        publish(&dir, &id);
        let path = temp.path().join(WARM_BUNDLE_MANIFEST_FILE);
        fs::write(&path, br#"{"format_version":1,"unknown":true}"#).unwrap();
        assert!(matches!(
            load_warm_bundle(&dir, &expected(&id), freshness()),
            Err(WarmBundleError::CorruptManifest(_))
        ));

        publish(&dir, &id);
        rewrite_manifest(&temp, |manifest| manifest.format_version = 2);
        assert!(matches!(
            load_warm_bundle(&dir, &expected(&id), freshness()),
            Err(WarmBundleError::UnsupportedVersion { found: 2, .. })
        ));

        publish(&dir, &id);
        rewrite_manifest(&temp, |manifest| {
            manifest.view_route_counts.pop();
        });
        assert!(matches!(
            load_warm_bundle(&dir, &expected(&id), freshness()),
            Err(WarmBundleError::MrtIdentityMismatch {
                field: "route-count view inventory"
            })
        ));

        publish(&dir, &id);
        rewrite_manifest(&temp, |manifest| {
            manifest.snapshot.path = "../outside.mrt".to_string();
        });
        assert!(matches!(
            load_warm_bundle(&dir, &expected(&id), freshness()),
            Err(WarmBundleError::InvalidSnapshotPath { .. })
        ));

        publish(&dir, &id);
        rewrite_manifest(&temp, |manifest| manifest.snapshot.size_bytes += 1);
        assert!(matches!(
            load_warm_bundle(&dir, &expected(&id), freshness()),
            Err(WarmBundleError::SnapshotSizeMismatch { .. })
        ));

        publish(&dir, &id);
        let manifest: WarmBundleManifestV1 =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        let artifact = temp.path().join(manifest.snapshot.path);
        let mut bytes = fs::read(&artifact).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        fs::write(artifact, bytes).unwrap();
        assert!(matches!(
            load_warm_bundle(&dir, &expected(&id), freshness()),
            Err(WarmBundleError::SnapshotHashMismatch)
        ));
    }

    #[test]
    fn invalid_identity_and_hard_read_caps_fail_before_adoption() {
        let temp = tempfile::tempdir().unwrap();
        let dir = opened(&temp);
        let id = identity();
        let snapshot = valid_snapshot(&id);
        let mut empty = id.clone();
        empty.views.clear();
        assert!(matches!(
            write_warm_bundle(&dir, empty, &snapshot),
            Err(WarmBundleError::EmptyViews)
        ));
        let mut unsorted = id.clone();
        unsorted.views.reverse();
        assert!(matches!(
            write_warm_bundle(&dir, unsorted, &snapshot),
            Err(WarmBundleError::NonCanonicalViews)
        ));

        publish(&dir, &id);
        let manifest: WarmBundleManifestV1 =
            serde_json::from_slice(&fs::read(temp.path().join(WARM_BUNDLE_MANIFEST_FILE)).unwrap())
                .unwrap();
        let artifact = temp.path().join(manifest.snapshot.path);
        OpenOptions::new()
            .write(true)
            .open(artifact)
            .unwrap()
            .set_len(MAX_WARM_BUNDLE_SNAPSHOT_BYTES + 1)
            .unwrap();
        assert!(matches!(
            load_warm_bundle(&dir, &expected(&id), freshness()),
            Err(WarmBundleError::FileTooLarge {
                role: "snapshot",
                ..
            })
        ));
    }

    #[test]
    fn impossible_snapshot_reservation_is_a_typed_cold_boot_error() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("empty");
        fs::write(&path, []).unwrap();
        let file = File::open(&path).unwrap();
        assert!(matches!(
            read_open_file_bounded(file, &path, "snapshot", u64::MAX, u64::MAX),
            Err(WarmBundleError::AllocationFailed {
                role: "snapshot",
                requested: u64::MAX
            })
        ));
    }

    #[test]
    fn malformed_skipped_incomplete_and_wrong_semantics_are_rejected() {
        let temp = tempfile::tempdir().unwrap();
        let dir = opened(&temp);
        let id = identity();
        for snapshot in [vec![0_u8; 3], valid_snapshot(&id)[..20].to_vec()] {
            assert!(matches!(
                write_warm_bundle(&dir, id.clone(), &snapshot),
                Err(WarmBundleError::InvalidMrt(_))
            ));
        }
        let mut skipped = valid_snapshot(&id);
        let mut unknown = Vec::new();
        record(&mut unknown, 99, &[]);
        skipped.extend_from_slice(&unknown);
        assert!(matches!(
            write_warm_bundle(&dir, id.clone(), &skipped),
            Err(WarmBundleError::SkippedMrtRecords { .. })
        ));
        let mut wrong_addpath = id.clone();
        wrong_addpath.views[0].add_path_receive = true;
        wrong_addpath.views.sort();
        assert!(matches!(
            write_warm_bundle(&dir, wrong_addpath, &valid_snapshot(&id)),
            Err(WarmBundleError::MrtIdentityMismatch { .. })
        ));

        let mut wrong_collector = id.clone();
        wrong_collector.local_router_id = Ipv4Addr::new(10, 255, 0, 2);
        assert!(matches!(
            write_warm_bundle(&dir, wrong_collector, &valid_snapshot(&id)),
            Err(WarmBundleError::MrtIdentityMismatch {
                field: "collector BGP ID"
            })
        ));
        let mut wrong_pit_view = id.clone();
        wrong_pit_view.peer_index_table_view.push_str("-other");
        assert!(matches!(
            write_warm_bundle(&dir, wrong_pit_view, &valid_snapshot(&id)),
            Err(WarmBundleError::MrtIdentityMismatch {
                field: "PEER_INDEX_TABLE view"
            })
        ));
        let mut wrong_peer = id.clone();
        wrong_peer.views[0].peer_asn += 1;
        wrong_peer.views.sort();
        assert!(matches!(
            write_warm_bundle(&dir, wrong_peer, &valid_snapshot(&id)),
            Err(WarmBundleError::MrtIdentityMismatch {
                field: "peer inventory"
            })
        ));
        let mut wrong_family = id.clone();
        wrong_family.views[0].family = WarmBundleFamilyV1::L2vpnEvpn;
        wrong_family.views.sort();
        assert!(matches!(
            write_warm_bundle(&dir, wrong_family, &valid_snapshot(&id)),
            Err(WarmBundleError::MrtIdentityMismatch { .. })
        ));
    }

    #[test]
    fn every_atomic_failure_has_an_old_or_complete_commit_point() {
        for fault in [
            FaultPoint::ArtifactWrite,
            FaultPoint::ArtifactFileSync,
            FaultPoint::ArtifactRename,
            FaultPoint::ArtifactDirSync,
            FaultPoint::ManifestWrite,
            FaultPoint::ManifestFileSync,
            FaultPoint::ManifestRename,
            FaultPoint::ManifestDirSync,
        ] {
            let temp = tempfile::tempdir().unwrap();
            let dir = opened(&temp);
            let old = identity();
            publish(&dir, &old);
            let mut next = old.clone();
            next.checkpoint_generation = "boot-42".to_string();
            next.snapshot_revision += 1;
            next.created_at_utc_seconds += 1;
            let result = write_warm_bundle_inner(&dir, next.clone(), &valid_snapshot(&next), fault);
            assert!(result.is_err(), "{fault:?}");
            if fault == FaultPoint::ManifestDirSync {
                assert!(load_warm_bundle(&dir, &expected(&next), freshness()).is_ok());
            } else {
                assert!(
                    load_warm_bundle(&dir, &expected(&old), freshness()).is_ok(),
                    "{fault:?}"
                );
            }
        }
    }

    #[test]
    fn directory_symlinks_permissions_and_path_replacement_fail_closed() {
        let root = tempfile::tempdir().unwrap();
        let real = root.path().join("real");
        fs::create_dir(&real).unwrap();
        let link = root.path().join("link");
        symlink(&real, &link).unwrap();
        assert!(WarmBundleDirectory::open(&link).is_err());

        fs::set_permissions(&real, fs::Permissions::from_mode(0o777)).unwrap();
        assert!(matches!(
            WarmBundleDirectory::open(&real),
            Err(WarmBundleError::UnsafePermissions {
                role: "directory",
                ..
            })
        ));
        fs::set_permissions(&real, fs::Permissions::from_mode(0o700)).unwrap();
        let dir = WarmBundleDirectory::open(&real).unwrap();
        let moved = root.path().join("moved");
        fs::rename(&real, &moved).unwrap();
        let attacker = root.path().join("attacker");
        fs::create_dir(&attacker).unwrap();
        symlink(&attacker, &real).unwrap();
        let id = identity();
        publish(&dir, &id);
        assert!(moved.join(WARM_BUNDLE_MANIFEST_FILE).is_file());
        assert!(!attacker.join(WARM_BUNDLE_MANIFEST_FILE).exists());
    }

    #[test]
    fn artifact_and_manifest_symlinks_or_unsafe_modes_are_rejected() {
        let temp = tempfile::tempdir().unwrap();
        let dir = opened(&temp);
        let id = identity();
        publish(&dir, &id);
        let manifest_path = temp.path().join(WARM_BUNDLE_MANIFEST_FILE);
        fs::set_permissions(&manifest_path, fs::Permissions::from_mode(0o666)).unwrap();
        assert!(matches!(
            load_warm_bundle(&dir, &expected(&id), freshness()),
            Err(WarmBundleError::UnsafePermissions {
                role: "manifest",
                ..
            })
        ));
        fs::remove_file(&manifest_path).unwrap();
        symlink("outside", &manifest_path).unwrap();
        assert!(load_warm_bundle(&dir, &expected(&id), freshness()).is_err());

        fs::remove_file(&manifest_path).unwrap();
        publish(&dir, &id);
        let manifest: WarmBundleManifestV1 =
            serde_json::from_slice(&fs::read(&manifest_path).unwrap()).unwrap();
        let artifact_path = temp.path().join(manifest.snapshot.path);
        fs::remove_file(&artifact_path).unwrap();
        fs::write(temp.path().join("outside"), b"not the snapshot").unwrap();
        symlink("outside", &artifact_path).unwrap();
        assert!(load_warm_bundle(&dir, &expected(&id), freshness()).is_err());
    }

    #[test]
    fn compact_manifest_handles_256_peer_dual_stack_inventory() {
        let mut views = Vec::new();
        for peer in 0_u16..256 {
            let octet = u8::try_from(peer % 254 + 1).unwrap();
            let subnet = u8::try_from(peer / 254).unwrap();
            let mut v4 = v4_view(octet, peer % 2 == 0);
            v4.peer = IpAddr::V4(Ipv4Addr::new(192, 0, subnet, octet));
            v4.peer_asn = 65_000 + u32::from(peer);
            v4.peer_router_id = Ipv4Addr::new(10, 0, subnet, octet);
            let mut v6 = v4.clone();
            v6.family = WarmBundleFamilyV1::Ipv6Unicast;
            views.extend([v4, v6]);
        }
        let id = identity_with(views);
        let temp = tempfile::tempdir().unwrap();
        let dir = opened(&temp);
        let manifest = write_warm_bundle(&dir, id.clone(), &valid_snapshot(&id)).unwrap();
        let bytes = fs::read(temp.path().join(WARM_BUNDLE_MANIFEST_FILE)).unwrap();
        assert!(bytes.len() < 256 * 1024, "{}", bytes.len());
        assert_eq!(manifest.identity.views.len(), 512);
        assert!(load_warm_bundle(&dir, &expected(&id), freshness()).is_ok());
    }
}
