//! rustbgpd-mrt — MRT dump export (RFC 6396)
//!
//! Periodic `TABLE_DUMP_V2` RIB snapshots to local files.

#![deny(unsafe_code)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]

/// MRT `TABLE_DUMP_V2` encoding (RFC 6396).
pub mod codec;
/// MRT dump manager: periodic + on-demand RIB snapshots.
pub mod manager;
/// MRT `TABLE_DUMP_V2` reader (RFC 6396).
pub mod reader;
/// Configuration and re-exported types.
pub mod types;
/// Durable, fail-closed warm-checkpoint bundle storage.
pub mod warm_bundle;
/// Atomic file writer with optional gzip compression.
pub mod writer;

pub use manager::MrtManager;
pub use reader::{ReadError, SnapshotEntry, SnapshotNlri, SnapshotReader};
pub use types::MrtWriterConfig;
pub use warm_bundle::{
    MAX_WARM_BUNDLE_MANIFEST_BYTES, MAX_WARM_BUNDLE_SNAPSHOT_BYTES, WARM_BUNDLE_FORMAT_VERSION,
    WARM_BUNDLE_MANIFEST_FILE, WARM_BUNDLE_POLICY_DIGEST_VERSION, WarmBundleArtifactV1,
    WarmBundleDirectory, WarmBundleError, WarmBundleExpectedV1, WarmBundleFamilyV1,
    WarmBundleFreshnessV1, WarmBundleIdentityV1, WarmBundleManifestV1, WarmBundlePolicyDigestV1,
    WarmBundlePolicyInputV1, WarmBundleV1, WarmBundleViewKindV1, WarmBundleViewV1,
    load_warm_bundle, resolved_import_policy_digest_v1, write_warm_bundle,
};
