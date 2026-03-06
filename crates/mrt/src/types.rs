use std::path::PathBuf;

pub use rustbgpd_rib::update::{MrtPeerEntry, MrtSnapshotData};

/// Configuration for the MRT writer.
#[derive(Debug, Clone)]
pub struct MrtWriterConfig {
    /// Directory where MRT dump files are written.
    pub output_dir: PathBuf,
    /// Seconds between periodic dumps (0 = disabled).
    pub dump_interval: u64,
    /// Whether to gzip-compress output files.
    pub compress: bool,
    /// Filename prefix for dump files.
    pub file_prefix: String,
}
