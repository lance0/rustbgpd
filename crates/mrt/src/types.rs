use std::path::PathBuf;

pub use rustbgpd_rib::update::{MrtPeerEntry, MrtSnapshotData};

/// Configuration for the MRT writer.
#[derive(Debug, Clone)]
pub struct MrtWriterConfig {
    pub output_dir: PathBuf,
    pub dump_interval: u64,
    pub compress: bool,
    pub file_prefix: String,
}
