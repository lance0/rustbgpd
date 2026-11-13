use std::num::NonZeroU32;
use std::path::{Path, PathBuf};

pub use rustbgpd_rib::update::{MrtPeerEntry, MrtSnapshotData};

/// Configuration for the MRT writer.
#[derive(Debug, Clone)]
pub struct MrtWriterConfig {
    /// Directory where MRT dump files are written.
    pub output_dir: PathBuf,
    /// Seconds between periodic dumps; must be greater than zero.
    pub dump_interval: u64,
    /// Whether to gzip-compress output files.
    pub compress: bool,
    /// Nonempty filename component for dump files; no separators, NUL, `.` or `..`.
    pub file_prefix: String,
    /// Keep at most this many of this writer's dumps; `None` keeps all.
    pub max_files: Option<NonZeroU32>,
    /// Vets the directories above `output_dir` before each dump; an error
    /// fails the dump. The daemon supplies its runtime-state ancestor rule.
    pub ancestor_check: Option<fn(&Path) -> std::io::Result<()>>,
}
