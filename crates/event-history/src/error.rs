//! Error types for the durable event history outbox.

use std::path::PathBuf;
use thiserror::Error;

/// All errors EHM surfaces. Storage-layer errors flow through this
/// type back to the async actor; the actor decides whether each
/// becomes a metric, a degraded-flag flip, or a fatal log.
#[derive(Debug, Error)]
pub enum EventHistoryError {
    /// SQLite-level error wrapped without losing the original code.
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),

    /// On-disk schema_version is higher than this daemon supports.
    /// Operator must upgrade the binary or quarantine the DB.
    #[error(
        "events.db schema version {on_disk} is higher than supported {supported}; refusing to start"
    )]
    SchemaDowngrade { on_disk: u32, supported: u32 },

    /// On-disk schema_version is lower than this daemon supports, and
    /// no migration path is wired between those versions. v1 is the
    /// only schema today, so this fires only on tampering.
    #[error("events.db schema_version {from} cannot migrate to {to}; no migration path defined")]
    SchemaMigrationGap { from: u32, to: u32 },

    /// Metadata table is malformed (missing keys, non-parseable values).
    /// Trigger a quarantine + fresh-init cycle.
    #[error("events.db schema corrupt: {0}")]
    SchemaCorrupt(String),

    /// Allocator value is missing or unparseable. Should be unreachable
    /// outside of explicit corruption.
    #[error("allocator metadata corrupt: {0}")]
    AllocatorCorrupt(String),

    /// I/O error during quarantine, sidecar write, or DB-file probe.
    #[error("event-history I/O error at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    /// EHM has been driven into pass-through mode (allocator anchor
    /// unrecoverable) and refuses to issue new event_ids. Operator
    /// resolves explicitly via `rbgp event-history reset-allocator`
    /// (P1 follow-up). See ADR-0072 "Allocator recovery ladder."
    #[error("event outbox in pass-through mode; allocator anchor unrecoverable")]
    PassThrough,
}
