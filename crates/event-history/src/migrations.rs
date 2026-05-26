//! Schema bootstrap + version-fence (ADR-0072).
//!
//! Mirrors the `GR_RESTART_MARKER_VERSION` pattern in
//! `src/main.rs:67` — a single u32 schema version stored in the
//! `metadata` table, validated at every open. A higher version on
//! disk than the daemon supports refuses to open (downgrade fence);
//! a lower version triggers in-place migration.
//!
//! v1 is the only schema version today. Future ALTER TABLE migrations
//! get a `fn migrate_v1_to_v2(...)` and a bump to [`CURRENT_SCHEMA_VERSION`].

use rusqlite::{Connection, OptionalExtension, params};

use crate::{SynchronousMode, error::EventHistoryError};

/// Schema version this daemon understands. Bumped on every schema-shape
/// change (new column, new index, new table). Downgrading the daemon
/// while pointing at a higher-version DB refuses to start.
pub(crate) const CURRENT_SCHEMA_VERSION: u32 = 1;

/// Metadata-table key carrying the schema version.
pub(crate) const META_SCHEMA_VERSION: &str = "schema_version";

/// Metadata-table key carrying the durable allocator value (last
/// assigned `event_id`). See [`crate::sequence`].
pub(crate) const META_LAST_EVENT_ID: &str = "last_event_id";

/// Metadata-table key carrying the daemon boot ID (UUIDv4 stamped at
/// startup). Used by clients to detect restarts independently of the
/// monotonic cursor.
pub(crate) const META_LAST_BOOT_ID: &str = "last_boot_id";

/// Metadata-table key carrying the Unix timestamp at which the DB
/// was first created. Diagnostic only.
pub(crate) const META_CREATED_AT_UNIX: &str = "created_at_unix";

/// Open / bootstrap a connection against the current schema.
///
/// Behavior:
/// - First-time open (empty DB) — create all tables / indexes / metadata
///   rows; allocator initialized to 0.
/// - Existing DB at the current schema version — leave it alone.
/// - Existing DB at a higher version — refuse with
///   [`EventHistoryError::SchemaDowngrade`]. The daemon either upgrades
///   forward or the operator quarantines manually.
/// - Existing DB at a lower version — run migrations in order. (None
///   exist yet; v1 is the only version.)
///
/// Called by [`crate::storage`] inside `spawn_blocking`; this function
/// is synchronous.
pub(crate) fn bootstrap(
    conn: &mut Connection,
    synchronous: SynchronousMode,
) -> Result<(), EventHistoryError> {
    apply_pragmas(conn, synchronous)?;

    // The metadata table is the version anchor. If it doesn't exist,
    // this is a fresh DB and we bootstrap everything.
    let metadata_exists: bool = conn
        .query_row(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='metadata'",
            [],
            |_| Ok(true),
        )
        .optional()?
        .unwrap_or(false);

    if !metadata_exists {
        first_init(conn)?;
        return Ok(());
    }

    // Existing DB — check version.
    let on_disk = read_schema_version(conn)?;
    match on_disk.cmp(&CURRENT_SCHEMA_VERSION) {
        std::cmp::Ordering::Equal => Ok(()),
        std::cmp::Ordering::Less => {
            // No migrations exist yet. Future versions append match arms.
            Err(EventHistoryError::SchemaMigrationGap {
                from: on_disk,
                to: CURRENT_SCHEMA_VERSION,
            })
        }
        std::cmp::Ordering::Greater => Err(EventHistoryError::SchemaDowngrade {
            on_disk,
            supported: CURRENT_SCHEMA_VERSION,
        }),
    }
}

/// Apply the PRAGMAs the ADR-0072 storage section requires. Idempotent
/// on every open.
fn apply_pragmas(conn: &Connection, synchronous: SynchronousMode) -> Result<(), EventHistoryError> {
    // SQLite returns the resolved mode for journal_mode pragmas; we ignore the
    // value and only care that the call succeeds.
    conn.pragma_update(None, "journal_mode", "WAL")?;
    conn.pragma_update(None, "synchronous", synchronous.as_pragma())?;
    conn.pragma_update(None, "busy_timeout", 5000_i32)?;
    conn.pragma_update(None, "foreign_keys", "OFF")?;
    conn.pragma_update(None, "wal_autocheckpoint", 1000_i32)?;
    Ok(())
}

fn first_init(conn: &mut Connection) -> Result<(), EventHistoryError> {
    let txn = conn.transaction()?;
    txn.execute_batch(SCHEMA_V1)?;
    txn.execute(
        "INSERT INTO metadata (key, value) VALUES (?1, ?2)",
        params![META_SCHEMA_VERSION, CURRENT_SCHEMA_VERSION.to_string()],
    )?;
    txn.execute(
        "INSERT INTO metadata (key, value) VALUES (?1, ?2)",
        params![META_LAST_EVENT_ID, "0"],
    )?;
    txn.execute(
        "INSERT INTO metadata (key, value) VALUES (?1, ?2)",
        params![
            META_CREATED_AT_UNIX,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs().to_string())
                .unwrap_or_else(|_| "0".to_string())
        ],
    )?;
    txn.commit()?;
    Ok(())
}

fn read_schema_version(conn: &Connection) -> Result<u32, EventHistoryError> {
    let raw: String = conn
        .query_row(
            "SELECT value FROM metadata WHERE key = ?1",
            params![META_SCHEMA_VERSION],
            |row| row.get(0),
        )
        .map_err(|_| {
            EventHistoryError::SchemaCorrupt(format!("metadata.{META_SCHEMA_VERSION} missing"))
        })?;
    raw.parse::<u32>().map_err(|e| {
        EventHistoryError::SchemaCorrupt(format!("metadata.{META_SCHEMA_VERSION} not a u32: {e}"))
    })
}

/// Schema v1 — see ADR-0072 schema section.
///
/// Two tables: `events` (the primary outbox) and `event_peers`
/// (the join-table peer index for "any-role" queries — see ADR-0072
/// for the rationale). Plus `metadata` (allocator, schema version,
/// boot id).
const SCHEMA_V1: &str = r#"
CREATE TABLE events (
    event_id           INTEGER NOT NULL PRIMARY KEY,
    timestamp_ns       INTEGER NOT NULL,
    category           TEXT    NOT NULL,
    event_type         TEXT    NOT NULL,
    peer               TEXT,
    previous_peer      TEXT,
    target_peer        TEXT,
    afi_safi           TEXT,
    prefix             TEXT,
    rd                 TEXT,
    evpn_route_type    INTEGER,
    severity           TEXT    NOT NULL,
    schema_version     INTEGER NOT NULL,
    daemon_boot_id     TEXT    NOT NULL,
    payload_codec      TEXT    NOT NULL DEFAULT 'opaque',
    payload            BLOB    NOT NULL
);

CREATE TABLE event_peers (
    event_id INTEGER NOT NULL,
    role     TEXT    NOT NULL,
    peer     TEXT    NOT NULL,
    PRIMARY KEY (event_id, role)
);

CREATE INDEX idx_events_category_id   ON events(category, event_id);
CREATE INDEX idx_events_prefix_id     ON events(prefix, event_id)
    WHERE prefix IS NOT NULL;
CREATE INDEX idx_events_rd_id         ON events(rd, event_id)
    WHERE rd IS NOT NULL;
CREATE INDEX idx_events_timestamp     ON events(timestamp_ns);
CREATE INDEX idx_event_peers_peer_id  ON event_peers(peer, event_id);

CREATE TABLE metadata (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"#;

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;

    fn open_in_memory() -> Connection {
        Connection::open_in_memory().expect("in-memory open")
    }

    #[test]
    fn first_init_creates_schema_at_current_version() {
        let mut conn = open_in_memory();
        bootstrap(&mut conn, SynchronousMode::Full).unwrap();
        let version = read_schema_version(&conn).unwrap();
        assert_eq!(version, CURRENT_SCHEMA_VERSION);

        // Verify allocator was initialized to 0.
        let last_id: String = conn
            .query_row(
                "SELECT value FROM metadata WHERE key = ?1",
                params![META_LAST_EVENT_ID],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(last_id, "0");
    }

    #[test]
    fn reopening_existing_db_is_noop() {
        let mut conn = open_in_memory();
        bootstrap(&mut conn, SynchronousMode::Full).unwrap();
        // Second bootstrap on the same connection must not error.
        bootstrap(&mut conn, SynchronousMode::Full).unwrap();
    }

    #[test]
    fn higher_on_disk_version_refuses() {
        let mut conn = open_in_memory();
        bootstrap(&mut conn, SynchronousMode::Full).unwrap();
        // Spoof a higher version directly into metadata.
        conn.execute(
            "UPDATE metadata SET value = ?1 WHERE key = ?2",
            params![
                (CURRENT_SCHEMA_VERSION + 1).to_string(),
                META_SCHEMA_VERSION
            ],
        )
        .unwrap();
        let err = bootstrap(&mut conn, SynchronousMode::Full).unwrap_err();
        assert!(matches!(err, EventHistoryError::SchemaDowngrade { .. }));
    }

    #[test]
    fn indexes_exist_after_first_init() {
        let mut conn = open_in_memory();
        bootstrap(&mut conn, SynchronousMode::Full).unwrap();
        let mut stmt = conn
            .prepare("SELECT name FROM sqlite_master WHERE type='index'")
            .unwrap();
        let names: Vec<String> = stmt
            .query_map([], |row| row.get(0))
            .unwrap()
            .filter_map(Result::ok)
            .collect();
        for required in [
            "idx_events_category_id",
            "idx_events_prefix_id",
            "idx_events_rd_id",
            "idx_events_timestamp",
            "idx_event_peers_peer_id",
        ] {
            assert!(
                names.iter().any(|n| n == required),
                "missing index {required}; have {names:?}"
            );
        }
    }

    #[test]
    fn synchronous_mode_is_applied() {
        let mut conn = open_in_memory();
        bootstrap(&mut conn, SynchronousMode::Normal).unwrap();

        let value: i64 = conn
            .pragma_query_value(None, "synchronous", |row| row.get(0))
            .unwrap();
        assert_eq!(value, 1, "NORMAL resolves to SQLite synchronous=1");
    }
}
