//! Corrupted-DB quarantine + sidecar allocator recovery (ADR-0072).
//!
//! Two surfaces:
//!
//! 1. **Quarantine.** When `events.db` fails to open cleanly (corrupted
//!    file, schema corruption, header garbage), rename the SQLite file
//!    set to `events.db.stale`, `events.db.stale-wal`, and
//!    `events.db.stale-shm` so a fresh DB can take its place. The main
//!    file naming matches the `*.json.stale` convention in
//!    `src/fib_runtime.rs:1140-1142` so operators inherit one
//!    quarantine idiom across the daemon. No timestamp suffix — a
//!    second quarantine overwrites the first; operators rename manually
//!    if they need forensic preservation.
//!
//! 2. **Sidecar.** A tiny file at `<runtime_state_dir>/events.last_id`
//!    carrying just the allocator value as ASCII. Written via the
//!    `tempfile + rename` atomic pattern at `src/fib_runtime.rs:1159-1161`.
//!    Sidecar updates may lag the DB by multiple commits. In v1, the
//!    sidecar is a diagnostic hint only: because it can lag committed
//!    events, it is not authoritative for allocator recovery. If the
//!    primary DB and quarantine both fail to yield an allocator anchor
//!    while a prior `events.db.stale` exists, EHM enters pass-through
//!    rather than restart the allocator from a possibly stale sidecar.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use rusqlite::Connection;
use tracing::warn;

use crate::error::EventHistoryError;
use crate::sequence;

/// Suffix appended to the events DB filename when quarantined.
const STALE_SUFFIX: &str = "stale";

/// Sidecar filename relative to the events DB.
const SIDECAR_FILENAME: &str = "events.last_id";

/// Return the path the events DB is quarantined to. `events.db` →
/// `events.db.stale`. Matches [`stale_owned_state_path`] in
/// `src/fib_runtime.rs`.
#[must_use]
pub(crate) fn stale_path(events_db: &Path) -> PathBuf {
    let mut p = events_db.to_path_buf();
    // The `fib-owned.json` convention is `with_extension("json.stale")`;
    // mirrored here: `events.db` becomes `events.db.stale`.
    let new_ext = events_db.extension().and_then(|e| e.to_str()).map_or_else(
        || STALE_SUFFIX.to_string(),
        |e| format!("{e}.{STALE_SUFFIX}"),
    );
    p.set_extension(new_ext);
    p
}

#[must_use]
pub(crate) fn wal_path(db: &Path) -> PathBuf {
    let mut p = db.as_os_str().to_os_string();
    p.push("-wal");
    PathBuf::from(p)
}

#[must_use]
pub(crate) fn shm_path(db: &Path) -> PathBuf {
    let mut p = db.as_os_str().to_os_string();
    p.push("-shm");
    PathBuf::from(p)
}

/// Sidecar path next to the events DB.
#[must_use]
pub(crate) fn sidecar_path(events_db: &Path) -> PathBuf {
    events_db.parent().map_or_else(
        || PathBuf::from(SIDECAR_FILENAME),
        |dir| dir.join(SIDECAR_FILENAME),
    )
}

/// Move the SQLite file set:
///
/// - `events.db` → `events.db.stale`
/// - `events.db-wal` → `events.db.stale-wal`
/// - `events.db-shm` → `events.db.stale-shm`
///
/// Overwrites any existing stale files. Returns OK even if the events DB
/// doesn't exist (idempotent on the "nothing to quarantine" case).
pub(crate) fn quarantine_db(events_db: &Path) -> Result<(), EventHistoryError> {
    if !events_db.exists() {
        return Ok(());
    }
    let target = stale_path(events_db);
    rename_overwrite(events_db, &target)?;

    // WAL mode side files are part of the database state. Rename them to
    // the names SQLite expects when opening `events.db.stale` so metadata
    // recovery sees committed-but-not-checkpointed allocator updates.
    let wal = wal_path(events_db);
    if wal.exists() {
        rename_overwrite(&wal, &wal_path(&target))?;
    }
    let shm = shm_path(events_db);
    if shm.exists() {
        rename_overwrite(&shm, &shm_path(&target))?;
    }
    warn!(
        events_db = %events_db.display(),
        quarantined_to = %target.display(),
        "quarantined corrupted events DB"
    );
    Ok(())
}

fn rename_overwrite(from: &Path, to: &Path) -> Result<(), EventHistoryError> {
    if to.exists() {
        fs::remove_file(to).map_err(|source| EventHistoryError::Io {
            path: to.to_path_buf(),
            source,
        })?;
    }
    fs::rename(from, to).map_err(|source| EventHistoryError::Io {
        path: to.to_path_buf(),
        source,
    })
}

/// Read the sidecar's allocator value, if the sidecar exists and
/// parses cleanly. Returns `None` on missing file or unparseable
/// contents (the latter logs a warning but does not propagate the
/// error). The value is diagnostic only in v1, not allocator authority.
pub(crate) fn read_sidecar(sidecar: &Path) -> Option<u64> {
    let raw = match fs::read_to_string(sidecar) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
        Err(e) => {
            warn!(
                sidecar = %sidecar.display(),
                error = %e,
                "sidecar read failed"
            );
            return None;
        }
    };
    let trimmed = raw.trim();
    match trimmed.parse::<u64>() {
        Ok(v) => Some(v),
        Err(e) => {
            warn!(
                sidecar = %sidecar.display(),
                contents = trimmed,
                error = %e,
                "sidecar contents unparseable; ignoring"
            );
            None
        }
    }
}

/// Write the sidecar atomically via tempfile + rename. Matches
/// `write_owned_state` in `src/fib_runtime.rs:1159-1161`.
pub(crate) fn write_sidecar(sidecar: &Path, value: u64) -> Result<(), EventHistoryError> {
    if let Some(parent) = sidecar.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent).map_err(|source| EventHistoryError::Io {
            path: parent.to_path_buf(),
            source,
        })?;
    }
    let tmp = sidecar.with_extension("last_id.tmp");
    {
        let mut f = fs::File::create(&tmp).map_err(|source| EventHistoryError::Io {
            path: tmp.clone(),
            source,
        })?;
        writeln!(f, "{value}").map_err(|source| EventHistoryError::Io {
            path: tmp.clone(),
            source,
        })?;
        f.sync_all().map_err(|source| EventHistoryError::Io {
            path: tmp.clone(),
            source,
        })?;
    }
    fs::rename(&tmp, sidecar).map_err(|source| EventHistoryError::Io {
        path: sidecar.to_path_buf(),
        source,
    })
}

/// Best-effort read of the allocator value from a quarantined DB.
///
/// Opens `events.db.stale` read-only and reads `metadata.last_event_id`.
/// Returns `None` if the quarantine doesn't exist or the metadata
/// is unrecoverable — we don't want quarantine-read failures to break
/// startup. Caller falls through to the sidecar.
pub(crate) fn read_quarantine_allocator(stale: &Path) -> Option<u64> {
    if !stale.exists() {
        return None;
    }
    let conn = match Connection::open_with_flags(stale, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
    {
        Ok(c) => c,
        Err(e) => {
            warn!(
                quarantine = %stale.display(),
                error = %e,
                "quarantine open failed; falling through to sidecar"
            );
            return None;
        }
    };
    match sequence::read_allocator(&conn) {
        Ok(opt) => opt,
        Err(e) => {
            warn!(
                quarantine = %stale.display(),
                error = %e,
                "quarantine metadata unrecoverable; falling through to sidecar"
            );
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn stale_path_appends_suffix() {
        let p = Path::new("/foo/bar/events.db");
        assert_eq!(stale_path(p), PathBuf::from("/foo/bar/events.db.stale"));
    }

    #[test]
    fn stale_path_handles_no_extension() {
        let p = Path::new("/foo/bar/events");
        assert_eq!(stale_path(p), PathBuf::from("/foo/bar/events.stale"));
    }

    #[test]
    fn sidecar_path_lives_next_to_db() {
        let p = Path::new("/foo/bar/events.db");
        assert_eq!(sidecar_path(p), PathBuf::from("/foo/bar/events.last_id"));
    }

    #[test]
    fn wal_and_shm_paths_append_suffix() {
        let p = Path::new("/foo/bar/events.db");
        assert_eq!(wal_path(p), PathBuf::from("/foo/bar/events.db-wal"));
        assert_eq!(shm_path(p), PathBuf::from("/foo/bar/events.db-shm"));
    }

    #[test]
    fn quarantine_db_renames_existing_file() {
        let dir = TempDir::new().unwrap();
        let events = dir.path().join("events.db");
        fs::write(&events, b"garbage").unwrap();
        quarantine_db(&events).unwrap();
        assert!(!events.exists());
        assert!(dir.path().join("events.db.stale").exists());
    }

    #[test]
    fn quarantine_db_renames_wal_side_files_as_a_set() {
        let dir = TempDir::new().unwrap();
        let events = dir.path().join("events.db");
        fs::write(&events, b"garbage").unwrap();
        fs::write(dir.path().join("events.db-wal"), b"wal").unwrap();
        fs::write(dir.path().join("events.db-shm"), b"shm").unwrap();

        quarantine_db(&events).unwrap();

        assert!(!events.exists());
        assert!(!dir.path().join("events.db-wal").exists());
        assert!(!dir.path().join("events.db-shm").exists());
        assert!(dir.path().join("events.db.stale").exists());
        assert_eq!(
            fs::read(dir.path().join("events.db.stale-wal")).unwrap(),
            b"wal"
        );
        assert_eq!(
            fs::read(dir.path().join("events.db.stale-shm")).unwrap(),
            b"shm"
        );
    }

    #[test]
    fn quarantine_db_is_noop_when_db_missing() {
        let dir = TempDir::new().unwrap();
        let events = dir.path().join("events.db");
        // Missing — should be OK, no stale file produced.
        quarantine_db(&events).unwrap();
        assert!(!dir.path().join("events.db.stale").exists());
    }

    #[test]
    fn sidecar_roundtrip() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("events.last_id");
        assert_eq!(read_sidecar(&path), None);
        write_sidecar(&path, 12345).unwrap();
        assert_eq!(read_sidecar(&path), Some(12345));
        write_sidecar(&path, 67890).unwrap();
        assert_eq!(read_sidecar(&path), Some(67890));
    }

    #[test]
    fn sidecar_unparseable_returns_none_and_does_not_panic() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("events.last_id");
        fs::write(&path, b"not-a-number\n").unwrap();
        assert_eq!(read_sidecar(&path), None);
    }
}
