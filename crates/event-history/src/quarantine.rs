//! Corrupted-DB quarantine + sidecar allocator recovery (ADR-0072).
//!
//! Two surfaces:
//!
//! 1. **Quarantine.** When `events.db` fails to open because of its
//!    content (corrupted file, schema corruption, header garbage; not a
//!    host error such as a full or read-only filesystem, which leaves the
//!    store in place), rename the SQLite file
//!    set to `events.db.stale`, `events.db.stale-wal`, and
//!    `events.db.stale-shm` so a fresh DB can take its place. The main
//!    file naming matches the `*.json.stale` convention in
//!    `src/fib_runtime.rs:1140-1142` so operators inherit one
//!    quarantine idiom across the daemon. A new quarantine never
//!    overwrites an older one: an existing `events.db.stale` set moves to
//!    `events.db.stale.<n>` first, taking the lowest unused `n`, so the
//!    highest number is the most recent earlier copy.
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
/// `events.db.stale`. Matches `stale_owned_state_path` in the
/// `rustbgpd` crate's `src/fib_runtime.rs`.
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

/// The SQLite file set for `db`: the database, its WAL, and its
/// shared-memory file. WAL side files are part of the database state, so
/// they move with it under the names SQLite expects for the new path;
/// metadata recovery then sees committed-but-not-checkpointed updates.
fn file_set(db: &Path) -> [PathBuf; 3] {
    [db.to_path_buf(), wal_path(db), shm_path(db)]
}

/// Move the SQLite file set:
///
/// - `events.db` → `events.db.stale`
/// - `events.db-wal` → `events.db.stale-wal`
/// - `events.db-shm` → `events.db.stale-shm`
///
/// An existing quarantine set is first rotated to `events.db.stale.<n>`.
/// Returns OK even if the events DB doesn't exist (idempotent on the
/// "nothing to quarantine" case).
pub(crate) fn quarantine_db(events_db: &Path) -> Result<(), EventHistoryError> {
    if !events_db.exists() {
        return Ok(());
    }
    let target = stale_path(events_db);
    rotate_quarantine(&target)?;
    move_file_set(events_db, &target)?;
    warn!(
        events_db = %events_db.display(),
        quarantined_to = %target.display(),
        "quarantined corrupted events DB"
    );
    Ok(())
}

/// Move an existing quarantine set to the lowest unused
/// `<stale>.<n>` so the next quarantine cannot overwrite it.
fn rotate_quarantine(stale: &Path) -> Result<(), EventHistoryError> {
    let occupied = |db: &Path| file_set(db).iter().any(|file| file.exists());
    if !occupied(stale) {
        return Ok(());
    }
    let mut n = 1_u32;
    let rotated = loop {
        let mut candidate = stale.as_os_str().to_os_string();
        candidate.push(format!(".{n}"));
        let candidate = PathBuf::from(candidate);
        if !occupied(&candidate) {
            break candidate;
        }
        n += 1;
    };
    move_file_set(stale, &rotated)?;
    warn!(
        quarantine = %stale.display(),
        preserved_as = %rotated.display(),
        "kept the previous events DB quarantine"
    );
    Ok(())
}

/// Rename every present member of `from`'s file set to the matching
/// member of `to`'s. Callers ensure `to`'s set is unoccupied.
fn move_file_set(from: &Path, to: &Path) -> Result<(), EventHistoryError> {
    for (file, target) in file_set(from).iter().zip(file_set(to)) {
        if file.exists() {
            fs::rename(file, &target).map_err(|source| EventHistoryError::Io {
                path: target,
                source,
            })?;
        }
    }
    Ok(())
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
    fn quarantine_db_keeps_every_earlier_quarantine() {
        let dir = TempDir::new().unwrap();
        let events = dir.path().join("events.db");
        for generation in ["first", "second", "third"] {
            fs::write(&events, generation).unwrap();
            fs::write(wal_path(&events), generation).unwrap();
            quarantine_db(&events).unwrap();
        }
        let read = |name: &str| fs::read_to_string(dir.path().join(name)).unwrap();
        assert_eq!(read("events.db.stale"), "third");
        assert_eq!(read("events.db.stale-wal"), "third");
        assert_eq!(read("events.db.stale.1"), "first");
        assert_eq!(read("events.db.stale.1-wal"), "first");
        assert_eq!(read("events.db.stale.2"), "second");
        assert_eq!(read("events.db.stale.2-wal"), "second");
    }

    #[test]
    fn quarantine_db_rotates_an_orphaned_side_file() {
        // A leftover stale WAL without its database is still evidence.
        let dir = TempDir::new().unwrap();
        let events = dir.path().join("events.db");
        fs::write(dir.path().join("events.db.stale-wal"), b"orphan").unwrap();
        fs::write(&events, b"garbage").unwrap();
        quarantine_db(&events).unwrap();
        assert_eq!(
            fs::read(dir.path().join("events.db.stale.1-wal")).unwrap(),
            b"orphan"
        );
        assert!(!dir.path().join("events.db.stale.1").exists());
        assert_eq!(
            fs::read(dir.path().join("events.db.stale")).unwrap(),
            b"garbage"
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
