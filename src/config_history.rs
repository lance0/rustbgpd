//! Bounded on-disk history of applied configs (Junos-style `rollback N`).
//!
//! [`crate::config_persister`] records each validated applied config here —
//! durable mutations, the boot snapshot, and successful SIGHUP refreshes —
//! one entry per distinct config, content-hash-deduplicated against the newest
//! entry and bounded to [`HISTORY_LIMIT`] snapshots under
//! `<runtime_state_dir>/config-history/`. Rollback resolves an entry by
//! index and routes it through the ordinary config transaction path (see
//! `config_transaction_control`); this module only stores and lists.
//!
//! Entries are individual files named `<seq>-<unix_ts>-<sha256>.toml`,
//! written with the commit-confirm journal's fsync'd atomic-write primitive.
//! The monotonic sequence number orders entries (newest = highest); the
//! content hash lives in the file name and is verified against the retained
//! bytes before deduplication or rollback.

#![deny(unsafe_code)]

use std::fs;
use std::io::{self, Read as _};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use sha2::{Digest as _, Sha256};

/// Directory name under `runtime_state_dir`.
pub const HISTORY_DIR_NAME: &str = "config-history";

/// Number of applied-config snapshots retained on disk. Deliberately a
/// fixed bound, same as the crash-report retention cap: N recent configs,
/// no candidate-config database.
pub const HISTORY_LIMIT: usize = 20;

/// Per-entry read cap, mirroring the commit-confirm journal's sanity limit:
/// a config snapshot larger than this is corrupt, and loading it would only
/// risk an OOM.
const MAX_ENTRY_BYTES: u64 = 10 * 1024 * 1024;

/// Metadata for one retained config snapshot (no document contents).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoryEntry {
    /// 0 = newest (the currently persisted config), 1 = previous, …
    pub index: usize,
    /// Monotonic on-disk sequence number (newest = highest).
    pub sequence: u64,
    /// Unix seconds at record time.
    pub timestamp_unix_seconds: u64,
    /// Hex-encoded SHA-256 of the applied TOML document.
    pub sha256: String,
    /// Entry file path.
    pub path: PathBuf,
}

#[must_use]
pub fn history_dir(runtime_state_dir: &Path) -> PathBuf {
    runtime_state_dir.join(HISTORY_DIR_NAME)
}

#[must_use]
pub fn sha256_hex(toml_str: &str) -> String {
    let digest = Sha256::digest(toml_str.as_bytes());
    let mut hex = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(hex, "{byte:02x}");
    }
    hex
}

/// Record `toml_str` as the newest history entry.
///
/// Deduplicates against the newest entry only (re-recording the identical
/// document does not grow history) and evicts the oldest entries beyond
/// [`HISTORY_LIMIT`]. Returns whether a new entry was written.
///
/// # Errors
///
/// Returns any io error from creating the directory, listing existing
/// entries, or atomically writing the new entry. Eviction failures are
/// returned too — a history that cannot honor its bound should be loud.
pub fn record(dir: &Path, toml_str: &str) -> io::Result<bool> {
    fs::create_dir_all(dir)?;
    let hash = sha256_hex(toml_str);
    let entries = list(dir)?;
    if let Some(newest) = entries.first()
        && newest.sha256 == hash
        && read(newest).is_ok_and(|contents| contents == toml_str)
    {
        return Ok(false);
    }
    let sequence = entries.first().map_or(Ok(1), |newest| {
        newest.sequence.checked_add(1).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "config history sequence is exhausted",
            )
        })
    })?;
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs());
    let path = dir.join(format!("{sequence:010}-{timestamp}-{hash}.toml"));
    crate::confirm_journal::write_atomic(&path, toml_str.as_bytes())?;
    // Evict beyond the bound, oldest first (the freshly written entry is
    // newest, so it is never a candidate).
    for stale in entries
        .iter()
        .rev()
        .take((entries.len() + 1).saturating_sub(HISTORY_LIMIT))
    {
        fs::remove_file(&stale.path)?;
    }
    Ok(true)
}

/// List retained entries, newest first. A missing directory is an empty
/// history. Files that do not match the entry naming scheme are ignored.
///
/// # Errors
///
/// Returns any io error from reading the directory.
pub fn list(dir: &Path) -> io::Result<Vec<HistoryEntry>> {
    let read_dir = match fs::read_dir(dir) {
        Ok(read_dir) => read_dir,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error),
    };
    let mut entries = Vec::new();
    for dir_entry in read_dir {
        let dir_entry = dir_entry?;
        if let Some(parsed) = parse_entry_name(&dir_entry.file_name().to_string_lossy()) {
            let (sequence, timestamp_unix_seconds, sha256) = parsed;
            entries.push(HistoryEntry {
                index: 0,
                sequence,
                timestamp_unix_seconds,
                sha256,
                path: dir_entry.path(),
            });
        }
    }
    entries.sort_by_key(|entry| std::cmp::Reverse(entry.sequence));
    for (index, entry) in entries.iter_mut().enumerate() {
        entry.index = index;
    }
    Ok(entries)
}

/// Load the TOML document of the entry at `index` (0 = newest).
///
/// # Errors
///
/// `NotFound` when the index is beyond the retained history (the message
/// names how many entries exist); other io errors from the bounded read.
pub fn read_entry(dir: &Path, index: usize) -> io::Result<(HistoryEntry, String)> {
    let entries = list(dir)?;
    let count = entries.len();
    let Some(entry) = entries.into_iter().nth(index) else {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!(
                "config history has {count} retained entr{} (valid indexes 0..={}); index {index} is out of range",
                if count == 1 { "y" } else { "ies" },
                count.saturating_sub(1),
            ),
        ));
    };
    let toml_str = read(&entry)?;
    Ok((entry, toml_str))
}

/// Load and integrity-check one exact history entry returned by [`list`].
///
/// Reading by entry rather than re-resolving its index keeps a concurrent
/// append from pairing one snapshot's metadata with another snapshot's
/// contents. The file name is only metadata until the retained bytes hash to
/// the embedded digest; a corrupt or replaced entry is never eligible for a
/// rollback.
///
/// # Errors
///
/// Returns `InvalidData` for a non-regular, oversized, non-UTF-8, or
/// digest-mismatched entry, plus ordinary filesystem errors.
pub fn read(entry: &HistoryEntry) -> io::Result<String> {
    let metadata = fs::symlink_metadata(&entry.path)?;
    if !metadata.file_type().is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "config history entry {} is not a regular file",
                entry.path.display()
            ),
        ));
    }
    if metadata.len() > MAX_ENTRY_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "config history entry {} exceeds the {MAX_ENTRY_BYTES}-byte sanity limit",
                entry.path.display()
            ),
        ));
    }
    let mut reader = fs::File::open(&entry.path)?.take(MAX_ENTRY_BYTES + 1);
    let mut toml_str = String::new();
    reader.read_to_string(&mut toml_str)?;
    if toml_str.len() as u64 > MAX_ENTRY_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "config history entry {} exceeds the {MAX_ENTRY_BYTES}-byte sanity limit",
                entry.path.display()
            ),
        ));
    }
    let actual_hash = sha256_hex(&toml_str);
    if actual_hash != entry.sha256 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "config history entry {} failed its SHA-256 integrity check (expected {}, got {actual_hash})",
                entry.path.display(),
                entry.sha256
            ),
        ));
    }
    Ok(toml_str)
}

/// One-line redacted summary of a retained config document: identity and
/// object counts only, never field values beyond ASN / router id.
#[must_use]
pub fn summarize(toml_str: &str) -> String {
    let Ok(value) = toml_str.parse::<toml::Table>() else {
        return "(unparseable config snapshot)".to_string();
    };
    let global = value.get("global");
    let asn = global
        .and_then(|g| g.get("asn"))
        .and_then(toml::Value::as_integer)
        .map_or_else(|| "?".to_string(), |asn| asn.to_string());
    let router_id = global
        .and_then(|g| g.get("router_id"))
        .and_then(toml::Value::as_str)
        .unwrap_or("?");
    let array_len = |key: &str| {
        value
            .get(key)
            .and_then(toml::Value::as_array)
            .map_or(0, Vec::len)
    };
    let policies = value
        .get("policy")
        .and_then(|p| p.get("definitions"))
        .and_then(toml::Value::as_array)
        .map_or(0, Vec::len);
    format!(
        "asn {asn}, router-id {router_id}, {} neighbor(s), {} dynamic range(s), {} fib table(s), {policies} policy definition(s)",
        array_len("neighbors"),
        array_len("dynamic_neighbors"),
        array_len("fib_tables"),
    )
}

fn parse_entry_name(name: &str) -> Option<(u64, u64, String)> {
    let stem = name.strip_suffix(".toml")?;
    let mut parts = stem.splitn(3, '-');
    let sequence = parts.next()?.parse::<u64>().ok()?;
    let timestamp = parts.next()?.parse::<u64>().ok()?;
    let hash = parts.next()?;
    if hash.len() != 64 || !hash.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    Some((sequence, timestamp, hash.to_ascii_lowercase()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config_toml(asn: u32) -> String {
        format!(
            "[global]\nasn = {asn}\nrouter_id = \"10.0.0.1\"\nlisten_port = 179\n\n[[neighbors]]\naddress = \"10.0.0.2\"\nremote_asn = 65002\n"
        )
    }

    #[test]
    fn record_and_list_newest_first() {
        let dir = tempfile::tempdir().unwrap();
        assert!(record(dir.path(), &config_toml(65001)).unwrap());
        assert!(record(dir.path(), &config_toml(65002)).unwrap());
        assert!(record(dir.path(), &config_toml(65003)).unwrap());

        let entries = list(dir.path()).unwrap();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].index, 0);
        assert_eq!(entries[0].sequence, 3);
        assert_eq!(entries[2].sequence, 1);
        // Entry 0 is the newest recorded document.
        let (_, newest) = read_entry(dir.path(), 0).unwrap();
        assert_eq!(newest, config_toml(65003));
        let (_, oldest) = read_entry(dir.path(), 2).unwrap();
        assert_eq!(oldest, config_toml(65001));
        // The hash in the listing matches the content.
        assert_eq!(entries[0].sha256, sha256_hex(&config_toml(65003)));
    }

    #[test]
    fn record_dedupes_identical_newest_content() {
        let dir = tempfile::tempdir().unwrap();
        assert!(record(dir.path(), &config_toml(65001)).unwrap());
        // Re-recording the identical document must not grow history.
        assert!(!record(dir.path(), &config_toml(65001)).unwrap());
        assert!(!record(dir.path(), &config_toml(65001)).unwrap());
        assert_eq!(list(dir.path()).unwrap().len(), 1);

        // A different document appends; returning to earlier content appends
        // again (only the NEWEST entry deduplicates — Junos-like).
        assert!(record(dir.path(), &config_toml(65002)).unwrap());
        assert!(record(dir.path(), &config_toml(65001)).unwrap());
        assert_eq!(list(dir.path()).unwrap().len(), 3);
    }

    #[test]
    fn record_evicts_beyond_bound_oldest_first() {
        let dir = tempfile::tempdir().unwrap();
        let limit = u32::try_from(HISTORY_LIMIT).unwrap();
        for asn in 0..(limit + 5) {
            assert!(record(dir.path(), &config_toml(65000 + asn)).unwrap());
        }
        let entries = list(dir.path()).unwrap();
        assert_eq!(entries.len(), HISTORY_LIMIT, "history must stay bounded");
        // Newest survived…
        assert_eq!(
            entries[0].sha256,
            sha256_hex(&config_toml(65000 + limit + 4))
        );
        // …and the survivors are exactly the most recent LIMIT documents.
        let (_, oldest_kept) = read_entry(dir.path(), HISTORY_LIMIT - 1).unwrap();
        assert_eq!(oldest_kept, config_toml(65000 + 5));
    }

    #[test]
    fn list_missing_dir_is_empty_and_ignores_foreign_files() {
        let dir = tempfile::tempdir().unwrap();
        let history = dir.path().join("does-not-exist");
        assert!(list(&history).unwrap().is_empty());

        assert!(record(dir.path(), &config_toml(65001)).unwrap());
        fs::write(dir.path().join("README.txt"), "not an entry").unwrap();
        fs::write(dir.path().join("bogus-name.toml"), "not an entry").unwrap();
        assert_eq!(list(dir.path()).unwrap().len(), 1);
    }

    #[test]
    fn history_survives_reopen() {
        // "Daemon restart" at this layer = a fresh process re-reading the same
        // directory: entries, order, and dedup state must all come from disk.
        let dir = tempfile::tempdir().unwrap();
        assert!(record(dir.path(), &config_toml(65001)).unwrap());
        assert!(record(dir.path(), &config_toml(65002)).unwrap());

        // Fresh reads see both entries in order…
        let entries = list(dir.path()).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].sha256, sha256_hex(&config_toml(65002)));
        // …and a boot-time re-record of the running config deduplicates
        // against the persisted newest entry instead of growing history.
        assert!(!record(dir.path(), &config_toml(65002)).unwrap());
        assert_eq!(list(dir.path()).unwrap().len(), 2);
        // Sequence numbering continues from disk after "restart".
        assert!(record(dir.path(), &config_toml(65003)).unwrap());
        assert_eq!(list(dir.path()).unwrap()[0].sequence, 3);
    }

    #[test]
    fn read_entry_out_of_range_errors_cleanly() {
        let dir = tempfile::tempdir().unwrap();
        assert!(record(dir.path(), &config_toml(65001)).unwrap());

        let error = read_entry(dir.path(), 3).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::NotFound);
        let message = error.to_string();
        assert!(message.contains("1 retained entry"), "{message}");
        assert!(message.contains("index 3 is out of range"), "{message}");

        let empty = dir.path().join("empty");
        let error = read_entry(&empty, 1).unwrap_err();
        assert!(error.to_string().contains("0 retained entries"));
    }

    /// Load-bearing integrity proof: changing retained bytes without changing
    /// the digest-bearing file name must make the entry unreadable. Removing
    /// the digest comparison in `read` makes this test green-light a tampered
    /// rollback candidate.
    #[test]
    fn read_entry_refuses_digest_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        assert!(record(dir.path(), &config_toml(65001)).unwrap());
        let entry = list(dir.path()).unwrap().remove(0);
        fs::write(&entry.path, config_toml(65002)).unwrap();

        let error = read_entry(dir.path(), 0).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("integrity check"), "{error}");
    }

    /// Load-bearing dedup proof: a corrupt newest file that merely retains the
    /// expected hash in its name must not suppress a fresh good snapshot.
    /// Restoring the old filename-only dedup makes `record` return false.
    #[test]
    fn record_repairs_filename_only_dedup_after_corruption() {
        let dir = tempfile::tempdir().unwrap();
        let original = config_toml(65001);
        assert!(record(dir.path(), &original).unwrap());
        let entry = list(dir.path()).unwrap().remove(0);
        fs::write(&entry.path, config_toml(65002)).unwrap();

        assert!(record(dir.path(), &original).unwrap());
        let entries = list(dir.path()).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(read(&entries[0]).unwrap(), original);
        assert!(read(&entries[1]).is_err(), "corrupt prior stays ineligible");
    }

    /// Load-bearing sequence-boundary proof: a corrupt maximum sequence must
    /// fail closed instead of panicking in debug builds or wrapping to zero in
    /// release builds. Restoring unchecked `newest.sequence + 1` breaks this.
    #[test]
    fn record_refuses_sequence_exhaustion() {
        let dir = tempfile::tempdir().unwrap();
        let prior = config_toml(65001);
        let path = dir
            .path()
            .join(format!("{}-1-{}.toml", u64::MAX, sha256_hex(&prior)));
        fs::write(path, prior).unwrap();

        let error = record(dir.path(), &config_toml(65002)).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(
            error.to_string().contains("sequence is exhausted"),
            "{error}"
        );
    }

    /// Load-bearing file-type proof: a digest-shaped symlink must not turn the
    /// rollback store into an arbitrary file reader. Replacing
    /// `symlink_metadata` with an unchecked `File::open` makes this pass as a
    /// valid snapshot.
    #[cfg(unix)]
    #[test]
    fn read_refuses_symlink_entry() {
        let dir = tempfile::tempdir().unwrap();
        let contents = config_toml(65001);
        let target = dir.path().join("target.toml");
        fs::write(&target, &contents).unwrap();
        let path = dir
            .path()
            .join(format!("0000000001-1-{}.toml", sha256_hex(&contents)));
        std::os::unix::fs::symlink(&target, &path).unwrap();

        let entry = list(dir.path()).unwrap().remove(0);
        let error = read(&entry).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("not a regular file"), "{error}");
    }

    #[test]
    fn summarize_reports_identity_and_counts_only() {
        let summary = summarize(&config_toml(65001));
        assert_eq!(
            summary,
            "asn 65001, router-id 10.0.0.1, 1 neighbor(s), 0 dynamic range(s), 0 fib table(s), 0 policy definition(s)"
        );
        assert_eq!(
            summarize("not [valid toml"),
            "(unparseable config snapshot)"
        );
    }

    #[test]
    fn summary_never_leaks_secret_material() {
        let toml_str = "[global]\nasn = 65001\nrouter_id = \"10.0.0.1\"\nlisten_port = 179\n\n[[neighbors]]\naddress = \"10.0.0.2\"\nremote_asn = 65002\nmd5_password = \"super-secret\"\n";
        let summary = summarize(toml_str);
        assert!(!summary.contains("super-secret"), "{summary}");
    }
}
