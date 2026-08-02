//! Bounded on-disk history of recorded config snapshots (Junos-style `rollback N`).
//!
//! [`crate::config_persister`] records each canonical, validated accepted
//! snapshot here on a best-effort basis after durable mutations, at boot, and
//! after successful SIGHUP refreshes. New v2 JSON entries retain normalized
//! TOML plus an integrity manifest for the accepted external-source roster;
//! they hash but do not archive referenced `.rpol` or dataset bytes.
//!
//! Legacy TOML and v2 JSON entries share one newest-first sequence namespace
//! and one [`HISTORY_LIMIT`]-entry bound under
//! `<runtime_state_dir>/config-history/`. Listing verifies and redacts both
//! generations. Rollback pins one exact mixed row, refuses unreadable rows,
//! and exposes a verified legacy or v2 payload to the provenance-aware caller.

#![deny(unsafe_code)]

pub(crate) mod v2;

#[cfg(test)]
use std::fs;
use std::io;
#[cfg(test)]
use std::io::Read as _;
use std::path::{Path, PathBuf};
#[cfg(test)]
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(test)]
use sha2::{Digest as _, Sha256};

use crate::config::AcceptedConfigSnapshot;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HistoryStatus {
    Recorded,
    LegacyTomlOnly,
    Unreadable,
}

#[derive(Debug, Clone)]
pub struct MixedHistoryEntry {
    pub index: usize,
    pub timestamp_unix_seconds: u64,
    pub sha256: Option<String>,
    pub source_sha256: Option<String>,
    pub status: HistoryStatus,
    pub summary: String,
    row: v2::StoredRow,
}

pub fn record_accepted(dir: &Path, snapshot: &AcceptedConfigSnapshot) -> io::Result<bool> {
    v2::record_v2(dir, snapshot.normalized_toml(), stored_manifest(snapshot))
}

fn stored_manifest(snapshot: &AcceptedConfigSnapshot) -> v2::Manifest {
    let manifest = snapshot.source_manifest();
    v2::Manifest {
        toml_sha256: manifest.toml_sha256,
        rpol_units: manifest
            .rpol_units
            .iter()
            .map(|unit| v2::RpolUnit {
                modules: unit
                    .modules
                    .iter()
                    .map(|module| v2::RpolModule {
                        path: v2::LosslessPath(
                            crate::config::source_provenance::lossless_path_bytes(&module.path).1,
                        ),
                        length: module.length,
                        sha256: module.sha256,
                        imports: module.imports.clone(),
                    })
                    .collect(),
            })
            .collect(),
        datasets: manifest
            .datasets
            .iter()
            .map(|dataset| v2::Dataset {
                name: dataset.name.clone(),
                kind: match dataset.kind {
                    rustbgpd_policy::datasets::DatasetKind::Prefix => v2::DatasetKind::Prefix,
                    rustbgpd_policy::datasets::DatasetKind::Asn => v2::DatasetKind::Asn,
                    rustbgpd_policy::datasets::DatasetKind::Community => v2::DatasetKind::Community,
                },
                path: v2::LosslessPath(
                    crate::config::source_provenance::lossless_path_bytes(&dataset.path).1,
                ),
                length: dataset.length,
                sha256: dataset.sha256,
            })
            .collect(),
    }
}

pub fn list_mixed(dir: &Path) -> io::Result<Vec<MixedHistoryEntry>> {
    v2::scan_mixed(dir).map(|rows| {
        rows.into_iter()
            .map(|row| MixedHistoryEntry {
                index: row.index,
                timestamp_unix_seconds: row.timestamp_unix_seconds,
                sha256: row.verified_sha256.map(|digest| v2::encode_hex(&digest)),
                source_sha256: row
                    .verified_source_sha256
                    .map(|digest| v2::encode_hex(&digest)),
                status: match row.status {
                    v2::StoredStatus::Recorded => HistoryStatus::Recorded,
                    v2::StoredStatus::LegacyTomlOnly => HistoryStatus::LegacyTomlOnly,
                    v2::StoredStatus::Unreadable => HistoryStatus::Unreadable,
                },
                summary: row
                    .redacted_summary
                    .clone()
                    .unwrap_or_else(|| "(unreadable config history entry)".to_string()),
                row,
            })
            .collect()
    })
}

#[cfg(test)]
pub fn read_mixed_legacy(dir: &Path, entry: &MixedHistoryEntry) -> io::Result<String> {
    if entry.status != HistoryStatus::LegacyTomlOnly {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "only legacy TOML-only history entries are rollback-readable",
        ));
    }
    match v2::read_mixed(dir, &entry.row)? {
        v2::StoredPayload::Legacy(toml) => Ok(toml),
        v2::StoredPayload::V2(_) => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "v2 config history rollback requires the external-source restore tranche",
        )),
    }
}

pub(crate) enum RollbackPayload {
    Legacy(String),
    V2 {
        normalized_toml: String,
        manifest: v2::Manifest,
        source_sha256: [u8; 32],
    },
}

/// Reopen the exact row captured by [`list_mixed`]. The v2 codec verifies the
/// pinned identity, envelope, TOML digest, manifest, and source digest before
/// returning this payload.
pub(crate) fn read_mixed_rollback(
    dir: &Path,
    entry: &MixedHistoryEntry,
) -> io::Result<RollbackPayload> {
    match v2::read_mixed(dir, &entry.row)? {
        v2::StoredPayload::Legacy(toml) => Ok(RollbackPayload::Legacy(toml)),
        v2::StoredPayload::V2(envelope) => Ok(RollbackPayload::V2 {
            normalized_toml: envelope.normalized_toml,
            manifest: envelope.manifest,
            source_sha256: envelope.source_sha256,
        }),
    }
}

pub(crate) fn verify_retained_snapshot(
    snapshot: &AcceptedConfigSnapshot,
    normalized_toml: &str,
    manifest: &v2::Manifest,
    source_sha256: [u8; 32],
) -> Result<(), String> {
    if snapshot.normalized_toml().as_bytes() != normalized_toml.as_bytes() {
        return Err("normalized TOML does not match the retained history snapshot".to_string());
    }
    let accepted_manifest = stored_manifest(snapshot);
    if &accepted_manifest != manifest {
        return Err(
            "external-source manifest does not match the retained history snapshot".to_string(),
        );
    }
    if snapshot.source_sha256() != source_sha256 {
        return Err(
            "external-source digest does not match the retained history snapshot".to_string(),
        );
    }
    Ok(())
}

/// Directory name under `runtime_state_dir`.
pub const HISTORY_DIR_NAME: &str = "config-history";

/// Number of recorded config snapshots retained on disk. Deliberately a
/// fixed bound, same as the crash-report retention cap: N recent configs,
/// no candidate-config database.
pub const HISTORY_LIMIT: usize = 20;

/// Per-entry read cap, mirroring the commit-confirm journal's sanity limit:
/// a config snapshot larger than this is corrupt, and loading it would only
/// risk an OOM.
const MAX_ENTRY_BYTES: u64 = 10 * 1024 * 1024;

/// Metadata for one retained config snapshot (no document contents).
#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoryEntry {
    /// 0 = newest config-history row, 1 = the next older row, …
    pub index: usize,
    /// Monotonic on-disk sequence number (newest = highest).
    pub sequence: u64,
    /// Unix seconds at record time.
    pub timestamp_unix_seconds: u64,
    /// Hex-encoded SHA-256 of the retained normalized TOML document only.
    pub sha256: String,
    /// Entry file path.
    pub path: PathBuf,
}

#[must_use]
pub fn history_dir(runtime_state_dir: &Path) -> PathBuf {
    runtime_state_dir.join(HISTORY_DIR_NAME)
}

#[must_use]
#[cfg(test)]
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
#[cfg(test)]
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
#[cfg(test)]
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
#[cfg(test)]
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
#[cfg(test)]
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
        .and_then(toml::Value::as_table)
        .map_or(0, toml::Table::len);
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

    const MAIN_RPOL: &str =
        "import \"lib.rpol\"\nimport \"a-child.rpol\"\npolicy outbound { term rest { accept } }\n";
    const LIB_RPOL: &str = "dataset asn-set customers\npolicy inbound {\n  term customer { if route.origin-as in customers { accept } }\n  term rest { reject }\n}\n";

    fn external_source_fixture(dir: &Path) -> PathBuf {
        fs::write(dir.join("policy.rpol"), MAIN_RPOL).unwrap();
        fs::write(dir.join("lib.rpol"), LIB_RPOL).unwrap();
        fs::write(
            dir.join("a-child.rpol"),
            "policy child { term rest { accept } }\n",
        )
        .unwrap();
        fs::write(
            dir.join("a-unit.rpol"),
            "policy second-unit { term rest { accept } }\n",
        )
        .unwrap();
        fs::write(dir.join("customers.txt"), "64500\n").unwrap();
        let config = crate::test_support::tier_authorized_uds_test_config(
            r#"
[global]
asn = 65000
router_id = "192.0.2.1"
listen_port = 179
[global.telemetry]
log_format = "json"
[policy]
rpol_files = ["policy.rpol", "a-unit.rpol"]
[policy.datasets.customers]
path = "customers.txt"
"#,
        );
        let path = dir.join("config.toml");
        fs::write(&path, config).unwrap();
        path
    }

    fn config_toml(asn: u32) -> String {
        format!(
            "[global]\nasn = {asn}\nrouter_id = \"10.0.0.1\"\nlisten_port = 179\n\n[[neighbors]]\naddress = \"10.0.0.2\"\nremote_asn = 65002\n"
        )
    }

    /// Red proof: dropping or reordering any rpol unit, import edge, dataset,
    /// kind, path, length, or digest in the storage conversion changes the
    /// stored roster or source digest and makes this full-fixture test fail.
    #[test]
    fn history_manifest_preserves_the_full_accepted_source_identity() {
        let dir = tempfile::tempdir().unwrap();
        let snapshot =
            AcceptedConfigSnapshot::load(&external_source_fixture(dir.path()), None).unwrap();
        let history = dir.path().join("history");

        // History must serialize the accepted snapshot, not reopen mutable
        // external sources after acceptance.
        for name in [
            "policy.rpol",
            "lib.rpol",
            "a-child.rpol",
            "a-unit.rpol",
            "customers.txt",
        ] {
            fs::remove_file(dir.path().join(name)).unwrap();
        }

        record_accepted(&history, &snapshot).unwrap();
        let row = v2::scan_mixed(&history).unwrap().remove(0);
        let v2::StoredPayload::V2(envelope) = v2::read_mixed(&history, &row).unwrap() else {
            panic!("accepted snapshot must produce a v2 history row");
        };

        assert_eq!(envelope.normalized_toml, snapshot.normalized_toml());
        assert_eq!(envelope.source_sha256, snapshot.source_sha256());
        assert_eq!(envelope.manifest.rpol_units.len(), 2);
        assert_eq!(envelope.manifest.rpol_units[0].modules.len(), 3);
        assert_eq!(envelope.manifest.rpol_units[0].modules[0].imports, [1, 2]);
        assert_eq!(envelope.manifest.datasets.len(), 1);
        assert_eq!(envelope.manifest.datasets[0].name, "customers");
        assert_eq!(envelope.manifest.datasets[0].kind, v2::DatasetKind::Asn);
    }

    /// Red proof: removing any of the three exact equality checks in
    /// `verify_retained_snapshot` makes its corresponding corrupted input
    /// succeed instead of producing the asserted stable category.
    #[test]
    fn retained_snapshot_verification_rejects_toml_manifest_and_source_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        let snapshot =
            AcceptedConfigSnapshot::load(&external_source_fixture(dir.path()), None).unwrap();
        let manifest = stored_manifest(&snapshot);
        let source_sha256 = snapshot.source_sha256();

        assert!(
            verify_retained_snapshot(&snapshot, "changed", &manifest, source_sha256)
                .unwrap_err()
                .contains("normalized TOML")
        );
        let mut changed_manifest = manifest.clone();
        changed_manifest.datasets[0].length += 1;
        assert!(
            verify_retained_snapshot(
                &snapshot,
                snapshot.normalized_toml(),
                &changed_manifest,
                source_sha256,
            )
            .unwrap_err()
            .contains("manifest")
        );
        let mut changed_source = source_sha256;
        changed_source[0] ^= 0xff;
        assert!(
            verify_retained_snapshot(
                &snapshot,
                snapshot.normalized_toml(),
                &manifest,
                changed_source,
            )
            .unwrap_err()
            .contains("source digest")
        );
    }

    /// Red proof: removing the status guard in `read_mixed_legacy` makes this
    /// deleted v2 payload reach the second read and return `NotFound` instead
    /// of the status-only refusal asserted here.
    #[test]
    fn mixed_legacy_reader_refuses_v2_before_reopening_the_payload() {
        let dir = tempfile::tempdir().unwrap();
        let content = crate::test_support::tier_authorized_uds_test_config(
            r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
log_format = "json"
"#,
        );
        let snapshot = AcceptedConfigSnapshot::from_config_for_test(
            crate::config::Config::load_toml_with_diagnostics(&content, "mixed reader test")
                .unwrap(),
        );
        record_accepted(dir.path(), &snapshot).unwrap();
        let entry = list_mixed(dir.path()).unwrap().remove(0);
        std::fs::remove_file(&entry.row.path).unwrap();

        let error = read_mixed_legacy(dir.path(), &entry).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
        assert_eq!(
            error.to_string(),
            "only legacy TOML-only history entries are rollback-readable"
        );
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
        // …and a boot-time re-record of the same config deduplicates
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
    fn summarize_counts_policy_definition_tables() {
        let toml_str = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[policy.definitions.customer-in]

[policy.definitions.customer-out]
"#;

        let summary = summarize(toml_str);
        assert!(summary.contains("2 policy definition(s)"), "{summary}");
    }

    #[test]
    fn summary_never_leaks_secret_material() {
        let toml_str = "[global]\nasn = 65001\nrouter_id = \"10.0.0.1\"\nlisten_port = 179\n\n[[neighbors]]\naddress = \"10.0.0.2\"\nremote_asn = 65002\nmd5_password = \"super-secret\"\n";
        let summary = summarize(toml_str);
        assert!(!summary.contains("super-secret"), "{summary}");
    }
}
