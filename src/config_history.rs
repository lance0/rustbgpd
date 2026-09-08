//! Bounded on-disk history of recorded config snapshots (Junos-style `rollback N`).
//!
//! [`crate::config_persister`] records each canonical, validated accepted
//! snapshot here on a best-effort basis after durable mutations, at boot, and
//! after successful SIGHUP refreshes. New v2 JSON entries retain normalized
//! TOML plus an integrity manifest for the accepted external-source roster;
//! they hash but do not archive referenced `.rpol` or dataset bytes.
//!
//! V2 payloads and bounded metadata-only v3 rows share one chronology.
//! Retired TOML is ignored and retained.

#![deny(unsafe_code)]

pub(crate) mod v2;
pub(crate) mod v3;

use std::io;
use std::path::{Path, PathBuf};

use crate::config::AcceptedConfigSnapshot;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HistoryStatus {
    Recorded,
    MetadataOnly,
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
    pub normalized_toml_bytes: Option<u64>,
    pub metadata_only_reason: Option<String>,
    row: v2::StoredRow,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RecordOutcome {
    Recorded { evicted: usize },
    Deduplicated { evicted: usize },
}

pub fn record_accepted(dir: &Path, snapshot: &AcceptedConfigSnapshot) -> io::Result<RecordOutcome> {
    v2::record_snapshot(dir, snapshot).map(|(recorded, evicted)| {
        if recorded {
            RecordOutcome::Recorded { evicted }
        } else {
            RecordOutcome::Deduplicated { evicted }
        }
    })
}

pub(crate) fn stored_manifest(snapshot: &AcceptedConfigSnapshot) -> v2::Manifest {
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
                    v2::StoredStatus::MetadataOnly => HistoryStatus::MetadataOnly,
                    v2::StoredStatus::Unreadable => HistoryStatus::Unreadable,
                },
                normalized_toml_bytes: row.normalized_toml_bytes,
                metadata_only_reason: row.metadata_only_reason.clone(),
                summary: row
                    .redacted_summary
                    .clone()
                    .unwrap_or_else(|| "(unreadable config history entry)".to_string()),
                row,
            })
            .collect()
    })
}

pub(crate) enum RollbackPayload {
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
    if entry.status == HistoryStatus::MetadataOnly {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "metadata-only history has no rollback payload",
        ));
    }
    match v2::read_mixed(dir, &entry.row)? {
        v2::StoredPayload::V2(envelope) => Ok(RollbackPayload::V2 {
            normalized_toml: envelope.normalized_toml,
            manifest: envelope.manifest,
            source_sha256: envelope.source_sha256,
        }),
        v2::StoredPayload::V3(_) => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "metadata-only history has no rollback payload",
        )),
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

#[must_use]
pub fn history_dir(runtime_state_dir: &Path) -> PathBuf {
    runtime_state_dir.join(HISTORY_DIR_NAME)
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

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
            panic!("expected v2")
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

    #[test]
    fn record_outcome_is_explicit_and_oversize_records_metadata() {
        // An oversized accepted snapshot adds one metadata row and identical
        // subsequent acceptance deduplicates without retaining its payload.
        let dir = tempfile::tempdir().unwrap();
        let small_toml = crate::test_support::tier_authorized_uds_test_config(
            r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179
[global.telemetry]
log_format = "json"
[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
"#,
        );
        let small = AcceptedConfigSnapshot::from_config_for_test(
            crate::config::Config::load_toml_with_diagnostics(&small_toml, "small").unwrap(),
        );
        assert_eq!(
            record_accepted(dir.path(), &small).unwrap(),
            RecordOutcome::Recorded { evicted: 0 }
        );
        assert_eq!(
            record_accepted(dir.path(), &small).unwrap(),
            RecordOutcome::Deduplicated { evicted: 0 }
        );
        let roster = || {
            let mut entries = fs::read_dir(dir.path())
                .unwrap()
                .map(|entry| {
                    let entry = entry.unwrap();
                    (entry.file_name(), fs::read(entry.path()).unwrap())
                })
                .collect::<Vec<_>>();
            entries.sort_by(|left, right| left.0.cmp(&right.0));
            entries
        };
        let roster_before = roster();

        let large_toml = small_toml.replacen(
            "remote_asn = 65002\n",
            &format!(
                "remote_asn = 65002\ndescription = {:?}\n",
                "x".repeat(v2::MAX_TOML + 1)
            ),
            1,
        );
        let large = AcceptedConfigSnapshot::from_config_for_test(
            crate::config::Config::load_toml_with_diagnostics(&large_toml, "oversize").unwrap(),
        );
        assert!(large.normalized_toml().len() > v2::MAX_TOML);
        assert_eq!(
            record_accepted(dir.path(), &large).unwrap(),
            RecordOutcome::Recorded { evicted: 0 }
        );
        let roster_after = roster();
        assert_eq!(roster_after.len(), roster_before.len() + 1);
        let entries = list_mixed(dir.path()).unwrap();
        assert_eq!(entries[0].status, HistoryStatus::MetadataOnly);
        assert!(entries[0].summary.len() <= v3::MAX_SUMMARY);
        assert_eq!(
            record_accepted(dir.path(), &large).unwrap(),
            RecordOutcome::Deduplicated { evicted: 0 }
        );
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

    /// Load-bearing retirement proof: old TOML-shaped files are ignored and retained.
    #[test]
    fn retired_toml_history_is_ignored_and_retained() {
        let dir = tempfile::tempdir().unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let path = dir
            .path()
            .join(format!("0000000001-1-{}.toml", "0".repeat(64)));
        let bytes = b"retired history bytes";
        fs::write(&path, bytes).unwrap();
        assert!(list_mixed(dir.path()).unwrap().is_empty());
        assert_eq!(fs::read(path).unwrap(), bytes);
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
    #[test]
    fn normalized_exact_ten_mib_remains_v2_and_plus_one_is_metadata_only() {
        let dir = tempfile::tempdir().unwrap();
        let toml = crate::test_support::tier_authorized_uds_test_config(
            &(config_toml(65001) + "\n[global.telemetry]\nlog_format = \"json\"\n"),
        );
        let mut config =
            crate::config::Config::load_toml_with_diagnostics(&toml, "boundary").unwrap();
        config.neighbors[0].description = Some(String::new());
        let base = AcceptedConfigSnapshot::from_config_for_test(config.clone())
            .normalized_toml()
            .len();
        config.neighbors[0].description = Some("x".repeat(v2::MAX_TOML - base));
        let exact = AcceptedConfigSnapshot::from_config_for_test(config.clone());
        assert_eq!(exact.normalized_toml().len(), v2::MAX_TOML);
        record_accepted(dir.path(), &exact).unwrap();
        config.neighbors[0].description.as_mut().unwrap().push('x');
        let large = AcceptedConfigSnapshot::from_config_for_test(config);
        assert_eq!(large.normalized_toml().len(), v2::MAX_TOML + 1);
        record_accepted(dir.path(), &large).unwrap();
        let entries = list_mixed(dir.path()).unwrap();
        assert_eq!(entries[0].status, HistoryStatus::MetadataOnly);
        assert_eq!(
            entries[0].normalized_toml_bytes,
            Some((v2::MAX_TOML + 1) as u64)
        );
        assert_eq!(
            entries[0].sha256.as_deref(),
            Some(v2::encode_hex(&large.source_manifest().toml_sha256).as_str())
        );
        assert_eq!(
            entries[0].source_sha256.as_deref(),
            Some(v2::encode_hex(&large.source_sha256()).as_str())
        );
        assert_eq!(entries[0].summary, summarize(exact.normalized_toml()));
        assert!(read_mixed_rollback(dir.path(), &entries[0]).is_err());
        assert_eq!(entries[1].status, HistoryStatus::Recorded);
        assert!(read_mixed_rollback(dir.path(), &entries[1]).is_ok());
        let bytes = fs::read(&entries[0].row.path).unwrap();
        assert!(bytes.len() <= v3::MAX_ENVELOPE);
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert!(json.get("normalized_toml").is_none() && json.get("manifest").is_none());
        assert!(!entries[0].summary.contains("xxxx"));
    }
    #[test]
    fn oversized_metadata_captures_source_identity_without_reopening_sources() {
        use std::fmt::Write as _;
        let dir = tempfile::tempdir().unwrap();
        let path = external_source_fixture(dir.path());
        let mut text = fs::read_to_string(&path).unwrap();
        write!(
            text,
            "\n[[neighbors]]\naddress = \"192.0.2.2\"\nremote_asn = 65002\ndescription = {:?}\n",
            "x".repeat(v2::MAX_TOML)
        )
        .unwrap();
        fs::write(&path, text).unwrap();
        let previous = AcceptedConfigSnapshot::load(&path, None).unwrap();
        fs::write(dir.path().join("customers.txt"), "64500\n64501\n").unwrap();
        let current = AcceptedConfigSnapshot::load(&path, None).unwrap();
        assert_eq!(previous.normalized_toml(), current.normalized_toml());
        assert_ne!(previous.source_sha256(), current.source_sha256());
        for name in [
            "policy.rpol",
            "lib.rpol",
            "a-child.rpol",
            "a-unit.rpol",
            "customers.txt",
        ] {
            fs::remove_file(dir.path().join(name)).unwrap();
        }
        let history = dir.path().join("history");
        record_accepted(&history, &previous).unwrap();
        assert_eq!(
            record_accepted(&history, &current).unwrap(),
            RecordOutcome::Recorded { evicted: 0 }
        );
        let entries = list_mixed(&history).unwrap();
        assert_eq!(entries.len(), 2);
        assert!(
            entries
                .iter()
                .all(|row| row.status == HistoryStatus::MetadataOnly)
        );
        assert_eq!(
            entries[0].source_sha256,
            Some(v2::encode_hex(&current.source_sha256()))
        );
        assert_eq!(
            entries[1].source_sha256,
            Some(v2::encode_hex(&previous.source_sha256()))
        );
        assert_eq!(entries[0].sha256, entries[1].sha256);
        assert_eq!(entries[0].summary, entries[1].summary);
    }

    /// Run this allocator receipt alone, after constructing accepted snapshots:
    /// ```console
    /// cargo test -p rustbgpd --bin rustbgpd --no-default-features --features dhat-heap metadata_history_allocation -- --ignored --test-threads=1
    /// ```
    #[cfg(feature = "dhat-heap")]
    #[test]
    #[ignore = "isolated dhat allocation receipt; requires --features dhat-heap and --test-threads=1"]
    fn metadata_history_allocation_is_independent_of_oversized_payloads() {
        let dir = tempfile::tempdir().unwrap();
        let toml = crate::test_support::tier_authorized_uds_test_config(
            &(config_toml(65001) + "\n[global.telemetry]\nlog_format = \"json\"\n"),
        );
        let mut config =
            crate::config::Config::load_toml_with_diagnostics(&toml, "allocation").unwrap();
        config.neighbors[0].description = Some("x".repeat(v2::MAX_TOML));
        let first = AcceptedConfigSnapshot::from_config_for_test(config.clone());
        config.neighbors[0].description.as_mut().unwrap().push('x');
        let second = AcceptedConfigSnapshot::from_config_for_test(config);
        for n in 0..20 {
            record_accepted(dir.path(), if n % 2 == 0 { &first } else { &second }).unwrap();
        }
        let _profiler = dhat::Profiler::builder()
            .testing()
            .trim_backtraces(Some(0))
            .build();
        assert_eq!(
            record_accepted(dir.path(), &first).unwrap(),
            RecordOutcome::Recorded { evicted: 1 }
        );
        let rows = list_mixed(dir.path()).unwrap();
        assert_eq!(rows.len(), 20);
        let stats = dhat::HeapStats::get();
        // Includes twenty-row scans, revalidation, summary strings, encoding,
        // and publication. A Config/TOML/manifest clone or reparse exceeds it.
        dhat::assert!(stats.max_bytes < 256 * 1024);
        dhat::assert!(stats.total_bytes < 512 * 1024);
        eprintln!(
            "metadata history allocation: peak={} total={}",
            stats.max_bytes, stats.total_bytes
        );
    }
}
