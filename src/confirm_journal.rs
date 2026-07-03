//! Durable commit-confirm revert journal (ADR-0076 Decision 6).
//!
//! A commit-confirmed config transaction persists the candidate to the config
//! file at commit time, so without on-disk revert state a daemon restart inside
//! the confirm window would silently make the unconfirmed candidate permanent
//! ("confirmed-by-restart") — defeating the whole point of commit-confirmed for
//! a config bad enough to crash the daemon. This module journals the pre-commit
//! config snapshot to `<runtime_state_dir>/commit-confirm-journal.json` BEFORE
//! the candidate commits, and boot ([`boot_revert_check`]) reverts to that
//! snapshot whenever an unconfirmed journal is found.
//!
//! Boot reverts on ANY unconfirmed journal regardless of remaining confirm
//! time: a restart mid-window means the operator's confirming session and the
//! in-memory timer are gone, and resuming a half-elapsed timer in a fresh
//! process invites split-brain between the operator's view and the daemon's.
//! This matches NETCONF (RFC 6241 §8.4) cancellation of a confirmed commit on
//! session loss.

#![deny(unsafe_code)]

use std::fs::{self, File};
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::config::Config;

/// Journal file name under `runtime_state_dir`.
pub const JOURNAL_FILE_NAME: &str = "commit-confirm-journal.json";

/// On-disk revert state for one pending commit-confirmed transaction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfirmJournal {
    /// Operator-chosen confirm handle, for the boot-revert log line.
    pub confirm_id: String,
    /// Informational only — boot revert ignores it (see module docs).
    pub deadline_unix_seconds: u64,
    /// TOML snapshot of the running config captured before the candidate
    /// committed; this is what boot restores.
    pub rollback_toml: String,
}

/// Boot-revert outcome consumed by `main`.
#[derive(Debug)]
pub struct BootRevert {
    /// The parsed pre-transaction config the daemon must boot from.
    pub config: Box<Config>,
    pub notice: BootRevertNotice,
}

/// The operator-facing facts of a boot revert (for the banner, log, metric).
#[derive(Debug, Clone)]
pub struct BootRevertNotice {
    pub confirm_id: String,
    /// Where the unconfirmed candidate was saved aside.
    pub backup_path: PathBuf,
}

#[must_use]
pub fn journal_path(runtime_state_dir: &Path) -> PathBuf {
    runtime_state_dir.join(JOURNAL_FILE_NAME)
}

/// Atomically persist the journal: write temp file, fsync it, rename over the
/// journal path, fsync the directory. Called BEFORE the candidate commits, so
/// a crash at any point either leaves no journal (nothing committed yet) or a
/// complete journal.
pub fn write(path: &Path, journal: &ConfirmJournal) -> io::Result<()> {
    let parent = parent_dir(path)?;
    fs::create_dir_all(parent)?;
    let encoded = serde_json::to_vec_pretty(journal).map_err(io::Error::other)?;
    write_atomic(path, &encoded)
}

/// Remove the journal and fsync the directory. A missing journal is success
/// (confirm after a boot revert already consumed it, or none was written).
pub fn remove(path: &Path) -> io::Result<()> {
    match fs::remove_file(path) {
        Ok(()) => fsync_dir(parent_dir(path)?),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

/// Boot-time check, run BEFORE the daemon adopts the on-disk config.
///
/// - No journal → `Ok(None)`: normal boot.
/// - Readable journal with a usable embedded previous config → revert: the
///   unconfirmed candidate config file is saved aside to
///   `<config_path>.unconfirmed`, the previous config is restored to
///   `config_path` (atomic write), the journal is removed, and the parsed
///   previous config is returned for the daemon to boot from.
/// - Journal present but unreadable/torn, or its embedded previous config is
///   unusable, or the revert writes fail → `Err`: boot must REFUSE with the
///   returned message (fail closed — never silently proceed with the
///   unconfirmed candidate).
pub fn boot_revert_check(
    journal_path: &Path,
    config_path: &Path,
) -> Result<Option<BootRevert>, String> {
    let raw = match fs::read_to_string(journal_path) {
        Ok(raw) => raw,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(refuse_message(
                journal_path,
                config_path,
                &format!("the journal cannot be read: {error}"),
            ));
        }
    };
    let journal: ConfirmJournal = serde_json::from_str(&raw).map_err(|error| {
        refuse_message(
            journal_path,
            config_path,
            &format!("the journal is torn or corrupt: {error}"),
        )
    })?;
    let config =
        Config::load_toml_with_diagnostics(&journal.rollback_toml, "commit-confirm revert journal")
            .map_err(|diagnostic| {
                refuse_message(
                    journal_path,
                    config_path,
                    &format!("the journaled pre-transaction config is unusable:\n{diagnostic}"),
                )
            })?;

    // Save the unconfirmed candidate aside for the operator, then restore the
    // previous config atomically. Order matters: the rename preserves the
    // candidate bytes before anything overwrites them.
    let backup_path = unconfirmed_backup_path(config_path);
    match fs::rename(config_path, &backup_path) {
        Ok(()) => {}
        // A missing config file is unexpected mid-revert but not a reason to
        // refuse restoring a known-good config.
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(refuse_message(
                journal_path,
                config_path,
                &format!(
                    "failed to save the unconfirmed candidate aside to {}: {error}",
                    backup_path.display()
                ),
            ));
        }
    }
    write_atomic(config_path, journal.rollback_toml.as_bytes()).map_err(|error| {
        refuse_message(
            journal_path,
            config_path,
            &format!("failed to restore the pre-transaction config: {error}"),
        )
    })?;
    remove(journal_path).map_err(|error| {
        refuse_message(
            journal_path,
            config_path,
            &format!(
                "the config file was reverted, but the journal could not be removed: {error}; \
                 delete the journal manually before restarting"
            ),
        )
    })?;
    Ok(Some(BootRevert {
        config: Box::new(config),
        notice: BootRevertNotice {
            confirm_id: journal.confirm_id,
            backup_path,
        },
    }))
}

/// `<config_path>.unconfirmed` — one well-known slot, overwritten by a later
/// boot revert; the loud boot log names it each time.
fn unconfirmed_backup_path(config_path: &Path) -> PathBuf {
    let mut name = config_path.as_os_str().to_os_string();
    name.push(".unconfirmed");
    PathBuf::from(name)
}

fn refuse_message(journal_path: &Path, config_path: &Path, detail: &str) -> String {
    format!(
        "refusing to boot: a commit-confirmed config transaction revert journal exists at {journal} \
         (meaning the last run stopped inside a confirm window, so the on-disk config {config} may be \
         an unconfirmed candidate), but {detail}. Inspect {journal} and {config}; to boot the current \
         on-disk config anyway, delete the journal.",
        journal = journal_path.display(),
        config = config_path.display(),
    )
}

/// Write temp file + fsync + rename + fsync dir.
fn write_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let parent = parent_dir(path)?;
    let mut tmp = path.as_os_str().to_os_string();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);
    let mut file = File::create(&tmp)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    fs::rename(&tmp, path)?;
    fsync_dir(parent)
}

fn parent_dir(path: &Path) -> io::Result<&Path> {
    path.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("path {} has no parent directory", path.display()),
        )
    })
}

fn fsync_dir(dir: &Path) -> io::Result<()> {
    File::open(dir)?.sync_all()
}

#[cfg(test)]
mod tests {
    use super::*;

    const PREVIOUS_TOML: &str = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"
"#;

    fn journal() -> ConfirmJournal {
        ConfirmJournal {
            confirm_id: "deploy-1".to_string(),
            deadline_unix_seconds: 1234,
            rollback_toml: PREVIOUS_TOML.to_string(),
        }
    }

    #[test]
    fn write_read_roundtrip_and_remove() {
        let dir = tempfile::tempdir().unwrap();
        let path = journal_path(dir.path());
        write(&path, &journal()).unwrap();
        let read: ConfirmJournal =
            serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(read, journal());
        assert!(
            !path.with_extension("json.tmp").exists(),
            "temp file must not linger"
        );
        remove(&path).unwrap();
        assert!(!path.exists());
        // Removing an absent journal is success.
        remove(&path).unwrap();
    }

    #[test]
    fn write_creates_missing_state_dir() {
        let dir = tempfile::tempdir().unwrap();
        let path = journal_path(&dir.path().join("nested/runtime"));
        write(&path, &journal()).unwrap();
        assert!(path.exists());
    }

    #[test]
    fn boot_check_without_journal_is_normal_boot() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("rustbgpd.toml");
        fs::write(&config_path, "candidate").unwrap();
        let outcome = boot_revert_check(&journal_path(dir.path()), &config_path).unwrap();
        assert!(outcome.is_none());
        assert_eq!(fs::read_to_string(&config_path).unwrap(), "candidate");
    }

    #[test]
    fn boot_check_reverts_unconfirmed_journal() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("rustbgpd.toml");
        fs::write(&config_path, "unconfirmed candidate bytes").unwrap();
        let path = journal_path(dir.path());
        write(&path, &journal()).unwrap();

        let revert = boot_revert_check(&path, &config_path)
            .unwrap()
            .expect("journal must trigger revert");
        assert_eq!(revert.notice.confirm_id, "deploy-1");
        assert_eq!(revert.config.global.asn, 65001);
        // Config file restored to the journaled previous config.
        assert_eq!(fs::read_to_string(&config_path).unwrap(), PREVIOUS_TOML);
        // Unconfirmed candidate saved aside verbatim.
        assert_eq!(
            fs::read_to_string(&revert.notice.backup_path).unwrap(),
            "unconfirmed candidate bytes"
        );
        // Journal consumed — the next boot is normal.
        assert!(!path.exists());
        assert!(
            boot_revert_check(&path, &config_path).unwrap().is_none(),
            "second boot must not revert again"
        );
    }

    #[test]
    fn boot_check_reverts_regardless_of_deadline_remaining() {
        // Deadline far in the future — revert must fire anyway (the
        // confirming session died with the old process).
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("rustbgpd.toml");
        fs::write(&config_path, "candidate").unwrap();
        let path = journal_path(dir.path());
        write(
            &path,
            &ConfirmJournal {
                deadline_unix_seconds: u64::MAX,
                ..journal()
            },
        )
        .unwrap();
        assert!(boot_revert_check(&path, &config_path).unwrap().is_some());
    }

    #[test]
    fn boot_check_refuses_on_torn_journal() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("rustbgpd.toml");
        fs::write(&config_path, "candidate").unwrap();
        let path = journal_path(dir.path());
        fs::create_dir_all(dir.path()).unwrap();
        // Truncated mid-JSON.
        fs::write(&path, "{\"confirm_id\": \"deploy-1\", \"dead").unwrap();

        let message = boot_revert_check(&path, &config_path).unwrap_err();
        assert!(message.contains("refusing to boot"), "{message}");
        assert!(message.contains(&*path.to_string_lossy()), "{message}");
        assert!(
            message.contains(&*config_path.to_string_lossy()),
            "{message}"
        );
        // Fail closed: nothing touched.
        assert_eq!(fs::read_to_string(&config_path).unwrap(), "candidate");
        assert!(path.exists());
    }

    #[test]
    fn boot_check_refuses_on_unusable_embedded_config() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("rustbgpd.toml");
        fs::write(&config_path, "candidate").unwrap();
        let path = journal_path(dir.path());
        write(
            &path,
            &ConfirmJournal {
                rollback_toml: "this is not a valid config".to_string(),
                ..journal()
            },
        )
        .unwrap();

        let message = boot_revert_check(&path, &config_path).unwrap_err();
        assert!(message.contains("refusing to boot"), "{message}");
        assert!(message.contains("unusable"), "{message}");
        assert_eq!(fs::read_to_string(&config_path).unwrap(), "candidate");
        assert!(path.exists());
    }

    #[test]
    fn boot_check_reverts_even_if_candidate_config_file_is_missing() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("rustbgpd.toml");
        let path = journal_path(dir.path());
        write(&path, &journal()).unwrap();

        let revert = boot_revert_check(&path, &config_path).unwrap().unwrap();
        assert_eq!(fs::read_to_string(&config_path).unwrap(), PREVIOUS_TOML);
        assert!(!revert.notice.backup_path.exists());
    }
}
