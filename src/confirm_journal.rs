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

pub(crate) mod v2;

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read as _, Write as _};
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::config::Config;

/// Journal file name under `runtime_state_dir`.
pub const JOURNAL_FILE_NAME: &str = "commit-confirm-journal.json";

/// Sanity cap on the on-disk journal size. A well-formed journal is a small
/// config snapshot; a journal larger than this is corrupt, and loading it would
/// only risk an OOM during boot deserialization, so it is refused before parse
/// (LAN-204).
const MAX_JOURNAL_BYTES: u64 = 10 * 1024 * 1024;

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
    /// Set when a live abort/timeout rollback of this transaction FAILED
    /// (LAN-277 three-way inconsistency: runtime part-candidate, disk holds
    /// the candidate, journal holds the pre-transaction snapshot). Boot
    /// diagnostics use it to say "a rollback already failed; the state
    /// before this restart was uncertain" instead of the generic
    /// never-confirmed message. Defaults to `false` so journals written by
    /// older versions still parse.
    #[serde(default)]
    pub rollback_failed: bool,
}

/// Boot-revert outcome consumed by `main`.
#[derive(Debug)]
pub struct BootRevert {
    /// The parsed pre-transaction config the daemon must boot from.
    pub config: Box<Config>,
    pub notice: BootRevertNotice,
}

/// The operator-facing facts of a boot revert (for the banner, log, metric).
///
/// A `BootRevert` is only produced when the revert fully succeeded — config
/// restored AND journal consumed. A journal-cleanup failure fails startup
/// (LAN-219), so there is no "booted anyway" residual state to carry here.
#[derive(Debug, Clone)]
pub struct BootRevertNotice {
    pub confirm_id: String,
    /// Where the unconfirmed candidate was saved aside.
    pub backup_path: PathBuf,
    /// The journal recorded a failed live rollback of this transaction: the
    /// state the daemon was in before this restart is uncertain (the banner
    /// says so), even though the boot revert itself succeeded.
    pub rollback_failed: bool,
    /// V2 locator-carried target paths are sensitive and must not be rendered
    /// by ordinary startup logs or banners.
    pub redact_paths: bool,
    /// V2 journal cleanup follows the durable terminal locator removal and is
    /// warning-only.  V1 never reports this state because its cleanup remains
    /// part of its legacy terminal operation.
    pub journal_cleanup_failed: bool,
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
///   `<config_path>.unconfirmed` (never overwriting an existing one), the
///   previous config is restored to `config_path` (atomic write), the journal
///   is removed, and the parsed previous config is returned to boot from.
/// - Journal present but not a regular file, unreadable/torn/oversized, its
///   embedded previous config is unusable, or the revert write fails → `Err`:
///   boot REFUSES (fail closed — never silently proceed with the unconfirmed
///   candidate).
/// - Revert write SUCCEEDED but the journal cannot then be removed → `Err`
///   (LAN-219): boot REFUSES rather than proceeding, because a daemon that
///   cannot prove the revert intent was consumed would silently re-revert every
///   config the operator applies on each restart. The recovery copy at
///   `<config_path>.unconfirmed` is preserved; the next boot fails identically
///   until the operator removes/fixes the journal.
#[expect(
    clippy::too_many_lines,
    reason = "the legacy v1 boot-revert lane remains intentionally unchanged and linear"
)]
pub fn boot_revert_check(
    journal_path: &Path,
    config_path: &Path,
) -> Result<Option<BootRevert>, String> {
    match v2::inspect_locator_absent_journal(journal_path) {
        Ok(v2::LocatorAbsentJournal::Absent | v2::LocatorAbsentJournal::V2ResidueRemoved) => {
            return Ok(None);
        }
        Ok(v2::LocatorAbsentJournal::LegacyV1) => {}
        Err(error) => {
            return Err(format!(
                "refusing to boot: locator-absent commit-confirm journal state is unsafe or invalid ({:?}: {error}); inspect the owner-only runtime-state journal",
                error.kind(),
            ));
        }
    }
    // Resolve a symlinked config up front (operators legitimately symlink
    // configs into place): every operation below — save-aside, restore
    // write, refusal messages — then targets the REAL file, so the revert
    // updates the file the symlink points at and the symlink itself
    // survives, instead of the restore replacing the symlink with a regular
    // file (or landing wherever a later-swapped symlink points). A plain
    // path canonicalizes to itself; a missing config (crash resume) is used
    // as-is.
    let resolved_config;
    let config_path = match fs::canonicalize(config_path) {
        Ok(real) => {
            resolved_config = real;
            resolved_config.as_path()
        }
        Err(_) => config_path,
    };
    // LAN-221: the journal must be a regular file. A FIFO/socket/device reports
    // `len() == 0` (silently bypassing the size guard) and then blocks or reads
    // unbounded; a directory is nonsense. Reject anything non-regular before
    // opening it.
    let meta = match fs::metadata(journal_path) {
        Ok(meta) => meta,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(refuse_message(
                journal_path,
                config_path,
                &format!("the journal cannot be read: {error}"),
            ));
        }
    };
    if !meta.is_file() {
        return Err(refuse_message(
            journal_path,
            config_path,
            "the journal is not a regular file (a directory, FIFO, socket, or device) — refusing to read it",
        ));
    }
    // Size guard BEFORE read (LAN-204): a corrupt journal with a giant
    // `rollback_toml` must not OOM deserialize at boot.
    if meta.len() > MAX_JOURNAL_BYTES {
        return Err(refuse_message(
            journal_path,
            config_path,
            &format!(
                "the journal is {} bytes, exceeding the {MAX_JOURNAL_BYTES}-byte sanity limit — refusing to load a journal this large",
                meta.len()
            ),
        ));
    }
    // Bounded read (LAN-221 defense-in-depth): even if `metadata().len()` lied
    // or the file grew after the size guard, never buffer more than the cap.
    let raw = match read_journal_bounded(journal_path) {
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

    // Preserve the unconfirmed candidate for the operator, then restore the
    // previous config. `candidate_saved` is true only when THIS call moved the
    // config aside, so the write-failure path below knows it may put it back.
    let backup_path = unconfirmed_backup_path(config_path);
    let candidate_saved = save_candidate_aside(config_path, &backup_path, journal_path)?;
    if let Err(error) = write_atomic(config_path, journal.rollback_toml.as_bytes()) {
        // The write failed. If we moved the config aside this call, put it back
        // so `config_path` is not left missing (LAN-207) — moving back only our
        // own fresh backup, never a pre-existing `.unconfirmed`. The refusal
        // message is state-aware about whether the config survived (LAN-220).
        if candidate_saved {
            let _ = fs::rename(&backup_path, config_path);
        }
        return Err(refuse_message(
            journal_path,
            config_path,
            &format!("failed to restore the pre-transaction config: {error}"),
        ));
    }
    // Config restored on disk. LAN-219: we must PROVE the revert intent was
    // consumed. If the journal cannot be removed, FAIL CLOSED — booting anyway
    // turns a filesystem fault into silent, repeated reverting of every config
    // the operator applies. The recovery copy already exists idempotently (moved
    // aside above, or preserved from a prior attempt), so refuse without
    // touching it; the next boot fails the same way until the journal is fixed.
    if let Err(error) = remove(journal_path) {
        return Err(refuse_after_revert_message(
            journal_path,
            config_path,
            &backup_path,
            &error,
        ));
    }
    Ok(Some(BootRevert {
        config: Box::new(config),
        notice: BootRevertNotice {
            confirm_id: journal.confirm_id,
            backup_path,
            rollback_failed: journal.rollback_failed,
            redact_paths: false,
            journal_cleanup_failed: false,
        },
    }))
}

/// Read the journal with a hard byte cap (LAN-221). Even if `metadata().len()`
/// under-reports (a lying special file slipped past `is_file`, or the file grew
/// after the size guard), never buffer more than the sanity cap.
fn read_journal_bounded(path: &Path) -> io::Result<String> {
    let mut reader = File::open(path)?.take(MAX_JOURNAL_BYTES + 1);
    let mut buf = String::new();
    reader.read_to_string(&mut buf)?;
    if buf.len() as u64 > MAX_JOURNAL_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("the journal exceeds the {MAX_JOURNAL_BYTES}-byte sanity limit"),
        ));
    }
    Ok(buf)
}

/// Move the current on-disk config aside to `backup_path` so the operator keeps
/// the unconfirmed candidate, then let the caller overwrite the config with the
/// rollback. IDEMPOTENCY INVARIANT (LAN-208/LAN-219): never overwrite an
/// existing `.unconfirmed` — on a restart loop it already holds the REAL saved
/// candidate, and the config file is about to be overwritten anyway. Returns
/// whether THIS call moved the config aside (so the caller may move it back on a
/// write failure — it, and only it, created that backup).
fn save_candidate_aside(
    config_path: &Path,
    backup_path: &Path,
    journal_path: &Path,
) -> Result<bool, String> {
    // Atomic no-clobber move (LAN-224). A bare `try_exists` + `rename` is a
    // check-then-act race: `rename(2)` overwrites the destination unconditionally,
    // so a `.unconfirmed` created between the check and the rename gets clobbered.
    // `hard_link` fails atomically with `AlreadyExists` if the backup exists (so we
    // never overwrite it); otherwise the backup now shares config's inode and
    // `remove_file` completes the move — same "config moved to backup" semantics as
    // the old rename, but with a truly atomic no-clobber guard.
    let save_error = |error: &io::Error| {
        refuse_message(
            journal_path,
            config_path,
            &format!(
                "failed to save the unconfirmed candidate aside to {}: {error}",
                backup_path.display()
            ),
        )
    };
    match fs::hard_link(config_path, backup_path) {
        Ok(()) => {}
        // Backup already holds the REAL saved candidate — never clobber it.
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => return Ok(false),
        // Config missing mid-revert (crash resume): nothing to save aside — the
        // recovery copy, if one was ever made, is already at backup.
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(save_error(&error)),
    }
    // Backup is in place; drop the original to finish the move. If this fails we
    // fail closed (Err) — the backup already holds the candidate bytes, config is
    // untouched, and the next boot sees the backup and no-clobbers idempotently.
    // ponytail: two syscalls vs one; switch to renameat2(RENAME_NOREPLACE) only if
    // the config dir ever lives on a filesystem without hard-link support.
    fs::remove_file(config_path).map_err(|error| save_error(&error))?;
    Ok(true)
}

/// `<config_path>.unconfirmed` — one well-known slot, written once and preserved
/// across restarts (never overwritten once it holds a candidate — LAN-208); the
/// loud boot log names it.
fn unconfirmed_backup_path(config_path: &Path) -> PathBuf {
    let mut name = config_path.as_os_str().to_os_string();
    name.push(".unconfirmed");
    PathBuf::from(name)
}

/// Refusal for a journal that could NOT be fully applied (not a regular file,
/// torn/oversized/unusable, or a failed save-aside/restore). State-aware on
/// whether the config file survived (LAN-220): advising the operator to `rm`
/// the journal and boot the on-disk config is wrong when that file is missing.
fn refuse_message(journal_path: &Path, config_path: &Path, detail: &str) -> String {
    let journal = journal_path.display();
    let config = config_path.display();
    let backup = unconfirmed_backup_path(config_path);
    let backup = backup.display();
    // Treat an errored existence check as "missing": the safe assumption is to
    // NOT advise booting a file we cannot confirm is present.
    if config_path.try_exists().unwrap_or(false) {
        format!(
            "refusing to boot: a commit-confirmed config transaction revert journal exists at {journal} \
             (meaning the last run stopped inside a confirm window, so the on-disk config {config} may be \
             an unconfirmed candidate), but {detail}. If a candidate was saved aside during the revert it \
             is at {backup}. Inspect {journal} and {config}; to boot the current on-disk config anyway, \
             run `rm {journal}` and restart."
        )
    } else {
        format!(
            "refusing to boot: a commit-confirmed config transaction revert journal exists at {journal} \
             (meaning the last run stopped inside a confirm window), but {detail}. The config file {config} \
             is MISSING, so there is nothing to boot — do NOT just `rm {journal}`. The pre-transaction config \
             is embedded in {journal} and the unconfirmed candidate, if one was saved, is at {backup}; \
             restore one of them to {config} before restarting."
        )
    }
}

/// Refusal after the revert WAS applied but the journal could not be cleaned up
/// (LAN-219 fail-closed). Distinct from [`refuse_message`]: the config on disk
/// is now the reverted pre-transaction config and the candidate is preserved, so
/// the recovery instructions differ — the operator must clear the journal, not
/// restore the config.
fn refuse_after_revert_message(
    journal_path: &Path,
    config_path: &Path,
    backup_path: &Path,
    error: &io::Error,
) -> String {
    format!(
        "refusing to boot: the commit-confirmed revert WAS applied — the pre-transaction config was written \
         to {config} — but the revert journal at {journal} could not be removed ({error}). The unconfirmed \
         candidate is preserved at {backup}. Refusing to start to avoid repeatedly reverting any config you \
         apply: until the journal is gone, every boot re-runs this revert. To recover, inspect and preserve \
         {backup}, then fix the journal's permissions or `rm {journal}`, and restart.",
        config = config_path.display(),
        journal = journal_path.display(),
        backup = backup_path.display(),
    )
}

/// Write temp file + fsync + rename + fsync dir. Shared with the config
/// persister so every durable config write goes through the same primitive.
///
/// Failures name the destination path: a bare io error ("No such file or
/// directory (os error 2)") is useless to an operator who doesn't know
/// which file the daemon was writing.
pub(crate) fn write_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    stage_atomic(path, bytes)?.commit()
}

/// A durable write that has been fully written and fsynced next to its
/// destination but not yet published. Every failure mode an operator hits in
/// practice — an unwritable directory, a read-only mount, a full filesystem —
/// is consumed by [`stage_atomic`], so a staged write can be committed with
/// only a `rename(2)` left to do, or discarded with no trace.
///
/// This is what lets runtime config mutations reserve their on-disk write
/// *before* touching a live BGP session: a staging failure has changed
/// nothing anywhere, and discarding costs nothing.
pub(crate) struct StagedWrite {
    tmp: PathBuf,
    target: PathBuf,
}

impl StagedWrite {
    /// Publish the staged bytes: rename into place and fsync the directory.
    pub(crate) fn commit(self) -> io::Result<()> {
        commit_staged(&self.tmp, &self.target)
            .map_err(|error| name_write_failure(&self.target, &error))
    }

    /// Drop the staged bytes. Best effort: a leftover temp file is harmless
    /// (the next stage truncates it) and there is nothing useful to report.
    pub(crate) fn discard(self) {
        let _ = fs::remove_file(&self.tmp);
    }
}

/// Write temp file + fsync, stopping short of the rename that publishes it.
///
/// Failures name the destination path: a bare io error ("No such file or
/// directory (os error 2)") is useless to an operator who doesn't know
/// which file the daemon was writing.
pub(crate) fn stage_atomic(path: &Path, bytes: &[u8]) -> io::Result<StagedWrite> {
    stage_atomic_inner(path, bytes).map_err(|error| name_write_failure(path, &error))
}

fn name_write_failure(path: &Path, error: &io::Error) -> io::Error {
    io::Error::new(
        error.kind(),
        format!("failed to write {}: {error}", path.display()),
    )
}

fn commit_staged(tmp: &Path, target: &Path) -> io::Result<()> {
    fs::rename(tmp, target)?;
    fsync_dir(parent_dir(target)?)
}

fn stage_atomic_inner(path: &Path, bytes: &[u8]) -> io::Result<StagedWrite> {
    // Resolve symlinks so the write lands on the REAL file: `rename(2)` over
    // a symlink replaces the symlink itself (orphaning its target), and
    // resolving at write time means the rename cannot be redirected by a
    // symlink swapped in underneath us in a world-writable directory. A
    // plain path canonicalizes to itself, so the non-symlink case is
    // unchanged.
    let target = match fs::canonicalize(path) {
        Ok(real) => real,
        // Destination absent (first write) or a dangling symlink: resolve
        // the parent so a symlinked directory still lands on the real one.
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let name = path.file_name().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("path {} has no file name", path.display()),
                )
            })?;
            fs::canonicalize(parent_dir(path)?)?.join(name)
        }
        Err(error) => return Err(error),
    };
    let mut tmp = target.clone().into_os_string();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);
    // Owner-only from the first byte: the payload embeds config snapshots
    // (which may carry secrets such as TCP-MD5 passwords), and a permissive
    // umask must not make them world-readable. The rename below preserves
    // the temp file's mode — it moves the inode.
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp)?;
    // `mode` applies only when the file is CREATED; clamp a stale leftover
    // temp file to owner-only too before secrets are written into it.
    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    Ok(StagedWrite { tmp, target })
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
    use crate::test_support::{
        assert_tier_authorized_test_config, tier_authorized_uds_test_config,
    };

    const PREVIOUS_TOML: &str = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"
"#;

    fn previous_toml() -> String {
        let prepared = tier_authorized_uds_test_config(PREVIOUS_TOML);
        let config = Config::load_toml_with_diagnostics(&prepared, "confirm journal test config")
            .expect("confirm journal test config must parse");
        assert_tier_authorized_test_config(&config);
        prepared
    }

    fn journal() -> ConfirmJournal {
        ConfirmJournal {
            confirm_id: "deploy-1".to_string(),
            deadline_unix_seconds: 1234,
            rollback_toml: previous_toml(),
            rollback_failed: false,
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
    fn boot_check_without_runtime_state_directory_is_normal_boot() {
        // Destructive proof: pinning the locator-free journal parent before
        // establishing path absence makes this fresh-install boot fail before
        // the daemon can create its runtime-state directory.
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("rustbgpd.toml");
        fs::write(&config_path, "candidate").unwrap();
        let runtime_state_dir = dir.path().join("missing/runtime");
        let path = journal_path(&runtime_state_dir);

        let outcome = boot_revert_check(&path, &config_path).unwrap();

        assert!(outcome.is_none());
        assert_eq!(fs::read_to_string(&config_path).unwrap(), "candidate");
        assert!(!runtime_state_dir.exists());
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
        assert_eq!(fs::read_to_string(&config_path).unwrap(), previous_toml());
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
        assert_eq!(fs::read_to_string(&config_path).unwrap(), previous_toml());
        // No candidate existed, so nothing was saved aside.
        assert!(!revert.notice.backup_path.exists());
    }

    #[test]
    fn boot_check_refuses_oversized_journal_before_parse() {
        // LAN-204: a corrupt journal larger than the sanity cap must be refused
        // up front, never read/deserialized (which would risk an OOM).
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("rustbgpd.toml");
        fs::write(&config_path, "candidate").unwrap();
        let path = journal_path(dir.path());
        let oversized = usize::try_from(MAX_JOURNAL_BYTES + 1).unwrap();
        fs::write(&path, vec![b'a'; oversized]).unwrap();

        let message = boot_revert_check(&path, &config_path).unwrap_err();
        assert!(message.contains("refusing to boot"), "{message}");
        assert!(message.contains("sanity limit"), "{message}");
        // Fail closed: config untouched, journal preserved.
        assert_eq!(fs::read_to_string(&config_path).unwrap(), "candidate");
        assert!(path.exists());
    }

    #[test]
    fn write_atomic_sets_owner_only_permissions() {
        // The payload may embed config secrets; the file must be 0o600 from
        // creation, under any umask, and the rename must preserve that mode.
        use std::os::unix::fs::MetadataExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("journal.json");
        write_atomic(&path, b"secret").unwrap();
        assert_eq!(fs::metadata(&path).unwrap().mode() & 0o777, 0o600);

        // Overwriting a pre-existing world-readable file tightens it: the
        // rename moves the 0o600 temp inode over the old one.
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        write_atomic(&path, b"secret2").unwrap();
        assert_eq!(fs::metadata(&path).unwrap().mode() & 0o777, 0o600);
        assert_eq!(fs::read_to_string(&path).unwrap(), "secret2");
    }

    #[test]
    fn write_atomic_writes_through_symlink_to_real_file() {
        // A symlinked destination (operators symlink configs) must have the
        // write land on the REAL file — a bare rename would replace the
        // symlink itself with a regular file and orphan the target.
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real.toml");
        fs::write(&real, "old").unwrap();
        let link = dir.path().join("config.toml");
        std::os::unix::fs::symlink(&real, &link).unwrap();

        write_atomic(&link, b"new").unwrap();

        assert!(
            fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink(),
            "the symlink must survive the write"
        );
        assert_eq!(fs::read_to_string(&real).unwrap(), "new");
        assert_eq!(fs::read_to_string(&link).unwrap(), "new");
    }

    #[test]
    fn journal_roundtrips_rollback_failed_and_defaults_it_when_absent() {
        let dir = tempfile::tempdir().unwrap();
        let path = journal_path(dir.path());
        write(
            &path,
            &ConfirmJournal {
                rollback_failed: true,
                ..journal()
            },
        )
        .unwrap();
        let read: ConfirmJournal =
            serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        assert!(read.rollback_failed);

        // A journal written before the field existed still parses (false).
        let legacy: ConfirmJournal = serde_json::from_str(
            &serde_json::to_string(&serde_json::json!({
                "confirm_id": "deploy-1",
                "deadline_unix_seconds": 1234,
                "rollback_toml": previous_toml(),
            }))
            .unwrap(),
        )
        .unwrap();
        assert!(!legacy.rollback_failed);
    }

    #[test]
    fn boot_check_notice_carries_rollback_failed() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("rustbgpd.toml");
        fs::write(&config_path, "candidate").unwrap();
        let path = journal_path(dir.path());
        write(
            &path,
            &ConfirmJournal {
                rollback_failed: true,
                ..journal()
            },
        )
        .unwrap();

        let revert = boot_revert_check(&path, &config_path).unwrap().unwrap();
        assert!(revert.notice.rollback_failed);
        // The revert itself still applies — the journaled snapshot is the
        // proven pre-transaction config.
        assert_eq!(fs::read_to_string(&config_path).unwrap(), previous_toml());
    }

    #[test]
    fn boot_check_reverts_through_symlinked_config() {
        // A symlinked config file survives the boot revert: the save-aside
        // and restore operate on the real file, next to which the
        // `.unconfirmed` candidate is preserved.
        let dir = tempfile::tempdir().unwrap();
        let real_dir = dir.path().join("real");
        fs::create_dir_all(&real_dir).unwrap();
        let real = real_dir.join("rustbgpd.toml");
        fs::write(&real, "unconfirmed candidate bytes").unwrap();
        let link = dir.path().join("config.toml");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let path = journal_path(dir.path());
        write(&path, &journal()).unwrap();

        let revert = boot_revert_check(&path, &link).unwrap().unwrap();

        assert!(
            fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink(),
            "the config symlink must survive the revert"
        );
        assert_eq!(fs::read_to_string(&real).unwrap(), previous_toml());
        assert_eq!(fs::read_to_string(&link).unwrap(), previous_toml());
        // Candidate saved aside next to the REAL file.
        assert_eq!(
            revert.notice.backup_path,
            real_dir.join("rustbgpd.toml.unconfirmed")
        );
        assert_eq!(
            fs::read_to_string(&revert.notice.backup_path).unwrap(),
            "unconfirmed candidate bytes"
        );
        assert!(!path.exists(), "journal consumed");
    }

    #[test]
    fn write_atomic_failure_names_the_destination_path() {
        // LAN-317: a persistence io failure must carry the destination path;
        // a bare "No such file or directory (os error 2)" is unactionable.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("missing-dir").join("config.toml");

        let error = write_atomic(&path, b"x").unwrap_err();

        let rendered = error.to_string();
        assert!(
            rendered.contains(&format!("failed to write {}", path.display())),
            "{rendered}"
        );
    }

    #[test]
    fn boot_check_restores_candidate_when_config_restore_write_fails() {
        // LAN-207: if write_atomic fails after the candidate was renamed aside,
        // the config must be put back rather than left missing. Inject the
        // failure by pre-creating a DIRECTORY at the temp path write_atomic
        // needs (`<config>.tmp`), so File::create there fails while the
        // candidate→backup rename still succeeds.
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("rustbgpd.toml");
        fs::write(&config_path, "unconfirmed candidate bytes").unwrap();
        let mut blocker = config_path.clone().into_os_string();
        blocker.push(".tmp");
        fs::create_dir(&blocker).unwrap();
        let path = journal_path(dir.path());
        write(&path, &journal()).unwrap();

        let message = boot_revert_check(&path, &config_path).unwrap_err();
        assert!(message.contains("refusing to boot"), "{message}");
        // The candidate was restored — the config file is NOT missing.
        assert_eq!(
            fs::read_to_string(&config_path).unwrap(),
            "unconfirmed candidate bytes",
            "candidate must be restored after a failed revert write"
        );
        // Refusal names the backup slot and an explicit recovery command.
        let backup = unconfirmed_backup_path(&config_path);
        assert!(message.contains(&*backup.to_string_lossy()), "{message}");
        assert!(message.contains("rm "), "{message}");
        assert!(path.exists());
    }

    #[cfg(unix)]
    #[test]
    fn boot_check_fails_closed_without_clobbering_candidate_when_journal_removal_fails() {
        // LAN-219 (SUPERSEDES LAN-208's boot-anyway): a journal-removal failure
        // AFTER a successful restore must FAIL STARTUP (return Err), not boot
        // anyway. Booting anyway lets a filesystem fault silently re-revert every
        // config the operator applies. The revert is still written to disk and
        // the real candidate is preserved at `.unconfirmed` — and, crucially, a
        // second boot (with a different on-disk config, as if the operator
        // re-applied) must STILL fail and must NOT clobber that candidate.
        use std::os::unix::fs::PermissionsExt;

        let base = tempfile::tempdir().unwrap();
        let journal_dir = base.path().join("journal");
        let config_dir = base.path().join("config");
        fs::create_dir_all(&journal_dir).unwrap();
        fs::create_dir_all(&config_dir).unwrap();
        let config_path = config_dir.join("rustbgpd.toml");
        fs::write(&config_path, "unconfirmed candidate bytes").unwrap();
        let path = journal_path(&journal_dir);
        write(&path, &journal()).unwrap();

        // Read-only journal dir → remove_file fails (needs dir write), but the
        // journal is still readable and the config dir stays writable.
        fs::set_permissions(&journal_dir, fs::Permissions::from_mode(0o500)).unwrap();
        // Root ignores directory-write permission; skip the strict assertion.
        if fs::File::create(journal_dir.join(".root-probe")).is_ok() {
            fs::set_permissions(&journal_dir, fs::Permissions::from_mode(0o700)).unwrap();
            return;
        }

        // First boot: revert is written, journal removal fails → fail closed.
        let message = boot_revert_check(&path, &config_path).unwrap_err();
        assert!(message.contains("refusing to boot"), "{message}");
        assert!(message.contains("WAS applied"), "{message}");
        // The revert WAS written despite the refusal.
        assert_eq!(fs::read_to_string(&config_path).unwrap(), previous_toml());
        // The real candidate is preserved in the backup slot.
        let backup = unconfirmed_backup_path(&config_path);
        assert_eq!(
            fs::read_to_string(&backup).unwrap(),
            "unconfirmed candidate bytes"
        );
        assert!(path.exists(), "journal preserved for the next boot");

        // Second boot, simulating an operator who applied a DIFFERENT config in
        // the meantime: it must STILL fail closed and must NOT overwrite the
        // preserved candidate with those different bytes (the LAN-208 clobber).
        fs::write(&config_path, "operator re-applied different bytes").unwrap();
        let message2 = boot_revert_check(&path, &config_path).unwrap_err();
        assert!(message2.contains("refusing to boot"), "{message2}");
        // Candidate is byte-for-byte unchanged — no clobber.
        assert_eq!(
            fs::read_to_string(&backup).unwrap(),
            "unconfirmed candidate bytes",
            "the saved candidate must never be overwritten by a restart loop"
        );

        // Restore perms so tempdir cleanup works.
        fs::set_permissions(&journal_dir, fs::Permissions::from_mode(0o700)).unwrap();
    }

    #[test]
    fn boot_check_never_overwrites_existing_unconfirmed_candidate() {
        // LAN-219 invariant: a pre-existing `.unconfirmed` (the real saved
        // candidate) is never overwritten, even on a normal successful revert.
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("rustbgpd.toml");
        fs::write(&config_path, "current on-disk config").unwrap();
        let backup = unconfirmed_backup_path(&config_path);
        fs::write(&backup, "the real preserved candidate").unwrap();
        let path = journal_path(dir.path());
        write(&path, &journal()).unwrap();

        let revert = boot_revert_check(&path, &config_path).unwrap().unwrap();
        // Revert still applied.
        assert_eq!(fs::read_to_string(&config_path).unwrap(), previous_toml());
        // The pre-existing candidate is untouched — NOT overwritten with the
        // current on-disk config.
        assert_eq!(
            fs::read_to_string(&revert.notice.backup_path).unwrap(),
            "the real preserved candidate"
        );
        assert!(!path.exists(), "journal consumed on success");
    }

    #[test]
    fn save_candidate_aside_no_clobbers_existing_backup() {
        // LAN-224: the atomic no-clobber move must return Ok(false) and leave a
        // pre-existing `.unconfirmed` byte-for-byte unchanged, even with a config
        // candidate present to move aside (the old try_exists+rename could clobber
        // a backup created between the check and the rename).
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("rustbgpd.toml");
        fs::write(&config_path, "current candidate").unwrap();
        let backup_path = unconfirmed_backup_path(&config_path);
        fs::write(&backup_path, "the real preserved candidate").unwrap();
        let jpath = journal_path(dir.path());

        let moved = save_candidate_aside(&config_path, &backup_path, &jpath).unwrap();
        assert!(!moved, "must not move when the backup already exists");
        // No clobber: the preserved candidate is untouched.
        assert_eq!(
            fs::read_to_string(&backup_path).unwrap(),
            "the real preserved candidate"
        );
        // Config left in place (not moved aside).
        assert_eq!(
            fs::read_to_string(&config_path).unwrap(),
            "current candidate"
        );
    }

    #[test]
    fn boot_check_resumes_revert_after_crash_without_overwriting_candidate() {
        // LAN-220 idempotency: crash mid-revert leaves config_path missing (it
        // was already renamed to `.unconfirmed`) with a live journal. Resume must
        // write the rollback and NOT overwrite the preserved candidate.
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("rustbgpd.toml");
        // config_path intentionally absent (renamed aside by the crashed run).
        let backup = unconfirmed_backup_path(&config_path);
        fs::write(&backup, "candidate from the crashed run").unwrap();
        let path = journal_path(dir.path());
        write(&path, &journal()).unwrap();

        let revert = boot_revert_check(&path, &config_path).unwrap().unwrap();
        assert_eq!(fs::read_to_string(&config_path).unwrap(), previous_toml());
        assert_eq!(
            fs::read_to_string(&revert.notice.backup_path).unwrap(),
            "candidate from the crashed run",
            "the candidate preserved before the crash must survive the resume"
        );
        assert!(!path.exists());
    }

    #[test]
    fn boot_check_refuse_message_is_state_aware_when_config_missing() {
        // LAN-220: when config_path does not exist, the refusal must NOT tell the
        // operator to `rm` the journal and boot the on-disk config (there is
        // none). It must name the journal and the `.unconfirmed` candidate.
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("rustbgpd.toml"); // absent
        let path = journal_path(dir.path());
        // Torn journal so the revert cannot apply, forcing a refusal.
        fs::write(&path, "{\"confirm_id\": \"deploy-1\", \"dead").unwrap();

        let message = boot_revert_check(&path, &config_path).unwrap_err();
        assert!(message.contains("refusing to boot"), "{message}");
        assert!(message.contains("MISSING"), "{message}");
        assert!(
            message.contains(&*path.to_string_lossy()),
            "must name the journal: {message}"
        );
        assert!(
            message.contains(&*unconfirmed_backup_path(&config_path).to_string_lossy()),
            "must name the .unconfirmed candidate: {message}"
        );
        assert!(
            !message.contains("boot the current on-disk config"),
            "must not advise booting a missing config: {message}"
        );
    }

    #[test]
    fn boot_check_refuses_non_regular_file_journal() {
        // LAN-221: a journal path that is a directory (or any non-regular file,
        // e.g. a FIFO reporting len()==0) must be refused, never read/hung.
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("rustbgpd.toml");
        fs::write(&config_path, "candidate").unwrap();
        let path = journal_path(dir.path());
        fs::create_dir(&path).unwrap();

        let message = boot_revert_check(&path, &config_path).unwrap_err();
        assert!(message.contains("refusing to boot"), "{message}");
        assert!(message.contains("not a regular file"), "{message}");
        // Fail closed: config untouched.
        assert_eq!(fs::read_to_string(&config_path).unwrap(), "candidate");
    }
}
