//! Durable writes, v3 commit-confirm authority, and retired-authority refusal.

#![deny(unsafe_code)]

pub(crate) mod v3;

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write as _};
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};

/// Journal file name under `runtime_state_dir`.
pub const JOURNAL_FILE_NAME: &str = "commit-confirm-journal.json";

/// The operator-facing facts of a boot revert (for the banner, log, metric).
///
/// A v3 boot revert is produced only after durable locator removal; later
/// pending-residue cleanup failures are warning-only.
#[derive(Debug, Clone)]
pub struct BootRevertNotice {
    pub confirm_id: String,
    /// Where the unconfirmed candidate was saved aside.
    pub backup_path: PathBuf,
    /// The journal recorded a failed live rollback of this transaction: the
    /// state the daemon was in before this restart is uncertain (the banner
    /// says so), even though the boot revert itself succeeded.
    pub rollback_failed: bool,
    /// V3 locator-carried target paths are sensitive and must not be rendered
    /// by ordinary startup logs or banners.
    pub redact_paths: bool,
    /// V3 pending cleanup follows durable terminal locator removal and is
    /// warning-only.
    pub journal_cleanup_failed: bool,
}

#[must_use]
pub fn journal_path(runtime_state_dir: &Path) -> PathBuf {
    runtime_state_dir.join(JOURNAL_FILE_NAME)
}

/// Refuse a retired locator-free v1/v2 authority without opening, changing, or
/// removing it. Its terminal state cannot be proven by the v0.65 daemon.
pub fn refuse_retired_journal(path: &Path) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Ok(_) | Err(_) => Err(format!(
            "refusing to boot: retired commit-confirm authority exists or is inaccessible at {}; recover it with rustbgpd v0.64.0, or delete it only after proving the transaction is terminal and the current config is intended; the artifact was left untouched",
            path.display()
        )),
    }
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
    pub(crate) fn commit(mut self) -> io::Result<()> {
        let result = commit_staged(&self.tmp, &self.target)
            .map_err(|error| name_write_failure(&self.target, &error));
        if result.is_ok() {
            // The rename consumed the temp file. Clear the path so `Drop`
            // cannot remove a live file a later stage re-creates under the
            // same name.
            self.tmp = PathBuf::new();
        }
        result
    }

    /// Drop the staged bytes without publishing them; [`Drop`] removes the
    /// temp file.
    pub(crate) fn discard(self) {
        drop(self);
    }
}

/// Best-effort removal of the temp file on every path that does not publish
/// it — an explicit [`StagedWrite::discard`], a failed [`StagedWrite::commit`]
/// (including an `fsync_dir` failure after the rename, where removing the
/// already-renamed-away temp path is a harmless no-op), or a caller error
/// path dropping the stage. The payload embeds config snapshots that may
/// carry TCP-MD5/TCP-AO secrets, so an unpublished temp file must not
/// outlive its stage.
impl Drop for StagedWrite {
    fn drop(&mut self) {
        if !self.tmp.as_os_str().is_empty() {
            let _ = fs::remove_file(&self.tmp);
        }
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
    use std::os::unix::fs::{MetadataExt as _, symlink};

    #[test]
    fn retired_locator_free_authority_is_refused_untouched() {
        let dir = tempfile::tempdir().unwrap();
        let path = journal_path(dir.path());
        let bytes = b"{\"version\":2,\"confirm_id\":\"pending\"}\n";
        fs::write(&path, bytes).unwrap();
        let before = fs::metadata(&path).unwrap();

        let error = refuse_retired_journal(&path).unwrap_err();

        assert!(error.contains("rustbgpd v0.64.0"), "{error}");
        assert!(error.contains("delete it only after proving"), "{error}");
        assert!(error.contains("left untouched"), "{error}");
        assert_eq!(fs::read(&path).unwrap(), bytes);
        let after = fs::metadata(&path).unwrap();
        assert_eq!((before.dev(), before.ino()), (after.dev(), after.ino()));
    }

    #[test]
    fn retired_authority_refusal_covers_non_regular_and_inaccessible_shapes() {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt as _;

        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target");
        fs::write(&target, b"target").unwrap();
        let link = dir.path().join("link");
        symlink(&target, &link).unwrap();
        assert!(refuse_retired_journal(&link).is_err());
        assert_eq!(fs::read_link(&link).unwrap(), target);

        let directory = dir.path().join("directory");
        fs::create_dir(&directory).unwrap();
        assert!(refuse_retired_journal(&directory).is_err());
        assert!(directory.is_dir());

        assert!(refuse_retired_journal(&dir.path().join("missing")).is_ok());
        assert!(refuse_retired_journal(Path::new(OsStr::from_bytes(b"bad\0path"))).is_err());
    }

    #[test]
    fn atomic_persistence_preserves_symlinks_secrets_and_actionable_errors() {
        // Load-bearing breaks: renaming over a symlink or retaining a failed
        // stage loses the operator's target or leaks config secrets; unnamed
        // failures leave the operator unable to find the rejected destination.
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("config.toml");
        write_atomic(&target, b"accepted").unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"accepted");
        assert_eq!(
            fs::metadata(&target).unwrap().permissions().mode() & 0o777,
            0o600
        );

        let stage = stage_atomic(&target, b"candidate").unwrap();
        stage.discard();
        assert_eq!(fs::read(&target).unwrap(), b"accepted");
        assert!(!target.with_extension("toml.tmp").exists());

        let link = dir.path().join("config-link.toml");
        symlink(&target, &link).unwrap();
        write_atomic(&link, b"through-link").unwrap();
        assert!(
            fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(fs::read(&target).unwrap(), b"through-link");

        let blocked = dir.path().join("blocked.toml");
        fs::create_dir(&blocked).unwrap();
        stage_atomic(&blocked, b"secret")
            .unwrap()
            .commit()
            .unwrap_err();
        assert!(!dir.path().join("blocked.toml.tmp").exists());
        assert!(blocked.is_dir());

        let missing = dir.path().join("missing").join("config.toml");
        let error = write_atomic(&missing, b"candidate")
            .unwrap_err()
            .to_string();
        assert!(error.contains(&format!("failed to write {}", missing.display())));
    }
}
