//! Durable writes, v3 commit-confirm authority, and retired-authority refusal.

#![deny(unsafe_code)]

pub(crate) mod v3;

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write as _};
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};

/// Exact publication boundary for an atomic write.
///
/// The variants are selected by control flow around `rename(2)`, never by
/// errno or error text. Before rename the target is provably unchanged; after
/// rename the candidate is visible but its crash durability is not proved.
#[derive(Debug)]
pub(crate) enum AtomicPublishError {
    NotPublished(io::Error),
    PublicationAmbiguous(io::Error),
}

impl std::fmt::Display for AtomicPublishError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotPublished(error) | Self::PublicationAmbiguous(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for AtomicPublishError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::NotPublished(error) | Self::PublicationAmbiguous(error) => Some(error),
        }
    }
}

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
/// removing it. Its terminal state cannot be proven by v0.65.0 or any later
/// release, so every one of them refuses boot untouched; finish or recover the
/// transaction before upgrading past v0.64.0.
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
pub(crate) fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), AtomicPublishError> {
    stage_atomic(path, bytes)
        .map_err(AtomicPublishError::NotPublished)?
        .commit()
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
#[derive(Debug)]
pub(crate) struct StagedWrite {
    tmp: PathBuf,
    target: PathBuf,
    file: File,
    tmp_dev: u64,
    tmp_ino: u64,
}

impl StagedWrite {
    /// Filesystem path of the unpublished, fsynced payload.
    pub(crate) fn path(&self) -> &Path {
        &self.tmp
    }

    /// Apply migration-only ownership and mode after payload validation.
    pub(crate) fn preserve_metadata(&mut self, uid: u32, gid: u32, mode: u32) -> io::Result<()> {
        #[cfg(debug_assertions)]
        if std::env::var("RUSTBGPD_TEST_MIGRATION_METADATA_FAILURE").as_deref() == Ok("chown") {
            return Err(io::Error::other("injected metadata preservation failure"));
        }
        std::os::unix::fs::fchown(&self.file, Some(uid), Some(gid))?;
        #[cfg(debug_assertions)]
        if std::env::var("RUSTBGPD_TEST_MIGRATION_METADATA_FAILURE").as_deref() == Ok("chmod") {
            return Err(io::Error::other("injected metadata preservation failure"));
        }
        self.file
            .set_permissions(fs::Permissions::from_mode(mode & 0o7777))?;
        #[cfg(debug_assertions)]
        if std::env::var("RUSTBGPD_TEST_MIGRATION_METADATA_FAILURE").as_deref() == Ok("fsync") {
            return Err(io::Error::other("injected metadata preservation failure"));
        }
        self.file.sync_all()
    }

    /// Publish the staged bytes: rename into place and fsync the directory.
    pub(crate) fn commit(mut self) -> Result<(), AtomicPublishError> {
        self.file
            .sync_all()
            .map_err(AtomicPublishError::NotPublished)?;
        self.publish()
    }

    /// Re-run a caller-owned stale-source fence immediately before publish.
    pub(crate) fn commit_if(
        mut self,
        fence: impl FnOnce() -> io::Result<()>,
    ) -> Result<(), AtomicPublishError> {
        self.file
            .sync_all()
            .map_err(AtomicPublishError::NotPublished)?;
        fence()
            .map_err(|error| name_write_failure(&self.target, &error))
            .map_err(AtomicPublishError::NotPublished)?;
        self.publish()
    }

    fn publish(&mut self) -> Result<(), AtomicPublishError> {
        self.publish_with(fsync_dir)
    }

    fn publish_with(
        &mut self,
        sync_directory: impl FnOnce(&Path) -> io::Result<()>,
    ) -> Result<(), AtomicPublishError> {
        self.verify_owned_temp()
            .map_err(AtomicPublishError::NotPublished)?;
        #[cfg(debug_assertions)]
        if std::env::var("RUSTBGPD_TEST_CONFIG_PUBLISH_FAILURE").as_deref() == Ok("not_published") {
            return Err(AtomicPublishError::NotPublished(io::Error::other(
                "injected pre-rename config publication failure",
            )));
        }
        fs::rename(&self.tmp, &self.target)
            .map_err(|error| name_write_failure(&self.target, &error))
            .map_err(AtomicPublishError::NotPublished)?;
        self.tmp = PathBuf::new();
        #[cfg(debug_assertions)]
        if std::env::var("RUSTBGPD_TEST_CONFIG_PUBLISH_FAILURE").as_deref()
            == Ok("publication_ambiguous")
        {
            return Err(AtomicPublishError::PublicationAmbiguous(io::Error::other(
                "injected post-rename directory fsync failure",
            )));
        }
        let parent = parent_dir(&self.target).map_err(AtomicPublishError::PublicationAmbiguous)?;
        sync_directory(parent).map_err(|error| {
            AtomicPublishError::PublicationAmbiguous(io::Error::new(
                error.kind(),
                format!("post-rename directory fsync failed; durability ambiguous: {error}"),
            ))
        })
    }

    #[cfg(test)]
    fn commit_with_dir_fsync(
        mut self,
        sync_directory: impl FnOnce(&Path) -> io::Result<()>,
    ) -> Result<(), AtomicPublishError> {
        self.file
            .sync_all()
            .map_err(AtomicPublishError::NotPublished)?;
        self.publish_with(sync_directory)
    }

    fn verify_owned_temp(&self) -> io::Result<()> {
        let metadata = fs::symlink_metadata(&self.tmp)?;
        if !metadata.file_type().is_file()
            || metadata.nlink() != 1
            || (metadata.dev(), metadata.ino()) != (self.tmp_dev, self.tmp_ino)
        {
            return Err(io::Error::other("atomic stage pathname identity changed"));
        }
        Ok(())
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
        if !self.tmp.as_os_str().is_empty() && self.verify_owned_temp().is_ok() {
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
        .read(true)
        .write(true)
        .create(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .mode(0o600)
        .open(&tmp)?;
    let target_metadata = fs::metadata(&target).ok();
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file()
        || metadata.nlink() != 1
        || target_metadata
            .as_ref()
            .is_some_and(|target| (metadata.dev(), metadata.ino()) == (target.dev(), target.ino()))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "atomic stage is not an independent regular file",
        ));
    }
    match file.try_lock() {
        Ok(()) => {}
        Err(fs::TryLockError::Error(error)) => return Err(error),
        Err(fs::TryLockError::WouldBlock) => {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "atomic stage is already in use",
            ));
        }
    }
    let path_metadata = fs::symlink_metadata(&tmp)?;
    if !path_metadata.file_type().is_file()
        || path_metadata.nlink() != 1
        || (path_metadata.dev(), path_metadata.ino()) != (metadata.dev(), metadata.ino())
    {
        return Err(io::Error::other("atomic stage pathname identity changed"));
    }
    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    file.set_len(0)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(StagedWrite {
        tmp,
        target,
        file,
        tmp_dev: metadata.dev(),
        tmp_ino: metadata.ino(),
    })
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
    #[cfg(debug_assertions)]
    if std::env::var_os("RUSTBGPD_TEST_MIGRATION_DIR_FSYNC_FAILURE").is_some() {
        return Err(io::Error::other("injected directory fsync failure"));
    }
    File::open(dir)?.sync_all()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

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

    #[test]
    fn temp_inode_lock_serializes_same_target_but_not_different_targets() {
        let dir = tempfile::tempdir().unwrap();
        let first = dir.path().join("first.toml");
        let second = dir.path().join("second.toml");
        fs::write(&first, b"first").unwrap();
        fs::write(&second, b"second").unwrap();
        let stage = stage_atomic(&first, b"candidate-one").unwrap();
        let stage_path = stage.path().to_path_buf();
        let before = fs::metadata(&stage_path).unwrap();
        let bytes = fs::read(&stage_path).unwrap();
        let collision = stage_atomic(&first, b"must-not-truncate").unwrap_err();
        assert_eq!(collision.kind(), io::ErrorKind::WouldBlock);
        let after = fs::metadata(&stage_path).unwrap();
        assert_eq!((before.dev(), before.ino()), (after.dev(), after.ino()));
        assert_eq!(fs::read(&stage_path).unwrap(), bytes);
        assert_eq!(fs::read(&first).unwrap(), b"first");
        let other = stage_atomic(&second, b"candidate-two").unwrap();
        other.discard();
        stage.discard();
        let retry = stage_atomic(&first, b"retry").unwrap();
        retry.discard();
    }

    #[test]
    fn stale_temp_is_clamped_before_payload_and_path_substitution_is_never_removed() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("config.toml");
        fs::write(&target, b"accepted").unwrap();
        let tmp = target.with_extension("toml.tmp");
        fs::write(&tmp, b"stale").unwrap();
        fs::set_permissions(&tmp, fs::Permissions::from_mode(0o644)).unwrap();
        let stage = stage_atomic(&target, b"candidate").unwrap();
        assert_eq!(
            fs::metadata(&tmp).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(fs::read(&tmp).unwrap(), b"candidate");
        let owned = dir.path().join("owned-aside");
        fs::rename(&tmp, &owned).unwrap();
        fs::write(&tmp, b"replacement").unwrap();
        assert!(stage.commit().is_err());
        assert_eq!(fs::read(&tmp).unwrap(), b"replacement");
        assert_eq!(fs::read(&owned).unwrap(), b"candidate");

        fs::remove_file(&tmp).unwrap();
        fs::remove_file(&owned).unwrap();
        let stage = stage_atomic(&target, b"drop-candidate").unwrap();
        fs::rename(&tmp, &owned).unwrap();
        fs::write(&tmp, b"drop-replacement").unwrap();
        drop(stage);
        assert_eq!(fs::read(&tmp).unwrap(), b"drop-replacement");
    }

    #[test]
    fn post_rename_directory_fsync_failure_cannot_delete_successor_temp() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("config.toml");
        fs::write(&target, b"accepted").unwrap();
        let successor = target.with_extension("toml.tmp");
        let stage = stage_atomic(&target, b"candidate").unwrap();
        let error = stage
            .commit_with_dir_fsync(|_| {
                fs::write(&successor, b"successor")?;
                Err(io::Error::other("injected directory fsync failure"))
            })
            .unwrap_err();
        assert!(matches!(
            &error,
            AtomicPublishError::PublicationAmbiguous(_)
        ));
        let message = error.to_string();
        assert!(message.contains("post-rename directory fsync failed"));
        assert!(message.contains("injected directory fsync failure"));
        assert_eq!(fs::read(&target).unwrap(), b"candidate");
        assert_eq!(fs::read(&successor).unwrap(), b"successor");
    }

    #[test]
    fn failures_before_rename_are_typed_not_published_and_preserve_target() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("config.toml");
        fs::write(&target, b"accepted").unwrap();
        let tmp = target.with_extension("toml.tmp");
        let stage = stage_atomic(&target, b"candidate").unwrap();
        let owned = dir.path().join("owned-aside");
        fs::rename(&tmp, &owned).unwrap();
        fs::write(&tmp, b"substitute").unwrap();

        assert!(matches!(
            stage.commit(),
            Err(AtomicPublishError::NotPublished(_))
        ));
        assert_eq!(fs::read(&target).unwrap(), b"accepted");
        assert_eq!(fs::read(&tmp).unwrap(), b"substitute");
        assert_eq!(fs::read(&owned).unwrap(), b"candidate");
    }
}
