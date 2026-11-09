//! Descriptor-bound source reads and retained config-backup protection.

#[cfg(unix)]
use std::collections::HashSet;
use std::fs::{File, Metadata};
use std::io;
#[cfg(unix)]
use std::path::Component;
use std::path::{Path, PathBuf};
use std::sync::Arc;
#[cfg(unix)]
use std::sync::Mutex;

#[cfg(test)]
macro_rules! count {
    ($field:ident) => {
        WORK.with(|work| work.borrow_mut().$field += 1);
    };
}
#[cfg(not(test))]
macro_rules! count {
    ($field:ident) => {};
}

/// Maximum total entries inspected in a protected config directory, including dots.
pub const MAX_BACKUP_DIRECTORY_ENTRIES: usize = 4096;
#[cfg(unix)]
const MAX_PATH_COMPONENTS: usize = 4096;

#[cfg(unix)]
use std::os::unix::fs::MetadataExt;

#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct FileIdentity(u64, u64);

#[cfg(unix)]
impl FileIdentity {
    #[cfg(unix)]
    fn of(metadata: &Metadata) -> Self {
        Self(metadata.dev(), metadata.ino())
    }
}

/// The resolved target and pinned parent belonging to accepted config bytes.
#[doc(hidden)]
#[derive(Debug, Clone)]
pub struct SourceFileTarget {
    path: PathBuf,
    parent: Arc<File>,
    #[cfg(unix)]
    accepted_file: Arc<Mutex<Option<Arc<File>>>>,
    #[cfg(unix)]
    identity: FileIdentity,
}

impl PartialEq for SourceFileTarget {
    fn eq(&self, other: &Self) -> bool {
        self.same_authority(other)
    }
}
impl Eq for SourceFileTarget {}

impl SourceFileTarget {
    fn same_authority(&self, other: &Self) -> bool {
        #[cfg(unix)]
        {
            self.path == other.path && self.identity == other.identity
        }
        #[cfg(not(unix))]
        {
            self.path == other.path
        }
    }

    /// Open a regular file and retain the parent authority of the same descriptor.
    ///
    /// # Errors
    /// Returns filesystem failures or a refusal if resolution changed before open.
    pub fn open(path: &Path) -> io::Result<(File, Self)> {
        let canonical = path.canonicalize()?;
        let expected = std::fs::metadata(&canonical)?;
        let (file, parent) = open_canonical(&canonical)?;
        let metadata = file.metadata()?;
        if !metadata.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "config target is not a regular file",
            ));
        }
        if !same_file(&expected, &metadata) {
            return Err(denied());
        }
        let target = Self::from_parent(canonical, &parent)?;
        #[cfg(unix)]
        let target = Self {
            accepted_file: Arc::new(Mutex::new(Some(Arc::new(file.try_clone()?)))),
            ..target
        };
        Ok((file, target))
    }

    /// Retain an already pinned target, including a temporarily absent leaf.
    ///
    /// # Errors
    /// Returns filesystem failures or a refusal for a different parent authority.
    pub fn from_parent(path: PathBuf, parent: &File) -> io::Result<Self> {
        let directory = path.parent().ok_or_else(denied)?;
        let current = open_directory(directory)?;
        let metadata = parent.metadata()?;
        if !same_file(&metadata, &current.metadata()?) {
            return Err(denied());
        }
        Ok(Self {
            path,
            parent: Arc::new(parent.try_clone()?),
            #[cfg(unix)]
            accepted_file: Arc::new(Mutex::new(None)),
            #[cfg(unix)]
            identity: FileIdentity::of(&metadata),
        })
    }

    /// Retain a trusted config target without reading its contents.
    ///
    /// # Errors
    /// Returns filesystem failures or a refusal for an unresolved terminal symlink.
    pub fn resolve(path: &Path) -> io::Result<Self> {
        let target = resolve_or_missing(path)?;
        let parent = open_directory(target.parent().ok_or_else(denied)?)?;
        Self::from_parent(target, &parent)
    }

    /// Fork publication ownership for a newly derived accepted snapshot.
    #[must_use]
    pub fn fork(&self) -> Self {
        Self {
            path: self.path.clone(),
            parent: Arc::clone(&self.parent),
            #[cfg(unix)]
            identity: self.identity,
            #[cfg(unix)]
            accepted_file: Arc::new(Mutex::new(
                self.accepted_file
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .clone(),
            )),
        }
    }

    /// Bind this snapshot to the exact descriptor whose bytes were published.
    /// Other generations retain their independently forked authority.
    pub fn record_published_file(&self, file: File) {
        #[cfg(unix)]
        {
            *self
                .accepted_file
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(Arc::new(file));
        }
        #[cfg(not(unix))]
        let _ = file;
    }

    /// The accepted physical config target.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Check the retained physical target still has its accepted parent authority.
    ///
    /// # Errors
    /// Refuses changed, unlinked, or unsafe authority without exposing target paths.
    pub fn verify_target(&self) -> io::Result<()> {
        // Use the accepted physical target, independent of a retargeted or
        // removed launch symlink. Missing accepted leaves fail closed.
        count!(fixed_stats);
        let actual = std::fs::metadata(&self.path)?;
        if self.path.canonicalize()? != self.path || !actual.is_file() {
            return Err(denied());
        }
        #[cfg(unix)]
        if let Some(file) = &*self
            .accepted_file
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
        {
            count!(fixed_stats);
            if !same_file(&actual, &file.metadata()?) {
                return Err(denied());
            }
        }
        let current = open_directory(self.path.parent().ok_or_else(denied)?)?;
        if !same_file(&self.parent.metadata()?, &current.metadata()?) {
            return Err(denied());
        }
        Ok(())
    }
}

fn resolve_or_missing(path: &Path) -> io::Result<PathBuf> {
    match path.canonicalize() {
        Ok(target) => Ok(target),
        Err(error) => {
            if error.kind() != io::ErrorKind::NotFound
                || path
                    .symlink_metadata()
                    .is_ok_and(|metadata| metadata.file_type().is_symlink())
            {
                return Err(denied());
            }
            Ok(path
                .parent()
                .ok_or_else(denied)?
                .canonicalize()?
                .join(path.file_name().ok_or_else(denied)?))
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DirectoryStamp {
    #[cfg(unix)]
    identity: FileIdentity,
    #[cfg(unix)]
    times: (i64, i64, i64, i64),
}
impl DirectoryStamp {
    fn of(metadata: &Metadata) -> Self {
        #[cfg(not(unix))]
        let _ = metadata;
        Self {
            #[cfg(unix)]
            identity: FileIdentity::of(metadata),
            #[cfg(unix)]
            times: (
                metadata.mtime(),
                metadata.mtime_nsec(),
                metadata.ctime(),
                metadata.ctime_nsec(),
            ),
        }
    }
}

#[derive(Debug)]
struct BackupSnapshot {
    #[cfg(unix)]
    target: SourceFileTarget,
    directory: Arc<File>,
    stamp: DirectoryStamp,
    #[cfg(unix)]
    accepted_file: Option<Arc<File>>,
    #[cfg(unix)]
    identities: HashSet<FileIdentity>,
}
impl BackupSnapshot {
    fn check(&self) -> io::Result<()> {
        count!(directory_checks);
        #[cfg(unix)]
        if self.accepted_file.is_some() {
            self.target.verify_target()?;
        }
        if DirectoryStamp::of(&self.directory.metadata()?) != self.stamp {
            return Err(denied());
        }
        Ok(())
    }
}

/// Files forbidden as policy inputs, including retained config-backup aliases.
#[doc(hidden)]
#[derive(Debug, Clone, Default)]
pub struct SourceFileProtection {
    pub files: Vec<PathBuf>,
    pub config_file: Option<PathBuf>,
    backups: Option<Arc<BackupSnapshot>>,
}

impl SourceFileProtection {
    /// Set protected files and the resolved config-backup prefix without I/O.
    #[must_use]
    pub fn new(files: Vec<PathBuf>, config_file: Option<PathBuf>) -> Self {
        Self {
            files,
            config_file,
            backups: None,
        }
    }

    /// Collect one bounded backup inventory for an entire candidate load.
    ///
    /// # Errors
    /// Refuses overflow, directory mutation, unsafe entries, and unavailable authority.
    pub fn snapshot(self, target: Option<&SourceFileTarget>) -> io::Result<Self> {
        #[cfg(unix)]
        let mut self_ = self;
        #[cfg(unix)]
        if let Some(target) = target {
            count!(directory_checks);
            let stamp = DirectoryStamp::of(&target.parent.metadata()?);
            let snapshot = self_.inventory(target, stamp).map_err(|error| {
                // A refusal concurrent with a directory change is retryable.
                match target.parent.metadata() {
                    Ok(metadata) if DirectoryStamp::of(&metadata) == stamp => error,
                    _ => changed(),
                }
            })?;
            self_.backups = Some(Arc::new(snapshot));
        }
        #[cfg(not(unix))]
        if target.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "protected config authority requires Unix",
            ));
        }
        #[cfg(unix)]
        {
            Ok(self_)
        }
        #[cfg(not(unix))]
        {
            Ok(self)
        }
    }

    #[cfg(unix)]
    fn inventory(
        &self,
        target: &SourceFileTarget,
        stamp: DirectoryStamp,
    ) -> io::Result<BackupSnapshot> {
        use nix::fcntl::OFlag;
        use nix::sys::stat::Mode;
        use std::os::unix::ffi::OsStrExt;
        count!(directory_opens);
        let mut directory = nix::dir::Dir::openat(
            &*target.parent,
            ".",
            OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .map_err(errno)?;
        let mut identities = HashSet::new();
        let mut entries = directory.iter();
        for index in 0..=MAX_BACKUP_DIRECTORY_ENTRIES {
            count!(enumeration_probes);
            let Some(entry) = entries.next() else {
                break;
            };
            let entry = entry.map_err(errno)?;
            count!(entries);
            if index == MAX_BACKUP_DIRECTORY_ENTRIES {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "protected config directory exceeds 4096 entries",
                ));
            }
            let name = std::ffi::OsStr::from_bytes(entry.file_name().to_bytes());
            let candidate = target.path.parent().ok_or_else(denied)?.join(name);
            if !self.is_backup_path(&candidate) {
                continue;
            }
            // Identity needs no read permission on the backup itself.
            count!(backup_stats);
            let stat = nix::sys::stat::fstatat(
                &*target.parent,
                name,
                nix::fcntl::AtFlags::AT_SYMLINK_NOFOLLOW,
            )
            .map_err(errno)?;
            if stat.st_mode & libc::S_IFMT != libc::S_IFREG {
                return Err(denied());
            }
            #[allow(
                clippy::unnecessary_cast,
                reason = "dev_t and ino_t are narrower than u64 on some Unix targets"
            )]
            let identity = FileIdentity(stat.st_dev as u64, stat.st_ino as u64);
            if identities.insert(identity) {
                count!(retained_identities);
            }
        }
        let snapshot = BackupSnapshot {
            target: target.fork(),
            directory: Arc::clone(&target.parent),
            stamp,
            accepted_file: target
                .accepted_file
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone(),
            identities,
        };
        snapshot.check()?;
        Ok(snapshot)
    }

    /// Whether the protected config directory changed after the inventory, which
    /// makes a refusal during the load retryable rather than final.
    #[must_use]
    pub fn inventory_changed(&self) -> bool {
        self.backups.as_ref().is_some_and(|backups| {
            backups.directory.metadata().map_or(true, |metadata| {
                DirectoryStamp::of(&metadata) != backups.stamp
            })
        })
    }

    /// Whether descriptor-level protection is required.
    #[must_use]
    pub fn is_active(&self) -> bool {
        !self.files.is_empty() || self.config_file.is_some() || self.backups.is_some()
    }

    /// Check fixed names and the accepted config backup prefix.
    #[must_use]
    pub fn protects_path(&self, path: &Path) -> bool {
        self.files.iter().any(|file| file == path) || self.is_backup_path(path)
    }

    fn is_backup_path(&self, path: &Path) -> bool {
        self.config_file.as_ref().is_some_and(|config| {
            config.parent() == path.parent()
                && config
                    .file_name()
                    .zip(path.file_name())
                    .is_some_and(|(config, name)| {
                        let mut prefix = config.as_encoded_bytes().to_vec();
                        prefix.extend_from_slice(b".unconfirmed-");
                        name.as_encoded_bytes().starts_with(&prefix)
                    })
        })
    }

    pub(crate) fn check_opened(&self, path: &Path, metadata: &Metadata) -> io::Result<()> {
        self.check_directory()?;
        if self.protects_path(path) {
            return Err(denied());
        }
        #[cfg(unix)]
        {
            if let Some(backups) = &self.backups {
                if backups.identities.contains(&FileIdentity::of(metadata)) {
                    return Err(denied());
                }
                if let Some(file) = &backups.accepted_file {
                    count!(fixed_stats);
                    if same_file(metadata, &file.metadata()?) {
                        return Err(denied());
                    }
                }
            }
            for protected in &self.files {
                count!(fixed_stats);
                match std::fs::metadata(protected) {
                    Ok(other) if same_file(metadata, &other) => return Err(denied()),
                    Ok(_) => {}
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error),
                }
            }
        }
        #[cfg(not(unix))]
        let _ = metadata;
        Ok(())
    }

    pub(crate) fn check_directory(&self) -> io::Result<()> {
        if let Some(backups) = &self.backups {
            backups.check()?;
        }
        Ok(())
    }

    pub(crate) fn open_checked(path: &Path, expected: &Metadata) -> io::Result<(File, Metadata)> {
        #[cfg(unix)]
        let (file, _) = open_canonical(path)?;
        #[cfg(not(unix))]
        let file = File::open(path)?;
        let actual = file.metadata()?;
        count!(source_stats);
        if !same_file(expected, &actual) {
            return Err(denied());
        }
        Ok((file, actual))
    }
}

/// The protected config directory changed during a load; retrying can succeed.
#[cfg(unix)]
fn changed() -> io::Error {
    io::Error::new(
        io::ErrorKind::ResourceBusy,
        "protected config directory changed during the load",
    )
}

fn denied() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "is not an admissible policy source",
    )
}

#[cfg(unix)]
fn errno(error: nix::errno::Errno) -> io::Error {
    io::Error::from_raw_os_error(error as i32)
}

fn same_file(left: &Metadata, right: &Metadata) -> bool {
    #[cfg(unix)]
    {
        FileIdentity::of(left) == FileIdentity::of(right)
    }
    #[cfg(not(unix))]
    {
        let _ = (left, right);
        true
    }
}

/// Walked directories only serve as `openat` bases and `fstat` targets, which
/// need search permission; `O_PATH` does not also require read permission.
#[cfg(unix)]
fn directory_walk_flags() -> nix::fcntl::OFlag {
    use nix::fcntl::OFlag;
    #[cfg(any(target_os = "linux", target_os = "android"))]
    let access = OFlag::O_PATH;
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    let access = OFlag::O_RDONLY;
    access | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC
}

#[cfg(unix)]
fn open_directory(path: &Path) -> io::Result<File> {
    use nix::fcntl::{open, openat};
    use nix::sys::stat::Mode;
    let components: Vec<_> = path
        .components()
        .take(MAX_PATH_COMPONENTS + 1)
        .inspect(|_| {
            count!(component_inspections);
        })
        .collect();
    if !path.is_absolute() || components.len() > MAX_PATH_COMPONENTS {
        return Err(denied());
    }
    count!(directory_opens);
    let mut directory =
        File::from(open("/", directory_walk_flags(), Mode::empty()).map_err(errno)?);
    for component in components {
        match component {
            Component::RootDir => {}
            Component::Normal(name) => {
                count!(directory_opens);
                directory = File::from(
                    openat(&directory, name, directory_walk_flags(), Mode::empty())
                        .map_err(errno)?,
                );
            }
            _ => return Err(denied()),
        }
    }
    Ok(directory)
}

#[cfg(not(unix))]
fn open_directory(path: &Path) -> io::Result<File> {
    File::open(path)
}

fn open_canonical(path: &Path) -> io::Result<(File, File)> {
    let directory = open_directory(path.parent().ok_or_else(denied)?)?;
    #[cfg(unix)]
    let file = {
        use nix::fcntl::{OFlag, openat};
        use nix::sys::stat::Mode;
        count!(source_opens);
        File::from(
            openat(
                &directory,
                path.file_name().ok_or_else(denied)?,
                OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK | OFlag::O_CLOEXEC,
                Mode::empty(),
            )
            .map_err(errno)?,
        )
    };
    #[cfg(not(unix))]
    let file = File::open(path)?;
    Ok((file, directory))
}

#[cfg(test)]
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct Work {
    pub enumeration_probes: usize,
    pub entries: usize,
    pub backup_stats: usize,
    pub retained_identities: usize,
    pub component_inspections: usize,
    pub directory_opens: usize,
    pub source_opens: usize,
    pub source_stats: usize,
    pub fixed_stats: usize,
    pub directory_checks: usize,
    pub reads: usize,
}
#[cfg(test)]
thread_local! { static WORK: std::cell::RefCell<Work> = std::cell::RefCell::new(Work::default()); }
#[cfg(test)]
pub(crate) fn take_work() -> Work {
    WORK.with(|work| std::mem::take(&mut *work.borrow_mut()))
}
pub(crate) fn mark_read() {
    count!(reads);
}
pub(crate) fn mark_stat() {
    count!(source_stats);
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    fn fixture() -> (tempfile::TempDir, SourceFileTarget, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().canonicalize().unwrap().join("config.toml");
        std::fs::write(&config, "accepted").unwrap();
        let (_, target) = SourceFileTarget::open(&config).unwrap();
        (dir, target, config)
    }

    #[test]
    fn normal_loader_preserves_static_in_root_symlinks() {
        let (dir, target, config) = fixture();
        let base = dir.path().canonicalize().unwrap();
        let source = base.join("safe.rpol");
        let link = base.join("input.rpol");
        std::fs::write(&source, "policy p { term t { accept } }\n").unwrap();
        std::os::unix::fs::symlink("safe.rpol", &link).unwrap();
        let protection = SourceFileProtection::new(vec![config.clone()], Some(config))
            .snapshot(Some(&target))
            .unwrap();
        crate::rpol::RpolFile::load_protected(&link, &[base], 1024, &protection).unwrap();
    }

    /// Restores a directory's mode on drop so the tempdir can be removed.
    struct ModeGuard(PathBuf, u32);
    impl Drop for ModeGuard {
        fn drop(&mut self) {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&self.0, std::fs::Permissions::from_mode(self.1));
        }
    }

    fn set_mode(path: &Path, mode: u32) -> ModeGuard {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
        ModeGuard(path.to_path_buf(), 0o755)
    }

    #[test]
    fn search_only_config_ancestor_needs_no_read_permission() {
        let dir = tempfile::tempdir().unwrap();
        let ancestor = dir.path().canonicalize().unwrap().join("search-only");
        let parent = ancestor.join("etc");
        std::fs::create_dir_all(&parent).unwrap();
        let config = parent.join("config.toml");
        std::fs::write(&config, "accepted").unwrap();
        let _guard = set_mode(&ancestor, 0o311);
        if std::fs::read_dir(&ancestor).is_ok() {
            eprintln!("skipped: this process bypasses directory read permission");
            return;
        }
        let (_, target) = SourceFileTarget::open(&config).unwrap();
        target.verify_target().unwrap();
        SourceFileTarget::resolve(&config).unwrap();
        SourceFileProtection::new(vec![config.clone()], Some(config))
            .snapshot(Some(&target))
            .unwrap();
    }

    #[test]
    fn backup_inventory_needs_no_read_permission_on_backups() {
        let (dir, target, config) = fixture();
        let backup = dir.path().join("config.toml.unconfirmed-root-only");
        let alias = dir.path().join("alias.rpol");
        std::fs::write(&backup, "secret").unwrap();
        std::fs::hard_link(&backup, &alias).unwrap();
        let _guard = set_mode(&backup, 0o000);
        if File::open(&backup).is_ok() {
            eprintln!("skipped: this process bypasses file read permission");
            return;
        }
        let protection = SourceFileProtection::new(vec![config.clone()], Some(config))
            .snapshot(Some(&target))
            .unwrap();
        assert!(
            protection
                .check_opened(&alias, &std::fs::metadata(&alias).unwrap())
                .is_err()
        );
    }

    #[test]
    fn inventory_reports_a_later_directory_change() {
        let (dir, target, config) = fixture();
        let protection = SourceFileProtection::new(vec![config.clone()], Some(config))
            .snapshot(Some(&target))
            .unwrap();
        assert!(!protection.inventory_changed());
        assert!(!SourceFileProtection::default().inventory_changed());
        std::fs::write(dir.path().join("persister-stage"), "x").unwrap();
        assert!(protection.inventory_changed());
    }

    #[test]
    fn backup_inventory_refuses_aliases_but_allows_unrelated_hardlinks() {
        let (dir, target, config) = fixture();
        let backup = dir.path().join("config.toml.unconfirmed-old");
        let alias = dir.path().join("alias.rpol");
        let safe = dir.path().join("safe.rpol");
        let safe_alias = dir.path().join("safe-alias.rpol");
        std::fs::write(&backup, "secret").unwrap();
        std::fs::hard_link(&backup, &alias).unwrap();
        std::fs::write(&safe, "safe").unwrap();
        std::fs::hard_link(&safe, &safe_alias).unwrap();
        let protection = SourceFileProtection::new(vec![config.clone()], Some(config))
            .snapshot(Some(&target))
            .unwrap();
        assert!(
            protection
                .check_opened(&alias, &std::fs::metadata(&alias).unwrap())
                .is_err()
        );
        assert!(
            protection
                .check_opened(&safe_alias, &std::fs::metadata(&safe_alias).unwrap())
                .is_ok()
        );
        assert!(
            SourceFileProtection::default()
                .check_opened(&alias, &std::fs::metadata(&alias).unwrap())
                .is_ok()
        );
    }

    #[test]
    fn accepted_config_inode_survives_unlink() {
        let (dir, target, config) = fixture();
        let alias = dir.path().join("alias.rpol");
        std::fs::hard_link(&config, &alias).unwrap();
        std::fs::remove_file(&config).unwrap();
        assert!(
            SourceFileProtection::new(vec![config.clone()], Some(config))
                .snapshot(Some(&target))
                .is_err()
        );
    }

    #[test]
    fn backup_inventory_rechecks_preinventory_leaf_replacement() {
        let (dir, target, config) = fixture();
        target.verify_target().unwrap();
        let second = dir.path().join("second");
        let alias = dir.path().join("alias.rpol");
        std::fs::write(&second, "new accepted secret").unwrap();
        std::fs::rename(second, &config).unwrap();
        std::fs::hard_link(&config, &alias).unwrap();
        let third = dir.path().join("third");
        std::fs::write(&third, "external replacement").unwrap();
        std::fs::rename(third, &config).unwrap();
        assert!(
            SourceFileProtection::new(vec![config.clone()], Some(config))
                .snapshot(Some(&target))
                .is_err()
        );
        assert_eq!(
            std::fs::read_to_string(alias).unwrap(),
            "new accepted secret"
        );
    }

    #[test]
    fn backup_inventory_detects_directory_mutation() {
        let (dir, target, config) = fixture();
        let protection = SourceFileProtection::new(vec![config.clone()], Some(config))
            .snapshot(Some(&target))
            .unwrap();
        std::fs::write(dir.path().join("config.toml.unconfirmed-new"), "secret").unwrap();
        assert!(protection.check_directory().is_err());
    }

    #[test]
    fn protected_read_refuses_replaced_config_ancestor_without_rescanning() {
        let dir = tempfile::tempdir().unwrap();
        let ancestor = dir.path().canonicalize().unwrap().join("live");
        let parent = ancestor.join("nested");
        std::fs::create_dir_all(&parent).unwrap();
        let config = parent.join("config.toml");
        std::fs::write(&config, "accepted secret").unwrap();
        let (_, target) = SourceFileTarget::open(&config).unwrap();
        let replacement = dir.path().join("replacement");
        let next_parent = replacement.join("nested");
        std::fs::create_dir_all(&next_parent).unwrap();
        // Keep the accepted leaf identity unchanged to isolate its parent authority.
        std::fs::hard_link(&config, next_parent.join("config.toml")).unwrap();
        let backup = next_parent.join("config.toml.unconfirmed-copy");
        std::fs::copy(&config, &backup).unwrap();
        std::fs::hard_link(&backup, next_parent.join("alias.rpol")).unwrap();
        let protection = SourceFileProtection::new(vec![config.clone()], Some(config))
            .snapshot(Some(&target))
            .unwrap();
        let before = DirectoryStamp::of(&target.parent.metadata().unwrap());
        std::fs::rename(&ancestor, dir.path().join("retired")).unwrap();
        std::fs::rename(replacement, &ancestor).unwrap();
        assert_eq!(
            DirectoryStamp::of(&target.parent.metadata().unwrap()),
            before
        );
        let alias = parent.join("alias.rpol");
        assert_eq!(std::fs::read(&alias).unwrap(), b"accepted secret");
        take_work();
        assert!(
            crate::datasets::read_regular_file_bounded_protected(&alias, 1024, &protection)
                .is_err()
        );
        let work = take_work();
        assert_eq!(work.enumeration_probes, 0);
        assert_eq!(work.entries, 0);
        assert_eq!(work.backup_stats, 0);
        assert_eq!(work.retained_identities, 0);
        let components = parent.components().count();
        assert_eq!(work.component_inspections, 2 * components);
        assert_eq!(work.directory_opens, 2 * components);
        assert_eq!(work.source_opens, 1);
        assert_eq!(work.source_stats, 2);
        assert_eq!(work.fixed_stats, 2);
        assert_eq!(work.directory_checks, 1);
        assert_eq!(work.reads, 0);
    }

    #[test]
    fn component_inspection_stops_at_limit_plus_probe() {
        let path = PathBuf::from(format!(
            "/{}",
            "absent-component/".repeat(MAX_PATH_COMPONENTS * 2)
        ));
        take_work();
        assert!(open_directory(&path).is_err());
        let work = take_work();
        assert_eq!(work.component_inspections, MAX_PATH_COMPONENTS + 1);
        assert_eq!(work.directory_opens, 0);
        assert_eq!(work.source_opens, 0);
        assert_eq!(work.source_stats, 0);
        assert_eq!(work.enumeration_probes, 0);
        assert_eq!(work.entries, 0);
        assert_eq!(work.backup_stats, 0);
        assert_eq!(work.retained_identities, 0);
        assert_eq!(work.fixed_stats, 0);
        assert_eq!(work.directory_checks, 0);
        assert_eq!(work.reads, 0);
    }

    #[test]
    fn backup_inventory_bounds_each_work_counter() {
        let (dir, target, config) = fixture();
        // Include the config plus dot entries in the total cap.
        for index in 0..MAX_BACKUP_DIRECTORY_ENTRIES - 3 {
            std::fs::write(
                dir.path().join(format!("config.toml.unconfirmed-{index}")),
                "x",
            )
            .unwrap();
        }
        take_work();
        let protection = SourceFileProtection::new(vec![config.clone()], Some(config.clone()))
            .snapshot(Some(&target))
            .unwrap();
        let work = take_work();
        assert_eq!(work.enumeration_probes, MAX_BACKUP_DIRECTORY_ENTRIES + 1);
        assert_eq!(work.entries, MAX_BACKUP_DIRECTORY_ENTRIES);
        assert_eq!(work.backup_stats, MAX_BACKUP_DIRECTORY_ENTRIES - 3);
        assert_eq!(work.retained_identities, MAX_BACKUP_DIRECTORY_ENTRIES - 3);
        assert_eq!(
            work.component_inspections,
            target.path.parent().unwrap().components().count()
        );
        assert_eq!(
            work.directory_opens,
            1 + target.path.parent().unwrap().components().count()
        );
        assert_eq!(work.source_opens, 0);
        assert_eq!(work.source_stats, 0);
        assert_eq!(work.fixed_stats, 2);
        assert_eq!(work.directory_checks, 2);
        assert_eq!(work.reads, 0);
        drop(protection);
        std::fs::write(dir.path().join("extra"), "x").unwrap();
        assert!(
            SourceFileProtection::new(vec![config.clone()], Some(config))
                .snapshot(Some(&target))
                .is_err()
        );
        let work = take_work();
        assert_eq!(work.enumeration_probes, MAX_BACKUP_DIRECTORY_ENTRIES + 1);
        assert_eq!(work.entries, MAX_BACKUP_DIRECTORY_ENTRIES + 1);
        assert!(work.backup_stats <= MAX_BACKUP_DIRECTORY_ENTRIES - 3);
        assert_eq!(work.retained_identities, work.backup_stats);
        assert_eq!(work.component_inspections, 0);
        assert_eq!(work.directory_opens, 1);
        assert_eq!(work.source_opens, 0);
        assert_eq!(work.source_stats, 0);
        assert_eq!(work.fixed_stats, 0);
        assert_eq!(work.directory_checks, 1);
        assert_eq!(work.reads, 0);
    }
}
