//! Atomic file writer for MRT dumps with optional gzip compression.

use std::collections::BTreeSet;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::num::NonZeroU32;
use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, PoisonError};

use chrono::Utc;
use nix::dir::Dir;
use nix::errno::Errno;
use nix::fcntl::{AtFlags, OFlag, open, openat, renameat};
use nix::sys::stat::{Mode, SFlag, fstatat};
use nix::unistd::{UnlinkatFlags, geteuid, unlinkat};
use tracing::{debug, info, warn};

use crate::types::MrtWriterConfig;

/// Validate the filename prefix without touching the filesystem.
///
/// # Errors
///
/// Returns [`std::io::ErrorKind::InvalidInput`] unless `prefix` is a nonempty
/// filename component other than `.` or `..`, without separators or NUL.
pub fn validate_file_prefix(prefix: &str) -> std::io::Result<()> {
    if prefix.is_empty() || matches!(prefix, "." | "..") || prefix.contains(['/', '\\', '\0']) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "file_prefix must be a nonempty filename component without separators or NUL, other than '.' or '..'",
        ));
    }
    Ok(())
}

/// Directories already warned about for group or other access, so the
/// warning appears once per process per directory.
static WARNED_READABLE_DIRS: Mutex<BTreeSet<PathBuf>> = Mutex::new(BTreeSet::new());

/// The validated output directory, pinned by descriptor for one dump.
///
/// Publishing and pruning are relative to `file`, so renaming the directory
/// or replacing it with a symlink after validation cannot redirect them.
pub(crate) struct OutputDir {
    file: File,
    /// Normalized spelling of the configured path, for messages and the
    /// returned dump path only.
    path: PathBuf,
}

/// Ensure the configured output path exists as a directory the daemon owns.
///
/// The manager calls this before asking the RIB actor to materialize a
/// snapshot. `write_dump` repeats the check so direct library callers retain
/// the same lazy-directory-creation contract.
pub(crate) fn prepare_output_dir(config: &MrtWriterConfig) -> std::io::Result<()> {
    open_output_dir(config).map(drop)
}

/// Create, open and validate the output directory.
///
/// Missing directories are created 0700. The directory is held to the
/// runtime-state directory's rule: opened with `O_NOFOLLOW`, so it must be a
/// real directory and not a symlink however it is spelled, and the opened
/// descriptor must be owned by the effective UID and not group- or
/// world-writable. Retention deletes the oldest names here, so another user
/// who could plant newer-named files could make it delete real dumps.
/// `config.ancestor_check`, when set, then vets the directories above the
/// opened descriptor, so the proof covers the directory written into. A
/// group- or other-readable directory is only warned about; it is an
/// operator-chosen path that may be shared, so it is never chmodded. Dump
/// files themselves are 0600.
fn open_output_dir(config: &MrtWriterConfig) -> std::io::Result<OutputDir> {
    validate_file_prefix(&config.file_prefix)?;
    // `dir/` and `dir/.` name the same entry as `dir`, but O_NOFOLLOW would
    // judge their final `.` and follow a symlink at `dir`. Pin the spelling
    // without them, so a symlinked directory is refused however it is
    // written. A final `..` cannot be judged that way at all.
    let path: PathBuf = config.output_dir.components().collect();
    if matches!(
        path.components().next_back(),
        None | Some(std::path::Component::ParentDir)
    ) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "MRT output_dir {} must name a directory, not end in `..`",
                config.output_dir.display()
            ),
        ));
    }
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&path)?;
    let fd = open(
        &path,
        OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|errno| match errno {
        Errno::ELOOP | Errno::ENOTDIR => std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "MRT output_dir {} must be a real directory, not a symlink",
                path.display()
            ),
        ),
        errno => errno.into(),
    })?;
    let file = File::from(fd);
    let metadata = file.metadata()?;
    let mode = metadata.mode() & 0o7777;
    if !metadata.is_dir() || metadata.uid() != geteuid().as_raw() || mode & 0o022 != 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "MRT output_dir {} must be a real directory owned by the daemon user and not \
                 group- or world-writable (is_dir={}, uid={}, mode={mode:o})",
                path.display(),
                metadata.is_dir(),
                metadata.uid(),
            ),
        ));
    }
    if let Some(check) = config.ancestor_check {
        check(&path, &file)?;
    }
    if mode & 0o077 != 0
        && WARNED_READABLE_DIRS
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(path.clone())
    {
        warn!(
            output_dir = %path.display(),
            mode = format_args!("{mode:o}"),
            "MRT output_dir is accessible to group or other; dump files are 0600 but their names are listable"
        );
    }
    Ok(OutputDir { file, path })
}

/// Parse `<prefix>.<YYYYMMDD>.<HHMMSS>.<nanos>.mrt[.gz]` and return the
/// fixed-width timestamp part, which sorts chronologically.
fn dump_timestamp<'a>(name: &'a str, prefix: &str) -> Option<&'a str> {
    let rest = name.strip_prefix(prefix)?.strip_prefix('.')?;
    let stamp = rest
        .strip_suffix(".mrt.gz")
        .or_else(|| rest.strip_suffix(".mrt"))?;
    let bytes = stamp.as_bytes();
    let shape_ok = bytes.len() == 8 + 1 + 6 + 1 + 9
        && bytes.iter().enumerate().all(|(index, byte)| match index {
            8 | 15 => *byte == b'.',
            _ => byte.is_ascii_digit(),
        });
    shape_ok.then_some(stamp)
}

/// Delete this writer's oldest dumps so at most `keep` remain, never
/// `published`. Only regular files whose whole name matches the writer's
/// own pattern are considered. Every lookup is relative to the pinned
/// directory descriptor.
fn prune_old_dumps(
    dir: &OutputDir,
    prefix: &str,
    keep: NonZeroU32,
    published: &str,
) -> std::io::Result<()> {
    let mut entries = Dir::openat(
        &dir.file,
        ".",
        OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC,
        Mode::empty(),
    )?;
    let mut dumps = Vec::new();
    for entry in entries.iter() {
        let entry = entry?;
        let Ok(name) = entry.file_name().to_str() else {
            continue;
        };
        if name == published {
            continue;
        }
        let Some(stamp) = dump_timestamp(name, prefix) else {
            continue;
        };
        let stat = fstatat(&dir.file, name, AtFlags::AT_SYMLINK_NOFOLLOW)?;
        if SFlag::from_bits_truncate(stat.st_mode) & SFlag::S_IFMT != SFlag::S_IFREG {
            continue;
        }
        dumps.push((stamp.to_owned(), name.to_owned()));
    }
    // The published dump counts toward `keep`; retain the newest others.
    let keep_others = usize::try_from(keep.get() - 1).unwrap_or(usize::MAX);
    if dumps.len() <= keep_others {
        return Ok(());
    }
    dumps.sort_unstable();
    let excess = dumps.len() - keep_others;
    for (_, name) in dumps.drain(..excess) {
        match unlinkat(&dir.file, name.as_str(), UnlinkatFlags::NoRemoveDir) {
            Ok(()) => debug!(path = %dir.path.join(&name).display(), "pruned old MRT dump"),
            Err(Errno::ENOENT) => {}
            Err(errno) => return Err(errno.into()),
        }
    }
    Ok(())
}

/// Sync MRT data before atomic rename, then sync its parent directory.
///
/// Returns the final file path and the published file's size in bytes. The
/// size comes from the written file's descriptor, so it describes the dump
/// published even if the directory's path changes afterward.
///
/// # Errors
///
/// Returns an error if prefix validation, directory creation, staging, syncing or renaming fails.
/// A parent-directory sync error occurs after the final file is published;
/// retrying after that error can produce a second dump.
pub fn write_dump(config: &MrtWriterConfig, data: &[u8]) -> std::io::Result<(PathBuf, u64)> {
    let dir = open_output_dir(config)?;
    publish(&dir, config, data)
}

/// Publish one dump into the pinned directory, then apply retention there.
fn publish(
    dir: &OutputDir,
    config: &MrtWriterConfig,
    data: &[u8],
) -> std::io::Result<(PathBuf, u64)> {
    let mut dump = StreamingDump::in_dir(dir, config)?;
    dump.write_all(data)?;
    dump.finish(&AtomicBool::new(false))
}

/// One bounded-memory dump, staged in the validated directory until complete.
pub(crate) struct StreamingDump {
    dir: OutputDir,
    config: MrtWriterConfig,
    filename: String,
    stage: StagedFile,
    next_run: u64,
}

fn dump_filename(config: &MrtWriterConfig) -> String {
    let now = Utc::now();
    let timestamp = now.format("%Y%m%d.%H%M%S");
    let nanos = now.timestamp_subsec_nanos();
    let ext = if config.compress { ".mrt.gz" } else { ".mrt" };
    format!("{}.{timestamp}.{nanos:09}{ext}", config.file_prefix)
}

impl StreamingDump {
    pub(crate) fn new(config: &MrtWriterConfig) -> std::io::Result<Self> {
        Self::in_dir(&open_output_dir(config)?, config)
    }

    fn in_dir(dir: &OutputDir, config: &MrtWriterConfig) -> std::io::Result<Self> {
        let filename = dump_filename(config);
        let final_path = dir.path.join(&filename);
        let tmp_name = format!(".{filename}.tmp");

        debug!(path = %final_path.display(), "staging MRT dump");
        let stage = StagedFile::new(&dir.file, &tmp_name, &filename, config.compress)?;
        Ok(Self {
            dir: OutputDir {
                file: dir.file.try_clone()?,
                path: dir.path.clone(),
            },
            config: config.clone(),
            filename,
            stage,
            next_run: 0,
        })
    }

    /// An anonymous, owner-only file in the same filesystem for an EVPN sort run.
    /// Unlink immediately so cancellation and process death cannot leave runs.
    pub(crate) fn create_run(&mut self) -> std::io::Result<File> {
        let name = format!(".{}.run.{}", self.filename, self.next_run);
        self.next_run = self
            .next_run
            .checked_add(1)
            .ok_or_else(|| std::io::Error::other("MRT sort run counter exhausted"))?;
        let file = File::from(openat(
            &self.dir.file,
            name.as_str(),
            OFlag::O_RDWR | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
            Mode::from_bits_truncate(0o600),
        )?);
        unlinkat(&self.dir.file, name.as_str(), UnlinkatFlags::NoRemoveDir)?;
        Ok(file)
    }

    pub(crate) fn finish(self, cancelled: &AtomicBool) -> std::io::Result<(PathBuf, u64)> {
        let Self {
            dir,
            config,
            mut stage,
            ..
        } = self;
        let filename = dump_filename(&config);
        stage.final_name.clone_from(&filename);
        let final_path = dir.path.join(&filename);
        let size = stage.finish(cancelled)?;
        info!(path = %final_path.display(), bytes = size, compressed = config.compress, "MRT dump written");

        // Retention runs only after the new dump is durably published, and a
        // pruning failure never fails the dump that already succeeded.
        if let Some(keep) = config.max_files
            && let Err(error) = prune_old_dumps(&dir, &config.file_prefix, keep, &filename)
        {
            warn!(
                output_dir = %dir.path.display(),
                error = %error,
                "MRT dump retention failed; older dumps were kept"
            );
        }

        Ok((final_path, size))
    }
}

impl Write for StreamingDump {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.stage.write(bytes)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.stage.flush()
    }
}

/// Stage, sync and rename one dump; returns its size from the descriptor.
#[cfg(test)]
fn write_atomic(
    directory: &File,
    tmp_name: &str,
    final_name: &str,
    data: &[u8],
    compress: bool,
) -> std::io::Result<u64> {
    let mut stage = StagedFile::new(directory, tmp_name, final_name, compress)?;
    stage.write_all(data)?;
    stage.finish(&AtomicBool::new(false))
}

enum StagedOutput {
    Plain(StageSink),
    Gzip(flate2::write::GzEncoder<StageSink>),
}

/// Detach unfinished buffers before gzip's destructor can write on an async owner.
struct StageSink(Option<BufWriter<File>>);

impl Write for StageSink {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0
            .as_mut()
            .ok_or_else(|| std::io::Error::other("MRT stage discarded"))?
            .write(bytes)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.0
            .as_mut()
            .ok_or_else(|| std::io::Error::other("MRT stage discarded"))?
            .flush()
    }
}

struct StagedFile {
    directory: File,
    tmp_name: String,
    final_name: String,
    output: Option<StagedOutput>,
}

impl StagedFile {
    fn new(
        directory: &File,
        tmp_name: &str,
        final_name: &str,
        compress: bool,
    ) -> std::io::Result<Self> {
        // Clone before creating the file: an fd exhaustion error must not leave a stage.
        let directory = directory.try_clone()?;
        let file = File::from(openat(
            &directory,
            tmp_name,
            OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
            Mode::from_bits_truncate(0o600),
        )?);
        let buffered = StageSink(Some(BufWriter::with_capacity(64 * 1024, file)));
        let output = if compress {
            StagedOutput::Gzip(flate2::write::GzEncoder::new(
                buffered,
                flate2::Compression::default(),
            ))
        } else {
            StagedOutput::Plain(buffered)
        };
        Ok(Self {
            directory,
            tmp_name: tmp_name.to_owned(),
            final_name: final_name.to_owned(),
            output: Some(output),
        })
    }

    fn finish(mut self, cancelled: &AtomicBool) -> std::io::Result<u64> {
        check_cancelled(cancelled)?;
        let output = self
            .output
            .take()
            .ok_or_else(|| std::io::Error::other("MRT stage already finished"))?;
        let sink = match output {
            StagedOutput::Plain(file) => file,
            StagedOutput::Gzip(encoder) => encoder.finish()?,
        };
        let file = sink
            .0
            .ok_or_else(|| std::io::Error::other("MRT stage discarded"))?
            .into_inner()
            .map_err(std::io::IntoInnerError::into_error)?;
        durability::sync(&file, "file")?;
        let size = file.metadata()?.len();
        check_cancelled(cancelled)?;
        renameat(
            &self.directory,
            self.tmp_name.as_str(),
            &self.directory,
            self.final_name.as_str(),
        )?;
        #[cfg(test)]
        durability::record("rename");
        durability::sync(&self.directory, "directory").map_err(|error| {
            std::io::Error::new(
                error.kind(),
                format!("MRT dump published but parent directory sync failed: {error}"),
            )
        })?;
        Ok(size)
    }
}

impl Write for StagedFile {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        match self.output.as_mut() {
            Some(StagedOutput::Plain(file)) => file.write(bytes),
            Some(StagedOutput::Gzip(encoder)) => encoder.write(bytes),
            None => Err(std::io::Error::other("MRT stage already finished")),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self.output.as_mut() {
            Some(StagedOutput::Plain(file)) => file.flush(),
            Some(StagedOutput::Gzip(encoder)) => encoder.flush(),
            None => Err(std::io::Error::other("MRT stage already finished")),
        }
    }
}

impl Drop for StagedFile {
    fn drop(&mut self) {
        let sink = match self.output.as_mut() {
            Some(StagedOutput::Plain(sink)) => Some(sink),
            Some(StagedOutput::Gzip(encoder)) => Some(encoder.get_mut()),
            None => None,
        };
        if let Some(buffered) = sink.and_then(|sink| sink.0.take()) {
            drop(buffered.into_parts());
        }
        let _ = unlinkat(
            &self.directory,
            self.tmp_name.as_str(),
            UnlinkatFlags::NoRemoveDir,
        );
    }
}

/// Publication's durability barriers; test builds log their order per thread.
mod durability {
    #[cfg(test)]
    thread_local! {
        static EVENTS: std::cell::RefCell<Vec<&'static str>> = const {
            std::cell::RefCell::new(Vec::new())
        };
    }

    pub(super) fn sync(file: &std::fs::File, what: &'static str) -> std::io::Result<()> {
        let result = file.sync_all();
        #[cfg(test)]
        record(what);
        #[cfg(not(test))]
        let _ = what;
        result
    }

    #[cfg(test)]
    pub(super) fn record(event: &'static str) {
        EVENTS.with(|events| events.borrow_mut().push(event));
    }

    #[cfg(test)]
    pub(super) fn take() -> Vec<&'static str> {
        EVENTS.with(|events| std::mem::take(&mut *events.borrow_mut()))
    }
}

/// Remove stage files a previous process left behind in this writer's
/// output directory: `.<dump name>.tmp` and an unlinked-too-late
/// `.<dump name>.run.<n>`, where `<dump name>` is this writer's own
/// `<prefix>.<stamp>.mrt[.gz]`. Nothing else is touched. A missing
/// directory is left for the first dump to create. Returns the number of
/// files removed; per-file failures are logged and skipped.
pub(crate) fn sweep_stale_stages(config: &MrtWriterConfig) -> std::io::Result<usize> {
    let path: PathBuf = config.output_dir.components().collect();
    if !path.try_exists()? {
        return Ok(0);
    }
    let dir = open_output_dir(config)?;
    let mut entries = Dir::openat(
        &dir.file,
        ".",
        OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC,
        Mode::empty(),
    )?;
    let mut removed = 0;
    for entry in entries.iter() {
        let entry = entry?;
        let Ok(name) = entry.file_name().to_str() else {
            continue;
        };
        if !is_stage_name(name, &config.file_prefix) {
            continue;
        }
        let regular = fstatat(&dir.file, name, AtFlags::AT_SYMLINK_NOFOLLOW).is_ok_and(|stat| {
            SFlag::from_bits_truncate(stat.st_mode) & SFlag::S_IFMT == SFlag::S_IFREG
        });
        if !regular {
            continue;
        }
        match unlinkat(&dir.file, name, UnlinkatFlags::NoRemoveDir) {
            Ok(()) => {
                removed += 1;
                info!(path = %dir.path.join(name).display(), "removed stale MRT stage file");
            }
            Err(Errno::ENOENT) => {}
            Err(errno) => warn!(
                path = %dir.path.join(name).display(),
                error = %errno,
                "failed to remove stale MRT stage file"
            ),
        }
    }
    Ok(removed)
}

/// `.{dump}.tmp` or `.{dump}.run.{n}` for one of this writer's dump names.
fn is_stage_name(name: &str, prefix: &str) -> bool {
    let Some(name) = name.strip_prefix('.') else {
        return false;
    };
    let dump = name.strip_suffix(".tmp").or_else(|| {
        let (dump, run) = name.rsplit_once(".run.")?;
        (!run.is_empty() && run.bytes().all(|byte| byte.is_ascii_digit())).then_some(dump)
    });
    dump.is_some_and(|dump| dump_timestamp(dump, prefix).is_some())
}

pub(crate) fn check_cancelled(cancelled: &AtomicBool) -> std::io::Result<()> {
    if cancelled.load(Ordering::Acquire) {
        // `Write::write_all` retries Interrupted indefinitely.
        Err(std::io::Error::other("MRT dump canceled"))
    } else {
        Ok(())
    }
}

/// A test directory the writer accepts under any umask: tempfile creates
/// directories with the process default mode.
#[cfg(test)]
pub(crate) fn private_tempdir() -> tempfile::TempDir {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    dir
}

#[cfg(test)]
mod tests {
    use std::io::Read;
    use std::path::Path;

    use super::*;

    #[test]
    fn dropping_a_stage_discards_plain_and_gzip_buffers() {
        for compress in [false, true] {
            let dir = private_tempdir();
            let directory = File::open(dir.path()).unwrap();
            let mut stage = StagedFile::new(&directory, ".partial", "published", compress).unwrap();
            let observed = File::open(dir.path().join(".partial")).unwrap();
            stage
                .write_all(b"an unfinished dump must not flush on drop")
                .unwrap();
            assert_eq!(observed.metadata().unwrap().len(), 0);
            drop(stage);
            assert_eq!(observed.metadata().unwrap().len(), 0);
            assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
        }
    }

    #[test]
    fn publication_syncs_the_file_before_rename_and_the_directory_after() {
        for compress in [false, true] {
            let dir = private_tempdir();
            let directory = File::open(dir.path()).unwrap();
            durability::take();
            write_atomic(&directory, ".stage", "published", b"dump", compress).unwrap();
            assert_eq!(durability::take(), ["file", "rename", "directory"]);
        }
    }

    #[test]
    fn startup_sweep_removes_only_this_writers_stage_files() {
        let dir = private_tempdir();
        let dump = "rib.20260101.000000.000000001";
        let stale = [
            format!(".{dump}.mrt.tmp"),
            format!(".{dump}.mrt.gz.tmp"),
            format!(".{dump}.mrt.run.0"),
            format!(".{dump}.mrt.gz.run.17"),
        ];
        let kept = [
            format!("{dump}.mrt"),
            format!("{dump}.mrt.tmp"),
            format!(".{dump}.mrt.tmp.bak"),
            format!(".{dump}.mrt.run."),
            format!(".{dump}.mrt.run.x"),
            format!(".{dump}.txt.tmp"),
            ".other.20260101.000000.000000001.mrt.tmp".to_owned(),
            ".rib.2026.tmp".to_owned(),
            ".rib.tmp".to_owned(),
        ];
        for name in stale.iter().chain(&kept) {
            std::fs::write(dir.path().join(name), b"x").unwrap();
        }
        // Stage-shaped names that are not regular files are left alone.
        let stage_dir = ".rib.20260101.000000.000000002.mrt.tmp".to_owned();
        std::fs::create_dir(dir.path().join(&stage_dir)).unwrap();
        let stage_link = ".rib.20260101.000000.000000003.mrt.tmp".to_owned();
        std::os::unix::fs::symlink(dir.path().join(&kept[0]), dir.path().join(&stage_link))
            .unwrap();
        let config = MrtWriterConfig {
            output_dir: dir.path().to_path_buf(),
            dump_interval: 3600,
            compress: false,
            file_prefix: "rib".to_string(),
            max_files: None,
            ancestor_check: None,
        };

        assert_eq!(sweep_stale_stages(&config).unwrap(), stale.len());
        let mut left: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect();
        left.sort_unstable();
        let mut expected: Vec<_> = kept
            .iter()
            .cloned()
            .chain([stage_dir, stage_link])
            .collect();
        expected.sort_unstable();
        assert_eq!(left, expected);

        let missing = MrtWriterConfig {
            output_dir: dir.path().join("not-created"),
            ..config
        };
        assert_eq!(sweep_stale_stages(&missing).unwrap(), 0);
        assert!(!missing.output_dir.exists(), "the sweep must not create it");
    }

    #[test]
    fn absolute_file_prefix_cannot_publish_outside_output_dir() {
        let dir = private_tempdir();
        let output_dir = dir.path().join("dumps");
        let escaped_prefix = dir.path().join("escaped");
        // Reproduce the existing staging path: prepending '.' makes the
        // absolute prefix relative, while the final path remains absolute.
        std::fs::create_dir_all(output_dir.join(format!(".{}", dir.path().display()))).unwrap();
        let config = MrtWriterConfig {
            output_dir,
            dump_interval: 3600,
            compress: false,
            file_prefix: escaped_prefix.to_str().unwrap().to_string(),
            max_files: None,
            ancestor_check: None,
        };
        let result = write_dump(&config, b"must stay inside dumps");
        assert!(result.is_err(), "published outside output_dir: {result:?}");
        assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::InvalidInput);
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[test]
    fn invalid_file_prefix_is_rejected_before_creating_output_dir() {
        let dir = private_tempdir();
        for prefix in [
            "", ".", "..", "/rib", "../rib", "dir/rib", "dir\\rib", "rib\0",
        ] {
            let output_dir = dir.path().join("not-created");
            let config = MrtWriterConfig {
                output_dir: output_dir.clone(),
                dump_interval: 3600,
                compress: false,
                file_prefix: prefix.to_string(),
                max_files: None,
                ancestor_check: None,
            };
            let error = write_dump(&config, b"no dump").unwrap_err();
            assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput, "{prefix:?}");
            assert!(!output_dir.exists(), "{prefix:?} created output directory");
        }
    }

    #[test]
    fn write_uncompressed() {
        let dir = private_tempdir();
        let config = MrtWriterConfig {
            output_dir: dir.path().to_path_buf(),
            dump_interval: 3600,
            compress: false,
            file_prefix: "rib".to_string(),
            max_files: None,
            ancestor_check: None,
        };

        let data = b"hello mrt";
        let path = write_dump(&config, data).unwrap().0;
        assert!(path.exists());
        assert!(path.to_string_lossy().ends_with(".mrt"));

        let content = std::fs::read(&path).unwrap();
        assert_eq!(content, data);
    }

    #[test]
    fn write_compressed() {
        let dir = private_tempdir();
        let config = MrtWriterConfig {
            output_dir: dir.path().to_path_buf(),
            dump_interval: 3600,
            compress: true,
            file_prefix: "rib".to_string(),
            max_files: None,
            ancestor_check: None,
        };

        let data = b"hello mrt compressed";
        let (path, size) = write_dump(&config, data).unwrap();
        assert!(path.exists());
        assert!(path.to_string_lossy().ends_with(".mrt.gz"));

        // Decompress and verify; the reported size is the compressed file's.
        let compressed = std::fs::read(&path).unwrap();
        assert_eq!(size, u64::try_from(compressed.len()).unwrap());
        let mut decoder = flate2::read::GzDecoder::new(&compressed[..]);
        let mut decompressed = Vec::new();
        decoder.read_to_end(&mut decompressed).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn write_empty_data() {
        let dir = private_tempdir();
        let config = MrtWriterConfig {
            output_dir: dir.path().to_path_buf(),
            dump_interval: 3600,
            compress: false,
            file_prefix: "empty".to_string(),
            max_files: None,
            ancestor_check: None,
        };

        let path = write_dump(&config, &[]).unwrap().0;
        assert!(path.exists());
        assert_eq!(std::fs::read(&path).unwrap().len(), 0);
    }

    #[test]
    fn failed_rename_removes_temp_and_preserves_destination() {
        for compress in [false, true] {
            let dir = private_tempdir();
            let final_path = dir.path().join("rib.mrt");
            // A directory destination forces rename to fail after the payload was staged.
            std::fs::create_dir(&final_path).unwrap();
            let original = final_path.join("original");
            std::fs::write(&original, "keep this").unwrap();
            let tmp_path = dir.path().join(".rib.mrt.tmp");

            let directory = File::open(dir.path()).unwrap();
            assert!(
                write_atomic(
                    &directory,
                    ".rib.mrt.tmp",
                    "rib.mrt",
                    b"replacement",
                    compress
                )
                .is_err()
            );
            assert!(!tmp_path.exists());
            assert!(final_path.is_dir());
            assert_eq!(std::fs::read_to_string(original).unwrap(), "keep this");
            assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
        }
    }

    #[test]
    fn existing_temp_is_not_overwritten_or_removed() {
        let dir = private_tempdir();
        let final_path = dir.path().join("rib.mrt");
        let tmp_path = dir.path().join(".rib.mrt.tmp");
        std::fs::write(&final_path, "original").unwrap();
        std::fs::write(&tmp_path, "another writer's stage").unwrap();

        let directory = File::open(dir.path()).unwrap();
        let error =
            write_atomic(&directory, ".rib.mrt.tmp", "rib.mrt", b"replacement", false).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists);
        assert_eq!(std::fs::read_to_string(final_path).unwrap(), "original");
        assert_eq!(
            std::fs::read_to_string(tmp_path).unwrap(),
            "another writer's stage"
        );
    }

    #[test]
    fn creates_output_dir() {
        let dir = private_tempdir();
        let nested = dir.path().join("a").join("b").join("c");
        let config = MrtWriterConfig {
            output_dir: nested.clone(),
            dump_interval: 3600,
            compress: false,
            file_prefix: "rib".to_string(),
            max_files: None,
            ancestor_check: None,
        };

        let path = write_dump(&config, b"test").unwrap().0;
        assert!(path.exists());
        assert!(nested.exists());
    }

    #[test]
    fn write_paths_are_unique_across_quick_successive_dumps() {
        let dir = private_tempdir();
        let config = MrtWriterConfig {
            output_dir: dir.path().to_path_buf(),
            dump_interval: 3600,
            compress: false,
            file_prefix: "rib".to_string(),
            max_files: None,
            ancestor_check: None,
        };

        let first = write_dump(&config, b"first").unwrap().0;
        // Ensure different timestamp component on coarse clocks.
        std::thread::sleep(std::time::Duration::from_millis(1));
        let second = write_dump(&config, b"second").unwrap().0;

        assert_ne!(first, second);
        assert!(first.exists());
        assert!(second.exists());
    }

    fn mode_of(path: &Path) -> u32 {
        std::fs::symlink_metadata(path).unwrap().mode() & 0o7777
    }

    fn file_names(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        names
    }

    fn retaining(output_dir: &Path, max_files: u32) -> MrtWriterConfig {
        MrtWriterConfig {
            output_dir: output_dir.to_path_buf(),
            dump_interval: 3600,
            compress: false,
            file_prefix: "rib".to_string(),
            max_files: NonZeroU32::new(max_files),
            ancestor_check: None,
        }
    }

    #[test]
    fn dumps_and_created_dirs_are_owner_only_under_umask_022() {
        use nix::sys::stat::{Mode, umask};

        const CHILD_ENV: &str = "RUSTBGPD_MRT_UMASK_TEST_CHILD";
        if std::env::var_os(CHILD_ENV).is_none() {
            // umask is process-wide: change it only in a dedicated child
            // invocation running this one test.
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "writer::tests::dumps_and_created_dirs_are_owner_only_under_umask_022",
                    "--test-threads=1",
                ])
                .env(CHILD_ENV, "1")
                .output()
                .unwrap();
            let stdout = String::from_utf8_lossy(&output.stdout);
            assert!(
                output.status.success() && stdout.contains("1 passed"),
                "{stdout}\n{}",
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }
        umask(Mode::from_bits_truncate(0o022));
        let dir = private_tempdir();
        let parent = dir.path().join("state");
        let output_dir = parent.join("mrt");
        for compress in [false, true] {
            let config = MrtWriterConfig {
                compress,
                ..retaining(&output_dir, 10)
            };
            let path = write_dump(&config, b"routes").unwrap().0;
            assert_eq!(mode_of(&path), 0o600, "{}", path.display());
        }
        assert_eq!(mode_of(&parent), 0o700);
        assert_eq!(mode_of(&output_dir), 0o700);
    }

    #[test]
    fn existing_output_dir_must_be_a_private_real_directory() {
        use std::os::unix::fs::PermissionsExt;

        let dir = private_tempdir();
        let config = retaining(dir.path(), 10);
        for mode in [0o770, 0o720, 0o757, 0o777, 0o1777] {
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(mode)).unwrap();
            let error = write_dump(&config, b"refused").unwrap_err();
            assert_eq!(
                error.kind(),
                std::io::ErrorKind::PermissionDenied,
                "{mode:o}"
            );
            assert!(file_names(dir.path()).is_empty(), "{mode:o}");
        }
        // Readable by group or other: warned about, never chmodded.
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        write_dump(&config, b"allowed").unwrap();
        assert_eq!(mode_of(dir.path()), 0o755);

        // A symlinked output_dir is refused however it is spelled, as the
        // runtime-state directory is; `dir/` and `dir/.` would otherwise
        // judge the symlink's target.
        let real = private_tempdir();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(real.path(), &link).unwrap();
        for spelling in [link.clone(), link.join(""), link.join(".")] {
            let error = write_dump(&retaining(&spelling, 10), b"refused").unwrap_err();
            assert_eq!(
                error.kind(),
                std::io::ErrorKind::PermissionDenied,
                "{}",
                spelling.display()
            );
        }
        assert_eq!(file_names(real.path()), Vec::<String>::new());
        // A final `..` cannot be judged without following it.
        let error = write_dump(&retaining(&real.path().join(".."), 10), b"refused").unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
    }

    #[test]
    fn dump_and_retention_stay_in_the_directory_pinned_at_validation() {
        let base = private_tempdir();
        let output_dir = base.path().join("mrt");
        let other = base.path().join("other");
        std::fs::create_dir(&other).unwrap();
        let decoy = "rib.20000101.000000.000000000.mrt".to_string();
        std::fs::write(other.join(&decoy), "not ours").unwrap();
        let config = retaining(&output_dir, 1);
        let pinned = open_output_dir(&config).unwrap();
        std::fs::write(output_dir.join(&decoy), "ours, old").unwrap();

        // Swap the validated directory for a symlink after the check.
        let moved = base.path().join("moved");
        std::fs::rename(&output_dir, &moved).unwrap();
        std::os::unix::fs::symlink(&other, &output_dir).unwrap();

        let published = publish(&pinned, &config, b"dump").unwrap().0;
        let name = published.file_name().unwrap().to_str().unwrap().to_string();
        assert_eq!(file_names(&moved), vec![name]);
        assert_eq!(file_names(&other), vec![decoy]);
    }

    #[test]
    fn ancestor_check_failure_fails_the_dump_before_publishing() {
        fn refuse(_: &Path, _: &File) -> std::io::Result<()> {
            Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "replaceable ancestor",
            ))
        }
        let dir = private_tempdir();
        let config = MrtWriterConfig {
            ancestor_check: Some(refuse),
            ..retaining(dir.path(), 10)
        };
        let error = write_dump(&config, b"refused").unwrap_err();
        assert_eq!(error.to_string(), "replaceable ancestor");
        assert_eq!(file_names(dir.path()), Vec::<String>::new());
    }

    #[test]
    fn retention_keeps_the_newest_max_files_dumps() {
        let dir = private_tempdir();
        let keep = 3;
        let mut published = Vec::new();
        for index in 0..keep + 2 {
            let config = MrtWriterConfig {
                // Both extensions belong to the writer and count together.
                compress: index % 2 == 1,
                ..retaining(dir.path(), keep)
            };
            published.push(write_dump(&config, b"dump").unwrap().0);
        }
        let expected: Vec<String> = published[2..]
            .iter()
            .map(|path| path.file_name().unwrap().to_str().unwrap().to_string())
            .collect();
        assert_eq!(file_names(dir.path()), expected);
    }

    #[test]
    fn retention_unset_keeps_every_dump() {
        let dir = private_tempdir();
        let config = retaining(dir.path(), 0);
        assert_eq!(config.max_files, None);
        for _ in 0..4 {
            write_dump(&config, b"dump").unwrap();
        }
        assert_eq!(file_names(dir.path()).len(), 4);
    }

    #[test]
    fn retention_leaves_files_outside_the_writer_pattern() {
        let dir = private_tempdir();
        let stamp = "20000101.000000.000000000";
        let unrelated = [
            "notes.txt".to_string(),
            "rib.mrt".to_string(),
            format!("rib.{stamp}.mrt.tmp"),
            format!(".rib.{stamp}.mrt.tmp"),
            format!("rib.v6.{stamp}.mrt"),
            format!("ribs.{stamp}.mrt"),
            format!("other.{stamp}.mrt.gz"),
            format!("rib.{stamp}.mrt.bz2"),
            "rib.20000101.000000.00000000x.mrt".to_string(),
        ];
        for name in &unrelated {
            std::fs::write(dir.path().join(name), "keep").unwrap();
        }
        // In-pattern but not a regular file: never removed.
        std::fs::create_dir(dir.path().join(format!("rib.{stamp}.mrt"))).unwrap();
        // In-pattern and older than every new dump: pruned.
        std::fs::write(dir.path().join(format!("rib.{stamp}.mrt.gz")), "old").unwrap();

        let config = retaining(dir.path(), 1);
        write_dump(&config, b"first").unwrap();
        let newest = write_dump(&config, b"second").unwrap().0;

        let mut expected: Vec<String> = unrelated.to_vec();
        expected.push(format!("rib.{stamp}.mrt"));
        expected.push(newest.file_name().unwrap().to_str().unwrap().to_string());
        expected.sort();
        assert_eq!(file_names(dir.path()), expected);
    }

    #[test]
    fn retention_never_removes_the_just_published_dump() {
        // A clock step backwards can give the new dump the oldest name.
        let dir = private_tempdir();
        let published = dir.path().join("rib.20000101.000000.000000000.mrt");
        let newer = dir.path().join("rib.20300101.000000.000000000.mrt");
        std::fs::write(&published, "new").unwrap();
        std::fs::write(&newer, "newer name").unwrap();

        let pinned = open_output_dir(&retaining(dir.path(), 1)).unwrap();
        let name = published.file_name().unwrap().to_str().unwrap();
        prune_old_dumps(&pinned, "rib", NonZeroU32::new(1).unwrap(), name).unwrap();
        assert!(published.exists());
        assert!(!newer.exists());
    }
}
