//! Atomic file writer for MRT dumps with optional gzip compression.

use std::collections::BTreeSet;
use std::io::Write;
use std::num::NonZeroU32;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};

use chrono::Utc;
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

/// Ensure the configured output path exists as a directory the daemon owns.
///
/// Missing directories are created 0700. An existing directory is held to the
/// runtime-state directory's rule: a real directory, not a symlink, owned by
/// the effective UID and not group- or world-writable. Retention deletes the
/// oldest names here, so another user who could plant newer-named files could
/// make it delete real dumps. `config.ancestor_check`, when set, then vets the
/// directories above it. Publishing and pruning use paths rather than a
/// pinned descriptor; that is sound because the ancestor check refuses any
/// parent that a user other than root or the daemon user could rename.
/// A group- or other-readable directory is only warned about; it is an
/// operator-chosen path that may be shared, so it is never chmodded. Dump
/// files themselves are 0600.
///
/// The manager calls this before asking the RIB actor to materialize a
/// snapshot. `write_dump` repeats the check so direct library callers retain
/// the same lazy-directory-creation contract.
pub(crate) fn prepare_output_dir(config: &MrtWriterConfig) -> std::io::Result<()> {
    validate_file_prefix(&config.file_prefix)?;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&config.output_dir)?;
    let metadata = std::fs::symlink_metadata(&config.output_dir)?;
    let mode = metadata.mode() & 0o7777;
    if !metadata.is_dir() || metadata.uid() != nix::unistd::geteuid().as_raw() || mode & 0o022 != 0
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "MRT output_dir {} must be a real directory owned by the daemon user and not \
                 group- or world-writable (is_dir={}, uid={}, mode={mode:o})",
                config.output_dir.display(),
                metadata.is_dir(),
                metadata.uid(),
            ),
        ));
    }
    if let Some(check) = config.ancestor_check {
        check(&config.output_dir)?;
    }
    if mode & 0o077 != 0
        && WARNED_READABLE_DIRS
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(config.output_dir.clone())
    {
        warn!(
            output_dir = %config.output_dir.display(),
            mode = format_args!("{mode:o}"),
            "MRT output_dir is accessible to group or other; dump files are 0600 but their names are listable"
        );
    }
    Ok(())
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
/// own pattern are considered.
fn prune_old_dumps(
    output_dir: &Path,
    prefix: &str,
    keep: NonZeroU32,
    published: &Path,
) -> std::io::Result<()> {
    let published = published.file_name();
    let mut dumps = Vec::new();
    for entry in std::fs::read_dir(output_dir)? {
        let entry = entry?;
        let name = entry.file_name();
        if Some(name.as_os_str()) == published || !entry.file_type()?.is_file() {
            continue;
        }
        if let Some(stamp) = name.to_str().and_then(|name| dump_timestamp(name, prefix)) {
            dumps.push((stamp.to_owned(), entry.path()));
        }
    }
    // The published dump counts toward `keep`; retain the newest others.
    let keep_others = usize::try_from(keep.get() - 1).unwrap_or(usize::MAX);
    if dumps.len() <= keep_others {
        return Ok(());
    }
    dumps.sort_unstable();
    let excess = dumps.len() - keep_others;
    for (_, path) in dumps.drain(..excess) {
        match std::fs::remove_file(&path) {
            Ok(()) => debug!(path = %path.display(), "pruned old MRT dump"),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

/// Sync MRT data before atomic rename, then sync its parent directory.
///
/// Returns the final file path on success.
///
/// # Errors
///
/// Returns an error if prefix validation, directory creation, staging, syncing or renaming fails.
/// A parent-directory sync error occurs after the final file is published;
/// retrying after that error can produce a second dump.
pub fn write_dump(config: &MrtWriterConfig, data: &[u8]) -> std::io::Result<PathBuf> {
    prepare_output_dir(config)?;

    let now = Utc::now();
    let timestamp = now.format("%Y%m%d.%H%M%S");
    let nanos = now.timestamp_subsec_nanos();
    let ext = if config.compress { ".mrt.gz" } else { ".mrt" };
    let filename = format!("{}.{timestamp}.{nanos:09}{ext}", config.file_prefix);
    let final_path = config.output_dir.join(&filename);
    let tmp_path = config.output_dir.join(format!(".{filename}.tmp"));

    debug!(path = %final_path.display(), bytes = data.len(), "writing MRT dump");

    write_atomic(&tmp_path, &final_path, data, config.compress)?;

    info!(
        path = %final_path.display(),
        bytes = data.len(),
        compressed = config.compress,
        "MRT dump written"
    );

    // Retention runs only after the new dump is durably published, and a
    // pruning failure never fails the dump that already succeeded.
    if let Some(keep) = config.max_files
        && let Err(error) =
            prune_old_dumps(&config.output_dir, &config.file_prefix, keep, &final_path)
    {
        warn!(
            output_dir = %config.output_dir.display(),
            error = %error,
            "MRT dump retention failed; older dumps were kept"
        );
    }

    Ok(final_path)
}

fn write_atomic(
    tmp_path: &Path,
    final_path: &Path,
    data: &[u8],
    compress: bool,
) -> std::io::Result<()> {
    let directory = std::fs::File::open(
        final_path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new(".")),
    )?;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(tmp_path)?;
    let result = (|| -> std::io::Result<()> {
        if compress {
            let mut encoder =
                flate2::write::GzEncoder::new(&mut file, flate2::Compression::default());
            encoder.write_all(data)?;
            encoder.finish()?;
        } else {
            file.write_all(data)?;
        }
        file.sync_all()?;
        std::fs::rename(tmp_path, final_path)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(tmp_path);
    }
    result?;
    directory.sync_all().map_err(|error| {
        std::io::Error::new(
            error.kind(),
            format!("MRT dump published but parent directory sync failed: {error}"),
        )
    })
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

    use super::*;

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
        let path = write_dump(&config, data).unwrap();
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
        let path = write_dump(&config, data).unwrap();
        assert!(path.exists());
        assert!(path.to_string_lossy().ends_with(".mrt.gz"));

        // Decompress and verify
        let compressed = std::fs::read(&path).unwrap();
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

        let path = write_dump(&config, &[]).unwrap();
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

            assert!(write_atomic(&tmp_path, &final_path, b"replacement", compress).is_err());
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

        let error = write_atomic(&tmp_path, &final_path, b"replacement", false).unwrap_err();
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

        let path = write_dump(&config, b"test").unwrap();
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

        let first = write_dump(&config, b"first").unwrap();
        // Ensure different timestamp component on coarse clocks.
        std::thread::sleep(std::time::Duration::from_millis(1));
        let second = write_dump(&config, b"second").unwrap();

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
            let path = write_dump(&config, b"routes").unwrap();
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

        // A symlinked output_dir is refused, as the runtime-state directory is.
        let real = private_tempdir();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(real.path(), &link).unwrap();
        let error = write_dump(&retaining(&link, 10), b"refused").unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        assert_eq!(file_names(real.path()), Vec::<String>::new());
    }

    #[test]
    fn ancestor_check_failure_fails_the_dump_before_publishing() {
        fn refuse(_: &Path) -> std::io::Result<()> {
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
            published.push(write_dump(&config, b"dump").unwrap());
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
        let newest = write_dump(&config, b"second").unwrap();

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

        prune_old_dumps(dir.path(), "rib", NonZeroU32::new(1).unwrap(), &published).unwrap();
        assert!(published.exists());
        assert!(!newer.exists());
    }
}
