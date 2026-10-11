//! Atomic file writer for MRT dumps with optional gzip compression.

use std::io::Write;
use std::path::{Path, PathBuf};

use chrono::Utc;
use tracing::{debug, info};

use crate::types::MrtWriterConfig;

/// Ensure the configured output path exists as a directory.
///
/// The manager calls this before asking the RIB actor to materialize a
/// snapshot. `write_dump` repeats the check so direct library callers retain
/// the same lazy-directory-creation contract.
pub(crate) fn prepare_output_dir(config: &MrtWriterConfig) -> std::io::Result<()> {
    std::fs::create_dir_all(&config.output_dir)
}

/// Sync MRT data before atomic rename, then sync its parent directory.
///
/// Returns the final file path on success.
///
/// # Errors
///
/// Returns an error if directory creation, staging, syncing or renaming fails.
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

#[cfg(test)]
mod tests {
    use std::io::Read;

    use super::*;

    #[test]
    fn write_uncompressed() {
        let dir = tempfile::tempdir().unwrap();
        let config = MrtWriterConfig {
            output_dir: dir.path().to_path_buf(),
            dump_interval: 3600,
            compress: false,
            file_prefix: "rib".to_string(),
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
        let dir = tempfile::tempdir().unwrap();
        let config = MrtWriterConfig {
            output_dir: dir.path().to_path_buf(),
            dump_interval: 3600,
            compress: true,
            file_prefix: "rib".to_string(),
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
        let dir = tempfile::tempdir().unwrap();
        let config = MrtWriterConfig {
            output_dir: dir.path().to_path_buf(),
            dump_interval: 3600,
            compress: false,
            file_prefix: "empty".to_string(),
        };

        let path = write_dump(&config, &[]).unwrap();
        assert!(path.exists());
        assert_eq!(std::fs::read(&path).unwrap().len(), 0);
    }

    #[test]
    fn failed_rename_removes_temp_and_preserves_destination() {
        for compress in [false, true] {
            let dir = tempfile::tempdir().unwrap();
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
        let dir = tempfile::tempdir().unwrap();
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
        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("a").join("b").join("c");
        let config = MrtWriterConfig {
            output_dir: nested.clone(),
            dump_interval: 3600,
            compress: false,
            file_prefix: "rib".to_string(),
        };

        let path = write_dump(&config, b"test").unwrap();
        assert!(path.exists());
        assert!(nested.exists());
    }

    #[test]
    fn write_paths_are_unique_across_quick_successive_dumps() {
        let dir = tempfile::tempdir().unwrap();
        let config = MrtWriterConfig {
            output_dir: dir.path().to_path_buf(),
            dump_interval: 3600,
            compress: false,
            file_prefix: "rib".to_string(),
        };

        let first = write_dump(&config, b"first").unwrap();
        // Ensure different timestamp component on coarse clocks.
        std::thread::sleep(std::time::Duration::from_millis(1));
        let second = write_dump(&config, b"second").unwrap();

        assert_ne!(first, second);
        assert!(first.exists());
        assert!(second.exists());
    }
}
