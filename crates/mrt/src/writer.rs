//! Atomic file writer for MRT dumps with optional gzip compression.

use std::io::Write;
use std::path::{Path, PathBuf};

use chrono::Utc;
use tracing::{debug, info};

use crate::types::MrtWriterConfig;

/// Write MRT data to a file using atomic rename.
///
/// Returns the final file path on success.
///
/// # Errors
///
/// Returns an error if the output directory cannot be created or the file
/// cannot be written.
pub fn write_dump(config: &MrtWriterConfig, data: &[u8]) -> std::io::Result<PathBuf> {
    std::fs::create_dir_all(&config.output_dir)?;

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
    {
        let file = std::fs::File::create(tmp_path)?;
        if compress {
            let mut encoder = flate2::write::GzEncoder::new(file, flate2::Compression::default());
            encoder.write_all(data)?;
            encoder.finish()?;
        } else {
            let mut writer = std::io::BufWriter::new(file);
            writer.write_all(data)?;
            writer.flush()?;
        }
    }
    std::fs::rename(tmp_path, final_path)?;
    Ok(())
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
