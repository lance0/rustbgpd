//! Dormant, bounded ADR-0121 v2 history codec and descriptor-relative store.

#![allow(
    dead_code,
    reason = "ADR-0121 deliberately lands v2 storage before runtime/public activation"
)]

use std::collections::HashMap;
use std::ffi::{OsStr, OsString};
#[cfg(test)]
use std::fs;
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::OwnedFd;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const VERSION: u32 = 2;
const MAX_ENVELOPE: usize = 32 * 1024 * 1024;
const MAX_TOML: usize = 10 * 1024 * 1024;
const MAX_MANIFEST: usize = 16 * 1024 * 1024;
const MAX_UNITS: usize = 4096;
const MAX_MODULES: usize = 64;
const MAX_IMPORTS: usize = 4096;
const MAX_DATASETS: usize = 65_536;
const MAX_TEXT: usize = 64 * 1024;
const SOURCE_DIGEST_DOMAIN: &[u8] = b"rustbgpd.config-source.v2\0";
static WRITER_LOCK: Mutex<()> = Mutex::new(());

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum WriteStep {
    Pinned,
    CleanupSync,
    StageCreate,
    StageWrite,
    StageSync,
    EvictionUnlink,
    EvictionSync,
    Publish,
    FinalSync,
}

/// Dormant v2 writer. Deliberately private and unreachable from v1 callers.
fn record_v2(dir: &Path, normalized_toml: &str, manifest: Manifest) -> io::Result<bool> {
    record_v2_with(dir, normalized_toml, manifest, |_| Ok(()))
}

#[allow(
    clippy::too_many_lines,
    reason = "the dormant writer keeps one ordered crash-consistency transaction visible"
)]
fn record_v2_with(
    dir: &Path,
    normalized_toml: &str,
    mut manifest: Manifest,
    mut step: impl FnMut(WriteStep) -> io::Result<()>,
) -> io::Result<bool> {
    use nix::fcntl::{OFlag, RenameFlags, openat, renameat2};
    use nix::sys::stat::{Mode, fchmod};
    use nix::unistd::{UnlinkatFlags, unlinkat};

    let _guard = WRITER_LOCK
        .lock()
        .map_err(|_| io::Error::other("config history writer lock is poisoned"))?;

    // Validate every caller-controlled component before creating even a stage.
    if normalized_toml.len() > MAX_TOML {
        return Err(limit("normalized TOML", MAX_TOML));
    }
    let toml_sha256 = Sha256::digest(normalized_toml.as_bytes()).into();
    if manifest.toml_sha256 != toml_sha256 {
        return Err(invalid("normalized TOML digest mismatch"));
    }
    validate_manifest(&manifest)?;

    let directory = open_or_create_writer_directory(dir)?;
    step(WriteStep::Pinned)?;
    let cleanup_result = cleanup_stages(&directory);
    let cleanup_sync_result = step(WriteStep::CleanupSync).and_then(|()| directory.sync_all());
    cleanup_result?;
    cleanup_sync_result?;

    let mut rows = scan_pinned(&directory, dir)?;
    let sequence = rows
        .iter()
        .map(|row| row.sequence)
        .max()
        .map_or(Ok(1), |maximum| {
            maximum
                .checked_add(1)
                .ok_or_else(|| invalid("config history sequence is exhausted"))
        })?;

    // Repair a pre-existing over-cap history before considering deduplication.
    if rows.len() > super::HISTORY_LIMIT {
        evict_to(&directory, &mut rows, super::HISTORY_LIMIT, &mut step)?;
    }
    if let Some(newest) = rows.first()
        && newest.status == StoredStatus::Recorded
        && newest.format == StoredFormat::V2
        && open_and_decode(&directory, newest, true).is_ok_and(|(payload, _)| {
            matches!(payload, StoredPayload::V2(envelope)
                if envelope.normalized_toml.as_bytes() == normalized_toml.as_bytes()
                    && envelope.manifest == manifest)
        })
    {
        return Ok(false);
    }

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs());
    manifest.toml_sha256 = toml_sha256;
    let source_sha256 = manifest_source_sha256(&manifest);
    let envelope = Envelope {
        version: VERSION,
        sequence,
        timestamp_unix_seconds: timestamp,
        sha256: toml_sha256,
        source_sha256,
        normalized_toml: normalized_toml.to_owned(),
        manifest,
    };
    let encoded = encode_envelope(&envelope)?;
    let digest = encode_hex(&source_sha256);
    let final_name = format!("v2-{sequence:020}-{timestamp}-{digest}.json");
    let stage_name = format!(".v2-{sequence:020}-{timestamp}-{digest}.json.tmp");

    let mut stage_exists = false;
    let mut stage_identity = None;
    let mut published = false;
    let result = (|| {
        step(WriteStep::StageCreate)?;
        let fd = openat(
            &directory,
            stage_name.as_str(),
            OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
            Mode::from_bits_truncate(0o600),
        )
        .map_err(errno)?;
        stage_exists = true;
        let mut stage = File::from(fd);
        fchmod(&stage, Mode::from_bits_truncate(0o600)).map_err(errno)?;
        let metadata = stage.metadata()?;
        stage_identity = Some((metadata.dev(), metadata.ino()));
        step(WriteStep::StageWrite)?;
        stage.write_all(&encoded)?;
        step(WriteStep::StageSync)?;
        stage.sync_all()?;
        drop(stage);

        evict_to(&directory, &mut rows, super::HISTORY_LIMIT - 1, &mut step)?;
        step(WriteStep::Publish)?;
        renameat2(
            &directory,
            stage_name.as_str(),
            &directory,
            final_name.as_str(),
            RenameFlags::RENAME_NOREPLACE,
        )
        .map_err(errno)?;
        stage_exists = false;
        published = true;
        step(WriteStep::FinalSync)?;
        directory.sync_all()
    })();
    if result.is_err() && stage_exists && !published {
        if metadata_at(&directory, OsStr::new(&stage_name)).is_ok_and(|metadata| {
            metadata.regular
                && metadata.uid == nix::unistd::geteuid().as_raw()
                && stage_identity == Some((metadata.dev, metadata.ino))
        }) {
            let _ = unlinkat(&directory, stage_name.as_str(), UnlinkatFlags::NoRemoveDir);
        }
        let _ = directory.sync_all();
    }
    result.map(|()| true)
}

fn open_or_create_writer_directory(path: &Path) -> io::Result<File> {
    use nix::fcntl::{OFlag, open};
    use nix::sys::stat::{Mode, fchmod};
    use nix::unistd::geteuid;

    use std::os::unix::fs::DirBuilderExt;

    let mut builder = std::fs::DirBuilder::new();
    builder.mode(0o700);
    match builder.create(path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error),
    }
    let fd = open(
        path,
        OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
        Mode::empty(),
    )
    .map_err(errno)?;
    let file = File::from(fd);
    let metadata = file.metadata()?;
    if !metadata.is_dir() || metadata.uid() != geteuid().as_raw() {
        return Err(invalid("unsafe config history directory owner or type"));
    }
    fchmod(&file, Mode::from_bits_truncate(0o700)).map_err(errno)?;
    let metadata = file.metadata()?;
    validate_directory_metadata(
        metadata.is_dir(),
        metadata.uid(),
        metadata.mode(),
        geteuid().as_raw(),
    )?;
    Ok(file)
}

fn cleanup_stages(directory: &File) -> io::Result<()> {
    use nix::dir::Dir;
    use nix::unistd::{UnlinkatFlags, geteuid, unlinkat};

    let owned: OwnedFd = directory.try_clone()?.into();
    let mut entries = Dir::from_fd(owned).map_err(errno)?;
    for item in entries.iter() {
        let item = item.map_err(errno)?;
        let name = OsString::from_vec(item.file_name().to_bytes().to_vec());
        if parse_stage_name(&name).is_none() {
            continue;
        }
        let metadata = metadata_at(directory, &name)?;
        if !metadata.regular || metadata.uid != geteuid().as_raw() {
            return Err(invalid("unsafe config history stage owner or type"));
        }
        unlinkat(directory, Path::new(&name), UnlinkatFlags::NoRemoveDir).map_err(errno)?;
    }
    Ok(())
}

fn evict_to(
    directory: &File,
    rows: &mut Vec<StoredRow>,
    limit: usize,
    step: &mut impl FnMut(WriteStep) -> io::Result<()>,
) -> io::Result<()> {
    use nix::unistd::{UnlinkatFlags, geteuid, unlinkat};

    let remove = rows.len().saturating_sub(limit);
    for row in rows.iter().rev().take(remove) {
        let metadata = metadata_at(directory, &row.filename)?;
        if !metadata.regular || metadata.uid != geteuid().as_raw() {
            return Err(invalid("unsafe config history eviction candidate"));
        }
    }
    for row in rows.iter().rev().take(remove) {
        step(WriteStep::EvictionUnlink)?;
        if let Err(error) = unlinkat(
            directory,
            Path::new(&row.filename),
            UnlinkatFlags::NoRemoveDir,
        )
        .map_err(errno)
        {
            let _ = directory.sync_all();
            return Err(error);
        }
    }
    rows.truncate(rows.len() - remove);
    step(WriteStep::EvictionSync)?;
    directory.sync_all()
}

struct AtMetadata {
    regular: bool,
    uid: u32,
    dev: u64,
    ino: u64,
}

fn metadata_at(directory: &File, name: &OsStr) -> io::Result<AtMetadata> {
    use nix::fcntl::AtFlags;
    use nix::sys::stat::{SFlag, fstatat};

    // fstatat is the type/owner authority. Opening is intentionally avoided so
    // a FIFO or device can never block; AT_SYMLINK_NOFOLLOW rejects links.
    let stat = fstatat(directory, Path::new(name), AtFlags::AT_SYMLINK_NOFOLLOW).map_err(errno)?;
    Ok(AtMetadata {
        regular: SFlag::from_bits_truncate(stat.st_mode) & SFlag::S_IFMT == SFlag::S_IFREG,
        uid: stat.st_uid,
        dev: stat.st_dev,
        ino: stat.st_ino,
    })
}

fn parse_stage_name(name: &OsStr) -> Option<ParsedName> {
    let text = name.to_str()?;
    let final_name = text.strip_prefix('.')?.strip_suffix(".tmp")?;
    let parsed = parse_mixed_name(OsStr::new(final_name))?;
    (parsed.format == StoredFormat::V2).then_some(parsed)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum StoredFormat {
    Legacy,
    V2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum StoredStatus {
    LegacyTomlOnly,
    Recorded,
    Unreadable,
}

#[derive(Debug, Clone)]
pub(super) struct StoredRow {
    pub(super) format: StoredFormat,
    pub(super) index: usize,
    pub(super) filename: OsString,
    pub(super) sequence: u64,
    pub(super) timestamp_unix_seconds: u64,
    pub(super) path: PathBuf,
    pub(super) status: StoredStatus,
    pub(super) verified_sha256: Option<[u8; 32]>,
    pub(super) verified_source_sha256: Option<[u8; 32]>,
    identity: Option<EntryIdentity>,
}

type EntryIdentity = (u64, u64, u64, i64, i64);

#[derive(Debug)]
pub(super) enum StoredPayload {
    Legacy(String),
    V2(Envelope),
}

struct ParsedName {
    format: StoredFormat,
    sequence: u64,
    timestamp: u64,
    digest: [u8; 32],
}

/// Scan both generations without exposing v2 entries to the legacy rollback API.
pub(super) fn scan_mixed(dir: &Path) -> io::Result<Vec<StoredRow>> {
    let directory = match open_directory(dir) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error),
    };
    scan_pinned(&directory, dir)
}

fn scan_pinned(directory: &File, display_path: &Path) -> io::Result<Vec<StoredRow>> {
    use nix::dir::Dir;

    let owned: OwnedFd = directory.try_clone()?.into();
    let mut entries = Dir::from_fd(owned).map_err(errno)?;
    let mut rows = Vec::new();
    for item in entries.iter() {
        let item = item.map_err(errno)?;
        let filename = OsString::from_vec(item.file_name().to_bytes().to_vec());
        let Some(parsed) = parse_mixed_name(&filename) else {
            continue;
        };
        let path = display_path.join(&filename);
        let mut row = StoredRow {
            format: parsed.format,
            index: 0,
            filename,
            sequence: parsed.sequence,
            timestamp_unix_seconds: parsed.timestamp,
            path,
            status: StoredStatus::Unreadable,
            verified_sha256: None,
            verified_source_sha256: None,
            identity: None,
        };
        if let Ok((payload, identity)) = open_and_decode(directory, &row, false) {
            row.identity = Some(identity);
            match payload {
                StoredPayload::Legacy(bytes) => {
                    row.status = StoredStatus::LegacyTomlOnly;
                    row.verified_sha256 = Some(Sha256::digest(bytes).into());
                }
                StoredPayload::V2(envelope) => {
                    row.status = StoredStatus::Recorded;
                    row.verified_sha256 = Some(envelope.sha256);
                    row.verified_source_sha256 = Some(envelope.source_sha256);
                }
            }
        }
        rows.push(row);
    }
    rows.sort_by(|left, right| {
        right
            .sequence
            .cmp(&left.sequence)
            .then_with(|| left.filename.as_bytes().cmp(right.filename.as_bytes()))
    });
    let mut counts = HashMap::new();
    for row in &rows {
        *counts.entry(row.sequence).or_insert(0usize) += 1;
    }
    for (index, row) in rows.iter_mut().enumerate() {
        row.index = index;
        if counts[&row.sequence] > 1 {
            row.status = StoredStatus::Unreadable;
            row.verified_sha256 = None;
            row.verified_source_sha256 = None;
        }
    }
    Ok(rows)
}

/// Reopen and revalidate the exact object observed by [`scan_mixed`].
pub(super) fn read_mixed(dir: &Path, row: &StoredRow) -> io::Result<StoredPayload> {
    if row.status == StoredStatus::Unreadable || row.path != dir.join(&row.filename) {
        return Err(invalid("config history entry is not readable"));
    }
    let directory = open_directory(dir)?;
    let (payload, identity) = open_and_decode(&directory, row, true)?;
    if row.identity != Some(identity) {
        return Err(invalid("config history entry was replaced after listing"));
    }
    Ok(payload)
}

fn open_directory(path: &Path) -> io::Result<File> {
    use nix::fcntl::{OFlag, open};
    use nix::sys::stat::Mode;
    use nix::unistd::geteuid;

    let fd = open(
        path,
        OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
        Mode::empty(),
    )
    .map_err(errno)?;
    let file = File::from(fd);
    let metadata = file.metadata()?;
    validate_directory_metadata(
        metadata.is_dir(),
        metadata.uid(),
        metadata.mode(),
        geteuid().as_raw(),
    )?;
    Ok(file)
}

fn validate_directory_metadata(
    regular_directory: bool,
    uid: u32,
    mode: u32,
    expected_uid: u32,
) -> io::Result<()> {
    if !regular_directory || uid != expected_uid || mode & 0o7777 != 0o700 {
        return Err(invalid(format!(
            "unsafe config history directory (dir={}, uid={}/{}, mode={:o})",
            regular_directory,
            uid,
            expected_uid,
            mode & 0o7777
        )));
    }
    Ok(())
}

fn open_and_decode(
    directory: &File,
    row: &StoredRow,
    require_digest: bool,
) -> io::Result<(StoredPayload, EntryIdentity)> {
    use nix::fcntl::{OFlag, openat};
    use nix::sys::stat::Mode;
    use nix::unistd::geteuid;

    let fd = openat(
        directory,
        Path::new(&row.filename),
        OFlag::O_RDONLY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK,
        Mode::empty(),
    )
    .map_err(errno)?;
    let file = File::from(fd);
    let metadata = file.metadata()?;
    let identity = (
        metadata.dev(),
        metadata.ino(),
        metadata.len(),
        metadata.ctime(),
        metadata.ctime_nsec(),
    );
    let cap = cap_for_format(row.format);
    let checked = CheckedMetadata {
        regular: metadata.is_file(),
        uid: metadata.uid(),
        mode: metadata.mode(),
        len: metadata.len(),
    };
    let bytes = read_bounded(file, checked, geteuid().as_raw(), cap)?;
    match row.format {
        StoredFormat::Legacy => {
            let digest: [u8; 32] = Sha256::digest(&bytes).into();
            let parsed = parse_mixed_name(&row.filename)
                .ok_or_else(|| invalid("legacy config history filename changed"))?;
            if digest != parsed.digest || require_digest && row.verified_sha256 != Some(digest) {
                return Err(invalid("legacy config history digest changed"));
            }
            let text = String::from_utf8(bytes).map_err(invalid)?;
            Ok((StoredPayload::Legacy(text), identity))
        }
        StoredFormat::V2 => {
            let envelope = decode_envelope(&bytes)?;
            let parsed = parse_mixed_name(&row.filename)
                .ok_or_else(|| invalid("v2 config history filename changed"))?;
            if envelope.sequence != parsed.sequence
                || envelope.timestamp_unix_seconds != parsed.timestamp
                || envelope.source_sha256 != parsed.digest
                || require_digest
                    && (row.verified_sha256 != Some(envelope.sha256)
                        || row.verified_source_sha256 != Some(envelope.source_sha256))
            {
                return Err(invalid("v2 config history filename/envelope mismatch"));
            }
            Ok((StoredPayload::V2(envelope), identity))
        }
    }
}

const fn cap_for_format(format: StoredFormat) -> u64 {
    match format {
        StoredFormat::Legacy => super::MAX_ENTRY_BYTES,
        StoredFormat::V2 => MAX_ENVELOPE as u64,
    }
}

#[derive(Clone, Copy)]
struct CheckedMetadata {
    regular: bool,
    uid: u32,
    mode: u32,
    len: u64,
}

fn read_bounded(
    reader: impl Read,
    metadata: CheckedMetadata,
    expected_uid: u32,
    cap: u64,
) -> io::Result<Vec<u8>> {
    if !metadata.regular
        || metadata.uid != expected_uid
        || metadata.mode & 0o7777 != 0o600
        || metadata.len > cap
    {
        return Err(invalid("unsafe config history entry metadata"));
    }
    let mut bytes = Vec::with_capacity(usize::try_from(metadata.len).map_err(invalid)?);
    reader.take(cap + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 != metadata.len || bytes.len() as u64 > cap {
        return Err(invalid("config history entry changed size while reading"));
    }
    Ok(bytes)
}

fn parse_mixed_name(name: &OsStr) -> Option<ParsedName> {
    let name = name.to_str()?;
    if let Some((sequence, timestamp, digest)) = super::parse_entry_name(name) {
        return Some(ParsedName {
            format: StoredFormat::Legacy,
            sequence,
            timestamp,
            digest: decode_digest(&digest)?,
        });
    }
    let stem = name.strip_prefix("v2-")?.strip_suffix(".json")?;
    let mut parts = stem.split('-');
    let sequence_text = parts.next()?;
    let timestamp_text = parts.next()?;
    let digest_text = parts.next()?;
    if parts.next().is_some()
        || sequence_text.len() != 20
        || !sequence_text.bytes().all(|byte| byte.is_ascii_digit())
        || (timestamp_text.len() > 1 && timestamp_text.starts_with('0'))
        || !timestamp_text.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    Some(ParsedName {
        format: StoredFormat::V2,
        sequence: sequence_text.parse().ok()?,
        timestamp: timestamp_text.parse().ok()?,
        digest: decode_digest(digest_text)?,
    })
}

fn decode_digest(value: &str) -> Option<[u8; 32]> {
    if value.len() != 64 {
        return None;
    }
    decode_hex(value).ok()?.try_into().ok()
}

fn errno(error: nix::errno::Errno) -> io::Error {
    io::Error::from_raw_os_error(error as i32)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Envelope {
    pub(super) version: u32,
    pub(super) sequence: u64,
    pub(super) timestamp_unix_seconds: u64,
    #[serde(with = "hex_digest")]
    pub(super) sha256: [u8; 32],
    #[serde(with = "hex_digest")]
    pub(super) source_sha256: [u8; 32],
    pub(super) normalized_toml: String,
    pub(super) manifest: Manifest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Manifest {
    #[serde(with = "hex_digest")]
    pub(super) toml_sha256: [u8; 32],
    pub(super) rpol_units: Vec<RpolUnit>,
    pub(super) datasets: Vec<Dataset>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RpolUnit {
    pub(super) modules: Vec<RpolModule>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RpolModule {
    pub(super) path: LosslessPath,
    pub(super) length: u64,
    #[serde(with = "hex_digest")]
    pub(super) sha256: [u8; 32],
    pub(super) imports: Vec<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Dataset {
    pub(super) name: String,
    pub(super) kind: DatasetKind,
    pub(super) path: LosslessPath,
    pub(super) length: u64,
    #[serde(with = "hex_digest")]
    pub(super) sha256: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(super) enum DatasetKind {
    #[serde(rename = "prefix-set")]
    Prefix,
    #[serde(rename = "asn-set")]
    Asn,
    #[serde(rename = "community-set")]
    Community,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct LosslessPath(pub(super) Vec<u8>);

impl Serialize for LosslessPath {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        #[derive(Serialize)]
        struct Wire<'a> {
            encoding: &'static str,
            value: &'a str,
        }
        let value = encode_hex(&self.0);
        Wire {
            encoding: "unix-bytes-hex",
            value: &value,
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for LosslessPath {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            encoding: String,
            value: String,
        }
        let wire = Wire::deserialize(deserializer)?;
        if wire.encoding != "unix-bytes-hex" {
            return Err(serde::de::Error::custom("unsupported path encoding"));
        }
        decode_hex(&wire.value)
            .map(Self)
            .map_err(serde::de::Error::custom)
    }
}

pub(super) fn encode_envelope(envelope: &Envelope) -> io::Result<Vec<u8>> {
    validate(envelope)?;
    let mut bytes = serde_json::to_vec(envelope).map_err(invalid)?;
    bytes.push(b'\n');
    if bytes.len() > MAX_ENVELOPE {
        return Err(limit("envelope", MAX_ENVELOPE));
    }
    Ok(bytes)
}

pub(super) fn decode_envelope(bytes: &[u8]) -> io::Result<Envelope> {
    if bytes.len() > MAX_ENVELOPE {
        return Err(limit("envelope", MAX_ENVELOPE));
    }
    let envelope: Envelope = serde_json::from_slice(bytes).map_err(invalid)?;
    validate(&envelope)?;
    if encode_envelope(&envelope)? != bytes {
        return Err(invalid("non-canonical v2 envelope"));
    }
    Ok(envelope)
}

fn validate(envelope: &Envelope) -> io::Result<()> {
    if envelope.version != VERSION {
        return Err(invalid("unsupported config-history envelope version"));
    }
    if envelope.normalized_toml.len() > MAX_TOML {
        return Err(limit("normalized TOML", MAX_TOML));
    }
    let actual_toml: [u8; 32] = Sha256::digest(envelope.normalized_toml.as_bytes()).into();
    if envelope.sha256 != actual_toml || envelope.manifest.toml_sha256 != actual_toml {
        return Err(invalid("normalized TOML digest mismatch"));
    }
    validate_manifest(&envelope.manifest)?;
    if envelope.source_sha256 != manifest_source_sha256(&envelope.manifest) {
        return Err(invalid("source manifest digest mismatch"));
    }
    Ok(())
}

fn validate_manifest(manifest: &Manifest) -> io::Result<()> {
    if manifest.rpol_units.len() > MAX_UNITS {
        return Err(limit("RPOL units", MAX_UNITS));
    }
    for unit in &manifest.rpol_units {
        if unit.modules.is_empty() || unit.modules.len() > MAX_MODULES {
            return Err(invalid("RPOL unit must contain 1..=64 modules"));
        }
        for module in &unit.modules {
            if module.path.0.len() > MAX_TEXT || module.imports.len() > MAX_IMPORTS {
                return Err(invalid("RPOL module exceeds a codec bound"));
            }
            if module
                .imports
                .iter()
                .any(|&index| index as usize >= unit.modules.len())
            {
                return Err(invalid("RPOL import index is outside its unit"));
            }
        }
    }
    if manifest.datasets.len() > MAX_DATASETS {
        return Err(limit("datasets", MAX_DATASETS));
    }
    let mut prior: Option<&[u8]> = None;
    for dataset in &manifest.datasets {
        if dataset.name.len() > MAX_TEXT || dataset.path.0.len() > MAX_TEXT {
            return Err(invalid("dataset name or path exceeds 64 KiB"));
        }
        if prior.is_some_and(|name| name >= dataset.name.as_bytes()) {
            return Err(invalid("datasets are not strictly byte-sorted and unique"));
        }
        prior = Some(dataset.name.as_bytes());
    }
    if serde_json::to_vec(manifest).map_err(invalid)?.len() > MAX_MANIFEST {
        return Err(limit("manifest", MAX_MANIFEST));
    }
    Ok(())
}

fn manifest_source_sha256(manifest: &Manifest) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(SOURCE_DIGEST_DOMAIN);
    frame(&mut digest, &manifest.toml_sha256);
    frame_u64(&mut digest, manifest.rpol_units.len() as u64);
    for unit in &manifest.rpol_units {
        frame_u64(&mut digest, unit.modules.len() as u64);
        for module in &unit.modules {
            frame(&mut digest, b"unix-os-bytes");
            frame(&mut digest, &module.path.0);
            frame_u64(&mut digest, module.length);
            frame(&mut digest, &module.sha256);
            frame_u64(&mut digest, module.imports.len() as u64);
            for import in &module.imports {
                frame(&mut digest, &import.to_be_bytes());
            }
        }
    }
    frame_u64(&mut digest, manifest.datasets.len() as u64);
    for dataset in &manifest.datasets {
        frame(&mut digest, dataset.name.as_bytes());
        frame(&mut digest, dataset_kind_name(dataset.kind).as_bytes());
        frame(&mut digest, b"unix-os-bytes");
        frame(&mut digest, &dataset.path.0);
        frame_u64(&mut digest, dataset.length);
        frame(&mut digest, &dataset.sha256);
    }
    digest.finalize().into()
}

fn frame(digest: &mut Sha256, bytes: &[u8]) {
    digest.update((bytes.len() as u64).to_be_bytes());
    digest.update(bytes);
}

fn frame_u64(digest: &mut Sha256, value: u64) {
    frame(digest, &value.to_be_bytes());
}

fn dataset_kind_name(kind: DatasetKind) -> &'static str {
    match kind {
        DatasetKind::Prefix => "prefix-set",
        DatasetKind::Asn => "asn-set",
        DatasetKind::Community => "community-set",
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut out, byte| {
            let _ = write!(out, "{byte:02x}");
            out
        })
}

fn decode_hex(value: &str) -> Result<Vec<u8>, &'static str> {
    if !value.len().is_multiple_of(2)
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("hex must be lowercase and even-length");
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let digit = |byte| {
                if byte <= b'9' {
                    byte - b'0'
                } else {
                    byte - b'a' + 10
                }
            };
            Ok((digit(pair[0]) << 4) | digit(pair[1]))
        })
        .collect()
}

mod hex_digest {
    use serde::{Deserialize, Deserializer, Serializer};

    pub(super) fn serialize<S: Serializer>(
        digest: &[u8; 32],
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&super::encode_hex(digest))
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<[u8; 32], D::Error> {
        let value = String::deserialize(deserializer)?;
        let bytes = super::decode_hex(&value).map_err(serde::de::Error::custom)?;
        bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("digest must be exactly 32 bytes"))
    }
}

fn invalid(error: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error.to_string())
}

fn limit(name: &str, bytes: usize) -> io::Error {
    invalid(format!("{name} exceeds its {bytes}-byte limit"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    fn sample() -> Envelope {
        let normalized_toml = "asn = 64512\n".to_string();
        let toml_sha256 = Sha256::digest(normalized_toml.as_bytes()).into();
        let manifest = Manifest {
            toml_sha256,
            rpol_units: vec![RpolUnit {
                modules: vec![RpolModule {
                    path: LosslessPath(b"/policy/main.rpol".to_vec()),
                    length: 3,
                    sha256: [0x22; 32],
                    imports: vec![0],
                }],
            }],
            datasets: vec![Dataset {
                name: "customers".into(),
                kind: DatasetKind::Asn,
                path: LosslessPath(b"/data/asns".to_vec()),
                length: 4,
                sha256: [0x33; 32],
            }],
        };
        Envelope {
            version: 2,
            sequence: 7,
            timestamp_unix_seconds: 9,
            sha256: toml_sha256,
            source_sha256: manifest_source_sha256(&manifest),
            normalized_toml,
            manifest,
        }
    }

    fn reseal(envelope: &mut Envelope) {
        envelope.sha256 = Sha256::digest(envelope.normalized_toml.as_bytes()).into();
        envelope.manifest.toml_sha256 = envelope.sha256;
        envelope.source_sha256 = manifest_source_sha256(&envelope.manifest);
    }

    fn manifest_for(toml: &str) -> Manifest {
        let mut manifest = sample().manifest;
        manifest.toml_sha256 = Sha256::digest(toml.as_bytes()).into();
        manifest
    }

    fn recorded_rows(dir: &Path) -> Vec<StoredRow> {
        scan_mixed(dir)
            .unwrap()
            .into_iter()
            .filter(|row| row.format == StoredFormat::V2)
            .collect()
    }

    fn assert_error(result: io::Result<impl Sized>, text: &str) {
        let Err(error) = result else {
            panic!("expected InvalidData containing {text:?}");
        };
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains(text), "{error}");
    }

    #[test]
    fn canonical_golden_order_and_lf_round_trip() {
        let envelope = sample();
        let bytes = encode_envelope(&envelope).unwrap();
        let text = String::from_utf8(bytes.clone()).unwrap();
        assert_eq!(
            text,
            concat!(
                "{\"version\":2,\"sequence\":7,\"timestamp_unix_seconds\":9,\"sha256\":\"a8745c2ae560173c753ac9fa5f37f2167c05d5eb68c5154d561502c674d72d6c\",",
                "\"source_sha256\":\"94f27364376996e7af8fe5f2e8ec07986f3ea41a0f655e730bd19ed9bfa2201c\",\"normalized_toml\":\"asn = 64512\\n\",",
                "\"manifest\":{\"toml_sha256\":\"a8745c2ae560173c753ac9fa5f37f2167c05d5eb68c5154d561502c674d72d6c\",\"rpol_units\":[",
                "{\"modules\":[{\"path\":{\"encoding\":\"unix-bytes-hex\",\"value\":\"2f706f6c6963792f6d61696e2e72706f6c\"},\"length\":3,",
                "\"sha256\":\"2222222222222222222222222222222222222222222222222222222222222222\",\"imports\":[0]}]}],",
                "\"datasets\":[{\"name\":\"customers\",\"kind\":\"asn-set\",\"path\":{\"encoding\":\"unix-bytes-hex\",",
                "\"value\":\"2f646174612f61736e73\"},\"length\":4,\"sha256\":\"3333333333333333333333333333333333333333333333333333333333333333\"}]}}\n"
            )
        );
        assert_eq!(decode_envelope(&bytes).unwrap(), envelope);
    }

    #[test]
    fn rejects_noncanonical_and_bad_wire_spellings() {
        let bytes = encode_envelope(&sample()).unwrap();
        // LOAD-BEARING BREAK: each mutation changes one canonical wire rule;
        // accepting any item makes this destructive proof red.
        for (broken, expected) in [
            (
                [&b" "[..], &bytes[..]].concat(),
                "non-canonical v2 envelope",
            ),
            (
                bytes[..bytes.len() - 1].to_vec(),
                "non-canonical v2 envelope",
            ),
            (
                String::from_utf8(bytes.clone())
                    .unwrap()
                    .replace(
                        "\"version\":2,\"sequence\":7",
                        "\"sequence\":7,\"version\":2",
                    )
                    .into_bytes(),
                "non-canonical v2 envelope",
            ),
            (
                String::from_utf8(bytes.clone())
                    .unwrap()
                    .replace("\"version\":2", "\"version\":3")
                    .into_bytes(),
                "unsupported config-history",
            ),
            (
                String::from_utf8(bytes.clone())
                    .unwrap()
                    .replace("unix-bytes-hex", "unix_bytes_hex")
                    .into_bytes(),
                "unsupported path encoding",
            ),
            (
                String::from_utf8(bytes.clone())
                    .unwrap()
                    .replace("asn-set", "ASN-set")
                    .into_bytes(),
                "unknown variant",
            ),
        ] {
            assert_error(decode_envelope(&broken), expected);
        }
        let duplicate =
            String::from_utf8(bytes.clone())
                .unwrap()
                .replacen('{', "{\"version\":2,", 1);
        assert_error(
            decode_envelope(duplicate.as_bytes()),
            "duplicate field `version`",
        );
        let unknown = String::from_utf8(bytes)
            .unwrap()
            .replacen('{', "{\"unknown\":0,", 1);
        assert_error(
            decode_envelope(unknown.as_bytes()),
            "unknown field `unknown`",
        );
    }

    #[test]
    fn rejects_digest_and_roster_invariants() {
        // LOAD-BEARING BREAK: recomputing or repairing caller-owned fields in
        // encode would make these destructive mutations unexpectedly green.
        let mut envelope = sample();
        envelope.sha256[0] ^= 1;
        assert_error(encode_envelope(&envelope), "TOML digest mismatch");
        envelope = sample();
        envelope.source_sha256[0] ^= 1;
        assert_error(
            encode_envelope(&envelope),
            "source manifest digest mismatch",
        );
        envelope = sample();
        envelope.manifest.rpol_units[0].modules.clear();
        reseal(&mut envelope);
        assert_error(encode_envelope(&envelope), "1..=64 modules");
        envelope = sample();
        envelope.manifest.rpol_units[0].modules[0].imports[0] = 1;
        reseal(&mut envelope);
        assert_error(encode_envelope(&envelope), "outside its unit");
        envelope = sample();
        envelope
            .manifest
            .datasets
            .push(envelope.manifest.datasets[0].clone());
        envelope.source_sha256 = manifest_source_sha256(&envelope.manifest);
        assert_error(encode_envelope(&envelope), "strictly byte-sorted");
    }

    #[test]
    fn loader_digest_golden_and_invalid_utf8_path() {
        let mut manifest = sample().manifest;
        manifest.rpol_units[0].modules[0].path = LosslessPath(vec![b'/', 0xff]);
        let envelope = Envelope {
            source_sha256: manifest_source_sha256(&manifest),
            manifest,
            ..sample()
        };
        assert_eq!(
            decode_envelope(&encode_envelope(&envelope).unwrap()).unwrap(),
            envelope
        );
        assert_eq!(
            encode_hex(&manifest_source_sha256(&Manifest {
                toml_sha256: [0x11; 32],
                rpol_units: vec![RpolUnit {
                    modules: vec![RpolModule {
                        path: LosslessPath(b"/policy".to_vec()),
                        length: 3,
                        sha256: [0x22; 32],
                        imports: vec![0, 1],
                    }],
                }],
                datasets: vec![Dataset {
                    name: "customers".into(),
                    kind: DatasetKind::Asn,
                    path: LosslessPath(b"/dataset".to_vec()),
                    length: 4,
                    sha256: [0x33; 32],
                }],
            })),
            "ea0d43501b201fcec9724d17ada9603e72a635cc9c048523b6449f0e4c7e6009"
        );
        // LOAD-BEARING BREAK: removing the unix-os-bytes tag or any framing
        // operation changes the golden above and proves loader incompatibility.
    }

    #[test]
    fn exact_and_plus_one_practical_bounds() {
        let mut envelope = sample();
        envelope.normalized_toml = "x".repeat(MAX_TOML);
        envelope.sha256 = Sha256::digest(envelope.normalized_toml.as_bytes()).into();
        envelope.manifest.toml_sha256 = envelope.sha256;
        envelope.source_sha256 = manifest_source_sha256(&envelope.manifest);
        assert!(encode_envelope(&envelope).is_ok());
        envelope.normalized_toml.push('x');
        reseal(&mut envelope);
        assert_error(encode_envelope(&envelope), "normalized TOML");
        envelope = sample();
        envelope.manifest.rpol_units[0].modules[0].path.0 = vec![b'x'; MAX_TEXT];
        envelope.source_sha256 = manifest_source_sha256(&envelope.manifest);
        assert!(encode_envelope(&envelope).is_ok());
        envelope.manifest.rpol_units[0].modules[0].path.0.push(b'x');
        reseal(&mut envelope);
        assert_error(encode_envelope(&envelope), "RPOL module");
        assert_error(
            decode_envelope(&vec![b' '; MAX_ENVELOPE + 1]),
            "envelope exceeds",
        );
    }

    #[test]
    fn exact_and_plus_one_roster_bounds() {
        let module = sample().manifest.rpol_units[0].modules[0].clone();
        let mut envelope = sample();
        envelope.manifest.rpol_units = vec![
            RpolUnit {
                modules: vec![module.clone()],
            };
            MAX_UNITS
        ];
        envelope.source_sha256 = manifest_source_sha256(&envelope.manifest);
        assert!(encode_envelope(&envelope).is_ok());
        envelope.manifest.rpol_units.push(RpolUnit {
            modules: vec![module.clone()],
        });
        reseal(&mut envelope);
        assert_error(encode_envelope(&envelope), "RPOL units");

        envelope = sample();
        envelope.manifest.rpol_units[0].modules = vec![module.clone(); MAX_MODULES];
        for item in &mut envelope.manifest.rpol_units[0].modules {
            item.imports = vec![0];
        }
        envelope.source_sha256 = manifest_source_sha256(&envelope.manifest);
        assert!(encode_envelope(&envelope).is_ok());
        envelope.manifest.rpol_units[0].modules.push(module.clone());
        reseal(&mut envelope);
        assert_error(encode_envelope(&envelope), "1..=64 modules");

        envelope = sample();
        envelope.manifest.rpol_units[0].modules[0].imports = vec![0; MAX_IMPORTS];
        envelope.source_sha256 = manifest_source_sha256(&envelope.manifest);
        assert!(encode_envelope(&envelope).is_ok());
        envelope.manifest.rpol_units[0].modules[0].imports.push(0);
        reseal(&mut envelope);
        assert_error(encode_envelope(&envelope), "RPOL module");

        envelope = sample();
        let dataset = envelope.manifest.datasets[0].clone();
        envelope.manifest.datasets = (0..MAX_DATASETS)
            .map(|index| Dataset {
                name: format!("{index:05}"),
                ..dataset.clone()
            })
            .collect();
        envelope.source_sha256 = manifest_source_sha256(&envelope.manifest);
        assert!(encode_envelope(&envelope).is_ok());
        envelope.manifest.datasets.push(Dataset {
            name: "zzzzz".into(),
            ..dataset
        });
        reseal(&mut envelope);
        assert_error(encode_envelope(&envelope), "datasets exceeds");
    }

    #[test]
    fn exact_manifest_and_text_bounds() {
        let template = sample().manifest.datasets[0].clone();
        let mut envelope = sample();
        envelope.manifest.datasets = (0..256)
            .map(|index| Dataset {
                name: if index < 255 {
                    format!("{index:03}{}", "x".repeat(MAX_TEXT - 3))
                } else {
                    "255".into()
                },
                path: LosslessPath(Vec::new()),
                ..template.clone()
            })
            .collect();
        let base = serde_json::to_vec(&envelope.manifest).unwrap().len();
        envelope.manifest.datasets[255]
            .name
            .push_str(&"x".repeat(MAX_MANIFEST - base));
        assert_eq!(
            serde_json::to_vec(&envelope.manifest).unwrap().len(),
            MAX_MANIFEST
        );
        reseal(&mut envelope);
        assert!(encode_envelope(&envelope).is_ok());
        envelope.manifest.datasets[255].name.push('x');
        reseal(&mut envelope);
        assert_error(encode_envelope(&envelope), "manifest exceeds");

        for field in ["name", "path"] {
            let mut envelope = sample();
            if field == "name" {
                envelope.manifest.datasets[0].name = "x".repeat(MAX_TEXT);
            } else {
                envelope.manifest.datasets[0].path.0 = vec![b'x'; MAX_TEXT];
            }
            reseal(&mut envelope);
            assert!(encode_envelope(&envelope).is_ok());
            if field == "name" {
                envelope.manifest.datasets[0].name.push('x');
            } else {
                envelope.manifest.datasets[0].path.0.push(b'x');
            }
            reseal(&mut envelope);
            assert_error(encode_envelope(&envelope), "name or path");
        }
    }

    #[test]
    fn exact_envelope_wire_bound_and_pre_serde_rejection() {
        let mut envelope = sample();
        envelope.normalized_toml.clear();
        reseal(&mut envelope);
        let base = encode_envelope(&envelope).unwrap().len();
        let remaining = MAX_ENVELOPE - base;
        envelope.normalized_toml = "\0".repeat(remaining / 6) + &"x".repeat(remaining % 6);
        reseal(&mut envelope);
        let bytes = encode_envelope(&envelope).unwrap();
        assert_eq!(bytes.len(), MAX_ENVELOPE);
        assert_eq!(decode_envelope(&bytes).unwrap(), envelope);
        envelope.normalized_toml.push('x');
        reseal(&mut envelope);
        assert_error(encode_envelope(&envelope), "envelope exceeds");
        assert_error(decode_envelope(&vec![b' '; MAX_ENVELOPE]), "EOF");
        assert_error(
            decode_envelope(&vec![b' '; MAX_ENVELOPE + 1]),
            "envelope exceeds",
        );
    }

    #[test]
    fn rejects_nested_schema_and_lexical_variants() {
        let canonical = String::from_utf8(encode_envelope(&sample()).unwrap()).unwrap();
        let cases = [
            (
                canonical.replace("\"sequence\":7", "\"sequence\":7.0"),
                "invalid type",
            ),
            (canonical.replace("22", "2A"), "hex must be lowercase"),
            (
                canonical.replace("2222", "222"),
                "digest must be exactly 32 bytes",
            ),
            (canonical.replace("2222", "22zz"), "hex must be lowercase"),
            (
                canonical.replacen("2f70", "2F70", 1),
                "hex must be lowercase",
            ),
            (canonical.replacen("2f70", "2f7", 1), "even-length"),
            (
                canonical.replacen("2f70", "2fzz", 1),
                "hex must be lowercase",
            ),
            (
                canonical.replace("\"modules\":[", "\"extra\":0,\"modules\":["),
                "unknown field `extra`",
            ),
            (
                canonical.replace("\"path\":{", "\"extra\":0,\"path\":{"),
                "unknown field `extra`",
            ),
            (
                canonical.replace("\"datasets\":[", "\"extra\":0,\"datasets\":["),
                "unknown field `extra`",
            ),
            (
                canonical.replace("\"name\":", "\"extra\":0,\"name\":"),
                "unknown field `extra`",
            ),
            (
                canonical.replace("\"encoding\":", "\"extra\":0,\"encoding\":"),
                "unknown field `extra`",
            ),
            (
                canonical.replacen("\"modules\":[", "\"modules\":[],\"modules\":[", 1),
                "duplicate field `modules`",
            ),
            (
                canonical.replacen("\"path\":{", "\"length\":3,\"path\":{", 1),
                "duplicate field `length`",
            ),
            (
                canonical.replacen("\"datasets\":[", "\"datasets\":[],\"datasets\":[", 1),
                "duplicate field `datasets`",
            ),
            (
                canonical.replacen("\"name\":", "\"name\":\"x\",\"name\":", 1),
                "duplicate field `name`",
            ),
            (
                canonical.replacen("\"encoding\":", "\"encoding\":\"x\",\"encoding\":", 1),
                "duplicate field `encoding`",
            ),
        ];
        for (broken, expected) in cases {
            assert_error(decode_envelope(broken.as_bytes()), expected);
        }
        let mut envelope = sample();
        envelope.manifest.toml_sha256[0] ^= 1;
        envelope.source_sha256 = manifest_source_sha256(&envelope.manifest);
        assert_error(encode_envelope(&envelope), "TOML digest mismatch");
        envelope = sample();
        envelope.manifest.datasets.insert(
            0,
            Dataset {
                name: "z".into(),
                ..envelope.manifest.datasets[0].clone()
            },
        );
        reseal(&mut envelope);
        assert_error(encode_envelope(&envelope), "strictly byte-sorted");
    }

    fn write_private(path: &Path, bytes: &[u8]) {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path.parent().unwrap(), fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(path, bytes).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    fn v2_name(envelope: &Envelope) -> String {
        format!(
            "v2-{:020}-{}-{}.json",
            envelope.sequence,
            envelope.timestamp_unix_seconds,
            encode_hex(&envelope.source_sha256)
        )
    }

    fn write_v2(dir: &Path, envelope: &Envelope) -> PathBuf {
        let path = dir.join(v2_name(envelope));
        write_private(&path, &encode_envelope(envelope).unwrap());
        path
    }

    /// LOAD-BEARING BREAK: broad suffix/prefix matching lists temporary or
    /// near-miss files and lets an incomplete publication enter history.
    #[test]
    fn mixed_final_grammar_is_exact_and_stages_are_invisible() {
        use std::os::unix::ffi::OsStringExt;

        let dir = tempfile::tempdir().unwrap();
        let envelope = sample();
        write_v2(dir.path(), &envelope);
        for name in [
            format!(".{}.tmp", v2_name(&envelope)),
            format!("{}-x", v2_name(&envelope)),
            format!("v2-7-9-{}.json", encode_hex(&envelope.source_sha256)),
            format!(
                "v2-{:020}-09-{}.json",
                7,
                encode_hex(&envelope.source_sha256)
            ),
            format!(
                "v2-00000000000000000007-9-{}.JSON",
                encode_hex(&envelope.source_sha256)
            ),
            format!(
                "v2-00000000000000000007-9-{}.json",
                encode_hex(&envelope.source_sha256).to_uppercase()
            ),
            format!(
                "v2-18446744073709551616-9-{}.json",
                encode_hex(&envelope.source_sha256)
            ),
            format!(".{}", v2_name(&envelope)),
            format!("{}.tmp", v2_name(&envelope)),
            "README".into(),
        ] {
            write_private(&dir.path().join(name), b"untouched");
        }
        write_private(
            &dir.path()
                .join(OsString::from_vec(vec![0xff, b'.', b'j', b's', b'o', b'n'])),
            b"untouched",
        );
        let before = fs::read_dir(dir.path()).unwrap().count();
        let rows = scan_mixed(dir.path()).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].status, StoredStatus::Recorded);
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), before);
    }

    /// LOAD-BEARING BREAK: pathname enumeration after pinning can pair decoy
    /// names with opens against a different directory authority.
    #[test]
    fn pinned_scan_enumerates_the_pinned_descriptor_after_path_replacement() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("history");
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        let old = b"old";
        let old_name = format!("1-1-{}.toml", encode_hex(&Sha256::digest(old)));
        write_private(&path.join(&old_name), old);
        let pinned = open_directory(&path).unwrap();
        let moved = root.path().join("moved");
        fs::rename(&path, &moved).unwrap();
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        let decoy = b"decoy";
        write_private(
            &path.join(format!("2-1-{}.toml", encode_hex(&Sha256::digest(decoy)))),
            decoy,
        );
        let rows = scan_pinned(&pinned, &path).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].filename, old_name.as_str());
        assert_eq!(rows[0].status, StoredStatus::LegacyTomlOnly);
        assert_eq!(rows[0].verified_sha256, Some(Sha256::digest(old).into()));
    }

    #[test]
    fn directory_authority_is_exact_and_missing_is_empty() {
        let root = tempfile::tempdir().unwrap();
        assert!(scan_mixed(&root.path().join("missing")).unwrap().is_empty());
        assert_error(validate_directory_metadata(true, 8, 0o40700, 9), "unsafe");
        assert_error(
            validate_directory_metadata(false, 9, 0o100_700, 9),
            "unsafe",
        );
        assert_error(validate_directory_metadata(true, 9, 0o40755, 9), "unsafe");
        let file = root.path().join("file");
        write_private(&file, b"x");
        assert!(scan_mixed(&file).is_err());
        let link = root.path().join("link");
        std::os::unix::fs::symlink(root.path(), &link).unwrap();
        assert!(scan_mixed(&link).is_err());
    }

    /// LOAD-BEARING BREAK: sequence-only unstable sorting or format grouping
    /// changes the deterministic mixed-history index assignment.
    #[test]
    fn mixed_order_is_sequence_then_raw_basename() {
        let dir = tempfile::tempdir().unwrap();
        let legacy = b"legacy";
        let hash = encode_hex(&Sha256::digest(legacy));
        write_private(&dir.path().join(format!("7-8-{hash}.toml")), legacy);
        let mut envelope = sample();
        envelope.sequence = 9;
        envelope.timestamp_unix_seconds = 10;
        write_v2(dir.path(), &envelope);
        envelope.sequence = 7;
        envelope.timestamp_unix_seconds = 11;
        write_v2(dir.path(), &envelope);

        let rows = scan_mixed(dir.path()).unwrap();
        assert_eq!(
            rows.iter().map(|r| r.sequence).collect::<Vec<_>>(),
            [9, 7, 7]
        );
        assert!(rows[1].filename.as_bytes() < rows[2].filename.as_bytes());
        assert!(
            rows[1..]
                .iter()
                .all(|r| r.status == StoredStatus::Unreadable)
        );
        assert!(rows[1..].iter().all(|r| r.verified_sha256.is_none()));
    }

    /// LOAD-BEARING BREAK: poisoning only the later duplicate leaves an
    /// ambiguous rollback identity eligible in legacy/v2 and same-format pairs.
    #[test]
    fn every_duplicate_sequence_member_is_poisoned() {
        for formats in [(false, false), (false, true), (true, true)] {
            let dir = tempfile::tempdir().unwrap();
            for (offset, is_v2) in [formats.0, formats.1].into_iter().enumerate() {
                if is_v2 {
                    let mut envelope = sample();
                    envelope.sequence = 42;
                    envelope.timestamp_unix_seconds += offset as u64;
                    write_v2(dir.path(), &envelope);
                } else {
                    let bytes = format!("legacy-{offset}");
                    let hash = encode_hex(&Sha256::digest(bytes.as_bytes()));
                    write_private(
                        &dir.path().join(format!("42-{}-{hash}.toml", 20 + offset)),
                        bytes.as_bytes(),
                    );
                }
            }
            let rows = scan_mixed(dir.path()).unwrap();
            assert_eq!(rows.len(), 2);
            assert!(rows.iter().all(|r| r.status == StoredStatus::Unreadable));
            assert!(rows.iter().all(|r| r.verified_sha256.is_none()));
            for row in &rows {
                fs::remove_file(&row.path).unwrap();
                assert_error(read_mixed(dir.path(), row), "not readable");
            }
        }
    }

    /// LOAD-BEARING BREAK: digest-based deduplication wrongly poisons distinct
    /// sequence identities carrying the same verified bytes.
    #[test]
    fn equal_digest_at_distinct_sequences_remains_valid() {
        let dir = tempfile::tempdir().unwrap();
        let bytes = b"same";
        let hash = encode_hex(&Sha256::digest(bytes));
        for sequence in [1, 2] {
            write_private(&dir.path().join(format!("{sequence}-1-{hash}.toml")), bytes);
        }
        let rows = scan_mixed(dir.path()).unwrap();
        assert!(
            rows.iter()
                .all(|r| r.status == StoredStatus::LegacyTomlOnly)
        );
    }

    #[test]
    fn matching_digest_invalid_utf8_legacy_is_unreadable() {
        let dir = tempfile::tempdir().unwrap();
        let bytes = [0xff];
        let name = format!("1-1-{}.toml", encode_hex(&Sha256::digest(bytes)));
        write_private(&dir.path().join(name), &bytes);
        let row = scan_mixed(dir.path()).unwrap().remove(0);
        assert_eq!(row.status, StoredStatus::Unreadable);
        assert!(row.verified_sha256.is_none());
    }

    /// LOAD-BEARING BREAK: trusting any filename identity or allowing codec
    /// errors to abort the scan either blesses mismatches or hides good rows.
    #[test]
    fn bad_v2_rows_are_listed_unreadable_without_failing_scan() {
        let dir = tempfile::tempdir().unwrap();
        let good = sample();
        write_v2(dir.path(), &good);
        let add = |sequence, timestamp, digest: [u8; 32], bytes: Vec<u8>| {
            let name = format!("v2-{sequence:020}-{timestamp}-{}.json", encode_hex(&digest));
            write_private(&dir.path().join(name), &bytes);
        };
        let aligned = |sequence, timestamp| Envelope {
            sequence,
            timestamp_unix_seconds: timestamp,
            ..good.clone()
        };
        add(8, 9, good.source_sha256, encode_envelope(&good).unwrap());
        add(
            9,
            8,
            good.source_sha256,
            encode_envelope(&aligned(9, 9)).unwrap(),
        );
        add(
            10,
            10,
            [0x44; 32],
            encode_envelope(&aligned(10, 10)).unwrap(),
        );
        add(11, 11, [0x55; 32], b"{broken".to_vec());
        add(
            12,
            12,
            [0x66; 32],
            encode_envelope(&good).unwrap()[..20].to_vec(),
        );
        let canonical = |sequence| {
            String::from_utf8(encode_envelope(&aligned(sequence, sequence)).unwrap()).unwrap()
        };
        add(
            13,
            13,
            good.source_sha256,
            format!(" {}", canonical(13)).into_bytes(),
        );
        add(
            14,
            14,
            good.source_sha256,
            canonical(14)
                .replace("\"version\":2", "\"version\":3")
                .into_bytes(),
        );
        add(
            15,
            15,
            good.source_sha256,
            canonical(15)
                .replacen(&encode_hex(&good.sha256), &"0".repeat(64), 1)
                .into_bytes(),
        );
        add(
            16,
            16,
            [0; 32],
            canonical(16)
                .replacen(&encode_hex(&good.source_sha256), &"0".repeat(64), 1)
                .into_bytes(),
        );
        let rows = scan_mixed(dir.path()).unwrap();
        assert_eq!(rows.len(), 10);
        assert_eq!(
            rows.iter()
                .filter(|r| r.status == StoredStatus::Recorded)
                .count(),
            1
        );
        for row in rows.iter().filter(|r| r.status == StoredStatus::Unreadable) {
            assert!(row.verified_sha256.is_none());
            assert!(row.verified_source_sha256.is_none());
        }
    }

    /// LOAD-BEARING BREAK: following links, accepting public modes, or opening
    /// FIFOs without `O_NONBLOCK` can disclose data or hang the daemon.
    #[test]
    fn unsafe_entry_types_and_modes_are_unreadable() {
        use nix::sys::stat::Mode;
        use nix::unistd::mkfifo;
        use std::os::unix::fs::{PermissionsExt, symlink};

        let dir = tempfile::tempdir().unwrap();
        let bytes = b"legacy";
        let hash = encode_hex(&Sha256::digest(bytes));
        let target = dir.path().join("target");
        write_private(&target, bytes);
        let regular = dir.path().join(format!("1-1-{hash}.toml"));
        write_private(&regular, bytes);
        fs::set_permissions(&regular, fs::Permissions::from_mode(0o644)).unwrap();
        let link = dir.path().join(format!("2-1-{hash}.toml"));
        symlink(&target, link).unwrap();
        let fifo = dir.path().join(format!("3-1-{hash}.toml"));
        mkfifo(&fifo, Mode::from_bits_truncate(0o600)).unwrap();
        symlink(
            dir.path().join("absent"),
            dir.path().join(format!("4-1-{hash}.toml")),
        )
        .unwrap();
        let rows = scan_mixed(dir.path()).unwrap();
        assert_eq!(rows.len(), 4);
        assert!(rows.iter().all(|r| r.status == StoredStatus::Unreadable));
    }

    struct PanicReader;
    impl Read for PanicReader {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            panic!("metadata rejection must precede reads")
        }
    }
    struct CountingReader(usize);
    impl Read for CountingReader {
        fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
            self.0 += output.len();
            output.fill(b'x');
            Ok(output.len())
        }
    }

    /// LOAD-BEARING BREAK: allocating or reading before validation permits an
    /// attacker-controlled oversized or unsafe object to consume resources.
    #[test]
    fn bounded_read_validates_metadata_first_and_reads_only_cap_plus_one() {
        let safe = |len| CheckedMetadata {
            regular: true,
            uid: 9,
            mode: 0o100_600,
            len,
        };
        assert_error(read_bounded(PanicReader, safe(11), 9, 10), "unsafe");
        for metadata in [
            CheckedMetadata { uid: 8, ..safe(0) },
            CheckedMetadata {
                mode: 0o100_644,
                ..safe(0)
            },
            CheckedMetadata {
                mode: 0o104_600,
                ..safe(0)
            },
            CheckedMetadata {
                regular: false,
                ..safe(0)
            },
        ] {
            assert_error(read_bounded(PanicReader, metadata, 9, 10), "unsafe");
        }
        let mut reader = CountingReader(0);
        assert_error(read_bounded(&mut reader, safe(10), 9, 10), "changed size");
        assert_eq!(reader.0, 11);
        assert_eq!(cap_for_format(StoredFormat::Legacy), 10 * 1024 * 1024);
        assert_eq!(cap_for_format(StoredFormat::V2), 32 * 1024 * 1024);
    }

    type SnapshotItem = (OsString, u8, u32, u32, u32, u64, u64, u64, Vec<u8>);

    fn snapshot(dir: &Path) -> (SnapshotItem, Vec<SnapshotItem>) {
        let capture = |name, path: &Path| {
            let metadata = fs::symlink_metadata(path).unwrap();
            let kind = if metadata.is_dir() {
                1
            } else if metadata.is_file() {
                2
            } else if metadata.file_type().is_symlink() {
                3
            } else {
                4
            };
            let bytes = if metadata.is_file() {
                fs::read(path).unwrap()
            } else if metadata.file_type().is_symlink() {
                fs::read_link(path).unwrap().as_os_str().as_bytes().to_vec()
            } else {
                Vec::new()
            };
            (
                name,
                kind,
                metadata.uid(),
                metadata.gid(),
                metadata.mode(),
                metadata.dev(),
                metadata.ino(),
                metadata.len(),
                bytes,
            )
        };
        let mut items = fs::read_dir(dir)
            .unwrap()
            .map(|item| {
                let item = item.unwrap();
                capture(item.file_name(), &item.path())
            })
            .collect::<Vec<_>>();
        items.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
        (capture(".".into(), dir), items)
    }

    /// LOAD-BEARING BREAK: cleanup, chmod, or rewrite behavior in a reader
    /// mutates operator evidence during an inspection-only operation.
    #[test]
    fn scan_and_read_leave_directory_unchanged() {
        let dir = tempfile::tempdir().unwrap();
        write_v2(dir.path(), &sample());
        write_private(&dir.path().join("foreign"), b"keep");
        write_private(
            &dir.path().join(format!(".{}.tmp", v2_name(&sample()))),
            b"stage",
        );
        let bad = b"bad";
        std::os::unix::fs::symlink(
            dir.path().join("foreign"),
            dir.path()
                .join(format!("1-1-{}.toml", encode_hex(&Sha256::digest(bad)))),
        )
        .unwrap();
        let before = snapshot(dir.path());
        let rows = scan_mixed(dir.path()).unwrap();
        let good = rows
            .iter()
            .find(|row| row.status == StoredStatus::Recorded)
            .unwrap();
        assert!(matches!(
            read_mixed(dir.path(), good).unwrap(),
            StoredPayload::V2(_)
        ));
        assert_eq!(snapshot(dir.path()), before);
    }

    /// LOAD-BEARING BREAK: reading by path without same-object identity lets a
    /// replacement swap contents between listing and the bounded read.
    #[test]
    fn read_mixed_refuses_replacement_and_unreadable_rows() {
        let dir = tempfile::tempdir().unwrap();
        let envelope = sample();
        let path = write_v2(dir.path(), &envelope);
        let row = scan_mixed(dir.path()).unwrap().remove(0);
        fs::remove_file(&path).unwrap();
        write_private(&path, &encode_envelope(&envelope).unwrap());
        assert_error(read_mixed(dir.path(), &row), "replaced after listing");

        fs::write(&path, b"broken").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let row = scan_mixed(dir.path()).unwrap().remove(0);
        assert_eq!(row.status, StoredStatus::Unreadable);
        assert_error(read_mixed(dir.path(), &row), "not readable");
    }

    /// LOAD-BEARING BREAK: wiring exact v2 finals into the legacy list makes
    /// JSON bytes reachable by the current String rollback path.
    #[test]
    fn v2_remains_invisible_to_public_legacy_reader() {
        let dir = tempfile::tempdir().unwrap();
        let toml = "asn = 64512\n";
        assert!(record_v2(dir.path(), toml, manifest_for(toml)).unwrap());
        assert!(super::super::list(dir.path()).unwrap().is_empty());
        assert_eq!(
            super::super::read_entry(dir.path(), 0).unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
    }

    /// LOAD-BEARING BREAK: failing to assign unique contiguous sequences or
    /// changing the retention bound leaves the wrong 20 logical rows.
    #[test]
    fn writer_serializes_sequence_and_retains_twenty() {
        use std::sync::Arc;

        let root = tempfile::tempdir().unwrap();
        let dir = Arc::new(root.path().join("history"));
        let mut threads = Vec::new();
        for index in 0..24 {
            let dir = Arc::clone(&dir);
            threads.push(std::thread::spawn(move || {
                let toml = format!("asn = {}\n", 64512 + index);
                record_v2(&dir, &toml, manifest_for(&toml)).unwrap()
            }));
        }
        assert!(threads.into_iter().all(|thread| thread.join().unwrap()));
        let rows = recorded_rows(&dir);
        assert_eq!(rows.len(), super::super::HISTORY_LIMIT);
        assert_eq!(rows.first().unwrap().sequence, 24);
        assert_eq!(rows.last().unwrap().sequence, 5);
        assert!(rows.iter().all(|row| row.status == StoredStatus::Recorded));
    }

    /// LOAD-BEARING BREAK: comparing TOML without the complete manifest, or
    /// accepting a legacy/corrupt newest row, loses a distinct source snapshot.
    #[test]
    fn writer_dedupe_requires_exact_toml_manifest_and_valid_v2_newest() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("history");
        let toml = "asn = 64512\n";
        let manifest = manifest_for(toml);
        assert!(record_v2(&dir, toml, manifest.clone()).unwrap());
        assert!(!record_v2(&dir, toml, manifest.clone()).unwrap());

        let mut changed = manifest.clone();
        changed.rpol_units[0].modules[0].length += 1;
        assert!(record_v2(&dir, toml, changed).unwrap());
        assert_eq!(recorded_rows(&dir).len(), 2);

        let newest = recorded_rows(&dir).remove(0);
        fs::write(dir.join(&newest.filename), b"corrupt").unwrap();
        assert!(record_v2(&dir, toml, manifest.clone()).unwrap());

        let legacy_dir = root.path().join("legacy");
        fs::create_dir(&legacy_dir).unwrap();
        fs::set_permissions(&legacy_dir, fs::Permissions::from_mode(0o700)).unwrap();
        let digest = encode_hex(&Sha256::digest(toml.as_bytes()));
        write_private(
            &legacy_dir.join(format!("1-1-{digest}.toml")),
            toml.as_bytes(),
        );
        assert!(record_v2(&legacy_dir, toml, manifest).unwrap());
    }

    /// LOAD-BEARING BREAK: path-relative work after pinning publishes into the
    /// replacement decoy rather than the original directory authority.
    #[test]
    fn writer_uses_pinned_directory_after_path_replacement() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("history");
        let moved = root.path().join("moved");
        let toml = "asn = 64512\n";
        let mut replaced = false;
        assert!(
            record_v2_with(&path, toml, manifest_for(toml), |point| {
                if point == WriteStep::Pinned && !replaced {
                    fs::rename(&path, &moved)?;
                    fs::create_dir(&path)?;
                    fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
                    write_private(&path.join("decoy"), b"untouched");
                    replaced = true;
                }
                Ok(())
            })
            .unwrap()
        );
        assert_eq!(recorded_rows(&moved).len(), 1);
        assert!(recorded_rows(&path).is_empty());
        assert_eq!(fs::read(path.join("decoy")).unwrap(), b"untouched");
    }

    /// LOAD-BEARING BREAK: broad stage matching deletes operator files;
    /// following an exact-stage link turns cleanup into an arbitrary unlink.
    #[test]
    fn writer_cleanup_is_exact_and_unsafe_exact_stage_blocks() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("history");
        fs::create_dir(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        let digest = "0".repeat(64);
        let exact = format!(".v2-{:020}-1-{digest}.json.tmp", 1);
        write_private(&dir.join(&exact), b"stage");
        for name in [
            format!("{exact}.extra"),
            format!(".v2-1-1-{digest}.json.tmp"),
            format!(".v2-{:020}-01-{digest}.json.tmp", 1),
            format!(".v2-{:020}-1-{}.json.tmp", 1, "A".repeat(64)),
        ] {
            write_private(&dir.join(name), b"keep");
        }
        let toml = "x = 1\n";
        assert!(record_v2(&dir, toml, manifest_for(toml)).unwrap());
        assert!(!dir.join(exact).exists());
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 5);

        let unsafe_name = format!(".v2-{:020}-2-{digest}.json.tmp", 2);
        symlink(dir.join("absent"), dir.join(&unsafe_name)).unwrap();
        let mut cleanup_sync_observed = false;
        assert_error(
            record_v2_with(&dir, "x = 2\n", manifest_for("x = 2\n"), |point| {
                cleanup_sync_observed |= point == WriteStep::CleanupSync;
                Ok(())
            }),
            "unsafe config history stage",
        );
        assert!(cleanup_sync_observed);
        assert!(
            fs::symlink_metadata(dir.join(unsafe_name))
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }

    /// LOAD-BEARING BREAK: validation after directory/stage creation leaves
    /// filesystem residue for an input that was never eligible to publish.
    #[test]
    fn writer_prevalidation_creates_no_directory_or_residue() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("history");
        let mut manifest = manifest_for("x = 1\n");
        manifest.rpol_units[0].modules.clear();
        assert_error(record_v2(&dir, "x = 1\n", manifest), "1..=64 modules");
        assert!(!dir.exists());

        let target = root.path().join("target");
        fs::create_dir(&target).unwrap();
        let link = root.path().join("link");
        symlink(&target, &link).unwrap();
        assert!(record_v2(&link, "x = 1\n", manifest_for("x = 1\n")).is_err());
        assert_eq!(fs::read_dir(&target).unwrap().count(), 0);
        let file = root.path().join("file");
        fs::write(&file, b"untouched").unwrap();
        assert!(record_v2(&file, "x = 1\n", manifest_for("x = 1\n")).is_err());
        assert_eq!(fs::read(&file).unwrap(), b"untouched");
    }

    /// LOAD-BEARING BREAK: a non-exclusive create, public stage mode, or
    /// clobbering rename can expose a partial entry or overwrite an object.
    #[test]
    fn writer_stage_is_private_and_publication_never_clobbers() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("history");
        let toml = "x = 1\n";
        let mut collision = None;
        let result = record_v2_with(&dir, toml, manifest_for(toml), |point| {
            if point == WriteStep::StageWrite {
                let stage = fs::read_dir(&dir)?
                    .map(|item| item.unwrap())
                    .find(|item| parse_stage_name(&item.file_name()).is_some())
                    .unwrap();
                assert_eq!(stage.metadata()?.mode() & 0o7777, 0o600);
            }
            if point == WriteStep::Publish {
                let stage = fs::read_dir(&dir)?
                    .map(|item| item.unwrap().file_name())
                    .find(|name| parse_stage_name(name).is_some())
                    .unwrap();
                let final_name = stage
                    .to_str()
                    .unwrap()
                    .strip_prefix('.')
                    .unwrap()
                    .strip_suffix(".tmp")
                    .unwrap();
                write_private(&dir.join(final_name), b"collision");
                collision = Some(final_name.to_string());
            }
            Ok(())
        });
        assert!(result.is_err());
        assert_eq!(
            fs::read(dir.join(collision.unwrap())).unwrap(),
            b"collision"
        );
        assert!(
            fs::read_dir(&dir)
                .unwrap()
                .all(|item| parse_stage_name(&item.unwrap().file_name()).is_none())
        );
    }

    /// LOAD-BEARING BREAK: dropping any sync or moving it across publication
    /// changes this real operation trace and its durability boundary.
    #[test]
    fn writer_operation_trace_and_final_sync_failure_boundary() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("history");
        let toml = "x = 1\n";
        let mut trace = Vec::new();
        assert!(
            record_v2_with(&dir, toml, manifest_for(toml), |point| {
                trace.push(point);
                Ok(())
            })
            .unwrap()
        );
        assert_eq!(
            trace,
            [
                WriteStep::Pinned,
                WriteStep::CleanupSync,
                WriteStep::StageCreate,
                WriteStep::StageWrite,
                WriteStep::StageSync,
                WriteStep::EvictionSync,
                WriteStep::Publish,
                WriteStep::FinalSync,
            ]
        );

        let error = record_v2_with(&dir, "x = 2\n", manifest_for("x = 2\n"), |point| {
            if point == WriteStep::FinalSync {
                Err(io::Error::other("injected final sync failure"))
            } else {
                Ok(())
            }
        })
        .unwrap_err();
        assert!(error.to_string().contains("final sync"));
        assert_eq!(recorded_rows(&dir).len(), 2);
        assert!(
            fs::read_dir(&dir)
                .unwrap()
                .all(|item| parse_stage_name(&item.unwrap().file_name()).is_none())
        );
    }

    /// LOAD-BEARING BREAK: every injected pre-publication error must remove
    /// this writer's stage and must not make a final visible.
    #[test]
    fn every_injected_prepublish_failure_has_no_final_or_stage() {
        for failure in [
            WriteStep::StageCreate,
            WriteStep::StageWrite,
            WriteStep::StageSync,
            WriteStep::Publish,
        ] {
            let root = tempfile::tempdir().unwrap();
            let dir = root.path().join("history");
            let result = record_v2_with(&dir, "x = 1\n", manifest_for("x = 1\n"), |point| {
                if point == failure {
                    Err(io::Error::other("injected prepublish failure"))
                } else {
                    Ok(())
                }
            });
            assert!(result.is_err(), "{failure:?}");
            assert!(recorded_rows(&dir).is_empty(), "{failure:?}");
            assert!(
                fs::read_dir(&dir)
                    .unwrap()
                    .all(|item| parse_stage_name(&item.unwrap().file_name()).is_none())
            );
        }

        for failure in [WriteStep::EvictionUnlink, WriteStep::EvictionSync] {
            let root = tempfile::tempdir().unwrap();
            let dir = root.path().join("history");
            for index in 0..super::super::HISTORY_LIMIT {
                let toml = format!("x = {index}\n");
                record_v2(&dir, &toml, manifest_for(&toml)).unwrap();
            }
            let result = record_v2_with(&dir, "x = 99\n", manifest_for("x = 99\n"), |point| {
                if point == failure {
                    Err(io::Error::other("injected eviction failure"))
                } else {
                    Ok(())
                }
            });
            assert!(result.is_err(), "{failure:?}");
            assert!(recorded_rows(&dir).iter().all(|row| row.sequence <= 20));
            assert!(
                fs::read_dir(&dir)
                    .unwrap()
                    .all(|item| parse_stage_name(&item.unwrap().file_name()).is_none())
            );
        }
    }

    /// LOAD-BEARING BREAK: failure cleanup must compare the stage object it
    /// created, not unlink an attacker replacement that reused the basename.
    #[test]
    fn unsafe_stage_regular_replacement_survives_failure_cleanup() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("history");
        let sentinel = b"replacement-sentinel";
        let mut replacement = None;
        let result = record_v2_with(&dir, "x = 1\n", manifest_for("x = 1\n"), |point| {
            if point == WriteStep::StageSync {
                let name = fs::read_dir(&dir)?
                    .map(|item| item.unwrap().file_name())
                    .find(|name| parse_stage_name(name).is_some())
                    .unwrap();
                fs::remove_file(dir.join(&name))?;
                write_private(&dir.join(&name), sentinel);
                replacement = Some(name);
                return Err(io::Error::other("injected replacement"));
            }
            Ok(())
        });
        assert!(result.is_err());
        let replacement = replacement.unwrap();
        assert_eq!(fs::read(dir.join(replacement)).unwrap(), sentinel);
    }

    /// LOAD-BEARING BREAK: eviction must revalidate the exact oldest object;
    /// following or removing an unsafe recognized final destroys evidence.
    #[test]
    fn unsafe_oldest_final_blocks_eviction_and_survives() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("history");
        fs::create_dir(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        let digest = "0".repeat(64);
        let unsafe_name = format!("v2-{:020}-1-{digest}.json", 1);
        symlink(dir.join("absent"), dir.join(&unsafe_name)).unwrap();
        for sequence in 2..=20 {
            write_private(
                &dir.join(format!("v2-{sequence:020}-1-{digest}.json")),
                b"corrupt",
            );
        }
        assert_error(
            record_v2(&dir, "x = 1\n", manifest_for("x = 1\n")),
            "unsafe config history eviction candidate",
        );
        assert!(
            fs::symlink_metadata(dir.join(unsafe_name))
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(scan_mixed(&dir).unwrap().len(), 20);
    }

    /// LOAD-BEARING BREAK: dedupe before repairing an over-cap store leaves 21
    /// rows, while skipping the unconditional cleanup sync permits a stage.
    #[test]
    fn over_cap_repair_precedes_dedupe_and_cleanup_sync_retries() {
        let root = tempfile::tempdir().unwrap();
        let failed = root.path().join("failed-sync");
        assert!(
            record_v2_with(&failed, "x = 1\n", manifest_for("x = 1\n"), |point| {
                if point == WriteStep::CleanupSync {
                    Err(io::Error::other("injected cleanup sync failure"))
                } else {
                    Ok(())
                }
            })
            .is_err()
        );
        assert!(scan_mixed(&failed).unwrap().is_empty());
        assert!(record_v2(&failed, "x = 1\n", manifest_for("x = 1\n")).unwrap());

        let dir = root.path().join("over-cap");
        fs::create_dir(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        let digest = "0".repeat(64);
        for sequence in 1..=20 {
            write_private(
                &dir.join(format!("v2-{sequence:020}-1-{digest}.json")),
                b"corrupt",
            );
        }
        let toml = "x = 1\n";
        let manifest = manifest_for(toml);
        let envelope = Envelope {
            version: VERSION,
            sequence: 21,
            timestamp_unix_seconds: 1,
            sha256: manifest.toml_sha256,
            source_sha256: manifest_source_sha256(&manifest),
            normalized_toml: toml.into(),
            manifest: manifest.clone(),
        };
        write_v2(&dir, &envelope);
        assert!(!record_v2(&dir, toml, manifest).unwrap());
        let rows = scan_mixed(&dir).unwrap();
        assert_eq!(rows.len(), 20);
        assert_eq!(rows.first().unwrap().sequence, 21);
        assert_eq!(rows.last().unwrap().sequence, 2);
    }

    /// LOAD-BEARING BREAK: tied sequences are ordered by raw basename bytes;
    /// reverse eviction must remove the lexically largest tied name first.
    #[test]
    fn tied_sequence_eviction_uses_reverse_raw_basename_order() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("history");
        fs::create_dir(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        let name = |prefix: u8| format!("v2-{:020}-1-{:02x}{}.json", 7, prefix, "0".repeat(62));
        for prefix in 0..=20 {
            write_private(&dir.join(name(prefix)), b"corrupt");
        }
        let mut unlinks = 0;
        let result = record_v2_with(&dir, "x = 1\n", manifest_for("x = 1\n"), |point| {
            if point == WriteStep::EvictionUnlink {
                unlinks += 1;
                if unlinks == 2 {
                    return Err(io::Error::other("stop at publication eviction"));
                }
            }
            Ok(())
        });
        assert!(result.is_err());
        assert!(!dir.join(name(20)).exists());
        assert!(dir.join(name(19)).exists());
        assert_eq!(scan_mixed(&dir).unwrap().len(), super::super::HISTORY_LIMIT);
    }

    /// LOAD-BEARING BREAK: the process-wide guard must cover both descriptor
    /// pinning/selection and the final publication boundary.
    #[test]
    fn writer_lock_spans_pinning_through_publication() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("history");
        let mut observed = Vec::new();
        assert!(
            record_v2_with(&dir, "x = 1\n", manifest_for("x = 1\n"), |point| {
                if matches!(point, WriteStep::Pinned | WriteStep::Publish) {
                    assert!(WRITER_LOCK.try_lock().is_err(), "lock absent at {point:?}");
                    observed.push(point);
                }
                Ok(())
            })
            .unwrap()
        );
        assert_eq!(observed, [WriteStep::Pinned, WriteStep::Publish]);
    }

    /// LOAD-BEARING BREAK: sequence selection that ignores either generation
    /// can reuse an identity; wrapping at `u64::MAX` silently poisons history.
    #[test]
    fn writer_mixed_sequence_and_overflow_are_strict() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("history");
        fs::create_dir(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        let bytes = b"legacy";
        let digest = encode_hex(&Sha256::digest(bytes));
        write_private(&dir.join(format!("8-1-{digest}.toml")), bytes);
        assert!(record_v2(&dir, "x = 1\n", manifest_for("x = 1\n")).unwrap());
        assert_eq!(recorded_rows(&dir)[0].sequence, 9);

        let overflow = root.path().join("overflow");
        fs::create_dir(&overflow).unwrap();
        fs::set_permissions(&overflow, fs::Permissions::from_mode(0o700)).unwrap();
        write_private(
            &overflow.join(format!("{}-1-{digest}.toml", u64::MAX)),
            bytes,
        );
        assert_error(
            record_v2(&overflow, "x = 1\n", manifest_for("x = 1\n")),
            "sequence is exhausted",
        );
        assert_eq!(fs::read_dir(&overflow).unwrap().count(), 1);
    }

    /// LOAD-BEARING BREAK: removing the directory `fchmod(0700)` leaves an
    /// owned existing directory public. Ignoring corrupt or duplicate logical
    /// rows breaks both the retention count and next-sequence selection.
    #[test]
    fn writer_repairs_directory_mode_and_counts_corrupt_duplicates() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("history");
        fs::create_dir(&dir).unwrap();
        for sequence in 1..=21 {
            let digest = "0".repeat(64);
            write_private(
                &dir.join(format!("v2-{sequence:020}-1-{digest}.json")),
                b"corrupt",
            );
        }
        // A second recognized final with sequence 21 poisons both duplicates.
        write_private(&dir.join(format!("21-1-{}.toml", "0".repeat(64))), b"bad");
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(record_v2(&dir, "x = 1\n", manifest_for("x = 1\n")).unwrap());
        assert_eq!(fs::metadata(&dir).unwrap().mode() & 0o7777, 0o700);
        assert_eq!(scan_mixed(&dir).unwrap().len(), super::super::HISTORY_LIMIT);
        assert_eq!(recorded_rows(&dir)[0].sequence, 22);
    }

    /// LOAD-BEARING BREAK: a duplicate or unknown-version newest row cannot be
    /// treated as a valid v2 dedupe target, including writable downgrade where
    /// a legacy writer reuses a sequence already occupied by v2.
    #[test]
    fn writer_refuses_duplicate_and_unknown_newest_dedupe() {
        let root = tempfile::tempdir().unwrap();
        let toml = "x = 1\n";

        let duplicate = root.path().join("duplicate");
        record_v2(&duplicate, toml, manifest_for(toml)).unwrap();
        let digest = encode_hex(&Sha256::digest(toml.as_bytes()));
        write_private(
            &duplicate.join(format!("1-1-{digest}.toml")),
            toml.as_bytes(),
        );
        let poisoned = scan_mixed(&duplicate).unwrap();
        assert_eq!(poisoned.len(), 2);
        assert!(
            poisoned
                .iter()
                .all(|row| row.status == StoredStatus::Unreadable)
        );
        assert!(record_v2(&duplicate, toml, manifest_for(toml)).unwrap());
        assert_eq!(recorded_rows(&duplicate)[0].sequence, 2);

        let unknown = root.path().join("unknown");
        record_v2(&unknown, toml, manifest_for(toml)).unwrap();
        let row = recorded_rows(&unknown).remove(0);
        let parsed = parse_mixed_name(&row.filename).unwrap();
        let manifest = manifest_for(toml);
        let aligned = Envelope {
            version: VERSION,
            sequence: 2,
            timestamp_unix_seconds: parsed.timestamp,
            sha256: manifest.toml_sha256,
            source_sha256: manifest_source_sha256(&manifest),
            normalized_toml: toml.into(),
            manifest,
        };
        let broken = String::from_utf8(encode_envelope(&aligned).unwrap())
            .unwrap()
            .replace("\"version\":2", "\"version\":3");
        write_private(
            &unknown.join(format!(
                "v2-{:020}-{}-{}.json",
                2,
                parsed.timestamp,
                encode_hex(&aligned.source_sha256)
            )),
            broken.as_bytes(),
        );
        assert!(record_v2(&unknown, toml, manifest_for(toml)).unwrap());
        assert_eq!(recorded_rows(&unknown)[0].sequence, 3);
    }

    /// Exact structural fence around the real durability/mode syscalls. This
    /// complements behavioral fault tests: deleting an actual guarded syscall,
    /// while leaving its nearby test hook in place, must still turn red.
    #[test]
    fn writer_real_syscall_fence_is_load_bearing() {
        let source = include_str!("v2.rs");
        for parts in [
            &["builder.mode", "(0o700);"][..],
            &["fchmod(&file, Mode::", "from_bits_truncate(0o700))"],
            &["fchmod(&stage, Mode::", "from_bits_truncate(0o600))"],
            &["stage.sync_", "all()?;"],
            &[
                "cleanup_sync_result = step(WriteStep::CleanupSync)",
                ".and_then(|()| directory.sync_all())",
            ],
            &[
                "step(WriteStep::EvictionSync)?;\n",
                "    directory.sync_all()",
            ],
            &[
                "step(WriteStep::FinalSync)?;\n",
                "        directory.sync_all()",
            ],
            &["static WRITER_LOCK: Mutex<", "()> = Mutex::new(());"],
            &["RenameFlags::RENAME_", "NOREPLACE"],
            &[
                ".lock()\n        .map_err(|_| io::Error::other(",
                "\"config history writer lock is poisoned\"))?;",
            ],
        ] {
            let required = parts.concat();
            assert!(
                source.contains(&required),
                "missing production fence: {required}"
            );
        }
        let lock = source
            .find(&["let _guard = WRITER_", "LOCK"].concat())
            .unwrap();
        let selection = source
            .find(&["let mut rows = scan_", "pinned(&directory, dir)?;"].concat())
            .unwrap();
        let publication = selection
            + source[selection..]
                .find(&["renameat2", "("].concat())
                .unwrap();
        assert!(lock < selection && selection < publication);

        let writer_start = source.find(&["fn record_v2_", "with("].concat()).unwrap();
        let writer_end = writer_start
            + source[writer_start..]
                .find(&["fn open_or_create_", "writer_directory"].concat())
                .unwrap();
        let writer = &source[writer_start..writer_end];
        let stage_start = writer.find(&["let fd = open", "at("].concat()).unwrap();
        let stage_end = stage_start
            + writer[stage_start..]
                .find(&[".map_err", "(errno)?;"].concat())
                .unwrap();
        let stage_open = &writer[stage_start..stage_end];
        for parts in [
            &["OFlag::O_EX", "CL"][..],
            &["OFlag::O_NO", "FOLLOW"],
            &["Mode::from_bits_", "truncate(0o600)"],
        ] {
            let required = parts.concat();
            assert!(
                stage_open.contains(&required),
                "stage open missing exact guard: {required}"
            );
        }
    }
}
