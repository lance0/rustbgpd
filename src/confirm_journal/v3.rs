//! Disk-backed v3 commit-confirm authority.
//!
//! A config-adjacent locator is the sole boot authority. It names one fixed
//! metadata object; metadata in turn binds one fixed raw normalized-prior
//! object by length, digest, device, and inode. Every object is opened relative
//! to a pinned directory descriptor and publication is raw, metadata, locator.

#![deny(unsafe_code)]

use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::{self, Read as _, Seek as _, Write as _};
use std::os::unix::ffi::{OsStrExt as _, OsStringExt as _};
use std::os::unix::fs::MetadataExt as _;
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::config::{AcceptedConfigSnapshot, Config, persisted_config_document};
use crate::config_history;
use crate::config_history::v2::{self as history_v2, LosslessPath, Manifest};

const VERSION: u32 = 3;
const MAX_CONFIRM_ID_CHARS: usize = 128;
pub(crate) const MAX_RAW_BYTES: usize = 384 * 1024 * 1024;
const MAX_METADATA_BYTES: usize = 34 * 1024 * 1024;
const MAX_LOCATOR_BYTES: usize = 512 * 1024;
const MAX_PATH_BYTES: usize = 64 * 1024;
const LOCATOR_SUFFIX: &str = ".commit-confirm-locator.json";
pub(crate) const RAW_FILE_NAME: &str = "commit-confirm-v3-prior.toml";
pub(crate) const METADATA_FILE_NAME: &str = "commit-confirm-v3-metadata.json";

const fn normalized_prior_length_within_limit(length: usize, limit: usize) -> bool {
    length <= limit
}

/// Stable lexical identity captured before the candidate config is opened.
#[derive(Clone, Debug)]
pub(crate) struct LaunchIdentity {
    lexical_config: PathBuf,
    #[cfg(test)]
    fail_publish_step: Option<PublishStep>,
    max_raw_bytes: usize,
}

impl LaunchIdentity {
    pub(crate) fn resolve(path: &Path) -> io::Result<Self> {
        let absolute = if path.is_absolute() {
            path.to_path_buf()
        } else {
            std::env::current_dir()?.join(path)
        };
        reject_ambiguous_terminal_path(&absolute)?;
        let lexical_config = normalize_launch_path(&absolute)?;
        if lexical_config.file_name().is_none() {
            return Err(invalid("launch config path has no final component"));
        }
        Ok(Self {
            lexical_config,
            #[cfg(test)]
            fail_publish_step: None,
            max_raw_bytes: MAX_RAW_BYTES,
        })
    }

    pub(crate) fn normalized_prior_limit_bytes(&self) -> usize {
        self.max_raw_bytes
    }

    pub(crate) fn accepts_normalized_prior_length(&self, length: usize) -> bool {
        normalized_prior_length_within_limit(length, self.normalized_prior_limit_bytes())
    }

    pub(crate) fn locator_path(&self) -> PathBuf {
        let mut bytes = self.lexical_config.as_os_str().as_bytes().to_vec();
        bytes.extend_from_slice(LOCATOR_SUFFIX.as_bytes());
        PathBuf::from(OsString::from_vec(bytes))
    }

    /// Inspect v3 before candidate access. A missing locator or canonical v2
    /// locator returns `Ok(None)` so the frozen compatibility lane can run.
    pub(crate) fn boot_revert_check(&self) -> Result<Option<BootRevert>, String> {
        self.boot_revert_check_io().map_err(|error| {
            format!(
                "v3 commit-confirm boot authority is invalid or unavailable ({:?}); inspect the config-adjacent locator and fixed owner-only pending files",
                error.kind()
            )
        })
    }

    fn boot_revert_check_io(&self) -> io::Result<Option<BootRevert>> {
        self.boot_revert_check_io_with(|_| Ok(()))
    }

    fn boot_revert_check_io_with(
        &self,
        mut step: impl FnMut(BootStep) -> io::Result<()>,
    ) -> io::Result<Option<BootRevert>> {
        let locator = Entry::pin_for_absence(&self.locator_path())?;
        if !locator.exists()? {
            return Ok(None);
        }
        locator.directory.validate_private()?;
        let (locator_bytes, locator_identity) = locator.read_bounded(MAX_LOCATOR_BYTES)?;
        if locator_bytes.starts_with(b"{\"version\":2,") {
            return Ok(None);
        }
        let locator_wire = decode_locator(&locator_bytes)?;

        let metadata_path = path_from_wire(&locator_wire.metadata_path)?;
        if metadata_path.file_name() != Some(OsStr::new(METADATA_FILE_NAME)) {
            return Err(invalid("locator metadata path is not the fixed v3 name"));
        }
        let pending = Directory::pin(
            metadata_path
                .parent()
                .ok_or_else(|| invalid("fixed v3 metadata path has no parent"))?,
        )?;
        let metadata = Entry::fixed(Arc::clone(&pending), METADATA_FILE_NAME);
        let raw = Entry::fixed(Arc::clone(&pending), RAW_FILE_NAME);
        if path_from_wire(&locator_wire.metadata_path)? != metadata.absolute_path() {
            return Err(invalid(
                "locator does not name the fixed v3 metadata object",
            ));
        }
        let (metadata_bytes, metadata_identity) = metadata.read_bounded(MAX_METADATA_BYTES)?;
        let metadata_wire = decode_metadata(&metadata_bytes)?;
        validate_linkage(&locator_wire, &metadata_wire)?;
        let (raw_bytes, raw_identity) = raw.read_exact_bounded(metadata_wire.raw_length)?;
        validate_raw(&raw_bytes, raw_identity, &metadata_wire)?;

        let recorded_target = path_from_wire(&locator_wire.config_target)?;
        verify_launch_target(&self.lexical_config, &recorded_target)?;
        let target = Entry::pin(&recorded_target)?;
        let raw_toml = std::str::from_utf8(&raw_bytes).map_err(invalid)?;
        let accepted = AcceptedConfigSnapshot::load_retained(raw_toml, &recorded_target)
            .map_err(|_| invalid("journaled prior sources are unavailable or changed"))?;
        verify_snapshot(&accepted, raw_toml, &metadata_wire)?;

        // Nothing above this point may touch the candidate or backup slot.
        let backup_name = append_name(&target.name, b".unconfirmed")?;
        step(BootStep::CandidateSave)?;
        save_candidate_aside(&target, &backup_name)?;
        step(BootStep::ConfigRestore)?;
        target.replace(raw_toml.as_bytes())?;

        step(BootStep::LocatorUnlink)?;
        locator.remove_matching(locator_identity)?;
        step(BootStep::LocatorDirectorySync)?;
        locator.directory.file.sync_all()?;
        let residue_cleanup_failed = (|| {
            step(BootStep::MetadataUnlink)?;
            metadata.remove_matching(metadata_identity)?;
            step(BootStep::RawUnlink)?;
            raw.remove_matching(raw_identity)?;
            step(BootStep::PendingDirectorySync)?;
            pending.file.sync_all()
        })()
        .is_err();
        Ok(Some(BootRevert {
            accepted,
            notice: BootRevertNotice {
                confirm_id: metadata_wire.confirm_id,
                rollback_failed: metadata_wire.rollback_failed,
                residue_cleanup_failed,
            },
        }))
    }

    pub(crate) fn publish(
        &self,
        pending_dir: &Path,
        confirm_id: &str,
        deadline_unix_seconds: u64,
        prior: &AcceptedConfigSnapshot,
    ) -> Result<PendingFiles, PublishError> {
        self.publish_with(
            pending_dir,
            confirm_id,
            deadline_unix_seconds,
            prior,
            |step| {
                #[cfg(test)]
                if self.fail_publish_step == Some(step) {
                    return Err(io::Error::other("injected v3 publication failure"));
                }
                #[cfg(not(test))]
                let _ = step;
                Ok(())
            },
        )
    }

    #[cfg(test)]
    pub(crate) fn fail_locator_directory_sync_for_test(mut self) -> Self {
        self.fail_publish_step = Some(PublishStep::LocatorDirectorySync);
        self
    }

    #[cfg(test)]
    pub(crate) fn with_max_raw_bytes_for_test(mut self, max_raw_bytes: usize) -> Self {
        self.max_raw_bytes = max_raw_bytes;
        self
    }

    #[expect(
        clippy::too_many_lines,
        reason = "one ordered raw-metadata-locator durability transaction"
    )]
    fn publish_with(
        &self,
        pending_dir: &Path,
        confirm_id: &str,
        deadline_unix_seconds: u64,
        prior: &AcceptedConfigSnapshot,
        mut step: impl FnMut(PublishStep) -> io::Result<()>,
    ) -> Result<PendingFiles, PublishError> {
        let locator = Entry::pin(&self.locator_path()).map_err(PublishError::ordinary)?;
        if locator.exists().map_err(PublishError::ordinary)? {
            return Err(PublishError::ordinary(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "commit-confirm locator is already present",
            )));
        }
        validate_confirm_id(confirm_id).map_err(PublishError::ordinary)?;
        let raw_bytes = prior.normalized_toml().as_bytes();
        if !self.accepts_normalized_prior_length(raw_bytes.len()) {
            return Err(PublishError::ordinary(limit(
                "raw normalized prior",
                self.normalized_prior_limit_bytes(),
            )));
        }
        let raw_sha256: [u8; 32] = Sha256::digest(raw_bytes).into();
        let manifest = config_history::stored_manifest(prior);
        history_v2::validate_manifest(&manifest).map_err(PublishError::ordinary)?;
        if manifest.toml_sha256 != raw_sha256
            || prior.source_sha256() != history_v2::manifest_source_sha256(&manifest)
        {
            return Err(PublishError::ordinary(invalid(
                "accepted prior digest mismatch",
            )));
        }

        let pending = Directory::pin(pending_dir).map_err(PublishError::ordinary)?;
        let raw = Entry::fixed(Arc::clone(&pending), RAW_FILE_NAME);
        let metadata = Entry::fixed(Arc::clone(&pending), METADATA_FILE_NAME);
        cleanup_locator_absent_residue_pinned(&pending).map_err(PublishError::ordinary)?;
        raw.cleanup_stage().map_err(PublishError::ordinary)?;
        metadata.cleanup_stage().map_err(PublishError::ordinary)?;
        locator.cleanup_stage().map_err(PublishError::ordinary)?;

        let raw_identity = raw
            .publish_with(raw_bytes, PublishRole::Raw, &mut step)
            .map_err(|failure| PublishError::ordinary(failure.error))?;
        let metadata_wire = Metadata {
            version: VERSION,
            confirm_id: confirm_id.to_string(),
            deadline_unix_seconds,
            rollback_failed: false,
            raw_name: LosslessPath(RAW_FILE_NAME.as_bytes().to_vec()),
            raw_length: raw_bytes.len() as u64,
            raw_sha256,
            raw_source_sha256: prior.source_sha256(),
            raw_device: raw_identity.device,
            raw_inode: raw_identity.inode,
            manifest,
        };
        let metadata_bytes = match encode_metadata(&metadata_wire) {
            Ok(bytes) => bytes,
            Err(error) => {
                cleanup_created(&raw, raw_identity);
                return Err(PublishError::ordinary(error));
            }
        };
        let metadata_identity =
            match metadata.publish_with(&metadata_bytes, PublishRole::Metadata, &mut step) {
                Ok(identity) => identity,
                Err(failure) => {
                    cleanup_created(&raw, raw_identity);
                    return Err(PublishError::ordinary(failure.error));
                }
            };
        let config_target = resolve_launch_target(&self.lexical_config, true)
            .and_then(|path| Entry::pin(&path).map(|entry| entry.absolute_path()))
            .map_err(|error| {
                cleanup_created(&metadata, metadata_identity);
                cleanup_created(&raw, raw_identity);
                PublishError::ordinary(error)
            })?;
        let locator_wire = Locator {
            version: VERSION,
            confirm_id: confirm_id.to_string(),
            metadata_path: path_to_wire(&metadata.absolute_path()).map_err(|error| {
                cleanup_created(&metadata, metadata_identity);
                cleanup_created(&raw, raw_identity);
                PublishError::ordinary(error)
            })?,
            config_target: path_to_wire(&config_target).map_err(|error| {
                cleanup_created(&metadata, metadata_identity);
                cleanup_created(&raw, raw_identity);
                PublishError::ordinary(error)
            })?,
            prior_sha256: raw_sha256,
            prior_source_sha256: prior.source_sha256(),
        };
        let locator_bytes = encode_locator(&locator_wire).map_err(|error| {
            cleanup_created(&metadata, metadata_identity);
            cleanup_created(&raw, raw_identity);
            PublishError::ordinary(error)
        })?;
        let locator_identity =
            match locator.publish_with(&locator_bytes, PublishRole::Locator, &mut step) {
                Ok(identity) => identity,
                Err(failure) if failure.renamed => {
                    return Err(PublishError {
                        error: failure.error,
                        authority_retained: true,
                    });
                }
                Err(failure) => {
                    cleanup_created(&metadata, metadata_identity);
                    cleanup_created(&raw, raw_identity);
                    return Err(PublishError::ordinary(failure.error));
                }
            };
        Ok(PendingFiles {
            locator,
            metadata,
            raw,
            state: Mutex::new(PendingState {
                locator_wire,
                locator_identity,
                metadata_wire,
                metadata_identity,
                raw_identity,
                locator_phase: CleanupPhase::Published,
                metadata_phase: CleanupPhase::Published,
                raw_phase: CleanupPhase::Published,
            }),
        })
    }
}

#[derive(Debug)]
pub(crate) struct PublishError {
    error: io::Error,
    authority_retained: bool,
}

impl PublishError {
    fn ordinary(error: io::Error) -> Self {
        Self {
            error,
            authority_retained: false,
        }
    }

    pub(crate) fn kind(&self) -> io::ErrorKind {
        self.error.kind()
    }

    pub(crate) fn authority_retained(&self) -> bool {
        self.authority_retained
    }
}

pub(crate) struct BootRevert {
    pub(crate) accepted: Arc<AcceptedConfigSnapshot>,
    pub(crate) notice: BootRevertNotice,
}

#[derive(Clone, Debug)]
pub(crate) struct BootRevertNotice {
    pub(crate) confirm_id: String,
    pub(crate) rollback_failed: bool,
    pub(crate) residue_cleanup_failed: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BootStep {
    CandidateSave,
    ConfigRestore,
    LocatorUnlink,
    LocatorDirectorySync,
    MetadataUnlink,
    RawUnlink,
    PendingDirectorySync,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PublishRole {
    Raw,
    Metadata,
    Locator,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PublishStep {
    RawStageSync,
    RawRename,
    RawDirectorySync,
    MetadataStageSync,
    MetadataRename,
    MetadataDirectorySync,
    LocatorStageSync,
    LocatorRename,
    LocatorDirectorySync,
}

impl PublishStep {
    const fn for_role(role: PublishRole, ordinal: u8) -> Self {
        match (role, ordinal) {
            (PublishRole::Raw, 0) => Self::RawStageSync,
            (PublishRole::Raw, 1) => Self::RawRename,
            (PublishRole::Raw, 2) => Self::RawDirectorySync,
            (PublishRole::Metadata, 0) => Self::MetadataStageSync,
            (PublishRole::Metadata, 1) => Self::MetadataRename,
            (PublishRole::Metadata, 2) => Self::MetadataDirectorySync,
            (PublishRole::Locator, 0) => Self::LocatorStageSync,
            (PublishRole::Locator, 1) => Self::LocatorRename,
            (PublishRole::Locator, 2) => Self::LocatorDirectorySync,
            _ => unreachable!(),
        }
    }
}

#[derive(Debug)]
pub(crate) struct PendingFiles {
    locator: Entry,
    metadata: Entry,
    raw: Entry,
    state: Mutex<PendingState>,
}

#[derive(Debug)]
struct PendingState {
    locator_wire: Locator,
    locator_identity: FileIdentity,
    metadata_wire: Metadata,
    metadata_identity: FileIdentity,
    raw_identity: FileIdentity,
    locator_phase: CleanupPhase,
    metadata_phase: CleanupPhase,
    raw_phase: CleanupPhase,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CleanupPhase {
    Published,
    Unlinked,
    Synced,
}

impl PendingFiles {
    /// Durably remove locator authority first. Fixed residue cleanup after
    /// that terminal point is warning-only and never re-arms authority.
    pub(crate) fn terminal_cleanup(&self) -> io::Result<bool> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| invalid("pending cleanup state is unavailable"))?;
        if state.locator_phase == CleanupPhase::Published {
            self.locator.verify_locator(&state.locator_wire)?;
            self.locator.remove_matching(state.locator_identity)?;
            state.locator_phase = CleanupPhase::Unlinked;
        }
        if state.locator_phase == CleanupPhase::Unlinked {
            self.locator.directory.file.sync_all()?;
            state.locator_phase = CleanupPhase::Synced;
        }
        let residue_result: io::Result<()> = (|| {
            if state.metadata_phase == CleanupPhase::Published {
                self.metadata
                    .verify_metadata(state.metadata_identity, &state.metadata_wire)?;
                self.metadata.remove_matching(state.metadata_identity)?;
                state.metadata_phase = CleanupPhase::Unlinked;
            }
            if state.raw_phase == CleanupPhase::Published {
                self.raw
                    .verify_raw(state.raw_identity, &state.metadata_wire)?;
                self.raw.remove_matching(state.raw_identity)?;
                state.raw_phase = CleanupPhase::Unlinked;
            }
            if state.metadata_phase == CleanupPhase::Unlinked
                || state.raw_phase == CleanupPhase::Unlinked
            {
                self.metadata.directory.file.sync_all()?;
                state.metadata_phase = CleanupPhase::Synced;
                state.raw_phase = CleanupPhase::Synced;
            }
            Ok(())
        })();
        Ok(residue_result.is_err())
    }

    /// Replace compact metadata only; locator linkage deliberately excludes
    /// metadata inode and digest, while the raw identity remains exact.
    pub(crate) fn record_rollback_failed(&self) -> io::Result<()> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| invalid("pending metadata state is unavailable"))?;
        if state.locator_phase != CleanupPhase::Published
            || state.metadata_phase != CleanupPhase::Published
            || state.raw_phase != CleanupPhase::Published
        {
            return Err(invalid("pending cleanup has already started"));
        }
        self.locator.verify_locator(&state.locator_wire)?;
        self.metadata
            .verify_metadata(state.metadata_identity, &state.metadata_wire)?;
        self.raw
            .verify_raw(state.raw_identity, &state.metadata_wire)?;
        let mut updated = state.metadata_wire.clone();
        updated.rollback_failed = true;
        let bytes = encode_metadata(&updated)?;
        let identity = self.metadata.replace(&bytes)?;
        state.metadata_wire = updated;
        state.metadata_identity = identity;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Locator {
    version: u32,
    confirm_id: String,
    metadata_path: LosslessPath,
    config_target: LosslessPath,
    #[serde(with = "history_digest")]
    prior_sha256: [u8; 32],
    #[serde(with = "history_digest")]
    prior_source_sha256: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Metadata {
    version: u32,
    confirm_id: String,
    deadline_unix_seconds: u64,
    rollback_failed: bool,
    raw_name: LosslessPath,
    raw_length: u64,
    #[serde(with = "history_digest")]
    raw_sha256: [u8; 32],
    #[serde(with = "history_digest")]
    raw_source_sha256: [u8; 32],
    raw_device: u64,
    raw_inode: u64,
    manifest: Manifest,
}

fn encode_locator(value: &Locator) -> io::Result<Vec<u8>> {
    validate_locator(value)?;
    let mut bytes = serde_json::to_vec(value).map_err(invalid)?;
    bytes.push(b'\n');
    enforce_cap("locator", bytes.len(), MAX_LOCATOR_BYTES)?;
    Ok(bytes)
}

fn decode_locator(bytes: &[u8]) -> io::Result<Locator> {
    enforce_cap("locator", bytes.len(), MAX_LOCATOR_BYTES)?;
    if !bytes.starts_with(b"{\"version\":3,") {
        return Err(invalid("locator is not canonical v3"));
    }
    let value: Locator = serde_json::from_slice(bytes).map_err(invalid)?;
    validate_locator(&value)?;
    if encode_locator(&value)? != bytes {
        return Err(invalid("non-canonical v3 locator"));
    }
    Ok(value)
}

fn validate_locator(value: &Locator) -> io::Result<()> {
    if value.version != VERSION {
        return Err(invalid("unsupported locator version"));
    }
    validate_confirm_id(&value.confirm_id)?;
    for path in [&value.metadata_path, &value.config_target] {
        let decoded = path_from_wire(path)?;
        if !decoded.is_absolute() || has_parent_dir(&decoded) {
            return Err(invalid("locator path is not absolute and lexical"));
        }
    }
    Ok(())
}

fn encode_metadata(value: &Metadata) -> io::Result<Vec<u8>> {
    validate_metadata(value)?;
    let mut bytes = serde_json::to_vec(value).map_err(invalid)?;
    bytes.push(b'\n');
    enforce_cap("metadata", bytes.len(), MAX_METADATA_BYTES)?;
    Ok(bytes)
}

fn decode_metadata(bytes: &[u8]) -> io::Result<Metadata> {
    enforce_cap("metadata", bytes.len(), MAX_METADATA_BYTES)?;
    if !bytes.starts_with(b"{\"version\":3,") {
        return Err(invalid("metadata is not canonical v3"));
    }
    let value: Metadata = serde_json::from_slice(bytes).map_err(invalid)?;
    validate_metadata(&value)?;
    if encode_metadata(&value)? != bytes {
        return Err(invalid("non-canonical v3 metadata"));
    }
    Ok(value)
}

fn validate_metadata(value: &Metadata) -> io::Result<()> {
    if value.version != VERSION {
        return Err(invalid("unsupported metadata version"));
    }
    validate_confirm_id(&value.confirm_id)?;
    if value.raw_name.0 != RAW_FILE_NAME.as_bytes() {
        return Err(invalid("metadata does not name the fixed raw object"));
    }
    if value.raw_length > MAX_RAW_BYTES as u64 {
        return Err(limit("raw normalized prior", MAX_RAW_BYTES));
    }
    history_v2::validate_manifest(&value.manifest)?;
    if value.manifest.toml_sha256 != value.raw_sha256
        || history_v2::manifest_source_sha256(&value.manifest) != value.raw_source_sha256
    {
        return Err(invalid("metadata digest linkage mismatch"));
    }
    Ok(())
}

fn validate_linkage(locator: &Locator, metadata: &Metadata) -> io::Result<()> {
    if locator.confirm_id != metadata.confirm_id
        || locator.prior_sha256 != metadata.raw_sha256
        || locator.prior_source_sha256 != metadata.raw_source_sha256
    {
        return Err(invalid("locator and metadata linkage mismatch"));
    }
    Ok(())
}

fn validate_raw(bytes: &[u8], identity: FileIdentity, metadata: &Metadata) -> io::Result<()> {
    if bytes.len() as u64 != metadata.raw_length
        || identity.device != metadata.raw_device
        || identity.inode != metadata.raw_inode
        || <[u8; 32]>::from(Sha256::digest(bytes)) != metadata.raw_sha256
    {
        return Err(invalid("raw normalized-prior identity or digest mismatch"));
    }
    std::str::from_utf8(bytes).map_err(invalid)?;
    Ok(())
}

fn verify_snapshot(
    snapshot: &AcceptedConfigSnapshot,
    normalized_toml: &str,
    metadata: &Metadata,
) -> io::Result<()> {
    config_history::verify_retained_snapshot(
        snapshot,
        normalized_toml,
        &metadata.manifest,
        metadata.raw_source_sha256,
    )
    .map_err(invalid)
}

fn validate_confirm_id(value: &str) -> io::Result<()> {
    if value.trim().is_empty()
        || value.chars().count() > MAX_CONFIRM_ID_CHARS
        || value.chars().any(char::is_control)
    {
        return Err(invalid("invalid confirm id"));
    }
    Ok(())
}

#[derive(Debug)]
struct Directory {
    file: File,
    real_path: PathBuf,
}

impl Directory {
    fn pin(path: &Path) -> io::Result<Arc<Self>> {
        let directory = Self::pin_unchecked(path)?;
        directory.validate_private()?;
        Ok(directory)
    }

    fn pin_unchecked(path: &Path) -> io::Result<Arc<Self>> {
        use nix::fcntl::{OFlag, open};
        use nix::sys::stat::Mode;

        let real_path = std::fs::canonicalize(path)
            .map_err(|error| io::Error::new(error.kind(), "pending parent unavailable"))?;
        let fd = open(
            &real_path,
            OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
            Mode::empty(),
        )
        .map_err(errno)?;
        Ok(Arc::new(Self {
            file: File::from(fd),
            real_path,
        }))
    }

    fn validate_private(&self) -> io::Result<()> {
        use nix::unistd::geteuid;

        let metadata = self.file.metadata()?;
        if !metadata.is_dir()
            || metadata.uid() != geteuid().as_raw()
            || metadata.mode() & 0o022 != 0
        {
            return Err(invalid("unsafe pending parent owner, type, or mode"));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FileIdentity {
    device: u64,
    inode: u64,
}

impl FileIdentity {
    fn from_metadata(metadata: &std::fs::Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
        }
    }
}

#[derive(Debug)]
struct Entry {
    directory: Arc<Directory>,
    name: OsString,
}

struct EntryPublishError {
    error: io::Error,
    renamed: bool,
}

impl Entry {
    fn fixed(directory: Arc<Directory>, name: &str) -> Self {
        Self {
            directory,
            name: OsString::from(name),
        }
    }

    fn pin(path: &Path) -> io::Result<Self> {
        Self::pin_inner(path, true)
    }

    fn pin_for_absence(path: &Path) -> io::Result<Self> {
        Self::pin_inner(path, false)
    }

    fn pin_inner(path: &Path, private: bool) -> io::Result<Self> {
        let absolute = absolute_path(path)?;
        let name = absolute
            .file_name()
            .ok_or_else(|| invalid("pending file has no final component"))?
            .to_os_string();
        let parent = absolute
            .parent()
            .ok_or_else(|| invalid("pending file has no parent"))?;
        let directory = if private {
            Directory::pin(parent)?
        } else {
            Directory::pin_unchecked(parent)?
        };
        Ok(Self { directory, name })
    }

    fn absolute_path(&self) -> PathBuf {
        self.directory.real_path.join(&self.name)
    }

    fn stage_name(&self) -> io::Result<OsString> {
        append_name(&self.name, b".tmp")
    }

    fn exists(&self) -> io::Result<bool> {
        use nix::fcntl::AtFlags;
        use nix::sys::stat::fstatat;

        match fstatat(
            &self.directory.file,
            Path::new(&self.name),
            AtFlags::AT_SYMLINK_NOFOLLOW,
        ) {
            Ok(_) => Ok(true),
            Err(nix::errno::Errno::ENOENT) => Ok(false),
            Err(error) => Err(errno(error)),
        }
    }

    fn open_nofollow(&self) -> io::Result<File> {
        use nix::fcntl::{OFlag, openat};
        use nix::sys::stat::Mode;

        openat(
            &self.directory.file,
            Path::new(&self.name),
            OFlag::O_RDONLY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK,
            Mode::empty(),
        )
        .map(File::from)
        .map_err(errno)
    }

    fn read_bounded(&self, cap: usize) -> io::Result<(Vec<u8>, FileIdentity)> {
        let mut file = self.open_nofollow()?;
        let metadata = file.metadata()?;
        validate_file_metadata(&metadata, cap)?;
        let identity = FileIdentity::from_metadata(&metadata);
        Ok((read_opened(&mut file, &metadata, cap)?, identity))
    }

    fn read_exact_bounded(&self, declared: u64) -> io::Result<(Vec<u8>, FileIdentity)> {
        if declared > MAX_RAW_BYTES as u64 {
            return Err(limit("raw normalized prior", MAX_RAW_BYTES));
        }
        let mut file = self.open_nofollow()?;
        let metadata = file.metadata()?;
        validate_file_metadata(&metadata, MAX_RAW_BYTES)?;
        if metadata.len() != declared {
            return Err(invalid("raw normalized-prior declared length mismatch"));
        }
        let identity = FileIdentity::from_metadata(&metadata);
        Ok((read_opened(&mut file, &metadata, MAX_RAW_BYTES)?, identity))
    }

    fn publish_with(
        &self,
        bytes: &[u8],
        role: PublishRole,
        step: &mut impl FnMut(PublishStep) -> io::Result<()>,
    ) -> Result<FileIdentity, EntryPublishError> {
        use nix::fcntl::{OFlag, RenameFlags, openat, renameat2};
        use nix::sys::stat::{Mode, fchmod};

        let stage = self.stage_name().map_err(|error| EntryPublishError {
            error,
            renamed: false,
        })?;
        self.cleanup_stage().map_err(|error| EntryPublishError {
            error,
            renamed: false,
        })?;
        let stage_entry = Self {
            directory: Arc::clone(&self.directory),
            name: stage.clone(),
        };
        let fd = openat(
            &self.directory.file,
            Path::new(&stage),
            OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
            Mode::from_bits_truncate(0o600),
        )
        .map_err(|error| EntryPublishError {
            error: errno(error),
            renamed: false,
        })?;
        let mut file = File::from(fd);
        fchmod(&file, Mode::from_bits_truncate(0o600)).map_err(|error| EntryPublishError {
            error: errno(error),
            renamed: false,
        })?;
        let identity =
            FileIdentity::from_metadata(&file.metadata().map_err(|error| EntryPublishError {
                error,
                renamed: false,
            })?);
        let mut renamed = false;
        let result = (|| {
            file.write_all(bytes)?;
            step(PublishStep::for_role(role, 0))?;
            file.sync_all()?;
            drop(file);
            step(PublishStep::for_role(role, 1))?;
            renameat2(
                &self.directory.file,
                Path::new(&stage),
                &self.directory.file,
                Path::new(&self.name),
                RenameFlags::RENAME_NOREPLACE,
            )
            .map_err(errno)?;
            renamed = true;
            step(PublishStep::for_role(role, 2))?;
            self.directory.file.sync_all()
        })();
        if let Err(error) = result {
            let _ = stage_entry.remove_matching(identity);
            if !(role == PublishRole::Locator && renamed) {
                let _ = self.remove_matching(identity);
                let _ = self.directory.file.sync_all();
            }
            return Err(EntryPublishError { error, renamed });
        }
        Ok(identity)
    }

    fn replace(&self, bytes: &[u8]) -> io::Result<FileIdentity> {
        use nix::fcntl::{OFlag, openat, renameat};
        use nix::sys::stat::{Mode, fchmod};

        let stage = self.stage_name()?;
        self.cleanup_stage()?;
        let fd = openat(
            &self.directory.file,
            Path::new(&stage),
            OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
            Mode::from_bits_truncate(0o600),
        )
        .map_err(errno)?;
        let mut file = File::from(fd);
        fchmod(&file, Mode::from_bits_truncate(0o600)).map_err(errno)?;
        let identity = FileIdentity::from_metadata(&file.metadata()?);
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        renameat(
            &self.directory.file,
            Path::new(&stage),
            &self.directory.file,
            Path::new(&self.name),
        )
        .map_err(errno)?;
        self.directory.file.sync_all()?;
        Ok(identity)
    }

    fn cleanup_stage(&self) -> io::Result<()> {
        remove_named_safe(&self.directory.file, &self.stage_name()?)?;
        self.directory.file.sync_all()
    }

    fn remove_matching(&self, expected: FileIdentity) -> io::Result<()> {
        use nix::fcntl::AtFlags;
        use nix::sys::stat::{SFlag, fstatat};
        use nix::unistd::{UnlinkatFlags, geteuid, unlinkat};

        let stat = fstatat(
            &self.directory.file,
            Path::new(&self.name),
            AtFlags::AT_SYMLINK_NOFOLLOW,
        )
        .map_err(errno)?;
        if SFlag::from_bits_truncate(stat.st_mode) & SFlag::S_IFMT != SFlag::S_IFREG
            || stat.st_uid != geteuid().as_raw()
            || stat.st_mode & 0o7777 != 0o600
            || stat.st_dev as u64 != expected.device
            || stat.st_ino as u64 != expected.inode
        {
            return Err(invalid("pending file identity changed before cleanup"));
        }
        unlinkat(
            &self.directory.file,
            Path::new(&self.name),
            UnlinkatFlags::NoRemoveDir,
        )
        .map_err(errno)
    }

    fn verify_locator(&self, expected: &Locator) -> io::Result<()> {
        let (bytes, _) = self.read_bounded(MAX_LOCATOR_BYTES)?;
        if decode_locator(&bytes)? != *expected {
            return Err(invalid("published locator changed before cleanup"));
        }
        Ok(())
    }

    fn verify_metadata(&self, identity: FileIdentity, expected: &Metadata) -> io::Result<()> {
        let (bytes, actual) = self.read_bounded(MAX_METADATA_BYTES)?;
        if actual != identity || decode_metadata(&bytes)? != *expected {
            return Err(invalid("published metadata changed before cleanup"));
        }
        Ok(())
    }

    fn verify_raw(&self, identity: FileIdentity, metadata: &Metadata) -> io::Result<()> {
        let (bytes, actual) = self.read_exact_bounded(metadata.raw_length)?;
        validate_raw(&bytes, actual, metadata)?;
        if actual != identity {
            return Err(invalid("published raw object changed before cleanup"));
        }
        Ok(())
    }
}

fn cleanup_created(entry: &Entry, identity: FileIdentity) {
    let _ = entry.remove_matching(identity);
    let _ = entry.directory.file.sync_all();
}

fn cleanup_locator_absent_residue_pinned(pending: &Arc<Directory>) -> io::Result<()> {
    let metadata = Entry::fixed(Arc::clone(pending), METADATA_FILE_NAME);
    let raw = Entry::fixed(Arc::clone(pending), RAW_FILE_NAME);
    let metadata_read = metadata.read_bounded(MAX_METADATA_BYTES);
    match metadata_read {
        Ok((bytes, metadata_identity)) => {
            let wire = decode_metadata(&bytes)?;
            let (raw_bytes, raw_identity) = raw.read_exact_bounded(wire.raw_length)?;
            validate_raw(&raw_bytes, raw_identity, &wire)?;
            metadata.remove_matching(metadata_identity)?;
            raw.remove_matching(raw_identity)?;
            pending.file.sync_all()
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let (bytes, raw_identity) = match raw.read_bounded(MAX_RAW_BYTES) {
                Ok(found) => found,
                Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
                Err(error) => return Err(error),
            };
            let raw_toml = std::str::from_utf8(&bytes).map_err(invalid)?;
            let config =
                Config::load_toml_with_diagnostics(raw_toml, "v3 raw residue").map_err(invalid)?;
            let normalized = persisted_config_document(&config).map_err(invalid)?;
            if normalized.as_bytes() != bytes {
                return Err(invalid("raw residue is not normalized TOML"));
            }
            raw.remove_matching(raw_identity)?;
            pending.file.sync_all()
        }
        Err(error) => Err(error),
    }
}

fn remove_named_safe(directory: &File, name: &OsStr) -> io::Result<()> {
    use nix::fcntl::AtFlags;
    use nix::sys::stat::{SFlag, fstatat};
    use nix::unistd::{UnlinkatFlags, geteuid, unlinkat};

    let stat = match fstatat(directory, Path::new(name), AtFlags::AT_SYMLINK_NOFOLLOW) {
        Ok(stat) => stat,
        Err(nix::errno::Errno::ENOENT) => return Ok(()),
        Err(error) => return Err(errno(error)),
    };
    if SFlag::from_bits_truncate(stat.st_mode) & SFlag::S_IFMT != SFlag::S_IFREG
        || stat.st_uid != geteuid().as_raw()
        || stat.st_mode & 0o7777 != 0o600
    {
        return Err(invalid("unsafe exact pending residue"));
    }
    unlinkat(directory, Path::new(name), UnlinkatFlags::NoRemoveDir).map_err(errno)
}

fn validate_file_metadata(metadata: &std::fs::Metadata, cap: usize) -> io::Result<()> {
    use nix::unistd::geteuid;

    validate_file_metadata_values(
        metadata.is_file(),
        metadata.uid(),
        metadata.mode(),
        metadata.len(),
        cap,
        geteuid().as_raw(),
    )
}

fn validate_file_metadata_values(
    regular: bool,
    owner: u32,
    mode: u32,
    length: u64,
    cap: usize,
    expected_owner: u32,
) -> io::Result<()> {
    if !regular || owner != expected_owner || mode & 0o7777 != 0o600 || length > cap as u64 {
        return Err(invalid("unsafe pending file metadata"));
    }
    Ok(())
}

fn read_opened(file: &mut File, metadata: &std::fs::Metadata, cap: usize) -> io::Result<Vec<u8>> {
    file.rewind()?;
    let capacity = usize::try_from(metadata.len())
        .map_err(|_| invalid("pending file length does not fit this platform"))?;
    let mut bytes = Vec::with_capacity(capacity);
    file.take(cap as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 != metadata.len() || bytes.len() > cap {
        return Err(invalid("pending file changed while reading"));
    }
    Ok(bytes)
}

fn save_candidate_aside(target: &Entry, backup_name: &OsStr) -> io::Result<()> {
    use nix::fcntl::AtFlags;
    use nix::unistd::{UnlinkatFlags, linkat, unlinkat};

    match linkat(
        &target.directory.file,
        Path::new(&target.name),
        &target.directory.file,
        Path::new(backup_name),
        AtFlags::empty(),
    ) {
        Ok(()) => {
            unlinkat(
                &target.directory.file,
                Path::new(&target.name),
                UnlinkatFlags::NoRemoveDir,
            )
            .map_err(errno)?;
            target.directory.file.sync_all()
        }
        Err(nix::errno::Errno::EEXIST | nix::errno::Errno::ENOENT) => Ok(()),
        Err(error) => Err(errno(error)),
    }
}

fn verify_launch_target(launch: &Path, recorded: &Path) -> io::Result<()> {
    match resolve_launch_target(launch, false) {
        Ok(current) if current == recorded => Ok(()),
        Ok(_) => Err(invalid("launch config target changed")),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

fn resolve_launch_target(launch: &Path, require_present: bool) -> io::Result<PathBuf> {
    let parent = launch
        .parent()
        .ok_or_else(|| invalid("launch config has no parent"))?;
    let directory = Directory::pin(parent)?;
    let name = launch
        .file_name()
        .ok_or_else(|| invalid("launch config has no name"))?;
    match std::fs::canonicalize(launch) {
        Ok(target) => normalize_absolute(&target),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            use nix::fcntl::{AtFlags, readlinkat};
            use nix::sys::stat::{SFlag, fstatat};

            match fstatat(
                &directory.file,
                Path::new(name),
                AtFlags::AT_SYMLINK_NOFOLLOW,
            ) {
                Ok(stat)
                    if SFlag::from_bits_truncate(stat.st_mode) & SFlag::S_IFMT
                        == SFlag::S_IFLNK =>
                {
                    let link = readlinkat(&directory.file, Path::new(name)).map_err(errno)?;
                    let target = if Path::new(&link).is_absolute() {
                        PathBuf::from(link)
                    } else {
                        directory.real_path.join(link)
                    };
                    reject_ambiguous_terminal_path(&target)?;
                    canonicalize_allow_missing(&target)
                }
                Ok(_) => Err(invalid("launch config target is not resolvable")),
                Err(nix::errno::Errno::ENOENT) if !require_present => {
                    Err(io::Error::from(io::ErrorKind::NotFound))
                }
                Err(nix::errno::Errno::ENOENT) => {
                    Err(invalid("launch config is missing before confirmed apply"))
                }
                Err(error) => Err(errno(error)),
            }
        }
        Err(error) => Err(error),
    }
}

fn absolute_path(path: &Path) -> io::Result<PathBuf> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    reject_ambiguous_terminal_path(&absolute)?;
    normalize_absolute(&absolute)
}

fn canonicalize_allow_missing(path: &Path) -> io::Result<PathBuf> {
    let mut probe = path.to_path_buf();
    let mut missing = Vec::new();
    loop {
        match std::fs::canonicalize(&probe) {
            Ok(mut existing) => {
                for component in missing.iter().rev() {
                    existing.push(component);
                }
                return normalize_absolute(&existing);
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                missing.push(
                    probe
                        .file_name()
                        .ok_or_else(|| invalid("dangling launch target has no ancestor"))?
                        .to_os_string(),
                );
                if !probe.pop() {
                    return Err(invalid("dangling launch target escapes root"));
                }
            }
            Err(error) => return Err(error),
        }
    }
}

fn reject_ambiguous_terminal_path(path: &Path) -> io::Result<()> {
    let bytes = path.as_os_str().as_bytes();
    if bytes.ends_with(b"/") || bytes.ends_with(b"/.") || bytes.ends_with(b"/..") {
        return Err(invalid("pending path has no unambiguous final component"));
    }
    Ok(())
}

fn normalize_launch_path(path: &Path) -> io::Result<PathBuf> {
    if has_parent_dir(path) {
        return Err(invalid("launch config path contains ParentDir"));
    }
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::RootDir | Component::Prefix(_) | Component::Normal(_) => {
                out.push(component.as_os_str());
            }
            Component::CurDir => {}
            Component::ParentDir => unreachable!(),
        }
    }
    Ok(out)
}

fn normalize_absolute(path: &Path) -> io::Result<PathBuf> {
    if !path.is_absolute() {
        return Err(invalid("path is not absolute"));
    }
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::RootDir | Component::Prefix(_) | Component::Normal(_) => {
                out.push(component.as_os_str());
            }
            Component::CurDir => {}
            Component::ParentDir => {
                if !out.pop() {
                    return Err(invalid("path escapes root"));
                }
            }
        }
    }
    Ok(out)
}

fn has_parent_dir(path: &Path) -> bool {
    path.components()
        .any(|component| component == Component::ParentDir)
}

fn append_name(name: &OsStr, suffix: &[u8]) -> io::Result<OsString> {
    let mut bytes = name.as_bytes().to_vec();
    bytes.extend_from_slice(suffix);
    if bytes.contains(&0) || bytes.len() > MAX_PATH_BYTES {
        return Err(invalid("pending basename exceeds its bound"));
    }
    Ok(OsString::from_vec(bytes))
}

fn path_to_wire(path: &Path) -> io::Result<LosslessPath> {
    let bytes = path.as_os_str().as_bytes();
    if !path.is_absolute() || bytes.len() > MAX_PATH_BYTES || bytes.contains(&0) {
        return Err(invalid("pending path is not canonical"));
    }
    Ok(LosslessPath(bytes.to_vec()))
}

fn path_from_wire(path: &LosslessPath) -> io::Result<PathBuf> {
    if path.0.len() > MAX_PATH_BYTES || path.0.contains(&0) {
        return Err(invalid("encoded pending path is invalid"));
    }
    Ok(PathBuf::from(OsString::from_vec(path.0.clone())))
}

fn enforce_cap(name: &str, len: usize, cap: usize) -> io::Result<()> {
    if len > cap {
        return Err(limit(name, cap));
    }
    Ok(())
}

fn errno(error: nix::errno::Errno) -> io::Error {
    io::Error::from_raw_os_error(error as i32)
}

fn invalid(error: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error.to_string())
}

fn limit(name: &str, bytes: usize) -> io::Error {
    invalid(format!("{name} exceeds its {bytes}-byte limit"))
}

mod history_digest {
    use serde::{Deserialize, Deserializer, Serializer};

    pub(super) fn serialize<S: Serializer>(
        digest: &[u8; 32],
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&super::history_v2::encode_hex(digest))
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<[u8; 32], D::Error> {
        let value = String::deserialize(deserializer)?;
        if value.len() != 64
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(serde::de::Error::custom(
                "digest must be 64 lowercase hexadecimal characters",
            ));
        }
        let mut digest = [0u8; 32];
        for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
            let digit = |byte| {
                if byte <= b'9' {
                    byte - b'0'
                } else {
                    byte - b'a' + 10
                }
            };
            digest[index] = (digit(pair[0]) << 4) | digit(pair[1]);
        }
        Ok(digest)
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt as _;

    use super::*;
    use crate::test_support::tier_authorized_uds_test_config;

    fn private(path: &Path) {
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }

    fn config_toml(asn: u32) -> String {
        tier_authorized_uds_test_config(&format!(
            r#"
[global]
asn = {asn}
router_id = "192.0.2.1"
listen_port = 0
[global.telemetry]
log_format = "json"
"#
        ))
    }

    struct Fixture {
        _root: tempfile::TempDir,
        config: PathBuf,
        state: PathBuf,
        raw: PathBuf,
        metadata: PathBuf,
        launch: LaunchIdentity,
        prior: Arc<AcceptedConfigSnapshot>,
    }

    fn fixture() -> Fixture {
        let root = tempfile::tempdir().unwrap();
        private(root.path());
        let state = root.path().join("state");
        fs::create_dir(&state).unwrap();
        private(&state);
        let config = root.path().join("rustbgpd.toml");
        let parsed = Config::load_toml_with_diagnostics(&config_toml(64_512), "prior").unwrap();
        let prior = AcceptedConfigSnapshot::from_config_for_test(parsed);
        fs::write(&config, prior.normalized_toml()).unwrap();
        let launch = LaunchIdentity::resolve(&config).unwrap();
        Fixture {
            raw: state.join(RAW_FILE_NAME),
            metadata: state.join(METADATA_FILE_NAME),
            _root: root,
            config,
            state,
            launch,
            prior,
        }
    }

    #[test]
    fn all_nine_publication_boundaries_precede_candidate_work() {
        // Destructive proof: deleting any hook or reordering a layer makes its
        // named failure unexpectedly succeed or leaves a lower object behind.
        let steps = [
            PublishStep::RawStageSync,
            PublishStep::RawRename,
            PublishStep::RawDirectorySync,
            PublishStep::MetadataStageSync,
            PublishStep::MetadataRename,
            PublishStep::MetadataDirectorySync,
            PublishStep::LocatorStageSync,
            PublishStep::LocatorRename,
            PublishStep::LocatorDirectorySync,
        ];
        for failed in steps {
            let fixture = fixture();
            let before = fs::read(&fixture.config).unwrap();
            let error = fixture
                .launch
                .publish_with(&fixture.state, "deploy-1", 9, &fixture.prior, |step| {
                    if step == failed {
                        Err(io::Error::other("injected publish boundary"))
                    } else {
                        Ok(())
                    }
                })
                .unwrap_err();
            assert_eq!(fs::read(&fixture.config).unwrap(), before, "{failed:?}");
            if failed == PublishStep::LocatorDirectorySync {
                assert!(error.authority_retained());
                assert!(fixture.launch.locator_path().exists());
                assert!(fixture.raw.exists() && fixture.metadata.exists());
            } else {
                assert!(!error.authority_retained(), "{failed:?}");
                assert!(!fixture.launch.locator_path().exists(), "{failed:?}");
                assert!(!fixture.raw.exists(), "{failed:?}");
                assert!(!fixture.metadata.exists(), "{failed:?}");
            }
        }
    }

    #[test]
    fn publication_cleanup_never_deletes_a_replacement() {
        // Destructive proof: name-only cleanup removes `replacement` here.
        let fixture = fixture();
        let error = fixture
            .launch
            .publish_with(&fixture.state, "deploy-1", 9, &fixture.prior, |step| {
                if step == PublishStep::RawDirectorySync {
                    let displaced = fixture.state.join("displaced");
                    fs::rename(&fixture.raw, &displaced)?;
                    fs::write(&fixture.raw, b"replacement")?;
                    fs::set_permissions(&fixture.raw, fs::Permissions::from_mode(0o600))?;
                    return Err(io::Error::other("inject after replacement"));
                }
                Ok(())
            })
            .unwrap_err();
        assert!(!error.authority_retained());
        assert_eq!(fs::read(&fixture.raw).unwrap(), b"replacement");
    }

    #[test]
    fn file_metadata_and_raw_caps_are_exact() {
        // Destructive proof: changing `>` to `>=`, dropping owner/mode/type,
        // lifting the raw cap, or bypassing the shared prior-length predicate
        // changes one of these exact boundary verdicts without a huge allocation.
        assert!(normalized_prior_length_within_limit(
            MAX_RAW_BYTES,
            MAX_RAW_BYTES
        ));
        assert!(!normalized_prior_length_within_limit(
            MAX_RAW_BYTES + 1,
            MAX_RAW_BYTES
        ));
        let owner = nix::unistd::geteuid().as_raw();
        assert!(
            validate_file_metadata_values(
                true,
                owner,
                0o100_600,
                MAX_RAW_BYTES as u64,
                MAX_RAW_BYTES,
                owner
            )
            .is_ok()
        );
        assert!(
            validate_file_metadata_values(
                true,
                owner,
                0o100_600,
                MAX_RAW_BYTES as u64 + 1,
                MAX_RAW_BYTES,
                owner,
            )
            .is_err()
        );
        assert!(validate_file_metadata_values(false, owner, 0o100_600, 1, 1, owner).is_err());
        assert!(validate_file_metadata_values(true, owner + 1, 0o100_600, 1, 1, owner).is_err());
        assert!(validate_file_metadata_values(true, owner, 0o100_640, 1, 1, owner).is_err());
    }

    #[test]
    fn every_corrupt_or_unsafe_layer_fails_before_candidate_access() {
        // Destructive proof: weakening mode, length, identity, digest, or
        // linkage validation lets the candidate move into `.unconfirmed`.
        for mutation in [
            "raw_mode",
            "raw_truncate",
            "raw_growth",
            "raw_digest",
            "raw_special",
            "metadata_identity",
            "metadata_provenance",
            "metadata_corrupt",
            "locator_linkage",
        ] {
            let fixture = fixture();
            fixture
                .launch
                .publish(&fixture.state, "deploy-1", 9, &fixture.prior)
                .unwrap();
            let candidate = b"unconfirmed candidate";
            fs::write(&fixture.config, candidate).unwrap();
            match mutation {
                "raw_mode" => {
                    fs::set_permissions(&fixture.raw, fs::Permissions::from_mode(0o640)).unwrap();
                }
                "raw_truncate" => {
                    let bytes = fs::read(&fixture.raw).unwrap();
                    fs::write(&fixture.raw, &bytes[..bytes.len() - 1]).unwrap();
                }
                "raw_growth" => fs::OpenOptions::new()
                    .append(true)
                    .open(&fixture.raw)
                    .unwrap()
                    .write_all(b"x")
                    .unwrap(),
                "raw_digest" => {
                    let mut bytes = fs::read(&fixture.raw).unwrap();
                    bytes[0] ^= 1;
                    fs::write(&fixture.raw, bytes).unwrap();
                }
                "raw_special" => {
                    fs::remove_file(&fixture.raw).unwrap();
                    fs::create_dir(&fixture.raw).unwrap();
                }
                "metadata_identity" => {
                    let mut wire = decode_metadata(&fs::read(&fixture.metadata).unwrap()).unwrap();
                    wire.raw_inode = wire.raw_inode.wrapping_add(1);
                    fs::write(&fixture.metadata, encode_metadata(&wire).unwrap()).unwrap();
                }
                "metadata_provenance" => {
                    let mut wire = decode_metadata(&fs::read(&fixture.metadata).unwrap()).unwrap();
                    wire.raw_source_sha256[0] ^= 1;
                    fs::write(&fixture.metadata, serde_json::to_vec(&wire).unwrap()).unwrap();
                }
                "metadata_corrupt" => fs::write(&fixture.metadata, b"{\"version\":3,").unwrap(),
                "locator_linkage" => {
                    let path = fixture.launch.locator_path();
                    let mut wire = decode_locator(&fs::read(&path).unwrap()).unwrap();
                    wire.confirm_id = "other".to_string();
                    fs::write(path, encode_locator(&wire).unwrap()).unwrap();
                }
                _ => unreachable!(),
            }
            assert!(fixture.launch.boot_revert_check().is_err(), "{mutation}");
            assert_eq!(fs::read(&fixture.config).unwrap(), candidate, "{mutation}");
            assert!(!fixture.config.with_extension("toml.unconfirmed").exists());
        }
    }

    #[test]
    fn rollback_failed_replaces_only_metadata_and_boot_restores() {
        // Destructive proof: embedding the bit in raw or binding metadata
        // identity in the locator changes the asserted inode/bytes or fails boot.
        let fixture = fixture();
        let files = fixture
            .launch
            .publish(&fixture.state, "deploy-1", 9, &fixture.prior)
            .unwrap();
        let raw_before = fs::read(&fixture.raw).unwrap();
        let raw_identity = FileIdentity::from_metadata(&fs::metadata(&fixture.raw).unwrap());
        let metadata_identity =
            FileIdentity::from_metadata(&fs::metadata(&fixture.metadata).unwrap());
        files.record_rollback_failed().unwrap();
        assert_eq!(fs::read(&fixture.raw).unwrap(), raw_before);
        assert_eq!(
            FileIdentity::from_metadata(&fs::metadata(&fixture.raw).unwrap()),
            raw_identity
        );
        assert_ne!(
            FileIdentity::from_metadata(&fs::metadata(&fixture.metadata).unwrap()),
            metadata_identity
        );
        fs::write(&fixture.config, b"candidate").unwrap();
        let reverted = fixture.launch.boot_revert_check().unwrap().unwrap();
        assert!(reverted.notice.rollback_failed);
        assert_eq!(
            reverted.accepted.normalized_toml(),
            fixture.prior.normalized_toml()
        );
    }

    #[test]
    fn restart_states_are_idempotent_and_locator_absence_never_rearms() {
        // Candidate hard-link/unlink completed, restore not yet started.
        let save_crash = fixture();
        save_crash
            .launch
            .publish(&save_crash.state, "save-crash", 9, &save_crash.prior)
            .unwrap();
        fs::write(&save_crash.config, b"candidate-one").unwrap();
        assert!(
            save_crash
                .launch
                .boot_revert_check_io_with(|step| {
                    if step == BootStep::ConfigRestore {
                        Err(io::Error::other("crash before restore"))
                    } else {
                        Ok(())
                    }
                })
                .is_err()
        );
        assert!(!save_crash.config.exists());
        assert!(
            save_crash
                .config
                .with_extension("toml.unconfirmed")
                .exists()
        );
        assert!(save_crash.launch.boot_revert_check().unwrap().is_some());
        assert!(save_crash.launch.boot_revert_check().unwrap().is_none());

        // Restore landed but locator unlink did not: next boot safely repeats.
        let restore_crash = fixture();
        restore_crash
            .launch
            .publish(
                &restore_crash.state,
                "restore-crash",
                9,
                &restore_crash.prior,
            )
            .unwrap();
        fs::write(&restore_crash.config, b"candidate-two").unwrap();
        assert!(
            restore_crash
                .launch
                .boot_revert_check_io_with(|step| {
                    if step == BootStep::LocatorUnlink {
                        Err(io::Error::other("crash before locator unlink"))
                    } else {
                        Ok(())
                    }
                })
                .is_err()
        );
        assert!(restore_crash.launch.locator_path().exists());
        assert!(restore_crash.launch.boot_revert_check().unwrap().is_some());

        // Locator unlink landed but its directory sync did not. Both crash
        // outcomes are safe: if absent, residue is ignored and never re-arms.
        let unlink_crash = fixture();
        unlink_crash
            .launch
            .publish(&unlink_crash.state, "unlink-crash", 9, &unlink_crash.prior)
            .unwrap();
        fs::write(&unlink_crash.config, b"candidate-three").unwrap();
        assert!(
            unlink_crash
                .launch
                .boot_revert_check_io_with(|step| {
                    if step == BootStep::LocatorDirectorySync {
                        Err(io::Error::other("crash after locator unlink"))
                    } else {
                        Ok(())
                    }
                })
                .is_err()
        );
        assert!(!unlink_crash.launch.locator_path().exists());
        assert!(unlink_crash.raw.exists() && unlink_crash.metadata.exists());
        assert!(unlink_crash.launch.boot_revert_check().unwrap().is_none());
        assert!(unlink_crash.raw.exists() && unlink_crash.metadata.exists());
    }

    #[test]
    fn v3_dispatch_preserves_frozen_v1_and_v2_authority() {
        // V1 bytes remain untouched without a locator.
        let v1_fixture = fixture();
        let legacy = v1_fixture
            .state
            .join(crate::confirm_journal::JOURNAL_FILE_NAME);
        fs::write(
            &legacy,
            b"{\"confirm_id\":\"v1\",\"deadline_unix_seconds\":9,\"rollback_toml\":\"x\"}",
        )
        .unwrap();
        assert!(v1_fixture.launch.boot_revert_check().unwrap().is_none());
        assert!(legacy.exists());

        // A canonical v2 locator is handed to the frozen v2 reader unchanged.
        let v2_fixture = fixture();
        let v2_journal = v2_fixture
            .state
            .join(crate::confirm_journal::JOURNAL_FILE_NAME);
        let v2 = crate::confirm_journal::v2::LaunchIdentity::resolve(&v2_fixture.config).unwrap();
        v2.publish(&v2_journal, "v2", 9, &v2_fixture.prior).unwrap();
        assert!(v2_fixture.launch.boot_revert_check().unwrap().is_none());
        fs::write(&v2_fixture.config, b"v2 candidate").unwrap();
        assert!(v2.boot_revert_check().unwrap().is_some());
    }
}
