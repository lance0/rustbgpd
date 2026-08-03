//! ADR-0121 v2 commit-confirm authority.
//!
//! The config-adjacent locator is the only v2 boot authority.  Both it and
//! the provenance-bearing journal are opened, read, published, and removed
//! relative to pinned private directory descriptors.  Paths retained in the
//! wire records are deliberately never included in returned errors.

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

use crate::config::AcceptedConfigSnapshot;
use crate::config_history;
use crate::config_history::v2::{self as history_v2, LosslessPath, Manifest};

const VERSION: u32 = 2;
const MAX_CONFIRM_ID_CHARS: usize = 128;
const MAX_JOURNAL_BYTES: usize = 34 * 1024 * 1024;
const MAX_LOCATOR_BYTES: usize = 512 * 1024;
const MAX_PATH_BYTES: usize = 64 * 1024;
const LOCATOR_SUFFIX: &str = ".commit-confirm-locator.json";

pub(crate) enum LocatorAbsentJournal {
    Absent,
    LegacyV1,
    V2ResidueRemoved,
}

/// Dispatch the candidate-derived legacy journal only after locator absence
/// has already been established.  A canonical v2 object has no authority in
/// this lane and is removed durably; it is never converted into pending state.
pub(crate) fn inspect_locator_absent_journal(path: &Path) -> io::Result<LocatorAbsentJournal> {
    // V1 deliberately retains its historical path/metadata behavior.  This
    // dispatcher pins only the containing directory, then uses one no-follow
    // descriptor to classify, validate, read, and (for canonical v2 residue)
    // remove the same inode.  A non-v2 object is never cleaned here.
    match std::fs::symlink_metadata(path) {
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Ok(LocatorAbsentJournal::Absent);
        }
        Err(error) => return Err(error),
    }
    let entry = Entry::pin_for_legacy_dispatch(path)?;
    entry.inspect_locator_absent()
}

/// Stable lexical identity of the launch argument.  It is resolved before a
/// daemon boot opens the candidate config and is also retained by the live
/// transaction controller; reloads cannot replace it.
#[derive(Clone, Debug)]
pub(crate) struct LaunchIdentity {
    lexical_config: PathBuf,
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
        Ok(Self { lexical_config })
    }

    pub(crate) fn locator_path(&self) -> PathBuf {
        let mut bytes = self.lexical_config.as_os_str().as_bytes().to_vec();
        bytes.extend_from_slice(LOCATOR_SUFFIX.as_bytes());
        PathBuf::from(OsString::from_vec(bytes))
    }

    /// Inspect v2 authority before candidate config access.  `Ok(None)` means
    /// the locator is absent and the caller may proceed to the legacy lane.
    pub(crate) fn boot_revert_check(&self) -> Result<Option<BootRevert>, String> {
        self.boot_revert_check_io().map_err(|error| {
            format!(
                "v2 commit-confirm boot authority is invalid or unavailable ({:?}); inspect the config-adjacent locator and owner-only pending files",
                error.kind()
            )
        })
    }

    fn boot_revert_check_io(&self) -> io::Result<Option<BootRevert>> {
        self.boot_revert_check_io_with(|_| Ok(()))
    }

    fn boot_revert_check_io_with(
        &self,
        step: impl FnMut(BootStep) -> io::Result<()>,
    ) -> io::Result<Option<BootRevert>> {
        self.boot_revert_check_io_with_limits(MAX_LOCATOR_BYTES, MAX_JOURNAL_BYTES, step)
    }

    fn boot_revert_check_io_with_limits(
        &self,
        max_locator_bytes: usize,
        max_journal_bytes: usize,
        mut step: impl FnMut(BootStep) -> io::Result<()>,
    ) -> io::Result<Option<BootRevert>> {
        // The packaged SIGHUP-only deployment intentionally keeps
        // /etc/rustbgpd root-owned and read-only to the daemon.  Establishing
        // locator absence there must not make an ordinary boot depend on
        // daemon ownership.  The parent still cannot admit untrusted writers;
        // any present locator is subject to the full owner-private contract.
        let locator = Entry::pin_for_absence(&self.locator_path())?;
        locator.directory.validate_no_untrusted_writers()?;
        if !locator.exists()? {
            return Ok(None);
        }
        locator.directory.validate_private()?;
        let (locator_bytes, locator_identity) =
            locator.read_bounded_identified(max_locator_bytes)?;
        let wire = decode_locator_with_cap(&locator_bytes, max_locator_bytes)?;

        let journal_path = path_from_wire(&wire.journal_path)?;
        let journal = Entry::pin(&journal_path)?;
        if journal.absolute_path_bytes() != journal_path.as_os_str().as_bytes() {
            return Err(invalid("journal identity is not canonical"));
        }
        let (journal_bytes, journal_identity) =
            journal.read_bounded_identified(max_journal_bytes)?;
        let journal_wire = decode_journal_with_cap(&journal_bytes, max_journal_bytes)?;
        validate_locator_journal(&wire, &journal_wire, &journal)?;

        let recorded_target = path_from_wire(&wire.config_target)?;
        verify_launch_target(&self.lexical_config, &recorded_target)?;
        let target = Entry::pin(&recorded_target)?;

        // Provenance is verified before the candidate, backup slot, locator,
        // or journal is changed.  This returned Arc is the one boot adopts.
        let accepted = AcceptedConfigSnapshot::load_retained(
            &journal_wire.prior.normalized_toml,
            &recorded_target,
        )
        .map_err(|_| invalid("journaled prior sources are unavailable or changed"))?;
        verify_prior_snapshot(&accepted, &journal_wire.prior)?;

        let backup_name = append_name(&target.name, b".unconfirmed")?;
        step(BootStep::CandidateSave)?;
        save_candidate_aside(&target, &backup_name)?;
        step(BootStep::ConfigRestore)?;
        target.replace(journal_wire.prior.normalized_toml.as_bytes())?;

        // Durable locator absence is terminal.  Journal cleanup happens only
        // afterwards and cannot make the completed revert fail or re-arm it.
        step(BootStep::LocatorUnlink)?;
        locator.remove_matching(locator_identity)?;
        step(BootStep::LocatorDirectorySync)?;
        locator.directory.file.sync_all()?;
        let journal_cleanup_failed = (|| {
            step(BootStep::JournalUnlink)?;
            journal.remove_matching(journal_identity)?;
            step(BootStep::JournalDirectorySync)?;
            journal.directory.file.sync_all()
        })()
        .is_err();
        Ok(Some(BootRevert {
            accepted,
            notice: BootRevertNotice {
                confirm_id: journal_wire.confirm_id,
                rollback_failed: journal_wire.rollback_failed,
                journal_cleanup_failed,
            },
        }))
    }

    /// Publish a complete v2 pending authority.  Both encodings are completed
    /// before any stage exists, then journal durability precedes locator
    /// durability.  The caller may mutate the candidate only after success.
    pub(crate) fn publish(
        &self,
        journal_path: &Path,
        confirm_id: &str,
        deadline_unix_seconds: u64,
        prior: &AcceptedConfigSnapshot,
    ) -> io::Result<PendingFiles> {
        self.publish_with(
            journal_path,
            confirm_id,
            deadline_unix_seconds,
            prior,
            |_| Ok(()),
        )
    }

    fn publish_with(
        &self,
        journal_path: &Path,
        confirm_id: &str,
        deadline_unix_seconds: u64,
        prior: &AcceptedConfigSnapshot,
        mut step: impl FnMut(PublishStep) -> io::Result<()>,
    ) -> io::Result<PendingFiles> {
        let locator = Entry::pin(&self.locator_path())?;
        if locator.exists()? {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "v2 commit-confirm locator is already present",
            ));
        }
        let journal_path = absolute_path(journal_path)?;
        let journal = Entry::pin(&journal_path)?;
        let journal_path = journal.absolute_path();
        let config_target = resolve_launch_target(&self.lexical_config, true)?;
        // A published transaction must be boot-revertible.  Pin and validate
        // the resolved target parent now, not for the first time after a crash.
        let config_target = Entry::pin(&config_target)?.absolute_path();
        let prior_wire = Prior::from_snapshot(prior);
        let journal_wire = Journal {
            version: VERSION,
            confirm_id: confirm_id.to_string(),
            deadline_unix_seconds,
            rollback_failed: false,
            prior: prior_wire.clone(),
        };
        let journal_bytes = encode_journal(&journal_wire)?;
        let locator_wire = Locator {
            version: VERSION,
            confirm_id: confirm_id.to_string(),
            journal_path: path_to_wire(&journal_path)?,
            config_target: path_to_wire(&config_target)?,
            prior_sha256: prior_wire.sha256,
            prior_source_sha256: prior_wire.source_sha256,
        };
        let locator_bytes = encode_locator(&locator_wire)?;

        // Exact safe residue only.  No directory scan or suffix cleanup is
        // permitted, and an unsafe object obstructs the new apply.
        locator.cleanup_stage()?;
        journal.cleanup_stage()?;
        journal.remove_canonical_v2_residue()?;
        let journal_identity =
            journal.publish_with(&journal_bytes, false, PublishRole::Journal, &mut step)?;
        let locator_identity =
            match locator.publish_with(&locator_bytes, false, PublishRole::Locator, &mut step) {
                Ok(identity) => identity,
                Err(error) => {
                    let _ =
                        journal.remove_matching_canonical_journal(journal_identity, &journal_wire);
                    let _ = journal.directory.file.sync_all();
                    return Err(error);
                }
            };
        Ok(PendingFiles {
            locator,
            journal,
            state: Mutex::new(PendingState {
                locator_wire,
                locator_identity,
                journal_wire,
                journal_identity,
                locator_phase: CleanupPhase::Published,
                journal_phase: CleanupPhase::Published,
            }),
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BootStep {
    CandidateSave,
    ConfigRestore,
    LocatorUnlink,
    LocatorDirectorySync,
    JournalUnlink,
    JournalDirectorySync,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PublishRole {
    Journal,
    Locator,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PublishStep {
    JournalStageSync,
    JournalRename,
    JournalDirectorySync,
    LocatorStageSync,
    LocatorRename,
    LocatorDirectorySync,
}

impl PublishStep {
    const fn for_role(role: PublishRole, ordinal: u8) -> Self {
        match (role, ordinal) {
            (PublishRole::Journal, 0) => Self::JournalStageSync,
            (PublishRole::Journal, 1) => Self::JournalRename,
            (PublishRole::Journal, 2) => Self::JournalDirectorySync,
            (PublishRole::Locator, 0) => Self::LocatorStageSync,
            (PublishRole::Locator, 1) => Self::LocatorRename,
            (PublishRole::Locator, 2) => Self::LocatorDirectorySync,
            _ => unreachable!(),
        }
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
    pub(crate) journal_cleanup_failed: bool,
}

/// Descriptor-pinned files for one live pending v2 transaction.
#[derive(Debug)]
pub(crate) struct PendingFiles {
    locator: Entry,
    journal: Entry,
    state: Mutex<PendingState>,
}

#[derive(Debug)]
struct PendingState {
    locator_wire: Locator,
    locator_identity: FileIdentity,
    journal_wire: Journal,
    journal_identity: FileIdentity,
    locator_phase: CleanupPhase,
    journal_phase: CleanupPhase,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CleanupPhase {
    Published,
    Unlinked,
    Synced,
}

impl PendingFiles {
    /// Remove and sync the locator first.  Once this succeeds the candidate is
    /// permanent (or the revert terminal); journal cleanup is warning-only.
    pub(crate) fn terminal_cleanup(&self) -> io::Result<bool> {
        self.terminal_cleanup_with(|_| Ok(()))
    }

    fn terminal_cleanup_with(
        &self,
        mut step: impl FnMut(TerminalStep) -> io::Result<()>,
    ) -> io::Result<bool> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| invalid("pending cleanup state is unavailable"))?;
        if state.locator_phase == CleanupPhase::Published {
            step(TerminalStep::LocatorUnlink)?;
            self.locator
                .remove_matching_canonical_locator(state.locator_identity, &state.locator_wire)?;
            state.locator_phase = CleanupPhase::Unlinked;
        }
        if state.locator_phase == CleanupPhase::Unlinked {
            step(TerminalStep::LocatorDirectorySync)?;
            self.locator.directory.file.sync_all()?;
            state.locator_phase = CleanupPhase::Synced;
        }

        let journal_result: io::Result<()> = (|| {
            if state.journal_phase == CleanupPhase::Published {
                step(TerminalStep::JournalUnlink)?;
                self.journal.remove_matching_canonical_journal(
                    state.journal_identity,
                    &state.journal_wire,
                )?;
                state.journal_phase = CleanupPhase::Unlinked;
            }
            if state.journal_phase == CleanupPhase::Unlinked {
                step(TerminalStep::JournalDirectorySync)?;
                self.journal.directory.file.sync_all()?;
                state.journal_phase = CleanupPhase::Synced;
            }
            Ok(())
        })();
        Ok(journal_result.is_err())
    }

    /// Persist the diagnostic rollback-failed bit without changing authority.
    /// Atomic replacement leaves either the old or new complete journal.
    pub(crate) fn record_rollback_failed(&self) -> io::Result<()> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| invalid("pending journal state is unavailable"))?;
        if state.locator_phase != CleanupPhase::Published
            || state.journal_phase != CleanupPhase::Published
        {
            return Err(invalid("pending journal cleanup has already started"));
        }
        self.journal
            .verify_matching_canonical_journal(state.journal_identity, &state.journal_wire)?;
        let mut journal_wire = state.journal_wire.clone();
        journal_wire.rollback_failed = true;
        let bytes = encode_journal(&journal_wire)?;
        let identity = self.journal.publish(&bytes, true)?;
        state.journal_wire = journal_wire;
        state.journal_identity = identity;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TerminalStep {
    LocatorUnlink,
    LocatorDirectorySync,
    JournalUnlink,
    JournalDirectorySync,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    version: u32,
    confirm_id: String,
    deadline_unix_seconds: u64,
    rollback_failed: bool,
    prior: Prior,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Prior {
    #[serde(with = "history_digest")]
    sha256: [u8; 32],
    #[serde(with = "history_digest")]
    source_sha256: [u8; 32],
    normalized_toml: String,
    manifest: Manifest,
}

impl Prior {
    fn from_snapshot(snapshot: &AcceptedConfigSnapshot) -> Self {
        let manifest = config_history::stored_manifest(snapshot);
        Self {
            sha256: manifest.toml_sha256,
            source_sha256: snapshot.source_sha256(),
            normalized_toml: snapshot.normalized_toml().to_string(),
            manifest,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Locator {
    version: u32,
    confirm_id: String,
    journal_path: LosslessPath,
    config_target: LosslessPath,
    #[serde(with = "history_digest")]
    prior_sha256: [u8; 32],
    #[serde(with = "history_digest")]
    prior_source_sha256: [u8; 32],
}

fn encode_journal(journal: &Journal) -> io::Result<Vec<u8>> {
    encode_journal_with_cap(journal, MAX_JOURNAL_BYTES)
}

fn encode_journal_with_cap(journal: &Journal, max_bytes: usize) -> io::Result<Vec<u8>> {
    validate_journal(journal)?;
    let mut bytes = serde_json::to_vec(journal).map_err(invalid)?;
    bytes.push(b'\n');
    if !bytes.starts_with(b"{\"version\":2,") {
        return Err(invalid("v2 journal dispatch prefix changed"));
    }
    enforce_total_cap("journal", bytes.len(), max_bytes)?;
    Ok(bytes)
}

fn decode_journal(bytes: &[u8]) -> io::Result<Journal> {
    decode_journal_with_cap(bytes, MAX_JOURNAL_BYTES)
}

fn decode_journal_with_cap(bytes: &[u8], max_bytes: usize) -> io::Result<Journal> {
    enforce_total_cap("journal", bytes.len(), max_bytes)?;
    if !bytes.starts_with(b"{\"version\":2,") {
        return Err(invalid("journal is not canonical v2"));
    }
    let journal: Journal = serde_json::from_slice(bytes).map_err(invalid)?;
    validate_journal(&journal)?;
    if encode_journal(&journal)? != bytes {
        return Err(invalid("non-canonical v2 journal"));
    }
    Ok(journal)
}

fn validate_journal(journal: &Journal) -> io::Result<()> {
    if journal.version != VERSION {
        return Err(invalid("unsupported journal version"));
    }
    validate_confirm_id(&journal.confirm_id)?;
    validate_prior(&journal.prior)
}

fn validate_prior(prior: &Prior) -> io::Result<()> {
    if prior.normalized_toml.len() > history_v2::MAX_TOML {
        return Err(limit("normalized TOML", history_v2::MAX_TOML));
    }
    let actual: [u8; 32] = Sha256::digest(prior.normalized_toml.as_bytes()).into();
    if prior.sha256 != actual || prior.manifest.toml_sha256 != actual {
        return Err(invalid("prior TOML digest mismatch"));
    }
    history_v2::validate_manifest(&prior.manifest)?;
    if prior.source_sha256 != history_v2::manifest_source_sha256(&prior.manifest) {
        return Err(invalid("prior source digest mismatch"));
    }
    Ok(())
}

fn verify_prior_snapshot(snapshot: &AcceptedConfigSnapshot, prior: &Prior) -> io::Result<()> {
    config_history::verify_retained_snapshot(
        snapshot,
        &prior.normalized_toml,
        &prior.manifest,
        prior.source_sha256,
    )
    .map_err(invalid)
}

fn encode_locator(locator: &Locator) -> io::Result<Vec<u8>> {
    encode_locator_with_cap(locator, MAX_LOCATOR_BYTES)
}

fn encode_locator_with_cap(locator: &Locator, max_bytes: usize) -> io::Result<Vec<u8>> {
    validate_locator(locator)?;
    let mut bytes = serde_json::to_vec(locator).map_err(invalid)?;
    bytes.push(b'\n');
    enforce_total_cap("locator", bytes.len(), max_bytes)?;
    Ok(bytes)
}

fn decode_locator(bytes: &[u8]) -> io::Result<Locator> {
    decode_locator_with_cap(bytes, MAX_LOCATOR_BYTES)
}

fn decode_locator_with_cap(bytes: &[u8], max_bytes: usize) -> io::Result<Locator> {
    enforce_total_cap("locator", bytes.len(), max_bytes)?;
    let locator: Locator = serde_json::from_slice(bytes).map_err(invalid)?;
    validate_locator(&locator)?;
    if encode_locator(&locator)? != bytes {
        return Err(invalid("non-canonical v2 locator"));
    }
    Ok(locator)
}

fn validate_locator(locator: &Locator) -> io::Result<()> {
    if locator.version != VERSION {
        return Err(invalid("unsupported locator version"));
    }
    validate_confirm_id(&locator.confirm_id)?;
    for path in [&locator.journal_path, &locator.config_target] {
        if path.0.len() > MAX_PATH_BYTES {
            return Err(limit("locator path", MAX_PATH_BYTES));
        }
        let decoded = path_from_wire(path)?;
        if !decoded.is_absolute() || has_parent_dir(&decoded) {
            return Err(invalid("locator path is not absolute and lexical"));
        }
    }
    Ok(())
}

fn validate_locator_journal(
    locator: &Locator,
    journal: &Journal,
    journal_entry: &Entry,
) -> io::Result<()> {
    if locator.confirm_id != journal.confirm_id
        || locator.prior_sha256 != journal.prior.sha256
        || locator.prior_source_sha256 != journal.prior.source_sha256
        || path_from_wire(&locator.journal_path)?
            .as_os_str()
            .as_bytes()
            != journal_entry.absolute_path_bytes()
    {
        return Err(invalid("locator and journal identity mismatch"));
    }
    Ok(())
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

fn enforce_total_cap(name: &str, len: usize, cap: usize) -> io::Result<()> {
    if len > cap {
        return Err(limit(name, cap));
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

    /// Pin a directory without applying v2 ownership/mode policy.  This exists
    /// only to classify locator-free legacy journals without changing the v1
    /// compatibility lane; any v2 read or cleanup validates the pinned
    /// descriptor before proceeding.
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
        let file = File::from(fd);
        Ok(Arc::new(Self { file, real_path }))
    }

    fn validate_private(&self) -> io::Result<()> {
        use nix::unistd::geteuid;

        let metadata = self.file.metadata()?;
        validate_directory_metadata_values(
            metadata.is_dir(),
            metadata.uid(),
            metadata.mode(),
            geteuid().as_raw(),
            true,
        )
    }

    fn validate_no_untrusted_writers(&self) -> io::Result<()> {
        use nix::unistd::geteuid;

        let metadata = self.file.metadata()?;
        validate_directory_metadata_values(
            metadata.is_dir(),
            metadata.uid(),
            metadata.mode(),
            geteuid().as_raw(),
            false,
        )
    }
}

fn validate_directory_metadata_values(
    is_dir: bool,
    owner: u32,
    mode: u32,
    expected_owner: u32,
    require_owner: bool,
) -> io::Result<()> {
    if !is_dir || mode & 0o022 != 0 || require_owner && owner != expected_owner {
        if require_owner {
            return Err(invalid(format!(
                "unsafe pending parent owner, type, or mode (dir={}, owner_match={}, mode={:o})",
                is_dir,
                owner == expected_owner,
                mode & 0o7777
            )));
        }
        return Err(invalid(format!(
            "unsafe pending parent type or mode (dir={}, mode={:o})",
            is_dir,
            mode & 0o7777
        )));
    }
    Ok(())
}

fn validate_pending_metadata(metadata: &std::fs::Metadata, cap: usize) -> io::Result<()> {
    use nix::unistd::geteuid;

    validate_pending_metadata_values(
        metadata.is_file(),
        metadata.uid(),
        metadata.mode(),
        metadata.len(),
        cap,
        geteuid().as_raw(),
    )
}

fn validate_pending_metadata_values(
    is_file: bool,
    owner: u32,
    mode: u32,
    len: u64,
    cap: usize,
    expected_owner: u32,
) -> io::Result<()> {
    if !is_file || owner != expected_owner || mode & 0o7777 != 0o600 || len > cap as u64 {
        return Err(invalid("unsafe pending file metadata"));
    }
    Ok(())
}

fn read_opened_bounded(
    file: &mut File,
    metadata: &std::fs::Metadata,
    cap: usize,
) -> io::Result<Vec<u8>> {
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

impl Entry {
    fn pin(path: &Path) -> io::Result<Self> {
        let absolute = absolute_path(path)?;
        let name = absolute
            .file_name()
            .ok_or_else(|| invalid("pending file has no final component"))?
            .to_os_string();
        let parent = absolute
            .parent()
            .ok_or_else(|| invalid("pending file has no parent"))?;
        Ok(Self {
            directory: Directory::pin(parent)?,
            name,
        })
    }

    fn pin_for_legacy_dispatch(path: &Path) -> io::Result<Self> {
        Self::pin_without_owner_check(path)
    }

    fn pin_for_absence(path: &Path) -> io::Result<Self> {
        Self::pin_without_owner_check(path)
    }

    fn pin_without_owner_check(path: &Path) -> io::Result<Self> {
        let absolute = absolute_path(path)?;
        let name = absolute
            .file_name()
            .ok_or_else(|| invalid("pending file has no final component"))?
            .to_os_string();
        let parent = absolute
            .parent()
            .ok_or_else(|| invalid("pending file has no parent"))?;
        Ok(Self {
            directory: Directory::pin_unchecked(parent)?,
            name,
        })
    }

    fn stage_name(&self) -> io::Result<OsString> {
        append_name(&self.name, b".tmp")
    }

    fn absolute_path(&self) -> PathBuf {
        self.directory.real_path.join(&self.name)
    }

    fn absolute_path_bytes(&self) -> Vec<u8> {
        self.absolute_path().as_os_str().as_bytes().to_vec()
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

    fn read_bounded_identified(&self, cap: usize) -> io::Result<(Vec<u8>, FileIdentity)> {
        self.read_bounded_identified_with(cap, || Ok(()))
    }

    fn read_bounded_identified_with(
        &self,
        cap: usize,
        after_check: impl FnOnce() -> io::Result<()>,
    ) -> io::Result<(Vec<u8>, FileIdentity)> {
        let mut file = self.open_nofollow()?;
        let metadata = file.metadata()?;
        validate_pending_metadata(&metadata, cap)?;
        let identity = FileIdentity::from_metadata(&metadata);
        after_check()?;
        Ok((read_opened_bounded(&mut file, &metadata, cap)?, identity))
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

    fn inspect_locator_absent(&self) -> io::Result<LocatorAbsentJournal> {
        self.inspect_locator_absent_with(|| Ok(()))
    }

    fn inspect_locator_absent_with(
        &self,
        after_prefix: impl FnOnce() -> io::Result<()>,
    ) -> io::Result<LocatorAbsentJournal> {
        use nix::fcntl::AtFlags;
        use nix::sys::stat::{SFlag, fstatat};

        let stat = match fstatat(
            &self.directory.file,
            Path::new(&self.name),
            AtFlags::AT_SYMLINK_NOFOLLOW,
        ) {
            Ok(stat) => stat,
            Err(nix::errno::Errno::ENOENT) => return Ok(LocatorAbsentJournal::Absent),
            Err(error) => return Err(errno(error)),
        };
        if SFlag::from_bits_truncate(stat.st_mode) & SFlag::S_IFMT != SFlag::S_IFREG {
            // Preserve the exact v1 lane for symlinks, directories, FIFOs,
            // sockets, and devices.  Only a regular file can carry v2 residue.
            return Ok(LocatorAbsentJournal::LegacyV1);
        }

        let mut file = self.open_nofollow()?;
        let metadata = file.metadata()?;
        if !metadata.is_file() {
            return Err(invalid(
                "locator-absent journal changed during classification",
            ));
        }
        let identity = FileIdentity::from_metadata(&metadata);
        let mut prefix = [0u8; 13];
        let mut prefix_len = 0;
        while prefix_len < prefix.len() {
            let read = file.read(&mut prefix[prefix_len..])?;
            if read == 0 {
                break;
            }
            prefix_len += read;
        }
        if prefix_len != prefix.len() || &prefix != b"{\"version\":2," {
            return Ok(LocatorAbsentJournal::LegacyV1);
        }

        after_prefix()?;
        self.directory.validate_private()?;
        validate_pending_metadata(&metadata, MAX_JOURNAL_BYTES)?;
        let bytes = read_opened_bounded(&mut file, &metadata, MAX_JOURNAL_BYTES)?;
        decode_journal(&bytes)?;
        self.remove_matching(identity)?;
        self.directory.file.sync_all()?;
        Ok(LocatorAbsentJournal::V2ResidueRemoved)
    }

    fn remove_canonical_v2_residue(&self) -> io::Result<()> {
        let mut file = match self.open_nofollow() {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error),
        };
        let metadata = file.metadata()?;
        validate_pending_metadata(&metadata, MAX_JOURNAL_BYTES)?;
        let identity = FileIdentity::from_metadata(&metadata);
        let bytes = read_opened_bounded(&mut file, &metadata, MAX_JOURNAL_BYTES)?;
        decode_journal(&bytes)?;
        self.remove_matching(identity)?;
        self.directory.file.sync_all()
    }

    fn verify_matching_canonical_journal(
        &self,
        expected_identity: FileIdentity,
        expected: &Journal,
    ) -> io::Result<()> {
        let (bytes, identity) = self.read_bounded_identified(MAX_JOURNAL_BYTES)?;
        if identity != expected_identity || decode_journal(&bytes)? != *expected {
            return Err(invalid("published journal identity changed before update"));
        }
        Ok(())
    }

    fn remove_matching_canonical_journal(
        &self,
        expected_identity: FileIdentity,
        expected: &Journal,
    ) -> io::Result<()> {
        match self.verify_matching_canonical_journal(expected_identity, expected) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error),
        }
        match self.remove_matching(expected_identity) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error),
        }
    }

    fn remove_matching_canonical_locator(
        &self,
        expected_identity: FileIdentity,
        expected: &Locator,
    ) -> io::Result<()> {
        let (bytes, _) = match self.read_bounded_identified(MAX_LOCATOR_BYTES) {
            Ok(found) => found,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error),
        };
        if decode_locator(&bytes)? != *expected {
            return Err(invalid("published locator identity changed before cleanup"));
        }
        match self.remove_matching(expected_identity) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error),
        }
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
        let regular = SFlag::from_bits_truncate(stat.st_mode) & SFlag::S_IFMT == SFlag::S_IFREG;
        if !regular
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

    fn cleanup_stage(&self) -> io::Result<()> {
        let stage = self.stage_name()?;
        remove_named_safe(&self.directory.file, &stage)?;
        self.directory.file.sync_all()
    }

    fn publish(&self, bytes: &[u8], replace: bool) -> io::Result<FileIdentity> {
        self.publish_with(bytes, replace, PublishRole::Journal, &mut |_| Ok(()))
    }

    fn publish_with(
        &self,
        bytes: &[u8],
        replace: bool,
        role: PublishRole,
        step: &mut impl FnMut(PublishStep) -> io::Result<()>,
    ) -> io::Result<FileIdentity> {
        use nix::fcntl::{OFlag, RenameFlags, openat, renameat, renameat2};
        use nix::sys::stat::{Mode, fchmod};

        let stage = self.stage_name()?;
        self.cleanup_stage()?;
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
        .map_err(errno)?;
        let mut file = File::from(fd);
        fchmod(&file, Mode::from_bits_truncate(0o600)).map_err(errno)?;
        let identity = FileIdentity::from_metadata(&file.metadata()?);
        let result = (|| {
            file.write_all(bytes)?;
            step(PublishStep::for_role(role, 0))?;
            file.sync_all()?;
            drop(file);
            step(PublishStep::for_role(role, 1))?;
            if replace {
                renameat(
                    &self.directory.file,
                    Path::new(&stage),
                    &self.directory.file,
                    Path::new(&self.name),
                )
                .map_err(errno)?;
            } else {
                renameat2(
                    &self.directory.file,
                    Path::new(&stage),
                    &self.directory.file,
                    Path::new(&self.name),
                    RenameFlags::RENAME_NOREPLACE,
                )
                .map_err(errno)?;
            }
            step(PublishStep::for_role(role, 2))?;
            self.directory.file.sync_all()
        })();
        if result.is_err() {
            // A hook or same-uid actor can replace the stage name after this
            // attempt captured its inode.  Error cleanup may remove only the
            // inode this publication created, never the replacement.
            let _ = stage_entry.remove_matching(identity);
            if !replace {
                let _ = self.remove_matching(identity);
            }
            let _ = self.directory.file.sync_all();
        }
        result.map(|()| identity)
    }

    fn replace(&self, bytes: &[u8]) -> io::Result<()> {
        self.publish(bytes, true).map(|_| ())
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
    let regular = SFlag::from_bits_truncate(stat.st_mode) & SFlag::S_IFMT == SFlag::S_IFREG;
    if !regular || stat.st_uid != geteuid().as_raw() || stat.st_mode & 0o7777 != 0o600 {
        return Err(invalid("unsafe exact pending residue"));
    }
    unlinkat(directory, Path::new(name), UnlinkatFlags::NoRemoveDir).map_err(errno)
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
        Ok(target) => Ok(target),
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
    let path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    reject_ambiguous_terminal_path(&path)?;
    normalize_absolute(&path)
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
                let component = probe
                    .file_name()
                    .ok_or_else(|| invalid("dangling launch target has no existing ancestor"))?
                    .to_os_string();
                missing.push(component);
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

    fn private_dir(parent: &Path, name: &str) -> PathBuf {
        let path = parent.join(name);
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        path
    }

    fn config_toml(asn: u32) -> String {
        tier_authorized_uds_test_config(&format!(
            r#"
[global]
asn = {asn}
router_id = "192.0.2.1"
listen_port = 179
[global.telemetry]
log_format = "json"
"#
        ))
    }

    fn fixture() -> (
        tempfile::TempDir,
        PathBuf,
        PathBuf,
        LaunchIdentity,
        Arc<AcceptedConfigSnapshot>,
    ) {
        let root = tempfile::tempdir().unwrap();
        let config_dir = private_dir(root.path(), "config");
        let journal_dir = private_dir(root.path(), "journal");
        let config = config_dir.join("rustbgpd.toml");
        fs::write(&config, config_toml(64_500)).unwrap();
        fs::set_permissions(&config, fs::Permissions::from_mode(0o600)).unwrap();
        let prior = Arc::new(AcceptedConfigSnapshot::load(&config, None).unwrap());
        let launch = LaunchIdentity::resolve(&config).unwrap();
        let journal = journal_dir.join(super::super::JOURNAL_FILE_NAME);
        (root, config, journal, launch, prior)
    }

    fn small_prior() -> Prior {
        let normalized_toml = "asn = 64512\n".to_string();
        let sha256 = Sha256::digest(normalized_toml.as_bytes()).into();
        let manifest = Manifest {
            toml_sha256: sha256,
            rpol_units: Vec::new(),
            datasets: Vec::new(),
        };
        Prior {
            sha256,
            source_sha256: history_v2::manifest_source_sha256(&manifest),
            normalized_toml,
            manifest,
        }
    }

    #[test]
    fn canonical_journal_and_locator_pin_dispatch_and_field_order() {
        // Destructive proof: reordering a wire-owned field, changing the
        // dispatch prefix, omitting LF, or accepting pretty JSON makes an
        // exact byte assertion or canonical decode fail.
        let prior = small_prior();
        let journal = Journal {
            version: 2,
            confirm_id: "deploy-1".into(),
            deadline_unix_seconds: 9,
            rollback_failed: false,
            prior: prior.clone(),
        };
        let bytes = encode_journal(&journal).unwrap();
        let sha = history_v2::encode_hex(&prior.sha256);
        let source = history_v2::encode_hex(&prior.source_sha256);
        assert_eq!(
            String::from_utf8(bytes.clone()).unwrap(),
            format!(
                "{{\"version\":2,\"confirm_id\":\"deploy-1\",\"deadline_unix_seconds\":9,\"rollback_failed\":false,\"prior\":{{\"sha256\":\"{sha}\",\"source_sha256\":\"{source}\",\"normalized_toml\":\"asn = 64512\\n\",\"manifest\":{{\"toml_sha256\":\"{sha}\",\"rpol_units\":[],\"datasets\":[]}}}}}}\n"
            )
        );
        assert_eq!(decode_journal(&bytes).unwrap(), journal);
        let mut noncanonical = bytes;
        noncanonical.insert(1, b' ');
        assert!(decode_journal(&noncanonical).is_err());

        let locator = Locator {
            version: 2,
            confirm_id: "deploy-1".into(),
            journal_path: LosslessPath(b"/state/commit-confirm-journal.json".to_vec()),
            config_target: LosslessPath(b"/etc/rustbgpd/config.toml".to_vec()),
            prior_sha256: prior.sha256,
            prior_source_sha256: prior.source_sha256,
        };
        let locator_bytes = encode_locator(&locator).unwrap();
        let locator_text = String::from_utf8(locator_bytes.clone()).unwrap();
        assert!(
            locator_text
                .starts_with("{\"version\":2,\"confirm_id\":\"deploy-1\",\"journal_path\":")
        );
        assert!(locator_text.ends_with(&format!(
            "\"prior_sha256\":\"{sha}\",\"prior_source_sha256\":\"{source}\"}}\n"
        )));
        assert_eq!(decode_locator(&locator_bytes).unwrap(), locator);
    }

    #[test]
    fn component_caps_accept_maximum_and_reject_plus_one() {
        // Destructive proof: changing either component `>` to `>=` or
        // dropping the confirm/path check breaks a named boundary below.
        let mut prior = small_prior();
        prior.normalized_toml = "x".repeat(history_v2::MAX_TOML);
        prior.sha256 = Sha256::digest(prior.normalized_toml.as_bytes()).into();
        prior.manifest.toml_sha256 = prior.sha256;
        prior.source_sha256 = history_v2::manifest_source_sha256(&prior.manifest);
        assert!(validate_prior(&prior).is_ok());
        prior.normalized_toml.push('x');
        assert!(validate_prior(&prior).is_err());

        let mut journal = Journal {
            version: 2,
            confirm_id: "é".repeat(MAX_CONFIRM_ID_CHARS),
            deadline_unix_seconds: 0,
            rollback_failed: false,
            prior: small_prior(),
        };
        assert!(encode_journal(&journal).is_ok());
        journal.confirm_id.push('é');
        assert!(encode_journal(&journal).is_err());
        journal.confirm_id = "   ".to_string();
        assert!(encode_journal(&journal).is_err());

        let path = format!("/{}", "x".repeat(MAX_PATH_BYTES - 1));
        let mut locator = Locator {
            version: 2,
            confirm_id: "x".into(),
            journal_path: LosslessPath(path.into_bytes()),
            config_target: LosslessPath(b"/c".to_vec()),
            prior_sha256: [0; 32],
            prior_source_sha256: [0; 32],
        };
        assert!(validate_locator(&locator).is_ok());
        locator.journal_path.0.push(b'x');
        assert!(validate_locator(&locator).is_err());
    }

    #[test]
    fn journal_and_locator_codec_total_caps_are_load_bearing() {
        // Destructive proof: removing the encoder cap makes the N-1 encode
        // succeed; removing the decoder cap makes the identical canonical
        // N-byte wire decode successfully under N-1.  These call the same
        // helpers as the production-constant wrappers above.
        let prior = small_prior();
        let journal = Journal {
            version: VERSION,
            confirm_id: "deploy-1".into(),
            deadline_unix_seconds: 9,
            rollback_failed: false,
            prior: prior.clone(),
        };
        let journal_wire = encode_journal(&journal).unwrap();
        let journal_max = journal_wire.len();
        assert_eq!(
            encode_journal_with_cap(&journal, journal_max).unwrap(),
            journal_wire
        );
        assert_eq!(
            decode_journal_with_cap(&journal_wire, journal_max).unwrap(),
            journal
        );
        assert!(encode_journal_with_cap(&journal, journal_max - 1).is_err());
        assert!(decode_journal_with_cap(&journal_wire, journal_max - 1).is_err());

        let locator = Locator {
            version: VERSION,
            confirm_id: "deploy-1".into(),
            journal_path: LosslessPath(b"/state/commit-confirm-journal.json".to_vec()),
            config_target: LosslessPath(b"/etc/rustbgpd/config.toml".to_vec()),
            prior_sha256: prior.sha256,
            prior_source_sha256: prior.source_sha256,
        };
        let locator_wire = encode_locator(&locator).unwrap();
        let locator_max = locator_wire.len();
        assert_eq!(
            encode_locator_with_cap(&locator, locator_max).unwrap(),
            locator_wire
        );
        assert_eq!(
            decode_locator_with_cap(&locator_wire, locator_max).unwrap(),
            locator
        );
        assert!(encode_locator_with_cap(&locator, locator_max - 1).is_err());
        assert!(decode_locator_with_cap(&locator_wire, locator_max - 1).is_err());
    }

    #[test]
    fn publication_is_journal_then_locator_and_every_failure_precedes_candidate_work() {
        // Destructive proof: swapping publication calls or moving a hook after
        // its named durability operation changes the exact crash state. Each
        // injected failure now occurs before that operation, leaves no locator
        // authority, and never touches config.
        let expected = [
            PublishStep::JournalStageSync,
            PublishStep::JournalRename,
            PublishStep::JournalDirectorySync,
            PublishStep::LocatorStageSync,
            PublishStep::LocatorRename,
            PublishStep::LocatorDirectorySync,
        ];
        let (_root, config, journal, launch, prior) = fixture();
        let before = fs::read(&config).unwrap();
        let mut observed = Vec::new();
        let files = launch
            .publish_with(&journal, "deploy-1", 9, &prior, |step| {
                observed.push(step);
                Ok(())
            })
            .unwrap();
        assert_eq!(observed, expected);
        assert_eq!(fs::read(&config).unwrap(), before);
        files.terminal_cleanup().unwrap();

        for fail in expected {
            let (_root, config, journal, launch, prior) = fixture();
            let before = fs::read(&config).unwrap();
            let result = launch.publish_with(&journal, "deploy-1", 9, &prior, |step| {
                if step == fail {
                    Err(io::Error::other("injected publication failure"))
                } else {
                    Ok(())
                }
            });
            assert!(result.is_err(), "{fail:?}");
            assert_eq!(fs::read(&config).unwrap(), before, "{fail:?}");
            assert!(!launch.locator_path().exists(), "{fail:?}");
            assert!(!journal.exists(), "{fail:?}");
        }
    }

    #[test]
    fn publication_failure_preserves_same_name_journal_replacement() {
        // Destructive proof: cleaning "any canonical v2 residue" after a
        // locator publication failure deletes this byte-identical replacement.
        // Cleanup must be bound to the exact inode created by this attempt.
        let (_root, _config, journal, launch, prior) = fixture();
        let replacement = journal.with_file_name("replacement-journal");
        let result = launch.publish_with(&journal, "deploy-1", 9, &prior, |step| {
            if step == PublishStep::LocatorDirectorySync {
                let bytes = fs::read(&journal).unwrap();
                fs::write(&replacement, bytes).unwrap();
                fs::set_permissions(&replacement, fs::Permissions::from_mode(0o600)).unwrap();
                fs::rename(&replacement, &journal).unwrap();
                return Err(io::Error::other("injected locator sync failure"));
            }
            Ok(())
        });
        assert!(result.is_err());
        assert!(!launch.locator_path().exists());
        assert!(journal.exists(), "replacement journal must survive cleanup");
    }

    #[test]
    fn publication_failure_preserves_same_name_stage_replacement() {
        // Destructive proof: name-only stage cleanup deletes this replacement
        // after the publisher has captured a different inode.  Error cleanup
        // must be bound to the exact stage identity created by this attempt.
        let (_root, _config, journal, launch, prior) = fixture();
        let stage =
            journal.with_file_name(append_name(journal.file_name().unwrap(), b".tmp").unwrap());
        let replacement = b"same-name replacement stage";
        let result = launch.publish_with(&journal, "deploy-1", 9, &prior, |step| {
            if step == PublishStep::JournalStageSync {
                fs::remove_file(&stage).unwrap();
                fs::write(&stage, replacement).unwrap();
                fs::set_permissions(&stage, fs::Permissions::from_mode(0o600)).unwrap();
                return Err(io::Error::other("injected journal stage failure"));
            }
            Ok(())
        });
        assert!(result.is_err());
        assert!(!launch.locator_path().exists());
        assert!(!journal.exists());
        assert_eq!(fs::read(stage).unwrap(), replacement);
    }

    #[test]
    fn writer_removes_only_canonical_v2_final_residue() {
        // Destructive proof: restoring the old metadata-only final cleanup
        // erases the byte-exact legacy and garbage occupants asserted below.
        let (_root, _config, journal, launch, prior) = fixture();
        super::super::write(
            &journal,
            &super::super::ConfirmJournal {
                confirm_id: "legacy".into(),
                deadline_unix_seconds: 1,
                rollback_toml: config_toml(64_499),
                rollback_failed: false,
            },
        )
        .unwrap();
        let legacy = fs::read(&journal).unwrap();
        assert!(launch.publish(&journal, "deploy-1", 9, &prior).is_err());
        assert_eq!(fs::read(&journal).unwrap(), legacy);
        assert!(!launch.locator_path().exists());

        fs::write(&journal, b"owner-private garbage").unwrap();
        fs::set_permissions(&journal, fs::Permissions::from_mode(0o600)).unwrap();
        let garbage = fs::read(&journal).unwrap();
        assert!(launch.publish(&journal, "deploy-1", 9, &prior).is_err());
        assert_eq!(fs::read(&journal).unwrap(), garbage);
        assert!(!launch.locator_path().exists());

        let canonical_residue = encode_journal(&Journal {
            version: VERSION,
            confirm_id: "old-v2".into(),
            deadline_unix_seconds: 1,
            rollback_failed: false,
            prior: Prior::from_snapshot(&prior),
        })
        .unwrap();
        fs::write(&journal, canonical_residue).unwrap();
        fs::set_permissions(&journal, fs::Permissions::from_mode(0o600)).unwrap();
        let files = launch
            .publish(&journal, "deploy-1", 9, &prior)
            .expect("exact canonical v2 residue is safe only while locator is absent");
        assert!(launch.locator_path().exists());
        files.terminal_cleanup().unwrap();
    }

    #[test]
    fn matching_v2_boot_verifies_then_restores_and_cleans_terminally() {
        // Destructive proof: removing journal/locator identity comparison,
        // prior verification, restore-before-unlink, or either terminal sync
        // makes this full state transition or the injected sequence fail.
        let (_root, config, journal, launch, prior) = fixture();
        let prior_bytes = prior.normalized_toml().as_bytes().to_vec();
        let files = launch.publish(&journal, "deploy-1", 9, &prior).unwrap();
        fs::write(&config, b"unconfirmed candidate bytes").unwrap();
        files.record_rollback_failed().unwrap();
        drop(files);

        let mut observed = Vec::new();
        let reverted = launch
            .boot_revert_check_io_with(|step| {
                observed.push(step);
                Ok(())
            })
            .unwrap()
            .expect("locator must authorize the exact journal");
        assert_eq!(
            observed,
            [
                BootStep::CandidateSave,
                BootStep::ConfigRestore,
                BootStep::LocatorUnlink,
                BootStep::LocatorDirectorySync,
                BootStep::JournalUnlink,
                BootStep::JournalDirectorySync,
            ]
        );
        assert_eq!(reverted.notice.confirm_id, "deploy-1");
        assert!(reverted.notice.rollback_failed);
        assert_eq!(reverted.accepted.normalized_toml().as_bytes(), prior_bytes);
        assert_eq!(fs::read(&config).unwrap(), prior_bytes);
        assert_eq!(
            fs::read(config.with_file_name("rustbgpd.toml.unconfirmed")).unwrap(),
            b"unconfirmed candidate bytes"
        );
        assert!(!launch.locator_path().exists());
        assert!(!journal.exists());
    }

    #[test]
    fn boot_reader_accepts_exact_journal_cap_and_rejects_plus_one_before_candidate_work() {
        // Destructive proof: removing the boot reader's journal cap lets the
        // N-byte journal pass an N-1 limit, increments the candidate-work
        // hook, and replaces the candidate.  The exact N boundary traverses
        // the real reader, provenance check, restore, and terminal cleanup.
        let (_root, config, journal, launch, prior) = fixture();
        let prior_bytes = prior.normalized_toml().as_bytes().to_vec();
        let files = launch.publish(&journal, "deploy-1", 9, &prior).unwrap();
        let locator_bytes = fs::read(launch.locator_path()).unwrap();
        let journal_bytes = fs::read(&journal).unwrap();
        fs::write(&config, b"unconfirmed candidate").unwrap();
        drop(files);

        let reverted = launch
            .boot_revert_check_io_with_limits(locator_bytes.len(), journal_bytes.len(), |_| Ok(()))
            .unwrap()
            .unwrap();
        assert_eq!(reverted.accepted.normalized_toml().as_bytes(), prior_bytes);
        assert_eq!(fs::read(&config).unwrap(), prior_bytes);
        assert!(!launch.locator_path().exists());
        assert!(!journal.exists());

        let (_root, config, journal, launch, prior) = fixture();
        let files = launch.publish(&journal, "deploy-2", 9, &prior).unwrap();
        let locator_bytes = fs::read(launch.locator_path()).unwrap();
        let journal_bytes = fs::read(&journal).unwrap();
        let candidate = b"second unconfirmed candidate";
        fs::write(&config, candidate).unwrap();
        drop(files);
        let candidate_steps = std::cell::Cell::new(0usize);

        let result = launch.boot_revert_check_io_with_limits(
            locator_bytes.len(),
            journal_bytes.len() - 1,
            |_| {
                candidate_steps.set(candidate_steps.get() + 1);
                Ok(())
            },
        );
        assert!(result.is_err());
        assert_eq!(candidate_steps.get(), 0);
        assert_eq!(fs::read(&config).unwrap(), candidate);
        assert!(launch.locator_path().exists());
        assert!(journal.exists());
    }

    #[test]
    fn boot_hooks_fail_before_each_named_operation_and_preserve_authority_order() {
        // Destructive proof: placing a hook after its operation, deleting the
        // restore-before-unlink edge, or cleaning the journal before durable
        // locator absence changes the per-step filesystem state below.
        let steps = [
            BootStep::CandidateSave,
            BootStep::ConfigRestore,
            BootStep::LocatorUnlink,
            BootStep::LocatorDirectorySync,
            BootStep::JournalUnlink,
            BootStep::JournalDirectorySync,
        ];
        for (index, fail) in steps.into_iter().enumerate() {
            let (_root, config, journal, launch, prior) = fixture();
            let prior_bytes = prior.normalized_toml().as_bytes().to_vec();
            let files = launch.publish(&journal, "deploy-1", 9, &prior).unwrap();
            let candidate = b"candidate";
            fs::write(&config, candidate).unwrap();
            drop(files);
            let mut observed = Vec::new();
            let result = launch.boot_revert_check_io_with(|step| {
                observed.push(step);
                if step == fail {
                    Err(io::Error::other("injected boot operation failure"))
                } else {
                    Ok(())
                }
            });
            assert_eq!(observed, steps[..=index], "{fail:?}");

            if matches!(
                fail,
                BootStep::JournalUnlink | BootStep::JournalDirectorySync
            ) {
                assert!(
                    result.unwrap().unwrap().notice.journal_cleanup_failed,
                    "post-terminal cleanup failure must be warning-only: {fail:?}"
                );
            } else {
                assert!(result.is_err(), "{fail:?}");
            }

            let backup = config.with_file_name("rustbgpd.toml.unconfirmed");
            match fail {
                BootStep::CandidateSave => {
                    assert_eq!(fs::read(&config).unwrap(), candidate);
                    assert!(!backup.exists());
                    assert!(launch.locator_path().exists());
                }
                BootStep::ConfigRestore => {
                    assert!(!config.exists());
                    assert_eq!(fs::read(&backup).unwrap(), candidate);
                    assert!(launch.locator_path().exists());
                }
                BootStep::LocatorUnlink => {
                    assert_eq!(fs::read(&config).unwrap(), prior_bytes);
                    assert!(launch.locator_path().exists());
                    assert!(journal.exists());
                }
                BootStep::LocatorDirectorySync => {
                    assert_eq!(fs::read(&config).unwrap(), prior_bytes);
                    assert!(!launch.locator_path().exists());
                    assert!(journal.exists());
                }
                BootStep::JournalUnlink => {
                    assert!(!launch.locator_path().exists());
                    assert!(journal.exists());
                }
                BootStep::JournalDirectorySync => {
                    assert!(!launch.locator_path().exists());
                    assert!(!journal.exists());
                }
            }
        }
    }

    #[test]
    fn locator_presence_is_fail_closed_and_never_falls_back() {
        // Destructive proof: treating invalid-present as absent would return
        // `Ok(None)` and let candidate/v1 discovery proceed.
        let (_root, config, _journal, launch, _prior) = fixture();
        let candidate = b"candidate must remain untouched";
        fs::write(&config, candidate).unwrap();
        fs::write(launch.locator_path(), b"{}\n").unwrap();
        fs::set_permissions(launch.locator_path(), fs::Permissions::from_mode(0o600)).unwrap();
        assert!(launch.boot_revert_check().is_err());
        assert_eq!(fs::read(&config).unwrap(), candidate);
        assert!(launch.locator_path().exists());
    }

    #[test]
    fn provenance_mismatch_touches_no_candidate_backup_or_pending_state() {
        // Destructive proof: loading sources after save-aside, clearing the
        // fence on mismatch, or deleting either pending file changes one of
        // these byte-exact untouched-state assertions.
        let root = tempfile::tempdir().unwrap();
        let config_dir = private_dir(root.path(), "config");
        let state_dir = private_dir(root.path(), "state");
        let source = config_dir.join("policy.rpol");
        fs::write(&source, "policy p { term rest { accept } }\n").unwrap();
        let config = config_dir.join("rustbgpd.toml");
        let prior_toml = format!(
            "{}\n[policy]\nrpol_files = [{:?}]\n",
            config_toml(64_500),
            source.display().to_string()
        );
        fs::write(&config, prior_toml).unwrap();
        let prior = Arc::new(AcceptedConfigSnapshot::load(&config, None).unwrap());
        let launch = LaunchIdentity::resolve(&config).unwrap();
        let journal = state_dir.join(super::super::JOURNAL_FILE_NAME);
        let files = launch.publish(&journal, "deploy-1", 9, &prior).unwrap();
        let candidate = b"unconfirmed candidate must remain untouched";
        fs::write(&config, candidate).unwrap();
        fs::write(&source, "policy p { term rest { reject } }\n").unwrap();
        let journal_before = fs::read(&journal).unwrap();
        let locator_before = fs::read(launch.locator_path()).unwrap();
        drop(files);

        assert!(launch.boot_revert_check().is_err());
        assert_eq!(fs::read(&config).unwrap(), candidate);
        assert!(!config.with_file_name("rustbgpd.toml.unconfirmed").exists());
        assert_eq!(fs::read(&journal).unwrap(), journal_before);
        assert_eq!(fs::read(launch.locator_path()).unwrap(), locator_before);
    }

    #[test]
    fn locator_journal_field_mismatch_touches_nothing() {
        // Destructive proof: deleting locator/journal field comparison lets the
        // changed confirm id authorize the otherwise-valid journal and mutates
        // the candidate before the mismatch can be observed.
        let (_root, config, journal, launch, prior) = fixture();
        let files = launch.publish(&journal, "deploy-1", 9, &prior).unwrap();
        let candidate = b"candidate must remain untouched";
        fs::write(&config, candidate).unwrap();
        let locator_path = launch.locator_path();
        let mut locator_wire = decode_locator(&fs::read(&locator_path).unwrap()).unwrap();
        locator_wire.confirm_id = "different-transaction".to_string();
        fs::write(&locator_path, encode_locator(&locator_wire).unwrap()).unwrap();

        assert!(launch.boot_revert_check().is_err());
        assert_eq!(fs::read(&config).unwrap(), candidate);
        assert!(!config.with_file_name("rustbgpd.toml.unconfirmed").exists());
        assert!(locator_path.exists());
        assert!(journal.exists());
        assert!(files.terminal_cleanup().is_err());
    }

    #[test]
    fn all_locator_and_journal_presence_states_dispatch_exactly() {
        // Destructive proof: absent-locator v2 authorization, lost-journal
        // tolerance, or v1 acceptance under a locator breaks one of these
        // explicit state rows.
        let (_root, config, journal, launch, prior) = fixture();
        assert!(launch.boot_revert_check().unwrap().is_none());

        // Absent locator + v1 remains delegated to the legacy lane.
        super::super::write(
            &journal,
            &super::super::ConfirmJournal {
                confirm_id: "legacy".into(),
                deadline_unix_seconds: 1,
                rollback_toml: config_toml(64_499),
                rollback_failed: false,
            },
        )
        .unwrap();
        assert!(launch.boot_revert_check().unwrap().is_none());
        assert!(matches!(
            inspect_locator_absent_journal(&journal).unwrap(),
            LocatorAbsentJournal::LegacyV1
        ));
        fs::remove_file(&journal).unwrap();

        // Present locator + absent journal refuses without touching candidate.
        let files = launch.publish(&journal, "deploy-1", 9, &prior).unwrap();
        fs::remove_file(&journal).unwrap();
        let before = fs::read(&config).unwrap();
        assert!(launch.boot_revert_check().is_err());
        assert_eq!(fs::read(&config).unwrap(), before);
        fs::write(&journal, b"legacy-v1").unwrap();
        fs::set_permissions(&journal, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(launch.boot_revert_check().is_err());
        assert_eq!(fs::read(&config).unwrap(), before);
        assert!(
            files.terminal_cleanup().unwrap(),
            "a replaced journal is warning-only after exact locator removal"
        );
        assert_eq!(fs::read(&journal).unwrap(), b"legacy-v1");
        assert!(!launch.locator_path().exists());
        fs::remove_file(&journal).unwrap();

        // Absent locator + canonical v2 is residue, never authority.
        let files = launch.publish(&journal, "deploy-2", 10, &prior).unwrap();
        fs::remove_file(launch.locator_path()).unwrap();
        drop(files);
        assert!(matches!(
            inspect_locator_absent_journal(&journal).unwrap(),
            LocatorAbsentJournal::V2ResidueRemoved
        ));
        assert!(!journal.exists());
    }

    #[test]
    fn locator_absent_dispatch_classifies_reads_and_cleans_one_inode() {
        // Destructive proof: the former metadata/open/reopen sequence deleted
        // `replacement` after classifying a different canonical v2 inode.
        let (_root, _config, journal, launch, prior) = fixture();
        let files = launch.publish(&journal, "deploy-1", 9, &prior).unwrap();
        fs::remove_file(launch.locator_path()).unwrap();
        drop(files);

        let replacement = journal.with_file_name("replacement");
        fs::write(&replacement, b"legacy replacement must survive").unwrap();
        fs::set_permissions(&replacement, fs::Permissions::from_mode(0o600)).unwrap();
        let entry = Entry::pin_for_legacy_dispatch(&journal).unwrap();
        let result = entry.inspect_locator_absent_with(|| {
            fs::rename(&replacement, &journal)?;
            Ok(())
        });
        assert!(result.is_err());
        assert_eq!(
            fs::read(&journal).unwrap(),
            b"legacy replacement must survive"
        );

        // A stable legacy object remains delegated byte-for-byte; dispatch
        // applies no v2 owner/mode/content cleanup to it.
        assert!(matches!(
            inspect_locator_absent_journal(&journal).unwrap(),
            LocatorAbsentJournal::LegacyV1
        ));
        assert_eq!(
            fs::read(&journal).unwrap(),
            b"legacy replacement must survive"
        );
    }

    #[test]
    fn symlink_target_binding_detects_retarget_and_restores_dangling_target() {
        // Destructive proof: recording the lexical leaf rather than the real
        // target makes the retarget case pass; failing to inspect a dangling
        // leaf prevents the second revert.
        let root = tempfile::tempdir().unwrap();
        let config_dir = private_dir(root.path(), "config");
        let state_dir = private_dir(root.path(), "state");
        let target_a = config_dir.join("a.toml");
        let target_b = config_dir.join("b.toml");
        fs::write(&target_a, config_toml(64_500)).unwrap();
        fs::write(&target_b, config_toml(64_501)).unwrap();
        let link = config_dir.join("config.toml");
        std::os::unix::fs::symlink("a.toml", &link).unwrap();
        let launch = LaunchIdentity::resolve(&link).unwrap();
        let prior = Arc::new(AcceptedConfigSnapshot::load(&link, None).unwrap());
        let journal = state_dir.join(super::super::JOURNAL_FILE_NAME);
        let files = launch.publish(&journal, "deploy-1", 9, &prior).unwrap();
        fs::remove_file(&link).unwrap();
        std::os::unix::fs::symlink("b.toml", &link).unwrap();
        assert!(launch.boot_revert_check().is_err());
        files.terminal_cleanup().unwrap();

        fs::remove_file(&link).unwrap();
        std::os::unix::fs::symlink("a.toml", &link).unwrap();
        let files = launch.publish(&journal, "deploy-2", 9, &prior).unwrap();
        fs::write(&target_a, b"candidate").unwrap();
        fs::remove_file(&target_a).unwrap();
        drop(files);
        assert!(launch.boot_revert_check().unwrap().is_some());
        assert_eq!(
            fs::read(&target_a).unwrap(),
            prior.normalized_toml().as_bytes()
        );
        assert_eq!(fs::read(&link).unwrap(), prior.normalized_toml().as_bytes());
    }

    #[test]
    fn writer_rejects_unsafe_resolved_target_parent_before_publication() {
        // Destructive proof: omitting the writer-side target Entry::pin makes
        // publication succeed even though boot recovery would later reject
        // this world-writable resolved parent.
        let root = tempfile::tempdir().unwrap();
        let config_dir = private_dir(root.path(), "config");
        let target_dir = private_dir(root.path(), "target");
        let state_dir = private_dir(root.path(), "state");
        let target = target_dir.join("real.toml");
        fs::write(&target, config_toml(64_500)).unwrap();
        let link = config_dir.join("config.toml");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let prior = Arc::new(AcceptedConfigSnapshot::load(&link, None).unwrap());
        let launch = LaunchIdentity::resolve(&link).unwrap();
        let journal = state_dir.join(super::super::JOURNAL_FILE_NAME);
        fs::set_permissions(&target_dir, fs::Permissions::from_mode(0o777)).unwrap();

        assert!(launch.publish(&journal, "deploy-1", 9, &prior).is_err());
        assert!(!launch.locator_path().exists());
        assert!(!journal.exists());
    }

    #[test]
    fn dangling_target_keeps_canonical_identity_through_symlinked_intermediate() {
        // Destructive proof: replacing `canonicalize_allow_missing` with
        // lexical normalization makes the dangling target compare as
        // `config/targets/prior.toml` instead of its recorded real parent.
        let root = tempfile::tempdir().unwrap();
        let config_dir = private_dir(root.path(), "config");
        let real_targets = private_dir(root.path(), "real-targets");
        let state_dir = private_dir(root.path(), "state");
        let target = real_targets.join("prior.toml");
        fs::write(&target, config_toml(64_500)).unwrap();
        std::os::unix::fs::symlink(&real_targets, config_dir.join("targets")).unwrap();
        let launch_path = config_dir.join("config.toml");
        std::os::unix::fs::symlink("targets/prior.toml", &launch_path).unwrap();
        let launch = LaunchIdentity::resolve(&launch_path).unwrap();
        let prior = Arc::new(AcceptedConfigSnapshot::load(&launch_path, None).unwrap());
        let journal = state_dir.join(super::super::JOURNAL_FILE_NAME);
        let files = launch.publish(&journal, "deploy-1", 9, &prior).unwrap();
        fs::remove_file(&target).unwrap();
        drop(files);

        assert!(launch.boot_revert_check().unwrap().is_some());
        assert_eq!(
            fs::read(&target).unwrap(),
            prior.normalized_toml().as_bytes()
        );
        assert!(launch_path.is_symlink());
    }

    #[test]
    fn descriptor_read_never_reopens_checked_name_and_detects_growth() {
        // Destructive proof: replacing the checked descriptor with a second
        // `open(path)` returns `replacement`; dropping the exact-length check
        // accepts the growth case.
        let root = tempfile::tempdir().unwrap();
        let dir = private_dir(root.path(), "private");
        let path = dir.join("entry");
        fs::write(&path, b"original").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let entry = Entry::pin(&path).unwrap();
        let replacement = dir.join("replacement");
        fs::write(&replacement, b"replacement").unwrap();
        fs::set_permissions(&replacement, fs::Permissions::from_mode(0o600)).unwrap();
        let bytes = entry
            .read_bounded_identified_with(64, || {
                fs::rename(&replacement, &path)?;
                Ok(())
            })
            .unwrap()
            .0;
        assert_eq!(bytes, b"original");
        assert_eq!(fs::read(&path).unwrap(), b"replacement");

        fs::write(&path, b"short").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let entry = Entry::pin(&path).unwrap();
        assert!(
            entry
                .read_bounded_identified_with(64, || {
                    fs::OpenOptions::new()
                        .append(true)
                        .open(&path)?
                        .write_all(b"-grew")?;
                    Ok(())
                })
                .is_err()
        );
    }

    #[test]
    fn v2_pending_metadata_owner_type_mode_and_size_are_fail_closed() {
        // Destructive proof: dropping any scalar guard makes its direct row
        // green; opening without O_NOFOLLOW or checking pathname metadata lets
        // one of the functional directory/symlink/oversize rows reach decode.
        use nix::unistd::geteuid;

        let owner = geteuid().as_raw();
        assert!(validate_pending_metadata_values(true, owner, 0o100_600, 64, 64, owner).is_ok());
        assert!(
            validate_pending_metadata_values(true, owner.wrapping_add(1), 0o100_600, 64, 64, owner)
                .is_err()
        );
        assert!(validate_pending_metadata_values(false, owner, 0o040_600, 64, 64, owner).is_err());
        assert!(validate_pending_metadata_values(true, owner, 0o100_640, 64, 64, owner).is_err());
        assert!(validate_pending_metadata_values(true, owner, 0o100_600, 65, 64, owner).is_err());

        for occupant in ["directory", "symlink", "oversize"] {
            let (_root, config, journal, launch, prior) = fixture();
            let files = launch.publish(&journal, "deploy-1", 9, &prior).unwrap();
            drop(files);
            fs::remove_file(&journal).unwrap();
            match occupant {
                "directory" => fs::create_dir(&journal).unwrap(),
                "symlink" => {
                    let target = journal.with_file_name("symlink-target");
                    fs::write(&target, b"not authority").unwrap();
                    std::os::unix::fs::symlink(target, &journal).unwrap();
                }
                "oversize" => {
                    let file = fs::File::create(&journal).unwrap();
                    file.set_len(MAX_JOURNAL_BYTES as u64 + 1).unwrap();
                    fs::set_permissions(&journal, fs::Permissions::from_mode(0o600)).unwrap();
                }
                _ => unreachable!(),
            }

            let before = fs::read(&config).unwrap();
            assert!(launch.boot_revert_check().is_err(), "{occupant}");
            assert_eq!(fs::read(&config).unwrap(), before, "{occupant}");
            assert!(launch.locator_path().exists(), "{occupant}");
        }
    }

    #[test]
    fn terminal_cleanup_requires_the_published_inode_even_for_identical_bytes() {
        // Destructive proof: deleting either identity comparison makes cleanup
        // unlink a byte-identical replacement that this transaction did not
        // publish. Locator replacement is nonterminal; journal replacement is
        // warning-only after locator authority becomes durably absent.
        let (_root, _config, journal, launch, prior) = fixture();
        let files = launch.publish(&journal, "deploy-1", 9, &prior).unwrap();
        let locator = launch.locator_path();
        let replacement = locator.with_file_name("replacement-locator");
        fs::write(&replacement, fs::read(&locator).unwrap()).unwrap();
        fs::set_permissions(&replacement, fs::Permissions::from_mode(0o600)).unwrap();
        fs::rename(&replacement, &locator).unwrap();
        assert!(files.terminal_cleanup().is_err());
        assert!(locator.exists());
        assert!(journal.exists());

        let (_root, _config, journal, launch, prior) = fixture();
        let files = launch.publish(&journal, "deploy-2", 10, &prior).unwrap();
        let replacement = journal.with_file_name("replacement-journal");
        let expected = fs::read(&journal).unwrap();
        fs::write(&replacement, &expected).unwrap();
        fs::set_permissions(&replacement, fs::Permissions::from_mode(0o600)).unwrap();
        fs::rename(&replacement, &journal).unwrap();
        assert!(files.record_rollback_failed().is_err());
        assert!(files.terminal_cleanup().unwrap());
        assert!(!launch.locator_path().exists());
        assert_eq!(fs::read(&journal).unwrap(), expected);
    }

    #[test]
    fn lexical_parentdir_unsafe_parent_and_unsafe_metadata_refuse() {
        // Destructive proof: normalizing ParentDir or a terminal `/.`, omitting
        // parent mode enforcement, requiring daemon ownership merely to prove
        // locator absence, or accepting journal mode 0640 makes a named
        // assertion fail.  The owner distinction preserves the packaged
        // root-owned, read-only config directory while every present v2 object
        // and writer still require daemon ownership.
        assert!(LaunchIdentity::resolve(Path::new("/etc/rustbgpd/../config.toml")).is_err());
        assert!(LaunchIdentity::resolve(Path::new("/etc/rustbgpd/.")).is_err());
        assert!(validate_directory_metadata_values(true, 0, 0o750, 1000, false).is_ok());
        assert!(validate_directory_metadata_values(true, 0, 0o750, 1000, true).is_err());

        let (_root, config, journal, launch, prior) = fixture();
        fs::set_permissions(config.parent().unwrap(), fs::Permissions::from_mode(0o777)).unwrap();
        assert!(
            launch.boot_revert_check().is_err(),
            "locator absence must be established under a pinned safe parent"
        );
        assert!(launch.publish(&journal, "deploy-1", 9, &prior).is_err());
        fs::set_permissions(config.parent().unwrap(), fs::Permissions::from_mode(0o700)).unwrap();

        let files = launch.publish(&journal, "deploy-1", 9, &prior).unwrap();
        fs::set_permissions(&journal, fs::Permissions::from_mode(0o640)).unwrap();
        assert!(launch.boot_revert_check().is_err());
        fs::set_permissions(&journal, fs::Permissions::from_mode(0o600)).unwrap();
        files.terminal_cleanup().unwrap();
    }

    #[test]
    fn absent_locator_preserves_root_owned_read_only_config_parent() {
        // Destructive proof: pinning the absent locator with the full
        // daemon-owner check makes this packaged-deployment shape fail for the
        // unprivileged service UID before candidate loading can begin.
        let launch =
            LaunchIdentity::resolve(Path::new("/etc/rustbgpd-v2-absence-proof.toml")).unwrap();
        assert!(!launch.locator_path().exists());
        assert!(launch.boot_revert_check().unwrap().is_none());
    }

    #[test]
    fn terminal_locator_sync_precedes_warning_only_journal_cleanup() {
        // Destructive proof: moving journal cleanup before locator sync
        // changes the exact observation sequence.  A post-terminal journal
        // failure reports only a warning bit and cannot revive authority.
        let (_root, _config, journal, launch, prior) = fixture();
        let files = launch.publish(&journal, "deploy-1", 9, &prior).unwrap();
        let mut observed = Vec::new();
        let warning = files
            .terminal_cleanup_with(|step| {
                observed.push(step);
                if step == TerminalStep::JournalUnlink {
                    Err(io::Error::other("injected post-terminal failure"))
                } else {
                    Ok(())
                }
            })
            .unwrap();
        assert!(warning);
        assert_eq!(
            observed,
            [
                TerminalStep::LocatorUnlink,
                TerminalStep::LocatorDirectorySync,
                TerminalStep::JournalUnlink,
            ]
        );
        assert!(!launch.locator_path().exists());
        // A retry still syncs durable absence and cleanup is harmless.
        assert!(!files.terminal_cleanup().unwrap());

        // NotFound is terminal only after both parent directories cross their
        // durability hooks; returning early on either absence drops a sync.
        let (_root, _config, journal, launch, prior) = fixture();
        let files = launch.publish(&journal, "deploy-2", 10, &prior).unwrap();
        fs::remove_file(launch.locator_path()).unwrap();
        fs::remove_file(&journal).unwrap();
        let mut observed = Vec::new();
        assert!(
            !files
                .terminal_cleanup_with(|step| {
                    observed.push(step);
                    Ok(())
                })
                .unwrap()
        );
        assert_eq!(
            observed,
            [
                TerminalStep::LocatorUnlink,
                TerminalStep::LocatorDirectorySync,
                TerminalStep::JournalUnlink,
                TerminalStep::JournalDirectorySync,
            ]
        );
    }
}
