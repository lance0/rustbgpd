//! Generation-pinned external dataset snapshots (LAN-305, ADR-0103
//! Decisions 8.5 and 9).
//!
//! External *data* is the entire external surface of the policy
//! language — there is no code tier (no WASM, no host functions, no
//! subprocess; Decision 9 rejected them outright). A **dataset** is a
//! named, kind-typed match set whose members come from a file the
//! operator (or their automation) maintains, instead of from `.rpol`
//! source text. Probes reuse the exact indexed structures in-language
//! sets compile into ([`PrefixSet`] / [`AsnSet`] / [`CommunitySet`]),
//! so a dataset probe costs what a set probe costs — the same code
//! runs.
//!
//! The moving parts:
//!
//! - [`DatasetHandle`] — one long-lived, shared cell per dataset name.
//!   Compiled chains hold `Arc<DatasetHandle>`s; content updates swap
//!   the handle's interior [`DatasetSnapshot`] atomically **without
//!   recompiling or replacing any chain** (Decision 8.5: programs
//!   validate against shape, not content).
//! - [`DatasetSnapshot`] — an immutable `(generation, data)` pair.
//!   Generations are monotonic per handle. An evaluation pins each
//!   referenced snapshot once at walk start (`crate::eval`), so one
//!   route never observes two generations of the same dataset.
//! - [`DatasetBindings`] — the name → handle map a compile resolves
//!   dataset references through (built by the daemon config from
//!   `[policy.datasets]`, or by in-language `test` block overrides).
//!
//! Loading, parsing, validation, size-bounding, and indexing all
//! happen here — outside evaluation, on the config-apply/SIGHUP path
//! (Decision 7 permits compile-stage I/O only through the config
//! loader). A file that fails to load or parse **keeps the prior
//! snapshot** and surfaces the error (counter + WARN + `rbgp policy
//! stats`); an empty snapshot is a semantic statement the operator
//! must make explicitly with an empty file.

use std::collections::HashMap;
use std::fmt;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, TryLockError};

use arc_swap::ArcSwap;
use sha2::{Digest, Sha256};

use crate::sets::{AsnSet, CommunitySet, PrefixSet};

/// Maximum dataset file size in bytes (64 MiB). Enforced before the
/// file is read into memory and again by the bounded read.
pub const MAX_DATASET_BYTES: u64 = 64 * 1024 * 1024;

/// Maximum records (entries) per dataset. Enforced while parsing.
pub const MAX_DATASET_RECORDS: usize = 1_000_000;

/// Maximum dataset declarations per `.rpol` compilation unit (main
/// file plus imports). Bounds the per-evaluation pin frame in
/// `crate::eval` — the pin is a fixed-size stack array, so this is a
/// compile-time budget in the ADR-0103 Decision 3 sense.
pub const MAX_UNIT_DATASETS: usize = 16;

/// The kind (schema) of a dataset — which set structure its file
/// parses into and which probe positions accept it. Declared in
/// `.rpol` source (`dataset asn-set customers`); a kind change is a
/// source change and therefore a config transaction with candidate
/// recompilation, never a hot content swap (ADR-0103 Decision 8.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DatasetKind {
    /// Prefix entries (`10.0.0.0/8 ge 24 le 28`) — probed by
    /// `route.prefix in <name>`.
    Prefix,
    /// ASN members (`64500`) — probed by `route.origin-as in`,
    /// `peer.asn in`, and `<binding> in`.
    Asn,
    /// Community criteria (`65000:100`, `65000:1:2`, `RT:65001:7`,
    /// well-known names) — probed by community-list `in` and, for the
    /// standard partition, `<binding> in`.
    Community,
}

impl DatasetKind {
    /// The `.rpol` spelling — the same keywords set definitions use.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            DatasetKind::Prefix => "prefix-set",
            DatasetKind::Asn => "asn-set",
            DatasetKind::Community => "community-set",
        }
    }
}

impl fmt::Display for DatasetKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A dataset's indexed content — exactly the structures in-language
/// sets intern into, so probes are the same code path at the same
/// cost (the LAN-305 parity requirement is structural, not measured).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DatasetData {
    /// Indexed prefix entries.
    Prefix(PrefixSet),
    /// Indexed ASN members.
    Asn(AsnSet),
    /// Indexed community criteria.
    Community(CommunitySet),
}

impl DatasetData {
    /// The kind this data satisfies.
    #[must_use]
    pub fn kind(&self) -> DatasetKind {
        match self {
            DatasetData::Prefix(_) => DatasetKind::Prefix,
            DatasetData::Asn(_) => DatasetKind::Asn,
            DatasetData::Community(_) => DatasetKind::Community,
        }
    }

    /// Whether `route.prefix in` / `route.origin-as in` answer
    /// differently against `self` and `next` for a route with `prefix`
    /// and `origin` — the same probes evaluation runs (`crate::eval`).
    /// Community data, or a kind change, conservatively differs: their
    /// probes are not bounded by these keys.
    #[must_use]
    pub fn route_key_verdict_differs(
        &self,
        next: &Self,
        prefix: rustbgpd_wire::Prefix,
        origin: Option<u32>,
    ) -> bool {
        match (self, next) {
            (DatasetData::Prefix(old), DatasetData::Prefix(new)) => {
                old.matches(prefix) != new.matches(prefix)
            }
            (DatasetData::Asn(old), DatasetData::Asn(new)) => {
                origin.is_some_and(|asn| old.contains(asn) != new.contains(asn))
            }
            _ => true,
        }
    }

    /// Number of (canonicalized) records.
    #[must_use]
    pub fn records(&self) -> usize {
        match self {
            DatasetData::Prefix(set) => set.entries().len(),
            DatasetData::Asn(set) => set.asns().len() + set.ranges().len(),
            DatasetData::Community(set) => set.criteria().len() + set.patterns().len(),
        }
    }
}

/// One immutable dataset generation: the indexed data plus its
/// monotonic generation number. Evaluations pin an `Arc` of this;
/// superseded snapshots live exactly as long as some walk still holds
/// them (retention is "current only" — there is no history ring).
#[derive(Debug)]
pub struct DatasetSnapshot {
    /// Monotonic per-handle generation, starting at 1.
    pub generation: u64,
    /// The indexed content.
    pub data: DatasetData,
}

/// Operator-facing status of one dataset (the `rbgp policy stats`
/// surface): current generation, record count, and the most recent
/// refresh failure if the current snapshot is stale because of one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DatasetStatus {
    /// Dataset name.
    pub name: String,
    /// Declared kind.
    pub kind: DatasetKind,
    /// Current snapshot generation.
    pub generation: u64,
    /// Records in the current snapshot.
    pub records: usize,
    /// The last refresh error, if the most recent refresh attempt
    /// failed (cleared by the next successful refresh). While set, the
    /// prior snapshot keeps serving probes.
    pub last_error: Option<String>,
}

/// The long-lived shared cell for one dataset: compiled chains hold
/// `Arc<DatasetHandle>` in their dataset tables, and evaluation pins
/// the current snapshot with one wait-free load (ADR-0103 Decision 7:
/// no lock acquisition on the evaluation path).
///
/// Writer discipline: swaps are performed by a single owner (the
/// daemon's config apply/reload path, serialized by the reload guard);
/// [`refresh`](Self::refresh) is not designed for concurrent writers.
#[derive(Debug)]
pub struct DatasetHandle {
    name: Arc<str>,
    kind: DatasetKind,
    current: ArcSwap<DatasetSnapshot>,
    /// Most recent refresh failure; load-path only, never touched by
    /// evaluation. Cleared on the next successful refresh.
    last_error: Mutex<Option<String>>,
}

impl DatasetHandle {
    /// A new handle at generation 1.
    ///
    /// # Panics
    ///
    /// If `data`'s kind differs from `kind` — construction sites pair
    /// them by parsing the file *as* the declared kind.
    #[must_use]
    pub fn new(name: &str, kind: DatasetKind, data: DatasetData) -> Self {
        assert_eq!(data.kind(), kind, "dataset data matches declared kind");
        Self::from_snapshot(
            name,
            kind,
            Arc::new(DatasetSnapshot {
                generation: 1,
                data,
            }),
        )
    }

    fn from_snapshot(name: &str, kind: DatasetKind, snapshot: Arc<DatasetSnapshot>) -> Self {
        assert_eq!(snapshot.data.kind(), kind, "dataset snapshot matches kind");
        Self {
            name: Arc::from(name),
            kind,
            current: ArcSwap::new(snapshot),
            last_error: Mutex::new(None),
        }
    }

    /// Dataset name.
    #[must_use]
    pub fn name(&self) -> &Arc<str> {
        &self.name
    }

    /// Declared kind.
    #[must_use]
    pub fn kind(&self) -> DatasetKind {
        self.kind
    }

    /// Pin the current snapshot: one wait-free atomic load. This is
    /// the per-walk pinning primitive (ADR-0103 Decision 8.5) — the
    /// evaluator calls it once per referenced dataset at walk start
    /// and probes only the pinned `Arc` thereafter.
    #[must_use]
    pub fn pin(&self) -> Arc<DatasetSnapshot> {
        self.current.load_full()
    }

    /// Swap in `data` if it differs from the current snapshot's,
    /// bumping the generation; content-equal data is a no-op (no swap,
    /// no generation bump, no downstream refresh — the #775
    /// content-equal discipline applied to data). Clears any recorded
    /// refresh error either way. Returns the new generation when a
    /// swap happened.
    ///
    /// # Panics
    ///
    /// If `data`'s kind differs from the handle's — kind changes are
    /// config transactions that build a fresh handle, never a swap.
    pub fn refresh(&self, data: DatasetData) -> Option<u64> {
        assert_eq!(data.kind(), self.kind, "dataset kind is fixed per handle");
        self.last_error
            .lock()
            .expect("dataset error mutex never poisoned")
            .take();
        let current = self.current.load();
        if current.data == data {
            return None;
        }
        let generation = current.generation + 1;
        self.current
            .store(Arc::new(DatasetSnapshot { generation, data }));
        Some(generation)
    }

    /// Record a refresh failure: the current snapshot stays in place
    /// and keeps serving probes (never substitute empty data —
    /// ADR-0103 Decision 8.5); the error is surfaced via
    /// [`status`](Self::status).
    ///
    /// # Panics
    ///
    /// If the error mutex is poisoned (a writer panicked mid-store —
    /// unreachable: stores are infallible assignments).
    pub fn record_error(&self, error: impl Into<String>) {
        *self
            .last_error
            .lock()
            .expect("dataset error mutex never poisoned") = Some(error.into());
    }

    /// Operator-facing status snapshot.
    ///
    /// # Panics
    ///
    /// If the error mutex is poisoned (unreachable, as above).
    #[must_use]
    pub fn status(&self) -> DatasetStatus {
        let snapshot = self.current.load();
        DatasetStatus {
            name: self.name.to_string(),
            kind: self.kind,
            generation: snapshot.generation,
            records: snapshot.data.records(),
            last_error: self
                .last_error
                .lock()
                .expect("dataset error mutex never poisoned")
                .clone(),
        }
    }

    /// [`Self::status`] for readers that must never wait on the owner: the
    /// error lock is taken with `try_lock`, so a busy lock reports
    /// [`TryLockError::WouldBlock`] instead of blocking the calling thread.
    /// Generation and record count come from one load of the current
    /// snapshot.
    ///
    /// # Errors
    ///
    /// `WouldBlock` while a refresh holds the error lock; `Poisoned` if a
    /// writer panicked while holding it.
    pub fn try_status(&self) -> Result<DatasetStatus, TryLockError<()>> {
        let last_error = match self.last_error.try_lock() {
            Ok(error) => error.clone(),
            Err(TryLockError::WouldBlock) => return Err(TryLockError::WouldBlock),
            Err(TryLockError::Poisoned(_)) => {
                return Err(TryLockError::Poisoned(std::sync::PoisonError::new(())));
            }
        };
        let snapshot = self.current.load();
        Ok(DatasetStatus {
            name: self.name.to_string(),
            kind: self.kind,
            generation: snapshot.generation,
            records: snapshot.data.records(),
            last_error,
        })
    }

    /// Hold the refresh-error lock, as a refresh in progress does. Test
    /// support for readers that must not wait on it.
    #[doc(hidden)]
    pub fn hold_error_lock_for_test(&self) -> std::sync::MutexGuard<'_, Option<String>> {
        self.last_error
            .lock()
            .expect("dataset error mutex never poisoned")
    }
}

/// Name → handle map a compile resolves `dataset` references through.
/// The daemon builds one from `[policy.datasets]` at config apply;
/// in-language `test` blocks build per-test ones from their `dataset`
/// overrides. Equality is by name set + handle *identity* (same
/// `Arc`), which is what config diffing needs: reusing the running
/// handles compares equal, rebinding a name to a new handle (a kind
/// change) does not — content swaps inside a handle never affect it.
#[derive(Debug, Clone, Default)]
pub struct DatasetBindings {
    handles: HashMap<String, Arc<DatasetHandle>>,
}

impl DatasetBindings {
    /// An empty binding set.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Bind `handle` under its own name, replacing any previous
    /// binding of that name.
    pub fn insert(&mut self, handle: Arc<DatasetHandle>) {
        self.handles.insert(handle.name().to_string(), handle);
    }

    /// Look up a handle by dataset name.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&Arc<DatasetHandle>> {
        self.handles.get(name)
    }

    /// Every bound handle, in unspecified order.
    pub fn handles(&self) -> impl Iterator<Item = &Arc<DatasetHandle>> {
        self.handles.values()
    }

    /// Number of bindings.
    #[must_use]
    pub fn len(&self) -> usize {
        self.handles.len()
    }

    /// True when no datasets are bound.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.handles.is_empty()
    }

    /// Copy current snapshot references into independent handles. This is for
    /// immutable config-source evidence, never config diffing. The immutable
    /// snapshot is shared until either handle is refreshed; their `ArcSwap`
    /// cells remain independent.
    #[doc(hidden)]
    #[must_use]
    pub fn detached_clone(&self) -> Self {
        let mut detached = Self::new();
        for handle in self.handles.values() {
            detached.insert(Arc::new(DatasetHandle::from_snapshot(
                handle.name(),
                handle.kind(),
                handle.pin(),
            )));
        }
        detached
    }
}

impl PartialEq for DatasetBindings {
    fn eq(&self, other: &Self) -> bool {
        self.handles.len() == other.handles.len()
            && self.handles.iter().all(|(name, handle)| {
                other
                    .handles
                    .get(name)
                    .is_some_and(|o| Arc::ptr_eq(o, handle))
            })
    }
}

impl Eq for DatasetBindings {}

/// Dataset names a compile referenced that had no binding — the
/// error [`crate::rpol::RpolFile::compile_policy`] and the test
/// runner surface when a `dataset` declaration is used but unbound.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MissingDatasets(pub Vec<String>);

impl fmt::Display for MissingDatasets {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "no binding for dataset{} {}",
            if self.0.len() == 1 { "" } else { "s" },
            self.0.join(", ")
        )
    }
}

/// Read and parse a dataset file as `kind`, enforcing the byte and
/// record bounds. This is the only filesystem touch in the dataset
/// machinery; it runs on the config-apply/SIGHUP path, never during
/// evaluation.
///
/// File format (documented in `docs/reference/rpol-language.md`): one entry per
/// line, `#` starts a comment, blank lines and surrounding whitespace
/// are ignored. Entries parse with the same literal parsers `.rpol`
/// set definitions use — a prefix entry with optional `ge`/`le`, a
/// bare u32 ASN, or a community literal of any kind.
///
/// # Errors
///
/// A human-readable description (missing/oversized/unreadable file,
/// or the first parse errors with line numbers). Callers keep the
/// prior snapshot on error.
pub fn load_dataset_file(path: &Path, kind: DatasetKind) -> Result<DatasetData, String> {
    load_dataset_file_protected(path, kind, &SourceFileProtection::default())
}

/// Read a dataset while refusing protected source files before reading bytes.
///
/// # Errors
///
/// As [`load_dataset_file`], or a protected-source refusal.
#[doc(hidden)]
pub fn load_dataset_file_protected(
    path: &Path,
    kind: DatasetKind,
    protection: &SourceFileProtection,
) -> Result<DatasetData, String> {
    let path = path
        .canonicalize()
        .map_err(|e| format!("cannot stat {}: {e}", path.display()))?;
    let bytes = read_regular_file_bounded_protected(&path, MAX_DATASET_BYTES, protection)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    let text =
        String::from_utf8(bytes).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    crate::rpol::parse_dataset_text(&text, kind)
}

#[doc(hidden)]
pub use crate::source_file::{
    MAX_BACKUP_DIRECTORY_ENTRIES, SourceFileProtection, SourceFileTarget,
};

/// Read a whole regular file holding at most `max_bytes`.
///
/// External policy inputs (`.rpol` modules, dataset files) can name
/// any path, so the reader refuses what is not a regular file before
/// it reads: the path is checked with `stat`, opened with `O_NONBLOCK`
/// (opening a FIFO for reading otherwise waits for a writer), and the
/// opened descriptor is checked again with `fstat`. The read itself is
/// capped at `max_bytes + 1` bytes, so a file that grows after the
/// check, or a size the kernel reports as zero, still cannot exceed
/// the bound.
///
/// # Errors
///
/// The open or read failure, [`std::io::ErrorKind::InvalidInput`] for
/// a FIFO, device, socket or directory, and
/// [`std::io::ErrorKind::FileTooLarge`] for a file over the bound.
#[doc(hidden)]
pub fn read_regular_file_bounded(path: &Path, max_bytes: u64) -> std::io::Result<Vec<u8>> {
    read_regular_file_bounded_protected(path, max_bytes, &SourceFileProtection::default())
}

/// Bounded regular-file read, checking the opened descriptor before reading.
///
/// # Errors
///
/// As [`read_regular_file_bounded`], or `PermissionDenied` for a protected source.
#[doc(hidden)]
pub fn read_regular_file_bounded_protected(
    path: &Path,
    max_bytes: u64,
    protection: &SourceFileProtection,
) -> std::io::Result<Vec<u8>> {
    use std::io::{Error, ErrorKind};

    let not_regular = || Error::new(ErrorKind::InvalidInput, "not a regular file");
    let too_large = || {
        Error::new(
            ErrorKind::FileTooLarge,
            format!("larger than the {max_bytes}-byte bound"),
        )
    };
    crate::source_file::mark_stat();
    let expected = std::fs::metadata(path)?;
    if !expected.is_file() {
        return Err(not_regular());
    }
    #[cfg(test)]
    tests::run_after_stat_hook();
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NONBLOCK);
    }
    let (file, meta) = if protection.is_active() {
        SourceFileProtection::open_checked(path, &expected)?
    } else {
        let file = options.open(path)?;
        let metadata = file.metadata()?;
        (file, metadata)
    };
    if !meta.is_file() {
        return Err(not_regular());
    }
    protection.check_opened(path, &meta)?;
    if meta.len() > max_bytes {
        return Err(too_large());
    }
    let mut bytes = Vec::with_capacity(usize::try_from(meta.len()).unwrap_or(0));
    crate::source_file::mark_read();
    file.take(max_bytes.saturating_add(1))
        .read_to_end(&mut bytes)?;
    protection.check_directory()?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > max_bytes {
        return Err(too_large());
    }
    Ok(bytes)
}

/// Lossless path and byte identity captured by the dataset loader.
#[doc(hidden)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DatasetFileFingerprint {
    pub canonical_path: PathBuf,
    pub raw_len: u64,
    pub raw_sha256: [u8; 32],
}

/// Canonicalize, open, and read a dataset once, then parse and return
/// metadata derived from those same bytes.
#[doc(hidden)]
pub fn load_dataset_file_captured(
    path: &Path,
    kind: DatasetKind,
) -> Result<(DatasetData, DatasetFileFingerprint), (String, Option<DatasetFileFingerprint>)> {
    let failure = |message| (message, None);
    let canonical_path = path
        .canonicalize()
        .map_err(|e| failure(format!("cannot stat {}: {e}", path.display())))?;
    let bytes = read_regular_file_bounded(&canonical_path, MAX_DATASET_BYTES)
        .map_err(|e| failure(format!("cannot read {}: {e}", path.display())))?;
    let source = DatasetFileFingerprint {
        canonical_path,
        raw_len: u64::try_from(bytes.len()).expect("bounded source length fits u64"),
        raw_sha256: Sha256::digest(&bytes).into(),
    };
    let text = String::from_utf8(bytes).map_err(|error| {
        (
            format!("cannot read {}: {error}", path.display()),
            Some(source.clone()),
        )
    })?;
    let data = crate::rpol::parse_dataset_text(&text, kind)
        .map_err(|message| (message, Some(source.clone())))?;
    Ok((data, source))
}

#[cfg(test)]
mod tests {
    use super::*;

    thread_local! {
        /// Runs once between the path `stat` and the `open` of the next
        /// bounded read on this thread, to swap the file underneath it.
        static AFTER_STAT: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
            const { std::cell::RefCell::new(None) };
    }

    pub(super) fn run_after_stat_hook() {
        if let Some(hook) = AFTER_STAT.with(|hook| hook.borrow_mut().take()) {
            hook();
        }
    }

    /// A FIFO renamed over a regular file between the `stat` and the `open`
    /// must not block the open (`O_NONBLOCK`) and must be refused by the
    /// `fstat` of the opened descriptor, not read as an empty file.
    #[cfg(unix)]
    #[test]
    fn a_fifo_swapped_in_after_the_stat_is_refused_without_blocking() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("swapped.rpol");
        std::fs::write(&path, "policy p { term t { accept } }\n").expect("write");
        let fifo = dir.path().join("pipe");
        let made = std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .expect("mkfifo");
        assert!(made.success());
        let (source, swap_from) = (path.clone(), fifo.clone());
        let read = within_deadline(move || {
            let swap_to = source.clone();
            AFTER_STAT.with(|hook| {
                *hook.borrow_mut() = Some(Box::new(move || {
                    std::fs::rename(&swap_from, &swap_to).expect("swap the FIFO in");
                }));
            });
            read_regular_file_bounded(&source, 1024).map_err(|error| error.kind())
        });
        // Release a reader blocked in open(2) so a failing run exits.
        {
            use std::os::unix::fs::OpenOptionsExt;
            let _ = std::fs::OpenOptions::new()
                .write(true)
                .custom_flags(libc::O_NONBLOCK)
                .open(&path);
        }
        let read = read.expect("the open must not block on the swapped-in FIFO");
        assert_eq!(read, Err(std::io::ErrorKind::InvalidInput));
    }

    #[cfg(unix)]
    #[test]
    fn protected_source_checks_the_opened_inode_after_a_path_swap() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("source.rpol");
        let credential = dir.path().join("credential.key");
        let replacement = dir.path().join("replacement.rpol");
        std::fs::write(&source, "safe").unwrap();
        std::fs::write(&credential, "secret").unwrap();
        std::fs::hard_link(&credential, &replacement).unwrap();
        let swapped_source = source.clone();
        AFTER_STAT.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move || {
                std::fs::rename(&replacement, &swapped_source).unwrap();
            }));
        });
        let protection = SourceFileProtection::new(vec![credential], None);
        let error = read_regular_file_bounded_protected(&source, 1024, &protection).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
    }

    #[cfg(unix)]
    #[test]
    fn protected_source_refuses_backup_symlink_swaps_after_stat() {
        for ancestor in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let config = dir.path().join("config.toml");
            std::fs::write(&config, "accepted").unwrap();
            let (_, target) = SourceFileTarget::open(&config).unwrap();
            let safe_dir = dir.path().join("safe");
            let secret_dir = dir.path().join("secrets");
            std::fs::create_dir(&safe_dir).unwrap();
            std::fs::create_dir(&secret_dir).unwrap();
            let source = safe_dir.join("source.rpol");
            std::fs::write(&source, "safe").unwrap();
            let backup = dir.path().join("config.toml.unconfirmed-old");
            std::fs::write(&backup, "secret").unwrap();
            std::fs::hard_link(&backup, secret_dir.join("source.rpol")).unwrap();
            let protection = SourceFileProtection::new(vec![config.clone()], Some(config))
                .snapshot(Some(&target))
                .unwrap();
            let swapped_source = source.clone();
            AFTER_STAT.with(|hook| {
                *hook.borrow_mut() = Some(Box::new(move || {
                    if ancestor {
                        std::fs::rename(&safe_dir, safe_dir.with_extension("old")).unwrap();
                        std::os::unix::fs::symlink(secret_dir, safe_dir).unwrap();
                    } else {
                        std::fs::remove_file(&swapped_source).unwrap();
                        std::os::unix::fs::symlink(backup, swapped_source).unwrap();
                    }
                }));
            });
            crate::source_file::take_work();
            assert!(read_regular_file_bounded_protected(&source, 1024, &protection).is_err());
            let work = crate::source_file::take_work();
            assert_eq!(work.enumeration_probes, 0);
            assert_eq!(work.entries, 0);
            assert_eq!(work.backup_opens, 0);
            assert_eq!(work.backup_stats, 0);
            assert_eq!(work.retained_identities, 0);
            assert!(work.component_inspections <= source.components().count());
            assert!(work.directory_opens <= source.components().count());
            assert_eq!(work.source_opens, usize::from(!ancestor));
            assert_eq!(work.source_stats, 1);
            assert_eq!(work.fixed_stats, 0);
            assert_eq!(work.directory_checks, 0);
            assert_eq!(work.reads, 0);
        }
    }

    /// Run `load` on its own thread and wait at most five seconds, so a
    /// reader that blocks or never finishes fails the test instead of
    /// hanging it.
    fn within_deadline<T: Send + 'static>(load: impl FnOnce() -> T + Send + 'static) -> Option<T> {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(load());
        });
        rx.recv_timeout(std::time::Duration::from_secs(5)).ok()
    }

    #[cfg(unix)]
    #[test]
    fn external_sources_refuse_fifos_and_devices_without_blocking() {
        use std::os::unix::fs::OpenOptionsExt;

        let dir = tempfile::tempdir().expect("tempdir");
        let fifo = dir.path().join("pipe.rpol");
        let made = std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .expect("mkfifo");
        assert!(made.success());
        for path in [fifo.clone(), PathBuf::from("/dev/zero")] {
            let source = path.clone();
            let rpol = within_deadline(move || {
                crate::rpol::RpolFile::load(&source, &[], 1024 * 1024)
                    .map(|_| ())
                    .map_err(|error| error.render(false))
            });
            let source = path.clone();
            let dataset =
                within_deadline(move || load_dataset_file(&source, DatasetKind::Asn).map(|_| ()));
            let source = path.clone();
            let captured = within_deadline(move || {
                load_dataset_file_captured(&source, DatasetKind::Asn)
                    .map(|_| ())
                    .map_err(|(error, _)| error)
            });
            // Release a reader blocked in open(2) so a failing run exits.
            let _ = std::fs::OpenOptions::new()
                .write(true)
                .custom_flags(libc::O_NONBLOCK)
                .open(&fifo);
            for (what, result) in [("rpol", rpol), ("dataset", dataset), ("captured", captured)] {
                let error = result
                    .unwrap_or_else(|| panic!("{what} load of {} blocked", path.display()))
                    .expect_err("not a regular file");
                assert!(error.contains("not a regular file"), "{what}: {error}");
            }
        }
    }

    #[test]
    fn bounded_read_refuses_a_file_over_the_bound() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("big");
        std::fs::write(&path, [b'#'; 65]).expect("write");
        assert_eq!(
            read_regular_file_bounded(&path, 65)
                .expect("at the bound")
                .len(),
            65
        );
        let error = read_regular_file_bounded(&path, 64).expect_err("over the bound");
        assert_eq!(error.kind(), std::io::ErrorKind::FileTooLarge);
    }

    fn asn_data(asns: &[u32]) -> DatasetData {
        DatasetData::Asn(AsnSet::new(asns.iter().copied()))
    }

    /// A held error lock makes `try_status` report `WouldBlock` rather than
    /// wait; once released it reports the same status as `status`.
    #[test]
    fn try_status_never_waits_on_the_error_lock() {
        let handle = DatasetHandle::new("customers", DatasetKind::Asn, asn_data(&[64500]));
        handle.record_error("line 3: bad");
        {
            let _held = handle.hold_error_lock_for_test();
            assert!(matches!(handle.try_status(), Err(TryLockError::WouldBlock)));
        }
        assert_eq!(handle.try_status().unwrap(), handle.status());
        assert_eq!(
            handle.try_status().unwrap().last_error.as_deref(),
            Some("line 3: bad")
        );
    }

    #[test]
    fn refresh_swaps_only_on_content_change_and_bumps_generation() {
        let handle = DatasetHandle::new("customers", DatasetKind::Asn, asn_data(&[64500, 64501]));
        assert_eq!(handle.pin().generation, 1);
        // Content-equal (reordered) data: no swap, no bump.
        assert_eq!(handle.refresh(asn_data(&[64501, 64500])), None);
        assert_eq!(handle.pin().generation, 1);
        // Changed content: swap, monotonic bump.
        assert_eq!(handle.refresh(asn_data(&[64500])), Some(2));
        let pinned = handle.pin();
        assert_eq!(pinned.generation, 2);
        assert_eq!(pinned.data.records(), 1);
    }

    #[test]
    fn failed_refresh_keeps_prior_snapshot_and_surfaces_error() {
        let handle = DatasetHandle::new("customers", DatasetKind::Asn, asn_data(&[64500]));
        let before = handle.pin();
        handle.record_error("parse error on line 3");
        // The prior snapshot still serves probes — never empty data.
        let after = handle.pin();
        assert!(Arc::ptr_eq(&before, &after));
        let status = handle.status();
        assert_eq!(status.generation, 1);
        assert_eq!(status.records, 1);
        assert_eq!(status.last_error.as_deref(), Some("parse error on line 3"));
        // The next successful refresh clears the error.
        assert_eq!(handle.refresh(asn_data(&[64500, 64502])), Some(2));
        assert_eq!(handle.status().last_error, None);
    }

    #[test]
    fn superseded_generation_survives_while_pinned() {
        let handle = DatasetHandle::new("customers", DatasetKind::Asn, asn_data(&[64500]));
        let pinned = handle.pin();
        handle.refresh(asn_data(&[64501])).expect("swapped");
        // The old pin still sees generation 1's data — a walk that
        // pinned before the swap completes on it.
        assert_eq!(pinned.generation, 1);
        match &pinned.data {
            DatasetData::Asn(set) => assert!(set.contains(64500) && !set.contains(64501)),
            other => panic!("wrong kind: {other:?}"),
        }
        assert_eq!(handle.pin().generation, 2);
    }

    #[test]
    fn bindings_equality_is_handle_identity() {
        let a = Arc::new(DatasetHandle::new(
            "customers",
            DatasetKind::Asn,
            asn_data(&[64500]),
        ));
        let mut left = DatasetBindings::new();
        left.insert(Arc::clone(&a));
        let mut right = DatasetBindings::new();
        right.insert(Arc::clone(&a));
        assert_eq!(left, right);
        // Content swap inside the shared handle: still equal.
        a.refresh(asn_data(&[64501]));
        assert_eq!(left, right);
        // A different handle under the same name (kind change /
        // rebind): unequal.
        let mut rebound = DatasetBindings::new();
        rebound.insert(Arc::new(DatasetHandle::new(
            "customers",
            DatasetKind::Asn,
            asn_data(&[64501]),
        )));
        assert_ne!(left, rebound);
    }

    #[test]
    fn detached_bindings_share_one_snapshot_then_refresh_independently() {
        let original = Arc::new(DatasetHandle::new(
            "customers",
            DatasetKind::Asn,
            asn_data(&[64500]),
        ));
        original.refresh(asn_data(&[64501])).expect("generation 2");
        let mut bindings = DatasetBindings::new();
        bindings.insert(Arc::clone(&original));

        let detached = bindings.detached_clone();
        let copy = Arc::clone(detached.get("customers").unwrap());
        assert!(!Arc::ptr_eq(&original, &copy));
        assert_eq!(copy.pin().generation, 2);
        assert!(Arc::ptr_eq(&original.pin(), &copy.pin()));

        original
            .refresh(asn_data(&[64502]))
            .expect("original swaps");
        assert_eq!(copy.pin().data, asn_data(&[64501]));
        copy.refresh(asn_data(&[64503])).expect("copy swaps");
        assert_eq!(original.pin().data, asn_data(&[64502]));
        assert_eq!(copy.pin().data, asn_data(&[64503]));
    }
}
