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
use std::sync::{Arc, Mutex};

use arc_swap::ArcSwap;
use sha2::{Digest, Sha256};

use crate::sets::{AsnSet, CommunitySet, PrefixSet};

/// Maximum dataset file size in bytes (64 MiB). Enforced before the
/// file is read into memory.
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

    /// Number of (canonicalized) records.
    #[must_use]
    pub fn records(&self) -> usize {
        match self {
            DatasetData::Prefix(set) => set.entries().len(),
            DatasetData::Asn(set) => set.asns().len(),
            DatasetData::Community(set) => set.criteria().len(),
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
        Self {
            name: Arc::from(name),
            kind,
            current: ArcSwap::from_pointee(DatasetSnapshot {
                generation: 1,
                data,
            }),
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

    /// Deep-copy current snapshots into independent handles. This is
    /// for immutable config-source evidence, never config diffing.
    #[doc(hidden)]
    #[must_use]
    pub fn detached_clone(&self) -> Self {
        let mut detached = Self::new();
        for handle in self.handles.values() {
            detached.insert(Arc::new(DatasetHandle::new(
                handle.name(),
                handle.kind(),
                handle.pin().data.clone(),
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
/// File format (documented in `docs/rpol-language.md`): one entry per
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
    let meta =
        std::fs::metadata(path).map_err(|e| format!("cannot stat {}: {e}", path.display()))?;
    if meta.len() > MAX_DATASET_BYTES {
        return Err(format!(
            "{} is {} bytes — larger than the {MAX_DATASET_BYTES}-byte dataset bound",
            path.display(),
            meta.len()
        ));
    }
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    crate::rpol::parse_dataset_text(&text, kind)
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
    let file = std::fs::File::open(&canonical_path)
        .map_err(|e| failure(format!("cannot read {}: {e}", path.display())))?;
    let meta = file
        .metadata()
        .map_err(|e| failure(format!("cannot stat {}: {e}", path.display())))?;
    if meta.len() > MAX_DATASET_BYTES {
        return Err(failure(format!(
            "{} is {} bytes — larger than the {MAX_DATASET_BYTES}-byte dataset bound",
            path.display(),
            meta.len()
        )));
    }
    let mut bytes = Vec::with_capacity(usize::try_from(meta.len()).unwrap_or(0));
    file.take(MAX_DATASET_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| failure(format!("cannot read {}: {e}", path.display())))?;
    if bytes.len() as u64 > MAX_DATASET_BYTES {
        return Err(failure(format!(
            "{} grew larger than the {MAX_DATASET_BYTES}-byte dataset bound while reading",
            path.display()
        )));
    }
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

    fn asn_data(asns: &[u32]) -> DatasetData {
        DatasetData::Asn(AsnSet::new(asns.iter().copied()))
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
}
