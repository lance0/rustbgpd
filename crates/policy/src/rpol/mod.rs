//! The `.rpol` policy-language frontend (ADR-0096 slice 2).
//!
//! Compiles `.rpol` source — `prefix-set` / `community-set`
//! definitions, `policy` blocks with named terms and parameters, and
//! in-language `test` blocks — into the public typed IR
//! ([`crate::ir`]), interning match data through a
//! [`crate::sets::SetStore`]. The daemon consumes this through
//! [`RpolFile`] / [`RpolPolicySet`] (config `rpol_files` references
//! and the `TestPolicy` RPC); the standalone entry points are:
//!
//! - [`compile_rpol`] — source → [`CompiledChain`] (every
//!   zero-parameter policy; parameterized policies are templates
//!   monomorphized at their use sites).
//! - [`check_rpol`] — parse + typecheck + run the in-language tests;
//!   what `rbgp policy check` calls.
//! - [`run_rpol_tests`] — just the test blocks.
//!
//! The pipeline is `lex (logos) → recursive-descent parse → typecheck
//! → lower to IR`, with multi-error recovery and ariadne-rendered
//! diagnostics throughout. See `docs/rpol-language.md` for the
//! language reference and the lowering/semantics decisions.

mod ast;
mod coverage;
mod diag;
mod fmt;
mod lexer;
mod lower;
mod modules;
mod parser;
mod testing;
mod typeck;

pub use coverage::{
    CoverageReport, Lint, LintKind, PolicyCoverage, PolicyTestStatus, TermCoverage,
};
pub use diag::{Diagnostic, Diagnostics, Span, Spanned, closest_matches};
pub use fmt::{FmtError, format_rpol};
pub use modules::{
    DEFAULT_MAX_GRAPH_BYTES, LoadError, MAX_MODULE_DEPTH, MAX_MODULE_FILES, ModuleSource,
};
pub use testing::{TestFailure, TestReport};

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::datasets::{DatasetBindings, DatasetData, DatasetKind, MissingDatasets};
use crate::ir::CompiledChain;
use crate::sets::SetStore;

/// Parse dataset file text as `kind` (LAN-305) — the operator file
/// format: one entry per line, `#` comments, whitespace-tolerant,
/// entries in the exact literal grammar `.rpol` set definitions use.
/// Public for the daemon's dataset loader and the fuzz harness; see
/// [`crate::datasets::load_dataset_file`] for the file-reading wrapper.
///
/// # Errors
///
/// The first parse failure, prefixed with its 1-based line number.
pub fn parse_dataset_text(text: &str, kind: DatasetKind) -> Result<DatasetData, String> {
    parser::parse_dataset_text(text, kind)
}

/// A parsed + typechecked `.rpol` compilation unit — the main source
/// plus every module its `import` graph resolved (LAN-300) — retained
/// (with all source texts) so config chain references — including
/// parameterized call-forms like `"customer-in(200)"` — can be
/// monomorphized at chain-resolve time.
#[derive(Debug)]
pub struct RpolFile {
    /// Per-module `(path, text, imports, digest)`, indexed by the
    /// `file` field of every [`Span`]; index 0 is the main file.
    modules: Vec<ModuleSource>,
    /// The merged compilation unit (imports dissolved).
    file: ast::SourceFile,
    /// Lazily-built interned set tables for high-fanout compilation.
    /// Interning is the expensive part of lowering (IRR-scale files
    /// carry millions of prefix-set entries), and per-chain re-interning
    /// gave every daemon neighbor its own copy of the set data. The
    /// roster resolver explicitly uses this cache; the general public
    /// compiler keeps interning through its caller's `SetStore` so
    /// separately parsed files can still share content.
    tables: std::sync::OnceLock<lower::SetTables>,
}

impl RpolFile {
    /// Parse and typecheck a single `.rpol` source with no filesystem
    /// access, retaining it for later per-policy compilation. `import`
    /// declarations are compile errors here — use [`Self::load`] for
    /// file-based, import-capable loading.
    ///
    /// # Errors
    ///
    /// All lex, parse, and type errors found in one pass.
    pub fn parse(source: &str) -> Result<Self, Diagnostics> {
        let (file, _) = front(source)?;
        Ok(Self {
            modules: vec![ModuleSource::inline(source)],
            file,
            tables: std::sync::OnceLock::new(),
        })
    }

    /// Read `path`, resolve its `import` graph against the importing
    /// files' directories plus `roots` (LAN-300), and typecheck the
    /// merged unit. All budgets (depth, `max_graph_bytes` total source
    /// size, file count), path confinement, cycle and duplicate-name
    /// checks apply. `max_graph_bytes` is the total-source-byte budget
    /// for the resolved graph — the daemon threads
    /// `[policy] rpol_max_graph_bytes` through; callers with no
    /// configuration pass [`DEFAULT_MAX_GRAPH_BYTES`].
    ///
    /// # Errors
    ///
    /// [`LoadError::Io`] when the main file or a configured root is
    /// unreadable; [`LoadError::Compile`] with multi-file diagnostics
    /// otherwise.
    pub fn load(path: &Path, roots: &[PathBuf], max_graph_bytes: usize) -> Result<Self, LoadError> {
        let graph = modules::resolve(path, roots, max_graph_bytes)?;
        let type_diags = typeck::typecheck(&graph.merged);
        if !type_diags.is_empty() {
            return Err(LoadError::Compile {
                sources: graph
                    .modules
                    .iter()
                    .map(|m| (m.path.clone(), m.text.clone()))
                    .collect(),
                diagnostics: Diagnostics(type_diags),
            });
        }
        Ok(Self {
            modules: graph.modules,
            file: graph.merged,
            tables: std::sync::OnceLock::new(),
        })
    }

    /// The unit's interned set tables, built on first use.
    fn tables(&self) -> &lower::SetTables {
        self.tables
            .get_or_init(|| lower::SetTables::build(&self.file))
    }

    /// The main file's source text.
    #[must_use]
    pub fn source(&self) -> &str {
        &self.modules[0].text
    }

    /// Every module of the compilation unit in resolution (span
    /// `file`-index) order; index 0 is the main file. This is the
    /// resolved-content identity: two units are policy-equal exactly
    /// when these texts are pairwise equal (paths excluded).
    #[must_use]
    pub fn modules(&self) -> &[ModuleSource] {
        &self.modules
    }

    /// Resolved-content equality (ADR-0103 Decision 5.3): pairwise
    /// module-text equality in resolution order, display paths
    /// excluded — moving an unchanged graph to new paths is not a
    /// policy change, while an edit to any imported leaf is.
    #[must_use]
    pub fn content_eq(&self, other: &Self) -> bool {
        self.modules.len() == other.modules.len()
            && self
                .modules
                .iter()
                .zip(&other.modules)
                .all(|(a, b)| a.text == b.text)
    }

    /// Run the unit's in-language `test` blocks (from every module).
    /// Dataset references (LAN-305) resolve through each test's own
    /// `dataset NAME { ... }` overrides — tests never read operator
    /// files; a test whose policy probes an un-overridden dataset
    /// fails with a message naming it.
    #[must_use]
    pub fn run_tests(&self) -> TestReport {
        let mut store = SetStore::new();
        let mut lowerer = lower::Lowerer::from_tables(&self.file, self.tables());
        testing::run_tests(&self.file.tests, &mut lowerer, &mut store)
    }

    /// [`Self::run_tests`] additionally attributing per-term coverage
    /// over the same walks, plus the static lints — the
    /// `rbgp policy check --coverage` backend (LAN-323). Test outcomes
    /// are identical to [`Self::run_tests`]. See
    /// [`coverage`](crate::rpol::CoverageReport) for what is (and
    /// deliberately is not) attributable.
    #[must_use]
    pub fn run_tests_with_coverage(&self) -> (TestReport, CoverageReport) {
        let mut store = SetStore::new();
        let mut lowerer = lower::Lowerer::from_tables(&self.file, self.tables());
        let mut accum = coverage::CoverageAccum::new(&self.file);
        let report = testing::run_tests_recording(
            &self.file.tests,
            &mut lowerer,
            &mut store,
            Some(&mut accum),
        );
        (report, accum.finish(&self.file))
    }

    /// `(name, kind)` for every `dataset` declared in the compilation
    /// unit (main file plus imports), in source order. The daemon
    /// config validates these against `[policy.datasets]` bindings at
    /// apply time.
    pub fn dataset_decls(&self) -> impl Iterator<Item = (&str, DatasetKind)> {
        self.file
            .datasets
            .iter()
            .map(|decl| (decl.name.node.as_str(), decl.kind))
    }

    /// `(name, parameter count)` for every policy defined in the file,
    /// in source order.
    pub fn policies(&self) -> impl Iterator<Item = (&str, usize)> {
        self.file
            .policies
            .iter()
            .map(|p| (p.name.node.as_str(), p.params.len()))
    }

    /// Monomorphize one policy with concrete arguments into a
    /// single-policy [`CompiledChain`] carrying the file's set tables,
    /// binding dataset references (LAN-305) through an empty binding
    /// set — a convenience for dataset-free files (tests, benches).
    /// Returns `None` for an unknown policy name.
    ///
    /// # Panics
    ///
    /// If `args.len()` does not match the policy's declared parameter
    /// count — callers check arity first (via [`Self::policies`]) —
    /// or if the policy references a dataset (use
    /// [`Self::compile_policy_bound`] with real bindings).
    #[must_use]
    pub fn compile_policy(
        &self,
        name: &str,
        args: &[u32],
        store: &mut SetStore,
    ) -> Option<CompiledChain> {
        self.compile_policy_bound(name, args, store, &DatasetBindings::new())
            .map(|result| result.expect("policy references no datasets"))
    }

    /// [`Self::compile_policy`] with explicit dataset bindings
    /// (LAN-305): referenced-but-unbound (or kind-mismatched) datasets yield
    /// `Err` naming them. Literal sets are interned through
    /// `store`, preserving content sharing with other sources compiled through
    /// that same caller-owned store.
    ///
    /// # Panics
    ///
    /// If `args.len()` does not match the policy's declared parameter
    /// count — callers check arity first (via [`Self::policies`]).
    #[must_use]
    pub fn compile_policy_bound(
        &self,
        name: &str,
        args: &[u32],
        store: &mut SetStore,
        datasets: &DatasetBindings,
    ) -> Option<Result<CompiledChain, MissingDatasets>> {
        self.compile_policy_bound_impl(name, args, store, datasets, false)
    }

    /// High-fanout variant of [`Self::compile_policy_bound`] for a caller that
    /// deliberately wants this file's once-built literal-set tables. The
    /// caller store still interns parameter-dependent regexes, but literal
    /// prefix/community/ASN sets come from the file cache instead of being
    /// re-canonicalized for every chain.
    ///
    /// Most callers should use [`Self::compile_policy_bound`], which preserves
    /// the [`SetStore`] contract across separately parsed files. The daemon's
    /// roster resolver uses this variant because one `RpolFile` fans out to
    /// hundreds of peer chains at IRR scale.
    ///
    /// # Panics
    ///
    /// If `args.len()` does not match the policy's declared parameter count.
    #[must_use]
    pub fn compile_policy_bound_cached_tables(
        &self,
        name: &str,
        args: &[u32],
        store: &mut SetStore,
        datasets: &DatasetBindings,
    ) -> Option<Result<CompiledChain, MissingDatasets>> {
        self.compile_policy_bound_impl(name, args, store, datasets, true)
    }

    fn compile_policy_bound_impl(
        &self,
        name: &str,
        args: &[u32],
        store: &mut SetStore,
        datasets: &DatasetBindings,
        cached_tables: bool,
    ) -> Option<Result<CompiledChain, MissingDatasets>> {
        let def = self.file.policies.iter().find(|p| p.name.node == name)?;
        assert_eq!(
            def.params.len(),
            args.len(),
            "rpol chain reference arity is checked at config resolve"
        );
        let mut lowerer = if cached_tables {
            lower::Lowerer::from_tables(&self.file, self.tables())
        } else {
            lower::Lowerer::new(&self.file, store)
        };
        let chain = lowerer.instantiate_chain(name, args, store, datasets);
        let missing = lowerer.take_missing_datasets();
        Some(if missing.is_empty() {
            Ok(chain)
        } else {
            Err(MissingDatasets(missing))
        })
    }
}

/// One named `.rpol` policy available to config chain references.
#[derive(Debug, Clone)]
pub struct RpolPolicyEntry {
    /// The owning parsed file (shared across every policy it defines).
    pub file: Arc<RpolFile>,
    /// Declared parameter count (all parameters are `u32` in V1).
    pub params: usize,
    /// Display path of the source file, for error messages.
    pub path: String,
}

/// The compiled `.rpol` policy registry a loaded daemon config carries:
/// policy name → owning file + arity. Lives in this crate (not the
/// daemon's config module) so the peer manager's command surface can
/// carry it across the api/binary crate boundary.
///
/// `PartialEq` is semantic content: two loads of the same `.rpol`
/// source compare equal, an edited file compares unequal. The display
/// `path` is deliberately excluded — moving unchanged source to a new
/// path is not a policy change (the `rpol_files` TOML list diff covers
/// path edits).
#[derive(Debug, Clone, Default)]
pub struct RpolPolicySet {
    /// Policy name → registry entry.
    pub policies: HashMap<String, RpolPolicyEntry>,
}

/// Split a policy chain reference into base name + `u32` arguments:
/// `"bogon-filter"` → `("bogon-filter", [])`,
/// `"customer-in(200)"` → `("customer-in", [200])`. Used by the daemon
/// config resolver and `rbgp policy test`'s selection argument.
///
/// # Errors
///
/// A human-readable description of the malformed call-form.
pub fn parse_call_form(reference: &str) -> Result<(&str, Vec<u32>), String> {
    let Some(open) = reference.find('(') else {
        return Ok((reference, Vec::new()));
    };
    let inner = reference[open..]
        .strip_prefix('(')
        .and_then(|rest| rest.strip_suffix(')'))
        .ok_or_else(|| format!("invalid reference {reference:?}: expected `name(arg, ...)`"))?;
    let base = reference[..open].trim();
    if base.is_empty() {
        return Err(format!(
            "invalid reference {reference:?}: missing policy name before `(`"
        ));
    }
    if inner.trim().is_empty() {
        return Err(format!(
            "invalid reference {reference:?}: empty argument list — write the bare name instead"
        ));
    }
    let args = inner
        .split(',')
        .map(|arg| {
            let arg = arg.trim();
            arg.parse::<u32>().map_err(|e| {
                format!("invalid reference {reference:?}: argument {arg:?} is not a u32: {e}")
            })
        })
        .collect::<Result<Vec<u32>, _>>()?;
    Ok((base, args))
}

impl PartialEq for RpolPolicySet {
    fn eq(&self, other: &Self) -> bool {
        self.policies.len() == other.policies.len()
            && self.policies.iter().all(|(name, entry)| {
                other
                    .policies
                    .get(name)
                    .is_some_and(|o| o.params == entry.params && o.file.content_eq(&entry.file))
            })
    }
}

impl Eq for RpolPolicySet {}

/// Compile `.rpol` source into a [`CompiledChain`] holding every
/// zero-parameter policy (in source order) plus the indexed set tables
/// their guards reference. Parameterized policies typecheck here but
/// compile only where instantiated. `test` blocks are validated, not
/// run — use [`check_rpol`] for that.
///
/// # Errors
///
/// All lex, parse, and type errors found in one pass.
pub fn compile_rpol(source: &str, store: &mut SetStore) -> Result<CompiledChain, Diagnostics> {
    let (file, diags) = front(source)?;
    debug_assert!(diags.is_empty());
    let mut lowerer = lower::Lowerer::new(&file, store);
    let chain = lowerer.zero_param_chain(store, &DatasetBindings::new());
    // Inline compilation has no config to bind datasets from
    // (LAN-305): a zero-parameter policy probing one is an error here,
    // like `import` — file-based loading through the daemon config is
    // the dataset-capable path.
    let missing = lowerer.take_missing_datasets();
    if missing.is_empty() {
        Ok(chain)
    } else {
        Err(Diagnostics(vec![Diagnostic::new(
            Span::in_file(0..0, 0),
            format!(
                "inline compilation cannot bind dataset{} {}",
                if missing.len() == 1 { "" } else { "s" },
                missing.join(", ")
            ),
            "datasets need config bindings",
        )
        .with_note(
            "load this policy through the daemon config (`rpol_files` + `[policy.datasets]`), or probe it from a `test` block with a `dataset` override",
        )]))
    }
}

/// Parse, typecheck, and run the in-language `test` blocks.
///
/// # Errors
///
/// All lex, parse, and type errors found in one pass (tests do not run
/// when the file has diagnostics).
pub fn run_rpol_tests(source: &str) -> Result<TestReport, Diagnostics> {
    let (file, _) = front(source)?;
    let mut store = SetStore::new();
    let mut lowerer = lower::Lowerer::new(&file, &mut store);
    Ok(testing::run_tests(&file.tests, &mut lowerer, &mut store))
}

/// The full `rbgp policy check` result: diagnostics (empty on a clean
/// file) and, when the file compiled, the in-language test report.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CheckReport {
    /// Lex/parse/type diagnostics (empty when the file is clean).
    pub diagnostics: Diagnostics,
    /// Test results; `None` when diagnostics prevented compilation.
    pub tests: Option<TestReport>,
}

impl CheckReport {
    /// True when the file compiled cleanly and every test passed.
    #[must_use]
    pub fn is_ok(&self) -> bool {
        self.diagnostics.is_empty() && self.tests.as_ref().is_none_or(TestReport::all_passed)
    }
}

/// Parse + typecheck + run tests, without touching a daemon — the
/// backing of `rbgp policy check <file.rpol>`.
#[must_use]
pub fn check_rpol(source: &str) -> CheckReport {
    match run_rpol_tests(source) {
        Ok(tests) => CheckReport {
            diagnostics: Diagnostics::default(),
            tests: Some(tests),
        },
        Err(diagnostics) => CheckReport {
            diagnostics,
            tests: None,
        },
    }
}

/// Shared single-source frontend: lex + parse + typecheck, all
/// diagnostics combined. Inline sources cannot import (there is no
/// filesystem to resolve against — ADR-0103 Decision 7 permits compile
/// I/O only through the config loader), so `import` declarations are
/// rejected here; [`RpolFile::load`] is the import-capable path.
fn front(source: &str) -> Result<(ast::SourceFile, Vec<Diagnostic>), Diagnostics> {
    let (file, mut diags) = parser::parse(source);
    for import in &file.imports {
        diags.push(
            Diagnostic::new(
                import.span,
                "`import` is not available for inline sources",
                "imports need file-based loading",
            )
            .with_note(
                "load this policy from a file (config `rpol_files` or `rbgp policy check`) \
                 to use imports",
            ),
        );
    }
    diags.extend(typeck::typecheck(&file));
    if diags.is_empty() {
        Ok((file, Vec::new()))
    } else {
        Err(Diagnostics(diags))
    }
}

#[cfg(test)]
mod tests;
