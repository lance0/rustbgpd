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
mod diag;
mod lexer;
mod lower;
mod parser;
mod testing;
mod typeck;

pub use diag::{Diagnostic, Diagnostics, Span, Spanned};
pub use testing::{TestFailure, TestReport};

use std::collections::HashMap;
use std::sync::Arc;

use crate::ir::CompiledChain;
use crate::sets::SetStore;

/// A parsed + typechecked `.rpol` source file, retained (with its
/// source text) so config chain references — including parameterized
/// call-forms like `"customer-in(200)"` — can be monomorphized at
/// chain-resolve time.
#[derive(Debug)]
pub struct RpolFile {
    source: String,
    file: ast::SourceFile,
}

impl RpolFile {
    /// Parse and typecheck `.rpol` source, retaining it for later
    /// per-policy compilation.
    ///
    /// # Errors
    ///
    /// All lex, parse, and type errors found in one pass.
    pub fn parse(source: &str) -> Result<Self, Diagnostics> {
        let (file, _) = front(source)?;
        Ok(Self {
            source: source.to_string(),
            file,
        })
    }

    /// The original source text.
    #[must_use]
    pub fn source(&self) -> &str {
        &self.source
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
    /// single-policy [`CompiledChain`] carrying the file's set tables.
    /// Returns `None` for an unknown policy name.
    ///
    /// # Panics
    ///
    /// If `args.len()` does not match the policy's declared parameter
    /// count — callers check arity first (via [`Self::policies`]).
    #[must_use]
    pub fn compile_policy(
        &self,
        name: &str,
        args: &[u32],
        store: &mut SetStore,
    ) -> Option<CompiledChain> {
        let def = self.file.policies.iter().find(|p| p.name.node == name)?;
        assert_eq!(
            def.params.len(),
            args.len(),
            "rpol chain reference arity is checked at config resolve"
        );
        let mut lowerer = lower::Lowerer::new(&self.file, store);
        Some(lowerer.instantiate_chain(name, args, store))
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
                other.policies.get(name).is_some_and(|o| {
                    o.params == entry.params && o.file.source() == entry.file.source()
                })
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
    Ok(lowerer.zero_param_chain(store))
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

/// Shared frontend: lex + parse + typecheck, all diagnostics combined.
fn front(source: &str) -> Result<(ast::SourceFile, Vec<Diagnostic>), Diagnostics> {
    let (file, mut diags) = parser::parse(source);
    diags.extend(typeck::typecheck(&file));
    if diags.is_empty() {
        Ok((file, Vec::new()))
    } else {
        Err(Diagnostics(diags))
    }
}

#[cfg(test)]
mod tests;
