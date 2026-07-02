//! The `.rpol` policy-language frontend (ADR-0096 slice 2).
//!
//! Compiles `.rpol` source — `prefix-set` / `community-set`
//! definitions, `policy` blocks with named terms and parameters, and
//! in-language `test` blocks — into the public typed IR
//! ([`crate::ir`]), interning match data through a
//! [`crate::sets::SetStore`]. Nothing in the daemon consumes
//! this yet (config/API wiring is the next slice); the standalone
//! entry points are:
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

use crate::ir::CompiledChain;
use crate::sets::SetStore;

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
