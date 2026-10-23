//! `rbgp policy ...` — wraps PolicyService gRPCs.
//!
//! - `list` / `get NAME` / `set NAME --from-file FILE` / `delete NAME`
//!   for named `[[policy_definitions]]` entries.
//! - `chain show [--neighbor ADDR]` for global or per-neighbor chains.
//! - `chain set-import (--global | --neighbor ADDR) POL...` /
//!   `chain set-export (--global | --neighbor ADDR) POL...` to install
//!   (or replace) a chain.
//! - `chain clear-import (--global | --neighbor ADDR)` /
//!   `chain clear-export (--global | --neighbor ADDR)` to drop the
//!   resolved chain entirely.

use std::io::Read;

use serde::Serialize;

use crate::commands::neighbor::{bare_ip_rpc_address, scope_address};
use crate::commands::policy_input::{JsonPolicyDefinition, load_json};
use crate::connection::{Connection, SETTLED_MUTATION_RPC_TIMEOUT, mutation_rpc, read_rpc};
use crate::error::CliError;
use crate::output::{self, outln};
use crate::proto::policy_service_client::PolicyServiceClient;
use crate::proto::{
    self, ClearGlobalExportChainRequest, ClearGlobalImportChainRequest,
    ClearNeighborExportChainRequest, ClearNeighborImportChainRequest, DeletePolicyRequest,
    ExplainImportPolicyRequest, GetGlobalPolicyChainsRequest, GetNeighborPolicyChainsRequest,
    GetPolicyRequest, GetPolicyStatsRequest, ListPoliciesRequest, SetGlobalExportChainRequest,
    SetGlobalImportChainRequest, SetNeighborExportChainRequest, SetNeighborImportChainRequest,
    SetPolicyRequest,
};

#[derive(Debug, Serialize)]
struct JsonPolicySummary {
    name: String,
    default_action: String,
    statement_count: usize,
}

#[derive(Debug, Serialize)]
struct JsonPolicyDetail {
    name: String,
    default_action: String,
    statements: Vec<JsonPolicyStatementOut>,
}

#[derive(Debug, Default, Serialize)]
struct JsonPolicyStatementOut {
    action: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    prefix: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ge: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    le: Option<u32>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    match_community: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    match_as_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    match_as_path_length_ge: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    match_as_path_length_le: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    match_rpki_validation: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    match_aspa_validation: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    match_neighbor_set: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    match_route_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    match_evpn_route_type: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    match_local_pref_ge: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    match_local_pref_le: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    match_med_ge: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    match_med_le: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    match_next_hop: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    set_local_pref: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    set_med: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    set_next_hop: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    set_community_add: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    set_community_remove: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    set_as_path_prepend: Option<JsonAsPathPrependOut>,
}

#[derive(Debug, Serialize)]
struct JsonAsPathPrependOut {
    asn: u32,
    count: u32,
}

impl From<proto::PolicyStatement> for JsonPolicyStatementOut {
    fn from(s: proto::PolicyStatement) -> Self {
        JsonPolicyStatementOut {
            action: s.action,
            prefix: s.prefix,
            ge: s.ge,
            le: s.le,
            match_community: s.match_community,
            match_as_path: s.match_as_path,
            match_as_path_length_ge: s.match_as_path_length_ge,
            match_as_path_length_le: s.match_as_path_length_le,
            match_rpki_validation: s.match_rpki_validation,
            match_aspa_validation: s.match_aspa_validation,
            match_neighbor_set: s.match_neighbor_set,
            match_route_type: s.match_route_type,
            match_evpn_route_type: s.match_evpn_route_type,
            match_local_pref_ge: s.match_local_pref_ge,
            match_local_pref_le: s.match_local_pref_le,
            match_med_ge: s.match_med_ge,
            match_med_le: s.match_med_le,
            match_next_hop: s.match_next_hop,
            set_local_pref: s.set_local_pref,
            set_med: s.set_med,
            set_next_hop: s.set_next_hop,
            set_community_add: s.set_community_add,
            set_community_remove: s.set_community_remove,
            set_as_path_prepend: s.set_as_path_prepend.map(|p| JsonAsPathPrependOut {
                asn: p.asn,
                count: p.count,
            }),
        }
    }
}

#[derive(Debug, Serialize)]
struct JsonChains {
    #[serde(skip_serializing_if = "Option::is_none")]
    neighbor: Option<String>,
    import_policy_names: Vec<String>,
    export_policy_names: Vec<String>,
}

/// Whether diagnostics on stderr may carry ANSI colour. The policy renderers
/// take a plain bool, so ask the same owo-colors decision every other
/// coloured CLI output uses: stderr is a terminal, `NO_COLOR` is unset,
/// `TERM` is not `dumb`, and `--no-color` has not set the global override.
fn stderr_color() -> bool {
    use owo_colors::{OwoColorize, Stream};
    " ".if_supports_color(Stream::Stderr, |s| s.red())
        .to_string()
        != " "
}

/// Exit code of `rbgp policy check` for compile diagnostics, an
/// unreadable file, or a failed output write.
pub const CHECK_EXIT_ERRORS: i32 = 1;
/// Exit code for a failing test, or no tests under `--fail-on-empty`.
pub const CHECK_EXIT_TESTS: i32 = 2;
/// Exit code for coverage below `--coverage-min`/`--coverage-matched-min`.
pub const CHECK_EXIT_COVERAGE: i32 = 3;
/// Exit code for a lint selected by `--deny-lints`.
pub const CHECK_EXIT_LINTS: i32 = 4;

/// The `rbgp policy check` flags.
#[derive(Debug, Default)]
pub struct CheckOptions<'a> {
    /// Extra `import` resolution roots (`--root`).
    pub roots: &'a [String],
    /// Print the resolved import graph instead of running tests.
    pub list_deps: bool,
    /// Report per-term coverage (`--coverage`).
    pub coverage: bool,
    /// `--coverage-min` threshold (implies coverage).
    pub coverage_min: Option<f64>,
    /// `--coverage-matched-min` threshold (implies coverage).
    pub coverage_matched_min: Option<f64>,
    /// `--max-graph-bytes` import-graph budget.
    pub max_graph_bytes: Option<usize>,
    /// Lints that fail the check (`--deny-lints`).
    pub deny_lints: &'a [rustbgpd_policy::rpol::LintKind],
    /// Fail when the unit defines no tests (`--fail-on-empty`).
    pub fail_on_empty: bool,
    /// Emit the `-j` document.
    pub json: bool,
}

/// `rbgp policy check <file.rpol>` — run the `.rpol` frontend
/// in-process (import resolution, parse, typecheck, in-language
/// tests, static lints); no daemon. See [`CheckOptions`] for the flags.
///
/// Returns the process exit code, in precedence order:
/// [`CHECK_EXIT_ERRORS`], [`CHECK_EXIT_TESTS`], [`CHECK_EXIT_COVERAGE`],
/// [`CHECK_EXIT_LINTS`], else 0. Diagnostics render to stderr, results
/// to stdout.
pub fn check_local(path: &str, options: &CheckOptions<'_>) -> i32 {
    check_local_with_writer(path, options, &mut std::io::stdout().lock())
}

fn check_local_with_writer(
    path: &str,
    options: &CheckOptions<'_>,
    stdout: &mut dyn std::io::Write,
) -> i32 {
    use std::path::PathBuf;

    use rustbgpd_policy::rpol::{DEFAULT_MAX_GRAPH_BYTES, LoadError, RpolFile};

    let root_paths: Vec<PathBuf> = options.roots.iter().map(PathBuf::from).collect();
    // Standalone check has no daemon config to read a budget from —
    // the default matches the daemon's `[policy] rpol_max_graph_bytes`
    // default (override with --max-graph-bytes to mirror a raised
    // daemon budget), so a file that checks clean here loads under a
    // default-budget daemon.
    let (file, diagnostics, mut findings) = match RpolFile::load(
        std::path::Path::new(path),
        &root_paths,
        options.max_graph_bytes.unwrap_or(DEFAULT_MAX_GRAPH_BYTES),
    ) {
        Ok(file) => (Some(file), Vec::new(), Vec::new()),
        Err(LoadError::Io { path, reason }) => {
            eprintln!("Error: cannot read {path}: {reason}");
            return CHECK_EXIT_ERRORS;
        }
        Err(LoadError::Compile {
            sources,
            diagnostics,
        }) => {
            if !options.json {
                eprint!("{}", diagnostics.render_sources(&sources, stderr_color()));
            }
            let sources: Vec<SourceLines<'_>> = sources
                .iter()
                .map(|(name, text)| SourceLines::new(name, text))
                .collect();
            let messages = diagnostics.0.iter().map(|d| d.message.clone()).collect();
            let findings = diagnostics
                .0
                .iter()
                .map(|d| JsonFinding::compile_error(d, &sources))
                .collect();
            (None, messages, findings)
        }
    };

    // --list-deps on a broken graph falls through to the compile
    // diagnostics below (exit 1).
    if options.list_deps
        && let Some(file) = &file
    {
        return print_deps(path, file, options.json, stdout);
    }
    let want_coverage = options.coverage
        || options.coverage_min.is_some()
        || options.coverage_matched_min.is_some();
    let (tests, cov) = match &file {
        Some(file) if want_coverage => {
            let (tests, cov) = file.run_tests_with_coverage();
            (Some(tests), Some(cov))
        }
        Some(file) => (Some(file.run_tests()), None),
        None => (None, None),
    };
    let mut denied = Vec::new();
    if let Some(file) = &file {
        let sources: Vec<SourceLines<'_>> = file
            .modules()
            .iter()
            .map(|m| SourceLines::new(&m.path, &m.text))
            .collect();
        for lint in file.lints() {
            // Text output shows only denied lints; skip locating the rest.
            if !options.json && !options.deny_lints.contains(&lint.kind) {
                continue;
            }
            let finding = JsonFinding::lint(&lint, options.deny_lints, &sources);
            if finding.severity == "error" {
                denied.push(format!(
                    "{}:{}:{}: error[{}]: {}",
                    finding.at.file,
                    finding.at.line,
                    finding.at.column,
                    finding.code,
                    finding.message
                ));
            }
            findings.push(finding);
        }
    }
    let empty_suite = options.fail_on_empty && tests.as_ref().is_some_and(|t| t.total == 0);

    if options.json {
        if let Err(error) = print_check_json(
            path,
            &diagnostics,
            &findings,
            tests.as_ref(),
            empty_suite,
            cov.as_ref(),
            file.as_ref(),
            stdout,
        ) {
            output::report_write_error("policy JSON output", &error);
            return CHECK_EXIT_ERRORS;
        }
    } else if !diagnostics.is_empty() {
        // Rendered excerpts already went to stderr above.
        eprintln!(
            "{path}: {} error{}",
            diagnostics.len(),
            if diagnostics.len() == 1 { "" } else { "s" }
        );
    } else {
        let result = (|| -> Result<(), CliError> {
            if let Some(tests) = &tests {
                if empty_suite {
                    eprintln!("{path}: no tests (--fail-on-empty)");
                } else if tests.total == 0 {
                    writeln!(stdout, "{path}: ok (no tests)")?;
                } else {
                    for failure in &tests.failures {
                        eprintln!("test {} ... FAILED: {}", failure.name, failure.message);
                    }
                    writeln!(
                        stdout,
                        "{path}: {} passed, {} failed",
                        tests.passed(),
                        tests.failures.len()
                    )?;
                }
            }
            if let (Some(cov), Some(file)) = (&cov, &file) {
                write_coverage_text(stdout, cov, file)?;
            }
            stdout.flush()?;
            Ok(())
        })();
        if report_policy_write_result(result) != 0 {
            return CHECK_EXIT_ERRORS;
        }
        for line in &denied {
            eprintln!("{line}");
        }
    }

    if !diagnostics.is_empty() {
        return CHECK_EXIT_ERRORS;
    }
    if empty_suite || tests.as_ref().is_some_and(|tests| !tests.all_passed()) {
        return CHECK_EXIT_TESTS;
    }
    if let (Some(min), Some(cov)) = (options.coverage_min, &cov)
        && cov.percent() < min
    {
        eprintln!(
            "{path}: coverage {:.1}% is below --coverage-min {min}%",
            cov.percent()
        );
        return CHECK_EXIT_COVERAGE;
    }
    if let (Some(min), Some(cov)) = (options.coverage_matched_min, &cov)
        && cov.matched_percent() < min
    {
        eprintln!(
            "{path}: matched coverage {:.1}% is below --coverage-matched-min {min}%",
            cov.matched_percent()
        );
        return CHECK_EXIT_COVERAGE;
    }
    if !denied.is_empty() {
        eprintln!(
            "{path}: {} lint{} denied by --deny-lints",
            denied.len(),
            if denied.len() == 1 { "" } else { "s" }
        );
        return CHECK_EXIT_LINTS;
    }
    0
}

/// A source position of a `-j` finding: 1-based line and column
/// (columns count Unicode scalar values); the end is exclusive.
#[derive(Debug, Serialize)]
struct JsonLocation {
    file: String,
    line: usize,
    column: usize,
    end_line: usize,
    end_column: usize,
}

/// One module's display path and text, with its line starts indexed
/// once so locating each finding costs a binary search plus a scan of
/// its own line, not a scan from the start of the file.
struct SourceLines<'a> {
    name: &'a str,
    text: &'a str,
    /// Byte offset of every line start; the first is 0.
    line_starts: Vec<usize>,
}

impl<'a> SourceLines<'a> {
    fn new(name: &'a str, text: &'a str) -> Self {
        let line_starts = std::iter::once(0)
            .chain(text.match_indices('\n').map(|(newline, _)| newline + 1))
            .collect();
        Self {
            name,
            text,
            line_starts,
        }
    }

    /// 1-based line and character column of byte `offset`, clamped to
    /// the text and to a character boundary.
    fn line_col(&self, offset: usize) -> (usize, usize) {
        let offset = self.text.floor_char_boundary(offset);
        // `line_starts[0] == 0`, so at least one start is <= offset.
        let line = self.line_starts.partition_point(|&start| start <= offset);
        let column = self.text[self.line_starts[line - 1]..offset]
            .chars()
            .count()
            + 1;
        (line, column)
    }
}

impl JsonLocation {
    /// Locate `span` in `sources` (one entry per module index), falling
    /// back to the main file like the text renderer.
    fn new(sources: &[SourceLines<'_>], span: rustbgpd_policy::rpol::Span) -> Self {
        let Some(source) = sources.get(span.file as usize).or_else(|| sources.first()) else {
            return Self {
                file: String::new(),
                line: 1,
                column: 1,
                end_line: 1,
                end_column: 1,
            };
        };
        let (line, column) = source.line_col(span.start);
        let (end_line, end_column) = source.line_col(span.end);
        Self {
            file: source.name.to_string(),
            line,
            column,
            end_line,
            end_column,
        }
    }
}

/// A secondary labelled location of a compile error.
#[derive(Debug, Serialize)]
struct JsonRelated {
    #[serde(flatten)]
    at: JsonLocation,
    label: String,
}

/// One `-j` finding: a compile error or a static lint.
#[derive(Debug, Serialize)]
struct JsonFinding {
    /// `error` (fails the check) or `warning`.
    severity: &'static str,
    /// The compiler stage code or the lint's stable name.
    code: &'static str,
    message: String,
    #[serde(flatten)]
    at: JsonLocation,
    label: Option<String>,
    notes: Vec<String>,
    related: Vec<JsonRelated>,
}

impl JsonFinding {
    fn compile_error(
        diagnostic: &rustbgpd_policy::rpol::Diagnostic,
        sources: &[SourceLines<'_>],
    ) -> Self {
        use rustbgpd_policy::rpol::Span;

        let (span, label) = diagnostic
            .labels
            .first()
            .map_or((Span::new(0..0), None), |(span, label)| {
                (*span, Some(label.clone()))
            });
        Self {
            severity: "error",
            code: diagnostic.code.label(),
            message: diagnostic.message.clone(),
            at: JsonLocation::new(sources, span),
            label,
            notes: diagnostic.notes.clone(),
            related: diagnostic
                .labels
                .iter()
                .skip(1)
                .map(|(span, label)| JsonRelated {
                    at: JsonLocation::new(sources, *span),
                    label: label.clone(),
                })
                .collect(),
        }
    }

    fn lint(
        lint: &rustbgpd_policy::rpol::Lint,
        deny: &[rustbgpd_policy::rpol::LintKind],
        sources: &[SourceLines<'_>],
    ) -> Self {
        Self {
            severity: if deny.contains(&lint.kind) {
                "error"
            } else {
                "warning"
            },
            code: lint.kind.label(),
            message: lint.message.clone(),
            at: JsonLocation::new(sources, lint.span),
            label: None,
            notes: Vec::new(),
            related: Vec::new(),
        }
    }
}

/// The `--coverage` text report (stdout): the exercised-term headline,
/// per-policy term table, and lint lines. Policies defined in an
/// imported module are attributed to their defining file.
fn write_coverage_text(
    out: &mut dyn std::io::Write,
    cov: &rustbgpd_policy::rpol::CoverageReport,
    file: &rustbgpd_policy::rpol::RpolFile,
) -> Result<(), CliError> {
    use rustbgpd_policy::rpol::PolicyTestStatus;

    writeln!(
        out,
        "coverage: {}/{} terms exercised by tests",
        cov.terms_exercised(),
        cov.terms_total()
    )?;
    writeln!(
        out,
        "matched coverage: {}/{} terms matched by tests",
        cov.terms_matched(),
        cov.terms_total()
    )?;
    let module_path = |index: u32| -> &str {
        file.modules()
            .get(index as usize)
            .map_or("", |m| m.path.as_str())
    };
    let multi_module = file.modules().len() > 1;
    for policy in &cov.policies {
        let origin = if multi_module {
            format!("  ({})", module_path(policy.file))
        } else {
            String::new()
        };
        match policy.status {
            PolicyTestStatus::Untested => {
                writeln!(
                    out,
                    "  policy {}{origin}    never referenced by any test",
                    policy.name
                )?;
                continue;
            }
            PolicyTestStatus::ApplyOnly => {
                writeln!(
                    out,
                    "  policy {}{origin}    exercised via apply only (terms not attributable)",
                    policy.name
                )?;
                continue;
            }
            PolicyTestStatus::Tested => writeln!(out, "  policy {}{origin}", policy.name)?,
        }
        let width = policy.terms.iter().map(|t| t.name.len()).max().unwrap_or(0);
        for term in &policy.terms {
            let facts = if term.evaluated == 0 {
                "never evaluated               <- earlier terms always decide".to_string()
            } else if term.matched == 0 {
                format!(
                    "evaluated {}x, never matched   <- no test route hits this",
                    term.evaluated
                )
            } else {
                format!("evaluated {}x, matched {}x", term.evaluated, term.matched)
            };
            writeln!(out, "    term {:width$}  {facts}", term.name)?;
        }
    }
    for lint in &cov.lints {
        writeln!(out, "lint [{}]: {}", lint.kind.label(), lint.message)?;
    }
    Ok(())
}

/// The `-j` form of `rbgp policy check` output, the
/// `rbgp-policy-check/1.0` document (stable keys; the `coverage` object
/// appears only under `--coverage` or either coverage threshold).
#[expect(
    clippy::too_many_arguments,
    reason = "one argument per document section; a struct would only relabel it"
)]
fn print_check_json(
    path: &str,
    diagnostics: &[String],
    findings: &[JsonFinding],
    tests: Option<&rustbgpd_policy::rpol::TestReport>,
    empty_suite: bool,
    cov: Option<&rustbgpd_policy::rpol::CoverageReport>,
    file: Option<&rustbgpd_policy::rpol::RpolFile>,
    stdout: &mut dyn std::io::Write,
) -> Result<(), CliError> {
    #[derive(Serialize)]
    struct JsonFailure<'a> {
        name: &'a str,
        message: &'a str,
    }
    #[derive(Serialize)]
    struct JsonCoverageTerm<'a> {
        name: &'a str,
        evaluated: u64,
        matched: u64,
    }
    #[derive(Serialize)]
    struct JsonCoveragePolicy<'a> {
        name: &'a str,
        file: &'a str,
        status: &'static str,
        terms: Vec<JsonCoverageTerm<'a>>,
    }
    #[derive(Serialize)]
    struct JsonLint<'a> {
        kind: &'static str,
        file: &'a str,
        message: &'a str,
    }
    #[derive(Serialize)]
    struct JsonCoverage<'a> {
        terms_total: usize,
        terms_exercised: usize,
        percent: f64,
        terms_matched: usize,
        matched_percent: f64,
        policies: Vec<JsonCoveragePolicy<'a>>,
        lints: Vec<JsonLint<'a>>,
    }
    #[derive(Serialize)]
    struct JsonCheck<'a> {
        format: &'static str,
        format_version: &'static str,
        file: &'a str,
        ok: bool,
        diagnostics: &'a [String],
        findings: &'a [JsonFinding],
        tests_total: usize,
        tests_passed: usize,
        failures: Vec<JsonFailure<'a>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        coverage: Option<JsonCoverage<'a>>,
    }
    let module_path = |index: u32| -> &str {
        file.and_then(|f| f.modules().get(index as usize))
            .map_or("", |m| m.path.as_str())
    };
    let coverage = cov.map(|cov| JsonCoverage {
        terms_total: cov.terms_total(),
        terms_exercised: cov.terms_exercised(),
        percent: cov.percent(),
        terms_matched: cov.terms_matched(),
        matched_percent: cov.matched_percent(),
        policies: cov
            .policies
            .iter()
            .map(|policy| JsonCoveragePolicy {
                name: &policy.name,
                file: module_path(policy.file),
                status: policy.status.label(),
                terms: policy
                    .terms
                    .iter()
                    .map(|term| JsonCoverageTerm {
                        name: &term.name,
                        evaluated: term.evaluated,
                        matched: term.matched,
                    })
                    .collect(),
            })
            .collect(),
        lints: cov
            .lints
            .iter()
            .map(|lint| JsonLint {
                kind: lint.kind.label(),
                file: module_path(lint.span.file),
                message: &lint.message,
            })
            .collect(),
    });
    let out = JsonCheck {
        format: "rbgp-policy-check",
        format_version: "1.0",
        file: path,
        ok: diagnostics.is_empty()
            && !empty_suite
            && tests.is_none_or(rustbgpd_policy::rpol::TestReport::all_passed),
        diagnostics,
        findings,
        tests_total: tests.map_or(0, |t| t.total),
        tests_passed: tests.map_or(0, rustbgpd_policy::rpol::TestReport::passed),
        failures: tests.map_or_else(Vec::new, |t| {
            t.failures
                .iter()
                .map(|f| JsonFailure {
                    name: &f.name,
                    message: &f.message,
                })
                .collect()
        }),
        coverage,
    };
    print_policy_json(Some(stdout), &out)
}

/// `rbgp policy check --list-deps` output: the resolved module graph
/// with content hashes, module 0 first (the main file), imports in
/// declaration order. Returns 0 when the graph and output succeed, 1
/// when stdout cannot be written.
fn print_deps(
    path: &str,
    file: &rustbgpd_policy::rpol::RpolFile,
    json: bool,
    stdout: &mut dyn std::io::Write,
) -> i32 {
    let modules = file.modules();
    if json {
        #[derive(Serialize)]
        struct JsonDep<'a> {
            path: &'a str,
            sha256: &'a str,
            imports: Vec<&'a str>,
        }
        #[derive(Serialize)]
        struct JsonDeps<'a> {
            file: &'a str,
            modules: Vec<JsonDep<'a>>,
        }
        let out = JsonDeps {
            file: path,
            modules: modules
                .iter()
                .map(|m| JsonDep {
                    path: &m.path,
                    sha256: &m.digest,
                    imports: m
                        .imports
                        .iter()
                        .map(|&id| modules[id as usize].path.as_str())
                        .collect(),
                })
                .collect(),
        };
        if let Err(error) = print_policy_json(Some(stdout), &out) {
            output::report_write_error("policy JSON output", &error);
            return 1;
        }
        return 0;
    }
    let result = (|| -> Result<(), CliError> {
        writeln!(
            stdout,
            "{path}: {} module{}",
            modules.len(),
            if modules.len() == 1 { "" } else { "s" }
        )?;
        for module in modules {
            writeln!(stdout, "  {} sha256:{}", module.path, module.digest)?;
            for &id in &module.imports {
                writeln!(stdout, "    imports {}", modules[id as usize].path)?;
            }
        }
        stdout.flush()?;
        Ok(())
    })();
    report_policy_write_result(result)
}

fn report_policy_write_result(result: Result<(), CliError>) -> i32 {
    match result {
        Ok(()) => 0,
        Err(error) => {
            output::report_write_error("policy output", &error);
            1
        }
    }
}

fn print_policy_json<T: Serialize>(
    writer: Option<&mut dyn std::io::Write>,
    value: &T,
) -> Result<(), CliError> {
    match writer {
        Some(writer) => output::write_json_pretty(writer, value),
        None => output::print_json_pretty(value),
    }
}

fn write_formatted_stdout(writer: &mut dyn std::io::Write, formatted: &str) -> i32 {
    match output::write_bytes(writer, formatted.as_bytes()) {
        Ok(()) => 0,
        Err(error) => {
            output::report_write_error("formatted policy output", &error);
            1
        }
    }
}

/// `rbgp policy fmt [--check] FILE...` — the canonical `.rpol`
/// formatter (LAN-323). Rewrites files in place via an atomic
/// write-temp-rename; `--check` rewrites nothing and prints a diff
/// for files needing formatting (CI mode); `-` reads stdin and writes
/// the formatted source to stdout (editor integration).
///
/// Returns the process exit code: 0 all files clean/formatted, 1 when
/// `--check` found differences or any file was unreadable/unformattable
/// (syntax errors — broken files are refused, never rewritten).
pub fn fmt_local(files: &[String], check: bool) -> i32 {
    use std::io::Read;

    use rustbgpd_policy::rpol::{FmtError, format_rpol};

    let mut failed = false;
    for file in files {
        let from_stdin = file == "-";
        let source = if from_stdin {
            let mut buf = String::new();
            match std::io::stdin().read_to_string(&mut buf) {
                Ok(_) => buf,
                Err(error) => {
                    eprintln!("Error: cannot read stdin: {error}");
                    failed = true;
                    continue;
                }
            }
        } else {
            match std::fs::read_to_string(file) {
                Ok(source) => source,
                Err(error) => {
                    eprintln!("Error: cannot read {file}: {error}");
                    failed = true;
                    continue;
                }
            }
        };
        let name = if from_stdin { "<stdin>" } else { file.as_str() };
        let formatted = match format_rpol(&source) {
            Ok(formatted) => formatted,
            Err(FmtError::Syntax(diags)) => {
                eprint!("{}", diags.render(name, &source, stderr_color()));
                eprintln!(
                    "{name}: not formatted ({} syntax error{} — see `rbgp policy check`)",
                    diags.len(),
                    if diags.len() == 1 { "" } else { "s" }
                );
                failed = true;
                continue;
            }
            Err(error @ FmtError::Internal(_)) => {
                eprintln!("Error: {name}: {error}");
                failed = true;
                continue;
            }
        };
        if from_stdin {
            // Stdin always streams the result; --check additionally
            // signals via the exit code without a diff dump.
            if check {
                if formatted != source {
                    eprintln!("<stdin>: needs formatting");
                    failed = true;
                }
            } else {
                failed |= write_formatted_stdout(&mut std::io::stdout(), &formatted) != 0;
            }
            continue;
        }
        if formatted == source {
            continue;
        }
        if check {
            failed = true;
            let diff = format!("Diff in {file}:\n{}", line_diff(&source, &formatted));
            if let Err(error) = output::print_text(&diff) {
                output::report_write_error("policy diff output", &error);
            }
        } else if let Err(error) = write_atomic(std::path::Path::new(file), &formatted) {
            eprintln!("Error: {error}");
            failed = true;
        }
    }
    i32::from(failed)
}

/// Rewrite through a unique sibling file, preserving permissions, syncing
/// the payload before rename and the parent directory afterward. Pre-rename
/// failures remove the temp; a directory-sync failure can report an error
/// after the target has been replaced. Errors name the destination path.
fn write_atomic(path: &std::path::Path, text: &str) -> std::io::Result<()> {
    use std::io::Write;

    let inner = || -> std::io::Result<()> {
        let permissions = std::fs::metadata(path)?.permissions();
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| std::path::Path::new("."));
        let directory = std::fs::File::open(parent)?;
        let (tmp, mut file) = create_policy_stage(parent)?;
        let result = (|| -> std::io::Result<()> {
            file.write_all(text.as_bytes())?;
            // Restore the original mode after writes, which can clear set-ID bits.
            file.set_permissions(permissions)?;
            file.sync_all()?;
            std::fs::rename(&tmp, path)
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(&tmp);
        }
        result?;
        directory.sync_all().map_err(|error| {
            std::io::Error::new(
                error.kind(),
                format!("replacement published but parent directory sync failed: {error}"),
            )
        })
    };
    inner().map_err(|error| {
        std::io::Error::new(
            error.kind(),
            format!("failed to write {}: {error}", path.display()),
        )
    })
}

/// Reserve a unique sibling; on Unix, create it with mode 0600.
fn create_policy_stage(
    parent: &std::path::Path,
) -> std::io::Result<(std::path::PathBuf, std::fs::File)> {
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    loop {
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let tmp = parent.join(format!(
            ".rbgp-policy-fmt.{}.{sequence}.tmp",
            std::process::id()
        ));
        match options.open(&tmp) {
            Ok(file) => return Ok((tmp, file)),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        }
    }
}

/// Minimal line diff (`-` old / `+` new, `@ line N` hunk markers) for
/// `fmt --check` output. LCS over lines; formatting diffs are small
/// and local, so the quadratic table is bounded by a size guard.
fn line_diff(old: &str, new: &str) -> String {
    let a: Vec<&str> = old.lines().collect();
    let b: Vec<&str> = new.lines().collect();
    if a.len().saturating_mul(b.len()) > 4_000_000 {
        return "  (file too large to diff; run `rbgp policy fmt` to rewrite it)\n".to_string();
    }
    // LCS length table.
    let mut lcs = vec![vec![0u32; b.len() + 1]; a.len() + 1];
    for i in (0..a.len()).rev() {
        for j in (0..b.len()).rev() {
            lcs[i][j] = if a[i] == b[j] {
                lcs[i + 1][j + 1] + 1
            } else {
                lcs[i + 1][j].max(lcs[i][j + 1])
            };
        }
    }
    let mut out = String::new();
    let (mut i, mut j) = (0, 0);
    let mut in_hunk = false;
    while i < a.len() || j < b.len() {
        if i < a.len() && j < b.len() && a[i] == b[j] {
            i += 1;
            j += 1;
            in_hunk = false;
            continue;
        }
        if !in_hunk {
            out.push_str(&format!("  @ line {}\n", i + 1));
            in_hunk = true;
        }
        if j >= b.len() || (i < a.len() && lcs[i + 1][j] >= lcs[i][j + 1]) {
            out.push_str(&format!("- {}\n", a[i]));
            i += 1;
        } else {
            out.push_str(&format!("+ {}\n", b[j]));
            j += 1;
        }
    }
    out
}

/// Options for `rbgp policy test` (ADR-0096 live-RIB dry run).
pub struct TestOptions<'a> {
    /// Path to the local `.rpol` file (its text is sent to the daemon).
    pub file: &'a str,
    /// Policy selection: name or call-form (`"customer-in(200)"`).
    pub policy: &'a str,
    /// `"import"` or `"export"`.
    pub direction: &'a str,
    /// Optional peer scope / export target.
    pub peer: Option<&'a str>,
    /// Optional family filter (`ipv4_unicast`, `ipv6_unicast`).
    pub family: Option<&'a str>,
    /// Max routes evaluated (0 = all).
    pub limit: u32,
    /// Max before/after diff samples.
    pub show_changes: u32,
    /// Candidate dataset NAME=PATH bindings.
    pub datasets: &'a [String],
    /// Max rejected route samples.
    pub show_rejected: u32,
}

// Bound file reads before allocation, then check the exact encoded request size.
const TEST_POLICY_MAX_REQUEST_BYTES: usize = 4 * 1024 * 1024;
const TEST_POLICY_MAX_REJECTED_SAMPLES: u32 = 1000;

fn read_test_policy_file(path: &str, limit: usize) -> Result<String, CliError> {
    let file = std::fs::File::open(path)
        .map_err(|error| CliError::Argument(format!("cannot read {path}: {error}")))?;
    let mut text = String::new();
    file.take((limit + 1) as u64)
        .read_to_string(&mut text)
        .map_err(|error| CliError::Argument(format!("cannot read {path}: {error}")))?;
    if text.len() > limit {
        return Err(CliError::Argument(format!(
            "{path} exceeds the TestPolicy request size limit"
        )));
    }
    Ok(text)
}

/// Read a candidate `.rpol` file and its NAME=PATH dataset bindings,
/// bounded together by the dry-run request size limit.
fn read_candidate_inputs(
    file: &str,
    bindings: &[String],
) -> Result<(String, Vec<proto::TestPolicyDataset>), CliError> {
    if bindings.len() > rustbgpd_policy::datasets::MAX_UNIT_DATASETS {
        return Err(CliError::Argument("too many --dataset bindings".into()));
    }
    let rpol_source = read_test_policy_file(file, TEST_POLICY_MAX_REQUEST_BYTES)?;
    let mut remaining = TEST_POLICY_MAX_REQUEST_BYTES - rpol_source.len();
    let mut names = std::collections::HashSet::new();
    let mut datasets = Vec::with_capacity(bindings.len());
    for binding in bindings {
        let (name, path) = binding.split_once('=').ok_or_else(|| {
            CliError::Argument(format!("invalid --dataset {binding:?}; expected NAME=PATH"))
        })?;
        if name.is_empty() || path.is_empty() || !names.insert(name) {
            return Err(CliError::Argument(format!(
                "invalid or duplicate --dataset {binding:?}; expected unique NAME=PATH"
            )));
        }
        remaining = remaining.checked_sub(name.len()).ok_or_else(|| {
            CliError::Argument("candidate datasets exceed the TestPolicy request size limit".into())
        })?;
        let entries = read_test_policy_file(path, remaining)?;
        remaining -= entries.len();
        datasets.push(proto::TestPolicyDataset {
            name: name.into(),
            entries,
        });
    }
    Ok((rpol_source, datasets))
}

fn dry_run_family(family: Option<&str>) -> Result<proto::AddressFamily, CliError> {
    match family {
        None => Ok(proto::AddressFamily::Unspecified),
        Some("ipv4_unicast" | "ipv4") => Ok(proto::AddressFamily::Ipv4Unicast),
        Some("ipv6_unicast" | "ipv6") => Ok(proto::AddressFamily::Ipv6Unicast),
        Some(other) => Err(CliError::Argument(format!(
            "unsupported family {other:?}; expected ipv4_unicast or ipv6_unicast"
        ))),
    }
}

#[derive(Serialize)]
struct JsonTermHits<'a> {
    term: &'a str,
    hits: u64,
}
#[derive(Serialize)]
struct JsonDiff<'a> {
    prefix: String,
    peer: &'a str,
    changes: &'a [String],
}

#[derive(Serialize)]
struct JsonRejectedRoute<'a> {
    prefix: String,
    peer: &'a str,
}
#[derive(Serialize)]
struct JsonTest<'a> {
    file: &'a str,
    policy: &'a str,
    direction: &'a str,
    compiled: bool,
    #[serde(skip_serializing_if = "str::is_empty")]
    diagnostics: &'a str,
    routes_evaluated: u64,
    accepted: u64,
    rejected: u64,
    modified: u64,
    term_hits: Vec<JsonTermHits<'a>>,
    diffs: Vec<JsonDiff<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    rejected_routes: Option<Vec<JsonRejectedRoute<'a>>>,
}

fn test_to_json<'a>(resp: &'a proto::TestPolicyResponse, opts: &TestOptions<'a>) -> JsonTest<'a> {
    JsonTest {
        file: opts.file,
        policy: opts.policy,
        direction: opts.direction,
        compiled: resp.compiled,
        diagnostics: &resp.diagnostics,
        routes_evaluated: resp.routes_evaluated,
        accepted: resp.accepted,
        rejected: resp.rejected,
        modified: resp.modified,
        term_hits: resp
            .term_hits
            .iter()
            .map(|t| JsonTermHits {
                term: &t.term,
                hits: t.hits,
            })
            .collect(),
        diffs: resp
            .diffs
            .iter()
            .map(|d| JsonDiff {
                prefix: format!("{}/{}", d.prefix, d.prefix_length),
                peer: &d.peer,
                changes: &d.changes,
            })
            .collect(),
        rejected_routes: (opts.show_rejected > 0).then(|| {
            resp.rejected_routes
                .iter()
                .map(|route| JsonRejectedRoute {
                    prefix: format!("{}/{}", route.prefix, route.prefix_length),
                    peer: &route.peer,
                })
                .collect()
        }),
    }
}

/// `rbgp policy test` — send the local `.rpol` source to the daemon
/// for a read-only dry run over a live-RIB snapshot.
pub async fn test(
    connection: Connection,
    opts: TestOptions<'_>,
    json: bool,
) -> Result<(), CliError> {
    use prost::Message;

    if opts.show_rejected > TEST_POLICY_MAX_REJECTED_SAMPLES {
        return Err(CliError::Argument(format!(
            "--show-rejected exceeds {TEST_POLICY_MAX_REJECTED_SAMPLES}"
        )));
    }
    let (rpol_source, datasets) = read_candidate_inputs(opts.file, opts.datasets)?;
    let afi_safi = dry_run_family(opts.family)?;
    let request = proto::TestPolicyRequest {
        rpol_source,
        policy: opts.policy.to_string(),
        direction: opts.direction.to_string(),
        peer: opts.peer.unwrap_or_default().to_string(),
        afi_safi: afi_safi as i32,
        limit: opts.limit,
        show_changes: opts.show_changes,
        datasets,
        show_rejected: opts.show_rejected,
    };
    if request.encoded_len() > TEST_POLICY_MAX_REQUEST_BYTES {
        return Err(CliError::Argument(
            "TestPolicy request exceeds the size limit".into(),
        ));
    }
    let mut client =
        PolicyServiceClient::with_interceptor(connection.channel(), connection.interceptor());
    let mut resp = read_rpc("TestPolicy", client.test_policy(request))
        .await?
        .into_inner();
    for diff in &mut resp.diffs {
        scope_address(&mut diff.peer, &diff.peer_interface);
    }
    for route in &mut resp.rejected_routes {
        scope_address(&mut route.peer, &route.peer_interface);
    }

    if json {
        output::print_json_pretty(&test_to_json(&resp, &opts))?;
        if !resp.compiled {
            std::process::exit(1);
        }
        return Ok(());
    }

    if !resp.compiled {
        eprint!("{}", resp.diagnostics);
        eprintln!("{}: compile failed", opts.file);
        std::process::exit(1);
    }
    outln!(
        "policy {:?} ({}) over {} route{}:",
        opts.policy,
        opts.direction,
        resp.routes_evaluated,
        if resp.routes_evaluated == 1 { "" } else { "s" }
    )?;
    outln!(
        "  accepted {}  rejected {}  modified {}",
        resp.accepted,
        resp.rejected,
        resp.modified
    )?;
    if !resp.term_hits.is_empty() {
        outln!("Term hits:")?;
        for t in &resp.term_hits {
            outln!("  {:<32} {}", t.term, t.hits)?;
        }
    }
    if !resp.diffs.is_empty() {
        outln!("Changes (up to {}):", opts.show_changes)?;
        for d in &resp.diffs {
            outln!("  {}/{} (from {}):", d.prefix, d.prefix_length, d.peer)?;
            for change in &d.changes {
                outln!("    {change}")?;
            }
        }
    }
    if opts.show_rejected > 0 {
        outln!(
            "Rejected routes (showing {} of {}):",
            resp.rejected_routes.len(),
            resp.rejected
        )?;
        for route in &resp.rejected_routes {
            outln!(
                "  {}/{} (from {})",
                route.prefix,
                route.prefix_length,
                route.peer
            )?;
        }
    }
    Ok(())
}

/// Options for `rbgp policy compare`.
#[derive(Clone, Copy)]
pub struct CompareOptions<'a> {
    /// Path to the local `.rpol` file (its text is sent to the daemon).
    pub file: &'a str,
    /// Candidate policies in chain order (names or call forms).
    pub policies: &'a [String],
    /// Installed member the single candidate policy replaces.
    pub replace: Option<&'a str>,
    /// Export target peer.
    pub peer: &'a str,
    /// Optional family filter (`ipv4_unicast`, `ipv6_unicast`).
    pub family: Option<&'a str>,
    /// Max routes evaluated (0 = all).
    pub limit: u32,
    /// Max samples per class.
    pub max_samples: u32,
    /// Candidate dataset NAME=PATH bindings.
    pub datasets: &'a [String],
}

#[derive(Serialize)]
struct JsonCompareRoute<'a> {
    prefix: String,
    peer: &'a str,
    installed_changes: &'a [String],
    candidate_changes: &'a [String],
}

#[derive(Serialize)]
struct JsonCompare<'a> {
    file: &'a str,
    peer: &'a str,
    compiled: bool,
    #[serde(skip_serializing_if = "str::is_empty")]
    diagnostics: &'a str,
    installed_chain: &'a [String],
    candidate_chain: &'a [String],
    routes_evaluated: u64,
    newly_rejected: u64,
    newly_accepted: u64,
    attributes_changed: u64,
    newly_rejected_routes: Vec<JsonCompareRoute<'a>>,
    newly_accepted_routes: Vec<JsonCompareRoute<'a>>,
    attributes_changed_routes: Vec<JsonCompareRoute<'a>>,
}

fn compare_routes_to_json(routes: &[proto::ComparePolicyRoute]) -> Vec<JsonCompareRoute<'_>> {
    routes
        .iter()
        .map(|route| JsonCompareRoute {
            prefix: format!("{}/{}", route.prefix, route.prefix_length),
            peer: &route.peer,
            installed_changes: &route.installed_changes,
            candidate_changes: &route.candidate_changes,
        })
        .collect()
}

fn compare_to_json<'a>(
    resp: &'a proto::ComparePolicyResponse,
    opts: &CompareOptions<'a>,
) -> JsonCompare<'a> {
    JsonCompare {
        file: opts.file,
        peer: opts.peer,
        compiled: resp.compiled,
        diagnostics: &resp.diagnostics,
        installed_chain: &resp.installed_chain,
        candidate_chain: &resp.candidate_chain,
        routes_evaluated: resp.routes_evaluated,
        newly_rejected: resp.newly_rejected,
        newly_accepted: resp.newly_accepted,
        attributes_changed: resp.attributes_changed,
        newly_rejected_routes: compare_routes_to_json(&resp.newly_rejected_routes),
        newly_accepted_routes: compare_routes_to_json(&resp.newly_accepted_routes),
        attributes_changed_routes: compare_routes_to_json(&resp.attributes_changed_routes),
    }
}

/// `rbgp policy compare` — compare a candidate export chain with the one
/// installed for a peer, over the live Loc-RIB.
pub async fn compare(
    connection: Connection,
    opts: CompareOptions<'_>,
    json: bool,
) -> Result<(), CliError> {
    use prost::Message;

    if opts.max_samples > TEST_POLICY_MAX_REJECTED_SAMPLES {
        return Err(CliError::Argument(format!(
            "--max-samples exceeds {TEST_POLICY_MAX_REJECTED_SAMPLES}"
        )));
    }
    if opts.replace.is_some() && opts.policies.len() != 1 {
        return Err(CliError::Argument(
            "--replace takes exactly one --policy".into(),
        ));
    }
    let (rpol_source, datasets) = read_candidate_inputs(opts.file, opts.datasets)?;
    let request = proto::ComparePolicyRequest {
        rpol_source,
        policies: opts.policies.to_vec(),
        replace_member: opts.replace.unwrap_or_default().to_string(),
        peer: opts.peer.to_string(),
        afi_safi: dry_run_family(opts.family)? as i32,
        limit: opts.limit,
        max_samples: opts.max_samples,
        datasets,
    };
    if request.encoded_len() > TEST_POLICY_MAX_REQUEST_BYTES {
        return Err(CliError::Argument(
            "ComparePolicy request exceeds the size limit".into(),
        ));
    }
    let mut client =
        PolicyServiceClient::with_interceptor(connection.channel(), connection.interceptor());
    let resp = read_rpc("ComparePolicy", client.compare_policy(request))
        .await?
        .into_inner();

    if json {
        output::print_json_pretty(&compare_to_json(&resp, &opts))?;
        if !resp.compiled {
            std::process::exit(1);
        }
        return Ok(());
    }

    if !resp.compiled {
        eprint!("{}", resp.diagnostics);
        eprintln!("{}: compile failed", opts.file);
        std::process::exit(1);
    }
    let chain = |names: &[String]| {
        if names.is_empty() {
            "(none: accept all)".to_string()
        } else {
            names.join(", ")
        }
    };
    outln!(
        "export to {} over {} route{}:",
        opts.peer,
        resp.routes_evaluated,
        if resp.routes_evaluated == 1 { "" } else { "s" }
    )?;
    outln!("  installed: {}", chain(&resp.installed_chain))?;
    outln!("  candidate: {}", chain(&resp.candidate_chain))?;
    outln!(
        "  newly rejected {}  newly accepted {}  attributes changed {}",
        resp.newly_rejected,
        resp.newly_accepted,
        resp.attributes_changed
    )?;
    for (label, total, routes) in [
        (
            "Newly rejected",
            resp.newly_rejected,
            &resp.newly_rejected_routes,
        ),
        (
            "Newly accepted",
            resp.newly_accepted,
            &resp.newly_accepted_routes,
        ),
        (
            "Attributes changed",
            resp.attributes_changed,
            &resp.attributes_changed_routes,
        ),
    ] {
        if routes.is_empty() {
            continue;
        }
        outln!("{label} (showing {} of {total}):", routes.len())?;
        for route in routes {
            outln!(
                "  {}/{} (from {})",
                route.prefix,
                route.prefix_length,
                route.peer
            )?;
            for change in &route.installed_changes {
                outln!("    installed: {change}")?;
            }
            for change in &route.candidate_changes {
                outln!("    candidate: {change}")?;
            }
        }
    }
    Ok(())
}

#[derive(Debug, Serialize)]
struct JsonPolicyStats {
    peer_address: String,
    direction: String,
    routes_evaluated: u64,
    /// Routes denied by an evaluation error since chain install
    /// (ADR-0103 Decision 4 fail-closed rail).
    eval_errors: u64,
    /// Most recent evaluation error (kind + failing policy/term);
    /// `None` when no evaluation has errored since chain install.
    #[serde(skip_serializing_if = "Option::is_none")]
    last_error: Option<String>,
    /// Identity of the chain instance the counters belong to, so
    /// counters that reset to zero read as "new chain instance", not
    /// continuous history: the install generation for import chains, the
    /// counter-instance id for export chains.
    policy_generation: u64,
    terms: Vec<JsonPolicyTermStat>,
}

#[derive(Debug, Serialize)]
struct JsonPolicyTermStat {
    policy_index: u32,
    policy: Option<String>,
    term_index: u32,
    term: Option<String>,
    hits: u64,
}

/// One external dataset status row (LAN-305).
#[derive(Debug, Serialize)]
struct JsonPolicyDataset {
    name: String,
    kind: String,
    generation: u64,
    records: u64,
    path: String,
    /// Most recent refresh failure; `None` when the last refresh
    /// succeeded. While set, the prior snapshot keeps serving probes.
    last_error: Option<String>,
}

/// Combined `rbgp policy stats --json` document (LAN-305 added the
/// dataset block alongside the chain counters).
#[derive(Debug, Serialize)]
struct JsonPolicyStatsDoc {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    incomplete_peer_addresses: Vec<String>,
    chains: Vec<JsonPolicyStats>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    datasets: Vec<JsonPolicyDataset>,
}

fn stats_to_json(
    resp: &crate::proto::GetPolicyStatsResponse,
    peer: Option<&str>,
) -> JsonPolicyStatsDoc {
    let chains: Vec<JsonPolicyStats> = resp
        .chains
        .iter()
        .map(|chain| JsonPolicyStats {
            peer_address: operator_peer_address(peer, &chain.peer_address).to_string(),
            direction: chain.direction.clone(),
            routes_evaluated: chain.routes_evaluated,
            eval_errors: chain.eval_errors,
            last_error: (!chain.last_error.is_empty()).then(|| chain.last_error.clone()),
            policy_generation: chain.policy_generation,
            terms: chain
                .terms
                .iter()
                .map(|t| JsonPolicyTermStat {
                    policy_index: t.policy_index,
                    policy: (!t.policy.is_empty()).then(|| t.policy.clone()),
                    term_index: t.term_index,
                    term: (!t.term.is_empty()).then(|| t.term.clone()),
                    hits: t.hits,
                })
                .collect(),
        })
        .collect();
    let datasets: Vec<JsonPolicyDataset> = resp
        .datasets
        .iter()
        .map(|d| JsonPolicyDataset {
            name: d.name.clone(),
            kind: d.kind.clone(),
            generation: d.generation,
            records: d.records,
            path: d.path.clone(),
            last_error: (!d.last_error.is_empty()).then(|| d.last_error.clone()),
        })
        .collect();
    JsonPolicyStatsDoc {
        chains,
        datasets,
        incomplete_peer_addresses: resp.incomplete_peer_addresses.clone(),
    }
}

/// One chain's heading line. Import chains carry their install generation
/// (bumps on every chain install, content-equal reinstalls included);
/// export chains carry their counter-instance id (new whenever the counters
/// restart).
fn stats_chain_heading(chain: &crate::proto::PolicyChainStats, peer: Option<&str>) -> String {
    let identity = if chain.direction == "import" {
        "install generation"
    } else {
        "counter instance"
    };
    format!(
        "{} {} chain — {} routes evaluated since install ({identity} {})",
        operator_peer_address(peer, &chain.peer_address),
        chain.direction,
        chain.routes_evaluated,
        chain.policy_generation
    )
}

/// `rbgp policy stats [--peer ADDR] [--direction import|export|both]`
/// — live per-term hit counters of the installed chains (ADR-0096).
pub async fn stats(
    connection: Connection,
    peer: Option<&str>,
    direction: &str,
    allow_partial: bool,
    json: bool,
) -> Result<(), CliError> {
    let mut client =
        PolicyServiceClient::with_interceptor(connection.channel(), connection.interceptor());
    let mut resp = read_rpc(
        "GetPolicyStats",
        client.get_policy_stats(GetPolicyStatsRequest {
            allow_partial,
            peer_address: peer.unwrap_or_default().to_string(),
            direction: direction.to_string(),
        }),
    )
    .await?
    .into_inner();
    for chain in &mut resp.chains {
        scope_address(&mut chain.peer_address, &chain.peer_interface);
    }

    if json {
        output::print_json_pretty(&stats_to_json(&resp, peer))?;
        return Ok(());
    }

    if !resp.incomplete_peer_addresses.is_empty() {
        outln!(
            "Partial import stats — sessions exited: {}",
            resp.incomplete_peer_addresses.join(", ")
        )?;
    }
    if resp.chains.is_empty() {
        outln!(
            "{}",
            if resp.incomplete_peer_addresses.is_empty() {
                "No installed policy chains"
            } else {
                "No policy chain counters collected"
            }
        )?;
    }
    for chain in &resp.chains {
        outln!("{}", stats_chain_heading(chain, peer))?;
        // LAN-301: evaluation errors are fail-closed denies — surface
        // the count and the most recent blame line when nonzero.
        if chain.eval_errors > 0 {
            outln!(
                "  {} route{} denied by evaluation errors (fail closed); last: {}",
                chain.eval_errors,
                if chain.eval_errors == 1 { "" } else { "s" },
                if chain.last_error.is_empty() {
                    "<unknown>"
                } else {
                    &chain.last_error
                },
            )?;
        }
        outln!("  {:<32} {:<24} HITS", "POLICY", "TERM")?;
        for t in &chain.terms {
            let policy = if t.policy.is_empty() {
                "inline".to_string()
            } else {
                t.policy.clone()
            };
            let term = if t.term.is_empty() {
                format!("statement {}", t.term_index)
            } else {
                t.term.clone()
            };
            outln!("  {policy:<32} {term:<24} {}", t.hits)?;
        }
    }
    // LAN-305: external dataset status — generation, size, and the
    // last refresh failure (prior snapshot still serving while set).
    if !resp.datasets.is_empty() {
        outln!("Datasets:")?;
        outln!(
            "  {:<24} {:<14} {:>4}  {:>8}  PATH",
            "NAME",
            "KIND",
            "GEN",
            "RECORDS"
        )?;
        for d in &resp.datasets {
            outln!(
                "  {:<24} {:<14} {:>4}  {:>8}  {}",
                d.name,
                d.kind,
                d.generation,
                d.records,
                d.path
            )?;
            if !d.last_error.is_empty() {
                outln!(
                    "    last refresh FAILED ({}); prior snapshot still serving",
                    d.last_error
                )?;
            }
        }
    }
    Ok(())
}

fn policies_to_json(resp: &proto::ListPoliciesResponse) -> Vec<JsonPolicySummary> {
    resp.policies
        .iter()
        .map(|p| JsonPolicySummary {
            name: p.name.clone(),
            default_action: p
                .definition
                .as_ref()
                .map(|d| d.default_action.clone())
                .unwrap_or_default(),
            statement_count: p
                .definition
                .as_ref()
                .map(|d| d.statements.len())
                .unwrap_or(0),
        })
        .collect()
}

pub async fn list(connection: Connection, json: bool) -> Result<(), CliError> {
    let mut client =
        PolicyServiceClient::with_interceptor(connection.channel(), connection.interceptor());
    let resp = read_rpc("ListPolicies", client.list_policies(ListPoliciesRequest {}))
        .await?
        .into_inner();

    if json {
        output::print_json_pretty(&policies_to_json(&resp))?;
    } else if resp.policies.is_empty() {
        outln!("No policies configured")?;
    } else {
        outln!("{:<32} {:<10} STATEMENTS", "NAME", "DEFAULT")?;
        for p in &resp.policies {
            let def = p.definition.as_ref();
            let default_action = def.map(|d| d.default_action.as_str()).unwrap_or("-");
            let count = def.map(|d| d.statements.len()).unwrap_or(0);
            outln!("{:<32} {:<10} {}", p.name, default_action, count)?;
        }
    }
    Ok(())
}

fn policy_to_json(resp: proto::GetPolicyResponse) -> JsonPolicyDetail {
    let def = resp.definition.unwrap_or_default();
    JsonPolicyDetail {
        name: resp.name,
        default_action: def.default_action,
        statements: def.statements.into_iter().map(Into::into).collect(),
    }
}

pub async fn get(connection: Connection, name: &str, json: bool) -> Result<(), CliError> {
    let mut client =
        PolicyServiceClient::with_interceptor(connection.channel(), connection.interceptor());
    let resp = read_rpc(
        "GetPolicy",
        client.get_policy(GetPolicyRequest {
            name: name.to_string(),
        }),
    )
    .await?
    .into_inner();

    if json {
        output::print_json_pretty(&policy_to_json(resp))?;
    } else {
        let def = resp.definition.unwrap_or_default();
        outln!("Name:           {}", resp.name)?;
        outln!("Default Action: {}", def.default_action)?;
        outln!("Statements:     {}", def.statements.len())?;
        for (i, s) in def.statements.iter().enumerate() {
            outln!("  [{i}] action={}", s.action)?;
            print_statement_details(s, "      ")?;
        }
    }
    Ok(())
}

pub async fn set(
    connection: Connection,
    name: &str,
    from_file: &str,
    json: bool,
) -> Result<(), CliError> {
    let definition: JsonPolicyDefinition = load_json(from_file)?;
    let mut client =
        PolicyServiceClient::with_interceptor(connection.channel(), connection.interceptor());
    mutation_rpc(
        "SetPolicy",
        SETTLED_MUTATION_RPC_TIMEOUT,
        &format!("`rbgp policy get {name}`"),
        client.set_policy(SetPolicyRequest {
            name: name.to_string(),
            definition: Some(definition.into()),
        }),
    )
    .await?;
    output::print_result(json, "set_policy", name, &format!("Policy {name} set"))
}

pub async fn delete(connection: Connection, name: &str, json: bool) -> Result<(), CliError> {
    let mut client =
        PolicyServiceClient::with_interceptor(connection.channel(), connection.interceptor());
    mutation_rpc(
        "DeletePolicy",
        SETTLED_MUTATION_RPC_TIMEOUT,
        &format!("`rbgp policy get {name}`"),
        client.delete_policy(DeletePolicyRequest {
            name: name.to_string(),
        }),
    )
    .await?;
    output::print_result(
        json,
        "delete_policy",
        name,
        &format!("Policy {name} deleted"),
    )
}

#[derive(Debug, Serialize)]
struct JsonImportExplainMatch {
    outcome: String,
    path_id: u32,
    matched_policy: Option<String>,
    rpki_validation: Option<String>,
    aspa_validation: Option<String>,
    modifications: Option<JsonImportExplainModifications>,
    evaluated_at_unix_ns: Option<i64>,
    policy_generation: Option<u64>,
    // Unconditional key (run-stable): empty for outcomes that carry no
    // statement trace (stale / withdrawn / evicted / not_seen /
    // cache_disabled / no_session, or a chain-less peer).
    statements: Vec<JsonImportExplainStatement>,
}

#[derive(Debug, Serialize)]
struct JsonImportExplainStatement {
    policy_index: u32,
    policy_name: Option<String>,
    // `None` when the policy fell through to its default action
    // (`default_action == true`).
    statement_index: Option<u32>,
    default_action: bool,
    action: String,
    matched_conditions: Vec<String>,
    modifications: Vec<String>,
    // rpol deciding-term name (ADR-0096); `None` for TOML statements
    // and fallthroughs.
    term: Option<String>,
    // rpol per-term trace lines; empty for TOML members.
    term_traces: Vec<String>,
}

#[derive(Debug, Serialize)]
struct JsonImportExplainModifications {
    set_local_pref: Option<u32>,
    set_med: Option<u32>,
    set_next_hop: Option<String>,
    communities_add: Vec<u32>,
    communities_remove: Vec<u32>,
    extended_communities_add: Vec<u64>,
    extended_communities_remove: Vec<u64>,
    large_communities_add: Vec<String>,
    large_communities_remove: Vec<String>,
    as_path_prepend_asn: Option<u32>,
    as_path_prepend_count: Option<u32>,
}

#[derive(Debug, Serialize)]
struct JsonImportExplain {
    peer_address: String,
    prefix: String,
    afi_safi: String,
    current_policy_generation: u64,
    // Null when the daemon did not report them (older daemon, or no
    // enabled cache answered).
    cache_size: Option<u64>,
    evictions_since_reset: Option<u64>,
    matches: Vec<JsonImportExplainMatch>,
}

/// Render a proto outcome enum as a stable lowercase operator string.
fn outcome_label(outcome: i32) -> &'static str {
    match proto::ImportExplainOutcome::try_from(outcome) {
        Ok(proto::ImportExplainOutcome::Permit) => "permit",
        Ok(proto::ImportExplainOutcome::Deny) => "deny",
        Ok(proto::ImportExplainOutcome::Withdrawn) => "withdrawn",
        Ok(proto::ImportExplainOutcome::Evicted) => "evicted",
        Ok(proto::ImportExplainOutcome::Stale) => "stale",
        Ok(proto::ImportExplainOutcome::NotSeen) => "not_seen",
        Ok(proto::ImportExplainOutcome::CacheDisabled) => "cache_disabled",
        Ok(proto::ImportExplainOutcome::NoSession) => "no_session",
        Ok(proto::ImportExplainOutcome::Unspecified) | Err(_) => "unspecified",
    }
}

/// The two LAN-320 outcomes that mean "the question could not be
/// evaluated" (as opposed to `not_seen`, which is an evaluated answer).
/// Rendered as errors with a nonzero exit; in JSON mode the response is
/// still printed first so scripts see the distinct outcome value.
fn unanswerable_error(outcome: i32, neighbor: &str) -> Option<CliError> {
    match proto::ImportExplainOutcome::try_from(outcome) {
        Ok(proto::ImportExplainOutcome::CacheDisabled) => Some(CliError::Rpc(
            "import-decision cache is disabled on this daemon (the default)\n  \
             hint: add `[policy.explain]` with `enabled = true`, reload, and let the \
             session re-establish\n  \
             cost: per session, up to `cache_size` (default 4096) entries of retained \
             decisions"
                .to_string(),
        )),
        Ok(proto::ImportExplainOutcome::NoSession) => {
            Some(CliError::Rpc(format!("no live session with {neighbor}")))
        }
        _ => None,
    }
}

/// Whether an outcome carries a recorded decision (and therefore
/// populated policy / validation / modification fields).
fn outcome_has_decision(outcome: i32) -> bool {
    matches!(
        proto::ImportExplainOutcome::try_from(outcome),
        Ok(proto::ImportExplainOutcome::Permit
            | proto::ImportExplainOutcome::Deny
            | proto::ImportExplainOutcome::Withdrawn
            | proto::ImportExplainOutcome::Stale)
    )
}

fn operator_peer_address<'a>(requested: Option<&'a str>, response: &'a str) -> &'a str {
    let Some(address) = requested else {
        return response;
    };
    let bare = bare_ip_rpc_address(address);
    if bare == address {
        return response;
    }
    match (
        bare.parse::<std::net::IpAddr>(),
        response.parse::<std::net::IpAddr>(),
    ) {
        (Ok(requested_ip), Ok(response_ip)) if requested_ip == response_ip => address,
        _ => response,
    }
}

/// Split a CIDR (`"192.0.2.0/24"` / `"2001:db8::/32"`) into the address
/// string, prefix length, and the matching `AddressFamily`. ADR-0073
/// scopes explain to IPv4 / IPv6 unicast, so the address family is
/// inferred from the prefix rather than asked for separately.
fn parse_cidr(prefix: &str) -> Result<(String, u32, proto::AddressFamily), CliError> {
    let (addr, len) = prefix
        .split_once('/')
        .ok_or_else(|| CliError::Argument(format!("--prefix must be CIDR (got {prefix:?})")))?;
    let length: u32 = len
        .parse()
        .map_err(|_| CliError::Argument(format!("invalid prefix length in {prefix:?}")))?;
    let ip: std::net::IpAddr = addr
        .parse()
        .map_err(|_| CliError::Argument(format!("invalid prefix address in {prefix:?}")))?;
    match ip {
        std::net::IpAddr::V4(_) if length <= 32 => {
            Ok((addr.to_string(), length, proto::AddressFamily::Ipv4Unicast))
        }
        std::net::IpAddr::V6(_) if length <= 128 => {
            Ok((addr.to_string(), length, proto::AddressFamily::Ipv6Unicast))
        }
        _ => Err(CliError::Argument(format!(
            "prefix length out of range for address family in {prefix:?}"
        ))),
    }
}

/// Rejection for `--path-id` with `--direction export`: the identifier
/// selects an Add-Path entry in the import-decision cache, while the
/// export dry run takes its source identity from the `rib advertised
/// --explain` flags.
pub const EXPLAIN_EXPORT_PATH_ID_ERROR: &str = "--path-id applies to --direction import only; \
     for Add-Path source selection on the export side use \
     `rib --prefix <cidr> advertised <peer> --explain --source-peer <addr> --source-path-id <id>`";

/// `rbgp policy explain --direction <import|export>`.
///
/// `import` reads the per-session import-decision cache
/// ([`explain_import`]); `export` is the read-only export dry run
/// behind `rib --prefix <cidr> advertised <peer> --explain`
/// ([`super::rib::explain_advertised`]) for the unicast, unlabeled,
/// best-source case. The CLI's `value_parser` and `validate_local_command`
/// refuse an unknown direction and `--path-id` with `export` before
/// dialing the daemon; the checks here keep this entry point honest for
/// any other caller.
pub async fn explain(
    connection: Connection,
    neighbor: &str,
    prefix: &str,
    path_id: Option<u32>,
    direction: &str,
    json: bool,
) -> Result<(), CliError> {
    match direction {
        "import" => explain_import(connection, neighbor, prefix, path_id, json).await,
        "export" if path_id.is_some() => {
            Err(CliError::Argument(EXPLAIN_EXPORT_PATH_ID_ERROR.into()))
        }
        "export" => {
            super::rib::explain_advertised(
                connection, neighbor, prefix, None, false, None, None, json,
            )
            .await
        }
        other => Err(CliError::Argument(format!(
            "unknown explain direction {other:?}; expected import or export"
        ))),
    }
}

pub async fn explain_import(
    connection: Connection,
    neighbor: &str,
    prefix: &str,
    path_id: Option<u32>,
    json: bool,
) -> Result<(), CliError> {
    let (addr, prefix_length, afi_safi) = parse_cidr(prefix)?;
    let mut client =
        PolicyServiceClient::with_interceptor(connection.channel(), connection.interceptor());
    let resp = read_rpc(
        "ExplainImportPolicy",
        client.explain_import_policy(ExplainImportPolicyRequest {
            peer_address: neighbor.to_string(),
            afi_safi: afi_safi as i32,
            prefix: addr,
            prefix_length,
            path_id,
        }),
    )
    .await?
    .into_inner();

    // LAN-320: cache-disabled / no-session mean the daemon could not
    // evaluate the question — surface an error (nonzero exit) instead
    // of a lookalike answer. These arrive as a single synthetic match.
    let unanswerable = resp
        .matches
        .iter()
        .find_map(|m| unanswerable_error(m.outcome, neighbor));

    if json {
        output::print_json_pretty(&import_explain_to_json(&resp, neighbor))?;
        // The JSON body already carries the distinct outcome; the
        // error exit still signals "not an evaluated answer".
        return match unanswerable {
            Some(err) => Err(err),
            None => Ok(()),
        };
    }
    if let Some(err) = unanswerable {
        return Err(err);
    }

    outln!(
        "import policy explain — peer {} prefix {}/{} (policy generation {})",
        operator_peer_address(Some(neighbor), &resp.peer_address),
        resp.prefix,
        resp.prefix_length,
        resp.current_policy_generation
    )?;
    if resp.matches.len() > 1 {
        outln!("{} matching paths:", resp.matches.len())?;
    }
    for m in &resp.matches {
        let path = if m.path_id == 0 {
            String::new()
        } else {
            format!(" path-id {}", m.path_id)
        };
        outln!("  {}{}", outcome_label(m.outcome), path)?;
        if outcome_has_decision(m.outcome) {
            outln!("    {}", decision_attribution_line(m))?;
            outln!(
                "    rpki:    {}    aspa: {}",
                blank_dash(&m.rpki_validation),
                blank_dash(&m.aspa_validation)
            )?;
            outln!("    eval-ns: {}", m.evaluated_at_unix_ns)?;
            if let Some(mods) = &m.modifications {
                let summary = modifications_summary(mods);
                if !summary.is_empty() {
                    outln!("    mods:    {summary}")?;
                }
            }
            for (i, s) in m.statements.iter().enumerate() {
                if i == 0 {
                    outln!("    statements:")?;
                }
                outln!("      {}", statement_line(s))?;
                for trace in &s.term_traces {
                    outln!("        {trace}")?;
                }
            }
        }
    }
    if let Some(notice) = import_explain_cache_notice(&resp) {
        outln!("{notice}")?;
    }
    Ok(())
}

fn import_explain_to_json(
    resp: &proto::ExplainImportPolicyResponse,
    neighbor: &str,
) -> JsonImportExplain {
    JsonImportExplain {
        peer_address: operator_peer_address(Some(neighbor), &resp.peer_address).to_string(),
        prefix: format!("{}/{}", resp.prefix, resp.prefix_length),
        afi_safi: address_family_label(resp.afi_safi).to_string(),
        current_policy_generation: resp.current_policy_generation,
        cache_size: resp.cache_size,
        evictions_since_reset: resp.evictions_since_reset,
        matches: resp.matches.iter().map(match_to_json).collect(),
    }
}

/// The explain cache's eviction state, printed under a text answer. A
/// daemon that does not report it may be one whose `not_seen` covers
/// evicted prefixes, so say so when that is the answer.
fn import_explain_cache_notice(resp: &proto::ExplainImportPolicyResponse) -> Option<String> {
    match (resp.cache_size, resp.evictions_since_reset) {
        (Some(size), Some(evictions)) => Some(format!(
            "  cache:   {evictions} decision(s) evicted since session reset (cache_size {size})"
        )),
        _ if resp
            .matches
            .iter()
            .any(|m| m.outcome == proto::ImportExplainOutcome::NotSeen as i32) =>
        {
            Some(
                "WARNING: this daemon does not report explain-cache evictions; \
                 not_seen may mean the decision was evicted"
                    .to_string(),
            )
        }
        _ => None,
    }
}

fn decision_attribution_line(m: &proto::ImportExplainMatch) -> String {
    if matches!(
        proto::ImportExplainOutcome::try_from(m.outcome),
        Ok(proto::ImportExplainOutcome::Permit)
    ) && m.matched_policy == rustbgpd_policy::CHAIN_DEFAULT_PERMIT_ATTRIBUTION
    {
        "decision: no policy rejected; chain default permit".to_string()
    } else {
        format!(
            "policy:  {}",
            if m.matched_policy.is_empty() {
                "inline"
            } else {
                &m.matched_policy
            }
        )
    }
}

/// One text row per statement-trace step:
/// `[0] policy lp-bump statement 1 permit  match: community 65001:100  set: local_pref 100 -> 200`
/// or, for a default-action fallthrough,
/// `[1] policy guard default-action deny`.
fn statement_line(s: &proto::ImportExplainStatementStep) -> String {
    let policy = if s.policy_name.is_empty() {
        "inline"
    } else {
        &s.policy_name
    };
    let mut line = format!("[{}] policy {policy}", s.policy_index);
    if s.default_action {
        line.push_str(&format!(" default-action {}", s.action));
        // ADR-0112: the reserved deny is daemon-supplied, and config
        // validation refuses both names to operator policies, so seeing one
        // here is proof rather than a guess. Say what it means — an operator
        // reading a bare `rfc8212_missing_import_policy` has no way to know
        // the chain is not theirs.
        if rustbgpd_policy::is_rfc8212_reserved_policy_name(&s.policy_name) {
            line.push_str("  (RFC 8212: no explicit import policy configured for this eBGP peer)");
        }
    } else if !s.term.is_empty() {
        // rpol member: the deciding term has a name.
        line.push_str(&format!(" term {} {}", s.term, s.action));
        if !s.matched_conditions.is_empty() {
            line.push_str(&format!("  match: {}", s.matched_conditions.join(", ")));
        }
        if !s.modifications.is_empty() {
            line.push_str(&format!("  set: {}", s.modifications.join(", ")));
        }
    } else {
        line.push_str(&format!(" statement {} {}", s.statement_index, s.action));
        if !s.matched_conditions.is_empty() {
            line.push_str(&format!("  match: {}", s.matched_conditions.join(", ")));
        }
        if !s.modifications.is_empty() {
            line.push_str(&format!("  set: {}", s.modifications.join(", ")));
        }
    }
    line
}

fn blank_dash(s: &str) -> &str {
    if s.is_empty() { "-" } else { s }
}

/// Map one proto match into its JSON shape. Decision-bearing fields
/// (policy / validation / modifications / timestamps) are populated
/// only for outcomes that recorded a decision; `NOT_SEEN` / `EVICTED`
/// leave them `None` so the JSON doesn't imply data that isn't there.
fn match_to_json(m: &proto::ImportExplainMatch) -> JsonImportExplainMatch {
    let has_decision = outcome_has_decision(m.outcome);
    let non_empty = |s: &str| (!s.is_empty()).then(|| s.to_string());
    JsonImportExplainMatch {
        outcome: outcome_label(m.outcome).to_string(),
        path_id: m.path_id,
        matched_policy: has_decision.then(|| non_empty(&m.matched_policy)).flatten(),
        rpki_validation: has_decision
            .then(|| non_empty(&m.rpki_validation))
            .flatten(),
        aspa_validation: has_decision
            .then(|| non_empty(&m.aspa_validation))
            .flatten(),
        modifications: if has_decision {
            m.modifications.as_ref().map(modifications_to_json)
        } else {
            None
        },
        evaluated_at_unix_ns: has_decision.then_some(m.evaluated_at_unix_ns),
        policy_generation: has_decision.then_some(m.policy_generation),
        statements: m.statements.iter().map(statement_to_json).collect(),
    }
}

fn statement_to_json(s: &proto::ImportExplainStatementStep) -> JsonImportExplainStatement {
    JsonImportExplainStatement {
        policy_index: s.policy_index,
        policy_name: (!s.policy_name.is_empty()).then(|| s.policy_name.clone()),
        statement_index: (!s.default_action).then_some(s.statement_index),
        default_action: s.default_action,
        action: s.action.clone(),
        matched_conditions: s.matched_conditions.clone(),
        modifications: s.modifications.clone(),
        term: (!s.term.is_empty()).then(|| s.term.clone()),
        term_traces: s.term_traces.clone(),
    }
}

fn address_family_label(afi_safi: i32) -> &'static str {
    match proto::AddressFamily::try_from(afi_safi) {
        Ok(proto::AddressFamily::Ipv4Unicast) => "ipv4-unicast",
        Ok(proto::AddressFamily::Ipv6Unicast) => "ipv6-unicast",
        _ => "unspecified",
    }
}

fn modifications_to_json(m: &proto::ExplainModifications) -> JsonImportExplainModifications {
    JsonImportExplainModifications {
        set_local_pref: m.set_local_pref,
        set_med: m.set_med,
        set_next_hop: Some(m.set_next_hop.clone()).filter(|s| !s.is_empty()),
        communities_add: m.communities_add.clone(),
        communities_remove: m.communities_remove.clone(),
        extended_communities_add: m.extended_communities_add.clone(),
        extended_communities_remove: m.extended_communities_remove.clone(),
        large_communities_add: m.large_communities_add.clone(),
        large_communities_remove: m.large_communities_remove.clone(),
        as_path_prepend_asn: m.as_path_prepend_asn,
        as_path_prepend_count: m.as_path_prepend_count,
    }
}

fn modifications_summary(m: &proto::ExplainModifications) -> String {
    let mut parts: Vec<String> = Vec::new();
    if let Some(lp) = m.set_local_pref {
        parts.push(format!("local_pref={lp}"));
    }
    if let Some(med) = m.set_med {
        parts.push(format!("med={med}"));
    }
    if !m.set_next_hop.is_empty() {
        parts.push(format!("next_hop={}", m.set_next_hop));
    }
    if !m.communities_add.is_empty() {
        parts.push(format!("comm+={}", m.communities_add.len()));
    }
    if !m.communities_remove.is_empty() {
        parts.push(format!("comm-={}", m.communities_remove.len()));
    }
    if !m.extended_communities_add.is_empty() {
        parts.push(format!("extcomm+={}", m.extended_communities_add.len()));
    }
    if !m.extended_communities_remove.is_empty() {
        parts.push(format!("extcomm-={}", m.extended_communities_remove.len()));
    }
    if !m.large_communities_add.is_empty() {
        parts.push(format!("largecomm+={}", m.large_communities_add.len()));
    }
    if !m.large_communities_remove.is_empty() {
        parts.push(format!("largecomm-={}", m.large_communities_remove.len()));
    }
    if let (Some(asn), Some(count)) = (m.as_path_prepend_asn, m.as_path_prepend_count) {
        parts.push(format!("prepend={asn}x{count}"));
    }
    parts.join(" ")
}

fn global_chains_to_json(resp: proto::GlobalPolicyChains) -> JsonChains {
    JsonChains {
        neighbor: None,
        import_policy_names: resp.import_policy_names,
        export_policy_names: resp.export_policy_names,
    }
}

fn neighbor_chains_to_json(resp: proto::NeighborPolicyChains, neighbor: &str) -> JsonChains {
    JsonChains {
        neighbor: Some(operator_peer_address(Some(neighbor), &resp.address).to_string()),
        import_policy_names: resp.import_policy_names,
        export_policy_names: resp.export_policy_names,
    }
}

pub async fn chain_show(
    connection: Connection,
    neighbor: Option<&str>,
    json: bool,
) -> Result<(), CliError> {
    let mut client =
        PolicyServiceClient::with_interceptor(connection.channel(), connection.interceptor());

    let out = match neighbor {
        Some(addr) => {
            let resp = read_rpc(
                "GetNeighborPolicyChains",
                client.get_neighbor_policy_chains(GetNeighborPolicyChainsRequest {
                    address: addr.to_string(),
                }),
            )
            .await?
            .into_inner();
            neighbor_chains_to_json(resp, addr)
        }
        None => {
            let resp = read_rpc(
                "GetGlobalPolicyChains",
                client.get_global_policy_chains(GetGlobalPolicyChainsRequest {}),
            )
            .await?
            .into_inner();
            global_chains_to_json(resp)
        }
    };

    if json {
        output::print_json_pretty(&out)?;
    } else {
        let scope = neighbor.unwrap_or("global");
        outln!("Scope:        {scope}")?;
        outln!(
            "Import Chain: {}",
            if out.import_policy_names.is_empty() {
                "(none)".to_string()
            } else {
                out.import_policy_names.join(" -> ")
            }
        )?;
        outln!(
            "Export Chain: {}",
            if out.export_policy_names.is_empty() {
                "(none)".to_string()
            } else {
                out.export_policy_names.join(" -> ")
            }
        )?;
    }
    Ok(())
}

pub async fn chain_set(
    connection: Connection,
    direction: ChainDirection,
    neighbor: Option<&str>,
    policy_names: Vec<String>,
    json: bool,
) -> Result<(), CliError> {
    let mut client =
        PolicyServiceClient::with_interceptor(connection.channel(), connection.interceptor());

    let (target, message) = match (direction, neighbor) {
        (ChainDirection::Import, None) => {
            mutation_rpc(
                "SetGlobalImportChain",
                SETTLED_MUTATION_RPC_TIMEOUT,
                "`rbgp policy chain show`",
                client.set_global_import_chain(SetGlobalImportChainRequest {
                    policy_names: policy_names.clone(),
                }),
            )
            .await?;
            (
                "global".to_string(),
                "Global import chain updated".to_string(),
            )
        }
        (ChainDirection::Export, None) => {
            mutation_rpc(
                "SetGlobalExportChain",
                SETTLED_MUTATION_RPC_TIMEOUT,
                "`rbgp policy chain show`",
                client.set_global_export_chain(SetGlobalExportChainRequest {
                    policy_names: policy_names.clone(),
                }),
            )
            .await?;
            (
                "global".to_string(),
                "Global export chain updated".to_string(),
            )
        }
        (ChainDirection::Import, Some(addr)) => {
            mutation_rpc(
                "SetNeighborImportChain",
                SETTLED_MUTATION_RPC_TIMEOUT,
                &format!("`rbgp policy chain show --neighbor {addr}`"),
                client.set_neighbor_import_chain(SetNeighborImportChainRequest {
                    address: addr.to_string(),
                    policy_names: policy_names.clone(),
                }),
            )
            .await?;
            (
                addr.to_string(),
                format!("Neighbor {addr} import chain updated"),
            )
        }
        (ChainDirection::Export, Some(addr)) => {
            mutation_rpc(
                "SetNeighborExportChain",
                SETTLED_MUTATION_RPC_TIMEOUT,
                &format!("`rbgp policy chain show --neighbor {addr}`"),
                client.set_neighbor_export_chain(SetNeighborExportChainRequest {
                    address: addr.to_string(),
                    policy_names: policy_names.clone(),
                }),
            )
            .await?;
            (
                addr.to_string(),
                format!("Neighbor {addr} export chain updated"),
            )
        }
    };
    output::print_result(
        json,
        match direction {
            ChainDirection::Import => "set_import_chain",
            ChainDirection::Export => "set_export_chain",
        },
        &target,
        &message,
    )
}

pub async fn chain_clear(
    connection: Connection,
    direction: ChainDirection,
    neighbor: Option<&str>,
    json: bool,
) -> Result<(), CliError> {
    let mut client =
        PolicyServiceClient::with_interceptor(connection.channel(), connection.interceptor());

    let (target, message) = match (direction, neighbor) {
        (ChainDirection::Import, None) => {
            mutation_rpc(
                "ClearGlobalImportChain",
                SETTLED_MUTATION_RPC_TIMEOUT,
                "`rbgp policy chain show`",
                client.clear_global_import_chain(ClearGlobalImportChainRequest {}),
            )
            .await?;
            (
                "global".to_string(),
                "Global import chain cleared".to_string(),
            )
        }
        (ChainDirection::Export, None) => {
            mutation_rpc(
                "ClearGlobalExportChain",
                SETTLED_MUTATION_RPC_TIMEOUT,
                "`rbgp policy chain show`",
                client.clear_global_export_chain(ClearGlobalExportChainRequest {}),
            )
            .await?;
            (
                "global".to_string(),
                "Global export chain cleared".to_string(),
            )
        }
        (ChainDirection::Import, Some(addr)) => {
            mutation_rpc(
                "ClearNeighborImportChain",
                SETTLED_MUTATION_RPC_TIMEOUT,
                &format!("`rbgp policy chain show --neighbor {addr}`"),
                client.clear_neighbor_import_chain(ClearNeighborImportChainRequest {
                    address: addr.to_string(),
                }),
            )
            .await?;
            (
                addr.to_string(),
                format!("Neighbor {addr} import chain cleared"),
            )
        }
        (ChainDirection::Export, Some(addr)) => {
            mutation_rpc(
                "ClearNeighborExportChain",
                SETTLED_MUTATION_RPC_TIMEOUT,
                &format!("`rbgp policy chain show --neighbor {addr}`"),
                client.clear_neighbor_export_chain(ClearNeighborExportChainRequest {
                    address: addr.to_string(),
                }),
            )
            .await?;
            (
                addr.to_string(),
                format!("Neighbor {addr} export chain cleared"),
            )
        }
    };
    output::print_result(
        json,
        match direction {
            ChainDirection::Import => "clear_import_chain",
            ChainDirection::Export => "clear_export_chain",
        },
        &target,
        &message,
    )
}

#[derive(Clone, Copy, Debug)]
pub enum ChainDirection {
    Import,
    Export,
}

fn print_statement_details(s: &proto::PolicyStatement, indent: &str) -> Result<(), CliError> {
    if let Some(p) = &s.prefix {
        outln!("{indent}prefix={p}")?;
    }
    if let Some(g) = s.ge {
        outln!("{indent}ge={g}")?;
    }
    if let Some(l) = s.le {
        outln!("{indent}le={l}")?;
    }
    if !s.match_community.is_empty() {
        outln!("{indent}match_community={}", s.match_community.join(","))?;
    }
    if let Some(p) = &s.match_as_path {
        outln!("{indent}match_as_path={p}")?;
    }
    if let Some(n) = &s.match_neighbor_set {
        outln!("{indent}match_neighbor_set={n}")?;
    }
    if let Some(rt) = &s.match_route_type {
        outln!("{indent}match_route_type={rt}")?;
    }
    if let Some(rt) = s.match_evpn_route_type {
        outln!("{indent}match_evpn_route_type={rt}")?;
    }
    if let Some(v) = &s.match_rpki_validation {
        outln!("{indent}match_rpki_validation={v}")?;
    }
    if let Some(v) = &s.match_aspa_validation {
        outln!("{indent}match_aspa_validation={v}")?;
    }
    if let Some(n) = &s.match_next_hop {
        outln!("{indent}match_next_hop={n}")?;
    }
    if let Some(lp) = s.set_local_pref {
        outln!("{indent}set_local_pref={lp}")?;
    }
    if let Some(med) = s.set_med {
        outln!("{indent}set_med={med}")?;
    }
    if let Some(n) = &s.set_next_hop {
        outln!("{indent}set_next_hop={n}")?;
    }
    if !s.set_community_add.is_empty() {
        outln!(
            "{indent}set_community_add={}",
            s.set_community_add.join(",")
        )?;
    }
    if !s.set_community_remove.is_empty() {
        outln!(
            "{indent}set_community_remove={}",
            s.set_community_remove.join(",")
        )?;
    }
    if let Some(p) = &s.set_as_path_prepend {
        outln!(
            "{indent}set_as_path_prepend=asn={} count={}",
            p.asn,
            p.count
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connection::connect;
    use crate::test_support::spawn_mock_server;
    use std::io::Write;

    fn complete_policy_statement() -> proto::PolicyStatement {
        // No default update: new generated fields require a projection decision.
        proto::PolicyStatement {
            action: "permit".into(),
            prefix: Some("2001:db8::/32".into()),
            ge: Some(48),
            le: Some(64),
            match_community: vec!["65001:7".into(), "BLACKHOLE".into()],
            match_as_path: Some("^65001_".into()),
            match_as_path_length_ge: Some(2),
            match_as_path_length_le: Some(9),
            match_rpki_validation: Some("valid".into()),
            match_aspa_validation: Some("invalid".into()),
            match_neighbor_set: Some("customers".into()),
            match_route_type: Some("external".into()),
            match_evpn_route_type: Some(5),
            match_local_pref_ge: Some(100),
            match_local_pref_le: Some(200),
            match_med_ge: Some(300),
            match_med_le: Some(400),
            match_next_hop: Some("2001:db8::1".into()),
            set_local_pref: Some(u32::MAX),
            set_med: Some(0),
            set_next_hop: Some("2001:db8::2".into()),
            set_community_add: vec!["65002:8".into(), "65002:9".into()],
            set_community_remove: vec!["65003:10".into()],
            set_as_path_prepend: Some(proto::AsPathPrepend {
                asn: u32::MAX,
                count: 3,
            }),
        }
    }

    #[test]
    fn policy_list_and_get_json_cover_proto_fields() {
        let empty = proto::PolicyStatement {
            action: "deny".into(),
            prefix: None,
            ge: None,
            le: None,
            match_community: vec![],
            match_as_path: None,
            match_as_path_length_ge: None,
            match_as_path_length_le: None,
            match_rpki_validation: None,
            match_aspa_validation: None,
            match_neighbor_set: None,
            match_route_type: None,
            match_evpn_route_type: None,
            match_local_pref_ge: None,
            match_local_pref_le: None,
            match_med_ge: None,
            match_med_le: None,
            match_next_hop: None,
            set_local_pref: None,
            set_med: None,
            set_next_hop: None,
            set_community_add: vec![],
            set_community_remove: vec![],
            set_as_path_prepend: None,
        };
        let mut response = proto::ListPoliciesResponse {
            policies: vec![
                proto::NamedPolicy {
                    name: "edge-in".into(),
                    definition: Some(proto::PolicyDefinition {
                        default_action: "deny".into(),
                        statements: vec![complete_policy_statement(), empty],
                    }),
                },
                proto::NamedPolicy {
                    name: "missing".into(),
                    definition: None,
                },
            ],
        };
        // List deliberately summarizes statements; get carries their full shape.
        assert_eq!(
            serde_json::to_value(policies_to_json(&response)).unwrap(),
            serde_json::json!([
                {"name": "edge-in", "default_action": "deny", "statement_count": 2},
                {"name": "missing", "default_action": "", "statement_count": 0}
            ])
        );
        let get_response = proto::GetPolicyResponse {
            name: "edge-in".into(),
            definition: response.policies.remove(0).definition,
        };
        assert_eq!(
            serde_json::to_value(policy_to_json(get_response)).unwrap(),
            serde_json::json!({
                "name": "edge-in", "default_action": "deny", "statements": [{
                    "action": "permit", "prefix": "2001:db8::/32", "ge": 48, "le": 64,
                    "match_community": ["65001:7", "BLACKHOLE"], "match_as_path": "^65001_",
                    "match_as_path_length_ge": 2, "match_as_path_length_le": 9,
                    "match_rpki_validation": "valid", "match_aspa_validation": "invalid",
                    "match_neighbor_set": "customers", "match_route_type": "external",
                    "match_evpn_route_type": 5, "match_local_pref_ge": 100,
                    "match_local_pref_le": 200, "match_med_ge": 300, "match_med_le": 400,
                    "match_next_hop": "2001:db8::1", "set_local_pref": u32::MAX,
                    "set_med": 0, "set_next_hop": "2001:db8::2",
                    "set_community_add": ["65002:8", "65002:9"],
                    "set_community_remove": ["65003:10"],
                    "set_as_path_prepend": {"asn": u32::MAX, "count": 3}
                }, {"action": "deny"}]
            })
        );
        assert_eq!(
            serde_json::to_value(policy_to_json(proto::GetPolicyResponse {
                name: "missing".into(),
                definition: None,
            }))
            .unwrap(),
            serde_json::json!({"name": "missing", "default_action": "", "statements": []})
        );
        response.policies.clear();
        assert_eq!(
            serde_json::to_value(policies_to_json(&response)).unwrap(),
            serde_json::json!([])
        );
    }

    #[test]
    fn policy_test_json_covers_proto_fields() {
        let mut opts = TestOptions {
            file: "edge.rpol",
            policy: "edge-in(200)",
            direction: "import",
            peer: Some("192.0.2.9"),
            family: Some("ipv6_unicast"),
            limit: 17,
            show_changes: 2,
            datasets: &[],
            show_rejected: 0,
        };
        let mut response = proto::TestPolicyResponse {
            compiled: true,
            diagnostics: "retained diagnostic".into(),
            routes_evaluated: u64::MAX,
            accepted: 101,
            rejected: 23,
            modified: 7,
            term_hits: vec![
                proto::TestPolicyTermHits {
                    term: "accept-customer".into(),
                    hits: u64::MAX,
                },
                proto::TestPolicyTermHits {
                    term: "deny-rest".into(),
                    hits: 23,
                },
            ],
            diffs: vec![proto::TestPolicyDiff {
                prefix: "2001:db8::".into(),
                prefix_length: 48,
                peer: "192.0.2.9".into(),
                peer_interface: String::new(),
                changes: vec![
                    "local_pref 100 -> 200".into(),
                    "communities + 65001:7".into(),
                ],
            }],
            ..Default::default()
        };
        // Request filters/bounds are not response fields; only file/policy/direction
        // annotate the RPC's counters and diffs in this curated document.
        assert_eq!(
            serde_json::to_value(test_to_json(&response, &opts)).unwrap(),
            serde_json::json!({
                "file": "edge.rpol", "policy": "edge-in(200)", "direction": "import",
                "compiled": true, "diagnostics": "retained diagnostic", "routes_evaluated": u64::MAX,
                "accepted": 101, "rejected": 23, "modified": 7,
                "term_hits": [{"term": "accept-customer", "hits": u64::MAX}, {"term": "deny-rest", "hits": 23}],
                "diffs": [{"prefix": "2001:db8::/48", "peer": "192.0.2.9",
                    "changes": ["local_pref 100 -> 200", "communities + 65001:7"]}]
            })
        );
        opts.show_rejected = 2;
        response.rejected_routes = vec![proto::TestPolicyRejectedRoute {
            prefix: "192.0.2.0".into(),
            prefix_length: 24,
            peer: "192.0.2.9".into(),
            peer_interface: String::new(),
        }];
        let json = serde_json::to_value(test_to_json(&response, &opts)).unwrap();
        assert_eq!(
            json["rejected_routes"],
            serde_json::json!([
                {"prefix": "192.0.2.0/24", "peer": "192.0.2.9"}
            ])
        );
        opts.show_rejected = 0;
        response.rejected_routes.clear();
        response.compiled = false;
        response.diagnostics.clear();
        response.routes_evaluated = 0;
        response.accepted = 0;
        response.rejected = 0;
        response.modified = 0;
        response.term_hits.clear();
        response.diffs.clear();
        assert_eq!(
            serde_json::to_value(test_to_json(&response, &opts)).unwrap(),
            serde_json::json!({
                "file": "edge.rpol", "policy": "edge-in(200)", "direction": "import",
                "compiled": false, "routes_evaluated": 0, "accepted": 0, "rejected": 0,
                "modified": 0, "term_hits": [], "diffs": []
            })
        );
    }

    #[test]
    fn import_explain_json_covers_proto_fields() {
        let mut response = proto::ExplainImportPolicyResponse {
            peer_interface: Default::default(),
            peer_address: "fe80::9".into(),
            prefix: "2001:db8::".into(),
            prefix_length: 48,
            afi_safi: proto::AddressFamily::Ipv6Unicast as i32,
            current_policy_generation: u64::MAX,
            cache_size: Some(u64::MAX),
            evictions_since_reset: Some(u64::MAX),
            matches: vec![proto::ImportExplainMatch {
                peer_interface: Default::default(),
                outcome: proto::ImportExplainOutcome::Permit as i32,
                // Per-match identity repeats the response envelope in normal RPC
                // replies and is deliberately omitted by this curated projection.
                peer_address: "192.0.2.99".into(),
                prefix: "198.51.100.0".into(),
                prefix_length: 24,
                afi_safi: proto::AddressFamily::Ipv4Unicast as i32,
                path_id: u32::MAX,
                matched_policy: "edge-in".into(),
                rpki_validation: "valid".into(),
                aspa_validation: "unknown".into(),
                evaluated_at_unix_ns: i64::MAX,
                policy_generation: u64::MAX - 1,
                modifications: Some(proto::ExplainModifications {
                    set_local_pref: Some(u32::MAX),
                    set_med: Some(0),
                    set_next_hop: "2001:db8::2".into(),
                    communities_add: vec![u32::MAX, 0],
                    communities_remove: vec![7],
                    extended_communities_add: vec![u64::MAX, 0],
                    extended_communities_remove: vec![9],
                    large_communities_add: vec!["65001:1:2".into()],
                    large_communities_remove: vec!["65002:3:4".into()],
                    as_path_prepend_asn: Some(u32::MAX - 1),
                    as_path_prepend_count: Some(3),
                }),
                statements: vec![proto::ImportExplainStatementStep {
                    policy_index: 2,
                    policy_name: "edge-in".into(),
                    default_action: false,
                    statement_index: 5,
                    action: "permit".into(),
                    matched_conditions: vec!["prefix 2001:db8::/32".into(), "rpki valid".into()],
                    modifications: vec!["med 100 -> 0".into()],
                    term: "accept-customer".into(),
                    term_traces: vec!["condition matched".into(), "action permit".into()],
                }],
            }],
        };
        let expected_match = serde_json::json!({
            "outcome": "permit", "path_id": u32::MAX, "matched_policy": "edge-in",
            "rpki_validation": "valid", "aspa_validation": "unknown",
            "evaluated_at_unix_ns": i64::MAX, "policy_generation": u64::MAX - 1,
            "modifications": {
                "set_local_pref": u32::MAX, "set_med": 0, "set_next_hop": "2001:db8::2",
                "communities_add": [u32::MAX, 0], "communities_remove": [7],
                "extended_communities_add": [u64::MAX, 0], "extended_communities_remove": [9],
                "large_communities_add": ["65001:1:2"], "large_communities_remove": ["65002:3:4"],
                "as_path_prepend_asn": u32::MAX - 1, "as_path_prepend_count": 3
            },
            "statements": [{"policy_index": 2, "policy_name": "edge-in", "default_action": false,
                "statement_index": 5, "action": "permit",
                "matched_conditions": ["prefix 2001:db8::/32", "rpki valid"],
                "modifications": ["med 100 -> 0"], "term": "accept-customer",
                "term_traces": ["condition matched", "action permit"]}]
        });
        assert_eq!(
            serde_json::to_value(import_explain_to_json(&response, "fe80::9%eth0")).unwrap(),
            serde_json::json!({"peer_address": "fe80::9%eth0", "prefix": "2001:db8::/48",
                "afi_safi": "ipv6-unicast", "current_policy_generation": u64::MAX,
                "cache_size": u64::MAX, "evictions_since_reset": u64::MAX,
                "matches": [expected_match.clone()]})
        );
        for (outcome, label) in [
            (proto::ImportExplainOutcome::Deny, "deny"),
            (proto::ImportExplainOutcome::Withdrawn, "withdrawn"),
            (proto::ImportExplainOutcome::Stale, "stale"),
        ] {
            response.matches[0].outcome = outcome as i32;
            let mut expected = expected_match.clone();
            expected["outcome"] = label.into();
            assert_eq!(
                serde_json::to_value(match_to_json(&response.matches[0])).unwrap(),
                expected
            );
        }
        response.matches[0].statements.clear();
        for (outcome, label) in [
            (
                proto::ImportExplainOutcome::Unspecified as i32,
                "unspecified",
            ),
            (proto::ImportExplainOutcome::NotSeen as i32, "not_seen"),
            (proto::ImportExplainOutcome::Evicted as i32, "evicted"),
            (
                proto::ImportExplainOutcome::CacheDisabled as i32,
                "cache_disabled",
            ),
            (proto::ImportExplainOutcome::NoSession as i32, "no_session"),
            (999, "unspecified"),
        ] {
            response.matches[0].outcome = outcome;
            // Even populated proto decision fields must not imply a recorded
            // decision for these outcomes. Null is part of the existing shape.
            assert_eq!(
                serde_json::to_value(match_to_json(&response.matches[0])).unwrap(),
                serde_json::json!({"outcome": label, "path_id": u32::MAX,
                    "matched_policy": null, "rpki_validation": null, "aspa_validation": null,
                    "modifications": null, "evaluated_at_unix_ns": null,
                    "policy_generation": null, "statements": []})
            );
        }
        response.matches[0].outcome = proto::ImportExplainOutcome::Permit as i32;
        response.matches[0].matched_policy.clear();
        response.matches[0].rpki_validation.clear();
        response.matches[0].aspa_validation.clear();
        response.matches[0].modifications = None;
        response.matches[0].evaluated_at_unix_ns = i64::MIN;
        response.matches[0].policy_generation = 0;
        assert_eq!(
            serde_json::to_value(match_to_json(&response.matches[0])).unwrap(),
            serde_json::json!({"outcome": "permit", "path_id": u32::MAX,
                "matched_policy": null, "rpki_validation": null, "aspa_validation": null,
                "modifications": null, "evaluated_at_unix_ns": i64::MIN,
                "policy_generation": 0, "statements": []})
        );
        response.matches.clear();
        response.afi_safi = 999;
        response.cache_size = None;
        response.evictions_since_reset = None;
        assert_eq!(
            serde_json::to_value(import_explain_to_json(&response, "fe80::10%eth1")).unwrap(),
            serde_json::json!({"peer_address": "fe80::9", "prefix": "2001:db8::/48",
                "afi_safi": "unspecified", "current_policy_generation": u64::MAX,
                "cache_size": null, "evictions_since_reset": null, "matches": []})
        );

        let fallthrough = proto::ImportExplainStatementStep {
            policy_index: 0,
            policy_name: String::new(),
            default_action: true,
            statement_index: 17,
            action: "deny".into(),
            matched_conditions: vec![],
            modifications: vec![],
            term: String::new(),
            term_traces: vec![],
        };
        assert_eq!(
            serde_json::to_value(statement_to_json(&fallthrough)).unwrap(),
            serde_json::json!({
                "policy_index": 0, "policy_name": null, "default_action": true, "statement_index": null,
                "action": "deny", "matched_conditions": [], "modifications": [], "term": null, "term_traces": []
            })
        );
        let empty_modifications = proto::ExplainModifications {
            set_local_pref: None,
            set_med: None,
            set_next_hop: String::new(),
            communities_add: vec![],
            communities_remove: vec![],
            extended_communities_add: vec![],
            extended_communities_remove: vec![],
            large_communities_add: vec![],
            large_communities_remove: vec![],
            as_path_prepend_asn: None,
            as_path_prepend_count: None,
        };
        assert_eq!(
            serde_json::to_value(modifications_to_json(&empty_modifications)).unwrap(),
            serde_json::json!({"set_local_pref": null, "set_med": null, "set_next_hop": null,
                "communities_add": [], "communities_remove": [], "extended_communities_add": [],
                "extended_communities_remove": [], "large_communities_add": [], "large_communities_remove": [],
                "as_path_prepend_asn": null, "as_path_prepend_count": null})
        );
    }

    #[test]
    fn policy_chain_json_covers_proto_fields() {
        let global = proto::GlobalPolicyChains {
            import_policy_names: vec!["customer-in".into(), "hygiene".into()],
            export_policy_names: vec!["customer-out".into(), "customer-out".into()],
        };
        assert_eq!(
            serde_json::to_value(global_chains_to_json(global)).unwrap(),
            serde_json::json!({
                "import_policy_names": ["customer-in", "hygiene"],
                "export_policy_names": ["customer-out", "customer-out"]
            })
        );
        let mut neighbor = proto::NeighborPolicyChains {
            address: "fe80::2".into(),
            import_policy_names: vec!["peer-in".into()],
            export_policy_names: vec!["peer-out".into()],
        };
        assert_eq!(
            serde_json::to_value(neighbor_chains_to_json(neighbor.clone(), "fe80::2%eth0"))
                .unwrap(),
            serde_json::json!({"neighbor": "fe80::2%eth0", "import_policy_names": ["peer-in"],
                "export_policy_names": ["peer-out"]})
        );
        neighbor.import_policy_names.clear();
        neighbor.export_policy_names.clear();
        assert_eq!(
            serde_json::to_value(neighbor_chains_to_json(neighbor, "fe80::3%eth1")).unwrap(),
            serde_json::json!({"neighbor": "fe80::2", "import_policy_names": [], "export_policy_names": []})
        );
        assert_eq!(
            serde_json::to_value(global_chains_to_json(proto::GlobalPolicyChains {
                import_policy_names: vec![],
                export_policy_names: vec![],
            }))
            .unwrap(),
            serde_json::json!({"import_policy_names": [], "export_policy_names": []})
        );
    }

    fn write_rpol(content: &str) -> tempfile::NamedTempFile {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        write!(tmp, "{content}").unwrap();
        tmp.flush().unwrap();
        tmp
    }

    #[test]
    fn operator_output_restores_scoped_identity_after_response_canonicalization() {
        assert_eq!(
            operator_peer_address(Some("fe80:0:0:0:0:0:0:9%eth0"), "fe80::9"),
            "fe80:0:0:0:0:0:0:9%eth0"
        );
    }

    #[test]
    fn operator_output_preserves_requested_scoped_identity() {
        assert_eq!(
            operator_peer_address(Some("fe80::9%eth0"), "fe80::9"),
            "fe80::9%eth0"
        );
    }

    #[test]
    fn operator_output_leaves_unfiltered_rows_unchanged() {
        assert_eq!(operator_peer_address(None, "fe80::9"), "fe80::9");
    }

    #[test]
    fn operator_output_leaves_unrelated_filtered_rows_unchanged() {
        assert_eq!(
            operator_peer_address(Some("fe80::9%eth0"), "fe80::10"),
            "fe80::10",
            "a filtered stats row must match before inheriting the requested scope"
        );
    }

    #[tokio::test]
    async fn test_scoped_link_local_sends_scoped_peer_and_renders() {
        let server = spawn_mock_server(None).await;
        let connection = connect(&server.addr, None).await.unwrap();
        let file = write_rpol("policy p { term t { reject } }");
        test(
            connection,
            TestOptions {
                file: file.path().to_str().unwrap(),
                policy: "customer-in(200)",
                direction: "import",
                peer: Some("fe80::9%eth0"),
                family: Some("ipv4_unicast"),
                limit: 100,
                show_changes: 5,
                datasets: &[],
                show_rejected: 0,
            },
            true,
        )
        .await
        .unwrap();
        let captured = server.state.last_test_policy.lock().await.clone().unwrap();
        assert_eq!(captured.rpol_source, "policy p { term t { reject } }");
        assert_eq!(captured.policy, "customer-in(200)");
        assert_eq!(captured.direction, "import");
        assert_eq!(captured.peer, "fe80::9%eth0");
        assert_eq!(
            captured.afi_safi,
            crate::proto::AddressFamily::Ipv4Unicast as i32
        );
        assert_eq!(captured.limit, 100);
        assert_eq!(captured.show_changes, 5);
    }

    #[tokio::test]
    async fn test_candidate_datasets_are_read_locally_and_sent_as_text() {
        let server = spawn_mock_server(None).await;
        let connection = connect(&server.addr, None).await.unwrap();
        let source = write_rpol("dataset prefix-set prefixes\npolicy p { term t { reject } }");
        let candidate = write_rpol("192.0.2.0/24\n");
        let binding = format!("prefixes={}", candidate.path().display());
        test(
            connection,
            TestOptions {
                file: source.path().to_str().unwrap(),
                policy: "p",
                direction: "import",
                peer: None,
                family: None,
                limit: 0,
                show_changes: 0,
                datasets: &[binding],
                show_rejected: 3,
            },
            true,
        )
        .await
        .unwrap();
        let captured = server.state.last_test_policy.lock().await.clone().unwrap();
        assert_eq!(captured.datasets.len(), 1);
        assert_eq!(captured.datasets[0].name, "prefixes");
        assert_eq!(captured.datasets[0].entries, "192.0.2.0/24\n");
        assert_eq!(captured.show_rejected, 3);
    }

    #[tokio::test]
    async fn compare_sends_the_candidate_and_renders_flip_classes() {
        let server = spawn_mock_server(None).await;
        let connection = connect(&server.addr, None).await.unwrap();
        let file = write_rpol("policy client-x { term t { accept } }");
        let policies = ["client-x".to_string()];
        let opts = CompareOptions {
            file: file.path().to_str().unwrap(),
            policies: &policies,
            replace: Some("client-x"),
            peer: "fe80::9%eth0",
            family: Some("ipv6_unicast"),
            limit: 0,
            max_samples: 3,
            datasets: &[],
        };
        compare(connection.clone(), opts, false).await.unwrap();
        let captured = server
            .state
            .last_compare_policy
            .lock()
            .await
            .clone()
            .unwrap();
        assert_eq!(
            captured.rpol_source,
            "policy client-x { term t { accept } }"
        );
        assert_eq!(captured.policies, ["client-x"]);
        assert_eq!(captured.replace_member, "client-x");
        assert_eq!(captured.peer, "fe80::9%eth0");
        assert_eq!(
            captured.afi_safi,
            crate::proto::AddressFamily::Ipv6Unicast as i32
        );
        assert_eq!(captured.max_samples, 3);

        let resp = proto::ComparePolicyResponse {
            compiled: true,
            installed_chain: vec!["rs-hygiene".to_string(), "client-x".to_string()],
            newly_rejected: 2,
            newly_rejected_routes: vec![proto::ComparePolicyRoute {
                prefix: "198.18.0.0".to_string(),
                prefix_length: 15,
                peer: "10.0.0.9".to_string(),
                ..Default::default()
            }],
            attributes_changed_routes: vec![proto::ComparePolicyRoute {
                prefix: "192.0.2.0".to_string(),
                prefix_length: 24,
                peer: "10.0.0.9".to_string(),
                installed_changes: vec!["local_pref unset -> 200".to_string()],
                candidate_changes: vec!["local_pref unset -> 300".to_string()],
            }],
            ..Default::default()
        };
        let json = serde_json::to_value(compare_to_json(
            &resp,
            &CompareOptions {
                file: "candidate.rpol",
                policies: &policies,
                replace: Some("client-x"),
                peer: "192.0.2.1",
                family: None,
                limit: 0,
                max_samples: 3,
                datasets: &[],
            },
        ))
        .unwrap();
        assert_eq!(json["newly_rejected"], 2);
        assert_eq!(json["newly_rejected_routes"][0]["prefix"], "198.18.0.0/15");
        assert_eq!(
            json["attributes_changed_routes"][0]["candidate_changes"][0],
            "local_pref unset -> 300"
        );
        assert_eq!(json["installed_chain"][1], "client-x");

        let two = ["a".to_string(), "b".to_string()];
        let error = compare(
            connection,
            CompareOptions {
                policies: &two,
                ..opts
            },
            true,
        )
        .await
        .unwrap_err();
        assert!(matches!(error, CliError::Argument(_)));
    }

    #[test]
    fn test_candidate_file_read_is_bounded() {
        let file = write_rpol("123456");
        let error = read_test_policy_file(file.path().to_str().unwrap(), 5).unwrap_err();
        assert!(matches!(error, CliError::Argument(_)));
    }

    #[tokio::test]
    async fn test_candidate_binding_requires_unique_name_and_path() {
        let server = spawn_mock_server(None).await;
        let connection = connect(&server.addr, None).await.unwrap();
        let source = write_rpol("policy p { term t { reject } }");
        let candidate = write_rpol("192.0.2.0/24\n");
        let valid = format!("prefixes={}", candidate.path().display());
        for datasets in [
            vec!["prefixes".to_string()],
            vec![valid.clone(), valid.clone()],
        ] {
            let error = test(
                connection.clone(),
                TestOptions {
                    file: source.path().to_str().unwrap(),
                    policy: "p",
                    direction: "import",
                    peer: None,
                    family: None,
                    limit: 0,
                    show_changes: 0,
                    datasets: &datasets,
                    show_rejected: 0,
                },
                true,
            )
            .await
            .unwrap_err();
            assert!(matches!(error, CliError::Argument(_)));
        }
        assert!(server.state.last_test_policy.lock().await.is_none());
    }

    #[tokio::test]
    async fn test_rejects_unknown_family_and_missing_file() {
        let server = spawn_mock_server(None).await;
        let connection = connect(&server.addr, None).await.unwrap();
        let file = write_rpol("policy p { term t { reject } }");
        let opts = |file: &str, family: Option<&'static str>| TestOptions {
            file: Box::leak(file.to_string().into_boxed_str()),
            policy: "p",
            direction: "import",
            peer: None,
            family,
            limit: 0,
            show_changes: 0,
            datasets: &[],
            show_rejected: 0,
        };
        let path = file.path().to_str().unwrap();
        let err = test(connection.clone(), opts(path, Some("l2vpn_evpn")), false)
            .await
            .unwrap_err();
        assert!(matches!(err, CliError::Argument(_)), "{err:?}");
        let err = test(connection, opts("/nonexistent/x.rpol", None), false)
            .await
            .unwrap_err();
        assert!(matches!(err, CliError::Argument(_)), "{err:?}");
    }

    /// Lines and columns are 1-based, columns count characters (not
    /// bytes), the end is exclusive, and a span in another module is
    /// located in that module's text.
    #[test]
    fn json_location_counts_lines_and_unicode_columns() {
        use rustbgpd_policy::rpol::Span;

        let lib = "# caf\u{e9}\n# \u{e9}\u{e9} x\n";
        let sources = [
            SourceLines::new("main.rpol", "policy p {}\n"),
            SourceLines::new("lib.rpol", lib),
        ];
        let offset = lib.find('x').unwrap();
        let at = JsonLocation::new(&sources, Span::in_file(offset..offset + 1, 1));
        assert_eq!(
            (
                at.file.as_str(),
                at.line,
                at.column,
                at.end_line,
                at.end_column
            ),
            ("lib.rpol", 2, 6, 2, 7)
        );
        let at = JsonLocation::new(&sources, Span::new(7..12));
        assert_eq!(
            (at.line, at.column, at.end_line, at.end_column),
            (1, 8, 2, 1)
        );
    }

    /// The line index agrees with a scan from the start of the text at
    /// every byte offset, including inside multi-byte characters, on a
    /// last line without a trailing newline, and past the end.
    #[test]
    fn source_lines_match_a_full_scan_at_every_offset() {
        fn scan(text: &str, offset: usize) -> (usize, usize) {
            let before = &text[..text.floor_char_boundary(offset)];
            let line_start = before.rfind('\n').map_or(0, |newline| newline + 1);
            (
                before.matches('\n').count() + 1,
                before[line_start..].chars().count() + 1,
            )
        }
        let tail = "a\n\n\u{e9}\u{1f600}x";
        for text in ["", "\n", "x", tail, "\u{e9}\n\u{e9}\n", "p {}\r\nq\n"] {
            let lines = SourceLines::new("f", text);
            for offset in 0..=text.len() + 2 {
                assert_eq!(
                    lines.line_col(offset),
                    scan(text, offset),
                    "{text:?} @ {offset}"
                );
            }
        }
        let lines = SourceLines::new("f", tail);
        let x = tail.find('x').unwrap();
        assert_eq!(lines.line_col(x), (3, 3));
        assert_eq!(lines.line_col(tail.len()), (3, 4));
        assert_eq!(lines.line_col(x - 1), (3, 2), "inside the emoji");
    }

    #[test]
    fn check_local_clean_file_exits_zero() {
        let tmp = write_rpol(
            "policy p { term t { if route.rpki == invalid { reject } } }
             test rejects-invalid {
                 route { prefix 10.0.0.0/24; rpki invalid }
                 expect p == reject
             }",
        );
        assert_eq!(
            check_local(tmp.path().to_str().unwrap(), &CheckOptions::default()),
            0
        );
        assert_eq!(
            check_local(
                tmp.path().to_str().unwrap(),
                &CheckOptions {
                    json: true,
                    ..CheckOptions::default()
                }
            ),
            0
        );
    }

    struct BrokenWriter;

    impl Write for BrokenWriter {
        fn write(&mut self, _bytes: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe))
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    struct ObservedWriter {
        bytes: Vec<u8>,
        flushes: usize,
        write_error: Option<std::io::ErrorKind>,
        flush_error: Option<std::io::ErrorKind>,
    }

    impl Write for ObservedWriter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if let Some(kind) = self.write_error {
                return Err(std::io::Error::from(kind));
            }
            self.bytes.extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            self.flushes += 1;
            self.flush_error
                .map_or(Ok(()), |kind| Err(std::io::Error::from(kind)))
        }
    }

    #[test]
    fn formatted_stdout_writes_exact_bytes_and_flushes() {
        let mut writer = ObservedWriter {
            bytes: Vec::new(),
            flushes: 0,
            write_error: None,
            flush_error: None,
        };
        assert_eq!(write_formatted_stdout(&mut writer, "policy p {}\n"), 0);
        assert_eq!(writer.bytes, b"policy p {}\n");
        assert_eq!(writer.flushes, 1);
    }

    #[test]
    fn formatted_stdout_write_and_flush_failures_exit_one() {
        for (write_error, flush_error) in [
            (Some(std::io::ErrorKind::BrokenPipe), None),
            (None, Some(std::io::ErrorKind::PermissionDenied)),
        ] {
            let mut writer = ObservedWriter {
                bytes: Vec::new(),
                flushes: 0,
                write_error,
                flush_error,
            };
            assert_eq!(write_formatted_stdout(&mut writer, "policy p {}\n"), 1);
        }
    }

    #[test]
    fn check_local_json_write_failure_exits_one() {
        let tmp = write_rpol("policy p { term t { accept } }");
        assert_eq!(
            check_local_with_writer(
                tmp.path().to_str().unwrap(),
                &CheckOptions {
                    json: true,
                    ..CheckOptions::default()
                },
                &mut BrokenWriter
            ),
            1
        );
    }

    #[test]
    fn check_text_paths_preserve_bytes_and_reject_write_failures() {
        let tmp = write_rpol(
            "policy p { term t { accept } }\n\
             test ok { route { prefix 10.0.0.0/24 } expect p == accept }",
        );
        let path = tmp.path().to_str().unwrap();
        for (list_deps, coverage) in [(false, false), (true, false), (false, true)] {
            assert_eq!(
                check_local_with_writer(
                    path,
                    &CheckOptions {
                        list_deps,
                        coverage,
                        ..CheckOptions::default()
                    },
                    &mut BrokenWriter
                ),
                1
            );
            let mut flush = ObservedWriter {
                bytes: vec![],
                flushes: 0,
                write_error: None,
                flush_error: Some(std::io::ErrorKind::PermissionDenied),
            };
            assert_eq!(
                check_local_with_writer(
                    path,
                    &CheckOptions {
                        list_deps,
                        coverage,
                        ..CheckOptions::default()
                    },
                    &mut flush
                ),
                1
            );
        }
        let mut bytes = Vec::new();
        assert_eq!(
            check_local_with_writer(
                path,
                &CheckOptions {
                    coverage: true,
                    ..CheckOptions::default()
                },
                &mut bytes
            ),
            0
        );
        assert_eq!(
            String::from_utf8(bytes).unwrap(),
            format!(
                "{path}: 1 passed, 0 failed\ncoverage: 1/1 terms exercised by tests\nmatched coverage: 1/1 terms matched by tests\n  policy p\n    term t  evaluated 1x, matched 1x\n"
            )
        );
    }

    #[test]
    fn check_local_diagnostics_exit_one() {
        let tmp = write_rpol("policy p { term t { if route.zzz == 1 { accept } } }");
        assert_eq!(
            check_local(tmp.path().to_str().unwrap(), &CheckOptions::default()),
            1
        );
        // Unreadable file is also exit 1.
        assert_eq!(
            check_local("/nonexistent/nope.rpol", &CheckOptions::default()),
            1
        );
    }

    /// LAN-300: `check` resolves the import graph (tests in the main
    /// file exercise imported definitions), `--root` resolves imports
    /// outside the main file's directory, and `--list-deps` exits 0 on
    /// a clean graph / 1 on a broken one.
    #[test]
    fn check_local_resolves_imports_and_lists_deps() {
        let dir = tempfile::tempdir().unwrap();
        let lib = tempfile::tempdir().unwrap();
        std::fs::write(
            lib.path().join("bogons.rpol"),
            "prefix-set bogons { 127.0.0.0/8 le 32 }",
        )
        .unwrap();
        std::fs::write(
            dir.path().join("main.rpol"),
            "import \"bogons.rpol\"\n\
             policy p { term t { if route.prefix in bogons { reject } } }\n\
             test rejects-loopback {\n\
                 route { prefix 127.0.0.1/32 }\n\
                 expect p == reject\n\
             }",
        )
        .unwrap();
        let main = dir.path().join("main.rpol");
        let main = main.to_str().unwrap();
        let root = lib.path().to_str().unwrap().to_string();
        // Without the root the import cannot resolve.
        assert_eq!(check_local(main, &CheckOptions::default()), 1);
        // With it: clean check (the cross-module test runs) and deps.
        assert_eq!(
            check_local(
                main,
                &CheckOptions {
                    roots: std::slice::from_ref(&root),
                    ..CheckOptions::default()
                }
            ),
            0
        );
        assert_eq!(
            check_local(
                main,
                &CheckOptions {
                    roots: std::slice::from_ref(&root),
                    list_deps: true,
                    ..CheckOptions::default()
                }
            ),
            0
        );
        assert_eq!(
            check_local(
                main,
                &CheckOptions {
                    roots: &[root],
                    list_deps: true,
                    json: true,
                    ..CheckOptions::default()
                }
            ),
            0
        );
        // --list-deps on a broken graph still exits 1.
        assert_eq!(
            check_local(
                main,
                &CheckOptions {
                    list_deps: true,
                    ..CheckOptions::default()
                }
            ),
            1
        );
    }

    #[test]
    fn check_local_failing_test_exits_two() {
        let tmp = write_rpol(
            "policy p { term t { reject } }
             test should-fail {
                 route { prefix 10.0.0.0/24 }
                 expect p == accept
             }",
        );
        assert_eq!(
            check_local(tmp.path().to_str().unwrap(), &CheckOptions::default()),
            2
        );
    }

    /// LAN-323: `--coverage` is a report (exit 0 even with unexercised
    /// terms), `--coverage-min` turns the shortfall into exit 3 (and
    /// implies coverage without the flag), a met threshold passes, and
    /// test failures keep precedence over the threshold.
    #[test]
    fn check_local_coverage_exit_codes() {
        // Term `dead` is behind the deciding `all`: 1/2 exercised.
        let tmp = write_rpol(
            "policy p { term all { accept } term dead { reject } }
             test accepts {
                 route { prefix 10.0.0.0/24 }
                 expect p == accept
             }",
        );
        let path = tmp.path().to_str().unwrap();
        assert_eq!(
            check_local(
                path,
                &CheckOptions {
                    coverage: true,
                    ..CheckOptions::default()
                }
            ),
            0
        );
        assert_eq!(
            check_local(
                path,
                &CheckOptions {
                    coverage: true,
                    json: true,
                    ..CheckOptions::default()
                }
            ),
            0
        );
        assert_eq!(
            check_local(
                path,
                &CheckOptions {
                    coverage_min: Some(100.0),
                    ..CheckOptions::default()
                }
            ),
            3
        );
        assert_eq!(
            check_local(
                path,
                &CheckOptions {
                    coverage: true,
                    coverage_min: Some(50.0),
                    ..CheckOptions::default()
                }
            ),
            0
        );
        // A failing test wins over the coverage threshold.
        let failing = write_rpol(
            "policy p { term t { reject } }
             test should-fail {
                 route { prefix 10.0.0.0/24 }
                 expect p == accept
             }",
        );
        let failing = failing.path().to_str().unwrap();
        assert_eq!(
            check_local(
                failing,
                &CheckOptions {
                    coverage_min: Some(100.0),
                    ..CheckOptions::default()
                }
            ),
            2
        );
    }

    #[tokio::test]
    async fn list_renders_empty() {
        let server = spawn_mock_server(None).await;
        let connection = connect(&server.addr, None).await.unwrap();
        list(connection, true).await.unwrap();
    }

    #[tokio::test]
    async fn set_reads_json_file_and_sends_definition() {
        let server = spawn_mock_server(None).await;
        let connection = connect(&server.addr, None).await.unwrap();

        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        write!(
            tmp,
            r#"{{"default_action":"deny","statements":[{{"action":"permit","prefix":"10.0.0.0/8","set_local_pref":300}}]}}"#
        )
        .unwrap();
        tmp.flush().unwrap();

        set(
            connection,
            "from-transit",
            tmp.path().to_str().unwrap(),
            true,
        )
        .await
        .unwrap();

        let captured = server.state.last_set_policy.lock().await.clone().unwrap();
        assert_eq!(captured.name, "from-transit");
        let def = captured.definition.unwrap();
        assert_eq!(def.default_action, "deny");
        assert_eq!(def.statements.len(), 1);
        assert_eq!(def.statements[0].action, "permit");
        assert_eq!(def.statements[0].set_local_pref, Some(300));
    }

    #[tokio::test]
    async fn explain_scoped_link_local_sends_scoped_peer_and_infers_afi() {
        // Pin: the CLI infers AFI from the prefix (no --afi flag) and
        // sends a well-formed request with the parsed address + length.
        let server = spawn_mock_server(None).await;
        let connection = connect(&server.addr, None).await.unwrap();
        explain_import(connection, "fe80::1%eth0", "2001:db8::/32", Some(7), true)
            .await
            .unwrap();
        let captured = server
            .state
            .last_explain_import
            .lock()
            .await
            .clone()
            .unwrap();
        assert_eq!(captured.peer_address, "fe80::1%eth0");
        assert_eq!(captured.prefix, "2001:db8::");
        assert_eq!(captured.prefix_length, 32);
        assert_eq!(captured.path_id, Some(7));
        assert_eq!(
            captured.afi_safi,
            crate::proto::AddressFamily::Ipv6Unicast as i32,
            "AFI inferred from the v6 prefix"
        );
    }

    #[tokio::test]
    async fn explain_rejects_non_cidr_prefix() {
        let server = spawn_mock_server(None).await;
        let connection = connect(&server.addr, None).await.unwrap();
        let err = explain_import(connection, "192.0.2.1", "192.0.2.0", None, true)
            .await
            .unwrap_err();
        assert!(matches!(err, CliError::Argument(_)));
    }

    #[tokio::test]
    async fn explain_all_paths_returns_every_match() {
        // Pin 7: omitting --path-id surfaces all matching paths, not an
        // arbitrary first hit. The mock returns two paths in that case.
        let server = spawn_mock_server(None).await;
        let connection = connect(&server.addr, None).await.unwrap();
        explain_import(connection, "192.0.2.1", "192.0.2.0/24", None, true)
            .await
            .unwrap();
        let captured = server
            .state
            .last_explain_import
            .lock()
            .await
            .clone()
            .unwrap();
        assert_eq!(captured.path_id, None);
        assert_eq!(
            captured.afi_safi,
            crate::proto::AddressFamily::Ipv4Unicast as i32
        );
    }

    /// `--direction export` is the `rib advertised --explain` dry run:
    /// it must reach `ExplainAdvertisedRoute` (not the import cache)
    /// with the neighbor and prefix, no RD, unlabeled, no source
    /// identity, and render in both text and JSON.
    #[tokio::test]
    async fn explain_direction_export_calls_advertised_rpc() {
        let server = spawn_mock_server(None).await;
        for json in [true, false] {
            let connection = connect(&server.addr, None).await.unwrap();
            explain(
                connection,
                "fe80::1%eth0",
                "203.0.113.0/24",
                None,
                "export",
                json,
            )
            .await
            .unwrap();
            let req = server
                .state
                .last_explain_advertised
                .lock()
                .await
                .take()
                .expect("export explain reached ExplainAdvertisedRoute");
            assert_eq!(req.peer_address, "fe80::1%eth0");
            assert_eq!(req.prefix, "203.0.113.0");
            assert_eq!(req.prefix_length, 24);
            assert_eq!(req.rd, "");
            assert!(!req.labeled);
            assert_eq!(req.source, None);
        }
        assert!(
            server.state.last_explain_import.lock().await.is_none(),
            "export explain must not consult the import-decision cache"
        );
    }

    #[tokio::test]
    async fn explain_direction_import_is_the_cache_lookup() {
        let server = spawn_mock_server(None).await;
        let connection = connect(&server.addr, None).await.unwrap();
        explain(
            connection,
            "192.0.2.1",
            "192.0.2.0/24",
            Some(7),
            "import",
            true,
        )
        .await
        .unwrap();
        let req = server
            .state
            .last_explain_import
            .lock()
            .await
            .clone()
            .expect("import explain reached ExplainImportPolicy");
        assert_eq!(req.path_id, Some(7));
        assert!(server.state.last_explain_advertised.lock().await.is_none());
    }

    #[tokio::test]
    async fn explain_direction_export_rejects_path_id_before_any_rpc() {
        let server = spawn_mock_server(None).await;
        let connection = connect(&server.addr, None).await.unwrap();
        let err = explain(
            connection,
            "192.0.2.1",
            "192.0.2.0/24",
            Some(3),
            "export",
            false,
        )
        .await
        .unwrap_err();
        assert!(matches!(err, CliError::Argument(_)), "{err}");
        assert_eq!(err.to_string(), EXPLAIN_EXPORT_PATH_ID_ERROR);
        assert!(server.state.last_explain_advertised.lock().await.is_none());
        assert!(server.state.last_explain_import.lock().await.is_none());
    }

    #[tokio::test]
    async fn explain_rejects_unknown_direction_before_any_rpc() {
        let server = spawn_mock_server(None).await;
        let connection = connect(&server.addr, None).await.unwrap();
        let err = explain(connection, "192.0.2.1", "192.0.2.0/24", None, "both", false)
            .await
            .unwrap_err();
        assert!(matches!(err, CliError::Argument(_)), "{err}");
        assert_eq!(
            err.to_string(),
            "unknown explain direction \"both\"; expected import or export"
        );
        assert!(server.state.last_explain_advertised.lock().await.is_none());
        assert!(server.state.last_explain_import.lock().await.is_none());
    }

    #[tokio::test]
    async fn explain_renders_text_and_json() {
        // Pin 8: both render paths run cleanly over a populated
        // multi-match response (permit + deny, modifications present).
        let server = spawn_mock_server(None).await;
        let json_conn = connect(&server.addr, None).await.unwrap();
        explain_import(json_conn, "192.0.2.1", "192.0.2.0/24", None, true)
            .await
            .unwrap();
        let text_conn = connect(&server.addr, None).await.unwrap();
        explain_import(text_conn, "192.0.2.1", "192.0.2.0/24", None, false)
            .await
            .unwrap();
    }

    /// `cache_disabled` is an error with the config hint (nonzero exit
    /// via `Err`), in both text and JSON modes — never a `not_seen`
    /// lookalike. Import explain is opt-in, so this is the response an
    /// operator meets on a stock daemon: it has to name the exact
    /// config lines to add, not just report an empty result.
    #[tokio::test]
    async fn explain_cache_disabled_errors_with_hint() {
        let server = spawn_mock_server(None).await;
        *server.state.explain_import_synthetic_outcome.lock().await =
            Some(rustbgpd_api::proto::ImportExplainOutcome::CacheDisabled);
        let connection = connect(&server.addr, None).await.unwrap();
        let err = explain_import(connection, "10.0.0.2", "10.0.0.0/24", None, false)
            .await
            .unwrap_err();
        assert!(matches!(err, CliError::Rpc(_)));
        let rendered = err.to_string();
        assert!(
            rendered.contains("[policy.explain]") && rendered.contains("enabled = true"),
            "the disabled response must name the exact config lines to add:\n{rendered}"
        );
        assert_eq!(
            rendered,
            "import-decision cache is disabled on this daemon (the default)\n  \
             hint: add `[policy.explain]` with `enabled = true`, reload, and let the \
             session re-establish\n  \
             cost: per session, up to `cache_size` (default 4096) entries of retained \
             decisions"
        );
        // JSON mode prints the body (distinct outcome value) but still
        // returns the error so the exit code stays nonzero.
        let json_conn = connect(&server.addr, None).await.unwrap();
        let err = explain_import(json_conn, "10.0.0.2", "10.0.0.0/24", None, true)
            .await
            .unwrap_err();
        assert!(matches!(err, CliError::Rpc(_)));
    }

    /// LAN-320 pin: `no_session` names the neighbor and errors (nonzero
    /// exit) — the question could not be evaluated.
    #[tokio::test]
    async fn explain_no_session_errors_with_neighbor() {
        let server = spawn_mock_server(None).await;
        *server.state.explain_import_synthetic_outcome.lock().await =
            Some(rustbgpd_api::proto::ImportExplainOutcome::NoSession);
        let connection = connect(&server.addr, None).await.unwrap();
        let err = explain_import(connection, "10.0.0.2", "10.0.0.0/24", None, false)
            .await
            .unwrap_err();
        assert_eq!(err.to_string(), "no live session with 10.0.0.2");
        let json_conn = connect(&server.addr, None).await.unwrap();
        let err = explain_import(json_conn, "10.0.0.2", "10.0.0.0/24", None, true)
            .await
            .unwrap_err();
        assert!(matches!(err, CliError::Rpc(_)));
    }

    /// LAN-320 pin: `not_seen` stays an evaluated answer — normal
    /// rendering, `Ok` (exit 0) — in both text and JSON modes.
    #[tokio::test]
    async fn explain_not_seen_stays_ok() {
        let server = spawn_mock_server(None).await;
        *server.state.explain_import_synthetic_outcome.lock().await =
            Some(rustbgpd_api::proto::ImportExplainOutcome::NotSeen);
        let connection = connect(&server.addr, None).await.unwrap();
        explain_import(connection, "10.0.0.2", "10.0.0.0/24", None, false)
            .await
            .unwrap();
        let json_conn = connect(&server.addr, None).await.unwrap();
        explain_import(json_conn, "10.0.0.2", "10.0.0.0/24", None, true)
            .await
            .unwrap();
    }

    #[test]
    fn import_explain_cache_notice_reports_evictions() {
        let mut resp = proto::ExplainImportPolicyResponse {
            cache_size: Some(4096),
            evictions_since_reset: Some(995_000),
            matches: vec![proto::ImportExplainMatch {
                outcome: proto::ImportExplainOutcome::Evicted as i32,
                ..Default::default()
            }],
            ..Default::default()
        };
        assert_eq!(
            import_explain_cache_notice(&resp).as_deref(),
            Some("  cache:   995000 decision(s) evicted since session reset (cache_size 4096)")
        );
        resp.cache_size = None;
        resp.evictions_since_reset = None;
        assert_eq!(import_explain_cache_notice(&resp), None);
        resp.matches[0].outcome = proto::ImportExplainOutcome::NotSeen as i32;
        assert_eq!(
            import_explain_cache_notice(&resp).as_deref(),
            Some(
                "WARNING: this daemon does not report explain-cache evictions; \
                 not_seen may mean the decision was evicted"
            )
        );
    }

    /// LAN-320: the JSON outcome strings for the tri-state are stable.
    #[test]
    fn outcome_labels_cover_tristate() {
        assert_eq!(
            outcome_label(proto::ImportExplainOutcome::NotSeen as i32),
            "not_seen"
        );
        assert_eq!(
            outcome_label(proto::ImportExplainOutcome::CacheDisabled as i32),
            "cache_disabled"
        );
        assert_eq!(
            outcome_label(proto::ImportExplainOutcome::NoSession as i32),
            "no_session"
        );
    }

    #[test]
    fn explain_attribution_distinguishes_chain_permit_from_policy_deny_and_inline() {
        let mut row = proto::ImportExplainMatch {
            outcome: proto::ImportExplainOutcome::Permit as i32,
            matched_policy: rustbgpd_policy::CHAIN_DEFAULT_PERMIT_ATTRIBUTION.to_string(),
            ..Default::default()
        };
        assert_eq!(
            decision_attribution_line(&row),
            "decision: no policy rejected; chain default permit"
        );

        row.outcome = proto::ImportExplainOutcome::Deny as i32;
        assert_eq!(
            decision_attribution_line(&row),
            "policy:  chain_default_permit",
            "an operator policy with the sentinel spelling stays ordinary deny attribution"
        );

        row.matched_policy.clear();
        assert_eq!(decision_attribution_line(&row), "policy:  inline");
    }

    #[test]
    fn stats_json_covers_proto_fields() {
        // Keep every generated response and nested message exhaustive so a
        // new API field requires an explicit JSON projection decision.
        let mut response = proto::GetPolicyStatsResponse {
            incomplete_peer_addresses: Vec::new(),
            chains: vec![proto::PolicyChainStats {
                peer_address: "fe80::2".into(),
                peer_interface: String::new(),
                direction: "import".into(),
                routes_evaluated: u64::MAX,
                eval_errors: 7,
                last_error: "fuel exhausted in policy customer-in term validate".into(),
                policy_generation: 19,
                terms: vec![proto::PolicyTermStat {
                    policy_index: 2,
                    policy: "customer-in".into(),
                    term_index: 3,
                    term: "validate".into(),
                    hits: u64::MAX,
                }],
            }],
            datasets: vec![proto::PolicyDatasetStatus {
                name: "customers".into(),
                kind: "prefix-set".into(),
                generation: 23,
                records: u64::MAX,
                path: "/etc/rustbgpd/customers.json".into(),
                last_error: "refresh failed".into(),
            }],
        };
        assert_eq!(
            serde_json::to_value(stats_to_json(&response, Some("fe80::2%eth0"))).unwrap(),
            serde_json::json!({
                "chains": [{
                    "peer_address": "fe80::2%eth0", "direction": "import",
                    "routes_evaluated": u64::MAX, "eval_errors": 7,
                    "last_error": "fuel exhausted in policy customer-in term validate",
                    "policy_generation": 19,
                    "terms": [{
                        "policy_index": 2, "policy": "customer-in", "term_index": 3,
                        "term": "validate", "hits": u64::MAX,
                    }],
                }],
                "datasets": [{
                    "name": "customers", "kind": "prefix-set", "generation": 23,
                    "records": u64::MAX, "path": "/etc/rustbgpd/customers.json",
                    "last_error": "refresh failed",
                }],
            })
        );

        let chain = &mut response.chains[0];
        chain.peer_address = "global".into();
        chain.direction = "export".into();
        chain.routes_evaluated = 0;
        chain.eval_errors = 0;
        chain.last_error.clear();
        chain.terms[0] = proto::PolicyTermStat {
            policy_index: 0,
            policy: String::new(),
            term_index: 0,
            term: String::new(),
            hits: 0,
        };
        response.datasets[0].last_error.clear();
        let mut expected = serde_json::json!({
            "chains": [{
                "peer_address": "global", "direction": "export",
                "routes_evaluated": 0, "eval_errors": 0, "policy_generation": 19,
                "terms": [{
                    "policy_index": 0, "policy": null, "term_index": 0,
                    "term": null, "hits": 0,
                }],
            }],
            "datasets": [{
                "name": "customers", "kind": "prefix-set", "generation": 23,
                "records": u64::MAX, "path": "/etc/rustbgpd/customers.json",
                "last_error": null,
            }],
        });
        assert_eq!(
            serde_json::to_value(stats_to_json(&response, None)).unwrap(),
            expected
        );

        // Export rows carry their counter-instance id and import generation zero
        // is present. Chain errors are omitted when empty, while dataset errors
        // and anonymous policy/term names are null.
        response.chains[0].direction = "import".into();
        response.chains[0].policy_generation = 0;
        expected["chains"][0]["direction"] = serde_json::json!("import");
        expected["chains"][0]["policy_generation"] = serde_json::json!(0);
        assert_eq!(
            serde_json::to_value(stats_to_json(&response, None)).unwrap(),
            expected
        );
        response.chains.clear();
        response.datasets.clear();
        assert_eq!(
            serde_json::to_value(stats_to_json(&response, None)).unwrap(),
            serde_json::json!({"chains": []})
        );
    }

    /// Both directions name the identity their counters belong to: the
    /// install generation for import, the counter-instance id for export.
    #[test]
    fn stats_heading_names_each_directions_counter_identity() {
        let mut chain = proto::PolicyChainStats {
            peer_address: "fe80::2".into(),
            direction: "export".into(),
            routes_evaluated: 7,
            policy_generation: 41,
            ..Default::default()
        };
        assert_eq!(
            stats_chain_heading(&chain, Some("fe80::2%eth0")),
            "fe80::2%eth0 export chain — 7 routes evaluated since install (counter instance 41)"
        );
        chain.direction = "import".into();
        chain.policy_generation = 0;
        assert_eq!(
            stats_chain_heading(&chain, None),
            "fe80::2 import chain — 7 routes evaluated since install (install generation 0)"
        );
    }

    #[tokio::test]
    async fn stats_scoped_link_local_sends_scoped_peer_and_renders() {
        let server = spawn_mock_server(None).await;
        let json_conn = connect(&server.addr, None).await.unwrap();
        stats(
            json_conn,
            Some("fe80:0:0:0:0:0:0:2%eth0"),
            "export",
            false,
            true,
        )
        .await
        .unwrap();
        let captured = server
            .state
            .last_get_policy_stats
            .lock()
            .await
            .clone()
            .unwrap();
        assert_eq!(captured.peer_address, "fe80:0:0:0:0:0:0:2%eth0");
        assert_eq!(captured.direction, "export");
        let text_conn = connect(&server.addr, None).await.unwrap();
        stats(text_conn, None, "export", false, false)
            .await
            .unwrap();
    }

    /// The direction flag passes through to the RPC: the mock server
    /// answers "import" and "both" with direction-tagged chains
    /// (import ones carrying an install generation), and both render.
    #[tokio::test]
    async fn stats_renders_import_and_both_directions() {
        let server = spawn_mock_server(None).await;
        let json_conn = connect(&server.addr, None).await.unwrap();
        stats(json_conn, Some("10.0.0.2"), "import", false, true)
            .await
            .unwrap();
        let text_conn = connect(&server.addr, None).await.unwrap();
        stats(text_conn, None, "both", false, false).await.unwrap();
    }

    #[tokio::test]
    async fn stats_partial_opt_in_and_incomplete_addresses_are_visible() {
        let server = spawn_mock_server(None).await;
        let connection = connect(&server.addr, None).await.unwrap();
        stats(connection, None, "both", true, false).await.unwrap();
        let request = server
            .state
            .last_get_policy_stats
            .lock()
            .await
            .clone()
            .unwrap();
        assert!(request.allow_partial);
        assert!(request.peer_address.is_empty());
        let response = proto::GetPolicyStatsResponse {
            incomplete_peer_addresses: vec!["192.0.2.1".into()],
            ..Default::default()
        };
        assert_eq!(
            serde_json::to_value(stats_to_json(&response, None)).unwrap(),
            serde_json::json!({"chains": [], "incomplete_peer_addresses": ["192.0.2.1"]})
        );
    }

    #[test]
    fn statement_line_renders_rpol_term_name() {
        let step = proto::ImportExplainStatementStep {
            policy_index: 0,
            policy_name: "customer-in(200)".to_string(),
            default_action: false,
            statement_index: 2,
            action: "permit".to_string(),
            matched_conditions: vec!["guard route.prefix in customers".to_string()],
            modifications: vec!["local_pref 100 -> 200".to_string()],
            term: "customer-routes".to_string(),
            term_traces: vec![
                "term rpki-guard: route.rpki == invalid => reject [not matched]".to_string(),
            ],
        };
        assert_eq!(
            statement_line(&step),
            "[0] policy customer-in(200) term customer-routes permit  \
             match: guard route.prefix in customers  set: local_pref 100 -> 200"
        );
    }

    #[test]
    fn statement_line_renders_match_and_set_clauses() {
        let step = proto::ImportExplainStatementStep {
            policy_index: 0,
            policy_name: "edge-import".to_string(),
            default_action: false,
            statement_index: 1,
            action: "permit".to_string(),
            matched_conditions: vec![
                "prefix 10.0.0.0/8 le 24".to_string(),
                "community 65001:100".to_string(),
            ],
            modifications: vec!["local_pref 100 -> 200".to_string()],
            term: String::new(),
            term_traces: vec![],
        };
        assert_eq!(
            statement_line(&step),
            "[0] policy edge-import statement 1 permit  \
             match: prefix 10.0.0.0/8 le 24, community 65001:100  \
             set: local_pref 100 -> 200"
        );
    }

    #[test]
    fn statement_line_renders_default_action_and_inline_policy() {
        let step = proto::ImportExplainStatementStep {
            policy_index: 2,
            policy_name: String::new(),
            default_action: true,
            statement_index: 0,
            action: "deny".to_string(),
            matched_conditions: vec![],
            modifications: vec![],
            term: String::new(),
            term_traces: vec![],
        };
        assert_eq!(
            statement_line(&step),
            "[2] policy inline default-action deny"
        );
    }

    #[test]
    fn statement_to_json_nulls_index_on_default_action_only() {
        let matched = proto::ImportExplainStatementStep {
            policy_index: 0,
            policy_name: "p".to_string(),
            default_action: false,
            statement_index: 3,
            action: "permit".to_string(),
            matched_conditions: vec!["any".to_string()],
            modifications: vec![],
            term: String::new(),
            term_traces: vec![],
        };
        let j = statement_to_json(&matched);
        assert_eq!(j.statement_index, Some(3));
        assert_eq!(j.policy_name.as_deref(), Some("p"));

        let fallthrough = proto::ImportExplainStatementStep {
            default_action: true,
            policy_name: String::new(),
            action: "deny".to_string(),
            ..Default::default()
        };
        let j = statement_to_json(&fallthrough);
        assert_eq!(j.statement_index, None, "fallthrough has no statement");
        assert_eq!(j.policy_name, None, "inline policy serializes as null");
    }

    #[tokio::test]
    async fn delete_sends_request() {
        let server = spawn_mock_server(None).await;
        let connection = connect(&server.addr, None).await.unwrap();
        delete(connection, "from-transit", true).await.unwrap();
        let captured = server
            .state
            .last_delete_policy
            .lock()
            .await
            .clone()
            .unwrap();
        assert_eq!(captured.name, "from-transit");
    }

    #[tokio::test]
    async fn chain_show_global_prints() {
        let server = spawn_mock_server(None).await;
        let connection = connect(&server.addr, None).await.unwrap();
        chain_show(connection, None, true).await.unwrap();
    }

    #[tokio::test]
    async fn chain_show_scoped_link_local_sends_scoped_neighbor() {
        let server = spawn_mock_server(None).await;
        let connection = connect(&server.addr, None).await.unwrap();
        chain_show(connection, Some("fe80::2%eth0"), true)
            .await
            .unwrap();
        let captured = server
            .state
            .last_get_neighbor_policy_chains
            .lock()
            .await
            .clone()
            .unwrap();
        assert_eq!(captured.address, "fe80::2%eth0");
    }

    #[tokio::test]
    async fn chain_set_global_import_captures_request() {
        let server = spawn_mock_server(None).await;
        let connection = connect(&server.addr, None).await.unwrap();
        chain_set(
            connection,
            ChainDirection::Import,
            None,
            vec!["a".to_string(), "b".to_string()],
            true,
        )
        .await
        .unwrap();
        let captured = server
            .state
            .last_set_global_import_chain
            .lock()
            .await
            .clone()
            .unwrap();
        assert_eq!(
            captured.policy_names,
            vec!["a".to_string(), "b".to_string()]
        );
    }

    #[tokio::test]
    async fn chain_set_neighbor_import_sends_scoped_address() {
        let server = spawn_mock_server(None).await;
        let connection = connect(&server.addr, None).await.unwrap();
        chain_set(
            connection,
            ChainDirection::Import,
            Some("fe80::2%eth0"),
            vec!["x".to_string()],
            true,
        )
        .await
        .unwrap();
        let captured = server
            .state
            .last_set_neighbor_import_chain
            .lock()
            .await
            .clone()
            .unwrap();
        assert_eq!(captured.address, "fe80::2%eth0");
        assert_eq!(captured.policy_names, vec!["x".to_string()]);
    }

    #[tokio::test]
    async fn chain_set_neighbor_export_sends_scoped_address() {
        let server = spawn_mock_server(None).await;
        let connection = connect(&server.addr, None).await.unwrap();
        chain_set(
            connection,
            ChainDirection::Export,
            Some("fe80::2%eth0"),
            vec!["x".to_string()],
            true,
        )
        .await
        .unwrap();
        let captured = server
            .state
            .last_set_neighbor_export_chain
            .lock()
            .await
            .clone()
            .unwrap();
        assert_eq!(captured.address, "fe80::2%eth0");
        assert_eq!(captured.policy_names, vec!["x".to_string()]);
    }

    #[tokio::test]
    async fn chain_clear_neighbor_import_sends_scoped_address() {
        let server = spawn_mock_server(None).await;
        let connection = connect(&server.addr, None).await.unwrap();
        chain_clear(
            connection,
            ChainDirection::Import,
            Some("fe80::2%eth0"),
            true,
        )
        .await
        .unwrap();
        let captured = server
            .state
            .last_clear_neighbor_import_chain
            .lock()
            .await
            .clone()
            .unwrap();
        assert_eq!(captured.address, "fe80::2%eth0");
    }

    #[tokio::test]
    async fn chain_clear_neighbor_export_sends_scoped_address() {
        let server = spawn_mock_server(None).await;
        let connection = connect(&server.addr, None).await.unwrap();
        chain_clear(
            connection,
            ChainDirection::Export,
            Some("fe80::2%eth0"),
            true,
        )
        .await
        .unwrap();
        let captured = server
            .state
            .last_clear_neighbor_export_chain
            .lock()
            .await
            .clone()
            .unwrap();
        assert_eq!(captured.address, "fe80::2%eth0");
    }

    /// LAN-323: `fmt` rewrites in place (atomically), a second run is
    /// a no-op, and the rewritten file still checks clean.
    #[test]
    fn fmt_local_rewrites_in_place_and_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let name = "p.rpol";
        let path = dir.path().join(name);
        std::fs::write(&path, "policy p{term t{if route.rpki==invalid{reject}}}").unwrap();
        let old_temp = dir.path().join(format!("{name}.tmp"));
        std::fs::write(&old_temp, "another writer's stage").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o2640)).unwrap();
        }
        let files = vec![path.to_str().unwrap().to_string()];
        assert_eq!(fmt_local(&files, false), 0);
        let formatted = std::fs::read_to_string(&path).unwrap();
        assert_eq!(
            formatted,
            "policy p {\n    term t { if route.rpki == invalid { reject } }\n}\n"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o7777,
                0o2640
            );
        }
        // Idempotent: nothing further to rewrite, and --check agrees.
        assert_eq!(fmt_local(&files, false), 0);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), formatted);
        assert_eq!(fmt_local(&files, true), 0);
        assert_eq!(
            std::fs::read_to_string(old_temp).unwrap(),
            "another writer's stage"
        );
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 2);
        assert_eq!(check_local(&files[0], &CheckOptions::default()), 0);
    }

    #[test]
    fn write_atomic_removes_temp_when_rename_fails() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("p.rpol");
        // A directory destination forces rename to fail after the payload was staged.
        std::fs::create_dir(&path).unwrap();
        let original = path.join("original");
        std::fs::write(&original, "keep this").unwrap();

        let error = write_atomic(&path, "replacement").unwrap_err();
        assert!(error.to_string().contains("failed to write"));
        assert!(path.is_dir());
        assert_eq!(std::fs::read_to_string(original).unwrap(), "keep this");
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[test]
    fn fmt_local_accepts_max_length_filename() {
        let dir = tempfile::tempdir().unwrap();
        // The target fits NAME_MAX=255; appending the former `.tmp` suffix does not.
        let name = format!("{}.rpol", "p".repeat(250));
        let path = dir.path().join(name);
        std::fs::write(&path, "policy p{term t{accept}}").unwrap();
        let files = vec![path.to_str().unwrap().to_string()];

        assert_eq!(fmt_local(&files, false), 0);
        assert_eq!(
            std::fs::read_to_string(path).unwrap(),
            "policy p {\n    term t { accept }\n}\n"
        );
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn policy_stage_is_private_with_permissive_umask() {
        use std::os::unix::fs::PermissionsExt;

        const CHILD_ENV: &str = "RUSTBGPD_POLICY_STAGE_UMASK_CHILD";
        if std::env::var_os(CHILD_ENV).is_none() {
            // Isolate the process-wide umask from tests running on other threads.
            let output = std::process::Command::new("sh")
                .args([
                    "-c",
                    "umask 0; exec \"$1\" --exact commands::policy::tests::policy_stage_is_private_with_permissive_umask --nocapture",
                    "policy-stage-test",
                ])
                .arg(std::env::current_exe().unwrap())
                .env(CHILD_ENV, "1")
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "private-stage subprocess failed:\n{}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }

        let dir = tempfile::tempdir().unwrap();
        let (path, file) = create_policy_stage(dir.path()).unwrap();
        assert_eq!(file.metadata().unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(
            std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    /// LAN-323: `--check` never rewrites, exits 1 on drift, and a
    /// multi-file invocation aggregates (one dirty file fails the run).
    #[test]
    fn fmt_local_check_mode_flags_drift_without_rewriting() {
        let dir = tempfile::tempdir().unwrap();
        let dirty = dir.path().join("dirty.rpol");
        let clean = dir.path().join("clean.rpol");
        std::fs::write(&dirty, "policy p{term t{accept}}").unwrap();
        std::fs::write(&clean, "policy p {\n    term t { accept }\n}\n").unwrap();
        let both = vec![
            clean.to_str().unwrap().to_string(),
            dirty.to_str().unwrap().to_string(),
        ];
        assert_eq!(fmt_local(&both[..1], true), 0);
        assert_eq!(fmt_local(&both, true), 1);
        // --check rewrote nothing.
        assert_eq!(
            std::fs::read_to_string(&dirty).unwrap(),
            "policy p{term t{accept}}"
        );
    }

    /// LAN-323: syntax-broken and unreadable files are refused (exit
    /// 1) and never rewritten.
    #[test]
    fn fmt_local_refuses_broken_and_missing_files() {
        let dir = tempfile::tempdir().unwrap();
        let broken = dir.path().join("broken.rpol");
        std::fs::write(&broken, "policy p { term t {").unwrap();
        assert_eq!(fmt_local(&[broken.to_str().unwrap().to_string()], false), 1);
        assert_eq!(
            std::fs::read_to_string(&broken).unwrap(),
            "policy p { term t {"
        );
        assert_eq!(fmt_local(&["/nonexistent/x.rpol".to_string()], false), 1);
    }

    #[test]
    fn line_diff_marks_changed_lines() {
        let diff = line_diff("a\nb\nc\n", "a\nB\nc\n");
        assert_eq!(diff, "  @ line 2\n- b\n+ B\n");
        assert_eq!(line_diff("same\n", "same\n"), "");
    }
}
