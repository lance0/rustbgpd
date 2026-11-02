//! The pinned `.rpol` decision corpus: every operator-facing program in
//! the tree, run against its own in-language test fixtures and a fixed
//! route matrix, with the verdict and the exact staged modifications
//! committed in `decision_corpus.golden`.
//!
//! Programs are the tracked `.rpol` files (with their imports) and the
//! ```` ```rpol ```` blocks of tracked Markdown files; Markdown blocks are
//! named by a content hash, so adding one elsewhere renames nothing.
//! `crates/policy/tests/decision_corpus/` holds small programs that give
//! every construct at least one case. The golden also records the
//! programs and policies that produce no case (and why), and a
//! per-construct count of the cases that executed it (a guard counts when
//! its term is evaluated, an action when its term matches); a construct no
//! case executes fails the test. Programs are identified by their
//! entrypoint and resolved imports. An evaluation error is recorded with
//! its outcome, which must be a deny with no modifications, and extended
//! communities carry their exact wire value.
//!
//! A change to `decision_corpus.golden` is a behaviour change; justify it
//! in the PR. After an intentional change, rewrite the golden with
//! `RPOL_DECISION_GOLDEN_BLESS=1 cargo test -p rustbgpd-policy --lib
//! corpus_decisions_are_pinned` and review every changed line.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use super::ast::{
    ActionStmt, CommunityArg, Expr, ForSource, NextHopArg, PolicyDef, Stmt, ValueExprAst,
};
use super::testing::{Fixture, override_data, render_expect};
use super::{RpolFile, lower};
use crate::datasets::{DatasetBindings, DatasetHandle};
use crate::engine::{NextHopAction, PolicyAction, RouteModifications};
use crate::ir::{CompiledChain, MatchExpr, Term, TermAction, ValueExpr};
use crate::sets::SetStore;

/// The curated programs that give every construct a case.
const CURATED: &str = "crates/policy/tests/decision_corpus/";

/// The fixed route matrix every zero-parameter policy runs against. It
/// is parsed by the in-language fixture parser, so the fields mean what
/// they mean in a `test` block.
const MATRIX: &str = r#"
policy corpus-matrix { term t { accept } }
test m01-v4-transit {
    route {
        prefix 192.0.2.0/24; next-hop 198.51.100.1; as-path "64500 64501 64502"
        communities [65000:100, 64500:1]; local-pref 100; med 50
        rpki valid; aspa valid; family ipv4-unicast; route-type external
    }
    peer { address 198.51.100.1; asn 64500; group "transit"; local-as 65000 }
    expect corpus-matrix == accept
}
test m02-v4-invalid-long {
    route {
        prefix 10.0.0.0/8; next-hop 198.51.100.9
        as-path "64496 64496 64496 64497 64498 64499 64500 64501 64502 64503 64504 64505"
        communities [65000:666, 65535:666, 64512:7]; med 1000
        rpki invalid; aspa invalid; family ipv4-unicast; route-type external
    }
    peer { address 198.51.100.9; asn 64496; group "peers"; local-as 65000 }
    expect corpus-matrix == accept
}
test m03-v6-tagged {
    route {
        prefix 2001:db8:100::/48; next-hop 2001:db8::1; as-path "64510 64511"
        communities [NO_EXPORT, 65000:200, 65001:999]
        large-communities [65000:1:2, 64510:0:1, 4200000000:7:7]
        ext-communities [RT:65000:1, RO:64510:5, OV_INVALID]
        local-pref 150; rpki not-found; aspa unknown; family ipv6-unicast; route-type external
    }
    peer { address 2001:db8::1; asn 64510; group "customers"; local-as 65000 }
    expect corpus-matrix == accept
}
test m04-bare {
    route { prefix 203.0.113.0/24 }
    expect corpus-matrix == accept
}
test m05-internal {
    route {
        prefix 203.0.113.128/25; next-hop 192.0.2.10; local-pref 300; med 0
        communities [65000:1, GRACEFUL_SHUTDOWN]; rpki valid; family ipv4-unicast
        route-type internal
    }
    peer { address 192.0.2.10; asn 65000; group "ibgp"; local-as 65000 }
    expect corpus-matrix == accept
}
test m06-local-as-set {
    route {
        prefix 198.51.100.0/24; as-path "64500 {64501 64502}"
        communities [BLACKHOLE, 64512:1, 65534:65535]
        large-communities [65000:0:0, 65000:1000:5]
        ext-communities [RT:192.0.2.1:7, OV_VALID]
        route-type local; family ipv4-unicast
    }
    peer { address 198.51.100.2; asn 4200000001; local-as 65000 }
    expect corpus-matrix == accept
}
test m07-default {
    route {
        prefix 0.0.0.0/0; next-hop 198.51.100.1; as-path "64500"; rpki not-found
        family ipv4-unicast; route-type external
    }
    peer { address 198.51.100.1; asn 64500; local-as 65000 }
    expect corpus-matrix == accept
}
test m08-host-routes {
    route {
        prefix 192.0.2.1/32; next-hop 198.51.100.7; as-path "64501 64500"
        communities [65000:100, 65000:200, 65000:300]; med 4294967295
        local-pref 4294967295; family ipv4-unicast; route-type external
    }
    peer { address 198.51.100.7; asn 64501; group "transit"; local-as 65000 }
    expect corpus-matrix == accept
}
test m09-evpn {
    route {
        prefix 192.0.2.0/24; family evpn; evpn-route-type 2
        ext-communities [RT:65000:100]; route-type internal
    }
    peer { address 192.0.2.20; asn 65000; group "rr-clients"; local-as 65000 }
    expect corpus-matrix == accept
}
test m10-v6-bogon {
    route {
        prefix 2001:db8::/32; next-hop 2001:db8::2; as-path "64512 64513"
        communities [65000:666]; large-communities [64512:666:0]
        rpki invalid; aspa valid; family ipv6-unicast; route-type external
    }
    peer { address 2001:db8::2; asn 64512; group "peers"; local-as 65000 }
    expect corpus-matrix == accept
}
"#;

#[derive(Default)]
struct Corpus {
    cases: Vec<String>,
    skipped: Vec<String>,
    counts: BTreeMap<&'static str, usize>,
}

/// One program of the corpus.
struct Program {
    id: String,
    text: String,
    /// The file, for `.rpol` files (import resolution).
    path: Option<PathBuf>,
}

/// A short, stable content name for a block or raw-string program.
fn content_id(text: &str) -> String {
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(text.as_bytes());
    format!("{:016x}", u64::from_be_bytes(hash[..8].try_into().unwrap()))
}

impl Corpus {
    /// Credit one case to every construct its evaluation of `ctx` reached:
    /// the guards of the IR terms it evaluated, the actions of the terms
    /// whose guard matched, and the AST statements of the source terms
    /// with a matched IR term. Loop bodies are credited whole when their
    /// loop term runs; the evaluator does not report body-term reachability.
    fn count(
        &mut self,
        chain: &CompiledChain,
        policies: &[&PolicyDef],
        ctx: &crate::RouteContext<'_>,
    ) {
        let mut evaluated = chain.zero_term_hits();
        let mut matched = chain.zero_term_hits();
        let _ = chain.evaluate_recording_coverage(ctx, &mut evaluated, &mut matched);
        let mut seen = std::collections::BTreeSet::new();
        let mut matched_source_terms: Vec<std::collections::BTreeSet<&str>> = Vec::new();
        for (index, policy) in chain.policies.iter().enumerate() {
            let mut source_terms = std::collections::BTreeSet::new();
            for (term_index, term) in policy.terms.iter().enumerate() {
                if evaluated[index][term_index] > 0 {
                    ir_guard(&term.guard, &mut seen);
                }
                if matched[index][term_index] > 0 {
                    ir_action(term, &mut seen);
                    if let Some(name) = &term.name {
                        source_terms.insert(name.split(['.', '/']).next().unwrap_or(name));
                    }
                }
            }
            matched_source_terms.push(source_terms);
        }
        for (index, def) in policies.iter().enumerate() {
            let source_terms = &matched_source_terms[index.min(matched_source_terms.len() - 1)];
            for term in &def.terms {
                if source_terms.contains(term.name.node.as_str()) {
                    ast_stmts(&term.stmts, &mut seen);
                }
            }
            if def.default_action.is_some() {
                seen.insert("ast.policy.default-action");
            }
            if !def.params.is_empty() {
                seen.insert("ast.policy.parameters");
            }
        }
        for name in seen {
            assert!(
                CONSTRUCTS.contains(&name),
                "construct {name} is missing from CONSTRUCTS"
            );
            *self.counts.entry(name).or_default() += 1;
        }
    }
}

fn verdict(result: &crate::PolicyResult, evaluation: &crate::PolicyEvaluation) -> String {
    let mut out = match result.action {
        PolicyAction::Permit => "permit".to_string(),
        PolicyAction::Deny => "deny".to_string(),
    };
    if let Some(error) = &evaluation.eval_error {
        // ADR-0103 Decision 4: an evaluation error denies and discards
        // every staged modification.
        assert!(
            result.action == PolicyAction::Deny && result.modifications.is_empty(),
            "an evaluation error must deny with no modifications"
        );
        out = format!("{out} (error {})", error.kind.label());
    }
    let mods = render_mods(&result.modifications);
    if !mods.is_empty() {
        out.push_str(" with ");
        out.push_str(&mods);
    }
    out
}

/// Staged modifications in `.rpol` action spelling, in a fixed field
/// order and staged value order.
fn render_mods(mods: &RouteModifications) -> String {
    let std = |value: &u32| format!("{}:{}", value >> 16, value & 0xFFFF);
    let mut parts = Vec::new();
    if let Some(value) = mods.set_local_pref {
        parts.push(format!("set local-pref {value}"));
    }
    if let Some(value) = mods.set_med {
        parts.push(format!("set med {value}"));
    }
    match &mods.set_next_hop {
        Some(NextHopAction::Self_) => parts.push("set next-hop self".to_string()),
        Some(NextHopAction::Specific(addr)) => parts.push(format!("set next-hop {addr}")),
        None => {}
    }
    if let Some((asn, count)) = mods.as_path_prepend {
        parts.push(format!("prepend as {asn} {count}"));
    }
    if mods.as_path_prepend_computed.is_some()
        || mods.set_local_pref_computed.is_some()
        || mods.set_med_computed.is_some()
    {
        parts.push("UNRESOLVED-COMPUTED".to_string());
    }
    for (verb, values) in [
        ("add", &mods.communities_add),
        ("remove", &mods.communities_remove),
    ] {
        parts.extend(
            values
                .iter()
                .map(|v| format!("{verb} community {}", std(v))),
        );
    }
    for (verb, values) in [
        ("add", &mods.large_communities_add),
        ("remove", &mods.large_communities_remove),
    ] {
        parts.extend(values.iter().map(|v| format!("{verb} large-community {v}")));
    }
    for (verb, values) in [
        ("add", &mods.extended_communities_add),
        ("remove", &mods.extended_communities_remove),
    ] {
        parts.extend(
            values
                .iter()
                .map(|v| format!("{verb} ext-community {v} ({:#018x})", v.as_u64())),
        );
    }
    parts.join("; ")
}

fn evaluate(chain: &CompiledChain, fixture: &Fixture) -> String {
    let (result, evaluation) = chain.evaluate_with_attribution(&fixture.context());
    verdict(&result, &evaluation)
}

/// Compile a program standalone, or from its file with its imports.
fn compile_program(program: &Program) -> Option<RpolFile> {
    RpolFile::parse(&program.text).ok().or_else(|| {
        let path = program.path.as_ref()?;
        RpolFile::load(
            path,
            &[path.parent().unwrap().to_path_buf()],
            super::DEFAULT_MAX_GRAPH_BYTES,
        )
        .ok()
    })
}

/// The identity of a compiled program: the entrypoint and every module
/// its imports resolved to, in resolution order.
fn program_identity(program: &Program, file: Option<&RpolFile>) -> String {
    match file {
        Some(file) => content_id(
            &file
                .modules
                .iter()
                .map(|module| module.digest.as_str())
                .collect::<Vec<_>>()
                .join(" "),
        ),
        None => content_id(&program.text),
    }
}

fn run_source(
    corpus: &mut Corpus,
    program: &Program,
    file: Option<&RpolFile>,
    matrix: &[(String, Fixture)],
) {
    let id = program.id.as_str();
    let Some(file) = file else {
        corpus.skipped.push(format!(
            "{id}: does not compile (a deliberate error, or datasets bound by config)"
        ));
        return;
    };
    // The curated programs' own expectations must hold; elsewhere (fuzz
    // seeds, receipts) a failing in-language test is recorded.
    let report = file.run_tests();
    if id.starts_with(CURATED) {
        assert!(
            report.all_passed(),
            "{id}: in-language tests fail: {:?}",
            report.failures
        );
    } else if !report.all_passed() {
        let names: Vec<&str> = report.failures.iter().map(|f| f.name.as_str()).collect();
        corpus.skipped.push(format!(
            "{id}: in-language tests fail: {}",
            names.join(", ")
        ));
    }
    let mut store = SetStore::new();
    let mut lowerer = lower::Lowerer::from_tables(&file.file, file.tables());
    let policy_def = |name: &str| file.file.policies.iter().find(|p| p.name.node == name);

    // The program's own in-language expectations.
    for test in &file.file.tests {
        let fixture = Fixture::build(test);
        let mut bindings = DatasetBindings::new();
        for def in &test.datasets {
            let kind = lowerer
                .dataset_kind(&def.name.node)
                .expect("typechecked: override names a declared dataset");
            bindings.insert(Arc::new(DatasetHandle::new(
                &def.name.node,
                kind,
                override_data(kind, &def.entries),
            )));
        }
        for expect in &test.expects {
            let call = render_expect(expect);
            let line =
                match super::testing::assemble_chain(expect, &mut lowerer, &mut store, &bindings) {
                    Ok((mut chain, _)) => {
                        chain.local_asn = fixture.local_asn;
                        let defs: Vec<&PolicyDef> = expect
                            .calls
                            .iter()
                            .filter_map(|call| policy_def(&call.policy.node))
                            .collect();
                        corpus.count(&chain, &defs, &fixture.context());
                        evaluate(&chain, &fixture)
                    }
                    Err(_) => "does not assemble".to_string(),
                };
            corpus
                .cases
                .push(format!("{id} | test {} | {call} => {line}", test.name.node));
        }
    }

    // Every zero-parameter policy against the route matrix.
    let empty = DatasetBindings::new();
    for def in &file.file.policies {
        let name = def.name.node.as_str();
        if !def.params.is_empty() {
            corpus.skipped.push(format!(
                "{id}: policy {name} takes parameters (in-language tests only)"
            ));
            continue;
        }
        let mut chain = lowerer.instantiate_member(name, &[], &mut store, &empty);
        if !lowerer.take_missing_datasets().is_empty() {
            corpus.skipped.push(format!(
                "{id}: policy {name} probes a dataset (in-language tests only)"
            ));
            continue;
        }
        for (route, fixture) in matrix {
            chain.local_asn = fixture.local_asn;
            corpus.count(&chain, &[def], &fixture.context());
            let line = evaluate(&chain, fixture);
            corpus
                .cases
                .push(format!("{id} | {name} | {route} => {line}"));
        }
    }
}

/// The tracked files of the tree (`git ls-files`), or every file under
/// `root` outside dot directories and `target` when `root` is not a git
/// work tree.
fn tracked_files(root: &Path) -> Vec<PathBuf> {
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if path.is_dir() {
                if !name.starts_with('.') && name != "target" {
                    walk(&path, out);
                }
            } else {
                out.push(path);
            }
        }
    }
    let listed = std::process::Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["ls-files", "-z", "--", "*.rpol", "*.md"])
        .output()
        .ok()
        .filter(|output| output.status.success());
    let mut files = Vec::new();
    if let Some(output) = listed {
        files.extend(
            output
                .stdout
                .split(|&byte| byte == 0)
                .filter(|name| !name.is_empty())
                .map(|name| root.join(String::from_utf8_lossy(name).as_ref()))
                .filter(|path| path.is_file()),
        );
    } else {
        walk(root, &mut files);
    }
    files.sort();
    files
}

/// Every `.rpol` file and every ```` ```rpol ```` Markdown block, in path
/// order.
fn programs(root: &Path) -> Vec<Program> {
    let mut out = Vec::new();
    for path in tracked_files(root) {
        let rel = path
            .strip_prefix(root)
            .unwrap()
            .to_string_lossy()
            .into_owned();
        match path.extension().and_then(|ext| ext.to_str()) {
            Some("rpol") => {
                let text = std::fs::read_to_string(&path).unwrap();
                out.push(Program {
                    id: rel,
                    text,
                    path: Some(path),
                });
            }
            Some("md") => {
                let text = std::fs::read_to_string(&path).unwrap();
                for body in markdown_blocks(&text) {
                    out.push(Program {
                        id: format!("{rel}#{}", content_id(&body)),
                        text: body,
                        path: None,
                    });
                }
            }
            _ => {}
        }
    }
    out
}

/// The bodies of the ```` ```rpol ```` blocks of a Markdown file.
fn markdown_blocks(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(at) = rest.find("```rpol\n") {
        let body = &rest[at + "```rpol\n".len()..];
        let Some(stop) = body.find("```") else { break };
        out.push(body[..stop].to_string());
        rest = &body[stop + 3..];
    }
    out
}

fn render(root: &Path) -> (String, Vec<&'static str>) {
    let matrix_file = RpolFile::parse(MATRIX).expect("the route matrix parses");
    let matrix: Vec<(String, Fixture)> = matrix_file
        .file
        .tests
        .iter()
        .map(|test| (test.name.node.clone(), Fixture::build(test)))
        .collect();
    let mut corpus = Corpus::default();
    let programs = programs(root);
    // A program that repeats an earlier one, entrypoint and resolved
    // imports alike (the generated receipt configs repeat a handful of
    // programs), decides identically; it is listed once against the first
    // copy instead of repeating its cases.
    let mut first_copy: BTreeMap<String, &str> = BTreeMap::new();
    let mut duplicates = Vec::new();
    for program in &programs {
        let file = compile_program(program);
        let identity = program_identity(program, file.as_ref());
        if let Some(first) = first_copy.get(&identity) {
            duplicates.push(format!("{} = {first}", program.id));
            continue;
        }
        first_copy.insert(identity, &program.id);
        run_source(&mut corpus, program, file.as_ref(), &matrix);
    }
    let mut out = String::new();
    writeln!(
        out,
        "# rpol decision corpus: {} programs, {} cases. Regenerate with\n\
         # RPOL_DECISION_GOLDEN_BLESS=1 cargo test -p rustbgpd-policy --lib corpus_decisions_are_pinned",
        programs.len(),
        corpus.cases.len()
    )
    .unwrap();
    out.push_str("\n## constructs (cases exercising each)\n");
    let mut uncovered = Vec::new();
    for name in CONSTRUCTS {
        let count = corpus.counts.get(name).copied().unwrap_or(0);
        if count == 0 {
            uncovered.push(*name);
        }
        writeln!(out, "{name} {count}").unwrap();
    }
    out.push_str("\n## programs and policies without cases\n");
    for line in &corpus.skipped {
        writeln!(out, "{line}").unwrap();
    }
    out.push_str("\n## programs identical to an earlier one\n");
    for line in &duplicates {
        writeln!(out, "{line}").unwrap();
    }
    out.push_str("\n## cases\n");
    for line in &corpus.cases {
        writeln!(out, "{line}").unwrap();
    }
    (out, uncovered)
}

/// Every v1-candidate construct the counter knows: parser AST node kinds
/// and compiled IR guards, actions and modifications.
const CONSTRUCTS: &[&str] = &[
    "ast.policy.default-action",
    "ast.policy.parameters",
    "ast.stmt.if",
    "ast.stmt.else-if",
    "ast.stmt.else",
    "ast.stmt.nested-if",
    "ast.stmt.for",
    "ast.for.field",
    "ast.for.set",
    "ast.action.accept",
    "ast.action.reject",
    "ast.action.set-local-pref",
    "ast.action.set-med",
    "ast.action.set-next-hop-self",
    "ast.action.set-next-hop-address",
    "ast.action.community-literal",
    "ast.action.large-community-admin-wildcard",
    "ast.action.community-all",
    "ast.action.community-binding",
    "ast.action.community-in-set",
    "ast.action.community-not-in-set",
    "ast.action.prepend",
    "ast.action.let",
    "ast.action.break",
    "ast.action.continue",
    "ast.expr.or",
    "ast.expr.and",
    "ast.expr.not",
    "ast.expr.cmp",
    "ast.expr.in",
    "ast.expr.ident-in",
    "ast.expr.has",
    "ast.expr.matches",
    "ast.expr.contains",
    "ast.expr.value-cmp",
    "ast.expr.apply",
    "ast.value.literal",
    "ast.value.identifier",
    "ast.value.field",
    "ast.value.arithmetic",
    "ast.value.call",
    "ir.guard.true",
    "ir.guard.prefix-in-set",
    "ir.guard.prefix-eq",
    "ir.guard.prefix-ne",
    "ir.guard.community-contains",
    "ir.guard.community-in-set",
    "ir.guard.as-path-matches",
    "ir.guard.as-path-len",
    "ir.guard.origin-as-eq",
    "ir.guard.origin-as-ne",
    "ir.guard.origin-as-in-set",
    "ir.guard.peer-as-in-set",
    "ir.guard.local-pref",
    "ir.guard.med",
    "ir.guard.next-hop-eq",
    "ir.guard.next-hop-eq-peer",
    "ir.guard.next-hop-ne",
    "ir.guard.next-hop-ne-peer",
    "ir.guard.neighbor-in",
    "ir.guard.neighbor-ne",
    "ir.guard.route-type-is",
    "ir.guard.route-type-ne",
    "ir.guard.evpn-route-type-is",
    "ir.guard.evpn-route-type-ne",
    "ir.guard.family-is",
    "ir.guard.family-ne",
    "ir.guard.rpki-is",
    "ir.guard.aspa-is",
    "ir.guard.value-cmp",
    "ir.guard.local-in-asn-set",
    "ir.guard.local-in-community-set",
    "ir.guard.in-dataset",
    "ir.guard.and",
    "ir.guard.or",
    "ir.guard.not",
    "ir.value.const",
    "ir.value.field",
    "ir.value.local",
    "ir.value.binary",
    "ir.value.min",
    "ir.value.max",
    "ir.value.clamp",
    "ir.action.permit",
    "ir.action.deny",
    "ir.action.continue",
    "ir.action.bind",
    "ir.action.for-each",
    "ir.action.break",
    "ir.action.continue-loop",
    "ir.action.community-var",
    "ir.action.remove-large-community-admin",
    "ir.action.remove-all-communities",
    "ir.action.remove-communities-in-set",
    "ir.mod.set-local-pref",
    "ir.mod.set-local-pref-computed",
    "ir.mod.set-med",
    "ir.mod.set-med-computed",
    "ir.mod.set-next-hop",
    "ir.mod.prepend",
    "ir.mod.prepend-computed",
    "ir.mod.community-add",
    "ir.mod.community-remove",
    "ir.mod.large-community-add",
    "ir.mod.large-community-remove",
    "ir.mod.ext-community-add",
    "ir.mod.ext-community-remove",
];

fn ast_stmts(stmts: &[Stmt], seen: &mut std::collections::BTreeSet<&'static str>) {
    for stmt in stmts {
        match stmt {
            Stmt::If(if_stmt) => {
                seen.insert("ast.stmt.if");
                if if_stmt.branches.len() > 1 {
                    seen.insert("ast.stmt.else-if");
                }
                if if_stmt.else_body.is_some() {
                    seen.insert("ast.stmt.else");
                }
                for branch in &if_stmt.branches {
                    ast_expr(&branch.cond, seen);
                    if branch.body.iter().any(|s| matches!(s, Stmt::If(_))) {
                        seen.insert("ast.stmt.nested-if");
                    }
                    ast_stmts(&branch.body, seen);
                }
                if let Some(else_body) = &if_stmt.else_body {
                    if else_body.body.iter().any(|s| matches!(s, Stmt::If(_))) {
                        seen.insert("ast.stmt.nested-if");
                    }
                    ast_stmts(&else_body.body, seen);
                }
            }
            Stmt::Action(action) => ast_action(action, seen),
            Stmt::For(for_stmt) => {
                seen.insert("ast.stmt.for");
                seen.insert(match for_stmt.source {
                    ForSource::Field(_) => "ast.for.field",
                    ForSource::Set(_) => "ast.for.set",
                });
                ast_stmts(&for_stmt.body, seen);
            }
        }
    }
}

fn ast_action(action: &ActionStmt, seen: &mut std::collections::BTreeSet<&'static str>) {
    let name = match action {
        ActionStmt::Accept(_) => "ast.action.accept",
        ActionStmt::Reject(_) => "ast.action.reject",
        ActionStmt::SetLocalPref(value, _) => {
            ast_value(value, seen);
            "ast.action.set-local-pref"
        }
        ActionStmt::SetMed(value, _) => {
            ast_value(value, seen);
            "ast.action.set-med"
        }
        ActionStmt::SetNextHop(NextHopArg::Self_(_), _) => "ast.action.set-next-hop-self",
        ActionStmt::SetNextHop(NextHopArg::Addr(..), _) => "ast.action.set-next-hop-address",
        ActionStmt::Community { arg, .. } => match arg {
            CommunityArg::Lit(_) => "ast.action.community-literal",
            CommunityArg::LargeAdminWildcard(_) => "ast.action.large-community-admin-wildcard",
            CommunityArg::All(_) => "ast.action.community-all",
            CommunityArg::Var(_) => "ast.action.community-binding",
            CommunityArg::InSet { negate: false, .. } => "ast.action.community-in-set",
            CommunityArg::InSet { negate: true, .. } => "ast.action.community-not-in-set",
        },
        ActionStmt::Prepend { .. } => "ast.action.prepend",
        ActionStmt::Let { init, .. } => {
            ast_value(init, seen);
            "ast.action.let"
        }
        ActionStmt::Break(_) => "ast.action.break",
        ActionStmt::Continue(_) => "ast.action.continue",
    };
    seen.insert(name);
}

fn ast_expr(expr: &Expr, seen: &mut std::collections::BTreeSet<&'static str>) {
    let name = match expr {
        Expr::Or(lhs, rhs) | Expr::And(lhs, rhs) => {
            ast_expr(lhs, seen);
            ast_expr(rhs, seen);
            if matches!(expr, Expr::Or(..)) {
                "ast.expr.or"
            } else {
                "ast.expr.and"
            }
        }
        Expr::Not(inner, _) => {
            ast_expr(inner, seen);
            "ast.expr.not"
        }
        Expr::Cmp { .. } => "ast.expr.cmp",
        Expr::In { .. } => "ast.expr.in",
        Expr::IdentIn { .. } => "ast.expr.ident-in",
        Expr::Has { .. } => "ast.expr.has",
        Expr::Matches { .. } => "ast.expr.matches",
        Expr::Contains { .. } => "ast.expr.contains",
        Expr::ValueCmp { lhs, rhs, .. } => {
            ast_value(lhs, seen);
            ast_value(rhs, seen);
            "ast.expr.value-cmp"
        }
        Expr::Apply { .. } => "ast.expr.apply",
    };
    seen.insert(name);
}

fn ast_value(value: &ValueExprAst, seen: &mut std::collections::BTreeSet<&'static str>) {
    let name = match value {
        ValueExprAst::Lit(..) => "ast.value.literal",
        ValueExprAst::Ident(_) => "ast.value.identifier",
        ValueExprAst::Field(_) => "ast.value.field",
        ValueExprAst::Binary { lhs, rhs, .. } => {
            ast_value(lhs, seen);
            ast_value(rhs, seen);
            "ast.value.arithmetic"
        }
        ValueExprAst::Call { args, .. } => {
            for arg in args {
                ast_value(arg, seen);
            }
            "ast.value.call"
        }
    };
    seen.insert(name);
}

/// The constructs an executed term's action uses.
fn ir_action(term: &Term, seen: &mut std::collections::BTreeSet<&'static str>) {
    let mods = match &term.action {
        TermAction::Permit(mods) => {
            seen.insert("ir.action.permit");
            Some(mods)
        }
        TermAction::Deny => {
            seen.insert("ir.action.deny");
            None
        }
        TermAction::Continue(mods) => {
            seen.insert("ir.action.continue");
            Some(mods)
        }
        TermAction::Bind { expr, .. } => {
            seen.insert("ir.action.bind");
            ir_value(expr, seen);
            None
        }
        TermAction::ForEach(node) => {
            seen.insert("ir.action.for-each");
            for body in &node.body {
                ir_guard(&body.guard, seen);
                ir_action(body, seen);
            }
            None
        }
        TermAction::Break => {
            seen.insert("ir.action.break");
            None
        }
        TermAction::ContinueLoop => {
            seen.insert("ir.action.continue-loop");
            None
        }
        TermAction::CommunityVar { .. } => {
            seen.insert("ir.action.community-var");
            None
        }
        TermAction::RemoveLargeCommunityAdmin { .. } => {
            seen.insert("ir.action.remove-large-community-admin");
            None
        }
        TermAction::RemoveAllCommunities { .. } => {
            seen.insert("ir.action.remove-all-communities");
            None
        }
        TermAction::RemoveCommunitiesInSet { .. } => {
            seen.insert("ir.action.remove-communities-in-set");
            None
        }
    };
    let Some(mods) = mods else { return };
    for (present, name) in [
        (mods.set_local_pref.is_some(), "ir.mod.set-local-pref"),
        (
            mods.set_local_pref_computed.is_some(),
            "ir.mod.set-local-pref-computed",
        ),
        (mods.set_med.is_some(), "ir.mod.set-med"),
        (mods.set_med_computed.is_some(), "ir.mod.set-med-computed"),
        (mods.set_next_hop.is_some(), "ir.mod.set-next-hop"),
        (mods.as_path_prepend.is_some(), "ir.mod.prepend"),
        (
            mods.as_path_prepend_computed.is_some(),
            "ir.mod.prepend-computed",
        ),
        (!mods.communities_add.is_empty(), "ir.mod.community-add"),
        (
            !mods.communities_remove.is_empty(),
            "ir.mod.community-remove",
        ),
        (
            !mods.large_communities_add.is_empty(),
            "ir.mod.large-community-add",
        ),
        (
            !mods.large_communities_remove.is_empty(),
            "ir.mod.large-community-remove",
        ),
        (
            !mods.extended_communities_add.is_empty(),
            "ir.mod.ext-community-add",
        ),
        (
            !mods.extended_communities_remove.is_empty(),
            "ir.mod.ext-community-remove",
        ),
    ] {
        if present {
            seen.insert(name);
        }
    }
    for expr in mods
        .set_local_pref_computed
        .iter()
        .chain(mods.set_med_computed.iter())
    {
        ir_value(expr, seen);
    }
}

fn ir_guard(expr: &MatchExpr, seen: &mut std::collections::BTreeSet<&'static str>) {
    let name = match expr {
        MatchExpr::True => "ir.guard.true",
        MatchExpr::PrefixInSet(_) => "ir.guard.prefix-in-set",
        MatchExpr::PrefixEq { .. } => "ir.guard.prefix-eq",
        MatchExpr::PrefixNe { .. } => "ir.guard.prefix-ne",
        MatchExpr::CommunityContains(_) => "ir.guard.community-contains",
        MatchExpr::CommunityInSet(_) => "ir.guard.community-in-set",
        MatchExpr::AsPathMatches(_) => "ir.guard.as-path-matches",
        MatchExpr::AsPathLen(_) => "ir.guard.as-path-len",
        MatchExpr::OriginAsEq(_) => "ir.guard.origin-as-eq",
        MatchExpr::OriginAsNe(_) => "ir.guard.origin-as-ne",
        MatchExpr::OriginAsInSet(_) => "ir.guard.origin-as-in-set",
        MatchExpr::PeerAsInSet(_) => "ir.guard.peer-as-in-set",
        MatchExpr::LocalPref(_) => "ir.guard.local-pref",
        MatchExpr::Med(_) => "ir.guard.med",
        MatchExpr::NextHopEq(_) => "ir.guard.next-hop-eq",
        MatchExpr::NextHopEqPeer => "ir.guard.next-hop-eq-peer",
        MatchExpr::NextHopNe(_) => "ir.guard.next-hop-ne",
        MatchExpr::NextHopNePeer => "ir.guard.next-hop-ne-peer",
        MatchExpr::NeighborIn(_) => "ir.guard.neighbor-in",
        MatchExpr::NeighborNe(_) => "ir.guard.neighbor-ne",
        MatchExpr::RouteTypeIs(_) => "ir.guard.route-type-is",
        MatchExpr::RouteTypeNe(_) => "ir.guard.route-type-ne",
        MatchExpr::EvpnRouteTypeIs(_) => "ir.guard.evpn-route-type-is",
        MatchExpr::EvpnRouteTypeNe(_) => "ir.guard.evpn-route-type-ne",
        MatchExpr::FamilyIs(_) => "ir.guard.family-is",
        MatchExpr::FamilyNe(_) => "ir.guard.family-ne",
        MatchExpr::RpkiIs(_) => "ir.guard.rpki-is",
        MatchExpr::AspaIs(_) => "ir.guard.aspa-is",
        MatchExpr::ValueCmp(node) => {
            ir_value(&node.lhs, seen);
            ir_value(&node.rhs, seen);
            "ir.guard.value-cmp"
        }
        MatchExpr::LocalInAsnSet { .. } => "ir.guard.local-in-asn-set",
        MatchExpr::LocalInCommunitySet { .. } => "ir.guard.local-in-community-set",
        MatchExpr::InDataset { .. } => "ir.guard.in-dataset",
        MatchExpr::And(children) | MatchExpr::Or(children) => {
            for child in children {
                ir_guard(child, seen);
            }
            if matches!(expr, MatchExpr::And(_)) {
                "ir.guard.and"
            } else {
                "ir.guard.or"
            }
        }
        MatchExpr::Not(inner) => {
            ir_guard(inner, seen);
            "ir.guard.not"
        }
    };
    seen.insert(name);
}

fn ir_value(expr: &ValueExpr, seen: &mut std::collections::BTreeSet<&'static str>) {
    let name = match expr {
        ValueExpr::Const(_) => "ir.value.const",
        ValueExpr::Field(_) => "ir.value.field",
        ValueExpr::Local { .. } => "ir.value.local",
        ValueExpr::Binary { lhs, rhs, .. } => {
            ir_value(lhs, seen);
            ir_value(rhs, seen);
            "ir.value.binary"
        }
        ValueExpr::Min(lhs, rhs) | ValueExpr::Max(lhs, rhs) => {
            ir_value(lhs, seen);
            ir_value(rhs, seen);
            if matches!(expr, ValueExpr::Min(..)) {
                "ir.value.min"
            } else {
                "ir.value.max"
            }
        }
        ValueExpr::Clamp(value, lo, hi) => {
            ir_value(value, seen);
            ir_value(lo, seen);
            ir_value(hi, seen);
            "ir.value.clamp"
        }
    };
    seen.insert(name);
}

#[test]
fn corpus_decisions_are_pinned() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let root = manifest.join("../..");
    let golden_path = manifest.join("src/rpol/decision_corpus.golden");
    let (rendered, uncovered) = render(&root);
    let bless = std::env::var_os("RPOL_DECISION_GOLDEN_BLESS").is_some();
    if bless {
        std::fs::write(&golden_path, &rendered).unwrap();
    }
    assert!(
        uncovered.is_empty(),
        "constructs with no corpus case: {uncovered:?}; add a program with `expect` tests \
         under {CURATED}"
    );
    if bless {
        return;
    }
    let golden = std::fs::read_to_string(&golden_path).unwrap();
    if golden == rendered {
        return;
    }
    // Pair changed cases by their key (the text left of `=>`), so each
    // change reads as golden-then-now; other lines diff as plain sets.
    let split = |text: &str| -> BTreeMap<String, String> {
        text.lines()
            .map(|line| match line.split_once(" => ") {
                Some((key, outcome)) => (key.to_string(), outcome.to_string()),
                None => (line.to_string(), String::new()),
            })
            .collect()
    };
    let (old, new) = (split(&golden), split(&rendered));
    let mut diff = String::new();
    let mut shown = 0;
    for key in old
        .keys()
        .chain(new.keys().filter(|key| !old.contains_key(*key)))
    {
        let (before, after) = (old.get(key), new.get(key));
        if before == after {
            continue;
        }
        shown += 1;
        if shown > 40 {
            continue;
        }
        let render = |side: Option<&String>| side.map_or("(absent)".to_string(), Clone::clone);
        writeln!(
            diff,
            "{key}\n    golden: {}\n    now:    {}",
            render(before),
            render(after)
        )
        .unwrap();
    }
    panic!(
        "{shown} rpol corpus lines changed (first 40 shown). Bless only an \
         intentional change, with RPOL_DECISION_GOLDEN_BLESS=1:\n{diff}"
    );
}
