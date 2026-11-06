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
//! communities carry their exact wire value. The golden also pins every
//! row each instantiation lowers to: its name (the name explain, test term
//! hits and policy stats show), its position, and its action with the
//! values, bindings and loop body it holds, though not its guard. A
//! lowering change that renames, reorders or refills a row fails like a
//! decision change, and two rows with one name fail outright.
//!
//! [`CONSTRUCTS`] is the exhaustive construct list: the name functions
//! below match every AST and IR enum they meet without a wildcard, and
//! destructure the AST structs and `RouteModifications` without a rest
//! pattern, so a new variant or field does not compile until it is named.
//! Parser sugar that desugars into an existing variant, or a new variant
//! mapped to an existing name, needs review to catch. The v1 construct
//! inventory in `docs/reference/v1-stable-surface.json` classifies every
//! name, and `scripts/check-v1-stable-surface.py` checks the two agree.
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
    ActionStmt, AsnSetDef, CallArg, CallStmt, CmpOp, CommunityArg, CommunityKind, CommunityLit,
    CommunitySetDef, DatasetDecl, DatasetEntryAst, ElseBody, ExpectCall, ExpectDef, ExpectVerdict,
    Expr, FieldPath, FnDef, FnLet, ForSource, ForStmt, IfBranch, IfStmt, NextHopArg, ParamType,
    PeerField, PolicyDef, PrefixEntryAst, PrefixSetDef, PrependAsArg, Rhs, RouteField, ScalarAttr,
    SourceFile, Stmt, TermDef, TestDatasetDef, TestDef, U32Arg, ValueExprAst, WithAssertion,
};
use super::diag::Spanned;
use super::testing::{Fixture, override_data, render_expect};
use super::typeck::{Field, resolve_field};
use super::{RpolFile, lower};
use crate::datasets::{DatasetBindings, DatasetHandle, DatasetKind};
use crate::engine::{
    CommunityMatch, NextHopAction, PolicyAction, PrependAs, RouteFamily, RouteModifications,
};
use crate::ir::{
    ArithOp, CommunityAttribute, CompiledChain, LoopSource, MatchExpr, Term, TermAction, ValueExpr,
};
use crate::sets::{AsnMember, CommunityField, CommunityMember, CommunityPattern, SetStore};

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
    /// The IR term names each instantiation lowers to: the names explain,
    /// test term hits and policy stats show, pinned like decisions.
    names: BTreeMap<String, String>,
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
    /// Record every row of every member of `chain` under `key`: its name and
    /// what it holds, so a rename and a moved action both show.
    /// Each row records its 1-based position, so the emission order is
    /// pinned too. A name repeated within one policy fails: it would make
    /// two stats rows indistinguishable.
    fn record_names(&mut self, key: &str, chain: &CompiledChain) {
        for policy in &chain.policies {
            let member = policy.name.as_deref().unwrap_or("-");
            let mut names = std::collections::HashSet::new();
            for (position, term) in policy.terms.iter().enumerate() {
                let name = term.name.as_deref().unwrap_or("-");
                assert!(
                    names.insert(name),
                    "{key}: policy {member} lowers two rows named {name}"
                );
                self.names.insert(
                    format!("{key} | row {member} {name}"),
                    format!("#{} {}", position + 1, row_contents(&term.action, chain)),
                );
            }
        }
    }

    /// Credit one case to every construct its evaluation of `ctx` reached:
    /// the guards of the IR terms it evaluated, the actions of the terms
    /// whose guard matched, and the AST statements of the source terms
    /// with a matched IR term. Loop bodies are credited whole when their
    /// loop term runs; the evaluator does not report body-term reachability.
    /// `declared` holds the program's declaration and test constructs
    /// ([`declared_constructs`]), credited to every case it runs.
    fn count(
        &mut self,
        chain: &CompiledChain,
        policies: &[&PolicyDef],
        ctx: &crate::RouteContext<'_>,
        declared: &Seen,
    ) {
        let mut evaluated = chain.zero_term_hits();
        let mut matched = chain.zero_term_hits();
        crate::eval::VISITED_GUARDS
            .with(|visited| *visited.borrow_mut() = Some(std::collections::HashSet::default()));
        let _ = chain.evaluate_recording_coverage(ctx, &mut evaluated, &mut matched);
        let visited = crate::eval::VISITED_GUARDS
            .with(|visited| visited.borrow_mut().take())
            .unwrap_or_default();
        let mut seen = std::collections::BTreeSet::new();
        let mut matched_source_terms: Vec<std::collections::BTreeSet<&str>> = Vec::new();
        for (index, policy) in chain.policies.iter().enumerate() {
            let mut source_terms = std::collections::BTreeSet::new();
            for (term_index, term) in policy.terms.iter().enumerate() {
                visited_guards(&term.guard, &visited, &mut seen);
                if matched[index][term_index] > 0 {
                    ir_action(term, &mut seen, &visited);
                    if let Some(name) = &term.name {
                        source_terms.insert(name.split(['.', '/']).next().unwrap_or(name));
                    }
                }
            }
            matched_source_terms.push(source_terms);
        }
        for (index, def) in policies.iter().enumerate() {
            let source_terms = &matched_source_terms[index.min(matched_source_terms.len() - 1)];
            // Destructured without `..`: a new policy-level form does not
            // compile until it is named.
            let PolicyDef {
                name: _,
                params,
                param_types,
                default_action,
                terms,
            } = def;
            for term in terms {
                let TermDef { name, stmts } = term;
                if source_terms.contains(name.node.as_str()) {
                    ast_stmts(stmts, &mut seen);
                }
            }
            if default_action.is_some() {
                seen.insert("ast.policy.default-action");
            }
            if !params.is_empty() {
                seen.insert("ast.policy.parameters");
            }
            for ty in param_types {
                seen.insert(param_type_name(*ty));
            }
        }
        seen.extend(declared);
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

/// What one lowered row does, in `.rpol` action spelling: its verdict or
/// action and the modifications it stages.
pub(super) fn row_contents(action: &TermAction, chain: &CompiledChain) -> String {
    let staged = |verb: &str, mods: &RouteModifications| {
        let mods = render_mods(mods);
        if mods.is_empty() {
            verb.to_string()
        } else {
            format!("{verb} with {mods}")
        }
    };
    match action {
        TermAction::Permit(mods) => staged("accept", mods),
        TermAction::Deny => "reject".to_string(),
        TermAction::Continue(mods) => staged("continue", mods),
        TermAction::Bind { name, expr, .. } => format!("let {name} = {expr}"),
        TermAction::ForEach(node) => {
            let source = match node.source {
                LoopSource::Communities => "route.communities",
                LoopSource::AsPath => "route.as-path",
                LoopSource::AsnSet(set) => chain
                    .asn_set_names
                    .get(set.0 as usize)
                    .and_then(Option::as_deref)
                    .unwrap_or("?"),
            };
            let body: Vec<String> = node
                .body
                .iter()
                .map(|term| row_contents(&term.action, chain))
                .collect();
            format!("for {} in {source} {{ {} }}", node.var, body.join(" | "))
        }
        TermAction::Break => "break".to_string(),
        TermAction::ContinueLoop => "next iteration".to_string(),
        TermAction::CommunityVar { add, name, .. } => {
            format!("{} community {name}", if *add { "add" } else { "remove" })
        }
        TermAction::RemoveLargeCommunityAdmin { global_admin } => {
            format!("remove large-community {global_admin}:*:*")
        }
        TermAction::RemoveAllCommunities { attributes } => attributes
            .iter()
            .map(CommunityAttribute::remove_all_str)
            .collect::<Vec<_>>()
            .join("; "),
        TermAction::RemoveCommunitiesInSet {
            attribute,
            set,
            negate,
        } => format!(
            "remove {}{} in {}",
            attribute.keyword(),
            if *negate { " not" } else { "" },
            chain
                .community_set_names
                .get(set.0 as usize)
                .and_then(Option::as_deref)
                .unwrap_or("?")
        ),
    }
}

/// Staged modifications in `.rpol` action spelling, in a fixed field
/// order and staged value order.
fn render_mods(mods: &RouteModifications) -> String {
    // Destructured without `..`: a new modification does not compile until
    // it is named here.
    let RouteModifications {
        set_local_pref,
        set_med,
        set_next_hop,
        communities_add,
        communities_remove,
        extended_communities_add,
        extended_communities_remove,
        large_communities_add,
        large_communities_remove,
        as_path_prepend,
        set_local_pref_computed,
        set_med_computed,
    } = mods;
    let std = |value: &u32| format!("{}:{}", value >> 16, value & 0xFFFF);
    let mut parts = Vec::new();
    // A lowered row stages computed values; an evaluated result never holds
    // one, so these render only in the term-name rows.
    if let Some(value) = set_local_pref {
        parts.push(format!("set local-pref {value}"));
    }
    if let Some(expr) = &set_local_pref_computed {
        parts.push(format!("set local-pref {expr}"));
    }
    if let Some(value) = set_med {
        parts.push(format!("set med {value}"));
    }
    if let Some(expr) = &set_med_computed {
        parts.push(format!("set med {expr}"));
    }
    match &set_next_hop {
        Some(NextHopAction::Self_) => parts.push("set next-hop self".to_string()),
        Some(NextHopAction::Specific(addr)) => parts.push(format!("set next-hop {addr}")),
        None => {}
    }
    // One part per prepend, in the order they run (each later one lands
    // to the left).
    for prepend in as_path_prepend {
        let asn = match prepend.asn {
            crate::engine::PrependAsn::Asn(asn) => asn.to_string(),
            crate::engine::PrependAsn::Computed(operand) => match operand {
                PrependAs::LocalAs => "self",
                PrependAs::PeerAs => "peer",
                PrependAs::OriginAs => "origin",
                PrependAs::PathFirst => "path-first",
            }
            .to_string(),
        };
        parts.push(format!("prepend as {asn} {}", prepend.count));
    }
    for (verb, values) in [("add", &communities_add), ("remove", &communities_remove)] {
        parts.extend(
            values
                .iter()
                .map(|v| format!("{verb} community {}", std(v))),
        );
    }
    for (verb, values) in [
        ("add", &large_communities_add),
        ("remove", &large_communities_remove),
    ] {
        parts.extend(values.iter().map(|v| format!("{verb} large-community {v}")));
    }
    for (verb, values) in [
        ("add", &extended_communities_add),
        ("remove", &extended_communities_remove),
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
        assert!(
            !id.starts_with(CURATED),
            "{id}: a curated corpus program does not compile"
        );
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
    let declared = declared_constructs(file);

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
                        corpus.count(&chain, &defs, &fixture.context(), &declared);
                        corpus.record_names(&format!("{id} | {call}"), &chain);
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
        corpus.record_names(&format!("{id} | {name}"), &chain);
        for (route, fixture) in matrix {
            chain.local_asn = fixture.local_asn;
            corpus.count(&chain, &[def], &fixture.context(), &declared);
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
    out.push_str(
        "\n## term names (every lowered row of every instantiation, with what it holds)\n",
    );
    for (key, names) in &corpus.names {
        writeln!(out, "{key} => {names}").unwrap();
    }
    out.push_str("\n## cases\n");
    for line in &corpus.cases {
        writeln!(out, "{line}").unwrap();
    }
    (out, uncovered)
}

/// Every construct the counter knows: parser AST node kinds, the fields,
/// operators, operands, parameter types, families, declarations, set
/// members and test forms they carry, and compiled IR guards, actions and
/// modifications. Every name a function below returns must be listed here;
/// the stable-surface checker enforces that, and that the v1 inventory
/// classifies exactly this list.
const CONSTRUCTS: &[&str] = &[
    "ast.policy.default-action",
    "ast.policy.parameters",
    "ast.stmt.if",
    "ast.stmt.else-if",
    "ast.stmt.else",
    "ast.stmt.nested-if",
    "ast.stmt.for",
    "ast.stmt.call",
    "ast.for.field",
    "ast.for.set",
    "ast.action.accept",
    "ast.action.reject",
    "ast.action.set-local-pref",
    "ast.action.set-med",
    "ast.action.set-next-hop-self",
    "ast.action.set-next-hop-address",
    "ast.action.set-next-hop-parameter",
    "ast.action.community-literal",
    "ast.action.large-community-admin-wildcard",
    "ast.action.community-all",
    "ast.action.community-binding",
    "ast.action.community-in-set",
    "ast.action.community-not-in-set",
    "ast.community.add",
    "ast.community.remove",
    "ast.community.kind.standard",
    "ast.community.kind.large",
    "ast.community.kind.extended",
    "ast.community.kind.any",
    "ast.literal.standard",
    "ast.literal.large",
    "ast.literal.route-target",
    "ast.literal.route-origin",
    "ast.literal.route-target-ipv4",
    "ast.literal.route-origin-ipv4",
    "ast.literal.well-known-ext",
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
    "ast.expr.has-parameter",
    "ast.expr.exists",
    "ast.expr.matches",
    "ast.expr.contains",
    "ast.contains.literal",
    "ast.contains.parameter",
    "ast.expr.value-cmp",
    "ast.expr.apply",
    "ast.call-arg.integer",
    "ast.call-arg.name",
    "ast.call-arg.community",
    "ast.call-arg.ip",
    "ast.value.literal",
    "ast.value.community",
    "ast.value.identifier",
    "ast.value.field",
    "ast.value.arithmetic",
    "ast.value.call",
    "ast.arith.add",
    "ast.arith.sub",
    "ast.arith.mul",
    "ast.arith.div",
    "ast.arith.rem",
    "ast.cmp.eq",
    "ast.cmp.ne",
    "ast.cmp.ge",
    "ast.cmp.le",
    "ast.rhs.integer",
    "ast.rhs.identifier",
    "ast.rhs.ip",
    "ast.rhs.prefix",
    "ast.rhs.string",
    "ast.rhs.field",
    "ast.field.route.prefix",
    "ast.field.route.communities",
    "ast.field.route.large-communities",
    "ast.field.route.ext-communities",
    "ast.field.route.any-community",
    "ast.field.route.as-path",
    "ast.field.route.as-path.len",
    "ast.field.route.communities.len",
    "ast.field.route.large-communities.len",
    "ast.field.route.ext-communities.len",
    "ast.field.route.origin-as",
    "ast.field.route.local-pref",
    "ast.field.route.med",
    "ast.field.route.next-hop",
    "ast.field.route.rpki",
    "ast.field.route.aspa",
    "ast.field.route.route-type",
    "ast.field.route.evpn-route-type",
    "ast.field.route.family",
    "ast.field.peer.address",
    "ast.field.peer.asn",
    "ast.field.peer.group",
    "ast.family.ipv4-unicast",
    "ast.family.ipv6-unicast",
    "ast.family.ipv4-labeled-unicast",
    "ast.family.ipv6-labeled-unicast",
    "ast.family.vpnv4",
    "ast.family.vpnv6",
    "ast.family.ipv4-flowspec",
    "ast.family.ipv6-flowspec",
    "ast.family.vpnv4-flowspec",
    "ast.family.vpnv6-flowspec",
    "ast.family.evpn",
    "ast.family.rtc",
    "ast.family.bgp-ls",
    "ast.family.bgp-ls-vpn",
    "ast.prepend.self",
    "ast.prepend.peer",
    "ast.prepend.origin",
    "ast.prepend.path-first",
    "ast.prepend.literal",
    "ast.prepend.parameter",
    "ast.prepend.count.literal",
    "ast.prepend.count.parameter",
    "ast.param.u32",
    "ast.param.prefix-set",
    "ast.param.community-set",
    "ast.param.asn-set",
    "ast.param.community",
    "ast.param.ip",
    "ast.decl.import",
    "ast.decl.prefix-set",
    "ast.decl.prefix-set.ge-le",
    "ast.decl.community-set",
    "ast.decl.asn-set",
    "ast.decl.dataset.prefix-set",
    "ast.decl.dataset.asn-set",
    "ast.decl.dataset.community-set",
    "ast.decl.fn",
    "ast.decl.fn.let",
    "ast.decl.test",
    "ast.set.community.standard",
    "ast.set.community.large",
    "ast.set.community.route-target",
    "ast.set.community.route-origin",
    "ast.set.community.well-known-ext",
    "ast.set.pattern.standard",
    "ast.set.pattern.large",
    "ast.set.pattern.route-target",
    "ast.set.pattern.route-origin",
    "ast.set.pattern-field.range",
    "ast.set.pattern-field.private-as",
    "ast.set.asn.range",
    "ast.set.asn.private-as",
    "ast.test.dataset-override",
    "ast.test.route.prefix",
    "ast.test.route.communities",
    "ast.test.route.large-communities",
    "ast.test.route.ext-communities",
    "ast.test.route.as-path",
    "ast.test.route.next-hop",
    "ast.test.route.local-pref",
    "ast.test.route.med",
    "ast.test.route.rpki",
    "ast.test.route.aspa",
    "ast.test.route.route-type",
    "ast.test.route.evpn-route-type",
    "ast.test.route.family",
    "ast.test.peer.address",
    "ast.test.peer.asn",
    "ast.test.peer.local-as",
    "ast.test.peer.group",
    "ast.test.expect.chain",
    "ast.test.expect.with-only",
    "ast.test.expect.accept",
    "ast.test.expect.reject",
    "ast.test.expect.error",
    "ast.test.with.local-pref",
    "ast.test.with.med",
    "ast.test.with.next-hop",
    "ast.test.with.community",
    "ast.test.with.prepend",
    "ast.test.with.prepend-path",
    "ast.test.with.removes",
    "ast.test.with.removes-large-admin",
    "ast.test.with.removes-all",
    "ast.test.with.not-removed",
    "ast.test.with.without-community",
    "ast.test.with.without.local-pref",
    "ast.test.with.without.med",
    "ast.test.with.without.next-hop",
    "ast.test.with.without.prepend",
    "ir.guard.true",
    "ir.guard.prefix-in-set",
    "ir.guard.prefix-eq",
    "ir.guard.prefix-ne",
    "ir.guard.community-contains",
    "ir.guard.community-in-set",
    "ir.guard.community-kind-in-set",
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
    "ir.guard.exists",
    "ir.guard.local-in-asn-set",
    "ir.guard.local-in-community-set",
    "ir.guard.in-dataset",
    "ir.guard.and",
    "ir.guard.or",
    "ir.guard.not",
    "ir.value.const",
    "ir.value.community",
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

type Seen = std::collections::BTreeSet<&'static str>;

fn ast_stmts(stmts: &[Stmt], seen: &mut Seen) {
    for stmt in stmts {
        match stmt {
            Stmt::If(IfStmt {
                branches,
                else_body,
            }) => {
                seen.insert("ast.stmt.if");
                if branches.len() > 1 {
                    seen.insert("ast.stmt.else-if");
                }
                if else_body.is_some() {
                    seen.insert("ast.stmt.else");
                }
                for IfBranch {
                    cond,
                    body,
                    span: _,
                } in branches
                {
                    ast_expr(cond, seen);
                    if body.iter().any(|s| matches!(s, Stmt::If(_))) {
                        seen.insert("ast.stmt.nested-if");
                    }
                    ast_stmts(body, seen);
                }
                if let Some(ElseBody { body, span: _ }) = else_body {
                    if body.iter().any(|s| matches!(s, Stmt::If(_))) {
                        seen.insert("ast.stmt.nested-if");
                    }
                    ast_stmts(body, seen);
                }
            }
            Stmt::Action(action) => ast_action(action, seen),
            Stmt::Call(CallStmt {
                policy: _,
                args,
                span: _,
            }) => {
                ast_call_args(args, seen);
                seen.insert("ast.stmt.call");
            }
            Stmt::For(ForStmt {
                var: _,
                source,
                body,
                span: _,
            }) => {
                seen.insert("ast.stmt.for");
                let source = match source {
                    ForSource::Field(path) => {
                        ast_field(path, seen);
                        "ast.for.field"
                    }
                    ForSource::Set(_) => "ast.for.set",
                };
                seen.insert(source);
                ast_stmts(body, seen);
            }
        }
    }
}

fn ast_action(action: &ActionStmt, seen: &mut Seen) {
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
        ActionStmt::SetNextHop(NextHopArg::Param(_), _) => "ast.action.set-next-hop-parameter",
        ActionStmt::Community {
            add,
            kind,
            arg,
            span: _,
        } => {
            seen.insert(if *add {
                "ast.community.add"
            } else {
                "ast.community.remove"
            });
            seen.insert(match kind {
                CommunityKind::Standard => "ast.community.kind.standard",
                CommunityKind::Large => "ast.community.kind.large",
                CommunityKind::Ext => "ast.community.kind.extended",
                CommunityKind::Any => "ast.community.kind.any",
            });
            match arg {
                CommunityArg::Lit(lit) => {
                    ast_literal(lit.node, seen);
                    "ast.action.community-literal"
                }
                CommunityArg::LargeAdminWildcard(_) => "ast.action.large-community-admin-wildcard",
                CommunityArg::All(_) => "ast.action.community-all",
                CommunityArg::Var(_) => "ast.action.community-binding",
                CommunityArg::InSet { negate: false, .. } => "ast.action.community-in-set",
                CommunityArg::InSet { negate: true, .. } => "ast.action.community-not-in-set",
            }
        }
        ActionStmt::Prepend {
            asn,
            count,
            span: _,
        } => {
            seen.insert(match count {
                U32Arg::Lit(..) => "ast.prepend.count.literal",
                U32Arg::Param(_) => "ast.prepend.count.parameter",
            });
            // Every argument form, then the operand it denotes: `origin`
            // and `path-first` arrive as a bare identifier.
            let form = match (asn, asn.operand()) {
                (PrependAsArg::SelfAs, _) => "ast.prepend.self",
                (PrependAsArg::Peer, _) => "ast.prepend.peer",
                (PrependAsArg::Value(_), Some(PrependAs::OriginAs)) => "ast.prepend.origin",
                (PrependAsArg::Value(_), Some(PrependAs::PathFirst)) => "ast.prepend.path-first",
                (PrependAsArg::Value(_), Some(PrependAs::LocalAs | PrependAs::PeerAs)) => {
                    unreachable!("self and peer have their own argument forms")
                }
                (PrependAsArg::Value(U32Arg::Lit(..)), None) => "ast.prepend.literal",
                (PrependAsArg::Value(U32Arg::Param(_)), None) => "ast.prepend.parameter",
            };
            seen.insert(form);
            "ast.action.prepend"
        }
        ActionStmt::Let { init, .. } => {
            ast_value(init, seen);
            "ast.action.let"
        }
        ActionStmt::Break(_) => "ast.action.break",
        ActionStmt::Continue(_) => "ast.action.continue",
    };
    seen.insert(name);
}

fn ast_expr(expr: &Expr, seen: &mut Seen) {
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
        Expr::Cmp { field, op, rhs, .. } => {
            ast_field(field, seen);
            ast_cmp(*op, seen);
            let operand = match rhs {
                Rhs::Int(..) => "ast.rhs.integer",
                Rhs::Ident(_) => "ast.rhs.identifier",
                Rhs::Ip(..) => "ast.rhs.ip",
                Rhs::Prefix(..) => "ast.rhs.prefix",
                Rhs::Str(_) => "ast.rhs.string",
                Rhs::Field(path) => {
                    ast_field(path, seen);
                    "ast.rhs.field"
                }
                // Parsed only so the typechecker can point at `has` and `in`;
                // no compiled program holds one.
                Rhs::Community(_) => unreachable!("typechecked: no community comparison"),
            };
            seen.insert(operand);
            "ast.expr.cmp"
        }
        Expr::In { field, .. } => {
            ast_field(field, seen);
            "ast.expr.in"
        }
        Expr::IdentIn { .. } => "ast.expr.ident-in",
        Expr::Has { field, lit } => {
            ast_literal(lit.node, seen);
            ast_field(field, seen);
            "ast.expr.has"
        }
        Expr::HasParam { field, .. } => {
            ast_field(field, seen);
            "ast.expr.has-parameter"
        }
        Expr::Exists { field, .. } => {
            ast_field(field, seen);
            "ast.expr.exists"
        }
        Expr::Matches { field, .. } => {
            ast_field(field, seen);
            "ast.expr.matches"
        }
        Expr::Contains { field, asn } => {
            seen.insert(match asn {
                U32Arg::Lit(..) => "ast.contains.literal",
                U32Arg::Param(_) => "ast.contains.parameter",
            });
            ast_field(field, seen);
            "ast.expr.contains"
        }
        Expr::ValueCmp { lhs, op, rhs, .. } => {
            ast_value(lhs, seen);
            ast_value(rhs, seen);
            ast_cmp(*op, seen);
            "ast.expr.value-cmp"
        }
        Expr::Apply {
            policy: _,
            args,
            span: _,
        } => {
            ast_call_args(args, seen);
            "ast.expr.apply"
        }
    };
    seen.insert(name);
}

fn ast_value(value: &ValueExprAst, seen: &mut Seen) {
    let name = match value {
        ValueExprAst::Lit(..) => "ast.value.literal",
        ValueExprAst::Community(..) => "ast.value.community",
        ValueExprAst::Ident(_) => "ast.value.identifier",
        ValueExprAst::Field(path) => {
            ast_field(path, seen);
            "ast.value.field"
        }
        ValueExprAst::Binary { op, lhs, rhs, .. } => {
            ast_value(lhs, seen);
            ast_value(rhs, seen);
            seen.insert(match op {
                ArithOp::Add => "ast.arith.add",
                ArithOp::Sub => "ast.arith.sub",
                ArithOp::Mul => "ast.arith.mul",
                ArithOp::Div => "ast.arith.div",
                ArithOp::Rem => "ast.arith.rem",
            });
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

/// A community literal's form, as written in a `has` probe or an action.
fn ast_literal(lit: CommunityLit, seen: &mut Seen) {
    seen.insert(match lit {
        CommunityLit::Standard(_) => "ast.literal.standard",
        CommunityLit::Large(_) => "ast.literal.large",
        CommunityLit::Ext {
            route_target,
            ipv4_admin,
            global: _,
            local: _,
        } => match (route_target, ipv4_admin) {
            (true, false) => "ast.literal.route-target",
            (false, false) => "ast.literal.route-origin",
            (true, true) => "ast.literal.route-target-ipv4",
            (false, true) => "ast.literal.route-origin-ipv4",
        },
        CommunityLit::ExtRaw(_) => "ast.literal.well-known-ext",
    });
}

/// The argument forms of a policy call, in `apply`, a call statement or an
/// `expect`.
fn ast_call_args(args: &[Spanned<CallArg>], seen: &mut Seen) {
    for arg in args {
        seen.insert(match arg.node {
            CallArg::Int(_) => "ast.call-arg.integer",
            CallArg::Name(_) => "ast.call-arg.name",
            CallArg::Community(_) => "ast.call-arg.community",
            CallArg::Ip(_) => "ast.call-arg.ip",
        });
    }
}

fn ast_cmp(op: CmpOp, seen: &mut Seen) {
    seen.insert(match op {
        CmpOp::Eq => "ast.cmp.eq",
        CmpOp::Ne => "ast.cmp.ne",
        CmpOp::Ge => "ast.cmp.ge",
        CmpOp::Le => "ast.cmp.le",
    });
}

/// The route or peer field a typechecked path reads.
fn ast_field(path: &FieldPath, seen: &mut Seen) {
    seen.insert(match resolve_field(path).expect("typechecked field") {
        Field::Prefix => "ast.field.route.prefix",
        Field::Communities => "ast.field.route.communities",
        Field::LargeCommunities => "ast.field.route.large-communities",
        Field::ExtCommunities => "ast.field.route.ext-communities",
        Field::AnyCommunity => "ast.field.route.any-community",
        Field::AsPath => "ast.field.route.as-path",
        Field::AsPathLen => "ast.field.route.as-path.len",
        Field::CommunitiesLen => "ast.field.route.communities.len",
        Field::LargeCommunitiesLen => "ast.field.route.large-communities.len",
        Field::ExtCommunitiesLen => "ast.field.route.ext-communities.len",
        Field::OriginAs => "ast.field.route.origin-as",
        Field::LocalPref => "ast.field.route.local-pref",
        Field::Med => "ast.field.route.med",
        Field::NextHop => "ast.field.route.next-hop",
        Field::Rpki => "ast.field.route.rpki",
        Field::Aspa => "ast.field.route.aspa",
        Field::RouteType => "ast.field.route.route-type",
        Field::EvpnRouteType => "ast.field.route.evpn-route-type",
        Field::Family => "ast.field.route.family",
        Field::PeerAddress => "ast.field.peer.address",
        Field::PeerAsn => "ast.field.peer.asn",
        Field::PeerGroup => "ast.field.peer.group",
    });
}

fn param_type_name(ty: ParamType) -> &'static str {
    match ty {
        ParamType::U32 => "ast.param.u32",
        ParamType::PrefixSet => "ast.param.prefix-set",
        ParamType::CommunitySet => "ast.param.community-set",
        ParamType::AsnSet => "ast.param.asn-set",
        ParamType::Community => "ast.param.community",
        ParamType::Ip => "ast.param.ip",
    }
}

fn family_name(family: RouteFamily) -> &'static str {
    match family {
        RouteFamily::Ipv4Unicast => "ast.family.ipv4-unicast",
        RouteFamily::Ipv6Unicast => "ast.family.ipv6-unicast",
        RouteFamily::Ipv4LabeledUnicast => "ast.family.ipv4-labeled-unicast",
        RouteFamily::Ipv6LabeledUnicast => "ast.family.ipv6-labeled-unicast",
        RouteFamily::Vpnv4 => "ast.family.vpnv4",
        RouteFamily::Vpnv6 => "ast.family.vpnv6",
        RouteFamily::Ipv4Flowspec => "ast.family.ipv4-flowspec",
        RouteFamily::Ipv6Flowspec => "ast.family.ipv6-flowspec",
        RouteFamily::Vpnv4Flowspec => "ast.family.vpnv4-flowspec",
        RouteFamily::Vpnv6Flowspec => "ast.family.vpnv6-flowspec",
        RouteFamily::Evpn => "ast.family.evpn",
        RouteFamily::RtConstrain => "ast.family.rtc",
        RouteFamily::BgpLs => "ast.family.bgp-ls",
        RouteFamily::BgpLsVpn => "ast.family.bgp-ls-vpn",
    }
}

/// A program's declaration and `test`-block constructs: the imports,
/// sets, set members, datasets and functions it declares and the test
/// grammar its tests use. Each is credited to every case the program runs.
fn declared_constructs(file: &RpolFile) -> Seen {
    let mut seen = Seen::new();
    // Destructured without `..`: a new declaration kind, or a new test or
    // expectation form, does not compile until it is named here.
    let SourceFile {
        // Dissolved by the resolver; `ast.decl.import` reads the modules.
        imports: _,
        prefix_sets,
        community_sets,
        asn_sets,
        datasets,
        fns,
        // Walked per evaluated case by `Corpus::count`.
        policies: _,
        tests,
    } = &file.file;
    if file.modules.len() > 1 {
        seen.insert("ast.decl.import");
    }
    for PrefixSetDef { name: _, entries } in prefix_sets {
        seen.insert("ast.decl.prefix-set");
        for PrefixEntryAst { prefix: _, ge, le } in entries {
            if ge.is_some() || le.is_some() {
                seen.insert("ast.decl.prefix-set.ge-le");
            }
        }
    }
    for CommunitySetDef { name: _, entries } in community_sets {
        seen.insert("ast.decl.community-set");
        for member in entries {
            community_member(&member.node, &mut seen);
        }
    }
    for AsnSetDef { name: _, entries } in asn_sets {
        seen.insert("ast.decl.asn-set");
        for member in entries {
            asn_member(member.node, &mut seen);
        }
    }
    for DatasetDecl {
        name: _,
        kind,
        kind_span: _,
    } in datasets
    {
        seen.insert(match kind {
            DatasetKind::Prefix => "ast.decl.dataset.prefix-set",
            DatasetKind::Asn => "ast.decl.dataset.asn-set",
            DatasetKind::Community => "ast.decl.dataset.community-set",
        });
    }
    for FnDef {
        name: _,
        params: _,
        lets,
        result: _,
    } in fns
    {
        seen.insert("ast.decl.fn");
        for FnLet { name: _, init: _ } in lets {
            seen.insert("ast.decl.fn.let");
        }
    }
    for test in tests {
        test_constructs(test, &mut seen);
    }
    seen
}

/// A `test` block's forms: dataset overrides, fixture fields and
/// expectations.
fn test_constructs(test: &TestDef, seen: &mut Seen) {
    let TestDef {
        name: _,
        datasets,
        route,
        peer,
        expects,
    } = test;
    seen.insert("ast.decl.test");
    for TestDatasetDef { name: _, entries } in datasets {
        seen.insert("ast.test.dataset-override");
        for entry in entries {
            match &entry.node {
                DatasetEntryAst::Community(member) => community_member(member, seen),
                DatasetEntryAst::Asn(member) => asn_member(*member, seen),
                // Prefix members are the set forms already named.
                DatasetEntryAst::Prefix(_) => {}
            }
        }
    }
    for field in route {
        seen.insert(match field {
            RouteField::Prefix(..) => "ast.test.route.prefix",
            RouteField::Communities(..) => "ast.test.route.communities",
            RouteField::LargeCommunities(..) => "ast.test.route.large-communities",
            RouteField::ExtCommunities(..) => "ast.test.route.ext-communities",
            RouteField::AsPath(_) => "ast.test.route.as-path",
            RouteField::NextHop(..) => "ast.test.route.next-hop",
            RouteField::LocalPref(..) => "ast.test.route.local-pref",
            RouteField::Med(..) => "ast.test.route.med",
            RouteField::Rpki(_) => "ast.test.route.rpki",
            RouteField::Aspa(_) => "ast.test.route.aspa",
            RouteField::RouteType(_) => "ast.test.route.route-type",
            RouteField::EvpnRouteType(..) => "ast.test.route.evpn-route-type",
            RouteField::Family(_) => "ast.test.route.family",
        });
    }
    for field in peer {
        seen.insert(match field {
            PeerField::Address(_) => "ast.test.peer.address",
            PeerField::Asn(_) => "ast.test.peer.asn",
            PeerField::LocalAs(_) => "ast.test.peer.local-as",
            PeerField::Group(_) => "ast.test.peer.group",
        });
    }
    for expect in expects {
        let ExpectDef {
            chain,
            calls,
            verdict,
            with,
            with_only,
        } = expect;
        for ExpectCall { policy: _, args } in calls {
            ast_call_args(args, seen);
        }
        if *chain {
            seen.insert("ast.test.expect.chain");
        }
        if *with_only {
            seen.insert("ast.test.expect.with-only");
        }
        seen.insert(match verdict {
            ExpectVerdict::Accept => "ast.test.expect.accept",
            ExpectVerdict::Reject => "ast.test.expect.reject",
            ExpectVerdict::Error(_) => "ast.test.expect.error",
        });
        for assertion in with {
            seen.insert(match assertion {
                WithAssertion::LocalPref(_) => "ast.test.with.local-pref",
                WithAssertion::Med(_) => "ast.test.with.med",
                WithAssertion::NextHop(_) => "ast.test.with.next-hop",
                WithAssertion::Community(_) => "ast.test.with.community",
                WithAssertion::Prepend(..) => "ast.test.with.prepend",
                WithAssertion::PrependPath(_) => "ast.test.with.prepend-path",
                WithAssertion::Removes(_) => "ast.test.with.removes",
                WithAssertion::RemovesLargeAdmin(_) => "ast.test.with.removes-large-admin",
                WithAssertion::RemovesAll(_) => "ast.test.with.removes-all",
                WithAssertion::NotRemoved(_) => "ast.test.with.not-removed",
                WithAssertion::WithoutCommunity(_) => "ast.test.with.without-community",
                WithAssertion::Without(attr) => match attr {
                    ScalarAttr::LocalPref => "ast.test.with.without.local-pref",
                    ScalarAttr::Med => "ast.test.with.without.med",
                    ScalarAttr::NextHop => "ast.test.with.without.next-hop",
                    ScalarAttr::Prepend => "ast.test.with.without.prepend",
                },
            });
        }
    }
}

/// An asn-set or ASN dataset member's form; an exact ASN is the set itself.
fn asn_member(member: AsnMember, seen: &mut Seen) {
    let name = match member {
        AsnMember::Exact(_) => return,
        AsnMember::Range { .. } => "ast.set.asn.range",
        AsnMember::PrivateAs => "ast.set.asn.private-as",
    };
    seen.insert(name);
}

/// A community-set or community-dataset member: its exact kind, or its
/// pattern kind and field forms.
fn community_member(member: &CommunityMember, seen: &mut Seen) {
    let fields: Vec<CommunityField> = match member {
        CommunityMember::Exact(exact) => {
            seen.insert(match exact {
                CommunityMatch::Standard { .. } => "ast.set.community.standard",
                CommunityMatch::LargeCommunity { .. } => "ast.set.community.large",
                CommunityMatch::RouteTarget { .. } => "ast.set.community.route-target",
                CommunityMatch::RouteOrigin { .. } => "ast.set.community.route-origin",
                CommunityMatch::ExactExt(_) => "ast.set.community.well-known-ext",
            });
            return;
        }
        CommunityMember::Pattern(pattern) => match **pattern {
            CommunityPattern::Standard { asn, value } => {
                seen.insert("ast.set.pattern.standard");
                vec![asn, value]
            }
            CommunityPattern::Large {
                global_admin,
                local_data1,
                local_data2,
            } => {
                seen.insert("ast.set.pattern.large");
                vec![global_admin, local_data1, local_data2]
            }
            CommunityPattern::RouteTarget { global, local } => {
                seen.insert("ast.set.pattern.route-target");
                vec![global, local]
            }
            CommunityPattern::RouteOrigin { global, local } => {
                seen.insert("ast.set.pattern.route-origin");
                vec![global, local]
            }
        },
    };
    for field in fields {
        seen.insert(match field {
            CommunityField::Range { lo, hi } if lo == hi => continue,
            CommunityField::Range { .. } => "ast.set.pattern-field.range",
            CommunityField::PrivateAs => "ast.set.pattern-field.private-as",
        });
    }
}

/// Credit the guard nodes of `expr` the evaluation visited: an `And` or
/// `Or` child after the short-circuit point stays uncredited.
fn visited_guards(
    expr: &MatchExpr,
    visited: &std::collections::HashSet<usize>,
    seen: &mut std::collections::BTreeSet<&'static str>,
) {
    if !visited.contains(&std::ptr::from_ref(expr).addr()) {
        return;
    }
    match expr {
        MatchExpr::And(children) | MatchExpr::Or(children) => {
            seen.insert(if matches!(expr, MatchExpr::And(_)) {
                "ir.guard.and"
            } else {
                "ir.guard.or"
            });
            for child in children {
                visited_guards(child, visited, seen);
            }
        }
        MatchExpr::Not(inner) => {
            seen.insert("ir.guard.not");
            visited_guards(inner, visited, seen);
        }
        leaf => ir_guard(leaf, seen),
    }
}

/// The constructs an executed term's action uses; loop bodies are walked
/// with their visited guards.
/// Whether `mods` stages a computed (or, with `false`, a literal) prepend.
fn prepend_kind(prepends: &[crate::engine::AsPathPrepend], computed: bool) -> bool {
    prepends
        .iter()
        .any(|p| matches!(p.asn, crate::engine::PrependAsn::Computed(_)) == computed)
}

fn ir_action(
    term: &Term,
    seen: &mut std::collections::BTreeSet<&'static str>,
    visited: &std::collections::HashSet<usize>,
) {
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
                visited_guards(&body.guard, visited, seen);
                ir_action(body, seen, visited);
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
    if let Some(mods) = mods {
        ir_mods(mods, seen);
    }
}

/// The modification kinds a row stages, and the values it computes.
fn ir_mods(mods: &RouteModifications, seen: &mut Seen) {
    // Destructured without `..`: a new modification does not compile until
    // it is named here.
    let RouteModifications {
        set_local_pref,
        set_med,
        set_next_hop,
        communities_add,
        communities_remove,
        extended_communities_add,
        extended_communities_remove,
        large_communities_add,
        large_communities_remove,
        as_path_prepend,
        set_local_pref_computed,
        set_med_computed,
    } = mods;
    let prepends = |computed: bool| prepend_kind(as_path_prepend, computed);
    for (present, name) in [
        (set_local_pref.is_some(), "ir.mod.set-local-pref"),
        (
            set_local_pref_computed.is_some(),
            "ir.mod.set-local-pref-computed",
        ),
        (set_med.is_some(), "ir.mod.set-med"),
        (set_med_computed.is_some(), "ir.mod.set-med-computed"),
        (set_next_hop.is_some(), "ir.mod.set-next-hop"),
        (prepends(false), "ir.mod.prepend"),
        (prepends(true), "ir.mod.prepend-computed"),
        (!communities_add.is_empty(), "ir.mod.community-add"),
        (!communities_remove.is_empty(), "ir.mod.community-remove"),
        (
            !large_communities_add.is_empty(),
            "ir.mod.large-community-add",
        ),
        (
            !large_communities_remove.is_empty(),
            "ir.mod.large-community-remove",
        ),
        (
            !extended_communities_add.is_empty(),
            "ir.mod.ext-community-add",
        ),
        (
            !extended_communities_remove.is_empty(),
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
        .chain(set_med_computed.iter())
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
        MatchExpr::CommunityKindInSet(..) => "ir.guard.community-kind-in-set",
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
        MatchExpr::FamilyIs(family) => {
            seen.insert(family_name(*family));
            "ir.guard.family-is"
        }
        MatchExpr::FamilyNe(family) => {
            seen.insert(family_name(*family));
            "ir.guard.family-ne"
        }
        MatchExpr::RpkiIs(_) => "ir.guard.rpki-is",
        MatchExpr::AspaIs(_) => "ir.guard.aspa-is",
        MatchExpr::ValueCmp(node) => {
            ir_value(&node.lhs, seen);
            ir_value(&node.rhs, seen);
            "ir.guard.value-cmp"
        }
        MatchExpr::Exists(_) => "ir.guard.exists",
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
        ValueExpr::Community(_) => "ir.value.community",
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

/// Coverage follows the evaluator's short-circuit: the second child of an
/// `Or` whose first child matched is not credited, and is once a route
/// reaches it.
#[test]
fn short_circuited_guard_children_are_not_credited() {
    let file = RpolFile::parse(
        "policy p { term t { if route.rpki == valid || route.med >= 5 { accept } } }",
    )
    .expect("parses");
    let mut store = SetStore::new();
    let mut lowerer = lower::Lowerer::from_tables(&file.file, file.tables());
    let chain = lowerer.instantiate_member("p", &[], &mut store, &DatasetBindings::new());
    let routes = RpolFile::parse(
        "policy q { term t { accept } }
         test valid { route { prefix 192.0.2.0/24; rpki valid; med 1 } expect q == accept }
         test invalid { route { prefix 192.0.2.0/24; rpki invalid; med 1 } expect q == accept }",
    )
    .expect("parses");
    let count = |test: usize| {
        let mut corpus = Corpus::default();
        let fixture = Fixture::build(&routes.file.tests[test]);
        corpus.count(
            &chain,
            &[&file.file.policies[0]],
            &fixture.context(),
            &Seen::new(),
        );
        corpus.counts
    };
    let short_circuited = count(0);
    assert_eq!(short_circuited.get("ir.guard.rpki-is"), Some(&1));
    assert_eq!(short_circuited.get("ir.guard.med"), None);
    assert_eq!(count(1).get("ir.guard.med"), Some(&1));
}
