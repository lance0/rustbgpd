//! The in-language `test` block runner: fixtures become
//! [`RouteContext`]s, expectations run through the real IR evaluator.
//!
//! `with` assertions check the evaluation result's **modifications**
//! (`set local-pref` produced `Some(200)`, an added community is in
//! the add list, …), not a post-application attribute image — the
//! frontend has no route to apply them to. Fixture defaults mirror
//! evaluation semantics: omitted `local-pref`/`med` are absent
//! attributes (so comparisons see the RFC 4271 implicit 100/0),
//! omitted `rpki` is `not-found`, omitted `aspa` is `unknown`.

use std::net::IpAddr;
use std::sync::Arc;

use rustbgpd_wire::{
    AsPath, AsPathSegment, AspaValidation, ExtendedCommunity, LargeCommunity, Prefix,
    RpkiValidation,
};

use crate::datasets::{DatasetBindings, DatasetData, DatasetHandle, DatasetKind};
use crate::engine::{
    NamedPolicy, NextHopAction, PolicyAction, PolicyChain, RouteContext, RouteFamily, RouteType,
};
use crate::ir::CompiledChain;
use crate::sets::{AsnSet, CommunitySet, PrefixSet, PrefixSetEntry, SetStore};

use super::ast::{
    CommunityLit, DatasetEntryAst, ExpectDef, ExpectVerdict, NextHopArg, PeerField, RouteField,
    ScalarAttr, TestDef, WithAssertion,
};
use super::lower::{Lowerer, ext_community_value};

/// The outcome of running a source file's `test` blocks.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TestReport {
    /// Number of `test` blocks executed.
    pub total: usize,
    /// Failed tests with human-readable reasons.
    pub failures: Vec<TestFailure>,
}

impl TestReport {
    /// Number of passing tests.
    #[must_use]
    pub fn passed(&self) -> usize {
        self.total - self.failures.len()
    }

    /// True when every test passed.
    #[must_use]
    pub fn all_passed(&self) -> bool {
        self.failures.is_empty()
    }
}

/// One failed in-language test.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TestFailure {
    /// The `test` block's name.
    pub name: String,
    /// What went wrong (one line per failed expectation).
    pub message: String,
}

/// An owned route/peer fixture backing a borrowed [`RouteContext`].
#[derive(Debug, Default)]
struct Fixture {
    prefix: Option<Prefix>,
    next_hop: Option<IpAddr>,
    communities: Vec<u32>,
    large_communities: Vec<LargeCommunity>,
    extended_communities: Vec<ExtendedCommunity>,
    as_path_str: String,
    /// Typed form of the fixture path, backing `for asn in
    /// route.as-path` (LAN-303).
    as_path: Option<AsPath>,
    as_path_len: usize,
    origin_asn: Option<u32>,
    local_pref: Option<u32>,
    med: Option<u32>,
    rpki: RpkiValidation,
    aspa: AspaValidation,
    route_type: Option<RouteType>,
    family: Option<RouteFamily>,
    evpn_route_type: Option<u8>,
    peer_address: Option<IpAddr>,
    peer_asn: Option<u32>,
    /// Backs `prepend as self` (LAN-296); stamped onto the chain under
    /// test, mirroring how the config resolver stamps `[global] asn`.
    local_asn: Option<u32>,
    peer_group: Option<String>,
}

impl Fixture {
    fn build(test: &TestDef) -> Self {
        let mut fixture = Fixture::default();
        for field in &test.route {
            match field {
                RouteField::Prefix(prefix, _) => fixture.prefix = Some(*prefix),
                RouteField::NextHop(addr, _) => fixture.next_hop = Some(*addr),
                RouteField::LocalPref(value, _) => fixture.local_pref = Some(*value),
                RouteField::Med(value, _) => fixture.med = Some(*value),
                RouteField::Communities(lits, _) => {
                    for lit in lits {
                        if let CommunityLit::Standard(value) = lit.node {
                            fixture.communities.push(value);
                        }
                    }
                }
                RouteField::LargeCommunities(lits, _) => {
                    for lit in lits {
                        if let CommunityLit::Large(lc) = lit.node {
                            fixture.large_communities.push(lc);
                        }
                    }
                }
                RouteField::ExtCommunities(lits, _) => {
                    for lit in lits {
                        match lit.node {
                            CommunityLit::Ext {
                                route_target,
                                global,
                                local,
                                ipv4_admin,
                            } => fixture.extended_communities.push(ext_community_value(
                                route_target,
                                global,
                                local,
                                ipv4_admin,
                            )),
                            CommunityLit::ExtRaw(raw) => fixture
                                .extended_communities
                                .push(ExtendedCommunity::new(raw)),
                            CommunityLit::Standard(_) | CommunityLit::Large(_) => {}
                        }
                    }
                }
                RouteField::AsPath(path) => {
                    // The string, length, and origin derive from the
                    // typed path exactly as live evaluation derives them
                    // from a received AS_PATH: canonical rendering,
                    // RFC 4271 length (an AS_SET counts 1), and the last
                    // ASN of the rightmost AS_SEQUENCE.
                    let typed = parse_fixture_as_path(&path.node)
                        .expect("typechecked: fixture as-path parses");
                    if let Some(typed) = &typed {
                        fixture.as_path_str = typed.to_aspath_string();
                        fixture.as_path_len = typed.len();
                        fixture.origin_asn = typed.origin_asn();
                    }
                    fixture.as_path = typed;
                }
                RouteField::Rpki(state) => {
                    fixture.rpki = match state.node.as_str() {
                        "valid" => RpkiValidation::Valid,
                        "invalid" => RpkiValidation::Invalid,
                        _ => RpkiValidation::NotFound,
                    };
                }
                RouteField::Aspa(state) => {
                    fixture.aspa = match state.node.as_str() {
                        "valid" => AspaValidation::Valid,
                        "invalid" => AspaValidation::Invalid,
                        _ => AspaValidation::Unknown,
                    };
                }
                RouteField::RouteType(kind) => {
                    fixture.route_type = Some(match kind.node.as_str() {
                        "local" => RouteType::Local,
                        "internal" => RouteType::Internal,
                        _ => RouteType::External,
                    });
                }
                RouteField::EvpnRouteType(value, _) => {
                    fixture.evpn_route_type =
                        Some(u8::try_from(*value).expect("typechecked range"));
                }
                // Typed family knowledge comes only from an explicit
                // fixture statement — never inferred from the fixture
                // prefix's shape (the ADR-0077 honest-context rule).
                RouteField::Family(name) => {
                    fixture.family = Some(super::lower::family_value(&name.node));
                }
            }
        }
        for field in &test.peer {
            match field {
                PeerField::Address(addr) => fixture.peer_address = Some(*addr),
                PeerField::Asn(asn) => fixture.peer_asn = Some(*asn),
                PeerField::LocalAs(asn) => fixture.local_asn = Some(*asn),
                PeerField::Group(group) => fixture.peer_group = Some(group.node.clone()),
            }
        }
        fixture
    }

    fn context(&self) -> RouteContext<'_> {
        RouteContext {
            prefix: self.prefix,
            next_hop: self.next_hop,
            extended_communities: &self.extended_communities,
            communities: &self.communities,
            large_communities: &self.large_communities,
            as_path_str: &self.as_path_str,
            as_path: self.as_path.as_ref(),
            as_path_len: self.as_path_len,
            origin_asn: self.origin_asn,
            validation_state: self.rpki,
            aspa_state: self.aspa,
            peer_address: self.peer_address,
            peer_asn: self.peer_asn,
            peer_group: self.peer_group.as_deref(),
            route_type: self.route_type,
            family: self.family,
            evpn_route_type: self.evpn_route_type,
            local_pref: self.local_pref,
            med: self.med,
        }
    }
}

/// Why a fixture `as-path` string is not an AS path: the byte range
/// within the string, and what is wrong there.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct AsPathFixtureError {
    pub(super) offset: usize,
    pub(super) len: usize,
    pub(super) message: String,
}

/// Parse a fixture `as-path` string strictly: decimal ASNs separated by
/// whitespace, with `{...}` grouping an `AS_SET` (the form
/// `AsPath::to_aspath_string` renders). Plain ASNs accumulate into
/// `AS_SEQUENCE` segments in written order. Anything else — a comma, a
/// word, a nested, empty or unbalanced brace — is an error, so a typo
/// cannot silently become an absent or shorter path. A blank string is
/// a route without an `AS_PATH` (`Ok(None)`).
pub(super) fn parse_fixture_as_path(text: &str) -> Result<Option<AsPath>, AsPathFixtureError> {
    let error = |offset: usize, len: usize, message: String| AsPathFixtureError {
        offset,
        len,
        message,
    };
    let mut segments: Vec<AsPathSegment> = Vec::new();
    // Byte offset of the open `{`, while inside an AS_SET.
    let mut open_set: Option<usize> = None;
    let mut chars = text.char_indices().peekable();
    while let Some((offset, ch)) = chars.next() {
        match ch {
            c if c.is_whitespace() => {}
            '{' => {
                if open_set.is_some() {
                    return Err(error(offset, 1, "AS_SETs do not nest".into()));
                }
                open_set = Some(offset);
                segments.push(AsPathSegment::AsSet(Vec::new()));
            }
            '}' => {
                let Some(open) = open_set.take() else {
                    return Err(error(offset, 1, "`}` without a matching `{`".into()));
                };
                if matches!(segments.last(), Some(AsPathSegment::AsSet(asns)) if asns.is_empty()) {
                    return Err(error(open, offset + 1 - open, "empty AS_SET".into()));
                }
            }
            '0'..='9' => {
                let mut end = offset + 1;
                while let Some(&(next, digit)) = chars.peek() {
                    if !digit.is_ascii_digit() {
                        break;
                    }
                    end = next + 1;
                    chars.next();
                }
                let word = &text[offset..end];
                let asn = word.parse::<u32>().map_err(|_| {
                    error(
                        offset,
                        end - offset,
                        format!("ASN `{word}` exceeds 4294967295"),
                    )
                })?;
                if let Some(&(next, ch)) = chars.peek()
                    && !ch.is_whitespace()
                    && ch != '{'
                    && ch != '}'
                {
                    return Err(error(
                        next,
                        ch.len_utf8(),
                        format!("unexpected `{ch}` after ASN `{word}`; separate ASNs with spaces"),
                    ));
                }
                match (open_set.is_some(), segments.last_mut()) {
                    (true, Some(AsPathSegment::AsSet(asns)))
                    | (false, Some(AsPathSegment::AsSequence(asns))) => asns.push(asn),
                    _ => segments.push(AsPathSegment::AsSequence(vec![asn])),
                }
            }
            other => {
                return Err(error(
                    offset,
                    other.len_utf8(),
                    format!("unexpected `{other}`; expected an ASN, `{{`, or `}}`"),
                ));
            }
        }
    }
    if let Some(open) = open_set {
        return Err(error(open, 1, "unclosed `{`".into()));
    }
    Ok((!segments.is_empty()).then_some(AsPath { segments }))
}

/// Execute every `test` block against the lowered policies.
pub(super) fn run_tests(
    tests: &[TestDef],
    lowerer: &mut Lowerer<'_>,
    store: &mut SetStore,
) -> TestReport {
    run_tests_recording(tests, lowerer, store, None)
}

/// [`run_tests`] optionally feeding a coverage accumulator (LAN-323):
/// with `Some`, every `expect` walk is re-run through the
/// coverage-recording evaluator (identical decision semantics) and its
/// evaluated/matched grids folded per source term. Test outcomes are
/// unaffected.
pub(super) fn run_tests_recording(
    tests: &[TestDef],
    lowerer: &mut Lowerer<'_>,
    store: &mut SetStore,
    mut coverage: Option<&mut super::coverage::CoverageAccum>,
) -> TestReport {
    let mut report = TestReport {
        total: tests.len(),
        failures: Vec::new(),
    };
    for test in tests {
        let fixture = Fixture::build(test);
        let ctx = fixture.context();
        let mut problems: Vec<String> = Vec::new();
        // LAN-305: the test's `dataset NAME { ... }` overrides are its
        // dataset content — fresh generation-1 handles per test, never
        // operator files. Kind agreement was typechecked.
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
            let (mut chain, members) = match assemble_chain(expect, lowerer, store, &bindings) {
                Ok(assembled) => assembled,
                Err(problem) => {
                    problems.push(problem);
                    continue;
                }
            };
            // The fixture's `peer { local-as N }` plays the config
            // resolver's role for `prepend as self` (LAN-296).
            chain.local_asn = fixture.local_asn;
            // LAN-323: attribute this walk's term coverage — a second,
            // decision-identical evaluation, so the assertion path
            // below stays exactly the shipped runner. Each chain member
            // contributes one policy, in order; its rows attribute to
            // the member's own source policy (the spliced copy carries
            // the call name instead).
            if let Some(accum) = coverage.as_deref_mut() {
                let mut evaluated = chain.zero_term_hits();
                let mut matched = chain.zero_term_hits();
                let _ = chain.evaluate_recording_coverage(&ctx, &mut evaluated, &mut matched);
                for (index, member) in members.iter().enumerate() {
                    accum.record_walk(&member.policies[0], &evaluated[index], &matched[index]);
                }
            }
            let (result, evaluation) = chain.evaluate_with_attribution(&ctx);
            // ADR-0103 Decision 4: an erroring evaluation is not a
            // clean verdict. `accept`/`reject` expectations FAIL on an
            // error with the error rendered; `error [KIND]` pins the
            // fail-closed rail itself.
            match (&expect.verdict, &evaluation.eval_error) {
                (ExpectVerdict::Error(expected_kind), Some(error)) => {
                    if let Some(expected) = expected_kind
                        && error.kind.label() != expected.node
                    {
                        problems.push(format!(
                            "{call}: expected error {}, got error {} ({})",
                            expected.node,
                            error.kind.label(),
                            error,
                        ));
                    }
                    continue;
                }
                (ExpectVerdict::Error(_), None) => {
                    problems.push(format!(
                        "{call}: expected an evaluation error, got {}",
                        verdict(result.action == PolicyAction::Permit),
                    ));
                    continue;
                }
                (ExpectVerdict::Accept | ExpectVerdict::Reject, Some(error)) => {
                    problems.push(format!(
                        "{call}: expected {}, got evaluation error: {error} \
                         (use `== error {}` to pin the fail-closed rail)",
                        verdict(matches!(expect.verdict, ExpectVerdict::Accept)),
                        error.kind.label(),
                    ));
                    continue;
                }
                (ExpectVerdict::Accept | ExpectVerdict::Reject, None) => {}
            }
            let accepted = result.action == PolicyAction::Permit;
            let expect_accept = matches!(expect.verdict, ExpectVerdict::Accept);
            if accepted != expect_accept {
                problems.push(format!(
                    "{call}: expected {}, got {}",
                    verdict(expect_accept),
                    verdict(accepted),
                ));
                continue;
            }
            for assertion in &expect.with {
                if let Some(problem) = check_assertion(assertion, &result.modifications) {
                    problems.push(format!("{call}: {problem}"));
                }
            }
        }
        if !problems.is_empty() {
            report.failures.push(TestFailure {
                name: test.name.node.clone(),
                message: problems.join("; "),
            });
        }
    }
    report
}

/// Assemble an expectation's policies into one chain. Every expectation
/// is a chain — `expect p` has one member — built by the daemon's own
/// chain compiler, so tests run the same splice and cross-policy merge
/// the daemon runs. Also returns each member's own compiled policy, for
/// coverage attribution (the spliced copy carries the call name).
fn assemble_chain(
    expect: &ExpectDef,
    lowerer: &mut Lowerer<'_>,
    store: &mut SetStore,
    bindings: &DatasetBindings,
) -> Result<(CompiledChain, Vec<Arc<CompiledChain>>), String> {
    let mut named = Vec::with_capacity(expect.calls.len());
    let mut members = Vec::with_capacity(expect.calls.len());
    for member in &expect.calls {
        let args: Vec<u32> = member.args.iter().map(|arg| arg.node).collect();
        let compiled =
            Arc::new(lowerer.instantiate_chain(&member.policy.node, &args, store, bindings));
        let missing = lowerer.take_missing_datasets();
        if !missing.is_empty() {
            return Err(format!(
                "{}: probes dataset{} {} with no `dataset {{ ... }}` override in this test",
                render_call(&member.policy.node, &args),
                if missing.len() == 1 { "" } else { "s" },
                missing.join(", "),
            ));
        }
        named.push(NamedPolicy::from_rpol(
            render_call(&member.policy.node, &args),
            Arc::clone(&compiled),
        ));
        members.push(compiled);
    }
    let chain = crate::compile::compile_chain(&PolicyChain::from_named(named), store);
    Ok((chain, members))
}

/// Build a test override's [`DatasetData`] from its parsed members.
/// Kind agreement between members and the declared kind is a
/// typecheck guarantee; mismatched members are unreachable here and
/// are skipped defensively.
fn override_data(
    kind: DatasetKind,
    entries: &[super::diag::Spanned<DatasetEntryAst>],
) -> DatasetData {
    match kind {
        DatasetKind::Prefix => DatasetData::Prefix(PrefixSet::new(entries.iter().filter_map(
            |entry| match &entry.node {
                DatasetEntryAst::Prefix(p) => Some(PrefixSetEntry {
                    prefix: p.prefix,
                    ge: p.ge,
                    le: p.le,
                }),
                _ => None,
            },
        ))),
        DatasetKind::Asn => {
            DatasetData::Asn(AsnSet::new(entries.iter().filter_map(
                |entry| match &entry.node {
                    DatasetEntryAst::Asn(asn) => Some(*asn),
                    _ => None,
                },
            )))
        }
        DatasetKind::Community => {
            DatasetData::Community(CommunitySet::new(entries.iter().filter_map(|entry| {
                match &entry.node {
                    DatasetEntryAst::Community(lit) => Some(lit.to_match()),
                    _ => None,
                }
            })))
        }
    }
}

fn verdict(accept: bool) -> &'static str {
    if accept { "accept" } else { "reject" }
}

fn render_expect(expect: &ExpectDef) -> String {
    let calls = expect
        .calls
        .iter()
        .map(|call| {
            let args: Vec<u32> = call.args.iter().map(|arg| arg.node).collect();
            render_call(&call.policy.node, &args)
        })
        .collect::<Vec<_>>();
    if expect.chain {
        format!("chain [{}]", calls.join(", "))
    } else {
        calls.join(", ")
    }
}

fn render_call(name: &str, args: &[u32]) -> String {
    if args.is_empty() {
        name.to_string()
    } else {
        format!(
            "{name}({})",
            args.iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        )
    }
}

fn check_assertion(
    assertion: &WithAssertion,
    mods: &crate::engine::RouteModifications,
) -> Option<String> {
    match assertion {
        WithAssertion::LocalPref(expected) => (mods.set_local_pref != Some(*expected)).then(|| {
            format!(
                "expected local-pref {expected}, got {}",
                render_opt(mods.set_local_pref)
            )
        }),
        WithAssertion::Med(expected) => (mods.set_med != Some(*expected))
            .then(|| format!("expected med {expected}, got {}", render_opt(mods.set_med))),
        WithAssertion::NextHop(arg) => {
            let expected = match arg {
                NextHopArg::Self_(_) => NextHopAction::Self_,
                NextHopArg::Addr(addr, _) => NextHopAction::Specific(*addr),
            };
            (mods.set_next_hop.as_ref() != Some(&expected)).then(|| {
                format!(
                    "expected next-hop {}, got {}",
                    render_next_hop(Some(&expected)),
                    render_next_hop(mods.set_next_hop.as_ref()),
                )
            })
        }
        WithAssertion::Community(lit) => (!community_listed(&lit.node, mods, true))
            .then(|| format!("expected community {} to be added", lit_text(&lit.node))),
        WithAssertion::Removes(lit) => (!community_listed(&lit.node, mods, false))
            .then(|| format!("expected community {} to be removed", lit_text(&lit.node))),
        WithAssertion::WithoutCommunity(lit) => community_listed(&lit.node, mods, true)
            .then(|| format!("expected community {} not to be added", lit_text(&lit.node))),
        WithAssertion::Without(attr) => {
            let set = match attr {
                ScalarAttr::LocalPref => mods.set_local_pref.map(|v| v.to_string()),
                ScalarAttr::Med => mods.set_med.map(|v| v.to_string()),
                ScalarAttr::NextHop => mods
                    .set_next_hop
                    .as_ref()
                    .map(|action| render_next_hop(Some(action))),
                ScalarAttr::Prepend => mods.as_path_prepend.map(|(a, c)| format!("as {a} {c}")),
            };
            set.map(|value| format!("expected no {} change, got {value}", attr.keyword()))
        }
        WithAssertion::Prepend(asn, count) => {
            let expected = Some((*asn, u8::try_from(*count).unwrap_or(u8::MAX)));
            (mods.as_path_prepend != expected).then(|| {
                format!(
                    "expected prepend as {asn} {count}, got {}",
                    mods.as_path_prepend
                        .map_or_else(|| "none".to_string(), |(a, c)| format!("as {a} {c}"))
                )
            })
        }
    }
}

/// Whether `lit` is in the modification add list (`added`) or remove
/// list (`!added`) of its kind.
fn community_listed(
    lit: &CommunityLit,
    mods: &crate::engine::RouteModifications,
    added: bool,
) -> bool {
    match *lit {
        CommunityLit::Standard(value) => if added {
            &mods.communities_add
        } else {
            &mods.communities_remove
        }
        .contains(&value),
        CommunityLit::Large(lc) => if added {
            &mods.large_communities_add
        } else {
            &mods.large_communities_remove
        }
        .contains(&lc),
        CommunityLit::Ext { .. } | CommunityLit::ExtRaw(_) => {
            let value = match *lit {
                CommunityLit::Ext {
                    route_target,
                    global,
                    local,
                    ipv4_admin,
                } => ext_community_value(route_target, global, local, ipv4_admin),
                CommunityLit::ExtRaw(raw) => ExtendedCommunity::new(raw),
                _ => unreachable!("matched above"),
            };
            if added {
                &mods.extended_communities_add
            } else {
                &mods.extended_communities_remove
            }
            .contains(&value)
        }
    }
}

fn lit_text(lit: &CommunityLit) -> String {
    match *lit {
        CommunityLit::Standard(value) => format!("{}:{}", value >> 16, value & 0xffff),
        CommunityLit::Large(lc) => {
            format!("{}:{}:{}", lc.global_admin, lc.local_data1, lc.local_data2)
        }
        CommunityLit::Ext {
            route_target,
            global,
            local,
            ipv4_admin,
        } => {
            let kind = if route_target { "RT" } else { "RO" };
            if ipv4_admin {
                format!("{kind}:{}:{local}", std::net::Ipv4Addr::from(global))
            } else {
                format!("{kind}:{global}:{local}")
            }
        }
        CommunityLit::ExtRaw(raw) => format!("0x{raw:016x}"),
    }
}

fn render_opt(value: Option<u32>) -> String {
    value.map_or_else(|| "none".to_string(), |v| v.to_string())
}

fn render_next_hop(action: Option<&NextHopAction>) -> String {
    match action {
        None => "none".to_string(),
        Some(NextHopAction::Self_) => "self".to_string(),
        Some(NextHopAction::Specific(addr)) => addr.to_string(),
    }
}
