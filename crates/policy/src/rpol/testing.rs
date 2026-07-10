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

use rustbgpd_wire::{AspaValidation, ExtendedCommunity, LargeCommunity, Prefix, RpkiValidation};

use crate::engine::{NextHopAction, PolicyAction, RouteContext, RouteType};
use crate::sets::SetStore;

use super::ast::{CommunityLit, NextHopArg, PeerField, RouteField, TestDef, WithAssertion};
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
    as_path_len: usize,
    origin_asn: Option<u32>,
    local_pref: Option<u32>,
    med: Option<u32>,
    rpki: RpkiValidation,
    aspa: AspaValidation,
    route_type: Option<RouteType>,
    evpn_route_type: Option<u8>,
    peer_address: Option<IpAddr>,
    peer_asn: Option<u32>,
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
                    // Fixture AS-path length is the whitespace-word
                    // count of the string form (AS_SET braces count as
                    // written) — documented in the language reference.
                    path.node.clone_into(&mut fixture.as_path_str);
                    fixture.as_path_len = path.node.split_whitespace().count();
                    fixture.origin_asn = fixture_origin_asn(&path.node);
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
            }
        }
        for field in &test.peer {
            match field {
                PeerField::Address(addr) => fixture.peer_address = Some(*addr),
                PeerField::Asn(asn) => fixture.peer_asn = Some(*asn),
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
            as_path_len: self.as_path_len,
            origin_asn: self.origin_asn,
            validation_state: self.rpki,
            aspa_state: self.aspa,
            peer_address: self.peer_address,
            peer_asn: self.peer_asn,
            peer_group: self.peer_group.as_deref(),
            route_type: self.route_type,
            evpn_route_type: self.evpn_route_type,
            local_pref: self.local_pref,
            med: self.med,
        }
    }
}

/// Origin AS of a fixture `as-path` string: the last plain ASN outside
/// `{...}` `AS_SET` braces — the string-form equivalent of
/// `AsPath::origin_asn` (last ASN of the rightmost non-empty
/// `AS_SEQUENCE`; sets never contribute an origin). `None` for empty
/// and `AS_SET`-only paths, mirroring evaluation semantics.
fn fixture_origin_asn(path: &str) -> Option<u32> {
    let mut origin = None;
    let mut in_set = false;
    for token in path.split_whitespace() {
        if token.starts_with('{') {
            in_set = true;
        }
        if !in_set && let Ok(asn) = token.parse::<u32>() {
            origin = Some(asn);
        }
        if token.ends_with('}') {
            in_set = false;
        }
    }
    origin
}

/// Execute every `test` block against the lowered policies.
pub(super) fn run_tests(
    tests: &[TestDef],
    lowerer: &mut Lowerer<'_>,
    store: &mut SetStore,
) -> TestReport {
    let mut report = TestReport {
        total: tests.len(),
        failures: Vec::new(),
    };
    for test in tests {
        let fixture = Fixture::build(test);
        let ctx = fixture.context();
        let mut problems: Vec<String> = Vec::new();
        for expect in &test.expects {
            let args: Vec<u32> = expect.args.iter().map(|arg| arg.node).collect();
            let chain = lowerer.instantiate_chain(&expect.policy.node, &args, store);
            let result = chain.evaluate(&ctx);
            let call = render_call(&expect.policy.node, &args);
            let accepted = result.action == PolicyAction::Permit;
            if accepted != expect.accept {
                problems.push(format!(
                    "{call}: expected {}, got {}",
                    verdict(expect.accept),
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

fn verdict(accept: bool) -> &'static str {
    if accept { "accept" } else { "reject" }
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
        WithAssertion::Community(lit) => {
            let present = match lit.node {
                CommunityLit::Standard(value) => mods.communities_add.contains(&value),
                CommunityLit::Large(lc) => mods.large_communities_add.contains(&lc),
                CommunityLit::Ext {
                    route_target,
                    global,
                    local,
                    ipv4_admin,
                } => mods.extended_communities_add.contains(&ext_community_value(
                    route_target,
                    global,
                    local,
                    ipv4_admin,
                )),
                CommunityLit::ExtRaw(raw) => mods
                    .extended_communities_add
                    .contains(&ExtendedCommunity::new(raw)),
            };
            (!present).then(|| "expected community was not added".to_string())
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
