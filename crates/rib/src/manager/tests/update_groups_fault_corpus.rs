//! Parameterized fixed-scenario differential corpus for update groups.
//!
//! The small corpus runs fixed schedules in normal PR CI. Seeds vary fixture
//! identities, not operation ordering. The ignored extension sweeps those same
//! schedules under hard parameter/operation caps on a weekly hosted runner.

use std::collections::{HashMap, HashSet};
use std::env;
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use rustbgpd_wire::{
    AddressPrefixOrf, Afi, Ipv4Prefix, OrfAction, OrfMatch, Prefix, RtcNlri, Safi,
};

use super::update_groups_oracle::{
    NormAnnounce, NormMsg, NormVpnAnnounce, Oracle, OraclePeerFeatures, Streams, deny_prefix_chain,
    deny_prefixes_chain, fold, fold_vpn, ibgp_route, peer_context_permit_chain, pfx, rtc_default,
    vpn_nlri, vpn_route, vpn_rtc_sendable,
};
use crate::route::RtcRibRouteKey;

const SOURCE: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
const LEFT: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
const RIGHT: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 3);
const PR_SEEDS: [u64; 3] = [0x51_7A, 0xC0_FF_EE, 0x05EE_D357];
const DEFAULT_SEED_START: u64 = 0x3570_0000;
const DEFAULT_SEED_COUNT: usize = 24;
const DEFAULT_MAX_OPS: usize = 64;
const SEED_COUNT_CAP: usize = 64;
const MIN_MAX_OPS: usize = 18;
const MAX_OPS_CAP: usize = 64;
const SEED_START_ENV: &str = "RUSTBGPD_UPDATE_GROUP_SEED_START";
const SEED_COUNT_ENV: &str = "RUSTBGPD_UPDATE_GROUP_SEED_COUNT";
const MAX_OPS_ENV: &str = "RUSTBGPD_UPDATE_GROUP_MAX_OPS";
const TEST_RT: u64 = 0x0002_FDE8_0000_002A;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ExtendedConfig {
    seed_start: u64,
    seed_count: usize,
    max_ops: usize,
}

fn parse_u64(name: &str, value: &str) -> Result<u64, String> {
    let parsed = value.strip_prefix("0x").unwrap_or(value);
    if value.starts_with("0x") {
        u64::from_str_radix(parsed, 16)
    } else {
        value.parse()
    }
    .map_err(|error| format!("invalid {name}={value:?}: {error}"))
}

fn parse_extended_config(get: impl Fn(&str) -> Option<String>) -> Result<ExtendedConfig, String> {
    let seed_start = get(SEED_START_ENV)
        .map(|value| parse_u64(SEED_START_ENV, &value))
        .transpose()?
        .unwrap_or(DEFAULT_SEED_START);
    let seed_count = get(SEED_COUNT_ENV)
        .map(|value| parse_u64(SEED_COUNT_ENV, &value))
        .transpose()?
        .map_or(Ok(DEFAULT_SEED_COUNT), |value| {
            usize::try_from(value)
                .map_err(|error| format!("invalid {SEED_COUNT_ENV}={value}: {error}"))
        })?;
    let max_ops = get(MAX_OPS_ENV)
        .map(|value| parse_u64(MAX_OPS_ENV, &value))
        .transpose()?
        .map_or(Ok(DEFAULT_MAX_OPS), |value| {
            usize::try_from(value)
                .map_err(|error| format!("invalid {MAX_OPS_ENV}={value}: {error}"))
        })?;
    if !(1..=SEED_COUNT_CAP).contains(&seed_count) {
        return Err(format!(
            "{SEED_COUNT_ENV} must be in 1..={SEED_COUNT_CAP}, got {seed_count}"
        ));
    }
    if !(MIN_MAX_OPS..=MAX_OPS_CAP).contains(&max_ops) {
        return Err(format!(
            "{MAX_OPS_ENV} must be in {MIN_MAX_OPS}..={MAX_OPS_CAP}, got {max_ops}"
        ));
    }
    let last_offset = u64::try_from(seed_count - 1).expect("seed count is capped at 64");
    seed_start
        .checked_add(last_offset)
        .ok_or_else(|| format!("{SEED_START_ENV} + {SEED_COUNT_ENV} overflows u64"))?;
    Ok(ExtendedConfig {
        seed_start,
        seed_count,
        max_ops,
    })
}

#[derive(Clone, Copy, Debug)]
enum ComparisonMode {
    ExactStream,
    SemanticFold,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FamilySet {
    Unicast,
    VpnRtc,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum PolicySpec {
    Permit,
    DenyOne(Ipv4Prefix),
    DenyMany(Vec<Ipv4Prefix>),
    PeerContext,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MembershipExpectation {
    SharedGroup,
    PeerContextFallback,
    AddPathFallback,
    OrfFallback,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Op {
    PeerUp {
        peer: Ipv4Addr,
        generation: u64,
        capacity: usize,
        families: FamilySet,
    },
    PeerDown {
        peer: Ipv4Addr,
        generation: u64,
    },
    PeerUpAddPath {
        peer: Ipv4Addr,
        generation: u64,
        capacity: usize,
        send_max: u32,
    },
    PeerUpOrf {
        peer: Ipv4Addr,
        generation: u64,
        capacity: usize,
    },
    AddPathLimit {
        peer: Ipv4Addr,
        generation: u64,
        limit: u32,
    },
    OrfPermitExact {
        peer: Ipv4Addr,
        generation: u64,
        prefix: Ipv4Prefix,
        accepted: bool,
    },
    OrfRemoveAll {
        peer: Ipv4Addr,
        generation: u64,
    },
    Announce {
        peer: Ipv4Addr,
        generation: u64,
        prefix: Ipv4Prefix,
        local_pref: u32,
    },
    Withdraw {
        peer: Ipv4Addr,
        generation: u64,
        prefix: Ipv4Prefix,
    },
    VpnAnnounce {
        peer: Ipv4Addr,
        generation: u64,
        id: u8,
    },
    ReplacePolicy {
        peer: Ipv4Addr,
        policy: PolicySpec,
    },
    AssertMembership {
        peer: Ipv4Addr,
        expectation: MembershipExpectation,
    },
    AssertAnnouncedPaths {
        peer: Ipv4Addr,
        prefix: Ipv4Prefix,
        expected: usize,
    },
    AssertLocRibAbsent(Ipv4Prefix),
    RtcDefaultAnnounce {
        peer: Ipv4Addr,
        generation: u64,
    },
    RtcDefaultWithdraw {
        peer: Ipv4Addr,
        generation: u64,
    },
    DrainOne(Ipv4Addr),
    DrainAvailable,
    AdvanceRetry,
    Quiesce,
}

#[derive(Clone, Debug)]
struct Schedule {
    name: &'static str,
    seed: u64,
    comparison: ComparisonMode,
    require_vpn_churn: bool,
    ops: Vec<Op>,
}

impl Schedule {
    fn replay(&self) -> String {
        let ops = self
            .ops
            .iter()
            .enumerate()
            .map(|(index, op)| format!("{index}:{op:?}"))
            .collect::<Vec<_>>()
            .join(", ");
        format!(
            "scenario={} seed={:#x} mode={:?} ops=[{}]",
            self.name, self.seed, self.comparison, ops
        )
    }
}

fn unicast() -> Vec<(Afi, Safi)> {
    vec![(Afi::Ipv4, Safi::Unicast)]
}

fn sentinel() -> Ipv4Prefix {
    Ipv4Prefix::new(Ipv4Addr::new(10, 255, 255, 0), 24)
}

fn seed_octet(seed: u64, lane: usize) -> u8 {
    // SplitMix64's stable finalizer makes every fixture lane depend on the
    // whole seed; consecutive extended-corpus seeds therefore do not leave
    // the high-byte lanes unchanged.
    let lane = u64::try_from(lane).expect("fixture lanes fit in u64");
    let mut mixed = seed ^ lane.wrapping_add(1).wrapping_mul(0x9E37_79B9_7F4A_7C15);
    mixed = (mixed ^ (mixed >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    mixed = (mixed ^ (mixed >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    (mixed ^ (mixed >> 31)).to_le_bytes()[0] | 1
}

fn distinct_seed_octet(seed: u64, lane: usize, other: u8) -> u8 {
    let candidate = seed_octet(seed, lane);
    if candidate == other {
        candidate.wrapping_add(2)
    } else {
        candidate
    }
}

fn distinct_seed_octet_from(seed: u64, lane: usize, others: &[u8]) -> u8 {
    let mut candidate = seed_octet(seed, lane);
    while others.contains(&candidate) {
        candidate = candidate.wrapping_add(2);
    }
    candidate
}

fn policy(spec: &PolicySpec) -> Option<rustbgpd_policy::PolicyChain> {
    match spec {
        PolicySpec::Permit => None,
        PolicySpec::DenyOne(prefix) => Some(deny_prefix_chain(*prefix)),
        PolicySpec::DenyMany(prefixes) => Some(deny_prefixes_chain(prefixes)),
        PolicySpec::PeerContext => Some(peer_context_permit_chain()),
    }
}

#[derive(Clone, Debug, PartialEq)]
enum SemanticEffect {
    SessionStart {
        peer: IpAddr,
        generation: u64,
    },
    Announce {
        peer: IpAddr,
        route: NormAnnounce,
    },
    Withdraw {
        peer: IpAddr,
        key: (Prefix, u32),
    },
    UnknownWithdrawBeforeTerminalRoute {
        peer: IpAddr,
        key: (Prefix, u32),
    },
    VpnAnnounce {
        peer: IpAddr,
        route: NormVpnAnnounce,
    },
    VpnWithdraw {
        peer: IpAddr,
        key: (String, u32),
    },
    UnknownVpnWithdrawBeforeTerminalRoute {
        peer: IpAddr,
        key: (String, u32),
    },
}

fn semantic_effects(streams: &Streams) -> Vec<SemanticEffect> {
    let terminal = fold(streams);
    let terminal_vpn = fold_vpn(streams);
    let mut effects = Vec::new();
    for (peer, messages) in streams {
        let mut state: HashMap<(Prefix, u32), NormAnnounce> = HashMap::new();
        let mut vpn_state: HashMap<String, NormVpnAnnounce> = HashMap::new();
        for message in messages {
            if let Some(generation) = message.session_start {
                state.clear();
                vpn_state.clear();
                effects.push(SemanticEffect::SessionStart {
                    peer: *peer,
                    generation,
                });
            }
            for key in &message.withdraw {
                if state.remove(key).is_some() {
                    effects.push(SemanticEffect::Withdraw {
                        peer: *peer,
                        key: *key,
                    });
                } else if terminal
                    .get(peer)
                    .is_some_and(|routes| routes.contains_key(key))
                {
                    effects.push(SemanticEffect::UnknownWithdrawBeforeTerminalRoute {
                        peer: *peer,
                        key: *key,
                    });
                }
            }
            for route in &message.announce {
                let key = (route.0, route.1);
                if state.get(&key) != Some(route) {
                    state.insert(key, route.clone());
                    effects.push(SemanticEffect::Announce {
                        peer: *peer,
                        route: route.clone(),
                    });
                }
            }
            for key in &message.vpn_withdraw {
                if vpn_state.remove(&key.0).is_some() {
                    effects.push(SemanticEffect::VpnWithdraw {
                        peer: *peer,
                        key: key.clone(),
                    });
                } else if terminal_vpn
                    .get(peer)
                    .is_some_and(|routes| routes.contains_key(&key.0))
                {
                    effects.push(SemanticEffect::UnknownVpnWithdrawBeforeTerminalRoute {
                        peer: *peer,
                        key: key.clone(),
                    });
                }
            }
            for route in &message.vpn_announce {
                if vpn_state.get(&route.0) != Some(route) {
                    vpn_state.insert(route.0.clone(), route.clone());
                    effects.push(SemanticEffect::VpnAnnounce {
                        peer: *peer,
                        route: route.clone(),
                    });
                }
            }
        }
    }
    effects
}

async fn apply_vpn_announce(oracle: &mut Oracle, peer: Ipv4Addr, generation: u64, id: u8) {
    oracle
        .vpn_routes_generation(
            peer,
            generation,
            vec![vpn_route(
                vpn_nlri(id, 16_000 + u32::from(id)),
                peer,
                100,
                vec![TEST_RT],
            )],
            vec![],
        )
        .await;
}

async fn assert_membership(
    oracle: &mut Oracle,
    peer: Ipv4Addr,
    expectation: MembershipExpectation,
    force_ungrouped: bool,
) {
    let label = oracle.group_label(peer).await;
    match expectation {
        MembershipExpectation::SharedGroup if force_ungrouped => assert!(
            !label.starts_with("group:"),
            "forced oracle unexpectedly grouped {peer}: {label}"
        ),
        MembershipExpectation::SharedGroup => assert!(
            label.starts_with("group:"),
            "grouped path did not group {peer}: {label}"
        ),
        MembershipExpectation::PeerContextFallback => assert!(
            !label.starts_with("group:") && (force_ungrouped || label == "policy_peer_context"),
            "peer-context transition did not reach per-peer path for {peer}: {label}"
        ),
        MembershipExpectation::AddPathFallback => assert!(
            !label.starts_with("group:") && (force_ungrouped || label == "add_path_send"),
            "Add-Path transition did not reach per-peer path for {peer}: {label}"
        ),
        MembershipExpectation::OrfFallback => assert!(
            !label.starts_with("group:") && (force_ungrouped || label == "orf_installed"),
            "ORF transition did not reach per-peer path for {peer}: {label}"
        ),
    }
}

fn announced_paths(messages: &[NormMsg], prefix: Ipv4Prefix) -> HashSet<(u32, IpAddr)> {
    messages
        .iter()
        .flat_map(|message| &message.announce)
        .filter_map(|route| (route.0 == Prefix::V4(prefix)).then_some((route.1, route.3)))
        .collect()
}

#[allow(
    clippy::too_many_lines,
    reason = "the exhaustive fault-script interpreter keeps every operation's behavior in one auditable match"
)]
async fn apply(oracle: &mut Oracle, op: &Op, force_ungrouped: bool) {
    match op {
        Op::PeerUp {
            peer,
            generation,
            capacity,
            families,
        } => {
            let sendable = match families {
                FamilySet::Unicast => unicast(),
                FamilySet::VpnRtc => vpn_rtc_sendable(),
            };
            oracle
                .peer_up_families_generation(
                    *peer,
                    *generation,
                    false,
                    true,
                    None,
                    *capacity,
                    sendable,
                )
                .await;
        }
        Op::PeerDown { peer, generation } => {
            oracle.peer_down_generation(*peer, *generation).await;
        }
        Op::PeerUpAddPath {
            peer,
            generation,
            capacity,
            send_max,
        } => {
            oracle
                .peer_up_families_generation_with_features(
                    *peer,
                    *generation,
                    false,
                    true,
                    None,
                    *capacity,
                    unicast(),
                    OraclePeerFeatures {
                        add_path_send_max: *send_max,
                        ..OraclePeerFeatures::default()
                    },
                )
                .await;
        }
        Op::PeerUpOrf {
            peer,
            generation,
            capacity,
        } => {
            oracle
                .peer_up_families_generation_with_features(
                    *peer,
                    *generation,
                    false,
                    true,
                    None,
                    *capacity,
                    unicast(),
                    OraclePeerFeatures {
                        negotiated_orf_recv: unicast(),
                        ..OraclePeerFeatures::default()
                    },
                )
                .await;
        }
        Op::AddPathLimit {
            peer,
            generation,
            limit,
        } => {
            oracle
                .peer_add_path_limits(*peer, *generation, *limit)
                .await;
        }
        Op::OrfPermitExact {
            peer,
            generation,
            prefix,
            accepted,
        } => {
            let result = oracle
                .peer_orf_update(
                    *peer,
                    *generation,
                    vec![AddressPrefixOrf {
                        action: OrfAction::Add,
                        match_: OrfMatch::Permit,
                        sequence: 10,
                        min_len: 0,
                        max_len: 0,
                        prefix: Some(Prefix::V4(*prefix)),
                    }],
                )
                .await;
            assert_eq!(
                result.is_ok(),
                *accepted,
                "ORF generation acceptance mismatch: {result:?}"
            );
        }
        Op::OrfRemoveAll { peer, generation } => {
            oracle
                .peer_orf_update(
                    *peer,
                    *generation,
                    vec![AddressPrefixOrf {
                        action: OrfAction::RemoveAll,
                        match_: OrfMatch::Permit,
                        sequence: 0,
                        min_len: 0,
                        max_len: 0,
                        prefix: None,
                    }],
                )
                .await
                .expect("current-session ORF Remove-All must be accepted");
        }
        Op::Announce {
            peer,
            generation,
            prefix,
            local_pref,
        } => {
            oracle
                .routes_generation(
                    *peer,
                    *generation,
                    vec![ibgp_route(*prefix, *peer, *local_pref, vec![])],
                    vec![],
                )
                .await;
        }
        Op::Withdraw {
            peer,
            generation,
            prefix,
        } => {
            oracle
                .routes_generation(*peer, *generation, vec![], vec![*prefix])
                .await;
        }
        Op::VpnAnnounce {
            peer,
            generation,
            id,
        } => {
            apply_vpn_announce(oracle, *peer, *generation, *id).await;
        }
        Op::ReplacePolicy { peer, policy: spec } => {
            oracle.replace_policy(*peer, policy(spec)).await;
        }
        Op::AssertMembership { peer, expectation } => {
            assert_membership(oracle, *peer, *expectation, force_ungrouped).await;
        }
        Op::AssertAnnouncedPaths {
            peer,
            prefix,
            expected,
        } => {
            let messages = oracle.drain_peer_available(*peer).await;
            let paths = announced_paths(&messages, *prefix);
            assert_eq!(
                paths.len(),
                *expected,
                "unexpected newly announced Add-Path identities for {prefix}: {paths:?}"
            );
        }
        Op::AssertLocRibAbsent(prefix) => {
            let routes = oracle.best_routes().await;
            assert!(
                routes
                    .iter()
                    .all(|route| route.prefix != Prefix::V4(*prefix)),
                "stale-session replacement route reached the Loc-RIB: {prefix}"
            );
        }
        Op::RtcDefaultAnnounce { peer, generation } => {
            oracle
                .rtc_routes_full_generation(*peer, *generation, vec![rtc_default(*peer)], vec![])
                .await;
            oracle.quiesce().await;
        }
        Op::RtcDefaultWithdraw { peer, generation } => {
            oracle
                .rtc_routes_full_generation(
                    *peer,
                    *generation,
                    vec![],
                    vec![RtcRibRouteKey {
                        nlri: RtcNlri::DEFAULT,
                        path_id: 0,
                    }],
                )
                .await;
            oracle.quiesce().await;
        }
        Op::DrainOne(peer) => {
            let _ = oracle.drain_one(*peer).await;
        }
        Op::DrainAvailable => oracle.drain_available(),
        Op::AdvanceRetry => {
            tokio::time::advance(Duration::from_secs(2)).await;
            oracle.quiesce().await;
        }
        Op::Quiesce => oracle.quiesce().await,
    }
}

async fn run_path(schedule: &Schedule, force_ungrouped: bool, max_ops: usize) -> Streams {
    assert!(
        schedule.ops.len() <= max_ops,
        "operation cap {max_ops} exceeded: {}",
        schedule.replay()
    );
    let mut oracle = Oracle::spawn(force_ungrouped, Some(Ipv4Addr::new(192, 0, 2, 1)));
    for (index, op) in schedule.ops.iter().enumerate() {
        eprintln!(
            "update-group replay: scenario={} seed={:#x} op={index} {op:?}",
            schedule.name, schedule.seed
        );
        apply(&mut oracle, op, force_ungrouped).await;
    }
    if !force_ungrouped {
        let left = oracle.group_label(LEFT).await;
        let right = oracle.group_label(RIGHT).await;
        assert!(
            left.starts_with("group:") && left == right,
            "scenario did not exercise a shared update group ({left:?}/{right:?}): {}",
            schedule.replay()
        );
    }

    // Every schedule ends with a current-generation sentinel from SOURCE.
    // Its delivery proves that the manager remains live after the injected
    // faults rather than merely comparing two empty or prematurely-ended runs.
    oracle
        .routes_generation(
            SOURCE,
            2,
            vec![ibgp_route(sentinel(), SOURCE, 250, vec![])],
            vec![],
        )
        .await;
    let health = oracle.terminal_health().await;
    assert_eq!(
        health,
        (0, 0, 0, 0, 0, 0),
        "terminal dirty/force/regroup/residue health is not clean: {}",
        schedule.replay()
    );
    let streams = oracle.finish().await; // Awaiting the handle proves manager completion.
    validate_terminal_stream(&streams).unwrap_or_else(|error| {
        panic!(
            "incomplete outbound stream ({error}): {}",
            schedule.replay()
        )
    });
    if schedule.require_vpn_churn {
        let left = streams
            .get(&IpAddr::V4(LEFT))
            .expect("LEFT is registered in every schedule");
        assert!(
            left.iter().any(|message| !message.vpn_announce.is_empty())
                && left.iter().any(|message| !message.vpn_withdraw.is_empty()),
            "RTC membership did not produce both VPN announce and withdraw traffic: {}",
            schedule.replay()
        );
        assert!(
            fold_vpn(&streams)
                .get(&IpAddr::V4(LEFT))
                .is_none_or(std::collections::HashMap::is_empty),
            "final RTC withdrawal must leave LEFT with no advertised VPN route: {}",
            schedule.replay()
        );
    }
    streams
}

fn validate_terminal_stream(streams: &Streams) -> Result<(), String> {
    let terminal = fold(streams);
    for peer in [LEFT, RIGHT] {
        let key = (Prefix::V4(sentinel()), 0);
        if !terminal
            .get(&IpAddr::V4(peer))
            .is_some_and(|routes| routes.contains_key(&key))
        {
            return Err(format!(
                "terminal sentinel absent from final session state for {peer}"
            ));
        }
    }
    Ok(())
}

async fn run_schedule(schedule: Schedule, max_ops: usize) {
    let grouped = run_path(&schedule, false, max_ops).await;
    let ungrouped = run_path(&schedule, true, max_ops).await;
    match schedule.comparison {
        ComparisonMode::ExactStream => assert_eq!(
            grouped,
            ungrouped,
            "exact stream mismatch: {}",
            schedule.replay()
        ),
        ComparisonMode::SemanticFold => assert_eq!(
            semantic_effects(&grouped),
            semantic_effects(&ungrouped),
            "normalized semantic-effect mismatch: {}",
            schedule.replay()
        ),
    }
    assert_eq!(
        fold(&grouped),
        fold(&ungrouped),
        "folded advertised-state mismatch: {}",
        schedule.replay()
    );
    assert_eq!(
        fold_vpn(&grouped),
        fold_vpn(&ungrouped),
        "folded VPN advertised-state mismatch: {}",
        schedule.replay()
    );
}

fn saturation_schedule(seed: u64) -> Schedule {
    let first = pfx(seed_octet(seed, 0), 0);
    let second = pfx(distinct_seed_octet(seed, 1, seed_octet(seed, 0)), 1);
    Schedule {
        name: "saturation-drain-virtual-retry",
        seed,
        comparison: ComparisonMode::SemanticFold,
        require_vpn_churn: false,
        ops: vec![
            Op::PeerUp {
                peer: SOURCE,
                generation: 2,
                capacity: 64,
                families: FamilySet::Unicast,
            },
            Op::PeerUp {
                peer: LEFT,
                generation: 2,
                capacity: 64,
                families: FamilySet::Unicast,
            },
            Op::PeerUp {
                peer: RIGHT,
                generation: 2,
                capacity: 1,
                families: FamilySet::Unicast,
            },
            Op::AssertMembership {
                peer: RIGHT,
                expectation: MembershipExpectation::SharedGroup,
            },
            Op::DrainOne(RIGHT),
            Op::Announce {
                peer: SOURCE,
                generation: 2,
                prefix: first,
                local_pref: 100,
            },
            Op::Announce {
                peer: SOURCE,
                generation: 2,
                prefix: second,
                local_pref: 110,
            },
            Op::Withdraw {
                peer: SOURCE,
                generation: 2,
                prefix: first,
            },
            Op::DrainOne(RIGHT),
            Op::AdvanceRetry,
            Op::DrainAvailable,
        ],
    }
}

fn dirty_policy_schedule(seed: u64) -> Schedule {
    let first = pfx(seed_octet(seed, 2), 2);
    let second = pfx(distinct_seed_octet(seed, 3, seed_octet(seed, 2)), 3);
    Schedule {
        name: "dirty-policy-regroup-transitions",
        seed,
        comparison: ComparisonMode::SemanticFold,
        require_vpn_churn: false,
        ops: vec![
            Op::PeerUp {
                peer: SOURCE,
                generation: 2,
                capacity: 64,
                families: FamilySet::Unicast,
            },
            Op::PeerUp {
                peer: LEFT,
                generation: 2,
                capacity: 64,
                families: FamilySet::Unicast,
            },
            Op::PeerUp {
                peer: RIGHT,
                generation: 2,
                capacity: 1,
                families: FamilySet::Unicast,
            },
            Op::DrainOne(RIGHT),
            Op::Announce {
                peer: SOURCE,
                generation: 2,
                prefix: first,
                local_pref: 100,
            },
            Op::Announce {
                peer: SOURCE,
                generation: 2,
                prefix: second,
                local_pref: 100,
            },
            Op::AssertMembership {
                peer: RIGHT,
                expectation: MembershipExpectation::SharedGroup,
            },
            Op::ReplacePolicy {
                peer: RIGHT,
                policy: PolicySpec::DenyOne(first),
            },
            Op::AssertMembership {
                peer: RIGHT,
                expectation: MembershipExpectation::SharedGroup,
            },
            Op::ReplacePolicy {
                peer: RIGHT,
                policy: PolicySpec::DenyMany(vec![first, second]),
            },
            Op::AssertMembership {
                peer: RIGHT,
                expectation: MembershipExpectation::SharedGroup,
            },
            Op::ReplacePolicy {
                peer: RIGHT,
                policy: PolicySpec::PeerContext,
            },
            Op::AssertMembership {
                peer: RIGHT,
                expectation: MembershipExpectation::PeerContextFallback,
            },
            Op::ReplacePolicy {
                peer: RIGHT,
                policy: PolicySpec::Permit,
            },
            Op::AssertMembership {
                peer: RIGHT,
                expectation: MembershipExpectation::SharedGroup,
            },
            Op::DrainOne(RIGHT),
            Op::AdvanceRetry,
            Op::DrainAvailable,
        ],
    }
}

fn stale_generation_rtc_schedule(seed: u64) -> Schedule {
    let live_octet = seed_octet(seed, 4);
    let stale_octet = distinct_seed_octet(seed, 5, live_octet);
    let live = pfx(live_octet, 4);
    let stale = pfx(stale_octet, 5);
    assert_ne!(
        live, stale,
        "stale-generation probe must not alias the current route"
    );
    Schedule {
        name: "stale-generation-rtc-membership-churn",
        seed,
        comparison: ComparisonMode::ExactStream,
        require_vpn_churn: true,
        ops: vec![
            Op::PeerUp {
                peer: SOURCE,
                generation: 1,
                capacity: 64,
                families: FamilySet::Unicast,
            },
            Op::PeerUp {
                peer: LEFT,
                generation: 1,
                capacity: 64,
                families: FamilySet::VpnRtc,
            },
            Op::PeerUp {
                peer: RIGHT,
                generation: 1,
                capacity: 64,
                families: FamilySet::VpnRtc,
            },
            Op::PeerUp {
                peer: SOURCE,
                generation: 2,
                capacity: 64,
                families: FamilySet::VpnRtc,
            },
            Op::Announce {
                peer: SOURCE,
                generation: 1,
                prefix: stale,
                local_pref: 200,
            },
            Op::PeerDown {
                peer: SOURCE,
                generation: 1,
            },
            Op::Announce {
                peer: SOURCE,
                generation: 2,
                prefix: live,
                local_pref: 100,
            },
            Op::RtcDefaultAnnounce {
                peer: LEFT,
                generation: 1,
            },
            Op::PeerUp {
                peer: LEFT,
                generation: 2,
                capacity: 64,
                families: FamilySet::VpnRtc,
            },
            Op::RtcDefaultWithdraw {
                peer: LEFT,
                generation: 2,
            },
            Op::RtcDefaultAnnounce {
                peer: LEFT,
                generation: 2,
            },
            Op::VpnAnnounce {
                peer: SOURCE,
                generation: 2,
                id: seed_octet(seed, 6),
            },
            Op::RtcDefaultWithdraw {
                peer: LEFT,
                generation: 2,
            },
            Op::Quiesce,
        ],
    }
}

fn add_path_membership_schedule(seed: u64) -> Schedule {
    let prefix = pfx(seed_octet(seed, 0), 7);
    Schedule {
        name: "add-path-membership-and-limit-churn",
        seed,
        comparison: ComparisonMode::SemanticFold,
        require_vpn_churn: false,
        ops: vec![
            Op::PeerUp {
                peer: SOURCE,
                generation: 2,
                capacity: 64,
                families: FamilySet::Unicast,
            },
            Op::PeerUp {
                peer: LEFT,
                generation: 2,
                capacity: 64,
                families: FamilySet::Unicast,
            },
            Op::PeerUp {
                peer: RIGHT,
                generation: 2,
                capacity: 64,
                families: FamilySet::Unicast,
            },
            Op::Announce {
                peer: SOURCE,
                generation: 2,
                prefix,
                local_pref: 200,
            },
            Op::Announce {
                peer: LEFT,
                generation: 2,
                prefix,
                local_pref: 100,
            },
            Op::PeerUpAddPath {
                peer: RIGHT,
                generation: 3,
                capacity: 64,
                send_max: 2,
            },
            Op::AssertMembership {
                peer: RIGHT,
                expectation: MembershipExpectation::AddPathFallback,
            },
            // Removing initial Add-Path fanout or rank compaction makes these
            // operation-boundary counts fail instead of merely comparing two
            // equally incomplete terminal folds.
            Op::AssertAnnouncedPaths {
                peer: RIGHT,
                prefix,
                expected: 2,
            },
            // The predecessor generation cannot narrow the active session's
            // cap or trigger its replay.
            Op::AddPathLimit {
                peer: RIGHT,
                generation: 2,
                limit: 1,
            },
            Op::AssertAnnouncedPaths {
                peer: RIGHT,
                prefix,
                expected: 0,
            },
            Op::AddPathLimit {
                peer: RIGHT,
                generation: 3,
                limit: 1,
            },
            Op::AssertAnnouncedPaths {
                peer: RIGHT,
                prefix,
                expected: 1,
            },
            Op::Withdraw {
                peer: SOURCE,
                generation: 2,
                prefix,
            },
            Op::PeerUp {
                peer: RIGHT,
                generation: 4,
                capacity: 64,
                families: FamilySet::Unicast,
            },
            Op::PeerDown {
                peer: RIGHT,
                generation: 3,
            },
            Op::AssertMembership {
                peer: RIGHT,
                expectation: MembershipExpectation::SharedGroup,
            },
            Op::Quiesce,
        ],
    }
}

fn orf_membership_schedule(seed: u64) -> Schedule {
    let first_octet = seed_octet(seed, 1);
    let second_octet = distinct_seed_octet(seed, 2, first_octet);
    let third_octet = distinct_seed_octet_from(seed, 3, &[first_octet, second_octet]);
    let first = pfx(first_octet, 8);
    let second = pfx(second_octet, 9);
    let third = pfx(third_octet, 10);
    Schedule {
        name: "orf-membership-generation-and-filter-churn",
        seed,
        comparison: ComparisonMode::SemanticFold,
        require_vpn_churn: false,
        ops: vec![
            Op::PeerUp {
                peer: SOURCE,
                generation: 2,
                capacity: 64,
                families: FamilySet::Unicast,
            },
            Op::PeerUp {
                peer: LEFT,
                generation: 2,
                capacity: 64,
                families: FamilySet::Unicast,
            },
            Op::PeerUp {
                peer: RIGHT,
                generation: 2,
                capacity: 64,
                families: FamilySet::Unicast,
            },
            Op::Announce {
                peer: SOURCE,
                generation: 2,
                prefix: first,
                local_pref: 100,
            },
            Op::Announce {
                peer: SOURCE,
                generation: 2,
                prefix: second,
                local_pref: 100,
            },
            Op::PeerUpOrf {
                peer: RIGHT,
                generation: 3,
                capacity: 64,
            },
            Op::AssertMembership {
                peer: RIGHT,
                expectation: MembershipExpectation::OrfFallback,
            },
            Op::OrfPermitExact {
                peer: RIGHT,
                generation: 2,
                prefix: first,
                accepted: false,
            },
            Op::OrfPermitExact {
                peer: RIGHT,
                generation: 3,
                prefix: first,
                accepted: true,
            },
            Op::Announce {
                peer: SOURCE,
                generation: 2,
                prefix: third,
                local_pref: 100,
            },
            Op::OrfRemoveAll {
                peer: RIGHT,
                generation: 3,
            },
            Op::Withdraw {
                peer: SOURCE,
                generation: 2,
                prefix: first,
            },
            Op::PeerUp {
                peer: RIGHT,
                generation: 4,
                capacity: 64,
                families: FamilySet::Unicast,
            },
            Op::PeerDown {
                peer: RIGHT,
                generation: 3,
            },
            Op::AssertMembership {
                peer: RIGHT,
                expectation: MembershipExpectation::SharedGroup,
            },
            Op::Quiesce,
        ],
    }
}

fn replacement_during_resync_schedule(seed: u64) -> Schedule {
    let first_octet = seed_octet(seed, 4);
    let second_octet = distinct_seed_octet(seed, 5, first_octet);
    let stale_octet = distinct_seed_octet_from(seed, 6, &[first_octet, second_octet]);
    let first = pfx(first_octet, 11);
    let second = pfx(second_octet, 12);
    let stale = pfx(stale_octet, 13);
    Schedule {
        name: "session-replacement-during-dirty-resync",
        seed,
        comparison: ComparisonMode::SemanticFold,
        require_vpn_churn: false,
        ops: vec![
            Op::PeerUp {
                peer: SOURCE,
                generation: 2,
                capacity: 64,
                families: FamilySet::Unicast,
            },
            Op::PeerUp {
                peer: LEFT,
                generation: 2,
                capacity: 64,
                families: FamilySet::Unicast,
            },
            Op::PeerUp {
                peer: RIGHT,
                generation: 2,
                capacity: 1,
                families: FamilySet::Unicast,
            },
            Op::DrainOne(RIGHT),
            Op::Announce {
                peer: SOURCE,
                generation: 2,
                prefix: first,
                local_pref: 100,
            },
            Op::Announce {
                peer: SOURCE,
                generation: 2,
                prefix: second,
                local_pref: 100,
            },
            // Replace the dirty transport before its virtual-time retry.
            Op::PeerUp {
                peer: RIGHT,
                generation: 3,
                capacity: 64,
                families: FamilySet::Unicast,
            },
            Op::PeerDown {
                peer: RIGHT,
                generation: 2,
            },
            Op::Announce {
                peer: RIGHT,
                generation: 2,
                prefix: stale,
                local_pref: 250,
            },
            // Removing the received-route generation fence exposes this
            // superseded session's higher-preference route in the Loc-RIB.
            Op::AssertLocRibAbsent(stale),
            Op::AdvanceRetry,
            Op::AssertMembership {
                peer: RIGHT,
                expectation: MembershipExpectation::SharedGroup,
            },
            Op::DrainAvailable,
        ],
    }
}

fn schedules(seed: u64) -> [Schedule; 6] {
    [
        saturation_schedule(seed),
        dirty_policy_schedule(seed),
        stale_generation_rtc_schedule(seed),
        add_path_membership_schedule(seed),
        orf_membership_schedule(seed),
        replacement_during_resync_schedule(seed),
    ]
}

fn norm_announce(prefix: Ipv4Prefix, local_pref: u32) -> NormAnnounce {
    let route = ibgp_route(prefix, SOURCE, local_pref, vec![]);
    (
        route.prefix,
        route.path_id,
        route.next_hop,
        route.peer,
        (*route.attributes).clone(),
        None,
    )
}

fn norm_message(announce: Vec<NormAnnounce>, withdraw: Vec<(Prefix, u32)>) -> NormMsg {
    NormMsg {
        session_start: None,
        announce,
        withdraw,
        end_of_rib: vec![],
        vpn_announce: vec![],
        vpn_withdraw: vec![],
    }
}

fn session_start_message(generation: u64) -> NormMsg {
    NormMsg {
        session_start: Some(generation),
        announce: vec![],
        withdraw: vec![],
        end_of_rib: vec![],
        vpn_announce: vec![],
        vpn_withdraw: vec![],
    }
}

fn one_peer_stream(messages: Vec<NormMsg>) -> Streams {
    [(IpAddr::V4(LEFT), messages)].into_iter().collect()
}

#[test]
fn semantic_effects_reject_transient_announces_and_attribute_changes() {
    let first = pfx(41, 0);
    let extra = pfx(43, 0);
    let baseline = one_peer_stream(vec![norm_message(vec![norm_announce(first, 100)], vec![])]);

    let extra_transient = one_peer_stream(vec![
        norm_message(vec![norm_announce(first, 100)], vec![]),
        norm_message(vec![norm_announce(extra, 100)], vec![]),
        norm_message(vec![], vec![(Prefix::V4(extra), 0)]),
    ]);
    assert_ne!(
        semantic_effects(&baseline),
        semantic_effects(&extra_transient)
    );

    let wrong_attributes = one_peer_stream(vec![
        norm_message(vec![norm_announce(first, 100)], vec![]),
        norm_message(vec![norm_announce(first, 200)], vec![]),
        norm_message(vec![norm_announce(first, 100)], vec![]),
    ]);
    assert_ne!(
        semantic_effects(&baseline),
        semantic_effects(&wrong_attributes)
    );
}

#[test]
fn semantic_effects_allow_only_terminally_absent_unknown_withdraws() {
    let prefix = pfx(45, 0);
    let empty = one_peer_stream(vec![]);
    let safe_over_withdraw =
        one_peer_stream(vec![norm_message(vec![], vec![(Prefix::V4(prefix), 0)])]);
    assert_eq!(
        semantic_effects(&empty),
        semantic_effects(&safe_over_withdraw)
    );

    let terminal_route =
        one_peer_stream(vec![norm_message(vec![norm_announce(prefix, 100)], vec![])]);
    let withdraw_before_terminal_route = one_peer_stream(vec![
        norm_message(vec![], vec![(Prefix::V4(prefix), 0)]),
        norm_message(vec![norm_announce(prefix, 100)], vec![]),
    ]);
    assert_ne!(
        semantic_effects(&terminal_route),
        semantic_effects(&withdraw_before_terminal_route)
    );
}

#[test]
fn completion_gate_rejects_equal_but_incomplete_streams() {
    let empty: Streams = [(IpAddr::V4(LEFT), vec![]), (IpAddr::V4(RIGHT), vec![])]
        .into_iter()
        .collect();
    assert!(
        validate_terminal_stream(&empty).is_err(),
        "equal empty streams must not pass the differential oracle"
    );

    let truncated_message = norm_message(vec![norm_announce(pfx(42, 0), 100)], vec![]);
    let truncated: Streams = [
        (IpAddr::V4(LEFT), vec![truncated_message.clone()]),
        (IpAddr::V4(RIGHT), vec![truncated_message]),
    ]
    .into_iter()
    .collect();
    assert!(
        validate_terminal_stream(&truncated).is_err(),
        "equal nonempty streams truncated before convergence must not pass"
    );

    let sentinel_message = norm_message(vec![norm_announce(sentinel(), 250)], vec![]);
    let mut complete: Streams = [
        (IpAddr::V4(LEFT), vec![sentinel_message.clone()]),
        (IpAddr::V4(RIGHT), vec![sentinel_message]),
    ]
    .into_iter()
    .collect();
    assert!(validate_terminal_stream(&complete).is_ok());

    complete
        .get_mut(&IpAddr::V4(RIGHT))
        .unwrap()
        .push(session_start_message(9));
    assert!(
        validate_terminal_stream(&complete).is_err(),
        "a sentinel from a superseded connection cannot complete the current session"
    );
}

#[test]
fn extended_seed_sweep_varies_every_schedule_operation_fixture() {
    let baseline = schedules(DEFAULT_SEED_START);
    let mut varied = [false; 6];
    for offset in 1..DEFAULT_SEED_COUNT {
        let seed = DEFAULT_SEED_START
            + u64::try_from(offset).expect("extended seed count is capped at 64");
        let candidate = schedules(seed);
        for (index, (baseline, candidate)) in baseline.iter().zip(candidate.iter()).enumerate() {
            varied[index] |= baseline.ops != candidate.ops;
        }
    }

    // Reverting the mixer to raw little-endian seed bytes leaves four of
    // these six actual operation fixtures unchanged across the default sweep.
    for (schedule, varied) in baseline.iter().zip(varied) {
        assert!(
            varied,
            "extended seeds did not vary operations for {}",
            schedule.name
        );
    }
}

#[tokio::test]
async fn deterministic_fault_corpus() {
    tokio::time::pause();
    for seed in PR_SEEDS {
        for schedule in schedules(seed) {
            run_schedule(schedule, DEFAULT_MAX_OPS).await;
        }
    }
}

#[test]
fn extended_config_defaults_and_boundaries() {
    let longest = schedules(DEFAULT_SEED_START)
        .iter()
        .map(|schedule| schedule.ops.len())
        .max()
        .unwrap();
    assert_eq!(
        MIN_MAX_OPS, longest,
        "minimum cap must track longest schedule"
    );
    assert_eq!(
        parse_extended_config(|_| None).unwrap(),
        ExtendedConfig {
            seed_start: DEFAULT_SEED_START,
            seed_count: DEFAULT_SEED_COUNT,
            max_ops: DEFAULT_MAX_OPS,
        }
    );

    let get = |name: &str| match name {
        SEED_START_ENV => Some("0xffffffffffffffff".to_owned()),
        SEED_COUNT_ENV => Some("1".to_owned()),
        MAX_OPS_ENV => Some(MIN_MAX_OPS.to_string()),
        _ => None,
    };
    assert_eq!(
        parse_extended_config(get).unwrap(),
        ExtendedConfig {
            seed_start: u64::MAX,
            seed_count: 1,
            max_ops: MIN_MAX_OPS,
        }
    );

    for (name, value, expected) in [
        (
            SEED_START_ENV,
            "wat",
            "invalid RUSTBGPD_UPDATE_GROUP_SEED_START",
        ),
        (SEED_COUNT_ENV, "0", "must be in 1..=64"),
        (SEED_COUNT_ENV, "65", "must be in 1..=64"),
        (MAX_OPS_ENV, "17", "must be in 18..=64"),
        (MAX_OPS_ENV, "65", "must be in 18..=64"),
    ] {
        let error = parse_extended_config(|key| (key == name).then(|| value.to_owned()))
            .expect_err("invalid boundary must fail");
        assert!(error.contains(expected), "unexpected error: {error}");
    }

    let overflow = parse_extended_config(|name| match name {
        SEED_START_ENV => Some(u64::MAX.to_string()),
        SEED_COUNT_ENV => Some("2".to_owned()),
        _ => None,
    })
    .expect_err("seed range overflow must fail");
    assert!(overflow.contains("overflows u64"));
}

#[tokio::test]
#[ignore = "bounded extended corpus; run explicitly or via weekly workflow"]
async fn deterministic_fault_corpus_extended() {
    tokio::time::pause();
    let config = parse_extended_config(|name| env::var(name).ok())
        .unwrap_or_else(|error| panic!("invalid extended fault-corpus controls: {error}"));
    for index in 0..config.seed_count {
        let seed = config.seed_start + u64::try_from(index).expect("seed count is capped at 64");
        for schedule in schedules(seed) {
            run_schedule(schedule, config.max_ops).await;
        }
    }
}
