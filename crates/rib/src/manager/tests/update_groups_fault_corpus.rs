//! Deterministic differential fault corpus for update-group distribution.
//!
//! The small corpus runs in normal PR CI. The ignored extended corpus uses the
//! same replayable schedules with a hard seed/operation cap; it is exercised by
//! the weekly GitHub-hosted workflow, never by a live soak runner.

use std::env;
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use rustbgpd_wire::{Afi, Ipv4Prefix, Prefix, RtcNlri, Safi};

use super::update_groups_oracle::{
    Oracle, Streams, deny_prefix_chain, deny_prefixes_chain, fold, fold_vpn, ibgp_route, pfx,
    rtc_default, vpn_nlri, vpn_route, vpn_rtc_sendable,
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
    if !(1..=MAX_OPS_CAP).contains(&max_ops) {
        return Err(format!(
            "{MAX_OPS_ENV} must be in 1..={MAX_OPS_CAP}, got {max_ops}"
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

#[derive(Clone, Copy, Debug)]
enum FamilySet {
    Unicast,
    VpnRtc,
}

#[derive(Clone, Debug)]
enum PolicySpec {
    Permit,
    DenyOne(Ipv4Prefix),
    DenyMany(Vec<Ipv4Prefix>),
}

#[derive(Clone, Debug)]
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

fn seed_octet(seed: u64, byte: usize) -> u8 {
    seed.to_le_bytes()[byte] | 1
}

fn distinct_seed_octet(seed: u64, byte: usize, other: u8) -> u8 {
    let candidate = seed_octet(seed, byte);
    if candidate == other {
        candidate.wrapping_add(2)
    } else {
        candidate
    }
}

fn policy(spec: &PolicySpec) -> Option<rustbgpd_policy::PolicyChain> {
    match spec {
        PolicySpec::Permit => None,
        PolicySpec::DenyOne(prefix) => Some(deny_prefix_chain(*prefix)),
        PolicySpec::DenyMany(prefixes) => Some(deny_prefixes_chain(prefixes)),
    }
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

async fn apply(oracle: &mut Oracle, op: &Op) {
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
        apply(&mut oracle, op).await;
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
    assert!(
        streams.values().any(|messages| !messages.is_empty()),
        "schedule emitted no traffic: {}",
        schedule.replay()
    );
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
    for peer in [LEFT, RIGHT] {
        let delivered = streams
            .get(&IpAddr::V4(peer))
            .into_iter()
            .flatten()
            .any(|message| {
                message
                    .announce
                    .iter()
                    .any(|(prefix, ..)| *prefix == Prefix::V4(sentinel()))
            });
        assert!(
            delivered,
            "terminal sentinel missing for {peer}: {}",
            schedule.replay()
        );
    }
    streams
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
            fold(&grouped),
            fold(&ungrouped),
            "folded advertised-state mismatch: {}",
            schedule.replay()
        ),
    }
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
            Op::ReplacePolicy {
                peer: RIGHT,
                policy: PolicySpec::DenyOne(first),
            },
            Op::ReplacePolicy {
                peer: RIGHT,
                policy: PolicySpec::DenyMany(vec![first, second]),
            },
            Op::ReplacePolicy {
                peer: RIGHT,
                policy: PolicySpec::Permit,
            },
            Op::DrainOne(RIGHT),
            Op::AdvanceRetry,
            Op::DrainAvailable,
        ],
    }
}

fn stale_generation_rtc_schedule(seed: u64) -> Schedule {
    let live = pfx(seed_octet(seed, 4), 4);
    let stale = pfx(seed_octet(seed, 5), 5);
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

fn schedules(seed: u64) -> [Schedule; 3] {
    [
        saturation_schedule(seed),
        dirty_policy_schedule(seed),
        stale_generation_rtc_schedule(seed),
    ]
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
        SEED_COUNT_ENV | MAX_OPS_ENV => Some("1".to_owned()),
        _ => None,
    };
    assert_eq!(
        parse_extended_config(get).unwrap(),
        ExtendedConfig {
            seed_start: u64::MAX,
            seed_count: 1,
            max_ops: 1,
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
        (MAX_OPS_ENV, "0", "must be in 1..=64"),
        (MAX_OPS_ENV, "65", "must be in 1..=64"),
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
