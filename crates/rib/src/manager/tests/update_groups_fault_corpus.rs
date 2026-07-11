//! Deterministic differential fault corpus for update-group distribution.
//!
//! The small corpus runs in normal PR CI. The ignored extended corpus uses the
//! same replayable schedules with a hard seed/operation cap; it is exercised by
//! the weekly GitHub-hosted workflow, never by a live soak runner.

use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use rustbgpd_wire::{Afi, Ipv4Prefix, Prefix, RtcNlri, Safi};

use super::update_groups_oracle::{
    Oracle, Streams, deny_prefix_chain, deny_prefixes_chain, fold, ibgp_route, pfx, rtc_default,
    vpn_rtc_sendable,
};
use crate::route::RtcRibRouteKey;

const SOURCE: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
const LEFT: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
const RIGHT: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 3);
const PR_SEEDS: [u64; 3] = [0x51_7A, 0xC0_FF_EE, 0x05EE_D357];
const EXTENDED_SEEDS: usize = 24;
const MAX_OPS: usize = 64;

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

fn policy(spec: &PolicySpec) -> Option<rustbgpd_policy::PolicyChain> {
    match spec {
        PolicySpec::Permit => None,
        PolicySpec::DenyOne(prefix) => Some(deny_prefix_chain(*prefix)),
        PolicySpec::DenyMany(prefixes) => Some(deny_prefixes_chain(prefixes)),
    }
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

async fn run_path(schedule: &Schedule, force_ungrouped: bool) -> Streams {
    assert!(
        schedule.ops.len() <= MAX_OPS,
        "operation cap exceeded: {}",
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

async fn run_schedule(schedule: Schedule) {
    let grouped = run_path(&schedule, false).await;
    let ungrouped = run_path(&schedule, true).await;
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
}

fn saturation_schedule(seed: u64) -> Schedule {
    let first = pfx(seed_octet(seed, 0), 0);
    let second = pfx(seed_octet(seed, 1), 1);
    Schedule {
        name: "saturation-drain-virtual-retry",
        seed,
        comparison: ComparisonMode::SemanticFold,
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
    let second = pfx(seed_octet(seed, 3), 3);
    Schedule {
        name: "dirty-policy-regroup-transitions",
        seed,
        comparison: ComparisonMode::SemanticFold,
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
                families: FamilySet::Unicast,
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
            run_schedule(schedule).await;
        }
    }
}

#[tokio::test]
#[ignore = "bounded extended corpus; run explicitly or via weekly workflow"]
async fn deterministic_fault_corpus_extended() {
    tokio::time::pause();
    for index in 0..EXTENDED_SEEDS {
        let seed = 0x3570_0000_u64.wrapping_add(index as u64);
        for schedule in schedules(seed) {
            run_schedule(schedule).await;
        }
    }
}
