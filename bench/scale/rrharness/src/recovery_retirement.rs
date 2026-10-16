//! Actual actor retirement boundaries; no daemon/fleet readiness qualification.

use super::recovery_memory::{
    evpn_withdrawal, key_update, populate, populate_evpn, verify_memory_identity, Counts,
    EvpnCounts, RecoveryHarness, Spec,
};
use super::{oneshot, RibManager, RibUpdate};
use std::io::{Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Default)]
struct ProbeReceipt {
    attempts: u64,
    admitted: u64,
    replied: u64,
    errors: u64,
    before_capture: u64,
    after_barrier: u64,
    inflight: u64,
    max_inflight: u64,
    max_reserve_ns: u128,
    max_enqueue_reply_ns: u128,
    max_attempt_reply_ns: u128,
    max_refill_ns: u128,
}

impl ProbeReceipt {
    fn assert_valid(&self, measured: bool) {
        assert_eq!(self.errors, 0, "real readiness query failed");
        assert_eq!(self.attempts, self.admitted);
        assert_eq!(self.admitted, self.replied);
        assert_eq!((self.before_capture, self.after_barrier), (1, 1));
        assert_eq!((self.inflight, self.max_inflight), (0, 1));
        if measured {
            assert!(
                self.max_attempt_reply_ns <= 200_000_000,
                "RIB readiness component exceeded its unchanged 200 ms deadline"
            );
        }
    }

    fn json(&self, measured: bool) -> String {
        format!(
            "{{\"attempts\":{},\"admitted\":{},\"replied\":{},\"errors\":{},\"max_inflight\":{},\"before_capture_replies\":{},\"after_barrier_replies\":{},\"max_reserve_wait_ns\":{},\"max_enqueue_reply_ns\":{},\"max_attempt_reply_ns\":{},\"max_refill_gap_ns\":{}}}",
            self.attempts,
            self.admitted,
            self.replied,
            self.errors,
            self.max_inflight,
            self.before_capture,
            self.after_barrier,
            optional_ns(measured.then_some(self.max_reserve_ns)),
            optional_ns(measured.then_some(self.max_enqueue_reply_ns)),
            optional_ns(measured.then_some(self.max_attempt_reply_ns)),
            optional_ns(measured.then_some(self.max_refill_ns))
        )
    }
}

struct ReadinessProbe {
    stop: Arc<AtomicBool>,
    thread: std::thread::JoinHandle<ProbeReceipt>,
}

impl ReadinessProbe {
    async fn start(harness: &RecoveryHarness, measured: bool) -> Self {
        Self::start_queries(harness.readiness_tx.clone(), measured).await
    }

    async fn start_queries(
        tx: tokio::sync::mpsc::Sender<rustbgpd_rib::RibReadinessQuery>,
        measured: bool,
    ) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = Arc::clone(&stop);
        let (ready, initial) = oneshot::channel();
        let thread = std::thread::Builder::new()
            .name("retirement-ready".into())
            .spawn(move || {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap()
                    .block_on(async move {
                        let mut receipt = ProbeReceipt::default();
                        let mut ready = Some(ready);
                        let mut previous_reply: Option<Instant> = None;
                        loop {
                            // A final request starts only after the primary FIFO barrier.
                            // There is never more than one reservation/reply in flight.
                            let final_probe = worker_stop.load(Ordering::Acquire);
                            let attempted = measured.then(Instant::now);
                            if let (Some(previous), Some(now)) = (previous_reply, attempted) {
                                receipt.max_refill_ns = receipt
                                    .max_refill_ns
                                    .max(now.duration_since(previous).as_nanos());
                            }
                            receipt.attempts += 1;
                            let Ok(permit) = tx.reserve().await else {
                                receipt.errors += 1;
                                break;
                            };
                            let (reply, answer) = oneshot::channel();
                            receipt.admitted += 1;
                            receipt.inflight += 1;
                            receipt.max_inflight = receipt.max_inflight.max(receipt.inflight);
                            let enqueued = Instant::now();
                            permit.send(rustbgpd_rib::RibReadinessQuery::LocRibCount {
                                reply,
                                enqueued,
                            });
                            if let Some(attempted) = attempted {
                                receipt.max_reserve_ns = receipt
                                    .max_reserve_ns
                                    .max(enqueued.duration_since(attempted).as_nanos());
                            }
                            // Keep ownership until the real reply, including when late.
                            // The containing native cell retains its existing timeout.
                            let result = answer.await;
                            receipt.inflight -= 1;
                            if !matches!(result, Ok(Ok(_))) {
                                receipt.errors += 1;
                                break;
                            }
                            receipt.replied += 1;
                            if let Some(attempted) = attempted {
                                let now = Instant::now();
                                receipt.max_enqueue_reply_ns = receipt
                                    .max_enqueue_reply_ns
                                    .max(now.duration_since(enqueued).as_nanos());
                                receipt.max_attempt_reply_ns = receipt
                                    .max_attempt_reply_ns
                                    .max(now.duration_since(attempted).as_nanos());
                                previous_reply = Some(now);
                            }
                            if let Some(ready) = ready.take() {
                                receipt.before_capture = 1;
                                ready.send(()).unwrap();
                            }
                            if final_probe {
                                receipt.after_barrier = 1;
                                break;
                            }
                        }
                        receipt
                    })
            })
            .unwrap();
        initial
            .await
            .expect("readiness producer failed before capture");
        Self { stop, thread }
    }

    async fn finish(self) -> ProbeReceipt {
        self.stop.store(true, Ordering::Release);
        tokio::task::spawn_blocking(move || {
            self.thread.join().expect("readiness producer panicked")
        })
        .await
        .expect("readiness producer join failed")
    }
}

fn owner_overlap(values: &[u64], keys: u64) -> bool {
    keys > 0
        && values[0] == 1
        && values[1] == 0
        && values[3] >= keys
        && values[2] >= values[3] + 2
        && values[4] > 0
        && values[6] == values[4]
        && values[5] >= values[6]
        && values[7] > 0
}

fn owner_json(values: &[u64], measured: bool, keys: u64) -> String {
    let overlap = owner_overlap(values, keys);
    let eligible = measured && overlap;
    format!(
        "{{\"owners\":{},\"invalid_owners\":{},\"callbacks\":{},\"body_callbacks\":{},\"admitted\":{},\"serviced\":{},\"replied\":{},\"body_replied\":{},\"overlap\":{},\"eligible\":{},\"max_checkpoint_interval_ns\":{},\"max_eligible_opportunity_gap_ns\":{},\"service_budget_ns\":{}}}",
        values[0],
        values[1],
        values[2],
        values[3],
        values[4],
        values[5],
        values[6],
        values[7],
        overlap,
        eligible,
        optional_ns((measured && values[0] > 0).then_some(u128::from(values[8]))),
        optional_ns((measured && values[0] > 0).then_some(u128::from(values[9]))),
        optional_ns((measured && values[0] > 0).then_some(u128::from(values[10])))
    )
}

fn readiness_json(probes: &ProbeReceipt, measured: bool, phases: &[u64; 16]) -> String {
    let owners = RibManager::bench_retirement_readiness();
    readiness_json_to(
        &mut std::io::stderr().lock(),
        probes,
        measured,
        phases,
        &owners,
    )
}

fn readiness_json_to(
    output: &mut impl Write,
    probes: &ProbeReceipt,
    measured: bool,
    phases: &[u64; 16],
    owners: &[u64; 33],
) -> String {
    let observation = format!(
        "{{\"probe\":{},\"owners\":{{\"received_cleanup_including_gc\":{},\"private_outbound_cleanup\":{},\"regroup_baseline_cleanup\":{}}}}}",
        probes.json(measured),
        owner_json(&owners[..11], measured, phases[5]),
        owner_json(&owners[11..22], measured, phases[9]),
        owner_json(&owners[22..], measured, phases[13])
    );
    // Capture and the observer have finished. Retain their actual observations
    // before a bound rejects this cell; this is not a completion receipt.
    writeln!(output, "retirement_readiness_observation {observation}")
        .expect("failed to retain retirement readiness observation");
    probes.assert_valid(measured);
    for (values, keys) in owners
        .as_chunks::<11>()
        .0
        .iter()
        .zip([phases[5], phases[9], phases[13]])
    {
        if measured && owner_overlap(values, keys) {
            assert!(
                values[8] <= 25_000_000,
                "instrumented cleanup callback interval exceeded the existing 25 ms budget"
            );
        }
    }
    observation
}

fn wait_for_ownership_ack(input: &mut impl Read) {
    let mut acknowledgment = [0];
    input
        .read_exact(&mut acknowledgment)
        .expect("missing launcher ownership acknowledgment");
    assert_eq!(acknowledgment, [b'1'], "invalid ownership acknowledgment");
}

fn optional_ns(value: Option<u128>) -> String {
    value.map_or_else(|| "null".into(), |value| value.to_string())
}

fn phase_json(values: &[u64], measured: bool) -> String {
    let elapsed = (measured && values[0] > 0).then_some(u128::from(values[3]));
    format!(
        "{{\"calls\":{},\"keys\":{},\"groups\":{},\"elapsed_ns\":{}}}",
        values[0],
        values[1],
        values[2],
        optional_ns(elapsed)
    )
}

async fn run(spec: Spec, empty: bool, measured: bool) {
    let expected = if empty { [0; 4] } else { spec.seed };
    let harness = RecoveryHarness::setup(1, spec, spec.seed).await;
    harness.verify_group().await;
    populate(&harness, expected).await;
    if empty {
        // PeerUp alone creates no received table. An actual empty receipt
        // creates the empty Adj-RIB-In that the control must then destroy.
        let update = if spec.seed[2] + spec.seed[3] > 0 {
            RibUpdate::VpnRoutesReceived {
                peer: harness.source,
                session_id: 1,
                announced: Vec::new(),
                withdrawn: Vec::new(),
            }
        } else {
            let mut update = super::empty_routes_received(harness.source, Vec::new());
            if let RibUpdate::RoutesReceived { session_id, .. } = &mut update {
                *session_id = 1;
            }
            update
        };
        harness.tx.send(update).await.unwrap();
    }
    let initial = harness.settle(expected).await;
    assert_eq!(initial.len(), 1);
    assert_eq!(initial[0].announces, expected.map(|n| n as u64));
    assert_eq!(initial[0].withdraws, [0; 4]);
    let probe = ReadinessProbe::start(&harness, measured).await;
    RibManager::bench_start_retirement_capture(measured);
    let started = measured.then(Instant::now);
    harness
        .tx
        .send(RibUpdate::PeerDown {
            peer: harness.source,
            session_id: 1,
        })
        .await
        .unwrap();
    // The same primary-channel FIFO barrier as the existing peer-down cell.
    let staged = harness.staged().await;
    let operation_ns = started.map(|started| started.elapsed().as_nanos());
    let probes = probe.finish().await;
    let phases = RibManager::bench_finish_retirement_capture();
    let readiness = readiness_json(&probes, measured, &phases);
    assert!(staged.values().all(|counts| *counts == [0; 4]));
    let settled = harness.settle([0; 4]).await;
    assert_eq!(settled[0].present, [0; 4]);
    assert_eq!(settled[0].announces, initial[0].announces);
    assert_eq!(settled[0].withdraws, expected.map(|n| n as u64));
    let keys = expected.iter().sum::<usize>() as u64;
    assert_eq!(phases[4], 1, "actual detached Adj-RIB-In drop must run");
    assert_eq!(phases[5], keys, "detached Adj-RIB-In cardinality differs");
    if expected[2] + expected[3] > 0 {
        assert_eq!(phases[0], 1, "actual bulk VPN-stage retirement must run");
        assert_eq!(
            phases[1], keys,
            "VPN stage must own the full changed inventory"
        );
        assert!(phases[2] > 0);
    } else {
        assert_eq!(&phases[..4], &[0; 4]);
    }
    // This query is a second actual actor barrier, after folded withdrawal.
    let (reply, answer) = oneshot::channel();
    harness
        .tx
        .send(RibUpdate::QueryLocRibCount { reply })
        .await
        .unwrap();
    assert_eq!(answer.await.unwrap(), 0);
    println!(
        "retirement_receipt {{\"profile\":\"{}\",\"cell\":\"{}\",\"measured\":{},\"receivers\":1,\"keys\":{},\"initial\":{},\"settled\":{},\"vpn_stage\":{},\"adj_rib_in\":{},\"operation_to_barrier_ns\":{},\"readiness\":{}}}",
        spec.name,
        if empty {
            "retirement-empty"
        } else {
            "retirement-full"
        },
        measured,
        keys,
        initial[0].json(),
        settled[0].json(),
        phase_json(&phases[..4], measured),
        phase_json(&phases[4..8], measured),
        optional_ns(operation_ns),
        readiness
    );
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ReceiverRetirement {
    AdjRibOut,
    Regroup,
}

impl ReceiverRetirement {
    fn cell(self, empty: bool) -> &'static str {
        match (self, empty) {
            (Self::AdjRibOut, false) => "retirement-adj-out-full",
            (Self::AdjRibOut, true) => "retirement-adj-out-empty",
            (Self::Regroup, false) => "retirement-regroup-full",
            (Self::Regroup, true) => "retirement-regroup-empty",
        }
    }
}

async fn settled_receivers(
    harness: &RecoveryHarness,
    expected: [usize; 4],
    evpn: usize,
) -> Vec<Counts> {
    loop {
        let health = harness.health().await;
        let staged = harness.staged().await;
        let private = harness.staged_evpn().await;
        let counts = harness.counts().await;
        assert_eq!(harness.source_counts().await, Counts::default());
        if health == (0, 0, 0, 0, 0, 0)
            && counts
                .iter()
                .all(|row| row.present == expected && row.evpn.present == evpn)
            && (0..2).all(|index| {
                let peer = harness.receiver_peer(index);
                staged.get(&peer).copied().unwrap_or_default() == expected.map(|n| n as u64)
                    && private.get(&peer).copied().unwrap_or(0) == evpn as u64
            })
        {
            return counts;
        }
        tokio::task::yield_now().await;
    }
}

async fn receiver_retirement(spec: Spec, kind: ReceiverRetirement, empty: bool, measured: bool) {
    let keys = if empty {
        0
    } else {
        spec.seed.iter().sum::<usize>()
    };
    // The grouped family is an eligibility anchor for the private EVPN cell,
    // not a claim that its N private rows are unicast or VPN.
    let expected = if kind == ReceiverRetirement::AdjRibOut {
        spec.seed.map(|count| usize::from(count > 0))
    } else if empty {
        [0; 4]
    } else {
        spec.seed
    };
    let mut fixture = spec;
    if kind == ReceiverRetirement::AdjRibOut {
        fixture.seed = expected;
        fixture = fixture.with_private_evpn(keys.max(1));
    }
    let limits = if kind == ReceiverRetirement::Regroup && empty {
        spec.seed.map(|count| usize::from(count > 0))
    } else {
        expected
    };
    let harness = RecoveryHarness::setup(2, fixture, limits).await;
    harness.verify_group().await;
    let witness_group = harness.group_label(1).await;
    let source_group_before = harness.peer_group_label(harness.source).await;
    if kind == ReceiverRetirement::Regroup {
        harness
            .tx
            .send(RibUpdate::PeerSlowState {
                peer: harness.receiver_peer(0),
                session_id: 1,
                slow: true,
            })
            .await
            .unwrap();
        assert_eq!(harness.group_label(0).await, "slow_peer");
    }
    populate(&harness, expected).await;
    let evpn = if kind == ReceiverRetirement::AdjRibOut {
        keys
    } else {
        0
    };
    if kind == ReceiverRetirement::AdjRibOut {
        // Even the empty control creates and empties the actual private table.
        populate_evpn(&harness, keys.max(1)).await;
        settled_receivers(&harness, expected, keys.max(1)).await;
        if empty {
            harness
                .tx
                .send(evpn_withdrawal(harness.source))
                .await
                .unwrap();
        }
    }
    let initial = settled_receivers(&harness, expected, evpn).await;
    assert_eq!(harness.evpn_received_best().await, [evpn as u64; 2]);
    for row in &initial {
        assert_eq!(row.announces, expected.map(|n| n as u64));
        assert_eq!(row.withdraws, [0; 4]);
        assert_eq!(
            row.evpn,
            EvpnCounts {
                present: evpn,
                announces: if kind == ReceiverRetirement::AdjRibOut {
                    keys.max(1) as u64
                } else {
                    0
                },
                withdrawals: u64::from(kind == ReceiverRetirement::AdjRibOut && empty),
            }
        );
    }
    let mut prepared = initial.clone();
    let mut release = None;
    let mut preparation_inputs = 0;
    let mut held_health = (0, 0, 0, 0, 0, 0);
    if kind == ReceiverRetirement::Regroup {
        release = Some(harness.pause_without_fill(0).await);
        assert_eq!(harness.receiver_capacity(0), 8);
        let family = spec.seed.iter().position(|count| *count > 0).unwrap();
        // Each receipt must be witnessed before the next is sent. Otherwise
        // the primary ingest path may coalesce the pair and never fill eight
        // actual outbound messages or retain the intended baseline.
        for step in 0..8 {
            let announce = (step % 2 == 0) == empty;
            harness
                .tx
                .send(key_update(harness.source, family, announce))
                .await
                .unwrap();
            if announce {
                prepared[1].present[family] += 1;
                prepared[1].announces[family] += 1;
            } else {
                prepared[1].present[family] -= 1;
                prepared[1].withdraws[family] += 1;
            }
            loop {
                let counts = harness.counts().await;
                let capacity = harness.receiver_capacity(0);
                assert!(capacity >= 7 - step, "unexpected extra preparation output");
                if capacity == 7 - step && counts[1] == prepared[1] {
                    assert_eq!(
                        counts[0], initial[0],
                        "held receiver consumed a preparation event"
                    );
                    break;
                }
                tokio::task::yield_now().await;
            }
            preparation_inputs += 1;
        }
        assert_eq!(prepared[1].present, expected);
        harness
            .tx
            .send(RibUpdate::PeerSlowState {
                peer: harness.receiver_peer(0),
                session_id: 1,
                slow: false,
            })
            .await
            .unwrap();
        assert_eq!(harness.group_label(0).await, witness_group);
        held_health = harness.health().await;
        assert_eq!(
            (held_health.0, held_health.2, held_health.4),
            (1, 1, 1),
            "actual dirty regroup must retain one baseline while its real queue is full"
        );
        assert_eq!(harness.receiver_capacity(0), 0);
    } else {
        harness.verify_group().await;
    }
    let target_group = harness.group_label(0).await;
    let queue_capacity = harness.receiver_capacity(0);
    assert_eq!(target_group, witness_group);
    let probe = ReadinessProbe::start(&harness, measured).await;
    RibManager::bench_start_retirement_capture(measured);
    let started = measured.then(Instant::now);
    harness
        .tx
        .send(RibUpdate::PeerDown {
            peer: harness.receiver_peer(0),
            session_id: 1,
        })
        .await
        .unwrap();
    let staged = harness.staged().await;
    let operation_ns = started.map(|started| started.elapsed().as_nanos());
    let probes = probe.finish().await;
    let phases = RibManager::bench_finish_retirement_capture();
    let readiness = readiness_json(&probes, measured, &phases);
    assert_eq!(
        &phases[..8],
        &[0; 8],
        "receiver departure must not retire source input or VPN stage"
    );
    assert_eq!(
        phases[8], 1,
        "actual detached private Adj-RIB-Out must be retired"
    );
    assert_eq!(
        phases[9],
        if kind == ReceiverRetirement::AdjRibOut {
            keys as u64
        } else {
            0
        }
    );
    assert_eq!(phases[10], 0);
    assert_eq!(phases[12], u64::from(kind == ReceiverRetirement::Regroup));
    assert_eq!(
        phases[13],
        if kind == ReceiverRetirement::Regroup {
            keys as u64
        } else {
            0
        }
    );
    assert_eq!(phases[14], 0);
    assert!(
        !staged.contains_key(&harness.receiver_peer(0)),
        "departed receiver still advertised"
    );
    assert_eq!(
        staged
            .get(&harness.receiver_peer(1))
            .copied()
            .unwrap_or_default(),
        expected.map(|n| n as u64)
    );
    let departed_group = harness.group_label(0).await;
    let surviving_group = harness.group_label(1).await;
    let source_group = harness.peer_group_label(harness.source).await;
    let source_counts = harness.source_counts().await;
    let settled_health = harness.health().await;
    let selected = harness.loc_counts().await;
    let evpn_received_best = harness.evpn_received_best().await;
    assert!(departed_group.is_empty());
    assert_eq!(surviving_group, witness_group);
    assert!(!source_group_before.is_empty());
    assert_eq!(source_group, source_group_before);
    assert_eq!(source_counts, Counts::default());
    assert_eq!(settled_health, (0, 0, 0, 0, 0, 0));
    assert_eq!(selected, expected.map(|n| n as u64));
    assert_eq!(evpn_received_best, [evpn as u64; 2]);
    let private = harness.staged_evpn().await;
    assert!(!private.contains_key(&harness.receiver_peer(0)));
    assert_eq!(
        private.get(&harness.receiver_peer(1)).copied().unwrap_or(0),
        evpn as u64
    );
    if let Some(release) = release {
        release.send(()).unwrap();
    }
    // Only the eight known pre-departure messages are drained. Session removal
    // need not manufacture withdrawals to an already disconnected receiver.
    prepared[0] = prepared[1];
    let settled = harness.counts().await;
    assert_eq!(
        settled, prepared,
        "receiver cleanup changed the surviving folded inventory"
    );
    println!(
        "retirement_receipt {{\"profile\":\"{}\",\"cell\":\"{}\",\"measured\":{},\"receivers\":2,\"keys\":{},\"initial\":{{\"target\":{},\"witness\":{}}},\"settled\":{{\"target\":{},\"witness\":{}}},\"private_evpn\":{{\"initial\":{{\"target\":{},\"witness\":{}}},\"settled\":{{\"target\":{},\"witness\":{}}}}},\"preparation\":{{\"inputs\":{},\"target_queue_capacity\":{},\"dirty_peers\":{},\"group_dirty_members\":{},\"regroup_baselines\":{}}},\"survivors\":{{\"target_group_before\":\"{}\",\"witness_group_before\":\"{}\",\"target_group_after\":\"{}\",\"witness_group_after\":\"{}\",\"source_group_before\":\"{}\",\"source_group_after\":\"{}\",\"source_fold\":{},\"source_evpn_fold\":{},\"selected\":{:?},\"evpn_received_best\":{:?},\"health\":[{},{},{},{},{},{}]}},\"vpn_stage\":{},\"adj_rib_in\":{},\"adj_rib_out\":{},\"regroup_baseline\":{},\"operation_to_barrier_ns\":{},\"readiness\":{}}}",
        spec.name,
        kind.cell(empty),
        measured,
        keys,
        initial[0].json(),
        initial[1].json(),
        settled[0].json(),
        settled[1].json(),
        initial[0].evpn.json(),
        initial[1].evpn.json(),
        settled[0].evpn.json(),
        settled[1].evpn.json(),
        preparation_inputs,
        queue_capacity,
        held_health.0,
        held_health.2,
        held_health.4,
        target_group,
        witness_group,
        departed_group,
        surviving_group,
        source_group_before,
        source_group,
        source_counts.json(),
        source_counts.evpn.json(),
        selected,
        evpn_received_best,
        settled_health.0,
        settled_health.1,
        settled_health.2,
        settled_health.3,
        settled_health.4,
        settled_health.5,
        phase_json(&phases[..4], measured),
        phase_json(&phases[4..8], measured),
        phase_json(&phases[8..12], measured),
        phase_json(&phases[12..16], measured),
        optional_ns(operation_ns),
        readiness
    );
}

pub(super) fn main(args: &[String]) {
    assert!(
        args.len() == 2 || (args.len() == 3 && args[2] == "--correctness-only"),
        "usage: rrharness recovery-retirement <retirement-{{full,empty,adj-out-full,adj-out-empty,regroup-full,regroup-empty}}> <profile> [--correctness-only]"
    );
    let (empty, receiver) = match args[0].as_str() {
        "retirement-full" => (false, None),
        "retirement-empty" => (true, None),
        "retirement-adj-out-full" => (false, Some(ReceiverRetirement::AdjRibOut)),
        "retirement-adj-out-empty" => (true, Some(ReceiverRetirement::AdjRibOut)),
        "retirement-regroup-full" => (false, Some(ReceiverRetirement::Regroup)),
        "retirement-regroup-empty" => (true, Some(ReceiverRetirement::Regroup)),
        _ => panic!("unknown retirement cell"),
    };
    let measured = args.len() == 2;
    assert!(
        matches!(args[1].as_str(), "full-uc" | "full-vpn")
            || (!measured && matches!(args[1].as_str(), "smoke-uc" | "smoke-vpn"))
    );
    if measured {
        assert_eq!(std::env::var("GITHUB_ACTIONS").as_deref(), Ok("true"));
        assert_eq!(
            std::env::var("RECOVERY_MEMORY_RUNNER_ENVIRONMENT").as_deref(),
            Ok("github-hosted")
        );
        let cgroup =
            std::env::var("RRHARNESS_RECOVERY_CGROUP").expect("swap-fenced launcher required");
        verify_memory_identity(std::path::Path::new(&cgroup));
        // The launcher owns the startup deadline and captures active membership
        // before releasing this hold. All measured work starts afterward.
        wait_for_ownership_ack(&mut std::io::stdin().lock());
    }
    let spec = Spec::named(&args[1]);
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let run = async {
                if let Some(kind) = receiver {
                    receiver_retirement(spec, kind, empty, measured).await;
                } else {
                    run(spec, empty, measured).await;
                }
            };
            tokio::time::timeout(Duration::from_secs(1800), run)
                .await
                .expect("retirement cell did not complete its actual actor barriers");
        });
}

#[cfg(test)]
mod tests {
    use super::wait_for_ownership_ack;
    use std::io::{self, Cursor, Read};
    use std::sync::mpsc;
    use std::time::Duration;

    #[test]
    fn boundary_only_owner_replies_are_not_body_overlap() {
        let mut values = [1, 0, 202, 200, 2, 2, 2, 0, 1, 1, 25_000_000];
        assert!(super::owner_json(&values, false, 200).contains("\"overlap\":false"));
        values[7] = 1;
        assert!(super::owner_json(&values, false, 200).contains("\"overlap\":true"));
        assert!(super::owner_json(&values, false, 200).contains("\"eligible\":false"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn readiness_probe_retains_one_reply_through_barrier_and_final_drain() {
        let (tx, mut rx) = tokio::sync::mpsc::channel(64);
        let (held, holding) = tokio::sync::oneshot::channel();
        let (release, released) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let mut released = Some(released);
            let mut held = Some(held);
            for n in 0..3 {
                let rustbgpd_rib::RibReadinessQuery::LocRibCount { reply, .. } =
                    rx.recv().await.unwrap();
                assert!(matches!(
                    rx.try_recv(),
                    Err(tokio::sync::mpsc::error::TryRecvError::Empty)
                ));
                if n == 1 {
                    held.take().unwrap().send(()).unwrap();
                    released.take().unwrap().await.unwrap();
                    assert!(matches!(
                        rx.try_recv(),
                        Err(tokio::sync::mpsc::error::TryRecvError::Empty)
                    ));
                }
                reply.send(Ok(123)).unwrap();
            }
            assert!(rx.recv().await.is_none());
        });
        let probe = super::ReadinessProbe::start_queries(tx, false).await;
        holding.await.unwrap();
        // This is the actual stop request issued after a primary FIFO barrier.
        probe.stop.store(true, std::sync::atomic::Ordering::Release);
        release.send(()).unwrap();
        let receipt = probe.finish().await;
        server.await.unwrap();
        assert_eq!((receipt.attempts, receipt.replied), (3, 3));
        assert_eq!((receipt.max_inflight, receipt.inflight), (1, 0));
        assert_eq!((receipt.before_capture, receipt.after_barrier), (1, 1));
        receipt.assert_valid(false);
        assert!(receipt
            .json(false)
            .contains("\"max_enqueue_reply_ns\":null"));
    }

    fn completed_observation(
        attempt_ns: u128,
        interval_ns: u64,
    ) -> (super::ProbeReceipt, [u64; 16], [u64; 33]) {
        let probes = super::ProbeReceipt {
            attempts: 3,
            admitted: 3,
            replied: 3,
            before_capture: 1,
            after_barrier: 1,
            max_inflight: 1,
            max_attempt_reply_ns: attempt_ns,
            ..Default::default()
        };
        let mut phases = [0; 16];
        phases[5] = 200;
        let mut owners = [0; 33];
        owners[..11].copy_from_slice(&[
            1,
            0,
            202,
            200,
            1,
            1,
            1,
            1,
            interval_ns,
            25_000_000,
            25_000_000,
        ]);
        (probes, phases, owners)
    }

    #[test]
    fn readiness_observations_survive_each_bound_failure() {
        for (attempt_ns, interval_ns, expected) in [
            (
                200_000_001,
                1,
                "RIB readiness component exceeded its unchanged 200 ms deadline",
            ),
            (
                1,
                25_000_001,
                "instrumented cleanup callback interval exceeded the existing 25 ms budget",
            ),
        ] {
            let (probes, phases, owners) = completed_observation(attempt_ns, interval_ns);
            let mut output = Vec::new();
            let failure = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                super::readiness_json_to(&mut output, &probes, true, &phases, &owners)
            }))
            .expect_err("a failed bound must still reject the native cell");
            assert_eq!(failure.downcast_ref::<&str>(), Some(&expected));
            let retained = String::from_utf8(output).unwrap();
            assert!(retained.starts_with("retirement_readiness_observation {"));
            assert_eq!(retained.lines().count(), 1);
            assert!(retained.contains(&format!("\"max_attempt_reply_ns\":{attempt_ns}")));
            assert!(retained.contains(&format!("\"max_checkpoint_interval_ns\":{interval_ns}")));
            assert!(!retained.contains("retirement_receipt "));
        }
    }

    #[test]
    fn readiness_observation_keeps_exact_limits_and_null_correctness_clocks() {
        let (probes, phases, owners) = completed_observation(200_000_000, 25_000_000);
        let mut output = Vec::new();
        let accepted = super::readiness_json_to(&mut output, &probes, true, &phases, &owners);
        assert_eq!(
            String::from_utf8(output).unwrap(),
            format!("retirement_readiness_observation {accepted}\n")
        );
        let (probes, phases, owners) = completed_observation(200_000_001, 25_000_001);
        let mut output = Vec::new();
        let unmeasured = super::readiness_json_to(&mut output, &probes, false, &phases, &owners);
        assert!(unmeasured.contains("\"max_attempt_reply_ns\":null"));
        assert!(unmeasured.contains("\"max_checkpoint_interval_ns\":null"));
        assert!(!unmeasured.contains("200000001"));
        assert!(!unmeasured.contains("25000001"));
        assert_eq!(
            String::from_utf8(output).unwrap(),
            format!("retirement_readiness_observation {unmeasured}\n")
        );
    }

    #[test]
    fn ownership_ack_holds_until_the_launcher_releases_it() {
        struct HeldAck {
            started: mpsc::Sender<()>,
            release: mpsc::Receiver<u8>,
        }

        impl Read for HeldAck {
            fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
                let Some(first) = buffer.first_mut() else {
                    return Ok(0);
                };
                self.started.send(()).unwrap();
                *first = self.release.recv().unwrap();
                Ok(1)
            }
        }

        let (started, reading) = mpsc::channel();
        let (release, acknowledgment) = mpsc::channel();
        let (finished, completion) = mpsc::channel();
        let worker = std::thread::spawn(move || {
            wait_for_ownership_ack(&mut HeldAck {
                started,
                release: acknowledgment,
            });
            finished.send(()).unwrap();
        });
        reading.recv_timeout(Duration::from_secs(5)).unwrap();
        let held = matches!(completion.try_recv(), Err(mpsc::TryRecvError::Empty));
        release.send(b'1').unwrap();
        completion.recv_timeout(Duration::from_secs(5)).unwrap();
        worker.join().unwrap();
        assert!(
            held,
            "work started before the launcher acknowledged ownership"
        );
    }

    #[test]
    #[should_panic(expected = "missing launcher ownership acknowledgment")]
    fn ownership_ack_rejects_eof() {
        wait_for_ownership_ack(&mut Cursor::new(b""));
    }

    #[test]
    #[should_panic(expected = "invalid ownership acknowledgment")]
    fn ownership_ack_rejects_a_wrong_byte() {
        wait_for_ownership_ack(&mut Cursor::new(b"0"));
    }
}
