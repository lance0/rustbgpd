//! Measure every physical poll of the RIB future, label it with the phase the
//! actor itself reported, and time two queued ordinary probes inside it.

use std::future::{poll_fn, Future};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{ensure, Context, Result};
use rustbgpd_rib::manager::GroupCaptureBenchEvent;
use rustbgpd_rib::update::RibUpdate;
use rustbgpd_rib::{PeerId, RibManager};
use serde_json::{json, Value};
use tokio::sync::{mpsc, oneshot};

use super::{host, PROBE_SOURCE, TRIGGER};

/// Phases in the order the actor reaches them, `setup` first. Every boundary
/// is an event the actor raises on its own thread, never a harness clock.
const PHASES: [&str; 5] = ["setup", "refusal", "dirty", "recovery", "settled"];
const REFUSAL: usize = 1;
const DIRTY: usize = 2;
const RECOVERY: usize = 3;
const SETTLED: usize = 4;

pub(super) type ProbeSlot = (mpsc::OwnedPermit<RibUpdate>, RibUpdate);

#[derive(Default)]
struct Probe {
    admitted: Option<Instant>,
    dispatch: Option<Instant>,
    winner: Option<Instant>,
}

#[derive(Default)]
struct Times {
    trigger: Option<Instant>,
    pass: Option<Instant>,
    capture: Option<Instant>,
    captured: Option<Instant>,
    finished: Option<Instant>,
    recovery: Option<Instant>,
    settled: Option<Instant>,
    /// The capture-walk probe, then the recovery probe.
    probes: [Probe; 2],
    poll: Option<(Instant, Instant)>,
    phase: usize,
    /// Bit per phase in force at any point of the poll in progress.
    touched: u8,
    polls: [(u64, Duration); 5],
    longest: (Duration, usize, u8),
    work: Option<(usize, usize, usize, bool)>,
    first_refused: Option<usize>,
    proofs: Vec<Value>,
    refusals: Vec<String>,
    /// Ledger bytes before the pass, after it, its peak, and both limits.
    ledger: [usize; 5],
    dirty_peers: usize,
    refused_slices: u64,
    recovery_slices: u64,
    probe_slice_open: bool,
    probe_slice_recovered: Option<bool>,
    // Last-owner retirement: the polls between the last observation of a
    // charged ledger and the first observation of its pre-capture charge.
    proofs_live: bool,
    window_reset: bool,
    window: Duration,
    retire_seen: bool,
    retirement: Option<Duration>,
}

impl Times {
    fn enter(&mut self, phase: usize) {
        self.phase = phase;
        self.touched |= 1 << phase;
    }
}

/// Each callback owns one prepared unrelated UPDATE and one reserved slot per
/// probe. Publishing one is synchronous on the actor's thread.
#[derive(Clone, Default)]
pub(super) struct Clocks(Arc<Mutex<Times>>);

impl Clocks {
    /// Run the actor on its own thread and runtime. The sessions, their peers
    /// and the harness keep running while one actor turn lasts.
    pub(super) fn observe(
        &self,
        mut manager: RibManager,
        capture_probe: ProbeSlot,
        recovery_probe: ProbeSlot,
    ) -> Result<oneshot::Receiver<()>> {
        let pending = Mutex::new([Some(capture_probe), Some(recovery_probe)]);
        let events = self.clone();
        manager.bench_observe_group_capture(
            host(TRIGGER),
            PeerId::from_ipv4(PROBE_SOURCE),
            move |event| {
                let now = Instant::now();
                let mut t = events.0.lock().unwrap();
                let admit = |t: &mut Times, index: usize| {
                    if let Some((slot, update)) = pending.lock().unwrap()[index].take() {
                        drop(slot.send(update));
                        t.probes[index].admitted = Some(Instant::now());
                    }
                };
                match event {
                    GroupCaptureBenchEvent::PassStarted {
                        proof_bytes,
                        member_limit_bytes,
                        daemon_limit_bytes,
                    } => {
                        t.pass = Some(now);
                        t.ledger = [proof_bytes, 0, 0, member_limit_bytes, daemon_limit_bytes];
                        t.enter(REFUSAL);
                    }
                    GroupCaptureBenchEvent::CaptureStarted => {
                        t.capture = Some(now);
                        admit(&mut t, 0);
                    }
                    GroupCaptureBenchEvent::ProofSealed {
                        strategy,
                        pool_reused,
                        keys,
                        slots,
                        walks,
                        projections,
                        member_charge_bytes,
                        daemon_bytes,
                    } => t.proofs.push(json!({
                        "strategy": strategy,
                        "pool": match (strategy, pool_reused) {
                            ("indexed", true) => "reused",
                            ("indexed", false) => "built",
                            _ => "none",
                        },
                        "keys": keys, "slots": slots, "walks": walks, "projections": projections,
                        "member_charge_bytes": member_charge_bytes,
                        "daemon_bytes": daemon_bytes,
                    })),
                    GroupCaptureBenchEvent::ProofRefused {
                        cause,
                        attempted_member_bytes,
                        attempted_daemon_bytes,
                    } => t.refusals.push(format!(
                        "{cause} (attempted {attempted_member_bytes} member bytes, \
                         {attempted_daemon_bytes} daemon bytes)"
                    )),
                    GroupCaptureBenchEvent::CaptureCompleted => t.captured = Some(now),
                    GroupCaptureBenchEvent::PassCompleted {
                        dirty_peers,
                        fresh_captures,
                        walks,
                        projections,
                        proof_bytes,
                        proof_peak_bytes,
                        checkpoint_tally_compiled,
                    } => {
                        t.finished = Some(now);
                        t.first_refused = Some(dirty_peers);
                        t.dirty_peers = dirty_peers;
                        t.work = Some((
                            fresh_captures,
                            walks,
                            projections,
                            checkpoint_tally_compiled,
                        ));
                        t.ledger[1] = proof_bytes;
                        t.ledger[2] = proof_peak_bytes;
                        t.proofs_live = proof_bytes > t.ledger[0];
                        t.window_reset = true;
                        t.enter(DIRTY);
                    }
                    GroupCaptureBenchEvent::ResyncSliceStarted { writable } => {
                        // Every receiver's queue stays full until the harness
                        // drains it, so the first slice that finds a free slot
                        // is the first recovery slice. The recovery probe is
                        // admitted there, before that slice builds anything.
                        if t.phase == DIRTY && writable {
                            t.recovery = Some(now);
                            t.enter(RECOVERY);
                            admit(&mut t, 1);
                            t.probe_slice_open = true;
                        }
                        match t.phase {
                            DIRTY => t.refused_slices += 1,
                            RECOVERY => t.recovery_slices += 1,
                            _ => {}
                        }
                    }
                    GroupCaptureBenchEvent::Progress {
                        dirty_peers,
                        proof_bytes,
                    } => {
                        if std::mem::take(&mut t.probe_slice_open) {
                            t.probe_slice_recovered = Some(dirty_peers < t.dirty_peers);
                        }
                        t.dirty_peers = dirty_peers;
                        if t.proofs_live {
                            if proof_bytes > t.ledger[0] {
                                t.window_reset = true;
                            } else {
                                t.proofs_live = false;
                                t.retire_seen = true;
                            }
                        }
                        if t.phase == RECOVERY && dirty_peers == 0 {
                            t.settled = Some(now);
                            t.enter(SETTLED);
                        }
                    }
                    GroupCaptureBenchEvent::ProbeDispatched => {
                        if let Some(probe) = t
                            .probes
                            .iter_mut()
                            .find(|probe| probe.admitted.is_some() && probe.dispatch.is_none())
                        {
                            probe.dispatch = Some(now);
                        }
                    }
                }
            },
        );
        let polls = self.clone();
        let (done_tx, done) = oneshot::channel();
        std::thread::Builder::new()
            .name("ribmgr".into())
            .spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("RIB actor runtime");
                let mut actor = Box::pin(manager.run());
                runtime.block_on(poll_fn(|cx| {
                    let start = Instant::now();
                    let began = {
                        let mut t = polls.0.lock().unwrap();
                        t.touched = 1 << t.phase;
                        t.phase
                    };
                    let result = actor.as_mut().poll(cx);
                    let end = Instant::now();
                    let elapsed = end - start;
                    let mut t = polls.0.lock().unwrap();
                    // One label per poll: any part of the capture pass makes it
                    // `refusal`, else any recovery work makes it `recovery`,
                    // else the phase in force when it began. The whole-run
                    // maximum also keeps every phase its poll touched.
                    let label = [REFUSAL, RECOVERY]
                        .into_iter()
                        .find(|phase| t.touched & (1 << phase) != 0)
                        .unwrap_or(began);
                    t.polls[label].0 += 1;
                    t.polls[label].1 = t.polls[label].1.max(elapsed);
                    if elapsed > t.longest.0 {
                        t.longest = (elapsed, label, t.touched);
                    }
                    if t.poll.is_none()
                        && t.pass.is_some_and(|pass| pass >= start)
                        && t.finished.is_some_and(|finished| finished <= end)
                    {
                        t.poll = Some((start, end));
                    }
                    t.window = if std::mem::take(&mut t.window_reset) {
                        elapsed
                    } else {
                        t.window.max(elapsed)
                    };
                    if t.retire_seen && t.retirement.is_none() {
                        t.retirement = Some(t.window);
                    }
                    result
                }));
                done_tx.send(()).ok();
            })?;
        Ok(done)
    }

    /// Call before the trigger is sent: the actor may enter its pass at once.
    pub(super) fn trigger(&self) {
        self.0.lock().unwrap().trigger = Some(Instant::now());
    }

    pub(super) fn winner(&self, probe: usize) {
        self.0.lock().unwrap().probes[probe].winner = Some(Instant::now());
    }

    pub(super) fn first_refused(&self) -> Result<usize> {
        self.0
            .lock()
            .unwrap()
            .first_refused
            .context("target pass never finished")
    }

    /// Ledger refusals of the selected pass, each with its cause.
    pub(super) fn refusals(&self) -> Vec<String> {
        self.0.lock().unwrap().refusals.clone()
    }

    /// Resync slices the actor ran against a still-full receiver.
    pub(super) fn refused_slices(&self) -> u64 {
        self.0.lock().unwrap().refused_slices
    }

    pub(super) fn recovery_probe_admitted(&self) -> bool {
        self.0.lock().unwrap().probes[1].admitted.is_some()
    }

    pub(super) fn receipt(&self) -> Result<Value> {
        let t = self.0.lock().unwrap();
        let trigger = t.trigger.context("missing trigger admission")?;
        let pass = t.pass.context("target ordinary pass never entered")?;
        let capture = t.capture.context("no fresh grouped capture")?;
        let captured = t.captured.context("capture loop never completed")?;
        let end = t.finished.context("target ordinary pass never completed")?;
        let recovery = t.recovery.context("no resync slice found a free slot")?;
        let settled = t.settled.context("recovery never left every peer clean")?;
        let [first, second] = &t.probes;
        let admitted = first.admitted.context("unrelated probe never admitted")?;
        let dispatch = first.dispatch.context("unrelated probe never dispatched")?;
        let winner = first.winner.context("unrelated winner never observed")?;
        let admitted2 = second.admitted.context("recovery probe never admitted")?;
        let dispatch2 = second.dispatch.context("recovery probe never dispatched")?;
        let winner2 = second.winner.context("recovery winner never observed")?;
        let (poll_start, poll_end) = t
            .poll
            .context("target pass did not fit in a single physical RIB poll")?;
        let (fresh, walks, projections, tally) = t.work.context("missing capture work witness")?;
        ensure!(
            trigger <= pass
                && poll_start <= pass
                && pass <= capture
                && capture <= admitted
                && admitted < captured
                && captured <= end
                && end <= poll_end
                && end <= dispatch
                && dispatch <= winner
                && winner <= recovery
                && recovery <= admitted2
                && admitted2 <= dispatch2
                && dispatch2 <= winner2
                && recovery <= settled,
            "capture/probe clocks out of order"
        );
        let epoch = trigger.min(poll_start);
        let ns = |at: Instant| u64::try_from((at - epoch).as_nanos()).unwrap();
        let nanos = |span: Duration| u64::try_from(span.as_nanos()).unwrap();
        let names = |bits: u8| -> Vec<&str> {
            (0..PHASES.len())
                .filter(|phase| bits & (1 << phase) != 0)
                .map(|phase| PHASES[phase])
                .collect()
        };
        let mut phases = serde_json::Map::new();
        for (index, name) in PHASES.iter().enumerate() {
            let mut phase =
                json!({"polls": t.polls[index].0, "longest_poll_ns": nanos(t.polls[index].1)});
            match index {
                DIRTY => phase["refused_resync_slices"] = json!(t.refused_slices),
                RECOVERY => phase["resync_slices"] = json!(t.recovery_slices),
                _ => {}
            }
            phases.insert((*name).into(), phase);
        }
        let [before, after, peak, member_limit, daemon_limit] = t.ledger;
        Ok(json!({
            "actor_polls": t.polls.iter().map(|(count, _)| count).sum::<u64>(),
            "longest_actor_poll_ns": nanos(t.longest.0), "longest_actor_poll_phase": PHASES[t.longest.1],
            "longest_actor_poll_touched": names(t.longest.2),
            "phases": phases,
            "retirement": {"reached": t.retirement.is_some(), "longest_poll_ns": t.retirement.map(nanos)},
            "clocks_ns":{"trigger_admission":ns(trigger),"pass_start":ns(pass),"capture_start":ns(capture),
                "probe_admission":ns(admitted),"capture_end":ns(captured),"pass_end":ns(end),
                "probe_dispatch":ns(dispatch),"probe_winner":ns(winner),"poll_start":ns(poll_start),"poll_end":ns(poll_end),
                "recovery_start":ns(recovery),"recovery_probe_admission":ns(admitted2),
                "recovery_probe_dispatch":ns(dispatch2),"recovery_probe_winner":ns(winner2),"recovery_end":ns(settled)},
            "capture_turn_poll_ns":ns(poll_end)-ns(poll_start), "capture_pass_ns":ns(end)-ns(pass),
            "capture_loop_ns":ns(captured)-ns(capture), "probe_admission_to_dispatch_ns":ns(dispatch)-ns(admitted),
            "probe_admission_to_winner_ns":ns(winner)-ns(admitted), "probe_winner_boundary":"first_matching_query_reply",
            "recovery_probe_admission_to_dispatch_ns":ns(dispatch2)-ns(admitted2),
            "recovery_probe_admission_to_winner_ns":ns(winner2)-ns(admitted2),
            "recovery_probe_slice_recovered": t.probe_slice_recovered,
            "fresh_captures":fresh, "walks":walks, "projections":projections,
            "group_capture_walks": t.proofs.iter().map(|proof| proof["walks"].as_u64().unwrap()).sum::<u64>(),
            "proofs": t.proofs,
            "proof_ledger": {"before_bytes": before, "after_bytes": after, "peak_bytes": peak,
                "member_limit_bytes": member_limit, "daemon_limit_bytes": daemon_limit},
            "checkpoint_tally_compiled_in":tally, "debug_assertions":cfg!(debug_assertions)
        }))
    }
}
