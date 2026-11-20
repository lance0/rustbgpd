//! Measure a physical poll of the RIB future and the queued ordinary probe inside it.

use std::future::{poll_fn, Future};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{ensure, Context, Result};
use rustbgpd_rib::manager::GroupCaptureBenchEvent;
use rustbgpd_rib::update::RibUpdate;
use rustbgpd_rib::{PeerId, RibManager};
use serde_json::{json, Value};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use super::{host, PROBE_SOURCE, TRIGGER};

#[derive(Default)]
struct Times {
    trigger: Option<Instant>,
    pass: Option<Instant>,
    capture: Option<Instant>,
    admitted: Option<Instant>,
    captured: Option<Instant>,
    finished: Option<Instant>,
    dispatch: Option<Instant>,
    winner: Option<Instant>,
    poll: Option<(Instant, Instant)>,
    longest_poll: Duration,
    poll_count: u64,
    work: Option<(usize, usize, usize, bool)>,
    first_refused: Option<usize>,
}

/// The callback owns exactly one prepared unrelated UPDATE and one reserved
/// slot. Publishing it is synchronous even on the actor's single runtime thread.
#[derive(Clone, Default)]
pub(super) struct Clocks(Arc<Mutex<Times>>);

impl Clocks {
    pub(super) fn observe(
        &self,
        mut manager: RibManager,
        probe_slot: mpsc::OwnedPermit<RibUpdate>,
        probe: RibUpdate,
    ) -> JoinHandle<()> {
        let pending = Mutex::new(Some((probe_slot, probe)));
        let events = self.clone();
        manager.bench_observe_group_capture(
            host(TRIGGER),
            PeerId::from_ipv4(PROBE_SOURCE),
            move |event| {
                let now = Instant::now();
                let mut t = events.0.lock().unwrap();
                match event {
                    GroupCaptureBenchEvent::PassStarted => t.pass = Some(now),
                    GroupCaptureBenchEvent::CaptureStarted => {
                        t.capture = Some(now);
                        if let Some((slot, update)) = pending.lock().unwrap().take() {
                            drop(slot.send(update));
                            t.admitted = Some(Instant::now());
                        }
                    }
                    GroupCaptureBenchEvent::CaptureCompleted => t.captured = Some(now),
                    GroupCaptureBenchEvent::PassCompleted {
                        dirty_peers,
                        fresh_captures,
                        walks,
                        projections,
                        checkpoint_tally_compiled,
                    } => {
                        t.finished = Some(now);
                        t.first_refused = Some(dirty_peers);
                        t.work = Some((
                            fresh_captures,
                            walks,
                            projections,
                            checkpoint_tally_compiled,
                        ));
                    }
                    GroupCaptureBenchEvent::ProbeDispatched => t.dispatch = Some(now),
                }
            },
        );
        let polls = self.clone();
        tokio::spawn(async move {
            let mut actor = Box::pin(manager.run());
            poll_fn(|cx| {
                let start = Instant::now();
                let result = actor.as_mut().poll(cx);
                let end = Instant::now();
                let mut t = polls.0.lock().unwrap();
                t.longest_poll = t.longest_poll.max(end - start);
                t.poll_count += 1;
                if t.poll.is_none()
                    && t.pass.is_some_and(|pass| pass >= start)
                    && t.finished.is_some_and(|finished| finished <= end)
                {
                    t.poll = Some((start, end));
                }
                result
            })
            .await;
        })
    }

    pub(super) fn trigger(&self) {
        self.0.lock().unwrap().trigger = Some(Instant::now());
    }

    pub(super) fn winner(&self) {
        self.0.lock().unwrap().winner = Some(Instant::now());
    }

    pub(super) fn first_refused(&self) -> Result<usize> {
        self.0
            .lock()
            .unwrap()
            .first_refused
            .context("target pass never finished")
    }

    pub(super) fn receipt(&self) -> Result<Value> {
        let t = self.0.lock().unwrap();
        let trigger = t.trigger.context("missing trigger admission")?;
        let pass = t.pass.context("target ordinary pass never entered")?;
        let capture = t.capture.context("no fresh grouped capture")?;
        let admitted = t.admitted.context("unrelated probe never admitted")?;
        let captured = t.captured.context("capture loop never completed")?;
        let end = t.finished.context("target ordinary pass never completed")?;
        let dispatch = t.dispatch.context("unrelated probe never dispatched")?;
        let winner = t.winner.context("unrelated winner never observed")?;
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
                && dispatch <= winner,
            "capture/probe clocks out of order"
        );
        let epoch = trigger.min(poll_start);
        let ns = |at: Instant| u64::try_from((at - epoch).as_nanos()).unwrap();
        Ok(json!({
            "longest_actor_poll_ns":u64::try_from(t.longest_poll.as_nanos())?, "actor_polls":t.poll_count,
            "clocks_ns":{"trigger_admission":ns(trigger),"pass_start":ns(pass),"capture_start":ns(capture),
                "probe_admission":ns(admitted),"capture_end":ns(captured),"pass_end":ns(end),
                "probe_dispatch":ns(dispatch),"probe_winner":ns(winner),"poll_start":ns(poll_start),"poll_end":ns(poll_end)},
            "capture_turn_poll_ns":ns(poll_end)-ns(poll_start), "capture_pass_ns":ns(end)-ns(pass),
            "capture_loop_ns":ns(captured)-ns(capture), "probe_admission_to_dispatch_ns":ns(dispatch)-ns(admitted),
            "probe_admission_to_winner_ns":ns(winner)-ns(admitted), "probe_winner_boundary":"first_matching_query_reply",
            "probe_overlapped_capture":true, "fresh_captures":fresh, "walks":walks, "projections":projections,
            "checkpoint_tally_compiled_in":tally, "debug_assertions":cfg!(debug_assertions)
        }))
    }
}
