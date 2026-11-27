//! Match replay transitions to the joiner's exact outbound session.

use std::{
    io,
    sync::{Arc, Mutex},
    time::Instant,
};

use rustbgpd_rib::{manager::BenchReplayEvent, PeerId, RibManager};

use crate::invalid_stat;

pub(super) struct ReplayObservation {
    joiner: PeerId,
    session: u64,
    started: Instant,
    events: Mutex<Vec<(u64, BenchReplayEvent)>>,
}

#[derive(Debug)]
pub(super) struct ReplayReceipt {
    pub(super) disposition: &'static str,
    pub(super) enrolled_us: Option<u64>,
    pub(super) fallback_us: Option<u64>,
    pub(super) completed_us: Option<u64>,
    pub(super) cause: Option<&'static str>,
}

fn is_reservation_refusal(cause: &str) -> bool {
    matches!(cause, "peer_limit" | "daemon_limit" | "allocation_failure")
}

impl ReplayObservation {
    pub(super) fn new(joiner: PeerId, session: u64, started: Instant) -> Self {
        Self {
            joiner,
            session,
            started,
            events: Mutex::default(),
        }
    }

    pub(super) fn attach(self: &Arc<Self>, manager: RibManager) -> RibManager {
        let observation = Arc::clone(self);
        manager.with_bench_initial_replay_observer(move |peer, session, event| {
            observation.record(peer, session, event);
        })
    }

    fn record(&self, peer: PeerId, session: u64, event: BenchReplayEvent) {
        if peer == self.joiner && session == self.session {
            let elapsed = u64::try_from(self.started.elapsed().as_micros()).unwrap_or(u64::MAX);
            self.events
                .lock()
                .expect("replay observations")
                .push((elapsed, event));
        }
    }

    pub(super) fn receipt(&self) -> io::Result<ReplayReceipt> {
        use BenchReplayEvent::{Completed, Dirty, Enrolled, EnrollmentRefused, Reconciled};

        let events = self.events.lock().expect("replay observations");
        // A later resync of the joiner is not part of its join.
        let join = events
            .iter()
            .position(|(_, event)| {
                matches!(
                    event,
                    BenchReplayEvent::ResyncReconcile | BenchReplayEvent::ResyncOneTurn(_)
                )
            })
            .unwrap_or(events.len());
        let events = &events[..join];
        // A replay that rewound into a reconcile keeps its terminal events;
        // the first rewind names the cause.
        let reconciled = events.iter().find_map(|(at, event)| match event {
            Reconciled(cause) => Some((*at, *cause)),
            _ => None,
        });
        let terminal: Vec<_> = events
            .iter()
            .copied()
            .filter(|(_, event)| !matches!(event, Reconciled(_)))
            .collect();
        match terminal.as_slice() {
            [(start, Enrolled), (end, Completed)] => Ok(ReplayReceipt {
                disposition: if reconciled.is_some() {
                    "reconcile_complete"
                } else {
                    "paced_complete"
                },
                enrolled_us: Some(*start),
                fallback_us: reconciled.map(|(at, _)| at),
                completed_us: Some(*end),
                cause: reconciled.map(|(_, cause)| cause),
            }),
            [(start, Enrolled), (end, Dirty(cause))] => Ok(ReplayReceipt {
                disposition: if is_reservation_refusal(cause) {
                    "budget_refusal"
                } else if matches!(*cause, "selection_release" | "release_fanout") {
                    "selection_release_to_dirty"
                } else if matches!(*cause, "scan_repair_limit" | "lag") {
                    "replay_to_dirty"
                } else {
                    return Err(invalid_stat(format!(
                        "unattributed replay handoff for {} session {} at {end} us: {cause}",
                        self.joiner, self.session
                    )));
                },
                enrolled_us: Some(*start),
                fallback_us: Some(*end),
                completed_us: None,
                cause: Some(cause),
            }),
            [(at, EnrollmentRefused(cause))] if is_reservation_refusal(cause) => {
                Ok(ReplayReceipt {
                    disposition: "budget_refusal",
                    enrolled_us: None,
                    fallback_us: Some(*at),
                    completed_us: None,
                    cause: Some(cause),
                })
            }
            _ => Err(invalid_stat(format!(
                "missing or inconsistent replay evidence for {} session {}: {events:?}",
                self.joiner, self.session
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_requires_own_session_enrollment_and_completion() {
        let peer = PeerId::from_addr("192.0.2.1".parse().unwrap());
        let other = PeerId::from_addr("192.0.2.2".parse().unwrap());
        let observation = ReplayObservation::new(peer, 7, Instant::now());
        observation.record(other, 7, BenchReplayEvent::Enrolled);
        observation.record(peer, 6, BenchReplayEvent::Completed);
        assert!(observation.receipt().is_err());
        observation.record(peer, 7, BenchReplayEvent::Enrolled);
        assert!(observation.receipt().is_err());
        observation.record(peer, 7, BenchReplayEvent::Completed);
        assert_eq!(observation.receipt().unwrap().disposition, "paced_complete");
        observation.record(peer, 7, BenchReplayEvent::Dirty("scan_repair_limit"));
        assert!(observation.receipt().is_err());
    }

    #[test]
    fn selection_release_requires_an_enrolled_dirty_handoff() {
        let peer = PeerId::from_addr("192.0.2.1".parse().unwrap());
        let observation = ReplayObservation::new(peer, 7, Instant::now());
        observation.record(peer, 7, BenchReplayEvent::Enrolled);
        observation.record(peer, 7, BenchReplayEvent::Dirty("selection_release"));
        let receipt = observation.receipt().unwrap();
        assert_eq!(receipt.disposition, "selection_release_to_dirty");
        assert_eq!(receipt.cause, Some("selection_release"));
        assert!(receipt.enrolled_us.is_some() && receipt.fallback_us.is_some());
        assert_eq!(receipt.completed_us, None);

        let observation = ReplayObservation::new(peer, 7, Instant::now());
        observation.record(peer, 7, BenchReplayEvent::Enrolled);
        observation.record(peer, 7, BenchReplayEvent::Dirty("release_fanout"));
        let receipt = observation.receipt().unwrap();
        assert_eq!(receipt.disposition, "selection_release_to_dirty");
        assert_eq!(receipt.cause, Some("release_fanout"));

        for event in [
            BenchReplayEvent::EnrollmentRefused("selection_release"),
            BenchReplayEvent::Dirty("selection_release"),
        ] {
            let observation = ReplayObservation::new(peer, 7, Instant::now());
            observation.record(peer, 7, event);
            assert!(observation.receipt().is_err());
        }
    }

    #[test]
    fn unrelated_dirty_or_unclassified_refusal_invalidates_measurement() {
        let peer = PeerId::from_addr("192.0.2.1".parse().unwrap());
        for cause in [
            "writer_unavailable",
            "group_changed",
            "change_outside_scan",
            "missing_proof",
            "unknown_limit",
        ] {
            let observation = ReplayObservation::new(peer, 7, Instant::now());
            observation.record(peer, 7, BenchReplayEvent::Enrolled);
            observation.record(peer, 7, BenchReplayEvent::Dirty(cause));
            assert!(observation.receipt().is_err(), "{cause}");
        }
        let observation = ReplayObservation::new(peer, 7, Instant::now());
        observation.record(
            peer,
            7,
            BenchReplayEvent::EnrollmentRefused("missing_proof"),
        );
        assert!(observation.receipt().is_err());
    }

    #[test]
    fn a_rewind_into_reconcile_names_its_first_cause() {
        let peer = PeerId::from_addr("192.0.2.1".parse().unwrap());
        let observation = ReplayObservation::new(peer, 7, Instant::now());
        observation.record(peer, 7, BenchReplayEvent::Enrolled);
        observation.record(peer, 7, BenchReplayEvent::Reconciled("scan_repair_limit"));
        observation.record(peer, 7, BenchReplayEvent::Reconciled("forced_resync"));
        observation.record(peer, 7, BenchReplayEvent::Completed);
        let receipt = observation.receipt().unwrap();
        assert_eq!(receipt.disposition, "reconcile_complete");
        assert_eq!(receipt.cause, Some("scan_repair_limit"));
        assert!(receipt.fallback_us.is_some() && receipt.completed_us.is_some());
        // A reconcile that later falls back reports the fallback.
        let observation = ReplayObservation::new(peer, 7, Instant::now());
        observation.record(peer, 7, BenchReplayEvent::Enrolled);
        observation.record(peer, 7, BenchReplayEvent::Reconciled("scan_repair_limit"));
        observation.record(peer, 7, BenchReplayEvent::Dirty("daemon_limit"));
        assert_eq!(observation.receipt().unwrap().disposition, "budget_refusal");
    }

    #[test]
    fn ledger_refusal_is_distinct_from_scan_repair_cap() {
        let peer = PeerId::from_addr("192.0.2.1".parse().unwrap());
        let observation = ReplayObservation::new(peer, 7, Instant::now());
        observation.record(peer, 7, BenchReplayEvent::EnrollmentRefused("peer_limit"));
        let receipt = observation.receipt().unwrap();
        assert_eq!(receipt.disposition, "budget_refusal");
        assert_eq!(receipt.enrolled_us, None);

        for (cause, expected) in [
            ("scan_repair_limit", "replay_to_dirty"),
            // A reconcile that overflowed on every rescan takes one resync.
            ("lag", "replay_to_dirty"),
            ("daemon_limit", "budget_refusal"),
            ("allocation_failure", "budget_refusal"),
        ] {
            let observation = ReplayObservation::new(peer, 7, Instant::now());
            observation.record(peer, 7, BenchReplayEvent::Enrolled);
            observation.record(peer, 7, BenchReplayEvent::Dirty(cause));
            let receipt = observation.receipt().unwrap();
            assert_eq!(receipt.disposition, expected);
            assert!(receipt.enrolled_us.is_some());
            assert_eq!(receipt.cause, Some(cause));
        }
    }
}
