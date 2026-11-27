//! Bench-only observations at the replay owner's enrollment and terminal decisions.

use rustbgpd_policy::{Policy, PolicyAction, PolicyChain, PolicyStatement, RouteModifications};

use super::{PeerId, RibManager};

/// Registration replay transitions for the specified receiver and outbound session.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BenchReplayEvent {
    /// The ledger and scan were enrolled and the replay was scheduled.
    Enrolled,
    /// The reservation for the initial proof failed with this ledger cause.
    EnrollmentRefused(&'static str),
    /// The replay did not start for this cause; the registration sent its
    /// table in its own turn.
    Refused(&'static str),
    /// The cursor and change queue completed before normal `EoR` settlement.
    Completed,
    /// The actor handed replay to dirty resync after this guard fired.
    Dirty(&'static str),
    /// The replay lost track of its changes for this cause and rewound into
    /// a paced reconcile; it still ends with `Completed`.
    Reconciled(&'static str),
}

pub(super) type ReplayObserver = Box<dyn Fn(PeerId, u64, BenchReplayEvent) + Send + Sync>;

impl RibManager {
    /// Observe the actor's initial replay decisions before starting the run loop.
    #[must_use]
    pub fn with_bench_initial_replay_observer(
        mut self,
        observer: impl Fn(PeerId, u64, BenchReplayEvent) + Send + Sync + 'static,
    ) -> Self {
        self.initial_member_replays.observer = Some(Box::new(observer));
        self
    }

    /// Reduce the per-peer admitted-proof budget to exercise a real refusal.
    ///
    /// # Panics
    ///
    /// Panics if the budget increases or the ledger already owns recovery records.
    #[must_use]
    pub fn with_bench_initial_replay_peer_limit(mut self, bytes: usize) -> Self {
        self.pending_group_admitted.set_bench_peer_limit(bytes);
        self
    }

    /// An export chain that permits every route and adds `community`, so a
    /// receiver forms its own update group with a policy-shaped table.
    #[must_use]
    pub fn bench_community_export_policy(community: u32) -> PolicyChain {
        let entry = PolicyStatement {
            prefix: None,
            ge: None,
            le: None,
            action: PolicyAction::Permit,
            match_community: vec![],
            match_as_path: None,
            match_neighbor_set: None,
            match_route_type: None,
            match_evpn_route_type: None,
            match_rpki_validation: None,
            match_aspa_validation: None,
            match_as_path_length_ge: None,
            match_as_path_length_le: None,
            match_local_pref_ge: None,
            match_local_pref_le: None,
            match_med_ge: None,
            match_med_le: None,
            match_next_hop: None,
            modifications: RouteModifications {
                communities_add: vec![community],
                ..Default::default()
            },
        };
        PolicyChain::new(vec![Policy {
            entries: vec![entry],
            default_action: PolicyAction::Deny,
        }])
    }

    pub(in crate::manager) fn observe_initial_replay(&self, peer: PeerId, event: BenchReplayEvent) {
        if let Some(observer) = &self.initial_member_replays.observer
            && let Some(&session) = self.outbound_session_ids.get(&peer)
        {
            observer(peer, session, event);
        }
    }
}
