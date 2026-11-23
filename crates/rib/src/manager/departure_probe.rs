//! Phase observations for the in-process source-departure harness.

use std::collections::HashSet;
use std::future::{Future, poll_fn};
use std::pin::pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use super::RibManager;
use crate::{OutboundRouteUpdate, PeerId};
use rustbgpd_policy::{
    NeighborSetMatch, Policy, PolicyAction, PolicyChain, PolicyStatement, RouteModifications,
};
use rustbgpd_wire::Prefix;

/// Actor observations in nanoseconds from the probe's single monotonic origin.
#[derive(Clone, Copy, Debug, Default)]
pub struct SourceDepartureSnapshot {
    /// Time the driver started the measured interval.
    pub armed_ns: Option<u64>,
    /// The departing source starts leaving the input indexes.
    pub detach_started_ns: Option<u64>,
    /// The measured family's changed best paths have been selected.
    pub selection_finished_ns: Option<u64>,
    /// The expected source was observed as the installed sentinel winner.
    pub applied_ns: Option<u64>,
    /// Completion of the enqueue that reached the expected withdrawal total.
    pub last_withdraw_published_ns: Option<u64>,
    /// Withdrawal rows enqueued for the measured receivers and family.
    pub published_withdrawals: u64,
    /// Longest physical actor poll beginning in the measured interval.
    pub max_rib_poll_ns: u64,
    /// Most measured withdrawal rows published within one physical poll: a
    /// lower bound on the receiver-keys that poll inspected.
    pub max_withdrawals_per_poll: u64,
}

/// An opt-in observer for one trial. The harness supplies the source, independent
/// winner and receiver roster before starting the actor.
pub struct SourceDepartureProbe {
    epoch: Instant,
    departed: PeerId,
    sentinel: Prefix,
    origin: PeerId,
    receivers: HashSet<PeerId>,
    flowspec: bool,
    expected_withdrawals: u64,
    counting_withdrawals: AtomicBool,
    published_withdrawals: AtomicU64,
    observations: Mutex<SourceDepartureSnapshot>,
}

impl SourceDepartureProbe {
    /// Create one unarmed trial observer.
    #[must_use]
    pub fn new(
        departed: PeerId,
        sentinel: Prefix,
        origin: PeerId,
        receivers: Vec<PeerId>,
        flowspec: bool,
        expected_withdrawals: u64,
    ) -> Arc<Self> {
        Arc::new(Self {
            epoch: Instant::now(),
            departed,
            sentinel,
            origin,
            receivers: receivers.into_iter().collect(),
            flowspec,
            expected_withdrawals,
            counting_withdrawals: AtomicBool::new(false),
            published_withdrawals: AtomicU64::new(0),
            observations: Mutex::default(),
        })
    }

    /// Convert an instant from the driver or receiver to this trial's clock.
    #[must_use]
    pub fn timestamp_ns(&self, at: Instant) -> u64 {
        u64::try_from(at.duration_since(self.epoch).as_nanos()).unwrap_or(u64::MAX)
    }

    /// Sample this trial's clock.
    #[must_use]
    pub fn now_ns(&self) -> u64 {
        self.timestamp_ns(Instant::now())
    }

    /// Start after initial convergence, immediately before enqueuing the pair.
    ///
    /// # Panics
    ///
    /// Panics on a second start or if another observer poisoned the mutex.
    pub fn arm(&self) -> u64 {
        let mut state = self.observations.lock().unwrap();
        let now = self.now_ns();
        assert!(state.armed_ns.replace(now).is_none(), "trial already armed");
        now
    }

    /// Read the observed boundaries. Unseen events retain `None`.
    ///
    /// # Panics
    ///
    /// Panics if another observer poisoned the mutex.
    #[must_use]
    pub fn snapshot(&self) -> SourceDepartureSnapshot {
        let state = self.observations.lock().unwrap();
        SourceDepartureSnapshot {
            published_withdrawals: self.published_withdrawals.load(Ordering::Relaxed),
            ..*state
        }
    }

    /// Time each physical poll of the actual RIB future.
    ///
    /// # Panics
    ///
    /// Panics if the actor panics or another observer poisoned the mutex.
    pub async fn observe_polls<F: Future>(&self, actor: F) -> F::Output {
        let mut actor = pin!(actor);
        poll_fn(|context| {
            let published = self.published_withdrawals.load(Ordering::Relaxed);
            let start = Instant::now();
            let result = actor.as_mut().poll(context);
            let end = Instant::now();
            let rows = self.published_withdrawals.load(Ordering::Relaxed) - published;
            let mut state = self.observations.lock().unwrap();
            if state
                .armed_ns
                .is_some_and(|armed| armed <= self.timestamp_ns(start))
            {
                let elapsed = u64::try_from((end - start).as_nanos()).unwrap_or(u64::MAX);
                state.max_rib_poll_ns = state.max_rib_poll_ns.max(elapsed);
                state.max_withdrawals_per_poll = state.max_withdrawals_per_poll.max(rows);
            }
            result
        })
        .await
    }

    pub(super) fn source_detaching(&self, peer: PeerId) {
        if peer == self.departed {
            let mut state = self.observations.lock().unwrap();
            if state.armed_ns.is_some() {
                state.detach_started_ns.get_or_insert_with(|| self.now_ns());
                self.counting_withdrawals.store(true, Ordering::Relaxed);
            }
        }
    }

    pub(super) fn selection_finished(&self, flowspec: bool) {
        if flowspec == self.flowspec {
            let mut state = self.observations.lock().unwrap();
            if state.detach_started_ns.is_some() {
                state
                    .selection_finished_ns
                    .get_or_insert_with(|| self.now_ns());
            }
        }
    }

    pub(super) fn winner_installed(&self, prefix: Prefix, source: Option<PeerId>) {
        if prefix == self.sentinel && source == Some(self.origin) {
            let mut state = self.observations.lock().unwrap();
            if state.detach_started_ns.is_some() {
                state.applied_ns.get_or_insert_with(|| self.now_ns());
            }
        }
    }

    pub(super) fn withdrawals_for_receiver(
        &self,
        peer: PeerId,
        update: &OutboundRouteUpdate,
    ) -> usize {
        let rows = if self.flowspec {
            update.flowspec_withdraw.len()
        } else {
            update.shared_withdraw.len() + update.withdraw.len()
        };
        if rows != 0 && self.receivers.contains(&peer) {
            rows
        } else {
            0
        }
    }

    pub(super) fn withdrawals_published(&self, rows: usize) {
        if rows == 0 || !self.counting_withdrawals.load(Ordering::Relaxed) {
            return;
        }
        // Only the actor writes this count. Snapshot readers also need the
        // boundary timestamp at the expected total, even if later sends exceed it.
        let total = self.published_withdrawals.load(Ordering::Relaxed)
            + u64::try_from(rows).expect("withdrawal count fits u64");
        if total == self.expected_withdrawals {
            let mut state = self.observations.lock().unwrap();
            state.last_withdraw_published_ns = Some(self.now_ns());
            self.published_withdrawals.store(total, Ordering::Relaxed);
        } else {
            self.published_withdrawals.store(total, Ordering::Relaxed);
        }
    }
}

impl SourceDepartureProbe {
    /// The neighbor-set-private export chain. A real neighbor set excludes it
    /// from shared unicast export; every fixture receiver (ASN 64512) reaches
    /// its permit.
    #[must_use]
    pub fn private_export_policy() -> PolicyChain {
        PolicyChain::new(vec![Policy {
            entries: vec![PolicyStatement {
                action: PolicyAction::Deny,
                match_neighbor_set: Some(NeighborSetMatch {
                    addresses: vec![],
                    remote_asns: vec![65099],
                    peer_groups: vec![],
                }),
                prefix: None,
                ge: None,
                le: None,
                match_community: vec![],
                match_as_path: None,
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
                modifications: RouteModifications::default(),
            }],
            default_action: PolicyAction::Permit,
        }])
    }
}

impl RibManager {
    /// Observe source teardown, installed winners and actual writer admission.
    #[must_use]
    pub fn with_bench_source_departure(mut self, probe: Arc<SourceDepartureProbe>) -> Self {
        self.departure_probe = Some(probe);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    use crate::test_support::{make_flowspec_route, peer_v4};
    use rustbgpd_wire::Ipv4Prefix;

    #[test]
    fn boundaries_require_the_measured_source_and_installed_winner() {
        let departed = peer_v4(Ipv4Addr::new(192, 0, 2, 1));
        let origin = peer_v4(Ipv4Addr::new(192, 0, 2, 2));
        let prefix = Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 254), 32));
        let wrong = Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 253), 32));
        let probe = SourceDepartureProbe::new(departed, prefix, origin, vec![], true, 1);
        probe.source_detaching(departed);
        let start = probe.arm();
        probe.source_detaching(origin);
        probe.winner_installed(prefix, Some(origin));
        assert_eq!(probe.snapshot().detach_started_ns, None);
        assert_eq!(probe.snapshot().applied_ns, None);

        probe.source_detaching(departed);
        probe.selection_finished(false);
        assert_eq!(probe.snapshot().selection_finished_ns, None);
        probe.selection_finished(true);
        probe.winner_installed(prefix, Some(departed));
        probe.winner_installed(wrong, Some(origin));
        probe.winner_installed(prefix, None);
        assert_eq!(probe.snapshot().applied_ns, None);
        probe.winner_installed(prefix, Some(origin));
        let state = probe.snapshot();
        assert!(start <= state.detach_started_ns.unwrap());
        assert!(state.detach_started_ns.unwrap() <= state.selection_finished_ns.unwrap());
        assert!(state.selection_finished_ns.unwrap() <= state.applied_ns.unwrap());
    }

    #[test]
    fn publication_counts_both_unicast_inventories_and_only_the_selected_family() {
        let address = Ipv4Addr::new(192, 0, 2, 1);
        let peer = peer_v4(address);
        let receiver = peer_v4(Ipv4Addr::new(192, 0, 2, 2));
        let prefix = Prefix::V4(Ipv4Prefix::new(address, 32));
        let update = OutboundRouteUpdate {
            shared_withdraw: Arc::new(vec![(prefix, 1), (prefix, 2)]).into(),
            withdraw: vec![(prefix, 3)],
            flowspec_withdraw: vec![make_flowspec_route(address).selection_key()],
            ..Default::default()
        };
        for (flowspec, expected) in [(false, 3), (true, 1)] {
            let expected_total = 2 * expected as u64;
            let probe = SourceDepartureProbe::new(
                peer,
                prefix,
                peer,
                vec![receiver],
                flowspec,
                expected_total,
            );
            probe.arm();
            probe.withdrawals_published(100);
            assert_eq!(probe.snapshot().published_withdrawals, 0);
            probe.source_detaching(peer);
            assert_eq!(probe.withdrawals_for_receiver(peer, &update), 0);
            let counted = probe.withdrawals_for_receiver(receiver, &update);
            assert_eq!(counted, expected);
            assert_eq!(probe.snapshot().last_withdraw_published_ns, None);
            probe.withdrawals_published(counted);
            assert_eq!(probe.snapshot().last_withdraw_published_ns, None);
            probe.withdrawals_published(counted);
            let state = probe.snapshot();
            assert_eq!(state.published_withdrawals, expected_total);
            assert!(state.last_withdraw_published_ns.is_some());
            probe.withdrawals_published(1);
            let excess = probe.snapshot();
            assert_eq!(excess.published_withdrawals, expected_total + 1);
            assert_eq!(
                excess.last_withdraw_published_ns,
                state.last_withdraw_published_ns
            );
        }
    }

    #[tokio::test]
    async fn per_poll_withdrawals_count_only_rows_published_inside_one_poll() {
        let address = Ipv4Addr::new(192, 0, 2, 1);
        let peer = peer_v4(address);
        let prefix = Prefix::V4(Ipv4Prefix::new(address, 32));
        let probe = SourceDepartureProbe::new(peer, prefix, peer, vec![peer], false, 11);
        probe.arm();
        probe.source_detaching(peer);
        // Outside any observed poll: never part of a per-poll maximum.
        probe.withdrawals_published(9);
        let mut polls = 0;
        probe
            .observe_polls(poll_fn(|context| {
                polls += 1;
                probe.withdrawals_published([1, 4, 2][polls - 1]);
                if polls == 3 {
                    return std::task::Poll::Ready(());
                }
                context.waker().wake_by_ref();
                std::task::Poll::Pending
            }))
            .await;
        let state = probe.snapshot();
        assert_eq!(state.published_withdrawals, 16);
        assert_eq!(state.max_withdrawals_per_poll, 4);
    }

    #[test]
    fn overshooting_the_target_counts_every_row_without_a_completion_timestamp() {
        let address = Ipv4Addr::new(192, 0, 2, 1);
        let peer = peer_v4(address);
        let prefix = Prefix::V4(Ipv4Prefix::new(address, 32));
        let probe = SourceDepartureProbe::new(peer, prefix, peer, vec![peer], false, 5);
        probe.arm();
        probe.source_detaching(peer);
        probe.withdrawals_published(3);
        probe.withdrawals_published(3);
        let state = probe.snapshot();
        assert_eq!(state.published_withdrawals, 6);
        assert_eq!(state.last_withdraw_published_ns, None);
    }
}
