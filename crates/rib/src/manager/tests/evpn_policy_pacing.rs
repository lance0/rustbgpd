//! An export-policy reload that moves peers carrying EVPN outbound state is
//! paced: the authoritative batch hands those members back unapplied, with
//! their installed chain untouched, and each is applied by its own per-peer
//! command so other RIB work runs between their whole-table resyncs.

use super::evpn_group_storage::received;
use super::update_groups::community_chain;
use super::*;
use crate::PeerId;
use crate::manager::distribution::{PACED_TURN_BUDGET, paced_admits_next};
use crate::manager::helpers::evpn_routes_equal;
use crate::manager::update_groups::GroupMembership;
use crate::update::{
    PacedApplyOutcome, PacedMemberCost, PeerExportPolicyReplacement,
    PeerExportPolicyRestoreReceipt, RibCommandError,
};
use rustbgpd_wire::{EthernetTagId, EvpnRouteKey};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration as Span;

const EVPN: (Afi, Safi) = (Afi::L2Vpn, Safi::Evpn);
const TAGGED: u32 = 0xFC00_0001;

pub(super) fn evpn_row(tag: u32) -> EvpnRibRoute {
    let mut route = received(100);
    let EvpnRoute::Imet(ref mut imet) = route.route else {
        panic!("IMET fixture");
    };
    imet.ethernet_tag = EthernetTagId(tag);
    route
}

pub(super) fn member(index: usize) -> PeerId {
    PeerId::from_addr(Ipv4Addr::new(192, 0, 2, 31 + u8::try_from(index).unwrap()).into())
}

/// Register a session the way the transport does, with its accepted chain.
fn peer_up(
    manager: &mut RibManager,
    peer: PeerId,
    session_id: u64,
    families: Vec<(Afi, Safi)>,
    export_policy: Option<PolicyChain>,
) -> mpsc::Receiver<OutboundRouteUpdate> {
    let (sender, output) = mpsc::channel(4096);
    manager.handle_update(RibUpdate::PeerUp {
        supersedes: None,
        peer,
        session_id,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::new(192, 0, 2, 30),
        outbound_tx: sender,
        export_policy,
        sendable_families: families,
        is_ebgp: false,
        route_reflector_client: true,
        orr_vantage: None,
        per_client_best: false,
        interpret_rfc1997: true,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: vec![],
        negotiated_llgr_families: vec![],
    });
    output
}

fn evpn_families() -> Vec<(Afi, Safi)> {
    vec![
        (Afi::Ipv4, Safi::Unicast),
        (Afi::Ipv4, Safi::MplsVpn),
        (Afi::L2Vpn, Safi::Evpn),
    ]
}

pub(super) struct Fleet {
    pub(super) manager: RibManager,
    pub(super) members: Vec<PeerId>,
    pub(super) outputs: Vec<mpsc::Receiver<OutboundRouteUpdate>>,
    pub(super) source: PeerId,
    pub(super) next: PolicyChain,
}

impl Fleet {
    pub(super) fn replacements(&self) -> Vec<PeerExportPolicyReplacement> {
        self.members
            .iter()
            .map(|&peer| PeerExportPolicyReplacement {
                peer,
                export_policy: Some(self.next.clone()),
            })
            .collect()
    }

    /// The peer manager's forward batch; returns the members it deferred.
    pub(super) fn batch(&mut self) -> Vec<PeerId> {
        let (reply, mut response) = oneshot::channel();
        self.manager
            .handle_update(RibUpdate::ReplacePeerExportPoliciesAuthoritatively {
                replacements: self.replacements(),
                reply,
            });
        response.try_recv().unwrap().unwrap()
    }

    /// One paced command for `peers`, with the walk's cost estimate.
    pub(super) fn paced(
        &mut self,
        peers: &[PeerId],
        cost: Option<PacedMemberCost>,
    ) -> PacedApplyOutcome {
        let (reply, mut response) = oneshot::channel();
        self.manager
            .handle_update(RibUpdate::ApplyPacedExportPolicies {
                replacements: peers
                    .iter()
                    .map(|&peer| PeerExportPolicyReplacement {
                        peer,
                        export_policy: Some(self.next.clone()),
                    })
                    .collect(),
                cost,
                reply,
            });
        response.try_recv().unwrap().unwrap()
    }

    /// The peer manager's walk over `pending`: each command offers a window
    /// of at most twice the previous command's applied members; `between`
    /// runs after each command with the members it applied. A fixed `cost`
    /// replaces the estimate each reply carries, and the fleet's budget clock
    /// is fixed, so members per command do not depend on host load. Returns
    /// each command's applied count.
    pub(super) fn walk(
        &mut self,
        mut pending: Vec<PeerId>,
        cost: Option<PacedMemberCost>,
        mut between: impl FnMut(&mut Self, &[PeerId]),
    ) -> Vec<usize> {
        let (mut estimate, mut window) = (cost, 1_usize);
        let mut applied = Vec::new();
        while !pending.is_empty() {
            let rest = pending.split_off(window.min(pending.len()));
            let outcome = self.paced(&pending, estimate);
            assert!(outcome.applied >= 1, "every command makes progress");
            assert_eq!(outcome.skipped, Vec::<PeerId>::new());
            let done = pending.len() - outcome.pending.len();
            assert_eq!(
                pending[done..],
                outcome.pending[..],
                "the rest, in caller order"
            );
            between(self, &pending[..done]);
            applied.push(outcome.applied);
            window = (2 * outcome.applied).max(1);
            pending = outcome.pending.into_iter().chain(rest).collect();
            estimate = cost.or(outcome.cost);
        }
        applied
    }

    /// The per-peer replacement (the reference path).
    pub(super) fn step(&mut self, peer: PeerId) -> Result<(), RibCommandError> {
        let (reply, mut response) = oneshot::channel();
        self.manager
            .handle_update(RibUpdate::ReplacePeerExportPolicy {
                peer,
                export_policy: Some(self.next.clone()),
                reply,
            });
        response.try_recv().unwrap()
    }

    /// One source route chunk: a new row and the withdrawal of an old one.
    fn churn(&mut self, round: u32) {
        self.manager
            .process_evpn_announce_chunk(self.source, vec![evpn_row(1000 + round)]);
        self.manager
            .process_evpn_withdraw_chunk(self.source, vec![evpn_row(round + 1).key()]);
    }
}

/// `members` EVPN receivers in one group holding `rows` reflected EVPN
/// routes. `owned` makes the source group and the prepared destination own
/// their EVPN tables (production ownership stays disabled); otherwise each
/// member keeps private EVPN rows.
pub(super) fn evpn_fleet(members: usize, rows: u32, owned: bool) -> Fleet {
    let (_tx, rx) = mpsc::channel(8);
    let mut manager = RibManager::new(
        rx,
        dummy_query_rx(),
        None,
        Some(Ipv4Addr::new(192, 0, 2, 254)),
        BgpMetrics::new(),
    );
    manager.flush_poll_budget = Duration::MAX;
    manager.paced_elapsed_for_test = Some(Duration::ZERO);
    let members: Vec<_> = (0..members).map(member).collect();
    let mut outputs: Vec<_> = members
        .iter()
        .map(|&peer| peer_up(&mut manager, peer, 7, evpn_families(), None))
        .collect();
    let old_gid = manager.grouped_member_of(members[0]).unwrap();
    assert!(
        members
            .iter()
            .all(|&peer| manager.grouped_member_of(peer) == Some(old_gid))
    );
    if owned {
        manager
            .group_ribs
            .get_mut(&old_gid)
            .unwrap()
            .set_evpn_ownership_for_test(true);
        for &peer in &members {
            assert!(manager.register_evpn_recovery(peer, false));
        }
    }
    let routes: Vec<_> = (1..=rows).map(evpn_row).collect();
    let source = routes[0].peer;
    manager.ribs.insert(source, AdjRibIn::new(source));
    manager.process_evpn_announce_chunk(source, routes);
    let next = community_chain(TAGGED);
    if owned {
        // Prepare the owned destination the way the fleet regression does.
        let first = members[0];
        let previous = manager.export_chains.get(&first).cloned();
        manager.export_chains.insert(first, Some(next.clone()));
        let GroupMembership::Grouped(destination) = manager.compute_update_group_membership(first)
        else {
            panic!("groupable destination");
        };
        manager.ensure_group_table(destination, first);
        manager
            .group_ribs
            .get_mut(&destination)
            .unwrap()
            .set_evpn_ownership_for_test(true);
        let keys: HashSet<_> = (1..=rows).map(|tag| evpn_row(tag).key()).collect();
        manager.stage_group_evpn_keys(destination, &keys);
        match previous {
            Some(previous) => manager.export_chains.insert(first, previous),
            None => manager.export_chains.remove(&first),
        }
    }
    for (peer, output) in members.iter().zip(&mut outputs) {
        let mut rows_seen = 0;
        while let Ok(update) = output.try_recv() {
            rows_seen += update.evpn_announce.len();
        }
        assert_eq!(rows_seen, rows as usize, "{peer} initial table");
    }
    Fleet {
        manager,
        members,
        outputs,
        source,
        next,
    }
}

#[derive(Clone)]
enum Event {
    Announce(EvpnRibRoute),
    Withdraw,
}

type KeyEvents = HashMap<EvpnRouteKey, Vec<Event>>;

/// Per receiver, every key's ordered EVPN announce/withdraw sequence.
fn drain_events(outputs: &mut [mpsc::Receiver<OutboundRouteUpdate>]) -> Vec<KeyEvents> {
    outputs
        .iter_mut()
        .map(|output| {
            let mut events = KeyEvents::new();
            while let Ok(update) = output.try_recv() {
                for key in &update.evpn_withdraw {
                    events.entry(*key).or_default().push(Event::Withdraw);
                }
                for route in update.evpn_announce.iter() {
                    events
                        .entry(route.key())
                        .or_default()
                        .push(Event::Announce(route.clone()));
                }
            }
            events
        })
        .collect()
}

fn same_sequence(left: &[Event], right: &[Event]) -> bool {
    left.len() == right.len()
        && left.iter().zip(right).all(|pair| match pair {
            (Event::Announce(a), Event::Announce(b)) => evpn_routes_equal(a, b),
            (Event::Withdraw, Event::Withdraw) => true,
            _ => false,
        })
}

/// Final per-key state: the last announced route, or absent.
fn end_state(events: &KeyEvents) -> HashMap<EvpnRouteKey, EvpnRibRoute> {
    events
        .iter()
        .filter_map(|(key, sequence)| match sequence.last() {
            Some(Event::Announce(route)) => Some((*key, route.clone())),
            _ => None,
        })
        .collect()
}

fn assert_same_end_state(left: &KeyEvents, right: &KeyEvents, context: &str) {
    let (left, right) = (end_state(left), end_state(right));
    assert_eq!(
        left.keys().collect::<HashSet<_>>(),
        right.keys().collect::<HashSet<_>>(),
        "{context}: final key set"
    );
    for (key, route) in &left {
        assert!(evpn_routes_equal(route, &right[key]), "{context}: {key:?}");
    }
}

/// An estimate under which the budget admits exactly two members: the second
/// is predicted at `elapsed + 100 + 100` ms, the third at `elapsed + 200 +
/// 100` ms, against the 250 ms budget.
const TWO_PER_COMMAND: PacedMemberCost = PacedMemberCost {
    recompute: Span::ZERO,
    pass_share: Span::from_millis(100),
};

/// An estimate under which only the always-admitted first member fits.
const ONE_PER_COMMAND: PacedMemberCost = PacedMemberCost {
    recompute: Span::from_millis(200),
    pass_share: Span::from_millis(100),
};

/// Paced (batch, then paced commands of two members, with a source route
/// chunk after every command) emits, per receiver and key, exactly the
/// per-peer reference sequence under the same interleaving, and ends where
/// the whole synchronous batch ends.
#[test]
fn paced_reload_matches_the_per_peer_reference_with_route_chunks_between_steps() {
    for owned in [false, true] {
        let mut paced = evpn_fleet(4, 6, owned);
        let before: Vec<_> = paced
            .members
            .iter()
            .map(|peer| paced.manager.export_chains.get(peer).cloned())
            .collect();
        let deferred = paced.batch();
        assert_eq!(deferred, paced.members, "owned={owned}: caller order");
        let after: Vec<_> = paced
            .members
            .iter()
            .map(|peer| paced.manager.export_chains.get(peer).cloned())
            .collect();
        assert_eq!(after, before, "owned={owned}: deferred chains untouched");
        // At most two members per command (windows 1, 2, 4), then a source
        // route chunk. A chunk follows every command: before the first member
        // joins it, the owned arm's hand-prepared destination is memberless
        // and not maintained, which production never leaves behind.
        let mut round = 0;
        let per_command = paced.walk(deferred, Some(TWO_PER_COMMAND), |fleet, _| {
            fleet.churn(round);
            round += 1;
        });
        assert_eq!(per_command, [1, 2, 1], "owned={owned}");

        let mut reference = evpn_fleet(4, 6, owned);
        let members = reference.members.clone();
        for (round, group) in (0..).zip([&members[..1], &members[1..3], &members[3..]]) {
            for &peer in group {
                reference.step(peer).unwrap();
            }
            reference.churn(round);
        }

        let mut whole = evpn_fleet(4, 6, owned);
        let replacements = whole.replacements();
        whole
            .manager
            .apply_export_policy_replacements_synchronously(replacements)
            .unwrap();
        for round in 0..3 {
            whole.churn(round);
        }

        for fleet in [&mut paced, &mut reference, &mut whole] {
            fleet.manager.resync_dirty_peers_bounded();
            for &peer in &fleet.members {
                fleet.manager.settle_eor_now(peer);
                assert_eq!(
                    fleet.manager.export_chains.get(&peer),
                    Some(&Some(fleet.next.clone()))
                );
            }
        }
        let paced_events = drain_events(&mut paced.outputs);
        let reference_events = drain_events(&mut reference.outputs);
        let whole_events = drain_events(&mut whole.outputs);
        for (receiver, (paced, reference)) in paced_events.iter().zip(&reference_events).enumerate()
        {
            assert_eq!(
                paced.keys().collect::<HashSet<_>>(),
                reference.keys().collect::<HashSet<_>>(),
                "owned={owned} receiver {receiver}: keys"
            );
            for (key, sequence) in paced {
                assert!(
                    same_sequence(sequence, &reference[key]),
                    "owned={owned} receiver {receiver} key {key:?}: per-key sequence differs"
                );
            }
            assert_same_end_state(paced, &whole_events[receiver], "paced vs whole batch");
            let final_rows = end_state(paced);
            assert_eq!(
                final_rows.len(),
                6,
                "owned={owned}: each chunk announces one row and withdraws one"
            );
            assert!(
                final_rows
                    .values()
                    .all(|route| route.communities().contains(&TAGGED)),
                "owned={owned} receiver {receiver}: every row carries the new policy"
            );
        }
    }
}

/// A deferred member that leaves mid-walk is `NotFound` (the walk skips it).
/// A member that reconnects mid-walk registers with its session's chain,
/// which the cohort hot-applied before the RIB batch: it comes back with the
/// new chain and its own command is a no-op. Were it to come back with the
/// old chain, its command still installs the new one.
#[test]
fn deferred_member_that_flaps_mid_walk_is_skipped_or_converges_to_the_new_chain() {
    let mut fleet = evpn_fleet(3, 4, false);
    let deferred = fleet.batch();
    assert_eq!(deferred, fleet.members);
    drain_events(&mut fleet.outputs);
    let [gone, old_reconnect, new_reconnect] = [deferred[0], deferred[1], deferred[2]];

    fleet.manager.handle_update(RibUpdate::PeerDown {
        peer: gone,
        session_id: 7,
    });
    // A peer that left the RIB comes back in `skipped`, neither applied nor
    // pending (the per-peer replacement answers `NotFound`).
    let outcome = fleet.paced(&[gone], None);
    assert_eq!(
        (outcome.applied, outcome.pending, outcome.skipped),
        (0, vec![], vec![gone]),
        "the departed peer is reported skipped"
    );
    assert!(matches!(
        fleet.step(gone),
        Err(RibCommandError::NotFound(_))
    ));

    for (peer, accepted) in [
        (old_reconnect, None),
        (new_reconnect, Some(fleet.next.clone())),
    ] {
        let index = fleet
            .members
            .iter()
            .position(|member| *member == peer)
            .unwrap();
        fleet.manager.handle_update(RibUpdate::PeerDown {
            peer,
            session_id: 7,
        });
        fleet.outputs[index] = peer_up(
            &mut fleet.manager,
            peer,
            8,
            evpn_families(),
            accepted.clone(),
        );
        let initial = end_state(&drain_events(std::slice::from_mut(&mut fleet.outputs[index]))[0]);
        assert_eq!(initial.len(), 4, "{peer}: initial table");
        let outcome = fleet.paced(&[peer], None);
        assert_eq!((outcome.applied, outcome.pending), (1, vec![]));
        assert_eq!(
            fleet.manager.export_chains.get(&peer),
            Some(&Some(fleet.next.clone())),
            "{peer}: the command installs the new chain"
        );
        if accepted.is_some() {
            assert!(
                initial
                    .values()
                    .all(|route| route.communities().contains(&TAGGED)),
                "{peer}: a reconnect carrying the accepted chain starts on the new policy"
            );
            fleet.manager.resync_dirty_peers_bounded();
            assert!(
                drain_events(std::slice::from_mut(&mut fleet.outputs[index]))[0].is_empty(),
                "{peer}: its own command is a no-op"
            );
            assert!(!fleet.manager.dirty_peers.contains(&peer));
        }
    }
}

/// A mixed reload: unicast-only members still move as one shared cohort
/// inside the batch, while every member that sends EVPN, including one that
/// also sends IPv4 unicast, is handed back and converges through the walk.
#[test]
fn mixed_reload_applies_the_unicast_cohort_inline_and_defers_evpn_members() {
    let mut fleet = evpn_fleet(1, 4, false);
    let evpn = fleet.members[0];
    let unicast: Vec<_> = (0..2)
        .map(|index| PeerId::from_addr(Ipv4Addr::new(198, 51, 100, 10 + index).into()))
        .collect();
    for &peer in &unicast {
        let output = peer_up(
            &mut fleet.manager,
            peer,
            7,
            vec![(Afi::Ipv4, Safi::Unicast)],
            None,
        );
        fleet.members.push(peer);
        fleet.outputs.push(output);
    }
    let mixed = PeerId::from_addr(Ipv4Addr::new(198, 51, 100, 20).into());
    let output = peer_up(
        &mut fleet.manager,
        mixed,
        7,
        vec![(Afi::Ipv4, Safi::Unicast), EVPN],
        None,
    );
    fleet.members.push(mixed);
    fleet.outputs.push(output);
    drain_events(&mut fleet.outputs);
    assert!(fleet.manager.adj_ribs_out[&mixed].evpn_len() > 0);
    let unicast_source = fleet.manager.grouped_member_of(unicast[0]);
    assert!(unicast_source.is_some());
    assert_eq!(fleet.manager.grouped_member_of(unicast[1]), unicast_source);

    let deferred = fleet.batch();
    assert_eq!(
        deferred,
        [evpn, mixed],
        "every EVPN sender, in caller order"
    );
    let receipt = fleet
        .manager
        .authoritative_transition_receipts
        .last()
        .unwrap();
    assert_eq!(receipt.deferred_members, 2);
    assert_eq!(
        receipt.shared_members, 2,
        "the unicast cohort shares one transition"
    );
    assert_eq!(receipt.fallback_members, 0);
    assert_eq!(receipt.classification, "paced");
    for &peer in &unicast {
        assert_eq!(
            fleet.manager.export_chains.get(&peer),
            Some(&Some(fleet.next.clone()))
        );
        assert_ne!(fleet.manager.grouped_member_of(peer), unicast_source);
    }
    assert_eq!(fleet.manager.export_chains.get(&evpn), Some(&None));

    // The budget splits the list after the EVPN-only member; each command
    // applies a caller-order prefix and the walk commits both, once.
    let per_command = fleet.walk(deferred, Some(ONE_PER_COMMAND), |fleet, applied| {
        for peer in applied {
            assert_eq!(
                fleet.manager.export_chains.get(peer),
                Some(&Some(fleet.next.clone()))
            );
        }
    });
    assert_eq!(per_command, [1, 1]);
    fleet.manager.resync_dirty_peers_bounded();
    for &peer in &fleet.members {
        fleet.manager.settle_eor_now(peer);
        assert_eq!(
            fleet.manager.export_chains.get(&peer),
            Some(&Some(fleet.next.clone()))
        );
    }
    let events = drain_events(&mut fleet.outputs);
    for (index, peer) in [(0, evpn), (3, mixed)] {
        assert_eq!(fleet.members[index], peer);
        let rows = end_state(&events[index]);
        assert_eq!(rows.len(), 4, "{peer}");
        assert!(
            rows.values()
                .all(|route| route.communities().contains(&TAGGED)),
            "{peer}: re-exported EVPN rows carry the new policy"
        );
        assert!(
            fleet.manager.adj_ribs_out[&peer]
                .iter_evpn()
                .all(|route| route.communities().contains(&TAGGED)),
            "{peer}: Adj-RIB-Out carries the new policy"
        );
        assert_eq!(fleet.manager.adj_ribs_out[&peer].evpn_len(), 4, "{peer}");
    }
}

/// The budget predicate: the first member always runs; later ones only with
/// an estimate, and only while the predicted turn stays within the budget,
/// counting the pass shares the applied members still owe.
#[test]
fn paced_budget_admits_exactly_while_the_predicted_turn_fits() {
    let ms = Span::from_millis;
    assert!(
        paced_admits_next(ms(10_000), 0, None),
        "the first member always runs"
    );
    assert!(
        !paced_admits_next(Span::ZERO, 1, None),
        "no estimate: one member"
    );
    let cost = PacedMemberCost {
        recompute: ms(30),
        pass_share: ms(50),
    };
    // elapsed + applied × pass_share + recompute + pass_share
    assert_eq!(PACED_TURN_BUDGET, ms(250));
    assert!(
        paced_admits_next(ms(70), 1, Some(cost)),
        "70 + 50 + 30 + 50 = 200"
    );
    assert!(
        paced_admits_next(ms(120), 1, Some(cost)),
        "120 + 50 + 30 + 50 = 250, at the budget"
    );
    assert!(!paced_admits_next(ms(121), 1, Some(cost)), "251 exceeds it");
    assert!(
        paced_admits_next(ms(70), 2, Some(cost)),
        "70 + 100 + 30 + 50 = 250"
    );
    assert!(
        !paced_admits_next(ms(71), 2, Some(cost)),
        "the owed pass share of each applied member counts"
    );
}

/// One paced command applies as many members as the estimate admits, in
/// caller order, through one distribution pass, and returns the rest with
/// their installed chains untouched.
#[test]
fn paced_command_applies_the_admitted_prefix_through_one_pass() {
    let mut fleet = evpn_fleet(6, 4, false);
    // An installed chain per member, so a member left pending can be checked
    // for its exact installed instance (its term-hit counters), not equality.
    let initial = community_chain(0xFC00_0002);
    for peer in fleet.members.clone() {
        let (reply, mut response) = oneshot::channel();
        fleet
            .manager
            .handle_update(RibUpdate::ReplacePeerExportPolicy {
                peer,
                export_policy: Some(initial.clone()),
                reply,
            });
        response.try_recv().unwrap().unwrap();
    }
    let counters = |fleet: &Fleet, peer: &PeerId| {
        Arc::clone(
            fleet
                .manager
                .export_chains
                .get(peer)
                .unwrap()
                .as_ref()
                .unwrap()
                .hit_counters(),
        )
    };
    let installed: HashMap<PeerId, _> = fleet
        .members
        .iter()
        .map(|peer| (*peer, counters(&fleet, peer)))
        .collect();
    let mut pending = fleet.batch();
    assert_eq!(pending, fleet.members);
    for (cost, expected) in [
        (None, 1),
        (Some(TWO_PER_COMMAND), 2),
        (Some(ONE_PER_COMMAND), 1),
        (Some(PacedMemberCost::default()), 2),
    ] {
        let passes = fleet.manager.adj_rib_out_commit_stats.metrics_handle_clones;
        let outcome = fleet.paced(&pending, cost);
        assert_eq!(outcome.applied, expected, "{cost:?}");
        assert_eq!(
            fleet.manager.adj_rib_out_commit_stats.metrics_handle_clones - passes,
            1,
            "{cost:?}: one distribution pass per command, not per member"
        );
        assert_eq!(
            outcome.pending[..],
            pending[expected..],
            "{cost:?}: the rest, in order"
        );
        for peer in &pending[..expected] {
            assert_eq!(
                fleet.manager.export_chains.get(peer),
                Some(&Some(fleet.next.clone()))
            );
        }
        for peer in &outcome.pending {
            assert!(
                Arc::ptr_eq(&counters(&fleet, peer), &installed[peer]),
                "{peer}: the installed chain instance, untouched"
            );
        }
        let receipt = fleet
            .manager
            .authoritative_transition_receipts
            .last()
            .unwrap();
        assert_eq!(
            (
                receipt.classification,
                receipt.applied_members,
                receipt.deferred_members,
                receipt.fallback_members
            ),
            ("paced_apply", expected, outcome.pending.len(), 0),
            "{cost:?}: paced members are not the fallback"
        );
        // The reply's estimate never shrinks below what came in.
        let reply = outcome.cost.expect("a resynced member gives an estimate");
        let incoming = cost.unwrap_or_default();
        assert!(reply.recompute >= incoming.recompute);
        assert!(reply.pass_share >= incoming.pass_share);
        pending = outcome.pending;
    }
    assert_eq!(pending, Vec::<PeerId>::new());
}

/// A list mixing members of two source groups (IPv4+EVPN and EVPN-only),
/// split by the budget mid-list: every member is applied exactly once, in
/// caller order, and ends on the new policy.
#[test]
fn paced_walk_split_mid_list_commits_every_member_once_and_in_order() {
    let mut fleet = evpn_fleet(3, 4, false);
    let evpn_only: Vec<_> = (0..2)
        .map(|index| PeerId::from_addr(Ipv4Addr::new(198, 51, 100, 40 + index).into()))
        .collect();
    for &peer in &evpn_only {
        let output = peer_up(&mut fleet.manager, peer, 7, vec![EVPN], None);
        fleet.outputs.push(output);
    }
    drain_events(&mut fleet.outputs);
    assert_ne!(
        fleet.manager.grouped_member_of(evpn_only[0]),
        fleet.manager.grouped_member_of(fleet.members[0]),
        "two source groups"
    );
    let order = vec![
        fleet.members[0],
        evpn_only[0],
        fleet.members[1],
        evpn_only[1],
        fleet.members[2],
    ];
    let mut all = fleet.members.clone();
    all.extend(&evpn_only);
    fleet.members = all;
    let (reply, mut response) = oneshot::channel();
    fleet
        .manager
        .handle_update(RibUpdate::ReplacePeerExportPoliciesAuthoritatively {
            replacements: order
                .iter()
                .map(|&peer| PeerExportPolicyReplacement {
                    peer,
                    export_policy: Some(fleet.next.clone()),
                })
                .collect(),
            reply,
        });
    let deferred = response.try_recv().unwrap().unwrap();
    assert_eq!(deferred, order, "caller order");
    let receipts = fleet.manager.authoritative_transition_receipts.len();
    let mut committed = Vec::new();
    let per_command = fleet.walk(deferred, Some(TWO_PER_COMMAND), |fleet, applied| {
        committed.extend_from_slice(applied);
        for peer in &order[committed.len()..] {
            assert_ne!(
                fleet.manager.export_chains.get(peer),
                Some(&Some(fleet.next.clone())),
                "{peer}: not yet applied"
            );
        }
    });
    assert_eq!(per_command, [1, 2, 2]);
    assert_eq!(committed, order, "each member once, in caller order");
    let applied: usize = fleet.manager.authoritative_transition_receipts[receipts..]
        .iter()
        .map(|receipt| receipt.applied_members)
        .sum();
    assert_eq!(applied, order.len(), "no member is applied twice");
    fleet.manager.resync_dirty_peers_bounded();
    for (index, events) in drain_events(&mut fleet.outputs).iter().enumerate() {
        let rows = end_state(events);
        assert_eq!(rows.len(), 4, "receiver {index}");
        assert!(
            rows.values()
                .all(|route| route.communities().contains(&TAGGED))
        );
    }
}

/// A pending member that re-registered as unicast-only would qualify for the
/// shared cohort transition; a paced command still applies it through the
/// budgeted per-member body, in caller order.
#[test]
fn paced_command_bypasses_the_shared_cohort_path() {
    let mut fleet = evpn_fleet(3, 4, false);
    let deferred = fleet.batch();
    let unicast = deferred[1];
    let index = fleet
        .members
        .iter()
        .position(|peer| *peer == unicast)
        .unwrap();
    fleet.manager.handle_update(RibUpdate::PeerDown {
        peer: unicast,
        session_id: 7,
    });
    fleet.outputs[index] = peer_up(
        &mut fleet.manager,
        unicast,
        8,
        vec![(Afi::Ipv4, Safi::Unicast)],
        None,
    );
    let source = fleet.manager.grouped_member_of(unicast);
    assert!(source.is_some());
    let outcome = fleet.paced(&deferred, Some(ONE_PER_COMMAND));
    assert_eq!(outcome.applied, 1);
    assert_eq!(outcome.pending, deferred[1..]);
    assert_eq!(
        fleet.manager.export_chains.get(&unicast),
        Some(&None),
        "the unicast-only member waits for its turn"
    );
    assert_eq!(fleet.manager.grouped_member_of(unicast), source);
    let outcome = fleet.paced(&outcome.pending, Some(ONE_PER_COMMAND));
    assert_eq!(outcome.applied, 1);
    assert_eq!(
        fleet.manager.export_chains.get(&unicast),
        Some(&Some(fleet.next.clone()))
    );
}

/// A duplicate peer rejects the whole paced command before any mutation, so
/// the walk rolls back instead of applying it unbudgeted.
#[test]
fn paced_command_rejects_duplicates_before_mutation() {
    let mut fleet = evpn_fleet(2, 4, false);
    let deferred = fleet.batch();
    let before = fleet.manager.export_chains.get(&deferred[0]).cloned();
    let (reply, mut response) = oneshot::channel();
    fleet
        .manager
        .handle_update(RibUpdate::ApplyPacedExportPolicies {
            replacements: [deferred[0], deferred[0]]
                .iter()
                .map(|&peer| PeerExportPolicyReplacement {
                    peer,
                    export_policy: Some(fleet.next.clone()),
                })
                .collect(),
            cost: None,
            reply,
        });
    assert!(matches!(
        response.try_recv().unwrap(),
        Err(RibCommandError::Internal(_))
    ));
    assert_eq!(
        fleet.manager.export_chains.get(&deferred[0]).cloned(),
        before
    );
}

/// A paced command whose caller has already gone (its deadline lapsed and
/// the rollback is queued behind) is skipped whole.
#[test]
fn paced_command_with_a_dropped_reply_is_skipped() {
    let mut fleet = evpn_fleet(2, 4, false);
    let deferred = fleet.batch();
    let before = fleet.manager.export_chains.get(&deferred[0]).cloned();
    let (reply, response) = oneshot::channel();
    drop(response);
    fleet
        .manager
        .handle_update(RibUpdate::ApplyPacedExportPolicies {
            replacements: vec![PeerExportPolicyReplacement {
                peer: deferred[0],
                export_policy: Some(fleet.next.clone()),
            }],
            cost: None,
            reply,
        });
    assert_eq!(
        fleet.manager.export_chains.get(&deferred[0]).cloned(),
        before
    );
}

/// IPv4 transport with IPv6-only configuration and no usable local IPv6
/// next hop registers with no sendable families; the session still exists.
fn empty_family_peer_up(
    manager: &mut RibManager,
    peer: PeerId,
    session_id: u64,
    chain: PolicyChain,
) -> mpsc::Receiver<OutboundRouteUpdate> {
    let (sender, receiver) = mpsc::channel(4096);
    let mut update = registering_peer_up(peer, session_id);
    let RibUpdate::PeerUp {
        outbound_tx,
        export_policy,
        ..
    } = &mut update
    else {
        unreachable!("PeerUp fixture");
    };
    *outbound_tx = sender;
    *export_policy = Some(chain);
    manager.handle_update(update);
    receiver
}

fn empty_family_fleet(rows: u32) -> Fleet {
    let (_tx, rx) = mpsc::channel(8);
    let mut manager = RibManager::new(
        rx,
        dummy_query_rx(),
        None,
        Some(Ipv4Addr::new(192, 0, 2, 254)),
        BgpMetrics::new(),
    );
    manager.flush_poll_budget = Duration::MAX;
    manager.paced_elapsed_for_test = Some(Duration::ZERO);
    let members: Vec<_> = (0..32).map(member).collect();
    let old = community_chain(0xFC00_0002);
    let outputs = members
        .iter()
        .map(|&peer| empty_family_peer_up(&mut manager, peer, 7, old.clone()))
        .collect();
    let source_addr = Ipv4Addr::new(198, 51, 100, 1);
    let source = peer_v4(source_addr);
    register_test_peer(&mut manager, source, 1);
    manager.handle_update(RibUpdate::RoutesReceived {
        peer: source,
        session_id: 1,
        announced: (0..rows)
            .map(|index| make_indexed_route(index, source_addr))
            .collect(),
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
        validated_with: None,
    });
    drain_route_chunks(&mut manager);
    assert_eq!(manager.loc_rib.len(), rows as usize);
    Fleet {
        manager,
        members,
        outputs,
        source,
        next: community_chain(TAGGED),
    }
}

fn empty_family_policy_work(moved: usize, restore: bool) -> (usize, usize, usize) {
    const ROWS: u32 = 128;
    let mut fleet = empty_family_fleet(ROWS);
    let members = fleet.members[..moved].to_vec();
    if restore {
        for &peer in &members {
            fleet.step(peer).unwrap();
        }
        fleet.next = community_chain(0xFC00_0002);
    }
    let visits = count_resync_rows(&mut fleet.manager);
    let replacements = members
        .iter()
        .map(|&peer| PeerExportPolicyReplacement {
            peer,
            export_policy: Some(fleet.next.clone()),
        })
        .collect();
    let mut pending = if restore {
        let (reply, mut response) = oneshot::channel();
        fleet
            .manager
            .handle_update(RibUpdate::RestorePeerExportPoliciesAuthoritatively {
                replacements,
                reply,
            });
        response
            .try_recv()
            .unwrap()
            .unwrap()
            .into_iter()
            .filter_map(|receipt| match receipt {
                PeerExportPolicyRestoreReceipt::Deferred { peer } => Some(peer),
                PeerExportPolicyRestoreReceipt::Restored { .. } => None,
                PeerExportPolicyRestoreReceipt::NotFound { .. } => panic!("registered member"),
            })
            .collect::<Vec<_>>()
    } else {
        let (reply, mut response) = oneshot::channel();
        fleet
            .manager
            .handle_update(RibUpdate::ReplacePeerExportPoliciesAuthoritatively {
                replacements,
                reply,
            });
        response.try_recv().unwrap().unwrap()
    };
    let batch_visits = visits.swap(0, Ordering::Relaxed);
    let (mut max_paced_visits, mut paced_commands) = (0, 0);
    while !pending.is_empty() {
        let replacements = pending
            .iter()
            .map(|&peer| PeerExportPolicyReplacement {
                peer,
                export_policy: Some(fleet.next.clone()),
            })
            .collect();
        let (reply, mut response) = oneshot::channel();
        let command = if restore {
            RibUpdate::RestorePacedExportPolicies {
                replacements,
                cost: Some(ONE_PER_COMMAND),
                reply,
            }
        } else {
            RibUpdate::ApplyPacedExportPolicies {
                replacements,
                cost: Some(ONE_PER_COMMAND),
                reply,
            }
        };
        fleet.manager.handle_update(command);
        let outcome = response.try_recv().unwrap().unwrap();
        assert_eq!(outcome.applied, 1);
        assert_eq!(outcome.skipped, Vec::<PeerId>::new());
        assert_eq!(outcome.pending, pending[1..]);
        pending = outcome.pending;
        max_paced_visits = max_paced_visits.max(visits.swap(0, Ordering::Relaxed));
        paced_commands += 1;
    }
    for &peer in &members {
        assert_eq!(fleet.manager.export_chains[&peer], Some(fleet.next.clone()));
    }
    assert_eq!(fleet.manager.loc_rib.len(), ROWS as usize);
    assert!(
        fleet
            .outputs
            .iter_mut()
            .all(|output| output.try_recv().is_err())
    );
    (batch_visits, max_paced_visits, paced_commands)
}

#[test]
fn empty_family_forward_policy_resync_row_work_is_flat_in_moved_members() {
    let counts: Vec<_> = [8, 32]
        .into_iter()
        .map(|moved| (moved, empty_family_policy_work(moved, false)))
        .collect();
    eprintln!("empty-family forward (members, (batch rows, max paced rows, commands)): {counts:?}");
    assert_eq!(counts, vec![(8, (0, 128, 8)), (32, (0, 128, 32))]);
}

#[test]
fn empty_family_restore_policy_resync_row_work_is_flat_in_moved_members() {
    let counts: Vec<_> = [8, 32]
        .into_iter()
        .map(|moved| (moved, empty_family_policy_work(moved, true)))
        .collect();
    eprintln!("empty-family restore (members, (batch rows, max paced rows, commands)): {counts:?}");
    assert_eq!(counts, vec![(8, (0, 128, 8)), (32, (0, 128, 32))]);
}

/// Counts Loc-RIB keys enumerated by resyncs. The drained-writer fixture
/// isolates changed residuals; group builds and member metadata are outside
/// this counter. It does not bound a whole actor turn.
fn count_resync_rows(manager: &mut RibManager) -> Arc<AtomicUsize> {
    let visits = Arc::new(AtomicUsize::new(0));
    manager.replacement_readiness_test_hook = Some(Arc::new({
        let visits = Arc::clone(&visits);
        move |stage| {
            if stage == "resync_loc_rib_key" {
                visits.fetch_add(1, Ordering::Relaxed);
            }
        }
    }));
    visits
}

#[test]
fn empty_family_unchanged_and_missing_members_avoid_resync() {
    let mut fleet = empty_family_fleet(4);
    let peer = fleet.members[0];
    let old = fleet.manager.export_chains[&peer].as_ref().unwrap();
    let installed = Arc::clone(old.hit_counters());
    let old = old.clone();
    let missing = peer_v4(Ipv4Addr::new(192, 0, 2, 250));
    let replacements = vec![
        PeerExportPolicyReplacement {
            peer,
            export_policy: Some(old),
        },
        PeerExportPolicyReplacement {
            peer: missing,
            export_policy: Some(fleet.next.clone()),
        },
    ];
    let visits = count_resync_rows(&mut fleet.manager);
    let (reply, mut response) = oneshot::channel();
    fleet
        .manager
        .handle_update(RibUpdate::ReplacePeerExportPoliciesAuthoritatively {
            replacements: replacements.clone(),
            reply,
        });
    assert_eq!(response.try_recv().unwrap().unwrap(), Vec::<PeerId>::new());
    let (reply, mut response) = oneshot::channel();
    fleet
        .manager
        .handle_update(RibUpdate::RestorePeerExportPoliciesAuthoritatively {
            replacements,
            reply,
        });
    assert_eq!(
        response.try_recv().unwrap().unwrap(),
        vec![
            PeerExportPolicyRestoreReceipt::NotFound { peer: missing },
            PeerExportPolicyRestoreReceipt::Restored { peer },
        ]
    );
    assert_eq!(visits.load(Ordering::Relaxed), 0);
    assert!(Arc::ptr_eq(
        &installed,
        fleet.manager.export_chains[&peer]
            .as_ref()
            .unwrap()
            .hit_counters()
    ));
    assert!(!fleet.manager.export_chains.contains_key(&missing));
}

#[test]
fn empty_family_member_unlocks_between_batch_and_paced_apply() {
    let mut fleet = empty_family_fleet(4);
    let peer = fleet.members[0];
    let prefix = Ipv6Prefix::new("2001:db8:1::".parse().unwrap(), 48);
    let mut route = make_v6_route(prefix, "2001:db8::1".parse().unwrap());
    set_peer(&mut route, fleet.source);
    fleet.manager.handle_update(RibUpdate::RoutesReceived {
        peer: fleet.source,
        session_id: 1,
        announced: vec![route],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
        validated_with: None,
    });
    drain_route_chunks(&mut fleet.manager);
    let old = fleet.manager.export_chains[&peer].clone();
    let (reply, mut response) = oneshot::channel();
    fleet
        .manager
        .handle_update(RibUpdate::ReplacePeerExportPoliciesAuthoritatively {
            replacements: vec![PeerExportPolicyReplacement {
                peer,
                export_policy: Some(fleet.next.clone()),
            }],
            reply,
        });
    assert_eq!(response.try_recv().unwrap().unwrap(), [peer]);
    assert_eq!(fleet.manager.export_chains[&peer], old);
    fleet.manager.handle_update(RibUpdate::PeerFamilySendable {
        peer,
        session_id: 7,
        family: (Afi::Ipv6, Safi::Unicast),
        add_path_send_limit: None,
    });
    let before: Vec<_> =
        std::iter::from_fn(|| fleet.outputs[0].try_recv().map(delivered).ok()).collect();
    assert!(
        before
            .iter()
            .flat_map(|update| update.announce.iter())
            .any(|route| {
                route.prefix == Prefix::V6(prefix) && route.communities().contains(&0xFC00_0002)
            })
    );
    let outcome = fleet.paced(&[peer], Some(ONE_PER_COMMAND));
    assert_eq!(outcome.applied, 1);
    assert_eq!(outcome.pending, Vec::<PeerId>::new());
    let after: Vec<_> =
        std::iter::from_fn(|| fleet.outputs[0].try_recv().map(delivered).ok()).collect();
    assert!(
        after
            .iter()
            .flat_map(|update| update.announce.iter())
            .any(|route| {
                route.prefix == Prefix::V6(prefix) && route.communities().contains(&TAGGED)
            })
    );
    assert_eq!(fleet.manager.export_chains[&peer], Some(fleet.next.clone()));
}

#[test]
fn empty_family_deferred_restore_handles_departure_and_replacement() {
    for reconnect in [false, true] {
        let mut fleet = empty_family_fleet(4);
        let peer = fleet.members[0];
        let prior = fleet.manager.export_chains[&peer].clone();
        fleet.step(peer).unwrap();
        let replacements = vec![PeerExportPolicyReplacement {
            peer,
            export_policy: prior.clone(),
        }];
        let (reply, mut response) = oneshot::channel();
        fleet
            .manager
            .handle_update(RibUpdate::RestorePeerExportPoliciesAuthoritatively {
                replacements: replacements.clone(),
                reply,
            });
        assert_eq!(
            response.try_recv().unwrap().unwrap(),
            [PeerExportPolicyRestoreReceipt::Deferred { peer }]
        );
        fleet.manager.handle_update(RibUpdate::PeerDown {
            peer,
            session_id: 7,
        });
        if reconnect {
            fleet.outputs[0] =
                empty_family_peer_up(&mut fleet.manager, peer, 8, fleet.next.clone());
        }
        let (reply, mut response) = oneshot::channel();
        fleet
            .manager
            .handle_update(RibUpdate::RestorePacedExportPolicies {
                replacements,
                cost: Some(ONE_PER_COMMAND),
                reply,
            });
        let outcome = response.try_recv().unwrap().unwrap();
        assert_eq!(outcome.pending, Vec::<PeerId>::new());
        if reconnect {
            assert_eq!(outcome.applied, 1);
            assert_eq!(outcome.skipped, Vec::<PeerId>::new());
            assert_eq!(fleet.manager.export_chains[&peer], prior);
            assert_eq!(fleet.manager.current_session_id(peer), Some(8));
        } else {
            assert_eq!(outcome.applied, 0);
            assert_eq!(outcome.skipped, [peer]);
            assert!(!fleet.manager.export_chains.contains_key(&peer));
        }
    }
}

/// Loc-RIB EVPN keys enumerated into resync key sets while every member of a
/// fleet holding `ROWS` rows is regrouped, one member per paced command.
fn resync_evpn_key_work(moved: usize, owned: bool) -> usize {
    const ROWS: u32 = 16;
    let mut fleet = evpn_fleet(moved, ROWS, owned);
    let visits = Arc::new(AtomicUsize::new(0));
    fleet.manager.replacement_readiness_test_hook = Some(Arc::new({
        let visits = Arc::clone(&visits);
        move |stage| {
            if stage == "resync_evpn_key" {
                visits.fetch_add(1, Ordering::Relaxed);
            }
        }
    }));
    let deferred = fleet.batch();
    assert_eq!(deferred, fleet.members);
    let per_command = fleet.walk(deferred, Some(ONE_PER_COMMAND), |_, _| {});
    assert_eq!(per_command, vec![1; moved]);
    assert!(
        fleet.manager.dirty_peers.is_empty(),
        "every resync committed"
    );
    for (index, events) in drain_events(&mut fleet.outputs).iter().enumerate() {
        let rows = end_state(events);
        assert_eq!(rows.len(), ROWS as usize, "receiver {index}");
        assert!(
            rows.values()
                .all(|route| route.communities().contains(&TAGGED)),
            "receiver {index} holds the new chain's rows"
        );
    }
    visits.load(Ordering::Relaxed)
}

/// A group-owned member's resync stages EVPN from its complete feed, so it
/// enumerates no Loc-RIB EVPN key; a private member's resync enumerates the
/// table once. Neither grows with the members moved before it.
#[test]
fn owned_member_resync_enumerates_no_evpn_key() {
    let counts: Vec<_> = [8, 32]
        .into_iter()
        .map(|moved| {
            (
                moved,
                resync_evpn_key_work(moved, true),
                resync_evpn_key_work(moved, false),
            )
        })
        .collect();
    eprintln!("resync EVPN keys (members, owned, private): {counts:?}");
    assert_eq!(counts, vec![(8, 0, 8 * 16), (32, 0, 32 * 16)]);
}

/// The resync of a group-owned member builds no EVPN key set, but a table
/// that holds EVPN rows is still not an empty resync. When the member's
/// complete feed cannot be sealed, the resync sends nothing and keeps its
/// duty: a dirty member is not taken off the dirty list and re-marked, which
/// would restart its dirty age, and a forced replay keeps its request.
#[test]
fn owned_member_resync_without_a_feed_is_not_an_empty_resync() {
    for forced in [false, true] {
        let mut fleet = evpn_fleet(2, 4, true);
        let peer = fleet.members[0];
        let gid = fleet.manager.evpn_grouped_member_of(peer).unwrap();
        if forced {
            fleet.manager.force_outbound_peers.insert(peer);
        } else {
            assert!(fleet.manager.mark_outbound_dirty(peer));
        }
        let dirty_since = fleet.manager.dirty_since.get(&peer).copied();
        // No feed can be sealed against an unstamped table.
        fleet
            .manager
            .group_ribs
            .get_mut(&gid)
            .unwrap()
            .evpn_table_stamp = 0;
        fleet.manager.distribute_resync_request();
        if forced {
            assert!(
                fleet.manager.force_outbound_peers.contains(&peer),
                "the forced replay was not delivered"
            );
        } else {
            assert!(fleet.manager.dirty_peers.contains(&peer));
            assert_eq!(
                fleet.manager.dirty_since.get(&peer).copied(),
                dirty_since,
                "the member stayed dirty throughout"
            );
        }
        assert!(
            fleet.outputs[0].try_recv().is_err(),
            "forced={forced}: nothing was sent"
        );
    }
}
