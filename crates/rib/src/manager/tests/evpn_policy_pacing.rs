//! An export-policy reload that moves peers carrying EVPN outbound state is
//! paced: the authoritative batch hands those members back unapplied, with
//! their installed chain untouched, and each is applied by its own per-peer
//! command so other RIB work runs between their whole-table resyncs.

use super::evpn_group_storage::received;
use super::update_groups::community_chain;
use super::*;
use crate::PeerId;
use crate::manager::helpers::evpn_routes_equal;
use crate::manager::update_groups::GroupMembership;
use crate::update::{PeerExportPolicyReplacement, RibCommandError};
use rustbgpd_wire::{EthernetTagId, EvpnRouteKey};

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

    /// One step of the peer manager's walk.
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

/// Paced (batch, then one per-peer command each, with a source route chunk
/// before every command) emits, per receiver and key, exactly the per-peer
/// reference sequence under the same interleaving, and ends where the whole
/// synchronous batch ends.
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
        // A chunk follows every step: before the first member joins it, the
        // owned arm's hand-prepared destination is memberless and not
        // maintained, which production never leaves behind.
        for (round, peer) in (0..).zip(deferred) {
            paced.step(peer).unwrap();
            paced.churn(round);
        }

        let mut reference = evpn_fleet(4, 6, owned);
        for (round, peer) in (0..).zip(reference.members.clone()) {
            reference.step(peer).unwrap();
            reference.churn(round);
        }

        let mut whole = evpn_fleet(4, 6, owned);
        let replacements = whole.replacements();
        whole
            .manager
            .apply_export_policy_replacements_synchronously(replacements)
            .unwrap();
        for round in 0..4 {
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
                "owned={owned}: 6 + 4 announced - 4 withdrawn"
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
        fleet.step(peer).unwrap();
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
/// inside the batch, while the EVPN-carrying member is handed back. A member
/// with IPv4 unicast plus private EVPN rows may take either path today; the
/// walk converges it either way.
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
    assert!(deferred.contains(&evpn), "{deferred:?}");
    assert!(
        deferred.iter().all(|peer| *peer == evpn || *peer == mixed),
        "{deferred:?}"
    );
    let receipt = fleet
        .manager
        .authoritative_transition_receipts
        .last()
        .unwrap();
    assert_eq!(receipt.deferred_members, deferred.len());
    assert!(
        receipt.shared_members >= 2,
        "the unicast cohort shares one transition"
    );
    for &peer in &unicast {
        assert_eq!(
            fleet.manager.export_chains.get(&peer),
            Some(&Some(fleet.next.clone()))
        );
        assert_ne!(fleet.manager.grouped_member_of(peer), unicast_source);
    }
    assert_eq!(fleet.manager.export_chains.get(&evpn), Some(&None));

    for peer in deferred {
        fleet.step(peer).unwrap();
    }
    fleet.manager.resync_dirty_peers_bounded();
    for &peer in &fleet.members {
        fleet.manager.settle_eor_now(peer);
        assert_eq!(
            fleet.manager.export_chains.get(&peer),
            Some(&Some(fleet.next.clone()))
        );
    }
    let events = drain_events(&mut fleet.outputs);
    let rows = end_state(&events[0]);
    assert_eq!(rows.len(), 4);
    assert!(
        rows.values()
            .all(|route| route.communities().contains(&TAGGED))
    );
}
