//! Outbound unicast prefix accounting (ADR-0113).
//!
//! Two layers: the pure per-family batch helper, and the export seam that
//! feeds it. Nothing outside these tests configures a limit, so the seam
//! tests also pin the unlimited path that every peer takes today.

use std::collections::HashSet;
use std::num::NonZeroU32;

use super::*;
use crate::manager::outbound_prefix_limits::{BatchAdmission, admit_batch};

fn v4(octet: u8) -> Prefix {
    Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, octet), 32))
}

fn limit(n: u32) -> NonZeroU32 {
    NonZeroU32::new(n).expect("test limits are non-zero")
}

// --- pure batch admission ---

/// Load-bearing break: admitting unconditionally lets the third prefix
/// through; counting the whole batch against the cap blocks the first two.
#[test]
fn net_new_prefixes_past_the_cap_are_blocked_and_the_rest_pass() {
    let announced = [v4(1), v4(2), v4(3)];
    let verdict = admit_batch(limit(2), 0, &HashSet::new(), &announced, |_| false);
    assert_eq!(
        verdict,
        BatchAdmission {
            admitted: HashSet::from([v4(1), v4(2)]),
            blocked: HashSet::from([v4(3)]),
        }
    );
}

/// Load-bearing break: gating announcements for already-admitted prefixes
/// (an attribute change or an extra path identity) blocks them at the cap.
#[test]
fn announcements_for_admitted_prefixes_pass_at_the_cap() {
    let admitted = HashSet::from([v4(1), v4(2)]);
    let announced = [v4(1), v4(2)];
    let verdict = admit_batch(limit(2), 2, &HashSet::new(), &announced, |prefix| {
        admitted.contains(prefix)
    });
    assert_eq!(verdict, BatchAdmission::default());
}

/// Load-bearing break: evaluating announcements before withdrawals blocks
/// the new prefix even though the batch is net-neutral at the cap.
#[test]
fn a_withdrawal_frees_its_slot_before_announcements_are_considered() {
    let admitted = HashSet::from([v4(1), v4(2)]);
    let freed = HashSet::from([v4(1)]);
    let announced = [v4(3)];
    let verdict = admit_batch(limit(2), 2, &freed, &announced, |prefix| {
        admitted.contains(prefix)
    });
    assert_eq!(
        verdict,
        BatchAdmission {
            admitted: HashSet::from([v4(3)]),
            blocked: HashSet::new(),
        }
    );
}

/// Load-bearing break: counting route identities instead of prefixes spends
/// one slot per path and blocks the second and third identities.
#[test]
fn every_path_identity_for_one_prefix_shares_a_single_slot() {
    // Three RFC 7911 identities for one NLRI, none advertised yet.
    let announced = [v4(1), v4(1), v4(1)];
    let verdict = admit_batch(limit(1), 0, &HashSet::new(), &announced, |_| false);
    assert_eq!(
        verdict,
        BatchAdmission {
            admitted: HashSet::from([v4(1)]),
            blocked: HashSet::new(),
        }
    );
}

/// A prefix whose last path leaves and which the same batch re-announces is
/// net-new again: it takes the slot its own withdrawal freed.
#[test]
fn a_freed_prefix_reannounced_in_the_same_batch_retakes_its_slot() {
    let admitted = HashSet::from([v4(1)]);
    let freed = HashSet::from([v4(1)]);
    let announced = [v4(1)];
    let verdict = admit_batch(limit(1), 1, &freed, &announced, |prefix| {
        admitted.contains(prefix)
    });
    assert_eq!(
        verdict,
        BatchAdmission {
            admitted: HashSet::from([v4(1)]),
            blocked: HashSet::new(),
        }
    );
}

// --- export seam ---

fn register_peer(manager: &mut RibManager, peer: IpAddr) -> mpsc::Receiver<OutboundRouteUpdate> {
    let (outbound_tx, mut outbound_rx) = mpsc::channel(64);
    manager.handle_update(RibUpdate::PeerUp {
        peer,
        session_id: 0,
        peer_asn: 65_000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: false,
        route_reflector_client: false,
        orr_vantage: None,
        per_client_best: false,
        interpret_rfc1997: true,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: vec![],
        negotiated_llgr_families: vec![],
    });
    let eor = outbound_rx.try_recv().expect("registration end-of-rib");
    assert_eq!(eor.end_of_rib, ipv4_sendable());
    outbound_rx
}

fn set_ipv4_limit(manager: &mut RibManager, peer: IpAddr, cap: u32) {
    manager
        .outbound_prefix_limits
        .entry(peer)
        .or_default()
        .family_mut(Afi::Ipv4)
        .expect("IPv4 unicast is a limited family")
        .limit = Some(limit(cap));
}

fn announce(manager: &mut RibManager, source: IpAddr, announced: Vec<Route>) {
    manager.handle_update(RibUpdate::RoutesReceived {
        peer: source,
        session_id: 0,
        announced,
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    });
    while manager.process_next_route_chunk() {}
}

fn withdraw(manager: &mut RibManager, source: IpAddr, withdrawn: Vec<(Prefix, u32)>) {
    manager.handle_update(RibUpdate::RoutesReceived {
        peer: source,
        session_id: 0,
        announced: vec![],
        withdrawn,
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    });
    while manager.process_next_route_chunk() {}
}

/// Prefixes the peer's envelopes leave advertised, i.e. announced and not
/// later withdrawn.
fn wire_prefixes(outbound_rx: &mut mpsc::Receiver<OutboundRouteUpdate>) -> HashSet<Prefix> {
    let mut advertised = HashSet::new();
    while let Ok(update) = outbound_rx.try_recv() {
        for route in update.announce.iter() {
            advertised.insert(route.prefix);
        }
        for (prefix, _) in &update.withdraw {
            advertised.remove(prefix);
        }
    }
    advertised
}

fn source_routes(source: Ipv4Addr, octets: &[u8]) -> Vec<Route> {
    octets
        .iter()
        .map(|octet| {
            crate::test_support::make_route(
                Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, *octet), 32),
                source,
            )
        })
        .collect()
}

/// Inertness: with no limit configured — the state of every peer today —
/// the export path advertises exactly what it advertised before this
/// accounting existed, and allocates no admission state.
#[test]
fn an_unlimited_peer_admits_every_prefix_and_allocates_no_admission_state() {
    let (_tx, rx) = mpsc::channel(1);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    manager.test_force_ungrouped = true;
    let peer = IpAddr::V4(Ipv4Addr::new(10, 113, 0, 1));
    let mut outbound_rx = register_peer(&mut manager, peer);

    let source = Ipv4Addr::new(192, 0, 2, 113);
    announce(
        &mut manager,
        IpAddr::V4(source),
        source_routes(source, &[1, 2, 3]),
    );

    assert_eq!(
        wire_prefixes(&mut outbound_rx),
        HashSet::from([v4(1), v4(2), v4(3)])
    );
    assert_eq!(
        manager.adj_ribs_out.get(&peer).map_or(0, AdjRibOut::len),
        3,
        "the unlimited path must commit every advertised route"
    );
    assert!(
        manager.outbound_prefix_limits.is_empty(),
        "an unlimited peer must not allocate per-peer admission state"
    );
}

/// Load-bearing break: dropping the enforcement call from the commit seam
/// puts all three prefixes on the wire and in Adj-RIB-Out.
#[test]
fn an_ungrouped_peer_at_its_cap_blocks_the_excess_prefix() {
    let (_tx, rx) = mpsc::channel(1);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    manager.test_force_ungrouped = true;
    let peer = IpAddr::V4(Ipv4Addr::new(10, 113, 0, 1));
    let mut outbound_rx = register_peer(&mut manager, peer);
    set_ipv4_limit(&mut manager, peer, 2);

    let source = Ipv4Addr::new(192, 0, 2, 113);
    announce(
        &mut manager,
        IpAddr::V4(source),
        source_routes(source, &[1, 2, 3]),
    );

    let advertised = wire_prefixes(&mut outbound_rx);
    assert_eq!(advertised.len(), 2, "only the cap may reach the wire");
    let committed: HashSet<Prefix> = manager
        .adj_ribs_out
        .get(&peer)
        .expect("a limited ungrouped peer keeps its private Adj-RIB-Out")
        .iter()
        .map(|route| route.prefix)
        .collect();
    assert_eq!(
        committed, advertised,
        "a blocked prefix must never enter Adj-RIB-Out"
    );
    assert!(
        manager
            .outbound_prefix_limits
            .get(&peer)
            .and_then(|limits| limits.family(Afi::Ipv4))
            .is_some_and(|family| family.blocking),
        "blocking a net-new prefix opens the family's episode"
    );
}

/// A withdrawal at the cap frees its slot, and the freed capacity is
/// re-offered to intent the limiter previously blocked — without an
/// inventory of blocked prefixes.
#[test]
fn freed_capacity_readmits_previously_blocked_intent() {
    let (_tx, rx) = mpsc::channel(1);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    manager.test_force_ungrouped = true;
    let peer = IpAddr::V4(Ipv4Addr::new(10, 113, 0, 1));
    let mut outbound_rx = register_peer(&mut manager, peer);
    set_ipv4_limit(&mut manager, peer, 2);

    let source = Ipv4Addr::new(192, 0, 2, 113);
    announce(
        &mut manager,
        IpAddr::V4(source),
        source_routes(source, &[1, 2, 3]),
    );
    let advertised = wire_prefixes(&mut outbound_rx);
    assert_eq!(advertised.len(), 2);
    let blocked = *[v4(1), v4(2), v4(3)]
        .iter()
        .find(|prefix| !advertised.contains(prefix))
        .expect("one prefix is over the cap");
    let admitted = *advertised.iter().next().expect("the cap admitted two");

    // Withdrawing an admitted prefix frees exactly one slot and schedules the
    // peer's export resync, which re-derives the blocked prefix from current
    // Loc-RIB intent.
    withdraw(&mut manager, IpAddr::V4(source), vec![(admitted, 0)]);
    assert!(
        manager.dirty_peers.contains(&peer),
        "freed capacity during an episode must schedule a recovery resync"
    );
    while manager.resync_dirty_peers_bounded() {}

    let recovered = wire_prefixes(&mut outbound_rx);
    assert!(
        recovered.contains(&blocked),
        "the freed slot must go to previously blocked intent"
    );
    assert_eq!(
        manager
            .adj_ribs_out
            .get(&peer)
            .map_or(0, |rib| rib.unicast_prefix_count(Afi::Ipv4)),
        2,
        "recovery must not exceed the cap"
    );
}

/// One limited member must not fragment its update group: the sibling keeps
/// the shared payload and both stay in the same group.
///
/// Load-bearing break: putting the limit in `GroupKey`, or filtering the
/// shared payload instead of the member's final vector, changes the
/// sibling's advertised set or splits the group.
#[test]
fn a_limited_group_member_blocks_alone() {
    let (_tx, rx) = mpsc::channel(1);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let limited = IpAddr::V4(Ipv4Addr::new(10, 113, 0, 1));
    let sibling = IpAddr::V4(Ipv4Addr::new(10, 113, 0, 2));
    let mut limited_rx = register_peer(&mut manager, limited);
    let mut sibling_rx = register_peer(&mut manager, sibling);
    set_ipv4_limit(&mut manager, limited, 2);

    let source = Ipv4Addr::new(192, 0, 2, 113);
    announce(
        &mut manager,
        IpAddr::V4(source),
        source_routes(source, &[1, 2, 3]),
    );

    let group = manager.grouped_member_of(limited);
    assert!(
        group.is_some(),
        "the fixture must exercise the grouped path"
    );
    assert_eq!(
        group,
        manager.grouped_member_of(sibling),
        "a limit must not split the update group"
    );
    assert_eq!(
        wire_prefixes(&mut sibling_rx),
        HashSet::from([v4(1), v4(2), v4(3)]),
        "an unlimited sibling keeps the full shared payload"
    );
    let advertised = wire_prefixes(&mut limited_rx);
    assert_eq!(
        advertised.len(),
        2,
        "only the cap reaches the limited member"
    );
    assert_eq!(
        manager
            .outbound_prefix_limits
            .get(&limited)
            .and_then(|limits| limits.family(Afi::Ipv4))
            .map(|family| family.grouped_admitted.clone()),
        Some(advertised),
        "the member's bounded admitted set is its advertised projection"
    );
}

/// Admission is per session generation: teardown reaps it on the same seam
/// as the rest of the peer's outbound state.
#[test]
fn peer_teardown_clears_admission_state() {
    let (_tx, rx) = mpsc::channel(1);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    manager.test_force_ungrouped = true;
    let peer = IpAddr::V4(Ipv4Addr::new(10, 113, 0, 1));
    let mut outbound_rx = register_peer(&mut manager, peer);
    set_ipv4_limit(&mut manager, peer, 2);

    let source = Ipv4Addr::new(192, 0, 2, 113);
    announce(
        &mut manager,
        IpAddr::V4(source),
        source_routes(source, &[1, 2, 3]),
    );
    drop(wire_prefixes(&mut outbound_rx));
    assert!(manager.outbound_prefix_limits.contains_key(&peer));

    manager.handle_update(RibUpdate::PeerDown {
        peer,
        session_id: 0,
    });
    assert!(
        !manager.outbound_prefix_limits.contains_key(&peer),
        "a reconnecting generation must start with empty admission state"
    );
}
