use super::exportability::ReusableExactExportEncoder;
use super::lifecycle::{test_peer_up, test_routes_received};
use super::*;

const BEST: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 1);
const LEAVING: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 2);
const THIRD: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 3);
const OBSERVER: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 10);
const ROWS: u32 = 320;

type Key = (Prefix, u32);
type Inventory = BTreeMap<Key, (PeerId, IpAddr, Arc<AttrSet>)>;

fn prefix(row: u32) -> Ipv4Prefix {
    Ipv4Prefix::new(Ipv4Addr::from(0x0a00_0000 + row), 32)
}

fn input(row: u32, source: Ipv4Addr) -> Route {
    let preference = match source {
        BEST => 300,
        LEAVING => 200,
        THIRD => 100,
        _ => unreachable!(),
    };
    make_route_with_lp(prefix(row), source, preference)
}

fn insert_expected(table: &mut Inventory, row: u32, id: u32, source: Ipv4Addr) {
    let route = input(row, source);
    table.insert(
        (route.prefix, id),
        (route.peer, route.next_hop, route.attributes),
    );
}

fn seed(manager: &mut RibManager) {
    for source in [BEST, LEAVING, THIRD] {
        register_test_peer(manager, peer_v4(source), 0);
        let routes = (0..ROWS)
            .filter(|row| source != THIRD || row % 2 == 0)
            .map(|row| input(row, source))
            .collect();
        manager.handle_update(test_routes_received(peer_v4(source), routes));
        drain_route_chunks(manager);
    }
}

fn receiver(
    manager: &mut RibManager,
    address: Ipv4Addr,
    add_path: bool,
) -> mpsc::Receiver<OutboundRouteUpdate> {
    let peer = peer_v4(address);
    manager.handle_update(RibUpdate::SetPeerExportEncoder {
        peer,
        session_id: 0,
        encoder: ReusableExactExportEncoder::new(u64::from(u32::from(address)), 1),
    });
    if !add_path {
        manager.handle_update(RibUpdate::SetPeerExportContext {
            peer,
            session_id: 0,
            local_role: Some(rustbgpd_wire::BgpRole::RouteServer),
        });
    }
    let (tx, rx) = mpsc::channel(512);
    let mut up = test_peer_up(peer, 0, tx);
    let RibUpdate::PeerUp {
        per_client_best,
        add_path_send_max,
        add_path_send_families,
        ..
    } = &mut up
    else {
        unreachable!()
    };
    if add_path {
        *add_path_send_max = 2;
        *add_path_send_families = ipv4_sendable();
    } else {
        *per_client_best = true;
    }
    manager.handle_update(up);
    rx
}

/// Fold the transport-visible rows. A shared announce can exclude its own source.
fn read(
    receiver: &mut mpsc::Receiver<OutboundRouteUpdate>,
    table: &mut Inventory,
) -> (Vec<Key>, Vec<Key>) {
    let (mut announced, mut withdrawn) = (Vec::new(), Vec::new());
    while let Ok(update) = receiver.try_recv().map(delivered) {
        for &key in update.unicast_withdrawals() {
            assert!(
                table.remove(&key).is_some(),
                "withdrawal of unadvertised {key:?}"
            );
            withdrawn.push(key);
        }
        for route in update
            .announce
            .iter()
            .filter(|route| update.announce_source_exclusion != Some(route.peer))
        {
            let key = (route.prefix, route.path_id);
            table.insert(
                key,
                (route.peer, route.next_hop, Arc::clone(&route.attributes)),
            );
            announced.push(key);
        }
    }
    announced.sort_unstable();
    withdrawn.sort_unstable();
    (announced, withdrawn)
}

fn depart(manager: &mut RibManager) -> usize {
    use crate::manager::source_departure::take_receiver_rows;

    take_receiver_rows();
    manager.handle_update(RibUpdate::PeerDown {
        peer: peer_v4(LEAVING),
        session_id: 0,
    });
    assert!(
        manager.source_departure.is_some(),
        "fixture must traverse the paged departure"
    );
    let mut peak = take_receiver_rows();
    while manager.source_departure.is_some() {
        manager.advance_source_departure();
        peak = peak.max(take_receiver_rows());
    }
    for row in 0..ROWS {
        assert_eq!(
            manager.loc_rib.get(&Prefix::V4(prefix(row))).unwrap().peer,
            peer_v4(BEST)
        );
    }
    peak
}

fn manager() -> RibManager {
    let (_tx, rx) = mpsc::channel(16);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    manager.outbound_row_credit_override = None;
    super::distribution_window::untimed_window(&mut manager);
    manager
}

#[test]
fn source_departure_grouped_per_client_best_updates_only_the_winners_exception_lane() {
    let mut manager = manager();
    let mut best_rx = receiver(&mut manager, BEST, false);
    let mut observer_rx = receiver(&mut manager, OBSERVER, false);
    let gid = manager
        .grouped_member_of(peer_v4(BEST))
        .expect("grouped PCB source");
    assert!(manager.group_ribs[&gid].per_client_best);
    assert_eq!(manager.grouped_member_of(peer_v4(OBSERVER)), Some(gid));
    seed(&mut manager);

    let (mut best, mut observer) = (Inventory::new(), Inventory::new());
    read(&mut best_rx, &mut best);
    read(&mut observer_rx, &mut observer);
    let (mut initially_best, mut always_observer) = (Inventory::new(), Inventory::new());
    let mut final_best = Inventory::new();
    let mut removed = Vec::new();
    for row in 0..ROWS {
        insert_expected(&mut initially_best, row, 0, LEAVING);
        insert_expected(&mut always_observer, row, 0, BEST);
        if row % 2 == 0 {
            insert_expected(&mut final_best, row, 0, THIRD);
        } else {
            removed.push((Prefix::V4(prefix(row)), 0));
        }
    }
    assert_eq!(best, initially_best);
    assert_eq!(observer, always_observer);

    let peak = depart(&mut manager);
    assert!(
        (1..=256).contains(&peak),
        "grouped PCB peak was {peak} inspected receiver rows"
    );
    let changes = read(&mut best_rx, &mut best);
    assert_eq!(changes, (final_best.keys().copied().collect(), removed));
    assert_eq!(best, final_best);
    assert_eq!(read(&mut observer_rx, &mut observer), (vec![], vec![]));
    assert_eq!(observer, always_observer);
}

#[test]
fn source_departure_add_path_replaces_or_withdraws_the_old_sender_path_id() {
    let mut manager = manager();
    let mut rx = receiver(&mut manager, OBSERVER, true);
    seed(&mut manager);
    let mut wire = Inventory::new();
    read(&mut rx, &mut wire);
    let (mut initial, mut final_table) = (Inventory::new(), Inventory::new());
    let (mut replacements, mut removals) = (Vec::new(), Vec::new());
    for row in 0..ROWS {
        insert_expected(&mut initial, row, 1, BEST);
        insert_expected(&mut initial, row, 2, LEAVING);
        insert_expected(&mut final_table, row, 1, BEST);
        let old = (Prefix::V4(prefix(row)), 2);
        if row % 2 == 0 {
            insert_expected(&mut final_table, row, 2, THIRD);
            replacements.push(old);
        } else {
            removals.push(old);
        }
    }
    assert_eq!(wire, initial);
    depart(&mut manager);
    assert_eq!(read(&mut rx, &mut wire), (replacements, removals));
    assert_eq!(wire, final_table);
}

/// The largest transport envelope a receiver got, in unicast rows.
fn largest_envelope(receiver: &mut mpsc::Receiver<OutboundRouteUpdate>) -> usize {
    let mut largest = 0;
    while let Ok(update) = receiver.try_recv().map(delivered) {
        largest = largest.max(update.unicast_withdrawals().count() + update.announce.len());
    }
    largest
}

/// Quiet pages widen only for plain groups and single-path private peers.
/// A per-client-best group keeps 16-key pages for its winner and lane walks.
#[test]
fn quiet_departure_keeps_narrow_pages_for_a_per_client_best_group() {
    let mut manager = manager();
    let mut best_rx = receiver(&mut manager, BEST, false);
    let mut observer_rx = receiver(&mut manager, OBSERVER, false);
    assert!(manager.group_ribs[&manager.grouped_member_of(peer_v4(BEST)).unwrap()].per_client_best);
    seed(&mut manager);
    largest_envelope(&mut best_rx);
    largest_envelope(&mut observer_rx);
    depart(&mut manager);
    let largest = largest_envelope(&mut best_rx).max(largest_envelope(&mut observer_rx));
    assert!(
        (1..=16).contains(&largest),
        "per-client-best departure envelope of {largest} rows"
    );
}

/// An Add-Path sender replaces or withdraws each old path ID. Its private
/// walks keep 16-key pages, so one page holds at most two rows per key.
#[test]
fn quiet_departure_keeps_narrow_pages_for_an_add_path_receiver() {
    let mut manager = manager();
    let mut rx = receiver(&mut manager, OBSERVER, true);
    seed(&mut manager);
    largest_envelope(&mut rx);
    depart(&mut manager);
    let largest = largest_envelope(&mut rx);
    assert!(
        (1..=2 * 16).contains(&largest),
        "Add-Path departure envelope of {largest} rows"
    );
}

/// The winning source leaves, so every row moves to its runner-up.
fn depart_winner(manager: &mut RibManager) {
    manager.handle_update(RibUpdate::PeerDown {
        peer: peer_v4(BEST),
        session_id: 0,
    });
    assert!(
        manager.source_departure.is_some(),
        "fixture must traverse the paged departure"
    );
    while manager.source_departure.is_some() {
        manager.advance_source_departure();
    }
}

/// A per-client-best receiver whose export policy keeps it out of every group.
fn private_per_client_best_receiver(
    manager: &mut RibManager,
    address: Ipv4Addr,
) -> mpsc::Receiver<OutboundRouteUpdate> {
    let peer = peer_v4(address);
    manager.handle_update(RibUpdate::SetPeerExportEncoder {
        peer,
        session_id: 0,
        encoder: ReusableExactExportEncoder::new(u64::from(u32::from(address)), 1),
    });
    manager.handle_update(RibUpdate::SetPeerExportContext {
        peer,
        session_id: 0,
        local_role: Some(rustbgpd_wire::BgpRole::RouteServer),
    });
    let (tx, rx) = mpsc::channel(512);
    let mut up = test_peer_up(peer, 0, tx);
    let RibUpdate::PeerUp {
        per_client_best,
        export_policy,
        ..
    } = &mut up
    else {
        unreachable!()
    };
    *per_client_best = true;
    *export_policy = Some(super::update_groups::peer_context_chain());
    manager.handle_update(up);
    rx
}

/// A private per-client-best receiver ranks every candidate itself, so its
/// quiet departure pages stay narrow like a grouped per-client-best lane.
#[test]
fn quiet_departure_keeps_narrow_pages_for_a_private_per_client_best_receiver() {
    let mut manager = manager();
    let mut rx = private_per_client_best_receiver(&mut manager, OBSERVER);
    assert!(manager.grouped_member_of(peer_v4(OBSERVER)).is_none());
    assert!(manager.private_per_client_best(peer_v4(OBSERVER)));
    seed(&mut manager);
    largest_envelope(&mut rx);
    depart_winner(&mut manager);
    let largest = largest_envelope(&mut rx);
    assert!(
        (1..=16).contains(&largest),
        "private per-client-best departure envelope of {largest} rows"
    );
}

/// An RFC 9107 receiver with a resolved vantage ranks candidates by its own
/// IGP view, so its quiet departure pages stay narrow.
#[test]
fn quiet_departure_keeps_narrow_pages_for_an_orr_receiver_with_a_resolved_vantage() {
    let mut manager = manager();
    let feed = Ipv4Addr::new(10, 9, 9, 9);
    manager.handle_update(super::registering_peer_up(peer_v4(feed), 0));
    manager.handle_update(RibUpdate::BgpLsRoutesReceived {
        session_id: 0,
        peer: peer_v4(feed),
        announced: crate::orr::fixtures::square_topology(feed),
        withdrawn: vec![],
    });
    let client = peer_v4(OBSERVER);
    let (tx, mut rx) = mpsc::channel(512);
    let mut up = test_peer_up(client, 0, tx);
    let RibUpdate::PeerUp {
        is_ebgp,
        route_reflector_client,
        orr_vantage,
        peer_asn,
        ..
    } = &mut up
    else {
        unreachable!()
    };
    *is_ebgp = false;
    *route_reflector_client = true;
    *orr_vantage = Some(super::vantage_at_node_a());
    *peer_asn = 65_000;
    manager.handle_update(up);
    manager.rebuild_orr_and_resync();
    assert!(manager.orr_vantage_resolved(client));
    assert!(manager.grouped_member_of(client).is_none());
    seed(&mut manager);
    largest_envelope(&mut rx);
    depart_winner(&mut manager);
    let largest = largest_envelope(&mut rx);
    assert!(
        (1..=16).contains(&largest),
        "ORR departure envelope of {largest} rows"
    );
}
