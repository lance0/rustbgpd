//! Retained-byte budget on the RIB-to-session channel: stalled receivers are
//! refused at a byte bound and recover through the dirty resync, owned EVPN
//! members hold at most one full complete feed in flight, and the channel
//! counters balance through every release path.

use super::evpn_group_storage::{received, register};
use super::*;
use crate::PeerId;
use rustbgpd_wire::{EthernetTagId, EvpnRoute, EvpnRouteKey};

const SOURCE: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);

fn manager(floor: usize, peer_budget: usize, total_budget: usize) -> RibManager {
    let (_tx, rx) = mpsc::channel(8);
    let mut manager = RibManager::new(
        rx,
        dummy_query_rx(),
        None,
        Some(Ipv4Addr::new(10, 0, 0, 100)),
        BgpMetrics::new(),
    );
    manager.set_outbound_retained_budgets(floor, peer_budget, total_budget);
    manager
}

fn peer_up(
    manager: &mut RibManager,
    peer: PeerId,
    capacity: usize,
) -> mpsc::Receiver<OutboundRouteUpdate> {
    let (outbound_tx, mut output) = mpsc::channel(capacity);
    manager.handle_update(RibUpdate::PeerUp {
        per_client_best: false,
        interpret_rfc1997: true,
        session_id: 0,
        peer,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::new(10, 0, 0, 200),
        outbound_tx,
        export_policy: None,
        sendable_families: evpn_sendable(),
        is_ebgp: false,
        route_reflector_client: true,
        orr_vantage: None,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: Vec::new(),
        negotiated_llgr_families: Vec::new(),
    });
    while take(&mut output).is_some() {}
    output
}

/// What the session does: take one update off the channel.
fn take(output: &mut mpsc::Receiver<OutboundRouteUpdate>) -> Option<OutboundRouteUpdate> {
    let mut update = output.try_recv().ok()?;
    update.retained.dequeued();
    Some(update)
}

type View = BTreeMap<EvpnRouteKey, EvpnRoute>;

/// Apply one update to a receiver's wire view. A withdrawal of a key the
/// receiver never held is a spurious withdrawal.
fn apply(view: &mut View, update: &OutboundRouteUpdate) {
    for key in &update.evpn_withdraw {
        assert!(view.remove(key).is_some(), "spurious withdrawal of {key:?}");
    }
    for route in update.evpn_announce.iter() {
        view.insert(route.key(), route.route.clone());
    }
}

fn churn_route(tag: u32, variant: u16) -> EvpnRibRoute {
    let mut route = received(variant);
    let EvpnRoute::Imet(ref mut imet) = route.route else {
        panic!("IMET fixture");
    };
    imet.ethernet_tag = EthernetTagId(tag);
    imet.originator_ip = IpAddr::V4(SOURCE);
    route.peer = peer_v4(SOURCE);
    route.next_hop = IpAddr::V4(SOURCE);
    route
}

/// Batch `index` of a deterministic churn: replace one of 24 routes with a
/// new version, and withdraw another every fifth batch.
fn churn(manager: &mut RibManager, index: u32) {
    let tag = index % 24;
    let withdrawn = (index * 7 + 3) % 24;
    manager.handle_update(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: peer_v4(SOURCE),
        announced: vec![],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![churn_route(tag, u16::try_from(index % 1000).unwrap())],
        evpn_withdrawn: if index % 5 == 4 && withdrawn != tag {
            vec![churn_route(withdrawn, 0).key()]
        } else {
            vec![]
        },
        validated_with: None,
    });
    drain_route_chunks(manager);
}

fn expected(manager: &RibManager) -> View {
    manager
        .loc_rib
        .iter_evpn()
        .map(|route| (route.key(), route.route.clone()))
        .collect()
}

/// N receivers that never drain, M churn batches. The bytes they retain stay
/// within the budget plus one update, they are marked dirty, and once they
/// drain and resync their wire view and Adj-RIB-Out equal a receiver that
/// never stalled. Red without the credit check: the stalled receivers keep
/// every route version queued, far over the budget.
fn stalled_receivers_stay_within_budget_and_recover(
    floor: usize,
    peer_budget: usize,
    total_budget: usize,
) {
    const STALLED: usize = 3;
    const BATCHES: u32 = 160;
    let mut manager = manager(floor, peer_budget, total_budget);
    let _source = peer_up(&mut manager, peer_v4(SOURCE), 4096);
    let control = peer_v4(Ipv4Addr::new(10, 0, 0, 2));
    let mut control_output = peer_up(&mut manager, control, 4096);
    let stalled: Vec<_> = (0..STALLED)
        .map(|index| {
            let peer = peer_v4(Ipv4Addr::new(10, 0, 0, 10 + u8::try_from(index).unwrap()));
            (peer, peer_up(&mut manager, peer, 4096))
        })
        .collect();
    let mut control_view = View::new();
    let mut largest = 0;
    for index in 0..BATCHES {
        churn(&mut manager, index);
        while let Some(update) = take(&mut control_output) {
            largest = largest.max(update.retained.bytes());
            apply(&mut control_view, &update);
        }
        assert!(
            !manager.dirty_peers.contains(&control),
            "a draining receiver is never refused"
        );
    }
    assert_eq!(control_view, expected(&manager));

    // Measure what the stalled receivers hold independently of the charge:
    // the payload estimate of every update still queued.
    let mut queued_total = 0;
    let mut views = Vec::new();
    for (peer, mut output) in stalled {
        let (charged, _) = manager.outbound_retained_bytes(peer);
        let mut updates = Vec::new();
        while let Some(update) = take(&mut output) {
            updates.push(update);
        }
        let queued: usize = updates
            .iter()
            .map(OutboundRouteUpdate::retained_bytes_estimate)
            .sum();
        assert_eq!(
            charged,
            updates
                .iter()
                .map(|update| update.retained.bytes())
                .sum::<usize>(),
            "the charge is exactly the queued updates' charges"
        );
        assert!(
            queued <= peer_budget + largest,
            "{peer}: {queued} queued bytes over the {peer_budget}-byte budget"
        );
        queued_total += queued;
        let mut view = View::new();
        for update in &updates {
            apply(&mut view, update);
        }
        drop(updates);
        views.push((peer, output, view));
    }
    assert!(
        queued_total <= total_budget + STALLED * (floor + largest),
        "{queued_total} queued bytes over the {total_budget}-byte daemon budget"
    );
    for (peer, _, _) in &views {
        assert!(
            manager.dirty_peers.contains(peer),
            "{peer} refused, so dirty"
        );
    }

    // Recovery: the sessions drain and every resync tick's output is applied.
    for _ in 0..64 {
        if !manager.resync_tick_pending() {
            break;
        }
        manager.resync_dirty_peers_bounded();
        for (peer, output, view) in &mut views {
            manager.flush_pending_eor(*peer);
            while let Some(update) = take(output) {
                apply(view, &update);
            }
        }
    }
    assert!(!manager.resync_tick_pending(), "recovery converged");
    let control_rib: Vec<_> = manager.adj_ribs_out[&control]
        .iter_evpn()
        .map(EvpnRibRoute::key)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    for (peer, _, view) in &views {
        assert_eq!(view, &control_view, "{peer} wire view after recovery");
        let rib: BTreeSet<_> = manager.adj_ribs_out[peer]
            .iter_evpn()
            .map(EvpnRibRoute::key)
            .collect();
        assert_eq!(rib.into_iter().collect::<Vec<_>>(), control_rib);
        assert_eq!(manager.outbound_retained_bytes(*peer).0, 0);
    }
    assert_eq!(manager.outbound_retained_bytes(control).1, 0);
}

#[test]
fn stalled_receivers_are_bounded_by_the_peer_budget_and_recover() {
    stalled_receivers_stay_within_budget_and_recover(1 << 10, 4 << 10, 64 << 20);
}

#[test]
fn stalled_receivers_are_bounded_by_the_daemon_budget_and_recover() {
    stalled_receivers_stay_within_budget_and_recover(2 << 10, 64 << 20, 8 << 10);
}

/// An owned EVPN member that never drains, forced through repeated resync
/// passes with churn between them, holds at most one full complete feed in
/// flight; after it drains, recovery converges to the current table with no
/// withdrawal of a key it never held. Red without the in-flight gate: every
/// pass queues another full-table copy.
#[test]
fn stalled_owned_member_holds_one_complete_feed_and_converges() {
    let mut manager = manager(1 << 20, 64 << 20, 1 << 30);
    let member = PeerId::from_addr(Ipv4Addr::new(192, 0, 2, 30).into());
    let (sender, mut output) = mpsc::channel(64);
    register(&mut manager, member, sender);
    while take(&mut output).is_some() {}
    let gid = manager.grouped_member_of(member).unwrap();
    manager
        .group_ribs
        .get_mut(&gid)
        .unwrap()
        .set_evpn_ownership_for_test(true);
    assert!(manager.register_evpn_recovery(member, false));
    let source = peer_v4(SOURCE);
    manager.ribs.insert(source, AdjRibIn::new(source));
    manager.process_evpn_announce_chunk(source, (0..8).map(|tag| churn_route(tag, 1)).collect());
    let mut view = View::new();
    while let Some(update) = take(&mut output) {
        apply(&mut view, &update);
    }
    assert_eq!(view, expected(&manager));

    let mut queued = Vec::new();
    let mut held_a_feed = false;
    for round in 0..6 {
        manager.process_evpn_announce_chunk(
            source,
            vec![churn_route(round % 8, 2 + u16::try_from(round).unwrap())],
        );
        if round % 2 == 1 {
            manager.process_evpn_withdraw_chunk(source, vec![churn_route(round % 8 + 1, 0).key()]);
        }
        let (reply, _) = tokio::sync::oneshot::channel();
        manager.handle_refresh_peer_outbound(member, reply);
        manager.resync_dirty_peers_bounded();
        // Peek without dequeuing: count the full feeds the member holds.
        while let Ok(update) = output.try_recv() {
            queued.push(update);
        }
        let full = queued
            .iter()
            .filter(|update| update.retained.complete_feed())
            .count();
        assert!(
            full <= 1,
            "round {round}: {full} full complete feeds in flight"
        );
        held_a_feed |= full == 1;
        // Keep them queued from the RIB's point of view.
        assert_eq!(manager.complete_evpn_feed_in_flight(member), full == 1);
    }

    assert!(held_a_feed, "a forced resync queued a full complete feed");
    // Drain in order and let recovery converge.
    for mut update in queued {
        update.retained.dequeued();
        apply(&mut view, &update);
    }
    for _ in 0..64 {
        manager.resync_dirty_peers_bounded();
        manager.flush_pending_eor(member);
        while let Some(update) = take(&mut output) {
            apply(&mut view, &update);
        }
        if !manager.resync_tick_pending() {
            break;
        }
    }
    assert!(!manager.resync_tick_pending());
    assert_eq!(view, expected(&manager));
    assert!(!manager.complete_evpn_feed_in_flight(member));
    assert_eq!(manager.outbound_retained_bytes(member), (0, 0));
}

/// The channel series at a controlled stalled-reader boundary: queued is
/// exactly enqueued minus dequeued minus discarded, a reserved slot is
/// counted apart from queued, and after the session ends with updates still
/// queued every charge is released. Red if any counter update is dropped.
#[test]
fn channel_counters_balance_through_stall_and_session_end() {
    let mut manager = manager(1 << 20, 64 << 20, 1 << 30);
    let _source = peer_up(&mut manager, peer_v4(SOURCE), 4096);
    let peer = peer_v4(Ipv4Addr::new(10, 0, 0, 2));
    let mut output = peer_up(&mut manager, peer, 16);
    let label = peer.label();
    let series = |manager: &RibManager| manager.metrics.peer_outbound_channel(&label);
    let [_, _, _, queued, reserved, enqueued, dequeued, discarded] = series(&manager);
    assert_eq!(
        (queued, reserved, enqueued - dequeued - discarded),
        (0, 0, 0)
    );
    let base = (enqueued, dequeued, discarded);

    for index in 0..5 {
        churn(&mut manager, index);
    }
    let [
        updates,
        bytes,
        high,
        queued,
        reserved,
        enqueued,
        dequeued,
        discarded,
    ] = series(&manager);
    assert_eq!(
        (queued, reserved, updates),
        (5, 0, 5),
        "five updates queued for the stalled reader"
    );
    assert_eq!(output.len(), 5);
    assert_eq!(
        (enqueued - base.0, dequeued - base.1, discarded - base.2),
        (5, 0, 0)
    );
    let (charged, total) = manager.outbound_retained_bytes(peer);
    assert_eq!(usize::try_from(bytes).unwrap(), charged);
    assert!(charged > 0 && high >= bytes);
    assert_eq!(
        manager.metrics.rib_outbound_retained_bytes().0,
        i64::try_from(total).unwrap()
    );

    // A reserved slot is not queued, and giving it back unreserves it.
    let sender = manager.outbound_peers[&peer].clone();
    let slot = manager.reserve_outbound(peer, &sender, true).unwrap();
    let [_, _, _, queued, reserved, ..] = series(&manager);
    assert_eq!((queued, reserved), (5, 1));
    drop(slot);
    assert_eq!(series(&manager)[4], 0);

    // The session takes two and finishes them.
    for _ in 0..2 {
        drop(take(&mut output).unwrap());
    }
    let [updates, _, _, queued, _, enqueued, dequeued, discarded] = series(&manager);
    assert_eq!((queued, updates), (3, 3));
    assert_eq!(queued, enqueued - dequeued - discarded);
    assert_eq!(dequeued - base.1, 2);

    // The session ends with three still queued: they are discarded, and the
    // budget returns to zero.
    manager.handle_update(RibUpdate::PeerDown {
        peer,
        session_id: 0,
    });
    drop(output);
    let [
        updates,
        bytes,
        high_after,
        queued,
        reserved,
        enqueued,
        dequeued,
        discarded,
    ] = series(&manager);
    assert_eq!((updates, bytes, queued, reserved), (0, 0, 0, 0));
    assert_eq!(discarded - base.2, 3);
    assert_eq!(queued, enqueued - dequeued - discarded);
    assert_eq!(high_after, high, "the high watermark is kept");
    assert_eq!(manager.outbound_retained_bytes(peer), (0, 0));
    assert_eq!(manager.metrics.rib_outbound_retained_bytes().0, 0);
}
