//! Retained outbound payload: what queued envelopes pin for receivers that
//! stop reading, counted by unique allocation rather than by envelope.

use super::*;

const SOURCE: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);

fn manager() -> RibManager {
    let (_tx, rx) = mpsc::channel(8);
    RibManager::new(
        rx,
        dummy_query_rx(),
        None,
        Some(Ipv4Addr::new(10, 0, 0, 100)),
        BgpMetrics::new(),
    )
}

fn peer_up_v4(
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
        sendable_families: ipv4_sendable(),
        is_ebgp: false,
        route_reflector_client: true,
        orr_vantage: None,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: Vec::new(),
        negotiated_llgr_families: Vec::new(),
    });
    while output.try_recv().is_ok() {}
    output
}

fn source_route(index: u32) -> Route {
    let mut route = make_indexed_route(index + 1, SOURCE);
    route.peer = peer_v4(SOURCE);
    route
}

/// Heap bytes the unicast withdrawal vectors of `updates` pin: each shared
/// vector once, by allocation, and every envelope's own vector.
fn pinned_withdraw_bytes(updates: &[OutboundRouteUpdate]) -> usize {
    let row = std::mem::size_of::<(Prefix, u32)>();
    let mut seen = std::collections::HashSet::new();
    updates
        .iter()
        .map(|update| {
            let shared = if seen.insert(Arc::as_ptr(&update.shared_withdraw) as usize) {
                update.shared_withdraw.capacity() * row
            } else {
                0
            };
            shared + update.withdraw.capacity() * row
        })
        .sum()
}

/// T12. A 64-member update group with 16 members stalled while the rest
/// drain: 400 passes each announce 8 new prefixes and withdraw the previous
/// pass's 8. The withdrawal bytes the stalled queues pin stay those of one
/// member's queue, whatever the number of stalled members, because every
/// member's envelope holds the group's shared vector. Red with per-member
/// copies: the stalled members pin 16 copies.
#[test]
fn stalled_group_members_share_withdrawal_payload() {
    const MEMBERS: u8 = 64;
    const STALLED: usize = 16;
    const BATCHES: u32 = 400;
    const PER_BATCH: u32 = 8;
    let mut manager = manager();
    let mut source_output = peer_up_v4(&mut manager, peer_v4(SOURCE), 4096);
    let mut members: Vec<_> = (0..MEMBERS)
        .map(|index| {
            let peer = peer_v4(Ipv4Addr::new(10, 0, 1, index + 1));
            (peer, peer_up_v4(&mut manager, peer, 4096))
        })
        .collect();
    let group = manager.grouped_member_of(members[0].0);
    assert!(group.is_some());
    assert!(
        members
            .iter()
            .all(|(peer, _)| manager.grouped_member_of(*peer) == group),
        "one update group"
    );
    let mut stalled: Vec<Vec<OutboundRouteUpdate>> = (0..STALLED).map(|_| Vec::new()).collect();
    for batch in 0..BATCHES {
        let announced = (0..PER_BATCH)
            .map(|i| source_route(batch * PER_BATCH + i))
            .collect();
        let withdrawn = if batch == 0 {
            vec![]
        } else {
            (0..PER_BATCH)
                .map(|i| (source_route((batch - 1) * PER_BATCH + i).prefix, 0))
                .collect()
        };
        manager.handle_update(RibUpdate::RoutesReceived {
            session_id: 0,
            peer: peer_v4(SOURCE),
            announced,
            withdrawn,
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
            evpn_announced: vec![],
            evpn_withdrawn: vec![],
            validated_with: None,
        });
        drain_route_chunks(&mut manager);
        while source_output.try_recv().is_ok() {}
        for (index, (_, output)) in members.iter_mut().enumerate() {
            while let Ok(update) = output.try_recv() {
                // Holding the envelope is what a stalled session does.
                if index < STALLED {
                    stalled[index].push(update);
                }
            }
        }
    }
    for (peer, _) in &members {
        assert!(!manager.dirty_peers.contains(peer), "{peer} never refused");
    }
    let one_member = pinned_withdraw_bytes(&stalled[0]);
    let rows: usize = stalled[0]
        .iter()
        .map(|update| update.unicast_withdrawals().count())
        .sum();
    assert_eq!(rows, usize::try_from((BATCHES - 1) * PER_BATCH).unwrap());
    let all: Vec<_> = stalled.into_iter().flatten().collect();
    let pinned = pinned_withdraw_bytes(&all);
    assert!(
        pinned <= one_member + one_member / 4,
        "{STALLED} stalled members pin {pinned} withdrawal bytes; one member's queue is \
         {one_member}"
    );
    assert!(
        all.iter().any(|update| !update.shared_withdraw.is_empty()),
        "the grouped fanout queued shared withdrawals"
    );
}
