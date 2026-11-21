//! A distribution pass with no changed prefix captures no admitted-key proof
//! for a clean grouped writer whose channel is full.
//!
//! The capture records what a member admitted before shared staging moves
//! its group's table. A pass with no changed prefix stages nothing, so a
//! capture there would be released unused at the end of the pass, and the
//! resync tick runs such a pass for every slice while any peer is dirty.

use std::collections::BTreeMap;

use crate::attr_set::AttrSet;

use super::*;

/// Grouped writers' channel capacity: small, so they fill quickly.
const CAP: usize = 4;

fn private(index: usize) -> PeerId {
    peer_v4(Ipv4Addr::new(203, 0, 113, u8::try_from(index + 1).unwrap()))
}

/// Register `peer` with its own exact-export encoder (one shared wire
/// profile) and a channel of `cap` envelopes. A peer-context export chain
/// keeps it out of the update groups.
fn register(
    manager: &mut RibManager,
    peer: PeerId,
    seq: usize,
    cap: usize,
    ungrouped: bool,
    pcb: bool,
) -> mpsc::Receiver<OutboundRouteUpdate> {
    let encoder = ReusableExactExportEncoder::new(u64::try_from(seq).unwrap() + 1, WIRE_PROFILE);
    manager.handle_update(RibUpdate::SetPeerExportEncoder {
        peer,
        session_id: 1,
        encoder,
    });
    let (outbound_tx, outbound_rx) = mpsc::channel(cap);
    let mut up = test_peer_up(peer, 1, outbound_tx);
    if let RibUpdate::PeerUp {
        export_policy,
        peer_asn,
        per_client_best,
        ..
    } = &mut up
    {
        *export_policy = ungrouped.then(super::super::update_groups::peer_context_chain);
        *peer_asn = 65_100 + u32::try_from(seq).unwrap();
        *per_client_best = pcb;
    }
    manager.handle_update(up);
    outbound_rx
}

/// What a receiver admitted: its current route per prefix.
type Admitted = BTreeMap<Prefix, Route>;

/// Apply one envelope to a receiver's admitted routes.
fn apply(admitted: &mut Admitted, update: &OutboundRouteUpdate) {
    for (prefix, _) in update.unicast_withdrawals() {
        admitted.remove(prefix);
    }
    for route in update.announce.iter() {
        admitted.insert(route.prefix, route.clone());
    }
}

/// Each admitted prefix with the peer it was learned from.
fn sources(admitted: &Admitted) -> BTreeMap<Prefix, PeerId> {
    admitted
        .iter()
        .map(|(prefix, route)| (*prefix, route.peer))
        .collect()
}

fn apply_all(admitted: &mut [Admitted], receivers: &mut [mpsc::Receiver<OutboundRouteUpdate>]) {
    for (admitted, rx) in admitted.iter_mut().zip(receivers) {
        while let Ok(update) = rx.try_recv() {
            apply(admitted, &update);
        }
    }
}

/// A manager with grouped writers and private peers, the writers' receivers
/// with what each has admitted so far, and the privates' receivers.
struct Fleet {
    manager: RibManager,
    tx: mpsc::Sender<RibUpdate>,
    writers: Vec<PeerId>,
    writer_rx: Vec<mpsc::Receiver<OutboundRouteUpdate>>,
    writer_admitted: Vec<Admitted>,
    private_rx: Vec<mpsc::Receiver<OutboundRouteUpdate>>,
}

/// `k` grouped writers whose channels are full of admitted one-route sends,
/// every one clean, plus `privates` ungrouped peers with channels of
/// `private_cap`. With `pcb` the writers form a per-client-best group, and
/// writer 0 is also the best source of [`contested`], which the external
/// source holds as its runner-up.
fn fleet(k: usize, privates: usize, private_cap: usize, rows: usize, pcb: bool) -> Fleet {
    let (tx, mut manager) = manager();
    manager.flush_poll_budget = Duration::from_secs(3600);
    manager.handle_update(routes_from(external(), 0, 1, rows));
    drain_route_chunks(&mut manager);
    let writers: Vec<PeerId> = (0..k).map(member).collect();
    let mut writer_rx: Vec<_> = writers
        .iter()
        .enumerate()
        .map(|(i, peer)| register(&mut manager, *peer, i, CAP, false, pcb))
        .collect();
    let mut private_rx: Vec<_> = (0..privates)
        .map(|i| register(&mut manager, private(i), 1000 + i, private_cap, true, false))
        .collect();
    if pcb {
        manager.handle_update(routes_from(writers[0], 1, 1, 1));
        drain_route_chunks(&mut manager);
        let best = manager.loc_rib.get(&contested()).expect("contested prefix");
        assert_eq!(best.peer, writers[0], "writer 0 holds the best path");
    }
    let mut writer_admitted = vec![Admitted::new(); k];
    apply_all(&mut writer_admitted, &mut writer_rx);
    drain(&mut private_rx);
    for peer in &writers {
        assert!(manager.grouped_member_of(*peer).is_some(), "{peer} grouped");
    }
    for i in 0..privates {
        assert!(
            manager.grouped_member_of(private(i)).is_none(),
            "private {i}"
        );
    }
    // One new route at a time: each pass is admitted until the channel
    // holds `CAP` envelopes. A full private is filled the same way.
    let mut full: Vec<PeerId> = writers.clone();
    if private_cap == CAP {
        full.extend((0..privates).map(private));
    }
    let mut n = 0;
    while !full.iter().all(|peer| manager.outbound_channel_full(*peer)) {
        n += 1;
        assert!(n < 64, "channels never filled");
        manager.handle_update(routes_from(external(), 0, 2, n));
        drain_route_chunks(&mut manager);
        if private_cap != CAP {
            drain(&mut private_rx);
        }
    }
    for peer in &writers {
        assert!(!manager.dirty_peers.contains(peer), "full but clean");
        assert!(
            !manager.pending_group_admitted.contains_key(peer),
            "no proof held"
        );
    }
    Fleet {
        manager,
        tx,
        writers,
        writer_rx,
        writer_admitted,
        private_rx,
    }
}

/// Each Loc-RIB best path's prefix with its source peer.
fn loc_rib_sources(manager: &RibManager) -> BTreeMap<Prefix, PeerId> {
    manager
        .loc_rib
        .iter()
        .map(|route| (route.prefix, route.peer))
        .collect()
}

/// The prefix writer 0 and the external source both announce.
fn contested() -> Prefix {
    Prefix::V4(prefix(1, 0))
}

fn captures(manager: &RibManager) -> usize {
    manager.adj_rib_out_commit_stats.group_table_captures
}

fn assert_siblings_untouched(manager: &RibManager, writers: &[PeerId]) {
    for peer in writers {
        assert!(!manager.dirty_peers.contains(peer), "{peer} stays clean");
        assert!(manager.outbound_channel_full(*peer), "{peer} stays full");
        assert!(
            !manager.pending_group_admitted.contains_key(peer),
            "{peer} holds no proof"
        );
        assert!(
            manager.group_recovery_fallback(*peer).is_none(),
            "{peer} no fallback"
        );
    }
}

/// Ticks with `dirty` healthy private peers to resync (one slice each):
/// sibling captures per tick.
fn healthy_ticks(k: usize, dirty: usize) -> Vec<usize> {
    let mut fleet = fleet(k, dirty, 4096, 256, false);
    let mut per_tick = Vec::new();
    for _ in 0..3 {
        for i in 0..dirty {
            assert!(fleet.manager.mark_outbound_dirty(private(i)));
        }
        let (before, builds) = (
            captures(&fleet.manager),
            fleet.manager.adj_rib_out_commit_stats.resync_builds,
        );
        fleet.manager.resync_dirty_peers_bounded();
        per_tick.push(captures(&fleet.manager) - before);
        assert_eq!(
            fleet.manager.adj_rib_out_commit_stats.resync_builds - builds,
            dirty,
            "every private resynced in its own slice"
        );
        for i in 0..dirty {
            assert!(
                !fleet.manager.dirty_peers.contains(&private(i)),
                "private {i} healed"
            );
        }
        drain(&mut fleet.private_rx);
        assert_siblings_untouched(&fleet.manager, &fleet.writers);
    }
    per_tick
}

#[test]
fn idle_resync_slice_captures_no_clean_full_sibling() {
    for k in [SMALL, LARGE] {
        for dirty in [1, 4] {
            assert_eq!(healthy_ticks(k, dirty), [0, 0, 0], "k={k} dirty={dirty}");
        }
    }
}

/// The dirty private peer's channel is full too, so its resync is refused
/// on every tick and it stays dirty: each retry is another sliced pass.
#[test]
fn refused_resync_retries_capture_no_clean_full_sibling() {
    for k in [SMALL, LARGE] {
        let mut fleet = fleet(k, 1, CAP, 256, false);
        assert!(fleet.manager.mark_outbound_dirty(private(0)));
        for tick in 0..3 {
            let before = captures(&fleet.manager);
            fleet.manager.resync_dirty_peers_bounded();
            assert_eq!(captures(&fleet.manager) - before, 0, "k={k} tick {tick}");
            assert!(
                fleet.manager.dirty_peers.contains(&private(0)),
                "still refused"
            );
            assert_siblings_untouched(&fleet.manager, &fleet.writers);
        }
    }
}

/// Assert that every writer in `missed` missed the pass's send and kept
/// its proof, and every other writer stayed clean with none.
fn assert_missed_with_proof(fleet: &Fleet, missed: &[PeerId]) {
    let manager = &fleet.manager;
    let fallbacks = counter_metric_value(
        &manager.metrics,
        "bgp_update_group_recovery_fallback_total",
        &[],
    );
    assert_eq!(fallbacks, 0.0, "no member fell back for a missing proof");
    for peer in &fleet.writers {
        let expect = missed.contains(peer);
        assert_eq!(manager.dirty_peers.contains(peer), expect, "{peer} dirty");
        assert_eq!(
            manager.pending_group_admitted.contains_key(peer),
            expect,
            "{peer} proof held"
        );
        assert!(
            manager.group_recovery_fallback(*peer).is_none(),
            "{peer} no fallback"
        );
    }
}

/// Resync until every writer is clean, recording what each admitted.
fn heal(fleet: &mut Fleet) {
    let mut ticks = 0;
    while !fleet.manager.dirty_peers.is_empty() {
        apply_all(&mut fleet.writer_admitted, &mut fleet.writer_rx);
        fleet.manager.resync_dirty_peers_bounded();
        ticks += 1;
        assert!(ticks < 100, "writers never healed");
    }
    apply_all(&mut fleet.writer_admitted, &mut fleet.writer_rx);
    for peer in &fleet.writers {
        assert!(
            !fleet.manager.pending_group_admitted.contains_key(peer),
            "{peer} proof retired"
        );
        assert!(fleet.manager.group_recovery_fallback(*peer).is_none());
    }
}

/// A pass that changes a best path still captures every full writer before
/// staging moves the table. Each writer then misses the send, keeps its
/// proof, and its resync heals it exactly.
#[test]
fn best_change_still_captures_full_writers_and_heals_exactly() {
    for k in [SMALL, LARGE] {
        let mut fleet = fleet(k, 0, 4096, 64, false);
        let before = captures(&fleet.manager);
        fleet
            .manager
            .handle_update(routes_from(external(), 0, 9, 1));
        drain_route_chunks(&mut fleet.manager);
        let writers = fleet.writers.clone();
        assert_missed_with_proof(&fleet, &writers);
        assert_eq!(captures(&fleet.manager) - before, k, "one per full writer");
        heal(&mut fleet);
        let expected = loc_rib_sources(&fleet.manager);
        assert!(expected.contains_key(&Prefix::V4(prefix(9, 0))));
        for (peer, admitted) in writers.iter().zip(&fleet.writer_admitted) {
            assert_eq!(sources(admitted), expected, "{peer} final table");
        }
    }
}

/// A forced refresh runs a pass with no changed prefix, and still captures
/// its own full writer: the forced resync is refused for the full channel
/// and heals later from that proof. No other writer is captured.
#[test]
fn forced_refresh_still_captures_its_full_writer() {
    let mut fleet = fleet(SMALL, 0, 4096, 64, false);
    let writer = fleet.writers[0];
    let before = captures(&fleet.manager);
    let (reply, _reply_rx) = oneshot::channel();
    fleet.manager.handle_update(RibUpdate::RefreshPeerOutbound {
        peer: writer,
        reply,
    });
    assert_missed_with_proof(&fleet, &[writer]);
    assert_eq!(
        captures(&fleet.manager) - before,
        1,
        "the forced writer only"
    );
    heal(&mut fleet);
    let expected = loc_rib_sources(&fleet.manager);
    for (peer, admitted) in fleet.writers.iter().zip(&fleet.writer_admitted) {
        assert_eq!(sources(admitted), expected, "{peer} final table");
    }
}

/// A pass whose only change is a non-best candidate still moves a
/// per-client-best group's table: writer 0, the best path's own source,
/// is sent the changed runner-up. Every full writer is captured first;
/// writer 0 misses its send and heals exactly from its proof.
#[test]
fn candidate_change_still_captures_per_client_best_writers() {
    const TAG: u32 = 0xfc00_0001;
    for k in [SMALL, LARGE] {
        let mut fleet = fleet(k, 0, 4096, 64, true);
        let writer = fleet.writers[0];
        assert_eq!(
            fleet.writer_admitted[0][&contested()].peer,
            external(),
            "writer 0 holds the runner-up"
        );
        let IpAddr::V4(next_hop) = external().addr() else {
            unreachable!("test peers are IPv4")
        };
        let mut runner_up = make_route(prefix(1, 0), next_hop);
        AttrSet::edit(&mut runner_up.attributes, |attrs| {
            attrs.push(PathAttribute::Communities(vec![TAG]));
        });
        let before = captures(&fleet.manager);
        fleet
            .manager
            .handle_update(test_routes_received(external(), vec![runner_up]));
        drain_route_chunks(&mut fleet.manager);
        let best = fleet.manager.loc_rib.get(&contested()).unwrap();
        assert_eq!(best.peer, writer, "the best path did not change");
        assert_missed_with_proof(&fleet, &[writer]);
        assert_eq!(captures(&fleet.manager) - before, k, "one per full writer");
        heal(&mut fleet);
        // Every writer holds the best paths, except that writer 0 holds the
        // runner-up of the path it is the source of.
        let mut expected = loc_rib_sources(&fleet.manager);
        for (i, admitted) in fleet.writer_admitted.iter().enumerate() {
            expected.insert(contested(), if i == 0 { external() } else { writer });
            assert_eq!(sources(admitted), expected, "writer {i} final table");
        }
        let tagged = fleet.writer_admitted[0][&contested()]
            .attributes
            .iter()
            .any(|attr| matches!(attr, PathAttribute::Communities(tags) if tags == &[TAG]));
        assert!(tagged, "writer 0 admitted the changed runner-up");
    }
}

/// The same refused retry through the actor loop: the resync timer fires
/// the sliced passes on paused time. Once the private peer drains, its
/// retried resync is admitted; no sibling was captured on any tick.
#[tokio::test(start_paused = true)]
async fn actor_retry_ticks_capture_no_clean_full_sibling() {
    let mut fleet = fleet(SMALL, 1, CAP, 256, false);
    assert!(fleet.manager.mark_outbound_dirty(private(0)));
    let before = captures(&fleet.manager);
    let Fleet {
        manager,
        tx,
        writers,
        writer_rx: _writer_rx,
        mut private_rx,
        ..
    } = fleet;
    let actor = tokio::spawn(manager.run_actor());
    // Several 1 s retries while the private's channel stays full.
    tokio::time::sleep(Duration::from_millis(3500)).await;
    assert!(
        private_rx[0].try_recv().is_ok(),
        "the private still holds its fill"
    );
    while private_rx[0].try_recv().is_ok() {}
    // The next retry is admitted (its table is unchanged, so it sends
    // nothing) and the peer is clean.
    tokio::time::sleep(Duration::from_millis(1500)).await;
    drop(tx);
    let manager = actor.await.unwrap();
    assert_eq!(
        captures(&manager) - before,
        0,
        "no sibling capture on any tick"
    );
    assert!(!manager.dirty_peers.contains(&private(0)), "private healed");
    assert_siblings_untouched(&manager, &writers);
}
