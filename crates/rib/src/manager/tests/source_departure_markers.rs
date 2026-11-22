use super::exportability::ReusableExactExportEncoder;
use super::lifecycle::{test_peer_up, test_routes_received};
use super::*;
use crate::manager::eor_hold::EorHold;
use crate::{EorGraceConfig, EorGracePeerConfig};
use rustbgpd_wire::RouteRefreshSubtype;

const FAMILY: (Afi, Safi) = (Afi::Ipv4, Safi::Unicast);
const SOURCE: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 1);
const SURVIVOR: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 2);
fn kept_prefix() -> Ipv4Prefix {
    Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 1), 32)
}

fn target(index: u8) -> PeerId {
    peer_v4(Ipv4Addr::new(192, 0, 2, index + 1))
}

fn lost(rows: u32) -> BTreeSet<Prefix> {
    (0..rows)
        .map(|row| Prefix::V4(Ipv4Prefix::new(Ipv4Addr::from(0x0a00_0000 + row), 32)))
        .collect()
}

fn register(manager: &mut RibManager, peer: PeerId) -> mpsc::Receiver<OutboundRouteUpdate> {
    manager.handle_update(RibUpdate::SetPeerExportEncoder {
        peer,
        session_id: 1,
        encoder: ReusableExactExportEncoder::new(1, 1),
    });
    manager.handle_update(RibUpdate::SetPeerGracefulRestartContext {
        peer,
        session_id: 1,
        peer_restart_state: false,
        peer_gr_helper: true,
        peer_gr_families: vec![FAMILY],
        peer_enhanced_refresh: true,
        peer_llgr_families: vec![],
        local_llgr_stale_time: 0,
    });
    let (sender, receiver) = mpsc::channel(256);
    let mut up = test_peer_up(peer, 1, sender);
    let RibUpdate::PeerUp { export_policy, .. } = &mut up else {
        unreachable!()
    };
    *export_policy = Some(super::update_groups::peer_context_chain());
    manager.handle_update(up);
    receiver
}

fn seed(manager: &mut RibManager, rows: &BTreeSet<Prefix>) {
    for address in [SOURCE, SURVIVOR] {
        register_test_peer(manager, peer_v4(address), 0);
    }
    manager.handle_update(test_routes_received(
        peer_v4(SOURCE),
        rows.iter()
            .map(|prefix| {
                let Prefix::V4(prefix) = prefix else {
                    unreachable!()
                };
                make_route(*prefix, SOURCE)
            })
            .collect(),
    ));
    manager.handle_update(test_routes_received(
        peer_v4(SURVIVOR),
        vec![make_route(kept_prefix(), SURVIVOR)],
    ));
    drain_route_chunks(manager);
}

fn assert_initial(
    receiver: &mut mpsc::Receiver<OutboundRouteUpdate>,
    rows: &BTreeSet<Prefix>,
    marker: bool,
) {
    let mut expected = rows.clone();
    expected.insert(Prefix::V4(kept_prefix()));
    let mut eor = 0;
    while let Ok(update) = receiver.try_recv().map(delivered) {
        for route in update.announce.iter() {
            assert!(expected.remove(&route.prefix));
        }
        eor += update
            .end_of_rib
            .iter()
            .filter(|&&family| family == FAMILY)
            .count();
    }
    assert!(expected.is_empty());
    assert_eq!(eor, usize::from(marker));
}

fn down() -> RibUpdate {
    RibUpdate::PeerDown {
        peer: peer_v4(SOURCE),
        session_id: 0,
    }
}

#[tokio::test(start_paused = true)]
async fn source_departure_initial_eor_follows_every_withdrawal_and_releases_in_pages() {
    const TARGETS: u8 = 12;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    let (_tx, rx) = mpsc::channel(16);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new())
        .with_eor_grace(EorGraceConfig {
            peers: (0..TARGETS)
                .map(|i| EorGracePeerConfig {
                    peer: target(i).into(),
                    deadline,
                    families: vec![FAMILY],
                })
                .collect(),
            replay_owners: vec![],
        });
    manager.outbound_row_credit_override = None;
    super::distribution_window::untimed_window(&mut manager);
    let rows = lost(64);
    let mut outs: Vec<_> = (0..TARGETS)
        .map(|i| register(&mut manager, target(i)))
        .collect();
    seed(&mut manager, &rows);
    for output in &mut outs {
        assert_initial(output, &rows, false);
    }

    manager.handle_update(down());
    assert!(manager.source_departure.is_some());
    manager.expire_eor_grace(deadline);
    for i in 0..TARGETS {
        let peer = target(i);
        assert!(
            manager
                .eor_holds(peer, FAMILY)
                .contains(EorHold::SourceDeparture)
        );
        assert!(!manager.eor_holds(peer, FAMILY).contains(EorHold::Grace));
        // Embedded dirty-resync markers and standalone offers use different hold masks.
        assert!(!manager.eor_resync_ready(peer).contains(&FAMILY));
        manager.settle_eor_now(peer);
    }
    manager.retry_eor_markers_bounded();
    while manager.source_departure.is_some() {
        manager.advance_source_departure();
    }

    let pending = (0..TARGETS)
        .filter(|&i| manager.eor.owes(target(i), FAMILY))
        .count();
    assert!(usize::from(TARGETS) - pending <= RESYNC_PEERS_PER_TICK);
    assert!(manager.marker_release_pending());
    manager.assert_eor_settled();
    for _ in 0..TARGETS {
        if !manager.marker_release_pending() {
            break;
        }
        manager.service_marker_release_backlog(RESYNC_PEERS_PER_TICK);
    }
    assert!(!manager.marker_release_pending());
    for output in &mut outs {
        let mut pending = rows.clone();
        let mut seen = false;
        while let Ok(update) = output.try_recv().map(delivered) {
            for &(prefix, id) in update.unicast_withdrawals() {
                assert!(!seen && id == 0 && pending.remove(&prefix));
            }
            if update.end_of_rib.contains(&FAMILY) {
                assert!(pending.is_empty(), "marker overtook departure withdrawals");
                assert!(!seen);
                seen = true;
            }
        }
        assert!(seen && pending.is_empty());
    }
}

#[tokio::test]
async fn source_departure_queued_refresh_brackets_only_the_surviving_table_after_withdrawals() {
    let (tx, rx) = mpsc::channel(16);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    manager.outbound_row_credit_override = None;
    super::distribution_window::untimed_window(&mut manager);
    let peer = target(0);
    let mut output = register(&mut manager, peer);
    let rows = lost(320);
    seed(&mut manager, &rows);
    assert_initial(&mut output, &rows, true);
    tx.try_send(down()).unwrap();
    tx.try_send(RibUpdate::RouteRefreshRequest {
        peer,
        session_id: 1,
        afi: FAMILY.0,
        safi: FAMILY.1,
        queued: Arc::default(),
    })
    .unwrap();
    drop(tx);
    let end = Box::pin(manager.run_actor()).await;
    assert!(end.source_departure.is_none());

    let mut pending = rows;
    let mut refresh_seen = false;
    while let Ok(update) = output.try_recv().map(delivered) {
        for &(prefix, id) in update.unicast_withdrawals() {
            assert!(!refresh_seen && id == 0 && pending.remove(&prefix));
        }
        if update.refresh_markers.is_empty() {
            assert!(update.announce.is_empty() && update.end_of_rib.is_empty());
            continue;
        }
        assert!(
            pending.is_empty(),
            "refresh began before all departure withdrawals"
        );
        assert!(!refresh_seen);
        assert_eq!(
            update.refresh_markers,
            [
                (FAMILY.0, FAMILY.1, RouteRefreshSubtype::BoRR),
                (FAMILY.0, FAMILY.1, RouteRefreshSubtype::EoRR),
            ]
        );
        // Transport emits the EoR for a plain refresh and brackets the same
        // replay with BoRR/EoRR on an enhanced-refresh session.
        assert_eq!(update.end_of_rib, [FAMILY]);
        assert_eq!(update.announce.len(), 1);
        assert_eq!(
            (update.announce[0].prefix, update.announce[0].peer),
            (Prefix::V4(kept_prefix()), peer_v4(SURVIVOR))
        );
        refresh_seen = true;
    }
    assert!(pending.is_empty() && refresh_seen);
}
