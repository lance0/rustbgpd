//! Neighbor-snapshot projection of outbound resync and update-group recovery
//! fallback state.

use std::time::Duration;

use super::update_groups_recovery::peer_up;
use super::*;
use crate::update::OutboundResyncState;

fn prefix(octet: u8) -> Ipv4Prefix {
    Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, octet), 32)
}

fn source_update(manager: &mut RibManager, announce: &[u8]) {
    let source = Ipv4Addr::new(192, 0, 2, 1);
    manager.handle_update(RibUpdate::RoutesReceived {
        peer: source.into(),
        session_id: 0,
        announced: announce
            .iter()
            .map(|octet| make_route(prefix(*octet), source))
            .collect(),
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
        validated_with: None,
    });
    while manager.process_next_route_chunk() {}
}

/// A grouped member that missed delivery reports a pending resync, its age,
/// the fallback cause, and a pending advertised count; a successful resync
/// clears all four. Red proofs: dropping the grouped/dirty predicate, the
/// dirty-since write, or the fallback read fails the dirty-window assert.
#[tokio::test(start_paused = true)]
async fn dirty_grouped_member_reports_pending_resync_and_fallback_cause() {
    let (_tx, rx) = mpsc::channel(1);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    source_update(&mut manager, &[1]);
    let member: IpAddr = Ipv4Addr::new(10, 220, 9, 1).into();
    let (outbound, mut receiver) = mpsc::channel(16);
    manager.handle_update(peer_up(member, outbound, None));
    while receiver.try_recv().is_ok() {}
    assert!(manager.grouped_member_of(member).is_some());

    let clean = manager.neighbor_rib_snapshot(member);
    assert_eq!(clean.outbound_resync, OutboundResyncState::default());
    assert_eq!(clean.advertised_count, 1);

    // Without its exact-export encoder the member cannot be sent this pass.
    let encoder = manager.peer_export_encoders.remove(&member).unwrap();
    source_update(&mut manager, &[2]);
    assert!(manager.dirty_peers.contains(&member));
    tokio::time::advance(Duration::from_secs(7)).await;

    let dirty = manager.neighbor_rib_snapshot(member);
    assert_eq!(
        dirty.outbound_resync,
        OutboundResyncState {
            pending: true,
            dirty_secs: Some(7),
            advertised_count_pending: true,
            recovery_fallback: Some("missing_proof"),
        }
    );
    // The count is still the group's desired view, hence the marker.
    assert_eq!(dirty.advertised_count, 2);

    manager.peer_export_encoders.insert(member, encoder);
    while manager.resync_dirty_peers_bounded() {}
    assert!(!manager.dirty_peers.contains(&member));
    assert_eq!(
        manager.neighbor_rib_snapshot(member).outbound_resync,
        OutboundResyncState::default()
    );
}

/// Each dirty episode restarts its clock: a member that resynced and goes
/// dirty again does not inherit the earlier episode's start time.
#[tokio::test(start_paused = true)]
async fn dirty_seconds_restart_with_each_episode() {
    let (_tx, rx) = mpsc::channel(1);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    source_update(&mut manager, &[1]);
    let member: IpAddr = Ipv4Addr::new(10, 220, 9, 2).into();
    let (outbound, mut receiver) = mpsc::channel(16);
    manager.handle_update(peer_up(member, outbound, None));
    while receiver.try_recv().is_ok() {}

    let encoder = manager.peer_export_encoders.remove(&member).unwrap();
    source_update(&mut manager, &[2]);
    tokio::time::advance(Duration::from_secs(30)).await;
    manager.peer_export_encoders.insert(member, encoder);
    while manager.resync_dirty_peers_bounded() {}
    while receiver.try_recv().is_ok() {}
    assert!(!manager.dirty_peers.contains(&member));

    let encoder = manager.peer_export_encoders.remove(&member).unwrap();
    source_update(&mut manager, &[3]);
    assert!(manager.dirty_peers.contains(&member));
    tokio::time::advance(Duration::from_secs(2)).await;
    assert_eq!(
        manager
            .neighbor_rib_snapshot(member)
            .outbound_resync
            .dirty_secs,
        Some(2)
    );
    manager.peer_export_encoders.insert(member, encoder);
}
