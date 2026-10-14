use std::sync::atomic::{AtomicUsize, Ordering};

use super::*;
use crate::manager::distribution::OutboundCommitBatch;
use crate::manager::update_groups::recovery_provenance::EvpnRecoveryProvenance;
use crate::update::{EvpnRecoveryReset, RoutePageError};

fn fixture(capacity: usize) -> (RibManager, IpAddr, mpsc::Receiver<OutboundRouteUpdate>) {
    let (_tx, rx) = mpsc::channel(8);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let peer: IpAddr = "192.0.2.30".parse().unwrap();
    let (sender, mut output) = mpsc::channel(capacity);
    register(&mut manager, peer, sender);
    while output.try_recv().is_ok() {}
    // A capacity-one registration can defer EoR after the initial RTC
    // batch. Settle that ordinary recovery before enabling the G1 owner.
    for _ in 0..3 {
        if !manager.dirty_peers.contains(&peer) {
            break;
        }
        manager.resync_dirty_peers_bounded();
        while output.try_recv().is_ok() {}
    }
    assert!(!manager.dirty_peers.contains(&peer));
    assert!(manager.grouped_member_of(peer).is_some());
    (manager, peer, output)
}

fn register(manager: &mut RibManager, peer: IpAddr, sender: mpsc::Sender<OutboundRouteUpdate>) {
    register_session(manager, peer, sender, 7);
}

fn register_session(
    manager: &mut RibManager,
    peer: IpAddr,
    sender: mpsc::Sender<OutboundRouteUpdate>,
    session_id: u64,
) {
    manager.handle_update(RibUpdate::PeerUp {
        peer,
        session_id,
        peer_asn: 65000,
        peer_router_id: "192.0.2.30".parse().unwrap(),
        outbound_tx: sender,
        export_policy: None,
        sendable_families: vec![
            (Afi::Ipv4, Safi::Unicast),
            (Afi::L2Vpn, Safi::Evpn),
            (Afi::Ipv4, Safi::RtConstrain),
        ],
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
}

fn own(manager: &mut RibManager, peer: IpAddr, fresh: bool) {
    let gid = manager.grouped_member_of(peer).unwrap();
    manager.group_ribs.get_mut(&gid).unwrap().owns_evpn = true;
    assert!(manager.register_evpn_recovery(peer, fresh));
}

fn route(tag: u32) -> EvpnRibRoute {
    make_evpn_imet("192.0.2.10".parse().unwrap(), tag)
}

#[test]
fn negotiated_evpn_and_unicast_grouping_do_not_own_evpn() {
    let (mut manager, peer, _output) = fixture(8);
    let gid = manager.grouped_member_of(peer).unwrap();
    assert!(
        manager.group_ribs[&gid]
            .sendable
            .contains(&(Afi::L2Vpn, Safi::Evpn))
    );
    manager.mark_outbound_dirty(peer);
    assert!(manager.evpn_grouped_member_of(peer).is_none());
    assert!(manager.evpn_recovery_handle(peer).is_none());
    assert!(!manager.evpn_advertised_resync_in_progress(peer));
    assert!(!manager.capture_evpn_recovery_before_projection(peer, [route(1).key()].into_iter()));
}

#[test]
fn owned_capture_is_retained_across_rtc_changes_and_generic_cleanup() {
    let (mut manager, peer, _output) = fixture(8);
    own(&mut manager, peer, false);
    let old = route(1).key();
    assert!(manager.capture_evpn_recovery_before_projection(peer, [old].into_iter()));
    let handle = manager.evpn_recovery_handle(peer).unwrap();
    manager.mark_outbound_dirty(peer);
    manager.set_rt_membership(
        peer,
        Some(RtcMembership {
            has_default: true,
            entries: vec![],
        }),
    );
    manager.set_rt_membership(peer, Some(RtcMembership::default()));
    assert_eq!(
        manager.evpn_recovery.proof(handle).unwrap(),
        Some([old].as_slice())
    );
    // A new desired iterator must not overwrite an already-owned old-Φ proof.
    assert!(manager.capture_evpn_recovery_before_projection(peer, [route(2).key()].into_iter()));
    assert_eq!(
        manager.evpn_recovery.proof(handle).unwrap(),
        Some([old].as_slice())
    );
    let prior_uc = manager.pending_group_admitted.get(&peer).cloned();
    manager.dirty_peers.remove(&peer);
    manager.clear_grouped_member_synced(peer);
    assert!(manager.dirty_peers.contains(&peer));
    assert_eq!(manager.pending_group_admitted.get(&peer), prior_uc.as_ref());
    assert_eq!(
        manager.evpn_recovery.proof(handle).unwrap(),
        Some([old].as_slice())
    );
    assert!(!manager.settle_evpn_recovery(peer, [route(2).key()].into_iter()));
    assert!(manager.settle_evpn_recovery(peer, [old].into_iter()));
    manager.dirty_peers.remove(&peer);
    manager.clear_grouped_member_synced(peer);
    assert!(manager.evpn_recovery.is_dormant(handle));
    assert!(!manager.evpn_advertised_resync_in_progress(peer));
}

#[test]
fn outbound_queue_credit_precedes_provenance_growth_and_reset_handoff() {
    let (mut manager, peer, mut output) = fixture(1);
    own(&mut manager, peer, true);
    let calls = Arc::new(AtomicUsize::new(0));
    let seen = calls.clone();
    manager.evpn_recovery_reset = Some(Arc::new(move |_| {
        seen.fetch_add(1, Ordering::SeqCst);
        false
    }));
    let unicast = make_route(
        Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 1), 32),
        Ipv4Addr::new(192, 0, 2, 10),
    );
    manager
        .outbound_prefix_limits
        .entry(peer)
        .or_default()
        .family_mut(Afi::Ipv4)
        .unwrap()
        .limit = std::num::NonZeroU32::new(1);
    assert!(manager.capture_group_admitted_keys(peer));
    let admitted_before = manager.pending_group_admitted[&peer].clone();
    let batch = || OutboundCommitBatch {
        evpn_announce: vec![route(1)],
        ..OutboundCommitBatch::with_unicast(Arc::new(vec![unicast.clone()]), Arc::new(vec![None]))
    };
    manager.outbound_peers[&peer]
        .try_send(OutboundRouteUpdate::default())
        .unwrap();
    let before = manager.evpn_recovery.daemon_usage();
    manager.evpn_recovery.fail_next_allocation_for_test();
    assert!(!manager.try_send_and_commit_outbound_update(peer, batch()));
    assert_eq!(manager.evpn_recovery.daemon_usage(), before);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    output.try_recv().unwrap();
    assert!(!manager.try_send_and_commit_outbound_update(peer, batch()));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert!(manager.evpn_recovery_reset_pending(peer));
    assert!(output.try_recv().is_err());
    assert_eq!(manager.pending_group_admitted[&peer], admitted_before);
    assert!(
        manager.adj_ribs_out[&peer]
            .get(&unicast.prefix, unicast.path_id)
            .is_none()
    );
    let limits = &manager.outbound_prefix_limits[&peer];
    assert_eq!(limits.grouped_len(Afi::Ipv4), 0);
    assert!(!limits.grouped_contains(&unicast.prefix));
    assert!(!limits.family(Afi::Ipv4).unwrap().blocking);
    assert!(!manager.finish_evpn_recovery(peer));
    assert!(manager.dirty_peers.contains(&peer));
}

#[test]
fn reset_refusal_retries_once_accepted_and_stays_exhausted_until_teardown() {
    let (mut manager, peer, _output) = fixture(8);
    own(&mut manager, peer, true);
    let requests = Arc::new(std::sync::Mutex::new(Vec::<EvpnRecoveryReset>::new()));
    let captured = requests.clone();
    manager.evpn_recovery_reset = Some(Arc::new(move |request| {
        let mut requests = captured.lock().unwrap();
        requests.push(request);
        requests.len() >= 2
    }));
    manager.evpn_recovery.fail_next_allocation_for_test();
    assert!(!manager.try_send_and_commit_outbound_update(
        peer,
        OutboundCommitBatch {
            evpn_announce: vec![route(1)],
            ..OutboundCommitBatch::default()
        }
    ));
    manager.resync_dirty_peers_bounded();
    manager.resync_dirty_peers_bounded();
    let handle = manager.evpn_recovery_handle(peer).unwrap();
    assert!(manager.evpn_recovery.reset_admitted(handle));
    assert_eq!(requests.lock().unwrap().len(), 2);
    assert_eq!(requests.lock().unwrap()[0].session_id, 7);
    assert!(
        requests.lock().unwrap()[0]
            .outbound
            .same_channel(&manager.outbound_peers[&peer])
    );
    assert!(manager.evpn_recovery_reset_pending(peer));
    assert!(!manager.settle_evpn_recovery(peer, [].into_iter()));
    manager.clear_outbound_peer_state(peer);
    assert!(manager.evpn_recovery.proof(handle).unwrap().is_none());
}

#[test]
fn final_admission_filters_unknown_withdrawals_and_releases_only_after_settlement() {
    let (mut manager, peer, mut output) = fixture(8);
    own(&mut manager, peer, true);
    let known = route(1);
    assert!(manager.try_send_and_commit_outbound_update(
        peer,
        OutboundCommitBatch {
            evpn_announce: vec![known.clone()],
            ..OutboundCommitBatch::default()
        }
    ));
    output.try_recv().unwrap();
    let handle = manager.evpn_recovery_handle(peer).unwrap();
    assert_eq!(
        manager.evpn_recovery.proof(handle).unwrap(),
        Some([known.key()].as_slice())
    );
    assert!(manager.try_send_and_commit_outbound_update(
        peer,
        OutboundCommitBatch {
            evpn_withdraw: vec![route(2).key(), known.key(), known.key()],
            ..OutboundCommitBatch::default()
        }
    ));
    assert_eq!(output.try_recv().unwrap().evpn_withdraw, vec![known.key()]);
    let retained = manager.evpn_recovery.daemon_usage().retained;
    assert!(manager.settle_evpn_recovery(peer, [].into_iter()));
    assert!(manager.evpn_recovery.daemon_usage().retained < retained);
    assert!(manager.evpn_recovery_handle(peer).is_some());
}

#[test]
fn reconnect_reuses_actor_id_but_retires_the_old_channel_owner() {
    let (mut manager, peer, _old_output) = fixture(8);
    own(&mut manager, peer, false);
    assert!(manager.capture_evpn_recovery_before_projection(peer, [route(1).key()].into_iter()));
    let old = manager.evpn_recovery_handle(peer).unwrap();
    let old_sender = manager.outbound_peers[&peer].clone();
    let (replacement, mut output) = mpsc::channel(8);
    register(&mut manager, peer, replacement.clone());
    while output.try_recv().is_ok() {}
    assert!(manager.evpn_recovery.proof(old).unwrap().is_none());
    assert!(!old_sender.same_channel(&replacement));
    own(&mut manager, peer, true);
    let new = manager.evpn_recovery_handle(peer).unwrap();
    assert_ne!(old, new);
    assert_eq!(
        manager.evpn_recovery.proof(new).unwrap(),
        Some([].as_slice())
    );
}

#[test]
fn clean_owned_same_connection_replay_refuses_incomplete_projection_transfer() {
    let (mut manager, peer, _output) = fixture(8);
    own(&mut manager, peer, true);
    let owner = manager.evpn_recovery_handle(peer).unwrap();
    assert!(manager.settle_evpn_recovery(peer, [].into_iter()));
    assert!(manager.evpn_recovery.is_dormant(owner));
    manager
        .adj_ribs_out
        .get_mut(&peer)
        .unwrap()
        .insert_evpn(route(1));
    let same_sender = manager.outbound_peers[&peer].clone();
    register(&mut manager, peer, same_sender);
    assert_eq!(manager.evpn_recovery_handle(peer), Some(owner));
    assert!(!manager.evpn_recovery.is_dormant(owner));
    assert!(manager.evpn_recovery.proof(owner).unwrap().is_none());
    assert!(manager.dirty_peers.contains(&peer));
    assert!(manager.evpn_advertised_resync_in_progress(peer));
    assert!(!manager.finish_evpn_recovery(peer));
    assert!(!manager.settle_evpn_recovery(peer, [].into_iter()));
}

#[test]
fn evpn_page_guard_requires_real_owned_unsettled_state_and_preserves_cursor_precedence() {
    let (mut manager, peer, _output) = fixture(8);
    manager.mark_outbound_dirty(peer);
    let (reply, mut response) = oneshot::channel();
    manager.handle_query_evpn_routes_page(
        RouteQueryScope::Advertised { peer },
        None,
        None,
        None,
        1,
        reply,
    );
    assert!(response.try_recv().unwrap().is_ok());
    own(&mut manager, peer, true);
    let (reply, mut response) = oneshot::channel();
    manager.handle_query_evpn_routes_page(
        RouteQueryScope::Advertised { peer },
        None,
        None,
        None,
        1,
        reply,
    );
    assert!(matches!(
        response.try_recv().unwrap(),
        Err(RoutePageError::ResyncInProgress)
    ));
    let (reply, mut response) = oneshot::channel();
    manager.handle_query_evpn_routes_page(
        RouteQueryScope::Advertised { peer },
        None,
        Some((route(1).key(), peer)),
        None,
        1,
        reply,
    );
    assert!(matches!(
        response.try_recv().unwrap(),
        Err(RoutePageError::Invalidated)
    ));
}

#[test]
fn ownership_registration_refusal_has_bounded_session_reset_control() {
    let (mut manager, peer, _output) = fixture(8);
    manager.evpn_recovery = EvpnRecoveryProvenance::with_test_limits(0, 1024 * 1024);
    let gid = manager.grouped_member_of(peer).unwrap();
    manager.group_ribs.get_mut(&gid).unwrap().owns_evpn = true;
    let calls = Arc::new(AtomicUsize::new(0));
    let seen = calls.clone();
    manager.evpn_recovery_reset = Some(Arc::new(move |request| {
        assert_eq!(
            request.cause,
            crate::update::EvpnRecoveryExhaustionCause::PeerLimit
        );
        seen.fetch_add(1, Ordering::SeqCst);
        true
    }));
    assert!(!manager.register_evpn_recovery(peer, true));
    assert!(manager.evpn_recovery_handle(peer).is_none());
    manager.resync_dirty_peers_bounded();
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert!(manager.evpn_recovery_reset_pending(peer));
    let same_sender = manager.outbound_peers[&peer].clone();
    register(&mut manager, peer, same_sender);
    manager.resync_dirty_peers_bounded();
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert!(manager.evpn_recovery_reset_pending(peer));
    assert!(manager.evpn_advertised_resync_in_progress(peer));
    let (replacement, _replacement_output) = mpsc::channel(8);
    register_session(&mut manager, peer, replacement, 8);
    assert!(
        manager.live_sessions[&peer]
            .iter()
            .find(|record| record.session_id == 7)
            .unwrap()
            .evpn_recovery_reset
            .is_none()
    );
    // The preparatory classifier stays off after a fresh registration;
    // explicitly commit the synthetic G2 owner for the replacement.
    let gid = manager.grouped_member_of(peer).unwrap();
    manager.group_ribs.get_mut(&gid).unwrap().owns_evpn = true;
    assert!(!manager.register_evpn_recovery(peer, true));
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    manager.clear_outbound_peer_state(peer);
    assert!(!manager.evpn_recovery_reset_pending(peer));
}
