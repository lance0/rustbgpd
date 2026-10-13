use super::*;
use rustbgpd_rib::{EvpnRecoveryExhaustionCause, EvpnRecoveryReset, OutboundRouteUpdate};

fn controlled_handle() -> (PeerHandle, mpsc::Receiver<PeerCommand>) {
    let (commands, receiver) = mpsc::channel(1);
    (
        PeerHandle::from_parts(commands, tokio::spawn(std::future::pending())),
        receiver,
    )
}

fn request(
    peer: IpAddr,
    session_id: u64,
    outbound: mpsc::Sender<OutboundRouteUpdate>,
) -> EvpnRecoveryReset {
    EvpnRecoveryReset {
        peer,
        session_id,
        outbound,
        cause: EvpnRecoveryExhaustionCause::PeerLimit,
        limiting_peer: Some(peer),
        attempted_peer_bytes: 17,
        attempted_daemon_bytes: 18,
        peer_limit_bytes: 16,
        daemon_limit_bytes: 256,
    }
}

#[tokio::test]
async fn evpn_recovery_full_queue_retains_and_coalesces_retry() {
    let peer = "192.0.2.1".parse().unwrap();
    let mut manager = test_peer_manager();
    let (handle, mut commands) = controlled_handle();
    handle
        .commands_sender()
        .try_send(PeerCommand::Start)
        .unwrap();
    insert_test_managed_peer(&mut manager, peer, handle, false);
    let (outbound, routes) = mpsc::channel(1);
    let reset = request(peer, 1, outbound);
    manager.reset_evpn_recovery_session(reset.clone());
    manager.reset_evpn_recovery_session(reset.clone());
    assert_eq!(
        manager
            .peers
            .recovery_reset_sessions()
            .filter(|(_, queued)| !queued)
            .count(),
        1
    );
    assert!(manager.evpn_recovery_retry_at.is_some());
    assert!(matches!(commands.try_recv(), Ok(PeerCommand::Start)));
    manager.retry_evpn_recovery_resets();
    let PeerCommand::ResetEvpnRecoverySession { request: admitted } = commands.try_recv().unwrap()
    else {
        panic!("expected guarded reset");
    };
    assert!(admitted.outbound.same_channel(&reset.outbound));
    manager.reset_evpn_recovery_session(reset);
    assert!(commands.try_recv().is_err());
    assert!(manager.evpn_recovery_retry_at.is_some());
    for family in manager.metrics.registry().gather() {
        if family.name() == "bgp_evpn_recovery_provenance_exhausted_total" {
            assert!(
                family
                    .get_metric()
                    .iter()
                    .all(|metric| metric.get_counter().get_value() == 0.0)
            );
        }
    }
    drop(routes);
    manager.retry_evpn_recovery_resets();
    assert_eq!(manager.peers.recovery_reset_sessions().count(), 0);
    assert!(manager.evpn_recovery_retry_at.is_none());
}

#[tokio::test]
async fn evpn_recovery_stale_primary_preserves_replacement_and_candidate() {
    let peer = "192.0.2.1".parse().unwrap();
    let mut manager = test_peer_manager();
    let (old, _old_commands) = controlled_handle();
    old.commands_sender().try_send(PeerCommand::Start).unwrap();
    insert_test_managed_peer(&mut manager, peer, old, false);
    let (outbound, _routes) = mpsc::channel(1);
    let reset = request(peer, 1, outbound);
    manager.reset_evpn_recovery_session(reset.clone());
    let (replacement, mut current_commands) = controlled_handle();
    let _old = manager
        .peers
        .replace_handle(&key(peer), replacement, 2)
        .unwrap();
    manager.register_session(2, &key(peer));
    let (candidate, mut candidate_commands) = controlled_handle();
    attach_test_pending_inbound(&mut manager, peer, candidate, 3);
    manager.retry_evpn_recovery_resets();
    manager.reset_evpn_recovery_session(reset);
    assert!(current_commands.try_recv().is_err());
    assert!(candidate_commands.try_recv().is_err());
    assert_eq!(manager.peers[&key(peer)].session_id(), 2);
    assert_eq!(
        manager.peers[&key(peer)]
            .pending_inbound
            .as_ref()
            .unwrap()
            .session_id,
        3
    );
    assert!(manager.evpn_recovery_retry_at.is_none());
}

#[tokio::test]
async fn evpn_recovery_pending_admission_survives_promotion_without_duplicate() {
    let peer = "192.0.2.1".parse().unwrap();
    let mut manager = test_peer_manager();
    let (primary, mut primary_commands) = controlled_handle();
    insert_test_managed_peer(&mut manager, peer, primary, false);
    let (candidate, mut candidate_commands) = controlled_handle();
    attach_test_pending_inbound(&mut manager, peer, candidate, 2);
    let (outbound, _routes) = mpsc::channel(1);
    let reset = request(peer, 2, outbound);
    manager.reset_evpn_recovery_session(reset.clone());
    assert!(primary_commands.try_recv().is_err());
    assert!(matches!(
        candidate_commands.try_recv(),
        Ok(PeerCommand::ResetEvpnRecoverySession { .. })
    ));
    let _retired = manager.promote_pending_inbound_handle(&key(peer)).unwrap();
    manager.reset_evpn_recovery_session(reset);
    assert!(candidate_commands.try_recv().is_err());
    assert_eq!(manager.peers[&key(peer)].session_id(), 2);
}

#[tokio::test]
async fn evpn_recovery_session_index_selects_interface_scoped_same_ip() {
    let peer = "fe80::1".parse().unwrap();
    let mut manager = test_peer_manager();
    let first = scoped_key(peer, "test-a");
    let second = scoped_key(peer, "test-b");
    let (primary, mut primary_commands) = controlled_handle();
    insert_test_managed_peer_for_key(&mut manager, &first, 65002, primary, false);
    let (other, mut other_commands) = controlled_handle();
    insert_test_managed_peer_for_key(&mut manager, &second, 65002, other, false);
    let (outbound, _routes) = mpsc::channel(1);
    manager.reset_evpn_recovery_session(request(peer, 2, outbound));
    assert!(primary_commands.try_recv().is_err());
    assert!(matches!(
        other_commands.try_recv(),
        Ok(PeerCommand::ResetEvpnRecoverySession { .. })
    ));
    assert_eq!(manager.peer_key_for_session(2), Some(second));
    assert_eq!(manager.peer_key_for_session(1), Some(first));
}

#[tokio::test]
async fn evpn_recovery_closed_connection_retry_allows_fresh_same_actor_token() {
    let peer = "192.0.2.1".parse().unwrap();
    let mut manager = test_peer_manager();
    let (handle, mut commands) = controlled_handle();
    handle
        .commands_sender()
        .try_send(PeerCommand::Start)
        .unwrap();
    insert_test_managed_peer(&mut manager, peer, handle, false);
    let (outbound, routes) = mpsc::channel(1);
    manager.reset_evpn_recovery_session(request(peer, 1, outbound));
    drop(routes);
    manager.retry_evpn_recovery_resets();
    assert_eq!(
        manager
            .peers
            .recovery_reset_sessions()
            .filter(|(_, queued)| !queued)
            .count(),
        0
    );
    assert!(matches!(commands.try_recv(), Ok(PeerCommand::Start)));
    assert!(commands.try_recv().is_err());
    let (fresh, _routes) = mpsc::channel(1);
    manager.reset_evpn_recovery_session(request(peer, 1, fresh));
    assert!(matches!(
        commands.try_recv(),
        Ok(PeerCommand::ResetEvpnRecoverySession { .. })
    ));
}

#[tokio::test]
async fn evpn_recovery_closed_command_channel_does_not_remove_membership() {
    let peer = "192.0.2.1".parse().unwrap();
    let mut manager = test_peer_manager();
    let (handle, commands) = controlled_handle();
    drop(commands);
    insert_test_managed_peer(&mut manager, peer, handle, false);
    let (outbound, _routes) = mpsc::channel(1);
    manager.reset_evpn_recovery_session(request(peer, 1, outbound));
    assert!(manager.peers.contains_key(&key(peer)));
    assert_eq!(manager.peer_key_for_session(1), Some(key(peer)));
    assert!(manager.evpn_recovery_retry_at.is_none());
}

#[tokio::test]
async fn evpn_recovery_retry_batch_is_fair_beyond_thirty_two_full_queues() {
    let mut manager = test_peer_manager();
    let mut commands = Vec::new();
    let mut routes = Vec::new();
    for suffix in 1..=33 {
        let peer = IpAddr::V4(Ipv4Addr::new(192, 0, 2, suffix));
        let (handle, receiver) = controlled_handle();
        handle
            .commands_sender()
            .try_send(PeerCommand::Start)
            .unwrap();
        insert_test_managed_peer(&mut manager, peer, handle, false);
        let (outbound, receiver_routes) = mpsc::channel(1);
        manager.reset_evpn_recovery_session(request(peer, u64::from(suffix), outbound));
        commands.push(receiver);
        routes.push(receiver_routes);
    }
    assert!(matches!(commands[32].try_recv(), Ok(PeerCommand::Start)));
    manager.retry_evpn_recovery_resets();
    assert!(commands[32].try_recv().is_err());
    manager.retry_evpn_recovery_resets();
    assert!(matches!(
        commands[32].try_recv(),
        Ok(PeerCommand::ResetEvpnRecoverySession { .. })
    ));
    assert_eq!(
        manager
            .peers
            .recovery_reset_sessions()
            .filter(|(_, queued)| !queued)
            .count(),
        32
    );
}
