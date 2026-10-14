use super::*;
use rustbgpd_rib::{
    EvpnRecoveryExhaustionCause, EvpnRecoveryReset, EvpnRecoveryResetOutcome, OutboundRouteUpdate,
};

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

fn submit(
    manager: &mut PeerManager,
    request: EvpnRecoveryReset,
) -> oneshot::Receiver<EvpnRecoveryResetOutcome> {
    let (reply, receipt) = oneshot::channel();
    manager.reset_evpn_recovery_session(request, reply);
    receipt
}

#[tokio::test]
async fn evpn_recovery_full_queue_keeps_receipt_pending_until_execution() {
    let peer = "192.0.2.1".parse().unwrap();
    let mut manager = test_peer_manager();
    let (handle, mut commands) = controlled_handle();
    handle
        .commands_sender()
        .try_send(PeerCommand::Start)
        .unwrap();
    insert_test_managed_peer(&mut manager, peer, handle, false);
    let (outbound, _routes) = mpsc::channel(1);
    let reset = request(peer, 1, outbound);
    let mut receipt = submit(&mut manager, reset.clone());
    let duplicate = submit(&mut manager, reset.clone());
    assert_eq!(duplicate.await.unwrap(), EvpnRecoveryResetOutcome::Rejected);
    assert!(matches!(
        receipt.try_recv(),
        Err(oneshot::error::TryRecvError::Empty)
    ));
    assert!(matches!(commands.try_recv(), Ok(PeerCommand::Start)));
    manager.retry_evpn_recovery_resets();
    let PeerCommand::ResetEvpnRecoverySession { reply, .. } = commands.try_recv().unwrap() else {
        panic!("expected guarded reset after queue credit");
    };
    assert!(matches!(
        receipt.try_recv(),
        Err(oneshot::error::TryRecvError::Empty)
    ));
    reply.send(EvpnRecoveryResetOutcome::Executed).unwrap();
    manager.retry_evpn_recovery_resets();
    assert_eq!(receipt.await.unwrap(), EvpnRecoveryResetOutcome::Executed);
    assert_eq!(
        submit(&mut manager, reset).await.unwrap(),
        EvpnRecoveryResetOutcome::Executed
    );
    assert!(commands.try_recv().is_err());
}

#[tokio::test]
async fn evpn_recovery_outbound_closure_keeps_pending_execution_receipt() {
    let peer = "192.0.2.1".parse().unwrap();
    let mut manager = test_peer_manager();
    let (handle, mut commands) = controlled_handle();
    insert_test_managed_peer(&mut manager, peer, handle, false);
    let (outbound, routes) = mpsc::channel(1);
    let reset = request(peer, 1, outbound);
    let mut receipt = submit(&mut manager, reset.clone());
    let PeerCommand::ResetEvpnRecoverySession { reply, .. } = commands.try_recv().unwrap() else {
        panic!("expected guarded reset command");
    };

    // SessionDown closes outbound before awaiting the RIB teardown event.
    drop(routes);
    assert!(reset.outbound.is_closed());
    for _ in 0..2 {
        manager.retry_evpn_recovery_resets();
        assert!(matches!(
            receipt.try_recv(),
            Err(oneshot::error::TryRecvError::Empty)
        ));
        assert_eq!(manager.peers.recovery_reset_sessions().count(), 1);
        assert!(manager.evpn_recovery_retry_at.is_some());
        assert!(matches!(
            commands.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
    }

    reply.send(EvpnRecoveryResetOutcome::Executed).unwrap();
    manager.retry_evpn_recovery_resets();
    assert_eq!(receipt.await.unwrap(), EvpnRecoveryResetOutcome::Executed);
    assert_eq!(manager.peers.recovery_reset_sessions().count(), 0);
    assert!(manager.evpn_recovery_retry_at.is_none());
    assert!(manager.peers.contains_key(&key(peer)));
    assert!(matches!(
        commands.try_recv(),
        Err(mpsc::error::TryRecvError::Empty)
    ));
}

#[tokio::test]
async fn evpn_recovery_receipt_distinguishes_dropped_rejected_and_executed_commands() {
    let peer = "192.0.2.1".parse().unwrap();
    let mut manager = test_peer_manager();
    let (handle, mut commands) = controlled_handle();
    insert_test_managed_peer(&mut manager, peer, handle, false);
    let (outbound, _routes) = mpsc::channel(1);
    let reset = request(peer, 1, outbound);
    let dropped = submit(&mut manager, reset.clone());
    drop(commands.try_recv().unwrap());
    manager.retry_evpn_recovery_resets();
    assert!(dropped.await.is_err(), "queue admission is not execution");
    assert!(manager.peers.contains_key(&key(peer)));

    let rejected = submit(&mut manager, reset.clone());
    let PeerCommand::ResetEvpnRecoverySession { reply, .. } = commands.try_recv().unwrap() else {
        panic!("expected guarded reset retry");
    };
    reply.send(EvpnRecoveryResetOutcome::Rejected).unwrap();
    manager.retry_evpn_recovery_resets();
    assert_eq!(rejected.await.unwrap(), EvpnRecoveryResetOutcome::Rejected);

    let executed = submit(&mut manager, reset.clone());
    let PeerCommand::ResetEvpnRecoverySession {
        request: captured,
        reply,
    } = commands.try_recv().unwrap()
    else {
        panic!("expected guarded reset retry");
    };
    assert!(captured.outbound.same_channel(&reset.outbound));
    reply.send(EvpnRecoveryResetOutcome::Executed).unwrap();
    manager.retry_evpn_recovery_resets();
    assert_eq!(executed.await.unwrap(), EvpnRecoveryResetOutcome::Executed);
    let duplicate = submit(&mut manager, reset);
    assert_eq!(duplicate.await.unwrap(), EvpnRecoveryResetOutcome::Executed);
    assert!(commands.try_recv().is_err(), "execution is deduplicated");
}

#[tokio::test]
async fn evpn_recovery_lost_rib_receipt_rejoins_the_single_pending_command() {
    let peer = "192.0.2.1".parse().unwrap();
    let mut manager = test_peer_manager();
    let (handle, mut commands) = controlled_handle();
    insert_test_managed_peer(&mut manager, peer, handle, false);
    let (outbound, _routes) = mpsc::channel(1);
    let reset = request(peer, 1, outbound);
    drop(submit(&mut manager, reset.clone()));
    let retry = submit(&mut manager, reset);
    let PeerCommand::ResetEvpnRecoverySession { reply, .. } = commands.try_recv().unwrap() else {
        panic!("expected the original guarded reset");
    };
    assert!(commands.try_recv().is_err(), "no second session command");
    reply.send(EvpnRecoveryResetOutcome::Executed).unwrap();
    manager.retry_evpn_recovery_resets();
    assert_eq!(retry.await.unwrap(), EvpnRecoveryResetOutcome::Executed);
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
    let _receipt = submit(&mut manager, reset.clone());
    let _receipt = submit(&mut manager, reset.clone());
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
    let PeerCommand::ResetEvpnRecoverySession {
        request: admitted, ..
    } = commands.try_recv().unwrap()
    else {
        panic!("expected guarded reset");
    };
    assert!(admitted.outbound.same_channel(&reset.outbound));
    let _receipt = submit(&mut manager, reset);
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
    let _receipt = submit(&mut manager, reset.clone());
    let (replacement, mut current_commands) = controlled_handle();
    let _old = manager
        .peers
        .replace_handle(&key(peer), replacement, 2)
        .unwrap();
    manager.register_session(2, &key(peer));
    let (candidate, mut candidate_commands) = controlled_handle();
    attach_test_pending_inbound(&mut manager, peer, candidate, 3);
    manager.retry_evpn_recovery_resets();
    let _receipt = submit(&mut manager, reset);
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
    let receipt = submit(&mut manager, reset.clone());
    assert!(primary_commands.try_recv().is_err());
    let PeerCommand::ResetEvpnRecoverySession { reply, .. } =
        candidate_commands.try_recv().unwrap()
    else {
        panic!("expected candidate reset command");
    };
    let _retired = manager.promote_pending_inbound_handle(&key(peer)).unwrap();
    let duplicate = submit(&mut manager, reset);
    assert_eq!(duplicate.await.unwrap(), EvpnRecoveryResetOutcome::Rejected);
    assert!(candidate_commands.try_recv().is_err());
    assert_eq!(manager.peers[&key(peer)].session_id(), 2);
    reply.send(EvpnRecoveryResetOutcome::Executed).unwrap();
    manager.retry_evpn_recovery_resets();
    assert_eq!(receipt.await.unwrap(), EvpnRecoveryResetOutcome::Executed);
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
    let _receipt = submit(&mut manager, request(peer, 2, outbound));
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
    let _receipt = submit(&mut manager, request(peer, 1, outbound));
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
    let _receipt = submit(&mut manager, request(peer, 1, fresh));
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
    let receipt = submit(&mut manager, request(peer, 1, outbound));
    assert_eq!(receipt.await.unwrap(), EvpnRecoveryResetOutcome::Rejected);
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
        let _receipt = submit(&mut manager, request(peer, u64::from(suffix), outbound));
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
