use super::*;

fn export_chain(action: PolicyAction) -> PolicyChain {
    PolicyChain::new(vec![Policy {
        entries: vec![],
        default_action: action,
    }])
}

async fn register_export_session(
    session: &PeerSession,
    session_id: u64,
    policy: Option<PolicyChain>,
) -> mpsc::Receiver<OutboundRouteUpdate> {
    let (outbound_tx, outbound_rx) = mpsc::channel(16);
    session
        .rib_tx
        .send(RibUpdate::SetPeerExportEncoder {
            peer: session.peer_ip,
            session_id,
            encoder: session.export_encoder.clone(),
        })
        .await
        .unwrap();
    session
        .rib_tx
        .send(RibUpdate::PeerUp {
            peer: session.peer_ip,
            session_id,
            peer_asn: 65002,
            peer_router_id: Ipv4Addr::new(10, 0, 0, 2),
            outbound_tx,
            export_policy: policy,
            sendable_families: vec![(Afi::Ipv4, Safi::Unicast)],
            is_ebgp: true,
            route_reflector_client: false,
            orr_vantage: None,
            per_client_best: false,
            interpret_rfc1997: true,
            add_path_send_families: vec![],
            add_path_send_max: 0,
            negotiated_orf_recv: vec![],
            negotiated_llgr_families: vec![],
        })
        .await
        .unwrap();
    outbound_rx
}

async fn next_export(rx: &mut mpsc::Receiver<OutboundRouteUpdate>) -> OutboundRouteUpdate {
    tokio::time::timeout(Duration::from_secs(3), rx.recv())
        .await
        .expect("RIB export reply")
        .expect("outbound channel remains open")
}

#[tokio::test]
async fn accepted_export_policy_survives_rib_collision_promotion() {
    let (mut session, rib_rx) =
        make_test_session_with_metrics_and_identity(BgpMetrics::new(), SessionIdentity::primary(7));
    install_test_negotiated_session(&mut session, negotiated_session(65002, false));
    session.publish_export_profile();
    let old = export_chain(PolicyAction::Deny);
    let next = export_chain(PolicyAction::Permit);
    session.export_policy = Some(old.clone());
    let (query_tx, query_rx) = mpsc::channel(8);
    let manager = rustbgpd_rib::RibManager::new(rib_rx, query_rx, None, None, BgpMetrics::new());
    let manager_task = tokio::spawn(manager.run());
    let mut survivor = register_export_session(&session, 7, Some(old)).await;
    assert!(!next_export(&mut survivor).await.end_of_rib.is_empty());

    let prefix = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24);
    let source = Ipv4Addr::new(10, 0, 0, 9);
    session
        .rib_tx
        .send(RibUpdate::RoutesReceived {
            peer: IpAddr::V4(source),
            session_id: 0,
            announced: vec![make_sourced_route(source, prefix, 65009)],
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
            evpn_announced: vec![],
            evpn_withdrawn: vec![],
        })
        .await
        .unwrap();

    // This is the real accepting transport handler, followed by the same
    // ordered RIB commit that the peer manager sends after its acknowledgement.
    let (reply, accepted) = oneshot::channel();
    let _ = session
        .handle_command(PeerCommand::UpdateExportPolicy {
            policy: Some(Box::new(next.clone())),
            reply,
        })
        .await;
    assert_eq!(accepted.await.unwrap(), Ok(()));
    let (reply, committed) = oneshot::channel();
    session
        .rib_tx
        .send(RibUpdate::ReplacePeerExportPolicy {
            peer: session.peer_ip,
            export_policy: Some(next.clone()),
            reply,
        })
        .await
        .unwrap();
    assert_eq!(committed.await.unwrap(), Ok(()));
    assert_eq!(next_export(&mut survivor).await.announce.len(), 1);

    let mut loser = register_export_session(&session, 8, Some(next)).await;
    assert_eq!(next_export(&mut loser).await.announce.len(), 1);
    session
        .rib_tx
        .send(RibUpdate::PeerDown {
            peer: session.peer_ip,
            session_id: 8,
        })
        .await
        .unwrap();
    let promoted = next_export(&mut survivor).await;
    assert_eq!(
        promoted.announce.len(),
        1,
        "collision promotion must retain the survivor's accepted permit policy"
    );
    assert_eq!(promoted.announce[0].prefix, Prefix::V4(prefix));

    drop(session);
    drop(query_tx);
    manager_task.await.unwrap();
}

#[tokio::test]
async fn accepted_export_policy_is_queued_before_ack_even_if_reply_dropped() {
    let (mut session, mut rx) =
        make_test_session_with_metrics_and_identity(BgpMetrics::new(), SessionIdentity::primary(7));
    let next = export_chain(PolicyAction::Permit);
    let (reply, accepted) = oneshot::channel();
    drop(accepted);
    let _ = session
        .handle_command(PeerCommand::UpdateExportPolicy {
            policy: Some(Box::new(next.clone())),
            reply,
        })
        .await;
    assert_eq!(session.export_policy, Some(next.clone()));
    match rx.try_recv().unwrap() {
        RibUpdate::SetPeerSessionExportPolicy {
            peer,
            session_id,
            export_policy,
        } => {
            assert_eq!(peer, session.peer_ip);
            assert_eq!(session_id, 7);
            assert_eq!(export_policy, Some(next));
        }
        _ => panic!("expected accepting session policy update"),
    }
}

#[tokio::test]
async fn accepted_export_policy_waits_for_capacity_and_rejects_closed_rib() {
    let (mut session, _rx) =
        make_test_session_with_metrics_and_identity(BgpMetrics::new(), SessionIdentity::primary(7));
    let old = export_chain(PolicyAction::Deny);
    session.export_policy = Some(old.clone());
    let (tx, mut rx) = mpsc::channel(1);
    tx.send(RibUpdate::PeerDown {
        peer: session.peer_ip,
        session_id: 99,
    })
    .await
    .unwrap();
    session.rib_tx = tx;
    let (reply, mut accepted) = oneshot::channel();
    {
        let command = session.handle_command(PeerCommand::UpdateExportPolicy {
            policy: None,
            reply,
        });
        tokio::pin!(command);
        tokio::select! {
            biased;
            _ = &mut command => panic!("full RIB channel must delay acceptance"),
            () = tokio::task::yield_now() => {},
        }
        assert!(matches!(
            accepted.try_recv(),
            Err(oneshot::error::TryRecvError::Empty)
        ));
    }
    assert_eq!(session.export_policy, Some(old.clone()));
    assert!(accepted.await.is_err(), "canceled wait did not acknowledge");
    drop(rx.recv().await);
    let (reply, accepted) = oneshot::channel();
    let _ = session
        .handle_command(PeerCommand::UpdateExportPolicy {
            policy: None,
            reply,
        })
        .await;
    assert_eq!(accepted.await.unwrap(), Ok(()));
    drop(rx);
    // The next update must fail without changing the accepted permit-all state.
    let (reply, accepted) = oneshot::channel();
    let _ = session
        .handle_command(PeerCommand::UpdateExportPolicy {
            policy: Some(Box::new(old)),
            reply,
        })
        .await;
    assert!(matches!(
        accepted.await.unwrap(),
        Err(PeerCommandError::CommandFailed(_))
    ));
    assert_eq!(session.export_policy, None);
}
