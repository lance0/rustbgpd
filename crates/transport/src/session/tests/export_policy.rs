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
            peer: PeerId::from_addr(session.peer_ip),
            session_id,
            encoder: session.export_encoder.clone(),
        })
        .await
        .unwrap();
    session
        .rib_tx
        .send(RibUpdate::PeerUp {
            peer: PeerId::from_addr(session.peer_ip),
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
    assert_ne!(next_export(&mut survivor).await.end_of_rib.len(), 0);

    let prefix = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24);
    let source = Ipv4Addr::new(10, 0, 0, 9);
    session
        .rib_tx
        .send(RibUpdate::RoutesReceived {
            peer: PeerId::from_addr(IpAddr::V4(source)),
            session_id: 0,
            announced: vec![make_sourced_route(source, prefix, 65009)],
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
            evpn_announced: vec![],
            evpn_withdrawn: vec![],
            validated_with: None,
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
            peer: PeerId::from_addr(session.peer_ip),
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
            peer: PeerId::from_addr(session.peer_ip),
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
            assert_eq!(peer, PeerId::from_addr(session.peer_ip));
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
        peer: PeerId::from_addr(session.peer_ip),
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

/// An export policy that sets an IPv6 next hop rewrites the RIB route's
/// next hop before export but leaves an injected route's stored
/// `NEXT_HOP 0.0.0.0`. Toward a peer without Extended Next Hop the override
/// cannot apply, and the route must fall back to self, never send the
/// next-hop-self sentinel. This runs the real RIB export path (policy and
/// export memo) and the live session encoder.
#[tokio::test]
async fn policy_ipv6_next_hop_on_injected_self_route_falls_back_to_self_on_the_wire() {
    let (mut session, rib_rx) =
        make_test_session_with_metrics_and_identity(BgpMetrics::new(), SessionIdentity::primary(7));
    let (client, mut server) = connected_stream_pair().await;
    session.test_install_stream(client);
    install_test_negotiated_session(&mut session, negotiated_session(65002, false));
    let local_ipv4 = session.publish_export_profile().local_ipv4();
    assert!(!local_ipv4.is_unspecified());
    let (query_tx, query_rx) = mpsc::channel(8);
    let manager = rustbgpd_rib::RibManager::new(rib_rx, query_rx, None, None, BgpMetrics::new());
    let manager_task = tokio::spawn(manager.run());
    let v6: Ipv6Addr = "2001:db8::99".parse().unwrap();
    let policy = PolicyChain::new(vec![Policy {
        entries: vec![PolicyStatement {
            prefix: None,
            ge: None,
            le: None,
            action: PolicyAction::Permit,
            match_community: vec![],
            match_as_path: None,
            match_neighbor_set: None,
            match_route_type: None,
            match_evpn_route_type: None,
            match_rpki_validation: None,
            match_aspa_validation: None,
            match_as_path_length_ge: None,
            match_as_path_length_le: None,
            match_local_pref_ge: None,
            match_local_pref_le: None,
            match_med_ge: None,
            match_med_le: None,
            match_next_hop: None,
            modifications: RouteModifications {
                set_next_hop: Some(rustbgpd_policy::NextHopAction::Specific(IpAddr::V6(v6))),
                ..Default::default()
            },
        }],
        default_action: PolicyAction::Deny,
    }]);
    let mut exports = register_export_session(&session, 7, Some(policy)).await;
    assert_ne!(next_export(&mut exports).await.end_of_rib.len(), 0);

    let prefix = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24);
    let (reply, injected) = oneshot::channel();
    session
        .rib_tx
        .send(RibUpdate::InjectRoute {
            route: Route {
                prefix: Prefix::V4(prefix),
                next_hop: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                link_local_next_hop: None,
                next_hop_scope: None,
                peer: PeerId::from_addr(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
                attributes: AttrSet::new(vec![
                    PathAttribute::Origin(Origin::Igp),
                    PathAttribute::AsPath(AsPath { segments: vec![] }),
                    PathAttribute::NextHop(Ipv4Addr::UNSPECIFIED),
                ]),
                received_at: rustbgpd_rib::route::ReceivedAt::now(),
                origin_type: rustbgpd_rib::RouteOrigin::Local,
                peer_router_id: Ipv4Addr::UNSPECIFIED,
                is_stale: false,
                is_llgr_stale: false,
                path_id: 0,
                validation_state: rustbgpd_wire::RpkiValidation::NotFound,
                aspa_state: rustbgpd_wire::AspaValidation::Unknown,
                received_as_path: None,
                aspa_context: rustbgpd_rib::route::AspaContextId::DEFAULT,
            },
            reply,
        })
        .await
        .unwrap();
    injected.await.unwrap().unwrap();

    let update = next_export(&mut exports).await;
    assert_eq!(update.announce.len(), 1);
    // The policy rewrite reached the route; the stored attribute did not move.
    assert_eq!(update.announce[0].next_hop, IpAddr::V6(v6));
    session.send_route_update(update);
    let Message::Update(msg) = read_single_bgp_message(&mut server).await else {
        panic!("expected UPDATE");
    };
    let parsed = msg.parse(true, false, &[]).unwrap();
    let next_hops: Vec<_> = parsed
        .attributes
        .iter()
        .filter_map(|attr| match attr {
            PathAttribute::NextHop(next_hop) => Some(*next_hop),
            _ => None,
        })
        .collect();
    assert_eq!(next_hops, vec![local_ipv4]);

    drop(session);
    drop(query_tx);
    manager_task.await.unwrap();
}

/// LAN-2512: a policy the session accepts before it establishes is the one its
/// `PeerUp` registers. An export-policy cohort that skipped the unregistered
/// peer in the RIB therefore installs the accepted chain at registration.
#[tokio::test]
async fn export_policy_accepted_before_establishment_rides_peer_up() {
    let (mut session, mut rib_rx, _bmp_rx) = make_test_session_with_rib_and_bmp(65001, 65002);
    session.export_policy = Some(export_chain(PolicyAction::Deny));
    let next = export_chain(PolicyAction::Permit);
    let (reply, accepted) = oneshot::channel();
    let _ = session
        .handle_command(PeerCommand::UpdateExportPolicy {
            policy: Some(Box::new(next.clone())),
            reply,
        })
        .await;
    assert_eq!(accepted.await.unwrap(), Ok(()));
    assert!(matches!(
        rib_rx.recv().await.unwrap(),
        RibUpdate::SetPeerSessionExportPolicy { .. }
    ));

    let (client, _server) = connected_stream_pair().await;
    session.test_install_stream(client);
    session
        .execute_actions(vec![Action::SessionEstablished(Box::new(
            negotiated_session(65002, false),
        ))])
        .await;
    let RibUpdate::PeerUp { export_policy, .. } =
        recv_peer_up_after_export_context(&mut rib_rx).await
    else {
        unreachable!("the helper returns PeerUp");
    };
    assert_eq!(export_policy, Some(next));
}
