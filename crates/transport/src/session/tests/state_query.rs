use super::*;

/// Load-bearing proof: mapping any of these unsupported AFI/SAFI pairs to a
/// metric family makes its exact `None` assertion fail.
#[test]
fn exact_export_metric_family_mapping_rejects_unsupported_pairs() {
    for family in [
        (Afi::Ipv4, Safi::Multicast),
        (Afi::Ipv6, Safi::Multicast),
        (Afi::Ipv6, Safi::RtConstrain),
    ] {
        assert_eq!(configured_exact_export_family_label(family), None);
    }
}

/// Load-bearing proof: deleting the outbound-constructor initialization call,
/// or any supported-family mapping arm, removes at least one asserted zero
/// child from this fresh registry and makes the test fail.
#[test]
fn outbound_constructor_materializes_route_safety_counter_children() {
    let mut peer_config = PeerConfig::new(65_001, 65_002, Ipv4Addr::new(10, 0, 0, 1));
    peer_config.families = exact_export_families()
        .into_iter()
        .map(|(family, _)| family)
        .collect();
    let config = TransportConfig::new(peer_config, "192.0.2.10:1179".parse().unwrap());
    let metrics = BgpMetrics::new();
    let (_cmd_tx, cmd_rx) = mpsc::channel(8);
    let (rib_tx, _rib_rx) = mpsc::channel(8);

    let _session = PeerSession::new(
        config,
        metrics.clone(),
        cmd_rx,
        rib_tx,
        None,
        None,
        None,
        None,
        None,
        false,
    );

    let exact = counter_samples(&metrics, "bgp_exact_export_rejections_total");
    assert_eq!(exact.len(), exact_export_families().len() * 4);
    for (_, family) in exact_export_families() {
        for reason in [
            "encoding",
            "missing_ipv6_next_hop",
            "ipv4_requires_extended_next_hop",
            "message_too_long",
        ] {
            assert_zero_counter_sample(
                &exact,
                &[
                    ("peer", "192.0.2.10"),
                    ("family", family),
                    ("reason", reason),
                ],
            );
        }
    }
    let malformed = counter_samples(&metrics, "bgp_update_malformed_total");
    assert_eq!(malformed.len(), 3);
    for disposition in ["attribute_discard", "treat_as_withdraw", "session_reset"] {
        assert_zero_counter_sample(
            &malformed,
            &[("peer", "192.0.2.10"), ("disposition", disposition)],
        );
    }
}

/// Load-bearing proof: deleting the accepted-session constructor's
/// initialization call leaves this independent fresh registry empty.
#[tokio::test]
async fn inbound_constructor_materializes_route_safety_counter_children() {
    let mut peer_config = PeerConfig::new(65_001, 65_002, Ipv4Addr::new(10, 0, 0, 1));
    peer_config.families = vec![(Afi::Ipv6, Safi::Unicast)];
    let config = TransportConfig::new(peer_config, "192.0.2.20:2179".parse().unwrap());
    let metrics = BgpMetrics::new();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let connect = TcpStream::connect(listener.local_addr().unwrap());
    let accept = listener.accept();
    let (client, accepted) = tokio::join!(connect, accept);
    let (_server, _) = accepted.unwrap();
    let (_cmd_tx, cmd_rx) = mpsc::channel(8);
    let (rib_tx, _rib_rx) = mpsc::channel(8);

    let _session = PeerSession::new_inbound_with_identity_and_lifecycle(
        config,
        metrics.clone(),
        cmd_rx,
        rib_tx,
        None,
        None,
        client.unwrap(),
        None,
        None,
        None,
        None,
        None,
        false,
        SessionIdentity::default(),
        None,
        None,
        crate::TcpAoRotationGeneration::STARTUP,
    );

    let exact = counter_samples(&metrics, "bgp_exact_export_rejections_total");
    assert_eq!(exact.len(), 4);
    for reason in [
        "encoding",
        "missing_ipv6_next_hop",
        "ipv4_requires_extended_next_hop",
        "message_too_long",
    ] {
        assert_zero_counter_sample(
            &exact,
            &[
                ("peer", "192.0.2.20"),
                ("family", "ipv6_unicast"),
                ("reason", reason),
            ],
        );
    }

    let malformed = counter_samples(&metrics, "bgp_update_malformed_total");
    assert_eq!(malformed.len(), 3);
    for disposition in ["attribute_discard", "treat_as_withdraw", "session_reset"] {
        assert_zero_counter_sample(
            &malformed,
            &[("peer", "192.0.2.20"), ("disposition", disposition)],
        );
    }
}

/// The `peer` metric/log label is the bare neighbor address, never the
/// transport endpoint's `addr:port`.
///
/// Sessions are the only emitter that holds a `SocketAddr`, so this is
/// where the split used to be introduced: session-owned families said
/// `10.0.0.2:179` while RIB-owned families said `10.0.0.2`, and every
/// `by (peer)` join across the two returned empty. A non-179 port here
/// proves the port is dropped rather than merely absent.
#[test]
fn session_peer_label_is_the_bare_neighbor_address() {
    let mut peer_config = PeerConfig::new(65001, 65002, Ipv4Addr::new(10, 0, 0, 1));
    peer_config.families = vec![(Afi::Ipv4, Safi::Unicast)];
    let config = TransportConfig::new(peer_config, "10.0.0.2:29179".parse().unwrap());
    let metrics = BgpMetrics::new();
    let (_cmd_tx, cmd_rx) = mpsc::channel(8);
    let (rib_tx, _rib_rx) = mpsc::channel(8);
    let session = PeerSession::new(
        config,
        metrics.clone(),
        cmd_rx,
        rib_tx,
        None,
        None,
        None,
        None,
        None,
        false,
    );

    assert_eq!(session.peer_label, "10.0.0.2");

    // Construction alone seeds the route-safety series; drive a
    // session-owned counter too, then check the whole registry.
    metrics.record_message_sent(&session.peer_label, "update");
    assert_eq!(
        rustbgpd_telemetry::non_canonical_peer_labels(metrics.registry()),
        Vec::<(String, String)>::new()
    );
}

#[tokio::test]
async fn query_state_sorts_both_paths_limit_vectors_by_numeric_family() {
    let mut session = make_test_session(65001, 65002);
    let mut negotiated = negotiated_session(65002, false);
    for (family, peer_limit, effective_limit) in [
        ((Afi::BgpLs, Safi::BgpLs), 11_u16, 21_u32),
        ((Afi::Ipv4, Safi::FlowSpec), 12, 22),
        ((Afi::Ipv6, Safi::Unicast), 13, 23),
        ((Afi::Ipv4, Safi::Unicast), 14, 24),
    ] {
        negotiated.peer_paths_limits.insert(family, peer_limit);
        negotiated
            .effective_add_path_send_limits
            .insert(family, effective_limit);
    }
    session.negotiated = Some(negotiated);

    let (reply, state) = oneshot::channel();
    assert!(matches!(
        session
            .handle_command(PeerCommand::QueryState { reply })
            .await,
        ControlFlow::Continue(())
    ));
    let state = state.await.unwrap();

    assert_eq!(
        state.peer_paths_limits,
        vec![
            ((Afi::Ipv4, Safi::Unicast), 14),
            ((Afi::Ipv4, Safi::FlowSpec), 12),
            ((Afi::Ipv6, Safi::Unicast), 13),
            ((Afi::BgpLs, Safi::BgpLs), 11),
        ]
    );
    assert_eq!(
        state.effective_add_path_send_limits,
        vec![
            ((Afi::Ipv4, Safi::Unicast), 24),
            ((Afi::Ipv4, Safi::FlowSpec), 22),
            ((Afi::Ipv6, Safi::Unicast), 23),
            ((Afi::BgpLs, Safi::BgpLs), 21),
        ]
    );
}

/// Load-bearing: replacing any `QueryState` max-prefix assignment with a
/// default makes its exact count, finite limit, or headroom assertion fail.
#[tokio::test]
async fn query_state_reports_exact_max_prefix_counts_limits_and_headroom() {
    let mut session = make_test_session(65001, 65002);
    session.config.max_prefixes = Some(9);
    session.config.max_prefixes_ipv4 = Some(4);
    session.config.max_prefixes_ipv6 = Some(6);

    let v4 = Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, 0), 24));
    let v6 = Prefix::V6(Ipv6Prefix::new(Ipv6Addr::LOCALHOST, 128));
    assert!(session.remember_known_path(v4, 0));
    assert!(session.remember_known_path(v6, 0));

    let (reply, state) = oneshot::channel();
    assert!(matches!(
        session
            .handle_command(PeerCommand::QueryState { reply })
            .await,
        ControlFlow::Continue(())
    ));
    let state = state.await.unwrap();

    assert_eq!(state.prefix_count, 2);
    assert_eq!(state.max_prefix.prefix_count_ipv4, 1);
    assert_eq!(state.max_prefix.prefix_count_ipv6, 1);
    assert_eq!(state.max_prefix.max_prefixes, Some(9));
    assert_eq!(state.max_prefix.max_prefixes_ipv4, Some(4));
    assert_eq!(state.max_prefix.max_prefixes_ipv6, Some(6));
    assert_eq!(state.max_prefix.headroom, Some(7));
    assert_eq!(state.max_prefix.headroom_ipv4, Some(3));
    assert_eq!(state.max_prefix.headroom_ipv6, Some(5));
}

#[tokio::test]
async fn warm_checkpoint_query_uses_current_gr_and_add_path_receive_direction() {
    let mut session = make_test_session(65001, 65002);
    let mut negotiated = negotiated_session(65002, false);
    negotiated.negotiated_families = vec![
        (Afi::Ipv6, Safi::Unicast),
        (Afi::Ipv4, Safi::Unicast),
        (Afi::L2Vpn, Safi::Evpn),
    ];
    negotiated.peer_gr_capable = true;
    negotiated.peer_restart_time = 120;
    negotiated.peer_gr_families = vec![rustbgpd_wire::GracefulRestartFamily {
        afi: Afi::Ipv4,
        safi: Safi::Unicast,
        forwarding_preserved: true,
    }];
    negotiated
        .add_path_families
        .insert((Afi::Ipv4, Safi::Unicast), AddPathMode::Receive);
    negotiated
        .add_path_families
        .insert((Afi::Ipv6, Safi::Unicast), AddPathMode::Send);
    negotiated
        .add_path_families
        .insert((Afi::L2Vpn, Safi::Evpn), AddPathMode::Both);
    install_test_negotiated_session(&mut session, negotiated);

    let (reply, state) = oneshot::channel();
    assert!(matches!(
        session
            .handle_command(PeerCommand::QueryWarmCheckpointState { reply })
            .await,
        ControlFlow::Continue(())
    ));
    let state = state.await.unwrap();

    assert_eq!(state.peer_asn, Some(65002));
    assert_eq!(state.peer_router_id, Some(Ipv4Addr::new(10, 0, 0, 2)));
    assert!(state.peer_gr_capable);
    assert_eq!(state.peer_gr_restart_time, 120);
    assert_eq!(
        state.negotiated_families,
        vec![
            (Afi::Ipv4, Safi::Unicast),
            (Afi::Ipv6, Safi::Unicast),
            (Afi::L2Vpn, Safi::Evpn),
        ]
    );
    assert_eq!(state.peer_gr_families, vec![(Afi::Ipv4, Safi::Unicast)]);
    assert_eq!(
        state.add_path_receive_families,
        vec![(Afi::Ipv4, Safi::Unicast), (Afi::L2Vpn, Safi::Evpn),]
    );
}

/// Load-bearing proof: removing the Established-state gate, copying configured
/// families, omitting a negotiated capability, deriving the outbound limit
/// from our advertisement instead of the peer's, omitting the peer/local
/// restart-time cap, or projecting the raw GR capability families instead of
/// their usable intersection makes an exact field assertion below fail.
#[tokio::test]
async fn query_state_projects_established_negotiation_and_capped_gr_runtime() {
    let mut peer_config = PeerConfig::new(65001, 65002, Ipv4Addr::new(10, 0, 0, 1));
    peer_config.connect_retry_secs = 30;
    peer_config.families = vec![(Afi::Ipv6, Safi::Unicast), (Afi::Ipv4, Safi::Unicast)];
    peer_config.graceful_restart = true;
    peer_config.gr_restart_time = 120;
    let mut session = make_test_session_with_peer_config(peer_config);
    session.config.gr_peer_restart_time_max = 300;
    let (client, _server) = connected_stream_pair().await;
    session.test_install_stream(client);
    session.drive_fsm(Event::ManualStart).await;
    session
        .drive_fsm(Event::OpenReceived(rustbgpd_wire::OpenMessage {
            version: 4,
            my_as: 65002,
            hold_time: 87,
            bgp_identifier: Ipv4Addr::new(192, 0, 2, 7),
            capabilities: vec![
                Capability::MultiProtocol {
                    afi: Afi::Ipv4,
                    safi: Safi::Unicast,
                },
                Capability::FourOctetAs { asn: 65002 },
                Capability::RouteRefresh,
                Capability::EnhancedRouteRefresh,
                Capability::ExtendedMessage,
                Capability::GracefulRestart {
                    restart_state: false,
                    notification: false,
                    restart_time: 777,
                    families: vec![
                        rustbgpd_wire::GracefulRestartFamily {
                            afi: Afi::Ipv6,
                            safi: Safi::Unicast,
                            forwarding_preserved: false,
                        },
                        rustbgpd_wire::GracefulRestartFamily {
                            afi: Afi::Ipv4,
                            safi: Safi::Unicast,
                            forwarding_preserved: true,
                        },
                        rustbgpd_wire::GracefulRestartFamily {
                            afi: Afi::L2Vpn,
                            safi: Safi::Evpn,
                            forwarding_preserved: true,
                        },
                    ],
                },
            ],
        }))
        .await;

    let (pre_reply, pre_state) = oneshot::channel();
    let _ = session
        .handle_command(PeerCommand::QueryState { reply: pre_reply })
        .await;
    assert!(pre_state.await.unwrap().negotiated_session.is_none());

    session.drive_fsm(Event::KeepaliveReceived).await;
    let (reply, state) = oneshot::channel();
    let _ = session
        .handle_command(PeerCommand::QueryState { reply })
        .await;
    let negotiated = state
        .await
        .unwrap()
        .negotiated_session
        .expect("Established session exposes negotiated values");
    assert_eq!(negotiated.hold_time, 87);
    assert_eq!(negotiated.remote_router_id, Ipv4Addr::new(192, 0, 2, 7));
    assert!(negotiated.four_octet_as);
    assert_eq!(negotiated.families, vec![(Afi::Ipv4, Safi::Unicast)]);
    assert!(negotiated.peer_route_refresh);
    assert!(negotiated.peer_enhanced_route_refresh);
    assert!(negotiated.peer_extended_message);
    assert_eq!(
        negotiated.outbound_max_message_bytes,
        rustbgpd_wire::EXTENDED_MAX_MESSAGE_LEN
    );
    assert_eq!(
        negotiated.graceful_restart,
        Some(crate::NegotiatedGracefulRestartState {
            peer_families: vec![(Afi::Ipv4, Safi::Unicast)],
            peer_restart_time: 777,
            effective_retention_time: Some(300),
        })
    );
}

/// Load-bearing proof: deriving effective retention solely from peer GR
/// capability, inventing absent capabilities, or reporting the extended
/// outbound limit without the peer capability makes an exact assertion fail.
#[tokio::test]
async fn query_state_with_local_gr_helper_disabled_omits_effective_retention() {
    let mut session = make_test_session(65001, 65002);
    session.config.peer.graceful_restart = false;
    let (client, _server) = connected_stream_pair().await;
    session.test_install_stream(client);
    session.drive_fsm(Event::ManualStart).await;
    session
        .drive_fsm(Event::OpenReceived(rustbgpd_wire::OpenMessage {
            version: 4,
            my_as: 65002,
            hold_time: 0,
            bgp_identifier: Ipv4Addr::new(192, 0, 2, 8),
            capabilities: vec![
                Capability::MultiProtocol {
                    afi: Afi::Ipv4,
                    safi: Safi::Unicast,
                },
                Capability::GracefulRestart {
                    restart_state: false,
                    notification: false,
                    restart_time: 0,
                    families: vec![rustbgpd_wire::GracefulRestartFamily {
                        afi: Afi::Ipv4,
                        safi: Safi::Unicast,
                        forwarding_preserved: false,
                    }],
                },
            ],
        }))
        .await;
    session.drive_fsm(Event::KeepaliveReceived).await;

    let (reply, state) = oneshot::channel();
    let _ = session
        .handle_command(PeerCommand::QueryState { reply })
        .await;
    let negotiated = state.await.unwrap().negotiated_session.unwrap();
    assert_eq!(negotiated.hold_time, 0);
    assert!(!negotiated.four_octet_as);
    assert!(!negotiated.peer_route_refresh);
    assert!(!negotiated.peer_enhanced_route_refresh);
    assert!(!negotiated.peer_extended_message);
    assert_eq!(
        negotiated.outbound_max_message_bytes,
        rustbgpd_wire::MAX_MESSAGE_LEN
    );
    assert_eq!(
        negotiated.graceful_restart,
        Some(crate::NegotiatedGracefulRestartState {
            peer_families: vec![(Afi::Ipv4, Safi::Unicast)],
            peer_restart_time: 0,
            effective_retention_time: None,
        })
    );
}

#[test]
fn connect_failure_is_retained_for_neighbor_diagnostics() {
    let (mut session, _rib_rx) = make_test_session_with_rib(65001, 65002);
    let error = std::io::Error::other(
        "failed to install TCP-AO key (send_id=7, recv_id=9, algorithm=hmac(sha256))",
    );
    session.record_connect_failure(&error);
    assert_eq!(session.last_error, error.to_string());
}
