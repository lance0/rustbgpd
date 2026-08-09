use super::*;

#[tokio::test]
async fn enhanced_refresh_markers_follow_gr_end_of_rib_gate_per_family() {
    let families = vec![(Afi::Ipv4, Safi::Unicast), (Afi::Ipv6, Safi::Unicast)];

    let (mut plain, mut plain_rib) = make_test_session_with_rib(65001, 65002);
    install_enhanced_refresh_session(&mut plain, families.clone(), false);
    buffer_route_refresh(
        &mut plain,
        Afi::Ipv4,
        Safi::Unicast,
        RouteRefreshSubtype::BoRR,
    );
    plain.process_read_buffer().await;
    assert!(matches!(
        plain_rib.try_recv(),
        Ok(RibUpdate::BeginRouteRefresh {
            afi: Afi::Ipv4,
            safi: Safi::Unicast,
            ..
        })
    ));
    assert!(
        plain.refresh_accounting_has_window((Afi::Ipv4, Safi::Unicast)),
        "a non-GR peer may begin ERR before any End-of-RIB"
    );

    let (mut gr, mut gr_rib) = make_test_session_with_rib(65001, 65002);
    install_enhanced_refresh_session(&mut gr, families, true);
    buffer_route_refresh(&mut gr, Afi::Ipv4, Safi::Unicast, RouteRefreshSubtype::BoRR);
    gr.process_read_buffer().await;
    assert!(gr_rib.try_recv().is_err());
    assert_eq!(gr.refresh_accounting_window_count(), 0);

    // An empty UPDATE completes only IPv4 unicast GR replay.
    gr.process_update(UpdateMessage::build(
        &[],
        &[],
        &[],
        true,
        false,
        Ipv4UnicastMode::Body,
    ))
    .await;
    assert!(matches!(
        gr_rib.try_recv(),
        Ok(RibUpdate::EndOfRib {
            afi: Afi::Ipv4,
            safi: Safi::Unicast,
            ..
        })
    ));
    buffer_route_refresh(&mut gr, Afi::Ipv4, Safi::Unicast, RouteRefreshSubtype::BoRR);
    buffer_route_refresh(&mut gr, Afi::Ipv6, Safi::Unicast, RouteRefreshSubtype::BoRR);
    gr.process_read_buffer().await;
    assert!(matches!(
        gr_rib.try_recv(),
        Ok(RibUpdate::BeginRouteRefresh {
            afi: Afi::Ipv4,
            safi: Safi::Unicast,
            ..
        })
    ));
    assert!(gr_rib.try_recv().is_err(), "IPv6 BoRR must remain gated");
    assert!(gr.refresh_accounting_has_window((Afi::Ipv4, Safi::Unicast)));
    assert!(!gr.refresh_accounting_has_window((Afi::Ipv6, Safi::Unicast)));
}

#[tokio::test]
async fn enhanced_refresh_sweeps_every_counted_family_with_typed_identity() {
    let mut session = make_test_session(65001, 65002);
    let unicast = Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, 0), 24));
    session.remember_known_path(unicast, 7);
    let flowspec = rustbgpd_rib::FlowSpecKey {
        afi: Afi::Ipv4,
        rule: FlowSpecRule {
            components: vec![FlowSpecComponent::DestinationPrefix(FlowSpecPrefix::V4(
                Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 0), 24),
            ))],
        },
    };
    session.known_flowspec.insert(flowspec);
    let evpn = rustbgpd_wire::EvpnRouteKey::Imet {
        rd: RouteDistinguisher([0, 0, 0xfd, 0xe8, 0, 0, 0, 1]),
        ethernet_tag: rustbgpd_wire::EthernetTagId(100),
        originator_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
    };
    session.known_evpn.insert(evpn);
    session.known_bgpls.insert(make_bgpls_route(1).key());
    session.known_vpn.insert(make_vpn_rib_route(100).key());
    session
        .known_labeled
        .insert(make_labeled_rib_route(200).key());
    session.known_rtc.insert(make_rtc_rib_route(300).key());
    let families = [
        (Afi::Ipv4, Safi::Unicast),
        (Afi::Ipv4, Safi::FlowSpec),
        (Afi::L2Vpn, Safi::Evpn),
        (Afi::BgpLs, Safi::BgpLs),
        (Afi::Ipv4, Safi::MplsVpn),
        (Afi::Ipv4, Safi::LabeledUnicast),
        (Afi::Ipv4, Safi::RtConstrain),
    ];
    assert_eq!(session.known_prefix_count(), families.len());
    for family in families {
        session.begin_refresh_accounting(family.0, family.1);
        assert_eq!(session.refresh_accounting_stale_count(family), Some(1));
        assert_eq!(
            session.known_prefix_count(),
            families.len(),
            "BoRR snapshots must not change live max-prefix accounting"
        );
    }
    for family in families {
        session.end_refresh_accounting(family.0, family.1);
    }
    assert_eq!(session.known_prefix_count(), 0);
    assert_eq!(session.refresh_accounting_window_count(), 0);
}

#[tokio::test]
async fn duplicate_borr_resnapshots_routes_replayed_in_the_prior_window() {
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    install_enhanced_refresh_session(&mut session, vec![(Afi::Ipv4, Safi::Unicast)], false);
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, 0), 24);
    session.remember_known_path(Prefix::V4(prefix), 0);

    buffer_route_refresh(
        &mut session,
        Afi::Ipv4,
        Safi::Unicast,
        RouteRefreshSubtype::BoRR,
    );
    session.process_read_buffer().await;
    assert!(matches!(
        rib_rx.try_recv(),
        Ok(RibUpdate::BeginRouteRefresh { .. })
    ));
    session
        .process_update(ipv4_announce(prefix, 0, false))
        .await;
    assert!(matches!(
        rib_rx.try_recv(),
        Ok(RibUpdate::RoutesReceived { .. })
    ));
    assert_eq!(
        session.refresh_accounting_stale_count((Afi::Ipv4, Safi::Unicast)),
        Some(0)
    );

    buffer_route_refresh(
        &mut session,
        Afi::Ipv4,
        Safi::Unicast,
        RouteRefreshSubtype::BoRR,
    );
    session.process_read_buffer().await;
    assert!(matches!(
        rib_rx.try_recv(),
        Ok(RibUpdate::BeginRouteRefresh { .. })
    ));
    assert_eq!(
        session.refresh_accounting_stale_count((Afi::Ipv4, Safi::Unicast)),
        Some(1),
        "duplicate BoRR must snapshot the route that the first replay made current"
    );

    buffer_route_refresh(
        &mut session,
        Afi::Ipv4,
        Safi::Unicast,
        RouteRefreshSubtype::EoRR,
    );
    session.process_read_buffer().await;
    assert!(matches!(
        rib_rx.try_recv(),
        Ok(RibUpdate::EndRouteRefresh { .. })
    ));
    assert_eq!(session.known_prefix_count(), 0);
}

/// Mutant: snapshotting plain ERR state as `(prefix, path_id)` identities fails
/// to retire the omitted compact prefix at `EoRR`, leaving the count at two.
#[tokio::test]
async fn eorr_reconciles_omitted_prefix_before_later_max_prefix_check() {
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    install_enhanced_refresh_session(&mut session, vec![(Afi::Ipv4, Safi::Unicast)], false);
    session.config.max_prefixes = Some(2);
    let replayed = Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, 0), 24);
    let omitted = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 0), 24);
    session.remember_known_path(Prefix::V4(replayed), 0);
    session.remember_known_path(Prefix::V4(omitted), 0);

    buffer_route_refresh(
        &mut session,
        Afi::Ipv4,
        Safi::Unicast,
        RouteRefreshSubtype::BoRR,
    );
    session.process_read_buffer().await;
    assert!(matches!(
        rib_rx.try_recv(),
        Ok(RibUpdate::BeginRouteRefresh { .. })
    ));
    session
        .process_update(ipv4_announce(replayed, 0, false))
        .await;
    assert!(matches!(
        rib_rx.try_recv(),
        Ok(RibUpdate::RoutesReceived { .. })
    ));
    buffer_route_refresh(
        &mut session,
        Afi::Ipv4,
        Safi::Unicast,
        RouteRefreshSubtype::EoRR,
    );
    session.process_read_buffer().await;
    assert!(matches!(
        rib_rx.try_recv(),
        Ok(RibUpdate::EndRouteRefresh { .. })
    ));
    assert_eq!(session.known_prefix_count(), 1);

    let later = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24);
    session.process_update(ipv4_announce(later, 0, false)).await;
    assert!(matches!(
        rib_rx.try_recv(),
        Ok(RibUpdate::RoutesReceived { .. })
    ));
    assert_eq!(session.known_prefix_count(), 2);
}

/// Mutant: collapsing Add-Path ERR state to a plain prefix makes replay of
/// valid path ID zero preserve the omitted path ID two as well.
#[tokio::test]
async fn add_path_partial_replay_sweeps_only_omitted_identity_and_keeps_prefix_count() {
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    let mut negotiated = negotiated_session(65002, false);
    negotiated.peer_route_refresh = true;
    negotiated.peer_enhanced_route_refresh = true;
    negotiated
        .add_path_families
        .insert((Afi::Ipv4, Safi::Unicast), AddPathMode::Both);
    install_test_negotiated_session(&mut session, negotiated);
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, 0), 24);
    session.remember_known_path(Prefix::V4(prefix), 0);
    session.remember_known_path(Prefix::V4(prefix), 2);
    session.begin_refresh_accounting(Afi::Ipv4, Safi::Unicast);
    session.process_update(ipv4_announce(prefix, 0, true)).await;
    assert!(matches!(
        rib_rx.try_recv(),
        Ok(RibUpdate::RoutesReceived { .. })
    ));
    buffer_route_refresh(
        &mut session,
        Afi::Ipv4,
        Safi::Unicast,
        RouteRefreshSubtype::EoRR,
    );
    session.process_read_buffer().await;
    assert!(matches!(
        rib_rx.try_recv(),
        Ok(RibUpdate::EndRouteRefresh { .. })
    ));
    assert!(session.known_paths.contains(&(Prefix::V4(prefix), 0)));
    assert!(!session.known_paths.contains(&(Prefix::V4(prefix), 2)));
    assert_eq!(session.known_prefix_count(), 1);
}

#[tokio::test]
async fn import_policy_denial_retires_refresh_stale_identity() {
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    install_test_negotiated_session(&mut session, negotiated_session(65002, false));
    session.install_import_policy(Some(PolicyChain::new(vec![Policy {
        entries: vec![],
        default_action: PolicyAction::Deny,
    }])));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, 0), 24);
    session.remember_known_path(Prefix::V4(prefix), 0);
    session.begin_refresh_accounting(Afi::Ipv4, Safi::Unicast);
    session
        .process_update(ipv4_announce(prefix, 0, false))
        .await;
    let RibUpdate::RoutesReceived {
        announced,
        withdrawn,
        ..
    } = rib_rx
        .try_recv()
        .expect("denied replacement must emit a withdrawal")
    else {
        panic!("expected RoutesReceived");
    };
    assert!(announced.is_empty());
    assert_eq!(withdrawn, vec![(Prefix::V4(prefix), 0)]);
    assert_eq!(
        session.refresh_accounting_stale_count((Afi::Ipv4, Safi::Unicast)),
        Some(0)
    );
    session.end_refresh_accounting(Afi::Ipv4, Safi::Unicast);
    assert_eq!(session.known_prefix_count(), 0);
}

#[tokio::test]
async fn ordinary_withdrawal_retires_refresh_stale_identity() {
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    install_test_negotiated_session(&mut session, negotiated_session(65002, false));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, 0), 24);
    session.remember_known_path(Prefix::V4(prefix), 0);
    session.begin_refresh_accounting(Afi::Ipv4, Safi::Unicast);

    session
        .process_update(ipv4_withdraw(prefix, 0, false))
        .await;
    assert!(matches!(
        rib_rx.try_recv(),
        Ok(RibUpdate::RoutesReceived { .. })
    ));
    assert_eq!(
        session.refresh_accounting_stale_count((Afi::Ipv4, Safi::Unicast)),
        Some(0)
    );
    session.end_refresh_accounting(Afi::Ipv4, Safi::Unicast);
    assert_eq!(session.known_prefix_count(), 0);
}

/// Mutant: sweeping before a timed-out RIB boundary is accepted removes the
/// compact plain prefix despite the closed channel and makes the count zero.
#[tokio::test(start_paused = true)]
async fn closed_rib_timeout_preserves_refresh_window_and_live_count() {
    let mut session = make_test_session(65001, 65002);
    let prefix = Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, 0), 24));
    session.remember_known_path(prefix, 0);
    session.begin_refresh_accounting(Afi::Ipv4, Safi::Unicast);

    tokio::time::advance(rustbgpd_rib::ERR_REFRESH_TIMEOUT).await;
    assert_eq!(session.expire_refresh_accounting_windows().await, Err(()));
    assert!(session.refresh_accounting_has_window((Afi::Ipv4, Safi::Unicast)));
    assert_eq!(session.known_prefix_count(), 1);
    assert!(
        session.refresh_accounting_timer.is_none(),
        "a closed RIB must not spin a past-due timer"
    );
}

/// Mutant: using one untyped unicast ERR snapshot either leaves the plain IPv4
/// prefix or mishandles Add-Path ID zero when the staggered windows expire.
#[tokio::test(start_paused = true)]
async fn staggered_refresh_timeouts_sweep_only_due_family_and_rearm() {
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    let mut negotiated = negotiated_session(65002, false);
    negotiated.negotiated_families = vec![(Afi::Ipv4, Safi::Unicast), (Afi::Ipv6, Safi::Unicast)];
    negotiated
        .add_path_families
        .insert((Afi::Ipv6, Safi::Unicast), AddPathMode::Receive);
    install_test_negotiated_session(&mut session, negotiated);
    let v4 = Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, 0), 24));
    let v6 = Prefix::V6(Ipv6Prefix::new(Ipv6Addr::LOCALHOST, 128));
    session.remember_known_path(v4, 0);
    session.remember_known_path(v6, 0);
    session.begin_refresh_accounting(Afi::Ipv4, Safi::Unicast);
    tokio::time::advance(Duration::from_secs(1)).await;
    session.begin_refresh_accounting(Afi::Ipv6, Safi::Unicast);

    tokio::time::advance(
        rustbgpd_rib::ERR_REFRESH_TIMEOUT
            .checked_sub(Duration::from_secs(1))
            .unwrap(),
    )
    .await;
    session.expire_refresh_accounting_windows().await.unwrap();
    assert!(matches!(
        rib_rx.try_recv(),
        Ok(RibUpdate::RouteRefreshTimeout {
            afi: Afi::Ipv4,
            safi: Safi::Unicast,
            ..
        })
    ));
    assert!(!session.known_plain_prefixes.contains(&v4));
    assert!(session.known_paths.contains(&(v6, 0)));
    assert!(!session.refresh_accounting_has_window((Afi::Ipv4, Safi::Unicast)));
    assert!(session.refresh_accounting_has_window((Afi::Ipv6, Safi::Unicast)));
    assert!(session.refresh_accounting_timer.is_some());

    tokio::time::advance(Duration::from_secs(1)).await;
    session.expire_refresh_accounting_windows().await.unwrap();
    assert!(matches!(
        rib_rx.try_recv(),
        Ok(RibUpdate::RouteRefreshTimeout {
            afi: Afi::Ipv6,
            safi: Safi::Unicast,
            ..
        })
    ));
    assert_eq!(session.known_prefix_count(), 0);
    assert_eq!(session.refresh_accounting_window_count(), 0);
}

#[tokio::test(start_paused = true)]
async fn quiet_run_loop_expires_refresh_accounting() {
    let (mut session, cmd_tx, mut rib_rx) = make_test_session_with_channels(65001, 65002, 8);
    let prefix = Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, 0), 24));
    session.remember_known_path(prefix, 0);
    session.begin_refresh_accounting(Afi::Ipv4, Safi::Unicast);
    let task = tokio::spawn(async move {
        session.run().await.unwrap();
    });

    tokio::time::advance(rustbgpd_rib::ERR_REFRESH_TIMEOUT).await;
    assert!(matches!(
        rib_rx.recv().await,
        Some(RibUpdate::RouteRefreshTimeout {
            afi: Afi::Ipv4,
            safi: Safi::Unicast,
            ..
        })
    ));
    let (reply, state) = oneshot::channel();
    cmd_tx
        .send(PeerCommand::QueryState { reply })
        .await
        .unwrap();
    assert_eq!(state.await.unwrap().prefix_count, 0);
    cmd_tx.send(PeerCommand::Shutdown).await.unwrap();
    task.await.unwrap();
}

/// Mutant: applying the buffered UPDATE before the ordered timeout boundary
/// leaves the stale compact prefix present after the task completes.
#[tokio::test(start_paused = true)]
async fn refresh_timeout_precedes_next_buffered_update_after_rib_backpressure() {
    let (mut session, _cmd_tx, mut rib_rx) = make_test_session_with_channels(65001, 65002, 1);
    install_test_negotiated_session(&mut session, negotiated_session(65002, false));
    let stale = Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, 0), 24);
    let first = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 0), 24);
    let second = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24);
    session.remember_known_path(Prefix::V4(stale), 0);
    session.begin_refresh_accounting(Afi::Ipv4, Safi::Unicast);
    session
        .rib_tx
        .try_send(RibUpdate::BeginRouteRefresh {
            peer: session.peer_ip,
            session_id: session.session_identity.id,
            afi: Afi::Ipv6,
            safi: Safi::Unicast,
        })
        .unwrap();
    for update in [
        ipv4_announce(first, 0, false),
        ipv4_announce(second, 0, false),
    ] {
        let encoded = rustbgpd_wire::encode_message(&Message::Update(update)).unwrap();
        session.read_buf.buf.extend_from_slice(&encoded);
    }
    let task = tokio::spawn(async move {
        session.process_read_buffer().await;
        session
    });
    tokio::task::yield_now().await;
    assert!(
        !task.is_finished(),
        "the first UPDATE must park on the full RIB channel"
    );

    tokio::time::advance(rustbgpd_rib::ERR_REFRESH_TIMEOUT).await;
    assert!(matches!(
        rib_rx.recv().await,
        Some(RibUpdate::BeginRouteRefresh { .. })
    ));
    assert!(matches!(
        rib_rx.recv().await,
        Some(RibUpdate::RoutesReceived { ref announced, .. })
            if announced.iter().any(|route| route.prefix == Prefix::V4(first))
    ));
    assert!(matches!(
        rib_rx.recv().await,
        Some(RibUpdate::RouteRefreshTimeout {
            afi: Afi::Ipv4,
            safi: Safi::Unicast,
            ..
        })
    ));
    assert!(matches!(
        rib_rx.recv().await,
        Some(RibUpdate::RoutesReceived { ref announced, .. })
            if announced.iter().any(|route| route.prefix == Prefix::V4(second))
    ));
    let session = task.await.unwrap();
    assert!(!session.known_plain_prefixes.contains(&Prefix::V4(stale)));
    assert_eq!(session.known_prefix_count(), 2);
}

#[tokio::test]
async fn full_rib_channel_delays_marker_accounting_mutation_until_acceptance() {
    let (mut session, _cmd_tx, mut rib_rx) = make_test_session_with_channels(65001, 65002, 1);
    install_enhanced_refresh_session(&mut session, vec![(Afi::Ipv4, Safi::Unicast)], false);
    let prefix = Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, 0), 24));
    session.remember_known_path(prefix, 0);
    session
        .rib_tx
        .try_send(RibUpdate::BeginRouteRefresh {
            peer: session.peer_ip,
            session_id: session.session_identity.id,
            afi: Afi::Ipv6,
            safi: Safi::Unicast,
        })
        .unwrap();
    buffer_route_refresh(
        &mut session,
        Afi::Ipv4,
        Safi::Unicast,
        RouteRefreshSubtype::BoRR,
    );
    {
        let process = session.process_read_buffer();
        tokio::pin!(process);
        tokio::select! {
            () = tokio::task::yield_now() => {}
            () = &mut process => panic!("BoRR unexpectedly crossed a full RIB channel"),
        }
    }
    assert_eq!(
        session.refresh_accounting_window_count(),
        0,
        "BoRR must not open local accounting before RIB acceptance"
    );
    assert!(matches!(
        rib_rx.recv().await,
        Some(RibUpdate::BeginRouteRefresh { .. })
    ));
    buffer_route_refresh(
        &mut session,
        Afi::Ipv4,
        Safi::Unicast,
        RouteRefreshSubtype::BoRR,
    );
    session.process_read_buffer().await;
    assert!(session.refresh_accounting_has_window((Afi::Ipv4, Safi::Unicast)));
    assert!(matches!(
        rib_rx.recv().await,
        Some(RibUpdate::BeginRouteRefresh { .. })
    ));

    session
        .rib_tx
        .try_send(RibUpdate::BeginRouteRefresh {
            peer: session.peer_ip,
            session_id: session.session_identity.id,
            afi: Afi::Ipv6,
            safi: Safi::Unicast,
        })
        .unwrap();
    buffer_route_refresh(
        &mut session,
        Afi::Ipv4,
        Safi::Unicast,
        RouteRefreshSubtype::EoRR,
    );
    {
        let process = session.process_read_buffer();
        tokio::pin!(process);
        tokio::select! {
            () = tokio::task::yield_now() => {}
            () = &mut process => panic!("EoRR unexpectedly crossed a full RIB channel"),
        }
    }
    assert!(session.refresh_accounting_has_window((Afi::Ipv4, Safi::Unicast)));
    assert_eq!(
        session.known_prefix_count(),
        1,
        "EoRR must not sweep local accounting before RIB acceptance"
    );
    assert!(matches!(
        rib_rx.recv().await,
        Some(RibUpdate::BeginRouteRefresh { .. })
    ));
    buffer_route_refresh(
        &mut session,
        Afi::Ipv4,
        Safi::Unicast,
        RouteRefreshSubtype::EoRR,
    );
    session.process_read_buffer().await;
    assert_eq!(session.refresh_accounting_window_count(), 0);
    assert_eq!(session.known_prefix_count(), 0);
    assert!(matches!(
        rib_rx.recv().await,
        Some(RibUpdate::EndRouteRefresh { .. })
    ));
}

#[tokio::test]
async fn refresh_stale_routes_remain_conservatively_counted_until_boundary() {
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    let (client, _server) = connected_stream_pair().await;
    session.test_install_stream(client);
    establish_test_session(&mut session, 65002).await;
    while rib_rx.try_recv().is_ok() {}
    session.config.max_prefixes = Some(1);
    let stale = Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, 0), 24);
    session.remember_known_path(Prefix::V4(stale), 0);
    session.begin_refresh_accounting(Afi::Ipv4, Safi::Unicast);
    let new = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 0), 24);
    session.process_update(ipv4_announce(new, 0, false)).await;
    let post_overflow: Vec<_> = std::iter::from_fn(|| rib_rx.try_recv().ok()).collect();
    assert!(
        post_overflow
            .iter()
            .all(|update| !matches!(update, RibUpdate::RoutesReceived { .. })),
        "a new route at the exact cap must not receive transient ERR headroom"
    );
    assert!(
        post_overflow
            .iter()
            .any(|update| matches!(update, RibUpdate::PeerDown { .. })),
        "the overflow must deregister the established peer"
    );
    assert!(
        session.read_half.is_none(),
        "the stale route must still count, so the new prefix drives Cease teardown"
    );
    assert_eq!(session.known_prefix_count(), 0);
    assert_eq!(session.refresh_accounting_window_count(), 0);
}

#[tokio::test]
async fn failed_refresh_marker_sends_never_mutate_local_accounting_window() {
    let mut session = make_test_session(65001, 65002);
    install_enhanced_refresh_session(&mut session, vec![(Afi::Ipv4, Safi::Unicast)], false);
    let prefix = Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, 0), 24));
    session.remember_known_path(prefix, 0);
    buffer_route_refresh(
        &mut session,
        Afi::Ipv4,
        Safi::Unicast,
        RouteRefreshSubtype::BoRR,
    );
    session.process_read_buffer().await;
    assert_eq!(session.refresh_accounting_window_count(), 0);

    session.begin_refresh_accounting(Afi::Ipv4, Safi::Unicast);
    buffer_route_refresh(
        &mut session,
        Afi::Ipv4,
        Safi::Unicast,
        RouteRefreshSubtype::EoRR,
    );
    session.process_read_buffer().await;
    assert!(session.refresh_accounting_has_window((Afi::Ipv4, Safi::Unicast)));
    assert_eq!(session.known_prefix_count(), 1);
}

#[tokio::test]
async fn stray_eorr_is_a_local_noop_after_ordered_rib_acceptance() {
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    let (client, _server) = connected_stream_pair().await;
    session.test_install_stream(client);
    establish_test_session(&mut session, 65002).await;
    install_enhanced_refresh_session(&mut session, vec![(Afi::Ipv4, Safi::Unicast)], false);
    while rib_rx.try_recv().is_ok() {}
    let prefix = Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, 0), 24));
    session.remember_known_path(prefix, 0);

    buffer_route_refresh(
        &mut session,
        Afi::Ipv4,
        Safi::Unicast,
        RouteRefreshSubtype::EoRR,
    );
    session.process_read_buffer().await;
    assert!(matches!(
        rib_rx.try_recv(),
        Ok(RibUpdate::EndRouteRefresh {
            afi: Afi::Ipv4,
            safi: Safi::Unicast,
            ..
        })
    ));
    assert_eq!(session.refresh_accounting_window_count(), 0);
    assert_eq!(session.known_prefix_count(), 1);
    assert!(session.read_half.is_some());
}

/// Regression: `SessionDown` must clear `FlowSpec` and `EVPN` alongside unicast
/// accounting; otherwise reconnect inherits stale counts and can trip a false
/// max-prefix violation. Mutant: omitting either plain or Add-Path storage from
/// `clear_known_routes` leaves the corresponding assertion non-empty.
#[tokio::test]
async fn session_down_clears_all_known_sets() {
    let mut session = make_test_session(65001, 65002);
    let mut negotiated = negotiated_session(65002, false);
    negotiated.negotiated_families = vec![(Afi::Ipv4, Safi::Unicast), (Afi::Ipv6, Safi::Unicast)];
    negotiated
        .add_path_families
        .insert((Afi::Ipv6, Safi::Unicast), AddPathMode::Receive);
    negotiated.peer_gr_capable = true;
    negotiated
        .peer_capabilities
        .push(Capability::GracefulRestart {
            restart_state: false,
            notification: false,
            restart_time: 120,
            families: vec![],
        });
    install_test_negotiated_session(&mut session, negotiated);
    session.config.peer.graceful_restart = true;
    session.established_at = Some(Instant::now());
    let prefix = Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24));
    session.remember_known_path(prefix, 0);
    let add_path_prefix = Prefix::V6(Ipv6Prefix::new(Ipv6Addr::LOCALHOST, 128));
    session.remember_known_path(add_path_prefix, 0);
    let fs_prefix =
        rustbgpd_wire::FlowSpecPrefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24));
    session.known_flowspec.insert(rustbgpd_rib::FlowSpecKey {
        afi: Afi::Ipv4,
        rule: rustbgpd_wire::FlowSpecRule {
            components: vec![rustbgpd_wire::FlowSpecComponent::DestinationPrefix(
                fs_prefix,
            )],
        },
    });
    let evpn_key = rustbgpd_wire::EvpnRouteKey::Imet {
        rd: rustbgpd_wire::RouteDistinguisher([0, 0, 0xFD, 0xE8, 0, 0, 0, 1]),
        ethernet_tag: rustbgpd_wire::EthernetTagId(100),
        originator_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
    };
    session.known_evpn.insert(evpn_key);
    session
        .received_eor_families
        .insert((Afi::Ipv4, Safi::Unicast));
    session.begin_refresh_accounting(Afi::Ipv4, Safi::Unicast);
    assert!(session.known_prefix_count() >= 3);
    session.execute_actions(vec![Action::SessionDown]).await;
    assert!(
        session.known_plain_prefixes.is_empty(),
        "known_plain_prefixes must clear"
    );
    assert!(session.known_paths.is_empty(), "known_paths must clear");
    assert!(
        session.known_prefix_refcounts.is_empty(),
        "known_prefix_refcounts must clear"
    );
    assert!(
        session.known_flowspec.is_empty(),
        "known_flowspec must clear"
    );
    assert!(session.known_evpn.is_empty(), "known_evpn must clear");
    assert!(session.received_eor_families.is_empty());
    assert_eq!(session.refresh_accounting_window_count(), 0);
    assert!(session.refresh_accounting_timer.is_none());
    assert_eq!(session.known_prefix_count(), 0);
}

/// `OutboundRouteUpdate::request_refresh_all_negotiated` (the RIB
/// manager's failover-driven inbound recovery) emits a plain RFC 2918
/// ROUTE-REFRESH request on the wire for EVERY negotiated family when
/// the peer negotiated the capability. The family set is the session
/// task's `negotiated_families` — deliberately NOT the sendable subset
/// the manager sees in `PeerUp`: here IPv6 unicast stands in for a
/// family negotiated for receive but pruned from the sendable set (no
/// usable local IPv6 next-hop), and it MUST still be refreshed.
#[tokio::test]
async fn send_route_update_emits_route_refresh_requests_for_all_negotiated_families() {
    let (mut session, _rib_rx) = make_test_session_with_rib(65001, 65002);
    let (client, mut server) = connected_stream_pair().await;
    session.test_install_stream(client);
    let mut negotiated = negotiated_session(65002, false);
    negotiated.peer_route_refresh = true;
    negotiated.negotiated_families = vec![(Afi::Ipv4, Safi::Unicast), (Afi::Ipv6, Safi::Unicast)];
    session
        .negotiated_families
        .clone_from(&negotiated.negotiated_families);
    session.negotiated = Some(negotiated);
    session.send_route_update(OutboundRouteUpdate {
        exact_export_snapshot: None,
        announce_source_exclusion: None,
        otc_blocked: vec![],
        announce: vec![].into(),
        withdraw: vec![],
        end_of_rib: vec![],
        refresh_markers: vec![],
        next_hop_override: vec![].into(),
        flowspec_announce: vec![],
        flowspec_withdraw: vec![],
        evpn_announce: vec![],
        evpn_withdraw: vec![],
        bgpls_announce: vec![],
        bgpls_withdraw: vec![],
        vpn_announce: vec![],
        labeled_announce: vec![],
        rtc_announce: vec![],
        vpn_withdraw: vec![],
        labeled_withdraw: vec![],
        rtc_withdraw: vec![],
        request_refresh_all_negotiated: true,
        shared_group_encode: None,
    });
    let mut refreshed = Vec::new();
    for _ in 0..2 {
        let Message::RouteRefresh(rr) = read_single_bgp_message(&mut server).await else {
            panic!("expected ROUTE-REFRESH request");
        };
        assert_eq!(
            rr.subtype_raw, 0,
            "manager-initiated refresh must be a plain RFC 2918 request"
        );
        refreshed.push((rr.afi_raw, rr.safi_raw));
    }
    assert!(
        refreshed.contains(&(Afi::Ipv4 as u16, Safi::Unicast as u8)),
        "IPv4 unicast (negotiated) must be refreshed, got {refreshed:?}"
    );
    assert!(
        refreshed.contains(&(Afi::Ipv6 as u16, Safi::Unicast as u8)),
        "IPv6 unicast (negotiated but not necessarily sendable) must be \
         refreshed, got {refreshed:?}"
    );
}

/// Without the negotiated Route Refresh capability the request is
/// skipped (warned, not sent) — the rest of the update still goes out.
#[tokio::test]
async fn send_route_update_skips_route_refresh_request_without_capability() {
    let (mut session, _rib_rx) = make_test_session_with_rib(65001, 65002);
    let (client, mut server) = connected_stream_pair().await;
    session.test_install_stream(client);
    let negotiated = negotiated_session(65002, false);
    assert!(!negotiated.peer_route_refresh);
    session
        .negotiated_families
        .clone_from(&negotiated.negotiated_families);
    session.negotiated = Some(negotiated);
    session.send_route_update(OutboundRouteUpdate {
        exact_export_snapshot: Some(session.publish_export_profile()),
        announce_source_exclusion: None,
        otc_blocked: vec![],
        announce: vec![].into(),
        withdraw: vec![],
        end_of_rib: vec![(Afi::Ipv4, Safi::Unicast)],
        refresh_markers: vec![],
        next_hop_override: vec![].into(),
        flowspec_announce: vec![],
        flowspec_withdraw: vec![],
        evpn_announce: vec![],
        evpn_withdraw: vec![],
        bgpls_announce: vec![],
        bgpls_withdraw: vec![],
        vpn_announce: vec![],
        labeled_announce: vec![],
        rtc_announce: vec![],
        vpn_withdraw: vec![],
        labeled_withdraw: vec![],
        rtc_withdraw: vec![],
        request_refresh_all_negotiated: true,
        shared_group_encode: None,
    });
    // The first wire message must be the EoR UPDATE — no ROUTE-REFRESH
    // was emitted ahead of it.
    let Message::Update(msg) = read_single_bgp_message(&mut server).await else {
        panic!("expected the EoR UPDATE, not a ROUTE-REFRESH");
    };
    let parsed = msg.parse(true, false, &[]).unwrap();
    assert!(parsed.announced.is_empty());
    assert!(parsed.withdrawn.is_empty());
}
