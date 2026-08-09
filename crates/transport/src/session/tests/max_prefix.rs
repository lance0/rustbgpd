use super::*;

/// Mutant: selecting Add-Path accounting from `path_id != 0`, or treating
/// absent/Send negotiation as Receive, makes at least one storage tuple differ.
#[test]
fn negotiated_receive_direction_selects_unicast_accounting_storage() {
    for (mode, expected_storage) in [
        (None, (1, 0, 0, 0)),
        (Some(AddPathMode::Send), (1, 0, 0, 0)),
        (Some(AddPathMode::Receive), (0, 2, 1, 2)),
        (Some(AddPathMode::Both), (0, 2, 1, 2)),
    ] {
        let mut session = make_test_session(65001, 65002);
        let mut negotiated = negotiated_session(65002, false);
        if let Some(mode) = mode {
            negotiated
                .add_path_families
                .insert((Afi::Ipv4, Safi::Unicast), mode);
        }
        install_test_negotiated_session(&mut session, negotiated);
        let prefix = Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24));
        assert!(session.remember_known_path(prefix, 0));
        let second_inserted = session.remember_known_path(prefix, 7);
        assert_eq!(second_inserted, expected_storage.1 == 2, "mode {mode:?}");
        assert_eq!(
            session.known_unicast_storage_counts(),
            expected_storage,
            "mode {mode:?}"
        );
        assert_eq!(session.known_prefix_count(), 1, "mode {mode:?}");
    }
}

/// Mutant: removing tuple deduplication increments the Add-Path refcount for
/// the repeated identity and makes the refcount total three instead of two.
#[test]
fn known_prefix_count_deduplicates_multiple_add_paths() {
    let mut session = make_test_session(65001, 65002);
    let mut negotiated = negotiated_session(65002, false);
    negotiated
        .add_path_families
        .insert((Afi::Ipv4, Safi::Unicast), AddPathMode::Receive);
    install_test_negotiated_session(&mut session, negotiated);
    let prefix = Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24));
    assert!(session.remember_known_path(prefix, 0));
    assert!(session.remember_known_path(prefix, 2));
    assert!(
        !session.remember_known_path(prefix, 2),
        "duplicate path announcements must not bump the refcount"
    );
    assert_eq!(session.known_unicast_storage_counts(), (0, 2, 1, 2));
    assert_eq!(session.known_prefix_count(), 1);
}

/// Mutant: deleting the per-prefix Add-Path refcount, or removing the prefix
/// on the first path withdrawal, makes the intermediate count zero.
#[test]
fn known_prefix_refcount_tracks_add_path_withdrawals() {
    let mut session = make_test_session(65001, 65002);
    let mut negotiated = negotiated_session(65002, false);
    negotiated
        .add_path_families
        .insert((Afi::Ipv4, Safi::Unicast), AddPathMode::Both);
    install_test_negotiated_session(&mut session, negotiated);
    let prefix = Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24));
    session.remember_known_path(prefix, 0);
    session.remember_known_path(prefix, 2);
    assert_eq!(session.known_prefix_count(), 1);
    assert!(session.forget_known_path(prefix, 0));
    assert_eq!(
        session.known_prefix_count(),
        1,
        "withdrawing one Add-Path path keeps the prefix counted"
    );
    assert!(
        !session.forget_known_path(prefix, 0),
        "duplicate withdrawals must not decrement the refcount"
    );
    assert_eq!(session.known_prefix_count(), 1);
    assert!(session.forget_known_path(prefix, 2));
    assert_eq!(
        session.known_prefix_count(),
        0,
        "the last path withdrawal removes the unique prefix"
    );
}

/// Mutant: counting only the plain set or only the Add-Path refcount map makes
/// this mixed-family total smaller than the two unique prefixes.
#[test]
fn mixed_family_modes_share_one_unique_prefix_count() {
    let mut session = make_test_session(65001, 65002);
    let mut negotiated = negotiated_session(65002, false);
    negotiated.negotiated_families = vec![(Afi::Ipv4, Safi::Unicast), (Afi::Ipv6, Safi::Unicast)];
    negotiated
        .add_path_families
        .insert((Afi::Ipv4, Safi::Unicast), AddPathMode::Both);
    negotiated
        .add_path_families
        .insert((Afi::Ipv6, Safi::Unicast), AddPathMode::Send);
    install_test_negotiated_session(&mut session, negotiated);

    let v4 = Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24));
    let v6 = Prefix::V6(Ipv6Prefix::new(Ipv6Addr::LOCALHOST, 128));
    assert!(session.remember_known_path(v4, 0));
    assert!(session.remember_known_path(v4, 7));
    assert!(session.remember_known_path(v6, 99));
    assert!(!session.remember_known_path(v6, 100));

    assert_eq!(session.known_unicast_storage_counts(), (1, 2, 1, 2));
    assert_eq!(session.known_prefix_count(), 2);
}

#[tokio::test]
async fn add_path_multiplicity_counts_one_prefix_for_max_prefix() {
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    let (client, _server) = connected_stream_pair().await;
    session.test_install_stream(client);
    establish_test_session(&mut session, 65002).await;
    while rib_rx.try_recv().is_ok() {}
    session.config.max_prefixes = Some(1);
    let mut negotiated = negotiated_session(65002, true);
    negotiated
        .add_path_families
        .insert((Afi::Ipv4, Safi::Unicast), AddPathMode::Both);
    install_test_negotiated_session(&mut session, negotiated);
    let attrs = vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath {
            segments: vec![AsPathSegment::AsSequence(vec![65002])],
        }),
        PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
    ];
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24);
    let update = UpdateMessage::build(
        &[
            Ipv4NlriEntry { path_id: 1, prefix },
            Ipv4NlriEntry { path_id: 2, prefix },
        ],
        &[],
        &attrs,
        true,
        true,
        Ipv4UnicastMode::Body,
    );
    session.process_update(update).await;
    let RibUpdate::RoutesReceived { announced, .. } = rib_rx.try_recv().unwrap() else {
        panic!("expected same-prefix Add-Path routes to pass max-prefix");
    };
    assert_eq!(announced.len(), 2);
    assert_eq!(
        session.known_prefix_count(),
        1,
        "two Add-Path IDs for one prefix count as one unique prefix"
    );
    assert!(
        session.read_half.is_some(),
        "fixture must be connected before the over-limit update"
    );
    let second_prefix = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 0), 24);
    let update = UpdateMessage::build(
        &[Ipv4NlriEntry {
            path_id: 3,
            prefix: second_prefix,
        }],
        &[],
        &attrs,
        true,
        true,
        Ipv4UnicastMode::Body,
    );
    session.process_update(update).await;
    assert!(
        session.read_half.is_none(),
        "max-prefix overflow must drive the FSM teardown path"
    );
    assert_eq!(
        session.known_prefix_count(),
        0,
        "teardown must clear max-prefix accounting"
    );
}

/// Load-bearing metric proof: removing the ordinary UPDATE sync leaves the
/// announce/withdraw assertions stale; counting Add-Path IDs instead of unique
/// prefixes changes `1` to `2`; removing finite-to-unlimited child removal
/// leaves limit/headroom present after the runtime update.
#[tokio::test]
async fn max_prefix_capacity_metrics_follow_updates_and_runtime_limits() {
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    session.config.max_prefixes = Some(10);
    session.config.max_prefixes_ipv4 = Some(5);
    let (client, _server) = connected_stream_pair().await;
    session.test_install_stream(client);
    establish_test_session(&mut session, 65002).await;
    while rib_rx.try_recv().is_ok() {}
    install_dual_stack_session(&mut session, true);

    for scope in ["aggregate", "ipv4_unicast", "ipv6_unicast"] {
        assert_max_prefix_gauge(&session, "bgp_max_prefix_usage", scope, Some(0.0));
    }
    assert_max_prefix_gauge(&session, "bgp_max_prefix_limit", "aggregate", Some(10.0));
    assert_max_prefix_gauge(
        &session,
        "bgp_max_prefix_headroom",
        "ipv4_unicast",
        Some(5.0),
    );
    assert_max_prefix_gauge(&session, "bgp_max_prefix_limit", "ipv6_unicast", None);

    let prefix = v4_prefix(1);
    session.process_update(ipv4_announce(prefix, 1, true)).await;
    session.process_update(ipv4_announce(prefix, 2, true)).await;
    assert_max_prefix_gauge(&session, "bgp_max_prefix_usage", "aggregate", Some(1.0));
    assert_max_prefix_gauge(&session, "bgp_max_prefix_usage", "ipv4_unicast", Some(1.0));
    assert_max_prefix_gauge(
        &session,
        "bgp_max_prefix_headroom",
        "ipv4_unicast",
        Some(4.0),
    );

    session.process_update(ipv4_withdraw(prefix, 1, true)).await;
    assert_max_prefix_gauge(&session, "bgp_max_prefix_usage", "ipv4_unicast", Some(1.0));
    session.process_update(ipv4_withdraw(prefix, 2, true)).await;
    assert_max_prefix_gauge(&session, "bgp_max_prefix_usage", "aggregate", Some(0.0));
    assert_max_prefix_gauge(&session, "bgp_max_prefix_usage", "ipv4_unicast", Some(0.0));

    let (reply, done) = oneshot::channel();
    assert_eq!(
        session
            .handle_command(PeerCommand::UpdateRuntimeConfig {
                max_prefixes: None,
                max_prefixes_ipv4: None,
                max_prefixes_ipv6: None,
                gr_stale_routes_time: session.config.gr_stale_routes_time,
                gr_peer_restart_time_max: session.config.gr_peer_restart_time_max,
                local_ipv6_nexthop: session.config.local_ipv6_nexthop,
                remove_private_as: session.config.remove_private_as,
                reply,
            })
            .await,
        ControlFlow::Continue(())
    );
    done.await.unwrap().unwrap();
    for scope in ["aggregate", "ipv4_unicast", "ipv6_unicast"] {
        assert_max_prefix_gauge(&session, "bgp_max_prefix_usage", scope, Some(0.0));
        assert_max_prefix_gauge(&session, "bgp_max_prefix_limit", scope, None);
        assert_max_prefix_gauge(&session, "bgp_max_prefix_headroom", scope, None);
    }
}

/// Load-bearing lifecycle proof: replacing the `SessionDown` reap with zeroes
/// leaves a live series while disconnected, and removing the Established sync
/// leaves the reconnect snapshot absent rather than freshly zeroed.
#[tokio::test]
async fn max_prefix_capacity_metrics_reap_on_down_and_republish_on_reconnect() {
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    session.config.max_prefixes = Some(10);
    let (client, _server) = connected_stream_pair().await;
    session.test_install_stream(client);
    establish_test_session(&mut session, 65002).await;
    while rib_rx.try_recv().is_ok() {}
    session
        .process_update(ipv4_announce(v4_prefix(1), 0, false))
        .await;
    assert_max_prefix_gauge(&session, "bgp_max_prefix_usage", "aggregate", Some(1.0));

    session.drive_fsm(Event::ManualStop { reason: None }).await;
    assert_eq!(session.fsm.state(), SessionState::Idle);
    assert_max_prefix_gauge(&session, "bgp_max_prefix_usage", "aggregate", None);
    assert_max_prefix_gauge(&session, "bgp_max_prefix_limit", "aggregate", None);
    assert_max_prefix_gauge(&session, "bgp_max_prefix_headroom", "aggregate", None);

    let (client, _server) = connected_stream_pair().await;
    session.test_install_stream(client);
    establish_test_session(&mut session, 65002).await;
    assert_max_prefix_gauge(&session, "bgp_max_prefix_usage", "aggregate", Some(0.0));
    assert_max_prefix_gauge(&session, "bgp_max_prefix_limit", "aggregate", Some(10.0));
    assert_max_prefix_gauge(&session, "bgp_max_prefix_headroom", "aggregate", Some(10.0));
}

/// Load-bearing collision-loser proof: allowing an inbound candidate to own
/// or reap the shared label changes the primary's exact `2` usage or removes
/// it when the losing candidate drops.
#[tokio::test]
async fn collision_candidate_cannot_overwrite_or_reap_primary_capacity_metrics() {
    let metrics = BgpMetrics::new();
    let (mut primary, mut primary_rib_rx) =
        make_test_session_with_metrics_and_identity(metrics.clone(), SessionIdentity::primary(1));
    let (mut candidate, mut candidate_rib_rx) =
        make_test_session_with_metrics_and_identity(metrics, SessionIdentity::inbound_candidate(2));
    let (primary_client, _primary_server) = connected_stream_pair().await;
    primary.test_install_stream(primary_client);
    establish_test_session(&mut primary, 65002).await;
    while primary_rib_rx.try_recv().is_ok() {}
    primary
        .process_update(ipv4_announce(v4_prefix(1), 0, false))
        .await;
    primary
        .process_update(ipv4_announce(v4_prefix(2), 0, false))
        .await;
    assert_eq!(
        peer_truth_gauge(
            &primary.metrics,
            "bgp_peer_session_established",
            &primary.peer_label,
            ""
        ),
        Some(1.0)
    );

    let (candidate_client, _candidate_server) = connected_stream_pair().await;
    candidate.test_install_stream(candidate_client);
    establish_test_session(&mut candidate, 65002).await;
    while candidate_rib_rx.try_recv().is_ok() {}
    candidate
        .process_update(ipv4_announce(v4_prefix(3), 0, false))
        .await;
    assert_max_prefix_gauge(&primary, "bgp_max_prefix_usage", "aggregate", Some(2.0));
    assert_eq!(
        peer_truth_gauge(
            &primary.metrics,
            "bgp_peer_session_established",
            &primary.peer_label,
            ""
        ),
        Some(1.0),
        "inactive candidate must not overwrite active-primary truth"
    );

    drop(candidate);
    assert_max_prefix_gauge(&primary, "bgp_max_prefix_usage", "aggregate", Some(2.0));
    assert_eq!(
        peer_truth_gauge(
            &primary.metrics,
            "bgp_peer_session_established",
            &primary.peer_label,
            ""
        ),
        Some(1.0),
        "dropping an inactive candidate must not zero active-primary truth"
    );
}

/// Load-bearing promoted-actor proof: removing either the activation command's
/// ownership flip or its synchronous snapshot leaves the exact `1` usage and
/// `9` headroom absent. `PeerManager` ordering is covered by its production-path
/// collision test.
#[tokio::test]
async fn promoted_collision_candidate_publishes_after_old_primary_quiesces() {
    let metrics = BgpMetrics::new();
    let (mut primary, mut primary_rib_rx) =
        make_test_session_with_metrics_and_identity(metrics.clone(), SessionIdentity::primary(1));
    let (mut candidate, mut candidate_rib_rx) =
        make_test_session_with_metrics_and_identity(metrics, SessionIdentity::inbound_candidate(2));
    let (primary_client, _primary_server) = connected_stream_pair().await;
    primary.test_install_stream(primary_client);
    establish_test_session(&mut primary, 65002).await;
    while primary_rib_rx.try_recv().is_ok() {}
    primary
        .process_update(ipv4_announce(v4_prefix(1), 0, false))
        .await;
    primary
        .process_update(ipv4_announce(v4_prefix(2), 0, false))
        .await;

    let (candidate_client, _candidate_server) = connected_stream_pair().await;
    candidate.test_install_stream(candidate_client);
    establish_test_session(&mut candidate, 65002).await;
    while candidate_rib_rx.try_recv().is_ok() {}
    candidate
        .process_update(ipv4_announce(v4_prefix(3), 0, false))
        .await;

    drop(primary);
    assert_max_prefix_gauge(&candidate, "bgp_max_prefix_usage", "aggregate", None);
    assert_eq!(
        peer_truth_gauge(
            &candidate.metrics,
            "bgp_peer_session_established",
            &candidate.peer_label,
            ""
        ),
        Some(0.0),
        "retiring primary must publish zero before ownership transfer"
    );
    let (reply, done) = oneshot::channel();
    assert_eq!(
        candidate
            .handle_command(PeerCommand::ActivateMaxPrefixMetrics { reply })
            .await,
        ControlFlow::Continue(())
    );
    done.await.unwrap();
    assert_eq!(
        peer_truth_gauge(
            &candidate.metrics,
            "bgp_peer_session_established",
            &candidate.peer_label,
            ""
        ),
        Some(1.0),
        "promotion must synchronously publish the candidate FSM snapshot"
    );
    assert_max_prefix_gauge(&candidate, "bgp_max_prefix_usage", "aggregate", Some(1.0));
    assert_max_prefix_gauge(
        &candidate,
        "bgp_max_prefix_headroom",
        "aggregate",
        Some(9.0),
    );
}

/// Load-bearing refresh proof: removing the post-sweep metric sync leaves
/// usage at `2` after `EoRR` and at `2` after timeout instead of the exact `1`
/// then `0` snapshots below.
#[tokio::test(start_paused = true)]
async fn max_prefix_capacity_metrics_follow_eorr_and_timeout_reconciliation() {
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    session.config.max_prefixes = Some(10);
    session.config.max_prefixes_ipv4 = Some(5);
    let (client, _server) = connected_stream_pair().await;
    session.test_install_stream(client);
    establish_test_session(&mut session, 65002).await;
    while rib_rx.try_recv().is_ok() {}
    install_enhanced_refresh_session(&mut session, vec![(Afi::Ipv4, Safi::Unicast)], false);

    let replayed = v4_prefix(1);
    let omitted = v4_prefix(2);
    session
        .process_update(ipv4_announce(replayed, 0, false))
        .await;
    session
        .process_update(ipv4_announce(omitted, 0, false))
        .await;
    while rib_rx.try_recv().is_ok() {}
    session.begin_refresh_accounting(Afi::Ipv4, Safi::Unicast);
    session
        .process_update(ipv4_announce(replayed, 0, false))
        .await;
    session.end_refresh_accounting(Afi::Ipv4, Safi::Unicast);
    assert_max_prefix_gauge(&session, "bgp_max_prefix_usage", "aggregate", Some(1.0));
    assert_max_prefix_gauge(
        &session,
        "bgp_max_prefix_headroom",
        "ipv4_unicast",
        Some(4.0),
    );

    session
        .process_update(ipv4_announce(omitted, 0, false))
        .await;
    while rib_rx.try_recv().is_ok() {}
    session.begin_refresh_accounting(Afi::Ipv4, Safi::Unicast);
    tokio::time::advance(rustbgpd_rib::ERR_REFRESH_TIMEOUT).await;
    session.expire_refresh_accounting_windows().await.unwrap();
    assert!(matches!(
        rib_rx.try_recv(),
        Ok(RibUpdate::RouteRefreshTimeout {
            afi: Afi::Ipv4,
            safi: Safi::Unicast,
            ..
        })
    ));
    assert_max_prefix_gauge(&session, "bgp_max_prefix_usage", "aggregate", Some(0.0));
    assert_max_prefix_gauge(
        &session,
        "bgp_max_prefix_headroom",
        "ipv4_unicast",
        Some(5.0),
    );
}

/// Mutant: dropping the `max_prefixes_ipv4` check (or counting v6 into the
/// v4 budget) keeps the session up past the v4 bound; encoding the wrong
/// AFI/SAFI/bound corrupts the RFC 4486 Cease data.
#[tokio::test]
async fn per_family_max_prefix_limits_enforce_independently() {
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    let (client, mut server) = connected_stream_pair().await;
    session.test_install_stream(client);
    establish_test_session(&mut session, 65002).await;
    while rib_rx.try_recv().is_ok() {}
    session.config.max_prefixes_ipv4 = Some(2);
    session.config.max_prefixes_ipv6 = Some(1);
    install_dual_stack_session(&mut session, false);

    // v6 at its limit, v4 at its limit: both families full, session alive.
    session.process_update(ipv6_announce(v6_prefix(1), 0)).await;
    session
        .process_update(ipv4_announce(v4_prefix(1), 0, false))
        .await;
    session
        .process_update(ipv4_announce(v4_prefix(2), 0, false))
        .await;
    assert!(
        session.read_half.is_some(),
        "both families at their exact limits must not tear down"
    );
    assert_eq!(session.known_unicast_v4, 2);
    assert_eq!(session.known_unicast_v6, 1);

    // One more v4 route exceeds only the v4 bound.
    session
        .process_update(ipv4_announce(v4_prefix(3), 0, false))
        .await;
    assert!(
        session.read_half.is_none(),
        "exceeding the v4 bound must tear the session down"
    );
    let notif = read_until_notification(&mut server).await;
    assert_eq!(notif.code, NotificationCode::Cease);
    assert_eq!(notif.subcode, cease_subcode::MAX_PREFIXES);
    assert_eq!(
        notif.data.as_ref(),
        max_prefix_cease_data(Afi::Ipv4, Safi::Unicast, 2).as_slice(),
        "Cease/1 data must carry the exceeding family's AFI, SAFI, and bound"
    );
    // Session reset clears per-family accounting like the aggregate's.
    assert_eq!(session.known_unicast_v4, 0);
    assert_eq!(session.known_unicast_v6, 0);
    assert_eq!(session.known_prefix_count(), 0);
}

/// Load-bearing proof for the max-prefix shutdown contract:
///
/// - removing `stop_requested = true` arms the reconnect timer on Idle;
/// - removing the lossless notification leaves the manager without the exact
///   generation/family/count/bound needed to latch passive paths;
/// - emitting bare Cease/1 with the N-bit retains the offending routes through
///   Notification GR instead of producing `PeerDown`;
/// - dropping RFC 8538 encapsulation loses the original Cease/1 reason/data.
#[tokio::test]
async fn max_prefix_with_notification_gr_latches_and_sends_encapsulated_hard_reset() {
    let mut peer_config = PeerConfig::new(65001, 65002, Ipv4Addr::new(10, 0, 0, 1));
    peer_config.connect_retry_secs = 1;
    peer_config.families = vec![(Afi::Ipv4, Safi::Unicast)];
    peer_config.graceful_restart = true;
    let mut config = TransportConfig::new(peer_config, "10.0.0.2:179".parse().unwrap());
    config.max_prefixes_ipv4 = Some(1);
    let (_cmd_tx, cmd_rx) = mpsc::channel(8);
    let (rib_tx, mut rib_rx) = mpsc::channel(64);
    let (notify_tx, mut notify_rx) = mpsc::unbounded_channel();
    let mut session = PeerSession::new_with_identity_and_lifecycle(
        config,
        BgpMetrics::new(),
        cmd_rx,
        rib_tx,
        None,
        None,
        Some(notify_tx),
        None,
        None,
        None,
        None,
        false,
        SessionIdentity::primary(77),
    );
    let (client, mut server) = connected_stream_pair().await;
    session.test_install_stream(client);
    establish_test_session(&mut session, 65002).await;
    while rib_rx.try_recv().is_ok() {}
    while notify_rx.try_recv().is_ok() {}

    let mut negotiated = negotiated_session(65002, false);
    negotiated.peer_gr_capable = true;
    negotiated.peer_notification_gr = true;
    negotiated.peer_restart_time = 120;
    negotiated.peer_gr_families = vec![rustbgpd_wire::GracefulRestartFamily {
        afi: Afi::Ipv4,
        safi: Safi::Unicast,
        forwarding_preserved: false,
    }];
    install_test_negotiated_session(&mut session, negotiated);

    session
        .process_update(ipv4_announce(v4_prefix(1), 0, false))
        .await;
    while rib_rx.try_recv().is_ok() {}
    session
        .process_update(ipv4_announce(v4_prefix(2), 0, false))
        .await;

    assert!(
        session.stop_requested,
        "max-prefix must latch local restart off"
    );
    assert!(
        session.reconnect_timer.is_none(),
        "Idle transition must not arm deferred reconnect after max-prefix"
    );
    assert!(matches!(
        notify_rx.try_recv(),
        Ok(SessionNotification::MaxPrefixExceeded {
            session_id: 77,
            role: crate::SessionRole::Primary,
            count: 2,
            bound: 1,
            family: Some((Afi::Ipv4, Safi::Unicast)),
            ..
        })
    ));

    let notification = read_until_notification(&mut server).await;
    assert_eq!(notification.code, NotificationCode::Cease);
    assert_eq!(notification.subcode, cease_subcode::HARD_RESET);
    let mut encapsulated = vec![NotificationCode::Cease.as_u8(), cease_subcode::MAX_PREFIXES];
    encapsulated.extend_from_slice(&max_prefix_cease_data(Afi::Ipv4, Safi::Unicast, 1));
    assert_eq!(notification.data.as_ref(), encapsulated.as_slice());
    assert!(matches!(rib_rx.try_recv(), Ok(RibUpdate::PeerDown { .. })));
    assert!(
        !matches!(rib_rx.try_recv(), Ok(RibUpdate::PeerGracefulRestart { .. })),
        "Hard Reset must not retain over-limit routes through GR"
    );
}

/// Mutant: charging v6 unicast routes against `max_prefixes_ipv4` (a single
/// shared counter) tears down before the v4 family used any of its budget.
#[tokio::test]
async fn one_family_cannot_consume_the_other_families_budget() {
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    let (client, mut server) = connected_stream_pair().await;
    session.test_install_stream(client);
    establish_test_session(&mut session, 65002).await;
    while rib_rx.try_recv().is_ok() {}
    session.config.max_prefixes_ipv4 = Some(10);
    install_dual_stack_session(&mut session, false);

    for index in 1..=10 {
        session
            .process_update(ipv6_announce(v6_prefix(index), 0))
            .await;
    }
    assert!(
        session.read_half.is_some(),
        "unlimited v6 routes must not consume the v4 budget"
    );
    for index in 1..=10 {
        session
            .process_update(ipv4_announce(v4_prefix(index), 0, false))
            .await;
    }
    assert!(
        session.read_half.is_some(),
        "v4 must retain its full headroom after 10 v6 routes"
    );
    session
        .process_update(ipv4_announce(v4_prefix(11), 0, false))
        .await;
    assert!(
        session.read_half.is_none(),
        "11th v4 route exceeds the bound"
    );
    let notif = read_until_notification(&mut server).await;
    assert_eq!(notif.subcode, cease_subcode::MAX_PREFIXES);
    assert_eq!(
        notif.data.as_ref(),
        max_prefix_cease_data(Afi::Ipv4, Safi::Unicast, 10).as_slice()
    );
}

/// Mutant: counting Add-Path multiplicity (paths instead of unique prefixes)
/// against the per-family bound diverges from the aggregate's pinned
/// unique-prefix semantics and tears down on the first UPDATE.
#[tokio::test]
async fn per_family_limit_counts_unique_prefixes_under_add_path() {
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    let (client, mut server) = connected_stream_pair().await;
    session.test_install_stream(client);
    establish_test_session(&mut session, 65002).await;
    while rib_rx.try_recv().is_ok() {}
    session.config.max_prefixes_ipv4 = Some(1);
    install_dual_stack_session(&mut session, true);

    let prefix = v4_prefix(1);
    session.process_update(ipv4_announce(prefix, 1, true)).await;
    session.process_update(ipv4_announce(prefix, 2, true)).await;
    assert!(
        session.read_half.is_some(),
        "two Add-Path IDs of one prefix count once against the per-family bound"
    );
    assert_eq!(session.known_unicast_v4, 1);

    session
        .process_update(ipv4_announce(v4_prefix(2), 3, true))
        .await;
    assert!(session.read_half.is_none());
    let notif = read_until_notification(&mut server).await;
    assert_eq!(notif.subcode, cease_subcode::MAX_PREFIXES);
    assert_eq!(
        notif.data.as_ref(),
        max_prefix_cease_data(Afi::Ipv4, Safi::Unicast, 1).as_slice()
    );
}

/// Mutant: double-counting a duplicate announcement, or failing to decrement
/// on withdrawal, falsely trips the bound at the boundary.
#[tokio::test]
async fn per_family_boundary_survives_duplicates_and_withdraw_reannounce() {
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    let (client, mut server) = connected_stream_pair().await;
    session.test_install_stream(client);
    establish_test_session(&mut session, 65002).await;
    while rib_rx.try_recv().is_ok() {}
    session.config.max_prefixes_ipv4 = Some(2);
    install_dual_stack_session(&mut session, false);

    session
        .process_update(ipv4_announce(v4_prefix(1), 0, false))
        .await;
    session
        .process_update(ipv4_announce(v4_prefix(2), 0, false))
        .await;
    // Duplicate announcement at the boundary must not double-count.
    session
        .process_update(ipv4_announce(v4_prefix(2), 0, false))
        .await;
    assert!(
        session.read_half.is_some(),
        "duplicate announcement at the bound must not tear down"
    );
    assert_eq!(session.known_unicast_v4, 2);

    // Withdrawal frees budget for a re-announcement at the boundary.
    session
        .process_update(ipv4_withdraw(v4_prefix(1), 0, false))
        .await;
    assert_eq!(session.known_unicast_v4, 1);
    session
        .process_update(ipv4_announce(v4_prefix(3), 0, false))
        .await;
    assert!(
        session.read_half.is_some(),
        "withdraw-then-announce at the bound must not tear down"
    );

    session
        .process_update(ipv4_announce(v4_prefix(4), 0, false))
        .await;
    assert!(session.read_half.is_none(), "one past the bound tears down");
    let notif = read_until_notification(&mut server).await;
    assert_eq!(notif.subcode, cease_subcode::MAX_PREFIXES);
}

/// Mutant: sweeping ERR stale plain prefixes without decrementing the
/// per-family counter leaves phantom v4 budget consumption; the post-EoRR
/// announcement then falsely exceeds `max_prefixes_ipv4`. Mirrors the
/// aggregate's `eorr_reconciles_omitted_prefix_before_later_max_prefix_check`.
#[tokio::test]
async fn eorr_reconciles_per_family_accounting_before_later_check() {
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    install_enhanced_refresh_session(&mut session, vec![(Afi::Ipv4, Safi::Unicast)], false);
    session.config.max_prefixes_ipv4 = Some(2);
    let replayed = v4_prefix(1);
    let omitted = v4_prefix(2);
    session.remember_known_path(Prefix::V4(replayed), 0);
    session.remember_known_path(Prefix::V4(omitted), 0);
    assert_eq!(session.known_unicast_v4, 2);

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
    assert_eq!(
        session.known_unicast_v4, 1,
        "EoRR sweep must release the omitted prefix's per-family budget"
    );

    session
        .process_update(ipv4_announce(v4_prefix(3), 0, false))
        .await;
    assert!(
        matches!(rib_rx.try_recv(), Ok(RibUpdate::RoutesReceived { .. })),
        "post-EoRR announcement within the reconciled bound must be accepted"
    );
    assert_eq!(session.known_unicast_v4, 2);
}

/// Mutant: dropping the immediate evaluation on `UpdateRuntimeConfig` leaves
/// a quiet peer holding more routes than the operator's new per-family bound
/// until its next UPDATE.
#[tokio::test]
async fn runtime_lowering_per_family_limit_enforces_immediately() {
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    let (client, mut server) = connected_stream_pair().await;
    session.test_install_stream(client);
    establish_test_session(&mut session, 65002).await;
    while rib_rx.try_recv().is_ok() {}
    install_dual_stack_session(&mut session, false);
    for index in 1..=3 {
        session
            .process_update(ipv4_announce(v4_prefix(index), 0, false))
            .await;
    }
    assert!(session.read_half.is_some());

    let (reply, done) = oneshot::channel();
    assert_eq!(
        session
            .handle_command(PeerCommand::UpdateRuntimeConfig {
                max_prefixes: None,
                max_prefixes_ipv4: Some(1),
                max_prefixes_ipv6: None,
                gr_stale_routes_time: 360,
                gr_peer_restart_time_max: 4095,
                local_ipv6_nexthop: None,
                remove_private_as: RemovePrivateAs::Disabled,
                reply,
            })
            .await,
        ControlFlow::Continue(())
    );
    done.await.unwrap().unwrap();
    assert!(
        session.read_half.is_none(),
        "lowering max_prefixes_ipv4 below the current count must tear down immediately"
    );
    let notif = read_until_notification(&mut server).await;
    assert_eq!(notif.code, NotificationCode::Cease);
    assert_eq!(notif.subcode, cease_subcode::MAX_PREFIXES);
    assert_eq!(
        notif.data.as_ref(),
        max_prefix_cease_data(Afi::Ipv4, Safi::Unicast, 1).as_slice()
    );
}

/// Pins the aggregate's documented hot-apply semantics (ADR-0108): lowering
/// the legacy `max_prefixes` below the current count trips on the NEXT
/// received UPDATE, not on apply.
#[tokio::test]
async fn runtime_lowering_aggregate_limit_keeps_next_update_semantics() {
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    let (client, mut server) = connected_stream_pair().await;
    session.test_install_stream(client);
    establish_test_session(&mut session, 65002).await;
    while rib_rx.try_recv().is_ok() {}
    install_dual_stack_session(&mut session, false);
    session
        .process_update(ipv4_announce(v4_prefix(1), 0, false))
        .await;
    session
        .process_update(ipv4_announce(v4_prefix(2), 0, false))
        .await;

    let (reply, done) = oneshot::channel();
    assert_eq!(
        session
            .handle_command(PeerCommand::UpdateRuntimeConfig {
                max_prefixes: Some(1),
                max_prefixes_ipv4: None,
                max_prefixes_ipv6: None,
                gr_stale_routes_time: 360,
                gr_peer_restart_time_max: 4095,
                local_ipv6_nexthop: None,
                remove_private_as: RemovePrivateAs::Disabled,
                reply,
            })
            .await,
        ControlFlow::Continue(())
    );
    done.await.unwrap().unwrap();
    assert!(
        session.read_half.is_some(),
        "aggregate lowering must not enforce until the next UPDATE"
    );

    session
        .process_update(ipv4_announce(v4_prefix(3), 0, false))
        .await;
    assert!(session.read_half.is_none());
    let notif = read_until_notification(&mut server).await;
    assert_eq!(notif.subcode, cease_subcode::MAX_PREFIXES);
    assert!(
        notif.data.is_empty(),
        "aggregate Cease/1 keeps its historical empty data"
    );
}

/// Regression pin: with only the legacy aggregate configured, behavior is
/// unchanged — teardown at the same point, empty NOTIFICATION data.
#[tokio::test]
async fn aggregate_max_prefix_alone_behaves_as_before() {
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    let (client, mut server) = connected_stream_pair().await;
    session.test_install_stream(client);
    establish_test_session(&mut session, 65002).await;
    while rib_rx.try_recv().is_ok() {}
    session.config.max_prefixes = Some(2);
    install_dual_stack_session(&mut session, false);

    session
        .process_update(ipv4_announce(v4_prefix(1), 0, false))
        .await;
    session.process_update(ipv6_announce(v6_prefix(1), 0)).await;
    assert!(session.read_half.is_some(), "at the aggregate bound: alive");
    session.process_update(ipv6_announce(v6_prefix(2), 0)).await;
    assert!(
        session.read_half.is_none(),
        "aggregate counts across families exactly as before"
    );
    let notif = read_until_notification(&mut server).await;
    assert_eq!(notif.code, NotificationCode::Cease);
    assert_eq!(notif.subcode, cease_subcode::MAX_PREFIXES);
    assert!(notif.data.is_empty(), "aggregate Cease/1 data stays empty");
}

/// Regression: max-prefix enforcement must count EVPN keys (and `FlowSpec`
/// rules) alongside unicast prefixes. Prior to the fix, `known_prefix_count`
/// only counted unique unicast prefixes, so a peer could flood arbitrary
/// EVPN routes without tripping the configured cap.
#[tokio::test]
async fn evpn_routes_counted_toward_max_prefix() {
    use rustbgpd_wire::{
        EthernetSegmentIdentifier, EthernetTagId, EvpnMacIp, EvpnRoute, MacAddress, MpReachNlri,
        MplsLabel, RouteDistinguisher,
    };
    let (mut session, _rib_rx) = make_test_session_with_rib(65001, 65001);
    let (client, _server) = connected_stream_pair().await;
    session.test_install_stream(client);
    establish_test_session(&mut session, 65001).await;
    session.config.max_prefixes = Some(2);
    let mut negotiated = NegotiatedSession::default();
    negotiated.peer_asn = 65001;
    negotiated.peer_router_id = Ipv4Addr::new(10, 0, 0, 2);
    negotiated.hold_time = 90;
    negotiated.keepalive_interval = 30;
    negotiated.four_octet_as = true;
    negotiated.negotiated_families = vec![(Afi::L2Vpn, Safi::Evpn)];
    session
        .negotiated_families
        .clone_from(&negotiated.negotiated_families);
    session.negotiated = Some(negotiated);
    let make_route = |mac_lo: u8| -> EvpnRoute {
        EvpnRoute::MacIp(EvpnMacIp {
            rd: RouteDistinguisher([0, 0, 0xFD, 0xE8, 0, 0, 0, 100]),
            esi: EthernetSegmentIdentifier::ZERO,
            ethernet_tag: EthernetTagId(100),
            mac: MacAddress([0x02, 0x00, 0x00, 0xAA, 0xBB, mac_lo]),
            ip: None,
            label1: MplsLabel::new(10_000),
            label2: None,
        })
    };
    let send_announces = |routes: Vec<EvpnRoute>| {
        let attrs = vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath { segments: vec![] }),
            PathAttribute::MpReachNlri(MpReachNlri {
                afi: Afi::L2Vpn,
                safi: Safi::Evpn,
                next_hop: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
                link_local_next_hop: None,
                announced: vec![],
                flowspec_announced: vec![],
                evpn_announced: routes,
                bgpls_announced: vec![],
                labeled_announced: vec![],
                vpn_announced: vec![],
                rtc_announced: vec![],
            }),
        ];
        UpdateMessage::build(&[], &[], &attrs, true, false, Ipv4UnicastMode::MpReach)
    };
    // Push 2 EVPN routes — at the limit, should not trip.
    session
        .process_update(send_announces(vec![make_route(0x01), make_route(0x02)]))
        .await;
    assert_eq!(
        session.known_prefix_count(),
        2,
        "EVPN routes must contribute to the prefix count"
    );
    assert!(
        session.read_half.is_some(),
        "fixture must be connected before the over-limit update"
    );
    // Push a 3rd — must exceed max_prefixes = 2.
    session
        .process_update(send_announces(vec![make_route(0x03)]))
        .await;
    assert!(
        session.read_half.is_none(),
        "max-prefix overflow must drive the FSM teardown path"
    );
    assert_eq!(
        session.known_prefix_count(),
        0,
        "teardown must clear max-prefix accounting"
    );
}

/// Max-prefix enforcement must count RTC membership NLRI alongside the
/// other families.
#[tokio::test]
async fn rtc_routes_counted_toward_max_prefix() {
    use rustbgpd_wire::{MpReachNlri, RtcNlri};
    let (mut session, _rib_rx) = make_test_session_with_rib(65001, 65001);
    let (client, _server) = connected_stream_pair().await;
    session.test_install_stream(client);
    establish_test_session(&mut session, 65001).await;
    session.config.max_prefixes = Some(2);
    let mut negotiated = NegotiatedSession::default();
    negotiated.peer_asn = 65001;
    negotiated.peer_router_id = Ipv4Addr::new(10, 0, 0, 2);
    negotiated.hold_time = 90;
    negotiated.keepalive_interval = 30;
    negotiated.four_octet_as = true;
    negotiated.negotiated_families = vec![(Afi::Ipv4, Safi::RtConstrain)];
    session
        .negotiated_families
        .clone_from(&negotiated.negotiated_families);
    session.negotiated = Some(negotiated);
    let make_nlri = |admin: u64| RtcNlri::new(65001, 0x0002_FDE9_0000_0000 | admin, 96).unwrap();
    let send_announces = |nlris: Vec<RtcNlri>| {
        let attrs = vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath { segments: vec![] }),
            PathAttribute::MpReachNlri(MpReachNlri {
                afi: Afi::Ipv4,
                safi: Safi::RtConstrain,
                next_hop: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
                link_local_next_hop: None,
                announced: vec![],
                flowspec_announced: vec![],
                evpn_announced: vec![],
                bgpls_announced: vec![],
                labeled_announced: vec![],
                vpn_announced: vec![],
                rtc_announced: nlris,
            }),
        ];
        UpdateMessage::build(&[], &[], &attrs, true, false, Ipv4UnicastMode::MpReach)
    };
    session
        .process_update(send_announces(vec![make_nlri(1), make_nlri(2)]))
        .await;
    assert_eq!(
        session.known_prefix_count(),
        2,
        "RTC routes must contribute to the prefix count"
    );
    assert!(session.read_half.is_some());
    session
        .process_update(send_announces(vec![make_nlri(3)]))
        .await;
    assert!(
        session.read_half.is_none(),
        "max-prefix overflow must drive the FSM teardown path"
    );
    assert_eq!(
        session.known_prefix_count(),
        0,
        "teardown must clear max-prefix accounting"
    );
}
