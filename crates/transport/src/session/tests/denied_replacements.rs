use super::*;

#[tokio::test]
async fn denied_classic_replacement_withdraws_exact_route_and_remains_explainable() {
    use super::import_decision_cache::{CachedOutcome, ImportDecisionKey, LookupResult};

    let mut peer_config = PeerConfig::new(65001, 65002, Ipv4Addr::new(10, 0, 0, 1));
    peer_config.connect_retry_secs = 30;
    peer_config.families = vec![(Afi::Ipv4, Safi::Unicast)];
    peer_config.gr_restart_time = 120;
    let mut config = TransportConfig::new(peer_config, "10.0.0.2:179".parse().unwrap());
    config.explain_enabled = true;
    let metrics = BgpMetrics::new();
    let (_cmd_tx, cmd_rx) = mpsc::channel(8);
    let (rib_tx, mut rib_rx) = mpsc::channel(64);
    let mut session = PeerSession::new(
        config, metrics, cmd_rx, rib_tx, None, None, None, None, None, false,
    );
    session.negotiated = Some(negotiated_session(65002, false));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24);
    let attrs = vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath {
            segments: vec![AsPathSegment::AsSequence(vec![65002])],
        }),
        PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
    ];
    let update = UpdateMessage::build(
        &[Ipv4NlriEntry { path_id: 0, prefix }],
        &[],
        &attrs,
        true,
        false,
        Ipv4UnicastMode::Body,
    );
    session.process_update(update.clone()).await;
    let RibUpdate::RoutesReceived { announced, .. } = rib_rx.try_recv().unwrap() else {
        panic!("expected first RoutesReceived");
    };
    assert_eq!(announced.len(), 1);
    let deny_chain = PolicyChain::new(vec![Policy {
        entries: vec![],
        default_action: PolicyAction::Deny,
    }]);
    let (reply_tx, reply_rx) = oneshot::channel();
    let flow = session
        .handle_command(PeerCommand::UpdateImportPolicy {
            policy: Some(deny_chain),
            reply: reply_tx,
        })
        .await;
    assert_eq!(flow, ControlFlow::Continue(()));
    assert_eq!(reply_rx.await.unwrap(), Ok(()));
    session.process_update(update).await;
    let RibUpdate::RoutesReceived {
        announced,
        withdrawn,
        ..
    } = rib_rx
        .try_recv()
        .expect("denied replacement must reach RIB")
    else {
        panic!("expected RoutesReceived");
    };
    assert!(announced.is_empty());
    assert_eq!(
        withdrawn,
        vec![(Prefix::V4(prefix), 0)],
        "a previously accepted classic NLRI denied on replacement must be withdrawn exactly"
    );
    assert_eq!(
        session.known_prefix_count(),
        0,
        "the denied replacement must retire max-prefix accounting"
    );
    let key = ImportDecisionKey {
        afi: Afi::Ipv4,
        safi: Safi::Unicast,
        prefix: Prefix::V4(prefix),
        path_id: 0,
    };
    match session
        .import_decision_cache
        .lookup(&key, session.import_policy_generation)
    {
        LookupResult::Hit(decision) => assert_eq!(decision.outcome, CachedOutcome::Deny),
        other => panic!("expected the replacement Deny to remain explainable, got {other:?}"),
    }
}

/// A denied MP-unicast replacement retires only its exact RFC 7911 identity.
/// An explicit `MP_UNREACH` for another denied identity in the same UPDATE must
/// not be duplicated, and an untouched sibling path must remain accepted.
#[expect(
    clippy::too_many_lines,
    reason = "covers MP Add-Path replacement, overlap deduplication, sibling retention, and explain outcomes"
)]
#[tokio::test]
async fn denied_mp_add_path_replacements_preserve_sibling_and_deduplicate_overlap() {
    use super::import_decision_cache::{CachedOutcome, ImportDecisionKey, LookupResult};
    use rustbgpd_wire::{MpReachNlri, MpUnreachNlri, NlriEntry};

    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    // Import explain is opt-in (ADR-0073); this test exercises the
    // populated cache, so turn it on explicitly.
    session.import_explain_enabled = true;
    let mut negotiated = negotiated_session(65002, false);
    negotiated.negotiated_families = vec![(Afi::Ipv6, Safi::Unicast)];
    negotiated
        .add_path_families
        .insert((Afi::Ipv6, Safi::Unicast), AddPathMode::Both);
    install_test_negotiated_session(&mut session, negotiated);

    let prefix = Prefix::V6(Ipv6Prefix::new("2001:db8:439::".parse().unwrap(), 64));
    let nlri = |path_id| NlriEntry { path_id, prefix };
    let base_attrs = || {
        vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath {
                segments: vec![AsPathSegment::AsSequence(vec![65002])],
            }),
        ]
    };

    let mut attrs = base_attrs();
    attrs.push(PathAttribute::MpReachNlri(MpReachNlri {
        afi: Afi::Ipv6,
        safi: Safi::Unicast,
        next_hop: "2001:db8::2".parse().unwrap(),
        link_local_next_hop: None,
        announced: vec![nlri(11), nlri(22), nlri(33)],
        flowspec_announced: vec![],
        evpn_announced: vec![],
        bgpls_announced: vec![],
        labeled_announced: vec![],
        vpn_announced: vec![],
        rtc_announced: vec![],
    }));
    session
        .process_update(UpdateMessage::build(
            &[],
            &[],
            &attrs,
            true,
            true,
            Ipv4UnicastMode::Body,
        ))
        .await;
    let RibUpdate::RoutesReceived { announced, .. } =
        rib_rx.try_recv().expect("initial paths must reach RIB")
    else {
        panic!("expected RoutesReceived");
    };
    assert_eq!(announced.len(), 3);

    session.install_import_policy(Some(PolicyChain::new(vec![Policy {
        entries: vec![],
        default_action: PolicyAction::Deny,
    }])));

    let mut replacement_attrs = base_attrs();
    replacement_attrs.push(PathAttribute::MpReachNlri(MpReachNlri {
        afi: Afi::Ipv6,
        safi: Safi::Unicast,
        next_hop: "2001:db8::3".parse().unwrap(),
        link_local_next_hop: None,
        announced: vec![nlri(11), nlri(22)],
        flowspec_announced: vec![],
        evpn_announced: vec![],
        bgpls_announced: vec![],
        labeled_announced: vec![],
        vpn_announced: vec![],
        rtc_announced: vec![],
    }));
    replacement_attrs.push(PathAttribute::MpUnreachNlri(MpUnreachNlri {
        afi: Afi::Ipv6,
        safi: Safi::Unicast,
        withdrawn: vec![nlri(22)],
        flowspec_withdrawn: vec![],
        evpn_withdrawn: vec![],
        bgpls_withdrawn: vec![],
        labeled_withdrawn: vec![],
        vpn_withdrawn: vec![],
        rtc_withdrawn: vec![],
    }));
    session
        .process_update(UpdateMessage::build(
            &[],
            &[],
            &replacement_attrs,
            true,
            true,
            Ipv4UnicastMode::Body,
        ))
        .await;
    let RibUpdate::RoutesReceived {
        announced,
        mut withdrawn,
        ..
    } = rib_rx
        .try_recv()
        .expect("denied replacements must reach RIB as withdrawals")
    else {
        panic!("expected RoutesReceived");
    };
    assert!(announced.is_empty());
    withdrawn.sort_unstable_by_key(|(_, path_id)| *path_id);
    assert_eq!(withdrawn, vec![(prefix, 11), (prefix, 22)]);
    assert!(!session.known_paths.contains(&(prefix, 11)));
    assert!(!session.known_paths.contains(&(prefix, 22)));
    assert!(session.known_paths.contains(&(prefix, 33)));
    assert_eq!(session.known_prefix_count(), 1);

    let decision = |path_id| ImportDecisionKey {
        afi: Afi::Ipv6,
        safi: Safi::Unicast,
        prefix,
        path_id,
    };
    match session
        .import_decision_cache
        .lookup(&decision(11), session.import_policy_generation)
    {
        LookupResult::Hit(entry) => assert_eq!(entry.outcome, CachedOutcome::Deny),
        other => panic!("expected synthetic withdrawal to preserve Deny, got {other:?}"),
    }
    match session
        .import_decision_cache
        .lookup(&decision(22), session.import_policy_generation)
    {
        LookupResult::Hit(entry) => assert_eq!(entry.outcome, CachedOutcome::Withdrawn),
        other => panic!("expected explicit withdrawal tombstone, got {other:?}"),
    }
}

/// A denied `FlowSpec` replacement retires only an accepted `(AFI, rule)`
/// identity. Explicit overlap is emitted once, first-seen/repeated denials stay
/// silent, and the same destinationless rule in the other AFI remains live.
///
/// Break-to-red: deleting denied-key collection, or hard-coding either AFI,
/// leaves the opposite-family deny-only identity accepted; removing the
/// known-set gate emits first-seen/repeated withdrawals and duplicates overlap.
#[tokio::test]
#[expect(clippy::too_many_lines, reason = "one ordered dual-AFI scenario")]
async fn denied_flowspec_replacements_retire_exact_afi_rule_identity() {
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    let mut negotiated = negotiated_session(65002, false);
    negotiated.negotiated_families = vec![(Afi::Ipv4, Safi::FlowSpec), (Afi::Ipv6, Safi::FlowSpec)];
    install_test_negotiated_session(&mut session, negotiated);
    let rule = |protocol: u8| FlowSpecRule {
        components: vec![FlowSpecComponent::IpProtocol(vec![NumericMatch {
            end_of_list: true,
            and_bit: false,
            lt: false,
            gt: false,
            eq: true,
            value: u64::from(protocol),
        }])],
    };
    let shared = rule(6);
    let explicit = rule(17);
    let overlap = rule(41);
    let sibling = rule(47);
    let first_seen = rule(132);
    let update = |afi, announced: Vec<FlowSpecRule>, withdrawn: Vec<FlowSpecRule>| {
        let mut reach =
            empty_nonunicast_reach(afi, Safi::FlowSpec, IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        reach.flowspec_announced = announced;
        let mut unreach = empty_nonunicast_unreach(afi, Safi::FlowSpec);
        unreach.flowspec_withdrawn = withdrawn;
        nonunicast_update(
            nonunicast_accepted_attrs(),
            reach,
            (!unreach.flowspec_withdrawn.is_empty()).then_some(unreach),
            false,
        )
    };
    let key = |afi, rule: &FlowSpecRule| FlowSpecKey {
        afi,
        rule: rule.clone(),
    };

    session
        .process_update(update(
            Afi::Ipv4,
            vec![shared.clone(), explicit.clone(), overlap.clone()],
            vec![],
        ))
        .await;
    session
        .process_update(update(
            Afi::Ipv6,
            vec![shared.clone(), sibling.clone()],
            vec![],
        ))
        .await;
    for expected in [3, 2] {
        let RibUpdate::RoutesReceived {
            flowspec_announced,
            flowspec_withdrawn,
            ..
        } = rib_rx.try_recv().expect("accepted FlowSpec reaches RIB")
        else {
            panic!("expected RoutesReceived");
        };
        assert_eq!(flowspec_announced.len(), expected);
        assert!(flowspec_withdrawn.is_empty());
    }
    assert_eq!(session.known_prefix_count(), 5);
    session.install_import_policy(Some(PolicyChain::new(vec![Policy {
        entries: vec![],
        default_action: PolicyAction::Deny,
    }])));

    session
        .process_update(update(Afi::Ipv6, vec![shared.clone()], vec![]))
        .await;
    let RibUpdate::RoutesReceived {
        flowspec_withdrawn, ..
    } = rib_rx.try_recv().expect("denied replacement reaches RIB")
    else {
        panic!("expected RoutesReceived");
    };
    assert_eq!(flowspec_withdrawn, vec![key(Afi::Ipv6, &shared)]);
    assert!(session.known_flowspec.contains(&key(Afi::Ipv4, &shared)));

    session
        .process_update(update(Afi::Ipv4, vec![shared.clone()], vec![]))
        .await;
    let RibUpdate::RoutesReceived {
        flowspec_withdrawn, ..
    } = rib_rx.try_recv().expect("opposite-AFI denial reaches RIB")
    else {
        panic!("expected RoutesReceived");
    };
    assert_eq!(flowspec_withdrawn, vec![key(Afi::Ipv4, &shared)]);

    session
        .process_update(update(Afi::Ipv4, vec![], vec![explicit.clone()]))
        .await;
    let RibUpdate::RoutesReceived {
        flowspec_withdrawn, ..
    } = rib_rx.try_recv().expect("explicit withdrawal reaches RIB")
    else {
        panic!("expected RoutesReceived");
    };
    assert_eq!(flowspec_withdrawn, vec![key(Afi::Ipv4, &explicit)]);

    session
        .process_update(update(
            Afi::Ipv4,
            vec![overlap.clone()],
            vec![overlap.clone()],
        ))
        .await;
    let RibUpdate::RoutesReceived {
        flowspec_withdrawn, ..
    } = rib_rx.try_recv().expect("overlap reaches RIB once")
    else {
        panic!("expected RoutesReceived");
    };
    assert_eq!(flowspec_withdrawn, vec![key(Afi::Ipv4, &overlap)]);

    for _ in 0..2 {
        session
            .process_update(update(Afi::Ipv4, vec![first_seen.clone()], vec![]))
            .await;
        assert!(rib_rx.try_recv().is_err(), "unknown denial stays silent");
    }
    assert!(session.known_flowspec.contains(&key(Afi::Ipv6, &sibling)));
    assert_eq!(session.known_prefix_count(), 1);
}

/// A denied EVPN Type-2 replacement retires its exact accepted key. Explicit
/// overlap is emitted once, first-seen/repeated denials stay silent, and an
/// untouched sibling remains accepted.
///
/// Break-to-red: deleting denied-key collection leaves the deny-only key live;
/// removing the known-set membership gate emits unknown/repeated withdrawals
/// and duplicates the explicit overlap.
#[tokio::test]
async fn denied_evpn_replacements_retire_exact_known_type2_key() {
    use rustbgpd_wire::{
        EthernetSegmentIdentifier, EthernetTagId, EvpnMacIp, EvpnRoute, MacAddress, MplsLabel,
    };

    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    let mut negotiated = negotiated_session(65002, false);
    negotiated.negotiated_families = vec![(Afi::L2Vpn, Safi::Evpn)];
    install_test_negotiated_session(&mut session, negotiated);
    let route = |suffix: u8| {
        EvpnRoute::MacIp(EvpnMacIp {
            rd: RouteDistinguisher([0, 0, 0xFD, 0xE8, 0, 0, 0, 100]),
            esi: EthernetSegmentIdentifier::ZERO,
            ethernet_tag: EthernetTagId(100),
            mac: MacAddress([0x02, 0, 0, 0, 0, suffix]),
            ip: None,
            label1: MplsLabel::new(10_000),
            label2: None,
        })
    };
    let deny_only = route(11);
    let explicit = route(22);
    let overlap = route(33);
    let sibling = route(44);
    let first_seen = route(55);
    let update = |announced: Vec<EvpnRoute>, withdrawn: Vec<EvpnRoute>| {
        let mut reach = empty_nonunicast_reach(
            Afi::L2Vpn,
            Safi::Evpn,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        );
        reach.evpn_announced = announced;
        let mut unreach = empty_nonunicast_unreach(Afi::L2Vpn, Safi::Evpn);
        unreach.evpn_withdrawn = withdrawn;
        nonunicast_update(
            nonunicast_accepted_attrs(),
            reach,
            (!unreach.evpn_withdrawn.is_empty()).then_some(unreach),
            false,
        )
    };

    session
        .process_update(update(
            vec![
                deny_only.clone(),
                explicit.clone(),
                overlap.clone(),
                sibling.clone(),
            ],
            vec![],
        ))
        .await;
    let RibUpdate::RoutesReceived {
        evpn_announced,
        evpn_withdrawn,
        ..
    } = rib_rx.try_recv().expect("accepted EVPN reaches RIB")
    else {
        panic!("expected RoutesReceived");
    };
    assert_eq!(evpn_announced.len(), 4);
    assert!(evpn_withdrawn.is_empty());
    assert_eq!(session.known_prefix_count(), 4);
    session.install_import_policy(Some(PolicyChain::new(vec![Policy {
        entries: vec![],
        default_action: PolicyAction::Deny,
    }])));

    session
        .process_update(update(vec![deny_only.clone()], vec![]))
        .await;
    let RibUpdate::RoutesReceived { evpn_withdrawn, .. } =
        rib_rx.try_recv().expect("denied replacement reaches RIB")
    else {
        panic!("expected RoutesReceived");
    };
    assert_eq!(evpn_withdrawn, vec![deny_only.key()]);

    session
        .process_update(update(vec![], vec![explicit.clone()]))
        .await;
    let RibUpdate::RoutesReceived { evpn_withdrawn, .. } =
        rib_rx.try_recv().expect("explicit withdrawal reaches RIB")
    else {
        panic!("expected RoutesReceived");
    };
    assert_eq!(evpn_withdrawn, vec![explicit.key()]);

    session
        .process_update(update(vec![overlap.clone()], vec![overlap.clone()]))
        .await;
    let RibUpdate::RoutesReceived { evpn_withdrawn, .. } =
        rib_rx.try_recv().expect("overlap reaches RIB once")
    else {
        panic!("expected RoutesReceived");
    };
    assert_eq!(evpn_withdrawn, vec![overlap.key()]);

    for _ in 0..2 {
        session
            .process_update(update(vec![first_seen.clone()], vec![]))
            .await;
        assert!(rib_rx.try_recv().is_err(), "unknown denial stays silent");
    }
    assert!(session.known_evpn.contains(&sibling.key()));
    assert_eq!(session.known_prefix_count(), 1);
}

/// End-to-end ERR/GR + import-policy interaction: a denied replacement must
/// remove the accepted route immediately, before `EoRR`, so neither refresh nor
/// subsequent graceful-restart retention can keep it alive.
#[expect(
    clippy::too_many_lines,
    reason = "regression test pins denied replacement removal across ERR and GR boundaries"
)]
#[tokio::test]
async fn denied_replacement_is_removed_before_eorr_and_cannot_survive_gr() {
    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let (rib_tx, rib_rx) = mpsc::channel(64);
    let (_, query_rx) = mpsc::channel(1);
    let manager = rustbgpd_rib::RibManager::new(rib_rx, query_rx, None, None, BgpMetrics::new());
    let manager_handle = tokio::spawn(manager.run());
    let denied_prefix = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 0), 24);
    let mut peer_config = PeerConfig::new(65001, 65002, Ipv4Addr::new(10, 0, 0, 1));
    peer_config.connect_retry_secs = 30;
    peer_config.families = vec![(Afi::Ipv4, Safi::Unicast)];
    peer_config.gr_restart_time = 120;
    let config = TransportConfig::new(peer_config, "10.0.0.2:179".parse().unwrap());
    let metrics = BgpMetrics::new();
    let (_cmd_tx, cmd_rx) = mpsc::channel(8);
    let mut session = PeerSession::new(
        config,
        metrics,
        cmd_rx,
        rib_tx.clone(),
        None,
        None,
        None,
        None,
        None,
        false,
    );
    let mut negotiated = negotiated_session(65002, false);
    negotiated.peer_route_refresh = true;
    negotiated.peer_enhanced_route_refresh = true;
    negotiated.peer_gr_capable = true;
    negotiated.peer_restart_time = 120;
    negotiated.peer_gr_families = vec![rustbgpd_wire::GracefulRestartFamily {
        afi: Afi::Ipv4,
        safi: Safi::Unicast,
        forwarding_preserved: false,
    }];
    install_test_negotiated_session(&mut session, negotiated);
    session.config.peer.graceful_restart = true;
    let attrs = vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath {
            segments: vec![AsPathSegment::AsSequence(vec![65002])],
        }),
        PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
    ];
    let accepted = UpdateMessage::build(
        &[Ipv4NlriEntry {
            path_id: 0,
            prefix: denied_prefix,
        }],
        &[],
        &attrs,
        true,
        false,
        Ipv4UnicastMode::Body,
    );
    session.process_update(accepted.clone()).await;
    assert_eq!(session.known_prefix_count(), 1);
    let (reply_tx, reply_rx) = oneshot::channel();
    rib_tx
        .send(RibUpdate::QueryReceivedRoutes {
            peer: Some(peer),
            reply: reply_tx,
        })
        .await
        .unwrap();
    let initially_received = reply_rx.await.unwrap();
    assert_eq!(initially_received.len(), 1);
    assert_eq!(initially_received[0].prefix, Prefix::V4(denied_prefix));

    buffer_route_refresh(
        &mut session,
        Afi::Ipv4,
        Safi::Unicast,
        RouteRefreshSubtype::BoRR,
    );
    session.process_read_buffer().await;
    assert_eq!(
        session.refresh_accounting_stale_count((Afi::Ipv4, Safi::Unicast)),
        Some(1)
    );

    let deny_policy = PolicyChain::new(vec![Policy {
        entries: vec![],
        default_action: PolicyAction::Deny,
    }]);
    let (reply_tx, reply_rx) = oneshot::channel();
    assert_eq!(
        session
            .handle_command(PeerCommand::UpdateImportPolicy {
                policy: Some(deny_policy),
                reply: reply_tx,
            })
            .await,
        ControlFlow::Continue(())
    );
    assert_eq!(reply_rx.await.unwrap(), Ok(()));

    // Re-advertise the accepted identity inside ERR. The replacement now
    // evaluates Deny and must become an immediate exact withdrawal.
    session.process_update(accepted).await;
    assert_eq!(session.known_prefix_count(), 0);
    assert_eq!(
        session.refresh_accounting_stale_count((Afi::Ipv4, Safi::Unicast)),
        Some(0),
        "the synthetic withdrawal must retire the ERR stale identity"
    );

    // The denial itself must remove the old accepted route. Waiting for EoRR
    // would leave a policy-rejected route usable throughout a long refresh.
    let (reply_tx, reply_rx) = oneshot::channel();
    rib_tx
        .send(RibUpdate::QueryReceivedRoutes {
            peer: Some(peer),
            reply: reply_tx,
        })
        .await
        .unwrap();
    assert!(
        reply_rx.await.unwrap().is_empty(),
        "denied route must be absent before EoRR closes the refresh window"
    );

    // EoRR (including a duplicate) is now an idempotent boundary: there is no
    // denied route left to sweep locally or in the RIB.
    for _ in 0..2 {
        buffer_route_refresh(
            &mut session,
            Afi::Ipv4,
            Safi::Unicast,
            RouteRefreshSubtype::EoRR,
        );
        session.process_read_buffer().await;
    }
    assert_eq!(session.refresh_accounting_window_count(), 0);
    assert_eq!(session.known_prefix_count(), 0);

    // A subsequent GR teardown cannot mark the already removed route stale.
    session.execute_actions(vec![Action::SessionDown]).await;
    let (reply_tx, reply_rx) = oneshot::channel();
    rib_tx
        .send(RibUpdate::QueryReceivedRoutes {
            peer: Some(peer),
            reply: reply_tx,
        })
        .await
        .unwrap();
    assert!(reply_rx.await.unwrap().is_empty());
    drop(session);
    drop(rib_tx);
    manager_handle.await.unwrap();
}
