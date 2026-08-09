use super::*;

/// Import policy is applied before `RoutesReceived` reaches the RIB. A
/// first-seen denial has no prior accepted identity, so it must produce
/// neither an announcement nor a synthetic withdrawal.
#[expect(
    clippy::too_many_lines,
    reason = "covers a mixed first-seen permit/deny batch and exact RIB payload assertions"
)]
#[tokio::test]
async fn import_policy_denied_routes_do_not_reach_rib() {
    // Create a session with import policy that denies 198.51.100.0/24
    let mut peer_config = PeerConfig::new(65001, 65002, Ipv4Addr::new(10, 0, 0, 1));
    peer_config.connect_retry_secs = 30;
    peer_config.families = vec![(Afi::Ipv4, Safi::Unicast)];
    peer_config.gr_restart_time = 120;
    let config = TransportConfig::new(peer_config, "10.0.0.2:179".parse().unwrap());
    let metrics = BgpMetrics::new();
    let (_cmd_tx, cmd_rx) = mpsc::channel(8);
    let (rib_tx, mut rib_rx) = mpsc::channel(64);
    let deny_policy = PolicyChain::new(vec![Policy {
        entries: vec![PolicyStatement {
            prefix: Some(Prefix::V4(Ipv4Prefix::new(
                Ipv4Addr::new(198, 51, 100, 0),
                24,
            ))),
            ge: None,
            le: None,
            action: PolicyAction::Deny,
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
            modifications: RouteModifications::default(),
        }],
        default_action: PolicyAction::Permit,
    }]);
    let mut session = PeerSession::new(
        config,
        metrics,
        cmd_rx,
        rib_tx,
        Some(deny_policy),
        None,
        None,
        None,
        None,
        false,
    );
    let mut negotiated = negotiated_session(65002, false);
    negotiated.peer_enhanced_route_refresh = true;
    session
        .negotiated_families
        .clone_from(&negotiated.negotiated_families);
    session.negotiated = Some(negotiated);
    // Send an UPDATE with 198.51.100.0/24 — should be denied by import policy
    let denied_prefix = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 0), 24);
    let permitted_prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, 0), 24);
    let attrs = vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath {
            segments: vec![AsPathSegment::AsSequence(vec![65002])],
        }),
        PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
    ];
    // Both prefixes in one UPDATE: one permitted, one denied
    let denied_nlri = Ipv4NlriEntry {
        path_id: 0,
        prefix: denied_prefix,
    };
    let permitted_nlri = Ipv4NlriEntry {
        path_id: 0,
        prefix: permitted_prefix,
    };
    let update = UpdateMessage::build(
        &[denied_nlri, permitted_nlri],
        &[],
        &attrs,
        true,
        false,
        Ipv4UnicastMode::Body,
    );
    session.process_update(update).await;
    assert_eq!(session.import_policy_routes_permitted, 1);
    assert_eq!(session.import_policy_routes_denied, 1);
    // Drain any messages — there may be zero or one RoutesReceived
    let mut all_announced = vec![];
    let mut all_withdrawn = vec![];
    while let Ok(msg) = rib_rx.try_recv() {
        if let RibUpdate::RoutesReceived {
            announced,
            withdrawn,
            ..
        } = msg
        {
            all_announced.extend(announced);
            all_withdrawn.extend(withdrawn);
        }
    }
    // Only the permitted prefix should reach the RIB; denied prefix filtered
    assert_eq!(
        all_announced.len(),
        1,
        "expected exactly 1 announced route, got {}: {all_announced:?}",
        all_announced.len()
    );
    assert_eq!(all_announced[0].prefix, Prefix::V4(permitted_prefix));
    assert!(
        all_withdrawn.is_empty(),
        "a first-seen policy denial has no accepted route to withdraw"
    );
}

/// LAN-291: a `FlowSpec` rule without a destination-prefix component is
/// `prefix = None` in the import policy context — prefix-based deny terms
/// (including exact-default ones) must not match it, while a rule with a
/// real destination prefix still evaluates that prefix. Covers IPv4 and
/// IPv6 `FlowSpec`.
#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "covers destination-less v4 + v6 rules and a real-prefix deny in one session scenario"
)]
async fn import_policy_prefix_term_does_not_match_destination_less_flowspec() {
    use rustbgpd_wire::attribute::MpReachNlri;

    let destless_rule = |protocol: u8| FlowSpecRule {
        components: vec![FlowSpecComponent::IpProtocol(vec![NumericMatch {
            end_of_list: true,
            and_bit: false,
            lt: false,
            gt: false,
            eq: true,
            value: u64::from(protocol),
        }])],
    };
    let deny = |prefix: Prefix| PolicyStatement {
        prefix: Some(prefix),
        ge: None,
        le: None,
        action: PolicyAction::Deny,
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
        modifications: RouteModifications::default(),
    };

    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    session.install_import_policy(Some(PolicyChain::new(vec![Policy {
        entries: vec![
            deny(Prefix::V4(Ipv4Prefix::new(Ipv4Addr::UNSPECIFIED, 0))),
            deny(Prefix::V6(Ipv6Prefix::new(Ipv6Addr::UNSPECIFIED, 0))),
            deny(Prefix::V4(Ipv4Prefix::new(
                Ipv4Addr::new(198, 51, 100, 0),
                24,
            ))),
        ],
        default_action: PolicyAction::Permit,
    }])));
    session.negotiated = Some(negotiated_session(65002, false));
    session.negotiated_families = vec![(Afi::Ipv4, Safi::FlowSpec), (Afi::Ipv6, Safi::FlowSpec)];

    let destless_v4 = destless_rule(6);
    let destless_v6 = destless_rule(17);
    let with_denied_prefix = FlowSpecRule {
        components: vec![FlowSpecComponent::DestinationPrefix(FlowSpecPrefix::V4(
            Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 0), 24),
        ))],
    };

    let attrs_for = |mp: MpReachNlri| {
        vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath {
                segments: vec![AsPathSegment::AsSequence(vec![65002])],
            }),
            PathAttribute::MpReachNlri(mp),
        ]
    };
    let v4_update = rustbgpd_wire::UpdateMessage::build(
        &[],
        &[],
        &attrs_for(MpReachNlri {
            afi: Afi::Ipv4,
            safi: Safi::FlowSpec,
            next_hop: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            link_local_next_hop: None,
            announced: vec![],
            flowspec_announced: vec![destless_v4.clone(), with_denied_prefix.clone()],
            evpn_announced: vec![],
            bgpls_announced: vec![],
            labeled_announced: vec![],
            vpn_announced: vec![],
            rtc_announced: vec![],
        }),
        true,
        false,
        rustbgpd_wire::Ipv4UnicastMode::Body,
    );
    session.process_update(v4_update).await;
    let v6_update = rustbgpd_wire::UpdateMessage::build(
        &[],
        &[],
        &attrs_for(MpReachNlri {
            afi: Afi::Ipv6,
            safi: Safi::FlowSpec,
            next_hop: "2001:db8::2".parse().unwrap(),
            link_local_next_hop: None,
            announced: vec![],
            flowspec_announced: vec![destless_v6.clone()],
            evpn_announced: vec![],
            bgpls_announced: vec![],
            labeled_announced: vec![],
            vpn_announced: vec![],
            rtc_announced: vec![],
        }),
        true,
        false,
        rustbgpd_wire::Ipv4UnicastMode::Body,
    );
    session.process_update(v6_update).await;

    assert_eq!(
        session.import_policy_routes_permitted, 2,
        "both destination-less rules must pass through to the default Permit"
    );
    assert_eq!(
        session.import_policy_routes_denied, 1,
        "the rule with a real destination prefix must match the deny term"
    );

    let mut announced = vec![];
    while let Ok(msg) = rib_rx.try_recv() {
        if let RibUpdate::RoutesReceived {
            flowspec_announced, ..
        } = msg
        {
            announced.extend(flowspec_announced);
        }
    }
    let rules: Vec<_> = announced.iter().map(|r| r.rule.clone()).collect();
    assert_eq!(rules, vec![destless_v4, destless_v6]);
    assert_eq!(
        announced.iter().map(|r| r.afi).collect::<Vec<_>>(),
        vec![Afi::Ipv4, Afi::Ipv6]
    );
}

/// ADR-0073 end-to-end pins 1 + 2: after `process_update`, the
/// per-session import-decision cache holds an explainable `Deny` entry
/// for the denied prefix (which never reached RIB) and a `Permit` entry
/// — carrying the applied modifications — for the permitted one.
#[expect(
    clippy::too_many_lines,
    reason = "regression test pins a full session lifecycle sequence"
)]
#[tokio::test]
async fn import_decision_cache_records_deny_and_permit_for_explain() {
    use super::import_decision_cache::{CachedOutcome, ImportDecisionKey, LookupResult};
    let mut peer_config = PeerConfig::new(65001, 65002, Ipv4Addr::new(10, 0, 0, 1));
    peer_config.connect_retry_secs = 30;
    peer_config.families = vec![(Afi::Ipv4, Safi::Unicast)];
    peer_config.gr_restart_time = 120;
    let mut config = TransportConfig::new(peer_config, "10.0.0.2:179".parse().unwrap());
    // Import explain is opt-in (ADR-0073); this test exercises the
    // populated cache, so turn it on explicitly.
    config.explain_enabled = true;
    let metrics = BgpMetrics::new();
    let (_cmd_tx, cmd_rx) = mpsc::channel(8);
    let (rib_tx, _rib_rx) = mpsc::channel(64);
    let denied_prefix = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 0), 24);
    let permitted_prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, 0), 24);
    // One chain, two statements: deny the first prefix, permit + set
    // LOCAL_PREF=200 on the second.
    let deny_stmt = PolicyStatement {
        prefix: Some(Prefix::V4(denied_prefix)),
        ge: None,
        le: None,
        action: PolicyAction::Deny,
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
        modifications: RouteModifications::default(),
    };
    let permit_stmt = PolicyStatement {
        prefix: Some(Prefix::V4(permitted_prefix)),
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
            set_local_pref: Some(200),
            ..RouteModifications::default()
        },
    };
    let chain = PolicyChain::new(vec![Policy {
        entries: vec![deny_stmt, permit_stmt],
        default_action: PolicyAction::Permit,
    }]);
    let mut session = PeerSession::new(
        config,
        metrics,
        cmd_rx,
        rib_tx,
        Some(chain),
        None,
        None,
        None,
        None,
        false,
    );
    let mut negotiated = negotiated_session(65002, false);
    negotiated.peer_enhanced_route_refresh = true;
    session
        .negotiated_families
        .clone_from(&negotiated.negotiated_families);
    session.negotiated = Some(negotiated);
    let attrs = vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath {
            segments: vec![AsPathSegment::AsSequence(vec![65002])],
        }),
        PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
    ];
    let update = UpdateMessage::build(
        &[
            Ipv4NlriEntry {
                path_id: 0,
                prefix: denied_prefix,
            },
            Ipv4NlriEntry {
                path_id: 0,
                prefix: permitted_prefix,
            },
        ],
        &[],
        &attrs,
        true,
        false,
        Ipv4UnicastMode::Body,
    );
    session.process_update(update).await;
    let generation = session.import_policy_generation;
    let key = |p: Ipv4Prefix| ImportDecisionKey {
        afi: Afi::Ipv4,
        safi: Safi::Unicast,
        prefix: Prefix::V4(p),
        path_id: 0,
    };
    // Pin 1: the denied prefix is explainable even though it never
    // reached RIB.
    match session
        .import_decision_cache
        .lookup(&key(denied_prefix), generation)
    {
        LookupResult::Hit(d) => assert_eq!(d.outcome, CachedOutcome::Deny),
        other => panic!("expected Hit(Deny) for denied prefix, got {other:?}"),
    }
    // Pin 2: the permitted prefix is explainable and carries the
    // modifications the chain applied.
    match session
        .import_decision_cache
        .lookup(&key(permitted_prefix), generation)
    {
        LookupResult::Hit(d) => {
            assert_eq!(d.outcome, CachedOutcome::Permit);
            assert_eq!(d.modifications.set_local_pref, Some(200));
        }
        other => panic!("expected Hit(Permit) for permitted prefix, got {other:?}"),
    }
}

/// ADR-0073 contract: the per-session import-decision cache must be
/// flushed on `Action::SessionDown`. A reconnecting `PeerSession` is not
/// reconstructed, so without the flush an explain query on the new
/// session could return a decision recorded on the *previous* session
/// for any prefix the peer has not yet re-advertised. Mirrors the
/// per-session permit/deny counter reset in the same handler.
#[tokio::test]
async fn session_down_flushes_import_decision_cache() {
    use super::import_decision_cache::{ImportDecisionKey, LookupResult};
    let mut peer_config = PeerConfig::new(65001, 65002, Ipv4Addr::new(10, 0, 0, 1));
    peer_config.connect_retry_secs = 30;
    peer_config.families = vec![(Afi::Ipv4, Safi::Unicast)];
    peer_config.gr_restart_time = 120;
    let mut config = TransportConfig::new(peer_config, "10.0.0.2:179".parse().unwrap());
    // Import explain is opt-in (ADR-0073); this test exercises the
    // populated cache, so turn it on explicitly.
    config.explain_enabled = true;
    let metrics = BgpMetrics::new();
    let (_cmd_tx, cmd_rx) = mpsc::channel(8);
    let (rib_tx, _rib_rx) = mpsc::channel(64);
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, 0), 24);
    let chain = PolicyChain::new(vec![Policy {
        entries: vec![PolicyStatement {
            prefix: Some(Prefix::V4(prefix)),
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
            modifications: RouteModifications::default(),
        }],
        default_action: PolicyAction::Permit,
    }]);
    let mut session = PeerSession::new(
        config,
        metrics,
        cmd_rx,
        rib_tx,
        Some(chain),
        None,
        None,
        None,
        None,
        false,
    );
    let mut negotiated = negotiated_session(65002, false);
    negotiated.peer_enhanced_route_refresh = true;
    session
        .negotiated_families
        .clone_from(&negotiated.negotiated_families);
    session.negotiated = Some(negotiated);
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
    session.process_update(update).await;
    let generation = session.import_policy_generation;
    let key = ImportDecisionKey {
        afi: Afi::Ipv4,
        safi: Safi::Unicast,
        prefix: Prefix::V4(prefix),
        path_id: 0,
    };
    // Precondition: the decision is cached and explainable on this session.
    assert!(
        matches!(
            session.import_decision_cache.lookup(&key, generation),
            LookupResult::Hit(_)
        ),
        "expected the permitted prefix to be cached before SessionDown",
    );
    // Flap: SessionDown must flush the per-session cache.
    session.execute_actions(vec![Action::SessionDown]).await;
    // Postcondition: the prior session's decision is gone — explain
    // reports NotSeen rather than a stale Hit from the dead session.
    assert!(
        matches!(
            session.import_decision_cache.lookup(&key, generation),
            LookupResult::NotSeen
        ),
        "import-decision cache must be flushed on SessionDown (ADR-0073)",
    );
}

/// ADR-0073 pin 3: an `ExplainImportPolicy` command is a read — it must
/// not move the import-policy permit/deny counters.
#[tokio::test]
async fn explain_import_policy_command_does_not_touch_counters() {
    use super::import_decision_cache::{LookupResult, ResolvedMatch};
    let (mut session, _rib_rx) = make_test_session_with_rib(65001, 65002);
    // Import explain is opt-in (ADR-0073); this test exercises the
    // populated cache, so turn it on explicitly.
    session.import_explain_enabled = true;
    let mut negotiated = negotiated_session(65002, false);
    negotiated.peer_enhanced_route_refresh = true;
    session
        .negotiated_families
        .clone_from(&negotiated.negotiated_families);
    session.negotiated = Some(negotiated);
    // Populate the cache with one permitted prefix (permit-all default).
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, 0), 24);
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
    session.process_update(update).await;
    let permitted_before = session.import_policy_routes_permitted;
    let denied_before = session.import_policy_routes_denied;
    // Issue the explain command through the real dispatch path.
    let (reply_tx, reply_rx) = oneshot::channel();
    let flow = session
        .handle_command(PeerCommand::ExplainImportPolicy {
            afi: Afi::Ipv4,
            safi: Safi::Unicast,
            prefix: Prefix::V4(prefix),
            path_id: None,
            reply: reply_tx,
        })
        .await;
    assert_eq!(flow, ControlFlow::Continue(()));
    let reply = reply_rx.await.expect("session replied");
    assert!(
        matches!(
            reply.matches.as_slice(),
            [ResolvedMatch {
                result: LookupResult::Hit(_),
                ..
            }]
        ),
        "expected a single Hit match, got {:?}",
        reply.matches
    );
    // The read must not have moved either counter.
    assert_eq!(session.import_policy_routes_permitted, permitted_before);
    assert_eq!(session.import_policy_routes_denied, denied_before);
}

/// The import-side stats read surface (LAN-248): the query command
/// snapshots the live per-term hit counters plus the install
/// generation, an explain read never moves them, and a chain
/// reinstall — content-equal included — advances the generation and
/// resets the counters instead of presenting continuous history.
#[expect(
    clippy::too_many_lines,
    reason = "regression test keeps snapshot, explain-non-counting, and reinstall assertions together"
)]
#[tokio::test]
async fn query_import_policy_term_hits_snapshots_without_counting() {
    use rustbgpd_policy::NamedPolicy;

    async fn snapshot(session: &mut PeerSession) -> Option<crate::handle::ImportPolicyTermHits> {
        let (reply_tx, reply_rx) = oneshot::channel();
        let flow = session
            .handle_command(PeerCommand::QueryImportPolicyTermHits { reply: reply_tx })
            .await;
        assert_eq!(flow, ControlFlow::Continue(()));
        reply_rx.await.expect("session replied")
    }
    async fn install(session: &mut PeerSession, chain: PolicyChain) {
        let (reply_tx, reply_rx) = oneshot::channel();
        let _ = session
            .handle_command(PeerCommand::UpdateImportPolicy {
                policy: Some(chain),
                reply: reply_tx,
            })
            .await;
        reply_rx
            .await
            .expect("session replied")
            .expect("install succeeds");
    }

    let (mut session, _rib_rx) = make_test_session_with_rib(65001, 65002);
    let mut negotiated = negotiated_session(65002, false);
    negotiated.peer_enhanced_route_refresh = true;
    session
        .negotiated_families
        .clone_from(&negotiated.negotiated_families);
    session.negotiated = Some(negotiated);

    // No import chain installed → nothing to report.
    assert!(snapshot(&mut session).await.is_none());

    let permit_all = PolicyStatement {
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
        modifications: RouteModifications::default(),
    };
    let chain = PolicyChain::from_named(vec![NamedPolicy {
        name: Some("edge-import".to_string()),
        policy: Policy {
            entries: vec![permit_all],
            default_action: PolicyAction::Permit,
        },
        rpol: None,
    }]);
    install(&mut session, chain.clone()).await;

    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, 0), 24);
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
    session.process_update(update).await;

    let first = snapshot(&mut session).await.expect("chain installed");
    assert_eq!(
        first.generation, 1,
        "session constructs at generation 0; one install advances it"
    );
    assert_eq!(first.evals, 1, "one route evaluated through the chain");
    assert_eq!(first.terms.len(), 1);
    assert_eq!(first.terms[0].policy.as_deref(), Some("edge-import"));
    assert_eq!(first.terms[0].hits, 1);

    // An explain read must not move the term-hit counters (LAN-248
    // pin, same contract as the permit/deny counters above).
    let (reply_tx, reply_rx) = oneshot::channel();
    let _ = session
        .handle_command(PeerCommand::ExplainImportPolicy {
            afi: Afi::Ipv4,
            safi: Safi::Unicast,
            prefix: Prefix::V4(prefix),
            path_id: None,
            reply: reply_tx,
        })
        .await;
    reply_rx.await.expect("session replied");
    let second = snapshot(&mut session).await.expect("chain installed");
    assert_eq!(second.evals, first.evals, "explain must not bump evals");
    assert_eq!(
        second.terms[0].hits, first.terms[0].hits,
        "explain must not bump term hits"
    );

    // A content-equal reinstall is a fresh chain instance: counters
    // reset and the generation advances, so the read surface never
    // presents the new instance as continuous history.
    install(&mut session, chain).await;
    let third = snapshot(&mut session).await.expect("chain installed");
    assert_eq!(third.generation, 2);
    assert_eq!(third.evals, 0);
    assert_eq!(third.terms[0].hits, 0);
}

/// Statement-level explain (the ADR-0073 deferred enrichment): a
/// current-generation Hit re-derives WHICH statement inside the matched
/// chain decided, through the real command dispatch path. A
/// generation bump (import-chain hot-apply) makes the entry `Stale`,
/// and a stale entry must carry NO statement trace — the chain that
/// produced the decision is gone, so re-walking the current chain
/// could contradict the recorded outcome.
#[expect(
    clippy::too_many_lines,
    reason = "regression test keeps cache hit and stale trace assertions together"
)]
#[tokio::test]
async fn explain_statement_trace_attributes_hit_and_skips_stale() {
    use super::import_decision_cache::LookupResult;
    use rustbgpd_policy::NamedPolicy;
    async fn explain_for(
        session: &mut PeerSession,
        prefix: Ipv4Prefix,
    ) -> super::import_decision_cache::ImportExplainReply {
        let (reply_tx, reply_rx) = oneshot::channel();
        let _ = session
            .handle_command(PeerCommand::ExplainImportPolicy {
                afi: Afi::Ipv4,
                safi: Safi::Unicast,
                prefix: Prefix::V4(prefix),
                path_id: None,
                reply: reply_tx,
            })
            .await;
        reply_rx.await.expect("session replied")
    }
    let mut peer_config = PeerConfig::new(65001, 65002, Ipv4Addr::new(10, 0, 0, 1));
    peer_config.connect_retry_secs = 30;
    peer_config.families = vec![(Afi::Ipv4, Safi::Unicast)];
    peer_config.gr_restart_time = 120;
    let mut config = TransportConfig::new(peer_config, "10.0.0.2:179".parse().unwrap());
    // Import explain is opt-in (ADR-0073); this test exercises the
    // populated cache, so turn it on explicitly.
    config.explain_enabled = true;
    let metrics = BgpMetrics::new();
    let (_cmd_tx, cmd_rx) = mpsc::channel(8);
    let (rib_tx, _rib_rx) = mpsc::channel(64);
    let denied_prefix = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 0), 24);
    let permitted_prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, 0), 24);
    let deny_stmt = PolicyStatement {
        prefix: Some(Prefix::V4(denied_prefix)),
        ge: None,
        le: None,
        action: PolicyAction::Deny,
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
        modifications: RouteModifications::default(),
    };
    let mut permit_stmt = deny_stmt.clone();
    permit_stmt.prefix = Some(Prefix::V4(permitted_prefix));
    permit_stmt.action = PolicyAction::Permit;
    permit_stmt.match_community = vec![CommunityMatch::Standard {
        value: (64512_u32 << 16) | 0x0064,
    }];
    permit_stmt.match_as_path = Some(AsPathRegex::new("_65002_").unwrap());
    permit_stmt.match_as_path_length_ge = Some(1);
    permit_stmt.match_as_path_length_le = Some(1);
    permit_stmt.match_local_pref_ge = Some(100);
    permit_stmt.match_med_le = Some(50);
    permit_stmt.match_next_hop = Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)));
    permit_stmt.modifications = RouteModifications {
        set_local_pref: Some(200),
        ..RouteModifications::default()
    };
    let chain = PolicyChain::from_named(vec![NamedPolicy {
        name: Some("edge-import".to_string()),
        policy: Policy {
            entries: vec![deny_stmt, permit_stmt],
            default_action: PolicyAction::Permit,
        },
        rpol: None,
    }]);
    let mut session = PeerSession::new(
        config,
        metrics,
        cmd_rx,
        rib_tx,
        Some(chain.clone()),
        None,
        None,
        None,
        None,
        false,
    );
    let mut negotiated = negotiated_session(65002, false);
    negotiated.peer_enhanced_route_refresh = true;
    session
        .negotiated_families
        .clone_from(&negotiated.negotiated_families);
    session.negotiated = Some(negotiated);
    let attrs = vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath {
            segments: vec![AsPathSegment::AsSequence(vec![65002])],
        }),
        PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
        PathAttribute::Communities(vec![(64512_u32 << 16) | 0x0064]),
        PathAttribute::LocalPref(150),
        PathAttribute::Med(42),
    ];
    let update = UpdateMessage::build(
        &[
            Ipv4NlriEntry {
                path_id: 0,
                prefix: denied_prefix,
            },
            Ipv4NlriEntry {
                path_id: 0,
                prefix: permitted_prefix,
            },
        ],
        &[],
        &attrs,
        true,
        false,
        Ipv4UnicastMode::Body,
    );
    session.process_update(update).await;
    // Permit: attributed to statement 1 of "edge-import", with the
    // prefix condition and the policy-local transition rendered from the
    // implicit default 100. The wire LOCAL_PREF 150 is ignored on eBGP.
    let reply = explain_for(&mut session, permitted_prefix).await;
    assert_eq!(reply.matches.len(), 1);
    let steps = &reply.matches[0].statements;
    assert_eq!(steps.len(), 1, "one policy evaluated");
    assert_eq!(steps[0].policy_index, 0);
    assert_eq!(steps[0].policy_name.as_deref(), Some("edge-import"));
    assert_eq!(steps[0].statement_index, Some(1));
    assert_eq!(steps[0].action, PolicyAction::Permit);
    assert_eq!(
        steps[0].matched_conditions,
        vec![
            "prefix 192.0.2.0/24",
            "community 64512:100",
            "as_path ~ \"_65002_\"",
            "as_path_len >= 1",
            "as_path_len <= 1",
            "local_pref >= 100",
            "med <= 50",
            "next_hop 10.0.0.2",
        ]
    );
    assert_eq!(steps[0].modifications, vec!["local_pref 100 -> 200"]);
    // Deny: attributed to statement 0 — the reject fast-path is
    // explainable even though the route never reached RIB.
    let reply = explain_for(&mut session, denied_prefix).await;
    let steps = &reply.matches[0].statements;
    assert_eq!(steps.len(), 1);
    assert_eq!(steps[0].statement_index, Some(0));
    assert_eq!(steps[0].action, PolicyAction::Deny);
    assert!(steps[0].modifications.is_empty());
    // Hot-apply the (same) chain: the generation bump makes the cached
    // entries Stale, and a stale match must carry no statement trace.
    let (reply_tx, reply_rx) = oneshot::channel();
    let _ = session
        .handle_command(PeerCommand::UpdateImportPolicy {
            policy: Some(chain),
            reply: reply_tx,
        })
        .await;
    reply_rx.await.expect("policy update acked").unwrap();
    let reply = explain_for(&mut session, permitted_prefix).await;
    assert!(
        matches!(reply.matches[0].result, LookupResult::Stale(_)),
        "generation bump must mark the entry stale"
    );
    assert!(
        reply.matches[0].statements.is_empty(),
        "stale entries must not carry a statement trace"
    );
}

/// ADR-0073 pin 4 (reset semantics): a freshly constructed session — the
/// state every peer reconnect / daemon restart starts from — has an
/// empty import-decision cache, so an explain query returns `NOT_SEEN`.
/// The cache is owned by `PeerSession`, so it cannot survive the session
/// drop; this pins the "resets on session reset" contract at the unit
/// boundary the lifecycle guarantees.
#[test]
fn fresh_session_import_decision_cache_is_empty() {
    use super::import_decision_cache::{ImportDecisionKey, LookupResult};
    let (session, _rib_rx) = make_test_session_with_rib(65001, 65002);
    let key = ImportDecisionKey {
        afi: Afi::Ipv4,
        safi: Safi::Unicast,
        prefix: Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, 0), 24)),
        path_id: 0,
    };
    assert!(matches!(
        session.import_decision_cache.lookup(&key, 0),
        LookupResult::NotSeen
    ));
}

/// ADR-0073 IPv6 scope: an `MP_REACH` IPv6-unicast announcement is
/// recorded in the explain cache keyed by `(Ipv6, Unicast, prefix,
/// path_id)`, proving the `MP_REACH` write path mirrors the IPv4 body
/// path.
#[tokio::test]
async fn import_decision_cache_records_ipv6_mp_reach() {
    use super::import_decision_cache::{CachedOutcome, ImportDecisionKey, LookupResult};
    let (mut session, _rib_rx) = make_test_session_with_rib(65001, 65002);
    // Import explain is opt-in (ADR-0073); this test exercises the
    // populated cache, so turn it on explicitly.
    session.import_explain_enabled = true;
    let mut negotiated = negotiated_session(65002, false);
    negotiated.negotiated_families = vec![(Afi::Ipv6, Safi::Unicast)];
    session
        .negotiated_families
        .clone_from(&negotiated.negotiated_families);
    session.negotiated = Some(negotiated);
    let v6 = Ipv6Prefix::new("2001:db8:1::".parse().unwrap(), 64);
    let mp_reach = rustbgpd_wire::MpReachNlri {
        afi: Afi::Ipv6,
        safi: Safi::Unicast,
        next_hop: IpAddr::V6("2001:db8:1::1".parse().unwrap()),
        link_local_next_hop: None,
        announced: vec![rustbgpd_wire::NlriEntry {
            path_id: 0,
            prefix: Prefix::V6(v6),
        }],
        flowspec_announced: vec![],
        evpn_announced: vec![],
        bgpls_announced: vec![],
        labeled_announced: vec![],
        vpn_announced: vec![],
        rtc_announced: vec![],
    };
    let attrs = vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath {
            segments: vec![AsPathSegment::AsSequence(vec![65002])],
        }),
        PathAttribute::MpReachNlri(mp_reach),
    ];
    let update = UpdateMessage::build(&[], &[], &attrs, true, false, Ipv4UnicastMode::Body);
    session.process_update(update).await;
    let key = ImportDecisionKey {
        afi: Afi::Ipv6,
        safi: Safi::Unicast,
        prefix: Prefix::V6(v6),
        path_id: 0,
    };
    match session.import_decision_cache.lookup(&key, 0) {
        LookupResult::Hit(d) => assert_eq!(d.outcome, CachedOutcome::Permit),
        other => panic!("expected Hit(Permit) for IPv6 MP_REACH prefix, got {other:?}"),
    }
}

/// ADR-0073 write-gating: with `[policy.explain].enabled = false`,
/// processing an UPDATE stores **no** decision — the eval-site clone is
/// skipped entirely. The empty cache after a *permitted* UPDATE is the
/// observable proof that the `if explain_enabled` guard runs before any
/// snapshot is built.
#[tokio::test]
async fn explain_disabled_stores_no_decisions() {
    use super::import_decision_cache::{ImportDecisionKey, LookupResult};
    let mut peer_config = PeerConfig::new(65001, 65002, Ipv4Addr::new(10, 0, 0, 1));
    peer_config.connect_retry_secs = 30;
    peer_config.families = vec![(Afi::Ipv4, Safi::Unicast)];
    peer_config.gr_restart_time = 120;
    let mut config = TransportConfig::new(peer_config, "10.0.0.2:179".parse().unwrap());
    config.explain_enabled = false;
    let metrics = BgpMetrics::new();
    let (_cmd_tx, cmd_rx) = mpsc::channel(8);
    let (rib_tx, _rib_rx) = mpsc::channel(64);
    // Permit-all (no import policy) so the route is accepted; only the
    // explain cache should differ from the enabled case.
    let mut session = PeerSession::new(
        config, metrics, cmd_rx, rib_tx, None, None, None, None, None, false,
    );
    let mut negotiated = negotiated_session(65002, false);
    negotiated.peer_enhanced_route_refresh = true;
    session
        .negotiated_families
        .clone_from(&negotiated.negotiated_families);
    session.negotiated = Some(negotiated);
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, 0), 24);
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
    session.process_update(update).await;
    // The route was permitted (counter moved) but nothing was cached.
    assert_eq!(session.import_policy_routes_permitted, 1);
    let key = ImportDecisionKey {
        afi: Afi::Ipv4,
        safi: Safi::Unicast,
        prefix: Prefix::V4(prefix),
        path_id: 0,
    };
    assert!(
        matches!(
            session.import_decision_cache.lookup(&key, 0),
            LookupResult::NotSeen
        ),
        "explain disabled must store no decision"
    );
    // Stronger than the lookup above, which an eagerly-allocated empty
    // cache satisfies just as well: a disabled session must be
    // allocation-free, not merely insert-free. `LruCache::new` sizes
    // its index at the configured cap up front, so building it at
    // session construction charged every peer for a cache it never
    // writes to.
    assert!(
        session.import_decision_cache.is_unallocated(),
        "explain disabled must hold no cache allocation"
    );
}

/// ADR-0073: the cached decision stores the typed `AS_PATH` only; the
/// `RouteContext.as_path_str` the statement re-derivation matches
/// against is rendered from it at query time. This drives a real
/// explain query through the command dispatch whose *rendered output*
/// exists only if that reconstruction reproduces the evaluation-time
/// string byte for byte.
///
/// The statement's regex is anchored to the exact
/// `AsPath::to_aspath_string` rendering of a three-ASN path. A
/// reconstruction that dropped the path, truncated it, or joined it
/// differently fails the regex, the statement stops matching, and the
/// trace disappears — so the rendered `matched_conditions` below exist
/// only if the reconstruction is byte-identical.
#[tokio::test]
async fn explain_trace_renders_as_path_from_the_cached_typed_value() {
    use rustbgpd_policy::NamedPolicy;
    let mut peer_config = PeerConfig::new(65001, 65002, Ipv4Addr::new(10, 0, 0, 1));
    peer_config.connect_retry_secs = 30;
    peer_config.families = vec![(Afi::Ipv4, Safi::Unicast)];
    peer_config.gr_restart_time = 120;
    let mut config = TransportConfig::new(peer_config, "10.0.0.2:179".parse().unwrap());
    // Import explain is opt-in (ADR-0073); this test exercises the
    // populated cache, so turn it on explicitly.
    config.explain_enabled = true;
    let metrics = BgpMetrics::new();
    let (_cmd_tx, cmd_rx) = mpsc::channel(8);
    let (rib_tx, _rib_rx) = mpsc::channel(64);
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, 0), 24);
    // Matches "65002 65003 65004" and nothing else — in particular not
    // the empty string a dropped `AS_PATH` would render as.
    let pattern = "^65002 65003 65004$";
    let permit_stmt = PolicyStatement {
        prefix: Some(Prefix::V4(prefix)),
        ge: None,
        le: None,
        action: PolicyAction::Permit,
        match_community: vec![],
        match_as_path: Some(AsPathRegex::new(pattern).unwrap()),
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
        modifications: RouteModifications::default(),
    };
    let chain = PolicyChain::from_named(vec![NamedPolicy {
        name: Some("as-path-explain".to_string()),
        policy: Policy {
            entries: vec![permit_stmt],
            default_action: PolicyAction::Deny,
        },
        rpol: None,
    }]);
    let mut session = PeerSession::new(
        config,
        metrics,
        cmd_rx,
        rib_tx,
        Some(chain),
        None,
        None,
        None,
        None,
        false,
    );
    let mut negotiated = negotiated_session(65002, false);
    negotiated.peer_enhanced_route_refresh = true;
    session
        .negotiated_families
        .clone_from(&negotiated.negotiated_families);
    session.negotiated = Some(negotiated);
    let attrs = vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath {
            segments: vec![AsPathSegment::AsSequence(vec![65002, 65003, 65004])],
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
    session.process_update(update).await;
    // The live evaluation permitted it: the regex matched the string the
    // inbound extractor rendered.
    assert_eq!(session.import_policy_routes_permitted, 1);

    let (reply_tx, reply_rx) = oneshot::channel();
    let _ = session
        .handle_command(PeerCommand::ExplainImportPolicy {
            afi: Afi::Ipv4,
            safi: Safi::Unicast,
            prefix: Prefix::V4(prefix),
            path_id: None,
            reply: reply_tx,
        })
        .await;
    let reply = reply_rx.await.expect("session replied");
    assert_eq!(reply.matches.len(), 1);
    let steps = &reply.matches[0].statements;
    assert_eq!(steps.len(), 1, "the hit re-derives a statement trace");
    assert_eq!(steps[0].action, PolicyAction::Permit);
    assert_eq!(
        steps[0].matched_conditions,
        vec![
            "prefix 192.0.2.0/24".to_string(),
            format!("as_path ~ {pattern:?}"),
        ],
        "the AS_PATH condition is rendered only if the query-time \
         reconstruction reproduced \"65002 65003 65004\"",
    );
}

/// LAN-320: the explain reply carries the session's own cache-enabled
/// flag (snapshotted from `[policy.explain] enabled` at session build)
/// so the RPC layer can report `CACHE_DISABLED` distinctly instead of
/// a `NOT_SEEN` lookalike.
#[tokio::test]
async fn explain_reply_carries_cache_enabled_flag() {
    for enabled in [true, false] {
        let mut peer_config = PeerConfig::new(65001, 65002, Ipv4Addr::new(10, 0, 0, 1));
        peer_config.connect_retry_secs = 30;
        peer_config.families = vec![(Afi::Ipv4, Safi::Unicast)];
        peer_config.gr_restart_time = 120;
        let mut config = TransportConfig::new(peer_config, "10.0.0.2:179".parse().unwrap());
        config.explain_enabled = enabled;
        let metrics = BgpMetrics::new();
        let (_cmd_tx, cmd_rx) = mpsc::channel(8);
        let (rib_tx, _rib_rx) = mpsc::channel(64);
        let mut session = PeerSession::new(
            config, metrics, cmd_rx, rib_tx, None, None, None, None, None, false,
        );
        let (reply_tx, reply_rx) = oneshot::channel();
        let _ = session
            .handle_command(PeerCommand::ExplainImportPolicy {
                afi: Afi::Ipv4,
                safi: Safi::Unicast,
                prefix: Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, 0), 24)),
                path_id: None,
                reply: reply_tx,
            })
            .await;
        let reply = reply_rx.await.expect("session replied");
        assert_eq!(
            reply.cache_enabled, enabled,
            "reply must snapshot the session's own explain flag"
        );
        assert!(reply.matches.is_empty(), "nothing cached, nothing matched");
    }
}

/// Import policy chains accumulate modifications across matching permit
/// policies before the route reaches the RIB.
#[expect(
    clippy::too_many_lines,
    reason = "regression test keeps accumulated policy modifications and route assertions together"
)]
#[tokio::test]
async fn import_policy_chain_accumulates_community_and_local_pref() {
    let mut peer_config = PeerConfig::new(65001, 65002, Ipv4Addr::new(10, 0, 0, 1));
    peer_config.connect_retry_secs = 30;
    peer_config.families = vec![(Afi::Ipv4, Safi::Unicast)];
    peer_config.gr_restart_time = 120;
    let config = TransportConfig::new(peer_config, "10.0.0.2:179".parse().unwrap());
    let metrics = BgpMetrics::new();
    let (_cmd_tx, cmd_rx) = mpsc::channel(8);
    let (rib_tx, mut rib_rx) = mpsc::channel(64);
    let chain = PolicyChain::new(vec![
        Policy {
            entries: vec![PolicyStatement {
                prefix: Some(Prefix::V4(Ipv4Prefix::new(Ipv4Addr::UNSPECIFIED, 0))),
                ge: Some(25),
                le: Some(32),
                action: PolicyAction::Deny,
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
                modifications: RouteModifications::default(),
            }],
            default_action: PolicyAction::Permit,
        },
        Policy {
            entries: vec![PolicyStatement {
                prefix: Some(Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 8))),
                ge: None,
                le: Some(16),
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
                    communities_add: vec![0xFDE9_0064],
                    ..Default::default()
                },
            }],
            default_action: PolicyAction::Permit,
        },
        Policy {
            entries: vec![PolicyStatement {
                prefix: None,
                ge: None,
                le: None,
                action: PolicyAction::Permit,
                match_community: vec![],
                match_as_path: Some(rustbgpd_policy::AsPathRegex::new("_65002_").unwrap()),
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
                    set_local_pref: Some(200),
                    ..Default::default()
                },
            }],
            default_action: PolicyAction::Permit,
        },
    ]);
    let mut session = PeerSession::new(
        config,
        metrics,
        cmd_rx,
        rib_tx,
        Some(chain),
        None,
        None,
        None,
        None,
        false,
    );
    session.negotiated = Some(negotiated_session(65002, false));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(10, 10, 0, 0), 16);
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
    session.process_update(update).await;
    let RibUpdate::RoutesReceived { announced, .. } = rib_rx.try_recv().unwrap() else {
        panic!("expected RoutesReceived");
    };
    assert_eq!(announced.len(), 1);
    let route = &announced[0];
    assert_eq!(route.prefix, Prefix::V4(prefix));
    assert_eq!(route.local_pref(), 200);
    assert_eq!(route.communities(), &[0xFDE9_0064]);
}

#[tokio::test]
async fn import_policy_match_next_hop_filters_route() {
    let mut peer_config = PeerConfig::new(65001, 65002, Ipv4Addr::new(10, 0, 0, 1));
    peer_config.connect_retry_secs = 30;
    peer_config.families = vec![(Afi::Ipv4, Safi::Unicast)];
    peer_config.gr_restart_time = 120;
    let config = TransportConfig::new(peer_config, "10.0.0.2:179".parse().unwrap());
    let metrics = BgpMetrics::new();
    let (_cmd_tx, cmd_rx) = mpsc::channel(8);
    let (rib_tx, mut rib_rx) = mpsc::channel(64);
    let deny_policy = PolicyChain::new(vec![Policy {
        entries: vec![PolicyStatement {
            prefix: None,
            ge: None,
            le: None,
            action: PolicyAction::Deny,
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
            match_next_hop: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))),
            modifications: RouteModifications::default(),
        }],
        default_action: PolicyAction::Permit,
    }]);
    let mut session = PeerSession::new(
        config,
        metrics,
        cmd_rx,
        rib_tx,
        Some(deny_policy),
        None,
        None,
        None,
        None,
        false,
    );
    session.negotiated = Some(negotiated_session(65002, false));
    let attrs = vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath {
            segments: vec![AsPathSegment::AsSequence(vec![65002])],
        }),
        PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
    ];
    let announced = vec![Ipv4NlriEntry {
        path_id: 0,
        prefix: Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24),
    }];
    let update = UpdateMessage::build(&announced, &[], &attrs, true, false, Ipv4UnicastMode::Body);
    session.process_update(update).await;
    assert!(
        rib_rx.try_recv().is_err(),
        "route should be filtered by next-hop"
    );
}
