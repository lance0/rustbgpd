use super::*;

#[test]
fn aspa_validation_context_uses_negotiated_asn_and_local_role() {
    let mut session = make_test_session(65001, 65002);
    session.config.peer.local_role = Some(rustbgpd_wire::BgpRole::RouteServerClient);
    session.negotiated = Some(negotiated_session(65099, false));
    let context = session.aspa_validation_context();
    assert_eq!(context.neighbor_asn, Some(65099));
    assert_eq!(
        context.local_role,
        Some(rustbgpd_wire::BgpRole::RouteServerClient)
    );
    assert!(context.first_as_check_exempt);
}

/// Load-bearing context proof: restoring the configured-role condition makes
/// the roleless neighbor ASN `None`, failing the exact negotiated-ASN assertion.
#[test]
fn aspa_validation_context_carries_neighbor_asn_without_a_role() {
    let mut session = make_test_session(65001, 65002);
    session.negotiated = Some(negotiated_session(65099, false));
    let context = session.aspa_validation_context();
    assert_eq!(context.neighbor_asn, Some(65099));
    assert_eq!(context.local_role, None);
    assert!(!context.first_as_check_exempt);
}

/// Load-bearing roleless-peer proof: restoring the configured-role gate leaves
/// the mismatched replacement installed, failing the exact withdrawal and
/// known-prefix assertions in the shared exercise.
#[tokio::test]
async fn aspa_first_as_mismatch_enforced_without_configured_role() {
    assert_aspa_first_as_mismatch_withdraws_replacement(true).await;
}

/// Load-bearing RFC 6793 OLD-peer proof: restoring the negotiated
/// four-octet-AS gate leaves the mismatched two-octet path installed, failing
/// the exact withdrawal and known-prefix assertions in the shared exercise.
#[tokio::test]
async fn aspa_first_as_mismatch_enforced_for_old_peer() {
    assert_aspa_first_as_mismatch_withdraws_replacement(false).await;
}

/// Load-bearing transparent-IX control: removing the legacy
/// `route_server_client` exemption (or applying the first-AS check to every
/// eBGP session) makes this mismatched route disappear instead of being
/// announced. This is the configuration seam used by existing route-server
/// deployments that do not also negotiate an RFC 9234 role.
#[tokio::test]
async fn aspa_first_as_mismatch_exempts_legacy_route_server_client() {
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    session.config.route_server_client = true;
    install_test_negotiated_session(&mut session, negotiated_session(65002, false));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 0), 24);

    session
        .process_update(aspa_first_as_update(prefix, 65003, true))
        .await;
    let RibUpdate::RoutesReceived {
        announced,
        withdrawn,
        ..
    } = rib_rx
        .try_recv()
        .expect("transparent-IX route must reach the RIB")
    else {
        panic!("expected route-server-client RoutesReceived");
    };
    assert_eq!(announced.len(), 1);
    assert!(withdrawn.is_empty());
    assert_eq!(session.known_prefix_count(), 1);
}

/// Load-bearing scope controls: removing either the eBGP or unicast-family
/// guard makes its corresponding mismatched path return a violation.
#[test]
fn aspa_first_as_mismatch_preserves_ibgp_and_family_scope() {
    let attrs = [PathAttribute::AsPath(AsPath {
        segments: vec![AsPathSegment::AsSequence(vec![65003])],
    })];

    let mut internal_role_session = make_test_session(65001, 65001);
    internal_role_session.config.peer.local_role = Some(BgpRole::Peer);
    install_test_negotiated_session(&mut internal_role_session, negotiated_session(65001, false));
    assert_eq!(
        internal_role_session.aspa_first_as_mismatch(false, true, &attrs),
        None,
        "the ASPA first-AS precondition is not applied to iBGP"
    );

    let mut external_role_session = make_test_session(65001, 65002);
    external_role_session.config.peer.local_role = Some(BgpRole::Peer);
    install_test_negotiated_session(&mut external_role_session, negotiated_session(65002, false));
    assert_eq!(
        external_role_session.aspa_first_as_mismatch(true, false, &attrs),
        None,
        "the draft check is scoped to IPv4/IPv6 unicast announcements"
    );

    let empty_path = [PathAttribute::AsPath(AsPath { segments: vec![] })];
    assert_eq!(
        external_role_session.aspa_first_as_mismatch(true, true, &empty_path),
        Some((None, 65002)),
        "an AS_PATH with no ordered first AS fails the neighbor-AS check"
    );
    let split_sequence = [PathAttribute::AsPath(AsPath {
        segments: vec![
            AsPathSegment::AsSequence(vec![]),
            AsPathSegment::AsSequence(vec![65003]),
        ],
    })];
    assert_eq!(
        external_role_session.aspa_first_as_mismatch(true, true, &split_sequence),
        Some((Some(65003), 65002)),
        "the first ordered ASN may be in a later AS_SEQUENCE"
    );
    let with_as_set = [PathAttribute::AsPath(AsPath {
        segments: vec![
            AsPathSegment::AsSequence(vec![65003]),
            AsPathSegment::AsSet(vec![65010]),
        ],
    })];
    assert_eq!(
        external_role_session.aspa_first_as_mismatch(true, true, &with_as_set),
        None,
        "AS_SET disposition remains outside the neighbor-AS gate"
    );
}

/// Verify that import policy `match_rpki_validation = "invalid"` + `action = "deny"`
/// actually drops RPKI-invalid routes when a `ValidationSnapshot` with a VRP table
/// is provided to the session.
#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "regression test keeps RPKI table setup and import-denial assertions together"
)]
async fn import_policy_filters_rpki_invalid_with_snapshot() {
    use rustbgpd_rpki::{ValidationSnapshot, VrpEntry, VrpTable};
    use tokio::sync::watch;
    let mut peer_config = PeerConfig::new(65001, 65002, Ipv4Addr::new(10, 0, 0, 1));
    peer_config.connect_retry_secs = 30;
    peer_config.families = vec![(Afi::Ipv4, Safi::Unicast)];
    peer_config.gr_restart_time = 120;
    let config = TransportConfig::new(peer_config, "10.0.0.2:179".parse().unwrap());
    let metrics = BgpMetrics::new();
    let (_cmd_tx, cmd_rx) = mpsc::channel(8);
    let (rib_tx, mut rib_rx) = mpsc::channel(64);
    // Build a VRP table: only 192.0.2.0/24 from AS 65002 is valid.
    // 198.51.100.0/24 from AS 65002 is invalid (VRP says AS 65099).
    let vrp_table = VrpTable::new(vec![
        VrpEntry {
            prefix: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 0)),
            prefix_len: 24,
            max_len: 24,
            origin_asn: 65002,
        },
        VrpEntry {
            prefix: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 0)),
            prefix_len: 24,
            max_len: 24,
            origin_asn: 65099, // Wrong origin → invalid for AS 65002
        },
    ]);
    let snapshot = ValidationSnapshot {
        vrp_table: Some(Arc::new(vrp_table)),
        aspa_table: None,
    };
    let (_watch_tx, watch_rx) = watch::channel(snapshot);
    // Import policy: deny RPKI-invalid routes
    let deny_invalid = PolicyChain::new(vec![Policy {
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
            match_rpki_validation: Some(rustbgpd_wire::RpkiValidation::Invalid),
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
        Some(deny_invalid),
        None,
        None,
        None,
        Some(watch_rx),
        false,
    );
    let negotiated = negotiated_session(65002, false);
    session
        .negotiated_families
        .clone_from(&negotiated.negotiated_families);
    session.negotiated = Some(negotiated);
    // UPDATE with two prefixes from AS 65002:
    //   192.0.2.0/24   → RPKI Valid  (VRP: AS 65002 covers it)   → permitted
    //   198.51.100.0/24 → RPKI Invalid (VRP says AS 65099)        → denied
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
                prefix: Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, 0), 24),
            },
            Ipv4NlriEntry {
                path_id: 0,
                prefix: Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 0), 24),
            },
        ],
        &[],
        &attrs,
        true,
        false,
        Ipv4UnicastMode::Body,
    );
    session.process_update(update).await;
    // Check what reached the RIB: only the valid prefix should be present
    let msg = rib_rx.try_recv().expect("expected RoutesReceived");
    match msg {
        RibUpdate::RoutesReceived { announced, .. } => {
            assert_eq!(
                announced.len(),
                1,
                "only RPKI-valid route should pass import policy"
            );
            assert_eq!(
                announced[0].prefix,
                Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, 0), 24))
            );
        }
        _ => panic!("expected RoutesReceived"),
    }
    // LAN-472: the RPKI-driven deny is retained for the looking-glass
    // surface with the policy_reject reason and the Invalid validation
    // state the member-support answer hinges on.
    {
        use rustbgpd_telemetry::reason_labels::ImportRejectReason;
        let entries = session.rejected_routes.snapshot();
        assert_eq!(entries.len(), 1, "the RPKI-invalid deny is retained");
        let (key, entry) = &entries[0];
        assert_eq!(
            key.prefix,
            Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 0), 24))
        );
        assert_eq!(entry.reason, ImportRejectReason::PolicyReject);
        assert_eq!(entry.rpki, rustbgpd_wire::RpkiValidation::Invalid);
    }
}

/// Load-bearing edge-ingress proof: removing the transport iBGP gate makes
/// both the IPv4 body and IPv6 `MP_REACH` paths evaluate `Invalid` at import
/// policy, so the permit-Unknown policy drops them and this exact two-route
/// assertion fails.
#[tokio::test]
async fn ibgp_import_policy_sees_unknown_aspa_for_ipv4_and_ipv6() {
    use rustbgpd_rpki::{AspaTable, ValidationSnapshot};
    use tokio::sync::watch;

    let mut peer_config = PeerConfig::new(65001, 65001, Ipv4Addr::new(10, 0, 0, 1));
    peer_config.families = vec![(Afi::Ipv4, Safi::Unicast), (Afi::Ipv6, Safi::Unicast)];
    let config = TransportConfig::new(peer_config, "10.0.0.2:179".parse().unwrap());
    let (_cmd_tx, cmd_rx) = mpsc::channel(8);
    let (rib_tx, mut rib_rx) = mpsc::channel(64);
    let snapshot = ValidationSnapshot {
        vrp_table: None,
        aspa_table: Some(Arc::new(AspaTable::new(vec![]))),
    };
    let (_watch_tx, watch_rx) = watch::channel(snapshot);
    let mut permit_unknown_statement = retention_statement(None, PolicyAction::Permit);
    permit_unknown_statement.match_aspa_validation = Some(rustbgpd_wire::AspaValidation::Unknown);
    let permit_unknown = PolicyChain::new(vec![Policy {
        entries: vec![permit_unknown_statement],
        default_action: PolicyAction::Deny,
    }]);
    let mut session = PeerSession::new(
        config,
        BgpMetrics::new(),
        cmd_rx,
        rib_tx,
        Some(permit_unknown),
        None,
        None,
        None,
        Some(watch_rx),
        false,
    );
    let mut negotiated = negotiated_session(65001, false);
    negotiated.negotiated_families = vec![(Afi::Ipv4, Safi::Unicast), (Afi::Ipv6, Safi::Unicast)];
    install_test_negotiated_session(&mut session, negotiated);

    let v4 = Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, 0), 24);
    let v6 = Ipv6Prefix::new("2001:db8::".parse().unwrap(), 32);
    let attrs = vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath {
            // No local-AS loop, but the leftmost AS does not match the iBGP
            // neighbor ASN; applying eBGP ASPA semantics would be Invalid.
            segments: vec![AsPathSegment::AsSequence(vec![65002, 65003])],
        }),
        PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
        PathAttribute::MpReachNlri(rustbgpd_wire::MpReachNlri {
            afi: Afi::Ipv6,
            safi: Safi::Unicast,
            next_hop: IpAddr::V6("2001:db8::1".parse().unwrap()),
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
        }),
    ];
    session
        .process_update(UpdateMessage::build(
            &[Ipv4NlriEntry {
                path_id: 0,
                prefix: v4,
            }],
            &[],
            &attrs,
            true,
            false,
            Ipv4UnicastMode::Body,
        ))
        .await;

    let RibUpdate::RoutesReceived { announced, .. } =
        rib_rx.try_recv().expect("both iBGP routes reach the RIB")
    else {
        panic!("expected RoutesReceived");
    };
    assert_eq!(announced.len(), 2);
    assert!(announced.iter().any(|route| route.prefix == Prefix::V4(v4)));
    assert!(announced.iter().any(|route| route.prefix == Prefix::V6(v6)));
    assert!(
        announced
            .iter()
            .all(|route| route.aspa_state == rustbgpd_wire::AspaValidation::Unknown)
    );
}

/// Verify that import policy `match_aspa_validation = "invalid"` + `action = "deny"`
/// drops ASPA-invalid routes when a `ValidationSnapshot` with an ASPA table is provided.
#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "regression test keeps ASPA table setup and import-denial assertions together"
)]
async fn import_policy_filters_aspa_invalid_with_snapshot() {
    use rustbgpd_rpki::{AspaRecord, AspaTable, ValidationSnapshot};
    use tokio::sync::watch;
    let mut peer_config = PeerConfig::new(65001, 65002, Ipv4Addr::new(10, 0, 0, 1));
    peer_config.connect_retry_secs = 30;
    peer_config.families = vec![(Afi::Ipv4, Safi::Unicast)];
    peer_config.gr_restart_time = 120;
    let config = TransportConfig::new(peer_config, "10.0.0.2:179".parse().unwrap());
    let metrics = BgpMetrics::new();
    let (_cmd_tx, cmd_rx) = mpsc::channel(8);
    let (rib_tx, mut rib_rx) = mpsc::channel(64);
    // ASPA table: AS 65003 authorizes AS 65002 as a provider.
    // AS 65004 authorizes only AS 65099 — not AS 65002.
    let aspa_table = AspaTable::new(vec![
        AspaRecord {
            customer_asn: 65003,
            provider_asns: vec![65002],
        },
        AspaRecord {
            customer_asn: 65004,
            provider_asns: vec![65099],
        },
    ]);
    let snapshot = ValidationSnapshot {
        vrp_table: None,
        aspa_table: Some(Arc::new(aspa_table)),
    };
    let (_watch_tx, watch_rx) = watch::channel(snapshot);
    // Import policy: deny ASPA-invalid routes
    let mut deny_invalid = PolicyChain::new(vec![Policy {
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
            match_aspa_validation: Some(rustbgpd_wire::AspaValidation::Invalid),
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
    deny_invalid.policies[0].name = Some("member-import".to_owned());
    let mut session = PeerSession::new(
        config,
        metrics,
        cmd_rx,
        rib_tx,
        Some(deny_invalid),
        None,
        None,
        None,
        Some(watch_rx),
        false,
    );
    let negotiated = negotiated_session(65002, false);
    session
        .negotiated_families
        .clone_from(&negotiated.negotiated_families);
    session.negotiated = Some(negotiated);
    // UPDATE with AS_PATH [65002, 65003] — ASPA Valid (65003 authorizes 65002).
    // Two prefixes: both should be permitted (same AS_PATH, same ASPA state).
    let valid_attrs = vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath {
            segments: vec![AsPathSegment::AsSequence(vec![65002, 65003])],
        }),
        PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
    ];
    let valid_update = UpdateMessage::build(
        &[Ipv4NlriEntry {
            path_id: 0,
            prefix: Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, 0), 24),
        }],
        &[],
        &valid_attrs,
        true,
        false,
        Ipv4UnicastMode::Body,
    );
    session.process_update(valid_update).await;
    // UPDATE with AS_PATH [65002, 65004] — ASPA Invalid (65004 does NOT authorize 65002).
    let invalid_attrs = vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath {
            segments: vec![AsPathSegment::AsSequence(vec![65002, 65004])],
        }),
        PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
    ];
    let invalid_update = UpdateMessage::build(
        &[Ipv4NlriEntry {
            path_id: 0,
            prefix: Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 0), 24),
        }],
        &[],
        &invalid_attrs,
        true,
        false,
        Ipv4UnicastMode::Body,
    );
    session.process_update(invalid_update).await;
    // First UPDATE (valid path) should produce a RoutesReceived with 1 route
    let msg = rib_rx
        .try_recv()
        .expect("expected RoutesReceived for valid route");
    match msg {
        RibUpdate::RoutesReceived { announced, .. } => {
            assert_eq!(
                announced.len(),
                1,
                "ASPA-valid route should pass import policy"
            );
            assert_eq!(
                announced[0].prefix,
                Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, 0), 24))
            );
        }
        _ => panic!("expected RoutesReceived"),
    }
    // Second UPDATE (invalid path) should produce RoutesReceived with 0 announced
    // (the route was denied by import policy, but withdrawn list may still be sent)
    match rib_rx.try_recv() {
        Ok(RibUpdate::RoutesReceived { announced, .. }) => {
            assert_eq!(
                announced.len(),
                0,
                "ASPA-invalid route should be dropped by import policy"
            );
        }
        Err(_) => {
            // No message at all — also acceptable (route was fully filtered)
        }
        _ => panic!("unexpected RibUpdate variant"),
    }
    // Load-bearing pair propagation proof: dropping the detailed verifier
    // result at ingress, swapping pair order, or losing policy attribution
    // makes these exact assertions fail.
    let retained = session.rejected_routes.snapshot();
    assert_eq!(retained.len(), 1);
    assert_eq!(retained[0].1.detail.as_deref(), Some("member-import"));
    assert_eq!(
        retained[0].1.aspa_invalid_hop,
        Some(rustbgpd_rpki::AspaInvalidHop {
            customer_asn: 65004,
            provider_asn: 65002,
        })
    );
}
