use super::*;

/// RFC 4760 §4 / RFC 8950 §4: Extended Next Hop governs only the next-hop
/// encoding, never whether IPv4 unicast may use the MP attributes. A route
/// announced in the classic body and withdrawn by an IPv4 `MP_UNREACH_NLRI`
/// must be withdrawn whether or not Extended Next Hop was negotiated.
#[tokio::test]
async fn ipv4_mp_unreach_withdraws_body_route_with_or_without_extended_nexthop() {
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24);
    for extended_nexthop in [false, true] {
        let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
        let (client, _server) = connected_stream_pair().await;
        session.test_install_stream(client);
        establish_test_session(&mut session, 65002).await;
        install_test_negotiated_session(&mut session, negotiated_session(65002, extended_nexthop));
        rfc7606_drain(&mut rib_rx);

        session
            .process_update(rfc7606_update(rfc7606_attr_bytes(&[]), &[prefix]))
            .await;
        let RibUpdate::RoutesReceived { announced, .. } = rib_rx.try_recv().unwrap() else {
            panic!("ENH={extended_nexthop}: expected the body announcement");
        };
        assert_eq!(announced.len(), 1, "ENH={extended_nexthop}");
        assert_eq!(session.known_prefix_count(), 1, "ENH={extended_nexthop}");

        // MP_UNREACH_NLRI: AFI 1, SAFI 1, withdrawn 203.0.113.0/24.
        session
            .process_update(UpdateMessage {
                withdrawn_routes: Bytes::new(),
                path_attributes: Bytes::from_static(&[0x80, 15, 7, 0, 1, 1, 24, 203, 0, 113]),
                nlri: Bytes::new(),
            })
            .await;
        let RibUpdate::RoutesReceived {
            announced,
            withdrawn,
            ..
        } = rib_rx.try_recv().unwrap()
        else {
            panic!("ENH={extended_nexthop}: IPv4 MP_UNREACH must reach the RIB");
        };
        assert!(announced.is_empty(), "ENH={extended_nexthop}");
        assert_eq!(
            withdrawn,
            vec![(Prefix::V4(prefix), 0)],
            "ENH={extended_nexthop}"
        );
        assert_eq!(session.known_prefix_count(), 0, "ENH={extended_nexthop}");
        assert_eq!(session.fsm.state(), SessionState::Established);
        assert_single_malformed_disposition(&session, "none");
    }
}

#[tokio::test]
async fn process_update_accepts_ipv4_mp_with_extended_nexthop() {
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    let negotiated = negotiated_session(65002, true);
    session.negotiated = Some(Arc::new(negotiated));
    let attrs = vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath {
            segments: vec![AsPathSegment::AsSequence(vec![65002])],
        }),
        PathAttribute::MpReachNlri(MpReachNlri {
            afi: Afi::Ipv4,
            safi: Safi::Unicast,
            next_hop: IpAddr::V6("2001:db8::1".parse().unwrap()),
            link_local_next_hop: None,
            announced: vec![NlriEntry {
                path_id: 0,
                prefix: Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24)),
            }],
            flowspec_announced: vec![],
            evpn_announced: vec![],
            bgpls_announced: vec![],
            labeled_announced: vec![],
            vpn_announced: vec![],
            rtc_announced: vec![],
        }),
    ];
    let update = UpdateMessage::build(&[], &[], &attrs, true, false, Ipv4UnicastMode::MpReach);
    session.process_update(update).await;
    let RibUpdate::RoutesReceived { announced, .. } = rib_rx.try_recv().unwrap() else {
        panic!("expected RoutesReceived");
    };
    assert_eq!(announced.len(), 1);
    assert_eq!(
        announced[0].prefix,
        Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24))
    );
    assert_eq!(
        announced[0].next_hop,
        IpAddr::V6("2001:db8::1".parse().unwrap())
    );
}

#[tokio::test]
async fn no_modification_update_shares_attribute_arc_across_nlri() {
    // Two IPv4 NLRI in one UPDATE, no import policy → both permitted with
    // no modifications. They must share one attribute `Arc` (the PR2 CoW
    // win), not deep-clone per route.
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    session.negotiated = Some(Arc::new(negotiated_session(65002, false)));
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
                prefix: Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24),
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
    let RibUpdate::RoutesReceived { announced, .. } = rib_rx.try_recv().unwrap() else {
        panic!("expected RoutesReceived");
    };
    assert_eq!(announced.len(), 2);
    assert!(
        Arc::ptr_eq(&announced[0].attributes, &announced[1].attributes),
        "two NLRI from one no-modification UPDATE must share one attribute Arc"
    );
}

/// `LOCAL_PREF` remains meaningful on iBGP. The eBGP normalization must be
/// session-type-specific rather than removing the attribute unconditionally.
#[tokio::test]
async fn ibgp_local_pref_is_preserved() {
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65001);
    session.negotiated = Some(Arc::new(negotiated_session(65001, false)));
    let update = UpdateMessage::build(
        &[Ipv4NlriEntry {
            path_id: 0,
            prefix: Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24),
        }],
        &[],
        &[
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath { segments: vec![] }),
            PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
            PathAttribute::LocalPref(500),
        ],
        true,
        false,
        Ipv4UnicastMode::Body,
    );
    session.process_update(update).await;

    let RibUpdate::RoutesReceived { announced, .. } = rib_rx.try_recv().unwrap() else {
        panic!("expected RoutesReceived");
    };
    assert_eq!(announced[0].local_pref_attr(), Some(500));
}

#[tokio::test]
async fn configured_route_server_attribute_discards_normalize_before_rib_and_count_occurrences() {
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    session.negotiated = Some(Arc::new(negotiated_session(65002, false)));
    session.config.route_server_client = true;
    session.config.discard_path_attributes = Arc::from([4, 8, 36]);
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24);
    let second_prefix = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 0), 24);
    let update = UpdateMessage::build(
        &[
            Ipv4NlriEntry { path_id: 0, prefix },
            Ipv4NlriEntry {
                path_id: 0,
                prefix: second_prefix,
            },
        ],
        &[],
        &[
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath {
                segments: vec![AsPathSegment::AsSequence(vec![65002])],
            }),
            PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
            PathAttribute::Med(4),
            PathAttribute::CommunitiesPartial(vec![0x000f_0001]),
            PathAttribute::Unknown(RawAttribute {
                flags: rustbgpd_wire::constants::attr_flags::OPTIONAL
                    | rustbgpd_wire::constants::attr_flags::TRANSITIVE
                    | rustbgpd_wire::constants::attr_flags::PARTIAL,
                type_code: 36,
                data: Bytes::from_static(&[1, 0, 0, 0, 0, 0, 0, 0]),
            }),
        ],
        true,
        false,
        Ipv4UnicastMode::Body,
    );

    session.process_update(update).await;

    let RibUpdate::RoutesReceived { announced, .. } = rib_rx.try_recv().unwrap() else {
        panic!("expected RoutesReceived");
    };
    assert_eq!(
        announced.len(),
        2,
        "discarding attributes must not discard the route"
    );
    for type_code in [4, 8, 36] {
        assert!(
            announced[0]
                .attributes
                .iter()
                .all(|attribute| attribute.type_code() != type_code),
            "configured attribute {type_code} reached the normalized RIB view"
        );
    }
    assert_eq!(
        counter_samples(&session.metrics, "bgp_path_attribute_discarded_total"),
        vec![
            (
                HashMap::from([
                    ("peer".to_string(), session.peer_label.clone()),
                    ("type_code".to_string(), "36".to_string()),
                ]),
                1.0,
            ),
            (
                HashMap::from([
                    ("peer".to_string(), session.peer_label.clone()),
                    ("type_code".to_string(), "4".to_string()),
                ]),
                1.0,
            ),
            (
                HashMap::from([
                    ("peer".to_string(), session.peer_label.clone()),
                    ("type_code".to_string(), "8".to_string()),
                ]),
                1.0,
            ),
        ]
    );
}

#[tokio::test]
async fn configured_discard_is_the_import_policy_and_explain_view() {
    use super::import_decision_cache::{ImportDecisionKey, LookupResult};

    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    session.config.route_server_client = true;
    session.config.discard_path_attributes = Arc::from([8]);
    session.import_explain_enabled = true;
    session.install_import_policy(Some(PolicyChain::new(vec![Policy {
        entries: vec![PolicyStatement {
            prefix: None,
            ge: None,
            le: None,
            action: PolicyAction::Deny,
            match_community: vec![CommunityMatch::Standard { value: 0x000f_0001 }],
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
    }])));
    session.negotiated = Some(Arc::new(negotiated_session(65002, false)));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24);
    let update = UpdateMessage::build(
        &[Ipv4NlriEntry { path_id: 0, prefix }],
        &[],
        &[
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath {
                segments: vec![AsPathSegment::AsSequence(vec![65002])],
            }),
            PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
            PathAttribute::Communities(vec![0x000f_0001]),
        ],
        true,
        false,
        Ipv4UnicastMode::Body,
    );

    session.process_update(update).await;

    let RibUpdate::RoutesReceived { announced, .. } = rib_rx.try_recv().unwrap() else {
        panic!("expected configured discard to remove the deny match before policy")
    };
    assert_eq!(announced.len(), 1);
    assert!(announced[0].communities().is_empty());
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
        LookupResult::Hit(decision) => assert!(decision.policy_context.communities.is_empty()),
        other => panic!("expected cached permit decision, got {other:?}"),
    }
}

#[tokio::test]
async fn configured_local_pref_discard_counts_before_ebgp_normalization() {
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    session.negotiated = Some(Arc::new(negotiated_session(65002, false)));
    session.config.route_server_client = true;
    session.config.discard_path_attributes = Arc::from([5]);
    let update = UpdateMessage::build(
        &[Ipv4NlriEntry {
            path_id: 0,
            prefix: Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 0), 24),
        }],
        &[],
        &[
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath {
                segments: vec![AsPathSegment::AsSequence(vec![65002])],
            }),
            PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
            PathAttribute::LocalPref(500),
        ],
        true,
        false,
        Ipv4UnicastMode::Body,
    );

    session.process_update(update).await;

    assert!(matches!(
        rib_rx.try_recv(),
        Ok(RibUpdate::RoutesReceived { .. })
    ));
    assert_eq!(
        counter_samples(&session.metrics, "bgp_path_attribute_discarded_total"),
        vec![(
            HashMap::from([
                ("peer".to_string(), session.peer_label.clone()),
                ("type_code".to_string(), "5".to_string()),
            ]),
            1.0,
        )]
    );
}

/// Ignoring a wire-supplied eBGP value happens before import policy and
/// explain caching, but a policy-set value is local intent and must survive.
#[tokio::test]
async fn ebgp_import_policy_sees_default_local_pref_and_can_set_it() {
    use super::import_decision_cache::{ImportDecisionKey, LookupResult};

    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    // Import explain is opt-in (ADR-0073); this test exercises the
    // populated cache, so turn it on explicitly.
    session.import_explain_enabled = true;
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24);
    session.install_import_policy(Some(PolicyChain::new(vec![Policy {
        entries: vec![
            PolicyStatement {
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
                match_local_pref_ge: Some(500),
                match_local_pref_le: None,
                match_med_ge: None,
                match_med_le: None,
                match_next_hop: None,
                modifications: RouteModifications::default(),
            },
            PolicyStatement {
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
                modifications: RouteModifications {
                    set_local_pref: Some(200),
                    ..RouteModifications::default()
                },
            },
        ],
        default_action: PolicyAction::Deny,
    }])));
    session.negotiated = Some(Arc::new(negotiated_session(65002, false)));
    let update = UpdateMessage::build(
        &[Ipv4NlriEntry { path_id: 0, prefix }],
        &[],
        &[
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath {
                segments: vec![AsPathSegment::AsSequence(vec![65002])],
            }),
            PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
            PathAttribute::LocalPref(500),
        ],
        true,
        false,
        Ipv4UnicastMode::Body,
    );
    session.process_update(update).await;

    let RibUpdate::RoutesReceived { announced, .. } = rib_rx.try_recv().unwrap() else {
        panic!("expected policy-set route; peer LOCAL_PREF must not match the deny term");
    };
    assert_eq!(announced[0].local_pref_attr(), Some(200));
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
        LookupResult::Hit(decision) => {
            assert_eq!(decision.policy_context.local_pref, None);
            assert_eq!(decision.modifications.set_local_pref, Some(200));
        }
        other => panic!("expected cached permit decision, got {other:?}"),
    }
}

/// The normalized attribute vector is shared by body and MP families. Exercise
/// the MP-unicast branch explicitly so eBGP stripping cannot regress into an
/// IPv4-body-only fix.
#[tokio::test]
async fn ebgp_local_pref_is_ignored_for_ipv6_mp_reach() {
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    let mut negotiated = negotiated_session(65002, false);
    negotiated.negotiated_families = vec![(Afi::Ipv6, Safi::Unicast)];
    install_test_negotiated_session(&mut session, negotiated);
    let prefix = Ipv6Prefix::new("2001:db8:1::".parse().unwrap(), 64);
    let attrs = vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath {
            segments: vec![AsPathSegment::AsSequence(vec![65002])],
        }),
        PathAttribute::LocalPref(500),
        PathAttribute::MpReachNlri(MpReachNlri {
            afi: Afi::Ipv6,
            safi: Safi::Unicast,
            next_hop: IpAddr::V6("2001:db8::1".parse().unwrap()),
            link_local_next_hop: None,
            announced: vec![NlriEntry {
                path_id: 0,
                prefix: Prefix::V6(prefix),
            }],
            flowspec_announced: vec![],
            evpn_announced: vec![],
            bgpls_announced: vec![],
            labeled_announced: vec![],
            vpn_announced: vec![],
            rtc_announced: vec![],
        }),
    ];
    let update = UpdateMessage::build(&[], &[], &attrs, true, false, Ipv4UnicastMode::Body);
    session.process_update(update).await;

    let RibUpdate::RoutesReceived { announced, .. } = rib_rx.try_recv().unwrap() else {
        panic!("expected IPv6 RoutesReceived");
    };
    assert_eq!(announced.len(), 1);
    assert_eq!(announced[0].prefix, Prefix::V6(prefix));
    assert_eq!(announced[0].local_pref_attr(), None);
}

#[tokio::test]
async fn modified_policy_update_shares_one_mutated_arc() {
    // Two IPv4 NLRI in one UPDATE, import policy adds a community → both
    // routes are modified, so they must not share the unmodified canonical
    // Arc and the mutation must land on each. Equal modifications share
    // one mutated Arc per UPDATE.
    const ADDED_COMMUNITY: u32 = 0xFDE9_0064; // 65001:100
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    session.negotiated = Some(Arc::new(negotiated_session(65002, false)));
    session.install_import_policy(Some(PolicyChain::new(vec![Policy {
        entries: vec![PolicyStatement {
            prefix: Some(Prefix::V4(Ipv4Prefix::new(Ipv4Addr::UNSPECIFIED, 0))),
            ge: None,
            le: Some(32),
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
                communities_add: vec![ADDED_COMMUNITY],
                ..RouteModifications::default()
            },
        }],
        default_action: PolicyAction::Permit,
    }])));
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
                prefix: Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24),
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
    let RibUpdate::RoutesReceived { announced, .. } = rib_rx.try_recv().unwrap() else {
        panic!("expected RoutesReceived");
    };
    assert_eq!(announced.len(), 2);
    assert!(
        Arc::ptr_eq(&announced[0].attributes, &announced[1].attributes),
        "equal modifications in one UPDATE share one mutated attribute Arc"
    );
    for route in &announced {
        assert!(
            route.attributes.iter().any(|a| matches!(
                a,
                PathAttribute::Communities(c) if c.contains(&ADDED_COMMUNITY)
            )),
            "the communities_add modification must land on each modified route"
        );
    }
}

#[tokio::test]
async fn process_update_accepts_ipv4_mp_with_extended_nexthop_and_add_path() {
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    let mut negotiated = negotiated_session(65002, true);
    // Enable Add-Path receive for IPv4 unicast
    negotiated
        .add_path_families
        .insert((Afi::Ipv4, Safi::Unicast), AddPathMode::Both);
    install_test_negotiated_session(&mut session, negotiated);
    let attrs = vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath {
            segments: vec![AsPathSegment::AsSequence(vec![65002])],
        }),
        PathAttribute::MpReachNlri(MpReachNlri {
            afi: Afi::Ipv4,
            safi: Safi::Unicast,
            next_hop: IpAddr::V6("2001:db8::1".parse().unwrap()),
            link_local_next_hop: None,
            announced: vec![NlriEntry {
                path_id: 42,
                prefix: Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24)),
            }],
            flowspec_announced: vec![],
            evpn_announced: vec![],
            bgpls_announced: vec![],
            labeled_announced: vec![],
            vpn_announced: vec![],
            rtc_announced: vec![],
        }),
    ];
    // Build with Add-Path enabled and MP encoding
    let update = UpdateMessage::build(&[], &[], &attrs, true, true, Ipv4UnicastMode::MpReach);
    session.process_update(update).await;
    let RibUpdate::RoutesReceived { announced, .. } = rib_rx.try_recv().unwrap() else {
        panic!("expected RoutesReceived");
    };
    assert_eq!(announced.len(), 1);
    assert_eq!(
        announced[0].prefix,
        Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24))
    );
    assert_eq!(
        announced[0].next_hop,
        IpAddr::V6("2001:db8::1".parse().unwrap())
    );
    assert_eq!(announced[0].path_id, 42);
}

// ---------------------------------------------------------------------------
// RFC 7606 §7.9 / §7.10: ORIGINATOR_ID and CLUSTER_LIST from an external
// neighbor are discarded. These tests cover the well-formed case, which the
// decoder does not remove.
// ---------------------------------------------------------------------------

const FORGED_ORIGINATOR: Ipv4Addr = Ipv4Addr::new(1, 1, 1, 1);

fn forged_cluster_list() -> Vec<Ipv4Addr> {
    vec![Ipv4Addr::new(10, 9, 9, 1), Ipv4Addr::new(10, 9, 9, 2)]
}

fn has_rr_attribute(attrs: &[PathAttribute]) -> bool {
    attrs.iter().any(|a| matches!(a.type_code(), 9 | 10))
}

fn rr_attribute_update(peer_asn: u32, rr_attrs: Vec<PathAttribute>) -> UpdateMessage {
    let segments = if peer_asn == 65001 {
        vec![]
    } else {
        vec![AsPathSegment::AsSequence(vec![peer_asn])]
    };
    let mut attrs = vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath { segments }),
        PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
    ];
    if peer_asn == 65001 {
        attrs.push(PathAttribute::LocalPref(100));
    }
    attrs.extend(rr_attrs);
    UpdateMessage::build(
        &[Ipv4NlriEntry {
            path_id: 0,
            prefix: Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24),
        }],
        &[],
        &attrs,
        true,
        false,
        Ipv4UnicastMode::Body,
    )
}

fn discarded_type_code_counts(session: &PeerSession) -> Vec<(String, f64)> {
    let mut rows: Vec<_> = counter_samples(&session.metrics, "bgp_path_attribute_discarded_total")
        .into_iter()
        .map(|(labels, value)| (labels["type_code"].clone(), value))
        .collect();
    rows.sort_by(|a, b| a.0.cmp(&b.0));
    rows
}

/// Process one body-IPv4 UPDATE on an Established session and return the
/// route handed to the RIB.
async fn receive_with_rr_attributes(
    session: &mut PeerSession,
    rib_rx: &mut mpsc::Receiver<RibUpdate>,
    peer_asn: u32,
    rr_attrs: Vec<PathAttribute>,
) -> Route {
    let (client, _server) = connected_stream_pair().await;
    session.test_install_stream(client);
    establish_test_session(session, peer_asn).await;
    while rib_rx.try_recv().is_ok() {}
    session
        .process_update(rr_attribute_update(peer_asn, rr_attrs))
        .await;
    assert_eq!(session.fsm.state(), SessionState::Established);
    let RibUpdate::RoutesReceived { mut announced, .. } =
        rib_rx.try_recv().expect("the route must reach the RIB")
    else {
        panic!("expected RoutesReceived");
    };
    assert_eq!(announced.len(), 1);
    announced.remove(0)
}

#[tokio::test]
async fn external_neighbor_rr_attributes_are_discarded_and_counted() {
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    let route = receive_with_rr_attributes(
        &mut session,
        &mut rib_rx,
        65002,
        vec![
            PathAttribute::OriginatorId(FORGED_ORIGINATOR),
            PathAttribute::ClusterList(forged_cluster_list()),
        ],
    )
    .await;
    assert!(
        !has_rr_attribute(&route.attributes),
        "ORIGINATOR_ID / CLUSTER_LIST from an external neighbor reached the RIB"
    );
    assert_eq!(route.originator_id(), None);
    assert!(route.cluster_list().is_empty());
    assert_eq!(
        discarded_type_code_counts(&session),
        vec![("10".to_string(), 1.0), ("9".to_string(), 1.0)]
    );
    assert!(
        counter_samples(&session.metrics, "bgp_update_malformed_causes_total").is_empty(),
        "a well-formed attribute is not a malformed-UPDATE cause"
    );
}

#[tokio::test]
async fn internal_neighbor_rr_attributes_are_kept() {
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65001);
    let route = receive_with_rr_attributes(
        &mut session,
        &mut rib_rx,
        65001,
        vec![
            PathAttribute::OriginatorId(FORGED_ORIGINATOR),
            PathAttribute::ClusterList(forged_cluster_list()),
        ],
    )
    .await;
    assert_eq!(route.originator_id(), Some(FORGED_ORIGINATOR));
    assert_eq!(route.cluster_list(), forged_cluster_list().as_slice());
    assert!(discarded_type_code_counts(&session).is_empty());
}

/// An external neighbor's attributes are discarded, so they cannot trip the
/// RFC 4456 §8 reflection-loop check first.
#[tokio::test]
async fn external_neighbor_rr_attributes_do_not_trigger_reflection_loop() {
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    let cluster_id = Ipv4Addr::new(10, 0, 0, 9);
    session.config.cluster_id = Some(cluster_id);
    let our_router_id = session.config.peer.local_router_id;
    let route = receive_with_rr_attributes(
        &mut session,
        &mut rib_rx,
        65002,
        vec![
            PathAttribute::OriginatorId(our_router_id),
            PathAttribute::ClusterList(vec![cluster_id]),
        ],
    )
    .await;
    assert!(!has_rr_attribute(&route.attributes));
    assert!(
        counter_samples(&session.metrics, "bgp_rr_loop_detected_total")
            .iter()
            .all(|(_, value)| *value == 0.0),
        "an external neighbor's UPDATE must not count as a reflection loop"
    );
}

/// The internal-neighbor loop check is unchanged by the external gate.
#[tokio::test]
async fn internal_neighbor_reflection_loop_is_still_detected() {
    for cluster_loop in [false, true] {
        let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65001);
        let cluster_id = Ipv4Addr::new(10, 0, 0, 9);
        session.config.cluster_id = Some(cluster_id);
        session.negotiated = Some(Arc::new(negotiated_session(65001, false)));
        let attr = if cluster_loop {
            PathAttribute::ClusterList(vec![cluster_id])
        } else {
            PathAttribute::OriginatorId(session.config.peer.local_router_id)
        };
        session
            .process_update(rr_attribute_update(65001, vec![attr]))
            .await;
        assert!(
            !matches!(rib_rx.try_recv(), Ok(RibUpdate::RoutesReceived { ref announced, .. }) if !announced.is_empty()),
            "a reflected route from an internal neighbor must still be dropped"
        );
    }
}

/// A forged low `ORIGINATOR_ID` or a forged `CLUSTER_LIST` from one external
/// peer must not move the identifier / cluster-list tie-break against another.
#[tokio::test]
async fn external_neighbor_rr_attributes_do_not_change_best_path() {
    use rustbgpd_rib::{BestPathReason, best_path::best_path_cmp_with_reason};
    use std::cmp::Ordering;

    async fn learned(peer_asn: u32, router_id: Ipv4Addr, rr_attrs: Vec<PathAttribute>) -> Route {
        let (mut session, mut rib_rx) = make_test_session_with_rib(65001, peer_asn);
        let mut negotiated = negotiated_session(peer_asn, false);
        negotiated.peer_router_id = router_id;
        session.negotiated = Some(Arc::new(negotiated));
        session
            .process_update(rr_attribute_update(peer_asn, rr_attrs))
            .await;
        let RibUpdate::RoutesReceived { mut announced, .. } = rib_rx.try_recv().unwrap() else {
            panic!("expected RoutesReceived");
        };
        announced.remove(0)
    }

    // Identifier step: the honest peer has the lower BGP Identifier; the
    // other peer forges an ORIGINATOR_ID lower still.
    let honest = learned(65002, Ipv4Addr::new(10, 0, 0, 2), vec![]).await;
    let forger = learned(
        65003,
        Ipv4Addr::new(10, 0, 0, 3),
        vec![PathAttribute::OriginatorId(FORGED_ORIGINATOR)],
    )
    .await;
    // CLUSTER_LIST step: equal identifiers, one peer carries a forged list.
    let plain = learned(65002, Ipv4Addr::new(10, 0, 0, 2), vec![]).await;
    let padded = learned(
        65003,
        Ipv4Addr::new(10, 0, 0, 2),
        vec![PathAttribute::ClusterList(forged_cluster_list())],
    )
    .await;
    // Both steps are evaluated before asserting so one failure cannot hide
    // the other. With nothing forged left, the second pair ties all the way
    // down to the final path-id step.
    assert_eq!(
        (
            best_path_cmp_with_reason(&honest, &forger),
            best_path_cmp_with_reason(&plain, &padded),
        ),
        (
            (Ordering::Less, BestPathReason::LowerBgpIdentifier),
            (Ordering::Equal, BestPathReason::LowerPathId),
        ),
        "forged ORIGINATOR_ID / CLUSTER_LIST from an external peer changed selection"
    );
}

/// An attribute covered by both the external-neighbor rule and the operator's
/// `discard_path_attributes` is one discard, counted once.
#[tokio::test]
async fn external_neighbor_rr_discard_counts_once_with_configured_discard() {
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    session.config.route_server_client = true;
    session.config.discard_path_attributes = Arc::from([9]);
    let route = receive_with_rr_attributes(
        &mut session,
        &mut rib_rx,
        65002,
        vec![PathAttribute::OriginatorId(FORGED_ORIGINATOR)],
    )
    .await;
    assert!(!has_rr_attribute(&route.attributes));
    assert_eq!(
        discarded_type_code_counts(&session),
        vec![("9".to_string(), 1.0)]
    );
}

/// Boundary: a zero-length `CLUSTER_LIST` decodes as an empty list. From an
/// external neighbor it is discarded like any other, and counted once.
#[tokio::test]
async fn external_neighbor_empty_cluster_list_is_discarded() {
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    let route = receive_with_rr_attributes(
        &mut session,
        &mut rib_rx,
        65002,
        vec![PathAttribute::ClusterList(vec![])],
    )
    .await;
    assert!(!has_rr_attribute(&route.attributes));
    assert_eq!(
        discarded_type_code_counts(&session),
        vec![("10".to_string(), 1.0)]
    );
}

/// Every family path stores attributes derived from the one normalized set,
/// so the external-neighbor discard holds for each of them.
#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "one matrix pins every family path that stores attributes from an UPDATE"
)]
async fn external_neighbor_rr_attributes_are_discarded_for_every_family() {
    use rustbgpd_wire::{
        EthernetSegmentIdentifier, EthernetTagId, EvpnMacIp, EvpnRoute, MacAddress, MplsLabel,
        RtcNlri,
    };

    async fn stored_attrs(
        family: (Afi, Safi),
        next_hop: IpAddr,
        fill: impl FnOnce(&mut rustbgpd_wire::MpReachNlri),
    ) -> (Vec<PathAttribute>, Vec<(String, f64)>) {
        let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
        let mut negotiated = negotiated_session(65002, false);
        negotiated.negotiated_families = vec![family];
        install_test_negotiated_session(&mut session, negotiated);
        let mut reach = empty_nonunicast_reach(family.0, family.1, next_hop);
        fill(&mut reach);
        let mut attrs = nonunicast_accepted_attrs();
        attrs.push(PathAttribute::OriginatorId(FORGED_ORIGINATOR));
        attrs.push(PathAttribute::ClusterList(forged_cluster_list()));
        session
            .process_update(nonunicast_update(attrs, reach, None, false))
            .await;
        let counts = discarded_type_code_counts(&session);
        let attrs = match rib_rx
            .try_recv()
            .unwrap_or_else(|_| panic!("{family:?}: no route reached the RIB"))
        {
            RibUpdate::RoutesReceived {
                announced,
                flowspec_announced,
                evpn_announced,
                ..
            } => announced
                .first()
                .map(|r| r.attributes.to_vec())
                .or_else(|| flowspec_announced.first().map(|r| r.attributes.clone()))
                .or_else(|| evpn_announced.first().map(|r| r.attributes.to_vec())),
            RibUpdate::BgpLsRoutesReceived { announced, .. } => {
                announced.first().map(|r| r.attributes.to_vec())
            }
            RibUpdate::VpnRoutesReceived { announced, .. } => {
                announced.first().map(|r| r.attributes.to_vec())
            }
            RibUpdate::LabeledRoutesReceived { announced, .. } => {
                announced.first().map(|r| r.attributes.to_vec())
            }
            RibUpdate::RtcRoutesReceived { announced, .. } => {
                announced.first().map(|r| r.attributes.to_vec())
            }
            _ => panic!("{family:?}: unexpected RIB update"),
        }
        .unwrap_or_else(|| panic!("{family:?}: the announcement was not installed"));
        (attrs, counts)
    }

    let v4_next_hop = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let v6_prefix = Prefix::V6(Ipv6Prefix::new("2001:db8:710::".parse().unwrap(), 48));
    let cases = vec![
        (
            (Afi::Ipv6, Safi::Unicast),
            stored_attrs(
                (Afi::Ipv6, Safi::Unicast),
                "2001:db8::2".parse().unwrap(),
                |mp| {
                    mp.announced = vec![NlriEntry {
                        path_id: 0,
                        prefix: v6_prefix,
                    }];
                },
            )
            .await,
        ),
        (
            (Afi::Ipv4, Safi::FlowSpec),
            stored_attrs((Afi::Ipv4, Safi::FlowSpec), v4_next_hop, |mp| {
                mp.flowspec_announced = vec![FlowSpecRule {
                    components: vec![FlowSpecComponent::DestinationPrefix(FlowSpecPrefix::V4(
                        Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 0), 24),
                    ))],
                }];
            })
            .await,
        ),
        (
            (Afi::L2Vpn, Safi::Evpn),
            stored_attrs((Afi::L2Vpn, Safi::Evpn), v4_next_hop, |mp| {
                mp.evpn_announced = vec![EvpnRoute::MacIp(EvpnMacIp {
                    rd: RouteDistinguisher([0, 0, 0xFD, 0xE8, 0, 0, 0, 100]),
                    esi: EthernetSegmentIdentifier::ZERO,
                    ethernet_tag: EthernetTagId(100),
                    mac: MacAddress([0x02, 0x00, 0x00, 0xAA, 0xBB, 0xCC]),
                    ip: None,
                    label1: MplsLabel::new(10_000),
                    label2: None,
                })];
            })
            .await,
        ),
        (
            (Afi::BgpLs, Safi::BgpLs),
            stored_attrs((Afi::BgpLs, Safi::BgpLs), v4_next_hop, |mp| {
                mp.bgpls_announced =
                    decode_bgpls_nlri(&[0xfd, 0xe8, 0, 3, 0xaa, 0xcc, 11]).unwrap();
            })
            .await,
        ),
        (
            (Afi::Ipv4, Safi::MplsVpn),
            stored_attrs((Afi::Ipv4, Safi::MplsVpn), v4_next_hop, |mp| {
                mp.vpn_announced = vec![rustbgpd_wire::VpnNlriEntry {
                    path_id: 0,
                    nlri: VpnNlri {
                        labels: vec![MplsLabelEntry::try_new(4093, 0, true).unwrap()],
                        route_distinguisher: RouteDistinguisher([0, 0, 0xfd, 0xe8, 0, 0, 0, 45]),
                        prefix: VpnPrefix::v4(Ipv4Addr::new(10, 44, 5, 0), 24).unwrap(),
                    },
                }];
            })
            .await,
        ),
        (
            (Afi::Ipv4, Safi::LabeledUnicast),
            stored_attrs((Afi::Ipv4, Safi::LabeledUnicast), v4_next_hop, |mp| {
                mp.labeled_announced = vec![rustbgpd_wire::LabeledNlriEntry {
                    path_id: 0,
                    nlri: rustbgpd_wire::LabeledNlri {
                        labels: vec![MplsLabelEntry::try_new(4092, 0, true).unwrap()],
                        prefix: Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 44, 6, 0), 24)),
                    },
                }];
            })
            .await,
        ),
        (
            (Afi::Ipv4, Safi::RtConstrain),
            stored_attrs((Afi::Ipv4, Safi::RtConstrain), v4_next_hop, |mp| {
                mp.rtc_announced = vec![RtcNlri::new(65002, 0x0002_FDEA_0000_000B, 96).unwrap()];
            })
            .await,
        ),
    ];
    assert_eq!(cases.len(), 7);
    // Collect every failing family so one family cannot mask another.
    let mut kept = Vec::new();
    let mut miscounted = Vec::new();
    for (family, (attrs, counts)) in cases {
        assert!(
            attrs.iter().any(|a| matches!(a, PathAttribute::AsPath(_))),
            "{family:?}: fixture sanity — the stored set must still carry AS_PATH"
        );
        if has_rr_attribute(&attrs) {
            kept.push(family);
        }
        if counts != [("10".to_string(), 1.0), ("9".to_string(), 1.0)] {
            miscounted.push(family);
        }
    }
    assert_eq!(
        (kept, miscounted),
        (vec![], vec![]),
        "families that kept (left) or did not count (right) an external neighbor's \
         ORIGINATOR_ID / CLUSTER_LIST"
    );
}

/// A modifying import policy materializes one attribute set per distinct
/// modification per UPDATE, not one deep clone per accepted NLRI: the RIB
/// otherwise hashes, compares, and frees every duplicate on its actor.
/// Routes with different modifications keep distinct sets.
#[tokio::test]
async fn modifying_import_shares_one_attribute_set_per_distinct_modification() {
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    let prefix = |octet: u8| Ipv4Prefix::new(Ipv4Addr::new(203, 0, octet, 0), 24);
    let mut low = retention_statement(Some(Prefix::V4(prefix(3))), PolicyAction::Permit);
    low.modifications.set_local_pref = Some(100);
    let mut high = retention_statement(None, PolicyAction::Permit);
    high.modifications.set_local_pref = Some(200);
    session.install_import_policy(Some(PolicyChain::new(vec![Policy {
        entries: vec![low, high],
        default_action: PolicyAction::Deny,
    }])));
    session.negotiated = Some(Arc::new(negotiated_session(65002, false)));
    let entries: Vec<Ipv4NlriEntry> = (1..=3)
        .map(|octet| Ipv4NlriEntry {
            path_id: 0,
            prefix: prefix(octet),
        })
        .collect();
    let update = UpdateMessage::build(
        &entries,
        &[],
        &[
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath {
                segments: vec![AsPathSegment::AsSequence(vec![65002])],
            }),
            PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
        ],
        true,
        false,
        Ipv4UnicastMode::Body,
    );
    session.process_update(update).await;

    let RibUpdate::RoutesReceived { announced, .. } = rib_rx.try_recv().unwrap() else {
        panic!("expected accepted routes");
    };
    let by_prefix = |octet: u8| {
        announced
            .iter()
            .find(|route| route.prefix == Prefix::V4(prefix(octet)))
            .unwrap()
    };
    assert_eq!(by_prefix(1).local_pref_attr(), Some(200));
    assert_eq!(by_prefix(3).local_pref_attr(), Some(100));
    assert!(
        Arc::ptr_eq(&by_prefix(1).attributes, &by_prefix(2).attributes),
        "equal modifications in one UPDATE must share one attribute set"
    );
    assert!(!Arc::ptr_eq(
        &by_prefix(1).attributes,
        &by_prefix(3).attributes
    ));
}
