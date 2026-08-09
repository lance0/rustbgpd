use super::*;

#[tokio::test]
async fn process_update_ignores_ipv4_mp_without_extended_nexthop() {
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    let negotiated = negotiated_session(65002, false);
    session
        .negotiated_families
        .clone_from(&negotiated.negotiated_families);
    session.negotiated = Some(negotiated);
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
    assert!(rib_rx.try_recv().is_err());
}

#[tokio::test]
async fn process_update_accepts_ipv4_mp_with_extended_nexthop() {
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    let negotiated = negotiated_session(65002, true);
    session
        .negotiated_families
        .clone_from(&negotiated.negotiated_families);
    session.negotiated = Some(negotiated);
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
    session.negotiated = Some(negotiated_session(65002, false));
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
    session.negotiated = Some(negotiated_session(65001, false));
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
    session.negotiated = Some(negotiated_session(65002, false));
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
async fn modified_policy_update_owns_distinct_arc_per_nlri() {
    // Two IPv4 NLRI in one UPDATE, import policy adds a community → both
    // routes are modified, so each must own a distinct (mutated) Arc
    // rather than sharing the canonical one, and the mutation must land.
    const ADDED_COMMUNITY: u32 = 0xFDE9_0064; // 65001:100
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    session.negotiated = Some(negotiated_session(65002, false));
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
        !Arc::ptr_eq(&announced[0].attributes, &announced[1].attributes),
        "policy-modified routes must each own a distinct attribute Arc"
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
