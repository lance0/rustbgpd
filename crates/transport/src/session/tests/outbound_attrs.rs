use super::*;

#[test]
fn ebgp_prepends_asn() {
    let session = make_test_session(65001, 65002);
    let route = make_route(100);
    let attrs = session.prepare_outbound_attributes(&route, true, Ipv4Addr::new(10, 0, 0, 1), None);
    let as_path = attrs
        .iter()
        .find_map(|a| match a {
            PathAttribute::AsPath(p) => Some(p),
            _ => None,
        })
        .unwrap();
    // Should have our ASN prepended
    if let AsPathSegment::AsSequence(asns) = &as_path.segments[0] {
        assert_eq!(asns[0], 65001);
        assert_eq!(asns[1], 65002);
    } else {
        panic!("expected AS_SEQUENCE");
    }
}

#[test]
fn route_server_client_ebgp_does_not_prepend_asn() {
    let mut session = make_test_session(65001, 65002);
    session.config.route_server_client = true;
    let route = make_route(100);
    let attrs = session.prepare_outbound_attributes(&route, true, Ipv4Addr::new(10, 0, 0, 1), None);
    let as_path = attrs
        .iter()
        .find_map(|a| match a {
            PathAttribute::AsPath(p) => Some(p),
            _ => None,
        })
        .unwrap();
    assert_eq!(
        as_path.segments,
        vec![AsPathSegment::AsSequence(vec![65002])],
    );
}

#[test]
fn route_server_client_ebgp_does_not_synthesize_as_path() {
    let mut session = make_test_session(65001, 65002);
    session.config.route_server_client = true;
    let route = Route {
        prefix: Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24)),
        next_hop: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        link_local_next_hop: None,
        next_hop_scope: None,
        peer: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        attributes: Arc::new(vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
        ]),
        received_at: Instant::now(),
        origin_type: rustbgpd_rib::RouteOrigin::Local,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        is_stale: false,
        is_llgr_stale: false,
        path_id: 0,
        validation_state: rustbgpd_wire::RpkiValidation::NotFound,
        aspa_state: rustbgpd_wire::AspaValidation::Unknown,
        aspa_context: rustbgpd_wire::AspaValidationContext::default(),
    };
    let attrs = session.prepare_outbound_attributes(&route, true, Ipv4Addr::new(10, 0, 0, 1), None);
    assert!(!attrs.iter().any(|a| matches!(a, PathAttribute::AsPath(_))));
    assert!(attrs.iter().any(|a| matches!(
        a,
        PathAttribute::NextHop(nh) if *nh == Ipv4Addr::new(10, 0, 0, 2)
    )));
}

#[test]
fn ebgp_strips_local_pref() {
    let session = make_test_session(65001, 65002);
    let route = make_route(200);
    let attrs = session.prepare_outbound_attributes(&route, true, Ipv4Addr::new(10, 0, 0, 1), None);
    assert!(
        !attrs
            .iter()
            .any(|a| matches!(a, PathAttribute::LocalPref(_)))
    );
}

#[test]
fn ibgp_preserves_local_pref() {
    let session = make_test_session(65001, 65001);
    let route = make_route(200);
    let attrs =
        session.prepare_outbound_attributes(&route, false, Ipv4Addr::new(10, 0, 0, 1), None);
    let lp = attrs.iter().find_map(|a| match a {
        PathAttribute::LocalPref(lp) => Some(*lp),
        _ => None,
    });
    assert_eq!(lp, Some(200));
}

#[test]
fn ebgp_sets_next_hop() {
    let session = make_test_session(65001, 65002);
    let route = make_route(100);
    // In production, local_ipv4 is extracted from the TCP stream's local
    // address. Test sessions have no real stream, so the caller provides
    // the address directly. Here we simulate a real local address.
    let local_ipv4 = Ipv4Addr::new(172, 16, 0, 1);
    let attrs = session.prepare_outbound_attributes(&route, true, local_ipv4, None);
    let nh = attrs
        .iter()
        .find_map(|a| match a {
            PathAttribute::NextHop(nh) => Some(*nh),
            _ => None,
        })
        .unwrap();
    assert_eq!(nh, local_ipv4);
}

#[test]
fn route_server_client_ebgp_preserves_next_hop() {
    let mut session = make_test_session(65001, 65002);
    session.config.route_server_client = true;
    let route = make_route(100);
    let attrs =
        session.prepare_outbound_attributes(&route, true, Ipv4Addr::new(172, 16, 0, 1), None);
    let nh = attrs
        .iter()
        .find_map(|a| match a {
            PathAttribute::NextHop(nh) => Some(*nh),
            _ => None,
        })
        .unwrap();
    assert_eq!(nh, Ipv4Addr::new(10, 0, 0, 2));
}

#[test]
fn route_server_client_force_next_hop_self_still_wins() {
    let mut session = make_test_session(65001, 65002);
    session.config.route_server_client = true;
    let route = make_route(100);
    let local_ipv4 = Ipv4Addr::new(172, 16, 0, 1);
    let attrs = session.prepare_outbound_attributes(
        &route,
        true,
        local_ipv4,
        Some(&rustbgpd_policy::NextHopAction::Self_),
    );
    let nh = attrs
        .iter()
        .find_map(|a| match a {
            PathAttribute::NextHop(nh) => Some(*nh),
            _ => None,
        })
        .unwrap();
    assert_eq!(nh, local_ipv4);
}

/// RFC 9494 §4.6 intra-AS exception: an LLGR-stale route advertised to
/// an iBGP peer that did NOT advertise the LLGR capability carries
/// `NO_EXPORT` and `LOCAL_PREF` zero — and keeps the `LLGR_STALE`
/// community, which "MUST NOT be removed when the route is further
/// advertised". (eBGP peers without LLGR never see the route: the RIB
/// export gate suppresses it at staging.)
#[test]
fn llgr_stale_to_non_llgr_ibgp_peer_carries_no_export_and_lpref_zero() {
    let session = make_test_session(65001, 65001);
    let route = Route {
        attributes: Arc::new(vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath {
                segments: vec![AsPathSegment::AsSequence(vec![65002])],
            }),
            PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
            PathAttribute::LocalPref(100),
            PathAttribute::Communities(vec![rustbgpd_wire::COMMUNITY_LLGR_STALE]),
        ]),
        ..make_route(100)
    };
    let attrs =
        session.prepare_outbound_attributes(&route, false, Ipv4Addr::new(10, 0, 0, 1), None);
    let comms = attrs
        .iter()
        .find_map(|a| match a {
            PathAttribute::Communities(comms) => Some(comms),
            _ => None,
        })
        .expect("communities attribute present");
    assert!(
        comms.contains(&rustbgpd_wire::COMMUNITY_LLGR_STALE),
        "LLGR_STALE must not be removed on re-advertisement"
    );
    assert!(
        comms.contains(&rustbgpd_wire::COMMUNITY_NO_EXPORT),
        "§4.6 requires NO_EXPORT toward a non-LLGR iBGP peer"
    );
    assert!(
        attrs
            .iter()
            .any(|a| matches!(a, PathAttribute::LocalPref(0))),
        "§4.6 requires LOCAL_PREF zero toward a non-LLGR iBGP peer"
    );
    // Everything else rides through untouched.
    assert!(
        attrs
            .iter()
            .any(|a| matches!(a, PathAttribute::Origin(Origin::Igp)))
    );
}

#[test]
fn llgr_rewrite_preserves_partial_communities() {
    let session = make_test_session(65001, 65001);
    let route = Route {
        attributes: Arc::new(vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath {
                segments: vec![AsPathSegment::AsSequence(vec![65002])],
            }),
            PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
            PathAttribute::LocalPref(100),
            PathAttribute::CommunitiesPartial(vec![rustbgpd_wire::COMMUNITY_LLGR_STALE]),
        ]),
        ..make_route(100)
    };

    let attrs =
        session.prepare_outbound_attributes(&route, false, Ipv4Addr::new(10, 0, 0, 1), None);
    let communities = attrs
        .iter()
        .find_map(|attr| match attr {
            PathAttribute::CommunitiesPartial(values) => Some(values),
            _ => None,
        })
        .expect("LLGR rewrite retains Partial");
    assert!(communities.contains(&rustbgpd_wire::COMMUNITY_LLGR_STALE));
    assert!(communities.contains(&rustbgpd_wire::COMMUNITY_NO_EXPORT));
    assert!(
        attrs
            .iter()
            .any(|attr| matches!(attr, PathAttribute::LocalPref(0)))
    );
}

#[test]
fn outbound_attribute_preparation_preserves_partial_community_variants() {
    let session = make_test_session(65001, 65002);
    let community = 0x0001_0002;
    let extended = rustbgpd_wire::ExtendedCommunity::new(0x0002_FDE8_0000_0064);
    let large = rustbgpd_wire::LargeCommunity::new(65_000, 1, 100);
    let route = Route {
        attributes: Arc::new(vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath {
                segments: vec![AsPathSegment::AsSequence(vec![65002])],
            }),
            PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
            PathAttribute::CommunitiesPartial(vec![community]),
            PathAttribute::ExtendedCommunitiesPartial(vec![extended]),
            PathAttribute::LargeCommunitiesPartial(vec![large]),
        ]),
        ..make_route(100)
    };

    let attrs = session.prepare_outbound_attributes(&route, true, Ipv4Addr::new(10, 0, 0, 1), None);
    assert!(matches!(
        attrs.iter().find(|attr| attr.communities().is_some()),
        Some(PathAttribute::CommunitiesPartial(values)) if values == &[community]
    ));
    assert!(matches!(
        attrs
            .iter()
            .find(|attr| attr.extended_communities().is_some()),
        Some(PathAttribute::ExtendedCommunitiesPartial(values)) if values == &[extended]
    ));
    assert!(matches!(
        attrs
            .iter()
            .find(|attr| attr.large_communities().is_some()),
        Some(PathAttribute::LargeCommunitiesPartial(values)) if values == &[large]
    ));

    let mut wire = Vec::new();
    rustbgpd_wire::attribute::encode_path_attributes(&attrs, &mut wire, true, false).unwrap();
    for (type_code, value) in [
        (8, community.to_be_bytes().to_vec()),
        (16, extended.as_u64().to_be_bytes().to_vec()),
        (
            32,
            [large.global_admin, large.local_data1, large.local_data2]
                .into_iter()
                .flat_map(u32::to_be_bytes)
                .collect(),
        ),
    ] {
        let mut frame = vec![0xe0, type_code, u8::try_from(value.len()).unwrap()];
        frame.extend(value);
        assert!(wire.windows(frame.len()).any(|window| window == frame));
    }
}

#[test]
fn plain_ebgp_strips_non_transitive_extended_communities_for_unicast() {
    let session = make_test_session(65001, 65002);
    let transitive = rustbgpd_wire::ExtendedCommunity::new(0x0002_FDE8_0000_0064);
    let non_transitive = rustbgpd_wire::ExtendedCommunity::ORIGIN_VALIDATION_INVALID;
    let route = Route {
        attributes: Arc::new(vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath {
                segments: vec![AsPathSegment::AsSequence(vec![65002])],
            }),
            PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
            PathAttribute::ExtendedCommunities(vec![transitive, non_transitive]),
        ]),
        ..make_route(100)
    };

    let attrs = session.prepare_outbound_attributes(&route, true, Ipv4Addr::new(10, 0, 0, 1), None);
    assert!(matches!(
        attrs
            .iter()
            .find(|attr| attr.extended_communities().is_some()),
        Some(PathAttribute::ExtendedCommunities(values)) if values == &[transitive]
    ));

    let route = Route {
        attributes: Arc::new(vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath {
                segments: vec![AsPathSegment::AsSequence(vec![65002])],
            }),
            PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
            PathAttribute::ExtendedCommunitiesPartial(vec![non_transitive]),
        ]),
        ..make_route(100)
    };
    let attrs = session.prepare_outbound_attributes(&route, true, Ipv4Addr::new(10, 0, 0, 1), None);
    assert!(
        attrs
            .iter()
            .all(|attr| attr.extended_communities().is_none()),
        "an empty filtered attribute is removed rather than encoded"
    );
}

#[test]
fn plain_ebgp_strips_non_transitive_extended_communities_for_mp_export() {
    let session = make_test_session(65001, 65002);
    let transitive = rustbgpd_wire::ExtendedCommunity::new(0x0002_FDE8_0000_0064);
    let non_transitive = rustbgpd_wire::ExtendedCommunity::ORIGIN_VALIDATION_INVALID;
    let mut route = make_flowspec_route();
    route
        .attributes
        .push(PathAttribute::ExtendedCommunitiesPartial(vec![
            non_transitive,
            transitive,
        ]));

    let attrs = session.prepare_outbound_attributes_flowspec(&route, true);
    assert!(matches!(
        attrs
            .iter()
            .find(|attr| attr.extended_communities().is_some()),
        Some(PathAttribute::ExtendedCommunitiesPartial(values)) if values == &[transitive]
    ));
}

#[test]
fn non_transitive_extended_communities_preserve_on_exempt_or_opted_in_export() {
    let non_transitive = rustbgpd_wire::ExtendedCommunity::ORIGIN_VALIDATION_INVALID;
    let route = Route {
        attributes: Arc::new(vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath {
                segments: vec![AsPathSegment::AsSequence(vec![65002])],
            }),
            PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
            PathAttribute::ExtendedCommunitiesPartial(vec![non_transitive]),
        ]),
        ..make_route(100)
    };

    for (name, local_asn, remote_asn, route_server_client, opted_in) in [
        ("iBGP", 65001, 65001, false, false),
        ("route-server client", 65001, 65002, true, false),
        ("plain eBGP opt-in", 65001, 65002, false, true),
    ] {
        let mut session = make_test_session(local_asn, remote_asn);
        session.config.route_server_client = route_server_client;
        session.config.send_non_transitive_extended_communities = opted_in;
        let attrs = session.prepare_outbound_attributes(
            &route,
            local_asn != remote_asn,
            Ipv4Addr::new(10, 0, 0, 1),
            None,
        );
        assert!(
            matches!(
                attrs
                    .iter()
                    .find(|attr| attr.extended_communities().is_some()),
                Some(PathAttribute::ExtendedCommunitiesPartial(values))
                    if values == &[non_transitive]
            ),
            "{name} must preserve the Partial attribute and value"
        );
    }
}

/// A fresh (non-LLGR-stale) route toward the same non-LLGR iBGP peer is
/// untouched by the §4.6 rewrite: no `NO_EXPORT`, `LOCAL_PREF` preserved.
#[test]
fn fresh_route_to_non_llgr_ibgp_peer_unmodified() {
    let session = make_test_session(65001, 65001);
    let route = Route {
        attributes: Arc::new(vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath {
                segments: vec![AsPathSegment::AsSequence(vec![65002])],
            }),
            PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
            PathAttribute::LocalPref(100),
            PathAttribute::Communities(vec![0x0001_0001]),
        ]),
        ..make_route(100)
    };
    let attrs =
        session.prepare_outbound_attributes(&route, false, Ipv4Addr::new(10, 0, 0, 1), None);
    assert!(!attrs.iter().any(|a| {
        matches!(
            a,
            PathAttribute::Communities(comms)
                if comms.contains(&rustbgpd_wire::COMMUNITY_NO_EXPORT)
        )
    }));
    assert!(
        attrs
            .iter()
            .any(|a| matches!(a, PathAttribute::LocalPref(100)))
    );
}

#[test]
fn llgr_peer_keeps_llgr_stale_community() {
    let mut session = make_test_session(65001, 65002);
    let mut negotiated = negotiated_session(65002, false);
    negotiated.peer_llgr_capable = true;
    negotiated.peer_llgr_families = vec![LlgrFamily {
        afi: Afi::Ipv4,
        safi: Safi::Unicast,
        stale_time: 3600,
        forwarding_preserved: false,
    }];
    session.negotiated = Some(Arc::new(negotiated));
    let route = Route {
        attributes: Arc::new(vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath {
                segments: vec![AsPathSegment::AsSequence(vec![65002])],
            }),
            PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
            PathAttribute::Communities(vec![rustbgpd_wire::COMMUNITY_LLGR_STALE]),
        ]),
        ..make_route(100)
    };
    let attrs = session.prepare_outbound_attributes(&route, true, Ipv4Addr::new(10, 0, 0, 1), None);
    assert!(attrs.iter().any(|a| {
        matches!(
            a,
            PathAttribute::Communities(comms)
                if comms.contains(&rustbgpd_wire::COMMUNITY_LLGR_STALE)
        )
    }));
}

#[test]
fn route_server_client_still_strips_local_pref() {
    let mut session = make_test_session(65001, 65002);
    session.config.route_server_client = true;
    let route = make_route(200);
    let attrs = session.prepare_outbound_attributes(&route, true, Ipv4Addr::new(10, 0, 0, 1), None);
    assert!(
        !attrs
            .iter()
            .any(|a| matches!(a, PathAttribute::LocalPref(_)))
    );
}

#[test]
fn ibgp_default_local_pref_when_missing() {
    let session = make_test_session(65001, 65001);
    let route = Route {
        prefix: Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24)),
        next_hop: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        link_local_next_hop: None,
        next_hop_scope: None,
        peer: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        attributes: Arc::new(vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath {
                segments: vec![AsPathSegment::AsSequence(vec![65002])],
            }),
            PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
        ]),
        received_at: Instant::now(),
        origin_type: rustbgpd_rib::RouteOrigin::Ibgp,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        is_stale: false,
        is_llgr_stale: false,
        path_id: 0,
        validation_state: rustbgpd_wire::RpkiValidation::NotFound,
        aspa_state: rustbgpd_wire::AspaValidation::Unknown,
        aspa_context: rustbgpd_wire::AspaValidationContext::default(),
    };
    let attrs =
        session.prepare_outbound_attributes(&route, false, Ipv4Addr::new(10, 0, 0, 1), None);
    let lp = attrs.iter().find_map(|a| match a {
        PathAttribute::LocalPref(lp) => Some(*lp),
        _ => None,
    });
    assert_eq!(lp, Some(100));
}

#[test]
fn rr_does_not_add_originator_or_cluster_for_local_route() {
    let mut session = make_test_session(65001, 65001);
    session.config.cluster_id = Some(Ipv4Addr::new(10, 0, 0, 9));
    let route = Route {
        prefix: Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24)),
        next_hop: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        link_local_next_hop: None,
        next_hop_scope: None,
        peer: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        attributes: Arc::new(vec![PathAttribute::Origin(Origin::Igp)]),
        received_at: Instant::now(),
        origin_type: rustbgpd_rib::RouteOrigin::Local,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        is_stale: false,
        is_llgr_stale: false,
        path_id: 0,
        validation_state: rustbgpd_wire::RpkiValidation::NotFound,
        aspa_state: rustbgpd_wire::AspaValidation::Unknown,
        aspa_context: rustbgpd_wire::AspaValidationContext::default(),
    };
    let attrs =
        session.prepare_outbound_attributes(&route, false, Ipv4Addr::new(10, 0, 0, 1), None);
    assert!(!attrs.iter().any(|a| matches!(
        a,
        PathAttribute::OriginatorId(_) | PathAttribute::ClusterList(_)
    )));
}

#[test]
fn rr_does_not_add_originator_or_cluster_for_ebgp_route() {
    let mut session = make_test_session(65001, 65001);
    session.config.cluster_id = Some(Ipv4Addr::new(10, 0, 0, 9));
    let route = make_route(100);
    let attrs =
        session.prepare_outbound_attributes(&route, false, Ipv4Addr::new(10, 0, 0, 1), None);
    assert!(!attrs.iter().any(|a| matches!(
        a,
        PathAttribute::OriginatorId(_) | PathAttribute::ClusterList(_)
    )));
}

#[test]
fn rr_adds_originator_and_cluster_for_ibgp_route() {
    let mut session = make_test_session(65001, 65001);
    let cluster_id = Ipv4Addr::new(10, 0, 0, 9);
    let source_id = Ipv4Addr::new(10, 0, 0, 42);
    session.config.cluster_id = Some(cluster_id);
    let route = Route {
        prefix: Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24)),
        next_hop: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        link_local_next_hop: None,
        next_hop_scope: None,
        peer: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        attributes: Arc::new(vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath { segments: vec![] }),
        ]),
        received_at: Instant::now(),
        origin_type: rustbgpd_rib::RouteOrigin::Ibgp,
        peer_router_id: source_id,
        is_stale: false,
        is_llgr_stale: false,
        path_id: 0,
        validation_state: rustbgpd_wire::RpkiValidation::NotFound,
        aspa_state: rustbgpd_wire::AspaValidation::Unknown,
        aspa_context: rustbgpd_wire::AspaValidationContext::default(),
    };
    let attrs =
        session.prepare_outbound_attributes(&route, false, Ipv4Addr::new(10, 0, 0, 1), None);
    assert!(
        attrs
            .iter()
            .any(|a| matches!(a, PathAttribute::OriginatorId(id) if *id == source_id))
    );
    assert!(
        attrs.iter().any(
            |a| matches!(a, PathAttribute::ClusterList(ids) if ids.as_slice() == [cluster_id])
        )
    );
}

// --- Private AS removal tests ---
#[test]
fn all_private_path_mode_remove() {
    let path = AsPath {
        segments: vec![AsPathSegment::AsSequence(vec![64512, 65000])],
    };
    let result = remove_private_asns(&path, RemovePrivateAs::Remove, 100);
    assert!(result.segments.is_empty());
}

#[test]
fn mixed_path_mode_remove_unchanged() {
    // 100 is public, 64512 is private — not all private, so unchanged
    let path = AsPath {
        segments: vec![AsPathSegment::AsSequence(vec![100, 64512, 200])],
    };
    let result = remove_private_asns(&path, RemovePrivateAs::Remove, 300);
    assert_eq!(result, path);
}

#[test]
fn mixed_path_mode_all() {
    // 100 and 200 are public, 64512 is private
    let path = AsPath {
        segments: vec![AsPathSegment::AsSequence(vec![100, 64512, 200])],
    };
    let result = remove_private_asns(&path, RemovePrivateAs::All, 300);
    assert_eq!(
        result.segments,
        vec![AsPathSegment::AsSequence(vec![100, 200])]
    );
}

#[test]
fn replace_mode() {
    // 100 is public, 64512 is private
    let path = AsPath {
        segments: vec![AsPathSegment::AsSequence(vec![100, 64512])],
    };
    let result = remove_private_asns(&path, RemovePrivateAs::Replace, 300);
    assert_eq!(
        result.segments,
        vec![AsPathSegment::AsSequence(vec![100, 300])]
    );
}

#[test]
fn four_byte_private_range() {
    let path = AsPath {
        segments: vec![AsPathSegment::AsSequence(vec![4_200_000_001])],
    };
    assert!(path.all_private());
    let result = remove_private_asns(&path, RemovePrivateAs::All, 100);
    assert!(result.segments.is_empty());
}

#[test]
fn as_set_filtering() {
    // 64512 is private, 100 is public
    let path = AsPath {
        segments: vec![AsPathSegment::AsSet(vec![64512, 100])],
    };
    let result = remove_private_asns(&path, RemovePrivateAs::All, 300);
    assert_eq!(result.segments, vec![AsPathSegment::AsSet(vec![100])]);
}

#[test]
fn empty_segment_dropped() {
    // First segment all-private → dropped; second segment has public ASN 100
    let path = AsPath {
        segments: vec![
            AsPathSegment::AsSequence(vec![64512]),
            AsPathSegment::AsSequence(vec![100]),
        ],
    };
    let result = remove_private_asns(&path, RemovePrivateAs::All, 300);
    assert_eq!(result.segments, vec![AsPathSegment::AsSequence(vec![100])]);
}

#[test]
fn disabled_noop() {
    let path = AsPath {
        segments: vec![AsPathSegment::AsSequence(vec![64512, 65000])],
    };
    let result = remove_private_asns(&path, RemovePrivateAs::Disabled, 100);
    assert_eq!(result, path);
}

#[test]
fn ibgp_unaffected() {
    let mut session = make_test_session(65001, 65001);
    session.config.remove_private_as = RemovePrivateAs::All;
    let mut route = make_route(100);
    route.attributes = Arc::new(vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath {
            segments: vec![AsPathSegment::AsSequence(vec![64512])],
        }),
        PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
        PathAttribute::LocalPref(100),
    ]);
    let attrs =
        session.prepare_outbound_attributes(&route, false, Ipv4Addr::new(10, 0, 0, 1), None);
    let as_path = attrs
        .iter()
        .find_map(|a| match a {
            PathAttribute::AsPath(p) => Some(p),
            _ => None,
        })
        .unwrap();
    // iBGP: no removal, no prepend — path unchanged
    assert_eq!(
        as_path.segments,
        vec![AsPathSegment::AsSequence(vec![64512])]
    );
}

#[test]
fn route_server_skipped() {
    let mut session = make_test_session(65001, 65002);
    session.config.route_server_client = true;
    session.config.remove_private_as = RemovePrivateAs::All;
    let mut route = make_route(100);
    route.attributes = Arc::new(vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath {
            segments: vec![AsPathSegment::AsSequence(vec![64512])],
        }),
        PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
    ]);
    let attrs = session.prepare_outbound_attributes(&route, true, Ipv4Addr::new(10, 0, 0, 1), None);
    let as_path = attrs
        .iter()
        .find_map(|a| match a {
            PathAttribute::AsPath(p) => Some(p),
            _ => None,
        })
        .unwrap();
    // Route server client: no removal, no prepend — path unchanged
    assert_eq!(
        as_path.segments,
        vec![AsPathSegment::AsSequence(vec![64512])]
    );
}

#[test]
fn flowspec_route_server_client_does_not_prepend_asn() {
    let mut session = make_test_session(65001, 65002);
    session.config.route_server_client = true;
    let mut route = make_flowspec_route();
    route.attributes.push(PathAttribute::AsPath(AsPath {
        segments: vec![AsPathSegment::AsSequence(vec![64512])],
    }));
    let attrs = session.prepare_outbound_attributes_flowspec(&route, true);
    let as_path = attrs
        .iter()
        .find_map(|a| match a {
            PathAttribute::AsPath(p) => Some(p),
            _ => None,
        })
        .unwrap();
    assert_eq!(
        as_path.segments,
        vec![AsPathSegment::AsSequence(vec![64512])]
    );
}

#[test]
fn flowspec_route_server_client_does_not_synthesize_as_path() {
    let mut session = make_test_session(65001, 65002);
    session.config.route_server_client = true;
    let route = make_flowspec_route();
    let attrs = session.prepare_outbound_attributes_flowspec(&route, true);
    assert!(!attrs.iter().any(|a| matches!(a, PathAttribute::AsPath(_))));
}

#[test]
fn ebgp_remove_private_as_all_prepends_after_removal() {
    let mut session = make_test_session(100, 200);
    session.config.remove_private_as = RemovePrivateAs::All;
    let mut route = make_route(100);
    route.attributes = Arc::new(vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath {
            segments: vec![AsPathSegment::AsSequence(vec![64512, 65535])],
        }),
        PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
    ]);
    let attrs = session.prepare_outbound_attributes(&route, true, Ipv4Addr::new(10, 0, 0, 1), None);
    let as_path = attrs
        .iter()
        .find_map(|a| match a {
            PathAttribute::AsPath(p) => Some(p),
            _ => None,
        })
        .unwrap();
    // 64512 removed (private), 65535 kept (not private: 65535 > 65534)
    // Then our ASN 100 prepended
    assert_eq!(
        as_path.segments,
        vec![AsPathSegment::AsSequence(vec![100, 65535])]
    );
}

/// RFC 9252 service TLVs are structurally checked and kept opaque. Pin value
/// preservation through the receive path and normal iBGP/eBGP export.
#[tokio::test]
async fn evpn_srv6_prefix_sid_value_survives_receive_and_export() {
    use rustbgpd_wire::{
        EthernetSegmentIdentifier, EthernetTagId, EvpnMacIp, EvpnRoute, MacAddress, MplsLabel,
        RouteDistinguisher,
    };
    let (mut receiver, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    let mut negotiated = negotiated_session(65002, false);
    negotiated.negotiated_families = vec![(Afi::L2Vpn, Safi::Evpn)];
    receiver.negotiated = Some(Arc::new(negotiated));

    // RFC 9252 sections 3/3.1: structurally valid L2 Service TLV (6).
    let service = srv6_test_service(6);
    let prefix_sid = PathAttribute::Unknown(RawAttribute {
        flags: 0xe0,
        type_code: rustbgpd_wire::constants::attr_type::PREFIX_SID,
        data: Bytes::from(service),
    });
    let route = EvpnRoute::MacIp(EvpnMacIp {
        rd: RouteDistinguisher([0, 0, 0xfd, 0xe8, 0, 0, 0, 100]),
        esi: EthernetSegmentIdentifier::ZERO,
        ethernet_tag: EthernetTagId(0),
        mac: MacAddress([0x02, 0, 0, 0, 0, 1]),
        ip: None,
        label1: MplsLabel::new(0x30), // Implicit NULL without SID transposition.
        label2: None,
    });
    let next_hop: IpAddr = "2001:db8::2".parse().unwrap();
    let attrs = vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath {
            segments: vec![AsPathSegment::AsSequence(vec![65002])],
        }),
        prefix_sid.clone(),
        PathAttribute::MpReachNlri(MpReachNlri {
            afi: Afi::L2Vpn,
            safi: Safi::Evpn,
            next_hop,
            link_local_next_hop: None,
            announced: vec![],
            flowspec_announced: vec![],
            evpn_announced: vec![route.clone()],
            bgpls_announced: vec![],
            labeled_announced: vec![],
            vpn_announced: vec![],
            rtc_announced: vec![],
        }),
    ];
    receiver
        .process_update(UpdateMessage::build(
            &[],
            &[],
            &attrs,
            true,
            false,
            Ipv4UnicastMode::MpReach,
        ))
        .await;
    let RibUpdate::RoutesReceived { evpn_announced, .. } = rib_rx.try_recv().unwrap() else {
        panic!("expected the EVPN announcement to be accepted");
    };
    assert_eq!(evpn_announced.len(), 1);
    assert!(evpn_announced[0].attributes.contains(&prefix_sid));

    for remote_asn in [65001, 65003] {
        let mut exporter = make_test_session(65001, remote_asn);
        exporter.negotiated = Some(Arc::new(negotiated_session(remote_asn, false)));
        let profile = exporter.publish_export_profile();
        let candidate = profile.prepare_evpn_candidate(&evpn_announced[0]);
        let update = profile
            .build_mp_reach(
                candidate.afi,
                candidate.safi,
                candidate.next_hop,
                None,
                &candidate.attrs,
                export::ReachNlri::Evpn(&[candidate.nlri]),
                Ipv4UnicastMode::MpReach,
            )
            .unwrap();
        let parsed = update.parse(true, false, &[]).unwrap();
        assert!(
            parsed.attributes.contains(&prefix_sid),
            "peer ASN {remote_asn}"
        );
        assert!(parsed.attributes.iter().any(|attr| matches!(
            attr, PathAttribute::MpReachNlri(mp)
                if mp.evpn_announced == [route.clone()] && mp.next_hop == next_hop
        )));
    }
}

// Reserved octets, an unknown endpoint behavior, an unknown sub-TLV, and
// an unknown sub-sub-TLV all survive the bounded structural walk.
fn srv6_test_service(kind: u8) -> Vec<u8> {
    let mut value = vec![kind, 0, 40, 0xfe, 1, 0, 33, 0xfd];
    value.extend("2001:db8:100::1".parse::<Ipv6Addr>().unwrap().octets());
    value.extend([0xff, 0xff, 0xff, 0xfc]);
    value.extend([1, 0, 6, 32, 16, 16, 0, 0, 0]);
    value.extend([99, 0, 0]);
    value.extend([99, 0, 0]);
    value
}

#[tokio::test]
async fn vpn_srv6_prefix_sid_value_survives_receive_and_export() {
    for afi in [Afi::Ipv4, Afi::Ipv6] {
        let (mut receiver, mut rib_rx) = make_test_session_with_rib(65001, 65002);
        let mut negotiated = negotiated_session(65002, false);
        negotiated.negotiated_families = vec![(afi, Safi::MplsVpn)];
        receiver.negotiated = Some(Arc::new(negotiated));
        let mut route = make_vpn_rib_route(3);
        route.next_hop = "2001:db8::2".parse().unwrap();
        if afi == Afi::Ipv6 {
            route.nlri.prefix = VpnPrefix::v6("2001:db8:100::".parse().unwrap(), 48).unwrap();
        }
        let prefix_sid = PathAttribute::Unknown(RawAttribute {
            flags: 0xe0,
            type_code: 40,
            data: Bytes::from(srv6_test_service(5)),
        });
        let mut attrs = route.attributes.as_ref().clone();
        attrs.push(prefix_sid.clone());
        attrs.push(PathAttribute::MpReachNlri(MpReachNlri {
            afi,
            safi: Safi::MplsVpn,
            next_hop: route.next_hop,
            link_local_next_hop: None,
            announced: vec![],
            flowspec_announced: vec![],
            evpn_announced: vec![],
            bgpls_announced: vec![],
            labeled_announced: vec![],
            vpn_announced: vec![rustbgpd_wire::VpnNlriEntry {
                path_id: 0,
                nlri: route.nlri.clone(),
            }],
            rtc_announced: vec![],
        }));
        receiver
            .process_update(UpdateMessage::build(
                &[],
                &[],
                &attrs,
                true,
                false,
                Ipv4UnicastMode::MpReach,
            ))
            .await;
        let RibUpdate::VpnRoutesReceived {
            announced: vpn_announced,
            ..
        } = rib_rx.try_recv().unwrap()
        else {
            panic!("expected VPN announcement");
        };
        assert_eq!(vpn_announced.len(), 1);
        assert!(vpn_announced[0].attributes.contains(&prefix_sid));
        for remote_asn in [65001, 65003] {
            let mut exporter = make_test_session(65001, remote_asn);
            let mut negotiated = negotiated_session(remote_asn, false);
            negotiated.negotiated_families = vec![(afi, Safi::MplsVpn)];
            if afi == Afi::Ipv4 {
                negotiated
                    .extended_nexthop_families
                    .insert((afi, Safi::MplsVpn), Afi::Ipv6);
            }
            exporter.negotiated = Some(Arc::new(negotiated));
            let profile = exporter.publish_export_profile();
            let candidate = profile.prepare_vpn_candidate(&vpn_announced[0]).unwrap();
            let update = profile
                .build_mp_reach(
                    candidate.afi,
                    candidate.safi,
                    candidate.next_hop,
                    None,
                    &candidate.attrs,
                    export::ReachNlri::Vpn(&[candidate.nlri]),
                    Ipv4UnicastMode::MpReach,
                )
                .unwrap();
            let parsed = update.parse(true, false, &[]).unwrap();
            assert!(
                parsed.attributes.contains(&prefix_sid),
                "peer ASN {remote_asn}"
            );
            assert!(parsed.attributes.iter().any(|attr| matches!(attr,
                PathAttribute::MpReachNlri(mp) if mp.next_hop == route.next_hop
                && mp.vpn_announced.len() == 1 && mp.vpn_announced[0].nlri == route.nlri
            )));
        }
    }
}
