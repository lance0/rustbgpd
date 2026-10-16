use super::*;
use rustbgpd_rib::AttrSet;

/// VPN `MP_REACH` must carry the original label stack and the stored VPN
/// next-hop verbatim — even on an eBGP session, where unicast would rewrite
/// to next-hop-self (ADR-0077 §6: next-hop-self is inert for SAFI 128). The
/// withdraw is emitted via `MP_UNREACH` with an empty (ignored) label stack.
#[expect(
    clippy::too_many_lines,
    reason = "pins label-stack pass-through, verbatim next-hop, and the withdraw in one wire sequence"
)]
#[tokio::test]
async fn send_route_update_emits_vpn_reach_and_unreach() {
    let (mut session, _rib_rx) = make_test_session_with_rib(65001, 65002);
    let (client, mut server) = connected_stream_pair().await;
    session.test_install_stream(client);
    let mut negotiated = negotiated_session(65002, false);
    negotiated.negotiated_families = vec![(Afi::Ipv4, Safi::MplsVpn)];
    session.negotiated = Some(Arc::new(negotiated));
    let route = make_vpn_rib_route(4093);
    let key = route.key();
    session.send_route_update(OutboundRouteUpdate {
        replay: None,
        exact_export_snapshot: Some(session.publish_export_profile()),
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
        vpn_announce: vec![route.clone()],
        labeled_announce: vec![],
        rtc_announce: vec![],
        vpn_withdraw: vec![],
        labeled_withdraw: vec![],
        rtc_withdraw: vec![],
        request_refresh_all_negotiated: false,
        shared_group_encode: None,
    });
    let Message::Update(msg) = read_single_bgp_message(&mut server).await else {
        panic!("expected VPN MP_REACH UPDATE");
    };
    let parsed = msg.parse(true, false, &[]).unwrap();
    let mp = parsed
        .attributes
        .iter()
        .find_map(|attr| match attr {
            PathAttribute::MpReachNlri(mp) => Some(mp),
            _ => None,
        })
        .expect("VPN announcement must use MP_REACH");
    assert_eq!(mp.afi, Afi::Ipv4);
    assert_eq!(mp.safi, Safi::MplsVpn);
    assert_eq!(
        mp.next_hop, route.next_hop,
        "VPN next-hop must pass through reflection unchanged"
    );
    assert_eq!(
        mp.vpn_announced,
        vec![rustbgpd_wire::VpnNlriEntry {
            path_id: 0,
            nlri: route.nlri.clone()
        }],
        "RD + MPLS label stack must round-trip verbatim"
    );
    session.send_route_update(OutboundRouteUpdate {
        replay: None,
        exact_export_snapshot: Some(session.publish_export_profile()),
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
        vpn_withdraw: vec![key],
        labeled_withdraw: vec![],
        rtc_withdraw: vec![],
        request_refresh_all_negotiated: false,
        shared_group_encode: None,
    });
    let Message::Update(msg) = read_single_bgp_message(&mut server).await else {
        panic!("expected VPN MP_UNREACH UPDATE");
    };
    let parsed = msg.parse(true, false, &[]).unwrap();
    let mp = parsed
        .attributes
        .iter()
        .find_map(|attr| match attr {
            PathAttribute::MpUnreachNlri(mp) => Some(mp),
            _ => None,
        })
        .expect("VPN withdrawal must use MP_UNREACH");
    assert_eq!(mp.afi, Afi::Ipv4);
    assert_eq!(mp.safi, Safi::MplsVpn);
    assert_eq!(
        mp.vpn_withdrawn,
        vec![rustbgpd_wire::VpnNlriEntry {
            path_id: 0,
            nlri: VpnNlri {
                labels: vec![],
                route_distinguisher: route.nlri.route_distinguisher,
                prefix: route.nlri.prefix,
            }
        }],
        "withdraw-mode NLRI carries no label stack (RFC 8277 §2.4 compatibility field)"
    );
}

/// RFC 7911 VPN outbound: with Add-Path send negotiated for (IPv4, SAFI
/// 128), announcements and withdrawals both carry the 4-octet path ID.
#[tokio::test]
async fn send_route_update_emits_vpn_add_path_reach_and_unreach() {
    let (mut session, _rib_rx) = make_test_session_with_rib(65001, 65002);
    let (client, mut server) = connected_stream_pair().await;
    session.test_install_stream(client);
    let mut negotiated = negotiated_session(65002, false);
    negotiated.negotiated_families = vec![(Afi::Ipv4, Safi::MplsVpn)];
    negotiated
        .add_path_families
        .insert((Afi::Ipv4, Safi::MplsVpn), AddPathMode::Both);
    session.negotiated = Some(Arc::new(negotiated));
    let mut route = make_vpn_rib_route(4093);
    route.path_id = 2;
    let key = route.key();
    session.send_route_update(OutboundRouteUpdate {
        exact_export_snapshot: Some(session.publish_export_profile()),
        vpn_announce: vec![route.clone()],
        ..empty_outbound_update()
    });
    let Message::Update(msg) = read_single_bgp_message(&mut server).await else {
        panic!("expected VPN Add-Path MP_REACH UPDATE");
    };
    let vpn_add_path = [(Afi::Ipv4, Safi::MplsVpn)];
    let parsed = msg.parse(true, false, &vpn_add_path).unwrap();
    let mp = parsed
        .attributes
        .iter()
        .find_map(|attr| match attr {
            PathAttribute::MpReachNlri(mp) => Some(mp),
            _ => None,
        })
        .expect("VPN Add-Path announcement must use MP_REACH");
    assert_eq!(
        mp.vpn_announced,
        vec![rustbgpd_wire::VpnNlriEntry {
            path_id: 2,
            nlri: route.nlri.clone()
        }],
        "announcement must carry the outbound path ID"
    );
    session.send_route_update(OutboundRouteUpdate {
        replay: None,
        exact_export_snapshot: Some(session.publish_export_profile()),
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
        vpn_withdraw: vec![key],
        labeled_withdraw: vec![],
        rtc_withdraw: vec![],
        request_refresh_all_negotiated: false,
        shared_group_encode: None,
    });
    let Message::Update(msg) = read_single_bgp_message(&mut server).await else {
        panic!("expected VPN Add-Path MP_UNREACH UPDATE");
    };
    let parsed = msg.parse(true, false, &vpn_add_path).unwrap();
    let mp = parsed
        .attributes
        .iter()
        .find_map(|attr| match attr {
            PathAttribute::MpUnreachNlri(mp) => Some(mp),
            _ => None,
        })
        .expect("VPN Add-Path withdrawal must use MP_UNREACH");
    assert_eq!(mp.vpn_withdrawn.len(), 1);
    assert_eq!(
        mp.vpn_withdrawn[0].path_id, 2,
        "withdrawal must carry the outbound path ID"
    );
}

/// RFC 7911 VPN inbound: with Add-Path receive negotiated for (IPv4, SAFI
/// 128), the decoded path ID threads into the `VpnRibRouteKey`/`VpnRibRoute`
/// delivered to the RIB — announcements and withdrawals alike.
#[tokio::test]
async fn process_update_threads_vpn_add_path_ids_into_rib_keys() {
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    let mut negotiated = negotiated_session(65002, true);
    negotiated.negotiated_families = vec![(Afi::Ipv4, Safi::MplsVpn)];
    negotiated
        .add_path_families
        .insert((Afi::Ipv4, Safi::MplsVpn), AddPathMode::Both);
    install_test_negotiated_session(&mut session, negotiated);
    let nlri = VpnNlri {
        labels: vec![MplsLabelEntry::try_new(4093, 0, true).unwrap()],
        route_distinguisher: RouteDistinguisher([0, 0, 0xFD, 0xE8, 0, 0, 0, 1]),
        prefix: VpnPrefix::v4(Ipv4Addr::new(10, 0, 1, 0), 24).unwrap(),
    };
    let attrs = vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath {
            segments: vec![AsPathSegment::AsSequence(vec![65002])],
        }),
        PathAttribute::MpReachNlri(Box::new(MpReachNlri {
            afi: Afi::Ipv4,
            safi: Safi::MplsVpn,
            next_hop: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7)),
            link_local_next_hop: None,
            announced: vec![],
            flowspec_announced: vec![],
            evpn_announced: vec![],
            bgpls_announced: vec![],
            labeled_announced: vec![],
            vpn_announced: vec![
                rustbgpd_wire::VpnNlriEntry {
                    path_id: 1,
                    nlri: nlri.clone(),
                },
                rustbgpd_wire::VpnNlriEntry {
                    path_id: 2,
                    nlri: nlri.clone(),
                },
            ],
            rtc_announced: vec![],
        })),
    ];
    let update = UpdateMessage::build(&[], &[], &attrs, true, true, Ipv4UnicastMode::Body);
    session.process_update(update).await;
    let RibUpdate::VpnRoutesReceived { announced, .. } = rib_rx.try_recv().unwrap() else {
        panic!("expected VpnRoutesReceived");
    };
    assert_eq!(announced.len(), 2);
    assert_eq!(announced[0].path_id, 1);
    assert_eq!(announced[1].path_id, 2);
    assert_eq!(announced[0].nlri, nlri);
    assert_eq!(
        announced[0].key(),
        rustbgpd_rib::VpnRibRouteKey {
            nlri_key: nlri.key(),
            path_id: 1,
        }
    );

    // Withdraw ONLY path 1 — the delivered key must carry the path ID.
    let attrs = vec![PathAttribute::MpUnreachNlri(Box::new(MpUnreachNlri {
        afi: Afi::Ipv4,
        safi: Safi::MplsVpn,
        withdrawn: vec![],
        flowspec_withdrawn: vec![],
        evpn_withdrawn: vec![],
        bgpls_withdrawn: vec![],
        labeled_withdrawn: vec![],
        vpn_withdrawn: vec![rustbgpd_wire::VpnNlriEntry {
            path_id: 1,
            nlri: VpnNlri {
                labels: vec![],
                route_distinguisher: nlri.route_distinguisher,
                prefix: nlri.prefix,
            },
        }],
        rtc_withdrawn: vec![],
    }))];
    let update = UpdateMessage::build(&[], &[], &attrs, true, true, Ipv4UnicastMode::Body);
    session.process_update(update).await;
    let RibUpdate::VpnRoutesReceived { withdrawn, .. } = rib_rx.try_recv().unwrap() else {
        panic!("expected VpnRoutesReceived withdrawal");
    };
    assert_eq!(
        withdrawn,
        vec![rustbgpd_rib::VpnRibRouteKey {
            nlri_key: nlri.key(),
            path_id: 1,
        }]
    );
}

/// Import-policy denial retires an accepted VPN Add-Path identity exactly,
/// deduplicates an overlapping explicit withdrawal, preserves siblings, and
/// keeps first-seen denials silent for both `VPNv4` and `VPNv6`.
///
/// Break-to-red: deleting denied-key collection or its presence-gated
/// `known_vpn.remove` leaves the denied path accepted; blindly appending the
/// key duplicates the overlap and emits the first-seen path.
#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "one scenario pins exact VPN identity and accounting across both address families"
)]
async fn denied_vpn_add_path_replacements_withdraw_exact_known_identity() {
    #[expect(
        clippy::too_many_lines,
        reason = "the shared dual-AFI fixture keeps all identity transitions in one stateful session"
    )]
    async fn exercise(afi: Afi) {
        let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
        let family = (afi, Safi::MplsVpn);
        let mut negotiated = negotiated_session(65002, true);
        negotiated.negotiated_families = vec![family];
        negotiated
            .add_path_families
            .insert(family, AddPathMode::Both);
        install_test_negotiated_session(&mut session, negotiated);

        let prefix = match afi {
            Afi::Ipv4 => VpnPrefix::v4(Ipv4Addr::new(10, 44, 2, 0), 24).unwrap(),
            Afi::Ipv6 => VpnPrefix::v6("2001:db8:442::".parse().unwrap(), 64).unwrap(),
            _ => unreachable!("test covers IP VPN families"),
        };
        let nlri = VpnNlri {
            labels: vec![MplsLabelEntry::try_new(4093, 0, true).unwrap()],
            route_distinguisher: RouteDistinguisher([0, 0, 0xFD, 0xE8, 0, 0, 0, 44]),
            prefix,
        };
        let next_hop = match afi {
            Afi::Ipv4 => IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7)),
            Afi::Ipv6 => IpAddr::V6("2001:db8::7".parse().unwrap()),
            _ => unreachable!("test covers IP VPN families"),
        };
        let base_attrs = || {
            vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath {
                    segments: vec![AsPathSegment::AsSequence(vec![65002])],
                }),
            ]
        };
        let reach = |path_ids: &[u32]| {
            PathAttribute::MpReachNlri(Box::new(MpReachNlri {
                afi,
                safi: Safi::MplsVpn,
                next_hop,
                link_local_next_hop: None,
                announced: vec![],
                flowspec_announced: vec![],
                evpn_announced: vec![],
                bgpls_announced: vec![],
                labeled_announced: vec![],
                vpn_announced: path_ids
                    .iter()
                    .map(|path_id| rustbgpd_wire::VpnNlriEntry {
                        path_id: *path_id,
                        nlri: nlri.clone(),
                    })
                    .collect(),
                rtc_announced: vec![],
            }))
        };
        let unreach = |path_id| {
            PathAttribute::MpUnreachNlri(Box::new(MpUnreachNlri {
                afi,
                safi: Safi::MplsVpn,
                withdrawn: vec![],
                flowspec_withdrawn: vec![],
                evpn_withdrawn: vec![],
                bgpls_withdrawn: vec![],
                labeled_withdrawn: vec![],
                vpn_withdrawn: vec![rustbgpd_wire::VpnNlriEntry {
                    path_id,
                    nlri: VpnNlri {
                        labels: vec![],
                        route_distinguisher: nlri.route_distinguisher,
                        prefix: nlri.prefix,
                    },
                }],
                rtc_withdrawn: vec![],
            }))
        };
        let update = |attributes: Vec<PathAttribute>| {
            UpdateMessage::build(&[], &[], &attributes, true, true, Ipv4UnicastMode::Body)
        };
        let key = |path_id| rustbgpd_rib::VpnRibRouteKey {
            nlri_key: nlri.key(),
            path_id,
        };

        let mut attributes = base_attrs();
        attributes.push(reach(&[11, 22, 33]));
        session.process_update(update(attributes)).await;
        let RibUpdate::VpnRoutesReceived {
            announced,
            withdrawn,
            ..
        } = rib_rx.try_recv().expect("accepted VPN paths reach the RIB")
        else {
            panic!("expected VpnRoutesReceived");
        };
        assert_eq!(announced.len(), 3);
        assert_eq!(withdrawn.len(), 0);
        assert_eq!(session.known_prefix_count(), 3);
        for path_id in [11, 22, 33] {
            assert!(session.known_vpn.contains(&key(path_id)));
        }

        session.install_import_policy(Some(PolicyChain::new(vec![Policy {
            entries: vec![],
            default_action: PolicyAction::Deny,
        }])));

        let mut attributes = base_attrs();
        attributes.push(reach(&[11]));
        session.process_update(update(attributes)).await;
        let RibUpdate::VpnRoutesReceived {
            announced,
            withdrawn,
            ..
        } = rib_rx
            .try_recv()
            .expect("denied replacement reaches the RIB")
        else {
            panic!("expected VpnRoutesReceived");
        };
        assert!(announced.is_empty());
        assert_eq!(withdrawn, vec![key(11)]);
        assert!(!session.known_vpn.contains(&key(11)));
        assert!(session.known_vpn.contains(&key(22)));
        assert!(session.known_vpn.contains(&key(33)));
        assert_eq!(session.known_prefix_count(), 2);

        let mut attributes = base_attrs();
        attributes.push(reach(&[22]));
        attributes.push(unreach(22));
        session.process_update(update(attributes)).await;
        let RibUpdate::VpnRoutesReceived {
            announced,
            withdrawn,
            ..
        } = rib_rx
            .try_recv()
            .expect("overlapping withdrawal reaches the RIB")
        else {
            panic!("expected VpnRoutesReceived");
        };
        assert!(announced.is_empty());
        assert_eq!(withdrawn.len(), 1, "overlap must not duplicate the key");
        assert_eq!(withdrawn, vec![key(22)]);
        assert!(!session.known_vpn.contains(&key(22)));
        assert!(session.known_vpn.contains(&key(33)));
        assert_eq!(session.known_prefix_count(), 1);

        let mut attributes = base_attrs();
        attributes.push(reach(&[44]));
        session.process_update(update(attributes)).await;
        assert!(rib_rx.try_recv().is_err(), "first-seen denial stays silent");
        assert!(!session.known_vpn.contains(&key(44)));
        assert_eq!(session.known_prefix_count(), 1);
    }

    exercise(Afi::Ipv4).await;
    exercise(Afi::Ipv6).await;
}

/// VPN export preserves or supplies attributes exactly once, strips inline
/// next-hop attributes, and retains the complete inherited reflector chain.
#[test]
fn prepare_outbound_attributes_vpn_has_exact_attribute_inventory() {
    let cluster_id = Ipv4Addr::new(10, 0, 0, 9);
    let source_id = Ipv4Addr::new(10, 0, 0, 42);
    let originator_id = Ipv4Addr::new(10, 0, 0, 7);
    let previous_clusters = [Ipv4Addr::new(10, 0, 0, 17), Ipv4Addr::new(10, 0, 0, 18)];
    for remote_asn in [65001, 65002] {
        let is_ebgp = remote_asn != 65001;
        let mut session = make_test_session(65001, remote_asn);
        session.config.cluster_id = Some(cluster_id);
        for has_attributes in [true, false] {
            let mut route = make_vpn_rib_route(100);
            route.origin_type = rustbgpd_rib::RouteOrigin::Ibgp;
            route.peer_router_id = source_id;
            let mut input = vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::NextHop(Ipv4Addr::new(192, 0, 2, 99)),
                PathAttribute::MpReachNlri(Box::new(empty_nonunicast_reach(
                    Afi::Ipv4,
                    Safi::MplsVpn,
                    route.next_hop,
                ))),
                PathAttribute::MpUnreachNlri(Box::new(empty_nonunicast_unreach(
                    Afi::Ipv4,
                    Safi::MplsVpn,
                ))),
            ];
            if has_attributes {
                input.extend([
                    PathAttribute::AsPath(AsPath {
                        segments: vec![AsPathSegment::AsSequence(vec![65002])],
                    }),
                    PathAttribute::LocalPref(200),
                    PathAttribute::OriginatorId(originator_id),
                    PathAttribute::ClusterList(previous_clusters.to_vec()),
                ]);
            }
            route.attributes = AttrSet::new(input);
            let mut attrs = session.prepare_outbound_attributes_vpn(&route, is_ebgp);
            let mut expected = vec![PathAttribute::Origin(Origin::Igp)];
            if is_ebgp || has_attributes {
                let asns = match (is_ebgp, has_attributes) {
                    (true, true) => vec![65001, 65002],
                    (true, false) => vec![65001],
                    (false, _) => vec![65002],
                };
                expected.push(PathAttribute::AsPath(AsPath {
                    segments: vec![AsPathSegment::AsSequence(asns)],
                }));
            }
            if !is_ebgp {
                expected.extend([
                    PathAttribute::LocalPref(if has_attributes { 200 } else { 100 }),
                    PathAttribute::OriginatorId(if has_attributes {
                        originator_id
                    } else {
                        source_id
                    }),
                    PathAttribute::ClusterList(if has_attributes {
                        vec![cluster_id, previous_clusters[0], previous_clusters[1]]
                    } else {
                        vec![cluster_id]
                    }),
                ]);
            }
            attrs.sort_by_key(PathAttribute::type_code);
            expected.sort_by_key(PathAttribute::type_code);
            assert_eq!(
                attrs, expected,
                "is_ebgp={is_ebgp}, has_attributes={has_attributes}"
            );
        }
    }
}

/// RFC 8950 §5 preserves the original `VPNv4` next-hop encoding on reflection.
/// Exercise both RD+IPv6 forms and Add-Path against the actual writer bytes.
#[tokio::test]
async fn vpnv4_ipv6_next_hop_reflection_matches_exact_probe() {
    use super::super::export::{ExportCandidate, ExportWithdrawal};

    let family = (Afi::Ipv4, Safi::MplsVpn);
    for remote_asn in [65001, 65002] {
        for link_local in [None, Some("fe80::7".parse().unwrap())] {
            for add_path in [false, true] {
                let (mut session, _rib_rx) = make_test_session_with_rib(65001, remote_asn);
                // The 48-octet form keeps its link-local half only toward
                // the source's link.
                if link_local.is_some() {
                    configure_scoped_link_local_peer(&mut session);
                }
                let (client, mut server) = connected_stream_pair().await;
                session.test_install_stream(client);
                let mut negotiated = negotiated_session(remote_asn, false);
                negotiated.negotiated_families = vec![family];
                negotiated
                    .extended_nexthop_families
                    .insert(family, Afi::Ipv6);
                if add_path {
                    negotiated
                        .add_path_families
                        .insert(family, AddPathMode::Both);
                }
                install_test_negotiated_session(&mut session, negotiated);
                let mut route = make_vpn_rib_route(4093);
                route.next_hop = "2001:db8::7".parse().unwrap();
                route.link_local_next_hop = link_local;
                route.next_hop_scope = session.link_local_next_hop_scope.clone().map(Box::new);
                route.path_id = if add_path { 42 } else { 0 };
                let profile = session.publish_export_profile();
                let probe = profile
                    .probe_announcement(ExportCandidate::Vpn(&route))
                    .unwrap();
                let expected =
                    rustbgpd_wire::encode_message(&Message::Update(probe.message)).unwrap();
                let mut update = empty_outbound_update();
                update.exact_export_snapshot = Some(profile.clone());
                update.vpn_announce = vec![route.clone()];
                session.send_route_update(update);
                let actual = read_single_raw_bgp_message(&mut server).await;
                assert_eq!(actual.as_slice(), expected.as_ref());
                let Message::Update(message) = rustbgpd_wire::decode_message(
                    &mut bytes::Bytes::from(actual),
                    rustbgpd_wire::MAX_MESSAGE_LEN,
                )
                .unwrap() else {
                    panic!("expected VPNv4 MP_REACH");
                };
                let add_path_families = if add_path { vec![family] } else { Vec::new() };
                let parsed = message.parse(true, false, &add_path_families).unwrap();
                let mp = parsed
                    .attributes
                    .iter()
                    .find_map(|attr| match attr {
                        PathAttribute::MpReachNlri(mp) => Some(mp),
                        _ => None,
                    })
                    .unwrap();
                assert_eq!((mp.afi, mp.safi), family);
                assert_eq!(mp.next_hop, route.next_hop);
                assert_eq!(mp.link_local_next_hop, link_local);
                assert_eq!(
                    mp.vpn_announced,
                    vec![rustbgpd_wire::VpnNlriEntry {
                        path_id: route.path_id,
                        nlri: route.nlri.clone(),
                    }]
                );

                let key = route.key();
                let probe = profile
                    .probe_withdrawal(ExportWithdrawal::Vpn(&key))
                    .unwrap();
                let expected =
                    rustbgpd_wire::encode_message(&Message::Update(probe.message)).unwrap();
                let mut update = empty_outbound_update();
                update.exact_export_snapshot = Some(profile);
                update.vpn_withdraw = vec![key];
                session.send_route_update(update);
                assert_eq!(
                    read_single_raw_bgp_message(&mut server).await.as_slice(),
                    expected.as_ref()
                );
            }
        }
    }
}

#[tokio::test]
async fn vpnv4_ipv6_next_hop_without_peer_capability_rejects_only_announcements() {
    use super::super::export::{ExportCandidate, ExportWithdrawal};
    use rustbgpd_rib::{ExactExportCandidate, ExactExportErrorCode, ExactExportSnapshot};

    let family = (Afi::Ipv4, Safi::MplsVpn);
    for unicast_capability in [false, true] {
        let (mut session, _rib_rx) = make_test_session_with_rib(65001, 65002);
        let (client, mut server) = connected_stream_pair().await;
        session.test_install_stream(client);
        let mut negotiated = negotiated_session(65002, unicast_capability);
        negotiated.negotiated_families = vec![family];
        install_test_negotiated_session(&mut session, negotiated);
        let mut route = make_vpn_rib_route(4093);
        let profile = session.publish_export_profile();
        assert!(
            profile
                .probe_announcement(ExportCandidate::Vpn(&route))
                .is_ok(),
            "legacy VPNv4 IPv4 next hops need no Extended Next Hop capability"
        );
        route.next_hop = "2001:db8::7".parse().unwrap();
        let error = ExactExportSnapshot::probe_announcement(
            profile.as_ref(),
            ExactExportCandidate::Vpn(&route),
        )
        .unwrap_err();
        assert_eq!(
            error.code(),
            ExactExportErrorCode::Ipv4RequiresExtendedNextHop
        );
        assert_eq!(
            error.detail(),
            "VPNv4 with an IPv6 next-hop requires peer Extended Next Hop support"
        );
        let key = route.key();
        let withdrawal = profile
            .probe_withdrawal(ExportWithdrawal::Vpn(&key))
            .unwrap();
        let expected = rustbgpd_wire::encode_message(&Message::Update(withdrawal.message)).unwrap();
        let mut update = empty_outbound_update();
        update.exact_export_snapshot = Some(profile);
        update.vpn_announce = vec![route];
        update.vpn_withdraw = vec![key];
        session.send_route_update(update);
        assert_eq!(
            read_single_raw_bgp_message(&mut server).await.as_slice(),
            expected.as_ref()
        );
        assert!(
            tokio::time::timeout(
                Duration::from_millis(50),
                read_single_raw_bgp_message(&mut server)
            )
            .await
            .is_err(),
            "the unsupported announcement must not reach the wire"
        );
    }
}

#[tokio::test]
async fn vpnv4_ipv6_next_hop_receive_does_not_require_peer_receive_capability() {
    let family = (Afi::Ipv4, Safi::MplsVpn);
    for link_local in [None, Some("fe80::7".parse().unwrap())] {
        let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
        session.config.peer.families = vec![family];
        let mut negotiated = negotiated_session(65002, false);
        negotiated.negotiated_families = vec![family];
        install_test_negotiated_session(&mut session, negotiated);
        let route = make_vpn_rib_route(4093);
        let next_hop = "2001:db8::7".parse().unwrap();
        let mut attrs = route.attributes.to_vec();
        attrs.push(PathAttribute::MpReachNlri(Box::new(MpReachNlri {
            afi: family.0,
            safi: family.1,
            next_hop,
            link_local_next_hop: link_local,
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
        })));
        let update = UpdateMessage::build(&[], &[], &attrs, true, false, Ipv4UnicastMode::Body);
        session.process_update(update).await;
        let RibUpdate::VpnRoutesReceived { announced, .. } = rib_rx.try_recv().unwrap() else {
            panic!("expected VPNv4 route admission");
        };
        assert_eq!(announced.len(), 1);
        assert_eq!(announced[0].nlri, route.nlri);
        assert_eq!(announced[0].next_hop, next_hop);
        assert_eq!(announced[0].link_local_next_hop, link_local);
    }
}

/// A mixed VPN envelope: shared and separately allocated equal attribute
/// sets, distinct sets, two families with equal attribute values and a
/// common next hop, two IPv4 next hops, and one shared `Arc` exported with two source router ids (whose
/// prepared `ORIGINATOR_ID` differs on a reflector).
fn mixed_vpn_envelope() -> Vec<rustbgpd_rib::VpnRibRoute> {
    let set = |asn: u32, med: Option<u32>| {
        let mut attrs = vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath {
                segments: vec![AsPathSegment::AsSequence(vec![asn])],
            }),
        ];
        attrs.extend(med.map(PathAttribute::Med));
        AttrSet::new(attrs)
    };
    let shared = [set(65010, None), set(65011, None), set(65012, Some(7))];
    // Equal by value to `shared[0]`, separately allocated.
    let twin = set(65010, None);
    (0..3_000u32)
        .map(|index| {
            let mut route = make_vpn_rib_route(16 + index);
            let v6 = index % 5 == 0;
            route.nlri.route_distinguisher = RouteDistinguisher([0, 0, 0xFD, 0xE8, 0, 0, 0, 1]);
            route.nlri.prefix = if v6 {
                VpnPrefix::v6(
                    Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, u16::try_from(index).unwrap()),
                    128,
                )
                .unwrap()
            } else {
                VpnPrefix::v4(Ipv4Addr::from(0x0a00_0000 | index), 32).unwrap()
            };
            // RFC 8950 VPNv4 routes share the VPNv6 next hop, so only the
            // family keeps their equal attribute sets apart.
            route.next_hop = if v6 || index % 5 == 1 {
                IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0xffff, 0, 0, 0, 0, 1))
            } else if index % 7 == 0 {
                IpAddr::V4(Ipv4Addr::new(192, 0, 2, 8))
            } else {
                IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7))
            };
            route.origin_type = rustbgpd_rib::RouteOrigin::Ibgp;
            route.peer_router_id = if index % 11 == 0 {
                Ipv4Addr::new(10, 0, 0, 3)
            } else {
                Ipv4Addr::new(10, 0, 0, 2)
            };
            route.attributes = match index % 13 {
                0..=5 => Arc::clone(&shared[0]),
                6 | 7 => Arc::clone(&twin),
                8 | 9 => Arc::clone(&shared[1]),
                10 => Arc::clone(&shared[2]),
                // Distinct per route; a few repeat a value already seen.
                _ => set(65100 + index % 97, Some(index % 41)),
            };
            route
        })
        .collect()
}

/// Hash-indexed VPN grouping emits exactly the frames of the reference
/// grouping it replaced: a linear first-match scan by deep equality of
/// (family, next hop, link-local, freshly prepared attributes), each group
/// then chunked with the VPN sender's halving rule in first-arrival order.
#[tokio::test]
async fn vpn_announce_grouping_matches_linear_reference_bytes() {
    let (mut session, _rib_rx) = make_test_session_with_rib(65001, 65001);
    session.config.cluster_id = Some(Ipv4Addr::new(10, 0, 0, 9));
    let mut negotiated = negotiated_session(65001, false);
    negotiated.negotiated_families = vec![(Afi::Ipv4, Safi::MplsVpn), (Afi::Ipv6, Safi::MplsVpn)];
    negotiated
        .extended_nexthop_families
        .insert((Afi::Ipv4, Safi::MplsVpn), Afi::Ipv6);
    session.negotiated = Some(Arc::new(negotiated));
    let (bulk, mut frames) = mpsc::channel(100_000);
    session.writer_bulk_tx = Some(bulk);
    let routes = mixed_vpn_envelope();
    let export = session.publish_export_profile();

    #[expect(
        clippy::type_complexity,
        reason = "the reference keeps the replaced grouping tuple verbatim"
    )]
    let mut groups: Vec<(
        (Afi, Safi),
        IpAddr,
        Option<Ipv6Addr>,
        Vec<PathAttribute>,
        Vec<rustbgpd_wire::VpnNlriEntry>,
    )> = Vec::new();
    for route in &routes {
        let prepared = export.prepare_vpn_candidate(route).unwrap();
        let family = (prepared.afi, prepared.safi);
        let key = (family, prepared.next_hop, prepared.link_local_next_hop);
        if let Some(group) = groups
            .iter_mut()
            .find(|g| (g.0, g.1, g.2) == key && g.3 == prepared.attrs)
        {
            group.4.push(prepared.nlri);
        } else {
            groups.push((key.0, key.1, key.2, prepared.attrs, vec![prepared.nlri]));
        }
    }
    assert!(groups.len() > 100, "fixture must exercise many groups");
    let max_len = export.max_message_len();
    let mut expected = Vec::new();
    for ((afi, safi), next_hop, link_local, attrs, entries) in &groups {
        let mut chunk_size = 1000usize;
        let mut idx = 0;
        while idx < entries.len() {
            let end = (idx + chunk_size).min(entries.len());
            let msg = export
                .build_mp_reach(
                    *afi,
                    *safi,
                    *next_hop,
                    *link_local,
                    attrs,
                    export::ReachNlri::Vpn(&entries[idx..end]),
                    Ipv4UnicastMode::Body,
                )
                .unwrap();
            if msg.encoded_len() > max_len {
                chunk_size /= 2;
                continue;
            }
            expected.push(Bytes::from(
                rustbgpd_wire::encode_message_with_limit(
                    &Message::Update(msg),
                    session.outbound_max_message_len(),
                )
                .unwrap(),
            ));
            idx = end;
        }
    }

    session.send_route_update(OutboundRouteUpdate {
        exact_export_snapshot: Some(export),
        vpn_announce: routes,
        ..OutboundRouteUpdate::default()
    });
    let mut actual = Vec::new();
    while let Ok(frame) = frames.try_recv() {
        actual.push(frame);
    }
    assert_eq!(actual.len(), expected.len(), "UPDATE count");
    assert!(
        actual == expected,
        "VPN UPDATE bytes diverged from the reference grouping"
    );
}
