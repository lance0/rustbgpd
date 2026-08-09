use super::*;

/// Labeled `MP_REACH` must carry the original label stack and the stored
/// next-hop verbatim — even on an eBGP session, where unicast would rewrite
/// to next-hop-self (ADR-0077 §4/§6: next-hop-self is inert for SAFI 4). The
/// withdraw is emitted via `MP_UNREACH` with an empty (ignored) label stack.
#[expect(
    clippy::too_many_lines,
    reason = "pins label-stack pass-through, verbatim next-hop, and the withdraw in one wire sequence"
)]
#[tokio::test]
async fn send_route_update_emits_labeled_reach_and_unreach() {
    let (mut session, _rib_rx) = make_test_session_with_rib(65001, 65002);
    let (client, mut server) = connected_stream_pair().await;
    session.test_install_stream(client);
    let mut negotiated = negotiated_session(65002, false);
    negotiated.negotiated_families = vec![(Afi::Ipv4, Safi::LabeledUnicast)];
    session
        .negotiated_families
        .clone_from(&negotiated.negotiated_families);
    session.negotiated = Some(negotiated);
    let route = make_labeled_rib_route(4093);
    let key = route.key();
    session.send_route_update(OutboundRouteUpdate {
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
        labeled_announce: vec![route.clone()],
        rtc_announce: vec![],
        vpn_withdraw: vec![],
        labeled_withdraw: vec![],
        rtc_withdraw: vec![],
        request_refresh_all_negotiated: false,
        shared_group_encode: None,
    });
    let Message::Update(msg) = read_single_bgp_message(&mut server).await else {
        panic!("expected labeled MP_REACH UPDATE");
    };
    let parsed = msg.parse(true, false, &[]).unwrap();
    let mp = parsed
        .attributes
        .iter()
        .find_map(|attr| match attr {
            PathAttribute::MpReachNlri(mp) => Some(mp),
            _ => None,
        })
        .expect("labeled announcement must use MP_REACH");
    assert_eq!(mp.afi, Afi::Ipv4);
    assert_eq!(mp.safi, Safi::LabeledUnicast);
    assert_eq!(
        mp.next_hop, route.next_hop,
        "labeled next-hop must pass through reflection unchanged"
    );
    assert_eq!(
        mp.labeled_announced,
        vec![rustbgpd_wire::LabeledNlriEntry {
            path_id: 0,
            nlri: route.nlri.clone()
        }],
        "MPLS label stack must round-trip verbatim"
    );
    session.send_route_update(OutboundRouteUpdate {
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
        vpn_withdraw: vec![],
        labeled_withdraw: vec![key],
        rtc_withdraw: vec![],
        request_refresh_all_negotiated: false,
        shared_group_encode: None,
    });
    let Message::Update(msg) = read_single_bgp_message(&mut server).await else {
        panic!("expected labeled MP_UNREACH UPDATE");
    };
    let parsed = msg.parse(true, false, &[]).unwrap();
    let mp = parsed
        .attributes
        .iter()
        .find_map(|attr| match attr {
            PathAttribute::MpUnreachNlri(mp) => Some(mp),
            _ => None,
        })
        .expect("labeled withdrawal must use MP_UNREACH");
    assert_eq!(mp.afi, Afi::Ipv4);
    assert_eq!(mp.safi, Safi::LabeledUnicast);
    assert_eq!(
        mp.labeled_withdrawn,
        vec![rustbgpd_wire::LabeledNlriEntry {
            path_id: 0,
            nlri: rustbgpd_wire::LabeledNlri {
                labels: vec![],
                prefix: route.nlri.prefix,
            }
        }],
        "withdraw-mode NLRI carries no label stack (RFC 8277 §2.4 compatibility field)"
    );
}

/// LAN-190: a labeled IPv6 route carrying an RFC 8950 two-address next-hop
/// (global + link-local) reflects the link-local half — the emitted
/// `MP_REACH` uses the 32-byte next-hop form, not the 16-byte single-address
/// form.
/// Without this, labeled IPv6 link-local forwarding breaks on reflection.
#[tokio::test]
async fn send_route_update_reflects_labeled_v6_link_local_next_hop() {
    let (mut session, _rib_rx) = make_test_session_with_rib(65001, 65002);
    let (client, mut server) = connected_stream_pair().await;
    session.test_install_stream(client);
    let mut negotiated = negotiated_session(65002, false);
    negotiated.negotiated_families = vec![(Afi::Ipv6, Safi::LabeledUnicast)];
    session
        .negotiated_families
        .clone_from(&negotiated.negotiated_families);
    session.negotiated = Some(negotiated);

    let global: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let link_local: Ipv6Addr = "fe80::1".parse().unwrap();
    let route = rustbgpd_rib::LabeledRibRoute {
        nlri: rustbgpd_wire::LabeledNlri {
            labels: vec![MplsLabelEntry::try_new(4093, 0, true).unwrap()],
            prefix: Prefix::V6(Ipv6Prefix::new("2001:db8:100::".parse().unwrap(), 48)),
        },
        next_hop: IpAddr::V6(global),
        link_local_next_hop: Some(link_local),
        peer: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        attributes: Arc::new(vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath {
                segments: vec![AsPathSegment::AsSequence(vec![65002])],
            }),
        ]),
        received_at: Instant::now(),
        origin_type: rustbgpd_rib::RouteOrigin::Ebgp,
        peer_router_id: Ipv4Addr::new(10, 0, 0, 2),
        is_stale: false,
        is_llgr_stale: false,
        path_id: 0,
    };
    session.send_route_update(OutboundRouteUpdate {
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
        labeled_announce: vec![route.clone()],
        rtc_announce: vec![],
        vpn_withdraw: vec![],
        labeled_withdraw: vec![],
        rtc_withdraw: vec![],
        request_refresh_all_negotiated: false,
        shared_group_encode: None,
    });
    let Message::Update(msg) = read_single_bgp_message(&mut server).await else {
        panic!("expected labeled MP_REACH UPDATE");
    };
    let parsed = msg.parse(true, false, &[]).unwrap();
    let mp = parsed
        .attributes
        .iter()
        .find_map(|attr| match attr {
            PathAttribute::MpReachNlri(mp) => Some(mp),
            _ => None,
        })
        .expect("labeled announcement must use MP_REACH");
    assert_eq!(mp.afi, Afi::Ipv6);
    assert_eq!(mp.safi, Safi::LabeledUnicast);
    assert_eq!(
        mp.next_hop,
        IpAddr::V6(global),
        "labeled global next-hop must pass through reflection unchanged"
    );
    assert_eq!(
        mp.link_local_next_hop,
        Some(link_local),
        "labeled IPv6 link-local next-hop must survive reflection (LAN-190)"
    );
}

/// RFC 7911 labeled outbound: with Add-Path send negotiated for (IPv4, SAFI
/// 4), announcements and withdrawals both carry the 4-octet path ID.
#[tokio::test]
async fn send_route_update_emits_labeled_add_path_reach_and_unreach() {
    let (mut session, _rib_rx) = make_test_session_with_rib(65001, 65002);
    let (client, mut server) = connected_stream_pair().await;
    session.test_install_stream(client);
    let mut negotiated = negotiated_session(65002, false);
    negotiated.negotiated_families = vec![(Afi::Ipv4, Safi::LabeledUnicast)];
    negotiated
        .add_path_families
        .insert((Afi::Ipv4, Safi::LabeledUnicast), AddPathMode::Both);
    session
        .negotiated_families
        .clone_from(&negotiated.negotiated_families);
    session.negotiated = Some(negotiated);
    let mut route = make_labeled_rib_route(4093);
    route.path_id = 2;
    let key = route.key();
    session.send_route_update(OutboundRouteUpdate {
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
        labeled_announce: vec![route.clone()],
        rtc_announce: vec![],
        vpn_withdraw: vec![],
        labeled_withdraw: vec![],
        rtc_withdraw: vec![],
        request_refresh_all_negotiated: false,
        shared_group_encode: None,
    });
    let Message::Update(msg) = read_single_bgp_message(&mut server).await else {
        panic!("expected labeled Add-Path MP_REACH UPDATE");
    };
    let labeled_add_path = [(Afi::Ipv4, Safi::LabeledUnicast)];
    let parsed = msg.parse(true, false, &labeled_add_path).unwrap();
    let mp = parsed
        .attributes
        .iter()
        .find_map(|attr| match attr {
            PathAttribute::MpReachNlri(mp) => Some(mp),
            _ => None,
        })
        .expect("labeled Add-Path announcement must use MP_REACH");
    assert_eq!(
        mp.labeled_announced,
        vec![rustbgpd_wire::LabeledNlriEntry {
            path_id: 2,
            nlri: route.nlri.clone()
        }],
        "announcement must carry the outbound path ID"
    );
    session.send_route_update(OutboundRouteUpdate {
        exact_export_snapshot: Some(session.publish_export_profile()),
        labeled_withdraw: vec![key],
        ..empty_outbound_update()
    });
    let Message::Update(msg) = read_single_bgp_message(&mut server).await else {
        panic!("expected labeled Add-Path MP_UNREACH UPDATE");
    };
    let parsed = msg.parse(true, false, &labeled_add_path).unwrap();
    let mp = parsed
        .attributes
        .iter()
        .find_map(|attr| match attr {
            PathAttribute::MpUnreachNlri(mp) => Some(mp),
            _ => None,
        })
        .expect("labeled Add-Path withdrawal must use MP_UNREACH");
    assert_eq!(mp.labeled_withdrawn.len(), 1);
    assert_eq!(
        mp.labeled_withdrawn[0].path_id, 2,
        "withdrawal must carry the outbound path ID"
    );
}

/// RFC 7911 labeled inbound: with Add-Path receive negotiated for (IPv4,
/// SAFI 4), the decoded path ID threads into the
/// `LabeledRibRouteKey`/`LabeledRibRoute` delivered to the RIB —
/// announcements and withdrawals alike.
#[tokio::test]
async fn process_update_threads_labeled_add_path_ids_into_rib_keys() {
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    let mut negotiated = negotiated_session(65002, true);
    negotiated.negotiated_families = vec![(Afi::Ipv4, Safi::LabeledUnicast)];
    negotiated
        .add_path_families
        .insert((Afi::Ipv4, Safi::LabeledUnicast), AddPathMode::Both);
    install_test_negotiated_session(&mut session, negotiated);
    let nlri = rustbgpd_wire::LabeledNlri {
        labels: vec![MplsLabelEntry::try_new(4093, 0, true).unwrap()],
        prefix: Prefix::V4(rustbgpd_wire::Ipv4Prefix::new(
            Ipv4Addr::new(10, 0, 1, 0),
            24,
        )),
    };
    let attrs = vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath {
            segments: vec![AsPathSegment::AsSequence(vec![65002])],
        }),
        PathAttribute::MpReachNlri(MpReachNlri {
            afi: Afi::Ipv4,
            safi: Safi::LabeledUnicast,
            next_hop: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7)),
            link_local_next_hop: None,
            announced: vec![],
            flowspec_announced: vec![],
            evpn_announced: vec![],
            bgpls_announced: vec![],
            vpn_announced: vec![],
            labeled_announced: vec![
                rustbgpd_wire::LabeledNlriEntry {
                    path_id: 1,
                    nlri: nlri.clone(),
                },
                rustbgpd_wire::LabeledNlriEntry {
                    path_id: 2,
                    nlri: nlri.clone(),
                },
            ],
            rtc_announced: vec![],
        }),
    ];
    let update = UpdateMessage::build(&[], &[], &attrs, true, true, Ipv4UnicastMode::Body);
    session.process_update(update).await;
    let RibUpdate::LabeledRoutesReceived { announced, .. } = rib_rx.try_recv().unwrap() else {
        panic!("expected LabeledRoutesReceived");
    };
    assert_eq!(announced.len(), 2);
    assert_eq!(announced[0].path_id, 1);
    assert_eq!(announced[1].path_id, 2);
    assert_eq!(announced[0].nlri, nlri);
    assert_eq!(
        announced[0].key(),
        rustbgpd_rib::LabeledRibRouteKey {
            prefix: nlri.key(),
            path_id: 1,
        }
    );

    // Withdraw ONLY path 1 — the delivered key must carry the path ID.
    let attrs = vec![PathAttribute::MpUnreachNlri(MpUnreachNlri {
        afi: Afi::Ipv4,
        safi: Safi::LabeledUnicast,
        withdrawn: vec![],
        flowspec_withdrawn: vec![],
        evpn_withdrawn: vec![],
        bgpls_withdrawn: vec![],
        vpn_withdrawn: vec![],
        labeled_withdrawn: vec![rustbgpd_wire::LabeledNlriEntry {
            path_id: 1,
            nlri: rustbgpd_wire::LabeledNlri {
                labels: vec![],
                prefix: nlri.prefix,
            },
        }],
        rtc_withdrawn: vec![],
    })];
    let update = UpdateMessage::build(&[], &[], &attrs, true, true, Ipv4UnicastMode::Body);
    session.process_update(update).await;
    let RibUpdate::LabeledRoutesReceived { withdrawn, .. } = rib_rx.try_recv().unwrap() else {
        panic!("expected LabeledRoutesReceived withdrawal");
    };
    assert_eq!(
        withdrawn,
        vec![rustbgpd_rib::LabeledRibRouteKey {
            prefix: nlri.key(),
            path_id: 1,
        }]
    );
}

/// Import-policy denial retires an exact accepted labeled Add-Path identity,
/// deduplicates an overlapping explicit withdrawal, preserves siblings, keeps
/// first-seen denials silent, and reconciles Enhanced Refresh accounting for
/// both labeled IPv4 and IPv6.
///
/// Break-to-red: deleting denied-key collection/presence-gated removal leaves
/// known/max-prefix/refresh state stale; appending without the membership gate
/// duplicates the overlap and emits the first-seen denial; applying refresh
/// capture before the synthetic withdrawal leaves the stale count unchanged.
#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "one dual-AFI stateful scenario pins exact denial, overlap, accounting, and Enhanced Refresh transitions"
)]
async fn denied_labeled_add_path_replacements_reconcile_exact_refresh_identity() {
    #[expect(
        clippy::too_many_lines,
        reason = "the shared per-AFI fixture keeps every identity transition inside one refresh window"
    )]
    async fn exercise(afi: Afi) {
        let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
        let family = (afi, Safi::LabeledUnicast);
        let mut negotiated = negotiated_session(65002, true);
        negotiated.negotiated_families = vec![family];
        negotiated
            .add_path_families
            .insert(family, AddPathMode::Both);
        negotiated.peer_route_refresh = true;
        negotiated.peer_enhanced_route_refresh = true;
        install_test_negotiated_session(&mut session, negotiated);

        let prefix = match afi {
            Afi::Ipv4 => Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 44, 3, 0), 24)),
            Afi::Ipv6 => Prefix::V6(Ipv6Prefix::new("2001:db8:443::".parse().unwrap(), 64)),
            _ => unreachable!("test covers IP labeled-unicast families"),
        };
        let nlri = rustbgpd_wire::LabeledNlri {
            labels: vec![MplsLabelEntry::try_new(4093, 0, true).unwrap()],
            prefix,
        };
        let next_hop = match afi {
            Afi::Ipv4 => IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7)),
            Afi::Ipv6 => IpAddr::V6("2001:db8::7".parse().unwrap()),
            _ => unreachable!("test covers IP labeled-unicast families"),
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
            PathAttribute::MpReachNlri(MpReachNlri {
                afi,
                safi: Safi::LabeledUnicast,
                next_hop,
                link_local_next_hop: None,
                announced: vec![],
                flowspec_announced: vec![],
                evpn_announced: vec![],
                bgpls_announced: vec![],
                vpn_announced: vec![],
                labeled_announced: path_ids
                    .iter()
                    .map(|path_id| rustbgpd_wire::LabeledNlriEntry {
                        path_id: *path_id,
                        nlri: nlri.clone(),
                    })
                    .collect(),
                rtc_announced: vec![],
            })
        };
        let unreach = |path_id| {
            PathAttribute::MpUnreachNlri(MpUnreachNlri {
                afi,
                safi: Safi::LabeledUnicast,
                withdrawn: vec![],
                flowspec_withdrawn: vec![],
                evpn_withdrawn: vec![],
                bgpls_withdrawn: vec![],
                vpn_withdrawn: vec![],
                labeled_withdrawn: vec![rustbgpd_wire::LabeledNlriEntry {
                    path_id,
                    nlri: rustbgpd_wire::LabeledNlri {
                        labels: vec![],
                        prefix,
                    },
                }],
                rtc_withdrawn: vec![],
            })
        };
        let update = |attributes: Vec<PathAttribute>| {
            UpdateMessage::build(&[], &[], &attributes, true, true, Ipv4UnicastMode::Body)
        };
        let key = |path_id| rustbgpd_rib::LabeledRibRouteKey { prefix, path_id };

        let mut attributes = base_attrs();
        attributes.push(reach(&[11, 22, 33]));
        session.process_update(update(attributes)).await;
        let RibUpdate::LabeledRoutesReceived {
            announced,
            withdrawn,
            ..
        } = rib_rx
            .try_recv()
            .expect("accepted labeled paths reach the RIB")
        else {
            panic!("expected LabeledRoutesReceived");
        };
        assert_eq!(announced.len(), 3);
        assert!(withdrawn.is_empty());
        assert_eq!(session.known_prefix_count(), 3);
        for path_id in [11, 22, 33] {
            assert!(session.known_labeled.contains(&key(path_id)));
        }

        buffer_route_refresh(
            &mut session,
            afi,
            Safi::LabeledUnicast,
            RouteRefreshSubtype::BoRR,
        );
        session.process_read_buffer().await;
        assert!(matches!(
            rib_rx.try_recv(),
            Ok(RibUpdate::BeginRouteRefresh {
                afi: marker_afi,
                safi: Safi::LabeledUnicast,
                ..
            }) if marker_afi == afi
        ));
        assert_eq!(session.refresh_accounting_stale_count(family), Some(3));

        session.install_import_policy(Some(PolicyChain::new(vec![Policy {
            entries: vec![],
            default_action: PolicyAction::Deny,
        }])));

        let mut attributes = base_attrs();
        attributes.push(reach(&[11]));
        session.process_update(update(attributes)).await;
        let RibUpdate::LabeledRoutesReceived {
            announced,
            withdrawn,
            ..
        } = rib_rx
            .try_recv()
            .expect("denied labeled replacement reaches the RIB")
        else {
            panic!("expected LabeledRoutesReceived");
        };
        assert!(announced.is_empty());
        assert_eq!(withdrawn, vec![key(11)]);
        assert!(!session.known_labeled.contains(&key(11)));
        assert!(session.known_labeled.contains(&key(22)));
        assert!(session.known_labeled.contains(&key(33)));
        assert_eq!(session.known_prefix_count(), 2);
        assert_eq!(session.refresh_accounting_stale_count(family), Some(2));

        let mut attributes = base_attrs();
        attributes.push(reach(&[22]));
        attributes.push(unreach(22));
        session.process_update(update(attributes)).await;
        let RibUpdate::LabeledRoutesReceived {
            announced,
            withdrawn,
            ..
        } = rib_rx.try_recv().expect("overlap reaches the RIB once")
        else {
            panic!("expected LabeledRoutesReceived");
        };
        assert!(announced.is_empty());
        assert_eq!(withdrawn.len(), 1, "overlap must not duplicate the key");
        assert_eq!(withdrawn, vec![key(22)]);
        assert!(!session.known_labeled.contains(&key(22)));
        assert!(session.known_labeled.contains(&key(33)));
        assert_eq!(session.known_prefix_count(), 1);
        assert_eq!(session.refresh_accounting_stale_count(family), Some(1));

        let mut attributes = base_attrs();
        attributes.push(reach(&[44]));
        session.process_update(update(attributes)).await;
        assert!(rib_rx.try_recv().is_err(), "first-seen denial stays silent");
        assert!(!session.known_labeled.contains(&key(44)));
        assert_eq!(session.known_prefix_count(), 1);
        assert_eq!(session.refresh_accounting_stale_count(family), Some(1));
        assert_eq!(session.import_policy_routes_permitted, 3);
        assert_eq!(session.import_policy_routes_denied, 3);

        buffer_route_refresh(
            &mut session,
            afi,
            Safi::LabeledUnicast,
            RouteRefreshSubtype::EoRR,
        );
        session.process_read_buffer().await;
        assert!(matches!(
            rib_rx.try_recv(),
            Ok(RibUpdate::EndRouteRefresh {
                afi: marker_afi,
                safi: Safi::LabeledUnicast,
                ..
            }) if marker_afi == afi
        ));
        assert_eq!(session.refresh_accounting_window_count(), 0);
        assert!(!session.known_labeled.contains(&key(33)));
        assert_eq!(session.known_prefix_count(), 0);
    }

    exercise(Afi::Ipv4).await;
    exercise(Afi::Ipv6).await;
}

/// iBGP reflection of a labeled route on an RR adds `ORIGINATOR_ID` and
/// `CLUSTER_LIST`, keeps `LOCAL_PREF`, and never emits inline `NextHop`/MP attrs.
#[test]
fn prepare_outbound_attributes_labeled_adds_rr_attrs_for_ibgp_reflection() {
    let mut session = make_test_session(65001, 65001);
    let cluster_id = Ipv4Addr::new(10, 0, 0, 9);
    let source_id = Ipv4Addr::new(10, 0, 0, 42);
    session.config.cluster_id = Some(cluster_id);
    let mut route = make_labeled_rib_route(100);
    route.origin_type = rustbgpd_rib::RouteOrigin::Ibgp;
    route.peer_router_id = source_id;
    route.attributes = Arc::new(vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath { segments: vec![] }),
        PathAttribute::LocalPref(200),
    ]);
    let attrs = session.prepare_outbound_attributes_labeled(&route, false);
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
    assert!(
        attrs
            .iter()
            .any(|a| matches!(a, PathAttribute::LocalPref(200)))
    );
    assert!(!attrs.iter().any(|a| matches!(
        a,
        PathAttribute::NextHop(_) | PathAttribute::MpReachNlri(_) | PathAttribute::MpUnreachNlri(_)
    )));
}
