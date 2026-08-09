use super::*;

/// Regression: when an inbound UPDATE is discarded due to RFC 4456
/// loop detection (our cluster-id present in `CLUSTER_LIST`), any EVPN
/// withdrawals carried on that same UPDATE must still be applied.
/// Prior to the fix, unicast + `FlowSpec` withdrawals were propagated
/// in the loop-detect branch but `evpn_withdrawn` was hard-coded to
/// `vec![]`, so reflected-loop withdrawals could leave stale EVPN state
/// downstream.
#[tokio::test]
async fn rr_loop_detected_update_still_applies_evpn_withdrawals() {
    use rustbgpd_wire::{
        EthernetSegmentIdentifier, EthernetTagId, EvpnMacIp, EvpnRoute, MacAddress, MpReachNlri,
        MpUnreachNlri, MplsLabel, RouteDistinguisher,
    };
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65001);
    let local_cluster_id = Ipv4Addr::new(10, 0, 0, 9);
    session.config.cluster_id = Some(local_cluster_id);
    // Negotiate L2VPN/EVPN so the withdrawal isn't family-filtered.
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
    // Build the withdrawn EVPN Type 2 key.
    let withdrawn_route = EvpnRoute::MacIp(EvpnMacIp {
        rd: RouteDistinguisher([0, 0, 0xFD, 0xE8, 0, 0, 0, 100]),
        esi: EthernetSegmentIdentifier::ZERO,
        ethernet_tag: EthernetTagId(100),
        mac: MacAddress([0x02, 0x00, 0x00, 0xAA, 0xBB, 0xCC]),
        ip: None,
        label1: MplsLabel::new(10_000),
        label2: None,
    });
    let expected_key = withdrawn_route.key();
    session.known_evpn.insert(expected_key);
    session.begin_refresh_accounting(Afi::L2Vpn, Safi::Evpn);
    // Craft the UPDATE: loop-triggering CLUSTER_LIST + MP_UNREACH with
    // the EVPN withdrawal. Also include an MP_REACH with a bogus announce
    // so the loop-detect branch has something to discard.
    let attrs = vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath { segments: vec![] }),
        // Triggers the loop — local cluster-id present in the advertised list.
        PathAttribute::ClusterList(vec![local_cluster_id]),
        PathAttribute::MpReachNlri(MpReachNlri {
            afi: Afi::L2Vpn,
            safi: Safi::Evpn,
            next_hop: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            link_local_next_hop: None,
            announced: vec![],
            flowspec_announced: vec![],
            evpn_announced: vec![withdrawn_route.clone()],
            bgpls_announced: vec![],
            labeled_announced: vec![],
            vpn_announced: vec![],
            rtc_announced: vec![],
        }),
        PathAttribute::MpUnreachNlri(MpUnreachNlri {
            afi: Afi::L2Vpn,
            safi: Safi::Evpn,
            withdrawn: vec![],
            flowspec_withdrawn: vec![],
            evpn_withdrawn: vec![withdrawn_route],
            bgpls_withdrawn: vec![],
            labeled_withdrawn: vec![],
            vpn_withdrawn: vec![],
            rtc_withdrawn: vec![],
        }),
    ];
    let update = UpdateMessage::build(&[], &[], &attrs, true, false, Ipv4UnicastMode::MpReach);
    session.process_update(update).await;
    // The session must still emit a RoutesReceived carrying the EVPN
    // withdrawal, even though the announce side was discarded.
    let msg = rib_rx
        .try_recv()
        .expect("loop-path must still dispatch withdrawals");
    match msg {
        RibUpdate::RoutesReceived {
            announced,
            evpn_announced,
            evpn_withdrawn,
            ..
        } => {
            assert!(
                announced.is_empty() && evpn_announced.is_empty(),
                "announces in a loop-detected UPDATE must be discarded"
            );
            assert_eq!(
                evpn_withdrawn,
                vec![expected_key],
                "EVPN withdrawals must survive loop detection"
            );
        }
        _ => panic!("expected RoutesReceived from the loop-detect path"),
    }
    assert_eq!(
        session.refresh_accounting_stale_count((Afi::L2Vpn, Safi::Evpn)),
        Some(0),
        "RR-loop withdrawal must retire the exact stale identity"
    );
    session.end_refresh_accounting(Afi::L2Vpn, Safi::Evpn);
    assert!(session.known_evpn.is_empty());
}

/// Both pre-policy loop rejections retire only exact accepted VPN Add-Path
/// identities. A distinct explicit withdrawal is preserved, while novel and
/// repeated rejected announcements remain silent.
///
/// Break-to-red: blindly appending rejected keys emits the novel identity;
/// gating the explicit withdrawal drops it; omitting the synthetic withdrawal
/// leaves known/max-prefix/refresh state at two.
#[tokio::test]
async fn safety_loop_vpn_replacements_are_presence_gated_for_both_afis() {
    async fn exercise(afi: Afi, trigger: NonUnicastSafetyLoop) {
        let family = (afi, Safi::MplsVpn);
        let (mut session, mut rib_rx) = nonunicast_safety_session(family, true, trigger);
        let prefix = match afi {
            Afi::Ipv4 => VpnPrefix::v4(Ipv4Addr::new(10, 44, 5, 0), 24).unwrap(),
            Afi::Ipv6 => VpnPrefix::v6("2001:db8:445::".parse().unwrap(), 64).unwrap(),
            _ => unreachable!("fixture covers VPNv4/v6"),
        };
        let nlri = VpnNlri {
            labels: vec![MplsLabelEntry::try_new(4093, 0, true).unwrap()],
            route_distinguisher: RouteDistinguisher([0, 0, 0xfd, 0xe8, 0, 0, 0, 45]),
            prefix,
        };
        let key = |path_id| rustbgpd_rib::VpnRibRouteKey {
            nlri_key: nlri.key(),
            path_id,
        };
        let next_hop = match afi {
            Afi::Ipv4 => IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7)),
            Afi::Ipv6 => IpAddr::V6("2001:db8::7".parse().unwrap()),
            _ => unreachable!(),
        };
        let reach = |path_ids: &[u32]| {
            let mut mp = empty_nonunicast_reach(afi, Safi::MplsVpn, next_hop);
            mp.vpn_announced = path_ids
                .iter()
                .map(|path_id| rustbgpd_wire::VpnNlriEntry {
                    path_id: *path_id,
                    nlri: nlri.clone(),
                })
                .collect();
            mp
        };
        let explicit = || {
            let mut mp = empty_nonunicast_unreach(afi, Safi::MplsVpn);
            mp.vpn_withdrawn = vec![rustbgpd_wire::VpnNlriEntry {
                path_id: 22,
                nlri: VpnNlri {
                    labels: vec![],
                    route_distinguisher: nlri.route_distinguisher,
                    prefix: nlri.prefix,
                },
            }];
            mp
        };

        session
            .process_update(nonunicast_update(
                nonunicast_accepted_attrs(),
                reach(&[11, 33]),
                None,
                true,
            ))
            .await;
        assert!(matches!(
            rib_rx.try_recv(),
            Ok(RibUpdate::VpnRoutesReceived { ref announced, .. }) if announced.len() == 2
        ));
        session.begin_refresh_accounting(afi, Safi::MplsVpn);

        session
            .process_update(nonunicast_update(
                nonunicast_safety_attrs(&session, trigger),
                reach(&[11, 44]),
                Some(explicit()),
                true,
            ))
            .await;
        let RibUpdate::VpnRoutesReceived {
            announced,
            withdrawn,
            ..
        } = rib_rx.try_recv().expect("VPN safety withdrawals reach RIB")
        else {
            panic!("expected VpnRoutesReceived");
        };
        assert!(announced.is_empty());
        assert_eq!(withdrawn, vec![key(22), key(11)]);
        assert!(!session.known_vpn.contains(&key(44)));
        assert!(session.known_vpn.contains(&key(33)));
        assert_eq!(session.known_prefix_count(), 1);
        assert_eq!(session.refresh_accounting_stale_count(family), Some(1));

        session
            .process_update(nonunicast_update(
                nonunicast_safety_attrs(&session, trigger),
                reach(&[11, 44]),
                None,
                true,
            ))
            .await;
        assert!(
            rib_rx.try_recv().is_err(),
            "repeated/novel rejects stay silent"
        );
    }

    for trigger in [
        NonUnicastSafetyLoop::AsPath,
        NonUnicastSafetyLoop::Originator,
    ] {
        exercise(Afi::Ipv4, trigger).await;
        exercise(Afi::Ipv6, trigger).await;
    }
}

/// VPN-equivalent safety semantics apply to labeled-unicast without losing
/// the Add-Path identity.
///
/// Break-to-red: removing the presence gate emits path 44; dropping the
/// labeled rejected collection leaves path 11 known and refresh-stale.
#[tokio::test]
async fn safety_loop_labeled_replacements_are_presence_gated_for_both_afis() {
    async fn exercise(afi: Afi, trigger: NonUnicastSafetyLoop) {
        let family = (afi, Safi::LabeledUnicast);
        let (mut session, mut rib_rx) = nonunicast_safety_session(family, true, trigger);
        let prefix = match afi {
            Afi::Ipv4 => Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 44, 6, 0), 24)),
            Afi::Ipv6 => Prefix::V6(Ipv6Prefix::new("2001:db8:446::".parse().unwrap(), 64)),
            _ => unreachable!("fixture covers labeled IPv4/IPv6"),
        };
        let nlri = rustbgpd_wire::LabeledNlri {
            labels: vec![MplsLabelEntry::try_new(4092, 0, true).unwrap()],
            prefix,
        };
        let key = |path_id| rustbgpd_rib::LabeledRibRouteKey { prefix, path_id };
        let next_hop = match afi {
            Afi::Ipv4 => IpAddr::V4(Ipv4Addr::new(192, 0, 2, 8)),
            Afi::Ipv6 => IpAddr::V6("2001:db8::8".parse().unwrap()),
            _ => unreachable!(),
        };
        let reach = |path_ids: &[u32]| {
            let mut mp = empty_nonunicast_reach(afi, Safi::LabeledUnicast, next_hop);
            mp.labeled_announced = path_ids
                .iter()
                .map(|path_id| rustbgpd_wire::LabeledNlriEntry {
                    path_id: *path_id,
                    nlri: nlri.clone(),
                })
                .collect();
            mp
        };
        let explicit = || {
            let mut mp = empty_nonunicast_unreach(afi, Safi::LabeledUnicast);
            mp.labeled_withdrawn = vec![rustbgpd_wire::LabeledNlriEntry {
                path_id: 22,
                nlri: rustbgpd_wire::LabeledNlri {
                    labels: vec![],
                    prefix,
                },
            }];
            mp
        };

        session
            .process_update(nonunicast_update(
                nonunicast_accepted_attrs(),
                reach(&[11, 33]),
                None,
                true,
            ))
            .await;
        assert!(matches!(
            rib_rx.try_recv(),
            Ok(RibUpdate::LabeledRoutesReceived { ref announced, .. }) if announced.len() == 2
        ));
        session.begin_refresh_accounting(afi, Safi::LabeledUnicast);

        session
            .process_update(nonunicast_update(
                nonunicast_safety_attrs(&session, trigger),
                reach(&[11, 44]),
                Some(explicit()),
                true,
            ))
            .await;
        let RibUpdate::LabeledRoutesReceived {
            announced,
            withdrawn,
            ..
        } = rib_rx
            .try_recv()
            .expect("labeled safety withdrawals reach RIB")
        else {
            panic!("expected LabeledRoutesReceived");
        };
        assert!(announced.is_empty());
        assert_eq!(withdrawn, vec![key(22), key(11)]);
        assert!(!session.known_labeled.contains(&key(44)));
        assert!(session.known_labeled.contains(&key(33)));
        assert_eq!(session.known_prefix_count(), 1);
        assert_eq!(session.refresh_accounting_stale_count(family), Some(1));

        session
            .process_update(nonunicast_update(
                nonunicast_safety_attrs(&session, trigger),
                reach(&[11, 44]),
                None,
                true,
            ))
            .await;
        assert!(
            rib_rx.try_recv().is_err(),
            "repeated/novel rejects stay silent"
        );
    }

    for trigger in [
        NonUnicastSafetyLoop::AsPath,
        NonUnicastSafetyLoop::Originator,
    ] {
        exercise(Afi::Ipv4, trigger).await;
        exercise(Afi::Ipv6, trigger).await;
    }
}

/// RTC loop rejection is presence-gated for both `AS_PATH` and RR-loop paths.
///
/// Break-to-red: deleting RTC rejected collection leaves the accepted NLRI
/// live; blind append emits the novel NLRI; excluding the synthesized key from
/// refresh capture leaves two stale identities.
#[tokio::test]
async fn safety_loop_rtc_replacements_are_presence_gated() {
    use rustbgpd_wire::RtcNlri;

    for trigger in [
        NonUnicastSafetyLoop::AsPath,
        NonUnicastSafetyLoop::Originator,
    ] {
        let family = (Afi::Ipv4, Safi::RtConstrain);
        let (mut session, mut rib_rx) = nonunicast_safety_session(family, false, trigger);
        let nlri =
            |id: u16| RtcNlri::new(65002, 0x0002_FDEA_0000_0000 | u64::from(id), 96).unwrap();
        let accepted = nlri(11);
        let explicit = nlri(22);
        let sibling = nlri(33);
        let novel = nlri(44);
        let key = |nlri| rustbgpd_rib::RtcRibRouteKey { nlri, path_id: 0 };
        let reach = |nlris| {
            let mut mp = empty_nonunicast_reach(
                Afi::Ipv4,
                Safi::RtConstrain,
                IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9)),
            );
            mp.rtc_announced = nlris;
            mp
        };
        let unreach = |nlris| {
            let mut mp = empty_nonunicast_unreach(Afi::Ipv4, Safi::RtConstrain);
            mp.rtc_withdrawn = nlris;
            mp
        };

        session
            .process_update(nonunicast_update(
                nonunicast_accepted_attrs(),
                reach(vec![accepted, sibling]),
                None,
                false,
            ))
            .await;
        assert!(matches!(
            rib_rx.try_recv(),
            Ok(RibUpdate::RtcRoutesReceived { ref announced, .. }) if announced.len() == 2
        ));
        session.begin_refresh_accounting(Afi::Ipv4, Safi::RtConstrain);

        session
            .process_update(nonunicast_update(
                nonunicast_safety_attrs(&session, trigger),
                reach(vec![accepted, novel]),
                Some(unreach(vec![explicit])),
                false,
            ))
            .await;
        let RibUpdate::RtcRoutesReceived {
            announced,
            withdrawn,
            ..
        } = rib_rx.try_recv().expect("RTC safety withdrawals reach RIB")
        else {
            panic!("expected RtcRoutesReceived");
        };
        assert!(announced.is_empty());
        assert_eq!(withdrawn, vec![key(explicit), key(accepted)]);
        assert!(!session.known_rtc.contains(&key(novel)));
        assert!(session.known_rtc.contains(&key(sibling)));
        assert_eq!(session.known_prefix_count(), 1);
        assert_eq!(session.refresh_accounting_stale_count(family), Some(1));

        session
            .process_update(nonunicast_update(
                nonunicast_safety_attrs(&session, trigger),
                reach(vec![accepted, novel]),
                None,
                false,
            ))
            .await;
        assert!(
            rib_rx.try_recv().is_err(),
            "repeated/novel rejects stay silent"
        );
    }
}

/// Both BGP-LS SAFIs use their SAFI-derived identity under both safety-loop
/// branches; explicit withdrawals remain independent of rejected `MP_REACH`.
///
/// Break-to-red: deleting either branch's BGP-LS collection leaves the exact
/// accepted topology object known and refresh-stale; blind append emits the
/// novel object.
#[tokio::test]
async fn safety_loop_bgpls_replacements_are_presence_gated_for_both_safis() {
    use rustbgpd_rib::BgpLsFamily;

    fn nlri(safi: Safi, suffix: u8) -> BgpLsNlri {
        match safi {
            Safi::BgpLs => decode_bgpls_nlri(&[0xfd, 0xe8, 0, 3, 0xaa, 0xcc, suffix]),
            Safi::BgpLsVpn => decode_bgpls_vpn_nlri(&[
                0xfd, 0xe8, 0, 11, 0, 0, 0xfd, 0xea, 0, 0, 0, 46, 0xaa, 0xcc, suffix,
            ]),
            _ => unreachable!("fixture covers BGP-LS SAFIs"),
        }
        .unwrap()
        .pop()
        .unwrap()
    }

    async fn exercise(safi: Safi, trigger: NonUnicastSafetyLoop) {
        let afi = Afi::BgpLs;
        let family = (afi, safi);
        let typed_family = BgpLsFamily::from_afi_safi(afi, safi).unwrap();
        let (mut session, mut rib_rx) = nonunicast_safety_session(family, false, trigger);
        let accepted = nlri(safi, 11);
        let explicit = nlri(safi, 22);
        let sibling = nlri(safi, 33);
        let novel = nlri(safi, 44);
        let key = |nlri: &BgpLsNlri| rustbgpd_rib::BgpLsRouteKey {
            family: typed_family,
            nlri: nlri.key(),
            path_id: 0,
        };
        let reach = |nlris| {
            let mut mp =
                empty_nonunicast_reach(afi, safi, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)));
            mp.bgpls_announced = nlris;
            mp
        };
        let unreach = |nlris| {
            let mut mp = empty_nonunicast_unreach(afi, safi);
            mp.bgpls_withdrawn = nlris;
            mp
        };

        session
            .process_update(nonunicast_update(
                nonunicast_accepted_attrs(),
                reach(vec![accepted.clone(), sibling.clone()]),
                None,
                false,
            ))
            .await;
        assert!(matches!(
            rib_rx.try_recv(),
            Ok(RibUpdate::BgpLsRoutesReceived { ref announced, .. }) if announced.len() == 2
        ));
        session.begin_refresh_accounting(afi, safi);

        session
            .process_update(nonunicast_update(
                nonunicast_safety_attrs(&session, trigger),
                reach(vec![accepted.clone(), novel.clone()]),
                Some(unreach(vec![explicit.clone()])),
                false,
            ))
            .await;
        let RibUpdate::BgpLsRoutesReceived {
            announced,
            withdrawn,
            ..
        } = rib_rx
            .try_recv()
            .expect("BGP-LS safety withdrawals reach RIB")
        else {
            panic!("expected BgpLsRoutesReceived");
        };
        assert!(announced.is_empty());
        assert_eq!(withdrawn, vec![key(&explicit), key(&accepted)]);
        assert!(!session.known_bgpls.contains(&key(&novel)));
        assert!(session.known_bgpls.contains(&key(&sibling)));
        assert_eq!(session.known_prefix_count(), 1);
        assert_eq!(session.refresh_accounting_stale_count(family), Some(1));

        session
            .process_update(nonunicast_update(
                nonunicast_safety_attrs(&session, trigger),
                reach(vec![accepted, novel]),
                None,
                false,
            ))
            .await;
        assert!(
            rib_rx.try_recv().is_err(),
            "repeated/novel rejects stay silent"
        );
    }

    for trigger in [
        NonUnicastSafetyLoop::AsPath,
        NonUnicastSafetyLoop::Originator,
    ] {
        exercise(Safi::BgpLs, trigger).await;
        exercise(Safi::BgpLsVpn, trigger).await;
    }
}

/// A loop-detected UPDATE (RR cluster-list loop) must synthesize RTC
/// withdrawals from both the `MP_UNREACH` withdrawals and the discarded
/// `MP_REACH` announcements, so a looped re-announcement cannot strand a
/// stale membership NLRI in the Adj-RIB-In.
#[tokio::test]
async fn rr_loop_detected_update_synthesizes_rtc_withdrawals() {
    use rustbgpd_wire::{MpReachNlri, MpUnreachNlri, RtcNlri};
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65001);
    let local_cluster_id = Ipv4Addr::new(10, 0, 0, 9);
    session.config.cluster_id = Some(local_cluster_id);
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
    let announced_nlri = RtcNlri::new(65001, 0x0002_FDE9_0000_0064, 96).unwrap();
    let withdrawn_nlri = RtcNlri::new(65001, 0x0002_FDE9_0000_00C8, 96).unwrap();
    session.known_rtc.extend([
        rustbgpd_rib::RtcRibRouteKey {
            nlri: announced_nlri,
            path_id: 0,
        },
        rustbgpd_rib::RtcRibRouteKey {
            nlri: withdrawn_nlri,
            path_id: 0,
        },
    ]);
    session.begin_refresh_accounting(Afi::Ipv4, Safi::RtConstrain);
    let attrs = vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath { segments: vec![] }),
        // Triggers the loop — local cluster-id present in the advertised list.
        PathAttribute::ClusterList(vec![local_cluster_id]),
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
            rtc_announced: vec![announced_nlri],
        }),
        PathAttribute::MpUnreachNlri(MpUnreachNlri {
            afi: Afi::Ipv4,
            safi: Safi::RtConstrain,
            withdrawn: vec![],
            flowspec_withdrawn: vec![],
            evpn_withdrawn: vec![],
            bgpls_withdrawn: vec![],
            labeled_withdrawn: vec![],
            vpn_withdrawn: vec![],
            rtc_withdrawn: vec![withdrawn_nlri],
        }),
    ];
    let update = UpdateMessage::build(&[], &[], &attrs, true, false, Ipv4UnicastMode::MpReach);
    session.process_update(update).await;
    let msg = rib_rx
        .try_recv()
        .expect("loop-path must still dispatch RTC withdrawals");
    match msg {
        RibUpdate::RtcRoutesReceived {
            announced,
            withdrawn,
            ..
        } => {
            assert!(
                announced.is_empty(),
                "announces in a loop-detected UPDATE must be discarded"
            );
            let withdrawn_nlris: Vec<_> = withdrawn.iter().map(|k| k.nlri).collect();
            assert!(
                withdrawn_nlris.contains(&withdrawn_nlri),
                "MP_UNREACH RTC withdrawals must survive loop detection"
            );
            assert!(
                withdrawn_nlris.contains(&announced_nlri),
                "loop-detected RTC announces must be synthesized into withdrawals"
            );
        }
        _ => panic!("expected RtcRoutesReceived from the loop-detect path"),
    }
    assert_eq!(
        session.refresh_accounting_stale_count((Afi::Ipv4, Safi::RtConstrain)),
        Some(0),
        "synthesized RR-loop RTC withdrawals must retire both stale identities"
    );
    session.end_refresh_accounting(Afi::Ipv4, Safi::RtConstrain);
    assert!(session.known_rtc.is_empty());
}

/// Regression: the AS_PATH-loop branch and the RR-loop branch share the
/// same withdrawal-recovery shape — both must propagate EVPN withdrawals.
/// The RR-loop fix landed earlier; this test covers the parallel
/// `AS_PATH contains local ASN` branch which was still hardcoding
/// `evpn_withdrawn: vec![]`.
#[tokio::test]
async fn as_path_loop_update_still_applies_evpn_withdrawals() {
    use rustbgpd_wire::{
        EthernetSegmentIdentifier, EthernetTagId, EvpnMacIp, EvpnRoute, MacAddress, MpReachNlri,
        MpUnreachNlri, MplsLabel, RouteDistinguisher,
    };
    // eBGP session — AS_PATH loop only triggers when the peer's UPDATE
    // contains our local ASN, which only happens across an eBGP boundary.
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    let mut negotiated = NegotiatedSession::default();
    negotiated.peer_asn = 65002;
    negotiated.peer_router_id = Ipv4Addr::new(10, 0, 0, 2);
    negotiated.hold_time = 90;
    negotiated.keepalive_interval = 30;
    negotiated.four_octet_as = true;
    negotiated.negotiated_families = vec![(Afi::L2Vpn, Safi::Evpn)];
    session
        .negotiated_families
        .clone_from(&negotiated.negotiated_families);
    session.negotiated = Some(negotiated);
    let withdrawn_route = EvpnRoute::MacIp(EvpnMacIp {
        rd: RouteDistinguisher([0, 0, 0xFD, 0xE8, 0, 0, 0, 100]),
        esi: EthernetSegmentIdentifier::ZERO,
        ethernet_tag: EthernetTagId(100),
        mac: MacAddress([0x02, 0x00, 0x00, 0xAA, 0xBB, 0xCC]),
        ip: None,
        label1: MplsLabel::new(10_000),
        label2: None,
    });
    let expected_key = withdrawn_route.key();
    session.known_evpn.insert(expected_key);
    session.begin_refresh_accounting(Afi::L2Vpn, Safi::Evpn);
    // AS_PATH that contains our local ASN (65001) → loop trigger.
    let attrs = vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath {
            segments: vec![AsPathSegment::AsSequence(vec![65002, 65001, 65003])],
        }),
        PathAttribute::MpReachNlri(MpReachNlri {
            afi: Afi::L2Vpn,
            safi: Safi::Evpn,
            next_hop: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            link_local_next_hop: None,
            announced: vec![],
            flowspec_announced: vec![],
            evpn_announced: vec![withdrawn_route.clone()],
            bgpls_announced: vec![],
            labeled_announced: vec![],
            vpn_announced: vec![],
            rtc_announced: vec![],
        }),
        PathAttribute::MpUnreachNlri(MpUnreachNlri {
            afi: Afi::L2Vpn,
            safi: Safi::Evpn,
            withdrawn: vec![],
            flowspec_withdrawn: vec![],
            evpn_withdrawn: vec![withdrawn_route],
            bgpls_withdrawn: vec![],
            labeled_withdrawn: vec![],
            vpn_withdrawn: vec![],
            rtc_withdrawn: vec![],
        }),
    ];
    let update = UpdateMessage::build(&[], &[], &attrs, true, false, Ipv4UnicastMode::MpReach);
    session.process_update(update).await;
    let msg = rib_rx
        .try_recv()
        .expect("AS_PATH-loop branch must still dispatch withdrawals");
    match msg {
        RibUpdate::RoutesReceived {
            announced,
            evpn_announced,
            evpn_withdrawn,
            ..
        } => {
            assert!(
                announced.is_empty() && evpn_announced.is_empty(),
                "announces in an AS_PATH-loop UPDATE must be discarded"
            );
            assert_eq!(
                evpn_withdrawn,
                vec![expected_key],
                "EVPN withdrawals must survive AS_PATH-loop discard"
            );
        }
        _ => panic!("expected RoutesReceived from the AS_PATH-loop path"),
    }
    assert_eq!(
        session.refresh_accounting_stale_count((Afi::L2Vpn, Safi::Evpn)),
        Some(0),
        "AS-loop withdrawal must retire the exact stale identity"
    );
    session.end_refresh_accounting(Afi::L2Vpn, Safi::Evpn);
    assert!(session.known_evpn.is_empty());
}

/// An AS_PATH-loop replacement is an implicit withdrawal only when its exact
/// wire identity was previously accepted. A first-seen rejected identity must
/// remain silent.
#[tokio::test]
async fn as_path_loop_replacement_withdraws_accepted_classic_identity_only() {
    use super::import_decision_cache::{CachedOutcome, ImportDecisionKey, LookupResult};

    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    session.import_explain_enabled = true;
    install_test_negotiated_session(&mut session, negotiated_session(65002, false));
    let accepted = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 0), 24);
    let first_seen = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24);
    let attrs = |path: Vec<u32>| {
        vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath {
                segments: vec![AsPathSegment::AsSequence(path)],
            }),
            PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
        ]
    };
    session
        .process_update(UpdateMessage::build(
            &[Ipv4NlriEntry {
                path_id: 0,
                prefix: accepted,
            }],
            &[],
            &attrs(vec![65002]),
            true,
            false,
            Ipv4UnicastMode::Body,
        ))
        .await;
    let RibUpdate::RoutesReceived { announced, .. } = rib_rx.try_recv().unwrap() else {
        panic!("expected accepted route");
    };
    assert_eq!(announced.len(), 1);

    session
        .process_update(UpdateMessage::build(
            &[
                Ipv4NlriEntry {
                    path_id: 0,
                    prefix: accepted,
                },
                Ipv4NlriEntry {
                    path_id: 0,
                    prefix: first_seen,
                },
            ],
            &[],
            &attrs(vec![65002, 65001]),
            true,
            false,
            Ipv4UnicastMode::Body,
        ))
        .await;
    let RibUpdate::RoutesReceived {
        announced,
        withdrawn,
        ..
    } = rib_rx
        .try_recv()
        .expect("accepted looped replacement must reach the RIB as a withdrawal")
    else {
        panic!("expected RoutesReceived");
    };
    assert!(announced.is_empty());
    assert_eq!(withdrawn, vec![(Prefix::V4(accepted), 0)]);
    assert_eq!(session.known_prefix_count(), 0);
    assert!(
        rib_rx.try_recv().is_err(),
        "first-seen reject must stay silent"
    );

    let key = ImportDecisionKey {
        afi: Afi::Ipv4,
        safi: Safi::Unicast,
        prefix: Prefix::V4(accepted),
        path_id: 0,
    };
    match session
        .import_decision_cache
        .lookup(&key, session.import_policy_generation)
    {
        LookupResult::Hit(decision) => assert_eq!(decision.outcome, CachedOutcome::Withdrawn),
        other => panic!("expected safety-withdrawn explain outcome, got {other:?}"),
    }
    let first_seen_key = ImportDecisionKey {
        prefix: Prefix::V4(first_seen),
        ..key
    };
    assert!(matches!(
        session
            .import_decision_cache
            .lookup(&first_seen_key, session.import_policy_generation),
        LookupResult::NotSeen
    ));
}

/// `ORIGINATOR_ID` rejection must retire exact IPv6 Add-Path identities before
/// later ERR/GR lifecycle messages, without duplicating an explicit overlap or
/// touching an accepted sibling path.
#[expect(
    clippy::too_many_lines,
    reason = "pins RR-loop replacement identity, overlap, ERR accounting, explain state, and GR channel ordering"
)]
#[tokio::test]
async fn rr_originator_loop_withdraws_mp_add_paths_before_gr_and_preserves_sibling() {
    use super::import_decision_cache::{CachedOutcome, ImportDecisionKey, LookupResult};
    use rustbgpd_wire::{MpReachNlri, MpUnreachNlri, NlriEntry};

    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65001);
    session.import_explain_enabled = true;
    session.config.peer.graceful_restart = true;
    let mut negotiated = negotiated_session(65001, false);
    negotiated.negotiated_families = vec![(Afi::Ipv6, Safi::Unicast)];
    negotiated
        .add_path_families
        .insert((Afi::Ipv6, Safi::Unicast), AddPathMode::Both);
    negotiated.peer_route_refresh = true;
    negotiated.peer_enhanced_route_refresh = true;
    negotiated.peer_gr_capable = true;
    negotiated.peer_restart_time = 120;
    negotiated.peer_gr_families = vec![rustbgpd_wire::GracefulRestartFamily {
        afi: Afi::Ipv6,
        safi: Safi::Unicast,
        forwarding_preserved: false,
    }];
    install_test_negotiated_session(&mut session, negotiated);
    let prefix = Prefix::V6(Ipv6Prefix::new("2001:db8:440::".parse().unwrap(), 64));
    let nlri = |path_id| NlriEntry { path_id, prefix };
    let reach = |announced| {
        PathAttribute::MpReachNlri(MpReachNlri {
            afi: Afi::Ipv6,
            safi: Safi::Unicast,
            next_hop: "2001:db8::2".parse().unwrap(),
            link_local_next_hop: None,
            announced,
            flowspec_announced: vec![],
            evpn_announced: vec![],
            bgpls_announced: vec![],
            labeled_announced: vec![],
            vpn_announced: vec![],
            rtc_announced: vec![],
        })
    };
    let base_attrs = || {
        vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath { segments: vec![] }),
        ]
    };
    let mut initial_attrs = base_attrs();
    initial_attrs.push(reach(vec![nlri(11), nlri(22), nlri(33)]));
    session
        .process_update(UpdateMessage::build(
            &[],
            &[],
            &initial_attrs,
            true,
            true,
            Ipv4UnicastMode::Body,
        ))
        .await;
    let RibUpdate::RoutesReceived { announced, .. } = rib_rx.try_recv().unwrap() else {
        panic!("expected initial Add-Path routes");
    };
    assert_eq!(announced.len(), 3);

    buffer_route_refresh(
        &mut session,
        Afi::Ipv6,
        Safi::Unicast,
        RouteRefreshSubtype::BoRR,
    );
    session.process_read_buffer().await;
    assert!(matches!(
        rib_rx.try_recv(),
        Ok(RibUpdate::BeginRouteRefresh {
            afi: Afi::Ipv6,
            safi: Safi::Unicast,
            ..
        })
    ));
    assert_eq!(
        session.refresh_accounting_stale_count((Afi::Ipv6, Safi::Unicast)),
        Some(3)
    );

    let mut loop_attrs = base_attrs();
    loop_attrs.push(PathAttribute::OriginatorId(
        session.config.peer.local_router_id,
    ));
    loop_attrs.push(reach(vec![nlri(11), nlri(22), nlri(44)]));
    loop_attrs.push(PathAttribute::MpUnreachNlri(MpUnreachNlri {
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
            &loop_attrs,
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
        .expect("RR-loop withdrawals must precede lifecycle messages")
    else {
        panic!("expected RoutesReceived");
    };
    assert!(announced.is_empty());
    withdrawn.sort_unstable_by_key(|(_, path_id)| *path_id);
    assert_eq!(withdrawn, vec![(prefix, 11), (prefix, 22)]);
    assert!(!session.known_paths.contains(&(prefix, 11)));
    assert!(!session.known_paths.contains(&(prefix, 22)));
    assert!(session.known_paths.contains(&(prefix, 33)));
    assert!(!session.known_paths.contains(&(prefix, 44)));
    assert_eq!(session.known_prefix_count(), 1);
    assert_eq!(
        session.refresh_accounting_stale_count((Afi::Ipv6, Safi::Unicast)),
        Some(1)
    );

    let key = |path_id| ImportDecisionKey {
        afi: Afi::Ipv6,
        safi: Safi::Unicast,
        prefix,
        path_id,
    };
    for path_id in [11, 22] {
        match session
            .import_decision_cache
            .lookup(&key(path_id), session.import_policy_generation)
        {
            LookupResult::Hit(decision) => {
                assert_eq!(decision.outcome, CachedOutcome::Withdrawn);
            }
            other => panic!("expected withdrawn path {path_id}, got {other:?}"),
        }
    }
    assert!(matches!(
        session
            .import_decision_cache
            .lookup(&key(44), session.import_policy_generation),
        LookupResult::NotSeen
    ));

    session.execute_actions(vec![Action::SessionDown]).await;
    match rib_rx
        .try_recv()
        .expect("GR lifecycle message must follow route withdrawal")
    {
        RibUpdate::PeerGracefulRestart { peer, .. } => assert_eq!(peer, session.peer_ip),
        _ => panic!("expected PeerGracefulRestart after route withdrawal"),
    }
}
