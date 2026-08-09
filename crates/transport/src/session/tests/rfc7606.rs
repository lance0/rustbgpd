use super::*;

/// RFC 7606 §7.4 + §2: a malformed MED treats the UPDATE as though its
/// routes had been withdrawn — previously accepted routes for the same
/// NLRI are removed — and the session stays Established. Load-bearing metric
/// proof: removing the dedicated treat-as-withdraw sync leaves usage at `2`
/// after the production accounting removed both routes.
#[tokio::test]
async fn rfc7606_treat_as_withdraw_removes_routes_and_keeps_session() {
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    let (client, _server) = connected_stream_pair().await;
    session.test_install_stream(client);
    establish_test_session(&mut session, 65002).await;
    rfc7606_drain(&mut rib_rx);
    let prefix_a = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24);
    let prefix_b = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 0), 24);
    // Announce both prefixes cleanly.
    session
        .process_update(rfc7606_update(
            rfc7606_attr_bytes(&[]),
            &[prefix_a, prefix_b],
        ))
        .await;
    let RibUpdate::RoutesReceived { announced, .. } = rib_rx.try_recv().unwrap() else {
        panic!("expected initial accepted routes");
    };
    assert_eq!(announced.len(), 2);
    assert_max_prefix_gauge(&session, "bgp_max_prefix_usage", "aggregate", Some(2.0));
    // Re-announce with a malformed MED appended (length 3, must be 4).
    session
        .process_update(rfc7606_update(
            rfc7606_attr_bytes(&[0x80, 4, 3, 0, 0, 1]),
            &[prefix_a, prefix_b],
        ))
        .await;
    let RibUpdate::RoutesReceived {
        announced,
        withdrawn,
        ..
    } = rib_rx.try_recv().unwrap()
    else {
        panic!("expected treat-as-withdraw RoutesReceived");
    };
    assert!(
        announced.is_empty(),
        "a malformed MED must not admit any announcement"
    );
    assert_eq!(withdrawn.len(), 2);
    assert!(withdrawn.contains(&(Prefix::V4(prefix_a), 0)));
    assert!(withdrawn.contains(&(Prefix::V4(prefix_b), 0)));
    assert_eq!(session.known_prefix_count(), 0);
    assert_max_prefix_gauge(&session, "bgp_max_prefix_usage", "aggregate", Some(0.0));
    assert_eq!(
        session.fsm.state(),
        SessionState::Established,
        "treat-as-withdraw must keep the session Established"
    );
    assert_single_malformed_disposition(&session, "treat_as_withdraw");
}

/// Load-bearing RFC 9774 proof: deleting the raw `AS_SET` inspection admits
/// both announcements, so the exact mixed-withdrawal and prefix-state
/// assertions fail. The explicit/replacement overlap also proves one output.
#[tokio::test]
async fn rfc9774_as_set_replacement_withdraws_exactly_once_and_keeps_session() {
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    let (client, _server) = connected_stream_pair().await;
    session.test_install_stream(client);
    establish_test_session(&mut session, 65002).await;
    rfc7606_drain(&mut rib_rx);
    let overlap = Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, 0), 24);
    let replacement = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 0), 24);
    let first_seen = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24);
    session
        .process_update(rfc7606_update(
            rfc7606_attr_bytes(&[]),
            &[overlap, replacement],
        ))
        .await;
    let RibUpdate::RoutesReceived { announced, .. } = rib_rx.try_recv().unwrap() else {
        panic!("expected initial accepted routes");
    };
    assert_eq!(announced.len(), 2);

    let mut withdrawn = Vec::new();
    rustbgpd_wire::nlri::encode_nlri(&[overlap], &mut withdrawn);
    let malformed = UpdateMessage {
        withdrawn_routes: Bytes::from(withdrawn),
        path_attributes: Bytes::from(
            [
                &[0x40, 1, 1, 0][..],
                &[0x40, 2, 6, 1, 1, 0, 0, 0xFD, 0xEA],
                &[0x40, 3, 4, 10, 0, 0, 2],
            ]
            .concat(),
        ),
        nlri: rfc7606_update(Vec::new(), &[overlap, replacement, first_seen]).nlri,
    };
    session.process_update(malformed).await;
    let RibUpdate::RoutesReceived {
        announced,
        withdrawn,
        ..
    } = rib_rx
        .try_recv()
        .expect("RFC 9774 withdrawal must reach RIB")
    else {
        panic!("expected treat-as-withdraw RoutesReceived");
    };
    assert!(announced.is_empty());
    assert_eq!(
        withdrawn,
        vec![(Prefix::V4(overlap), 0), (Prefix::V4(replacement), 0)],
        "explicit/replacement overlap is emitted once; first-seen stays silent"
    );
    assert!(rib_rx.try_recv().is_err());
    assert_eq!(session.known_prefix_count(), 0);
    assert_eq!(session.fsm.state(), SessionState::Established);
    assert_single_malformed_disposition(&session, "treat_as_withdraw");
}

/// Load-bearing RFC 7606 §5.2 composition proof: deleting the new RFC 9774
/// detector (or bypassing existing disposition composition) leaves this
/// no-NLRI `AS_SET` UPDATE Established instead of reset.
#[tokio::test]
async fn rfc9774_as_set_without_reachable_nlri_resets_session() {
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    let (client, _server) = connected_stream_pair().await;
    session.test_install_stream(client);
    establish_test_session(&mut session, 65002).await;
    rfc7606_drain(&mut rib_rx);
    session
        .process_update(rfc7606_update(
            vec![0x40, 1, 1, 0, 0x40, 2, 6, 1, 1, 0, 0, 0xFD, 0xEA],
            &[],
        ))
        .await;
    assert_ne!(session.fsm.state(), SessionState::Established);
    while let Ok(update) = rib_rx.try_recv() {
        assert!(!matches!(update, RibUpdate::RoutesReceived { .. }));
    }
    assert_single_malformed_disposition(&session, "session_reset");
}

/// RFC 7606 §7.7: a malformed AGGREGATOR is attribute-discard — the UPDATE
/// (and its announcements) proceed without the attribute, and the session
/// stays Established.
#[tokio::test]
async fn rfc7606_attribute_discard_keeps_announcement_and_session() {
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    let (client, _server) = connected_stream_pair().await;
    session.test_install_stream(client);
    establish_test_session(&mut session, 65002).await;
    rfc7606_drain(&mut rib_rx);
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24);
    // AGGREGATOR with length 5 (must be 8 under 4-octet-AS negotiation).
    session
        .process_update(rfc7606_update(
            rfc7606_attr_bytes(&[0xC0, 7, 5, 0, 0, 0xFD, 0xEA, 1]),
            &[prefix],
        ))
        .await;
    let RibUpdate::RoutesReceived { announced, .. } = rib_rx.try_recv().unwrap() else {
        panic!("expected the announcement to survive attribute-discard");
    };
    assert_eq!(announced.len(), 1);
    assert_eq!(announced[0].prefix, Prefix::V4(prefix));
    assert_eq!(session.fsm.state(), SessionState::Established);
    assert_single_malformed_disposition(&session, "attribute_discard");
}

/// RFC 6793 / RFC 7606: a malformed `AS4_PATH` is discarded without losing
/// reachable NLRI or the valid ordinary path on a legacy session.
///
/// Load-bearing proof: bypassing AS4 normalization leaves raw type 17 on the
/// delivered route and skips the attribute-discard counter; escalating the
/// parse failure removes the announcement or drops the Established session.
#[tokio::test]
async fn malformed_as4_path_discards_only_sidecar_and_keeps_reachable_nlri() {
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    let (client, _server) = connected_stream_pair().await;
    session.test_install_stream(client);
    establish_test_session(&mut session, 65002).await;
    rfc7606_drain(&mut rib_rx);
    let mut negotiated = negotiated_session(65002, false);
    negotiated.four_octet_as = false;
    install_test_negotiated_session(&mut session, negotiated);

    let prefix = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 17), 32);
    let attrs = [
        &[0x40, 1, 1, 0][..],
        &[0x40, 2, 4, 2, 1, 0xFD, 0xEA],
        &[0x40, 3, 4, 10, 0, 0, 2],
        // Optional+Transitive AS4_PATH with a value shorter than one segment.
        &[0xC0, 17, 0],
    ]
    .concat();
    session
        .process_update(rfc7606_update(attrs, &[prefix]))
        .await;

    let RibUpdate::RoutesReceived {
        announced,
        withdrawn,
        ..
    } = rib_rx
        .try_recv()
        .expect("reachable NLRI must survive malformed AS4_PATH")
    else {
        panic!("expected RoutesReceived");
    };
    assert!(withdrawn.is_empty());
    assert_eq!(announced.len(), 1);
    assert_eq!(announced[0].prefix, Prefix::V4(prefix));
    assert_eq!(
        announced[0]
            .as_path()
            .expect("ordinary AS_PATH survives")
            .asns()
            .collect::<Vec<_>>(),
        vec![65_002]
    );
    assert!(
        announced[0].attributes.iter().all(|attribute| {
            attribute.type_code() != rustbgpd_wire::constants::attr_type::AS4_PATH
        }),
        "malformed compatibility sidecar must not enter Adj-RIB-In"
    );
    assert_eq!(session.fsm.state(), SessionState::Established);
    assert_single_malformed_disposition(&session, "attribute_discard");
}

/// RFC 9552 §8.2.2: malformed TLV framing discards the complete BGP-LS
/// Attribute while preserving its BGP-LS NLRI and the session.
///
/// Load-bearing live proof: bypassing the Attribute 29 parser leaves type 29
/// on the delivered route and fails the absence assertion; changing its
/// disposition to treat-as-withdraw removes the announcement and fails the
/// `BgpLsRoutesReceived` assertion.
#[tokio::test]
async fn bgpls_attribute_discard_keeps_nlri_and_session() {
    use rustbgpd_wire::MpReachNlri;

    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    let (client, _server) = connected_stream_pair().await;
    session.test_install_stream(client);
    establish_test_session(&mut session, 65002).await;
    rfc7606_drain(&mut rib_rx);

    let mut negotiated = negotiated_session(65002, false);
    negotiated.negotiated_families = vec![(Afi::BgpLs, Safi::BgpLs)];
    install_test_negotiated_session(&mut session, negotiated);

    let nlri = BgpLsNlri::try_new(
        BgpLsNlriType::Unknown(65_000),
        None,
        Bytes::from_static(&[0xaa, 0xbb, 0xcc]),
    )
    .unwrap();
    let attrs = vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath {
            segments: vec![AsPathSegment::AsSequence(vec![65002])],
        }),
        PathAttribute::MpReachNlri(MpReachNlri {
            afi: Afi::BgpLs,
            safi: Safi::BgpLs,
            next_hop: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)),
            link_local_next_hop: None,
            announced: vec![],
            flowspec_announced: vec![],
            evpn_announced: vec![],
            bgpls_announced: vec![nlri.clone()],
            labeled_announced: vec![],
            vpn_announced: vec![],
            rtc_announced: vec![],
        }),
        PathAttribute::Unknown(RawAttribute {
            flags: rustbgpd_wire::constants::attr_flags::OPTIONAL,
            type_code: rustbgpd_wire::constants::attr_type::BGP_LS,
            // IGP Metric TLV 1095 declares four bytes but only three remain.
            data: Bytes::from_static(&[0x04, 0x47, 0, 4, 0, 0, 7]),
        }),
    ];

    session
        .process_update(UpdateMessage::build(
            &[],
            &[],
            &attrs,
            true,
            false,
            Ipv4UnicastMode::Body,
        ))
        .await;

    let RibUpdate::BgpLsRoutesReceived {
        announced,
        withdrawn,
        ..
    } = rib_rx.try_recv().expect("BGP-LS NLRI must survive")
    else {
        panic!("expected BgpLsRoutesReceived");
    };
    assert_eq!(announced.len(), 1);
    assert_eq!(announced[0].nlri, nlri);
    assert!(withdrawn.is_empty());
    assert!(
        !announced[0]
            .attributes
            .iter()
            .any(|attr| attr.type_code() == rustbgpd_wire::constants::attr_type::BGP_LS),
        "the malformed Attribute 29 must not enter Adj-RIB-In"
    );
    assert_eq!(session.fsm.state(), SessionState::Established);
    assert_single_malformed_disposition(&session, "attribute_discard");
}

/// RFC 7606 §7.11: a malformed `MP_REACH_NLRI` means the NLRI cannot be
/// located — the session-reset approach is retained.
#[tokio::test]
async fn rfc7606_malformed_mp_reach_still_resets_session() {
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    let (client, _server) = connected_stream_pair().await;
    session.test_install_stream(client);
    establish_test_session(&mut session, 65002).await;
    rfc7606_drain(&mut rib_rx);
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24);
    // MP_REACH_NLRI truncated to 2 bytes (minimum is 5).
    session
        .process_update(rfc7606_update(
            rfc7606_attr_bytes(&[0x80, 14, 2, 0, 1]),
            &[prefix],
        ))
        .await;
    assert_ne!(
        session.fsm.state(),
        SessionState::Established,
        "malformed MP_REACH_NLRI must reset the session"
    );
    // Teardown emits PeerDown/GR messages; none of them may carry routes.
    while let Ok(msg) = rib_rx.try_recv() {
        assert!(
            !matches!(msg, RibUpdate::RoutesReceived { .. }),
            "no routes may be delivered"
        );
    }
    assert_single_malformed_disposition(&session, "session_reset");
}

/// RFC 7606 §5.2: an UPDATE carrying path attributes but no reachable NLRI
/// gives no confidence its NLRI parsed; a treat-as-withdraw-class error must
/// escalate to session reset.
#[tokio::test]
async fn rfc7606_malformed_attr_without_reachable_nlri_resets_session() {
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    let (client, _server) = connected_stream_pair().await;
    session.test_install_stream(client);
    establish_test_session(&mut session, 65002).await;
    rfc7606_drain(&mut rib_rx);
    // Malformed MED, no NLRI anywhere in the UPDATE.
    session
        .process_update(rfc7606_update(
            rfc7606_attr_bytes(&[0x80, 4, 3, 0, 0, 1]),
            &[],
        ))
        .await;
    assert_ne!(
        session.fsm.state(),
        SessionState::Established,
        "treat-as-withdraw with no reachable NLRI must reset (RFC 7606 §5.2)"
    );
    while let Ok(msg) = rib_rx.try_recv() {
        assert!(
            !matches!(msg, RibUpdate::RoutesReceived { .. }),
            "no routes may be delivered"
        );
    }
    assert_single_malformed_disposition(&session, "session_reset");
}

/// RFC 7606 §5.2: an `MP_REACH_NLRI` attribute that is present but
/// encodes ZERO NLRI provides no reachable NLRI — a
/// treat-as-withdraw-class error must escalate to session reset exactly
/// as when the attribute is absent. Attribute presence must not shield
/// the reset: treat-as-withdraw would withdraw nothing here.
#[tokio::test]
async fn rfc7606_empty_mp_reach_with_taw_error_resets_session() {
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    let (client, _server) = connected_stream_pair().await;
    session.test_install_stream(client);
    establish_test_session(&mut session, 65002).await;
    rfc7606_drain(&mut rib_rx);
    // Malformed MED (treat-as-withdraw) + an empty-NLRI MP_REACH; no
    // body NLRI anywhere.
    let mut extra = vec![0x80, 4, 3, 0, 0, 1];
    extra.extend(rfc7606_mp_reach(&[]));
    session
        .process_update(rfc7606_update(rfc7606_attr_bytes(&extra), &[]))
        .await;
    assert_ne!(
        session.fsm.state(),
        SessionState::Established,
        "an empty-NLRI MP_REACH encodes no reachable NLRI; the error must reset (RFC 7606 §5.2)"
    );
    while let Ok(msg) = rib_rx.try_recv() {
        assert!(
            !matches!(msg, RibUpdate::RoutesReceived { .. }),
            "no routes may be delivered"
        );
    }
    assert_single_malformed_disposition(&session, "session_reset");
}

/// Regression guard for the §5.2 tightening above: an `MP_REACH` that
/// DOES carry NLRI keeps the ordinary treat-as-withdraw behavior — the
/// session stays Established and no announcement is admitted.
#[tokio::test]
async fn rfc7606_nonempty_mp_reach_with_taw_error_stays_established() {
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    let (client, _server) = connected_stream_pair().await;
    session.test_install_stream(client);
    establish_test_session(&mut session, 65002).await;
    rfc7606_drain(&mut rib_rx);
    // Malformed MED + MP_REACH announcing 2001:db8::/32.
    let mut extra = vec![0x80, 4, 3, 0, 0, 1];
    extra.extend(rfc7606_mp_reach(&[32, 0x20, 0x01, 0x0d, 0xb8]));
    session
        .process_update(rfc7606_update(rfc7606_attr_bytes(&extra), &[]))
        .await;
    assert_eq!(
        session.fsm.state(),
        SessionState::Established,
        "reachable MP NLRI keeps the treat-as-withdraw path (no over-reset)"
    );
    assert_single_malformed_disposition(&session, "treat_as_withdraw");
    while let Ok(msg) = rib_rx.try_recv() {
        if let RibUpdate::RoutesReceived { announced, .. } = msg {
            assert!(
                announced.is_empty(),
                "treat-as-withdraw must not admit the announcement"
            );
        }
    }
}

/// An UPDATE whose only attributes were discarded as malformed must not be
/// mistaken for an End-of-RIB marker.
#[tokio::test]
async fn rfc7606_discarded_attrs_do_not_fake_end_of_rib() {
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    let (client, _server) = connected_stream_pair().await;
    session.test_install_stream(client);
    establish_test_session(&mut session, 65002).await;
    rfc7606_drain(&mut rib_rx);
    // Only a malformed ATOMIC_AGGREGATE (attribute-discard), nothing else.
    session
        .process_update(rfc7606_update(vec![0x40, 6, 1, 0xAB], &[]))
        .await;
    assert!(rib_rx.try_recv().is_err());
    assert!(
        !session
            .received_eor_families
            .contains(&(Afi::Ipv4, Safi::Unicast)),
        "an all-attributes-discarded UPDATE is junk, not an EoR"
    );
    assert_eq!(session.fsm.state(), SessionState::Established);
    assert_single_malformed_disposition(&session, "attribute_discard");
}

/// RFC 7606 §2: treat-as-withdraw must cover EVPN too — a previously
/// accepted EVPN route re-announced in an UPDATE with a malformed attribute
/// is withdrawn from the RIB, and the session stays Established.
#[tokio::test]
async fn rfc7606_treat_as_withdraw_covers_previously_accepted_evpn_routes() {
    use rustbgpd_wire::{
        EthernetSegmentIdentifier, EthernetTagId, EvpnMacIp, EvpnRoute, MacAddress, MpReachNlri,
        MplsLabel, RouteDistinguisher,
    };
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    let (client, _server) = connected_stream_pair().await;
    session.test_install_stream(client);
    establish_test_session(&mut session, 65002).await;
    session.negotiated_families.push((Afi::L2Vpn, Safi::Evpn));
    rfc7606_drain(&mut rib_rx);
    let evpn_route = EvpnRoute::MacIp(EvpnMacIp {
        rd: RouteDistinguisher([0x00, 0x00, 0xFD, 0xE8, 0x00, 0x00, 0x00, 0x64]),
        esi: EthernetSegmentIdentifier::ZERO,
        ethernet_tag: EthernetTagId(0),
        mac: MacAddress([0xaa, 0xbb, 0xcc, 0x00, 0x00, 0x01]),
        ip: Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))),
        label1: MplsLabel::new(100),
        label2: None,
    });
    let attrs = vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath {
            segments: vec![AsPathSegment::AsSequence(vec![65002])],
        }),
        PathAttribute::MpReachNlri(MpReachNlri {
            afi: Afi::L2Vpn,
            safi: Safi::Evpn,
            next_hop: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            link_local_next_hop: None,
            announced: vec![],
            flowspec_announced: vec![],
            evpn_announced: vec![evpn_route.clone()],
            bgpls_announced: vec![],
            labeled_announced: vec![],
            vpn_announced: vec![],
            rtc_announced: vec![],
        }),
    ];
    let clean = UpdateMessage::build(&[], &[], &attrs, true, false, Ipv4UnicastMode::Body);
    session.process_update(clean.clone()).await;
    let RibUpdate::RoutesReceived { evpn_announced, .. } = rib_rx.try_recv().unwrap() else {
        panic!("expected the clean EVPN announcement to be accepted");
    };
    assert_eq!(evpn_announced.len(), 1);
    assert!(session.known_evpn.contains(&evpn_route.key()));
    // Re-announce the same EVPN route with a malformed MED appended.
    let mut attr_bytes = clean.path_attributes.to_vec();
    attr_bytes.extend([0x80, 4, 3, 0, 0, 1]);
    session
        .process_update(UpdateMessage {
            withdrawn_routes: Bytes::new(),
            path_attributes: Bytes::from(attr_bytes),
            nlri: Bytes::new(),
        })
        .await;
    let RibUpdate::RoutesReceived {
        evpn_announced,
        evpn_withdrawn,
        ..
    } = rib_rx.try_recv().unwrap()
    else {
        panic!("expected treat-as-withdraw RoutesReceived for the EVPN route");
    };
    assert!(evpn_announced.is_empty());
    assert_eq!(evpn_withdrawn, vec![evpn_route.key()]);
    assert!(
        session.known_evpn.is_empty(),
        "the previously accepted EVPN route must leave the session's accepted set"
    );
    assert_eq!(session.fsm.state(), SessionState::Established);
}

/// RFC 4724 §2 MP End-of-RIB: an UPDATE whose only content is an empty
/// `MP_UNREACH_NLRI` marks End-of-RIB for that family and the session stays
/// Established.
#[tokio::test]
async fn mp_eor_empty_mp_unreach_marks_end_of_rib() {
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    let (client, _server) = connected_stream_pair().await;
    session.test_install_stream(client);
    establish_test_session(&mut session, 65002).await;
    rfc7606_drain(&mut rib_rx);
    // Hand-crafted MP_UNREACH_NLRI: flags 0x80, type 15, len 3,
    // AFI=2 (IPv6), SAFI=1 (unicast), no NLRI.
    session
        .process_update(UpdateMessage {
            withdrawn_routes: Bytes::new(),
            path_attributes: Bytes::from_static(&[0x80, 15, 3, 0, 2, 1]),
            nlri: Bytes::new(),
        })
        .await;
    assert!(
        session
            .received_eor_families
            .contains(&(Afi::Ipv6, Safi::Unicast)),
        "an empty MP_UNREACH must mark End-of-RIB for its family"
    );
    match rib_rx.try_recv().unwrap() {
        RibUpdate::EndOfRib { afi, safi, .. } => {
            assert_eq!(afi, Afi::Ipv6);
            assert_eq!(safi, Safi::Unicast);
        }
        _ => panic!("expected EndOfRib"),
    }
    assert_eq!(session.fsm.state(), SessionState::Established);
}

/// RFC 7606 §6: the malformed-UPDATE debug dump must capture the ENTIRE
/// UPDATE message (no truncation — the message is protocol-bounded) and
/// list the NLRI involved explicitly, with Add-Path path IDs and per
/// family, not just counts.
#[test]
fn malformed_update_dump_is_untruncated_and_enumerates_nlri() {
    // Body NLRI: 80 Add-Path IPv4 announcements (8 bytes each = 640 B,
    // past the old 512-byte per-section hex cap).
    let mut nlri = Vec::new();
    for i in 0..80u32 {
        nlri.extend_from_slice(&(i + 1).to_be_bytes()); // path ID
        nlri.push(24);
        #[expect(clippy::cast_possible_truncation, reason = "i < 80")]
        nlri.extend_from_slice(&[10, 0, i as u8]);
    }
    // One Add-Path withdrawn route: path ID 7, 192.0.2.0/24.
    let mut withdrawn = Vec::new();
    withdrawn.extend_from_slice(&7u32.to_be_bytes());
    withdrawn.push(24);
    withdrawn.extend_from_slice(&[192, 0, 2]);
    // Attributes: a malformed ORIGIN (length 2 — §7.1 treat-as-withdraw),
    // a valid AS_PATH and NEXT_HOP, and a valid MP_UNREACH_NLRI carrying
    // an IPv6 withdrawal so a second family is involved.
    let attrs: Vec<u8> = [
        &[0x40, 0x01, 0x02, 0x00, 0x00][..], // ORIGIN, bad length
        &[0x40, 0x02, 0x06, 0x02, 0x01, 0x00, 0x00, 0xFD, 0xE8], // AS_PATH seq [65000]
        &[0x40, 0x03, 0x04, 192, 0, 2, 1],   // NEXT_HOP
        &[
            0x80, 0x0F, 0x08, 0x00, 0x02, 0x01, 32, 0x20, 0x01, 0x0D, 0xB8,
        ], // MP_UNREACH 2001:db8::/32
    ]
    .concat();
    let update = rustbgpd_wire::UpdateMessage {
        withdrawn_routes: Bytes::from(withdrawn),
        path_attributes: Bytes::from(attrs),
        nlri: Bytes::from(nlri),
    };
    let revised = update
        .parse_revised(true, false, true, &[])
        .expect("revised parse recovers the malformed ORIGIN");
    assert!(
        !revised.malformed.is_empty(),
        "the malformed ORIGIN must be recovered, not dropped silently"
    );

    // (a) The full-message hex covers every byte and carries no
    // truncation marker.
    let hex = super::inbound::full_update_hex(&update);
    assert_eq!(
        hex.len(),
        update.encoded_len() * 2,
        "every byte of the UPDATE is hex-dumped"
    );
    assert!(!hex.contains('…'), "no truncation marker");
    assert!(
        hex.ends_with("00000050180a004f"),
        "the final NLRI entry (path ID 80, 10.0.79.0/24) is present past \
         the old 512-byte cap; got tail {}",
        &hex[hex.len() - 20..]
    );

    // (b) Every involved NLRI is enumerated: per family, with path IDs.
    let listed = super::inbound::involved_nlri(&revised.update);
    assert!(
        listed.contains("ipv4_unicast_announced"),
        "family label present: {listed}"
    );
    assert!(
        listed.contains("10.0.0.0/24 path-id 1"),
        "first announcement with path ID: {listed}"
    );
    assert!(
        listed.contains("10.0.79.0/24 path-id 80"),
        "last announcement (beyond the old cap) with path ID: {listed}"
    );
    assert!(
        listed.contains("ipv4_unicast_withdrawn") && listed.contains("192.0.2.0/24 path-id 7"),
        "withdrawal enumerated: {listed}"
    );
    assert!(
        listed.contains("ipv6_unicast_withdrawn") && listed.contains("2001:db8::/32"),
        "MP family withdrawal enumerated: {listed}"
    );
}
