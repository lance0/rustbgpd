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
    // Directly seed the runtime list to pin ordering: the config validator
    // rejects protected type 7, but even a defensive impossible-state test
    // must not double-count an attribute RFC 7606 already removed.
    session.config.discard_path_attributes = Arc::from([7]);
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
    assert!(
        counter_samples(&session.metrics, "bgp_path_attribute_discarded_total").is_empty(),
        "RFC 7606-removed attributes are absent before configured-discard accounting"
    );
}

/// RFC 4271 section 5: an unrecognized optional non-transitive attribute is
/// ignored while its reachable NLRI and the Established session survive.
#[tokio::test]
async fn unknown_optional_non_transitive_is_absent_from_delivered_route() {
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    let (client, _server) = connected_stream_pair().await;
    session.test_install_stream(client);
    establish_test_session(&mut session, 65002).await;
    rfc7606_drain(&mut rib_rx);
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 99), 32);

    session
        .process_update(rfc7606_update(
            rfc7606_attr_bytes(&[0x80, 99, 2, 0xaa, 0xbb]),
            &[prefix],
        ))
        .await;

    let RibUpdate::RoutesReceived { announced, .. } = rib_rx.try_recv().unwrap() else {
        panic!("expected the announcement to survive");
    };
    assert_eq!(announced.len(), 1);
    assert_eq!(announced[0].prefix, Prefix::V4(prefix));
    assert!(
        announced[0]
            .attributes
            .iter()
            .all(|attribute| attribute.type_code() != 99)
    );
    assert_eq!(session.fsm.state(), SessionState::Established);
}

#[tokio::test]
async fn assigned_opaque_attributes_reach_rib_while_edge_metadata_is_absent() {
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    let (client, mut server) = connected_stream_pair().await;
    session.test_install_stream(client);
    establish_test_session(&mut session, 65002).await;
    assert!(matches!(
        read_single_bgp_message(&mut server).await,
        Message::Open(_)
    ));
    assert!(matches!(
        read_single_bgp_message(&mut server).await,
        Message::Keepalive
    ));
    rfc7606_drain(&mut rib_rx);
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 42), 32);
    let values = [
        (25_u8, (0_u8..20).collect::<Vec<_>>()),
        (34_u8, vec![0, 2, 0x5a, 0xa5, 0, 6]),
        (36_u8, vec![1, 0, 0, 0, 0, 0, 0, 0]),
        (37, vec![2, 0, 4, 1, 99, 0, 0]),
        (38, vec![1, 0, 0, 0, 1, 1, 4, 192, 0, 2, 1]),
        (39, vec![0, 1, 1, 4, 192, 0, 2, 1, 0, 1, 0, 0]),
        (41, vec![0, 1, 0, 12, 0, 0, 0, 0, 0, 4, 0, 4, 192, 0, 2, 1]),
    ];
    let mut extra = Vec::new();
    for (code, value) in &values {
        extra.extend([0xc0, *code, u8::try_from(value.len()).unwrap()]);
        extra.extend(value);
    }
    extra.extend([0x80, 24, 1, 0xbb]);
    extra.extend([0x80, 42, 1, 0xaa]);
    session
        .process_update(rfc7606_update(rfc7606_attr_bytes(&extra), &[prefix]))
        .await;

    let RibUpdate::RoutesReceived { announced, .. } = rib_rx.try_recv().unwrap() else {
        panic!("expected assigned opaque announcement");
    };
    assert_eq!(announced.len(), 1);
    for (code, _) in &values {
        assert!(
            announced[0]
                .attributes
                .iter()
                .any(|attribute| attribute.type_code() == *code),
            "assigned type {code} did not reach the RIB"
        );
    }
    assert!(
        announced[0]
            .attributes
            .iter()
            .all(|attribute| attribute.type_code() != 24)
    );
    assert!(
        announced[0]
            .attributes
            .iter()
            .all(|attribute| attribute.type_code() != 42)
    );
    let delivered = announced[0].clone();
    session.send_route_update(OutboundRouteUpdate {
        exact_export_snapshot: Some(session.publish_export_profile()),
        announce: vec![delivered].into(),
        next_hop_override: vec![None].into(),
        ..empty_outbound_update()
    });
    let Message::Update(egress) = read_single_bgp_message(&mut server).await else {
        panic!("expected outbound UPDATE");
    };
    let parsed = egress.parse(true, false, &[]).unwrap();
    for (code, value) in &values {
        let Some(PathAttribute::Unknown(raw)) = parsed
            .attributes
            .iter()
            .find(|attribute| attribute.type_code() == *code)
        else {
            panic!("assigned type {code} missing from outbound UPDATE");
        };
        assert_eq!(raw.flags, 0xe0, "assigned type {code} missing Partial");
        assert_eq!(raw.data.as_ref(), value);
    }
    assert!(
        parsed
            .attributes
            .iter()
            .all(|attribute| attribute.type_code() != 42)
    );
    assert_eq!(session.fsm.state(), SessionState::Established);
}

#[tokio::test]
async fn malformed_community_container_withdraws_dual_stack_replacements() {
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    let (client, _server) = connected_stream_pair().await;
    session.test_install_stream(client);
    establish_test_session(&mut session, 65002).await;
    install_dual_stack_session(&mut session, false);
    rfc7606_drain(&mut rib_rx);
    let ipv4 = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 0), 24);
    let ipv6 = Ipv6Prefix::new("2001:db8::".parse().unwrap(), 32);
    let ipv6_nlri = [32, 0x20, 0x01, 0x0d, 0xb8];

    session
        .process_update(rfc7606_update(rfc7606_attr_bytes(&[]), &[ipv4]))
        .await;
    session
        .process_update(rfc7606_update(
            rfc7606_attr_bytes(&rfc7606_mp_reach(&ipv6_nlri)),
            &[],
        ))
        .await;
    for expected in [Prefix::V4(ipv4), Prefix::V6(ipv6)] {
        let RibUpdate::RoutesReceived { announced, .. } =
            rib_rx.try_recv().expect("initial route must reach RIB")
        else {
            panic!("expected initial route");
        };
        assert_eq!(announced.len(), 1);
        assert_eq!(announced[0].prefix, expected);
    }

    let mut replacement = vec![0xc0, 34, 5, 0, 1, 0, 0, 0];
    replacement.extend(rfc7606_mp_reach(&ipv6_nlri));
    session
        .process_update(rfc7606_update(rfc7606_attr_bytes(&replacement), &[ipv4]))
        .await;
    let RibUpdate::RoutesReceived {
        announced,
        withdrawn,
        ..
    } = rib_rx
        .try_recv()
        .expect("replacement withdrawals must reach RIB")
    else {
        panic!("expected replacement withdrawals");
    };
    assert!(announced.is_empty(), "malformed attribute must stay absent");
    assert_eq!(withdrawn.len(), 2);
    assert!(withdrawn.contains(&(Prefix::V4(ipv4), 0)));
    assert!(withdrawn.contains(&(Prefix::V6(ipv6), 0)));
    assert!(rib_rx.try_recv().is_err());
    assert_eq!(session.known_prefix_count(), 0);
    assert_eq!(session.fsm.state(), SessionState::Established);
    assert_single_malformed_disposition(&session, "treat_as_withdraw");
}

#[tokio::test]
async fn traffic_engineering_transitive_conflict_withdraws_route_and_keeps_session() {
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    let (client, _server) = connected_stream_pair().await;
    session.test_install_stream(client);
    establish_test_session(&mut session, 65002).await;
    rfc7606_drain(&mut rib_rx);
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 24), 32);
    session
        .process_update(rfc7606_update(rfc7606_attr_bytes(&[]), &[prefix]))
        .await;
    let _ = rib_rx.try_recv().expect("initial route");

    session
        .process_update(rfc7606_update(
            rfc7606_attr_bytes(&[0xc0, 24, 1, 0xaa]),
            &[prefix],
        ))
        .await;
    let RibUpdate::RoutesReceived {
        announced,
        withdrawn,
        ..
    } = rib_rx.try_recv().expect("treat-as-withdraw update")
    else {
        panic!("expected route withdrawal");
    };
    assert!(announced.is_empty());
    assert_eq!(withdrawn, vec![(Prefix::V4(prefix), 0)]);
    assert_eq!(session.known_prefix_count(), 0);
    assert_eq!(session.fsm.state(), SessionState::Established);
    assert_single_malformed_disposition(&session, "treat_as_withdraw");
}

#[tokio::test]
async fn malformed_ipv6_specific_community_withdraws_route_and_keeps_session() {
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    let (client, _server) = connected_stream_pair().await;
    session.test_install_stream(client);
    establish_test_session(&mut session, 65002).await;
    rfc7606_drain(&mut rib_rx);
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 25), 32);
    session
        .process_update(rfc7606_update(rfc7606_attr_bytes(&[]), &[prefix]))
        .await;
    let _ = rib_rx.try_recv().expect("initial route");

    let mut malformed = vec![0xc0, 25, 19];
    malformed.extend([0xaa; 19]);
    session
        .process_update(rfc7606_update(rfc7606_attr_bytes(&malformed), &[prefix]))
        .await;
    let RibUpdate::RoutesReceived {
        announced,
        withdrawn,
        ..
    } = rib_rx.try_recv().expect("treat-as-withdraw update")
    else {
        panic!("expected route withdrawal");
    };
    assert!(announced.is_empty());
    assert_eq!(withdrawn, vec![(Prefix::V4(prefix), 0)]);
    assert_eq!(session.known_prefix_count(), 0);
    assert_eq!(session.fsm.state(), SessionState::Established);
    assert_single_malformed_disposition(&session, "treat_as_withdraw");
}

#[tokio::test]
async fn malformed_domain_path_withdraws_route_and_keeps_session() {
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    let (client, _server) = connected_stream_pair().await;
    session.test_install_stream(client);
    establish_test_session(&mut session, 65002).await;
    rfc7606_drain(&mut rib_rx);
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 36), 32);
    session
        .process_update(rfc7606_update(rfc7606_attr_bytes(&[]), &[prefix]))
        .await;
    let _ = rib_rx.try_recv().expect("initial route");

    session
        .process_update(rfc7606_update(
            rfc7606_attr_bytes(&[0xc0, 36, 8, 0, 0, 0, 0, 0, 0, 0, 0]),
            &[prefix],
        ))
        .await;
    let RibUpdate::RoutesReceived {
        announced,
        withdrawn,
        ..
    } = rib_rx.try_recv().expect("treat-as-withdraw update")
    else {
        panic!("expected route withdrawal");
    };
    assert!(announced.is_empty());
    assert_eq!(withdrawn, vec![(Prefix::V4(prefix), 0)]);
    assert_eq!(session.fsm.state(), SessionState::Established);
    assert_single_malformed_disposition(&session, "treat_as_withdraw");
}

#[tokio::test]
async fn malformed_bfd_discriminator_discards_attribute_and_keeps_route() {
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    let (client, _server) = connected_stream_pair().await;
    session.test_install_stream(client);
    establish_test_session(&mut session, 65002).await;
    rfc7606_drain(&mut rib_rx);
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 38), 32);
    let malformed = [0xc0, 38, 11, 1, 0, 0, 0, 1, 2, 4, 0, 0, 0, 0];
    session
        .process_update(rfc7606_update(rfc7606_attr_bytes(&malformed), &[prefix]))
        .await;
    let RibUpdate::RoutesReceived { announced, .. } =
        rib_rx.try_recv().expect("attribute-discard announcement")
    else {
        panic!("expected retained route");
    };
    assert_eq!(announced.len(), 1);
    assert!(
        announced[0]
            .attributes
            .iter()
            .all(|attribute| attribute.type_code() != 38)
    );
    assert_eq!(session.fsm.state(), SessionState::Established);
    assert_single_malformed_disposition(&session, "attribute_discard");
}

#[tokio::test]
async fn empty_bier_attribute_is_discarded_and_keeps_route_and_session() {
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    let (client, _server) = connected_stream_pair().await;
    session.test_install_stream(client);
    establish_test_session(&mut session, 65002).await;
    rfc7606_drain(&mut rib_rx);
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 41), 32);
    session
        .process_update(rfc7606_update(
            rfc7606_attr_bytes(&[0xc0, 41, 0]),
            &[prefix],
        ))
        .await;

    let RibUpdate::RoutesReceived { announced, .. } =
        rib_rx.try_recv().expect("attribute-discard announcement")
    else {
        panic!("expected retained route");
    };
    assert_eq!(announced.len(), 1);
    assert_eq!(announced[0].prefix, Prefix::V4(prefix));
    assert!(
        announced[0]
            .attributes
            .iter()
            .all(|attribute| attribute.type_code() != 41)
    );
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
    let (client, mut server) = connected_stream_pair().await;
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
    let notification = read_until_notification(&mut server).await;
    assert_eq!(
        notification.code,
        rustbgpd_wire::notification::NotificationCode::UpdateMessage
    );
    assert_eq!(
        notification.subcode,
        rustbgpd_wire::notification::update_subcode::ATTRIBUTE_LENGTH_ERROR
    );
    assert_eq!(
        notification.data.as_ref(),
        &[0x80, 14, 2, 0, 1],
        "complete undersized MP value must be returned exactly"
    );
}

/// RFC 7606 §§3(j), 4, 5.3: a visible MP attribute whose declared value
/// overruns Total Path Attribute Length cannot expose reliably parsed MP NLRI.
/// Body NLRI is deliberately present so the independent §5.2 no-reachable-NLRI
/// escalation cannot make this test pass.
#[tokio::test]
async fn rfc7606_mp_attribute_value_overrun_sends_optional_attribute_error() {
    for type_code in [14, 15] {
        let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
        let (client, mut server) = connected_stream_pair().await;
        session.test_install_stream(client);
        establish_test_session(&mut session, 65002).await;
        rfc7606_drain(&mut rib_rx);
        let prefix = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24);
        let malformed_mp = [0x80, type_code, 8, 0, 2, 1];

        session
            .process_update(rfc7606_update(rfc7606_attr_bytes(&malformed_mp), &[prefix]))
            .await;

        assert_ne!(
            session.fsm.state(),
            SessionState::Established,
            "type {type_code}: MP framing overrun must reset even with body NLRI present"
        );
        while let Ok(message) = rib_rx.try_recv() {
            assert!(
                !matches!(message, RibUpdate::RoutesReceived { .. }),
                "type {type_code}: no route may reach the RIB"
            );
        }
        assert_single_malformed_disposition(&session, "session_reset");

        let notification = read_until_notification(&mut server).await;
        assert_eq!(
            notification.code,
            rustbgpd_wire::notification::NotificationCode::UpdateMessage,
            "type {type_code}"
        );
        assert_eq!(
            notification.subcode,
            rustbgpd_wire::notification::update_subcode::OPTIONAL_ATTRIBUTE_ERROR,
            "type {type_code}"
        );
        assert_eq!(
            notification.data.as_ref(),
            malformed_mp,
            "type {type_code}: NOTIFICATION data must be the exact received attribute bytes"
        );
    }
}

/// RFC 4760 §§3-4 and RFC 7606 §5.3: MP attributes are optional
/// non-transitive and therefore cannot carry Partial. Compact and Extended
/// Length examples exercise the same live session-reset and exact 3/4
/// NOTIFICATION contract; body NLRI prevents a §5.2-only pass.
#[tokio::test]
async fn rfc7606_mp_partial_flag_resets_with_exact_attribute_flags_error() {
    let cases = [
        (14, false, &[0, 1, Safi::FlowSpec as u8, 0, 0][..]),
        (14, true, &[0, 1, Safi::FlowSpec as u8, 0, 0][..]),
        (15, false, &[0, 2, Safi::Unicast as u8][..]),
        (15, true, &[0, 2, Safi::Unicast as u8][..]),
    ];
    for (type_code, extended, value) in cases {
        let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
        let (client, mut server) = connected_stream_pair().await;
        session.test_install_stream(client);
        establish_test_session(&mut session, 65002).await;
        rfc7606_drain(&mut rib_rx);
        let prefix = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24);
        let mut malformed_mp = vec![0x80 | 0x20 | if extended { 0x10 } else { 0 }, type_code];
        if extended {
            malformed_mp.extend_from_slice(&u16::try_from(value.len()).unwrap().to_be_bytes());
        } else {
            malformed_mp.push(u8::try_from(value.len()).unwrap());
        }
        malformed_mp.extend_from_slice(value);

        session
            .process_update(rfc7606_update(rfc7606_attr_bytes(&malformed_mp), &[prefix]))
            .await;

        assert_ne!(
            session.fsm.state(),
            SessionState::Established,
            "type {type_code}, extended={extended}: Partial must reset the session"
        );
        while let Ok(message) = rib_rx.try_recv() {
            assert!(
                !matches!(message, RibUpdate::RoutesReceived { .. }),
                "type {type_code}, extended={extended}: no route may reach the RIB"
            );
        }
        assert_single_malformed_disposition(&session, "session_reset");

        let notification = read_until_notification(&mut server).await;
        assert_eq!(
            notification.code,
            rustbgpd_wire::notification::NotificationCode::UpdateMessage,
            "type {type_code}, extended={extended}"
        );
        assert_eq!(
            notification.subcode,
            rustbgpd_wire::notification::update_subcode::ATTRIBUTE_FLAGS_ERROR,
            "type {type_code}, extended={extended}"
        );
        assert_eq!(
            notification.data.as_ref(),
            malformed_mp,
            "type {type_code}, extended={extended}: exact received attribute bytes"
        );
    }
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

/// RFC 7606 §7.11 reserves reset for MP syntax that prevents reliable NLRI
/// parsing. A structurally complete `MP_REACH` with an invalid unspecified
/// IPv6 next hop is instead treat-as-withdraw: the exact accepted replacement
/// is withdrawn, no announcement survives, and the live session stays up.
#[tokio::test]
async fn rfc7606_semantic_mp_next_hop_error_withdraws_without_reset() {
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    let (client, _server) = connected_stream_pair().await;
    session.test_install_stream(client);
    establish_test_session(&mut session, 65002).await;
    install_dual_stack_session(&mut session, false);
    rfc7606_drain(&mut rib_rx);
    let prefix = Ipv6Prefix::new("2001:db8::".parse().unwrap(), 32);
    let nlri = [32, 0x20, 0x01, 0x0d, 0xb8];

    session
        .process_update(rfc7606_update(
            rfc7606_attr_bytes(&rfc7606_mp_reach(&nlri)),
            &[],
        ))
        .await;
    let RibUpdate::RoutesReceived { announced, .. } = rib_rx
        .try_recv()
        .expect("valid IPv6 MP route must reach the RIB")
    else {
        panic!("expected RoutesReceived");
    };
    assert_eq!(announced.len(), 1);
    assert_eq!(announced[0].prefix, Prefix::V6(prefix));

    let mut invalid = rfc7606_mp_reach(&nlri);
    invalid[7..23].fill(0); // Preserve complete framing; replace NH with ::.
    session
        .process_update(rfc7606_update(rfc7606_attr_bytes(&invalid), &[]))
        .await;
    let RibUpdate::RoutesReceived {
        announced,
        withdrawn,
        ..
    } = rib_rx
        .try_recv()
        .expect("treat-as-withdraw must reach the RIB")
    else {
        panic!("expected RoutesReceived");
    };
    assert!(announced.is_empty());
    assert_eq!(withdrawn, vec![(Prefix::V6(prefix), 0)]);
    assert!(rib_rx.try_recv().is_err());
    assert_eq!(session.known_prefix_count(), 0);
    assert_eq!(session.fsm.state(), SessionState::Established);
    assert!(
        session.read_half.is_some(),
        "the live transport must stay up"
    );
    assert_single_malformed_disposition(&session, "treat_as_withdraw");
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
    let mut negotiated = session.negotiated.as_deref().unwrap().clone();
    negotiated
        .negotiated_families
        .push((Afi::L2Vpn, Safi::Evpn));
    session.negotiated = Some(Arc::new(negotiated));
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

/// RFC 7606 §5.4 / RFC 9136 §3: an unsupported EVPN route type is isolated,
/// while supported NLRIs in the same `MP_REACH` are delivered and the session
/// remains Established. The peer-scoped counter records the exact discard.
#[tokio::test]
async fn unsupported_evpn_route_type_is_observed_without_losing_supported_routes() {
    use rustbgpd_wire::{EthernetTagId, EvpnImet, EvpnRoute, RouteDistinguisher};

    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    let (client, _server) = connected_stream_pair().await;
    session.test_install_stream(client);
    establish_test_session(&mut session, 65002).await;
    let mut negotiated = session.negotiated.as_deref().unwrap().clone();
    negotiated
        .negotiated_families
        .push((Afi::L2Vpn, Safi::Evpn));
    session.negotiated = Some(Arc::new(negotiated));
    rfc7606_drain(&mut rib_rx);

    let route = EvpnRoute::Imet(EvpnImet {
        rd: RouteDistinguisher([0x00, 0x00, 0xFD, 0xE8, 0x00, 0x00, 0x00, 0x64]),
        ethernet_tag: EthernetTagId(100),
        originator_ip: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
    });
    let mut evpn_nlri = Vec::new();
    rustbgpd_wire::encode_evpn_nlri(std::slice::from_ref(&route), &mut evpn_nlri).unwrap();
    evpn_nlri.extend_from_slice(&[99, 2, 0xaa, 0xbb]);
    evpn_nlri.extend_from_slice(&[99, 0]);

    let mut mp_reach = vec![0, 25, 70, 4, 10, 0, 0, 2, 0];
    mp_reach.extend_from_slice(&evpn_nlri);
    let mut attributes = vec![0x40, 1, 1, 0];
    attributes.extend([0x40, 2, 6, 2, 1, 0, 0, 0xFD, 0xEA]);
    attributes.extend([0x80, 14, u8::try_from(mp_reach.len()).unwrap()]);
    attributes.extend(mp_reach);

    session
        .process_update(UpdateMessage {
            withdrawn_routes: Bytes::new(),
            path_attributes: Bytes::from(attributes),
            nlri: Bytes::new(),
        })
        .await;

    let RibUpdate::RoutesReceived { evpn_announced, .. } = rib_rx
        .try_recv()
        .expect("supported EVPN route must reach the RIB")
    else {
        panic!("expected RoutesReceived");
    };
    assert_eq!(evpn_announced.len(), 1);
    assert_eq!(evpn_announced[0].route, route);
    assert_eq!(session.fsm.state(), SessionState::Established);
    let samples = counter_samples(&session.metrics, "bgp_evpn_nlri_discarded_total");
    assert_eq!(
        samples,
        vec![(
            HashMap::from([("peer".to_string(), session.peer_label.clone())]),
            2.0
        )]
    );
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
    install_dual_stack_session(&mut session, false);
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

/// RFC 4724 §2 scopes MP End-of-RIB to an AFI/SAFI negotiated on the session.
/// The same valid empty IPv6 `MP_UNREACH` bytes must be ignored by an IPv4-only
/// session rather than mutating GR state or notifying the RIB.
#[tokio::test]
async fn mp_eor_for_unnegotiated_family_is_ignored() {
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    let (client, _server) = connected_stream_pair().await;
    session.test_install_stream(client);
    establish_test_session(&mut session, 65002).await;
    rfc7606_drain(&mut rib_rx);

    session
        .process_update(UpdateMessage {
            withdrawn_routes: Bytes::new(),
            path_attributes: Bytes::from_static(&[0x80, 15, 3, 0, 2, 1]),
            nlri: Bytes::new(),
        })
        .await;

    assert!(
        !session
            .received_eor_families
            .contains(&(Afi::Ipv6, Safi::Unicast)),
        "an unnegotiated family must not mutate received EoR state"
    );
    assert!(
        rib_rx.try_recv().is_err(),
        "an unnegotiated family must not emit EndOfRib"
    );
    assert_eq!(session.fsm.state(), SessionState::Established);
}

/// IPv4 unicast is negotiated by default, but RFC 8950 Extended Next Hop is
/// what makes its `MP_REACH` / `MP_UNREACH` wire form eligible. Without that
/// capability, an empty IPv4 `MP_UNREACH` must not become an MP `EoR`.
#[tokio::test]
async fn mp_eor_ipv4_without_extended_next_hop_is_ignored() {
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    let (client, _server) = connected_stream_pair().await;
    session.test_install_stream(client);
    establish_test_session(&mut session, 65002).await;
    rfc7606_drain(&mut rib_rx);

    session
        .process_update(UpdateMessage {
            withdrawn_routes: Bytes::new(),
            path_attributes: Bytes::from_static(&[0x80, 15, 3, 0, 1, 1]),
            nlri: Bytes::new(),
        })
        .await;

    assert!(
        !session
            .received_eor_families
            .contains(&(Afi::Ipv4, Safi::Unicast)),
        "ineligible IPv4 MP form must not mutate received EoR state"
    );
    assert!(
        rib_rx.try_recv().is_err(),
        "ineligible IPv4 MP form must not emit EndOfRib"
    );
    assert_eq!(session.fsm.state(), SessionState::Established);
}

/// RFC 8950 Extended Next Hop makes IPv4-unicast MP route encoding eligible,
/// but does not amend RFC 4724's classic empty-UPDATE End-of-RIB marker.
#[tokio::test]
async fn mp_eor_ipv4_with_extended_next_hop_is_ignored() {
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    let (client, _server) = connected_stream_pair().await;
    session.test_install_stream(client);
    establish_test_session(&mut session, 65002).await;
    install_test_negotiated_session(&mut session, negotiated_session(65002, true));
    rfc7606_drain(&mut rib_rx);

    session
        .process_update(UpdateMessage {
            withdrawn_routes: Bytes::new(),
            path_attributes: Bytes::from_static(&[0x80, 15, 3, 0, 1, 1]),
            nlri: Bytes::new(),
        })
        .await;

    assert!(
        !session
            .received_eor_families
            .contains(&(Afi::Ipv4, Safi::Unicast)),
        "Extended Next Hop must not change IPv4's EoR marker"
    );
    assert!(
        rib_rx.try_recv().is_err(),
        "IPv4 MP_UNREACH must not emit EndOfRib even with Extended Next Hop"
    );
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
