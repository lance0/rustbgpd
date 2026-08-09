use super::*;

/// A route-bearing envelope is valid only when the RIB attaches the concrete
/// snapshot used by precommit. Missing snapshots, foreign concrete types, and
/// same-type snapshots owned by another session are invariant breaches, so all
/// take the established Cease/8 teardown path rather than letting logical
/// Adj-RIB-Out get ahead of the wire.
#[tokio::test]
async fn route_bearing_envelope_without_own_session_snapshot_fails_closed() {
    use rustbgpd_wire::notification::{NotificationCode, cease_subcode};

    type SnapshotFailureCase = (
        &'static str,
        Option<Arc<dyn rustbgpd_rib::ExactExportSnapshot>>,
        crate::handle::SessionFailureCause,
    );

    let (other_session, _other_rib_rx) = make_test_session_with_rib(65001, 65002);
    let cases: Vec<SnapshotFailureCase> = vec![
        (
            "missing",
            None,
            crate::handle::SessionFailureCause::ExportSnapshotMissing,
        ),
        (
            "foreign concrete type",
            Some(Arc::new(ForeignExactExportSnapshot)),
            crate::handle::SessionFailureCause::ExportSnapshotIncompatible,
        ),
        (
            "same concrete type from another session",
            Some(other_session.publish_export_profile()),
            crate::handle::SessionFailureCause::ExportSnapshotWrongOwner,
        ),
    ];
    for (name, snapshot, cause) in cases {
        let (mut session, _rib_rx) = make_test_session_with_rib(65001, 65002);
        let (client, mut server) = connected_stream_pair().await;
        session.test_install_stream(client);
        let mut update = empty_outbound_update();
        update.exact_export_snapshot = snapshot;
        update.announce = vec![make_route(100)].into();
        update.next_hop_override = vec![None].into();

        session.send_route_update(update);

        let Message::Notification(notification) = read_single_bgp_message(&mut server).await else {
            panic!("{name}: expected Cease notification");
        };
        assert_eq!(notification.code, NotificationCode::Cease);
        assert_eq!(notification.subcode, cease_subcode::OUT_OF_RESOURCES);
        assert_eq!(
            session.pending_outbound_teardown_cause,
            Some(cause),
            "{name}"
        );
        assert_eq!(session.last_error, cause.to_string(), "{name}");
        assert!(session.read_half.is_none(), "{name}: read half must close");
        assert!(
            session.writer_bulk_tx.is_none(),
            "{name}: bulk sender must close"
        );
    }
}

/// LAN-380: the high-level exact probe must be byte-identical to the real
/// `OutboundRouteUpdate -> send_route_update -> writer -> TCP` path. This is
/// intentionally a socket receipt rather than a probe-vs-builder unit test:
/// it catches drift in grouping, next-hop selection, withdrawal-key rebuild,
/// Add-Path, ENHE, and the profile generation held by one envelope.
#[expect(
    clippy::too_many_lines,
    reason = "one matrix pins every outbound subfamily and both directions against real writer bytes"
)]
#[expect(
    clippy::items_after_statements,
    reason = "local helper and macros keep the full wire matrix readable"
)]
#[tokio::test]
async fn exact_export_probe_matches_real_writer_for_every_family_and_limit() {
    for extended_messages in [false, true] {
        for extended_nexthop in [false, true] {
            let (mut session, _rib_rx) = make_test_session_with_rib(65_001, 65_002);
            let (client, mut server) = connected_stream_pair().await;
            session.test_install_stream(client);
            session.config.local_ipv6_nexthop = Some("2001:db8::1".parse().unwrap());

            let families = vec![
                (Afi::Ipv4, Safi::Unicast),
                (Afi::Ipv6, Safi::Unicast),
                (Afi::Ipv4, Safi::FlowSpec),
                (Afi::Ipv6, Safi::FlowSpec),
                (Afi::L2Vpn, Safi::Evpn),
                (Afi::BgpLs, Safi::BgpLs),
                (Afi::BgpLs, Safi::BgpLsVpn),
                (Afi::Ipv4, Safi::MplsVpn),
                (Afi::Ipv6, Safi::MplsVpn),
                (Afi::Ipv4, Safi::LabeledUnicast),
                (Afi::Ipv6, Safi::LabeledUnicast),
                (Afi::Ipv4, Safi::RtConstrain),
            ];
            let mut negotiated = negotiated_session(65_002, extended_nexthop);
            negotiated.peer_extended_message = extended_messages;
            negotiated.negotiated_families.clone_from(&families);
            for family in [
                (Afi::Ipv4, Safi::Unicast),
                (Afi::Ipv6, Safi::Unicast),
                (Afi::Ipv4, Safi::MplsVpn),
                (Afi::Ipv6, Safi::MplsVpn),
                (Afi::Ipv4, Safi::LabeledUnicast),
                (Afi::Ipv6, Safi::LabeledUnicast),
            ] {
                negotiated
                    .add_path_families
                    .insert(family, AddPathMode::Send);
            }
            install_test_negotiated_session(&mut session, negotiated);
            let held = session.publish_export_profile();
            assert_eq!(
                held.max_message_len(),
                if extended_messages { 65_535 } else { 4_096 }
            );
            let held_generation = held.generation();

            let mut v4 = make_route(100);
            v4.path_id = 101;
            let mut v6 = make_v6_unicast_route("2001:db8:ffff::1".parse().unwrap());
            v6.path_id = 102;

            let fs_v4 = make_flowspec_route();
            let mut fs_v6 = make_flowspec_route();
            fs_v6.afi = Afi::Ipv6;
            fs_v6.rule = FlowSpecRule {
                components: vec![FlowSpecComponent::DestinationPrefix(FlowSpecPrefix::V6(
                    Ipv6PrefixOffset {
                        prefix: Ipv6Prefix::new("2001:db8:100::".parse().unwrap(), 64),
                        offset: 0,
                    },
                ))],
            };

            let evpn = rustbgpd_rib::EvpnRibRoute {
                route: EvpnRoute::MacIp(rustbgpd_wire::EvpnMacIp {
                    rd: RouteDistinguisher([0, 0, 0xfd, 0xe8, 0, 0, 0, 100]),
                    esi: rustbgpd_wire::EthernetSegmentIdentifier::ZERO,
                    ethernet_tag: rustbgpd_wire::EthernetTagId(100),
                    mac: rustbgpd_wire::MacAddress([0x02, 0, 0, 0xaa, 0xbb, 0xcc]),
                    ip: Some(IpAddr::V6("2001:db8::10".parse().unwrap())),
                    label1: rustbgpd_wire::MplsLabel::new(10_000),
                    label2: None,
                }),
                next_hop: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7)),
                link_local_next_hop: None,
                peer: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
                attributes: Arc::new(vec![
                    PathAttribute::Origin(Origin::Igp),
                    PathAttribute::AsPath(AsPath {
                        segments: vec![AsPathSegment::AsSequence(vec![65_002])],
                    }),
                ]),
                received_at: Instant::now(),
                origin_type: rustbgpd_rib::RouteOrigin::Ebgp,
                peer_router_id: Ipv4Addr::new(10, 0, 0, 2),
                is_stale: false,
                is_llgr_stale: false,
            };

            let bgpls = make_bgpls_route(0xcc);
            let mut bgpls_vpn = make_bgpls_route(0xdd);
            bgpls_vpn.family = rustbgpd_rib::BgpLsFamily::LinkStateVpn;
            bgpls_vpn.nlri.route_distinguisher = Some([0, 0, 0xfd, 0xe8, 0, 0, 0, 2]);

            let mut vpn_v4 = make_vpn_rib_route(20_000);
            vpn_v4.path_id = 103;
            let mut vpn_v6 = make_vpn_rib_route(20_001);
            vpn_v6.path_id = 104;
            vpn_v6.nlri.prefix = VpnPrefix::v6("2001:db8:200::".parse().unwrap(), 64).unwrap();
            vpn_v6.next_hop = IpAddr::V6("2001:db8::20".parse().unwrap());
            vpn_v6.link_local_next_hop = Some("fe80::20".parse().unwrap());

            let mut labeled_v4 = make_labeled_rib_route(20_002);
            labeled_v4.path_id = 105;
            let mut labeled_v6 = make_labeled_rib_route(20_003);
            labeled_v6.path_id = 106;
            labeled_v6.nlri.prefix =
                Prefix::V6(Ipv6Prefix::new("2001:db8:300::".parse().unwrap(), 64));
            labeled_v6.next_hop = IpAddr::V6("2001:db8::30".parse().unwrap());
            labeled_v6.link_local_next_hop = Some("fe80::30".parse().unwrap());

            let rtc = make_rtc_rib_route(100);

            assert_eq!(
                matches!(
                    held.prepare_unicast_candidate(&v4, None).unwrap(),
                    super::export::PreparedUnicastCandidate::Mp { .. }
                ),
                extended_nexthop,
                "matrix must exercise both IPv4 body and IPv4-over-IPv6 ENHE"
            );

            async fn assert_frame(
                session: &mut PeerSession,
                server: &mut TcpStream,
                probe: super::export::ExactExportProbe,
                mut update: OutboundRouteUpdate,
                generation: u64,
            ) {
                assert_eq!(probe.generation, generation);
                let expected = rustbgpd_wire::encode_message(&Message::Update(probe.message))
                    .unwrap()
                    .to_vec();
                update.exact_export_snapshot = Some(session.export_encoder.snapshot());
                session.send_route_update(update);
                let actual = read_single_raw_bgp_message(server).await;
                assert_eq!(actual, expected);
                assert_eq!(session.export_encoder.snapshot().generation(), generation);
            }

            macro_rules! announce {
                ($candidate:expr, $field:ident, $route:expr) => {{
                    let probe = held.probe_announcement($candidate).unwrap();
                    let mut update = empty_outbound_update();
                    update.$field = vec![$route.clone()];
                    assert_frame(&mut session, &mut server, probe, update, held_generation).await;
                }};
            }
            macro_rules! withdraw {
                ($withdrawal:expr, $field:ident, $key:expr) => {{
                    let probe = held.probe_withdrawal($withdrawal).unwrap();
                    let mut update = empty_outbound_update();
                    update.$field = vec![$key.clone()];
                    assert_frame(&mut session, &mut server, probe, update, held_generation).await;
                }};
            }

            for route in [&v4, &v6] {
                let probe = held
                    .probe_announcement(ExportCandidate::Unicast {
                        route,
                        next_hop_override: None,
                    })
                    .unwrap();
                let mut update = empty_outbound_update();
                update.announce = vec![route.clone()].into();
                update.next_hop_override = vec![None].into();
                assert_frame(&mut session, &mut server, probe, update, held_generation).await;
            }
            announce!(ExportCandidate::FlowSpec(&fs_v4), flowspec_announce, fs_v4);
            announce!(ExportCandidate::FlowSpec(&fs_v6), flowspec_announce, fs_v6);
            announce!(ExportCandidate::Evpn(&evpn), evpn_announce, evpn);
            announce!(ExportCandidate::BgpLs(&bgpls), bgpls_announce, bgpls);
            announce!(
                ExportCandidate::BgpLs(&bgpls_vpn),
                bgpls_announce,
                bgpls_vpn
            );
            announce!(ExportCandidate::Vpn(&vpn_v4), vpn_announce, vpn_v4);
            announce!(ExportCandidate::Vpn(&vpn_v6), vpn_announce, vpn_v6);
            announce!(
                ExportCandidate::Labeled(&labeled_v4),
                labeled_announce,
                labeled_v4
            );
            announce!(
                ExportCandidate::Labeled(&labeled_v6),
                labeled_announce,
                labeled_v6
            );
            announce!(ExportCandidate::Rtc(&rtc), rtc_announce, rtc);

            for route in [&v4, &v6] {
                let probe = held
                    .probe_withdrawal(ExportWithdrawal::Unicast {
                        prefix: route.prefix,
                        path_id: route.path_id,
                    })
                    .unwrap();
                let mut update = empty_outbound_update();
                update.withdraw = vec![(route.prefix, route.path_id)];
                assert_frame(&mut session, &mut server, probe, update, held_generation).await;
            }

            let fs_v4_key = fs_v4.selection_key();
            let fs_v6_key = fs_v6.selection_key();
            let evpn_key = evpn.route.key();
            let bgpls_key = bgpls.key();
            let bgpls_vpn_key = bgpls_vpn.key();
            let vpn_v4_key = vpn_v4.key();
            let vpn_v6_key = vpn_v6.key();
            let labeled_v4_key = labeled_v4.key();
            let labeled_v6_key = labeled_v6.key();
            let rtc_key = rtc.key();
            withdraw!(
                ExportWithdrawal::FlowSpec(&fs_v4_key),
                flowspec_withdraw,
                fs_v4_key
            );
            withdraw!(
                ExportWithdrawal::FlowSpec(&fs_v6_key),
                flowspec_withdraw,
                fs_v6_key
            );
            withdraw!(ExportWithdrawal::Evpn(&evpn_key), evpn_withdraw, evpn_key);
            withdraw!(
                ExportWithdrawal::BgpLs(&bgpls_key),
                bgpls_withdraw,
                bgpls_key
            );
            withdraw!(
                ExportWithdrawal::BgpLs(&bgpls_vpn_key),
                bgpls_withdraw,
                bgpls_vpn_key
            );
            withdraw!(ExportWithdrawal::Vpn(&vpn_v4_key), vpn_withdraw, vpn_v4_key);
            withdraw!(ExportWithdrawal::Vpn(&vpn_v6_key), vpn_withdraw, vpn_v6_key);
            withdraw!(
                ExportWithdrawal::Labeled(&labeled_v4_key),
                labeled_withdraw,
                labeled_v4_key
            );
            withdraw!(
                ExportWithdrawal::Labeled(&labeled_v6_key),
                labeled_withdraw,
                labeled_v6_key
            );
            withdraw!(ExportWithdrawal::Rtc(&rtc_key), rtc_withdraw, rtc_key);
        }
    }
}

#[tokio::test]
#[allow(
    clippy::items_after_statements,
    reason = "local async helpers keep the generation transition assertions compact"
)]
async fn export_profile_generation_changes_once_per_wire_runtime_mutation() {
    let mut session = make_test_session(65_001, 65_002);
    install_test_negotiated_session(&mut session, negotiated_session(65_002, false));
    let initial = session.publish_export_profile();
    let generation = initial.generation();

    async fn runtime_update(
        session: &mut PeerSession,
        local_ipv6_nexthop: Option<Ipv6Addr>,
        remove_private_as: RemovePrivateAs,
    ) {
        let (reply, done) = oneshot::channel();
        assert_eq!(
            session
                .handle_command(PeerCommand::UpdateRuntimeConfig {
                    max_prefixes: Some(123),
                    max_prefixes_ipv4: None,
                    max_prefixes_ipv6: None,
                    gr_stale_routes_time: 999,
                    gr_peer_restart_time_max: 333,
                    local_ipv6_nexthop,
                    remove_private_as,
                    reply,
                })
                .await,
            ControlFlow::Continue(())
        );
        done.await.unwrap().unwrap();
    }

    async fn gshut(session: &mut PeerSession, enabled: bool) {
        let (reply, done) = oneshot::channel();
        assert_eq!(
            session
                .handle_command(PeerCommand::UpdateGracefulShutdown { enabled, reply })
                .await,
            ControlFlow::Continue(())
        );
        done.await.unwrap().unwrap();
    }

    runtime_update(&mut session, None, RemovePrivateAs::Disabled).await;
    assert_eq!(
        session.config.gr_peer_restart_time_max, 333,
        "dropping the hot-apply assignment leaves the default 4095"
    );
    assert_eq!(
        session.export_encoder.snapshot().generation(),
        generation,
        "non-wire/equal runtime fields must not republish"
    );
    gshut(&mut session, false).await;
    assert_eq!(session.export_encoder.snapshot().generation(), generation);

    let local_v6 = Some("2001:db8::1".parse().unwrap());
    runtime_update(&mut session, local_v6, RemovePrivateAs::Disabled).await;
    assert_eq!(
        session.export_encoder.snapshot().generation(),
        generation + 1
    );
    runtime_update(&mut session, local_v6, RemovePrivateAs::Disabled).await;
    assert_eq!(
        session.export_encoder.snapshot().generation(),
        generation + 1
    );

    runtime_update(&mut session, local_v6, RemovePrivateAs::All).await;
    assert_eq!(
        session.export_encoder.snapshot().generation(),
        generation + 2
    );
    gshut(&mut session, true).await;
    assert_eq!(
        session.export_encoder.snapshot().generation(),
        generation + 3
    );
    gshut(&mut session, true).await;
    assert_eq!(
        session.export_encoder.snapshot().generation(),
        generation + 3
    );
}
