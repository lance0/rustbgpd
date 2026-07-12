use super::*;
use bytes::Bytes;
use rustbgpd_fsm::PeerConfig;
use rustbgpd_policy::{
    AsPathRegex, CommunityMatch, Policy, PolicyAction, PolicyChain, PolicyStatement,
    RouteModifications,
};
use rustbgpd_wire::{
    AddressPrefixOrf, AsPath, AsPathSegment, FlowSpecComponent, FlowSpecPrefix, FlowSpecRule,
    Ipv4NlriEntry, Ipv4Prefix, Ipv6Prefix, Ipv6PrefixOffset, LlgrFamily, Message, MplsLabelEntry,
    NumericMatch, OrfAction, OrfEntries, OrfEntryGroup, OrfMatch, OrfPayload, OrfType, Origin,
    PathAttribute, RouteDistinguisher, VpnNlri, VpnPrefix, WhenToRefresh,
    bgpls::{BgpLsNlri, BgpLsNlriType, decode_bgpls_nlri},
};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;
use tokio::sync::oneshot;
fn make_test_session(local_asn: u32, remote_asn: u32) -> PeerSession {
    let mut peer_config = PeerConfig::new(local_asn, remote_asn, Ipv4Addr::new(10, 0, 0, 1));
    peer_config.connect_retry_secs = 30;
    peer_config.families = vec![(Afi::Ipv4, Safi::Unicast)];
    peer_config.gr_restart_time = 120;
    let config = TransportConfig::new(peer_config, "10.0.0.2:179".parse().unwrap());
    let metrics = BgpMetrics::new();
    let (_cmd_tx, cmd_rx) = mpsc::channel(8);
    let (rib_tx, _rib_rx) = mpsc::channel(64);
    PeerSession::new(
        config, metrics, cmd_rx, rib_tx, None, None, None, None, None, false,
    )
}
fn make_test_session_with_rib(
    local_asn: u32,
    remote_asn: u32,
) -> (PeerSession, mpsc::Receiver<RibUpdate>) {
    let mut peer_config = PeerConfig::new(local_asn, remote_asn, Ipv4Addr::new(10, 0, 0, 1));
    peer_config.connect_retry_secs = 30;
    peer_config.families = vec![(Afi::Ipv4, Safi::Unicast)];
    peer_config.gr_restart_time = 120;
    let config = TransportConfig::new(peer_config, "10.0.0.2:179".parse().unwrap());
    let metrics = BgpMetrics::new();
    let (_cmd_tx, cmd_rx) = mpsc::channel(8);
    let (rib_tx, rib_rx) = mpsc::channel(64);
    (
        PeerSession::new(
            config, metrics, cmd_rx, rib_tx, None, None, None, None, None, false,
        ),
        rib_rx,
    )
}
fn make_test_session_with_rib_and_bmp(
    local_asn: u32,
    remote_asn: u32,
) -> (
    PeerSession,
    mpsc::Receiver<RibUpdate>,
    mpsc::Receiver<BmpEvent>,
) {
    let mut peer_config = PeerConfig::new(local_asn, remote_asn, Ipv4Addr::new(10, 0, 0, 1));
    peer_config.connect_retry_secs = 30;
    peer_config.families = vec![(Afi::Ipv4, Safi::Unicast)];
    peer_config.gr_restart_time = 120;
    let config = TransportConfig::new(peer_config, "10.0.0.2:179".parse().unwrap());
    let metrics = BgpMetrics::new();
    let (_cmd_tx, cmd_rx) = mpsc::channel(8);
    let (rib_tx, rib_rx) = mpsc::channel(64);
    let (bmp_tx, bmp_rx) = mpsc::channel(16);
    (
        PeerSession::new(
            config,
            metrics,
            cmd_rx,
            rib_tx,
            None,
            None,
            None,
            Some(bmp_tx),
            None,
            false,
        ),
        rib_rx,
        bmp_rx,
    )
}
fn negotiated_session(remote_asn: u32, extended_nexthop: bool) -> NegotiatedSession {
    let mut extended_nexthop_families = HashMap::new();
    if extended_nexthop {
        extended_nexthop_families.insert((Afi::Ipv4, Safi::Unicast), Afi::Ipv6);
    }
    let mut negotiated = NegotiatedSession::default();
    negotiated.peer_asn = remote_asn;
    negotiated.peer_router_id = Ipv4Addr::new(10, 0, 0, 2);
    negotiated.hold_time = 90;
    negotiated.keepalive_interval = 30;
    negotiated.four_octet_as = true;
    negotiated.negotiated_families = vec![(Afi::Ipv4, Safi::Unicast)];
    negotiated.extended_nexthop_families = extended_nexthop_families;
    negotiated
}
fn install_test_negotiated_session(session: &mut PeerSession, negotiated: NegotiatedSession) {
    session
        .negotiated_families
        .clone_from(&negotiated.negotiated_families);
    session.add_path_receive_families = negotiated
        .add_path_families
        .iter()
        .filter_map(|(family, mode)| {
            if matches!(mode, AddPathMode::Receive | AddPathMode::Both) {
                Some(*family)
            } else {
                None
            }
        })
        .collect();
    session.negotiated = Some(negotiated);
}
fn make_bgpls_route(payload_tag: u8) -> rustbgpd_rib::BgpLsRibRoute {
    let nlri = decode_bgpls_nlri(&[0xfd, 0xe8, 0, 3, 0xaa, 0xbb, payload_tag])
        .expect("fixture BGP-LS NLRI decodes")
        .pop()
        .expect("fixture contains one NLRI");
    rustbgpd_rib::BgpLsRibRoute {
        family: rustbgpd_rib::BgpLsFamily::LinkState,
        nlri,
        next_hop: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
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
    }
}
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
#[test]
fn aspa_validation_context_preserves_roleless_legacy_behavior() {
    let mut session = make_test_session(65001, 65002);
    session.negotiated = Some(negotiated_session(65099, false));
    let context = session.aspa_validation_context();
    assert_eq!(context.neighbor_asn, None);
    assert_eq!(context.local_role, None);
    assert!(!context.first_as_check_exempt);
}
fn configure_scoped_link_local_peer(session: &mut PeerSession) {
    session.peer_ip = IpAddr::V6("fe80::2".parse().unwrap());
    session.config.peer_interface = Some("eth1".to_string());
    session.config.peer_scope_id = Some(7);
    session.link_local_next_hop_scope =
        PeerSession::link_local_next_hop_scope_from_config(&session.config);
}
fn make_route(local_pref: u32) -> Route {
    Route {
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
            PathAttribute::LocalPref(local_pref),
        ]),
        received_at: Instant::now(),
        origin_type: rustbgpd_rib::RouteOrigin::Ebgp,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        is_stale: false,
        is_llgr_stale: false,
        path_id: 0,
        validation_state: rustbgpd_wire::RpkiValidation::NotFound,
        aspa_state: rustbgpd_wire::AspaValidation::Unknown,
        aspa_context: rustbgpd_wire::AspaValidationContext::default(),
    }
}
fn replace_route_attrs(route: &Route, attrs: Vec<PathAttribute>) -> Route {
    Route {
        attributes: Arc::new(attrs),
        ..route.clone()
    }
}
fn make_v6_unicast_route(next_hop: Ipv6Addr) -> Route {
    Route {
        prefix: Prefix::V6(Ipv6Prefix::new("2001:db8:1::".parse().unwrap(), 64)),
        next_hop: IpAddr::V6(next_hop),
        link_local_next_hop: None,
        next_hop_scope: None,
        peer: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        attributes: Arc::new(vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath {
                segments: vec![AsPathSegment::AsSequence(vec![65002])],
            }),
        ]),
        received_at: Instant::now(),
        origin_type: rustbgpd_rib::RouteOrigin::Ebgp,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        is_stale: false,
        is_llgr_stale: false,
        path_id: 0,
        validation_state: rustbgpd_wire::RpkiValidation::NotFound,
        aspa_state: rustbgpd_wire::AspaValidation::Unknown,
        aspa_context: rustbgpd_wire::AspaValidationContext::default(),
    }
}
fn make_flowspec_route() -> FlowSpecRoute {
    FlowSpecRoute {
        rule: FlowSpecRule {
            components: vec![FlowSpecComponent::DestinationPrefix(FlowSpecPrefix::V4(
                Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, 0), 24),
            ))],
        },
        afi: Afi::Ipv4,
        peer: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        attributes: vec![PathAttribute::Origin(Origin::Igp)],
        received_at: Instant::now(),
        origin_type: rustbgpd_rib::RouteOrigin::Ebgp,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        is_stale: false,
        is_llgr_stale: false,
        path_id: 0,
    }
}
async fn connected_stream_pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (client, server) = tokio::join!(TcpStream::connect(addr), listener.accept());
    (client.unwrap(), server.unwrap().0)
}
async fn establish_test_session(session: &mut PeerSession, remote_asn: u32) {
    session.drive_fsm(Event::ManualStart).await;
    session
        .drive_fsm(Event::OpenReceived(rustbgpd_wire::OpenMessage {
            version: 4,
            my_as: u16::try_from(remote_asn).unwrap_or(23_456),
            hold_time: 90,
            bgp_identifier: Ipv4Addr::new(10, 0, 0, 2),
            capabilities: vec![
                Capability::MultiProtocol {
                    afi: Afi::Ipv4,
                    safi: Safi::Unicast,
                },
                Capability::FourOctetAs { asn: remote_asn },
            ],
        }))
        .await;
    session.drive_fsm(Event::KeepaliveReceived).await;
    assert_eq!(session.fsm.state(), SessionState::Established);
}
async fn read_single_bgp_message(stream: &mut TcpStream) -> Message {
    let mut header = [0_u8; 19];
    stream.read_exact(&mut header).await.unwrap();
    let msg_len = usize::from(u16::from_be_bytes([header[16], header[17]]));
    let mut body = vec![0_u8; msg_len - header.len()];
    stream.read_exact(&mut body).await.unwrap();
    let mut raw = header.to_vec();
    raw.extend_from_slice(&body);
    let mut buf = Bytes::from(raw);
    rustbgpd_wire::decode_message(&mut buf, rustbgpd_wire::MAX_MESSAGE_LEN).unwrap()
}
#[tokio::test]
async fn shutdown_aborts_inflight_connect_task() {
    let mut session = make_test_session(65001, 65002);
    session.connect_task = Some(tokio::spawn(async {
        tokio::time::sleep(Duration::from_mins(1)).await;
        unreachable!("connect task should have been aborted by shutdown");
    }));
    assert_eq!(
        session.handle_command(PeerCommand::Shutdown).await,
        ControlFlow::Break(())
    );
    assert!(session.connect_task.is_none());
}
#[tokio::test]
async fn session_established_emits_bmp_peer_up() {
    let (mut session, _rib_rx, mut bmp_rx) = make_test_session_with_rib_and_bmp(65001, 65002);
    let (client, _server) = connected_stream_pair().await;
    session.test_install_stream(client);
    session.local_open_pdu = Some(Bytes::from_static(&[1, 2, 3]));
    session.remote_open_pdu = Some(Bytes::from_static(&[4, 5, 6]));
    session
        .execute_actions(vec![Action::SessionEstablished(Box::new(
            negotiated_session(65002, false),
        ))])
        .await;
    match bmp_rx.recv().await.unwrap() {
        BmpEvent::PeerUp {
            peer_info,
            local_open,
            remote_open,
            ..
        } => {
            assert_eq!(peer_info.peer_addr, session.peer_ip);
            assert_eq!(peer_info.peer_asn, 65002);
            assert_eq!(local_open.as_ref(), &[1, 2, 3]);
            assert_eq!(remote_open.as_ref(), &[4, 5, 6]);
        }
        other => panic!("expected BMP PeerUp, got {other:?}"),
    }
}
#[tokio::test]
async fn accept_any_session_established_uses_learned_asn_for_bmp_and_rib() {
    let (mut session, mut rib_rx, mut bmp_rx) = make_test_session_with_rib_and_bmp(65001, 0);
    let (client, _server) = connected_stream_pair().await;
    session.test_install_stream(client);
    session
        .execute_actions(vec![Action::SessionEstablished(Box::new(
            negotiated_session(65099, false),
        ))])
        .await;
    match bmp_rx.recv().await.unwrap() {
        BmpEvent::PeerUp { peer_info, .. } => {
            assert_eq!(peer_info.peer_asn, 65099);
        }
        other => panic!("expected BMP PeerUp, got {other:?}"),
    }
    match recv_peer_up_after_export_context(&mut rib_rx).await {
        RibUpdate::PeerUp { peer_asn, .. } => {
            assert_eq!(peer_asn, 65099);
        }
        _ => panic!("expected RIB PeerUp"),
    }
}
#[tokio::test]
async fn session_down_emits_bmp_peer_down() {
    let (mut session, _rib_rx, mut bmp_rx) = make_test_session_with_rib_and_bmp(65001, 65002);
    session.negotiated = Some(negotiated_session(65002, false));
    session.established_at = Some(Instant::now());
    session.last_down_reason = Some(PeerDownReason::RemoteNoNotification);
    session.execute_actions(vec![Action::SessionDown]).await;
    match bmp_rx.recv().await.unwrap() {
        BmpEvent::PeerDown { peer_info, reason } => {
            assert_eq!(peer_info.peer_addr, session.peer_ip);
            assert!(matches!(reason, PeerDownReason::RemoteNoNotification));
        }
        other => panic!("expected BMP PeerDown, got {other:?}"),
    }
}
#[tokio::test]
async fn inbound_update_emits_bmp_route_monitoring() {
    let (mut session, _rib_rx, mut bmp_rx) = make_test_session_with_rib_and_bmp(65001, 65002);
    session.negotiated = Some(negotiated_session(65002, false));
    session.negotiated_families = vec![(Afi::Ipv4, Safi::Unicast)];
    let update = rustbgpd_wire::UpdateMessage::build(
        &[Ipv4NlriEntry {
            path_id: 0,
            prefix: Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24),
        }],
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
        rustbgpd_wire::Ipv4UnicastMode::Body,
    );
    let encoded = rustbgpd_wire::encode_message(&Message::Update(update)).unwrap();
    session.read_buf.buf.extend_from_slice(&encoded);
    session.process_read_buffer().await;
    match bmp_rx.recv().await.unwrap() {
        BmpEvent::RouteMonitoring {
            peer_info,
            update_pdu,
        } => {
            assert_eq!(peer_info.peer_addr, session.peer_ip);
            assert_eq!(update_pdu.as_ref(), encoded.as_ref());
        }
        other => panic!("expected BMP RouteMonitoring, got {other:?}"),
    }
}

/// RFC 4271 §5.1.5 requires a received eBGP `LOCAL_PREF` to be ignored,
/// while RFC 7854 pre-policy BMP reports the unprocessed wire UPDATE. Pin
/// both sides of that boundary together: the RIB route loses the attribute,
/// but BMP retains the byte-exact PDU that carried it.
#[tokio::test]
async fn ebgp_local_pref_is_ignored_after_pre_policy_bmp_tap() {
    let (mut session, mut rib_rx, mut bmp_rx) = make_test_session_with_rib_and_bmp(65001, 65002);
    session.negotiated = Some(negotiated_session(65002, false));
    session.negotiated_families = vec![(Afi::Ipv4, Safi::Unicast)];
    let update = UpdateMessage::build(
        &[Ipv4NlriEntry {
            path_id: 0,
            prefix: Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24),
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
    let encoded = rustbgpd_wire::encode_message(&Message::Update(update)).unwrap();
    session.read_buf.buf.extend_from_slice(&encoded);
    session.process_read_buffer().await;

    let RibUpdate::RoutesReceived { announced, .. } = rib_rx.try_recv().unwrap() else {
        panic!("expected RoutesReceived");
    };
    assert_eq!(announced.len(), 1);
    assert_eq!(
        announced[0].local_pref_attr(),
        None,
        "peer-supplied eBGP LOCAL_PREF must not reach the RIB"
    );
    match bmp_rx.recv().await.unwrap() {
        BmpEvent::RouteMonitoring { update_pdu, .. } => {
            assert_eq!(
                update_pdu.as_ref(),
                encoded.as_ref(),
                "pre-policy BMP must preserve the original wire LOCAL_PREF"
            );
        }
        other => panic!("expected BMP RouteMonitoring, got {other:?}"),
    }
}
/// Inbound EVPN UPDATE → BMP `RouteMonitoring` with byte-equal `update_pdu`.
///
/// The BMP emit site at `crates/transport/src/session/io.rs` has no AFI/SAFI
/// filter — every UPDATE flows to the collector with the raw wire bytes.
/// This regression test locks that behavior in: it negotiates L2VPN/EVPN,
/// pushes a Type 2 (MAC/IP) `MP_REACH_NLRI` UPDATE, and asserts that the
/// `BmpEvent::RouteMonitoring` carries the original encoded bytes
/// unchanged. A future refactor that quietly added a unicast-only family
/// gate would fail this test.
#[tokio::test]
async fn inbound_evpn_update_emits_bmp_route_monitoring() {
    use rustbgpd_wire::attribute::MpReachNlri;
    use rustbgpd_wire::{
        EthernetSegmentIdentifier, EthernetTagId, EvpnMacIp, EvpnRoute, MacAddress, MplsLabel,
        RouteDistinguisher,
    };
    let (mut session, _rib_rx, mut bmp_rx) = make_test_session_with_rib_and_bmp(65001, 65002);
    session.negotiated = Some(negotiated_session(65002, false));
    session.negotiated_families = vec![(Afi::L2Vpn, Safi::Evpn)];
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
            evpn_announced: vec![evpn_route],
            bgpls_announced: vec![],
            labeled_announced: vec![],
            vpn_announced: vec![],
            rtc_announced: vec![],
        }),
    ];
    let update = rustbgpd_wire::UpdateMessage::build(
        &[],
        &[],
        &attrs,
        true,
        false,
        rustbgpd_wire::Ipv4UnicastMode::Body,
    );
    let encoded = rustbgpd_wire::encode_message(&Message::Update(update)).unwrap();
    session.read_buf.buf.extend_from_slice(&encoded);
    session.process_read_buffer().await;
    match bmp_rx.recv().await.unwrap() {
        BmpEvent::RouteMonitoring {
            peer_info,
            update_pdu,
        } => {
            assert_eq!(peer_info.peer_addr, session.peer_ip);
            assert_eq!(
                update_pdu.as_ref(),
                encoded.as_ref(),
                "BMP RouteMonitoring update_pdu must be byte-equal to the inbound \
                 EVPN UPDATE — collectors parse the inner MP_REACH_NLRI to \
                 discover AFI=25/SAFI=70"
            );
        }
        other => panic!("expected BMP RouteMonitoring, got {other:?}"),
    }
}
/// Read one raw BGP message (header + body bytes) off the wire without
/// decoding — for byte-exact comparison against BMP `update_pdu`.
async fn read_single_raw_bgp_message(stream: &mut TcpStream) -> Vec<u8> {
    let mut header = [0_u8; 19];
    stream.read_exact(&mut header).await.unwrap();
    let msg_len = usize::from(u16::from_be_bytes([header[16], header[17]]));
    let mut body = vec![0_u8; msg_len - header.len()];
    stream.read_exact(&mut body).await.unwrap();
    let mut raw = header.to_vec();
    raw.extend_from_slice(&body);
    raw
}

async fn recv_peer_up_after_export_context(rib_rx: &mut mpsc::Receiver<RibUpdate>) -> RibUpdate {
    assert!(matches!(
        rib_rx.recv().await.unwrap(),
        RibUpdate::SetPeerExportContext { .. }
    ));
    rib_rx.recv().await.unwrap()
}
/// All-empty `OutboundRouteUpdate` for the rib-out BMP tap tests.
fn empty_outbound_update() -> OutboundRouteUpdate {
    OutboundRouteUpdate {
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
        labeled_withdraw: vec![],
        rtc_withdraw: vec![],
        request_refresh_all_negotiated: false,
    }
}
/// Expect the next BMP event to be a rib-out `RouteMonitoring` and
/// return its PDU bytes, asserting the RFC 8671 marking.
fn expect_rib_out_rm(event: BmpEvent) -> Bytes {
    match event {
        BmpEvent::RouteMonitoring {
            peer_info,
            update_pdu,
        } => {
            assert!(peer_info.is_rib_out, "O flag marking (Adj-RIB-Out)");
            assert!(peer_info.is_post_policy, "L flag marking (post-policy)");
            update_pdu
        }
        other => panic!("expected BMP RouteMonitoring, got {other:?}"),
    }
}
/// Outbound UPDATE → RFC 8671 rib-out BMP `RouteMonitoring`, byte-exact
/// with what went on the wire, remote peer identity preserved.
#[tokio::test]
async fn outbound_update_emits_rib_out_bmp_route_monitoring() {
    let (mut session, _rib_rx, mut bmp_rx) = make_test_session_with_rib_and_bmp(65001, 65002);
    session.config.bmp_rib_out = true;
    let (client, mut server) = connected_stream_pair().await;
    session.test_install_stream(client);
    let negotiated = negotiated_session(65002, false);
    session
        .negotiated_families
        .clone_from(&negotiated.negotiated_families);
    session.negotiated = Some(negotiated);
    let mut update = empty_outbound_update();
    update.announce = vec![make_route(100)].into();
    update.next_hop_override = vec![None].into();
    session.send_route_update(update);
    let wire = read_single_raw_bgp_message(&mut server).await;
    let pdu = expect_rib_out_rm(bmp_rx.try_recv().unwrap());
    assert_eq!(
        pdu.as_ref(),
        &wire[..],
        "BMP rib-out PDU must be byte-exact with the transmitted UPDATE"
    );
}
/// Withdraws and End-of-RIB markers are UPDATEs through the same byte
/// funnel — both are tapped (`EoR` for free, no special-casing).
#[tokio::test]
async fn outbound_withdraw_and_eor_emit_rib_out_bmp() {
    let (mut session, _rib_rx, mut bmp_rx) = make_test_session_with_rib_and_bmp(65001, 65002);
    session.config.bmp_rib_out = true;
    let (client, mut server) = connected_stream_pair().await;
    session.test_install_stream(client);
    let negotiated = negotiated_session(65002, false);
    session
        .negotiated_families
        .clone_from(&negotiated.negotiated_families);
    session.negotiated = Some(negotiated);
    let mut update = empty_outbound_update();
    update.withdraw = vec![(
        Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24)),
        0,
    )];
    update.end_of_rib = vec![(Afi::Ipv4, Safi::Unicast)];
    session.send_route_update(update);
    // Wire order: withdraw UPDATE, then the 23-byte EoR UPDATE.
    let withdraw_wire = read_single_raw_bgp_message(&mut server).await;
    let eor_wire = read_single_raw_bgp_message(&mut server).await;
    assert_eq!(eor_wire.len(), 23, "IPv4 unicast EoR is the empty UPDATE");
    let withdraw_pdu = expect_rib_out_rm(bmp_rx.try_recv().unwrap());
    let eor_pdu = expect_rib_out_rm(bmp_rx.try_recv().unwrap());
    assert_eq!(withdraw_pdu.as_ref(), &withdraw_wire[..]);
    assert_eq!(eor_pdu.as_ref(), &eor_wire[..]);
}
/// The rib-out tap is off by default (`bmp_rib_out = false`), and even
/// when on it never taps non-UPDATE bulk traffic (ROUTE-REFRESH).
#[tokio::test]
async fn rib_out_tap_default_off_and_skips_non_update_messages() {
    let (mut session, _rib_rx, mut bmp_rx) = make_test_session_with_rib_and_bmp(65001, 65002);
    let (client, mut server) = connected_stream_pair().await;
    session.test_install_stream(client);
    let mut negotiated = negotiated_session(65002, false);
    negotiated.peer_route_refresh = true;
    session
        .negotiated_families
        .clone_from(&negotiated.negotiated_families);
    session.negotiated = Some(negotiated);
    // Default: bmp_rib_out is false — outbound UPDATE not tapped.
    let mut update = empty_outbound_update();
    update.announce = vec![make_route(100)].into();
    update.next_hop_override = vec![None].into();
    session.send_route_update(update);
    let _ = read_single_raw_bgp_message(&mut server).await;
    assert!(
        bmp_rx.try_recv().is_err(),
        "rib-out tap must be off unless a collector monitors rib_out_post"
    );
    // Enabled: ROUTE-REFRESH goes through the same bulk channel but is
    // not route monitoring.
    session.config.bmp_rib_out = true;
    let mut refresh = empty_outbound_update();
    refresh.request_refresh_all_negotiated = true;
    session.send_route_update(refresh);
    let _ = read_single_raw_bgp_message(&mut server).await;
    assert!(
        bmp_rx.try_recv().is_err(),
        "non-UPDATE bulk messages must not be tapped"
    );
}
/// Outbound `VPNv4` UPDATE (SAFI 128) → rib-out BMP, byte-exact — the tap
/// sits below the family senders so `RD/label/MP_REACH` encoding is
/// mirrored exactly as transmitted.
#[tokio::test]
async fn outbound_vpn_update_emits_rib_out_bmp_byte_exact() {
    let (mut session, _rib_rx, mut bmp_rx) = make_test_session_with_rib_and_bmp(65001, 65002);
    session.config.bmp_rib_out = true;
    let (client, mut server) = connected_stream_pair().await;
    session.test_install_stream(client);
    let mut negotiated = negotiated_session(65002, false);
    negotiated.negotiated_families = vec![(Afi::Ipv4, Safi::MplsVpn)];
    session
        .negotiated_families
        .clone_from(&negotiated.negotiated_families);
    session.negotiated = Some(negotiated);
    let mut update = empty_outbound_update();
    update.vpn_announce = vec![make_vpn_rib_route(4093)];
    session.send_route_update(update);
    let wire = read_single_raw_bgp_message(&mut server).await;
    let pdu = expect_rib_out_rm(bmp_rx.try_recv().unwrap());
    assert_eq!(pdu.as_ref(), &wire[..]);
}
/// Outbound EVPN UPDATE (AFI 25 / SAFI 70) → rib-out BMP, byte-exact.
#[tokio::test]
async fn outbound_evpn_update_emits_rib_out_bmp_byte_exact() {
    use rustbgpd_wire::{
        EthernetSegmentIdentifier, EthernetTagId, EvpnMacIp, EvpnRoute, MacAddress, MplsLabel,
        RouteDistinguisher,
    };
    let (mut session, _rib_rx, mut bmp_rx) = make_test_session_with_rib_and_bmp(65001, 65002);
    session.config.bmp_rib_out = true;
    let (client, mut server) = connected_stream_pair().await;
    session.test_install_stream(client);
    let mut negotiated = negotiated_session(65002, false);
    negotiated.negotiated_families = vec![(Afi::L2Vpn, Safi::Evpn)];
    session
        .negotiated_families
        .clone_from(&negotiated.negotiated_families);
    session.negotiated = Some(negotiated);
    let evpn_route = rustbgpd_rib::EvpnRibRoute {
        route: EvpnRoute::MacIp(EvpnMacIp {
            rd: RouteDistinguisher([0x00, 0x00, 0xFD, 0xE8, 0x00, 0x00, 0x00, 0x64]),
            esi: EthernetSegmentIdentifier::ZERO,
            ethernet_tag: EthernetTagId(0),
            mac: MacAddress([0xaa, 0xbb, 0xcc, 0x00, 0x00, 0x01]),
            ip: Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))),
            label1: MplsLabel::new(100),
            label2: None,
        }),
        next_hop: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7)),
        link_local_next_hop: None,
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
    };
    let mut update = empty_outbound_update();
    update.evpn_announce = vec![evpn_route];
    session.send_route_update(update);
    let wire = read_single_raw_bgp_message(&mut server).await;
    let pdu = expect_rib_out_rm(bmp_rx.try_recv().unwrap());
    assert_eq!(pdu.as_ref(), &wire[..]);
}
/// The rib-out tap keeps the non-blocking posture: a full BMP event
/// channel drops the event and bumps `bmp_source_drops_total` — it
/// never blocks or tears down the session. But the drop is no longer
/// silent: the UPDATE did reach the wire, so the session latches the
/// divergence for the forced peer-state reset (see
/// `bmp_channel_full_after_wire_send_forces_peer_state_reset`).
#[tokio::test]
async fn rib_out_tap_full_channel_increments_source_drop_counter() {
    let (mut session, _rib_rx, _bmp_rx) = make_test_session_with_rib_and_bmp(65001, 65002);
    session.config.bmp_rib_out = true;
    let (client, _server) = connected_stream_pair().await;
    session.test_install_stream(client);
    let negotiated = negotiated_session(65002, false);
    session
        .negotiated_families
        .clone_from(&negotiated.negotiated_families);
    session.negotiated = Some(negotiated);
    // The helper's BMP channel holds 16 events; never drain it. The
    // 17th tapped UPDATE hits Full and must count a source drop.
    for _ in 0..17 {
        let mut update = empty_outbound_update();
        update.announce = vec![make_route(100)].into();
        update.next_hop_override = vec![None].into();
        session.send_route_update(update);
    }
    let drops: u64 = session
        .metrics
        .registry()
        .gather()
        .iter()
        .filter(|f| f.name() == "bmp_source_drops_total")
        .flat_map(|f| f.metric.iter())
        .map(|m| {
            #[expect(
                clippy::cast_possible_truncation,
                clippy::cast_sign_loss,
                reason = "Prometheus counters are monotonic non-negative integers exposed as f64"
            )]
            let v = m.counter.value() as u64;
            v
        })
        .sum();
    assert_eq!(drops, 1, "17th event over a 16-deep channel drops once");
    assert!(
        session.writer_bulk_tx.is_some(),
        "a BMP-side drop must never tear down the BGP session"
    );
    assert!(
        session.bmp_stream_diverged,
        "a dropped rib-out RouteMonitoring must latch the divergence"
    );
    assert!(
        session.bmp_repair_timer.is_some(),
        "the bounded-latency repair timer must be armed"
    );
}
/// Outbound-writer saturation ordering: the UPDATE that failed to
/// enqueue is never mirrored to BMP (RFC 8671 mirrors what was actually
/// sent), and the saturation teardown ends in a BMP `PeerDown` ordered
/// after the last mirrored `RouteMonitoring` on the same channel — a
/// collector sees an explicit resync signal (discard peer state; the
/// re-established session re-floods), never a silent gap.
#[tokio::test]
async fn writer_saturation_orders_bmp_peer_down_after_last_mirrored_update() {
    let (mut session, _rib_rx, mut bmp_rx) = make_test_session_with_rib_and_bmp(65001, 65002);
    session.config.bmp_rib_out = true;
    let (client, _server) = connected_stream_pair().await;
    session.test_install_stream(client);
    establish_test_session(&mut session, 65002).await;
    match bmp_rx.try_recv().unwrap() {
        BmpEvent::PeerUp { .. } => {}
        other => panic!("expected BMP PeerUp, got {other:?}"),
    }
    // Swap in a capacity-1 bulk channel that is never drained: the
    // first UPDATE enqueues (and is mirrored), the second hits Full.
    let (bulk_tx, _bulk_rx) = mpsc::channel(1);
    session.writer_bulk_tx = Some(bulk_tx);
    for lp in [100, 200] {
        let mut update = empty_outbound_update();
        update.announce = vec![make_route(lp)].into();
        update.next_hop_override = vec![None].into();
        session.send_route_update(update);
    }
    assert!(
        session.writer_bulk_tx.is_none(),
        "bulk-channel Full must trigger the saturation teardown"
    );
    // Run-loop follow-through: the writer exit surfaces as a TCP
    // disconnect and drives the FSM out of Established.
    session.drive_fsm(Event::TcpConnectionFails).await;
    assert_ne!(session.fsm.state(), SessionState::Established);
    // BMP stream order: the mirrored UPDATE, then PeerDown. Nothing
    // for the UPDATE that never reached the wire.
    let _mirrored = expect_rib_out_rm(bmp_rx.try_recv().unwrap());
    match bmp_rx.try_recv().unwrap() {
        BmpEvent::PeerDown { reason, .. } => match reason {
            PeerDownReason::LocalNotification(pdu) => {
                // 19-byte header, then code 6 (Cease) / subcode 8
                // (Out of Resources).
                assert_eq!(&pdu[19..21], &[6, 8], "Cease/8 NOTIFICATION PDU");
            }
            other => panic!("expected reason 1 (local NOTIFICATION), got {other:?}"),
        },
        other => panic!("expected BMP PeerDown after the last mirrored RM, got {other:?}"),
    }
    assert!(
        bmp_rx.try_recv().is_err(),
        "no RouteMonitoring may be emitted for the UPDATE that never reached the wire"
    );
}
/// The inverse saturation case — the wire send succeeded but the BMP
/// channel was full: the divergence is repaired by forcing a synthetic
/// PeerDown/PeerUp pair (RFC 7854 peer-state reset) ahead of the next
/// emission, so collectors detect the reset instead of keeping a
/// silently incomplete Adj-RIB-Out view forever.
#[tokio::test]
async fn bmp_channel_full_after_wire_send_forces_peer_state_reset() {
    let (mut session, _rib_rx, mut bmp_rx) = make_test_session_with_rib_and_bmp(65001, 65002);
    session.config.bmp_rib_out = true;
    let (client, _server) = connected_stream_pair().await;
    session.test_install_stream(client);
    let negotiated = negotiated_session(65002, false);
    session
        .negotiated_families
        .clone_from(&negotiated.negotiated_families);
    session.negotiated = Some(negotiated);
    session.local_open_pdu = Some(Bytes::from_static(&[1, 2, 3]));
    session.remote_open_pdu = Some(Bytes::from_static(&[4, 5, 6]));
    // 16 mirrored UPDATEs fill the channel; the 17th reaches the wire
    // but its RouteMonitoring is dropped → divergence latched.
    for _ in 0..17 {
        let mut update = empty_outbound_update();
        update.announce = vec![make_route(100)].into();
        update.next_hop_override = vec![None].into();
        session.send_route_update(update);
    }
    assert!(session.bmp_stream_diverged);
    for _ in 0..16 {
        expect_rib_out_rm(bmp_rx.try_recv().unwrap());
    }
    // Next emission repairs the stream first: PeerDown, PeerUp, then
    // the new RouteMonitoring — in that order, on the same channel.
    let mut update = empty_outbound_update();
    update.announce = vec![make_route(300)].into();
    update.next_hop_override = vec![None].into();
    session.send_route_update(update);
    assert!(!session.bmp_stream_diverged, "repair must clear the latch");
    assert!(session.bmp_repair_timer.is_none());
    match bmp_rx.try_recv().unwrap() {
        BmpEvent::PeerDown { reason, .. } => assert!(
            matches!(reason, PeerDownReason::LocalNoNotification(0)),
            "synthetic reset uses reason 2 with FSM event code 0, got {reason:?}"
        ),
        other => panic!("expected synthetic BMP PeerDown, got {other:?}"),
    }
    match bmp_rx.try_recv().unwrap() {
        BmpEvent::PeerUp { local_open, .. } => {
            assert_eq!(local_open.as_ref(), &[1, 2, 3], "cached OPEN replayed");
        }
        other => panic!("expected synthetic BMP PeerUp, got {other:?}"),
    }
    expect_rib_out_rm(bmp_rx.try_recv().unwrap());
    assert!(bmp_rx.try_recv().is_err());
}
/// A session that goes quiet right after the drop is repaired from the
/// run loop's `bmp_repair_timer` arm instead of waiting for its next
/// UPDATE: retry re-arms while the channel is saturated and emits the
/// PeerDown/PeerUp reset once it drains.
#[tokio::test]
async fn bmp_repair_timer_retries_until_channel_drains() {
    let (mut session, _rib_rx, mut bmp_rx) = make_test_session_with_rib_and_bmp(65001, 65002);
    session.negotiated = Some(negotiated_session(65002, false));
    // Fill the 16-deep channel, then latch divergence with one more RM.
    let tx = session.bmp_tx.clone().unwrap();
    for _ in 0..16 {
        tx.try_send(BmpEvent::StatsReport {
            peer_info: session.build_bmp_peer_info(),
            adj_rib_in_routes: 0,
            adj_rib_out_post: None,
        })
        .unwrap();
    }
    session.emit_bmp_event(BmpEvent::RouteMonitoring {
        peer_info: session.build_bmp_peer_info(),
        update_pdu: Bytes::from_static(&[0xde, 0xad]),
    });
    assert!(session.bmp_stream_diverged);
    // Channel still full: the retry must keep the latch and re-arm.
    session.bmp_repair_timer = None;
    session.retry_bmp_stream_repair();
    assert!(session.bmp_stream_diverged);
    assert!(session.bmp_repair_timer.is_some(), "retry must re-arm");
    // Drain, then retry succeeds.
    for _ in 0..16 {
        bmp_rx.try_recv().unwrap();
    }
    session.retry_bmp_stream_repair();
    assert!(!session.bmp_stream_diverged);
    assert!(session.bmp_repair_timer.is_none());
    assert!(matches!(
        bmp_rx.try_recv().unwrap(),
        BmpEvent::PeerDown { .. }
    ));
    assert!(matches!(
        bmp_rx.try_recv().unwrap(),
        BmpEvent::PeerUp { .. }
    ));
}
/// `PeerDown` is never lost to a full BMP channel: the session awaits
/// channel space (bounded — the `BmpManager` loop always drains) rather
/// than dropping the one signal that tells collectors to discard the
/// peer's state.
#[tokio::test]
async fn bmp_peer_down_survives_full_channel() {
    let (mut session, _rib_rx, mut bmp_rx) = make_test_session_with_rib_and_bmp(65001, 65002);
    session.negotiated = Some(negotiated_session(65002, false));
    session.established_at = Some(Instant::now());
    session.last_down_reason = Some(PeerDownReason::RemoteNoNotification);
    let tx = session.bmp_tx.clone().unwrap();
    for _ in 0..16 {
        tx.try_send(BmpEvent::StatsReport {
            peer_info: session.build_bmp_peer_info(),
            adj_rib_in_routes: 0,
            adj_rib_out_post: None,
        })
        .unwrap();
    }
    // Consumer (the BmpManager stand-in) drains concurrently; the
    // awaited PeerDown send completes once space frees up.
    let drain = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(50)).await;
        while let Some(event) = bmp_rx.recv().await {
            if matches!(event, BmpEvent::PeerDown { .. }) {
                return true;
            }
        }
        false
    });
    session.execute_actions(vec![Action::SessionDown]).await;
    drop(session);
    assert!(
        drain.await.unwrap(),
        "PeerDown must be delivered even when the channel was full"
    );
}
/// LAN-200: a TCP disconnect abandons any pending BMP divergence repair.
/// Otherwise the run loop's `bmp_repair_timer` arm could fire after the
/// socket died and emit a synthetic `PeerDown`/`PeerUp` for a dead session
/// — which the reconnect would then stack a real `PeerUp` on top of.
#[tokio::test]
async fn tcp_disconnect_clears_bmp_repair_latch() {
    let (mut session, _rib_rx, mut bmp_rx) = make_test_session_with_rib_and_bmp(65001, 65002);
    session.negotiated = Some(negotiated_session(65002, false));
    session.tcp_ao_info = Some(crate::TcpAoInfoSnapshot {
        has_current_key: true,
        has_rnext_key: true,
        ao_required: true,
        accept_icmps: false,
        current_key: 7,
        rnext_key: 9,
        pkt_good: 12,
        pkt_bad: 0,
        pkt_key_not_found: 0,
        pkt_ao_required: 0,
        pkt_dropped_icmp: 0,
    });
    // Latch divergence + arm the repair timer via a dropped RM on a full
    // channel.
    let tx = session.bmp_tx.clone().unwrap();
    for _ in 0..16 {
        tx.try_send(BmpEvent::StatsReport {
            peer_info: session.build_bmp_peer_info(),
            adj_rib_in_routes: 0,
            adj_rib_out_post: None,
        })
        .unwrap();
    }
    session.emit_bmp_event(BmpEvent::RouteMonitoring {
        peer_info: session.build_bmp_peer_info(),
        update_pdu: Bytes::from_static(&[0xde, 0xad]),
    });
    assert!(session.bmp_stream_diverged);
    assert!(session.bmp_repair_timer.is_some());
    // Drain so a stray repair *could* succeed if it fired.
    for _ in 0..16 {
        bmp_rx.try_recv().unwrap();
    }
    // TCP disconnect must abandon the repair outright.
    session.handle_tcp_disconnect();
    assert!(session.tcp_ao_info.is_none(), "disconnect clears AO health");
    assert!(
        !session.bmp_stream_diverged,
        "disconnect clears the divergence latch"
    );
    assert!(
        session.bmp_repair_timer.is_none(),
        "disconnect disarms the repair timer"
    );
    // A late repair-timer fire on the dead session must emit nothing.
    session.retry_bmp_stream_repair();
    assert!(
        bmp_rx.try_recv().is_err(),
        "no synthetic PeerDown/PeerUp for a dead session"
    );
}

#[test]
fn connect_failure_is_retained_for_neighbor_diagnostics() {
    let (mut session, _rib_rx) = make_test_session_with_rib(65001, 65002);
    let error = std::io::Error::other(
        "failed to install TCP-AO key (send_id=7, recv_id=9, algorithm=hmac(sha256))",
    );
    session.record_connect_failure(&error);
    assert_eq!(session.last_error, error.to_string());
}
/// LAN-201: a partial repair attempt — `PeerDown` enqueued, `PeerUp` hits
/// a full channel — leaves the latch set and retries. The collector-visible
/// sequence carries a duplicate `PeerDown`, which is acceptable: RFC 7854
/// `PeerDown` is idempotent (the collector has already discarded peer state
/// from the first one), and the pair still ends in exactly one `PeerUp`.
#[tokio::test]
async fn repair_partial_enqueue_duplicate_peer_down_is_acceptable() {
    let (mut session, _rib_rx, mut bmp_rx) = make_test_session_with_rib_and_bmp(65001, 65002);
    session.negotiated = Some(negotiated_session(65002, false));
    let tx = session.bmp_tx.clone().unwrap();
    // Leave exactly one free slot in the 16-deep channel: PeerDown will
    // enqueue, the following PeerUp hits Full.
    for _ in 0..15 {
        tx.try_send(BmpEvent::StatsReport {
            peer_info: session.build_bmp_peer_info(),
            adj_rib_in_routes: 0,
            adj_rib_out_post: None,
        })
        .unwrap();
    }
    session.bmp_stream_diverged = true;
    // Partial attempt: PeerDown enqueues, PeerUp returns Full → incomplete.
    assert!(
        !session.repair_bmp_stream(&tx),
        "PeerUp Full leaves the repair incomplete"
    );
    assert!(
        session.bmp_stream_diverged,
        "latch stays set after a partial attempt"
    );
    // Drain the 15 fillers; the 16th queued item is the partial PeerDown.
    for _ in 0..15 {
        assert!(matches!(
            bmp_rx.try_recv().unwrap(),
            BmpEvent::StatsReport { .. }
        ));
    }
    assert!(
        matches!(bmp_rx.try_recv().unwrap(), BmpEvent::PeerDown { .. }),
        "partial attempt enqueued a PeerDown"
    );
    // Channel now empty → the retry completes the reset: PeerDown, PeerUp.
    assert!(
        session.repair_bmp_stream(&tx),
        "retry completes once the channel drains"
    );
    assert!(!session.bmp_stream_diverged);
    assert!(matches!(
        bmp_rx.try_recv().unwrap(),
        BmpEvent::PeerDown { .. }
    ));
    assert!(matches!(
        bmp_rx.try_recv().unwrap(),
        BmpEvent::PeerUp { .. }
    ));
    assert!(
        bmp_rx.try_recv().is_err(),
        "the completed reset ends in exactly one PeerUp"
    );
}
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
fn otc_egress_adds_local_asn_for_provider_peer_and_route_server() {
    for role in [BgpRole::Provider, BgpRole::Peer, BgpRole::RouteServer] {
        let mut session = make_test_session(65001, 65002);
        session.config.peer.local_role = Some(role);
        let route = make_route(100);
        let attrs =
            session.prepare_outbound_attributes(&route, true, Ipv4Addr::new(10, 0, 0, 1), None);
        assert!(
            attrs
                .iter()
                .any(|a| matches!(a, PathAttribute::OnlyToCustomer(65001))),
            "role {role:?} must add OTC(local AS) on eBGP unicast egress"
        );
    }
}
#[test]
fn otc_egress_preserves_existing_otc() {
    let mut session = make_test_session(65001, 65002);
    session.config.peer.local_role = Some(BgpRole::Provider);
    let route = replace_route_attrs(
        &make_route(100),
        vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath {
                segments: vec![AsPathSegment::AsSequence(vec![65002])],
            }),
            PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
            PathAttribute::OnlyToCustomer(64512),
        ],
    );
    let attrs = session.prepare_outbound_attributes(&route, true, Ipv4Addr::new(10, 0, 0, 1), None);
    let otcs: Vec<u32> = attrs
        .iter()
        .filter_map(|a| match a {
            PathAttribute::OnlyToCustomer(asn) => Some(*asn),
            _ => None,
        })
        .collect();
    assert_eq!(
        otcs,
        vec![64512],
        "E1 must not overwrite or duplicate an existing OTC attribute"
    );
}
#[test]
fn otc_egress_blocks_unicast_to_provider_peer_or_route_server_client() {
    for role in [BgpRole::Customer, BgpRole::Peer, BgpRole::RouteServerClient] {
        let mut session = make_test_session(65001, 65002);
        session.config.peer.local_role = Some(role);
        let route = replace_route_attrs(
            &make_route(100),
            vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath {
                    segments: vec![AsPathSegment::AsSequence(vec![65002])],
                }),
                PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
                PathAttribute::OnlyToCustomer(65002),
            ],
        );
        assert!(
            session.otc_egress_blocks_unicast(&route),
            "role {role:?} must not propagate an OTC-tagged unicast route"
        );
    }
}
#[test]
fn known_prefix_count_deduplicates_multiple_paths() {
    let mut session = make_test_session(65001, 65002);
    let prefix = Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24));
    assert!(session.remember_known_path(prefix, 1));
    assert!(session.remember_known_path(prefix, 2));
    assert!(
        !session.remember_known_path(prefix, 2),
        "duplicate path announcements must not bump the refcount"
    );
    assert_eq!(session.known_prefix_count(), 1);
}
#[test]
fn known_prefix_refcount_tracks_add_path_withdrawals() {
    let mut session = make_test_session(65001, 65002);
    let prefix = Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24));
    session.remember_known_path(prefix, 1);
    session.remember_known_path(prefix, 2);
    assert_eq!(session.known_prefix_count(), 1);
    assert!(session.forget_known_path(prefix, 1));
    assert_eq!(
        session.known_prefix_count(),
        1,
        "withdrawing one Add-Path path keeps the prefix counted"
    );
    assert!(
        !session.forget_known_path(prefix, 1),
        "duplicate withdrawals must not decrement the refcount"
    );
    assert_eq!(session.known_prefix_count(), 1);
    assert!(session.forget_known_path(prefix, 2));
    assert_eq!(
        session.known_prefix_count(),
        0,
        "the last path withdrawal removes the unique prefix"
    );
}
/// Regression: `Action::SessionDown` must clear `known_flowspec` and
/// `known_evpn` alongside unicast path accounting. Reconnects previously inherited
/// stale accounting, which could trip false max-prefix violations on the
/// next session because `known_prefix_count` sums all three sets.
#[tokio::test]
async fn session_down_clears_all_known_sets() {
    let mut session = make_test_session(65001, 65002);
    session.negotiated = Some(negotiated_session(65002, false));
    session.established_at = Some(Instant::now());
    let prefix = Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24));
    session.remember_known_path(prefix, 1);
    let fs_prefix =
        rustbgpd_wire::FlowSpecPrefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24));
    session.known_flowspec.insert(rustbgpd_wire::FlowSpecRule {
        components: vec![rustbgpd_wire::FlowSpecComponent::DestinationPrefix(
            fs_prefix,
        )],
    });
    let evpn_key = rustbgpd_wire::EvpnRouteKey::Imet {
        rd: rustbgpd_wire::RouteDistinguisher([0, 0, 0xFD, 0xE8, 0, 0, 0, 1]),
        ethernet_tag: rustbgpd_wire::EthernetTagId(100),
        originator_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
    };
    session.known_evpn.insert(evpn_key);
    assert!(session.known_prefix_count() >= 3);
    session.execute_actions(vec![Action::SessionDown]).await;
    assert!(session.known_paths.is_empty(), "known_paths must clear");
    assert!(
        session.known_prefix_refcounts.is_empty(),
        "known_prefix_refcounts must clear"
    );
    assert!(
        session.known_flowspec.is_empty(),
        "known_flowspec must clear"
    );
    assert!(session.known_evpn.is_empty(), "known_evpn must clear");
    assert_eq!(session.known_prefix_count(), 0);
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
#[tokio::test]
async fn send_route_update_batches_ipv4_routes_with_identical_attributes() {
    let (mut session, _rib_rx) = make_test_session_with_rib(65001, 65002);
    let (client, mut server) = connected_stream_pair().await;
    session.test_install_stream(client);
    let negotiated = negotiated_session(65002, false);
    session
        .negotiated_families
        .clone_from(&negotiated.negotiated_families);
    session.negotiated = Some(negotiated);
    let attrs = Arc::new(vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath {
            segments: vec![AsPathSegment::AsSequence(vec![65002])],
        }),
        PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
    ]);
    let route1 = Route {
        prefix: Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, 0), 24)),
        next_hop: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        link_local_next_hop: None,
        next_hop_scope: None,
        peer: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        attributes: Arc::clone(&attrs),
        received_at: Instant::now(),
        origin_type: rustbgpd_rib::RouteOrigin::Ebgp,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        is_stale: false,
        is_llgr_stale: false,
        path_id: 0,
        validation_state: rustbgpd_wire::RpkiValidation::NotFound,
        aspa_state: rustbgpd_wire::AspaValidation::Unknown,
        aspa_context: rustbgpd_wire::AspaValidationContext::default(),
    };
    let route2 = Route {
        prefix: Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 0), 24)),
        ..route1.clone()
    };
    session.send_route_update(OutboundRouteUpdate {
        otc_blocked: vec![],
        announce: vec![route1, route2].into(),
        withdraw: vec![],
        end_of_rib: vec![],
        refresh_markers: vec![],
        next_hop_override: vec![None, None].into(),
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
        labeled_withdraw: vec![],
        rtc_withdraw: vec![],
        request_refresh_all_negotiated: false,
    });
    let Message::Update(msg) = read_single_bgp_message(&mut server).await else {
        panic!("expected UPDATE");
    };
    let parsed = msg.parse(true, false, &[]).unwrap();
    assert_eq!(parsed.announced.len(), 2);
}
#[tokio::test]
async fn send_route_update_emits_bgpls_reach_and_unreach() {
    let (mut session, _rib_rx) = make_test_session_with_rib(65001, 65002);
    let (client, mut server) = connected_stream_pair().await;
    session.test_install_stream(client);
    let mut negotiated = negotiated_session(65002, false);
    negotiated.negotiated_families = vec![(Afi::BgpLs, Safi::BgpLs)];
    session
        .negotiated_families
        .clone_from(&negotiated.negotiated_families);
    session.negotiated = Some(negotiated);
    let route = make_bgpls_route(0xcc);
    let key = route.key();
    session.send_route_update(OutboundRouteUpdate {
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
        bgpls_announce: vec![route.clone()],
        bgpls_withdraw: vec![],
        vpn_announce: vec![],
        labeled_announce: vec![],
        rtc_announce: vec![],
        vpn_withdraw: vec![],
        labeled_withdraw: vec![],
        rtc_withdraw: vec![],
        request_refresh_all_negotiated: false,
    });
    let Message::Update(msg) = read_single_bgp_message(&mut server).await else {
        panic!("expected BGP-LS MP_REACH UPDATE");
    };
    let parsed = msg.parse(true, false, &[]).unwrap();
    let mp = parsed
        .attributes
        .iter()
        .find_map(|attr| match attr {
            PathAttribute::MpReachNlri(mp) => Some(mp),
            _ => None,
        })
        .expect("BGP-LS announcement must use MP_REACH");
    assert_eq!(mp.afi, Afi::BgpLs);
    assert_eq!(mp.safi, Safi::BgpLs);
    assert_eq!(mp.next_hop, route.next_hop);
    assert_eq!(mp.bgpls_announced, vec![route.nlri.clone()]);
    session.send_route_update(OutboundRouteUpdate {
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
        bgpls_withdraw: vec![key],
        vpn_announce: vec![],
        labeled_announce: vec![],
        rtc_announce: vec![],
        vpn_withdraw: vec![],
        labeled_withdraw: vec![],
        rtc_withdraw: vec![],
        request_refresh_all_negotiated: false,
    });
    let Message::Update(msg) = read_single_bgp_message(&mut server).await else {
        panic!("expected BGP-LS MP_UNREACH UPDATE");
    };
    let parsed = msg.parse(true, false, &[]).unwrap();
    let mp = parsed
        .attributes
        .iter()
        .find_map(|attr| match attr {
            PathAttribute::MpUnreachNlri(mp) => Some(mp),
            _ => None,
        })
        .expect("BGP-LS withdrawal must use MP_UNREACH");
    assert_eq!(mp.afi, Afi::BgpLs);
    assert_eq!(mp.safi, Safi::BgpLs);
    assert_eq!(mp.bgpls_withdrawn, vec![route.nlri]);
}
#[tokio::test]
async fn oversized_bgpls_output_tears_down_session() {
    use rustbgpd_wire::notification::{NotificationCode, cease_subcode};
    let (mut session, _rib_rx) = make_test_session_with_rib(65001, 65002);
    let (client, mut server) = connected_stream_pair().await;
    session.test_install_stream(client);
    let mut negotiated = negotiated_session(65002, false);
    negotiated.negotiated_families = vec![(Afi::BgpLs, Safi::BgpLs)];
    session
        .negotiated_families
        .clone_from(&negotiated.negotiated_families);
    session.negotiated = Some(negotiated);
    let mut route = make_bgpls_route(0xdd);
    route.nlri = BgpLsNlri::try_new(
        BgpLsNlriType::Unknown(65_000),
        None,
        Bytes::from(vec![0xab; usize::from(rustbgpd_wire::MAX_MESSAGE_LEN)]),
    )
    .expect("oversize-for-peer fixture still fits BGP-LS NLRI length");
    session.send_route_update(OutboundRouteUpdate {
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
        bgpls_announce: vec![route],
        bgpls_withdraw: vec![],
        vpn_announce: vec![],
        labeled_announce: vec![],
        rtc_announce: vec![],
        vpn_withdraw: vec![],
        labeled_withdraw: vec![],
        rtc_withdraw: vec![],
        request_refresh_all_negotiated: false,
    });
    assert!(
        session.read_half.is_none(),
        "structurally unsendable BGP-LS output must tear down the peer"
    );
    let join = session
        .writer_join
        .take()
        .expect("writer_join stays for run-loop observation after teardown");
    let Message::Notification(notif) = read_single_bgp_message(&mut server).await else {
        panic!("expected Cease/Out-of-Resources for oversize BGP-LS output");
    };
    assert_eq!(notif.code, NotificationCode::Cease);
    assert_eq!(notif.subcode, cease_subcode::OUT_OF_RESOURCES);
    let result = tokio::time::timeout(Duration::from_secs(2), join)
        .await
        .expect("writer should exit after oversize-triggered teardown")
        .expect("writer join should not panic");
    assert!(
        matches!(result, Err(super::writer::WriterExit::TornDown)),
        "oversize output routes through the saturation hard close, got: {result:?}"
    );
}
fn make_vpn_rib_route(label: u32) -> rustbgpd_rib::VpnRibRoute {
    rustbgpd_rib::VpnRibRoute {
        nlri: VpnNlri {
            labels: vec![MplsLabelEntry::try_new(label, 0, true).unwrap()],
            route_distinguisher: RouteDistinguisher([0, 0, 0xFD, 0xE8, 0, 0, 0, 1]),
            prefix: VpnPrefix::v4(Ipv4Addr::new(10, 0, 1, 0), 24).unwrap(),
        },
        next_hop: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7)),
        link_local_next_hop: None,
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
    }
}
fn make_labeled_rib_route(label: u32) -> rustbgpd_rib::LabeledRibRoute {
    rustbgpd_rib::LabeledRibRoute {
        nlri: rustbgpd_wire::LabeledNlri {
            labels: vec![MplsLabelEntry::try_new(label, 0, true).unwrap()],
            prefix: Prefix::V4(rustbgpd_wire::Ipv4Prefix::new(
                Ipv4Addr::new(10, 0, 1, 0),
                24,
            )),
        },
        next_hop: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7)),
        link_local_next_hop: None,
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
    }
}
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
/// LAN-217: a `VPNv6` route carrying an RFC 4659 §3.2.1.1 48-byte two-address
/// next-hop (global + link-local) reflects the link-local half — the emitted
/// `MP_REACH` uses the 48-byte next-hop form, not the 24-byte single-address
/// form.
/// Without this, `VPNv6` link-local forwarding breaks on reflection.
#[tokio::test]
async fn send_route_update_reflects_vpnv6_link_local_next_hop() {
    let (mut session, _rib_rx) = make_test_session_with_rib(65001, 65002);
    let (client, mut server) = connected_stream_pair().await;
    session.test_install_stream(client);
    let mut negotiated = negotiated_session(65002, false);
    negotiated.negotiated_families = vec![(Afi::Ipv6, Safi::MplsVpn)];
    session
        .negotiated_families
        .clone_from(&negotiated.negotiated_families);
    session.negotiated = Some(negotiated);

    let global: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let link_local: Ipv6Addr = "fe80::1".parse().unwrap();
    let route = rustbgpd_rib::VpnRibRoute {
        nlri: VpnNlri {
            labels: vec![MplsLabelEntry::try_new(4093, 0, true).unwrap()],
            route_distinguisher: RouteDistinguisher([0, 0, 0xFD, 0xE8, 0, 0, 0, 1]),
            prefix: VpnPrefix::v6("2001:db8:100::".parse().unwrap(), 48).unwrap(),
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
    assert_eq!(mp.afi, Afi::Ipv6);
    assert_eq!(mp.safi, Safi::MplsVpn);
    assert_eq!(
        mp.next_hop,
        IpAddr::V6(global),
        "VPN global next-hop must pass through reflection unchanged"
    );
    assert_eq!(
        mp.link_local_next_hop,
        Some(link_local),
        "VPNv6 link-local next-hop must survive reflection (LAN-217)"
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
    session
        .negotiated_families
        .clone_from(&negotiated.negotiated_families);
    session.negotiated = Some(negotiated);
    let route = make_vpn_rib_route(4093);
    let key = route.key();
    session.send_route_update(OutboundRouteUpdate {
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
    session
        .negotiated_families
        .clone_from(&negotiated.negotiated_families);
    session.negotiated = Some(negotiated);
    let mut route = make_vpn_rib_route(4093);
    route.path_id = 2;
    let key = route.key();
    session.send_route_update(OutboundRouteUpdate {
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
        PathAttribute::MpReachNlri(MpReachNlri {
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
        }),
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
    let attrs = vec![PathAttribute::MpUnreachNlri(MpUnreachNlri {
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
    })];
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
/// iBGP reflection of a VPN route on an RR adds `ORIGINATOR_ID` and
/// `CLUSTER_LIST`, keeps `LOCAL_PREF`, and never emits inline `NextHop`/MP attrs.
#[test]
fn prepare_outbound_attributes_vpn_adds_rr_attrs_for_ibgp_reflection() {
    let mut session = make_test_session(65001, 65001);
    let cluster_id = Ipv4Addr::new(10, 0, 0, 9);
    let source_id = Ipv4Addr::new(10, 0, 0, 42);
    session.config.cluster_id = Some(cluster_id);
    let mut route = make_vpn_rib_route(100);
    route.origin_type = rustbgpd_rib::RouteOrigin::Ibgp;
    route.peer_router_id = source_id;
    route.attributes = Arc::new(vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath { segments: vec![] }),
        PathAttribute::LocalPref(200),
    ]);
    let attrs = session.prepare_outbound_attributes_vpn(&route, false);
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
/// eBGP export of a VPN route strips `ORIGINATOR_ID`/`CLUSTER_LIST`/`LOCAL_PREF`
/// and prepends the local ASN to `AS_PATH`.
#[test]
fn prepare_outbound_attributes_vpn_strips_rr_attrs_for_ebgp() {
    let session = make_test_session(65001, 65002);
    let mut route = make_vpn_rib_route(100);
    route.attributes = Arc::new(vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath {
            segments: vec![AsPathSegment::AsSequence(vec![65002])],
        }),
        PathAttribute::LocalPref(200),
        PathAttribute::OriginatorId(Ipv4Addr::new(10, 0, 0, 42)),
        PathAttribute::ClusterList(vec![Ipv4Addr::new(10, 0, 0, 9)]),
    ]);
    let attrs = session.prepare_outbound_attributes_vpn(&route, true);
    assert!(!attrs.iter().any(|a| matches!(
        a,
        PathAttribute::OriginatorId(_)
            | PathAttribute::ClusterList(_)
            | PathAttribute::LocalPref(_)
    )));
    let as_path = attrs
        .iter()
        .find_map(|a| match a {
            PathAttribute::AsPath(p) => Some(p),
            _ => None,
        })
        .expect("eBGP VPN export must carry AS_PATH");
    assert_eq!(
        as_path.segments,
        vec![AsPathSegment::AsSequence(vec![65001, 65002])]
    );
}
fn make_rtc_rib_route(local_admin: u16) -> rustbgpd_rib::RtcRibRoute {
    rustbgpd_rib::RtcRibRoute {
        nlri: rustbgpd_wire::RtcNlri::new(
            65002,
            0x0002_FDEA_0000_0000 | u64::from(local_admin),
            96,
        )
        .unwrap(),
        next_hop: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7)),
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
    }
}
/// RTC `MP_REACH` carries the membership NLRI verbatim with the stored
/// next-hop; the locally-originated default (stored with an unspecified
/// next-hop) is emitted with the session-local address. The withdraw uses
/// the same NLRI codec via `MP_UNREACH`.
#[expect(
    clippy::too_many_lines,
    reason = "pins announce grouping, both next-hop forms, and the withdraw in one wire sequence"
)]
#[tokio::test]
async fn send_route_update_emits_rtc_reach_and_unreach() {
    let (mut session, _rib_rx) = make_test_session_with_rib(65001, 65002);
    let (client, mut server) = connected_stream_pair().await;
    let session_local_ip = client.local_addr().unwrap().ip();
    session.test_install_stream(client);
    let mut negotiated = negotiated_session(65002, false);
    negotiated.negotiated_families = vec![(Afi::Ipv4, Safi::RtConstrain)];
    session
        .negotiated_families
        .clone_from(&negotiated.negotiated_families);
    session.negotiated = Some(negotiated);
    let route = make_rtc_rib_route(100);
    let key = route.key();
    // A locally-originated default rides in the same update; its stored
    // next-hop is unspecified and must be rewritten to the session-local
    // address on the wire.
    let local_default = rustbgpd_rib::RtcRibRoute {
        nlri: rustbgpd_wire::RtcNlri::DEFAULT,
        next_hop: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        peer: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        attributes: Arc::new(vec![PathAttribute::Origin(Origin::Igp)]),
        received_at: Instant::now(),
        origin_type: rustbgpd_rib::RouteOrigin::Local,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        is_stale: false,
        is_llgr_stale: false,
        path_id: 0,
    };
    session.send_route_update(OutboundRouteUpdate {
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
        vpn_withdraw: vec![],
        labeled_withdraw: vec![],
        rtc_announce: vec![route.clone(), local_default],
        rtc_withdraw: vec![],
        request_refresh_all_negotiated: false,
    });
    // Distinct next-hops (stored vs session-local) split into two UPDATEs.
    let mut seen_nlris = Vec::new();
    let mut seen_next_hops = Vec::new();
    for _ in 0..2 {
        let Message::Update(msg) = read_single_bgp_message(&mut server).await else {
            panic!("expected RTC MP_REACH UPDATE");
        };
        let parsed = msg.parse(true, false, &[]).unwrap();
        let mp = parsed
            .attributes
            .iter()
            .find_map(|attr| match attr {
                PathAttribute::MpReachNlri(mp) => Some(mp),
                _ => None,
            })
            .expect("RTC announcement must use MP_REACH");
        assert_eq!(mp.afi, Afi::Ipv4);
        assert_eq!(mp.safi, Safi::RtConstrain);
        seen_nlris.extend(mp.rtc_announced.iter().copied());
        seen_next_hops.push(mp.next_hop);
    }
    assert!(
        seen_nlris.contains(&route.nlri),
        "membership NLRI must ride through verbatim"
    );
    assert!(
        seen_nlris.contains(&rustbgpd_wire::RtcNlri::DEFAULT),
        "default NLRI must be emitted"
    );
    assert!(
        seen_next_hops.contains(&route.next_hop),
        "stored RTC next-hop must pass through unchanged"
    );
    assert!(
        seen_next_hops.contains(&session_local_ip),
        "local default must be emitted with the session-local address, got {seen_next_hops:?}"
    );
    session.send_route_update(OutboundRouteUpdate {
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
        vpn_withdraw: vec![],
        labeled_withdraw: vec![],
        rtc_announce: vec![],
        rtc_withdraw: vec![key],
        request_refresh_all_negotiated: false,
    });
    let Message::Update(msg) = read_single_bgp_message(&mut server).await else {
        panic!("expected RTC MP_UNREACH UPDATE");
    };
    let parsed = msg.parse(true, false, &[]).unwrap();
    let mp = parsed
        .attributes
        .iter()
        .find_map(|attr| match attr {
            PathAttribute::MpUnreachNlri(mp) => Some(mp),
            _ => None,
        })
        .expect("RTC withdrawal must use MP_UNREACH");
    assert_eq!(mp.afi, Afi::Ipv4);
    assert_eq!(mp.safi, Safi::RtConstrain);
    assert_eq!(mp.rtc_withdrawn, vec![route.nlri]);
}
/// iBGP reflection of an RTC route on an RR adds `ORIGINATOR_ID` and
/// `CLUSTER_LIST` — identical semantics to the VPN preparation.
#[test]
fn prepare_outbound_attributes_rtc_adds_rr_attrs_for_ibgp_reflection() {
    let mut session = make_test_session(65001, 65001);
    let cluster_id = Ipv4Addr::new(10, 0, 0, 9);
    let source_id = Ipv4Addr::new(10, 0, 0, 42);
    session.config.cluster_id = Some(cluster_id);
    let mut route = make_rtc_rib_route(100);
    route.origin_type = rustbgpd_rib::RouteOrigin::Ibgp;
    route.peer_router_id = source_id;
    route.attributes = Arc::new(vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath { segments: vec![] }),
        PathAttribute::LocalPref(200),
    ]);
    let attrs = session.prepare_outbound_attributes_rtc(&route, false);
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
    assert!(!attrs.iter().any(|a| matches!(
        a,
        PathAttribute::NextHop(_) | PathAttribute::MpReachNlri(_) | PathAttribute::MpUnreachNlri(_)
    )));
}
/// `OutboundRouteUpdate::request_refresh_all_negotiated` (the RIB
/// manager's failover-driven inbound recovery) emits a plain RFC 2918
/// ROUTE-REFRESH request on the wire for EVERY negotiated family when
/// the peer negotiated the capability. The family set is the session
/// task's `negotiated_families` — deliberately NOT the sendable subset
/// the manager sees in `PeerUp`: here IPv6 unicast stands in for a
/// family negotiated for receive but pruned from the sendable set (no
/// usable local IPv6 next-hop), and it MUST still be refreshed.
#[tokio::test]
async fn send_route_update_emits_route_refresh_requests_for_all_negotiated_families() {
    let (mut session, _rib_rx) = make_test_session_with_rib(65001, 65002);
    let (client, mut server) = connected_stream_pair().await;
    session.test_install_stream(client);
    let mut negotiated = negotiated_session(65002, false);
    negotiated.peer_route_refresh = true;
    negotiated.negotiated_families = vec![(Afi::Ipv4, Safi::Unicast), (Afi::Ipv6, Safi::Unicast)];
    session
        .negotiated_families
        .clone_from(&negotiated.negotiated_families);
    session.negotiated = Some(negotiated);
    session.send_route_update(OutboundRouteUpdate {
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
        labeled_withdraw: vec![],
        rtc_withdraw: vec![],
        request_refresh_all_negotiated: true,
    });
    let mut refreshed = Vec::new();
    for _ in 0..2 {
        let Message::RouteRefresh(rr) = read_single_bgp_message(&mut server).await else {
            panic!("expected ROUTE-REFRESH request");
        };
        assert_eq!(
            rr.subtype_raw, 0,
            "manager-initiated refresh must be a plain RFC 2918 request"
        );
        refreshed.push((rr.afi_raw, rr.safi_raw));
    }
    assert!(
        refreshed.contains(&(Afi::Ipv4 as u16, Safi::Unicast as u8)),
        "IPv4 unicast (negotiated) must be refreshed, got {refreshed:?}"
    );
    assert!(
        refreshed.contains(&(Afi::Ipv6 as u16, Safi::Unicast as u8)),
        "IPv6 unicast (negotiated but not necessarily sendable) must be \
         refreshed, got {refreshed:?}"
    );
}
/// Without the negotiated Route Refresh capability the request is
/// skipped (warned, not sent) — the rest of the update still goes out.
#[tokio::test]
async fn send_route_update_skips_route_refresh_request_without_capability() {
    let (mut session, _rib_rx) = make_test_session_with_rib(65001, 65002);
    let (client, mut server) = connected_stream_pair().await;
    session.test_install_stream(client);
    let negotiated = negotiated_session(65002, false);
    assert!(!negotiated.peer_route_refresh);
    session
        .negotiated_families
        .clone_from(&negotiated.negotiated_families);
    session.negotiated = Some(negotiated);
    session.send_route_update(OutboundRouteUpdate {
        otc_blocked: vec![],
        announce: vec![].into(),
        withdraw: vec![],
        end_of_rib: vec![(Afi::Ipv4, Safi::Unicast)],
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
        labeled_withdraw: vec![],
        rtc_withdraw: vec![],
        request_refresh_all_negotiated: true,
    });
    // The first wire message must be the EoR UPDATE — no ROUTE-REFRESH
    // was emitted ahead of it.
    let Message::Update(msg) = read_single_bgp_message(&mut server).await else {
        panic!("expected the EoR UPDATE, not a ROUTE-REFRESH");
    };
    let parsed = msg.parse(true, false, &[]).unwrap();
    assert!(parsed.announced.is_empty());
    assert!(parsed.withdrawn.is_empty());
}
#[tokio::test]
async fn send_route_update_splits_ipv6_routes_by_next_hop() {
    let (mut session, _rib_rx) = make_test_session_with_rib(65001, 65002);
    let (client, mut server) = connected_stream_pair().await;
    session.test_install_stream(client);
    session.config.route_server_client = true;
    let mut negotiated = negotiated_session(65002, false);
    negotiated.negotiated_families = vec![(Afi::Ipv6, Safi::Unicast)];
    session
        .negotiated_families
        .clone_from(&negotiated.negotiated_families);
    session.negotiated = Some(negotiated);
    let attrs = Arc::new(vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath {
            segments: vec![AsPathSegment::AsSequence(vec![65002])],
        }),
    ]);
    let route1 = Route {
        prefix: Prefix::V6(Ipv6Prefix::new("2001:db8:1::".parse().unwrap(), 64)),
        next_hop: IpAddr::V6("2001:db8::1".parse().unwrap()),
        link_local_next_hop: None,
        next_hop_scope: None,
        peer: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        attributes: Arc::clone(&attrs),
        received_at: Instant::now(),
        origin_type: rustbgpd_rib::RouteOrigin::Ebgp,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        is_stale: false,
        is_llgr_stale: false,
        path_id: 0,
        validation_state: rustbgpd_wire::RpkiValidation::NotFound,
        aspa_state: rustbgpd_wire::AspaValidation::Unknown,
        aspa_context: rustbgpd_wire::AspaValidationContext::default(),
    };
    let route2 = Route {
        prefix: Prefix::V6(Ipv6Prefix::new("2001:db8:2::".parse().unwrap(), 64)),
        next_hop: IpAddr::V6("2001:db8::2".parse().unwrap()),
        ..route1.clone()
    };
    session.send_route_update(OutboundRouteUpdate {
        otc_blocked: vec![],
        announce: vec![route1, route2].into(),
        withdraw: vec![],
        end_of_rib: vec![],
        refresh_markers: vec![],
        next_hop_override: vec![None, None].into(),
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
        labeled_withdraw: vec![],
        rtc_withdraw: vec![],
        request_refresh_all_negotiated: false,
    });
    let Message::Update(first) = read_single_bgp_message(&mut server).await else {
        panic!("expected first UPDATE");
    };
    let first = first.parse(true, false, &[]).unwrap();
    let first_mp = first
        .attributes
        .iter()
        .find_map(|a| match a {
            PathAttribute::MpReachNlri(mp) => Some(mp),
            _ => None,
        })
        .unwrap();
    assert_eq!(first_mp.announced.len(), 1);
    let Message::Update(second) = read_single_bgp_message(&mut server).await else {
        panic!("expected second UPDATE");
    };
    let second = second.parse(true, false, &[]).unwrap();
    let second_mp = second
        .attributes
        .iter()
        .find_map(|a| match a {
            PathAttribute::MpReachNlri(mp) => Some(mp),
            _ => None,
        })
        .unwrap();
    assert_eq!(second_mp.announced.len(), 1);
    assert_ne!(first_mp.next_hop, second_mp.next_hop);
}

/// A single attribute group whose NLRI exceeds one 4096-byte UPDATE must be
/// split across multiple wire UPDATEs with every prefix advertised — not
/// truncated. Before the size-aware chunker, `send_route_update` built one
/// oversized UPDATE per attribute group; `enqueue_bulk` rejected it
/// (`MessageTooLong`) and returned early, silently advertising nothing while
/// the RIB believed the whole group was sent.
#[tokio::test]
async fn send_route_update_splits_oversized_ipv4_group_across_updates() {
    let (mut session, _rib_rx) = make_test_session_with_rib(65001, 65002);
    let (client, mut server) = connected_stream_pair().await;
    session.test_install_stream(client);
    session.config.route_server_client = true;
    let mut negotiated = negotiated_session(65002, false);
    negotiated.negotiated_families = vec![(Afi::Ipv4, Safi::Unicast)];
    session
        .negotiated_families
        .clone_from(&negotiated.negotiated_families);
    session.negotiated = Some(negotiated);

    // One shared attribute set + next hop => one attribute group. 1500 /24s
    // (4 NLRI bytes each = 6000 bytes) cannot fit a single 4096-byte UPDATE.
    let attrs = Arc::new(vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath {
            segments: vec![AsPathSegment::AsSequence(vec![65002])],
        }),
    ]);
    let count: u32 = 1500;
    let route = |i: u32| Route {
        prefix: Prefix::V4(Ipv4Prefix::new(
            Ipv4Addr::from(0x1400_0000_u32 | (i << 8)),
            24,
        )),
        next_hop: IpAddr::V4(Ipv4Addr::new(10, 9, 0, 1)),
        link_local_next_hop: None,
        next_hop_scope: None,
        peer: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        attributes: Arc::clone(&attrs),
        received_at: Instant::now(),
        origin_type: rustbgpd_rib::RouteOrigin::Ebgp,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        is_stale: false,
        is_llgr_stale: false,
        path_id: 0,
        validation_state: rustbgpd_wire::RpkiValidation::NotFound,
        aspa_state: rustbgpd_wire::AspaValidation::Unknown,
        aspa_context: rustbgpd_wire::AspaValidationContext::default(),
    };
    let routes: Vec<Route> = (0..count).map(route).collect();
    let sent_before = session.updates_sent;
    session.send_route_update(OutboundRouteUpdate {
        otc_blocked: vec![],
        announce: routes.into(),
        next_hop_override: vec![None; count as usize].into(),
        ..empty_outbound_update()
    });

    // Drain every emitted UPDATE: each must fit the limit, and the union of
    // announced prefixes must cover all 1500 with none dropped or duplicated.
    let mut seen: std::collections::HashSet<u32> = std::collections::HashSet::new();
    let mut updates = 0usize;
    while let Ok(raw) = tokio::time::timeout(
        Duration::from_millis(500),
        read_single_raw_bgp_message(&mut server),
    )
    .await
    {
        assert!(
            raw.len() <= 4096,
            "emitted UPDATE is {} bytes, over the 4096 limit",
            raw.len()
        );
        let mut buf = Bytes::from(raw);
        let Message::Update(u) =
            rustbgpd_wire::decode_message(&mut buf, rustbgpd_wire::MAX_MESSAGE_LEN).unwrap()
        else {
            continue;
        };
        let parsed = u.parse(true, false, &[]).unwrap();
        for e in &parsed.announced {
            assert!(
                seen.insert(u32::from(e.prefix.addr)),
                "prefix advertised more than once"
            );
        }
        updates += 1;
    }
    assert!(
        updates >= 2,
        "oversized group must split across multiple UPDATEs, got {updates}"
    );
    assert_eq!(
        seen.len(),
        count as usize,
        "every prefix in the oversized group must be advertised"
    );
    assert_eq!(
        session.updates_sent - sent_before,
        updates as u64,
        "updates_sent must count exactly the emitted wire UPDATEs"
    );
}

/// The withdrawal path has the same single-UPDATE construction as the
/// announcement path: a large IPv4 withdrawal set must also split across
/// multiple wire UPDATEs, none over 4096 bytes, covering every prefix.
#[tokio::test]
async fn send_route_update_splits_oversized_ipv4_withdrawals_across_updates() {
    let (mut session, _rib_rx) = make_test_session_with_rib(65001, 65002);
    let (client, mut server) = connected_stream_pair().await;
    session.test_install_stream(client);
    session.config.route_server_client = true;
    let mut negotiated = negotiated_session(65002, false);
    negotiated.negotiated_families = vec![(Afi::Ipv4, Safi::Unicast)];
    session
        .negotiated_families
        .clone_from(&negotiated.negotiated_families);
    session.negotiated = Some(negotiated);

    let count: u32 = 2000;
    let withdraw: Vec<(Prefix, u32)> = (0..count)
        .map(|i| {
            (
                Prefix::V4(Ipv4Prefix::new(
                    Ipv4Addr::from(0x1400_0000_u32 | (i << 8)),
                    24,
                )),
                0u32,
            )
        })
        .collect();
    session.send_route_update(OutboundRouteUpdate {
        otc_blocked: vec![],
        withdraw,
        ..empty_outbound_update()
    });

    let mut seen: std::collections::HashSet<u32> = std::collections::HashSet::new();
    let mut updates = 0usize;
    while let Ok(raw) = tokio::time::timeout(
        Duration::from_millis(500),
        read_single_raw_bgp_message(&mut server),
    )
    .await
    {
        assert!(
            raw.len() <= 4096,
            "withdrawal UPDATE is {} bytes",
            raw.len()
        );
        let mut buf = Bytes::from(raw);
        let Message::Update(u) =
            rustbgpd_wire::decode_message(&mut buf, rustbgpd_wire::MAX_MESSAGE_LEN).unwrap()
        else {
            continue;
        };
        let parsed = u.parse(true, false, &[]).unwrap();
        for e in &parsed.withdrawn {
            assert!(
                seen.insert(u32::from(e.prefix.addr)),
                "prefix withdrawn twice"
            );
        }
        updates += 1;
    }
    assert!(
        updates >= 2,
        "oversized withdrawal must split across multiple UPDATEs, got {updates}"
    );
    assert_eq!(
        seen.len(),
        count as usize,
        "every prefix in the oversized withdrawal must be sent"
    );
}

/// Extended Next Hop carries IPv4 NLRI in `MP_REACH` rather than the UPDATE
/// body. Keep that construction path covered by the same oversized-group
/// regression as ordinary IPv4 announcements.
#[tokio::test]
async fn send_route_update_splits_oversized_ipv4_mp_reach_across_updates() {
    let (mut session, _rib_rx) = make_test_session_with_rib(65001, 65002);
    configure_scoped_link_local_peer(&mut session);
    session.config.local_ipv6_nexthop = Some("fe80::1".parse().unwrap());
    session.config.route_server_client = true;
    let (client, mut server) = connected_stream_pair().await;
    session.test_install_stream(client);
    install_test_negotiated_session(&mut session, negotiated_session(65002, true));

    let attrs = Arc::new(vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath {
            segments: vec![AsPathSegment::AsSequence(vec![65002])],
        }),
    ]);
    let count: u32 = 1500;
    let routes: Vec<Route> = (0..count)
        .map(|i| Route {
            prefix: Prefix::V4(Ipv4Prefix::new(
                Ipv4Addr::from(0x1400_0000_u32 | (i << 8)),
                24,
            )),
            next_hop: IpAddr::V6("fe80::2".parse().unwrap()),
            link_local_next_hop: Some("fe80::2".parse().unwrap()),
            next_hop_scope: None,
            peer: IpAddr::V6("fe80::2".parse().unwrap()),
            attributes: Arc::clone(&attrs),
            received_at: Instant::now(),
            origin_type: rustbgpd_rib::RouteOrigin::Ebgp,
            peer_router_id: Ipv4Addr::UNSPECIFIED,
            is_stale: false,
            is_llgr_stale: false,
            path_id: 0,
            validation_state: rustbgpd_wire::RpkiValidation::NotFound,
            aspa_state: rustbgpd_wire::AspaValidation::Unknown,
            aspa_context: rustbgpd_wire::AspaValidationContext::default(),
        })
        .collect();
    session.send_route_update(OutboundRouteUpdate {
        otc_blocked: vec![],
        announce: routes.into(),
        next_hop_override: vec![None; count as usize].into(),
        ..empty_outbound_update()
    });

    let mut seen = std::collections::HashSet::new();
    let mut updates = 0usize;
    while let Ok(raw) = tokio::time::timeout(
        Duration::from_millis(500),
        read_single_raw_bgp_message(&mut server),
    )
    .await
    {
        assert!(raw.len() <= 4096, "MP_REACH UPDATE is {} bytes", raw.len());
        let mut buf = Bytes::from(raw);
        let Message::Update(update) =
            rustbgpd_wire::decode_message(&mut buf, rustbgpd_wire::MAX_MESSAGE_LEN).unwrap()
        else {
            continue;
        };
        let parsed = update.parse(true, false, &[]).unwrap();
        let mp = parsed
            .attributes
            .iter()
            .find_map(|attr| match attr {
                PathAttribute::MpReachNlri(mp) => Some(mp),
                _ => None,
            })
            .expect("Extended Next Hop announcement must use MP_REACH");
        assert_eq!((mp.afi, mp.safi), (Afi::Ipv4, Safi::Unicast));
        for entry in &mp.announced {
            let Prefix::V4(prefix) = entry.prefix else {
                panic!("IPv4 MP_REACH contained non-IPv4 NLRI");
            };
            assert!(seen.insert(u32::from(prefix.addr)));
        }
        updates += 1;
    }
    assert!(updates >= 2, "oversized MP_REACH group was not split");
    assert_eq!(seen.len(), count as usize);
}

/// Extended Next Hop also moves IPv4 withdrawals into `MP_UNREACH`. Verify an
/// oversized set is split without dropping or duplicating any withdrawn NLRI.
#[tokio::test]
async fn send_route_update_splits_oversized_ipv4_mp_unreach_across_updates() {
    let (mut session, _rib_rx) = make_test_session_with_rib(65001, 65002);
    configure_scoped_link_local_peer(&mut session);
    let (client, mut server) = connected_stream_pair().await;
    session.test_install_stream(client);
    install_test_negotiated_session(&mut session, negotiated_session(65002, true));

    let count: u32 = 2000;
    let withdraw = (0..count)
        .map(|i| {
            (
                Prefix::V4(Ipv4Prefix::new(
                    Ipv4Addr::from(0x1400_0000_u32 | (i << 8)),
                    24,
                )),
                0,
            )
        })
        .collect();
    session.send_route_update(OutboundRouteUpdate {
        otc_blocked: vec![],
        withdraw,
        ..empty_outbound_update()
    });

    let mut seen = std::collections::HashSet::new();
    let mut updates = 0usize;
    while let Ok(raw) = tokio::time::timeout(
        Duration::from_millis(500),
        read_single_raw_bgp_message(&mut server),
    )
    .await
    {
        assert!(
            raw.len() <= 4096,
            "MP_UNREACH UPDATE is {} bytes",
            raw.len()
        );
        let mut buf = Bytes::from(raw);
        let Message::Update(update) =
            rustbgpd_wire::decode_message(&mut buf, rustbgpd_wire::MAX_MESSAGE_LEN).unwrap()
        else {
            continue;
        };
        let parsed = update.parse(true, false, &[]).unwrap();
        let mp = parsed
            .attributes
            .iter()
            .find_map(|attr| match attr {
                PathAttribute::MpUnreachNlri(mp) => Some(mp),
                _ => None,
            })
            .expect("Extended Next Hop withdrawal must use MP_UNREACH");
        assert_eq!((mp.afi, mp.safi), (Afi::Ipv4, Safi::Unicast));
        for entry in &mp.withdrawn {
            let Prefix::V4(prefix) = entry.prefix else {
                panic!("IPv4 MP_UNREACH contained non-IPv4 NLRI");
            };
            assert!(seen.insert(u32::from(prefix.addr)));
        }
        updates += 1;
    }
    assert!(updates >= 2, "oversized MP_UNREACH set was not split");
    assert_eq!(seen.len(), count as usize);
}

/// IPv6 unicast previously bypassed every size-aware sender: one large
/// `MP_REACH/MP_UNREACH` group reached `enqueue_bulk` after the RIB had already
/// committed the complete logical batch. Pin both directions at the standard
/// limit, then prove that the same announcement legitimately stays whole for
/// a peer advertising Extended Messages.
#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "one standard announce/withdraw plus extended-limit parity receipt"
)]
async fn send_route_update_chunks_ipv6_at_negotiated_message_limit() {
    let (mut session, _rib_rx) = make_test_session_with_rib(65001, 65002);
    session.config.route_server_client = true;
    let (client, mut server) = connected_stream_pair().await;
    session.test_install_stream(client);
    let mut negotiated = negotiated_session(65002, false);
    negotiated.negotiated_families = vec![(Afi::Ipv6, Safi::Unicast)];
    install_test_negotiated_session(&mut session, negotiated);

    let attrs = Arc::new(vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath {
            segments: vec![AsPathSegment::AsSequence(vec![65002])],
        }),
    ]);
    let count: u32 = 700;
    let prefix = |i: u32| {
        Ipv6Prefix::new(
            Ipv6Addr::from(0x2001_0db8_0001_0000_0000_0000_0000_0000_u128 + u128::from(i)),
            128,
        )
    };
    let routes: Vec<Route> = (0..count)
        .map(|i| Route {
            prefix: Prefix::V6(prefix(i)),
            next_hop: IpAddr::V6("2001:db8::2".parse().unwrap()),
            link_local_next_hop: None,
            next_hop_scope: None,
            peer: IpAddr::V6("2001:db8::2".parse().unwrap()),
            attributes: Arc::clone(&attrs),
            received_at: Instant::now(),
            origin_type: rustbgpd_rib::RouteOrigin::Ebgp,
            peer_router_id: Ipv4Addr::UNSPECIFIED,
            is_stale: false,
            is_llgr_stale: false,
            path_id: 0,
            validation_state: rustbgpd_wire::RpkiValidation::NotFound,
            aspa_state: rustbgpd_wire::AspaValidation::Unknown,
            aspa_context: rustbgpd_wire::AspaValidationContext::default(),
        })
        .collect();
    session.send_route_update(OutboundRouteUpdate {
        otc_blocked: vec![],
        announce: routes.clone().into(),
        next_hop_override: vec![None; count as usize].into(),
        ..empty_outbound_update()
    });

    let mut announced = std::collections::HashSet::new();
    let mut announce_updates = 0;
    while let Ok(raw) = tokio::time::timeout(
        Duration::from_millis(500),
        read_single_raw_bgp_message(&mut server),
    )
    .await
    {
        assert!(raw.len() <= 4096, "IPv6 UPDATE is {} bytes", raw.len());
        let mut buf = Bytes::from(raw);
        let Message::Update(update) =
            rustbgpd_wire::decode_message(&mut buf, rustbgpd_wire::MAX_MESSAGE_LEN).unwrap()
        else {
            continue;
        };
        let parsed = update.parse(true, false, &[]).unwrap();
        let mp = parsed.attributes.iter().find_map(|attr| match attr {
            PathAttribute::MpReachNlri(mp) => Some(mp),
            _ => None,
        });
        if let Some(mp) = mp {
            for entry in &mp.announced {
                assert!(announced.insert(entry.prefix));
            }
            announce_updates += 1;
        }
    }
    assert!(announce_updates >= 2);
    assert_eq!(announced.len(), count as usize);

    session.send_route_update(OutboundRouteUpdate {
        otc_blocked: vec![],
        withdraw: (0..count).map(|i| (Prefix::V6(prefix(i)), 0)).collect(),
        ..empty_outbound_update()
    });
    let mut withdrawn = std::collections::HashSet::new();
    let mut withdraw_updates = 0;
    while let Ok(raw) = tokio::time::timeout(
        Duration::from_millis(500),
        read_single_raw_bgp_message(&mut server),
    )
    .await
    {
        assert!(raw.len() <= 4096, "IPv6 withdrawal is {} bytes", raw.len());
        let mut buf = Bytes::from(raw);
        let Message::Update(update) =
            rustbgpd_wire::decode_message(&mut buf, rustbgpd_wire::MAX_MESSAGE_LEN).unwrap()
        else {
            continue;
        };
        let parsed = update.parse(true, false, &[]).unwrap();
        if let Some(mp) = parsed.attributes.iter().find_map(|attr| match attr {
            PathAttribute::MpUnreachNlri(mp) => Some(mp),
            _ => None,
        }) {
            for entry in &mp.withdrawn {
                assert!(withdrawn.insert(entry.prefix));
            }
            withdraw_updates += 1;
        }
    }
    assert!(withdraw_updates >= 2);
    assert_eq!(withdrawn.len(), count as usize);

    session.negotiated.as_mut().unwrap().peer_extended_message = true;
    session.send_route_update(OutboundRouteUpdate {
        otc_blocked: vec![],
        announce: routes.into(),
        next_hop_override: vec![None; count as usize].into(),
        ..empty_outbound_update()
    });
    let raw = tokio::time::timeout(
        Duration::from_secs(1),
        read_single_raw_bgp_message(&mut server),
    )
    .await
    .unwrap();
    assert!(raw.len() > 4096 && raw.len() <= 65_535);
    let mut buf = Bytes::from(raw);
    let Message::Update(update) =
        rustbgpd_wire::decode_message(&mut buf, rustbgpd_wire::EXTENDED_MAX_MESSAGE_LEN).unwrap()
    else {
        panic!("expected Extended Message IPv6 announcement UPDATE");
    };
    let parsed = update.parse(true, false, &[]).unwrap();
    let extended_announced = parsed
        .attributes
        .iter()
        .find_map(|attribute| match attribute {
            PathAttribute::MpReachNlri(mp) => Some(&mp.announced),
            _ => None,
        })
        .unwrap();
    assert_eq!(extended_announced.len(), count as usize);
    assert_eq!(
        extended_announced
            .iter()
            .map(|entry| entry.prefix)
            .collect::<std::collections::HashSet<_>>()
            .len(),
        count as usize
    );
    assert!(
        tokio::time::timeout(
            Duration::from_millis(200),
            read_single_raw_bgp_message(&mut server)
        )
        .await
        .is_err(),
        "Extended Message peer should receive this group in one UPDATE"
    );

    session.send_route_update(OutboundRouteUpdate {
        otc_blocked: vec![],
        withdraw: (0..count).map(|i| (Prefix::V6(prefix(i)), 0)).collect(),
        ..empty_outbound_update()
    });
    let raw = tokio::time::timeout(
        Duration::from_secs(1),
        read_single_raw_bgp_message(&mut server),
    )
    .await
    .unwrap();
    assert!(raw.len() > 4096 && raw.len() <= 65_535);
    let mut buf = Bytes::from(raw);
    let Message::Update(update) =
        rustbgpd_wire::decode_message(&mut buf, rustbgpd_wire::EXTENDED_MAX_MESSAGE_LEN).unwrap()
    else {
        panic!("expected Extended Message IPv6 withdrawal UPDATE");
    };
    let parsed = update.parse(true, false, &[]).unwrap();
    let extended_withdrawn = parsed
        .attributes
        .iter()
        .find_map(|attribute| match attribute {
            PathAttribute::MpUnreachNlri(mp) => Some(&mp.withdrawn),
            _ => None,
        })
        .unwrap();
    assert_eq!(extended_withdrawn.len(), count as usize);
    assert_eq!(
        extended_withdrawn
            .iter()
            .map(|entry| entry.prefix)
            .collect::<std::collections::HashSet<_>>()
            .len(),
        count as usize
    );
    assert!(
        tokio::time::timeout(
            Duration::from_millis(200),
            read_single_raw_bgp_message(&mut server)
        )
        .await
        .is_err(),
        "Extended Message peer should receive this withdrawal in one UPDATE"
    );
}

/// `FlowSpec`'s structured NLRI encoder is fallible, so batching must use
/// `try_build` while shrinking both total-message overflow and structured
/// encoding overflow. Cover v4/v6 announcements and withdrawals, plus the
/// Extended Message ceiling, without dropping or duplicating a rule.
#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "dual-family reach/unreach chunk receipt"
)]
async fn send_route_update_chunks_flowspec_without_infallible_build() {
    let (mut session, _rib_rx) = make_test_session_with_rib(65001, 65002);
    let (client, mut server) = connected_stream_pair().await;
    session.test_install_stream(client);
    let mut negotiated = negotiated_session(65002, false);
    negotiated.negotiated_families = vec![(Afi::Ipv4, Safi::FlowSpec), (Afi::Ipv6, Safi::FlowSpec)];
    install_test_negotiated_session(&mut session, negotiated);

    let count: u32 = 500;
    let rule = |afi: Afi, i: u32| FlowSpecRule {
        components: vec![FlowSpecComponent::DestinationPrefix(match afi {
            Afi::Ipv4 => {
                FlowSpecPrefix::V4(Ipv4Prefix::new(Ipv4Addr::from(0x0a00_0000_u32 + i), 32))
            }
            Afi::Ipv6 => FlowSpecPrefix::V6(Ipv6PrefixOffset {
                prefix: Ipv6Prefix::new(
                    Ipv6Addr::from(0x2001_0db8_0002_0000_0000_0000_0000_0000_u128 + u128::from(i)),
                    128,
                ),
                offset: 0,
            }),
            Afi::L2Vpn | Afi::BgpLs => unreachable!(),
        })],
    };
    let routes: Vec<FlowSpecRoute> = [Afi::Ipv4, Afi::Ipv6]
        .into_iter()
        .flat_map(|afi| {
            (0..count).map(move |i| FlowSpecRoute {
                rule: rule(afi, i),
                afi,
                peer: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
                attributes: vec![PathAttribute::Origin(Origin::Igp)],
                received_at: Instant::now(),
                origin_type: rustbgpd_rib::RouteOrigin::Ebgp,
                peer_router_id: Ipv4Addr::UNSPECIFIED,
                is_stale: false,
                is_llgr_stale: false,
                path_id: 0,
            })
        })
        .collect();
    session.send_route_update(OutboundRouteUpdate {
        otc_blocked: vec![],
        flowspec_announce: routes.clone(),
        ..empty_outbound_update()
    });
    let mut announced = std::collections::HashSet::new();
    let mut announce_updates = 0;
    while let Ok(raw) = tokio::time::timeout(
        Duration::from_millis(500),
        read_single_raw_bgp_message(&mut server),
    )
    .await
    {
        assert!(raw.len() <= 4096, "FlowSpec UPDATE is {} bytes", raw.len());
        let mut buf = Bytes::from(raw);
        let Message::Update(update) =
            rustbgpd_wire::decode_message(&mut buf, rustbgpd_wire::MAX_MESSAGE_LEN).unwrap()
        else {
            continue;
        };
        let parsed = update.parse(true, false, &[]).unwrap();
        if let Some(mp) = parsed.attributes.iter().find_map(|attr| match attr {
            PathAttribute::MpReachNlri(mp) => Some(mp),
            _ => None,
        }) {
            for rule in &mp.flowspec_announced {
                assert!(announced.insert(rule.clone()));
            }
            announce_updates += 1;
        }
    }
    assert!(announce_updates >= 3, "both family groups must be emitted");
    assert_eq!(announced.len(), (count * 2) as usize);

    session.send_route_update(OutboundRouteUpdate {
        otc_blocked: vec![],
        flowspec_withdraw: routes.iter().map(|route| route.rule.clone()).collect(),
        ..empty_outbound_update()
    });
    let mut withdrawn = std::collections::HashSet::new();
    let mut withdraw_updates = 0;
    while let Ok(raw) = tokio::time::timeout(
        Duration::from_millis(500),
        read_single_raw_bgp_message(&mut server),
    )
    .await
    {
        assert!(raw.len() <= 4096);
        let mut buf = Bytes::from(raw);
        let Message::Update(update) =
            rustbgpd_wire::decode_message(&mut buf, rustbgpd_wire::MAX_MESSAGE_LEN).unwrap()
        else {
            continue;
        };
        let parsed = update.parse(true, false, &[]).unwrap();
        if let Some(mp) = parsed.attributes.iter().find_map(|attr| match attr {
            PathAttribute::MpUnreachNlri(mp) => Some(mp),
            _ => None,
        }) {
            for rule in &mp.flowspec_withdrawn {
                assert!(withdrawn.insert(rule.clone()));
            }
            withdraw_updates += 1;
        }
    }
    assert!(withdraw_updates >= 3);
    assert_eq!(withdrawn.len(), (count * 2) as usize);

    session.negotiated.as_mut().unwrap().peer_extended_message = true;
    session.send_route_update(OutboundRouteUpdate {
        otc_blocked: vec![],
        flowspec_announce: routes,
        ..empty_outbound_update()
    });
    let first = tokio::time::timeout(
        Duration::from_secs(1),
        read_single_raw_bgp_message(&mut server),
    )
    .await
    .unwrap();
    let second = tokio::time::timeout(
        Duration::from_secs(1),
        read_single_raw_bgp_message(&mut server),
    )
    .await
    .unwrap();
    assert!(first.len() <= 65_535 && second.len() <= 65_535);
    assert!(
        tokio::time::timeout(
            Duration::from_millis(200),
            read_single_raw_bgp_message(&mut server)
        )
        .await
        .is_err(),
        "one Extended Message UPDATE per FlowSpec family expected"
    );
}
#[tokio::test]
async fn send_route_update_uses_ipv6_specific_next_hop_override() {
    let (mut session, _rib_rx) = make_test_session_with_rib(65001, 65002);
    let (client, mut server) = connected_stream_pair().await;
    session.test_install_stream(client);
    let mut negotiated = negotiated_session(65002, false);
    negotiated.negotiated_families = vec![(Afi::Ipv6, Safi::Unicast)];
    session
        .negotiated_families
        .clone_from(&negotiated.negotiated_families);
    session.negotiated = Some(negotiated);
    let route = make_v6_unicast_route("2001:db8::1".parse().unwrap());
    let override_nh =
        rustbgpd_policy::NextHopAction::Specific(IpAddr::V6("2001:db8::42".parse().unwrap()));
    session.send_route_update(OutboundRouteUpdate {
        otc_blocked: vec![],
        announce: vec![route].into(),
        withdraw: vec![],
        end_of_rib: vec![],
        refresh_markers: vec![],
        next_hop_override: vec![Some(override_nh)].into(),
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
        labeled_withdraw: vec![],
        rtc_withdraw: vec![],
        request_refresh_all_negotiated: false,
    });
    let Message::Update(msg) = read_single_bgp_message(&mut server).await else {
        panic!("expected UPDATE");
    };
    let parsed = msg.parse(true, false, &[]).unwrap();
    let mp = parsed
        .attributes
        .iter()
        .find_map(|a| match a {
            PathAttribute::MpReachNlri(mp) => Some(mp),
            _ => None,
        })
        .unwrap();
    assert_eq!(mp.next_hop, IpAddr::V6("2001:db8::42".parse().unwrap()));
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
    session.negotiated = Some(negotiated);
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
async fn otc_ingress_adds_remote_asn_for_route_from_provider_unicast() {
    for role in [BgpRole::Customer, BgpRole::Peer, BgpRole::RouteServerClient] {
        let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
        session.config.peer.local_role = Some(role);
        session.negotiated = Some(negotiated_session(65002, false));
        let prefix = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24);
        let attrs = vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath {
                segments: vec![AsPathSegment::AsSequence(vec![65002])],
            }),
            PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
        ];
        let update = UpdateMessage::build(
            &[Ipv4NlriEntry { path_id: 0, prefix }],
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
        assert_eq!(announced.len(), 1);
        assert!(
            announced[0]
                .attributes
                .iter()
                .any(|a| matches!(a, PathAttribute::OnlyToCustomer(65002))),
            "I3 must add OTC(remote AS) for local role {role:?} receiving untagged unicast"
        );
    }
}
#[tokio::test]
async fn otc_ingress_provider_drops_tagged_unicast_from_customer_but_keeps_withdrawals() {
    for role in [BgpRole::Provider, BgpRole::RouteServer] {
        let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
        session.config.peer.local_role = Some(role);
        session.negotiated = Some(negotiated_session(65002, false));
        let announced_prefix = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24);
        let withdrawn_prefix = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 0), 24);
        let attrs = vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath {
                segments: vec![AsPathSegment::AsSequence(vec![65002])],
            }),
            PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
            PathAttribute::OnlyToCustomer(65002),
        ];
        let update = UpdateMessage::build(
            &[Ipv4NlriEntry {
                path_id: 0,
                prefix: announced_prefix,
            }],
            &[Ipv4NlriEntry {
                path_id: 0,
                prefix: withdrawn_prefix,
            }],
            &attrs,
            true,
            false,
            Ipv4UnicastMode::Body,
        );
        session.process_update(update).await;
        let RibUpdate::RoutesReceived {
            announced,
            withdrawn,
            ..
        } = rib_rx.try_recv().unwrap()
        else {
            panic!("expected RoutesReceived");
        };
        assert!(
            announced.is_empty(),
            "I1 must drop tagged unicast announces for local role {role:?}"
        );
        assert_eq!(
            withdrawn,
            vec![(Prefix::V4(withdrawn_prefix), 0)],
            "I1 must preserve withdrawals from the same UPDATE for local role {role:?}"
        );
    }
}
#[tokio::test]
async fn otc_ingress_peer_drops_tagged_unicast_from_wrong_as() {
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    session.config.peer.local_role = Some(BgpRole::Peer);
    session.negotiated = Some(negotiated_session(65002, false));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24);
    let attrs = vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath {
            segments: vec![AsPathSegment::AsSequence(vec![65002])],
        }),
        PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
        PathAttribute::OnlyToCustomer(64512),
    ];
    let update = UpdateMessage::build(
        &[Ipv4NlriEntry { path_id: 0, prefix }],
        &[],
        &attrs,
        true,
        false,
        Ipv4UnicastMode::Body,
    );
    session.process_update(update).await;
    assert!(
        rib_rx.try_recv().is_err(),
        "I2 must drop tagged unicast announces whose OTC ASN is not the peer AS"
    );
}
#[tokio::test]
async fn otc_ingress_malformed_length_drops_unicast_announces_but_keeps_withdrawals() {
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    session.config.peer.local_role = Some(BgpRole::Provider);
    session.negotiated = Some(negotiated_session(65002, false));
    let announced_prefix = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24);
    let withdrawn_prefix = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 0), 24);
    let attrs = vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath {
            segments: vec![AsPathSegment::AsSequence(vec![65002])],
        }),
        PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
        PathAttribute::Unknown(rustbgpd_wire::RawAttribute {
            flags: rustbgpd_wire::constants::attr_flags::OPTIONAL
                | rustbgpd_wire::constants::attr_flags::TRANSITIVE,
            type_code: rustbgpd_wire::constants::attr_type::ONLY_TO_CUSTOMER,
            data: Bytes::from_static(&[0, 0, 0]),
        }),
    ];
    let update = UpdateMessage::build(
        &[Ipv4NlriEntry {
            path_id: 0,
            prefix: announced_prefix,
        }],
        &[Ipv4NlriEntry {
            path_id: 0,
            prefix: withdrawn_prefix,
        }],
        &attrs,
        true,
        false,
        Ipv4UnicastMode::Body,
    );
    session.process_update(update).await;
    let RibUpdate::RoutesReceived {
        announced,
        withdrawn,
        ..
    } = rib_rx.try_recv().unwrap()
    else {
        panic!("expected RoutesReceived");
    };
    assert!(
        announced.is_empty(),
        "malformed OTC length must use treat-as-withdraw behavior for unicast"
    );
    assert_eq!(withdrawn, vec![(Prefix::V4(withdrawn_prefix), 0)]);
}
// ---------------------------------------------------------------------
// ADR-0072 follow-up — structured OTC route-leak event publishing
// ---------------------------------------------------------------------
#[derive(Default)]
struct RecordingTransportSink {
    events: std::sync::Mutex<Vec<crate::event_sink::OtcRouteBlockedEvent>>,
}
impl RecordingTransportSink {
    fn snapshot(&self) -> Vec<crate::event_sink::OtcRouteBlockedEvent> {
        self.events.lock().unwrap().clone()
    }
}
impl crate::event_sink::TransportEventSink for RecordingTransportSink {
    fn publish_otc_route_blocked(&self, event: &crate::event_sink::OtcRouteBlockedEvent) {
        self.events.lock().unwrap().push(event.clone());
    }
}
fn install_recording_sink(session: &mut PeerSession) -> Arc<RecordingTransportSink> {
    let sink = Arc::new(RecordingTransportSink::default());
    session.set_event_sink(sink.clone());
    sink
}

#[test]
fn rib_staged_otc_denial_publishes_existing_egress_diagnostics() {
    let mut session = make_test_session(65001, 65002);
    session.config.peer.local_role = Some(BgpRole::Customer);
    session.negotiated = Some(negotiated_session(65002, false));
    let sink = install_recording_sink(&mut session);
    let route = replace_route_attrs(
        &make_route(100),
        vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath {
                segments: vec![AsPathSegment::AsSequence(vec![64512])],
            }),
            PathAttribute::OnlyToCustomer(64512),
        ],
    );
    let blocked_before = session.otc_routes_blocked;
    let mut update = empty_outbound_update();
    update.otc_blocked.push(route.clone());

    session.send_route_update(update);

    assert_eq!(session.otc_routes_blocked, blocked_before + 1);
    let events = sink.snapshot();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].direction, crate::event_sink::OtcDirection::Egress);
    assert_eq!(events[0].reason.as_str(), "egress_to_upstream_via_otc");
    assert_eq!(events[0].prefixes, vec![route.prefix.to_string()]);
    assert_eq!(events[0].otc_value, Some(64512));
}
#[tokio::test]
async fn otc_ingress_provider_publishes_structured_event() {
    // I1: Provider/RouteServer receives OTC-tagged unicast from a
    // Customer/RouteServerClient — the legacy counter increments and
    // a single `OtcRouteBlockedEvent` should be published with the
    // matching reason, the announced prefixes, both role labels, and
    // the decoded OTC value.
    let (mut session, _rib_rx) = make_test_session_with_rib(65001, 65002);
    session.config.peer.local_role = Some(BgpRole::Provider);
    session.negotiated = Some(negotiated_session(65002, false));
    let sink = install_recording_sink(&mut session);
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24);
    let attrs = vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath {
            segments: vec![AsPathSegment::AsSequence(vec![65002, 64999])],
        }),
        PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
        PathAttribute::OnlyToCustomer(65002),
    ];
    let update = UpdateMessage::build(
        &[Ipv4NlriEntry { path_id: 0, prefix }],
        &[],
        &attrs,
        true,
        false,
        Ipv4UnicastMode::Body,
    );
    session.process_update(update).await;
    let events = sink.snapshot();
    assert_eq!(events.len(), 1, "exactly one event per blocked UPDATE");
    let event = &events[0];
    assert_eq!(event.reason.as_str(), "ingress_from_customer_rsclient");
    assert_eq!(event.direction, crate::event_sink::OtcDirection::Ingress);
    assert_eq!(event.prefixes, vec![prefix.to_string()]);
    assert_eq!(event.local_role, Some(BgpRole::Provider));
    assert_eq!(event.otc_value, Some(65002));
    // AS_PATH stays lossless via `to_aspath_string`.
    assert_eq!(event.as_path, "65002 64999");
}
#[tokio::test]
async fn otc_ingress_peer_mismatch_publishes_structured_event() {
    // I2: Peer role with OTC ASN != peer ASN.
    let (mut session, _rib_rx) = make_test_session_with_rib(65001, 65002);
    session.config.peer.local_role = Some(BgpRole::Peer);
    session.negotiated = Some(negotiated_session(65002, false));
    let sink = install_recording_sink(&mut session);
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24);
    let attrs = vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath {
            segments: vec![AsPathSegment::AsSequence(vec![65002])],
        }),
        PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
        // OTC ASN 64512 disagrees with the peer's negotiated ASN
        // (65002). RFC 9234 §5 says to reject.
        PathAttribute::OnlyToCustomer(64512),
    ];
    let update = UpdateMessage::build(
        &[Ipv4NlriEntry { path_id: 0, prefix }],
        &[],
        &attrs,
        true,
        false,
        Ipv4UnicastMode::Body,
    );
    session.process_update(update).await;
    let events = sink.snapshot();
    assert_eq!(events.len(), 1);
    let event = &events[0];
    assert_eq!(event.reason.as_str(), "ingress_peer_mismatch");
    assert_eq!(event.otc_value, Some(64512));
    assert_eq!(event.local_role, Some(BgpRole::Peer));
}
#[tokio::test]
async fn otc_ingress_malformed_publishes_structured_event_with_no_otc_value() {
    // Malformed OTC length: the codec cannot decode an ASN, so the
    // event's otc_value field is None.
    let (mut session, _rib_rx) = make_test_session_with_rib(65001, 65002);
    session.config.peer.local_role = Some(BgpRole::Provider);
    session.negotiated = Some(negotiated_session(65002, false));
    let sink = install_recording_sink(&mut session);
    let announced_prefix = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24);
    let attrs = vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath {
            segments: vec![AsPathSegment::AsSequence(vec![65002])],
        }),
        PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
        PathAttribute::Unknown(rustbgpd_wire::RawAttribute {
            flags: rustbgpd_wire::constants::attr_flags::OPTIONAL
                | rustbgpd_wire::constants::attr_flags::TRANSITIVE,
            type_code: rustbgpd_wire::constants::attr_type::ONLY_TO_CUSTOMER,
            data: Bytes::from_static(&[0, 0, 0]),
        }),
    ];
    let update = UpdateMessage::build(
        &[Ipv4NlriEntry {
            path_id: 0,
            prefix: announced_prefix,
        }],
        &[],
        &attrs,
        true,
        false,
        Ipv4UnicastMode::Body,
    );
    session.process_update(update).await;
    let events = sink.snapshot();
    assert_eq!(events.len(), 1);
    let event = &events[0];
    assert_eq!(event.reason.as_str(), "malformed_length");
    assert!(
        event.otc_value.is_none(),
        "malformed_length must not surface a decoded OTC value"
    );
}
#[tokio::test]
async fn otc_ingress_event_collects_mp_reach_v6_prefixes() {
    // Regression: the event's prefix list must include IPv6 unicast
    // MP_REACH_NLRI announcements, not just IPv4 body NLRI. Otherwise
    // an operator reading the event would see "blocked 0 prefixes" on
    // an IPv6-only OTC violation.
    let (mut session, _rib_rx) = make_test_session_with_rib(65001, 65002);
    session.config.peer.local_role = Some(BgpRole::Provider);
    session.negotiated = Some(negotiated_session(65002, false));
    let sink = install_recording_sink(&mut session);
    let v6_prefix = Ipv6Prefix::new(std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0), 32);
    let mp_reach = rustbgpd_wire::MpReachNlri {
        afi: Afi::Ipv6,
        safi: Safi::Unicast,
        next_hop: IpAddr::V6(std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
        link_local_next_hop: None,
        announced: vec![rustbgpd_wire::NlriEntry {
            path_id: 0,
            prefix: Prefix::V6(v6_prefix),
        }],
        flowspec_announced: vec![],
        evpn_announced: vec![],
        bgpls_announced: vec![],
        labeled_announced: vec![],
        vpn_announced: vec![],
        rtc_announced: vec![],
    };
    let attrs = vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath {
            segments: vec![AsPathSegment::AsSequence(vec![65002])],
        }),
        PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
        PathAttribute::OnlyToCustomer(65002),
        PathAttribute::MpReachNlri(mp_reach),
    ];
    let update = UpdateMessage::build(&[], &[], &attrs, true, false, Ipv4UnicastMode::Body);
    session.process_update(update).await;
    let events = sink.snapshot();
    assert_eq!(events.len(), 1);
    assert!(
        events[0]
            .prefixes
            .iter()
            .any(|p| p == &v6_prefix.to_string()),
        "OtcRouteBlockedEvent must surface MP_REACH IPv6 announcements"
    );
}
#[tokio::test]
async fn otc_ingress_skips_event_when_rejected_count_is_zero() {
    // Regression: a malformed-length OTC UPDATE that carries only
    // withdrawals (no announced unicast) must not produce a
    // zero-count OtcRouteBlockedEvent — the proto contract is
    // "blocks one or more unicast routes". The withdrawal still
    // processes through the normal path; only the structured event
    // and the per-peer counter bump are skipped.
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    session.config.peer.local_role = Some(BgpRole::Provider);
    session.negotiated = Some(negotiated_session(65002, false));
    let sink = install_recording_sink(&mut session);
    let baseline_blocked = session.otc_routes_blocked;
    let withdrawn_prefix = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 0), 24);
    let attrs = vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath {
            segments: vec![AsPathSegment::AsSequence(vec![65002])],
        }),
        PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
        PathAttribute::Unknown(rustbgpd_wire::RawAttribute {
            flags: rustbgpd_wire::constants::attr_flags::OPTIONAL
                | rustbgpd_wire::constants::attr_flags::TRANSITIVE,
            type_code: rustbgpd_wire::constants::attr_type::ONLY_TO_CUSTOMER,
            data: Bytes::from_static(&[0, 0, 0]),
        }),
    ];
    // No announced NLRI — only the withdrawal.
    let update = UpdateMessage::build(
        &[],
        &[Ipv4NlriEntry {
            path_id: 0,
            prefix: withdrawn_prefix,
        }],
        &attrs,
        true,
        false,
        Ipv4UnicastMode::Body,
    );
    session.process_update(update).await;
    assert!(
        sink.snapshot().is_empty(),
        "no announced unicast → no structured OtcRouteBlockedEvent"
    );
    assert_eq!(
        session.otc_routes_blocked, baseline_blocked,
        "rejected=0 must not bump the per-peer counter"
    );
    // Withdrawal still surfaces through the RIB path.
    let RibUpdate::RoutesReceived { withdrawn, .. } = rib_rx.try_recv().unwrap() else {
        panic!("expected RoutesReceived");
    };
    assert_eq!(withdrawn, vec![(Prefix::V4(withdrawn_prefix), 0)]);
}
#[tokio::test]
async fn otc_ingress_no_event_when_no_decision() {
    // Untagged UPDATE from a customer arrives at a Customer-role
    // local — no OTC rule fires, so the sink must stay empty.
    let (mut session, _rib_rx) = make_test_session_with_rib(65001, 65002);
    session.config.peer.local_role = Some(BgpRole::Customer);
    session.negotiated = Some(negotiated_session(65002, false));
    let sink = install_recording_sink(&mut session);
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24);
    let attrs = vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath {
            segments: vec![AsPathSegment::AsSequence(vec![65002])],
        }),
        PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
    ];
    let update = UpdateMessage::build(
        &[Ipv4NlriEntry { path_id: 0, prefix }],
        &[],
        &attrs,
        true,
        false,
        Ipv4UnicastMode::Body,
    );
    session.process_update(update).await;
    assert!(
        sink.snapshot().is_empty(),
        "OTC sink must stay silent when no decision fired"
    );
}
#[tokio::test]
async fn process_update_accepts_ipv4_mp_link_local_for_scoped_unnumbered_peer() {
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    configure_scoped_link_local_peer(&mut session);
    let negotiated = negotiated_session(65002, true);
    session
        .negotiated_families
        .clone_from(&negotiated.negotiated_families);
    session.negotiated = Some(negotiated);
    let next_hop: Ipv6Addr = "fe80::1".parse().unwrap();
    let attrs = vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath {
            segments: vec![AsPathSegment::AsSequence(vec![65002])],
        }),
        PathAttribute::MpReachNlri(MpReachNlri {
            afi: Afi::Ipv4,
            safi: Safi::Unicast,
            next_hop: IpAddr::V6(next_hop),
            link_local_next_hop: Some(next_hop),
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
    assert_eq!(announced[0].next_hop, IpAddr::V6(next_hop));
    assert_eq!(announced[0].link_local_next_hop, Some(next_hop));
    let scope = announced[0]
        .next_hop_scope
        .as_ref()
        .expect("link-local next-hop must carry scope toward FIB");
    assert_eq!(scope.interface.as_ref(), "eth1");
    assert_eq!(scope.ifindex, 7);
}
#[tokio::test]
async fn import_policy_next_hop_rewrite_clears_ipv4_mp_link_local_companion() {
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    configure_scoped_link_local_peer(&mut session);
    let negotiated = negotiated_session(65002, true);
    session
        .negotiated_families
        .clone_from(&negotiated.negotiated_families);
    session.negotiated = Some(negotiated);
    let replacement_next_hop: IpAddr = "2001:db8::99".parse().unwrap();
    session.install_import_policy(Some(PolicyChain::new(vec![Policy {
        entries: vec![PolicyStatement {
            prefix: None,
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
                set_next_hop: Some(rustbgpd_policy::NextHopAction::Specific(
                    replacement_next_hop,
                )),
                ..Default::default()
            },
        }],
        default_action: PolicyAction::Deny,
    }])));
    let received_next_hop: Ipv6Addr = "fe80::1".parse().unwrap();
    let attrs = vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath {
            segments: vec![AsPathSegment::AsSequence(vec![65002])],
        }),
        PathAttribute::MpReachNlri(MpReachNlri {
            afi: Afi::Ipv4,
            safi: Safi::Unicast,
            next_hop: IpAddr::V6(received_next_hop),
            link_local_next_hop: Some(received_next_hop),
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
    assert_eq!(announced[0].next_hop, replacement_next_hop);
    assert_eq!(announced[0].link_local_next_hop, None);
    assert_eq!(announced[0].next_hop_scope, None);
}
#[tokio::test]
async fn process_update_rejects_ipv4_mp_link_local_without_extended_nexthop() {
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    configure_scoped_link_local_peer(&mut session);
    let negotiated = negotiated_session(65002, false);
    session
        .negotiated_families
        .clone_from(&negotiated.negotiated_families);
    session.negotiated = Some(negotiated);
    let next_hop: Ipv6Addr = "fe80::1".parse().unwrap();
    let attrs = vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath {
            segments: vec![AsPathSegment::AsSequence(vec![65002])],
        }),
        PathAttribute::MpReachNlri(MpReachNlri {
            afi: Afi::Ipv4,
            safi: Safi::Unicast,
            next_hop: IpAddr::V6(next_hop),
            link_local_next_hop: Some(next_hop),
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
    // Fail closed on the route, gracefully: a scoped link-local peer that did
    // not negotiate Extended Next Hop must not import an IPv4-over-IPv6
    // link-local MP_REACH (no route reaches the RIB), but the route is dropped
    // per-route (ignore + WARN at the ENH gate), not by tearing the session
    // down with a NOTIFICATION. Pinning both ends guards against a regression in
    // either direction — silently accepting the route, or escalating to a
    // session reset. The positive case is covered by
    // `process_update_accepts_ipv4_mp_link_local_for_scoped_unnumbered_peer`.
    assert!(rib_rx.try_recv().is_err(), "no route may reach the RIB");
    assert_eq!(
        session.notifications_sent, 0,
        "the route is dropped at the Extended-Next-Hop gate, not via NOTIFICATION"
    );
}
#[tokio::test]
async fn process_update_ignores_ipv4_body_nlri_for_scoped_unnumbered_peer() {
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    configure_scoped_link_local_peer(&mut session);
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
        PathAttribute::NextHop(Ipv4Addr::new(192, 0, 2, 1)),
    ];
    let update = UpdateMessage::build(
        &[],
        &[Ipv4NlriEntry {
            path_id: 0,
            prefix: Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24),
        }],
        &attrs,
        true,
        false,
        Ipv4UnicastMode::Body,
    );
    session.process_update(update).await;
    assert!(
        rib_rx.try_recv().is_err(),
        "scoped link-local peers must not import IPv4 body NLRI"
    );
}
#[tokio::test]
async fn route_server_client_extended_nexthop_preserves_ipv6_next_hop() {
    let (mut session, _rib_rx) = make_test_session_with_rib(65001, 65002);
    let (client, mut server) = connected_stream_pair().await;
    session.test_install_stream(client);
    session.config.route_server_client = true;
    let negotiated = negotiated_session(65002, true);
    session
        .negotiated_families
        .clone_from(&negotiated.negotiated_families);
    session.negotiated = Some(negotiated);
    let v6_nh: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let update = OutboundRouteUpdate {
        otc_blocked: vec![],
        announce: vec![Route {
            prefix: Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24)),
            next_hop: IpAddr::V6(v6_nh),
            link_local_next_hop: None,
            next_hop_scope: None,
            peer: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            attributes: Arc::new(vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath {
                    segments: vec![AsPathSegment::AsSequence(vec![65002])],
                }),
            ]),
            received_at: Instant::now(),
            origin_type: rustbgpd_rib::RouteOrigin::Ebgp,
            peer_router_id: Ipv4Addr::UNSPECIFIED,
            is_stale: false,
            is_llgr_stale: false,
            path_id: 0,
            validation_state: rustbgpd_wire::RpkiValidation::NotFound,
            aspa_state: rustbgpd_wire::AspaValidation::Unknown,
            aspa_context: rustbgpd_wire::AspaValidationContext::default(),
        }]
        .into(),
        withdraw: vec![],
        end_of_rib: vec![],
        refresh_markers: vec![],
        next_hop_override: vec![None].into(),
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
        labeled_withdraw: vec![],
        rtc_withdraw: vec![],
        request_refresh_all_negotiated: false,
    };
    session.send_route_update(update);
    let Message::Update(msg) = read_single_bgp_message(&mut server).await else {
        panic!("expected UPDATE");
    };
    let parsed = msg.parse(true, false, &[]).unwrap();
    let mp = parsed
        .attributes
        .iter()
        .find_map(|a| match a {
            PathAttribute::MpReachNlri(mp) => Some(mp),
            _ => None,
        })
        .unwrap();
    assert_eq!(mp.afi, Afi::Ipv4);
    assert_eq!(mp.safi, Safi::Unicast);
    assert_eq!(mp.next_hop, IpAddr::V6(v6_nh));
}
#[tokio::test]
async fn unnumbered_ipv4_extended_nexthop_sends_link_local_mp_reach() {
    let (mut session, _rib_rx) = make_test_session_with_rib(65001, 65002);
    configure_scoped_link_local_peer(&mut session);
    session.config.local_ipv6_nexthop = Some("fe80::1".parse().unwrap());
    let (client, mut server) = connected_stream_pair().await;
    session.test_install_stream(client);
    let negotiated = negotiated_session(65002, true);
    session
        .negotiated_families
        .clone_from(&negotiated.negotiated_families);
    session.negotiated = Some(negotiated);
    let update = OutboundRouteUpdate {
        otc_blocked: vec![],
        announce: vec![make_route(100)].into(),
        withdraw: vec![],
        end_of_rib: vec![],
        refresh_markers: vec![],
        next_hop_override: vec![None].into(),
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
        labeled_withdraw: vec![],
        rtc_withdraw: vec![],
        request_refresh_all_negotiated: false,
    };
    session.send_route_update(update);
    let Message::Update(msg) = read_single_bgp_message(&mut server).await else {
        panic!("expected UPDATE");
    };
    let parsed = msg.parse(true, false, &[]).unwrap();
    let mp = parsed
        .attributes
        .iter()
        .find_map(|a| match a {
            PathAttribute::MpReachNlri(mp) => Some(mp),
            _ => None,
        })
        .expect("IPv4 unnumbered must use MP_REACH");
    let link_local: Ipv6Addr = "fe80::1".parse().unwrap();
    assert_eq!(mp.afi, Afi::Ipv4);
    assert_eq!(mp.safi, Safi::Unicast);
    assert_eq!(mp.next_hop, IpAddr::V6(link_local));
    assert_eq!(mp.link_local_next_hop, Some(link_local));
}
#[tokio::test]
async fn unnumbered_ipv4_recomputes_link_local_companion_after_next_hop_self() {
    let (mut session, _rib_rx) = make_test_session_with_rib(65001, 65002);
    configure_scoped_link_local_peer(&mut session);
    session.config.local_ipv6_nexthop = Some("fe80::1".parse().unwrap());
    let (client, mut server) = connected_stream_pair().await;
    session.test_install_stream(client);
    let negotiated = negotiated_session(65002, true);
    session
        .negotiated_families
        .clone_from(&negotiated.negotiated_families);
    session.negotiated = Some(negotiated);
    let remote_ll: Ipv6Addr = "fe80::2".parse().unwrap();
    let mut route = make_route(100);
    route.next_hop = IpAddr::V6(remote_ll);
    route.link_local_next_hop = Some(remote_ll);
    let update = OutboundRouteUpdate {
        otc_blocked: vec![],
        announce: vec![route].into(),
        withdraw: vec![],
        end_of_rib: vec![],
        refresh_markers: vec![],
        next_hop_override: vec![None].into(),
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
        labeled_withdraw: vec![],
        rtc_withdraw: vec![],
        request_refresh_all_negotiated: false,
    };
    session.send_route_update(update);
    let Message::Update(msg) = read_single_bgp_message(&mut server).await else {
        panic!("expected UPDATE");
    };
    let parsed = msg.parse(true, false, &[]).unwrap();
    let mp = parsed
        .attributes
        .iter()
        .find_map(|a| match a {
            PathAttribute::MpReachNlri(mp) => Some(mp),
            _ => None,
        })
        .expect("IPv4 unnumbered must use MP_REACH");
    let local_ll: Ipv6Addr = "fe80::1".parse().unwrap();
    assert_eq!(mp.next_hop, IpAddr::V6(local_ll));
    assert_eq!(
        mp.link_local_next_hop,
        Some(local_ll),
        "next-hop-self must not preserve the original remote link-local companion"
    );
}
#[tokio::test]
async fn extended_nexthop_clears_companion_when_primary_next_hop_is_rewritten() {
    let (mut session, _rib_rx) = make_test_session_with_rib(65001, 65002);
    session.config.local_ipv6_nexthop = Some("2001:db8::1".parse().unwrap());
    let (client, mut server) = connected_stream_pair().await;
    session.test_install_stream(client);
    let negotiated = negotiated_session(65002, true);
    session
        .negotiated_families
        .clone_from(&negotiated.negotiated_families);
    session.negotiated = Some(negotiated);
    let mut route = make_route(100);
    route.next_hop = IpAddr::V6("2001:db8::2".parse().unwrap());
    route.link_local_next_hop = Some("fe80::2".parse().unwrap());
    let update = OutboundRouteUpdate {
        otc_blocked: vec![],
        announce: vec![route].into(),
        withdraw: vec![],
        end_of_rib: vec![],
        refresh_markers: vec![],
        next_hop_override: vec![None].into(),
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
        labeled_withdraw: vec![],
        rtc_withdraw: vec![],
        request_refresh_all_negotiated: false,
    };
    session.send_route_update(update);
    let Message::Update(msg) = read_single_bgp_message(&mut server).await else {
        panic!("expected UPDATE");
    };
    let parsed = msg.parse(true, false, &[]).unwrap();
    let mp = parsed
        .attributes
        .iter()
        .find_map(|a| match a {
            PathAttribute::MpReachNlri(mp) => Some(mp),
            _ => None,
        })
        .expect("IPv4 extended next-hop must use MP_REACH");
    assert_eq!(mp.next_hop, IpAddr::V6("2001:db8::1".parse().unwrap()));
    assert_eq!(
        mp.link_local_next_hop, None,
        "stale link-local companion must be cleared when the primary next-hop changes"
    );
}
#[tokio::test]
async fn unnumbered_ipv4_without_extended_nexthop_does_not_fallback_to_body_nlri() {
    let (mut session, _rib_rx) = make_test_session_with_rib(65001, 65002);
    configure_scoped_link_local_peer(&mut session);
    let (client, mut server) = connected_stream_pair().await;
    session.test_install_stream(client);
    let negotiated = negotiated_session(65002, false);
    session
        .negotiated_families
        .clone_from(&negotiated.negotiated_families);
    session.negotiated = Some(negotiated);
    let update = OutboundRouteUpdate {
        otc_blocked: vec![],
        announce: vec![make_route(100)].into(),
        withdraw: vec![],
        end_of_rib: vec![],
        refresh_markers: vec![],
        next_hop_override: vec![None].into(),
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
        labeled_withdraw: vec![],
        rtc_withdraw: vec![],
        request_refresh_all_negotiated: false,
    };
    session.send_route_update(update);
    let mut header = [0_u8; 19];
    let result =
        tokio::time::timeout(Duration::from_millis(100), server.read_exact(&mut header)).await;
    assert!(
        result.is_err(),
        "scoped link-local peer must fail closed instead of sending IPv4 body NLRI"
    );
}
#[tokio::test]
async fn route_server_client_ipv6_preserves_next_hop() {
    let (mut session, _rib_rx) = make_test_session_with_rib(65001, 65002);
    let (client, mut server) = connected_stream_pair().await;
    session.test_install_stream(client);
    session.config.route_server_client = true;
    let mut negotiated = negotiated_session(65002, false);
    negotiated.negotiated_families = vec![(Afi::Ipv6, Safi::Unicast)];
    session
        .negotiated_families
        .clone_from(&negotiated.negotiated_families);
    session.negotiated = Some(negotiated);
    let v6_nh: Ipv6Addr = "2001:db8::2".parse().unwrap();
    let update = OutboundRouteUpdate {
        otc_blocked: vec![],
        announce: vec![Route {
            prefix: Prefix::V6(Ipv6Prefix::new(v6_nh, 64)),
            next_hop: IpAddr::V6(v6_nh),
            link_local_next_hop: None,
            next_hop_scope: None,
            peer: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            attributes: Arc::new(vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath {
                    segments: vec![AsPathSegment::AsSequence(vec![65002])],
                }),
            ]),
            received_at: Instant::now(),
            origin_type: rustbgpd_rib::RouteOrigin::Ebgp,
            peer_router_id: Ipv4Addr::UNSPECIFIED,
            is_stale: false,
            is_llgr_stale: false,
            path_id: 0,
            validation_state: rustbgpd_wire::RpkiValidation::NotFound,
            aspa_state: rustbgpd_wire::AspaValidation::Unknown,
            aspa_context: rustbgpd_wire::AspaValidationContext::default(),
        }]
        .into(),
        withdraw: vec![],
        end_of_rib: vec![],
        refresh_markers: vec![],
        next_hop_override: vec![None].into(),
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
        labeled_withdraw: vec![],
        rtc_withdraw: vec![],
        request_refresh_all_negotiated: false,
    };
    session.send_route_update(update);
    let Message::Update(msg) = read_single_bgp_message(&mut server).await else {
        panic!("expected UPDATE");
    };
    let parsed = msg.parse(true, false, &[]).unwrap();
    let mp = parsed
        .attributes
        .iter()
        .find_map(|a| match a {
            PathAttribute::MpReachNlri(mp) => Some(mp),
            _ => None,
        })
        .unwrap();
    assert_eq!(mp.afi, Afi::Ipv6);
    assert_eq!(mp.safi, Safi::Unicast);
    assert_eq!(mp.next_hop, IpAddr::V6(v6_nh));
    assert_eq!(mp.link_local_next_hop, None);
}
#[tokio::test]
async fn ipv6_next_hop_self_clears_stale_link_local_companion() {
    let (mut session, _rib_rx) = make_test_session_with_rib(65001, 65002);
    let (client, mut server) = connected_stream_pair().await;
    session.test_install_stream(client);
    session.config.local_ipv6_nexthop = Some("2001:db8::1".parse().unwrap());
    let mut negotiated = negotiated_session(65002, false);
    negotiated.negotiated_families = vec![(Afi::Ipv6, Safi::Unicast)];
    session
        .negotiated_families
        .clone_from(&negotiated.negotiated_families);
    session.negotiated = Some(negotiated);
    let remote_global: Ipv6Addr = "2001:db8::2".parse().unwrap();
    let mut route = make_v6_unicast_route(remote_global);
    route.link_local_next_hop = Some("fe80::2".parse().unwrap());
    let update = OutboundRouteUpdate {
        otc_blocked: vec![],
        announce: vec![route].into(),
        withdraw: vec![],
        end_of_rib: vec![],
        refresh_markers: vec![],
        next_hop_override: vec![None].into(),
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
        labeled_withdraw: vec![],
        rtc_withdraw: vec![],
        request_refresh_all_negotiated: false,
    };
    session.send_route_update(update);
    let Message::Update(msg) = read_single_bgp_message(&mut server).await else {
        panic!("expected UPDATE");
    };
    let parsed = msg.parse(true, false, &[]).unwrap();
    let mp = parsed
        .attributes
        .iter()
        .find_map(|a| match a {
            PathAttribute::MpReachNlri(mp) => Some(mp),
            _ => None,
        })
        .unwrap();
    assert_eq!(mp.afi, Afi::Ipv6);
    assert_eq!(mp.safi, Safi::Unicast);
    assert_eq!(mp.next_hop, IpAddr::V6("2001:db8::1".parse().unwrap()));
    assert_eq!(
        mp.link_local_next_hop, None,
        "IPv6 next-hop-self must not preserve an upstream link-local companion"
    );
}
#[tokio::test]
async fn scoped_peer_does_not_send_ipv6_unicast_with_link_local_primary_next_hop() {
    let (mut session, _rib_rx) = make_test_session_with_rib(65001, 65001);
    configure_scoped_link_local_peer(&mut session);
    session.config.local_ipv6_nexthop = Some("fe80::1".parse().unwrap());
    let (client, mut server) = connected_stream_pair().await;
    session.test_install_stream(client);
    let mut negotiated = negotiated_session(65001, false);
    negotiated.negotiated_families = vec![(Afi::Ipv6, Safi::Unicast)];
    session
        .negotiated_families
        .clone_from(&negotiated.negotiated_families);
    session.negotiated = Some(negotiated);
    let route_next_hop = "2001:db8::2".parse().unwrap();
    let update = OutboundRouteUpdate {
        otc_blocked: vec![],
        announce: vec![make_v6_unicast_route(route_next_hop)].into(),
        withdraw: vec![],
        end_of_rib: vec![],
        refresh_markers: vec![],
        next_hop_override: vec![Some(rustbgpd_policy::NextHopAction::Self_)].into(),
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
        labeled_withdraw: vec![],
        rtc_withdraw: vec![],
        request_refresh_all_negotiated: false,
    };
    session.send_route_update(update);
    let Message::Update(msg) = read_single_bgp_message(&mut server).await else {
        panic!("expected UPDATE");
    };
    let parsed = msg.parse(true, false, &[]).unwrap();
    let mp = parsed
        .attributes
        .iter()
        .find_map(|a| match a {
            PathAttribute::MpReachNlri(mp) => Some(mp),
            _ => None,
        })
        .unwrap();
    assert_eq!(mp.next_hop, IpAddr::V6(route_next_hop));
    assert_eq!(
        mp.link_local_next_hop, None,
        "IPv6 unicast must not reuse the IPv4 ENHE scoped link-local relaxation"
    );
}
/// Import policy is applied before `RoutesReceived` reaches the RIB.
/// Denied routes are filtered locally in transport and never forwarded.
#[tokio::test]
async fn import_policy_denied_routes_do_not_reach_rib() {
    // Create a session with import policy that denies 198.51.100.0/24
    let mut peer_config = PeerConfig::new(65001, 65002, Ipv4Addr::new(10, 0, 0, 1));
    peer_config.connect_retry_secs = 30;
    peer_config.families = vec![(Afi::Ipv4, Safi::Unicast)];
    peer_config.gr_restart_time = 120;
    let config = TransportConfig::new(peer_config, "10.0.0.2:179".parse().unwrap());
    let metrics = BgpMetrics::new();
    let (_cmd_tx, cmd_rx) = mpsc::channel(8);
    let (rib_tx, mut rib_rx) = mpsc::channel(64);
    let deny_policy = PolicyChain::new(vec![Policy {
        entries: vec![PolicyStatement {
            prefix: Some(Prefix::V4(Ipv4Prefix::new(
                Ipv4Addr::new(198, 51, 100, 0),
                24,
            ))),
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
        Some(deny_policy),
        None,
        None,
        None,
        None,
        false,
    );
    let mut negotiated = negotiated_session(65002, false);
    negotiated.peer_enhanced_route_refresh = true;
    session
        .negotiated_families
        .clone_from(&negotiated.negotiated_families);
    session.negotiated = Some(negotiated);
    // Send an UPDATE with 198.51.100.0/24 — should be denied by import policy
    let denied_prefix = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 0), 24);
    let permitted_prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, 0), 24);
    let attrs = vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath {
            segments: vec![AsPathSegment::AsSequence(vec![65002])],
        }),
        PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
    ];
    // Both prefixes in one UPDATE: one permitted, one denied
    let denied_nlri = Ipv4NlriEntry {
        path_id: 0,
        prefix: denied_prefix,
    };
    let permitted_nlri = Ipv4NlriEntry {
        path_id: 0,
        prefix: permitted_prefix,
    };
    let update = UpdateMessage::build(
        &[denied_nlri, permitted_nlri],
        &[],
        &attrs,
        true,
        false,
        Ipv4UnicastMode::Body,
    );
    session.process_update(update).await;
    assert_eq!(session.import_policy_routes_permitted, 1);
    assert_eq!(session.import_policy_routes_denied, 1);
    // Drain any messages — there may be zero or one RoutesReceived
    let mut all_announced = vec![];
    while let Ok(msg) = rib_rx.try_recv() {
        if let RibUpdate::RoutesReceived { announced, .. } = msg {
            all_announced.extend(announced);
        }
    }
    // Only the permitted prefix should reach the RIB; denied prefix filtered
    assert_eq!(
        all_announced.len(),
        1,
        "expected exactly 1 announced route, got {}: {all_announced:?}",
        all_announced.len()
    );
    assert_eq!(all_announced[0].prefix, Prefix::V4(permitted_prefix));
}

/// LAN-291: a `FlowSpec` rule without a destination-prefix component is
/// `prefix = None` in the import policy context — prefix-based deny terms
/// (including exact-default ones) must not match it, while a rule with a
/// real destination prefix still evaluates that prefix. Covers IPv4 and
/// IPv6 `FlowSpec`.
#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "covers destination-less v4 + v6 rules and a real-prefix deny in one session scenario"
)]
async fn import_policy_prefix_term_does_not_match_destination_less_flowspec() {
    use rustbgpd_wire::attribute::MpReachNlri;

    let destless_rule = |protocol: u8| FlowSpecRule {
        components: vec![FlowSpecComponent::IpProtocol(vec![NumericMatch {
            end_of_list: true,
            and_bit: false,
            lt: false,
            gt: false,
            eq: true,
            value: u64::from(protocol),
        }])],
    };
    let deny = |prefix: Prefix| PolicyStatement {
        prefix: Some(prefix),
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
        match_local_pref_ge: None,
        match_local_pref_le: None,
        match_med_ge: None,
        match_med_le: None,
        match_next_hop: None,
        modifications: RouteModifications::default(),
    };

    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    session.install_import_policy(Some(PolicyChain::new(vec![Policy {
        entries: vec![
            deny(Prefix::V4(Ipv4Prefix::new(Ipv4Addr::UNSPECIFIED, 0))),
            deny(Prefix::V6(Ipv6Prefix::new(Ipv6Addr::UNSPECIFIED, 0))),
            deny(Prefix::V4(Ipv4Prefix::new(
                Ipv4Addr::new(198, 51, 100, 0),
                24,
            ))),
        ],
        default_action: PolicyAction::Permit,
    }])));
    session.negotiated = Some(negotiated_session(65002, false));
    session.negotiated_families = vec![(Afi::Ipv4, Safi::FlowSpec), (Afi::Ipv6, Safi::FlowSpec)];

    let destless_v4 = destless_rule(6);
    let destless_v6 = destless_rule(17);
    let with_denied_prefix = FlowSpecRule {
        components: vec![FlowSpecComponent::DestinationPrefix(FlowSpecPrefix::V4(
            Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 0), 24),
        ))],
    };

    let attrs_for = |mp: MpReachNlri| {
        vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath {
                segments: vec![AsPathSegment::AsSequence(vec![65002])],
            }),
            PathAttribute::MpReachNlri(mp),
        ]
    };
    let v4_update = rustbgpd_wire::UpdateMessage::build(
        &[],
        &[],
        &attrs_for(MpReachNlri {
            afi: Afi::Ipv4,
            safi: Safi::FlowSpec,
            next_hop: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            link_local_next_hop: None,
            announced: vec![],
            flowspec_announced: vec![destless_v4.clone(), with_denied_prefix.clone()],
            evpn_announced: vec![],
            bgpls_announced: vec![],
            labeled_announced: vec![],
            vpn_announced: vec![],
            rtc_announced: vec![],
        }),
        true,
        false,
        rustbgpd_wire::Ipv4UnicastMode::Body,
    );
    session.process_update(v4_update).await;
    let v6_update = rustbgpd_wire::UpdateMessage::build(
        &[],
        &[],
        &attrs_for(MpReachNlri {
            afi: Afi::Ipv6,
            safi: Safi::FlowSpec,
            next_hop: "2001:db8::2".parse().unwrap(),
            link_local_next_hop: None,
            announced: vec![],
            flowspec_announced: vec![destless_v6.clone()],
            evpn_announced: vec![],
            bgpls_announced: vec![],
            labeled_announced: vec![],
            vpn_announced: vec![],
            rtc_announced: vec![],
        }),
        true,
        false,
        rustbgpd_wire::Ipv4UnicastMode::Body,
    );
    session.process_update(v6_update).await;

    assert_eq!(
        session.import_policy_routes_permitted, 2,
        "both destination-less rules must pass through to the default Permit"
    );
    assert_eq!(
        session.import_policy_routes_denied, 1,
        "the rule with a real destination prefix must match the deny term"
    );

    let mut announced = vec![];
    while let Ok(msg) = rib_rx.try_recv() {
        if let RibUpdate::RoutesReceived {
            flowspec_announced, ..
        } = msg
        {
            announced.extend(flowspec_announced);
        }
    }
    let rules: Vec<_> = announced.iter().map(|r| r.rule.clone()).collect();
    assert_eq!(rules, vec![destless_v4, destless_v6]);
    assert_eq!(
        announced.iter().map(|r| r.afi).collect::<Vec<_>>(),
        vec![Afi::Ipv4, Afi::Ipv6]
    );
}
/// ADR-0073 end-to-end pins 1 + 2: after `process_update`, the
/// per-session import-decision cache holds an explainable `Deny` entry
/// for the denied prefix (which never reached RIB) and a `Permit` entry
/// — carrying the applied modifications — for the permitted one.
#[expect(
    clippy::too_many_lines,
    reason = "regression test pins a full session lifecycle sequence"
)]
#[tokio::test]
async fn import_decision_cache_records_deny_and_permit_for_explain() {
    use super::import_decision_cache::{CachedOutcome, ImportDecisionKey, LookupResult};
    let mut peer_config = PeerConfig::new(65001, 65002, Ipv4Addr::new(10, 0, 0, 1));
    peer_config.connect_retry_secs = 30;
    peer_config.families = vec![(Afi::Ipv4, Safi::Unicast)];
    peer_config.gr_restart_time = 120;
    let config = TransportConfig::new(peer_config, "10.0.0.2:179".parse().unwrap());
    let metrics = BgpMetrics::new();
    let (_cmd_tx, cmd_rx) = mpsc::channel(8);
    let (rib_tx, _rib_rx) = mpsc::channel(64);
    let denied_prefix = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 0), 24);
    let permitted_prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, 0), 24);
    // One chain, two statements: deny the first prefix, permit + set
    // LOCAL_PREF=200 on the second.
    let deny_stmt = PolicyStatement {
        prefix: Some(Prefix::V4(denied_prefix)),
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
        match_local_pref_ge: None,
        match_local_pref_le: None,
        match_med_ge: None,
        match_med_le: None,
        match_next_hop: None,
        modifications: RouteModifications::default(),
    };
    let permit_stmt = PolicyStatement {
        prefix: Some(Prefix::V4(permitted_prefix)),
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
    };
    let chain = PolicyChain::new(vec![Policy {
        entries: vec![deny_stmt, permit_stmt],
        default_action: PolicyAction::Permit,
    }]);
    let mut session = PeerSession::new(
        config,
        metrics,
        cmd_rx,
        rib_tx,
        Some(chain),
        None,
        None,
        None,
        None,
        false,
    );
    let mut negotiated = negotiated_session(65002, false);
    negotiated.peer_enhanced_route_refresh = true;
    session
        .negotiated_families
        .clone_from(&negotiated.negotiated_families);
    session.negotiated = Some(negotiated);
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
                prefix: denied_prefix,
            },
            Ipv4NlriEntry {
                path_id: 0,
                prefix: permitted_prefix,
            },
        ],
        &[],
        &attrs,
        true,
        false,
        Ipv4UnicastMode::Body,
    );
    session.process_update(update).await;
    let generation = session.import_policy_generation;
    let key = |p: Ipv4Prefix| ImportDecisionKey {
        afi: Afi::Ipv4,
        safi: Safi::Unicast,
        prefix: Prefix::V4(p),
        path_id: 0,
    };
    // Pin 1: the denied prefix is explainable even though it never
    // reached RIB.
    match session
        .import_decision_cache
        .lookup(&key(denied_prefix), generation)
    {
        LookupResult::Hit(d) => assert_eq!(d.outcome, CachedOutcome::Deny),
        other => panic!("expected Hit(Deny) for denied prefix, got {other:?}"),
    }
    // Pin 2: the permitted prefix is explainable and carries the
    // modifications the chain applied.
    match session
        .import_decision_cache
        .lookup(&key(permitted_prefix), generation)
    {
        LookupResult::Hit(d) => {
            assert_eq!(d.outcome, CachedOutcome::Permit);
            assert_eq!(d.modifications.set_local_pref, Some(200));
        }
        other => panic!("expected Hit(Permit) for permitted prefix, got {other:?}"),
    }
}
/// ADR-0073 contract: the per-session import-decision cache must be
/// flushed on `Action::SessionDown`. A reconnecting `PeerSession` is not
/// reconstructed, so without the flush an explain query on the new
/// session could return a decision recorded on the *previous* session
/// for any prefix the peer has not yet re-advertised. Mirrors the
/// per-session permit/deny counter reset in the same handler.
#[tokio::test]
async fn session_down_flushes_import_decision_cache() {
    use super::import_decision_cache::{ImportDecisionKey, LookupResult};
    let mut peer_config = PeerConfig::new(65001, 65002, Ipv4Addr::new(10, 0, 0, 1));
    peer_config.connect_retry_secs = 30;
    peer_config.families = vec![(Afi::Ipv4, Safi::Unicast)];
    peer_config.gr_restart_time = 120;
    let config = TransportConfig::new(peer_config, "10.0.0.2:179".parse().unwrap());
    let metrics = BgpMetrics::new();
    let (_cmd_tx, cmd_rx) = mpsc::channel(8);
    let (rib_tx, _rib_rx) = mpsc::channel(64);
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, 0), 24);
    let chain = PolicyChain::new(vec![Policy {
        entries: vec![PolicyStatement {
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
            modifications: RouteModifications::default(),
        }],
        default_action: PolicyAction::Permit,
    }]);
    let mut session = PeerSession::new(
        config,
        metrics,
        cmd_rx,
        rib_tx,
        Some(chain),
        None,
        None,
        None,
        None,
        false,
    );
    let mut negotiated = negotiated_session(65002, false);
    negotiated.peer_enhanced_route_refresh = true;
    session
        .negotiated_families
        .clone_from(&negotiated.negotiated_families);
    session.negotiated = Some(negotiated);
    let attrs = vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath {
            segments: vec![AsPathSegment::AsSequence(vec![65002])],
        }),
        PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
    ];
    let update = UpdateMessage::build(
        &[Ipv4NlriEntry { path_id: 0, prefix }],
        &[],
        &attrs,
        true,
        false,
        Ipv4UnicastMode::Body,
    );
    session.process_update(update).await;
    let generation = session.import_policy_generation;
    let key = ImportDecisionKey {
        afi: Afi::Ipv4,
        safi: Safi::Unicast,
        prefix: Prefix::V4(prefix),
        path_id: 0,
    };
    // Precondition: the decision is cached and explainable on this session.
    assert!(
        matches!(
            session.import_decision_cache.lookup(&key, generation),
            LookupResult::Hit(_)
        ),
        "expected the permitted prefix to be cached before SessionDown",
    );
    // Flap: SessionDown must flush the per-session cache.
    session.execute_actions(vec![Action::SessionDown]).await;
    // Postcondition: the prior session's decision is gone — explain
    // reports NotSeen rather than a stale Hit from the dead session.
    assert!(
        matches!(
            session.import_decision_cache.lookup(&key, generation),
            LookupResult::NotSeen
        ),
        "import-decision cache must be flushed on SessionDown (ADR-0073)",
    );
}
/// ADR-0073 pin 3: an `ExplainImportPolicy` command is a read — it must
/// not move the import-policy permit/deny counters.
#[tokio::test]
async fn explain_import_policy_command_does_not_touch_counters() {
    use super::import_decision_cache::{LookupResult, ResolvedMatch};
    let (mut session, _rib_rx) = make_test_session_with_rib(65001, 65002);
    let mut negotiated = negotiated_session(65002, false);
    negotiated.peer_enhanced_route_refresh = true;
    session
        .negotiated_families
        .clone_from(&negotiated.negotiated_families);
    session.negotiated = Some(negotiated);
    // Populate the cache with one permitted prefix (permit-all default).
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, 0), 24);
    let attrs = vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath {
            segments: vec![AsPathSegment::AsSequence(vec![65002])],
        }),
        PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
    ];
    let update = UpdateMessage::build(
        &[Ipv4NlriEntry { path_id: 0, prefix }],
        &[],
        &attrs,
        true,
        false,
        Ipv4UnicastMode::Body,
    );
    session.process_update(update).await;
    let permitted_before = session.import_policy_routes_permitted;
    let denied_before = session.import_policy_routes_denied;
    // Issue the explain command through the real dispatch path.
    let (reply_tx, reply_rx) = oneshot::channel();
    let flow = session
        .handle_command(PeerCommand::ExplainImportPolicy {
            afi: Afi::Ipv4,
            safi: Safi::Unicast,
            prefix: Prefix::V4(prefix),
            path_id: None,
            reply: reply_tx,
        })
        .await;
    assert_eq!(flow, ControlFlow::Continue(()));
    let reply = reply_rx.await.expect("session replied");
    assert!(
        matches!(
            reply.matches.as_slice(),
            [ResolvedMatch {
                result: LookupResult::Hit(_),
                ..
            }]
        ),
        "expected a single Hit match, got {:?}",
        reply.matches
    );
    // The read must not have moved either counter.
    assert_eq!(session.import_policy_routes_permitted, permitted_before);
    assert_eq!(session.import_policy_routes_denied, denied_before);
}
/// The import-side stats read surface (LAN-248): the query command
/// snapshots the live per-term hit counters plus the install
/// generation, an explain read never moves them, and a chain
/// reinstall — content-equal included — advances the generation and
/// resets the counters instead of presenting continuous history.
#[expect(
    clippy::too_many_lines,
    reason = "regression test keeps snapshot, explain-non-counting, and reinstall assertions together"
)]
#[tokio::test]
async fn query_import_policy_term_hits_snapshots_without_counting() {
    use rustbgpd_policy::NamedPolicy;

    async fn snapshot(session: &mut PeerSession) -> Option<crate::handle::ImportPolicyTermHits> {
        let (reply_tx, reply_rx) = oneshot::channel();
        let flow = session
            .handle_command(PeerCommand::QueryImportPolicyTermHits { reply: reply_tx })
            .await;
        assert_eq!(flow, ControlFlow::Continue(()));
        reply_rx.await.expect("session replied")
    }
    async fn install(session: &mut PeerSession, chain: PolicyChain) {
        let (reply_tx, reply_rx) = oneshot::channel();
        let _ = session
            .handle_command(PeerCommand::UpdateImportPolicy {
                policy: Some(chain),
                reply: reply_tx,
            })
            .await;
        reply_rx
            .await
            .expect("session replied")
            .expect("install succeeds");
    }

    let (mut session, _rib_rx) = make_test_session_with_rib(65001, 65002);
    let mut negotiated = negotiated_session(65002, false);
    negotiated.peer_enhanced_route_refresh = true;
    session
        .negotiated_families
        .clone_from(&negotiated.negotiated_families);
    session.negotiated = Some(negotiated);

    // No import chain installed → nothing to report.
    assert!(snapshot(&mut session).await.is_none());

    let permit_all = PolicyStatement {
        prefix: None,
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
        modifications: RouteModifications::default(),
    };
    let chain = PolicyChain::from_named(vec![NamedPolicy {
        name: Some("edge-import".to_string()),
        policy: Policy {
            entries: vec![permit_all],
            default_action: PolicyAction::Permit,
        },
        rpol: None,
    }]);
    install(&mut session, chain.clone()).await;

    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, 0), 24);
    let attrs = vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath {
            segments: vec![AsPathSegment::AsSequence(vec![65002])],
        }),
        PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
    ];
    let update = UpdateMessage::build(
        &[Ipv4NlriEntry { path_id: 0, prefix }],
        &[],
        &attrs,
        true,
        false,
        Ipv4UnicastMode::Body,
    );
    session.process_update(update).await;

    let first = snapshot(&mut session).await.expect("chain installed");
    assert_eq!(
        first.generation, 1,
        "session constructs at generation 0; one install advances it"
    );
    assert_eq!(first.evals, 1, "one route evaluated through the chain");
    assert_eq!(first.terms.len(), 1);
    assert_eq!(first.terms[0].policy.as_deref(), Some("edge-import"));
    assert_eq!(first.terms[0].hits, 1);

    // An explain read must not move the term-hit counters (LAN-248
    // pin, same contract as the permit/deny counters above).
    let (reply_tx, reply_rx) = oneshot::channel();
    let _ = session
        .handle_command(PeerCommand::ExplainImportPolicy {
            afi: Afi::Ipv4,
            safi: Safi::Unicast,
            prefix: Prefix::V4(prefix),
            path_id: None,
            reply: reply_tx,
        })
        .await;
    reply_rx.await.expect("session replied");
    let second = snapshot(&mut session).await.expect("chain installed");
    assert_eq!(second.evals, first.evals, "explain must not bump evals");
    assert_eq!(
        second.terms[0].hits, first.terms[0].hits,
        "explain must not bump term hits"
    );

    // A content-equal reinstall is a fresh chain instance: counters
    // reset and the generation advances, so the read surface never
    // presents the new instance as continuous history.
    install(&mut session, chain).await;
    let third = snapshot(&mut session).await.expect("chain installed");
    assert_eq!(third.generation, 2);
    assert_eq!(third.evals, 0);
    assert_eq!(third.terms[0].hits, 0);
}
/// Statement-level explain (the ADR-0073 deferred enrichment): a
/// current-generation Hit re-derives WHICH statement inside the matched
/// chain decided, through the real command dispatch path. A
/// generation bump (import-chain hot-apply) makes the entry `Stale`,
/// and a stale entry must carry NO statement trace — the chain that
/// produced the decision is gone, so re-walking the current chain
/// could contradict the recorded outcome.
#[expect(
    clippy::too_many_lines,
    reason = "regression test keeps cache hit and stale trace assertions together"
)]
#[tokio::test]
async fn explain_statement_trace_attributes_hit_and_skips_stale() {
    use super::import_decision_cache::LookupResult;
    use rustbgpd_policy::NamedPolicy;
    async fn explain_for(
        session: &mut PeerSession,
        prefix: Ipv4Prefix,
    ) -> super::import_decision_cache::ImportExplainReply {
        let (reply_tx, reply_rx) = oneshot::channel();
        let _ = session
            .handle_command(PeerCommand::ExplainImportPolicy {
                afi: Afi::Ipv4,
                safi: Safi::Unicast,
                prefix: Prefix::V4(prefix),
                path_id: None,
                reply: reply_tx,
            })
            .await;
        reply_rx.await.expect("session replied")
    }
    let mut peer_config = PeerConfig::new(65001, 65002, Ipv4Addr::new(10, 0, 0, 1));
    peer_config.connect_retry_secs = 30;
    peer_config.families = vec![(Afi::Ipv4, Safi::Unicast)];
    peer_config.gr_restart_time = 120;
    let config = TransportConfig::new(peer_config, "10.0.0.2:179".parse().unwrap());
    let metrics = BgpMetrics::new();
    let (_cmd_tx, cmd_rx) = mpsc::channel(8);
    let (rib_tx, _rib_rx) = mpsc::channel(64);
    let denied_prefix = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 0), 24);
    let permitted_prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, 0), 24);
    let deny_stmt = PolicyStatement {
        prefix: Some(Prefix::V4(denied_prefix)),
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
        match_local_pref_ge: None,
        match_local_pref_le: None,
        match_med_ge: None,
        match_med_le: None,
        match_next_hop: None,
        modifications: RouteModifications::default(),
    };
    let mut permit_stmt = deny_stmt.clone();
    permit_stmt.prefix = Some(Prefix::V4(permitted_prefix));
    permit_stmt.action = PolicyAction::Permit;
    permit_stmt.match_community = vec![CommunityMatch::Standard {
        value: (64512_u32 << 16) | 0x0064,
    }];
    permit_stmt.match_as_path = Some(AsPathRegex::new("_65002_").unwrap());
    permit_stmt.match_as_path_length_ge = Some(1);
    permit_stmt.match_as_path_length_le = Some(1);
    permit_stmt.match_local_pref_ge = Some(100);
    permit_stmt.match_med_le = Some(50);
    permit_stmt.match_next_hop = Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)));
    permit_stmt.modifications = RouteModifications {
        set_local_pref: Some(200),
        ..RouteModifications::default()
    };
    let chain = PolicyChain::from_named(vec![NamedPolicy {
        name: Some("edge-import".to_string()),
        policy: Policy {
            entries: vec![deny_stmt, permit_stmt],
            default_action: PolicyAction::Permit,
        },
        rpol: None,
    }]);
    let mut session = PeerSession::new(
        config,
        metrics,
        cmd_rx,
        rib_tx,
        Some(chain.clone()),
        None,
        None,
        None,
        None,
        false,
    );
    let mut negotiated = negotiated_session(65002, false);
    negotiated.peer_enhanced_route_refresh = true;
    session
        .negotiated_families
        .clone_from(&negotiated.negotiated_families);
    session.negotiated = Some(negotiated);
    let attrs = vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath {
            segments: vec![AsPathSegment::AsSequence(vec![65002])],
        }),
        PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
        PathAttribute::Communities(vec![(64512_u32 << 16) | 0x0064]),
        PathAttribute::LocalPref(150),
        PathAttribute::Med(42),
    ];
    let update = UpdateMessage::build(
        &[
            Ipv4NlriEntry {
                path_id: 0,
                prefix: denied_prefix,
            },
            Ipv4NlriEntry {
                path_id: 0,
                prefix: permitted_prefix,
            },
        ],
        &[],
        &attrs,
        true,
        false,
        Ipv4UnicastMode::Body,
    );
    session.process_update(update).await;
    // Permit: attributed to statement 1 of "edge-import", with the
    // prefix condition and the policy-local transition rendered from the
    // implicit default 100. The wire LOCAL_PREF 150 is ignored on eBGP.
    let reply = explain_for(&mut session, permitted_prefix).await;
    assert_eq!(reply.matches.len(), 1);
    let steps = &reply.matches[0].statements;
    assert_eq!(steps.len(), 1, "one policy evaluated");
    assert_eq!(steps[0].policy_index, 0);
    assert_eq!(steps[0].policy_name.as_deref(), Some("edge-import"));
    assert_eq!(steps[0].statement_index, Some(1));
    assert_eq!(steps[0].action, PolicyAction::Permit);
    assert_eq!(
        steps[0].matched_conditions,
        vec![
            "prefix 192.0.2.0/24",
            "community 64512:100",
            "as_path ~ \"_65002_\"",
            "as_path_len >= 1",
            "as_path_len <= 1",
            "local_pref >= 100",
            "med <= 50",
            "next_hop 10.0.0.2",
        ]
    );
    assert_eq!(steps[0].modifications, vec!["local_pref 100 -> 200"]);
    // Deny: attributed to statement 0 — the reject fast-path is
    // explainable even though the route never reached RIB.
    let reply = explain_for(&mut session, denied_prefix).await;
    let steps = &reply.matches[0].statements;
    assert_eq!(steps.len(), 1);
    assert_eq!(steps[0].statement_index, Some(0));
    assert_eq!(steps[0].action, PolicyAction::Deny);
    assert!(steps[0].modifications.is_empty());
    // Hot-apply the (same) chain: the generation bump makes the cached
    // entries Stale, and a stale match must carry no statement trace.
    let (reply_tx, reply_rx) = oneshot::channel();
    let _ = session
        .handle_command(PeerCommand::UpdateImportPolicy {
            policy: Some(chain),
            reply: reply_tx,
        })
        .await;
    reply_rx.await.expect("policy update acked").unwrap();
    let reply = explain_for(&mut session, permitted_prefix).await;
    assert!(
        matches!(reply.matches[0].result, LookupResult::Stale(_)),
        "generation bump must mark the entry stale"
    );
    assert!(
        reply.matches[0].statements.is_empty(),
        "stale entries must not carry a statement trace"
    );
}
/// ADR-0073 pin 4 (reset semantics): a freshly constructed session — the
/// state every peer reconnect / daemon restart starts from — has an
/// empty import-decision cache, so an explain query returns `NOT_SEEN`.
/// The cache is owned by `PeerSession`, so it cannot survive the session
/// drop; this pins the "resets on session reset" contract at the unit
/// boundary the lifecycle guarantees.
#[test]
fn fresh_session_import_decision_cache_is_empty() {
    use super::import_decision_cache::{ImportDecisionKey, LookupResult};
    let (session, _rib_rx) = make_test_session_with_rib(65001, 65002);
    let key = ImportDecisionKey {
        afi: Afi::Ipv4,
        safi: Safi::Unicast,
        prefix: Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, 0), 24)),
        path_id: 0,
    };
    assert!(matches!(
        session.import_decision_cache.lookup(&key, 0),
        LookupResult::NotSeen
    ));
}
/// ADR-0073 IPv6 scope: an `MP_REACH` IPv6-unicast announcement is
/// recorded in the explain cache keyed by `(Ipv6, Unicast, prefix,
/// path_id)`, proving the `MP_REACH` write path mirrors the IPv4 body
/// path.
#[tokio::test]
async fn import_decision_cache_records_ipv6_mp_reach() {
    use super::import_decision_cache::{CachedOutcome, ImportDecisionKey, LookupResult};
    let (mut session, _rib_rx) = make_test_session_with_rib(65001, 65002);
    let mut negotiated = negotiated_session(65002, false);
    negotiated.negotiated_families = vec![(Afi::Ipv6, Safi::Unicast)];
    session
        .negotiated_families
        .clone_from(&negotiated.negotiated_families);
    session.negotiated = Some(negotiated);
    let v6 = Ipv6Prefix::new("2001:db8:1::".parse().unwrap(), 64);
    let mp_reach = rustbgpd_wire::MpReachNlri {
        afi: Afi::Ipv6,
        safi: Safi::Unicast,
        next_hop: IpAddr::V6("2001:db8:1::1".parse().unwrap()),
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
    };
    let attrs = vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath {
            segments: vec![AsPathSegment::AsSequence(vec![65002])],
        }),
        PathAttribute::MpReachNlri(mp_reach),
    ];
    let update = UpdateMessage::build(&[], &[], &attrs, true, false, Ipv4UnicastMode::Body);
    session.process_update(update).await;
    let key = ImportDecisionKey {
        afi: Afi::Ipv6,
        safi: Safi::Unicast,
        prefix: Prefix::V6(v6),
        path_id: 0,
    };
    match session.import_decision_cache.lookup(&key, 0) {
        LookupResult::Hit(d) => assert_eq!(d.outcome, CachedOutcome::Permit),
        other => panic!("expected Hit(Permit) for IPv6 MP_REACH prefix, got {other:?}"),
    }
}
/// ADR-0073 write-gating: with `[policy.explain].enabled = false`,
/// processing an UPDATE stores **no** decision — the eval-site clone is
/// skipped entirely. The empty cache after a *permitted* UPDATE is the
/// observable proof that the `if explain_enabled` guard runs before any
/// snapshot is built.
#[tokio::test]
async fn explain_disabled_stores_no_decisions() {
    use super::import_decision_cache::{ImportDecisionKey, LookupResult};
    let mut peer_config = PeerConfig::new(65001, 65002, Ipv4Addr::new(10, 0, 0, 1));
    peer_config.connect_retry_secs = 30;
    peer_config.families = vec![(Afi::Ipv4, Safi::Unicast)];
    peer_config.gr_restart_time = 120;
    let mut config = TransportConfig::new(peer_config, "10.0.0.2:179".parse().unwrap());
    config.explain_enabled = false;
    let metrics = BgpMetrics::new();
    let (_cmd_tx, cmd_rx) = mpsc::channel(8);
    let (rib_tx, _rib_rx) = mpsc::channel(64);
    // Permit-all (no import policy) so the route is accepted; only the
    // explain cache should differ from the enabled case.
    let mut session = PeerSession::new(
        config, metrics, cmd_rx, rib_tx, None, None, None, None, None, false,
    );
    let mut negotiated = negotiated_session(65002, false);
    negotiated.peer_enhanced_route_refresh = true;
    session
        .negotiated_families
        .clone_from(&negotiated.negotiated_families);
    session.negotiated = Some(negotiated);
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, 0), 24);
    let attrs = vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath {
            segments: vec![AsPathSegment::AsSequence(vec![65002])],
        }),
        PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
    ];
    let update = UpdateMessage::build(
        &[Ipv4NlriEntry { path_id: 0, prefix }],
        &[],
        &attrs,
        true,
        false,
        Ipv4UnicastMode::Body,
    );
    session.process_update(update).await;
    // The route was permitted (counter moved) but nothing was cached.
    assert_eq!(session.import_policy_routes_permitted, 1);
    let key = ImportDecisionKey {
        afi: Afi::Ipv4,
        safi: Safi::Unicast,
        prefix: Prefix::V4(prefix),
        path_id: 0,
    };
    assert!(
        matches!(
            session.import_decision_cache.lookup(&key, 0),
            LookupResult::NotSeen
        ),
        "explain disabled must store no decision"
    );
}
/// LAN-320: the explain reply carries the session's own cache-enabled
/// flag (snapshotted from `[policy.explain] enabled` at session build)
/// so the RPC layer can report `CACHE_DISABLED` distinctly instead of
/// a `NOT_SEEN` lookalike.
#[tokio::test]
async fn explain_reply_carries_cache_enabled_flag() {
    for enabled in [true, false] {
        let mut peer_config = PeerConfig::new(65001, 65002, Ipv4Addr::new(10, 0, 0, 1));
        peer_config.connect_retry_secs = 30;
        peer_config.families = vec![(Afi::Ipv4, Safi::Unicast)];
        peer_config.gr_restart_time = 120;
        let mut config = TransportConfig::new(peer_config, "10.0.0.2:179".parse().unwrap());
        config.explain_enabled = enabled;
        let metrics = BgpMetrics::new();
        let (_cmd_tx, cmd_rx) = mpsc::channel(8);
        let (rib_tx, _rib_rx) = mpsc::channel(64);
        let mut session = PeerSession::new(
            config, metrics, cmd_rx, rib_tx, None, None, None, None, None, false,
        );
        let (reply_tx, reply_rx) = oneshot::channel();
        let _ = session
            .handle_command(PeerCommand::ExplainImportPolicy {
                afi: Afi::Ipv4,
                safi: Safi::Unicast,
                prefix: Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, 0), 24)),
                path_id: None,
                reply: reply_tx,
            })
            .await;
        let reply = reply_rx.await.expect("session replied");
        assert_eq!(
            reply.cache_enabled, enabled,
            "reply must snapshot the session's own explain flag"
        );
        assert!(reply.matches.is_empty(), "nothing cached, nothing matched");
    }
}
/// Import policy chains accumulate modifications across matching permit
/// policies before the route reaches the RIB.
#[expect(
    clippy::too_many_lines,
    reason = "regression test keeps accumulated policy modifications and route assertions together"
)]
#[tokio::test]
async fn import_policy_chain_accumulates_community_and_local_pref() {
    let mut peer_config = PeerConfig::new(65001, 65002, Ipv4Addr::new(10, 0, 0, 1));
    peer_config.connect_retry_secs = 30;
    peer_config.families = vec![(Afi::Ipv4, Safi::Unicast)];
    peer_config.gr_restart_time = 120;
    let config = TransportConfig::new(peer_config, "10.0.0.2:179".parse().unwrap());
    let metrics = BgpMetrics::new();
    let (_cmd_tx, cmd_rx) = mpsc::channel(8);
    let (rib_tx, mut rib_rx) = mpsc::channel(64);
    let chain = PolicyChain::new(vec![
        Policy {
            entries: vec![PolicyStatement {
                prefix: Some(Prefix::V4(Ipv4Prefix::new(Ipv4Addr::UNSPECIFIED, 0))),
                ge: Some(25),
                le: Some(32),
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
                match_local_pref_ge: None,
                match_local_pref_le: None,
                match_med_ge: None,
                match_med_le: None,
                match_next_hop: None,
                modifications: RouteModifications::default(),
            }],
            default_action: PolicyAction::Permit,
        },
        Policy {
            entries: vec![PolicyStatement {
                prefix: Some(Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 8))),
                ge: None,
                le: Some(16),
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
                    communities_add: vec![0xFDE9_0064],
                    ..Default::default()
                },
            }],
            default_action: PolicyAction::Permit,
        },
        Policy {
            entries: vec![PolicyStatement {
                prefix: None,
                ge: None,
                le: None,
                action: PolicyAction::Permit,
                match_community: vec![],
                match_as_path: Some(rustbgpd_policy::AsPathRegex::new("_65002_").unwrap()),
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
                    ..Default::default()
                },
            }],
            default_action: PolicyAction::Permit,
        },
    ]);
    let mut session = PeerSession::new(
        config,
        metrics,
        cmd_rx,
        rib_tx,
        Some(chain),
        None,
        None,
        None,
        None,
        false,
    );
    session.negotiated = Some(negotiated_session(65002, false));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(10, 10, 0, 0), 16);
    let attrs = vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath {
            segments: vec![AsPathSegment::AsSequence(vec![65002])],
        }),
        PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
    ];
    let update = UpdateMessage::build(
        &[Ipv4NlriEntry { path_id: 0, prefix }],
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
    assert_eq!(announced.len(), 1);
    let route = &announced[0];
    assert_eq!(route.prefix, Prefix::V4(prefix));
    assert_eq!(route.local_pref(), 200);
    assert_eq!(route.communities(), &[0xFDE9_0064]);
}
#[tokio::test]
async fn update_import_policy_applies_to_future_updates() {
    let mut peer_config = PeerConfig::new(65001, 65002, Ipv4Addr::new(10, 0, 0, 1));
    peer_config.connect_retry_secs = 30;
    peer_config.families = vec![(Afi::Ipv4, Safi::Unicast)];
    peer_config.gr_restart_time = 120;
    let config = TransportConfig::new(peer_config, "10.0.0.2:179".parse().unwrap());
    let metrics = BgpMetrics::new();
    let (_cmd_tx, cmd_rx) = mpsc::channel(8);
    let (rib_tx, mut rib_rx) = mpsc::channel(64);
    let mut session = PeerSession::new(
        config, metrics, cmd_rx, rib_tx, None, None, None, None, None, false,
    );
    session.negotiated = Some(negotiated_session(65002, false));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24);
    let attrs = vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath {
            segments: vec![AsPathSegment::AsSequence(vec![65002])],
        }),
        PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
    ];
    let update = UpdateMessage::build(
        &[Ipv4NlriEntry { path_id: 0, prefix }],
        &[],
        &attrs,
        true,
        false,
        Ipv4UnicastMode::Body,
    );
    session.process_update(update.clone()).await;
    let RibUpdate::RoutesReceived { announced, .. } = rib_rx.try_recv().unwrap() else {
        panic!("expected first RoutesReceived");
    };
    assert_eq!(announced.len(), 1);
    let deny_chain = PolicyChain::new(vec![Policy {
        entries: vec![PolicyStatement {
            prefix: Some(Prefix::V4(prefix)),
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
            match_local_pref_ge: None,
            match_local_pref_le: None,
            match_med_ge: None,
            match_med_le: None,
            match_next_hop: None,
            modifications: RouteModifications::default(),
        }],
        default_action: PolicyAction::Permit,
    }]);
    let (reply_tx, reply_rx) = oneshot::channel();
    let flow = session
        .handle_command(PeerCommand::UpdateImportPolicy {
            policy: Some(deny_chain),
            reply: reply_tx,
        })
        .await;
    assert_eq!(flow, ControlFlow::Continue(()));
    assert_eq!(reply_rx.await.unwrap(), Ok(()));
    session.process_update(update).await;
    assert!(rib_rx.try_recv().is_err());
}
/// End-to-end ERR + import policy interaction:
/// a stale route that is "replaced" by an inbound UPDATE denied by import
/// policy is not reinstalled, so the stale entry is swept at `EoRR`.
#[expect(
    clippy::too_many_lines,
    reason = "regression test pins ERR stale-sweep behavior after import-policy denial"
)]
#[tokio::test]
async fn err_denied_replacement_is_swept_at_eorr() {
    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let (rib_tx, rib_rx) = mpsc::channel(64);
    let (_, query_rx) = mpsc::channel(1);
    let manager = rustbgpd_rib::RibManager::new(rib_rx, query_rx, None, None, BgpMetrics::new());
    let manager_handle = tokio::spawn(manager.run());
    let denied_prefix = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 0), 24);
    let permitted_prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, 0), 24);
    // Seed the RIB with an existing route that will become refresh-stale.
    rib_tx
        .send(RibUpdate::RoutesReceived {
            session_id: 0,
            peer,
            announced: vec![Route {
                prefix: Prefix::V4(denied_prefix),
                next_hop: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
                link_local_next_hop: None,
                next_hop_scope: None,
                peer,
                attributes: Arc::new(vec![
                    PathAttribute::Origin(Origin::Igp),
                    PathAttribute::AsPath(AsPath {
                        segments: vec![AsPathSegment::AsSequence(vec![65002])],
                    }),
                    PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
                ]),
                received_at: Instant::now(),
                origin_type: rustbgpd_rib::RouteOrigin::Ebgp,
                peer_router_id: Ipv4Addr::UNSPECIFIED,
                is_stale: false,
                is_llgr_stale: false,
                path_id: 0,
                validation_state: rustbgpd_wire::RpkiValidation::NotFound,
                aspa_state: rustbgpd_wire::AspaValidation::Unknown,
                aspa_context: rustbgpd_wire::AspaValidationContext::default(),
            }],
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
            evpn_announced: vec![],
            evpn_withdrawn: vec![],
        })
        .await
        .unwrap();
    // Start the ERR refresh window for IPv4 unicast.
    rib_tx
        .send(RibUpdate::BeginRouteRefresh {
            session_id: 0,
            peer,
            afi: Afi::Ipv4,
            safi: Safi::Unicast,
        })
        .await
        .unwrap();
    // Session import policy denies the stale prefix, but permits the new one.
    let mut peer_config = PeerConfig::new(65001, 65002, Ipv4Addr::new(10, 0, 0, 1));
    peer_config.connect_retry_secs = 30;
    peer_config.families = vec![(Afi::Ipv4, Safi::Unicast)];
    peer_config.gr_restart_time = 120;
    let config = TransportConfig::new(peer_config, "10.0.0.2:179".parse().unwrap());
    let metrics = BgpMetrics::new();
    let (_cmd_tx, cmd_rx) = mpsc::channel(8);
    let deny_policy = PolicyChain::new(vec![Policy {
        entries: vec![PolicyStatement {
            prefix: Some(Prefix::V4(denied_prefix)),
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
        rib_tx.clone(),
        Some(deny_policy),
        None,
        None,
        None,
        None,
        false,
    );
    let mut negotiated = negotiated_session(65002, false);
    negotiated.peer_enhanced_route_refresh = true;
    session
        .negotiated_families
        .clone_from(&negotiated.negotiated_families);
    session.negotiated = Some(negotiated);
    let attrs = vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath {
            segments: vec![AsPathSegment::AsSequence(vec![65002])],
        }),
        PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
    ];
    // The denied prefix is filtered by import policy, so only the permitted
    // replacement reaches the RIB during the refresh window.
    let update = UpdateMessage::build(
        &[
            Ipv4NlriEntry {
                path_id: 0,
                prefix: denied_prefix,
            },
            Ipv4NlriEntry {
                path_id: 0,
                prefix: permitted_prefix,
            },
        ],
        &[],
        &attrs,
        true,
        false,
        Ipv4UnicastMode::Body,
    );
    session.process_update(update).await;
    // Close the refresh window; the unreplaced stale route should be swept.
    rib_tx
        .send(RibUpdate::EndRouteRefresh {
            session_id: 0,
            peer,
            afi: Afi::Ipv4,
            safi: Safi::Unicast,
        })
        .await
        .unwrap();
    let (reply_tx, reply_rx) = oneshot::channel();
    rib_tx
        .send(RibUpdate::QueryReceivedRoutes {
            peer: Some(peer),
            reply: reply_tx,
        })
        .await
        .unwrap();
    let received = reply_rx.await.unwrap();
    assert_eq!(received.len(), 1);
    assert_eq!(received[0].prefix, Prefix::V4(permitted_prefix));
    drop(session);
    drop(rib_tx);
    manager_handle.await.unwrap();
}
#[tokio::test]
async fn import_policy_match_next_hop_filters_route() {
    let mut peer_config = PeerConfig::new(65001, 65002, Ipv4Addr::new(10, 0, 0, 1));
    peer_config.connect_retry_secs = 30;
    peer_config.families = vec![(Afi::Ipv4, Safi::Unicast)];
    peer_config.gr_restart_time = 120;
    let config = TransportConfig::new(peer_config, "10.0.0.2:179".parse().unwrap());
    let metrics = BgpMetrics::new();
    let (_cmd_tx, cmd_rx) = mpsc::channel(8);
    let (rib_tx, mut rib_rx) = mpsc::channel(64);
    let deny_policy = PolicyChain::new(vec![Policy {
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
            match_aspa_validation: None,
            match_as_path_length_ge: None,
            match_as_path_length_le: None,
            match_local_pref_ge: None,
            match_local_pref_le: None,
            match_med_ge: None,
            match_med_le: None,
            match_next_hop: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))),
            modifications: RouteModifications::default(),
        }],
        default_action: PolicyAction::Permit,
    }]);
    let mut session = PeerSession::new(
        config,
        metrics,
        cmd_rx,
        rib_tx,
        Some(deny_policy),
        None,
        None,
        None,
        None,
        false,
    );
    session.negotiated = Some(negotiated_session(65002, false));
    let attrs = vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath {
            segments: vec![AsPathSegment::AsSequence(vec![65002])],
        }),
        PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
    ];
    let announced = vec![Ipv4NlriEntry {
        path_id: 0,
        prefix: Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24),
    }];
    let update = UpdateMessage::build(&announced, &[], &attrs, true, false, Ipv4UnicastMode::Body);
    session.process_update(update).await;
    assert!(
        rib_rx.try_recv().is_err(),
        "route should be filtered by next-hop"
    );
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
#[tokio::test]
async fn add_path_multiplicity_counts_one_prefix_for_max_prefix() {
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    let (client, _server) = connected_stream_pair().await;
    session.test_install_stream(client);
    establish_test_session(&mut session, 65002).await;
    while rib_rx.try_recv().is_ok() {}
    session.config.max_prefixes = Some(1);
    let mut negotiated = negotiated_session(65002, true);
    negotiated
        .add_path_families
        .insert((Afi::Ipv4, Safi::Unicast), AddPathMode::Both);
    install_test_negotiated_session(&mut session, negotiated);
    let attrs = vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath {
            segments: vec![AsPathSegment::AsSequence(vec![65002])],
        }),
        PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
    ];
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24);
    let update = UpdateMessage::build(
        &[
            Ipv4NlriEntry { path_id: 1, prefix },
            Ipv4NlriEntry { path_id: 2, prefix },
        ],
        &[],
        &attrs,
        true,
        true,
        Ipv4UnicastMode::Body,
    );
    session.process_update(update).await;
    let RibUpdate::RoutesReceived { announced, .. } = rib_rx.try_recv().unwrap() else {
        panic!("expected same-prefix Add-Path routes to pass max-prefix");
    };
    assert_eq!(announced.len(), 2);
    assert_eq!(
        session.known_prefix_count(),
        1,
        "two Add-Path IDs for one prefix count as one unique prefix"
    );
    assert!(
        session.read_half.is_some(),
        "fixture must be connected before the over-limit update"
    );
    let second_prefix = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 0), 24);
    let update = UpdateMessage::build(
        &[Ipv4NlriEntry {
            path_id: 3,
            prefix: second_prefix,
        }],
        &[],
        &attrs,
        true,
        true,
        Ipv4UnicastMode::Body,
    );
    session.process_update(update).await;
    assert!(
        session.read_half.is_none(),
        "max-prefix overflow must drive the FSM teardown path"
    );
    assert_eq!(
        session.known_prefix_count(),
        0,
        "teardown must clear max-prefix accounting"
    );
}
#[test]
fn notification_teardown_detects_inbound_notification() {
    let event = Event::NotificationReceived(NotificationMessage::new(
        NotificationCode::Cease,
        cease_subcode::ADMINISTRATIVE_SHUTDOWN,
        Bytes::new(),
    ));
    let actions = vec![Action::SessionDown];
    assert!(notification_teardown_event(&event, &actions));
}
#[test]
fn notification_teardown_detects_local_notification_path() {
    let event = Event::ManualStop { reason: None };
    let actions = vec![
        Action::SessionDown,
        Action::SendNotification(NotificationMessage::new(
            NotificationCode::Cease,
            cease_subcode::ADMINISTRATIVE_SHUTDOWN,
            Bytes::new(),
        )),
    ];
    assert!(notification_teardown_event(&event, &actions));
}
#[test]
fn hard_reset_detected_in_actions() {
    let actions = vec![Action::SendNotification(NotificationMessage::new(
        NotificationCode::Cease,
        cease_subcode::HARD_RESET,
        Bytes::new(),
    ))];
    assert!(hard_reset_notification_in_actions(&actions));
}
#[tokio::test]
async fn notification_teardown_without_n_bit_uses_peer_down() {
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    let mut neg = negotiated_session(65002, false);
    neg.peer_gr_capable = true;
    neg.peer_restart_time = 120;
    neg.peer_gr_families = vec![rustbgpd_wire::GracefulRestartFamily {
        afi: Afi::Ipv4,
        safi: Safi::Unicast,
        forwarding_preserved: false,
    }];
    neg.peer_notification_gr = false;
    session.config.peer.graceful_restart = true;
    session.negotiated = Some(neg);
    session.notification_teardown = true;
    session.execute_actions(vec![Action::SessionDown]).await;
    match rib_rx.try_recv().unwrap() {
        RibUpdate::PeerDown { peer, .. } => assert_eq!(peer, session.peer_ip),
        _ => panic!("expected PeerDown"),
    }
}
#[tokio::test]
async fn notification_teardown_with_n_bit_uses_peer_graceful_restart() {
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    let mut neg = negotiated_session(65002, false);
    neg.peer_gr_capable = true;
    neg.peer_restart_time = 120;
    neg.peer_gr_families = vec![rustbgpd_wire::GracefulRestartFamily {
        afi: Afi::Ipv4,
        safi: Safi::Unicast,
        forwarding_preserved: false,
    }];
    neg.peer_notification_gr = true;
    session.config.peer.graceful_restart = true;
    session.negotiated = Some(neg);
    session.notification_teardown = true;
    session.execute_actions(vec![Action::SessionDown]).await;
    match rib_rx.try_recv().unwrap() {
        RibUpdate::PeerGracefulRestart { peer, .. } => assert_eq!(peer, session.peer_ip),
        _ => panic!("expected PeerGracefulRestart"),
    }
}
#[tokio::test]
async fn hard_reset_always_bypasses_gr_even_with_n_bit() {
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    let mut neg = negotiated_session(65002, false);
    neg.peer_gr_capable = true;
    neg.peer_restart_time = 120;
    neg.peer_gr_families = vec![rustbgpd_wire::GracefulRestartFamily {
        afi: Afi::Ipv4,
        safi: Safi::Unicast,
        forwarding_preserved: false,
    }];
    neg.peer_notification_gr = true;
    session.config.peer.graceful_restart = true;
    session.negotiated = Some(neg);
    session.notification_teardown = true;
    session.received_hard_reset = true;
    session.execute_actions(vec![Action::SessionDown]).await;
    match rib_rx.try_recv().unwrap() {
        RibUpdate::PeerDown { peer, .. } => assert_eq!(peer, session.peer_ip),
        _ => panic!("expected PeerDown"),
    }
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
}
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
}
/// Regression: max-prefix enforcement must count EVPN keys (and `FlowSpec`
/// rules) alongside unicast prefixes. Prior to the fix, `known_prefix_count`
/// only counted unique unicast prefixes, so a peer could flood arbitrary
/// EVPN routes without tripping the configured cap.
#[tokio::test]
async fn evpn_routes_counted_toward_max_prefix() {
    use rustbgpd_wire::{
        EthernetSegmentIdentifier, EthernetTagId, EvpnMacIp, EvpnRoute, MacAddress, MpReachNlri,
        MplsLabel, RouteDistinguisher,
    };
    let (mut session, _rib_rx) = make_test_session_with_rib(65001, 65001);
    let (client, _server) = connected_stream_pair().await;
    session.test_install_stream(client);
    establish_test_session(&mut session, 65001).await;
    session.config.max_prefixes = Some(2);
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
    let make_route = |mac_lo: u8| -> EvpnRoute {
        EvpnRoute::MacIp(EvpnMacIp {
            rd: RouteDistinguisher([0, 0, 0xFD, 0xE8, 0, 0, 0, 100]),
            esi: EthernetSegmentIdentifier::ZERO,
            ethernet_tag: EthernetTagId(100),
            mac: MacAddress([0x02, 0x00, 0x00, 0xAA, 0xBB, mac_lo]),
            ip: None,
            label1: MplsLabel::new(10_000),
            label2: None,
        })
    };
    let send_announces = |routes: Vec<EvpnRoute>| {
        let attrs = vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath { segments: vec![] }),
            PathAttribute::MpReachNlri(MpReachNlri {
                afi: Afi::L2Vpn,
                safi: Safi::Evpn,
                next_hop: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
                link_local_next_hop: None,
                announced: vec![],
                flowspec_announced: vec![],
                evpn_announced: routes,
                bgpls_announced: vec![],
                labeled_announced: vec![],
                vpn_announced: vec![],
                rtc_announced: vec![],
            }),
        ];
        UpdateMessage::build(&[], &[], &attrs, true, false, Ipv4UnicastMode::MpReach)
    };
    // Push 2 EVPN routes — at the limit, should not trip.
    session
        .process_update(send_announces(vec![make_route(0x01), make_route(0x02)]))
        .await;
    assert_eq!(
        session.known_prefix_count(),
        2,
        "EVPN routes must contribute to the prefix count"
    );
    assert!(
        session.read_half.is_some(),
        "fixture must be connected before the over-limit update"
    );
    // Push a 3rd — must exceed max_prefixes = 2.
    session
        .process_update(send_announces(vec![make_route(0x03)]))
        .await;
    assert!(
        session.read_half.is_none(),
        "max-prefix overflow must drive the FSM teardown path"
    );
    assert_eq!(
        session.known_prefix_count(),
        0,
        "teardown must clear max-prefix accounting"
    );
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
}
/// Max-prefix enforcement must count RTC membership NLRI alongside the
/// other families.
#[tokio::test]
async fn rtc_routes_counted_toward_max_prefix() {
    use rustbgpd_wire::{MpReachNlri, RtcNlri};
    let (mut session, _rib_rx) = make_test_session_with_rib(65001, 65001);
    let (client, _server) = connected_stream_pair().await;
    session.test_install_stream(client);
    establish_test_session(&mut session, 65001).await;
    session.config.max_prefixes = Some(2);
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
    let make_nlri = |admin: u64| RtcNlri::new(65001, 0x0002_FDE9_0000_0000 | admin, 96).unwrap();
    let send_announces = |nlris: Vec<RtcNlri>| {
        let attrs = vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath { segments: vec![] }),
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
                rtc_announced: nlris,
            }),
        ];
        UpdateMessage::build(&[], &[], &attrs, true, false, Ipv4UnicastMode::MpReach)
    };
    session
        .process_update(send_announces(vec![make_nlri(1), make_nlri(2)]))
        .await;
    assert_eq!(
        session.known_prefix_count(),
        2,
        "RTC routes must contribute to the prefix count"
    );
    assert!(session.read_half.is_some());
    session
        .process_update(send_announces(vec![make_nlri(3)]))
        .await;
    assert!(
        session.read_half.is_none(),
        "max-prefix overflow must drive the FSM teardown path"
    );
    assert_eq!(
        session.known_prefix_count(),
        0,
        "teardown must clear max-prefix accounting"
    );
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
}
/// ADR-0051: when the writer's bulk channel saturates, the session must
/// emit a `Cease` / `Out of Resources` (RFC 4486 §4 subcode 8)
/// NOTIFICATION on the priority channel and tear the session down,
/// rather than blackholing routes silently. Drives
/// `trigger_outbound_saturation_teardown` directly to verify the
/// invariants without trying to force kernel TCP buffer saturation
/// from a unit test.
#[tokio::test]
async fn outbound_saturation_teardown_emits_cease_out_of_resources() {
    use rustbgpd_wire::notification::{NotificationCode, cease_subcode};
    let (mut session, _rib_rx) = make_test_session_with_rib(65001, 65002);
    let (client, mut server) = connected_stream_pair().await;
    session.test_install_stream(client);
    // Sanity: writer is up before the trigger.
    assert!(session.read_half.is_some());
    assert!(session.writer_bulk_tx.is_some());
    assert!(session.writer_priority_tx.is_some());
    assert!(session.writer_join.is_some());
    session.trigger_outbound_saturation_teardown();
    // Post-trigger invariants: read half + writer senders dropped, but
    // the JoinHandle stays in place so the run loop's writer-exit arm
    // can still observe the writer's natural exit.
    assert!(
        session.read_half.is_none(),
        "trigger_outbound_saturation_teardown must clear read_half"
    );
    assert!(
        session.writer_bulk_tx.is_none(),
        "writer_bulk_tx must be dropped to signal writer to exit"
    );
    assert!(
        session.writer_priority_tx.is_none(),
        "writer_priority_tx must be dropped to signal writer to exit"
    );
    let join = session
        .writer_join
        .take()
        .expect("writer_join should outlive the trigger so the run loop observes exit");
    // The writer pulled the Cease/8 from the priority channel before
    // seeing both senders dropped, so it should be on the wire now.
    let msg = read_single_bgp_message(&mut server).await;
    let Message::Notification(notif) = msg else {
        panic!("expected NOTIFICATION on saturation, got {msg:?}");
    };
    assert_eq!(notif.code, NotificationCode::Cease);
    assert_eq!(
        notif.subcode,
        cease_subcode::OUT_OF_RESOURCES,
        "saturation must surface as Cease/Out-of-Resources, not silent drop"
    );
    // After flushing the Cease the writer hard-closes with `TornDown`
    // (never draining any bulk backlog), which is what the run loop's
    // writer-exit arm maps to `TcpConnectionFails` + FSM/RIB cleanup.
    let result = tokio::time::timeout(Duration::from_secs(2), join)
        .await
        .expect("writer should exit within 2s of the teardown signal")
        .expect("writer task should not panic");
    assert!(
        matches!(result, Err(super::writer::WriterExit::TornDown)),
        "writer should exit TornDown after the saturation hard close, got: {result:?}"
    );
}
/// Split a captured wire byte stream into BGP frames as
/// `(message_type, frame_bytes)` pairs, asserting the stream contains
/// no truncated trailing frame.
fn parse_wire_frames(mut wire: &[u8]) -> Vec<(u8, Vec<u8>)> {
    let mut frames = Vec::new();
    while !wire.is_empty() {
        assert!(
            wire.len() >= 19,
            "trailing partial BGP header on the wire: {} bytes left",
            wire.len()
        );
        let len = usize::from(u16::from_be_bytes([wire[16], wire[17]]));
        assert!(
            (19..=wire.len()).contains(&len),
            "truncated BGP frame: declared {len}, {} bytes left",
            wire.len()
        );
        frames.push((wire[18], wire[..len].to_vec()));
        wire = &wire[len..];
    }
    frames
}
/// LAN-280 end-to-end regression: outbound saturation detected on the
/// REAL run-loop path — a peer draining too slowly while outbound
/// updates flood in through the RIB channel — must:
///
/// 1. put the `Cease/8` NOTIFICATION on the wire as the FINAL frame:
///    the queued UPDATE backlog is discarded, never drained after the
///    NOTIFICATION;
/// 2. deregister the peer from the RIB (`PeerDown`) via the
///    writer-exit → `TcpConnectionFails` wiring, with **no manually
///    injected FSM events** (the vacuity this test exists to prevent);
/// 3. leave the session task alive and responsive afterwards.
#[tokio::test]
async fn saturation_teardown_from_run_loop_ceases_closes_and_deregisters() {
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    // The harness drops its command sender, which would end `run()`
    // immediately — install a live command channel instead.
    let (cmd_tx, cmd_rx) = mpsc::channel(8);
    session.commands = cmd_rx;
    // Small socket buffers so the writer wedges in `write_all` after a
    // few KiB and the bounded bulk queue actually fills.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let connect = tokio::spawn(async move {
        let socket = tokio::net::TcpSocket::new_v4().unwrap();
        socket.set_recv_buffer_size(4096).unwrap();
        socket.connect(addr).await.unwrap()
    });
    let (server, _) = listener.accept().await.unwrap();
    socket2::SockRef::from(&server)
        .set_send_buffer_size(4096)
        .unwrap();
    let peer = connect.await.unwrap();
    session.test_install_stream(server);
    establish_test_session(&mut session, 65002).await;
    match recv_peer_up_after_export_context(&mut rib_rx).await {
        RibUpdate::PeerUp { .. } => {}
        _ => panic!("expected RIB PeerUp after establishment"),
    }
    let outbound_tx = session.outbound_tx.clone();
    let session_task = tokio::spawn(async move { session.run().await });
    // Slow reader: trickles just enough that the writer stays wedged
    // while the flood fills the bulk queue, but keeps draining so the
    // in-flight frame completes within the teardown linger and the
    // whole wire (including the final Cease) is observable to EOF.
    let reader = tokio::spawn(async move {
        let mut peer = peer;
        let mut collected = Vec::new();
        let mut buf = [0u8; 1024];
        loop {
            tokio::time::sleep(Duration::from_millis(20)).await;
            match peer.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => collected.extend_from_slice(&buf[..n]),
            }
        }
        collected
    });
    // Flood through the REAL outbound path (outbound channel → run
    // loop → send_route_update → enqueue_bulk). 3× the writer queue
    // depth guarantees `try_send` hits `Full` and the production
    // saturation detection fires. No `trigger_outbound_saturation_-
    // teardown` call, no injected FSM events.
    let flood_total = 3 * OUTBOUND_BUFFER;
    for _ in 0..flood_total {
        let mut update = empty_outbound_update();
        update.announce = vec![make_route(100)].into();
        update.next_hop_override = vec![None].into();
        if outbound_tx.send(update).await.is_err() {
            // SessionDown already recreated the outbound channel.
            break;
        }
    }
    // (2) Production wiring: the RIB observes the PeerDown without any
    // manually injected `TcpConnectionFails`. Skip other session-up
    // messages (e.g. `SetPeerPolicyContext`) on the way.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    loop {
        let msg = tokio::time::timeout_at(deadline, rib_rx.recv())
            .await
            .expect("RIB must observe the saturation teardown (writer-exit → TcpConnectionFails)")
            .expect("rib channel must stay open");
        match msg {
            RibUpdate::PeerDown { peer, .. } => {
                assert_eq!(peer, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)));
                break;
            }
            RibUpdate::PeerGracefulRestart { .. } => {
                panic!("saturation teardown must deregister via PeerDown, not GR-preserve")
            }
            _ => {}
        }
    }
    // (3) The session task survived the teardown and terminates
    // cleanly on command.
    cmd_tx.send(PeerCommand::Shutdown).await.unwrap();
    tokio::time::timeout(Duration::from_secs(5), session_task)
        .await
        .expect("session task must terminate on Shutdown")
        .expect("session task must not panic")
        .expect("run() must return Ok");
    // (1) The wire: the writer hard-closed, so the peer reaches EOF;
    // the Cease/8 is the FINAL frame and no UPDATE follows it.
    let wire = tokio::time::timeout(Duration::from_secs(15), reader)
        .await
        .expect("peer must observe EOF after the hard close")
        .unwrap();
    let frames = parse_wire_frames(&wire);
    let notif_idx = frames
        .iter()
        .position(|(msg_type, _)| *msg_type == 3)
        .expect("the Cease NOTIFICATION must reach the wire");
    assert_eq!(
        &frames[notif_idx].1[19..21],
        &[6, 8],
        "NOTIFICATION must be Cease/Out of Resources"
    );
    assert_eq!(
        notif_idx,
        frames.len() - 1,
        "the NOTIFICATION must be the final frame — the saturated backlog \
         must be discarded, never drained after the Cease"
    );
    let updates_on_wire = frames.iter().filter(|(t, _)| *t == 2).count();
    assert!(
        updates_on_wire > 0,
        "sanity: UPDATEs must have flowed before saturation"
    );
    assert!(
        updates_on_wire < flood_total,
        "sanity: the flood must have outrun the wire"
    );
}
// ── Inbound ORF ROUTE-REFRESH handling (RFC 5291/5292) ──────────────────
fn orf_rr_with_when(
    when_to_refresh: WhenToRefresh,
    orf_type: OrfType,
    entries: OrfEntries,
) -> RouteRefreshMessage {
    RouteRefreshMessage::new_with_orf(
        Afi::Ipv4,
        Safi::Unicast,
        OrfPayload {
            when_to_refresh,
            groups: vec![OrfEntryGroup { orf_type, entries }],
        },
    )
}
fn orf_rr(orf_type: OrfType, entries: OrfEntries) -> RouteRefreshMessage {
    orf_rr_with_when(WhenToRefresh::Immediate, orf_type, entries)
}
fn orf_rr_with_groups(groups: Vec<OrfEntryGroup>) -> RouteRefreshMessage {
    RouteRefreshMessage::new_with_orf(
        Afi::Ipv4,
        Safi::Unicast,
        OrfPayload {
            when_to_refresh: WhenToRefresh::Immediate,
            groups,
        },
    )
}
fn one_permit_entry() -> OrfEntries {
    OrfEntries::AddressPrefix(vec![AddressPrefixOrf {
        action: OrfAction::Add,
        match_: OrfMatch::Permit,
        sequence: 1,
        min_len: 0,
        max_len: 0,
        prefix: Some(Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 8))),
    }])
}
#[derive(Debug)]
struct CapturedOrfUpdate {
    afi: Afi,
    safi: Safi,
    when: WhenToRefresh,
    entries: Vec<AddressPrefixOrf>,
}
async fn drive_inbound_orf_with_reply(
    session: &mut PeerSession,
    rib_rx: &mut mpsc::Receiver<RibUpdate>,
    rr: &RouteRefreshMessage,
    reply_result: Result<(), String>,
) -> (bool, CapturedOrfUpdate) {
    let process = session.process_inbound_orf(Afi::Ipv4, Safi::Unicast, rr);
    tokio::pin!(process);
    let msg = tokio::select! {
        msg = rib_rx.recv() => msg.expect("PeerOrfUpdate should be emitted"),
        handled = &mut process => panic!("process_inbound_orf returned before RIB reply: {handled}"),
    };
    let RibUpdate::PeerOrfUpdate {
        afi,
        safi,
        when,
        entries,
        reply,
        ..
    } = msg
    else {
        panic!("expected RibUpdate::PeerOrfUpdate");
    };
    reply
        .send(reply_result)
        .expect("process_inbound_orf should still be awaiting RIB reply");
    let handled = process.await;
    (
        handled,
        CapturedOrfUpdate {
            afi,
            safi,
            when,
            entries,
        },
    )
}
#[tokio::test]
async fn inbound_orf_emits_peer_orf_update_when_negotiated() {
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    let mut neg = negotiated_session(65002, false);
    neg.negotiated_orf_recv = vec![(Afi::Ipv4, Safi::Unicast)];
    session.negotiated = Some(neg);
    let rr = orf_rr(OrfType::AddressPrefix, one_permit_entry());
    let (handled, update) =
        drive_inbound_orf_with_reply(&mut session, &mut rib_rx, &rr, Ok(())).await;
    assert!(handled, "accepted ORF must be handled by the RIB");
    assert_eq!((update.afi, update.safi), (Afi::Ipv4, Safi::Unicast));
    assert_eq!(update.when, WhenToRefresh::Immediate);
    assert_eq!(update.entries.len(), 1);
}
#[tokio::test]
async fn inbound_orf_preserves_defer_when_negotiated() {
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    let mut neg = negotiated_session(65002, false);
    neg.negotiated_orf_recv = vec![(Afi::Ipv4, Safi::Unicast)];
    session.negotiated = Some(neg);
    let rr = orf_rr_with_when(
        WhenToRefresh::Defer,
        OrfType::AddressPrefix,
        one_permit_entry(),
    );
    let (handled, update) =
        drive_inbound_orf_with_reply(&mut session, &mut rib_rx, &rr, Ok(())).await;
    assert!(handled, "accepted ORF must be handled by the RIB");
    assert_eq!(update.when, WhenToRefresh::Defer);
    assert_eq!(update.entries.len(), 1);
}
#[tokio::test]
async fn inbound_orf_ignored_when_family_not_negotiated() {
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    // negotiated_session() leaves negotiated_orf_recv empty.
    session.negotiated = Some(negotiated_session(65002, false));
    let rr = orf_rr(OrfType::AddressPrefix, one_permit_entry());
    let handled = session
        .process_inbound_orf(Afi::Ipv4, Safi::Unicast, &rr)
        .await;
    assert!(!handled, "ORF for an un-negotiated family is ignored");
    assert!(
        rib_rx.try_recv().is_err(),
        "no PeerOrfUpdate should be emitted"
    );
}
#[tokio::test]
async fn inbound_orf_ignores_legacy_type_128() {
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    let mut neg = negotiated_session(65002, false);
    neg.negotiated_orf_recv = vec![(Afi::Ipv4, Safi::Unicast)];
    session.negotiated = Some(neg);
    // Family negotiated, but the legacy type 128 is never negotiated by us.
    let rr = orf_rr(OrfType::AddressPrefixLegacy, one_permit_entry());
    let handled = session
        .process_inbound_orf(Afi::Ipv4, Safi::Unicast, &rr)
        .await;
    assert!(!handled, "legacy type 128 is not a negotiated type");
    assert!(rib_rx.try_recv().is_err());
}
#[tokio::test]
async fn inbound_orf_malformed_group_resets_via_remove_all() {
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    let mut neg = negotiated_session(65002, false);
    neg.negotiated_orf_recv = vec![(Afi::Ipv4, Safi::Unicast)];
    session.negotiated = Some(neg);
    // A malformed Address-Prefix group → RFC 5291 §5.2 reset (REMOVE-ALL).
    let rr = orf_rr(
        OrfType::AddressPrefix,
        OrfEntries::Malformed(Bytes::from_static(&[0x40])),
    );
    let (handled, update) =
        drive_inbound_orf_with_reply(&mut session, &mut rib_rx, &rr, Ok(())).await;
    assert!(handled);
    assert_eq!(update.entries.len(), 1);
    assert_eq!(update.entries[0].action, OrfAction::RemoveAll);
}
#[tokio::test]
async fn inbound_orf_rejected_by_rib_falls_through_to_plain_refresh() {
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    let mut neg = negotiated_session(65002, false);
    neg.negotiated_orf_recv = vec![(Afi::Ipv4, Safi::Unicast)];
    session.negotiated = Some(neg);
    let rr = orf_rr(OrfType::AddressPrefix, one_permit_entry());
    let (handled, update) = drive_inbound_orf_with_reply(
        &mut session,
        &mut rib_rx,
        &rr,
        Err("stale ORF update".to_string()),
    )
    .await;
    assert!(
        !handled,
        "RIB rejection must not silently suppress plain Route Refresh fallback"
    );
    assert_eq!((update.afi, update.safi), (Afi::Ipv4, Safi::Unicast));
}
#[tokio::test]
async fn inbound_orf_any_rib_group_rejection_falls_through_to_plain_refresh() {
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    let mut neg = negotiated_session(65002, false);
    neg.negotiated_orf_recv = vec![(Afi::Ipv4, Safi::Unicast)];
    session.negotiated = Some(neg);
    let rr = orf_rr_with_groups(vec![
        OrfEntryGroup {
            orf_type: OrfType::AddressPrefix,
            entries: one_permit_entry(),
        },
        OrfEntryGroup {
            orf_type: OrfType::AddressPrefix,
            entries: one_permit_entry(),
        },
    ]);
    let process = session.process_inbound_orf(Afi::Ipv4, Safi::Unicast, &rr);
    tokio::pin!(process);
    let first = tokio::select! {
        msg = rib_rx.recv() => msg.expect("first PeerOrfUpdate should be emitted"),
        handled = &mut process => panic!("process_inbound_orf returned before first RIB reply: {handled}"),
    };
    let RibUpdate::PeerOrfUpdate { reply, .. } = first else {
        panic!("expected first RibUpdate::PeerOrfUpdate");
    };
    reply
        .send(Ok(()))
        .expect("process_inbound_orf should await first RIB reply");
    let second = tokio::select! {
        msg = rib_rx.recv() => msg.expect("second PeerOrfUpdate should be emitted"),
        handled = &mut process => panic!("process_inbound_orf returned before second RIB reply: {handled}"),
    };
    let RibUpdate::PeerOrfUpdate { reply, .. } = second else {
        panic!("expected second RibUpdate::PeerOrfUpdate");
    };
    reply
        .send(Err("peer no longer registered".to_string()))
        .expect("process_inbound_orf should await second RIB reply");
    let handled = process.await;
    assert!(
        !handled,
        "any RIB rejection must fall through to the plain Route Refresh path"
    );
}
#[tokio::test]
async fn inbound_orf_dropped_rib_reply_falls_through_to_plain_refresh() {
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    let mut neg = negotiated_session(65002, false);
    neg.negotiated_orf_recv = vec![(Afi::Ipv4, Safi::Unicast)];
    session.negotiated = Some(neg);
    let rr = orf_rr(OrfType::AddressPrefix, one_permit_entry());
    let process = session.process_inbound_orf(Afi::Ipv4, Safi::Unicast, &rr);
    tokio::pin!(process);
    let msg = tokio::select! {
        msg = rib_rx.recv() => msg.expect("PeerOrfUpdate should be emitted"),
        handled = &mut process => panic!("process_inbound_orf returned before RIB reply: {handled}"),
    };
    let RibUpdate::PeerOrfUpdate { reply, .. } = msg else {
        panic!("expected RibUpdate::PeerOrfUpdate");
    };
    drop(reply);
    let handled = process.await;
    assert!(
        !handled,
        "dropped RIB reply must not silently suppress plain Route Refresh fallback"
    );
}
#[tokio::test]
async fn inbound_orf_rib_reply_timeout_falls_through_to_plain_refresh() {
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    let mut neg = negotiated_session(65002, false);
    neg.negotiated_orf_recv = vec![(Afi::Ipv4, Safi::Unicast)];
    session.negotiated = Some(neg);
    let rr = orf_rr(OrfType::AddressPrefix, one_permit_entry());
    let process = session.process_inbound_orf(Afi::Ipv4, Safi::Unicast, &rr);
    tokio::pin!(process);
    let msg = tokio::select! {
        msg = rib_rx.recv() => msg.expect("PeerOrfUpdate should be emitted"),
        handled = &mut process => panic!("process_inbound_orf returned before RIB reply: {handled}"),
    };
    let RibUpdate::PeerOrfUpdate { reply, .. } = msg else {
        panic!("expected RibUpdate::PeerOrfUpdate");
    };
    let _keep_reply_open = reply;
    let handled = tokio::time::timeout(Duration::from_secs(1), process)
        .await
        .expect("ORF reply wait should be bounded");
    assert!(
        !handled,
        "RIB reply timeout must not silently suppress plain Route Refresh fallback"
    );
}
// ---------------------------------------------------------------------------
// ADR-0078: inbound transport→RIB backpressure — block, never drop
// ---------------------------------------------------------------------------
fn counter_value(metrics: &BgpMetrics, name: &str, peer: &str) -> f64 {
    metrics
        .registry()
        .gather()
        .into_iter()
        .find(|family| family.name() == name)
        .and_then(|family| {
            family.get_metric().iter().find_map(|metric| {
                metric
                    .get_label()
                    .iter()
                    .any(|label| label.name() == "peer" && label.value() == peer)
                    .then(|| {
                        metric
                            .get_counter()
                            .as_ref()
                            .map_or(0.0, prometheus::proto::Counter::value)
                    })
            })
        })
        .unwrap_or(0.0)
}
fn backpressure_test_session(
    rib_capacity: usize,
) -> (PeerSession, mpsc::Receiver<RibUpdate>, BgpMetrics) {
    let mut peer_config = PeerConfig::new(65001, 65002, Ipv4Addr::new(10, 0, 0, 1));
    peer_config.connect_retry_secs = 30;
    peer_config.families = vec![(Afi::Ipv4, Safi::Unicast)];
    peer_config.gr_restart_time = 120;
    let config = TransportConfig::new(peer_config, "10.0.0.2:179".parse().unwrap());
    let metrics = BgpMetrics::new();
    let (_cmd_tx, cmd_rx) = mpsc::channel(8);
    let (rib_tx, rib_rx) = mpsc::channel(rib_capacity);
    let session = PeerSession::new(
        config,
        metrics.clone(),
        cmd_rx,
        rib_tx,
        None,
        None,
        None,
        None,
        None,
        false,
    );
    (session, rib_rx, metrics)
}
fn sample_update_message() -> bytes::BytesMut {
    let update = rustbgpd_wire::UpdateMessage::build(
        &[Ipv4NlriEntry {
            path_id: 0,
            prefix: Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24),
        }],
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
        rustbgpd_wire::Ipv4UnicastMode::Body,
    );
    rustbgpd_wire::encode_message(&Message::Update(update)).unwrap()
}
fn placeholder_routes_received() -> RibUpdate {
    RibUpdate::RoutesReceived {
        session_id: 0,
        peer: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 99)),
        announced: vec![],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    }
}
/// ADR-0078 rule 1: a full RIB channel parks the session task instead of
/// dropping the batch — the routes arrive once the channel drains, and
/// the saturation counter records the blocked send.
#[tokio::test]
async fn full_rib_channel_parks_session_and_never_drops_routes() {
    let (mut session, mut rib_rx, metrics) = backpressure_test_session(1);
    session.negotiated = Some(negotiated_session(65002, false));
    session.negotiated_families = vec![(Afi::Ipv4, Safi::Unicast)];
    // Fill the capacity-1 channel so the delivery must block.
    session
        .rib_tx
        .try_send(placeholder_routes_received())
        .unwrap();
    session
        .read_buf
        .buf
        .extend_from_slice(&sample_update_message());
    let peer_label = session.peer_label.clone();
    let process = session.process_read_buffer();
    tokio::pin!(process);
    assert!(
        tokio::time::timeout(Duration::from_millis(100), &mut process)
            .await
            .is_err(),
        "processing must park on the full RIB channel, not drop the batch"
    );
    // Drain the pre-fill; the parked delivery completes.
    let placeholder = rib_rx.recv().await.expect("pre-filled update");
    assert!(matches!(
        placeholder,
        RibUpdate::RoutesReceived { peer, .. } if peer == IpAddr::V4(Ipv4Addr::new(192, 0, 2, 99))
    ));
    tokio::time::timeout(Duration::from_secs(5), &mut process)
        .await
        .expect("processing must complete once the RIB drains");
    match rib_rx.recv().await.expect("delivered batch") {
        RibUpdate::RoutesReceived { announced, .. } => {
            assert_eq!(announced.len(), 1);
            assert_eq!(
                announced[0].prefix,
                Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24))
            );
        }
        _ => panic!("expected RoutesReceived"),
    }
    let blocked = counter_value(&metrics, "bgp_inbound_rib_backpressure_total", &peer_label);
    assert!((blocked - 1.0).abs() < f64::EPSILON, "got {blocked}");
}
/// ADR-0078 rule 3: a hold-timer expiry with an unprocessed COMPLETE
/// frame already in the read buffer re-arms instead of expiring — we
/// were the bottleneck, not the peer. The buffered bytes are a full
/// encoded KEEPALIVE on purpose: liveness is counted in complete
/// frames, so partial bytes would not qualify (see
/// `hold_expiry_with_partial_frame_expires`).
#[tokio::test]
async fn hold_expiry_with_buffered_input_rearms_instead_of_expiring() {
    let (mut session, _rib_rx) = make_test_session_with_rib(65001, 65002);
    let (client, _server) = connected_stream_pair().await;
    session.test_install_stream(client);
    establish_test_session(&mut session, 65002).await;
    assert_eq!(session.fsm.state(), SessionState::Established);
    let keepalive = rustbgpd_wire::encode_message(&Message::Keepalive).unwrap();
    session.read_buf.buf.extend_from_slice(&keepalive);
    session.timers.hold = None; // the expiry the select loop observed
    session.handle_hold_timer_expiry().await;
    assert_eq!(
        session.fsm.state(),
        SessionState::Established,
        "pending input must not let the hold timer tear the session down"
    );
    assert!(
        session.timers.hold.is_some(),
        "processing the buffered KEEPALIVE must re-arm the hold timer"
    );
    let rearmed = counter_value(
        &session.metrics.clone(),
        "bgp_hold_timer_rearmed_pending_input_total",
        &session.peer_label,
    );
    assert!((rearmed - 1.0).abs() < f64::EPSILON, "got {rearmed}");
}
/// ADR-0078 rule 3, socket flavor: a complete frame sitting unread in
/// the kernel receive buffer also counts as liveness at hold expiry.
/// As above, the peer writes a full encoded KEEPALIVE — completeness
/// is what qualifies it as liveness, not the mere presence of bytes.
#[tokio::test]
async fn hold_expiry_with_unread_socket_data_rearms() {
    use tokio::io::AsyncWriteExt;
    let (mut session, _rib_rx) = make_test_session_with_rib(65001, 65002);
    let (client, mut server) = connected_stream_pair().await;
    session.test_install_stream(client);
    establish_test_session(&mut session, 65002).await;
    let keepalive = rustbgpd_wire::encode_message(&Message::Keepalive).unwrap();
    server.write_all(&keepalive).await.unwrap();
    server.flush().await.unwrap();
    // Let the bytes land in the local receive buffer.
    tokio::time::sleep(Duration::from_millis(50)).await;
    session.timers.hold = None;
    session.handle_hold_timer_expiry().await;
    assert_eq!(session.fsm.state(), SessionState::Established);
    assert!(session.timers.hold.is_some());
}
/// A partial frame in the read buffer is NOT liveness: a peer whose
/// application hangs mid-frame while its kernel keeps acknowledging must not
/// re-arm the hold timer forever (zombie session). RFC 4271 resets the
/// hold timer on receipt of a complete message; ten bytes of a header
/// don't qualify, so the expiry stands.
#[tokio::test]
async fn hold_expiry_with_partial_frame_expires() {
    let (mut session, _rib_rx) = make_test_session_with_rib(65001, 65002);
    let (client, _server) = connected_stream_pair().await;
    session.test_install_stream(client);
    establish_test_session(&mut session, 65002).await;
    let keepalive = rustbgpd_wire::encode_message(&Message::Keepalive).unwrap();
    session.read_buf.buf.extend_from_slice(&keepalive[..10]);
    session.timers.hold = None;
    session.handle_hold_timer_expiry().await;
    assert_ne!(
        session.fsm.state(),
        SessionState::Established,
        "a permanently incomplete frame must not hold the session open"
    );
    assert!(
        session.timers.hold.is_none(),
        "partial input must not re-arm the hold timer"
    );
}
/// Partial frame, socket flavor: the peer wrote ten bytes of a frame
/// and then hung. The socket probe drains them into the read buffer,
/// but without a complete frame there is no liveness — the session
/// expires instead of zombieing.
#[tokio::test]
async fn hold_expiry_with_partial_socket_frame_expires() {
    use tokio::io::AsyncWriteExt;
    let (mut session, _rib_rx) = make_test_session_with_rib(65001, 65002);
    let (client, mut server) = connected_stream_pair().await;
    session.test_install_stream(client);
    establish_test_session(&mut session, 65002).await;
    let keepalive = rustbgpd_wire::encode_message(&Message::Keepalive).unwrap();
    server.write_all(&keepalive[..10]).await.unwrap();
    server.flush().await.unwrap();
    // Let the bytes land in the local receive buffer.
    tokio::time::sleep(Duration::from_millis(50)).await;
    session.timers.hold = None;
    session.handle_hold_timer_expiry().await;
    assert_ne!(
        session.fsm.state(),
        SessionState::Established,
        "a peer hung mid-frame must still expire the hold timer"
    );
}
/// Boundary: one complete frame followed by a partial second frame
/// re-arms — the complete frame is liveness, and the trailing partial
/// simply waits in the buffer for the rest of its bytes.
#[tokio::test]
async fn hold_expiry_with_complete_frame_then_partial_rearms() {
    let (mut session, _rib_rx) = make_test_session_with_rib(65001, 65002);
    let (client, _server) = connected_stream_pair().await;
    session.test_install_stream(client);
    establish_test_session(&mut session, 65002).await;
    let keepalive = rustbgpd_wire::encode_message(&Message::Keepalive).unwrap();
    session.read_buf.buf.extend_from_slice(&keepalive);
    session.read_buf.buf.extend_from_slice(&keepalive[..10]);
    session.timers.hold = None;
    session.handle_hold_timer_expiry().await;
    assert_eq!(
        session.fsm.state(),
        SessionState::Established,
        "the complete leading frame is liveness even with a partial tail"
    );
    assert!(
        session.timers.hold.is_some(),
        "processing the complete KEEPALIVE must re-arm the hold timer"
    );
    assert_eq!(
        session.read_buf.buf.len(),
        10,
        "the partial second frame stays buffered for the normal read path"
    );
}
/// When the pending input itself tears the session down (here: a
/// NOTIFICATION), the manual re-arm after processing must be skipped.
/// The FSM stopped the hold timer and closed the connection during
/// teardown; re-arming would plant a hold timer on the dead session
/// that later fires in Idle and logs a spurious stale-timer
/// "daemon-side timer-management bug" warning.
#[tokio::test]
async fn hold_expiry_teardown_during_processing_does_not_rearm() {
    let (mut session, _rib_rx) = make_test_session_with_rib(65001, 65002);
    let (client, _server) = connected_stream_pair().await;
    session.test_install_stream(client);
    establish_test_session(&mut session, 65002).await;
    let notification =
        rustbgpd_wire::encode_message(&Message::Notification(NotificationMessage::new(
            NotificationCode::Cease,
            cease_subcode::ADMINISTRATIVE_SHUTDOWN,
            Bytes::new(),
        )))
        .unwrap();
    session.read_buf.buf.extend_from_slice(&notification);
    session.timers.hold = None;
    session.handle_hold_timer_expiry().await;
    assert_ne!(
        session.fsm.state(),
        SessionState::Established,
        "the buffered NOTIFICATION must tear the session down"
    );
    assert!(
        session.read_half.is_none(),
        "teardown must have dropped the read half"
    );
    assert!(
        session.timers.hold.is_none(),
        "a torn-down session must not get its hold timer re-armed"
    );
}
/// A genuinely silent peer still expires: no buffered or readable input
/// means the hold expiry stands and the session leaves Established.
#[tokio::test]
async fn hold_expiry_without_pending_input_expires() {
    let (mut session, _rib_rx) = make_test_session_with_rib(65001, 65002);
    let (client, _server) = connected_stream_pair().await;
    session.test_install_stream(client);
    establish_test_session(&mut session, 65002).await;
    session.timers.hold = None;
    session.handle_hold_timer_expiry().await;
    assert_ne!(
        session.fsm.state(),
        SessionState::Established,
        "a silent peer must still expire the hold timer"
    );
}
/// ADR-0078 rule 2: negotiating a session routes the KEEPALIVE cadence
/// to the writer task (watch holds the negotiated interval) instead of
/// arming the session-loop keepalive timer.
#[tokio::test]
async fn established_session_routes_keepalive_cadence_to_writer() {
    let (mut session, _rib_rx) = make_test_session_with_rib(65001, 65002);
    let (client, _server) = connected_stream_pair().await;
    session.test_install_stream(client);
    establish_test_session(&mut session, 65002).await;
    assert!(
        session.timers.keepalive.is_none(),
        "the session loop must not own the keepalive cadence"
    );
    let cadence = *session
        .writer_keepalive_tx
        .as_ref()
        .expect("writer keepalive control must exist")
        .borrow();
    assert_eq!(
        cadence,
        Some(Duration::from_secs(30)),
        "hold 90 negotiates a 30 s keepalive cadence owned by the writer"
    );
}

/// RFC 9687 §4.3 teardown semantics at the session layer: a writer
/// exit of `SendHoldExpired` must (1) tear the session down to Idle
/// through the TCP-failure path, (2) emit a BMP Peer Down with reason
/// 2 — local close, *no* NOTIFICATION — carrying FSM event code 29
/// (`SendHoldTimer_Expires`, RFC 9687 §4.2), (3) increment
/// `bgp_send_hold_expirations_total`, and (4) put no NOTIFICATION on
/// the wire (the peer observes a bare FIN after the handshake bytes).
#[tokio::test]
async fn send_hold_expiry_tears_down_without_notification() {
    let (mut session, _rib_rx, mut bmp_rx) = make_test_session_with_rib_and_bmp(65001, 65002);
    let (client, mut server) = connected_stream_pair().await;
    session.test_install_stream(client);
    establish_test_session(&mut session, 65002).await;

    // Drain the handshake bytes we sent (OPEN + KEEPALIVE) and the BMP
    // Peer Up so the assertions below observe only the teardown.
    assert!(matches!(
        read_single_bgp_message(&mut server).await,
        Message::Open(_)
    ));
    assert!(matches!(
        read_single_bgp_message(&mut server).await,
        Message::Keepalive
    ));
    assert!(matches!(
        bmp_rx.recv().await.unwrap(),
        BmpEvent::PeerUp { .. }
    ));

    // The writer observed a wedged peer and exited with SendHoldExpired.
    session
        .handle_writer_exit(Ok(Err(super::writer::WriterExit::SendHoldExpired {
            limit: Duration::from_secs(2),
        })))
        .await;

    assert_eq!(session.fsm.state(), SessionState::Idle);
    match bmp_rx.recv().await.unwrap() {
        BmpEvent::PeerDown { reason, .. } => {
            assert!(
                matches!(reason, PeerDownReason::LocalNoNotification(29)),
                "expected reason 2 with FSM event 29, got {reason:?}"
            );
        }
        other => panic!("expected BMP PeerDown, got {other:?}"),
    }
    let expirations = counter_value(
        &session.metrics.clone(),
        "bgp_send_hold_expirations_total",
        &session.peer_label,
    );
    assert!(
        (expirations - 1.0).abs() < f64::EPSILON,
        "got {expirations}"
    );
    assert!(session.last_error.contains("send hold timer expired"));

    // No NOTIFICATION follows the handshake: the teardown dropped the
    // writer senders, so the peer sees EOF as the very next event.
    let mut trailing = [0_u8; 64];
    let n = tokio::time::timeout(Duration::from_secs(5), server.read(&mut trailing))
        .await
        .expect("peer must observe EOF promptly")
        .unwrap();
    assert_eq!(
        n,
        0,
        "unexpected bytes after teardown: {:?}",
        &trailing[..n]
    );
}
/// RFC 8654 §2 directionality, inbound: OUR advertised Extended Message
/// capability governs what we accept. The peer here did NOT advertise the
/// capability (see `establish_test_session`'s OPEN), yet a >4096-byte
/// UPDATE from it must be accepted because we always advertise it.
#[tokio::test]
async fn inbound_extended_message_accepted_from_peer_without_capability() {
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    let (client, _server) = connected_stream_pair().await;
    session.test_install_stream(client);
    establish_test_session(&mut session, 65002).await;
    assert!(
        !session.negotiated.as_ref().unwrap().peer_extended_message,
        "test premise: the peer did not advertise Extended Messages"
    );
    // ~1100 /24 prefixes at 4 bytes of NLRI each pushes the UPDATE past 4096.
    let entries: Vec<Ipv4NlriEntry> = (0..1100_u32)
        .map(|i| Ipv4NlriEntry {
            path_id: 0,
            prefix: Ipv4Prefix::new(
                Ipv4Addr::new(
                    10,
                    u8::try_from(i / 256).unwrap(),
                    u8::try_from(i % 256).unwrap(),
                    0,
                ),
                24,
            ),
        })
        .collect();
    let update = rustbgpd_wire::UpdateMessage::build(
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
        rustbgpd_wire::Ipv4UnicastMode::Body,
    );
    let encoded = rustbgpd_wire::encode_message_with_limit(
        &Message::Update(update),
        rustbgpd_wire::EXTENDED_MAX_MESSAGE_LEN,
    )
    .unwrap();
    assert!(
        encoded.len() > usize::from(rustbgpd_wire::MAX_MESSAGE_LEN),
        "test premise: the UPDATE exceeds 4096 bytes (got {})",
        encoded.len()
    );
    session.read_buf.buf.extend_from_slice(&encoded);
    session.process_read_buffer().await;
    assert_eq!(
        session.fsm.state(),
        SessionState::Established,
        "an extended inbound message must not tear the session down"
    );
    // Establishment emits its own RibUpdate first; skip to the routes.
    loop {
        if let RibUpdate::RoutesReceived { announced, .. } =
            rib_rx.recv().await.expect("routes delivered")
        {
            assert_eq!(announced.len(), 1100);
            break;
        }
    }
}
/// RFC 8654 §2 directionality, outbound: the PEER's advertised Extended
/// Message capability governs what we may send. Without it, an oversized
/// message must fail to encode; with it, the extended limit applies.
#[tokio::test]
async fn outbound_extended_message_gated_on_peer_capability() {
    let mut session = make_test_session(65001, 65002);
    session.negotiated = Some(negotiated_session(65002, false));
    assert_eq!(
        session.outbound_max_message_len(),
        rustbgpd_wire::MAX_MESSAGE_LEN
    );
    let big = Message::Notification(rustbgpd_wire::NotificationMessage::new(
        rustbgpd_wire::NotificationCode::Cease,
        2,
        Bytes::from(vec![0_u8; 5000]),
    ));
    assert!(
        session.enqueue_priority(&big).is_err(),
        "oversized NOTIFICATION must not encode toward a peer without the capability"
    );
    session.negotiated.as_mut().unwrap().peer_extended_message = true;
    assert_eq!(
        session.outbound_max_message_len(),
        rustbgpd_wire::EXTENDED_MAX_MESSAGE_LEN
    );
    assert!(
        session.enqueue_priority(&big).is_ok(),
        "the peer advertised Extended Messages — the extended limit applies"
    );
}
