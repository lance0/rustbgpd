use bytes::Bytes;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rustbgpd_fsm::PeerConfig;
use rustbgpd_policy::{
    AsPathRegex, CommunityMatch, Policy, PolicyAction, PolicyChain, PolicyStatement,
    RouteModifications,
};
use rustbgpd_wire::{
    AddressPrefixOrf, AsPath, AsPathSegment, FlowSpecComponent, FlowSpecPrefix, FlowSpecRule,
    Ipv4NlriEntry, Ipv4Prefix, Ipv6Prefix, LlgrFamily, Message, OrfAction, OrfEntries,
    OrfEntryGroup, OrfMatch, OrfPayload, OrfType, Origin, PathAttribute, WhenToRefresh,
    bgpls::{BgpLsNlri, BgpLsNlriType, decode_bgpls_nlri},
};
use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;
use tokio::sync::oneshot;

use super::*;

fn make_test_session(local_asn: u32, remote_asn: u32) -> PeerSession {
    let peer_config = PeerConfig {
        local_asn,
        remote_asn,
        local_router_id: Ipv4Addr::new(10, 0, 0, 1),
        hold_time: 90,
        connect_retry_secs: 30,
        families: vec![(Afi::Ipv4, Safi::Unicast)],
        graceful_restart: false,
        gr_restart_time: 120,
        llgr_stale_time: 0,
        add_path_receive: false,
        add_path_send: false,
        add_path_send_max: 0,
        local_role: None,
        strict_role: false,
        prefix_orf_receive: false,
        disable_ipv4_unicast: false,
    };
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
    let peer_config = PeerConfig {
        local_asn,
        remote_asn,
        local_router_id: Ipv4Addr::new(10, 0, 0, 1),
        hold_time: 90,
        connect_retry_secs: 30,
        families: vec![(Afi::Ipv4, Safi::Unicast)],
        graceful_restart: false,
        gr_restart_time: 120,
        llgr_stale_time: 0,
        add_path_receive: false,
        add_path_send: false,
        add_path_send_max: 0,
        local_role: None,
        strict_role: false,
        prefix_orf_receive: false,
        disable_ipv4_unicast: false,
    };
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
    let peer_config = PeerConfig {
        local_asn,
        remote_asn,
        local_router_id: Ipv4Addr::new(10, 0, 0, 1),
        hold_time: 90,
        connect_retry_secs: 30,
        families: vec![(Afi::Ipv4, Safi::Unicast)],
        graceful_restart: false,
        gr_restart_time: 120,
        llgr_stale_time: 0,
        add_path_receive: false,
        add_path_send: false,
        add_path_send_max: 0,
        local_role: None,
        strict_role: false,
        prefix_orf_receive: false,
        disable_ipv4_unicast: false,
    };
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
    NegotiatedSession {
        peer_asn: remote_asn,
        peer_router_id: Ipv4Addr::new(10, 0, 0, 2),
        hold_time: 90,
        keepalive_interval: 30,
        peer_capabilities: vec![],
        four_octet_as: true,
        negotiated_families: vec![(Afi::Ipv4, Safi::Unicast)],
        peer_gr_capable: false,
        peer_restart_state: false,
        peer_restart_time: 0,
        peer_gr_families: vec![],
        peer_notification_gr: false,
        peer_llgr_capable: false,
        peer_llgr_families: vec![],
        peer_route_refresh: false,
        peer_enhanced_route_refresh: false,
        peer_extended_message: false,
        local_role: None,
        remote_role: None,
        role_negotiated: false,
        extended_nexthop_families,
        add_path_families: HashMap::new(),
        negotiated_orf_recv: Vec::new(),
    }
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

    match rib_rx.recv().await.unwrap() {
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
        announce: vec![route1, route2],
        withdraw: vec![],
        end_of_rib: vec![],
        refresh_markers: vec![],
        next_hop_override: vec![None, None],
        flowspec_announce: vec![],
        flowspec_withdraw: vec![],
        evpn_announce: vec![],
        evpn_withdraw: vec![],
        bgpls_announce: vec![],
        bgpls_withdraw: vec![],
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
        announce: vec![],
        withdraw: vec![],
        end_of_rib: vec![],
        refresh_markers: vec![],
        next_hop_override: vec![],
        flowspec_announce: vec![],
        flowspec_withdraw: vec![],
        evpn_announce: vec![],
        evpn_withdraw: vec![],
        bgpls_announce: vec![route.clone()],
        bgpls_withdraw: vec![],
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
        announce: vec![],
        withdraw: vec![],
        end_of_rib: vec![],
        refresh_markers: vec![],
        next_hop_override: vec![],
        flowspec_announce: vec![],
        flowspec_withdraw: vec![],
        evpn_announce: vec![],
        evpn_withdraw: vec![],
        bgpls_announce: vec![],
        bgpls_withdraw: vec![key],
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
        announce: vec![],
        withdraw: vec![],
        end_of_rib: vec![],
        refresh_markers: vec![],
        next_hop_override: vec![],
        flowspec_announce: vec![],
        flowspec_withdraw: vec![],
        evpn_announce: vec![],
        evpn_withdraw: vec![],
        bgpls_announce: vec![route],
        bgpls_withdraw: vec![],
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
    assert!(result.is_ok());
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
        announce: vec![],
        withdraw: vec![],
        end_of_rib: vec![],
        refresh_markers: vec![],
        next_hop_override: vec![],
        flowspec_announce: vec![],
        flowspec_withdraw: vec![],
        evpn_announce: vec![],
        evpn_withdraw: vec![],
        bgpls_announce: vec![],
        bgpls_withdraw: vec![],
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
        announce: vec![],
        withdraw: vec![],
        end_of_rib: vec![(Afi::Ipv4, Safi::Unicast)],
        refresh_markers: vec![],
        next_hop_override: vec![],
        flowspec_announce: vec![],
        flowspec_withdraw: vec![],
        evpn_announce: vec![],
        evpn_withdraw: vec![],
        bgpls_announce: vec![],
        bgpls_withdraw: vec![],
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
        announce: vec![route1, route2],
        withdraw: vec![],
        end_of_rib: vec![],
        refresh_markers: vec![],
        next_hop_override: vec![None, None],
        flowspec_announce: vec![],
        flowspec_withdraw: vec![],
        evpn_announce: vec![],
        evpn_withdraw: vec![],
        bgpls_announce: vec![],
        bgpls_withdraw: vec![],
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
        announce: vec![route],
        withdraw: vec![],
        end_of_rib: vec![],
        refresh_markers: vec![],
        next_hop_override: vec![Some(override_nh)],
        flowspec_announce: vec![],
        flowspec_withdraw: vec![],
        evpn_announce: vec![],
        evpn_withdraw: vec![],
        bgpls_announce: vec![],
        bgpls_withdraw: vec![],
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

#[test]
fn non_llgr_peer_strips_llgr_stale_community() {
    let session = make_test_session(65001, 65002);
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
    assert!(!attrs.iter().any(|a| {
        matches!(
            a,
            PathAttribute::Communities(comms)
                if comms.contains(&rustbgpd_wire::COMMUNITY_LLGR_STALE)
        )
    }));
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

#[tokio::test]
async fn modified_policy_update_owns_distinct_arc_per_nlri() {
    // Two IPv4 NLRI in one UPDATE, import policy adds a community → both
    // routes are modified, so each must own a distinct (mutated) Arc
    // rather than sharing the canonical one, and the mutation must land.
    const ADDED_COMMUNITY: u32 = 0xFDE9_0064; // 65001:100
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    session.negotiated = Some(negotiated_session(65002, false));
    session.import_policy = Some(PolicyChain::new(vec![Policy {
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
    }]));

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
    session.import_policy = Some(PolicyChain::new(vec![Policy {
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
    }]));

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
        }],
        withdraw: vec![],
        end_of_rib: vec![],
        refresh_markers: vec![],
        next_hop_override: vec![None],
        flowspec_announce: vec![],
        flowspec_withdraw: vec![],
        evpn_announce: vec![],
        evpn_withdraw: vec![],
        bgpls_announce: vec![],
        bgpls_withdraw: vec![],
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
        announce: vec![make_route(100)],
        withdraw: vec![],
        end_of_rib: vec![],
        refresh_markers: vec![],
        next_hop_override: vec![None],
        flowspec_announce: vec![],
        flowspec_withdraw: vec![],
        evpn_announce: vec![],
        evpn_withdraw: vec![],
        bgpls_announce: vec![],
        bgpls_withdraw: vec![],
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
        announce: vec![route],
        withdraw: vec![],
        end_of_rib: vec![],
        refresh_markers: vec![],
        next_hop_override: vec![None],
        flowspec_announce: vec![],
        flowspec_withdraw: vec![],
        evpn_announce: vec![],
        evpn_withdraw: vec![],
        bgpls_announce: vec![],
        bgpls_withdraw: vec![],
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
        announce: vec![route],
        withdraw: vec![],
        end_of_rib: vec![],
        refresh_markers: vec![],
        next_hop_override: vec![None],
        flowspec_announce: vec![],
        flowspec_withdraw: vec![],
        evpn_announce: vec![],
        evpn_withdraw: vec![],
        bgpls_announce: vec![],
        bgpls_withdraw: vec![],
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
        announce: vec![make_route(100)],
        withdraw: vec![],
        end_of_rib: vec![],
        refresh_markers: vec![],
        next_hop_override: vec![None],
        flowspec_announce: vec![],
        flowspec_withdraw: vec![],
        evpn_announce: vec![],
        evpn_withdraw: vec![],
        bgpls_announce: vec![],
        bgpls_withdraw: vec![],
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
        }],
        withdraw: vec![],
        end_of_rib: vec![],
        refresh_markers: vec![],
        next_hop_override: vec![None],
        flowspec_announce: vec![],
        flowspec_withdraw: vec![],
        evpn_announce: vec![],
        evpn_withdraw: vec![],
        bgpls_announce: vec![],
        bgpls_withdraw: vec![],
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
        announce: vec![route],
        withdraw: vec![],
        end_of_rib: vec![],
        refresh_markers: vec![],
        next_hop_override: vec![None],
        flowspec_announce: vec![],
        flowspec_withdraw: vec![],
        evpn_announce: vec![],
        evpn_withdraw: vec![],
        bgpls_announce: vec![],
        bgpls_withdraw: vec![],
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
        announce: vec![make_v6_unicast_route(route_next_hop)],
        withdraw: vec![],
        end_of_rib: vec![],
        refresh_markers: vec![],
        next_hop_override: vec![Some(rustbgpd_policy::NextHopAction::Self_)],
        flowspec_announce: vec![],
        flowspec_withdraw: vec![],
        evpn_announce: vec![],
        evpn_withdraw: vec![],
        bgpls_announce: vec![],
        bgpls_withdraw: vec![],
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
#[expect(
    clippy::too_many_lines,
    reason = "linear test scaffold + many fields per PolicyStatement; splitting hurts readability"
)]
#[tokio::test]
async fn import_policy_denied_routes_do_not_reach_rib() {
    // Create a session with import policy that denies 198.51.100.0/24
    let peer_config = PeerConfig {
        local_asn: 65001,
        remote_asn: 65002,
        local_router_id: Ipv4Addr::new(10, 0, 0, 1),
        hold_time: 90,
        connect_retry_secs: 30,
        families: vec![(Afi::Ipv4, Safi::Unicast)],
        graceful_restart: false,
        gr_restart_time: 120,
        llgr_stale_time: 0,
        add_path_receive: false,
        add_path_send: false,
        add_path_send_max: 0,
        local_role: None,
        strict_role: false,
        prefix_orf_receive: false,
        disable_ipv4_unicast: false,
    };
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

    let peer_config = PeerConfig {
        local_asn: 65001,
        remote_asn: 65002,
        local_router_id: Ipv4Addr::new(10, 0, 0, 1),
        hold_time: 90,
        connect_retry_secs: 30,
        families: vec![(Afi::Ipv4, Safi::Unicast)],
        graceful_restart: false,
        gr_restart_time: 120,
        llgr_stale_time: 0,
        add_path_receive: false,
        add_path_send: false,
        add_path_send_max: 0,
        local_role: None,
        strict_role: false,
        prefix_orf_receive: false,
        disable_ipv4_unicast: false,
    };
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
#[expect(
    clippy::too_many_lines,
    reason = "regression test keeps the multi-step policy refresh scenario readable"
)]
#[tokio::test]
async fn session_down_flushes_import_decision_cache() {
    use super::import_decision_cache::{ImportDecisionKey, LookupResult};

    let peer_config = PeerConfig {
        local_asn: 65001,
        remote_asn: 65002,
        local_router_id: Ipv4Addr::new(10, 0, 0, 1),
        hold_time: 90,
        connect_retry_secs: 30,
        families: vec![(Afi::Ipv4, Safi::Unicast)],
        graceful_restart: false,
        gr_restart_time: 120,
        llgr_stale_time: 0,
        add_path_receive: false,
        add_path_send: false,
        add_path_send_max: 0,
        local_role: None,
        strict_role: false,
        prefix_orf_receive: false,
        disable_ipv4_unicast: false,
    };
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

    let peer_config = PeerConfig {
        local_asn: 65001,
        remote_asn: 65002,
        local_router_id: Ipv4Addr::new(10, 0, 0, 1),
        hold_time: 90,
        connect_retry_secs: 30,
        families: vec![(Afi::Ipv4, Safi::Unicast)],
        graceful_restart: false,
        gr_restart_time: 120,
        llgr_stale_time: 0,
        add_path_receive: false,
        add_path_send: false,
        add_path_send_max: 0,
        local_role: None,
        strict_role: false,
        prefix_orf_receive: false,
        disable_ipv4_unicast: false,
    };
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
    // prefix condition and the local_pref transition rendered.
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
    assert_eq!(steps[0].modifications, vec!["local_pref 150 -> 200"]);

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

    let peer_config = PeerConfig {
        local_asn: 65001,
        remote_asn: 65002,
        local_router_id: Ipv4Addr::new(10, 0, 0, 1),
        hold_time: 90,
        connect_retry_secs: 30,
        families: vec![(Afi::Ipv4, Safi::Unicast)],
        graceful_restart: false,
        gr_restart_time: 120,
        llgr_stale_time: 0,
        add_path_receive: false,
        add_path_send: false,
        add_path_send_max: 0,
        local_role: None,
        strict_role: false,
        prefix_orf_receive: false,
        disable_ipv4_unicast: false,
    };
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

/// Import policy chains accumulate modifications across matching permit
/// policies before the route reaches the RIB.
#[expect(
    clippy::too_many_lines,
    reason = "regression test keeps accumulated policy modifications and route assertions together"
)]
#[tokio::test]
async fn import_policy_chain_accumulates_community_and_local_pref() {
    let peer_config = PeerConfig {
        local_asn: 65001,
        remote_asn: 65002,
        local_router_id: Ipv4Addr::new(10, 0, 0, 1),
        hold_time: 90,
        connect_retry_secs: 30,
        families: vec![(Afi::Ipv4, Safi::Unicast)],
        graceful_restart: false,
        gr_restart_time: 120,
        llgr_stale_time: 0,
        add_path_receive: false,
        add_path_send: false,
        add_path_send_max: 0,
        local_role: None,
        strict_role: false,
        prefix_orf_receive: false,
        disable_ipv4_unicast: false,
    };
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
    let peer_config = PeerConfig {
        local_asn: 65001,
        remote_asn: 65002,
        local_router_id: Ipv4Addr::new(10, 0, 0, 1),
        hold_time: 90,
        connect_retry_secs: 30,
        families: vec![(Afi::Ipv4, Safi::Unicast)],
        graceful_restart: false,
        gr_restart_time: 120,
        llgr_stale_time: 0,
        add_path_receive: false,
        add_path_send: false,
        add_path_send_max: 0,
        local_role: None,
        strict_role: false,
        prefix_orf_receive: false,
        disable_ipv4_unicast: false,
    };
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
    let peer_config = PeerConfig {
        local_asn: 65001,
        remote_asn: 65002,
        local_router_id: Ipv4Addr::new(10, 0, 0, 1),
        hold_time: 90,
        connect_retry_secs: 30,
        families: vec![(Afi::Ipv4, Safi::Unicast)],
        graceful_restart: false,
        gr_restart_time: 120,
        llgr_stale_time: 0,
        add_path_receive: false,
        add_path_send: false,
        add_path_send_max: 0,
        local_role: None,
        strict_role: false,
        prefix_orf_receive: false,
        disable_ipv4_unicast: false,
    };
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
    let peer_config = PeerConfig {
        local_asn: 65001,
        remote_asn: 65002,
        local_router_id: Ipv4Addr::new(10, 0, 0, 1),
        hold_time: 90,
        connect_retry_secs: 30,
        families: vec![(Afi::Ipv4, Safi::Unicast)],
        graceful_restart: false,
        gr_restart_time: 120,
        llgr_stale_time: 0,
        add_path_receive: false,
        add_path_send: false,
        add_path_send_max: 0,
        local_role: None,
        strict_role: false,
        prefix_orf_receive: false,
        disable_ipv4_unicast: false,
    };
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
                path_id: 42,
                prefix: Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24)),
            }],
            flowspec_announced: vec![],
            evpn_announced: vec![],
            bgpls_announced: vec![],
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

    let peer_config = PeerConfig {
        local_asn: 65001,
        remote_asn: 65002,
        local_router_id: Ipv4Addr::new(10, 0, 0, 1),
        hold_time: 90,
        connect_retry_secs: 30,
        families: vec![(Afi::Ipv4, Safi::Unicast)],
        graceful_restart: false,
        gr_restart_time: 120,
        llgr_stale_time: 0,
        add_path_receive: false,
        add_path_send: false,
        add_path_send_max: 0,
        local_role: None,
        strict_role: false,
        prefix_orf_receive: false,
        disable_ipv4_unicast: false,
    };
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

    let peer_config = PeerConfig {
        local_asn: 65001,
        remote_asn: 65002,
        local_router_id: Ipv4Addr::new(10, 0, 0, 1),
        hold_time: 90,
        connect_retry_secs: 30,
        families: vec![(Afi::Ipv4, Safi::Unicast)],
        graceful_restart: false,
        gr_restart_time: 120,
        llgr_stale_time: 0,
        add_path_receive: false,
        add_path_send: false,
        add_path_send_max: 0,
        local_role: None,
        strict_role: false,
        prefix_orf_receive: false,
        disable_ipv4_unicast: false,
    };
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
    let negotiated = NegotiatedSession {
        peer_asn: 65001,
        peer_router_id: Ipv4Addr::new(10, 0, 0, 2),
        hold_time: 90,
        keepalive_interval: 30,
        peer_capabilities: vec![],
        four_octet_as: true,
        negotiated_families: vec![(Afi::L2Vpn, Safi::Evpn)],
        peer_gr_capable: false,
        peer_restart_state: false,
        peer_restart_time: 0,
        peer_gr_families: vec![],
        peer_notification_gr: false,
        peer_llgr_capable: false,
        peer_llgr_families: vec![],
        peer_route_refresh: false,
        peer_enhanced_route_refresh: false,
        peer_extended_message: false,
        local_role: None,
        remote_role: None,
        role_negotiated: false,
        extended_nexthop_families: HashMap::new(),
        add_path_families: HashMap::new(),
        negotiated_orf_recv: Vec::new(),
    };
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
        }),
        PathAttribute::MpUnreachNlri(MpUnreachNlri {
            afi: Afi::L2Vpn,
            safi: Safi::Evpn,
            withdrawn: vec![],
            flowspec_withdrawn: vec![],
            evpn_withdrawn: vec![withdrawn_route],
            bgpls_withdrawn: vec![],
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
    let negotiated = NegotiatedSession {
        peer_asn: 65001,
        peer_router_id: Ipv4Addr::new(10, 0, 0, 2),
        hold_time: 90,
        keepalive_interval: 30,
        peer_capabilities: vec![],
        four_octet_as: true,
        negotiated_families: vec![(Afi::L2Vpn, Safi::Evpn)],
        peer_gr_capable: false,
        peer_restart_state: false,
        peer_restart_time: 0,
        peer_gr_families: vec![],
        peer_notification_gr: false,
        peer_llgr_capable: false,
        peer_llgr_families: vec![],
        peer_route_refresh: false,
        peer_enhanced_route_refresh: false,
        peer_extended_message: false,
        local_role: None,
        remote_role: None,
        role_negotiated: false,
        extended_nexthop_families: HashMap::new(),
        add_path_families: HashMap::new(),
        negotiated_orf_recv: Vec::new(),
    };
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
    let negotiated = NegotiatedSession {
        peer_asn: 65002,
        peer_router_id: Ipv4Addr::new(10, 0, 0, 2),
        hold_time: 90,
        keepalive_interval: 30,
        peer_capabilities: vec![],
        four_octet_as: true,
        negotiated_families: vec![(Afi::L2Vpn, Safi::Evpn)],
        peer_gr_capable: false,
        peer_restart_state: false,
        peer_restart_time: 0,
        peer_gr_families: vec![],
        peer_notification_gr: false,
        peer_llgr_capable: false,
        peer_llgr_families: vec![],
        peer_route_refresh: false,
        peer_enhanced_route_refresh: false,
        peer_extended_message: false,
        local_role: None,
        remote_role: None,
        role_negotiated: false,
        extended_nexthop_families: HashMap::new(),
        add_path_families: HashMap::new(),
        negotiated_orf_recv: Vec::new(),
    };
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
        }),
        PathAttribute::MpUnreachNlri(MpUnreachNlri {
            afi: Afi::L2Vpn,
            safi: Safi::Evpn,
            withdrawn: vec![],
            flowspec_withdrawn: vec![],
            evpn_withdrawn: vec![withdrawn_route],
            bgpls_withdrawn: vec![],
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

    // After the priority message drains and both senders are gone, the
    // biased select's `else` arm fires and the writer exits Ok.
    let result = tokio::time::timeout(Duration::from_secs(2), join)
        .await
        .expect("writer should exit within 2s of senders dropped")
        .expect("writer task should not panic");
    assert!(
        result.is_ok(),
        "writer should exit Ok after clean shutdown, got: {result:?}"
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

#[tokio::test]
async fn inbound_orf_emits_peer_orf_update_when_negotiated() {
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    let mut neg = negotiated_session(65002, false);
    neg.negotiated_orf_recv = vec![(Afi::Ipv4, Safi::Unicast)];
    session.negotiated = Some(neg);

    let rr = orf_rr(OrfType::AddressPrefix, one_permit_entry());
    let handled = session
        .process_inbound_orf(Afi::Ipv4, Safi::Unicast, &rr)
        .await;
    assert!(handled, "negotiated ORF must be forwarded to the RIB");

    let msg = rib_rx.try_recv().expect("PeerOrfUpdate should be emitted");
    match msg {
        RibUpdate::PeerOrfUpdate {
            afi,
            safi,
            when,
            entries,
            ..
        } => {
            assert_eq!((afi, safi), (Afi::Ipv4, Safi::Unicast));
            assert_eq!(when, WhenToRefresh::Immediate);
            assert_eq!(entries.len(), 1);
        }
        _ => panic!("expected RibUpdate::PeerOrfUpdate"),
    }
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
    let handled = session
        .process_inbound_orf(Afi::Ipv4, Safi::Unicast, &rr)
        .await;
    assert!(handled, "negotiated ORF must be forwarded to the RIB");

    let msg = rib_rx.try_recv().expect("PeerOrfUpdate should be emitted");
    match msg {
        RibUpdate::PeerOrfUpdate { when, entries, .. } => {
            assert_eq!(when, WhenToRefresh::Defer);
            assert_eq!(entries.len(), 1);
        }
        _ => panic!("expected RibUpdate::PeerOrfUpdate"),
    }
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
    let handled = session
        .process_inbound_orf(Afi::Ipv4, Safi::Unicast, &rr)
        .await;
    assert!(handled);
    let msg = rib_rx.try_recv().expect("PeerOrfUpdate should be emitted");
    match msg {
        RibUpdate::PeerOrfUpdate { entries, .. } => {
            assert_eq!(entries.len(), 1);
            assert_eq!(entries[0].action, OrfAction::RemoveAll);
        }
        _ => panic!("expected RibUpdate::PeerOrfUpdate"),
    }
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
    let peer_config = PeerConfig {
        local_asn: 65001,
        remote_asn: 65002,
        local_router_id: Ipv4Addr::new(10, 0, 0, 1),
        hold_time: 90,
        connect_retry_secs: 30,
        families: vec![(Afi::Ipv4, Safi::Unicast)],
        graceful_restart: false,
        gr_restart_time: 120,
        llgr_stale_time: 0,
        add_path_receive: false,
        add_path_send: false,
        add_path_send_max: 0,
        local_role: None,
        strict_role: false,
        prefix_orf_receive: false,
        disable_ipv4_unicast: false,
    };
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
