use super::export::{ExportCandidate, ExportWithdrawal};
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
    bgpls::{BgpLsNlri, BgpLsNlriType, decode_bgpls_nlri, decode_bgpls_vpn_nlri},
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

#[test]
fn recreated_active_session_starts_at_committed_tcp_ao_generation() {
    let peer_config = PeerConfig::new(65001, 65002, Ipv4Addr::new(10, 0, 0, 1));
    let config = TransportConfig::new(peer_config, "10.0.0.2:179".parse().unwrap());
    let (_cmd_tx, cmd_rx) = mpsc::channel(8);
    let (rib_tx, _rib_rx) = mpsc::channel(8);
    let generation = crate::TcpAoRotationGeneration::new(7).unwrap();
    let session = PeerSession::new_at_tcp_ao_generation(
        config,
        BgpMetrics::new(),
        cmd_rx,
        rib_tx,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        false,
        SessionIdentity::default(),
        generation,
    );
    assert_eq!(session.tcp_ao_generation, generation);
}

#[test]
fn disconnected_active_session_accepts_only_immediate_append_only_generation() {
    let peer_config = PeerConfig::new(65001, 65002, Ipv4Addr::new(10, 0, 0, 1));
    let mut config = TransportConfig::new(peer_config, "10.0.0.2:179".parse().unwrap());
    let old = crate::TcpAoConfig {
        key: "old-secret".into(),
        send_id: 1,
        recv_id: 11,
        algorithm: crate::TcpAoAlgorithm::HmacSha256,
        preferred: false,
        deprecated: false,
    };
    config.tcp_ao = Some(crate::TcpAoKeyring(vec![old.clone()]));
    let (_cmd_tx, cmd_rx) = mpsc::channel(8);
    let (rib_tx, _rib_rx) = mpsc::channel(8);
    let mut session = PeerSession::new_at_tcp_ao_generation(
        config,
        BgpMetrics::new(),
        cmd_rx,
        rib_tx,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        false,
        SessionIdentity::default(),
        crate::TcpAoRotationGeneration::STARTUP,
    );
    let mut successor = old.clone();
    successor.key = "successor-secret".into();
    successor.send_id = 2;
    successor.recv_id = 12;
    let generation_two = crate::TcpAoRotationGeneration::new(2).unwrap();
    session
        .apply_tcp_ao_add_only(crate::TcpAoSessionGeneration {
            generation: generation_two,
            active_keyring: Some(crate::TcpAoKeyring(vec![old.clone(), successor])),
            accepted_owners: Vec::new().into(),
        })
        .unwrap();
    assert_eq!(session.tcp_ao_generation, generation_two);
    assert_eq!(session.config.tcp_ao.as_ref().unwrap().0.len(), 2);

    let skipped = session.apply_tcp_ao_add_only(crate::TcpAoSessionGeneration {
        generation: crate::TcpAoRotationGeneration::new(4).unwrap(),
        active_keyring: Some(crate::TcpAoKeyring(vec![old.clone()])),
        accepted_owners: Vec::new().into(),
    });
    assert!(skipped.is_err());

    let removal = session.apply_tcp_ao_add_only(crate::TcpAoSessionGeneration {
        generation: crate::TcpAoRotationGeneration::new(3).unwrap(),
        active_keyring: Some(crate::TcpAoKeyring(vec![old])),
        accepted_owners: Vec::new().into(),
    });
    assert!(removal.is_err());
    assert_eq!(session.tcp_ao_generation, generation_two);
}

#[test]
fn disconnected_protected_session_cannot_advance_without_active_owner_inventory() {
    let peer_config = PeerConfig::new(65001, 65002, Ipv4Addr::new(10, 0, 0, 1));
    let mut config = TransportConfig::new(peer_config, "10.0.0.2:179".parse().unwrap());
    config.tcp_ao = Some(crate::TcpAoKeyring(vec![crate::TcpAoConfig {
        key: "old-secret".into(),
        send_id: 1,
        recv_id: 11,
        algorithm: crate::TcpAoAlgorithm::HmacSha256,
        preferred: false,
        deprecated: false,
    }]));
    let (_cmd_tx, cmd_rx) = mpsc::channel(8);
    let (rib_tx, _rib_rx) = mpsc::channel(8);
    let mut session = PeerSession::new_at_tcp_ao_generation(
        config,
        BgpMetrics::new(),
        cmd_rx,
        rib_tx,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        false,
        SessionIdentity::default(),
        crate::TcpAoRotationGeneration::STARTUP,
    );
    let result = session.apply_tcp_ao_add_only(crate::TcpAoSessionGeneration {
        generation: crate::TcpAoRotationGeneration::new(2).unwrap(),
        active_keyring: None,
        accepted_owners: Vec::new().into(),
    });
    assert!(result.is_err());
    assert_eq!(
        session.tcp_ao_generation,
        crate::TcpAoRotationGeneration::STARTUP
    );
    assert!(session.config.tcp_ao.is_some());
}

fn make_test_session_with_rib(
    local_asn: u32,
    remote_asn: u32,
) -> (PeerSession, mpsc::Receiver<RibUpdate>) {
    let (session, _cmd_tx, rib_rx) = make_test_session_with_channels(local_asn, remote_asn, 64);
    (session, rib_rx)
}

fn make_test_session_with_channels(
    local_asn: u32,
    remote_asn: u32,
    rib_capacity: usize,
) -> (
    PeerSession,
    mpsc::Sender<PeerCommand>,
    mpsc::Receiver<RibUpdate>,
) {
    let mut peer_config = PeerConfig::new(local_asn, remote_asn, Ipv4Addr::new(10, 0, 0, 1));
    peer_config.connect_retry_secs = 30;
    peer_config.families = vec![(Afi::Ipv4, Safi::Unicast)];
    peer_config.gr_restart_time = 120;
    let config = TransportConfig::new(peer_config, "10.0.0.2:179".parse().unwrap());
    let metrics = BgpMetrics::new();
    let (cmd_tx, cmd_rx) = mpsc::channel(8);
    let (rib_tx, rib_rx) = mpsc::channel(rib_capacity);
    (
        PeerSession::new(
            config, metrics, cmd_rx, rib_tx, None, None, None, None, None, false,
        ),
        cmd_tx,
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

fn install_enhanced_refresh_session(
    session: &mut PeerSession,
    families: Vec<(Afi, Safi)>,
    graceful_restart: bool,
) {
    let mut negotiated = negotiated_session(65002, false);
    negotiated.negotiated_families = families;
    negotiated.peer_route_refresh = true;
    negotiated.peer_enhanced_route_refresh = true;
    if graceful_restart {
        negotiated
            .peer_capabilities
            .push(Capability::GracefulRestart {
                restart_state: false,
                notification: false,
                restart_time: 120,
                families: vec![],
            });
    }
    install_test_negotiated_session(session, negotiated);
}

fn buffer_route_refresh(
    session: &mut PeerSession,
    afi: Afi,
    safi: Safi,
    subtype: RouteRefreshSubtype,
) {
    let encoded = rustbgpd_wire::encode_message(&Message::RouteRefresh(
        RouteRefreshMessage::new_with_subtype(afi, safi, subtype),
    ))
    .unwrap();
    session.read_buf.buf.extend_from_slice(&encoded);
}

fn ipv4_announce(prefix: Ipv4Prefix, path_id: u32, add_path: bool) -> UpdateMessage {
    UpdateMessage::build(
        &[Ipv4NlriEntry { path_id, prefix }],
        &[],
        &[
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath {
                segments: vec![AsPathSegment::AsSequence(vec![65002])],
            }),
            PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
        ],
        true,
        add_path,
        Ipv4UnicastMode::Body,
    )
}

fn ipv6_announce(prefix: Ipv6Prefix, path_id: u32) -> UpdateMessage {
    UpdateMessage::build(
        &[],
        &[],
        &[
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath {
                segments: vec![AsPathSegment::AsSequence(vec![65002])],
            }),
            PathAttribute::MpReachNlri(MpReachNlri {
                afi: Afi::Ipv6,
                safi: Safi::Unicast,
                next_hop: "2001:db8::2".parse().unwrap(),
                link_local_next_hop: None,
                announced: vec![NlriEntry {
                    path_id,
                    prefix: Prefix::V6(prefix),
                }],
                flowspec_announced: vec![],
                evpn_announced: vec![],
                bgpls_announced: vec![],
                labeled_announced: vec![],
                vpn_announced: vec![],
                rtc_announced: vec![],
            }),
        ],
        true,
        false,
        Ipv4UnicastMode::Body,
    )
}

/// Drain the session's outbound stream (OPEN, KEEPALIVE, UPDATEs) until the
/// first NOTIFICATION and return it.
async fn read_until_notification(stream: &mut TcpStream) -> NotificationMessage {
    loop {
        if let Message::Notification(notif) = read_single_bgp_message(stream).await {
            return notif;
        }
    }
}

/// RFC 4486 optional Cease/1 data: AFI (2 octets), SAFI (1 octet),
/// upper bound (4 octets).
fn max_prefix_cease_data(afi: Afi, safi: Safi, bound: u32) -> Vec<u8> {
    let mut data = Vec::with_capacity(7);
    data.extend_from_slice(&(afi as u16).to_be_bytes());
    data.push(safi as u8);
    data.extend_from_slice(&bound.to_be_bytes());
    data
}

fn ipv4_withdraw(prefix: Ipv4Prefix, path_id: u32, add_path: bool) -> UpdateMessage {
    UpdateMessage::build(
        &[],
        &[Ipv4NlriEntry { path_id, prefix }],
        &[],
        true,
        add_path,
        Ipv4UnicastMode::Body,
    )
}

#[tokio::test]
async fn query_state_sorts_both_paths_limit_vectors_by_numeric_family() {
    let mut session = make_test_session(65001, 65002);
    let mut negotiated = negotiated_session(65002, false);
    for (family, peer_limit, effective_limit) in [
        ((Afi::BgpLs, Safi::BgpLs), 11_u16, 21_u32),
        ((Afi::Ipv4, Safi::FlowSpec), 12, 22),
        ((Afi::Ipv6, Safi::Unicast), 13, 23),
        ((Afi::Ipv4, Safi::Unicast), 14, 24),
    ] {
        negotiated.peer_paths_limits.insert(family, peer_limit);
        negotiated
            .effective_add_path_send_limits
            .insert(family, effective_limit);
    }
    session.negotiated = Some(negotiated);

    let (reply, state) = oneshot::channel();
    assert!(matches!(
        session
            .handle_command(PeerCommand::QueryState { reply })
            .await,
        ControlFlow::Continue(())
    ));
    let state = state.await.unwrap();

    assert_eq!(
        state.peer_paths_limits,
        vec![
            ((Afi::Ipv4, Safi::Unicast), 14),
            ((Afi::Ipv4, Safi::FlowSpec), 12),
            ((Afi::Ipv6, Safi::Unicast), 13),
            ((Afi::BgpLs, Safi::BgpLs), 11),
        ]
    );
    assert_eq!(
        state.effective_add_path_send_limits,
        vec![
            ((Afi::Ipv4, Safi::Unicast), 24),
            ((Afi::Ipv4, Safi::FlowSpec), 22),
            ((Afi::Ipv6, Safi::Unicast), 23),
            ((Afi::BgpLs, Safi::BgpLs), 21),
        ]
    );
}

#[tokio::test]
async fn warm_checkpoint_query_uses_current_gr_and_add_path_receive_direction() {
    let mut session = make_test_session(65001, 65002);
    let mut negotiated = negotiated_session(65002, false);
    negotiated.negotiated_families = vec![
        (Afi::Ipv6, Safi::Unicast),
        (Afi::Ipv4, Safi::Unicast),
        (Afi::L2Vpn, Safi::Evpn),
    ];
    negotiated.peer_gr_capable = true;
    negotiated.peer_restart_time = 120;
    negotiated.peer_gr_families = vec![rustbgpd_wire::GracefulRestartFamily {
        afi: Afi::Ipv4,
        safi: Safi::Unicast,
        forwarding_preserved: true,
    }];
    negotiated
        .add_path_families
        .insert((Afi::Ipv4, Safi::Unicast), AddPathMode::Receive);
    negotiated
        .add_path_families
        .insert((Afi::Ipv6, Safi::Unicast), AddPathMode::Send);
    negotiated
        .add_path_families
        .insert((Afi::L2Vpn, Safi::Evpn), AddPathMode::Both);
    install_test_negotiated_session(&mut session, negotiated);

    let (reply, state) = oneshot::channel();
    assert!(matches!(
        session
            .handle_command(PeerCommand::QueryWarmCheckpointState { reply })
            .await,
        ControlFlow::Continue(())
    ));
    let state = state.await.unwrap();

    assert_eq!(state.peer_asn, Some(65002));
    assert_eq!(state.peer_router_id, Some(Ipv4Addr::new(10, 0, 0, 2)));
    assert!(state.peer_gr_capable);
    assert_eq!(state.peer_gr_restart_time, 120);
    assert_eq!(
        state.negotiated_families,
        vec![
            (Afi::Ipv4, Safi::Unicast),
            (Afi::Ipv6, Safi::Unicast),
            (Afi::L2Vpn, Safi::Evpn),
        ]
    );
    assert_eq!(state.peer_gr_families, vec![(Afi::Ipv4, Safi::Unicast)]);
    assert_eq!(
        state.add_path_receive_families,
        vec![(Afi::Ipv4, Safi::Unicast), (Afi::L2Vpn, Safi::Evpn),]
    );
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
async fn tcp_ao_generation_does_not_advance_past_inflight_old_inventory_connect() {
    let mut peer_config = PeerConfig::new(65001, 65002, Ipv4Addr::new(10, 0, 0, 1));
    peer_config.connect_retry_secs = 30;
    let mut config = TransportConfig::new(peer_config, "10.0.0.2:179".parse().unwrap());
    let old = crate::TcpAoConfig {
        key: "old-secret".into(),
        send_id: 1,
        recv_id: 11,
        algorithm: crate::TcpAoAlgorithm::HmacSha256,
        preferred: false,
        deprecated: false,
    };
    config.tcp_ao = Some(crate::TcpAoKeyring(vec![old.clone()]));
    let (_cmd_tx, cmd_rx) = mpsc::channel(8);
    let (rib_tx, _rib_rx) = mpsc::channel(8);
    let mut session = PeerSession::new_at_tcp_ao_generation(
        config,
        BgpMetrics::new(),
        cmd_rx,
        rib_tx,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        false,
        SessionIdentity::default(),
        crate::TcpAoRotationGeneration::STARTUP,
    );
    session.connect_task = Some(tokio::spawn(async {
        std::future::pending::<ConnectResult>().await
    }));
    let mut successor = old.clone();
    successor.key = "successor-secret".into();
    successor.send_id = 2;
    successor.recv_id = 12;
    let result = session.apply_tcp_ao_add_only(crate::TcpAoSessionGeneration {
        generation: crate::TcpAoRotationGeneration::new(2).unwrap(),
        active_keyring: Some(crate::TcpAoKeyring(vec![old, successor])),
        accepted_owners: Vec::new().into(),
    });
    assert!(result.is_err());
    assert_eq!(
        session.tcp_ao_generation,
        crate::TcpAoRotationGeneration::STARTUP
    );
    assert_eq!(session.config.tcp_ao.as_ref().unwrap().0.len(), 1);
    assert!(session.connect_task.is_some());
    session.close_tcp();
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
    assert!(matches!(
        rib_rx.recv().await.unwrap(),
        RibUpdate::SetPeerExportEncoder { .. }
    ));
    assert!(matches!(
        rib_rx.recv().await.unwrap(),
        RibUpdate::SetPeerGracefulRestartContext { .. }
    ));
    rib_rx.recv().await.unwrap()
}
/// All-empty `OutboundRouteUpdate` for the rib-out BMP tap tests.
fn empty_outbound_update() -> OutboundRouteUpdate {
    OutboundRouteUpdate {
        exact_export_snapshot: None,
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
        labeled_withdraw: vec![],
        rtc_withdraw: vec![],
        request_refresh_all_negotiated: false,
        shared_group_encode: None,
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
    update.exact_export_snapshot = Some(session.publish_export_profile());
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
    update.exact_export_snapshot = Some(session.publish_export_profile());
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
    update.exact_export_snapshot = Some(session.publish_export_profile());
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
    update.exact_export_snapshot = Some(session.publish_export_profile());
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
    update.exact_export_snapshot = Some(session.publish_export_profile());
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
        update.exact_export_snapshot = Some(session.publish_export_profile());
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
        update.exact_export_snapshot = Some(session.publish_export_profile());
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
        update.exact_export_snapshot = Some(session.publish_export_profile());
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
    update.exact_export_snapshot = Some(session.publish_export_profile());
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
        keys: Vec::new(),
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

fn tcp_ao_snapshot(good: u64, bad: u64) -> crate::TcpAoInfoSnapshot {
    crate::TcpAoInfoSnapshot {
        has_current_key: true,
        has_rnext_key: true,
        ao_required: true,
        accept_icmps: false,
        current_key: 7,
        rnext_key: 9,
        pkt_good: good,
        pkt_bad: bad,
        pkt_key_not_found: 0,
        pkt_ao_required: 0,
        pkt_dropped_icmp: 0,
        keys: vec![crate::TcpAoKeyState {
            peer: "10.0.0.2".parse().unwrap(),
            prefix_len: 32,
            send_id: 7,
            recv_id: 9,
            algorithm: crate::TcpAoAlgorithm::HmacSha256,
            is_current: true,
            is_rnext: true,
            preferred: false,
            deprecated: false,
            vrf_ifindex: None,
            pkt_good: good,
            pkt_bad: bad,
        }],
    }
}

#[cfg(target_os = "linux")]
#[test]
fn active_open_second_key_install_failure_abandons_socket_before_connect() {
    use socket2::Socket;
    use std::cell::{Cell, RefCell};
    use std::io::Read as _;
    use std::time::Duration;

    let mut peer_config = PeerConfig::new(65001, 65002, Ipv4Addr::new(10, 0, 0, 1));
    peer_config.families = vec![(Afi::Ipv4, Safi::Unicast)];
    let mut config = TransportConfig::new(peer_config, "192.0.2.2:179".parse().unwrap());
    config.tcp_ao = Some(crate::TcpAoKeyring(vec![
        crate::TcpAoConfig {
            key: "selected".into(),
            send_id: 1,
            recv_id: 11,
            algorithm: crate::TcpAoAlgorithm::HmacSha256,
            preferred: true,
            deprecated: false,
        },
        crate::TcpAoConfig {
            key: "standby".into(),
            send_id: 2,
            recv_id: 12,
            algorithm: crate::TcpAoAlgorithm::HmacSha256,
            preferred: false,
            deprecated: false,
        },
    ]));

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let client = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (mut peer, _) = listener.accept().unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
    let socket = Socket::from(client);
    let installed = RefCell::new(Vec::new());
    let connect_attempts = Cell::new(0usize);
    let result = super::io::prepare_active_socket_for_test(
        socket,
        &config,
        "192.0.2.2",
        |_socket, _peer, _prefix_len, key, role| {
            installed.borrow_mut().push((key.send_id, role));
            if key.send_id == 2 {
                Err(std::io::Error::other("injected second-key failure"))
            } else {
                Ok(())
            }
        },
        |_socket, _addr| {
            connect_attempts.set(connect_attempts.get() + 1);
            Ok(())
        },
    );
    let Err(error) = result else {
        panic!("a partial TCP-AO keyring install must abandon the active-open socket");
    };

    assert_eq!(
        installed.into_inner(),
        vec![
            (1, crate::socket_opts::TcpAoSocketRole::ActiveOpen),
            (2, crate::socket_opts::TcpAoSocketRole::Listener),
        ]
    );
    assert_eq!(connect_attempts.get(), 0, "connect must not be attempted");
    assert!(error.to_string().contains("send_id=2"), "{error}");
    assert!(error.to_string().contains("recv_id=12"), "{error}");

    // The peer observes EOF on this exact connection, proving the consumed
    // partially programmed socket was closed rather than retained for a
    // plaintext retry. The timeout keeps a retained descriptor from hanging
    // the suite indefinitely.
    let mut byte = [0u8; 1];
    assert_eq!(peer.read(&mut byte).unwrap(), 0);
}

#[expect(
    clippy::too_many_arguments,
    clippy::fn_params_excessive_bools,
    reason = "test helper keeps multi-key TCP-AO state fixtures readable"
)]
fn tcp_ao_key_state(
    peer: &str,
    prefix_len: u8,
    send_id: u8,
    recv_id: u8,
    is_current: bool,
    is_rnext: bool,
    preferred: bool,
    deprecated: bool,
    pkt_good: u64,
) -> crate::TcpAoKeyState {
    crate::TcpAoKeyState {
        peer: peer.parse().unwrap(),
        prefix_len,
        send_id,
        recv_id,
        algorithm: crate::TcpAoAlgorithm::HmacSha256,
        is_current,
        is_rnext,
        preferred,
        deprecated,
        vrf_ifindex: None,
        pkt_good,
        pkt_bad: 0,
    }
}

async fn tcp_ao_query_test_session() -> PeerSession {
    let mut session = make_test_session(65001, 65002);
    session.config.tcp_ao = Some(
        crate::TcpAoConfig {
            key: "test-secret".into(),
            send_id: 7,
            recv_id: 9,
            algorithm: crate::TcpAoAlgorithm::HmacSha256,
            preferred: true,
            deprecated: false,
        }
        .into(),
    );
    // The test mutates config after construction; production constructors
    // seed this durable bit from config before the session starts.
    session.tcp_ao_protected = true;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let connect = TcpStream::connect(listener.local_addr().unwrap());
    let accept = listener.accept();
    let (client, accepted) = tokio::join!(connect, accept);
    let (_server, _) = accepted.unwrap();
    session.test_install_stream(client.unwrap());
    session
}

async fn accepted_query_test_session(tcp_ao_info: Option<crate::TcpAoInfoSnapshot>) -> PeerSession {
    let mut peer_config = PeerConfig::new(65001, 65002, Ipv4Addr::new(10, 0, 0, 1));
    peer_config.families = vec![(Afi::Ipv4, Safi::Unicast)];
    let config = TransportConfig::new(peer_config, "127.0.0.1:179".parse().unwrap());
    assert!(config.tcp_ao.is_none());
    accepted_query_test_session_with_config(config, tcp_ao_info).await
}

async fn accepted_query_test_session_with_config(
    config: TransportConfig,
    tcp_ao_info: Option<crate::TcpAoInfoSnapshot>,
) -> PeerSession {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let connect = TcpStream::connect(listener.local_addr().unwrap());
    let accept = listener.accept();
    let (client, accepted) = tokio::join!(connect, accept);
    let (_server, _) = accepted.unwrap();
    let (_cmd_tx, cmd_rx) = mpsc::channel(8);
    let (rib_tx, _rib_rx) = mpsc::channel(64);
    PeerSession::new_inbound_with_identity_and_lifecycle(
        config,
        BgpMetrics::new(),
        cmd_rx,
        rib_tx,
        None,
        None,
        client.unwrap(),
        None,
        None,
        None,
        None,
        None,
        false,
        crate::SessionIdentity::default(),
        tcp_ao_info,
        crate::TcpAoRotationGeneration::STARTUP,
    )
}

#[tokio::test]
async fn tcp_ao_query_refreshes_degraded_cumulative_counters() {
    let mut session = tcp_ao_query_test_session().await;
    session.refresh_tcp_ao_info_with(|_| Ok(tcp_ao_snapshot(43, 1)));
    let snapshot = session.tcp_ao_info.unwrap();
    assert_eq!(snapshot.pkt_good, 43);
    assert_eq!(snapshot.pkt_bad, 1);
}

#[tokio::test]
async fn tcp_ao_query_clears_stale_snapshot_and_recovers() {
    let mut session = tcp_ao_query_test_session().await;
    session.tcp_ao_info = Some(tcp_ao_snapshot(12, 0));
    session.refresh_tcp_ao_info_with(|_| {
        Err(std::io::Error::new(
            std::io::ErrorKind::WouldBlock,
            "TCP-AO INFO and key inventory remained inconsistent",
        ))
    });
    assert!(session.tcp_ao_info.is_none());

    session.refresh_tcp_ao_info_with(|_| Ok(tcp_ao_snapshot(44, 0)));
    assert_eq!(session.tcp_ao_info.as_ref().unwrap().pkt_good, 44);
    assert!(session.tcp_ao_info.as_ref().unwrap().keys[0].preferred);
}

#[tokio::test]
async fn accepted_tcp_ao_snapshot_seeds_durable_refresh_across_failure_and_recovery() {
    let mut initial = tcp_ao_snapshot(20, 0);
    initial.keys[0].preferred = true;
    let mut session = accepted_query_test_session(Some(initial)).await;
    assert!(session.config.tcp_ao.is_none());
    assert!(session.tcp_ao_protected);

    session.refresh_tcp_ao_info_with(|_| Ok(tcp_ao_snapshot(43, 0)));
    assert_eq!(session.tcp_ao_info.as_ref().unwrap().pkt_good, 43);
    assert!(session.tcp_ao_info.as_ref().unwrap().keys[0].preferred);
    session.refresh_tcp_ao_info_with(|_| Err(std::io::Error::other("inspection failed")));
    assert!(session.tcp_ao_info.is_none());
    assert!(
        session.tcp_ao_protected,
        "inspection failure must not erase protection identity"
    );
    session.refresh_tcp_ao_info_with(|_| Ok(tcp_ao_snapshot(44, 0)));
    assert_eq!(session.tcp_ao_info.as_ref().unwrap().pkt_good, 44);
    assert!(session.tcp_ao_info.as_ref().unwrap().keys[0].preferred);
}

#[tokio::test]
async fn accepted_tcp_ao_refresh_restores_overlapping_owner_selectors_after_host_normalization() {
    let connected: IpAddr = "127.0.0.1".parse().unwrap();
    let mut initial = tcp_ao_snapshot(20, 0);
    initial.current_key = 8;
    initial.rnext_key = 12;
    initial.keys = vec![
        tcp_ao_key_state("127.0.0.0", 24, 7, 9, false, false, false, false, 20),
        tcp_ao_key_state("127.0.0.1", 32, 8, 10, true, false, false, true, 20),
        tcp_ao_key_state("127.0.0.1", 32, 11, 12, false, true, true, false, 20),
    ];
    let mut peer_config = PeerConfig::new(65001, 65002, Ipv4Addr::new(10, 0, 0, 1));
    peer_config.families = vec![(Afi::Ipv4, Safi::Unicast)];
    let mut config = TransportConfig::new(peer_config, "127.0.0.1:179".parse().unwrap());
    config.tcp_ao = Some(crate::TcpAoKeyring(vec![
        crate::TcpAoConfig {
            key: "static-current".into(),
            send_id: 8,
            recv_id: 10,
            algorithm: crate::TcpAoAlgorithm::HmacSha256,
            preferred: false,
            deprecated: true,
        },
        crate::TcpAoConfig {
            key: "static-selected".into(),
            send_id: 11,
            recv_id: 12,
            algorithm: crate::TcpAoAlgorithm::HmacSha256,
            preferred: true,
            deprecated: false,
        },
    ]));
    let mut session = accepted_query_test_session_with_config(config, Some(initial)).await;

    let mut refreshed = tcp_ao_snapshot(43, 0);
    refreshed.current_key = 8;
    refreshed.rnext_key = 12;
    refreshed.keys = vec![
        tcp_ao_key_state("127.0.0.1", 32, 7, 9, false, false, false, false, 43),
        tcp_ao_key_state("127.0.0.1", 32, 8, 10, true, false, false, false, 43),
        tcp_ao_key_state("127.0.0.1", 32, 11, 12, false, true, false, false, 43),
    ];
    session.refresh_tcp_ao_info_with(|_| Ok(refreshed));

    let keys = &session.tcp_ao_info.as_ref().unwrap().keys;
    let covering = keys.iter().find(|key| key.send_id == 7).unwrap();
    assert_eq!(covering.peer, "127.0.0.0".parse::<IpAddr>().unwrap());
    assert_eq!(covering.prefix_len, 24);
    let deprecated_current = keys.iter().find(|key| key.send_id == 8).unwrap();
    assert_eq!(deprecated_current.peer, connected);
    assert_eq!(deprecated_current.prefix_len, 32);
    assert!(deprecated_current.is_current);
    assert!(deprecated_current.deprecated);
    let selected_rnext = keys.iter().find(|key| key.send_id == 11).unwrap();
    assert_eq!(selected_rnext.peer, connected);
    assert_eq!(selected_rnext.prefix_len, 32);
    assert!(selected_rnext.is_rnext);
    assert!(selected_rnext.preferred);
}

#[tokio::test]
async fn plaintext_accepted_session_does_not_inherit_tcp_ao_protection() {
    let mut session = accepted_query_test_session(None).await;
    assert!(!session.tcp_ao_protected);
    session.refresh_tcp_ao_info_with(|_| -> std::io::Result<crate::TcpAoInfoSnapshot> {
        panic!("plaintext accepted session must not inspect TCP_AO_INFO")
    });
    assert!(session.tcp_ao_info.is_none());
}

#[test]
fn non_tcp_ao_query_does_not_invoke_inspector() {
    let mut session = make_test_session(65001, 65002);
    session.tcp_ao_info = Some(tcp_ao_snapshot(12, 0));
    session.refresh_tcp_ao_info_with(|_| -> std::io::Result<crate::TcpAoInfoSnapshot> {
        panic!("non-AO session must not inspect TCP_AO_INFO")
    });
    assert!(session.tcp_ao_info.is_none());
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
        for (prefix, route_next_hop) in [
            (
                Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, 0), 24)),
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            ),
            (
                Prefix::V6(Ipv6Prefix::new("2001:db8::".parse().unwrap(), 64)),
                IpAddr::V6("2001:db8::2".parse().unwrap()),
            ),
        ] {
            let mut session = make_test_session(65001, 65002);
            session.config.peer.local_role = Some(role);
            let mut attributes = vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath {
                    segments: vec![AsPathSegment::AsSequence(vec![65002])],
                }),
                PathAttribute::OnlyToCustomer(65002),
            ];
            if let IpAddr::V4(next_hop) = route_next_hop {
                attributes.push(PathAttribute::NextHop(next_hop));
            }
            let mut route = replace_route_attrs(&make_route(100), attributes);
            route.prefix = prefix;
            route.next_hop = route_next_hop;
            assert!(
                session.otc_egress_blocks_unicast(&route),
                "role {role:?} must not propagate an OTC-tagged {prefix} route"
            );
        }
    }
}
/// Mutant: selecting Add-Path accounting from `path_id != 0`, or treating
/// absent/Send negotiation as Receive, makes at least one storage tuple differ.
#[test]
fn negotiated_receive_direction_selects_unicast_accounting_storage() {
    for (mode, expected_storage) in [
        (None, (1, 0, 0, 0)),
        (Some(AddPathMode::Send), (1, 0, 0, 0)),
        (Some(AddPathMode::Receive), (0, 2, 1, 2)),
        (Some(AddPathMode::Both), (0, 2, 1, 2)),
    ] {
        let mut session = make_test_session(65001, 65002);
        let mut negotiated = negotiated_session(65002, false);
        if let Some(mode) = mode {
            negotiated
                .add_path_families
                .insert((Afi::Ipv4, Safi::Unicast), mode);
        }
        install_test_negotiated_session(&mut session, negotiated);
        let prefix = Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24));
        assert!(session.remember_known_path(prefix, 0));
        let second_inserted = session.remember_known_path(prefix, 7);
        assert_eq!(second_inserted, expected_storage.1 == 2, "mode {mode:?}");
        assert_eq!(
            session.known_unicast_storage_counts(),
            expected_storage,
            "mode {mode:?}"
        );
        assert_eq!(session.known_prefix_count(), 1, "mode {mode:?}");
    }
}

/// Mutant: removing tuple deduplication increments the Add-Path refcount for
/// the repeated identity and makes the refcount total three instead of two.
#[test]
fn known_prefix_count_deduplicates_multiple_add_paths() {
    let mut session = make_test_session(65001, 65002);
    let mut negotiated = negotiated_session(65002, false);
    negotiated
        .add_path_families
        .insert((Afi::Ipv4, Safi::Unicast), AddPathMode::Receive);
    install_test_negotiated_session(&mut session, negotiated);
    let prefix = Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24));
    assert!(session.remember_known_path(prefix, 0));
    assert!(session.remember_known_path(prefix, 2));
    assert!(
        !session.remember_known_path(prefix, 2),
        "duplicate path announcements must not bump the refcount"
    );
    assert_eq!(session.known_unicast_storage_counts(), (0, 2, 1, 2));
    assert_eq!(session.known_prefix_count(), 1);
}

/// Mutant: deleting the per-prefix Add-Path refcount, or removing the prefix
/// on the first path withdrawal, makes the intermediate count zero.
#[test]
fn known_prefix_refcount_tracks_add_path_withdrawals() {
    let mut session = make_test_session(65001, 65002);
    let mut negotiated = negotiated_session(65002, false);
    negotiated
        .add_path_families
        .insert((Afi::Ipv4, Safi::Unicast), AddPathMode::Both);
    install_test_negotiated_session(&mut session, negotiated);
    let prefix = Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24));
    session.remember_known_path(prefix, 0);
    session.remember_known_path(prefix, 2);
    assert_eq!(session.known_prefix_count(), 1);
    assert!(session.forget_known_path(prefix, 0));
    assert_eq!(
        session.known_prefix_count(),
        1,
        "withdrawing one Add-Path path keeps the prefix counted"
    );
    assert!(
        !session.forget_known_path(prefix, 0),
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

/// Mutant: counting only the plain set or only the Add-Path refcount map makes
/// this mixed-family total smaller than the two unique prefixes.
#[test]
fn mixed_family_modes_share_one_unique_prefix_count() {
    let mut session = make_test_session(65001, 65002);
    let mut negotiated = negotiated_session(65002, false);
    negotiated.negotiated_families = vec![(Afi::Ipv4, Safi::Unicast), (Afi::Ipv6, Safi::Unicast)];
    negotiated
        .add_path_families
        .insert((Afi::Ipv4, Safi::Unicast), AddPathMode::Both);
    negotiated
        .add_path_families
        .insert((Afi::Ipv6, Safi::Unicast), AddPathMode::Send);
    install_test_negotiated_session(&mut session, negotiated);

    let v4 = Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24));
    let v6 = Prefix::V6(Ipv6Prefix::new(Ipv6Addr::LOCALHOST, 128));
    assert!(session.remember_known_path(v4, 0));
    assert!(session.remember_known_path(v4, 7));
    assert!(session.remember_known_path(v6, 99));
    assert!(!session.remember_known_path(v6, 100));

    assert_eq!(session.known_unicast_storage_counts(), (1, 2, 1, 2));
    assert_eq!(session.known_prefix_count(), 2);
}

#[tokio::test]
async fn enhanced_refresh_markers_follow_gr_end_of_rib_gate_per_family() {
    let families = vec![(Afi::Ipv4, Safi::Unicast), (Afi::Ipv6, Safi::Unicast)];

    let (mut plain, mut plain_rib) = make_test_session_with_rib(65001, 65002);
    install_enhanced_refresh_session(&mut plain, families.clone(), false);
    buffer_route_refresh(
        &mut plain,
        Afi::Ipv4,
        Safi::Unicast,
        RouteRefreshSubtype::BoRR,
    );
    plain.process_read_buffer().await;
    assert!(matches!(
        plain_rib.try_recv(),
        Ok(RibUpdate::BeginRouteRefresh {
            afi: Afi::Ipv4,
            safi: Safi::Unicast,
            ..
        })
    ));
    assert!(
        plain.refresh_accounting_has_window((Afi::Ipv4, Safi::Unicast)),
        "a non-GR peer may begin ERR before any End-of-RIB"
    );

    let (mut gr, mut gr_rib) = make_test_session_with_rib(65001, 65002);
    install_enhanced_refresh_session(&mut gr, families, true);
    buffer_route_refresh(&mut gr, Afi::Ipv4, Safi::Unicast, RouteRefreshSubtype::BoRR);
    gr.process_read_buffer().await;
    assert!(gr_rib.try_recv().is_err());
    assert_eq!(gr.refresh_accounting_window_count(), 0);

    // An empty UPDATE completes only IPv4 unicast GR replay.
    gr.process_update(UpdateMessage::build(
        &[],
        &[],
        &[],
        true,
        false,
        Ipv4UnicastMode::Body,
    ))
    .await;
    assert!(matches!(
        gr_rib.try_recv(),
        Ok(RibUpdate::EndOfRib {
            afi: Afi::Ipv4,
            safi: Safi::Unicast,
            ..
        })
    ));
    buffer_route_refresh(&mut gr, Afi::Ipv4, Safi::Unicast, RouteRefreshSubtype::BoRR);
    buffer_route_refresh(&mut gr, Afi::Ipv6, Safi::Unicast, RouteRefreshSubtype::BoRR);
    gr.process_read_buffer().await;
    assert!(matches!(
        gr_rib.try_recv(),
        Ok(RibUpdate::BeginRouteRefresh {
            afi: Afi::Ipv4,
            safi: Safi::Unicast,
            ..
        })
    ));
    assert!(gr_rib.try_recv().is_err(), "IPv6 BoRR must remain gated");
    assert!(gr.refresh_accounting_has_window((Afi::Ipv4, Safi::Unicast)));
    assert!(!gr.refresh_accounting_has_window((Afi::Ipv6, Safi::Unicast)));
}

#[tokio::test]
async fn enhanced_refresh_sweeps_every_counted_family_with_typed_identity() {
    let mut session = make_test_session(65001, 65002);
    let unicast = Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, 0), 24));
    session.remember_known_path(unicast, 7);
    let flowspec = rustbgpd_rib::FlowSpecKey {
        afi: Afi::Ipv4,
        rule: FlowSpecRule {
            components: vec![FlowSpecComponent::DestinationPrefix(FlowSpecPrefix::V4(
                Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 0), 24),
            ))],
        },
    };
    session.known_flowspec.insert(flowspec);
    let evpn = rustbgpd_wire::EvpnRouteKey::Imet {
        rd: RouteDistinguisher([0, 0, 0xfd, 0xe8, 0, 0, 0, 1]),
        ethernet_tag: rustbgpd_wire::EthernetTagId(100),
        originator_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
    };
    session.known_evpn.insert(evpn);
    session.known_bgpls.insert(make_bgpls_route(1).key());
    session.known_vpn.insert(make_vpn_rib_route(100).key());
    session
        .known_labeled
        .insert(make_labeled_rib_route(200).key());
    session.known_rtc.insert(make_rtc_rib_route(300).key());
    let families = [
        (Afi::Ipv4, Safi::Unicast),
        (Afi::Ipv4, Safi::FlowSpec),
        (Afi::L2Vpn, Safi::Evpn),
        (Afi::BgpLs, Safi::BgpLs),
        (Afi::Ipv4, Safi::MplsVpn),
        (Afi::Ipv4, Safi::LabeledUnicast),
        (Afi::Ipv4, Safi::RtConstrain),
    ];
    assert_eq!(session.known_prefix_count(), families.len());
    for family in families {
        session.begin_refresh_accounting(family.0, family.1);
        assert_eq!(session.refresh_accounting_stale_count(family), Some(1));
        assert_eq!(
            session.known_prefix_count(),
            families.len(),
            "BoRR snapshots must not change live max-prefix accounting"
        );
    }
    for family in families {
        session.end_refresh_accounting(family.0, family.1);
    }
    assert_eq!(session.known_prefix_count(), 0);
    assert_eq!(session.refresh_accounting_window_count(), 0);
}

#[tokio::test]
async fn duplicate_borr_resnapshots_routes_replayed_in_the_prior_window() {
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    install_enhanced_refresh_session(&mut session, vec![(Afi::Ipv4, Safi::Unicast)], false);
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, 0), 24);
    session.remember_known_path(Prefix::V4(prefix), 0);

    buffer_route_refresh(
        &mut session,
        Afi::Ipv4,
        Safi::Unicast,
        RouteRefreshSubtype::BoRR,
    );
    session.process_read_buffer().await;
    assert!(matches!(
        rib_rx.try_recv(),
        Ok(RibUpdate::BeginRouteRefresh { .. })
    ));
    session
        .process_update(ipv4_announce(prefix, 0, false))
        .await;
    assert!(matches!(
        rib_rx.try_recv(),
        Ok(RibUpdate::RoutesReceived { .. })
    ));
    assert_eq!(
        session.refresh_accounting_stale_count((Afi::Ipv4, Safi::Unicast)),
        Some(0)
    );

    buffer_route_refresh(
        &mut session,
        Afi::Ipv4,
        Safi::Unicast,
        RouteRefreshSubtype::BoRR,
    );
    session.process_read_buffer().await;
    assert!(matches!(
        rib_rx.try_recv(),
        Ok(RibUpdate::BeginRouteRefresh { .. })
    ));
    assert_eq!(
        session.refresh_accounting_stale_count((Afi::Ipv4, Safi::Unicast)),
        Some(1),
        "duplicate BoRR must snapshot the route that the first replay made current"
    );

    buffer_route_refresh(
        &mut session,
        Afi::Ipv4,
        Safi::Unicast,
        RouteRefreshSubtype::EoRR,
    );
    session.process_read_buffer().await;
    assert!(matches!(
        rib_rx.try_recv(),
        Ok(RibUpdate::EndRouteRefresh { .. })
    ));
    assert_eq!(session.known_prefix_count(), 0);
}

/// Mutant: snapshotting plain ERR state as `(prefix, path_id)` identities fails
/// to retire the omitted compact prefix at `EoRR`, leaving the count at two.
#[tokio::test]
async fn eorr_reconciles_omitted_prefix_before_later_max_prefix_check() {
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    install_enhanced_refresh_session(&mut session, vec![(Afi::Ipv4, Safi::Unicast)], false);
    session.config.max_prefixes = Some(2);
    let replayed = Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, 0), 24);
    let omitted = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 0), 24);
    session.remember_known_path(Prefix::V4(replayed), 0);
    session.remember_known_path(Prefix::V4(omitted), 0);

    buffer_route_refresh(
        &mut session,
        Afi::Ipv4,
        Safi::Unicast,
        RouteRefreshSubtype::BoRR,
    );
    session.process_read_buffer().await;
    assert!(matches!(
        rib_rx.try_recv(),
        Ok(RibUpdate::BeginRouteRefresh { .. })
    ));
    session
        .process_update(ipv4_announce(replayed, 0, false))
        .await;
    assert!(matches!(
        rib_rx.try_recv(),
        Ok(RibUpdate::RoutesReceived { .. })
    ));
    buffer_route_refresh(
        &mut session,
        Afi::Ipv4,
        Safi::Unicast,
        RouteRefreshSubtype::EoRR,
    );
    session.process_read_buffer().await;
    assert!(matches!(
        rib_rx.try_recv(),
        Ok(RibUpdate::EndRouteRefresh { .. })
    ));
    assert_eq!(session.known_prefix_count(), 1);

    let later = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24);
    session.process_update(ipv4_announce(later, 0, false)).await;
    assert!(matches!(
        rib_rx.try_recv(),
        Ok(RibUpdate::RoutesReceived { .. })
    ));
    assert_eq!(session.known_prefix_count(), 2);
}

/// Mutant: collapsing Add-Path ERR state to a plain prefix makes replay of
/// valid path ID zero preserve the omitted path ID two as well.
#[tokio::test]
async fn add_path_partial_replay_sweeps_only_omitted_identity_and_keeps_prefix_count() {
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    let mut negotiated = negotiated_session(65002, false);
    negotiated.peer_route_refresh = true;
    negotiated.peer_enhanced_route_refresh = true;
    negotiated
        .add_path_families
        .insert((Afi::Ipv4, Safi::Unicast), AddPathMode::Both);
    install_test_negotiated_session(&mut session, negotiated);
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, 0), 24);
    session.remember_known_path(Prefix::V4(prefix), 0);
    session.remember_known_path(Prefix::V4(prefix), 2);
    session.begin_refresh_accounting(Afi::Ipv4, Safi::Unicast);
    session.process_update(ipv4_announce(prefix, 0, true)).await;
    assert!(matches!(
        rib_rx.try_recv(),
        Ok(RibUpdate::RoutesReceived { .. })
    ));
    buffer_route_refresh(
        &mut session,
        Afi::Ipv4,
        Safi::Unicast,
        RouteRefreshSubtype::EoRR,
    );
    session.process_read_buffer().await;
    assert!(matches!(
        rib_rx.try_recv(),
        Ok(RibUpdate::EndRouteRefresh { .. })
    ));
    assert!(session.known_paths.contains(&(Prefix::V4(prefix), 0)));
    assert!(!session.known_paths.contains(&(Prefix::V4(prefix), 2)));
    assert_eq!(session.known_prefix_count(), 1);
}

#[tokio::test]
async fn import_policy_denial_retires_refresh_stale_identity() {
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    install_test_negotiated_session(&mut session, negotiated_session(65002, false));
    session.install_import_policy(Some(PolicyChain::new(vec![Policy {
        entries: vec![],
        default_action: PolicyAction::Deny,
    }])));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, 0), 24);
    session.remember_known_path(Prefix::V4(prefix), 0);
    session.begin_refresh_accounting(Afi::Ipv4, Safi::Unicast);
    session
        .process_update(ipv4_announce(prefix, 0, false))
        .await;
    let RibUpdate::RoutesReceived {
        announced,
        withdrawn,
        ..
    } = rib_rx
        .try_recv()
        .expect("denied replacement must emit a withdrawal")
    else {
        panic!("expected RoutesReceived");
    };
    assert!(announced.is_empty());
    assert_eq!(withdrawn, vec![(Prefix::V4(prefix), 0)]);
    assert_eq!(
        session.refresh_accounting_stale_count((Afi::Ipv4, Safi::Unicast)),
        Some(0)
    );
    session.end_refresh_accounting(Afi::Ipv4, Safi::Unicast);
    assert_eq!(session.known_prefix_count(), 0);
}

#[tokio::test]
async fn ordinary_withdrawal_retires_refresh_stale_identity() {
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    install_test_negotiated_session(&mut session, negotiated_session(65002, false));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, 0), 24);
    session.remember_known_path(Prefix::V4(prefix), 0);
    session.begin_refresh_accounting(Afi::Ipv4, Safi::Unicast);

    session
        .process_update(ipv4_withdraw(prefix, 0, false))
        .await;
    assert!(matches!(
        rib_rx.try_recv(),
        Ok(RibUpdate::RoutesReceived { .. })
    ));
    assert_eq!(
        session.refresh_accounting_stale_count((Afi::Ipv4, Safi::Unicast)),
        Some(0)
    );
    session.end_refresh_accounting(Afi::Ipv4, Safi::Unicast);
    assert_eq!(session.known_prefix_count(), 0);
}

/// Mutant: sweeping before a timed-out RIB boundary is accepted removes the
/// compact plain prefix despite the closed channel and makes the count zero.
#[tokio::test(start_paused = true)]
async fn closed_rib_timeout_preserves_refresh_window_and_live_count() {
    let mut session = make_test_session(65001, 65002);
    let prefix = Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, 0), 24));
    session.remember_known_path(prefix, 0);
    session.begin_refresh_accounting(Afi::Ipv4, Safi::Unicast);

    tokio::time::advance(rustbgpd_rib::ERR_REFRESH_TIMEOUT).await;
    assert_eq!(session.expire_refresh_accounting_windows().await, Err(()));
    assert!(session.refresh_accounting_has_window((Afi::Ipv4, Safi::Unicast)));
    assert_eq!(session.known_prefix_count(), 1);
    assert!(
        session.refresh_accounting_timer.is_none(),
        "a closed RIB must not spin a past-due timer"
    );
}

/// Mutant: using one untyped unicast ERR snapshot either leaves the plain IPv4
/// prefix or mishandles Add-Path ID zero when the staggered windows expire.
#[tokio::test(start_paused = true)]
async fn staggered_refresh_timeouts_sweep_only_due_family_and_rearm() {
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    let mut negotiated = negotiated_session(65002, false);
    negotiated.negotiated_families = vec![(Afi::Ipv4, Safi::Unicast), (Afi::Ipv6, Safi::Unicast)];
    negotiated
        .add_path_families
        .insert((Afi::Ipv6, Safi::Unicast), AddPathMode::Receive);
    install_test_negotiated_session(&mut session, negotiated);
    let v4 = Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, 0), 24));
    let v6 = Prefix::V6(Ipv6Prefix::new(Ipv6Addr::LOCALHOST, 128));
    session.remember_known_path(v4, 0);
    session.remember_known_path(v6, 0);
    session.begin_refresh_accounting(Afi::Ipv4, Safi::Unicast);
    tokio::time::advance(Duration::from_secs(1)).await;
    session.begin_refresh_accounting(Afi::Ipv6, Safi::Unicast);

    tokio::time::advance(
        rustbgpd_rib::ERR_REFRESH_TIMEOUT
            .checked_sub(Duration::from_secs(1))
            .unwrap(),
    )
    .await;
    session.expire_refresh_accounting_windows().await.unwrap();
    assert!(matches!(
        rib_rx.try_recv(),
        Ok(RibUpdate::RouteRefreshTimeout {
            afi: Afi::Ipv4,
            safi: Safi::Unicast,
            ..
        })
    ));
    assert!(!session.known_plain_prefixes.contains(&v4));
    assert!(session.known_paths.contains(&(v6, 0)));
    assert!(!session.refresh_accounting_has_window((Afi::Ipv4, Safi::Unicast)));
    assert!(session.refresh_accounting_has_window((Afi::Ipv6, Safi::Unicast)));
    assert!(session.refresh_accounting_timer.is_some());

    tokio::time::advance(Duration::from_secs(1)).await;
    session.expire_refresh_accounting_windows().await.unwrap();
    assert!(matches!(
        rib_rx.try_recv(),
        Ok(RibUpdate::RouteRefreshTimeout {
            afi: Afi::Ipv6,
            safi: Safi::Unicast,
            ..
        })
    ));
    assert_eq!(session.known_prefix_count(), 0);
    assert_eq!(session.refresh_accounting_window_count(), 0);
}

#[tokio::test(start_paused = true)]
async fn quiet_run_loop_expires_refresh_accounting() {
    let (mut session, cmd_tx, mut rib_rx) = make_test_session_with_channels(65001, 65002, 8);
    let prefix = Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, 0), 24));
    session.remember_known_path(prefix, 0);
    session.begin_refresh_accounting(Afi::Ipv4, Safi::Unicast);
    let task = tokio::spawn(async move {
        session.run().await.unwrap();
    });

    tokio::time::advance(rustbgpd_rib::ERR_REFRESH_TIMEOUT).await;
    assert!(matches!(
        rib_rx.recv().await,
        Some(RibUpdate::RouteRefreshTimeout {
            afi: Afi::Ipv4,
            safi: Safi::Unicast,
            ..
        })
    ));
    let (reply, state) = oneshot::channel();
    cmd_tx
        .send(PeerCommand::QueryState { reply })
        .await
        .unwrap();
    assert_eq!(state.await.unwrap().prefix_count, 0);
    cmd_tx.send(PeerCommand::Shutdown).await.unwrap();
    task.await.unwrap();
}

/// Mutant: applying the buffered UPDATE before the ordered timeout boundary
/// leaves the stale compact prefix present after the task completes.
#[tokio::test(start_paused = true)]
async fn refresh_timeout_precedes_next_buffered_update_after_rib_backpressure() {
    let (mut session, _cmd_tx, mut rib_rx) = make_test_session_with_channels(65001, 65002, 1);
    install_test_negotiated_session(&mut session, negotiated_session(65002, false));
    let stale = Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, 0), 24);
    let first = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 0), 24);
    let second = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24);
    session.remember_known_path(Prefix::V4(stale), 0);
    session.begin_refresh_accounting(Afi::Ipv4, Safi::Unicast);
    session
        .rib_tx
        .try_send(RibUpdate::BeginRouteRefresh {
            peer: session.peer_ip,
            session_id: session.session_identity.id,
            afi: Afi::Ipv6,
            safi: Safi::Unicast,
        })
        .unwrap();
    for update in [
        ipv4_announce(first, 0, false),
        ipv4_announce(second, 0, false),
    ] {
        let encoded = rustbgpd_wire::encode_message(&Message::Update(update)).unwrap();
        session.read_buf.buf.extend_from_slice(&encoded);
    }
    let task = tokio::spawn(async move {
        session.process_read_buffer().await;
        session
    });
    tokio::task::yield_now().await;
    assert!(
        !task.is_finished(),
        "the first UPDATE must park on the full RIB channel"
    );

    tokio::time::advance(rustbgpd_rib::ERR_REFRESH_TIMEOUT).await;
    assert!(matches!(
        rib_rx.recv().await,
        Some(RibUpdate::BeginRouteRefresh { .. })
    ));
    assert!(matches!(
        rib_rx.recv().await,
        Some(RibUpdate::RoutesReceived { ref announced, .. })
            if announced.iter().any(|route| route.prefix == Prefix::V4(first))
    ));
    assert!(matches!(
        rib_rx.recv().await,
        Some(RibUpdate::RouteRefreshTimeout {
            afi: Afi::Ipv4,
            safi: Safi::Unicast,
            ..
        })
    ));
    assert!(matches!(
        rib_rx.recv().await,
        Some(RibUpdate::RoutesReceived { ref announced, .. })
            if announced.iter().any(|route| route.prefix == Prefix::V4(second))
    ));
    let session = task.await.unwrap();
    assert!(!session.known_plain_prefixes.contains(&Prefix::V4(stale)));
    assert_eq!(session.known_prefix_count(), 2);
}

#[tokio::test]
async fn full_rib_channel_delays_marker_accounting_mutation_until_acceptance() {
    let (mut session, _cmd_tx, mut rib_rx) = make_test_session_with_channels(65001, 65002, 1);
    install_enhanced_refresh_session(&mut session, vec![(Afi::Ipv4, Safi::Unicast)], false);
    let prefix = Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, 0), 24));
    session.remember_known_path(prefix, 0);
    session
        .rib_tx
        .try_send(RibUpdate::BeginRouteRefresh {
            peer: session.peer_ip,
            session_id: session.session_identity.id,
            afi: Afi::Ipv6,
            safi: Safi::Unicast,
        })
        .unwrap();
    buffer_route_refresh(
        &mut session,
        Afi::Ipv4,
        Safi::Unicast,
        RouteRefreshSubtype::BoRR,
    );
    {
        let process = session.process_read_buffer();
        tokio::pin!(process);
        tokio::select! {
            () = tokio::task::yield_now() => {}
            () = &mut process => panic!("BoRR unexpectedly crossed a full RIB channel"),
        }
    }
    assert_eq!(
        session.refresh_accounting_window_count(),
        0,
        "BoRR must not open local accounting before RIB acceptance"
    );
    assert!(matches!(
        rib_rx.recv().await,
        Some(RibUpdate::BeginRouteRefresh { .. })
    ));
    buffer_route_refresh(
        &mut session,
        Afi::Ipv4,
        Safi::Unicast,
        RouteRefreshSubtype::BoRR,
    );
    session.process_read_buffer().await;
    assert!(session.refresh_accounting_has_window((Afi::Ipv4, Safi::Unicast)));
    assert!(matches!(
        rib_rx.recv().await,
        Some(RibUpdate::BeginRouteRefresh { .. })
    ));

    session
        .rib_tx
        .try_send(RibUpdate::BeginRouteRefresh {
            peer: session.peer_ip,
            session_id: session.session_identity.id,
            afi: Afi::Ipv6,
            safi: Safi::Unicast,
        })
        .unwrap();
    buffer_route_refresh(
        &mut session,
        Afi::Ipv4,
        Safi::Unicast,
        RouteRefreshSubtype::EoRR,
    );
    {
        let process = session.process_read_buffer();
        tokio::pin!(process);
        tokio::select! {
            () = tokio::task::yield_now() => {}
            () = &mut process => panic!("EoRR unexpectedly crossed a full RIB channel"),
        }
    }
    assert!(session.refresh_accounting_has_window((Afi::Ipv4, Safi::Unicast)));
    assert_eq!(
        session.known_prefix_count(),
        1,
        "EoRR must not sweep local accounting before RIB acceptance"
    );
    assert!(matches!(
        rib_rx.recv().await,
        Some(RibUpdate::BeginRouteRefresh { .. })
    ));
    buffer_route_refresh(
        &mut session,
        Afi::Ipv4,
        Safi::Unicast,
        RouteRefreshSubtype::EoRR,
    );
    session.process_read_buffer().await;
    assert_eq!(session.refresh_accounting_window_count(), 0);
    assert_eq!(session.known_prefix_count(), 0);
    assert!(matches!(
        rib_rx.recv().await,
        Some(RibUpdate::EndRouteRefresh { .. })
    ));
}

#[tokio::test]
async fn refresh_stale_routes_remain_conservatively_counted_until_boundary() {
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    let (client, _server) = connected_stream_pair().await;
    session.test_install_stream(client);
    establish_test_session(&mut session, 65002).await;
    while rib_rx.try_recv().is_ok() {}
    session.config.max_prefixes = Some(1);
    let stale = Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, 0), 24);
    session.remember_known_path(Prefix::V4(stale), 0);
    session.begin_refresh_accounting(Afi::Ipv4, Safi::Unicast);
    let new = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 0), 24);
    session.process_update(ipv4_announce(new, 0, false)).await;
    let post_overflow: Vec<_> = std::iter::from_fn(|| rib_rx.try_recv().ok()).collect();
    assert!(
        post_overflow
            .iter()
            .all(|update| !matches!(update, RibUpdate::RoutesReceived { .. })),
        "a new route at the exact cap must not receive transient ERR headroom"
    );
    assert!(
        post_overflow
            .iter()
            .any(|update| matches!(update, RibUpdate::PeerDown { .. })),
        "the overflow must deregister the established peer"
    );
    assert!(
        session.read_half.is_none(),
        "the stale route must still count, so the new prefix drives Cease teardown"
    );
    assert_eq!(session.known_prefix_count(), 0);
    assert_eq!(session.refresh_accounting_window_count(), 0);
}

#[tokio::test]
async fn failed_refresh_marker_sends_never_mutate_local_accounting_window() {
    let mut session = make_test_session(65001, 65002);
    install_enhanced_refresh_session(&mut session, vec![(Afi::Ipv4, Safi::Unicast)], false);
    let prefix = Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, 0), 24));
    session.remember_known_path(prefix, 0);
    buffer_route_refresh(
        &mut session,
        Afi::Ipv4,
        Safi::Unicast,
        RouteRefreshSubtype::BoRR,
    );
    session.process_read_buffer().await;
    assert_eq!(session.refresh_accounting_window_count(), 0);

    session.begin_refresh_accounting(Afi::Ipv4, Safi::Unicast);
    buffer_route_refresh(
        &mut session,
        Afi::Ipv4,
        Safi::Unicast,
        RouteRefreshSubtype::EoRR,
    );
    session.process_read_buffer().await;
    assert!(session.refresh_accounting_has_window((Afi::Ipv4, Safi::Unicast)));
    assert_eq!(session.known_prefix_count(), 1);
}

#[tokio::test]
async fn stray_eorr_is_a_local_noop_after_ordered_rib_acceptance() {
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    let (client, _server) = connected_stream_pair().await;
    session.test_install_stream(client);
    establish_test_session(&mut session, 65002).await;
    install_enhanced_refresh_session(&mut session, vec![(Afi::Ipv4, Safi::Unicast)], false);
    while rib_rx.try_recv().is_ok() {}
    let prefix = Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, 0), 24));
    session.remember_known_path(prefix, 0);

    buffer_route_refresh(
        &mut session,
        Afi::Ipv4,
        Safi::Unicast,
        RouteRefreshSubtype::EoRR,
    );
    session.process_read_buffer().await;
    assert!(matches!(
        rib_rx.try_recv(),
        Ok(RibUpdate::EndRouteRefresh {
            afi: Afi::Ipv4,
            safi: Safi::Unicast,
            ..
        })
    ));
    assert_eq!(session.refresh_accounting_window_count(), 0);
    assert_eq!(session.known_prefix_count(), 1);
    assert!(session.read_half.is_some());
}
/// Regression: `SessionDown` must clear `FlowSpec` and `EVPN` alongside unicast
/// accounting; otherwise reconnect inherits stale counts and can trip a false
/// max-prefix violation. Mutant: omitting either plain or Add-Path storage from
/// `clear_known_routes` leaves the corresponding assertion non-empty.
#[tokio::test]
async fn session_down_clears_all_known_sets() {
    let mut session = make_test_session(65001, 65002);
    let mut negotiated = negotiated_session(65002, false);
    negotiated.negotiated_families = vec![(Afi::Ipv4, Safi::Unicast), (Afi::Ipv6, Safi::Unicast)];
    negotiated
        .add_path_families
        .insert((Afi::Ipv6, Safi::Unicast), AddPathMode::Receive);
    negotiated.peer_gr_capable = true;
    negotiated
        .peer_capabilities
        .push(Capability::GracefulRestart {
            restart_state: false,
            notification: false,
            restart_time: 120,
            families: vec![],
        });
    install_test_negotiated_session(&mut session, negotiated);
    session.config.peer.graceful_restart = true;
    session.established_at = Some(Instant::now());
    let prefix = Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24));
    session.remember_known_path(prefix, 0);
    let add_path_prefix = Prefix::V6(Ipv6Prefix::new(Ipv6Addr::LOCALHOST, 128));
    session.remember_known_path(add_path_prefix, 0);
    let fs_prefix =
        rustbgpd_wire::FlowSpecPrefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24));
    session.known_flowspec.insert(rustbgpd_rib::FlowSpecKey {
        afi: Afi::Ipv4,
        rule: rustbgpd_wire::FlowSpecRule {
            components: vec![rustbgpd_wire::FlowSpecComponent::DestinationPrefix(
                fs_prefix,
            )],
        },
    });
    let evpn_key = rustbgpd_wire::EvpnRouteKey::Imet {
        rd: rustbgpd_wire::RouteDistinguisher([0, 0, 0xFD, 0xE8, 0, 0, 0, 1]),
        ethernet_tag: rustbgpd_wire::EthernetTagId(100),
        originator_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
    };
    session.known_evpn.insert(evpn_key);
    session
        .received_eor_families
        .insert((Afi::Ipv4, Safi::Unicast));
    session.begin_refresh_accounting(Afi::Ipv4, Safi::Unicast);
    assert!(session.known_prefix_count() >= 3);
    session.execute_actions(vec![Action::SessionDown]).await;
    assert!(
        session.known_plain_prefixes.is_empty(),
        "known_plain_prefixes must clear"
    );
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
    assert!(session.received_eor_families.is_empty());
    assert_eq!(session.refresh_accounting_window_count(), 0);
    assert!(session.refresh_accounting_timer.is_none());
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
        exact_export_snapshot: Some(session.publish_export_profile()),
        announce_source_exclusion: None,
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
        shared_group_encode: None,
    });
    let Message::Update(msg) = read_single_bgp_message(&mut server).await else {
        panic!("expected UPDATE");
    };
    let parsed = msg.parse(true, false, &[]).unwrap();
    assert_eq!(parsed.announced.len(), 2);
}

#[tokio::test]
async fn shared_transition_payload_excludes_only_the_target_source() {
    let (mut session, _rib_rx) = make_test_session_with_rib(65001, 65002);
    let (client, mut server) = connected_stream_pair().await;
    session.test_install_stream(client);
    let negotiated = negotiated_session(65002, false);
    session
        .negotiated_families
        .clone_from(&negotiated.negotiated_families);
    session.negotiated = Some(negotiated);

    let own = make_route(100);
    assert_eq!(own.peer, session.peer_ip);
    let other_prefix = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 0), 24);
    let other = Route {
        prefix: Prefix::V4(other_prefix),
        peer: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9)),
        ..own.clone()
    };
    let mut update = empty_outbound_update();
    update.exact_export_snapshot = Some(session.publish_export_profile());
    update.announce_source_exclusion = Some(session.peer_ip);
    update.announce = vec![own, other.clone()].into();
    update.next_hop_override = vec![None, None].into();
    session.send_route_update(update);

    let Message::Update(message) = read_single_bgp_message(&mut server).await else {
        panic!("expected UPDATE");
    };
    let parsed = message.parse(true, false, &[]).unwrap();
    assert_eq!(parsed.announced.len(), 1);
    assert_eq!(parsed.announced[0].prefix, other_prefix);
}

/// Build a route-server-style route owned by `source` with a per-source
/// `AS_PATH` so shared-encode grouping cannot merge sources through
/// interned attribute pointers.
fn make_sourced_route(source: Ipv4Addr, prefix: Ipv4Prefix, asn: u32) -> Route {
    Route {
        prefix: Prefix::V4(prefix),
        peer: IpAddr::V4(source),
        next_hop: IpAddr::V4(source),
        attributes: Arc::new(vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath {
                segments: vec![AsPathSegment::AsSequence(vec![asn])],
            }),
            PathAttribute::NextHop(source),
        ]),
        ..make_route(100)
    }
}

/// One update-group member session wired to a live loopback stream.
async fn shared_group_member(local_asn: u32) -> (PeerSession, TcpStream) {
    let (mut session, _rib_rx) = make_test_session_with_rib(local_asn, 65002);
    let (client, server) = connected_stream_pair().await;
    session.test_install_stream(client);
    let negotiated = negotiated_session(65002, false);
    session
        .negotiated_families
        .clone_from(&negotiated.negotiated_families);
    session.negotiated = Some(negotiated);
    session.config.route_server_client = true;
    (session, server)
}

fn shared_group_envelope(
    session: &PeerSession,
    shared: &Arc<rustbgpd_rib::SharedGroupEncode>,
    excluded_source: Ipv4Addr,
    announce: &[Route],
) -> OutboundRouteUpdate {
    let mut update = empty_outbound_update();
    update.exact_export_snapshot = Some(session.publish_export_profile());
    update.announce_source_exclusion = Some(IpAddr::V4(excluded_source));
    update.announce = announce.to_vec().into();
    update.next_hop_override = vec![None; announce.len()].into();
    update.shared_group_encode = Some(Arc::clone(shared));
    update
}

async fn read_announced_prefixes(stream: &mut TcpStream, expected_updates: usize) -> Vec<Prefix> {
    let mut prefixes = Vec::new();
    for _ in 0..expected_updates {
        let Message::Update(message) = read_single_bgp_message(stream).await else {
            panic!("expected UPDATE");
        };
        let parsed = message.parse(true, false, &[]).unwrap();
        prefixes.extend(parsed.announced.iter().map(|nlri| Prefix::V4(nlri.prefix)));
    }
    prefixes.sort_unstable();
    prefixes
}

/// The first member of a grouped fanout encodes the shared inventory once;
/// the second reuses the published bytes. Each member's stream is the
/// inventory minus its own source's chunks (split horizon composes from
/// whole per-source chunks).
#[tokio::test]
async fn shared_group_encode_first_member_encodes_and_second_reuses() {
    let source_a = Ipv4Addr::new(10, 30, 0, 1);
    let source_b = Ipv4Addr::new(10, 30, 0, 2);
    let source_c = Ipv4Addr::new(10, 30, 0, 3);
    let prefix_a = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24);
    let prefix_b = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 0), 24);
    let prefix_c = Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, 0), 24);
    let announce = vec![
        make_sourced_route(source_a, prefix_a, 64_601),
        make_sourced_route(source_b, prefix_b, 64_602),
        make_sourced_route(source_c, prefix_c, 64_603),
    ];
    let shared = Arc::new(rustbgpd_rib::SharedGroupEncode::default());

    let (mut member_a, mut wire_a) = shared_group_member(65001).await;
    let update = shared_group_envelope(&member_a, &shared, source_a, &announce);
    member_a.handle_outbound_route_update(update).await;
    let published = shared.cell.get().expect("first member publishes the cell");
    let (chunk_count, terminal) = published
        .downcast_ref::<super::shared_group::ProgressiveUnicastEncode>()
        .expect("cell payload is the transport shared-encode type")
        .test_snapshot();
    assert_eq!(
        terminal,
        Some(super::shared_group::StreamTerminal::Complete),
        "uniform-profile inventory must complete"
    );
    assert_eq!(chunk_count, 3, "one chunk per source at this size");
    assert_eq!(
        read_announced_prefixes(&mut wire_a, 2).await,
        {
            let mut expected = vec![Prefix::V4(prefix_b), Prefix::V4(prefix_c)];
            expected.sort_unstable();
            expected
        },
        "member A receives the table minus its own source"
    );

    let (mut member_b, mut wire_b) = shared_group_member(65001).await;
    let update = shared_group_envelope(&member_b, &shared, source_b, &announce);
    member_b.handle_outbound_route_update(update).await;
    assert!(
        Arc::ptr_eq(shared.cell.get().unwrap(), published),
        "second member reuses the published encode"
    );
    assert_eq!(
        read_announced_prefixes(&mut wire_b, 2).await,
        {
            let mut expected = vec![Prefix::V4(prefix_a), Prefix::V4(prefix_c)];
            expected.sort_unstable();
            expected
        },
        "member B receives the table minus its own source"
    );
}

/// A member whose export profile is not provably wire-identical to the
/// encoder's must fall back to its ordinary per-session encode and still
/// deliver a correct stream.
#[tokio::test]
async fn shared_group_encode_profile_mismatch_falls_back_to_local_encode() {
    let source_a = Ipv4Addr::new(10, 31, 0, 1);
    let source_b = Ipv4Addr::new(10, 31, 0, 2);
    let prefix_a = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24);
    let prefix_b = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 0), 24);
    let announce = vec![
        make_sourced_route(source_a, prefix_a, 64_601),
        make_sourced_route(source_b, prefix_b, 64_602),
    ];
    let shared = Arc::new(rustbgpd_rib::SharedGroupEncode::default());

    let (mut member_a, mut wire_a) = shared_group_member(65001).await;
    let update = shared_group_envelope(&member_a, &shared, source_a, &announce);
    member_a.handle_outbound_route_update(update).await;
    assert!(shared.cell.get().is_some());
    assert_eq!(
        read_announced_prefixes(&mut wire_a, 1).await,
        vec![Prefix::V4(prefix_b)]
    );

    // Different local ASN = different wire bytes (AS_PATH prepend) — the
    // equality proof must reject the published encode.
    let (mut member_b, mut wire_b) = shared_group_member(64_999).await;
    let update = shared_group_envelope(&member_b, &shared, source_b, &announce);
    member_b.handle_outbound_route_update(update).await;
    assert_eq!(
        read_announced_prefixes(&mut wire_b, 1).await,
        vec![Prefix::V4(prefix_a)],
        "fallback member still delivers its correct per-session stream"
    );
}

/// Shared chunks carry their family; a member that did not negotiate a
/// family skips those chunks even though the encoder produced them.
#[tokio::test]
async fn shared_group_encode_skips_chunks_of_unnegotiated_families() {
    let source_a = Ipv4Addr::new(10, 32, 0, 1);
    let source_b = Ipv4Addr::new(10, 32, 0, 2);
    let prefix_v4 = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24);
    let v6_route = Route {
        prefix: Prefix::V6(Ipv6Prefix::new(
            "2001:db8:2::".parse::<Ipv6Addr>().unwrap(),
            48,
        )),
        next_hop: IpAddr::V6("2001:db8::b".parse::<Ipv6Addr>().unwrap()),
        ..make_sourced_route(source_b, prefix_v4, 64_602)
    };
    let announce = vec![make_sourced_route(source_a, prefix_v4, 64_601), v6_route];
    let shared = Arc::new(rustbgpd_rib::SharedGroupEncode::default());

    // Encoder negotiated IPv4 only, and its own source is excluded — its
    // wire stream must skip the IPv6 chunk it still encoded for the group.
    let (mut member_a, mut wire_a) = shared_group_member(65001).await;
    let update = shared_group_envelope(&member_a, &shared, source_a, &announce);
    member_a.handle_outbound_route_update(update).await;
    let published = shared.cell.get().expect("cell published");
    let (chunk_count, terminal) = published
        .downcast_ref::<super::shared_group::ProgressiveUnicastEncode>()
        .unwrap()
        .test_snapshot();
    assert_eq!(
        terminal,
        Some(super::shared_group::StreamTerminal::Complete)
    );
    assert_eq!(
        chunk_count, 2,
        "encoder produced the IPv6 chunk for dual-stack members"
    );
    // Member A negotiated only IPv4-unicast and excluded source A: nothing
    // but the IPv6 chunk remains, and that chunk is skipped — so the next
    // message on the wire would block forever. Prove the skip by sending a
    // sentinel envelope through the ordinary path and reading it back.
    let mut sentinel = empty_outbound_update();
    sentinel.exact_export_snapshot = Some(member_a.publish_export_profile());
    let sentinel_prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, 128), 25);
    sentinel.announce = vec![make_sourced_route(source_b, sentinel_prefix, 64_602)].into();
    sentinel.next_hop_override = vec![None].into();
    member_a.handle_outbound_route_update(sentinel).await;
    assert_eq!(
        read_announced_prefixes(&mut wire_a, 1).await,
        vec![Prefix::V4(sentinel_prefix)],
        "no IPv6 UPDATE preceded the sentinel on an IPv4-only session"
    );
}

/// A stream that terminates `Failed` after a member already sent shared
/// chunks must fall back to the full local encode: the receiver sees the
/// head chunk again (byte-identical, idempotent) and every remaining route
/// exactly once — repetition is possible, skipping is not.
#[tokio::test]
async fn shared_group_encode_midstream_failure_falls_back_without_skips() {
    use super::shared_group::{ProgressiveUnicastEncode, StreamTerminal};
    let source_a = Ipv4Addr::new(10, 33, 0, 1);
    let source_b = Ipv4Addr::new(10, 33, 0, 2);
    let source_x = Ipv4Addr::new(10, 33, 0, 9);
    let prefix_a = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24);
    let prefix_b = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 0), 24);
    let announce = vec![
        make_sourced_route(source_a, prefix_a, 64_601),
        make_sourced_route(source_b, prefix_b, 64_602),
    ];

    let (mut member, mut wire) = shared_group_member(65001).await;
    let profile = (*member.publish_export_profile()).clone();
    let encode = ProgressiveUnicastEncode::test_new(profile.clone());
    // Simulate an encoder that published the first source's chunk and then
    // hit an anomaly.
    let mut cache = super::export::PreparedAttrCache::default();
    let head = super::shared_group::encode_shared_unicast_slice(
        &profile,
        &mut cache,
        &announce[..1],
        &[None],
        &[0],
    )
    .expect("head slice encodes");
    encode.test_publish(head);
    encode.test_finish(StreamTerminal::Failed);
    let shared = Arc::new(rustbgpd_rib::SharedGroupEncode::default());
    assert!(
        shared
            .cell
            .set(Arc::new(encode) as Arc<dyn std::any::Any + Send + Sync>)
            .is_ok(),
        "fresh cell"
    );

    // Exclusion targets an uninvolved source, so this member wants both
    // routes.
    let update = shared_group_envelope(&member, &shared, source_x, &announce);
    member.handle_outbound_route_update(update).await;

    // Wire: the shared head chunk (prefix A), then the full local fallback
    // stream (prefix A and prefix B in distinct-attr UPDATEs).
    assert_eq!(
        read_announced_prefixes(&mut wire, 3).await,
        {
            let mut expected = vec![
                Prefix::V4(prefix_a),
                Prefix::V4(prefix_a),
                Prefix::V4(prefix_b),
            ];
            expected.sort_unstable();
            expected
        },
        "head chunk repeats (idempotent), nothing is skipped"
    );
}

/// The encoder unwinding without a terminal must leave `Failed`, never a
/// stream consumers could wait on forever.
#[tokio::test]
async fn shared_group_encoder_guard_publishes_failed_on_unwind() {
    use super::shared_group::{EncoderGuard, ProgressiveUnicastEncode, StreamTerminal};
    let (member, _wire) = shared_group_member(65001).await;
    let encode = ProgressiveUnicastEncode::test_new((*member.publish_export_profile()).clone());
    drop(EncoderGuard(&encode));
    assert_eq!(encode.test_snapshot(), (0, Some(StreamTerminal::Failed)));
}

/// An inventory larger than one encoder slice is published progressively
/// across slices and streams completely to a consumer, with split horizon
/// still composed from whole per-source chunks.
#[tokio::test]
async fn shared_group_encode_streams_multiple_slices() {
    let sources = [
        Ipv4Addr::new(10, 34, 0, 1),
        Ipv4Addr::new(10, 34, 0, 2),
        Ipv4Addr::new(10, 34, 0, 3),
    ];
    // One attribute Arc per source so same-source routes group into shared
    // chunks (mirroring interned route-server tables).
    let attrs: Vec<Arc<Vec<PathAttribute>>> = sources
        .iter()
        .enumerate()
        .map(|(i, source)| {
            Arc::new(vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath {
                    segments: vec![AsPathSegment::AsSequence(vec![
                        64_601 + u32::try_from(i).unwrap(),
                    ])],
                }),
                PathAttribute::NextHop(*source),
            ])
        })
        .collect();
    let total = 2_100_usize; // > one 2048-route slice
    let announce: Vec<Route> = (0..total)
        .map(|i| {
            let source = sources[i % 3];
            Route {
                prefix: Prefix::V4(Ipv4Prefix::new(
                    Ipv4Addr::from(0x0A40_0000_u32 + u32::try_from(i).unwrap() * 256),
                    24,
                )),
                peer: IpAddr::V4(source),
                next_hop: IpAddr::V4(source),
                attributes: Arc::clone(&attrs[i % 3]),
                ..make_route(100)
            }
        })
        .collect();
    let shared = Arc::new(rustbgpd_rib::SharedGroupEncode::default());

    let (mut member_a, mut wire_a) = shared_group_member(65001).await;
    let update = shared_group_envelope(&member_a, &shared, sources[0], &announce);
    member_a.handle_outbound_route_update(update).await;
    let (chunk_count, terminal) = shared
        .cell
        .get()
        .unwrap()
        .downcast_ref::<super::shared_group::ProgressiveUnicastEncode>()
        .unwrap()
        .test_snapshot();
    assert_eq!(
        terminal,
        Some(super::shared_group::StreamTerminal::Complete)
    );
    assert_eq!(
        chunk_count, 4,
        "source-sorted iteration keeps per-source chunks dense: three whole \
         sources in slice one, the third source's tail in slice two"
    );

    let expected_a: Vec<Prefix> = {
        let mut v: Vec<Prefix> = announce
            .iter()
            .filter(|route| route.peer != IpAddr::V4(sources[0]))
            .map(|route| route.prefix)
            .collect();
        v.sort_unstable();
        v
    };
    assert_eq!(read_announced_prefixes(&mut wire_a, 3).await, expected_a);

    let (mut member_b, mut wire_b) = shared_group_member(65001).await;
    let update = shared_group_envelope(&member_b, &shared, sources[1], &announce);
    member_b.handle_outbound_route_update(update).await;
    let expected_b: Vec<Prefix> = {
        let mut v: Vec<Prefix> = announce
            .iter()
            .filter(|route| route.peer != IpAddr::V4(sources[1]))
            .map(|route| route.prefix)
            .collect();
        v.sort_unstable();
        v
    };
    assert_eq!(read_announced_prefixes(&mut wire_b, 3).await, expected_b);
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
        bgpls_announce: vec![route.clone()],
        bgpls_withdraw: vec![],
        vpn_announce: vec![],
        labeled_announce: vec![],
        rtc_announce: vec![],
        vpn_withdraw: vec![],
        labeled_withdraw: vec![],
        rtc_withdraw: vec![],
        request_refresh_all_negotiated: false,
        shared_group_encode: None,
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
        bgpls_withdraw: vec![key],
        vpn_announce: vec![],
        labeled_announce: vec![],
        rtc_announce: vec![],
        vpn_withdraw: vec![],
        labeled_withdraw: vec![],
        rtc_withdraw: vec![],
        request_refresh_all_negotiated: false,
        shared_group_encode: None,
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
        bgpls_announce: vec![route],
        bgpls_withdraw: vec![],
        vpn_announce: vec![],
        labeled_announce: vec![],
        rtc_announce: vec![],
        vpn_withdraw: vec![],
        labeled_withdraw: vec![],
        rtc_withdraw: vec![],
        request_refresh_all_negotiated: false,
        shared_group_encode: None,
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
        "oversize output routes through the out-of-resources hard close, got: {result:?}"
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
    session
        .negotiated_families
        .clone_from(&negotiated.negotiated_families);
    session.negotiated = Some(negotiated);
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
            PathAttribute::MpReachNlri(MpReachNlri {
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
            })
        };
        let unreach = |path_id| {
            PathAttribute::MpUnreachNlri(MpUnreachNlri {
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
            })
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
        assert!(withdrawn.is_empty());
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

/// Import-policy denial retires an accepted RTC identity exactly once,
/// deduplicates an overlapping explicit withdrawal, keeps first-seen denials
/// silent, and reconciles max-prefix plus Enhanced Refresh accounting.
///
/// Break-to-red: deleting denied-key collection leaves the accepted route and
/// stale refresh identity live; appending without `known_rtc.remove` duplicates
/// the overlap and emits a first-seen withdrawal; capturing refresh state
/// without the synthetic withdrawal leaves the stale count unchanged.
#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "one ordered refresh sequence proves replacement, deduplication, and accounting"
)]
async fn denied_rtc_replacements_reconcile_exact_refresh_identity() {
    use rustbgpd_wire::{MpReachNlri, MpUnreachNlri, RtcNlri};

    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    let family = (Afi::Ipv4, Safi::RtConstrain);
    let mut negotiated = negotiated_session(65002, false);
    negotiated.negotiated_families = vec![family];
    negotiated.peer_route_refresh = true;
    negotiated.peer_enhanced_route_refresh = true;
    install_test_negotiated_session(&mut session, negotiated);

    let nlri =
        |admin: u16| RtcNlri::new(65002, 0x0002_FDEA_0000_0000 | u64::from(admin), 96).unwrap();
    let first = nlri(11);
    let overlap = nlri(22);
    let first_seen = nlri(33);
    let key = |nlri| rustbgpd_rib::RtcRibRouteKey { nlri, path_id: 0 };
    let base_attrs = || {
        vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath {
                segments: vec![AsPathSegment::AsSequence(vec![65002])],
            }),
        ]
    };
    let reach = |nlris: Vec<RtcNlri>| {
        PathAttribute::MpReachNlri(MpReachNlri {
            afi: Afi::Ipv4,
            safi: Safi::RtConstrain,
            next_hop: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)),
            link_local_next_hop: None,
            announced: vec![],
            flowspec_announced: vec![],
            evpn_announced: vec![],
            bgpls_announced: vec![],
            labeled_announced: vec![],
            vpn_announced: vec![],
            rtc_announced: nlris,
        })
    };
    let unreach = |nlris: Vec<RtcNlri>| {
        PathAttribute::MpUnreachNlri(MpUnreachNlri {
            afi: Afi::Ipv4,
            safi: Safi::RtConstrain,
            withdrawn: vec![],
            flowspec_withdrawn: vec![],
            evpn_withdrawn: vec![],
            bgpls_withdrawn: vec![],
            labeled_withdrawn: vec![],
            vpn_withdrawn: vec![],
            rtc_withdrawn: nlris,
        })
    };
    let update = |mut attributes: Vec<PathAttribute>, reach_attr, unreach_attr| {
        attributes.push(reach_attr);
        if let Some(unreach_attr) = unreach_attr {
            attributes.push(unreach_attr);
        }
        UpdateMessage::build(&[], &[], &attributes, true, false, Ipv4UnicastMode::Body)
    };

    session
        .process_update(update(base_attrs(), reach(vec![first, overlap]), None))
        .await;
    let RibUpdate::RtcRoutesReceived {
        announced,
        withdrawn,
        ..
    } = rib_rx
        .try_recv()
        .expect("accepted RTC routes reach the RIB")
    else {
        panic!("expected RtcRoutesReceived");
    };
    assert_eq!(announced.len(), 2);
    assert!(withdrawn.is_empty());
    assert_eq!(session.known_prefix_count(), 2);

    buffer_route_refresh(
        &mut session,
        Afi::Ipv4,
        Safi::RtConstrain,
        RouteRefreshSubtype::BoRR,
    );
    session.process_read_buffer().await;
    assert!(matches!(
        rib_rx.try_recv(),
        Ok(RibUpdate::BeginRouteRefresh {
            afi: Afi::Ipv4,
            safi: Safi::RtConstrain,
            ..
        })
    ));
    assert_eq!(session.refresh_accounting_stale_count(family), Some(2));

    session.install_import_policy(Some(PolicyChain::new(vec![Policy {
        entries: vec![],
        default_action: PolicyAction::Deny,
    }])));

    session
        .process_update(update(base_attrs(), reach(vec![first]), None))
        .await;
    let RibUpdate::RtcRoutesReceived {
        announced,
        withdrawn,
        ..
    } = rib_rx
        .try_recv()
        .expect("denied RTC replacement reaches the RIB")
    else {
        panic!("expected RtcRoutesReceived");
    };
    assert!(announced.is_empty());
    assert_eq!(withdrawn, vec![key(first)]);
    assert_eq!(session.known_prefix_count(), 1);
    assert_eq!(session.refresh_accounting_stale_count(family), Some(1));

    session
        .process_update(update(
            base_attrs(),
            reach(vec![overlap]),
            Some(unreach(vec![overlap])),
        ))
        .await;
    let RibUpdate::RtcRoutesReceived {
        announced,
        withdrawn,
        ..
    } = rib_rx.try_recv().expect("overlap reaches the RIB once")
    else {
        panic!("expected RtcRoutesReceived");
    };
    assert!(announced.is_empty());
    assert_eq!(withdrawn, vec![key(overlap)]);
    assert_eq!(session.known_prefix_count(), 0);
    assert_eq!(session.refresh_accounting_stale_count(family), Some(0));

    session
        .process_update(update(base_attrs(), reach(vec![first_seen]), None))
        .await;
    assert!(
        rib_rx.try_recv().is_err(),
        "first-seen RTC denial is silent"
    );
    assert!(!session.known_rtc.contains(&key(first_seen)));
    assert_eq!(session.known_prefix_count(), 0);
    assert_eq!(session.refresh_accounting_stale_count(family), Some(0));

    buffer_route_refresh(
        &mut session,
        Afi::Ipv4,
        Safi::RtConstrain,
        RouteRefreshSubtype::EoRR,
    );
    session.process_read_buffer().await;
    assert!(matches!(
        rib_rx.try_recv(),
        Ok(RibUpdate::EndRouteRefresh {
            afi: Afi::Ipv4,
            safi: Safi::RtConstrain,
            ..
        })
    ));
    assert_eq!(session.refresh_accounting_window_count(), 0);
}

/// Import-policy denial retires an accepted BGP-LS identity exactly once for
/// SAFI 71 and 72, deduplicates an overlapping explicit withdrawal, keeps
/// first-seen denials silent, and reconciles max-prefix plus Enhanced Refresh.
///
/// Break-to-red: deleting denied-key collection leaves the accepted topology
/// object and stale refresh identity live; appending without
/// `known_bgpls.remove` duplicates the overlap and emits first-seen state;
/// omitting the synthetic withdrawal from refresh capture leaves stale count.
#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "one ordered refresh sequence covers both BGP-LS SAFIs"
)]
async fn denied_bgpls_replacements_reconcile_exact_refresh_identity_for_both_safis() {
    use rustbgpd_rib::BgpLsFamily;
    use rustbgpd_wire::{MpReachNlri, MpUnreachNlri};

    fn nlri(safi: Safi, suffix: u8) -> BgpLsNlri {
        match safi {
            Safi::BgpLs => decode_bgpls_nlri(&[0xfd, 0xe8, 0, 3, 0xaa, 0xbb, suffix]),
            Safi::BgpLsVpn => decode_bgpls_vpn_nlri(&[
                0xfd, 0xe8, 0, 11, // 8-byte RD + 3-byte opaque payload
                0, 0, 0xfd, 0xea, 0, 0, 0, 44, 0xaa, 0xbb, suffix,
            ]),
            _ => unreachable!("fixture covers only BGP-LS SAFIs"),
        }
        .expect("fixture BGP-LS NLRI decodes")
        .pop()
        .expect("fixture contains one BGP-LS NLRI")
    }

    #[expect(
        clippy::too_many_lines,
        reason = "the per-SAFI sequence proves replacement, deduplication, and accounting"
    )]
    async fn exercise(safi: Safi) {
        let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
        let afi = Afi::BgpLs;
        let family = (afi, safi);
        let bgpls_family = BgpLsFamily::from_afi_safi(afi, safi).unwrap();
        let mut negotiated = negotiated_session(65002, false);
        negotiated.negotiated_families = vec![family];
        negotiated.peer_route_refresh = true;
        negotiated.peer_enhanced_route_refresh = true;
        install_test_negotiated_session(&mut session, negotiated);

        let first = nlri(safi, 11);
        let overlap = nlri(safi, 22);
        let first_seen = nlri(safi, 33);
        let key = |nlri: &BgpLsNlri| rustbgpd_rib::BgpLsRouteKey {
            family: bgpls_family,
            nlri: nlri.key(),
            path_id: 0,
        };
        let base_attrs = || {
            vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath {
                    segments: vec![AsPathSegment::AsSequence(vec![65002])],
                }),
            ]
        };
        let reach = |nlris: Vec<BgpLsNlri>| {
            PathAttribute::MpReachNlri(MpReachNlri {
                afi,
                safi,
                next_hop: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)),
                link_local_next_hop: None,
                announced: vec![],
                flowspec_announced: vec![],
                evpn_announced: vec![],
                bgpls_announced: nlris,
                labeled_announced: vec![],
                vpn_announced: vec![],
                rtc_announced: vec![],
            })
        };
        let unreach = |nlris: Vec<BgpLsNlri>| {
            PathAttribute::MpUnreachNlri(MpUnreachNlri {
                afi,
                safi,
                withdrawn: vec![],
                flowspec_withdrawn: vec![],
                evpn_withdrawn: vec![],
                bgpls_withdrawn: nlris,
                labeled_withdrawn: vec![],
                vpn_withdrawn: vec![],
                rtc_withdrawn: vec![],
            })
        };
        let update = |mut attributes: Vec<PathAttribute>, reach_attr, unreach_attr| {
            attributes.push(reach_attr);
            if let Some(unreach_attr) = unreach_attr {
                attributes.push(unreach_attr);
            }
            UpdateMessage::build(&[], &[], &attributes, true, false, Ipv4UnicastMode::Body)
        };

        session
            .process_update(update(
                base_attrs(),
                reach(vec![first.clone(), overlap.clone()]),
                None,
            ))
            .await;
        let RibUpdate::BgpLsRoutesReceived {
            announced,
            withdrawn,
            ..
        } = rib_rx.try_recv().expect("accepted BGP-LS routes reach RIB")
        else {
            panic!("expected BgpLsRoutesReceived");
        };
        assert_eq!(announced.len(), 2);
        assert!(withdrawn.is_empty());
        assert_eq!(session.known_prefix_count(), 2);

        buffer_route_refresh(&mut session, afi, safi, RouteRefreshSubtype::BoRR);
        session.process_read_buffer().await;
        assert!(matches!(
            rib_rx.try_recv(),
            Ok(RibUpdate::BeginRouteRefresh {
                afi: Afi::BgpLs,
                safi: marker_safi,
                ..
            }) if marker_safi == safi
        ));
        assert_eq!(session.refresh_accounting_stale_count(family), Some(2));

        session.install_import_policy(Some(PolicyChain::new(vec![Policy {
            entries: vec![],
            default_action: PolicyAction::Deny,
        }])));

        session
            .process_update(update(base_attrs(), reach(vec![first.clone()]), None))
            .await;
        let RibUpdate::BgpLsRoutesReceived {
            announced,
            withdrawn,
            ..
        } = rib_rx
            .try_recv()
            .expect("denied BGP-LS replacement reaches RIB")
        else {
            panic!("expected BgpLsRoutesReceived");
        };
        assert!(announced.is_empty());
        assert_eq!(withdrawn, vec![key(&first)]);
        assert_eq!(session.known_prefix_count(), 1);
        assert_eq!(session.refresh_accounting_stale_count(family), Some(1));

        session
            .process_update(update(
                base_attrs(),
                reach(vec![overlap.clone()]),
                Some(unreach(vec![overlap.clone()])),
            ))
            .await;
        let RibUpdate::BgpLsRoutesReceived {
            announced,
            withdrawn,
            ..
        } = rib_rx.try_recv().expect("BGP-LS overlap reaches RIB once")
        else {
            panic!("expected BgpLsRoutesReceived");
        };
        assert!(announced.is_empty());
        assert_eq!(withdrawn, vec![key(&overlap)]);
        assert_eq!(session.known_prefix_count(), 0);
        assert_eq!(session.refresh_accounting_stale_count(family), Some(0));

        session
            .process_update(update(base_attrs(), reach(vec![first_seen.clone()]), None))
            .await;
        assert!(
            rib_rx.try_recv().is_err(),
            "first-seen BGP-LS denial is silent"
        );
        assert!(!session.known_bgpls.contains(&key(&first_seen)));
        assert_eq!(session.known_prefix_count(), 0);
        assert_eq!(session.refresh_accounting_stale_count(family), Some(0));

        buffer_route_refresh(&mut session, afi, safi, RouteRefreshSubtype::EoRR);
        session.process_read_buffer().await;
        assert!(matches!(
            rib_rx.try_recv(),
            Ok(RibUpdate::EndRouteRefresh {
                afi: Afi::BgpLs,
                safi: marker_safi,
                ..
            }) if marker_safi == safi
        ));
        assert_eq!(session.refresh_accounting_window_count(), 0);
    }

    exercise(Safi::BgpLs).await;
    exercise(Safi::BgpLsVpn).await;
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
        vpn_withdraw: vec![],
        labeled_withdraw: vec![],
        rtc_announce: vec![route.clone(), local_default],
        rtc_withdraw: vec![],
        request_refresh_all_negotiated: false,
        shared_group_encode: None,
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
        vpn_withdraw: vec![],
        labeled_withdraw: vec![],
        rtc_announce: vec![],
        rtc_withdraw: vec![key],
        request_refresh_all_negotiated: false,
        shared_group_encode: None,
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
        exact_export_snapshot: None,
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
        labeled_withdraw: vec![],
        rtc_withdraw: vec![],
        request_refresh_all_negotiated: true,
        shared_group_encode: None,
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

struct ForeignExactExportSnapshot;

impl rustbgpd_rib::ExactExportSnapshot for ForeignExactExportSnapshot {
    fn owner_id(&self) -> u64 {
        u64::MAX
    }

    fn generation(&self) -> u64 {
        0
    }

    fn probe_announcement(
        &self,
        _candidate: rustbgpd_rib::ExactExportCandidate<'_>,
    ) -> Result<rustbgpd_rib::ExactExportResult, rustbgpd_rib::ExactExportError> {
        Err(rustbgpd_rib::ExactExportError::new(
            rustbgpd_rib::ExactExportErrorCode::Encoding,
            "foreign test snapshot",
        ))
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

/// A route-bearing envelope is valid only when the RIB attaches the concrete
/// snapshot used by precommit. Missing snapshots, foreign concrete types, and
/// same-type snapshots owned by another session are invariant breaches, so all
/// take the established Cease/8 teardown path rather than letting logical
/// Adj-RIB-Out get ahead of the wire.
#[tokio::test]
async fn route_bearing_envelope_without_own_session_snapshot_fails_closed() {
    use rustbgpd_wire::notification::{NotificationCode, cease_subcode};

    let (other_session, _other_rib_rx) = make_test_session_with_rib(65001, 65002);
    let cases: Vec<(&str, Option<Arc<dyn rustbgpd_rib::ExactExportSnapshot>>)> = vec![
        ("missing", None),
        (
            "foreign concrete type",
            Some(Arc::new(ForeignExactExportSnapshot)),
        ),
        (
            "same concrete type from another session",
            Some(other_session.publish_export_profile()),
        ),
    ];
    for (name, snapshot) in cases {
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
        assert!(session.read_half.is_none(), "{name}: read half must close");
        assert!(
            session.writer_bulk_tx.is_none(),
            "{name}: bulk sender must close"
        );
    }
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
        exact_export_snapshot: Some(session.publish_export_profile()),
        announce_source_exclusion: None,
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
        shared_group_encode: None,
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
        exact_export_snapshot: Some(session.publish_export_profile()),
        announce_source_exclusion: None,
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
        shared_group_encode: None,
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
        exact_export_snapshot: Some(session.publish_export_profile()),
        announce_source_exclusion: None,
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
        exact_export_snapshot: Some(session.publish_export_profile()),
        announce_source_exclusion: None,
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
        exact_export_snapshot: Some(session.publish_export_profile()),
        announce_source_exclusion: None,
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
        exact_export_snapshot: Some(session.publish_export_profile()),
        announce_source_exclusion: None,
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
        exact_export_snapshot: Some(session.publish_export_profile()),
        announce_source_exclusion: None,
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
        exact_export_snapshot: Some(session.publish_export_profile()),
        announce_source_exclusion: None,
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
        exact_export_snapshot: Some(session.publish_export_profile()),
        announce_source_exclusion: None,
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
        exact_export_snapshot: Some(session.publish_export_profile()),
        announce_source_exclusion: None,
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

/// Extended Messages should not freeze MP batches at the conservative 1,024
/// entry first probe. Use a large shared attribute so 1,024 entries fit while
/// 2,048 do not; the sender must remember that failed upper bound, make
/// monotonic progress with a later in-between probe, and preserve exact order.
#[tokio::test]
async fn extended_ipv6_chunk_probe_grows_bounded_without_reordering() {
    let (mut session, _rib_rx) = make_test_session_with_rib(65001, 65002);
    session.config.route_server_client = true;
    let (client, mut server) = connected_stream_pair().await;
    session.test_install_stream(client);
    let mut negotiated = negotiated_session(65002, false);
    negotiated.negotiated_families = vec![(Afi::Ipv6, Safi::Unicast)];
    negotiated.peer_extended_message = true;
    install_test_negotiated_session(&mut session, negotiated);

    let padding = Bytes::from(vec![0x5a; 36_000]);
    let attrs = Arc::new(vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath {
            segments: vec![AsPathSegment::AsSequence(vec![65002])],
        }),
        PathAttribute::Unknown(rustbgpd_wire::RawAttribute {
            flags: rustbgpd_wire::constants::attr_flags::OPTIONAL
                | rustbgpd_wire::constants::attr_flags::TRANSITIVE,
            type_code: 99,
            data: padding,
        }),
    ]);
    let count = 3_500_u32;
    let expected: Vec<Prefix> = (0..count)
        .map(|i| {
            Prefix::V6(Ipv6Prefix::new(
                Ipv6Addr::from(0x2001_0db8_0003_0000_0000_0000_0000_0000_u128 + u128::from(i)),
                128,
            ))
        })
        .collect();
    let routes: Vec<Route> = expected
        .iter()
        .copied()
        .map(|prefix| Route {
            prefix,
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
        exact_export_snapshot: Some(session.publish_export_profile()),
        announce: routes.into(),
        next_hop_override: vec![None; count as usize].into(),
        ..empty_outbound_update()
    });

    let mut actual = Vec::new();
    let mut chunk_sizes = Vec::new();
    while let Ok(raw) = tokio::time::timeout(
        Duration::from_millis(500),
        read_single_raw_bgp_message(&mut server),
    )
    .await
    {
        assert!(
            raw.len() <= 65_535,
            "Extended UPDATE is {} bytes",
            raw.len()
        );
        let mut buf = Bytes::from(raw);
        let Message::Update(update) =
            rustbgpd_wire::decode_message(&mut buf, rustbgpd_wire::EXTENDED_MAX_MESSAGE_LEN)
                .unwrap()
        else {
            continue;
        };
        let parsed = update.parse(true, false, &[]).unwrap();
        let announced = parsed
            .attributes
            .iter()
            .find_map(|attribute| match attribute {
                PathAttribute::MpReachNlri(mp) => Some(&mp.announced),
                _ => None,
            })
            .expect("IPv6 announcement uses MP_REACH");
        chunk_sizes.push(announced.len());
        actual.extend(announced.iter().map(|entry| entry.prefix));
    }
    assert_eq!(
        actual, expected,
        "IPv6 NLRI must be emitted exactly once in order"
    );
    assert_eq!(chunk_sizes.first(), Some(&1024));
    assert!(
        chunk_sizes.iter().any(|size| *size > 1024),
        "a proven Extended Message candidate must grow beyond 1,024: {chunk_sizes:?}"
    );
}

/// Pin the same bounded-growth invariant for the fallible `FlowSpec` encoder.
#[tokio::test]
async fn extended_flowspec_chunk_probe_grows_and_preserves_exact_order() {
    let (mut session, _rib_rx) = make_test_session_with_rib(65001, 65002);
    let (client, mut server) = connected_stream_pair().await;
    session.test_install_stream(client);
    let mut negotiated = negotiated_session(65002, false);
    negotiated.negotiated_families = vec![(Afi::Ipv6, Safi::FlowSpec)];
    negotiated.peer_extended_message = true;
    install_test_negotiated_session(&mut session, negotiated);

    let padding = Bytes::from(vec![0xa5; 36_000]);
    let count = 3_500_u32;
    let rules: Vec<FlowSpecRule> = (0..count)
        .map(|i| FlowSpecRule {
            components: vec![FlowSpecComponent::DestinationPrefix(FlowSpecPrefix::V6(
                Ipv6PrefixOffset {
                    prefix: Ipv6Prefix::new(
                        Ipv6Addr::from(
                            0x2001_0db8_0004_0000_0000_0000_0000_0000_u128 + u128::from(i),
                        ),
                        128,
                    ),
                    offset: 0,
                },
            ))],
        })
        .collect();
    let routes = rules
        .iter()
        .cloned()
        .map(|rule| FlowSpecRoute {
            rule,
            afi: Afi::Ipv6,
            peer: IpAddr::V6("2001:db8::2".parse().unwrap()),
            attributes: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::Unknown(rustbgpd_wire::RawAttribute {
                    flags: rustbgpd_wire::constants::attr_flags::OPTIONAL
                        | rustbgpd_wire::constants::attr_flags::TRANSITIVE,
                    type_code: 99,
                    data: padding.clone(),
                }),
            ],
            received_at: Instant::now(),
            origin_type: rustbgpd_rib::RouteOrigin::Ebgp,
            peer_router_id: Ipv4Addr::UNSPECIFIED,
            is_stale: false,
            is_llgr_stale: false,
            path_id: 0,
        })
        .collect();
    session.send_route_update(OutboundRouteUpdate {
        exact_export_snapshot: Some(session.publish_export_profile()),
        flowspec_announce: routes,
        ..empty_outbound_update()
    });

    let mut actual = Vec::new();
    let mut chunk_sizes = Vec::new();
    while let Ok(raw) = tokio::time::timeout(
        Duration::from_millis(500),
        read_single_raw_bgp_message(&mut server),
    )
    .await
    {
        assert!(
            raw.len() <= 65_535,
            "Extended UPDATE is {} bytes",
            raw.len()
        );
        let mut buf = Bytes::from(raw);
        let Message::Update(update) =
            rustbgpd_wire::decode_message(&mut buf, rustbgpd_wire::EXTENDED_MAX_MESSAGE_LEN)
                .unwrap()
        else {
            continue;
        };
        let parsed = update.parse(true, false, &[]).unwrap();
        let announced = parsed
            .attributes
            .iter()
            .find_map(|attribute| match attribute {
                PathAttribute::MpReachNlri(mp) => Some(&mp.flowspec_announced),
                _ => None,
            })
            .expect("FlowSpec announcement uses MP_REACH");
        chunk_sizes.push(announced.len());
        actual.extend(announced.iter().cloned());
    }
    assert_eq!(
        actual, rules,
        "FlowSpec rules must be emitted exactly once in order"
    );
    assert_eq!(chunk_sizes.first(), Some(&1024));
    assert!(
        chunk_sizes.iter().any(|size| *size > 1024),
        "a proven Extended Message candidate must grow beyond 1,024: {chunk_sizes:?}"
    );
}

#[tokio::test]
async fn destinationless_flowspec_withdrawal_uses_explicit_afi() {
    let (mut session, _rib_rx) = make_test_session_with_rib(65001, 65002);
    let (client, mut server) = connected_stream_pair().await;
    session.test_install_stream(client);
    let mut negotiated = negotiated_session(65002, false);
    negotiated.negotiated_families = vec![(Afi::Ipv4, Safi::FlowSpec), (Afi::Ipv6, Safi::FlowSpec)];
    install_test_negotiated_session(&mut session, negotiated);
    let rule = FlowSpecRule {
        components: vec![FlowSpecComponent::IpProtocol(vec![NumericMatch {
            end_of_list: true,
            and_bit: false,
            lt: false,
            gt: false,
            eq: true,
            value: 6,
        }])],
    };
    let route = |afi| FlowSpecRoute {
        rule: rule.clone(),
        afi,
        peer: "192.0.2.1".parse().unwrap(),
        attributes: vec![PathAttribute::Origin(Origin::Igp)],
        received_at: Instant::now(),
        origin_type: rustbgpd_rib::RouteOrigin::Ebgp,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        is_stale: false,
        is_llgr_stale: false,
        path_id: 0,
    };
    session.send_route_update(OutboundRouteUpdate {
        exact_export_snapshot: Some(session.publish_export_profile()),
        announce_source_exclusion: None,
        otc_blocked: vec![],
        flowspec_announce: vec![route(Afi::Ipv4), route(Afi::Ipv6)],
        ..empty_outbound_update()
    });
    for expected_afi in [Afi::Ipv4, Afi::Ipv6] {
        let Message::Update(update) = read_single_bgp_message(&mut server).await else {
            panic!("expected FlowSpec announcement");
        };
        let parsed = update.parse(true, false, &[]).unwrap();
        let mp = parsed
            .attributes
            .iter()
            .find_map(|attribute| match attribute {
                PathAttribute::MpReachNlri(mp) => Some(mp),
                _ => None,
            })
            .unwrap();
        assert_eq!(mp.afi, expected_afi);
        assert_eq!(mp.flowspec_announced, vec![rule.clone()]);
    }

    session.send_route_update(OutboundRouteUpdate {
        exact_export_snapshot: Some(session.publish_export_profile()),
        announce_source_exclusion: None,
        otc_blocked: vec![],
        flowspec_withdraw: vec![
            rustbgpd_rib::FlowSpecKey {
                afi: Afi::Ipv6,
                rule: rule.clone(),
            },
            rustbgpd_rib::FlowSpecKey {
                afi: Afi::Ipv4,
                rule: rule.clone(),
            },
        ],
        ..empty_outbound_update()
    });
    for expected_afi in [Afi::Ipv4, Afi::Ipv6] {
        let Message::Update(update) = read_single_bgp_message(&mut server).await else {
            panic!("expected FlowSpec withdrawal");
        };
        let parsed = update.parse(true, false, &[]).unwrap();
        let mp = parsed
            .attributes
            .iter()
            .find_map(|attribute| match attribute {
                PathAttribute::MpUnreachNlri(mp) => Some(mp),
                _ => None,
            })
            .unwrap();
        assert_eq!(mp.afi, expected_afi);
        assert_eq!(mp.flowspec_withdrawn, vec![rule.clone()]);
    }
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
        exact_export_snapshot: Some(session.publish_export_profile()),
        announce_source_exclusion: None,
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
        exact_export_snapshot: Some(session.publish_export_profile()),
        announce_source_exclusion: None,
        otc_blocked: vec![],
        flowspec_withdraw: routes.iter().map(FlowSpecRoute::selection_key).collect(),
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
        exact_export_snapshot: Some(session.publish_export_profile()),
        announce_source_exclusion: None,
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
        exact_export_snapshot: Some(session.publish_export_profile()),
        announce_source_exclusion: None,
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
        shared_group_encode: None,
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

/// An OTC safety rejection replaces accepted classic and MP-unicast routes
/// with exact withdrawals. First-seen rejected identities remain silent.
#[expect(
    clippy::too_many_lines,
    reason = "pins classic and MP replacement withdrawal, first-seen gating, accounting, and explain state"
)]
#[tokio::test]
async fn otc_replacements_withdraw_accepted_classic_and_mp_routes_only() {
    use super::import_decision_cache::{CachedOutcome, ImportDecisionKey, LookupResult};
    use rustbgpd_wire::{MpReachNlri, NlriEntry};

    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    session.config.peer.local_role = Some(BgpRole::Provider);
    session.import_explain_enabled = true;
    let mut negotiated = negotiated_session(65002, false);
    negotiated.negotiated_families = vec![(Afi::Ipv4, Safi::Unicast), (Afi::Ipv6, Safi::Unicast)];
    install_test_negotiated_session(&mut session, negotiated);
    let accepted_v4 = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 0), 24);
    let first_seen_v4 = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24);
    let accepted_v6 = Prefix::V6(Ipv6Prefix::new("2001:db8:440:1::".parse().unwrap(), 64));
    let first_seen_v6 = Prefix::V6(Ipv6Prefix::new("2001:db8:440:2::".parse().unwrap(), 64));
    let attrs = |mp_announced: Vec<NlriEntry>, blocked: bool| {
        let mut attrs = vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath {
                segments: vec![AsPathSegment::AsSequence(vec![65002])],
            }),
            PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
        ];
        if blocked {
            attrs.push(PathAttribute::OnlyToCustomer(65002));
        }
        attrs.push(PathAttribute::MpReachNlri(MpReachNlri {
            afi: Afi::Ipv6,
            safi: Safi::Unicast,
            next_hop: "2001:db8::2".parse().unwrap(),
            link_local_next_hop: None,
            announced: mp_announced,
            flowspec_announced: vec![],
            evpn_announced: vec![],
            bgpls_announced: vec![],
            labeled_announced: vec![],
            vpn_announced: vec![],
            rtc_announced: vec![],
        }));
        attrs
    };
    session
        .process_update(UpdateMessage::build(
            &[Ipv4NlriEntry {
                path_id: 0,
                prefix: accepted_v4,
            }],
            &[],
            &attrs(
                vec![NlriEntry {
                    path_id: 0,
                    prefix: accepted_v6,
                }],
                false,
            ),
            true,
            false,
            Ipv4UnicastMode::Body,
        ))
        .await;
    let RibUpdate::RoutesReceived { announced, .. } = rib_rx.try_recv().unwrap() else {
        panic!("expected accepted classic and MP routes");
    };
    assert_eq!(announced.len(), 2);

    session
        .process_update(UpdateMessage::build(
            &[
                Ipv4NlriEntry {
                    path_id: 0,
                    prefix: accepted_v4,
                },
                Ipv4NlriEntry {
                    path_id: 0,
                    prefix: first_seen_v4,
                },
            ],
            &[],
            &attrs(
                vec![
                    NlriEntry {
                        path_id: 0,
                        prefix: accepted_v6,
                    },
                    NlriEntry {
                        path_id: 0,
                        prefix: first_seen_v6,
                    },
                ],
                true,
            ),
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
        .expect("accepted OTC replacements must become withdrawals")
    else {
        panic!("expected RoutesReceived");
    };
    assert!(announced.is_empty());
    assert_eq!(withdrawn.len(), 2);
    assert!(withdrawn.contains(&(Prefix::V4(accepted_v4), 0)));
    assert!(withdrawn.contains(&(accepted_v6, 0)));
    assert_eq!(session.known_prefix_count(), 0);
    assert!(
        rib_rx.try_recv().is_err(),
        "first-seen rejects must stay silent"
    );

    let key = |prefix| ImportDecisionKey {
        afi: match prefix {
            Prefix::V4(_) => Afi::Ipv4,
            Prefix::V6(_) => Afi::Ipv6,
        },
        safi: Safi::Unicast,
        prefix,
        path_id: 0,
    };
    for prefix in [Prefix::V4(accepted_v4), accepted_v6] {
        match session
            .import_decision_cache
            .lookup(&key(prefix), session.import_policy_generation)
        {
            LookupResult::Hit(decision) => {
                assert_eq!(decision.outcome, CachedOutcome::Withdrawn);
            }
            other => panic!("expected OTC-withdrawn {prefix}, got {other:?}"),
        }
    }
    for prefix in [Prefix::V4(first_seen_v4), first_seen_v6] {
        assert!(matches!(
            session
                .import_decision_cache
                .lookup(&key(prefix), session.import_policy_generation),
            LookupResult::NotSeen
        ));
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
async fn otc_ingress_malformed_length_withdraws_a_real_accepted_replacement() {
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    session.config.peer.local_role = Some(BgpRole::Provider);
    install_test_negotiated_session(&mut session, negotiated_session(65002, false));
    let announced_prefix = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24);
    let overlap_prefix = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 0), 24);
    let accepted_attrs = vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath {
            segments: vec![AsPathSegment::AsSequence(vec![65002])],
        }),
        PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
    ];
    session
        .process_update(UpdateMessage::build(
            &[
                Ipv4NlriEntry {
                    path_id: 0,
                    prefix: announced_prefix,
                },
                Ipv4NlriEntry {
                    path_id: 0,
                    prefix: overlap_prefix,
                },
            ],
            &[],
            &accepted_attrs,
            true,
            false,
            Ipv4UnicastMode::Body,
        ))
        .await;
    let RibUpdate::RoutesReceived { announced, .. } = rib_rx.try_recv().unwrap() else {
        panic!("expected initial accepted route");
    };
    assert_eq!(announced.len(), 2);

    let malformed_attrs = vec![
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
        &[
            Ipv4NlriEntry {
                path_id: 0,
                prefix: announced_prefix,
            },
            Ipv4NlriEntry {
                path_id: 0,
                prefix: overlap_prefix,
            },
        ],
        &[Ipv4NlriEntry {
            path_id: 0,
            prefix: overlap_prefix,
        }],
        &malformed_attrs,
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
    assert_eq!(withdrawn.len(), 2);
    assert!(withdrawn.contains(&(Prefix::V4(announced_prefix), 0)));
    assert!(withdrawn.contains(&(Prefix::V4(overlap_prefix), 0)));
    assert_eq!(session.known_prefix_count(), 0);
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
        exact_export_snapshot: Some(session.publish_export_profile()),
        announce_source_exclusion: None,
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
        shared_group_encode: None,
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
        exact_export_snapshot: Some(session.publish_export_profile()),
        announce_source_exclusion: None,
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
        shared_group_encode: None,
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
        exact_export_snapshot: Some(session.publish_export_profile()),
        announce_source_exclusion: None,
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
        shared_group_encode: None,
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
        exact_export_snapshot: Some(session.publish_export_profile()),
        announce_source_exclusion: None,
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
        shared_group_encode: None,
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
        exact_export_snapshot: Some(session.publish_export_profile()),
        announce_source_exclusion: None,
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
        shared_group_encode: None,
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
        exact_export_snapshot: Some(session.publish_export_profile()),
        announce_source_exclusion: None,
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
        shared_group_encode: None,
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
        exact_export_snapshot: Some(session.publish_export_profile()),
        announce_source_exclusion: None,
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
        shared_group_encode: None,
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
        exact_export_snapshot: Some(session.publish_export_profile()),
        announce_source_exclusion: None,
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
        shared_group_encode: None,
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
/// Import policy is applied before `RoutesReceived` reaches the RIB. A
/// first-seen denial has no prior accepted identity, so it must produce
/// neither an announcement nor a synthetic withdrawal.
#[expect(
    clippy::too_many_lines,
    reason = "covers a mixed first-seen permit/deny batch and exact RIB payload assertions"
)]
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
    let mut all_withdrawn = vec![];
    while let Ok(msg) = rib_rx.try_recv() {
        if let RibUpdate::RoutesReceived {
            announced,
            withdrawn,
            ..
        } = msg
        {
            all_announced.extend(announced);
            all_withdrawn.extend(withdrawn);
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
    assert!(
        all_withdrawn.is_empty(),
        "a first-seen policy denial has no accepted route to withdraw"
    );
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
async fn denied_classic_replacement_withdraws_exact_route_and_remains_explainable() {
    use super::import_decision_cache::{CachedOutcome, ImportDecisionKey, LookupResult};

    let mut peer_config = PeerConfig::new(65001, 65002, Ipv4Addr::new(10, 0, 0, 1));
    peer_config.connect_retry_secs = 30;
    peer_config.families = vec![(Afi::Ipv4, Safi::Unicast)];
    peer_config.gr_restart_time = 120;
    let mut config = TransportConfig::new(peer_config, "10.0.0.2:179".parse().unwrap());
    config.explain_enabled = true;
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
        entries: vec![],
        default_action: PolicyAction::Deny,
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
    let RibUpdate::RoutesReceived {
        announced,
        withdrawn,
        ..
    } = rib_rx
        .try_recv()
        .expect("denied replacement must reach RIB")
    else {
        panic!("expected RoutesReceived");
    };
    assert!(announced.is_empty());
    assert_eq!(
        withdrawn,
        vec![(Prefix::V4(prefix), 0)],
        "a previously accepted classic NLRI denied on replacement must be withdrawn exactly"
    );
    assert_eq!(
        session.known_prefix_count(),
        0,
        "the denied replacement must retire max-prefix accounting"
    );
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
        LookupResult::Hit(decision) => assert_eq!(decision.outcome, CachedOutcome::Deny),
        other => panic!("expected the replacement Deny to remain explainable, got {other:?}"),
    }
}

/// A denied MP-unicast replacement retires only its exact RFC 7911 identity.
/// An explicit `MP_UNREACH` for another denied identity in the same UPDATE must
/// not be duplicated, and an untouched sibling path must remain accepted.
#[expect(
    clippy::too_many_lines,
    reason = "covers MP Add-Path replacement, overlap deduplication, sibling retention, and explain outcomes"
)]
#[tokio::test]
async fn denied_mp_add_path_replacements_preserve_sibling_and_deduplicate_overlap() {
    use super::import_decision_cache::{CachedOutcome, ImportDecisionKey, LookupResult};
    use rustbgpd_wire::{MpReachNlri, MpUnreachNlri, NlriEntry};

    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    let mut negotiated = negotiated_session(65002, false);
    negotiated.negotiated_families = vec![(Afi::Ipv6, Safi::Unicast)];
    negotiated
        .add_path_families
        .insert((Afi::Ipv6, Safi::Unicast), AddPathMode::Both);
    install_test_negotiated_session(&mut session, negotiated);

    let prefix = Prefix::V6(Ipv6Prefix::new("2001:db8:439::".parse().unwrap(), 64));
    let nlri = |path_id| NlriEntry { path_id, prefix };
    let base_attrs = || {
        vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath {
                segments: vec![AsPathSegment::AsSequence(vec![65002])],
            }),
        ]
    };

    let mut attrs = base_attrs();
    attrs.push(PathAttribute::MpReachNlri(MpReachNlri {
        afi: Afi::Ipv6,
        safi: Safi::Unicast,
        next_hop: "2001:db8::2".parse().unwrap(),
        link_local_next_hop: None,
        announced: vec![nlri(11), nlri(22), nlri(33)],
        flowspec_announced: vec![],
        evpn_announced: vec![],
        bgpls_announced: vec![],
        labeled_announced: vec![],
        vpn_announced: vec![],
        rtc_announced: vec![],
    }));
    session
        .process_update(UpdateMessage::build(
            &[],
            &[],
            &attrs,
            true,
            true,
            Ipv4UnicastMode::Body,
        ))
        .await;
    let RibUpdate::RoutesReceived { announced, .. } =
        rib_rx.try_recv().expect("initial paths must reach RIB")
    else {
        panic!("expected RoutesReceived");
    };
    assert_eq!(announced.len(), 3);

    session.install_import_policy(Some(PolicyChain::new(vec![Policy {
        entries: vec![],
        default_action: PolicyAction::Deny,
    }])));

    let mut replacement_attrs = base_attrs();
    replacement_attrs.push(PathAttribute::MpReachNlri(MpReachNlri {
        afi: Afi::Ipv6,
        safi: Safi::Unicast,
        next_hop: "2001:db8::3".parse().unwrap(),
        link_local_next_hop: None,
        announced: vec![nlri(11), nlri(22)],
        flowspec_announced: vec![],
        evpn_announced: vec![],
        bgpls_announced: vec![],
        labeled_announced: vec![],
        vpn_announced: vec![],
        rtc_announced: vec![],
    }));
    replacement_attrs.push(PathAttribute::MpUnreachNlri(MpUnreachNlri {
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
            &replacement_attrs,
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
        .expect("denied replacements must reach RIB as withdrawals")
    else {
        panic!("expected RoutesReceived");
    };
    assert!(announced.is_empty());
    withdrawn.sort_unstable_by_key(|(_, path_id)| *path_id);
    assert_eq!(withdrawn, vec![(prefix, 11), (prefix, 22)]);
    assert!(!session.known_paths.contains(&(prefix, 11)));
    assert!(!session.known_paths.contains(&(prefix, 22)));
    assert!(session.known_paths.contains(&(prefix, 33)));
    assert_eq!(session.known_prefix_count(), 1);

    let decision = |path_id| ImportDecisionKey {
        afi: Afi::Ipv6,
        safi: Safi::Unicast,
        prefix,
        path_id,
    };
    match session
        .import_decision_cache
        .lookup(&decision(11), session.import_policy_generation)
    {
        LookupResult::Hit(entry) => assert_eq!(entry.outcome, CachedOutcome::Deny),
        other => panic!("expected synthetic withdrawal to preserve Deny, got {other:?}"),
    }
    match session
        .import_decision_cache
        .lookup(&decision(22), session.import_policy_generation)
    {
        LookupResult::Hit(entry) => assert_eq!(entry.outcome, CachedOutcome::Withdrawn),
        other => panic!("expected explicit withdrawal tombstone, got {other:?}"),
    }
}

/// End-to-end ERR/GR + import-policy interaction: a denied replacement must
/// remove the accepted route immediately, before `EoRR`, so neither refresh nor
/// subsequent graceful-restart retention can keep it alive.
#[expect(
    clippy::too_many_lines,
    reason = "regression test pins denied replacement removal across ERR and GR boundaries"
)]
#[tokio::test]
async fn denied_replacement_is_removed_before_eorr_and_cannot_survive_gr() {
    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let (rib_tx, rib_rx) = mpsc::channel(64);
    let (_, query_rx) = mpsc::channel(1);
    let manager = rustbgpd_rib::RibManager::new(rib_rx, query_rx, None, None, BgpMetrics::new());
    let manager_handle = tokio::spawn(manager.run());
    let denied_prefix = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 0), 24);
    let mut peer_config = PeerConfig::new(65001, 65002, Ipv4Addr::new(10, 0, 0, 1));
    peer_config.connect_retry_secs = 30;
    peer_config.families = vec![(Afi::Ipv4, Safi::Unicast)];
    peer_config.gr_restart_time = 120;
    let config = TransportConfig::new(peer_config, "10.0.0.2:179".parse().unwrap());
    let metrics = BgpMetrics::new();
    let (_cmd_tx, cmd_rx) = mpsc::channel(8);
    let mut session = PeerSession::new(
        config,
        metrics,
        cmd_rx,
        rib_tx.clone(),
        None,
        None,
        None,
        None,
        None,
        false,
    );
    let mut negotiated = negotiated_session(65002, false);
    negotiated.peer_route_refresh = true;
    negotiated.peer_enhanced_route_refresh = true;
    negotiated.peer_gr_capable = true;
    negotiated.peer_restart_time = 120;
    negotiated.peer_gr_families = vec![rustbgpd_wire::GracefulRestartFamily {
        afi: Afi::Ipv4,
        safi: Safi::Unicast,
        forwarding_preserved: false,
    }];
    install_test_negotiated_session(&mut session, negotiated);
    session.config.peer.graceful_restart = true;
    let attrs = vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath {
            segments: vec![AsPathSegment::AsSequence(vec![65002])],
        }),
        PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
    ];
    let accepted = UpdateMessage::build(
        &[Ipv4NlriEntry {
            path_id: 0,
            prefix: denied_prefix,
        }],
        &[],
        &attrs,
        true,
        false,
        Ipv4UnicastMode::Body,
    );
    session.process_update(accepted.clone()).await;
    assert_eq!(session.known_prefix_count(), 1);
    let (reply_tx, reply_rx) = oneshot::channel();
    rib_tx
        .send(RibUpdate::QueryReceivedRoutes {
            peer: Some(peer),
            reply: reply_tx,
        })
        .await
        .unwrap();
    let initially_received = reply_rx.await.unwrap();
    assert_eq!(initially_received.len(), 1);
    assert_eq!(initially_received[0].prefix, Prefix::V4(denied_prefix));

    buffer_route_refresh(
        &mut session,
        Afi::Ipv4,
        Safi::Unicast,
        RouteRefreshSubtype::BoRR,
    );
    session.process_read_buffer().await;
    assert_eq!(
        session.refresh_accounting_stale_count((Afi::Ipv4, Safi::Unicast)),
        Some(1)
    );

    let deny_policy = PolicyChain::new(vec![Policy {
        entries: vec![],
        default_action: PolicyAction::Deny,
    }]);
    let (reply_tx, reply_rx) = oneshot::channel();
    assert_eq!(
        session
            .handle_command(PeerCommand::UpdateImportPolicy {
                policy: Some(deny_policy),
                reply: reply_tx,
            })
            .await,
        ControlFlow::Continue(())
    );
    assert_eq!(reply_rx.await.unwrap(), Ok(()));

    // Re-advertise the accepted identity inside ERR. The replacement now
    // evaluates Deny and must become an immediate exact withdrawal.
    session.process_update(accepted).await;
    assert_eq!(session.known_prefix_count(), 0);
    assert_eq!(
        session.refresh_accounting_stale_count((Afi::Ipv4, Safi::Unicast)),
        Some(0),
        "the synthetic withdrawal must retire the ERR stale identity"
    );

    // The denial itself must remove the old accepted route. Waiting for EoRR
    // would leave a policy-rejected route usable throughout a long refresh.
    let (reply_tx, reply_rx) = oneshot::channel();
    rib_tx
        .send(RibUpdate::QueryReceivedRoutes {
            peer: Some(peer),
            reply: reply_tx,
        })
        .await
        .unwrap();
    assert!(
        reply_rx.await.unwrap().is_empty(),
        "denied route must be absent before EoRR closes the refresh window"
    );

    // EoRR (including a duplicate) is now an idempotent boundary: there is no
    // denied route left to sweep locally or in the RIB.
    for _ in 0..2 {
        buffer_route_refresh(
            &mut session,
            Afi::Ipv4,
            Safi::Unicast,
            RouteRefreshSubtype::EoRR,
        );
        session.process_read_buffer().await;
    }
    assert_eq!(session.refresh_accounting_window_count(), 0);
    assert_eq!(session.known_prefix_count(), 0);

    // A subsequent GR teardown cannot mark the already removed route stale.
    session.execute_actions(vec![Action::SessionDown]).await;
    let (reply_tx, reply_rx) = oneshot::channel();
    rib_tx
        .send(RibUpdate::QueryReceivedRoutes {
            peer: Some(peer),
            reply: reply_tx,
        })
        .await
        .unwrap();
    assert!(reply_rx.await.unwrap().is_empty());
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

/// Negotiate IPv4+IPv6 unicast on an established fixture session.
fn install_dual_stack_session(session: &mut PeerSession, add_path: bool) {
    let mut negotiated = negotiated_session(65002, false);
    negotiated.negotiated_families = vec![(Afi::Ipv4, Safi::Unicast), (Afi::Ipv6, Safi::Unicast)];
    if add_path {
        negotiated
            .add_path_families
            .insert((Afi::Ipv4, Safi::Unicast), AddPathMode::Both);
    }
    install_test_negotiated_session(session, negotiated);
}

fn v6_prefix(index: u16) -> Ipv6Prefix {
    Ipv6Prefix::new(
        format!("2001:db8:{index:x}::").parse::<Ipv6Addr>().unwrap(),
        64,
    )
}

fn v4_prefix(index: u8) -> Ipv4Prefix {
    Ipv4Prefix::new(Ipv4Addr::new(203, 0, index, 0), 24)
}

/// Mutant: dropping the `max_prefixes_ipv4` check (or counting v6 into the
/// v4 budget) keeps the session up past the v4 bound; encoding the wrong
/// AFI/SAFI/bound corrupts the RFC 4486 Cease data.
#[tokio::test]
async fn per_family_max_prefix_limits_enforce_independently() {
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    let (client, mut server) = connected_stream_pair().await;
    session.test_install_stream(client);
    establish_test_session(&mut session, 65002).await;
    while rib_rx.try_recv().is_ok() {}
    session.config.max_prefixes_ipv4 = Some(2);
    session.config.max_prefixes_ipv6 = Some(1);
    install_dual_stack_session(&mut session, false);

    // v6 at its limit, v4 at its limit: both families full, session alive.
    session.process_update(ipv6_announce(v6_prefix(1), 0)).await;
    session
        .process_update(ipv4_announce(v4_prefix(1), 0, false))
        .await;
    session
        .process_update(ipv4_announce(v4_prefix(2), 0, false))
        .await;
    assert!(
        session.read_half.is_some(),
        "both families at their exact limits must not tear down"
    );
    assert_eq!(session.known_unicast_v4, 2);
    assert_eq!(session.known_unicast_v6, 1);

    // One more v4 route exceeds only the v4 bound.
    session
        .process_update(ipv4_announce(v4_prefix(3), 0, false))
        .await;
    assert!(
        session.read_half.is_none(),
        "exceeding the v4 bound must tear the session down"
    );
    let notif = read_until_notification(&mut server).await;
    assert_eq!(notif.code, NotificationCode::Cease);
    assert_eq!(notif.subcode, cease_subcode::MAX_PREFIXES);
    assert_eq!(
        notif.data.as_ref(),
        max_prefix_cease_data(Afi::Ipv4, Safi::Unicast, 2).as_slice(),
        "Cease/1 data must carry the exceeding family's AFI, SAFI, and bound"
    );
    // Session reset clears per-family accounting like the aggregate's.
    assert_eq!(session.known_unicast_v4, 0);
    assert_eq!(session.known_unicast_v6, 0);
    assert_eq!(session.known_prefix_count(), 0);
}

/// Mutant: charging v6 unicast routes against `max_prefixes_ipv4` (a single
/// shared counter) tears down before the v4 family used any of its budget.
#[tokio::test]
async fn one_family_cannot_consume_the_other_families_budget() {
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    let (client, mut server) = connected_stream_pair().await;
    session.test_install_stream(client);
    establish_test_session(&mut session, 65002).await;
    while rib_rx.try_recv().is_ok() {}
    session.config.max_prefixes_ipv4 = Some(10);
    install_dual_stack_session(&mut session, false);

    for index in 1..=10 {
        session
            .process_update(ipv6_announce(v6_prefix(index), 0))
            .await;
    }
    assert!(
        session.read_half.is_some(),
        "unlimited v6 routes must not consume the v4 budget"
    );
    for index in 1..=10 {
        session
            .process_update(ipv4_announce(v4_prefix(index), 0, false))
            .await;
    }
    assert!(
        session.read_half.is_some(),
        "v4 must retain its full headroom after 10 v6 routes"
    );
    session
        .process_update(ipv4_announce(v4_prefix(11), 0, false))
        .await;
    assert!(
        session.read_half.is_none(),
        "11th v4 route exceeds the bound"
    );
    let notif = read_until_notification(&mut server).await;
    assert_eq!(notif.subcode, cease_subcode::MAX_PREFIXES);
    assert_eq!(
        notif.data.as_ref(),
        max_prefix_cease_data(Afi::Ipv4, Safi::Unicast, 10).as_slice()
    );
}

/// Mutant: counting Add-Path multiplicity (paths instead of unique prefixes)
/// against the per-family bound diverges from the aggregate's pinned
/// unique-prefix semantics and tears down on the first UPDATE.
#[tokio::test]
async fn per_family_limit_counts_unique_prefixes_under_add_path() {
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    let (client, mut server) = connected_stream_pair().await;
    session.test_install_stream(client);
    establish_test_session(&mut session, 65002).await;
    while rib_rx.try_recv().is_ok() {}
    session.config.max_prefixes_ipv4 = Some(1);
    install_dual_stack_session(&mut session, true);

    let prefix = v4_prefix(1);
    session.process_update(ipv4_announce(prefix, 1, true)).await;
    session.process_update(ipv4_announce(prefix, 2, true)).await;
    assert!(
        session.read_half.is_some(),
        "two Add-Path IDs of one prefix count once against the per-family bound"
    );
    assert_eq!(session.known_unicast_v4, 1);

    session
        .process_update(ipv4_announce(v4_prefix(2), 3, true))
        .await;
    assert!(session.read_half.is_none());
    let notif = read_until_notification(&mut server).await;
    assert_eq!(notif.subcode, cease_subcode::MAX_PREFIXES);
    assert_eq!(
        notif.data.as_ref(),
        max_prefix_cease_data(Afi::Ipv4, Safi::Unicast, 1).as_slice()
    );
}

/// Mutant: double-counting a duplicate announcement, or failing to decrement
/// on withdrawal, falsely trips the bound at the boundary.
#[tokio::test]
async fn per_family_boundary_survives_duplicates_and_withdraw_reannounce() {
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    let (client, mut server) = connected_stream_pair().await;
    session.test_install_stream(client);
    establish_test_session(&mut session, 65002).await;
    while rib_rx.try_recv().is_ok() {}
    session.config.max_prefixes_ipv4 = Some(2);
    install_dual_stack_session(&mut session, false);

    session
        .process_update(ipv4_announce(v4_prefix(1), 0, false))
        .await;
    session
        .process_update(ipv4_announce(v4_prefix(2), 0, false))
        .await;
    // Duplicate announcement at the boundary must not double-count.
    session
        .process_update(ipv4_announce(v4_prefix(2), 0, false))
        .await;
    assert!(
        session.read_half.is_some(),
        "duplicate announcement at the bound must not tear down"
    );
    assert_eq!(session.known_unicast_v4, 2);

    // Withdrawal frees budget for a re-announcement at the boundary.
    session
        .process_update(ipv4_withdraw(v4_prefix(1), 0, false))
        .await;
    assert_eq!(session.known_unicast_v4, 1);
    session
        .process_update(ipv4_announce(v4_prefix(3), 0, false))
        .await;
    assert!(
        session.read_half.is_some(),
        "withdraw-then-announce at the bound must not tear down"
    );

    session
        .process_update(ipv4_announce(v4_prefix(4), 0, false))
        .await;
    assert!(session.read_half.is_none(), "one past the bound tears down");
    let notif = read_until_notification(&mut server).await;
    assert_eq!(notif.subcode, cease_subcode::MAX_PREFIXES);
}

/// Mutant: sweeping ERR stale plain prefixes without decrementing the
/// per-family counter leaves phantom v4 budget consumption; the post-EoRR
/// announcement then falsely exceeds `max_prefixes_ipv4`. Mirrors the
/// aggregate's `eorr_reconciles_omitted_prefix_before_later_max_prefix_check`.
#[tokio::test]
async fn eorr_reconciles_per_family_accounting_before_later_check() {
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    install_enhanced_refresh_session(&mut session, vec![(Afi::Ipv4, Safi::Unicast)], false);
    session.config.max_prefixes_ipv4 = Some(2);
    let replayed = v4_prefix(1);
    let omitted = v4_prefix(2);
    session.remember_known_path(Prefix::V4(replayed), 0);
    session.remember_known_path(Prefix::V4(omitted), 0);
    assert_eq!(session.known_unicast_v4, 2);

    buffer_route_refresh(
        &mut session,
        Afi::Ipv4,
        Safi::Unicast,
        RouteRefreshSubtype::BoRR,
    );
    session.process_read_buffer().await;
    assert!(matches!(
        rib_rx.try_recv(),
        Ok(RibUpdate::BeginRouteRefresh { .. })
    ));
    session
        .process_update(ipv4_announce(replayed, 0, false))
        .await;
    assert!(matches!(
        rib_rx.try_recv(),
        Ok(RibUpdate::RoutesReceived { .. })
    ));
    buffer_route_refresh(
        &mut session,
        Afi::Ipv4,
        Safi::Unicast,
        RouteRefreshSubtype::EoRR,
    );
    session.process_read_buffer().await;
    assert!(matches!(
        rib_rx.try_recv(),
        Ok(RibUpdate::EndRouteRefresh { .. })
    ));
    assert_eq!(
        session.known_unicast_v4, 1,
        "EoRR sweep must release the omitted prefix's per-family budget"
    );

    session
        .process_update(ipv4_announce(v4_prefix(3), 0, false))
        .await;
    assert!(
        matches!(rib_rx.try_recv(), Ok(RibUpdate::RoutesReceived { .. })),
        "post-EoRR announcement within the reconciled bound must be accepted"
    );
    assert_eq!(session.known_unicast_v4, 2);
}

/// Mutant: dropping the immediate evaluation on `UpdateRuntimeConfig` leaves
/// a quiet peer holding more routes than the operator's new per-family bound
/// until its next UPDATE.
#[tokio::test]
async fn runtime_lowering_per_family_limit_enforces_immediately() {
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    let (client, mut server) = connected_stream_pair().await;
    session.test_install_stream(client);
    establish_test_session(&mut session, 65002).await;
    while rib_rx.try_recv().is_ok() {}
    install_dual_stack_session(&mut session, false);
    for index in 1..=3 {
        session
            .process_update(ipv4_announce(v4_prefix(index), 0, false))
            .await;
    }
    assert!(session.read_half.is_some());

    let (reply, done) = oneshot::channel();
    assert_eq!(
        session
            .handle_command(PeerCommand::UpdateRuntimeConfig {
                max_prefixes: None,
                max_prefixes_ipv4: Some(1),
                max_prefixes_ipv6: None,
                gr_stale_routes_time: 360,
                local_ipv6_nexthop: None,
                remove_private_as: RemovePrivateAs::Disabled,
                reply,
            })
            .await,
        ControlFlow::Continue(())
    );
    done.await.unwrap().unwrap();
    assert!(
        session.read_half.is_none(),
        "lowering max_prefixes_ipv4 below the current count must tear down immediately"
    );
    let notif = read_until_notification(&mut server).await;
    assert_eq!(notif.code, NotificationCode::Cease);
    assert_eq!(notif.subcode, cease_subcode::MAX_PREFIXES);
    assert_eq!(
        notif.data.as_ref(),
        max_prefix_cease_data(Afi::Ipv4, Safi::Unicast, 1).as_slice()
    );
}

/// Pins the aggregate's documented hot-apply semantics (ADR-0108): lowering
/// the legacy `max_prefixes` below the current count trips on the NEXT
/// received UPDATE, not on apply.
#[tokio::test]
async fn runtime_lowering_aggregate_limit_keeps_next_update_semantics() {
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    let (client, mut server) = connected_stream_pair().await;
    session.test_install_stream(client);
    establish_test_session(&mut session, 65002).await;
    while rib_rx.try_recv().is_ok() {}
    install_dual_stack_session(&mut session, false);
    session
        .process_update(ipv4_announce(v4_prefix(1), 0, false))
        .await;
    session
        .process_update(ipv4_announce(v4_prefix(2), 0, false))
        .await;

    let (reply, done) = oneshot::channel();
    assert_eq!(
        session
            .handle_command(PeerCommand::UpdateRuntimeConfig {
                max_prefixes: Some(1),
                max_prefixes_ipv4: None,
                max_prefixes_ipv6: None,
                gr_stale_routes_time: 360,
                local_ipv6_nexthop: None,
                remove_private_as: RemovePrivateAs::Disabled,
                reply,
            })
            .await,
        ControlFlow::Continue(())
    );
    done.await.unwrap().unwrap();
    assert!(
        session.read_half.is_some(),
        "aggregate lowering must not enforce until the next UPDATE"
    );

    session
        .process_update(ipv4_announce(v4_prefix(3), 0, false))
        .await;
    assert!(session.read_half.is_none());
    let notif = read_until_notification(&mut server).await;
    assert_eq!(notif.subcode, cease_subcode::MAX_PREFIXES);
    assert!(
        notif.data.is_empty(),
        "aggregate Cease/1 keeps its historical empty data"
    );
}

/// Regression pin: with only the legacy aggregate configured, behavior is
/// unchanged — teardown at the same point, empty NOTIFICATION data.
#[tokio::test]
async fn aggregate_max_prefix_alone_behaves_as_before() {
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    let (client, mut server) = connected_stream_pair().await;
    session.test_install_stream(client);
    establish_test_session(&mut session, 65002).await;
    while rib_rx.try_recv().is_ok() {}
    session.config.max_prefixes = Some(2);
    install_dual_stack_session(&mut session, false);

    session
        .process_update(ipv4_announce(v4_prefix(1), 0, false))
        .await;
    session.process_update(ipv6_announce(v6_prefix(1), 0)).await;
    assert!(session.read_half.is_some(), "at the aggregate bound: alive");
    session.process_update(ipv6_announce(v6_prefix(2), 0)).await;
    assert!(
        session.read_half.is_none(),
        "aggregate counts across families exactly as before"
    );
    let notif = read_until_notification(&mut server).await;
    assert_eq!(notif.code, NotificationCode::Cease);
    assert_eq!(notif.subcode, cease_subcode::MAX_PREFIXES);
    assert!(notif.data.is_empty(), "aggregate Cease/1 data stays empty");
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
#[derive(Clone, Copy, Debug)]
enum NonUnicastSafetyLoop {
    AsPath,
    Originator,
}

fn nonunicast_safety_session(
    family: (Afi, Safi),
    add_path: bool,
    trigger: NonUnicastSafetyLoop,
) -> (PeerSession, mpsc::Receiver<RibUpdate>) {
    let remote_asn = match trigger {
        NonUnicastSafetyLoop::AsPath => 65002,
        NonUnicastSafetyLoop::Originator => 65001,
    };
    let (mut session, rib_rx) = make_test_session_with_rib(65001, remote_asn);
    let mut negotiated = negotiated_session(remote_asn, false);
    negotiated.negotiated_families = vec![family];
    if add_path {
        negotiated
            .add_path_families
            .insert(family, AddPathMode::Both);
    }
    negotiated.peer_route_refresh = true;
    negotiated.peer_enhanced_route_refresh = true;
    install_test_negotiated_session(&mut session, negotiated);
    (session, rib_rx)
}

fn nonunicast_accepted_attrs() -> Vec<PathAttribute> {
    vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath {
            segments: vec![AsPathSegment::AsSequence(vec![65002])],
        }),
    ]
}

fn nonunicast_safety_attrs(
    session: &PeerSession,
    trigger: NonUnicastSafetyLoop,
) -> Vec<PathAttribute> {
    let mut attrs = vec![PathAttribute::Origin(Origin::Igp)];
    match trigger {
        NonUnicastSafetyLoop::AsPath => attrs.push(PathAttribute::AsPath(AsPath {
            segments: vec![AsPathSegment::AsSequence(vec![65002, 65001])],
        })),
        NonUnicastSafetyLoop::Originator => {
            attrs.push(PathAttribute::AsPath(AsPath { segments: vec![] }));
            attrs.push(PathAttribute::OriginatorId(
                session.config.peer.local_router_id,
            ));
        }
    }
    attrs
}

fn empty_nonunicast_reach(afi: Afi, safi: Safi, next_hop: IpAddr) -> rustbgpd_wire::MpReachNlri {
    rustbgpd_wire::MpReachNlri {
        afi,
        safi,
        next_hop,
        link_local_next_hop: None,
        announced: vec![],
        flowspec_announced: vec![],
        evpn_announced: vec![],
        bgpls_announced: vec![],
        labeled_announced: vec![],
        vpn_announced: vec![],
        rtc_announced: vec![],
    }
}

fn empty_nonunicast_unreach(afi: Afi, safi: Safi) -> rustbgpd_wire::MpUnreachNlri {
    rustbgpd_wire::MpUnreachNlri {
        afi,
        safi,
        withdrawn: vec![],
        flowspec_withdrawn: vec![],
        evpn_withdrawn: vec![],
        bgpls_withdrawn: vec![],
        labeled_withdrawn: vec![],
        vpn_withdrawn: vec![],
        rtc_withdrawn: vec![],
    }
}

fn nonunicast_update(
    mut attrs: Vec<PathAttribute>,
    reach: rustbgpd_wire::MpReachNlri,
    unreach: Option<rustbgpd_wire::MpUnreachNlri>,
    add_path: bool,
) -> UpdateMessage {
    attrs.push(PathAttribute::MpReachNlri(reach));
    if let Some(unreach) = unreach {
        attrs.push(PathAttribute::MpUnreachNlri(unreach));
    }
    UpdateMessage::build(&[], &[], &attrs, true, add_path, Ipv4UnicastMode::Body)
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
    let exact_export_snapshot: Arc<dyn rustbgpd_rib::ExactExportSnapshot> =
        session.publish_export_profile();
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
        update.exact_export_snapshot = Some(Arc::clone(&exact_export_snapshot));
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

// ===========================================================================
// Shared-group encode invariant regressions: per-source chunk integrity,
// override alignment under the source sort, live-encoder streaming, and the
// wire-equivalence normalization boundary.
// ===========================================================================

/// Read UPDATEs until `expected_prefixes` announced prefixes were seen and
/// map each prefix to the exact (ordered) attribute list of its UPDATE.
async fn shared_group_read_prefix_attr_map(
    stream: &mut TcpStream,
    expected_prefixes: usize,
) -> std::collections::BTreeMap<String, Vec<String>> {
    let mut map = std::collections::BTreeMap::new();
    let mut seen = 0_usize;
    while seen < expected_prefixes {
        let msg = tokio::time::timeout(Duration::from_secs(5), read_single_bgp_message(stream))
            .await
            .expect("wire read timed out");
        let Message::Update(message) = msg else {
            panic!("expected UPDATE");
        };
        let parsed = message.parse(true, false, &[]).unwrap();
        let attrs: Vec<String> = parsed
            .attributes
            .iter()
            .map(|attr| format!("{attr:?}"))
            .collect();
        for nlri in &parsed.announced {
            map.insert(nlri.prefix.to_string(), attrs.clone());
            seen += 1;
        }
    }
    map
}

/// Two different source peers whose routes carry a pointer-identical
/// attribute `Arc` (the shape global attribute interning produces) must
/// still land in distinct per-source chunks. If the shared group key ever
/// merged them, split horizon would compose wrongly: the excluded member
/// would either lose the other source's route (silent under-advertise) or
/// receive its own route back (leak).
#[tokio::test]
async fn shared_group_interned_attrs_across_sources_never_merge_chunks() {
    let shared_attrs = Arc::new(vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath {
            segments: vec![AsPathSegment::AsSequence(vec![64_601])],
        }),
        PathAttribute::NextHop(Ipv4Addr::new(10, 40, 0, 9)),
    ]);
    let source_a = Ipv4Addr::new(10, 40, 0, 1);
    let source_b = Ipv4Addr::new(10, 40, 0, 2);
    let source_c = Ipv4Addr::new(10, 40, 0, 3);
    let prefix_a = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24);
    let prefix_b = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 0), 24);
    let prefix_c = Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, 0), 24);
    let route_a = Route {
        prefix: Prefix::V4(prefix_a),
        peer: IpAddr::V4(source_a),
        next_hop: IpAddr::V4(Ipv4Addr::new(10, 40, 0, 9)),
        attributes: Arc::clone(&shared_attrs),
        ..make_route(100)
    };
    let route_b = Route {
        prefix: Prefix::V4(prefix_b),
        peer: IpAddr::V4(source_b),
        next_hop: IpAddr::V4(Ipv4Addr::new(10, 40, 0, 9)),
        attributes: Arc::clone(&shared_attrs),
        ..make_route(100)
    };
    let route_c = make_sourced_route(source_c, prefix_c, 64_603);
    let announce = vec![route_a, route_b, route_c];
    let shared = Arc::new(rustbgpd_rib::SharedGroupEncode::default());

    let (mut member_a, mut wire_a) = shared_group_member(65001).await;
    let update = shared_group_envelope(&member_a, &shared, source_a, &announce);
    member_a.handle_outbound_route_update(update).await;
    let (chunk_count, terminal) = shared
        .cell
        .get()
        .unwrap()
        .downcast_ref::<super::shared_group::ProgressiveUnicastEncode>()
        .unwrap()
        .test_snapshot();
    assert_eq!(
        terminal,
        Some(super::shared_group::StreamTerminal::Complete)
    );
    assert_eq!(
        chunk_count, 3,
        "pointer-identical attrs across two sources must still yield two distinct chunks"
    );
    let map_a = shared_group_read_prefix_attr_map(&mut wire_a, 2).await;
    assert_eq!(
        map_a
            .keys()
            .cloned()
            .collect::<std::collections::BTreeSet<_>>(),
        [prefix_b.to_string(), prefix_c.to_string()].into(),
        "member A: everything except its own source, despite interned attrs"
    );

    let (mut member_b, mut wire_b) = shared_group_member(65001).await;
    let update = shared_group_envelope(&member_b, &shared, source_b, &announce);
    member_b.handle_outbound_route_update(update).await;
    let map_b = shared_group_read_prefix_attr_map(&mut wire_b, 2).await;
    assert_eq!(
        map_b
            .keys()
            .cloned()
            .collect::<std::collections::BTreeSet<_>>(),
        [prefix_a.to_string(), prefix_c.to_string()].into(),
        "member B: everything except its own source"
    );

    // Ordinary-path reference with an identical profile: same envelope, no
    // cell. The shared bytes must be attribute-identical per prefix.
    let (mut member_r, mut wire_r) = shared_group_member(65001).await;
    let mut reference = shared_group_envelope(&member_r, &shared, source_b, &announce);
    reference.shared_group_encode = None;
    member_r.handle_outbound_route_update(reference).await;
    let map_r = shared_group_read_prefix_attr_map(&mut wire_r, 2).await;
    assert_eq!(
        map_b, map_r,
        "shared stream must be attribute-identical to the ordinary per-session encode"
    );
}

/// The encoder walks the inventory through a source-sorted index while
/// `next_hop_override` stays parallel to the ORIGINAL announce order. If
/// the encoder ever indexed the overrides by sorted position, an override
/// would land on the wrong prefix — a silent wrong next hop on the wire.
#[tokio::test]
async fn shared_group_nh_override_alignment_survives_source_sort() {
    // Original order deliberately unsorted by source so the sorted index
    // walk permutes positions: sources .3, .1, .2.
    let prefix_0 = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24);
    let prefix_1 = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 0), 24);
    let prefix_2 = Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, 0), 24);
    let announce = vec![
        make_sourced_route(Ipv4Addr::new(10, 41, 0, 3), prefix_0, 64_603),
        make_sourced_route(Ipv4Addr::new(10, 41, 0, 1), prefix_1, 64_601),
        make_sourced_route(Ipv4Addr::new(10, 41, 0, 2), prefix_2, 64_602),
    ];
    let overrides: Vec<Option<rustbgpd_policy::NextHopAction>> =
        vec![None, Some(rustbgpd_policy::NextHopAction::Self_), None];
    let excluded = Ipv4Addr::new(10, 41, 0, 9);
    let shared = Arc::new(rustbgpd_rib::SharedGroupEncode::default());

    let (mut member, mut wire) = shared_group_member(65001).await;
    let mut update = shared_group_envelope(&member, &shared, excluded, &announce);
    update.next_hop_override = overrides.clone().into();
    member.handle_outbound_route_update(update).await;
    let map_shared = shared_group_read_prefix_attr_map(&mut wire, 3).await;

    let self_hop = format!("{:?}", PathAttribute::NextHop(Ipv4Addr::LOCALHOST));
    assert!(
        map_shared[&prefix_1.to_string()].contains(&self_hop),
        "override at original index 1 must produce next-hop-self on prefix_1; got {:?}",
        map_shared[&prefix_1.to_string()]
    );
    assert!(
        map_shared[&prefix_0.to_string()].contains(&format!(
            "{:?}",
            PathAttribute::NextHop(Ipv4Addr::new(10, 41, 0, 3))
        )),
        "prefix_0 keeps its source next hop"
    );
    assert!(
        map_shared[&prefix_2.to_string()].contains(&format!(
            "{:?}",
            PathAttribute::NextHop(Ipv4Addr::new(10, 41, 0, 2))
        )),
        "prefix_2 keeps its source next hop"
    );

    // Attribute-equivalence against the ordinary path with the same
    // overrides.
    let (mut member_r, mut wire_r) = shared_group_member(65001).await;
    let mut reference = shared_group_envelope(&member_r, &shared, excluded, &announce);
    reference.next_hop_override = overrides.into();
    reference.shared_group_encode = None;
    member_r.handle_outbound_route_update(reference).await;
    let map_r = shared_group_read_prefix_attr_map(&mut wire_r, 3).await;
    assert_eq!(map_shared, map_r);
}

/// A consumer that starts streaming BEFORE the encoder has published
/// anything must observe every later slice and the terminal, with
/// publications racing its notify loop (lost-wakeup / stale-snapshot
/// regression guard).
#[tokio::test]
async fn shared_group_consumer_streams_concurrently_with_live_encoder() {
    use super::shared_group::{ProgressiveUnicastEncode, StreamTerminal};
    let source_a = Ipv4Addr::new(10, 42, 0, 1);
    let source_b = Ipv4Addr::new(10, 42, 0, 2);
    let prefix_a = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24);
    let prefix_b = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 0), 24);
    let announce = vec![
        make_sourced_route(source_a, prefix_a, 64_601),
        make_sourced_route(source_b, prefix_b, 64_602),
    ];
    let (member, mut wire) = shared_group_member(65001).await;
    let profile = (*member.publish_export_profile()).clone();
    let mut cache = super::export::PreparedAttrCache::default();
    let slice_1 = super::shared_group::encode_shared_unicast_slice(
        &profile,
        &mut cache,
        &announce,
        &[None, None],
        &[0],
    )
    .unwrap();
    let slice_2 = super::shared_group::encode_shared_unicast_slice(
        &profile,
        &mut cache,
        &announce,
        &[None, None],
        &[1],
    )
    .unwrap();
    let typed = Arc::new(ProgressiveUnicastEncode::test_new(profile));
    let shared = Arc::new(rustbgpd_rib::SharedGroupEncode::default());
    assert!(
        shared
            .cell
            .set(Arc::clone(&typed) as Arc<dyn std::any::Any + Send + Sync>)
            .is_ok()
    );
    let update = shared_group_envelope(&member, &shared, Ipv4Addr::new(10, 42, 0, 9), &announce);
    let mut member = member;
    let consumer = tokio::spawn(async move {
        member.handle_outbound_route_update(update).await;
    });
    // Publish while the consumer is (very likely) parked on the notify.
    tokio::time::sleep(Duration::from_millis(50)).await;
    typed.test_publish(slice_1);
    tokio::time::sleep(Duration::from_millis(50)).await;
    typed.test_publish(slice_2);
    typed.test_finish(StreamTerminal::Complete);
    tokio::time::timeout(Duration::from_secs(5), consumer)
        .await
        .expect("consumer must terminate once the stream completes")
        .unwrap();
    let map = shared_group_read_prefix_attr_map(&mut wire, 2).await;
    assert_eq!(
        map.keys().cloned().collect::<Vec<_>>(),
        {
            let mut v = vec![prefix_a.to_string(), prefix_b.to_string()];
            v.sort();
            v
        },
        "both progressively published slices reach the wire, none skipped"
    );
}

/// The wire-equivalence proof must ignore ONLY byte-inert fields. Extended
/// Messages changes the negotiated ceiling but never the bytes of a
/// 4096-fitting message (shared chunks are encoded at the standard
/// ceiling), so it must NOT break sharing; Add-Path send changes NLRI
/// framing and MUST break it.
#[tokio::test]
async fn shared_group_wire_equivalence_proof_ignores_only_byte_inert_fields() {
    let (a, _wire_a) = shared_group_member(65001).await;
    let (mut b, _wire_b) = shared_group_member(65001).await;
    b.negotiated.as_mut().unwrap().peer_extended_message = true;
    let profile_a = a.publish_export_profile();
    let profile_b = b.publish_export_profile();
    assert!(
        profile_a.has_same_wire_encoding(&profile_b),
        "extended-message ceiling is byte-inert at the shared 4096 ceiling"
    );
    let (mut c, _wire_c) = shared_group_member(65001).await;
    c.negotiated
        .as_mut()
        .unwrap()
        .add_path_families
        .insert((Afi::Ipv4, Safi::Unicast), AddPathMode::Send);
    let profile_c = c.publish_export_profile();
    assert!(
        !profile_a.has_same_wire_encoding(&profile_c),
        "Add-Path send changes NLRI bytes and must break the proof"
    );
}

/// ADR-0107 strict-peer `NEXT_HOP` ownership, classic IPv4 body NLRI: a
/// conforming next-hop (the session's own address) is accepted; a foreign
/// next-hop is rejected pre-policy — withdrawals from the same UPDATE
/// still flow, a previously accepted identity is retired treat-as-withdraw
/// style, and a first-seen rejection stays silent. The spoofed UPDATE
/// carries RFC 7999 BLACKHOLE, pinning ADR-0107 §5: a community is never
/// an ownership bypass.
#[tokio::test]
async fn strict_peer_next_hop_rejects_foreign_ipv4_body_and_withdraws_replacement() {
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    session.config.next_hop_ownership_strict_peer = true;
    session.negotiated = Some(negotiated_session(65002, false));
    let accepted = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 0), 24);
    let first_seen = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24);
    let withdrawn_prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, 0), 24);
    let attrs = |next_hop: Ipv4Addr, blackhole: bool| {
        let mut attrs = vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath {
                segments: vec![AsPathSegment::AsSequence(vec![65002])],
            }),
            PathAttribute::NextHop(next_hop),
        ];
        if blackhole {
            // RFC 7999 BLACKHOLE (65535:666).
            attrs.push(PathAttribute::Communities(vec![0xFFFF_029A]));
        }
        attrs
    };
    // Conforming: the wire next-hop is the advertising session's address.
    session
        .process_update(UpdateMessage::build(
            &[Ipv4NlriEntry {
                path_id: 0,
                prefix: accepted,
            }],
            &[],
            &attrs(Ipv4Addr::new(10, 0, 0, 2), false),
            true,
            false,
            Ipv4UnicastMode::Body,
        ))
        .await;
    let RibUpdate::RoutesReceived { announced, .. } = rib_rx.try_recv().unwrap() else {
        panic!("expected RoutesReceived");
    };
    assert_eq!(
        announced.len(),
        1,
        "conforming next-hop must be accepted under strict_peer"
    );
    // Foreign next-hop (another member's address) + BLACKHOLE: rejected
    // pre-policy; the accepted identity is withdrawn, the first-seen one
    // stays silent, and the explicit withdrawal is preserved.
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
            &[Ipv4NlriEntry {
                path_id: 0,
                prefix: withdrawn_prefix,
            }],
            &attrs(Ipv4Addr::new(10, 0, 0, 9), true),
            true,
            false,
            Ipv4UnicastMode::Body,
        ))
        .await;
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
        "foreign next-hop must be rejected even with BLACKHOLE attached"
    );
    assert_eq!(withdrawn.len(), 2);
    assert!(withdrawn.contains(&(Prefix::V4(withdrawn_prefix), 0)));
    assert!(
        withdrawn.contains(&(Prefix::V4(accepted), 0)),
        "rejected replacement must retire the exact prior identity"
    );
    assert!(
        !withdrawn.contains(&(Prefix::V4(first_seen), 0)),
        "first-seen rejections must stay silent"
    );
    assert_eq!(session.known_prefix_count(), 0);
}

/// ADR-0107 strict-peer over MP IPv6 unicast: a conforming global
/// next-hop is accepted; a foreign one is rejected with exact replacement
/// withdrawal and explain tombstones (mirrors the OTC sibling test).
#[expect(
    clippy::too_many_lines,
    reason = "pins conforming acceptance, foreign rejection, replacement withdrawal, first-seen gating, and explain tombstones in one flow"
)]
#[tokio::test]
async fn strict_peer_next_hop_rejects_foreign_ipv6_mp_and_withdraws_replacement() {
    use super::import_decision_cache::{CachedOutcome, ImportDecisionKey, LookupResult};
    use rustbgpd_wire::{MpReachNlri, NlriEntry};

    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    session.config.next_hop_ownership_strict_peer = true;
    session.import_explain_enabled = true;
    session.peer_ip = "2001:db8::2".parse().unwrap();
    let mut negotiated = negotiated_session(65002, false);
    negotiated.negotiated_families = vec![(Afi::Ipv6, Safi::Unicast)];
    install_test_negotiated_session(&mut session, negotiated);
    let accepted = Prefix::V6(Ipv6Prefix::new("2001:db8:473:1::".parse().unwrap(), 64));
    let first_seen = Prefix::V6(Ipv6Prefix::new("2001:db8:473:2::".parse().unwrap(), 64));
    let attrs = |next_hop: &str, announced: Vec<NlriEntry>| {
        vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath {
                segments: vec![AsPathSegment::AsSequence(vec![65002])],
            }),
            PathAttribute::MpReachNlri(MpReachNlri {
                afi: Afi::Ipv6,
                safi: Safi::Unicast,
                next_hop: next_hop.parse().unwrap(),
                link_local_next_hop: None,
                announced,
                flowspec_announced: vec![],
                evpn_announced: vec![],
                bgpls_announced: vec![],
                labeled_announced: vec![],
                vpn_announced: vec![],
                rtc_announced: vec![],
            }),
        ]
    };
    session
        .process_update(UpdateMessage::build(
            &[],
            &[],
            &attrs(
                "2001:db8::2",
                vec![NlriEntry {
                    path_id: 0,
                    prefix: accepted,
                }],
            ),
            true,
            false,
            Ipv4UnicastMode::Body,
        ))
        .await;
    let RibUpdate::RoutesReceived { announced, .. } = rib_rx.try_recv().unwrap() else {
        panic!("expected conforming MP route accepted");
    };
    assert_eq!(announced.len(), 1);

    session
        .process_update(UpdateMessage::build(
            &[],
            &[],
            &attrs(
                "2001:db8::99",
                vec![
                    NlriEntry {
                        path_id: 0,
                        prefix: accepted,
                    },
                    NlriEntry {
                        path_id: 0,
                        prefix: first_seen,
                    },
                ],
            ),
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
        .expect("accepted replacement must become a withdrawal")
    else {
        panic!("expected RoutesReceived");
    };
    assert!(announced.is_empty());
    assert_eq!(withdrawn, vec![(accepted, 0)]);
    assert_eq!(session.known_prefix_count(), 0);
    assert!(
        rib_rx.try_recv().is_err(),
        "first-seen rejects must stay silent"
    );
    let key = |prefix| ImportDecisionKey {
        afi: Afi::Ipv6,
        safi: Safi::Unicast,
        prefix,
        path_id: 0,
    };
    match session
        .import_decision_cache
        .lookup(&key(accepted), session.import_policy_generation)
    {
        LookupResult::Hit(decision) => {
            assert_eq!(decision.outcome, CachedOutcome::Withdrawn);
        }
        other => panic!("expected ownership-withdrawn {accepted}, got {other:?}"),
    }
    assert!(matches!(
        session
            .import_decision_cache
            .lookup(&key(first_seen), session.import_policy_generation),
        LookupResult::NotSeen
    ));
}

/// ADR-0107 §2: a global + link-local next-hop pair always fails closed
/// under the strict pilot — the companion cannot be mapped to the single
/// session address even when the global component matches, and it is
/// never silently ignored.
#[tokio::test]
async fn strict_peer_next_hop_rejects_link_local_companion_pair() {
    use rustbgpd_wire::{MpReachNlri, NlriEntry};

    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    session.config.next_hop_ownership_strict_peer = true;
    session.peer_ip = "2001:db8::2".parse().unwrap();
    let mut negotiated = negotiated_session(65002, false);
    negotiated.negotiated_families = vec![(Afi::Ipv6, Safi::Unicast)];
    install_test_negotiated_session(&mut session, negotiated);
    let attrs = vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath {
            segments: vec![AsPathSegment::AsSequence(vec![65002])],
        }),
        PathAttribute::MpReachNlri(MpReachNlri {
            afi: Afi::Ipv6,
            safi: Safi::Unicast,
            // Global component matches the session; the link-local
            // companion is still unverifiable under strict_peer.
            next_hop: "2001:db8::2".parse().unwrap(),
            link_local_next_hop: Some("fe80::2".parse().unwrap()),
            announced: vec![NlriEntry {
                path_id: 0,
                prefix: Prefix::V6(Ipv6Prefix::new("2001:db8:473:3::".parse().unwrap(), 64)),
            }],
            flowspec_announced: vec![],
            evpn_announced: vec![],
            bgpls_announced: vec![],
            labeled_announced: vec![],
            vpn_announced: vec![],
            rtc_announced: vec![],
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
    assert!(
        rib_rx.try_recv().is_err(),
        "a paired link-local companion must fail closed under strict_peer"
    );
}

/// The ownership gate is opt-in: without `next_hop_ownership =
/// "strict_peer"` a third-party next-hop keeps flowing (RFC 7947
/// transparency), pinning that ADR-0107 changes nothing by default.
#[tokio::test]
async fn next_hop_ownership_disabled_by_default_accepts_foreign_next_hop() {
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    session.negotiated = Some(negotiated_session(65002, false));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24);
    let attrs = vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath {
            segments: vec![AsPathSegment::AsSequence(vec![65002])],
        }),
        PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 9)),
    ];
    session
        .process_update(UpdateMessage::build(
            &[Ipv4NlriEntry { path_id: 0, prefix }],
            &[],
            &attrs,
            true,
            false,
            Ipv4UnicastMode::Body,
        ))
        .await;
    let RibUpdate::RoutesReceived { announced, .. } = rib_rx.try_recv().unwrap() else {
        panic!("expected RoutesReceived");
    };
    assert_eq!(
        announced.len(),
        1,
        "default (unset) must preserve transparent behavior"
    );
}

// ---------------------------------------------------------------------
// RFC 7606 revised error handling — treat-as-withdraw / attribute-discard
// ---------------------------------------------------------------------

/// Craft raw attribute bytes: valid `ORIGIN` + `AS_PATH` (65002, 4-octet) +
/// `NEXT_HOP`, followed by `extra`.
fn rfc7606_attr_bytes(extra: &[u8]) -> Vec<u8> {
    let mut attrs = vec![0x40, 1, 1, 0]; // ORIGIN = IGP
    attrs.extend([0x40, 2, 6, 2, 1, 0, 0, 0xFD, 0xEA]); // AS_PATH seq [65002]
    attrs.extend([0x40, 3, 4, 10, 0, 0, 2]); // NEXT_HOP 10.0.0.2
    attrs.extend_from_slice(extra);
    attrs
}

/// Drain the establishment-time RIB messages (`SetPeerExportContext`, `PeerUp`,
/// ...) so tests observe only what `process_update` produces.
fn rfc7606_drain(rib_rx: &mut mpsc::Receiver<RibUpdate>) {
    while rib_rx.try_recv().is_ok() {}
}

fn rfc7606_update(attr_bytes: Vec<u8>, announced: &[Ipv4Prefix]) -> UpdateMessage {
    let mut nlri = Vec::new();
    rustbgpd_wire::nlri::encode_nlri(announced, &mut nlri);
    UpdateMessage {
        withdrawn_routes: Bytes::new(),
        path_attributes: Bytes::from(attr_bytes),
        nlri: Bytes::from(nlri),
    }
}

/// RFC 7606 §7.4 + §2: a malformed MED treats the UPDATE as though its
/// routes had been withdrawn — previously accepted routes for the same
/// NLRI are removed — and the session stays Established.
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
    assert_eq!(
        session.fsm.state(),
        SessionState::Established,
        "treat-as-withdraw must keep the session Established"
    );
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
