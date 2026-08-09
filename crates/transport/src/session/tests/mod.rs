// Sibling modules reach the session's own submodules with `super::`, which for
// them resolves to `session::tests`. Bind the names they path-qualify here so
// those paths keep resolving to `session::*`.
use super::export::{ExportCandidate, ExportWithdrawal};
use super::*;
use super::{export, import_decision_cache, io, shared_group, tcp_ao_key_metadata, writer};
use crate::PeerCommandError;
use bytes::Bytes;
use rustbgpd_fsm::PeerConfig;
use rustbgpd_policy::{
    AsPathRegex, CommunityMatch, NeighborSetMatch, Policy, PolicyAction, PolicyChain,
    PolicyStatement, RouteModifications,
};
use rustbgpd_wire::{
    AddressPrefixOrf, AsPath, AsPathSegment, FlowSpecComponent, FlowSpecPrefix, FlowSpecRule,
    Ipv4NlriEntry, Ipv4Prefix, Ipv6Prefix, Ipv6PrefixOffset, LlgrFamily, Message, MplsLabelEntry,
    NumericMatch, OrfAction, OrfEntries, OrfEntryGroup, OrfMatch, OrfPayload, OrfType, Origin,
    PathAttribute, RawAttribute, RouteDistinguisher, VpnNlri, VpnPrefix, WhenToRefresh,
    bgpls::{BgpLsNlri, BgpLsNlriType, decode_bgpls_nlri, decode_bgpls_vpn_nlri},
};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::oneshot;

fn counter_samples(metrics: &BgpMetrics, name: &str) -> Vec<(HashMap<String, String>, f64)> {
    metrics
        .registry()
        .gather()
        .into_iter()
        .find(|family| family.name() == name)
        .map_or_else(Vec::new, |family| {
            family
                .get_metric()
                .iter()
                .map(|metric| {
                    let labels = metric
                        .get_label()
                        .iter()
                        .map(|label| (label.name().to_string(), label.value().to_string()))
                        .collect();
                    (labels, metric.get_counter().value())
                })
                .collect()
        })
}

fn assert_zero_counter_sample(
    samples: &[(HashMap<String, String>, f64)],
    expected_labels: &[(&str, &str)],
) {
    let matching: Vec<_> = samples
        .iter()
        .filter(|(labels, _)| {
            expected_labels
                .iter()
                .all(|(name, value)| labels.get(*name).is_some_and(|actual| actual == value))
        })
        .collect();
    assert_eq!(
        matching.len(),
        1,
        "expected one counter sample with labels {expected_labels:?}, got {matching:?}"
    );
    assert!(
        matching[0].1.abs() < f64::EPSILON,
        "new counter child must start at zero"
    );
}

fn exact_export_families() -> [((Afi, Safi), &'static str); 12] {
    [
        ((Afi::Ipv4, Safi::Unicast), "ipv4_unicast"),
        ((Afi::Ipv6, Safi::Unicast), "ipv6_unicast"),
        ((Afi::Ipv4, Safi::FlowSpec), "ipv4_flowspec"),
        ((Afi::Ipv6, Safi::FlowSpec), "ipv6_flowspec"),
        ((Afi::L2Vpn, Safi::Evpn), "l2vpn_evpn"),
        ((Afi::BgpLs, Safi::BgpLs), "bgpls"),
        ((Afi::BgpLs, Safi::BgpLsVpn), "bgpls_vpn"),
        ((Afi::Ipv4, Safi::MplsVpn), "l3vpn_ipv4_unicast"),
        ((Afi::Ipv6, Safi::MplsVpn), "l3vpn_ipv6_unicast"),
        ((Afi::Ipv4, Safi::LabeledUnicast), "ipv4_labeled_unicast"),
        ((Afi::Ipv6, Safi::LabeledUnicast), "ipv6_labeled_unicast"),
        ((Afi::Ipv4, Safi::RtConstrain), "rtc"),
    ]
}

fn make_test_session(local_asn: u32, remote_asn: u32) -> PeerSession {
    let mut peer_config = PeerConfig::new(local_asn, remote_asn, Ipv4Addr::new(10, 0, 0, 1));
    peer_config.connect_retry_secs = 30;
    peer_config.families = vec![(Afi::Ipv4, Safi::Unicast)];
    peer_config.gr_restart_time = 120;
    make_test_session_with_peer_config(peer_config)
}

fn make_test_session_with_peer_config(peer_config: PeerConfig) -> PeerSession {
    let config = TransportConfig::new(peer_config, "10.0.0.2:179".parse().unwrap());
    let metrics = BgpMetrics::new();
    let (_cmd_tx, cmd_rx) = mpsc::channel(8);
    let (rib_tx, _rib_rx) = mpsc::channel(64);
    PeerSession::new(
        config, metrics, cmd_rx, rib_tx, None, None, None, None, None, false,
    )
}

fn tcp_ao_deletion_test_fixture() -> (PeerSession, crate::TcpAoSessionDeletion) {
    let retired = crate::TcpAoConfig {
        key: "retired-secret".into(),
        send_id: 1,
        recv_id: 11,
        algorithm: crate::TcpAoAlgorithm::HmacSha256,
        preferred: false,
        deprecated: true,
    };
    let successor = crate::TcpAoConfig {
        key: "successor-secret".into(),
        send_id: 2,
        recv_id: 12,
        algorithm: crate::TcpAoAlgorithm::HmacSha256,
        preferred: true,
        deprecated: false,
    };
    let current_keyring = crate::TcpAoKeyring(vec![retired, successor.clone()]);
    let desired_keyring = crate::TcpAoKeyring(vec![successor]);
    let mut peer_config = PeerConfig::new(65001, 65002, Ipv4Addr::new(10, 0, 0, 1));
    peer_config.families = vec![(Afi::Ipv4, Safi::Unicast)];
    let mut config = TransportConfig::new(peer_config, "10.0.0.2:179".parse().unwrap());
    config.tcp_ao = Some(current_keyring.clone());
    let (_cmd_tx, cmd_rx) = mpsc::channel(8);
    let (rib_tx, _rib_rx) = mpsc::channel(8);
    let generation = crate::TcpAoRotationGeneration::new(2).unwrap();
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
        crate::TcpAoRotationGeneration::STARTUP,
    );
    let deletion = crate::TcpAoSessionDeletion {
        generation,
        current: crate::TcpAoSessionGeneration {
            generation: crate::TcpAoRotationGeneration::STARTUP,
            active_keyring: Some(current_keyring),
            accepted_owners: Vec::new().into(),
        },
        desired: crate::TcpAoSessionGeneration {
            generation,
            active_keyring: Some(desired_keyring),
            accepted_owners: Vec::new().into(),
        },
    };
    (session, deletion)
}

async fn install_test_tcp_stream(session: &mut PeerSession) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let connect = TcpStream::connect(listener.local_addr().unwrap());
    let accept = listener.accept();
    let (client, accepted) = tokio::join!(connect, accept);
    let (_server, _) = accepted.unwrap();
    session.test_install_stream(client.unwrap());
}

fn make_test_session_with_rib(
    local_asn: u32,
    remote_asn: u32,
) -> (PeerSession, mpsc::Receiver<RibUpdate>) {
    let (session, _cmd_tx, rib_rx) = make_test_session_with_channels(local_asn, remote_asn, 64);
    (session, rib_rx)
}

fn make_test_session_with_metrics_and_identity(
    metrics: BgpMetrics,
    session_identity: SessionIdentity,
) -> (PeerSession, mpsc::Receiver<RibUpdate>) {
    let mut peer_config = PeerConfig::new(65001, 65002, Ipv4Addr::new(10, 0, 0, 1));
    peer_config.connect_retry_secs = 30;
    peer_config.families = vec![(Afi::Ipv4, Safi::Unicast)];
    let mut config = TransportConfig::new(peer_config, "10.0.0.2:179".parse().unwrap());
    config.max_prefixes = Some(10);
    config.max_prefixes_ipv4 = Some(5);
    let (_cmd_tx, cmd_rx) = mpsc::channel(8);
    let (rib_tx, rib_rx) = mpsc::channel(64);
    (
        PeerSession::new_with_identity_and_lifecycle(
            config,
            metrics,
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
            session_identity,
        ),
        rib_rx,
    )
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

fn max_prefix_gauge(metrics: &BgpMetrics, name: &str, peer: &str, scope: &str) -> Option<f64> {
    metrics
        .registry()
        .gather()
        .into_iter()
        .find(|family| family.name() == name)
        .and_then(|family| {
            family.get_metric().iter().find_map(|metric| {
                let has_peer = metric
                    .get_label()
                    .iter()
                    .any(|label| label.name() == "peer" && label.value() == peer);
                let has_scope = metric
                    .get_label()
                    .iter()
                    .any(|label| label.name() == "scope" && label.value() == scope);
                (has_peer && has_scope).then(|| metric.get_gauge().value())
            })
        })
}

fn peer_truth_gauge(metrics: &BgpMetrics, name: &str, peer: &str, interface: &str) -> Option<f64> {
    metrics
        .registry()
        .gather()
        .into_iter()
        .find(|family| family.name() == name)
        .and_then(|family| {
            family.get_metric().iter().find_map(|metric| {
                let has_peer = metric
                    .get_label()
                    .iter()
                    .any(|label| label.name() == "peer" && label.value() == peer);
                let has_interface = metric
                    .get_label()
                    .iter()
                    .any(|label| label.name() == "interface" && label.value() == interface);
                (has_peer && has_interface).then(|| metric.get_gauge().value())
            })
        })
}

fn assert_max_prefix_gauge(session: &PeerSession, name: &str, scope: &str, expected: Option<f64>) {
    assert_eq!(
        max_prefix_gauge(&session.metrics, name, &session.peer_label, scope),
        expected,
        "unexpected {name} for {} scope {scope}",
        session.peer_label
    );
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
fn aspa_first_as_update(prefix: Ipv4Prefix, first_asn: u32, four_octet_as: bool) -> UpdateMessage {
    UpdateMessage::build(
        &[Ipv4NlriEntry { path_id: 0, prefix }],
        &[],
        &[
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath {
                segments: vec![AsPathSegment::AsSequence(vec![first_asn, 65010])],
            }),
            PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
        ],
        four_octet_as,
        false,
        Ipv4UnicastMode::Body,
    )
}
async fn assert_aspa_first_as_mismatch_withdraws_replacement(four_octet_as: bool) {
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    let (client, _server) = connected_stream_pair().await;
    session.test_install_stream(client);
    establish_test_session(&mut session, 65002).await;
    while rib_rx.try_recv().is_ok() {}
    let mut negotiated = negotiated_session(65002, false);
    negotiated.four_octet_as = four_octet_as;
    install_test_negotiated_session(&mut session, negotiated);

    let prefix = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24);
    session
        .process_update(aspa_first_as_update(prefix, 65002, four_octet_as))
        .await;
    let RibUpdate::RoutesReceived { announced, .. } = rib_rx
        .try_recv()
        .expect("matching first-AS route must reach the RIB")
    else {
        panic!("expected matching first-AS RoutesReceived");
    };
    assert_eq!(announced.len(), 1, "matching first AS remains accepted");
    assert_eq!(session.known_prefix_count(), 1);

    session
        .process_update(aspa_first_as_update(prefix, 65003, four_octet_as))
        .await;
    let RibUpdate::RoutesReceived {
        announced,
        withdrawn,
        ..
    } = rib_rx
        .try_recv()
        .expect("mismatched replacement must reach the RIB as a withdrawal")
    else {
        panic!("expected treat-as-withdraw RoutesReceived");
    };
    assert!(announced.is_empty());
    assert_eq!(withdrawn, vec![(Prefix::V4(prefix), 0)]);
    assert_eq!(session.known_prefix_count(), 0);
    assert_eq!(
        session.fsm.state(),
        SessionState::Established,
        "first-AS treat-as-withdraw must not reset the session"
    );
    assert_single_malformed_disposition(&session, "treat_as_withdraw");
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
        RibUpdate::SetPeerRsControl { .. }
    ));
    assert!(matches!(
        rib_rx.recv().await.unwrap(),
        RibUpdate::SetPeerExportEncoder { .. }
    ));
    assert!(matches!(
        rib_rx.recv().await.unwrap(),
        RibUpdate::SetPeerGracefulRestartContext { .. }
    ));
    // Load-bearing ordering: the peer group must reach the RIB BEFORE
    // `PeerUp` builds the initial Adj-RIB-Out. Otherwise a group-scoped
    // export rule misses that dump, and (ADR-0113) a group-inheriting peer
    // floods its initial feed with no outbound prefix maximum resolved.
    assert!(matches!(
        rib_rx.recv().await.unwrap(),
        RibUpdate::SetPeerPolicyContext { .. }
    ));
    rib_rx.recv().await.unwrap()
}

/// Export chain that denies every route advertised to a member of
/// `group`, and permits everything else.
fn deny_export_to_peer_group(group: &str) -> PolicyChain {
    PolicyChain::new(vec![Policy {
        entries: vec![PolicyStatement {
            prefix: None,
            ge: None,
            le: None,
            action: PolicyAction::Deny,
            match_community: vec![],
            match_as_path: None,
            match_neighbor_set: Some(NeighborSetMatch {
                addresses: vec![],
                remote_asns: vec![],
                peer_groups: vec![group.to_string()],
            }),
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
    }])
}

/// Bring one peer to Established against a REAL `RibManager` that already
/// holds one route, and return the prefixes its initial full-table dump
/// announced. The peer's export chain denies everything advertised to
/// peer-group `rs-members`.
async fn initial_dump_announcements(peer_group: Option<&str>) -> Vec<Prefix> {
    let (rib_tx, rib_rx) = mpsc::channel(64);
    let (_query_tx, query_rx) = mpsc::channel(8);
    let manager = tokio::spawn(
        rustbgpd_rib::RibManager::new(rib_rx, query_rx, None, None, BgpMetrics::new()).run(),
    );

    // One route from an unrelated peer, so the dump has something to carry.
    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9));
    let mut route = make_route(100);
    route.prefix = Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24));
    route.peer = source;
    route.next_hop = source;
    route.attributes = Arc::new(vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath {
            segments: vec![AsPathSegment::AsSequence(vec![65002])],
        }),
        PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 9)),
    ]);
    rib_tx
        .send(RibUpdate::RoutesReceived {
            peer: source,
            session_id: 0,
            announced: vec![route],
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
            evpn_announced: vec![],
            evpn_withdrawn: vec![],
        })
        .await
        .unwrap();

    let mut peer_config = PeerConfig::new(65001, 65010, Ipv4Addr::new(10, 0, 0, 1));
    peer_config.connect_retry_secs = 30;
    peer_config.families = vec![(Afi::Ipv4, Safi::Unicast)];
    let mut config = TransportConfig::new(peer_config, "10.0.0.2:179".parse().unwrap());
    config.peer_group = peer_group.map(str::to_string);
    let (_cmd_tx, cmd_rx) = mpsc::channel(8);
    let mut session = PeerSession::new(
        config,
        BgpMetrics::new(),
        cmd_rx,
        rib_tx,
        None,
        Some(deny_export_to_peer_group("rs-members")),
        None,
        None,
        None,
        false,
    );
    let (client, _peer_end) = connected_stream_pair().await;
    session.test_install_stream(client);
    establish_test_session(&mut session, 65010).await;

    // Collect the dump through its End-of-RIB — the marker the RIB always
    // emits for a negotiated family, so an empty result is observed, not
    // assumed from a timeout.
    let mut announced = Vec::new();
    loop {
        let update = tokio::time::timeout(Duration::from_secs(10), session.outbound_rx.recv())
            .await
            .expect("initial table dump must reach the peer's outbound channel")
            .expect("outbound channel must stay open");
        announced.extend(update.announce.iter().map(|route| route.prefix));
        if !update.end_of_rib.is_empty() {
            break;
        }
    }
    manager.abort();
    announced
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
        None,
        crate::TcpAoRotationGeneration::STARTUP,
    )
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

/// `bgp_update_malformed_total` value for this session's peer and the
/// given disposition label; 0 when the series does not exist.
fn update_malformed_count(session: &PeerSession, disposition: &str) -> u64 {
    session
        .metrics
        .registry()
        .gather()
        .iter()
        .filter(|f| f.name() == "bgp_update_malformed_total")
        .flat_map(prometheus::proto::MetricFamily::get_metric)
        .filter(|m| {
            m.get_label()
                .iter()
                .any(|l| l.name() == "disposition" && l.value() == disposition)
        })
        .map(|m| {
            #[expect(
                clippy::cast_possible_truncation,
                clippy::cast_sign_loss,
                reason = "Prometheus counters are monotonic non-negative integers exposed as f64"
            )]
            let v = m.get_counter().value() as u64;
            v
        })
        .sum()
}

/// Assert the counter recorded exactly one malformed UPDATE, under
/// exactly `disposition` — the sibling dispositions must stay at zero.
fn assert_single_malformed_disposition(session: &PeerSession, disposition: &str) {
    for label in ["attribute_discard", "treat_as_withdraw", "session_reset"] {
        let expected = u64::from(label == disposition);
        assert_eq!(
            update_malformed_count(session, label),
            expected,
            "bgp_update_malformed_total{{disposition=\"{label}\"}}"
        );
    }
}

/// Structurally valid IPv6-unicast `MP_REACH_NLRI` raw attribute:
/// next-hop `2001:db8::1`, then the given NLRI prefix bytes (an empty
/// slice encodes an `MP_REACH` that carries zero NLRI).
fn rfc7606_mp_reach(nlri: &[u8]) -> Vec<u8> {
    let mut attr = vec![0x80, 14, 0]; // optional flags, type, len (patched)
    attr.extend([0, 2, 1, 16]); // AFI=IPv6, SAFI=unicast, NH-Len=16
    attr.extend([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    attr.push(0); // reserved
    attr.extend_from_slice(nlri);
    attr[2] = u8::try_from(attr.len() - 3).expect("attribute fits one length octet");
    attr
}

// ───────────────── LAN-472: rejected-route retention ─────────────────

/// Longhand `PolicyStatement` builder for the retention tests below —
/// only the fields under test vary.
use super::import_decision_cache::ImportDecisionKey as RetentionKey;

fn retention_statement(prefix: Option<Prefix>, action: PolicyAction) -> PolicyStatement {
    PolicyStatement {
        prefix,
        ge: None,
        le: None,
        action,
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
    }
}

fn retention_session_with_chain(
    chain: Option<PolicyChain>,
    mutate_config: impl FnOnce(&mut TransportConfig),
) -> (PeerSession, BgpMetrics) {
    let mut peer_config = PeerConfig::new(65001, 65002, Ipv4Addr::new(10, 0, 0, 1));
    peer_config.connect_retry_secs = 30;
    peer_config.families = vec![(Afi::Ipv4, Safi::Unicast)];
    peer_config.gr_restart_time = 120;
    let mut config = TransportConfig::new(peer_config, "10.0.0.2:179".parse().unwrap());
    mutate_config(&mut config);
    let metrics = BgpMetrics::new();
    let (_cmd_tx, cmd_rx) = mpsc::channel(8);
    let (rib_tx, _rib_rx) = mpsc::channel(64);
    let mut session = PeerSession::new(
        config,
        metrics.clone(),
        cmd_rx,
        rib_tx,
        chain,
        None,
        None,
        None,
        None,
        false,
    );
    let negotiated = negotiated_session(65002, false);
    session
        .negotiated_families
        .clone_from(&negotiated.negotiated_families);
    session.negotiated = Some(negotiated);
    (session, metrics)
}

fn retention_update(announce: &[Ipv4Prefix], withdraw: &[Ipv4Prefix]) -> UpdateMessage {
    let attrs = vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath {
            segments: vec![AsPathSegment::AsSequence(vec![65002])],
        }),
        PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
    ];
    let announced: Vec<Ipv4NlriEntry> = announce
        .iter()
        .map(|&prefix| Ipv4NlriEntry { path_id: 0, prefix })
        .collect();
    let withdrawn: Vec<Ipv4NlriEntry> = withdraw
        .iter()
        .map(|&prefix| Ipv4NlriEntry { path_id: 0, prefix })
        .collect();
    UpdateMessage::build(
        &announced,
        &withdrawn,
        &attrs,
        true,
        false,
        Ipv4UnicastMode::Body,
    )
}

fn retention_key(prefix: Ipv4Prefix) -> RetentionKey {
    RetentionKey {
        afi: Afi::Ipv4,
        safi: Safi::Unicast,
        prefix: Prefix::V4(prefix),
        path_id: 0,
    }
}

fn rejected_route_prototype_builds(session: &PeerSession) -> usize {
    session
        .rejected_route_prototype_builds
        .load(std::sync::atomic::Ordering::Relaxed)
}

mod bmp;
mod denied_replacements;
mod exact_export;
mod import_policy;
mod inbound_update;
mod labeled;
mod loop_detection;
mod max_prefix;
mod next_hop;
mod notification;
mod orf;
mod otc;
mod outbound_attrs;
mod outbound_encode;
mod refresh;
mod reject_retention;
mod rfc7606;
mod rpki_aspa;
mod rtc_bgpls;
mod run_loop;
mod shared_group_encode;
mod state_query;
mod tcp_ao;
mod vpn;
