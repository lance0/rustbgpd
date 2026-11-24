//! A restarting source retains one route across two negotiated OPENs.
//! Check the identifier each receiver actually decodes from its writer.
use super::*;
use rustbgpd_wire::{
    EthernetSegmentIdentifier, EthernetTagId, EvpnMacIp, EvpnRoute, ExtendedCommunity, LabeledNlri,
    LabeledNlriEntry, MacAddress, MpReachNlri, MplsLabel, RtcNlri, VpnNlriEntry,
};

type Family = (Afi, Safi);

async fn register(
    tx: &mpsc::Sender<RibUpdate>,
    family: Family,
    address: Ipv4Addr,
    identifier: Ipv4Addr,
    remote_asn: u16,
    generation: u64,
) -> (PeerSession, TcpStream) {
    let cluster = Ipv4Addr::new(10, 0, 0, 1);
    let mut config = PeerConfig::new(65001, u32::from(remote_asn), cluster);
    config.families = vec![family];
    config.graceful_restart = true;
    let mut session = make_test_session_with_peer_config(config);
    session.peer_ip = address.into();
    session.rib_tx = tx.clone();
    session.session_identity = SessionIdentity::primary(generation);
    session.config.cluster_id = Some(cluster);
    session.config.route_reflector_client = remote_asn == 65001;
    session.config.local_ipv6_nexthop = Some("2001:db8::1".parse().unwrap());
    let (socket, remote) = connected_stream_pair().await;
    session.test_install_stream(socket);
    let (afi, safi) = family;
    let restarting = generation == 2;
    let open = rustbgpd_wire::OpenMessage {
        version: 4,
        my_as: remote_asn,
        bgp_identifier: identifier,
        hold_time: 90,
        capabilities: vec![
            Capability::FourOctetAs {
                asn: u32::from(remote_asn),
            },
            Capability::MultiProtocol { afi, safi },
            Capability::GracefulRestart {
                restart_state: restarting,
                notification: false,
                restart_time: 120,
                families: vec![rustbgpd_wire::GracefulRestartFamily {
                    afi,
                    safi,
                    forwarding_preserved: restarting,
                }],
            },
        ],
    };
    session.drive_fsm(Event::ManualStart).await;
    session.drive_fsm(Event::OpenReceived(open)).await;
    session.drive_fsm(Event::KeepaliveReceived).await;
    assert_eq!(session.fsm.state(), SessionState::Established);
    assert!(
        session
            .negotiated
            .as_ref()
            .unwrap()
            .negotiated_families
            .contains(&family)
    );
    (session, remote)
}

// These queries run on the primary FIFO after selection and distribution.
async fn selected(tx: &mpsc::Sender<RibUpdate>, safi: Safi, source: PeerId) -> (Ipv4Addr, bool) {
    macro_rules! row {
        ($query:ident) => {{
            let (reply, result) = oneshot::channel();
            tx.send(RibUpdate::$query {
                filter: Some(Box::new(move |route| route.peer == source)),
                reply,
            })
            .await
            .unwrap();
            let rows = result.await.unwrap();
            let [row] = rows.as_slice() else {
                panic!("{safi:?}: expected one selected row, got {}", rows.len());
            };
            (row.peer_router_id, row.is_stale)
        }};
    }
    match safi {
        Safi::FlowSpec => row!(QueryFlowSpecRoutes),
        Safi::Evpn => row!(QueryEvpnRoutes),
        Safi::MplsVpn => row!(QueryVpnRoutes),
        Safi::LabeledUnicast => row!(QueryLabeledRoutes),
        Safi::BgpLs | Safi::BgpLsVpn => row!(QueryBgpLsRoutes),
        Safi::RtConstrain => row!(QueryRtcRoutes),
        _ => panic!("unsupported fixture family {safi:?}"),
    }
}

async fn decoded(
    receiver: &mut (PeerSession, TcpStream),
    expected: &MpReachNlri,
) -> Vec<Option<Ipv4Addr>> {
    let family = (expected.afi, expected.safi);
    let (session, wire) = receiver;
    let mut ids = Vec::new();
    while let Ok(update) = session.outbound_rx.try_recv() {
        assert!(
            update.evpn_withdraw.is_empty()
                && update.vpn_withdraw.is_empty()
                && update.labeled_withdraw.is_empty()
                && update.flowspec_withdraw.is_empty()
                && update.bgpls_withdraw.is_empty()
                && update.rtc_withdraw.is_empty(),
            "{family:?}: retained advertisement was withdrawn"
        );
        let rows = update.evpn_announce.len()
            + update.vpn_announce.len()
            + update.labeled_announce.len()
            + update.flowspec_announce.len()
            + update.bgpls_announce.len()
            + update.rtc_announce.len();
        if rows == 0 {
            continue;
        }
        assert_eq!(rows, 1, "one advertised row per envelope");
        session.send_route_update(update);
        let parsed = tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                if let Message::Update(frame) = read_single_bgp_message(wire).await {
                    break frame.parse(true, false, &[]).unwrap();
                }
            }
        })
        .await
        .expect("MP UPDATE on the writer socket");
        let mut originator = None;
        let mut reached = false;
        for attr in &parsed.attributes {
            match attr {
                PathAttribute::MpReachNlri(mp) => {
                    assert!(!reached);
                    assert_eq!((mp.afi, mp.safi), family);
                    assert_eq!(mp.evpn_announced, expected.evpn_announced);
                    assert_eq!(mp.vpn_announced, expected.vpn_announced);
                    assert_eq!(mp.labeled_announced, expected.labeled_announced);
                    assert_eq!(mp.rtc_announced, expected.rtc_announced);
                    assert_eq!(mp.bgpls_announced, expected.bgpls_announced);
                    assert_eq!(mp.flowspec_announced, expected.flowspec_announced);
                    reached = true;
                }
                PathAttribute::OriginatorId(id) => assert!(originator.replace(*id).is_none()),
                _ => {}
            }
        }
        assert!(reached, "missing MP_REACH_NLRI");
        ids.push(originator);
    }
    ids
}

fn announcement(reach: &MpReachNlri, originator: Option<Ipv4Addr>) -> UpdateMessage {
    let mut attrs = vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath { segments: vec![] }),
        PathAttribute::LocalPref(100),
    ];
    if matches!(reach.safi, Safi::Evpn | Safi::MplsVpn) {
        attrs.push(PathAttribute::ExtendedCommunities(vec![
            ExtendedCommunity::new(0x0002_fde8_0000_0064),
        ]));
    }
    attrs.extend(originator.map(PathAttribute::OriginatorId));
    nonunicast_update(attrs, reach.clone(), None, false)
}

async fn receivers(
    tx: &mpsc::Sender<RibUpdate>,
    family: Family,
) -> Vec<(&'static str, (PeerSession, TcpStream))> {
    let mut sinks = Vec::new();
    for (name, octet, asn) in [
        ("iBGP", 3, 65001),
        ("private iBGP", 4, 65001),
        ("eBGP", 5, 65002),
    ] {
        let addr = Ipv4Addr::new(10, 0, 0, octet);
        let sink = register(tx, family, addr, addr, asn, 7).await;
        let peer = sink.0.rib_peer();
        if name == "private iBGP" {
            tx.send(RibUpdate::PeerSlowState {
                peer,
                session_id: 7,
                slow: true,
            })
            .await
            .unwrap();
        }
        let (reply, result) = oneshot::channel();
        tx.send(RibUpdate::QueryPeerUpdateGroup { peer, reply })
            .await
            .unwrap();
        let membership = result.await.unwrap();
        if name == "private iBGP" {
            assert_eq!(membership, "slow_peer");
        } else {
            assert!(
                membership.starts_with("group:"),
                "{family:?} {name}: {membership}"
            );
        }
        sinks.push((name, sink));
    }
    sinks
}

async fn check_route(reach: &MpReachNlri) {
    let family = (reach.afi, reach.safi);
    let old = Ipv4Addr::new(192, 0, 2, 10);
    let new = Ipv4Addr::new(192, 0, 2, 11);
    let source = Ipv4Addr::new(10, 0, 0, 2);
    let mut differences = Vec::new();
    for (reopened, carried) in [
        (new, None),
        (old, None),
        (new, Some(Ipv4Addr::new(192, 0, 2, 99))),
    ] {
        let (tx, rx) = mpsc::channel(128);
        let (_qtx, qrx) = mpsc::channel(8);
        let cluster = Ipv4Addr::new(10, 0, 0, 1);
        let manager =
            rustbgpd_rib::RibManager::new(rx, qrx, None, Some(cluster), BgpMetrics::new());
        let actor = tokio::spawn(manager.run());
        let mut sinks = receivers(&tx, family).await;
        let (mut first, _first_wire) = register(&tx, family, source, old, 65001, 1).await;
        let source_peer = first.rib_peer();
        if family.1 == Safi::RtConstrain {
            // The speaker originates a default RTC membership before it learns the source membership.
            let (reply, done) = oneshot::channel();
            tx.send(RibUpdate::QueryLocRibCount { reply })
                .await
                .unwrap();
            done.await.unwrap();
            for (_, (sink, _)) in &mut sinks {
                while let Ok(initial) = sink.outbound_rx.try_recv() {
                    assert_eq!(
                        initial.rtc_withdraw,
                        [] as [rustbgpd_rib::RtcRibRouteKey; 0]
                    );
                    assert!(initial.rtc_announce.iter().all(|row| row.nlri.is_default()
                        && row.origin_type == rustbgpd_rib::RouteOrigin::Local));
                }
            }
        }
        first.process_update(announcement(reach, carried)).await;
        assert_eq!(selected(&tx, family.1, source_peer).await, (old, false));
        for (name, sink) in &mut sinks {
            let expected = (*name != "eBGP").then_some(carried.unwrap_or(old));
            assert_eq!(
                decoded(sink, reach).await,
                [expected],
                "{family:?} initial {name}"
            );
        }
        first.drive_fsm(Event::TcpConnectionFails).await;
        assert_eq!(selected(&tx, family.1, source_peer).await, (old, true));
        let (mut second, _second_wire) = register(&tx, family, source, reopened, 65001, 2).await;
        assert_eq!(selected(&tx, family.1, source_peer).await, (old, true));
        for (name, sink) in &mut sinks {
            let expected = (*name != "eBGP").then_some(carried.unwrap_or(old));
            assert!(
                decoded(sink, reach).await.iter().all(|id| *id == expected),
                "{family:?} {name} changed retained identity before reannouncement"
            );
        }
        for refresh in [true, false] {
            second.process_update(announcement(reach, carried)).await;
            assert_eq!(
                selected(&tx, family.1, source_peer).await,
                (reopened, false)
            );
            for (name, sink) in &mut sinks {
                let reflected = *name != "eBGP";
                let actual = decoded(sink, reach).await;
                let wire_id = reflected.then_some(carried.unwrap_or(reopened));
                let wire_changed = reopened != old && reflected && carried.is_none();
                let correct = if refresh && wire_changed {
                    actual == [wire_id]
                } else if refresh && family.1 == Safi::FlowSpec {
                    // A retained FlowSpec winner becoming fresh can repeat its current export.
                    actual.is_empty() || actual == [wire_id]
                } else {
                    actual.is_empty()
                };
                if !correct {
                    differences.push(format!("{family:?} {name} reopened={reopened} refresh={refresh} carried={carried:?}: got {actual:?}, wire_id={wire_id:?} changed={wire_changed}"));
                }
            }
        }
        actor.abort();
    }
    assert!(differences.is_empty(), "{}", differences.join("\n"));
}

#[tokio::test]
async fn evpn_mac_ip() {
    let mut reach = empty_nonunicast_reach(Afi::L2Vpn, Safi::Evpn, "192.0.2.7".parse().unwrap());
    reach.evpn_announced.push(EvpnRoute::MacIp(EvpnMacIp {
        rd: "65000:100".parse().unwrap(),
        esi: EthernetSegmentIdentifier::ZERO,
        ethernet_tag: EthernetTagId(0),
        mac: MacAddress([0x02, 0, 0, 0, 0, 7]),
        ip: Some("198.51.100.7".parse().unwrap()),
        label1: MplsLabel::new((16_100 << 4) | 1),
        label2: None,
    }));
    Box::pin(check_route(&reach)).await;
}

async fn check_mpls(afi: Afi, safi: Safi) {
    let (prefix, vpn_prefix, hop) = match afi {
        Afi::Ipv4 => {
            let addr = Ipv4Addr::new(198, 51, 100, 0);
            (
                Prefix::V4(Ipv4Prefix::new(addr, 24)),
                VpnPrefix::v4(addr, 24),
                "192.0.2.7",
            )
        }
        Afi::Ipv6 => {
            let addr = "2001:db8:100::".parse().unwrap();
            (
                Prefix::V6(Ipv6Prefix::new(addr, 64)),
                VpnPrefix::v6(addr, 64),
                "2001:db8::7",
            )
        }
        _ => unreachable!(),
    };
    let mut reach = empty_nonunicast_reach(afi, safi, hop.parse().unwrap());
    let labels = vec![MplsLabelEntry::try_new(16_100, 0, true).unwrap()];
    match safi {
        Safi::MplsVpn => reach.vpn_announced.push(VpnNlriEntry {
            path_id: 0,
            nlri: VpnNlri {
                labels,
                route_distinguisher: "65000:100".parse().unwrap(),
                prefix: vpn_prefix.unwrap(),
            },
        }),
        Safi::LabeledUnicast => reach.labeled_announced.push(LabeledNlriEntry {
            path_id: 0,
            nlri: LabeledNlri { labels, prefix },
        }),
        _ => unreachable!(),
    }
    Box::pin(check_route(&reach)).await;
}

#[tokio::test]
async fn vpnv4() {
    check_mpls(Afi::Ipv4, Safi::MplsVpn).await;
}

#[tokio::test]
async fn vpnv6() {
    check_mpls(Afi::Ipv6, Safi::MplsVpn).await;
}

#[tokio::test]
async fn labeled_v4() {
    check_mpls(Afi::Ipv4, Safi::LabeledUnicast).await;
}

#[tokio::test]
async fn labeled_v6() {
    check_mpls(Afi::Ipv6, Safi::LabeledUnicast).await;
}

#[tokio::test]
async fn rtc_membership() {
    let mut reach = empty_nonunicast_reach(
        Afi::Ipv4,
        Safi::RtConstrain,
        Ipv4Addr::new(192, 0, 2, 7).into(),
    );
    // A full membership prefix for RT 65000:100.
    reach
        .rtc_announced
        .push(RtcNlri::new(65_000, 0x0002_fde8_0000_0064, 96).unwrap());
    Box::pin(check_route(&reach)).await;
}

async fn check_link_state(safi: Safi) {
    let mut reach = empty_nonunicast_reach(Afi::BgpLs, safi, Ipv4Addr::new(192, 0, 2, 7).into());
    let rd = (safi == Safi::BgpLsVpn).then_some([0, 0, 0xfd, 0xe8, 0, 0, 0, 100]);
    let payload = Bytes::from_static(&[
        3, 0, 0, 0, 0, 0, 0, 0, 1, // OSPFv2, instance 1
        1, 0, 0, 8, // Local Node Descriptors (256)
        2, 3, 0, 4, 192, 0, 2, 9, // IGP Router-ID (515)
    ]);
    reach
        .bgpls_announced
        .push(BgpLsNlri::try_new(BgpLsNlriType::Node, rd, payload).unwrap());
    Box::pin(check_route(&reach)).await;
}

#[tokio::test]
async fn bgpls_node() {
    check_link_state(Safi::BgpLs).await;
}

#[tokio::test]
async fn bgpls_vpn_node() {
    check_link_state(Safi::BgpLsVpn).await;
}

async fn check_flowspec(afi: Afi, destination: FlowSpecPrefix) {
    let mut reach = empty_nonunicast_reach(afi, Safi::FlowSpec, Ipv4Addr::UNSPECIFIED.into());
    reach.flowspec_announced.push(FlowSpecRule {
        components: vec![FlowSpecComponent::DestinationPrefix(destination)],
    });
    Box::pin(check_route(&reach)).await;
}

#[tokio::test]
async fn flowspec_v4() {
    check_flowspec(
        Afi::Ipv4,
        FlowSpecPrefix::V4(Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 0), 24)),
    )
    .await;
}

#[tokio::test]
async fn flowspec_v6() {
    check_flowspec(
        Afi::Ipv6,
        FlowSpecPrefix::V6(Ipv6PrefixOffset {
            prefix: Ipv6Prefix::new("2001:db8:100::".parse().unwrap(), 64),
            offset: 0,
        }),
    )
    .await;
}
