//! ADR-0146: received VPN `FlowSpec` (AFI 1 / SAFI 134) is decoded, counted
//! and discarded, so it never reaches the RIB; locally originated VPN rules
//! leave as SAFI 134 with their Route Distinguisher.

use super::*;
use rustbgpd_wire::{
    Ipv4UnicastMode, MpReachNlri, MpUnreachNlri, ParsedUpdate, UpdateMessage, VpnFlowSpecRule,
};

const DISCARDED: &str = "bgp_vpn_flowspec_nlri_discarded_total";

/// The next message the peer receives. A missing message fails the test
/// instead of leaving it waiting forever.
async fn read_message(server: &mut tokio::net::TcpStream) -> Message {
    tokio::time::timeout(Duration::from_secs(5), read_single_bgp_message(server))
        .await
        .expect("the peer receives the next message within 5 s")
}

#[test]
fn rfc7606_diagnostics_list_vpn_flowspec_nlri() {
    let parsed = ParsedUpdate {
        withdrawn: Vec::new(),
        attributes: vec![reach(vec![vpn_rule(40)]), unreach(vec![vpn_rule(41)])],
        announced: Vec::new(),
        bgpls_nlri_discarded: 0,
    };
    let rule = vpn_rule(40).to_string();
    assert_eq!(
        super::inbound::treat_as_withdraw_summary(&parsed),
        super::inbound::TreatAsWithdrawSummary {
            announced: 1,
            families: "l3vpn_ipv4_flowspec=1".into(),
            next_hop: "none".into(),
            link_local_next_hop: None,
            prefixes: vec![rule.clone()],
        }
    );
    let involved = super::inbound::involved_nlri(&parsed);
    assert!(involved.contains(&rule), "{involved}");
    assert!(involved.contains(&vpn_rule(41).to_string()), "{involved}");
}

#[tokio::test]
async fn an_update_stopped_before_import_is_not_counted_as_discarded() {
    let (mut session, mut rib_rx) = session_with(vec![
        (Afi::Ipv4, Safi::Unicast),
        (Afi::Ipv4, Safi::FlowSpecVpn),
    ]);
    // AS_PATH loop: treat-as-withdraw (RFC 4271 §9.1.2).
    session
        .process_update(update(&[
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath {
                segments: vec![AsPathSegment::AsSequence(vec![65002, 65001])],
            }),
            reach(vec![vpn_rule(40)]),
        ]))
        .await;
    // Missing mandatory ORIGIN: an RFC 7606 treat-as-withdraw.
    session
        .process_update(update(&[
            PathAttribute::AsPath(AsPath {
                segments: vec![AsPathSegment::AsSequence(vec![65002])],
            }),
            reach(vec![vpn_rule(41)]),
        ]))
        .await;
    assert_eq!(discarded(&session), Vec::new());
    while let Ok(update) = rib_rx.try_recv() {
        assert!(
            !matches!(&update, RibUpdate::RoutesReceived { announced, .. } if !announced.is_empty()),
            "nothing is imported"
        );
    }
}

fn vpn_rule(assigned: u8) -> VpnFlowSpecRule {
    VpnFlowSpecRule {
        rd: RouteDistinguisher([0, 0, 0xad, 0x77, 0, 0, 0, assigned]),
        rule: FlowSpecRule {
            components: vec![FlowSpecComponent::DestinationPrefix(FlowSpecPrefix::V4(
                Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 10), 32),
            ))],
        },
    }
}

fn reach(rules: Vec<VpnFlowSpecRule>) -> PathAttribute {
    PathAttribute::MpReachNlri(Box::new(MpReachNlri {
        afi: Afi::Ipv4,
        safi: Safi::FlowSpecVpn,
        next_hop: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        link_local_next_hop: None,
        announced: vec![],
        flowspec_announced: vec![],
        evpn_announced: vec![],
        bgpls_announced: vec![],
        vpn_announced: vec![],
        labeled_announced: vec![],
        rtc_announced: vec![],
        vpn_flowspec_announced: rules,
    }))
}

fn unreach(rules: Vec<VpnFlowSpecRule>) -> PathAttribute {
    PathAttribute::MpUnreachNlri(Box::new(MpUnreachNlri {
        afi: Afi::Ipv4,
        safi: Safi::FlowSpecVpn,
        withdrawn: vec![],
        flowspec_withdrawn: vec![],
        evpn_withdrawn: vec![],
        bgpls_withdrawn: vec![],
        vpn_withdrawn: vec![],
        labeled_withdrawn: vec![],
        rtc_withdrawn: vec![],
        vpn_flowspec_withdrawn: rules,
    }))
}

fn update(attributes: &[PathAttribute]) -> UpdateMessage {
    UpdateMessage::build(&[], &[], attributes, true, false, Ipv4UnicastMode::Body)
}

fn announcement(rules: Vec<VpnFlowSpecRule>) -> UpdateMessage {
    update(&[
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath {
            segments: vec![AsPathSegment::AsSequence(vec![65002])],
        }),
        reach(rules),
    ])
}

fn session_with(
    families: Vec<(Afi, Safi)>,
) -> (PeerSession, tokio::sync::mpsc::Receiver<RibUpdate>) {
    let (mut session, rib_rx) = make_test_session_with_rib(65001, 65002);
    let mut negotiated = negotiated_session(65002, false);
    negotiated.negotiated_families = families;
    session.negotiated = Some(Arc::new(negotiated));
    (session, rib_rx)
}

fn discarded(session: &PeerSession) -> Vec<(HashMap<String, String>, f64)> {
    counter_samples(&session.metrics, DISCARDED)
}

#[tokio::test]
async fn received_vpn_flowspec_is_counted_and_never_reaches_the_rib() {
    let (mut session, mut rib_rx) = session_with(vec![
        (Afi::Ipv4, Safi::Unicast),
        (Afi::Ipv4, Safi::FlowSpecVpn),
    ]);

    session
        .process_update(announcement(vec![vpn_rule(40), vpn_rule(41)]))
        .await;
    // A withdrawal carries NLRI, so it is counted and is not End-of-RIB.
    session
        .process_update(update(&[unreach(vec![vpn_rule(40)])]))
        .await;

    assert_eq!(
        discarded(&session),
        vec![(
            HashMap::from([("peer".to_string(), session.peer_label.clone())]),
            3.0,
        )]
    );
    assert!(
        rib_rx.try_recv().is_err(),
        "VPN FlowSpec must not reach the RIB"
    );
    assert!(session.received_eor_families.is_empty());
}

#[tokio::test]
async fn vpn_flowspec_end_of_rib_is_accepted_and_not_counted() {
    let (mut session, mut rib_rx) = session_with(vec![
        (Afi::Ipv4, Safi::Unicast),
        (Afi::Ipv4, Safi::FlowSpecVpn),
    ]);

    session.process_update(update(&[unreach(vec![])])).await;

    assert!(matches!(
        rib_rx.try_recv(),
        Ok(RibUpdate::EndOfRib {
            afi: Afi::Ipv4,
            safi: Safi::FlowSpecVpn,
            ..
        })
    ));
    assert!(
        session
            .received_eor_families
            .contains(&(Afi::Ipv4, Safi::FlowSpecVpn))
    );
    assert_eq!(discarded(&session), Vec::new());
}

#[tokio::test]
async fn an_update_without_vpn_flowspec_creates_no_discard_series() {
    let (mut session, _rib_rx) = session_with(vec![
        (Afi::Ipv4, Safi::Unicast),
        (Afi::Ipv4, Safi::FlowSpecVpn),
    ]);
    session
        .process_update(UpdateMessage::build(
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
            Ipv4UnicastMode::Body,
        ))
        .await;
    assert_eq!(discarded(&session), Vec::new());
}

#[tokio::test]
async fn unnegotiated_vpn_flowspec_is_ignored_without_counting() {
    let (mut session, mut rib_rx) = session_with(vec![(Afi::Ipv4, Safi::Unicast)]);

    session
        .process_update(announcement(vec![vpn_rule(40)]))
        .await;

    assert_eq!(discarded(&session), Vec::new());
    assert!(rib_rx.try_recv().is_err());
}

#[test]
fn vpn_flowspec_route_refresh_is_never_requested() {
    let (mut session, _rib_rx) = session_with(vec![
        (Afi::Ipv4, Safi::FlowSpec),
        (Afi::Ipv4, Safi::FlowSpecVpn),
    ]);
    // No writer is installed, so any real request fails to enqueue.
    assert!(
        session
            .send_route_refresh(Afi::Ipv4, Safi::FlowSpec)
            .is_err()
    );
    assert_eq!(
        session.send_route_refresh(Afi::Ipv4, Safi::FlowSpecVpn),
        Ok(())
    );
}

fn refresh_capable_vpn_session() -> (PeerSession, tokio::sync::mpsc::Receiver<RibUpdate>) {
    let (mut session, rib_rx) = session_with(vec![
        (Afi::Ipv4, Safi::Unicast),
        (Afi::Ipv4, Safi::FlowSpecVpn),
    ]);
    let mut negotiated = session.negotiated.as_deref().unwrap().clone();
    negotiated.peer_route_refresh = true;
    session.negotiated = Some(Arc::new(negotiated));
    (session, rib_rx)
}

/// The families of the ROUTE-REFRESH messages in `messages`, in order.
fn refresh_requests(messages: &[Message]) -> Vec<(u16, u8)> {
    messages
        .iter()
        .filter_map(|message| match message {
            Message::RouteRefresh(request) => Some((request.afi_raw, request.safi_raw)),
            _ => None,
        })
        .collect()
}

#[tokio::test]
async fn rib_requested_refresh_skips_vpn_flowspec_on_the_paced_path() {
    let (mut session, _rib_rx) = refresh_capable_vpn_session();
    let (bulk, mut receiver) = tokio::sync::mpsc::channel(8);
    session.writer_bulk_tx = Some(bulk);
    let update = OutboundRouteUpdate {
        exact_export_snapshot: Some(session.publish_export_profile()),
        request_refresh_all_negotiated: true,
        end_of_rib: vec![(Afi::Ipv4, Safi::Unicast)],
        ..OutboundRouteUpdate::default()
    };
    session.handle_outbound_route_update(update).await;
    let mut messages = Vec::new();
    loop {
        while let Ok(mut bytes) = receiver.try_recv() {
            messages.push(
                rustbgpd_wire::decode_message(&mut bytes, rustbgpd_wire::MAX_MESSAGE_LEN).unwrap(),
            );
        }
        if session.pending_outbound.is_none() {
            break;
        }
        session.advance_pending_outbound();
    }
    assert_eq!(
        refresh_requests(&messages),
        [(Afi::Ipv4 as u16, Safi::Unicast as u8)]
    );
}

#[tokio::test]
async fn rib_requested_refresh_skips_vpn_flowspec_on_the_direct_path() {
    let (mut session, _rib_rx) = refresh_capable_vpn_session();
    let (client, mut server) = connected_stream_pair().await;
    session.test_install_stream(client);
    session.send_route_update(OutboundRouteUpdate {
        exact_export_snapshot: Some(session.publish_export_profile()),
        request_refresh_all_negotiated: true,
        end_of_rib: vec![(Afi::Ipv4, Safi::Unicast)],
        ..OutboundRouteUpdate::default()
    });
    let first = read_message(&mut server).await;
    let second = read_message(&mut server).await;
    assert_eq!(
        refresh_requests(&[first]),
        [(Afi::Ipv4 as u16, Safi::Unicast as u8)]
    );
    assert!(
        matches!(second, Message::Update(_)),
        "the IPv4 End-of-RIB follows; no VPN FlowSpec request precedes it: {second:?}"
    );
}

/// One `SendRouteRefresh` through command dispatch, as a soft reset sends it.
async fn refresh(session: &mut PeerSession, safi: Safi) -> Result<(), PeerCommandError> {
    let (reply, response) = tokio::sync::oneshot::channel();
    let _ = session
        .handle_command(PeerCommand::SendRouteRefresh {
            afi: Afi::Ipv4,
            safi,
            reply,
        })
        .await;
    response.await.unwrap()
}

#[tokio::test]
async fn soft_reset_of_vpn_flowspec_needs_no_route_refresh_capability() {
    let (mut session, _rib_rx) = make_test_session_with_rib(65001, 65002);
    let (client, _server) = connected_stream_pair().await;
    session.test_install_stream(client);
    establish_test_session(&mut session, 65002).await;
    let mut negotiated = negotiated_session(65002, false);
    negotiated.peer_route_refresh = false;
    negotiated.negotiated_families =
        vec![(Afi::Ipv4, Safi::Unicast), (Afi::Ipv4, Safi::FlowSpecVpn)];
    session.negotiated = Some(Arc::new(negotiated));
    assert!(refresh(&mut session, Safi::FlowSpecVpn).await.is_ok());
    assert!(matches!(
        refresh(&mut session, Safi::Unicast).await,
        Err(PeerCommandError::RouteRefreshUnsupported)
    ));
    // The family must still be negotiated.
    let mut negotiated = session.negotiated.as_deref().unwrap().clone();
    negotiated.negotiated_families = vec![(Afi::Ipv4, Safi::Unicast)];
    session.negotiated = Some(Arc::new(negotiated));
    assert!(matches!(
        refresh(&mut session, Safi::FlowSpecVpn).await,
        Err(PeerCommandError::FamilyNotNegotiated { .. })
    ));
}

/// ADR-0146 slice 2: VPN rules leave as AFI 1 / SAFI 134 with their RD, and
/// global rules with the same components as SAFI 133. Interleaved in one
/// outbound batch with the same attributes, the families are partitioned
/// into their own UPDATEs and no rule is lost. Withdrawals follow the same
/// split.
///
/// Break-to-red: grouping by AFI alone puts the VPN rule into the SAFI 133
/// UPDATE without its RD.
#[tokio::test]
async fn vpn_and_global_flowspec_leave_in_separate_updates() {
    let (mut session, _rib_rx) = session_with(vec![
        (Afi::Ipv4, Safi::FlowSpec),
        (Afi::Ipv4, Safi::FlowSpecVpn),
    ]);
    let (client, mut server) = connected_stream_pair().await;
    session.test_install_stream(client);
    let vpn = vpn_rule(40);
    let other = FlowSpecRule {
        components: vec![FlowSpecComponent::DestinationPrefix(FlowSpecPrefix::V4(
            Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 11), 32),
        ))],
    };
    let route = |rd, rule: &FlowSpecRule| FlowSpecRoute {
        rule: rule.clone(),
        afi: Afi::Ipv4,
        rd,
        peer: PeerId::from_addr("192.0.2.1".parse().unwrap()),
        attributes: vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath { segments: vec![] }),
        ],
        received_at: Instant::now(),
        origin_type: rustbgpd_rib::RouteOrigin::Local,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        is_stale: false,
        is_llgr_stale: false,
        path_id: 0,
    };
    session.send_route_update(OutboundRouteUpdate {
        exact_export_snapshot: Some(session.publish_export_profile()),
        flowspec_announce: vec![
            route(None, &vpn.rule),
            route(Some(vpn.rd), &vpn.rule),
            route(None, &other),
        ],
        ..OutboundRouteUpdate::default()
    });
    let mut reaches = Vec::new();
    for _ in 0..2 {
        let Message::Update(update) = read_message(&mut server).await else {
            panic!("expected a FlowSpec announcement");
        };
        let parsed = update.parse(true, false, &[]).unwrap();
        let mut mps = parsed.attributes.into_iter().filter_map(|attr| match attr {
            PathAttribute::MpReachNlri(mp) => Some(*mp),
            _ => None,
        });
        reaches.push(mps.next().unwrap());
        assert!(mps.next().is_none());
    }
    assert_eq!(reaches[0].safi, Safi::FlowSpec);
    assert_eq!(
        reaches[0].flowspec_announced,
        [vpn.rule.clone(), other.clone()]
    );
    assert_eq!(reaches[0].vpn_flowspec_announced, []);
    assert_eq!(reaches[1].safi, Safi::FlowSpecVpn);
    assert_eq!(reaches[1].flowspec_announced, []);
    assert_eq!(
        reaches[1].vpn_flowspec_announced,
        std::slice::from_ref(&vpn)
    );

    let key = |rd, rule: &FlowSpecRule| rustbgpd_rib::FlowSpecKey {
        afi: Afi::Ipv4,
        rd,
        rule: rule.clone(),
    };
    session.send_route_update(OutboundRouteUpdate {
        exact_export_snapshot: Some(session.publish_export_profile()),
        flowspec_withdraw: vec![
            key(Some(vpn.rd), &vpn.rule),
            key(None, &vpn.rule),
            key(None, &other),
        ],
        ..OutboundRouteUpdate::default()
    });
    let mut unreaches = Vec::new();
    for _ in 0..2 {
        let Message::Update(update) = read_message(&mut server).await else {
            panic!("expected a FlowSpec withdrawal");
        };
        let parsed = update.parse(true, false, &[]).unwrap();
        unreaches.extend(parsed.attributes.into_iter().filter_map(|attr| match attr {
            PathAttribute::MpUnreachNlri(mp) => Some(*mp),
            _ => None,
        }));
    }
    assert_eq!(unreaches.len(), 2);
    assert_eq!(unreaches[0].safi, Safi::FlowSpec);
    assert_eq!(unreaches[0].flowspec_withdrawn, [vpn.rule.clone(), other]);
    assert_eq!(unreaches[1].safi, Safi::FlowSpecVpn);
    assert_eq!(unreaches[1].vpn_flowspec_withdrawn, [vpn]);
}

/// One outbound batch carrying a VPN withdrawal, a VPN announcement and the
/// family's End-of-RIB sends all three in order: a successful VPN send never
/// cuts the rest of the batch short.
#[tokio::test]
async fn a_vpn_flowspec_batch_sends_every_section() {
    let (mut session, _rib_rx) = session_with(vec![(Afi::Ipv4, Safi::FlowSpecVpn)]);
    let (client, mut server) = connected_stream_pair().await;
    session.test_install_stream(client);
    let withdrawn = vpn_rule(40);
    let announced = vpn_rule(41);
    session.send_route_update(OutboundRouteUpdate {
        exact_export_snapshot: Some(session.publish_export_profile()),
        flowspec_withdraw: vec![rustbgpd_rib::FlowSpecKey {
            afi: Afi::Ipv4,
            rd: Some(withdrawn.rd),
            rule: withdrawn.rule.clone(),
        }],
        flowspec_announce: vec![FlowSpecRoute {
            rule: announced.rule.clone(),
            afi: Afi::Ipv4,
            rd: Some(announced.rd),
            peer: PeerId::from_addr("192.0.2.1".parse().unwrap()),
            attributes: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath { segments: vec![] }),
            ],
            received_at: Instant::now(),
            origin_type: rustbgpd_rib::RouteOrigin::Local,
            peer_router_id: Ipv4Addr::UNSPECIFIED,
            is_stale: false,
            is_llgr_stale: false,
            path_id: 0,
        }],
        end_of_rib: vec![(Afi::Ipv4, Safi::FlowSpecVpn)],
        ..OutboundRouteUpdate::default()
    });
    let mut seen = Vec::new();
    for _ in 0..3 {
        let Message::Update(update) = read_message(&mut server).await else {
            panic!("expected an UPDATE");
        };
        for attr in update.parse(true, false, &[]).unwrap().attributes {
            match attr {
                PathAttribute::MpUnreachNlri(mp) if mp.vpn_flowspec_withdrawn.is_empty() => {
                    seen.push("end-of-rib");
                }
                PathAttribute::MpUnreachNlri(mp) => {
                    assert_eq!(mp.vpn_flowspec_withdrawn, std::slice::from_ref(&withdrawn));
                    seen.push("withdrawal");
                }
                PathAttribute::MpReachNlri(mp) => {
                    assert_eq!(mp.vpn_flowspec_announced, std::slice::from_ref(&announced));
                    seen.push("announcement");
                }
                _ => {}
            }
        }
    }
    assert_eq!(seen, ["withdrawal", "announcement", "end-of-rib"]);
}
