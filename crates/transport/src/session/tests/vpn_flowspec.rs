//! ADR-0146: received VPN `FlowSpec` (AFI 1/2 / SAFI 134) is decoded, counted
//! and discarded, so it never reaches the RIB; locally originated VPN rules
//! leave as SAFI 134 with their Route Distinguisher.

use super::*;
use rustbgpd_wire::{
    Ipv4UnicastMode, MpReachNlri, MpUnreachNlri, ParsedUpdate, UpdateMessage, VpnFlowSpecRule,
};
use std::collections::HashSet;

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
        attributes: vec![
            reach(Afi::Ipv4, vec![vpn_rule(Afi::Ipv4, 40)]),
            unreach(Afi::Ipv4, vec![vpn_rule(Afi::Ipv4, 41)]),
        ],
        announced: Vec::new(),
        bgpls_nlri_discarded: 0,
    };
    let rule = vpn_rule(Afi::Ipv4, 40).to_string();
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
    assert!(
        involved.contains(&vpn_rule(Afi::Ipv4, 41).to_string()),
        "{involved}"
    );
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
            reach(Afi::Ipv4, vec![vpn_rule(Afi::Ipv4, 40)]),
        ]))
        .await;
    // Missing mandatory ORIGIN: an RFC 7606 treat-as-withdraw.
    session
        .process_update(update(&[
            PathAttribute::AsPath(AsPath {
                segments: vec![AsPathSegment::AsSequence(vec![65002])],
            }),
            reach(Afi::Ipv4, vec![vpn_rule(Afi::Ipv4, 41)]),
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

fn vpn_rule(afi: Afi, assigned: u8) -> VpnFlowSpecRule {
    let prefix = if afi == Afi::Ipv6 {
        FlowSpecPrefix::V6(Ipv6PrefixOffset {
            prefix: Ipv6Prefix::new("2001:db8::10".parse().unwrap(), 128),
            offset: 0,
        })
    } else {
        FlowSpecPrefix::V4(Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 10), 32))
    };
    VpnFlowSpecRule {
        rd: RouteDistinguisher([0, 0, 0xad, 0x77, 0, 0, 0, assigned]),
        rule: FlowSpecRule {
            components: vec![FlowSpecComponent::DestinationPrefix(prefix)],
        },
    }
}

fn reach(afi: Afi, rules: Vec<VpnFlowSpecRule>) -> PathAttribute {
    PathAttribute::MpReachNlri(Box::new(MpReachNlri {
        afi,
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

fn unreach(afi: Afi, rules: Vec<VpnFlowSpecRule>) -> PathAttribute {
    PathAttribute::MpUnreachNlri(Box::new(MpUnreachNlri {
        afi,
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

fn announcement(afi: Afi, rules: Vec<VpnFlowSpecRule>) -> UpdateMessage {
    update(&[
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath {
            segments: vec![AsPathSegment::AsSequence(vec![65002])],
        }),
        reach(afi, rules),
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
    use crate::config::{MaxPrefixAction, PrefixLimitFamily};

    for afi in [Afi::Ipv4, Afi::Ipv6] {
        let (mut session, mut rib_rx) = session_with(vec![
            (Afi::Ipv4, Safi::Unicast),
            (afi, Safi::FlowSpec),
            (afi, Safi::FlowSpecVpn),
        ]);
        session.config.max_prefixes = Some(1);
        session.config.max_prefixes_family.0[PrefixLimitFamily::Ipv4Flowspec as usize] = Some(1);
        session.config.max_prefixes_family.0[PrefixLimitFamily::Ipv6Flowspec as usize] = Some(1);
        session.config.max_prefix_action = MaxPrefixAction::Block;
        session.config.max_prefix_warning_percent = Some(100);
        // A real global UPDATE proves that the same receive path stores and
        // accounts rules; its sibling VPN withdrawal must never remove it.
        let PathAttribute::MpReachNlri(mut global) = reach(afi, vec![]) else {
            unreachable!()
        };
        global.safi = Safi::FlowSpec;
        global.flowspec_announced = vec![vpn_rule(afi, 40).rule];
        session
            .process_update(update(&[
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath {
                    segments: vec![AsPathSegment::AsSequence(vec![65002])],
                }),
                PathAttribute::MpReachNlri(global),
            ]))
            .await;
        assert!(
            matches!(rib_rx.try_recv(), Ok(RibUpdate::RoutesReceived { flowspec_announced, .. }) if flowspec_announced.len() == 1)
        );
        assert_eq!(session.known_prefix_count(), 1);
        let known = session.known_flowspec.clone();
        let counts = session.flowspec_counts;
        assert_eq!(counts, if afi == Afi::Ipv4 { [1, 0] } else { [0, 1] });
        let warned = session.max_prefix_warned;
        let blocking = session.max_prefix_blocking;

        session
            .process_update(announcement(
                afi,
                vec![vpn_rule(afi, 40), vpn_rule(afi, 41)],
            ))
            .await;
        session
            .process_update(update(&[unreach(afi, vec![vpn_rule(afi, 40)])]))
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
        assert_eq!(session.known_flowspec, known);
        assert_eq!(session.flowspec_counts, counts);
        assert_eq!(session.known_prefix_count(), 1);
        assert_eq!(
            session.family_prefix_usage(PrefixLimitFamily::Ipv4Flowspec),
            counts[0]
        );
        assert_eq!(
            session.family_prefix_usage(PrefixLimitFamily::Ipv6Flowspec),
            counts[1]
        );
        assert_eq!(session.max_prefix_warned, warned);
        assert_eq!(session.max_prefix_blocking, blocking);

        let PathAttribute::MpUnreachNlri(mut global) = unreach(afi, vec![]) else {
            unreachable!()
        };
        global.safi = Safi::FlowSpec;
        global.flowspec_withdrawn = vec![vpn_rule(afi, 40).rule];
        session
            .process_update(update(&[PathAttribute::MpUnreachNlri(global)]))
            .await;
        assert!(
            matches!(rib_rx.try_recv(), Ok(RibUpdate::RoutesReceived { flowspec_withdrawn, .. }) if flowspec_withdrawn.len() == 1)
        );
        assert_eq!(session.known_prefix_count(), 0);
        assert!(session.known_flowspec.is_empty());
        assert_eq!(session.flowspec_counts, [0, 0]);
    }
}

#[tokio::test]
async fn vpn_flowspec_end_of_rib_is_accepted_and_not_counted() {
    for afi in [Afi::Ipv4, Afi::Ipv6] {
        let (mut session, mut rib_rx) =
            session_with(vec![(Afi::Ipv4, Safi::Unicast), (afi, Safi::FlowSpecVpn)]);
        session
            .process_update(update(&[unreach(afi, vec![])]))
            .await;
        assert!(
            matches!(rib_rx.try_recv(), Ok(RibUpdate::EndOfRib { afi: received_afi, safi: Safi::FlowSpecVpn, .. }) if received_afi == afi)
        );
        assert!(
            session
                .received_eor_families
                .contains(&(afi, Safi::FlowSpecVpn))
        );
        assert_eq!(discarded(&session), Vec::new());
    }
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
    for (afi, other) in [(Afi::Ipv4, Afi::Ipv6), (Afi::Ipv6, Afi::Ipv4)] {
        let (mut session, mut rib_rx) = session_with(vec![
            (Afi::Ipv4, Safi::Unicast),
            (afi, Safi::FlowSpec),
            (other, Safi::FlowSpecVpn),
        ]);
        session
            .process_update(announcement(afi, vec![vpn_rule(afi, 40)]))
            .await;
        assert_eq!(discarded(&session), Vec::new());
        assert!(rib_rx.try_recv().is_err());
        assert!(session.known_flowspec.is_empty());
        assert_eq!(session.flowspec_counts, [0, 0]);
    }
}

#[test]
fn vpn_flowspec_route_refresh_is_never_requested() {
    for afi in [Afi::Ipv4, Afi::Ipv6] {
        let (mut session, _rib_rx) =
            session_with(vec![(afi, Safi::FlowSpec), (afi, Safi::FlowSpecVpn)]);
        // No writer is installed, so any real request fails to enqueue.
        assert!(session.send_route_refresh(afi, Safi::FlowSpec).is_err());
        assert_eq!(session.send_route_refresh(afi, Safi::FlowSpecVpn), Ok(()));
    }
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

/// ADR-0146 slice 2: VPN rules leave as AFI 1/2 / SAFI 134 with their RD, and
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
    let vpn = vpn_rule(Afi::Ipv4, 40);
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
        attributes: AttrSet::new(vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath { segments: vec![] }),
        ]),
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
    let withdrawn = vpn_rule(Afi::Ipv4, 40);
    let announced = vpn_rule(Afi::Ipv4, 41);
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
            attributes: AttrSet::new(vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath { segments: vec![] }),
            ]),
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

#[tokio::test]
async fn dual_stack_vpn_and_global_flowspec_batches_keep_each_family_separate() {
    let families = vec![
        (Afi::Ipv4, Safi::FlowSpec),
        (Afi::Ipv6, Safi::FlowSpec),
        (Afi::Ipv4, Safi::FlowSpecVpn),
        (Afi::Ipv6, Safi::FlowSpecVpn),
    ];
    let (mut session, _rib_rx) = session_with(families.clone());
    let (client, mut server) = connected_stream_pair().await;
    session.test_install_stream(client);
    let routes: Vec<_> = families
        .iter()
        .rev()
        .map(|&(afi, safi)| {
            let vpn = vpn_rule(afi, 40);
            FlowSpecRoute {
                rule: vpn.rule,
                afi,
                rd: (safi == Safi::FlowSpecVpn).then_some(vpn.rd),
                peer: PeerId::from_addr("192.0.2.1".parse().unwrap()),
                attributes: AttrSet::new(vec![
                    PathAttribute::Origin(Origin::Igp),
                    PathAttribute::AsPath(AsPath { segments: vec![] }),
                ]),
                received_at: Instant::now(),
                origin_type: rustbgpd_rib::RouteOrigin::Local,
                peer_router_id: Ipv4Addr::UNSPECIFIED,
                is_stale: false,
                is_llgr_stale: false,
                path_id: 0,
            }
        })
        .collect();
    let withdrawals = routes.iter().map(FlowSpecRoute::selection_key).collect();
    session.send_route_update(OutboundRouteUpdate {
        exact_export_snapshot: Some(session.publish_export_profile()),
        flowspec_announce: routes,
        ..OutboundRouteUpdate::default()
    });
    let mut seen = HashSet::new();
    for _ in &families {
        let Message::Update(update) = read_message(&mut server).await else {
            panic!("expected UPDATE")
        };
        let parsed = update.parse(true, false, &[]).unwrap();
        let reaches: Vec<_> = parsed
            .attributes
            .into_iter()
            .filter_map(|attr| match attr {
                PathAttribute::MpReachNlri(mp) => Some(mp),
                _ => None,
            })
            .collect();
        assert_eq!(reaches.len(), 1);
        let mp = &reaches[0];
        assert!(seen.insert((mp.afi, mp.safi)));
        let vpn = vpn_rule(mp.afi, 40);
        if mp.safi == Safi::FlowSpecVpn {
            assert_eq!(mp.vpn_flowspec_announced, [vpn]);
            assert_eq!(mp.flowspec_announced.len(), 0);
        } else {
            assert_eq!(mp.flowspec_announced, [vpn.rule]);
            assert_eq!(mp.vpn_flowspec_announced.len(), 0);
        }
    }
    assert_eq!(seen, families.iter().copied().collect());
    session.send_route_update(OutboundRouteUpdate {
        exact_export_snapshot: Some(session.publish_export_profile()),
        flowspec_withdraw: withdrawals,
        ..OutboundRouteUpdate::default()
    });
    let mut seen = HashSet::new();
    for _ in &families {
        let Message::Update(update) = read_message(&mut server).await else {
            panic!("expected UPDATE")
        };
        let parsed = update.parse(true, false, &[]).unwrap();
        let unreaches: Vec<_> = parsed
            .attributes
            .into_iter()
            .filter_map(|attr| match attr {
                PathAttribute::MpUnreachNlri(mp) => Some(mp),
                _ => None,
            })
            .collect();
        assert_eq!(unreaches.len(), 1);
        let mp = &unreaches[0];
        assert!(seen.insert((mp.afi, mp.safi)));
        let vpn = vpn_rule(mp.afi, 40);
        if mp.safi == Safi::FlowSpecVpn {
            assert_eq!(mp.vpn_flowspec_withdrawn, [vpn]);
            assert_eq!(mp.flowspec_withdrawn.len(), 0);
        } else {
            assert_eq!(mp.flowspec_withdrawn, [vpn.rule]);
            assert_eq!(mp.vpn_flowspec_withdrawn.len(), 0);
        }
    }
    assert_eq!(seen, families.iter().copied().collect());
}
