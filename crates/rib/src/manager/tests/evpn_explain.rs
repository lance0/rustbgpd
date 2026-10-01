use super::*;
use crate::attr_set::AttrSet;
use crate::best_path::BestPathReason;
use crate::update::{ExplainDecision, ExplainEvpnRoute, ExportGateVerdict};

const SOURCE: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
const TARGET: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9));

fn fixture() -> (
    RibManager,
    mpsc::Receiver<OutboundRouteUpdate>,
    EvpnRibRoute,
) {
    let (_tx, rx) = mpsc::channel(8);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let (out_tx, out_rx) = mpsc::channel(8);
    manager.outbound_peers.insert(TARGET, out_tx);
    manager
        .peer_sendable_families
        .insert(TARGET, evpn_sendable());
    manager.peer_is_ebgp.insert(TARGET, true);
    manager.peer_interpret_rfc1997.insert(TARGET);
    let route = super::evpn::make_evpn_macip(SOURCE, [2, 0, 0, 0, 0, 1], Some(1), false);
    install(&mut manager, &route);
    (manager, out_rx, route)
}

fn install(manager: &mut RibManager, route: &EvpnRibRoute) {
    manager
        .ribs
        .entry(route.peer)
        .or_insert_with(|| AdjRibIn::new(route.peer))
        .insert_evpn(route.clone());
    manager
        .loc_rib
        .recompute_evpn(route.key(), std::iter::once(route));
}

fn query(
    manager: &mut RibManager,
    key: rustbgpd_wire::EvpnRouteKey,
    received_from: Option<IpAddr>,
    advertised_to: Option<IpAddr>,
) -> ExplainEvpnRoute {
    let (reply, mut rx) = oneshot::channel();
    manager.handle_update(RibUpdate::ExplainEvpnRoute {
        key,
        received_from,
        advertised_to,
        srv6_argument_companion: None,
        reply,
    });
    rx.try_recv().expect("exact actor query replied")
}

fn policy(body: &str) -> rustbgpd_policy::PolicyChain {
    let text = format!("policy fabric {{ term selected-term {{ {body} }} }}");
    let compiled = rustbgpd_policy::rpol::RpolFile::parse(&text)
        .unwrap()
        .compile_policy("fabric", &[], &mut rustbgpd_policy::sets::SetStore::new())
        .unwrap();
    rustbgpd_policy::PolicyChain::from_named(vec![rustbgpd_policy::NamedPolicy::from_rpol(
        "fabric".to_string(),
        Arc::new(compiled),
    )])
}

#[test]
fn exact_evpn_explain_covers_every_typed_key_without_cross_matching() {
    let (mut manager, _out, _) = fixture();
    for route in super::evpn_dataplane_query::relevant_routes()
        .into_iter()
        .chain(super::evpn_dataplane_query::irrelevant_routes())
    {
        install(&mut manager, &route);
        let explain = query(&mut manager, route.key(), Some(route.peer), None);
        assert_eq!(explain.key, route.key());
        assert_eq!(explain.received.unwrap().route, route.route);
        assert_eq!(explain.best.unwrap().route, route.route);
        assert_eq!(explain.selection_best.unwrap().route, route.route);
        assert_eq!(explain.candidate_count, 1);
        assert!(explain.compared.is_none());
        assert!(explain.reason.is_none());
    }
}

#[test]
fn exact_evpn_explain_freshness_precedes_sticky_and_sequence() {
    for (stale, sticky, sequence, reason) in [
        (true, true, 200, BestPathReason::StalePreference),
        (false, true, 0, BestPathReason::EvpnMacMobility),
        (false, false, 200, BestPathReason::EvpnMacMobility),
    ] {
        let (mut manager, _out, route) = fixture();
        let mut other = super::evpn::make_evpn_macip(
            Ipv4Addr::new(192, 0, 2, 2),
            [2, 0, 0, 0, 0, 1],
            Some(sequence),
            sticky,
        );
        other.is_stale = stale;
        manager
            .ribs
            .entry(other.peer)
            .or_insert_with(|| AdjRibIn::new(other.peer))
            .insert_evpn(other.clone());
        manager
            .loc_rib
            .recompute_evpn(route.key(), [&route, &other].into_iter());
        let expected = if stale { route.peer } else { other.peer };
        let explain = query(&mut manager, route.key(), None, None);
        assert_eq!(explain.best.unwrap().peer, expected);
        assert_eq!(explain.selection_best.unwrap().peer, expected);
        assert_eq!(explain.reason, Some(reason));
        assert_eq!(explain.candidate_count, 2);
        assert!(
            explain
                .reason_detail
                .contains(if stale { "freshness" } else { "sticky=" })
        );
    }
}

#[test]
fn exact_evpn_explain_runs_each_export_stop_in_live_order() {
    for expected in [
        "destination_unavailable",
        "family_not_sendable",
        "no_best_route",
        "no_advertise_suppressed",
        "no_export_suppressed",
        "llgr_stale_suppressed",
        "rt_membership_miss",
        "source_peer",
        "ibgp_split_horizon",
        "policy_denied",
        "no_advertise_policy_suppressed",
    ] {
        let (mut manager, mut out, mut route) = fixture();
        match expected {
            "destination_unavailable" => {
                manager.outbound_peers.remove(&TARGET);
            }
            "family_not_sendable" => {
                manager.peer_sendable_families.remove(&TARGET);
            }
            "no_best_route" => {
                manager.loc_rib.remove_evpn(&route.key());
            }
            "no_advertise_suppressed" => {
                AttrSet::edit(&mut route.attributes, |attrs| {
                    attrs.push(PathAttribute::Communities(vec![
                        rustbgpd_wire::COMMUNITY_NO_ADVERTISE,
                    ]));
                });
                install(&mut manager, &route);
            }
            "no_export_suppressed" => {
                AttrSet::edit(&mut route.attributes, |attrs| {
                    attrs.push(PathAttribute::Communities(vec![
                        rustbgpd_wire::COMMUNITY_NO_EXPORT,
                    ]));
                });
                install(&mut manager, &route);
            }
            "llgr_stale_suppressed" => {
                route.is_llgr_stale = true;
                install(&mut manager, &route);
            }
            "rt_membership_miss" => {
                // RT-Constrain negotiated, no membership: strict empty.
                manager.peer_sendable_families.insert(
                    TARGET,
                    vec![(Afi::L2Vpn, Safi::Evpn), (Afi::Ipv4, Safi::RtConstrain)],
                );
            }
            "source_peer" => {
                route.peer = TARGET;
                install(&mut manager, &route);
            }
            "ibgp_split_horizon" => {
                manager.peer_is_ebgp.insert(TARGET, false);
            }
            "policy_denied" => {
                manager.export_chains.insert(TARGET, Some(policy("reject")));
            }
            "no_advertise_policy_suppressed" => {
                manager
                    .export_chains
                    .insert(TARGET, Some(policy("add community 65535:65282; accept")));
            }
            _ => unreachable!(),
        }
        let explain = query(&mut manager, route.key(), None, Some(TARGET))
            .export
            .unwrap();
        assert_ne!(explain.decision, ExplainDecision::Advertise, "{expected}");
        assert_eq!(explain.gates.last().unwrap().code, expected);
        assert_eq!(
            explain.gates.last().unwrap().verdict,
            ExportGateVerdict::Stop
        );
        assert_eq!(
            explain
                .gates
                .iter()
                .filter(|g| g.verdict == ExportGateVerdict::Stop)
                .count(),
            1
        );
        assert!(explain.staged.is_none());
        if expected == "policy_denied" {
            assert!(explain.reasons[0].message.contains("fabric:selected-term"));
        }
        assert!(
            out.try_recv().is_err(),
            "explain emitted an outbound update"
        );
    }
}

#[test]
fn exact_evpn_explain_preserves_policy_counters_events_and_committed_state() {
    let (mut manager, mut out, route) = fixture();
    let chain = policy("add community 65000:7; accept");
    manager.export_chains.insert(TARGET, Some(chain.share()));
    let before_stats = manager.export_policy_stats.clone();
    let metrics_snapshot = |manager: &RibManager| {
        manager
            .metrics
            .registry()
            .gather()
            .into_iter()
            .filter(|family| family.name().starts_with("bgp_"))
            .map(|family| (family.name().to_string(), format!("{family:?}")))
            .collect::<BTreeMap<_, _>>()
    };
    let before_metrics = metrics_snapshot(&manager);
    let mut events = manager.evpn_events_tx.subscribe();
    let first = query(&mut manager, route.key(), None, Some(TARGET))
        .export
        .unwrap();
    assert_eq!(first.decision, ExplainDecision::Advertise);
    assert_eq!(first.modifications.communities_add, vec![(65000 << 16) | 7]);
    let staged = first.staged.unwrap();
    assert!(staged.communities().contains(&((65000 << 16) | 7)));
    assert!(first.advertised.is_none());
    manager
        .adj_ribs_out
        .entry(TARGET)
        .or_insert_with(|| AdjRibOut::new(TARGET))
        .insert_evpn(staged.clone());
    let second = query(&mut manager, route.key(), None, Some(TARGET))
        .export
        .unwrap();
    assert!(second.already_advertised);
    assert_eq!(second.gates.last().unwrap().code, "already_advertised");
    assert_eq!(second.staged.unwrap().attributes, staged.attributes);
    assert_eq!(second.advertised.unwrap().attributes, staged.attributes);
    assert_eq!(manager.export_policy_stats, before_stats);
    assert_eq!(chain.hit_counters().evals(), 0);
    assert!(
        chain
            .hit_counters()
            .snapshot()
            .iter()
            .flatten()
            .all(|hits| *hits == 0)
    );
    let after_metrics = metrics_snapshot(&manager);
    for (name, before) in before_metrics {
        assert_eq!(
            after_metrics.get(&name),
            Some(&before),
            "metric {name} changed"
        );
    }
    assert!(events.try_recv().is_err());
    assert!(manager.evpn_route_event_history.is_empty());
    assert!(out.try_recv().is_err());
}

#[test]
fn exact_evpn_explain_source_scope_deferral_dirty_and_encoder_overlay_are_distinct() {
    let (manager, mut out, old) = fixture();
    let mut manager = manager.with_selection_deferral(crate::SelectionDeferralConfig {
        timeout: Duration::from_secs(60),
        waiters: vec![crate::SelectionDeferralWaiterConfig {
            peer: old.peer,
            families: evpn_sendable(),
        }],
    });
    manager
        .adj_ribs_out
        .entry(TARGET)
        .or_insert_with(|| AdjRibOut::new(TARGET))
        .insert_evpn(old.clone());
    let mut fresh = old.clone();
    fresh.peer = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2));
    AttrSet::edit(&mut fresh.attributes, |attrs| {
        attrs.push(PathAttribute::LocalPref(250));
    });
    manager
        .ribs
        .entry(fresh.peer)
        .or_insert_with(|| AdjRibIn::new(fresh.peer))
        .insert_evpn(fresh.clone());
    manager.dirty_peers.insert(TARGET);
    let explain = query(&mut manager, old.key(), Some(old.peer), Some(TARGET));
    assert!(explain.selection_deferred);
    assert_eq!(explain.best.unwrap().peer, old.peer);
    assert_eq!(explain.selection_best.unwrap().peer, fresh.peer);
    assert_eq!(explain.received.unwrap().peer, old.peer);
    assert_eq!(explain.compared.unwrap().peer, old.peer);
    assert_eq!(explain.reason, Some(BestPathReason::HigherLocalPref));
    let export = explain.export.unwrap();
    assert!(export.outbound_dirty);
    assert_eq!(
        export.staged.unwrap().peer,
        old.peer,
        "source query cannot replace installed export winner"
    );
    assert_eq!(export.advertised.unwrap().peer, old.peer);
    manager
        .peer_unexportable
        .entry(TARGET)
        .or_default()
        .insert(ExactExportKey::Evpn(old.key()));
    let rejected = query(&mut manager, old.key(), Some(fresh.peer), Some(TARGET))
        .export
        .unwrap();
    assert_eq!(rejected.decision, ExplainDecision::Deny);
    assert_eq!(rejected.reasons[0].code, "exact_export_rejected");
    assert!(rejected.staged.is_none());
    assert!(!rejected.already_advertised);
    assert!(rejected.advertised.is_some());
    assert!(manager.dirty_peers.contains(&TARGET));
    assert!(out.try_recv().is_err());
    let missing = query(&mut manager, old.key(), Some(TARGET), None);
    assert!(missing.received.is_none());
    assert!(missing.reason.is_none());
    assert!(
        missing
            .reason_detail
            .contains("import rejection history is not retained")
    );
}

fn argument_routes(argument: u16) -> (EvpnRibRoute, EvpnRibRoute) {
    use rustbgpd_wire::{EthernetSegmentIdentifier, EvpnEadPerEs};
    let mut imet = make_evpn_imet(SOURCE, 100);
    imet.attributes = AttrSet::new(vec![crate::srv6::tests::service_attribute(
        6,
        "2001:db8:1:fbd1:fbd1::".parse().unwrap(),
        124,
        Some([32, 16, 32, 16, 0, 0]),
    )]);
    let mut ead = imet.clone();
    ead.route = EvpnRoute::EadPerEs(EvpnEadPerEs {
        rd: "65000:200".parse().unwrap(),
        esi: EthernetSegmentIdentifier::new([1; 10]),
        ethernet_tag: EthernetTagId::MAX_ET,
        // Deliberately different from the Argument: this is never its source.
        label: rustbgpd_wire::MplsLabel::new(0x0012_3456),
    });
    ead.next_hop = "2001:db8::99".parse().unwrap();
    ead.attributes = AttrSet::new(vec![crate::srv6::tests::service_attribute(
        6,
        std::net::Ipv6Addr::from(u128::from(argument) << 48),
        68,
        Some([32, 16, 16, 16, 0, 0]),
    )]);
    (imet, ead)
}

fn argument_query(
    manager: &mut RibManager,
    imet: &EvpnRibRoute,
    ead: &EvpnRibRoute,
    received_from: Option<IpAddr>,
    advertised_to: Option<IpAddr>,
) -> crate::update::ExplainSrv6Argument {
    let (reply, mut rx) = oneshot::channel();
    manager.handle_update(RibUpdate::ExplainEvpnRoute {
        key: imet.key(),
        received_from,
        advertised_to,
        srv6_argument_companion: Some(ead.key()),
        reply,
    });
    rx.try_recv().unwrap().srv6_argument.unwrap()
}

#[test]
fn srv6_argument_snapshots_keep_best_received_and_committed_advertised_separate() {
    use crate::update::{RouteQueryScope, Srv6ArgumentStatus as Status};
    let (mut manager, mut out, _) = fixture();
    let (imet, installed) = argument_routes(0xaaaa);
    install(&mut manager, &imet);
    install(&mut manager, &installed);
    let (_, mut received) = argument_routes(0xbbbb);
    AttrSet::edit(&mut received.attributes, |attrs| {
        attrs.push(PathAttribute::LocalPref(200));
    });
    manager
        .ribs
        .get_mut(&received.peer)
        .unwrap()
        .insert_evpn(received.clone());
    // The installed pair is intentionally older than fresh candidate selection.
    let (_, committed) = argument_routes(0xcccc);
    let mut rib_out = AdjRibOut::new(TARGET);
    rib_out.insert_evpn(imet.clone());
    rib_out.insert_evpn(committed.clone());
    manager.adj_ribs_out.insert(TARGET, rib_out);
    let before_stats = manager.export_policy_stats.clone();
    let mut events = manager.evpn_events_tx.subscribe();
    for (received_from, advertised_to, scope, expected, attributes) in [
        (
            None,
            None,
            RouteQueryScope::Best,
            "2001:db8:1:fbd1:fbd1:aaaa::",
            &installed.attributes,
        ),
        (
            Some(imet.peer),
            None,
            RouteQueryScope::Received {
                peer: Some(imet.peer),
            },
            "2001:db8:1:fbd1:fbd1:bbbb::",
            &received.attributes,
        ),
        (
            None,
            Some(TARGET),
            RouteQueryScope::Advertised { peer: TARGET },
            "2001:db8:1:fbd1:fbd1:cccc::",
            &committed.attributes,
        ),
    ] {
        let result = argument_query(
            &mut manager,
            &imet,
            &installed,
            received_from,
            advertised_to,
        );
        assert_eq!(result.status, Status::Composed);
        assert_eq!(result.sid, Some(expected.parse().unwrap()));
        assert_eq!(result.scope, scope);
        assert_eq!(result.companion_key, installed.key());
        assert_eq!(&result.companion.unwrap().attributes, attributes);
        assert_eq!(result.association, "caller_selected");
    }
    assert_eq!(manager.export_policy_stats, before_stats);
    assert!(events.try_recv().is_err());
    assert!(out.try_recv().is_err());
    // A staged export remains available but cannot fill a missing committed pair.
    manager
        .adj_ribs_out
        .get_mut(&TARGET)
        .unwrap()
        .remove_evpn(&installed.key());
    let absent = argument_query(&mut manager, &imet, &installed, None, Some(TARGET));
    assert_eq!(absent.status, Status::LocFuncOnly);
    assert!(absent.companion.is_none());
    assert_eq!(absent.sid, Some("2001:db8:1:fbd1:fbd1::".parse().unwrap()));
    manager
        .adj_ribs_out
        .get_mut(&TARGET)
        .unwrap()
        .remove_evpn(&imet.key());
    assert_eq!(
        argument_query(&mut manager, &imet, &installed, None, Some(TARGET)).status,
        Status::Unavailable
    );
}

#[test]
fn srv6_argument_exact_pair_tracks_replacement_withdrawal_and_reannouncement() {
    use crate::update::Srv6ArgumentStatus as Status;
    let (_tx, rx) = mpsc::channel(8);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let (imet, ead) = argument_routes(0xaaaa);
    let receive = |manager: &mut RibManager, announced, withdrawn| {
        manager.handle_update(RibUpdate::RoutesReceived {
            session_id: 0,
            peer: imet.peer,
            announced: vec![],
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
            evpn_announced: announced,
            evpn_withdrawn: withdrawn,
            validated_with: None,
        });
        while manager.process_next_route_chunk() {}
    };
    receive(&mut manager, vec![imet.clone(), ead.clone()], vec![]);
    assert_eq!(
        argument_query(&mut manager, &imet, &ead, None, None).sid,
        Some("2001:db8:1:fbd1:fbd1:aaaa::".parse().unwrap())
    );
    let (_, replacement) = argument_routes(0xbbbb);
    receive(&mut manager, vec![replacement], vec![]);
    assert_eq!(
        argument_query(&mut manager, &imet, &ead, None, None).sid,
        Some("2001:db8:1:fbd1:fbd1:bbbb::".parse().unwrap())
    );
    receive(&mut manager, vec![], vec![ead.key()]);
    for scope in [None, Some(imet.peer)] {
        let absent = argument_query(&mut manager, &imet, &ead, scope, None);
        assert_eq!(absent.status, Status::LocFuncOnly);
        assert!(absent.companion.is_none());
    }
    receive(&mut manager, vec![ead.clone()], vec![]);
    assert_eq!(
        argument_query(&mut manager, &imet, &ead, None, None).status,
        Status::Composed
    );
    receive(&mut manager, vec![], vec![imet.key()]);
    assert_eq!(
        argument_query(&mut manager, &imet, &ead, None, None).status,
        Status::Unavailable
    );
}

#[test]
fn srv6_argument_route_wrapper_uses_esi_community_and_ignores_malformed_companion_for_zero_al() {
    use crate::update::Srv6ArgumentStatus as Status;
    use rustbgpd_wire::{ExtendedCommunity, RawAttribute};
    let (mut imet, mut ead) = argument_routes(0);
    ead.attributes = AttrSet::new(vec![
        crate::srv6::tests::service_attribute(
            6,
            "::".parse().unwrap(),
            24,
            Some([32, 16, 16, 16, 16, 64]),
        ),
        PathAttribute::ExtendedCommunities(vec![ExtendedCommunity::esi_label(false, 0x00aa_aa00)]),
    ]);
    let result = crate::srv6::inspect_argument_pair(Some(&imet), Some(&ead));
    assert_eq!(result.status, Status::Composed);
    assert_eq!(
        result.sid,
        Some("2001:db8:1:fbd1:fbd1:aaaa::".parse().unwrap())
    );
    AttrSet::edit(&mut ead.attributes, |attrs| {
        attrs.retain(|attr| !matches!(attr, PathAttribute::ExtendedCommunities(_)));
    });
    assert_eq!(
        crate::srv6::inspect_argument_pair(Some(&imet), Some(&ead)).status,
        Status::Unavailable
    );
    AttrSet::edit(&mut ead.attributes, |attrs| {
        attrs.push(PathAttribute::ExtendedCommunities(vec![
            ExtendedCommunity::esi_label(false, 0x00aa_aa00),
            ExtendedCommunity::esi_label(false, 0x00bb_bb00),
        ]));
    });
    assert_eq!(
        crate::srv6::inspect_argument_pair(Some(&imet), Some(&ead)).status,
        Status::Ambiguous
    );
    imet.attributes = AttrSet::new(vec![crate::srv6::tests::service_attribute(
        6,
        "2001:db8:1:fbd1:fbd1::".parse().unwrap(),
        124,
        Some([32, 16, 32, 0, 0, 0]),
    )]);
    ead.attributes = AttrSet::new(vec![PathAttribute::Unknown(RawAttribute {
        flags: 0xe0,
        type_code: 40,
        data: vec![6, 0, 255].into(),
    })]);
    let result = crate::srv6::inspect_argument_pair(Some(&imet), Some(&ead));
    assert_eq!(result.status, Status::LocFuncOnly);
    assert_eq!(result.sid, Some("2001:db8:1:fbd1:fbd1::".parse().unwrap()));
}

#[test]
fn srv6_p2mp_imet_replacement_withdrawal_and_recovery_reach_export_and_inspection() {
    use crate::srv6::tests::{p2mp_imet, service_attribute};
    use crate::update::Srv6ArgumentStatus as Status;
    let (_tx, rx) = mpsc::channel(8);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let (outbound_tx, mut out) = mpsc::channel(16);
    manager.handle_update(RibUpdate::PeerUp {
        per_client_best: false,
        interpret_rfc1997: true,
        session_id: 0,
        peer: TARGET,
        peer_asn: 65100,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx,
        export_policy: None,
        sendable_families: evpn_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: vec![],
        negotiated_llgr_families: vec![],
    });
    while out.try_recv().is_ok() {}
    let mut imet = p2mp_imet();
    let (_, ead) = argument_routes(0xaaaa);
    let receive = |manager: &mut RibManager, route: &EvpnRibRoute, withdraw| {
        manager.handle_update(RibUpdate::RoutesReceived {
            session_id: 0,
            peer: route.peer,
            announced: vec![],
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
            evpn_announced: if withdraw {
                vec![]
            } else {
                vec![route.clone()]
            },
            evpn_withdrawn: if withdraw { vec![route.key()] } else { vec![] },
            validated_with: None,
        });
        drain_route_chunks(manager);
    };
    receive(&mut manager, &ead, false);
    while out.try_recv().is_ok() {}
    // Ordered actor updates exercise replacement by an invalid sole candidate,
    // recovery, explicit withdrawal, and reannouncement without timing sleeps.
    for (label, length, withdraw, expected) in [
        (0x00fb_d100, 16, false, Some("2001:db8:1:fbd1:aaaa::")),
        (0x00ab_cd0f, 16, false, Some("2001:db8:1:abcd:aaaa::")),
        (0x00ab_cd0f, 21, false, None),
        (0x00fb_d100, 16, false, Some("2001:db8:1:fbd1:aaaa::")),
        (0x00fb_d100, 16, true, None),
        (0x00fb_d100, 16, false, Some("2001:db8:1:fbd1:aaaa::")),
    ] {
        AttrSet::edit(&mut imet.attributes, |attrs| {
            attrs[0] = service_attribute(
                6,
                "2001:db8:1::".parse().unwrap(),
                24,
                Some([32, 16, if length == 21 { 24 } else { 16 }, 16, length, 48]),
            );
            let PathAttribute::PmsiTunnel(tunnel) = &mut attrs[1] else {
                panic!("PMSI fixture")
            };
            tunnel.mpls_label = label;
        });
        receive(&mut manager, &imet, withdraw);
        let result = argument_query(&mut manager, &imet, &ead, None, None);
        assert_eq!(result.sid, expected.map(|sid| sid.parse().unwrap()));
        assert_eq!(
            result.status,
            expected.map_or(Status::Unavailable, |_| Status::Composed)
        );
        assert_eq!(result.association, "caller_selected");
        let explain = query(&mut manager, imet.key(), Some(imet.peer), Some(TARGET));
        assert_eq!(explain.best.is_some(), expected.is_some());
        if withdraw {
            assert!(explain.received.is_none());
        } else {
            assert_eq!(explain.received.unwrap().attributes, imet.attributes);
        }
        let mut announced = Vec::new();
        let mut withdrawn = Vec::new();
        while let Ok(update) = out.try_recv() {
            announced.extend(update.evpn_announce);
            withdrawn.extend(update.evpn_withdraw);
        }
        if expected.is_some() {
            assert_eq!(withdrawn.len(), 0);
            assert_eq!(announced.len(), 1);
            assert_eq!(announced[0].key(), imet.key());
            assert_eq!(announced[0].attributes, imet.attributes);
        } else {
            assert!(announced.is_empty());
            assert_eq!(withdrawn, vec![imet.key()]);
        }
    }
}
