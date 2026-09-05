use super::*;
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
                Arc::make_mut(&mut route.attributes).push(PathAttribute::Communities(vec![
                    rustbgpd_wire::COMMUNITY_NO_ADVERTISE,
                ]));
                install(&mut manager, &route);
            }
            "no_export_suppressed" => {
                Arc::make_mut(&mut route.attributes).push(PathAttribute::Communities(vec![
                    rustbgpd_wire::COMMUNITY_NO_EXPORT,
                ]));
                install(&mut manager, &route);
            }
            "llgr_stale_suppressed" => {
                route.is_llgr_stale = true;
                install(&mut manager, &route);
            }
            "source_peer" => {
                route.peer = TARGET;
                install(&mut manager, &route);
            }
            "ibgp_split_horizon" => {
                manager.peer_is_ebgp.insert(TARGET, false);
            }
            "policy_denied" => {
                manager
                    .peer_export_policies
                    .insert(TARGET, Some(policy("reject")));
            }
            "no_advertise_policy_suppressed" => {
                manager
                    .peer_export_policies
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
    manager
        .peer_export_policies
        .insert(TARGET, Some(chain.share()));
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
    Arc::make_mut(&mut fresh.attributes).push(PathAttribute::LocalPref(250));
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
