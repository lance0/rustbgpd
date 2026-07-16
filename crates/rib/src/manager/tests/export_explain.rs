//! Export-explain gate-ladder tests: every export gate as the deciding
//! factor, asserted through `ExplainAdvertisedRoute` — plus the
//! differential oracle applied to explain (a grouped member and a
//! content-equivalent ungrouped peer must produce identical verdicts).
//!
//! The single-best unicast and VPN explains dry-run the very staging
//! bodies live distribution executes (`distribute_single_best_prefix` /
//! `stage_vpn_routes`) via `ExportTarget::Explain`, so these tests pin
//! the truthfulness mechanism itself.

use rustbgpd_policy::{
    NeighborSetMatch, Policy, PolicyAction, PolicyChain, PolicyStatement, RouteModifications,
};

use super::*;
use crate::update::{ExportGateStep, ExportGateVerdict};

fn statement(prefix: Ipv4Prefix, action: PolicyAction) -> PolicyStatement {
    PolicyStatement {
        prefix: Some(Prefix::V4(prefix)),
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

fn deny_prefix_chain(prefix: Ipv4Prefix) -> PolicyChain {
    PolicyChain::new(vec![Policy {
        entries: vec![statement(prefix, PolicyAction::Deny)],
        default_action: PolicyAction::Permit,
    }])
}

/// `deny_prefix_chain` plus a never-matching neighbor-set statement:
/// decision-equivalent for every test route, but `requires_peer_context`
/// disqualifies its peers from update-grouping — the knob the
/// grouped-vs-ungrouped differential turns.
fn deny_prefix_chain_peer_context(prefix: Ipv4Prefix) -> PolicyChain {
    let mut never_matching = statement(
        Ipv4Prefix::new(Ipv4Addr::new(192, 168, 255, 0), 24),
        PolicyAction::Deny,
    );
    never_matching.match_neighbor_set = Some(NeighborSetMatch {
        addresses: vec![],
        remote_asns: vec![65099],
        peer_groups: vec![],
    });
    PolicyChain::new(vec![Policy {
        entries: vec![never_matching, statement(prefix, PolicyAction::Deny)],
        default_action: PolicyAction::Permit,
    }])
}

/// Bring up a peer and drain the initial-table `EoR`.
#[expect(
    clippy::too_many_arguments,
    reason = "explain scenarios exercise every PeerUp axis"
)]
async fn explain_peer_up(
    tx: &mpsc::Sender<RibUpdate>,
    peer: IpAddr,
    sendable: Vec<(Afi, Safi)>,
    is_ebgp: bool,
    rr_client: bool,
    export_policy: Option<PolicyChain>,
    negotiated_orf_recv: Vec<(Afi, Safi)>,
    negotiated_llgr_families: Vec<(Afi, Safi)>,
) -> mpsc::Receiver<OutboundRouteUpdate> {
    let (out_tx, mut out_rx) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        per_client_best: false,
        interpret_rfc1997: true,
        session_id: 0,
        peer,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy,
        sendable_families: sendable,
        is_ebgp,
        route_reflector_client: rr_client,
        orr_vantage: None,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv,
        negotiated_llgr_families,
    })
    .await
    .unwrap();
    drain_eor(&mut out_rx).await;
    out_rx
}

async fn feed_routes(tx: &mpsc::Sender<RibUpdate>, peer: IpAddr, announced: Vec<Route>) {
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer,
        announced,
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();
}

fn stopped_gate(explain: &crate::update::ExplainAdvertisedRoute) -> Option<&ExportGateStep> {
    explain
        .gates
        .iter()
        .find(|step| step.verdict == ExportGateVerdict::Stop)
}

/// The ladder shape the differential oracle compares: everything except
/// free-text detail strings.
fn gate_shape(
    explain: &crate::update::ExplainAdvertisedRoute,
) -> Vec<(&str, &str, ExportGateVerdict)> {
    explain
        .gates
        .iter()
        .map(|step| (step.gate, step.code, step.verdict))
        .collect()
}

#[tokio::test]
async fn no_best_route_stops_the_ladder_at_best_route() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let _rx_t = explain_peer_up(
        &tx,
        target,
        ipv4_sendable(),
        true,
        false,
        None,
        vec![],
        vec![],
    )
    .await;

    let prefix = Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24));
    let explain = query_explain_advertised_route(&tx, target, prefix).await;
    assert_eq!(
        explain.decision,
        crate::update::ExplainDecision::NoBestRoute
    );
    let stop = stopped_gate(&explain).expect("ladder must stop");
    assert_eq!((stop.gate, stop.code), ("best_route", "no_best_route"));

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn family_gate_stops_route_for_family_mismatch() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let _rx_s = explain_peer_up(
        &tx,
        source,
        ipv4_sendable(),
        true,
        false,
        None,
        vec![],
        vec![],
    )
    .await;
    // Target negotiated IPv6 unicast only.
    let _rx_t = explain_peer_up(
        &tx,
        target,
        vec![(Afi::Ipv6, Safi::Unicast)],
        true,
        false,
        None,
        vec![],
        vec![],
    )
    .await;

    let prefix = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24);
    feed_routes(
        &tx,
        source,
        vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 1))],
    )
    .await;

    let explain = query_explain_advertised_route(&tx, target, Prefix::V4(prefix)).await;
    assert_eq!(
        explain.decision,
        crate::update::ExplainDecision::UnsupportedFamily
    );
    let stop = stopped_gate(&explain).expect("ladder must stop");
    assert_eq!((stop.gate, stop.code), ("family", "family_not_sendable"));
    assert_eq!(explain.reasons[0].code, "family_not_sendable");
    // The gates before the family rung passed, in live body order.
    let names: Vec<&str> = explain.gates.iter().map(|step| step.gate).collect();
    assert_eq!(
        names,
        ["best_route", "split_horizon", "rr_reflection", "family"]
    );

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn split_horizon_gate_stops_route_to_its_source() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let _rx_s = explain_peer_up(
        &tx,
        source,
        ipv4_sendable(),
        true,
        false,
        None,
        vec![],
        vec![],
    )
    .await;

    let prefix = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24);
    feed_routes(
        &tx,
        source,
        vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 1))],
    )
    .await;

    let explain = query_explain_advertised_route(&tx, source, Prefix::V4(prefix)).await;
    assert_eq!(explain.decision, crate::update::ExplainDecision::Deny);
    let stop = stopped_gate(&explain).expect("ladder must stop");
    assert_eq!(
        (stop.gate, stop.code),
        ("split_horizon", "ibgp_split_horizon")
    );
    assert_eq!(explain.reasons[0].code, "ibgp_split_horizon");

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn rr_gate_names_non_client_to_non_client_suppression() {
    let (tx, rx) = mpsc::channel(64);
    let cluster_id = Some(Ipv4Addr::new(10, 0, 0, 100));
    let manager = RibManager::new(rx, dummy_query_rx(), None, cluster_id, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    // Both iBGP non-clients under a configured cluster id.
    let _rx_s = explain_peer_up(
        &tx,
        source,
        ipv4_sendable(),
        false,
        false,
        None,
        vec![],
        vec![],
    )
    .await;
    let _rx_t = explain_peer_up(
        &tx,
        target,
        ipv4_sendable(),
        false,
        false,
        None,
        vec![],
        vec![],
    )
    .await;

    let prefix = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24);
    let mut route = make_route(prefix, Ipv4Addr::new(10, 0, 0, 1));
    route.origin_type = crate::route::RouteOrigin::Ibgp;
    feed_routes(&tx, source, vec![route]).await;

    let explain = query_explain_advertised_route(&tx, target, Prefix::V4(prefix)).await;
    assert_eq!(explain.decision, crate::update::ExplainDecision::Deny);
    let stop = stopped_gate(&explain).expect("ladder must stop");
    assert_eq!(
        (stop.gate, stop.code),
        ("rr_reflection", "rr_non_client_to_non_client")
    );
    assert_eq!(explain.reasons[0].code, "rr_non_client_to_non_client");

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn llgr_gate_stops_stale_route_toward_non_llgr_ebgp_peer() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let no_llgr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let with_llgr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
    let _rx_s = explain_peer_up(
        &tx,
        source,
        ipv4_sendable(),
        true,
        false,
        None,
        vec![],
        vec![],
    )
    .await;
    let _rx_a = explain_peer_up(
        &tx,
        no_llgr,
        ipv4_sendable(),
        true,
        false,
        None,
        vec![],
        vec![],
    )
    .await;
    let _rx_b = explain_peer_up(
        &tx,
        with_llgr,
        ipv4_sendable(),
        true,
        false,
        None,
        vec![],
        ipv4_sendable(),
    )
    .await;

    // Route carrying the LLGR_STALE community (an upstream helper's tag).
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24);
    let mut route = make_route(prefix, Ipv4Addr::new(10, 0, 0, 1));
    route.attributes = Arc::new(vec![PathAttribute::Communities(vec![
        rustbgpd_wire::COMMUNITY_LLGR_STALE,
    ])]);
    feed_routes(&tx, source, vec![route]).await;

    let denied = query_explain_advertised_route(&tx, no_llgr, Prefix::V4(prefix)).await;
    assert_eq!(denied.decision, crate::update::ExplainDecision::Deny);
    let stop = stopped_gate(&denied).expect("ladder must stop");
    assert_eq!((stop.gate, stop.code), ("llgr", "llgr_stale_suppressed"));
    assert_eq!(denied.reasons[0].code, "llgr_stale_suppressed");

    // A peer that advertised the LLGR capability for the family clears it.
    let permitted = query_explain_advertised_route(&tx, with_llgr, Prefix::V4(prefix)).await;
    assert_eq!(
        permitted.decision,
        crate::update::ExplainDecision::Advertise
    );
    assert!(stopped_gate(&permitted).is_none());
    assert!(
        permitted
            .gates
            .iter()
            .any(|step| step.gate == "llgr" && step.verdict == ExportGateVerdict::Pass)
    );

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn orf_gates_stop_pending_family_then_filtered_prefix() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let _rx_s = explain_peer_up(
        &tx,
        source,
        ipv4_sendable(),
        true,
        false,
        None,
        vec![],
        vec![],
    )
    .await;
    // Target negotiated ORF-receive: the family is gated until its
    // first ROUTE-REFRESH (RFC 5291 §6).
    let (out_tx, _rx_t) = mpsc::channel::<OutboundRouteUpdate>(64);
    tx.send(RibUpdate::PeerUp {
        per_client_best: false,
        interpret_rfc1997: true,
        session_id: 0,
        peer: target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: ipv4_sendable(),
        negotiated_llgr_families: vec![],
    })
    .await
    .unwrap();

    let prefix = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24);
    feed_routes(
        &tx,
        source,
        vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 1))],
    )
    .await;

    let gated = query_explain_advertised_route(&tx, target, Prefix::V4(prefix)).await;
    assert_eq!(gated.decision, crate::update::ExplainDecision::Deny);
    let stop = stopped_gate(&gated).expect("ladder must stop");
    assert_eq!((stop.gate, stop.code), ("orf_gate", "orf_pending"));

    // The peer pushes an ORF permitting only an unrelated prefix
    // (IMMEDIATE lifts the gate and installs the filter).
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::PeerOrfUpdate {
        session_id: 0,
        peer: target,
        afi: Afi::Ipv4,
        safi: Safi::Unicast,
        when: WhenToRefresh::Immediate,
        entries: vec![AddressPrefixOrf {
            action: OrfAction::Add,
            match_: OrfMatch::Permit,
            sequence: 10,
            min_len: 0,
            max_len: 32,
            prefix: Some(Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 99, 0, 0), 16))),
        }],
        reply: reply_tx,
    })
    .await
    .unwrap();
    reply_rx.await.unwrap().unwrap();

    let filtered = query_explain_advertised_route(&tx, target, Prefix::V4(prefix)).await;
    assert_eq!(filtered.decision, crate::update::ExplainDecision::Deny);
    let stop = stopped_gate(&filtered).expect("ladder must stop");
    assert_eq!((stop.gate, stop.code), ("orf", "orf_filtered"));
    assert_eq!(filtered.reasons[0].code, "orf_filtered");

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn policy_deny_gate_reports_the_deciding_chain_member() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24);
    let _rx_s = explain_peer_up(
        &tx,
        source,
        ipv4_sendable(),
        true,
        false,
        None,
        vec![],
        vec![],
    )
    .await;
    let _rx_t = explain_peer_up(
        &tx,
        target,
        ipv4_sendable(),
        true,
        false,
        Some(deny_prefix_chain(prefix)),
        vec![],
        vec![],
    )
    .await;

    feed_routes(
        &tx,
        source,
        vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 1))],
    )
    .await;

    let explain = query_explain_advertised_route(&tx, target, Prefix::V4(prefix)).await;
    assert_eq!(explain.decision, crate::update::ExplainDecision::Deny);
    let stop = stopped_gate(&explain).expect("ladder must stop");
    assert_eq!((stop.gate, stop.code), ("export_policy", "policy_denied"));
    assert!(
        stop.detail.contains("denied this route"),
        "policy detail names the verdict, got {:?}",
        stop.detail
    );
    assert_eq!(explain.reasons[0].code, "policy_denied");
    // Everything before export_policy passed — LLGR and ORF present as
    // rungs (pass / not-applicable), proving the full ladder is named.
    let names: Vec<&str> = explain.gates.iter().map(|step| step.gate).collect();
    assert_eq!(
        names,
        [
            "best_route",
            "split_horizon",
            "rr_reflection",
            "family",
            "llgr",
            "orf",
            "export_policy"
        ]
    );

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn advertised_route_reports_in_sync_and_staged_modifications() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24);
    // Export policy that modifies MED on the way out.
    let mut modifying = statement(prefix, PolicyAction::Permit);
    modifying.modifications.set_med = Some(750);
    let chain = PolicyChain::new(vec![Policy {
        entries: vec![modifying],
        default_action: PolicyAction::Permit,
    }]);
    let _rx_s = explain_peer_up(
        &tx,
        source,
        ipv4_sendable(),
        true,
        false,
        None,
        vec![],
        vec![],
    )
    .await;
    let mut rx_t = explain_peer_up(
        &tx,
        target,
        ipv4_sendable(),
        true,
        false,
        Some(chain),
        vec![],
        vec![],
    )
    .await;

    feed_routes(
        &tx,
        source,
        vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 1))],
    )
    .await;
    // Live distribution announced the (modified) route.
    let update = rx_t.recv().await.unwrap();
    assert_eq!(update.announce.len(), 1);

    let explain = query_explain_advertised_route(&tx, target, Prefix::V4(prefix)).await;
    assert_eq!(explain.decision, crate::update::ExplainDecision::Advertise);
    assert!(stopped_gate(&explain).is_none());
    assert_eq!(explain.modifications.set_med, Some(750));
    assert_eq!(explain.route_peer, Some(source));
    assert_eq!(
        explain.next_hop,
        Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)))
    );
    // The staged (post-modification) route equals the advertised state:
    // the peer is in sync and the live path would suppress re-sending.
    assert!(explain.already_advertised);
    let last = explain.gates.last().expect("ladder ends at adj_rib_out");
    assert_eq!(
        (last.gate, last.code),
        ("adj_rib_out", "already_advertised")
    );

    drop(tx);
    handle.await.unwrap();
}

/// A denied route's explain trace must carry no staged modifications —
/// `distribute_single_best_prefix` records `trace.modifications` only
/// after the export policy permits, matching the per-client-best arm. A
/// permitted route in the same chain still reports its modifications.
#[tokio::test]
async fn denied_route_explain_has_no_modifications() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let denied_prefix = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24);
    let permitted_prefix = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 0), 24);

    // One chain: deny one prefix (with configured — but dropped — mods,
    // documenting that a deny carries none), permit + modify the other.
    let mut denying = statement(denied_prefix, PolicyAction::Deny);
    denying.modifications.set_med = Some(999);
    let mut modifying = statement(permitted_prefix, PolicyAction::Permit);
    modifying.modifications.set_med = Some(750);
    let chain = PolicyChain::new(vec![Policy {
        entries: vec![denying, modifying],
        default_action: PolicyAction::Permit,
    }]);

    let _rx_s = explain_peer_up(
        &tx,
        source,
        ipv4_sendable(),
        true,
        false,
        None,
        vec![],
        vec![],
    )
    .await;
    let _rx_t = explain_peer_up(
        &tx,
        target,
        ipv4_sendable(),
        true,
        false,
        Some(chain),
        vec![],
        vec![],
    )
    .await;

    feed_routes(
        &tx,
        source,
        vec![
            make_route(denied_prefix, Ipv4Addr::new(10, 0, 0, 1)),
            make_route(permitted_prefix, Ipv4Addr::new(10, 0, 0, 1)),
        ],
    )
    .await;

    let denied = query_explain_advertised_route(&tx, target, Prefix::V4(denied_prefix)).await;
    assert_eq!(denied.decision, crate::update::ExplainDecision::Deny);
    assert!(
        denied.modifications.is_empty(),
        "denied route must carry no staged modifications, got {:?}",
        denied.modifications
    );

    let permitted = query_explain_advertised_route(&tx, target, Prefix::V4(permitted_prefix)).await;
    assert_eq!(
        permitted.decision,
        crate::update::ExplainDecision::Advertise
    );
    assert_eq!(permitted.modifications.set_med, Some(750));

    drop(tx);
    handle.await.unwrap();
}

/// The differential oracle applied to explain: an update-grouped member
/// and a content-equivalent ungrouped peer (peer-context chain, the
/// grouping disqualifier) must produce identical gate ladders and
/// verdicts for the same routes — only the group identity differs.
#[tokio::test]
async fn grouped_and_ungrouped_explains_agree() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let grouped_a = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let grouped_b = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
    let ungrouped = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 4));
    let denied_prefix = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24);
    let permitted_prefix = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 0), 24);

    let _rx_s = explain_peer_up(
        &tx,
        source,
        ipv4_sendable(),
        true,
        false,
        None,
        vec![],
        vec![],
    )
    .await;
    let _rx_a = explain_peer_up(
        &tx,
        grouped_a,
        ipv4_sendable(),
        false,
        false,
        Some(deny_prefix_chain(denied_prefix)),
        vec![],
        vec![],
    )
    .await;
    let _rx_b = explain_peer_up(
        &tx,
        grouped_b,
        ipv4_sendable(),
        false,
        false,
        Some(deny_prefix_chain(denied_prefix)),
        vec![],
        vec![],
    )
    .await;
    let _rx_u = explain_peer_up(
        &tx,
        ungrouped,
        ipv4_sendable(),
        false,
        false,
        Some(deny_prefix_chain_peer_context(denied_prefix)),
        vec![],
        vec![],
    )
    .await;

    feed_routes(
        &tx,
        source,
        vec![
            make_route(denied_prefix, Ipv4Addr::new(10, 0, 0, 1)),
            make_route(permitted_prefix, Ipv4Addr::new(10, 0, 0, 1)),
        ],
    )
    .await;

    for prefix in [denied_prefix, permitted_prefix] {
        let grouped = query_explain_advertised_route(&tx, grouped_a, Prefix::V4(prefix)).await;
        let solo = query_explain_advertised_route(&tx, ungrouped, Prefix::V4(prefix)).await;

        assert!(
            grouped.update_group_id.is_some(),
            "content-equal chains must group"
        );
        assert!(
            solo.update_group_id.is_none(),
            "a peer-context chain must disqualify from grouping"
        );
        // Identical verdicts and ladder shape — the explain-level
        // differential oracle.
        assert_eq!(grouped.decision, solo.decision, "prefix {prefix}");
        assert_eq!(gate_shape(&grouped), gate_shape(&solo), "prefix {prefix}");
        assert_eq!(
            grouped.already_advertised, solo.already_advertised,
            "prefix {prefix}"
        );
        assert_eq!(grouped.next_hop, solo.next_hop, "prefix {prefix}");
    }

    // Spot-check the expected outcomes themselves.
    let denied = query_explain_advertised_route(&tx, grouped_a, Prefix::V4(denied_prefix)).await;
    assert_eq!(denied.decision, crate::update::ExplainDecision::Deny);
    let permitted =
        query_explain_advertised_route(&tx, grouped_a, Prefix::V4(permitted_prefix)).await;
    assert_eq!(
        permitted.decision,
        crate::update::ExplainDecision::Advertise
    );
    assert!(
        permitted.already_advertised,
        "live path already advertised it"
    );

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn vpn_rt_membership_gate_names_the_miss_and_the_match() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    // Source: VPN-only peer feeding one VPNv4 route tagged RT:65001:200.
    let _rx_s = explain_peer_up(
        &tx,
        source,
        vpn_sendable(),
        false,
        true,
        None,
        vec![],
        vec![],
    )
    .await;
    // Target: eBGP peer that negotiated VPN + RT-Constrain.
    let mut rx_t = vpn_rtc_peer_up(&tx, target).await;
    drain_strict_vpn_rtc_initial_dump(&mut rx_t).await;

    let route = make_vpn_rib_route_with_rts(Ipv4Addr::new(10, 0, 0, 1), 7, vec![rt(200)]);
    let rd = route.nlri.route_distinguisher;
    tx.send(RibUpdate::VpnRoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![route],
        withdrawn: vec![],
    })
    .await
    .unwrap();

    let inner = Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 7, 0), 24));
    // Membership advertises interest in RT:65001:100 only — a miss.
    send_rtc_interest(&tx, Ipv4Addr::new(10, 0, 0, 2), &[100]).await;
    let miss = query_explain_advertised_vpn_route(&tx, target, inner, rd).await;
    assert_eq!(miss.decision, crate::update::ExplainDecision::Deny);
    assert_eq!(miss.rd, Some(rd));
    let stop = stopped_gate(&miss).expect("ladder must stop");
    assert_eq!(
        (stop.gate, stop.code),
        ("rt_membership", "rt_membership_miss")
    );
    assert_eq!(miss.reasons[0].code, "rt_membership_miss");

    // Adding interest in RT:65001:200 turns the gate into a pass and
    // the decision into Advertise.
    send_rtc_interest(&tx, Ipv4Addr::new(10, 0, 0, 2), &[200]).await;
    let hit = query_explain_advertised_vpn_route(&tx, target, inner, rd).await;
    assert_eq!(hit.decision, crate::update::ExplainDecision::Advertise);
    assert!(
        hit.gates
            .iter()
            .any(|step| step.gate == "rt_membership" && step.verdict == ExportGateVerdict::Pass)
    );
    assert_eq!(hit.route_peer, Some(source));

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn vpn_explain_without_rtc_marks_rt_gate_not_applicable() {
    let (tx, rx) = mpsc::channel(64);
    // Route reflector (cluster id set): iBGP client-to-client VPN
    // reflection is permitted.
    let cluster_id = Some(Ipv4Addr::new(10, 0, 0, 100));
    let manager = RibManager::new(rx, dummy_query_rx(), None, cluster_id, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let _rx_s = explain_peer_up(
        &tx,
        source,
        vpn_sendable(),
        false,
        true,
        None,
        vec![],
        vec![],
    )
    .await;
    let _rx_t = explain_peer_up(
        &tx,
        target,
        vpn_sendable(),
        false,
        true,
        None,
        vec![],
        vec![],
    )
    .await;

    let route = make_vpn_rib_route(Ipv4Addr::new(10, 0, 0, 1), 7, 100, 100);
    let rd = route.nlri.route_distinguisher;
    tx.send(RibUpdate::VpnRoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![route],
        withdrawn: vec![],
    })
    .await
    .unwrap();

    let inner = Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 7, 0), 24));
    let explain = query_explain_advertised_vpn_route(&tx, target, inner, rd).await;
    assert_eq!(explain.decision, crate::update::ExplainDecision::Advertise);
    assert!(
        explain
            .gates
            .iter()
            .any(|step| step.gate == "rt_membership"
                && step.verdict == ExportGateVerdict::NotApplicable),
        "no RTC negotiation must render the RT gate not-applicable, gates: {:?}",
        explain.gates
    );
    assert!(
        explain.already_advertised,
        "reflected before the explain ran"
    );

    drop(tx);
    handle.await.unwrap();
}

// --- Labeled-unicast (SAFI 4) explain: the ladder is recorded by a dry
// run of `stage_labeled_routes` itself, the same body live reflection
// executes, so these tests pin the labeled truthfulness mechanism.

async fn feed_labeled_routes(
    tx: &mpsc::Sender<RibUpdate>,
    peer: IpAddr,
    announced: Vec<crate::route::LabeledRibRoute>,
) {
    tx.send(RibUpdate::LabeledRoutesReceived {
        session_id: 0,
        peer,
        announced,
        withdrawn: vec![],
    })
    .await
    .unwrap();
}

fn labeled_with_communities(
    mut route: crate::route::LabeledRibRoute,
    communities: Vec<u32>,
) -> crate::route::LabeledRibRoute {
    Arc::make_mut(&mut route.attributes).push(PathAttribute::Communities(communities));
    route
}

#[tokio::test]
async fn labeled_split_horizon_gate_stops_route_to_its_source() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let _rx_s = explain_peer_up(
        &tx,
        source,
        labeled_sendable(),
        true,
        false,
        None,
        vec![],
        vec![],
    )
    .await;

    let route = make_labeled_rib_route(Ipv4Addr::new(10, 0, 0, 1), 61, 100, 100);
    let prefix = route.nlri.prefix;
    feed_labeled_routes(&tx, source, vec![route]).await;

    let explain = query_explain_advertised_labeled_route(&tx, source, prefix).await;
    assert_eq!(explain.decision, crate::update::ExplainDecision::Deny);
    let stop = stopped_gate(&explain).expect("ladder must stop");
    assert_eq!(
        (stop.gate, stop.code),
        ("split_horizon", "ibgp_split_horizon")
    );
    assert_eq!(explain.reasons[0].code, "ibgp_split_horizon");

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn labeled_no_advertise_gate_stops_source_route() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let _rx_s = explain_peer_up(
        &tx,
        source,
        labeled_sendable(),
        true,
        false,
        None,
        vec![],
        vec![],
    )
    .await;
    let _rx_t = explain_peer_up(
        &tx,
        target,
        labeled_sendable(),
        true,
        false,
        None,
        vec![],
        vec![],
    )
    .await;

    let route = labeled_with_communities(
        make_labeled_rib_route(Ipv4Addr::new(10, 0, 0, 1), 62, 100, 100),
        vec![rustbgpd_wire::COMMUNITY_NO_ADVERTISE],
    );
    let prefix = route.nlri.prefix;
    feed_labeled_routes(&tx, source, vec![route]).await;

    let explain = query_explain_advertised_labeled_route(&tx, target, prefix).await;
    assert_eq!(explain.decision, crate::update::ExplainDecision::Deny);
    let stop = stopped_gate(&explain).expect("ladder must stop");
    assert_eq!(
        (stop.gate, stop.code),
        ("no_advertise", "no_advertise_suppressed")
    );
    assert_eq!(explain.reasons[0].code, "no_advertise_suppressed");
    // The full labeled ladder is named, in live body order, up to the stop.
    let names: Vec<&str> = explain.gates.iter().map(|step| step.gate).collect();
    assert_eq!(
        names,
        [
            "family",
            "best_route",
            "llgr",
            "split_horizon",
            "rr_reflection",
            "no_advertise"
        ]
    );

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn labeled_llgr_gate_stops_stale_route_toward_non_llgr_ebgp_peer() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let no_llgr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let with_llgr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
    let _rx_s = explain_peer_up(
        &tx,
        source,
        labeled_sendable(),
        true,
        false,
        None,
        vec![],
        vec![],
    )
    .await;
    let _rx_a = explain_peer_up(
        &tx,
        no_llgr,
        labeled_sendable(),
        true,
        false,
        None,
        vec![],
        vec![],
    )
    .await;
    let _rx_b = explain_peer_up(
        &tx,
        with_llgr,
        labeled_sendable(),
        true,
        false,
        None,
        vec![],
        labeled_sendable(),
    )
    .await;

    let route = labeled_with_communities(
        make_labeled_rib_route(Ipv4Addr::new(10, 0, 0, 1), 63, 100, 100),
        vec![rustbgpd_wire::COMMUNITY_LLGR_STALE],
    );
    let prefix = route.nlri.prefix;
    feed_labeled_routes(&tx, source, vec![route]).await;

    let denied = query_explain_advertised_labeled_route(&tx, no_llgr, prefix).await;
    assert_eq!(denied.decision, crate::update::ExplainDecision::Deny);
    let stop = stopped_gate(&denied).expect("ladder must stop");
    assert_eq!((stop.gate, stop.code), ("llgr", "llgr_stale_suppressed"));
    assert_eq!(denied.reasons[0].code, "llgr_stale_suppressed");

    // A peer that advertised the LLGR capability for the family clears it.
    let permitted = query_explain_advertised_labeled_route(&tx, with_llgr, prefix).await;
    assert_eq!(
        permitted.decision,
        crate::update::ExplainDecision::Advertise
    );
    assert!(stopped_gate(&permitted).is_none());
    assert!(
        permitted
            .gates
            .iter()
            .any(|step| step.gate == "llgr" && step.verdict == ExportGateVerdict::Pass)
    );
    assert_eq!(permitted.route_peer, Some(source));

    drop(tx);
    handle.await.unwrap();
}
