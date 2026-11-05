//! ADR-0146: IPv4 VPN `FlowSpec` (AFI 1 / SAFI 134) identity, policy and
//! distribution. A rule is keyed by `(family, RD, components)`: the same
//! components in global scope and in each RD are distinct rules.

use super::*;
use crate::route::FlowSpecKey;
use crate::test_support::peer_v4;
use crate::update::InjectOutcome;
use rustbgpd_wire::{ExtendedCommunity, RouteDistinguisher};

const RD_A: RouteDistinguisher = RouteDistinguisher([0, 0, 0xad, 0x77, 0, 0, 0, 40]);
const RD_B: RouteDistinguisher = RouteDistinguisher([0, 0, 0xad, 0x77, 0, 0, 0, 41]);
const RD_C: RouteDistinguisher = RouteDistinguisher([0, 0, 0xad, 0x77, 0, 0, 0, 42]);
const GLOBAL: (Afi, Safi) = (Afi::Ipv4, Safi::FlowSpec);
const VPN: (Afi, Safi) = (Afi::Ipv4, Safi::FlowSpecVpn);
const RTC: (Afi, Safi) = (Afi::Ipv4, Safi::RtConstrain);

/// Route Target `44407:value` (two-octet AS, type 0x00 / sub-type 0x02).
fn rt(value: u32) -> PathAttribute {
    PathAttribute::ExtendedCommunities(vec![ExtendedCommunity::new(
        0x0002_ad77_0000_0000 | u64::from(value),
    )])
}

/// A local rule for `192.0.2.0/24` in `rd` (global when `None`), exported
/// with Route Target `44407:rt_value`.
fn local_rule(rd: Option<RouteDistinguisher>, rt_value: u32) -> FlowSpecRoute {
    let mut route = make_flowspec_route(Ipv4Addr::UNSPECIFIED);
    route.peer = LOCAL_PEER;
    route.origin_type = crate::route::RouteOrigin::Local;
    route.peer_router_id = Ipv4Addr::UNSPECIFIED;
    route.rd = rd;
    route.attributes = vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath { segments: vec![] }),
        rt(rt_value),
    ];
    route
}

fn key(rd: Option<RouteDistinguisher>) -> FlowSpecKey {
    local_rule(rd, 0).selection_key()
}

async fn inject(tx: &mpsc::Sender<RibUpdate>, route: FlowSpecRoute) -> InjectOutcome {
    let (reply, rx) = oneshot::channel();
    tx.send(RibUpdate::InjectFlowSpec { route, reply })
        .await
        .unwrap();
    rx.await.unwrap().unwrap()
}

async fn withdraw(tx: &mpsc::Sender<RibUpdate>, key: FlowSpecKey) -> bool {
    let (reply, rx) = oneshot::channel();
    tx.send(RibUpdate::WithdrawFlowSpec {
        key,
        allow_missing: false,
        owner: String::new(),
        override_owner: false,
        reply,
    })
    .await
    .unwrap();
    rx.await.unwrap().unwrap().removed
}

async fn peer_up(
    tx: &mpsc::Sender<RibUpdate>,
    octet: u8,
    families: Vec<(Afi, Safi)>,
    export_policy: Option<rustbgpd_policy::PolicyChain>,
) -> mpsc::Receiver<OutboundRouteUpdate> {
    let mut out_rx = register(tx, octet, families, export_policy).await;
    drain_eor(&mut out_rx).await;
    out_rx
}

async fn register(
    tx: &mpsc::Sender<RibUpdate>,
    octet: u8,
    families: Vec<(Afi, Safi)>,
    export_policy: Option<rustbgpd_policy::PolicyChain>,
) -> mpsc::Receiver<OutboundRouteUpdate> {
    let (outbound_tx, out_rx) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        per_client_best: false,
        interpret_rfc1997: true,
        session_id: 0,
        peer: peer_v4(Ipv4Addr::new(192, 0, 2, octet)),
        peer_asn: 65100,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx,
        export_policy,
        sendable_families: families,
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: Vec::new(),
        negotiated_llgr_families: Vec::new(),
    })
    .await
    .unwrap();
    out_rx
}

fn drain(out_rx: &mut mpsc::Receiver<OutboundRouteUpdate>) -> Vec<OutboundRouteUpdate> {
    std::iter::from_fn(|| out_rx.try_recv().ok()).collect()
}

fn announced(updates: &[OutboundRouteUpdate]) -> Vec<FlowSpecKey> {
    let mut keys: Vec<_> = updates
        .iter()
        .flat_map(|update| update.flowspec_announce.iter())
        .map(FlowSpecRoute::selection_key)
        .collect();
    keys.sort_by_key(|key| key.rd);
    keys
}

fn withdrawn(updates: &[OutboundRouteUpdate]) -> Vec<FlowSpecKey> {
    updates
        .iter()
        .flat_map(|update| update.flowspec_withdraw.iter().cloned())
        .collect()
}

async fn selected(tx: &mpsc::Sender<RibUpdate>) -> Vec<Option<RouteDistinguisher>> {
    let mut rds: Vec<_> = query_flowspec_routes(tx)
        .await
        .into_iter()
        .map(|route| route.rd)
        .collect();
    rds.sort();
    rds
}

fn start() -> (mpsc::Sender<RibUpdate>, tokio::task::JoinHandle<()>) {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    (tx, tokio::spawn(manager.run()))
}

fn rpol_chain(source: &str) -> rustbgpd_policy::PolicyChain {
    let compiled = rustbgpd_policy::rpol::RpolFile::parse(source)
        .expect("clean rpol")
        .compile_policy("export", &[], &mut rustbgpd_policy::sets::SetStore::new())
        .expect("export policy exists");
    rustbgpd_policy::PolicyChain::from_named(vec![rustbgpd_policy::NamedPolicy::from_rpol(
        "export".to_string(),
        Arc::new(compiled),
    )])
}

#[tokio::test]
async fn rpol_flowspec_family_denies_only_its_own_scope() {
    let (tx, handle) = start();
    let mut vpn_deny = peer_up(
        &tx,
        10,
        vec![GLOBAL, VPN],
        Some(rpol_chain(
            "policy export { term vpn { if route.family == vpnv4-flowspec { reject } } }",
        )),
    )
    .await;
    let mut global_deny = peer_up(
        &tx,
        11,
        vec![GLOBAL, VPN],
        Some(rpol_chain(
            "policy export { term global { if route.family == ipv4-flowspec { reject } } }",
        )),
    )
    .await;

    for rd in [None, Some(RD_A), Some(RD_B)] {
        inject(&tx, local_rule(rd, 777)).await;
    }
    let vpn_updates = drain(&mut vpn_deny);
    assert_eq!(
        announced(&vpn_updates),
        [key(None)],
        "vpnv4-flowspec denies both VPN scopes while preserving the global rule"
    );
    assert_eq!(withdrawn(&vpn_updates), []);
    let global_updates = drain(&mut global_deny);
    assert_eq!(
        announced(&global_updates),
        [key(Some(RD_A)), key(Some(RD_B))],
        "ipv4-flowspec does not match VPN rules"
    );
    assert_eq!(withdrawn(&global_updates), []);

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn rpol_vpn_rt_rewrite_preserves_identity_actions_and_other_scopes() {
    let policy = rpol_chain(
        r"policy export {
            term vpn {
                if route.family == vpnv4-flowspec && route.ext-communities has RT:44407:777 {
                    remove ext-community RT:44407:777
                    add ext-community RT:44407:778
                    accept
                }
            }
        }",
    );
    let action =
        ExtendedCommunity::from_flowspec_action(&rustbgpd_wire::FlowSpecAction::TrafficRateBytes {
            asn: 0,
            rate: 1_024.0,
        });
    let marker = (65000 << 16) | 0x2a;
    let (tx, handle) = start();
    let mut out_rx = peer_up(&tx, 10, vec![GLOBAL, VPN], Some(policy)).await;
    for (rd, target) in [(None, 777), (Some(RD_A), 777), (Some(RD_B), 779)] {
        let mut route = local_rule(rd, target);
        for attr in &mut route.attributes {
            if let PathAttribute::ExtendedCommunities(communities) = attr {
                communities.push(action);
            }
        }
        route
            .attributes
            .push(PathAttribute::Communities(vec![marker]));
        inject(&tx, route).await;
    }
    let updates = drain(&mut out_rx);
    assert_eq!(
        announced(&updates),
        [key(None), key(Some(RD_A)), key(Some(RD_B))],
        "RT edits preserve the RD and rule components"
    );
    assert_eq!(withdrawn(&updates), []);
    for route in updates.iter().flat_map(|update| &update.flowspec_announce) {
        let target = match route.rd {
            None => 777,
            Some(RD_A) => 778,
            Some(RD_B) => 779,
            _ => unreachable!("the exact advertised keys were checked above"),
        };
        let expected = ExtendedCommunity::new(0x0002_ad77_0000_0000 | target);
        assert_eq!(route.extended_communities().len(), 2);
        assert!(route.extended_communities().contains(&expected));
        assert!(route.extended_communities().contains(&action));
        assert_eq!(route.communities(), [marker]);
    }
    let stored = query_flowspec_routes(&tx).await;
    let original = stored.iter().find(|route| route.rd == Some(RD_A)).unwrap();
    assert!(
        original
            .extended_communities()
            .contains(&ExtendedCommunity::new(0x0002_ad77_0000_0309)),
        "export modifications do not rewrite the selected input"
    );

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn vpn_no_advertise_suppresses_withdraws_and_recovers_exact_scope() {
    let cases = [
        (
            rustbgpd_wire::COMMUNITY_NO_ADVERTISE,
            "policy export { term scrub { remove community NO_ADVERTISE; accept } }",
        ),
        (
            (65000 << 16) | 0x63,
            r"policy export {
                term suppress {
                    if route.family == vpnv4-flowspec && route.communities has 65000:99 {
                        add community NO_ADVERTISE
                        accept
                    }
                }
            }",
        ),
    ];
    for (marker, source) in cases {
        let (tx, handle) = start();
        let mut out_rx = peer_up(&tx, 10, vec![GLOBAL, VPN], Some(rpol_chain(source))).await;
        let plain = local_rule(Some(RD_A), 777);
        let mut restricted = plain.clone();
        restricted
            .attributes
            .push(PathAttribute::Communities(vec![marker]));
        inject(&tx, restricted.clone()).await;
        assert!(
            drain(&mut out_rx).is_empty(),
            "first-seen source or policy NO_ADVERTISE sends neither announce nor withdrawal"
        );

        inject(&tx, local_rule(None, 777)).await;
        inject(&tx, local_rule(Some(RD_B), 777)).await;
        assert_eq!(inject(&tx, plain.clone()).await, InjectOutcome::Replaced);
        let admitted = drain(&mut out_rx);
        assert_eq!(
            announced(&admitted),
            [key(None), key(Some(RD_A)), key(Some(RD_B))]
        );
        assert_eq!(withdrawn(&admitted), []);

        assert_eq!(
            inject(&tx, restricted.clone()).await,
            InjectOutcome::Replaced
        );
        let suppressed = drain(&mut out_rx);
        assert_eq!(announced(&suppressed), []);
        assert_eq!(
            withdrawn(&suppressed),
            [key(Some(RD_A))],
            "NO_ADVERTISE withdraws only the previously admitted VPN scope"
        );
        restricted.attributes.push(PathAttribute::Med(999));
        inject(&tx, restricted).await;
        assert!(
            drain(&mut out_rx).is_empty(),
            "repeated suppression does not withdraw global or RD-sibling rules"
        );

        assert_eq!(inject(&tx, plain).await, InjectOutcome::Replaced);
        let recovered = drain(&mut out_rx);
        assert_eq!(announced(&recovered), [key(Some(RD_A))]);
        assert_eq!(withdrawn(&recovered), []);
        assert_eq!(selected(&tx).await, [None, Some(RD_A), Some(RD_B)]);

        drop(tx);
        handle.await.unwrap();
    }
}

/// The same components in global scope, RD A and RD B are three rules. An
/// RT-only change replaces its rule in place with one announcement and no
/// withdrawal; a delete touches only its own RD; a new RD is a new rule and
/// leaves the old one in place.
///
/// Break-to-red: a key without the RD collapses the three rules into one, so
/// the first assertion sees one announcement and the delete removes them all.
#[tokio::test]
async fn global_and_scoped_rules_coexist_and_change_independently() {
    let (tx, handle) = start();
    let mut out_rx = peer_up(&tx, 10, vec![GLOBAL, VPN], None).await;

    for rd in [None, Some(RD_A), Some(RD_B)] {
        assert_eq!(
            inject(&tx, local_rule(rd, 777)).await,
            InjectOutcome::Created
        );
    }
    let updates = drain(&mut out_rx);
    assert_eq!(
        announced(&updates),
        [key(None), key(Some(RD_A)), key(Some(RD_B))]
    );
    assert_eq!(withdrawn(&updates), []);

    // RT-only change: the same key, replaced in place.
    let changed = local_rule(Some(RD_A), 778);
    assert_eq!(inject(&tx, changed.clone()).await, InjectOutcome::Replaced);
    let updates = drain(&mut out_rx);
    assert_eq!(announced(&updates), [key(Some(RD_A))]);
    assert_eq!(
        updates[0].flowspec_announce[0].attributes, changed.attributes,
        "the advertised rule carries only the new RT"
    );
    assert_eq!(withdrawn(&updates), []);

    // A delete in RD A leaves global scope and RD B.
    assert!(withdraw(&tx, key(Some(RD_A))).await);
    let updates = drain(&mut out_rx);
    assert_eq!(announced(&updates), []);
    assert_eq!(withdrawn(&updates), [key(Some(RD_A))]);
    assert_eq!(selected(&tx).await, [None, Some(RD_B)]);

    // An RD change is a new rule; the old key stays until it is deleted.
    assert_eq!(
        inject(&tx, local_rule(Some(RD_C), 777)).await,
        InjectOutcome::Created
    );
    let updates = drain(&mut out_rx);
    assert_eq!(announced(&updates), [key(Some(RD_C))]);
    assert_eq!(withdrawn(&updates), []);
    assert_eq!(selected(&tx).await, [None, Some(RD_B), Some(RD_C)]);

    drop(tx);
    handle.await.unwrap();
}

/// A peer receives only the `FlowSpec` families it negotiated: global rules
/// never reach a VPN-only peer and VPN rules never reach a global-only one.
/// End-of-RIB is sent per negotiated family.
#[tokio::test]
async fn rules_reach_only_peers_that_negotiated_their_family() {
    let (tx, handle) = start();
    let (outbound_tx, mut both_rx) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        per_client_best: false,
        interpret_rfc1997: true,
        session_id: 0,
        peer: peer_v4(Ipv4Addr::new(192, 0, 2, 9)),
        peer_asn: 65100,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx,
        export_policy: None,
        sendable_families: vec![GLOBAL, VPN],
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: Vec::new(),
        negotiated_llgr_families: Vec::new(),
    })
    .await
    .unwrap();
    let eor = both_rx.recv().await.unwrap();
    assert_eq!(eor.end_of_rib, [GLOBAL, VPN]);

    let mut global_rx = peer_up(&tx, 10, vec![GLOBAL], None).await;
    let mut vpn_rx = peer_up(&tx, 11, vec![VPN], None).await;
    inject(&tx, local_rule(None, 777)).await;
    inject(&tx, local_rule(Some(RD_A), 777)).await;
    assert_eq!(announced(&drain(&mut global_rx)), [key(None)]);
    assert_eq!(announced(&drain(&mut vpn_rx)), [key(Some(RD_A))]);
    assert_eq!(
        announced(&drain(&mut both_rx)),
        [key(None), key(Some(RD_A))]
    );

    drop(tx);
    handle.await.unwrap();
}

/// An RT change that export policy denies withdraws the rule from the peer
/// that had it, with no announcement: the rule is no longer eligible.
#[tokio::test]
async fn an_rt_change_that_export_policy_denies_withdraws_the_rule() {
    let mut deny = super::flowspec::flowspec_policy_statement(
        0,
        rustbgpd_policy::RouteModifications::default(),
    );
    deny.match_community = vec![rustbgpd_policy::CommunityMatch::RouteTarget {
        global: 44407,
        local: 999,
    }];
    deny.action = rustbgpd_policy::PolicyAction::Deny;
    let policy = rustbgpd_policy::PolicyChain::new(vec![rustbgpd_policy::Policy {
        entries: vec![deny],
        default_action: rustbgpd_policy::PolicyAction::Permit,
    }]);
    let (tx, handle) = start();
    let mut out_rx = peer_up(&tx, 10, vec![VPN], Some(policy)).await;

    inject(&tx, local_rule(Some(RD_A), 777)).await;
    assert_eq!(announced(&drain(&mut out_rx)), [key(Some(RD_A))]);
    assert_eq!(
        inject(&tx, local_rule(Some(RD_A), 999)).await,
        InjectOutcome::Replaced
    );
    let updates = drain(&mut out_rx);
    assert_eq!(announced(&updates), []);
    assert_eq!(withdrawn(&updates), [key(Some(RD_A))]);

    drop(tx);
    handle.await.unwrap();
}

/// A ROUTE-REFRESH for (1, 134) replays the VPN rules only, then the
/// family's End-of-RIB.
#[tokio::test]
async fn route_refresh_for_vpn_flowspec_replays_vpn_rules_only() {
    let (tx, handle) = start();
    let target = 10;
    let mut out_rx = peer_up(&tx, target, vec![GLOBAL, VPN], None).await;
    inject(&tx, local_rule(None, 777)).await;
    inject(&tx, local_rule(Some(RD_A), 777)).await;
    drain(&mut out_rx);

    tx.send(RibUpdate::RouteRefreshRequest {
        queued: Arc::default(),
        session_id: 0,
        peer: peer_v4(Ipv4Addr::new(192, 0, 2, target)),
        afi: Afi::Ipv4,
        safi: Safi::FlowSpecVpn,
    })
    .await
    .unwrap();
    let update = out_rx.recv().await.unwrap();
    assert_eq!(announced(std::slice::from_ref(&update)), [key(Some(RD_A))]);
    assert_eq!(update.end_of_rib, [VPN]);

    drop(tx);
    handle.await.unwrap();
}

/// RFC 4684 RT-Constrain does not gate VPN `FlowSpec` (ADR-0146 §5): a peer
/// that negotiated RTC and announced no membership still receives the rule,
/// and the (1, 134) End-of-RIB is not held behind the peer's RTC End-of-RIB.
/// Gating it later is a deliberate change.
#[tokio::test]
async fn rt_constrain_does_not_gate_vpn_flowspec() {
    let vpn_unicast = (Afi::Ipv4, Safi::MplsVpn);
    let (tx, handle) = start();
    let mut out_rx = register(&tx, 10, vec![RTC, VPN, vpn_unicast], None).await;
    inject(&tx, local_rule(Some(RD_A), 777)).await;
    let _ = query_flowspec_routes(&tx).await;
    let updates = drain(&mut out_rx);
    assert!(
        !updates
            .iter()
            .any(|update| update.end_of_rib.contains(&vpn_unicast)),
        "VPN unicast still waits for RT-Constrain End-of-RIB"
    );
    assert!(
        updates
            .iter()
            .any(|update| update.end_of_rib.contains(&VPN)),
        "the (1, 134) End-of-RIB waits for no RT-Constrain End-of-RIB"
    );
    assert_eq!(announced(&updates), [key(Some(RD_A))]);

    drop(tx);
    handle.await.unwrap();
}

/// VPN rules are counted as their own family: they never inflate the
/// `ipv4_flowspec` Loc-RIB and Adj-RIB-Out counts.
#[tokio::test]
async fn vpn_rules_are_counted_apart_from_global_ipv4_flowspec() {
    let (_tx, rx) = mpsc::channel(8);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let (outbound_tx, _out_rx) = mpsc::channel(64);
    manager.handle_update(RibUpdate::PeerUp {
        per_client_best: false,
        interpret_rfc1997: true,
        session_id: 0,
        peer: peer_v4(Ipv4Addr::new(192, 0, 2, 10)),
        peer_asn: 65100,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx,
        export_policy: None,
        sendable_families: vec![GLOBAL, VPN],
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: Vec::new(),
        negotiated_llgr_families: Vec::new(),
    });
    for rd in [None, Some(RD_A), Some(RD_B)] {
        let (reply, mut response) = oneshot::channel();
        manager.handle_inject_flowspec(local_rule(rd, 777), reply);
        response.try_recv().unwrap().unwrap();
    }
    let lens = manager.loc_rib.family_lens();
    assert_eq!((lens.flowspec, lens.flowspec_vpn), ([1, 0], 2));
    let peer = peer_v4(Ipv4Addr::new(192, 0, 2, 10));
    let lens = manager.adj_ribs_out[&peer].family_lens();
    assert_eq!((lens.flowspec, lens.flowspec_vpn), ([1, 0], 2));

    // The published gauges carry the same split.
    let peer = peer.to_string();
    for (family, expected) in [("ipv4_flowspec", 1.0), ("l3vpn_ipv4_flowspec", 2.0)] {
        assert!(
            (gauge_metric_value(
                &manager.metrics,
                "bgp_rib_loc_prefixes",
                &[("family", family)]
            ) - expected)
                .abs()
                < f64::EPSILON,
            "Loc-RIB {family}"
        );
        assert!(
            (gauge_metric_value(
                &manager.metrics,
                "bgp_rib_adj_out_prefixes",
                &[("peer", &peer), ("family", family)]
            ) - expected)
                .abs()
                < f64::EPSILON,
            "Adj-RIB-Out {family}"
        );
    }
}

/// Exact-export metrics label a VPN rule with its own family.
#[test]
fn exact_export_keys_label_each_flowspec_family() {
    use crate::update::ExactExportKey;
    let mut v6 = key(None);
    v6.afi = Afi::Ipv6;
    for (key, label) in [
        (key(None), "ipv4_flowspec"),
        (v6, "ipv6_flowspec"),
        (key(Some(RD_A)), "l3vpn_ipv4_flowspec"),
    ] {
        assert_eq!(ExactExportKey::FlowSpec(key).family_label(), label);
    }
}

/// An enhanced route refresh of global `FlowSpec` (RFC 7313) snapshots,
/// counts and sweeps that family's rules by rule: a re-announced rule leaves
/// the stale set, a withdrawn one is uncounted, the End-of-Route-Refresh
/// sweeps only the rules that were not refreshed, and the window leaves no
/// stale snapshot behind. The `withdrawing_*` tests below cover the AFI and
/// RD parts of the identity.
#[test]
fn flowspec_refresh_window_counts_and_sweeps_by_identity() {
    let (_tx, rx) = mpsc::channel(8);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let source = Ipv4Addr::new(10, 0, 0, 1);
    let peer = peer_v4(source);
    let (outbound_tx, _outbound_rx) = mpsc::channel(64);
    manager.handle_update(RibUpdate::PeerUp {
        per_client_best: false,
        interpret_rfc1997: true,
        session_id: 2,
        peer,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx,
        export_policy: None,
        sendable_families: vec![GLOBAL],
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: Vec::new(),
        negotiated_llgr_families: Vec::new(),
    });
    let rule = |octet| {
        let mut route = make_flowspec_route(source);
        route.rule.components = vec![rustbgpd_wire::FlowSpecComponent::DestinationPrefix(
            rustbgpd_wire::FlowSpecPrefix::V4(Ipv4Prefix::new(
                Ipv4Addr::new(203, 0, 113, octet),
                32,
            )),
        )];
        route
    };
    let received = |announced, withdrawn| RibUpdate::RoutesReceived {
        session_id: 2,
        peer,
        announced: vec![],
        withdrawn: vec![],
        flowspec_announced: announced,
        flowspec_withdrawn: withdrawn,
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
        validated_with: None,
    };
    let stale = |manager: &RibManager| {
        manager
            .refresh_stale_counts
            .get(&(peer, Afi::Ipv4, Safi::FlowSpec))
            .copied()
            .unwrap_or(0)
    };
    manager.handle_update(received(vec![rule(1), rule(2), rule(3), rule(4)], vec![]));
    drain_route_chunks(&mut manager);
    manager.handle_update(RibUpdate::BeginRouteRefresh {
        session_id: 2,
        peer,
        afi: Afi::Ipv4,
        safi: Safi::FlowSpec,
    });
    assert_eq!(stale(&manager), 4);

    manager.handle_update(received(vec![rule(1)], vec![]));
    drain_route_chunks(&mut manager);
    assert_eq!(stale(&manager), 3, "a re-announced rule is refreshed");
    manager.handle_update(received(vec![], vec![rule(2).selection_key()]));
    drain_route_chunks(&mut manager);
    assert_eq!(stale(&manager), 2, "a withdrawn rule is no longer stale");

    manager.handle_update(RibUpdate::EndRouteRefresh {
        session_id: 2,
        peer,
        afi: Afi::Ipv4,
        safi: Safi::FlowSpec,
    });
    drain_route_chunks(&mut manager);
    let left: Vec<_> = manager.ribs[&peer]
        .iter_flowspec()
        .map(|route| route.rule.clone())
        .collect();
    assert_eq!(left, [rule(1).rule], "only the unrefreshed rules are swept");
    assert_eq!(stale(&manager), 0);
    assert!(
        !manager.refresh_stale_flowspec.contains_key(&peer),
        "the window's stale snapshot is released"
    );
}

/// A rule with only a destination-port component, so the same components are
/// legal in either AFI and in any RD.
fn port_rule(source: Ipv4Addr, afi: Afi, rd: Option<RouteDistinguisher>) -> FlowSpecRoute {
    let mut route = make_flowspec_route(source);
    route.afi = afi;
    route.rd = rd;
    route.rule.components = vec![rustbgpd_wire::FlowSpecComponent::DestinationPort(vec![
        rustbgpd_wire::NumericMatch {
            end_of_list: true,
            and_bit: false,
            lt: false,
            gt: false,
            eq: true,
            value: 80,
        },
    ])];
    route
}

/// Receive `withdrawn` and `twin` (the same components under another AFI or
/// RD), open the enhanced-refresh window of each family, and withdraw
/// `withdrawn`. The twin must stay stale and counted, and be swept at its
/// End-of-Route-Refresh.
fn withdrawing_one_rule_keeps_its_twin_stale(
    source: Ipv4Addr,
    withdrawn: FlowSpecRoute,
    twin: FlowSpecRoute,
) {
    let (_tx, rx) = mpsc::channel(8);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let peer = peer_v4(source);
    let mut families = vec![withdrawn.family(), twin.family()];
    families.dedup();
    let (outbound_tx, _outbound_rx) = mpsc::channel(64);
    manager.handle_update(RibUpdate::PeerUp {
        per_client_best: false,
        interpret_rfc1997: true,
        session_id: 2,
        peer,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx,
        export_policy: None,
        sendable_families: families.clone(),
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: Vec::new(),
        negotiated_llgr_families: Vec::new(),
    });
    let received = |announced, withdrawn| RibUpdate::RoutesReceived {
        session_id: 2,
        peer,
        announced: vec![],
        withdrawn: vec![],
        flowspec_announced: announced,
        flowspec_withdrawn: withdrawn,
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
        validated_with: None,
    };
    let stale = |manager: &RibManager, (afi, safi): (Afi, Safi)| {
        manager
            .refresh_stale_counts
            .get(&(peer, afi, safi))
            .copied()
            .unwrap_or(0)
    };
    let twin_family = twin.family();
    let withdrawn_key = withdrawn.selection_key();
    manager.handle_update(received(vec![withdrawn, twin], vec![]));
    drain_route_chunks(&mut manager);
    assert_eq!(manager.ribs[&peer].iter_flowspec().count(), 2);
    for &(afi, safi) in &families {
        manager.handle_update(RibUpdate::BeginRouteRefresh {
            session_id: 2,
            peer,
            afi,
            safi,
        });
    }

    manager.handle_update(received(vec![], vec![withdrawn_key]));
    drain_route_chunks(&mut manager);
    assert_eq!(
        stale(&manager, twin_family),
        1,
        "withdrawing one rule leaves its twin stale"
    );

    for &(afi, safi) in &families {
        manager.handle_update(RibUpdate::EndRouteRefresh {
            session_id: 2,
            peer,
            afi,
            safi,
        });
    }
    drain_route_chunks(&mut manager);
    assert_eq!(
        manager.ribs[&peer].iter_flowspec().count(),
        0,
        "the unrefreshed twin is swept at End-of-Route-Refresh"
    );
}

/// The same destination-less rule in IPv4 and IPv6, both windows open.
#[test]
fn withdrawing_a_rule_keeps_its_other_afi_twin_stale() {
    let source = Ipv4Addr::new(10, 0, 0, 1);
    withdrawing_one_rule_keeps_its_twin_stale(
        source,
        port_rule(source, Afi::Ipv4, None),
        port_rule(source, Afi::Ipv6, None),
    );
}

/// The same components under RD A and RD B in one (1, 134) window.
#[test]
fn withdrawing_a_vpn_rule_keeps_its_other_rd_twin_stale() {
    let source = Ipv4Addr::new(10, 0, 0, 1);
    withdrawing_one_rule_keeps_its_twin_stale(
        source,
        port_rule(source, Afi::Ipv4, Some(RD_A)),
        port_rule(source, Afi::Ipv4, Some(RD_B)),
    );
}

/// The same components as a global rule and under RD A, with the (1, 133)
/// and (1, 134) windows both open.
#[test]
fn withdrawing_a_global_rule_keeps_its_vpn_twin_stale() {
    let source = Ipv4Addr::new(10, 0, 0, 1);
    withdrawing_one_rule_keeps_its_twin_stale(
        source,
        port_rule(source, Afi::Ipv4, None),
        port_rule(source, Afi::Ipv4, Some(RD_A)),
    );
}
