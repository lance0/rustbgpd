//! VPN `FlowSpec` (AFI 1 and 2 / SAFI 134) identity, policy and
//! distribution. A rule is keyed by `(family, RD, components)`: the same
//! components in global scope and in each RD are distinct rules.

use super::*;
use crate::injection_lease::{GuardedFence, MutationWindowId};
use crate::route::FlowSpecKey;
use crate::test_support::peer_v4;
use crate::update::{InjectOutcome, RibCommandError};
use rustbgpd_wire::{ExtendedCommunity, RouteDistinguisher};

const RD_A: RouteDistinguisher = RouteDistinguisher([0, 0, 0xad, 0x77, 0, 0, 0, 40]);
const RD_B: RouteDistinguisher = RouteDistinguisher([0, 0, 0xad, 0x77, 0, 0, 0, 41]);
const RD_C: RouteDistinguisher = RouteDistinguisher([0, 0, 0xad, 0x77, 0, 0, 0, 42]);
const GLOBAL: (Afi, Safi) = (Afi::Ipv4, Safi::FlowSpec);
const VPN: (Afi, Safi) = (Afi::Ipv4, Safi::FlowSpecVpn);
const GLOBAL_V6: (Afi, Safi) = (Afi::Ipv6, Safi::FlowSpec);
const VPN_V6: (Afi, Safi) = (Afi::Ipv6, Safi::FlowSpecVpn);
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
    route.attributes = AttrSet::new(vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath { segments: vec![] }),
        rt(rt_value),
    ]);
    route
}

fn key(rd: Option<RouteDistinguisher>) -> FlowSpecKey {
    local_rule(rd, 0).selection_key()
}

/// The same components are valid across both AFIs, global scope and each RD.
fn local_port_rule(afi: Afi, rd: Option<RouteDistinguisher>, rt_value: u32) -> FlowSpecRoute {
    let mut route = local_rule(rd, rt_value);
    route.afi = afi;
    route.rule = port_rule(Ipv4Addr::UNSPECIFIED, afi, rd).rule;
    route
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
        supersedes: None,
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

#[derive(Clone, Copy, Debug)]
enum AddMode {
    Plain,
    Leased,
    Guarded,
}

fn add_in_mode(
    manager: &mut RibManager,
    mode: AddMode,
    route: FlowSpecRoute,
    window: MutationWindowId,
    lease_seconds: u32,
) -> Result<InjectOutcome, RibCommandError> {
    if matches!(mode, AddMode::Plain) {
        let (reply, mut response) = oneshot::channel();
        manager.handle_update(RibUpdate::InjectFlowSpec { route, reply });
        return response.try_recv().unwrap();
    }
    let (reply, mut response) = oneshot::channel();
    manager.handle_update(match mode {
        AddMode::Leased => RibUpdate::InjectLeasedFlowSpec {
            route,
            owner: "ctl".to_string(),
            lease_seconds,
            reply,
        },
        AddMode::Guarded => RibUpdate::InjectGuardedFlowSpec {
            route,
            owner: "ctl".to_string(),
            lease_seconds,
            fence: GuardedFence {
                window,
                revision: std::num::NonZeroU64::new(1).unwrap(),
            },
            reply,
        },
        AddMode::Plain => unreachable!("plain replies do not carry a lease generation"),
    });
    response.try_recv().unwrap().map(|(outcome, _)| outcome)
}

fn scope_admission_manager() -> (RibManager, mpsc::Receiver<OutboundRouteUpdate>) {
    let (_tx, rx) = mpsc::channel(8);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let (outbound_tx, out_rx) = mpsc::channel(64);
    manager.handle_update(RibUpdate::PeerUp {
        supersedes: None,
        per_client_best: false,
        interpret_rfc1997: true,
        session_id: 0,
        peer: peer_v4(Ipv4Addr::new(192, 0, 2, 10)),
        peer_asn: 65100,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx,
        export_policy: None,
        sendable_families: vec![GLOBAL, GLOBAL_V6, VPN, VPN_V6],
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: Vec::new(),
        negotiated_llgr_families: Vec::new(),
    });
    (manager, out_rx)
}

/// Internal typed commands still cross the common admission boundary. This
/// unsupported shape cannot arrive through the receive-and-discard path.
/// Removing the guard admits the key and changes family counts and leases.
#[tokio::test(start_paused = true)]
async fn vpn_scope_rejects_non_ip_before_any_admission() {
    let peer = peer_v4(Ipv4Addr::new(192, 0, 2, 10));
    for mode in [AddMode::Plain, AddMode::Leased, AddMode::Guarded] {
        let (mut manager, mut out_rx) = scope_admission_manager();
        let leases = manager.injection_leases();
        let (window, _) = leases.issue_window("ctl", 120).unwrap();
        let snapshot = |manager: &RibManager| {
            let row = |route: &FlowSpecRoute| {
                (route.key(), (route.attributes.clone(), route.received_at))
            };
            (
                manager
                    .ribs
                    .get(&LOCAL_PEER)
                    .map(|rib| rib.iter_flowspec().map(row).collect::<HashMap<_, _>>()),
                manager
                    .loc_rib
                    .iter_flowspec()
                    .map(row)
                    .collect::<HashMap<_, _>>(),
                manager.adj_ribs_out[&peer]
                    .iter_flowspec()
                    .map(row)
                    .collect::<HashMap<_, _>>(),
                manager.loc_rib.family_lens(),
                manager.adj_ribs_out[&peer].family_lens(),
                manager.injected_owners.clone(),
                manager.owner_keys.clone(),
                leases.list(None),
            )
        };
        // Refusal must neither create a new lease nor renew an existing one.
        for seeded in [false, true] {
            if seeded {
                for afi in [Afi::Ipv4, Afi::Ipv6] {
                    for rd in [None, Some(RD_A), Some(RD_B)] {
                        assert_eq!(
                            add_in_mode(
                                &mut manager,
                                mode,
                                local_port_rule(afi, rd, 777),
                                window,
                                5
                            )
                            .unwrap(),
                            InjectOutcome::Created,
                            "{mode:?}: valid global and VPN controls are admitted"
                        );
                    }
                }
                assert_eq!(announced(&drain(&mut out_rx)).len(), 6);
                let lens = manager.loc_rib.family_lens();
                assert_eq!((lens.flowspec, lens.flowspec_vpn), ([1, 1], [2, 2]));
            } else {
                drain(&mut out_rx);
            }
            let before = snapshot(&manager);
            for afi in [Afi::L2Vpn, Afi::BgpLs] {
                let invalid = local_port_rule(afi, Some(RD_A), 777);
                let error = add_in_mode(&mut manager, mode, invalid, window, 60).unwrap_err();
                assert!(
                    matches!(error, RibCommandError::Internal(_)),
                    "{mode:?}: {error:?}"
                );
                assert!(
                    error.to_string().contains("requires IPv4 or IPv6"),
                    "{error}"
                );
                assert_eq!(snapshot(&manager), before, "{mode:?}/{afi:?}: no mutation");
                assert!(
                    drain(&mut out_rx).is_empty(),
                    "{mode:?}/{afi:?}: no outbound work"
                );
            }
        }
    }
}

#[tokio::test]
async fn missing_vpn_rule_diagnostics_preserve_the_scoped_identity() {
    let (_tx, rx) = mpsc::channel(8);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    // These two RDs have the same Display text but different wire encodings.
    let small_asn_type_two = RouteDistinguisher([0, 2, 0, 0, 0xad, 0x77, 0, 40]);
    assert_eq!(RD_A.to_string(), small_asn_type_two.to_string());
    for afi in [Afi::Ipv4, Afi::Ipv6] {
        for rd in [None, Some(RD_A), Some(RD_B), Some(small_asn_type_two)] {
            let key = local_port_rule(afi, rd, 777).selection_key();
            let (reply, mut response) = oneshot::channel();
            manager.handle_update(RibUpdate::WithdrawFlowSpec {
                key: key.clone(),
                allow_missing: false,
                owner: String::new(),
                override_owner: false,
                reply,
            });
            let expected = match rd {
                Some(rd) => format!(
                    "FlowSpec {afi:?}/FlowSpecVpn RD 0x{:016x} rule {} not found",
                    u64::from_be_bytes(rd.octets()),
                    key.rule
                ),
                None => format!("FlowSpec {afi:?} rule {} not found", key.rule),
            };
            assert_eq!(
                response.try_recv().unwrap(),
                Err(RibCommandError::NotFound(expected))
            );
        }
    }
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
async fn rpol_ipv6_vpn_flowspec_matches_only_its_afi_and_scope() {
    let (tx, handle) = start();
    let mut out_rx = peer_up(
        &tx,
        10,
        vec![GLOBAL, GLOBAL_V6, VPN, VPN_V6],
        Some(rpol_chain(
            "policy export { term vpn { if route.family == vpnv6-flowspec { reject } } }",
        )),
    )
    .await;
    let mut expected = HashSet::new();
    for afi in [Afi::Ipv4, Afi::Ipv6] {
        for rd in [None, Some(RD_A), Some(RD_B)] {
            let route = local_port_rule(afi, rd, 777);
            if route.family() != VPN_V6 {
                expected.insert(route.selection_key());
            }
            inject(&tx, route).await;
        }
    }
    let updates = drain(&mut out_rx);
    assert_eq!(
        announced(&updates).into_iter().collect::<HashSet<_>>(),
        expected
    );
    assert_eq!(withdrawn(&updates).len(), 0);
    assert_eq!(query_flowspec_routes(&tx).await.len(), 6);
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
        AttrSet::edit(&mut route.attributes, |attrs| {
            for attr in attrs.iter_mut() {
                if let PathAttribute::ExtendedCommunities(communities) = attr {
                    communities.push(action);
                }
            }
            attrs.push(PathAttribute::Communities(vec![marker]));
        });
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
        AttrSet::edit(&mut restricted.attributes, |attrs| {
            attrs.push(PathAttribute::Communities(vec![marker]));
        });
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
        AttrSet::edit(&mut restricted.attributes, |attrs| {
            attrs.push(PathAttribute::Med(999));
        });
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

/// Negotiation and End-of-RIB cover the complete AFI/SAFI tuple.
#[tokio::test]
async fn rules_reach_only_peers_that_negotiated_their_family() {
    let (tx, handle) = start();
    let families = [GLOBAL, GLOBAL_V6, VPN, VPN_V6];
    let mut all_rx = register(&tx, 9, families.to_vec(), None).await;
    assert_eq!(all_rx.recv().await.unwrap().end_of_rib, families);
    let mut peers = Vec::new();
    for (index, family) in families.into_iter().enumerate() {
        let out_rx = peer_up(&tx, 10 + u8::try_from(index).unwrap(), vec![family], None).await;
        peers.push((family, out_rx));
    }
    let mut keys = HashSet::new();
    for afi in [Afi::Ipv4, Afi::Ipv6] {
        for rd in [None, Some(RD_A), Some(RD_B)] {
            let route = local_port_rule(afi, rd, 777);
            keys.insert(route.selection_key());
            inject(&tx, route).await;
        }
    }
    assert_eq!(
        announced(&drain(&mut all_rx))
            .into_iter()
            .collect::<HashSet<_>>(),
        keys
    );
    for (family, out_rx) in &mut peers {
        let expected = keys
            .iter()
            .filter(|key| key.family() == *family)
            .cloned()
            .collect::<HashSet<_>>();
        assert_eq!(
            announced(&drain(out_rx))
                .into_iter()
                .collect::<HashSet<_>>(),
            expected,
            "{family:?}"
        );
    }
    for key in &keys {
        assert!(withdraw(&tx, key.clone()).await);
    }
    assert_eq!(
        withdrawn(&drain(&mut all_rx))
            .into_iter()
            .collect::<HashSet<_>>(),
        keys
    );
    for (family, out_rx) in &mut peers {
        let expected = keys
            .iter()
            .filter(|key| key.family() == *family)
            .cloned()
            .collect::<HashSet<_>>();
        assert_eq!(
            withdrawn(&drain(out_rx))
                .into_iter()
                .collect::<HashSet<_>>(),
            expected,
            "{family:?}"
        );
    }
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

/// A requested VPN replay includes only that AFI/SAFI and its End-of-RIB.
#[tokio::test]
async fn route_refresh_for_vpn_flowspec_replays_vpn_rules_only() {
    let (tx, handle) = start();
    let target = 10;
    let mut out_rx = peer_up(&tx, target, vec![GLOBAL, GLOBAL_V6, VPN, VPN_V6], None).await;
    for afi in [Afi::Ipv4, Afi::Ipv6] {
        for rd in [None, Some(RD_A), Some(RD_B)] {
            inject(&tx, local_port_rule(afi, rd, 777)).await;
        }
    }
    drain(&mut out_rx);
    for (afi, safi) in [VPN, VPN_V6] {
        tx.send(RibUpdate::RouteRefreshRequest {
            queued: Arc::default(),
            session_id: 0,
            peer: peer_v4(Ipv4Addr::new(192, 0, 2, target)),
            afi,
            safi,
        })
        .await
        .unwrap();
        let update = out_rx.recv().await.unwrap();
        assert_eq!(
            announced(std::slice::from_ref(&update)),
            [
                local_port_rule(afi, Some(RD_A), 777).selection_key(),
                local_port_rule(afi, Some(RD_B), 777).selection_key(),
            ]
        );
        assert_eq!(update.end_of_rib, [(afi, safi)]);
    }
    drop(tx);
    handle.await.unwrap();
}

/// RFC 4684 RT-Constrain does not gate VPN `FlowSpec` (ADR-0146 §5): a peer
/// that negotiated RTC and announced no membership still receives the rule,
/// and neither AFI's End-of-RIB is held behind the peer's RTC End-of-RIB.
/// Gating it later is a deliberate change.
#[tokio::test]
async fn rt_constrain_does_not_gate_vpn_flowspec() {
    let vpn_unicast = (Afi::Ipv4, Safi::MplsVpn);
    let (tx, handle) = start();
    let mut out_rx = register(&tx, 10, vec![RTC, VPN, VPN_V6, vpn_unicast], None).await;
    inject(&tx, local_port_rule(Afi::Ipv4, Some(RD_A), 777)).await;
    inject(&tx, local_port_rule(Afi::Ipv6, Some(RD_A), 777)).await;
    let _ = query_flowspec_routes(&tx).await;
    let updates = drain(&mut out_rx);
    assert!(
        !updates
            .iter()
            .any(|update| update.end_of_rib.contains(&vpn_unicast)),
        "VPN unicast still waits for RT-Constrain End-of-RIB"
    );
    for family in [VPN, VPN_V6] {
        assert!(
            updates
                .iter()
                .any(|update| update.end_of_rib.contains(&family)),
            "the {family:?} End-of-RIB waits for no RT-Constrain End-of-RIB"
        );
    }
    assert_eq!(
        announced(&updates).into_iter().collect::<HashSet<_>>(),
        [Afi::Ipv4, Afi::Ipv6]
            .into_iter()
            .map(|afi| local_port_rule(afi, Some(RD_A), 777).selection_key())
            .collect::<HashSet<_>>()
    );

    drop(tx);
    handle.await.unwrap();
}

fn assert_flowspec_counts(manager: &RibManager, global: [usize; 2], vpn: [usize; 2]) {
    let peer = peer_v4(Ipv4Addr::new(192, 0, 2, 10));
    let local = &manager.ribs[&LOCAL_PEER];
    assert_eq!(local.flowspec_lens(), global);
    assert_eq!(
        local.flowspec_family_lens_with_checkpoint(&mut || {}),
        [global, vpn]
    );
    for lens in [
        manager.loc_rib.family_lens(),
        manager.adj_ribs_out[&peer].family_lens(),
    ] {
        assert_eq!((lens.flowspec, lens.flowspec_vpn), (global, vpn));
    }
    let local_label = LOCAL_PEER.to_string();
    let peer_label = peer.to_string();
    for (family, expected) in [
        ("ipv4_flowspec", global[0]),
        ("ipv6_flowspec", global[1]),
        ("l3vpn_ipv4_flowspec", vpn[0]),
        ("l3vpn_ipv6_flowspec", vpn[1]),
    ] {
        let expected = f64::from(u32::try_from(expected).unwrap());
        for (metric, labels) in [
            ("bgp_rib_loc_prefixes", vec![("family", family)]),
            (
                "bgp_rib_adj_out_prefixes",
                vec![("peer", peer_label.as_str()), ("family", family)],
            ),
            (
                "bgp_rib_prefixes",
                vec![("peer", local_label.as_str()), ("family", family)],
            ),
        ] {
            assert!(
                (gauge_metric_value(&manager.metrics, metric, &labels) - expected).abs()
                    < f64::EPSILON,
                "{metric}/{family}"
            );
        }
    }
}

/// All four AFI/SAFI combinations count separately through replacement and
/// removal, including the zero/one boundary of each family.
#[tokio::test]
async fn vpn_rules_are_counted_apart_from_global_flowspec_in_both_afis() {
    let (mut manager, mut out_rx) = scope_admission_manager();
    let mut routes = Vec::new();
    for afi in [Afi::Ipv4, Afi::Ipv6] {
        for rd in [None, Some(RD_A), Some(RD_B)] {
            let route = local_port_rule(afi, rd, 777);
            let (reply, mut response) = oneshot::channel();
            manager.handle_inject_flowspec(route.clone(), reply);
            assert_eq!(
                response.try_recv().unwrap().unwrap(),
                InjectOutcome::Created
            );
            routes.push(route);
        }
    }
    let updates = drain(&mut out_rx);
    assert_eq!(
        announced(&updates).into_iter().collect::<HashSet<_>>(),
        routes
            .iter()
            .map(FlowSpecRoute::selection_key)
            .collect::<HashSet<_>>()
    );
    assert_flowspec_counts(&manager, [1, 1], [2, 2]);

    let mut global = [1, 1];
    let mut vpn = [2, 2];
    for mut route in routes {
        AttrSet::edit(&mut route.attributes, |attrs| attrs[2] = rt(778));
        for outcome in [InjectOutcome::Replaced, InjectOutcome::Unchanged] {
            let (reply, mut response) = oneshot::channel();
            manager.handle_inject_flowspec(route.clone(), reply);
            assert_eq!(response.try_recv().unwrap().unwrap(), outcome);
            assert_flowspec_counts(&manager, global, vpn);
        }
        let updates = drain(&mut out_rx);
        assert_eq!(announced(&updates), [route.selection_key()]);
        assert_eq!(withdrawn(&updates).len(), 0);
        let counts = if route.rd.is_some() {
            &mut vpn
        } else {
            &mut global
        };
        counts[usize::from(route.afi == Afi::Ipv6)] -= 1;
        for removed in [true, false] {
            let (reply, mut response) = oneshot::channel();
            manager.handle_update(RibUpdate::WithdrawFlowSpec {
                key: route.selection_key(),
                allow_missing: true,
                owner: String::new(),
                override_owner: false,
                reply,
            });
            assert_eq!(response.try_recv().unwrap().unwrap().removed, removed);
            assert_flowspec_counts(&manager, global, vpn);
        }
        let updates = drain(&mut out_rx);
        assert_eq!(announced(&updates).len(), 0);
        assert_eq!(withdrawn(&updates), [route.selection_key()]);
    }
}

/// Exact-export metrics label a VPN rule with its own family.
#[test]
fn exact_export_keys_label_each_flowspec_family() {
    use crate::update::ExactExportKey;
    for (afi, rd, label) in [
        (Afi::Ipv4, None, "ipv4_flowspec"),
        (Afi::Ipv6, None, "ipv6_flowspec"),
        (Afi::Ipv4, Some(RD_A), "l3vpn_ipv4_flowspec"),
        (Afi::Ipv6, Some(RD_A), "l3vpn_ipv6_flowspec"),
    ] {
        let key = local_port_rule(afi, rd, 777).selection_key();
        assert_eq!(ExactExportKey::FlowSpec(key).family_label(), label);
    }
}

#[test]
fn neither_vpn_flowspec_afi_requests_route_refresh() {
    for afi in [Afi::Ipv4, Afi::Ipv6] {
        assert!(crate::route::requests_route_refresh((afi, Safi::FlowSpec)));
        assert!(!crate::route::requests_route_refresh((
            afi,
            Safi::FlowSpecVpn
        )));
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
        supersedes: None,
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
        supersedes: None,
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
    for rd in [None, Some(RD_A)] {
        withdrawing_one_rule_keeps_its_twin_stale(
            source,
            port_rule(source, Afi::Ipv4, rd),
            port_rule(source, Afi::Ipv6, rd),
        );
    }
}

/// The same components under RD A and RD B in either SAFI 134 window.
#[test]
fn withdrawing_a_vpn_rule_keeps_its_other_rd_twin_stale() {
    let source = Ipv4Addr::new(10, 0, 0, 1);
    for afi in [Afi::Ipv4, Afi::Ipv6] {
        withdrawing_one_rule_keeps_its_twin_stale(
            source,
            port_rule(source, afi, Some(RD_A)),
            port_rule(source, afi, Some(RD_B)),
        );
    }
}

/// The same components as a global rule and under RD A, with both SAFI
/// windows open for each AFI.
#[test]
fn withdrawing_a_global_rule_keeps_its_vpn_twin_stale() {
    let source = Ipv4Addr::new(10, 0, 0, 1);
    for afi in [Afi::Ipv4, Afi::Ipv6] {
        withdrawing_one_rule_keeps_its_twin_stale(
            source,
            port_rule(source, afi, None),
            port_rule(source, afi, Some(RD_A)),
        );
    }
}

/// Synthetic typed receive rows exercise the RIB's family inventory; wire
/// receive still discards VPN rules before this boundary.
#[tokio::test(start_paused = true)]
async fn synthetic_vpn_gr_retention_and_expiry_cover_both_afis() {
    let source = Ipv4Addr::new(192, 0, 2, 10);
    let peer = peer_v4(source);
    for retain_v6 in [false, true] {
        let (mut manager, _out_rx) = scope_admission_manager();
        let routes: Vec<_> = [Afi::Ipv4, Afi::Ipv6]
            .into_iter()
            .flat_map(|afi| {
                [None, Some(RD_A), Some(RD_B)]
                    .into_iter()
                    .map(move |rd| port_rule(source, afi, rd))
            })
            .collect();
        let expected: HashSet<_> = routes
            .iter()
            .filter(|route| retain_v6 || route.family() != VPN_V6)
            .map(FlowSpecRoute::selection_key)
            .collect();
        manager.handle_update(RibUpdate::RoutesReceived {
            session_id: 0,
            peer,
            announced: vec![],
            withdrawn: vec![],
            flowspec_announced: routes,
            flowspec_withdrawn: vec![],
            evpn_announced: vec![],
            evpn_withdrawn: vec![],
            validated_with: None,
        });
        drain_route_chunks(&mut manager);
        assert_eq!(manager.loc_rib.flowspec_len(), 6);
        let mut gr_families = vec![GLOBAL, GLOBAL_V6, VPN];
        if retain_v6 {
            gr_families.push(VPN_V6);
        }
        manager.handle_update(RibUpdate::PeerGracefulRestart {
            session_id: 0,
            peer,
            restart_time: 120,
            stale_routes_time: 360,
            gr_families,
            peer_llgr_capable: false,
            peer_llgr_families: vec![],
            llgr_stale_time: 3600,
        });
        assert_eq!(
            manager
                .loc_rib
                .iter_flowspec()
                .map(FlowSpecRoute::selection_key)
                .collect::<HashSet<_>>(),
            expected,
            "only GR-negotiated families remain"
        );
        assert!(
            manager.ribs[&peer]
                .iter_flowspec()
                .all(|route| route.is_stale)
        );
        manager.sweep_gr_stale(peer);
        assert_eq!(
            manager.loc_rib.flowspec_len(),
            0,
            "GR expiry purges every AFI"
        );
        assert!(
            manager
                .ribs
                .get(&peer)
                .is_none_or(|rib| rib.flowspec_len() == 0)
        );
        let lens = manager.loc_rib.family_lens();
        assert_eq!((lens.flowspec, lens.flowspec_vpn), ([0, 0], [0, 0]));
    }
}
