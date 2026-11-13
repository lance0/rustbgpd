//! Readiness inside the table-sized units of typed-family ingest: an
//! RT-Constrain UPDATE that changes a VPN group member's membership, and a
//! BGP-LS UPDATE that rebuilds the ORR cache.

use std::collections::BTreeMap;

use super::llgr_promotion::{
    PRE_QUEUED, chain_topology, readiness_manager, run_with_readiness_probe,
};
use super::*;
use crate::test_support::peer_v4;

const SOURCE: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 9);
const CLIENT: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
/// The one Route Target every staged VPN route carries. It sorts after
/// every other membership entry, so a match compares the whole membership.
const MATCHING_RT: u16 = 60_000;

fn answered(counts: &BTreeMap<&'static str, usize>, stage: &str) -> usize {
    counts.get(stage).copied().unwrap_or(0)
}

/// Run `work` with one readiness query outstanding at a time: every
/// checkpoint that finds the outstanding query answered credits the stage
/// that queued it and queues the next. Unlike [`run_with_readiness_probe`]
/// an unanswered query stays outstanding, because the send path also calls
/// the observer at marks that are not checkpoints. `PRE_QUEUED` counts a
/// query queued before `work` and answered inside it.
pub(super) fn count_answered_readiness(
    manager: &mut RibManager,
    readiness_tx: mpsc::Sender<crate::RibReadinessQuery>,
    work: impl FnOnce(&mut RibManager),
) -> BTreeMap<&'static str, usize> {
    type Reply = oneshot::Receiver<Result<usize, crate::RibReadinessError>>;
    let query = move || {
        let (reply, response) = oneshot::channel();
        readiness_tx
            .try_send(crate::RibReadinessQuery::LocRibCount {
                reply,
                enqueued: Instant::now(),
            })
            .unwrap();
        response
    };
    let mut pre_queued = query();
    let state = Arc::new(Mutex::new((
        None::<(&'static str, Reply)>,
        BTreeMap::<&'static str, usize>::new(),
    )));
    manager.flush_poll_budget = Duration::ZERO;
    manager.replacement_readiness_test_hook = Some(Arc::new({
        let state = Arc::clone(&state);
        move |stage| {
            let mut state = state.lock().unwrap();
            if let Some((queued_at, reply)) = state.0.as_mut() {
                if reply.try_recv().is_err() {
                    return;
                }
                let queued_at = *queued_at;
                *state.1.entry(queued_at).or_default() += 1;
            }
            state.0 = Some((stage, query()));
        }
    }));
    work(manager);
    manager.replacement_readiness_test_hook = None;
    let mut answered = std::mem::take(&mut state.lock().unwrap().1);
    if pre_queued.try_recv().is_ok() {
        answered.insert(PRE_QUEUED, 1);
    }
    answered
}

struct RtcCase {
    answered: BTreeMap<&'static str, usize>,
    vpn_announced: usize,
}

/// A VPN group member with an empty RT membership behind `routes` staged
/// VPN routes (and `evpn` Loc-RIB EVPN routes) receives one RT-Constrain
/// UPDATE of `entries` non-matching Route Targets and the matching one.
/// Returns the readiness queries each stage answered inside that UPDATE's
/// actor turn and the VPN routes it announced to the member.
fn run_rtc_update(routes: u16, entries: u16, evpn: u8, evpn_sendable: bool) -> RtcCase {
    let (mut manager, readiness_tx) = readiness_manager();
    for addr in [SOURCE, CLIENT] {
        manager
            .ribs
            .insert(peer_v4(addr), AdjRibIn::new(peer_v4(addr)));
    }
    register_test_peer(&mut manager, peer_v4(SOURCE), 0);
    manager.handle_update(RibUpdate::VpnRoutesReceived {
        session_id: 0,
        peer: peer_v4(SOURCE),
        announced: (0..routes)
            .map(|index| {
                let mut route = make_vpn_rib_route_with_rts(SOURCE, 0, vec![rt(MATCHING_RT)]);
                let [high, low] = index.to_be_bytes();
                route.nlri.prefix = VpnPrefix::v4(Ipv4Addr::new(10, high, low, 0), 24).unwrap();
                route
            })
            .collect(),
        withdrawn: Vec::new(),
    });
    manager.handle_update(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: peer_v4(SOURCE),
        announced: Vec::new(),
        withdrawn: Vec::new(),
        flowspec_announced: Vec::new(),
        flowspec_withdrawn: Vec::new(),
        evpn_announced: (0..evpn)
            .map(|tag| make_evpn_imet(SOURCE, u32::from(tag)))
            .collect(),
        evpn_withdrawn: Vec::new(),
        validated_with: None,
    });
    drain_route_chunks(&mut manager);

    let mut sendable_families = vpn_rtc_sendable();
    if evpn_sendable {
        sendable_families.push((Afi::L2Vpn, Safi::Evpn));
    }
    let (outbound_tx, mut outbound_rx) = mpsc::channel(usize::from(routes) + 4096);
    manager.handle_update(RibUpdate::PeerUp {
        supersedes: None,
        per_client_best: false,
        interpret_rfc1997: true,
        session_id: 0,
        peer: peer_v4(CLIENT),
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx,
        export_policy: None,
        sendable_families,
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: Vec::new(),
        negotiated_llgr_families: Vec::new(),
    });
    assert!(
        manager.vpn_grouped_member_of(peer_v4(CLIENT)).is_some(),
        "the client must be a VPN group member"
    );
    while outbound_rx.try_recv().is_ok() {}

    let answered = count_answered_readiness(&mut manager, readiness_tx, |manager| {
        manager.handle_update(RibUpdate::RtcRoutesReceived {
            session_id: 0,
            peer: peer_v4(CLIENT),
            announced: (1000..1000 + entries)
                .chain([MATCHING_RT])
                .map(|admin| make_rtc_rib_route(CLIENT, admin, 100))
                .collect(),
            withdrawn: Vec::new(),
        });
    });
    let mut vpn_announced = 0;
    while let Ok(update) = outbound_rx.try_recv() {
        vpn_announced += update.vpn_announce.len();
    }
    RtcCase {
        answered,
        vpn_announced,
    }
}

/// One RT-Constrain UPDATE from a VPN group member walks the group's staged
/// VPN routes and compares each against the whole new membership. The turn
/// answers a probe queued before it and one at every staged route and every
/// membership entry compared, so the work between two answers is one
/// comparison whatever the table and membership sizes; the announcement it
/// produces is unchanged.
#[test]
fn rtc_update_answers_readiness_at_every_route_and_membership_entry() {
    let small = run_rtc_update(64, 8, 0, false);
    let large = run_rtc_update(4096, 100, 0, false);
    for (case, routes, entries) in [(&small, 64, 8), (&large, 4096, 100)] {
        assert_eq!(case.vpn_announced, routes, "every matching route is sent");
        let (walked, compared) = (
            answered(&case.answered, "rtc_membership_delta"),
            answered(&case.answered, "rtc_membership_match"),
        );
        assert!(
            answered(&case.answered, PRE_QUEUED) == 1
                && walked >= routes
                && compared >= routes * (entries + 1),
            "{routes} routes x {entries} entries answered {walked} route and {compared} \
             comparison checkpoints: {:?}",
            case.answered
        );
    }
}

/// The membership change restages the member's private EVPN view. A member
/// that cannot be sent EVPN has none, so its turn must not collect the
/// Loc-RIB's EVPN keys (the empty restage keeps a fixed handful of
/// checkpoints); a member that can still walks them.
#[test]
fn rtc_update_collects_evpn_keys_only_for_an_evpn_member() {
    let without = run_rtc_update(8, 1, 64, false);
    let with = run_rtc_update(8, 1, 64, true);
    let (without, with) = (
        answered(&without.answered, "selection_evpn"),
        answered(&with.answered, "selection_evpn"),
    );
    assert!(
        without < 8 && with >= 64,
        "64 EVPN routes: {without} checkpoints without EVPN sendable, {with} with"
    );
}

const FEED: Ipv4Addr = Ipv4Addr::new(10, 9, 9, 1);

#[expect(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "a small non-negative counter"
)]
fn spf_runs(metrics: &BgpMetrics) -> u64 {
    counter_metric_value(metrics, "bgp_orr_spf_runs_total", &[]) as u64
}

/// The interface address node `node` of [`chain_topology`] has toward its
/// successor: a vantage that resolves to that node.
fn chain_vantage(node: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(10, 0, node, node + 1))
}

/// The first chain link re-advertised with `metric`.
fn first_link(metric: u32) -> crate::route::BgpLsRibRoute {
    use crate::orr::fixtures::{link_route, v4_interface, v4_neighbor};
    link_route(
        FEED,
        1,
        2,
        Some(metric),
        &[
            v4_interface(Ipv4Addr::new(10, 0, 1, 2)),
            v4_neighbor(Ipv4Addr::new(10, 0, 2, 1)),
        ],
    )
}

fn bgpls_update(session_id: u64, announced: Vec<crate::route::BgpLsRibRoute>) -> RibUpdate {
    RibUpdate::BgpLsRoutesReceived {
        session_id,
        peer: peer_v4(FEED),
        announced,
        withdrawn: Vec::new(),
    }
}

/// Bind `vantages` ORR vantages, one per chain node, and feed a chain of
/// `nodes` so each resolves.
fn feed_chain(manager: &mut RibManager, nodes: u8, vantages: u8) {
    for node in 1..=vantages {
        manager
            .peer_orr_vantage
            .insert(peer_v4(Ipv4Addr::new(10, 7, 0, node)), chain_vantage(node));
    }
    register_test_peer(manager, peer_v4(FEED), 0);
    manager.handle_update(bgpls_update(0, chain_topology(FEED, nodes)));
    for node in 1..=vantages {
        assert_eq!(manager.orr.resolved.get(&chain_vantage(node)), Some(&true));
    }
}

/// One BGP-LS UPDATE that moves a link metric, with `vantages` bound over a
/// chain of `nodes`: the readiness queries each stage answered inside its
/// actor turn.
fn run_bgpls_update(nodes: u8, vantages: u8) -> BTreeMap<&'static str, usize> {
    let (mut manager, readiness_tx) = readiness_manager();
    feed_chain(&mut manager, nodes, vantages);
    let answered = run_with_readiness_probe(&mut manager, readiness_tx, |manager| {
        manager.handle_update(bgpls_update(0, vec![first_link(7)]));
    });
    assert_eq!(manager.orr_rebuild_owed_updates, 0);
    assert_eq!(manager.orr.topology.node_count(), usize::from(nodes));
    answered
}

/// A BGP-LS UPDATE with a vantage bound rebuilds the topology and runs one
/// SPF per vantage in its own actor turn. The turn answers a probe queued
/// before it and one inside every rebuild stage; the scan answers per
/// stored route and the SPF per node of every vantage, so neither a larger
/// topology nor more vantages lengthens the work between two answers.
#[test]
fn bgpls_update_answers_readiness_inside_every_orr_rebuild_stage() {
    let small = run_bgpls_update(16, 2);
    let large = run_bgpls_update(250, 64);
    for (counts, nodes, vantages) in [(&small, 16, 2), (&large, 250, 64)] {
        // One prefix and two links per node, less the chain's open end.
        let routes = 3 * nodes - 2;
        let unanswered: Vec<_> = [
            (PRE_QUEUED, 1),
            ("orr_scan", routes),
            ("orr_build", 1),
            ("orr_compare", 1),
            ("orr_vantages", vantages),
            ("orr_spf", nodes * vantages),
            ("orr_signature", vantages),
            ("orr_retire", 1),
        ]
        .into_iter()
        .filter(|&(stage, floor)| answered(counts, stage) < floor)
        .collect();
        assert!(
            unanswered.is_empty(),
            "{nodes} nodes x {vantages} vantages: stages below their floor {unanswered:?}: \
             {counts:?}"
        );
    }
}

/// Binding a peer's ORR vantage at session up, and dropping the last
/// binding at session down, rebuild or retire the cache in that turn: both
/// answer readiness inside the rebuild.
#[test]
fn orr_vantage_bind_and_unbind_answer_readiness_inside_the_rebuild() {
    let (mut manager, readiness_tx) = readiness_manager();
    register_test_peer(&mut manager, peer_v4(FEED), 0);
    manager.handle_update(bgpls_update(0, chain_topology(FEED, 64)));
    let client = peer_v4(CLIENT);
    let (outbound_tx, _outbound_rx) = mpsc::channel(64);
    let bound = count_answered_readiness(&mut manager, readiness_tx.clone(), |manager| {
        manager.handle_update(RibUpdate::PeerUp {
            supersedes: None,
            per_client_best: false,
            interpret_rfc1997: true,
            session_id: 0,
            peer: client,
            peer_asn: 65000,
            peer_router_id: Ipv4Addr::UNSPECIFIED,
            outbound_tx,
            export_policy: None,
            sendable_families: vec![(Afi::Ipv4, Safi::Unicast)],
            is_ebgp: false,
            route_reflector_client: true,
            orr_vantage: Some(chain_vantage(1)),
            add_path_send_families: vec![],
            add_path_send_max: 0,
            negotiated_orf_recv: Vec::new(),
            negotiated_llgr_families: Vec::new(),
        });
    });
    assert_eq!(manager.orr.resolved.get(&chain_vantage(1)), Some(&true));
    let unbound = count_answered_readiness(&mut manager, readiness_tx, |manager| {
        manager.handle_update(RibUpdate::PeerDown {
            peer: client,
            session_id: 0,
        });
    });
    assert!(manager.orr.is_empty());
    assert!(
        answered(&bound, "orr_spf") >= 64 && answered(&unbound, "orr_retire") >= 64,
        "bind answered {bound:?}; unbind answered {unbound:?}"
    );
}

struct Burst {
    manager: RibManager,
    tx: mpsc::Sender<RibUpdate>,
    metrics: BgpMetrics,
}

impl Burst {
    fn new() -> Self {
        let metrics = BgpMetrics::new();
        let (tx, rx) = mpsc::channel(16);
        let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, metrics.clone());
        feed_chain(&mut manager, 8, 2);
        Self {
            manager,
            tx,
            metrics,
        }
    }

    /// Dispatch the next queued primary update, as the actor loop does.
    /// Returns the SPF runs it cost and whether it left a rebuild owed.
    fn step(&mut self) -> (u64, bool) {
        let before = spf_runs(&self.metrics);
        let update = self.manager.try_recv_primary().expect("a queued update");
        self.manager.handle_update(update);
        (
            spf_runs(&self.metrics) - before,
            self.manager.orr_rebuild_owed_updates > 0,
        )
    }
}

/// BGP-LS UPDATEs queued back to back rebuild the ORR cache once, when the
/// last one is dispatched, and leave the cache a one-by-one feed builds.
#[test]
fn queued_bgpls_burst_rebuilds_the_orr_cache_once() {
    let mut burst = Burst::new();
    let mut control = Burst::new();
    for metric in [5, 6, 7] {
        burst
            .tx
            .try_send(bgpls_update(0, vec![first_link(metric)]))
            .unwrap();
        let before = spf_runs(&control.metrics);
        control
            .manager
            .handle_update(bgpls_update(0, vec![first_link(metric)]));
        assert_eq!(
            spf_runs(&control.metrics) - before,
            2,
            "an UPDATE with nothing queued behind it rebuilds at once"
        );
    }
    assert_eq!(
        [burst.step(), burst.step(), burst.step()],
        [(0, true), (0, true), (2, false)],
        "(SPF runs, rebuild owed) per queued UPDATE"
    );
    assert_eq!(burst.manager.orr.signatures, control.manager.orr.signatures);
    assert_eq!(
        burst.manager.loc_rib.family_lens().bgpls,
        control.manager.loc_rib.family_lens().bgpls
    );
}

/// Only a following BGP-LS UPDATE is handled against the older cache: any
/// other queued update, a query, and a discarded BGP-LS UPDATE each end the
/// burst with the cache rebuilt.
#[test]
fn orr_rebuild_is_owed_only_across_consecutive_bgpls_updates() {
    // Another primary update is next: rebuild in the BGP-LS turn itself.
    let mut burst = Burst::new();
    let (reply, _response) = oneshot::channel();
    burst
        .tx
        .try_send(bgpls_update(0, vec![first_link(5)]))
        .unwrap();
    burst
        .tx
        .try_send(RibUpdate::QueryLocRibCount { reply })
        .unwrap();
    assert_eq!(burst.step(), (2, false));
    assert_eq!(burst.step(), (0, false));

    // A query served between two queued BGP-LS UPDATEs rebuilds first.
    for metric in [6, 7] {
        burst
            .tx
            .try_send(bgpls_update(0, vec![first_link(metric)]))
            .unwrap();
    }
    assert_eq!(burst.step(), (0, true));
    let before = spf_runs(&burst.metrics);
    let (reply, _response) = oneshot::channel();
    burst
        .manager
        .handle_update(RibUpdate::QueryLocRibCount { reply });
    assert_eq!(burst.manager.orr_rebuild_owed_updates, 0);
    assert_eq!(spf_runs(&burst.metrics) - before, 2);
    assert_eq!(burst.step(), (2, false));

    // The awaited BGP-LS UPDATE is from a superseded session, then from a
    // deleted neighbor's handle: each discard still pays the rebuild.
    let deleted = PeerId::allocate(crate::PeerEndpoint::new(
        "fe80::9".parse().unwrap(),
        Some("eth0"),
    ));
    burst.manager.handle_update(RibUpdate::PeerDeleted {
        peer: deleted,
        label: None,
        keep_series: false,
    });
    burst
        .manager
        .handle_update(RibUpdate::ReleasePeer { peer: deleted });
    let mut from_deleted = bgpls_update(0, vec![first_link(1)]);
    if let RibUpdate::BgpLsRoutesReceived { peer, .. } = &mut from_deleted {
        *peer = deleted;
    }
    for (metric, discarded) in [
        (8, bgpls_update(99, vec![first_link(1)])),
        (9, from_deleted),
    ] {
        burst
            .tx
            .try_send(bgpls_update(0, vec![first_link(metric)]))
            .unwrap();
        burst.tx.try_send(discarded).unwrap();
        assert_eq!(burst.step(), (0, true));
        assert_eq!(burst.step(), (2, false), "after metric {metric}");
    }
}

/// A re-announcement identical to the stored route is still reselected but
/// owes no ORR rebuild; one that changes the route does.
#[test]
fn identical_bgpls_reannouncement_owes_no_orr_rebuild() {
    let mut burst = Burst::new();
    let before = spf_runs(&burst.metrics);
    burst
        .manager
        .handle_update(bgpls_update(0, chain_topology(FEED, 8)));
    assert_eq!(
        spf_runs(&burst.metrics),
        before,
        "an identical re-announcement re-ran SPF"
    );
    burst
        .manager
        .handle_update(bgpls_update(0, vec![first_link(9)]));
    assert_eq!(
        spf_runs(&burst.metrics) - before,
        2,
        "a changed link metric must rebuild"
    );
}

/// A BGP-LS UPDATE reselects every key it carries against every
/// Adj-RIB-In, and a withdrawal whose identity holds an exact-export
/// rejection walks every stored BGP-LS route to confirm the identity is
/// gone. With no ORR vantage bound there is no rebuild, yet the turn still
/// answers a probe queued before it and one per selected key and per stored
/// route walked.
#[test]
fn bgpls_update_answers_readiness_in_selection_and_rejection_retirement() {
    let (mut manager, readiness_tx) = readiness_manager();
    register_test_peer(&mut manager, peer_v4(FEED), 0);
    let topology = chain_topology(FEED, 64);
    let routes = topology.len();
    let withdrawn_key = topology[0].key();
    let announced = count_answered_readiness(&mut manager, readiness_tx.clone(), |manager| {
        manager.handle_update(bgpls_update(0, topology));
    });
    assert_eq!(manager.loc_rib.family_lens().bgpls[0], routes);

    manager
        .peer_unexportable
        .entry(peer_v4(CLIENT))
        .or_default()
        .insert(ExactExportKey::BgpLs(withdrawn_key.clone()));
    let withdrawn = count_answered_readiness(&mut manager, readiness_tx, |manager| {
        manager.handle_update(RibUpdate::BgpLsRoutesReceived {
            session_id: 0,
            peer: peer_v4(FEED),
            announced: Vec::new(),
            withdrawn: vec![withdrawn_key],
        });
    });
    assert!(
        manager.peer_unexportable.is_empty(),
        "the rejection of a withdrawn identity is retired"
    );
    assert!(
        answered(&announced, PRE_QUEUED) == 1
            && answered(&announced, "selection_bgpls") >= routes
            && answered(&withdrawn, PRE_QUEUED) == 1
            && answered(&withdrawn, "exact_rejection_retirement") >= routes - 1,
        "{routes} routes: announce answered {announced:?}; withdraw answered {withdrawn:?}"
    );
}

/// Withdrawing an RT-Constrain route whose identity holds an exact-export
/// rejection confirms the identity is gone by walking every stored
/// RT-Constrain route. The walk answers readiness at every route.
#[test]
fn rtc_withdrawal_answers_readiness_while_retiring_its_rejection() {
    let (mut manager, readiness_tx) = readiness_manager();
    register_test_peer(&mut manager, peer_v4(SOURCE), 0);
    let routes = 512;
    manager.handle_update(RibUpdate::RtcRoutesReceived {
        session_id: 0,
        peer: peer_v4(SOURCE),
        announced: (0..routes)
            .map(|admin| make_rtc_rib_route(SOURCE, admin, 100))
            .collect(),
        withdrawn: Vec::new(),
    });
    let withdrawn_key = make_rtc_rib_route(SOURCE, 0, 100).key();
    manager
        .peer_unexportable
        .entry(peer_v4(CLIENT))
        .or_default()
        .insert(ExactExportKey::Rtc(withdrawn_key.clone()));
    let counts = count_answered_readiness(&mut manager, readiness_tx, |manager| {
        manager.handle_update(RibUpdate::RtcRoutesReceived {
            session_id: 0,
            peer: peer_v4(SOURCE),
            announced: Vec::new(),
            withdrawn: vec![withdrawn_key],
        });
    });
    assert!(manager.peer_unexportable.is_empty());
    let walked = answered(&counts, "exact_rejection_retirement");
    assert!(
        walked >= usize::from(routes) - 1,
        "{routes} routes: the retirement walk answered {walked}: {counts:?}"
    );
}

/// An End-of-RIB prunes the rejection overlay. A rejected BGP-LS identity
/// that no longer exists is confirmed gone by walking every stored BGP-LS
/// route, and the walk answers readiness at every route.
#[test]
fn end_of_rib_prune_answers_readiness_while_walking_bgpls_routes() {
    let (mut manager, readiness_tx) = readiness_manager();
    register_test_peer(&mut manager, peer_v4(FEED), 0);
    let topology = chain_topology(FEED, 64);
    let routes = topology.len();
    manager.handle_update(bgpls_update(0, topology));
    let dead =
        crate::orr::fixtures::prefix_route(FEED, 200, Ipv4Addr::new(172, 16, 200, 0), 24, Some(1));
    manager
        .peer_unexportable
        .entry(peer_v4(CLIENT))
        .or_default()
        .insert(ExactExportKey::BgpLs(dead.key()));
    let counts = count_answered_readiness(&mut manager, readiness_tx, |manager| {
        manager.handle_update(RibUpdate::EndOfRib {
            session_id: 0,
            peer: peer_v4(FEED),
            afi: Afi::BgpLs,
            safi: Safi::BgpLs,
        });
    });
    assert!(
        manager.peer_unexportable.is_empty(),
        "the dead identity is pruned"
    );
    let walked = answered(&counts, "exact_rejection_retirement");
    assert!(
        walked >= routes,
        "{routes} routes: the prune walk answered {walked}: {counts:?}"
    );
}

/// Retiring a withdrawn Unicast identity's rejection checks liveness through
/// the prefix index, so it takes no readiness owner; a withdrawn BGP-LS
/// identity, whose liveness check can walk the family, takes one.
#[test]
fn indexed_rejection_retirement_takes_no_readiness_owner() {
    let (mut manager, _readiness_tx) = readiness_manager();
    let prefix = Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24));
    let bgpls = chain_topology(FEED, 1)[0].key();
    let rejected = [
        ExactExportKey::Unicast(prefix, 0),
        ExactExportKey::BgpLs(bgpls.clone()),
    ];
    manager
        .peer_unexportable
        .insert(peer_v4(CLIENT), rejected.iter().cloned().collect());
    manager.replacement_readiness_receipts.clear();

    manager.retire_exact_export_rejections([ExactExportKey::Unicast(prefix, 0)]);
    assert!(
        manager.replacement_readiness_receipts.is_empty(),
        "a Unicast retirement took an owner: {:?}",
        manager.replacement_readiness_receipts
    );
    manager.retire_exact_export_rejections([ExactExportKey::BgpLs(bgpls)]);
    assert_eq!(
        manager
            .replacement_readiness_receipts
            .iter()
            .map(|receipt| receipt.kind)
            .collect::<Vec<_>>(),
        [ReadinessOwnerKind::Ingest]
    );
    assert!(manager.peer_unexportable.is_empty(), "both were retired");
}

/// What one actor turn did at a counted stage: the items it visited, the
/// readiness queries answered at them, and the owners the turn took.
#[derive(Debug)]
struct CountedTurn {
    visited: usize,
    answered: usize,
    owners: Vec<ReadinessOwnerKind>,
}

/// Run `turn` with readiness queries wired and count `stage`.
fn counted_turn(
    manager: &mut RibManager,
    readiness_tx: mpsc::Sender<crate::RibReadinessQuery>,
    stage: &'static str,
    turn: impl FnOnce(&mut RibManager),
) -> CountedTurn {
    manager.replacement_readiness_receipts.clear();
    let mut counts = BTreeMap::new();
    let work = super::work_scaling::checkpoints_in(|| {
        counts = count_answered_readiness(manager, readiness_tx, turn);
    });
    CountedTurn {
        visited: work.get(stage).copied().unwrap_or(0),
        answered: answered(&counts, stage),
        owners: manager
            .replacement_readiness_receipts
            .iter()
            .map(|receipt| receipt.kind)
            .collect(),
    }
}

/// A session registers as the first member of its update group over a
/// Loc-RIB of `routes` routes, so its `PeerUp` turn builds the group table.
fn first_member_registration(routes: u16) -> CountedTurn {
    let (mut manager, readiness_tx) = readiness_manager();
    let source = peer_v4(SOURCE);
    register_test_peer(&mut manager, source, 0);
    let announced = (0..routes)
        .map(|index| {
            let [high, low] = index.to_be_bytes();
            make_route(
                Ipv4Prefix::new(Ipv4Addr::new(198, 18, high, low), 32),
                SOURCE,
            )
        })
        .collect();
    manager.handle_update(super::lifecycle::test_routes_received(source, announced));
    drain_route_chunks(&mut manager);
    assert_eq!(manager.loc_rib.len(), usize::from(routes));
    let groups = manager.group_ribs.len();

    let member = peer_v4(CLIENT);
    let (outbound_tx, mut outbound_rx) = mpsc::channel(usize::from(routes) + 8);
    let mut up = super::lifecycle::test_peer_up(member, 1, outbound_tx);
    // An iBGP member cannot share the eBGP source's group.
    if let RibUpdate::PeerUp { is_ebgp, .. } = &mut up {
        *is_ebgp = false;
    }
    let turn = counted_turn(
        &mut manager,
        readiness_tx,
        crate::manager::GROUP_TABLE_BUILD_ROW,
        |manager| manager.handle_update(up),
    );
    let gid = manager
        .grouped_member_of(member)
        .expect("member is grouped");
    assert_eq!(
        manager.group_ribs.len(),
        groups + 1,
        "a new group was built"
    );
    assert_eq!(manager.group_ribs[&gid].table.len(), usize::from(routes));
    let mut sent = 0;
    while let Ok(update) = outbound_rx.try_recv() {
        sent += update.announce.len();
    }
    assert_eq!(sent, usize::from(routes), "the initial table is unchanged");
    turn
}

/// The first member's registration builds its group table from the whole
/// Loc-RIB before the initial table is sent. The build visits every route,
/// and answers readiness at each of them under the ingest owner, ahead of
/// the initial table's own owner.
#[test]
fn first_member_registration_answers_readiness_while_building_the_group_table() {
    let small = first_member_registration(64);
    let large = first_member_registration(256);
    assert_eq!(
        (small.visited, large.visited),
        (64, 256),
        "the build visits every Loc-RIB route in one turn"
    );
    for (routes, turn) in [(64, &small), (256, &large)] {
        assert!(
            turn.answered >= routes,
            "{routes} routes: the build answered {}: {turn:?}",
            turn.answered
        );
        assert_eq!(
            turn.owners,
            [ReadinessOwnerKind::Ingest, ReadinessOwnerKind::Replacement],
            "{routes} routes"
        );
    }
}

/// An EVPN group member whose recovery ledger holds `keys` admitted keys
/// goes down, so its teardown turn releases the ledger.
fn evpn_member_teardown(keys: u16) -> CountedTurn {
    let (mut manager, member, _gid, _output) = super::evpn_group_storage::fixture();
    let (readiness_tx, readiness_rx) = mpsc::channel(2);
    manager = manager.with_readiness_queries(readiness_rx);
    for index in 0..keys {
        let [high, low] = index.to_be_bytes();
        manager
            .adj_ribs_out
            .get_mut(&member)
            .unwrap()
            .insert_evpn(make_evpn_imet(Ipv4Addr::new(198, 51, high, low), 1));
    }
    assert!(
        manager.with_replacement_readiness(|manager| manager.capture_private_evpn_admitted(member))
    );
    let handle = manager.evpn_recovery_handle(member).unwrap();
    assert_eq!(
        manager
            .evpn_recovery
            .proof_keys(handle)
            .unwrap()
            .unwrap()
            .len(),
        usize::from(keys)
    );
    let turn = counted_turn(
        &mut manager,
        readiness_tx,
        crate::manager::EVPN_RECOVERY_RETIRE,
        |manager| {
            manager.handle_update(RibUpdate::PeerDown {
                peer: member,
                session_id: 7,
            });
        },
    );
    assert_eq!(manager.evpn_recovery_handle(member), None);
    turn
}

/// A departing EVPN member's recovery ledger is released one slot at a time
/// with a checkpoint per 64 slots. The release answers readiness at each of
/// them under the ingest owner.
#[test]
fn evpn_member_teardown_answers_readiness_while_releasing_its_recovery_ledger() {
    let small = evpn_member_teardown(4096);
    let large = evpn_member_teardown(32768);
    assert!(
        small.visited >= 4096 / 64 && large.visited >= 32768 / 64,
        "the release checkpoints every 64 slots: {small:?} {large:?}"
    );
    for turn in [&small, &large] {
        assert_eq!(turn.answered, turn.visited, "{turn:?}");
        assert_eq!(
            turn.owners.first(),
            Some(&ReadinessOwnerKind::Ingest),
            "{turn:?}"
        );
    }
}

fn assert_only_ingest_owners(case: &str, owners: &[ReadinessOwnerKind]) {
    assert!(
        !owners.is_empty()
            && owners
                .iter()
                .all(|kind| *kind == ReadinessOwnerKind::Ingest),
        "{case}: no policy transition is pending, so every owner is the ingest one: {owners:?}"
    );
}

/// Retiring a departing session's Adj-RIB-Out and regrouping a peer for a
/// family that became sendable involve no policy transition, so their
/// readiness waits belong to the actor loop's seam, not the replacement
/// fence's.
#[test]
fn outbound_teardown_and_family_unlock_take_the_ingest_owner() {
    assert_only_ingest_owners("teardown", &evpn_member_teardown(64).owners);

    let (mut manager, member, _gid, _output) = super::evpn_group_storage::fixture();
    manager.replacement_readiness_receipts.clear();
    manager.handle_update(RibUpdate::PeerFamilySendable {
        peer: member,
        session_id: 7,
        family: (Afi::Ipv6, Safi::Unicast),
        add_path_send_limit: None,
    });
    assert!(
        manager.peer_sendable_families[&member].contains(&(Afi::Ipv6, Safi::Unicast)),
        "the family was unlocked"
    );
    let owners: Vec<_> = manager
        .replacement_readiness_receipts
        .iter()
        .map(|receipt| receipt.kind)
        .collect();
    assert_only_ingest_owners("family unlock", &owners);
}
