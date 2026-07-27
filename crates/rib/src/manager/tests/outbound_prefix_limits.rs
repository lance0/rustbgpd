//! Outbound unicast prefix accounting (ADR-0113).
//!
//! Two layers: the pure per-family batch helper, and the export seam that
//! feeds it. Nothing outside these tests configures a limit, so the seam
//! tests also pin the unlimited path that every peer takes today.

use std::collections::HashSet;
use std::num::NonZeroU32;

use super::*;
use crate::manager::outbound_prefix_limits::{BatchAdmission, admit_batch};
use crate::update::{
    OutboundPrefixLimitConfig, OutboundPrefixLimitFamilyState, OutboundPrefixLimitPair,
    OutboundPrefixLimitViolation,
};

fn v4(octet: u8) -> Prefix {
    Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, octet), 32))
}

fn limit(n: u32) -> NonZeroU32 {
    NonZeroU32::new(n).expect("test limits are non-zero")
}

// --- pure batch admission ---

/// Load-bearing break: admitting unconditionally lets the third prefix
/// through; counting the whole batch against the cap blocks the first two.
#[test]
fn net_new_prefixes_past_the_cap_are_blocked_and_the_rest_pass() {
    let announced = [v4(1), v4(2), v4(3)];
    let verdict = admit_batch(limit(2), 0, &HashSet::new(), &announced, |_| false);
    assert_eq!(
        verdict,
        BatchAdmission {
            admitted: HashSet::from([v4(1), v4(2)]),
            blocked: HashSet::from([v4(3)]),
        }
    );
}

/// Load-bearing break: gating announcements for already-admitted prefixes
/// (an attribute change or an extra path identity) blocks them at the cap.
#[test]
fn announcements_for_admitted_prefixes_pass_at_the_cap() {
    let admitted = HashSet::from([v4(1), v4(2)]);
    let announced = [v4(1), v4(2)];
    let verdict = admit_batch(limit(2), 2, &HashSet::new(), &announced, |prefix| {
        admitted.contains(prefix)
    });
    assert_eq!(verdict, BatchAdmission::default());
}

/// Load-bearing break: evaluating announcements before withdrawals blocks
/// the new prefix even though the batch is net-neutral at the cap.
#[test]
fn a_withdrawal_frees_its_slot_before_announcements_are_considered() {
    let admitted = HashSet::from([v4(1), v4(2)]);
    let freed = HashSet::from([v4(1)]);
    let announced = [v4(3)];
    let verdict = admit_batch(limit(2), 2, &freed, &announced, |prefix| {
        admitted.contains(prefix)
    });
    assert_eq!(
        verdict,
        BatchAdmission {
            admitted: HashSet::from([v4(3)]),
            blocked: HashSet::new(),
        }
    );
}

/// Load-bearing break: counting route identities instead of prefixes spends
/// one slot per path and blocks the second and third identities.
#[test]
fn every_path_identity_for_one_prefix_shares_a_single_slot() {
    // Three RFC 7911 identities for one NLRI, none advertised yet.
    let announced = [v4(1), v4(1), v4(1)];
    let verdict = admit_batch(limit(1), 0, &HashSet::new(), &announced, |_| false);
    assert_eq!(
        verdict,
        BatchAdmission {
            admitted: HashSet::from([v4(1)]),
            blocked: HashSet::new(),
        }
    );
}

/// A prefix whose last path leaves and which the same batch re-announces is
/// net-new again: it takes the slot its own withdrawal freed.
#[test]
fn a_freed_prefix_reannounced_in_the_same_batch_retakes_its_slot() {
    let admitted = HashSet::from([v4(1)]);
    let freed = HashSet::from([v4(1)]);
    let announced = [v4(1)];
    let verdict = admit_batch(limit(1), 1, &freed, &announced, |prefix| {
        admitted.contains(prefix)
    });
    assert_eq!(
        verdict,
        BatchAdmission {
            admitted: HashSet::from([v4(1)]),
            blocked: HashSet::new(),
        }
    );
}

// --- export seam ---

fn register_peer(manager: &mut RibManager, peer: IpAddr) -> mpsc::Receiver<OutboundRouteUpdate> {
    let (outbound_tx, mut outbound_rx) = mpsc::channel(64);
    manager.handle_update(RibUpdate::PeerUp {
        peer,
        session_id: 0,
        peer_asn: 65_000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: false,
        route_reflector_client: false,
        orr_vantage: None,
        per_client_best: false,
        interpret_rfc1997: true,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: vec![],
        negotiated_llgr_families: vec![],
    });
    let eor = outbound_rx.try_recv().expect("registration end-of-rib");
    assert_eq!(eor.end_of_rib, ipv4_sendable());
    outbound_rx
}

fn set_ipv4_limit(manager: &mut RibManager, peer: IpAddr, cap: u32) {
    manager
        .outbound_prefix_limits
        .entry(peer)
        .or_default()
        .family_mut(Afi::Ipv4)
        .expect("IPv4 unicast is a limited family")
        .limit = Some(limit(cap));
}

fn announce(manager: &mut RibManager, source: IpAddr, announced: Vec<Route>) {
    manager.handle_update(RibUpdate::RoutesReceived {
        peer: source,
        session_id: 0,
        announced,
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    });
    while manager.process_next_route_chunk() {}
}

fn withdraw(manager: &mut RibManager, source: IpAddr, withdrawn: Vec<(Prefix, u32)>) {
    manager.handle_update(RibUpdate::RoutesReceived {
        peer: source,
        session_id: 0,
        announced: vec![],
        withdrawn,
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    });
    while manager.process_next_route_chunk() {}
}

/// Prefixes the peer's envelopes leave advertised, i.e. announced and not
/// later withdrawn.
fn wire_prefixes(outbound_rx: &mut mpsc::Receiver<OutboundRouteUpdate>) -> HashSet<Prefix> {
    let mut advertised = HashSet::new();
    while let Ok(update) = outbound_rx.try_recv() {
        for route in update.announce.iter() {
            advertised.insert(route.prefix);
        }
        for (prefix, _) in &update.withdraw {
            advertised.remove(prefix);
        }
    }
    advertised
}

fn source_routes(source: Ipv4Addr, octets: &[u8]) -> Vec<Route> {
    octets
        .iter()
        .map(|octet| {
            crate::test_support::make_route(
                Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, *octet), 32),
                source,
            )
        })
        .collect()
}

/// Inertness: with no limit configured — the state of every peer today —
/// the export path advertises exactly what it advertised before this
/// accounting existed, and allocates no admission state.
#[test]
fn an_unlimited_peer_admits_every_prefix_and_allocates_no_admission_state() {
    let (_tx, rx) = mpsc::channel(1);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    manager.test_force_ungrouped = true;
    let peer = IpAddr::V4(Ipv4Addr::new(10, 113, 0, 1));
    let mut outbound_rx = register_peer(&mut manager, peer);

    let source = Ipv4Addr::new(192, 0, 2, 113);
    announce(
        &mut manager,
        IpAddr::V4(source),
        source_routes(source, &[1, 2, 3]),
    );

    assert_eq!(
        wire_prefixes(&mut outbound_rx),
        HashSet::from([v4(1), v4(2), v4(3)])
    );
    assert_eq!(
        manager.adj_ribs_out.get(&peer).map_or(0, AdjRibOut::len),
        3,
        "the unlimited path must commit every advertised route"
    );
    assert!(
        manager.outbound_prefix_limits.is_empty(),
        "an unlimited peer must not allocate per-peer admission state"
    );
}

/// Load-bearing break: dropping the enforcement call from the commit seam
/// puts all three prefixes on the wire and in Adj-RIB-Out.
#[test]
fn an_ungrouped_peer_at_its_cap_blocks_the_excess_prefix() {
    let (_tx, rx) = mpsc::channel(1);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    manager.test_force_ungrouped = true;
    let peer = IpAddr::V4(Ipv4Addr::new(10, 113, 0, 1));
    let mut outbound_rx = register_peer(&mut manager, peer);
    set_ipv4_limit(&mut manager, peer, 2);

    let source = Ipv4Addr::new(192, 0, 2, 113);
    announce(
        &mut manager,
        IpAddr::V4(source),
        source_routes(source, &[1, 2, 3]),
    );

    let advertised = wire_prefixes(&mut outbound_rx);
    assert_eq!(advertised.len(), 2, "only the cap may reach the wire");
    let committed: HashSet<Prefix> = manager
        .adj_ribs_out
        .get(&peer)
        .expect("a limited ungrouped peer keeps its private Adj-RIB-Out")
        .iter()
        .map(|route| route.prefix)
        .collect();
    assert_eq!(
        committed, advertised,
        "a blocked prefix must never enter Adj-RIB-Out"
    );
    assert!(
        manager
            .outbound_prefix_limits
            .get(&peer)
            .and_then(|limits| limits.family(Afi::Ipv4))
            .is_some_and(|family| family.blocking),
        "blocking a net-new prefix opens the family's episode"
    );
}

/// A withdrawal at the cap frees its slot, and the freed capacity is
/// re-offered to intent the limiter previously blocked — without an
/// inventory of blocked prefixes.
#[test]
fn freed_capacity_readmits_previously_blocked_intent() {
    let (_tx, rx) = mpsc::channel(1);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    manager.test_force_ungrouped = true;
    let peer = IpAddr::V4(Ipv4Addr::new(10, 113, 0, 1));
    let mut outbound_rx = register_peer(&mut manager, peer);
    set_ipv4_limit(&mut manager, peer, 2);

    let source = Ipv4Addr::new(192, 0, 2, 113);
    announce(
        &mut manager,
        IpAddr::V4(source),
        source_routes(source, &[1, 2, 3]),
    );
    let advertised = wire_prefixes(&mut outbound_rx);
    assert_eq!(advertised.len(), 2);
    let blocked = *[v4(1), v4(2), v4(3)]
        .iter()
        .find(|prefix| !advertised.contains(prefix))
        .expect("one prefix is over the cap");
    let admitted = *advertised.iter().next().expect("the cap admitted two");

    // Withdrawing an admitted prefix frees exactly one slot and schedules a
    // family-scoped resync, which re-derives the blocked prefix from current
    // Loc-RIB intent.
    //
    // Load-bearing break: scheduling a peer-wide resync instead re-derives
    // every family this peer carries, not the one that regained capacity.
    withdraw(&mut manager, IpAddr::V4(source), vec![(admitted, 0)]);
    assert_eq!(
        manager.outbound_limit_recovery_for(peer),
        vec![Afi::Ipv4],
        "freed capacity during an episode must schedule one family-scoped resync"
    );
    while manager.resync_dirty_peers_bounded() {}

    let recovered = wire_prefixes(&mut outbound_rx);
    assert!(
        recovered.contains(&blocked),
        "the freed slot must go to previously blocked intent"
    );
    assert_eq!(
        manager
            .adj_ribs_out
            .get(&peer)
            .map_or(0, |rib| rib.unicast_prefix_count(Afi::Ipv4)),
        2,
        "recovery must not exceed the cap"
    );
}

/// One limited member must not fragment its update group: the sibling keeps
/// the shared payload and both stay in the same group.
///
/// Load-bearing break: putting the limit in `GroupKey`, or filtering the
/// shared payload instead of the member's final vector, changes the
/// sibling's advertised set or splits the group.
#[test]
fn a_limited_group_member_blocks_alone() {
    let (_tx, rx) = mpsc::channel(1);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let limited = IpAddr::V4(Ipv4Addr::new(10, 113, 0, 1));
    let sibling = IpAddr::V4(Ipv4Addr::new(10, 113, 0, 2));
    let mut limited_rx = register_peer(&mut manager, limited);
    let mut sibling_rx = register_peer(&mut manager, sibling);
    set_ipv4_limit(&mut manager, limited, 2);

    let source = Ipv4Addr::new(192, 0, 2, 113);
    announce(
        &mut manager,
        IpAddr::V4(source),
        source_routes(source, &[1, 2, 3]),
    );

    let group = manager.grouped_member_of(limited);
    assert!(
        group.is_some(),
        "the fixture must exercise the grouped path"
    );
    assert_eq!(
        group,
        manager.grouped_member_of(sibling),
        "a limit must not split the update group"
    );
    assert_eq!(
        wire_prefixes(&mut sibling_rx),
        HashSet::from([v4(1), v4(2), v4(3)]),
        "an unlimited sibling keeps the full shared payload"
    );
    let advertised = wire_prefixes(&mut limited_rx);
    assert_eq!(
        advertised.len(),
        2,
        "only the cap reaches the limited member"
    );
    assert_eq!(
        manager
            .outbound_prefix_limits
            .get(&limited)
            .and_then(|limits| limits.family(Afi::Ipv4))
            .map(|family| family.grouped_admitted.clone()),
        Some(advertised),
        "the member's bounded admitted set is its advertised projection"
    );
}

/// Admission is per session generation: teardown reaps it on the same seam
/// as the rest of the peer's outbound state.
#[test]
fn peer_teardown_clears_admission_state() {
    let (_tx, rx) = mpsc::channel(1);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    manager.test_force_ungrouped = true;
    let peer = IpAddr::V4(Ipv4Addr::new(10, 113, 0, 1));
    let mut outbound_rx = register_peer(&mut manager, peer);
    set_ipv4_limit(&mut manager, peer, 2);

    let source = Ipv4Addr::new(192, 0, 2, 113);
    announce(
        &mut manager,
        IpAddr::V4(source),
        source_routes(source, &[1, 2, 3]),
    );
    drop(wire_prefixes(&mut outbound_rx));
    assert!(manager.outbound_prefix_limits.contains_key(&peer));

    manager.handle_update(RibUpdate::PeerDown {
        peer,
        session_id: 0,
    });
    assert!(
        !manager.outbound_prefix_limits.contains_key(&peer),
        "a reconnecting generation must start with empty admission state"
    );
}

// --- configuration, transaction, and observability ---

fn limit_config(
    neighbors: &[(IpAddr, Option<u32>, Option<u32>)],
    groups: &[(&str, Option<u32>, Option<u32>)],
) -> OutboundPrefixLimitConfig {
    let pair = |ipv4: Option<u32>, ipv6: Option<u32>| OutboundPrefixLimitPair {
        ipv4: ipv4.map(limit),
        ipv6: ipv6.map(limit),
    };
    OutboundPrefixLimitConfig {
        neighbors: neighbors
            .iter()
            .map(|(peer, ipv4, ipv6)| (*peer, pair(*ipv4, *ipv6)))
            .collect(),
        groups: groups
            .iter()
            .map(|(name, ipv4, ipv6)| ((*name).to_string(), pair(*ipv4, *ipv6)))
            .collect(),
    }
}

fn prepare(
    manager: &mut RibManager,
    txn: u64,
    config: OutboundPrefixLimitConfig,
) -> Result<(), Vec<OutboundPrefixLimitViolation>> {
    let (reply, mut rx) = tokio::sync::oneshot::channel();
    manager.handle_update(RibUpdate::PrepareOutboundPrefixLimits { txn, config, reply });
    rx.try_recv().expect("prepare replies synchronously")
}

fn apply(manager: &mut RibManager, txn: u64, activate: bool) -> Result<(), String> {
    let (reply, mut rx) = tokio::sync::oneshot::channel();
    manager.handle_update(RibUpdate::ApplyOutboundPrefixLimits {
        txn,
        activate,
        reply,
    });
    rx.try_recv().expect("apply replies synchronously")
}

fn outbound_limit_actor_samples(metrics: &BgpMetrics) -> std::collections::BTreeMap<String, u64> {
    metrics
        .registry()
        .gather()
        .into_iter()
        .find(|family| family.name() == "bgp_rib_outbound_prefix_limit_actor_duration_seconds")
        .expect("outbound prefix-limit actor histogram is registered")
        .metric
        .iter()
        .map(|metric| {
            let operation = metric
                .get_label()
                .iter()
                .find(|label| label.name() == "operation")
                .expect("operation label exists")
                .value()
                .to_owned();
            (operation, metric.get_histogram().sample_count())
        })
        .collect()
}

fn install(manager: &mut RibManager, txn: u64, config: OutboundPrefixLimitConfig) {
    prepare(manager, txn, config).expect("preflight passes");
    apply(manager, txn, true).expect("activation passes");
}

fn ipv4_row(manager: &RibManager, peer: IpAddr) -> OutboundPrefixLimitFamilyState {
    manager
        .outbound_prefix_limit_rows(peer)
        .into_iter()
        .find(|row| row.family == "ipv4_unicast")
        .expect("a registered peer reports both unicast families")
}

/// Load-bearing break: removing either active-attempt observation leaves the
/// `apply` count short; observing discard, missing, superseded, or idempotent
/// branches makes one of the exact zero/two assertions red.
#[test]
fn only_an_active_outbound_limit_apply_attempt_records_an_apply_batch() {
    let metrics = BgpMetrics::new();
    let (_tx, rx) = mpsc::channel(1);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, metrics.clone());
    manager.test_force_ungrouped = true;
    let peer = IpAddr::V4(Ipv4Addr::new(10, 113, 0, 1));
    let _outbound_rx = register_peer(&mut manager, peer);

    assert_eq!(
        outbound_limit_actor_samples(&metrics),
        std::collections::BTreeMap::from([("apply".to_string(), 0), ("recovery".to_string(), 0),]),
        "peer registration is not a prefix-limit apply or recovery batch"
    );
    assert!(apply(&mut manager, 10, false).is_ok());
    assert!(apply(&mut manager, 10, true).is_err());
    prepare(
        &mut manager,
        11,
        limit_config(&[(peer, Some(4), None)], &[]),
    )
    .expect("first preflight passes");
    prepare(
        &mut manager,
        12,
        limit_config(&[(peer, Some(3), None)], &[]),
    )
    .expect("replacement preflight passes");
    assert!(
        apply(&mut manager, 11, true).is_err(),
        "the first transaction was superseded"
    );
    assert_eq!(
        outbound_limit_actor_samples(&metrics)["apply"],
        0,
        "inactive paths must not publish actor work"
    );

    prepare(
        &mut manager,
        13,
        limit_config(&[(peer, Some(1), None)], &[]),
    )
    .expect("the empty peer passes preflight");
    let source = Ipv4Addr::new(192, 0, 2, 113);
    announce(
        &mut manager,
        IpAddr::V4(source),
        source_routes(source, &[1, 2]),
    );
    assert!(
        apply(&mut manager, 13, true).is_err(),
        "the active apply recheck catches post-prepare growth"
    );
    assert_eq!(
        outbound_limit_actor_samples(&metrics)["apply"],
        1,
        "the live precondition scan is real actor work even when it rejects"
    );

    prepare(
        &mut manager,
        12,
        limit_config(&[(peer, Some(3), None)], &[]),
    )
    .expect("a fresh preflight passes after the superseded request");
    apply(&mut manager, 12, true).expect("the prepared transaction activates");
    assert_eq!(outbound_limit_actor_samples(&metrics)["apply"], 2);
    assert_eq!(outbound_limit_actor_samples(&metrics)["recovery"], 0);

    apply(&mut manager, 12, true).expect("an activation retry is idempotent");
    assert_eq!(
        outbound_limit_actor_samples(&metrics)["apply"],
        2,
        "an idempotent retry must not publish a second batch"
    );
}

/// Load-bearing break: removing the production recovery observation leaves
/// `recovery` at zero; observing an empty drain makes either zero/one
/// assertion red.
#[test]
fn only_a_real_withheld_prefix_recovery_records_a_recovery_batch() {
    let metrics = BgpMetrics::new();
    let (_tx, rx) = mpsc::channel(1);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, metrics.clone());
    manager.test_force_ungrouped = true;
    let peer = IpAddr::V4(Ipv4Addr::new(10, 113, 0, 1));
    let mut outbound_rx = register_peer(&mut manager, peer);
    install(&mut manager, 1, limit_config(&[(peer, Some(2), None)], &[]));
    let source = Ipv4Addr::new(192, 0, 2, 113);
    announce(
        &mut manager,
        IpAddr::V4(source),
        source_routes(source, &[1, 2, 3]),
    );
    assert_eq!(wire_prefixes(&mut outbound_rx).len(), 2);
    assert!(!manager.drain_outbound_limit_recovery());
    assert_eq!(outbound_limit_actor_samples(&metrics)["recovery"], 0);

    install(&mut manager, 2, limit_config(&[(peer, Some(3), None)], &[]));
    assert_eq!(manager.outbound_limit_recovery_for(peer), vec![Afi::Ipv4]);
    assert!(manager.drain_outbound_limit_recovery());
    assert_eq!(wire_prefixes(&mut outbound_rx).len(), 3);
    assert_eq!(outbound_limit_actor_samples(&metrics)["apply"], 2);
    assert_eq!(outbound_limit_actor_samples(&metrics)["recovery"], 1);

    assert!(!manager.drain_outbound_limit_recovery());
    assert_eq!(
        outbound_limit_actor_samples(&metrics)["recovery"],
        1,
        "an empty queue must not publish another batch"
    );
}

/// A dynamic child has no neighbor entry: it inherits its configured group,
/// and a neighbor entry overrides that group for its own peer.
///
/// Load-bearing break: resolving only neighbor entries leaves every accepted
/// dynamic child unlimited no matter what its group configures.
#[test]
fn a_registration_inherits_its_peer_group_unless_the_neighbor_overrides_it() {
    let (_tx, rx) = mpsc::channel(1);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    manager.test_force_ungrouped = true;
    let inheriting = IpAddr::V4(Ipv4Addr::new(10, 113, 0, 1));
    let overriding = IpAddr::V4(Ipv4Addr::new(10, 113, 0, 2));
    for peer in [inheriting, overriding] {
        manager.handle_update(RibUpdate::SetPeerPolicyContext {
            peer,
            session_id: 0,
            peer_group: Some("clients".to_string()),
        });
    }
    install(
        &mut manager,
        1,
        limit_config(
            &[(overriding, Some(9), None)],
            &[("clients", Some(2), None)],
        ),
    );

    // Registration resolves before the initial feed, so the cap applies to it.
    let mut inheriting_rx = register_peer(&mut manager, inheriting);
    let _overriding_rx = register_peer(&mut manager, overriding);
    let source = Ipv4Addr::new(192, 0, 2, 113);
    announce(
        &mut manager,
        IpAddr::V4(source),
        source_routes(source, &[1, 2, 3]),
    );

    assert_eq!(wire_prefixes(&mut inheriting_rx).len(), 2);
    assert_eq!(ipv4_row(&manager, inheriting).limit, Some(2));
    assert_eq!(ipv4_row(&manager, overriding).limit, Some(9));
}

/// Load-bearing break: mutating any peer before every affected peer passes
/// preflight lets a group-wide lowering land on the members that fit and
/// leaves the running configuration disagreeing with admission state.
#[test]
fn a_lowering_below_current_usage_rejects_the_whole_edit() {
    let (_tx, rx) = mpsc::channel(1);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    manager.test_force_ungrouped = true;
    let over = IpAddr::V4(Ipv4Addr::new(10, 113, 0, 1));
    let under = IpAddr::V4(Ipv4Addr::new(10, 113, 0, 2));
    let mut over_rx = register_peer(&mut manager, over);
    let mut under_rx = register_peer(&mut manager, under);
    let source = Ipv4Addr::new(192, 0, 2, 113);
    announce(
        &mut manager,
        IpAddr::V4(source),
        source_routes(source, &[1, 2, 3]),
    );
    drop(wire_prefixes(&mut over_rx));
    drop(wire_prefixes(&mut under_rx));
    // Only the direct edit is over usage; the inherited one is not.
    install(
        &mut manager,
        1,
        limit_config(&[], &[("clients", Some(5), None)]),
    );

    let violations = prepare(
        &mut manager,
        2,
        limit_config(&[(over, Some(1), None)], &[("clients", Some(5), None)]),
    )
    .expect_err("a maximum below current usage must be refused");
    assert_eq!(violations.len(), 1);
    assert_eq!(violations[0].peer, over);
    assert_eq!(violations[0].usage, 3);
    assert_eq!(violations[0].requested, 1);

    assert!(
        manager.outbound_prefix_limits.is_empty(),
        "a rejected edit must not install admission state on any peer"
    );
    assert_eq!(
        manager.adj_ribs_out.get(&over).map(AdjRibOut::len),
        Some(3),
        "a rejected lowering is not an implicit pruning policy"
    );
    assert!(apply(&mut manager, 2, true).is_err());
}

/// A raise re-derives only the affected family; activation is idempotent by
/// transaction identity, and a superseded identity is refused.
///
/// Load-bearing break: omitting recovery leaves the freed capacity unused
/// because blocked intent is deliberately never inventoried.
#[test]
fn a_raise_schedules_one_family_scoped_recovery_and_activates_once() {
    let (_tx, rx) = mpsc::channel(1);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    manager.test_force_ungrouped = true;
    let peer = IpAddr::V4(Ipv4Addr::new(10, 113, 0, 1));
    let mut outbound_rx = register_peer(&mut manager, peer);
    install(
        &mut manager,
        1,
        limit_config(&[(peer, Some(2), Some(4))], &[]),
    );

    let source = Ipv4Addr::new(192, 0, 2, 113);
    announce(
        &mut manager,
        IpAddr::V4(source),
        source_routes(source, &[1, 2, 3]),
    );
    assert_eq!(wire_prefixes(&mut outbound_rx).len(), 2);
    assert!(ipv4_row(&manager, peer).blocking);

    install(
        &mut manager,
        2,
        limit_config(&[(peer, Some(3), Some(4))], &[]),
    );
    assert_eq!(
        manager.outbound_limit_recovery_for(peer),
        vec![Afi::Ipv4],
        "a raise re-derives only the family it raised"
    );
    while manager.resync_dirty_peers_bounded() {}
    assert_eq!(wire_prefixes(&mut outbound_rx).len(), 3);
    let row = ipv4_row(&manager, peer);
    assert_eq!((row.usage, row.limit, row.headroom), (3, Some(3), Some(0)));
    assert!(
        !row.blocking,
        "a resync that blocks nothing ends the episode"
    );

    // Idempotent by identity: a retry or boot repair applies nothing twice,
    // and the superseded identity 1 can no longer be activated.
    assert!(apply(&mut manager, 2, true).is_ok());
    assert!(apply(&mut manager, 1, true).is_err());
}

/// Removing a maximum drops the numeric API surface rather than reporting a
/// stale finite value, and releases the bounded member set.
#[test]
fn removing_a_maximum_reports_unlimited_without_inventing_a_number() {
    let (_tx, rx) = mpsc::channel(1);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    manager.test_force_ungrouped = true;
    let peer = IpAddr::V4(Ipv4Addr::new(10, 113, 0, 1));
    let mut outbound_rx = register_peer(&mut manager, peer);
    install(&mut manager, 1, limit_config(&[(peer, Some(2), None)], &[]));
    let source = Ipv4Addr::new(192, 0, 2, 113);
    announce(
        &mut manager,
        IpAddr::V4(source),
        source_routes(source, &[1, 2, 3]),
    );
    assert_eq!(wire_prefixes(&mut outbound_rx).len(), 2);

    install(&mut manager, 2, limit_config(&[], &[]));
    while manager.resync_dirty_peers_bounded() {}
    let row = ipv4_row(&manager, peer);
    assert_eq!(row.limit, None, "an unlimited family reports no maximum");
    assert_eq!(row.headroom, None);
    assert_eq!(row.usage, 3);
    assert!(!row.blocking);
    assert!(
        manager.outbound_prefix_limits.is_empty(),
        "a peer with no remaining maximum returns to the unlimited state shape"
    );
}

/// One peer/family capacity gauge, or `None` when the series is absent.
fn capacity_gauge(metrics: &BgpMetrics, name: &str, peer: IpAddr, family: &str) -> Option<f64> {
    let peer = peer.to_string();
    let gathered = metrics.registry().gather();
    let gauge = gathered.iter().find(|group| group.name() == name)?;
    gauge
        .metric
        .iter()
        .find(|metric| {
            metric
                .get_label()
                .iter()
                .any(|label| label.name() == "peer" && label.value() == peer)
                && metric
                    .get_label()
                    .iter()
                    .any(|label| label.name() == "family" && label.value() == family)
        })
        .map(|metric| metric.get_gauge().value())
}

/// A blocking family's gauges must agree with the admitted truth the API
/// reports, in the same snapshot.
///
/// Load-bearing break: publishing them at the enforcement seam — which runs
/// before the Adj-RIB-Out commit — exports a scrape that contradicts itself,
/// `usage 0` and `headroom 2` on a family that is withholding prefixes.
#[test]
fn a_blocking_family_publishes_the_committed_usage_not_the_pre_batch_one() {
    let metrics = BgpMetrics::new();
    let (_tx, rx) = mpsc::channel(1);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, metrics.clone());
    manager.test_force_ungrouped = true;
    let peer = IpAddr::V4(Ipv4Addr::new(10, 113, 0, 1));
    let mut outbound_rx = register_peer(&mut manager, peer);
    set_ipv4_limit(&mut manager, peer, 2);

    let source = Ipv4Addr::new(192, 0, 2, 113);
    announce(
        &mut manager,
        IpAddr::V4(source),
        source_routes(source, &[1, 2, 3]),
    );
    assert_eq!(wire_prefixes(&mut outbound_rx).len(), 2);

    let row = ipv4_row(&manager, peer);
    assert_eq!((row.usage, row.headroom, row.blocking), (2, Some(0), true));
    for (name, want) in [
        ("bgp_outbound_prefix_usage", 2.0),
        ("bgp_outbound_prefix_headroom", 0.0),
        ("bgp_outbound_prefix_blocking", 1.0),
    ] {
        assert_eq!(
            capacity_gauge(&metrics, name, peer, "ipv4_unicast"),
            Some(want),
            "{name} must report the same admitted truth as the neighbor API"
        );
    }
}

/// A limited grouped member advertises its admitted projection, and its
/// unlimited sibling keeps reporting the whole group table.
///
/// Load-bearing break: leaving the grouped advertised projection as raw
/// group intent makes `rbgp rib advertised` list prefixes the limiter
/// withheld, contradicting the peer's own usage row in the same snapshot.
#[test]
fn a_limited_grouped_member_reports_only_what_it_advertised() {
    let metrics = BgpMetrics::new();
    let (_tx, rx) = mpsc::channel(1);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, metrics.clone());
    let member = IpAddr::V4(Ipv4Addr::new(10, 113, 0, 1));
    let sibling = IpAddr::V4(Ipv4Addr::new(10, 113, 0, 2));
    let mut member_rx = register_peer(&mut manager, member);
    let mut sibling_rx = register_peer(&mut manager, sibling);
    install(
        &mut manager,
        1,
        limit_config(&[(member, Some(2), None)], &[]),
    );

    let source = Ipv4Addr::new(192, 0, 2, 113);
    announce(
        &mut manager,
        IpAddr::V4(source),
        source_routes(source, &[1, 2, 3]),
    );
    let advertised = wire_prefixes(&mut member_rx);
    assert_eq!(advertised.len(), 2);
    assert_eq!(wire_prefixes(&mut sibling_rx).len(), 3);
    assert!(manager.grouped_member_of(member).is_some());

    let projected: HashSet<Prefix> = manager
        .grouped_advertised_routes(member)
        .expect("a grouped member synthesizes its advertised view")
        .into_iter()
        .map(|route| route.prefix)
        .collect();
    assert_eq!(
        projected, advertised,
        "the advertised projection must not list withheld prefixes"
    );
    assert_eq!(manager.grouped_advertised_count(member), Some(2));
    assert_eq!(
        manager.grouped_advertised_count(sibling),
        Some(3),
        "one member's cap must not shrink an unlimited sibling's projection"
    );
    assert_eq!(
        capacity_gauge(
            &metrics,
            "bgp_outbound_prefix_usage",
            sibling,
            "ipv4_unicast"
        ),
        Some(3.0),
        "an unlimited family still publishes live usage"
    );

    // Raising the member's maximum recovers the withheld prefix over the
    // shared fanout without touching the sibling. The integration receipt
    // cannot observe this path — a peer-group edit reshapes its static
    // members before the recovery can be seen — so it is pinned here.
    let withheld = *[v4(1), v4(2), v4(3)]
        .iter()
        .find(|prefix| !advertised.contains(prefix))
        .expect("one prefix is over the cap");
    install(
        &mut manager,
        2,
        limit_config(&[(member, Some(3), None)], &[]),
    );
    while manager.resync_dirty_peers_bounded() {}
    let recovered = wire_prefixes(&mut member_rx);
    assert!(
        recovered.contains(&withheld),
        "a grouped member's raise must deliver the withheld prefix"
    );
    assert_eq!(manager.grouped_advertised_count(member), Some(3));
    assert_eq!(
        wire_prefixes(&mut sibling_rx),
        HashSet::new(),
        "the recovery resync must not churn the shared group's other members"
    );
}

/// Install a candidate through the running actor's own message channel,
/// the way the reload and transaction paths do.
async fn install_over_channel(
    tx: &mpsc::Sender<RibUpdate>,
    txn: u64,
    config: OutboundPrefixLimitConfig,
) {
    let (reply, prepared) = tokio::sync::oneshot::channel();
    tx.send(RibUpdate::PrepareOutboundPrefixLimits { txn, config, reply })
        .await
        .expect("the manager is running");
    prepared
        .await
        .expect("prepare replies")
        .expect("preflight passes");
    let (reply, applied) = tokio::sync::oneshot::channel();
    tx.send(RibUpdate::ApplyOutboundPrefixLimits {
        txn,
        activate: true,
        reply,
    })
    .await
    .expect("the manager is running");
    applied
        .await
        .expect("apply replies")
        .expect("activation passes");
}

/// Accumulate the peer's advertised prefixes until `want` of them are on the
/// wire.
async fn wire_prefixes_until(
    outbound_rx: &mut mpsc::Receiver<OutboundRouteUpdate>,
    want: usize,
) -> HashSet<Prefix> {
    let mut advertised = HashSet::new();
    while advertised.len() < want {
        let update = outbound_rx.recv().await.expect("the session stays up");
        for route in update.announce.iter() {
            advertised.insert(route.prefix);
        }
        for (prefix, _) in &update.withdraw {
            advertised.remove(prefix);
        }
    }
    advertised
}

/// A raise must put the withheld prefixes on the wire under the manager's
/// own event loop, with nothing else happening on the daemon. Every other
/// test here drains the recovery by calling `resync_dirty_peers_bounded`
/// itself, which is precisely the drive a real quiescent daemon does not
/// supply.
///
/// Load-bearing break: scheduling the recovery without arming its own drive
/// parks the intent forever, because the resync timer that drains it is
/// armed only by unrelated dirty-peer state — the peer stays at the old cap
/// while the gauges and logs report the new one.
#[tokio::test]
async fn a_raise_delivers_the_withheld_prefixes_on_a_quiescent_daemon() {
    tokio::time::pause();
    let (tx, rx) = mpsc::channel(64);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    manager.test_force_ungrouped = true;
    let handle = tokio::spawn(manager.run());

    let peer = IpAddr::V4(Ipv4Addr::new(10, 113, 0, 1));
    install_over_channel(&tx, 1, limit_config(&[(peer, Some(2), None)], &[])).await;

    let (outbound_tx, mut outbound_rx) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        peer,
        session_id: 0,
        peer_asn: 65_000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: false,
        route_reflector_client: false,
        orr_vantage: None,
        per_client_best: false,
        interpret_rfc1997: true,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: vec![],
        negotiated_llgr_families: vec![],
    })
    .await
    .expect("the manager is running");

    let source = Ipv4Addr::new(192, 0, 2, 113);
    tx.send(RibUpdate::RoutesReceived {
        peer: IpAddr::V4(source),
        session_id: 0,
        announced: source_routes(source, &[1, 2, 3]),
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .expect("the manager is running");

    let admitted = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        wire_prefixes_until(&mut outbound_rx, 2),
    )
    .await
    .expect("the cap admits two prefixes");
    let withheld = *[v4(1), v4(2), v4(3)]
        .iter()
        .find(|prefix| !admitted.contains(prefix))
        .expect("one prefix is over the cap");

    install_over_channel(&tx, 2, limit_config(&[(peer, Some(3), None)], &[])).await;

    let recovered = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        wire_prefixes_until(&mut outbound_rx, 3),
    )
    .await;
    assert!(
        recovered.is_ok_and(|advertised| advertised.contains(&withheld)),
        "a raise must deliver the withheld prefix without any unrelated peer \
         happening to be dirty"
    );

    drop(tx);
    handle.await.expect("the manager shuts down cleanly");
}

/// A formerly unlimited grouped member materializes its advertised
/// projection as the bounded admitted set, and a regroup carries that
/// ownership rather than resetting it.
///
/// Load-bearing break: resetting admission during either handoff loses the
/// member's advertised prefixes and re-offers their slots as fresh capacity.
#[test]
fn a_grouped_member_materializes_and_carries_its_admitted_set() {
    let (_tx, rx) = mpsc::channel(1);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let member = IpAddr::V4(Ipv4Addr::new(10, 113, 0, 1));
    let sibling = IpAddr::V4(Ipv4Addr::new(10, 113, 0, 2));
    let mut member_rx = register_peer(&mut manager, member);
    let _sibling_rx = register_peer(&mut manager, sibling);
    let source = Ipv4Addr::new(192, 0, 2, 113);
    announce(
        &mut manager,
        IpAddr::V4(source),
        source_routes(source, &[1, 2, 3]),
    );
    let advertised = wire_prefixes(&mut member_rx);
    assert_eq!(advertised.len(), 3);
    assert!(manager.grouped_member_of(member).is_some());

    // Preflight walks the unlimited member's projection; activation turns it
    // into the bounded set.
    install(
        &mut manager,
        1,
        limit_config(&[(member, Some(3), None)], &[]),
    );
    let admitted = manager
        .outbound_prefix_limits
        .get(&member)
        .and_then(|limits| limits.family(Afi::Ipv4))
        .map(|family| family.grouped_admitted.clone());
    assert_eq!(admitted, Some(advertised.clone()));
    assert_eq!(ipv4_row(&manager, member).usage, 3);

    // Leaving the group hands ownership back to the private prefix index; the
    // reported usage is unchanged across the handoff.
    manager.test_force_ungrouped = true;
    manager.recompute_update_group(member);
    while manager.resync_dirty_peers_bounded() {}
    assert!(manager.grouped_member_of(member).is_none());
    assert_eq!(
        ipv4_row(&manager, member).usage,
        3,
        "a regroup neither forgets an advertisement nor frees capacity"
    );
    assert!(
        manager
            .outbound_prefix_limits
            .get(&member)
            .and_then(|limits| limits.family(Afi::Ipv4))
            .is_some_and(|family| family.grouped_admitted.is_empty()),
        "the private table is authoritative again, so the member set is released"
    );
}
