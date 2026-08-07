//! RFC 7947 §2.3.2 per-client best-path (route-server path-hiding
//! mitigation): the fourth distribution mode stages the first
//! export-policy-permitted candidate at `path_id 0` instead of the
//! Loc-RIB best. These tests pin the §2.3 scenario itself, the
//! churn/stability contract (the `OpenBGPd` `rde evaluate all` bug
//! class: spurious 2nd-best withdrawals / re-advertisements), the
//! single-best presentation shape, and the refresh/GShut replays.

use rustbgpd_policy::{
    CommunityMatch, Policy, PolicyAction, PolicyChain, PolicyStatement, RouteModifications,
};

use super::*;

/// Community attached to the Loc-RIB best so a client chain can deny it:
/// 65000:99.
const DENIED_COMMUNITY: u32 = 0xFDE8_0063;

/// Export chain denying routes tagged `65000:99`, permitting the rest.
fn deny_tagged_chain() -> PolicyChain {
    PolicyChain::new(vec![Policy {
        entries: vec![PolicyStatement {
            prefix: None,
            ge: None,
            le: None,
            action: PolicyAction::Deny,
            match_community: vec![CommunityMatch::Standard {
                value: DENIED_COMMUNITY,
            }],
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
        }],
        default_action: PolicyAction::Permit,
    }])
}

/// An eBGP route with an AS path and optional standard communities.
fn ebgp_route(prefix: Ipv4Prefix, peer: Ipv4Addr, asns: Vec<u32>, communities: Vec<u32>) -> Route {
    let mut attributes = vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath {
            segments: vec![AsPathSegment::AsSequence(asns)],
        }),
    ];
    if !communities.is_empty() {
        attributes.push(PathAttribute::Communities(communities));
    }
    Route {
        prefix: Prefix::V4(prefix),
        next_hop: IpAddr::V4(peer),
        link_local_next_hop: None,
        next_hop_scope: None,
        peer: IpAddr::V4(peer),
        attributes: Arc::new(attributes),
        received_at: Instant::now(),
        origin_type: crate::route::RouteOrigin::Ebgp,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        is_stale: false,
        is_llgr_stale: false,
        path_id: 0,
        validation_state: rustbgpd_wire::RpkiValidation::NotFound,
        aspa_state: rustbgpd_wire::AspaValidation::Unknown,
        aspa_context: rustbgpd_wire::AspaValidationContext::default(),
    }
}

/// Bring up an eBGP client peer (no Add-Path) with the given export
/// chain and per-client-best flag. Does NOT drain the initial dump.
async fn client_peer_up(
    tx: &mpsc::Sender<RibUpdate>,
    peer: IpAddr,
    export_policy: Option<PolicyChain>,
    per_client_best: bool,
) -> mpsc::Receiver<OutboundRouteUpdate> {
    let (out_tx, out_rx) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        session_id: 0,
        peer,
        peer_asn: 65100,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy,
        sendable_families: ipv4_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
        per_client_best,
        interpret_rfc1997: true,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: Vec::new(),
        negotiated_llgr_families: Vec::new(),
    })
    .await
    .unwrap();
    out_rx
}

/// Announce `routes` from `source` (each route's `peer` must equal
/// `source`).
async fn announce_from(tx: &mpsc::Sender<RibUpdate>, source: Ipv4Addr, routes: Vec<Route>) {
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: IpAddr::V4(source),
        announced: routes,
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();
}

/// Round-trip a query so all prior sends are fully processed.
async fn sync(tx: &mpsc::Sender<RibUpdate>) {
    let _ = query_best_routes(tx).await;
}

const PREFIX: (Ipv4Addr, u8) = (Ipv4Addr::new(203, 0, 113, 0), 24);

fn prefix() -> Ipv4Prefix {
    Ipv4Prefix::new(PREFIX.0, PREFIX.1)
}

const SOURCE_A: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1); // Loc-RIB best (tagged)
const SOURCE_B: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2); // runner-up
const SOURCE_E: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 5); // third-best

fn best_route() -> Route {
    ebgp_route(prefix(), SOURCE_A, vec![65001], vec![DENIED_COMMUNITY])
}

fn runner_up_route() -> Route {
    ebgp_route(prefix(), SOURCE_B, vec![65002, 65002], vec![])
}

fn third_route() -> Route {
    ebgp_route(prefix(), SOURCE_E, vec![65005, 65005, 65005], vec![])
}

/// The RFC 7947 §2.3 scenario. Two candidates; the Loc-RIB best is
/// denied by the client's export chain:
/// - without `per_client_best`, the client gets NOTHING (today's
///   documented path-hiding behavior — pinned);
/// - with `per_client_best`, the client receives the runner-up, staged
///   at `path_id 0` (Adj-RIB-Out presents the single-best shape).
#[tokio::test]
async fn best_denied_single_best_hides_per_client_best_sends_runner_up() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    announce_from(&tx, SOURCE_A, vec![best_route()]).await;
    announce_from(&tx, SOURCE_B, vec![runner_up_route()]).await;
    sync(&tx).await;
    // Best-path sanity: A's shorter AS path wins the Loc-RIB.
    let best = query_best_routes(&tx).await;
    assert_eq!(best.len(), 1);
    assert_eq!(best[0].peer, IpAddr::V4(SOURCE_A));

    // Single-best client: the denied best hides the prefix entirely.
    let hidden = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
    let mut hidden_rx = client_peer_up(&tx, hidden, Some(deny_tagged_chain()), false).await;
    drain_eor(&mut hidden_rx).await; // initial dump: EoR only, no routes

    // Per-client-best client: same chain, receives the runner-up.
    let mitigated = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 4));
    let mut mitigated_rx = client_peer_up(&tx, mitigated, Some(deny_tagged_chain()), true).await;
    let dump = mitigated_rx.recv().await.unwrap();
    assert_eq!(dump.announce.len(), 1, "exactly the filtered best");
    assert_eq!(dump.announce[0].peer, IpAddr::V4(SOURCE_B));
    assert_eq!(dump.announce[0].path_id, 0, "single-best shape");
    assert!(dump.withdraw.is_empty());
    drain_eor(&mut mitigated_rx).await;

    // Adj-RIB-Out / ListAdvertisedRoutes present the same shape.
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryAdvertisedRoutes {
        peer: mitigated,
        reply: reply_tx,
    })
    .await
    .unwrap();
    let advertised = reply_rx.await.unwrap();
    assert_eq!(advertised.len(), 1);
    assert_eq!(advertised[0].peer, IpAddr::V4(SOURCE_B));
    assert_eq!(advertised[0].path_id, 0);

    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryAdvertisedRoutes {
        peer: hidden,
        reply: reply_tx,
    })
    .await
    .unwrap();
    assert!(reply_rx.await.unwrap().is_empty(), "path hiding pinned");

    drop(tx);
    handle.await.unwrap();
}

/// A per-client-best target treats `NO_ADVERTISE` as candidate
/// ineligibility before policy. When the current winner becomes scoped,
/// the next permitted candidate replaces it at path-id 0 without a
/// withdraw/announce gap, even if policy would remove the community.
#[tokio::test]
async fn no_advertise_winner_is_replaced_by_per_client_runner_up_before_policy() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let initial_best = ebgp_route(prefix(), SOURCE_A, vec![65001], vec![]);
    announce_from(&tx, SOURCE_A, vec![initial_best]).await;
    announce_from(&tx, SOURCE_B, vec![runner_up_route()]).await;
    sync(&tx).await;

    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 40));
    let mut out_rx = client_peer_up(
        &tx,
        target,
        Some(super::unicast::no_advertise_removal_chain(false)),
        true,
    )
    .await;
    let initial = out_rx.recv().await.unwrap();
    assert_eq!(initial.announce.len(), 1);
    assert_eq!(initial.announce[0].peer, IpAddr::V4(SOURCE_A));
    assert_eq!(initial.announce[0].path_id, 0);
    drain_eor(&mut out_rx).await;

    announce_from(
        &tx,
        SOURCE_A,
        vec![ebgp_route(
            prefix(),
            SOURCE_A,
            vec![65001],
            vec![rustbgpd_wire::COMMUNITY_NO_ADVERTISE],
        )],
    )
    .await;
    sync(&tx).await;

    let replacement = out_rx
        .try_recv()
        .expect("runner-up replacement emitted after query synchronization");
    assert_eq!(replacement.announce.len(), 1);
    assert_eq!(replacement.announce[0].peer, IpAddr::V4(SOURCE_B));
    assert_eq!(replacement.announce[0].path_id, 0);
    assert!(
        replacement.withdraw.is_empty(),
        "path-id 0 replacement is an implicit withdraw"
    );
    assert!(out_rx.try_recv().is_err());

    let (reply, response) = oneshot::channel();
    tx.send(RibUpdate::QueryAdvertisedRoutes {
        peer: target,
        reply,
    })
    .await
    .unwrap();
    let advertised = response.await.unwrap();
    assert_eq!(advertised.len(), 1);
    assert_eq!(advertised[0].peer, IpAddr::V4(SOURCE_B));
    assert_eq!(advertised[0].path_id, 0);

    let (reply, response) = oneshot::channel();
    tx.send(RibUpdate::ReplacePeerExportPolicy {
        peer: target,
        export_policy: Some(super::unicast::no_advertise_addition_chain(false)),
        reply,
    })
    .await
    .unwrap();
    assert_eq!(response.await.unwrap(), Ok(()));
    sync(&tx).await;

    let update = out_rx
        .try_recv()
        .expect("policy-added NO_ADVERTISE withdraws the per-client winner");
    assert!(update.announce.is_empty());
    assert_eq!(update.withdraw, vec![(Prefix::V4(prefix()), 0)]);
    let (reply, response) = oneshot::channel();
    tx.send(RibUpdate::QueryAdvertisedRoutes {
        peer: target,
        reply,
    })
    .await
    .unwrap();
    assert!(response.await.unwrap().is_empty());

    let explain = query_explain_advertised_route(&tx, target, Prefix::V4(prefix())).await;
    assert_eq!(explain.decision, crate::update::ExplainDecision::Deny);
    assert_eq!(
        explain.gates.last().map(|step| (step.gate, step.code)),
        Some(("no_advertise", "no_advertise_policy_suppressed"))
    );
    assert!(
        explain
            .modifications
            .communities_add
            .contains(&rustbgpd_wire::COMMUNITY_NO_ADVERTISE)
    );
    assert!(
        explain
            .reasons
            .iter()
            .any(|reason| reason.code == "per_client_candidate_no_advertise")
    );

    drop(tx);
    handle.await.unwrap();
}

/// Split horizon inside the collector: the member sourcing the Loc-RIB
/// best receives the runner-up (its own path is excluded from its
/// candidate set), where single-best would have sent nothing.
#[tokio::test]
async fn source_member_of_best_gets_runner_up() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    // A is an outbound per-client-best client AND the source of the best.
    let a = IpAddr::V4(SOURCE_A);
    let mut a_rx = client_peer_up(&tx, a, None, true).await;
    drain_eor(&mut a_rx).await;

    announce_from(&tx, SOURCE_A, vec![best_route()]).await;
    sync(&tx).await;
    // Only candidate is A's own route: split horizon, nothing sent.
    assert!(a_rx.try_recv().is_err(), "own route never echoes back");

    announce_from(&tx, SOURCE_B, vec![runner_up_route()]).await;
    sync(&tx).await;
    let update = a_rx.recv().await.unwrap();
    assert_eq!(update.announce.len(), 1);
    assert_eq!(update.announce[0].peer, IpAddr::V4(SOURCE_B));
    assert_eq!(update.announce[0].path_id, 0);
    assert!(update.withdraw.is_empty());

    drop(tx);
    handle.await.unwrap();
}

/// ADR-0126: a GROUPED per-client-best member takes the dedicated
/// per-client-best explain arm, with its advertised-state diff
/// materialized from the group's `adv(m)` view — so explain for the
/// winner's source names the RUNNER-UP (the lane substitution on its
/// wire), reports it in sync, and carries the update-group identity.
#[tokio::test]
async fn grouped_source_member_explain_names_runner_up_substitution() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    // Two shareable-chain unicast-only per-client-best members: since
    // the classifier flip they share one mitigated group.
    let a = IpAddr::V4(SOURCE_A);
    let e = IpAddr::V4(SOURCE_E);
    let mut a_rx = client_peer_up(&tx, a, None, true).await;
    drain_eor(&mut a_rx).await;
    let mut e_rx = client_peer_up(&tx, e, None, true).await;
    drain_eor(&mut e_rx).await;
    let membership = |peer| {
        let tx = tx.clone();
        async move {
            let (reply_tx, reply_rx) = oneshot::channel();
            tx.send(RibUpdate::QueryPeerUpdateGroup {
                peer,
                reply: reply_tx,
            })
            .await
            .unwrap();
            reply_rx.await.unwrap()
        }
    };
    let group = membership(a).await;
    assert!(group.starts_with("group:"), "grouped member: {group}");
    assert_eq!(membership(e).await, group);

    // A sources the winner; B's route is the runner-up in the lane.
    announce_from(
        &tx,
        SOURCE_A,
        vec![ebgp_route(prefix(), SOURCE_A, vec![65001], vec![])],
    )
    .await;
    announce_from(&tx, SOURCE_B, vec![runner_up_route()]).await;
    sync(&tx).await;
    let update = a_rx.recv().await.unwrap();
    assert_eq!(update.announce.len(), 1);
    assert_eq!(update.announce[0].peer, IpAddr::V4(SOURCE_B));

    let explain = query_explain_advertised_route(&tx, a, Prefix::V4(prefix())).await;
    assert_eq!(explain.decision, crate::update::ExplainDecision::Advertise);
    assert_eq!(
        explain.route_peer,
        Some(IpAddr::V4(SOURCE_B)),
        "explain for source(w) names the runner-up substitution"
    );
    assert!(
        explain.already_advertised,
        "the substitution is on the member's wire — explain must report in sync"
    );
    assert!(
        explain.update_group_id.is_some(),
        "a grouped member's explain carries its update-group identity"
    );

    // The non-source member's explain names the winner, also in sync.
    let e_update = e_rx.recv().await.unwrap();
    assert_eq!(e_update.announce[0].peer, IpAddr::V4(SOURCE_A));
    let explain = query_explain_advertised_route(&tx, e, Prefix::V4(prefix())).await;
    assert_eq!(explain.route_peer, Some(IpAddr::V4(SOURCE_A)));
    assert!(explain.already_advertised);

    drop(tx);
    handle.await.unwrap();
}

/// The `OpenBGPd` `rde evaluate all` bug-class pins:
/// (a) a candidate change that does NOT alter the client's filtered
///     best produces NO re-announcement (equality suppression);
/// (b) withdrawing the current filtered best converges to the next
///     candidate as a clean implicit replace — announce only, no
///     spurious withdraw+announce pair;
/// (c) a policy "reload" with identical content produces zero wire
///     churn (the resync diffs against Adj-RIB-Out);
/// plus the `GShut` force replay re-emits the filtered best (the force
/// path deliberately bypasses the equality check).
#[tokio::test]
async fn candidate_churn_produces_minimal_deltas() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    announce_from(&tx, SOURCE_A, vec![best_route()]).await;
    announce_from(&tx, SOURCE_B, vec![runner_up_route()]).await;

    let client = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 4));
    let mut client_rx = client_peer_up(&tx, client, Some(deny_tagged_chain()), true).await;
    let dump = client_rx.recv().await.unwrap();
    assert_eq!(dump.announce.len(), 1);
    assert_eq!(dump.announce[0].peer, IpAddr::V4(SOURCE_B));
    drain_eor(&mut client_rx).await;

    // (a) new WORSE candidate: filtered best stays B — no wire traffic.
    announce_from(&tx, SOURCE_E, vec![third_route()]).await;
    sync(&tx).await;
    assert!(
        client_rx.try_recv().is_err(),
        "unchanged filtered best must not re-announce"
    );

    // (a) denied best changes attributes: still denied — no wire traffic.
    let mut retagged_best = best_route();
    Arc::make_mut(&mut retagged_best.attributes).push(PathAttribute::Med(50));
    announce_from(&tx, SOURCE_A, vec![retagged_best]).await;
    sync(&tx).await;
    assert!(
        client_rx.try_recv().is_err(),
        "churn on the denied best must not leak to the client"
    );

    // (b) withdraw the filtered best: implicit replace to the next
    // candidate — announce E, withdraw NOTHING (same path_id 0).
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: IpAddr::V4(SOURCE_B),
        announced: vec![],
        withdrawn: vec![(Prefix::V4(prefix()), 0)],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();
    sync(&tx).await;
    let update = client_rx.recv().await.unwrap();
    assert_eq!(update.announce.len(), 1);
    assert_eq!(update.announce[0].peer, IpAddr::V4(SOURCE_E));
    assert_eq!(update.announce[0].path_id, 0);
    assert!(
        update.withdraw.is_empty(),
        "filtered-best flip must be an implicit replace, not withdraw+announce"
    );
    assert!(client_rx.try_recv().is_err(), "exactly one update");

    // (c) reload-with-unchanged-policy: replace the chain with
    // content-equal contents — the resync must be fully suppressed.
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::ReplacePeerExportPolicy {
        peer: client,
        export_policy: Some(deny_tagged_chain()),
        reply: reply_tx,
    })
    .await
    .unwrap();
    reply_rx.await.unwrap().unwrap();
    sync(&tx).await;
    assert!(
        client_rx.try_recv().is_err(),
        "no-op policy reload must produce zero wire churn"
    );

    // GShut-style force replay bypasses the equality check and re-emits
    // the current filtered best unchanged.
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::RefreshPeerOutbound {
        peer: client,
        reply: reply_tx,
    })
    .await
    .unwrap();
    reply_rx.await.unwrap().unwrap();
    let update = client_rx.recv().await.unwrap();
    assert_eq!(update.announce.len(), 1);
    assert_eq!(update.announce[0].peer, IpAddr::V4(SOURCE_E));
    assert_eq!(update.announce[0].path_id, 0);
    assert!(update.withdraw.is_empty());

    drop(tx);
    handle.await.unwrap();
}

/// ROUTE-REFRESH replay re-derives the same filtered best the live path
/// staged: one announce at `path_id 0`, not the (denied) Loc-RIB best.
#[tokio::test]
async fn route_refresh_replays_filtered_best() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    announce_from(&tx, SOURCE_A, vec![best_route()]).await;
    announce_from(&tx, SOURCE_B, vec![runner_up_route()]).await;

    let client = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 4));
    let mut client_rx = client_peer_up(&tx, client, Some(deny_tagged_chain()), true).await;
    let dump = client_rx.recv().await.unwrap();
    assert_eq!(dump.announce.len(), 1);
    drain_eor(&mut client_rx).await;

    tx.send(RibUpdate::RouteRefreshRequest {
        peer: client,
        session_id: 0,
        afi: Afi::Ipv4,
        safi: Safi::Unicast,
    })
    .await
    .unwrap();
    let replay = client_rx.recv().await.unwrap();
    assert_eq!(
        replay.announce.len(),
        1,
        "refresh replays the filtered best"
    );
    assert_eq!(replay.announce[0].peer, IpAddr::V4(SOURCE_B));
    assert_eq!(replay.announce[0].path_id, 0);
    assert!(replay.withdraw.is_empty());

    drop(tx);
    handle.await.unwrap();
}

/// An rpol chain with a named term denying `65000:99`-tagged routes —
/// the explain tests assert the term label surfaces per candidate.
fn rpol_deny_tagged_chain() -> PolicyChain {
    const RPOL: &str = r"
policy no-tagged {
    term block-tagged {
        if route.communities has 65000:99 { reject }
    }
}
";
    let file = rustbgpd_policy::rpol::RpolFile::parse(RPOL).expect("clean rpol");
    let mut store = rustbgpd_policy::sets::SetStore::new();
    let compiled = file
        .compile_policy("no-tagged", &[], &mut store)
        .expect("policy exists");
    PolicyChain::from_named(vec![rustbgpd_policy::NamedPolicy::from_rpol(
        "no-tagged".to_string(),
        Arc::new(compiled),
    )])
}

/// The slice-1 known gap, fixed: `ExplainAdvertisedRoute` for a
/// per-client-best peer dry-runs the filtered-best walk live staging
/// performs — when the Loc-RIB best is policy-denied it explains the
/// advertised runner-up (candidate ladder with per-candidate term
/// labels), not a false "denied". A single-best sibling with the same
/// chain keeps its truthful Deny.
#[tokio::test]
async fn explain_names_runner_up_selection_with_term_labels() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    announce_from(&tx, SOURCE_A, vec![best_route()]).await;
    announce_from(&tx, SOURCE_B, vec![runner_up_route()]).await;

    let mitigated = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 4));
    let mut mitigated_rx =
        client_peer_up(&tx, mitigated, Some(rpol_deny_tagged_chain()), true).await;
    let dump = mitigated_rx.recv().await.unwrap();
    assert_eq!(dump.announce.len(), 1, "live sends the runner-up");
    assert_eq!(dump.announce[0].peer, IpAddr::V4(SOURCE_B));

    let hidden = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
    let mut hidden_rx = client_peer_up(&tx, hidden, Some(rpol_deny_tagged_chain()), false).await;
    drain_eor(&mut hidden_rx).await;

    // Per-client-best explain: agrees with the wire — the runner-up IS
    // advertised, with the denied best named per candidate.
    let explain = query_explain_advertised_route(&tx, mitigated, Prefix::V4(prefix())).await;
    assert_eq!(explain.decision, crate::update::ExplainDecision::Advertise);
    assert_eq!(explain.route_peer, Some(IpAddr::V4(SOURCE_B)));
    assert_eq!(explain.next_hop, Some(IpAddr::V4(SOURCE_B)));
    assert!(
        explain.already_advertised,
        "live already advertised the filtered best — explain must report in-sync"
    );
    let selection = explain
        .gates
        .iter()
        .find(|step| step.code == "per_client_best")
        .expect("per-client selection gate present");
    assert_eq!(selection.gate, "best_route");
    assert!(
        selection.detail.contains("candidate 2 of 2"),
        "selection names the ladder position, got {:?}",
        selection.detail
    );
    let denial = explain
        .reasons
        .iter()
        .find(|reason| reason.code == "per_client_candidate_denied")
        .expect("denied candidate recorded");
    assert!(
        denial.message.contains("no-tagged:block-tagged"),
        "per-candidate verdict names the rpol term, got {:?}",
        denial.message
    );
    assert!(
        denial.message.contains("candidate 1 of 2"),
        "denial names the rank, got {:?}",
        denial.message
    );
    // The winner's own policy gate passed with the chain named.
    assert!(
        explain
            .gates
            .iter()
            .any(|step| step.code == "policy_permitted"),
        "winner passes the export-policy rung"
    );

    // Single-best sibling: same chain, truthful Deny (path hiding).
    let hidden_explain = query_explain_advertised_route(&tx, hidden, Prefix::V4(prefix())).await;
    assert_eq!(
        hidden_explain.decision,
        crate::update::ExplainDecision::Deny
    );
    assert!(
        hidden_explain
            .reasons
            .iter()
            .any(|reason| reason.code == "policy_denied"),
        "single-best explain unchanged"
    );

    drop(tx);
    handle.await.unwrap();
}

/// Every candidate denied: the explain ladder stops at selection with
/// one recorded verdict per candidate — mirroring the live walk, which
/// stages nothing.
#[tokio::test]
async fn explain_reports_every_denied_candidate_when_nothing_is_advertised() {
    const RPOL: &str = r"
policy deny-all {
    term block-everything { reject }
}
";
    let file = rustbgpd_policy::rpol::RpolFile::parse(RPOL).expect("clean rpol");
    let mut store = rustbgpd_policy::sets::SetStore::new();
    let compiled = file
        .compile_policy("deny-all", &[], &mut store)
        .expect("policy exists");
    let chain = PolicyChain::from_named(vec![rustbgpd_policy::NamedPolicy::from_rpol(
        "deny-all".to_string(),
        Arc::new(compiled),
    )]);

    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    announce_from(&tx, SOURCE_A, vec![best_route()]).await;
    announce_from(&tx, SOURCE_B, vec![runner_up_route()]).await;

    let client = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 4));
    let mut client_rx = client_peer_up(&tx, client, Some(chain), true).await;
    drain_eor(&mut client_rx).await; // nothing staged: EoR only

    let explain = query_explain_advertised_route(&tx, client, Prefix::V4(prefix())).await;
    assert_eq!(explain.decision, crate::update::ExplainDecision::Deny);
    let stop = explain
        .gates
        .iter()
        .find(|step| step.verdict == crate::update::ExportGateVerdict::Stop)
        .expect("ladder stops");
    assert_eq!(
        (stop.gate, stop.code),
        ("best_route", "per_client_all_denied")
    );
    let denials: Vec<_> = explain
        .reasons
        .iter()
        .filter(|reason| reason.code == "per_client_candidate_denied")
        .collect();
    assert_eq!(denials.len(), 2, "one verdict per candidate");
    assert!(
        denials
            .iter()
            .all(|reason| reason.message.contains("deny-all:block-everything")),
        "each verdict names the term"
    );

    drop(tx);
    handle.await.unwrap();
}

/// With no denying chain, per-client-best selects the same route
/// single-best would — the modes agree on the common path (differential
/// pin against mode drift, design risk 4).
#[tokio::test]
async fn agrees_with_single_best_when_policy_permits_the_best() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    announce_from(&tx, SOURCE_A, vec![best_route()]).await;
    announce_from(&tx, SOURCE_B, vec![runner_up_route()]).await;

    let plain = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 6));
    let mut plain_rx = client_peer_up(&tx, plain, None, false).await;
    let plain_dump = plain_rx.recv().await.unwrap();
    drain_eor(&mut plain_rx).await;

    let pcb = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 7));
    let mut pcb_rx = client_peer_up(&tx, pcb, None, true).await;
    let pcb_dump = pcb_rx.recv().await.unwrap();
    drain_eor(&mut pcb_rx).await;

    assert_eq!(plain_dump.announce.len(), 1);
    assert_eq!(pcb_dump.announce.len(), 1);
    assert_eq!(plain_dump.announce[0].peer, pcb_dump.announce[0].peer);
    assert_eq!(plain_dump.announce[0].prefix, pcb_dump.announce[0].prefix);
    assert_eq!(plain_dump.announce[0].path_id, 0);
    assert_eq!(pcb_dump.announce[0].path_id, 0);

    drop(tx);
    handle.await.unwrap();
}
