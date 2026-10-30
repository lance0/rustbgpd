use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicUsize};

use super::export_explain::deny_local_pref_at_least;
use super::update_groups::{CohortExactEncoder, community_chain};
use super::*;
use crate::update::{ExplainDecision, RouteSourceIdentity};

const SOURCES: [Ipv4Addr; 2] = [Ipv4Addr::new(192, 0, 2, 1), Ipv4Addr::new(192, 0, 2, 2)];
const FAMILY: (Afi, Safi) = (Afi::Ipv4, Safi::Unicast);
const INPUT: &str = "policy_filtered_input";
const REBUILD: &str = "policy_filtered_rebuild";
const ALLOCATION: &str = "policy_filtered_allocation";
const RETIREMENT: &str = "policy_filtered_retirement";
const HISTORY: &str = "policy_filtered_retained";
const HISTORY_CLEANUP: &str = "policy_filtered_history_cleanup";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Writer {
    Initial,
    Refresh,
    Distribution,
    Transition,
}

fn target(index: u8) -> PeerId {
    peer_v4(Ipv4Addr::new(198, 18, 0, index + 1))
}

fn prefix(index: u8) -> Prefix {
    Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(203, 0, index, 0), 24))
}

fn candidate(source: Ipv4Addr, prefix_index: u8, path_id: u32, local_pref: u32) -> Route {
    let Prefix::V4(prefix) = prefix(prefix_index) else {
        unreachable!()
    };
    let mut route = make_route_with_lp(prefix, source, local_pref);
    route.path_id = path_id;
    // Equal retention tiers keep every denial ahead of the first permit
    // on the per-client-best transition path.
    route.is_stale = prefix_index == 0;
    route.is_llgr_stale = prefix_index == 1;
    route.aspa_context = crate::route::AspaContextId::intern_scoped(
        rustbgpd_wire::AspaValidationContext::default(),
        Some(if source == SOURCES[0] {
            "source-a"
        } else {
            "source-b"
        }),
    );
    route
}

fn receive(manager: &mut RibManager, source: Ipv4Addr, announced: Vec<Route>) {
    manager.handle_update(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: peer_v4(source),
        announced,
        withdrawn: Vec::new(),
        flowspec_announced: Vec::new(),
        flowspec_withdrawn: Vec::new(),
        evpn_announced: Vec::new(),
        evpn_withdrawn: Vec::new(),
        validated_with: None,
    });
    drain_route_chunks(manager);
}

fn feed_candidates(manager: &mut RibManager) {
    for source in SOURCES {
        let routes = (0..2)
            .flat_map(|prefix_index| {
                (1..=8).map(move |path_id| {
                    candidate(
                        source,
                        prefix_index,
                        path_id,
                        if path_id % 2 == 1 { 200 } else { 100 },
                    )
                })
            })
            .collect();
        receive(manager, source, routes);
    }
}

fn manager() -> RibManager {
    let (_tx, rx) = mpsc::channel(1);
    RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new())
}

fn register_target(
    manager: &mut RibManager,
    index: u8,
    grouped: bool,
    policy: rustbgpd_policy::PolicyChain,
    outbound_tx: mpsc::Sender<OutboundRouteUpdate>,
) {
    let peer = target(index);
    manager.handle_update(RibUpdate::SetPeerSourceContext {
        peer,
        session_id: 0,
        context: Arc::new(crate::update::PeerSourceContext {
            dampening_admission: None,
            peer_interface: Some("target-interface".into()),
            accepted_dynamic_range: None,
            route_server_client: grouped,
        }),
    });
    if grouped {
        manager.handle_update(RibUpdate::SetPeerExportEncoder {
            peer,
            session_id: 0,
            encoder: Arc::new(CohortExactEncoder {
                owner: u64::from(index) + 1,
                profile: 97,
                max_len: 65_535,
                generation: AtomicUsize::new(0),
                advance_generation: false,
                probes: Arc::new(AtomicUsize::new(0)),
                reuses: Arc::new(AtomicUsize::new(0)),
            }),
        });
        manager.handle_update(RibUpdate::SetPeerExportContext {
            peer,
            session_id: 0,
            local_role: Some(rustbgpd_wire::BgpRole::RouteServer),
        });
    }
    manager.handle_update(RibUpdate::PeerUp {
        peer,
        session_id: 0,
        peer_asn: 65_100,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx,
        export_policy: Some(policy),
        sendable_families: vec![FAMILY],
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
        per_client_best: grouped,
        interpret_rfc1997: true,
        add_path_send_families: if grouped { Vec::new() } else { vec![FAMILY] },
        add_path_send_max: if grouped { 0 } else { u32::MAX },
        negotiated_orf_recv: Vec::new(),
        negotiated_llgr_families: vec![FAMILY],
    });
}

fn refresh(manager: &mut RibManager, peer: PeerId) {
    let queued = Arc::new(AtomicBool::new(true));
    manager.handle_update(RibUpdate::RouteRefreshRequest {
        peer,
        session_id: 0,
        afi: FAMILY.0,
        safi: FAMILY.1,
        queued: Arc::clone(&queued),
    });
    assert!(!queued.load(std::sync::atomic::Ordering::Relaxed));
}

fn expected_denials(peer: PeerId) -> HashSet<PolicyFilteredRouteKey> {
    SOURCES
        .into_iter()
        .flat_map(|source| {
            (0..2).flat_map(move |index| {
                [1, 3, 5, 7].map(move |path_id| PolicyFilteredRouteKey {
                    target_peer: peer,
                    source_peer: peer_v4(source),
                    prefix: prefix(index),
                    path_id,
                })
            })
        })
        .collect()
}

fn denial_events(manager: &RibManager, peer: PeerId) -> Vec<Arc<crate::event::RouteEvent>> {
    manager
        .route_event_history
        .iter()
        .filter(|event| {
            event.event_type == RouteEventType::PolicyFiltered
                && event.target_peer == Some(peer.addr())
        })
        .cloned()
        .collect()
}

fn assert_candidate_tables(manager: &RibManager) {
    assert_eq!(manager.loc_rib.len(), 2);
    for source in SOURCES {
        let rib = &manager.ribs[&peer_v4(source)];
        assert_eq!(rib.len(), 16);
        let counts = vec![(
            FAMILY,
            crate::adj_rib_in::StaleRouteCounts {
                stale: 8,
                llgr_stale: 8,
            },
        )];
        assert_eq!(rib.maintained_stale_route_counts(), counts);
        assert_eq!(rib.scanned_stale_route_counts(), counts);
        assert_eq!(rib.retained_stale_count(), 16);
    }
}

fn assert_denials_and_events(manager: &RibManager, peer: PeerId) {
    let expected = expected_denials(peer);
    assert_eq!(retained_policy_rejection_keys(manager, peer), expected);
    let events = denial_events(manager, peer);
    assert_eq!(events.len(), 16);
    let observed: HashSet<_> = events
        .iter()
        .map(|event| {
            assert_eq!(event.reason, "policy_denied");
            assert_eq!(
                event.target_peer_interface().as_deref(),
                Some("target-interface")
            );
            assert_eq!(
                event.peer_interface().as_deref(),
                Some(if event.peer == Some(IpAddr::V4(SOURCES[0])) {
                    "source-a"
                } else {
                    "source-b"
                })
            );
            (event.peer.unwrap(), event.prefix, event.path_id)
        })
        .collect();
    assert_eq!(
        observed,
        expected
            .into_iter()
            .map(|key| (key.source_peer.addr(), key.prefix, key.path_id))
            .collect()
    );
}

fn observe_inventory(
    manager: &mut RibManager,
    frozen_summaries: bool,
    work: impl FnOnce(&mut RibManager),
) -> BTreeMap<&'static str, usize> {
    // Authoritative replacement serves its existing frozen summary view;
    // the other export owners keep that lane queued.
    let expected_summary = frozen_summaries.then(|| manager.neighbor_rib_snapshot(target(0)));
    let (primary_tx, rx) = mpsc::channel(1);
    let (query_tx, query_rx) = mpsc::channel(1);
    let (summary_tx, summary_rx) = mpsc::channel(1);
    let (readiness_tx, readiness_rx) = mpsc::channel(1);
    manager.rx = rx;
    manager.query_rx = query_rx;
    manager.summary_rx = Some(summary_rx);
    manager.readiness_rx = Some(readiness_rx);
    manager.flush_poll_budget = Duration::ZERO;
    let (reply, mutation) = oneshot::channel();
    primary_tx
        .try_send(RibUpdate::ReplacePeerExportPolicy {
            peer: target(0),
            export_policy: None,
            reply,
        })
        .unwrap();
    let (reply, general) = oneshot::channel();
    query_tx
        .try_send(RibUpdate::QueryLocRibCount { reply })
        .unwrap();
    let (reply, summary) = oneshot::channel();
    summary_tx
        .try_send(crate::RibSummaryQuery::NeighborRibSnapshots {
            peers: vec![target(0)],
            comparison: None,
            reply,
            include_retained: false,
        })
        .unwrap();
    let visits = Arc::new(Mutex::new(BTreeMap::new()));
    let pending = Arc::new(Mutex::new(
        None::<oneshot::Receiver<Result<usize, crate::RibReadinessError>>>,
    ));
    manager.replacement_readiness_test_hook = Some(Arc::new({
        let visits = Arc::clone(&visits);
        let pending = Arc::clone(&pending);
        let mutation = Mutex::new(mutation);
        let general = Mutex::new(general);
        let summary = Mutex::new(Some(summary));
        move |stage| {
            if !matches!(
                stage,
                INPUT | REBUILD | ALLOCATION | RETIREMENT | HISTORY | HISTORY_CLEANUP
            ) {
                return;
            }
            for empty in [
                matches!(
                    mutation.lock().unwrap().try_recv(),
                    Err(oneshot::error::TryRecvError::Empty)
                ),
                matches!(
                    general.lock().unwrap().try_recv(),
                    Err(oneshot::error::TryRecvError::Empty)
                ),
            ] {
                assert!(
                    empty,
                    "ordinary lanes must remain queued during inventory work"
                );
            }
            if let Some(expected) = &expected_summary {
                if let Some(mut response) = summary.lock().unwrap().take() {
                    assert_eq!(
                        response.try_recv().unwrap().snapshots,
                        vec![expected.clone()]
                    );
                }
            } else {
                assert!(matches!(
                    summary.lock().unwrap().as_mut().unwrap().try_recv(),
                    Err(oneshot::error::TryRecvError::Empty)
                ));
            }
            if let Some(mut response) = pending.lock().unwrap().take() {
                assert_eq!(response.try_recv().unwrap(), Ok(2));
            }
            *visits.lock().unwrap().entry(stage).or_default() += 1;
            let (reply, response) = oneshot::channel();
            readiness_tx
                .try_send(crate::RibReadinessQuery::LocRibCount {
                    reply,
                    enqueued: std::time::Instant::now(),
                })
                .unwrap();
            *pending.lock().unwrap() = Some(response);
        }
    }));
    work(manager);
    manager.replacement_readiness_test_hook = None;
    let mut response = pending
        .lock()
        .unwrap()
        .take()
        .expect("inventory checkpoint");
    assert_eq!(response.try_recv().unwrap(), Ok(2));
    Arc::try_unwrap(visits).unwrap().into_inner().unwrap()
}

fn inventory_writer_uses_candidate_bounds(writer: Writer) {
    let mut manager = manager();
    if writer != Writer::Distribution {
        feed_candidates(&mut manager);
    }
    let (outbound_tx, mut outbound_rx) = mpsc::channel(8);
    let policy = deny_local_pref_at_least(200);
    if writer != Writer::Initial {
        register_target(
            &mut manager,
            0,
            writer == Writer::Transition,
            if writer == Writer::Transition {
                community_chain(0xFDE8_0001)
            } else {
                policy.clone()
            },
            outbound_tx.clone(),
        );
        while outbound_rx.try_recv().is_ok() {}
    }
    let mut second_rx = if writer == Writer::Transition {
        let (tx, mut rx) = mpsc::channel(8);
        register_target(&mut manager, 1, true, community_chain(0xFDE8_0001), tx);
        while rx.try_recv().is_ok() {}
        let group = manager.grouped_member_of(target(0)).unwrap();
        assert_eq!(manager.grouped_member_of(target(1)), Some(group));
        Some(rx)
    } else {
        None
    };
    let visits =
        observe_inventory(
            &mut manager,
            writer == Writer::Transition,
            |manager| match writer {
                Writer::Initial => register_target(manager, 0, false, policy.clone(), outbound_tx),
                Writer::Refresh => refresh(manager, target(0)),
                Writer::Distribution => feed_candidates(manager),
                Writer::Transition => {
                    let (reply, mut response) = oneshot::channel();
                    manager.handle_update(RibUpdate::ReplacePeerExportPoliciesAuthoritatively {
                        replacements: (0..2)
                            .map(|index| crate::update::PeerExportPolicyReplacement {
                                peer: target(index),
                                export_policy: Some(policy.clone()),
                            })
                            .collect(),
                        reply,
                    });
                    assert_eq!(response.try_recv().unwrap(), Ok(()));
                }
            },
        );
    let (inputs, rebuilds, allocations, retired) = match writer {
        Writer::Initial | Writer::Refresh => (16, 8, 12, 19),
        Writer::Distribution => (24, 12, 24, 30),
        Writer::Transition => (32, 0, 12, 38),
    };
    assert_eq!(
        visits.get(INPUT).copied().unwrap_or_default(),
        inputs,
        "{writer:?}"
    );
    assert_eq!(
        visits.get(REBUILD).copied().unwrap_or_default(),
        rebuilds,
        "{writer:?}"
    );
    assert_eq!(
        visits.get(ALLOCATION).copied().unwrap_or_default(),
        allocations,
        "{writer:?}: allocation edges"
    );
    assert_eq!(
        visits.get(RETIREMENT).copied().unwrap_or_default(),
        retired,
        "{writer:?}: retire every temporary key and allocation"
    );
    assert!(visits[HISTORY] > 0, "{writer:?}: history");
    assert_candidate_tables(&manager);
    assert_denials_and_events(&manager, target(0));
    assert!(
        retained_policy_rejection_keys(&manager, target(0)).len()
            > HashSet::<PolicyFilteredRouteKey>::with_capacity(manager.loc_rib.len()).capacity(),
        "real rejected candidate identities exceed the old prefix-count capacity"
    );
    if writer == Writer::Transition {
        let stats = manager.policy_transition_stats;
        assert_eq!(stats.batched_authoritative_shared_members, 2);
        assert_eq!(stats.batched_authoritative_fallback_members, 0);
        assert_denials_and_events(&manager, target(1));
        let advertised = manager.grouped_advertised_routes(target(0)).unwrap();
        assert_eq!(advertised.len(), 2);
        assert!(second_rx.as_mut().unwrap().try_recv().is_ok());
    } else {
        assert_eq!(manager.adj_ribs_out[&target(0)].len(), 16);
    }
    assert!(outbound_rx.try_recv().is_ok());
}

#[test]
fn initial_policy_filtered_inventory_uses_candidate_bounds() {
    inventory_writer_uses_candidate_bounds(Writer::Initial);
}

#[test]
fn refresh_policy_filtered_inventory_uses_candidate_bounds() {
    inventory_writer_uses_candidate_bounds(Writer::Refresh);
}

#[test]
fn distribution_policy_filtered_inventory_uses_candidate_bounds() {
    inventory_writer_uses_candidate_bounds(Writer::Distribution);
}

#[test]
fn transition_policy_filtered_inventory_uses_candidate_bounds() {
    inventory_writer_uses_candidate_bounds(Writer::Transition);
}

fn collect_pages(manager: &mut RibManager, scope: RouteQueryScope, total: u64) -> Vec<Route> {
    let mut routes = Vec::new();
    let mut after = None;
    let mut expected_version = None;
    loop {
        let (reply, mut response) = oneshot::channel();
        manager.handle_update(RibUpdate::QueryRoutesPage {
            scope,
            filter: None,
            after,
            expected_version,
            page_size: 3,
            reply,
        });
        let page = response.try_recv().unwrap().unwrap();
        assert_eq!(page.total, total);
        assert!(page.routes.len() <= 3);
        expected_version = Some(page.version);
        after = page.routes.last().map(route_query_key);
        routes.extend(page.routes);
        if !page.has_more {
            return routes;
        }
        assert!(after.is_some(), "a continuation must advance its cursor");
    }
}

fn assert_pages_and_explain(manager: &mut RibManager) {
    let before = manager
        .export_policy_counters
        .get(&target(0))
        .map(crate::update::ExportPolicyCounters::snapshot);
    let event_count = manager.route_event_history.len();
    let received = collect_pages(manager, RouteQueryScope::Received { peer: None }, 32);
    let identities: HashSet<_> = received
        .iter()
        .map(|route| (route.prefix, route.peer, route.path_id))
        .collect();
    assert_eq!(received.len(), 32);
    assert_eq!(
        identities.len(),
        32,
        "same inbound path IDs from different sources stay distinct"
    );
    let advertised = collect_pages(manager, RouteQueryScope::Advertised { peer: target(0) }, 16);
    assert_eq!(advertised.len(), 16);
    assert!(
        advertised
            .iter()
            .all(|route| route.local_pref_attr() == Some(100))
    );
    for index in 0..2 {
        assert_eq!(
            advertised
                .iter()
                .filter(|route| route.prefix == prefix(index))
                .map(|route| route.path_id)
                .collect::<BTreeSet<_>>(),
            (1..=8).collect()
        );
    }
    for (source_index, source) in SOURCES.into_iter().enumerate() {
        for index in 0..2 {
            for path_id in 1..=8 {
                assert!(identities.contains(&(prefix(index), peer_v4(source), path_id)));
                let (reply, mut response) = oneshot::channel();
                manager.handle_update(RibUpdate::ExplainAdvertisedRoute {
                    peer: target(0),
                    prefix: prefix(index),
                    rd: None,
                    labeled: false,
                    source: Some(RouteSourceIdentity {
                        peer: peer_v4(source),
                        path_id,
                    }),
                    reply,
                });
                let explanation = response.try_recv().unwrap().unwrap();
                assert_eq!(explanation.route_peer, Some(peer_v4(source)));
                assert_eq!(explanation.route_path_id, Some(path_id));
                if path_id % 2 == 1 {
                    assert_eq!(explanation.decision, ExplainDecision::Deny);
                    assert!(
                        explanation
                            .reasons
                            .iter()
                            .any(|reason| reason.code == "policy_denied")
                    );
                } else {
                    assert_eq!(explanation.decision, ExplainDecision::Advertise);
                    assert!(explanation.already_advertised);
                    assert_eq!(
                        explanation.path_id,
                        u32::try_from(source_index).unwrap() * 4 + path_id / 2
                    );
                }
            }
        }
    }
    assert_eq!(
        manager
            .export_policy_counters
            .get(&target(0))
            .map(crate::update::ExportPolicyCounters::snapshot),
        before
    );
    assert_eq!(manager.route_event_history.len(), event_count);
}

#[test]
fn policy_filtered_inventory_retry_preserves_event_edges_and_diagnostics() {
    let mut manager = manager();
    feed_candidates(&mut manager);
    let (tx, mut outbound) = mpsc::channel(8);
    let held: Vec<_> = (0..8)
        .map(|_| tx.clone().try_reserve_owned().unwrap())
        .collect();
    let visits = observe_inventory(&mut manager, false, |manager| {
        register_target(manager, 0, false, deny_local_pref_at_least(200), tx);
    });
    assert_eq!(
        visits.get(INPUT).copied().unwrap_or_default(),
        16,
        "failed initial input"
    );
    assert_eq!(
        visits.get(REBUILD).copied().unwrap_or_default(),
        8,
        "failed initial rebuild"
    );
    assert_eq!(
        visits.get(ALLOCATION).copied().unwrap_or_default(),
        12,
        "failed initial allocation"
    );
    assert_eq!(
        visits.get(RETIREMENT).copied().unwrap_or_default(),
        19,
        "failed initial admission retires its snapshot under the owner"
    );
    assert!(manager.dirty_peers.contains(&target(0)));
    assert!(!manager.policy_filtered_routes.contains_key(&target(0)));
    assert_eq!(denial_events(&manager, target(0)).len(), 0);
    refresh(&mut manager, target(0));
    assert!(manager.pending_refresh[&target(0)].contains(&FAMILY));
    assert_eq!(denial_events(&manager, target(0)).len(), 0);
    drop(held);
    manager.resync_dirty_peers_bounded();
    assert!(!manager.dirty_peers.contains(&target(0)));
    assert!(!manager.pending_refresh.contains_key(&target(0)));
    while outbound.try_recv().is_ok() {}
    assert_denials_and_events(&manager, target(0));
    let stale = Arc::new(AtomicBool::new(true));
    manager.handle_update(RibUpdate::RouteRefreshRequest {
        peer: target(0),
        session_id: 9,
        afi: FAMILY.0,
        safi: FAMILY.1,
        queued: Arc::clone(&stale),
    });
    assert!(!stale.load(std::sync::atomic::Ordering::Relaxed));
    assert!(!manager.pending_refresh.contains_key(&target(0)));
    assert_eq!(manager.adj_ribs_out[&target(0)].len(), 16);
    assert!(matches!(
        outbound.try_recv(),
        Err(mpsc::error::TryRecvError::Empty)
    ));
    assert_denials_and_events(&manager, target(0));
    for _ in 0..2 {
        refresh(&mut manager, target(0));
        while outbound.try_recv().is_ok() {}
        assert_denials_and_events(&manager, target(0));
    }

    let changed = PolicyFilteredRouteKey {
        target_peer: target(0),
        source_peer: peer_v4(SOURCES[0]),
        prefix: prefix(0),
        path_id: 1,
    };
    let allowed = candidate(SOURCES[0], 0, 1, 100);
    receive(&mut manager, SOURCES[0], vec![allowed]);
    let mut expected = expected_denials(target(0));
    assert!(expected.remove(&changed));
    assert_eq!(
        retained_policy_rejection_keys(&manager, target(0)),
        expected
    );
    assert_eq!(manager.adj_ribs_out[&target(0)].len(), 17);
    assert_eq!(denial_events(&manager, target(0)).len(), 16);
    while outbound.try_recv().is_ok() {}
    let denied = candidate(SOURCES[0], 0, 1, 200);
    receive(&mut manager, SOURCES[0], vec![denied]);
    assert_eq!(
        retained_policy_rejection_keys(&manager, target(0)),
        expected_denials(target(0))
    );
    let events = denial_events(&manager, target(0));
    assert_eq!(events.len(), 17);
    assert_eq!(
        events
            .iter()
            .filter(|event| event.peer == Some(SOURCES[0].into())
                && event.prefix == prefix(0)
                && event.path_id == 1)
            .count(),
        2,
        "only the newly denied source/path publishes another event"
    );
    assert_candidate_tables(&manager);
    assert_pages_and_explain(&mut manager);
}

#[test]
fn policy_rejection_history_refresh_preserves_siblings_and_empty_cleanup() {
    let mut manager = manager();
    let peer = target(0);
    let v4 = prefix(0);
    let v6 = Prefix::V6(Ipv6Prefix::new("2001:db8:1::".parse().unwrap(), 48));
    let key = |prefix, source_peer, path_id| PolicyFilteredRouteKey {
        target_peer: peer,
        source_peer,
        prefix,
        path_id,
    };
    let first = key(v4, peer_v4(SOURCES[0]), 1);
    let sibling = key(v4, peer_v4(SOURCES[1]), 7);
    let other_family = key(v6, peer_v4(SOURCES[0]), 3);
    let both = HashSet::from([v4, v6]);
    let all = HashSet::from([first, sibling, other_family]);
    manager.update_policy_filtered_routes_for_prefixes(peer, &both, &all);
    manager.update_policy_filtered_routes_for_prefixes(peer, &both, &all);
    assert_eq!(retained_policy_rejection_keys(&manager, peer), all);
    assert_eq!(denial_events(&manager, peer).len(), 3);
    let only_v4 = HashSet::from([v4]);
    manager.update_policy_filtered_routes_for_prefixes(peer, &only_v4, &HashSet::from([first]));
    assert_eq!(
        retained_policy_rejection_keys(&manager, peer),
        HashSet::from([first, other_family])
    );
    assert_eq!(denial_events(&manager, peer).len(), 3);
    manager.update_policy_filtered_routes_for_prefixes(
        peer,
        &only_v4,
        &HashSet::from([first, sibling]),
    );
    assert_eq!(retained_policy_rejection_keys(&manager, peer), all);
    assert_eq!(denial_events(&manager, peer).len(), 4);
    manager.update_policy_filtered_routes_for_prefixes(peer, &only_v4, &HashSet::new());
    assert_eq!(
        retained_policy_rejection_keys(&manager, peer),
        HashSet::from([other_family])
    );
    assert!(!manager.policy_filtered_routes[&peer].contains_key(&v4));
    manager.update_policy_filtered_routes_for_prefixes(peer, &HashSet::from([v6]), &HashSet::new());
    assert!(!manager.policy_filtered_routes.contains_key(&peer));
    assert_eq!(denial_events(&manager, peer).len(), 4);
    manager.update_policy_filtered_routes_for_prefixes(peer, &only_v4, &HashSet::from([sibling]));
    assert_eq!(
        retained_policy_rejection_keys(&manager, peer),
        HashSet::from([sibling])
    );
    assert_eq!(denial_events(&manager, peer).len(), 5);
    manager.clear_policy_filtered_routes_for_peer(peer);
    assert!(!manager.policy_filtered_routes.contains_key(&peer));
}

#[test]
fn policy_rejection_history_peer_down_services_interior_readiness() {
    let mut manager = manager();
    feed_candidates(&mut manager);
    let (tx, mut outbound) = mpsc::channel(8);
    register_target(&mut manager, 0, false, deny_local_pref_at_least(200), tx);
    while outbound.try_recv().is_ok() {}
    assert_candidate_tables(&manager);
    assert_denials_and_events(&manager, target(0));
    let visits = observe_inventory(&mut manager, false, |manager| {
        manager.handle_update(RibUpdate::PeerDown {
            peer: target(0),
            session_id: 0,
        });
    });
    assert!(
        visits.get(HISTORY_CLEANUP).copied().unwrap_or_default() > 1,
        "bucket and allocation cleanup must serve readiness under the history owner"
    );
    assert!(!manager.policy_filtered_routes.contains_key(&target(0)));
    assert_candidate_tables(&manager);
    assert_eq!(denial_events(&manager, target(0)).len(), 16);
}

/// A clean pass whose per-client-best group stages denied candidates owns
/// that shared staging inside an executor handoff.
#[test]
fn per_client_best_rejection_staging_is_owned_and_handed_off() {
    let mut manager = manager();
    let (outbound_tx, mut outbound_rx) = mpsc::channel(8);
    register_target(
        &mut manager,
        0,
        true,
        deny_local_pref_at_least(200),
        outbound_tx,
    );
    while outbound_rx.try_recv().is_ok() {}
    let group = manager
        .grouped_member_of(target(0))
        .expect("grouped target");
    assert!(manager.group_ribs[&group].per_client_best);
    let observed = owned_checkpoints(&mut manager, feed_candidates);
    assert_owned_inside_handoff("per-client-best staging", &observed, "staging_shared_emit");
    assert_candidate_tables(&manager);
    assert_denials_and_events(&manager, target(0));
}

/// A clean Add-Path pass whose export policy memoizes more distinct
/// candidate attribute sets than it stages prefixes releases that memo under
/// an owner inside an executor handoff.
#[test]
fn add_path_export_memo_retirement_is_owned_and_handed_off() {
    let mut manager = manager();
    let (outbound_tx, mut outbound_rx) = mpsc::channel(8);
    register_target(
        &mut manager,
        0,
        false,
        community_chain(0xFDE8_0001),
        outbound_tx,
    );
    while outbound_rx.try_recv().is_ok() {}
    assert!(manager.grouped_member_of(target(0)).is_none());
    // Eight distinct attribute sets across two prefixes.
    let routes = (0..2)
        .flat_map(|prefix_index| {
            (1..=8).map(move |path_id| candidate(SOURCES[0], prefix_index, path_id, 100 + path_id))
        })
        .collect();
    let observed = owned_checkpoints(&mut manager, |manager| {
        receive(manager, SOURCES[0], routes);
    });
    assert_owned_inside_handoff("Add-Path memo retirement", &observed, "retirement");
    assert_eq!(manager.adj_ribs_out[&target(0)].len(), 16);
}
