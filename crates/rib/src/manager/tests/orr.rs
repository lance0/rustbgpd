use super::*;

/// Value of a label-less counter metric (0.0 when never incremented).
fn counter_metric_value(metrics: &BgpMetrics, name: &str) -> f64 {
    metrics
        .registry()
        .gather()
        .iter()
        .find(|family| family.name() == name)
        .and_then(|family| family.metric.first())
        .map_or(0.0, |metric| metric.get_counter().value())
}

/// A still-gated BGP-LS family must not influence already-released unicast
/// ORR selection. The topology becomes visible only when the BGP-LS gate
/// itself releases.
#[tokio::test]
async fn selection_deferral_hides_bgpls_topology_until_family_release() {
    let feed = Ipv4Addr::new(10, 9, 9, 9);
    let feed_peer = IpAddr::V4(feed);
    let family = (Afi::BgpLs, Safi::BgpLs);
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new())
        .with_selection_deferral(SelectionDeferralConfig {
            timeout: Duration::from_mins(1),
            waiters: vec![SelectionDeferralWaiterConfig {
                peer: feed_peer,
                families: vec![family],
            }],
        });
    let handle = tokio::spawn(manager.run());

    feed_square_topology(&tx, feed).await;
    let client = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let _client_rx = orr_client_peer_up(&tx, client, Some(vantage_at_node_a())).await;
    let gated = query_orr_status(&tx).await;
    assert_eq!(gated.topology_nodes, 0);
    assert!(!gated.vantages[0].resolved);

    tx.send(RibUpdate::SetPeerGracefulRestartContext {
        peer: feed_peer,
        session_id: 1,
        peer_restart_state: false,
        peer_gr_families: vec![family],
    })
    .await
    .unwrap();
    let (feed_tx, _feed_rx) = mpsc::channel(8);
    tx.send(RibUpdate::PeerUp {
        per_client_best: false,
        session_id: 1,
        peer: feed_peer,
        peer_asn: 65000,
        peer_router_id: feed,
        outbound_tx: feed_tx,
        export_policy: None,
        sendable_families: vec![family],
        is_ebgp: false,
        route_reflector_client: true,
        orr_vantage: None,
        add_path_send_families: Vec::new(),
        add_path_send_max: 0,
        negotiated_orf_recv: Vec::new(),
        negotiated_llgr_families: Vec::new(),
    })
    .await
    .unwrap();
    tx.send(RibUpdate::EndOfRib {
        peer: feed_peer,
        session_id: 1,
        afi: family.0,
        safi: family.1,
    })
    .await
    .unwrap();

    let released = query_orr_status(&tx).await;
    assert_eq!(released.topology_nodes, 4);
    assert!(released.vantages[0].resolved);

    drop(tx);
    handle.await.unwrap();
}

/// `PeerUp` with an `orr_vantage` registers the vantage (visible through
/// `QueryOrrStatus` and the topology gauges); tearing the peer down
/// clears the registry and empties the cached state again.
#[tokio::test]
async fn peer_up_registers_orr_vantage_and_teardown_clears() {
    let metrics = BgpMetrics::new();
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, metrics.clone());
    let handle = tokio::spawn(manager.run());

    let feed = Ipv4Addr::new(10, 9, 9, 9);
    feed_square_topology(&tx, feed).await;

    // Before any vantage: the cache is intentionally empty.
    let status = query_orr_status(&tx).await;
    assert!(status.vantages.is_empty());
    assert_eq!(status.topology_nodes, 0);

    let client = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let _out_rx = orr_client_peer_up(&tx, client, Some(vantage_at_node_a())).await;

    let status = query_orr_status(&tx).await;
    assert_eq!(status.vantages.len(), 1);
    assert_eq!(status.vantages[0].vantage, vantage_at_node_a());
    assert!(status.vantages[0].resolved);
    assert_eq!(status.vantages[0].peers, vec![client]);
    assert_eq!(status.topology_nodes, 4);
    assert_eq!(status.topology_links, 4);
    assert_eq!(status.input_diagnostics.included_default, 4);
    assert_eq!(status.input_diagnostics.excluded_nondefault, 0);
    assert!(
        (gauge_metric_value(&metrics, "bgp_orr_topology_nodes", &[]) - 4.0).abs() < f64::EPSILON
    );
    let input_family = metrics
        .registry()
        .gather()
        .into_iter()
        .find(|family| family.name() == "bgp_orr_input_objects")
        .expect("ORR input diagnostic metric registered");
    let classifications: std::collections::BTreeSet<_> = input_family
        .metric
        .iter()
        .map(|metric| {
            assert_eq!(metric.get_label().len(), 1, "only classification label");
            assert_eq!(metric.get_label()[0].name(), "classification");
            metric.get_label()[0].value().to_owned()
        })
        .collect();
    assert_eq!(
        classifications,
        [
            "default_with_ignored_flex_algo",
            "excluded_nondefault",
            "included_default",
            "malformed_attribute_29",
            "malformed_topology",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect()
    );
    assert!(
        (gauge_metric_value(
            &metrics,
            "bgp_orr_input_objects",
            &[("classification", "included_default")],
        ) - 4.0)
            .abs()
            < f64::EPSILON
    );

    tx.send(RibUpdate::PeerDown {
        peer: client,
        session_id: 0,
    })
    .await
    .unwrap();

    let status = query_orr_status(&tx).await;
    assert!(
        status.vantages.is_empty(),
        "teardown clears the vantage registry"
    );
    assert_eq!(status.topology_nodes, 0, "cached state emptied");
    assert_eq!(
        status.input_diagnostics,
        crate::orr::OrrInputDiagnostics::default()
    );
    assert!(gauge_metric_value(&metrics, "bgp_orr_topology_nodes", &[]).abs() < f64::EPSILON);
    for classification in classifications {
        assert!(
            gauge_metric_value(
                &metrics,
                "bgp_orr_input_objects",
                &[("classification", classification.as_str())],
            )
            .abs()
                < f64::EPSILON,
            "{classification} resets when the last vantage is removed"
        );
    }

    drop(tx);
    handle.await.unwrap();
}

/// `QueryOrrStatus` reports a resolved vantage (with node descriptors +
/// SPF reach) and an unresolved one (no node, zero reach) side by side,
/// sorted by vantage IP, with the unresolved gauge tracking.
#[tokio::test]
async fn orr_status_reports_resolved_and_unresolved_vantages() {
    use crate::orr::fixtures::A;

    let metrics = BgpMetrics::new();
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, metrics.clone());
    let handle = tokio::spawn(manager.run());

    feed_square_topology(&tx, Ipv4Addr::new(10, 9, 9, 9)).await;

    let client1 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let client2 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
    let outside = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9));
    let _out1 = orr_client_peer_up(&tx, client1, Some(vantage_at_node_a())).await;
    let _out2 = orr_client_peer_up(&tx, client2, Some(outside)).await;

    let status = query_orr_status(&tx).await;
    assert_eq!(status.vantages.len(), 2);
    // Sorted by vantage IP: 10.0.1.3 < 203.0.113.9.
    let resolved = &status.vantages[0];
    assert_eq!(resolved.vantage, vantage_at_node_a());
    assert!(resolved.resolved);
    assert!(!resolved.node_key_hex.is_empty());
    assert_eq!(resolved.asn, Some(64512));
    assert_eq!(resolved.router_id_hex, format!("00000000000{A:x}"));
    // From A the square reaches A, X, and Y — never B.
    assert_eq!(resolved.reachable_nodes, 3);
    assert_eq!(resolved.peers, vec![client1]);

    let unresolved = &status.vantages[1];
    assert_eq!(unresolved.vantage, outside);
    assert!(!unresolved.resolved);
    assert!(unresolved.node_key_hex.is_empty());
    assert_eq!(unresolved.reachable_nodes, 0);
    assert_eq!(unresolved.peers, vec![client2]);

    assert!(
        (gauge_metric_value(&metrics, "bgp_orr_unresolved_vantages", &[]) - 1.0).abs()
            < f64::EPSILON
    );

    drop(tx);
    handle.await.unwrap();
}

/// The cached SPF state rebuilds at the BGP-LS mutation seams — and the GR
/// stale window deliberately does NOT count as a mutation for the topology:
/// a vantage registered before any topology is unresolved, resolves when
/// BGP-LS routes arrive through the receive path, STAYS resolved while the
/// feed peer's routes are GR-preserved as stale (the ORR-stability
/// motivation — `iter_bgpls` keeps feeding stale entries to the topology),
/// and unresolves only when the GR timer expiry finally sweeps them.
#[tokio::test]
async fn bgpls_gr_stale_topology_keeps_orr_vantages_resolved() {
    tokio::time::pause();

    let metrics = BgpMetrics::new();
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, metrics.clone());
    let handle = tokio::spawn(manager.run());

    let client = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let _out_rx = orr_client_peer_up(&tx, client, Some(vantage_at_node_a())).await;

    let status = query_orr_status(&tx).await;
    assert!(!status.vantages[0].resolved, "no topology yet");

    let feed = Ipv4Addr::new(10, 9, 9, 9);
    feed_square_topology(&tx, feed).await;

    let status = query_orr_status(&tx).await;
    assert!(
        status.vantages[0].resolved,
        "receive path rebuilt the cache"
    );
    assert_eq!(status.topology_nodes, 4);
    let runs_after_receive = counter_metric_value(&metrics, "bgp_orr_spf_runs_total");
    assert!(runs_after_receive >= 1.0, "SPF ran for the vantage");

    // GR entry with (BgpLs, BgpLs) in the capability preserves the feed
    // peer's routes as stale — the topology, and the vantage, must survive.
    tx.send(RibUpdate::PeerGracefulRestart {
        session_id: 0,
        peer: IpAddr::V4(feed),
        restart_time: 2,
        stale_routes_time: 5,
        gr_families: vec![(Afi::BgpLs, Safi::BgpLs)],
        peer_llgr_capable: false,
        peer_llgr_families: vec![],
        llgr_stale_time: 0,
    })
    .await
    .unwrap();

    let status = query_orr_status(&tx).await;
    assert!(
        status.vantages[0].resolved,
        "GR-stale BGP-LS routes must keep feeding the topology"
    );
    assert_eq!(status.topology_nodes, 4);

    // GR timer expiry sweeps the stale routes — NOW the vantage unresolves.
    tokio::time::advance(Duration::from_secs(3)).await;
    tokio::task::yield_now().await;

    let status = query_orr_status(&tx).await;
    assert!(
        !status.vantages[0].resolved,
        "GR expiry sweep rebuilt the cache against the emptied topology"
    );
    assert_eq!(status.topology_nodes, 0);

    drop(tx);
    handle.await.unwrap();
}

/// The early-out pin: with no vantage configured, BGP-LS churn (and even
/// an RR client without a vantage) never triggers a topology rebuild or
/// an SPF run — the `bgp_orr_spf_runs_total` counter stays at zero and
/// the topology gauges stay untouched.
#[tokio::test]
async fn no_vantage_configured_skips_topology_rebuild() {
    let metrics = BgpMetrics::new();
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, metrics.clone());
    let handle = tokio::spawn(manager.run());

    let client = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let _out_rx = orr_client_peer_up(&tx, client, None).await;

    // BGP-LS churn: announce, re-announce, withdraw.
    let feed = Ipv4Addr::new(10, 9, 9, 9);
    feed_square_topology(&tx, feed).await;
    feed_square_topology(&tx, feed).await;
    let keys: Vec<_> = crate::orr::fixtures::square_topology(feed)
        .iter()
        .map(crate::route::BgpLsRibRoute::key)
        .collect();
    tx.send(RibUpdate::BgpLsRoutesReceived {
        session_id: 0,
        peer: IpAddr::V4(feed),
        announced: vec![],
        withdrawn: keys,
    })
    .await
    .unwrap();

    // Sync point so all churn above has been processed.
    let status = query_orr_status(&tx).await;
    assert!(status.vantages.is_empty());
    assert!(
        counter_metric_value(&metrics, "bgp_orr_spf_runs_total").abs() < f64::EPSILON,
        "no SPF may run without a configured vantage"
    );
    assert!(gauge_metric_value(&metrics, "bgp_orr_topology_nodes", &[]).abs() < f64::EPSILON);

    drop(tx);
    handle.await.unwrap();
}

/// LAN-189 sub-item 2: a BGP-LS batch that changes nothing (a withdraw of
/// a key not held) must not rebuild the topology or re-run SPF — the
/// `bgp_orr_spf_runs_total` counter stays put even with a resolved vantage
/// configured.
#[tokio::test]
async fn empty_bgpls_batch_skips_orr_recompute() {
    let metrics = BgpMetrics::new();
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, metrics.clone());
    let handle = tokio::spawn(manager.run());

    // Resolve a vantage against the square topology (initial SPF run).
    let feed = Ipv4Addr::new(10, 9, 9, 9);
    feed_square_topology(&tx, feed).await;
    let client = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let _out_rx = orr_client_peer_up(&tx, client, Some(vantage_at_node_a())).await;
    let status = query_orr_status(&tx).await;
    assert!(status.vantages[0].resolved, "vantage must resolve");
    let runs_before = counter_metric_value(&metrics, "bgp_orr_spf_runs_total");
    assert!(runs_before >= 1.0, "initial SPF ran");

    // No-op batch: withdraw a real key from a peer that holds nothing, so
    // the affected set stays empty.
    let unheld_key = crate::orr::fixtures::square_topology(feed)
        .first()
        .expect("fixture has routes")
        .key();
    tx.send(RibUpdate::BgpLsRoutesReceived {
        session_id: 0,
        peer: IpAddr::V4(Ipv4Addr::new(10, 8, 8, 8)),
        announced: vec![],
        withdrawn: vec![unheld_key],
    })
    .await
    .unwrap();
    // Sync point so the no-op batch is fully processed.
    let _ = query_orr_status(&tx).await;
    assert!(
        (counter_metric_value(&metrics, "bgp_orr_spf_runs_total") - runs_before).abs()
            < f64::EPSILON,
        "an empty BGP-LS batch must not re-run ORR SPF"
    );

    drop(tx);
    handle.await.unwrap();
}

/// Collect the unicast staging stream (announce prefixes + withdraws per
/// update) an RR client sees for a fixed scenario, with or without an
/// ORR vantage configured on it.
async fn unicast_stream_with_vantage(vantage: Option<IpAddr>) -> Vec<(Vec<String>, Vec<String>)> {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    // The BGP-LS topology is present in BOTH runs; the vantage config is
    // the only variable.
    feed_square_topology(&tx, Ipv4Addr::new(10, 9, 9, 9)).await;

    let client = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let mut out_rx = orr_client_peer_up(&tx, client, vantage).await;

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let prefix1 = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
    let prefix2 = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 2, 0), 24);
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![
            make_route(prefix1, Ipv4Addr::new(10, 0, 0, 1)),
            make_route(prefix2, Ipv4Addr::new(10, 0, 0, 1)),
        ],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();
    // Sync point between the batches: without it the manager may
    // coalesce them (distribute-coalesce), making the CHUNKING of the
    // staged stream timing-dependent — this test compares two runs and
    // needs both paced identically.
    let _ = query_best_routes(&tx).await;
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![],
        withdrawn: vec![(Prefix::V4(prefix1), 0)],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    // Sync point: both batches processed and distributed.
    let _ = query_best_routes(&tx).await;
    drop(tx);
    handle.await.unwrap();

    let mut stream = Vec::new();
    while let Ok(update) = out_rx.try_recv() {
        // Order WITHIN one staged update is HashSet-iteration incidental;
        // sort so the comparison pins semantics, not hasher state.
        let mut announce: Vec<String> = update
            .announce
            .iter()
            .map(|r| r.prefix.to_string())
            .collect();
        announce.sort();
        let mut withdraw: Vec<String> =
            update.withdraw.iter().map(|(p, _)| p.to_string()).collect();
        withdraw.sort();
        stream.push((announce, withdraw));
    }
    stream
}

/// Distribution-switch pin: this scenario's next-hop lies OUTSIDE the
/// BGP-LS topology (unknown vantage cost) and each prefix has a single
/// candidate, so the per-vantage ORR path must stage output identical
/// to the standard path — a configured vantage may never perturb what
/// it cannot rank. (Originally the pre-switch "zero effect" guardrail;
/// still load-bearing as the unknown-cost/no-divergence pin.)
#[tokio::test]
async fn staged_output_identical_with_and_without_vantages() {
    let without = unicast_stream_with_vantage(None).await;
    let with = unicast_stream_with_vantage(Some(vantage_at_node_a())).await;
    assert!(
        !without.is_empty(),
        "scenario must actually stage unicast output"
    );
    assert_eq!(
        without, with,
        "a configured vantage must not change the staged unicast stream"
    );
}

// --- RFC 9107 ORR per-vantage best selection ---

/// Feed peer for the square topology (never registered for outbound).
const ORR_FEED: Ipv4Addr = Ipv4Addr::new(10, 9, 9, 9);
/// iBGP source announcing via NH-X — lower peer address, so its route
/// is the standard Loc-RIB best when everything else ties.
const ORR_SRC_X: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
/// iBGP source announcing via NH-Y.
const ORR_SRC_Y: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 2);

/// Neighbor address of the A→X link — resolves to node X
/// (interior cost 1 from vantage A, 10 from vantage B).
fn orr_nh_x() -> IpAddr {
    use crate::orr::fixtures::{A, X};
    IpAddr::V4(Ipv4Addr::new(10, 0, X, A))
}

/// Neighbor address of the A→Y link — resolves to node Y
/// (interior cost 10 from vantage A, 1 from vantage B).
fn orr_nh_y() -> IpAddr {
    use crate::orr::fixtures::{A, Y};
    IpAddr::V4(Ipv4Addr::new(10, 0, Y, A))
}

/// Interface address of the B→X link (`10.0.B.X`) — resolves to B.
fn vantage_at_node_b() -> IpAddr {
    use crate::orr::fixtures::{B, X};
    IpAddr::V4(Ipv4Addr::new(10, 0, B, X))
}

/// The contested prefix of the divergence scenario.
fn orr_prefix() -> Ipv4Prefix {
    Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 0), 24)
}

/// Adj-RIB-Out map key of the scenario prefix as a single best.
fn orr_prefix_key() -> (Prefix, u32) {
    (Prefix::V4(orr_prefix()), 0)
}

/// An iBGP-learned route for `prefix` from `peer` with the given
/// next-hop. Attributes are identical across sources so only the ORR
/// interior-cost step and the final peer-address tiebreak can decide.
fn ibgp_route(prefix: Ipv4Prefix, peer: Ipv4Addr, next_hop: IpAddr) -> Route {
    Route {
        prefix: Prefix::V4(prefix),
        next_hop,
        link_local_next_hop: None,
        next_hop_scope: None,
        peer: IpAddr::V4(peer),
        attributes: Arc::new(vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::LocalPref(100),
        ]),
        received_at: Instant::now(),
        origin_type: crate::route::RouteOrigin::Ibgp,
        peer_router_id: peer,
        is_stale: false,
        is_llgr_stale: false,
        path_id: 0,
        validation_state: RpkiValidation::NotFound,
        aspa_state: rustbgpd_wire::AspaValidation::Unknown,
        aspa_context: rustbgpd_wire::AspaValidationContext::default(),
    }
}

/// An RR-mode manager (cluster id set, so iBGP-learned routes reflect
/// to clients) with the square topology already fed from `ORR_FEED`.
async fn orr_rr_manager() -> (mpsc::Sender<RibUpdate>, tokio::task::JoinHandle<()>) {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(
        rx,
        dummy_query_rx(),
        None,
        Some(Ipv4Addr::new(10, 255, 0, 1)),
        BgpMetrics::new(),
    );
    let handle = tokio::spawn(manager.run());
    feed_square_topology(&tx, ORR_FEED).await;
    (tx, handle)
}

/// Announce unicast routes from `peer` (unregistered sources pass the
/// stale-session gate with session id 0).
async fn announce_unicast(tx: &mpsc::Sender<RibUpdate>, peer: Ipv4Addr, announced: Vec<Route>) {
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: IpAddr::V4(peer),
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

/// The arc's divergence scenario: the SAME prefix from two iBGP sources
/// with next-hops at node X and node Y, followed by a sync point so both
/// batches are recomputed and distributed.
async fn announce_divergent_bests(tx: &mpsc::Sender<RibUpdate>) {
    announce_unicast(
        tx,
        ORR_SRC_X,
        vec![ibgp_route(orr_prefix(), ORR_SRC_X, orr_nh_x())],
    )
    .await;
    announce_unicast(
        tx,
        ORR_SRC_Y,
        vec![ibgp_route(orr_prefix(), ORR_SRC_Y, orr_nh_y())],
    )
    .await;
    let _ = query_best_routes(tx).await;
}

/// Drain every queued outbound update and fold to the final advertised
/// unicast state: `(prefix, path_id)` → the last announced route.
fn drain_final_unicast(
    rx: &mut mpsc::Receiver<OutboundRouteUpdate>,
) -> HashMap<(Prefix, u32), Route> {
    let mut state = HashMap::new();
    while let Ok(update) = rx.try_recv() {
        for route in update.announce.iter() {
            state.insert((route.prefix, route.path_id), route.clone());
        }
        for (prefix, path_id) in &update.withdraw {
            state.remove(&(*prefix, *path_id));
        }
    }
    state
}

/// THE arc's signature behavior: two RR clients bound to different
/// vantages receive DIVERGENT bests for the same prefix — each exits
/// via the next-hop closest to its own IGP location, not the RR's.
#[tokio::test]
async fn two_clients_different_vantages_receive_divergent_bests() {
    let (tx, handle) = orr_rr_manager().await;
    let client_a = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let client_b = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
    let mut out_a = orr_client_peer_up(&tx, client_a, Some(vantage_at_node_a())).await;
    let mut out_b = orr_client_peer_up(&tx, client_b, Some(vantage_at_node_b())).await;

    announce_divergent_bests(&tx).await;
    drop(tx);
    handle.await.unwrap();

    let final_a = drain_final_unicast(&mut out_a);
    let final_b = drain_final_unicast(&mut out_b);
    assert_eq!(
        final_a.get(&orr_prefix_key()).map(|r| r.next_hop),
        Some(orr_nh_x()),
        "client at A exits via X (cost 1 < 10)"
    );
    assert_eq!(
        final_b.get(&orr_prefix_key()).map(|r| r.next_hop),
        Some(orr_nh_y()),
        "client at B exits via Y (cost 1 < 10)"
    );
}

/// A topology metric flip re-stages ONLY the peers bound to the vantage
/// whose SPF surface changed: the affected client's best flips, while
/// the other vantage's client and a non-ORR client see zero messages.
#[tokio::test]
async fn topology_metric_flip_marks_only_affected_vantage_peers_dirty_and_flips_best() {
    use crate::orr::fixtures::{A, X, link_route, v4_interface, v4_neighbor};

    let (tx, handle) = orr_rr_manager().await;
    let client_a = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let client_b = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
    let client_c = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 4));
    let mut out_a = orr_client_peer_up(&tx, client_a, Some(vantage_at_node_a())).await;
    let mut out_b = orr_client_peer_up(&tx, client_b, Some(vantage_at_node_b())).await;
    let mut out_c = orr_client_peer_up(&tx, client_c, None).await;

    announce_divergent_bests(&tx).await;
    // Steady state reached — empty every channel before the flip.
    let _ = drain_final_unicast(&mut out_a);
    let _ = drain_final_unicast(&mut out_b);
    let _ = drain_final_unicast(&mut out_c);

    // Flip A→X to metric 100 (the SAME Link NLRI — identical descriptors
    // — so the entry is replaced, not duplicated). From A the SPF now
    // prefers Y (10 < 100); distances from B are untouched.
    tx.send(RibUpdate::BgpLsRoutesReceived {
        session_id: 0,
        peer: IpAddr::V4(ORR_FEED),
        announced: vec![link_route(
            ORR_FEED,
            A,
            X,
            Some(100),
            &[
                v4_interface(Ipv4Addr::new(10, 0, A, X)),
                v4_neighbor(Ipv4Addr::new(10, 0, X, A)),
            ],
        )],
        withdrawn: vec![],
    })
    .await
    .unwrap();
    let _ = query_best_routes(&tx).await;
    drop(tx);
    handle.await.unwrap();

    let final_a = drain_final_unicast(&mut out_a);
    assert_eq!(
        final_a.get(&orr_prefix_key()).map(|r| r.next_hop),
        Some(orr_nh_y()),
        "affected client flips to Y (cost 10 < 100)"
    );
    assert!(
        out_b.try_recv().is_err(),
        "unaffected vantage's client must see zero messages"
    );
    assert!(
        out_c.try_recv().is_err(),
        "non-ORR client must see zero messages"
    );
}

/// A non-default topology object is observable but cannot perturb the
/// cached default graph, SPF signatures, or any client's advertised state.
#[tokio::test]
async fn excluded_topology_mutation_does_not_dirty_or_stage_outbound() {
    use crate::orr::fixtures::{A, X, link_route, mt_id_tlv, v4_interface, v4_neighbor};

    let (tx, handle) = orr_rr_manager().await;
    let client_a = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let client_b = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
    let client_c = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 4));
    let mut out_a = orr_client_peer_up(&tx, client_a, Some(vantage_at_node_a())).await;
    let mut out_b = orr_client_peer_up(&tx, client_b, Some(vantage_at_node_b())).await;
    let mut out_c = orr_client_peer_up(&tx, client_c, None).await;

    announce_divergent_bests(&tx).await;
    let _ = drain_final_unicast(&mut out_a);
    let _ = drain_final_unicast(&mut out_b);
    let _ = drain_final_unicast(&mut out_c);

    tx.send(RibUpdate::BgpLsRoutesReceived {
        session_id: 0,
        peer: IpAddr::V4(ORR_FEED),
        announced: vec![link_route(
            ORR_FEED,
            A,
            X,
            Some(0),
            &[
                v4_interface(Ipv4Addr::new(10, 0, A, X)),
                v4_neighbor(Ipv4Addr::new(10, 0, X, A)),
                mt_id_tlv(&[2]),
            ],
        )],
        withdrawn: vec![],
    })
    .await
    .unwrap();
    let status = query_orr_status(&tx).await;
    assert_eq!(status.topology_nodes, 4);
    assert_eq!(status.topology_links, 4);
    assert_eq!(status.input_diagnostics.included_default, 4);
    assert_eq!(status.input_diagnostics.excluded_nondefault, 1);

    drop(tx);
    handle.await.unwrap();
    assert!(out_a.try_recv().is_err(), "vantage A must not be restaged");
    assert!(out_b.try_recv().is_err(), "vantage B must not be restaged");
    assert!(
        out_c.try_recv().is_err(),
        "plain client must not be restaged"
    );
}

/// A vantage that does not resolve to a topology node silently falls
/// back to the standard single-best: the ORR client's advertisement is
/// identical to a vantage-less peer's.
#[tokio::test]
async fn unresolved_vantage_falls_back_to_loc_rib_best() {
    let (tx, handle) = orr_rr_manager().await;
    let orr_client = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let plain_client = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
    let outside = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9));
    let mut out_orr = orr_client_peer_up(&tx, orr_client, Some(outside)).await;
    let mut out_plain = orr_client_peer_up(&tx, plain_client, None).await;

    announce_divergent_bests(&tx).await;
    drop(tx);
    handle.await.unwrap();

    let final_orr = drain_final_unicast(&mut out_orr);
    let final_plain = drain_final_unicast(&mut out_plain);
    let unresolved = final_orr
        .get(&orr_prefix_key())
        .expect("unresolved-vantage client is advertised the prefix");
    let plain = final_plain
        .get(&orr_prefix_key())
        .expect("vantage-less client is advertised the prefix");
    assert_eq!(unresolved.next_hop, orr_nh_x(), "the Loc-RIB best");
    assert_eq!(unresolved.next_hop, plain.next_hop);
    assert_eq!(unresolved.attributes, plain.attributes);
    assert_eq!(unresolved.peer, plain.peer);
    assert_eq!(unresolved.path_id, plain.path_id);
}

/// Withdrawing every BGP-LS link unresolves all vantages: ORR clients
/// revert to the standard best. The client whose vantage best already
/// matched it sees zero messages (equality suppression).
#[tokio::test]
async fn bgpls_withdrawal_of_all_links_reverts_orr_peers_to_standard_best() {
    let (tx, handle) = orr_rr_manager().await;
    let client_a = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let client_b = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
    let mut out_a = orr_client_peer_up(&tx, client_a, Some(vantage_at_node_a())).await;
    let mut out_b = orr_client_peer_up(&tx, client_b, Some(vantage_at_node_b())).await;

    announce_divergent_bests(&tx).await;
    let _ = drain_final_unicast(&mut out_a);
    let _ = drain_final_unicast(&mut out_b);

    let keys: Vec<BgpLsRouteKey> = crate::orr::fixtures::square_topology(ORR_FEED)
        .iter()
        .map(BgpLsRibRoute::key)
        .collect();
    tx.send(RibUpdate::BgpLsRoutesReceived {
        session_id: 0,
        peer: IpAddr::V4(ORR_FEED),
        announced: vec![],
        withdrawn: keys,
    })
    .await
    .unwrap();
    let _ = query_best_routes(&tx).await;
    drop(tx);
    handle.await.unwrap();

    let final_b = drain_final_unicast(&mut out_b);
    assert_eq!(
        final_b.get(&orr_prefix_key()).map(|r| r.next_hop),
        Some(orr_nh_x()),
        "client at B reverts from NH-Y to the standard best NH-X"
    );
    assert!(
        out_a.try_recv().is_err(),
        "client at A already held the standard best — zero messages"
    );
}

/// A client that establishes AFTER the routes and topology are in place
/// gets its per-vantage best in the initial table dump.
#[tokio::test]
async fn orr_client_initial_dump_gets_vantage_best() {
    let (tx, handle) = orr_rr_manager().await;
    announce_divergent_bests(&tx).await;

    let client_b = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
    let (out_tx, mut out_b) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        per_client_best: false,
        session_id: 0,
        peer: client_b,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: false,
        route_reflector_client: true,
        orr_vantage: Some(vantage_at_node_b()),
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: Vec::new(),
        negotiated_llgr_families: Vec::new(),
    })
    .await
    .unwrap();
    let _ = query_best_routes(&tx).await;
    drop(tx);
    handle.await.unwrap();

    let final_b = drain_final_unicast(&mut out_b);
    assert_eq!(
        final_b.get(&orr_prefix_key()).map(|r| r.next_hop),
        Some(orr_nh_y()),
        "initial dump carries the vantage best, not the Loc-RIB best"
    );
}

/// A ROUTE-REFRESH replay re-derives the same per-vantage best the live
/// distribution path sent.
#[tokio::test]
async fn route_refresh_replays_vantage_best() {
    let (tx, handle) = orr_rr_manager().await;
    let client_b = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
    let mut out_b = orr_client_peer_up(&tx, client_b, Some(vantage_at_node_b())).await;

    announce_divergent_bests(&tx).await;
    let _ = drain_final_unicast(&mut out_b);

    tx.send(RibUpdate::RouteRefreshRequest {
        peer: client_b,
        session_id: 0,
        afi: Afi::Ipv4,
        safi: Safi::Unicast,
    })
    .await
    .unwrap();
    let _ = query_best_routes(&tx).await;
    drop(tx);
    handle.await.unwrap();

    let final_b = drain_final_unicast(&mut out_b);
    let replayed = final_b
        .get(&orr_prefix_key())
        .expect("refresh replays the prefix (empty refresh view forces a re-emit)");
    assert_eq!(
        replayed.next_hop,
        orr_nh_y(),
        "the replay is the vantage best"
    );
}

/// `ExplainAdvertisedRoute` for an ORR-bound peer surfaces the vantage,
/// every candidate with its interior cost (ranked per-vantage best
/// first, unknown-cost last per RFC 9107 §3.1), and the decisive
/// interior-cost reason with the compared costs.
#[tokio::test]
async fn explain_advertised_route_reports_orr_vantage_and_costs() {
    use crate::orr::fixtures::{A, X, link_route, mt_id_tlv};

    let (tx, handle) = orr_rr_manager().await;
    let client_b = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
    let _out_b = orr_client_peer_up(&tx, client_b, Some(vantage_at_node_b())).await;

    announce_divergent_bests(&tx).await;
    // A third source whose next-hop resolves nowhere in the topology —
    // unknown cost, must rank least preferred.
    let src_unknown = Ipv4Addr::new(192, 0, 2, 3);
    let nh_unknown = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 99));
    announce_unicast(
        &tx,
        src_unknown,
        vec![ibgp_route(orr_prefix(), src_unknown, nh_unknown)],
    )
    .await;
    tx.send(RibUpdate::BgpLsRoutesReceived {
        session_id: 0,
        peer: IpAddr::V4(ORR_FEED),
        announced: vec![link_route(ORR_FEED, A, X, Some(0), &[mt_id_tlv(&[2])])],
        withdrawn: vec![],
    })
    .await
    .unwrap();

    let explain = query_explain_advertised_route(&tx, client_b, Prefix::V4(orr_prefix())).await;
    assert_eq!(explain.decision, crate::update::ExplainDecision::Advertise);
    assert_eq!(
        explain.next_hop,
        Some(orr_nh_y()),
        "vantage B's best exits via Y, not the Loc-RIB best via X"
    );
    assert_eq!(explain.orr_vantage, Some(vantage_at_node_b()));

    let candidates = &explain.orr_candidates;
    assert_eq!(candidates.len(), 3, "all surviving candidates listed");
    assert_eq!(candidates[0].next_hop, orr_nh_y());
    assert_eq!(candidates[0].cost, Some(1));
    assert!(candidates[0].selected);
    assert_eq!(candidates[1].next_hop, orr_nh_x());
    assert_eq!(candidates[1].cost, Some(10));
    assert!(!candidates[1].selected);
    assert_eq!(
        candidates[2].next_hop, nh_unknown,
        "unknown-cost candidate ranks last (RFC 9107 §3.1)"
    );
    assert_eq!(candidates[2].cost, None);
    assert!(!candidates[2].selected);

    let orr_reason = explain
        .reasons
        .iter()
        .find(|reason| reason.code == "orr_interior_cost")
        .expect("interior-cost step decided the winner");
    assert!(
        orr_reason.message.contains("orr_cost 1 < 10"),
        "compared vantage costs rendered: {}",
        orr_reason.message
    );
    let diagnostic_reason = explain
        .reasons
        .iter()
        .find(|reason| reason.code == "orr_topology_input_diagnostics")
        .expect("aggregate filtered-input diagnostics are explained");
    assert!(diagnostic_reason.message.contains("aggregate non-decisive"));
    assert!(
        diagnostic_reason
            .message
            .contains("winner and decisive cost are unchanged")
    );
    assert!(diagnostic_reason.message.contains("excluded_nondefault=1"));
    assert_eq!(
        explain
            .reasons
            .iter()
            .filter(|reason| reason.code == "orr_interior_cost")
            .count(),
        1,
        "the aggregate diagnostic does not replace the decisive cost reason"
    );

    drop(tx);
    handle.await.unwrap();
}

/// Regression: a peer with NO ORR vantage gets the pre-ORR explain
/// shape in the same scenario — Loc-RIB best, no vantage, no candidate
/// list, no ORR reason codes.
#[tokio::test]
async fn explain_advertised_route_non_orr_peer_unchanged() {
    let (tx, handle) = orr_rr_manager().await;
    let plain_client = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5));
    let _out = orr_client_peer_up(&tx, plain_client, None).await;

    announce_divergent_bests(&tx).await;

    let explain = query_explain_advertised_route(&tx, plain_client, Prefix::V4(orr_prefix())).await;
    assert_eq!(explain.decision, crate::update::ExplainDecision::Advertise);
    assert_eq!(
        explain.next_hop,
        Some(orr_nh_x()),
        "non-ORR peer explains the Loc-RIB best"
    );
    assert_eq!(explain.orr_vantage, None);
    assert!(explain.orr_candidates.is_empty());
    assert!(
        explain
            .reasons
            .iter()
            .all(|reason| !reason.code.starts_with("orr")),
        "no ORR reasons on a non-ORR explain"
    );

    drop(tx);
    handle.await.unwrap();
}

/// An ORR peer whose vantage-visible candidate set is empty (the only
/// path came from the peer itself) explains as no-candidate instead of
/// leaking the split-horizon-suppressed route.
#[tokio::test]
async fn explain_advertised_route_orr_no_surviving_candidate() {
    let (tx, handle) = orr_rr_manager().await;
    let client_b = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
    let client_b_v4 = Ipv4Addr::new(10, 0, 0, 3);
    let _out_b = orr_client_peer_up(&tx, client_b, Some(vantage_at_node_b())).await;

    // The only path is client B's own announcement.
    announce_unicast(
        &tx,
        client_b_v4,
        vec![ibgp_route(orr_prefix(), client_b_v4, orr_nh_x())],
    )
    .await;

    let explain = query_explain_advertised_route(&tx, client_b, Prefix::V4(orr_prefix())).await;
    assert_eq!(
        explain.decision,
        crate::update::ExplainDecision::NoBestRoute
    );
    assert_eq!(explain.orr_vantage, Some(vantage_at_node_b()));
    assert!(explain.orr_candidates.is_empty());
    assert_eq!(explain.reasons[0].code, "no_orr_candidate");

    drop(tx);
    handle.await.unwrap();
}

/// Split horizon and RFC 4456 reflection suppression run BEFORE the ORR
/// ranking: a cost-0 candidate the target must not receive can never
/// win.
#[tokio::test]
async fn split_horizon_and_rr_suppression_apply_before_orr_ranking() {
    let (tx, handle) = orr_rr_manager().await;
    let client_b = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
    let client_b_v4 = Ipv4Addr::new(10, 0, 0, 3);
    let mut out_b = orr_client_peer_up(&tx, client_b, Some(vantage_at_node_b())).await;

    // A non-client iBGP peer bound to the same vantage. (Config
    // validation rejects orr_vantage without rr-client; the RIB layer
    // trusts PeerUp, and the suppression seam must hold regardless.)
    let peer_d = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 4));
    let (out_tx_d, mut out_d) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        per_client_best: false,
        session_id: 0,
        peer: peer_d,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx_d,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: false,
        route_reflector_client: false,
        orr_vantage: Some(vantage_at_node_b()),
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: Vec::new(),
        negotiated_llgr_families: Vec::new(),
    })
    .await
    .unwrap();
    drain_eor(&mut out_d).await;

    // prefix1 — split-horizon probe: client B's OWN route has interior
    // cost 0 (next-hop at its vantage node); a non-client source offers
    // cost 10 via NH-X.
    let prefix1 = orr_prefix();
    announce_unicast(
        &tx,
        client_b_v4,
        vec![ibgp_route(prefix1, client_b_v4, vantage_at_node_b())],
    )
    .await;
    announce_unicast(
        &tx,
        ORR_SRC_X,
        vec![ibgp_route(prefix1, ORR_SRC_X, orr_nh_x())],
    )
    .await;

    // prefix2 — RR-suppression probe: the cost-0 candidate comes from a
    // NON-client (never reflectable to the non-client target D); client
    // B offers cost 10 via NH-X (client routes reflect to everyone).
    let prefix2 = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 101, 0), 24);
    announce_unicast(
        &tx,
        ORR_SRC_Y,
        vec![ibgp_route(prefix2, ORR_SRC_Y, vantage_at_node_b())],
    )
    .await;
    announce_unicast(
        &tx,
        client_b_v4,
        vec![ibgp_route(prefix2, client_b_v4, orr_nh_x())],
    )
    .await;

    let _ = query_best_routes(&tx).await;
    drop(tx);
    handle.await.unwrap();

    let final_b = drain_final_unicast(&mut out_b);
    assert_eq!(
        final_b.get(&(Prefix::V4(prefix1), 0)).map(|r| r.next_hop),
        Some(orr_nh_x()),
        "the target's own cost-0 route is split-horizoned before ranking"
    );
    let final_d = drain_final_unicast(&mut out_d);
    assert_eq!(
        final_d.get(&(Prefix::V4(prefix2), 0)).map(|r| r.next_hop),
        Some(orr_nh_x()),
        "the cost-0 non-client candidate is RR-suppressed before ranking"
    );
}

/// Add-Path send to an ORR peer ranks the advertised paths by the
/// vantage's interior cost (comparator swap in the multipath sort):
/// path id 1 is the vantage-closest exit, not the standard-chain
/// winner.
#[tokio::test]
async fn orr_with_addpath_send_ranks_by_vantage_cost() {
    let (tx, handle) = orr_rr_manager().await;
    let client_b = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
    let (out_tx, mut out_b) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        per_client_best: false,
        session_id: 0,
        peer: client_b,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: false,
        route_reflector_client: true,
        orr_vantage: Some(vantage_at_node_b()),
        add_path_send_families: vec![(Afi::Ipv4, Safi::Unicast)],
        add_path_send_max: 2,
        negotiated_orf_recv: Vec::new(),
        negotiated_llgr_families: Vec::new(),
    })
    .await
    .unwrap();
    drain_eor(&mut out_b).await;

    announce_divergent_bests(&tx).await;
    drop(tx);
    handle.await.unwrap();

    let final_b = drain_final_unicast(&mut out_b);
    // Standard ranking would put NH-X first (lower peer address); from
    // vantage B the costs are Y=1, X=10 — the ORR comparator must rank
    // NH-Y as path 1.
    assert_eq!(
        final_b
            .get(&(Prefix::V4(orr_prefix()), 1))
            .map(|r| r.next_hop),
        Some(orr_nh_y()),
        "rank 1 is the vantage-closest path"
    );
    assert_eq!(
        final_b
            .get(&(Prefix::V4(orr_prefix()), 2))
            .map(|r| r.next_hop),
        Some(orr_nh_x()),
        "rank 2 is the vantage-farther path"
    );
}

/// Sendable families for a VPNv6-only test peer.
fn vpn6_sendable() -> Vec<(Afi, Safi)> {
    vec![(Afi::Ipv6, Safi::MplsVpn)]
}

/// A `VPNv4` route from `peer` with an explicit next-hop (identical
/// attributes across sources so only the ORR interior-cost step and the
/// final peer-address tiebreak can decide).
fn vpn_route_at(peer: Ipv4Addr, next_hop: IpAddr, prefix_octet: u8) -> VpnRibRoute {
    let mut route = make_vpn_rib_route(peer, prefix_octet, 100, 100);
    route.next_hop = next_hop;
    route
}

/// A `VPNv6` route from `peer` with an explicit next-hop.
fn vpn6_route_at(peer: Ipv4Addr, next_hop: IpAddr, segment: u16) -> VpnRibRoute {
    let mut route = make_vpn6_rib_route_with_rts(peer, segment, vec![]);
    route.next_hop = next_hop;
    route
}

/// Bring up an iBGP VPN-capable peer with the given ORR vantage and
/// RR-client flag, draining the initial-table `EoR`.
async fn vpn_orr_peer_up(
    tx: &mpsc::Sender<RibUpdate>,
    peer: IpAddr,
    vantage: Option<IpAddr>,
    sendable_families: Vec<(Afi, Safi)>,
    route_reflector_client: bool,
) -> mpsc::Receiver<OutboundRouteUpdate> {
    let (out_tx, mut out_rx) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        per_client_best: false,
        session_id: 0,
        peer,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families,
        is_ebgp: false,
        route_reflector_client,
        orr_vantage: vantage,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: Vec::new(),
        negotiated_llgr_families: Vec::new(),
    })
    .await
    .unwrap();
    drain_eor(&mut out_rx).await;
    out_rx
}

/// Announce VPN routes from `peer` through the normal receive path.
async fn announce_vpn(tx: &mpsc::Sender<RibUpdate>, peer: Ipv4Addr, announced: Vec<VpnRibRoute>) {
    tx.send(RibUpdate::VpnRoutesReceived {
        session_id: 0,
        peer: IpAddr::V4(peer),
        announced,
        withdrawn: vec![],
    })
    .await
    .unwrap();
}

/// The VPN divergence scenario: the SAME RD+prefix key from two iBGP
/// PEs with next-hops at node X and node Y, followed by a sync point.
/// Returns the contested key.
async fn announce_divergent_vpn_bests(
    tx: &mpsc::Sender<RibUpdate>,
    prefix_octet: u8,
) -> crate::route::VpnRibRouteKey {
    let route_x = vpn_route_at(ORR_SRC_X, orr_nh_x(), prefix_octet);
    let key = route_x.key();
    announce_vpn(tx, ORR_SRC_X, vec![route_x]).await;
    announce_vpn(
        tx,
        ORR_SRC_Y,
        vec![vpn_route_at(ORR_SRC_Y, orr_nh_y(), prefix_octet)],
    )
    .await;
    let _ = query_vpn_routes(tx).await;
    key
}

/// The composed differentiators: two RR clients bound to different
/// vantages receive DIVERGENT VPN bests for the same RD+prefix — each
/// exits via the PE closest to its own IGP location, not the RR's.
#[tokio::test]
async fn two_vpn_clients_different_vantages_receive_divergent_bests() {
    let (tx, handle) = orr_rr_manager().await;
    let client_a = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let client_b = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
    let mut out_a = vpn_orr_peer_up(
        &tx,
        client_a,
        Some(vantage_at_node_a()),
        vpn_sendable(),
        true,
    )
    .await;
    let mut out_b = vpn_orr_peer_up(
        &tx,
        client_b,
        Some(vantage_at_node_b()),
        vpn_sendable(),
        true,
    )
    .await;

    let key = announce_divergent_vpn_bests(&tx, 80).await;
    drop(tx);
    handle.await.unwrap();

    let final_a = drain_final_vpn(&mut out_a);
    let final_b = drain_final_vpn(&mut out_b);
    assert_eq!(
        final_a.get(&key).map(|r| r.next_hop),
        Some(orr_nh_x()),
        "client at A exits via X (cost 1 < 10)"
    );
    assert_eq!(
        final_b.get(&key).map(|r| r.next_hop),
        Some(orr_nh_y()),
        "client at B exits via Y (cost 1 < 10)"
    );
}

/// RFC 9107 + RFC 7911 composed: an ORR client with Add-Path send ranks
/// its staged top-N by the VANTAGE's interior costs — `path_id` 1 is the
/// vantage-closest exit, not the RR-local best.
#[tokio::test]
async fn vpn_orr_addpath_ranking_uses_vantage_costs() {
    let (tx, handle) = orr_rr_manager().await;
    let client_a = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let (out_tx, mut out_a) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        per_client_best: false,
        session_id: 0,
        peer: client_a,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: vpn_sendable(),
        is_ebgp: false,
        route_reflector_client: true,
        orr_vantage: Some(vantage_at_node_a()),
        add_path_send_families: vec![(Afi::Ipv4, Safi::MplsVpn)],
        add_path_send_max: 2,
        negotiated_orf_recv: Vec::new(),
        negotiated_llgr_families: Vec::new(),
    })
    .await
    .unwrap();
    drain_eor(&mut out_a).await;

    // Same RD+prefix via X (cost 1 from vantage A) and Y (cost 10).
    let key = announce_divergent_vpn_bests(&tx, 81).await;
    drop(tx);
    handle.await.unwrap();

    let staged = drain_final_vpn(&mut out_a);
    assert_eq!(staged.len(), 2, "both candidates staged under send_max=2");
    assert_eq!(
        staged
            .get(&crate::route::VpnRibRouteKey {
                nlri_key: key.nlri_key,
                path_id: 1,
            })
            .map(|r| r.next_hop),
        Some(orr_nh_x()),
        "path_id 1 = vantage-closest exit (cost 1 via X)"
    );
    assert_eq!(
        staged
            .get(&crate::route::VpnRibRouteKey {
                nlri_key: key.nlri_key,
                path_id: 2,
            })
            .map(|r| r.next_hop),
        Some(orr_nh_y()),
        "path_id 2 = the farther exit (cost 10 via Y)"
    );
}

/// `VPNv6` divergence — the candidate handling is family-agnostic, so
/// the same scenario over SAFI 128 IPv6 keys diverges identically.
#[tokio::test]
async fn two_vpn6_clients_different_vantages_receive_divergent_bests() {
    let (tx, handle) = orr_rr_manager().await;
    let client_a = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let client_b = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
    let mut out_a = vpn_orr_peer_up(
        &tx,
        client_a,
        Some(vantage_at_node_a()),
        vpn6_sendable(),
        true,
    )
    .await;
    let mut out_b = vpn_orr_peer_up(
        &tx,
        client_b,
        Some(vantage_at_node_b()),
        vpn6_sendable(),
        true,
    )
    .await;

    let route_x = vpn6_route_at(ORR_SRC_X, orr_nh_x(), 0x60);
    let key = route_x.key();
    announce_vpn(&tx, ORR_SRC_X, vec![route_x]).await;
    announce_vpn(
        &tx,
        ORR_SRC_Y,
        vec![vpn6_route_at(ORR_SRC_Y, orr_nh_y(), 0x60)],
    )
    .await;
    let _ = query_vpn_routes(&tx).await;
    drop(tx);
    handle.await.unwrap();

    let final_a = drain_final_vpn(&mut out_a);
    let final_b = drain_final_vpn(&mut out_b);
    assert_eq!(final_a.get(&key).map(|r| r.next_hop), Some(orr_nh_x()));
    assert_eq!(final_b.get(&key).map(|r| r.next_hop), Some(orr_nh_y()));
}

/// A topology metric flip re-stages ONLY the peers bound to the vantage
/// whose SPF surface changed: the affected client's VPN best flips,
/// while the other vantage's client and a non-ORR client see zero
/// messages.
#[tokio::test]
async fn vpn_orr_topology_metric_flip_moves_only_affected_client() {
    use crate::orr::fixtures::{A, X, link_route, v4_interface, v4_neighbor};

    let (tx, handle) = orr_rr_manager().await;
    let client_a = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let client_b = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
    let client_c = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 4));
    let mut out_a = vpn_orr_peer_up(
        &tx,
        client_a,
        Some(vantage_at_node_a()),
        vpn_sendable(),
        true,
    )
    .await;
    let mut out_b = vpn_orr_peer_up(
        &tx,
        client_b,
        Some(vantage_at_node_b()),
        vpn_sendable(),
        true,
    )
    .await;
    let mut out_c = vpn_orr_peer_up(&tx, client_c, None, vpn_sendable(), true).await;

    let key = announce_divergent_vpn_bests(&tx, 81).await;
    // Steady state reached — empty every channel before the flip.
    let _ = drain_final_vpn(&mut out_a);
    let _ = drain_final_vpn(&mut out_b);
    let _ = drain_final_vpn(&mut out_c);

    // Flip A→X to metric 100: from A the SPF now prefers Y (10 < 100).
    tx.send(RibUpdate::BgpLsRoutesReceived {
        session_id: 0,
        peer: IpAddr::V4(ORR_FEED),
        announced: vec![link_route(
            ORR_FEED,
            A,
            X,
            Some(100),
            &[
                v4_interface(Ipv4Addr::new(10, 0, A, X)),
                v4_neighbor(Ipv4Addr::new(10, 0, X, A)),
            ],
        )],
        withdrawn: vec![],
    })
    .await
    .unwrap();
    let _ = query_vpn_routes(&tx).await;
    drop(tx);
    handle.await.unwrap();

    let final_a = drain_final_vpn(&mut out_a);
    assert_eq!(
        final_a.get(&key).map(|r| r.next_hop),
        Some(orr_nh_y()),
        "affected client's VPN best flips to Y (cost 10 < 100)"
    );
    assert!(
        out_b.try_recv().is_err(),
        "unaffected vantage's client must see zero messages"
    );
    assert!(
        out_c.try_recv().is_err(),
        "non-ORR client must see zero messages"
    );
}

/// A vantage that does not resolve to a topology node silently falls
/// back to the standard Loc-RIB best: the ORR client's VPN
/// advertisement is identical to a vantage-less peer's.
#[tokio::test]
async fn vpn_orr_unresolved_vantage_falls_back_to_loc_rib_best() {
    let (tx, handle) = orr_rr_manager().await;
    let orr_client = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let plain_client = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
    let outside = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9));
    let mut out_orr = vpn_orr_peer_up(&tx, orr_client, Some(outside), vpn_sendable(), true).await;
    let mut out_plain = vpn_orr_peer_up(&tx, plain_client, None, vpn_sendable(), true).await;

    let key = announce_divergent_vpn_bests(&tx, 82).await;
    drop(tx);
    handle.await.unwrap();

    let final_orr = drain_final_vpn(&mut out_orr);
    let final_plain = drain_final_vpn(&mut out_plain);
    let unresolved = final_orr
        .get(&key)
        .expect("unresolved-vantage client is advertised the key");
    let plain = final_plain
        .get(&key)
        .expect("vantage-less client is advertised the key");
    assert_eq!(unresolved.next_hop, orr_nh_x(), "the Loc-RIB best");
    assert_eq!(unresolved.next_hop, plain.next_hop);
    assert_eq!(unresolved.attributes, plain.attributes);
    assert_eq!(unresolved.peer, plain.peer);
    assert_eq!(unresolved.nlri, plain.nlri);
}

/// Regression guard: a VPN peer with NO ORR vantage keeps the exact
/// pre-ORR behavior in the divergence scenario — the Loc-RIB best, with
/// no re-advertisement when the losing candidate arrives.
#[tokio::test]
async fn non_orr_vpn_peer_unchanged() {
    let (tx, handle) = orr_rr_manager().await;
    let plain_client = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5));
    let mut out = vpn_orr_peer_up(&tx, plain_client, None, vpn_sendable(), true).await;

    let key = announce_divergent_vpn_bests(&tx, 83).await;
    drop(tx);
    handle.await.unwrap();

    let mut announces = 0;
    let mut last = None;
    while let Ok(update) = out.try_recv() {
        for route in &update.vpn_announce {
            announces += 1;
            last = Some(route.clone());
        }
        assert!(update.vpn_withdraw.is_empty());
    }
    assert_eq!(
        announces, 1,
        "the second candidate must not re-stage a non-ORR peer"
    );
    let last = last.unwrap();
    assert_eq!(last.key(), key);
    assert_eq!(last.next_hop, orr_nh_x(), "the Loc-RIB best");
}

/// RFC 4684 composes with VPN-ORR on the WINNER: the RT-Constrain
/// membership gate applies to the vantage winner's Route Targets — the
/// route actually being advertised — not the Loc-RIB best's.
#[tokio::test]
async fn vpn_orr_rtc_filter_applies_to_vantage_winner() {
    let (tx, handle) = orr_rr_manager().await;

    // Same key from two PEs: the Loc-RIB best (X, lower peer address)
    // carries RT 100; the vantage-B winner (Y, cost 1 < 10) carries
    // RT 200.
    let mut route_x = make_vpn_rib_route_with_rts(ORR_SRC_X, 84, vec![rt(100)]);
    route_x.next_hop = orr_nh_x();
    let key = route_x.key();
    let mut route_y = make_vpn_rib_route_with_rts(ORR_SRC_Y, 84, vec![rt(200)]);
    route_y.next_hop = orr_nh_y();
    announce_vpn(&tx, ORR_SRC_X, vec![route_x]).await;
    announce_vpn(&tx, ORR_SRC_Y, vec![route_y]).await;
    let _ = query_vpn_routes(&tx).await;

    // An iBGP RR client at vantage B that negotiated VPNv4 + RTC.
    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
    let (out_tx, mut out_rx) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        per_client_best: false,
        session_id: 0,
        peer: target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: vec![(Afi::Ipv4, Safi::MplsVpn), (Afi::Ipv4, Safi::RtConstrain)],
        is_ebgp: false,
        route_reflector_client: true,
        orr_vantage: Some(vantage_at_node_b()),
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: Vec::new(),
        negotiated_llgr_families: Vec::new(),
    })
    .await
    .unwrap();
    let _ = query_vpn_routes(&tx).await;
    assert!(
        drain_final_vpn(&mut out_rx).is_empty(),
        "strict RFC 4684: empty membership withholds every VPN route"
    );

    // Interest in the LOC-RIB BEST's RT only: the vantage winner (RT
    // 200) misses the gate, so nothing may be advertised — gating on
    // the Loc-RIB best's RT 100 would wrongly announce here.
    send_rtc_interest(&tx, Ipv4Addr::new(10, 0, 0, 3), &[100]).await;
    let _ = query_vpn_routes(&tx).await;
    assert!(
        !drain_final_vpn(&mut out_rx).contains_key(&key),
        "the gate must apply to the vantage winner's RTs, not the Loc-RIB best's"
    );

    // Interest in the WINNER's RT: the vantage best flows.
    send_rtc_interest(&tx, Ipv4Addr::new(10, 0, 0, 3), &[200]).await;
    let _ = query_vpn_routes(&tx).await;
    drop(tx);
    handle.await.unwrap();
    let advertised = drain_final_vpn(&mut out_rx);
    assert_eq!(
        advertised.get(&key).map(|r| r.next_hop),
        Some(orr_nh_y()),
        "matching the winner's RT admits the vantage best"
    );
}

/// Split horizon and RFC 4456 reflection suppression run BEFORE the ORR
/// ranking: a cost-0 VPN candidate the target must not receive can
/// never win.
#[tokio::test]
async fn vpn_orr_split_horizon_and_rr_suppression_before_ranking() {
    let (tx, handle) = orr_rr_manager().await;
    let client_b = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
    let client_b_v4 = Ipv4Addr::new(10, 0, 0, 3);
    let mut out_b = vpn_orr_peer_up(
        &tx,
        client_b,
        Some(vantage_at_node_b()),
        vpn_sendable(),
        true,
    )
    .await;
    // A non-client iBGP peer bound to the same vantage (the RIB layer
    // trusts PeerUp; the suppression seam must hold regardless).
    let peer_d = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 4));
    let mut out_d = vpn_orr_peer_up(
        &tx,
        peer_d,
        Some(vantage_at_node_b()),
        vpn_sendable(),
        false,
    )
    .await;

    // key1 — split-horizon probe: client B's OWN route has interior
    // cost 0 (next-hop at its vantage node); a non-client source offers
    // cost 10 via NH-X.
    let own = vpn_route_at(client_b_v4, vantage_at_node_b(), 85);
    let key1 = own.key();
    announce_vpn(&tx, client_b_v4, vec![own]).await;
    announce_vpn(
        &tx,
        ORR_SRC_X,
        vec![vpn_route_at(ORR_SRC_X, orr_nh_x(), 85)],
    )
    .await;

    // key2 — RR-suppression probe: the cost-0 candidate comes from a
    // NON-client (never reflectable to the non-client target D); client
    // B offers cost 10 via NH-X (client routes reflect to everyone).
    let non_client_route = vpn_route_at(ORR_SRC_Y, vantage_at_node_b(), 86);
    let key2 = non_client_route.key();
    announce_vpn(&tx, ORR_SRC_Y, vec![non_client_route]).await;
    announce_vpn(
        &tx,
        client_b_v4,
        vec![vpn_route_at(client_b_v4, orr_nh_x(), 86)],
    )
    .await;

    let _ = query_vpn_routes(&tx).await;
    drop(tx);
    handle.await.unwrap();

    let final_b = drain_final_vpn(&mut out_b);
    assert_eq!(
        final_b.get(&key1).map(|r| r.next_hop),
        Some(orr_nh_x()),
        "the target's own cost-0 route is split-horizoned before ranking"
    );
    let final_d = drain_final_vpn(&mut out_d);
    assert_eq!(
        final_d.get(&key2).map(|r| r.next_hop),
        Some(orr_nh_x()),
        "the cost-0 non-client candidate is RR-suppressed before ranking"
    );
}

/// A client that establishes AFTER the VPN routes and topology are in
/// place gets its per-vantage best in the initial table dump.
#[tokio::test]
async fn vpn_orr_initial_dump_gets_vantage_best() {
    let (tx, handle) = orr_rr_manager().await;
    let key = announce_divergent_vpn_bests(&tx, 87).await;

    let client_b = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
    let (out_tx, mut out_b) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        per_client_best: false,
        session_id: 0,
        peer: client_b,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: vpn_sendable(),
        is_ebgp: false,
        route_reflector_client: true,
        orr_vantage: Some(vantage_at_node_b()),
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: Vec::new(),
        negotiated_llgr_families: Vec::new(),
    })
    .await
    .unwrap();
    let _ = query_vpn_routes(&tx).await;
    drop(tx);
    handle.await.unwrap();

    let final_b = drain_final_vpn(&mut out_b);
    assert_eq!(
        final_b.get(&key).map(|r| r.next_hop),
        Some(orr_nh_y()),
        "initial dump carries the vantage best, not the Loc-RIB best"
    );
}

/// A ROUTE-REFRESH replay re-derives the same per-vantage VPN best the
/// live distribution path sent.
#[tokio::test]
async fn vpn_orr_route_refresh_replays_vantage_best() {
    let (tx, handle) = orr_rr_manager().await;
    let client_b = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
    let mut out_b = vpn_orr_peer_up(
        &tx,
        client_b,
        Some(vantage_at_node_b()),
        vpn_sendable(),
        true,
    )
    .await;

    let key = announce_divergent_vpn_bests(&tx, 88).await;
    let _ = drain_final_vpn(&mut out_b);

    tx.send(RibUpdate::RouteRefreshRequest {
        peer: client_b,
        session_id: 0,
        afi: Afi::Ipv4,
        safi: Safi::MplsVpn,
    })
    .await
    .unwrap();
    let _ = query_vpn_routes(&tx).await;
    drop(tx);
    handle.await.unwrap();

    let final_b = drain_final_vpn(&mut out_b);
    assert_eq!(
        final_b.get(&key).map(|r| r.next_hop),
        Some(orr_nh_y()),
        "the replay is the vantage best"
    );
}

// ---------------------------------------------------------------------------
// RFC 9494 §4.4 / §4.6 LLGR-stale export gate
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// RFC 9107 labeled-unicast ORR: per-vantage best selection for SAFI 4
// ---------------------------------------------------------------------------

/// An IPv4 labeled route from `peer` with an explicit next-hop (identical
/// attributes across sources so only the ORR interior-cost step and the
/// final peer-address tiebreak can decide).
fn labeled_route_at(
    peer: Ipv4Addr,
    next_hop: IpAddr,
    prefix_octet: u8,
) -> crate::route::LabeledRibRoute {
    let mut route = make_labeled_rib_route(peer, prefix_octet, 100, 100);
    route.next_hop = next_hop;
    route
}

/// Announce labeled routes from `peer` through the normal receive path.
async fn announce_labeled(
    tx: &mpsc::Sender<RibUpdate>,
    peer: Ipv4Addr,
    announced: Vec<crate::route::LabeledRibRoute>,
) {
    tx.send(RibUpdate::LabeledRoutesReceived {
        session_id: 0,
        peer: IpAddr::V4(peer),
        announced,
        withdrawn: vec![],
    })
    .await
    .unwrap();
}

/// The labeled divergence scenario: the SAME prefix key from two iBGP
/// speakers with next-hops at node X and node Y, followed by a sync point.
/// Returns the contested key.
async fn announce_divergent_labeled_bests(
    tx: &mpsc::Sender<RibUpdate>,
    prefix_octet: u8,
) -> crate::route::LabeledRibRouteKey {
    let route_x = labeled_route_at(ORR_SRC_X, orr_nh_x(), prefix_octet);
    let key = route_x.key();
    announce_labeled(tx, ORR_SRC_X, vec![route_x]).await;
    announce_labeled(
        tx,
        ORR_SRC_Y,
        vec![labeled_route_at(ORR_SRC_Y, orr_nh_y(), prefix_octet)],
    )
    .await;
    let _ = query_labeled_routes(tx).await;
    key
}

/// Two RR clients bound to different vantages receive DIVERGENT labeled
/// bests for the same prefix — each exits via the speaker closest to its
/// own IGP location, not the RR's (the SAFI 4 mirror of the VPN test).
#[tokio::test]
async fn two_labeled_clients_different_vantages_receive_divergent_bests() {
    let (tx, handle) = orr_rr_manager().await;
    let client_a = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let client_b = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
    let mut out_a = vpn_orr_peer_up(
        &tx,
        client_a,
        Some(vantage_at_node_a()),
        labeled_sendable(),
        true,
    )
    .await;
    let mut out_b = vpn_orr_peer_up(
        &tx,
        client_b,
        Some(vantage_at_node_b()),
        labeled_sendable(),
        true,
    )
    .await;

    let key = announce_divergent_labeled_bests(&tx, 80).await;
    drop(tx);
    handle.await.unwrap();

    let final_a = drain_final_labeled(&mut out_a);
    let final_b = drain_final_labeled(&mut out_b);
    assert_eq!(
        final_a.get(&key).map(|r| r.next_hop),
        Some(orr_nh_x()),
        "client at A exits via X (cost 1 < 10)"
    );
    assert_eq!(
        final_b.get(&key).map(|r| r.next_hop),
        Some(orr_nh_y()),
        "client at B exits via Y (cost 1 < 10)"
    );
}

/// A topology metric flip re-stages labeled keys ONLY toward the client
/// whose vantage best actually moved — the unaffected vantage and the
/// non-ORR client see zero messages (the vantage-changed dirty resync
/// covers labeled keys).
#[tokio::test]
async fn labeled_orr_topology_metric_flip_moves_only_affected_client() {
    use crate::orr::fixtures::{A, X, link_route, v4_interface, v4_neighbor};

    let (tx, handle) = orr_rr_manager().await;
    let client_a = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let client_b = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
    let client_c = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 4));
    let mut out_a = vpn_orr_peer_up(
        &tx,
        client_a,
        Some(vantage_at_node_a()),
        labeled_sendable(),
        true,
    )
    .await;
    let mut out_b = vpn_orr_peer_up(
        &tx,
        client_b,
        Some(vantage_at_node_b()),
        labeled_sendable(),
        true,
    )
    .await;
    let mut out_c = vpn_orr_peer_up(&tx, client_c, None, labeled_sendable(), true).await;

    let key = announce_divergent_labeled_bests(&tx, 81).await;
    // Steady state reached — empty every channel before the flip.
    let _ = drain_final_labeled(&mut out_a);
    let _ = drain_final_labeled(&mut out_b);
    let _ = drain_final_labeled(&mut out_c);

    // Flip A→X to metric 100: from A the SPF now prefers Y (10 < 100).
    tx.send(RibUpdate::BgpLsRoutesReceived {
        session_id: 0,
        peer: IpAddr::V4(ORR_FEED),
        announced: vec![link_route(
            ORR_FEED,
            A,
            X,
            Some(100),
            &[
                v4_interface(Ipv4Addr::new(10, 0, A, X)),
                v4_neighbor(Ipv4Addr::new(10, 0, X, A)),
            ],
        )],
        withdrawn: vec![],
    })
    .await
    .unwrap();
    let _ = query_labeled_routes(&tx).await;
    drop(tx);
    handle.await.unwrap();

    let final_a = drain_final_labeled(&mut out_a);
    assert_eq!(
        final_a.get(&key).map(|r| r.next_hop),
        Some(orr_nh_y()),
        "affected client's labeled best flips to Y (cost 10 < 100)"
    );
    assert!(
        out_b.try_recv().is_err(),
        "unaffected vantage's client must see zero messages"
    );
    assert!(
        out_c.try_recv().is_err(),
        "non-ORR client must see zero messages"
    );
}
