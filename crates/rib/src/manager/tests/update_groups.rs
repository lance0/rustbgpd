//! Shadow-mode update-group fingerprint registry (slice 1): membership
//! labels, gauges, ungrouped reasons, and — the risk-3 property — key
//! stability under a content-identical export-policy reinstall.

use rustbgpd_policy::{
    NeighborSetMatch, Policy, PolicyAction, PolicyChain, PolicyStatement, RouteModifications,
};

use super::*;

/// A minimal deny-one-prefix statement (everything else unset).
fn deny_statement(prefix: Ipv4Prefix) -> PolicyStatement {
    PolicyStatement {
        prefix: Some(Prefix::V4(prefix)),
        ge: None,
        le: None,
        action: PolicyAction::Deny,
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

/// A chain denying one prefix — rebuilt fresh per call so two calls
/// yield content-equal but instance-distinct chains.
fn deny_chain(prefix: Ipv4Prefix) -> PolicyChain {
    PolicyChain::new(vec![Policy {
        entries: vec![deny_statement(prefix)],
        default_action: PolicyAction::Permit,
    }])
}

/// A chain with a peer-set criterion (matches on peer ASN).
fn peer_context_chain() -> PolicyChain {
    let mut statement = deny_statement(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 8));
    statement.match_neighbor_set = Some(NeighborSetMatch {
        addresses: vec![],
        remote_asns: vec![65099],
        peer_groups: vec![],
    });
    PolicyChain::new(vec![Policy {
        entries: vec![statement],
        default_action: PolicyAction::Permit,
    }])
}

/// `PeerUp` with update-group-relevant knobs; the rest defaulted.
struct PeerUpSpec {
    peer: IpAddr,
    export_policy: Option<PolicyChain>,
    is_ebgp: bool,
    route_reflector_client: bool,
    orr_vantage: Option<IpAddr>,
    add_path_send_max: u32,
    negotiated_orf_recv: Vec<(Afi, Safi)>,
    negotiated_llgr_families: Vec<(Afi, Safi)>,
}

impl PeerUpSpec {
    fn ibgp(peer: IpAddr) -> Self {
        Self {
            peer,
            export_policy: None,
            is_ebgp: false,
            route_reflector_client: false,
            orr_vantage: None,
            add_path_send_max: 0,
            negotiated_orf_recv: Vec::new(),
            negotiated_llgr_families: Vec::new(),
        }
    }
}

/// Send the `PeerUp` and drain its initial-table End-of-RIB.
async fn peer_up(
    tx: &mpsc::Sender<RibUpdate>,
    spec: PeerUpSpec,
) -> mpsc::Receiver<OutboundRouteUpdate> {
    let (out_tx, mut out_rx) = mpsc::channel(64);
    let add_path_send_families = if spec.add_path_send_max > 0 {
        ipv4_sendable()
    } else {
        vec![]
    };
    tx.send(RibUpdate::PeerUp {
        session_id: 0,
        peer: spec.peer,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: spec.export_policy,
        sendable_families: ipv4_sendable(),
        is_ebgp: spec.is_ebgp,
        route_reflector_client: spec.route_reflector_client,
        orr_vantage: spec.orr_vantage,
        add_path_send_families,
        add_path_send_max: spec.add_path_send_max,
        negotiated_orf_recv: spec.negotiated_orf_recv,
        negotiated_llgr_families: spec.negotiated_llgr_families,
    })
    .await
    .unwrap();
    drain_eor(&mut out_rx).await;
    out_rx
}

async fn query_update_group(tx: &mpsc::Sender<RibUpdate>, peer: IpAddr) -> String {
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryPeerUpdateGroup {
        peer,
        reply: reply_tx,
    })
    .await
    .unwrap();
    reply_rx.await.unwrap()
}

fn regroups_total(metrics: &BgpMetrics) -> f64 {
    metrics
        .registry()
        .gather()
        .iter()
        .find(|family| family.name() == "bgp_update_group_regroups_total")
        .map_or(0.0, |family| family.metric[0].get_counter().value())
}

/// Epsilon-compare a gauge/counter reading (clippy `float_cmp`).
fn assert_metric(observed: f64, expected: f64, what: &str) {
    assert!(
        (observed - expected).abs() < f64::EPSILON,
        "{what}: expected {expected}, observed {observed}"
    );
}

#[tokio::test]
async fn identical_peers_group_together_and_gauges_track_membership() {
    let metrics = BgpMetrics::new();
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, metrics.clone());
    let handle = tokio::spawn(manager.run());

    let a = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let b = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let _rx_a = peer_up(&tx, PeerUpSpec::ibgp(a)).await;
    let _rx_b = peer_up(&tx, PeerUpSpec::ibgp(b)).await;

    assert_eq!(query_update_group(&tx, a).await, "group:0");
    assert_eq!(query_update_group(&tx, b).await, "group:0");
    assert_metric(
        gauge_metric_value(&metrics, "bgp_update_groups", &[]),
        1.0,
        "bgp_update_groups",
    );
    assert_metric(
        gauge_metric_value(&metrics, "bgp_update_group_members", &[("group", "0")]),
        2.0,
        "bgp_update_group_members{group=0}",
    );
    assert_metric(
        gauge_metric_value(&metrics, "bgp_update_group_fallback_peers", &[]),
        0.0,
        "bgp_update_group_fallback_peers",
    );

    // A fingerprint-different peer (eBGP) lands in a second group.
    let c = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
    let mut spec = PeerUpSpec::ibgp(c);
    spec.is_ebgp = true;
    let _rx_c = peer_up(&tx, spec).await;
    assert_eq!(query_update_group(&tx, c).await, "group:1");
    assert_metric(
        gauge_metric_value(&metrics, "bgp_update_groups", &[]),
        2.0,
        "bgp_update_groups",
    );

    // Departures shrink membership; an emptied group's series is removed.
    tx.send(RibUpdate::PeerDown {
        peer: a,
        session_id: 0,
    })
    .await
    .unwrap();
    tx.send(RibUpdate::PeerDown {
        peer: b,
        session_id: 0,
    })
    .await
    .unwrap();
    assert_eq!(query_update_group(&tx, a).await, "");
    assert_metric(
        gauge_metric_value(&metrics, "bgp_update_group_members", &[("group", "0")]),
        0.0,
        "emptied group's member series must be gone (helper reads absent as 0)",
    );
    assert_metric(
        gauge_metric_value(&metrics, "bgp_update_groups", &[]),
        1.0,
        "bgp_update_groups",
    );
    // Membership churn is join/leave, not a regroup.
    assert_metric(regroups_total(&metrics), 0.0, "regroups_total");

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn ungrouped_reasons_surface_per_disqualifier() {
    let metrics = BgpMetrics::new();
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, metrics.clone());
    let handle = tokio::spawn(manager.run());

    let policy_peer = IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1));
    let add_path_peer = IpAddr::V4(Ipv4Addr::new(10, 0, 1, 2));
    let orr_peer = IpAddr::V4(Ipv4Addr::new(10, 0, 1, 3));
    let orf_negotiated_peer = IpAddr::V4(Ipv4Addr::new(10, 0, 1, 4));

    let mut spec = PeerUpSpec::ibgp(policy_peer);
    spec.export_policy = Some(peer_context_chain());
    let _rx1 = peer_up(&tx, spec).await;

    let mut spec = PeerUpSpec::ibgp(add_path_peer);
    spec.add_path_send_max = 2;
    let _rx2 = peer_up(&tx, spec).await;

    let mut spec = PeerUpSpec::ibgp(orr_peer);
    spec.orr_vantage = Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)));
    let _rx3 = peer_up(&tx, spec).await;

    let mut spec = PeerUpSpec::ibgp(orf_negotiated_peer);
    spec.negotiated_orf_recv = ipv4_sendable();
    // The RFC 5291 §6 gate holds the ORF peer's initial dump (no EoR
    // yet), so send PeerUp by hand instead of the helper.
    let (out_tx, _out_rx) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        session_id: 0,
        peer: orf_negotiated_peer,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: spec.export_policy,
        sendable_families: ipv4_sendable(),
        is_ebgp: spec.is_ebgp,
        route_reflector_client: spec.route_reflector_client,
        orr_vantage: spec.orr_vantage,
        add_path_send_families: vec![],
        add_path_send_max: spec.add_path_send_max,
        negotiated_orf_recv: spec.negotiated_orf_recv,
        negotiated_llgr_families: spec.negotiated_llgr_families,
    })
    .await
    .unwrap();

    assert_eq!(
        query_update_group(&tx, policy_peer).await,
        "policy_peer_context"
    );
    assert_eq!(
        query_update_group(&tx, add_path_peer).await,
        "add_path_send"
    );
    assert_eq!(query_update_group(&tx, orr_peer).await, "orr_vantage");
    assert_eq!(
        query_update_group(&tx, orf_negotiated_peer).await,
        "orf_installed"
    );
    assert_metric(
        gauge_metric_value(&metrics, "bgp_update_group_fallback_peers", &[]),
        4.0,
        "bgp_update_group_fallback_peers",
    );
    assert_metric(
        gauge_metric_value(&metrics, "bgp_update_groups", &[]),
        0.0,
        "bgp_update_groups",
    );

    drop(tx);
    handle.await.unwrap();
}

/// Design risk 3: a no-op policy reload (ADR-0076 txn / SIGHUP rpol
/// overlay reinstalling a content-identical chain through
/// `ReplacePeerExportPolicy`) must keep the group key stable and must
/// NOT count as a regroup — content-equality keying, not instance
/// identity. A materially different chain must regroup.
#[tokio::test]
async fn content_identical_policy_replace_is_key_stable() {
    let metrics = BgpMetrics::new();
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, metrics.clone());
    let handle = tokio::spawn(manager.run());

    let prefix = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24);
    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1));
    let mut spec = PeerUpSpec::ibgp(peer);
    spec.export_policy = Some(deny_chain(prefix));
    let _out_rx = peer_up(&tx, spec).await;

    assert_eq!(query_update_group(&tx, peer).await, "group:0");
    assert_metric(regroups_total(&metrics), 0.0, "regroups_total");

    // Reinstall a content-identical chain: freshly constructed, so a
    // distinct instance with a cold compiled-IR cache. Same content ⇒
    // same interned index ⇒ identical key ⇒ no regroup.
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::ReplacePeerExportPolicy {
        peer,
        export_policy: Some(deny_chain(prefix)),
        reply: reply_tx,
    })
    .await
    .unwrap();
    assert_eq!(reply_rx.await.unwrap(), Ok(()));

    assert_eq!(
        query_update_group(&tx, peer).await,
        "group:0",
        "content-identical reinstall must not move the peer"
    );
    assert_metric(
        regroups_total(&metrics),
        0.0,
        "content-identical reinstall must not count as a regroup",
    );

    // A materially different chain regroups the peer.
    let other = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 0), 24);
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::ReplacePeerExportPolicy {
        peer,
        export_policy: Some(deny_chain(other)),
        reply: reply_tx,
    })
    .await
    .unwrap();
    assert_eq!(reply_rx.await.unwrap(), Ok(()));

    assert_eq!(query_update_group(&tx, peer).await, "group:1");
    assert_metric(regroups_total(&metrics), 1.0, "regroups_total");

    // And replacing with a peer-context chain moves it to the fallback
    // path with the recorded reason (also a regroup).
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::ReplacePeerExportPolicy {
        peer,
        export_policy: Some(peer_context_chain()),
        reply: reply_tx,
    })
    .await
    .unwrap();
    assert_eq!(reply_rx.await.unwrap(), Ok(()));
    assert_eq!(query_update_group(&tx, peer).await, "policy_peer_context");
    assert_metric(regroups_total(&metrics), 2.0, "regroups_total");
    assert_metric(
        gauge_metric_value(&metrics, "bgp_update_group_fallback_peers", &[]),
        1.0,
        "bgp_update_group_fallback_peers",
    );

    drop(tx);
    handle.await.unwrap();
}
