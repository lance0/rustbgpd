//! Shadow-mode update-group fingerprint registry (slice 1): membership
//! labels, gauges, ungrouped reasons, and — the risk-3 property — key
//! stability under a content-identical export-policy reinstall.

use std::any::Any;
use std::sync::atomic::{AtomicUsize, Ordering};

use rustbgpd_policy::{
    NeighborSetMatch, Policy, PolicyAction, PolicyChain, PolicyStatement, RouteModifications,
};

use super::*;

#[test]
fn policy_transition_production_slice_boundaries_are_exact() {
    let budget = super::super::POLICY_TRANSITION_PRODUCTION_ROUTE_SLICE;
    let slice_ends = |len| {
        let mut cursor = 0;
        let mut ends = Vec::new();
        while cursor < len {
            cursor = super::super::policy_transition_slice_end(cursor, len, budget);
            ends.push(cursor);
        }
        ends
    };

    assert_eq!(budget, 1_024);
    assert_eq!(slice_ends(0), Vec::<usize>::new());
    assert_eq!(slice_ends(1_023), vec![1_023]);
    assert_eq!(slice_ends(1_024), vec![1_024]);
    assert_eq!(slice_ends(1_025), vec![1_024, 1_025]);
    assert_eq!(slice_ends(2_049), vec![1_024, 2_048, 2_049]);
}

struct CohortExactEncoder {
    owner: u64,
    profile: u64,
    max_len: usize,
    generation: AtomicUsize,
    advance_generation: bool,
    probes: Arc<AtomicUsize>,
    reuses: Arc<AtomicUsize>,
}

struct CohortExactSnapshot {
    owner: u64,
    profile: u64,
    max_len: usize,
    generation: u64,
    probes: Arc<AtomicUsize>,
    reuses: Arc<AtomicUsize>,
}

impl crate::update::ExactExportSnapshot for CohortExactSnapshot {
    fn owner_id(&self) -> u64 {
        self.owner
    }

    fn generation(&self) -> u64 {
        self.generation
    }

    fn probe_announcement(
        &self,
        candidate: crate::update::ExactExportCandidate<'_>,
    ) -> Result<crate::update::ExactExportResult, crate::update::ExactExportError> {
        self.probes.fetch_add(1, Ordering::Relaxed);
        let encoded_len = match candidate {
            crate::update::ExactExportCandidate::Unicast { route, .. }
                if route.attributes.iter().any(|attribute| {
                    matches!(attribute, PathAttribute::Communities(values) if values.contains(&0xFDE8_0002))
                }) =>
            {
                match route.prefix {
                    Prefix::V4(prefix) if prefix.addr.octets()[2].is_multiple_of(2) => 256,
                    _ => 192,
                }
            }
            _ => 64,
        };
        if encoded_len > self.max_len {
            Err(crate::update::ExactExportError::new(
                crate::update::ExactExportErrorCode::MessageTooLong,
                "synthetic cohort ceiling",
            ))
        } else {
            Ok(crate::update::ExactExportResult {
                encoded_len,
                max_len: self.max_len,
                generation: self.generation,
            })
        }
    }

    fn reuse_successful_probes(
        &self,
        source: &dyn crate::update::ExactExportSnapshot,
        encoded_lengths: &[usize],
    ) -> Option<Vec<Result<crate::update::ExactExportResult, crate::update::ExactExportError>>>
    {
        let source = source.as_any().downcast_ref::<Self>()?;
        if source.profile != self.profile {
            return None;
        }
        self.reuses
            .fetch_add(encoded_lengths.len(), Ordering::Relaxed);
        Some(
            encoded_lengths
                .iter()
                .map(|&encoded_len| {
                    if encoded_len > self.max_len {
                        Err(crate::update::ExactExportError::new(
                            crate::update::ExactExportErrorCode::MessageTooLong,
                            "synthetic reused cohort ceiling",
                        ))
                    } else {
                        Ok(crate::update::ExactExportResult {
                            encoded_len,
                            max_len: self.max_len,
                            generation: self.generation,
                        })
                    }
                })
                .collect(),
        )
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl crate::update::ExactExportEncoder for CohortExactEncoder {
    fn owner_id(&self) -> u64 {
        self.owner
    }

    fn snapshot(&self) -> Arc<dyn crate::update::ExactExportSnapshot> {
        let generation = if self.advance_generation {
            u64::try_from(self.generation.fetch_add(1, Ordering::Relaxed) + 1).unwrap()
        } else {
            1
        };
        Arc::new(CohortExactSnapshot {
            owner: self.owner,
            profile: self.profile,
            max_len: self.max_len,
            generation,
            probes: Arc::clone(&self.probes),
            reuses: Arc::clone(&self.reuses),
        })
    }
}

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

fn community_chain(community: u32) -> PolicyChain {
    let mut statement = deny_statement(Ipv4Prefix::new(Ipv4Addr::UNSPECIFIED, 0));
    statement.prefix = None;
    statement.action = PolicyAction::Permit;
    statement.modifications.communities_add.push(community);
    PolicyChain::new(vec![Policy {
        entries: vec![statement],
        default_action: PolicyAction::Deny,
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
    per_client_best: bool,
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
            per_client_best: false,
            add_path_send_max: 0,
            negotiated_orf_recv: Vec::new(),
            negotiated_llgr_families: Vec::new(),
        }
    }

    fn ebgp(peer: IpAddr) -> Self {
        Self {
            is_ebgp: true,
            ..Self::ibgp(peer)
        }
    }
}

/// Send the `PeerUp` and drain its initial-table End-of-RIB.
async fn peer_up(
    tx: &mpsc::Sender<RibUpdate>,
    spec: PeerUpSpec,
) -> mpsc::Receiver<OutboundRouteUpdate> {
    peer_up_with_capacity(tx, spec, 64).await
}

async fn peer_up_with_capacity(
    tx: &mpsc::Sender<RibUpdate>,
    spec: PeerUpSpec,
    capacity: usize,
) -> mpsc::Receiver<OutboundRouteUpdate> {
    let (out_tx, mut out_rx) = mpsc::channel(capacity);
    let add_path_send_families = if spec.add_path_send_max > 0 {
        ipv4_sendable()
    } else {
        vec![]
    };
    tx.send(RibUpdate::PeerUp {
        per_client_best: spec.per_client_best,
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

async fn peer_up_with_cohort_encoder(
    tx: &mpsc::Sender<RibUpdate>,
    spec: PeerUpSpec,
    encoder: Arc<dyn crate::update::ExactExportEncoder>,
) -> mpsc::Receiver<OutboundRouteUpdate> {
    tx.send(RibUpdate::SetPeerExportEncoder {
        peer: spec.peer,
        session_id: 0,
        encoder,
    })
    .await
    .unwrap();
    peer_up(tx, spec).await
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

async fn query_first_export_term_hits(tx: &mpsc::Sender<RibUpdate>, peer: IpAddr) -> (u64, u64) {
    let (reply, response) = oneshot::channel();
    tx.send(RibUpdate::QueryExportPolicyTermHits {
        peer: Some(peer),
        reply,
    })
    .await
    .unwrap();
    let hits = response.await.unwrap();
    assert_eq!(hits.len(), 1, "peer must report its installed chain");
    assert_eq!(
        hits[0].terms.len(),
        1,
        "fixture policy must expose one term"
    );
    (hits[0].evals, hits[0].terms[0].hits)
}

async fn query_peer_outbound_state(
    tx: &mpsc::Sender<RibUpdate>,
    peer: IpAddr,
) -> crate::PeerOutboundState {
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryPeerOutboundState {
        peer,
        reply: reply_tx,
    })
    .await
    .unwrap();
    reply_rx.await.unwrap()
}

async fn apply_authoritative_policy_handoff(
    tx: &mpsc::Sender<RibUpdate>,
    peers: &[IpAddr],
    export_policy: Option<PolicyChain>,
    outcome: crate::update::ExportPolicyCohortOutcome,
) {
    if outcome != crate::update::ExportPolicyCohortOutcome::RequiresAuthoritativePerPeerApply {
        return;
    }
    for &peer in peers {
        let (reply, response) = oneshot::channel();
        tx.send(RibUpdate::ReplacePeerExportPolicy {
            peer,
            export_policy: export_policy.clone(),
            reply,
        })
        .await
        .unwrap();
        assert_eq!(response.await.unwrap(), Ok(()));
    }
}

async fn query_uncommitted_policy_transition_groups(tx: &mpsc::Sender<RibUpdate>) -> usize {
    let (reply, response) = oneshot::channel();
    tx.send(RibUpdate::TestQueryUncommittedPolicyTransitionGroups { reply })
        .await
        .unwrap();
    response.await.unwrap()
}

#[expect(
    clippy::too_many_lines,
    reason = "the oracle fixture preserves full session, route, and wire-view setup"
)]
async fn run_clean_transition_equivalence(force_ungrouped: bool) -> Vec<Vec<String>> {
    let (tx, rx) = mpsc::channel(64);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    manager.test_force_ungrouped = force_ungrouped;
    let handle = tokio::spawn(manager.run());
    let probes = Arc::new(AtomicUsize::new(0));
    let reuses = Arc::new(AtomicUsize::new(0));
    let old_policy = community_chain(0xFDE8_0001);
    let next_policy = community_chain(0xFDE8_0002);
    let peers = [
        IpAddr::V4(Ipv4Addr::new(10, 25, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 25, 0, 2)),
    ];
    let mut receivers = Vec::new();
    for (index, peer) in peers.iter().copied().enumerate() {
        let mut spec = PeerUpSpec::ibgp(peer);
        spec.route_reflector_client = true;
        spec.export_policy = Some(old_policy.clone());
        receivers.push(
            peer_up_with_cohort_encoder(
                &tx,
                spec,
                Arc::new(CohortExactEncoder {
                    owner: u64::try_from(index + 1).unwrap(),
                    profile: 23,
                    max_len: 4_096,
                    generation: AtomicUsize::new(0),
                    advance_generation: false,
                    probes: Arc::clone(&probes),
                    reuses: Arc::clone(&reuses),
                }),
            )
            .await,
        );
    }
    let third_source = Ipv4Addr::new(192, 0, 2, 14);
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: IpAddr::V4(third_source),
        announced: vec![
            crate::test_support::make_route(
                Ipv4Prefix::new(Ipv4Addr::new(203, 0, 117, 0), 24),
                match peers[0] {
                    IpAddr::V4(value) => value,
                    IpAddr::V6(_) => unreachable!(),
                },
            ),
            crate::test_support::make_route(
                Ipv4Prefix::new(Ipv4Addr::new(203, 0, 118, 0), 24),
                match peers[1] {
                    IpAddr::V4(value) => value,
                    IpAddr::V6(_) => unreachable!(),
                },
            ),
            crate::test_support::make_route(
                Ipv4Prefix::new(Ipv4Addr::new(203, 0, 119, 0), 24),
                third_source,
            ),
        ],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();
    for receiver in &mut receivers {
        assert_eq!(receiver.recv().await.unwrap().announce.len(), 2);
    }

    let (reply, response) = oneshot::channel();
    tx.send(RibUpdate::ReplacePeerExportPolicies {
        replacements: peers
            .iter()
            .map(|&peer| crate::update::PeerExportPolicyReplacement {
                peer,
                export_policy: Some(next_policy.clone()),
            })
            .collect(),
        reply,
    })
    .await
    .unwrap();
    let outcome = response.await.unwrap().unwrap();
    assert_eq!(
        outcome,
        if force_ungrouped {
            crate::update::ExportPolicyCohortOutcome::RequiresAuthoritativePerPeerApply
        } else {
            crate::update::ExportPolicyCohortOutcome::Committed
        }
    );
    apply_authoritative_policy_handoff(&tx, &peers, Some(next_policy.clone()), outcome).await;

    let mut folded = Vec::new();
    for receiver in &mut receivers {
        let update = receiver.recv().await.unwrap();
        assert!(update.withdraw.is_empty());
        let mut routes = update
            .announce
            .iter()
            .zip(update.next_hop_override.iter())
            .filter(|(route, _)| update.announce_source_exclusion != Some(route.peer))
            .map(|(route, next_hop)| {
                format!(
                    "{:?}|{}|{:?}|{:?}|{:?}",
                    route.prefix, route.path_id, route.peer, route.attributes, next_hop
                )
            })
            .collect::<Vec<_>>();
        routes.sort_unstable();
        folded.push(routes);
    }
    let (stats_reply, stats_response) = oneshot::channel();
    tx.send(RibUpdate::TestQueryPolicyTransitionStats { reply: stats_reply })
        .await
        .unwrap();
    assert_eq!(
        stats_response.await.unwrap().0,
        usize::from(!force_ungrouped)
    );

    drop(tx);
    handle.await.unwrap();
    folded
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
async fn replace_export_policy_after_peer_down_returns_typed_not_found() {
    let (tx, rx) = mpsc::channel(16);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());
    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 42));
    let _outbound = peer_up(&tx, PeerUpSpec::ibgp(peer)).await;

    tx.send(RibUpdate::PeerDown {
        peer,
        session_id: 0,
    })
    .await
    .unwrap();
    let (reply, response) = oneshot::channel();
    tx.send(RibUpdate::ReplacePeerExportPolicy {
        peer,
        export_policy: None,
        reply,
    })
    .await
    .unwrap();

    assert!(matches!(
        response.await.unwrap(),
        Err(crate::update::RibCommandError::NotFound(_))
    ));
    drop(tx);
    handle.await.unwrap();
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
    assert_eq!(
        query_peer_outbound_state(&tx, a)
            .await
            .effective_distribution_mode,
        crate::EffectiveDistributionMode::SingleBest
    );
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
    assert_eq!(
        query_peer_outbound_state(&tx, a)
            .await
            .effective_distribution_mode,
        crate::EffectiveDistributionMode::Unknown
    );
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
    let per_client_best_peer = IpAddr::V4(Ipv4Addr::new(10, 0, 1, 5));

    let mut spec = PeerUpSpec::ibgp(policy_peer);
    spec.export_policy = Some(peer_context_chain());
    let _rx1 = peer_up(&tx, spec).await;

    let mut spec = PeerUpSpec::ibgp(add_path_peer);
    spec.add_path_send_max = 2;
    let _rx2 = peer_up(&tx, spec).await;

    let mut spec = PeerUpSpec::ibgp(orr_peer);
    spec.orr_vantage = Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)));
    let _rx3 = peer_up(&tx, spec).await;

    let mut spec = PeerUpSpec::ebgp(per_client_best_peer);
    spec.per_client_best = true;
    let _rx5 = peer_up(&tx, spec).await;

    let mut spec = PeerUpSpec::ibgp(orf_negotiated_peer);
    spec.negotiated_orf_recv = ipv4_sendable();
    // The RFC 5291 §6 gate holds the ORF peer's initial dump (no EoR
    // yet), so send PeerUp by hand instead of the helper.
    let (out_tx, _out_rx) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        per_client_best: spec.per_client_best,
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
        query_update_group(&tx, per_client_best_peer).await,
        "per_client_best"
    );
    assert_eq!(
        query_update_group(&tx, orf_negotiated_peer).await,
        "orf_installed"
    );
    assert_eq!(
        query_peer_outbound_state(&tx, policy_peer)
            .await
            .effective_distribution_mode,
        crate::EffectiveDistributionMode::SingleBest
    );
    assert_eq!(
        query_peer_outbound_state(&tx, add_path_peer)
            .await
            .effective_distribution_mode,
        crate::EffectiveDistributionMode::AddPath
    );
    assert_eq!(
        query_peer_outbound_state(&tx, per_client_best_peer)
            .await
            .effective_distribution_mode,
        crate::EffectiveDistributionMode::PerClientBest
    );
    assert_eq!(
        query_peer_outbound_state(&tx, orf_negotiated_peer)
            .await
            .effective_distribution_mode,
        crate::EffectiveDistributionMode::SingleBest
    );
    assert_metric(
        gauge_metric_value(&metrics, "bgp_update_group_fallback_peers", &[]),
        5.0,
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

/// The RS mixed-group pin (route-server design §3): transparent
/// route-server clients share staged routes with plain eBGP peers —
/// `route_server_client` is applied per-session in transport, BELOW
/// the group staging boundary, so it is deliberately absent from the
/// manager's fingerprint inputs and two eBGP peers with the same chain
/// group regardless of it. Only `per_client_best` (a *selection*
/// divergence, not an attribute-prep one) disqualifies.
#[tokio::test]
async fn rs_transparent_peers_group_per_client_best_falls_back() {
    let metrics = BgpMetrics::new();
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, metrics.clone());
    let handle = tokio::spawn(manager.run());

    // Conceptually: rs1/rs2 are RS-transparent members, plain is not.
    // The manager sees identical staging inputs for all three — the
    // transparency flag lives in transport (outbound attribute prep).
    let rs1 = IpAddr::V4(Ipv4Addr::new(10, 0, 3, 1));
    let rs2 = IpAddr::V4(Ipv4Addr::new(10, 0, 3, 2));
    let plain = IpAddr::V4(Ipv4Addr::new(10, 0, 3, 3));
    let pcb = IpAddr::V4(Ipv4Addr::new(10, 0, 3, 4));

    let mut rx1 = peer_up(&tx, PeerUpSpec::ebgp(rs1)).await;
    let mut rx2 = peer_up(&tx, PeerUpSpec::ebgp(rs2)).await;
    let _rx3 = peer_up(&tx, PeerUpSpec::ebgp(plain)).await;
    let mut spec = PeerUpSpec::ebgp(pcb);
    spec.per_client_best = true;
    let _rx4 = peer_up(&tx, spec).await;

    let g1 = query_update_group(&tx, rs1).await;
    assert!(g1.starts_with("group:"), "RS-transparent peers group: {g1}");
    assert_eq!(query_update_group(&tx, rs2).await, g1);
    assert_eq!(
        query_update_group(&tx, plain).await,
        g1,
        "transparency is transport-side; shared chain ⇒ shared group"
    );
    assert_eq!(query_update_group(&tx, pcb).await, "per_client_best");
    assert_metric(
        gauge_metric_value(&metrics, "bgp_update_group_fallback_peers", &[]),
        1.0,
        "bgp_update_group_fallback_peers",
    );

    // Shared staging feeds the grouped members identically.
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 0), 24);
    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 3, 9));
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![crate::test_support::make_route(
            prefix,
            Ipv4Addr::new(10, 0, 3, 9),
        )],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    let u1 = rx1.recv().await.unwrap();
    let u2 = rx2.recv().await.unwrap();
    assert_eq!(u1.announce.len(), 1);
    assert_eq!(u1.announce[0].prefix, Prefix::V4(prefix));
    assert_eq!(u1.announce[0].attributes, u2.announce[0].attributes);

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
    assert_metric(
        gauge_metric_value(&metrics, "bgp_update_group_interned_chains", &[]),
        1.0,
        "bgp_update_group_interned_chains",
    );
    assert_metric(
        gauge_metric_value(&metrics, "bgp_update_group_keys", &[]),
        1.0,
        "bgp_update_group_keys",
    );

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
    assert_metric(
        gauge_metric_value(&metrics, "bgp_update_group_interned_chains", &[]),
        1.0,
        "content-identical reinstall must not grow the interned-chain registry",
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
    // Registry growth is append-only: the new content and key ADD to
    // the registry (LAN-311 growth observability; slot 0 is retained
    // for key-stable reuse, not evicted).
    assert_metric(
        gauge_metric_value(&metrics, "bgp_update_group_interned_chains", &[]),
        2.0,
        "bgp_update_group_interned_chains after a content change",
    );
    assert_metric(
        gauge_metric_value(&metrics, "bgp_update_group_keys", &[]),
        2.0,
        "bgp_update_group_keys after a content change",
    );

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

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "the scaling regression keeps every cohort counter assertion in one fixture"
)]
async fn clean_policy_transition_builds_and_probes_once_per_wire_cohort() {
    const MEMBER_COUNT: usize = 8;
    const ROUTE_COUNT: usize = 32;

    let metrics = BgpMetrics::new();
    let (tx, rx) = mpsc::channel(128);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, metrics);
    let handle = tokio::spawn(manager.run());
    let probes = Arc::new(AtomicUsize::new(0));
    let reuses = Arc::new(AtomicUsize::new(0));
    let old_policy = community_chain(0xFDE8_0001);
    let next_policy = community_chain(0xFDE8_0002);
    let mut peers = Vec::new();
    let mut receivers = Vec::new();

    for index in 0..MEMBER_COUNT {
        let peer = IpAddr::V4(Ipv4Addr::new(10, 20, 0, u8::try_from(index + 1).unwrap()));
        peers.push(peer);
        let mut spec = PeerUpSpec::ibgp(peer);
        spec.route_reflector_client = true;
        spec.export_policy = Some(old_policy.clone());
        receivers.push(
            peer_up_with_cohort_encoder(
                &tx,
                spec,
                Arc::new(CohortExactEncoder {
                    owner: u64::try_from(index + 1).unwrap(),
                    profile: 7,
                    max_len: if index % 2 == 0 { 4_096 } else { 65_535 },
                    generation: AtomicUsize::new(0),
                    advance_generation: false,
                    probes: Arc::clone(&probes),
                    reuses: Arc::clone(&reuses),
                }),
            )
            .await,
        );
    }

    let source = Ipv4Addr::new(192, 0, 2, 9);
    let announced = (0..ROUTE_COUNT)
        .map(|index| {
            crate::test_support::make_route(
                Ipv4Prefix::new(Ipv4Addr::new(198, 51, u8::try_from(index).unwrap(), 0), 24),
                source,
            )
        })
        .collect();
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: IpAddr::V4(source),
        announced,
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();
    for receiver in &mut receivers {
        let initial = receiver.recv().await.unwrap();
        assert_eq!(initial.announce.len(), ROUTE_COUNT);
    }
    probes.store(0, Ordering::Relaxed);
    reuses.store(0, Ordering::Relaxed);

    let (reply, response) = oneshot::channel();
    tx.send(RibUpdate::ReplacePeerExportPolicies {
        replacements: peers
            .iter()
            .map(|&peer| crate::update::PeerExportPolicyReplacement {
                peer,
                export_policy: Some(next_policy.clone()),
            })
            .collect(),
        reply,
    })
    .await
    .unwrap();
    assert_eq!(
        response.await.unwrap(),
        Ok(crate::update::ExportPolicyCohortOutcome::Committed)
    );
    let transition_hits = (ROUTE_COUNT as u64, ROUTE_COUNT as u64);
    for &peer in &peers {
        assert_eq!(
            query_first_export_term_hits(&tx, peer).await,
            transition_hits,
            "every installed member must expose the destination group's staged evaluations"
        );
    }

    let mut updates = Vec::new();
    for receiver in &mut receivers {
        let update = receiver.recv().await.unwrap();
        assert_eq!(update.announce.len(), ROUTE_COUNT);
        updates.push(update);
    }
    for update in &updates[1..] {
        assert!(Arc::ptr_eq(&updates[0].announce, &update.announce));
        assert!(Arc::ptr_eq(
            &updates[0].next_hop_override,
            &update.next_hop_override
        ));
    }
    assert_eq!(
        probes.load(Ordering::Relaxed),
        ROUTE_COUNT,
        "full exact probes scale with routes times compatible wire profiles"
    );
    assert_eq!(
        reuses.load(Ordering::Relaxed),
        MEMBER_COUNT - 1,
        "each compatible member must recheck only the cohort maximum length"
    );

    let (stats_reply, stats_response) = oneshot::channel();
    tx.send(RibUpdate::TestQueryPolicyTransitionStats { reply: stats_reply })
        .await
        .unwrap();
    let (plans, full_probes, materialized, max_slice_ns, actor_polls) =
        stats_response.await.unwrap();
    assert_eq!(plans, 1);
    assert_eq!(full_probes, ROUTE_COUNT);
    assert_eq!(materialized, ROUTE_COUNT);
    assert!(max_slice_ns > 0);
    assert!(
        actor_polls >= ROUTE_COUNT,
        "the test-only one-route budget must require multiple real actor polls"
    );
    for &peer in &peers {
        assert_eq!(query_update_group(&tx, peer).await, "group:1");
    }

    let later_prefix = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24);
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: IpAddr::V4(source),
        announced: vec![crate::test_support::make_route(later_prefix, source)],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();
    for receiver in &mut receivers {
        let update = receiver.recv().await.unwrap();
        assert_eq!(update.announce.len(), 1);
        assert_eq!(update.announce[0].prefix, Prefix::V4(later_prefix));
    }
    for peer in peers {
        assert_eq!(
            query_first_export_term_hits(&tx, peer).await,
            (transition_hits.0 + 1, transition_hits.1 + 1),
            "later group evaluations must advance every installed member's shared counters"
        );
    }

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "the existing-destination regression checks every grouped counter handle before and after later staging"
)]
async fn clean_policy_transition_existing_destination_shares_every_members_counters() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());
    let probes = Arc::new(AtomicUsize::new(0));
    let reuses = Arc::new(AtomicUsize::new(0));
    let old_policy = community_chain(0xFDE8_0001);
    let next_policy = community_chain(0xFDE8_0002);
    let moving = [
        IpAddr::V4(Ipv4Addr::new(10, 27, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 27, 0, 2)),
    ];
    let destination_member = IpAddr::V4(Ipv4Addr::new(10, 27, 0, 3));
    let mut moving_receivers = Vec::new();
    for (index, peer) in moving.iter().copied().enumerate() {
        let mut spec = PeerUpSpec::ibgp(peer);
        spec.route_reflector_client = true;
        spec.export_policy = Some(old_policy.clone());
        moving_receivers.push(
            peer_up_with_cohort_encoder(
                &tx,
                spec,
                Arc::new(CohortExactEncoder {
                    owner: u64::try_from(index + 1).unwrap(),
                    profile: 31,
                    max_len: 4_096,
                    generation: AtomicUsize::new(0),
                    advance_generation: false,
                    probes: Arc::clone(&probes),
                    reuses: Arc::clone(&reuses),
                }),
            )
            .await,
        );
    }
    let mut destination_spec = PeerUpSpec::ibgp(destination_member);
    destination_spec.route_reflector_client = true;
    destination_spec.export_policy = Some(next_policy.clone());
    let mut destination_receiver = peer_up_with_cohort_encoder(
        &tx,
        destination_spec,
        Arc::new(CohortExactEncoder {
            owner: 3,
            profile: 31,
            max_len: 4_096,
            generation: AtomicUsize::new(0),
            advance_generation: false,
            probes: Arc::clone(&probes),
            reuses: Arc::clone(&reuses),
        }),
    )
    .await;

    let source = Ipv4Addr::new(192, 0, 2, 17);
    let first_prefix = Ipv4Prefix::new(Ipv4Addr::new(198, 53, 0, 0), 24);
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: IpAddr::V4(source),
        announced: vec![crate::test_support::make_route(first_prefix, source)],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();
    for receiver in &mut moving_receivers {
        assert_eq!(receiver.recv().await.unwrap().announce.len(), 1);
    }
    assert_eq!(destination_receiver.recv().await.unwrap().announce.len(), 1);

    let (reply, response) = oneshot::channel();
    tx.send(RibUpdate::ReplacePeerExportPolicies {
        replacements: moving
            .iter()
            .map(|&peer| crate::update::PeerExportPolicyReplacement {
                peer,
                export_policy: Some(next_policy.clone()),
            })
            .collect(),
        reply,
    })
    .await
    .unwrap();
    assert_eq!(
        response.await.unwrap(),
        Ok(crate::update::ExportPolicyCohortOutcome::Committed)
    );
    for receiver in &mut moving_receivers {
        assert_eq!(receiver.recv().await.unwrap().announce.len(), 1);
    }
    assert!(destination_receiver.try_recv().is_err());

    for peer in moving.into_iter().chain([destination_member]) {
        assert_eq!(query_update_group(&tx, peer).await, "group:1");
        assert_eq!(
            query_first_export_term_hits(&tx, peer).await,
            (1, 1),
            "every member must expose the maintained destination group's counter instance"
        );
    }

    let later_prefix = Ipv4Prefix::new(Ipv4Addr::new(198, 53, 1, 0), 24);
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: IpAddr::V4(source),
        announced: vec![crate::test_support::make_route(later_prefix, source)],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();
    for receiver in &mut moving_receivers {
        assert_eq!(receiver.recv().await.unwrap().announce.len(), 1);
    }
    assert_eq!(destination_receiver.recv().await.unwrap().announce.len(), 1);
    for peer in moving.into_iter().chain([destination_member]) {
        assert_eq!(
            query_first_export_term_hits(&tx, peer).await,
            (2, 2),
            "later staging must advance every member's shared counter view"
        );
    }

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test(flavor = "current_thread")]
#[expect(
    clippy::too_many_lines,
    reason = "the scheduler regression pins dedicated readiness, general-query isolation, and terminal release in one transaction"
)]
async fn clean_policy_transition_isolates_readiness_from_general_query_flood() {
    const ROUTE_COUNT: usize = 32;
    const QUERY_FLOOD: usize = 128;
    let (tx, rx) = mpsc::channel(128);
    let (query_tx, query_rx) = mpsc::channel(QUERY_FLOOD);
    let (readiness_tx, readiness_rx) = mpsc::channel(8);
    let metrics = BgpMetrics::new();
    let manager = RibManager::new(rx, query_rx, None, None, metrics.clone())
        .with_readiness_queries(readiness_rx);
    let handle = tokio::spawn(manager.run());
    let probes = Arc::new(AtomicUsize::new(0));
    let reuses = Arc::new(AtomicUsize::new(0));
    let old_policy = community_chain(0xFDE8_1001);
    let next_policy = community_chain(0xFDE8_1002);
    let peers = [
        IpAddr::V4(Ipv4Addr::new(10, 25, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 25, 0, 2)),
    ];
    let mut receivers = Vec::new();
    for (index, peer) in peers.iter().copied().enumerate() {
        let mut spec = PeerUpSpec::ibgp(peer);
        spec.route_reflector_client = true;
        spec.export_policy = Some(old_policy.clone());
        receivers.push(
            peer_up_with_cohort_encoder(
                &tx,
                spec,
                Arc::new(CohortExactEncoder {
                    owner: u64::try_from(index + 1).unwrap(),
                    profile: 23,
                    max_len: 4_096,
                    generation: AtomicUsize::new(0),
                    advance_generation: false,
                    probes: Arc::clone(&probes),
                    reuses: Arc::clone(&reuses),
                }),
            )
            .await,
        );
    }
    let source = Ipv4Addr::new(192, 0, 2, 14);
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: IpAddr::V4(source),
        announced: (0..ROUTE_COUNT)
            .map(|index| {
                crate::test_support::make_route(
                    Ipv4Prefix::new(Ipv4Addr::new(198, 52, u8::try_from(index).unwrap(), 0), 24),
                    source,
                )
            })
            .collect(),
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();
    for receiver in &mut receivers {
        assert_eq!(receiver.recv().await.unwrap().announce.len(), ROUTE_COUNT);
    }

    let replacements = peers
        .iter()
        .map(|&peer| crate::update::PeerExportPolicyReplacement {
            peer,
            export_policy: Some(next_policy.clone()),
        })
        .collect::<Vec<_>>();
    let (reply, mut response) = oneshot::channel();
    tx.send(RibUpdate::ReplacePeerExportPolicies {
        replacements,
        reply,
    })
    .await
    .unwrap();

    // The zero-label gauge is the production ownership barrier. On this
    // current-thread runtime the actor yields after each transition poll, so
    // observing 1 proves the transition owns the actor before the flood below.
    while (gauge_metric_value(&metrics, "bgp_rib_policy_transition_in_progress", &[]) - 1.0).abs()
        >= f64::EPSILON
    {
        tokio::task::yield_now().await;
    }
    assert!(matches!(
        response.try_recv(),
        Err(oneshot::error::TryRecvError::Empty)
    ));

    let mut general_replies = Vec::with_capacity(QUERY_FLOOD);
    for _ in 0..QUERY_FLOOD {
        let (reply, response) = oneshot::channel();
        query_tx
            .send(RibUpdate::QueryLocRibCount { reply })
            .await
            .unwrap();
        general_replies.push(response);
    }
    assert_eq!(
        query_tx.capacity(),
        0,
        "general query lane must be saturated"
    );

    let (readiness_reply, readiness_response) = oneshot::channel();
    readiness_tx
        .send(crate::update::RibReadinessQuery::LocRibCount {
            reply: readiness_reply,
        })
        .await
        .unwrap();
    assert_eq!(
        tokio::time::timeout(std::time::Duration::from_millis(200), readiness_response)
            .await
            .expect("dedicated readiness must beat the core deadline")
            .unwrap(),
        ROUTE_COUNT
    );
    assert_metric(
        gauge_metric_value(&metrics, "bgp_rib_policy_transition_in_progress", &[]),
        1.0,
        "transition remains owned while readiness overtakes the query flood",
    );
    for reply in &mut general_replies {
        assert!(matches!(
            reply.try_recv(),
            Err(oneshot::error::TryRecvError::Empty)
        ));
    }
    assert!(
        receivers
            .iter_mut()
            .all(|receiver| receiver.try_recv().is_err())
    );
    assert!(matches!(
        response.try_recv(),
        Err(oneshot::error::TryRecvError::Empty)
    ));

    assert_eq!(
        response.await.unwrap(),
        Ok(crate::update::ExportPolicyCohortOutcome::Committed)
    );
    assert_metric(
        gauge_metric_value(&metrics, "bgp_rib_policy_transition_in_progress", &[]),
        0.0,
        "commit clears transition ownership",
    );
    for reply in &mut general_replies {
        assert!(matches!(
            reply.try_recv(),
            Err(oneshot::error::TryRecvError::Empty)
        ));
    }
    for receiver in &mut receivers {
        assert_eq!(receiver.recv().await.unwrap().announce.len(), ROUTE_COUNT);
    }
    for reply in general_replies {
        assert_eq!(reply.await.unwrap(), ROUTE_COUNT);
    }
    assert_eq!(query_update_group(&query_tx, peers[0]).await, "group:1");
    assert_eq!(query_update_group(&query_tx, peers[1]).await, "group:1");

    drop(tx);
    drop(query_tx);
    drop(readiness_tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn rejected_policy_transition_batches_leave_observability_idle() {
    let (_tx, rx) = mpsc::channel(1);
    let metrics = BgpMetrics::new();
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, metrics.clone());

    let (empty_reply, empty_response) = oneshot::channel();
    manager.handle_replace_peer_export_policies(Vec::new(), empty_reply);
    assert_eq!(
        empty_response.await.unwrap(),
        Ok(crate::update::ExportPolicyCohortOutcome::Committed)
    );

    let (invalid_reply, invalid_response) = oneshot::channel();
    manager.handle_replace_peer_export_policies(
        vec![crate::update::PeerExportPolicyReplacement {
            peer: "192.0.2.250".parse().unwrap(),
            export_policy: None,
        }],
        invalid_reply,
    );
    assert!(invalid_response.await.unwrap().is_err());

    assert_metric(
        gauge_metric_value(&metrics, "bgp_rib_policy_transition_in_progress", &[]),
        0.0,
        "empty and rejected batches never acquire transition ownership",
    );
    assert_metric(
        gauge_metric_value(
            &metrics,
            "bgp_rib_policy_transition_last_duration_milliseconds",
            &[],
        ),
        0.0,
        "non-started batches do not create a terminal duration",
    );
}

#[tokio::test]
async fn duplicate_pending_policy_transition_returns_internal_error_without_gauge_churn() {
    let (_tx, rx) = mpsc::channel(1);
    let metrics = BgpMetrics::new();
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, metrics.clone());
    let peer: IpAddr = "192.0.2.251".parse().unwrap();
    let (outbound_tx, _outbound_rx) = mpsc::channel(1);
    manager.outbound_peers.insert(peer, outbound_tx);
    let replacement = crate::update::PeerExportPolicyReplacement {
        peer,
        export_policy: None,
    };

    let (first_reply, mut first_response) = oneshot::channel();
    manager.handle_replace_peer_export_policies(vec![replacement.clone()], first_reply);
    assert!(matches!(
        first_response.try_recv(),
        Err(oneshot::error::TryRecvError::Empty)
    ));
    assert_metric(
        gauge_metric_value(&metrics, "bgp_rib_policy_transition_in_progress", &[]),
        1.0,
        "first batch acquires transition ownership",
    );

    let (duplicate_reply, duplicate_response) = oneshot::channel();
    manager.handle_replace_peer_export_policies(vec![replacement], duplicate_reply);
    assert_eq!(
        duplicate_response.await.unwrap().unwrap_err(),
        "internal RIB sequencing error: policy transition already in progress"
    );
    assert_metric(
        gauge_metric_value(&metrics, "bgp_rib_policy_transition_in_progress", &[]),
        1.0,
        "duplicate rejection must not clear or reacquire existing ownership",
    );
    assert_metric(
        gauge_metric_value(
            &metrics,
            "bgp_rib_policy_transition_last_duration_milliseconds",
            &[],
        ),
        0.0,
        "duplicate rejection must not create a terminal duration",
    );
}

#[tokio::test]
async fn accepted_policy_transition_does_not_drain_prequeued_general_queries() {
    let (_tx, rx) = mpsc::channel(1);
    let (query_tx, query_rx) = mpsc::channel(1);
    let (query_reply, mut query_response) = oneshot::channel();
    query_tx
        .send(RibUpdate::QueryLocRibCount { reply: query_reply })
        .await
        .unwrap();

    let metrics = BgpMetrics::new();
    let mut manager = RibManager::new(rx, query_rx, None, None, metrics.clone());
    let peer: IpAddr = "192.0.2.252".parse().unwrap();
    let (outbound_tx, _outbound_rx) = mpsc::channel(1);
    manager.outbound_peers.insert(peer, outbound_tx);
    let (transition_reply, mut transition_response) = oneshot::channel();
    manager.handle_replace_peer_export_policies(
        vec![crate::update::PeerExportPolicyReplacement {
            peer,
            export_policy: None,
        }],
        transition_reply,
    );

    // This is the exact fairness seam used after a primary-channel receive.
    // The accepted transition must suppress it even though the query was
    // already queued before ownership began.
    manager.drain_general_queries_if_unfenced();
    assert!(matches!(
        query_response.try_recv(),
        Err(oneshot::error::TryRecvError::Empty)
    ));
    assert!(matches!(
        transition_response.try_recv(),
        Err(oneshot::error::TryRecvError::Empty)
    ));
    assert_metric(
        gauge_metric_value(&metrics, "bgp_rib_policy_transition_in_progress", &[]),
        1.0,
        "prequeued general query remains behind accepted transition",
    );
}

#[tokio::test(flavor = "current_thread")]
async fn clean_policy_transition_finishes_after_reply_and_channels_close() {
    let (tx, rx) = mpsc::channel(32);
    let (query_tx, query_rx) = mpsc::channel(8);
    let manager = RibManager::new(rx, query_rx, None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());
    let probes = Arc::new(AtomicUsize::new(0));
    let reuses = Arc::new(AtomicUsize::new(0));
    let old_policy = community_chain(0xFDE8_2001);
    let next_policy = community_chain(0xFDE8_2002);
    let peers = [
        IpAddr::V4(Ipv4Addr::new(10, 26, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 26, 0, 2)),
    ];
    let mut receivers = Vec::new();
    for (index, peer) in peers.iter().copied().enumerate() {
        let mut spec = PeerUpSpec::ibgp(peer);
        spec.route_reflector_client = true;
        spec.export_policy = Some(old_policy.clone());
        receivers.push(
            peer_up_with_cohort_encoder(
                &tx,
                spec,
                Arc::new(CohortExactEncoder {
                    owner: u64::try_from(index + 1).unwrap(),
                    profile: 29,
                    max_len: 4_096,
                    generation: AtomicUsize::new(0),
                    advance_generation: false,
                    probes: Arc::clone(&probes),
                    reuses: Arc::clone(&reuses),
                }),
            )
            .await,
        );
    }
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 117, 0), 24);
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 15)),
        announced: vec![crate::test_support::make_route(
            prefix,
            Ipv4Addr::new(192, 0, 2, 15),
        )],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();
    for receiver in &mut receivers {
        assert_eq!(receiver.recv().await.unwrap().announce.len(), 1);
    }

    let (reply, dropped_response) = oneshot::channel();
    tx.send(RibUpdate::ReplacePeerExportPolicies {
        replacements: peers
            .iter()
            .map(|&peer| crate::update::PeerExportPolicyReplacement {
                peer,
                export_policy: Some(next_policy.clone()),
            })
            .collect(),
        reply,
    })
    .await
    .unwrap();
    drop(dropped_response);
    let (dropped_query_reply, dropped_query_response) = oneshot::channel();
    query_tx
        .send(RibUpdate::QueryLocRibCount {
            reply: dropped_query_reply,
        })
        .await
        .unwrap();
    drop(dropped_query_response);
    drop(tx);
    drop(query_tx);

    for receiver in &mut receivers {
        let update = receiver.recv().await.unwrap();
        assert_eq!(update.announce.len(), 1);
        assert!(update.announce[0].attributes.iter().any(|attribute| {
            matches!(attribute, PathAttribute::Communities(values) if values.contains(&0xFDE8_2002))
        }));
    }
    handle.await.unwrap();
}

#[tokio::test]
async fn clean_policy_transition_matches_force_ungrouped_member_views() {
    let shared = run_clean_transition_equivalence(false).await;
    let authoritative = run_clean_transition_equivalence(true).await;
    assert_eq!(shared, authoritative);
    assert!(shared.iter().all(|routes| routes.len() == 2));
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "the fallback regression covers canonical counters through later staging and a complete prior-policy rollback"
)]
async fn clean_policy_transition_falls_back_wholesale_on_member_ceiling_rejection() {
    let (tx, rx) = mpsc::channel(64);
    let metrics = BgpMetrics::new();
    metrics.set_rib_policy_transition_last_duration(std::time::Duration::from_secs(987));
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, metrics.clone());
    let handle = tokio::spawn(manager.run());
    let probes = Arc::new(AtomicUsize::new(0));
    let reuses = Arc::new(AtomicUsize::new(0));
    let old_policy = community_chain(0xFDE8_0001);
    let next_policy = community_chain(0xFDE8_0002);
    let peers = [
        IpAddr::V4(Ipv4Addr::new(10, 21, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 21, 0, 2)),
    ];
    let mut receivers = Vec::new();
    for (index, peer) in peers.iter().copied().enumerate() {
        let mut spec = PeerUpSpec::ibgp(peer);
        spec.route_reflector_client = true;
        spec.export_policy = Some(old_policy.clone());
        receivers.push(
            peer_up_with_cohort_encoder(
                &tx,
                spec,
                Arc::new(CohortExactEncoder {
                    owner: u64::try_from(index + 1).unwrap(),
                    profile: 11,
                    max_len: if index == 0 { 4_096 } else { 128 },
                    generation: AtomicUsize::new(0),
                    advance_generation: false,
                    probes: Arc::clone(&probes),
                    reuses: Arc::clone(&reuses),
                }),
            )
            .await,
        );
    }
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24);
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
        announced: vec![crate::test_support::make_route(
            prefix,
            Ipv4Addr::new(192, 0, 2, 10),
        )],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();
    for receiver in &mut receivers {
        assert_eq!(receiver.recv().await.unwrap().announce.len(), 1);
    }
    probes.store(0, Ordering::Relaxed);
    reuses.store(0, Ordering::Relaxed);

    let (reply, response) = oneshot::channel();
    tx.send(RibUpdate::ReplacePeerExportPolicies {
        replacements: peers
            .iter()
            .map(|&peer| crate::update::PeerExportPolicyReplacement {
                peer,
                export_policy: Some(next_policy.clone()),
            })
            .collect(),
        reply,
    })
    .await
    .unwrap();
    let outcome = response.await.unwrap().unwrap();
    assert_eq!(
        outcome,
        crate::update::ExportPolicyCohortOutcome::RequiresAuthoritativePerPeerApply
    );
    assert!(
        receivers
            .iter_mut()
            .all(|receiver| receiver.try_recv().is_err())
    );
    for &peer in &peers {
        assert_eq!(query_update_group(&tx, peer).await, "group:0");
    }
    assert_eq!(
        query_uncommitted_policy_transition_groups(&tx).await,
        0,
        "a fully staged destination must be removed before the fallback handoff"
    );
    assert_metric(
        gauge_metric_value(&metrics, "bgp_rib_policy_transition_in_progress", &[]),
        0.0,
        "fallback clears transition ownership",
    );
    assert!(
        gauge_metric_value(
            &metrics,
            "bgp_rib_policy_transition_last_duration_milliseconds",
            &[],
        ) < 987_000.0,
        "fallback must replace the retained terminal-duration sample"
    );
    apply_authoritative_policy_handoff(&tx, &peers, Some(next_policy.clone()), outcome).await;

    let accepted = receivers[0].recv().await.unwrap();
    assert_eq!(accepted.announce.len(), 1);
    assert!(accepted.withdraw.is_empty());
    let rejected = receivers[1].recv().await.unwrap();
    assert!(rejected.announce.is_empty());
    assert_eq!(rejected.withdraw, vec![(Prefix::V4(prefix), 0)]);

    let (stats_reply, stats_response) = oneshot::channel();
    tx.send(RibUpdate::TestQueryPolicyTransitionStats { reply: stats_reply })
        .await
        .unwrap();
    assert_eq!(stats_response.await.unwrap().0, 0);
    assert!(
        reuses.load(Ordering::Relaxed) >= 1,
        "the rejecting target must reapply its own ceiling to a proven wire-cohort length"
    );

    for &peer in &peers {
        assert_eq!(
            query_first_export_term_hits(&tx, peer).await,
            (1, 1),
            "authoritative fallback must install the destination group's actual counter instance for every grouped member"
        );
    }

    let later_prefix = Ipv4Prefix::new(Ipv4Addr::new(203, 1, 113, 0), 24);
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
        announced: vec![crate::test_support::make_route(
            later_prefix,
            Ipv4Addr::new(192, 0, 2, 10),
        )],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();
    assert_eq!(receivers[0].recv().await.unwrap().announce.len(), 1);
    for &peer in &peers {
        assert_eq!(
            query_first_export_term_hits(&tx, peer).await,
            (2, 2),
            "later evaluations must remain visible through every fallback member"
        );
    }

    // Model the peer-manager rollback after a failed outer transaction by
    // reinstalling the captured prior chain as one cohort. The prior group was
    // removed when its last member left, so this also proves a freshly rebuilt
    // rollback destination canonicalizes every member, not just its creator.
    let (rollback_reply, rollback_response) = oneshot::channel();
    tx.send(RibUpdate::ReplacePeerExportPolicies {
        replacements: peers
            .iter()
            .map(|&peer| crate::update::PeerExportPolicyReplacement {
                peer,
                export_policy: Some(old_policy.clone()),
            })
            .collect(),
        reply: rollback_reply,
    })
    .await
    .unwrap();
    let rollback_outcome = rollback_response.await.unwrap().unwrap();
    apply_authoritative_policy_handoff(&tx, &peers, Some(old_policy.clone()), rollback_outcome)
        .await;
    for receiver in &mut receivers {
        let mut rollback_updates = 0;
        while receiver.try_recv().is_ok() {
            rollback_updates += 1;
        }
        assert!(
            rollback_updates > 0,
            "rollback must reconcile every member's prior wire view"
        );
    }
    for &peer in &peers {
        assert_eq!(query_update_group(&tx, peer).await, "group:0");
        assert_eq!(
            query_first_export_term_hits(&tx, peer).await,
            (2, 2),
            "rollback must expose the rebuilt prior group's counter instance for every member"
        );
    }

    let post_rollback_prefix = Ipv4Prefix::new(Ipv4Addr::new(203, 2, 113, 0), 24);
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
        announced: vec![crate::test_support::make_route(
            post_rollback_prefix,
            Ipv4Addr::new(192, 0, 2, 10),
        )],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();
    for receiver in &mut receivers {
        assert_eq!(receiver.recv().await.unwrap().announce.len(), 1);
    }
    for peer in peers {
        assert_eq!(
            query_first_export_term_hits(&tx, peer).await,
            (3, 3),
            "post-rollback evaluations must keep every prior member's counters live"
        );
    }

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn clean_policy_transition_falls_back_wholesale_for_add_path_member() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());
    let probes = Arc::new(AtomicUsize::new(0));
    let reuses = Arc::new(AtomicUsize::new(0));
    let old_policy = community_chain(0xFDE8_0001);
    let next_policy = community_chain(0xFDE8_0002);
    let peers = [
        IpAddr::V4(Ipv4Addr::new(10, 22, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 22, 0, 2)),
    ];
    let mut receivers = Vec::new();
    for (index, peer) in peers.iter().copied().enumerate() {
        let mut spec = PeerUpSpec::ibgp(peer);
        spec.route_reflector_client = true;
        spec.export_policy = Some(old_policy.clone());
        if index == 1 {
            spec.add_path_send_max = 2;
        }
        receivers.push(
            peer_up_with_cohort_encoder(
                &tx,
                spec,
                Arc::new(CohortExactEncoder {
                    owner: u64::try_from(index + 1).unwrap(),
                    profile: 13,
                    max_len: 4_096,
                    generation: AtomicUsize::new(0),
                    advance_generation: false,
                    probes: Arc::clone(&probes),
                    reuses: Arc::clone(&reuses),
                }),
            )
            .await,
        );
    }
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 11)),
        announced: vec![crate::test_support::make_route(
            Ipv4Prefix::new(Ipv4Addr::new(203, 0, 114, 0), 24),
            Ipv4Addr::new(192, 0, 2, 11),
        )],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();
    for receiver in &mut receivers {
        assert_eq!(receiver.recv().await.unwrap().announce.len(), 1);
    }

    let (reply, response) = oneshot::channel();
    tx.send(RibUpdate::ReplacePeerExportPolicies {
        replacements: peers
            .iter()
            .map(|&peer| crate::update::PeerExportPolicyReplacement {
                peer,
                export_policy: Some(next_policy.clone()),
            })
            .collect(),
        reply,
    })
    .await
    .unwrap();
    let outcome = response.await.unwrap().unwrap();
    assert_eq!(
        outcome,
        crate::update::ExportPolicyCohortOutcome::RequiresAuthoritativePerPeerApply
    );
    apply_authoritative_policy_handoff(&tx, &peers, Some(next_policy.clone()), outcome).await;

    for receiver in &mut receivers {
        let update = receiver.recv().await.unwrap();
        assert_eq!(update.announce.len(), 1);
        assert!(update.announce[0].attributes.iter().any(|attribute| {
            matches!(attribute, PathAttribute::Communities(values) if values.contains(&0xFDE8_0002))
        }));
    }
    let (stats_reply, stats_response) = oneshot::channel();
    tx.send(RibUpdate::TestQueryPolicyTransitionStats { reply: stats_reply })
        .await
        .unwrap();
    assert_eq!(stats_response.await.unwrap().0, 0);
    assert!(
        query_update_group(&tx, peers[0])
            .await
            .starts_with("group:")
    );
    assert_eq!(query_update_group(&tx, peers[1]).await, "add_path_send");

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test(start_paused = true)]
#[expect(
    clippy::too_many_lines,
    reason = "the saturation regression verifies enqueue, dirty carry, and timer healing together"
)]
async fn clean_policy_transition_saturation_falls_back_and_heals_without_duplicates() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());
    let probes = Arc::new(AtomicUsize::new(0));
    let reuses = Arc::new(AtomicUsize::new(0));
    let old_policy = community_chain(0xFDE8_0001);
    let next_policy = community_chain(0xFDE8_0002);
    let peers = [
        IpAddr::V4(Ipv4Addr::new(10, 23, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 23, 0, 2)),
    ];
    let mut receivers = Vec::new();
    for (index, peer) in peers.iter().copied().enumerate() {
        tx.send(RibUpdate::SetPeerExportEncoder {
            peer,
            session_id: 0,
            encoder: Arc::new(CohortExactEncoder {
                owner: u64::try_from(index + 1).unwrap(),
                profile: 17,
                max_len: 4_096,
                generation: AtomicUsize::new(0),
                advance_generation: false,
                probes: Arc::clone(&probes),
                reuses: Arc::clone(&reuses),
            }),
        })
        .await
        .unwrap();
        let mut spec = PeerUpSpec::ibgp(peer);
        spec.route_reflector_client = true;
        spec.export_policy = Some(old_policy.clone());
        receivers.push(peer_up_with_capacity(&tx, spec, 1).await);
    }
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 12)),
        announced: vec![crate::test_support::make_route(
            Ipv4Prefix::new(Ipv4Addr::new(203, 0, 115, 0), 24),
            Ipv4Addr::new(192, 0, 2, 12),
        )],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();
    let first_old = receivers[0].recv().await.unwrap();
    assert_eq!(first_old.announce.len(), 1);
    // Leave the second member's old-policy announcement queued so only its
    // writer is saturated when the cohort command arrives.

    let (reply, response) = oneshot::channel();
    tx.send(RibUpdate::ReplacePeerExportPolicies {
        replacements: peers
            .iter()
            .map(|&peer| crate::update::PeerExportPolicyReplacement {
                peer,
                export_policy: Some(next_policy.clone()),
            })
            .collect(),
        reply,
    })
    .await
    .unwrap();
    let outcome = response.await.unwrap().unwrap();
    assert_eq!(
        outcome,
        crate::update::ExportPolicyCohortOutcome::RequiresAuthoritativePerPeerApply
    );
    apply_authoritative_policy_handoff(&tx, &peers, Some(next_policy.clone()), outcome).await;

    let first_new = receivers[0].recv().await.unwrap();
    assert!(first_new.announce[0].attributes.iter().any(|attribute| {
        matches!(attribute, PathAttribute::Communities(values) if values.contains(&0xFDE8_0002))
    }));
    let second_old = receivers[1].recv().await.unwrap();
    assert!(second_old.announce[0].attributes.iter().any(|attribute| {
        matches!(attribute, PathAttribute::Communities(values) if values.contains(&0xFDE8_0001))
    }));

    let (health_reply, health_response) = oneshot::channel();
    tx.send(RibUpdate::TestQueryOutboundHealth {
        reply: health_reply,
    })
    .await
    .unwrap();
    let (dirty, _, group_dirty, _, baseline, _) = health_response.await.unwrap();
    assert_eq!((dirty, group_dirty, baseline), (1, 1, 1));
    let (stats_reply, stats_response) = oneshot::channel();
    tx.send(RibUpdate::TestQueryPolicyTransitionStats { reply: stats_reply })
        .await
        .unwrap();
    assert_eq!(stats_response.await.unwrap().0, 0);

    tokio::time::advance(std::time::Duration::from_secs(1)).await;
    tokio::task::yield_now().await;
    let second_new = receivers[1].recv().await.unwrap();
    assert!(second_new.announce[0].attributes.iter().any(|attribute| {
        matches!(attribute, PathAttribute::Communities(values) if values.contains(&0xFDE8_0002))
    }));
    assert!(
        receivers[0].try_recv().is_err(),
        "the accepted member must not be replayed"
    );

    let (health_reply, health_response) = oneshot::channel();
    tx.send(RibUpdate::TestQueryOutboundHealth {
        reply: health_reply,
    })
    .await
    .unwrap();
    assert_eq!(health_response.await.unwrap(), (0, 0, 0, 0, 0, 0));

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn clean_policy_transition_generation_change_rejects_stale_plan() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());
    let probes = Arc::new(AtomicUsize::new(0));
    let reuses = Arc::new(AtomicUsize::new(0));
    let old_policy = community_chain(0xFDE8_0001);
    let next_policy = community_chain(0xFDE8_0002);
    let peers = [
        IpAddr::V4(Ipv4Addr::new(10, 24, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 24, 0, 2)),
    ];
    let mut receivers = Vec::new();
    for (index, peer) in peers.iter().copied().enumerate() {
        let mut spec = PeerUpSpec::ibgp(peer);
        spec.route_reflector_client = true;
        spec.export_policy = Some(old_policy.clone());
        receivers.push(
            peer_up_with_cohort_encoder(
                &tx,
                spec,
                Arc::new(CohortExactEncoder {
                    owner: u64::try_from(index + 1).unwrap(),
                    profile: 19,
                    max_len: 4_096,
                    generation: AtomicUsize::new(0),
                    advance_generation: true,
                    probes: Arc::clone(&probes),
                    reuses: Arc::clone(&reuses),
                }),
            )
            .await,
        );
    }
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 13)),
        announced: vec![crate::test_support::make_route(
            Ipv4Prefix::new(Ipv4Addr::new(203, 0, 116, 0), 24),
            Ipv4Addr::new(192, 0, 2, 13),
        )],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();
    for receiver in &mut receivers {
        assert_eq!(receiver.recv().await.unwrap().announce.len(), 1);
    }

    let (reply, response) = oneshot::channel();
    tx.send(RibUpdate::ReplacePeerExportPolicies {
        replacements: peers
            .iter()
            .map(|&peer| crate::update::PeerExportPolicyReplacement {
                peer,
                export_policy: Some(next_policy.clone()),
            })
            .collect(),
        reply,
    })
    .await
    .unwrap();
    let outcome = response.await.unwrap().unwrap();
    assert_eq!(
        outcome,
        crate::update::ExportPolicyCohortOutcome::RequiresAuthoritativePerPeerApply
    );
    apply_authoritative_policy_handoff(&tx, &peers, Some(next_policy.clone()), outcome).await;
    for receiver in &mut receivers {
        let update = receiver.recv().await.unwrap();
        assert!(update.announce[0].attributes.iter().any(|attribute| {
            matches!(attribute, PathAttribute::Communities(values) if values.contains(&0xFDE8_0002))
        }));
    }
    let (stats_reply, stats_response) = oneshot::channel();
    tx.send(RibUpdate::TestQueryPolicyTransitionStats { reply: stats_reply })
        .await
        .unwrap();
    assert_eq!(stats_response.await.unwrap().0, 0);

    drop(tx);
    handle.await.unwrap();
}

/// LAN-311 item 2: the withdrawal-residue gauge follows tombstones
/// held while a member is dirty and returns to zero when the resync
/// clears them — emitted at growth AND clear (the gate-metric rule),
/// so a soak slope-gate on it can actually fail.
#[tokio::test]
async fn residue_gauge_tracks_tombstones_and_clears_on_resync() {
    tokio::time::pause();
    let metrics = BgpMetrics::new();
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, metrics.clone());
    let handle = tokio::spawn(manager.run());

    let residue = || gauge_metric_value(&metrics, "bgp_update_group_residue_entries", &[]);
    let quiesce = async || {
        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(RibUpdate::QueryBestRoutes { reply: reply_tx })
            .await
            .unwrap();
        let _ = reply_rx.await.unwrap();
    };
    let send_routes = async |announced: Vec<crate::route::Route>, withdrawn: Vec<(Prefix, u32)>| {
        tx.send(RibUpdate::RoutesReceived {
            session_id: 0,
            peer: IpAddr::V4(Ipv4Addr::new(10, 0, 5, 9)),
            announced,
            withdrawn,
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
            evpn_announced: vec![],
            evpn_withdrawn: vec![],
        })
        .await
        .unwrap();
    };

    // Grouped member with a capacity-1 outbound channel so a second
    // update jams it (the wedged-writer shape from the seam sweep).
    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 5, 1));
    let (out_tx, mut out_rx) = mpsc::channel(1);
    tx.send(RibUpdate::PeerUp {
        per_client_best: false,
        session_id: 0,
        peer,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: false,
        route_reflector_client: true,
        orr_vantage: None,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: vec![],
        negotiated_llgr_families: vec![],
    })
    .await
    .unwrap();
    drain_eor(&mut out_rx).await;
    assert_eq!(query_update_group(&tx, peer).await, "group:0");

    let p1 = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 0), 24);
    let p2 = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 101, 0), 24);
    let mk = |p: Ipv4Prefix| crate::test_support::make_route(p, Ipv4Addr::new(10, 0, 5, 9));

    // p1 fills the channel; p2's emission fails → member goes dirty;
    // p1 withdrawn WHILE dirty → tombstone.
    send_routes(vec![mk(p1)], vec![]).await;
    send_routes(vec![mk(p2)], vec![]).await;
    send_routes(vec![], vec![(Prefix::V4(p1), 0)]).await;
    quiesce().await;
    assert_metric(
        residue(),
        1.0,
        "tombstone recorded while a member is dirty must show in the residue gauge",
    );

    // Free the channel and let the resync timer clear the residue.
    let jammed = out_rx.recv().await.unwrap();
    assert_eq!(jammed.announce.len(), 1, "p1 was delivered before the jam");
    tokio::time::advance(std::time::Duration::from_secs(2)).await;
    let resync = out_rx.recv().await.unwrap();
    assert!(
        resync
            .withdraw
            .iter()
            .any(|(prefix, _)| *prefix == Prefix::V4(p1)),
        "resync must (over-)withdraw the tombstoned prefix"
    );
    quiesce().await;
    assert_metric(
        residue(),
        0.0,
        "a completed resync (last dirty member) must clear the residue gauge",
    );

    drop(tx);
    handle.await.unwrap();
}

/// The withdrawal-residue gauge across a grouped→per-peer move while
/// dirty: the carried extra withdraws keep the gauge nonzero until the
/// per-peer resync EMITS them; a successful resync must then drain the
/// residue (gauge back to zero) — it must not floor at nonzero because
/// the per-peer path never consumes the carried extras.
#[tokio::test]
async fn residue_gauge_clears_after_dirty_leaver_moves_to_per_peer_path() {
    tokio::time::pause();
    let metrics = BgpMetrics::new();
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, metrics.clone());
    let handle = tokio::spawn(manager.run());

    let residue = || gauge_metric_value(&metrics, "bgp_update_group_residue_entries", &[]);
    let quiesce = async || {
        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(RibUpdate::QueryBestRoutes { reply: reply_tx })
            .await
            .unwrap();
        let _ = reply_rx.await.unwrap();
    };
    let send_routes = async |announced: Vec<crate::route::Route>, withdrawn: Vec<(Prefix, u32)>| {
        tx.send(RibUpdate::RoutesReceived {
            session_id: 0,
            peer: IpAddr::V4(Ipv4Addr::new(10, 0, 5, 9)),
            announced,
            withdrawn,
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
            evpn_announced: vec![],
            evpn_withdrawn: vec![],
        })
        .await
        .unwrap();
    };

    // Grouped member with a capacity-1 outbound channel so a second
    // update jams it.
    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 5, 1));
    let (out_tx, mut out_rx) = mpsc::channel(1);
    tx.send(RibUpdate::PeerUp {
        per_client_best: false,
        session_id: 0,
        peer,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: false,
        route_reflector_client: true,
        orr_vantage: None,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: vec![],
        negotiated_llgr_families: vec![],
    })
    .await
    .unwrap();
    drain_eor(&mut out_rx).await;
    assert_eq!(query_update_group(&tx, peer).await, "group:0");

    let p1 = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 0), 24);
    let p2 = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 101, 0), 24);
    let mk = |p: Ipv4Prefix| crate::test_support::make_route(p, Ipv4Addr::new(10, 0, 5, 9));

    // p1 fills the channel; p2's emission fails → member goes dirty;
    // p1 withdrawn WHILE dirty → tombstone.
    send_routes(vec![mk(p1)], vec![]).await;
    send_routes(vec![mk(p2)], vec![]).await;
    send_routes(vec![], vec![(Prefix::V4(p1), 0)]).await;
    quiesce().await;
    assert_metric(
        residue(),
        1.0,
        "tombstone recorded while a member is dirty must show in the residue gauge",
    );

    // The member's chain becomes peer-context-dependent: it moves to
    // the per-peer path while dirty, carrying the tombstone as an
    // extra withdraw — still residue.
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
    // Two entries: the carried tombstone (p1) plus the dirty leaver's
    // baseline key (p2) — a dirty mover's baseline rides the residue as
    // (over-)withdraw candidates instead of seeding the Adj-RIB-Out
    // (its snapshot is intended state, not wire state — LAN-346).
    assert_metric(
        residue(),
        2.0,
        "the extra withdraws carried across the move must stay in the residue gauge",
    );

    // Free the channel and let the resync timer drain the residue.
    let jammed = out_rx.recv().await.unwrap();
    assert_eq!(jammed.announce.len(), 1, "p1 was delivered before the jam");
    tokio::time::advance(std::time::Duration::from_secs(2)).await;
    quiesce().await;
    let resync = out_rx
        .try_recv()
        .expect("the per-peer resync must emit the residue withdraw");
    assert!(
        resync
            .withdraw
            .iter()
            .any(|(prefix, _)| *prefix == Prefix::V4(p1)),
        "the per-peer resync must (over-)withdraw the carried tombstoned prefix"
    );
    quiesce().await;
    assert_metric(
        residue(),
        0.0,
        "a completed per-peer resync must drain the carried residue",
    );

    drop(tx);
    handle.await.unwrap();
}

/// LAN-311 item 3 (the term-hit freeze): a content-equal chain
/// reinstall must keep the INSTALLED chain instance, not just the
/// group key. The group's staging handle shares the installed
/// instance's ADR-0096 term-hit counters (`PolicyChain::share`), so
/// swapping in a fresh content-equal instance leaves evaluations
/// landing on the group's old instance while the term-hits query
/// snapshots the new (forever-zero) one — grouped peers read frozen
/// counters. A content-CHANGED chain still installs fresh (counters
/// reset — "since install" semantics).
#[tokio::test]
async fn content_identical_replace_keeps_export_term_hit_counters() {
    async fn send_route(tx: &mpsc::Sender<RibUpdate>, source: IpAddr, prefix: Ipv4Prefix) {
        tx.send(RibUpdate::RoutesReceived {
            session_id: 0,
            peer: source,
            announced: vec![crate::test_support::make_route(
                prefix,
                Ipv4Addr::new(10, 0, 4, 9),
            )],
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
            evpn_announced: vec![],
            evpn_withdrawn: vec![],
        })
        .await
        .unwrap();
    }

    /// (total evaluations, deny-term guard hits) of the peer's
    /// installed chain instance.
    async fn hits_for(tx: &mpsc::Sender<RibUpdate>, peer: IpAddr) -> (u64, u64) {
        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(RibUpdate::QueryExportPolicyTermHits {
            peer: Some(peer),
            reply: reply_tx,
        })
        .await
        .unwrap();
        let hits = reply_rx.await.unwrap();
        assert_eq!(hits.len(), 1, "peer must report an installed chain");
        (hits[0].evals, hits[0].terms[0].hits)
    }

    let metrics = BgpMetrics::new();
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, metrics.clone());
    let handle = tokio::spawn(manager.run());

    let denied = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24);
    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 4, 1));
    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 4, 9));
    let mut spec = PeerUpSpec::ibgp(peer);
    spec.export_policy = Some(deny_chain(denied));
    let mut out_rx = peer_up(&tx, spec).await;
    assert_eq!(query_update_group(&tx, peer).await, "group:0");

    // One permitted route: the shared group staging pass evaluates the
    // chain once, through the handle sharing the installed instance's
    // counters.
    send_route(
        &tx,
        source,
        Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 0), 24),
    )
    .await;
    assert_eq!(out_rx.recv().await.unwrap().announce.len(), 1);
    assert_eq!(hits_for(&tx, peer).await, (1, 0));

    // Content-equal reinstall (fresh instance, zeroed counters — the
    // SIGHUP / txn no-op shape). The installed instance must survive.
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::ReplacePeerExportPolicy {
        peer,
        export_policy: Some(deny_chain(denied)),
        reply: reply_tx,
    })
    .await
    .unwrap();
    assert_eq!(reply_rx.await.unwrap(), Ok(()));

    send_route(
        &tx,
        source,
        Ipv4Prefix::new(Ipv4Addr::new(198, 51, 101, 0), 24),
    )
    .await;
    assert_eq!(out_rx.recv().await.unwrap().announce.len(), 1);
    assert_eq!(
        hits_for(&tx, peer).await,
        (2, 0),
        "term-hit counters must survive a content-equal reinstall and keep counting \
         (a frozen/zero reading means the query snapshots a fresh instance while the \
         group keeps evaluating the old one)"
    );

    // The denied prefix evaluates (and matches the deny term) without
    // emitting — still on the surviving instance. The query rides the
    // same serial channel, so its reply proves the route was staged.
    send_route(&tx, source, denied).await;
    assert_eq!(hits_for(&tx, peer).await, (3, 1));

    // A content-CHANGED chain installs fresh: the peer regroups and the
    // query snapshots the NEW instance — the join-time table rebuild
    // re-evaluates the three staged prefixes (evals 3) but the old
    // instance's deny-term history is gone (its deny matches nothing
    // in the table), pinning "reset on material change".
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::ReplacePeerExportPolicy {
        peer,
        export_policy: Some(deny_chain(Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, 0), 24))),
        reply: reply_tx,
    })
    .await
    .unwrap();
    assert_eq!(reply_rx.await.unwrap(), Ok(()));
    assert_eq!(query_update_group(&tx, peer).await, "group:1");
    assert_eq!(
        hits_for(&tx, peer).await,
        (3, 0),
        "a content-changed install must evaluate through a fresh instance \
         (rebuild evals only; no carried deny-term history)"
    );

    drop(tx);
    handle.await.unwrap();
}

/// Strict next-hop (`route.next-hop == peer.address`, rpol) reads peer
/// identity, so an EXPORT chain carrying it must disqualify the peer
/// from update-group membership (`policy_peer_context`). The other
/// direction of the matrix — the same policy on an IMPORT chain — is
/// grouping-irrelevant by construction: import chains are applied at
/// session ingress and never enter the fingerprint (`PeerUp` carries
/// only `export_policy`), so a peer whose import policy uses strict
/// next-hop still groups normally.
#[tokio::test]
async fn strict_next_hop_export_chain_disqualifies_grouping() {
    use std::sync::Arc;

    use rustbgpd_policy::NamedPolicy;
    use rustbgpd_policy::rpol::RpolFile;
    use rustbgpd_policy::sets::SetStore;

    fn rpol_chain(source: &str, name: &str) -> PolicyChain {
        let mut store = SetStore::new();
        let compiled = RpolFile::parse(source)
            .expect("clean rpol")
            .compile_policy(name, &[], &mut store)
            .expect("policy exists");
        PolicyChain::from_named(vec![NamedPolicy::from_rpol(
            name.to_string(),
            Arc::new(compiled),
        )])
    }

    let strict_nh = "policy strict-nh {
        term nh { if route.next-hop == peer.address { reject } }
        term rest { accept }
    }";
    let plain = "policy plain {
        term nh { if route.next-hop == 192.0.2.99 { reject } }
        term rest { accept }
    }";

    let metrics = BgpMetrics::new();
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, metrics.clone());
    let handle = tokio::spawn(manager.run());

    let strict_peer = IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1));
    let plain_a = IpAddr::V4(Ipv4Addr::new(10, 0, 2, 2));
    let plain_b = IpAddr::V4(Ipv4Addr::new(10, 0, 2, 3));

    let mut spec = PeerUpSpec::ibgp(strict_peer);
    spec.export_policy = Some(rpol_chain(strict_nh, "strict-nh"));
    let _rx1 = peer_up(&tx, spec).await;

    // Content-equal non-strict chains group together.
    for peer in [plain_a, plain_b] {
        let mut spec = PeerUpSpec::ibgp(peer);
        spec.export_policy = Some(rpol_chain(plain, "plain"));
        let _rx = peer_up(&tx, spec).await;
    }

    assert_eq!(
        query_update_group(&tx, strict_peer).await,
        "policy_peer_context"
    );
    let group_a = query_update_group(&tx, plain_a).await;
    assert!(
        group_a.starts_with("group:"),
        "plain peer must group: {group_a}"
    );
    assert_eq!(query_update_group(&tx, plain_b).await, group_a);

    drop(tx);
    handle.await.unwrap();
}

/// LAN-295: family predicates are route-context-only — an export chain
/// matching `route.family` reads no peer identity, so content-equal
/// chains using it must still group (unlike peer-dependent predicates,
/// which fall back to `policy_peer_context`).
#[tokio::test]
async fn family_predicate_export_chain_still_groups() {
    use std::sync::Arc;

    use rustbgpd_policy::NamedPolicy;
    use rustbgpd_policy::rpol::RpolFile;
    use rustbgpd_policy::sets::SetStore;

    fn rpol_chain(source: &str, name: &str) -> PolicyChain {
        let mut store = SetStore::new();
        let compiled = RpolFile::parse(source)
            .expect("clean rpol")
            .compile_policy(name, &[], &mut store)
            .expect("policy exists");
        PolicyChain::from_named(vec![NamedPolicy::from_rpol(
            name.to_string(),
            Arc::new(compiled),
        )])
    }

    let family_gate = "policy family-gate {
        term v4-only { if route.family != ipv4-unicast { reject } }
        term rest { accept }
    }";

    let metrics = BgpMetrics::new();
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, metrics.clone());
    let handle = tokio::spawn(manager.run());

    let peer_a = IpAddr::V4(Ipv4Addr::new(10, 0, 3, 1));
    let peer_b = IpAddr::V4(Ipv4Addr::new(10, 0, 3, 2));
    for peer in [peer_a, peer_b] {
        let mut spec = PeerUpSpec::ibgp(peer);
        spec.export_policy = Some(rpol_chain(family_gate, "family-gate"));
        let _rx = peer_up(&tx, spec).await;
    }

    let group_a = query_update_group(&tx, peer_a).await;
    assert!(
        group_a.starts_with("group:"),
        "a family-predicate chain must not disqualify grouping: {group_a}"
    );
    assert_eq!(query_update_group(&tx, peer_b).await, group_a);

    drop(tx);
    handle.await.unwrap();
}

/// LAN-296: computed prepend operands and update-group eligibility —
/// the second level of the proof (`requires_peer_context` at the chain
/// level is pinned in `crates/policy/src/rpol/tests.rs`). A
/// `prepend as peer` export chain reads peer identity, so its peers
/// fall back to `policy_peer_context` (defense in depth: config
/// attachment rejects such chains on export outright — this pins the
/// fingerprint for chains installed through other paths). `prepend as
/// self` / `prepend as origin` are chain/route-context-only and must
/// still group.
#[tokio::test]
async fn computed_prepend_export_chains_group_unless_peer_dependent() {
    use std::sync::Arc;

    use rustbgpd_policy::NamedPolicy;
    use rustbgpd_policy::rpol::RpolFile;
    use rustbgpd_policy::sets::SetStore;

    fn rpol_chain(source: &str, name: &str) -> PolicyChain {
        let mut store = SetStore::new();
        let compiled = RpolFile::parse(source)
            .expect("clean rpol")
            .compile_policy(name, &[], &mut store)
            .expect("policy exists");
        PolicyChain::from_named(vec![NamedPolicy::from_rpol(
            name.to_string(),
            Arc::new(compiled),
        )])
    }

    let self_pad = "policy self-pad { term t { prepend as self 3; accept } }";
    let origin_pad = "policy origin-pad { term t { prepend as origin 2; accept } }";
    let peer_pad = "policy peer-pad { term t { prepend as peer 3; accept } }";

    let metrics = BgpMetrics::new();
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, metrics.clone());
    let handle = tokio::spawn(manager.run());

    // Two peers sharing a `prepend as self` chain and two sharing a
    // `prepend as origin` chain: both pairs must group.
    let self_a = IpAddr::V4(Ipv4Addr::new(10, 0, 4, 1));
    let self_b = IpAddr::V4(Ipv4Addr::new(10, 0, 4, 2));
    for peer in [self_a, self_b] {
        let mut spec = PeerUpSpec::ibgp(peer);
        spec.export_policy = Some(rpol_chain(self_pad, "self-pad"));
        let _rx = peer_up(&tx, spec).await;
    }
    let origin_a = IpAddr::V4(Ipv4Addr::new(10, 0, 4, 3));
    let origin_b = IpAddr::V4(Ipv4Addr::new(10, 0, 4, 4));
    for peer in [origin_a, origin_b] {
        let mut spec = PeerUpSpec::ibgp(peer);
        spec.export_policy = Some(rpol_chain(origin_pad, "origin-pad"));
        let _rx = peer_up(&tx, spec).await;
    }
    // A `prepend as peer` chain disqualifies its peer from grouping.
    let peer_dep = IpAddr::V4(Ipv4Addr::new(10, 0, 4, 5));
    let mut spec = PeerUpSpec::ibgp(peer_dep);
    spec.export_policy = Some(rpol_chain(peer_pad, "peer-pad"));
    let _rx = peer_up(&tx, spec).await;

    let self_group = query_update_group(&tx, self_a).await;
    assert!(
        self_group.starts_with("group:"),
        "`prepend as self` must not disqualify grouping: {self_group}"
    );
    assert_eq!(query_update_group(&tx, self_b).await, self_group);

    let origin_group = query_update_group(&tx, origin_a).await;
    assert!(
        origin_group.starts_with("group:"),
        "`prepend as origin` must not disqualify grouping: {origin_group}"
    );
    assert_eq!(query_update_group(&tx, origin_b).await, origin_group);

    assert_eq!(
        query_update_group(&tx, peer_dep).await,
        "policy_peer_context",
        "`prepend as peer` must register as peer-dependent"
    );

    drop(tx);
    handle.await.unwrap();
}

/// LAN-210: a grouped member's export-policy counters must not drift
/// from an otherwise-identical ungrouped peer's across a dirty resync.
/// Before the fix the dirty-resync distribution pass replayed the group
/// table to the wire but never re-recorded the per-member counters
/// (`apply_group_policy_counters` was `!resync`-gated, and the join
/// replay only ran from lifecycle/route-refresh paths), while the
/// ungrouped per-prefix path re-records every entry on resync.
#[tokio::test]
async fn grouped_and_ungrouped_export_counters_match_after_dirty_resync() {
    tokio::time::pause();

    let metrics = BgpMetrics::new();
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, metrics.clone());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let grouped = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let ungrouped = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
    // Unresolved ORR vantage: disqualifies grouping but leaves
    // single-best selection and the permit-all verdict untouched, so the
    // two peers must report identical counters at every step.
    let vantage = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
    let prefix1 = Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, 0), 24);
    let prefix2 = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 0), 24);

    // Capacity-1 channels so the second announce can't fit and drives the
    // dirty-resync path.
    let (g_tx, mut g_rx) = mpsc::channel(1);
    let (u_tx, mut u_rx) = mpsc::channel(1);
    for (peer, out_tx, vantage) in [(grouped, g_tx, None), (ungrouped, u_tx, Some(vantage))] {
        tx.send(RibUpdate::PeerUp {
            per_client_best: false,
            session_id: 0,
            peer,
            peer_asn: 65000,
            peer_router_id: Ipv4Addr::UNSPECIFIED,
            outbound_tx: out_tx,
            export_policy: None,
            sendable_families: ipv4_sendable(),
            is_ebgp: true,
            route_reflector_client: false,
            orr_vantage: vantage,
            add_path_send_families: vec![],
            add_path_send_max: 0,
            negotiated_orf_recv: Vec::new(),
            negotiated_llgr_families: Vec::new(),
        })
        .await
        .unwrap();
    }
    drain_eor(&mut g_rx).await;
    drain_eor(&mut u_rx).await;
    assert_eq!(query_update_group(&tx, grouped).await, "group:0");
    assert_eq!(query_update_group(&tx, ungrouped).await, "orr_vantage");

    // First route fits both channels; the second can't, marking both
    // peers dirty. Neither is drained yet.
    for prefix in [prefix1, prefix2] {
        tx.send(RibUpdate::RoutesReceived {
            session_id: 0,
            peer: source,
            announced: vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 1))],
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
            evpn_announced: vec![],
            evpn_withdrawn: vec![],
        })
        .await
        .unwrap();
    }
    // Serialize past both distribution passes.
    let _ = query_best_routes(&tx).await;

    let pre_grouped = query_neighbor_policy_stats(&tx, grouped).await;
    let pre_ungrouped = query_neighbor_policy_stats(&tx, ungrouped).await;
    assert_eq!(
        pre_grouped.export_policy_routes_permitted, pre_ungrouped.export_policy_routes_permitted,
        "grouped/ungrouped counters must already agree pre-resync"
    );
    assert!(pre_grouped.export_policy_routes_permitted > 0);

    // Drain the stuck first announce so the resync has room, then fire
    // the dirty-resync timer.
    let _ = g_rx.recv().await.unwrap();
    let _ = u_rx.recv().await.unwrap();
    tokio::time::advance(Duration::from_secs(2)).await;
    // The resync delivers the previously-dropped prefix2 to both peers.
    let _ = g_rx.recv().await.unwrap();
    let _ = u_rx.recv().await.unwrap();

    let post_grouped = query_neighbor_policy_stats(&tx, grouped).await;
    let post_ungrouped = query_neighbor_policy_stats(&tx, ungrouped).await;
    assert!(
        post_ungrouped.export_policy_routes_permitted
            > pre_ungrouped.export_policy_routes_permitted,
        "sanity: ungrouped peer must re-record its table on resync"
    );
    assert_eq!(
        post_grouped.export_policy_routes_permitted, post_ungrouped.export_policy_routes_permitted,
        "grouped peer must re-record export counters on dirty resync (LAN-210)"
    );
    assert_eq!(
        post_grouped.export_policy_routes_denied,
        post_ungrouped.export_policy_routes_denied,
    );

    drop(tx);
    handle.await.unwrap();
}
