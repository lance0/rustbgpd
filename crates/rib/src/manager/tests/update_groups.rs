//! Shadow-mode update-group fingerprint registry (slice 1): membership
//! labels, gauges, ungrouped reasons, and — the risk-3 property — key
//! stability under a content-identical export-policy reinstall.

use std::any::Any;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

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

struct IngestReadinessProbe {
    readiness_tx: mpsc::Sender<crate::update::RibReadinessQuery>,
    reply: Mutex<Option<oneshot::Receiver<Result<usize, crate::update::RibReadinessError>>>>,
    probes: AtomicUsize,
    answered_before_later_probe: AtomicBool,
}

struct IngestReadinessEncoder {
    owner: u64,
    probe: Arc<IngestReadinessProbe>,
}

struct IngestReadinessSnapshot {
    owner: u64,
    probe: Arc<IngestReadinessProbe>,
}

impl crate::update::ExactExportSnapshot for IngestReadinessSnapshot {
    fn owner_id(&self) -> u64 {
        self.owner
    }

    fn generation(&self) -> u64 {
        1
    }

    fn probe_announcement(
        &self,
        _candidate: crate::update::ExactExportCandidate<'_>,
    ) -> Result<crate::update::ExactExportResult, crate::update::ExactExportError> {
        let probe_index = self.probe.probes.fetch_add(1, Ordering::Relaxed);
        let mut reply = self.probe.reply.lock().unwrap();
        if probe_index == 0 {
            let (reply_tx, reply_rx) = oneshot::channel();
            self.probe
                .readiness_tx
                .try_send(crate::update::RibReadinessQuery::LocRibCount { reply: reply_tx })
                .unwrap();
            *reply = Some(reply_rx);
        } else if let Some(reply) = reply.as_mut()
            && matches!(reply.try_recv(), Ok(Ok(1)))
        {
            self.probe
                .answered_before_later_probe
                .store(true, Ordering::Relaxed);
        }
        Ok(crate::update::ExactExportResult {
            encoded_len: 64,
            max_len: 4_096,
            generation: 1,
        })
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl crate::update::ExactExportEncoder for IngestReadinessEncoder {
    fn owner_id(&self) -> u64 {
        self.owner
    }

    fn snapshot(&self) -> Arc<dyn crate::update::ExactExportSnapshot> {
        Arc::new(IngestReadinessSnapshot {
            owner: self.owner,
            probe: Arc::clone(&self.probe),
        })
    }
}

/// Load-bearing regression: deleting the ingest-only readiness drain from the
/// outbound peer boundary leaves the query queued when the second real
/// exact-export probe runs, so `answered_before_later_probe` stays false and
/// this test goes red.
#[test]
#[expect(
    clippy::too_many_lines,
    reason = "the regression keeps the mixed fanout setup and mid-pass observation together"
)]
fn ordinary_ingest_services_readiness_mid_mixed_fanout() {
    const GROUPED_PEERS: usize = 4;
    const FALLBACK_PEERS: usize = 2;
    let (_tx, rx) = mpsc::channel(1);
    let (query_tx, query_rx) = mpsc::channel(1);
    let (readiness_tx, readiness_rx) = mpsc::channel(8);
    let mut manager = RibManager::new(rx, query_rx, None, None, BgpMetrics::new())
        .with_readiness_queries(readiness_rx);
    let (general_reply, mut general_response) = oneshot::channel();
    query_tx
        .try_send(RibUpdate::QueryLocRibCount {
            reply: general_reply,
        })
        .unwrap();
    let probe = Arc::new(IngestReadinessProbe {
        readiness_tx,
        reply: Mutex::new(None),
        probes: AtomicUsize::new(0),
        answered_before_later_probe: AtomicBool::new(false),
    });
    let grouped_probes = Arc::new(AtomicUsize::new(0));
    let grouped_reuses = Arc::new(AtomicUsize::new(0));
    let mut peers = Vec::new();
    let mut receivers = Vec::new();

    for index in 0..GROUPED_PEERS + FALLBACK_PEERS {
        let peer = IpAddr::V4(Ipv4Addr::new(10, 51, 0, u8::try_from(index + 1).unwrap()));
        peers.push(peer);
        let encoder: Arc<dyn crate::update::ExactExportEncoder> = if index < GROUPED_PEERS {
            Arc::new(CohortExactEncoder {
                owner: u64::try_from(index + 1).unwrap(),
                profile: 51,
                max_len: 4_096,
                generation: AtomicUsize::new(0),
                advance_generation: false,
                probes: Arc::clone(&grouped_probes),
                reuses: Arc::clone(&grouped_reuses),
            })
        } else {
            Arc::new(IngestReadinessEncoder {
                owner: u64::try_from(index + 1).unwrap(),
                probe: Arc::clone(&probe),
            })
        };
        manager.handle_update(RibUpdate::SetPeerExportEncoder {
            peer,
            session_id: 0,
            encoder,
        });
        let (outbound_tx, mut outbound_rx) = mpsc::channel(8);
        manager.handle_update(RibUpdate::PeerUp {
            peer,
            session_id: 0,
            peer_asn: 65_000,
            peer_router_id: Ipv4Addr::UNSPECIFIED,
            outbound_tx,
            export_policy: (index >= GROUPED_PEERS).then(peer_context_chain),
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
        assert_eq!(outbound_rx.try_recv().unwrap().end_of_rib, ipv4_sendable());
        receivers.push(outbound_rx);
    }

    assert!(
        peers[..GROUPED_PEERS]
            .iter()
            .all(|peer| manager.grouped_member_of(*peer).is_some())
    );
    assert!(peers[GROUPED_PEERS..].iter().all(|peer| matches!(
        manager.update_groups.membership(*peer),
        Some(crate::manager::update_groups::GroupMembership::PolicyPeerContext)
    )));

    let source_v4 = Ipv4Addr::new(192, 0, 2, 51);
    let source = IpAddr::V4(source_v4);
    manager.handle_update(RibUpdate::RoutesReceived {
        peer: source,
        session_id: 0,
        announced: vec![crate::test_support::make_route(
            Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24),
            source_v4,
        )],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    });
    while manager.process_next_route_chunk() {}

    assert_eq!(
        probe.probes.load(Ordering::Relaxed),
        FALLBACK_PEERS,
        "both peer-context fallback peers took a real exact-export probe"
    );
    assert_eq!(
        grouped_probes.load(Ordering::Relaxed),
        1,
        "the grouped peers shared one real exact-export probe"
    );
    assert_eq!(
        grouped_reuses.load(Ordering::Relaxed),
        GROUPED_PEERS - 1,
        "every later grouped peer reused the shared probe result"
    );
    assert!(
        probe.answered_before_later_probe.load(Ordering::Relaxed),
        "readiness reply must arrive after fanout starts and before a later peer is probed"
    );
    assert!(
        matches!(
            general_response.try_recv(),
            Err(oneshot::error::TryRecvError::Empty)
        ),
        "ordinary queries must remain fenced during the ingest fanout"
    );
    for receiver in &mut receivers {
        assert_eq!(receiver.try_recv().unwrap().announce.len(), 1);
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
    peer_asn: u32,
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
            peer_asn: 65000,
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
        interpret_rfc1997: true,
        session_id: 0,
        peer: spec.peer,
        peer_asn: spec.peer_asn,
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

#[derive(Debug, PartialEq, Eq)]
struct ExactUpdateSemantic {
    snapshot: Option<(u64, u64)>,
    payload: String,
}
fn exact_update_semantic(update: &OutboundRouteUpdate) -> ExactUpdateSemantic {
    let snapshot = update
        .exact_export_snapshot
        .as_ref()
        .map(|snapshot| (snapshot.owner_id(), snapshot.generation()));
    ExactUpdateSemantic {
        snapshot,
        payload: format!(
            "{:?}|{:?}|{:?}|{:?}|{:?}|{:?}|{:?}|{:?}|{:?}|{:?}|{:?}|{:?}|{:?}|{:?}|{:?}|{:?}|{:?}|{:?}|{:?}|{}",
            update.announce_source_exclusion,
            update.announce,
            update.withdraw,
            update.end_of_rib,
            update.refresh_markers,
            update.next_hop_override,
            update.flowspec_announce,
            update.flowspec_withdraw,
            update.evpn_announce,
            update.evpn_withdraw,
            update.bgpls_announce,
            update.bgpls_withdraw,
            update.vpn_announce,
            update.vpn_withdraw,
            update.labeled_announce,
            update.labeled_withdraw,
            update.rtc_announce,
            update.rtc_withdraw,
            update.otc_blocked,
            update.request_refresh_all_negotiated,
        ),
    }
}
#[derive(Debug, PartialEq, Eq)]
struct ExactPrecommitState {
    updates: [ExactUpdateSemantic; 2],
    overlays: [HashSet<ExactExportKey>; 2],
    advertised: [Vec<String>; 2],
    groups: [Option<usize>; 2],
}

fn register_direct_exact_peer(
    manager: &mut RibManager,
    peer: IpAddr,
    encoder: Arc<dyn crate::update::ExactExportEncoder>,
) -> mpsc::Receiver<OutboundRouteUpdate> {
    manager.handle_update(RibUpdate::SetPeerExportEncoder {
        peer,
        session_id: 0,
        encoder,
    });
    let (outbound_tx, mut outbound_rx) = mpsc::channel(8);
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
    let eor = outbound_rx.try_recv().unwrap();
    assert_eq!(eor.end_of_rib, ipv4_sendable());
    outbound_rx
}

fn register_direct_peer(
    manager: &mut RibManager,
    peer: IpAddr,
) -> mpsc::Receiver<OutboundRouteUpdate> {
    register_direct_peer_with_families(manager, peer, ipv4_sendable())
}

fn register_direct_peer_with_families(
    manager: &mut RibManager,
    peer: IpAddr,
    sendable_families: Vec<(Afi, Safi)>,
) -> mpsc::Receiver<OutboundRouteUpdate> {
    let (outbound_tx, outbound_rx) = mpsc::channel(8);
    manager.handle_update(RibUpdate::PeerUp {
        peer,
        session_id: 0,
        peer_asn: 65_000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx,
        export_policy: None,
        sendable_families,
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
    outbound_rx
}

fn distribute_direct_routes(
    manager: &mut RibManager,
    source: Ipv4Addr,
    prefixes: impl IntoIterator<Item = Ipv4Prefix>,
) {
    manager.handle_update(RibUpdate::RoutesReceived {
        peer: IpAddr::V4(source),
        session_id: 0,
        announced: prefixes
            .into_iter()
            .map(|prefix| crate::test_support::make_route(prefix, source))
            .collect(),
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    });
    while manager.process_next_route_chunk() {}
}

fn distribute_direct_route(manager: &mut RibManager, source: Ipv4Addr, prefix: Ipv4Prefix) {
    distribute_direct_routes(manager, source, [prefix]);
}

#[test]
fn distribution_clones_metrics_once_per_pass() {
    const PEERS: usize = 4;

    let (_tx, rx) = mpsc::channel(1);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let mut outbound = Vec::with_capacity(PEERS);
    for index in 0..PEERS {
        let host = u8::try_from(index + 1).expect("four peers fit in an IPv4 host octet");
        let peer = IpAddr::V4(Ipv4Addr::new(10, 63, 2, host));
        let mut receiver = register_direct_peer(&mut manager, peer);
        assert_eq!(receiver.try_recv().unwrap().end_of_rib, ipv4_sendable());
        assert!(manager.grouped_member_of(peer).is_some());
        outbound.push(receiver);
    }

    manager.adj_rib_out_commit_stats = AdjRibOutCommitStats::default();
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 116, 0), 24);
    distribute_direct_route(&mut manager, Ipv4Addr::new(192, 0, 2, 6), prefix);

    // Load-bearing proof: moving the production clone back inside the peer
    // loop makes this read four and fails the assertion.
    assert_eq!(manager.adj_rib_out_commit_stats.metrics_handle_clones, 1);
    assert_eq!(manager.adj_rib_out_commit_stats.successful_commits, PEERS);
    assert_eq!(manager.adj_rib_out_commit_stats.successful_enqueues, PEERS);
    for receiver in &mut outbound {
        let update = receiver.try_recv().unwrap();
        assert_eq!(update.announce.len(), 1);
        assert_eq!(update.announce[0].prefix, Prefix::V4(prefix));
        assert!(matches!(
            receiver.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
    }
}

#[test]
fn distribution_skips_pristine_otc_prefix_visits() {
    const PEERS: usize = 4;
    const CHANGED: usize = 64;

    let (_tx, rx) = mpsc::channel(1);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let mut outbound = Vec::with_capacity(PEERS);
    for index in 0..PEERS {
        let host = u8::try_from(index + 1).expect("four peers fit in an IPv4 host octet");
        let peer = IpAddr::V4(Ipv4Addr::new(10, 63, 2, host));
        let mut receiver = register_direct_peer(&mut manager, peer);
        assert_eq!(receiver.try_recv().unwrap().end_of_rib, ipv4_sendable());
        assert!(manager.grouped_member_of(peer).is_some());
        outbound.push(receiver);
    }

    manager.adj_rib_out_commit_stats = AdjRibOutCommitStats::default();
    let prefixes: Vec<_> = (0..CHANGED)
        .map(|index| {
            let octet = u8::try_from(index).expect("64 prefixes fit in one IPv4 octet");
            Ipv4Prefix::new(Ipv4Addr::new(203, 0, octet, 0), 24)
        })
        .collect();
    distribute_direct_routes(
        &mut manager,
        Ipv4Addr::new(192, 0, 2, 6),
        prefixes.iter().copied(),
    );

    // Load-bearing proof: moving the production clone back inside the peer
    // loop makes this read four and fails the assertion.
    assert_eq!(manager.adj_rib_out_commit_stats.metrics_handle_clones, 1);
    // Load-bearing proof: removing the production early return makes this
    // read CHANGED * PEERS and fails the assertion.
    assert_eq!(
        manager.adj_rib_out_commit_stats.otc_reconcile_prefix_visits,
        0
    );
    assert!(manager.peer_otc_blocked.is_empty());
    assert!(manager.pending_otc_blocked.is_empty());
    assert_eq!(manager.adj_rib_out_commit_stats.successful_commits, PEERS);
    assert_eq!(manager.adj_rib_out_commit_stats.successful_enqueues, PEERS);
    for receiver in &mut outbound {
        let update = receiver.try_recv().unwrap();
        assert_eq!(update.announce.len(), CHANGED);
        assert_eq!(
            update
                .announce
                .iter()
                .map(|route| route.prefix)
                .collect::<HashSet<_>>(),
            prefixes
                .iter()
                .copied()
                .map(Prefix::V4)
                .collect::<HashSet<_>>()
        );
        assert!(matches!(
            receiver.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
    }
}

#[test]
fn otc_reconcile_non_pristine_state_uses_prefix_loop_and_clears_exactly() {
    let (_tx, rx) = mpsc::channel(1);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let peer = IpAddr::V4(Ipv4Addr::new(10, 63, 3, 1));
    let prefix = Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24));
    let route = crate::test_support::make_route(
        Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24),
        Ipv4Addr::new(192, 0, 2, 7),
    );
    let identity = (route.prefix, route.path_id);
    let affected = HashSet::from([prefix]);

    manager.reconcile_peer_otc_blocked(peer, &affected, vec![route.clone()]);

    assert_eq!(
        manager.adj_rib_out_commit_stats.otc_reconcile_prefix_visits,
        1
    );
    assert_eq!(
        manager.peer_otc_blocked[&peer][&prefix],
        HashSet::from([route.path_id])
    );
    let pending = &manager.pending_otc_blocked[&peer][&identity];
    assert_eq!(pending.prefix, route.prefix);
    assert_eq!(pending.path_id, route.path_id);
    assert_eq!(pending.next_hop, route.next_hop);

    manager.reconcile_peer_otc_blocked(peer, &affected, vec![]);

    assert_eq!(
        manager.adj_rib_out_commit_stats.otc_reconcile_prefix_visits,
        2
    );
    assert!(!manager.peer_otc_blocked.contains_key(&peer));
    assert!(!manager.pending_otc_blocked.contains_key(&peer));
}

#[test]
fn grouped_peer_private_unicast_stays_unallocated_during_distribution() {
    let (_tx, rx) = mpsc::channel(1);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let peer = IpAddr::V4(Ipv4Addr::new(10, 63, 1, 1));
    let mut outbound = register_direct_peer(&mut manager, peer);
    assert_eq!(outbound.try_recv().unwrap().end_of_rib, ipv4_sendable());
    assert!(manager.grouped_member_of(peer).is_some());

    let prefix = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24);
    distribute_direct_route(&mut manager, Ipv4Addr::new(192, 0, 2, 1), prefix);

    let update = outbound.try_recv().unwrap();
    assert_eq!(update.announce.len(), 1);
    assert_eq!(update.announce[0].prefix, Prefix::V4(prefix));
    assert_eq!(manager.grouped_advertised_routes(peer).unwrap().len(), 1);
    let private = manager
        .adj_ribs_out
        .get(&peer)
        .expect("private family state");
    assert_eq!(private.len(), 0);
    assert_eq!(private.bench_route_capacity(), 0);
}

#[test]
fn grouped_late_join_private_unicast_stays_unallocated_during_initial_dump() {
    let (_tx, rx) = mpsc::channel(1);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 114, 0), 24);
    distribute_direct_route(&mut manager, Ipv4Addr::new(192, 0, 2, 2), prefix);

    let peer = IpAddr::V4(Ipv4Addr::new(10, 63, 1, 2));
    let mut outbound = register_direct_peer(&mut manager, peer);
    let dump = outbound.try_recv().unwrap();
    assert_eq!(dump.announce.len(), 1);
    assert_eq!(dump.announce[0].prefix, Prefix::V4(prefix));
    assert_eq!(outbound.try_recv().unwrap().end_of_rib, ipv4_sendable());
    assert!(manager.grouped_member_of(peer).is_some());
    assert_eq!(manager.grouped_advertised_routes(peer).unwrap().len(), 1);
    let private = manager
        .adj_ribs_out
        .get(&peer)
        .expect("private family state");
    assert_eq!(private.len(), 0);
    assert_eq!(private.bench_route_capacity(), 0);
}

#[test]
fn grouped_peer_non_unicast_first_delta_keeps_private_unicast_unallocated() {
    let (_tx, rx) = mpsc::channel(1);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 115, 0), 24);
    distribute_direct_route(&mut manager, Ipv4Addr::new(192, 0, 2, 3), prefix);
    assert_eq!(manager.loc_rib.len(), 1);

    let peer = IpAddr::V4(Ipv4Addr::new(10, 63, 1, 3));
    let mut outbound =
        register_direct_peer_with_families(&mut manager, peer, ipv4_flowspec_sendable());
    assert_eq!(
        outbound.try_recv().unwrap().end_of_rib,
        ipv4_flowspec_sendable()
    );
    assert!(manager.grouped_member_of(peer).is_some());

    let (reply_tx, _reply_rx) = oneshot::channel();
    manager.handle_inject_flowspec(make_flowspec_route(Ipv4Addr::new(192, 0, 2, 4)), reply_tx);

    let update = outbound.try_recv().unwrap();
    assert_eq!(update.flowspec_announce.len(), 1);
    let private = manager
        .adj_ribs_out
        .get(&peer)
        .expect("private non-unicast family state");
    assert_eq!(private.flowspec_len(), 1);
    assert_eq!(private.len(), 0);
    assert_eq!(private.bench_route_capacity(), 0);
}

#[test]
fn grouped_peer_ungroup_seeds_private_advertised_routes() {
    let (_tx, rx) = mpsc::channel(1);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let peer = IpAddr::V4(Ipv4Addr::new(10, 63, 1, 4));
    let mut outbound = register_direct_peer(&mut manager, peer);
    assert_eq!(outbound.try_recv().unwrap().end_of_rib, ipv4_sendable());
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 115, 0), 24);
    distribute_direct_route(&mut manager, Ipv4Addr::new(192, 0, 2, 5), prefix);
    assert_eq!(outbound.try_recv().unwrap().announce.len(), 1);

    manager.handle_update(RibUpdate::PeerSlowState {
        peer,
        session_id: 0,
        slow: true,
    });
    while manager.process_next_route_chunk() {}

    assert!(manager.grouped_member_of(peer).is_none());
    let private = manager
        .adj_ribs_out
        .get(&peer)
        .expect("private fallback state");
    assert_eq!(private.len(), 1);
    assert!(private.get(&Prefix::V4(prefix), 0).is_some());
    assert!(matches!(
        outbound.try_recv(),
        Err(mpsc::error::TryRecvError::Empty)
    ));
}

fn drive_exact_precommit_step(
    manager: &mut RibManager,
    peers: [IpAddr; 2],
    receivers: &mut [mpsc::Receiver<OutboundRouteUpdate>; 2],
    source: IpAddr,
    route: Route,
) -> (ExactPrecommitState, u64) {
    let hits_before = manager.test_exact_export_fast_path_hits;
    manager.handle_update(RibUpdate::RoutesReceived {
        peer: source,
        session_id: 0,
        announced: vec![route],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    });
    while manager.process_next_route_chunk() {}
    let updates = receivers
        .each_mut()
        .map(|receiver| exact_update_semantic(&receiver.try_recv().unwrap()));
    let rejected = &manager.peer_unexportable;
    let overlays = peers.map(|peer| rejected.get(&peer).cloned().unwrap_or_default());
    let advertised = peers.map(|peer| {
        manager
            .grouped_advertised_routes(peer)
            .expect("both targets remain grouped")
            .iter()
            .map(|route| format!("{route:?}"))
            .collect()
    });
    let groups = peers.map(|peer| manager.grouped_member_of(peer));
    let state = ExactPrecommitState {
        updates,
        overlays,
        advertised,
        groups,
    };
    (
        state,
        manager.test_exact_export_fast_path_hits - hits_before,
    )
}

fn run_exact_precommit_differential(
    force_slow: bool,
    routes: &[Route; 3],
) -> Vec<(ExactPrecommitState, u64)> {
    let (_tx, rx) = mpsc::channel(1);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    manager.test_force_exact_export_slow_path = force_slow;
    let peers = [
        IpAddr::V4(Ipv4Addr::new(10, 90, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 90, 0, 2)),
    ];
    let probes = Arc::new(AtomicUsize::new(0));
    let reuses = Arc::new(AtomicUsize::new(0));
    let mut receivers = peers.map(|peer| {
        let limited = peer == peers[1];
        register_direct_exact_peer(
            &mut manager,
            peer,
            Arc::new(CohortExactEncoder {
                owner: if limited { 2 } else { 1 },
                profile: 90,
                max_len: if limited { 128 } else { 4_096 },
                generation: AtomicUsize::new(0),
                advance_generation: false,
                probes: Arc::clone(&probes),
                reuses: Arc::clone(&reuses),
            }),
        )
    });
    let source = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 90));
    routes
        .iter()
        .cloned()
        .map(|route| drive_exact_precommit_step(&mut manager, peers, &mut receivers, source, route))
        .collect()
}

fn assert_plain_unicast_update(
    actual: &ExactUpdateSemantic,
    owner: u64,
    announce: Vec<Route>,
    withdraw: Vec<(Prefix, u32)>,
) {
    let expected = exact_update_semantic(&OutboundRouteUpdate {
        next_hop_override: vec![None; announce.len()].into(),
        announce: announce.into(),
        withdraw,
        ..OutboundRouteUpdate::default()
    });
    assert_eq!(actual.snapshot, Some((owner, 1)));
    assert_eq!(actual.payload, expected.payload);
}

/// Load-bearing breaks: disable fast => [0,0,0]; drop success => oversize leak; retain overlay => route absent.
#[test]
fn real_caller_grouped_exact_precommit_fast_and_slow_paths_are_equivalent() {
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24);
    let source = Ipv4Addr::new(192, 0, 2, 90);
    let small = crate::test_support::make_route(prefix, source);
    let mut oversized = small.clone();
    Arc::make_mut(&mut oversized.attributes).push(PathAttribute::Communities(vec![0xFDE8_0002]));
    let routes = [small.clone(), oversized, small];
    let normal = run_exact_precommit_differential(false, &routes);
    let forced_slow = run_exact_precommit_differential(true, &routes);
    let key = ExactExportKey::Unicast(Prefix::V4(prefix), 0);

    let hit_deltas =
        |steps: &[(ExactPrecommitState, u64)]| steps.iter().map(|step| step.1).collect::<Vec<_>>();
    assert_eq!(hit_deltas(&normal), [2, 1, 1]);
    assert_eq!(hit_deltas(&forced_slow), [0, 0, 0]);
    for (normal, slow) in normal.iter().zip(&forced_slow) {
        assert_eq!(normal.0, slow.0, "fast/slow semantic states must match");
        assert_eq!(normal.0.groups, [Some(0), Some(0)]);
    }
    assert_eq!(normal[0].0.overlays, [HashSet::new(), HashSet::new()]);
    assert_eq!(normal[1].0.overlays, [HashSet::new(), HashSet::from([key])]);
    assert_eq!(normal[2].0.overlays, [HashSet::new(), HashSet::new()]);
    let advertised = routes.each_ref().map(|route| vec![format!("{route:?}")]);
    assert_eq!(
        normal[0].0.advertised,
        [advertised[0].clone(), advertised[0].clone()]
    );
    assert_eq!(
        normal[1].0.advertised,
        [vec![format!("{:?}", routes[1])], vec![]]
    );
    assert_eq!(
        normal[2].0.advertised,
        [advertised[2].clone(), advertised[2].clone()]
    );
    assert_plain_unicast_update(&normal[0].0.updates[0], 1, vec![routes[0].clone()], vec![]);
    assert_plain_unicast_update(&normal[0].0.updates[1], 2, vec![routes[0].clone()], vec![]);
    assert_plain_unicast_update(&normal[1].0.updates[0], 1, vec![routes[1].clone()], vec![]);
    assert_plain_unicast_update(
        &normal[1].0.updates[1],
        2,
        vec![],
        vec![(Prefix::V4(prefix), 0)],
    );
    assert_plain_unicast_update(&normal[2].0.updates[0], 1, vec![routes[2].clone()], vec![]);
    assert_plain_unicast_update(&normal[2].0.updates[1], 2, vec![routes[2].clone()], vec![]);
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
    let mut shared_cells = Vec::new();
    for receiver in &mut receivers {
        let update = receiver.recv().await.unwrap();
        assert!(update.withdraw.is_empty());
        if let Some(cell) = &update.shared_group_encode {
            shared_cells.push(Arc::clone(cell));
        }
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
    // A grouped commit hands every member the SAME encode-once cell so the
    // transport fanout encodes the shared inventory exactly once; the
    // ungrouped per-peer path must never carry one.
    if force_ungrouped {
        assert!(shared_cells.is_empty());
    } else {
        assert_eq!(shared_cells.len(), receivers.len());
        assert!(
            shared_cells
                .iter()
                .all(|cell| Arc::ptr_eq(cell, &shared_cells[0]))
        );
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
#[expect(
    clippy::too_many_lines,
    reason = "one scenario surfaces every ungrouped fallback reason side by side"
)]
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

    // Since the ADR-0126 flip a unicast-only per-client-best peer
    // groups, so the residual `per_client_best` reason needs a
    // non-unicast-only session (VPNv4 negotiated) — sent by hand, the
    // helper hard-codes IPv4-unicast.
    let (pcb_tx, mut pcb_rx) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        per_client_best: true,
        interpret_rfc1997: true,
        session_id: 0,
        peer: per_client_best_peer,
        peer_asn: 65001,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: pcb_tx,
        export_policy: None,
        sendable_families: vec![(Afi::Ipv4, Safi::Unicast), (Afi::Ipv4, Safi::MplsVpn)],
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: vec![],
        negotiated_llgr_families: vec![],
    })
    .await
    .unwrap();
    drain_eor(&mut pcb_rx).await;

    let mut spec = PeerUpSpec::ibgp(orf_negotiated_peer);
    spec.negotiated_orf_recv = ipv4_sendable();
    // The RFC 5291 §6 gate holds the ORF peer's initial dump (no EoR
    // yet), so send PeerUp by hand instead of the helper.
    let (out_tx, _out_rx) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        per_client_best: spec.per_client_best,
        interpret_rfc1997: true,
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
/// group regardless of it. Since the ADR-0126 Phase 3 classifier flip
/// a shareable-chain unicast-only `per_client_best` peer GROUPS too —
/// on its own key (the `per_client_best` bit separates mitigated from
/// plain staging), with no fallback reason and no fallback-gauge
/// count.
#[tokio::test]
async fn rs_transparent_peers_group_per_client_best_groups_on_own_key() {
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
    let mut rx4 = peer_up(&tx, spec).await;

    let g1 = query_update_group(&tx, rs1).await;
    assert!(g1.starts_with("group:"), "RS-transparent peers group: {g1}");
    assert_eq!(query_update_group(&tx, rs2).await, g1);
    assert_eq!(
        query_update_group(&tx, plain).await,
        g1,
        "transparency is transport-side; shared chain ⇒ shared group"
    );
    let g_pcb = query_update_group(&tx, pcb).await;
    assert!(
        g_pcb.starts_with("group:"),
        "shareable-chain unicast-only per-client-best peer groups (ADR-0126): {g_pcb}"
    );
    assert_ne!(
        g_pcb, g1,
        "mitigated and unmitigated groups never share a table"
    );
    assert_metric(
        gauge_metric_value(&metrics, "bgp_update_group_fallback_peers", &[]),
        0.0,
        "bgp_update_group_fallback_peers",
    );
    // Grouping does not rename the selection surface: the member still
    // reports the per-client-best distribution mode.
    assert_eq!(
        query_peer_outbound_state(&tx, pcb)
            .await
            .effective_distribution_mode,
        crate::EffectiveDistributionMode::PerClientBest
    );

    // Shared staging feeds the grouped members identically; the
    // per-client-best group stages the same (sole) candidate.
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
    let u4 = rx4.recv().await.unwrap();
    assert_eq!(u1.announce.len(), 1);
    assert_eq!(u1.announce[0].prefix, Prefix::V4(prefix));
    assert_eq!(u1.announce[0].attributes, u2.announce[0].attributes);
    assert_eq!(u4.announce.len(), 1);
    assert_eq!(u4.announce[0].attributes, u1.announce[0].attributes);

    drop(tx);
    handle.await.unwrap();
}

/// The ADR-0126 residual fallback, pinned: `per_client_best` on a
/// NON-unicast-only session (`VPNv4` or RT-Constrain negotiated) keeps
/// today's per-peer path with the SAME `per_client_best` reason — no
/// new reason surface — and counts toward the fallback gauge.
#[tokio::test]
async fn per_client_best_with_vpn_or_rtc_families_keeps_fallback_reason() {
    let metrics = BgpMetrics::new();
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, metrics.clone());
    let handle = tokio::spawn(manager.run());

    let vpn_peer = IpAddr::V4(Ipv4Addr::new(10, 0, 4, 1));
    let rtc_peer = IpAddr::V4(Ipv4Addr::new(10, 0, 4, 2));
    for (peer, families) in [
        (
            vpn_peer,
            vec![(Afi::Ipv4, Safi::Unicast), (Afi::Ipv4, Safi::MplsVpn)],
        ),
        (
            rtc_peer,
            vec![(Afi::Ipv4, Safi::Unicast), (Afi::Ipv4, Safi::RtConstrain)],
        ),
    ] {
        let (out_tx, _out_rx) = mpsc::channel(64);
        tx.send(RibUpdate::PeerUp {
            peer,
            session_id: 0,
            peer_asn: 65001,
            peer_router_id: Ipv4Addr::UNSPECIFIED,
            outbound_tx: out_tx,
            export_policy: None,
            sendable_families: families,
            is_ebgp: true,
            route_reflector_client: false,
            orr_vantage: None,
            per_client_best: true,
            interpret_rfc1997: true,
            add_path_send_families: vec![],
            add_path_send_max: 0,
            negotiated_orf_recv: vec![],
            negotiated_llgr_families: vec![],
        })
        .await
        .unwrap();
    }

    assert_eq!(query_update_group(&tx, vpn_peer).await, "per_client_best");
    assert_eq!(query_update_group(&tx, rtc_peer).await, "per_client_best");
    assert_metric(
        gauge_metric_value(&metrics, "bgp_update_group_fallback_peers", &[]),
        2.0,
        "bgp_update_group_fallback_peers",
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
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, metrics.clone());
    // This test proves the multi-poll seam exists in the LIVE actor (poll
    // accounting, readiness interleaving), so pin the flush budget to zero:
    // one test-sized stride per poll, exactly as before the budget loops.
    manager.flush_poll_budget = std::time::Duration::ZERO;
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
    let poll_counts = histogram_sample_counts_by_label(
        &metrics,
        "bgp_rib_policy_transition_actor_poll_duration_seconds",
        "poll_kind",
    );
    assert_eq!(
        poll_counts,
        BTreeMap::from([
            (
                "bounded".to_owned(),
                u64::try_from(actor_polls - 4).unwrap()
            ),
            // MEMBER_COUNT members fit one COMMIT_MEMBERS_PER_POLL batch.
            ("commit".to_owned(), 1),
            ("finalize".to_owned(), 1),
            ("prefix_snapshot".to_owned(), 2),
        ])
    );
    assert_eq!(
        poll_counts.values().sum::<u64>(),
        u64::try_from(actor_polls).unwrap()
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
async fn clean_policy_transition_falls_back_for_distinct_runtime_group_edges() {
    let (tx, rx) = mpsc::channel(32);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());
    let probes = Arc::new(AtomicUsize::new(0));
    let reuses = Arc::new(AtomicUsize::new(0));
    let peers = [
        IpAddr::V4(Ipv4Addr::new(10, 40, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 40, 0, 2)),
    ];
    let old_policies = [community_chain(0xFDE8_1001), community_chain(0xFDE8_1002)];
    let next_policy = community_chain(0xFDE8_1003);
    let mut receivers = Vec::new();
    for (index, peer) in peers.iter().copied().enumerate() {
        let mut spec = PeerUpSpec::ibgp(peer);
        spec.route_reflector_client = true;
        spec.export_policy = Some(old_policies[index].clone());
        receivers.push(
            peer_up_with_cohort_encoder(
                &tx,
                spec,
                Arc::new(CohortExactEncoder {
                    owner: u64::try_from(index + 1).unwrap(),
                    profile: 41,
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
    let source_groups = [
        query_update_group(&tx, peers[0]).await,
        query_update_group(&tx, peers[1]).await,
    ];
    assert_ne!(source_groups[0], source_groups[1]);

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
        response.await.unwrap().unwrap(),
        crate::update::ExportPolicyCohortOutcome::RequiresAuthoritativePerPeerApply
    );
    assert_eq!(query_update_group(&tx, peers[0]).await, source_groups[0]);
    assert_eq!(query_update_group(&tx, peers[1]).await, source_groups[1]);
    assert!(
        receivers
            .iter_mut()
            .all(|receiver| receiver.try_recv().is_err())
    );
    assert_eq!(
        query_uncommitted_policy_transition_groups(&tx).await,
        0,
        "a divergent source edge must not retain a staged destination"
    );

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test(start_paused = true)]
#[expect(
    clippy::too_many_lines,
    reason = "the residue regression constructs an unrelated saturated member and proves the batch reply boundary"
)]
async fn clean_policy_transition_drains_unrelated_dirty_residue_before_reply() {
    let metrics = BgpMetrics::new();
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, metrics.clone());
    let handle = tokio::spawn(manager.run());
    let probes = Arc::new(AtomicUsize::new(0));
    let reuses = Arc::new(AtomicUsize::new(0));
    let old_policy = community_chain(0xFDE8_1101);
    let next_policy = community_chain(0xFDE8_1102);
    let cohort = [
        IpAddr::V4(Ipv4Addr::new(10, 41, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 41, 0, 2)),
    ];
    let mut cohort_receivers = Vec::new();
    for (index, peer) in cohort.iter().copied().enumerate() {
        let mut spec = PeerUpSpec::ibgp(peer);
        spec.route_reflector_client = true;
        spec.export_policy = Some(old_policy.clone());
        cohort_receivers.push(
            peer_up_with_cohort_encoder(
                &tx,
                spec,
                Arc::new(CohortExactEncoder {
                    owner: u64::try_from(index + 1).unwrap(),
                    profile: 43,
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

    let dirty_peer = IpAddr::V4(Ipv4Addr::new(10, 41, 0, 3));
    tx.send(RibUpdate::SetPeerExportEncoder {
        peer: dirty_peer,
        session_id: 0,
        encoder: Arc::new(CohortExactEncoder {
            owner: 3,
            profile: 43,
            max_len: 4_096,
            generation: AtomicUsize::new(0),
            advance_generation: false,
            probes: Arc::clone(&probes),
            reuses: Arc::clone(&reuses),
        }),
    })
    .await
    .unwrap();
    let mut dirty_spec = PeerUpSpec::ibgp(dirty_peer);
    dirty_spec.route_reflector_client = true;
    let mut dirty_receiver = peer_up_with_capacity(&tx, dirty_spec, 1).await;
    let source = Ipv4Addr::new(192, 0, 2, 41);
    let first_prefix = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 121, 0), 24);
    let second_prefix = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 122, 0), 24);
    let send_routes = async |announced: Vec<crate::route::Route>, withdrawn: Vec<(Prefix, u32)>| {
        tx.send(RibUpdate::RoutesReceived {
            session_id: 0,
            peer: IpAddr::V4(source),
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
    let make_route = |prefix| crate::test_support::make_route(prefix, source);
    send_routes(vec![make_route(first_prefix)], vec![]).await;
    send_routes(vec![make_route(second_prefix)], vec![]).await;
    send_routes(vec![], vec![(Prefix::V4(first_prefix), 0)]).await;
    let (health_reply, health_response) = oneshot::channel();
    tx.send(RibUpdate::TestQueryOutboundHealth {
        reply: health_reply,
    })
    .await
    .unwrap();
    let (dirty, _, group_dirty, _, _, _) = health_response.await.unwrap();
    assert_eq!((dirty, group_dirty), (1, 1));
    assert!(
        gauge_metric_value(&metrics, "bgp_update_group_residue_entries", &[]) > 0.0,
        "withdrawal residue must exist before the clean cohort commit"
    );
    let initially_delivered = dirty_receiver.recv().await.unwrap();
    assert_eq!(initially_delivered.announce.len(), 1);
    for receiver in &mut cohort_receivers {
        while receiver.try_recv().is_ok() {}
    }

    let (reply, response) = oneshot::channel();
    tx.send(RibUpdate::ReplacePeerExportPolicies {
        replacements: cohort
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
        response.await.unwrap().unwrap(),
        crate::update::ExportPolicyCohortOutcome::Committed
    );

    let (health_reply, health_response) = oneshot::channel();
    tx.send(RibUpdate::TestQueryOutboundHealth {
        reply: health_reply,
    })
    .await
    .unwrap();
    assert_eq!(
        health_response.await.unwrap(),
        (0, 0, 0, 0, 0, 0),
        "the success reply must follow the global dirty drain"
    );
    assert_metric(
        gauge_metric_value(&metrics, "bgp_update_group_residue_entries", &[]),
        0.0,
        "residue after pre-reply dirty drain",
    );
    let healed = dirty_receiver.recv().await.unwrap();
    assert!(
        healed.withdraw.contains(&(Prefix::V4(first_prefix), 0)),
        "the pre-reply drain must emit the unrelated withdrawal residue"
    );
    assert!(
        healed
            .announce
            .iter()
            .any(|route| route.prefix == Prefix::V4(second_prefix))
    );

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

#[tokio::test(flavor = "current_thread", start_paused = true)]
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
    tokio::time::advance(std::time::Duration::from_millis(29_999)).await;
    assert_eq!(
        tokio::time::timeout(std::time::Duration::from_millis(200), readiness_response)
            .await
            .expect("dedicated readiness must beat the core deadline")
            .unwrap(),
        Ok(ROUTE_COUNT),
        "a legitimately progressing transition stays ready below the ownership limit"
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

    let (stalled_reply, stalled_response) = oneshot::channel();
    readiness_tx
        .send(crate::update::RibReadinessQuery::LocRibCount {
            reply: stalled_reply,
        })
        .await
        .unwrap();
    tokio::time::advance(std::time::Duration::from_millis(1)).await;
    assert_eq!(
        tokio::time::timeout(std::time::Duration::from_millis(200), stalled_response)
            .await
            .expect("stalled readiness verdict must beat the core deadline")
            .unwrap(),
        Err(crate::update::RibReadinessError::PolicyTransitionStalled),
        "readiness must fail closed at the 30-second ownership limit"
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

    let (recovered_reply, recovered_response) = oneshot::channel();
    readiness_tx
        .send(crate::update::RibReadinessQuery::LocRibCount {
            reply: recovered_reply,
        })
        .await
        .unwrap();
    assert_eq!(
        tokio::time::timeout(std::time::Duration::from_millis(200), recovered_response)
            .await
            .expect("terminal transition must restore readiness immediately")
            .unwrap(),
        Ok(ROUTE_COUNT)
    );
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

/// Permit-all chain applying `mods` to every route (rs-control
/// transition scenarios).
fn mods_chain(mods: RouteModifications) -> PolicyChain {
    let mut statement = deny_statement(Ipv4Prefix::new(Ipv4Addr::UNSPECIFIED, 0));
    statement.prefix = None;
    statement.action = PolicyAction::Permit;
    statement.modifications = mods;
    PolicyChain::new(vec![Policy {
        entries: vec![statement],
        default_action: PolicyAction::Permit,
    }])
}

/// `SetPeerRsControl` (staged before `PeerUp`, mirroring the transport
/// registration order) + [`peer_up_with_cohort_encoder`].
async fn rs_peer_up_with_cohort_encoder(
    tx: &mpsc::Sender<RibUpdate>,
    spec: PeerUpSpec,
    rs_control_asn: u32,
    encoder: Arc<dyn crate::update::ExactExportEncoder>,
) -> mpsc::Receiver<OutboundRouteUpdate> {
    tx.send(RibUpdate::SetPeerRsControl {
        peer: spec.peer,
        session_id: 0,
        rs_control_asn: Some(rs_control_asn),
    })
    .await
    .unwrap();
    peer_up_with_cohort_encoder(tx, spec, encoder).await
}

/// An `rs_control_communities` cohort whose inventory carries no
/// control-form community — the overwhelming route-server case — must
/// take the shared clean transition like ordinary members instead of
/// the serial per-member full-table resync (the reload-completion
/// regression at route-server scale).
#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "the cohort setup, shared-payload proof, and stats assertions form one scenario"
)]
async fn clean_policy_transition_admits_rs_control_members_on_untagged_inventory() {
    const MEMBER_COUNT: usize = 3;
    const ROUTE_COUNT: usize = 8;
    const RS_AS: u32 = 64512;

    let (tx, rx) = mpsc::channel(128);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());
    let probes = Arc::new(AtomicUsize::new(0));
    let reuses = Arc::new(AtomicUsize::new(0));
    let old_policy = community_chain(0xFDE8_0001);
    let next_policy = community_chain(0xFDE8_0002);
    let mut peers = Vec::new();
    let mut receivers = Vec::new();
    for index in 0..MEMBER_COUNT {
        let peer = IpAddr::V4(Ipv4Addr::new(10, 61, 0, u8::try_from(index + 1).unwrap()));
        peers.push(peer);
        let mut spec = PeerUpSpec::ebgp(peer);
        spec.peer_asn = 65001 + u32::try_from(index).unwrap();
        spec.export_policy = Some(old_policy.clone());
        receivers.push(
            rs_peer_up_with_cohort_encoder(
                &tx,
                spec,
                RS_AS,
                Arc::new(CohortExactEncoder {
                    owner: u64::try_from(index + 1).unwrap(),
                    profile: 19,
                    max_len: 65_535,
                    generation: AtomicUsize::new(0),
                    advance_generation: false,
                    probes: Arc::clone(&probes),
                    reuses: Arc::clone(&reuses),
                }),
            )
            .await,
        );
    }

    let source = Ipv4Addr::new(192, 0, 2, 61);
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
        assert_eq!(receiver.recv().await.unwrap().announce.len(), ROUTE_COUNT);
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
    assert_eq!(
        response.await.unwrap(),
        Ok(crate::update::ExportPolicyCohortOutcome::Committed),
        "an untagged inventory must admit rs-control members to the shared transition"
    );

    let mut updates = Vec::new();
    for receiver in &mut receivers {
        let update = receiver.recv().await.unwrap();
        assert_eq!(update.announce.len(), ROUTE_COUNT);
        updates.push(update);
    }
    for update in &updates[1..] {
        assert!(
            Arc::ptr_eq(&updates[0].announce, &update.announce),
            "rs-control members must share the cohort's one announce payload"
        );
    }
    let (stats_reply, stats_response) = oneshot::channel();
    tx.send(RibUpdate::TestQueryPolicyTransitionStats { reply: stats_reply })
        .await
        .unwrap();
    assert_eq!(
        stats_response.await.unwrap().0,
        1,
        "the cohort must commit through exactly one shared plan, not per-member resyncs"
    );
    for &peer in &peers {
        assert_eq!(query_update_group(&tx, peer).await, "group:1");
    }

    drop(tx);
    handle.await.unwrap();
}

/// The tagged-inventory gate must consider the SOURCE routes: a policy
/// that strips a "do not announce to PEER" community leaves the
/// post-policy inventory clean while the member's verdict still
/// diverges. The cohort must fall back to the authoritative per-peer
/// path, and the suppressed member must never receive the route.
#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "the tagged-source setup, fallback handoff, and per-member wire proofs form one scenario"
)]
async fn clean_policy_transition_tagged_source_keeps_rs_members_on_authoritative_path() {
    const RS_AS: u32 = 64512;
    let deny_to_a = rustbgpd_wire::LargeCommunity {
        global_admin: RS_AS,
        local_data1: 0,
        local_data2: 65001,
    };

    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());
    let probes = Arc::new(AtomicUsize::new(0));
    let reuses = Arc::new(AtomicUsize::new(0));
    // Both chains strip the control community (the stripped-tag trap:
    // the post-policy inventory looks clean while the source verdict
    // diverges); the replacement also stamps a community so the table
    // diffs.
    let old_policy = mods_chain(RouteModifications {
        large_communities_remove: vec![deny_to_a],
        ..RouteModifications::default()
    });
    let next_policy = mods_chain(RouteModifications {
        large_communities_remove: vec![deny_to_a],
        communities_add: vec![0xFDE8_0002],
        ..RouteModifications::default()
    });
    let peers = [
        IpAddr::V4(Ipv4Addr::new(10, 62, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 62, 0, 2)),
    ];
    let mut receivers = Vec::new();
    for (index, peer) in peers.iter().copied().enumerate() {
        let mut spec = PeerUpSpec::ebgp(peer);
        spec.peer_asn = 65001 + u32::try_from(index).unwrap();
        spec.export_policy = Some(old_policy.clone());
        receivers.push(
            rs_peer_up_with_cohort_encoder(
                &tx,
                spec,
                RS_AS,
                Arc::new(CohortExactEncoder {
                    owner: u64::try_from(index + 1).unwrap(),
                    profile: 23,
                    max_len: 65_535,
                    generation: AtomicUsize::new(0),
                    advance_generation: false,
                    probes: Arc::clone(&probes),
                    reuses: Arc::clone(&reuses),
                }),
            )
            .await,
        );
    }

    let prefix = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 118, 0), 24);
    let source = Ipv4Addr::new(192, 0, 2, 62);
    let mut steered = make_route_with_as_path(prefix, source, vec![65010]);
    Arc::make_mut(&mut steered.attributes).push(PathAttribute::LargeCommunities(vec![deny_to_a]));
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: IpAddr::V4(source),
        announced: vec![steered],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();
    let _ = query_best_routes(&tx).await;
    assert!(
        receivers[0].try_recv().is_err(),
        "the source-denied member must not receive the route initially"
    );
    assert_eq!(receivers[1].try_recv().unwrap().announce.len(), 1);

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
        crate::update::ExportPolicyCohortOutcome::RequiresAuthoritativePerPeerApply,
        "a source-tagged inventory must keep rs members off the shared transition"
    );
    apply_authoritative_policy_handoff(&tx, &peers, Some(next_policy.clone()), outcome).await;

    while let Ok(update) = receivers[0].try_recv() {
        assert!(
            !update
                .announce
                .iter()
                .any(|route| route.prefix == Prefix::V4(prefix)),
            "the source-denied member must never receive the route through any transition path"
        );
    }
    let mut b_routes = Vec::new();
    while let Ok(update) = receivers[1].try_recv() {
        b_routes.extend(update.announce.iter().cloned());
    }
    let reannounced = b_routes
        .iter()
        .find(|route| route.prefix == Prefix::V4(prefix))
        .expect("the other member re-receives the route under the new policy");
    assert!(reannounced.communities().contains(&0xFDE8_0002));
    assert!(
        reannounced.large_communities().is_empty(),
        "the control community stays stripped/scrubbed from the wire"
    );
    let (stats_reply, stats_response) = oneshot::channel();
    tx.send(RibUpdate::TestQueryPolicyTransitionStats { reply: stats_reply })
        .await
        .unwrap();
    assert_eq!(
        stats_response.await.unwrap().0,
        0,
        "no shared plan may commit"
    );

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
        interpret_rfc1997: true,
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
        interpret_rfc1997: true,
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
            interpret_rfc1997: true,
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

/// Direct-drive fixture for mid-flush observation: `member_count` grouped
/// RR-client members installed on one shared export policy, `route_count`
/// Loc-RIB routes distributed and drained, no actor task. Tests step the
/// parked transition through the same seam the run loop polls.
fn direct_clean_transition_manager(
    member_count: usize,
    route_count: usize,
    readiness_rx: Option<mpsc::Receiver<crate::update::RibReadinessQuery>>,
) -> (
    RibManager,
    Vec<IpAddr>,
    Vec<mpsc::Receiver<OutboundRouteUpdate>>,
) {
    let (_tx, rx) = mpsc::channel(1);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    // Zero flush budget parks the commit poll after every stride, making the
    // per-poll batch boundaries deterministic for the seam assertions below.
    manager.flush_poll_budget = std::time::Duration::ZERO;
    if let Some(readiness_rx) = readiness_rx {
        manager = manager.with_readiness_queries(readiness_rx);
    }
    let probes = Arc::new(AtomicUsize::new(0));
    let reuses = Arc::new(AtomicUsize::new(0));
    let old_policy = community_chain(0xFDE8_2101);
    let mut peers = Vec::new();
    let mut receivers = Vec::new();
    for index in 0..member_count {
        let peer = IpAddr::V4(Ipv4Addr::new(10, 42, 0, u8::try_from(index + 1).unwrap()));
        peers.push(peer);
        manager.handle_update(RibUpdate::SetPeerExportEncoder {
            peer,
            session_id: 0,
            encoder: Arc::new(CohortExactEncoder {
                owner: u64::try_from(index + 1).unwrap(),
                profile: 42,
                max_len: 65_535,
                generation: AtomicUsize::new(0),
                advance_generation: false,
                probes: Arc::clone(&probes),
                reuses: Arc::clone(&reuses),
            }),
        });
        let (outbound_tx, mut outbound_rx) = mpsc::channel(8);
        manager.handle_update(RibUpdate::PeerUp {
            peer,
            session_id: 0,
            peer_asn: 65_000,
            peer_router_id: Ipv4Addr::UNSPECIFIED,
            outbound_tx,
            export_policy: Some(old_policy.clone()),
            sendable_families: ipv4_sendable(),
            is_ebgp: false,
            route_reflector_client: true,
            orr_vantage: None,
            per_client_best: false,
            interpret_rfc1997: true,
            add_path_send_families: vec![],
            add_path_send_max: 0,
            negotiated_orf_recv: vec![],
            negotiated_llgr_families: vec![],
        });
        let eor = outbound_rx.try_recv().unwrap();
        assert_eq!(eor.end_of_rib, ipv4_sendable());
        receivers.push(outbound_rx);
    }
    let source = Ipv4Addr::new(192, 0, 2, 42);
    let announced = (0..route_count)
        .map(|index| {
            crate::test_support::make_route(
                Ipv4Prefix::new(Ipv4Addr::new(198, 51, u8::try_from(index).unwrap(), 0), 24),
                source,
            )
        })
        .collect();
    manager.handle_update(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: IpAddr::V4(source),
        announced,
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    });
    while manager.process_next_route_chunk() {}
    for receiver in &mut receivers {
        while receiver.try_recv().is_ok() {}
    }
    (manager, peers, receivers)
}

/// One run-loop poll of the parked transition, returning the recorded poll
/// kind and outcome exactly as the actor seam observes them.
fn step_parked_transition(manager: &mut RibManager) -> (&'static str, &'static str) {
    use crate::manager::distribution::CleanPolicyTransitionAdvance;
    let pending = manager
        .pending_clean_policy_transition
        .take()
        .expect("a parked transition to poll");
    let kind = pending.poll_kind().as_str();
    match manager.advance_clean_policy_transition(pending) {
        CleanPolicyTransitionAdvance::Continue(next) => {
            manager.pending_clean_policy_transition = Some(next);
            (kind, "continue")
        }
        CleanPolicyTransitionAdvance::Committed(_) => (kind, "committed"),
        CleanPolicyTransitionAdvance::Fallback(mut failed) => {
            failed
                .discard_uncommitted_transition(manager)
                .expect("fallback cleanup succeeds");
            (kind, "fallback")
        }
    }
}

fn start_clean_transition(
    manager: &mut RibManager,
    peers: &[IpAddr],
    next_policy: &PolicyChain,
) -> oneshot::Receiver<Result<crate::update::ExportPolicyCohortOutcome, String>> {
    let (reply, response) = oneshot::channel();
    manager.handle_update(RibUpdate::ReplacePeerExportPolicies {
        replacements: peers
            .iter()
            .map(|&peer| crate::update::PeerExportPolicyReplacement {
                peer,
                export_policy: Some(next_policy.clone()),
            })
            .collect(),
        reply,
    });
    assert!(manager.pending_clean_policy_transition.is_some());
    response
}

/// LAN-447: the dedicated readiness lane must be answerable BETWEEN commit
/// batches. With a monolithic finalize poll (no Validate/CommitMembers
/// split) no mid-flush seam exists and this test fails: the first
/// commit-kind poll would terminate the transition.
#[tokio::test]
async fn readiness_answered_between_commit_flush_batches() {
    const MEMBER_COUNT: usize = 3 * super::super::COMMIT_MEMBERS_PER_POLL + 2;
    const ROUTE_COUNT: usize = 2;
    let (readiness_tx, readiness_rx) = mpsc::channel(8);
    let (mut manager, peers, _receivers) =
        direct_clean_transition_manager(MEMBER_COUNT, ROUTE_COUNT, Some(readiness_rx));
    let next_policy = community_chain(0xFDE8_2102);
    let mut response = start_clean_transition(&mut manager, &peers, &next_policy);

    // Drive the poll seam until the FIRST commit poll completes.
    loop {
        let (kind, outcome) = step_parked_transition(&mut manager);
        assert_eq!(outcome, "continue", "{kind} poll must park mid-transition");
        if kind == "commit" {
            break;
        }
    }
    let pending = manager
        .pending_clean_policy_transition
        .as_ref()
        .expect("transition still owned mid-flush");
    let cursor = pending.commit_cursor().expect("commit phase parked");
    assert_eq!(cursor, super::super::COMMIT_MEMBERS_PER_POLL);
    assert!(cursor < MEMBER_COUNT);
    let elapsed = pending.elapsed();

    // The readiness lane is serviced at exactly this seam.
    let (reply, mut probe) = oneshot::channel();
    readiness_tx
        .try_send(crate::update::RibReadinessQuery::LocRibCount { reply })
        .unwrap();
    manager.drain_readiness_queries(Some(elapsed));
    assert_eq!(
        probe
            .try_recv()
            .expect("readiness answered mid-flush")
            .expect("healthy verdict while the flush is parked"),
        ROUTE_COUNT
    );
    assert!(manager.pending_clean_policy_transition.is_some());

    // The flush then completes without fallback.
    loop {
        let (kind, outcome) = step_parked_transition(&mut manager);
        assert_eq!(kind, "commit");
        if outcome == "committed" {
            break;
        }
        assert_eq!(outcome, "continue");
    }
    assert_eq!(
        response.try_recv().unwrap(),
        Ok(crate::update::ExportPolicyCohortOutcome::Committed)
    );
}

/// The commit phase drains members in bounded batches: ceil(M/8)-1 Continue
/// polls, each flushing at most `COMMIT_MEMBERS_PER_POLL` members.
#[tokio::test]
async fn commit_flush_batches_are_bounded_and_drain_monotonically() {
    const MEMBER_COUNT: usize = 3 * super::super::COMMIT_MEMBERS_PER_POLL + 2;
    const ROUTE_COUNT: usize = 2;
    let (mut manager, peers, mut receivers) =
        direct_clean_transition_manager(MEMBER_COUNT, ROUTE_COUNT, None);
    let next_policy = community_chain(0xFDE8_2103);
    let mut response = start_clean_transition(&mut manager, &peers, &next_policy);

    let mut batch_sizes = Vec::new();
    let mut commit_continues = 0_usize;
    loop {
        let (kind, outcome) = step_parked_transition(&mut manager);
        assert_ne!(outcome, "fallback");
        if kind == "commit" {
            // Each member receives exactly one shared flush envelope, so the
            // per-poll count of newly delivered envelopes IS the batch size.
            let delivered = receivers
                .iter_mut()
                .filter_map(|receiver| receiver.try_recv().ok())
                .count();
            batch_sizes.push(delivered);
            if outcome == "committed" {
                break;
            }
            commit_continues += 1;
        } else {
            assert_eq!(outcome, "continue");
        }
    }
    assert_eq!(batch_sizes, vec![8, 8, 8, 2]);
    assert_eq!(
        commit_continues,
        MEMBER_COUNT.div_ceil(super::super::COMMIT_MEMBERS_PER_POLL) - 1
    );
    let destination = manager.grouped_member_of(peers[0]).expect("grouped");
    for &peer in &peers {
        assert_eq!(manager.grouped_member_of(peer), Some(destination));
    }
    assert_eq!(
        response.try_recv().unwrap(),
        Ok(crate::update::ExportPolicyCohortOutcome::Committed)
    );
}

/// With wall-clock budget in hand, the probe-and-prepare phase strides the
/// whole cohort in a handful of polls instead of one route-slice per poll —
/// the fenced pre-commit window must not scale with table x member count
/// when the actor has time available.
#[tokio::test]
async fn probe_phase_uses_full_poll_budget_before_parking() {
    const MEMBER_COUNT: usize = 3 * super::super::COMMIT_MEMBERS_PER_POLL + 2;
    const ROUTE_COUNT: usize = 2;
    let (mut manager, peers, _receivers) =
        direct_clean_transition_manager(MEMBER_COUNT, ROUTE_COUNT, None);
    // The helper zeroes the budget for deterministic per-stride tests;
    // restore a generous one so pre-commit phases stride to completion.
    manager.flush_poll_budget = std::time::Duration::from_mins(1);
    let next_policy = community_chain(0xFDE8_2106);
    let mut response = start_clean_transition(&mut manager, &peers, &next_policy);

    let mut pre_commit_polls = 0_usize;
    loop {
        let (kind, outcome) = step_parked_transition(&mut manager);
        assert_ne!(outcome, "fallback");
        if kind == "commit" {
            if outcome == "committed" {
                break;
            }
        } else {
            pre_commit_polls += 1;
            assert_eq!(outcome, "continue");
        }
    }
    // Under a zero budget this shape needs one poll per member probe
    // route-slice (the test slice is a single route) plus classification
    // polls — dozens. A budgeted poll strides through; allow a small
    // constant for the distinct phases (classify, probe, validate,
    // snapshot seams).
    assert!(
        pre_commit_polls <= 8,
        "budgeted pre-commit phases must not scale with members x routes: {pre_commit_polls} polls"
    );
    assert_eq!(
        response.try_recv().unwrap(),
        Ok(crate::update::ExportPolicyCohortOutcome::Committed)
    );
}

/// With wall-clock budget available, one commit poll keeps flushing strides
/// instead of parking after a fixed member count — emission start must not
/// scale with fleet size when the actor has time in hand.
#[tokio::test]
async fn commit_flush_uses_full_poll_budget_before_parking() {
    const MEMBER_COUNT: usize = 3 * super::super::COMMIT_MEMBERS_PER_POLL + 2;
    const ROUTE_COUNT: usize = 2;
    let (mut manager, peers, mut receivers) =
        direct_clean_transition_manager(MEMBER_COUNT, ROUTE_COUNT, None);
    // The helper zeroes the budget for deterministic seam tests; restore a
    // generous one so the whole cohort fits a single poll.
    manager.flush_poll_budget = std::time::Duration::from_mins(1);
    let next_policy = community_chain(0xFDE8_2105);
    let mut response = start_clean_transition(&mut manager, &peers, &next_policy);

    let mut commit_polls = 0_usize;
    loop {
        let (kind, outcome) = step_parked_transition(&mut manager);
        assert_ne!(outcome, "fallback");
        if kind == "commit" {
            commit_polls += 1;
            if outcome == "committed" {
                break;
            }
        } else {
            assert_eq!(outcome, "continue");
        }
    }
    assert_eq!(commit_polls, 1, "budgeted poll drains the whole cohort");
    let delivered = receivers
        .iter_mut()
        .filter_map(|receiver| receiver.try_recv().ok())
        .count();
    assert_eq!(delivered, MEMBER_COUNT);
    assert_eq!(
        response.try_recv().unwrap(),
        Ok(crate::update::ExportPolicyCohortOutcome::Committed)
    );
}

/// Once the first batch has emitted, a member's dropped transport receiver
/// must not fall the transition back: the dead peer's envelope is silently
/// dropped, every other member commits, and the cohort ends Committed.
#[tokio::test]
async fn commit_flush_never_falls_back_after_first_emission() {
    const MEMBER_COUNT: usize = 10;
    const ROUTE_COUNT: usize = 2;
    let (mut manager, peers, mut receivers) =
        direct_clean_transition_manager(MEMBER_COUNT, ROUTE_COUNT, None);
    let next_policy = community_chain(0xFDE8_2104);
    let mut response = start_clean_transition(&mut manager, &peers, &next_policy);

    // First commit batch flushes members 0..8 (replacement order).
    loop {
        let (kind, outcome) = step_parked_transition(&mut manager);
        assert_eq!(outcome, "continue");
        if kind == "commit" {
            break;
        }
    }
    for receiver in &mut receivers[..8] {
        assert!(
            receiver.try_recv().is_ok(),
            "first batch flushed members 0..8"
        );
    }
    // Drop a NOT-yet-committed member's transport receiver mid-flush.
    drop(receivers.remove(9));

    loop {
        let (kind, outcome) = step_parked_transition(&mut manager);
        assert_eq!(kind, "commit");
        match outcome {
            "committed" => break,
            "continue" => {}
            other => panic!("post-emission poll must never {other}"),
        }
    }
    assert_eq!(
        response.try_recv().unwrap(),
        Ok(crate::update::ExportPolicyCohortOutcome::Committed)
    );
    // The surviving ninth member got its envelope; the dead member's
    // membership still committed with the cohort.
    assert!(receivers[8].try_recv().is_ok());
    let destination = manager.grouped_member_of(peers[0]).expect("grouped");
    assert_eq!(manager.grouped_member_of(peers[9]), Some(destination));
}

/// The observational snapshot surface keeps its chain-content dimension
/// (planning comparisons diff live rows against candidate rows on it),
/// while runtime classification skips the rendering entirely (LAN-886).
/// The digest must agree across distinct instances of content-equal
/// chains and differ across different chain content.
#[tokio::test]
async fn snapshot_rows_carry_content_stable_policy_fingerprints() {
    let (_tx, rx) = mpsc::channel(1);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let shared = community_chain(0xFDE8_2114);
    let distinct = community_chain(0xFDE8_2115);
    let chains = [shared.clone(), shared.clone(), distinct.clone()];
    let mut peers = Vec::new();
    for (index, chain) in chains.into_iter().enumerate() {
        let peer = IpAddr::V4(Ipv4Addr::new(10, 44, 0, u8::try_from(index + 1).unwrap()));
        peers.push(peer);
        let (outbound_tx, _outbound_rx) = mpsc::channel(8);
        manager.handle_update(RibUpdate::PeerUp {
            peer,
            session_id: 0,
            peer_asn: 65_000,
            peer_router_id: Ipv4Addr::UNSPECIFIED,
            outbound_tx,
            export_policy: Some(chain),
            sendable_families: ipv4_sendable(),
            is_ebgp: false,
            route_reflector_client: true,
            orr_vantage: None,
            per_client_best: false,
            interpret_rfc1997: true,
            add_path_send_families: vec![],
            add_path_send_max: 0,
            negotiated_orf_recv: vec![],
            negotiated_llgr_families: vec![],
        });
    }
    let (reply, response) = oneshot::channel();
    manager.handle_query_update_group_snapshot(reply);
    let snapshot = response.await.unwrap();
    let fingerprint_of = |peer: IpAddr| {
        snapshot
            .peers
            .iter()
            .find(|row| row.peer == peer)
            .expect("snapshot row per registered peer")
            .input
            .policy_fingerprint
            .clone()
            .expect("snapshot rows carry the planning fingerprint")
    };
    assert_eq!(
        fingerprint_of(peers[0]),
        fingerprint_of(peers[1]),
        "content-equal chain instances share one planning fingerprint"
    );
    assert_ne!(
        fingerprint_of(peers[0]),
        fingerprint_of(peers[2]),
        "different chain content yields a different planning fingerprint"
    );
}

/// LAN-886: a transition whose PRE-COMMIT phases outlive the ownership
/// budget must hand the cohort back fail-closed while every session is
/// still healthy. Before the budget existed, every pre-commit fallback
/// trigger was an invalidation event (session/channel loss, table drift),
/// so a slow-but-healthy transition fenced the actor — and all wire
/// output — until session teardown finally invalidated it: the grouped
/// IRR-scale reload wedged for the entire 600 s observation window and
/// completed `fallback_handoff` one second AFTER teardown. On the
/// pre-budget logic this test fails at the poll below with `continue`.
#[tokio::test(start_paused = true)]
async fn healthy_transition_past_precommit_budget_hands_off_fail_closed() {
    use crate::manager::distribution::CleanPolicyTransitionAdvance;
    const MEMBER_COUNT: usize = 4;
    const ROUTE_COUNT: usize = 3;
    let (mut manager, peers, mut receivers) =
        direct_clean_transition_manager(MEMBER_COUNT, ROUTE_COUNT, None);
    let next_policy = community_chain(0xFDE8_2112);
    let mut response = start_clean_transition(&mut manager, &peers, &next_policy);
    let source = manager.grouped_member_of(peers[0]).expect("grouped");

    // Healthy pre-commit progress first: classification completes.
    let (kind, outcome) = step_parked_transition(&mut manager);
    assert_eq!((kind, outcome), ("bounded", "continue"));

    // The fenced pre-commit work outlives the ownership budget (paused
    // time models the LAN-886 shape, where per-member classification cost
    // stretched the phases past any healthy observation window).
    tokio::time::advance(super::super::MAX_PRECOMMIT_POLICY_TRANSITION_OWNERSHIP).await;

    let pending = manager
        .pending_clean_policy_transition
        .take()
        .expect("transition still owned");
    match manager.advance_clean_policy_transition(pending) {
        CleanPolicyTransitionAdvance::Fallback(mut failed) => {
            failed
                .discard_uncommitted_transition(&mut manager)
                .expect("fallback cleanup succeeds");
            // Mirror the run loop's fallback arm: the caller receives the
            // authoritative per-peer handoff.
            let reply = failed.take_reply().expect("fallback owns the caller reply");
            reply
                .send(Ok(
                    crate::update::ExportPolicyCohortOutcome::RequiresAuthoritativePerPeerApply,
                ))
                .expect("caller awaits the handoff");
        }
        CleanPolicyTransitionAdvance::Continue(_) => {
            panic!("healthy transition past its pre-commit budget must hand off, not continue")
        }
        CleanPolicyTransitionAdvance::Committed(_) => {
            panic!("healthy transition past its pre-commit budget must hand off, not commit")
        }
    }
    assert_eq!(
        response.try_recv().unwrap(),
        Ok(crate::update::ExportPolicyCohortOutcome::RequiresAuthoritativePerPeerApply)
    );
    // Fail-closed: nothing externally visible happened — no envelope
    // reached any member and every membership is unchanged.
    for receiver in &mut receivers {
        assert!(receiver.try_recv().is_err());
    }
    for &peer in &peers {
        assert_eq!(manager.grouped_member_of(peer), Some(source));
    }
}

/// The pre-commit budget must never abort `CommitMembers`: once the first
/// batch has emitted, an over-budget transition still runs to `Committed`
/// (an envelope may already be on a member's wire — the phase-level
/// invariant of ADR-0105 §3.6).
#[tokio::test(start_paused = true)]
async fn over_budget_commit_flush_still_completes() {
    const MEMBER_COUNT: usize = 2 * super::super::COMMIT_MEMBERS_PER_POLL + 1;
    const ROUTE_COUNT: usize = 2;
    let (mut manager, peers, _receivers) =
        direct_clean_transition_manager(MEMBER_COUNT, ROUTE_COUNT, None);
    let next_policy = community_chain(0xFDE8_2113);
    let mut response = start_clean_transition(&mut manager, &peers, &next_policy);

    // Drive to the first parked commit poll (first batch already emitted).
    loop {
        let (kind, outcome) = step_parked_transition(&mut manager);
        assert_eq!(outcome, "continue", "{kind} poll must park mid-transition");
        if kind == "commit" {
            break;
        }
    }
    tokio::time::advance(super::super::MAX_PRECOMMIT_POLICY_TRANSITION_OWNERSHIP).await;
    loop {
        let (kind, outcome) = step_parked_transition(&mut manager);
        assert_eq!(kind, "commit");
        match outcome {
            "committed" => break,
            "continue" => {}
            other => panic!("over-budget commit flush must complete, not {other}"),
        }
    }
    assert_eq!(
        response.try_recv().unwrap(),
        Ok(crate::update::ExportPolicyCohortOutcome::Committed)
    );
    let destination = manager.grouped_member_of(peers[0]).expect("grouped");
    for &peer in &peers {
        assert_eq!(manager.grouped_member_of(peer), Some(destination));
    }
}

/// Fence integrity across the batched flush: a primary route update and a
/// second cohort enqueued behind an owned transition are processed only
/// after its terminal commit, in order — every member observes
/// flush-then-mutation-then-second-flush.
#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "the fence regression preserves full cohort setup plus the three-message queue-order proof"
)]
async fn fence_holds_queued_work_until_commit_flush_terminal() {
    const MEMBER_COUNT: usize = 3 * super::super::COMMIT_MEMBERS_PER_POLL + 2;
    const ROUTE_COUNT: usize = 2;
    let (tx, rx) = mpsc::channel(256);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());
    let probes = Arc::new(AtomicUsize::new(0));
    let reuses = Arc::new(AtomicUsize::new(0));
    let old_policy = community_chain(0xFDE8_2105);
    let mid_policy = community_chain(0xFDE8_2106);
    let final_policy = community_chain(0xFDE8_2107);
    let mut peers = Vec::new();
    let mut receivers = Vec::new();
    for index in 0..MEMBER_COUNT {
        let peer = IpAddr::V4(Ipv4Addr::new(10, 43, 0, u8::try_from(index + 1).unwrap()));
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
                    profile: 43,
                    max_len: 65_535,
                    generation: AtomicUsize::new(0),
                    advance_generation: false,
                    probes: Arc::clone(&probes),
                    reuses: Arc::clone(&reuses),
                }),
            )
            .await,
        );
    }
    let source = Ipv4Addr::new(192, 0, 2, 43);
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
        assert_eq!(receiver.recv().await.unwrap().announce.len(), ROUTE_COUNT);
    }

    // Enqueue the cohort, then a primary update, then a second cohort —
    // all queued behind the owned transition.
    let (reply_mid, response_mid) = oneshot::channel();
    tx.send(RibUpdate::ReplacePeerExportPolicies {
        replacements: peers
            .iter()
            .map(|&peer| crate::update::PeerExportPolicyReplacement {
                peer,
                export_policy: Some(mid_policy.clone()),
            })
            .collect(),
        reply: reply_mid,
    })
    .await
    .unwrap();
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
    let (reply_final, response_final) = oneshot::channel();
    tx.send(RibUpdate::ReplacePeerExportPolicies {
        replacements: peers
            .iter()
            .map(|&peer| crate::update::PeerExportPolicyReplacement {
                peer,
                export_policy: Some(final_policy.clone()),
            })
            .collect(),
        reply: reply_final,
    })
    .await
    .unwrap();

    assert_eq!(
        response_mid.await.unwrap(),
        Ok(crate::update::ExportPolicyCohortOutcome::Committed)
    );
    assert_eq!(
        response_final.await.unwrap(),
        Ok(crate::update::ExportPolicyCohortOutcome::Committed),
        "the second cohort must queue behind the fence, not race the flush"
    );
    for receiver in &mut receivers {
        let flush = receiver.recv().await.unwrap();
        assert_eq!(
            flush.announce.len(),
            ROUTE_COUNT,
            "cohort flush precedes the queued primary update"
        );
        let primary = receiver.recv().await.unwrap();
        assert_eq!(primary.announce.len(), 1);
        assert_eq!(primary.announce[0].prefix, Prefix::V4(later_prefix));
        let second_flush = receiver.recv().await.unwrap();
        assert_eq!(
            second_flush.announce.len(),
            ROUTE_COUNT + 1,
            "second cohort flushes the post-mutation table"
        );
    }

    drop(tx);
    handle.await.unwrap();
}

/// LAN-447 companion bound: one resync-timer tick hands at most
/// `RESYNC_PEERS_PER_TICK` dirty peers to the O(table) resync pass; the
/// withheld remainder survives untouched for the next tick.
#[tokio::test]
async fn dirty_resync_tick_bounds_peers_and_preserves_backlog() {
    const PEER_COUNT: usize = 12;
    const ROUTE_COUNT: usize = 1;
    let (mut manager, peers, mut receivers) =
        direct_clean_transition_manager(PEER_COUNT, ROUTE_COUNT, None);
    for &peer in &peers {
        manager.mark_outbound_dirty(peer);
    }
    assert_eq!(manager.dirty_peers.len(), PEER_COUNT);

    // First tick: exactly the bounded slice resyncs (each successful dirty
    // resync of a grouped member replays the group table as one envelope);
    // the withheld backlog is reported and survives untouched.
    let backlog = manager.resync_dirty_peers_bounded();
    assert!(backlog, "a withheld remainder must be reported as backlog");
    assert_eq!(
        manager.dirty_peers.len(),
        PEER_COUNT - super::super::RESYNC_PEERS_PER_TICK
    );
    let first_tick_envelopes = receivers
        .iter_mut()
        .filter_map(|receiver| receiver.try_recv().ok())
        .count();
    assert_eq!(first_tick_envelopes, super::super::RESYNC_PEERS_PER_TICK);

    // Second tick drains the remainder without over-reporting backlog.
    let backlog = manager.resync_dirty_peers_bounded();
    assert!(!backlog, "no withheld peers remain");
    assert!(manager.dirty_peers.is_empty());
    let second_tick_envelopes = receivers
        .iter_mut()
        .filter_map(|receiver| receiver.try_recv().ok())
        .count();
    assert_eq!(
        second_tick_envelopes,
        PEER_COUNT - super::super::RESYNC_PEERS_PER_TICK
    );
}

/// With wall-clock budget in hand, one resync tick keeps taking strides
/// instead of parking after a fixed peer count — backlog recovery
/// throughput must not scale inversely with fleet size when the actor has
/// time available.
#[tokio::test]
async fn dirty_resync_tick_uses_full_poll_budget_before_parking() {
    const PEER_COUNT: usize = 12;
    const ROUTE_COUNT: usize = 1;
    let (mut manager, peers, mut receivers) =
        direct_clean_transition_manager(PEER_COUNT, ROUTE_COUNT, None);
    // The helper zeroes the budget for deterministic per-stride tests;
    // restore a generous one so the whole backlog drains in a single tick.
    manager.flush_poll_budget = std::time::Duration::from_mins(1);
    for &peer in &peers {
        manager.mark_outbound_dirty(peer);
    }
    assert_eq!(manager.dirty_peers.len(), PEER_COUNT);

    let backlog = manager.resync_dirty_peers_bounded();
    assert!(!backlog, "budgeted tick drains the whole backlog");
    assert!(manager.dirty_peers.is_empty());
    let envelopes = receivers
        .iter_mut()
        .filter_map(|receiver| receiver.try_recv().ok())
        .count();
    assert_eq!(envelopes, PEER_COUNT);
}

/// Failed sends must not spin the budget loop: peers whose channel is full
/// stay dirty after their attempt, and the tick returns without backlog
/// (they wait for the ordinary retry interval) instead of re-attempting
/// them until the budget expires.
#[tokio::test]
async fn dirty_resync_tick_attempts_each_peer_at_most_once() {
    const PEER_COUNT: usize = 12;
    const ROUTE_COUNT: usize = 1;
    let (mut manager, peers, mut receivers) =
        direct_clean_transition_manager(PEER_COUNT, ROUTE_COUNT, None);
    manager.flush_poll_budget = std::time::Duration::from_mins(1);
    // Saturate every outbound channel (helper capacity 8) by repeatedly
    // re-dirtying and resyncing without draining the receivers: each
    // grouped dirty resync replays the group table as one envelope, so the
    // channels fill and further sends fail, leaving the peers dirty.
    for _ in 0..9 {
        for &peer in &peers {
            manager.mark_outbound_dirty(peer);
        }
        manager.resync_dirty_peers_bounded();
    }
    for &peer in &peers {
        manager.mark_outbound_dirty(peer);
    }
    let _ = &mut receivers;
    let started = std::time::Instant::now();
    let backlog = manager.resync_dirty_peers_bounded();
    assert!(
        !backlog,
        "attempted-but-failed peers are not withheld backlog"
    );
    assert!(
        !manager.dirty_peers.is_empty(),
        "peers with saturated channels stay dirty for the ordinary retry"
    );
    assert!(
        started.elapsed() < std::time::Duration::from_secs(30),
        "the tick must terminate without spinning the budget loop"
    );
}

/// LAN-459 regression: a dirty backlog whose outbound channels are all
/// closed (sessions torn down, e.g. at shutdown) must quiesce in one
/// tick — the tick drops the dead peers instead of re-marking them, so
/// the resync timer disarms (`dirty_peers` empty) and the actor can
/// observe shutdown instead of re-arming forever.
#[tokio::test]
async fn dirty_resync_tick_drops_closed_channel_peers_and_quiesces() {
    const PEER_COUNT: usize = 12;
    const ROUTE_COUNT: usize = 1;
    let (mut manager, peers, receivers) =
        direct_clean_transition_manager(PEER_COUNT, ROUTE_COUNT, None);
    for &peer in &peers {
        manager.mark_outbound_dirty(peer);
    }
    assert_eq!(manager.dirty_peers.len(), PEER_COUNT);

    // Tear down every session: the outbound receivers drop, closing the
    // channels while the peers are still marked dirty.
    drop(receivers);

    let backlog = manager.resync_dirty_peers_bounded();
    assert!(
        !backlog,
        "closed-channel peers must not be withheld as backlog"
    );
    assert!(
        manager.dirty_peers.is_empty(),
        "one tick must drop every closed-channel dirty peer so the resync timer disarms"
    );
    for &peer in &peers {
        if let Some(gid) = manager.grouped_member_of(peer) {
            assert!(
                !manager.group_ribs[&gid].dirty_members.contains(&peer),
                "group dirty flag must drop with the peer's dirty state"
            );
        }
    }
}

/// LAN-459 regression: the send-failure retry path routes through
/// `mark_outbound_dirty`; once a peer's channel is closed, that path
/// must drop the peer's dirty state instead of re-inserting it — the
/// livelock was closed channels re-marking themselves dirty on every
/// resync attempt.
#[tokio::test]
async fn mark_outbound_dirty_drops_peer_with_closed_channel() {
    const PEER_COUNT: usize = 2;
    const ROUTE_COUNT: usize = 1;
    let (mut manager, peers, mut receivers) =
        direct_clean_transition_manager(PEER_COUNT, ROUTE_COUNT, None);
    let (live, dead) = (peers[0], peers[1]);

    // Both channels open: both marks stick.
    manager.mark_outbound_dirty(live);
    manager.mark_outbound_dirty(dead);
    assert_eq!(manager.dirty_peers.len(), PEER_COUNT);

    // Close one session, then re-mark it (as the retry path would after a
    // failed send): the mark must remove the peer, not keep it dirty.
    drop(receivers.pop().unwrap());
    manager.mark_outbound_dirty(dead);
    assert!(
        !manager.dirty_peers.contains(&dead),
        "re-marking a closed-channel peer must drop it from the dirty set"
    );
    assert!(
        manager.dirty_peers.contains(&live),
        "an open-channel dirty peer is untouched"
    );
}

/// Prepare a cohort's destination group before the transition, churn a new
/// route through the ordinary path AFTER the preparation completed, then
/// commit the transition. The prepared group must be found `Maintained`
/// (skipping the fenced staging walk), the churned route must appear in the
/// shared transition inventory (the prepared table is live, not a snapshot),
/// and every member must carry the same encode-once cell.
#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "the fixture keeps prepare, churn, and commit phases in one scenario"
)]
async fn prepared_destination_commits_with_interleaved_churn() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());
    let probes = Arc::new(AtomicUsize::new(0));
    let reuses = Arc::new(AtomicUsize::new(0));
    let old_policy = community_chain(0xFDE8_0001);
    let next_policy = community_chain(0xFDE8_0002);
    let peers = [
        IpAddr::V4(Ipv4Addr::new(10, 61, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 61, 0, 2)),
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
                    profile: 61,
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
    let source = Ipv4Addr::new(192, 0, 2, 61);
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: IpAddr::V4(source),
        announced: vec![
            crate::test_support::make_route(
                Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24),
                source,
            ),
            crate::test_support::make_route(
                Ipv4Prefix::new(Ipv4Addr::new(203, 0, 114, 0), 24),
                source,
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
    tx.send(RibUpdate::PrepareExportPolicyDestination {
        peer: peers[0],
        export_policy: Some(next_policy.clone()),
        reply,
    })
    .await
    .unwrap();
    response.await.unwrap().unwrap();
    assert_eq!(
        query_uncommitted_policy_transition_groups(&tx).await,
        1,
        "the prepared destination is a staged, still-unowned group"
    );

    // Churn AFTER preparation completed: the new prefix reaches members
    // through the ordinary delta path AND must land in the prepared table.
    let churned = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 115, 0), 24);
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: IpAddr::V4(source),
        announced: vec![crate::test_support::make_route(churned, source)],
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
    assert_eq!(
        response.await.unwrap().unwrap(),
        crate::update::ExportPolicyCohortOutcome::Committed
    );
    let mut shared_cells = Vec::new();
    for receiver in &mut receivers {
        let update = receiver.recv().await.unwrap();
        assert!(update.withdraw.is_empty());
        assert_eq!(update.announce.len(), 3, "all three routes changed chains");
        assert!(
            update
                .announce
                .iter()
                .any(|route| route.prefix == Prefix::V4(churned)),
            "the prepared table must have tracked the post-preparation churn"
        );
        shared_cells.push(Arc::clone(update.shared_group_encode.as_ref().unwrap()));
    }
    assert!(Arc::ptr_eq(&shared_cells[0], &shared_cells[1]));
    assert_eq!(
        query_uncommitted_policy_transition_groups(&tx).await,
        0,
        "the committed destination is owned; nothing uncommitted remains"
    );

    drop(tx);
    handle.await.unwrap();
}

/// A prepared destination whose cohort never commits is removed by the
/// explicit discard command, so an orphaned staged table cannot keep
/// consuming per-churn staging work.
#[tokio::test]
async fn discarded_prepared_destination_is_removed() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());
    let old_policy = community_chain(0xFDE8_0001);
    let next_policy = community_chain(0xFDE8_0002);
    let peers = [
        IpAddr::V4(Ipv4Addr::new(10, 62, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 62, 0, 2)),
    ];
    let mut receivers = Vec::new();
    for peer in peers {
        let mut spec = PeerUpSpec::ibgp(peer);
        spec.route_reflector_client = true;
        spec.export_policy = Some(old_policy.clone());
        receivers.push(peer_up(&tx, spec).await);
    }
    let source = Ipv4Addr::new(192, 0, 2, 62);
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: IpAddr::V4(source),
        announced: vec![crate::test_support::make_route(
            Ipv4Prefix::new(Ipv4Addr::new(203, 0, 116, 0), 24),
            source,
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
    tx.send(RibUpdate::PrepareExportPolicyDestination {
        peer: peers[0],
        export_policy: Some(next_policy.clone()),
        reply,
    })
    .await
    .unwrap();
    response.await.unwrap().unwrap();
    assert_eq!(query_uncommitted_policy_transition_groups(&tx).await, 1);

    tx.send(RibUpdate::DiscardPreparedExportPolicyDestination {
        peer: peers[0],
        export_policy: Some(next_policy),
    })
    .await
    .unwrap();
    assert_eq!(
        query_uncommitted_policy_transition_groups(&tx).await,
        0,
        "the unowned prepared group must be removed"
    );

    drop(tx);
    handle.await.unwrap();
}

/// A transition sent immediately after (or racing) a preparation must
/// commit and leave no uncommitted group behind, whether the preparation
/// completed (Maintained path) or was superseded mid-walk (discarded, then
/// ordinary Created path).
#[tokio::test]
async fn transition_immediately_after_prepare_commits_without_leaks() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());
    let probes = Arc::new(AtomicUsize::new(0));
    let reuses = Arc::new(AtomicUsize::new(0));
    let old_policy = community_chain(0xFDE8_0001);
    let next_policy = community_chain(0xFDE8_0002);
    let peers = [
        IpAddr::V4(Ipv4Addr::new(10, 63, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 63, 0, 2)),
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
                    profile: 63,
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
    let source = Ipv4Addr::new(192, 0, 2, 63);
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: IpAddr::V4(source),
        announced: vec![crate::test_support::make_route(
            Ipv4Prefix::new(Ipv4Addr::new(203, 0, 117, 0), 24),
            source,
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

    // No await between the two commands: the transition may supersede the
    // preparation mid-walk or find it complete — both must commit cleanly.
    let (prepare_reply, prepare_response) = oneshot::channel();
    tx.send(RibUpdate::PrepareExportPolicyDestination {
        peer: peers[0],
        export_policy: Some(next_policy.clone()),
        reply: prepare_reply,
    })
    .await
    .unwrap();
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
        response.await.unwrap().unwrap(),
        crate::update::ExportPolicyCohortOutcome::Committed
    );
    // The prepare reply resolved either way (Ok if it finished first, or
    // dropped/Err when superseded); it must never hang.
    let _ = prepare_response.await;
    for receiver in &mut receivers {
        let update = receiver.recv().await.unwrap();
        assert_eq!(update.announce.len(), 1);
        assert!(update.shared_group_encode.is_some());
    }
    assert_eq!(query_uncommitted_policy_transition_groups(&tx).await, 0);

    drop(tx);
    handle.await.unwrap();
}

/// Regression test for membership-during-prestage (LAN-463): a peer whose
/// export policy is content-equal to a mid-walk prestaged destination joins
/// that group via the ordinary registration seam. The join must not adopt
/// the partial table — the prestage is discarded and the group rebuilt, so
/// the joiner's initial dump carries the full table.
#[expect(
    clippy::too_many_lines,
    reason = "the regression fixture preserves full session, route, and prestage-race setup"
)]
#[tokio::test]
async fn prestage_mid_walk_join_of_prestaged_destination() {
    let (tx, rx) = mpsc::channel(64);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    // One test-sized (1-prefix) slice per prestage advance.
    manager.flush_poll_budget = std::time::Duration::ZERO;
    let handle = tokio::spawn(manager.run());
    let old_policy = community_chain(0xFDE8_0001);
    let next_policy = community_chain(0xFDE8_0002);
    let peers = [
        IpAddr::V4(Ipv4Addr::new(10, 99, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 99, 0, 2)),
    ];
    let mut receivers = Vec::new();
    for peer in peers {
        let mut spec = PeerUpSpec::ibgp(peer);
        spec.route_reflector_client = true;
        spec.export_policy = Some(old_policy.clone());
        receivers.push(peer_up(&tx, spec).await);
    }
    let source = Ipv4Addr::new(192, 0, 2, 99);
    let announced = (0..3)
        .map(|i| {
            crate::test_support::make_route(
                Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113 + i, 0), 24),
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
        assert_eq!(receiver.recv().await.unwrap().announce.len(), 3);
    }

    // Queue the prestage AND a stranger's PeerUp (content-equal policy)
    // back-to-back: mutation traffic outranks the walk, so the join lands
    // on the still-partial prestaged table.
    let (reply, prepare_response) = oneshot::channel();
    tx.send(RibUpdate::PrepareExportPolicyDestination {
        peer: peers[0],
        export_policy: Some(next_policy.clone()),
        reply,
    })
    .await
    .unwrap();
    let stranger = IpAddr::V4(Ipv4Addr::new(10, 99, 0, 3));
    let (stranger_tx, mut stranger_rx) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        per_client_best: false,
        interpret_rfc1997: true,
        session_id: 0,
        peer: stranger,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: stranger_tx,
        export_policy: Some(next_policy.clone()),
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
    // The prepare reply resolves either way (Ok if the walk finished before
    // the join landed, Err when the join discarded it); it must never hang.
    let _ = prepare_response.await;

    // The stranger owns the group now.
    let group = query_update_group(&tx, stranger).await;
    assert!(group.starts_with("group:"), "stranger ungrouped: {group}");
    assert_eq!(
        query_uncommitted_policy_transition_groups(&tx).await,
        0,
        "prestaged group became OWNED mid-walk"
    );

    // Churn one more prefix so every member gets one ordinary delta.
    let churned = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 120, 0), 24);
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: IpAddr::V4(source),
        announced: vec![crate::test_support::make_route(churned, source)],
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

    // Collect everything the stranger was ever sent.
    let mut stranger_announced: Vec<Prefix> = Vec::new();
    let mut got_eor = false;
    while let Ok(Some(update)) =
        tokio::time::timeout(std::time::Duration::from_millis(300), stranger_rx.recv()).await
    {
        stranger_announced.extend(update.announce.iter().map(|r| r.prefix));
        got_eor |= !update.end_of_rib.is_empty();
    }
    assert!(got_eor, "stranger never finished its initial dump");
    assert_eq!(
        stranger_announced.len(),
        4,
        "UNDER-ADVERTISE: stranger received {stranger_announced:?}, \
         but the group table holds 4 routes"
    );

    drop(tx);
    handle.await.unwrap();
}

/// Control for the membership-during-prestage regression test above: the
/// same join with no prestage in flight replays the full group table.
#[expect(
    clippy::too_many_lines,
    reason = "the regression fixture preserves full session, route, and join setup"
)]
#[tokio::test]
async fn prestage_control_join_without_prestage() {
    let (tx, rx) = mpsc::channel(64);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    // One test-sized (1-prefix) slice per prestage advance.
    manager.flush_poll_budget = std::time::Duration::ZERO;
    let handle = tokio::spawn(manager.run());
    let old_policy = community_chain(0xFDE8_0001);
    let next_policy = community_chain(0xFDE8_0002);
    let peers = [
        IpAddr::V4(Ipv4Addr::new(10, 99, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 99, 0, 2)),
    ];
    let mut receivers = Vec::new();
    for peer in peers {
        let mut spec = PeerUpSpec::ibgp(peer);
        spec.route_reflector_client = true;
        spec.export_policy = Some(old_policy.clone());
        receivers.push(peer_up(&tx, spec).await);
    }
    let source = Ipv4Addr::new(192, 0, 2, 99);
    let announced = (0..3)
        .map(|i| {
            crate::test_support::make_route(
                Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113 + i, 0), 24),
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
        assert_eq!(receiver.recv().await.unwrap().announce.len(), 3);
    }

    // The same join as the regression test above, with no prestage queued.
    let stranger = IpAddr::V4(Ipv4Addr::new(10, 99, 0, 3));
    let (stranger_tx, mut stranger_rx) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        per_client_best: false,
        interpret_rfc1997: true,
        session_id: 0,
        peer: stranger,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: stranger_tx,
        export_policy: Some(next_policy.clone()),
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
    // The stranger owns its group.
    let group = query_update_group(&tx, stranger).await;
    assert!(group.starts_with("group:"), "stranger ungrouped: {group}");
    assert_eq!(
        query_uncommitted_policy_transition_groups(&tx).await,
        0,
        "no unowned group may remain after the join"
    );

    // Churn one more prefix so every member gets one ordinary delta.
    let churned = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 120, 0), 24);
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: IpAddr::V4(source),
        announced: vec![crate::test_support::make_route(churned, source)],
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

    // Collect everything the stranger was ever sent.
    let mut stranger_announced: Vec<Prefix> = Vec::new();
    let mut got_eor = false;
    while let Ok(Some(update)) =
        tokio::time::timeout(std::time::Duration::from_millis(300), stranger_rx.recv()).await
    {
        stranger_announced.extend(update.announce.iter().map(|r| r.prefix));
        got_eor |= !update.end_of_rib.is_empty();
    }
    assert!(got_eor, "stranger never finished its initial dump");
    assert_eq!(
        stranger_announced.len(),
        4,
        "UNDER-ADVERTISE: stranger received {stranger_announced:?}, \
         but the group table holds 4 routes"
    );

    drop(tx);
    handle.await.unwrap();
}

/// A completed prestage whose cohort later resolves a DIFFERENT destination
/// must not leak the staged memberless group: the transition discards the
/// exact prestaged gid when it commits elsewhere.
#[tokio::test]
async fn prestage_discarded_when_cohort_resolves_different_destination() {
    let (tx, rx) = mpsc::channel(64);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    manager.flush_poll_budget = std::time::Duration::ZERO;
    let handle = tokio::spawn(manager.run());
    let old_policy = community_chain(0xFDE8_0001);
    let prepared_policy = community_chain(0xFDE8_0002);
    let committed_policy = community_chain(0xFDE8_0003);
    let peers = [
        IpAddr::V4(Ipv4Addr::new(10, 99, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 99, 0, 2)),
    ];
    let mut receivers = Vec::new();
    for peer in peers {
        let mut spec = PeerUpSpec::ibgp(peer);
        spec.route_reflector_client = true;
        spec.export_policy = Some(old_policy.clone());
        receivers.push(peer_up(&tx, spec).await);
    }
    let source = Ipv4Addr::new(192, 0, 2, 99);
    let announced = (0..3)
        .map(|i| {
            crate::test_support::make_route(
                Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113 + i, 0), 24),
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
        assert_eq!(receiver.recv().await.unwrap().announce.len(), 3);
    }

    // Prepare one destination and let the walk complete.
    let (prepare_reply, prepare_response) = oneshot::channel();
    tx.send(RibUpdate::PrepareExportPolicyDestination {
        peer: peers[0],
        export_policy: Some(prepared_policy.clone()),
        reply: prepare_reply,
    })
    .await
    .unwrap();
    prepare_response.await.unwrap().unwrap();

    // The cohort then commits under a DIFFERENT policy (different group key).
    let (reply, response) = oneshot::channel();
    tx.send(RibUpdate::ReplacePeerExportPolicies {
        replacements: peers
            .iter()
            .map(|&peer| crate::update::PeerExportPolicyReplacement {
                peer,
                export_policy: Some(committed_policy.clone()),
            })
            .collect(),
        reply,
    })
    .await
    .unwrap();
    assert_eq!(
        response.await.unwrap().unwrap(),
        crate::update::ExportPolicyCohortOutcome::Committed
    );
    // The prestaged group (never adopted by the cohort) must be gone.
    assert_eq!(
        query_uncommitted_policy_transition_groups(&tx).await,
        0,
        "the prestaged destination leaked past a commit that resolved elsewhere"
    );

    drop(tx);
    handle.await.unwrap();
}

/// Slow-peer isolation (LAN-470): a transport `PeerSlowState` signal
/// moves a grouped member onto the per-peer fallback path (ungrouped
/// reason `slow_peer`) without disturbing its group-mates, and the
/// clear signal regroups it with its old group through the ordinary
/// regroup lifecycle.
#[tokio::test]
async fn slow_peer_isolation_moves_member_to_fallback_and_back() {
    let metrics = BgpMetrics::new();
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, metrics.clone());
    let handle = tokio::spawn(manager.run());

    let a = IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1));
    let b = IpAddr::V4(Ipv4Addr::new(10, 0, 2, 2));
    let _rx_a = peer_up(&tx, PeerUpSpec::ibgp(a)).await;
    let _rx_b = peer_up(&tx, PeerUpSpec::ibgp(b)).await;
    assert_eq!(query_update_group(&tx, a).await, "group:0");
    assert_eq!(query_update_group(&tx, b).await, "group:0");

    // Transport flags `a` slow: it leaves the shared group for the
    // per-peer path; its group-mate is untouched.
    tx.send(RibUpdate::PeerSlowState {
        peer: a,
        session_id: 0,
        slow: true,
    })
    .await
    .unwrap();
    assert_eq!(query_update_group(&tx, a).await, "slow_peer");
    assert_eq!(query_update_group(&tx, b).await, "group:0");
    assert_metric(
        gauge_metric_value(&metrics, "bgp_update_group_fallback_peers", &[]),
        1.0,
        "bgp_update_group_fallback_peers while isolated",
    );

    // Duplicate signal: idempotent, still isolated.
    tx.send(RibUpdate::PeerSlowState {
        peer: a,
        session_id: 0,
        slow: true,
    })
    .await
    .unwrap();
    assert_eq!(query_update_group(&tx, a).await, "slow_peer");

    // The flag clears: the peer regroups with its old group.
    tx.send(RibUpdate::PeerSlowState {
        peer: a,
        session_id: 0,
        slow: false,
    })
    .await
    .unwrap();
    assert_eq!(query_update_group(&tx, a).await, "group:0");
    assert_eq!(query_update_group(&tx, b).await, "group:0");
    assert_metric(
        gauge_metric_value(&metrics, "bgp_update_group_fallback_peers", &[]),
        0.0,
        "bgp_update_group_fallback_peers after recovery",
    );

    // Session teardown clears any lingering isolation: a replacement
    // session for the same address starts on the shared path.
    tx.send(RibUpdate::PeerSlowState {
        peer: a,
        session_id: 0,
        slow: true,
    })
    .await
    .unwrap();
    assert_eq!(query_update_group(&tx, a).await, "slow_peer");
    tx.send(RibUpdate::PeerDown {
        peer: a,
        session_id: 0,
    })
    .await
    .unwrap();
    let _rx_a2 = peer_up(&tx, PeerUpSpec::ibgp(a)).await;
    assert_eq!(
        query_update_group(&tx, a).await,
        "group:0",
        "isolation must not survive the session that reported it"
    );

    drop(tx);
    handle.await.unwrap();
}

/// An eBGP route-server candidate ranked by AS-path length: rank 1
/// wins best path, higher ranks lose in order.
fn ranked_rs_route(prefix: Ipv4Prefix, src: Ipv4Addr, rank: u32) -> Route {
    Route {
        prefix: Prefix::V4(prefix),
        next_hop: IpAddr::V4(src),
        link_local_next_hop: None,
        next_hop_scope: None,
        peer: IpAddr::V4(src),
        attributes: Arc::new(vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath {
                segments: vec![AsPathSegment::AsSequence(vec![65000 + rank; rank as usize])],
            }),
        ]),
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

/// ADR-0126 Decision 9 migration pin: a CONVERGED ungrouped
/// per-client-best fleet with overlapping announcements regroups
/// through the ordinary baseline machinery (`recompute_update_group`
/// via the slow-isolation membership seam) with a BYTE-EMPTY diff —
/// zero announces and zero withdraws on every member's wire, no
/// session resets — and the rebuilt group's exception lane holds
/// exactly the substitutions the ungrouped walks were delivering
/// (proven on the wire by the RFC 2918 refresh replay of `adv(m)`).
#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "one end-to-end scenario proves the ADR-0126 converged-regroup migration"
)]
async fn converged_per_client_best_fleet_regroups_byte_empty() {
    tokio::time::pause();
    let metrics = BgpMetrics::new();
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, metrics.clone());
    let handle = tokio::spawn(manager.run());

    let a = Ipv4Addr::new(10, 0, 5, 1);
    let b = Ipv4Addr::new(10, 0, 5, 2);
    let c = Ipv4Addr::new(10, 0, 5, 3);
    let members = [a, b, c];
    let mut receivers = Vec::new();
    for member in members {
        let mut spec = PeerUpSpec::ebgp(IpAddr::V4(member));
        spec.per_client_best = true;
        receivers.push(peer_up(&tx, spec).await);
    }

    // Move the fleet onto the per-peer path (the pre-flip shape a
    // migrating deployment converged on) through the one membership
    // seam that changes no staging input.
    for member in members {
        tx.send(RibUpdate::PeerSlowState {
            peer: IpAddr::V4(member),
            session_id: 0,
            slow: true,
        })
        .await
        .unwrap();
        assert_eq!(
            query_update_group(&tx, IpAddr::V4(member)).await,
            "slow_peer"
        );
    }

    // Overlapping announcements from the members themselves:
    // p1 ranked A > B > C (winner A, runner-up B), p2 ranked B > C
    // (winner B, runner-up C). Each member's ungrouped walk delivers
    // the winner, with the substitution toward the winner's source.
    let p1 = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 0), 24);
    let p2 = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 101, 0), 24);
    for (source, routes) in [
        (a, vec![ranked_rs_route(p1, a, 1)]),
        (
            b,
            vec![ranked_rs_route(p1, b, 2), ranked_rs_route(p2, b, 1)],
        ),
        (
            c,
            vec![ranked_rs_route(p1, c, 3), ranked_rs_route(p2, c, 2)],
        ),
    ] {
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
    let _ = query_best_routes(&tx).await;
    // Converged: drain the ungrouped convergence traffic and verify
    // each member's final wire state (fold announce/withdraw order).
    let mut folded: HashMap<Ipv4Addr, HashMap<Prefix, IpAddr>> = HashMap::new();
    for (member, out_rx) in members.iter().zip(receivers.iter_mut()) {
        let table = folded.entry(*member).or_default();
        while let Ok(update) = out_rx.try_recv() {
            for (prefix, _) in &update.withdraw {
                table.remove(prefix);
            }
            for route in update.announce.iter() {
                table.insert(route.prefix, route.peer);
            }
        }
    }
    let expect = |m: Ipv4Addr, w1: Ipv4Addr, w2: Ipv4Addr| {
        assert_eq!(
            folded[&m],
            HashMap::from([
                (Prefix::V4(p1), IpAddr::V4(w1)),
                (Prefix::V4(p2), IpAddr::V4(w2)),
            ]),
            "ungrouped converged view for {m}"
        );
    };
    expect(a, b, b); // p1: substitution toward source(w); p2: winner
    expect(b, a, c); // p2: substitution toward source(w)
    expect(c, a, b); // non-source: both winners

    // The flip: clear the isolation — each member regroups through
    // `recompute_update_group` with an adv(m)-aware baseline.
    for member in members {
        tx.send(RibUpdate::PeerSlowState {
            peer: IpAddr::V4(member),
            session_id: 0,
            slow: false,
        })
        .await
        .unwrap();
    }
    let label = query_update_group(&tx, IpAddr::V4(a)).await;
    assert!(label.starts_with("group:"), "regrouped label: {label}");
    for member in [b, c] {
        assert_eq!(query_update_group(&tx, IpAddr::V4(member)).await, label);
    }
    // The regroup diff is consumed by the distribute pass inside the
    // slow-state handler; advance past the resync interval anyway so
    // any deferred work would flush before the emptiness assertions.
    for _ in 0..3 {
        tokio::time::advance(Duration::from_secs(2)).await;
        tokio::task::yield_now().await;
    }
    let _ = query_best_routes(&tx).await;
    // Guard against a vacuous pass: every membership move must have
    // been a REAL regroup (3 grouped→slow + 3 slow→grouped). The
    // regroup's baseline diff is consumed synchronously by the
    // distribute pass inside the slow-state handler — a member left
    // pending would instead surface as over-emission below or as a
    // stale refresh replay in the lane proof.
    assert_metric(regroups_total(&metrics), 6.0, "regroups_total");
    for (member, out_rx) in members.iter().zip(receivers.iter_mut()) {
        assert!(
            out_rx.try_recv().is_err(),
            "converged regroup must be byte-empty on {member}'s wire"
        );
    }

    // The rebuilt lane is the O(overlapped prefixes) sidecar: exactly
    // the two runner-up entries the ungrouped walks were substituting.
    assert_metric(
        gauge_metric_value(&metrics, "bgp_update_group_runner_up_entries", &[]),
        2.0,
        "bgp_update_group_runner_up_entries",
    );

    // Wire-level lane proof: an RFC 2918 refresh replays adv(m); the
    // winner sources receive their substitutions, byte-for-byte what
    // the ungrouped path had delivered.
    for (member, w1, w2) in [(a, b, b), (b, a, c), (c, a, b)] {
        tx.send(RibUpdate::RouteRefreshRequest {
            peer: IpAddr::V4(member),
            session_id: 0,
            afi: Afi::Ipv4,
            safi: Safi::Unicast,
        })
        .await
        .unwrap();
        let _ = query_best_routes(&tx).await;
        let idx = members.iter().position(|m| *m == member).unwrap();
        let mut replayed = HashMap::new();
        while let Ok(update) = receivers[idx].try_recv() {
            assert!(update.withdraw.is_empty(), "refresh replay never withdraws");
            for route in update.announce.iter() {
                replayed.insert(route.prefix, route.peer);
            }
        }
        assert_eq!(
            replayed,
            HashMap::from([
                (Prefix::V4(p1), IpAddr::V4(w1)),
                (Prefix::V4(p2), IpAddr::V4(w2)),
            ]),
            "refresh replay of adv({member}) must match the ungrouped view"
        );
    }

    drop(tx);
    handle.await.unwrap();
}
