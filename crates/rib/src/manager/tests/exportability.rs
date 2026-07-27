use std::any::Any;
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, RwLock};

use super::*;
use crate::update::{
    ExactExportCandidate, ExactExportEncoder, ExactExportError, ExactExportErrorCode,
    ExactExportKey, ExactExportResult, ExactExportSnapshot,
};

#[derive(Clone)]
struct MockExportConfig {
    generation: u64,
    rejected: HashSet<ExactExportKey>,
}

struct MockExactExportEncoder {
    config: RwLock<MockExportConfig>,
    probed: Arc<Mutex<Vec<ExactExportKey>>>,
    probe_batches: Arc<AtomicUsize>,
}

impl MockExactExportEncoder {
    fn accepting(generation: u64) -> Arc<Self> {
        Arc::new(Self {
            config: RwLock::new(MockExportConfig {
                generation,
                rejected: HashSet::new(),
            }),
            probed: Arc::new(Mutex::new(Vec::new())),
            probe_batches: Arc::new(AtomicUsize::new(0)),
        })
    }

    fn set_profile(&self, generation: u64, rejected: impl IntoIterator<Item = ExactExportKey>) {
        *self.config.write().unwrap() = MockExportConfig {
            generation,
            rejected: rejected.into_iter().collect(),
        };
    }

    fn probed(&self) -> Vec<ExactExportKey> {
        self.probed.lock().unwrap().clone()
    }

    fn probe_batch_count(&self) -> usize {
        self.probe_batches.load(Ordering::Relaxed)
    }
}

struct MockExactExportSnapshot {
    config: MockExportConfig,
    probed: Arc<Mutex<Vec<ExactExportKey>>>,
    probe_batches: Arc<AtomicUsize>,
}

impl ExactExportSnapshot for MockExactExportSnapshot {
    fn owner_id(&self) -> u64 {
        1
    }

    fn generation(&self) -> u64 {
        self.config.generation
    }

    fn probe_announcement(
        &self,
        candidate: ExactExportCandidate<'_>,
    ) -> Result<ExactExportResult, ExactExportError> {
        let key = candidate.key();
        self.probed.lock().unwrap().push(key.clone());
        if self.config.rejected.contains(&key) {
            return Err(ExactExportError::new(
                ExactExportErrorCode::MessageTooLong,
                "fixture route exceeds the classic message ceiling ".repeat(16),
            ));
        }
        Ok(ExactExportResult {
            encoded_len: 64,
            max_len: 65_535,
            generation: self.config.generation,
        })
    }

    fn probe_announcements(
        &self,
        candidates: &[ExactExportCandidate<'_>],
    ) -> Vec<Result<ExactExportResult, ExactExportError>> {
        self.probe_batches.fetch_add(1, Ordering::Relaxed);
        candidates
            .iter()
            .copied()
            .map(|candidate| self.probe_announcement(candidate))
            .collect()
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl ExactExportEncoder for MockExactExportEncoder {
    fn owner_id(&self) -> u64 {
        1
    }

    fn snapshot(&self) -> Arc<dyn ExactExportSnapshot> {
        Arc::new(MockExactExportSnapshot {
            config: self.config.read().unwrap().clone(),
            probed: Arc::clone(&self.probed),
            probe_batches: Arc::clone(&self.probe_batches),
        })
    }
}

struct ReusableExactExportEncoder {
    owner_id: u64,
    wire_profile: u64,
    encoded_len: usize,
    max_len: usize,
    wrong_reuse_cardinality: bool,
    probed: Arc<AtomicUsize>,
}

impl ReusableExactExportEncoder {
    fn new(owner_id: u64, wire_profile: u64) -> Arc<Self> {
        Arc::new(Self {
            owner_id,
            wire_profile,
            encoded_len: 64,
            max_len: 4_096,
            wrong_reuse_cardinality: false,
            probed: Arc::new(AtomicUsize::new(0)),
        })
    }

    fn with_wrong_reuse_cardinality(owner_id: u64, wire_profile: u64) -> Arc<Self> {
        Arc::new(Self {
            owner_id,
            wire_profile,
            encoded_len: 64,
            max_len: 4_096,
            wrong_reuse_cardinality: true,
            probed: Arc::new(AtomicUsize::new(0)),
        })
    }

    fn with_limits(
        owner_id: u64,
        wire_profile: u64,
        encoded_len: usize,
        max_len: usize,
    ) -> Arc<Self> {
        Arc::new(Self {
            owner_id,
            wire_profile,
            encoded_len,
            max_len,
            wrong_reuse_cardinality: false,
            probed: Arc::new(AtomicUsize::new(0)),
        })
    }

    fn probe_count(&self) -> usize {
        self.probed.load(Ordering::Relaxed)
    }
}

struct ReusableExactExportSnapshot {
    owner_id: u64,
    wire_profile: u64,
    encoded_len: usize,
    max_len: usize,
    wrong_reuse_cardinality: bool,
    probed: Arc<AtomicUsize>,
}

impl ReusableExactExportSnapshot {
    fn result_for_len(&self, encoded_len: usize) -> Result<ExactExportResult, ExactExportError> {
        if encoded_len > self.max_len {
            return Err(ExactExportError::new(
                ExactExportErrorCode::MessageTooLong,
                format_args!(
                    "fixture UPDATE is {encoded_len} bytes; maximum is {} bytes",
                    self.max_len
                ),
            ));
        }
        Ok(ExactExportResult {
            encoded_len,
            max_len: self.max_len,
            generation: 1,
        })
    }
}

impl ExactExportSnapshot for ReusableExactExportSnapshot {
    fn owner_id(&self) -> u64 {
        self.owner_id
    }

    fn generation(&self) -> u64 {
        1
    }

    fn probe_announcement(
        &self,
        _candidate: ExactExportCandidate<'_>,
    ) -> Result<ExactExportResult, ExactExportError> {
        self.probed.fetch_add(1, Ordering::Relaxed);
        self.result_for_len(self.encoded_len)
    }

    fn reuse_successful_probes(
        &self,
        source: &dyn ExactExportSnapshot,
        encoded_lengths: &[usize],
    ) -> Option<Vec<Result<ExactExportResult, ExactExportError>>> {
        let source = source.as_any().downcast_ref::<Self>()?;
        (self.wire_profile == source.wire_profile).then(|| {
            if self.wrong_reuse_cardinality {
                return Vec::new();
            }
            encoded_lengths
                .iter()
                .map(|encoded_len| self.result_for_len(*encoded_len))
                .collect()
        })
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl ExactExportEncoder for ReusableExactExportEncoder {
    fn owner_id(&self) -> u64 {
        self.owner_id
    }

    fn snapshot(&self) -> Arc<dyn ExactExportSnapshot> {
        Arc::new(ReusableExactExportSnapshot {
            owner_id: self.owner_id,
            wire_profile: self.wire_profile,
            encoded_len: self.encoded_len,
            max_len: self.max_len,
            wrong_reuse_cardinality: self.wrong_reuse_cardinality,
            probed: Arc::clone(&self.probed),
        })
    }
}

struct WrongCardinalityBatchEncoder {
    probed: Arc<Mutex<Vec<ExactExportKey>>>,
}

struct WrongCardinalityBatchSnapshot {
    probed: Arc<Mutex<Vec<ExactExportKey>>>,
}

impl ExactExportSnapshot for WrongCardinalityBatchSnapshot {
    fn owner_id(&self) -> u64 {
        2
    }

    fn generation(&self) -> u64 {
        1
    }

    fn probe_announcement(
        &self,
        candidate: ExactExportCandidate<'_>,
    ) -> Result<ExactExportResult, ExactExportError> {
        self.probed.lock().unwrap().push(candidate.key());
        Ok(ExactExportResult {
            encoded_len: 64,
            max_len: 4_096,
            generation: 1,
        })
    }

    fn probe_announcements(
        &self,
        _candidates: &[ExactExportCandidate<'_>],
    ) -> Vec<Result<ExactExportResult, ExactExportError>> {
        Vec::new()
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl ExactExportEncoder for WrongCardinalityBatchEncoder {
    fn owner_id(&self) -> u64 {
        2
    }

    fn snapshot(&self) -> Arc<dyn ExactExportSnapshot> {
        Arc::new(WrongCardinalityBatchSnapshot {
            probed: Arc::clone(&self.probed),
        })
    }
}

#[derive(Default)]
struct ExactBatch {
    announce: Vec<Route>,
    withdraw: Vec<(Prefix, u32)>,
    flowspec_announce: Vec<FlowSpecRoute>,
    flowspec_withdraw: Vec<crate::route::FlowSpecKey>,
    evpn_announce: Vec<EvpnRibRoute>,
    evpn_withdraw: Vec<rustbgpd_wire::EvpnRouteKey>,
    bgpls_announce: Vec<BgpLsRibRoute>,
    bgpls_withdraw: Vec<BgpLsRouteKey>,
    vpn_announce: Vec<VpnRibRoute>,
    vpn_withdraw: Vec<crate::route::VpnRibRouteKey>,
    labeled_announce: Vec<crate::route::LabeledRibRoute>,
    labeled_withdraw: Vec<crate::route::LabeledRibRouteKey>,
    rtc_announce: Vec<crate::route::RtcRibRoute>,
    rtc_withdraw: Vec<crate::route::RtcRibRouteKey>,
}

fn test_manager() -> RibManager {
    let (_tx, rx) = mpsc::channel(1);
    RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new())
}

fn register_exact_target(
    manager: &mut RibManager,
    peer: IpAddr,
    encoder: Arc<dyn ExactExportEncoder>,
) -> mpsc::Receiver<OutboundRouteUpdate> {
    let (tx, rx) = mpsc::channel(16);
    manager.outbound_peers.insert(peer, tx);
    manager.peer_export_encoders.insert(peer, encoder);
    rx
}

fn commit_batch(manager: &mut RibManager, peer: IpAddr, batch: ExactBatch) -> bool {
    let next_hop_override = vec![None; batch.announce.len()].into();
    manager.try_send_and_commit_outbound_update(
        peer,
        next_hop_override,
        batch.announce.into(),
        batch.withdraw,
        Vec::new(),
        Vec::new(),
        batch.flowspec_announce,
        batch.flowspec_withdraw,
        batch.evpn_announce,
        batch.evpn_withdraw,
        batch.bgpls_announce,
        batch.bgpls_withdraw,
        batch.vpn_announce,
        batch.vpn_withdraw,
        batch.labeled_announce,
        batch.labeled_withdraw,
        batch.rtc_announce,
        batch.rtc_withdraw,
    )
}

fn commit_shared_exact_batch_with_precommit(
    manager: &mut RibManager,
    peer: IpAddr,
    batch: ExactBatch,
    group_prior: HashSet<ExactExportKey>,
    cache: &mut crate::manager::distribution::SharedUnicastProbeCache,
) -> bool {
    let next_hop_override = vec![None; batch.announce.len()].into();
    manager.try_send_and_commit_outbound_update_with_group_prior(
        peer,
        next_hop_override,
        batch.announce.into(),
        batch.withdraw,
        Vec::new(),
        Vec::new(),
        batch.flowspec_announce,
        batch.flowspec_withdraw,
        batch.evpn_announce,
        batch.evpn_withdraw,
        batch.bgpls_announce,
        batch.bgpls_withdraw,
        batch.vpn_announce,
        batch.vpn_withdraw,
        batch.labeled_announce,
        batch.labeled_withdraw,
        batch.rtc_announce,
        batch.rtc_withdraw,
        group_prior,
        Some(crate::manager::distribution::SharedUnicastPrecommit {
            group_id: 7,
            probe_cache: cache,
            lazy_group_prior: None,
        }),
    )
}

fn commit_shared_unicast_with_cache(
    manager: &mut RibManager,
    peer: IpAddr,
    announce: Arc<[Route]>,
    next_hop_override: Arc<[Option<rustbgpd_policy::NextHopAction>]>,
    group_prior: HashSet<ExactExportKey>,
    cache: &mut crate::manager::distribution::SharedUnicastProbeCache,
) -> bool {
    commit_shared_unicast_with_precommit(
        manager,
        peer,
        announce,
        next_hop_override,
        group_prior,
        cache,
        None,
    )
}

fn commit_shared_unicast_with_precommit(
    manager: &mut RibManager,
    peer: IpAddr,
    announce: Arc<[Route]>,
    next_hop_override: Arc<[Option<rustbgpd_policy::NextHopAction>]>,
    group_prior: HashSet<ExactExportKey>,
    cache: &mut crate::manager::distribution::SharedUnicastProbeCache,
    lazy_group_prior: Option<crate::manager::distribution::LazyCleanGroupPrior<'_>>,
) -> bool {
    commit_shared_unicast_batch_with_precommit(
        manager,
        peer,
        announce,
        next_hop_override,
        Vec::new(),
        group_prior,
        cache,
        lazy_group_prior,
    )
}

#[expect(
    clippy::too_many_arguments,
    reason = "the helper exposes the grouped unicast batch fields needed by exact-export tests"
)]
fn commit_shared_unicast_batch_with_precommit(
    manager: &mut RibManager,
    peer: IpAddr,
    announce: Arc<[Route]>,
    next_hop_override: Arc<[Option<rustbgpd_policy::NextHopAction>]>,
    withdraw: Vec<(Prefix, u32)>,
    group_prior: HashSet<ExactExportKey>,
    cache: &mut crate::manager::distribution::SharedUnicastProbeCache,
    lazy_group_prior: Option<crate::manager::distribution::LazyCleanGroupPrior<'_>>,
) -> bool {
    manager.try_send_and_commit_outbound_update_with_group_prior(
        peer,
        next_hop_override,
        announce,
        withdraw,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        group_prior,
        Some(crate::manager::distribution::SharedUnicastPrecommit {
            group_id: 7,
            probe_cache: cache,
            lazy_group_prior,
        }),
    )
}

#[test]
fn lazy_clean_group_prior_falls_back_when_identity_or_stage_is_missing() {
    let target = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 40));
    let staged: HashMap<usize, Vec<crate::manager::update_groups::GroupDelta>> = HashMap::new();

    // Restoring either former `expect` makes one of these missing-input
    // cases panic instead of selecting the eager exact-reconciliation path.
    assert!(
        crate::manager::distribution::resolve_lazy_clean_group_prior(
            true,
            target,
            None,
            |group_id| staged.get(&group_id).map(Vec::as_slice),
        )
        .is_none()
    );
    assert!(
        crate::manager::distribution::resolve_lazy_clean_group_prior(
            true,
            target,
            Some(7),
            |group_id| staged.get(&group_id).map(Vec::as_slice),
        )
        .is_none()
    );
}

#[test]
fn lazy_clean_group_prior_defers_only_for_a_resolved_eligible_stage() {
    let source = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 41));
    let target = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 41));
    let route = make_route(
        Ipv4Prefix::new(Ipv4Addr::new(203, 0, 116, 0), 24),
        Ipv4Addr::new(198, 51, 100, 41),
    );
    let staged = HashMap::from([(
        7,
        vec![crate::manager::update_groups::GroupDelta {
            prefix: route.prefix,
            path_id: route.path_id,
            new: Some((route.clone(), None)),
            old_source: Some(source),
            policy_label: None,
            source_attrs: None,
        }],
    )]);

    // Always selecting the eager path makes the eligible assertion fail;
    // ignoring eligibility makes the second assertion fail.
    let resolved = crate::manager::distribution::resolve_lazy_clean_group_prior(
        true,
        target,
        Some(7),
        |group_id| staged.get(&group_id).map(Vec::as_slice),
    )
    .expect("an eligible existing stage must be deferred");
    assert_eq!(resolved.peer, target);
    assert_eq!(resolved.deltas.len(), 1);
    assert_eq!(resolved.deltas[0].prefix, route.prefix);
    assert!(
        crate::manager::distribution::resolve_lazy_clean_group_prior(
            false,
            target,
            Some(7),
            |group_id| staged.get(&group_id).map(Vec::as_slice),
        )
        .is_none()
    );
}

#[test]
fn exact_export_error_detail_is_bounded_by_unicode_scalars() {
    let error = ExactExportError::new(ExactExportErrorCode::Encoding, "xé".repeat(300));
    assert_eq!(error.detail().chars().count(), 256);
    assert!(error.detail().is_char_boundary(error.detail().len()));
}

#[tokio::test]
async fn private_route_rejection_withdraws_once_then_recovers() {
    let peer = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24);
    let route = make_route(prefix, Ipv4Addr::new(198, 51, 100, 1));
    let key = ExactExportKey::Unicast(route.prefix, route.path_id);
    let encoder = MockExactExportEncoder::accepting(11);
    let mut manager = test_manager();
    let mut rx = register_exact_target(&mut manager, peer, encoder.clone());

    assert!(commit_batch(
        &mut manager,
        peer,
        ExactBatch {
            announce: vec![route.clone()],
            ..ExactBatch::default()
        }
    ));
    let accepted = rx.recv().await.unwrap();
    assert_eq!(accepted.announce.len(), 1);
    assert_eq!(accepted.announce[0].prefix, route.prefix);
    assert_eq!(accepted.announce[0].peer, route.peer);
    assert_eq!(accepted.exact_export_snapshot.unwrap().generation(), 11);
    assert!(manager.adj_ribs_out[&peer].get(&route.prefix, 0).is_some());

    encoder.set_profile(12, [key.clone()]);
    assert!(commit_batch(
        &mut manager,
        peer,
        ExactBatch {
            announce: vec![route.clone()],
            ..ExactBatch::default()
        }
    ));
    let rejected = rx.recv().await.unwrap();
    assert!(rejected.announce.is_empty());
    assert_eq!(rejected.withdraw, vec![(route.prefix, 0)]);
    assert_eq!(rejected.exact_export_snapshot.unwrap().generation(), 12);
    assert!(manager.adj_ribs_out[&peer].get(&route.prefix, 0).is_none());
    assert_eq!(
        manager.peer_unexportable[&peer],
        HashSet::from([key.clone()])
    );

    assert!(commit_batch(
        &mut manager,
        peer,
        ExactBatch {
            announce: vec![route.clone()],
            ..ExactBatch::default()
        }
    ));
    let repeated = rx.recv().await.unwrap();
    assert!(repeated.announce.is_empty());
    assert!(repeated.withdraw.is_empty(), "repeated rejection is quiet");
    assert!(manager.adj_ribs_out[&peer].get(&route.prefix, 0).is_none());

    encoder.set_profile(13, []);
    assert!(commit_batch(
        &mut manager,
        peer,
        ExactBatch {
            announce: vec![route.clone()],
            ..ExactBatch::default()
        }
    ));
    let recovered = rx.recv().await.unwrap();
    assert_eq!(recovered.announce.len(), 1);
    assert_eq!(recovered.announce[0].prefix, route.prefix);
    assert_eq!(recovered.announce[0].peer, route.peer);
    assert!(recovered.withdraw.is_empty());
    assert_eq!(recovered.exact_export_snapshot.unwrap().generation(), 13);
    assert!(!manager.peer_unexportable.contains_key(&peer));
    assert!(manager.adj_ribs_out[&peer].get(&route.prefix, 0).is_some());
}

#[tokio::test]
async fn grouped_withdrawal_only_skips_exact_probe_and_keeps_snapshot_commit() {
    let peer = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 61));
    let route = make_route(
        Ipv4Prefix::new(Ipv4Addr::new(203, 0, 116, 0), 24),
        Ipv4Addr::new(198, 51, 100, 61),
    );
    let key = ExactExportKey::Unicast(route.prefix, route.path_id);
    let encoder = MockExactExportEncoder::accepting(61);
    let mut manager = test_manager();
    let mut rx = register_exact_target(&mut manager, peer, encoder.clone());

    assert!(commit_batch(
        &mut manager,
        peer,
        ExactBatch {
            announce: vec![route.clone()],
            ..ExactBatch::default()
        }
    ));
    assert_eq!(rx.recv().await.unwrap().announce.len(), 1);
    assert_eq!(encoder.probe_batch_count(), 1);
    assert!(manager.adj_ribs_out[&peer].get(&route.prefix, 0).is_some());

    manager.adj_rib_out_commit_stats = Default::default();
    let mut cache = crate::manager::distribution::SharedUnicastProbeCache::default();
    assert!(commit_shared_unicast_batch_with_precommit(
        &mut manager,
        peer,
        Vec::<Route>::new().into(),
        Vec::<Option<rustbgpd_policy::NextHopAction>>::new().into(),
        vec![(route.prefix, route.path_id)],
        HashSet::from([key]),
        &mut cache,
        None,
    ));

    let withdrawn = rx.recv().await.unwrap();
    let snapshot = withdrawn
        .exact_export_snapshot
        .as_ref()
        .expect("route-bearing grouped withdrawal retains the concrete snapshot");
    assert_eq!((snapshot.owner_id(), snapshot.generation()), (1, 61));
    assert!(withdrawn.announce.is_empty());
    assert_eq!(withdrawn.withdraw, vec![(route.prefix, route.path_id)]);
    assert_eq!(
        encoder.probe_batch_count(),
        1,
        "withdrawal-only grouped precommit must not issue an empty exact batch"
    );
    assert_eq!(manager.adj_rib_out_commit_stats.exact_probe_batches, 0);
    assert_eq!(manager.adj_rib_out_commit_stats.exact_probe_candidates, 0);
    assert_eq!(manager.adj_rib_out_commit_stats.successful_commits, 1);
    assert_eq!(manager.adj_rib_out_commit_stats.successful_enqueues, 1);
    assert!(manager.adj_ribs_out[&peer].get(&route.prefix, 0).is_none());
    assert!(rx.try_recv().is_err(), "the commit enqueues exactly once");
}

#[tokio::test]
async fn grouped_mixed_family_rejection_still_probes_and_retires_overlay() {
    let peer = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 62));
    let source = Ipv4Addr::new(198, 51, 100, 62);
    let route = make_route(Ipv4Prefix::new(Ipv4Addr::new(203, 0, 117, 0), 24), source);
    let route_key = ExactExportKey::Unicast(route.prefix, route.path_id);
    let flowspec = make_flowspec_route(source);
    let flowspec_selection_key = flowspec.selection_key();
    let flowspec_key = ExactExportKey::FlowSpec(flowspec_selection_key.clone());
    let encoder = MockExactExportEncoder::accepting(62);
    let mut manager = test_manager();
    let mut rx = register_exact_target(&mut manager, peer, encoder.clone());

    assert!(commit_batch(
        &mut manager,
        peer,
        ExactBatch {
            announce: vec![route.clone()],
            ..ExactBatch::default()
        }
    ));
    assert_eq!(rx.recv().await.unwrap().announce.len(), 1);
    let initial_probe_batches = encoder.probe_batch_count();

    encoder.set_profile(63, [flowspec_key.clone()]);
    manager.adj_rib_out_commit_stats = Default::default();
    let mut cache = crate::manager::distribution::SharedUnicastProbeCache::default();
    assert!(commit_shared_exact_batch_with_precommit(
        &mut manager,
        peer,
        ExactBatch {
            withdraw: vec![(route.prefix, route.path_id)],
            flowspec_announce: vec![flowspec],
            ..ExactBatch::default()
        },
        HashSet::from([route_key]),
        &mut cache,
    ));

    let mixed = rx.recv().await.unwrap();
    let snapshot = mixed
        .exact_export_snapshot
        .as_ref()
        .expect("mixed grouped envelope retains its probed snapshot");
    assert_eq!((snapshot.owner_id(), snapshot.generation()), (1, 63));
    assert!(mixed.announce.is_empty());
    assert_eq!(mixed.withdraw, vec![(route.prefix, route.path_id)]);
    assert!(
        mixed.flowspec_announce.is_empty(),
        "the rejected announcement must fail closed"
    );
    assert_eq!(encoder.probe_batch_count(), initial_probe_batches + 1);
    assert_eq!(encoder.probed().last(), Some(&flowspec_key));
    assert_eq!(manager.adj_rib_out_commit_stats.exact_probe_batches, 1);
    assert_eq!(manager.adj_rib_out_commit_stats.exact_probe_candidates, 1);
    assert_eq!(manager.adj_rib_out_commit_stats.successful_commits, 1);
    assert_eq!(manager.adj_rib_out_commit_stats.successful_enqueues, 1);
    assert_eq!(
        manager.peer_unexportable[&peer],
        HashSet::from([flowspec_key])
    );
    assert!(manager.adj_ribs_out[&peer].get(&route.prefix, 0).is_none());
    assert_eq!(manager.adj_ribs_out[&peer].flowspec_len(), 0);

    manager.adj_rib_out_commit_stats = Default::default();
    assert!(commit_shared_exact_batch_with_precommit(
        &mut manager,
        peer,
        ExactBatch {
            flowspec_withdraw: vec![flowspec_selection_key],
            ..ExactBatch::default()
        },
        HashSet::new(),
        &mut cache,
    ));
    let retired = rx.recv().await.unwrap();
    assert!(
        retired.flowspec_withdraw.is_empty(),
        "a route rejected before commit must not receive a wire withdrawal"
    );
    assert!(retired.exact_export_snapshot.is_some());
    assert_eq!(encoder.probe_batch_count(), initial_probe_batches + 1);
    assert_eq!(manager.adj_rib_out_commit_stats.exact_probe_batches, 0);
    assert!(!manager.peer_unexportable.contains_key(&peer));
}

#[tokio::test]
async fn every_route_family_is_probed_before_commit() {
    let peer = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2));
    let source = Ipv4Addr::new(198, 51, 100, 2);
    let unicast = make_route(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 1, 0), 24), source);
    let flowspec = make_flowspec_route(source);
    let evpn = make_evpn_imet(source, 101);
    let bgpls = make_bgpls_route(source, 0x41, 100);
    let vpn = make_vpn_rib_route(source, 41, 1041, 100);
    let labeled = make_labeled_rib_route(source, 42, 1042, 100);
    let rtc = make_rtc_rib_route(source, 43, 100);
    let expected = HashSet::from([
        ExactExportKey::Unicast(unicast.prefix, unicast.path_id),
        ExactExportKey::FlowSpec(flowspec.selection_key()),
        ExactExportKey::Evpn(evpn.key()),
        ExactExportKey::BgpLs(bgpls.key()),
        ExactExportKey::Vpn(vpn.key()),
        ExactExportKey::Labeled(labeled.key()),
        ExactExportKey::Rtc(rtc.key()),
    ]);
    for key in &expected {
        assert!(
            key.bounded_log_identity().len() <= 96,
            "diagnostic identity must stay bounded: {}",
            key.bounded_log_identity()
        );
    }

    let encoder = MockExactExportEncoder::accepting(21);
    let mut manager = test_manager();
    let mut rx = register_exact_target(&mut manager, peer, encoder.clone());
    assert!(commit_batch(
        &mut manager,
        peer,
        ExactBatch {
            announce: vec![unicast],
            flowspec_announce: vec![flowspec],
            evpn_announce: vec![evpn],
            bgpls_announce: vec![bgpls],
            vpn_announce: vec![vpn],
            labeled_announce: vec![labeled],
            rtc_announce: vec![rtc],
            ..ExactBatch::default()
        }
    ));

    let update = rx.recv().await.unwrap();
    assert_eq!(update.announce.len(), 1);
    assert_eq!(update.flowspec_announce.len(), 1);
    assert_eq!(update.evpn_announce.len(), 1);
    assert_eq!(update.bgpls_announce.len(), 1);
    assert_eq!(update.vpn_announce.len(), 1);
    assert_eq!(update.labeled_announce.len(), 1);
    assert_eq!(update.rtc_announce.len(), 1);
    assert_eq!(
        encoder.probed().into_iter().collect::<HashSet<_>>(),
        expected
    );
}

#[tokio::test]
async fn batched_probe_results_filter_the_matching_family_in_order() {
    let peer = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 22));
    let source = Ipv4Addr::new(198, 51, 100, 22);
    let unicast = make_route(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 22, 0), 24), source);
    let flowspec = make_flowspec_route(source);
    let evpn = make_evpn_imet(source, 221);
    let bgpls = make_bgpls_route(source, 0x42, 200);
    let vpn = make_vpn_rib_route(source, 44, 2044, 200);
    let labeled = make_labeled_rib_route(source, 45, 2045, 200);
    let rtc = make_rtc_rib_route(source, 46, 200);
    let rejected = HashSet::from([
        ExactExportKey::FlowSpec(flowspec.selection_key()),
        ExactExportKey::BgpLs(bgpls.key()),
        ExactExportKey::Labeled(labeled.key()),
    ]);
    let encoder = MockExactExportEncoder::accepting(22);
    encoder.set_profile(22, rejected.clone());
    let mut manager = test_manager();
    let mut rx = register_exact_target(&mut manager, peer, encoder);

    assert!(commit_batch(
        &mut manager,
        peer,
        ExactBatch {
            announce: vec![unicast],
            flowspec_announce: vec![flowspec],
            evpn_announce: vec![evpn],
            bgpls_announce: vec![bgpls],
            vpn_announce: vec![vpn],
            labeled_announce: vec![labeled],
            rtc_announce: vec![rtc],
            ..ExactBatch::default()
        }
    ));
    let update = rx.recv().await.unwrap();
    assert_eq!(update.announce.len(), 1);
    assert!(update.flowspec_announce.is_empty());
    assert_eq!(update.evpn_announce.len(), 1);
    assert!(update.bgpls_announce.is_empty());
    assert_eq!(update.vpn_announce.len(), 1);
    assert!(update.labeled_announce.is_empty());
    assert_eq!(update.rtc_announce.len(), 1);
    assert_eq!(manager.peer_unexportable[&peer], rejected);
}

#[test]
fn route_bearing_commit_without_encoder_fails_closed() {
    let peer = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 3));
    let route = make_route(
        Ipv4Prefix::new(Ipv4Addr::new(10, 0, 2, 0), 24),
        Ipv4Addr::new(198, 51, 100, 3),
    );
    let mut manager = test_manager();
    let (tx, mut rx) = mpsc::channel(1);
    manager.outbound_peers.insert(peer, tx);

    assert!(!commit_batch(
        &mut manager,
        peer,
        ExactBatch {
            announce: vec![route],
            ..ExactBatch::default()
        }
    ));
    assert!(!manager.adj_ribs_out.contains_key(&peer));
    assert!(rx.try_recv().is_err());
}

#[tokio::test]
async fn malformed_batch_probe_cardinality_falls_back_to_scalar() {
    let peer = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 33));
    let route = make_route(
        Ipv4Prefix::new(Ipv4Addr::new(10, 0, 33, 0), 24),
        Ipv4Addr::new(198, 51, 100, 33),
    );
    let key = ExactExportKey::Unicast(route.prefix, route.path_id);
    let probed = Arc::new(Mutex::new(Vec::new()));
    let encoder = Arc::new(WrongCardinalityBatchEncoder {
        probed: Arc::clone(&probed),
    });
    let mut manager = test_manager();
    let mut rx = register_exact_target(&mut manager, peer, encoder);

    assert!(commit_batch(
        &mut manager,
        peer,
        ExactBatch {
            announce: vec![route],
            ..ExactBatch::default()
        }
    ));
    assert_eq!(rx.recv().await.unwrap().announce.len(), 1);
    assert_eq!(*probed.lock().unwrap(), vec![key]);
}

#[test]
fn missing_encoder_does_not_consume_retry_state() {
    let peer = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 4));
    let route = make_route(
        Ipv4Prefix::new(Ipv4Addr::new(10, 0, 3, 0), 24),
        Ipv4Addr::new(198, 51, 100, 4),
    );
    let key = ExactExportKey::Unicast(route.prefix, route.path_id);
    let mut manager = test_manager();
    let (tx, _rx) = mpsc::channel(1);
    manager.outbound_peers.insert(peer, tx);
    manager
        .peer_unexportable
        .insert(peer, HashSet::from([key.clone()]));
    manager
        .pending_otc_blocked
        .entry(peer)
        .or_default()
        .insert((route.prefix, route.path_id), route.clone());

    assert!(!commit_batch(
        &mut manager,
        peer,
        ExactBatch {
            withdraw: vec![(route.prefix, route.path_id)],
            ..ExactBatch::default()
        }
    ));
    assert!(manager.peer_unexportable[&peer].contains(&key));
    assert!(manager.pending_otc_blocked[&peer].contains_key(&(route.prefix, route.path_id)));
}

#[test]
fn rejection_pruning_follows_sparse_overlay_liveness() {
    let target = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 5));
    let source = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 5));
    let mut route = make_route(
        Ipv4Prefix::new(Ipv4Addr::new(10, 0, 4, 0), 24),
        Ipv4Addr::new(198, 51, 100, 5),
    );
    route.path_id = 42;
    // The rejected overlay records the outbound single-best identity, not
    // the source's inbound Add-Path ID.
    let key = ExactExportKey::Unicast(route.prefix, 0);
    let mut bgpls = make_bgpls_route(Ipv4Addr::new(198, 51, 100, 5), 0x55, 100);
    bgpls.path_id = 77;
    let bgpls_inbound_key = bgpls.key();
    let bgpls_key = ExactExportKey::BgpLs(bgpls_inbound_key.clone()).nlri_identity();
    let mut manager = test_manager();
    let mut rib = AdjRibIn::new(source);
    rib.insert(route.clone());
    rib.insert_bgpls(bgpls);
    manager.ribs.insert(source, rib);
    manager.register_unicast_announcer(source, route.prefix);
    manager
        .peer_unexportable
        .insert(target, HashSet::from([key.clone(), bgpls_key.clone()]));

    manager.prune_exact_export_rejections();
    assert!(manager.peer_unexportable[&target].contains(&key));
    assert!(manager.peer_unexportable[&target].contains(&bgpls_key));

    manager.retire_exact_export_rejections([ExactExportKey::Unicast(route.prefix, 42)]);
    assert!(
        manager.peer_unexportable[&target].contains(&key),
        "a surviving source path must retain the outbound rejection"
    );
    manager.retire_exact_export_rejections([ExactExportKey::BgpLs(bgpls_inbound_key.clone())]);
    assert!(
        manager.peer_unexportable[&target].contains(&bgpls_key),
        "opaque-family liveness must ignore the inbound Add-Path ID"
    );

    manager
        .ribs
        .get_mut(&source)
        .unwrap()
        .withdraw(&route.prefix, 42);
    manager.retire_exact_export_rejections([ExactExportKey::Unicast(route.prefix, 42)]);
    assert!(!manager.peer_unexportable[&target].contains(&key));
    manager
        .ribs
        .get_mut(&source)
        .unwrap()
        .withdraw_bgpls(&bgpls_inbound_key);
    manager.retire_exact_export_rejections([ExactExportKey::BgpLs(bgpls_inbound_key)]);
    assert!(!manager.peer_unexportable.contains_key(&target));
}

async fn peer_up_with_encoder(
    tx: &mpsc::Sender<RibUpdate>,
    peer: IpAddr,
    encoder: Arc<dyn ExactExportEncoder>,
) -> mpsc::Receiver<OutboundRouteUpdate> {
    tx.send(RibUpdate::SetPeerExportEncoder {
        peer,
        session_id: 7,
        encoder,
    })
    .await
    .unwrap();
    let (out_tx, mut out_rx) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        per_client_best: false,
        interpret_rfc1997: true,
        session_id: 7,
        peer,
        peer_asn: 65_100,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
        add_path_send_families: Vec::new(),
        add_path_send_max: 0,
        negotiated_orf_recv: Vec::new(),
        negotiated_llgr_families: Vec::new(),
    })
    .await
    .unwrap();
    drain_eor(&mut out_rx).await;
    out_rx
}

async fn vpn_peer_up_with_encoder(
    tx: &mpsc::Sender<RibUpdate>,
    peer: IpAddr,
    encoder: Arc<dyn ExactExportEncoder>,
) -> mpsc::Receiver<OutboundRouteUpdate> {
    tx.send(RibUpdate::SetPeerExportEncoder {
        peer,
        session_id: 9,
        encoder,
    })
    .await
    .unwrap();
    let (out_tx, mut out_rx) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        per_client_best: false,
        interpret_rfc1997: true,
        session_id: 9,
        peer,
        peer_asn: 65_100,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: vpn_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
        add_path_send_families: Vec::new(),
        add_path_send_max: 0,
        negotiated_orf_recv: Vec::new(),
        negotiated_llgr_families: Vec::new(),
    })
    .await
    .unwrap();
    drain_eor(&mut out_rx).await;
    out_rx
}

async fn add_path_peer_up_with_encoder(
    tx: &mpsc::Sender<RibUpdate>,
    peer: IpAddr,
    encoder: Arc<dyn ExactExportEncoder>,
    send_max: u32,
) -> mpsc::Receiver<OutboundRouteUpdate> {
    tx.send(RibUpdate::SetPeerExportEncoder {
        peer,
        session_id: 8,
        encoder,
    })
    .await
    .unwrap();
    let (out_tx, mut out_rx) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        per_client_best: false,
        interpret_rfc1997: true,
        session_id: 8,
        peer,
        peer_asn: 65_100,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
        add_path_send_families: ipv4_sendable(),
        add_path_send_max: send_max,
        negotiated_orf_recv: Vec::new(),
        negotiated_llgr_families: Vec::new(),
    })
    .await
    .unwrap();
    drain_eor(&mut out_rx).await;
    out_rx
}

async fn advertised_count(tx: &mpsc::Sender<RibUpdate>, peer: IpAddr) -> usize {
    let (reply, result) = oneshot::channel();
    tx.send(RibUpdate::QueryAdvertisedCount { peer, reply })
        .await
        .unwrap();
    result.await.unwrap()
}

async fn advertised_routes(tx: &mpsc::Sender<RibUpdate>, peer: IpAddr) -> Vec<Route> {
    let (reply, result) = oneshot::channel();
    tx.send(RibUpdate::QueryAdvertisedRoutes { peer, reply })
        .await
        .unwrap();
    result.await.unwrap()
}

async fn update_group(tx: &mpsc::Sender<RibUpdate>, peer: IpAddr) -> String {
    let (reply, result) = oneshot::channel();
    tx.send(RibUpdate::QueryPeerUpdateGroup { peer, reply })
        .await
        .unwrap();
    result.await.unwrap()
}

#[test]
fn cached_success_rechecks_target_ceiling_and_emits_owed_withdrawal() {
    let source = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 40));
    let limited = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 41));
    let source_encoder = ReusableExactExportEncoder::with_limits(40, 77, 512, 4_096);
    let limited_encoder = ReusableExactExportEncoder::with_limits(41, 77, 512, 128);
    let mut manager = test_manager();
    let mut source_rx = register_exact_target(&mut manager, source, source_encoder.clone());
    let mut limited_rx = register_exact_target(&mut manager, limited, limited_encoder.clone());

    let prefix = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 116, 0), 24);
    let route = make_route(prefix, Ipv4Addr::new(198, 51, 100, 40));
    let key = ExactExportKey::Unicast(route.prefix, route.path_id);
    let route_identity = (route.prefix, route.path_id);
    let announce: Arc<[Route]> = vec![route].into();
    let next_hop_override: Arc<[Option<rustbgpd_policy::NextHopAction>]> = vec![None].into();
    let mut cache = crate::manager::distribution::SharedUnicastProbeCache::default();

    assert!(commit_shared_unicast_with_cache(
        &mut manager,
        source,
        Arc::clone(&announce),
        Arc::clone(&next_hop_override),
        HashSet::new(),
        &mut cache,
    ));
    let source_update = source_rx.try_recv().unwrap();
    assert_eq!(source_update.announce.len(), 1);
    assert!(source_update.withdraw.is_empty());
    assert_eq!(source_encoder.probe_count(), 1);

    assert!(commit_shared_unicast_with_cache(
        &mut manager,
        limited,
        Arc::clone(&announce),
        Arc::clone(&next_hop_override),
        HashSet::from([key.clone()]),
        &mut cache,
    ));
    let limited_update = limited_rx.try_recv().unwrap();
    assert!(limited_update.announce.is_empty());
    assert_eq!(limited_update.withdraw, vec![route_identity]);
    assert!(manager.peer_unexportable[&limited].contains(&key));
    assert_eq!(
        limited_encoder.probe_count(),
        0,
        "the limited target must reject by rechecking the cached encoded length"
    );
}

#[test]
fn clean_group_all_success_preserves_shared_payload_and_target_snapshot_fence() {
    let source = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 42));
    let target = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 42));
    let encoder = ReusableExactExportEncoder::new(4_242, 17);
    let mut manager = test_manager();
    let mut rx = register_exact_target(&mut manager, target, encoder);
    let route = make_route(
        Ipv4Prefix::new(Ipv4Addr::new(203, 0, 117, 0), 24),
        Ipv4Addr::new(198, 51, 100, 42),
    );
    let deltas = [crate::manager::update_groups::GroupDelta {
        prefix: route.prefix,
        path_id: route.path_id,
        new: Some((route.clone(), None)),
        old_source: Some(source),
        policy_label: None,
        source_attrs: None,
    }];
    let announce: Arc<[Route]> = vec![route].into();
    let next_hop_override: Arc<[Option<rustbgpd_policy::NextHopAction>]> = vec![None].into();
    let mut cache = crate::manager::distribution::SharedUnicastProbeCache::default();

    assert!(commit_shared_unicast_with_precommit(
        &mut manager,
        target,
        Arc::clone(&announce),
        Arc::clone(&next_hop_override),
        HashSet::new(),
        &mut cache,
        Some(crate::manager::distribution::LazyCleanGroupPrior {
            peer: target,
            deltas: &deltas,
        }),
    ));
    let update = rx.try_recv().unwrap();
    assert!(Arc::ptr_eq(&update.announce, &announce));
    assert!(Arc::ptr_eq(&update.next_hop_override, &next_hop_override));
    let snapshot = update.exact_export_snapshot.unwrap();
    assert_eq!(snapshot.owner_id(), 4_242);
    assert_eq!(snapshot.generation(), 1);
    assert!(!manager.peer_unexportable.contains_key(&target));
}

#[test]
fn clean_group_cached_failure_materializes_prior_and_emits_owed_withdrawal() {
    let source = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 43));
    let limited = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 44));
    let source_encoder = ReusableExactExportEncoder::with_limits(43, 88, 8_192, 65_535);
    let limited_encoder = ReusableExactExportEncoder::with_limits(44, 88, 8_192, 4_096);
    let mut manager = test_manager();
    let mut source_rx = register_exact_target(&mut manager, source, source_encoder.clone());
    let mut limited_rx = register_exact_target(&mut manager, limited, limited_encoder.clone());
    let route = make_route(
        Ipv4Prefix::new(Ipv4Addr::new(203, 0, 118, 0), 24),
        Ipv4Addr::new(198, 51, 100, 43),
    );
    let key = ExactExportKey::Unicast(route.prefix, route.path_id);
    let route_identity = (route.prefix, route.path_id);
    let deltas = [crate::manager::update_groups::GroupDelta {
        prefix: route.prefix,
        path_id: route.path_id,
        new: Some((route.clone(), None)),
        old_source: Some(source),
        policy_label: None,
        source_attrs: None,
    }];
    let announce: Arc<[Route]> = vec![route].into();
    let next_hop_override: Arc<[Option<rustbgpd_policy::NextHopAction>]> = vec![None].into();
    let mut cache = crate::manager::distribution::SharedUnicastProbeCache::default();

    assert!(commit_shared_unicast_with_cache(
        &mut manager,
        source,
        Arc::clone(&announce),
        Arc::clone(&next_hop_override),
        HashSet::new(),
        &mut cache,
    ));
    assert_eq!(source_rx.try_recv().unwrap().announce.len(), 1);
    assert!(commit_shared_unicast_with_precommit(
        &mut manager,
        limited,
        Arc::clone(&announce),
        Arc::clone(&next_hop_override),
        HashSet::new(),
        &mut cache,
        Some(crate::manager::distribution::LazyCleanGroupPrior {
            peer: limited,
            deltas: &deltas,
        }),
    ));
    let limited_update = limited_rx.try_recv().unwrap();
    assert!(limited_update.announce.is_empty());
    assert_eq!(limited_update.withdraw, vec![route_identity]);
    assert!(manager.peer_unexportable[&limited].contains(&key));
    assert_eq!(source_encoder.probe_count(), 1);
    assert_eq!(
        limited_encoder.probe_count(),
        0,
        "the target must apply its ceiling to the shared encoded length"
    );
}

#[test]
fn clean_group_overlay_blocks_fast_path_and_retains_unrelated_family() {
    let source = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 45));
    let target = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 45));
    let encoder = ReusableExactExportEncoder::new(45, 19);
    let mut manager = test_manager();
    let mut rx = register_exact_target(&mut manager, target, encoder);
    let route = make_route(
        Ipv4Prefix::new(Ipv4Addr::new(203, 0, 119, 0), 24),
        Ipv4Addr::new(198, 51, 100, 45),
    );
    let route_key = ExactExportKey::Unicast(route.prefix, route.path_id);
    let unrelated_key = ExactExportKey::FlowSpec(
        make_flowspec_route(Ipv4Addr::new(198, 51, 100, 45)).selection_key(),
    );
    manager.peer_unexportable.insert(
        target,
        HashSet::from([route_key.clone(), unrelated_key.clone()]),
    );
    let deltas = [crate::manager::update_groups::GroupDelta {
        prefix: route.prefix,
        path_id: route.path_id,
        new: Some((route.clone(), None)),
        old_source: Some(source),
        policy_label: None,
        source_attrs: None,
    }];
    let announce: Arc<[Route]> = vec![route].into();
    let next_hop_override: Arc<[Option<rustbgpd_policy::NextHopAction>]> = vec![None].into();
    let mut cache = crate::manager::distribution::SharedUnicastProbeCache::default();

    assert!(commit_shared_unicast_with_precommit(
        &mut manager,
        target,
        announce,
        next_hop_override,
        HashSet::new(),
        &mut cache,
        Some(crate::manager::distribution::LazyCleanGroupPrior {
            peer: target,
            deltas: &deltas,
        }),
    ));
    assert_eq!(rx.try_recv().unwrap().announce.len(), 1);
    let overlay = &manager.peer_unexportable[&target];
    assert!(!overlay.contains(&route_key));
    assert!(overlay.contains(&unrelated_key));
}

#[tokio::test]
async fn grouped_shared_unicast_probes_once_per_compatible_wire_profile() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let mut receivers = Vec::new();
    let mut encoders = Vec::new();
    for octet in 10..74 {
        let peer = IpAddr::V4(Ipv4Addr::new(192, 0, 2, octet));
        let encoder = ReusableExactExportEncoder::new(u64::from(octet), u64::from(octet % 2));
        receivers.push(peer_up_with_encoder(&tx, peer, encoder.clone()).await);
        encoders.push(encoder);
        assert_eq!(update_group(&tx, peer).await, "group:0");
    }

    let source = Ipv4Addr::new(198, 51, 100, 1);
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24);
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: IpAddr::V4(source),
        announced: vec![make_route(prefix, source)],
        withdrawn: Vec::new(),
        flowspec_announced: Vec::new(),
        flowspec_withdrawn: Vec::new(),
        evpn_announced: Vec::new(),
        evpn_withdrawn: Vec::new(),
    })
    .await
    .unwrap();

    for receiver in &mut receivers {
        assert_eq!(receiver.recv().await.unwrap().announce.len(), 1);
    }
    assert_eq!(
        encoders
            .iter()
            .map(|encoder| encoder.probe_count())
            .sum::<usize>(),
        2,
        "64 grouped members across two compatible wire profiles should require two encodes"
    );

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn grouped_shared_unicast_does_not_reuse_when_snapshot_refuses() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let a = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 20));
    let b = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 21));
    let encoder_a = MockExactExportEncoder::accepting(41);
    let encoder_b = MockExactExportEncoder::accepting(41);
    let mut receiver_a = peer_up_with_encoder(&tx, a, encoder_a.clone()).await;
    let mut receiver_b = peer_up_with_encoder(&tx, b, encoder_b.clone()).await;
    assert_eq!(update_group(&tx, a).await, "group:0");
    assert_eq!(update_group(&tx, b).await, "group:0");

    let source = Ipv4Addr::new(198, 51, 100, 2);
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 114, 0), 24);
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: IpAddr::V4(source),
        announced: vec![make_route(prefix, source)],
        withdrawn: Vec::new(),
        flowspec_announced: Vec::new(),
        flowspec_withdrawn: Vec::new(),
        evpn_announced: Vec::new(),
        evpn_withdrawn: Vec::new(),
    })
    .await
    .unwrap();

    assert_eq!(receiver_a.recv().await.unwrap().announce.len(), 1);
    assert_eq!(receiver_b.recv().await.unwrap().announce.len(), 1);
    assert_eq!(
        encoder_a.probed().len() + encoder_b.probed().len(),
        2,
        "the trait's default refusal must preserve one exact probe per member"
    );

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn grouped_shared_unicast_falls_back_on_wrong_reuse_cardinality() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let a = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 30));
    let b = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 31));
    let encoder_a = ReusableExactExportEncoder::with_wrong_reuse_cardinality(30, 9);
    let encoder_b = ReusableExactExportEncoder::with_wrong_reuse_cardinality(31, 9);
    let mut receiver_a = peer_up_with_encoder(&tx, a, encoder_a.clone()).await;
    let mut receiver_b = peer_up_with_encoder(&tx, b, encoder_b.clone()).await;
    assert_eq!(update_group(&tx, a).await, "group:0");
    assert_eq!(update_group(&tx, b).await, "group:0");

    let source = Ipv4Addr::new(198, 51, 100, 3);
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 115, 0), 24);
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: IpAddr::V4(source),
        announced: vec![make_route(prefix, source)],
        withdrawn: Vec::new(),
        flowspec_announced: Vec::new(),
        flowspec_withdrawn: Vec::new(),
        evpn_announced: Vec::new(),
        evpn_withdrawn: Vec::new(),
    })
    .await
    .unwrap();

    assert_eq!(receiver_a.recv().await.unwrap().announce.len(), 1);
    assert_eq!(receiver_b.recv().await.unwrap().announce.len(), 1);
    assert_eq!(
        encoder_a.probe_count() + encoder_b.probe_count(),
        2,
        "wrong reuse cardinality must fall back to each target's exact batch probe"
    );

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "one scenario covers grouped rejection, source flip, regroup, explain, and projections"
)]
async fn grouped_classic_rejection_is_a_member_local_overlay_across_source_flip_and_regroup() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let classic = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
    let extended = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 11));
    let source_a = Ipv4Addr::new(198, 51, 100, 10);
    let source_b = Ipv4Addr::new(198, 51, 100, 11);
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24);
    let route_a = make_route_with_lp(prefix, source_a, 100);
    let route_b = make_route_with_lp(prefix, source_b, 200);
    let key = ExactExportKey::Unicast(route_a.prefix, route_a.path_id);
    let classic_encoder = MockExactExportEncoder::accepting(31);
    classic_encoder.set_profile(31, [key]);
    let extended_encoder = MockExactExportEncoder::accepting(32);
    let mut classic_rx = peer_up_with_encoder(&tx, classic, classic_encoder).await;
    let mut extended_rx = peer_up_with_encoder(&tx, extended, extended_encoder).await;
    assert_eq!(update_group(&tx, classic).await, "group:0");
    assert_eq!(update_group(&tx, extended).await, "group:0");

    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: IpAddr::V4(source_a),
        announced: vec![route_a],
        withdrawn: Vec::new(),
        flowspec_announced: Vec::new(),
        flowspec_withdrawn: Vec::new(),
        evpn_announced: Vec::new(),
        evpn_withdrawn: Vec::new(),
    })
    .await
    .unwrap();
    let classic_first = classic_rx.recv().await.unwrap();
    let extended_first = extended_rx.recv().await.unwrap();
    assert!(classic_first.announce.is_empty());
    assert_eq!(extended_first.announce.len(), 1);
    assert_eq!(advertised_count(&tx, classic).await, 0);
    assert_eq!(advertised_count(&tx, extended).await, 1);
    assert!(advertised_routes(&tx, classic).await.is_empty());
    assert_eq!(advertised_routes(&tx, extended).await.len(), 1);
    let classic_explain = query_explain_advertised_route(&tx, classic, Prefix::V4(prefix)).await;
    assert_eq!(
        classic_explain.decision,
        crate::update::ExplainDecision::Deny
    );
    assert_eq!(
        classic_explain.gates.last().map(|gate| gate.code),
        Some("exact_export_rejected")
    );
    let extended_explain = query_explain_advertised_route(&tx, extended, Prefix::V4(prefix)).await;
    assert_eq!(
        extended_explain.decision,
        crate::update::ExplainDecision::Advertise
    );

    // Replacing the group-table winner must not erase the classic member's
    // rejection overlay just because the source peer changed.
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: IpAddr::V4(source_b),
        announced: vec![route_b],
        withdrawn: Vec::new(),
        flowspec_announced: Vec::new(),
        flowspec_withdrawn: Vec::new(),
        evpn_announced: Vec::new(),
        evpn_withdrawn: Vec::new(),
    })
    .await
    .unwrap();
    let classic_flip = classic_rx.recv().await.unwrap();
    let extended_flip = extended_rx.recv().await.unwrap();
    assert!(classic_flip.announce.is_empty());
    assert!(classic_flip.withdraw.is_empty());
    assert_eq!(extended_flip.announce.len(), 1);
    assert_eq!(extended_flip.announce[0].peer, IpAddr::V4(source_b));
    assert_eq!(advertised_count(&tx, classic).await, 0);
    assert_eq!(
        advertised_routes(&tx, extended).await[0].peer,
        IpAddr::V4(source_b)
    );

    // A content change moves only the classic peer to a new group. Its
    // one-shot old-view diff and its new group projection must both retain
    // the exact-export rejection rather than resurrecting the route.
    let unrelated = Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 99, 0, 0), 16));
    let (reply, result) = oneshot::channel();
    tx.send(RibUpdate::ReplacePeerExportPolicy {
        peer: classic,
        export_policy: Some(deny_prefixes_chain(&[unrelated])),
        reply,
    })
    .await
    .unwrap();
    assert_eq!(result.await.unwrap(), Ok(()));
    assert_ne!(
        update_group(&tx, classic).await,
        update_group(&tx, extended).await
    );
    assert_eq!(advertised_count(&tx, classic).await, 0);
    assert!(advertised_routes(&tx, classic).await.is_empty());
    assert_eq!(advertised_count(&tx, extended).await, 1);

    let (reply, result) = oneshot::channel();
    tx.send(RibUpdate::QueryAdjRibOutCounts { reply })
        .await
        .unwrap();
    let counts = result.await.unwrap();
    assert!(counts[&classic].is_empty());
    assert_eq!(counts[&extended], vec![((Afi::Ipv4, Safi::Unicast), 1)]);

    // Remove the non-best source, then the remaining best. The grouped table
    // owes a withdrawal only to the extended peer; the classic member's
    // rejected overlay must suppress a duplicate wire withdrawal before the
    // targeted retirement pass clears the now-dead identity.
    for source in [source_a, source_b] {
        tx.send(RibUpdate::RoutesReceived {
            session_id: 0,
            peer: IpAddr::V4(source),
            announced: Vec::new(),
            withdrawn: vec![(Prefix::V4(prefix), 0)],
            flowspec_announced: Vec::new(),
            flowspec_withdrawn: Vec::new(),
            evpn_announced: Vec::new(),
            evpn_withdrawn: Vec::new(),
        })
        .await
        .unwrap();
        let _ = advertised_count(&tx, classic).await;
    }
    let extended_withdraw = extended_rx.recv().await.unwrap();
    assert_eq!(extended_withdraw.withdraw, vec![(Prefix::V4(prefix), 0)]);
    if let Ok(Some(classic_update)) =
        tokio::time::timeout(Duration::from_millis(25), classic_rx.recv()).await
    {
        assert!(
            classic_update.withdraw.is_empty(),
            "a route rejected before commit must never receive a duplicate withdrawal"
        );
    }
    assert_eq!(advertised_count(&tx, classic).await, 0);
    assert_eq!(advertised_count(&tx, extended).await, 0);

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn grouped_vpn_force_rejection_withdraws_stale_route_once() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let target = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 30));
    let sibling = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 31));
    let source = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 30));
    let route = make_vpn_rib_route(Ipv4Addr::new(198, 51, 100, 30), 30, 1030, 100);
    let key = route.key();
    let exact_key = ExactExportKey::Vpn(key.clone());
    let target_encoder = MockExactExportEncoder::accepting(51);
    let sibling_encoder = MockExactExportEncoder::accepting(52);
    let mut target_rx = vpn_peer_up_with_encoder(&tx, target, target_encoder.clone()).await;
    let mut sibling_rx = vpn_peer_up_with_encoder(&tx, sibling, sibling_encoder).await;
    assert_eq!(update_group(&tx, target).await, "group:0");
    assert_eq!(update_group(&tx, sibling).await, "group:0");

    tx.send(RibUpdate::VpnRoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![route],
        withdrawn: Vec::new(),
    })
    .await
    .unwrap();
    assert_eq!(target_rx.recv().await.unwrap().vpn_announce.len(), 1);
    assert_eq!(sibling_rx.recv().await.unwrap().vpn_announce.len(), 1);

    // A GShut-style forced refresh changes the wire attributes. If the
    // refreshed route no longer fits, the grouped peer must withdraw the
    // previously-advertised identity rather than leave its old attributes
    // resident indefinitely.
    target_encoder.set_profile(53, [exact_key.clone()]);
    let (reply, result) = oneshot::channel();
    tx.send(RibUpdate::RefreshPeerOutbound {
        peer: target,
        reply,
    })
    .await
    .unwrap();
    assert_eq!(result.await.unwrap(), Ok(()));
    let rejected_refresh = target_rx.recv().await.unwrap();
    assert!(rejected_refresh.vpn_announce.is_empty());
    assert_eq!(rejected_refresh.vpn_withdraw, vec![key.clone()]);

    // The later source withdrawal retires the rejected overlay. It must not
    // require (or emit) a second wire withdrawal: the forced-refresh reject
    // already removed the stale route.
    tx.send(RibUpdate::VpnRoutesReceived {
        session_id: 0,
        peer: source,
        announced: Vec::new(),
        withdrawn: vec![key.clone()],
    })
    .await
    .unwrap();
    assert_eq!(sibling_rx.recv().await.unwrap().vpn_withdraw, vec![key]);
    let (reply, result) = oneshot::channel();
    tx.send(RibUpdate::TestQueryVpnAdvertised {
        peer: target,
        reply,
    })
    .await
    .unwrap();
    assert!(result.await.unwrap().is_empty());

    if let Ok(Some(update)) =
        tokio::time::timeout(Duration::from_millis(25), target_rx.recv()).await
    {
        assert!(
            update.vpn_withdraw.is_empty(),
            "withdrawal must be emitted once"
        );
    }

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn add_path_explain_does_not_mark_exact_rejected_rank_as_advertised() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());
    let target = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 20));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(198, 18, 0, 0), 24);
    let encoder = MockExactExportEncoder::accepting(41);
    encoder.set_profile(41, [ExactExportKey::Unicast(Prefix::V4(prefix), 2)]);
    let _out_rx = add_path_peer_up_with_encoder(&tx, target, encoder, 3).await;

    for (source, local_pref) in [
        (Ipv4Addr::new(198, 51, 100, 20), 300),
        (Ipv4Addr::new(198, 51, 100, 21), 200),
        (Ipv4Addr::new(198, 51, 100, 22), 100),
    ] {
        tx.send(RibUpdate::RoutesReceived {
            session_id: 0,
            peer: IpAddr::V4(source),
            announced: vec![make_route_with_lp(prefix, source, local_pref)],
            withdrawn: Vec::new(),
            flowspec_announced: Vec::new(),
            flowspec_withdrawn: Vec::new(),
            evpn_announced: Vec::new(),
            evpn_withdrawn: Vec::new(),
        })
        .await
        .unwrap();
    }
    let _ = advertised_count(&tx, target).await;
    let explain = query_explain_best_path_for_peer(&tx, Prefix::V4(prefix), target)
        .await
        .expect("known peer");
    let rejected = explain
        .candidates
        .iter()
        .find(|candidate| candidate.route.peer == IpAddr::V4(Ipv4Addr::new(198, 51, 100, 21)))
        .expect("rank-two candidate");
    assert_eq!(rejected.advertised_path_id, 0);

    let selected = query_explain_advertised_source(
        &tx,
        target,
        Prefix::V4(prefix),
        crate::update::RouteSourceIdentity {
            peer: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 21)),
            path_id: 0,
        },
    )
    .await
    .unwrap();
    assert_eq!(selected.decision, crate::update::ExplainDecision::Deny);
    assert_eq!(selected.path_id, 2, "exact denial retains attempted rank");
    assert_eq!(
        selected.gates.last().map(|step| (step.gate, step.code)),
        Some(("exact_export", "exact_export_rejected"))
    );

    // Load-bearing proof: removing the exact-export overlay makes this
    // candidate advertise; assigning rank after the overlay makes path_id 0.

    drop(tx);
    handle.await.unwrap();
}
