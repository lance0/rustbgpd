//! The [`RibManager`] actor: one tokio task that owns every Adj-RIB-In, the
//! Loc-RIB and every Adj-RIB-Out, and serves its update, query, readiness
//! and summary channels. Family distribution, graceful restart, route
//! refresh, queries and update groups live in submodules.

mod actor_turn;
#[cfg(feature = "bench-internals")]
mod bench_support;
#[cfg(feature = "bench-internals")]
pub use bench_support::{
    AdjRibOutFanoutBenchReceipt, DataplanePrefixIndexBenchReceipt, EvpnDataplaneQueryBenchReceipt,
    EvpnGroupBenchReceipt, EvpnPeerBenchReceipt, PolicyTransitionBenchReceipt, RecoveryScanReceipt,
    RecoveryScanSpec, UnicastPrefixPeersMemoryReceipt, bench_evpn_dataplane_generation_query,
    bench_evpn_dataplane_generation_snapshot, bench_evpn_dataplane_legacy_snapshot,
    bench_recovery_capture_scan,
};
mod conditional_advertisement;
mod dampening_history;
mod distribution;
mod eor_grace;
mod evpn_recovery;
mod export_chains;
mod flowspec_validation;
mod graceful_restart;
mod helpers;
mod lease_expiry;
mod outbound_prefix_limits;
mod peer_lifecycle;
mod queries;
mod replacement_summaries;
use crate::PeerId;
use crate::fast_hash::ShardedMap;
use peer_lifecycle::{PeerUpRegistration, SessionTeardownDisposition};
mod route_refresh;
mod selection_deferral;
mod slice_timing;
mod update_groups;

#[cfg(test)]
mod tests;

#[cfg(test)]
use crate::ERR_REFRESH_TIMEOUT;

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::future::Future;
use std::hash::{BuildHasher, Hasher};
use std::net::{IpAddr, Ipv4Addr};
use std::num::NonZeroU32;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Wake, Waker};

use rustbgpd_policy::PolicyChain;
use rustbgpd_rpki::VrpTable;
use rustbgpd_telemetry::BgpMetrics;
use rustbgpd_telemetry::metrics::RibPolicyTransitionOutcome;
use rustbgpd_telemetry::metrics::StaleSessionMessageKind as Kind;
use rustbgpd_telemetry::metrics::StaleSessionMessageKind::{
    BgpLs, Eor, Labeled, Orf, Refresh, Rtc, Vpn,
};
use rustbgpd_wire::{Afi, BgpRole, Prefix, Safi};
use tokio::sync::{broadcast, mpsc, watch};
use tracing::{debug, info, warn};

/// Let independent response tasks run while a synchronous actor retains
/// exclusive state ownership. Current-thread embedders remain synchronous.
fn with_executor_handoff<T>(work: impl FnOnce() -> T) -> T {
    #[cfg(test)]
    EXECUTOR_HANDOFFS.with(|handoffs| {
        let (entered, open) = handoffs.get();
        handoffs.set((entered + 1, open + 1));
    });
    let result = if tokio::runtime::Handle::try_current().is_ok_and(|handle| {
        matches!(
            handle.runtime_flavor(),
            tokio::runtime::RuntimeFlavor::MultiThread
        )
    }) {
        tokio::task::block_in_place(work)
    } else {
        work()
    };
    #[cfg(test)]
    EXECUTOR_HANDOFFS.with(|handoffs| {
        let (entered, open) = handoffs.get();
        handoffs.set((entered, open - 1));
    });
    result
}

#[cfg(test)]
thread_local! {
    /// Executor handoffs this thread entered, and how many are open now.
    static EXECUTOR_HANDOFFS: std::cell::Cell<(usize, usize)> =
        const { std::cell::Cell::new((0, 0)) };
}

#[cfg(test)]
fn executor_handoffs() -> (usize, usize) {
    EXECUTOR_HANDOFFS.with(std::cell::Cell::get)
}

/// Add one export batch's tally for `peer` to its neighbor's totals, one map
/// lookup per peer per batch. An empty tally touches nothing.
fn add_export_tally(
    counters: &mut HashMap<PeerId, crate::update::ExportPolicyCounters>,
    peer: PeerId,
    tally: NeighborPolicyStats,
) {
    if tally != NeighborPolicyStats::default() {
        counters.entry(peer).or_default().add(tally);
    }
}

/// Release owned temporary elements while the actor still owns readiness.
pub(crate) fn retire_vec<T>(values: &mut Vec<T>, checkpoint: &mut impl FnMut()) {
    checkpoint();
    if std::mem::needs_drop::<T>() {
        while let Some(value) = values.pop() {
            drop(value);
            checkpoint();
        }
    }
    drop(std::mem::take(values));
    checkpoint();
}

fn retire_hash_set<T, S: BuildHasher + Default>(
    values: &mut HashSet<T, S>,
    checkpoint: &mut impl FnMut(),
) {
    checkpoint();
    if std::mem::needs_drop::<T>() {
        for value in values.drain() {
            drop(value);
            checkpoint();
        }
    }
    drop(std::mem::take(values));
    checkpoint();
}

use crate::adj_rib_in::AdjRibIn;
use crate::adj_rib_out::AdjRibOut;
use crate::event::{RouteEvent, RouteEventType};
use crate::loc_rib::LocRib;
use crate::update::{
    ExactExportEncoder, ExactExportKey, NeighborPolicyStats, OutboundRouteUpdate,
    RibReadinessError, RibReadinessQuery, RibSummaryQuery, RibUpdate, RoutePageError,
    RoutePageVersion, RouteQueryScope,
};

#[cfg(test)]
use queries::{BMP_DUMP_CHUNK_SIZE, page_routes, send_mrt_snapshot};

pub use conditional_advertisement::{
    ConditionEntryStatus, ConditionalAdvertiseIf, ConditionalAdvertisement,
    ConditionalAdvertisementCapture, ConditionalAdvertisementSet, ConditionalAdvertisementStatus,
};
pub use eor_grace::{EorGraceConfig, EorGracePeerConfig, EorGraceTarget, ReplayComplete};
use helpers::{DIRTY_RESYNC_INTERVAL, LlgrPeerConfig, gauge_val, prefix_family};
pub use selection_deferral::{SelectionDeferralConfig, SelectionDeferralWaiterConfig};

#[cfg(any(test, feature = "bench-internals"))]
#[derive(Clone, Copy, Debug, Default)]
struct PolicyTransitionStats {
    plan_builds: usize,
    full_exact_probes: usize,
    route_shell_materializations: usize,
    actor_polls: usize,
    max_actor_slice: std::time::Duration,
    max_prefix_snapshot_poll: std::time::Duration,
    max_finalize_poll: std::time::Duration,
    max_commit_poll: std::time::Duration,
    /// Batched authoritative applies
    /// (`RibUpdate::ReplacePeerExportPoliciesAuthoritatively`) and how
    /// their members split between the shared cohort transition and the
    /// per-member fallback — the one-pass receipt for tests.
    batched_authoritative_batches: usize,
    batched_authoritative_shared_members: usize,
    batched_authoritative_fallback_members: usize,
    #[cfg(feature = "bench-internals")]
    authoritative_peer_applies: usize,
    #[cfg(feature = "bench-internals")]
    max_authoritative_peer_apply: std::time::Duration,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct AuthoritativeTransitionReceipt {
    outcome: &'static str,
    classification: &'static str,
    failure_stage: &'static str,
    precondition_us: u64,
    registration_membership_us: u64,
    registered_peer_source_membership_scan_us: u64,
    policy_compare_install_us: u64,
    destination_membership_us: u64,
    cohort_partition_us: u64,
    cohort_precheck_us: u64,
    destination_build_us: u64,
    inventory_build_us: u64,
    membership_commit_us: u64,
    filtered_scope_build_us: u64,
    member_emit_state_us: u64,
    cohort_finalize_us: u64,
    fallback_regroup_us: u64,
    distribution_us: u64,
    duplicate_fallback_us: u64,
    total_us: u64,
    remainder_us: u64,
    input_peers: usize,
    present_peers: usize,
    skipped_peers: usize,
    duplicate_peers: usize,
    candidate_cohorts: usize,
    shared_cohorts: usize,
    shared_members: usize,
    fallback_members: usize,
    destination_ensures: usize,
    destination_builds: usize,
    destination_adoptions: usize,
    membership_moves: usize,
    inventory_announces: usize,
    inventory_withdraws: usize,
    inventory_supplements: usize,
    tombstones: usize,
    lagging_members: usize,
    filtered_scope_prefixes: usize,
    filtered_scope_member_visits: usize,
    emits_attempted: usize,
    emits_succeeded: usize,
    emits_degraded: usize,
    distribution_passes: usize,
    filtered_state_before: usize,
    filtered_state_after: usize,
    dirty_before: usize,
    dirty_after: usize,
    pending_before: usize,
    pending_after: usize,
    groups_before: usize,
    groups_after: usize,
    policy_equality_attempts: usize,
    policy_equality_equal: usize,
    policy_equality_changed: usize,
    rpol_shared_backing: usize,
    rpol_detached_backing: usize,
    detached_prefix_set_entries: usize,
    intern_candidates: usize,
    intern_hits: usize,
    intern_misses: usize,
    membership_grouped: usize,
    membership_ungrouped: usize,
}

/// Test/benchmark-only receipt from the authoritative outbound commit path.
///
/// The counters live on the production path but compile out of normal builds.
/// They prove performance fixtures reached production ingress and exact
/// export where applicable, committed one route-bearing envelope per peer,
/// and exercised the intended family-gauge writes instead of an
/// equality-suppressed no-op.
#[cfg(any(test, feature = "bench-internals"))]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct AdjRibOutCommitStats {
    routes_received_dispatches: usize,
    routes_received_withdrawals: usize,
    exact_probe_batches: usize,
    exact_probe_candidates: usize,
    exact_probe_nonzero_encoded_lengths: usize,
    exact_probe_cache_reuses: usize,
    successful_commits: usize,
    successful_enqueues: usize,
    family_gauge_writes: usize,
    last_family_gauge_write_mask: u8,
    pristine_otc_reconcile_candidates: usize,
    private_extra_prefix_scans: usize,
    /// Last End-of-RIB unicast pass: prefixes recomputed, best changes,
    /// and the recompute / distribution split in nanoseconds.
    eor_unicast_affected: usize,
    eor_unicast_changed: usize,
    eor_unicast_recompute_ns: u64,
    eor_unicast_distribute_ns: u64,
    #[cfg(feature = "bench-internals")]
    eor_attr_gc_ns: u64,
    #[cfg(feature = "bench-internals")]
    eor_stale_count_ns: u64,
    #[cfg(feature = "bench-internals")]
    eor_stale_resolution_ns: u64,
    #[cfg(test)]
    metrics_handle_clones: usize,
    #[cfg(test)]
    otc_reconcile_prefix_visits: usize,
    /// Per-peer passes that built a full resync (dirty or force).
    #[cfg(test)]
    resync_builds: usize,
    /// Distinct keys collected into per-peer VPN resync enumerations.
    #[cfg(test)]
    vpn_resync_key_inserts: usize,
    /// Controlled refusal at the actual post-admission completeness seam.
    #[cfg(test)]
    fail_evpn_feed_completion: bool,
}

#[cfg(test)]
struct PermissiveTestExactExport;

#[cfg(test)]
impl crate::update::ExactExportSnapshot for PermissiveTestExactExport {
    fn owner_id(&self) -> u64 {
        0
    }

    fn generation(&self) -> u64 {
        0
    }

    fn probe_announcement(
        &self,
        _candidate: crate::update::ExactExportCandidate<'_>,
    ) -> Result<crate::update::ExactExportResult, crate::update::ExactExportError> {
        Ok(crate::update::ExactExportResult {
            encoded_len: 0,
            max_len: usize::MAX,
            generation: 0,
        })
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

#[cfg(test)]
impl ExactExportEncoder for PermissiveTestExactExport {
    fn owner_id(&self) -> u64 {
        0
    }

    fn snapshot(&self) -> Arc<dyn crate::update::ExactExportSnapshot> {
        Arc::new(Self)
    }
}

#[cfg(test)]
fn permissive_test_exact_export_encoder() -> Arc<dyn ExactExportEncoder> {
    Arc::new(PermissiveTestExactExport)
}

/// Reverse index of unicast announcing peers: prefix → the peers whose
/// Adj-RIB-In currently holds at least one route for it. `FxHash` +
/// peer-fed keys: same deliberate `HashDoS` tradeoff as the route maps (see the
/// rationale block at the top of `adj_rib_in.rs`).
///
/// Maintenance contract (load-bearing): the index may OVER-count but must
/// never UNDER-count — `recompute_best` collects candidates only from the
/// indexed peers, so a missing entry would silently drop a live candidate
/// from best-path selection. Every seam that inserts a unicast route into
/// an Adj-RIB-In must call [`RibManager::register_unicast_announcer`]
/// (announce chunks, local injection, bench seeding — the only three
/// insert sites). Per-prefix removal seams (withdraw, GR/LLGR sweeps, `EoR`
/// clears, max-prefix teardown) need no eager hook: a peer that no longer
/// holds the prefix is pruned lazily by the next `recompute_best` probe.
/// Destructive peer teardown retires its incarnation epoch before recompute;
/// GR/LLGR retention deliberately preserves that epoch while routes remain.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct AdjRibInEpoch(NonZeroU32);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PrefixAnnouncers {
    Inline(AdjRibInEpoch),
    Spill(NonZeroU32),
}

#[derive(Default)]
struct UnicastPrefixPeers {
    prefixes: crate::fast_hash::FastMap<Prefix, PrefixAnnouncers>,
    spills: Vec<smallvec::SmallVec<[AdjRibInEpoch; 2]>>,
    free_spills: Vec<u32>,
    peer_epochs: HashMap<PeerId, AdjRibInEpoch>,
    epoch_peers: crate::fast_hash::FastMap<AdjRibInEpoch, PeerId>,
    next_epoch: u32,
}

impl UnicastPrefixPeers {
    fn epoch_for_peer(&mut self, peer: PeerId) -> AdjRibInEpoch {
        if let Some(&epoch) = self.peer_epochs.get(&peer) {
            return epoch;
        }
        self.next_epoch = self
            .next_epoch
            .checked_add(1)
            .expect("Adj-RIB-In epoch space exhausted");
        let epoch = AdjRibInEpoch(NonZeroU32::new(self.next_epoch).expect("epoch starts at one"));
        self.peer_epochs.insert(peer, epoch);
        self.epoch_peers.insert(epoch, peer);
        epoch
    }

    fn retire_peer(&mut self, peer: PeerId) {
        if let Some(epoch) = self.peer_epochs.remove(&peer) {
            self.epoch_peers.remove(&epoch);
        }
    }

    fn register(&mut self, peer: PeerId, prefix: Prefix) {
        let epoch = self.epoch_for_peer(peer);
        match self.prefixes.get(&prefix).copied() {
            None => {
                self.prefixes
                    .insert(prefix, PrefixAnnouncers::Inline(epoch));
            }
            Some(PrefixAnnouncers::Inline(existing)) if existing == epoch => {}
            Some(PrefixAnnouncers::Inline(existing)) => {
                let slot = if let Some(slot) = self.free_spills.pop() {
                    let peers = &mut self.spills[slot as usize];
                    debug_assert!(peers.is_empty());
                    peers.extend([existing, epoch]);
                    slot
                } else {
                    let slot = u32::try_from(self.spills.len())
                        .expect("unicast announcer spill slot space exhausted");
                    self.spills.push(smallvec::smallvec![existing, epoch]);
                    slot
                };
                let handle = NonZeroU32::new(slot.checked_add(1).expect("spill handle exhausted"))
                    .expect("one-based spill handle");
                self.prefixes
                    .insert(prefix, PrefixAnnouncers::Spill(handle));
            }
            Some(PrefixAnnouncers::Spill(handle)) => {
                let peers = &mut self.spills[(handle.get() - 1) as usize];
                if !peers.contains(&epoch) {
                    peers.push(epoch);
                }
            }
        }
    }

    fn epochs(&self, prefix: &Prefix) -> impl Iterator<Item = AdjRibInEpoch> + '_ {
        let slice: &[AdjRibInEpoch] = match self.prefixes.get(prefix) {
            None => &[],
            Some(PrefixAnnouncers::Inline(epoch)) => std::slice::from_ref(epoch),
            Some(PrefixAnnouncers::Spill(handle)) => &self.spills[(handle.get() - 1) as usize],
        };
        slice.iter().copied()
    }

    fn peers(&self, prefix: &Prefix) -> impl Iterator<Item = PeerId> + '_ {
        self.epochs(prefix)
            .filter_map(|epoch| self.epoch_peers.get(&epoch).copied())
    }

    fn prune_to_live(&mut self, prefix: &Prefix, mut live: impl FnMut(PeerId) -> bool) {
        let Some(value) = self.prefixes.get(prefix).copied() else {
            return;
        };
        let live_epoch = |epoch: &AdjRibInEpoch, live: &mut dyn FnMut(PeerId) -> bool| {
            self.epoch_peers.get(epoch).copied().is_some_and(live)
        };
        match value {
            PrefixAnnouncers::Inline(epoch) if !live_epoch(&epoch, &mut live) => {
                self.prefixes.remove(prefix);
            }
            PrefixAnnouncers::Inline(_) => {}
            PrefixAnnouncers::Spill(handle) => {
                let peers = &mut self.spills[(handle.get() - 1) as usize];
                peers.retain(|epoch| live_epoch(epoch, &mut live));
                match peers.as_slice() {
                    [] => {
                        self.prefixes.remove(prefix);
                        self.release_spill(handle);
                    }
                    [epoch] => {
                        self.prefixes
                            .insert(*prefix, PrefixAnnouncers::Inline(*epoch));
                        self.release_spill(handle);
                    }
                    _ => {}
                }
            }
        }
    }

    fn release_spill(&mut self, handle: NonZeroU32) {
        let slot = handle.get() - 1;
        let peers = &mut self.spills[slot as usize];
        peers.clear();
        peers.shrink_to_fit();
        self.free_spills.push(slot);
    }

    #[cfg(feature = "bench-internals")]
    fn len(&self) -> usize {
        self.prefixes.len()
    }
    #[cfg(feature = "bench-internals")]
    fn capacity(&self) -> usize {
        self.prefixes.capacity()
    }
    #[cfg(feature = "bench-internals")]
    fn is_empty(&self) -> bool {
        self.prefixes.is_empty()
    }
}

#[cfg(test)]
use helpers::{LOCAL_PEER, validate_route_rpki};

/// A peer's RT-Constrain membership (RFC 4684): the Route Targets the peer
/// declared interest in via SAFI-132 NLRI. Rebuilt whole from the peer's OWN
/// Adj-RIB-In (all paths — never the Loc-RIB best, whose tiebreak winner may
/// belong to a different peer) whenever that Adj-RIB-In mutates.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct RtcMembership {
    /// Peer advertised the zero-length default NLRI: interest in every RT.
    has_default: bool,
    /// Non-default membership NLRI, sorted + deduped so rebuilds of the
    /// same set compare equal regardless of `HashMap` iteration order.
    entries: Vec<rustbgpd_wire::RtcNlri>,
}

impl RtcMembership {
    /// Whether any of `rts` falls inside this membership. An empty
    /// membership (SAFI 132 negotiated, no interest received yet) matches
    /// nothing — the strict RFC 4684 rule, so a route with no Route Target
    /// at all only passes via the default NLRI.
    ///
    /// RFC 7432 §7.6 makes the EVPN ES-Import RT (type 0x06, sub-type
    /// 0x02) a Route Target that RT-Constrain MUST apply to. It has no
    /// two-part encoding, so it needs explicit recognition here; like
    /// ordinary RTs, it matches on the RT bits under the prefix alone.
    fn matches_any(&self, rts: &[rustbgpd_wire::ExtendedCommunity]) -> bool {
        if self.has_default {
            return true;
        }
        rts.iter().any(|&rt| {
            self.entries.iter().any(|nlri| {
                nlri.matches(rt)
                    || (rt.as_es_import_rt().is_some()
                        && (rt.as_u64() ^ nlri.route_target_bits)
                            .checked_shr(96 - u32::from(nlri.prefix_len))
                            .unwrap_or(0)
                            == 0)
            })
        })
    }
}

/// Shared immutable inputs for VPN and labeled-unicast export staging.
#[expect(
    clippy::struct_excessive_bools,
    reason = "the context preserves existing independent export flags without changing their semantics"
)]
struct VpnLabeledStagingContext<'a> {
    loc_rib: &'a LocRib,
    ribs: &'a HashMap<PeerId, AdjRibIn>,
    rib_out: &'a AdjRibOut,
    peer_is_rr_client: &'a HashMap<PeerId, bool>,
    target_is_ebgp: bool,
    interpret_rfc1997: bool,
    target_is_rr_client: bool,
    cluster_id: Option<Ipv4Addr>,
    sendable: Option<&'a Vec<(Afi, Safi)>>,
    llgr: Option<&'a Vec<(Afi, Safi)>>,
    orr_ctx: Option<(&'a crate::orr::OrrTopology, &'a crate::orr::SpfResult)>,
    add_path_send_max: u32,
    add_path_send_limits: Option<&'a HashMap<(Afi, Safi), u32>>,
    add_path_send_families: &'a [(Afi, Safi)],
    export_pol: Option<&'a PolicyChain>,
    force: bool,
}

#[cfg(test)]
type PrimaryUpdateHook = Arc<dyn Fn(&RibUpdate) + Send + Sync>;

/// The full pass an unbounded dataset re-evaluation takes under the test and
/// benchmark hooks.
#[cfg(any(test, feature = "bench-internals"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FullPassPath {
    /// Once per update group where the targets allow it (production).
    Group,
    /// Always the per-member full resync.
    Member,
}

/// Central RIB manager that owns all Adj-RIB-In, Loc-RIB, and Adj-RIB-Out state.
///
/// Runs as a single tokio task, receiving updates via an mpsc channel.
/// No `Arc<RwLock>` — all state is owned by this task.
#[cfg_attr(
    all(test, feature = "bench-internals"),
    expect(
        clippy::struct_excessive_bools,
        reason = "independent fixture switches coexist with the production event-ID exhaustion flag"
    )
)]
pub struct RibManager {
    ribs: HashMap<PeerId, AdjRibIn>,
    /// Global cross-peer attribute intern table (LAN-336). Owned by this
    /// task like everything else — lock-free by construction. Every route
    /// insertion seam interns `route.attributes` here BEFORE storing the
    /// route. Unicast UPDATE chunks amortize collection by displaced count
    /// and deadline; explicit teardown sweeps remain immediate.
    attr_intern: crate::attr_intern::AttrInternTable,
    /// Unicast replacements/removals since the last full attribute sweep.
    attr_intern_gc_displaced: usize,
    attr_intern_gc_deadline: Option<tokio::time::Instant>,
    /// See [`UnicastPrefixPeers`] for the maintenance contract.
    unicast_prefix_peers: UnicastPrefixPeers,
    loc_rib: LocRib,
    /// Wrapping equality token for the Type 1/2/3/5 Loc-RIB projection consumed
    /// by the daemon's EVPN dataplane supervisor.  Actor ownership makes the
    /// token and a materialized snapshot one atomic observation.
    evpn_dataplane_generation: u64,
    /// Exact cardinality of Type 1/2/3/5 Loc-RIB rows. Maintained at the same
    /// recompute seam as the generation token so an all-relevant table can
    /// retain the pre-existing bulk-clone fast path.
    evpn_dataplane_route_count: usize,
    /// Deterministic proof that equality/cancellation branches do not walk
    /// the Loc-RIB. Counts rows visited only by full internal snapshots.
    #[cfg(test)]
    evpn_dataplane_query_row_visits: usize,
    /// Deterministic proof that paged FIB queries use the prefix-announcer
    /// reverse index rather than walking unrelated peer RIBs.
    #[cfg(test)]
    dataplane_page_announcer_visits: std::sync::atomic::AtomicUsize,
    #[cfg(test)]
    dataplane_page_sibling_visits: std::sync::atomic::AtomicUsize,
    /// Deterministic exact-FIB cancellation injection after N visits. Zero
    /// disables the test hook.
    #[cfg(test)]
    dataplane_exact_cancel_after_visits: std::sync::atomic::AtomicUsize,
    adj_ribs_out: HashMap<PeerId, AdjRibOut>,
    /// Per-peer outbound unicast prefix admission state (ADR-0113). An entry
    /// exists only for a peer whose resolved `max_prefixes_out_ipv4` /
    /// `max_prefixes_out_ipv6` sets a limit in at least one family — a
    /// neighbor value overriding its peer group, an absent one inheriting.
    /// A peer left unlimited in both families has no entry, and clearing a
    /// peer's last family limit removes its entry again, so the unlimited
    /// export path keeps its original state shape and per-route cost.
    outbound_prefix_limits: HashMap<PeerId, outbound_prefix_limits::OutboundPrefixLimits>,
    /// Resolver tables, prepared-transaction slot, admission epoch, and
    /// coalesced family-scoped recovery intent for those limits (ADR-0113).
    outbound_limit_control: outbound_prefix_limits::OutboundLimitControl,
    outbound_peers: HashMap<PeerId, mpsc::Sender<OutboundRouteUpdate>>,
    /// Transport session identity recorded at `PeerUp` registration,
    /// keyed like `outbound_peers`. `handle_peer_down` /
    /// `handle_peer_graceful_restart` discard a teardown whose stamped id
    /// doesn't match, so a stale collision-loser `PeerDown` (RFC 4271
    /// §6.8 overlap, processed after the winner's `PeerUp`) cannot
    /// destroy the surviving session's state. Invariant: equals the
    /// `session_id` of the LAST entry in `live_sessions[peer]` whenever a
    /// registration exists.
    outbound_session_ids: HashMap<PeerId, u64>,
    /// Every live transport session known for a peer address, in `PeerUp`
    /// arrival order (last = the active registration), bounded by
    /// [`MAX_LIVE_SESSIONS_PER_PEER`]. During the RFC 4271 §6.8 collision
    /// window two session tasks can be Established for one address and
    /// their `PeerUp`/`PeerDown` events interleave arbitrarily across the
    /// shared mpsc (per-sender FIFO only). Keeping the superseded-but-
    /// still-live session's registration material lets the manager FAIL
    /// OVER to it when the active session goes down (the symmetric
    /// interleaving `PeerUp(winner)` → `PeerUp(loser)` →
    /// `PeerDown(loser)`) instead of tearing down a peer that still has
    /// an Established session. Entries are removed by their session's own
    /// `PeerDown`/GR-down or by full peer teardown.
    live_sessions: HashMap<PeerId, Vec<LiveSessionRecord>>,
    /// Physical live-session completion options, including collision records.
    /// Zero avoids fleet scans while EVPN completion control is inactive.
    evpn_feed_receipt_count: usize,
    /// Session-stamped local role staged before `PeerUp`, so the initial
    /// Adj-RIB-Out build can enforce RFC 9234 OTC egress rules.
    pending_peer_export_context: HashMap<(PeerId, u64), Option<BgpRole>>,
    /// Session-stamped negotiated-but-withheld families staged before
    /// `PeerUp` (`RibUpdate::SetPeerWithheldFamilies`).
    pending_peer_withheld_families: HashMap<(PeerId, u64), Vec<crate::update::WithheldFamily>>,
    /// Session-stamped RFC 7947 §2.3.2 control-community context staged
    /// before `PeerUp` (the RS-side local ASN when the session interprets
    /// route-server control communities).
    pending_peer_rs_control: HashMap<(PeerId, u64), Option<u32>>,
    /// Session-stamped exact encoder staged immediately before `PeerUp`.
    /// Keeping the handle separate from the legacy registration payload
    /// avoids making every non-transport `PeerUp` producer construct a fake
    /// wire encoder while still fencing collision losers by session id.
    pending_peer_export_encoders: HashMap<(PeerId, u64), Arc<dyn ExactExportEncoder>>,
    /// Neighbor export-policy totals staged before `PeerUp`, keyed like the
    /// encoders above.
    pending_peer_export_counters: HashMap<(PeerId, u64), crate::update::ExportPolicyCounters>,
    /// Session-stamped peer GR capability context staged immediately before
    /// `PeerUp`, used only by the process-start RFC 4724 selection gate.
    pending_peer_gr_context: HashMap<(PeerId, u64), PeerSelectionDeferralContext>,
    /// Accepted provenance awaiting its matching session registration.
    pending_peer_source_context: HashMap<(PeerId, u64), Arc<crate::update::PeerSourceContext>>,
    /// Committed owner authority; history allocation remains absent in production.
    dampening_history: dampening_history::DampeningHistoryState,
    /// Policy identity awaiting its matching registration, before initial export.
    pending_peer_policy_context: HashMap<(PeerId, u64), Option<String>>,
    /// Exact encoder owned by the active outbound registration. Every
    /// precommit pass captures one immutable snapshot from this handle and
    /// attaches that same snapshot to the outbound envelope.
    peer_export_encoders: HashMap<PeerId, Arc<dyn ExactExportEncoder>>,
    /// Sparse per-peer identities rejected by exact wire preparation. For
    /// update-group members this is the member-local overlay over the shared
    /// group table; for private peers it suppresses repeated diagnostics and
    /// withdrawals for routes that were never advertised.
    peer_unexportable: HashMap<PeerId, HashSet<ExactExportKey>>,
    #[cfg(test)]
    grouped_advertised_count_calls: std::sync::atomic::AtomicUsize,
    /// Installed export chains, per peer and global fallback, and their
    /// published counter roster (ADR-0136).
    export_chains: export_chains::ExportChains,
    /// Families the transport can actually serialize per peer.
    peer_sendable_families: HashMap<PeerId, Vec<(Afi, Safi)>>,
    /// Advances whenever a peer joins or leaves `peer_sendable_families`, so
    /// a paged export-disposition walk detects a roster change between pages.
    outbound_roster_generation: u64,
    /// Advances whenever a registered peer's export settings change without
    /// a session reset: its outbound prefix limits, conditional
    /// advertisement gate, peer group, Add-Path send limits, sendable
    /// families or ORF state. Folded into the export-disposition walk's
    /// policy version so a paged walk detects such a change between pages.
    export_settings_generation: u64,
    /// Families for which each registered outbound peer advertised the
    /// Long-Lived Graceful Restart capability (RFC 9494). Gates the
    /// export of LLGR-stale routes: absent family + eBGP target =
    /// suppress (§4.4); absent family + iBGP target = advertise with
    /// `NO_EXPORT` and `LOCAL_PREF` 0, rewritten in transport (§4.6).
    peer_advertised_llgr_families: HashMap<PeerId, Vec<(Afi, Safi)>>,
    /// Whether each registered outbound peer is eBGP (true) or iBGP (false).
    peer_is_ebgp: HashMap<PeerId, bool>,
    /// Whether the active or GR/LLGR-retained peer is a route reflector
    /// client. Retained across graceful-restart outbound teardown because
    /// stale iBGP routes still need their source classification; overwritten
    /// at re-registration and removed by terminal peer teardown.
    peer_is_rr_client: HashMap<PeerId, bool>,
    /// Local RFC 9234 role for the active outbound registration.
    peer_local_roles: HashMap<PeerId, Option<BgpRole>>,
    /// Current RFC 9234 egress-denied disposition, indexed by peer and
    /// prefix so one-prefix churn never scans every denied route.
    peer_otc_blocked: HashMap<PeerId, HashMap<Prefix, HashSet<u32>>>,
    /// OTC rejections waiting to ride the next reserved outbound envelope to
    /// transport's existing metric/event publisher. Every pending identity is
    /// also present in [`Self::peer_otc_blocked`].
    pending_otc_blocked: HashMap<PeerId, HashMap<(Prefix, u32), crate::route::Route>>,
    /// RFC 9107 ORR vantage per registered outbound peer (RR clients
    /// configured with `orr_vantage` only).
    peer_orr_vantage: HashMap<PeerId, IpAddr>,
    /// Cached ORR topology + per-vantage SPF state (RFC 9107), rebuilt
    /// by [`Self::recompute_orr`] at every BGP-LS mutation seam. Empty
    /// while `peer_orr_vantage` is empty (zero non-ORR cost).
    orr: crate::orr::OrrState,
    /// Topology built on demand for paged topology reads while no vantage
    /// cache exists, tagged with the table page version it was built under.
    /// Dropped when that version advances or the vantage cache takes over,
    /// so a page walk builds once and never holds a second copy.
    /// Boxed: the manager is embedded in large async fixtures.
    orr_page_topology: Option<Box<(RoutePageVersion, crate::orr::OrrTopology)>>,
    /// Counts on-demand topology builds for paged reads.
    #[cfg(test)]
    orr_page_topology_builds: usize,
    /// Local cluster ID for route reflection (RFC 4456). `None` = not an RR.
    cluster_id: Option<Ipv4Addr>,
    /// Peers that failed a `try_send()` and need a full export resync.
    /// Ordered (`BTreeSet`) so the resync tick can round-robin fairly via
    /// [`Self::dirty_resync_cursor`] instead of re-drawing an arbitrary
    /// subset each tick.
    dirty_peers: BTreeSet<PeerId>,
    /// When each peer's current dirty episode began. Written when a peer
    /// enters `dirty_peers`; meaningful only while it is still there.
    dirty_since: HashMap<PeerId, tokio::time::Instant>,
    /// Ring position of the dirty-resync round-robin: the last peer
    /// attempted. Selection resumes strictly after it (wrapping), so peers
    /// whose sends keep failing cannot monopolize every tick while
    /// drainable peers starve.
    dirty_resync_cursor: Option<PeerId>,
    /// Collision-failback inbound ROUTE-REFRESH requests deferred because
    /// the surviving session's outbound channel was full. One generation
    /// per peer coalesces repeat attempts and fences delivery to the same
    /// live session that became the survivor.
    pending_inbound_refresh: BTreeMap<PeerId, u64>,
    /// Ring position for bounded pending inbound-refresh retries.
    pending_inbound_refresh_cursor: Option<PeerId>,
    /// Wall-clock budget one actor poll may spend flushing paced work —
    /// commit-kind transition polls and dirty-resync ticks — before parking
    /// for the readiness seam. A unit of paced work is cheap-to-moderate,
    /// but ~10 ms of interleaved actor work elapses between polls, so a
    /// fixed per-poll item count makes throughput scale inversely with
    /// fleet size (measured ~0.88 s of emission stagger at 700 members).
    /// Tests override this to force deterministic per-stride parking.
    flush_poll_budget: std::time::Duration,
    /// Set by the actor's poll wrapper whenever the actor future returns
    /// `Pending`, whichever `select!` branch or await caused it; consumed by
    /// the primary run budget.
    actor_suspended: Arc<AtomicBool>,
    /// Peers whose next `distribute_changes` pass must bypass the
    /// `AdjRibOut`-already-matches suppression for currently-
    /// advertised routes. Used by `RibUpdate::RefreshPeerOutbound`
    /// when an *outbound attribute surface* changes that the RIB
    /// itself cannot see — RFC 8326 `GShut` community attach toggle
    /// is the canonical case: the toggle lives on `PeerSession` and
    /// gets applied in transport's `attach_graceful_shutdown_if_enabled`,
    /// AFTER the RIB-side equality check, so the diff sees no change
    /// and would otherwise skip re-emit. The set is consumed (cleared
    /// per peer) at the end of each `distribute_changes` pass so the
    /// force is one-shot and doesn't leak into unrelated subsequent
    /// passes.
    force_outbound_peers: HashSet<PeerId>,
    /// `EoR` markers that failed to enqueue and must be retried.
    pending_eor: HashMap<PeerId, HashSet<(Afi, Safi)>>,
    /// Families with an outstanding enhanced route refresh response retry.
    /// Entries are never left empty: readers check the key.
    pending_refresh: HashMap<PeerId, HashSet<(Afi, Safi)>>,
    /// Outbound registrations (initial table dumps) deferred behind queued
    /// actor work, completed one per run-loop iteration between drained
    /// mutation batches (LAN-475). Peer-keyed (deduplicated): the advance
    /// registers the peer's CURRENT last live session, so a session
    /// superseded or failed over while queued resolves to its survivor.
    pending_initial_registrations: VecDeque<PeerId>,
    /// When the next `bgp_rib_outbound_registration_pending_*` sample runs.
    /// Armed one interval ahead when a registration wait starts, so a burst
    /// of `PeerUp`s shares one scan; re-armed one interval out while the last
    /// sample counted a wait; `None` once a sample counts none.
    registration_wait_sample_at: Option<tokio::time::Instant>,
    /// Loc-RIB size below which a `PeerUp` initial dump always completes
    /// inline even with queued actor work — a small dump costs microseconds,
    /// so deferring it buys nothing and only perturbs registration-timing
    /// semantics. Defaults to [`INITIAL_DUMP_DEFER_MIN_ROUTES`]; tests pin
    /// it to 0 to exercise the deferral without bulk data.
    initial_dump_defer_min_routes: usize,
    /// Active inbound enhanced route refresh windows by peer/family.
    refresh_in_progress: HashMap<PeerId, HashSet<(Afi, Safi)>>,
    /// Per-peer/per-family deadlines for active enhanced route refresh windows.
    refresh_deadlines: graceful_restart::DeadlineMap<(PeerId, Afi, Safi)>,
    /// Unicast routes still awaiting replacement during an inbound refresh.
    refresh_stale_routes: HashMap<PeerId, ShardedMap<(Prefix, u32), ()>>,
    /// `FlowSpec` routes still awaiting replacement during an inbound refresh.
    refresh_stale_flowspec: HashMap<PeerId, ShardedMap<crate::route::FlowSpecRouteKey, ()>>,
    /// EVPN routes still awaiting replacement during an inbound refresh.
    refresh_stale_evpn: HashMap<PeerId, ShardedMap<rustbgpd_wire::EvpnRouteKey, ()>>,
    /// BGP-LS routes still awaiting replacement during an inbound refresh.
    refresh_stale_bgpls: HashMap<PeerId, ShardedMap<crate::route::BgpLsRouteKey, ()>>,
    /// VPNv4/VPNv6 routes still awaiting replacement during an inbound refresh.
    refresh_stale_vpn: HashMap<PeerId, ShardedMap<crate::route::VpnRibRouteKey, ()>>,
    /// Labeled-unicast route keys marked stale by an in-progress RFC 7313
    /// enhanced route refresh (the SAFI 4 sibling of `refresh_stale_vpn`).
    refresh_stale_labeled: HashMap<PeerId, ShardedMap<crate::route::LabeledRibRouteKey, ()>>,
    /// RT-Constrain routes still awaiting replacement during an inbound refresh.
    refresh_stale_rtc: HashMap<PeerId, ShardedMap<crate::route::RtcRibRouteKey, ()>>,
    /// O(1) per-peer/per-family stale-entry counts for refresh observability.
    refresh_stale_counts: HashMap<(PeerId, Afi, Safi), usize>,
    /// Peers currently undergoing graceful restart, keyed by peer address.
    /// Value is the set of (AFI, SAFI) families still awaiting End-of-RIB.
    gr_peers: HashMap<PeerId, HashSet<(Afi, Safi)>>,
    /// Deadlines for sweeping stale routes per GR peer.
    gr_stale_deadlines: graceful_restart::DeadlineMap<PeerId>,
    /// Configured stale-routes-time per GR peer (seconds), used to reset
    /// the timer on `PeerUp` during graceful restart.
    gr_stale_routes_time: HashMap<PeerId, u64>,
    /// Peers currently in LLGR stale phase (RFC 9494), keyed by peer address.
    /// Value is the set of (AFI, SAFI) families in LLGR.
    llgr_peers: HashMap<PeerId, HashSet<(Afi, Safi)>>,
    /// Deadlines for sweeping LLGR-stale routes, per (peer, AFI, SAFI) —
    /// RFC 9494 §4.3 stale time is negotiated per family. An entry is
    /// stamped ONCE when the family enters the LLGR stale phase and
    /// deliberately survives re-establishment while routes remain
    /// LLGR-stale: the ORIGINAL Long-Lived Stale Time bounds total
    /// retention, so a reconnect-then-down never restarts the timer.
    llgr_stale_deadlines: graceful_restart::DeadlineMap<(PeerId, Afi, Safi)>,
    /// Configured per-peer LLGR parameters, stored on `PeerGracefulRestart`.
    llgr_peer_config: HashMap<PeerId, LlgrPeerConfig>,
    /// Maximum Add-Path paths per prefix per peer (0 = single-best only).
    peer_add_path_send_max: HashMap<PeerId, u32>,
    /// Effective family-local Add-Path caps, including peer Paths-Limit.
    peer_add_path_send_limits: HashMap<PeerId, HashMap<(Afi, Safi), u32>>,
    /// Route-server clients with RFC 7947 §2.3.2 per-client best-path
    /// enabled: unicast export stages the first export-policy-permitted
    /// candidate (path-hiding mitigation) at `path_id 0` instead of the
    /// Loc-RIB best. Families with negotiated Add-Path send take the
    /// multipath path instead.
    peer_per_client_best: HashSet<PeerId>,
    /// Peers with RFC 1997 `NO_EXPORT`/`NO_EXPORT_SUBCONFED` egress
    /// enforcement enabled (config `interpret_rfc1997`, default
    /// `!route_server_client`). Source routes carrying either community
    /// are suppressed at staging toward these peers when they are eBGP.
    peer_interpret_rfc1997: HashSet<PeerId>,
    /// Peers whose sessions interpret RFC 7947 §2.3.2 route-server
    /// control communities at export staging (config
    /// `rs_control_communities`, default `route_server_client`), mapped
    /// to the RS-side local ASN the control communities are keyed on.
    /// Enabled peers are disqualified from update-group sharing.
    peer_rs_control: HashMap<PeerId, u32>,
    /// Peer ASN, tracked for MRT `PEER_INDEX_TABLE`.
    peer_asn: HashMap<PeerId, u32>,
    /// Peer-group membership used for export policy neighbor-set matching.
    peer_group: HashMap<PeerId, String>,
    /// ADR-0137 conditional-advertisement condition tracker.
    conditional_advertisements: conditional_advertisement::ConditionalAdvertisementTracker,
    /// Process-local content version for exact peer-group planning seals.
    peer_group_version: Option<RoutePageVersion>,
    /// Peer BGP router ID, tracked for MRT `PEER_INDEX_TABLE`.
    peer_bgp_id: HashMap<PeerId, Ipv4Addr>,
    /// Families for which Add-Path Send/Both was negotiated per peer.
    peer_add_path_send_families: HashMap<PeerId, Vec<(Afi, Safi)>>,
    /// Per-peer Address-Prefix ORF filters (RFC 5291/5292), keyed by
    /// `(AFI, SAFI)`. Consulted as an additional outbound filter before export
    /// policy when distributing to the peer. Absent ⇒ no ORF constraint.
    peer_orf_filters: HashMap<PeerId, HashMap<(Afi, Safi), crate::orf::OrfFilterSet>>,
    /// Peers currently isolated from shared update-groups because their
    /// transport flagged them slow (LAN-470, `slow_peer_isolation`).
    /// Membership recomputes classify these as
    /// `GroupMembership::SlowPeer` (per-peer fallback path). Per-session
    /// state: cleared on session teardown like the ORF gate above.
    slow_isolated_peers: HashSet<PeerId>,
    /// Per-peer RT-Constrain membership (RFC 4684) gating VPNv4/VPNv6
    /// distribution. Present (possibly empty = advertise NO VPN routes,
    /// the strict rule) from peer-up for every peer that negotiated
    /// `(IPv4, RtConstrain)`; absent ⇒ no RTC constraint. Per-session
    /// state: cleared with the rest of the outbound teardown, so a GR
    /// re-establish starts strict until the peer's interest re-arrives.
    peer_rt_membership: HashMap<PeerId, RtcMembership>,
    /// Families whose initial advertisement is gated pending the peer's first
    /// ROUTE-REFRESH (RFC 5291 §6). While a `(peer, AFI, SAFI)` is here, the
    /// initial table dump skips it; the gate is lifted on the first refresh.
    /// A peer's entry is dropped once no family remains gated
    /// (`lift_orf_gate`), so key presence means "at least one family gated".
    peer_orf_pending: HashMap<PeerId, HashSet<(Afi, Safi)>>,
    /// Families whose initial-table `EoR` is withheld because the peer came
    /// back as a graceful-restart RESTARTER (RFC 4724) while the family was
    /// still behind the RFC 5291 §6 ORF initial-advertisement gate. An
    /// immediate `EoR` would tell the restarter our initial update is
    /// complete and trigger its stale-route sweep BEFORE the gated flood
    /// arrives — a self-inflicted blackhole window. The `EoR` is emitted
    /// after the gate lifts and the gated flood is sent. A marker held by
    /// selection deferral or replay grace records the same obligation at
    /// `PeerUp` or family unlock. Other non-GR ORF peers keep the immediate
    /// `EoR`, including a pending marker whose initial honest-empty send
    /// encountered backpressure, and a family withheld at selection release.
    gr_deferred_eor: HashMap<PeerId, HashSet<(Afi, Safi)>>,
    /// Peers whose RT-Constrain-filtered families (VPN, EVPN) keep their
    /// initial-table `EoR` in `pending_eor` until the peer's RT-Constrain
    /// `EoR` arrives or the [`RTC_EOR_HOLD_CAP`] deadline passes (RFC 4684
    /// §6). Armed at `PeerUp` when the session starts with an empty
    /// membership; a membership re-derived from GR-retained RTC routes is
    /// already known and is not held. A peer acting as GR helper sweeps the
    /// routes it kept from us on our `EoR`, so an `EoR` sent before its
    /// interest arrives withdraws VPN routes we are about to re-send. A peer
    /// with the Restart State bit set is never held: it withholds its own
    /// RTC `EoR` until it has ours (RFC 4724 §4.1).
    rtc_eor_hold: graceful_restart::DeadlineMap<PeerId>,
    /// Held peers whose RT-Constrain `EoR` (or closing `EoRR`) arrived while
    /// RT-Constrain selection was deferred. Membership is not rebuilt until
    /// that deferral is staged or released, so the hold ends there, after
    /// the rebuild has emitted the matching VPN/EVPN routes.
    rtc_eor_hold_ready: HashSet<PeerId>,
    /// Opt-in End-of-RIB grace windows after a planned restart, keyed by
    /// configured peer. Empty on cold starts and once each deadline passes.
    eor_grace: HashMap<EorGraceTarget, eor_grace::EorGracePeer>,
    /// Each grace window's absolute deadline, with a cached minimum so the
    /// run loop's per-turn timer probe does not scan the peers.
    eor_grace_deadlines: graceful_restart::DeadlineMap<EorGraceTarget>,
    /// Controllers whose replay-complete signals release the grace windows
    /// early, and the ones that have signalled.
    eor_replay: eor_grace::ReplayWait,
    /// Process-start RFC 4724 route-selection gates. `None` on cold starts.
    selection_deferral: Option<selection_deferral::SelectionDeferral>,
    /// Route identities touched while their family's Loc-RIB was frozen.
    /// Includes withdrawals so restored rows absent from Adj-RIB-In are
    /// still removed when the gate releases.
    deferred_selection_keys: selection_deferral::DeferredSelectionKeys,
    /// Route-refresh responses received while family convergence and `EoR`
    /// remain held. Replayed after the convergence `EoR` is queued.
    selection_deferred_refresh: HashMap<PeerId, HashSet<(Afi, Safi)>>,
    /// Current RPKI VRP table for origin validation. `None` = no RPKI data.
    vrp_table: Option<Arc<VrpTable>>,
    /// Current ASPA table for path verification. `None` = no ASPA data.
    aspa_table: Option<Arc<rustbgpd_rpki::AspaTable>>,
    route_events_tx: broadcast::Sender<Arc<RouteEvent>>,
    /// FIB install-candidate change generation. Bumped once per unicast
    /// distribution batch (`distribute_changes_inner`) so the FIB
    /// reconciler wakes for candidate changes that keep the Loc-RIB best
    /// and therefore publish no route event.
    fib_candidate_changes_tx: watch::Sender<u64>,
    /// Currently surfaced unicast export-policy denials. This keeps
    /// route-level policy-filtered events transition-based instead of
    /// re-emitting on every dirty or forced outbound resync. Prefix buckets
    /// keep incremental refreshes independent of unrelated rejected routes.
    policy_filtered_routes: HashMap<PeerId, BTreeMap<Prefix, PolicyFilteredBucket>>,
    /// The attached session's export-policy totals handle, keyed by target
    /// peer. The handle belongs to the neighbor (`PeerUp` carries it), so the
    /// totals outlive this registration; only the RIB's reference ends with
    /// the session.
    export_policy_counters: HashMap<PeerId, crate::update::ExportPolicyCounters>,
    /// Bounded recent route-event history for after-the-fact operator
    /// timeline queries. Live streaming still uses `route_events_tx`.
    route_event_history: VecDeque<Arc<RouteEvent>>,
    /// Monotonic process-local id assigned before route events are recorded in
    /// history and broadcast to live subscribers.
    next_route_event_id: u64,
    /// True after the process-local route-event id reaches `u64::MAX`.
    /// Further events keep publishing with the saturated id instead of
    /// panicking the RIB manager. This is a defense-in-depth branch: hitting
    /// it would require exhausting the entire 64-bit event space in one
    /// daemon lifetime.
    route_event_id_exhausted: bool,
    /// EVPN best-path change broadcast. Separate from
    /// `route_events_tx` because `RouteEvent` is keyed by `Prefix`
    /// (unicast-only) and EVPN consumers (the daemon's local-MAC
    /// originator) need an `EvpnRouteKey`-shaped event with the full
    /// new best path attached. ADR-0055 §5 — Gate 7c.
    evpn_events_tx: broadcast::Sender<Arc<crate::event::EvpnRouteEvent>>,
    /// Bounded recent EVPN best-path event history for after-the-fact
    /// operator timeline queries. Live streaming still uses
    /// `evpn_events_tx`.
    evpn_route_event_history: VecDeque<Arc<crate::event::EvpnRouteEvent>>,
    /// RFC 9069 Loc-RIB BMP tap. When set, every Loc-RIB best-path
    /// change on a streamed family (unicast + VPN) is synthesized into
    /// an UPDATE PDU and sent as a `LocRibRouteMonitoring` event; `None`
    /// (no collector monitors `loc_rib`) costs one `is_some()` check
    /// per recompute.
    bmp_tx: Option<mpsc::Sender<rustbgpd_bmp::BmpEvent>>,
    metrics: BgpMetrics,
    rx: mpsc::Receiver<RibUpdate>,
    /// Priority channel for read-only queries (gRPC).
    query_rx: mpsc::Receiver<RibUpdate>,
    /// Dedicated type-narrow lane used only by core readiness.
    readiness_rx: Option<mpsc::Receiver<RibReadinessQuery>>,
    /// Dedicated lane for summaries with frozen replacement projections.
    summary_rx: Option<mpsc::Receiver<RibSummaryQuery>>,
    /// Readiness and frozen values are shared across synchronous replacement
    /// helpers. Canonical RIB state remains actor-owned.
    replacement_readiness: Option<Arc<ReplacementReadinessContext>>,
    #[cfg(test)]
    replacement_readiness_test_hook: Option<Arc<dyn Fn(&'static str) + Send + Sync>>,
    /// Runs synchronously at the start of every applied primary update.
    #[cfg(test)]
    test_primary_update_hook: Option<PrimaryUpdateHook>,
    /// Rate limit of the slow actor-turn WARN.
    slow_actor_turn_log: actor_turn::SlowActorTurnLog,
    #[cfg(test)]
    replacement_readiness_receipts: Vec<ReplacementReadinessReceipt>,
    /// Large route batches that are being processed in chunks.
    pending_route_batches: VecDeque<PendingRoutesReceived>,
    /// An inbound EVPN chunk's private fanout parked at a receiver boundary.
    /// The route chunk queue finishes it before any other chunk, and it
    /// survives a purge of its source's batches: a parked withdrawal must
    /// still reach the remaining receivers.
    pending_evpn_fanout: Option<distribution::PendingEvpnFanout>,
    /// Retained receive-side `FlowSpec` feasibility; empty when disabled.
    flowspec_validation: flowspec_validation::ValidationState,
    /// One explicit shared policy transition advanced by the actor itself.
    /// While present, only the dedicated type-narrow readiness lane may
    /// interleave; general queries, primary mutations, and timers remain
    /// ordered behind the final commit or fail-closed fallback handoff.
    pending_clean_policy_transition: Option<distribution::PendingCleanPolicyTransition>,
    /// Attribution of the first general or summary query after a committed
    /// transition; armed by the terminal commit poll, finished by the next
    /// dispatch on any delivery path, including a frozen replacement view.
    post_commit_query_trace: Option<PostCommitQueryTrace>,
    /// In-progress unfenced staging of a prospective clean-transition
    /// destination group (`RibUpdate::PrepareExportPolicyDestination`).
    /// Advanced one budgeted slice at a time only when no ordinary
    /// mutation traffic is queued — churn keeps flowing, and keeps the
    /// staged table current, while this walk covers the snapshot.
    pending_destination_prestage: Option<distribution::DestinationPrestage>,
    /// The exact group id a COMPLETED prestage staged, recorded so every
    /// discard removes the group that was actually built (never a
    /// re-derivation from current attributes, which can drift) and so a
    /// committing cohort that resolves a different destination discards
    /// the unadopted group instead of leaking it.
    prepared_destination: Option<usize>,
    /// The clean-transition inventory walked unfenced after the prestage
    /// that staged `prepared_destination`; consumed (re-checked against
    /// the churned keys only) by the fenced `BuildInventory`.
    prestaged_inventory: Option<update_groups::PrestagedTransitionInventory>,
    /// Withdrawn NLRI identities accumulated across the current distribution
    /// window. Retired only after distribution so the exact overlay can
    /// suppress any rejected-only wire withdrawal first.
    pending_exact_export_withdrawals: HashSet<ExactExportKey>,
    /// Best-path changes accumulated across the chunks of the current
    /// distribution window and distributed in a single `distribute_changes`
    /// call when the window settles. Deferring only the *distribution*
    /// coalesces a multi-chunk initial-load flood, and a run of small
    /// already-queued `RoutesReceived` messages, into one outbound batch per
    /// peer instead of one per chunk or message (RFC 4271 Appendix F.1).
    /// `recompute_best` still runs per chunk, so Loc-RIB, route events,
    /// counters and partial-progress Loc-RIB queries stay live mid-window.
    ///
    /// Window boundary, precisely: a window is one route batch plus any
    /// further unicast-only `RoutesReceived` messages that were ALREADY
    /// queued on the primary channel when the previous batch drained
    /// (`extend_distribution_window`); nothing waits for input. The window
    /// settles (flush, then exact-export retirement) when no such message is
    /// queued, when the next queued update is anything else (`PeerUp` /
    /// `PeerDown`, `EoR`, refresh, config, a primary-lane query), or when
    /// the window reaches its message, input-route, affected-prefix or
    /// elapsed bound (`DistributionWindowLimits`). Dirty-peer resync
    /// (`resync_dirty_peers_bounded`, the only resync entry that can run
    /// mid-window) settles it before reading advertised state. The run loop admits
    /// other primary updates only while no route batch is queued, and a
    /// window always holds a queued batch until it settles, so the
    /// accumulator is empty whenever no route batch is queued and before
    /// any other mutation observes Adj-RIB-Out. Priority read-only
    /// *queries* DO still interleave between chunks (`drain_queries`): a
    /// `QueryAdvertised*` reading Adj-RIB-Out mid-window correctly sees
    /// pre-flush advertised state — those routes have not been advertised
    /// yet — even though Loc-RIB has advanced. That is an accurate,
    /// eventually-consistent intermediate view, not stale data:
    /// Adj-RIB-Out is "what we have sent", and we have not sent the
    /// deferred window yet. `FlowSpec` validation slices, which read the
    /// dependency invalidations that the flush publishes, wait for the
    /// window to settle; the window bounds cap that delay.
    pending_distribute_changed: HashSet<Prefix>,
    pending_distribute_affected: HashSet<Prefix>,
    /// Progress of the current distribution window against its bounds.
    distribution_window: distribution::DistributionWindow,
    distribution_window_limits: distribution::DistributionWindowLimits,
    /// A primary update received while deciding whether to extend a
    /// distribution window, held until the run loop's next ordinary receive
    /// so a non-extending update keeps its FIFO position.
    primary_lookahead: Option<RibUpdate>,
    /// ADR-0137 admission cutoffs, one per run-loop timer: while a timer is
    /// due, the primary updates still admitted before it fires, which is
    /// the backlog when it was first seen due. Every admission counts,
    /// including one a distribution window coalesces, and a window does not
    /// extend past an exhausted cutoff. Sustained ingress therefore cannot
    /// postpone any of these deadlines indefinitely.
    expiry_cutoffs: ExpiryCutoffs,
    /// Process-local mutation versions bound into opaque route-page tokens.
    /// A successful continuation must match the requested scope's current
    /// version; no server-side snapshots are retained.
    route_page_table_version: Option<RoutePageVersion>,
    route_page_advertised_version: Option<RoutePageVersion>,
    /// Test-only ingest stall (ADR-0078 fault injection). When set via
    /// [`TEST_INGEST_STALL_ENV`], the run loop sleeps this long before
    /// handling each `RoutesReceived` batch popped from the primary
    /// channel, so the channel's remaining capacity stays occupied by
    /// the session tasks' sends and the inbound backpressure path
    /// (block-never-drop, writer-owned keepalives, pending-input hold
    /// re-arm) becomes deterministically observable. `None` in
    /// production — the only cost when unset is an `is_some()` check.
    test_ingest_stall: Option<std::time::Duration>,
    /// Daemon-wide ADR-0141 lease table, shared with every injection
    /// service and the expiry task.
    injection_leases: Arc<crate::injection_lease::InjectionLeases>,
    /// ADR-0141 ownership index for `LOCAL_PEER` keys: the tag of each owned
    /// key and each owner's keys. Changed only in the RIB turn that changes
    /// the local Adj-RIB-In, and swept here on expiry, never under the
    /// shared lease-table lock.
    injected_owners:
        HashMap<crate::injection_lease::InjectedKey, crate::injection_lease::InjectionTag>,
    owner_keys: HashMap<Arc<str>, HashSet<crate::injection_lease::InjectedKey>>,
    /// Owner label values already used on the lease-expiry counter; at most
    /// [`crate::injection_lease::MAX_LIVE_OWNERS`], then `_other`.
    lease_metric_owners: HashSet<Arc<str>>,
    /// Test-only fail-stop probe. Captured once at construction so a live
    /// process cannot change supervision behavior by mutating its environment.
    test_panic_on_peer_up: Option<()>,
    /// Update-group fingerprint registry (slice 1): membership (group
    /// id or ungrouped reason) per registered peer. Since slice 2 the
    /// distribution path reads it: grouped peers share the staged
    /// tables in `group_ribs`; ungrouped peers keep the per-peer path.
    update_groups: update_groups::UpdateGroupRegistry,
    /// Group-owned staged outbound tables, keyed by group id. One per
    /// non-empty group; created (and built with a single shared staging
    /// pass) at the first member's join, dropped at the last member's
    /// leave. See [`update_groups::GroupRibOut`].
    group_ribs: HashMap<usize, update_groups::GroupRibOut>,
    /// A regrouped member's previously-advertised view (old group table
    /// minus own-sourced, or the per-peer Adj-RIB-Out) — unicast plus
    /// group-owned VPN — held until its one-shot resync diff succeeds.
    /// Transient — regroups are config-time events.
    pending_regroup_baseline: HashMap<PeerId, update_groups::RegroupBaseline>,
    /// Candidate withdrawal keys carried across a dirty regroup; admission
    /// intersects these with the member's actual admitted-key proof. Cleared
    /// on resync success.
    pending_extra_withdraws: HashMap<PeerId, update_groups::ExtraWithdraws>,
    /// Actual admitted unicast/VPN keys while a member's shared desired view
    /// can advance without delivery. Exact capacity charge is capped at
    /// 64 MiB per peer and 512 MiB per daemon (provisional qualification
    /// sizing); refusal preserves existing conservative withdrawal duties.
    /// Released after recovery; healthy members retain no key proof.
    pending_group_admitted: update_groups::admitted_recovery::AdmittedRecovery,
    /// Charged EVPN history only for explicitly group-owned EVPN. Negotiated
    /// families and unicast group membership do not establish that ownership.
    evpn_recovery: update_groups::recovery_provenance::EvpnRecoveryProvenance,
    evpn_recovery_reset: Option<crate::update::EvpnRecoveryResetFn>,
    /// Unique across group recreation and paired EVPN route/input writes.
    evpn_table_stamp: u64,
    /// Fairness position for marker-only completion retries on the resync timer.
    evpn_marker_cursor: Option<PeerId>,
    /// Closed-cohort wire-oracle preparation only. Never configured by the daemon.
    #[cfg(feature = "bench-internals")]
    bench_evpn_group_ownership: bool,
    /// Differential-oracle test hook: disqualify every peer from
    /// grouping so identical scenarios can be driven through the
    /// per-peer path (the correctness oracle) and compared against a
    /// grouped run.
    #[cfg(test)]
    test_force_ungrouped: bool,
    /// Differential-oracle and benchmark hook: which full pass an unbounded
    /// dataset re-evaluation takes, so the group-level pass can be compared
    /// against the per-member resync.
    #[cfg(any(test, feature = "bench-internals"))]
    full_pass_path: FullPassPath,
    /// Full group-table control-tag scans run by deferred-registration
    /// cohort admission (LAN-1826): the per-turn work bound.
    #[cfg(test)]
    join_cohort_tag_scans: usize,
    /// Full-table dataset re-evaluation scans by group: an empty target set
    /// must run none.
    #[cfg(test)]
    dataset_full_table_scans: usize,
    /// Grouped VPN member emissions and clean→dirty deferral warnings:
    /// an already-dirty member must cost neither on later passes.
    #[cfg(test)]
    vpn_group_member_emits: usize,
    #[cfg(test)]
    vpn_member_deferral_warnings: usize,
    /// Per-peer family "outbound channel full" warnings, and dirty peers
    /// whose resync committed ("outbound routes resynced").
    #[cfg(test)]
    per_peer_deferral_warnings: usize,
    #[cfg(test)]
    dirty_resync_commits: usize,
    #[cfg(test)]
    test_force_exact_export_slow_path: bool,
    #[cfg(test)]
    test_exact_export_fast_path_hits: u64,
    #[cfg(test)]
    test_exact_export_full_prune_calls: u64,
    /// Test/benchmark-only evidence for the explicit clean policy transition.
    #[cfg(any(test, feature = "bench-internals"))]
    policy_transition_stats: PolicyTransitionStats,
    #[cfg(test)]
    authoritative_transition_receipts: Vec<AuthoritativeTransitionReceipt>,
    /// Test/benchmark-only evidence from the authoritative outbound commit.
    #[cfg(any(test, feature = "bench-internals"))]
    adj_rib_out_commit_stats: AdjRibOutCommitStats,
    #[cfg(feature = "bench-internals")]
    vpn_query_bench_receipts: Option<mpsc::Sender<(u64, usize, usize, u64)>>,
    #[cfg(feature = "bench-internals")]
    vpn_query_bench_dispatches: u64,
}

/// Bound on `live_sessions` entries per peer address. The RFC 4271 §6.8
/// collision window realistically holds two concurrent sessions (one per
/// connection direction); the bound only guards against a pathological
/// emitter. When exceeded, the OLDEST (most-superseded) record is dropped
/// — its eventual `PeerDown` is then discarded as stale.
const MAX_LIVE_SESSIONS_PER_PEER: usize = 2;

/// Cadence of the `bgp_rib_outbound_registration_pending_*` sample while a
/// registration wait may exist.
const REGISTRATION_WAIT_SAMPLE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);

/// A transition exceeding the former cohort wait budget is still allowed to
/// complete, but deserves an operator-visible warning and metric investigation.
const SLOW_POLICY_TRANSITION: std::time::Duration = std::time::Duration::from_secs(5);

/// Readiness stays live during bounded transition progress, but fails closed
/// once ownership is far beyond any legitimate transition receipt.
pub(in crate::manager) const MAX_HEALTHY_POLICY_TRANSITION_AGE: std::time::Duration =
    std::time::Duration::from_secs(30);

/// Limit the observation window after a committed transition. Queries
/// arriving after it do not emit a record; the interval alone cannot
/// establish whether a query was delayed by the commit.
const POST_COMMIT_QUERY_TRACE_WINDOW: std::time::Duration = std::time::Duration::from_secs(10);

/// Run-loop timers whose expiry waits only for the work queued when they
/// first fell due (ADR-0137 admission cutoff).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ExpiryTimer {
    RtcEor,
    Conditional,
    GrStale,
    LlgrStale,
    RefreshWindow,
    SelectionDeferral,
}

impl ExpiryTimer {
    const COUNT: usize = 6;
}

/// One admission cutoff per [`ExpiryTimer`]: `None` while the timer is not
/// due, else the primary updates still admitted before it fires. An
/// admission is charged to every captured cutoff, so several timers due at
/// once each fire within the backlog present when they fell due.
#[derive(Debug, Default)]
struct ExpiryCutoffs([Option<usize>; ExpiryTimer::COUNT]);

/// Wall-clock bound on one run of primary updates the run loop applies
/// back to back without yielding.
///
/// The run ends when the budget is spent (the loop yields) or when the actor
/// has suspended since the previous update, whichever `select!` branch or
/// await suspended it. Idle time between runs is therefore never charged: a
/// lone update after an idle gap does not yield ahead of the loop's own
/// due-timer check. A backlog sampled empty does not end the run, because a
/// producer on another worker can refill it before the receive is polled;
/// only a real `Pending` of the actor future counts.
#[derive(Debug, Default)]
struct PrimaryRunBudget {
    started: Option<std::time::Instant>,
}

impl PrimaryRunBudget {
    /// The start of the current run. A suspension recorded in `suspended`
    /// since the previous update ends the previous run; the flag is consumed.
    fn start(&mut self, now: std::time::Instant, suspended: &AtomicBool) -> std::time::Instant {
        if suspended.swap(false, Ordering::Relaxed) {
            self.started = None;
        }
        *self.started.get_or_insert(now)
    }

    /// Account one applied update; `true` means yield before the next one.
    fn should_yield(
        &mut self,
        started: std::time::Instant,
        now: std::time::Instant,
        budget: std::time::Duration,
    ) -> bool {
        if now.duration_since(started) >= budget {
            self.started = None;
            return true;
        }
        false
    }
}

impl ExpiryCutoffs {
    /// Capture `backlog` the first time `timer` is seen due; forget it once
    /// the timer is no longer due.
    fn observe(&mut self, timer: ExpiryTimer, due: bool, backlog: usize) {
        let cutoff = &mut self.0[timer as usize];
        if !due {
            *cutoff = None;
        } else if cutoff.is_none() {
            *cutoff = Some(backlog);
        }
    }

    fn remaining(&self, timer: ExpiryTimer) -> usize {
        self.0[timer as usize].unwrap_or(0)
    }

    fn clear(&mut self, timer: ExpiryTimer) {
        self.0[timer as usize] = None;
    }

    /// Charge one primary admission to every due timer.
    fn charge(&mut self) {
        for cutoff in self.0.iter_mut().flatten() {
            *cutoff = cutoff.saturating_sub(1);
        }
    }

    fn any_exhausted(&self) -> bool {
        self.0.contains(&Some(0))
    }

    /// Whether due `timer` must wait for another due timer whose cutoff is
    /// already exhausted. Its branch is skipped until that timer has fired:
    /// admitting more here would run post-deadline work ahead of the
    /// exhausted timer and stretch its bound.
    fn yields(&self, timer: ExpiryTimer) -> bool {
        self.remaining(timer) > 0 && self.any_exhausted()
    }
}

/// Upper bound on holding a peer's VPN/EVPN End-of-RIB while waiting for its
/// RT-Constrain End-of-RIB. RFC 4684 §6: a speaker that delays VPN
/// advertisement until that marker "MUST limit that delay to an upper bound.
/// By default, a 60 second value should be used."
const RTC_EOR_HOLD_CAP: std::time::Duration = std::time::Duration::from_secs(60);

/// Actor work units accounted between a transition's terminal commit poll and
/// the first general or summary query dispatched afterwards.
#[derive(Clone, Copy)]
enum PostCommitWork {
    RouteChunk,
    PrimaryUpdate,
    ResyncTick,
}

/// What the actor ran between a committed clean policy transition's terminal
/// poll and the first general or summary query it dispatches afterwards. One
/// `post-commit first general query timing` record per committed transition
/// that a general or summary query follows within [`POST_COMMIT_QUERY_TRACE_WINDOW`].
/// The historical event name is retained; `query_lane` identifies the receiver.
/// `first_query_wait_us` is wall-clock from the end of the terminal poll,
/// `busy_us` the elapsed wall time in completed units of the three instrumented
/// work classes, and `unattributed_us` the remainder, including uninstrumented
/// actor work, idle time, and scheduling delays outside those classes. A
/// synchronous owner still running at a frozen-summary or retirement dispatch
/// has not completed its work unit, so its elapsed time remains unattributed.
/// Dispatch is measured before the query handler runs, not at reply
/// completion. The two queued-query fields report lane depths at commit;
/// neither identifies whether the dispatched request itself was queued then.
struct PostCommitQueryTrace {
    since: std::time::Instant,
    member_count: usize,
    terminal_poll: std::time::Duration,
    queued_general_queries: usize,
    queued_summary_queries: usize,
    ingest_backlog: usize,
    busy: std::time::Duration,
    route_chunks: u32,
    primary_updates: u32,
    resync_ticks: u32,
}

impl PostCommitQueryTrace {
    fn record(&mut self, unit: PostCommitWork, elapsed: std::time::Duration) {
        self.busy += elapsed;
        let counter = match unit {
            PostCommitWork::RouteChunk => &mut self.route_chunks,
            PostCommitWork::PrimaryUpdate => &mut self.primary_updates,
            PostCommitWork::ResyncTick => &mut self.resync_ticks,
        };
        *counter = counter.saturating_add(1);
    }

    fn emit(self, query_lane: &'static str) {
        let wait = self.since.elapsed();
        if wait > POST_COMMIT_QUERY_TRACE_WINDOW {
            return;
        }
        let micros =
            |duration: std::time::Duration| u64::try_from(duration.as_micros()).unwrap_or(u64::MAX);
        info!(
            member_count = self.member_count,
            terminal_poll_us = micros(self.terminal_poll),
            queued_general_queries = self.queued_general_queries,
            queued_summary_queries = self.queued_summary_queries,
            query_lane,
            ingest_backlog_at_commit = self.ingest_backlog,
            first_query_wait_us = micros(wait),
            busy_us = micros(self.busy),
            unattributed_us = micros(wait.saturating_sub(self.busy)),
            route_chunks = self.route_chunks,
            primary_updates = self.primary_updates,
            resync_ticks = self.resync_ticks,
            "post-commit first general query timing"
        );
    }
}

/// A channel wake marks work pending without sharing canonical RIB state.
/// Keep this separate from the context: receiver-held wakers must not retain
/// the context that owns those receivers.
struct ReadinessWake {
    pending: AtomicBool,
}

impl Wake for ReadinessWake {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.pending.store(true, Ordering::Release);
    }
}

struct ReplacementReadinessContext {
    wake: Arc<ReadinessWake>,
    state: Mutex<ReplacementReadiness>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ReadinessOwnerKind {
    Replacement,
    SelectionRelease,
    PeerTeardown,
}

/// Register the checkpoint wake when empty, without charging the synchronous
/// owner's Tokio task budget. The caller retains the existing per-lane cap.
fn poll_readiness_query<T>(rx: &mut mpsc::Receiver<T>, cx: &mut Context<'_>) -> Poll<Option<T>> {
    std::pin::pin!(tokio::task::unconstrained(rx.recv())).poll(cx)
}

struct ReplacementReadiness {
    summaries: Option<replacement_summaries::ReplacementSummaries>,
    #[cfg(feature = "bench-internals")]
    capacities: HashMap<&'static str, (usize, usize, usize)>,
    #[cfg(test)]
    observer: Option<Arc<dyn Fn(&'static str) + Send + Sync>>,
    rx: Option<mpsc::Receiver<RibReadinessQuery>>,
    metrics: BgpMetrics,
    count: usize,
    /// Selection release and source teardown publish completed prefix changes;
    /// replacement ownership always keeps its original frozen count.
    kind: ReadinessOwnerKind,
    started: tokio::time::Instant,
    /// Tokio's clock, so a test can hold the service budget still with a
    /// paused clock; outside a paused runtime it reads the system clock.
    last_service: tokio::time::Instant,
    budget: std::time::Duration,
    #[cfg(any(test, feature = "bench-internals"))]
    last_opportunity: tokio::time::Instant,
    #[cfg(any(test, feature = "bench-internals"))]
    max_gap: std::time::Duration,
    #[cfg(any(test, feature = "bench-internals"))]
    serviced: usize,
    #[cfg(feature = "bench-internals")]
    retirement: bench_support::RetirementReadiness,
}

#[cfg(test)]
#[derive(Debug)]
struct ReplacementReadinessReceipt {
    kind: ReadinessOwnerKind,
    count: usize,
    elapsed: std::time::Duration,
    max_gap: std::time::Duration,
    serviced: usize,
}

#[expect(
    clippy::ref_option,
    reason = "callbacks borrow the actor's optional shared fence handle without creating another owner"
)]
fn replacement_readiness_checkpoint_at(
    readiness: &Option<Arc<ReplacementReadinessContext>>,
    stage: &'static str,
    force: bool,
) {
    #[cfg(test)]
    if let Some(context) = readiness {
        let observer = context
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .observer
            .clone();
        if let Some(observer) = observer {
            observer(stage);
        }
    }
    #[cfg(all(not(test), not(feature = "bench-internals")))]
    let _ = stage;
    #[cfg(feature = "bench-internals")]
    replacement_readiness_checkpoint_tagged(readiness, force, Some(stage), false);
    #[cfg(not(feature = "bench-internals"))]
    {
        slice_timing::checkpoint(Some(stage));
        replacement_readiness_checkpoint_untimed(readiness, force);
    }
}

/// Classify only the current helper callback, never a remembered stage or ordinal.
#[expect(clippy::ref_option, reason = "cleanup borrows its existing owner")]
fn replacement_readiness_cleanup_checkpoint(
    readiness: &Option<Arc<ReplacementReadinessContext>>,
    stage: &'static str,
    progress: crate::adj_rib_out::RetirementProgress,
) {
    #[cfg(all(test, feature = "bench-internals"))]
    if let Some(context) = readiness {
        let observer = context
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .observer
            .clone();
        if let Some(observer) = observer {
            observer(stage);
        }
    }
    #[cfg(feature = "bench-internals")]
    replacement_readiness_checkpoint_tagged(
        readiness,
        false,
        Some(stage),
        progress == crate::adj_rib_out::RetirementProgress::Progress,
    );
    #[cfg(not(feature = "bench-internals"))]
    {
        let _ = progress;
        replacement_readiness_checkpoint_at(readiness, stage, false);
    }
}

/// Call only on the actor while its synchronous readiness owner is held.
/// The shared handle exposes readiness and frozen values; canonical RIB
/// state remains exclusively owned by the actor.
#[cfg(not(feature = "bench-internals"))]
#[expect(
    clippy::ref_option,
    reason = "callbacks borrow the actor's optional shared fence handle without creating another owner"
)]
fn replacement_readiness_checkpoint(
    readiness: &Option<Arc<ReplacementReadinessContext>>,
    force: bool,
) {
    slice_timing::checkpoint(None);
    replacement_readiness_checkpoint_untimed(readiness, force);
}

#[cfg(not(feature = "bench-internals"))]
#[expect(
    clippy::ref_option,
    reason = "callbacks borrow the actor's optional shared fence handle without creating another owner"
)]
#[inline]
fn replacement_readiness_checkpoint_untimed(
    readiness: &Option<Arc<ReplacementReadinessContext>>,
    force: bool,
) {
    let Some(context) = readiness else {
        return;
    };
    #[cfg(test)]
    {
        let mut readiness = context
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if force || readiness.last_service.elapsed() >= readiness.budget {
            let now = tokio::time::Instant::now();
            readiness.max_gap = readiness
                .max_gap
                .max(now.duration_since(readiness.last_opportunity));
            readiness.last_opportunity = now;
        }
    }
    service_replacement_readiness(context, force);
}

#[cfg(feature = "bench-internals")]
#[expect(
    clippy::ref_option,
    reason = "callbacks borrow the actor's optional shared fence handle without creating another owner"
)]
fn replacement_readiness_checkpoint(
    readiness: &Option<Arc<ReplacementReadinessContext>>,
    force: bool,
) {
    replacement_readiness_checkpoint_tagged(readiness, force, None, false);
}

#[cfg(feature = "bench-internals")]
#[expect(
    clippy::ref_option,
    reason = "callbacks borrow the actor's optional shared fence handle without creating another owner"
)]
fn replacement_readiness_checkpoint_tagged(
    readiness: &Option<Arc<ReplacementReadinessContext>>,
    force: bool,
    stage: Option<&'static str>,
    progress: bool,
) {
    slice_timing::checkpoint(stage);
    let Some(context) = readiness else {
        return;
    };
    // Instrumented builds measure eligible opportunities, including idle
    // checkpoints, at forced checkpoints and during a retirement capture.
    // Once armed, production idle dispatch needs no mutex or clock. A capped
    // drain retains its hint until it can rearm below.
    if force || bench_support::measure_checkpoint() {
        let mut readiness = context
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let now = tokio::time::Instant::now();
        readiness
            .retirement
            .checkpoint(now, stage, force || !progress);
        if force || now.duration_since(readiness.last_service) >= readiness.budget {
            readiness.max_gap = readiness
                .max_gap
                .max(now.duration_since(readiness.last_opportunity));
            readiness.last_opportunity = now;
        }
    }
    service_replacement_readiness_with_origin(
        context,
        force,
        !force && progress && bench_support::retirement_body_stage(stage),
    );
}

#[cfg(not(feature = "bench-internals"))]
use self::service_replacement_readiness_with_origin as service_replacement_readiness;

// Existing unit controls invoke the untagged service seam directly. It cannot
// supply evidence of service at a productive cleanup checkpoint.
#[cfg(all(test, feature = "bench-internals"))]
fn service_replacement_readiness(context: &ReplacementReadinessContext, force: bool) {
    service_replacement_readiness_with_origin(context, force, false);
}

fn service_replacement_readiness_with_origin(
    context: &ReplacementReadinessContext,
    force: bool,
    #[cfg(feature = "bench-internals")] cleanup_body: bool,
) {
    if !force && !context.wake.pending.load(Ordering::Acquire) {
        return;
    }
    let mut readiness = context
        .state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if !force && readiness.last_service.elapsed() < readiness.budget {
        return;
    }
    let started = tokio::time::Instant::now();
    // Clear before polling: a concurrent enqueue either appears in this pass
    // or wakes the flag after poll_recv registers it. Never clear after a drain.
    context.wake.pending.store(false, Ordering::Release);
    let waker = Waker::from(Arc::clone(&context.wake));
    let mut cx = Context::from_waker(&waker);
    let mut received = 0;
    for _ in 0..QUERY_BUDGET_PER_CHUNK {
        let query = match readiness.rx.as_mut() {
            Some(rx) => match poll_readiness_query(rx, &mut cx) {
                Poll::Ready(Some(query)) => query,
                Poll::Pending => break,
                Poll::Ready(None) => {
                    readiness.rx = None;
                    break;
                }
            },
            None => break,
        };
        received += 1;
        let RibReadinessQuery::LocRibCount { reply, enqueued } = query;
        // Each mechanism shares the healthy bound but reports its own cause.
        let (seam, stalled) = match readiness.kind {
            ReadinessOwnerKind::SelectionRelease => (
                "selection_release",
                RibReadinessError::SelectionReleaseStalled,
            ),
            ReadinessOwnerKind::PeerTeardown => {
                ("peer_teardown", RibReadinessError::PeerTeardownStalled)
            }
            ReadinessOwnerKind::Replacement => (
                "policy_transition_fence",
                RibReadinessError::PolicyTransitionStalled,
            ),
        };
        readiness
            .metrics
            .observe_rib_readiness_query_wait(seam, enqueued.elapsed());
        let result = if readiness.started.elapsed() >= MAX_HEALTHY_POLICY_TRANSITION_AGE {
            Err(stalled)
        } else {
            Ok(readiness.count)
        };
        #[cfg(feature = "bench-internals")]
        {
            let in_owner = enqueued >= readiness.retirement.entered().into_std();
            let healthy = result.is_ok();
            let delivered = reply.send(result).is_ok();
            readiness
                .retirement
                .reply(in_owner, delivered && healthy, cleanup_body);
        }
        #[cfg(not(feature = "bench-internals"))]
        let _ = reply.send(result);
        #[cfg(any(test, feature = "bench-internals"))]
        {
            readiness.serviced += 1;
        }
    }
    if received == QUERY_BUDGET_PER_CHUNK {
        // The cap can stop before an empty poll registers the next wake.
        context.wake.wake_by_ref();
    }
    if let Some(summaries) = readiness.summaries.as_mut() {
        let count = summaries.drain(&mut cx);
        if count == QUERY_BUDGET_PER_CHUNK {
            context.wake.wake_by_ref();
        }
        received += count;
    }
    // A close or a coalesced wake can leave no query. As before, idle passes
    // must not postpone service for the next query by advancing this clock.
    if force || received != 0 {
        readiness.last_service = started;
        #[cfg(any(test, feature = "bench-internals"))]
        {
            // A sampled build may not have measured this checkpoint; record
            // the gap that ends here before the service pass resets it.
            readiness.max_gap = readiness
                .max_gap
                .max(started.duration_since(readiness.last_opportunity));
            readiness.last_opportunity = started;
        }
    }
}

fn collect_evpn_dataplane_routes<'a>(
    rows: impl Iterator<Item = &'a crate::route::EvpnRibRoute>,
    known_generation: Option<u64>,
    current_generation: u64,
    total_rows: usize,
    relevant_rows: usize,
) -> Option<Vec<crate::route::EvpnRibRoute>> {
    if known_generation == Some(current_generation) {
        return None;
    }
    if relevant_rows == total_rows {
        return Some(rows.cloned().collect());
    }
    let mut routes = Vec::with_capacity(relevant_rows);
    routes.extend(
        rows.filter(|route| rustbgpd_wire::is_dataplane_route_type(route.route_type()))
            .cloned(),
    );
    Some(routes)
}

/// Aggregate pre-commit ownership budget for one clean policy transition:
/// still short of `CommitMembers` at this age, the transition hands the
/// cohort to the authoritative per-peer path fail-closed (LAN-886 — before
/// this budget existed, every pre-commit fallback trigger was an
/// invalidation event, so a slow-but-healthy transition fenced the actor
/// and all wire output until session teardown finally closed an outbound
/// channel). Twice the readiness bound by construction: the stalled
/// readiness verdict at [`MAX_HEALTHY_POLICY_TRANSITION_AGE`] is the early
/// warning, this handoff is the remedy.
pub(in crate::manager) const MAX_PRECOMMIT_POLICY_TRANSITION_OWNERSHIP: std::time::Duration =
    MAX_HEALTHY_POLICY_TRANSITION_AGE.saturating_mul(2);

/// Registration material for one live transport session of a peer
/// address, captured at `PeerUp`. Held in `RibManager::live_sessions` so
/// an outbound-registration failover can re-register a surviving session
/// (channel + negotiated metadata + initial table dump) after the active
/// session goes down during the collision window.
#[expect(
    clippy::struct_excessive_bools,
    reason = "mirrors the independent PeerUp registration booleans"
)]
pub(super) struct LiveSessionRecord {
    session_id: u64,
    /// Start of this session's current outbound-registration wait: its
    /// `PeerUp`, or the collision failback that handed an earlier-registered
    /// survivor the registration again. `None` once its registration installs.
    registration_wait_since: Option<tokio::time::Instant>,
    source_context: Option<Arc<crate::update::PeerSourceContext>>,
    /// Interned scope of `source_context`'s interface, resolved at
    /// registration; `DEFAULT` for a numbered neighbor.
    peer_scope: crate::route::AspaContextId,
    peer_group: Option<String>,
    outbound_tx: mpsc::Sender<OutboundRouteUpdate>,
    peer_asn: u32,
    peer_router_id: Ipv4Addr,
    export_policy: Option<PolicyChain>,
    sendable_families: Vec<(Afi, Safi)>,
    /// Negotiated families withheld from `sendable_families`, with the
    /// session's reason; each gets an empty `EoR` with the initial dump.
    withheld_families: Vec<crate::update::WithheldFamily>,
    is_ebgp: bool,
    route_reflector_client: bool,
    local_role: Option<BgpRole>,
    orr_vantage: Option<IpAddr>,
    per_client_best: bool,
    interpret_rfc1997: bool,
    /// RFC 7947 §2.3.2 control-community context: the RS-side local ASN
    /// when the session interprets control communities, staged via
    /// `SetPeerRsControl` before `PeerUp`.
    rs_control_asn: Option<u32>,
    add_path_send_families: Vec<(Afi, Safi)>,
    add_path_send_max: u32,
    /// Per-family Paths-Limit caps (RFC-draft Paths-Limit), filtered to the
    /// negotiated send families. Empty at `PeerUp`; the session emits its
    /// `PeerAddPathLimits` exactly once, and the handler mirrors the accepted
    /// map here so a collision failback replays it instead of clamping every
    /// family back to the scalar `add_path_send_max`.
    add_path_send_limits: HashMap<(Afi, Safi), u32>,
    negotiated_orf_recv: Vec<(Afi, Safi)>,
    negotiated_llgr_families: Vec<(Afi, Safi)>,
    gr_context: Option<PeerSelectionDeferralContext>,
    exact_export_encoder: Option<Arc<dyn ExactExportEncoder>>,
    /// This session has sent its L2VPN/EVPN End-of-RIB since the peer's
    /// Adj-RIB-In was last discarded.
    evpn_end_of_rib: bool,
    /// Failed reset admission remains in this bounded existing session record.
    evpn_recovery_reset: Option<evpn_recovery::PendingReset>,
    /// One nonblocking execution receipt, fixed lifecycle control metadata.
    evpn_recovery_reset_receipt: Option<evpn_recovery::ResetReceipt>,
    /// Bound refusal/drop diagnostics to one warning per connection episode.
    evpn_recovery_reset_retry_reported: bool,
    /// Fixed completion metadata, separate from charged recovery key storage.
    evpn_feed_completion: Option<evpn_recovery::EvpnFeedCompletion>,
    /// Actual group-owned EVPN admission, including clean deltas without keys.
    evpn_admitted_count: usize,
    group_recovery_fallback: Option<update_groups::RecoveryFallbackCause>,
    /// Initial unicast replay omitted rows behind process-start selection.
    /// Own its admitted-key proof independently of End-of-RIB replay grace.
    selection_initial_pending: bool,
    /// A process-start hold retains this receiver's admitted projection.
    selection_partial_pending: [bool; 4],
    /// Every currently exportable change is admitted; only held work remains.
    selection_partial_caught_up: bool,
    /// Actual admitted UC-v4/v6 and VPN-v4/v6 path counts, then UC-v4/v6
    /// prefix counts. Final batch deltas keep frozen-view gauges O(batch).
    selection_initial_admitted: [usize; 6],
    /// Counts remain truthful if a later bounded proof reservation refuses.
    selection_initial_admitted_valid: bool,
    /// The neighbor's export-policy totals, installed with the registration.
    export_policy_counters: crate::update::ExportPolicyCounters,
}

#[derive(Clone, Debug, Default)]
struct PeerSelectionDeferralContext {
    peer_restart_state: bool,
    /// The OPEN carried a Graceful Restart capability, even one listing no
    /// family (helper-only, RFC 4724 §3): the peer retains our routes.
    peer_gr_helper: bool,
    peer_gr_families: Vec<(Afi, Safi)>,
    /// Peer negotiated enhanced route refresh (RFC 7313). Collision
    /// failback only arms a `BoRR`/`EoRR` convergence wait when the
    /// survivor can actually produce the pair.
    peer_enhanced_refresh: bool,
    /// The new OPEN's LLGR families; re-derives the LLGR promotion config of
    /// a peer that re-establishes during retention.
    peer_llgr_families: Vec<rustbgpd_wire::LlgrFamily>,
    local_llgr_stale_time: u32,
}

const ROUTES_RECEIVED_CHUNK_SIZE: usize = 1024;
/// Server-side hard cap on a paged route-query page — bounds per-page
/// allocation regardless of the client-requested size.
pub const ROUTE_QUERY_MAX_PAGE_SIZE: usize = 1000;
/// Most local route keys one export-disposition query may name. Every page
/// of a walk re-reads each named key's route to check the walk's fence, so
/// this bounds that per-page work beside the page size.
pub const LOCAL_ROUTE_EXPORT_MAX_KEYS: usize = 1000;

const QUERY_BUDGET_PER_CHUNK: usize = 8;
/// Production stride of probed routes between wall-clock checks inside one
/// strict shared-policy actor poll; the poll keeps striding until
/// [`FLUSH_POLL_BUDGET`] elapses.
pub(in crate::manager) const POLICY_TRANSITION_PRODUCTION_ROUTE_SLICE: usize = 1_024;
/// Maximum route identities processed by one strict shared-policy actor poll.
#[cfg(not(test))]
pub(in crate::manager) const POLICY_TRANSITION_ROUTE_SLICE: usize =
    POLICY_TRANSITION_PRODUCTION_ROUTE_SLICE;
/// Tiny deterministic unit used to prove multi-poll ordering in tests.
#[cfg(test)]
pub(in crate::manager) const POLICY_TRANSITION_ROUTE_SLICE: usize = 1;

pub(in crate::manager) fn policy_transition_slice_end(
    cursor: usize,
    len: usize,
    budget: usize,
) -> usize {
    (cursor + budget).min(len)
}
/// Maximum members classified by one strict shared-policy actor poll.
pub(in crate::manager) const POLICY_TRANSITION_MEMBER_SLICE: usize = 8;
/// Stride of validated members committed between wall-clock checks inside
/// one commit-kind actor poll (matches `QUERY_BUDGET_PER_CHUNK`). The poll
/// keeps flushing strides until [`FLUSH_POLL_BUDGET`] elapses, then
/// parks so the readiness lane gets its seam.
pub(in crate::manager) const COMMIT_MEMBERS_PER_POLL: usize = 8;
/// Wall-clock budget for one paced actor poll — a commit-kind member flush
/// or a dirty-resync tick. Bounds the readiness-seam latency (well under
/// the 200 ms readiness deadline) while decoupling paced throughput from
/// fleet size — a fixed 8-item poll at ~10 ms of interleaved actor work per
/// poll seam cost ~0.88 s of staggered emission at 700 members.
const FLUSH_POLL_BUDGET: std::time::Duration = std::time::Duration::from_millis(25);

/// The flush budget a new manager starts with. Unit tests can force it with
/// `RUSTBGPD_TEST_FLUSH_BUDGET_US` so every update paces, which makes a test
/// barrier that only holds on a fast host fail deterministically
/// (`just test-rib-paced`). Other builds always use [`FLUSH_POLL_BUDGET`].
#[cfg(test)]
fn initial_flush_poll_budget() -> std::time::Duration {
    std::env::var("RUSTBGPD_TEST_FLUSH_BUDGET_US").map_or(FLUSH_POLL_BUDGET, |micros| {
        std::time::Duration::from_micros(
            micros
                .parse()
                .expect("RUSTBGPD_TEST_FLUSH_BUDGET_US must be whole microseconds"),
        )
    })
}

#[cfg(not(test))]
const fn initial_flush_poll_budget() -> std::time::Duration {
    FLUSH_POLL_BUDGET
}
/// Maximum deferred inbound-refresh retries in a resync-timer tick. Dirty
/// route replays poll the work budget after each complete peer instead.
const RESYNC_PEERS_PER_TICK: usize = 8;
/// Re-arm interval while a withheld dirty-resync backlog remains. Short by
/// design: the backlog is work the actor already owes, so the next slice
/// should run as soon as queued updates and queries have had a turn.
const DIRTY_RESYNC_BACKLOG_INTERVAL: std::time::Duration = std::time::Duration::from_millis(10);
// Bound deferred unicast garbage by displaced routes and elapsed time. Small
// intern tables retain immediate collection; retain scans capacity, not length.
const ATTR_INTERN_GC_DISPLACED_LIMIT: usize = 4096;
const ATTR_INTERN_GC_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);
const ROUTE_EVENT_HISTORY_CAPACITY: usize = 4096;
const EVPN_ROUTE_EVENT_HISTORY_CAPACITY: usize = 4096;
/// Loc-RIB size at which a `PeerUp` initial dump is expensive enough to
/// defer behind queued actor work (LAN-475). Below this an inline dump is
/// sub-10-ms-class (measured ~2M NLRI/s staged-dump throughput at the IXP
/// receipt shape), so even a 50-peer reconnect burst serializes well under
/// a second; above it, mass-reconnect dump serialization visibly delays
/// re-announcement fan-out and the deferral engages.
const INITIAL_DUMP_DEFER_MIN_ROUTES: usize = 10_000;

fn initial_route_page_version() -> RoutePageVersion {
    let state = std::collections::hash_map::RandomState::new();
    let mut hasher = state.build_hasher();
    hasher.write_u64(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |duration| {
                u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX)
            }),
    );
    RoutePageVersion {
        epoch: hasher.finish(),
        generation: 0,
    }
}

/// Test-only fault injection for the ADR-0078 inbound backpressure
/// contract: milliseconds the RIB manager sleeps before handling each
/// `RoutesReceived` batch. Used by the M63 interop smoke to stall the
/// RIB against a real peer so the inbound channel fills, the session
/// task parks, and hold-timer survival is provable. Never set this in
/// production. Read once at RIB-manager construction; unset, empty,
/// zero, or unparseable values disable the stall.
const TEST_INGEST_STALL_ENV: &str = "RUSTBGPD_TEST_RIB_INGEST_STALL_MS";

/// Test-only fail-stop probe used by the daemon supervision integration test.
/// The panic occurs before any page-generation mutation for the `PeerUp`.
const TEST_PANIC_ON_PEER_UP_ENV: &str = "RUSTBGPD_TEST_RIB_PANIC_ON_PEER_UP";

fn test_panic_on_peer_up_override(env: Option<&str>) -> bool {
    match env.map(str::trim) {
        Some("1") => true,
        None => false,
        Some(_) => {
            warn!("ignoring invalid {TEST_PANIC_ON_PEER_UP_ENV} (expected 1)");
            false
        }
    }
}

/// Pure core of the [`TEST_INGEST_STALL_ENV`] override with the
/// environment value injected, so the parse rule (positive u64
/// milliseconds → stall, anything else → no stall) is unit-testable
/// without touching process-global env state.
fn test_ingest_stall_override(env: Option<&str>) -> Option<std::time::Duration> {
    let raw = env?;
    match raw.trim().parse::<u64>() {
        Ok(ms) if ms > 0 => Some(std::time::Duration::from_millis(ms)),
        Ok(_) => None,
        Err(_) => {
            warn!(
                value = %raw,
                "ignoring invalid {TEST_INGEST_STALL_ENV} (expected milliseconds as a u64)"
            );
            None
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(super) struct PolicyFilteredRouteKey {
    pub(super) target_peer: PeerId,
    pub(super) source_peer: PeerId,
    pub(super) prefix: Prefix,
    pub(super) path_id: u32,
}

/// One prefix's retained export-policy denials toward one target. Most
/// prefixes carry a single denied source/path identity, which stays inline;
/// a set is allocated only for two or more.
#[derive(Debug)]
pub(super) enum PolicyFilteredBucket {
    One(PolicyFilteredRouteKey),
    Many(HashSet<PolicyFilteredRouteKey>),
}

impl PolicyFilteredBucket {
    #[cfg(test)]
    pub(super) fn iter(&self) -> impl Iterator<Item = &PolicyFilteredRouteKey> {
        let (one, many) = match self {
            Self::One(key) => (Some(key), None),
            Self::Many(keys) => (None, Some(keys)),
        };
        one.into_iter().chain(many.into_iter().flatten())
    }

    /// Keep only identities still denied; `false` when none remain. A set
    /// left with one identity releases its allocation and stores it inline.
    fn retain(
        &mut self,
        mut keep: impl FnMut(&PolicyFilteredRouteKey) -> bool,
        allocation_checkpoint: &impl Fn(),
    ) -> bool {
        let keys = match self {
            Self::One(key) => return keep(key),
            Self::Many(keys) => keys,
        };
        keys.retain(|key| keep(key));
        if keys.len() == 1
            && let Some(&key) = keys.iter().next()
        {
            allocation_checkpoint();
            drop(std::mem::replace(self, Self::One(key)));
            allocation_checkpoint();
            return true;
        }
        !keys.is_empty()
    }

    /// Record `group` (one prefix's current denials), pushing identities not
    /// already retained. Growth allocates the exact existing-plus-incoming
    /// bound once and moves old keys between checkpoints.
    fn insert_group(
        &mut self,
        group: &[PolicyFilteredRouteKey],
        newly_filtered: &mut Vec<PolicyFilteredRouteKey>,
        checkpoint: &impl Fn(),
        allocation_checkpoint: &impl Fn(),
    ) {
        if let Self::One(key) = self
            && group.iter().all(|incoming| {
                checkpoint();
                incoming == key
            })
        {
            return;
        }
        let required = group.len().saturating_add(match self {
            Self::One(_) => 1,
            Self::Many(keys) => keys.len(),
        });
        if !matches!(self, Self::Many(keys) if keys.capacity() >= required) {
            allocation_checkpoint();
            let mut replacement = HashSet::with_capacity(required);
            allocation_checkpoint();
            match self {
                Self::One(key) => {
                    replacement.insert(*key);
                }
                Self::Many(keys) => {
                    for key in keys.drain() {
                        checkpoint();
                        replacement.insert(key);
                    }
                }
            }
            allocation_checkpoint();
            drop(std::mem::replace(self, Self::Many(replacement)));
            allocation_checkpoint();
        }
        let Self::Many(keys) = self else {
            unreachable!("growth installed a set")
        };
        for key in group.iter().copied() {
            checkpoint();
            if keys.insert(key) {
                newly_filtered.push(key);
            }
        }
    }
}

/// A prefix can contribute many rejected source/path identities. Grow an
/// empty allocation from the exact incoming identity bound, never by
/// reserving a populated set or assuming prefix cardinality is sufficient.
#[expect(
    clippy::ref_option,
    reason = "inventory work borrows its existing readiness owner"
)]
fn extend_policy_filtered_routes_with_readiness(
    routes: &mut HashSet<PolicyFilteredRouteKey>,
    mut incoming: impl ExactSizeIterator<Item = PolicyFilteredRouteKey>,
    readiness: &Option<Arc<ReplacementReadinessContext>>,
) {
    let required = routes.len().saturating_add(incoming.len());
    if required > routes.capacity() {
        replacement_readiness_checkpoint_at(readiness, "policy_filtered_allocation", true);
        let mut replacement = HashSet::with_capacity(required);
        replacement_readiness_checkpoint_at(readiness, "policy_filtered_allocation", true);
        #[cfg(test)]
        let capacity = replacement.capacity();
        for key in routes.drain() {
            replacement_readiness_checkpoint_at(readiness, "policy_filtered_rebuild", false);
            replacement.insert(key);
            #[cfg(test)]
            assert_eq!(
                replacement.capacity(),
                capacity,
                "policy-filtered inventory grew during old-key rebuild"
            );
        }
        replacement_readiness_checkpoint_at(readiness, "policy_filtered_allocation", true);
        drop(std::mem::replace(routes, replacement));
        replacement_readiness_checkpoint_at(readiness, "policy_filtered_allocation", true);
    }
    #[cfg(test)]
    let capacity = routes.capacity();
    for key in incoming.by_ref() {
        replacement_readiness_checkpoint_at(readiness, "policy_filtered_input", false);
        routes.insert(key);
        #[cfg(test)]
        assert_eq!(
            routes.capacity(),
            capacity,
            "policy-filtered inventory grew during candidate insertion"
        );
    }
    replacement_readiness_checkpoint_at(readiness, "policy_filtered_allocation", true);
    drop(incoming);
    replacement_readiness_checkpoint_at(readiness, "policy_filtered_allocation", true);
}

#[expect(
    clippy::ref_option,
    reason = "inventory cleanup borrows its existing readiness owner"
)]
fn retire_policy_filtered_routes_with_readiness(
    routes: &mut HashSet<PolicyFilteredRouteKey>,
    readiness: &Option<Arc<ReplacementReadinessContext>>,
) {
    replacement_readiness_checkpoint_at(readiness, "policy_filtered_retirement", true);
    for _ in routes.drain() {
        replacement_readiness_checkpoint_at(readiness, "policy_filtered_retirement", false);
    }
    replacement_readiness_checkpoint_at(readiness, "policy_filtered_retirement", true);
    drop(std::mem::take(routes));
    replacement_readiness_checkpoint_at(readiness, "policy_filtered_retirement", true);
}

enum PendingRouteChunk {
    Withdrawn(Vec<(Prefix, u32)>),
    Announced(Vec<crate::route::Route>),
    FlowSpecWithdrawn(Vec<crate::route::FlowSpecKey>),
    FlowSpecAnnounced(Vec<crate::route::FlowSpecRoute>),
    EvpnWithdrawn(Vec<rustbgpd_wire::EvpnRouteKey>),
    EvpnAnnounced(Vec<crate::route::EvpnRibRoute>),
}

impl PendingRouteChunk {
    fn len(&self) -> usize {
        match self {
            Self::Withdrawn(entries) => entries.len(),
            Self::Announced(entries) => entries.len(),
            Self::FlowSpecWithdrawn(entries) => entries.len(),
            Self::FlowSpecAnnounced(entries) => entries.len(),
            Self::EvpnWithdrawn(entries) => entries.len(),
            Self::EvpnAnnounced(entries) => entries.len(),
        }
    }
}

enum PendingRoutePhase {
    Withdrawn,
    Announced,
    FlowSpecWithdrawn,
    FlowSpecAnnounced,
    EvpnWithdrawn,
    EvpnAnnounced,
    Done,
}

struct PendingRoutesReceived {
    source: crate::update::ReceivedRouteSource,
    /// Committed history eligibility fixed at admission, never re-bound later.
    dampening_source: Option<crate::dampening::DampeningSource>,
    original_unicast_withdrawals: usize,
    route_capacity_hint: usize,
    flowspec_capacity_hint: usize,
    withdrawn: std::vec::IntoIter<(Prefix, u32)>,
    announced: std::vec::IntoIter<crate::route::Route>,
    flowspec_withdrawn: std::vec::IntoIter<crate::route::FlowSpecKey>,
    flowspec_announced: std::vec::IntoIter<crate::route::FlowSpecRoute>,
    evpn_withdrawn: std::vec::IntoIter<rustbgpd_wire::EvpnRouteKey>,
    evpn_announced: std::vec::IntoIter<crate::route::EvpnRibRoute>,
    validated_with: Option<rustbgpd_rpki::ValidationSnapshot>,
    phase: PendingRoutePhase,
    /// A chunk of this batch parked its EVPN fanout; the batch continues,
    /// or finishes its message, once [`RibManager::pending_evpn_fanout`]
    /// drains.
    fanout_parked: bool,
}

impl PendingRoutesReceived {
    #[expect(
        clippy::too_many_arguments,
        reason = "RIB update messages carry every supported family as one transaction"
    )]
    fn new(
        peer: PeerId,
        announced: Vec<crate::route::Route>,
        withdrawn: Vec<(Prefix, u32)>,
        flowspec_announced: Vec<crate::route::FlowSpecRoute>,
        flowspec_withdrawn: Vec<crate::route::FlowSpecKey>,
        evpn_announced: Vec<crate::route::EvpnRibRoute>,
        evpn_withdrawn: Vec<rustbgpd_wire::EvpnRouteKey>,
        validated_with: Option<rustbgpd_rpki::ValidationSnapshot>,
    ) -> Self {
        let route_capacity_hint = (announced.len() + withdrawn.len()).max(16);
        let flowspec_capacity_hint = (flowspec_announced.len() + flowspec_withdrawn.len()).max(4);
        Self {
            source: crate::update::ReceivedRouteSource {
                peer,
                session_id: 0,
                peer_asn: None,
                context: None,
            },
            dampening_source: None,
            original_unicast_withdrawals: 0,
            route_capacity_hint,
            flowspec_capacity_hint,
            withdrawn: withdrawn.into_iter(),
            announced: announced.into_iter(),
            flowspec_withdrawn: flowspec_withdrawn.into_iter(),
            flowspec_announced: flowspec_announced.into_iter(),
            evpn_withdrawn: evpn_withdrawn.into_iter(),
            evpn_announced: evpn_announced.into_iter(),
            validated_with,
            phase: PendingRoutePhase::Withdrawn,
            fanout_parked: false,
        }
    }

    fn route_capacity_hint(&self) -> usize {
        self.route_capacity_hint
    }

    fn flowspec_capacity_hint(&self) -> usize {
        self.flowspec_capacity_hint
    }

    fn peer(&self) -> PeerId {
        self.source.peer
    }

    fn next_chunk(&mut self) -> Option<PendingRouteChunk> {
        loop {
            match self.phase {
                PendingRoutePhase::Withdrawn => {
                    let chunk: Vec<_> = self
                        .withdrawn
                        .by_ref()
                        .take(ROUTES_RECEIVED_CHUNK_SIZE)
                        .collect();
                    if chunk.is_empty() {
                        self.phase = PendingRoutePhase::Announced;
                        continue;
                    }
                    return Some(PendingRouteChunk::Withdrawn(chunk));
                }
                PendingRoutePhase::Announced => {
                    let chunk: Vec<_> = self
                        .announced
                        .by_ref()
                        .take(ROUTES_RECEIVED_CHUNK_SIZE)
                        .collect();
                    if chunk.is_empty() {
                        self.phase = PendingRoutePhase::FlowSpecWithdrawn;
                        continue;
                    }
                    return Some(PendingRouteChunk::Announced(chunk));
                }
                PendingRoutePhase::FlowSpecWithdrawn => {
                    let chunk: Vec<_> = self
                        .flowspec_withdrawn
                        .by_ref()
                        .take(ROUTES_RECEIVED_CHUNK_SIZE)
                        .collect();
                    if chunk.is_empty() {
                        self.phase = PendingRoutePhase::FlowSpecAnnounced;
                        continue;
                    }
                    return Some(PendingRouteChunk::FlowSpecWithdrawn(chunk));
                }
                PendingRoutePhase::FlowSpecAnnounced => {
                    let chunk: Vec<_> = self
                        .flowspec_announced
                        .by_ref()
                        .take(ROUTES_RECEIVED_CHUNK_SIZE)
                        .collect();
                    if chunk.is_empty() {
                        self.phase = PendingRoutePhase::EvpnWithdrawn;
                        continue;
                    }
                    return Some(PendingRouteChunk::FlowSpecAnnounced(chunk));
                }
                PendingRoutePhase::EvpnWithdrawn => {
                    let chunk: Vec<_> = self
                        .evpn_withdrawn
                        .by_ref()
                        .take(ROUTES_RECEIVED_CHUNK_SIZE)
                        .collect();
                    if chunk.is_empty() {
                        self.phase = PendingRoutePhase::EvpnAnnounced;
                        continue;
                    }
                    return Some(PendingRouteChunk::EvpnWithdrawn(chunk));
                }
                PendingRoutePhase::EvpnAnnounced => {
                    let chunk: Vec<_> = self
                        .evpn_announced
                        .by_ref()
                        .take(ROUTES_RECEIVED_CHUNK_SIZE)
                        .collect();
                    if chunk.is_empty() {
                        self.phase = PendingRoutePhase::Done;
                        continue;
                    }
                    return Some(PendingRouteChunk::EvpnAnnounced(chunk));
                }
                PendingRoutePhase::Done => return None,
            }
        }
    }

    fn has_more(&self) -> bool {
        !self.withdrawn.as_slice().is_empty()
            || !self.announced.as_slice().is_empty()
            || !self.flowspec_withdrawn.as_slice().is_empty()
            || !self.flowspec_announced.as_slice().is_empty()
            || !self.evpn_withdrawn.as_slice().is_empty()
            || !self.evpn_announced.as_slice().is_empty()
    }
}

fn log_orr_input_transition(
    previous: crate::orr::OrrInputDiagnostics,
    current: crate::orr::OrrInputDiagnostics,
) {
    match crate::orr::input_diagnostics_transition(previous, current) {
        Some(crate::orr::OrrInputTransition::ExclusionsActivated) => warn!(
            included_default = current.included_default,
            excluded_nondefault = current.excluded_nondefault,
            malformed_topology = current.malformed_topology,
            malformed_attribute_29 = current.malformed_attribute_29,
            default_with_ignored_flex_algo = current.default_with_ignored_flex_algo,
            "ORR BGP-LS exclusions became active for the supported default topology"
        ),
        Some(crate::orr::OrrInputTransition::ExclusionsCleared) => info!(
            included_default = current.included_default,
            excluded_nondefault = current.excluded_nondefault,
            malformed_topology = current.malformed_topology,
            malformed_attribute_29 = current.malformed_attribute_29,
            default_with_ignored_flex_algo = current.default_with_ignored_flex_algo,
            "one or more ORR BGP-LS exclusion categories cleared; other diagnostics remain active"
        ),
        Some(crate::orr::OrrInputTransition::FlexChanged) => info!(
            included_default = current.included_default,
            excluded_nondefault = current.excluded_nondefault,
            malformed_topology = current.malformed_topology,
            malformed_attribute_29 = current.malformed_attribute_29,
            default_with_ignored_flex_algo = current.default_with_ignored_flex_algo,
            "ORR ignored Flex-Algorithm input changed; classic default-topology metrics remain active"
        ),
        Some(crate::orr::OrrInputTransition::Cleared) => {
            info!("ORR BGP-LS input filtering is no longer active");
        }
        None => {}
    }
}

impl RibManager {
    /// Immediately reclaim unused attributes at teardown and explicit sweep seams.
    fn gc_attr_intern(&mut self) {
        self.gc_attr_intern_with_checkpoint(&mut || {});
    }

    fn gc_attr_intern_with_checkpoint(
        &mut self,
        checkpoint: &mut impl crate::adj_rib_out::RetirementCheckpoint,
    ) {
        self.attr_intern.gc_with_checkpoint(checkpoint);
        self.attr_intern_gc_displaced = 0;
        self.attr_intern_gc_deadline = None;
        self.sync_attr_intern_gauge();
    }

    /// Account deadline-triggered sweeps separately from route-chunk work.
    fn gc_attr_intern_on_timer(&mut self) {
        let started = std::time::Instant::now();
        self.gc_attr_intern();
        self.metrics
            .observe_rib_actor_work("attribute_gc", started.elapsed());
    }

    /// Amortize the measured unicast UPDATE hot path without changing Arc
    /// ownership or the point at which routes become visible. At most one route
    /// chunk can take the displaced count over the limit before collection.
    fn defer_unicast_attr_gc(&mut self, displaced: usize) {
        if displaced == 0 {
            return;
        }
        self.attr_intern_gc_displaced = self.attr_intern_gc_displaced.saturating_add(displaced);
        let now = tokio::time::Instant::now();
        let deadline = *self
            .attr_intern_gc_deadline
            .get_or_insert(now + ATTR_INTERN_GC_INTERVAL);
        if self.attr_intern.capacity() <= ATTR_INTERN_GC_DISPLACED_LIMIT
            || self.attr_intern_gc_displaced >= ATTR_INTERN_GC_DISPLACED_LIMIT
            || now >= deadline
        {
            // ponytail: each sweep is still O(global table); this bounds its
            // frequency, not its latency. Revisit incremental collection if a
            // single large-table sweep exceeds the actor work budget.
            self.gc_attr_intern();
        }
    }

    /// Refresh the global intern-table gauge without sweeping. Run after
    /// insert-only batches so growth is visible at every mutation seam
    /// (a gauge a scenario never updates cannot gate anything).
    fn sync_attr_intern_gauge(&self) {
        self.metrics
            .set_rib_attr_intern_global_size(gauge_val(self.attr_intern.len()));
    }
}

impl RibManager {
    /// Create a new RIB manager with the given update channel and optional export policy.
    #[must_use]
    #[expect(
        clippy::too_many_lines,
        reason = "constructor initializes the manager's deliberately centralized actor state"
    )]
    pub fn new(
        rx: mpsc::Receiver<RibUpdate>,
        query_rx: mpsc::Receiver<RibUpdate>,
        export_policy: Option<PolicyChain>,
        cluster_id: Option<Ipv4Addr>,
        metrics: BgpMetrics,
    ) -> Self {
        let (route_events_tx, _) = broadcast::channel(4096);
        metrics.set_route_event_history_capacity(
            i64::try_from(ROUTE_EVENT_HISTORY_CAPACITY).unwrap_or(i64::MAX),
        );
        metrics.set_route_event_history_depth(0);
        // EVPN broadcast — same capacity as the unicast channel.
        // Slow EVPN subscribers receive `Lagged(_)`; the daemon's
        // originator falls back to `repoll_rib` per ADR-0054 §6's
        // level-triggered model. Capacity here only needs to ride
        // through transient bursts (mobility storms, FRR-side
        // re-advertisement on session up).
        let (evpn_events_tx, _) = broadcast::channel(4096);
        // Read the test-only ingest stall once at construction
        // (RIB-manager startup); unset in production.
        let test_ingest_stall_env = match std::env::var(TEST_INGEST_STALL_ENV) {
            Ok(value) => Some(value),
            Err(std::env::VarError::NotPresent) => None,
            Err(std::env::VarError::NotUnicode(_)) => {
                warn!("ignoring non-unicode {TEST_INGEST_STALL_ENV}");
                None
            }
        };
        let test_ingest_stall = test_ingest_stall_override(test_ingest_stall_env.as_deref());
        if let Some(stall) = test_ingest_stall {
            warn!(
                stall_ms = u64::try_from(stall.as_millis()).unwrap_or(u64::MAX),
                "{TEST_INGEST_STALL_ENV} active: stalling every RoutesReceived batch \
                 (ADR-0078 fault injection — test use only, never set in production)"
            );
        }
        let test_panic_on_peer_up_env = match std::env::var(TEST_PANIC_ON_PEER_UP_ENV) {
            Ok(value) => Some(value),
            Err(std::env::VarError::NotPresent) => None,
            Err(std::env::VarError::NotUnicode(_)) => {
                warn!("ignoring non-unicode {TEST_PANIC_ON_PEER_UP_ENV}");
                None
            }
        };
        let test_panic_on_peer_up =
            test_panic_on_peer_up_override(test_panic_on_peer_up_env.as_deref());
        if test_panic_on_peer_up {
            warn!(
                "{TEST_PANIC_ON_PEER_UP_ENV} active: panicking on PeerUp \
                 (fail-stop supervision fault injection — test use only)"
            );
        }
        let pending_group_admitted = update_groups::admitted_recovery::AdmittedRecovery::new();
        metrics.set_update_group_recovery_limit_bytes(
            i64::try_from(update_groups::admitted_recovery::PEER_LIMIT_BYTES).unwrap_or(i64::MAX),
            i64::try_from(update_groups::admitted_recovery::DAEMON_LIMIT_BYTES).unwrap_or(i64::MAX),
        );
        metrics.set_update_group_recovery_entries(0);
        metrics.set_update_group_recovery_bytes(
            i64::try_from(pending_group_admitted.bytes()).unwrap_or(i64::MAX),
        );
        metrics.set_update_group_recovery_peak_bytes(
            i64::try_from(pending_group_admitted.peak_bytes()).unwrap_or(i64::MAX),
        );
        Self {
            ribs: HashMap::new(),
            attr_intern: crate::attr_intern::AttrInternTable::new(),
            attr_intern_gc_displaced: 0,
            attr_intern_gc_deadline: None,
            unicast_prefix_peers: UnicastPrefixPeers::default(),
            loc_rib: LocRib::new(),
            evpn_dataplane_generation: 0,
            evpn_dataplane_route_count: 0,
            #[cfg(test)]
            evpn_dataplane_query_row_visits: 0,
            #[cfg(test)]
            dataplane_page_announcer_visits: std::sync::atomic::AtomicUsize::new(0),
            #[cfg(test)]
            dataplane_page_sibling_visits: std::sync::atomic::AtomicUsize::new(0),
            #[cfg(test)]
            dataplane_exact_cancel_after_visits: std::sync::atomic::AtomicUsize::new(0),
            adj_ribs_out: HashMap::new(),
            outbound_prefix_limits: HashMap::new(),
            outbound_limit_control: outbound_prefix_limits::OutboundLimitControl::default(),
            outbound_peers: HashMap::new(),
            flush_poll_budget: initial_flush_poll_budget(),
            actor_suspended: Arc::default(),
            outbound_session_ids: HashMap::new(),
            live_sessions: HashMap::new(),
            evpn_feed_receipt_count: 0,
            pending_peer_export_context: HashMap::new(),
            pending_peer_withheld_families: HashMap::new(),
            pending_peer_rs_control: HashMap::new(),
            pending_peer_export_encoders: HashMap::new(),
            pending_peer_export_counters: HashMap::new(),
            pending_peer_gr_context: HashMap::new(),
            pending_peer_source_context: HashMap::new(),
            dampening_history: dampening_history::DampeningHistoryState::default(),
            pending_peer_policy_context: HashMap::new(),
            peer_export_encoders: HashMap::new(),
            peer_unexportable: HashMap::new(),
            #[cfg(test)]
            grouped_advertised_count_calls: std::sync::atomic::AtomicUsize::new(0),
            // ADR-0136: publishes the first roster, creating the global
            // fallback's counters.
            export_chains: export_chains::ExportChains::new(export_policy),
            peer_sendable_families: HashMap::new(),
            outbound_roster_generation: 0,
            export_settings_generation: 0,
            peer_advertised_llgr_families: HashMap::new(),
            peer_is_ebgp: HashMap::new(),
            peer_is_rr_client: HashMap::new(),
            peer_local_roles: HashMap::new(),
            peer_otc_blocked: HashMap::new(),
            pending_otc_blocked: HashMap::new(),
            peer_orr_vantage: HashMap::new(),
            orr: crate::orr::OrrState::default(),
            orr_page_topology: None,
            #[cfg(test)]
            orr_page_topology_builds: 0,
            cluster_id,
            dirty_peers: BTreeSet::new(),
            dirty_since: HashMap::new(),
            dirty_resync_cursor: None,
            pending_inbound_refresh: BTreeMap::new(),
            pending_inbound_refresh_cursor: None,
            force_outbound_peers: HashSet::new(),
            pending_eor: HashMap::new(),
            pending_refresh: HashMap::new(),
            pending_initial_registrations: VecDeque::new(),
            registration_wait_sample_at: None,
            initial_dump_defer_min_routes: INITIAL_DUMP_DEFER_MIN_ROUTES,
            refresh_in_progress: HashMap::new(),
            refresh_deadlines: graceful_restart::DeadlineMap::default(),
            refresh_stale_routes: HashMap::new(),
            refresh_stale_flowspec: HashMap::new(),
            refresh_stale_evpn: HashMap::new(),
            refresh_stale_bgpls: HashMap::new(),
            refresh_stale_vpn: HashMap::new(),
            refresh_stale_labeled: HashMap::new(),
            refresh_stale_rtc: HashMap::new(),
            refresh_stale_counts: HashMap::new(),
            gr_peers: HashMap::new(),
            gr_stale_deadlines: graceful_restart::DeadlineMap::default(),
            gr_stale_routes_time: HashMap::new(),
            llgr_peers: HashMap::new(),
            llgr_stale_deadlines: graceful_restart::DeadlineMap::default(),
            llgr_peer_config: HashMap::new(),
            peer_add_path_send_max: HashMap::new(),
            peer_add_path_send_limits: HashMap::new(),
            peer_per_client_best: HashSet::new(),
            peer_interpret_rfc1997: HashSet::new(),
            peer_rs_control: HashMap::new(),
            peer_add_path_send_families: HashMap::new(),
            peer_orf_filters: HashMap::new(),
            slow_isolated_peers: HashSet::new(),
            peer_rt_membership: HashMap::new(),
            peer_orf_pending: HashMap::new(),
            gr_deferred_eor: HashMap::new(),
            rtc_eor_hold: graceful_restart::DeadlineMap::default(),
            rtc_eor_hold_ready: HashSet::new(),
            eor_grace: HashMap::new(),
            eor_grace_deadlines: graceful_restart::DeadlineMap::default(),
            eor_replay: eor_grace::ReplayWait::default(),
            selection_deferral: None,
            deferred_selection_keys: selection_deferral::DeferredSelectionKeys::default(),
            selection_deferred_refresh: HashMap::new(),
            peer_asn: HashMap::new(),
            peer_group: HashMap::new(),
            conditional_advertisements:
                conditional_advertisement::ConditionalAdvertisementTracker::default(),
            peer_group_version: Some(initial_route_page_version()),
            peer_bgp_id: HashMap::new(),
            update_groups: update_groups::UpdateGroupRegistry::default(),
            group_ribs: HashMap::new(),
            pending_regroup_baseline: HashMap::new(),
            pending_extra_withdraws: HashMap::new(),
            pending_group_admitted,
            evpn_recovery: update_groups::recovery_provenance::EvpnRecoveryProvenance::new(),
            evpn_recovery_reset: None,
            evpn_table_stamp: 0,
            evpn_marker_cursor: None,
            #[cfg(feature = "bench-internals")]
            bench_evpn_group_ownership: false,
            #[cfg(test)]
            test_force_ungrouped: false,
            #[cfg(any(test, feature = "bench-internals"))]
            full_pass_path: FullPassPath::Group,
            #[cfg(test)]
            join_cohort_tag_scans: 0,
            #[cfg(test)]
            dataset_full_table_scans: 0,
            #[cfg(test)]
            vpn_group_member_emits: 0,
            #[cfg(test)]
            vpn_member_deferral_warnings: 0,
            #[cfg(test)]
            per_peer_deferral_warnings: 0,
            #[cfg(test)]
            dirty_resync_commits: 0,
            #[cfg(test)]
            test_force_exact_export_slow_path: false,
            #[cfg(test)]
            test_exact_export_fast_path_hits: 0,
            #[cfg(test)]
            test_exact_export_full_prune_calls: 0,
            #[cfg(any(test, feature = "bench-internals"))]
            policy_transition_stats: PolicyTransitionStats::default(),
            #[cfg(test)]
            authoritative_transition_receipts: Vec::new(),
            #[cfg(any(test, feature = "bench-internals"))]
            adj_rib_out_commit_stats: AdjRibOutCommitStats::default(),
            #[cfg(feature = "bench-internals")]
            vpn_query_bench_receipts: None,
            #[cfg(feature = "bench-internals")]
            vpn_query_bench_dispatches: 0,
            vrp_table: None,
            aspa_table: None,
            route_events_tx,
            fib_candidate_changes_tx: watch::channel(0).0,
            policy_filtered_routes: HashMap::new(),
            export_policy_counters: HashMap::new(),
            route_event_history: VecDeque::new(),
            next_route_event_id: 1,
            route_event_id_exhausted: false,
            evpn_events_tx,
            evpn_route_event_history: VecDeque::new(),
            bmp_tx: None,
            metrics,
            rx,
            query_rx,
            readiness_rx: None,
            summary_rx: None,
            replacement_readiness: None,
            #[cfg(test)]
            replacement_readiness_test_hook: None,
            #[cfg(test)]
            test_primary_update_hook: None,
            slow_actor_turn_log: actor_turn::SlowActorTurnLog::default(),
            #[cfg(test)]
            replacement_readiness_receipts: Vec::new(),
            pending_route_batches: VecDeque::new(),
            pending_evpn_fanout: None,
            flowspec_validation: flowspec_validation::ValidationState::default(),
            pending_clean_policy_transition: None,
            post_commit_query_trace: None,
            pending_destination_prestage: None,
            prepared_destination: None,
            prestaged_inventory: None,
            pending_exact_export_withdrawals: HashSet::new(),
            pending_distribute_changed: HashSet::new(),
            pending_distribute_affected: HashSet::new(),
            distribution_window: distribution::DistributionWindow::default(),
            distribution_window_limits: distribution::DistributionWindowLimits::default(),
            expiry_cutoffs: ExpiryCutoffs::default(),
            primary_lookahead: None,
            route_page_table_version: Some(initial_route_page_version()),
            route_page_advertised_version: Some(initial_route_page_version()),
            test_ingest_stall,
            injection_leases: Arc::new(crate::injection_lease::InjectionLeases::new()),
            lease_metric_owners: HashSet::new(),
            injected_owners: HashMap::new(),
            owner_keys: HashMap::new(),
            test_panic_on_peer_up: test_panic_on_peer_up.then_some(()),
        }
    }

    /// Select eager Loc-RIB prefix indexing for bounded internal dataplane
    /// pages. The mode must be chosen before the manager contains any unicast
    /// route; this avoids a synchronous index rebuild at cutover time.
    ///
    /// # Panics
    ///
    /// Panics if any Adj-RIB-In or Loc-RIB unicast route is already present.
    #[must_use]
    pub fn with_eager_dataplane_prefix_index(mut self) -> Self {
        assert!(
            self.loc_rib.is_empty() && self.ribs.is_empty(),
            "eager dataplane prefix indexing must be selected on an empty RIB manager"
        );
        assert!(
            self.loc_rib.enable_dataplane_prefix_index(),
            "eager dataplane prefix indexing requires pristine index state"
        );
        self
    }

    /// Arm bounded benchmark receipts for the real VPN snapshot query arm.
    #[cfg(feature = "bench-internals")]
    #[must_use]
    pub fn with_vpn_query_bench_receipts(
        mut self,
        receipts: mpsc::Sender<(u64, usize, usize, u64)>,
    ) -> Self {
        self.vpn_query_bench_receipts = Some(receipts);
        self
    }

    /// Run every unbounded dataset re-evaluation as the per-member full
    /// resync, which marks each target dirty: the mass-dirty seed of the
    /// recovery-memory harness and the cost of the fallback path.
    #[cfg(feature = "bench-internals")]
    #[must_use]
    pub fn with_member_full_pass(mut self) -> Self {
        self.full_pass_path = FullPassPath::Member;
        self
    }

    /// Install the dedicated type-narrow RIB readiness-query receiver.
    #[must_use]
    pub fn with_readiness_queries(
        mut self,
        readiness_rx: mpsc::Receiver<RibReadinessQuery>,
    ) -> Self {
        self.readiness_rx = Some(readiness_rx);
        self
    }

    /// Install nonblocking reset admission to the existing session lifecycle
    /// owner. Exhausted EVPN recovery remains unsettled until that generation
    /// leaves; successful callback admission is not a completed reset receipt.
    #[must_use]
    pub fn with_evpn_recovery_reset_handler(
        mut self,
        handler: crate::update::EvpnRecoveryResetFn,
    ) -> Self {
        self.evpn_recovery_reset = Some(handler);
        self
    }

    /// Outbound export/replacement does not change Loc-RIB cardinality. Keep that exact
    /// actor-owned invariant while readiness acknowledgements and optional
    /// frozen operator summaries interleave.
    fn with_replacement_readiness<T>(&mut self, work: impl FnOnce(&mut Self) -> T) -> T {
        let installed = self.begin_replacement_readiness();
        let result = work(self);
        self.finish_readiness_owner(installed);
        result
    }

    fn begin_replacement_readiness(&mut self) -> bool {
        let age = self.pending_clean_policy_transition.as_ref().map_or(
            std::time::Duration::ZERO,
            distribution::PendingCleanPolicyTransition::elapsed,
        );
        self.begin_readiness_owner(age, false)
    }

    fn with_replacement_readiness_age<T>(
        &mut self,
        age: std::time::Duration,
        work: impl FnOnce(&mut Self) -> T,
    ) -> T {
        self.with_readiness_owner(age, false, work)
    }

    /// Selection retains exclusive actor ownership and its existing gate/EoR
    /// order. Only its dedicated readiness lane can observe completed unicast
    /// mutations; replacement owners continue to use their frozen count.
    fn with_selection_readiness<T>(&mut self, work: impl FnOnce(&mut Self) -> T) -> T {
        with_executor_handoff(|| self.with_readiness_owner(std::time::Duration::ZERO, true, work))
    }

    /// End changing-count teardown before detached-table and attribute cleanup.
    fn with_peer_teardown_readiness<T>(&mut self, work: impl FnOnce(&mut Self) -> T) -> T {
        let age = self.pending_clean_policy_transition.as_ref().map_or(
            std::time::Duration::ZERO,
            distribution::PendingCleanPolicyTransition::elapsed,
        );
        with_executor_handoff(|| {
            let installed = self.begin_readiness_owner_kind(age, ReadinessOwnerKind::PeerTeardown);
            let result = work(self);
            self.finish_readiness_owner(installed);
            result
        })
    }

    fn with_readiness_owner<T>(
        &mut self,
        age: std::time::Duration,
        selection_release: bool,
        work: impl FnOnce(&mut Self) -> T,
    ) -> T {
        let installed = self.begin_readiness_owner(age, selection_release);
        let result = work(self);
        self.finish_readiness_owner(installed);
        result
    }

    /// Nested work retains the existing owner's exact identity and age.
    fn begin_readiness_owner(&mut self, age: std::time::Duration, selection_release: bool) -> bool {
        self.begin_readiness_owner_kind(
            age,
            if selection_release {
                ReadinessOwnerKind::SelectionRelease
            } else {
                ReadinessOwnerKind::Replacement
            },
        )
    }

    fn begin_readiness_owner_kind(
        &mut self,
        age: std::time::Duration,
        kind: ReadinessOwnerKind,
    ) -> bool {
        if self.replacement_readiness.is_some() {
            return false;
        }
        let entered = tokio::time::Instant::now();
        let started = entered - age;
        self.replacement_readiness = Some(Arc::new(ReplacementReadinessContext {
            wake: Arc::new(ReadinessWake {
                pending: AtomicBool::new(true),
            }),
            state: Mutex::new(ReplacementReadiness {
                summaries: None,
                #[cfg(feature = "bench-internals")]
                capacities: HashMap::new(),
                #[cfg(test)]
                observer: self.replacement_readiness_test_hook.clone(),
                rx: self.readiness_rx.take(),
                metrics: self.metrics.clone(),
                count: self.loc_rib.len(),
                kind,
                started,
                last_service: tokio::time::Instant::now(),
                budget: self.flush_poll_budget.min(FLUSH_POLL_BUDGET),
                #[cfg(any(test, feature = "bench-internals"))]
                last_opportunity: tokio::time::Instant::now(),
                #[cfg(any(test, feature = "bench-internals"))]
                max_gap: std::time::Duration::ZERO,
                #[cfg(any(test, feature = "bench-internals"))]
                serviced: 0,
                #[cfg(feature = "bench-internals")]
                retirement: bench_support::RetirementReadiness::new(entered),
            }),
        }));
        self.replacement_checkpoint(true);
        self.record_replacement_capacities();
        true
    }

    /// Call after all temporary checkpoint handles have left the work frame.
    fn finish_readiness_owner(&mut self, installed: bool) {
        if !installed {
            return;
        }
        self.record_replacement_capacities();
        self.replacement_checkpoint_at("terminal_cleanup", true);
        let context = self
            .replacement_readiness
            .take()
            .expect("replacement scope retains its readiness context");
        debug_assert_eq!(
            Arc::strong_count(&context),
            1,
            "readiness callback escaped its command frame"
        );
        let mut readiness = context
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        debug_assert_eq!(readiness.count, self.loc_rib.len());
        self.readiness_rx = readiness.rx.take();
        #[cfg(feature = "bench-internals")]
        readiness
            .retirement
            .finish(readiness.max_gap, readiness.budget);
        #[cfg(all(feature = "bench-internals", not(test)))]
        info!(target: "replacement_readiness", count = readiness.count,
            elapsed_us = readiness.started.elapsed().as_micros(),
            max_gap_us = readiness.max_gap.as_micros(), serviced = readiness.serviced,
            "replacement readiness scope finished");
        #[cfg(all(feature = "bench-internals", not(test)))]
        for (name, (len, capacity, slots)) in &readiness.capacities {
            info!(target: "replacement_capacity", name, max_len = len, max_capacity = capacity,
                max_raw_slots = slots, "replacement capacity maximum");
        }
        #[cfg(test)]
        {
            self.replacement_readiness_receipts
                .push(ReplacementReadinessReceipt {
                    kind: readiness.kind,
                    count: readiness.count,
                    elapsed: readiness.started.elapsed(),
                    max_gap: readiness.max_gap,
                    serviced: readiness.serviced,
                });
        }
    }

    /// Call only after a complete prefix mutation, before any checkpoint can
    /// answer from the new selection. Never alter a frozen replacement owner.
    fn selection_readiness_checkpoint(&self) {
        if let Some(context) = &self.replacement_readiness {
            let mut context = context
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if context.kind == ReadinessOwnerKind::Replacement {
                return;
            }
            context.count = self.loc_rib.len();
        }
        self.replacement_checkpoint_at("selection_recompute", false);
    }

    fn replacement_checkpoint_at(&self, stage: &'static str, force: bool) {
        replacement_readiness_checkpoint_at(&self.replacement_readiness, stage, force);
    }

    fn replacement_checkpoint(&self, force: bool) {
        replacement_readiness_checkpoint(&self.replacement_readiness, force);
    }

    /// Aggregate capacity evidence within the owning command, never per route.
    fn replacement_capacity(&self, name: &'static str, len: usize, capacity: usize) {
        self.replacement_storage_shape(name, len, capacity, 0);
    }

    fn replacement_storage_shape(
        &self,
        name: &'static str,
        len: usize,
        capacity: usize,
        slots: usize,
    ) {
        #[cfg(feature = "bench-internals")]
        if let Some(context) = &self.replacement_readiness {
            let mut context = context
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let maximum = context.capacities.entry(name).or_default();
            maximum.0 = maximum.0.max(len);
            maximum.1 = maximum.1.max(capacity);
            maximum.2 = maximum.2.max(slots);
        }
        #[cfg(not(feature = "bench-internals"))]
        let _ = (self, name, len, capacity, slots);
    }

    fn record_replacement_capacities(&self) {
        #[cfg(not(feature = "bench-internals"))]
        let _ = self;
        #[cfg(feature = "bench-internals")]
        if self.replacement_readiness.is_some() {
            for group in self.group_ribs.values() {
                let (len, slots, capacity) = group.table.bench_unicast_storage_shape();
                self.replacement_storage_shape("group_unicast", len, capacity, slots);
                let (len, capacity) = group.bench_otc_storage_shape();
                self.replacement_capacity("group_otc", len, capacity);
            }
            for table in self.adj_ribs_out.values() {
                let (len, slots, capacity) = table.bench_unicast_storage_shape();
                self.replacement_storage_shape("private_unicast", len, capacity, slots);
            }
            for baseline in self.pending_regroup_baseline.values() {
                self.replacement_capacity(
                    "pending_baseline",
                    baseline.unicast.len(),
                    baseline.unicast.capacity(),
                );
            }
            for pending in self.pending_otc_blocked.values() {
                self.replacement_capacity("pending_otc", pending.len(), pending.capacity());
            }
        }
    }

    /// Test-only ADR-0078 fault injection: sleep before handling a
    /// `RoutesReceived` batch popped from the primary channel. The
    /// sleep happens *after* the recv and *before* `handle_update`, so
    /// the channel's remaining slots stay occupied by session-task
    /// sends for the whole stall — exactly the saturation shape the
    /// M63 interop smoke needs. No-op (one `is_some()` check) unless
    /// [`TEST_INGEST_STALL_ENV`] was set at construction.
    async fn maybe_stall_test_ingest(&self, update: &RibUpdate) {
        if let Some(stall) = self.test_ingest_stall
            && matches!(
                update,
                RibUpdate::RoutesReceived { .. } | RibUpdate::WireRoutesReceived(_)
            )
        {
            debug!(
                stall_ms = u64::try_from(stall.as_millis()).unwrap_or(u64::MAX),
                "test ingest stall before RoutesReceived batch"
            );
            tokio::time::sleep(stall).await;
        }
    }

    /// Install the RFC 9069 Loc-RIB BMP tap. Called at startup by the
    /// daemon binary when at least one BMP collector monitors the
    /// `loc_rib` view; left `None` otherwise so non-monitored
    /// deployments pay nothing for PDU synthesis.
    #[must_use]
    pub fn with_bmp_tx(mut self, bmp_tx: mpsc::Sender<rustbgpd_bmp::BmpEvent>) -> Self {
        self.bmp_tx = Some(bmp_tx);
        self
    }

    /// Install the startup-frozen RFC 4724 restarting-speaker waiter roster.
    /// Called before the actor starts; cold starts leave the gate absent.
    #[must_use]
    pub fn with_selection_deferral(mut self, config: SelectionDeferralConfig) -> Self {
        self.selection_deferral = selection_deferral::SelectionDeferral::new(config, &self.metrics);
        self
    }

    /// Seed the startup conditional-advertisement install (ADR-0137) before
    /// the actor starts, so no session can register ahead of its gate.
    /// Definitions start `pending`. Install after
    /// [`Self::with_selection_deferral`] so RFC 4724 deferral holds them.
    #[must_use]
    pub fn with_conditional_advertisements(mut self, set: ConditionalAdvertisementSet) -> Self {
        let _ = self.handle_install_conditional_advertisements(set, &[]);
        self
    }

    #[must_use]
    /// L2VPN/EVPN session counts and End-of-RIB sync, from the newest live
    /// session record per peer.
    fn evpn_sessions_sync(&self) -> crate::update::EvpnSessionsSync {
        let evpn = (Afi::L2Vpn, Safi::Evpn);
        // The newest live record is the one registration uses; an older
        // collision-window record cannot vouch for it.
        let peers: Vec<bool> = self
            .live_sessions
            .values()
            .filter_map(|sessions| sessions.last())
            .filter(|s| s.sendable_families.contains(&evpn))
            .map(|s| s.evpn_end_of_rib)
            .collect();
        // Peers retaining L2VPN/EVPN routes as GR or LLGR stale: the
        // overlay still forwards on them (ADR-0140 decision 2).
        let stale = self
            .gr_peers
            .keys()
            .chain(self.llgr_peers.keys())
            .collect::<HashSet<_>>()
            .into_iter()
            .filter(|peer| {
                self.gr_peers.get(*peer).is_some_and(|f| f.contains(&evpn))
                    || self
                        .llgr_peers
                        .get(*peer)
                        .is_some_and(|f| f.contains(&evpn))
            })
            .count();
        // GR selection deferral keeps EVPN Loc-RIB unchanged, so remote
        // Type 4 routes are not readable until it releases.
        crate::update::EvpnSessionsSync {
            established: peers.len(),
            stale,
            synced: !self.selection_deferred(evpn)
                && !peers.is_empty()
                && peers.iter().all(|&synced| synced),
        }
    }

    pub(super) fn selection_deferred(&self, family: (Afi, Safi)) -> bool {
        self.selection_deferral
            .as_ref()
            .is_some_and(|state| state.selection_deferred(family))
    }

    #[must_use]
    pub(super) fn selection_convergence_held(&self, family: (Afi, Safi)) -> bool {
        self.selection_deferral
            .as_ref()
            .is_some_and(|state| state.is_gated(family))
    }

    /// Whether `family`'s pending `EoR` toward `peer` must stay queued: the
    /// RFC 4724 convergence gate, the RFC 4684 §6 hold on the families RT
    /// membership filters while `peer`'s RT-Constrain `EoR` is outstanding,
    /// or the opt-in planned-restart grace window.
    pub(super) fn eor_held(&self, peer: PeerId, family: (Afi, Safi)) -> bool {
        self.selection_convergence_held(family)
            || (self.rtc_eor_hold.contains_key(&peer) && Self::rtc_gated_family(family))
            || self.eor_grace_held(peer, family)
    }

    /// The families the RFC 4684 outbound membership gate filters.
    pub(super) fn rtc_gated_family(family: (Afi, Safi)) -> bool {
        family.1 == Safi::MplsVpn || family == (Afi::L2Vpn, Safi::Evpn)
    }

    /// End a peer's RFC 4684 §6 `EoR` hold and emit the held markers. A
    /// dirty peer keeps them pending: its resync flushes them after the
    /// routes it replays, preserving table-before-`EoR` order.
    fn release_rtc_eor_hold(&mut self, peer: PeerId) {
        self.rtc_eor_hold_ready.remove(&peer);
        if self.rtc_eor_hold.remove(&peer).is_some() && !self.dirty_peers.contains(&peer) {
            self.flush_pending_eor(peer);
        }
    }

    /// `peer`'s RT membership is complete on the wire (its RT-Constrain
    /// `EoR`, or an `EoRR` closing an active window). Release the hold now,
    /// unless RT-Constrain selection is still deferred: membership is then
    /// rebuilt only when the deferral is staged or released, and the hold
    /// ends there instead, after the VPN/EVPN routes it admits.
    fn rtc_membership_complete(&mut self, peer: PeerId) {
        if self.selection_deferred(crate::route::RtcRibRouteKey::afi_safi()) {
            if self.rtc_eor_hold.contains_key(&peer) {
                self.rtc_eor_hold_ready.insert(peer);
            }
        } else {
            self.release_rtc_eor_hold(peer);
        }
    }

    /// RT-Constrain selection was just staged or released and every
    /// membership rebuilt: end the holds whose `EoR` already arrived.
    fn release_ready_rtc_eor_holds(&mut self) {
        let ready: Vec<PeerId> = self.rtc_eor_hold_ready.drain().collect();
        for peer in ready {
            self.release_rtc_eor_hold(peer);
        }
    }

    /// The nearest `EoR` hold deadline: an RFC 4684 §6 cap or a grace window.
    fn next_eor_hold_deadline(&mut self) -> Option<tokio::time::Instant> {
        match (self.rtc_eor_hold.min(), self.next_eor_grace_deadline()) {
            (Some(rtc), Some(grace)) => Some(rtc.min(grace)),
            (rtc, grace) => rtc.or(grace),
        }
    }

    /// Expire the holds behind the shared timer that fell due at `due`. Grace
    /// windows release only up to `due`: a later window waits for its own
    /// turn, so the work queued before its deadline drains first.
    fn expire_eor_holds(&mut self, due: tokio::time::Instant) {
        self.expire_eor_grace(due);
        let now = tokio::time::Instant::now();
        let expired: Vec<PeerId> = self
            .rtc_eor_hold
            .iter()
            .filter(|&(_, &deadline)| deadline <= now)
            .map(|(&peer, _)| peer)
            .collect();
        for peer in expired {
            info!(
                %peer,
                cap_secs = RTC_EOR_HOLD_CAP.as_secs(),
                "no RT-Constrain End-of-RIB from peer within the cap — sending held VPN/EVPN End-of-RIB"
            );
            self.release_rtc_eor_hold(peer);
        }
    }

    /// Emit an RFC 9069 Loc-RIB Route Monitoring event. `pdu = None`
    /// (synthesis failure, already warned) is a no-op. `path_status`
    /// carries the Path Marking payload for announcements (`None` on
    /// withdrawals — a gone path has no status). Uses `try_send`
    /// — monitoring must never backpressure the RIB task; drops are
    /// surfaced with a warning.
    fn emit_bmp_loc_rib(
        &self,
        pdu: Option<bytes::Bytes>,
        path_status: Option<rustbgpd_bmp::BmpPathStatus>,
        timestamp: std::time::SystemTime,
    ) {
        let (Some(tx), Some(update_pdu)) = (self.bmp_tx.as_ref(), pdu) else {
            return;
        };
        if let Err(e) = tx.try_send(rustbgpd_bmp::BmpEvent::LocRibRouteMonitoring {
            update_pdu,
            timestamp,
            path_status,
        }) {
            let reason = match e {
                tokio::sync::mpsc::error::TrySendError::Full(_) => "channel_full",
                tokio::sync::mpsc::error::TrySendError::Closed(_) => "channel_closed",
            };
            self.metrics
                .record_bmp_loc_rib_source_drop("route_monitoring", reason);
            warn!(error = %e, "BMP event channel full or closed, dropping Loc-RIB route monitoring");
        }
    }

    #[must_use]
    fn peer_has_any_add_path_send(&self, peer: PeerId) -> bool {
        self.peer_add_path_send_max.get(&peer).copied().unwrap_or(0) > 0
            && self
                .peer_add_path_send_families
                .get(&peer)
                .is_some_and(|families| !families.is_empty())
    }

    #[must_use]
    fn add_path_send_max_for_prefix(&self, peer: PeerId, prefix: &Prefix) -> u32 {
        let send_max = self.peer_add_path_send_max.get(&peer).copied().unwrap_or(0);
        if send_max == 0 {
            return 0;
        }
        let family = prefix_family(prefix);
        // The exact family map is subordinate to the negotiated Add-Path
        // send set. Keep this check ahead of the map lookup so a malformed
        // cross-crate payload can never enable Add-Path for an unnegotiated
        // family in release builds.
        if !self
            .peer_add_path_send_families
            .get(&peer)
            .is_some_and(|families| families.contains(&family))
        {
            return 0;
        }
        if let Some(limit) = self
            .peer_add_path_send_limits
            .get(&peer)
            .and_then(|limits| limits.get(&family))
        {
            return *limit;
        }
        send_max
    }

    /// Create the counter instance of each named peer's installed export
    /// chain (ADR-0136), compiling it if needed, at install rather than at
    /// the roster's publication or first evaluation. Policy replacements call this
    /// once membership has settled: a grouped member's per-peer chain has then
    /// been replaced by its group's already-counted handle, so a discarded
    /// chain is never compiled. Registration needs no call: its initial dump
    /// takes a counted `share()` of the installed chain, and group handles are
    /// always shares.
    fn create_installed_export_counters(&self, peers: impl IntoIterator<Item = PeerId>) {
        for peer in peers {
            if let Some(Some(chain)) = self.export_chains.get(&peer) {
                let _ = chain.hit_counters();
            }
        }
    }

    /// Publish the export roster if the installed export chains changed.
    /// Skipped while a clean transition is parked: its pre-commit phases
    /// change no committed chain, and its `CommitMembers` batches switch
    /// members that must publish together at the terminal batch.
    fn publish_export_roster(&mut self) {
        if self.pending_clean_policy_transition.is_none() {
            self.export_chains.publish_if_changed();
            #[cfg(test)]
            self.export_chains.assert_published();
        }
    }

    /// The export roster `GetPolicyStats` reads (ADR-0136). The cell closes
    /// when this manager is dropped.
    #[must_use]
    pub fn export_roster(&self) -> crate::export_roster::ExportRosterReader {
        self.export_chains.reader()
    }

    /// The daemon-wide ADR-0141 lease table. Injection services read and
    /// renew through it; the expiry task drives it with a RIB sender.
    #[must_use]
    pub fn injection_leases(&self) -> Arc<crate::injection_lease::InjectionLeases> {
        Arc::clone(&self.injection_leases)
    }

    /// Resolve the export policy for a peer: per-peer if set, else global.
    fn export_policy_for(&self, peer: PeerId) -> Option<&PolicyChain> {
        self.export_chains.for_peer(peer)
    }

    /// Clear all enhanced route refresh state for a peer.
    fn clear_peer_refresh_state(&mut self, peer: PeerId) {
        self.pending_refresh.remove(&peer);
        self.refresh_in_progress.remove(&peer);
        self.refresh_stale_routes.remove(&peer);
        self.refresh_stale_flowspec.remove(&peer);
        self.refresh_stale_evpn.remove(&peer);
        self.refresh_stale_bgpls.remove(&peer);
        self.refresh_stale_vpn.remove(&peer);
        self.refresh_stale_labeled.remove(&peer);
        self.refresh_stale_rtc.remove(&peer);
        self.refresh_stale_counts
            .retain(|(stale_peer, _, _), _| *stale_peer != peer);
        self.refresh_deadlines
            .retain(|(stale_peer, _, _)| *stale_peer != peer);
    }

    /// Advance one scope version without ever reusing a process-local value.
    /// Generation rollover increments the epoch; exhausting both words leaves
    /// the scope disabled so continuation fails closed.
    fn advance_route_page_version(version: &mut Option<RoutePageVersion>) {
        let Some(current) = version.as_mut() else {
            return;
        };
        if let Some(next) = current.generation.checked_add(1) {
            current.generation = next;
        } else if let Some(next_epoch) = current.epoch.checked_add(1) {
            current.epoch = next_epoch;
            current.generation = 0;
        } else {
            *version = None;
        }
    }

    fn advance_table_pages(&mut self) {
        Self::advance_route_page_version(&mut self.route_page_table_version);
        // A topology built under the old version can serve no further page.
        self.orr_page_topology = None;
    }

    pub(super) fn set_peer_group(&mut self, peer: PeerId, group: Option<String>) {
        let changed = match group {
            Some(group) => {
                self.peer_group.get(&peer) != Some(&group) && {
                    self.peer_group.insert(peer, group);
                    true
                }
            }
            None => self.peer_group.remove(&peer).is_some(),
        };
        if changed {
            self.advance_export_settings();
            Self::advance_route_page_version(&mut self.peer_group_version);
            // ADR-0137: a `condition_policy` reads the source peer's group.
            let _ = self.reobserve_conditional_advertisement_source(peer);
        }
    }

    /// Record a change to a peer's export settings for paged
    /// export-disposition walks ([`Self::export_settings_generation`]).
    pub(super) fn advance_export_settings(&mut self) {
        self.export_settings_generation = self.export_settings_generation.wrapping_add(1);
    }

    pub(super) fn advance_advertised_pages(&mut self) {
        Self::advance_route_page_version(&mut self.route_page_advertised_version);
    }

    fn advance_all_route_pages(&mut self) {
        self.advance_table_pages();
        self.advance_advertised_pages();
    }

    fn route_page_versions_snapshot(&self) -> [Option<RoutePageVersion>; 2] {
        [
            self.route_page_table_version,
            self.route_page_advertised_version,
        ]
    }

    fn ensure_advertised_pages_advanced(&mut self, snapshot: [Option<RoutePageVersion>; 2]) {
        // Cover untouched scopes; synchronous internal distribution passes remain uncoalesced.
        if self.route_page_advertised_version == snapshot[1] {
            self.advance_advertised_pages();
        }
    }

    fn ensure_all_route_pages_advanced(&mut self, snapshot: [Option<RoutePageVersion>; 2]) {
        if self.route_page_table_version == snapshot[0] {
            self.advance_table_pages();
        }
        self.ensure_advertised_pages_advanced(snapshot);
    }

    fn route_page_version(
        &self,
        scope: RouteQueryScope,
    ) -> Result<RoutePageVersion, RoutePageError> {
        let version = match scope {
            RouteQueryScope::Received { .. } | RouteQueryScope::Best => {
                self.route_page_table_version
            }
            RouteQueryScope::Advertised { .. } => self.route_page_advertised_version,
        };
        version.ok_or(RoutePageError::GenerationExhausted)
    }

    fn advance_route_pages_for_update(&mut self, update: &RibUpdate) {
        match update {
            // `ReplacePeerExportPolicies` stages a multi-iteration clean
            // transition whose `CommitMembers` flips group memberships and
            // export overlays. Advancing here at acceptance invalidates every
            // continuation from before the transaction; the terminal commit
            // advances again (`finish_clean_policy_transition_commit`) so a
            // page started between pre-commit polls, where general queries
            // are served from the pre-commit state, cannot continue across
            // the switch.
            RibUpdate::ReplacePeerExportPolicy { .. }
            | RibUpdate::ReplacePeerExportPolicies { .. }
            | RibUpdate::ReplacePeerExportPoliciesAuthoritatively { .. }
            | RibUpdate::RestorePeerExportPoliciesAuthoritatively { .. }
            | RibUpdate::ApplyOutboundPrefixLimits { .. }
            | RibUpdate::ReevaluatePeerExportPolicies { .. }
            | RibUpdate::InstallConditionalAdvertisements { .. }
            | RibUpdate::RestoreConditionalAdvertisements { .. }
            | RibUpdate::RefreshPeerOutbound { .. }
            | RibUpdate::ReplayPeerOutbound { .. } => self.advance_advertised_pages(),
            RibUpdate::PeerUp { .. }
            | RibUpdate::PeerDeleted { .. }
            | RibUpdate::RebindPeer { .. }
            | RibUpdate::InjectRoute { .. }
            | RibUpdate::InjectLeasedRoute { .. }
            | RibUpdate::WithdrawInjected { .. }
            | RibUpdate::ExpireInjectionLeases { .. }
            | RibUpdate::RpkiCacheUpdate { .. }
            | RibUpdate::AspaTableUpdate { .. } => self.advance_all_route_pages(),
            _ => {}
        }
    }

    /// Drain a bounded number of pending queries from the priority channel.
    fn drain_queries(&mut self, limit: usize) {
        self.drain_summary_queries();
        for _ in 0..limit {
            let Ok(query) = self.query_rx.try_recv() else {
                break;
            };
            self.serve_general_query(query);
        }
    }

    /// Serve one item received from the general query lane. Every delivery
    /// path (the bounded drains and both event-loop select arms) goes
    /// through here so the post-commit query trace is consumed by the
    /// first general query dispatched, whichever path delivers it.
    fn serve_general_query(&mut self, query: RibUpdate) {
        if let Some(trace) = self.post_commit_query_trace.take() {
            trace.emit("general");
        }
        self.handle_update(query);
    }

    /// Run one actor work unit, accounting its duration to the post-commit
    /// query trace while one is armed.
    fn traced<T>(&mut self, unit: PostCommitWork, work: impl FnOnce(&mut Self) -> T) -> T {
        if self.post_commit_query_trace.is_none() {
            return work(self);
        }
        let started = std::time::Instant::now();
        let out = work(self);
        if let Some(trace) = self.post_commit_query_trace.as_mut() {
            trace.record(unit, started.elapsed());
        }
        out
    }

    /// [`Self::process_next_route_chunk`] under the post-commit query trace:
    /// only a processed chunk counts, not the empty-queue probe.
    fn traced_route_chunk(&mut self) -> bool {
        if self.post_commit_query_trace.is_none() {
            return self.process_next_route_chunk();
        }
        let started = std::time::Instant::now();
        let processed = self.process_next_route_chunk();
        if processed && let Some(trace) = self.post_commit_query_trace.as_mut() {
            trace.record(PostCommitWork::RouteChunk, started.elapsed());
        }
        processed
    }

    /// Preserve the policy-transition ownership fence when a primary update
    /// acquires it: the post-update fairness drain must not admit general
    /// queries until that transition is terminal.
    fn drain_general_queries_if_unfenced(&mut self) {
        if self.pending_clean_policy_transition.is_none() {
            self.drain_queries(QUERY_BUDGET_PER_CHUNK);
        }
    }

    /// Serve one bounded general-query budget between two polls of an owned
    /// clean policy transition. Every pre-commit poll leaves committed
    /// membership, installed policy, counters, and wire state untouched, so
    /// the primary state at this seam is exactly the pre-commit generation
    /// and a read answered here is what the same read would have returned
    /// just before the transition was accepted. The query lane carries only
    /// reads by construction (mutations arrive on the primary channel, which
    /// stays fenced), so nothing served here can invalidate the parked
    /// phase. The commit phase keeps the fence: membership and counters
    /// move per batch there, and its terminal poll advances the advertised
    /// page generation before any read can observe the new state.
    fn drain_general_queries_between_transition_polls(&mut self) {
        let pre_commit = self
            .pending_clean_policy_transition
            .as_ref()
            .is_some_and(|pending| {
                !matches!(
                    pending.poll_kind(),
                    distribution::CleanPolicyTransitionPollKind::Commit
                )
            });
        if pre_commit {
            self.drain_queries(QUERY_BUDGET_PER_CHUNK);
        }
    }

    fn handle_readiness_query(
        &self,
        query: RibReadinessQuery,
        policy_transition_elapsed: Option<std::time::Duration>,
    ) {
        match query {
            RibReadinessQuery::LocRibCount { reply, enqueued } => {
                self.metrics
                    .observe_rib_readiness_query_wait("actor_loop", enqueued.elapsed());
                let result = match policy_transition_elapsed {
                    Some(elapsed) if elapsed >= MAX_HEALTHY_POLICY_TRANSITION_AGE => {
                        Err(RibReadinessError::PolicyTransitionStalled)
                    }
                    _ => Ok(self.loc_rib.len()),
                };
                let _ = reply.send(result);
            }
        }
    }

    /// Answer a readiness probe from the actor loop, then yield. The reply
    /// wakes the probe's task into this worker's LIFO slot, which other
    /// workers cannot steal. Without the yield that task waits until the actor
    /// next returns `Pending`; back-to-back queued updates (a mass GR entry)
    /// can defer that for Tokio's whole cooperative budget, about 200 ms at
    /// 200 peers.
    async fn serve_readiness_query(&mut self, query: RibReadinessQuery) {
        self.handle_readiness_query(query, None);
        tokio::task::yield_now().await;
    }

    /// Service a bounded number of type-narrow readiness probes at an actor
    /// seam without admitting any ordinary query or mutation.
    fn drain_readiness_queries(&mut self, policy_transition_elapsed: Option<std::time::Duration>) {
        for _ in 0..QUERY_BUDGET_PER_CHUNK {
            let query = match self.readiness_rx.as_mut() {
                Some(rx) => match rx.try_recv() {
                    Ok(query) => query,
                    Err(mpsc::error::TryRecvError::Empty) => break,
                    Err(mpsc::error::TryRecvError::Disconnected) => {
                        self.readiness_rx = None;
                        break;
                    }
                },
                None => break,
            };
            self.handle_readiness_query(query, policy_transition_elapsed);
        }
    }

    /// Publish the dirty-set size and the age of its oldest episode.
    /// `dirty_since` is stamped when a peer enters the set and outlives it,
    /// so only peers still dirty count.
    fn sample_outbound_dirty_gauges(&self) {
        let convergence = self.outbound_convergence();
        self.metrics.set_rib_outbound_dirty_peers(
            i64::try_from(convergence.pending_peers).unwrap_or(i64::MAX),
        );
        self.metrics.set_rib_outbound_dirty_oldest_seconds(
            i64::try_from(convergence.oldest_pending_secs).unwrap_or(i64::MAX),
        );
    }

    /// Publish the registration-wait gauges at most once per second, and only
    /// while a wait may exist: a steady state with every Established session
    /// registered costs nothing here.
    fn sample_outbound_registration_wait_if_due(&mut self) {
        if self
            .registration_wait_sample_at
            .is_some_and(|at| tokio::time::Instant::now() >= at)
        {
            self.sample_outbound_registration_wait();
        }
    }

    /// Count Established sessions whose newest live-session record is not
    /// the registered outbound session, and the age of the oldest such wait.
    /// Derived from the session records rather than the deferral queue, so a
    /// registration lost from the queue stays counted and keeps ageing.
    fn sample_outbound_registration_wait(&mut self) {
        let now = tokio::time::Instant::now();
        let mut pending = 0_usize;
        let mut oldest = 0_u64;
        for (peer, sessions) in &self.live_sessions {
            let Some(record) = sessions.last() else {
                continue;
            };
            if self.outbound_session_ids.get(peer) == Some(&record.session_id) {
                continue;
            }
            pending += 1;
            if let Some(since) = record.registration_wait_since {
                oldest = oldest.max(now.saturating_duration_since(since).as_secs());
            }
        }
        self.registration_wait_sample_at =
            (pending != 0).then(|| now + REGISTRATION_WAIT_SAMPLE_INTERVAL);
        self.metrics.set_rib_outbound_registration_pending(
            i64::try_from(pending).unwrap_or(i64::MAX),
            i64::try_from(oldest).unwrap_or(i64::MAX),
        );
    }

    fn outbound_convergence(&self) -> crate::update::OutboundConvergence {
        let now = tokio::time::Instant::now();
        crate::update::OutboundConvergence {
            pending_peers: self.dirty_peers.len(),
            oldest_pending_secs: self
                .dirty_peers
                .iter()
                .filter_map(|peer| self.dirty_since.get(peer))
                .map(|since| now.saturating_duration_since(*since).as_secs())
                .max()
                .unwrap_or(0),
        }
    }

    /// Whether the resync timer still has runnable work: failed outbound
    /// sends, deferred collision-failback inbound refreshes, or an ADR-0113
    /// capacity recovery that is not selection/ORF gated. Gate-blocked
    /// recovery remains queued without spinning the timer; the gate-release
    /// message makes it runnable and the next event loop turn arms this timer
    /// again.
    fn resync_tick_pending(&self) -> bool {
        self.dirty_peers.iter().any(|&peer| {
            self.replacement_checkpoint(false);
            !self.selection_partial_caught_up(peer)
        }) || !self.pending_inbound_refresh.is_empty()
            || (self.evpn_feed_receipt_count != 0
                && self.live_sessions.keys().any(|&peer| {
                    self.replacement_checkpoint(false);
                    self.evpn_marker_retry_runnable(peer)
                }))
            || self.pending_eor.keys().any(|&peer| {
                self.replacement_checkpoint(false);
                self.evpn_marker_retry_runnable(peer)
            })
            || self.outbound_limit_recovery_runnable()
    }

    /// Run one bounded resync-timer tick. ADR-0113 recovery replays at most
    /// one peer/family; dirty peers are handed to `distribute_changes` in
    /// one-peer slices until the poll's wall-clock budget elapses.
    /// Selection round-robins from
    /// [`Self::dirty_resync_cursor`] and never re-attempts a peer within the
    /// same tick.
    ///
    /// Returns `true` after a successful recovery slice or when dirty work
    /// was withheld without being attempted. The caller uses that result only
    /// when [`Self::resync_tick_pending`] still reports work, selecting the
    /// short backlog interval. A final successful recovery may therefore
    /// return `true` even though it drained the queue. `false` means no
    /// recovery slice completed and any still-dirty peers already failed this
    /// tick, so they wait for the ordinary retry interval.
    ///
    /// Safe to run partially: per-peer resync is idempotent — Adj-RIB-Out
    /// state and the dirty flag are committed/cleared only after a successful
    /// send, and withheld peers are not touched at all.
    fn resync_dirty_peers_bounded(&mut self) -> bool {
        // A whole member replay can outlive the tick's peer-stride budget.
        // Activate its existing interior checkpoints on every timer arm.
        with_executor_handoff(|| {
            self.with_replacement_readiness(Self::resync_dirty_peers_with_readiness)
        })
    }

    fn resync_dirty_peers_with_readiness(&mut self) -> bool {
        // Resync diffs against advertised state, and a due timer can fire
        // between the chunks of an open distribution window: settle it
        // (flush and exact-export retirement) before any recovery runs.
        self.settle_distribution_window();
        // ADR-0113 capacity recovery is family-scoped and already coalesced.
        // One live peer/family is replayed per timer tick; any runnable
        // remainder keeps `resync_tick_pending` true and re-arms the timer.
        let recovered = self.drain_outbound_limit_recovery();
        self.retry_pending_inbound_refresh_bounded();
        self.retry_evpn_feed_markers_bounded();
        // Peers whose outbound channel is gone can never resync: drop them
        // before selecting the slice, so a backlog of dead sessions (e.g.
        // after shutdown tore the TCP sessions down) quiesces in one cheap
        // tick — instead of burning an O(table) export pass per dead peer
        // and re-arming forever, starving the shutdown observation.
        let gone: Vec<PeerId> = self
            .dirty_peers
            .iter()
            .copied()
            .filter(|&peer| self.outbound_channel_gone(peer))
            .collect();
        for peer in gone {
            debug!(%peer, "dropping dirty peer whose outbound channel closed");
            self.drop_gone_dirty_peer(peer);
        }
        let poll_start = std::time::Instant::now();
        let mut attempted: HashSet<PeerId> = HashSet::new();
        loop {
            // One full-table member can consume the poll budget on its own.
            // Check after that real transaction completes so a healthy fleet
            // does not become one readiness owner older than the stall bound.
            // Cheap peers can still drain within the same poll budget.
            let ring: Vec<PeerId> = {
                let after = self
                    .dirty_peers
                    .iter()
                    .filter(|peer| match self.dirty_resync_cursor {
                        Some(cursor) => **peer > cursor,
                        None => true,
                    });
                let wrapped = self.dirty_peers.iter().filter(|peer| {
                    self.dirty_resync_cursor
                        .is_some_and(|cursor| **peer <= cursor)
                });
                after
                    .chain(wrapped)
                    .filter(|peer| {
                        !attempted.contains(*peer) && !self.selection_partial_caught_up(**peer)
                    })
                    .take(1)
                    .copied()
                    .collect()
            };
            let Some(&last) = ring.last() else {
                // Nothing unattempted remains: any peers still dirty failed
                // their send this tick and wait for the ordinary retry.
                return recovered;
            };
            self.dirty_resync_cursor = Some(last);
            attempted.extend(ring.iter().copied());
            let selected: BTreeSet<PeerId> = ring.into_iter().collect();
            let withheld: Vec<PeerId> = self.dirty_peers.difference(&selected).copied().collect();
            // A withheld peer re-marked during this pass continues its
            // episode; keep its original start time.
            let withheld_since: Vec<(PeerId, tokio::time::Instant)> = withheld
                .iter()
                .filter_map(|peer| self.dirty_since.get(peer).map(|since| (*peer, *since)))
                .collect();
            // A failed forced replay is also dirty. Its force bit must not
            // bypass this same peer slice; unrelated force-only work keeps
            // its existing path and scheduling.
            let withheld_force: Vec<PeerId> = withheld
                .iter()
                .copied()
                .filter(|peer| self.force_outbound_peers.remove(peer))
                .collect();
            self.dirty_peers = selected;
            self.distribute_changes(&HashSet::new(), &HashSet::new());
            self.dirty_peers.extend(withheld);
            self.dirty_since.extend(withheld_since);
            self.force_outbound_peers.extend(withheld_force);
            let unattempted_remain = self
                .dirty_peers
                .iter()
                .any(|peer| !attempted.contains(peer) && !self.selection_partial_caught_up(*peer));
            if !unattempted_remain {
                return recovered;
            }
            if poll_start.elapsed() >= self.flush_poll_budget {
                return true;
            }
        }
    }

    /// Complete one deferred outbound registration (LAN-475), targeting the
    /// peer's CURRENT last live session, plus the queued same-group joiners
    /// that share its initial replay (LAN-1826,
    /// `complete_deferred_registration`). Entries whose peer no longer has a
    /// live session (torn down while queued) or whose session already
    /// registered are discarded until one real registration completes (or
    /// the queue empties). A closed outbound channel does NOT skip the
    /// registration — the synchronous path never skipped it either; its
    /// sends fail harmlessly and the session's `PeerDown` cleans up.
    fn advance_pending_initial_registration(&mut self) {
        while let Some(peer) = self.pending_initial_registrations.pop_front() {
            let target = self
                .live_sessions
                .get(&peer)
                .and_then(|sessions| sessions.last())
                .map(|record| record.session_id);
            match target {
                Some(session_id) if self.outbound_session_ids.get(&peer) != Some(&session_id) => {
                    self.complete_deferred_registration(peer);
                    return;
                }
                _ => {
                    debug!(
                        %peer,
                        "dropping deferred outbound registration — session gone or already registered"
                    );
                }
            }
        }
    }

    async fn receive_readiness_query(
        readiness_rx: &mut Option<mpsc::Receiver<RibReadinessQuery>>,
    ) -> Option<RibReadinessQuery> {
        match readiness_rx {
            Some(rx) => rx.recv().await,
            None => std::future::pending().await,
        }
    }

    /// Record one real state-machine poll. Production yields immediately after
    /// each call; the benchmark driver invokes the same advance seam
    /// synchronously and records identical phase boundaries.
    pub(in crate::manager) fn record_policy_transition_poll(
        &mut self,
        kind: distribution::CleanPolicyTransitionPollKind,
        elapsed: std::time::Duration,
    ) {
        self.metrics
            .observe_rib_policy_transition_actor_poll(kind.as_str(), elapsed);
        #[cfg(any(test, feature = "bench-internals"))]
        {
            self.policy_transition_stats.actor_polls =
                self.policy_transition_stats.actor_polls.saturating_add(1);
            self.policy_transition_stats.max_actor_slice =
                self.policy_transition_stats.max_actor_slice.max(elapsed);
            match kind {
                distribution::CleanPolicyTransitionPollKind::PrefixSnapshot => {
                    self.policy_transition_stats.max_prefix_snapshot_poll = self
                        .policy_transition_stats
                        .max_prefix_snapshot_poll
                        .max(elapsed);
                }
                distribution::CleanPolicyTransitionPollKind::Finalize => {
                    self.policy_transition_stats.max_finalize_poll =
                        self.policy_transition_stats.max_finalize_poll.max(elapsed);
                }
                distribution::CleanPolicyTransitionPollKind::Commit => {
                    self.policy_transition_stats.max_commit_poll =
                        self.policy_transition_stats.max_commit_poll.max(elapsed);
                }
                distribution::CleanPolicyTransitionPollKind::Bounded => {}
            }
        }
    }

    fn finish_policy_transition_observability(
        &self,
        outcome: RibPolicyTransitionOutcome,
        member_count: usize,
        elapsed: std::time::Duration,
    ) {
        self.metrics.set_rib_policy_transition_in_progress(false);
        self.metrics
            .set_rib_policy_transition_last_duration(elapsed);
        self.metrics.record_rib_policy_transition_outcome(outcome);
        let elapsed_ms = u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX);
        info!(
            outcome = outcome.as_str(),
            member_count, elapsed_ms, "RIB export-policy transition completed"
        );
    }

    fn warn_if_policy_transition_slow(
        pending: &mut distribution::PendingCleanPolicyTransition,
        member_count: usize,
    ) {
        if let Some(elapsed) = pending.take_slow_warning(SLOW_POLICY_TRANSITION) {
            warn!(
                member_count,
                elapsed_ms = u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX),
                "RIB export-policy transition remains in progress"
            );
        }
    }

    /// The next queued primary update, the held lookahead first.
    fn try_recv_primary(&mut self) -> Option<RibUpdate> {
        let update = self
            .primary_lookahead
            .take()
            .or_else(|| self.rx.try_recv().ok());
        if update.is_some() {
            self.expiry_cutoffs.charge();
        }
        update
    }

    /// A due timer's admission cutoff is exhausted: coalescing paths must
    /// not admit further primary updates ahead of its expiry.
    fn expiry_cutoff_reached(&self) -> bool {
        self.expiry_cutoffs.any_exhausted()
    }

    /// Drain-first expiry for a due `timer`: run one admitted route chunk,
    /// or admit one queued update charged to the cutoffs, and return `true`
    /// so the caller re-enters the loop. Return `false`, clearing the
    /// cutoff, once only post-deadline work remains and the timer may fire.
    /// An admitted route batch always finishes first (its chunks and final
    /// distribution); batches come only from admitted updates, so this
    /// stays bounded.
    async fn drain_before_expiry(&mut self, timer: ExpiryTimer) -> bool {
        let remaining = self.expiry_cutoffs.remaining(timer);
        if (!self.pending_route_batches.is_empty() || remaining > 0)
            && self.drain_ready_updates().await
        {
            return true;
        }
        self.expiry_cutoffs.clear(timer);
        false
    }

    /// Cancel-safe receive of the next primary update, the held lookahead
    /// first: the lookahead is taken only by a poll that completes.
    async fn recv_primary(
        lookahead: &mut Option<RibUpdate>,
        rx: &mut mpsc::Receiver<RibUpdate>,
    ) -> Option<RibUpdate> {
        match lookahead.take() {
            Some(update) => Some(update),
            None => rx.recv().await,
        }
    }

    /// Queued primary updates, including the held lookahead.
    fn primary_backlog(&self) -> usize {
        self.rx.len() + usize::from(self.primary_lookahead.is_some())
    }

    /// Apply one queued actor unit before timer or idle-only work. Returning
    /// `true` keeps that work deferred until the primary backlog is empty.
    async fn drain_ready_updates(&mut self) -> bool {
        // Finish an older route batch before receiving its following EoR or
        // other primary message. Yielding between chunks preserves that FIFO
        // while giving operator reads and the executor their ordinary seam.
        if !self.traced_route_chunk() {
            let Some(update) = self.try_recv_primary() else {
                return false;
            };
            self.traced(PostCommitWork::PrimaryUpdate, |manager| {
                manager.handle_update(update);
            });
        }
        let transition_elapsed = self
            .pending_clean_policy_transition
            .as_ref()
            .map(distribution::PendingCleanPolicyTransition::elapsed);
        self.drain_readiness_queries(transition_elapsed);
        // A newly accepted cohort owns the next actor turn. Its own
        // between-poll seam decides when general queries can be served.
        self.drain_general_queries_if_unfenced();
        tokio::task::yield_now().await;
        true
    }

    /// Process a single `RibUpdate` message: one actor turn, timed by kind
    /// into `bgp_rib_actor_turn_duration_seconds`. Every message lane
    /// (primary, general and summary queries) dispatches through here, except
    /// summaries answered from a synchronous replacement's frozen projection.
    fn handle_update(&mut self, update: RibUpdate) {
        let turn = actor_turn::ActorTurn::new(&update, &self.ribs);
        let started = std::time::Instant::now();
        self.handle_update_untimed(update);
        self.finish_actor_turn(turn, started.elapsed());
    }

    /// Apply one message without turn timing.
    ///
    /// The typed-family receipts, `PeerUp` and the refresh boundaries change
    /// a peer's stale routes in this turn without publishing
    /// `bgp_gr_stale_routes` themselves, so the gauge is republished here
    /// when the count moved. Unicast, `FlowSpec` and EVPN receipts are
    /// queued and republish per chunk (`process_next_route_chunk`). GR
    /// entry, the timer sweeps, End-of-RIB and teardown publish at their
    /// own sites.
    fn handle_update_untimed(&mut self, update: RibUpdate) {
        if let Some(peer) = update.session_peer()
            && !peer.is_live()
        {
            debug!(
                %peer,
                "discarding a session message that names a deleted neighbor's handle"
            );
            return;
        }
        let receipt_peer = match &update {
            RibUpdate::BgpLsRoutesReceived { peer, .. }
            | RibUpdate::VpnRoutesReceived { peer, .. }
            | RibUpdate::LabeledRoutesReceived { peer, .. }
            | RibUpdate::RtcRoutesReceived { peer, .. }
            | RibUpdate::PeerUp { peer, .. }
            | RibUpdate::EndRouteRefresh { peer, .. }
            | RibUpdate::RouteRefreshTimeout { peer, .. } => Some(*peer),
            _ => None,
        };
        let before = receipt_peer.map(|peer| (peer, self.retained_stale_count(peer)));
        self.dispatch_update(update);
        if let Some((peer, before)) = before {
            self.republish_gr_stale_routes_if_moved(peer, before);
        }
        #[cfg(test)]
        self.assert_stale_counters_match_scan();
    }

    /// Test-only oracle: every Adj-RIB-In's maintained stale counters equal
    /// a full scan of its tables.
    #[cfg(test)]
    pub(super) fn assert_stale_counters_match_scan(&self) {
        for (peer, rib) in &self.ribs {
            assert_eq!(
                rib.maintained_stale_route_counts(),
                rib.scanned_stale_route_counts(),
                "maintained stale counters diverged from a scan for {peer}"
            );
        }
    }

    #[expect(
        clippy::too_many_lines,
        reason = "dispatcher needs one arm per RibUpdate variant"
    )]
    fn dispatch_update(&mut self, update: RibUpdate) {
        #[cfg(test)]
        if let Some(hook) = &self.test_primary_update_hook {
            hook(&update);
        }
        self.dampening_history.arm_owner_retirement();
        assert!(
            !(self.test_panic_on_peer_up.is_some() && matches!(&update, RibUpdate::PeerUp { .. })),
            "{TEST_PANIC_ON_PEER_UP_ENV} triggered before route-page generation advance"
        );
        self.advance_route_pages_for_update(&update);
        match update {
            RibUpdate::WireRoutesReceived(batch) => self.admit_received_batch(batch, true),
            batch @ RibUpdate::RoutesReceived { .. } => {
                self.admit_received_batch(crate::update::WireRoutesReceived::new(batch, 0), false);
            }
            RibUpdate::PublishDampeningOwners {
                publication,
                owners,
                reply,
            } => {
                let result = self.dampening_history.publish(publication, owners);
                let _ = reply.send(result);
            }
            RibUpdate::PrepareDampeningEnable {
                source,
                reason,
                reply,
            } => {
                let result = self.dampening_history.prepare_enable(&source, reason);
                let _ = reply.send(result);
            }
            RibUpdate::CompleteDampeningEnable {
                receipt,
                enabled,
                reply,
            } => {
                let result = self.dampening_history.complete_enable(receipt, enabled);
                let _ = reply.send(result);
            }
            RibUpdate::BgpLsRoutesReceived {
                peer,
                session_id,
                announced,
                withdrawn,
            } => {
                if !self.stale_session_message(peer, session_id, "BgpLsRoutesReceived", BgpLs) {
                    let announced = if self.dampening_session_blocked(peer, session_id) {
                        Vec::new()
                    } else {
                        announced
                    };
                    let retired = withdrawn
                        .iter()
                        .cloned()
                        .map(ExactExportKey::BgpLs)
                        .collect::<Vec<_>>();
                    self.handle_bgpls_routes_received(peer, announced, withdrawn);
                    self.retire_exact_export_rejections(retired);
                }
            }
            RibUpdate::VpnRoutesReceived {
                peer,
                session_id,
                announced,
                withdrawn,
            } => {
                if !self.stale_session_message(peer, session_id, "VpnRoutesReceived", Vpn) {
                    let announced = if self.dampening_session_blocked(peer, session_id) {
                        Vec::new()
                    } else {
                        announced
                    };
                    let retired = withdrawn
                        .iter()
                        .cloned()
                        .map(ExactExportKey::Vpn)
                        .collect::<Vec<_>>();
                    self.handle_vpn_routes_received(peer, announced, withdrawn);
                    self.retire_exact_export_rejections(retired);
                }
            }
            RibUpdate::LabeledRoutesReceived {
                peer,
                session_id,
                announced,
                withdrawn,
            } => {
                if !self.stale_session_message(peer, session_id, "LabeledRoutesReceived", Labeled) {
                    let announced = if self.dampening_session_blocked(peer, session_id) {
                        Vec::new()
                    } else {
                        announced
                    };
                    let retired = withdrawn
                        .iter()
                        .copied()
                        .map(ExactExportKey::Labeled)
                        .collect::<Vec<_>>();
                    self.handle_labeled_routes_received(peer, announced, withdrawn);
                    self.retire_exact_export_rejections(retired);
                }
            }
            RibUpdate::RtcRoutesReceived {
                peer,
                session_id,
                announced,
                withdrawn,
            } => {
                if !self.stale_session_message(peer, session_id, "RtcRoutesReceived", Rtc) {
                    let announced = if self.dampening_session_blocked(peer, session_id) {
                        Vec::new()
                    } else {
                        announced
                    };
                    let retired = withdrawn
                        .iter()
                        .cloned()
                        .map(ExactExportKey::Rtc)
                        .collect::<Vec<_>>();
                    self.handle_rtc_routes_received(peer, announced, withdrawn);
                    self.retire_exact_export_rejections(retired);
                }
            }
            RibUpdate::PeerDown { peer, session_id } => {
                let page_versions = self.route_page_versions_snapshot();
                match self.handle_peer_down(peer, session_id) {
                    SessionTeardownDisposition::DiscardStale => {}
                    SessionTeardownDisposition::FailOver => {
                        self.ensure_all_route_pages_advanced(page_versions);
                    }
                    SessionTeardownDisposition::NoRegistration
                    | SessionTeardownDisposition::TeardownActive => {
                        self.prune_exact_export_rejections();
                        self.ensure_all_route_pages_advanced(page_versions);
                    }
                }
            }
            RibUpdate::PeerDeleted {
                peer,
                label,
                keep_series,
            } => self.handle_peer_deleted(peer, label, keep_series),
            RibUpdate::RetireEorGraceInterface { interface } => {
                self.retire_eor_grace_interface(interface);
            }
            RibUpdate::ReleasePeer { peer } => {
                if !peer.release() {
                    debug!(%peer, "release of a handle that was not live");
                }
            }
            RibUpdate::RebindPeer { peer, endpoint } => self.handle_rebind_peer(peer, endpoint),
            RibUpdate::PeerUp {
                peer,
                session_id,
                peer_asn,
                peer_router_id,
                outbound_tx,
                export_policy,
                sendable_families,
                is_ebgp,
                route_reflector_client,
                orr_vantage,
                per_client_best,
                interpret_rfc1997,
                add_path_send_families,
                add_path_send_max,
                negotiated_orf_recv,
                negotiated_llgr_families,
            } => self.handle_peer_up(
                peer,
                PeerUpRegistration {
                    session_id,
                    peer_asn,
                    peer_router_id,
                    outbound_tx,
                    export_policy,
                    sendable_families,
                    is_ebgp,
                    route_reflector_client,
                    orr_vantage,
                    per_client_best,
                    interpret_rfc1997,
                    add_path_send_families,
                    add_path_send_max,
                    negotiated_orf_recv,
                    negotiated_llgr_families,
                },
            ),
            RibUpdate::PeerAddPathLimits {
                peer,
                session_id,
                limits,
            } => {
                // Transport emits this once per session from the immutable
                // OPEN negotiation, immediately after PeerUp. Idempotency
                // suppresses duplicate delivery; this is not a runtime cap
                // reconfiguration surface (a decrease requires a new session
                // so excess advertised path IDs are withdrawn by teardown).
                let Some(send_families) = self
                    .newest_live_session_mut(peer, session_id)
                    .map(|record| record.add_path_send_families.clone())
                else {
                    return;
                };
                let mut rejected_families = Vec::new();
                let new_limits: HashMap<_, _> = limits
                    .into_iter()
                    .filter(|(family, _)| {
                        let accepted = send_families.contains(family);
                        if !accepted {
                            rejected_families.push(*family);
                        }
                        accepted
                    })
                    .collect();
                if !rejected_families.is_empty() {
                    rejected_families.sort_by_key(|(afi, safi)| (*afi as u16, *safi as u8));
                    rejected_families.dedup();
                    warn!(
                        %peer,
                        ?rejected_families,
                        "ignoring Paths-Limit entries outside the negotiated Add-Path send families"
                    );
                }
                // Stage the immutable negotiated map before registration. A
                // deferred initial dump installs this record later; a stale
                // superseded session cannot mutate the newest record.
                self.newest_live_session_mut(peer, session_id)
                    .expect("newest live session checked above")
                    .add_path_send_limits
                    .clone_from(&new_limits);

                if self.outbound_session_ids.get(&peer).copied() == Some(session_id) {
                    let page_versions = self.route_page_versions_snapshot();
                    let scalar_limit = self.peer_add_path_send_max.get(&peer).copied().unwrap_or(0);
                    let effective_limit_changed = self
                        .peer_add_path_send_families
                        .get(&peer)
                        .is_some_and(|families| {
                            families.iter().any(|family| {
                                let old = self
                                    .peer_add_path_send_limits
                                    .get(&peer)
                                    .and_then(|limits| limits.get(family))
                                    .copied()
                                    .unwrap_or(scalar_limit);
                                let new = new_limits.get(family).copied().unwrap_or(scalar_limit);
                                old != new
                            })
                        });
                    self.peer_add_path_send_limits.insert(peer, new_limits);
                    if effective_limit_changed {
                        self.advance_export_settings();
                        self.send_initial_table(peer);
                    }
                    self.ensure_advertised_pages_advanced(page_versions);
                }
            }
            RibUpdate::PeerOrfUpdate {
                peer,
                session_id,
                afi,
                safi,
                when,
                entries,
                reply,
            } => {
                if self.stale_session_message(peer, session_id, "PeerOrfUpdate", Orf) {
                    let _ = reply.send(Err(format!(
                        "stale ORF update from superseded session {session_id} discarded"
                    )));
                } else {
                    self.advance_advertised_pages();
                    self.handle_peer_orf_update(peer, afi, safi, when, &entries, reply);
                }
            }
            RibUpdate::PeerSlowState {
                peer,
                session_id,
                slow,
            } => {
                if !self.stale_session_message(peer, session_id, "PeerSlowState", Kind::SlowPeer) {
                    self.advance_advertised_pages();
                    self.handle_peer_slow_state(peer, slow);
                }
            }
            RibUpdate::PeerFamilySendable {
                peer,
                session_id,
                family,
                add_path_send_limit,
            } => self.handle_peer_family_sendable(peer, session_id, family, add_path_send_limit),
            RibUpdate::SetPeerSessionExportPolicy {
                peer,
                session_id,
                export_policy,
            } => {
                if let Some(record) = self.live_sessions.get_mut(&peer).and_then(|sessions| {
                    sessions
                        .iter_mut()
                        .find(|record| record.session_id == session_id)
                }) {
                    record.export_policy = export_policy;
                }
            }
            RibUpdate::SetPeerPolicyContext {
                peer,
                session_id,
                peer_group,
            } => {
                let current = self
                    .live_sessions
                    .get(&peer)
                    .and_then(|sessions| sessions.last())
                    .is_some_and(|record| record.session_id == session_id);
                if let Some(record) = self.live_sessions.get_mut(&peer).and_then(|sessions| {
                    sessions
                        .iter_mut()
                        .find(|record| record.session_id == session_id)
                }) {
                    // A displaced live session retains updates for failback,
                    // but only the current session publishes installed identity.
                    record.peer_group.clone_from(&peer_group);
                    if current {
                        self.advance_advertised_pages();
                        self.handle_set_peer_policy_context(peer, peer_group);
                    }
                } else {
                    // Establishment sends this before PeerUp, while an older
                    // registration may still be active. Do not apply its stale
                    // data-message gate or mutate that registration's identity.
                    self.pending_peer_policy_context
                        .insert((peer, session_id), peer_group);
                }
            }
            RibUpdate::SetPeerSourceContext {
                peer,
                session_id,
                context,
            } => {
                self.pending_peer_source_context
                    .insert((peer, session_id), context);
            }
            RibUpdate::SetPeerWithheldFamilies {
                peer,
                session_id,
                families,
            } => {
                self.pending_peer_withheld_families
                    .insert((peer, session_id), families);
            }
            RibUpdate::SetPeerExportContext {
                peer,
                session_id,
                local_role,
            } => {
                // This context intentionally precedes `PeerUp` so the initial
                // table build cannot race RFC 9234 enforcement. Key by session
                // id because collision-window senders can interleave.
                self.pending_peer_export_context
                    .insert((peer, session_id), local_role);
            }
            RibUpdate::SetPeerRsControl {
                peer,
                session_id,
                rs_control_asn,
            } => {
                // Staged before `PeerUp` like the role context above so the
                // initial table build already honors control communities;
                // keyed by session id against collision-window interleaving.
                self.pending_peer_rs_control
                    .insert((peer, session_id), rs_control_asn);
            }
            RibUpdate::SetPeerExportPolicyCounters {
                peer,
                session_id,
                counters,
            } => {
                self.pending_peer_export_counters
                    .insert((peer, session_id), counters);
            }
            RibUpdate::SetPeerExportEncoder {
                peer,
                session_id,
                encoder,
            } => {
                // Like the role context above, this is deliberately staged
                // before PeerUp. Collision-window senders can interleave, so
                // only the matching session consumes the handle.
                self.pending_peer_export_encoders
                    .insert((peer, session_id), encoder);
            }
            RibUpdate::SetPeerGracefulRestartContext {
                peer,
                session_id,
                peer_restart_state,
                peer_gr_helper,
                peer_gr_families,
                peer_enhanced_refresh,
                peer_llgr_families,
                local_llgr_stale_time,
            } => {
                self.pending_peer_gr_context.insert(
                    (peer, session_id),
                    PeerSelectionDeferralContext {
                        peer_restart_state,
                        peer_gr_helper,
                        peer_gr_families,
                        peer_enhanced_refresh,
                        peer_llgr_families,
                        local_llgr_stale_time,
                    },
                );
            }
            RibUpdate::InjectRoute { route, reply } => {
                self.with_selection_readiness(|manager| manager.handle_inject_route(route, reply));
            }
            RibUpdate::InjectLeasedRoute {
                route,
                owner,
                lease_seconds,
                reply,
            } => {
                self.with_selection_readiness(|manager| {
                    manager.handle_inject_leased_route(route, &owner, lease_seconds, reply);
                });
            }
            RibUpdate::WithdrawInjected {
                prefix,
                path_id,
                allow_missing,
                owner,
                override_owner,
                reply,
            } => {
                self.with_selection_readiness(|manager| {
                    manager.handle_withdraw_injected(
                        prefix,
                        path_id,
                        allow_missing,
                        &owner,
                        override_owner,
                        reply,
                    );
                    manager
                        .retire_exact_export_rejections([ExactExportKey::Unicast(prefix, path_id)]);
                });
            }
            RibUpdate::ExpireInjectionLeases { leases } => {
                self.handle_expire_injection_leases(&leases);
            }
            RibUpdate::QueryRoutesPage {
                scope,
                filter,
                after,
                expected_version,
                page_size,
                reply,
            } => {
                self.handle_query_routes_page_versioned(
                    scope,
                    filter.as_ref(),
                    after,
                    expected_version,
                    page_size,
                    reply,
                );
            }
            RibUpdate::QueryBestRoutes { deadline, reply } => {
                self.handle_query_best_routes(deadline, reply);
            }
            RibUpdate::QueryBestRoutesPage {
                after,
                deadline,
                reply,
            } => self.handle_query_best_routes_page(after, deadline, reply),
            RibUpdate::QueryFibInstallCandidates {
                max_paths,
                relax,
                weighted,
                deadline,
                reply,
            } => {
                self.handle_query_fib_install_candidates(
                    max_paths, relax, weighted, deadline, reply,
                );
            }
            RibUpdate::QueryFibInstallCandidatesPage {
                after,
                max_paths,
                relax,
                weighted,
                deadline,
                reply,
            } => self.handle_query_fib_install_candidates_page(
                after, max_paths, relax, weighted, deadline, reply,
            ),
            RibUpdate::QueryDataplaneVersions { deadline, reply } => {
                self.handle_query_dataplane_versions(deadline, reply);
            }
            RibUpdate::QueryPeerGroupsVersioned { deadline, reply } => {
                self.handle_query_peer_groups_versioned(deadline, reply);
            }
            RibUpdate::QueryBestRoutesExact {
                prefixes,
                deadline,
                reply,
            } => {
                self.handle_query_best_routes_exact(prefixes, deadline, reply);
            }
            RibUpdate::QueryFibInstallCandidatesExact {
                prefixes,
                max_paths,
                relax,
                weighted,
                deadline,
                reply,
            } => self.handle_query_fib_install_candidates_exact(
                prefixes, max_paths, relax, weighted, deadline, reply,
            ),
            RibUpdate::QueryPeerGroups { reply } => self.handle_query_peer_groups(reply),
            RibUpdate::QueryInstalledExportChain { peer, reply } => {
                let installed = self.outbound_peers.contains_key(&peer).then(|| {
                    crate::update::InstalledExportChain {
                        chain: self
                            .export_policy_for(peer)
                            .map(PolicyChain::compiled_shared),
                        peer_interface: self.session_peer_scope(peer).peer_interface(),
                    }
                });
                if reply.send(installed).is_err() {
                    warn!("query caller dropped before receiving installed export chain");
                }
            }
            RibUpdate::ExplainBestPath {
                prefix,
                peer,
                reply,
            } => {
                self.handle_explain_best_path(prefix, peer, reply);
            }
            RibUpdate::LookupBestPath { prefix, reply } => {
                self.handle_lookup_best_path(prefix, reply);
            }
            RibUpdate::ExplainAdvertisedRoute {
                peer,
                prefix,
                rd,
                labeled,
                source,
                reply,
            } => self.handle_explain_advertised_route(peer, prefix, rd, labeled, source, reply),
            RibUpdate::QueryLeasedKeys {
                owner,
                resume,
                page_size,
                reply,
            } => {
                let page = self.leased_keys_page(&owner, resume.as_ref(), page_size);
                if reply.send(page).is_err() {
                    warn!("query caller dropped before receiving response");
                }
            }
            RibUpdate::MarkReplayComplete {
                owner,
                incarnation,
                reply,
            } => {
                let result = self.mark_replay_complete(&owner, incarnation);
                if reply.send(result).is_err() {
                    warn!("replay-complete caller dropped before receiving response");
                }
            }
            RibUpdate::QueryLocalRouteExport {
                keys,
                managed,
                resume,
                page_size,
                reply,
            } => self.handle_query_local_route_export(&keys, managed, resume, page_size, reply),
            RibUpdate::QueryLocalFlowSpecExport {
                key,
                managed,
                resume,
                page_size,
                reply,
            } => self.handle_query_local_flowspec_export(&key, managed, resume, page_size, reply),
            RibUpdate::SubscribeRouteEvents { reply } => {
                self.handle_subscribe_route_events(reply);
            }
            RibUpdate::SubscribeFibCandidateChanges { reply } => {
                let _ = reply.send(self.fib_candidate_changes_tx.subscribe());
            }
            RibUpdate::QueryRouteEventHistory {
                peer,
                peer_interface,
                afi,
                prefix,
                limit,
                reply,
            } => {
                let peer = peer.map(|peer| (peer, peer_interface.as_deref()));
                self.handle_query_route_event_history(peer, afi, prefix, limit, reply);
            }
            RibUpdate::SubscribeEvpnRouteEvents { reply } => {
                self.handle_subscribe_evpn_route_events(reply);
            }
            RibUpdate::QueryEvpnRouteEventHistory {
                peer,
                peer_interface,
                route_type,
                rd,
                event_types,
                limit,
                reply,
            } => {
                self.handle_query_evpn_route_event_history(
                    peer.map(|peer| (peer, peer_interface.as_deref())),
                    route_type,
                    rd,
                    &event_types,
                    limit,
                    reply,
                );
            }
            RibUpdate::QueryLocRibCount { reply } => self.handle_query_loc_rib_count(reply),
            RibUpdate::QueryBmpPeerStats { reply } => {
                self.handle_query_bmp_peer_stats(reply);
            }
            RibUpdate::QueryAdvertisedCount { peer, reply } => {
                self.handle_query_advertised_count(peer, reply);
            }
            RibUpdate::QueryPeerRetainedStale { peer, reply } => {
                self.handle_query_peer_retained_stale(peer, reply);
            }
            RibUpdate::QueryPeerRetention { peer, reply } => {
                self.handle_query_peer_retention(peer, reply);
            }
            RibUpdate::QueryNeighborPolicyStats { peer, reply } => {
                self.handle_query_neighbor_policy_stats(peer, reply);
            }
            RibUpdate::QueryPeerUpdateGroup { peer, reply } => {
                self.handle_query_peer_update_group(peer, reply);
            }
            RibUpdate::QueryPeerOutboundState { peer, reply } => {
                self.handle_query_peer_outbound_state(peer, reply);
            }
            RibUpdate::QueryNeighborRibSnapshots {
                peers,
                comparison,
                include_retained,
                reply,
            } => {
                self.handle_query_neighbor_rib_snapshots(
                    peers,
                    comparison,
                    include_retained,
                    reply,
                );
            }
            RibUpdate::QueryOutboundConvergence { reply } => {
                let _ = reply.send(self.outbound_convergence());
            }
            RibUpdate::QueryUpdateGroupSnapshot { reply } => {
                self.handle_query_update_group_snapshot(reply);
            }
            RibUpdate::QueryUpdateGroupComparison {
                primary,
                comparison,
                reply,
            } => {
                self.handle_query_update_group_comparison(primary, comparison, reply);
            }
            #[cfg(test)]
            RibUpdate::TestQueryVpnAdvertised { peer, reply } => {
                self.handle_test_query_vpn_advertised(peer, reply);
            }
            #[cfg(any(test, feature = "bench-internals"))]
            RibUpdate::TestQueryOutboundHealth { reply } => {
                let group_dirty = self
                    .group_ribs
                    .values()
                    .map(|group| group.dirty_members.len())
                    .sum();
                let group_tombstones = self
                    .group_ribs
                    .values()
                    .map(|group| group.tombstones.len() + group.vpn_tombstones.len())
                    .sum();
                let _ = reply.send((
                    self.dirty_peers.len(),
                    self.force_outbound_peers.len(),
                    group_dirty,
                    group_tombstones,
                    self.pending_regroup_baseline.len(),
                    self.pending_extra_withdraws.len(),
                ));
            }
            #[cfg(feature = "bench-internals")]
            RibUpdate::BenchVpnAdmissionWithCredit {
                grants,
                update,
                reply,
            } => {
                let result = (|| {
                    if !matches!(&*update, RibUpdate::VpnRoutesReceived { .. }) {
                        return Err(crate::update::RibCommandError::internal(
                            "benchmark credit requires a VPN receipt",
                        ));
                    }
                    for (grant, acknowledged) in grants {
                        grant.send(()).map_err(|()| {
                            crate::update::RibCommandError::internal("benchmark receiver closed")
                        })?;
                        // Benchmark consumers run on a separate runtime. This bounded
                        // one-shot wait prevents a retry timer stealing the granted credit.
                        acknowledged
                            .lock()
                            .map_err(|error| {
                                crate::update::RibCommandError::internal(error.to_string())
                            })?
                            .recv_timeout(std::time::Duration::from_secs(30))
                            .map_err(|error| {
                                crate::update::RibCommandError::internal(error.to_string())
                            })?
                            .map_err(crate::update::RibCommandError::internal)?;
                    }
                    self.handle_update(*update);
                    Ok(())
                })();
                let _ = reply.send(result);
            }
            #[cfg(test)]
            RibUpdate::TestQueryPeerOutboundDirty { peer, reply } => {
                let _ = reply.send(self.dirty_peers.contains(&peer));
            }
            #[cfg(test)]
            RibUpdate::TestQueryPolicyTransitionStats { reply } => {
                let stats = self.policy_transition_stats;
                let _ = reply.send((
                    stats.plan_builds,
                    stats.full_exact_probes,
                    stats.route_shell_materializations,
                    stats.max_actor_slice.as_nanos(),
                    stats.actor_polls,
                ));
            }
            #[cfg(test)]
            RibUpdate::TestQueryUncommittedPolicyTransitionGroups { reply } => {
                let count = self
                    .group_ribs
                    .values()
                    .filter(|group| group.members.is_empty())
                    .count();
                let _ = reply.send(count);
            }
            RibUpdate::PrepareOutboundPrefixLimits { txn, config, reply } => {
                self.handle_prepare_outbound_prefix_limits(txn, config, reply);
            }
            RibUpdate::ApplyOutboundPrefixLimits {
                txn,
                activate,
                reply,
            } => self.handle_apply_outbound_prefix_limits(txn, activate, reply),
            RibUpdate::ReplacePeerExportPolicy {
                peer,
                export_policy,
                reply,
            } => self.handle_replace_peer_export_policy(peer, export_policy, reply),
            RibUpdate::ReplacePeerExportPolicies {
                replacements,
                reply,
            } => self.handle_replace_peer_export_policies(replacements, reply),
            RibUpdate::ReplacePeerExportPoliciesAuthoritatively {
                replacements,
                reply,
            } => self.handle_replace_peer_export_policies_authoritatively(replacements, reply),
            RibUpdate::RestorePeerExportPoliciesAuthoritatively {
                replacements,
                reply,
            } => self.handle_restore_peer_export_policies_authoritatively(replacements, reply),
            RibUpdate::PrepareExportPolicyDestination {
                peer,
                export_policy,
                reply,
            } => self.begin_destination_prestage(peer, export_policy.as_ref(), reply),
            RibUpdate::DiscardPreparedExportPolicyDestination { .. } => {
                self.discard_prepared_export_destination();
            }
            RibUpdate::ReplayPeerOutbound {
                peer,
                session_id,
                families,
                replay,
                reply,
            } => {
                let result = self.handle_replay_peer_outbound(peer, session_id, families, &replay);
                if result.is_err() {
                    replay.cancel();
                }
                if reply.send(result).is_err() {
                    replay.cancel();
                }
            }
            RibUpdate::RefreshPeerOutbound { peer, reply } => {
                self.handle_refresh_peer_outbound(peer, reply);
            }
            RibUpdate::ConfirmPeerOutbound {
                peer,
                session_id,
                reply,
            } => {
                let result = if !self.outbound_peers.contains_key(&peer) {
                    Err(crate::RibCommandError::not_found(format!(
                        "peer {peer} not registered for outbound updates"
                    )))
                } else if self.outbound_session_ids.get(&peer) == Some(&session_id)
                    && self
                        .peer_sendable_families
                        .get(&peer)
                        .is_some_and(|families| families.contains(&(Afi::Ipv6, Safi::Unicast)))
                {
                    Ok(())
                } else {
                    Err(crate::RibCommandError::internal(format!(
                        "peer {peer} session {session_id} has no outbound IPv6 unlock"
                    )))
                };
                let _ = reply.send(result);
            }
            RibUpdate::ReevaluatePeerExportPolicies {
                peers,
                swaps,
                reply,
            } => {
                self.handle_reevaluate_peer_export_policies(&peers, swaps.as_deref(), reply);
            }
            RibUpdate::InstallConditionalAdvertisements {
                set,
                swapping_datasets,
                reply,
            } => {
                let _ = reply
                    .send(self.handle_install_conditional_advertisements(set, &swapping_datasets));
            }
            RibUpdate::RestoreConditionalAdvertisements { capture, reply } => {
                self.handle_restore_conditional_advertisements(capture);
                let _ = reply.send(());
            }
            RibUpdate::ReobserveConditionalAdvertisements {
                datasets,
                changed,
                reply,
            } => {
                let _ = reply.send(
                    self.handle_reobserve_conditional_advertisement_datasets(&datasets, &changed),
                );
            }
            RibUpdate::EndOfRib {
                peer,
                session_id,
                afi,
                safi,
            } => {
                if !self.stale_session_message(peer, session_id, "EndOfRib", Eor) {
                    self.advance_all_route_pages();
                    let selection_transition =
                        self.selection_deferral_end_of_rib(peer, session_id, (afi, safi));
                    self.handle_end_of_rib(peer, afi, safi);
                    if (afi, safi) == (Afi::L2Vpn, Safi::Evpn)
                        && let Some(record) =
                            self.live_sessions.get_mut(&peer).and_then(|sessions| {
                                sessions.iter_mut().find(|s| s.session_id == session_id)
                            })
                    {
                        record.evpn_end_of_rib = true;
                    }
                    if let Some(transition) = selection_transition {
                        self.apply_selection_deferral_transitions(
                            [transition],
                            "all current-session End-of-RIB markers received",
                        );
                    }
                    if (afi, safi) == crate::route::RtcRibRouteKey::afi_safi() {
                        // Membership is complete: every RTC UPDATE before
                        // this marker has been applied and its VPN/EVPN
                        // corrective emit queued (or left to the dirty
                        // resync, which flushes after the replay). Runs
                        // after the selection transition above, which is
                        // what rebuilds membership while RTC selection was
                        // deferred.
                        self.rtc_membership_complete(peer);
                    }
                }
            }
            RibUpdate::RouteRefreshRequest {
                peer,
                session_id,
                afi,
                safi,
                queued,
            } => {
                // Release before the replay reads the Loc-RIB: a refresh the
                // peer sends from here on needs (and gets) its own replay.
                queued.store(false, std::sync::atomic::Ordering::Release);
                if !self.stale_session_message(peer, session_id, "RouteRefreshRequest", Refresh) {
                    self.advance_advertised_pages();
                    self.handle_route_refresh_request(peer, afi, safi);
                }
            }
            RibUpdate::BeginRouteRefresh {
                peer,
                session_id,
                afi,
                safi,
            } => {
                if !self.stale_session_message(peer, session_id, "BeginRouteRefresh", Refresh) {
                    self.advance_all_route_pages();
                    self.handle_begin_route_refresh(peer, afi, safi);
                    if let Some(transition) =
                        self.selection_deferral_begin_route_refresh(peer, session_id, (afi, safi))
                    {
                        self.apply_selection_deferral_transitions(
                            [transition],
                            "collision-failback refresh began",
                        );
                    }
                }
            }
            RibUpdate::EndRouteRefresh {
                peer,
                session_id,
                afi,
                safi,
            } => {
                if !self.stale_session_message(peer, session_id, "EndRouteRefresh", Refresh) {
                    // A collision-failback survivor already sent its EoR;
                    // its refreshed membership ends with the EoRR that
                    // closes an active RTC refresh window. A stray or
                    // duplicate EoRR (ignored below) proves nothing.
                    let rtc_refresh_completed = (afi, safi)
                        == crate::route::RtcRibRouteKey::afi_safi()
                        && self
                            .refresh_in_progress
                            .get(&peer)
                            .is_some_and(|families| families.contains(&(afi, safi)));
                    self.handle_end_route_refresh(peer, afi, safi);
                    if let Some(transition) =
                        self.selection_deferral_end_route_refresh(peer, session_id, (afi, safi))
                    {
                        self.apply_selection_deferral_transitions(
                            [transition],
                            "collision-failback survivor refresh completed",
                        );
                    }
                    // After the transition, as on the EoR path.
                    if rtc_refresh_completed {
                        self.rtc_membership_complete(peer);
                    }
                }
            }
            RibUpdate::RouteRefreshTimeout {
                peer,
                session_id,
                afi,
                safi,
            } => {
                if !self.stale_session_message(peer, session_id, "RouteRefreshTimeout", Refresh) {
                    self.finish_route_refresh(peer, afi, safi, true);
                }
            }
            RibUpdate::PeerGracefulRestart {
                peer,
                session_id,
                restart_time,
                stale_routes_time,
                gr_families,
                peer_llgr_capable,
                peer_llgr_families,
                llgr_stale_time,
            } => {
                let page_versions = self.route_page_versions_snapshot();
                if self.handle_peer_graceful_restart(
                    peer,
                    session_id,
                    restart_time,
                    stale_routes_time,
                    gr_families,
                    peer_llgr_capable,
                    peer_llgr_families,
                    llgr_stale_time,
                ) {
                    self.ensure_all_route_pages_advanced(page_versions);
                }
            }
            RibUpdate::RpkiCacheUpdate { table, delta } => {
                self.handle_rpki_cache_update(table, delta);
            }
            RibUpdate::AspaTableUpdate {
                table,
                changed_customer_asns,
            } => {
                self.handle_aspa_cache_update(table, changed_customer_asns);
            }
            RibUpdate::InjectFlowSpec { route, reply } => self.handle_inject_flowspec(route, reply),
            RibUpdate::InjectLeasedFlowSpec {
                route,
                owner,
                lease_seconds,
                reply,
            } => self.handle_inject_leased_flowspec(route, &owner, lease_seconds, reply),
            RibUpdate::InjectGuardedFlowSpec {
                route,
                owner,
                lease_seconds,
                fence,
                reply,
            } => self.handle_inject_guarded_flowspec(route, &owner, lease_seconds, fence, reply),
            RibUpdate::WithdrawFlowSpec {
                key,
                allow_missing,
                owner,
                override_owner,
                reply,
            } => {
                let retired = ExactExportKey::FlowSpec(key.clone());
                self.handle_withdraw_flowspec(
                    key,
                    allow_missing,
                    &owner,
                    override_owner,
                    None,
                    reply,
                );
                self.retire_exact_export_rejections([retired]);
            }
            RibUpdate::WithdrawGuardedFlowSpec {
                key,
                owner,
                revision,
                reply,
            } => {
                let retired = ExactExportKey::FlowSpec(key.clone());
                let owner = crate::injection_lease::guarded_owner(&owner);
                self.handle_withdraw_flowspec(key, true, &owner, false, Some(revision), reply);
                self.retire_exact_export_rejections([retired]);
            }
            RibUpdate::InjectEvpn { route, reply } => self.handle_inject_evpn(route, reply),
            RibUpdate::WithdrawEvpn { key, reply } => {
                self.handle_withdraw_evpn(key, reply);
                self.retire_exact_export_rejections([ExactExportKey::Evpn(key)]);
            }
            RibUpdate::QueryFlowSpecRoutes { filter, reply } => {
                queries::send_filtered_rows(self.loc_rib.iter_flowspec(), filter.as_ref(), reply);
            }
            RibUpdate::QueryAdvertisedFlowSpecRoutes {
                peer,
                filter,
                reply,
            } => {
                if let Some(rows) =
                    self.collect_advertised_flowspec(peer, filter.as_ref(), || reply.is_closed())
                {
                    let _ = reply.send(rows);
                }
            }
            RibUpdate::QueryReceivedFlowSpecRoutes {
                peer,
                filter,
                reply,
            } => {
                self.send_received_flowspec(peer, filter.as_ref(), reply);
            }
            RibUpdate::ExplainEvpnRoute {
                key,
                received_from,
                advertised_to,
                srv6_argument_companion,
                reply,
            } => {
                if !reply.is_closed() {
                    let _ = reply.send(self.explain_evpn_route(
                        key,
                        received_from,
                        advertised_to,
                        srv6_argument_companion,
                    ));
                }
            }
            RibUpdate::QueryEvpnRoutes { filter, reply } => {
                queries::send_filtered_rows(self.loc_rib.iter_evpn(), filter.as_ref(), reply);
            }
            RibUpdate::QueryEvpnSessionsSynced { reply } => {
                let _ = reply.send(self.evpn_sessions_sync());
            }
            RibUpdate::QueryEvpnEsSnapshot { reply } => {
                if !reply.is_closed() {
                    let _ = reply.send(crate::update::EvpnEsSnapshot {
                        sessions: self.evpn_sessions_sync(),
                        es_routes: self.loc_rib.iter_evpn_es().cloned().collect(),
                    });
                }
            }
            RibUpdate::QueryEvpnRoutesPage {
                scope,
                filter,
                after,
                expected_version,
                page_size,
                reply,
            } => self.handle_query_evpn_routes_page(
                scope,
                filter.as_ref(),
                after,
                expected_version,
                page_size,
                reply,
            ),
            RibUpdate::QueryVpnRoutesPage {
                scope,
                filter,
                after,
                expected_version,
                page_size,
                reply,
            } => self.handle_query_vpn_routes_page(
                scope,
                filter.as_ref(),
                after,
                expected_version,
                page_size,
                reply,
            ),
            RibUpdate::QueryLabeledRoutesPage {
                scope,
                filter,
                after,
                expected_version,
                page_size,
                reply,
            } => self.handle_query_labeled_routes_page(
                scope,
                filter.as_ref(),
                after,
                expected_version,
                page_size,
                reply,
            ),
            RibUpdate::QueryBgpLsRoutesPage {
                scope,
                filter,
                after,
                expected_version,
                page_size,
                reply,
            } => self.handle_query_bgpls_routes_page(
                scope,
                filter.as_ref(),
                after,
                expected_version,
                page_size,
                reply,
            ),
            RibUpdate::QueryRtcRoutesPage {
                scope,
                filter,
                after,
                expected_version,
                page_size,
                reply,
            } => self.handle_query_rtc_routes_page(
                scope,
                filter.as_ref(),
                after,
                expected_version,
                page_size,
                reply,
            ),
            RibUpdate::QueryEvpnDataplaneRoutes {
                known_generation,
                reply,
            } => {
                if reply.is_closed() {
                    debug!("EVPN dataplane route query canceled before materialization");
                    return;
                }
                #[cfg(test)]
                if known_generation != Some(self.evpn_dataplane_generation) {
                    self.evpn_dataplane_query_row_visits = self
                        .evpn_dataplane_query_row_visits
                        .saturating_add(self.loc_rib.evpn_len());
                }
                let routes = collect_evpn_dataplane_routes(
                    self.loc_rib.iter_evpn(),
                    known_generation,
                    self.evpn_dataplane_generation,
                    self.loc_rib.evpn_len(),
                    self.evpn_dataplane_route_count,
                );
                let _ = reply.send(crate::update::EvpnDataplaneRoutesResponse {
                    generation: self.evpn_dataplane_generation,
                    routes,
                });
            }
            RibUpdate::QueryBgpLsRoutes { filter, reply } => {
                queries::send_filtered_rows(self.loc_rib.iter_bgpls(), filter.as_ref(), reply);
            }
            RibUpdate::QueryLabeledRoutes { filter, reply } => {
                queries::send_filtered_rows(self.loc_rib.iter_labeled(), filter.as_ref(), reply);
            }
            RibUpdate::QueryVpnRoutes { filter, reply } => {
                if reply.is_closed() {
                    debug!("VPN route listing canceled before materialization");
                    return;
                }
                #[cfg(feature = "bench-internals")]
                let started = std::time::Instant::now();
                let routes = queries::filter_rows(self.loc_rib.iter_vpn(), filter.as_ref());
                #[cfg(feature = "bench-internals")]
                let (rows, capacity) = (routes.len(), routes.capacity());
                // The handler duration must be captured BEFORE the reply is
                // sent: once the reply lands, the service task can finish the
                // whole RPC while this thread is preempted, and a
                // capture-after-send handler time can exceed the caller's
                // wall-clock measurement (the vpn_query bench subtracts the
                // two and relies on strict nesting).
                #[cfg(feature = "bench-internals")]
                let handler_ns = u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX);
                let _ = reply.send(routes);
                #[cfg(feature = "bench-internals")]
                if let Some(receipts) = &self.vpn_query_bench_receipts {
                    self.vpn_query_bench_dispatches =
                        self.vpn_query_bench_dispatches.saturating_add(1);
                    let _ = receipts.try_send((
                        handler_ns,
                        rows,
                        capacity,
                        self.vpn_query_bench_dispatches,
                    ));
                }
            }
            RibUpdate::QueryRtcRoutes { filter, reply } => {
                queries::send_filtered_rows(self.loc_rib.iter_rtc(), filter.as_ref(), reply);
            }
            RibUpdate::QueryOrrTopology { reply } => {
                // With vantages configured the cached topology is fresh
                // by construction (rebuilt at every BGP-LS mutation
                // seam); without them the cache is intentionally empty,
                // so build on demand as before.
                let snapshot = if self.peer_orr_vantage.is_empty() {
                    self.build_orr_topology().snapshot()
                } else {
                    self.orr.topology.snapshot()
                };
                let _ = reply.send(snapshot);
            }
            RibUpdate::QueryOrrTopologyNodesPage {
                after,
                expected_version,
                page_size,
                reply,
            } => self.handle_query_orr_nodes_page(after, expected_version, page_size, reply),
            RibUpdate::QueryOrrTopologyLinksPage {
                after,
                expected_version,
                page_size,
                reply,
            } => self.handle_query_orr_links_page(after, expected_version, page_size, reply),
            RibUpdate::QueryOrrStatus { reply } => self.handle_query_orr_status(reply),
            RibUpdate::QueryConditionalAdvertisements { reply } => {
                let _ = reply.send(self.conditional_advertisement_status());
            }
            RibUpdate::QueryMrtSnapshot { reply } => self.handle_query_mrt_snapshot(reply),
            RibUpdate::QueryWarmMrtSnapshot {
                views,
                budget,
                reply,
            } => {
                self.handle_query_warm_mrt_snapshot(&views, &budget, reply);
            }
            RibUpdate::QueryBmpLocRibDump {
                cursor,
                started_at,
                reply,
            } => {
                self.handle_query_bmp_loc_rib_dump(cursor, started_at, reply);
            }
            RibUpdate::QueryBmpLocRibStats { reply } => {
                self.handle_query_bmp_loc_rib_stats(reply);
            }
        }
    }

    /// Remove sparse rejection-overlay keys whose NLRI identity no longer
    /// exists in any Adj-RIB-In. This full live-set rebuild is reserved for
    /// infrequent bulk lifecycle sweeps; the UPDATE hot path uses targeted
    /// withdrawal cleanup instead.
    fn prune_exact_export_rejections(&mut self) {
        #[cfg(test)]
        {
            self.test_exact_export_full_prune_calls += 1;
        }
        if self.peer_unexportable.is_empty() {
            return;
        }
        let live = self.live_exact_export_nlri();
        self.peer_unexportable.retain(|_, rejected| {
            rejected.retain(|key| live.contains(&key.nlri_identity()));
            !rejected.is_empty()
        });
    }

    fn live_exact_export_nlri(&self) -> HashSet<ExactExportKey> {
        self.ribs
            .values()
            .flat_map(|rib| {
                rib.iter()
                    // Invariant: unicast is keyed at path_id 0 here because
                    // lookups go through ExactExportKey::nlri_identity()
                    // (crates/rib/src/update.rs), which normalizes the
                    // unicast Add-Path rank to 0. Changing either side's
                    // keying requires changing the other.
                    .map(|route| ExactExportKey::Unicast(route.prefix, 0))
                    .chain(
                        rib.iter_flowspec()
                            .map(|route| ExactExportKey::FlowSpec(route.selection_key())),
                    )
                    .chain(
                        rib.iter_evpn()
                            .map(|route| ExactExportKey::Evpn(route.key())),
                    )
                    .chain(
                        rib.iter_bgpls()
                            .map(|route| ExactExportKey::BgpLs(route.key()).nlri_identity()),
                    )
                    .chain(
                        rib.iter_vpn()
                            .map(|route| ExactExportKey::Vpn(route.key()).nlri_identity()),
                    )
                    .chain(
                        rib.iter_labeled()
                            .map(|route| ExactExportKey::Labeled(route.key()).nlri_identity()),
                    )
                    .chain(
                        rib.iter_rtc()
                            .map(|route| ExactExportKey::Rtc(route.key()).nlri_identity()),
                    )
            })
            .collect()
    }

    fn exact_export_nlri_is_live(
        &self,
        key: &ExactExportKey,
        checkpoint: &mut impl FnMut(),
    ) -> bool {
        match key {
            ExactExportKey::Unicast(prefix, _) => self
                .unicast_prefix_peers
                .peers(prefix)
                .inspect(|_| checkpoint())
                .any(|peer| {
                    self.ribs
                        .get(&peer)
                        .is_some_and(|rib| rib.iter_prefix(prefix).next().is_some())
                }),
            ExactExportKey::FlowSpec(key) => self.ribs.values().any(|rib| {
                checkpoint();
                rib.iter_flowspec()
                    .inspect(|_| checkpoint())
                    .any(|route| route.selection_key() == *key)
            }),
            ExactExportKey::Evpn(key) => self
                .ribs
                .values()
                .inspect(|_| checkpoint())
                .any(|rib| rib.get_evpn(key).is_some()),
            ExactExportKey::BgpLs(key) => self.ribs.values().any(|rib| {
                checkpoint();
                rib.iter_bgpls().inspect(|_| checkpoint()).any(|route| {
                    ExactExportKey::BgpLs(route.key()).nlri_identity()
                        == ExactExportKey::BgpLs(key.clone()).nlri_identity()
                })
            }),
            ExactExportKey::Vpn(key) => self
                .ribs
                .values()
                .inspect(|_| checkpoint())
                .any(|rib| rib.iter_vpn_for_nlri(&key.nlri_key).next().is_some()),
            ExactExportKey::Labeled(key) => self
                .ribs
                .values()
                .inspect(|_| checkpoint())
                .any(|rib| rib.iter_labeled_for_prefix(&key.prefix).next().is_some()),
            ExactExportKey::Rtc(key) => self.ribs.values().any(|rib| {
                checkpoint();
                rib.iter_rtc().inspect(|_| checkpoint()).any(|route| {
                    ExactExportKey::Rtc(route.key()).nlri_identity()
                        == ExactExportKey::Rtc(key.clone()).nlri_identity()
                })
            }),
        }
    }

    /// Retire withdrawn overlay identities after distribution had the first
    /// chance to suppress a rejected-only wire withdrawal. A surviving source
    /// path keeps the overlay; the distribution pass has already refreshed its
    /// exact accept/reject state.
    fn retire_exact_export_rejections(
        &mut self,
        withdrawn: impl IntoIterator<Item = ExactExportKey>,
    ) {
        if self.peer_unexportable.is_empty() {
            return;
        }
        let readiness = self.replacement_readiness.clone();
        let mut checkpoint = || {
            replacement_readiness_checkpoint_at(&readiness, "exact_rejection_retirement", false);
        };
        let mut withdrawn = withdrawn
            .into_iter()
            .map(|key| {
                checkpoint();
                key.nlri_identity()
            })
            .collect::<HashSet<_>>();
        if withdrawn.is_empty() {
            return;
        }
        let mut rejected_withdrawn = HashSet::new();
        for rejected in self.peer_unexportable.values() {
            checkpoint();
            for key in rejected {
                checkpoint();
                let identity = key.nlri_identity();
                if withdrawn.contains(&identity) {
                    rejected_withdrawn.insert(identity);
                }
            }
        }
        if rejected_withdrawn.is_empty() {
            retire_hash_set(&mut withdrawn, &mut checkpoint);
            retire_hash_set(&mut rejected_withdrawn, &mut checkpoint);
            return;
        }
        let mut live = rejected_withdrawn
            .iter()
            .filter(|key| {
                checkpoint();
                self.exact_export_nlri_is_live(key, &mut checkpoint)
            })
            .cloned()
            .collect::<HashSet<_>>();
        self.peer_unexportable.retain(|_, rejected| {
            checkpoint();
            rejected.retain(|key| {
                checkpoint();
                let identity = key.nlri_identity();
                !rejected_withdrawn.contains(&identity) || live.contains(&identity)
            });
            !rejected.is_empty()
        });
        retire_hash_set(&mut live, &mut checkpoint);
        retire_hash_set(&mut rejected_withdrawn, &mut checkpoint);
        retire_hash_set(&mut withdrawn, &mut checkpoint);
    }

    /// Interned scope of the active session registered at `peer`, from the
    /// accepted source context it staged. It resolves to that interface for
    /// a scoped (IPv6 link-local) neighbor and to none for numbered
    /// neighbors, an active session without one, and peers without a live
    /// session.
    pub(super) fn session_peer_scope(&self, peer: PeerId) -> crate::route::AspaContextId {
        // The active registration is the newest live record (see
        // `register_active_session`); a collision loser's scope never counts.
        self.live_sessions
            .get(&peer)
            .and_then(|records| records.last())
            .map_or(crate::route::AspaContextId::DEFAULT, |record| {
                record.peer_scope
            })
    }

    fn publish_route_event(&mut self, mut event: RouteEvent) {
        event.event_id = self.next_route_event_id;
        if let Some(next) = self.next_route_event_id.checked_add(1) {
            self.next_route_event_id = next;
        } else if !self.route_event_id_exhausted {
            self.route_event_id_exhausted = true;
            warn!(
                event_id = self.next_route_event_id,
                "route event id space exhausted; publishing future route events with \
                 the saturated id instead of panicking"
            );
        }
        if self.route_event_history.len() == ROUTE_EVENT_HISTORY_CAPACITY {
            self.route_event_history.pop_front();
        }
        let event = Arc::new(event);
        self.route_event_history.push_back(Arc::clone(&event));
        self.metrics.set_route_event_history_depth(
            i64::try_from(self.route_event_history.len()).unwrap_or(i64::MAX),
        );
        let _ = self.route_events_tx.send(event);
    }

    #[expect(
        clippy::too_many_lines,
        reason = "prefix-scoped rejection mutation and transition event publication share one commit"
    )]
    pub(super) fn update_policy_filtered_routes_for_prefixes(
        &mut self,
        target_peer: PeerId,
        prefixes: &HashSet<Prefix>,
        current: &HashSet<PolicyFilteredRouteKey>,
    ) {
        if current.is_empty() && !self.policy_filtered_routes.contains_key(&target_peer) {
            return;
        }
        let readiness = &self.replacement_readiness;
        let checkpoint = || replacement_readiness_checkpoint(readiness, false);
        let allocation_checkpoint = || replacement_readiness_checkpoint(readiness, true);
        let retained_checkpoint = || {
            #[cfg(test)]
            replacement_readiness_checkpoint_at(readiness, "policy_filtered_retained", false);
            #[cfg(not(test))]
            checkpoint();
        };
        let peer_routes = self.policy_filtered_routes.entry(target_peer).or_default();
        let refresh = |keys: &mut PolicyFilteredBucket| {
            keys.retain(
                |key| {
                    retained_checkpoint();
                    current.contains(key)
                },
                &allocation_checkpoint,
            )
        };
        // Walk whichever side is smaller: a clean transition passes the
        // whole table as scope for every member, while the history usually
        // holds a few prefixes.
        if prefixes.len() <= peer_routes.len() {
            for prefix in prefixes {
                retained_checkpoint();
                if peer_routes
                    .get_mut(prefix)
                    .is_some_and(|keys| !refresh(keys))
                {
                    allocation_checkpoint();
                    drop(peer_routes.remove(prefix));
                    allocation_checkpoint();
                }
            }
        } else {
            peer_routes.retain(|prefix, keys| {
                retained_checkpoint();
                !prefixes.contains(prefix) || refresh(keys)
            });
        }
        allocation_checkpoint();
        let mut incoming: Vec<_> = current.iter().inspect(|_| checkpoint()).copied().collect();
        allocation_checkpoint();
        incoming.sort_unstable_by(|left, right| {
            checkpoint();
            left.prefix.cmp(&right.prefix)
        });
        allocation_checkpoint();
        let mut newly_filtered = Vec::with_capacity(incoming.len());
        allocation_checkpoint();
        for group in incoming.chunk_by(|left, right| {
            checkpoint();
            left.prefix == right.prefix
        }) {
            retained_checkpoint();
            match peer_routes.entry(group[0].prefix) {
                std::collections::btree_map::Entry::Vacant(slot) if group.len() == 1 => {
                    checkpoint();
                    slot.insert(PolicyFilteredBucket::One(group[0]));
                    newly_filtered.push(group[0]);
                }
                entry => entry
                    .or_insert_with(|| PolicyFilteredBucket::Many(HashSet::new()))
                    .insert_group(
                        group,
                        &mut newly_filtered,
                        &checkpoint,
                        &allocation_checkpoint,
                    ),
            }
        }
        retire_vec(&mut incoming, &mut || checkpoint());
        if peer_routes.is_empty() {
            allocation_checkpoint();
            self.policy_filtered_routes.remove(&target_peer);
            allocation_checkpoint();
        }
        let mut newly_filtered = newly_filtered.into_iter();
        // Resolved only when an event is published.
        let target_peer_scope = if newly_filtered.as_slice().is_empty() {
            crate::route::AspaContextId::DEFAULT
        } else {
            self.session_peer_scope(target_peer)
        };
        for key in newly_filtered.by_ref() {
            self.replacement_checkpoint(false);
            let peer_scope = self
                .ribs
                .get(&key.source_peer)
                .and_then(|rib| rib.get(&key.prefix, key.path_id))
                .map_or(crate::route::AspaContextId::DEFAULT, |route| {
                    route.aspa_context
                });
            self.publish_route_event(RouteEvent {
                event_id: 0,
                event_type: RouteEventType::PolicyFiltered,
                prefix: key.prefix,
                peer: Some(key.source_peer.addr()),
                previous_peer: None,
                target_peer: Some(key.target_peer.addr()),
                peer_scope,
                previous_peer_scope: crate::route::AspaContextId::DEFAULT,
                target_peer_scope,
                timestamp_unix_ms: crate::event::unix_time_ms_now(),
                path_id: key.path_id,
                reason: "policy_denied".to_string(),
            });
        }
        self.replacement_checkpoint(true);
        drop(newly_filtered);
        self.replacement_checkpoint(true);
    }

    pub(super) fn clear_policy_filtered_routes_for_peer(&mut self, target_peer: PeerId) {
        if !self.policy_filtered_routes.contains_key(&target_peer) {
            return;
        }
        with_executor_handoff(|| {
            self.with_replacement_readiness(|manager| {
                if let Some(mut routes) = manager.policy_filtered_routes.remove(&target_peer) {
                    while let Some((_, keys)) = routes.pop_first() {
                        manager.replacement_checkpoint_at("policy_filtered_history_cleanup", false);
                        if let PolicyFilteredBucket::Many(mut keys) = keys {
                            retire_hash_set(&mut keys, &mut || {
                                manager.replacement_checkpoint_at(
                                    "policy_filtered_history_cleanup",
                                    false,
                                );
                            });
                        }
                    }
                    manager.replacement_checkpoint_at("policy_filtered_history_cleanup", true);
                    drop(routes);
                    manager.replacement_checkpoint_at("policy_filtered_history_cleanup", true);
                }
            });
        });
    }

    fn publish_evpn_route_event(&mut self, event: crate::event::EvpnRouteEvent) {
        if self.evpn_route_event_history.len() == EVPN_ROUTE_EVENT_HISTORY_CAPACITY {
            self.evpn_route_event_history.pop_front();
        }
        let event = Arc::new(event);
        self.evpn_route_event_history.push_back(Arc::clone(&event));
        let _ = self.evpn_events_tx.send(event);
    }

    fn handle_bgpls_routes_received(
        &mut self,
        peer: PeerId,
        announced: Vec<crate::route::BgpLsRibRoute>,
        withdrawn: Vec<crate::route::BgpLsRouteKey>,
    ) {
        let active_refresh = self
            .refresh_in_progress
            .get(&peer)
            .cloned()
            .unwrap_or_default();
        let mut affected: HashSet<crate::route::BgpLsRouteKey> = HashSet::new();
        let mut removed_stale_counts: HashMap<(Afi, Safi), usize> = HashMap::new();
        let mut needs_intern_gc = false;

        {
            let rib = self.ribs.entry(peer).or_insert_with(|| AdjRibIn::new(peer));
            for key in withdrawn {
                let family = key.family.to_afi_safi();
                if rib.withdraw_bgpls(&key) {
                    needs_intern_gc = true;
                    affected.insert(key.clone());
                }
                if active_refresh.contains(&family)
                    && let Some(stale) = self.refresh_stale_bgpls.get_mut(&peer)
                    && stale.remove(&key).is_some()
                {
                    *removed_stale_counts.entry(family).or_default() += 1;
                }
            }

            for mut route in announced {
                let key = route.key();
                let family = route.family.to_afi_safi();
                self.attr_intern.intern(&mut route.attributes);
                needs_intern_gc |= rib.insert_bgpls(route);
                affected.insert(key.clone());
                if active_refresh.contains(&family)
                    && let Some(stale) = self.refresh_stale_bgpls.get_mut(&peer)
                    && stale.remove(&key).is_some()
                {
                    *removed_stale_counts.entry(family).or_default() += 1;
                }
            }
        }

        for ((afi, safi), count) in removed_stale_counts {
            self.decrement_refresh_stale_count(peer, afi, safi, count);
        }
        self.update_peer_refresh_metrics(peer);
        self.recompute_bgpls_keys(&affected);
        if !affected.is_empty() {
            if needs_intern_gc {
                self.attr_intern.gc();
            }
            self.sync_attr_intern_gauge();
        }
    }

    fn handle_vpn_routes_received(
        &mut self,
        peer: PeerId,
        announced: Vec<crate::route::VpnRibRoute>,
        withdrawn: Vec<crate::route::VpnRibRouteKey>,
    ) {
        let active_refresh = self
            .refresh_in_progress
            .get(&peer)
            .cloned()
            .unwrap_or_default();
        let mut affected: HashSet<crate::route::VpnRibRouteKey> = HashSet::new();
        let mut removed_stale_counts: HashMap<(Afi, Safi), usize> = HashMap::new();
        let mut needs_intern_gc = false;

        {
            let rib = self.ribs.entry(peer).or_insert_with(|| AdjRibIn::new(peer));
            for key in withdrawn {
                let family = key.afi_safi();
                if rib.withdraw_vpn(&key) {
                    needs_intern_gc = true;
                    affected.insert(key.clone());
                }
                if active_refresh.contains(&family)
                    && let Some(stale) = self.refresh_stale_vpn.get_mut(&peer)
                    && stale.remove(&key).is_some()
                {
                    *removed_stale_counts.entry(family).or_default() += 1;
                }
            }

            for mut route in announced {
                let key = route.key();
                let family = route.afi_safi();
                self.attr_intern.intern(&mut route.attributes);
                needs_intern_gc |= rib.insert_vpn(route);
                affected.insert(key.clone());
                if active_refresh.contains(&family)
                    && let Some(stale) = self.refresh_stale_vpn.get_mut(&peer)
                    && stale.remove(&key).is_some()
                {
                    *removed_stale_counts.entry(family).or_default() += 1;
                }
            }
        }

        for ((afi, safi), count) in removed_stale_counts {
            self.decrement_refresh_stale_count(peer, afi, safi, count);
        }
        self.update_peer_refresh_metrics(peer);
        self.recompute_vpn_keys(&affected);
        if !affected.is_empty() {
            if needs_intern_gc {
                self.attr_intern.gc();
            }
            self.sync_attr_intern_gauge();
        }
    }

    /// Recompute the Loc-RIB VPN selection for each affected key across the
    /// current set of peer Adj-RIB-Ins, then distribute the changes to
    /// eligible peers. Shared by the receive path, peer teardown, and the
    /// GR-entry conservative withdraw so a departed peer's routes fall back
    /// to the next-best candidate (or are withdrawn downstream), mirroring
    /// the unicast/FlowSpec/EVPN/BGP-LS recompute + distribution pattern.
    fn recompute_vpn_keys(&mut self, affected: &HashSet<crate::route::VpnRibRouteKey>) {
        self.recompute_and_distribute_vpn(affected);
    }

    fn handle_labeled_routes_received(
        &mut self,
        peer: PeerId,
        announced: Vec<crate::route::LabeledRibRoute>,
        withdrawn: Vec<crate::route::LabeledRibRouteKey>,
    ) {
        let active_refresh = self
            .refresh_in_progress
            .get(&peer)
            .cloned()
            .unwrap_or_default();
        let mut affected: HashSet<crate::route::LabeledRibRouteKey> = HashSet::new();
        let mut removed_stale_counts: HashMap<(Afi, Safi), usize> = HashMap::new();
        let mut needs_intern_gc = false;

        {
            let rib = self.ribs.entry(peer).or_insert_with(|| AdjRibIn::new(peer));
            for key in withdrawn {
                let family = key.afi_safi();
                if rib.withdraw_labeled(&key) {
                    needs_intern_gc = true;
                    affected.insert(key);
                }
                if active_refresh.contains(&family)
                    && let Some(stale) = self.refresh_stale_labeled.get_mut(&peer)
                    && stale.remove(&key).is_some()
                {
                    *removed_stale_counts.entry(family).or_default() += 1;
                }
            }

            for mut route in announced {
                let key = route.key();
                let family = route.afi_safi();
                self.attr_intern.intern(&mut route.attributes);
                needs_intern_gc |= rib.insert_labeled(route);
                affected.insert(key);
                if active_refresh.contains(&family)
                    && let Some(stale) = self.refresh_stale_labeled.get_mut(&peer)
                    && stale.remove(&key).is_some()
                {
                    *removed_stale_counts.entry(family).or_default() += 1;
                }
            }
        }

        for ((afi, safi), count) in removed_stale_counts {
            self.decrement_refresh_stale_count(peer, afi, safi, count);
        }
        self.update_peer_refresh_metrics(peer);
        self.recompute_labeled_keys(&affected);
        if !affected.is_empty() {
            if needs_intern_gc {
                self.attr_intern.gc();
            }
            self.sync_attr_intern_gauge();
        }
    }

    /// Recompute the Loc-RIB labeled selection for each affected key across
    /// the current set of peer Adj-RIB-Ins, then distribute the changes to
    /// eligible peers, mirroring [`Self::recompute_vpn_keys`].
    fn recompute_labeled_keys(&mut self, affected: &HashSet<crate::route::LabeledRibRouteKey>) {
        self.recompute_and_distribute_labeled(affected);
    }

    /// RT-Constrain ingest (RFC 4684). Mirrors the VPN receive path; after
    /// the Adj-RIB-In mutation the peer's RT membership is rebuilt so the
    /// VPNv4/VPNv6 Adj-RIB-Out restages under the new filter.
    fn handle_rtc_routes_received(
        &mut self,
        peer: PeerId,
        announced: Vec<crate::route::RtcRibRoute>,
        withdrawn: Vec<crate::route::RtcRibRouteKey>,
    ) {
        let family = crate::route::RtcRibRouteKey::afi_safi();
        let active_refresh = self
            .refresh_in_progress
            .get(&peer)
            .is_some_and(|families| families.contains(&family));
        let mut affected: HashSet<crate::route::RtcRibRouteKey> = HashSet::new();
        let mut removed_stale = 0usize;
        let mut needs_intern_gc = false;

        {
            let rib = self.ribs.entry(peer).or_insert_with(|| AdjRibIn::new(peer));
            for key in withdrawn {
                if rib.withdraw_rtc(&key) {
                    needs_intern_gc = true;
                    affected.insert(key.clone());
                }
                if active_refresh
                    && let Some(stale) = self.refresh_stale_rtc.get_mut(&peer)
                    && stale.remove(&key).is_some()
                {
                    removed_stale += 1;
                }
            }
            for mut route in announced {
                let key = route.key();
                self.attr_intern.intern(&mut route.attributes);
                needs_intern_gc |= rib.insert_rtc(route);
                if active_refresh
                    && let Some(stale) = self.refresh_stale_rtc.get_mut(&peer)
                    && stale.remove(&key).is_some()
                {
                    removed_stale += 1;
                }
                affected.insert(key);
            }
        }

        self.decrement_refresh_stale_count(peer, family.0, family.1, removed_stale);
        self.update_peer_refresh_metrics(peer);
        self.recompute_rtc_keys(&affected);
        if !affected.is_empty() {
            if needs_intern_gc {
                self.attr_intern.gc();
            }
            self.sync_attr_intern_gauge();
        }
        if !self.selection_deferred(family) {
            self.rebuild_rtc_membership_and_restage_vpn(peer);
        }
    }

    /// Rebuild `peer`'s RT-Constrain membership from its Adj-RIB-In (all
    /// paths) and route the result through [`Self::set_rt_membership`] —
    /// the corrective emit (grouped delta walk or per-peer restage) fires
    /// there iff the membership actually changed.
    fn rebuild_rtc_membership_and_restage_vpn(&mut self, peer: PeerId) {
        let membership = self.rtc_membership_from_rib(peer);
        self.set_rt_membership(peer, Some(membership));
    }

    /// THE single Φ-write function (design §2.3 / risk 1): EVERY mutation
    /// of `peer_rt_membership` routes through here, so a membership
    /// change can never be split from its corrective emit. Sites:
    ///
    /// - `rebuild_rtc_membership_and_restage_vpn` (RTC routes received,
    ///   RFC 7313 stale sweeps, GR/LLGR sweeps) → `Some(derived)`;
    /// - `register_active_session` at `PeerUp` → `Some` (empty-strict,
    ///   or GR-re-derived) / `None` (family not negotiated) — both run
    ///   BEFORE the outbound registration, so no corrective emit fires
    ///   and the Φ-filtered initial-dump replay covers delivery;
    /// - `clear_outbound_peer_state` teardown → `None` (the outbound
    ///   registration is going away; nothing to correct).
    ///
    /// Corrective emit for a changed Φ on a live registration: a member
    /// of a VPN-staging group takes the membership-delta table walk
    /// (zero policy evals, table untouched — design §2.3); everyone else
    /// keeps the per-peer dirty restage (the Adj-RIB-Out equality
    /// machinery yields the RFC 4684 minimal update set, no session
    /// reset). An unchanged membership is a strict no-op.
    fn set_rt_membership(&mut self, peer: PeerId, membership: Option<RtcMembership>) {
        // Removing Φ is valid only before outbound registration (a new
        // session that did not negotiate RTC) or after deregistration during
        // teardown. On a live registration it would silently change the peer
        // from RT-filtered to unfiltered without a corrective VPN emission.
        // Keep this before the equality early-return so an already-absent
        // entry cannot conceal an invalid live call.
        debug_assert!(
            membership.is_some() || !self.outbound_peers.contains_key(&peer),
            "RT membership may be cleared only before outbound registration or after deregistration"
        );
        // Capture BEFORE the write (design §2.3): under the invariant
        // adv(m) = Φ-filtered group table, `old` is the true prior
        // advertised state.
        let old = self.peer_rt_membership.get(&peer).cloned();
        if old == membership {
            return;
        }
        // Grouped VPN pages read the current membership even when emission defers.
        self.advance_advertised_pages();
        let Some(new) = membership else {
            self.peer_rt_membership.remove(&peer);
            return;
        };
        let captured_prior =
            self.vpn_grouped_member_of(peer).is_some() && self.capture_group_admitted_keys(peer);
        self.peer_rt_membership.insert(peer, new.clone());
        if !self.outbound_peers.contains_key(&peer) {
            return;
        }
        if let Some(gid) = self.vpn_grouped_member_of(peer) {
            // Absent prior membership on a live RTC registration
            // resolves to strict empty — the `rtc_export_filter` rule.
            let old = old.unwrap_or_default();
            self.apply_rtc_membership_delta_to_grouped_member(peer, gid, &old, &new);
            // Negotiated RTC excludes EVPN group ownership even when UC/VPN
            // remain grouped, so this VPN delta walk does not cover EVPN:
            // restage its private view under the new Φ. Future grouped RTC
            // needs OLD Φ capture before publication and separate qualification.
            // A dirty peer's pending resync already does. A dormant startup
            // can have advertised rows before the first waiter arms; release
            // restages that frozen private inventory under the current Φ.
            let evpn_deferred = self.selection_deferred((Afi::L2Vpn, Safi::Evpn));
            if !self.dirty_peers.contains(&peer) && !evpn_deferred {
                let readiness = self.replacement_readiness.clone();
                let mut checkpoint = || {
                    replacement_readiness_checkpoint_at(&readiness, "selection_evpn", false);
                };
                let mut keys: HashSet<rustbgpd_wire::EvpnRouteKey> = self
                    .loc_rib
                    .iter_evpn()
                    .inspect(|_| checkpoint())
                    .map(crate::route::EvpnRibRoute::key)
                    .collect();
                if let Some(rib_out) = self.adj_ribs_out.get(&peer) {
                    keys.extend(
                        rib_out
                            .iter_evpn()
                            .inspect(|_| checkpoint())
                            .map(crate::route::EvpnRibRoute::key),
                    );
                }
                self.distribute_evpn_keys_to_peer(peer, &keys, &mut checkpoint);
                retire_hash_set(&mut keys, &mut checkpoint);
            }
        } else {
            self.mark_outbound_dirty(peer);
            self.distribute_changes(&HashSet::new(), &HashSet::new());
        }
        if captured_prior
            && !self.dirty_peers.contains(&peer)
            && !self.pending_regroup_baseline.contains_key(&peer)
        {
            self.release_group_admitted_keys(peer);
        }
    }

    /// Derive `peer`'s RT-Constrain membership from its Adj-RIB-In (all
    /// paths, stale included — GR-preserved interest keeps filtering VPN
    /// advertisements through the restart window). Shared by the rebuild
    /// seam above and the GR re-establish path in
    /// `register_active_session`.
    fn rtc_membership_from_rib(&self, peer: PeerId) -> RtcMembership {
        let mut has_default = false;
        let mut entries: Vec<rustbgpd_wire::RtcNlri> = Vec::new();
        if let Some(rib) = self.ribs.get(&peer) {
            for route in rib.iter_rtc() {
                self.replacement_checkpoint_at("selection_rtc_membership", false);
                if route.nlri.is_default() {
                    has_default = true;
                } else {
                    entries.push(route.nlri);
                }
            }
        }
        entries.sort_unstable();
        entries.dedup();
        RtcMembership {
            has_default,
            entries,
        }
    }

    /// Recompute the Loc-RIB RT-Constrain selection for each affected key
    /// and distribute the changes, mirroring [`Self::recompute_vpn_keys`].
    fn recompute_rtc_keys(&mut self, affected: &HashSet<crate::route::RtcRibRouteKey>) {
        self.recompute_and_distribute_rtc(affected);
    }

    /// Recompute the Loc-RIB BGP-LS selection for each affected key across the
    /// current set of peer Adj-RIB-Ins.
    ///
    /// Shared by the receive path and the peer-teardown cleanup so a departed
    /// peer's routes fall back to the next-best remaining candidate (or are
    /// removed when no peer still advertises the key), mirroring the
    /// unicast/FlowSpec/EVPN recompute + distribution pattern.
    fn recompute_bgpls_keys(&mut self, affected: &HashSet<crate::route::BgpLsRouteKey>) {
        self.recompute_and_distribute_bgpls(affected);
        // An empty affected set means no BGP-LS route actually changed
        // (e.g. a withdraw of a key not held, or an empty batch), so the
        // Adj-RIB-In topology union is byte-identical and the SPF surface
        // cannot have moved — skip the topology rebuild + per-vantage SPF
        // (LAN-189). Vantage-config changes take the direct
        // `recompute_orr()` path in peer_lifecycle, not this seam, so
        // they are unaffected by this guard.
        if affected.is_empty() {
            return;
        }
        // Every BGP-LS mutation seam routes through here — receive
        // (`handle_bgpls_routes_received`), the enhanced-refresh EoRR
        // sweep (`finish_route_refresh`), the GR entry sweep
        // (`handle_peer_graceful_restart`, recompute-then-GC ordering),
        // and BGP-LS-bearing peer teardown (`clear_peer_adj_rib_in`) —
        // so the ORR cache rebuild needs exactly one call site.
        let changed = self.recompute_orr();
        self.resync_orr_bound_peers(&changed);
    }

    /// Resync every established peer bound to a changed ORR vantage: a
    /// changed next-hop cost surface (metric shift, lookup change, or
    /// vantage resolution flip) can
    /// move those peers' per-vantage bests without any unicast RIB
    /// change, so nothing else would re-stage them. Dirty + empty-set
    /// `distribute_changes` is the `ReplacePeerExportPolicy` precedent —
    /// the Adj-RIB-Out equality machinery reduces the full restage to
    /// the minimal announce/withdraw delta per peer (unaffected peers
    /// see zero messages).
    fn resync_orr_bound_peers(&mut self, changed: &HashSet<IpAddr>) {
        if changed.is_empty() {
            return;
        }
        let bound: Vec<PeerId> = self
            .peer_orr_vantage
            .iter()
            .filter(|(peer, vantage)| {
                changed.contains(*vantage) && self.outbound_peers.contains_key(*peer)
            })
            .map(|(peer, _)| *peer)
            .collect();
        if bound.is_empty() {
            return;
        }
        // Preserve the single dirty-marking seam: ORR currently disqualifies
        // grouping, but routing through the helper also marks group state if
        // that eligibility rule changes later.
        for peer in bound {
            self.mark_outbound_dirty(peer);
        }
        self.distribute_changes(&HashSet::new(), &HashSet::new());
    }

    /// The ORR topology input: every peer's BGP-LS Adj-RIB-In, excluding
    /// families whose selection is still deferred. The vantage cache and
    /// every on-demand read share this one definition, so a read cannot
    /// change source when the vantage set empties or fills.
    pub(super) fn build_orr_topology(&self) -> crate::orr::OrrTopology {
        self.build_orr_topology_with_checkpoint(&mut || {}, &mut || {})
    }

    /// [`Self::build_orr_topology`] with `scan` called for every visited
    /// input, deferred-family exclusions included, and `build` inside the
    /// topology construction.
    fn build_orr_topology_with_checkpoint(
        &self,
        scan: &mut impl FnMut(),
        build: &mut impl FnMut(),
    ) -> crate::orr::OrrTopology {
        let mut inputs = 0_usize;
        for rib in self.ribs.values() {
            scan();
            inputs = inputs.saturating_add(rib.bgpls_len());
        }
        crate::orr::OrrTopology::build_with_checkpoint(
            // A leading `None` per RIB yields a checkpoint even for a peer
            // with no BGP-LS routes, so empty tables cannot accumulate inside
            // one `next()`.
            self.ribs
                .values()
                .flat_map(|rib| std::iter::once(None).chain(rib.iter_bgpls().map(Some)))
                .inspect(|_| scan())
                .flatten()
                .filter(|route| !self.selection_deferred(route.family.to_afi_safi())),
            inputs,
            build,
        )
    }

    /// Rebuild the cached RFC 9107 ORR state: one topology from the
    /// BGP-LS Adj-RIB-In union, one SPF per DISTINCT configured vantage
    /// IP. Returns the vantages whose next-hop cost surface changed
    /// (consumed by [`Self::resync_orr_bound_peers`] to dirty their
    /// bound peers). Early-outs with no
    /// topology build and no SPF while `peer_orr_vantage` is empty, so
    /// non-ORR deployments pay nothing on BGP-LS churn.
    ///
    /// Under a readiness owner, every unit checkpoints: the inventory scan,
    /// topology construction, lookup comparison, vantage collection and
    /// resolution, SPF, signature sorting and comparison, and retirement of
    /// the replaced state. Each collection is reserved before it fills.
    #[expect(
        clippy::too_many_lines,
        reason = "one readiness-owned rebuild keeps every ORR unit's checkpoint in view"
    )]
    pub(super) fn recompute_orr(&mut self) -> HashSet<IpAddr> {
        let readiness = self.replacement_readiness.clone();
        let mut scan = || replacement_readiness_checkpoint_at(&readiness, "orr_scan", false);
        let mut build = || replacement_readiness_checkpoint_at(&readiness, "orr_build", false);
        let mut compare = || replacement_readiness_checkpoint_at(&readiness, "orr_compare", false);
        let mut vantage_step =
            || replacement_readiness_checkpoint_at(&readiness, "orr_vantages", false);
        let mut spf_step = || replacement_readiness_checkpoint_at(&readiness, "orr_spf", false);
        let mut signature_step =
            || replacement_readiness_checkpoint_at(&readiness, "orr_signature", false);
        let mut retire = || replacement_readiness_checkpoint_at(&readiness, "orr_retire", false);
        if self.peer_orr_vantage.is_empty() {
            if !self.orr.is_empty() {
                log_orr_input_transition(
                    self.orr.topology.input_diagnostics(),
                    crate::orr::OrrInputDiagnostics::default(),
                );
                std::mem::take(&mut self.orr).retire_with(&mut retire);
            }
            self.metrics.set_orr_topology_nodes(0);
            self.metrics.set_orr_topology_links(0);
            self.metrics.set_orr_unresolved_vantages(0);
            self.metrics
                .set_orr_input_diagnostics(crate::orr::OrrInputDiagnostics::default().values());
            return HashSet::new();
        }
        // The vantage cache below now serves paged topology reads.
        if let Some(page) = self.orr_page_topology.take() {
            let (_, topology) = *page;
            topology.retire_with(&mut retire);
        }

        let topology = self.build_orr_topology_with_checkpoint(&mut scan, &mut build);
        let input_diagnostics = topology.input_diagnostics();
        log_orr_input_transition(self.orr.topology.input_diagnostics(), input_diagnostics);
        // Next-hop costs also depend on exact address ownership and covering
        // prefix advertisers/metrics, which can move without any node distance.
        let lookup_changed =
            !topology.same_next_hop_lookup_with_checkpoint(&self.orr.topology, &mut compare);
        let mut vantages = HashSet::with_capacity(self.peer_orr_vantage.len());
        vantage_step();
        #[cfg(test)]
        let reserved = vantages.capacity();
        for &vantage in self.peer_orr_vantage.values() {
            vantage_step();
            vantages.insert(vantage);
        }
        #[cfg(test)]
        crate::orr::rebuild_growth::record("orr_vantages", reserved, vantages.capacity());
        let mut changed = HashSet::with_capacity(vantages.len());
        vantage_step();
        let mut spf = HashMap::with_capacity(vantages.len());
        vantage_step();
        let mut resolved = HashMap::with_capacity(vantages.len());
        vantage_step();
        let mut signatures = HashMap::with_capacity(vantages.len());
        vantage_step();
        #[cfg(test)]
        let reserved = (
            changed.capacity(),
            spf.capacity(),
            resolved.capacity(),
            signatures.capacity(),
        );
        for vantage in vantages {
            vantage_step();
            let node = topology.resolve_node_with_checkpoint(vantage, &mut vantage_step);
            let was_resolved = self.orr.resolved.get(&vantage).copied();
            // Log once per transition (a fresh vantage counts as one).
            match (was_resolved, node.is_some()) {
                (Some(true) | None, false) => warn!(
                    %vantage,
                    "ORR vantage does not resolve to a BGP-LS topology node — \
                     bound peers fall back to the standard best path"
                ),
                (Some(false) | None, true) => {
                    info!(%vantage, "ORR vantage resolved to a BGP-LS topology node");
                }
                (Some(true), true) | (Some(false), false) => {}
            }
            resolved.insert(vantage, node.is_some());
            if let Some(node) = node {
                let result = topology.spf_with_checkpoint(node, &mut spf_step);
                self.metrics.record_orr_spf_run();
                let signature =
                    topology.spf_signature_with_checkpoint(&result, &mut signature_step);
                if lookup_changed
                    || self.orr.signatures.get(&vantage).is_none_or(|previous| {
                        !crate::orr::eq_with_checkpoint(previous, &signature, &mut signature_step)
                    })
                {
                    changed.insert(vantage);
                }
                spf.insert(vantage, result);
                signatures.insert(vantage, signature);
            } else if self.orr.spf.contains_key(&vantage) {
                // Resolved → unresolved is a change too: bound peers
                // revert to the standard best path (PR-4).
                changed.insert(vantage);
            }
        }

        let unresolved = resolved
            .values()
            .inspect(|_| vantage_step())
            .filter(|resolved| !**resolved)
            .count();
        self.metrics
            .set_orr_topology_nodes(i64::try_from(topology.node_count()).unwrap_or(i64::MAX));
        self.metrics
            .set_orr_topology_links(i64::try_from(topology.link_count()).unwrap_or(i64::MAX));
        self.metrics
            .set_orr_unresolved_vantages(i64::try_from(unresolved).unwrap_or(i64::MAX));
        self.metrics
            .set_orr_input_diagnostics(input_diagnostics.values());
        #[cfg(test)]
        {
            crate::orr::rebuild_growth::record("orr_changed", reserved.0, changed.capacity());
            crate::orr::rebuild_growth::record("orr_spf_results", reserved.1, spf.capacity());
            crate::orr::rebuild_growth::record("orr_resolved", reserved.2, resolved.capacity());
            crate::orr::rebuild_growth::record("orr_signatures", reserved.3, signatures.capacity());
        }
        std::mem::replace(
            &mut self.orr,
            crate::orr::OrrState {
                topology,
                spf,
                resolved,
                signatures,
            },
        )
        .retire_with(&mut retire);
        changed
    }

    /// Run the RIB manager event loop until the channel is closed.
    ///
    /// When dirty peers exist (from failed outbound sends), a persistent
    /// resync timer fires to retry distribution independently of both
    /// incoming mutations and non-mutating query traffic. The timer is
    /// started when `dirty_peers` transitions from empty to non-empty and
    /// reset after each retry tick; it is not recreated per loop iteration,
    /// so incoming messages cannot starve it.
    ///
    /// Every poll, and every readiness-checkpoint slice within it, is timed
    /// into `bgp_rib_actor_slice_seconds`.
    pub async fn run(self) {
        let recorder = self.metrics.rib_actor_slice_recorder();
        let suspended = Arc::clone(&self.actor_suspended);
        slice_timing::TimedActor::new(self.run_actor(), recorder, suspended).await;
    }

    #[expect(
        clippy::too_many_lines,
        reason = "event loop with timer arms and query draining"
    )]
    async fn run_actor(mut self) {
        // Persistent timer: starts far in the future (disabled). Reset to
        // DIRTY_RESYNC_INTERVAL when dirty_peers becomes non-empty.
        let resync_sleep = tokio::time::sleep(DIRTY_RESYNC_INTERVAL);
        tokio::pin!(resync_sleep);
        let mut resync_armed = false;
        let mut query_rx_open = true;
        let mut primary_run = PrimaryRunBudget::default();
        // Start of the primary work admitted since the last prestage slice.
        let mut prestage_primary_since: Option<std::time::Instant> = None;

        // A deferred attribute sweep must also run when UPDATE traffic stops.
        let attr_gc_sleep = tokio::time::sleep(ATTR_INTERN_GC_INTERVAL);
        tokio::pin!(attr_gc_sleep);

        // GR stale sweep timer — reset each iteration to the nearest deadline.
        let gr_sleep = tokio::time::sleep(std::time::Duration::from_hours(24));
        tokio::pin!(gr_sleep);

        // LLGR stale sweep timer — reset each iteration to the nearest deadline.
        let llgr_sleep = tokio::time::sleep(std::time::Duration::from_hours(24));
        tokio::pin!(llgr_sleep);

        // Enhanced route refresh timer — reset each iteration to the nearest
        // active refresh deadline.
        let refresh_sleep = tokio::time::sleep(std::time::Duration::from_hours(24));
        tokio::pin!(refresh_sleep);

        // RFC 4684 §6 VPN/EVPN End-of-RIB hold cap — reset each iteration to
        // the nearest held peer's deadline.
        let rtc_eor_sleep = tokio::time::sleep(std::time::Duration::from_hours(24));
        tokio::pin!(rtc_eor_sleep);

        // RFC 4724 restarting-speaker selection-deferral timer. The roster
        // and deadline are frozen before this actor starts.
        let selection_sleep = tokio::time::sleep(std::time::Duration::from_hours(24));
        tokio::pin!(selection_sleep);

        // ADR-0137 conditional-advertisement settle timer — reset each
        // iteration to the earliest armed settle deadline.
        let conditional_sleep = tokio::time::sleep(std::time::Duration::from_hours(24));
        tokio::pin!(conditional_sleep);

        // Registration-wait sample: armed only while a wait may exist, so a
        // registration lost while the actor is idle still ages on the gauge.
        let registration_wait_sleep = tokio::time::sleep(std::time::Duration::from_hours(24));
        tokio::pin!(registration_wait_sleep);

        loop {
            if self.dampening_history.notice_failed() {
                tracing::error!(
                    "dampening capacity disable owner unavailable; terminating RIB actor"
                );
                return;
            }
            // The export roster's one publication point (ADR-0136): after
            // each completed unit, never while a grouped transition is
            // parked between `CommitMembers` batches.
            self.publish_export_roster();

            // Sample ingest-channel depth once per iteration — a gauge
            // pegged at the channel capacity on scrape means producers
            // (sessions, local originators) are parked on backpressure.
            self.metrics.set_rib_ingest_channel_depth(
                i64::try_from(self.primary_backlog()).unwrap_or(i64::MAX),
            );
            self.sample_outbound_dirty_gauges();
            self.sample_outbound_registration_wait_if_due();

            if let Some(mut pending) = self.pending_clean_policy_transition.take() {
                // A newly owned transition supersedes any trace still armed
                // from the previous commit.
                self.post_commit_query_trace = None;
                // The type-narrow readiness lane interleaves at every poll,
                // and a bounded general-query budget between pre-commit
                // polls (see `drain_general_queries_between_transition_polls`).
                // Primary updates, route chunks, timers, and resync work
                // remain queued until terminal commit or the fail-closed
                // fallback handoff.
                let member_count = pending.member_count();
                Self::warn_if_policy_transition_slow(&mut pending, member_count);
                self.drain_readiness_queries(Some(pending.elapsed()));
                let kind = pending.poll_kind();
                let started = std::time::Instant::now();
                let mut terminal_reply = None;
                let policy_transition_elapsed = self.with_replacement_readiness_age(pending.elapsed(), |manager| { match manager.advance_clean_policy_transition(pending)
                {
                    distribution::CleanPolicyTransitionAdvance::Continue(mut next) => {
                        manager.record_policy_transition_poll(kind, started.elapsed());
                        let member_count = next.member_count();
                        Self::warn_if_policy_transition_slow(&mut next, member_count);
                        let elapsed = next.elapsed();
                        manager.pending_clean_policy_transition = Some(next);
                        Some(elapsed)
                    }
                    distribution::CleanPolicyTransitionAdvance::Committed(mut done) => {
                        manager.record_policy_transition_poll(kind, started.elapsed());
                        let member_count = done.member_count();
                        Self::warn_if_policy_transition_slow(&mut done, member_count);
                        manager.finish_policy_transition_observability(
                            RibPolicyTransitionOutcome::Committed,
                            done.member_count(),
                            done.elapsed(),
                        );
                        done.retire_inputs(manager);
                        let reply = done.take_reply();
                        drop(done);
                        manager.replacement_checkpoint(true);
                        if let Some(reply) = reply {
                            terminal_reply = Some((reply, Ok(crate::update::ExportPolicyCohortOutcome::Committed)));
                        }
                        manager.post_commit_query_trace = Some(PostCommitQueryTrace {
                            since: std::time::Instant::now(),
                            member_count,
                            terminal_poll: started.elapsed(),
                            queued_general_queries: manager.query_rx.len(),
                            queued_summary_queries: manager.summary_rx.as_ref().map_or(0, mpsc::Receiver::len),
                            ingest_backlog: manager.primary_backlog(),
                            busy: std::time::Duration::ZERO,
                            route_chunks: 0,
                            primary_updates: 0,
                            resync_ticks: 0,
                        });
                        None
                    }
                    distribution::CleanPolicyTransitionAdvance::Fallback(mut failed) => {
                        let cleanup = failed.discard_uncommitted_transition(manager);
                        manager.record_policy_transition_poll(kind, started.elapsed());
                        let member_count = failed.member_count();
                        Self::warn_if_policy_transition_slow(&mut failed, member_count);
                        let outcome = if cleanup.is_ok() {
                            RibPolicyTransitionOutcome::FallbackHandoff
                        } else {
                            RibPolicyTransitionOutcome::FallbackCleanupError
                        };
                        manager.finish_policy_transition_observability(
                            outcome,
                            member_count,
                            failed.elapsed(),
                        );
                        let reply = failed.take_reply();
                        drop(failed);
                        manager.replacement_checkpoint(true);
                        if let Some(reply) = reply {
                            let result = cleanup.map(|()| {
                                crate::update::ExportPolicyCohortOutcome::RequiresAuthoritativePerPeerApply
                            });
                            terminal_reply = Some((reply, result));
                        }
                        None
                    }
                } });
                if let Some((reply, result)) = terminal_reply {
                    let _ = reply.send(result);
                }
                self.drain_readiness_queries(policy_transition_elapsed);
                self.drain_general_queries_between_transition_polls();
                tokio::task::yield_now().await;
                continue;
            }

            // One bounded validation slice per ordinary actor turn, including
            // under sustained primary traffic. Clean transitions above retain
            // their existing ownership fence.
            let validated_flowspec = self.process_flowspec_validation_chunk();
            let retired_dampening = self.dampening_history.retire(ROUTES_RECEIVED_CHUNK_SIZE) > 0;
            if validated_flowspec || retired_dampening {
                self.drain_readiness_queries(None);
                self.drain_queries(QUERY_BUDGET_PER_CHUNK);
                tokio::task::yield_now().await;
            }

            // Arm the resync timer when resync work transitions none → some.
            if self.resync_tick_pending() && !resync_armed {
                resync_sleep
                    .as_mut()
                    .reset(tokio::time::Instant::now() + DIRTY_RESYNC_INTERVAL);
                resync_armed = true;
            }

            // Arm the GR timer to the nearest stale deadline.
            let has_gr_timers = if let Some(deadline) = self.next_gr_deadline() {
                gr_sleep.as_mut().reset(deadline);
                true
            } else {
                false
            };

            // Arm the LLGR timer to the nearest stale deadline.
            let has_llgr_timers = if let Some(deadline) = self.next_llgr_deadline() {
                llgr_sleep.as_mut().reset(deadline);
                true
            } else {
                false
            };

            let has_refresh_timers = if let Some(deadline) = self.next_refresh_deadline() {
                refresh_sleep.as_mut().reset(deadline);
                true
            } else {
                false
            };

            let has_rtc_eor_timer = if let Some(deadline) = self.next_eor_hold_deadline() {
                rtc_eor_sleep.as_mut().reset(deadline);
                true
            } else {
                false
            };

            let has_selection_timer =
                if let Some(deadline) = self.next_selection_deferral_deadline() {
                    selection_sleep.as_mut().reset(deadline);
                    true
                } else {
                    false
                };

            let has_conditional_timer =
                if let Some(deadline) = self.next_conditional_advertisement_deadline() {
                    conditional_sleep.as_mut().reset(deadline);
                    true
                } else {
                    false
                };

            let has_attr_gc_timer = if let Some(deadline) = self.attr_intern_gc_deadline {
                attr_gc_sleep.as_mut().reset(deadline);
                true
            } else {
                false
            };

            let has_registration_wait_timer = if let Some(at) = self.registration_wait_sample_at {
                registration_wait_sleep.as_mut().reset(at);
                true
            } else {
                false
            };

            let needs_timers = has_attr_gc_timer
                || has_registration_wait_timer
                || resync_armed
                || has_gr_timers
                || has_llgr_timers
                || has_refresh_timers
                || has_rtc_eor_timer
                || has_selection_timer
                || has_conditional_timer;

            if query_rx_open && self.query_rx.is_closed() {
                query_rx_open = false;
            }

            let now = tokio::time::Instant::now();
            let conditional_due = has_conditional_timer && conditional_sleep.deadline() <= now;
            let rtc_eor_due = has_rtc_eor_timer && rtc_eor_sleep.deadline() <= now;
            let gr_due = has_gr_timers && gr_sleep.deadline() <= now;
            let llgr_due = has_llgr_timers && llgr_sleep.deadline() <= now;
            let refresh_due = has_refresh_timers && refresh_sleep.deadline() <= now;
            let selection_due = has_selection_timer && selection_sleep.deadline() <= now;
            // ADR-0137: capture every due timer's admission cutoff the
            // moment it is first seen due, before any branch below drains.
            // Each due branch admits only that backlog (drain-first within
            // it) and then fires, and every admission is charged to all
            // captured cutoffs, so an update that arrives after a deadline
            // is never counted as pre-deadline work and sustained ingress
            // cannot postpone any of these timers. The branch order below
            // decides which of several due timers drains first, but once
            // any due timer's cutoff is exhausted, every timer that still
            // has room yields (its branch is skipped) until the exhausted
            // one has fired, so no branch admits post-deadline work ahead
            // of another timer's expiry.
            let backlog = self.primary_backlog();
            for (timer, due) in [
                (ExpiryTimer::RtcEor, rtc_eor_due),
                (ExpiryTimer::Conditional, conditional_due),
                (ExpiryTimer::GrStale, gr_due),
                (ExpiryTimer::LlgrStale, llgr_due),
                (ExpiryTimer::RefreshWindow, refresh_due),
                (ExpiryTimer::SelectionDeferral, selection_due),
            ] {
                self.expiry_cutoffs.observe(timer, due, backlog);
            }
            let cutoffs = &self.expiry_cutoffs;
            let rtc_eor_due = rtc_eor_due && !cutoffs.yields(ExpiryTimer::RtcEor);
            let conditional_due = conditional_due && !cutoffs.yields(ExpiryTimer::Conditional);
            let gr_due = gr_due && !cutoffs.yields(ExpiryTimer::GrStale);
            let llgr_due = llgr_due && !cutoffs.yields(ExpiryTimer::LlgrStale);
            let refresh_due = refresh_due && !cutoffs.yields(ExpiryTimer::RefreshWindow);
            let selection_due = selection_due && !cutoffs.yields(ExpiryTimer::SelectionDeferral);
            if rtc_eor_due {
                // A queued RT-Constrain EoR releases the hold with its
                // membership applied; let it win over the cap. RFC 4684 §6
                // requires the delay to be bounded; an admitted route batch
                // finishes first, so no route from an update queued before
                // the cap lands behind the released EoR. The planned-restart
                // grace window shares this timer for the same reason: an
                // injection queued before its deadline precedes the marker.
                if self.drain_before_expiry(ExpiryTimer::RtcEor).await {
                    continue;
                }
                self.expire_eor_holds(rtc_eor_sleep.deadline());
                continue;
            }
            if has_attr_gc_timer && attr_gc_sleep.deadline() <= now {
                self.gc_attr_intern_on_timer();
                continue;
            }
            if resync_armed && resync_sleep.deadline() <= now {
                debug!(
                    count = self.dirty_peers.len(),
                    "resync timer fired for dirty peers"
                );
                let backlog =
                    self.traced(PostCommitWork::ResyncTick, Self::resync_dirty_peers_bounded);
                if self.resync_tick_pending() {
                    self.metrics.record_rib_dirty_resync("still_dirty");
                    let interval = if backlog {
                        DIRTY_RESYNC_BACKLOG_INTERVAL
                    } else {
                        DIRTY_RESYNC_INTERVAL
                    };
                    resync_sleep
                        .as_mut()
                        .reset(tokio::time::Instant::now() + interval);
                } else {
                    self.metrics.record_rib_dirty_resync("cleared");
                    resync_armed = false;
                }
                continue;
            }
            if conditional_due {
                // ADR-0137: expiry applies only the observation of a finished
                // batch. An open route batch, and the primary updates already
                // queued when expiry was first seen, run first so their
                // observation flush precedes it.
                if self.drain_before_expiry(ExpiryTimer::Conditional).await {
                    continue;
                }
                let _ = self.fire_conditional_advertisement_timers();
                continue;
            }
            if gr_due {
                if self.drain_before_expiry(ExpiryTimer::GrStale).await {
                    continue;
                }
                let expired: Vec<PeerId> = self
                    .gr_stale_deadlines
                    .iter()
                    .filter(|&(_, &deadline)| deadline <= now)
                    .map(|(&peer, _)| peer)
                    .collect();
                for peer in expired {
                    self.sweep_gr_stale(peer);
                }
                continue;
            }
            if llgr_due {
                if self.drain_before_expiry(ExpiryTimer::LlgrStale).await {
                    continue;
                }
                self.sweep_expired_llgr_stale();
                continue;
            }
            if refresh_due {
                if self.drain_before_expiry(ExpiryTimer::RefreshWindow).await {
                    continue;
                }
                self.expire_refresh_windows();
                continue;
            }
            if selection_due {
                // A current-session EoR queued before the timer was first
                // seen due wins the all-EoR release race; one that arrives
                // after it does not count toward the expired deferral.
                if self
                    .drain_before_expiry(ExpiryTimer::SelectionDeferral)
                    .await
                {
                    continue;
                }
                self.expire_selection_deferral();
                continue;
            }

            // Unfenced destination pre-staging: queued mutation traffic goes
            // first, so churn keeps flowing (and keeps already-staged
            // prefixes current) between slices. That priority is bounded:
            // once primary work has held the actor for one flush budget
            // since the last slice, the next slice runs at a route-batch
            // boundary even with updates still queued. Steady churn that
            // never empties the queue would otherwise starve the walk past
            // the caller's reply deadline and push the full staging walk
            // back under the transition fence. Readiness and a bounded
            // query budget are served every iteration, mirroring the
            // paced-flush seams.
            if self.pending_destination_prestage.is_some() {
                let primary_since =
                    *prestage_primary_since.get_or_insert_with(std::time::Instant::now);
                let slice_owed = primary_since.elapsed() >= self.flush_poll_budget
                    && self.pending_route_batches.is_empty();
                if !slice_owed && self.drain_ready_updates().await {
                    continue;
                }
                prestage_primary_since = None;
                self.drain_readiness_queries(None);
                self.advance_destination_prestage();
                self.drain_queries(QUERY_BUDGET_PER_CHUNK);
                tokio::task::yield_now().await;
                continue;
            }
            prestage_primary_since = None;

            // Deferred outbound registrations (LAN-475): complete one
            // initial table dump per iteration, and only after every queued
            // mutation batch has drained — imports and their fan-out to
            // established peers always preempt the reconnecting peers'
            // full-table catch-up, so a mass reconnect cannot head-of-line
            // block re-announcement delivery to survivors.
            if !self.pending_initial_registrations.is_empty() {
                if self.drain_ready_updates().await {
                    continue;
                }
                self.drain_readiness_queries(None);
                self.advance_pending_initial_registration();
                self.drain_queries(QUERY_BUDGET_PER_CHUNK);
                tokio::task::yield_now().await;
                continue;
            }

            if self.traced_route_chunk() {
                self.drain_readiness_queries(None);
                self.drain_queries(QUERY_BUDGET_PER_CHUNK);
                tokio::task::yield_now().await;
            } else if validated_flowspec || retired_dampening {
                // Do not sleep while validation remains queued, but admit a
                // primary update between slices instead of monopolizing turns.
                if let Some(update) = self.try_recv_primary() {
                    self.traced(PostCommitWork::PrimaryUpdate, |manager| {
                        manager.handle_update(update);
                    });
                    self.drain_general_queries_if_unfenced();
                }
            } else if needs_timers {
                tokio::select! {
                    readiness = Self::receive_readiness_query(&mut self.readiness_rx) => {
                        match readiness {
                            Some(query) => self.serve_readiness_query(query).await,
                            None => self.readiness_rx = None,
                        }
                    }
                    summary = Self::receive_summary_query(&mut self.summary_rx) => {
                        match summary {
                            Some(query) => self.serve_summary_query(query),
                            None => self.summary_rx = None,
                        }
                    }
                    query = self.query_rx.recv(), if query_rx_open => {
                        match query {
                            Some(q) => self.serve_general_query(q),
                            None => query_rx_open = false,
                        }
                    }
                    update = Self::recv_primary(&mut self.primary_lookahead, &mut self.rx) => {
                        match update {
                            Some(update) => {
                                self.maybe_stall_test_ingest(&update).await;
                                let started = primary_run
                                    .start(std::time::Instant::now(), &self.actor_suspended);
                                self.traced(PostCommitWork::PrimaryUpdate, |manager| {
                                    manager.handle_update(update);
                                });
                                self.drain_general_queries_if_unfenced();
                                // Bound one actor poll by the flush budget.
                                // Otherwise the loop drains a deep backlog up
                                // to Tokio's whole cooperative budget in one
                                // poll, and a task woken meanwhile (a readiness
                                // reply's probe) waits behind it on this
                                // worker. Yielding after every update instead
                                // measurably slowed bulk VPN ingest.
                                if primary_run.should_yield(
                                    started,
                                    std::time::Instant::now(),
                                    self.flush_poll_budget,
                                ) {
                                    tokio::task::yield_now().await;
                                }
                            }
                            None => break,
                        }
                    }
                    () = attr_gc_sleep.as_mut(), if has_attr_gc_timer => {
                        self.gc_attr_intern_on_timer();
                    }
                    () = resync_sleep.as_mut(), if resync_armed => {
                        debug!(
                            count = self.dirty_peers.len(),
                            "resync timer fired for dirty peers"
                        );
                        let backlog = self
                            .traced(PostCommitWork::ResyncTick, Self::resync_dirty_peers_bounded);

                        // Reset for next tick if work remains, otherwise disarm.
                        if self.resync_tick_pending() {
                            self.metrics.record_rib_dirty_resync("still_dirty");
                            let interval = if backlog {
                                DIRTY_RESYNC_BACKLOG_INTERVAL
                            } else {
                                DIRTY_RESYNC_INTERVAL
                            };
                            resync_sleep.as_mut().reset(
                                tokio::time::Instant::now() + interval,
                            );
                        } else {
                            self.metrics.record_rib_dirty_resync("cleared");
                            resync_armed = false;
                        }
                    }
                    // Each timer only wakes the loop: expiry is applied by
                    // the due checks above, under its admission cutoff.
                    () = gr_sleep.as_mut(), if has_gr_timers => {}
                    () = llgr_sleep.as_mut(), if has_llgr_timers => {}
                    () = refresh_sleep.as_mut(), if has_refresh_timers => {}
                    () = rtc_eor_sleep.as_mut(), if has_rtc_eor_timer => {}
                    () = selection_sleep.as_mut(), if has_selection_timer => {}
                    () = conditional_sleep.as_mut(), if has_conditional_timer => {}
                    () = registration_wait_sleep.as_mut(), if has_registration_wait_timer => {}
                }
            } else {
                // No timers needed — wait for a route update or query.
                tokio::select! {
                    readiness = Self::receive_readiness_query(&mut self.readiness_rx) => {
                        match readiness {
                            Some(query) => self.serve_readiness_query(query).await,
                            None => self.readiness_rx = None,
                        }
                    }
                    summary = Self::receive_summary_query(&mut self.summary_rx) => {
                        match summary {
                            Some(query) => self.serve_summary_query(query),
                            None => self.summary_rx = None,
                        }
                    }
                    query = self.query_rx.recv(), if query_rx_open => {
                        match query {
                            Some(q) => self.serve_general_query(q),
                            None => query_rx_open = false,
                        }
                    }
                    update = Self::recv_primary(&mut self.primary_lookahead, &mut self.rx) => {
                        match update {
                            Some(update) => {
                                self.maybe_stall_test_ingest(&update).await;
                                let started = primary_run
                                    .start(std::time::Instant::now(), &self.actor_suspended);
                                self.traced(PostCommitWork::PrimaryUpdate, |manager| {
                                    manager.handle_update(update);
                                });
                                self.drain_general_queries_if_unfenced();
                                // Same poll bound as the timer-aware wait above.
                                if primary_run.should_yield(
                                    started,
                                    std::time::Instant::now(),
                                    self.flush_poll_budget,
                                ) {
                                    tokio::task::yield_now().await;
                                }
                            }
                            None => break,
                        }
                    }
                }
            }

            // Disarm if a message handler cleared the work (e.g. PeerDown).
            // That drain is a `cleared` outcome like a draining timer tick.
            if resync_armed && !self.resync_tick_pending() {
                self.metrics.record_rib_dirty_resync("cleared");
                resync_armed = false;
            }
        }

        debug!("rib manager shutting down");
    }
}
