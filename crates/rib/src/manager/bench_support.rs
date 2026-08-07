//! Bench-only manager hot-path drivers.
//!
//! Exposed solely to workspace microbenchmarks behind the `bench-internals`
//! feature (set via `required-features` on each bench target). The `pub fn
//! bench_*` methods join the crate's public surface only when that feature is
//! enabled; in a normal (default-feature) build the whole module is compiled
//! out and nothing here is reachable.
//!
//! The fanout driver registers synthetic outbound peers, seeds the Loc-RIB, and
//! runs `distribute_changes` directly. The event-history driver calls the same
//! private publish helpers as the manager actor so the API crate can compare
//! the default no-op sink with its concrete EHM sink without widening the
//! normal public API or duplicating manager-side ring/broadcast work.

use std::cell::Cell;
use std::collections::{BTreeMap, HashSet};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

use rustbgpd_policy::PolicyChain;
use rustbgpd_wire::{Afi, Prefix, Safi};
use tokio::sync::{mpsc, oneshot};

use super::RibManager;
use crate::event::{EvpnRouteEvent, RouteEvent};
use crate::route::Route;
use crate::update::{
    ExactExportEncoder, OutboundRouteUpdate, PeerExportPolicyReplacement, RibUpdate, RoutePage,
    RouteQueryKey, RouteQueryScope,
};

static POLICY_TRANSITION_RECEIPT_PRINTED: AtomicBool = AtomicBool::new(false);
static PCB_ENUMERATION_PHASES: AtomicUsize = AtomicUsize::new(0);
static PCB_ENUMERATED_PREFIXES: AtomicUsize = AtomicUsize::new(0);
static PCB_STAGING_PHASES: AtomicUsize = AtomicUsize::new(0);
static PCB_STAGING_PREFIXES: AtomicUsize = AtomicUsize::new(0);
static PCB_EXACT_PHASES: AtomicUsize = AtomicUsize::new(0);
static PCB_COMMIT_PHASES: AtomicUsize = AtomicUsize::new(0);
static PCB_ENQUEUE_PHASES: AtomicUsize = AtomicUsize::new(0);
static PCB_TOTAL_ENUMERATION_NANOS: AtomicU64 = AtomicU64::new(0);
static PCB_TOTAL_STAGING_NANOS: AtomicU64 = AtomicU64::new(0);
static PCB_TOTAL_EXACT_NANOS: AtomicU64 = AtomicU64::new(0);
static PCB_TOTAL_COMMIT_NANOS: AtomicU64 = AtomicU64::new(0);
static PCB_TOTAL_ENQUEUE_NANOS: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy)]
struct PerClientBestCandidateBenchAggregate {
    capture_active: bool,
    prefix_visits: usize,
    empty_sets: usize,
    singleton_sets: usize,
    multi_sets: usize,
    heap_backed_collections: usize,
}

impl PerClientBestCandidateBenchAggregate {
    const INACTIVE: Self = Self {
        capture_active: false,
        prefix_visits: 0,
        empty_sets: 0,
        singleton_sets: 0,
        multi_sets: 0,
        heap_backed_collections: 0,
    };

    const fn active() -> Self {
        Self {
            capture_active: true,
            ..Self::INACTIVE
        }
    }
}

thread_local! {
    static PCB_CANDIDATE_AGGREGATE: Cell<PerClientBestCandidateBenchAggregate> =
        const { Cell::new(PerClientBestCandidateBenchAggregate::INACTIVE) };
}

/// Bench-only proof that an authoritative per-client-best policy replacement
/// traversed the real full-resync selection arm. Durations are deliberately
/// coarse per-peer totals; no clock is read inside the prefix loop.
#[derive(Clone, Copy, Debug)]
pub struct PerClientBestResyncBenchReceipt {
    pub candidate_prefix_visits: usize,
    pub empty_candidate_sets: usize,
    pub singleton_candidate_sets: usize,
    pub multi_candidate_sets: usize,
    pub heap_backed_candidate_collections: usize,
    pub enumeration_phases: usize,
    pub enumerated_prefixes: usize,
    pub staging_phases: usize,
    pub staging_prefixes: usize,
    pub exact_phases: usize,
    pub commit_phases: usize,
    pub enqueue_phases: usize,
    pub total_enumeration: std::time::Duration,
    pub total_staging: std::time::Duration,
    pub total_exact_build_and_encode: std::time::Duration,
    pub total_private_commit: std::time::Duration,
    pub total_enqueue: std::time::Duration,
    pub pending_regroup_baselines: usize,
    pub pending_extra_withdraw_peers: usize,
    pub pending_exact_export_withdrawals: usize,
    pub exact_export_rejection_peers: usize,
    pub outbound_prefix_limit_peers: usize,
    pub forced_resync_peers: usize,
}

fn bench_duration_nanos(duration: std::time::Duration) -> u64 {
    u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX)
}

fn bench_add_duration(total: &AtomicU64, elapsed: std::time::Duration) {
    let nanos = bench_duration_nanos(elapsed);
    let _ = total.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
        Some(current.saturating_add(nanos))
    });
}

pub(in crate::manager) fn bench_record_per_client_best_candidates(
    cardinality: usize,
    heap_backed: bool,
) {
    PCB_CANDIDATE_AGGREGATE.with(|aggregate| {
        let mut receipt = aggregate.get();
        if !receipt.capture_active {
            return;
        }
        receipt.prefix_visits = receipt.prefix_visits.saturating_add(1);
        match cardinality {
            0 => receipt.empty_sets = receipt.empty_sets.saturating_add(1),
            1 => receipt.singleton_sets = receipt.singleton_sets.saturating_add(1),
            _ => receipt.multi_sets = receipt.multi_sets.saturating_add(1),
        }
        if heap_backed {
            receipt.heap_backed_collections = receipt.heap_backed_collections.saturating_add(1);
        }
        aggregate.set(receipt);
    });
}

pub(in crate::manager) fn bench_record_per_client_best_enumeration(
    prefixes: usize,
    elapsed: std::time::Duration,
) {
    PCB_ENUMERATION_PHASES.fetch_add(1, Ordering::Relaxed);
    PCB_ENUMERATED_PREFIXES.fetch_add(prefixes, Ordering::Relaxed);
    bench_add_duration(&PCB_TOTAL_ENUMERATION_NANOS, elapsed);
}

pub(in crate::manager) fn bench_record_per_client_best_staging(
    prefixes: usize,
    elapsed: std::time::Duration,
) {
    PCB_STAGING_PHASES.fetch_add(1, Ordering::Relaxed);
    PCB_STAGING_PREFIXES.fetch_add(prefixes, Ordering::Relaxed);
    bench_add_duration(&PCB_TOTAL_STAGING_NANOS, elapsed);
}

pub(in crate::manager) fn bench_record_per_client_best_exact(elapsed: std::time::Duration) {
    PCB_EXACT_PHASES.fetch_add(1, Ordering::Relaxed);
    bench_add_duration(&PCB_TOTAL_EXACT_NANOS, elapsed);
}

pub(in crate::manager) fn bench_record_per_client_best_commit(elapsed: std::time::Duration) {
    PCB_COMMIT_PHASES.fetch_add(1, Ordering::Relaxed);
    bench_add_duration(&PCB_TOTAL_COMMIT_NANOS, elapsed);
}

pub(in crate::manager) fn bench_record_per_client_best_enqueue(elapsed: std::time::Duration) {
    PCB_ENQUEUE_PHASES.fetch_add(1, Ordering::Relaxed);
    bench_add_duration(&PCB_TOTAL_ENQUEUE_NANOS, elapsed);
}

/// Instrumentation from the production clean-transition state machine.
#[derive(Clone, Copy, Debug)]
pub struct PolicyTransitionBenchReceipt {
    pub plan_builds: usize,
    pub full_exact_probes: usize,
    pub route_shell_materializations: usize,
    pub actor_polls: usize,
    pub max_actor_poll: std::time::Duration,
    pub max_prefix_snapshot_poll: std::time::Duration,
    pub max_finalize_poll: std::time::Duration,
    pub max_commit_poll: std::time::Duration,
    pub authoritative_peer_applies: usize,
    pub max_authoritative_peer_apply: std::time::Duration,
    pub max_uninterrupted_work: std::time::Duration,
}

/// Evidence that the fanout benchmark traversed the intended production
/// ingress and authoritative grouped commit paths rather than an
/// equality-suppressed or fallback path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AdjRibOutFanoutBenchReceipt {
    pub update_groups: usize,
    pub grouped_peers: usize,
    pub ungrouped_peers: usize,
    pub dirty_peers: usize,
    pub grouped_unicast_routes: usize,
    pub private_unicast_routes: usize,
    pub routes_received_dispatches: usize,
    pub routes_received_withdrawals: usize,
    pub exact_probe_batches: usize,
    pub exact_probe_candidates: usize,
    pub exact_probe_nonzero_encoded_lengths: usize,
    pub exact_probe_cache_reuses: usize,
    pub successful_commits: usize,
    pub successful_enqueues: usize,
    pub family_gauge_writes: usize,
    pub last_family_gauge_write_mask: u8,
    pub pristine_otc_reconcile_candidates: usize,
    pub private_extra_prefix_scans: usize,
    pub first_peer_family_values: [i64; 7],
}

impl RibManager {
    /// Synthetic peer address used by [`Self::bench_register_peers`].
    ///
    /// Keeping address construction in one helper lets paging benchmarks
    /// query a real grouped member without duplicating the registration
    /// scheme.
    ///
    /// # Panics
    ///
    /// Panics when `index` exceeds `u32::MAX`, far beyond a useful benchmark.
    #[must_use]
    pub fn bench_peer_address(index: usize) -> IpAddr {
        let idx = u32::try_from(index).expect("bench peer index fits in u32");
        let [_, b1, b2, b3] = idx.to_be_bytes();
        IpAddr::V4(Ipv4Addr::new(10, b1, b2, b3))
    }

    /// Register `n_peers` synthetic iBGP outbound peers (`10.a.b.c`), each
    /// cloning `export_policy` and advertising IPv4 unicast. Returns the peer
    /// receivers; the caller MUST hold them so the bounded channels stay open —
    /// a full or closed channel drops the fanout onto the dirty-peer resync path
    /// and stops measuring the steady-state advertise cost. Each registration's
    /// initial-table dump enqueues an End-of-RIB marker (even for an empty
    /// Loc-RIB); that marker is drained here so the channels genuinely start
    /// empty for the measured pass, independent of `channel_capacity`.
    /// `make_exact_export_encoder` must return a fresh authoritative encoder
    /// for each synthetic session so the measured path includes the same exact
    /// wire-size probe and immutable session snapshot as production. The
    /// writer-side owner fence is outside this RIB fanout benchmark.
    ///
    /// # Panics
    /// If `n_peers` exceeds `u32::MAX` — far beyond any realistic bench.
    #[must_use]
    pub fn bench_register_peers<F>(
        &mut self,
        n_peers: usize,
        export_policy: Option<&PolicyChain>,
        is_rr_client: bool,
        channel_capacity: usize,
        mut make_exact_export_encoder: F,
    ) -> Vec<mpsc::Receiver<OutboundRouteUpdate>>
    where
        F: FnMut() -> Arc<dyn ExactExportEncoder>,
    {
        self.bench_register_peers_with_profile(
            n_peers,
            export_policy,
            channel_capacity,
            |_| 64_512,
            false,
            false,
            is_rr_client,
            |_| make_exact_export_encoder(),
        )
    }

    /// Register one synthetic iBGP route-reflector client against the current
    /// Loc-RIB without draining its initial-table envelopes.
    ///
    /// The caller constructs the bounded channel and authoritative encoder
    /// before starting its timer, then inspects the receiver after registration
    /// to prove the timed call sent the expected route inventory and `EoR`. This
    /// keeps Loc-RIB fixture construction, channel allocation, and encoder
    /// construction outside an initial-table join measurement while still
    /// driving the same `PeerUp` registration, first update-group construction,
    /// and `send_initial_table` path as production.
    ///
    /// # Panics
    ///
    /// Panics when `index` exceeds `u32::MAX`, far beyond a useful benchmark.
    pub fn bench_join_route_reflector_peer(
        &mut self,
        index: usize,
        outbound_tx: mpsc::Sender<OutboundRouteUpdate>,
        exact_export_encoder: Arc<dyn ExactExportEncoder>,
    ) {
        let idx = u32::try_from(index).expect("bench peer index fits u32");
        let peer = Self::bench_peer_address(index);
        let session_id = u64::from(idx) + 1;
        self.pending_peer_export_encoders
            .insert((peer, session_id), exact_export_encoder);
        self.handle_peer_up(
            peer,
            session_id,
            64_512,
            Ipv4Addr::new(192, 0, 2, 1),
            outbound_tx,
            None,
            vec![(Afi::Ipv4, Safi::Unicast)],
            false,
            true,
            None,
            false,
            true,
            Vec::new(),
            0,
            Vec::new(),
            Vec::new(),
        );
    }

    /// Register synthetic eBGP route-server clients with the supplied remote
    /// ASNs. All other manager-side grouping inputs remain homogeneous, so the
    /// benchmark isolates exact-export snapshot compatibility at realistic IXP
    /// fanout sizes without changing the established RR fixture above.
    #[must_use]
    pub fn bench_register_route_server_peers<F>(
        &mut self,
        remote_asns: &[u32],
        export_policy: Option<&PolicyChain>,
        channel_capacity: usize,
        make_exact_export_encoder: F,
    ) -> Vec<mpsc::Receiver<OutboundRouteUpdate>>
    where
        F: FnMut(u32) -> Arc<dyn ExactExportEncoder>,
    {
        self.bench_register_peers_with_profile(
            remote_asns.len(),
            export_policy,
            channel_capacity,
            |index| remote_asns[index],
            true,
            false,
            false,
            make_exact_export_encoder,
        )
    }

    /// Register synthetic eBGP route-server clients on the production
    /// per-client-best per-peer fallback. Since the ADR-0126 Phase 3
    /// classifier flip a unicast-only per-client-best peer GROUPS, so the
    /// fallback these fixtures promise requires a non-unicast-only session:
    /// each peer also negotiates VPNv4 (no VPN routes exist in any fixture,
    /// so the wire stays pure IPv4-unicast). The explicit seam keeps the
    /// grouping disqualifier visible instead of adding a positional flag to
    /// callers.
    #[must_use]
    pub fn bench_register_per_client_best_route_server_peers<F>(
        &mut self,
        remote_asns: &[u32],
        export_policy: Option<&PolicyChain>,
        channel_capacity: usize,
        make_exact_export_encoder: F,
    ) -> Vec<mpsc::Receiver<OutboundRouteUpdate>>
    where
        F: FnMut(u32) -> Arc<dyn ExactExportEncoder>,
    {
        self.bench_register_peers_with_profile(
            remote_asns.len(),
            export_policy,
            channel_capacity,
            |index| remote_asns[index],
            true,
            true,
            false,
            make_exact_export_encoder,
        )
    }

    /// Register one synthetic iBGP RR client with negotiated IPv4-unicast
    /// Add-Path send. The returned receiver retains the initial-table route
    /// envelope and `EoR` so the caller can prove the setup inventory before
    /// measuring a replacement pass.
    ///
    /// # Panics
    ///
    /// Panics if `send_max` is zero.
    #[must_use]
    pub fn bench_register_add_path_peer(
        &mut self,
        export_policy: Option<&PolicyChain>,
        send_max: u32,
        channel_capacity: usize,
        exact_export_encoder: Arc<dyn ExactExportEncoder>,
    ) -> mpsc::Receiver<OutboundRouteUpdate> {
        assert!(
            send_max > 0,
            "Add-Path benchmark requires a nonzero send_max"
        );
        let peer = Self::bench_peer_address(0);
        let session_id = 1;
        let (tx, rx) = mpsc::channel(channel_capacity);
        self.pending_peer_export_encoders
            .insert((peer, session_id), exact_export_encoder);
        self.handle_peer_up(
            peer,
            session_id,
            64_512,
            Ipv4Addr::new(192, 0, 2, 1),
            tx,
            export_policy.cloned(),
            vec![(Afi::Ipv4, Safi::Unicast)],
            false,
            true,
            None,
            false,
            true,
            vec![(Afi::Ipv4, Safi::Unicast)],
            send_max,
            Vec::new(),
            Vec::new(),
        );
        rx
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the bench seam keeps each production PeerUp grouping dimension explicit"
    )]
    fn bench_register_peers_with_profile<P, F>(
        &mut self,
        n_peers: usize,
        export_policy: Option<&PolicyChain>,
        channel_capacity: usize,
        mut peer_asn: P,
        is_ebgp: bool,
        per_client_best: bool,
        is_rr_client: bool,
        mut make_exact_export_encoder: F,
    ) -> Vec<mpsc::Receiver<OutboundRouteUpdate>>
    where
        P: FnMut(usize) -> u32,
        F: FnMut(u32) -> Arc<dyn ExactExportEncoder>,
    {
        let mut receivers = Vec::with_capacity(n_peers);
        for i in 0..n_peers {
            // Unique peer address `10.b1.b2.b3` from the index; the high byte is
            // dropped (n_peers far below 2^24 for any bench).
            let idx = u32::try_from(i).expect("bench peer count fits in u32");
            let peer = Self::bench_peer_address(i);
            let session_id = u64::from(idx) + 1;
            let peer_asn = peer_asn(i);
            let (tx, mut rx) = mpsc::channel(channel_capacity);
            self.pending_peer_export_encoders
                .insert((peer, session_id), make_exact_export_encoder(peer_asn));
            // ADR-0126 Decision 1: a unicast-only per-client-best session
            // classifies Groupable, so a per-client-best fixture peer must
            // negotiate a non-unicast-only family to stay on the per-peer
            // fallback these fixtures measure. No fixture seeds VPN routes,
            // so the negotiated-but-empty family never reaches an envelope,
            // a receipt counter, or a family gauge.
            let sendable_families = if per_client_best {
                vec![(Afi::Ipv4, Safi::Unicast), (Afi::Ipv4, Safi::MplsVpn)]
            } else {
                vec![(Afi::Ipv4, Safi::Unicast)]
            };
            self.handle_peer_up(
                peer,
                session_id,
                peer_asn,
                Ipv4Addr::new(192, 0, 2, 1), // shared bgp-id (irrelevant to fanout cost)
                tx,
                export_policy.cloned(),
                sendable_families,
                is_ebgp,
                is_rr_client,
                None, // no ORR vantage
                per_client_best,
                true,       // interpret RFC 1997 (production default)
                Vec::new(), // no Add-Path send
                0,
                Vec::new(), // no negotiated receive-side ORF
                Vec::new(), // no negotiated LLGR families
            );
            // Drain the initial-table dump's End-of-RIB marker so the channel
            // starts empty for the measured fanout pass.
            while rx.try_recv().is_ok() {}
            receivers.push(rx);
        }
        receivers
    }

    /// Drive one production `RoutesReceived` envelope to completion through
    /// the manager dispatcher, bounded route chunks, recompute, distribution,
    /// and every mutation-version fence implemented by the selected git ref.
    /// This synchronous bench seam does not include manager-channel dequeue or
    /// Tokio actor scheduling.
    fn bench_apply_routes_received(
        &mut self,
        peer: IpAddr,
        announced: Vec<Route>,
        withdrawn: Vec<(Prefix, u32)>,
    ) {
        // An unregistered synthetic source deliberately takes the production
        // legacy-producer compatibility branch, whose accepted session stamp
        // is zero. Outbound benchmark peers retain their registered stamps.
        let session_id = self.outbound_session_ids.get(&peer).copied().unwrap_or(0);
        self.handle_update(RibUpdate::RoutesReceived {
            peer,
            session_id,
            announced,
            withdrawn,
            flowspec_announced: Vec::new(),
            flowspec_withdrawn: Vec::new(),
            evpn_announced: Vec::new(),
            evpn_withdrawn: Vec::new(),
        });
        while self.process_next_route_chunk() {}
    }

    /// Seed the Loc-RIB through the production dispatcher/chunk path, grouped
    /// into one envelope per synthetic source peer. A source without an
    /// outbound registration uses the production legacy-unregistered
    /// `session_id = 0` compatibility branch.
    pub fn bench_seed_loc_rib(&mut self, routes: Vec<Route>) {
        let mut by_peer: BTreeMap<IpAddr, Vec<Route>> = BTreeMap::new();
        for route in routes {
            by_peer.entry(route.peer).or_default().push(route);
        }
        for (peer, announced) in by_peer {
            self.bench_apply_routes_received(peer, announced, Vec::new());
        }
    }

    /// Withdraw a prepared unicast inventory through one production
    /// `RoutesReceived` envelope. Callers build the owned withdrawal vector
    /// before starting their timer so the measured interval begins at the
    /// manager dispatcher and ends after its bounded route-chunk, recompute,
    /// and distribution work drains. Manager-channel dequeue and Tokio actor
    /// scheduling are outside this synchronous benchmark.
    pub fn bench_withdraw_loc_rib(&mut self, peer: IpAddr, withdrawn: Vec<(Prefix, u32)>) {
        self.bench_apply_routes_received(peer, Vec::new(), withdrawn);
    }

    /// Withdraw and re-announce an existing unicast subset through production
    /// `RoutesReceived` envelopes. The final table is identical to the input
    /// fixture, so traversal remains a checksum oracle while the timed control
    /// includes each ref's actual chunking and invalidation behavior.
    ///
    /// # Panics
    ///
    /// Panics if a requested fixture route was not present in its source
    /// Adj-RIB-In; that would make the churn control incomparable.
    pub fn bench_churn_loc_rib(&mut self, routes: Vec<Route>) {
        let mut by_peer: BTreeMap<IpAddr, Vec<Route>> = BTreeMap::new();
        for route in routes {
            by_peer.entry(route.peer).or_default().push(route);
        }
        for (&peer, peer_routes) in &by_peer {
            let withdrawn = peer_routes
                .iter()
                .map(|route| (route.prefix, route.path_id))
                .collect();
            self.bench_apply_routes_received(peer, Vec::new(), withdrawn);
        }
        for (peer, announced) in by_peer {
            self.bench_apply_routes_received(peer, announced, Vec::new());
        }
    }

    /// Fan `changed` out to every registered peer — the measured hot path. Both
    /// `distribute_changes` arguments are `changed`: for the bench's single-best,
    /// no-Add-Path peers, best-changed and affected are the same set.
    pub fn bench_distribute(&mut self, changed: &HashSet<Prefix>) {
        self.distribute_changes(changed, changed);
    }

    /// Replace existing unicast routes in their source Adj-RIB-In and
    /// recompute Loc-RIB without distributing the change. This fixture-only
    /// seam puts a real wire-visible change immediately in front of the timed
    /// production distribution path; setup, interning, and recompute remain
    /// outside the accumulated duration.
    ///
    /// # Panics
    ///
    /// Panics if a source Adj-RIB-In is absent or the replacement does not
    /// change every requested Loc-RIB best.
    #[must_use]
    pub fn bench_prepare_unicast_replacement(&mut self, routes: Vec<Route>) -> HashSet<Prefix> {
        let expected = routes.len();
        let mut by_peer: BTreeMap<IpAddr, Vec<Route>> = BTreeMap::new();
        for route in routes {
            by_peer.entry(route.peer).or_default().push(route);
        }

        let mut changed = HashSet::new();
        for (peer, mut routes) in by_peer {
            let mut affected = HashSet::with_capacity(routes.len());
            for route in &mut routes {
                self.attr_intern.intern(&mut route.attributes);
                affected.insert(route.prefix);
            }
            let rib = self
                .ribs
                .get_mut(&peer)
                .expect("benchmark source Adj-RIB-In remains registered");
            for route in routes {
                rib.insert(route);
            }
            for prefix in &affected {
                self.register_unicast_announcer(peer, *prefix);
            }
            changed.extend(self.recompute_best_after_announce(peer, &affected));
        }
        assert_eq!(
            changed.len(),
            expected,
            "every benchmark replacement must change its Loc-RIB best"
        );
        changed
    }

    /// Replace a multi-path prefix's complete candidate inventory without
    /// distributing it. Unlike the single-best replacement helper, every
    /// candidate may change while the selected best remains stable.
    ///
    /// # Panics
    ///
    /// Panics if any replacement's source `AdjRibIn` is absent.
    #[must_use]
    pub fn bench_prepare_multipath_replacement(&mut self, routes: Vec<Route>) -> HashSet<Prefix> {
        let mut by_peer: BTreeMap<IpAddr, Vec<Route>> = BTreeMap::new();
        let mut affected = HashSet::new();
        for route in routes {
            affected.insert(route.prefix);
            by_peer.entry(route.peer).or_default().push(route);
        }
        for (peer, mut routes) in by_peer {
            let mut peer_affected = HashSet::with_capacity(routes.len());
            for route in &mut routes {
                self.attr_intern.intern(&mut route.attributes);
                peer_affected.insert(route.prefix);
            }
            let rib = self
                .ribs
                .get_mut(&peer)
                .expect("benchmark source Adj-RIB-In remains registered");
            for route in routes {
                rib.insert(route);
            }
            for prefix in &peer_affected {
                self.register_unicast_announcer(peer, *prefix);
            }
            let _ = self.recompute_best_after_announce(peer, &peer_affected);
        }
        affected
    }

    /// Count the production Adj-RIB-In candidates for `prefix` through the
    /// same reverse-index collector used by Add-Path selection.
    #[must_use]
    pub fn bench_unicast_candidate_count(&self, prefix: Prefix) -> usize {
        Self::unicast_candidates(&self.ribs, &self.unicast_prefix_peers, &prefix).count()
    }

    /// Reset the production-path counters immediately before one measured
    /// fanout pass.
    pub fn bench_reset_adj_rib_out_fanout_receipt(&mut self) {
        self.adj_rib_out_commit_stats = super::AdjRibOutCommitStats::default();
    }

    /// Reset the feature-gated per-client-best full-resync instrumentation.
    pub fn bench_reset_per_client_best_resync_receipt(&mut self) {
        PCB_CANDIDATE_AGGREGATE.set(PerClientBestCandidateBenchAggregate::active());
        for counter in [
            &PCB_ENUMERATION_PHASES,
            &PCB_ENUMERATED_PREFIXES,
            &PCB_STAGING_PHASES,
            &PCB_STAGING_PREFIXES,
            &PCB_EXACT_PHASES,
            &PCB_COMMIT_PHASES,
            &PCB_ENQUEUE_PHASES,
        ] {
            counter.store(0, Ordering::Relaxed);
        }
        for total in [
            &PCB_TOTAL_ENUMERATION_NANOS,
            &PCB_TOTAL_STAGING_NANOS,
            &PCB_TOTAL_EXACT_NANOS,
            &PCB_TOTAL_COMMIT_NANOS,
            &PCB_TOTAL_ENQUEUE_NANOS,
        ] {
            total.store(0, Ordering::Relaxed);
        }
    }

    /// Capture the most recent per-client-best full-resync phase and residue
    /// proof. The returned non-`Eq` receipt deliberately carries durations.
    #[must_use]
    pub fn bench_per_client_best_resync_receipt(&self) -> PerClientBestResyncBenchReceipt {
        let candidates = PCB_CANDIDATE_AGGREGATE.get();
        PCB_CANDIDATE_AGGREGATE.set(PerClientBestCandidateBenchAggregate {
            capture_active: false,
            ..candidates
        });
        let load = |counter: &AtomicUsize| counter.load(Ordering::Relaxed);
        let duration =
            |total: &AtomicU64| std::time::Duration::from_nanos(total.load(Ordering::Relaxed));
        PerClientBestResyncBenchReceipt {
            candidate_prefix_visits: candidates.prefix_visits,
            empty_candidate_sets: candidates.empty_sets,
            singleton_candidate_sets: candidates.singleton_sets,
            multi_candidate_sets: candidates.multi_sets,
            heap_backed_candidate_collections: candidates.heap_backed_collections,
            enumeration_phases: load(&PCB_ENUMERATION_PHASES),
            enumerated_prefixes: load(&PCB_ENUMERATED_PREFIXES),
            staging_phases: load(&PCB_STAGING_PHASES),
            staging_prefixes: load(&PCB_STAGING_PREFIXES),
            exact_phases: load(&PCB_EXACT_PHASES),
            commit_phases: load(&PCB_COMMIT_PHASES),
            enqueue_phases: load(&PCB_ENQUEUE_PHASES),
            total_enumeration: duration(&PCB_TOTAL_ENUMERATION_NANOS),
            total_staging: duration(&PCB_TOTAL_STAGING_NANOS),
            total_exact_build_and_encode: duration(&PCB_TOTAL_EXACT_NANOS),
            total_private_commit: duration(&PCB_TOTAL_COMMIT_NANOS),
            total_enqueue: duration(&PCB_TOTAL_ENQUEUE_NANOS),
            pending_regroup_baselines: self.pending_regroup_baseline.len(),
            pending_extra_withdraw_peers: self.pending_extra_withdraws.len(),
            pending_exact_export_withdrawals: self.pending_exact_export_withdrawals.len(),
            exact_export_rejection_peers: self.peer_unexportable.len(),
            outbound_prefix_limit_peers: self.outbound_prefix_limits.len(),
            forced_resync_peers: self.force_outbound_peers.len(),
        }
    }

    /// Capture production-path and current metric evidence after one measured
    /// fanout pass.
    #[must_use]
    pub fn bench_adj_rib_out_fanout_receipt(&self) -> AdjRibOutFanoutBenchReceipt {
        use super::update_groups::GroupMembership;

        let group_ids = self
            .update_groups
            .members
            .values()
            .filter_map(|membership| match membership {
                GroupMembership::Grouped(group_id) => Some(*group_id),
                _ => None,
            })
            .collect::<HashSet<_>>();
        let grouped_peers = self
            .update_groups
            .members
            .values()
            .filter(|membership| matches!(membership, GroupMembership::Grouped(_)))
            .count();
        let stats = self.adj_rib_out_commit_stats;
        AdjRibOutFanoutBenchReceipt {
            update_groups: group_ids.len(),
            grouped_peers,
            ungrouped_peers: self
                .update_groups
                .members
                .len()
                .saturating_sub(grouped_peers),
            dirty_peers: self.dirty_peers.len(),
            grouped_unicast_routes: self
                .group_ribs
                .values()
                .map(|group| group.table.len())
                .sum(),
            private_unicast_routes: self
                .adj_ribs_out
                .values()
                .map(super::super::adj_rib_out::AdjRibOut::len)
                .sum(),
            routes_received_dispatches: stats.routes_received_dispatches,
            routes_received_withdrawals: stats.routes_received_withdrawals,
            exact_probe_batches: stats.exact_probe_batches,
            exact_probe_candidates: stats.exact_probe_candidates,
            exact_probe_nonzero_encoded_lengths: stats.exact_probe_nonzero_encoded_lengths,
            exact_probe_cache_reuses: stats.exact_probe_cache_reuses,
            successful_commits: stats.successful_commits,
            successful_enqueues: stats.successful_enqueues,
            family_gauge_writes: stats.family_gauge_writes,
            last_family_gauge_write_mask: stats.last_family_gauge_write_mask,
            pristine_otc_reconcile_candidates: stats.pristine_otc_reconcile_candidates,
            private_extra_prefix_scans: stats.private_extra_prefix_scans,
            first_peer_family_values: self
                .bench_adj_rib_out_family_values(Self::bench_peer_address(0)),
        }
    }

    #[expect(
        clippy::cast_possible_truncation,
        reason = "benchmark fixture gauge counts are exact small nonnegative integers"
    )]
    fn bench_adj_rib_out_family_values(&self, peer: IpAddr) -> [i64; 7] {
        const FAMILIES: [&str; 7] = ["all", "flowspec", "evpn", "bgpls", "vpn", "labeled", "rtc"];
        let peer_label = peer.to_string();
        let gathered = self.metrics.registry().gather();
        let Some(gauge) = gathered
            .iter()
            .find(|family| family.name() == "bgp_rib_adj_out_prefixes")
        else {
            return [0; 7];
        };
        std::array::from_fn(|index| {
            gauge
                .metric
                .iter()
                .find(|metric| {
                    metric
                        .get_label()
                        .iter()
                        .any(|label| label.name() == "peer" && label.value() == peer_label)
                        && metric.get_label().iter().any(|label| {
                            label.name() == "afi_safi" && label.value() == FAMILIES[index]
                        })
                })
                .map_or(0, |metric| metric.get_gauge().value() as i64)
        })
    }

    /// Apply one export-policy replacement to every synthetic peer through
    /// the shared clean-transition seam. Returns whether the fast path was
    /// selected.
    ///
    /// # Panics
    ///
    /// Panics if the fast path falls back and any of the first `n_peers`
    /// synthetic peers was not registered by the benchmark fixture.
    pub fn bench_replace_export_policy_cohort(
        &mut self,
        n_peers: usize,
        export_policy: &PolicyChain,
    ) -> bool {
        self.policy_transition_stats = super::PolicyTransitionStats::default();
        let replacements = (0..n_peers)
            .map(|index| PeerExportPolicyReplacement {
                peer: Self::bench_peer_address(index),
                export_policy: Some(export_policy.clone()),
            })
            .collect::<Vec<_>>();
        let fast = self.try_clean_group_policy_transition(&replacements);
        if !fast {
            for replacement in replacements {
                self.bench_apply_authoritative_export_policy(
                    replacement.peer,
                    replacement.export_policy,
                );
            }
        }
        self.bench_maybe_print_policy_transition_receipt(n_peers, fast);
        fast
    }

    fn bench_apply_authoritative_export_policy(
        &mut self,
        peer: IpAddr,
        export_policy: Option<PolicyChain>,
    ) {
        let started = std::time::Instant::now();
        self.replace_peer_export_policy_synchronously(peer, export_policy)
            .expect("synthetic peer remains registered");
        let elapsed = started.elapsed();
        self.policy_transition_stats.authoritative_peer_applies = self
            .policy_transition_stats
            .authoritative_peer_applies
            .saturating_add(1);
        self.policy_transition_stats.max_authoritative_peer_apply = self
            .policy_transition_stats
            .max_authoritative_peer_apply
            .max(elapsed);
    }

    fn bench_maybe_print_policy_transition_receipt(&self, n_peers: usize, fast: bool) {
        if std::env::var_os("RUSTBGPD_POLICY_TRANSITION_RECEIPT").is_some()
            && !POLICY_TRANSITION_RECEIPT_PRINTED.swap(true, Ordering::Relaxed)
        {
            let receipt = self.bench_policy_transition_receipt();
            eprintln!(
                "policy_transition_receipt peers={n_peers} fast={fast} plans={} \
                 full_exact_probes={} route_shell_materializations={} actor_polls={} \
                 max_actor_poll_ns={} max_prefix_snapshot_poll_ns={} max_finalize_poll_ns={} \
                 max_commit_poll_ns={} \
                 authoritative_peer_applies={} max_authoritative_peer_apply_ns={} \
                 max_uninterrupted_work_ns={}",
                receipt.plan_builds,
                receipt.full_exact_probes,
                receipt.route_shell_materializations,
                receipt.actor_polls,
                receipt.max_actor_poll.as_nanos(),
                receipt.max_prefix_snapshot_poll.as_nanos(),
                receipt.max_finalize_poll.as_nanos(),
                receipt.max_commit_poll.as_nanos(),
                receipt.authoritative_peer_applies,
                receipt.max_authoritative_peer_apply.as_nanos(),
                receipt.max_uninterrupted_work.as_nanos(),
            );
        }
    }

    /// Authoritative old path for A/B policy-regroup measurements.
    ///
    /// # Panics
    ///
    /// Panics if any of the first `n_peers` synthetic peers was not registered
    /// by the benchmark fixture.
    pub fn bench_replace_export_policy_per_peer(
        &mut self,
        n_peers: usize,
        export_policy: &PolicyChain,
    ) {
        self.policy_transition_stats = super::PolicyTransitionStats::default();
        for index in 0..n_peers {
            self.bench_apply_authoritative_export_policy(
                Self::bench_peer_address(index),
                Some(export_policy.clone()),
            );
        }
        self.bench_maybe_print_policy_transition_receipt(n_peers, false);
    }

    /// Production state-machine instrumentation from the most recent shared
    /// transition.
    #[must_use]
    pub fn bench_policy_transition_receipt(&self) -> PolicyTransitionBenchReceipt {
        let stats = self.policy_transition_stats;
        PolicyTransitionBenchReceipt {
            plan_builds: stats.plan_builds,
            full_exact_probes: stats.full_exact_probes,
            route_shell_materializations: stats.route_shell_materializations,
            actor_polls: stats.actor_polls,
            max_actor_poll: stats.max_actor_slice,
            max_prefix_snapshot_poll: stats.max_prefix_snapshot_poll,
            max_finalize_poll: stats.max_finalize_poll,
            max_commit_poll: stats.max_commit_poll,
            authoritative_peer_applies: stats.authoritative_peer_applies,
            max_authoritative_peer_apply: stats.max_authoritative_peer_apply,
            max_uninterrupted_work: stats
                .max_actor_slice
                .max(stats.max_authoritative_peer_apply),
        }
    }

    /// Drive the production paged-query handler synchronously and return its
    /// reply. The benchmark deliberately includes the oneshot boundary while
    /// excluding async task scheduling noise.
    ///
    /// # Panics
    ///
    /// Panics if the production handler stops replying synchronously; that
    /// would invalidate this benchmark's synchronous handler-boundary model.
    #[must_use]
    pub fn bench_query_route_page(
        &mut self,
        scope: RouteQueryScope,
        after: Option<RouteQueryKey>,
        page_size: usize,
    ) -> RoutePage {
        let (reply, mut response) = oneshot::channel();
        self.handle_query_routes_page(scope, None, after, page_size, reply);
        response
            .try_recv()
            .expect("route page handler replies synchronously")
    }

    /// Publish an owned batch through the production route-event helper.
    ///
    /// Input construction belongs in the benchmark setup closure. Consuming
    /// the batch here keeps event cloning out of the timed manager phase while
    /// retaining the real process-local ID, ring, sink, and legacy-broadcast
    /// work performed by `RibManager::publish_route_event`.
    pub fn bench_publish_route_events(&mut self, events: impl IntoIterator<Item = RouteEvent>) {
        for event in events {
            self.publish_route_event(event);
        }
    }

    /// Publish an owned batch through the production EVPN-event helper.
    ///
    /// Like [`Self::bench_publish_route_events`], this method exists only under
    /// `bench-internals` and deliberately adds no alternate production path.
    pub fn bench_publish_evpn_events(&mut self, events: impl IntoIterator<Item = EvpnRouteEvent>) {
        for event in events {
            self.publish_evpn_route_event(event);
        }
    }
}
