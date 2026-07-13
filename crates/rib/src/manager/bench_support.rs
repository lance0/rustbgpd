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

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use rustbgpd_policy::PolicyChain;
use rustbgpd_wire::{Afi, Prefix, Safi};
use tokio::sync::{mpsc, oneshot};

use super::RibManager;
use crate::adj_rib_in::AdjRibIn;
use crate::event::{EvpnRouteEvent, RouteEvent};
use crate::route::Route;
use crate::update::{
    ExactExportEncoder, OutboundRouteUpdate, PeerExportPolicyReplacement, RoutePage, RouteQueryKey,
    RouteQueryScope,
};

static POLICY_TRANSITION_RECEIPT_PRINTED: AtomicBool = AtomicBool::new(false);

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
    pub authoritative_peer_applies: usize,
    pub max_authoritative_peer_apply: std::time::Duration,
    pub max_uninterrupted_work: std::time::Duration,
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
            is_rr_client,
            |_| make_exact_export_encoder(),
        )
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
            make_exact_export_encoder,
        )
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
            self.handle_peer_up(
                peer,
                session_id,
                peer_asn,
                Ipv4Addr::new(192, 0, 2, 1), // shared bgp-id (irrelevant to fanout cost)
                tx,
                export_policy.cloned(),
                vec![(Afi::Ipv4, Safi::Unicast)],
                is_ebgp,
                is_rr_client,
                None,       // no ORR vantage
                false,      // no per-client best (RS mode)
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

    /// Seed the Loc-RIB by inserting each route under its declared source peer
    /// and recomputing best paths, so [`RibManager::bench_distribute`] has a
    /// populated table to fan out. Call AFTER [`RibManager::bench_register_peers`]
    /// so the initial-table dump sees an empty Loc-RIB (it then emits only the
    /// drained `EoR` marker, no route announces).
    pub fn bench_seed_loc_rib(&mut self, routes: Vec<Route>) {
        let mut affected = HashSet::with_capacity(routes.len());
        let mut announcers = HashSet::with_capacity(routes.len());
        for mut route in routes {
            let source = route.peer;
            affected.insert(route.prefix);
            announcers.insert((source, route.prefix));
            self.attr_intern.intern(&mut route.attributes);
            self.ribs
                .entry(source)
                .or_insert_with(|| AdjRibIn::new(source))
                .insert(route);
        }
        for (source, prefix) in announcers {
            self.register_unicast_announcer(source, prefix);
        }
        self.recompute_best(&affected);
    }

    /// Fan `changed` out to every registered peer — the measured hot path. Both
    /// `distribute_changes` arguments are `changed`: for the bench's single-best,
    /// no-Add-Path peers, best-changed and affected are the same set.
    pub fn bench_distribute(&mut self, changed: &HashSet<Prefix>) {
        self.distribute_changes(changed, changed);
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
                 authoritative_peer_applies={} max_authoritative_peer_apply_ns={} \
                 max_uninterrupted_work_ns={}",
                receipt.plan_builds,
                receipt.full_exact_probes,
                receipt.route_shell_materializations,
                receipt.actor_polls,
                receipt.max_actor_poll.as_nanos(),
                receipt.max_prefix_snapshot_poll.as_nanos(),
                receipt.max_finalize_poll.as_nanos(),
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
