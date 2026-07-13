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

use rustbgpd_policy::PolicyChain;
use rustbgpd_wire::{Afi, Prefix, Safi};
use tokio::sync::{mpsc, oneshot};

use super::RibManager;
use crate::adj_rib_in::AdjRibIn;
use crate::event::{EvpnRouteEvent, RouteEvent};
use crate::route::Route;
use crate::update::{
    ExactExportEncoder, OutboundRouteUpdate, RoutePage, RouteQueryKey, RouteQueryScope,
};

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
        let mut receivers = Vec::with_capacity(n_peers);
        for i in 0..n_peers {
            // Unique peer address `10.b1.b2.b3` from the index; the high byte is
            // dropped (n_peers far below 2^24 for any bench).
            let idx = u32::try_from(i).expect("bench peer count fits in u32");
            let peer = Self::bench_peer_address(i);
            let session_id = u64::from(idx) + 1;
            let (tx, mut rx) = mpsc::channel(channel_capacity);
            self.pending_peer_export_encoders
                .insert((peer, session_id), make_exact_export_encoder());
            self.handle_peer_up(
                peer,
                session_id,
                64_512,                      // iBGP — all peers share the local ASN
                Ipv4Addr::new(192, 0, 2, 1), // shared bgp-id (irrelevant to fanout cost)
                tx,
                export_policy.cloned(),
                vec![(Afi::Ipv4, Safi::Unicast)],
                false, // is_ebgp = false (iBGP / route-reflector scenario)
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
