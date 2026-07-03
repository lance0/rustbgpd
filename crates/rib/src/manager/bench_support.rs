//! Bench-only fanout driver.
//!
//! Exposed solely to the `fanout` distribution microbench behind the
//! `bench-internals` feature (set via `required-features` on the bench target).
//! The `pub fn bench_*` methods join the crate's public surface only when that
//! feature is enabled; in a normal (default-feature) build the whole module is
//! compiled out and nothing here is reachable.
//!
//! The driver registers N synthetic outbound peers, seeds the Loc-RIB, and runs
//! the manager's `distribute_changes` directly, so the bench measures the
//! per-peer export fanout cost (policy eval + Adj-RIB-Out staging + bounded
//! channel send) without the async `run()` task loop in the way.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr};

use rustbgpd_policy::PolicyChain;
use rustbgpd_wire::{Afi, Prefix, Safi};
use tokio::sync::mpsc;

use super::RibManager;
use crate::adj_rib_in::AdjRibIn;
use crate::route::Route;
use crate::update::OutboundRouteUpdate;

impl RibManager {
    /// Register `n_peers` synthetic iBGP outbound peers (`10.a.b.c`), each
    /// cloning `export_policy` and advertising IPv4 unicast. Returns the peer
    /// receivers; the caller MUST hold them so the bounded channels stay open —
    /// a full or closed channel drops the fanout onto the dirty-peer resync path
    /// and stops measuring the steady-state advertise cost. Each registration's
    /// initial-table dump enqueues an End-of-RIB marker (even for an empty
    /// Loc-RIB); that marker is drained here so the channels genuinely start
    /// empty for the measured pass, independent of `channel_capacity`.
    ///
    /// # Panics
    /// If `n_peers` exceeds `u32::MAX` — far beyond any realistic bench.
    #[must_use]
    pub fn bench_register_peers(
        &mut self,
        n_peers: usize,
        export_policy: Option<&PolicyChain>,
        is_rr_client: bool,
        channel_capacity: usize,
    ) -> Vec<mpsc::Receiver<OutboundRouteUpdate>> {
        let mut receivers = Vec::with_capacity(n_peers);
        for i in 0..n_peers {
            // Unique peer address `10.b1.b2.b3` from the index; the high byte is
            // dropped (n_peers far below 2^24 for any bench).
            let idx = u32::try_from(i).expect("bench peer count fits in u32");
            let [_, b1, b2, b3] = idx.to_be_bytes();
            let peer = IpAddr::V4(Ipv4Addr::new(10, b1, b2, b3));
            let (tx, mut rx) = mpsc::channel(channel_capacity);
            self.handle_peer_up(
                peer,
                u64::from(idx) + 1,          // synthetic session id
                64_512,                      // iBGP — all peers share the local ASN
                Ipv4Addr::new(192, 0, 2, 1), // shared bgp-id (irrelevant to fanout cost)
                tx,
                export_policy.cloned(),
                vec![(Afi::Ipv4, Safi::Unicast)],
                false, // is_ebgp = false (iBGP / route-reflector scenario)
                is_rr_client,
                None,       // no ORR vantage
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

    /// Seed the Loc-RIB by inserting `routes` from one synthetic inbound peer and
    /// recomputing best paths, so [`RibManager::bench_distribute`] has a
    /// populated table to fan out. Call AFTER [`RibManager::bench_register_peers`]
    /// so the initial-table dump sees an empty Loc-RIB (it then emits only the
    /// drained `EoR` marker, no route announces).
    pub fn bench_seed_loc_rib(&mut self, routes: Vec<Route>) {
        let source = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1));
        let rib = self
            .ribs
            .entry(source)
            .or_insert_with(|| AdjRibIn::new(source));
        let mut affected = HashSet::with_capacity(routes.len());
        for route in routes {
            affected.insert(route.prefix);
            rib.insert(route);
        }
        for prefix in &affected {
            self.register_unicast_announcer(source, *prefix);
        }
        self.recompute_best(&affected);
    }

    /// Fan `changed` out to every registered peer — the measured hot path. Both
    /// `distribute_changes` arguments are `changed`: for the bench's single-best,
    /// no-Add-Path peers, best-changed and affected are the same set.
    pub fn bench_distribute(&mut self, changed: &HashSet<Prefix>) {
        self.distribute_changes(changed, changed);
    }
}
