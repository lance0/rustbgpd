//! Linux netlink dataplane implementation — Gate 7b.
//!
//! Implements the [`crate::Dataplane`] trait against the `rtnetlink`
//! and `netlink-packet-route` crates (versions pinned in
//! `crates/evpn-linux/Cargo.toml`). Three private submodules:
//!
//! - `fdb` — bridge FDB dump + program/withdraw via `RTM_NEWNEIGH` /
//!   `RTM_DELNEIGH` with `NTF_EXT_LEARNED` and `NUD_NOARP` /
//!   `NUD_PERMANENT` so the entry is non-expiring.
//! - `links` — bridge + VXLAN inventory via `LinkHandle::get`. Used
//!   by `probe` to resolve bridge names to ifindex, validate VXLAN
//!   port attachment, and reject VLAN-aware bridges (ADR-0054 §4).
//! - `probe` — per-instance readiness checks. Returns
//!   [`crate::InstanceProbe::Ready`] only when the operator-built
//!   topology matches the [`rustbgpd_evpn::EvpnInstance`] expectations.
//!
//! The trait's `next_event` still returns `pending()` for reconcile-
//! trigger events; the reconcile actor falls back to its 60 s periodic
//! dump cadence, so kernel drift is repaired structurally rather than
//! through edge-triggered notifications. `RTNLGRP_NEIGH` is active for
//! local-MAC observations through the dedicated
//! [`crate::Dataplane::take_local_mac_rx`] channel. `RTNLGRP_LINK` and
//! reconcile-trigger subscriptions remain follow-up work.
//!
//! ## Failure semantics
//!
//! - `connect()` failures (no netlink socket, missing permissions)
//!   surface as `DataplaneError::Io`. The daemon's spawn site catches
//!   this and logs at `warn!` without crashing — the EVPN dataplane
//!   becomes a no-op rather than wedging the whole daemon.
//! - `apply()` failures bubble up per-op so the actor's backoff
//!   schedule retries individual ops.
//! - `probe()` never fails; a kernel that can't be queried surfaces
//!   as `NotReady` with a "kernel inventory dump failed" reason.

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::Arc;

use futures::StreamExt;
use netlink_packet_core::NetlinkPayload;
use netlink_packet_route::RouteNetlinkMessage;
use netlink_sys::AsyncSocket;
use rtnetlink::Handle;
use rustbgpd_evpn::ip_vrf::{
    IpVrfNotReady, IpVrfRouteDump, IpVrfStatus, IpVrfTable, probe as probe_ip_vrf,
};
use rustbgpd_evpn::{EvpnInstanceTable, IpVrfId, LocalMacObservation, MacAddress};
use tokio::sync::{Mutex, mpsc};
use tracing::warn;

use crate::dataplane::{Dataplane, DataplaneOp, KernelEvent};
use crate::error::DataplaneError;
use crate::snapshot::{InstanceProbes, KernelSnapshot};

mod bum_filter;
mod fdb;
mod fdb_nhg;
mod ip_vrf;
mod l3;
mod links;
pub mod nexthop_raw;
mod notify;
mod probe;
mod routes;

type ObservationDropHook = Arc<dyn Fn(&'static str) + Send + Sync + 'static>;
const IP_NEIGHBOUR_MAC_CACHE_LIMIT: usize = 16_384;

/// Linux-only dataplane impl backed by `rtnetlink`.
///
/// The struct holds the `rtnetlink::Handle` and a mutex-guarded link
/// inventory cache. The cache is refreshed on every `dump_snapshot` so
/// `probe()` and the FDB dump pass see consistent state.
pub struct LinuxDataplane {
    handle: Handle,
    /// Last full link inventory from a successful dump. `probe` reads
    /// this to resolve bridge names to ifindex without hammering
    /// netlink. Wrapped in `Mutex` because the trait methods take
    /// `&mut self` so we already serialize, but `probe` and
    /// `dump_snapshot` both write here from the same actor task — the lock
    /// makes future concurrency easy if the actor ever splits.
    link_cache: Arc<Mutex<links::LinkCache>>,
    /// Upward `LocalMacObservation` channel receiver, taken once via
    /// [`Dataplane::take_local_mac_rx`] and handed to the daemon's
    /// originator. `Some` while the dataplane owns it; `None` after
    /// the daemon takes ownership. The matching sender is held by the
    /// background notify task spawned in [`Self::connect`].
    local_mac_rx: Option<mpsc::Receiver<LocalMacObservation>>,
    /// Upward `KernelEvent` channel for the reconcile actor's
    /// [`Dataplane::next_event`]. The notify task pushes
    /// [`KernelEvent::KernelStateChanged`] here when an
    /// `RTNLGRP_IPV4_ROUTE` / `RTNLGRP_IPV6_ROUTE` message survives
    /// [`notify::classify_route`], so withdraws on operator
    /// `ip addr del` (or any custom-table route change) reach the
    /// actor within milliseconds instead of waiting for the periodic
    /// dump cycle.
    kernel_event_rx: mpsc::Receiver<KernelEvent>,
    /// Dedicated `NETLINK_ROUTE` socket for ADR-0059 FDB nexthop
    /// group programming. Distinct from `handle` so nexthop traffic
    /// doesn't compete with FDB/link/route requests on the primary
    /// socket. Slice 2 (`nexthop_raw::NexthopSocket`) supplies the
    /// underlying primitive; slice 3b uses it via `NexthopOps`.
    nexthop_socket: nexthop_raw::NexthopSocket,
}

impl LinuxDataplane {
    /// Open a netlink socket and spawn the rtnetlink connection task.
    /// Returns `Err` if the kernel rejects the socket (no
    /// `CAP_NET_ADMIN`, `AF_NETLINK` unavailable, etc.). The daemon's
    /// spawn path catches this and logs `warn!` rather than crashing
    /// the daemon.
    ///
    /// # Errors
    /// Returns [`DataplaneError::Io`] if `rtnetlink::new_connection`
    /// fails.
    pub async fn connect() -> Result<Self, DataplaneError> {
        Self::connect_with_observation_drop_hook(|_| {}).await
    }

    /// Open a netlink socket and install a hook called whenever a
    /// classified local-MAC observation cannot be forwarded to the
    /// daemon originator.
    ///
    /// The hook keeps `rustbgpd-evpn-linux` independent of the
    /// daemon's telemetry crate while still allowing the binary to
    /// attach Prometheus accounting at the boundary.
    ///
    /// # Errors
    /// Returns [`DataplaneError::Io`] if `rtnetlink::new_connection`
    /// fails.
    pub async fn connect_with_observation_drop_hook<F>(
        on_observation_drop: F,
    ) -> Result<Self, DataplaneError>
    where
        F: Fn(&'static str) + Send + Sync + 'static,
    {
        let (mut connection, handle, messages) =
            rtnetlink::new_connection().map_err(DataplaneError::Io)?;

        // Subscribe to RTNLGRP_NEIGH + RTNLGRP_IPV4_ROUTE +
        // RTNLGRP_IPV6_ROUTE on the same socket that carries our
        // solicited dump/program traffic. `add_membership` is a
        // synchronous setsockopt call, so it must happen before we
        // hand the connection to the runtime via `tokio::spawn`.
        // Failure on any subscription is logged but non-fatal — the
        // dataplane still works for downward programming, just with
        // the corresponding upward feed silent.
        //
        // - `RTNLGRP_NEIGH` (id 3) feeds the slice 6a/6b local-MAC
        //   observation pipeline.
        // - `RTNLGRP_IPV4_ROUTE` (7) + `RTNLGRP_IPV6_ROUTE` (11)
        //   feed the slice 6a kernel-event channel so `ip addr del`
        //   / `ip route add ... table N` in an IP-VRF's custom
        //   table refreshes the IP-VRF route observation within
        //   ~50 ms instead of waiting for the actor's 60 s
        //   periodic dump. The downstream Type 5 withdraw (slice
        //   6b origination) and any L3 FIB cleanup (slice 6c
        //   install) ride off the same reconcile pass. (5 and 7
        //   would be `RTNLGRP_IPV4_IFADDR` / `RTNLGRP_IPV4_ROUTE` —
        //   the off-by-one is exactly what `notify::tests::
        //   route_rtnlgrp_constants_match_kernel_enum_values`
        //   guards against.)
        for (group, name) in [
            (notify::RTNLGRP_NEIGH, "RTNLGRP_NEIGH"),
            (notify::RTNLGRP_IPV4_ROUTE, "RTNLGRP_IPV4_ROUTE"),
            (notify::RTNLGRP_IPV6_ROUTE, "RTNLGRP_IPV6_ROUTE"),
        ] {
            if let Err(e) = connection.socket_mut().socket_mut().add_membership(group) {
                warn!(
                    error = %e,
                    group_name = name,
                    "rtnetlink multicast subscription failed; corresponding upward feed will be silent"
                );
            }
        }

        // Spawn the netlink connection driver. rtnetlink's design has
        // the connection task read/write the netlink socket while the
        // Handle issues commands; both must run for any request to
        // make progress.
        tokio::spawn(connection);

        let link_cache: Arc<Mutex<links::LinkCache>> =
            Arc::new(Mutex::new(links::LinkCache::default()));

        // Prime the link cache with one synchronous dump_links pass
        // BEFORE spawning the notify loop. The notify classifier
        // resolves a bridge-port ifindex to a VNI via
        // `LinkCache::bridge_port_to_vni`; if the cache is empty when
        // an early RTM_NEWNEIGH arrives (which it is, by default —
        // the supervisor's polling cycle is what would normally
        // populate it), the event drops silently. A startup-time
        // dump closes the race.
        //
        // **Bounded with a 2 s timeout**: this runs on the daemon's
        // startup critical path before gRPC, listener, peers, etc.,
        // so a stuck rtnetlink dump must not wedge the whole boot.
        // The prime is best-effort — the supervisor's periodic dump
        // will repopulate the cache within 5 s of the timeout, so
        // the worst case is a brief window where early local-MAC
        // events miss-and-drop.
        match tokio::time::timeout(
            std::time::Duration::from_secs(2),
            links::dump_links(&handle),
        )
        .await
        {
            Ok(Ok(cache)) => {
                *link_cache.lock().await = cache;
                tracing::debug!("primed link cache for RTNLGRP_NEIGH classifier");
            }
            Ok(Err(e)) => {
                warn!(
                    error = %e,
                    "initial link cache prime failed; early local-MAC events may drop until supervisor's first dump"
                );
            }
            Err(_) => {
                warn!(
                    "initial link cache prime timed out after 2s; continuing startup — \
                     supervisor's periodic dump will populate the cache shortly"
                );
            }
        }

        // 1024-slot upward channel — matches the bound the daemon
        // originator advertises in its module docs. Overflow is
        // treated as harmless drop because the level-triggered
        // reconcile model recovers via the periodic dump cadence.
        let (local_mac_tx, local_mac_rx) = mpsc::channel(1024);
        // Smaller (64-slot) channel for the kernel-event wake feed.
        // The reconcile actor's coalesce window folds bursts into a
        // single pass, so back-pressure here is irrelevant — what
        // matters is the next reconcile pass running, not the queue
        // depth. Overflow drops silently and the next periodic dump
        // recovers regardless.
        let (kernel_event_tx, kernel_event_rx) = mpsc::channel(64);
        let cache_for_notify = Arc::clone(&link_cache);
        let on_observation_drop: ObservationDropHook = Arc::new(on_observation_drop);
        tokio::spawn(notify_loop(
            messages,
            cache_for_notify,
            local_mac_tx,
            kernel_event_tx,
            on_observation_drop,
        ));

        // ADR-0059 slice 3b: open the dedicated NETLINK_ROUTE socket
        // for FDB nexthop group programming. Distinct from the primary
        // `handle` so nexthop request/reply traffic doesn't compete
        // with FDB / link / route messages on a single socket. Startup
        // adoption (dumping rustbgpd-tagged nexthops and reserving
        // their IDs in the allocator) is deferred to the reconcile
        // actor's first pass — the actor calls `dump_owned_nexthops()`
        // through `NexthopOps` before any `compute_diff` Pass 1b
        // emission, so allocator collisions are prevented without
        // baking adoption into the synchronous constructor.
        let nexthop_socket = nexthop_raw::NexthopSocket::connect().map_err(|e| match e {
            nexthop_raw::NexthopError::Io(io_err) => DataplaneError::Io(io_err),
            other => DataplaneError::Other(format!("nexthop socket connect: {other}")),
        })?;

        Ok(Self {
            handle,
            link_cache,
            local_mac_rx: Some(local_mac_rx),
            kernel_event_rx,
            nexthop_socket,
        })
    }
}

/// Drain the unsolicited multicast message stream and forward
/// classified observations to the daemon. Exits when the upstream
/// connection task closes the stream.
async fn notify_loop(
    mut messages: futures::channel::mpsc::UnboundedReceiver<(
        netlink_packet_core::NetlinkMessage<RouteNetlinkMessage>,
        netlink_sys::SocketAddr,
    )>,
    link_cache: Arc<Mutex<links::LinkCache>>,
    local_mac_tx: mpsc::Sender<LocalMacObservation>,
    kernel_event_tx: mpsc::Sender<KernelEvent>,
    on_observation_drop: ObservationDropHook,
) {
    let mut ip_neighbour_macs: HashMap<(u32, IpAddr), MacAddress> = HashMap::new();
    let mut ip_neighbour_mac_order: VecDeque<(u32, IpAddr)> = VecDeque::new();

    while let Some((msg, _src)) = messages.next().await {
        let NetlinkPayload::InnerMessage(payload) = msg.payload else {
            continue;
        };
        match payload {
            RouteNetlinkMessage::NewNeighbour(neigh) => {
                let cache = link_cache.lock().await.clone();
                if let Some(obs) =
                    notify::classify_neigh(notify::NeighEventKind::New, &neigh, &cache)
                {
                    if let LocalMacObservation::IpAdded { mac, ip, .. } = obs
                        && let Some(key) = notify::ip_neighbour_cache_key(&neigh)
                    {
                        remember_ip_neighbour_mac(
                            &mut ip_neighbour_macs,
                            &mut ip_neighbour_mac_order,
                            key,
                            mac,
                        );
                        debug_assert_eq!(key.1, ip);
                    }
                    forward_observation_or_record_drop(&local_mac_tx, obs, &on_observation_drop);
                }
            }
            RouteNetlinkMessage::DelNeighbour(neigh) => {
                let cache = link_cache.lock().await.clone();
                let key = notify::ip_neighbour_cache_key(&neigh);
                let obs = notify::classify_neigh(notify::NeighEventKind::Del, &neigh, &cache)
                    .or_else(|| {
                        let cached_mac = key.and_then(|k| ip_neighbour_macs.get(&k).copied())?;
                        notify::classify_ip_neighbour_delete_with_cached_mac(
                            &neigh, &cache, cached_mac,
                        )
                    });
                if let Some(obs) = obs {
                    if matches!(obs, LocalMacObservation::IpRemoved { .. })
                        && let Some(key) = key
                    {
                        ip_neighbour_macs.remove(&key);
                    }
                    forward_observation_or_record_drop(&local_mac_tx, obs, &on_observation_drop);
                }
            }
            RouteNetlinkMessage::NewRoute(route)
                if notify::classify_route(&route, notify::RouteEventKind::New) =>
            {
                // `try_send` is right here: the actor's coalesce
                // window collapses bursts into a single pass, so
                // backpressure adds latency, not correctness. A
                // dropped wake is recovered by the next periodic
                // dump anyway.
                let _ = kernel_event_tx.try_send(KernelEvent::KernelStateChanged);
            }
            RouteNetlinkMessage::DelRoute(route)
                if notify::classify_route(&route, notify::RouteEventKind::Del) =>
            {
                let _ = kernel_event_tx.try_send(KernelEvent::KernelStateChanged);
            }
            _ => {}
        }
    }
}

fn forward_observation_or_record_drop(
    local_mac_tx: &mpsc::Sender<LocalMacObservation>,
    obs: LocalMacObservation,
    on_observation_drop: &ObservationDropHook,
) {
    match local_mac_tx.try_send(obs) {
        Ok(()) => {}
        Err(mpsc::error::TrySendError::Full(_)) => {
            on_observation_drop("channel_full");
            warn!("local-MAC observation buffer full; dropped event");
        }
        Err(mpsc::error::TrySendError::Closed(_)) => {
            on_observation_drop("channel_closed");
            warn!("local-MAC observation originator gone; dropped event");
        }
    }
}

fn remember_ip_neighbour_mac(
    cache: &mut HashMap<(u32, IpAddr), MacAddress>,
    order: &mut VecDeque<(u32, IpAddr)>,
    key: (u32, IpAddr),
    mac: MacAddress,
) {
    remember_ip_neighbour_mac_with_limit(cache, order, key, mac, IP_NEIGHBOUR_MAC_CACHE_LIMIT);
}

fn remember_ip_neighbour_mac_with_limit(
    cache: &mut HashMap<(u32, IpAddr), MacAddress>,
    order: &mut VecDeque<(u32, IpAddr)>,
    key: (u32, IpAddr),
    mac: MacAddress,
    limit: usize,
) {
    let is_new = !cache.contains_key(&key);
    if is_new && cache.len() >= limit {
        while let Some(old_key) = order.pop_front() {
            if cache.remove(&old_key).is_some() {
                warn!(
                    limit,
                    "evicted oldest stale IP-neighbour MAC cache entry after reaching bounded capacity"
                );
                break;
            }
        }
    }
    if is_new {
        order.push_back(key);
    }
    cache.insert(key, mac);
}

impl Dataplane for LinuxDataplane {
    async fn probe(&mut self, instances: &EvpnInstanceTable) -> InstanceProbes {
        // Refresh the link cache before probing so probe() sees the
        // same inventory the next dump_snapshot will see. Failures
        // here surface as NotReady-with-dump-failed for every
        // instance, which is the right operational answer: the actor
        // shouldn't program anything if it can't see what's already
        // there.
        let refresh = links::dump_links(&self.handle).await;
        let cache = match refresh {
            Ok(c) => {
                let mut guard = self.link_cache.lock().await;
                *guard = c.clone();
                c
            }
            Err(e) => {
                tracing::warn!(error = %e, "link inventory dump failed");
                let mut probes = InstanceProbes::new();
                for inst in instances.iter() {
                    probes.insert(
                        inst.id,
                        crate::snapshot::InstanceProbe::NotReady {
                            reason: format!("kernel link dump failed: {e}"),
                        },
                    );
                }
                return probes;
            }
        };
        probe::probe_instances(instances, &cache)
    }

    async fn dump_snapshot(&mut self) -> Result<KernelSnapshot, DataplaneError> {
        let cache = links::dump_links(&self.handle).await?;
        {
            let mut guard = self.link_cache.lock().await;
            *guard = cache.clone();
        }
        let fdb_entries = fdb::dump_fdb(&self.handle, &cache).await?;
        let mut snap = KernelSnapshot::new();
        for ((vni, _mac), entry) in fdb_entries {
            snap.insert_fdb(vni, entry);
        }
        for (name, link) in &cache.bridges {
            // Only surface bridges with exactly one VXLAN port so
            // the diff loop's NotReady inference matches the probe
            // pass. Bridges with 0 or 2+ VXLAN ports are reported
            // NotReady by the probe and contribute zero ops anyway.
            let vxlan = if link.vxlan_attach_count == 1 {
                link.vxlan.clone()
            } else {
                None
            };
            snap.insert_link(crate::snapshot::KernelLinkInfo {
                bridge_name: name.clone(),
                vlan_filtering: link.vlan_filtering,
                vxlan,
                ce_port_ifindexes: link.ce_port_ifindexes.clone(),
            });
        }
        Ok(snap)
    }

    async fn dump_ip_vrf_routes(&mut self, ip_vrfs: &IpVrfTable) -> Option<IpVrfRouteDump> {
        // Skip the netlink dump entirely when no IP-VRFs are
        // configured — Gate 9 is opt-in and the vast majority of
        // deployments never reach this branch with a non-empty table.
        // Returning `Some(empty)` is distinct from `None`: it means
        // "we successfully observed zero VRFs," not "we couldn't
        // observe."
        if ip_vrfs.is_empty() {
            return Some(IpVrfRouteDump::default());
        }
        // Build the L3VXLAN name→ifindex map from the link inventory.
        // `probe_ip_vrfs` runs the same link dump in its own pass; for
        // 6a we accept the dup (one extra `RTM_GETLINK` per reconcile
        // cycle). A shared inventory pass is a follow-up.
        //
        // Failures on either dump return `None` — the reconciler
        // preserves the daemon's last successful observation snapshot
        // rather than re-emitting empty (which would cascade into the
        // L3 originator withdrawing every active Type 5 on a
        // transient netlink hiccup).
        let observations = match ip_vrf::dump_ip_vrf_observations(&self.handle).await {
            Ok(o) => o,
            Err(e) => {
                tracing::warn!(error = %e, "ip-vrf link dump (route observation) failed");
                return None;
            }
        };
        let resolution = routes::IpVrfRoutingResolution::from_table(
            ip_vrfs,
            &observations.vxlan_name_to_ifindex(),
        );
        match routes::dump_routes(&self.handle, &resolution).await {
            Ok(dump) => Some(dump),
            Err(e) => {
                tracing::warn!(error = %e, "ip-vrf route dump failed");
                None
            }
        }
    }

    async fn probe_ip_vrfs(&mut self, ip_vrfs: &IpVrfTable) -> HashMap<IpVrfId, IpVrfStatus> {
        // Empty config — skip the netlink dump entirely. Gate 9 is
        // opt-in, so the vast majority of deployments never reach
        // this branch with a non-empty table.
        if ip_vrfs.is_empty() {
            return HashMap::new();
        }
        // Run one rtnetlink link dump per reconcile pass; per-VRF the
        // probe is pure and fast (in-memory map lookup + 7 predicate
        // checks). A dump failure means we cannot evaluate readiness;
        // synthesize a NotReady-with-dump-failed verdict for every
        // configured VRF so the operator-visible state reflects the
        // outage rather than going silent.
        let observations = match ip_vrf::dump_ip_vrf_observations(&self.handle).await {
            Ok(o) => o,
            Err(e) => {
                tracing::warn!(error = %e, "ip-vrf link dump failed");
                let mut out: HashMap<IpVrfId, IpVrfStatus> = HashMap::with_capacity(ip_vrfs.len());
                for vrf in ip_vrfs.iter() {
                    out.insert(
                        vrf.id,
                        IpVrfStatus::NotReady {
                            reasons: vec![
                                // Reuse VrfDeviceMissing as the "we don't
                                // know" signal. A future variant
                                // (KernelDumpFailed) would be cleaner
                                // but would expand the surface for
                                // little gain — the operator-visible
                                // log line says "ip-vrf link dump
                                // failed" with the error.
                                IpVrfNotReady::VrfDeviceMissing,
                            ],
                        },
                    );
                }
                return out;
            }
        };
        let mut out: HashMap<IpVrfId, IpVrfStatus> = HashMap::with_capacity(ip_vrfs.len());
        for vrf in ip_vrfs.iter() {
            let snap = observations.snapshot_for(&vrf.vrf_device, &vrf.l3vxlan_device);
            out.insert(vrf.id, probe_ip_vrf(vrf, &snap));
        }
        out
    }

    async fn apply(&mut self, op: &DataplaneOp) -> Result<(), DataplaneError> {
        match op {
            DataplaneOp::SetBumPortFlags { ifindex, flags } => {
                bum_filter::apply_bum_port_flags(&self.handle, *ifindex, *flags).await
            }
            DataplaneOp::AddRemoteFdb { .. }
            | DataplaneOp::UpdateRemoteFdb { .. }
            | DataplaneOp::RemoveRemoteFdb { .. } => {
                let cache = self.link_cache.lock().await.clone();
                fdb::apply_op(&self.handle, &cache, op).await
            }
            DataplaneOp::AddRemoteIpRoute {
                prefix,
                table_id,
                l3vxlan_ifindex,
                next_hop,
                ..
            } => {
                l3::apply_add_ip_route(
                    &self.handle,
                    *prefix,
                    *table_id,
                    *l3vxlan_ifindex,
                    *next_hop,
                )
                .await
            }
            DataplaneOp::RemoveRemoteIpRoute {
                prefix,
                table_id,
                l3vxlan_ifindex,
                next_hop,
                ..
            } => {
                l3::apply_remove_ip_route(
                    &self.handle,
                    *prefix,
                    *table_id,
                    *l3vxlan_ifindex,
                    *next_hop,
                )
                .await
            }
            DataplaneOp::AddL3Neighbor {
                l3vxlan_ifindex,
                next_hop,
                router_mac,
                ..
            } => {
                l3::apply_add_l3_neighbor(&self.handle, *l3vxlan_ifindex, *next_hop, *router_mac)
                    .await
            }
            DataplaneOp::RemoveL3Neighbor {
                l3vxlan_ifindex,
                next_hop,
                ..
            } => l3::apply_remove_l3_neighbor(&self.handle, *l3vxlan_ifindex, *next_hop).await,
            DataplaneOp::AddL3VxlanFdb {
                l3vxlan_ifindex,
                router_mac,
                next_hop,
                ..
            } => {
                l3::apply_add_l3vxlan_fdb(&self.handle, *l3vxlan_ifindex, *router_mac, *next_hop)
                    .await
            }
            DataplaneOp::RemoveL3VxlanFdb {
                l3vxlan_ifindex,
                router_mac,
                ..
            } => l3::apply_remove_l3vxlan_fdb(&self.handle, *l3vxlan_ifindex, *router_mac).await,
            // ADR-0059 slice 3 FDB-NHG ops never reach `Dataplane::apply` —
            // the reconcile actor's coordinator routes them through
            // `NexthopOps` + `linux::fdb_nhg` directly, because they
            // require allocator + refcount state owned by the actor.
            // If one slips through here, the routing is broken; use
            // `InvalidArgument` so the failure classifier marks it
            // `Permanent` and the actor suppresses the op rather than
            // backoff-retrying a programming bug forever.
            DataplaneOp::InstallFdbNhg { .. }
            | DataplaneOp::UpdateFdbNhgMembers { .. }
            | DataplaneOp::RemoveFdbNhg { .. } => Err(DataplaneError::InvalidArgument(
                "FDB-NHG ops must be applied via the reconcile-actor coordinator, \
                 not Dataplane::apply"
                    .into(),
            )),
        }
    }

    fn next_event(&mut self) -> impl Future<Output = Option<KernelEvent>> + Send {
        // Drain the kernel-event channel populated by the
        // `RTNLGRP_IPV4_ROUTE` / `RTNLGRP_IPV6_ROUTE` notify task.
        // The reconcile actor awaits this in its `tokio::select!`
        // and re-runs `coalesce_and_reconcile` on every wake — slice
        // 6a's IP-VRF observation refreshes within milliseconds of
        // an operator `ip addr del` / `ip route add` in a custom
        // table, instead of waiting for the 60 s periodic dump.
        //
        // `RTNLGRP_NEIGH` events stay on the dedicated
        // `LocalMacObservation` channel surfaced by
        // `take_local_mac_rx` (ADR-0054 §1's "narrow upward
        // interface" rationale). `RTNLGRP_LINK` subscription is
        // still a follow-up — the periodic dump catches link/FDB
        // drift.
        self.kernel_event_rx.recv()
    }

    fn take_local_mac_rx(&mut self) -> Option<mpsc::Receiver<LocalMacObservation>> {
        self.local_mac_rx.take()
    }
}

impl crate::dataplane::NexthopOps for LinuxDataplane {
    async fn add_nexthop_member(
        &mut self,
        id: u32,
        gateway: std::net::IpAddr,
    ) -> Result<(), DataplaneError> {
        self.nexthop_socket
            .add_fdb_member(id, gateway)
            .await
            .map_err(map_nexthop_error)
    }

    async fn add_nexthop_group(
        &mut self,
        id: u32,
        member_ids: &[u32],
    ) -> Result<(), DataplaneError> {
        // Build domain-shaped members; allocator already guarantees
        // non-zero IDs upstream so `NexthopGroupMember::new` here
        // can't fail except on programmer error (zero ID slipped
        // through). Surface that as a permanent error so the actor
        // suppresses rather than retrying.
        let mut members = Vec::with_capacity(member_ids.len());
        for mid in member_ids {
            let m = nexthop_raw::NexthopGroupMember::new(*mid).map_err(|e| {
                DataplaneError::InvalidArgument(format!("invalid group member id 0x{mid:08x}: {e}"))
            })?;
            members.push(m);
        }
        self.nexthop_socket
            .add_fdb_group(id, &members)
            .await
            .map_err(map_nexthop_error)
    }

    async fn del_nexthop(&mut self, id: u32) -> Result<(), DataplaneError> {
        self.nexthop_socket.del(id).await.map_err(map_nexthop_error)
    }

    async fn install_fdb_nhg_row(
        &mut self,
        vni: rustbgpd_evpn::EvpnInstanceId,
        mac: rustbgpd_evpn::MacAddress,
        nh_id: u32,
    ) -> Result<(), DataplaneError> {
        let cache = self.link_cache.lock().await.clone();
        fdb_nhg::apply_install_fdb_nhg_row(&self.handle, &cache, vni, mac, nh_id).await
    }

    async fn remove_fdb_nhg_row(
        &mut self,
        vni: rustbgpd_evpn::EvpnInstanceId,
        mac: rustbgpd_evpn::MacAddress,
    ) -> Result<(), DataplaneError> {
        let cache = self.link_cache.lock().await.clone();
        fdb_nhg::apply_remove_fdb_nhg_row(&self.handle, &cache, vni, mac).await
    }

    async fn dump_owned_nexthops(
        &mut self,
    ) -> Result<Vec<crate::dataplane::KernelNexthop>, DataplaneError> {
        self.nexthop_socket
            .dump_owned()
            .await
            .map_err(map_nexthop_error)
    }
}

/// Map `NexthopError` (slice-2 socket-layer typed failure) into the
/// dataplane-wide `DataplaneError`. `Io` propagates;
/// `Kernel(errno)` routes through [`map_nexthop_kernel_errno`] for
/// per-errno classification (`PermissionDenied` / `KernelTooOld` /
/// `InvalidArgument` / `Other` — see that function for the
/// permanent-vs-transient mapping); validation becomes
/// `InvalidArgument` (permanent — our message shape is wrong);
/// truncation / unexpected message become `Other` (transient — the
/// next dump pass will retry on its own cadence).
fn map_nexthop_error(e: nexthop_raw::NexthopError) -> DataplaneError {
    match e {
        nexthop_raw::NexthopError::Io(io) => DataplaneError::Io(io),
        nexthop_raw::NexthopError::Kernel(errno) => map_nexthop_kernel_errno(errno),
        nexthop_raw::NexthopError::Validation(v) => {
            DataplaneError::InvalidArgument(format!("nexthop validation: {v}"))
        }
        other => DataplaneError::Other(format!("nexthop socket: {other}")),
    }
}

/// Classify a positive errno from the nexthop netlink socket. Mirrors
/// the dispatch in [`crate::linux::fdb::errno_to_dataplane_error`] so
/// transient kernel errors (`EBUSY` / `ENOMEM` / etc.) stay
/// `FailureClass::Transient` instead of getting trapped in the
/// actor's permanent-failure suppression — a blanket
/// `InvalidArgument` would suppress them forever and strand
/// allocator reservations + kernel nexthops.
fn map_nexthop_kernel_errno(errno: i32) -> DataplaneError {
    let detail = format!("nexthop kernel errno {errno}");
    match errno {
        libc::EPERM | libc::EACCES => DataplaneError::PermissionDenied(detail),
        libc::EOPNOTSUPP => DataplaneError::KernelTooOld {
            feature: "NDA_NH_ID / FDB nexthop groups (Linux \u{2265} 5.8)".to_string(),
        },
        libc::EINVAL => DataplaneError::InvalidArgument(detail),
        _ => DataplaneError::Other(detail),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Constructing the dataplane via `connect()` must not panic on
    /// hosts where the netlink socket fails (e.g., container without
    /// `CAP_NET_ADMIN`). It either succeeds and returns a usable
    /// dataplane, or it returns an Err that the daemon spawn path
    /// catches.
    #[tokio::test]
    async fn connect_returns_ok_or_err_does_not_panic() {
        match LinuxDataplane::connect().await {
            Ok(_dp) => {
                // Got a netlink socket — connection task spawned.
                // Don't actually issue requests in PR-CI because
                // results depend on host kernel state.
            }
            Err(e) => {
                // Plausible on a netns-restricted runner.
                tracing::info!(error = %e, "connect failed (expected on CI)");
            }
        }
    }

    #[test]
    fn local_mac_observation_try_send_failure_calls_drop_hook() {
        let (tx, rx) = mpsc::channel(1);
        let full_drops = Arc::new(AtomicUsize::new(0));
        let closed_drops = Arc::new(AtomicUsize::new(0));
        let full_drops_hook = Arc::clone(&full_drops);
        let closed_drops_hook = Arc::clone(&closed_drops);
        let hook: ObservationDropHook = Arc::new(move |reason| match reason {
            "channel_full" => {
                full_drops_hook.fetch_add(1, Ordering::Relaxed);
            }
            "channel_closed" => {
                closed_drops_hook.fetch_add(1, Ordering::Relaxed);
            }
            other => panic!("unexpected drop reason {other}"),
        });
        let obs = LocalMacObservation::Aged {
            vni: rustbgpd_evpn::EvpnInstanceId::new(100).unwrap(),
            mac: rustbgpd_evpn::MacAddress::new([0xaa; 6]),
        };

        forward_observation_or_record_drop(&tx, obs.clone(), &hook);
        forward_observation_or_record_drop(&tx, obs.clone(), &hook);
        assert_eq!(full_drops.load(Ordering::Relaxed), 1);
        assert_eq!(closed_drops.load(Ordering::Relaxed), 0);

        drop(rx);
        forward_observation_or_record_drop(&tx, obs, &hook);
        assert_eq!(full_drops.load(Ordering::Relaxed), 1);
        assert_eq!(closed_drops.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn ip_neighbour_mac_cache_is_bounded() {
        let mut cache = HashMap::new();
        let mut order = VecDeque::new();
        let first_key = (7, "192.0.2.1".parse::<IpAddr>().unwrap());
        let second_key = (7, "192.0.2.2".parse::<IpAddr>().unwrap());
        let first_mac = MacAddress::new([0x02, 0, 0, 0, 0, 1]);
        let second_mac = MacAddress::new([0x02, 0, 0, 0, 0, 2]);

        remember_ip_neighbour_mac_with_limit(&mut cache, &mut order, first_key, first_mac, 1);
        assert_eq!(cache.get(&first_key), Some(&first_mac));

        remember_ip_neighbour_mac_with_limit(&mut cache, &mut order, second_key, second_mac, 1);
        assert_eq!(cache.len(), 1);
        assert!(!cache.contains_key(&first_key));
        assert_eq!(cache.get(&second_key), Some(&second_mac));
    }
}
