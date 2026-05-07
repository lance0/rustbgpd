//! Linux netlink dataplane implementation — Gate 7b.
//!
//! Implements the [`crate::Dataplane`] trait against `rtnetlink` 0.14
//! and `netlink-packet-route` 0.19. Three private submodules:
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

use std::sync::Arc;

use futures::StreamExt;
use netlink_packet_core::NetlinkPayload;
use netlink_packet_route::RouteNetlinkMessage;
use netlink_sys::AsyncSocket;
use rtnetlink::Handle;
use rustbgpd_evpn::{EvpnInstanceTable, LocalMacObservation};
use tokio::sync::{Mutex, mpsc};
use tracing::warn;

use crate::dataplane::{Dataplane, DataplaneOp, KernelEvent};
use crate::error::DataplaneError;
use crate::snapshot::{InstanceProbes, KernelSnapshot};

mod fdb;
mod links;
mod notify;
mod probe;

type ObservationDropHook = Arc<dyn Fn(&'static str) + Send + Sync + 'static>;

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

        // Subscribe to RTNLGRP_NEIGH on the same socket that carries
        // our solicited dump/program traffic. `add_membership` is a
        // synchronous setsockopt call, so it must happen before we
        // hand the connection to the runtime via `tokio::spawn`.
        // Failure here is logged but non-fatal — the dataplane still
        // works for downward FDB programming, just without a
        // local-MAC observation feed.
        if let Err(e) = connection
            .socket_mut()
            .socket_mut()
            .add_membership(notify::RTNLGRP_NEIGH)
        {
            warn!(
                error = %e,
                "could not subscribe to RTNLGRP_NEIGH; local-MAC observations will be silent"
            );
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
        let cache_for_notify = Arc::clone(&link_cache);
        let on_observation_drop: ObservationDropHook = Arc::new(on_observation_drop);
        tokio::spawn(notify_loop(
            messages,
            cache_for_notify,
            local_mac_tx,
            on_observation_drop,
        ));

        Ok(Self {
            handle,
            link_cache,
            local_mac_rx: Some(local_mac_rx),
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
    on_observation_drop: ObservationDropHook,
) {
    while let Some((msg, _src)) = messages.next().await {
        let NetlinkPayload::InnerMessage(payload) = msg.payload else {
            continue;
        };
        let (kind, neigh) = match payload {
            RouteNetlinkMessage::NewNeighbour(n) => (notify::NeighEventKind::New, n),
            RouteNetlinkMessage::DelNeighbour(n) => (notify::NeighEventKind::Del, n),
            _ => continue,
        };
        let cache = link_cache.lock().await.clone();
        let Some(obs) = notify::classify_neigh(kind, &neigh, &cache) else {
            continue;
        };
        forward_observation_or_record_drop(&local_mac_tx, obs, &on_observation_drop);
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
            });
        }
        Ok(snap)
    }

    async fn apply(&mut self, op: &DataplaneOp) -> Result<(), DataplaneError> {
        let cache = self.link_cache.lock().await.clone();
        fdb::apply_op(&self.handle, &cache, op).await
    }

    fn next_event(&mut self) -> impl Future<Output = Option<KernelEvent>> + Send {
        // RTNLGRP_LINK subscription is still a follow-up; we surface
        // RTNLGRP_NEIGH messages through the dedicated `LocalMacObservation`
        // channel rather than this `next_event` flow (see ADR-0054 §1's
        // "narrow upward interface" rationale). The reconcile actor
        // therefore relies on its 60s periodic dump cadence to catch
        // link / FDB drift — the level-triggered design tolerates this
        // gap.
        std::future::pending()
    }

    fn take_local_mac_rx(&mut self) -> Option<mpsc::Receiver<LocalMacObservation>> {
        self.local_mac_rx.take()
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
}
