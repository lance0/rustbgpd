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
//! The trait's `next_event` returns `pending()` in this slice; the
//! reconcile actor falls back to its 60 s periodic dump cadence, so
//! kernel drift is repaired structurally rather than through edge-
//! triggered notifications. `RTNLGRP_NEIGH` / `RTNLGRP_LINK`
//! subscription is a follow-up commit on the same branch — the
//! level-triggered reconcile design tolerates the gap.
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

use rtnetlink::Handle;
use rustbgpd_evpn::EvpnInstanceTable;
use tokio::sync::Mutex;

use crate::dataplane::{Dataplane, DataplaneOp, KernelEvent};
use crate::error::DataplaneError;
use crate::snapshot::{InstanceProbes, KernelSnapshot};

mod fdb;
mod links;
mod probe;

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
    pub fn connect() -> Result<Self, DataplaneError> {
        let (connection, handle, _messages) =
            rtnetlink::new_connection().map_err(DataplaneError::Io)?;
        // Spawn the netlink connection driver. rtnetlink's design has
        // the connection task read/write the netlink socket while the
        // Handle issues commands; both must run for any request to
        // make progress.
        tokio::spawn(connection);
        Ok(Self {
            handle,
            link_cache: Arc::new(Mutex::new(links::LinkCache::default())),
        })
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
            snap.insert_link(crate::snapshot::KernelLinkInfo {
                bridge_name: name.clone(),
                vlan_filtering: link.vlan_filtering,
                vxlan: link.vxlan.clone(),
            });
        }
        Ok(snap)
    }

    async fn apply(&mut self, op: &DataplaneOp) -> Result<(), DataplaneError> {
        let cache = self.link_cache.lock().await.clone();
        fdb::apply_op(&self.handle, &cache, op).await
    }

    fn next_event(&mut self) -> impl Future<Output = Option<KernelEvent>> + Send {
        // ADR-0054 §6 makes events optional — the reconcile actor
        // falls back to its periodic-dump cadence when this branch
        // doesn't fire. RTNLGRP_NEIGH / RTNLGRP_LINK subscription is
        // a follow-up; the level-triggered design tolerates the gap.
        std::future::pending()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Constructing the dataplane via `connect()` must not panic on
    /// hosts where the netlink socket fails (e.g., container without
    /// `CAP_NET_ADMIN`). It either succeeds and returns a usable
    /// dataplane, or it returns an Err that the daemon spawn path
    /// catches.
    #[tokio::test]
    async fn connect_returns_ok_or_err_does_not_panic() {
        match LinuxDataplane::connect() {
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
}
