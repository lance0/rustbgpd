//! Pure-function L3 diff for Gate 9 slice 6c symmetric IRB.
//!
//! Translates the desired [`rustbgpd_evpn::ip_vrf::RemoteIpPrefixTable`]
//! (carried on `DataplaneIntent.remote_ip_prefixes`) into a sequence
//! of [`DataplaneOp`]s against the actor's current
//! [`L3OwnedState`]. The function is deterministic, allocation-bounded,
//! and free of any I/O — the reconcile actor wraps it inside its
//! `tokio::select!` loop and feeds the resulting ops through
//! `Dataplane::apply`.
//!
//! ## Refcounted neighbor + FDB
//!
//! Two prefixes that arrive over the same remote VTEP and the same
//! Router MAC share the kernel-side L3 neighbor and L3VXLAN FDB
//! entries. The diff function tracks reference counts on
//! `(l3vxlan_ifindex, next_hop)` and `(l3vxlan_ifindex, router_mac)`
//! so the second prefix's install emits no neighbor/FDB op (the
//! first one already programmed them), and only the *last* prefix's
//! withdraw emits the neighbor/FDB remove. Without this, two routes
//! sharing a VTEP would step on each other on the second withdraw:
//! removing the neighbor while a still-installed route depends on
//! it would leave forwarding broken.
//!
//! ## Foreign preservation
//!
//! The diff never iterates kernel state — only [`L3OwnedState`], the
//! actor's record of what *we* installed. Routes / neighbors / FDB
//! rows the kernel learned through other paths (`ip route add` by
//! the operator, FRR co-tenant, etc.) are structurally invisible to
//! the withdraw path. This mirrors ADR-0054 §5's foreign-preservation
//! rule on the L2 FDB side.
//!
//! ## Readiness gate
//!
//! For each `(IpVrfId, prefix)` in the desired projection, the diff
//! checks `vrf_status[vrf_id] == Ready` before emitting any install
//! ops. Not-ready VRFs implicitly drop their entries from the
//! desired-want set so the symmetrical withdraw branch fires for
//! everything we previously installed in that VRF — exactly the
//! Ready→NotReady contract the L3 originator uses on the
//! origination side (slice 6b).
//!
//! ## Apply / withdraw order
//!
//! Per the user's review (PR B research notes):
//!
//! - **Install** order per prefix: neighbor (if new) → FDB (if new)
//!   → route. The route is the consumer of the shared L2 resolution
//!   objects, so installing it after the objects guarantees the
//!   kernel can resolve every encapsulation step the moment the
//!   route lands.
//! - **Withdraw** order per prefix: route → neighbor (only if last
//!   ref) → FDB (only if last ref). Removing the route first
//!   guarantees no in-flight encapsulation depends on the
//!   neighbor/FDB by the time we tear them down.
//!
//! ## Family mismatch
//!
//! IPv6 prefix over IPv4 VTEP (and vice versa) requires
//! `RTA_VIA` for the cross-family gateway encoding, which the
//! current `linux::l3` apply path does not implement. The diff
//! drops mismatched routes into [`L3Drop::FamilyMismatch`] (counted,
//! observable) rather than half-supporting them — explicit
//! suppression rather than a silent miscompose.

use std::collections::BTreeMap;
use std::net::IpAddr;

use rustbgpd_evpn::ip_vrf::{IpVrfTable, RemoteIpPrefixEntry, RemoteIpPrefixTable};
use rustbgpd_evpn::{EvpnIpPrefixValue, IpVrfId, MacAddress};

use crate::dataplane::DataplaneOp;

/// State the L3 diff loop owns. Updated only on successful kernel
/// apply by the reconcile actor (a failed inject leaves the
/// in-memory state at the prior shape so the next reconcile pass
/// retries).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct L3OwnedState {
    /// `(IpVrfId, prefix) → (next_hop, router_mac, l3vxlan_ifindex,
    /// table_id)` for every currently-installed route. The
    /// `l3vxlan_ifindex` + `table_id` are recorded at install time
    /// so a subsequent kernel-side reshuffle (e.g., L3VXLAN drops
    /// and re-appears under a new ifindex) doesn't leak orphan
    /// entries on withdraw.
    pub routes: BTreeMap<(IpVrfId, EvpnIpPrefixValue), OwnedRoute>,
    /// Reference count for the L3 neighbor entries
    /// (`l3vxlan_ifindex`, `next_hop`) → count. Decremented on
    /// withdraw; the kernel neighbor row is torn down only when the
    /// count reaches zero.
    pub neighbor_refs: BTreeMap<(u32, IpAddr), u32>,
    /// Reference count for the L3VXLAN FDB entries
    /// (`l3vxlan_ifindex`, `router_mac`) → count. Same lifecycle as
    /// neighbor refs.
    pub fdb_refs: BTreeMap<(u32, MacAddress), u32>,
}

/// One row of installed-route bookkeeping. Captures everything the
/// diff loop needs to symmetrically remove the route later, even if
/// the IP-VRF's configured `table_id` / `l3vxlan_device` change at
/// runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OwnedRoute {
    pub next_hop: IpAddr,
    pub router_mac: MacAddress,
    pub l3vxlan_ifindex: u32,
    pub table_id: u32,
}

impl L3OwnedState {
    /// Number of currently-installed routes for one IP-VRF. Backing
    /// store for the `IpVrfState.installed_routes_count` gRPC field.
    #[must_use]
    pub fn route_count_for(&self, vrf_id: IpVrfId) -> u64 {
        self.routes.keys().filter(|(id, _)| *id == vrf_id).count() as u64
    }

    /// True when the owned-set has no routes at all (RR-only /
    /// no-Gate-9 default).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.routes.is_empty()
    }
}

/// Why a desired remote prefix did not make it into the apply plan.
/// Distinct from `RemoteIpPrefixTable::drops` (which captures
/// projection-time drops); this enum captures install-time drops,
/// surfaced for per-VRF Prometheus counters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum L3Drop {
    /// IP-VRF is `NotReady` — every desired prefix in it is
    /// suppressed. The matching withdraw branch fires symmetrically
    /// (the diff treats NotReady-VRF prefixes as "not in want").
    NotReady {
        vrf_id: IpVrfId,
        prefix: EvpnIpPrefixValue,
    },
    /// Cross-family prefix vs next-hop. Slice 6c does not implement
    /// `RTA_VIA`; the apply path would reject the op anyway. Counted
    /// so an operator chasing "why isn't my v6 route installed?"
    /// sees the suppression directly.
    FamilyMismatch {
        vrf_id: IpVrfId,
        prefix: EvpnIpPrefixValue,
        next_hop: IpAddr,
    },
    /// IP-VRF's `l3vxlan_ifindex` is not yet known (probe hasn't
    /// surfaced a Ready verdict with the ifindex, or the L3VXLAN
    /// device disappeared between probe and diff). Withdraws are
    /// emitted normally from the cached `OwnedRoute.l3vxlan_ifindex`,
    /// but installs cannot proceed without a current ifindex. The
    /// next reconcile pass with a Ready probe retries.
    NoL3VxlanIfindex {
        vrf_id: IpVrfId,
        prefix: EvpnIpPrefixValue,
    },
}

/// Output of one L3 diff pass.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct L3Plan {
    /// Ops to apply, in the install-then-withdraw order documented
    /// at the module level. The reconcile actor feeds them through
    /// `Dataplane::apply` sequentially; the per-op apply order is
    /// preserved as ordered by this `Vec`.
    pub ops: Vec<DataplaneOp>,
    /// Drops captured this pass, for per-`(vrf, reason)` Prometheus
    /// counters.
    pub drops: Vec<L3Drop>,
}

/// Compute the next L3 plan from the desired projection + current
/// owned state + the per-VRF Ready / ifindex map.
///
/// `ready_l3vxlan_ifindex` is `IpVrfId → l3vxlan_ifindex` for every
/// VRF whose readiness probe returned `Ready` with a real ifindex.
/// Not-Ready VRFs are simply absent from the map (the diff treats
/// them as "no install" → withdraw everything we own).
///
/// # Panics
///
/// Panics on an internal invariant violation: when a key is in
/// `want` (which was just built up by checking the `ready_…` map and
/// the `ip_vrfs` table) but lookup against either source fails.
/// Both `.expect(...)` sites prove a programmer error in the diff,
/// not a runtime condition.
#[allow(clippy::too_many_lines)]
#[must_use]
pub fn compute_l3_diff(
    intent: &RemoteIpPrefixTable,
    owned: &L3OwnedState,
    ready_l3vxlan_ifindex: &BTreeMap<IpVrfId, u32>,
    ip_vrfs: &IpVrfTable,
) -> L3Plan {
    let mut plan = L3Plan::default();

    // ── Phase 1: compute `want` ────────────────────────────────
    //
    // `want` is the set of `(IpVrfId, prefix)` we intend to have
    // installed after the apply phase. A prefix is in `want` only
    // when (a) its VRF is Ready with a known L3VXLAN ifindex, (b)
    // its prefix/next-hop family matches, and (c) the projection
    // produced an entry for the key.
    //
    // Drops captured below feed per-`(vrf, reason)` counters and
    // are *not* themselves ops — they're observability only.
    let mut want: BTreeMap<(IpVrfId, EvpnIpPrefixValue), &RemoteIpPrefixEntry> = BTreeMap::new();
    for ((vrf_id, prefix), entry) in intent.iter() {
        let Some(vrf) = ip_vrfs.iter().find(|v| v.id == *vrf_id) else {
            // projection produced an entry for an unknown VRF; drop silently
            continue;
        };
        if !ready_l3vxlan_ifindex.contains_key(vrf_id) {
            plan.drops.push(L3Drop::NotReady {
                vrf_id: *vrf_id,
                prefix: *prefix,
            });
            continue;
        }
        if !family_matches(*prefix, entry.next_hop) {
            plan.drops.push(L3Drop::FamilyMismatch {
                vrf_id: *vrf_id,
                prefix: *prefix,
                next_hop: entry.next_hop,
            });
            continue;
        }
        // Family also checks against the IP-VRF's local_vtep_ip
        // (a v4 remote prefix in an IPv6-VTEP VRF would round-trip
        // wrongly even if next_hop happens to be v4).
        if !family_matches_vrf(*prefix, vrf.local_vtep_ip) {
            plan.drops.push(L3Drop::FamilyMismatch {
                vrf_id: *vrf_id,
                prefix: *prefix,
                next_hop: entry.next_hop,
            });
            continue;
        }
        want.insert((*vrf_id, *prefix), entry);
    }

    // ── Phase 2: withdrawals ───────────────────────────────────
    //
    // Walk owned routes; for any key not in `want`, emit a route
    // remove and decrement neighbor/FDB refcounts. Build a working
    // copy of the refcount tables so the symmetric "is this the
    // last ref?" check uses the post-decrement value.
    let mut sim_neighbor = owned.neighbor_refs.clone();
    let mut sim_fdb = owned.fdb_refs.clone();
    let to_withdraw: Vec<((IpVrfId, EvpnIpPrefixValue), OwnedRoute)> = owned
        .routes
        .iter()
        .filter(|(k, _)| !want.contains_key(k))
        .map(|(k, v)| (*k, *v))
        .collect();
    for ((vrf_id, prefix), route) in to_withdraw {
        plan.ops.push(DataplaneOp::RemoveRemoteIpRoute {
            vrf_id,
            prefix,
            table_id: route.table_id,
            l3vxlan_ifindex: route.l3vxlan_ifindex,
            next_hop: route.next_hop,
        });
        let neigh_key = (route.l3vxlan_ifindex, route.next_hop);
        let new_neigh = decrement_ref(&mut sim_neighbor, neigh_key);
        if new_neigh == 0 {
            plan.ops.push(DataplaneOp::RemoveL3Neighbor {
                vrf_id,
                l3vxlan_ifindex: route.l3vxlan_ifindex,
                next_hop: route.next_hop,
            });
        }
        let fdb_key = (route.l3vxlan_ifindex, route.router_mac);
        let new_fdb = decrement_ref(&mut sim_fdb, fdb_key);
        if new_fdb == 0 {
            plan.ops.push(DataplaneOp::RemoveL3VxlanFdb {
                vrf_id,
                l3vxlan_ifindex: route.l3vxlan_ifindex,
                router_mac: route.router_mac,
            });
        }
    }

    // ── Phase 3: installs ──────────────────────────────────────
    //
    // Walk `want`; for any key not already owned at the same shape,
    // emit neighbor add (if first ref) → FDB add (if first ref) →
    // route add. The kernel needs the L2 resolution objects in
    // place before the route's recursive lookup runs, even with
    // `RTNH_F_ONLINK`.
    //
    // Already-owned but shape-changed (e.g., next-hop drift on the
    // same prefix) is handled by emitting the install as a
    // *replace* — the apply path's `.replace()` on netlink makes
    // the Add op idempotent over the existing entry. Refcount math
    // still needs to handle the neighbor/FDB transition; for the
    // first cut we drop and re-add when shape changes, treating
    // the change as withdraw-then-install. See below.
    for ((vrf_id, prefix), entry) in &want {
        let l3vxlan_ifindex = *ready_l3vxlan_ifindex
            .get(vrf_id)
            .expect("ready_l3vxlan_ifindex membership was checked when building `want`");
        let vrf = ip_vrfs
            .iter()
            .find(|v| v.id == *vrf_id)
            .expect("`want` membership implies a configured VRF");
        let new_route = OwnedRoute {
            next_hop: entry.next_hop,
            router_mac: entry.router_mac,
            l3vxlan_ifindex,
            table_id: vrf.table_id,
        };
        // Shape-changed: same prefix key, different
        // next_hop/router_mac/ifindex/table_id. Treat as remove +
        // add so the refcount math stays clean. The previous entry
        // was already emitted under "to_withdraw" if `want`
        // disagreed; but Phase 2 only catches keys absent from
        // `want`. Need to handle shape changes here.
        if let Some(prev) = owned.routes.get(&(*vrf_id, *prefix))
            && prev != &new_route
        {
            plan.ops.push(DataplaneOp::RemoveRemoteIpRoute {
                vrf_id: *vrf_id,
                prefix: *prefix,
                table_id: prev.table_id,
                l3vxlan_ifindex: prev.l3vxlan_ifindex,
                next_hop: prev.next_hop,
            });
            let prev_neigh = (prev.l3vxlan_ifindex, prev.next_hop);
            if decrement_ref(&mut sim_neighbor, prev_neigh) == 0 {
                plan.ops.push(DataplaneOp::RemoveL3Neighbor {
                    vrf_id: *vrf_id,
                    l3vxlan_ifindex: prev.l3vxlan_ifindex,
                    next_hop: prev.next_hop,
                });
            }
            let prev_fdb = (prev.l3vxlan_ifindex, prev.router_mac);
            if decrement_ref(&mut sim_fdb, prev_fdb) == 0 {
                plan.ops.push(DataplaneOp::RemoveL3VxlanFdb {
                    vrf_id: *vrf_id,
                    l3vxlan_ifindex: prev.l3vxlan_ifindex,
                    router_mac: prev.router_mac,
                });
            }
        } else if owned.routes.get(&(*vrf_id, *prefix)) == Some(&new_route) {
            // Already installed at the desired shape — idempotent.
            continue;
        }

        let neigh_key = (l3vxlan_ifindex, entry.next_hop);
        let prev_neigh = *sim_neighbor.get(&neigh_key).unwrap_or(&0);
        sim_neighbor.insert(neigh_key, prev_neigh + 1);
        if prev_neigh == 0 {
            plan.ops.push(DataplaneOp::AddL3Neighbor {
                vrf_id: *vrf_id,
                l3vxlan_ifindex,
                next_hop: entry.next_hop,
                router_mac: entry.router_mac,
            });
        }
        let fdb_key = (l3vxlan_ifindex, entry.router_mac);
        let prev_fdb = *sim_fdb.get(&fdb_key).unwrap_or(&0);
        sim_fdb.insert(fdb_key, prev_fdb + 1);
        if prev_fdb == 0 {
            plan.ops.push(DataplaneOp::AddL3VxlanFdb {
                vrf_id: *vrf_id,
                l3vxlan_ifindex,
                router_mac: entry.router_mac,
                next_hop: entry.next_hop,
            });
        }
        plan.ops.push(DataplaneOp::AddRemoteIpRoute {
            vrf_id: *vrf_id,
            prefix: *prefix,
            table_id: vrf.table_id,
            l3vxlan_ifindex,
            next_hop: entry.next_hop,
        });
    }

    plan
}

/// Apply a successful op to the owned state. The reconcile actor
/// calls this once per `Ok(())` returned from `Dataplane::apply`.
/// Failed ops leave the owned state untouched so the next reconcile
/// pass retries with the same shape.
pub fn record_l3_success(
    owned: &mut L3OwnedState,
    op: &DataplaneOp,
    ready_l3vxlan_ifindex: &BTreeMap<IpVrfId, u32>,
    ip_vrfs: &IpVrfTable,
    intent: &RemoteIpPrefixTable,
) {
    match op {
        DataplaneOp::AddRemoteIpRoute { vrf_id, prefix, .. } => {
            // Re-derive the OwnedRoute shape from the same inputs
            // the diff used; this keeps a single source of truth
            // and makes the test surface simpler.
            if let (Some(ifindex), Some(entry)) = (
                ready_l3vxlan_ifindex.get(vrf_id).copied(),
                intent
                    .iter()
                    .find(|((id, p), _)| id == vrf_id && p == prefix)
                    .map(|(_, e)| e),
            ) {
                let vrf = ip_vrfs.iter().find(|v| v.id == *vrf_id);
                if let Some(vrf) = vrf {
                    owned.routes.insert(
                        (*vrf_id, *prefix),
                        OwnedRoute {
                            next_hop: entry.next_hop,
                            router_mac: entry.router_mac,
                            l3vxlan_ifindex: ifindex,
                            table_id: vrf.table_id,
                        },
                    );
                }
            }
        }
        DataplaneOp::RemoveRemoteIpRoute { vrf_id, prefix, .. } => {
            owned.routes.remove(&(*vrf_id, *prefix));
        }
        DataplaneOp::AddL3Neighbor {
            l3vxlan_ifindex,
            next_hop,
            ..
        } => {
            *owned
                .neighbor_refs
                .entry((*l3vxlan_ifindex, *next_hop))
                .or_insert(0) += 1;
        }
        DataplaneOp::RemoveL3Neighbor {
            l3vxlan_ifindex,
            next_hop,
            ..
        } => {
            let key = (*l3vxlan_ifindex, *next_hop);
            if let Some(c) = owned.neighbor_refs.get_mut(&key) {
                *c = c.saturating_sub(1);
                if *c == 0 {
                    owned.neighbor_refs.remove(&key);
                }
            }
        }
        DataplaneOp::AddL3VxlanFdb {
            l3vxlan_ifindex,
            router_mac,
            ..
        } => {
            *owned
                .fdb_refs
                .entry((*l3vxlan_ifindex, *router_mac))
                .or_insert(0) += 1;
        }
        DataplaneOp::RemoveL3VxlanFdb {
            l3vxlan_ifindex,
            router_mac,
            ..
        } => {
            let key = (*l3vxlan_ifindex, *router_mac);
            if let Some(c) = owned.fdb_refs.get_mut(&key) {
                *c = c.saturating_sub(1);
                if *c == 0 {
                    owned.fdb_refs.remove(&key);
                }
            }
        }
        // L2 FDB / BUM ops are not L3 ops; the L3 owned state is
        // not affected.
        DataplaneOp::AddRemoteFdb { .. }
        | DataplaneOp::UpdateRemoteFdb { .. }
        | DataplaneOp::RemoveRemoteFdb { .. }
        | DataplaneOp::SetBumPortFlags { .. } => {}
    }
}

fn family_matches(prefix: EvpnIpPrefixValue, next_hop: IpAddr) -> bool {
    matches!(
        (prefix, next_hop),
        (EvpnIpPrefixValue::V4(_), IpAddr::V4(_)) | (EvpnIpPrefixValue::V6(_), IpAddr::V6(_))
    )
}

fn family_matches_vrf(prefix: EvpnIpPrefixValue, vtep: IpAddr) -> bool {
    matches!(
        (prefix, vtep),
        (EvpnIpPrefixValue::V4(_), IpAddr::V4(_)) | (EvpnIpPrefixValue::V6(_), IpAddr::V6(_))
    )
}

fn decrement_ref<K: Ord + Copy>(map: &mut BTreeMap<K, u32>, key: K) -> u32 {
    let new_val = match map.get_mut(&key) {
        Some(c) => {
            *c = c.saturating_sub(1);
            *c
        }
        None => 0,
    };
    if new_val == 0 {
        map.remove(&key);
    }
    new_val
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use rustbgpd_evpn::ip_vrf::{IpVrf, RemoteIpPrefixEntry};
    use rustbgpd_evpn::{IpVrfId, Ipv4Prefix, RouteDistinguisher, RouteTarget};
    use std::net::{IpAddr, Ipv4Addr};

    fn mac(b: u8) -> MacAddress {
        MacAddress::new([0xaa, 0xbb, 0xcc, 0xdd, 0xee, b])
    }

    fn vrf(id: u32, table_id: u32, vtep: IpAddr) -> IpVrf {
        IpVrf::new(
            format!("vrf{id}"),
            IpVrfId::new(id).unwrap(),
            format!("65000:{id}").parse::<RouteDistinguisher>().unwrap(),
            vec![format!("65000:{id}").parse::<RouteTarget>().unwrap()],
            vtep,
            mac(0x10),
            format!("vrf{id}"),
            format!("l3vxlan{id}"),
            table_id,
        )
        .unwrap()
    }

    fn v4(octets: [u8; 4], len: u8) -> EvpnIpPrefixValue {
        EvpnIpPrefixValue::V4(Ipv4Prefix::new(Ipv4Addr::from(octets), len))
    }

    fn ip4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    fn one_vrf_table(id: u32, table_id: u32, vtep: IpAddr) -> IpVrfTable {
        let mut t = IpVrfTable::new();
        t.insert(vrf(id, table_id, vtep)).unwrap();
        t
    }

    /// Build a `RemoteIpPrefixTable` from a flat list of entries.
    /// `RemoteIpPrefixTable::entries` is private, so the test
    /// fixture builds it by calling the pure projection helper
    /// with a hand-crafted input — but for this diff test we can
    /// just construct entries via the `RemoteIpPrefixEntry` field
    /// initializer because it's `pub`.
    fn intent_with(
        entries: Vec<((IpVrfId, EvpnIpPrefixValue), RemoteIpPrefixEntry)>,
    ) -> RemoteIpPrefixTable {
        // No public constructor for entries; build via the
        // projection helper with a synthesized input that matches.
        // To keep tests minimal we use a thin wrapper.
        let mut table = RemoteIpPrefixTable::new();
        for ((vrf_id, prefix), entry) in entries {
            // Re-insert via a tiny helper that pushes onto the
            // private map. The crate's projection helper does the
            // same insertion path, but we don't want to rebuild
            // route_targets / RT match logic for the diff test.
            // The `pub` field initializer on `RemoteIpPrefixTable`
            // would be ideal; in lieu of that we use the
            // projection helper directly with a one-route input.
            use rustbgpd_evpn::ip_vrf::{ProjectedIpPrefixRoute, project_ip_prefix_routes};
            let mut vrfs = IpVrfTable::new();
            vrfs.insert(
                IpVrf::new(
                    format!("v{}", vrf_id.as_u32()),
                    vrf_id,
                    "65000:1".parse().unwrap(),
                    vec!["65000:1".parse().unwrap()],
                    IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                    mac(0x99),
                    format!("v{}", vrf_id.as_u32()),
                    format!("l3vxlan{}", vrf_id.as_u32()),
                    100 + vrf_id.as_u32(),
                )
                .unwrap(),
            )
            .unwrap();
            let routes = vec![ProjectedIpPrefixRoute {
                rd: "65000:1".parse().unwrap(),
                prefix,
                next_hop: entry.next_hop,
                l3vni: vrf_id.as_u32(),
                route_targets: vec!["65000:1".parse().unwrap()],
                router_mac: Some(entry.router_mac),
            }];
            let projected = project_ip_prefix_routes(&vrfs, routes);
            for ((id, p), e) in projected.iter() {
                let _ = e;
                let _ = id;
                let _ = p;
            }
            // The above project_ip_prefix_routes call works on a
            // single-VRF universe; merge its output into `table`.
            // Since `RemoteIpPrefixTable` doesn't expose a public
            // merge API, build a fresh one for each call and rely
            // on the test using a single VRF / single entry per
            // table for simplicity.
            table = projected;
        }
        table
    }

    /// Cold start with one prefix → three ops in canonical order:
    /// neighbor, FDB, route.
    #[test]
    fn cold_start_one_prefix_emits_neighbor_then_fdb_then_route() {
        let prefix = v4([198, 51, 100, 0], 24);
        let nh = ip4(10, 0, 0, 2);
        let rmac = mac(0xaa);

        let vrf_id = IpVrfId::new(101).unwrap();
        let ip_vrfs = {
            // Match the table the test-intent builder synthesizes
            // (table_id = 100 + vrf_id, l3vxlan = l3vxlanN).
            let mut t = IpVrfTable::new();
            t.insert(
                IpVrf::new(
                    "v101".into(),
                    vrf_id,
                    "65000:1".parse().unwrap(),
                    vec!["65000:1".parse().unwrap()],
                    IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                    mac(0x99),
                    "v101".into(),
                    "l3vxlan101".into(),
                    201,
                )
                .unwrap(),
            )
            .unwrap();
            t
        };

        let intent = intent_with(vec![(
            (vrf_id, prefix),
            RemoteIpPrefixEntry {
                prefix,
                next_hop: nh,
                l3vni: 101,
                router_mac: rmac,
            },
        )]);
        let owned = L3OwnedState::default();
        let mut ready = BTreeMap::new();
        ready.insert(vrf_id, 42_u32);

        let plan = compute_l3_diff(&intent, &owned, &ready, &ip_vrfs);
        assert_eq!(plan.drops, vec![], "no drops expected for ready VRF");
        assert_eq!(plan.ops.len(), 3);
        assert!(matches!(plan.ops[0], DataplaneOp::AddL3Neighbor { .. }));
        assert!(matches!(plan.ops[1], DataplaneOp::AddL3VxlanFdb { .. }));
        assert!(matches!(plan.ops[2], DataplaneOp::AddRemoteIpRoute { .. }));
    }

    /// Two prefixes sharing the same `(l3vxlan, vtep, router_mac)`
    /// tuple emit neighbor + FDB only once; the second prefix gets
    /// just a route op.
    #[test]
    fn second_prefix_sharing_vtep_emits_route_only() {
        let prefix_a = v4([198, 51, 100, 0], 24);
        let prefix_b = v4([198, 51, 101, 0], 24);
        let nh = ip4(10, 0, 0, 2);
        let rmac = mac(0xaa);
        let vrf_id = IpVrfId::new(101).unwrap();

        // Simulate "first install already happened" via the owned
        // state — equivalent to a previous reconcile pass having
        // applied the cold-start plan.
        let mut owned = L3OwnedState::default();
        owned.routes.insert(
            (vrf_id, prefix_a),
            OwnedRoute {
                next_hop: nh,
                router_mac: rmac,
                l3vxlan_ifindex: 42,
                table_id: 201,
            },
        );
        owned.neighbor_refs.insert((42, nh), 1);
        owned.fdb_refs.insert((42, rmac), 1);

        let ip_vrfs = {
            let mut t = IpVrfTable::new();
            t.insert(
                IpVrf::new(
                    "v101".into(),
                    vrf_id,
                    "65000:1".parse().unwrap(),
                    vec!["65000:1".parse().unwrap()],
                    IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                    mac(0x99),
                    "v101".into(),
                    "l3vxlan101".into(),
                    201,
                )
                .unwrap(),
            )
            .unwrap();
            t
        };
        // Intent now has both prefixes A and B.
        let intent = {
            use rustbgpd_evpn::ip_vrf::{ProjectedIpPrefixRoute, project_ip_prefix_routes};
            let routes = vec![
                ProjectedIpPrefixRoute {
                    rd: "65000:1".parse().unwrap(),
                    prefix: prefix_a,
                    next_hop: nh,
                    l3vni: 101,
                    route_targets: vec!["65000:1".parse().unwrap()],
                    router_mac: Some(rmac),
                },
                ProjectedIpPrefixRoute {
                    rd: "65000:1".parse().unwrap(),
                    prefix: prefix_b,
                    next_hop: nh,
                    l3vni: 101,
                    route_targets: vec!["65000:1".parse().unwrap()],
                    router_mac: Some(rmac),
                },
            ];
            project_ip_prefix_routes(&ip_vrfs, routes)
        };
        let mut ready = BTreeMap::new();
        ready.insert(vrf_id, 42_u32);

        let plan = compute_l3_diff(&intent, &owned, &ready, &ip_vrfs);
        // Only the new prefix's route is emitted — neighbor + FDB
        // are already at refcount 1 from prefix_a.
        let adds: Vec<_> = plan
            .ops
            .iter()
            .filter(|op| {
                matches!(
                    op,
                    DataplaneOp::AddRemoteIpRoute { .. }
                        | DataplaneOp::AddL3Neighbor { .. }
                        | DataplaneOp::AddL3VxlanFdb { .. }
                )
            })
            .collect();
        assert_eq!(adds.len(), 1, "only the route op should fire, got {adds:?}");
        assert!(matches!(adds[0], DataplaneOp::AddRemoteIpRoute { .. }));
    }

    /// Withdrawing one of two prefixes sharing a VTEP must keep the
    /// neighbor + FDB rows alive (the other prefix still references
    /// them).
    #[test]
    fn withdraw_one_of_two_keeps_shared_neighbor_and_fdb() {
        let prefix_a = v4([198, 51, 100, 0], 24);
        let prefix_b = v4([198, 51, 101, 0], 24);
        let nh = ip4(10, 0, 0, 2);
        let rmac = mac(0xaa);
        let vrf_id = IpVrfId::new(101).unwrap();
        let ip_vrfs = one_vrf_table(101, 201, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));

        let mut owned = L3OwnedState::default();
        for p in [prefix_a, prefix_b] {
            owned.routes.insert(
                (vrf_id, p),
                OwnedRoute {
                    next_hop: nh,
                    router_mac: rmac,
                    l3vxlan_ifindex: 42,
                    table_id: 201,
                },
            );
        }
        owned.neighbor_refs.insert((42, nh), 2);
        owned.fdb_refs.insert((42, rmac), 2);

        // Intent now only has prefix_a.
        let intent = {
            use rustbgpd_evpn::ip_vrf::{ProjectedIpPrefixRoute, project_ip_prefix_routes};
            let routes = vec![ProjectedIpPrefixRoute {
                rd: "65000:101".parse().unwrap(),
                prefix: prefix_a,
                next_hop: nh,
                l3vni: 101,
                route_targets: vec!["65000:101".parse().unwrap()],
                router_mac: Some(rmac),
            }];
            project_ip_prefix_routes(&ip_vrfs, routes)
        };
        let mut ready = BTreeMap::new();
        ready.insert(vrf_id, 42_u32);

        let plan = compute_l3_diff(&intent, &owned, &ready, &ip_vrfs);
        let neighbor_removes: usize = plan
            .ops
            .iter()
            .filter(|op| matches!(op, DataplaneOp::RemoveL3Neighbor { .. }))
            .count();
        let fdb_removes: usize = plan
            .ops
            .iter()
            .filter(|op| matches!(op, DataplaneOp::RemoveL3VxlanFdb { .. }))
            .count();
        let route_removes: usize = plan
            .ops
            .iter()
            .filter(|op| matches!(op, DataplaneOp::RemoveRemoteIpRoute { .. }))
            .count();
        assert_eq!(route_removes, 1, "one route should withdraw");
        assert_eq!(neighbor_removes, 0, "neighbor still referenced");
        assert_eq!(fdb_removes, 0, "FDB still referenced");
    }

    /// Withdrawing the last prefix on a shared `(vtep, mac)` tuple
    /// tears down the neighbor + FDB.
    #[test]
    fn withdraw_last_prefix_tears_down_neighbor_and_fdb() {
        let prefix = v4([198, 51, 100, 0], 24);
        let nh = ip4(10, 0, 0, 2);
        let rmac = mac(0xaa);
        let vrf_id = IpVrfId::new(101).unwrap();
        let ip_vrfs = one_vrf_table(101, 201, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));

        let mut owned = L3OwnedState::default();
        owned.routes.insert(
            (vrf_id, prefix),
            OwnedRoute {
                next_hop: nh,
                router_mac: rmac,
                l3vxlan_ifindex: 42,
                table_id: 201,
            },
        );
        owned.neighbor_refs.insert((42, nh), 1);
        owned.fdb_refs.insert((42, rmac), 1);

        let intent = RemoteIpPrefixTable::new(); // empty
        let mut ready = BTreeMap::new();
        ready.insert(vrf_id, 42_u32);

        let plan = compute_l3_diff(&intent, &owned, &ready, &ip_vrfs);
        let kinds: Vec<&str> = plan
            .ops
            .iter()
            .map(|op| match op {
                DataplaneOp::RemoveRemoteIpRoute { .. } => "route",
                DataplaneOp::RemoveL3Neighbor { .. } => "neighbor",
                DataplaneOp::RemoveL3VxlanFdb { .. } => "fdb",
                _ => "other",
            })
            .collect();
        // Order: route → neighbor → fdb.
        assert_eq!(kinds, vec!["route", "neighbor", "fdb"]);
    }

    /// IP-VRF becomes `NotReady` → every prefix in it is withdrawn,
    /// neighbor + FDB tear down.
    #[test]
    fn vrf_not_ready_drains_all_owned_routes() {
        let prefix = v4([198, 51, 100, 0], 24);
        let nh = ip4(10, 0, 0, 2);
        let rmac = mac(0xaa);
        let vrf_id = IpVrfId::new(101).unwrap();
        let ip_vrfs = one_vrf_table(101, 201, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));

        let mut owned = L3OwnedState::default();
        owned.routes.insert(
            (vrf_id, prefix),
            OwnedRoute {
                next_hop: nh,
                router_mac: rmac,
                l3vxlan_ifindex: 42,
                table_id: 201,
            },
        );
        owned.neighbor_refs.insert((42, nh), 1);
        owned.fdb_refs.insert((42, rmac), 1);

        // Intent says we want the prefix, but `ready_l3vxlan_ifindex`
        // is empty (VRF probe returned NotReady).
        let intent = {
            use rustbgpd_evpn::ip_vrf::{ProjectedIpPrefixRoute, project_ip_prefix_routes};
            let routes = vec![ProjectedIpPrefixRoute {
                rd: "65000:101".parse().unwrap(),
                prefix,
                next_hop: nh,
                l3vni: 101,
                route_targets: vec!["65000:101".parse().unwrap()],
                router_mac: Some(rmac),
            }];
            project_ip_prefix_routes(&ip_vrfs, routes)
        };
        let ready = BTreeMap::new();

        let plan = compute_l3_diff(&intent, &owned, &ready, &ip_vrfs);
        assert!(matches!(plan.drops.as_slice(), [L3Drop::NotReady { .. }],));
        // Route + neighbor + fdb all withdraw.
        assert_eq!(plan.ops.len(), 3);
    }

    /// `record_l3_success` round-trips the owned state through the
    /// full apply plan: after applying every op in order, the
    /// owned state matches what the diff expected.
    #[test]
    fn record_success_makes_diff_idempotent_on_next_pass() {
        let prefix = v4([198, 51, 100, 0], 24);
        let nh = ip4(10, 0, 0, 2);
        let rmac = mac(0xaa);
        let vrf_id = IpVrfId::new(101).unwrap();
        let ip_vrfs = one_vrf_table(101, 201, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));

        let intent = {
            use rustbgpd_evpn::ip_vrf::{ProjectedIpPrefixRoute, project_ip_prefix_routes};
            let routes = vec![ProjectedIpPrefixRoute {
                rd: "65000:101".parse().unwrap(),
                prefix,
                next_hop: nh,
                l3vni: 101,
                route_targets: vec!["65000:101".parse().unwrap()],
                router_mac: Some(rmac),
            }];
            project_ip_prefix_routes(&ip_vrfs, routes)
        };
        let mut ready = BTreeMap::new();
        ready.insert(vrf_id, 42_u32);

        let mut owned = L3OwnedState::default();
        let plan = compute_l3_diff(&intent, &owned, &ready, &ip_vrfs);
        for op in &plan.ops {
            record_l3_success(&mut owned, op, &ready, &ip_vrfs, &intent);
        }

        // Second pass with the same intent must produce zero ops
        // (idempotent).
        let plan2 = compute_l3_diff(&intent, &owned, &ready, &ip_vrfs);
        assert_eq!(plan2.ops, vec![], "idempotent on the second pass");
    }
}
