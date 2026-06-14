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
//! ## Transactional ownership
//!
//! Three kernel objects per remote prefix — IP route, L3 neighbor,
//! L3VXLAN FDB — but only one of them (the route) is uniquely owned
//! by a single `(IpVrfId, prefix)`. The neighbor and FDB rows are
//! *shared* across every prefix that advertises the same
//! `(l3vxlan_ifindex, next_hop)` or `(l3vxlan_ifindex, router_mac)`
//! tuple.
//!
//! [`L3OwnedState`] tracks the two layers separately so a partial-
//! success window doesn't leak kernel state:
//!
//! - [`L3OwnedState::installs`] — per-`(vrf, prefix)` rows. Each
//!   tracks `route_installed: bool` plus the cached identity needed
//!   to emit the symmetric remove op.
//! - [`L3OwnedState::kernel_neighbors`] — `(l3vxlan_ifindex,
//!   next_hop) → router_mac` map for every L3 neighbor row we
//!   have programmed. The value (lladdr) is load-bearing
//!   forwarding state; a remote PE rotating its router MAC on
//!   the same next-hop must trigger a replace.
//! - [`L3OwnedState::kernel_fdb`] — `(l3vxlan_ifindex,
//!   router_mac) → next_hop` map for every L3VXLAN FDB row. The
//!   value (dst) is load-bearing: a remote PE migrating its
//!   VTEP behind the same router MAC must trigger a replace, or
//!   the FDB row would silently keep encapsulating to the old
//!   VTEP.
//!
//! With this split, the diff derives `desired_neighbors` /
//! `desired_fdb` from the live `want` set (not from `installs`), so a
//! prefix whose route install failed but whose neighbor/FDB adds
//! succeeded — and that the operator subsequently removed from the
//! intent — still triggers `RemoveL3Neighbor` + `RemoveL3VxlanFdb`
//! cleanup on the next reconcile pass (because the kernel rows are
//! in `kernel_neighbors` / `kernel_fdb` but not in the new
//! `desired_*` sets).
//!
//! The inverse case (a `RemoveRemoteIpRoute` succeeds but the
//! follow-up `RemoveL3Neighbor` fails) likewise stays correctly
//! retryable: `kernel_neighbors` still contains the key, no `want`
//! entry needs it, so the next pass re-emits the remove.
//!
//! ## Router MAC conflict
//!
//! The kernel-side FDB row is `(l3vxlan_ifindex, router_mac) → dst`.
//! Two `want` prefixes carrying the same `router_mac` but different
//! `next_hop` values would have the second `AddL3VxlanFdb` overwrite
//! the first via `.replace()`, silently misforwarding the first
//! prefix's traffic. The diff detects this as
//! [`L3Drop::RouterMacConflict`] and drops *every* conflicting
//! prefix (operator misconfig — fail loud).
//!
//! ## Apply / withdraw order
//!
//! Per ADR-0054 and the user's PR-B research notes, plan ops are
//! emitted in the following four-phase order:
//!
//! 1. **Route removes** — routes go away first so no in-flight
//!    encapsulation depends on resolution rows we're about to tear
//!    down.
//! 2. **Resolution adds** — neighbor adds then FDB adds, so any
//!    fresh route in phase 3 has a complete inner-DMAC resolution.
//! 3. **Route adds** — only after neighbor/FDB are in the kernel.
//! 4. **Resolution removes** — neighbor + FDB rows the diff
//!    determined are no longer needed (no want entry references
//!    them after phase 1's removals).
//!
//! ## Foreign preservation
//!
//! The diff never iterates kernel state — only [`L3OwnedState`], the
//! actor's record of what *we* installed. Routes / neighbors / FDB
//! rows the kernel learned through other paths (`ip route add` by
//! the operator, FRR co-tenant, etc.) are structurally invisible to
//! the withdraw path. Mirrors ADR-0054 §5's foreign-preservation
//! rule on the L2 side.
//!
//! ## Family mismatch
//!
//! IPv6 prefix over IPv4 VTEP (and vice versa) requires `RTA_VIA`
//! for the cross-family gateway encoding, which the current
//! `linux::l3` apply path does not implement. The diff drops
//! mismatched routes into [`L3Drop::FamilyMismatch`] (counted,
//! observable) — explicit suppression rather than a silent
//! miscompose.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use rustbgpd_evpn::ip_vrf::{IpVrfTable, RemoteIpPrefixTable};
use rustbgpd_evpn::{EvpnIpPrefixValue, IpVrfId, MacAddress};

use crate::dataplane::DataplaneOp;

/// State the L3 diff loop owns. Updated only on successful kernel
/// apply by the reconcile actor; a failed op leaves the in-memory
/// state at its prior shape so the next reconcile pass retries.
///
/// The split between `installs` (per-prefix routes) and
/// `kernel_neighbors` / `kernel_fdb` (shared resolution rows) is
/// load-bearing for partial-success safety — see the module-level
/// docs.
///
/// `kernel_neighbors` and `kernel_fdb` track the row *value*, not
/// just the row *key*. The kernel L3 neighbor row is
/// `(dev, dst) → lladdr`; the L3VXLAN FDB row is
/// `(dev, lladdr) → dst`. In both cases the value is load-bearing
/// forwarding state — a remote PE rotating its router MAC, or a
/// MAC-mobility-style next-hop change carrying the same router MAC,
/// must trigger a replace. Tracking only the key (as a `BTreeSet`)
/// would miss those transitions because `desired ∩ current` would
/// look unchanged.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct L3OwnedState {
    /// Per-prefix install state. Created on the first successful
    /// kernel op for that prefix; deleted only when
    /// `route_installed` falls back to false (a `RemoveRemoteIpRoute`
    /// has succeeded). The cached identity stays present for the
    /// withdraw path even if the IP-VRF's `l3vxlan_device` /
    /// `table_id` change at runtime.
    pub installs: BTreeMap<(IpVrfId, EvpnIpPrefixValue), InstallState>,
    /// Per-VRF cache of how many entries in `installs` have
    /// `route_installed == true`. Kept in lock-step with `installs`
    /// through `record_install` / `record_remove` so
    /// `route_count_for` is O(log VRFs) instead of an O(N) scan.
    pub installed_route_counts: BTreeMap<IpVrfId, u64>,
    /// `(l3vxlan_ifindex, next_hop) → router_mac` for every L3
    /// neighbor row we have programmed. Toggled by `AddL3Neighbor`
    /// (insert / replace) and `RemoveL3Neighbor` (remove) op
    /// successes. The value (lladdr) is tracked so router-MAC drift
    /// on the same next-hop emits a replace.
    pub kernel_neighbors: BTreeMap<(u32, IpAddr), MacAddress>,
    /// `(l3vxlan_ifindex, router_mac) → next_hop` for every L3VXLAN
    /// FDB row we have programmed. Same lifecycle as
    /// `kernel_neighbors`. The value (dst) is tracked so a remote
    /// PE rotating its VTEP while keeping the same router MAC emits
    /// a replace — without this, the FDB row would silently keep
    /// encapsulating to the old VTEP.
    pub kernel_fdb: BTreeMap<(u32, MacAddress), IpAddr>,
}

/// Per-prefix install bookkeeping.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InstallState {
    /// True iff the kernel has the IP route row for this prefix.
    pub route_installed: bool,
    /// Remote VTEP IP — cached so the symmetric remove op uses the
    /// correct gateway even if the projection layer subsequently
    /// changes its mind on the desired next-hop.
    pub next_hop: IpAddr,
    /// Remote PE's router MAC.
    pub router_mac: MacAddress,
    /// L3 VXLAN ifindex at the time of install.
    pub l3vxlan_ifindex: u32,
    /// Kernel VRF route table id.
    pub table_id: u32,
}

impl L3OwnedState {
    /// Currently-installed routes for one IP-VRF. Backing store for
    /// the `IpVrfState.installed_routes_count` gRPC field. Reads
    /// the per-VRF count cache maintained by `record_install` /
    /// `record_remove`; absent means zero.
    #[must_use]
    pub fn route_count_for(&self, vrf_id: IpVrfId) -> u64 {
        self.installed_route_counts
            .get(&vrf_id)
            .copied()
            .unwrap_or(0)
    }

    /// True when the owned set has no routes installed and no
    /// resolution rows in the kernel.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.installs.is_empty() && self.kernel_neighbors.is_empty() && self.kernel_fdb.is_empty()
    }

    /// Insert / replace an install row, keeping the per-VRF
    /// `installed_route_counts` cache in lock-step. Every install
    /// site in this crate that previously did `installs.insert(...)`
    /// must route through here.
    pub(crate) fn record_install(
        &mut self,
        key: (IpVrfId, EvpnIpPrefixValue),
        install: InstallState,
    ) {
        let prev = self.installs.insert(key, install);
        let was_installed = prev.is_some_and(|p| p.route_installed);
        match (was_installed, install.route_installed) {
            (false, true) => {
                *self.installed_route_counts.entry(key.0).or_insert(0) += 1;
            }
            (true, false) => self.decrement_count(key.0),
            _ => {}
        }
    }

    /// Remove an install row, keeping the per-VRF
    /// `installed_route_counts` cache in lock-step. Returns the
    /// removed `InstallState` if one was present (parity with
    /// `BTreeMap::remove`).
    pub(crate) fn record_remove(
        &mut self,
        key: &(IpVrfId, EvpnIpPrefixValue),
    ) -> Option<InstallState> {
        let removed = self.installs.remove(key);
        if removed.is_some_and(|r| r.route_installed) {
            self.decrement_count(key.0);
        }
        removed
    }

    fn decrement_count(&mut self, vrf_id: IpVrfId) {
        if let Some(count) = self.installed_route_counts.get_mut(&vrf_id) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                self.installed_route_counts.remove(&vrf_id);
            }
        }
    }
}

/// Why a desired remote prefix did not make it into the apply plan.
/// Distinct from the projection layer's `DropReason` (which captures
/// projection-time drops); this enum captures install-time drops,
/// surfaced for per-VRF Prometheus counters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum L3Drop {
    /// IP-VRF is `NotReady` — every desired prefix in it is
    /// suppressed.
    NotReady {
        vrf_id: IpVrfId,
        prefix: EvpnIpPrefixValue,
    },
    /// Cross-family prefix vs next-hop. Slice 6c does not implement
    /// `RTA_VIA`.
    FamilyMismatch {
        vrf_id: IpVrfId,
        prefix: EvpnIpPrefixValue,
        next_hop: IpAddr,
    },
    /// Two or more `want` prefixes share an
    /// `(l3vxlan_ifindex, router_mac)` key but advertise different
    /// `next_hop` values. The kernel FDB can only store one
    /// destination per `(idx, mac)` key, so installing both would
    /// silently misforward one prefix's traffic to the other's
    /// VTEP. Drop all conflicting prefixes — operator must
    /// reconfigure.
    RouterMacConflict {
        vrf_id: IpVrfId,
        prefix: EvpnIpPrefixValue,
        router_mac: MacAddress,
        conflicting_next_hop: IpAddr,
    },
}

/// Output of one L3 diff pass.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct L3Plan {
    /// Ops to apply, in the four-phase order documented at the
    /// module level. The reconcile actor feeds them through
    /// `Dataplane::apply` sequentially.
    pub ops: Vec<DataplaneOp>,
    /// Drops captured this pass, for per-`(vrf, reason)` Prometheus
    /// counters.
    pub drops: Vec<L3Drop>,
}

/// Resolved install target derived from one `(vrf, prefix)` in
/// `want`. Carries every identity the apply path needs.
#[derive(Debug, Clone, Copy)]
struct Target {
    next_hop: IpAddr,
    router_mac: MacAddress,
    l3vxlan_ifindex: u32,
    table_id: u32,
}

impl Target {
    fn shape_matches(&self, install: &InstallState) -> bool {
        self.next_hop == install.next_hop
            && self.router_mac == install.router_mac
            && self.l3vxlan_ifindex == install.l3vxlan_ifindex
            && self.table_id == install.table_id
    }
}

/// Compute the next L3 plan from the desired projection + current
/// owned state + the per-VRF Ready / ifindex map.
///
/// `ready_l3vxlan_ifindex` is `IpVrfId → l3vxlan_ifindex` for every
/// VRF whose readiness probe returned `Ready`. Not-Ready VRFs are
/// simply absent from the map (the diff treats them as "no install"
/// → withdraw everything we own).
///
/// # Panics
///
/// Panics on an internal invariant violation: the diff's owner-lookup
/// for `AddL3Neighbor` / `AddL3VxlanFdb` ops expects every key in
/// `desired_*` to have been seen during the `want` build. Both
/// `.expect(...)` sites prove a programmer error, not a runtime
/// condition.
#[allow(clippy::too_many_lines)]
#[must_use]
pub fn compute_l3_diff(
    intent: &RemoteIpPrefixTable,
    owned: &L3OwnedState,
    ready_l3vxlan_ifindex: &BTreeMap<IpVrfId, u32>,
    ip_vrfs: &IpVrfTable,
) -> L3Plan {
    let mut plan = L3Plan::default();

    // ── Build `want` ───────────────────────────────────────────
    let want = build_want(intent, ip_vrfs, ready_l3vxlan_ifindex, &mut plan);

    // ── Compute desired resolution maps from `want` ────────────
    //
    // The values matter: kernel neighbor rows are
    // `(dev, dst) → lladdr` and FDB rows are `(dev, lladdr) → dst`.
    // The router_mac-conflict check in `build_want` already drops
    // any `want` set with multiple distinct values per key, so each
    // map entry has exactly one value.
    let mut desired_neighbors: BTreeMap<(u32, IpAddr), MacAddress> = BTreeMap::new();
    let mut desired_fdb: BTreeMap<(u32, MacAddress), IpAddr> = BTreeMap::new();
    for target in want.values() {
        desired_neighbors.insert((target.l3vxlan_ifindex, target.next_hop), target.router_mac);
        desired_fdb.insert((target.l3vxlan_ifindex, target.router_mac), target.next_hop);
    }

    // ── Phase A: route removes ─────────────────────────────────
    //
    // Any owned install whose shape no longer matches `want` (or
    // whose prefix dropped from `want` entirely) has its route
    // torn down first. Resolution-row removal happens in Phase D
    // once we've torn down every dependent route.
    let mut shape_changed: BTreeSet<(IpVrfId, EvpnIpPrefixValue)> = BTreeSet::new();
    for ((vrf_id, prefix), install) in &owned.installs {
        let want_entry = want.get(&(*vrf_id, *prefix));
        let shape_ok = want_entry.is_some_and(|t| t.shape_matches(install));
        if shape_ok {
            continue;
        }
        if install.route_installed {
            plan.ops.push(DataplaneOp::RemoveRemoteIpRoute {
                vrf_id: *vrf_id,
                prefix: *prefix,
                table_id: install.table_id,
                l3vxlan_ifindex: install.l3vxlan_ifindex,
                next_hop: install.next_hop,
            });
        }
        if want_entry.is_some() {
            // Shape change — the prefix is still in `want`, but the
            // identity differs. Phase C re-installs from scratch.
            shape_changed.insert((*vrf_id, *prefix));
        }
    }

    // ── Phase B: resolution adds (or replaces on value drift) ──
    //
    // Order: neighbor adds, then FDB adds. Emit an `AddL3Neighbor`
    // when either:
    //   (a) the `(l3vxlan_ifindex, next_hop)` key is missing from
    //       `kernel_neighbors`, OR
    //   (b) the kernel has the row but its recorded `router_mac`
    //       differs from the desired one — a remote PE's router
    //       MAC rotated, and the kernel's `.replace()` overwrites
    //       the existing row atomically.
    // Same logic for FDB. Without (b) a router_mac-stable
    // next-hop migration (operator moves the prefix's VTEP behind
    // the same router MAC) would leave the FDB row pointing at
    // the old VTEP — silent misforwarding.
    //
    // Picking one arbitrary `want` entry per key supplies the
    // `vrf_id` accounting tag; the value (router_mac for neighbor,
    // next_hop for FDB) comes from `desired_*`.
    let mut neighbor_op_owners: BTreeMap<(u32, IpAddr), IpVrfId> = BTreeMap::new();
    let mut fdb_op_owners: BTreeMap<(u32, MacAddress), IpVrfId> = BTreeMap::new();
    for ((vrf_id, _prefix), target) in &want {
        neighbor_op_owners
            .entry((target.l3vxlan_ifindex, target.next_hop))
            .or_insert(*vrf_id);
        fdb_op_owners
            .entry((target.l3vxlan_ifindex, target.router_mac))
            .or_insert(*vrf_id);
    }
    for ((idx, nh), desired_router_mac) in &desired_neighbors {
        let needs_install = match owned.kernel_neighbors.get(&(*idx, *nh)) {
            None => true,
            Some(current) => current != desired_router_mac,
        };
        if needs_install {
            let vrf_id = neighbor_op_owners
                .get(&(*idx, *nh))
                .copied()
                .expect("desired_neighbors keys come from neighbor_op_owners");
            plan.ops.push(DataplaneOp::AddL3Neighbor {
                vrf_id,
                l3vxlan_ifindex: *idx,
                next_hop: *nh,
                router_mac: *desired_router_mac,
            });
        }
    }
    for ((idx, router_mac), desired_next_hop) in &desired_fdb {
        let needs_install = match owned.kernel_fdb.get(&(*idx, *router_mac)) {
            None => true,
            Some(current) => current != desired_next_hop,
        };
        if needs_install {
            let vrf_id = fdb_op_owners
                .get(&(*idx, *router_mac))
                .copied()
                .expect("desired_fdb keys come from fdb_op_owners");
            plan.ops.push(DataplaneOp::AddL3VxlanFdb {
                vrf_id,
                l3vxlan_ifindex: *idx,
                router_mac: *router_mac,
                next_hop: *desired_next_hop,
            });
        }
    }

    // ── Phase C: route adds ────────────────────────────────────
    //
    // For each `want` entry whose owned install is missing, has a
    // shape mismatch, or has `route_installed=false`, emit
    // `AddRemoteIpRoute`. The shape-mismatch case is covered by
    // Phase A's RemoveRemoteIpRoute earlier in the same plan — the
    // apply path executes them in order, so the kernel sees
    // remove then add for shape transitions.
    for ((vrf_id, prefix), target) in &want {
        let needs_route = match owned.installs.get(&(*vrf_id, *prefix)) {
            None => true,
            Some(install) if !target.shape_matches(install) => true,
            Some(install) => !install.route_installed,
        };
        if needs_route {
            plan.ops.push(DataplaneOp::AddRemoteIpRoute {
                vrf_id: *vrf_id,
                prefix: *prefix,
                table_id: target.table_id,
                l3vxlan_ifindex: target.l3vxlan_ifindex,
                next_hop: target.next_hop,
                router_mac: target.router_mac,
            });
        }
    }

    // ── Phase D: resolution removes ────────────────────────────
    //
    // Any kernel resolution row whose key is no longer in
    // `desired_*` is torn down. Order: neighbor removes, then FDB
    // removes (same intra-phase order as the adds in Phase B).
    //
    // Value drift on a key that *is* still desired does NOT remove
    // here — Phase B already emitted a `.replace()` AddL3* op for
    // it, which the kernel applies atomically. Emitting Remove +
    // Add for the same key would leave a brief window with no
    // resolution row, and the AddL3* replace is sufficient.
    for (idx, nh) in owned.kernel_neighbors.keys() {
        if !desired_neighbors.contains_key(&(*idx, *nh)) {
            let (vrf_id, _) = remove_neighbor_owner(&owned.installs, *idx, *nh);
            plan.ops.push(DataplaneOp::RemoveL3Neighbor {
                vrf_id,
                l3vxlan_ifindex: *idx,
                next_hop: *nh,
            });
        }
    }
    for (idx, router_mac) in owned.kernel_fdb.keys() {
        if !desired_fdb.contains_key(&(*idx, *router_mac)) {
            let vrf_id = remove_fdb_owner(&owned.installs, *idx, *router_mac);
            plan.ops.push(DataplaneOp::RemoveL3VxlanFdb {
                vrf_id,
                l3vxlan_ifindex: *idx,
                router_mac: *router_mac,
            });
        }
    }

    plan
}

/// Build the validated `want` set and record drops.
fn build_want(
    intent: &RemoteIpPrefixTable,
    ip_vrfs: &IpVrfTable,
    ready_l3vxlan_ifindex: &BTreeMap<IpVrfId, u32>,
    plan: &mut L3Plan,
) -> BTreeMap<(IpVrfId, EvpnIpPrefixValue), Target> {
    let mut want: BTreeMap<(IpVrfId, EvpnIpPrefixValue), Target> = BTreeMap::new();
    for ((vrf_id, prefix), entry) in intent.iter() {
        let Some(vrf) = ip_vrfs.iter().find(|v| v.id == *vrf_id) else {
            // Projection produced an entry for an unknown VRF; drop
            // silently — the projection-side `DropReason` would have
            // already caught this if reachable.
            continue;
        };
        let Some(ifindex) = ready_l3vxlan_ifindex.get(vrf_id).copied() else {
            plan.drops.push(L3Drop::NotReady {
                vrf_id: *vrf_id,
                prefix: *prefix,
            });
            continue;
        };
        if !family_matches(*prefix, entry.next_hop) || !family_matches(*prefix, vrf.local_vtep_ip) {
            plan.drops.push(L3Drop::FamilyMismatch {
                vrf_id: *vrf_id,
                prefix: *prefix,
                next_hop: entry.next_hop,
            });
            continue;
        }
        want.insert(
            (*vrf_id, *prefix),
            Target {
                next_hop: entry.next_hop,
                router_mac: entry.router_mac,
                l3vxlan_ifindex: ifindex,
                table_id: vrf.table_id,
            },
        );
        let _ = entry; // suppress accidental clippy::used-binding noise
    }

    // ── Router MAC conflict detection ──────────────────────────
    //
    // The kernel FDB row is `(l3vxlan_ifindex, router_mac) → dst`.
    // If two `want` entries claim the same `(idx, router_mac)` but
    // map it to different next-hops, the last `AddL3VxlanFdb` to
    // win the race would silently misforward the other prefix's
    // traffic. Drop every conflicting entry (operator misconfig —
    // fail loud).
    let mut by_mac: BTreeMap<(u32, MacAddress), BTreeSet<IpAddr>> = BTreeMap::new();
    for target in want.values() {
        by_mac
            .entry((target.l3vxlan_ifindex, target.router_mac))
            .or_default()
            .insert(target.next_hop);
    }
    let conflicting: BTreeSet<(u32, MacAddress)> = by_mac
        .iter()
        .filter(|(_, hops)| hops.len() > 1)
        .map(|(k, _)| *k)
        .collect();
    if !conflicting.is_empty() {
        let conflict_keys: Vec<(IpVrfId, EvpnIpPrefixValue, MacAddress, IpAddr)> = want
            .iter()
            .filter_map(|((vrf_id, prefix), t)| {
                if conflicting.contains(&(t.l3vxlan_ifindex, t.router_mac)) {
                    Some((*vrf_id, *prefix, t.router_mac, t.next_hop))
                } else {
                    None
                }
            })
            .collect();
        for (vrf_id, prefix, router_mac, conflicting_next_hop) in conflict_keys {
            want.remove(&(vrf_id, prefix));
            plan.drops.push(L3Drop::RouterMacConflict {
                vrf_id,
                prefix,
                router_mac,
                conflicting_next_hop,
            });
        }
    }

    want
}

/// Find an owner install for a neighbor key we're about to remove.
/// Returns `(vrf_id_tag, router_mac_tag)` — the values are purely
/// for accounting on the emitted op; the kernel doesn't need
/// `router_mac` on the remove side, so the second tuple element is
/// returned unused for callers that want it.
fn remove_neighbor_owner(
    installs: &BTreeMap<(IpVrfId, EvpnIpPrefixValue), InstallState>,
    idx: u32,
    next_hop: IpAddr,
) -> (IpVrfId, MacAddress) {
    installs
        .iter()
        .find_map(|((vrf_id, _), i)| {
            if i.l3vxlan_ifindex == idx && i.next_hop == next_hop {
                Some((*vrf_id, i.router_mac))
            } else {
                None
            }
        })
        // Defensive fallback: pick the lowest-numbered IpVrfId we
        // can synthesize. The kernel doesn't care about the
        // accounting tag, only the `(idx, next_hop)` identity.
        .unwrap_or_else(|| {
            (
                IpVrfId::new(1).expect("VNI 1 is always valid"),
                MacAddress::new([0; 6]),
            )
        })
}

/// Find an owner install for an FDB key we're about to remove.
fn remove_fdb_owner(
    installs: &BTreeMap<(IpVrfId, EvpnIpPrefixValue), InstallState>,
    idx: u32,
    router_mac: MacAddress,
) -> IpVrfId {
    installs
        .iter()
        .find_map(|((vrf_id, _), i)| {
            if i.l3vxlan_ifindex == idx && i.router_mac == router_mac {
                Some(*vrf_id)
            } else {
                None
            }
        })
        .unwrap_or_else(|| IpVrfId::new(1).expect("VNI 1 is always valid"))
}

/// Apply a successful op to the owned state. Called once per
/// `Ok(())` from `Dataplane::apply`. Failed ops leave the state
/// unchanged so the next reconcile pass retries.
///
/// For `AddRemoteIpRoute` the actor needs the matching
/// `RemoteIpPrefixEntry` and IP-VRF table to recover the install's
/// cached identity. Pass them through; on a non-matching op variant
/// the parameters are ignored.
pub fn record_l3_success(
    owned: &mut L3OwnedState,
    op: &DataplaneOp,
    ready_l3vxlan_ifindex: &BTreeMap<IpVrfId, u32>,
    ip_vrfs: &IpVrfTable,
    intent: &RemoteIpPrefixTable,
) {
    match op {
        DataplaneOp::AddRemoteIpRoute { vrf_id, prefix, .. } => {
            let entry = intent
                .iter()
                .find_map(|((id, p), e)| (id == vrf_id && p == prefix).then_some(e));
            let vrf = ip_vrfs.iter().find(|v| v.id == *vrf_id);
            let ifindex = ready_l3vxlan_ifindex.get(vrf_id).copied();
            if let (Some(entry), Some(vrf), Some(ifindex)) = (entry, vrf, ifindex) {
                owned.record_install(
                    (*vrf_id, *prefix),
                    InstallState {
                        route_installed: true,
                        next_hop: entry.next_hop,
                        router_mac: entry.router_mac,
                        l3vxlan_ifindex: ifindex,
                        table_id: vrf.table_id,
                    },
                );
            }
        }
        DataplaneOp::RemoveRemoteIpRoute { vrf_id, prefix, .. } => {
            owned.record_remove(&(*vrf_id, *prefix));
        }
        DataplaneOp::AddL3Neighbor {
            l3vxlan_ifindex,
            next_hop,
            router_mac,
            ..
        } => {
            // Insert-or-replace: the lladdr value is the load-bearing
            // forwarding state, so a router-MAC drift on the same
            // (idx, next_hop) key overwrites the prior value.
            owned
                .kernel_neighbors
                .insert((*l3vxlan_ifindex, *next_hop), *router_mac);
        }
        DataplaneOp::RemoveL3Neighbor {
            l3vxlan_ifindex,
            next_hop,
            ..
        } => {
            owned
                .kernel_neighbors
                .remove(&(*l3vxlan_ifindex, *next_hop));
        }
        DataplaneOp::AddL3VxlanFdb {
            l3vxlan_ifindex,
            router_mac,
            next_hop,
            ..
        } => {
            // Insert-or-replace: the dst value is load-bearing.
            owned
                .kernel_fdb
                .insert((*l3vxlan_ifindex, *router_mac), *next_hop);
        }
        DataplaneOp::RemoveL3VxlanFdb {
            l3vxlan_ifindex,
            router_mac,
            ..
        } => {
            owned.kernel_fdb.remove(&(*l3vxlan_ifindex, *router_mac));
        }
        DataplaneOp::AddRemoteFdb { .. }
        | DataplaneOp::UpdateRemoteFdb { .. }
        | DataplaneOp::RemoveRemoteFdb { .. }
        | DataplaneOp::SetBumPortFlags { .. }
        | DataplaneOp::SetAcPortState { .. }
        | DataplaneOp::InstallFdbNhg { .. }
        | DataplaneOp::UpdateFdbNhgMembers { .. }
        | DataplaneOp::RemoveFdbNhg { .. } => {
            // L2 FDB / BUM / AC-gate / FDB-NHG ops have their own
            // owned state.
        }
    }
}

fn family_matches(prefix: EvpnIpPrefixValue, addr: IpAddr) -> bool {
    matches!(
        (prefix, addr),
        (EvpnIpPrefixValue::V4(_), IpAddr::V4(_)) | (EvpnIpPrefixValue::V6(_), IpAddr::V6(_))
    )
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use rustbgpd_evpn::ip_vrf::{IpVrf, ProjectedIpPrefixRoute, project_ip_prefix_routes};
    use rustbgpd_evpn::{EthernetSegmentIdentifier, Ipv4Prefix};
    use std::net::{IpAddr, Ipv4Addr};

    fn mac(b: u8) -> MacAddress {
        MacAddress::new([0xaa, 0xbb, 0xcc, 0xdd, 0xee, b])
    }

    fn vrf(id: u32, table_id: u32, vtep: IpAddr) -> IpVrf {
        IpVrf::new(
            format!("vrf{id}"),
            IpVrfId::new(id).unwrap(),
            format!("65000:{id}")
                .parse::<rustbgpd_evpn::RouteDistinguisher>()
                .unwrap(),
            vec![
                format!("65000:{id}")
                    .parse::<rustbgpd_evpn::RouteTarget>()
                    .unwrap(),
            ],
            vtep,
            mac(0x10),
            format!("vrf{id}"),
            format!("l3vxlan{id}"),
            table_id,
        )
        .unwrap()
    }

    fn one_vrf_table(id: u32, table_id: u32, vtep: IpAddr) -> IpVrfTable {
        let mut t = IpVrfTable::new();
        t.insert(vrf(id, table_id, vtep)).unwrap();
        t
    }

    fn v4(octets: [u8; 4], len: u8) -> EvpnIpPrefixValue {
        EvpnIpPrefixValue::V4(Ipv4Prefix::new(Ipv4Addr::from(octets), len))
    }

    fn ip4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    /// Build a `RemoteIpPrefixTable` containing a list of routes
    /// for a single VRF. The routes here are pre-built
    /// `ProjectedIpPrefixRoute`s — we pass them through the pure
    /// projection helper so the resulting table looks identical
    /// to one the supervisor would produce.
    fn intent_with(
        ip_vrfs: &IpVrfTable,
        routes: Vec<ProjectedIpPrefixRoute>,
    ) -> RemoteIpPrefixTable {
        project_ip_prefix_routes(ip_vrfs, routes)
    }

    fn t5(
        prefix: EvpnIpPrefixValue,
        next_hop: IpAddr,
        vni: u32,
        rmac: MacAddress,
    ) -> ProjectedIpPrefixRoute {
        let gateway = match prefix {
            EvpnIpPrefixValue::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            EvpnIpPrefixValue::V6(_) => IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
        };
        ProjectedIpPrefixRoute {
            rd: format!("65000:{vni}").parse().unwrap(),
            prefix,
            next_hop,
            gateway,
            esi: EthernetSegmentIdentifier::ZERO,
            l3vni: vni,
            route_targets: vec![format!("65000:{vni}").parse().unwrap()],
            router_mac: Some(rmac),
        }
    }

    /// Cold start with one prefix → three ops in canonical phase
    /// order: neighbor add (B) → FDB add (B) → route add (C).
    #[test]
    fn cold_start_one_prefix_emits_neighbor_then_fdb_then_route() {
        let prefix = v4([198, 51, 100, 0], 24);
        let nh = ip4(10, 0, 0, 2);
        let rmac = mac(0xaa);
        let vrf_id = IpVrfId::new(101).unwrap();
        let ip_vrfs = one_vrf_table(101, 201, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));

        let intent = intent_with(&ip_vrfs, vec![t5(prefix, nh, 101, rmac)]);
        let owned = L3OwnedState::default();
        let ready = BTreeMap::from([(vrf_id, 42_u32)]);

        let plan = compute_l3_diff(&intent, &owned, &ready, &ip_vrfs);
        assert_eq!(plan.drops, vec![]);
        assert_eq!(plan.ops.len(), 3);
        assert!(matches!(plan.ops[0], DataplaneOp::AddL3Neighbor { .. }));
        assert!(matches!(plan.ops[1], DataplaneOp::AddL3VxlanFdb { .. }));
        assert!(matches!(plan.ops[2], DataplaneOp::AddRemoteIpRoute { .. }));
    }

    /// Two prefixes sharing `(idx, vtep, mac)` → second prefix's
    /// plan emits only the route op; the resolution rows already
    /// exist in `kernel_neighbors` / `kernel_fdb`.
    #[test]
    fn second_prefix_sharing_vtep_emits_route_only() {
        let prefix_a = v4([198, 51, 100, 0], 24);
        let prefix_b = v4([198, 51, 101, 0], 24);
        let nh = ip4(10, 0, 0, 2);
        let rmac = mac(0xaa);
        let vrf_id = IpVrfId::new(101).unwrap();
        let ip_vrfs = one_vrf_table(101, 201, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));

        // Simulate "first install already complete".
        let mut owned = L3OwnedState::default();
        owned.record_install(
            (vrf_id, prefix_a),
            InstallState {
                route_installed: true,
                next_hop: nh,
                router_mac: rmac,
                l3vxlan_ifindex: 42,
                table_id: 201,
            },
        );
        owned.kernel_neighbors.insert((42, nh), rmac);
        owned.kernel_fdb.insert((42, rmac), nh);

        let intent = intent_with(
            &ip_vrfs,
            vec![t5(prefix_a, nh, 101, rmac), t5(prefix_b, nh, 101, rmac)],
        );
        let ready = BTreeMap::from([(vrf_id, 42_u32)]);
        let plan = compute_l3_diff(&intent, &owned, &ready, &ip_vrfs);

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

    /// Withdrawing one of two shared prefixes keeps the resolution
    /// rows alive — the second prefix still needs them.
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
            owned.record_install(
                (vrf_id, p),
                InstallState {
                    route_installed: true,
                    next_hop: nh,
                    router_mac: rmac,
                    l3vxlan_ifindex: 42,
                    table_id: 201,
                },
            );
        }
        owned.kernel_neighbors.insert((42, nh), rmac);
        owned.kernel_fdb.insert((42, rmac), nh);

        let intent = intent_with(&ip_vrfs, vec![t5(prefix_a, nh, 101, rmac)]);
        let ready = BTreeMap::from([(vrf_id, 42_u32)]);
        let plan = compute_l3_diff(&intent, &owned, &ready, &ip_vrfs);

        let route_removes = plan
            .ops
            .iter()
            .filter(|op| matches!(op, DataplaneOp::RemoveRemoteIpRoute { .. }))
            .count();
        let neighbor_removes = plan
            .ops
            .iter()
            .filter(|op| matches!(op, DataplaneOp::RemoveL3Neighbor { .. }))
            .count();
        let fdb_removes = plan
            .ops
            .iter()
            .filter(|op| matches!(op, DataplaneOp::RemoveL3VxlanFdb { .. }))
            .count();
        assert_eq!(route_removes, 1);
        assert_eq!(neighbor_removes, 0, "neighbor still in desired set");
        assert_eq!(fdb_removes, 0, "FDB still in desired set");
    }

    /// Withdrawing the last prefix on a shared key tears down
    /// route + neighbor + FDB in canonical phase order.
    #[test]
    fn withdraw_last_prefix_tears_down_neighbor_and_fdb() {
        let prefix = v4([198, 51, 100, 0], 24);
        let nh = ip4(10, 0, 0, 2);
        let rmac = mac(0xaa);
        let vrf_id = IpVrfId::new(101).unwrap();
        let ip_vrfs = one_vrf_table(101, 201, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));

        let mut owned = L3OwnedState::default();
        owned.record_install(
            (vrf_id, prefix),
            InstallState {
                route_installed: true,
                next_hop: nh,
                router_mac: rmac,
                l3vxlan_ifindex: 42,
                table_id: 201,
            },
        );
        owned.kernel_neighbors.insert((42, nh), rmac);
        owned.kernel_fdb.insert((42, rmac), nh);

        let intent = RemoteIpPrefixTable::new();
        let ready = BTreeMap::from([(vrf_id, 42_u32)]);
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
        // Phase A (route remove) → Phase D (neighbor remove → fdb remove).
        assert_eq!(kinds, vec!["route", "neighbor", "fdb"]);
    }

    /// IP-VRF drops out of the ready map → every prefix in it is
    /// withdrawn.
    #[test]
    fn vrf_not_ready_drains_all_owned_routes() {
        let prefix = v4([198, 51, 100, 0], 24);
        let nh = ip4(10, 0, 0, 2);
        let rmac = mac(0xaa);
        let vrf_id = IpVrfId::new(101).unwrap();
        let ip_vrfs = one_vrf_table(101, 201, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));

        let mut owned = L3OwnedState::default();
        owned.record_install(
            (vrf_id, prefix),
            InstallState {
                route_installed: true,
                next_hop: nh,
                router_mac: rmac,
                l3vxlan_ifindex: 42,
                table_id: 201,
            },
        );
        owned.kernel_neighbors.insert((42, nh), rmac);
        owned.kernel_fdb.insert((42, rmac), nh);

        let intent = intent_with(&ip_vrfs, vec![t5(prefix, nh, 101, rmac)]);
        let ready = BTreeMap::new(); // no Ready ifindex → drop

        let plan = compute_l3_diff(&intent, &owned, &ready, &ip_vrfs);
        assert!(matches!(plan.drops.as_slice(), [L3Drop::NotReady { .. }]));
        assert_eq!(plan.ops.len(), 3);
    }

    /// Applying the entire cold-start plan via `record_l3_success`
    /// converges the owned state. A second diff pass against the
    /// same intent emits zero ops.
    #[test]
    fn record_success_makes_diff_idempotent_on_next_pass() {
        let prefix = v4([198, 51, 100, 0], 24);
        let nh = ip4(10, 0, 0, 2);
        let rmac = mac(0xaa);
        let vrf_id = IpVrfId::new(101).unwrap();
        let ip_vrfs = one_vrf_table(101, 201, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));

        let intent = intent_with(&ip_vrfs, vec![t5(prefix, nh, 101, rmac)]);
        let ready = BTreeMap::from([(vrf_id, 42_u32)]);

        let mut owned = L3OwnedState::default();
        let plan = compute_l3_diff(&intent, &owned, &ready, &ip_vrfs);
        for op in &plan.ops {
            record_l3_success(&mut owned, op, &ready, &ip_vrfs, &intent);
        }

        let plan2 = compute_l3_diff(&intent, &owned, &ready, &ip_vrfs);
        assert_eq!(plan2.ops, vec![]);
    }

    /// Regression for review finding #2 (partial-success leak):
    /// `AddL3Neighbor` + `AddL3VxlanFdb` succeed but
    /// `AddRemoteIpRoute` fails. If the operator then removes the
    /// prefix from intent, the next diff pass must emit
    /// `RemoveL3Neighbor` + `RemoveL3VxlanFdb` even though no
    /// install ever recorded `route_installed=true`.
    #[test]
    fn partial_success_cleans_up_when_intent_disappears() {
        let prefix = v4([198, 51, 100, 0], 24);
        let nh = ip4(10, 0, 0, 2);
        let rmac = mac(0xaa);
        let vrf_id = IpVrfId::new(101).unwrap();
        let ip_vrfs = one_vrf_table(101, 201, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));

        // Cold-start plan computed below. We only call
        // `record_l3_success` for the neighbor + FDB ops (simulating
        // a kernel that accepted those but rejected the route).
        let intent = intent_with(&ip_vrfs, vec![t5(prefix, nh, 101, rmac)]);
        let ready = BTreeMap::from([(vrf_id, 42_u32)]);
        let mut owned = L3OwnedState::default();
        let plan = compute_l3_diff(&intent, &owned, &ready, &ip_vrfs);
        for op in &plan.ops {
            if matches!(op, DataplaneOp::AddRemoteIpRoute { .. }) {
                continue; // simulate route apply failure
            }
            record_l3_success(&mut owned, op, &ready, &ip_vrfs, &intent);
        }
        assert!(owned.installs.is_empty(), "route never installed");
        assert!(owned.kernel_neighbors.contains_key(&(42, nh)));
        assert!(owned.kernel_fdb.contains_key(&(42, rmac)));

        // Intent disappears.
        let empty_intent = RemoteIpPrefixTable::new();
        let cleanup = compute_l3_diff(&empty_intent, &owned, &ready, &ip_vrfs);
        let kinds: Vec<&str> = cleanup
            .ops
            .iter()
            .map(|op| match op {
                DataplaneOp::RemoveL3Neighbor { .. } => "neighbor",
                DataplaneOp::RemoveL3VxlanFdb { .. } => "fdb",
                _ => "other",
            })
            .collect();
        assert_eq!(
            kinds,
            vec!["neighbor", "fdb"],
            "stranded kernel rows must be cleaned up on the next reconcile"
        );
    }

    /// Regression for review finding #2 (inverse leak):
    /// `RemoveRemoteIpRoute` succeeds, then `RemoveL3Neighbor` fails.
    /// Owned state: route gone from `installs`, neighbor still in
    /// `kernel_neighbors`. Next diff pass must retry the neighbor
    /// remove even though no route remains.
    #[test]
    fn failed_neighbor_remove_retries_on_next_pass() {
        let nh = ip4(10, 0, 0, 2);
        let rmac = mac(0xaa);
        let vrf_id = IpVrfId::new(101).unwrap();
        let ip_vrfs = one_vrf_table(101, 201, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));

        // Simulate post-route-remove state: route gone, kernel
        // resolution rows still present.
        let mut owned = L3OwnedState::default();
        owned.kernel_neighbors.insert((42, nh), rmac);
        owned.kernel_fdb.insert((42, rmac), nh);

        let empty_intent = RemoteIpPrefixTable::new();
        let ready = BTreeMap::from([(vrf_id, 42_u32)]);
        let plan = compute_l3_diff(&empty_intent, &owned, &ready, &ip_vrfs);
        let neighbor_removes = plan
            .ops
            .iter()
            .filter(|op| matches!(op, DataplaneOp::RemoveL3Neighbor { .. }))
            .count();
        let fdb_removes = plan
            .ops
            .iter()
            .filter(|op| matches!(op, DataplaneOp::RemoveL3VxlanFdb { .. }))
            .count();
        assert_eq!(neighbor_removes, 1, "neighbor removal must retry");
        assert_eq!(fdb_removes, 1, "FDB removal must retry");
    }

    /// Regression for review finding #3: two prefixes claim the
    /// same `(l3vxlan_ifindex, router_mac)` but advertise different
    /// `next_hop` values → both dropped with
    /// `L3Drop::RouterMacConflict`, no `AddL3VxlanFdb` emitted.
    #[test]
    fn router_mac_conflict_drops_both_prefixes() {
        let prefix_a = v4([198, 51, 100, 0], 24);
        let prefix_b = v4([198, 51, 101, 0], 24);
        let nh_a = ip4(10, 0, 0, 2);
        let nh_b = ip4(10, 0, 0, 3);
        let rmac = mac(0xaa); // same MAC, different VTEPs!
        let vrf_id = IpVrfId::new(101).unwrap();
        let ip_vrfs = one_vrf_table(101, 201, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));

        let intent = intent_with(
            &ip_vrfs,
            vec![t5(prefix_a, nh_a, 101, rmac), t5(prefix_b, nh_b, 101, rmac)],
        );
        let owned = L3OwnedState::default();
        let ready = BTreeMap::from([(vrf_id, 42_u32)]);
        let plan = compute_l3_diff(&intent, &owned, &ready, &ip_vrfs);

        // Both prefixes dropped.
        let conflict_drops: Vec<_> = plan
            .drops
            .iter()
            .filter(|d| matches!(d, L3Drop::RouterMacConflict { .. }))
            .collect();
        assert_eq!(conflict_drops.len(), 2, "both prefixes must drop");
        // No FDB add emitted — the conflict drops both candidates.
        assert!(
            plan.ops
                .iter()
                .all(|op| !matches!(op, DataplaneOp::AddL3VxlanFdb { .. })),
            "no FDB add when the (idx, mac) maps to multiple VTEPs",
        );
        // Same for neighbor adds — neither owner survived.
        assert!(
            plan.ops
                .iter()
                .all(|op| !matches!(op, DataplaneOp::AddRemoteIpRoute { .. })),
        );
    }

    /// Regression for review finding #4 (FDB dst drift): the owned
    /// state has an FDB row `(idx, router_mac) → vtep_A`, but the
    /// desired intent maps the same `(idx, router_mac)` to
    /// `vtep_B`. Without value tracking, the diff would see the
    /// `(idx, router_mac)` key in both `desired` and `kernel` and
    /// emit no `AddL3VxlanFdb` — leaving the FDB pointing at
    /// `vtep_A` while the route went to `vtep_B`. Now the diff
    /// emits `AddL3VxlanFdb` so the kernel's `.replace()`
    /// overwrites the dst atomically.
    #[test]
    fn fdb_dst_drift_emits_replace() {
        let prefix = v4([198, 51, 100, 0], 24);
        let old_vtep = ip4(10, 0, 0, 2);
        let new_vtep = ip4(10, 0, 0, 3);
        let rmac = mac(0xaa);
        let vrf_id = IpVrfId::new(101).unwrap();
        let ip_vrfs = one_vrf_table(101, 201, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));

        // Simulate: a previous reconcile installed the prefix
        // pointing at old_vtep. Now the remote PE has migrated the
        // prefix behind the same router MAC to new_vtep — the
        // intent now carries new_vtep for the same (idx, router_mac).
        let mut owned = L3OwnedState::default();
        owned.record_install(
            (vrf_id, prefix),
            InstallState {
                route_installed: true,
                next_hop: old_vtep,
                router_mac: rmac,
                l3vxlan_ifindex: 42,
                table_id: 201,
            },
        );
        owned.kernel_neighbors.insert((42, old_vtep), rmac);
        owned.kernel_fdb.insert((42, rmac), old_vtep);

        let intent = intent_with(&ip_vrfs, vec![t5(prefix, new_vtep, 101, rmac)]);
        let ready = BTreeMap::from([(vrf_id, 42_u32)]);
        let plan = compute_l3_diff(&intent, &owned, &ready, &ip_vrfs);

        // The prefix's identity changed (next_hop), so Phase A
        // emits a RemoveRemoteIpRoute against the old shape, and
        // Phase C emits AddRemoteIpRoute against the new shape.
        // The (idx, router_mac) → dst FDB key is still in
        // `desired_fdb`, but its value has changed → AddL3VxlanFdb
        // is emitted to replace the row with the new dst.
        let fdb_adds: Vec<_> = plan
            .ops
            .iter()
            .filter_map(|op| match op {
                DataplaneOp::AddL3VxlanFdb { next_hop, .. } => Some(*next_hop),
                _ => None,
            })
            .collect();
        assert_eq!(
            fdb_adds,
            vec![new_vtep],
            "FDB dst drift must emit a replace op targeting the new VTEP",
        );
    }

    /// Regression for review finding #4 (neighbor lladdr drift):
    /// the owned state has a neighbor row `(idx, next_hop) →
    /// router_mac_A`, but the desired intent now maps the same
    /// `(idx, next_hop)` to `router_mac_B` (remote PE rotated its
    /// router MAC). Without value tracking, the diff would emit no
    /// `AddL3Neighbor` and the kernel would keep using the old
    /// lladdr for the inner Ethernet header.
    #[test]
    fn neighbor_lladdr_drift_emits_replace() {
        let prefix = v4([198, 51, 100, 0], 24);
        let nh = ip4(10, 0, 0, 2);
        let old_rmac = mac(0xaa);
        let new_rmac = mac(0xbb);
        let vrf_id = IpVrfId::new(101).unwrap();
        let ip_vrfs = one_vrf_table(101, 201, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));

        let mut owned = L3OwnedState::default();
        owned.record_install(
            (vrf_id, prefix),
            InstallState {
                route_installed: true,
                next_hop: nh,
                router_mac: old_rmac,
                l3vxlan_ifindex: 42,
                table_id: 201,
            },
        );
        owned.kernel_neighbors.insert((42, nh), old_rmac);
        owned.kernel_fdb.insert((42, old_rmac), nh);

        let intent = intent_with(&ip_vrfs, vec![t5(prefix, nh, 101, new_rmac)]);
        let ready = BTreeMap::from([(vrf_id, 42_u32)]);
        let plan = compute_l3_diff(&intent, &owned, &ready, &ip_vrfs);

        // The (idx, next_hop) key is still in `desired_neighbors`,
        // but the value (lladdr) has changed → AddL3Neighbor emits
        // the new router_mac.
        let neighbor_adds: Vec<_> = plan
            .ops
            .iter()
            .filter_map(|op| match op {
                DataplaneOp::AddL3Neighbor { router_mac, .. } => Some(*router_mac),
                _ => None,
            })
            .collect();
        assert_eq!(
            neighbor_adds,
            vec![new_rmac],
            "neighbor lladdr drift must emit a replace op with the new router MAC",
        );
    }

    /// Regression for Copilot finding `reconcile.rs:489`:
    /// when config reload removes every `[[evpn_ip_vrfs]]`
    /// entry, the `IpVrfTable` carried on `DataplaneIntent`
    /// becomes empty, but `L3OwnedState` can still hold the
    /// kernel rows we installed before the reload. The diff
    /// must drain every owned row in that case — otherwise
    /// the kernel keeps forwarding through L3VXLAN devices
    /// whose IP-VRF config is gone.
    #[test]
    fn empty_intent_with_non_empty_owned_state_drains_everything() {
        let prefix = v4([198, 51, 100, 0], 24);
        let nh = ip4(10, 0, 0, 2);
        let rmac = mac(0xaa);
        let vrf_id = IpVrfId::new(101).unwrap();

        let mut owned = L3OwnedState::default();
        owned.record_install(
            (vrf_id, prefix),
            InstallState {
                route_installed: true,
                next_hop: nh,
                router_mac: rmac,
                l3vxlan_ifindex: 42,
                table_id: 201,
            },
        );
        owned.kernel_neighbors.insert((42, nh), rmac);
        owned.kernel_fdb.insert((42, rmac), nh);

        // Both intent tables empty — simulates "operator removed
        // every [[evpn_ip_vrfs]] entry and reloaded".
        let empty_intent = RemoteIpPrefixTable::new();
        let empty_ip_vrfs = IpVrfTable::new();
        let empty_ready: BTreeMap<IpVrfId, u32> = BTreeMap::new();

        let plan = compute_l3_diff(&empty_intent, &owned, &empty_ready, &empty_ip_vrfs);

        let kinds: Vec<&str> = plan
            .ops
            .iter()
            .map(|op| match op {
                DataplaneOp::RemoveRemoteIpRoute { .. } => "route_remove",
                DataplaneOp::RemoveL3Neighbor { .. } => "neighbor_remove",
                DataplaneOp::RemoveL3VxlanFdb { .. } => "fdb_remove",
                _ => "other",
            })
            .collect();
        assert_eq!(
            kinds,
            vec!["route_remove", "neighbor_remove", "fdb_remove"],
            "empty intent with non-empty owned must drain in canonical phase order \
             (Phase A route remove → Phase D neighbor remove → Phase D FDB remove)",
        );
    }
}
