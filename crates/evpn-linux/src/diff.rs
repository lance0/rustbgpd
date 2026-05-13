//! Pure diff function — the heart of the EVPN Linux reconciler.
//!
//! [`compute_diff`] takes desired intent + kernel snapshot + previously-
//! applied set + per-instance probe results, and returns a [`Plan`] of
//! [`crate::DataplaneOp`]s the actor should attempt to apply. The
//! function is pure: no I/O, no clocks, no allocations beyond the
//! returned `Vec`. That makes the entire reconciliation contract
//! unit-testable without touching netlink.
//!
//! ## Foreign-entry preservation (ADR-0054 §5/§6/§7)
//!
//! The function structurally cannot emit a delete for an FDB entry
//! rustbgpd never programmed. The delete pass iterates [`OwnedSet`],
//! not [`KernelSnapshot`], so:
//!
//! - kernel-learned local MACs (dynamic, no `extern_learn`),
//! - operator-static FDB entries (`permanent` / `noarp`),
//! - entries owned by other agents,
//!
//! are all invisible to the delete logic. They are visible to the
//! create/update pass — but only for the purpose of *skipping* a
//! competing operation, never for overwriting.
//!
//! ## Mobility update path
//!
//! When the same `(VNI, MAC)` shows up in both `desired` and
//! `last_applied` but with a different VTEP IP, an
//! [`crate::DataplaneOp::UpdateRemoteFdb`] is emitted. Mobility
//! sequence is not the trigger — the dst change is. The sequence is
//! recorded on apply (in [`crate::OwnedEntry::last_applied_seq`]) so a
//! later snapshot whose seq is *lower* than what we believe we
//! applied flags a stale race for the next reconcile.
//!
//! The kernel may have an entry under `(VNI, MAC)` with a different
//! `dst` but no `extern_learn` flag — that's a foreign entry the
//! operator placed by hand. Skip; never overwrite.

use std::collections::BTreeSet;
use std::net::IpAddr;

use rustbgpd_evpn::{
    EvpnInstanceId, EvpnInstanceTable, MacAddress, RemoteMacEntry, RemoteMacTable, group_members,
};

use crate::dataplane::DataplaneOp;
use crate::group_state::{AliasGroupKey, GroupOwnedMap};
use crate::snapshot::{InstanceProbes, KernelFdbEntry, KernelSnapshot, OwnedEntryKind, OwnedSet};

/// Output of a single diff pass.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Plan {
    /// Operations to attempt, in deterministic order: deletes first
    /// (including transition removes pushed from Pass 1/1b — e.g.,
    /// `SingleDst → FdbNhg` emits `RemoveRemoteFdb` here), then
    /// creates (sorted by `(VNI, MAC)`), then updates. This ordering
    /// makes transition pairs (`Remove → Install`) safe within a
    /// single plan even though the per-MAC ops target the same
    /// kernel row. The actor applies serially with per-op backoff on
    /// failure.
    pub ops: Vec<DataplaneOp>,
    /// `(VNI, MAC)` keys whose multi-homed Type 2 entry contains at
    /// least one IPv6 alias and therefore fell back to the single-dst
    /// path this pass. ADR-0059 slice 3b emits one warn per
    /// *transition into fallback* — the reconcile actor compares this
    /// set against the previous pass to suppress steady-state spam.
    /// Empty when no entries fall back.
    pub ipv6_alias_fallback_keys: BTreeSet<(EvpnInstanceId, MacAddress)>,
}

impl Plan {
    /// `true` if no operations are scheduled — i.e., the kernel is
    /// already in the desired state.
    #[must_use]
    pub fn is_noop(&self) -> bool {
        self.ops.is_empty()
    }

    /// Number of scheduled operations.
    #[must_use]
    pub fn len(&self) -> usize {
        self.ops.len()
    }

    /// Alias of [`Self::is_noop`] satisfying clippy's
    /// `len-without-is-empty` lint. Prefer [`Self::is_noop`] in
    /// reconciliation code; the empty plan and a no-op pass are the
    /// same thing semantically.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.ops.is_empty()
    }
}

/// Compute the operations needed to bring `snapshot` (kernel state)
/// into agreement with `desired` (the intent), using `last_applied`
/// to identify rustbgpd-owned entries and `probes` to scope work to
/// Ready instances. `instances` carries the per-VNI policy bits
/// (currently `apply_aliasing_ecmp`); VNIs absent from the table
/// default to the production posture (aliasing enabled) — the
/// `probes` readiness gate is the real install/no-install boundary.
///
/// See module docs for the foreign-entry preservation invariant.
#[must_use]
pub fn compute_diff(
    desired: &RemoteMacTable,
    snapshot: &KernelSnapshot,
    last_applied: &OwnedSet,
    probes: &InstanceProbes,
    groups: &GroupOwnedMap,
    instances: &EvpnInstanceTable,
) -> Plan {
    let mut creates: Vec<DataplaneOp> = Vec::new();
    let mut updates: Vec<DataplaneOp> = Vec::new();
    let mut deletes: Vec<DataplaneOp> = Vec::new();

    // Pass 1b helpers — track which (VNI, ESI, EthTag) groups have
    // already been considered for member-set diff, so two MACs
    // sharing the same group_key produce at most one
    // `UpdateFdbNhgMembers` op per pass.
    let mut group_seen: BTreeSet<AliasGroupKey> = BTreeSet::new();

    // Collect every (VNI, MAC) that hit the IPv6-fallback arm this
    // pass. The reconcile actor diffs this against the previous
    // pass's set so the warn fires once per *transition into
    // fallback*, not once per reconcile. Empty when no entries fall
    // back.
    let mut ipv6_alias_fallback_keys: BTreeSet<(EvpnInstanceId, MacAddress)> = BTreeSet::new();

    // Pass 1 + 1b — creates / updates. Scoped to Ready instances;
    // entries for NotReady / Unbound instances contribute zero ops.
    for (&(vni, mac), entry) in desired.iter() {
        if !probes.is_ready(vni) {
            continue;
        }

        // Decide single-dst vs FDB-NHG path on three dimensions:
        //   - `alias_group_key`: Some(_) when the wire intent
        //     carries a multi-homed `(ESI, EthernetTag)` group key
        //     (slice 1).
        //   - `all_v4`: false when any alias / primary is IPv6.
        //     Slice 2 `NexthopSocket` rejects v6 gateways, so the
        //     FDB-NHG path can't handle it yet — diff degrades to
        //     single-dst at the primary VTEP and records the key
        //     so the reconcile actor can warn once per
        //     enter-fallback transition.
        //   - `aliasing_enabled`: false when the operator set
        //     `apply_aliasing_ecmp = false` for this VNI (slice
        //     3.5 PR 1 off-switch). When the operator turned it
        //     off, there's no IPv6 fallback to warn about — the
        //     dispatch is just "go to single-dst", same as
        //     single-homed.
        let aliasing_enabled = instances.get(vni).is_none_or(|i| i.apply_aliasing_ecmp);
        match (entry.alias_group_key, all_v4(entry), aliasing_enabled) {
            (Some(portable_key), true, true) => {
                // FDB-NHG path.
                let linux_key = AliasGroupKey::new(vni, portable_key.0, portable_key.1);
                emit_fdb_nhg_pass(
                    vni,
                    mac,
                    entry,
                    linux_key,
                    last_applied,
                    snapshot,
                    groups,
                    &mut group_seen,
                    &mut creates,
                    &mut updates,
                    &mut deletes,
                );
            }
            (Some(_), false, true) => {
                // IPv6 fallback — alias-aware *and* aliasing is
                // enabled, but at least one alias is IPv6. The
                // FDB-NHG path can't program v6 gateways in slice
                // 2; record so the actor warns once on the
                // transition into fallback. NOT reached when
                // `aliasing_enabled = false` (the off-switch
                // arm handles all multi-homed entries on that VNI
                // regardless of family — no misleading IPv6 warn
                // when the operator intentionally disabled aliasing).
                ipv6_alias_fallback_keys.insert((vni, mac));
                emit_single_dst_pass(
                    vni,
                    mac,
                    entry,
                    snapshot,
                    last_applied,
                    &mut creates,
                    &mut updates,
                    &mut deletes,
                );
            }
            _ => {
                // Catch-all single-dst:
                //   - (None, _, _) — single-homed entry, slice 1 shape.
                //   - (Some(_), _, false) — multi-homed entry on a VNI
                //     with the operator off-switch flipped. Same path
                //     as single-homed; no fallback record. The
                //     `FdbNhg → SingleDst` transition (when last_applied
                //     carries FdbNhg) is handled inside
                //     `emit_single_dst_pass` via `last_applied` lookup,
                //     so the diff converges cleanly *if* the instance
                //     table ever mutates at runtime. Today the table
                //     is pinned at startup (`[[evpn_instances]]`
                //     reload reverts edits) — the transition only
                //     fires across a daemon restart that takes the
                //     flip via the startup config snapshot.
                emit_single_dst_pass(
                    vni,
                    mac,
                    entry,
                    snapshot,
                    last_applied,
                    &mut creates,
                    &mut updates,
                    &mut deletes,
                );
            }
        }
    }

    // Pass 2 — deletes. Iterate `last_applied`, NEVER the kernel
    // snapshot. This makes foreign-entry preservation a structural
    // property of the algorithm, not a runtime check.
    for (&(vni, mac), owned) in last_applied.iter() {
        let still_desired = desired.get(vni, mac).is_some();
        let instance_ready = probes.is_ready(vni);

        if still_desired && instance_ready {
            continue;
        }

        match owned.kind {
            OwnedEntryKind::SingleDst { .. } => {
                // Existing single-dst delete: check kernel snapshot,
                // emit RemoveRemoteFdb only if the kernel still has
                // it. Interface flap / manual `bridge fdb del` is a
                // no-op for this pass — the actor's OwnedSet drift
                // self-heals on the next successful reconcile.
                if snapshot.find_fdb(vni, mac).is_some() {
                    deletes.push(DataplaneOp::RemoveRemoteFdb { vni, mac });
                }
            }
            OwnedEntryKind::FdbNhg { group_key } => {
                // FDB-NHG delete: always emit. The coordinator is
                // idempotent (slice 3a `apply_remove_fdb_nhg_row`
                // uses `classify_remove_apply_error` → ENOENT-as-ACK).
                // We don't gate on kernel snapshot because nhid-row
                // drift detection from RTNLGRP_NEIGH is incomplete
                // per research §8.
                deletes.push(DataplaneOp::RemoveFdbNhg {
                    vni,
                    mac,
                    group_key,
                });
            }
        }
    }

    // Order: deletes (including Pass 2 withdrawals AND transition
    // removes from Pass 1/1b) → creates → updates. Transition pairs
    // (`SingleDst → FdbNhg`, `FdbNhg → SingleDst`, group-key drift)
    // push their Remove into `deletes` and their Install/Add into
    // `creates`, so the remove always runs first within the plan
    // even though the per-MAC remove + add target the same kernel
    // row. Mobility-style `UpdateRemoteFdb` ops stay in `updates`
    // because they're atomic netlink REPLACE calls, no remove
    // needed.
    // De-dupe redundant `UpdateFdbNhgMembers` ops: if the same plan
    // also carries an `InstallFdbNhg` for the same `group_key`, the
    // Install path's REPLACE branch in `apply_nhg_op` already covers
    // the member-set update, so emitting the Update would be a second
    // REPLACE on the same NHID — wasted netlink churn and a more
    // complicated failure-classification surface.
    let install_group_keys: BTreeSet<AliasGroupKey> = creates
        .iter()
        .filter_map(|op| match op {
            DataplaneOp::InstallFdbNhg { group_key, .. } => Some(*group_key),
            _ => None,
        })
        .collect();
    if !install_group_keys.is_empty() {
        updates.retain(|op| match op {
            DataplaneOp::UpdateFdbNhgMembers { group_key, .. } => {
                !install_group_keys.contains(group_key)
            }
            _ => true,
        });
    }

    let mut ops = deletes;
    ops.append(&mut creates);
    ops.append(&mut updates);
    Plan {
        ops,
        ipv6_alias_fallback_keys,
    }
}

/// `true` when `entry.remote_vtep_ip` and every `alias_vtep_ips`
/// member is IPv4. Slice 1's projection enforces same-family-per-
/// `(ESI, EthernetTag)` so we never see mixed-family aliases; this
/// check is the v4-only gate that triggers the FDB-NHG path.
fn all_v4(entry: &RemoteMacEntry) -> bool {
    entry.remote_vtep_ip.is_ipv4() && entry.alias_vtep_ips.iter().all(IpAddr::is_ipv4)
}

/// Pass 1 / IPv6-fallback emission — emit `AddRemoteFdb` /
/// `UpdateRemoteFdb` for a single-dst entry.
#[allow(clippy::too_many_arguments)]
fn emit_single_dst_pass(
    vni: EvpnInstanceId,
    mac: MacAddress,
    entry: &RemoteMacEntry,
    snapshot: &KernelSnapshot,
    last_applied: &OwnedSet,
    creates: &mut Vec<DataplaneOp>,
    updates: &mut Vec<DataplaneOp>,
    deletes: &mut Vec<DataplaneOp>,
) {
    // Transition: previously installed as FdbNhg, now wants single-dst.
    // Emit RemoveFdbNhg into `deletes` so the plan-level ordering
    // (deletes → creates → updates) runs the remove before the add
    // — apply ops within the same `(vni, mac)` are serialized so
    // this avoids kernel-side conflicts. RemoveFdbNhg is idempotent
    // on `ENOENT` (slice 3a `classify_remove_apply_error`), so we
    // emit unconditionally without gating on the kernel snapshot.
    if let Some(owned) = last_applied.get(vni, mac)
        && let OwnedEntryKind::FdbNhg { group_key } = owned.kind
    {
        deletes.push(DataplaneOp::RemoveFdbNhg {
            vni,
            mac,
            group_key,
        });
        creates.push(DataplaneOp::AddRemoteFdb {
            vni,
            mac,
            dst: entry.remote_vtep_ip,
        });
        return;
    }

    match snapshot.find_fdb(vni, mac) {
        None => {
            creates.push(DataplaneOp::AddRemoteFdb {
                vni,
                mac,
                dst: entry.remote_vtep_ip,
            });
        }
        Some(kernel_entry) => {
            handle_existing_kernel_entry(
                vni,
                mac,
                kernel_entry,
                entry.remote_vtep_ip,
                last_applied,
                updates,
            );
        }
    }
}

/// Pass 1b emission — `InstallFdbNhg` / `UpdateFdbNhgMembers` /
/// transitions when the entry is FDB-NHG-eligible.
#[allow(clippy::too_many_arguments)]
fn emit_fdb_nhg_pass(
    vni: EvpnInstanceId,
    mac: MacAddress,
    entry: &RemoteMacEntry,
    linux_key: AliasGroupKey,
    last_applied: &OwnedSet,
    snapshot: &KernelSnapshot,
    groups: &GroupOwnedMap,
    group_seen: &mut BTreeSet<AliasGroupKey>,
    creates: &mut Vec<DataplaneOp>,
    updates: &mut Vec<DataplaneOp>,
    deletes: &mut Vec<DataplaneOp>,
) {
    let canonical = group_members(entry);

    let owned_kind = last_applied.get(vni, mac).map(|e| e.kind.clone());
    match owned_kind {
        None => {
            // Fresh install — but `last_applied` empty doesn't mean the
            // kernel is empty: on restart we lose the in-memory owned
            // set, and an operator may have a static row at this MAC.
            // Foreign-entry preservation (the module-level invariant)
            // gates Install on whichever holds:
            //   - no kernel row, OR
            //   - the row is `extern_learn` (our own marker — restart
            //     case or NHG-tagged carryover; NLM_F_REPLACE heals).
            // Operator-static / kernel-learned rows are skipped here
            // the same way `handle_existing_kernel_entry` does for the
            // single-dst path.
            let install_safe = match snapshot.find_fdb(vni, mac) {
                None => true,
                Some(k) => k.is_extern_learned(),
            };
            if install_safe {
                creates.push(DataplaneOp::InstallFdbNhg {
                    vni,
                    mac,
                    group_key: linux_key,
                    members: canonical,
                });
            } else {
                tracing::trace!(
                    ?vni,
                    mac = %mac,
                    "FDB-NHG install skipped: foreign kernel row at this (vni, mac)"
                );
            }
        }
        Some(OwnedEntryKind::SingleDst { .. }) => {
            // Single-dst → FDB-NHG transition. Remove the old row
            // first (goes into `deletes` so the plan-level ordering
            // runs it before the Install). Gate on snapshot presence:
            // `RemoveRemoteFdb` via `linux::fdb::classify_apply_error`
            // treats `ENOENT` as transient (would backoff-retry
            // forever), so don't emit if the kernel row is already
            // gone.
            if snapshot.find_fdb(vni, mac).is_some() {
                deletes.push(DataplaneOp::RemoveRemoteFdb { vni, mac });
            }
            creates.push(DataplaneOp::InstallFdbNhg {
                vni,
                mac,
                group_key: linux_key,
                members: canonical,
            });
        }
        Some(OwnedEntryKind::FdbNhg {
            group_key: prev_key,
        }) if prev_key != linux_key => {
            // Group-key drift on the same MAC (ESI change / VNI change).
            // RemoveFdbNhg is idempotent on ENOENT (slice 3a) so
            // unconditional emission is safe. Goes into `deletes`
            // for plan-level ordering.
            deletes.push(DataplaneOp::RemoveFdbNhg {
                vni,
                mac,
                group_key: prev_key,
            });
            creates.push(DataplaneOp::InstallFdbNhg {
                vni,
                mac,
                group_key: linux_key,
                members: canonical,
            });
        }
        Some(OwnedEntryKind::FdbNhg { .. }) => {
            // Same key. Per-MAC FDB row already installed.
            let tracked_group_id = groups.group(&linux_key).map(|g| g.id);

            // Per-group member-set diff. Dedupe across MACs that
            // share the group. The group-missing case (our local
            // state doesn't track this `linux_key`) is intentionally
            // *not* healed here — the per-MAC kernel-drift check
            // below emits one Install per MAC, which the apply path
            // dedupes at the group level via `record_group_install`.
            if group_seen.insert(linux_key)
                && let Some(existing) = groups.group(&linux_key)
            {
                let existing_members: Vec<_> = existing.members.iter().copied().collect();
                if existing_members != canonical {
                    updates.push(DataplaneOp::UpdateFdbNhgMembers {
                        group_key: linux_key,
                        members: canonical.clone(),
                    });
                }
            }

            // Per-MAC kernel-snapshot drift check. Re-emit Install
            // when:
            //   - kernel has no FDB row for `(vni, mac)`,
            //   - kernel row is single-dst (no `nh_id`),
            //   - kernel row points at an `nh_id` that doesn't
            //     match our locally-tracked group ID (manual
            //     `bridge fdb replace`, partial-failure carryover,
            //     or stale state — we'd silently forward via the
            //     wrong group otherwise),
            //   - or we don't track the group locally
            //     (startup-adoption mismatch).
            // `InstallFdbNhg` is idempotent under `NLM_F_REPLACE` so
            // re-emitting when the row is already correct is safe.
            let kernel_row_correct = snapshot
                .find_fdb(vni, mac)
                .and_then(|k| k.nh_id)
                .is_some_and(|kernel_id| tracked_group_id == Some(kernel_id));
            if !kernel_row_correct {
                creates.push(DataplaneOp::InstallFdbNhg {
                    vni,
                    mac,
                    group_key: linux_key,
                    members: canonical,
                });
            }
        }
    }
}

/// Decide what to do when `desired` wants `(vni, mac) -> dst` and the
/// kernel already has *some* entry there. Splits the four interesting
/// cases:
///
/// 1. We own it (`extern_learn` + `last_applied`) and dst matches — no-op.
/// 2. We own it but dst differs — emit `UpdateRemoteFdb` (mobility).
/// 3. Foreign kernel-learned local MAC — log + skip; the upward
///    `LocalMacObservation` handles RFC 7432 §15 mobility resolution at
///    the domain layer.
/// 4. Foreign static / permanent / `self` entry — operator territory;
///    skip without logging at warn level.
fn handle_existing_kernel_entry(
    vni: EvpnInstanceId,
    mac: MacAddress,
    kernel_entry: &KernelFdbEntry,
    desired_dst: std::net::IpAddr,
    last_applied: &OwnedSet,
    updates: &mut Vec<DataplaneOp>,
) {
    let we_own_it = kernel_entry.is_extern_learned() && last_applied.contains(vni, mac);

    if we_own_it {
        if kernel_entry.dst != Some(desired_dst) {
            updates.push(DataplaneOp::UpdateRemoteFdb {
                vni,
                mac,
                dst: desired_dst,
            });
        }
        // else: kernel already matches; no-op.
        return;
    }

    if kernel_entry.is_kernel_learned_local() {
        // Mobility race: kernel learned the same MAC locally. Per
        // ADR-0054 §5, we skip programming the remote and let the
        // domain layer resolve via RFC 7432 §15.
        tracing::debug!(
            ?vni,
            mac = %mac,
            "kernel-learned local MAC blocks remote programming; skipping"
        );
        return;
    }

    // Operator-static / `self` / non-extern_learn entry. Skip silently;
    // the operator owns this entry.
    tracing::trace!(
        ?vni,
        mac = %mac,
        "foreign FDB entry preserved (not extern_learn, not kernel-learned)"
    );
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use rustbgpd_evpn::{
        EvpnInstance, EvpnInstanceId, EvpnInstanceTable, MacAddress, RemoteMacEntry,
        RemoteMacSource, RemoteMacTable, RouteTarget,
    };

    use super::*;
    use crate::snapshot::{
        InstanceProbe, InstanceProbes, KernelFdbEntry, KernelFdbFlags, KernelSnapshot, OwnedEntry,
        OwnedSet,
    };

    fn vni(n: u32) -> EvpnInstanceId {
        EvpnInstanceId::new(n).unwrap()
    }
    fn mac(b: u8) -> MacAddress {
        MacAddress::new([b; 6])
    }
    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn ready_probes(vnis: &[EvpnInstanceId]) -> InstanceProbes {
        let mut p = InstanceProbes::new();
        for &v in vnis {
            p.insert(v, InstanceProbe::Ready);
        }
        p
    }

    /// Build an `EvpnInstanceTable` with one entry per VNI, all
    /// flipped to `apply_aliasing_ecmp = false`. Used by the slice
    /// 3.5 off-switch tests. (Tests that want the production-default
    /// posture pass an empty `EvpnInstanceTable::new()` — unknown
    /// VNIs default to aliasing-enabled.)
    fn instances_disabled(vnis: &[EvpnInstanceId]) -> EvpnInstanceTable {
        let mut t = EvpnInstanceTable::new();
        for &v in vnis {
            let inst = EvpnInstance::new(
                v,
                "65000:1".parse().unwrap(),
                vec!["65000:1".parse::<RouteTarget>().unwrap()],
                "10.0.0.1".parse().unwrap(),
                None,
                false,
            )
            .unwrap()
            .with_apply_aliasing_ecmp(false);
            t.insert(inst).unwrap();
        }
        t
    }

    fn entry(remote: &str, seq: Option<u32>) -> RemoteMacEntry {
        RemoteMacEntry {
            remote_vtep_ip: ip(remote),
            mobility_sequence: seq,
            alias_vtep_ips: Vec::new(),
            alias_group_key: None,
            source: RemoteMacSource::EvpnRibBestPath,
        }
    }

    fn ours(dst: &str) -> KernelFdbEntry {
        KernelFdbEntry {
            mac: mac(0),
            dst: Some(ip(dst)),
            nh_id: None,
            flags: KernelFdbFlags {
                extern_learn: true,
                master: true,
                ..Default::default()
            },
        }
    }

    fn desired_one(v: EvpnInstanceId, m: MacAddress, e: RemoteMacEntry) -> RemoteMacTable {
        let mut b = RemoteMacTable::builder();
        b.insert(v, m, e).unwrap();
        b.build()
    }

    fn applied_one(v: EvpnInstanceId, m: MacAddress, dst: &str, seq: Option<u32>) -> OwnedSet {
        let mut o = OwnedSet::new();
        o.record_applied(v, m, OwnedEntry::single_dst(ip(dst), seq));
        o
    }

    // 1. Empty kernel + one desired entry → one create.
    #[test]
    fn creates_when_kernel_empty() {
        let desired = desired_one(vni(100), mac(1), entry("10.0.0.2", None));
        let snapshot = KernelSnapshot::new();
        let applied = OwnedSet::new();
        let probes = ready_probes(&[vni(100)]);
        let plan = compute_diff(
            &desired,
            &snapshot,
            &applied,
            &probes,
            &GroupOwnedMap::new(),
            &EvpnInstanceTable::new(),
        );
        assert_eq!(
            plan.ops,
            vec![DataplaneOp::AddRemoteFdb {
                vni: vni(100),
                mac: mac(1),
                dst: ip("10.0.0.2"),
            }]
        );
    }

    // 2. Kernel matches desired (same dst, owned) → no-op.
    #[test]
    fn noop_when_kernel_matches_desired() {
        let desired = desired_one(vni(100), mac(1), entry("10.0.0.2", None));
        let mut snapshot = KernelSnapshot::new();
        let mut e = ours("10.0.0.2");
        e.mac = mac(1);
        snapshot.insert_fdb(vni(100), e);
        let applied = applied_one(vni(100), mac(1), "10.0.0.2", None);
        let probes = ready_probes(&[vni(100)]);
        let plan = compute_diff(
            &desired,
            &snapshot,
            &applied,
            &probes,
            &GroupOwnedMap::new(),
            &EvpnInstanceTable::new(),
        );
        assert!(plan.is_noop(), "expected no-op, got {:?}", plan.ops);
    }

    // 3. Mobility — same `(VNI, MAC)`, dst changed → UpdateRemoteFdb.
    #[test]
    fn update_on_vtep_change() {
        let desired = desired_one(vni(100), mac(1), entry("10.0.0.3", None));
        let mut snapshot = KernelSnapshot::new();
        let mut e = ours("10.0.0.2");
        e.mac = mac(1);
        snapshot.insert_fdb(vni(100), e);
        let applied = applied_one(vni(100), mac(1), "10.0.0.2", None);
        let probes = ready_probes(&[vni(100)]);
        let plan = compute_diff(
            &desired,
            &snapshot,
            &applied,
            &probes,
            &GroupOwnedMap::new(),
            &EvpnInstanceTable::new(),
        );
        assert_eq!(
            plan.ops,
            vec![DataplaneOp::UpdateRemoteFdb {
                vni: vni(100),
                mac: mac(1),
                dst: ip("10.0.0.3"),
            }]
        );
    }

    // 4. Entry no longer desired → RemoveRemoteFdb.
    #[test]
    fn delete_when_no_longer_desired() {
        let desired = RemoteMacTable::new();
        let mut snapshot = KernelSnapshot::new();
        let mut e = ours("10.0.0.2");
        e.mac = mac(1);
        snapshot.insert_fdb(vni(100), e);
        let applied = applied_one(vni(100), mac(1), "10.0.0.2", None);
        let probes = ready_probes(&[vni(100)]);
        let plan = compute_diff(
            &desired,
            &snapshot,
            &applied,
            &probes,
            &GroupOwnedMap::new(),
            &EvpnInstanceTable::new(),
        );
        assert_eq!(
            plan.ops,
            vec![DataplaneOp::RemoveRemoteFdb {
                vni: vni(100),
                mac: mac(1),
            }]
        );
    }

    // 5. Instance went NotReady → withdraw owned entries.
    #[test]
    fn delete_when_instance_goes_not_ready() {
        let desired = desired_one(vni(100), mac(1), entry("10.0.0.2", None));
        let mut snapshot = KernelSnapshot::new();
        let mut e = ours("10.0.0.2");
        e.mac = mac(1);
        snapshot.insert_fdb(vni(100), e);
        let applied = applied_one(vni(100), mac(1), "10.0.0.2", None);
        let mut probes = InstanceProbes::new();
        probes.insert(
            vni(100),
            InstanceProbe::NotReady {
                reason: "bridge gone".into(),
            },
        );
        let plan = compute_diff(
            &desired,
            &snapshot,
            &applied,
            &probes,
            &GroupOwnedMap::new(),
            &EvpnInstanceTable::new(),
        );
        assert_eq!(
            plan.ops,
            vec![DataplaneOp::RemoveRemoteFdb {
                vni: vni(100),
                mac: mac(1),
            }]
        );
    }

    // 6. Foreign static entry preserved — kernel has a permanent
    //    entry for the same (VNI, MAC), our applied set is empty.
    //    Pass 1 must skip; pass 2 must not emit (no owned key).
    #[test]
    fn preserves_foreign_static_entry_in_same_vni() {
        let desired = desired_one(vni(100), mac(1), entry("10.0.0.2", None));
        let mut snapshot = KernelSnapshot::new();
        snapshot.insert_fdb(
            vni(100),
            KernelFdbEntry {
                mac: mac(1),
                dst: Some(ip("10.0.0.99")),
                nh_id: None,
                flags: KernelFdbFlags {
                    permanent: true,
                    master: true,
                    ..Default::default()
                },
            },
        );
        let applied = OwnedSet::new();
        let probes = ready_probes(&[vni(100)]);
        let plan = compute_diff(
            &desired,
            &snapshot,
            &applied,
            &probes,
            &GroupOwnedMap::new(),
            &EvpnInstanceTable::new(),
        );
        assert!(
            plan.is_noop(),
            "should not overwrite foreign static, got {:?}",
            plan.ops
        );
    }

    // 7. Foreign kernel-learned local entry — same (VNI, MAC), dynamic,
    //    no extern_learn. Must skip; mobility resolution belongs to
    //    the domain layer.
    #[test]
    fn preserves_foreign_kernel_learned_entry() {
        let desired = desired_one(vni(100), mac(1), entry("10.0.0.2", None));
        let mut snapshot = KernelSnapshot::new();
        snapshot.insert_fdb(
            vni(100),
            KernelFdbEntry {
                mac: mac(1),
                dst: None,
                nh_id: None,
                flags: KernelFdbFlags::default(),
            },
        );
        let applied = OwnedSet::new();
        let probes = ready_probes(&[vni(100)]);
        let plan = compute_diff(
            &desired,
            &snapshot,
            &applied,
            &probes,
            &GroupOwnedMap::new(),
            &EvpnInstanceTable::new(),
        );
        assert!(plan.is_noop(), "should preserve kernel-learned local");
    }

    // 8. `bridge = None` instance — probe says Unbound; no ops emitted
    //    even if desired entries exist for it.
    #[test]
    fn does_not_emit_op_for_unbound_instance() {
        let desired = desired_one(vni(100), mac(1), entry("10.0.0.2", None));
        let snapshot = KernelSnapshot::new();
        let applied = OwnedSet::new();
        let mut probes = InstanceProbes::new();
        probes.insert(vni(100), InstanceProbe::Unbound);
        let plan = compute_diff(
            &desired,
            &snapshot,
            &applied,
            &probes,
            &GroupOwnedMap::new(),
            &EvpnInstanceTable::new(),
        );
        assert!(plan.is_noop());
    }

    // 9. Idempotency — running compute_diff against (snapshot already
    //    matching desired, applied set populated) yields zero ops.
    #[test]
    fn idempotent_on_repeated_call_with_same_inputs() {
        let desired = desired_one(vni(100), mac(1), entry("10.0.0.2", None));
        let mut snapshot = KernelSnapshot::new();
        let mut e = ours("10.0.0.2");
        e.mac = mac(1);
        snapshot.insert_fdb(vni(100), e);
        let applied = applied_one(vni(100), mac(1), "10.0.0.2", None);
        let probes = ready_probes(&[vni(100)]);
        let plan_a = compute_diff(
            &desired,
            &snapshot,
            &applied,
            &probes,
            &GroupOwnedMap::new(),
            &EvpnInstanceTable::new(),
        );
        let plan_b = compute_diff(
            &desired,
            &snapshot,
            &applied,
            &probes,
            &GroupOwnedMap::new(),
            &EvpnInstanceTable::new(),
        );
        assert!(plan_a.is_noop());
        assert_eq!(plan_a, plan_b);
    }

    // 10. Mobility-sequence advance triggers Update, not Add+Remove.
    //     The diff pass keys on (VNI, MAC) + dst; sequence is recorded
    //     on apply but doesn't fan out into separate ops.
    #[test]
    fn mobility_sequence_advance_triggers_update_not_recreate() {
        let desired = desired_one(vni(100), mac(1), entry("10.0.0.3", Some(2)));
        let mut snapshot = KernelSnapshot::new();
        let mut e = ours("10.0.0.2");
        e.mac = mac(1);
        snapshot.insert_fdb(vni(100), e);
        let applied = applied_one(vni(100), mac(1), "10.0.0.2", Some(1));
        let probes = ready_probes(&[vni(100)]);
        let plan = compute_diff(
            &desired,
            &snapshot,
            &applied,
            &probes,
            &GroupOwnedMap::new(),
            &EvpnInstanceTable::new(),
        );
        assert_eq!(
            plan.ops,
            vec![DataplaneOp::UpdateRemoteFdb {
                vni: vni(100),
                mac: mac(1),
                dst: ip("10.0.0.3"),
            }]
        );
    }

    // 11. Owned entry, kernel already lost it (interface flap). Don't
    //     emit a redundant remove; the next successful create-pass
    //     will re-add and clean up the OwnedSet on apply.
    #[test]
    fn owned_entry_already_gone_from_kernel_emits_no_remove() {
        // No longer desired AND kernel doesn't have it → no remove
        // emitted. The actor will drop the owned entry on next
        // successful reconcile.
        let desired = RemoteMacTable::new();
        let snapshot = KernelSnapshot::new();
        let applied = applied_one(vni(100), mac(1), "10.0.0.2", None);
        let probes = ready_probes(&[vni(100)]);
        let plan = compute_diff(
            &desired,
            &snapshot,
            &applied,
            &probes,
            &GroupOwnedMap::new(),
            &EvpnInstanceTable::new(),
        );
        assert!(plan.is_noop());
    }

    // Property-style: every emitted Remove key must exist in the
    // applied set, and every emitted Add/Update key must exist in the
    // desired table. Exhaustive over a hand-rolled cartesian.
    #[test]
    fn emitted_keys_are_always_grounded_in_inputs() {
        let mut desired_b = RemoteMacTable::builder();
        desired_b
            .insert(vni(100), mac(1), entry("10.0.0.2", None))
            .unwrap();
        desired_b
            .insert(vni(200), mac(2), entry("10.0.0.3", None))
            .unwrap();
        let desired = desired_b.build();

        let mut snapshot = KernelSnapshot::new();
        // Foreign static for vni 200, mac 9 — must be ignored.
        snapshot.insert_fdb(
            vni(200),
            KernelFdbEntry {
                mac: mac(9),
                dst: Some(ip("10.0.0.99")),
                nh_id: None,
                flags: KernelFdbFlags {
                    permanent: true,
                    master: true,
                    ..Default::default()
                },
            },
        );

        let mut applied = OwnedSet::new();
        // Stale ownership of (300, 7) → should produce a Remove only
        // if kernel has it AND probes say its instance is unready/
        // missing. Here it's missing entirely from probes (= NotReady),
        // and snapshot doesn't have it → no emit.
        applied.record_applied(
            vni(300),
            mac(7),
            OwnedEntry::single_dst(ip("10.0.0.4"), None),
        );

        let probes = ready_probes(&[vni(100), vni(200)]);
        let plan = compute_diff(
            &desired,
            &snapshot,
            &applied,
            &probes,
            &GroupOwnedMap::new(),
            &EvpnInstanceTable::new(),
        );

        for op in &plan.ops {
            match op {
                DataplaneOp::AddRemoteFdb { vni: v, mac: m, .. }
                | DataplaneOp::UpdateRemoteFdb { vni: v, mac: m, .. } => {
                    assert!(
                        desired.get(*v, *m).is_some(),
                        "Add/Update key not in desired: {op:?}"
                    );
                }
                DataplaneOp::RemoveRemoteFdb { vni: v, mac: m } => {
                    assert!(
                        applied.contains(*v, *m),
                        "Remove key not in applied: {op:?}"
                    );
                }
                DataplaneOp::SetBumPortFlags { .. }
                | DataplaneOp::AddRemoteIpRoute { .. }
                | DataplaneOp::RemoveRemoteIpRoute { .. }
                | DataplaneOp::AddL3Neighbor { .. }
                | DataplaneOp::RemoveL3Neighbor { .. }
                | DataplaneOp::AddL3VxlanFdb { .. }
                | DataplaneOp::RemoveL3VxlanFdb { .. }
                | DataplaneOp::InstallFdbNhg { .. }
                | DataplaneOp::UpdateFdbNhgMembers { .. }
                | DataplaneOp::RemoveFdbNhg { .. } => {
                    panic!("compute_diff must only produce L2 FDB ops; got {op:?}");
                }
            }
        }
    }

    // ─── ADR-0059 slice 3b: Pass 1b transitions ────────────────────

    use crate::group_state::AliasGroupKey;
    use rustbgpd_evpn::{EthernetSegmentIdentifier, EthernetTagId};

    fn esi(seed: u8) -> EthernetSegmentIdentifier {
        EthernetSegmentIdentifier::new([seed; 10])
    }

    /// Build a `RemoteMacEntry` with `alias_group_key` set (multi-homed,
    /// FDB-NHG-eligible). `aliases` is the list of alias VTEP IPs beyond
    /// the primary `remote`.
    fn entry_multi_homed(remote: &str, aliases: &[&str], seg: u8) -> RemoteMacEntry {
        RemoteMacEntry {
            remote_vtep_ip: ip(remote),
            mobility_sequence: None,
            alias_vtep_ips: aliases.iter().map(|s| ip(s)).collect(),
            alias_group_key: Some((esi(seg), EthernetTagId(0))),
            source: RemoteMacSource::EvpnRibBestPath,
        }
    }

    fn linux_key(v: u32, seg: u8) -> AliasGroupKey {
        AliasGroupKey::new(vni(v), esi(seg), EthernetTagId(0))
    }

    #[test]
    fn transition_single_dst_owned_to_desired_fdb_nhg() {
        // Last applied: SingleDst → Desired: FdbNhg.
        // Expect: RemoveRemoteFdb + InstallFdbNhg (in that order).
        let mut desired = RemoteMacTable::builder();
        desired
            .insert(
                vni(100),
                mac(1),
                entry_multi_homed("10.0.0.2", &["10.0.0.3"], 7),
            )
            .unwrap();
        let desired = desired.build();

        // Kernel still has the prior single-dst row — RemoveRemoteFdb
        // is gated on snapshot presence to keep the op idempotent.
        let mut snapshot = KernelSnapshot::new();
        let mut e = ours("10.0.0.2");
        e.mac = mac(1);
        snapshot.insert_fdb(vni(100), e);
        let mut applied = OwnedSet::new();
        applied.record_applied(
            vni(100),
            mac(1),
            OwnedEntry::single_dst(ip("10.0.0.2"), None),
        );
        let probes = ready_probes(&[vni(100)]);

        let plan = compute_diff(
            &desired,
            &snapshot,
            &applied,
            &probes,
            &GroupOwnedMap::new(),
            &EvpnInstanceTable::new(),
        );

        // The plan should contain both a RemoveRemoteFdb (for the old
        // single-dst row) and an InstallFdbNhg (for the new FDB-NHG).
        assert!(
            plan.ops
                .iter()
                .any(|o| matches!(o, DataplaneOp::RemoveRemoteFdb { vni: v, mac: m } if *v == vni(100) && *m == mac(1))),
            "expected RemoveRemoteFdb in {:?}",
            plan.ops,
        );
        assert!(
            plan.ops.iter().any(|o| matches!(
                o,
                DataplaneOp::InstallFdbNhg { vni: v, mac: m, group_key, .. }
                    if *v == vni(100) && *m == mac(1) && *group_key == linux_key(100, 7),
            )),
            "expected InstallFdbNhg in {:?}",
            plan.ops,
        );
    }

    #[test]
    fn transition_fdb_nhg_owned_to_desired_single_dst() {
        // Last applied: FdbNhg → Desired: single-dst (alias_group_key None).
        // Expect: RemoveFdbNhg + AddRemoteFdb.
        let mut desired = RemoteMacTable::builder();
        desired
            .insert(vni(100), mac(1), entry("10.0.0.2", None))
            .unwrap();
        let desired = desired.build();

        let snapshot = KernelSnapshot::new();
        let mut applied = OwnedSet::new();
        applied.record_applied(vni(100), mac(1), OwnedEntry::fdb_nhg(linux_key(100, 7)));
        let probes = ready_probes(&[vni(100)]);

        let plan = compute_diff(
            &desired,
            &snapshot,
            &applied,
            &probes,
            &GroupOwnedMap::new(),
            &EvpnInstanceTable::new(),
        );

        assert!(
            plan.ops
                .iter()
                .any(|o| matches!(o, DataplaneOp::RemoveFdbNhg { vni: v, mac: m, .. } if *v == vni(100) && *m == mac(1))),
            "expected RemoveFdbNhg in {:?}",
            plan.ops,
        );
        assert!(
            plan.ops
                .iter()
                .any(|o| matches!(o, DataplaneOp::AddRemoteFdb { vni: v, mac: m, .. } if *v == vni(100) && *m == mac(1))),
            "expected AddRemoteFdb in {:?}",
            plan.ops,
        );
    }

    #[test]
    fn transition_fdb_nhg_group_key_changes_on_same_mac() {
        // Last applied: FdbNhg(esi=7) → Desired: FdbNhg(esi=8).
        // Expect: RemoveFdbNhg(old key) + InstallFdbNhg(new key).
        let mut desired = RemoteMacTable::builder();
        desired
            .insert(
                vni(100),
                mac(1),
                entry_multi_homed("10.0.0.2", &["10.0.0.3"], 8),
            )
            .unwrap();
        let desired = desired.build();

        let snapshot = KernelSnapshot::new();
        let mut applied = OwnedSet::new();
        applied.record_applied(vni(100), mac(1), OwnedEntry::fdb_nhg(linux_key(100, 7)));
        let probes = ready_probes(&[vni(100)]);

        let plan = compute_diff(
            &desired,
            &snapshot,
            &applied,
            &probes,
            &GroupOwnedMap::new(),
            &EvpnInstanceTable::new(),
        );

        // RemoveFdbNhg should carry the OLD key, Install should carry NEW.
        assert!(
            plan.ops.iter().any(|o| matches!(
                o,
                DataplaneOp::RemoveFdbNhg { group_key, .. } if *group_key == linux_key(100, 7),
            )),
            "expected RemoveFdbNhg(old esi=7) in {:?}",
            plan.ops,
        );
        assert!(
            plan.ops.iter().any(|o| matches!(
                o,
                DataplaneOp::InstallFdbNhg { group_key, .. } if *group_key == linux_key(100, 8),
            )),
            "expected InstallFdbNhg(new esi=8) in {:?}",
            plan.ops,
        );
    }

    #[test]
    fn fdb_nhg_member_set_shrinks_stays_group_backed() {
        // last_applied says FdbNhg(esi=7) with members {10.0.0.2,
        // 10.0.0.3, 10.0.0.4}, groups map reflects same; desired
        // drops one alias keeping {primary 10.0.0.2, alias 10.0.0.3}.
        // Expect UpdateFdbNhgMembers emitted once.
        //
        // The shrink must NOT bring `alias_vtep_ips` to empty — the
        // projection invariant (`empty alias_vtep_ips ⇔
        // alias_group_key.is_none()`) means a fully-drained set would
        // hit the FDB-NHG→single-dst transition, not the
        // UpdateFdbNhgMembers path. The N→1-member-but-still-grouped
        // case can't be reached through the projection layer.
        let mut desired = RemoteMacTable::builder();
        desired
            .insert(
                vni(100),
                mac(1),
                entry_multi_homed("10.0.0.2", &["10.0.0.3"], 7),
            )
            .unwrap();
        let desired = desired.build();

        let snapshot = {
            let mut s = KernelSnapshot::new();
            // Snapshot reports the FDB row still present (with the
            // installed nh_id) so the Pass 1b drift check sees nothing
            // missing for this MAC and skips an Install re-emit.
            s.insert_fdb(
                vni(100),
                KernelFdbEntry {
                    mac: mac(1),
                    dst: None,
                    nh_id: Some(0x4000_0001),
                    flags: KernelFdbFlags {
                        extern_learn: true,
                        master: true,
                        ..Default::default()
                    },
                },
            );
            s
        };

        let mut applied = OwnedSet::new();
        applied.record_applied(vni(100), mac(1), OwnedEntry::fdb_nhg(linux_key(100, 7)));
        let probes = ready_probes(&[vni(100)]);

        let mut groups = GroupOwnedMap::new();
        groups.record_member_install(ip("10.0.0.2"), 0x3000_0001);
        groups.record_member_install(ip("10.0.0.3"), 0x3000_0002);
        groups.record_member_install(ip("10.0.0.4"), 0x3000_0003);
        let mut members = std::collections::BTreeSet::new();
        members.insert(ip("10.0.0.2"));
        members.insert(ip("10.0.0.3"));
        members.insert(ip("10.0.0.4"));
        groups.record_group_install(linux_key(100, 7), 0x4000_0001, members);
        groups.record_mac_ref(linux_key(100, 7), vni(100), mac(1));

        let plan = compute_diff(
            &desired,
            &snapshot,
            &applied,
            &probes,
            &groups,
            &EvpnInstanceTable::new(),
        );

        // Member set should shrink to [10.0.0.2, 10.0.0.3].
        let updates: Vec<_> = plan
            .ops
            .iter()
            .filter(|o| matches!(o, DataplaneOp::UpdateFdbNhgMembers { .. }))
            .collect();
        assert_eq!(
            updates.len(),
            1,
            "expected exactly one UpdateFdbNhgMembers; got {:?}",
            plan.ops
        );
        if let DataplaneOp::UpdateFdbNhgMembers { members, .. } = updates[0] {
            assert_eq!(members, &vec![ip("10.0.0.2"), ip("10.0.0.3")]);
        }
        // Also: no InstallFdbNhg / RemoveFdbNhg — N→1 keeps the group.
        assert!(
            !plan
                .ops
                .iter()
                .any(|o| matches!(o, DataplaneOp::InstallFdbNhg { .. }))
        );
        assert!(
            !plan
                .ops
                .iter()
                .any(|o| matches!(o, DataplaneOp::RemoveFdbNhg { .. }))
        );
    }

    #[test]
    fn instance_not_ready_drains_existing_fdb_nhg_rows() {
        // Last applied: FdbNhg, instance probes drop the VNI from
        // Ready → expect RemoveFdbNhg per MAC even though intent
        // still lists it.
        let mut desired = RemoteMacTable::builder();
        desired
            .insert(
                vni(100),
                mac(1),
                entry_multi_homed("10.0.0.2", &["10.0.0.3"], 7),
            )
            .unwrap();
        let desired = desired.build();

        let snapshot = KernelSnapshot::new();
        let mut applied = OwnedSet::new();
        applied.record_applied(vni(100), mac(1), OwnedEntry::fdb_nhg(linux_key(100, 7)));
        // probes is EMPTY → vni(100) is NotReady by default.
        let probes = InstanceProbes::new();

        let plan = compute_diff(
            &desired,
            &snapshot,
            &applied,
            &probes,
            &GroupOwnedMap::new(),
            &EvpnInstanceTable::new(),
        );

        assert!(
            plan.ops
                .iter()
                .any(|o| matches!(o, DataplaneOp::RemoveFdbNhg { vni: v, mac: m, .. } if *v == vni(100) && *m == mac(1))),
            "expected RemoveFdbNhg from NotReady drain in {:?}",
            plan.ops,
        );
        // No Install ops — the instance is NotReady.
        assert!(
            !plan
                .ops
                .iter()
                .any(|o| matches!(o, DataplaneOp::InstallFdbNhg { .. }))
        );
    }

    #[test]
    fn ipv6_alias_members_fall_back_to_single_dst_with_warn() {
        // Multi-homed with an IPv6 alias → falls back to AddRemoteFdb
        // (single-dst at primary) because slice 2's `NexthopSocket`
        // rejects v6 gateways. Diff emits no InstallFdbNhg.
        let mut desired = RemoteMacTable::builder();
        desired
            .insert(
                vni(100),
                mac(1),
                entry_multi_homed("10.0.0.2", &["2001:db8::1"], 7),
            )
            .unwrap();
        let desired = desired.build();

        let snapshot = KernelSnapshot::new();
        let applied = OwnedSet::new();
        let probes = ready_probes(&[vni(100)]);

        let plan = compute_diff(
            &desired,
            &snapshot,
            &applied,
            &probes,
            &GroupOwnedMap::new(),
            &EvpnInstanceTable::new(),
        );

        assert!(
            plan.ops
                .iter()
                .any(|o| matches!(o, DataplaneOp::AddRemoteFdb { vni: v, mac: m, dst, .. } if *v == vni(100) && *m == mac(1) && *dst == ip("10.0.0.2"))),
            "expected AddRemoteFdb fallback in {:?}",
            plan.ops,
        );
        assert!(
            !plan
                .ops
                .iter()
                .any(|o| matches!(o, DataplaneOp::InstallFdbNhg { .. })),
            "must NOT emit InstallFdbNhg when v6 aliases present: {:?}",
            plan.ops,
        );
    }

    // ─── ADR-0059 slice 3.5: per-VNI apply_aliasing_ecmp off-switch ───

    #[test]
    fn apply_aliasing_ecmp_false_emits_single_dst_for_multihomed_entry() {
        // Multi-homed v4 entry on a VNI whose `apply_aliasing_ecmp` is
        // `false` → AddRemoteFdb at the primary VTEP, no InstallFdbNhg.
        let mut desired = RemoteMacTable::builder();
        desired
            .insert(
                vni(100),
                mac(1),
                entry_multi_homed("10.0.0.2", &["10.0.0.3"], 7),
            )
            .unwrap();
        let desired = desired.build();

        let snapshot = KernelSnapshot::new();
        let applied = OwnedSet::new();
        let probes = ready_probes(&[vni(100)]);
        let instances = instances_disabled(&[vni(100)]);

        let plan = compute_diff(
            &desired,
            &snapshot,
            &applied,
            &probes,
            &GroupOwnedMap::new(),
            &instances,
        );

        assert!(
            plan.ops.iter().any(|o| matches!(
                o,
                DataplaneOp::AddRemoteFdb { vni: v, mac: m, dst, .. }
                    if *v == vni(100) && *m == mac(1) && *dst == ip("10.0.0.2")
            )),
            "expected single-dst AddRemoteFdb fallback, got {:?}",
            plan.ops,
        );
        assert!(
            !plan
                .ops
                .iter()
                .any(|o| matches!(o, DataplaneOp::InstallFdbNhg { .. })),
            "must NOT emit InstallFdbNhg when apply_aliasing_ecmp=false: {:?}",
            plan.ops,
        );
        // IPv6 fallback set should stay empty — this isn't an IPv6
        // alias case, the gate is the operator off-switch.
        assert!(plan.ipv6_alias_fallback_keys.is_empty());
    }

    #[test]
    fn apply_aliasing_ecmp_false_emits_transition_when_last_applied_fdb_nhg() {
        // Pin the diff-algorithm property that an `EvpnInstance` with
        // `apply_aliasing_ecmp = false` plus a previously-installed
        // FDB-NHG emits `RemoveFdbNhg + AddRemoteFdb` (the standard
        // `FdbNhg → SingleDst` transition). Today this only fires
        // across a daemon restart that picks up the flip from the
        // startup config; the test is structured around the diff
        // algorithm, not against a runtime mutation path that doesn't
        // exist yet.
        let mut desired = RemoteMacTable::builder();
        desired
            .insert(
                vni(100),
                mac(1),
                entry_multi_homed("10.0.0.2", &["10.0.0.3"], 7),
            )
            .unwrap();
        let desired = desired.build();

        let snapshot = KernelSnapshot::new();
        let mut applied = OwnedSet::new();
        applied.record_applied(vni(100), mac(1), OwnedEntry::fdb_nhg(linux_key(100, 7)));
        let probes = ready_probes(&[vni(100)]);
        let instances = instances_disabled(&[vni(100)]);

        let plan = compute_diff(
            &desired,
            &snapshot,
            &applied,
            &probes,
            &GroupOwnedMap::new(),
            &instances,
        );

        assert!(
            plan.ops.iter().any(|o| matches!(
                o,
                DataplaneOp::RemoveFdbNhg { vni: v, mac: m, .. }
                    if *v == vni(100) && *m == mac(1)
            )),
            "expected RemoveFdbNhg in transition, got {:?}",
            plan.ops,
        );
        assert!(
            plan.ops.iter().any(|o| matches!(
                o,
                DataplaneOp::AddRemoteFdb { vni: v, mac: m, dst, .. }
                    if *v == vni(100) && *m == mac(1) && *dst == ip("10.0.0.2")
            )),
            "expected AddRemoteFdb in transition, got {:?}",
            plan.ops,
        );
        // Plan-level ordering: deletes precede creates.
        let remove_idx = plan
            .ops
            .iter()
            .position(|o| matches!(o, DataplaneOp::RemoveFdbNhg { .. }))
            .expect("RemoveFdbNhg present");
        let add_idx = plan
            .ops
            .iter()
            .position(|o| matches!(o, DataplaneOp::AddRemoteFdb { .. }))
            .expect("AddRemoteFdb present");
        assert!(
            remove_idx < add_idx,
            "RemoveFdbNhg must precede AddRemoteFdb in {:?}",
            plan.ops,
        );
    }

    #[test]
    fn apply_aliasing_ecmp_unknown_vni_defaults_to_enabled() {
        // A VNI not yet in the `EvpnInstanceTable` (race window
        // during config reload) defaults to aliasing-enabled — the
        // `probes` readiness gate is the real install/no-install
        // boundary, not the instance-table presence check.
        let mut desired = RemoteMacTable::builder();
        desired
            .insert(
                vni(100),
                mac(1),
                entry_multi_homed("10.0.0.2", &["10.0.0.3"], 7),
            )
            .unwrap();
        let desired = desired.build();

        let snapshot = KernelSnapshot::new();
        let applied = OwnedSet::new();
        let probes = ready_probes(&[vni(100)]);
        let instances = EvpnInstanceTable::new(); // empty

        let plan = compute_diff(
            &desired,
            &snapshot,
            &applied,
            &probes,
            &GroupOwnedMap::new(),
            &instances,
        );

        assert!(
            plan.ops
                .iter()
                .any(|o| matches!(o, DataplaneOp::InstallFdbNhg { .. })),
            "unknown VNI must default to aliasing-enabled (InstallFdbNhg expected), got {:?}",
            plan.ops,
        );
    }

    #[test]
    fn apply_aliasing_ecmp_false_with_ipv6_alias_does_not_record_fallback() {
        // Multi-homed entry with an IPv6 alias on a VNI whose
        // `apply_aliasing_ecmp = false` → routes through single-dst
        // BUT must NOT record the (VNI, MAC) into
        // `ipv6_alias_fallback_keys`. The operator turned aliasing
        // off; the reconcile actor would otherwise emit a
        // misleading "IPv6 alias unsupported" warn even though the
        // single-dst path was the intentional configuration.
        let mut desired = RemoteMacTable::builder();
        desired
            .insert(
                vni(100),
                mac(1),
                entry_multi_homed("10.0.0.2", &["2001:db8::1"], 7),
            )
            .unwrap();
        let desired = desired.build();

        let snapshot = KernelSnapshot::new();
        let applied = OwnedSet::new();
        let probes = ready_probes(&[vni(100)]);
        let instances = instances_disabled(&[vni(100)]);

        let plan = compute_diff(
            &desired,
            &snapshot,
            &applied,
            &probes,
            &GroupOwnedMap::new(),
            &instances,
        );

        assert!(
            plan.ops.iter().any(|o| matches!(
                o,
                DataplaneOp::AddRemoteFdb { vni: v, mac: m, dst, .. }
                    if *v == vni(100) && *m == mac(1) && *dst == ip("10.0.0.2")
            )),
            "expected single-dst AddRemoteFdb at the primary VTEP, got {:?}",
            plan.ops,
        );
        assert!(
            !plan
                .ops
                .iter()
                .any(|o| matches!(o, DataplaneOp::InstallFdbNhg { .. })),
            "off-switch must skip FDB-NHG install: {:?}",
            plan.ops,
        );
        // The key invariant this test pins: no entry in the IPv6
        // fallback set, even though one of the aliases is IPv6.
        assert!(
            plan.ipv6_alias_fallback_keys.is_empty(),
            "off-switch must not record a misleading IPv6 fallback warning; \
             got fallback keys: {:?}",
            plan.ipv6_alias_fallback_keys,
        );
    }
}
