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

use rustbgpd_evpn::{EvpnInstanceId, MacAddress, RemoteMacTable};

use crate::dataplane::DataplaneOp;
use crate::snapshot::{InstanceProbes, KernelFdbEntry, KernelSnapshot, OwnedSet};

/// Output of a single diff pass.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Plan {
    /// Operations to attempt, in deterministic order: creates first
    /// (sorted by `(VNI, MAC)`), then updates, then deletes. The
    /// actor applies them serially with backoff per-op on failure.
    pub ops: Vec<DataplaneOp>,
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
/// Ready instances.
///
/// See module docs for the foreign-entry preservation invariant.
#[must_use]
pub fn compute_diff(
    desired: &RemoteMacTable,
    snapshot: &KernelSnapshot,
    last_applied: &OwnedSet,
    probes: &InstanceProbes,
) -> Plan {
    let mut creates: Vec<DataplaneOp> = Vec::new();
    let mut updates: Vec<DataplaneOp> = Vec::new();
    let mut deletes: Vec<DataplaneOp> = Vec::new();

    // Pass 1 — creates & updates. Scoped to Ready instances; entries
    // for NotReady / Unbound instances contribute zero ops.
    for (&(vni, mac), entry) in desired.iter() {
        if !probes.is_ready(vni) {
            continue;
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
                    &mut updates,
                );
            }
        }
    }

    // Pass 2 — deletes. Iterate `last_applied`, NEVER the kernel
    // snapshot. This makes foreign-entry preservation a structural
    // property of the algorithm, not a runtime check.
    for (&(vni, mac), _owned) in last_applied.iter() {
        let still_desired = desired.get(vni, mac).is_some();
        let instance_ready = probes.is_ready(vni);
        let still_in_kernel = snapshot.find_fdb(vni, mac).is_some();

        // Withdraw if (no longer desired OR instance went NotReady) AND
        // the kernel still has the entry. If the kernel already
        // dropped it (interface flap, manual `bridge fdb del`), we
        // emit no op now — the actor will reconcile its OwnedSet on
        // the next successful pass instead.
        let should_remove = (!still_desired || !instance_ready) && still_in_kernel;
        if should_remove {
            deletes.push(DataplaneOp::RemoveRemoteFdb { vni, mac });
        }
    }

    let mut ops = creates;
    ops.append(&mut updates);
    ops.append(&mut deletes);
    Plan { ops }
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
        EvpnInstanceId, MacAddress, RemoteMacEntry, RemoteMacSource, RemoteMacTable,
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

    fn entry(remote: &str, seq: Option<u32>) -> RemoteMacEntry {
        RemoteMacEntry {
            remote_vtep_ip: ip(remote),
            mobility_sequence: seq,
            alias_vtep_ips: Vec::new(),
            source: RemoteMacSource::EvpnRibBestPath,
        }
    }

    fn ours(dst: &str) -> KernelFdbEntry {
        KernelFdbEntry {
            mac: mac(0),
            dst: Some(ip(dst)),
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
        o.record_applied(
            v,
            m,
            OwnedEntry {
                last_applied_dst: ip(dst),
                last_applied_seq: seq,
            },
        );
        o
    }

    // 1. Empty kernel + one desired entry → one create.
    #[test]
    fn creates_when_kernel_empty() {
        let desired = desired_one(vni(100), mac(1), entry("10.0.0.2", None));
        let snapshot = KernelSnapshot::new();
        let applied = OwnedSet::new();
        let probes = ready_probes(&[vni(100)]);
        let plan = compute_diff(&desired, &snapshot, &applied, &probes);
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
        let plan = compute_diff(&desired, &snapshot, &applied, &probes);
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
        let plan = compute_diff(&desired, &snapshot, &applied, &probes);
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
        let plan = compute_diff(&desired, &snapshot, &applied, &probes);
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
        let plan = compute_diff(&desired, &snapshot, &applied, &probes);
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
                flags: KernelFdbFlags {
                    permanent: true,
                    master: true,
                    ..Default::default()
                },
            },
        );
        let applied = OwnedSet::new();
        let probes = ready_probes(&[vni(100)]);
        let plan = compute_diff(&desired, &snapshot, &applied, &probes);
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
                flags: KernelFdbFlags::default(),
            },
        );
        let applied = OwnedSet::new();
        let probes = ready_probes(&[vni(100)]);
        let plan = compute_diff(&desired, &snapshot, &applied, &probes);
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
        let plan = compute_diff(&desired, &snapshot, &applied, &probes);
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
        let plan_a = compute_diff(&desired, &snapshot, &applied, &probes);
        let plan_b = compute_diff(&desired, &snapshot, &applied, &probes);
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
        let plan = compute_diff(&desired, &snapshot, &applied, &probes);
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
        let plan = compute_diff(&desired, &snapshot, &applied, &probes);
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
            OwnedEntry {
                last_applied_dst: ip("10.0.0.4"),
                last_applied_seq: None,
            },
        );

        let probes = ready_probes(&[vni(100), vni(200)]);
        let plan = compute_diff(&desired, &snapshot, &applied, &probes);

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
                DataplaneOp::SetBumPortFlags { .. } => {
                    panic!("compute_diff must not produce SetBumPortFlags ops; got {op:?}");
                }
            }
        }
    }
}
