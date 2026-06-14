//! Single-active attachment-circuit gate — pure plan layer.
//!
//! RFC 7432 §14.1.1 requires the non-DF PE of a single-active
//! Ethernet Segment to block **all** traffic on the segment AC,
//! known unicast included. The BUM flood-flag triplet
//! ([`crate::bum_filter`]) only covers the flood classes, so this
//! module derives the whole-port half: the desired
//! `IFLA_BRPORT_STATE` for each bound AC port
//! (`BR_STATE_DISABLED` to block, `BR_STATE_FORWARDING` to
//! restore), realized by `DataplaneOp::SetAcPortState` through the
//! `RTM_SETLINK`/`AF_BRIDGE` `bridge link set` wire shape (see
//! `linux::ac_gate` for why the BUM filter's `set_port` shape
//! cannot carry port state).
//!
//! ## Diff against *observed* state, not a remembered plan
//!
//! Unlike the BUM flags — which the kernel never touches on its own —
//! bridge-port state is rewritten by the kernel on carrier
//! transitions: `br_port_carrier_check` re-enables a
//! `BR_STATE_DISABLED` port the moment carrier returns (and disables
//! any port on carrier loss). A remembered-plan diff would conclude
//! "already blocked" and leave a non-DF AC forwarding after a
//! carrier flap. [`resolve_ac_gate_plan`] therefore diffs the desired
//! state against the **observed** `IFLA_BRPORT_STATE` from the
//! current kernel snapshot on every reconcile pass, so kernel-driven
//! drift heals at the next pass (kernel event wake or the periodic
//! dump). The remembered map ([`restore_ops`]'s `last_managed`
//! input) exists only to restore ports that *leave* management —
//! ES/binding removed from config, redundancy mode flipped to
//! all-active, daemon shutdown — so a port is never left disabled
//! orphaned.
//!
//! ## Authority
//!
//! Rows exist only for single-active segments with an ADR-0085
//! `interface` binding. The binding is the operator contract handing
//! rustbgpd authority over that port's gate: a desired-`Forwarding`
//! row re-enables a port found disabled (e.g. crash leftover from a
//! prior daemon lifetime) just as a desired-`Blocked` row disables a
//! forwarding one. Kernel STP must not be running on the bound AC —
//! both would fight over the same per-port state (same constraint
//! every EVPN-MH implementation has).

use std::collections::BTreeMap;

use rustbgpd_evpn::BumEnforcementTable;

use crate::snapshot::KernelSnapshot;

/// `BR_STATE_DISABLED` — block every frame through the port.
pub const BR_STATE_DISABLED: u8 = 0;
/// `BR_STATE_FORWARDING` — normal forwarding.
pub const BR_STATE_FORWARDING: u8 = 3;
/// `BR_STATE_LISTENING` — STP-owned bridge-port state.
pub const BR_STATE_LISTENING: u8 = 1;
/// `BR_STATE_LEARNING` — STP-owned bridge-port state.
pub const BR_STATE_LEARNING: u8 = 2;
/// `BR_STATE_BLOCKING` — STP-owned bridge-port state.
pub const BR_STATE_BLOCKING: u8 = 4;

/// One AC-gate action: a bound AC bridge-port ifindex plus the
/// desired whole-port state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AcGatePortPlan {
    /// Kernel ifindex of the bound AC bridge port.
    pub ifindex: u32,
    /// `true` → `BR_STATE_DISABLED`; `false` → `BR_STATE_FORWARDING`.
    pub blocked: bool,
}

/// Result of resolving the intent's AC-gate rows against the current
/// kernel snapshot.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AcGateResolution {
    /// Ports whose observed state differs from the desired state —
    /// the ops to emit this pass.
    pub ops: Vec<AcGatePortPlan>,
    /// Every port currently under gate management, with its desired
    /// blocked state — resolved or not yet matching. Fed back as the
    /// next pass's `last_managed` so [`restore_ops`] can detect
    /// ports leaving management.
    pub managed: BTreeMap<u32, bool>,
    /// Bound interface names that did not resolve to a bridge port
    /// in the snapshot (link missing, or not enslaved to any
    /// bridge). The reconciler warns for names newly entering this
    /// set — an operator whose bound AC never resolves must not get
    /// silent non-enforcement.
    pub unresolved: Vec<String>,
    /// Bound interface names whose observed state is STP-owned
    /// (`listening`, `learning`, or `blocking`). The AC gate manages
    /// only `disabled` and `forwarding`; when kernel STP owns the
    /// port state, rustbgpd leaves it untouched and warns.
    pub stp_conflicts: Vec<String>,
}

/// Resolve the intent's AC-gate rows against the kernel snapshot.
///
/// - Resolution is by link name via [`KernelSnapshot::bridge_ports`];
///   a name that is not currently an enslaved non-VXLAN bridge port
///   lands in `unresolved` (no op — there is no port to gate).
/// - Multiple ESes bound to the same port (misconfiguration)
///   dedupe most-restrictive-wins: blocked beats forwarding,
///   mirroring [`crate::bum_filter::compute_flag_plan`].
/// - An op is emitted whenever the observed `IFLA_BRPORT_STATE`
///   differs from the desired state (unknown observed state counts
///   as differing — fail toward making the kernel state known).
/// - If a bound port is in an STP-owned state (`listening`,
///   `learning`, or `blocking`), no op is emitted. Kernel STP and
///   rustbgpd cannot both own the same whole-port state knob.
#[must_use]
pub fn resolve_ac_gate_plan(
    intent: &BumEnforcementTable,
    snapshot: &KernelSnapshot,
) -> AcGateResolution {
    let mut resolution = AcGateResolution::default();
    let mut desired_by_ifindex: BTreeMap<u32, bool> = BTreeMap::new();

    for entry in intent.ac_gates() {
        let Some(port) = snapshot.bridge_ports.get(&entry.interface) else {
            resolution.unresolved.push(entry.interface.clone());
            continue;
        };
        if port.state.is_some_and(is_stp_owned_state) {
            resolution.stp_conflicts.push(entry.interface.clone());
            continue;
        }
        let blocked = entry.state.is_blocked();
        desired_by_ifindex
            .entry(port.ifindex)
            .and_modify(|existing| *existing |= blocked) // blocked wins
            .or_insert(blocked);
    }

    let observed_by_ifindex: BTreeMap<u32, Option<u8>> = snapshot
        .bridge_ports
        .values()
        .map(|p| (p.ifindex, p.state))
        .collect();

    for (&ifindex, &blocked) in &desired_by_ifindex {
        let desired_state = if blocked {
            BR_STATE_DISABLED
        } else {
            BR_STATE_FORWARDING
        };
        let observed = observed_by_ifindex.get(&ifindex).copied().flatten();
        if observed != Some(desired_state) {
            resolution.ops.push(AcGatePortPlan { ifindex, blocked });
        }
    }
    resolution.unresolved.sort_unstable();
    resolution.unresolved.dedup();
    resolution.stp_conflicts.sort_unstable();
    resolution.stp_conflicts.dedup();
    resolution.managed = desired_by_ifindex;
    resolution
}

/// Compute the restore ops for ports that left gate management:
/// present in `last_managed` with desired blocked, absent from the
/// current `managed` map. Restored to `BR_STATE_FORWARDING` so a
/// removed ES/binding never leaves a port disabled orphaned —
/// mirroring [`crate::bum_filter::diff_flag_plans`]'s
/// restore-to-allow-all discipline.
///
/// Ports already observed forwarding (the kernel's carrier check may
/// have re-enabled them) and ports that vanished from the snapshot
/// entirely (link deleted) emit nothing.
#[must_use]
pub fn restore_ops(
    last_managed: &BTreeMap<u32, bool>,
    managed: &BTreeMap<u32, bool>,
    snapshot: &KernelSnapshot,
) -> Vec<AcGatePortPlan> {
    let observed_by_ifindex: BTreeMap<u32, Option<u8>> = snapshot
        .bridge_ports
        .values()
        .map(|p| (p.ifindex, p.state))
        .collect();

    last_managed
        .iter()
        .filter(|&(ifindex, &blocked)| blocked && !managed.contains_key(ifindex))
        .filter_map(|(&ifindex, _)| {
            // Only restore ports that still exist as bridge ports and
            // are not already forwarding.
            let observed = observed_by_ifindex.get(&ifindex)?;
            if observed.is_some_and(is_stp_owned_state) || *observed == Some(BR_STATE_FORWARDING) {
                return None;
            }
            Some(AcGatePortPlan {
                ifindex,
                blocked: false,
            })
        })
        .collect()
}

fn is_stp_owned_state(state: u8) -> bool {
    matches!(
        state,
        BR_STATE_LISTENING | BR_STATE_LEARNING | BR_STATE_BLOCKING
    )
}

#[cfg(test)]
mod tests {
    use rustbgpd_evpn::{AcGateState, EthernetSegmentIdentifier};

    use super::*;

    fn esi(seed: u8) -> EthernetSegmentIdentifier {
        EthernetSegmentIdentifier::new([seed; 10])
    }

    fn snapshot_with_port(name: &str, ifindex: u32, state: Option<u8>) -> KernelSnapshot {
        let mut snap = KernelSnapshot::new();
        snap.insert_bridge_port(name, ifindex, state);
        snap
    }

    #[test]
    fn blocked_row_on_forwarding_port_emits_disable() {
        let mut table = BumEnforcementTable::new();
        table.set_ac_gate(esi(1), "eth2".to_string(), AcGateState::Blocked);
        let snap = snapshot_with_port("eth2", 10, Some(BR_STATE_FORWARDING));

        let res = resolve_ac_gate_plan(&table, &snap);
        assert_eq!(
            res.ops,
            vec![AcGatePortPlan {
                ifindex: 10,
                blocked: true
            }]
        );
        assert_eq!(res.managed.get(&10), Some(&true));
        assert!(res.unresolved.is_empty());
    }

    #[test]
    fn blocked_row_on_already_disabled_port_is_idempotent() {
        let mut table = BumEnforcementTable::new();
        table.set_ac_gate(esi(1), "eth2".to_string(), AcGateState::Blocked);
        let snap = snapshot_with_port("eth2", 10, Some(BR_STATE_DISABLED));

        let res = resolve_ac_gate_plan(&table, &snap);
        assert!(res.ops.is_empty(), "observed already matches desired");
        // Still managed — removal later must restore it.
        assert_eq!(res.managed.get(&10), Some(&true));
    }

    #[test]
    fn kernel_carrier_reset_drift_is_healed() {
        // The kernel re-enables a DISABLED port when carrier returns
        // (br_port_carrier_check). Because the diff is against
        // observed state, the next pass re-emits the block even
        // though we "already applied" it.
        let mut table = BumEnforcementTable::new();
        table.set_ac_gate(esi(1), "eth2".to_string(), AcGateState::Blocked);

        let snap_blocked = snapshot_with_port("eth2", 10, Some(BR_STATE_DISABLED));
        assert!(resolve_ac_gate_plan(&table, &snap_blocked).ops.is_empty());

        let snap_reset = snapshot_with_port("eth2", 10, Some(BR_STATE_FORWARDING));
        let res = resolve_ac_gate_plan(&table, &snap_reset);
        assert_eq!(
            res.ops,
            vec![AcGatePortPlan {
                ifindex: 10,
                blocked: true
            }]
        );
    }

    #[test]
    fn forwarding_row_re_enables_disabled_port() {
        // DF role (or a crash leftover from a prior daemon lifetime):
        // a desired-Forwarding row is authoritative for a bound AC.
        let mut table = BumEnforcementTable::new();
        table.set_ac_gate(esi(1), "eth2".to_string(), AcGateState::Forwarding);
        let snap = snapshot_with_port("eth2", 10, Some(BR_STATE_DISABLED));

        let res = resolve_ac_gate_plan(&table, &snap);
        assert_eq!(
            res.ops,
            vec![AcGatePortPlan {
                ifindex: 10,
                blocked: false
            }]
        );
        assert_eq!(res.managed.get(&10), Some(&false));
    }

    #[test]
    fn mixed_roles_resolves_to_forwarding_port_state() {
        // RFC 8584 service carving split the roles — port-level
        // blocking would break the DF VNIs, so the port forwards and
        // only BUM flags enforce.
        let mut table = BumEnforcementTable::new();
        table.set_ac_gate(esi(1), "eth2".to_string(), AcGateState::MixedRoles);
        let snap = snapshot_with_port("eth2", 10, Some(BR_STATE_FORWARDING));

        let res = resolve_ac_gate_plan(&table, &snap);
        assert!(res.ops.is_empty());
        assert_eq!(res.managed.get(&10), Some(&false));
    }

    #[test]
    fn unknown_observed_state_emits_op() {
        let mut table = BumEnforcementTable::new();
        table.set_ac_gate(esi(1), "eth2".to_string(), AcGateState::Blocked);
        let snap = snapshot_with_port("eth2", 10, None);

        let res = resolve_ac_gate_plan(&table, &snap);
        assert_eq!(res.ops.len(), 1);
    }

    #[test]
    fn stp_owned_observed_state_is_reported_not_overridden() {
        let mut table = BumEnforcementTable::new();
        table.set_ac_gate(esi(1), "eth2".to_string(), AcGateState::Forwarding);

        for state in [BR_STATE_LISTENING, BR_STATE_LEARNING, BR_STATE_BLOCKING] {
            let snap = snapshot_with_port("eth2", 10, Some(state));
            let res = resolve_ac_gate_plan(&table, &snap);

            assert!(
                res.ops.is_empty(),
                "STP-owned bridge-port state {state} must not be overwritten"
            );
            assert!(
                res.managed.is_empty(),
                "a port owned by STP must not enter AC-gate management"
            );
            assert_eq!(res.stp_conflicts, vec!["eth2".to_string()]);
        }
    }

    #[test]
    fn unresolved_interface_is_reported_not_acted_on() {
        let mut table = BumEnforcementTable::new();
        table.set_ac_gate(esi(1), "eth9".to_string(), AcGateState::Blocked);
        let snap = snapshot_with_port("eth2", 10, Some(BR_STATE_FORWARDING));

        let res = resolve_ac_gate_plan(&table, &snap);
        assert!(res.ops.is_empty());
        assert!(res.managed.is_empty());
        assert_eq!(res.unresolved, vec!["eth9".to_string()]);
    }

    #[test]
    fn shared_port_dedupes_with_blocked_winning() {
        // Two ESes bound to the same port (misconfiguration):
        // most-restrictive wins, like the BUM flag dedupe.
        let mut table = BumEnforcementTable::new();
        table.set_ac_gate(esi(1), "eth2".to_string(), AcGateState::Forwarding);
        table.set_ac_gate(esi(2), "eth2".to_string(), AcGateState::Blocked);
        let snap = snapshot_with_port("eth2", 10, Some(BR_STATE_FORWARDING));

        let res = resolve_ac_gate_plan(&table, &snap);
        assert_eq!(
            res.ops,
            vec![AcGatePortPlan {
                ifindex: 10,
                blocked: true
            }]
        );
        assert_eq!(res.managed.get(&10), Some(&true));
    }

    #[test]
    fn restore_emits_forwarding_for_port_leaving_management() {
        let last: BTreeMap<u32, bool> = [(10, true)].into();
        let managed = BTreeMap::new();
        let snap = snapshot_with_port("eth2", 10, Some(BR_STATE_DISABLED));

        let ops = restore_ops(&last, &managed, &snap);
        assert_eq!(
            ops,
            vec![AcGatePortPlan {
                ifindex: 10,
                blocked: false
            }]
        );
    }

    #[test]
    fn restore_skips_port_already_forwarding_or_still_managed() {
        // Kernel carrier check may have re-enabled the port already —
        // no redundant netlink write.
        let last: BTreeMap<u32, bool> = [(10, true), (11, true), (12, false)].into();
        let managed: BTreeMap<u32, bool> = [(11, true)].into();
        let mut snap = KernelSnapshot::new();
        snap.insert_bridge_port("eth2", 10, Some(BR_STATE_FORWARDING));
        snap.insert_bridge_port("eth3", 11, Some(BR_STATE_DISABLED));
        snap.insert_bridge_port("eth4", 12, Some(BR_STATE_FORWARDING));

        // 10: already forwarding → skip. 11: still managed → skip.
        // 12: was managed-forwarding (never blocked) → nothing to
        // restore.
        assert!(restore_ops(&last, &managed, &snap).is_empty());
    }

    #[test]
    fn restore_skips_stp_owned_port() {
        let last: BTreeMap<u32, bool> = [(10, true)].into();
        let snap = snapshot_with_port("eth2", 10, Some(BR_STATE_BLOCKING));

        assert!(
            restore_ops(&last, &BTreeMap::new(), &snap).is_empty(),
            "leaving management must not override an STP-owned bridge-port state"
        );
    }

    #[test]
    fn restore_skips_vanished_port() {
        // Link deleted from the kernel — ENODEV would be the only
        // outcome; nothing to restore.
        let last: BTreeMap<u32, bool> = [(10, true)].into();
        assert!(restore_ops(&last, &BTreeMap::new(), &KernelSnapshot::new()).is_empty());
    }
}
