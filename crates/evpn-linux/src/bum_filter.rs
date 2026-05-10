//! Linux-bridge BUM-suppression primitive — Gate 8b kernel half.
//!
//! Pure-logic mapping from a resolved
//! [`rustbgpd_evpn::BumEnforcementStatus`] row into the per-port
//! `bridge link` flag triplet that realizes the desired forwarding
//! action on each CE-facing bridge port:
//!
//! | Action     | `flood` | `mcast_flood` | `bcast_flood` |
//! |------------|:-------:|:-------------:|:-------------:|
//! | `Allow`    | `on`    | `on`          | `on`          |
//! | `Suppress` | `off`   | `off`         | `off`         |
//!
//! These three flags map 1:1 to the kernel's
//! `IFLA_BRPORT_UNICAST_FLOOD` / `IFLA_BRPORT_MCAST_FLOOD` /
//! `IFLA_BRPORT_BCAST_FLOOD` netlink attributes. `bcast_flood` was
//! added in Linux 4.18 (commit 4ce1b1bb05a3); the other two predate
//! it. The privileged spike at
//! `tests/scripts/netns-bum-filter-spike.sh` proves all three
//! together suppress broadcast / multicast / unknown-unicast flooding
//! toward the CE-facing port while leaving known-unicast forwarding
//! and remote-FDB programming intact — the load-bearing invariants
//! for EVPN multi-homing enforcement.
//!
//! This module deliberately does **not** speak netlink. The
//! [`BumPortFlagPlan`] rows it returns feed the rtnetlink-backed
//! `RTM_SETLINK` bridge-port `slave_data` triplet in the Linux
//! dataplane implementation, while this pure layer keeps the
//! mapping contract easy to pin with unit tests.

use rustbgpd_evpn::{BumEnforcementReadiness, BumEnforcementStatus, BumForwardingAction};

/// Per-port bridge flood-flag triplet.
///
/// Each field is the desired *enabled* state: `true` means "allow
/// flooding of this traffic class to this port", `false` means
/// "suppress."
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BumPortFlags {
    /// `IFLA_BRPORT_UNICAST_FLOOD` — unknown unicast.
    pub unicast_flood: bool,
    /// `IFLA_BRPORT_MCAST_FLOOD` — unknown multicast.
    pub multicast_flood: bool,
    /// `IFLA_BRPORT_BCAST_FLOOD` — broadcast (kernel >= 4.18).
    pub broadcast_flood: bool,
}

impl BumPortFlags {
    /// All flags on — DF baseline / pre-Gate-8b status quo.
    #[must_use]
    pub const fn allow_all() -> Self {
        Self {
            unicast_flood: true,
            multicast_flood: true,
            broadcast_flood: true,
        }
    }

    /// All flags off — Non-DF suppression.
    #[must_use]
    pub const fn suppress_all() -> Self {
        Self {
            unicast_flood: false,
            multicast_flood: false,
            broadcast_flood: false,
        }
    }

    /// Derive desired flags from the resolved BUM action.
    #[must_use]
    pub const fn for_action(action: BumForwardingAction) -> Self {
        match action {
            BumForwardingAction::Allow => Self::allow_all(),
            BumForwardingAction::Suppress => Self::suppress_all(),
        }
    }
}

/// One row of the kernel-primitive plan: a CE-facing bridge port
/// ifindex plus the desired flag triplet to apply to it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BumPortFlagPlan {
    /// Kernel ifindex of the CE-facing bridge port.
    pub ifindex: u32,
    /// Desired flood flags for this port.
    pub flags: BumPortFlags,
}

/// Resolve a slice of [`BumEnforcementStatus`] rows into the flat
/// list of `(ifindex, flags)` actions the Linux dataplane pushes to
/// the kernel. Skips rows whose readiness is not `Ready` — the
/// orchestrator already logs those at warn level and they are reported
/// back to operators via the `DataplaneReport` surface.
///
/// Deduplicates per ifindex on a "most-restrictive wins" basis. If
/// the same CE-facing port appears under both an `Allow` row and a
/// `Suppress` row (legal when one PE serves multiple `(ESI, VNI)`
/// pairs that share a CE port), the suppress action wins — failing
/// open would forward CE-facing BUM that some segment requires us
/// to drop.
#[must_use]
pub fn compute_flag_plan(rows: &[BumEnforcementStatus]) -> Vec<BumPortFlagPlan> {
    use std::collections::BTreeMap;

    let mut by_ifindex: BTreeMap<u32, BumPortFlags> = BTreeMap::new();
    for row in rows {
        if row.readiness != BumEnforcementReadiness::Ready {
            continue;
        }
        let new = BumPortFlags::for_action(row.action);
        for &ifindex in &row.ce_port_ifindexes {
            by_ifindex
                .entry(ifindex)
                .and_modify(|existing| {
                    // Most-restrictive wins. Suppress has any-false
                    // beats any-true; we AND each flag.
                    existing.unicast_flood &= new.unicast_flood;
                    existing.multicast_flood &= new.multicast_flood;
                    existing.broadcast_flood &= new.broadcast_flood;
                })
                .or_insert(new);
        }
    }
    by_ifindex
        .into_iter()
        .map(|(ifindex, flags)| BumPortFlagPlan { ifindex, flags })
        .collect()
}

/// Diff two plan snapshots and return only the entries that need to
/// change. Idempotent: an unchanged port emits nothing. Used by the
/// reconciler to translate a level-triggered intent into the minimal
/// set of `RTM_SETLINK` calls.
#[must_use]
pub fn diff_flag_plans(prior: &[BumPortFlagPlan], new: &[BumPortFlagPlan]) -> Vec<BumPortFlagPlan> {
    use std::collections::BTreeMap;

    let prior_by_ifindex: BTreeMap<u32, BumPortFlags> =
        prior.iter().map(|p| (p.ifindex, p.flags)).collect();

    let mut changed = Vec::new();
    let mut seen_in_new = std::collections::BTreeSet::new();
    for plan in new {
        seen_in_new.insert(plan.ifindex);
        match prior_by_ifindex.get(&plan.ifindex) {
            Some(existing) if *existing == plan.flags => {} // idempotent
            _ => changed.push(*plan),
        }
    }

    // Ports that were in `prior` but disappeared from `new` should
    // be restored to the allow-all default — the segment no longer
    // covers them so the kernel should not stay in suppress mode.
    for plan in prior {
        if !seen_in_new.contains(&plan.ifindex) && plan.flags != BumPortFlags::allow_all() {
            changed.push(BumPortFlagPlan {
                ifindex: plan.ifindex,
                flags: BumPortFlags::allow_all(),
            });
        }
    }

    changed
}

#[cfg(test)]
mod tests {
    use rustbgpd_evpn::{
        BumEnforcementReadiness, BumEnforcementStatus, BumForwardingAction, DfRole,
        EthernetSegmentIdentifier, EvpnInstanceId,
    };

    use super::*;

    fn vni(n: u32) -> EvpnInstanceId {
        EvpnInstanceId::new(n).unwrap()
    }

    fn esi(seed: u8) -> EthernetSegmentIdentifier {
        EthernetSegmentIdentifier::new([seed; 10])
    }

    fn row(
        action: BumForwardingAction,
        ce_ifindexes: Vec<u32>,
        readiness: BumEnforcementReadiness,
    ) -> BumEnforcementStatus {
        let role = match action {
            BumForwardingAction::Allow => DfRole::Df,
            BumForwardingAction::Suppress => DfRole::NonDf,
        };
        BumEnforcementStatus {
            esi: esi(1),
            vni: vni(100),
            role,
            action,
            bridge: "br100".to_string(),
            vxlan_ifindex: Some(200),
            ce_port_ifindexes: ce_ifindexes,
            readiness,
        }
    }

    #[test]
    fn for_action_round_trips_through_df_role() {
        assert_eq!(
            BumPortFlags::for_action(BumForwardingAction::from_df_role(DfRole::Df)),
            BumPortFlags::allow_all()
        );
        assert_eq!(
            BumPortFlags::for_action(BumForwardingAction::from_df_role(DfRole::NonDf)),
            BumPortFlags::suppress_all()
        );
    }

    #[test]
    fn allow_and_suppress_are_complementary_triplets() {
        let allow = BumPortFlags::allow_all();
        let suppress = BumPortFlags::suppress_all();
        assert!(allow.unicast_flood && allow.multicast_flood && allow.broadcast_flood);
        assert!(!suppress.unicast_flood && !suppress.multicast_flood && !suppress.broadcast_flood);
    }

    #[test]
    fn compute_plan_skips_not_ready_rows() {
        let rows = vec![row(
            BumForwardingAction::Suppress,
            vec![10],
            BumEnforcementReadiness::NotReady {
                reason: "missing VXLAN".into(),
            },
        )];
        assert!(compute_flag_plan(&rows).is_empty());
    }

    #[test]
    fn compute_plan_emits_one_row_per_ce_port() {
        let rows = vec![row(
            BumForwardingAction::Suppress,
            vec![10, 11, 12],
            BumEnforcementReadiness::Ready,
        )];
        let plan = compute_flag_plan(&rows);
        assert_eq!(plan.len(), 3);
        for entry in &plan {
            assert_eq!(entry.flags, BumPortFlags::suppress_all());
        }
        let ifindexes: Vec<u32> = plan.iter().map(|p| p.ifindex).collect();
        assert_eq!(ifindexes, vec![10, 11, 12]);
    }

    #[test]
    fn compute_plan_dedupes_with_suppress_winning_over_allow() {
        // Same CE port appears under one Allow row and one Suppress row.
        // The suppress action must win — failing open would leak BUM
        // for whichever segment required suppression.
        let rows = vec![
            row(
                BumForwardingAction::Allow,
                vec![10, 11],
                BumEnforcementReadiness::Ready,
            ),
            row(
                BumForwardingAction::Suppress,
                vec![11, 12],
                BumEnforcementReadiness::Ready,
            ),
        ];
        let plan = compute_flag_plan(&rows);
        assert_eq!(plan.len(), 3);
        let by_ifindex: std::collections::BTreeMap<u32, BumPortFlags> =
            plan.iter().map(|p| (p.ifindex, p.flags)).collect();
        assert_eq!(by_ifindex[&10], BumPortFlags::allow_all());
        assert_eq!(by_ifindex[&11], BumPortFlags::suppress_all()); // suppress wins
        assert_eq!(by_ifindex[&12], BumPortFlags::suppress_all());
    }

    #[test]
    fn diff_emits_nothing_for_unchanged_plan() {
        let plan = vec![BumPortFlagPlan {
            ifindex: 10,
            flags: BumPortFlags::suppress_all(),
        }];
        assert!(diff_flag_plans(&plan, &plan).is_empty());
    }

    #[test]
    fn diff_emits_changed_ports_only() {
        let prior = vec![
            BumPortFlagPlan {
                ifindex: 10,
                flags: BumPortFlags::allow_all(),
            },
            BumPortFlagPlan {
                ifindex: 11,
                flags: BumPortFlags::suppress_all(),
            },
        ];
        let new = vec![
            BumPortFlagPlan {
                ifindex: 10,
                flags: BumPortFlags::suppress_all(), // flipped
            },
            BumPortFlagPlan {
                ifindex: 11,
                flags: BumPortFlags::suppress_all(), // unchanged
            },
        ];
        let diff = diff_flag_plans(&prior, &new);
        assert_eq!(diff.len(), 1);
        assert_eq!(diff[0].ifindex, 10);
        assert_eq!(diff[0].flags, BumPortFlags::suppress_all());
    }

    #[test]
    fn diff_restores_disappeared_suppressed_ports_to_allow_all() {
        // A port that was previously suppressed but is no longer
        // covered by any segment must be restored to allow_all so
        // the kernel doesn't leak suppress state into a port that
        // the EVPN orchestrator no longer manages.
        let prior = vec![BumPortFlagPlan {
            ifindex: 10,
            flags: BumPortFlags::suppress_all(),
        }];
        let new: Vec<BumPortFlagPlan> = vec![];
        let diff = diff_flag_plans(&prior, &new);
        assert_eq!(diff.len(), 1);
        assert_eq!(diff[0].ifindex, 10);
        assert_eq!(diff[0].flags, BumPortFlags::allow_all());
    }

    #[test]
    fn diff_skips_disappeared_already_allow_ports() {
        // No restoration needed if the port was already at the
        // default (allow_all) — saves a redundant netlink call.
        let prior = vec![BumPortFlagPlan {
            ifindex: 10,
            flags: BumPortFlags::allow_all(),
        }];
        let new: Vec<BumPortFlagPlan> = vec![];
        assert!(diff_flag_plans(&prior, &new).is_empty());
    }
}
