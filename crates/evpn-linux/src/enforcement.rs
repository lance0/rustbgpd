//! Observable Gate 8b BUM-enforcement plan derivation.
//!
//! This module deliberately does **not** mutate kernel state. It
//! resolves the portable [`rustbgpd_evpn::BumEnforcementTable`] against
//! the current link snapshot so operators and follow-up tests can see
//! exactly which bridge / VXLAN / CE-facing ports would be targeted
//! before we choose the concrete Linux primitive.

use rustbgpd_evpn::{BumEnforcementReadiness, BumEnforcementStatus, BumEnforcementTable};

use crate::snapshot::KernelSnapshot;

/// Resolve desired BUM-enforcement rows against the current kernel
/// link inventory.
#[must_use]
pub fn build_bum_enforcement_status(
    intent: &BumEnforcementTable,
    snapshot: &KernelSnapshot,
) -> Vec<BumEnforcementStatus> {
    intent
        .iter()
        .map(|entry| {
            let Some(link) = snapshot.links.get(&entry.bridge) else {
                return BumEnforcementStatus {
                    esi: entry.esi,
                    vni: entry.vni,
                    role: entry.role,
                    action: entry.action,
                    bridge: entry.bridge.clone(),
                    vxlan_ifindex: None,
                    ce_port_ifindexes: Vec::new(),
                    readiness: BumEnforcementReadiness::NotReady {
                        reason: format!("bridge {} not found", entry.bridge),
                    },
                };
            };

            let vxlan_ifindex = link.vxlan.as_ref().map(|v| v.ifindex);
            let ce_port_ifindexes = link.ce_port_ifindexes.clone();
            let readiness = if link.vxlan.is_none() {
                BumEnforcementReadiness::NotReady {
                    reason: format!(
                        "bridge {} has no unique VXLAN port for VNI {}",
                        entry.bridge,
                        entry.vni.as_u32()
                    ),
                }
            } else if ce_port_ifindexes.is_empty() {
                BumEnforcementReadiness::NotReady {
                    reason: format!("bridge {} has no CE-facing ports", entry.bridge),
                }
            } else {
                BumEnforcementReadiness::Ready
            };

            BumEnforcementStatus {
                esi: entry.esi,
                vni: entry.vni,
                role: entry.role,
                action: entry.action,
                bridge: entry.bridge.clone(),
                vxlan_ifindex,
                ce_port_ifindexes,
                readiness,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use rustbgpd_evpn::{BumForwardingAction, DfRole, EthernetSegmentIdentifier, EvpnInstanceId};

    use super::*;
    use crate::snapshot::{KernelLinkInfo, KernelVxlanInfo};

    fn vni(n: u32) -> EvpnInstanceId {
        EvpnInstanceId::new(n).unwrap()
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn esi(seed: u8) -> EthernetSegmentIdentifier {
        EthernetSegmentIdentifier::new([seed; 10])
    }

    #[test]
    fn resolves_ready_non_df_to_suppress_plan() {
        let mut table = BumEnforcementTable::new();
        table.insert(esi(1), vni(100), DfRole::NonDf, "br100".to_string());
        let mut snapshot = KernelSnapshot::new();
        snapshot.insert_link(KernelLinkInfo {
            bridge_name: "br100".to_string(),
            vlan_filtering: false,
            vxlan: Some(KernelVxlanInfo {
                ifindex: 200,
                vni: 100,
                local_ip: ip("10.0.0.1"),
                learning_disabled: Some(true),
            }),
            ce_port_ifindexes: vec![10, 11],
        });

        let rows = build_bum_enforcement_status(&table, &snapshot);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].action, BumForwardingAction::Suppress);
        assert_eq!(rows[0].vxlan_ifindex, Some(200));
        assert_eq!(rows[0].ce_port_ifindexes, vec![10, 11]);
        assert_eq!(rows[0].readiness, BumEnforcementReadiness::Ready);
    }

    #[test]
    fn df_role_resolves_to_allow_plan() {
        let mut table = BumEnforcementTable::new();
        table.insert(esi(1), vni(100), DfRole::Df, "br100".to_string());
        let mut snapshot = KernelSnapshot::new();
        snapshot.insert_link(KernelLinkInfo {
            bridge_name: "br100".to_string(),
            vlan_filtering: false,
            vxlan: Some(KernelVxlanInfo {
                ifindex: 200,
                vni: 100,
                local_ip: ip("10.0.0.1"),
                learning_disabled: Some(true),
            }),
            ce_port_ifindexes: vec![10],
        });

        let rows = build_bum_enforcement_status(&table, &snapshot);
        assert_eq!(rows[0].action, BumForwardingAction::Allow);
        assert_eq!(rows[0].readiness, BumEnforcementReadiness::Ready);
    }

    #[test]
    fn missing_bridge_reports_not_ready() {
        let mut table = BumEnforcementTable::new();
        table.insert(esi(1), vni(100), DfRole::NonDf, "br100".to_string());

        let rows = build_bum_enforcement_status(&table, &KernelSnapshot::new());
        assert!(matches!(
            rows[0].readiness,
            BumEnforcementReadiness::NotReady { .. }
        ));
        assert_eq!(rows[0].vxlan_ifindex, None);
        assert!(rows[0].ce_port_ifindexes.is_empty());
    }

    #[test]
    fn missing_ce_ports_reports_not_ready() {
        let mut table = BumEnforcementTable::new();
        table.insert(esi(1), vni(100), DfRole::NonDf, "br100".to_string());
        let mut snapshot = KernelSnapshot::new();
        snapshot.insert_link(KernelLinkInfo {
            bridge_name: "br100".to_string(),
            vlan_filtering: false,
            vxlan: Some(KernelVxlanInfo {
                ifindex: 200,
                vni: 100,
                local_ip: ip("10.0.0.1"),
                learning_disabled: Some(true),
            }),
            ce_port_ifindexes: Vec::new(),
        });

        let rows = build_bum_enforcement_status(&table, &snapshot);
        assert!(matches!(
            rows[0].readiness,
            BumEnforcementReadiness::NotReady { .. }
        ));
        assert_eq!(rows[0].vxlan_ifindex, Some(200));
    }

    #[test]
    fn preserves_intent_order_by_esi_then_vni() {
        let mut table = BumEnforcementTable::new();
        table.insert(esi(2), vni(200), DfRole::Df, "br200".to_string());
        table.insert(esi(1), vni(100), DfRole::Df, "br100".to_string());

        let rows = build_bum_enforcement_status(&table, &KernelSnapshot::new());
        assert_eq!(rows[0].esi, esi(1));
        assert_eq!(rows[1].esi, esi(2));
    }
}
