//! Per-instance readiness checks.
//!
//! Walks every [`rustbgpd_evpn::EvpnInstance`] and emits a
//! [`crate::InstanceProbe`] result based on the link cache from
//! [`crate::linux::links`].
//!
//! Per ADR-0054 §4 and ADR-0089 the probe verifies topology before it
//! reports `Ready`:
//!
//! 1. The named bridge exists.
//! 2. Legacy instances (`bridge_vlan = None`) use the historical
//!    one-bridge-one-VXLAN shape and require `vlan_filtering=0`.
//! 3. ADR-0089 instances (`bridge_vlan = Some(VID)`) require
//!    `vlan_filtering=1`, a unique VXLAN member whose VNI matches the
//!    instance, and VLAN membership for `VID` on both the bridge and
//!    that VXLAN member.
//! 4. In both shapes, the VXLAN port's `local` source IP matches
//!    `local_vtep_ip` and kernel learning is disabled.
//!
//! Any failed check produces `NotReady` with an operator-facing
//! reason. Instances with `bridge = None` produce `Unbound` and are
//! excluded from reconcile entirely.

use rustbgpd_evpn::{EvpnInstance, EvpnInstanceTable};

use crate::snapshot::{
    InstanceProbe, InstanceProbes, KernelBridgePortVlanInfo, KernelBridgeVlanInfo, KernelVxlanInfo,
};

use super::links::{BridgeLink, LinkCache};

pub(crate) fn probe_instances(instances: &EvpnInstanceTable, cache: &LinkCache) -> InstanceProbes {
    let mut probes = InstanceProbes::new();
    for inst in instances.iter() {
        probes.insert(inst.id, probe_one(inst, cache));
        // Surface the bridge MAC alongside the probe outcome when
        // the kernel reported one. SVI-MAC origination consumes this
        // via `InstanceDataplaneStatus.bridge_mac` rather than
        // re-walking the LinkCache itself (ADR-0054 §1).
        if let Some(bridge_name) = inst.bridge.as_deref()
            && let Some(bridge) = cache.bridges.get(bridge_name)
            && let Some(mac) = bridge.mac
        {
            probes.set_bridge_mac(inst.id, mac);
        }
    }
    probes
}

fn probe_one(inst: &EvpnInstance, cache: &LinkCache) -> InstanceProbe {
    let Some(bridge_name) = inst.bridge.as_deref() else {
        return InstanceProbe::Unbound;
    };
    let Some(bridge) = cache.bridges.get(bridge_name) else {
        return InstanceProbe::NotReady {
            reason: format!("bridge {bridge_name} not found"),
        };
    };
    if bridge.vlan_filtering {
        if let Some(bridge_vlan) = inst.bridge_vlan {
            return probe_vlan_aware_bridge(inst, bridge_name, bridge, bridge_vlan.as_u16());
        }
        return InstanceProbe::NotReady {
            reason: format!(
                "bridge {bridge_name} is VLAN-aware (vlan_filtering=1); \
                 configure bridge_vlan to enable ADR-0089 VLAN-aware readiness"
            ),
        };
    }
    if let Some(bridge_vlan) = inst.bridge_vlan {
        return InstanceProbe::NotReady {
            reason: format!(
                "instance has bridge_vlan={} but bridge {bridge_name} has vlan_filtering=0",
                bridge_vlan.as_u16()
            ),
        };
    }
    probe_legacy_bridge(inst, bridge_name, bridge)
}

fn probe_legacy_bridge(
    inst: &EvpnInstance,
    bridge_name: &str,
    bridge: &BridgeLink,
) -> InstanceProbe {
    if bridge.vxlan_attach_count != 1 {
        return InstanceProbe::NotReady {
            reason: format!(
                "bridge {bridge_name} has {} VXLAN ports attached \
                 (require exactly 1)",
                bridge.vxlan_attach_count
            ),
        };
    }
    let Some(vxlan) = &bridge.vxlan else {
        return InstanceProbe::NotReady {
            reason: format!(
                "bridge {bridge_name} has a single VXLAN port but \
                 inventory missed its attributes"
            ),
        };
    };
    probe_vxlan_attrs(inst, bridge_name, vxlan)
}

fn probe_vlan_aware_bridge(
    inst: &EvpnInstance,
    bridge_name: &str,
    bridge: &BridgeLink,
    bridge_vlan: u16,
) -> InstanceProbe {
    let want_vni = inst.id.as_u32();
    let matching: Vec<_> = bridge
        .vxlan_ports
        .iter()
        .filter(|port| port.vni == want_vni)
        .collect();
    let [port] = matching.as_slice() else {
        return InstanceProbe::NotReady {
            reason: format!(
                "bridge {bridge_name} has {} VXLAN ports for VNI {want_vni} \
                 (require exactly 1 for bridge_vlan={bridge_vlan})",
                matching.len()
            ),
        };
    };
    if !vlan_rows_contain(&bridge.vlans, bridge_vlan) {
        return InstanceProbe::NotReady {
            reason: format!("bridge {bridge_name} does not carry VLAN {bridge_vlan}"),
        };
    }
    let Some(port_inventory) = bridge
        .port_vlan_inventory
        .iter()
        .find(|row| row.ifindex == port.ifindex)
    else {
        return InstanceProbe::NotReady {
            reason: format!(
                "VXLAN port ifindex {} on bridge {bridge_name} has no VLAN inventory",
                port.ifindex
            ),
        };
    };
    if !port_vlan_inventory_contains(port_inventory, bridge_vlan) {
        return InstanceProbe::NotReady {
            reason: format!(
                "VXLAN port ifindex {} on bridge {bridge_name} does not carry VLAN {bridge_vlan}",
                port.ifindex
            ),
        };
    }
    probe_vxlan_attrs(inst, bridge_name, port)
}

fn probe_vxlan_attrs(
    inst: &EvpnInstance,
    bridge_name: &str,
    vxlan: &KernelVxlanInfo,
) -> InstanceProbe {
    let want_vni = inst.id.as_u32();
    if vxlan.vni != want_vni {
        return InstanceProbe::NotReady {
            reason: format!(
                "VXLAN port on bridge {bridge_name} has VNI {} (want {want_vni})",
                vxlan.vni
            ),
        };
    }
    if vxlan.local_ip != inst.local_vtep_ip {
        return InstanceProbe::NotReady {
            reason: format!(
                "VXLAN local IP {} does not match instance local_vtep_ip {}",
                vxlan.local_ip, inst.local_vtep_ip
            ),
        };
    }
    match vxlan.learning_disabled {
        Some(true) => {}
        Some(false) => {
            return InstanceProbe::NotReady {
                reason: format!(
                    "VXLAN port on bridge {bridge_name} has learning enabled; \
                     EVPN requires `nolearning`"
                ),
            };
        }
        None => {
            // Fail closed: kernel didn't report `IFLA_VXLAN_LEARNING`.
            // Older kernel or non-vanilla driver — surface explicitly
            // rather than silently programming.
            return InstanceProbe::NotReady {
                reason: format!(
                    "VXLAN port on bridge {bridge_name} did not report \
                     IFLA_VXLAN_LEARNING; cannot verify nolearning"
                ),
            };
        }
    }
    InstanceProbe::Ready
}

fn port_vlan_inventory_contains(row: &KernelBridgePortVlanInfo, vlan: u16) -> bool {
    vlan_rows_contain(&row.vlans, vlan)
}

fn vlan_rows_contain(rows: &[KernelBridgeVlanInfo], vlan: u16) -> bool {
    let mut range_start = None;
    for row in rows {
        if row.flags.range_begin {
            range_start = Some(row.vid);
            if row.vid == vlan {
                return true;
            }
            continue;
        }
        if row.flags.range_end {
            if let Some(start) = range_start.take()
                && start <= vlan
                && vlan <= row.vid
            {
                return true;
            }
            if row.vid == vlan {
                return true;
            }
            continue;
        }
        if row.vid == vlan {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use std::collections::{HashMap, HashSet};
    use std::net::IpAddr;

    use rustbgpd_evpn::{
        BridgeVlan, EvpnInstance, EvpnInstanceId, EvpnInstanceTable, RouteDistinguisher,
        RouteTarget,
    };

    use super::super::links::{BridgeLink, LinkCache};
    use super::*;
    use crate::snapshot::{
        KernelBridgePortVlanInfo, KernelBridgeVlanFlags, KernelBridgeVlanInfo, KernelVxlanInfo,
    };

    fn vni(n: u32) -> EvpnInstanceId {
        EvpnInstanceId::new(n).unwrap()
    }
    fn ipa(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn instance(v: u32, bridge: Option<&str>, vtep: &str) -> EvpnInstance {
        let mut bytes = [0u8; 8];
        bytes[2..4].copy_from_slice(&65001u16.to_be_bytes());
        bytes[4..8].copy_from_slice(&v.to_be_bytes());
        EvpnInstance::new(
            vni(v),
            RouteDistinguisher::new(bytes),
            vec![RouteTarget::TwoOctetAs {
                asn: 65001,
                value: v,
            }],
            ipa(vtep),
            bridge.map(String::from),
            false,
        )
        .unwrap()
    }

    fn instance_with_vlan(v: u32, bridge: &str, vtep: &str, vlan: u16) -> EvpnInstance {
        instance(v, Some(bridge), vtep)
            .with_bridge_vlan(Some(BridgeVlan::new(u32::from(vlan)).unwrap()))
    }

    fn cache_with(name: &str, link: BridgeLink) -> LinkCache {
        let mut bridges = HashMap::new();
        let mut vxlan_to_vni = HashMap::new();
        if let Some(v) = &link.vxlan {
            vxlan_to_vni.insert(v.ifindex, v.vni);
        }
        for v in &link.vxlan_ports {
            vxlan_to_vni.insert(v.ifindex, v.vni);
        }
        bridges.insert(name.to_string(), link);
        LinkCache {
            bridges,
            vxlan_ifindex_to_vni: vxlan_to_vni,
            bridge_port_to_vni: HashMap::new(),
            local_mac_vlan_bindings: HashMap::new(),
            bridge_port_vlan_to_vni: HashMap::new(),
            bridge_ports_requiring_vlan_attribution: HashSet::new(),
            vxlan_port_vlan_to_vni: HashMap::new(),
            vxlan_ports_requiring_vlan_attribution: HashSet::new(),
            bridge_ports_by_name: HashMap::new(),
        }
    }

    fn ready_link(vni: u32, local: &str) -> BridgeLink {
        let vxlan = KernelVxlanInfo {
            ifindex: 200,
            vni,
            local_ip: ipa(local),
            learning_disabled: Some(true),
        };
        BridgeLink {
            ifindex: 100,
            mac: None,
            vlan_filtering: false,
            vxlan_attach_count: 1,
            ce_port_ifindexes: Vec::new(),
            vxlan: Some(vxlan.clone()),
            vxlan_ports: vec![vxlan],
            ..BridgeLink::default()
        }
    }

    fn vlan_row(vlan: u16) -> KernelBridgeVlanInfo {
        KernelBridgeVlanInfo {
            vid: vlan,
            flags: KernelBridgeVlanFlags::default(),
        }
    }

    fn vlan_aware_link(vni: u32, bridge_vlan: u16, local: &str) -> BridgeLink {
        let vxlan_port = KernelVxlanInfo {
            ifindex: 200,
            vni,
            local_ip: ipa(local),
            learning_disabled: Some(true),
        };
        BridgeLink {
            ifindex: 100,
            mac: None,
            vlan_filtering: true,
            vxlan: None,
            vxlan_ports: vec![vxlan_port.clone()],
            vxlan_attach_count: 1,
            ce_port_ifindexes: Vec::new(),
            vlans: vec![vlan_row(bridge_vlan)],
            port_vlan_inventory: vec![KernelBridgePortVlanInfo {
                ifindex: vxlan_port.ifindex,
                name: Some("vxlan100".to_string()),
                is_vxlan: true,
                vlans: vec![vlan_row(bridge_vlan)],
                vlan_tunnels: Vec::new(),
            }],
            ..BridgeLink::default()
        }
    }

    #[test]
    fn unbound_instance_when_bridge_is_none() {
        let inst = instance(100, None, "10.0.0.1");
        let cache = LinkCache::default();
        assert_eq!(probe_one(&inst, &cache), InstanceProbe::Unbound);
    }

    #[test]
    fn not_ready_when_bridge_missing() {
        let inst = instance(100, Some("br100"), "10.0.0.1");
        let cache = LinkCache::default();
        match probe_one(&inst, &cache) {
            InstanceProbe::NotReady { reason } => assert!(reason.contains("br100")),
            other => panic!("expected NotReady, got {other:?}"),
        }
    }

    #[test]
    fn ready_when_all_checks_pass() {
        let inst = instance(100, Some("br100"), "10.0.0.1");
        let cache = cache_with("br100", ready_link(100, "10.0.0.1"));
        assert_eq!(probe_one(&inst, &cache), InstanceProbe::Ready);
    }

    #[test]
    fn not_ready_when_bridge_is_vlan_aware() {
        let inst = instance(100, Some("br100"), "10.0.0.1");
        let mut link = ready_link(100, "10.0.0.1");
        link.vlan_filtering = true;
        let cache = cache_with("br100", link);
        match probe_one(&inst, &cache) {
            InstanceProbe::NotReady { reason } => assert!(reason.contains("VLAN-aware")),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn ready_when_vlan_aware_binding_matches_traditional_vxlan() {
        let inst = instance_with_vlan(100, "br100", "10.0.0.1", 10);
        let cache = cache_with("br100", vlan_aware_link(100, 10, "10.0.0.1"));
        assert_eq!(probe_one(&inst, &cache), InstanceProbe::Ready);
    }

    #[test]
    fn not_ready_when_bridge_vlan_configured_on_non_vlan_filtering_bridge() {
        let inst = instance_with_vlan(100, "br100", "10.0.0.1", 10);
        let cache = cache_with("br100", ready_link(100, "10.0.0.1"));
        match probe_one(&inst, &cache) {
            InstanceProbe::NotReady { reason } => assert!(reason.contains("vlan_filtering=0")),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn not_ready_when_vlan_aware_bridge_lacks_bridge_vlan() {
        let inst = instance_with_vlan(100, "br100", "10.0.0.1", 10);
        let mut link = vlan_aware_link(100, 10, "10.0.0.1");
        link.vlans.clear();
        let cache = cache_with("br100", link);
        match probe_one(&inst, &cache) {
            InstanceProbe::NotReady { reason } => {
                assert!(reason.contains("does not carry VLAN 10"));
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn not_ready_when_vlan_missing_on_matching_vxlan_port() {
        let inst = instance_with_vlan(100, "br100", "10.0.0.1", 10);
        let mut link = vlan_aware_link(100, 10, "10.0.0.1");
        link.port_vlan_inventory[0].vlans.clear();
        let cache = cache_with("br100", link);
        match probe_one(&inst, &cache) {
            InstanceProbe::NotReady { reason } => {
                assert!(reason.contains("does not carry VLAN 10"));
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn not_ready_when_no_matching_vxlan_for_vlan_aware_binding() {
        let inst = instance_with_vlan(100, "br100", "10.0.0.1", 10);
        let cache = cache_with("br100", vlan_aware_link(200, 10, "10.0.0.1"));
        match probe_one(&inst, &cache) {
            InstanceProbe::NotReady { reason } => assert!(reason.contains("0 VXLAN ports")),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn not_ready_when_multiple_matching_vxlan_ports_for_vlan_aware_binding() {
        let inst = instance_with_vlan(100, "br100", "10.0.0.1", 10);
        let mut link = vlan_aware_link(100, 10, "10.0.0.1");
        let mut second = link.vxlan_ports[0].clone();
        second.ifindex = 201;
        link.vxlan_ports.push(second.clone());
        link.vxlan_attach_count = 2;
        link.port_vlan_inventory.push(KernelBridgePortVlanInfo {
            ifindex: second.ifindex,
            name: Some("vxlan100b".to_string()),
            is_vxlan: true,
            vlans: vec![vlan_row(10)],
            vlan_tunnels: Vec::new(),
        });
        let cache = cache_with("br100", link);
        match probe_one(&inst, &cache) {
            InstanceProbe::NotReady { reason } => assert!(reason.contains("2 VXLAN ports")),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn not_ready_on_vni_mismatch() {
        let inst = instance(100, Some("br100"), "10.0.0.1");
        let cache = cache_with("br100", ready_link(200, "10.0.0.1"));
        match probe_one(&inst, &cache) {
            InstanceProbe::NotReady { reason } => assert!(reason.contains("VNI 200")),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn not_ready_on_local_ip_mismatch() {
        let inst = instance(100, Some("br100"), "10.0.0.1");
        let cache = cache_with("br100", ready_link(100, "10.0.0.2"));
        match probe_one(&inst, &cache) {
            InstanceProbe::NotReady { reason } => assert!(reason.contains("local_vtep_ip")),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn not_ready_when_learning_enabled() {
        let inst = instance(100, Some("br100"), "10.0.0.1");
        let mut link = ready_link(100, "10.0.0.1");
        if let Some(v) = link.vxlan.as_mut() {
            v.learning_disabled = Some(false);
        }
        let cache = cache_with("br100", link);
        match probe_one(&inst, &cache) {
            InstanceProbe::NotReady { reason } => assert!(reason.contains("learning")),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn not_ready_when_learning_attribute_missing() {
        let inst = instance(100, Some("br100"), "10.0.0.1");
        let mut link = ready_link(100, "10.0.0.1");
        if let Some(v) = link.vxlan.as_mut() {
            v.learning_disabled = None;
        }
        let cache = cache_with("br100", link);
        match probe_one(&inst, &cache) {
            InstanceProbe::NotReady { reason } => {
                assert!(reason.contains("IFLA_VXLAN_LEARNING"));
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn not_ready_when_two_vxlan_ports_attached() {
        let inst = instance(100, Some("br100"), "10.0.0.1");
        let mut link = ready_link(100, "10.0.0.1");
        link.vxlan_attach_count = 2;
        link.vxlan = None;
        let cache = cache_with("br100", link);
        match probe_one(&inst, &cache) {
            InstanceProbe::NotReady { reason } => {
                assert!(reason.contains("2 VXLAN"));
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn probe_instances_walks_full_table() {
        let mut table = EvpnInstanceTable::new();
        table
            .insert(instance(100, Some("br100"), "10.0.0.1"))
            .unwrap();
        table.insert(instance(200, None, "10.0.0.1")).unwrap();
        let cache = cache_with("br100", ready_link(100, "10.0.0.1"));
        let probes = probe_instances(&table, &cache);
        assert_eq!(probes.get(vni(100)), Some(&InstanceProbe::Ready));
        assert_eq!(probes.get(vni(200)), Some(&InstanceProbe::Unbound));
    }
}
