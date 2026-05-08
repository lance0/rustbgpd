//! Per-instance readiness checks.
//!
//! Walks every [`rustbgpd_evpn::EvpnInstance`] and emits a
//! [`crate::InstanceProbe`] result based on the link cache from
//! [`crate::linux::links`].
//!
//! Per ADR-0054 §4 the probe verifies five properties before it
//! reports `Ready`:
//!
//! 1. The named bridge exists.
//! 2. Exactly one VXLAN port for the instance VNI is attached to it.
//! 3. The VXLAN port's `local` source IP matches `local_vtep_ip`.
//! 4. The VXLAN port has kernel learning disabled (EVPN owns the FDB).
//! 5. The bridge is **not** VLAN-aware (Gate 7b explicitly defers).
//!
//! Any failed check produces `NotReady` with an operator-facing
//! reason. Instances with `bridge = None` produce `Unbound` and are
//! excluded from reconcile entirely.

use rustbgpd_evpn::{EvpnInstance, EvpnInstanceTable};

use crate::snapshot::{InstanceProbe, InstanceProbes};

use super::links::LinkCache;

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
        return InstanceProbe::NotReady {
            reason: format!(
                "bridge {bridge_name} is VLAN-aware (vlan_filtering=1); \
                 not supported in Gate 7b"
            ),
        };
    }
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

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::net::IpAddr;

    use rustbgpd_evpn::{
        EvpnInstance, EvpnInstanceId, EvpnInstanceTable, RouteDistinguisher, RouteTarget,
    };

    use super::super::links::{BridgeLink, LinkCache};
    use super::*;
    use crate::snapshot::KernelVxlanInfo;

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

    fn cache_with(name: &str, link: BridgeLink) -> LinkCache {
        let mut bridges = HashMap::new();
        let mut vxlan_to_vni = HashMap::new();
        if let Some(v) = &link.vxlan {
            vxlan_to_vni.insert(v.ifindex, v.vni);
        }
        bridges.insert(name.to_string(), link);
        LinkCache {
            bridges,
            vxlan_ifindex_to_vni: vxlan_to_vni,
            bridge_port_to_vni: HashMap::new(),
        }
    }

    fn ready_link(vni: u32, local: &str) -> BridgeLink {
        BridgeLink {
            ifindex: 100,
            mac: None,
            vlan_filtering: false,
            vxlan_attach_count: 1,
            vxlan: Some(KernelVxlanInfo {
                ifindex: 200,
                vni,
                local_ip: ipa(local),
                learning_disabled: Some(true),
            }),
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
