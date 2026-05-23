//! Local IP-VRF / L3VNI domain model (Gate 9, RFC 9136 §4.4.2
//! symmetric Interface-less IRB).
//!
//! Mirrors the shape of `instance::EvpnInstance` for the L2 side. Pure
//! configuration / domain object — kernel-free, no netlink, no I/O.
//! Reconciliation lives in the daemon-side supervisor that consumes
//! these.
//!
//! See ADR-0058 for the architecture pinned around this object — in
//! particular §3 (observe-only Linux device lifecycle) and §4 (Router
//! MAC is operator-supplied, never auto-derived from the kernel).

pub mod observation;
pub mod origination;
pub mod projection;
pub mod readiness;

pub use observation::{IpVrfRouteDump, LocalIpRouteObservation, RouteFilterReason, RouteSource};
pub use origination::{
    LocalIpRoute, OriginatedIpPrefixRoute, OriginationError, originate_ip_prefix_route,
};
pub use projection::{
    ProjectedIpPrefixRoute, ProjectedOverlayIndexRoute, RemoteIpPrefixEntry, RemoteIpPrefixTable,
    project_ip_prefix_routes, project_ip_prefix_routes_with_overlay_index,
};
pub use readiness::{
    IpVrfKernelSnapshot, IpVrfNotReady, IpVrfStatus, L3VxlanObservation, VrfObservation, probe,
};

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use rustbgpd_wire::{MacAddress, RouteDistinguisher};

use crate::instance::EvpnInstanceId;
use crate::route_target::RouteTarget;

/// Identifier for one local IP-VRF, distinct from the L2 VNI namespace
/// by domain even though the wire VNI space is shared (validation at
/// config load enforces no overlap between L2VNIs and L3VNIs).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct IpVrfId(u32);

impl IpVrfId {
    /// Build an [`IpVrfId`] from a raw VNI in `1..=16_777_215`.
    ///
    /// # Errors
    /// Returns [`IpVrfIdError::OutOfRange`] when `vni` is 0 or above the
    /// 24-bit max.
    pub fn new(vni: u32) -> Result<Self, IpVrfIdError> {
        if vni == 0 {
            return Err(IpVrfIdError::OutOfRange { vni });
        }
        if vni > 0x00FF_FFFF {
            return Err(IpVrfIdError::OutOfRange { vni });
        }
        Ok(Self(vni))
    }

    /// Raw L3VNI value.
    #[must_use]
    pub fn as_u32(self) -> u32 {
        self.0
    }
}

#[derive(Debug, thiserror::Error)]
pub enum IpVrfIdError {
    #[error("L3VNI {vni} out of range (must be 1..=16_777_215)")]
    OutOfRange { vni: u32 },
}

/// One local IP-VRF / L3VNI tenant served by this VTEP.
///
/// Shape mirrors `EvpnInstance` for the L2 side. The kernel-side
/// devices (`vrf_device`, `l3vxlan_device`) are operator-managed —
/// the daemon only observes them and reports readiness; it does not
/// create or destroy them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpVrf {
    /// Operator-facing handle. Used by `[[evpn_instances]].ip_vrf` to
    /// bind L2VNIs to this IP-VRF. Validated at config load to be
    /// unique across `[[evpn_ip_vrfs]]`.
    pub name: String,
    /// L3VNI for the VXLAN encapsulation of routed traffic.
    pub id: IpVrfId,
    /// Route Distinguisher (RFC 4364 §4.2 form).
    pub rd: RouteDistinguisher,
    /// Bidirectional Route Targets — applied to both import and
    /// export. Always non-empty.
    pub route_targets: Vec<RouteTarget>,
    /// VXLAN tunnel source IP carried as `NEXT_HOP` on outbound Type 5.
    pub local_vtep_ip: IpAddr,
    /// Router MAC value advertised on every outbound Type 5 via the
    /// RFC 9135 §4.2 / RFC 9136 Router MAC extended community, and
    /// asserted against the kernel-side L3VXLAN device's MAC at
    /// readiness. Operator-supplied — see ADR-0058 §4 for why we do
    /// not auto-derive this.
    pub router_mac: MacAddress,
    /// Linux VRF device name. Observe-only — the daemon does not own
    /// its lifecycle.
    pub vrf_device: String,
    /// Linux L3 VXLAN device name. Observe-only.
    pub l3vxlan_device: String,
    /// VRF route table id. Cross-checked against `vrf_device`'s
    /// `IFLA_VRF_TABLE` at readiness.
    pub table_id: u32,
}

impl IpVrf {
    /// Build a new IP-VRF, normalizing the RT list (dedupe + sort).
    ///
    /// # Errors
    /// Returns [`IpVrfError::EmptyRouteTargets`] when `route_targets`
    /// is empty, [`IpVrfError::NonUnicastVtepIp`] when `local_vtep_ip`
    /// is unspecified / multicast / loopback,
    /// [`IpVrfError::InvalidRouterMac`] when `router_mac` is the
    /// all-zero MAC or a multicast MAC,
    /// [`IpVrfError::EmptyDeviceName`] when either device name is
    /// blank, and [`IpVrfError::InvalidTableId`] when `table_id` is 0.
    #[expect(
        clippy::too_many_arguments,
        reason = "every argument names an independent operator-supplied field; \
                  bundling them into a helper struct just to satisfy the lint \
                  would push the validation surface into a second hop without \
                  cutting any."
    )]
    pub fn new(
        name: String,
        id: IpVrfId,
        rd: RouteDistinguisher,
        route_targets: Vec<RouteTarget>,
        local_vtep_ip: IpAddr,
        router_mac: MacAddress,
        vrf_device: String,
        l3vxlan_device: String,
        table_id: u32,
    ) -> Result<Self, IpVrfError> {
        if route_targets.is_empty() {
            return Err(IpVrfError::EmptyRouteTargets { name });
        }
        if !is_unicast_vtep_ip(local_vtep_ip) {
            return Err(IpVrfError::NonUnicastVtepIp {
                name,
                ip: local_vtep_ip,
            });
        }
        if !is_valid_router_mac(router_mac) {
            return Err(IpVrfError::InvalidRouterMac { name });
        }
        if vrf_device.trim().is_empty() {
            return Err(IpVrfError::EmptyDeviceName {
                name,
                which: "vrf_device",
            });
        }
        if l3vxlan_device.trim().is_empty() {
            return Err(IpVrfError::EmptyDeviceName {
                name,
                which: "l3vxlan_device",
            });
        }
        if table_id == 0 {
            return Err(IpVrfError::InvalidTableId { name });
        }
        let mut rts = route_targets;
        rts.sort();
        rts.dedup();
        Ok(Self {
            name,
            id,
            rd,
            route_targets: rts,
            local_vtep_ip,
            router_mac,
            vrf_device,
            l3vxlan_device,
            table_id,
        })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum IpVrfError {
    #[error("evpn_ip_vrfs[{name}]: route_targets must not be empty")]
    EmptyRouteTargets { name: String },
    #[error(
        "evpn_ip_vrfs[{name}]: local_vtep_ip {ip} must be unicast (not unspecified / multicast / loopback)"
    )]
    NonUnicastVtepIp { name: String, ip: IpAddr },
    #[error("evpn_ip_vrfs[{name}]: router_mac must be a unicast non-zero MAC")]
    InvalidRouterMac { name: String },
    #[error("evpn_ip_vrfs[{name}]: {which} must not be empty")]
    EmptyDeviceName { name: String, which: &'static str },
    #[error("evpn_ip_vrfs[{name}]: table_id must be > 0")]
    InvalidTableId { name: String },
}

/// Resolved table of local IP-VRFs, with uniqueness enforced on
/// `(name)`, `(id)`, and `(table_id)`. Built once at config load (or
/// after each SIGHUP reconcile pass) and held by the supervisor.
///
/// `table_id` uniqueness matters for runtime correctness, not just
/// operator hygiene: the slice 6a route classifier
/// (`crates/evpn-linux/src/linux/routes.rs`) keys observations off
/// `RouteAttribute::Table(u32)`, so two VRFs sharing the same
/// `table_id` would misattribute every kernel route in that table to
/// whichever VRF won the `HashMap::insert` race. That cross-tenant
/// misattribution could leak a prefix under the wrong L3VNI / RD / RT
/// on the wire. Rejecting at config load keeps the runtime path
/// structurally safe.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct IpVrfTable {
    by_name: std::collections::BTreeMap<String, IpVrf>,
    by_id: std::collections::BTreeMap<IpVrfId, String>,
    /// `table_id` → operator-facing name. Built so route observations
    /// keyed on `RouteAttribute::Table` resolve to a single IP-VRF.
    by_table_id: std::collections::BTreeMap<u32, String>,
    /// Names of IP-VRFs that any `[[evpn_instances]]` entry referenced.
    /// Built incrementally so the config layer can validate without
    /// scanning the L2 table.
    referenced_names: BTreeSet<String>,
    /// IP-VRF name -> local L2VNIs that reference it through
    /// `[[evpn_instances]].ip_vrf`. Overlay-index Type 5 recursion
    /// uses this to constrain gateway Type 2 lookups to the tenant's
    /// own MAC-VRFs instead of guessing from a globally unique host IP.
    referenced_l2vnis: BTreeMap<String, BTreeSet<EvpnInstanceId>>,
}

impl IpVrfTable {
    /// Create an empty table.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert an IP-VRF, enforcing uniqueness on `name`, `id`, and
    /// `table_id`.
    ///
    /// # Errors
    /// Returns [`IpVrfTableError::DuplicateName`] /
    /// [`IpVrfTableError::DuplicateId`] /
    /// [`IpVrfTableError::DuplicateTableId`] when the respective
    /// key is already present.
    pub fn insert(&mut self, vrf: IpVrf) -> Result<(), IpVrfTableError> {
        if self.by_name.contains_key(&vrf.name) {
            return Err(IpVrfTableError::DuplicateName { name: vrf.name });
        }
        if let Some(existing) = self.by_id.get(&vrf.id) {
            return Err(IpVrfTableError::DuplicateId {
                vni: vrf.id.as_u32(),
                existing: existing.clone(),
                duplicate: vrf.name,
            });
        }
        if let Some(existing) = self.by_table_id.get(&vrf.table_id) {
            return Err(IpVrfTableError::DuplicateTableId {
                table_id: vrf.table_id,
                existing: existing.clone(),
                duplicate: vrf.name,
            });
        }
        self.by_id.insert(vrf.id, vrf.name.clone());
        self.by_table_id.insert(vrf.table_id, vrf.name.clone());
        self.by_name.insert(vrf.name.clone(), vrf);
        Ok(())
    }

    /// Look up an IP-VRF by operator-facing name.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&IpVrf> {
        self.by_name.get(name)
    }

    /// Whether any L2VNI has referenced this IP-VRF via
    /// `[[evpn_instances]].ip_vrf`. Surfaced by the config layer for
    /// emitting "declared but unused" warnings.
    #[must_use]
    pub fn is_referenced(&self, name: &str) -> bool {
        self.referenced_names.contains(name)
    }

    /// Return the local L2VNIs that reference this IP-VRF.
    #[must_use]
    pub fn referenced_l2vnis(&self, name: &str) -> Option<&BTreeSet<EvpnInstanceId>> {
        self.referenced_l2vnis.get(name)
    }

    /// Whether the L2VNI->IP-VRF link references differ from another table,
    /// independent of the IP-VRF rows themselves. An `ip_vrf` relink (an L2VNI
    /// re-homed to a different IP-VRF, or its link added/removed) mutates only
    /// this derived metadata, leaving every IP-VRF row identical — so the plan's
    /// row changesets stay empty and this is the only signal a relink happened.
    #[must_use]
    pub fn references_differ(&self, other: &Self) -> bool {
        self.referenced_names != other.referenced_names
            || self.referenced_l2vnis != other.referenced_l2vnis
    }

    /// Invert the reference metadata into a per-L2VNI link map (`VNI -> IP-VRF
    /// name`). Each L2VNI links to at most one IP-VRF (`[[evpn_instances]].ip_vrf`
    /// is a single name), so this is well-defined. Used to tell which specific
    /// L2VNIs were relinked between a committed model and a candidate.
    #[must_use]
    pub fn l2vni_link_map(&self) -> BTreeMap<EvpnInstanceId, String> {
        let mut map = BTreeMap::new();
        for (name, vnis) in &self.referenced_l2vnis {
            for vni in vnis {
                map.insert(*vni, name.clone());
            }
        }
        map
    }

    /// Mark an IP-VRF as referenced by one L2VNI. Idempotent.
    pub fn mark_referenced_by_l2vni(&mut self, name: String, vni: EvpnInstanceId) {
        self.referenced_names.insert(name.clone());
        self.referenced_l2vnis.entry(name).or_default().insert(vni);
    }

    /// Iterate the IP-VRFs in name order.
    pub fn iter(&self) -> impl Iterator<Item = &IpVrf> {
        self.by_name.values()
    }

    /// Count of declared IP-VRFs.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_name.len()
    }

    /// True when no IP-VRFs are declared (the common L2-only case).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_name.is_empty()
    }

    /// Iterate the L3VNIs in the table. Used by the config layer's
    /// L2/L3 VNI overlap check.
    pub fn vnis(&self) -> impl Iterator<Item = IpVrfId> + '_ {
        self.by_id.keys().copied()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum IpVrfTableError {
    #[error("evpn_ip_vrfs: duplicate name {name:?}")]
    DuplicateName { name: String },
    #[error("evpn_ip_vrfs: L3VNI {vni} declared twice ({existing:?} and {duplicate:?})")]
    DuplicateId {
        vni: u32,
        existing: String,
        duplicate: String,
    },
    #[error(
        "evpn_ip_vrfs: table_id {table_id} declared twice ({existing:?} and {duplicate:?}) — \
         each IP-VRF must own its own kernel route table or slice 6a route observations would \
         misattribute prefixes across tenants"
    )]
    DuplicateTableId {
        table_id: u32,
        existing: String,
        duplicate: String,
    },
}

fn is_unicast_vtep_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            !v4.is_unspecified() && !v4.is_multicast() && !v4.is_loopback() && !v4.is_broadcast()
        }
        IpAddr::V6(v6) => !v6.is_unspecified() && !v6.is_multicast() && !v6.is_loopback(),
    }
}

fn is_valid_router_mac(mac: MacAddress) -> bool {
    let bytes = mac.octets();
    if bytes.iter().all(|&b| b == 0) {
        return false;
    }
    // First octet's low bit is the I/G bit; 1 = multicast/group.
    // Router MAC must be unicast.
    (bytes[0] & 0x01) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rd() -> RouteDistinguisher {
        "65000:5000".parse().unwrap()
    }

    fn rt() -> RouteTarget {
        "65000:5000".parse().unwrap()
    }

    fn vtep() -> IpAddr {
        "10.0.0.1".parse().unwrap()
    }

    fn router_mac() -> MacAddress {
        MacAddress::new([0x02, 0x00, 0x00, 0x00, 0x00, 0x01])
    }

    #[test]
    fn id_rejects_zero_and_overflow() {
        assert!(IpVrfId::new(0).is_err());
        assert!(IpVrfId::new(0x0100_0000).is_err());
        assert_eq!(IpVrfId::new(5000).unwrap().as_u32(), 5000);
    }

    #[test]
    fn ip_vrf_normalizes_route_targets() {
        let a: RouteTarget = "65000:5000".parse().unwrap();
        let b: RouteTarget = "65000:5001".parse().unwrap();
        let vrf = IpVrf::new(
            "blue".to_string(),
            IpVrfId::new(5000).unwrap(),
            rd(),
            vec![b, a, b], // unsorted + duplicate
            vtep(),
            router_mac(),
            "vrf-blue".to_string(),
            "vni5000".to_string(),
            5000,
        )
        .unwrap();
        assert_eq!(vrf.route_targets, vec![a, b]);
    }

    #[test]
    fn rejects_empty_rt_list() {
        let err = IpVrf::new(
            "blue".to_string(),
            IpVrfId::new(5000).unwrap(),
            rd(),
            vec![],
            vtep(),
            router_mac(),
            "vrf-blue".to_string(),
            "vni5000".to_string(),
            5000,
        )
        .unwrap_err();
        assert!(matches!(err, IpVrfError::EmptyRouteTargets { .. }));
    }

    #[test]
    fn rejects_unspecified_vtep_ip() {
        let err = IpVrf::new(
            "blue".to_string(),
            IpVrfId::new(5000).unwrap(),
            rd(),
            vec![rt()],
            "0.0.0.0".parse().unwrap(),
            router_mac(),
            "vrf-blue".to_string(),
            "vni5000".to_string(),
            5000,
        )
        .unwrap_err();
        assert!(matches!(err, IpVrfError::NonUnicastVtepIp { .. }));
    }

    #[test]
    fn rejects_multicast_router_mac() {
        let multicast = MacAddress::new([0x01, 0x00, 0x5e, 0x00, 0x00, 0x01]);
        let err = IpVrf::new(
            "blue".to_string(),
            IpVrfId::new(5000).unwrap(),
            rd(),
            vec![rt()],
            vtep(),
            multicast,
            "vrf-blue".to_string(),
            "vni5000".to_string(),
            5000,
        )
        .unwrap_err();
        assert!(matches!(err, IpVrfError::InvalidRouterMac { .. }));
    }

    #[test]
    fn rejects_zero_router_mac() {
        let zero = MacAddress::new([0; 6]);
        let err = IpVrf::new(
            "blue".to_string(),
            IpVrfId::new(5000).unwrap(),
            rd(),
            vec![rt()],
            vtep(),
            zero,
            "vrf-blue".to_string(),
            "vni5000".to_string(),
            5000,
        )
        .unwrap_err();
        assert!(matches!(err, IpVrfError::InvalidRouterMac { .. }));
    }

    #[test]
    fn rejects_blank_vrf_device() {
        let err = IpVrf::new(
            "blue".to_string(),
            IpVrfId::new(5000).unwrap(),
            rd(),
            vec![rt()],
            vtep(),
            router_mac(),
            "  ".to_string(),
            "vni5000".to_string(),
            5000,
        )
        .unwrap_err();
        assert!(matches!(err, IpVrfError::EmptyDeviceName { which, .. } if which == "vrf_device"));
    }

    #[test]
    fn rejects_zero_table_id() {
        let err = IpVrf::new(
            "blue".to_string(),
            IpVrfId::new(5000).unwrap(),
            rd(),
            vec![rt()],
            vtep(),
            router_mac(),
            "vrf-blue".to_string(),
            "vni5000".to_string(),
            0,
        )
        .unwrap_err();
        assert!(matches!(err, IpVrfError::InvalidTableId { .. }));
    }

    #[test]
    fn table_rejects_duplicate_name() {
        let mut t = IpVrfTable::new();
        let a = IpVrf::new(
            "blue".to_string(),
            IpVrfId::new(5000).unwrap(),
            rd(),
            vec![rt()],
            vtep(),
            router_mac(),
            "vrf-blue".to_string(),
            "vni5000".to_string(),
            5000,
        )
        .unwrap();
        let b = IpVrf::new(
            "blue".to_string(),
            IpVrfId::new(5001).unwrap(),
            rd(),
            vec![rt()],
            vtep(),
            router_mac(),
            "vrf-blue-2".to_string(),
            "vni5001".to_string(),
            5001,
        )
        .unwrap();
        t.insert(a).unwrap();
        let err = t.insert(b).unwrap_err();
        assert!(matches!(err, IpVrfTableError::DuplicateName { .. }));
    }

    #[test]
    fn table_rejects_duplicate_id() {
        let mut t = IpVrfTable::new();
        let a = IpVrf::new(
            "blue".to_string(),
            IpVrfId::new(5000).unwrap(),
            rd(),
            vec![rt()],
            vtep(),
            router_mac(),
            "vrf-blue".to_string(),
            "vni5000".to_string(),
            5000,
        )
        .unwrap();
        let b = IpVrf::new(
            "red".to_string(),
            IpVrfId::new(5000).unwrap(),
            rd(),
            vec![rt()],
            vtep(),
            router_mac(),
            "vrf-red".to_string(),
            "vni5000-shadow".to_string(),
            5002,
        )
        .unwrap();
        t.insert(a).unwrap();
        let err = t.insert(b).unwrap_err();
        assert!(matches!(
            err,
            IpVrfTableError::DuplicateId { vni: 5000, .. }
        ));
    }

    /// Two IP-VRFs sharing the same `table_id` must be rejected at
    /// table-insert time. The slice 6a route classifier keys
    /// observations off `RouteAttribute::Table`, so a collision
    /// would silently misattribute kernel routes to whichever VRF
    /// won the `HashMap::insert` race — a potential cross-tenant
    /// leak. Catching at config load makes the runtime path
    /// structurally safe.
    #[test]
    fn rejects_duplicate_table_id() {
        let mut t = IpVrfTable::new();
        let a = IpVrf::new(
            "blue".to_string(),
            IpVrfId::new(5000).unwrap(),
            rd(),
            vec![rt()],
            vtep(),
            router_mac(),
            "vrf-blue".to_string(),
            "vni5000".to_string(),
            100,
        )
        .unwrap();
        let b = IpVrf::new(
            "red".to_string(),
            IpVrfId::new(6000).unwrap(),
            rd(),
            vec![rt()],
            vtep(),
            router_mac(),
            "vrf-red".to_string(),
            "vni6000".to_string(),
            100, // collision
        )
        .unwrap();
        t.insert(a).unwrap();
        let err = t.insert(b).unwrap_err();
        assert!(matches!(
            err,
            IpVrfTableError::DuplicateTableId { table_id: 100, .. }
        ));
    }
}
