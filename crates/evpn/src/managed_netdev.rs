//! Portable managed-netdev domain/status types (ADR-0091).
//!
//! The Linux implementation owns the netlink details. This module keeps the
//! daemon/API boundary kernel-free: desired bridge rows, derived ownership
//! stamps, and compact operator-facing status rows.

use std::collections::BTreeMap;
use std::net::IpAddr;

use crate::MacAddress;

/// Prefix used in rustbgpd-managed altname ownership stamps.
pub const MANAGED_NETDEV_STAMP_PREFIX: &str = "rustbgpd";
/// Maximum Linux altname byte length (`ALTIFNAMSIZ - 1`).
pub const MAX_ALT_IFNAME_LEN: usize = 127;
/// Maximum Linux ifname byte length (`IFNAMSIZ - 1`).
pub const MAX_IFNAME_LEN: usize = 15;
/// Maximum configured owner token length for ADR-0091 v1.
pub const MAX_OWNER_TOKEN_LEN: usize = 63;

/// Managed netdev class. ADR-0091 ships lifecycle support class by class:
/// bridge, fixed-VNI VXLAN, VRF, and L3VXLAN rows all have lifecycle support.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ManagedNetdevClass {
    /// Linux bridge device.
    Bridge,
    /// Traditional Linux VXLAN device with one fixed VNI.
    Vxlan,
    /// Linux VRF master device.
    Vrf,
    /// Linux L3 VXLAN device enslaved to a VRF.
    L3Vxlan,
}

impl ManagedNetdevClass {
    /// Stable lowercase label used in altnames and API output.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Bridge => "bridge",
            Self::Vxlan => "vxlan",
            Self::Vrf => "vrf",
            Self::L3Vxlan => "l3vxlan",
        }
    }
}

/// One configured bridge row in the managed-netdev table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedBridgeNetdev {
    /// Linux bridge name.
    pub name: String,
    /// Desired protected `vlan_filtering` value.
    pub vlan_filtering: bool,
    /// Derived durable ownership stamp.
    pub ownership_stamp: String,
}

/// Desired protected attributes for one managed fixed-VNI VXLAN.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedVxlanNetdevSpec {
    /// VXLAN VNI (`1..=16_777_215`).
    pub vni: u32,
    /// Local source IP for encapsulated packets.
    pub local_ip: IpAddr,
    /// UDP destination port.
    pub dstport: u16,
    /// Bridge this VXLAN must be enslaved to before it can satisfy EVPN
    /// readiness.
    pub bridge: String,
}

/// One configured fixed-VNI VXLAN row in the managed-netdev table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedVxlanNetdev {
    /// Linux VXLAN interface name.
    pub name: String,
    /// Desired protected attributes.
    pub spec: ManagedVxlanNetdevSpec,
    /// Derived durable ownership stamp.
    pub ownership_stamp: String,
}

/// Desired protected attributes for one managed Linux VRF.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedVrfNetdevSpec {
    /// Linux route-table id carried by `IFLA_VRF_TABLE`.
    pub table_id: u32,
}

/// One configured VRF row in the managed-netdev table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedVrfNetdev {
    /// Linux VRF interface name.
    pub name: String,
    /// Desired protected attributes.
    pub spec: ManagedVrfNetdevSpec,
    /// Derived durable ownership stamp.
    pub ownership_stamp: String,
}

/// Desired protected attributes for one managed L3 VXLAN.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedL3VxlanNetdevSpec {
    /// VXLAN VNI (`1..=16_777_215`).
    pub vni: u32,
    /// Local source IP for encapsulated packets.
    pub local_ip: IpAddr,
    /// UDP destination port.
    pub dstport: u16,
    /// VRF this L3 VXLAN must be enslaved to before it can satisfy IP-VRF
    /// readiness.
    pub vrf: String,
    /// Router MAC the L3 VXLAN link must carry.
    pub router_mac: MacAddress,
}

/// One configured L3 VXLAN row in the managed-netdev table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedL3VxlanNetdev {
    /// Linux L3 VXLAN interface name.
    pub name: String,
    /// Desired protected attributes.
    pub spec: ManagedL3VxlanNetdevSpec,
    /// Derived durable ownership stamp.
    pub ownership_stamp: String,
}

/// Resolved managed-netdev desired state.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ManagedNetdevTable {
    owner_token: Option<String>,
    bridges: BTreeMap<String, ManagedBridgeNetdev>,
    vxlans: BTreeMap<String, ManagedVxlanNetdev>,
    vrfs: BTreeMap<String, ManagedVrfNetdev>,
    l3vxlans: BTreeMap<String, ManagedL3VxlanNetdev>,
}

impl ManagedNetdevTable {
    /// Empty desired state.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Build a table from validated, already-unique bridge rows.
    #[must_use]
    pub fn from_bridge_map(owner_token: String, bridges: BTreeMap<String, bool>) -> Self {
        Self::from_maps(owner_token, bridges, BTreeMap::new())
    }

    /// Build a table from validated, already-unique bridge and VXLAN rows.
    #[must_use]
    pub fn from_maps(
        owner_token: String,
        bridges: BTreeMap<String, bool>,
        vxlans: BTreeMap<String, ManagedVxlanNetdevSpec>,
    ) -> Self {
        Self::from_all_maps(
            owner_token,
            bridges,
            vxlans,
            BTreeMap::new(),
            BTreeMap::new(),
        )
    }

    /// Build a table from validated, already-unique managed-netdev rows.
    #[must_use]
    pub fn from_all_maps(
        owner_token: String,
        bridges: BTreeMap<String, bool>,
        vxlans: BTreeMap<String, ManagedVxlanNetdevSpec>,
        vrfs: BTreeMap<String, ManagedVrfNetdevSpec>,
        l3vxlans: BTreeMap<String, ManagedL3VxlanNetdevSpec>,
    ) -> Self {
        let bridges = bridges
            .into_iter()
            .map(|(name, vlan_filtering)| {
                let ownership_stamp = bridge_ownership_stamp(&owner_token, &name);
                (
                    name.clone(),
                    ManagedBridgeNetdev {
                        name,
                        vlan_filtering,
                        ownership_stamp,
                    },
                )
            })
            .collect();
        let vxlans = vxlans
            .into_iter()
            .map(|(name, spec)| {
                let ownership_stamp = vxlan_ownership_stamp(&owner_token, &name);
                (
                    name.clone(),
                    ManagedVxlanNetdev {
                        name,
                        spec,
                        ownership_stamp,
                    },
                )
            })
            .collect();
        let vrfs = vrfs
            .into_iter()
            .map(|(name, spec)| {
                let ownership_stamp = vrf_ownership_stamp(&owner_token, &name);
                (
                    name.clone(),
                    ManagedVrfNetdev {
                        name,
                        spec,
                        ownership_stamp,
                    },
                )
            })
            .collect();
        let l3vxlans = l3vxlans
            .into_iter()
            .map(|(name, spec)| {
                let ownership_stamp = l3vxlan_ownership_stamp(&owner_token, &name);
                (
                    name.clone(),
                    ManagedL3VxlanNetdev {
                        name,
                        spec,
                        ownership_stamp,
                    },
                )
            })
            .collect();
        Self {
            owner_token: Some(owner_token),
            bridges,
            vxlans,
            vrfs,
            l3vxlans,
        }
    }

    /// Whether no managed-netdev intent is configured.
    ///
    /// An owner token without rows is still non-empty: it lets the
    /// dataplane actor reap rustbgpd-owned leftovers for that owner when
    /// the operator removes the last managed bridge row.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.owner_token.is_none()
            && self.bridges.is_empty()
            && self.vxlans.is_empty()
            && self.vrfs.is_empty()
            && self.l3vxlans.is_empty()
    }

    /// Owner token when `[managed_netdevs]` is configured.
    #[must_use]
    pub fn owner_token(&self) -> Option<&str> {
        self.owner_token.as_deref()
    }

    /// Desired bridge rows in deterministic name order.
    pub fn bridges(&self) -> impl Iterator<Item = &ManagedBridgeNetdev> {
        self.bridges.values()
    }

    /// Find one desired bridge by name.
    #[must_use]
    pub fn bridge(&self, name: &str) -> Option<&ManagedBridgeNetdev> {
        self.bridges.get(name)
    }

    /// Desired fixed-VNI VXLAN rows in deterministic name order.
    pub fn vxlans(&self) -> impl Iterator<Item = &ManagedVxlanNetdev> {
        self.vxlans.values()
    }

    /// Find one desired fixed-VNI VXLAN by name.
    #[must_use]
    pub fn vxlan(&self, name: &str) -> Option<&ManagedVxlanNetdev> {
        self.vxlans.get(name)
    }

    /// Desired VRF rows in deterministic name order.
    pub fn vrfs(&self) -> impl Iterator<Item = &ManagedVrfNetdev> {
        self.vrfs.values()
    }

    /// Find one desired VRF by name.
    #[must_use]
    pub fn vrf(&self, name: &str) -> Option<&ManagedVrfNetdev> {
        self.vrfs.get(name)
    }

    /// Desired L3 VXLAN rows in deterministic name order.
    pub fn l3vxlans(&self) -> impl Iterator<Item = &ManagedL3VxlanNetdev> {
        self.l3vxlans.values()
    }

    /// Find one desired L3 VXLAN by name.
    #[must_use]
    pub fn l3vxlan(&self, name: &str) -> Option<&ManagedL3VxlanNetdev> {
        self.l3vxlans.get(name)
    }
}

/// Derived bridge ownership stamp.
#[must_use]
pub fn bridge_ownership_stamp(owner_token: &str, bridge_name: &str) -> String {
    format!(
        "{MANAGED_NETDEV_STAMP_PREFIX}:{}:{owner_token}:{bridge_name}",
        ManagedNetdevClass::Bridge.as_str()
    )
}

/// Derived fixed-VNI VXLAN ownership stamp.
#[must_use]
pub fn vxlan_ownership_stamp(owner_token: &str, vxlan_name: &str) -> String {
    format!(
        "{MANAGED_NETDEV_STAMP_PREFIX}:{}:{owner_token}:{vxlan_name}",
        ManagedNetdevClass::Vxlan.as_str()
    )
}

/// Derived VRF ownership stamp.
#[must_use]
pub fn vrf_ownership_stamp(owner_token: &str, vrf_name: &str) -> String {
    format!(
        "{MANAGED_NETDEV_STAMP_PREFIX}:{}:{owner_token}:{vrf_name}",
        ManagedNetdevClass::Vrf.as_str()
    )
}

/// Derived L3 VXLAN ownership stamp.
#[must_use]
pub fn l3vxlan_ownership_stamp(owner_token: &str, l3vxlan_name: &str) -> String {
    format!(
        "{MANAGED_NETDEV_STAMP_PREFIX}:{}:{owner_token}:{l3vxlan_name}",
        ManagedNetdevClass::L3Vxlan.as_str()
    )
}

/// Parsed rustbgpd ownership stamp from a link altname.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedNetdevStamp {
    /// Original altname.
    pub raw: String,
    /// Managed class encoded in the stamp.
    pub class: ManagedNetdevClass,
    /// Owner token encoded in the stamp.
    pub owner_token: String,
    /// Link name encoded in the stamp.
    pub name: String,
}

/// Parse a rustbgpd ownership stamp. Returns `None` for unrelated altnames.
#[must_use]
pub fn parse_ownership_stamp(raw: &str) -> Option<ManagedNetdevStamp> {
    let mut parts = raw.split(':');
    let prefix = parts.next()?;
    if prefix != MANAGED_NETDEV_STAMP_PREFIX {
        return None;
    }
    let class = match parts.next()? {
        "bridge" => ManagedNetdevClass::Bridge,
        "vxlan" => ManagedNetdevClass::Vxlan,
        "vrf" => ManagedNetdevClass::Vrf,
        "l3vxlan" => ManagedNetdevClass::L3Vxlan,
        _ => return None,
    };
    let owner_token = parts.next()?;
    let name = parts.next()?;
    if parts.next().is_some() || owner_token.is_empty() || name.is_empty() {
        return None;
    }
    Some(ManagedNetdevStamp {
        raw: raw.to_string(),
        class,
        owner_token: owner_token.to_string(),
        name: name.to_string(),
    })
}

/// Coarse status for one desired or observed managed netdev.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManagedNetdevState {
    /// No live dataplane status has been published yet.
    Unknown,
    /// Configured row is absent from the current kernel snapshot.
    DesiredAbsent,
    /// Exact stamp, expected kind, and protected attributes all match.
    OwnedSafe,
    /// A same-name device exists but lacks the expected ownership stamp.
    ForeignPresent,
    /// A rustbgpd-stamped row exists but does not match the configured owner,
    /// class, name, or protected attributes.
    OwnedUnsafe,
    /// A rustbgpd-stamped row exists with no corresponding desired config.
    Orphaned,
}

impl ManagedNetdevState {
    /// Stable lowercase label for API/CLI output.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::DesiredAbsent => "desired-absent",
            Self::OwnedSafe => "owned-safe",
            Self::ForeignPresent => "foreign-present",
            Self::OwnedUnsafe => "owned-unsafe",
            Self::Orphaned => "orphaned",
        }
    }
}

/// Operator-facing status row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedNetdevStatus {
    /// Netdev class.
    pub class: ManagedNetdevClass,
    /// Link name.
    pub name: String,
    /// Whether this row is present in desired config.
    pub desired: bool,
    /// Desired ownership stamp, when configured.
    pub ownership_stamp: Option<String>,
    /// Current status.
    pub state: ManagedNetdevState,
    /// Operator-facing reason. Empty for the happy path.
    pub reason: String,
    /// Observed kernel ifindex when present.
    pub ifindex: Option<u32>,
    /// Observed protected `vlan_filtering` value for bridge rows.
    pub observed_vlan_filtering: Option<bool>,
    /// Observed fixed VNI for VXLAN rows.
    pub observed_vni: Option<u32>,
    /// Observed local source IP for VXLAN rows.
    pub observed_local_ip: Option<IpAddr>,
    /// Observed UDP destination port for VXLAN rows.
    pub observed_dstport: Option<u16>,
    /// Observed inverted VXLAN learning state. `Some(true)` means
    /// `nolearning`; `None` means the kernel did not report the attribute.
    pub observed_learning_disabled: Option<bool>,
    /// Observed collect-metadata / external mode for VXLAN rows.
    pub observed_collect_metadata: Option<bool>,
    /// Observed VNI filter mode for VXLAN rows.
    pub observed_vnifilter: Option<bool>,
    /// Observed bridge master for VXLAN rows.
    pub observed_bridge: Option<String>,
    /// Observed VRF table id for VRF rows.
    pub observed_table_id: Option<u32>,
    /// Observed administrative link-up state for VRF and L3VXLAN rows.
    pub observed_up: Option<bool>,
    /// Observed master device for L3VXLAN rows.
    pub observed_master: Option<String>,
    /// Observed Router MAC / link-layer address for L3VXLAN rows.
    pub observed_router_mac: Option<MacAddress>,
    /// Observed rustbgpd ownership stamps on the link.
    pub observed_stamps: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bridge_stamp_round_trips() {
        let stamp = bridge_ownership_stamp("leaf-1", "br100");
        assert_eq!(stamp, "rustbgpd:bridge:leaf-1:br100");
        let parsed = parse_ownership_stamp(&stamp).unwrap();
        assert_eq!(parsed.class, ManagedNetdevClass::Bridge);
        assert_eq!(parsed.owner_token, "leaf-1");
        assert_eq!(parsed.name, "br100");
    }

    #[test]
    fn vxlan_stamp_round_trips() {
        let stamp = vxlan_ownership_stamp("leaf-1", "vxlan100");
        assert_eq!(stamp, "rustbgpd:vxlan:leaf-1:vxlan100");
        let parsed = parse_ownership_stamp(&stamp).unwrap();
        assert_eq!(parsed.class, ManagedNetdevClass::Vxlan);
        assert_eq!(parsed.owner_token, "leaf-1");
        assert_eq!(parsed.name, "vxlan100");
    }

    #[test]
    fn vrf_and_l3vxlan_stamps_round_trip() {
        let vrf = vrf_ownership_stamp("leaf-1", "vrf100");
        assert_eq!(vrf, "rustbgpd:vrf:leaf-1:vrf100");
        let parsed = parse_ownership_stamp(&vrf).unwrap();
        assert_eq!(parsed.class, ManagedNetdevClass::Vrf);
        assert_eq!(parsed.owner_token, "leaf-1");
        assert_eq!(parsed.name, "vrf100");

        let l3vxlan = l3vxlan_ownership_stamp("leaf-1", "l3vxlan100");
        assert_eq!(l3vxlan, "rustbgpd:l3vxlan:leaf-1:l3vxlan100");
        let parsed = parse_ownership_stamp(&l3vxlan).unwrap();
        assert_eq!(parsed.class, ManagedNetdevClass::L3Vxlan);
        assert_eq!(parsed.owner_token, "leaf-1");
        assert_eq!(parsed.name, "l3vxlan100");
    }

    #[test]
    fn parse_ownership_stamp_ignores_unrelated_or_malformed_altnames() {
        assert!(parse_ownership_stamp("operator:bridge:leaf-1:br100").is_none());
        assert!(parse_ownership_stamp("rustbgpd:bridge:leaf-1").is_none());
        assert!(parse_ownership_stamp("rustbgpd:bridge:leaf-1:br100:extra").is_none());
    }
}
