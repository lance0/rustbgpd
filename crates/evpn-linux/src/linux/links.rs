//! Bridge + VXLAN link inventory via `rtnetlink::LinkHandle::get`.
//!
//! Walks every netlink-reported link, filters to bridges and VXLAN
//! ports, and indexes them so the per-instance probe can resolve a
//! bridge name to ifindex / VLAN-aware state / attached VXLAN
//! attributes (VNI, local IP, learning mode) without re-querying.
//!
//! ADR-0054 §3 narrows what this module surfaces: bridge VLAN
//! filtering state, VXLAN VNI / local IP / learning, and the link
//! membership relationships. Statistics, MTU, neighbor tables, etc.
//! are out of scope.

use std::collections::{HashMap, HashSet, hash_map::Entry};
use std::net::IpAddr;

use futures::stream::TryStreamExt;
use netlink_packet_route::AddressFamily;
use netlink_packet_route::link::{
    AfSpecBridge, BridgeVlanInfo, BridgeVlanInfoFlags, BridgeVlanTunnelInfo, InfoBridge,
    InfoBridgePort, InfoData, InfoKind, InfoPortData, InfoVlan, InfoVxlan, LinkAttribute,
    LinkExtentMask, LinkInfo, LinkMessage, Prop,
};
use rtnetlink::Handle;

use rustbgpd_evpn::{EvpnInstanceId, EvpnInstanceTable, MacAddress};

use crate::error::DataplaneError;
use crate::snapshot::{
    KernelBridgePortVlanInfo, KernelBridgeVlanFlags, KernelBridgeVlanInfo,
    KernelBridgeVlanTunnelInfo, KernelSvdVxlanInfo, KernelVxlanInfo, vlan_rows_contain,
};

/// One bridge link the inventory cared about.
#[derive(Debug, Clone, Default)]
pub(crate) struct BridgeLink {
    /// Kernel ifindex of the bridge. Used by the `RTNLGRP_LINK`
    /// reconcile-wake classifier (`notify::classify_link_event`) to
    /// recognize changes on — or enslavements to — a managed bridge.
    pub ifindex: u32,
    /// Bridge link-layer (MAC) address, when the kernel reports one.
    /// Captured for SVI-MAC origination (RFC 9135 §6.1) — the daemon
    /// surfaces this on `InstanceDataplaneStatus.bridge_mac` so the
    /// SVI task can originate Type 2 routes for the bridge's own
    /// address without reaching back into this internal cache.
    pub mac: Option<MacAddress>,
    /// Linux alternative interface names observed on the bridge.
    pub altnames: Vec<String>,
    /// `true` when the bridge has `vlan_filtering=1`. Legacy instances
    /// still reject this shape; ADR-0089 instances with `bridge_vlan`
    /// validate the bridge/VXLAN VLAN inventory before reporting Ready.
    pub vlan_filtering: bool,
    /// VXLAN port attached to this bridge whose VNI matches the
    /// instance, if exactly one exists. `None` indicates either no
    /// VXLAN port or multiple competing ports — `probe` reports the
    /// instance `NotReady` in that case. The presence of multiple
    /// ports is detected by [`vxlan_attach_count`], not by
    /// [`Option<KernelVxlanInfo>`] alone.
    pub vxlan: Option<KernelVxlanInfo>,
    /// Every VXLAN member attached to this bridge. Legacy
    /// VLAN-unaware readiness still uses [`Self::vxlan`] plus
    /// [`Self::vxlan_attach_count`] to require exactly one VXLAN
    /// port; ADR-0089 VLAN-aware readiness selects the member whose
    /// VNI matches the instance and then verifies VLAN membership on
    /// that specific port.
    pub vxlan_ports: Vec<KernelVxlanInfo>,
    /// Collect-metadata / SVD VXLAN members attached to this bridge.
    /// These can become Ready for `bridge_vlan` instances only when
    /// the bridge VLAN tunnel inventory maps the configured VLAN to
    /// the instance VNI unambiguously; runtime FDB programming then
    /// targets this shared ifindex with an explicit `NDA_SRC_VNI`.
    pub svd_vxlan_ports: Vec<KernelSvdVxlanInfo>,
    /// Number of VXLAN ports attached to this bridge. Legacy
    /// VLAN-unaware readiness still requires exactly one; ADR-0089
    /// VLAN-aware readiness allows multiple VXLAN ports on a bridge
    /// when each configured VNI has exactly one matching VLAN member.
    pub vxlan_attach_count: u32,
    /// Non-VXLAN bridge-member ifindexes. These are CE-facing
    /// candidates for Gate 8b BUM enforcement.
    pub ce_port_ifindexes: Vec<u32>,
    /// VLAN membership observed on the bridge device itself.
    pub vlans: Vec<KernelBridgeVlanInfo>,
    /// VLAN tunnel mappings observed on the bridge device itself.
    pub vlan_tunnels: Vec<KernelBridgeVlanTunnelInfo>,
    /// VLAN membership/tunnel inventory for each bridge member that has at
    /// least one VLAN or tunnel row (members with neither are omitted),
    /// including VXLAN members. Read-only ADR-0088 substrate.
    pub port_vlan_inventory: Vec<KernelBridgePortVlanInfo>,
}

/// Per-VXLAN port slice, before being attached to a bridge.
#[derive(Debug, Clone)]
enum VxlanPort {
    Fixed(FixedVxlanPort),
    Svd(SvdVxlanPort),
}

/// Per fixed-VNI VXLAN port slice, before being attached to a bridge.
#[derive(Debug, Clone)]
struct FixedVxlanPort {
    /// Bridge-master ifindex this VXLAN port slaves to (`IFLA_MASTER`
    /// in netlink terms; we read it from the Controller attribute on
    /// the link message). `None` means the VXLAN device is unparented
    /// and unusable for EVPN.
    master: Option<u32>,
    info: KernelVxlanInfo,
}

/// Per collect-metadata VXLAN port slice, before being attached to a bridge.
#[derive(Debug, Clone)]
struct SvdVxlanPort {
    /// Bridge-master ifindex this VXLAN port slaves to.
    master: Option<u32>,
    info: KernelSvdVxlanInfo,
}

/// VLAN upper device (`br0.10`) before config-driven attribution.
#[derive(Debug, Clone, Copy)]
struct VlanUpperLink {
    ifindex: u32,
    lower_ifindex: u32,
    vlan: u16,
}

/// Result of one link inventory pass. Built fresh on every dump and
/// stored on the [`crate::LinuxDataplane`] so probe + diff see
/// consistent state.
#[derive(Debug, Clone, Default)]
pub(crate) struct LinkCache {
    /// Every link name reported by the kernel in this dump, regardless
    /// of link kind. Managed-netdev status and lifecycle code use this
    /// to distinguish "bridge is absent" from "the desired bridge name
    /// is already occupied by a non-bridge link."
    pub all_link_names: HashSet<String>,
    /// Bridges by name. Empty if no bridges exist on the host.
    pub bridges: HashMap<String, BridgeLink>,
    /// VXLAN ifindex -> EVPN VNI back-reference. Populated alongside
    /// the bridge inventory so the FDB dump can derive the VNI of an
    /// FDB entry from `msg.header.ifindex` (which is the *VXLAN*
    /// ifindex for bridge FDB entries, not the bridge itself).
    pub vxlan_ifindex_to_vni: HashMap<u32, u32>,
    /// Collect-metadata VXLAN ifindexes. These do not imply one VNI per
    /// ifindex; FDB parsing uses an explicit `NDA_VNI` / `NDA_SRC_VNI`
    /// attribute for rows on these ports.
    pub svd_vxlan_ifindexes: HashSet<u32>,
    /// **Non-VXLAN** bridge port ifindex -> VNI of the bridge it is
    /// enslaved to. Populated by walking every link's Controller
    /// attribute against the known bridge inventory. Used by the
    /// `RTNLGRP_NEIGH` subscriber to classify a local-MAC observation
    /// (bridge fdb on a real port) into the right `EvpnInstanceId`.
    /// VXLAN ports are intentionally excluded — those carry remote
    /// MACs reached via VXLAN, not local kernel learns.
    pub bridge_port_to_vni: HashMap<u32, u32>,
    /// Configured `(bridge_name, bridge_vlan) -> VNI` bindings used to
    /// rebuild the VLAN-aware local-MAC attribution maps after a fresh
    /// link dump. `None` means the config attempted an ambiguous duplicate
    /// binding and must fail closed for observation purposes.
    pub local_mac_vlan_bindings: HashMap<(String, u16), Option<u32>>,
    /// VLAN-aware non-VXLAN bridge-port attribution:
    /// `(port_ifindex, bridge_vlan) -> VNI`. Populated only from
    /// configured `bridge_vlan` instances whose observed topology has
    /// exactly one matching VXLAN member carrying the same VLAN.
    pub bridge_port_vlan_to_vni: HashMap<(u32, u16), u32>,
    /// Non-VXLAN bridge ports on bridges with at least one configured
    /// `bridge_vlan` binding. These ports must never fall back to legacy
    /// ifindex-only classification; if the VLAN-specific map has no entry,
    /// observation fails closed.
    pub bridge_ports_requiring_vlan_attribution: HashSet<u32>,
    /// Observed VLAN upper devices keyed by `(lower_bridge_ifindex, VLAN)`.
    /// `None` means duplicate uppers were observed for the same lower/VLAN
    /// pair, so MAC+IP attribution must fail closed for that pair.
    pub(crate) vlan_upper_links: HashMap<(u32, u16), Option<u32>>,
    /// `AF_INET` / `AF_INET6` neighbour attribution for VLAN upper devices:
    /// `vlan_upper_ifindex -> VNI`. Populated only after the configured
    /// `bridge_vlan` binding and observed bridge/VXLAN VLAN membership agree.
    pub ip_neighbour_vlan_upper_to_vni: HashMap<u32, u32>,
    /// VLAN-aware VXLAN-port attribution for remote-takeover echoes:
    /// `(vxlan_ifindex, bridge_vlan) -> VNI`. This prevents a remote row
    /// in one bridge VLAN from withdrawing a local claim in another VNI.
    pub vxlan_port_vlan_to_vni: HashMap<(u32, u16), u32>,
    /// VXLAN ports on bridges with at least one configured `bridge_vlan`
    /// binding. Mirrors `bridge_ports_requiring_vlan_attribution` for
    /// remote-takeover echo classification.
    pub vxlan_ports_requiring_vlan_attribution: HashSet<u32>,
    /// Non-VXLAN ports of **any** known bridge, by link name, with
    /// the observed `IFLA_BRPORT_STATE` from the port's
    /// `IFLA_INFO_PORT_DATA` slave info. Unlike `bridge_port_to_vni`
    /// this map does NOT require the bridge to have a resolved VNI —
    /// the AC-gate resolver must find a bound AC even while the
    /// bridge topology is otherwise `NotReady` (e.g. mid-bring-up),
    /// so a non-DF port is never silently left forwarding.
    pub bridge_ports_by_name: HashMap<String, crate::snapshot::KernelBridgePortInfo>,
}

/// Kernel target for programming one remote-MAC FDB row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct FdbVxlanTarget {
    /// VXLAN device ifindex to use as `ndm_ifindex`.
    pub ifindex: u32,
    /// Explicit `NDA_SRC_VNI` required by collect-metadata / SVD
    /// VXLAN devices. `None` means a traditional fixed-VNI VXLAN
    /// device where the ifindex itself identifies the VNI.
    pub source_vni: Option<EvpnInstanceId>,
    /// Observed VXLAN learning state for the CVE-2025-39851 guard.
    pub learning_disabled: Option<bool>,
}

fn find_unique_vxlan_for_vni(
    cache: &LinkCache,
    vni: EvpnInstanceId,
) -> Result<Option<&KernelVxlanInfo>, DataplaneError> {
    let raw = vni.as_u32();
    let mut found = None;

    for bridge in cache.bridges.values() {
        if bridge.vxlan_ports.is_empty() {
            if let Some(vxlan) = bridge.vxlan.as_ref().filter(|vxlan| vxlan.vni == raw) {
                record_vxlan_match(&mut found, vxlan, vni)?;
            }
            continue;
        }
        for vxlan in bridge.vxlan_ports.iter().filter(|vxlan| vxlan.vni == raw) {
            record_vxlan_match(&mut found, vxlan, vni)?;
        }
    }

    Ok(found)
}

/// Resolve the kernel FDB programming target for `vni`.
///
/// Traditional fixed-VNI VXLAN devices are selected by their configured
/// VNI. SVD / collect-metadata VXLAN devices are selected only through
/// explicit `bridge_vlan` configuration plus bridge VLAN tunnel
/// inventory. If both shapes match, or if multiple SVD ports match, the
/// topology is ambiguous and programming fails closed.
pub(crate) fn unique_fdb_vxlan_target_for_vni(
    cache: &LinkCache,
    vni: EvpnInstanceId,
) -> Result<FdbVxlanTarget, DataplaneError> {
    let fixed = find_unique_vxlan_for_vni(cache, vni)?;
    let svd = find_unique_svd_vxlan_target_for_vni(cache, vni)?;

    match (fixed, svd) {
        (
            Some(fixed),
            Some(SvdVxlanTarget {
                ifindex: svd_ifindex,
                ..
            }),
        ) if fixed.ifindex != svd_ifindex => Err(DataplaneError::InvalidArgument(format!(
            "ambiguous VXLAN target for VNI {vni}: fixed-VNI ifindex {} and SVD ifindex {svd_ifindex} both match",
            fixed.ifindex
        ))),
        (Some(fixed), _) => Ok(FdbVxlanTarget {
            ifindex: fixed.ifindex,
            source_vni: None,
            learning_disabled: fixed.learning_disabled,
        }),
        (None, Some(svd)) => Ok(FdbVxlanTarget {
            ifindex: svd.ifindex,
            source_vni: Some(vni),
            learning_disabled: svd.learning_disabled,
        }),
        (None, None) => Err(DataplaneError::LinkNotFound {
            name: format!("VXLAN target for VNI {vni}"),
        }),
    }
}

fn record_vxlan_match<'a>(
    found: &mut Option<&'a KernelVxlanInfo>,
    candidate: &'a KernelVxlanInfo,
    vni: EvpnInstanceId,
) -> Result<(), DataplaneError> {
    match *found {
        None => {
            *found = Some(candidate);
            Ok(())
        }
        Some(existing) if existing.ifindex == candidate.ifindex => Ok(()),
        Some(existing) => Err(DataplaneError::InvalidArgument(format!(
            "ambiguous VXLAN port for VNI {vni}: ifindexes {} and {} both match",
            existing.ifindex, candidate.ifindex
        ))),
    }
}

#[derive(Debug, Clone, Copy)]
struct SvdVxlanTarget {
    ifindex: u32,
    learning_disabled: Option<bool>,
}

fn find_unique_svd_vxlan_target_for_vni(
    cache: &LinkCache,
    vni: EvpnInstanceId,
) -> Result<Option<SvdVxlanTarget>, DataplaneError> {
    let raw = vni.as_u32();
    let mut found = None;
    for ((bridge_name, bridge_vlan), bound_vni) in &cache.local_mac_vlan_bindings {
        if *bound_vni != Some(raw) {
            continue;
        }
        let Some(bridge) = cache.bridges.get(bridge_name) else {
            continue;
        };
        if !bridge.vlan_filtering || !vlan_rows_contain(&bridge.vlans, *bridge_vlan) {
            continue;
        }
        for svd in matching_svd_vxlan_ports(bridge, *bridge_vlan, raw) {
            let candidate = SvdVxlanTarget {
                ifindex: svd.ifindex,
                learning_disabled: svd.learning_disabled,
            };
            record_svd_match(&mut found, candidate, vni)?;
        }
    }
    Ok(found)
}

fn record_svd_match(
    found: &mut Option<SvdVxlanTarget>,
    candidate: SvdVxlanTarget,
    vni: EvpnInstanceId,
) -> Result<(), DataplaneError> {
    match *found {
        None => {
            *found = Some(candidate);
            Ok(())
        }
        Some(existing) if existing.ifindex == candidate.ifindex => Ok(()),
        Some(existing) => Err(DataplaneError::InvalidArgument(format!(
            "ambiguous SVD VXLAN target for VNI {vni}: ifindexes {} and {} both match",
            existing.ifindex, candidate.ifindex
        ))),
    }
}

/// SVD / collect-metadata VXLAN ports whose bridge VLAN tunnel
/// inventory maps `bridge_vlan` to `want_vni`.
pub(crate) fn matching_svd_vxlan_ports(
    bridge: &BridgeLink,
    bridge_vlan: u16,
    want_vni: u32,
) -> Vec<&KernelSvdVxlanInfo> {
    bridge
        .svd_vxlan_ports
        .iter()
        .filter(|svd| {
            bridge
                .port_vlan_inventory
                .iter()
                .any(|row| svd_inventory_matches(row, svd, bridge_vlan, want_vni))
        })
        .collect()
}

/// Return whether one bridge-member VLAN row proves that `svd`
/// carries `bridge_vlan` with tunnel ID / VNI `want_vni`.
pub(crate) fn svd_inventory_matches(
    row: &KernelBridgePortVlanInfo,
    svd: &KernelSvdVxlanInfo,
    bridge_vlan: u16,
    want_vni: u32,
) -> bool {
    row.is_vxlan
        && row.ifindex == svd.ifindex
        && vlan_rows_contain(&row.vlans, bridge_vlan)
        && row
            .vlan_tunnels
            .iter()
            .any(|t| t.vid == Some(bridge_vlan) && t.tunnel_id == Some(want_vni))
}

impl LinkCache {
    /// Rebuild VLAN-aware local-MAC attribution from the configured EVPN
    /// instances. The raw link inventory is intentionally not enough:
    /// a Linux port may carry default or extra VLANs that rustbgpd did
    /// not bind to an L2VNI. Only explicit `bridge_vlan` config creates
    /// an observation map entry.
    pub(crate) fn bind_local_mac_vlan_attribution(&mut self, instances: &EvpnInstanceTable) {
        self.local_mac_vlan_bindings.clear();
        for inst in instances.iter() {
            let (Some(bridge), Some(bridge_vlan)) = (&inst.bridge, inst.bridge_vlan) else {
                continue;
            };
            insert_unique_binding(
                &mut self.local_mac_vlan_bindings,
                (bridge.clone(), bridge_vlan.as_u16()),
                inst.id.as_u32(),
            );
        }
        self.rebuild_local_mac_vlan_attribution();
    }

    /// Carry the last configured bindings across a fresh link dump.
    pub(crate) fn inherit_local_mac_vlan_attribution_from(&mut self, previous: &Self) {
        self.local_mac_vlan_bindings
            .clone_from(&previous.local_mac_vlan_bindings);
        self.rebuild_local_mac_vlan_attribution();
    }

    fn rebuild_local_mac_vlan_attribution(&mut self) {
        let mut bridge_port_vlan_to_vni = HashMap::new();
        let mut vxlan_port_vlan_to_vni = HashMap::new();
        let mut ip_neighbour_vlan_upper_to_vni = HashMap::new();
        let mut bridge_ports_requiring_vlan_attribution = HashSet::new();
        let mut vxlan_ports_requiring_vlan_attribution = HashSet::new();
        for ((bridge_name, vlan), vni) in &self.local_mac_vlan_bindings {
            let Some(bridge) = self.bridges.get(bridge_name) else {
                continue;
            };
            for port in &bridge.port_vlan_inventory {
                if port.is_vxlan {
                    vxlan_ports_requiring_vlan_attribution.insert(port.ifindex);
                } else {
                    bridge_ports_requiring_vlan_attribution.insert(port.ifindex);
                }
            }
            for ifindex in &bridge.ce_port_ifindexes {
                bridge_ports_requiring_vlan_attribution.insert(*ifindex);
            }
            for vxlan in &bridge.vxlan_ports {
                vxlan_ports_requiring_vlan_attribution.insert(vxlan.ifindex);
            }
            let Some(vni) = *vni else {
                continue;
            };
            if !bridge.vlan_filtering || !vlan_rows_contain(&bridge.vlans, *vlan) {
                continue;
            }
            let mut vxlan_ifindex = None;
            let matching_vxlan: Vec<_> = bridge
                .vxlan_ports
                .iter()
                .filter(|port| port.vni == vni)
                .collect();
            if let [vxlan] = matching_vxlan.as_slice()
                && let Some(vxlan_inventory) = bridge
                    .port_vlan_inventory
                    .iter()
                    .find(|row| row.is_vxlan && row.ifindex == vxlan.ifindex)
                && vlan_rows_contain(&vxlan_inventory.vlans, *vlan)
            {
                vxlan_ifindex = Some(vxlan.ifindex);
            }
            let matching_svd = matching_svd_vxlan_ports(bridge, *vlan, vni);
            if let [svd] = matching_svd.as_slice() {
                if vxlan_ifindex.is_some() {
                    continue;
                }
                vxlan_ifindex = Some(svd.ifindex);
            }
            let Some(vxlan_ifindex) = vxlan_ifindex else {
                continue;
            };
            vxlan_port_vlan_to_vni.insert((vxlan_ifindex, *vlan), vni);
            if let Some(Some(vlan_upper_ifindex)) =
                self.vlan_upper_links.get(&(bridge.ifindex, *vlan))
            {
                ip_neighbour_vlan_upper_to_vni.insert(*vlan_upper_ifindex, vni);
            }
            for row in &bridge.port_vlan_inventory {
                if row.is_vxlan || !vlan_rows_contain(&row.vlans, *vlan) {
                    continue;
                }
                bridge_port_vlan_to_vni.insert((row.ifindex, *vlan), vni);
            }
        }
        self.bridge_port_vlan_to_vni = bridge_port_vlan_to_vni;
        self.bridge_ports_requiring_vlan_attribution = bridge_ports_requiring_vlan_attribution;
        self.ip_neighbour_vlan_upper_to_vni = ip_neighbour_vlan_upper_to_vni;
        self.vxlan_port_vlan_to_vni = vxlan_port_vlan_to_vni;
        self.vxlan_ports_requiring_vlan_attribution = vxlan_ports_requiring_vlan_attribution;
    }
}

fn insert_unique_binding(
    bindings: &mut HashMap<(String, u16), Option<u32>>,
    key: (String, u16),
    vni: u32,
) {
    match bindings.entry(key) {
        Entry::Vacant(entry) => {
            entry.insert(Some(vni));
        }
        Entry::Occupied(mut entry) => {
            if *entry.get() != Some(vni) {
                entry.insert(None);
            }
        }
    }
}

fn insert_unique_ifindex_binding(
    bindings: &mut HashMap<(u32, u16), Option<u32>>,
    key: (u32, u16),
    ifindex: u32,
) {
    match bindings.entry(key) {
        Entry::Vacant(entry) => {
            entry.insert(Some(ifindex));
        }
        Entry::Occupied(mut entry) => {
            if *entry.get() != Some(ifindex) {
                entry.insert(None);
            }
        }
    }
}

type BridgeVlanInventory =
    HashMap<u32, (Vec<KernelBridgeVlanInfo>, Vec<KernelBridgeVlanTunnelInfo>)>;

async fn dump_bridge_vlan_inventory_optional(handle: &Handle) -> BridgeVlanInventory {
    match dump_bridge_vlan_inventory(handle).await {
        Ok(inventory) => inventory,
        Err(e) => {
            // Best-effort: a kernel that refuses the extension mask (or any
            // dump error) leaves us with no VLAN-aware substrate this pass,
            // which is the fail-closed default. Log so an unexpected refusal
            // is still diagnosable rather than silently invisible.
            tracing::debug!(error = %e, "bridge VLAN inventory dump unavailable; continuing without VLAN-aware substrate");
            BridgeVlanInventory::default()
        }
    }
}

/// Walk every netlink-reported link and build the inventory cache.
///
/// Two-pass: pass 1 captures bridges with their VLAN-filtering state;
/// pass 2 captures VXLAN ports and stitches them onto their master
/// bridge. Two passes are necessary because the link list is
/// kernel-ordered and a VXLAN port can appear before its master
/// bridge.
pub(crate) async fn dump_links(handle: &Handle) -> Result<LinkCache, DataplaneError> {
    let mut bridges: HashMap<String, BridgeLink> = HashMap::new();
    let mut all_link_names: HashSet<String> = HashSet::new();
    let mut bridge_ifindex_to_name: HashMap<u32, String> = HashMap::new();
    let mut vxlan_ports: Vec<VxlanPort> = Vec::new();
    let mut vlan_upper_links: HashMap<(u32, u16), Option<u32>> = HashMap::new();
    // The AF_BRIDGE filtered dump carries bridge VLAN/tunnel extension
    // rows, but on real kernels it is not a substitute for the normal
    // RTM_GETLINK walk: VXLAN InfoData/learning attributes can be absent
    // there. Keep this diagnostic substrate optional so a kernel that
    // refuses the extension mask does not break existing readiness.
    let vlan_inventory = dump_bridge_vlan_inventory_optional(handle).await;
    // Every link that has a Controller attribute. Post-processed by
    // `index_bridge_ports` to seed `bridge_port_to_vni` and
    // `bridge_ports_by_name` for non-VXLAN ports of known bridges.
    let mut all_enslaved: Vec<EnslavedLink> = Vec::new();

    let mut stream = handle.link().get().execute();
    while let Some(msg) = stream
        .try_next()
        .await
        .map_err(|e| DataplaneError::Other(format!("link dump: {e}")))?
    {
        let (kind, name) = link_kind_and_name(&msg);
        all_link_names.extend(name.iter().cloned());
        let (bridge_vlans, vlan_tunnels) = vlan_inventory
            .get(&msg.header.index)
            .cloned()
            .unwrap_or_else(|| extract_bridge_vlan_inventory(&msg));
        let ifindex = msg.header.index;
        let master = extract_controller(&msg);
        if let Some(master_idx) = master {
            all_enslaved.push(EnslavedLink {
                ifindex,
                master: master_idx,
                is_vxlan: matches!(kind, Some(InfoKind::Vxlan)),
                name: name.clone(),
                brport_state: extract_bridge_port_state(&msg),
                vlans: bridge_vlans.clone(),
                vlan_tunnels: vlan_tunnels.clone(),
            });
        }
        match kind {
            Some(InfoKind::Bridge) => {
                if let Some(name) = name {
                    let vlan_filtering = bridge_vlan_filtering(&msg);
                    let mac = extract_link_mac(&msg);
                    let altnames = extract_altnames(&msg);
                    bridges.insert(
                        name.clone(),
                        BridgeLink {
                            ifindex,
                            mac,
                            altnames,
                            vlan_filtering,
                            vxlan: None,
                            vxlan_ports: Vec::new(),
                            svd_vxlan_ports: Vec::new(),
                            vxlan_attach_count: 0,
                            ce_port_ifindexes: Vec::new(),
                            vlans: bridge_vlans,
                            vlan_tunnels,
                            port_vlan_inventory: Vec::new(),
                        },
                    );
                    bridge_ifindex_to_name.insert(ifindex, name);
                }
            }
            Some(InfoKind::Vxlan) => {
                if let Some(port) = parse_vxlan_port(&msg) {
                    vxlan_ports.push(port);
                }
            }
            Some(InfoKind::Vlan) => {
                if let Some(upper) = parse_vlan_upper_link(&msg) {
                    insert_unique_ifindex_binding(
                        &mut vlan_upper_links,
                        (upper.lower_ifindex, upper.vlan),
                        upper.ifindex,
                    );
                }
            }
            _ => {}
        }
    }

    let (vxlan_ifindex_to_vni, svd_vxlan_ifindexes) =
        attach_vxlan_ports(vxlan_ports, &bridge_ifindex_to_name, &mut bridges);

    let (bridge_port_to_vni, bridge_ports_by_name) =
        index_bridge_ports(all_enslaved, &bridge_ifindex_to_name, &mut bridges);

    Ok(LinkCache {
        all_link_names,
        bridges,
        vxlan_ifindex_to_vni,
        svd_vxlan_ifindexes,
        bridge_port_to_vni,
        local_mac_vlan_bindings: HashMap::new(),
        bridge_port_vlan_to_vni: HashMap::new(),
        bridge_ports_requiring_vlan_attribution: HashSet::new(),
        vlan_upper_links,
        ip_neighbour_vlan_upper_to_vni: HashMap::new(),
        vxlan_port_vlan_to_vni: HashMap::new(),
        vxlan_ports_requiring_vlan_attribution: HashSet::new(),
        bridge_ports_by_name,
    })
}

fn attach_vxlan_ports(
    vxlan_ports: Vec<VxlanPort>,
    bridge_ifindex_to_name: &HashMap<u32, String>,
    bridges: &mut HashMap<String, BridgeLink>,
) -> (HashMap<u32, u32>, HashSet<u32>) {
    let mut vxlan_ifindex_to_vni = HashMap::new();
    let mut svd_vxlan_ifindexes = HashSet::new();
    for vxlan in vxlan_ports {
        match vxlan {
            VxlanPort::Fixed(vxlan) => {
                attach_fixed_vxlan(
                    vxlan,
                    bridge_ifindex_to_name,
                    bridges,
                    &mut vxlan_ifindex_to_vni,
                );
            }
            VxlanPort::Svd(vxlan) => {
                if let Some(ifindex) = attach_svd_vxlan(vxlan, bridge_ifindex_to_name, bridges) {
                    svd_vxlan_ifindexes.insert(ifindex);
                }
            }
        }
    }
    (vxlan_ifindex_to_vni, svd_vxlan_ifindexes)
}

fn attach_fixed_vxlan(
    vxlan: FixedVxlanPort,
    bridge_ifindex_to_name: &HashMap<u32, String>,
    bridges: &mut HashMap<String, BridgeLink>,
    vxlan_ifindex_to_vni: &mut HashMap<u32, u32>,
) {
    let Some(master_idx) = vxlan.master else {
        return;
    };
    let Some(bridge_name) = bridge_ifindex_to_name.get(&master_idx) else {
        return;
    };
    let Some(bridge) = bridges.get_mut(bridge_name) else {
        return;
    };
    bridge.vxlan_attach_count = bridge.vxlan_attach_count.saturating_add(1);
    vxlan_ifindex_to_vni.insert(vxlan.info.ifindex, vxlan.info.vni);
    bridge.vxlan_ports.push(vxlan.info.clone());
    // Keep the legacy single-port slot only while the bridge has one
    // VXLAN member. VLAN-aware probing uses `vxlan_ports` to select the
    // member matching the configured VNI.
    if bridge.vxlan_attach_count == 1 {
        bridge.vxlan = Some(vxlan.info);
    } else {
        // Clear the legacy slot so non-VLAN-aware probing reports NotReady
        // instead of guessing.
        bridge.vxlan = None;
    }
}

fn attach_svd_vxlan(
    vxlan: SvdVxlanPort,
    bridge_ifindex_to_name: &HashMap<u32, String>,
    bridges: &mut HashMap<String, BridgeLink>,
) -> Option<u32> {
    let master_idx = vxlan.master?;
    let bridge_name = bridge_ifindex_to_name.get(&master_idx)?;
    let bridge = bridges.get_mut(bridge_name)?;
    let ifindex = vxlan.info.ifindex;
    bridge.vxlan_attach_count = bridge.vxlan_attach_count.saturating_add(1);
    bridge.svd_vxlan_ports.push(vxlan.info);
    // SVD does not satisfy the legacy fixed-VNI slot.
    bridge.vxlan = None;
    Some(ifindex)
}

async fn dump_bridge_vlan_inventory(
    handle: &Handle,
) -> Result<BridgeVlanInventory, DataplaneError> {
    let mut inventory = HashMap::new();
    let mut stream = handle
        .link()
        .get()
        .set_filter_mask(
            AddressFamily::Bridge,
            vec![LinkExtentMask::BrvlanCompressed],
        )
        .execute();
    while let Some(msg) = stream
        .try_next()
        .await
        .map_err(|e| DataplaneError::Other(format!("bridge VLAN link dump: {e}")))?
    {
        let rows = extract_bridge_vlan_inventory(&msg);
        if !rows.0.is_empty() || !rows.1.is_empty() {
            inventory.insert(msg.header.index, rows);
        }
    }
    Ok(inventory)
}

/// One enslaved link from the dump's first pass — the raw material
/// for [`index_bridge_ports`].
struct EnslavedLink {
    ifindex: u32,
    master: u32,
    is_vxlan: bool,
    name: Option<String>,
    brport_state: Option<u8>,
    vlans: Vec<KernelBridgeVlanInfo>,
    vlan_tunnels: Vec<KernelBridgeVlanTunnelInfo>,
}

/// Build `bridge_port_to_vni` + `bridge_ports_by_name` from the
/// enslaved-links list, and fill each bridge's `ce_port_ifindexes`.
///
/// `bridge_port_to_vni` only includes non-VXLAN slaves whose master
/// bridge has a resolved VNI (exactly one VXLAN port attached) —
/// bridges without a VNI are EVPN-managed-but-unready and we should
/// not mis-classify their MAC observations. `bridge_ports_by_name`
/// is broader: any named non-VXLAN port of a known bridge is an
/// AC-gate candidate, VNI-resolved or not (see the field docs).
fn index_bridge_ports(
    all_enslaved: Vec<EnslavedLink>,
    bridge_ifindex_to_name: &HashMap<u32, String>,
    bridges: &mut HashMap<String, BridgeLink>,
) -> (
    HashMap<u32, u32>,
    HashMap<String, crate::snapshot::KernelBridgePortInfo>,
) {
    let mut bridge_port_to_vni: HashMap<u32, u32> = HashMap::new();
    let mut bridge_ports_by_name: HashMap<String, crate::snapshot::KernelBridgePortInfo> =
        HashMap::new();
    for port in all_enslaved {
        let Some(bridge_name) = bridge_ifindex_to_name.get(&port.master) else {
            continue;
        };
        if (!port.vlans.is_empty() || !port.vlan_tunnels.is_empty())
            && let Some(bridge) = bridges.get_mut(bridge_name)
        {
            bridge.port_vlan_inventory.push(KernelBridgePortVlanInfo {
                ifindex: port.ifindex,
                name: port.name.clone(),
                is_vxlan: port.is_vxlan,
                vlans: port.vlans.clone(),
                vlan_tunnels: port.vlan_tunnels.clone(),
            });
        }
        if port.is_vxlan {
            continue;
        }
        if let Some(name) = port.name {
            bridge_ports_by_name.insert(
                name,
                crate::snapshot::KernelBridgePortInfo {
                    ifindex: port.ifindex,
                    state: port.brport_state,
                },
            );
        }
        let Some(bridge) = bridges.get(bridge_name) else {
            continue;
        };
        let Some(vxlan) = &bridge.vxlan else {
            continue;
        };
        bridge_port_to_vni.insert(port.ifindex, vxlan.vni);
        if let Some(bridge) = bridges.get_mut(bridge_name) {
            bridge.ce_port_ifindexes.push(port.ifindex);
        }
    }
    for bridge in bridges.values_mut() {
        bridge.ce_port_ifindexes.sort_unstable();
        bridge.ce_port_ifindexes.dedup();
        bridge
            .port_vlan_inventory
            .sort_by(|a, b| (a.ifindex, &a.name).cmp(&(b.ifindex, &b.name)));
    }
    (bridge_port_to_vni, bridge_ports_by_name)
}

/// Extract the Controller (master) ifindex attribute, if present.
fn extract_controller(msg: &LinkMessage) -> Option<u32> {
    for attr in &msg.attributes {
        if let LinkAttribute::Controller(idx) = attr {
            return Some(*idx);
        }
    }
    None
}

/// Extract the link-layer (MAC) address attribute, if the kernel
/// reports one and it is exactly six octets. Other lengths (Infiniband
/// LL is 20 bytes, IP-over-IP tunnels report empty) are silently
/// dropped — the bridge will simply have no `bridge_mac` on its
/// status row.
fn extract_link_mac(msg: &LinkMessage) -> Option<MacAddress> {
    for attr in &msg.attributes {
        if let LinkAttribute::Address(bytes) = attr
            && let Ok(arr) = <[u8; 6]>::try_from(bytes.as_slice())
        {
            return Some(MacAddress::new(arr));
        }
    }
    None
}

/// Extract Linux alternative interface names from
/// `IFLA_PROP_LIST/IFLA_ALT_IFNAME`.
fn extract_altnames(msg: &LinkMessage) -> Vec<String> {
    let mut altnames = Vec::new();
    for attr in &msg.attributes {
        if let LinkAttribute::PropList(props) = attr {
            for prop in props {
                if let Prop::AltIfName(name) = prop {
                    altnames.push(name.clone());
                }
            }
        }
    }
    altnames.sort();
    altnames.dedup();
    altnames
}

/// Extract the observed `IFLA_BRPORT_STATE` from the link's
/// `IFLA_INFO_PORT_DATA` slave info, if the kernel reported bridge
/// port data. Kept as the raw `BR_STATE_*` scalar — the snapshot
/// types are platform-independent and the parser keeps scalars, not
/// crate enums.
fn extract_bridge_port_state(msg: &LinkMessage) -> Option<u8> {
    for attr in &msg.attributes {
        if let LinkAttribute::LinkInfo(infos) = attr {
            for info in infos {
                if let LinkInfo::PortData(InfoPortData::BridgePort(ports)) = info {
                    for port in ports {
                        if let InfoBridgePort::State(state) = port {
                            return Some(u8::from(*state));
                        }
                    }
                }
            }
        }
    }
    None
}

fn extract_bridge_vlan_inventory(
    msg: &LinkMessage,
) -> (Vec<KernelBridgeVlanInfo>, Vec<KernelBridgeVlanTunnelInfo>) {
    let mut vlans = Vec::new();
    let mut vlan_tunnels = Vec::new();
    for attr in &msg.attributes {
        if let LinkAttribute::AfSpecBridge(items) = attr {
            for item in items {
                match item {
                    AfSpecBridge::VlanInfo(info) => {
                        vlans.push(kernel_bridge_vlan_info(*info));
                    }
                    AfSpecBridge::VlanTunnelInfo(items) => {
                        vlan_tunnels.push(kernel_bridge_vlan_tunnel_info(items));
                    }
                    _ => {}
                }
            }
        }
    }
    // Sort keys must be total — these vectors participate in snapshot `Eq`
    // comparisons, so any field that distinguishes two rows (every flag bit,
    // not just the range/pvid/untagged subset) has to be in the key, or the
    // ordering stays dependent on netlink arrival order and churns the snapshot.
    vlans.sort_by_key(|v| (v.vid, v.flags));
    vlan_tunnels.sort_by_key(|v| (v.vid, v.tunnel_id, v.flags));
    (vlans, vlan_tunnels)
}

fn kernel_bridge_vlan_info(info: BridgeVlanInfo) -> KernelBridgeVlanInfo {
    KernelBridgeVlanInfo {
        vid: info.vid,
        flags: kernel_bridge_vlan_flags(info.flags),
    }
}

fn kernel_bridge_vlan_tunnel_info(items: &[BridgeVlanTunnelInfo]) -> KernelBridgeVlanTunnelInfo {
    let mut tunnel_id = None;
    let mut vid = None;
    let mut flags = KernelBridgeVlanFlags::default();
    for item in items {
        match item {
            BridgeVlanTunnelInfo::Id(id) => tunnel_id = Some(*id),
            BridgeVlanTunnelInfo::Vid(v) => vid = Some(*v),
            BridgeVlanTunnelInfo::Flags(f) => flags = kernel_bridge_vlan_flags(*f),
            _ => {}
        }
    }
    KernelBridgeVlanTunnelInfo {
        tunnel_id,
        vid,
        flags,
    }
}

fn kernel_bridge_vlan_flags(flags: BridgeVlanInfoFlags) -> KernelBridgeVlanFlags {
    KernelBridgeVlanFlags {
        controller: flags.contains(BridgeVlanInfoFlags::Controller),
        pvid: flags.contains(BridgeVlanInfoFlags::Pvid),
        untagged: flags.contains(BridgeVlanInfoFlags::Untagged),
        range_begin: flags.contains(BridgeVlanInfoFlags::RangeBegin),
        range_end: flags.contains(BridgeVlanInfoFlags::RangeEnd),
        bridge_entry: flags.contains(BridgeVlanInfoFlags::Brentry),
        only_options: flags.contains(BridgeVlanInfoFlags::OnlyOpts),
    }
}

fn link_kind_and_name(msg: &LinkMessage) -> (Option<InfoKind>, Option<String>) {
    let mut name = None;
    let mut kind = None;
    for attr in &msg.attributes {
        match attr {
            LinkAttribute::IfName(n) => name = Some(n.clone()),
            LinkAttribute::LinkInfo(infos) => {
                for info in infos {
                    if let LinkInfo::Kind(k) = info {
                        kind = Some(k.clone());
                    }
                }
            }
            _ => {}
        }
    }
    (kind, name)
}

fn bridge_vlan_filtering(msg: &LinkMessage) -> bool {
    for attr in &msg.attributes {
        if let LinkAttribute::LinkInfo(infos) = attr {
            for info in infos {
                if let LinkInfo::Data(InfoData::Bridge(brs)) = info {
                    for br in brs {
                        if let InfoBridge::VlanFiltering(v) = br {
                            return *v;
                        }
                    }
                }
            }
        }
    }
    false
}

fn parse_vxlan_port(msg: &LinkMessage) -> Option<VxlanPort> {
    let ifindex = msg.header.index;
    let mut master = None;
    let mut vni: Option<u32> = None;
    let mut local: Option<IpAddr> = None;
    let mut collect_metadata = false;
    let mut vnifilter = false;
    // None until we observe IFLA_VXLAN_LEARNING. Probe fails closed
    // on `None` so a kernel that omits the attribute doesn't quietly
    // pass the readiness check.
    let mut learning_disabled: Option<bool> = None;

    for attr in &msg.attributes {
        match attr {
            LinkAttribute::Controller(idx) => master = Some(*idx),
            LinkAttribute::LinkInfo(infos) => {
                for info in infos {
                    if let LinkInfo::Data(InfoData::Vxlan(items)) = info {
                        for item in items {
                            match item {
                                InfoVxlan::Id(v) => vni = Some(*v),
                                InfoVxlan::Local(addr) => {
                                    local = Some(IpAddr::V4(*addr));
                                }
                                InfoVxlan::Local6(addr) => {
                                    local = Some(IpAddr::V6(*addr));
                                }
                                InfoVxlan::Learning(b) => learning_disabled = Some(!*b),
                                InfoVxlan::CollectMetadata(b) => collect_metadata = *b,
                                InfoVxlan::Vnifilter(b) => vnifilter = *b,
                                _ => {}
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }

    if collect_metadata {
        return Some(VxlanPort::Svd(SvdVxlanPort {
            master,
            info: KernelSvdVxlanInfo {
                ifindex,
                vnifilter,
                local_ip: local,
                learning_disabled,
            },
        }));
    }

    Some(VxlanPort::Fixed(FixedVxlanPort {
        master,
        info: KernelVxlanInfo {
            ifindex,
            vni: vni?,
            local_ip: local?,
            learning_disabled,
        },
    }))
}

fn parse_vlan_upper_link(msg: &LinkMessage) -> Option<VlanUpperLink> {
    let ifindex = msg.header.index;
    let mut lower_ifindex = None;
    let mut vlan = None;

    for attr in &msg.attributes {
        match attr {
            LinkAttribute::Link(idx) => lower_ifindex = Some(*idx),
            LinkAttribute::LinkInfo(infos) => {
                for info in infos {
                    if let LinkInfo::Data(InfoData::Vlan(items)) = info {
                        for item in items {
                            if let InfoVlan::Id(id) = item {
                                vlan = Some(*id);
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }

    Some(VlanUpperLink {
        ifindex,
        lower_ifindex: lower_ifindex?,
        vlan: vlan?,
    })
}

#[cfg(test)]
mod tests {
    use std::collections::{HashMap, HashSet};

    use super::*;
    use crate::snapshot::KernelVxlanInfo;
    use netlink_packet_route::link::LinkMessage;
    use rustbgpd_evpn::{
        BridgeVlan, EvpnInstance, EvpnInstanceId, EvpnInstanceTable, RouteDistinguisher,
    };

    fn synthesize_link_msg(addr: Vec<u8>) -> LinkMessage {
        let mut msg = LinkMessage::default();
        msg.attributes.push(LinkAttribute::Address(addr));
        msg
    }

    fn vlan_row(vid: u16) -> KernelBridgeVlanInfo {
        KernelBridgeVlanInfo {
            vid,
            flags: KernelBridgeVlanFlags::default(),
        }
    }

    fn vni(raw: u32) -> EvpnInstanceId {
        EvpnInstanceId::new(raw).unwrap()
    }

    fn instance(vni: u32, bridge: &str, vlan: u16) -> EvpnInstance {
        EvpnInstance::new(
            EvpnInstanceId::new(vni).unwrap(),
            format!("65000:{vni}")
                .parse::<RouteDistinguisher>()
                .unwrap(),
            vec![format!("65000:{vni}").parse().unwrap()],
            "10.0.0.1".parse().unwrap(),
            Some(bridge.to_string()),
            false,
        )
        .unwrap()
        .with_bridge_vlan(Some(BridgeVlan::new(u32::from(vlan)).unwrap()))
    }

    #[test]
    fn extract_link_mac_captures_six_octet_address() {
        let bytes = vec![0x52, 0x54, 0x00, 0x12, 0x34, 0x56];
        let msg = synthesize_link_msg(bytes.clone());
        let mac = extract_link_mac(&msg).expect("six-octet address must yield Some");
        assert_eq!(mac.octets(), [0x52, 0x54, 0x00, 0x12, 0x34, 0x56]);
    }

    #[test]
    fn extract_link_mac_drops_non_six_octet_addresses() {
        // Infiniband-shaped 20-byte LL address — silently ignored
        // rather than half-decoded.
        let msg = synthesize_link_msg(vec![0u8; 20]);
        assert!(extract_link_mac(&msg).is_none());
        // Empty address (some IP-over-IP tunnels) — also dropped.
        let msg = synthesize_link_msg(vec![]);
        assert!(extract_link_mac(&msg).is_none());
    }

    #[test]
    fn extract_link_mac_returns_none_when_no_address_attribute() {
        let msg = LinkMessage::default();
        assert!(extract_link_mac(&msg).is_none());
    }

    #[test]
    fn extract_bridge_port_state_reads_port_data_scalar() {
        use netlink_packet_route::link::{BridgePortState, InfoPortKind};

        let mut msg = LinkMessage::default();
        msg.attributes.push(LinkAttribute::LinkInfo(vec![
            LinkInfo::PortKind(InfoPortKind::Bridge),
            LinkInfo::PortData(InfoPortData::BridgePort(vec![InfoBridgePort::State(
                BridgePortState::Disabled,
            )])),
        ]));
        assert_eq!(extract_bridge_port_state(&msg), Some(0));

        let mut msg = LinkMessage::default();
        msg.attributes.push(LinkAttribute::LinkInfo(vec![
            LinkInfo::PortKind(InfoPortKind::Bridge),
            LinkInfo::PortData(InfoPortData::BridgePort(vec![InfoBridgePort::State(
                BridgePortState::Forwarding,
            )])),
        ]));
        assert_eq!(extract_bridge_port_state(&msg), Some(3));
    }

    #[test]
    fn extract_bridge_port_state_none_without_port_data() {
        let msg = LinkMessage::default();
        assert!(extract_bridge_port_state(&msg).is_none());
    }

    #[test]
    fn extract_bridge_vlan_inventory_reads_vlan_and_tunnel_rows() {
        let mut msg = LinkMessage::default();
        msg.attributes.push(LinkAttribute::AfSpecBridge(vec![
            AfSpecBridge::VlanInfo(BridgeVlanInfo {
                flags: BridgeVlanInfoFlags::Pvid | BridgeVlanInfoFlags::Untagged,
                vid: 100,
            }),
            AfSpecBridge::VlanTunnelInfo(vec![
                BridgeVlanTunnelInfo::Id(5000),
                BridgeVlanTunnelInfo::Vid(100),
                BridgeVlanTunnelInfo::Flags(BridgeVlanInfoFlags::Untagged),
            ]),
        ]));

        let (vlans, tunnels) = extract_bridge_vlan_inventory(&msg);

        assert_eq!(vlans.len(), 1);
        assert_eq!(vlans[0].vid, 100);
        assert!(vlans[0].flags.pvid);
        assert!(vlans[0].flags.untagged);
        assert_eq!(tunnels.len(), 1);
        assert_eq!(tunnels[0].tunnel_id, Some(5000));
        assert_eq!(tunnels[0].vid, Some(100));
        assert!(tunnels[0].flags.untagged);
    }

    #[test]
    fn parse_vxlan_port_captures_fixed_vni_device() {
        let mut msg = LinkMessage::default();
        msg.header.index = 20;
        msg.attributes.push(LinkAttribute::Controller(10));
        msg.attributes.push(LinkAttribute::LinkInfo(vec![
            LinkInfo::Kind(InfoKind::Vxlan),
            LinkInfo::Data(InfoData::Vxlan(vec![
                InfoVxlan::Id(100),
                InfoVxlan::Local("10.0.0.1".parse().unwrap()),
                InfoVxlan::Learning(false),
            ])),
        ]));

        let Some(VxlanPort::Fixed(port)) = parse_vxlan_port(&msg) else {
            panic!("expected fixed VXLAN port");
        };
        assert_eq!(port.master, Some(10));
        assert_eq!(port.info.ifindex, 20);
        assert_eq!(port.info.vni, 100);
        assert_eq!(port.info.local_ip, "10.0.0.1".parse::<IpAddr>().unwrap());
        assert_eq!(port.info.learning_disabled, Some(true));
    }

    #[test]
    fn parse_vxlan_port_captures_collect_metadata_without_fixed_vni() {
        let mut msg = LinkMessage::default();
        msg.header.index = 30;
        msg.attributes.push(LinkAttribute::Controller(10));
        msg.attributes.push(LinkAttribute::LinkInfo(vec![
            LinkInfo::Kind(InfoKind::Vxlan),
            LinkInfo::Data(InfoData::Vxlan(vec![
                InfoVxlan::CollectMetadata(true),
                InfoVxlan::Vnifilter(true),
                InfoVxlan::Learning(false),
            ])),
        ]));

        let Some(VxlanPort::Svd(port)) = parse_vxlan_port(&msg) else {
            panic!("expected SVD VXLAN port");
        };
        assert_eq!(port.master, Some(10));
        assert_eq!(port.info.ifindex, 30);
        assert!(port.info.vnifilter);
        assert_eq!(port.info.local_ip, None);
        assert_eq!(port.info.learning_disabled, Some(true));
    }

    #[test]
    fn parse_vlan_upper_link_captures_lower_ifindex_and_vlan_id() {
        let mut msg = LinkMessage::default();
        msg.header.index = 110;
        msg.attributes.push(LinkAttribute::Link(10));
        msg.attributes.push(LinkAttribute::LinkInfo(vec![
            LinkInfo::Kind(InfoKind::Vlan),
            LinkInfo::Data(InfoData::Vlan(vec![InfoVlan::Id(20)])),
        ]));

        let upper = parse_vlan_upper_link(&msg).expect("vlan upper");

        assert_eq!(upper.ifindex, 110);
        assert_eq!(upper.lower_ifindex, 10);
        assert_eq!(upper.vlan, 20);
    }

    #[test]
    fn parse_vlan_upper_link_drops_without_lower_or_vlan() {
        let mut without_lower = LinkMessage::default();
        without_lower.header.index = 110;
        without_lower
            .attributes
            .push(LinkAttribute::LinkInfo(vec![LinkInfo::Data(
                InfoData::Vlan(vec![InfoVlan::Id(20)]),
            )]));
        assert!(parse_vlan_upper_link(&without_lower).is_none());

        let mut without_vlan = LinkMessage::default();
        without_vlan.header.index = 111;
        without_vlan.attributes.push(LinkAttribute::Link(10));
        assert!(parse_vlan_upper_link(&without_vlan).is_none());
    }

    #[test]
    fn attach_vxlan_ports_indexes_only_bridge_attached_svd_ports() {
        let mut bridges = HashMap::new();
        bridges.insert(
            "br100".to_string(),
            BridgeLink {
                ifindex: 10,
                ..BridgeLink::default()
            },
        );
        let mut bridge_ifindex_to_name = HashMap::new();
        bridge_ifindex_to_name.insert(10, "br100".to_string());

        let svd_info = |ifindex| KernelSvdVxlanInfo {
            ifindex,
            vnifilter: true,
            local_ip: None,
            learning_disabled: Some(true),
        };
        let (_, svd_ifindexes) = attach_vxlan_ports(
            vec![
                VxlanPort::Svd(SvdVxlanPort {
                    master: None,
                    info: svd_info(20),
                }),
                VxlanPort::Svd(SvdVxlanPort {
                    master: Some(99),
                    info: svd_info(21),
                }),
                VxlanPort::Svd(SvdVxlanPort {
                    master: Some(10),
                    info: svd_info(22),
                }),
            ],
            &bridge_ifindex_to_name,
            &mut bridges,
        );

        assert_eq!(svd_ifindexes, HashSet::from([22]));
        let bridge = bridges.get("br100").unwrap();
        assert_eq!(bridge.vxlan_attach_count, 1);
        assert_eq!(bridge.svd_vxlan_ports.len(), 1);
        assert_eq!(bridge.svd_vxlan_ports[0].ifindex, 22);
    }

    #[test]
    fn index_bridge_ports_keeps_vlan_inventory_read_only() {
        let mut bridges = HashMap::new();
        bridges.insert(
            "br100".to_string(),
            BridgeLink {
                ifindex: 10,
                vxlan_attach_count: 1,
                vxlan: Some(KernelVxlanInfo {
                    ifindex: 20,
                    vni: 100,
                    local_ip: "10.0.0.1".parse().unwrap(),
                    learning_disabled: Some(true),
                }),
                ..BridgeLink::default()
            },
        );
        let mut bridge_ifindex_to_name = HashMap::new();
        bridge_ifindex_to_name.insert(10, "br100".to_string());

        let (bridge_port_to_vni, bridge_ports_by_name) = index_bridge_ports(
            vec![
                EnslavedLink {
                    ifindex: 20,
                    master: 10,
                    is_vxlan: true,
                    name: Some("vxlan100".to_string()),
                    brport_state: None,
                    vlans: vec![KernelBridgeVlanInfo {
                        vid: 100,
                        flags: KernelBridgeVlanFlags {
                            untagged: true,
                            ..KernelBridgeVlanFlags::default()
                        },
                    }],
                    vlan_tunnels: vec![KernelBridgeVlanTunnelInfo {
                        tunnel_id: Some(5000),
                        vid: Some(100),
                        flags: KernelBridgeVlanFlags::default(),
                    }],
                },
                EnslavedLink {
                    ifindex: 30,
                    master: 10,
                    is_vxlan: false,
                    name: Some("swp1".to_string()),
                    brport_state: Some(3),
                    vlans: vec![KernelBridgeVlanInfo {
                        vid: 100,
                        flags: KernelBridgeVlanFlags {
                            pvid: true,
                            untagged: true,
                            ..KernelBridgeVlanFlags::default()
                        },
                    }],
                    vlan_tunnels: Vec::new(),
                },
            ],
            &bridge_ifindex_to_name,
            &mut bridges,
        );

        assert_eq!(bridge_port_to_vni.get(&30), Some(&100));
        assert!(!bridge_port_to_vni.contains_key(&20));
        assert!(bridge_ports_by_name.contains_key("swp1"));
        assert!(!bridge_ports_by_name.contains_key("vxlan100"));
        let inventory = &bridges["br100"].port_vlan_inventory;
        assert_eq!(inventory.len(), 2);
        assert!(
            inventory
                .iter()
                .any(|row| row.is_vxlan && row.ifindex == 20)
        );
        assert!(
            inventory
                .iter()
                .any(|row| !row.is_vxlan && row.ifindex == 30)
        );
    }

    #[test]
    fn bind_local_mac_vlan_attribution_uses_configured_bridge_vlans_only() {
        let mut cache = LinkCache::default();
        cache.bridges.insert(
            "br100".to_string(),
            BridgeLink {
                ifindex: 10,
                vlan_filtering: true,
                vxlan_ports: vec![
                    KernelVxlanInfo {
                        ifindex: 20,
                        vni: 100,
                        local_ip: "10.0.0.1".parse().unwrap(),
                        learning_disabled: Some(true),
                    },
                    KernelVxlanInfo {
                        ifindex: 21,
                        vni: 200,
                        local_ip: "10.0.0.1".parse().unwrap(),
                        learning_disabled: Some(true),
                    },
                ],
                vxlan_attach_count: 2,
                vlans: vec![vlan_row(10), vlan_row(20), vlan_row(99)],
                port_vlan_inventory: vec![
                    KernelBridgePortVlanInfo {
                        ifindex: 20,
                        name: Some("vxlan100".to_string()),
                        is_vxlan: true,
                        vlans: vec![vlan_row(10), vlan_row(99)],
                        vlan_tunnels: Vec::new(),
                    },
                    KernelBridgePortVlanInfo {
                        ifindex: 21,
                        name: Some("vxlan200".to_string()),
                        is_vxlan: true,
                        vlans: vec![vlan_row(20)],
                        vlan_tunnels: Vec::new(),
                    },
                    KernelBridgePortVlanInfo {
                        ifindex: 30,
                        name: Some("swp1".to_string()),
                        is_vxlan: false,
                        vlans: vec![vlan_row(10), vlan_row(20), vlan_row(99)],
                        vlan_tunnels: Vec::new(),
                    },
                ],
                ..BridgeLink::default()
            },
        );
        let mut instances = EvpnInstanceTable::new();
        instances.insert(instance(100, "br100", 10)).unwrap();
        instances.insert(instance(200, "br100", 20)).unwrap();

        cache.bind_local_mac_vlan_attribution(&instances);

        assert_eq!(cache.bridge_port_vlan_to_vni.get(&(30, 10)), Some(&100));
        assert_eq!(cache.bridge_port_vlan_to_vni.get(&(30, 20)), Some(&200));
        assert!(cache.ip_neighbour_vlan_upper_to_vni.is_empty());
        assert!(cache.bridge_ports_requiring_vlan_attribution.contains(&30));
        assert!(
            !cache.bridge_port_vlan_to_vni.contains_key(&(30, 99)),
            "extra topology VLAN without configured bridge_vlan must not become observable"
        );
        assert_eq!(cache.vxlan_port_vlan_to_vni.get(&(20, 10)), Some(&100));
        assert_eq!(cache.vxlan_port_vlan_to_vni.get(&(21, 20)), Some(&200));
        assert!(cache.vxlan_ports_requiring_vlan_attribution.contains(&20));
        assert!(cache.vxlan_ports_requiring_vlan_attribution.contains(&21));
        assert!(!cache.vxlan_port_vlan_to_vni.contains_key(&(20, 99)));
    }

    #[test]
    fn bind_local_mac_vlan_attribution_indexes_vlan_upper_devices() {
        let mut cache = LinkCache::default();
        cache.vlan_upper_links.insert((10, 10), Some(110));
        cache.vlan_upper_links.insert((10, 20), Some(120));
        cache.vlan_upper_links.insert((10, 99), Some(199));
        cache.bridges.insert(
            "br100".to_string(),
            BridgeLink {
                ifindex: 10,
                vlan_filtering: true,
                vxlan_ports: vec![
                    KernelVxlanInfo {
                        ifindex: 20,
                        vni: 100,
                        local_ip: "10.0.0.1".parse().unwrap(),
                        learning_disabled: Some(true),
                    },
                    KernelVxlanInfo {
                        ifindex: 21,
                        vni: 200,
                        local_ip: "10.0.0.1".parse().unwrap(),
                        learning_disabled: Some(true),
                    },
                ],
                vxlan_attach_count: 2,
                vlans: vec![vlan_row(10), vlan_row(20), vlan_row(99)],
                port_vlan_inventory: vec![
                    KernelBridgePortVlanInfo {
                        ifindex: 20,
                        name: Some("vxlan100".to_string()),
                        is_vxlan: true,
                        vlans: vec![vlan_row(10)],
                        vlan_tunnels: Vec::new(),
                    },
                    KernelBridgePortVlanInfo {
                        ifindex: 21,
                        name: Some("vxlan200".to_string()),
                        is_vxlan: true,
                        vlans: vec![vlan_row(20)],
                        vlan_tunnels: Vec::new(),
                    },
                ],
                ..BridgeLink::default()
            },
        );
        let mut instances = EvpnInstanceTable::new();
        instances.insert(instance(100, "br100", 10)).unwrap();
        instances.insert(instance(200, "br100", 20)).unwrap();

        cache.bind_local_mac_vlan_attribution(&instances);

        assert_eq!(cache.ip_neighbour_vlan_upper_to_vni.get(&110), Some(&100));
        assert_eq!(cache.ip_neighbour_vlan_upper_to_vni.get(&120), Some(&200));
        assert!(
            !cache.ip_neighbour_vlan_upper_to_vni.contains_key(&199),
            "unconfigured VLAN upper must not become MAC+IP-attributable"
        );
    }

    #[test]
    fn bind_local_mac_vlan_attribution_drops_duplicate_config_binding() {
        let mut cache = LinkCache::default();
        cache.bridges.insert(
            "br100".to_string(),
            BridgeLink {
                ifindex: 10,
                vlan_filtering: true,
                vxlan_ports: vec![KernelVxlanInfo {
                    ifindex: 20,
                    vni: 100,
                    local_ip: "10.0.0.1".parse().unwrap(),
                    learning_disabled: Some(true),
                }],
                vxlan_attach_count: 1,
                vlans: vec![vlan_row(10)],
                port_vlan_inventory: vec![
                    KernelBridgePortVlanInfo {
                        ifindex: 20,
                        name: Some("vxlan100".to_string()),
                        is_vxlan: true,
                        vlans: vec![vlan_row(10)],
                        vlan_tunnels: Vec::new(),
                    },
                    KernelBridgePortVlanInfo {
                        ifindex: 30,
                        name: Some("swp1".to_string()),
                        is_vxlan: false,
                        vlans: vec![vlan_row(10)],
                        vlan_tunnels: Vec::new(),
                    },
                ],
                ..BridgeLink::default()
            },
        );
        let mut instances = EvpnInstanceTable::new();
        instances.insert(instance(100, "br100", 10)).unwrap();
        instances.insert(instance(200, "br100", 10)).unwrap();

        cache.bind_local_mac_vlan_attribution(&instances);

        assert!(cache.bridge_port_vlan_to_vni.is_empty());
        assert!(cache.vxlan_port_vlan_to_vni.is_empty());
        assert!(cache.bridge_ports_requiring_vlan_attribution.contains(&30));
        assert!(cache.vxlan_ports_requiring_vlan_attribution.contains(&20));
        assert!(cache.ip_neighbour_vlan_upper_to_vni.is_empty());
    }

    #[test]
    fn bind_local_mac_vlan_attribution_drops_duplicate_vlan_upper_device() {
        let mut cache = LinkCache::default();
        cache.vlan_upper_links.insert((10, 10), None);
        cache.bridges.insert(
            "br100".to_string(),
            BridgeLink {
                ifindex: 10,
                vlan_filtering: true,
                vxlan_ports: vec![KernelVxlanInfo {
                    ifindex: 20,
                    vni: 100,
                    local_ip: "10.0.0.1".parse().unwrap(),
                    learning_disabled: Some(true),
                }],
                vxlan_attach_count: 1,
                vlans: vec![vlan_row(10)],
                port_vlan_inventory: vec![KernelBridgePortVlanInfo {
                    ifindex: 20,
                    name: Some("vxlan100".to_string()),
                    is_vxlan: true,
                    vlans: vec![vlan_row(10)],
                    vlan_tunnels: Vec::new(),
                }],
                ..BridgeLink::default()
            },
        );
        let mut instances = EvpnInstanceTable::new();
        instances.insert(instance(100, "br100", 10)).unwrap();

        cache.bind_local_mac_vlan_attribution(&instances);

        assert!(cache.ip_neighbour_vlan_upper_to_vni.is_empty());
    }

    #[test]
    fn unique_fdb_vxlan_target_resolves_svd_binding() {
        let mut cache = LinkCache::default();
        cache.svd_vxlan_ifindexes.insert(40);
        cache.bridges.insert(
            "br100".to_string(),
            BridgeLink {
                ifindex: 10,
                vlan_filtering: true,
                svd_vxlan_ports: vec![KernelSvdVxlanInfo {
                    ifindex: 40,
                    vnifilter: true,
                    local_ip: None,
                    learning_disabled: Some(true),
                }],
                vxlan_attach_count: 1,
                vlans: vec![vlan_row(10)],
                port_vlan_inventory: vec![
                    KernelBridgePortVlanInfo {
                        ifindex: 40,
                        name: Some("vxlan-svd".to_string()),
                        is_vxlan: true,
                        vlans: vec![vlan_row(10)],
                        vlan_tunnels: vec![KernelBridgeVlanTunnelInfo {
                            tunnel_id: Some(100),
                            vid: Some(10),
                            flags: KernelBridgeVlanFlags::default(),
                        }],
                    },
                    KernelBridgePortVlanInfo {
                        ifindex: 30,
                        name: Some("swp1".to_string()),
                        is_vxlan: false,
                        vlans: vec![vlan_row(10)],
                        vlan_tunnels: Vec::new(),
                    },
                ],
                ..BridgeLink::default()
            },
        );
        let mut instances = EvpnInstanceTable::new();
        instances.insert(instance(100, "br100", 10)).unwrap();
        cache.bind_local_mac_vlan_attribution(&instances);

        let target = unique_fdb_vxlan_target_for_vni(&cache, vni(100)).unwrap();
        assert_eq!(target.ifindex, 40);
        assert_eq!(target.source_vni, Some(vni(100)));
        assert_eq!(target.learning_disabled, Some(true));
        assert_eq!(cache.bridge_port_vlan_to_vni.get(&(30, 10)), Some(&100));
        assert_eq!(cache.vxlan_port_vlan_to_vni.get(&(40, 10)), Some(&100));
    }

    #[test]
    fn unique_fdb_vxlan_target_rejects_fixed_and_svd_ambiguity() {
        let mut cache = LinkCache::default();
        cache.vxlan_ifindex_to_vni.insert(20, 100);
        cache.svd_vxlan_ifindexes.insert(40);
        cache.bridges.insert(
            "br100".to_string(),
            BridgeLink {
                ifindex: 10,
                vlan_filtering: true,
                vxlan_ports: vec![KernelVxlanInfo {
                    ifindex: 20,
                    vni: 100,
                    local_ip: "10.0.0.1".parse().unwrap(),
                    learning_disabled: Some(true),
                }],
                svd_vxlan_ports: vec![KernelSvdVxlanInfo {
                    ifindex: 40,
                    vnifilter: true,
                    local_ip: None,
                    learning_disabled: Some(true),
                }],
                vxlan_attach_count: 2,
                vlans: vec![vlan_row(10)],
                port_vlan_inventory: vec![
                    KernelBridgePortVlanInfo {
                        ifindex: 20,
                        name: Some("vxlan100".to_string()),
                        is_vxlan: true,
                        vlans: vec![vlan_row(10)],
                        vlan_tunnels: Vec::new(),
                    },
                    KernelBridgePortVlanInfo {
                        ifindex: 40,
                        name: Some("vxlan-svd".to_string()),
                        is_vxlan: true,
                        vlans: vec![vlan_row(10)],
                        vlan_tunnels: vec![KernelBridgeVlanTunnelInfo {
                            tunnel_id: Some(100),
                            vid: Some(10),
                            flags: KernelBridgeVlanFlags::default(),
                        }],
                    },
                ],
                ..BridgeLink::default()
            },
        );
        let mut instances = EvpnInstanceTable::new();
        instances.insert(instance(100, "br100", 10)).unwrap();
        cache.bind_local_mac_vlan_attribution(&instances);

        let err = unique_fdb_vxlan_target_for_vni(&cache, vni(100)).unwrap_err();
        assert!(
            matches!(err, DataplaneError::InvalidArgument(_)),
            "ambiguous fixed+SVD topology must fail closed: {err:?}"
        );
    }
}
