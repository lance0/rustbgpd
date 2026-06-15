//! Kernel-side snapshot types — the dataplane actor's view of the world.
//!
//! [`KernelSnapshot`] is what the dataplane crate dumps from netlink (or
//! constructs in tests via [`crate::InMemoryDataplane`]). The diff
//! function compares it against the desired [`rustbgpd_evpn::RemoteMacTable`]
//! and the [`OwnedSet`] of previously-applied entries to compute a
//! [`crate::Plan`] of operations.
//!
//! ## Foreign-entry preservation
//!
//! ADR-0054 §5/§6/§7 require the diff loop to never delete entries it
//! didn't program. The mechanism is structural: the delete pass
//! iterates [`OwnedSet`], not the snapshot, so kernel-learned local
//! MACs and operator-static FDB entries are invisible to deletion.
//! The snapshot still needs to surface flag information so the diff
//! pass can recognize *update* opportunities on entries we own and
//! *skip* operations on entries we don't.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use rustbgpd_evpn::{EvpnInstanceId, MacAddress};

/// `RTPROT_BGP` (186) — the daemon's kernel ownership identity, shared
/// with every route we install (`rtm_protocol`) and, per ADR-0082, the
/// `NDA_PROTOCOL` stamp on every FDB/neighbor install. Kept as a raw
/// `u8` here because the snapshot types are platform-independent (the
/// netlink crates are Linux-only deps).
const RTPROT_BGP: u8 = 186;

/// Bridge / VXLAN link inventory entry.
///
/// Phase 2 holds only the fields the diff loop and per-instance probe
/// need today; Phase 4 (the real netlink impl) extends with admin/oper
/// state and bridge aging time as those become relevant.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KernelLinkInfo {
    /// Bridge name (e.g., `"br100"`).
    pub bridge_name: String,
    /// `true` if the bridge has `vlan_filtering=1`. ADR-0054 §4 rejects
    /// VLAN-aware bridges in Gate 7b — the probe surfaces this as
    /// `NotReady`.
    pub vlan_filtering: bool,
    /// VXLAN port attached to the bridge for this instance's VNI, if
    /// exactly one is found. `None` indicates a missing or ambiguous
    /// VXLAN port and reports the instance `NotReady`.
    pub vxlan: Option<KernelVxlanInfo>,
    /// Non-VXLAN bridge-member ifindexes observed under this bridge.
    /// These are the CE-facing candidates Gate 8b will target for
    /// BUM suppression once the kernel primitive is selected.
    pub ce_port_ifindexes: Vec<u32>,
    /// VLAN membership observed on the bridge device itself via
    /// `IFLA_AF_SPEC(AF_BRIDGE)`. Read-only ADR-0088 substrate; the
    /// probe still reports `vlan_filtering=1` as `NotReady`.
    pub vlans: Vec<KernelBridgeVlanInfo>,
    /// VLAN tunnel mappings observed on the bridge device itself.
    /// Future VLAN-aware support will decide whether these are desired
    /// state; today they are diagnostics only.
    pub vlan_tunnels: Vec<KernelBridgeVlanTunnelInfo>,
    /// VLAN membership/tunnel inventory for bridge-member links that carry
    /// at least one VLAN or tunnel row (members with neither are omitted).
    /// This includes VXLAN and non-VXLAN members so future code can reason
    /// about the VLAN-aware topology without changing the existing AC-gate
    /// `bridge_ports` map.
    pub port_vlan_inventory: Vec<KernelBridgePortVlanInfo>,
}

/// Parsed Linux bridge VLAN flags kept as raw booleans so the snapshot
/// layer remains independent of the netlink crate's bitflags type.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct KernelBridgeVlanFlags {
    /// `BRIDGE_VLAN_INFO_MASTER` / crate `Controller`: operation or row
    /// applies to the bridge device.
    pub controller: bool,
    /// VLAN is the ingress untagged PVID.
    pub pvid: bool,
    /// VLAN egresses untagged.
    pub untagged: bool,
    /// Start of a compressed VLAN range.
    pub range_begin: bool,
    /// End of a compressed VLAN range.
    pub range_end: bool,
    /// Global bridge VLAN entry.
    pub bridge_entry: bool,
    /// Kernel row carries options only.
    pub only_options: bool,
}

/// One `IFLA_BRIDGE_VLAN_INFO` row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KernelBridgeVlanInfo {
    /// VLAN identifier.
    pub vid: u16,
    /// Kernel flags for this row.
    pub flags: KernelBridgeVlanFlags,
}

/// One `IFLA_BRIDGE_VLAN_TUNNEL_INFO` row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KernelBridgeVlanTunnelInfo {
    /// Tunnel ID / VNI, when the kernel reported it.
    pub tunnel_id: Option<u32>,
    /// VLAN identifier, when the kernel reported it.
    pub vid: Option<u16>,
    /// Kernel flags for this tunnel row.
    pub flags: KernelBridgeVlanFlags,
}

/// VLAN inventory observed on one bridge-member link.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KernelBridgePortVlanInfo {
    /// Kernel ifindex of the member link.
    pub ifindex: u32,
    /// Link name if the kernel reported one.
    pub name: Option<String>,
    /// `true` when this member is a VXLAN device.
    pub is_vxlan: bool,
    /// VLAN membership rows for this member.
    pub vlans: Vec<KernelBridgeVlanInfo>,
    /// VLAN tunnel mappings for this member.
    pub vlan_tunnels: Vec<KernelBridgeVlanTunnelInfo>,
}

/// One non-VXLAN bridge port observed in the kernel link inventory,
/// keyed by link name in [`KernelSnapshot::bridge_ports`]. The AC-gate
/// resolver uses this to turn an ADR-0085 `interface` binding into a
/// concrete ifindex + the *observed* port state — the gate diffs
/// desired against observed (not against a remembered plan) because
/// the kernel rewrites the state underneath us: `br_port_carrier_check`
/// re-enables a `BR_STATE_DISABLED` port the moment carrier returns,
/// so a remembered-plan diff would silently leave a non-DF AC
/// forwarding after a carrier flap.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KernelBridgePortInfo {
    /// Kernel ifindex of the port.
    pub ifindex: u32,
    /// Observed `IFLA_BRPORT_STATE` scalar (`BR_STATE_*`: 0 disabled,
    /// 1 listening, 2 learning, 3 forwarding, 4 blocking). `None`
    /// when the kernel dump did not report port state.
    pub state: Option<u8>,
}

/// Properties of a VXLAN port that the probe verifies before treating
/// the instance as Ready.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KernelVxlanInfo {
    /// Kernel ifindex of the VXLAN port itself (not the bridge). The
    /// FDB program path targets this ifindex with `NTF_MASTER` so the
    /// bridge owns the entry — `bridge fdb add MAC dev vxlanX master
    /// dst REMOTE` shape.
    pub ifindex: u32,
    /// Configured VNI on the VXLAN port. The probe checks this matches
    /// the instance VNI.
    pub vni: u32,
    /// Local source IP the VXLAN port encapsulates from. The probe
    /// checks this matches `EvpnInstance::local_vtep_ip`.
    pub local_ip: IpAddr,
    /// Whether `IFLA_VXLAN_LEARNING` was observed in the netlink dump
    /// at all. `None` means the kernel didn't report it (older kernel
    /// or unusual driver) — the probe must fail closed in that case
    /// rather than assume `nolearning`.
    pub learning_disabled: Option<bool>,
}

/// One bridge FDB entry as observed in the kernel.
///
/// Ownership flags are preserved so the diff loop can distinguish
/// rustbgpd-programmed entries (`extern_learn` set) from
/// kernel-learned local entries (dynamic, no `extern_learn`) from
/// operator-static entries (`static`/`permanent`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KernelFdbEntry {
    /// MAC address the entry covers.
    pub mac: MacAddress,
    /// Remote VTEP destination if the entry is a tunnel-encap entry,
    /// `None` for bridge-port-local entries and for FDB rows that
    /// point at an FDB nexthop group via `nh_id`.
    pub dst: Option<IpAddr>,
    /// Kernel nexthop ID this FDB row references (`NDA_NH_ID`), for
    /// ADR-0059 aliasing-ECMP rows. `None` when the row carries
    /// `NDA_DST` instead (single-VTEP rows). Mutually exclusive with
    /// `dst` per `vxlan_fdb_parse` kernel rules.
    pub nh_id: Option<u32>,
    /// `NDA_PROTOCOL` ownership stamp (`rtm_protocol` value space) if
    /// the kernel echoed one back. Mainline `AF_BRIDGE` FDB does not
    /// store the attribute (`rtnl_fdb_add` parses with a NULL policy
    /// and drops it), so on current kernels this is always `None`;
    /// once kernel support lands, the stamp rustbgpd already writes
    /// starts round-tripping and the ADR-0082 prefer-mode check in
    /// [`Self::is_extern_learned`] becomes effective with no flag day.
    pub protocol: Option<u8>,
    /// Coarse-grained ownership flags.
    pub flags: KernelFdbFlags,
}

impl KernelFdbEntry {
    /// `true` if this entry carries rustbgpd's ownership markers:
    /// `extern_learn` set, and — when the kernel reports an
    /// `NDA_PROTOCOL` value — that value equal to `RTPROT_BGP`.
    /// Foreign entries (kernel-learned, operator-static) lack the
    /// flag; a row stamped with another controller's protocol value
    /// (e.g. zebra's 11) is provably not ours regardless of flags
    /// (ADR-0082 prefer mode). Protocol absence keeps the flag-based
    /// rule — current kernels never return the attribute for FDB rows.
    #[must_use]
    pub fn is_extern_learned(&self) -> bool {
        self.flags.extern_learn && self.protocol.is_none_or(|p| p == RTPROT_BGP)
    }

    /// `true` if this entry is dynamic (no static/permanent flags) and
    /// not externally-learned — i.e., the kernel learned it from
    /// data-plane traffic. Diff loop treats these as foreign and
    /// preserves them.
    #[must_use]
    pub fn is_kernel_learned_local(&self) -> bool {
        !self.flags.extern_learn && !self.flags.is_static_or_permanent() && self.dst.is_none()
    }
}

/// Coarse-grained FDB-entry ownership flags.
///
/// The Phase 4 netlink impl populates these from the netlink
/// `NeighbourFlags` (`NTF_*`) and `NeighbourState` (`NUD_*`) fields.
/// Phase 2 wires only what the diff loop reads. Each field maps 1:1 to
/// a kernel flag bit, so refactoring into a state enum would lose the
/// direct correspondence we need at the netlink boundary.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct KernelFdbFlags {
    /// `NTF_EXT_LEARNED` — set by rustbgpd on entries it programs.
    pub extern_learn: bool,
    /// `NUD_PERMANENT` — operator manually set the entry; never
    /// auto-aged. We never delete these.
    pub permanent: bool,
    /// `NUD_NOARP` (used as a "static" marker for FDB entries) — same
    /// as permanent for our purposes, but distinct on the wire.
    pub noarp: bool,
    /// `NTF_MASTER` — bridge-owned entry (vs. `NTF_SELF` device-local).
    /// rustbgpd's remote-MAC entries are always `master`-routed.
    pub master: bool,
    /// `NTF_SELF` — device-local entry. We never program these in
    /// Gate 7b; foreign `self` entries are preserved.
    pub self_flag: bool,
}

impl KernelFdbFlags {
    /// `true` if any "operator-set, never auto-age" flag is set.
    #[must_use]
    pub fn is_static_or_permanent(self) -> bool {
        self.permanent || self.noarp
    }
}

/// Per-instance readiness probe results — what the dataplane actor's
/// link/probe pass discovered about the operator-built bridge/VXLAN
/// topology.
///
/// Instances missing from the probe map default to `NotReady` in the
/// diff loop (treated as "we have not validated this instance yet").
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct InstanceProbes {
    by_vni: BTreeMap<EvpnInstanceId, InstanceProbe>,
    bridge_macs: BTreeMap<EvpnInstanceId, MacAddress>,
}

impl InstanceProbes {
    /// Empty probe map — every instance defaults to `NotReady`.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record one instance's probe result.
    pub fn insert(&mut self, vni: EvpnInstanceId, probe: InstanceProbe) {
        self.by_vni.insert(vni, probe);
    }

    /// Record the kernel-reported bridge MAC for one instance. Surfaced
    /// to the daemon on `InstanceDataplaneStatus.bridge_mac` for the
    /// SVI-MAC origination path (RFC 9135 §6.1) — Linux observes,
    /// daemon decides whether to originate.
    pub fn set_bridge_mac(&mut self, vni: EvpnInstanceId, mac: MacAddress) {
        self.bridge_macs.insert(vni, mac);
    }

    /// `true` if the instance has been probed and passed all checks.
    #[must_use]
    pub fn is_ready(&self, vni: EvpnInstanceId) -> bool {
        matches!(self.by_vni.get(&vni), Some(InstanceProbe::Ready))
    }

    /// Look up a single probe.
    #[must_use]
    pub fn get(&self, vni: EvpnInstanceId) -> Option<&InstanceProbe> {
        self.by_vni.get(&vni)
    }

    /// Look up the bridge MAC for one instance, if the dataplane saw
    /// a six-octet link-layer address on the bridge.
    #[must_use]
    pub fn bridge_mac(&self, vni: EvpnInstanceId) -> Option<MacAddress> {
        self.bridge_macs.get(&vni).copied()
    }

    /// Iterate probe results in deterministic VNI ascending order.
    pub fn iter(&self) -> impl Iterator<Item = (EvpnInstanceId, &InstanceProbe)> {
        self.by_vni.iter().map(|(&vni, p)| (vni, p))
    }
}

/// Outcome of probing one EVPN instance against the kernel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InstanceProbe {
    /// All probe checks passed. Remote MACs for this instance can be
    /// programmed.
    Ready,
    /// Probe failed. The accompanying message is operator-facing.
    NotReady {
        /// Why the probe failed (e.g., "bridge br100 not found", "VXLAN
        /// VNI mismatch: expected 100, found 200", "VLAN-aware bridges
        /// not supported in Gate 7b").
        reason: String,
    },
    /// Instance has `bridge = None` — no probe applies.
    Unbound,
}

/// Snapshot of every kernel FDB entry the dataplane is interested in,
/// keyed by `(VNI, MAC)`. The Linux netlink dump derives the VNI from
/// the FDB entry's **VXLAN-port** ifindex (which is what bridge-family
/// `RTM_NEWNEIGH` messages carry in `header.ifindex`) by looking it
/// up in the link cache's `vxlan_ifindex_to_vni` table.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KernelSnapshot {
    fdb: BTreeMap<(EvpnInstanceId, MacAddress), KernelFdbEntry>,
    /// Per-bridge link info, indexed by bridge name. Used by the probe
    /// pass; the diff function itself does not read this.
    pub links: BTreeMap<String, KernelLinkInfo>,
    /// Non-VXLAN bridge ports by link name, with observed
    /// `IFLA_BRPORT_STATE`. Consumed by the single-active AC-gate
    /// resolver (`crate::ac_gate`) to map an ADR-0085 `interface`
    /// binding onto a concrete port.
    pub bridge_ports: BTreeMap<String, KernelBridgePortInfo>,
}

impl KernelSnapshot {
    /// Empty snapshot.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert (or overwrite) a kernel FDB entry.
    pub fn insert_fdb(&mut self, vni: EvpnInstanceId, entry: KernelFdbEntry) {
        self.fdb.insert((vni, entry.mac), entry);
    }

    /// Remove an FDB entry, returning the previous value if any. Used
    /// by [`crate::InMemoryDataplane`] to simulate kernel-side
    /// withdrawals.
    pub fn remove_fdb(&mut self, vni: EvpnInstanceId, mac: MacAddress) -> Option<KernelFdbEntry> {
        self.fdb.remove(&(vni, mac))
    }

    /// Look up a single FDB entry.
    #[must_use]
    pub fn find_fdb(&self, vni: EvpnInstanceId, mac: MacAddress) -> Option<&KernelFdbEntry> {
        self.fdb.get(&(vni, mac))
    }

    /// Iterate FDB entries in deterministic `(VNI, MAC)` ascending
    /// order.
    pub fn iter_fdb(
        &self,
    ) -> impl Iterator<Item = (&(EvpnInstanceId, MacAddress), &KernelFdbEntry)> {
        self.fdb.iter()
    }

    /// Number of FDB entries in the snapshot.
    #[must_use]
    pub fn fdb_len(&self) -> usize {
        self.fdb.len()
    }

    /// Replace the link inventory wholesale.
    pub fn set_links(&mut self, links: BTreeMap<String, KernelLinkInfo>) {
        self.links = links;
    }

    /// Add a single bridge to the link inventory (test convenience).
    pub fn insert_link(&mut self, info: KernelLinkInfo) {
        self.links.insert(info.bridge_name.clone(), info);
    }

    /// Add (or overwrite) one named bridge port. Used by the Linux
    /// dump and by tests staging AC-gate state.
    pub fn insert_bridge_port(&mut self, name: &str, ifindex: u32, state: Option<u8>) {
        self.bridge_ports
            .insert(name.to_string(), KernelBridgePortInfo { ifindex, state });
    }
}

/// Set of `(VNI, MAC)` keys rustbgpd has successfully programmed and
/// has not yet successfully removed.
///
/// The diff loop's delete pass iterates *this* set rather than the
/// kernel snapshot — that's how foreign-entry preservation becomes a
/// structural invariant. An entry is added on successful apply and
/// removed on successful withdraw.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OwnedSet {
    entries: BTreeMap<(EvpnInstanceId, MacAddress), OwnedEntry>,
}

impl OwnedSet {
    /// Empty owned set — the actor's startup state.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of entries currently considered programmed.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// `true` if no entries are programmed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Record a successful program / update for `(vni, mac)`.
    pub fn record_applied(&mut self, vni: EvpnInstanceId, mac: MacAddress, entry: OwnedEntry) {
        self.entries.insert((vni, mac), entry);
    }

    /// Drop an entry on successful withdraw.
    pub fn record_withdrawn(&mut self, vni: EvpnInstanceId, mac: MacAddress) -> Option<OwnedEntry> {
        self.entries.remove(&(vni, mac))
    }

    /// `true` if the actor previously programmed this `(vni, mac)`
    /// and hasn't since withdrawn it.
    #[must_use]
    pub fn contains(&self, vni: EvpnInstanceId, mac: MacAddress) -> bool {
        self.entries.contains_key(&(vni, mac))
    }

    /// Look up the recorded entry for an owned `(vni, mac)`.
    #[must_use]
    pub fn get(&self, vni: EvpnInstanceId, mac: MacAddress) -> Option<&OwnedEntry> {
        self.entries.get(&(vni, mac))
    }

    /// Iterate the owned set in deterministic `(VNI, MAC)` ascending
    /// order. The delete pass uses this iterator.
    pub fn iter(&self) -> impl Iterator<Item = (&(EvpnInstanceId, MacAddress), &OwnedEntry)> {
        self.entries.iter()
    }

    /// Set of all currently-owned `(vni, mac)` keys. Test helper.
    #[must_use]
    pub fn keys(&self) -> BTreeSet<(EvpnInstanceId, MacAddress)> {
        self.entries.keys().copied().collect()
    }
}

/// What rustbgpd remembers about each entry it programmed.
///
/// The kind variant lets the diff loop distinguish single-dst entries
/// (which carry an applied VTEP IP + mobility sequence) from FDB-NHG
/// entries (which carry the alias group identity instead). Invalid
/// states like `dst=X AND group_key=Some(...)` are unrepresentable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnedEntry {
    pub kind: OwnedEntryKind,
}

/// Variant payload for an [`OwnedEntry`]. ADR-0059 slice 3 distinguishes
/// single-VTEP FDB rows (`SingleDst`) from FDB-NHG rows (`FdbNhg`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OwnedEntryKind {
    /// Single-VTEP FDB row programmed via `RTM_NEWNEIGH` with `NDA_DST`.
    SingleDst {
        /// VTEP IP we last successfully programmed for this `(vni, mac)`.
        dst: IpAddr,
        /// Mobility sequence recorded at apply time, if the route
        /// carried one. Lets a stale lower-seq snapshot avoid
        /// triggering pointless updates.
        mobility_seq: Option<u32>,
    },
    /// FDB-NHG row programmed via `RTM_NEWNEIGH` with `NDA_NH_ID`. The
    /// `group_key` identifies the Linux-owned `(VNI, ESI, EthernetTag)`
    /// tuple whose kernel `nh_id` this FDB row references. Mobility
    /// for multi-homed entries lives at the projection layer (which
    /// picks the winning Type 2 for a given MAC) — the group key
    /// reflects whatever that winning Type 2 carries.
    FdbNhg {
        group_key: crate::group_state::AliasGroupKey,
    },
}

impl OwnedEntry {
    /// Convenience constructor for a single-VTEP entry. Existing
    /// pre-slice-3 callers use this shape; FDB-NHG callers construct
    /// `OwnedEntry { kind: FdbNhg { ... } }` directly.
    #[must_use]
    pub fn single_dst(dst: IpAddr, mobility_seq: Option<u32>) -> Self {
        Self {
            kind: OwnedEntryKind::SingleDst { dst, mobility_seq },
        }
    }

    /// Convenience constructor for an FDB-NHG entry.
    #[must_use]
    pub fn fdb_nhg(group_key: crate::group_state::AliasGroupKey) -> Self {
        Self {
            kind: OwnedEntryKind::FdbNhg { group_key },
        }
    }

    /// Last-applied destination if this entry is a single-dst one.
    /// `None` for FDB-NHG entries.
    #[must_use]
    pub fn last_applied_dst(&self) -> Option<IpAddr> {
        match self.kind {
            OwnedEntryKind::SingleDst { dst, .. } => Some(dst),
            OwnedEntryKind::FdbNhg { .. } => None,
        }
    }

    /// Last-applied mobility sequence if this entry is a single-dst
    /// one. `None` for FDB-NHG entries (mobility is decided at the
    /// projection layer for those).
    #[must_use]
    pub fn last_applied_seq(&self) -> Option<u32> {
        match self.kind {
            OwnedEntryKind::SingleDst { mobility_seq, .. } => mobility_seq,
            OwnedEntryKind::FdbNhg { .. } => None,
        }
    }

    /// Alias group key if this entry is FDB-NHG. `None` for single-dst.
    #[must_use]
    pub fn group_key(&self) -> Option<crate::group_state::AliasGroupKey> {
        match self.kind {
            OwnedEntryKind::SingleDst { .. } => None,
            OwnedEntryKind::FdbNhg { group_key } => Some(group_key),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vni(n: u32) -> EvpnInstanceId {
        EvpnInstanceId::new(n).unwrap()
    }
    fn mac(b: u8) -> MacAddress {
        MacAddress::new([b; 6])
    }
    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn extern_learned_classification() {
        let entry = KernelFdbEntry {
            mac: mac(1),
            dst: Some(ip("10.0.0.2")),
            nh_id: None,
            protocol: None,
            flags: KernelFdbFlags {
                extern_learn: true,
                master: true,
                ..Default::default()
            },
        };
        assert!(entry.is_extern_learned());
        assert!(!entry.is_kernel_learned_local());
    }

    #[test]
    fn kernel_learned_local_classification() {
        // No extern_learn, no static/permanent, no dst (bridge-port
        // local) — the kernel learned this from data-plane traffic.
        let entry = KernelFdbEntry {
            mac: mac(2),
            dst: None,
            nh_id: None,
            protocol: None,
            flags: KernelFdbFlags::default(),
        };
        assert!(!entry.is_extern_learned());
        assert!(entry.is_kernel_learned_local());
    }

    #[test]
    fn foreign_protocol_stamp_disqualifies_extern_learn() {
        // ADR-0082 prefer mode: a kernel-echoed NDA_PROTOCOL value
        // other than RTPROT_BGP proves another controller owns the
        // row (zebra stamps 11), so `extern_learn` alone no longer
        // claims it. Our own stamp (186) keeps the classification.
        let mut entry = KernelFdbEntry {
            mac: mac(1),
            dst: Some(ip("10.0.0.2")),
            nh_id: None,
            protocol: Some(11), // RTPROT_ZEBRA
            flags: KernelFdbFlags {
                extern_learn: true,
                master: true,
                ..Default::default()
            },
        };
        assert!(!entry.is_extern_learned());
        assert!(!entry.is_kernel_learned_local());

        entry.protocol = Some(186); // RTPROT_BGP — ours
        assert!(entry.is_extern_learned());
    }

    #[test]
    fn operator_static_is_neither_ours_nor_kernel_learned() {
        let entry = KernelFdbEntry {
            mac: mac(3),
            dst: None,
            nh_id: None,
            protocol: None,
            flags: KernelFdbFlags {
                permanent: true,
                ..Default::default()
            },
        };
        assert!(!entry.is_extern_learned());
        assert!(!entry.is_kernel_learned_local());
    }

    #[test]
    fn instance_probe_ready_lookup() {
        let mut probes = InstanceProbes::new();
        probes.insert(vni(100), InstanceProbe::Ready);
        probes.insert(
            vni(200),
            InstanceProbe::NotReady {
                reason: "bridge missing".into(),
            },
        );
        assert!(probes.is_ready(vni(100)));
        assert!(!probes.is_ready(vni(200)));
        assert!(!probes.is_ready(vni(300))); // unprobed = not ready
    }

    #[test]
    fn owned_set_round_trip() {
        let mut owned = OwnedSet::new();
        assert!(owned.is_empty());
        owned.record_applied(
            vni(100),
            mac(1),
            OwnedEntry::single_dst(ip("10.0.0.2"), Some(0)),
        );
        assert!(owned.contains(vni(100), mac(1)));
        assert_eq!(owned.len(), 1);
        let prev = owned.record_withdrawn(vni(100), mac(1)).unwrap();
        assert_eq!(prev.last_applied_dst(), Some(ip("10.0.0.2")));
        assert!(owned.is_empty());
    }

    #[test]
    fn snapshot_round_trip() {
        let mut snap = KernelSnapshot::new();
        snap.insert_fdb(
            vni(100),
            KernelFdbEntry {
                mac: mac(1),
                dst: Some(ip("10.0.0.2")),
                nh_id: None,
                protocol: None,
                flags: KernelFdbFlags {
                    extern_learn: true,
                    master: true,
                    ..Default::default()
                },
            },
        );
        let entry = snap.find_fdb(vni(100), mac(1)).unwrap();
        assert_eq!(entry.dst, Some(ip("10.0.0.2")));
        assert_eq!(snap.fdb_len(), 1);
        assert!(snap.find_fdb(vni(100), mac(2)).is_none());
    }

    #[test]
    fn snapshot_iteration_is_vni_ascending() {
        let mut snap = KernelSnapshot::new();
        for v in [300u32, 100, 200] {
            snap.insert_fdb(
                vni(v),
                KernelFdbEntry {
                    mac: mac(1),
                    dst: Some(ip("10.0.0.2")),
                    nh_id: None,
                    protocol: None,
                    flags: KernelFdbFlags::default(),
                },
            );
        }
        let order: Vec<u32> = snap.iter_fdb().map(|((v, _), _)| v.as_u32()).collect();
        assert_eq!(order, vec![100, 200, 300]);
    }
}
