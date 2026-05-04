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

/// Bridge / VXLAN link inventory entry.
///
/// Phase 2 holds only the fields the diff loop and per-instance probe
/// need today; Phase 4 (the real netlink impl) extends with admin/oper
/// state and bridge aging time as those become relevant.
#[derive(Debug, Clone, PartialEq, Eq)]
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
}

/// Properties of a VXLAN port that the probe verifies before treating
/// the instance as Ready.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KernelVxlanInfo {
    /// Configured VNI on the VXLAN port. The probe checks this matches
    /// the instance VNI.
    pub vni: u32,
    /// Local source IP the VXLAN port encapsulates from. The probe
    /// checks this matches `EvpnInstance::local_vtep_ip`.
    pub local_ip: IpAddr,
    /// `true` if the VXLAN port has kernel learning *disabled*. EVPN
    /// requires `nolearning` so the control plane owns the FDB.
    pub learning_disabled: bool,
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
    /// `None` for bridge-port-local entries.
    pub dst: Option<IpAddr>,
    /// Coarse-grained ownership flags.
    pub flags: KernelFdbFlags,
}

impl KernelFdbEntry {
    /// `true` if this entry has `extern_learn` set — the marker
    /// rustbgpd uses to denote "this entry was programmed by us".
    /// Foreign entries (kernel-learned, operator-static) do not have
    /// this flag.
    #[must_use]
    pub fn is_extern_learned(&self) -> bool {
        self.flags.extern_learn
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
/// keyed by `(VNI, MAC)`. Phase 4 derives the VNI from the FDB entry's
/// `master` ifindex via the link inventory.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KernelSnapshot {
    fdb: BTreeMap<(EvpnInstanceId, MacAddress), KernelFdbEntry>,
    /// Per-bridge link info, indexed by bridge name. Used by the probe
    /// pass; the diff function itself does not read this.
    pub links: BTreeMap<String, KernelLinkInfo>,
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
/// `last_applied_dst` lets the diff loop detect "we programmed dst=X,
/// kernel snapshot now shows dst=Y" — the actor re-issues the program
/// to bring the kernel back in sync. `last_applied_seq` carries the
/// MAC mobility sequence so a stale lower-seq snapshot doesn't trigger
/// pointless updates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnedEntry {
    /// VTEP IP we last successfully programmed for this `(vni, mac)`.
    pub last_applied_dst: IpAddr,
    /// Mobility sequence we recorded at apply time, if the route
    /// carried one.
    pub last_applied_seq: Option<u32>,
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
            flags: KernelFdbFlags::default(),
        };
        assert!(!entry.is_extern_learned());
        assert!(entry.is_kernel_learned_local());
    }

    #[test]
    fn operator_static_is_neither_ours_nor_kernel_learned() {
        let entry = KernelFdbEntry {
            mac: mac(3),
            dst: None,
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
            OwnedEntry {
                last_applied_dst: ip("10.0.0.2"),
                last_applied_seq: Some(0),
            },
        );
        assert!(owned.contains(vni(100), mac(1)));
        assert_eq!(owned.len(), 1);
        let prev = owned.record_withdrawn(vni(100), mac(1)).unwrap();
        assert_eq!(prev.last_applied_dst, ip("10.0.0.2"));
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
                    flags: KernelFdbFlags::default(),
                },
            );
        }
        let order: Vec<u32> = snap.iter_fdb().map(|((v, _), _)| v.as_u32()).collect();
        assert_eq!(order, vec![100, 200, 300]);
    }
}
