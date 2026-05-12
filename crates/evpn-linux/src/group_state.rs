//! Owned-state tracking for FDB nexthop groups (ADR-0059 slice 3).
//!
//! Three coordinating maps the reconcile actor maintains:
//!
//! 1. **Groups** keyed by `AliasGroupKey = (VNI, ESI, EthernetTag)`.
//!    Each group tracks its kernel `id`, the canonical member set
//!    last applied, and the set of `(VNI, MAC)` rows referencing it.
//! 2. **Per-VTEP nexthops** keyed by `IpAddr`. Each one tracks its
//!    kernel `id` and the set of groups referencing it.
//! 3. Refcount semantics: groups install on the first MAC that
//!    references them, tear down on the last unref. Per-VTEP NHs
//!    tear down only when their group-ref set hits empty.
//!
//! **Why VNI in the group key:** ADR-0059 §7's `share_l2_nhg` knob
//! defaults off, so two L2VNIs that happen to share `(ESI,
//! EthernetTag)` get separate kernel groups in slice 3. The portable
//! wire-facing key on `RemoteMacEntry::alias_group_key` stays
//! `(ESI, EthernetTag)` per slice 1; this dataplane-owned key extends
//! it with VNI. When `share_l2_nhg` lands, the key collapses for
//! instances opting in.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use rustbgpd_evpn::{EthernetSegmentIdentifier, EthernetTagId, EvpnInstanceId, MacAddress};

/// Dataplane-owned group identity. Distinct from the portable
/// `RemoteMacEntry::alias_group_key` (which is `(ESI, EthernetTag)`
/// without VNI) — see module-level docs for why.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AliasGroupKey {
    pub vni: EvpnInstanceId,
    pub esi: EthernetSegmentIdentifier,
    pub ethernet_tag: EthernetTagId,
}

impl AliasGroupKey {
    #[must_use]
    pub fn new(
        vni: EvpnInstanceId,
        esi: EthernetSegmentIdentifier,
        ethernet_tag: EthernetTagId,
    ) -> Self {
        Self {
            vni,
            esi,
            ethernet_tag,
        }
    }
}

/// One FDB nexthop group installed in the kernel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupOwned {
    /// Kernel nexthop ID (tagged via [`crate::nh_id_alloc::NHG_TAG`]).
    pub id: u32,
    /// Canonical sorted+deduped VTEP IP member set, last successfully
    /// applied to the kernel. `BTreeSet` for deterministic ordering.
    pub members: BTreeSet<IpAddr>,
    /// The `(VNI, MAC)` rows whose FDB entries reference this group's
    /// kernel ID via `NDA_NH_ID`.
    pub ref_macs: BTreeSet<(EvpnInstanceId, MacAddress)>,
}

/// One per-VTEP FDB nexthop installed in the kernel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VtepNh {
    /// Kernel nexthop ID (tagged via
    /// [`crate::nh_id_alloc::VTEP_NH_TAG`]).
    pub id: u32,
    /// Groups that reference this per-VTEP NH as a member.
    pub ref_groups: BTreeSet<AliasGroupKey>,
}

/// Result of unref'ing a group on `RemoveFdbNhg` apply — tells the
/// caller what kernel cleanup is required.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RefDelta {
    /// The group still has other MACs referencing it; nothing else
    /// to tear down.
    GroupStillReferenced,
    /// Last MAC unref'd. Caller should delete the group from the
    /// kernel and unref each member; per-VTEP NHs whose ref count
    /// hits zero (reported via [`GroupOwnedMap::record_member_unref`])
    /// should themselves be deleted.
    GroupShouldDelete { id: u32, members: Vec<IpAddr> },
}

/// Coordinated state for the FDB-NHG dataplane.
#[derive(Debug, Default, Clone)]
pub struct GroupOwnedMap {
    groups: BTreeMap<AliasGroupKey, GroupOwned>,
    vtep_nhs: BTreeMap<IpAddr, VtepNh>,
}

impl GroupOwnedMap {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Look up a group by key.
    #[must_use]
    pub fn group(&self, key: &AliasGroupKey) -> Option<&GroupOwned> {
        self.groups.get(key)
    }

    /// Look up a per-VTEP NH by gateway IP.
    #[must_use]
    pub fn vtep_nh(&self, ip: &IpAddr) -> Option<&VtepNh> {
        self.vtep_nhs.get(ip)
    }

    /// `true` if no groups and no per-VTEP NHs are tracked.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.groups.is_empty() && self.vtep_nhs.is_empty()
    }

    /// Number of tracked groups.
    #[must_use]
    pub fn group_count(&self) -> usize {
        self.groups.len()
    }

    /// Number of tracked per-VTEP NHs.
    #[must_use]
    pub fn vtep_nh_count(&self) -> usize {
        self.vtep_nhs.len()
    }

    /// Record a successful per-VTEP NH install. Idempotent.
    pub fn record_member_install(&mut self, ip: IpAddr, id: u32) {
        self.vtep_nhs.entry(ip).or_insert_with(|| VtepNh {
            id,
            ref_groups: BTreeSet::new(),
        });
    }

    /// Record a successful group install with its initial canonical
    /// members. Each member's `ref_groups` set gets `group_key` added.
    pub fn record_group_install(&mut self, key: AliasGroupKey, id: u32, members: BTreeSet<IpAddr>) {
        for ip in &members {
            if let Some(vtep) = self.vtep_nhs.get_mut(ip) {
                vtep.ref_groups.insert(key);
            }
        }
        self.groups.insert(
            key,
            GroupOwned {
                id,
                members,
                ref_macs: BTreeSet::new(),
            },
        );
    }

    /// Record a member-set change for an existing group. Returns the
    /// IPs removed from the group (caller decrements their per-VTEP
    /// refcounts via [`Self::record_member_unref`]).
    pub fn record_group_member_change(
        &mut self,
        key: AliasGroupKey,
        new_members: BTreeSet<IpAddr>,
    ) -> Vec<IpAddr> {
        let Some(group) = self.groups.get_mut(&key) else {
            // No group recorded → nothing to update; record_group_install handles fresh case.
            return Vec::new();
        };
        let added: Vec<IpAddr> = new_members.difference(&group.members).copied().collect();
        let removed: Vec<IpAddr> = group.members.difference(&new_members).copied().collect();

        for ip in &added {
            if let Some(vtep) = self.vtep_nhs.get_mut(ip) {
                vtep.ref_groups.insert(key);
            }
        }
        for ip in &removed {
            if let Some(vtep) = self.vtep_nhs.get_mut(ip) {
                vtep.ref_groups.remove(&key);
            }
        }
        group.members = new_members;
        removed
    }

    /// Record a MAC referencing an existing group. Idempotent.
    pub fn record_mac_ref(&mut self, key: AliasGroupKey, vni: EvpnInstanceId, mac: MacAddress) {
        if let Some(group) = self.groups.get_mut(&key) {
            group.ref_macs.insert((vni, mac));
        }
    }

    /// Unref a MAC from a group. Returns [`RefDelta`] describing what
    /// the caller needs to tear down (group + members if refcount
    /// hits 0). Removes the group from the map when its `ref_macs`
    /// empties.
    pub fn record_mac_unref(
        &mut self,
        key: AliasGroupKey,
        vni: EvpnInstanceId,
        mac: MacAddress,
    ) -> RefDelta {
        let Some(group) = self.groups.get_mut(&key) else {
            // Group never installed (e.g., racing withdraw); nothing to do.
            return RefDelta::GroupStillReferenced;
        };
        group.ref_macs.remove(&(vni, mac));
        if !group.ref_macs.is_empty() {
            return RefDelta::GroupStillReferenced;
        }
        // Last ref — remove the group entry and report cleanup work.
        let id = group.id;
        let members: Vec<IpAddr> = group.members.iter().copied().collect();
        self.groups.remove(&key);
        // Unref each member's ref_groups set (the caller will follow up
        // with record_member_unref to discover which need kernel deletion).
        for ip in &members {
            if let Some(vtep) = self.vtep_nhs.get_mut(ip) {
                vtep.ref_groups.remove(&key);
            }
        }
        RefDelta::GroupShouldDelete { id, members }
    }

    /// Unref a per-VTEP NH from a group. Returns `Some(id)` if the
    /// VTEP NH's ref-group set hit empty (caller must delete the NH
    /// from the kernel and release the allocator slot); returns
    /// `None` if other groups still reference it.
    ///
    /// Called after [`Self::record_mac_unref`] has already cleared
    /// the `group_key` from each member's `ref_groups` — this exists for
    /// **explicit** unref by callers that didn't go through
    /// [`Self::record_mac_unref`] (e.g., member-set shrink).
    pub fn record_member_unref(&mut self, ip: IpAddr, key: AliasGroupKey) -> Option<u32> {
        let vtep = self.vtep_nhs.get_mut(&ip)?;
        vtep.ref_groups.remove(&key);
        if vtep.ref_groups.is_empty() {
            let id = vtep.id;
            self.vtep_nhs.remove(&ip);
            Some(id)
        } else {
            None
        }
    }

    /// Check if a per-VTEP NH's ref-group set is currently empty
    /// (caller hasn't followed up with [`Self::record_member_unref`]).
    /// Used by `record_mac_unref` callers to GC orphan members after
    /// a `GroupShouldDelete` decision.
    #[must_use]
    pub fn vtep_nh_is_orphan(&self, ip: &IpAddr) -> bool {
        self.vtep_nhs
            .get(ip)
            .is_some_and(|v| v.ref_groups.is_empty())
    }

    /// Remove an orphaned per-VTEP NH from tracking. Caller already
    /// deleted the kernel object and released the allocator slot.
    pub fn drop_vtep_nh(&mut self, ip: &IpAddr) -> Option<u32> {
        self.vtep_nhs.remove(ip).map(|v| v.id)
    }

    /// Iterate all groups (deterministic order by key).
    pub fn iter_groups(&self) -> impl Iterator<Item = (&AliasGroupKey, &GroupOwned)> {
        self.groups.iter()
    }

    /// Iterate all per-VTEP NHs.
    pub fn iter_vtep_nhs(&self) -> impl Iterator<Item = (&IpAddr, &VtepNh)> {
        self.vtep_nhs.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vni(n: u32) -> EvpnInstanceId {
        EvpnInstanceId::new(n).expect("test VNI")
    }
    fn esi(seed: u8) -> EthernetSegmentIdentifier {
        EthernetSegmentIdentifier::new([seed; 10])
    }
    fn mac(b: u8) -> MacAddress {
        MacAddress::new([b; 6])
    }
    fn ipa(s: &str) -> IpAddr {
        s.parse().unwrap()
    }
    fn key(v: u32, e: u8, t: u32) -> AliasGroupKey {
        AliasGroupKey::new(vni(v), esi(e), EthernetTagId(t))
    }

    /// Helper to set up a one-MAC group with two members already
    /// installed. Mirrors the apply sequence the reconcile actor
    /// would do for a fresh `InstallFdbNhg`.
    fn install_one_mac_two_members(map: &mut GroupOwnedMap) -> AliasGroupKey {
        let k = key(100, 7, 0);
        map.record_member_install(ipa("10.0.0.2"), 0x3000_0001);
        map.record_member_install(ipa("10.0.0.3"), 0x3000_0002);
        let mut members = BTreeSet::new();
        members.insert(ipa("10.0.0.2"));
        members.insert(ipa("10.0.0.3"));
        map.record_group_install(k, 0x4000_0001, members);
        map.record_mac_ref(k, vni(100), mac(1));
        k
    }

    #[test]
    fn single_mac_install_then_remove_tears_down_group() {
        let mut map = GroupOwnedMap::new();
        let k = install_one_mac_two_members(&mut map);

        assert_eq!(map.group_count(), 1);
        assert_eq!(map.vtep_nh_count(), 2);
        assert_eq!(map.group(&k).unwrap().ref_macs.len(), 1);

        let delta = map.record_mac_unref(k, vni(100), mac(1));
        match delta {
            RefDelta::GroupShouldDelete { id, ref members } => {
                assert_eq!(id, 0x4000_0001);
                assert_eq!(members.len(), 2);
            }
            RefDelta::GroupStillReferenced => {
                panic!("expected GroupShouldDelete, got GroupStillReferenced")
            }
        }
        assert!(map.group(&k).is_none(), "group should be removed");
        // Members should now be orphans (caller GCs them).
        assert!(map.vtep_nh_is_orphan(&ipa("10.0.0.2")));
        assert!(map.vtep_nh_is_orphan(&ipa("10.0.0.3")));

        map.drop_vtep_nh(&ipa("10.0.0.2"));
        map.drop_vtep_nh(&ipa("10.0.0.3"));
        assert!(map.is_empty());
    }

    #[test]
    fn two_macs_share_group_first_remove_keeps_group() {
        let mut map = GroupOwnedMap::new();
        let k = install_one_mac_two_members(&mut map);
        map.record_mac_ref(k, vni(100), mac(2)); // second MAC same group

        let delta = map.record_mac_unref(k, vni(100), mac(1));
        assert_eq!(delta, RefDelta::GroupStillReferenced);
        assert_eq!(map.group(&k).unwrap().ref_macs.len(), 1);
        assert!(
            map.group(&k)
                .unwrap()
                .ref_macs
                .contains(&(vni(100), mac(2)))
        );
    }

    #[test]
    fn second_remove_after_share_tears_down_group() {
        let mut map = GroupOwnedMap::new();
        let k = install_one_mac_two_members(&mut map);
        map.record_mac_ref(k, vni(100), mac(2));

        let _ = map.record_mac_unref(k, vni(100), mac(1));
        let delta = map.record_mac_unref(k, vni(100), mac(2));
        assert!(matches!(delta, RefDelta::GroupShouldDelete { .. }));
        assert!(map.group(&k).is_none());
    }

    #[test]
    fn member_set_shrink_returns_removed_and_keeps_others() {
        let mut map = GroupOwnedMap::new();
        let k = install_one_mac_two_members(&mut map);

        // Drain 10.0.0.3 (N=2 → N=1).
        let mut new_members = BTreeSet::new();
        new_members.insert(ipa("10.0.0.2"));
        let removed = map.record_group_member_change(k, new_members);
        assert_eq!(removed, vec![ipa("10.0.0.3")]);
        assert_eq!(map.group(&k).unwrap().members.len(), 1);
        // 10.0.0.3 is no longer ref'd by this group → it's an orphan.
        assert!(map.vtep_nh_is_orphan(&ipa("10.0.0.3")));
        // 10.0.0.2 still ref'd.
        assert!(!map.vtep_nh_is_orphan(&ipa("10.0.0.2")));
    }

    #[test]
    fn n_to_1_drain_keeps_group_alive() {
        let mut map = GroupOwnedMap::new();
        let k = install_one_mac_two_members(&mut map);

        let mut new_members = BTreeSet::new();
        new_members.insert(ipa("10.0.0.2"));
        let _ = map.record_group_member_change(k, new_members);

        // Group still here at 1 member — N→1 lifecycle invariant 4.
        let group = map.group(&k).expect("group still installed");
        assert_eq!(group.members.len(), 1);
        assert_eq!(group.id, 0x4000_0001, "id unchanged across replace");
        // ref_macs untouched.
        assert_eq!(group.ref_macs.len(), 1);
    }

    #[test]
    fn vtep_nh_shared_across_groups_only_torn_down_at_ref_zero() {
        let mut map = GroupOwnedMap::new();
        let ka = key(100, 7, 0);
        let kb = key(100, 8, 0);

        // Install 10.0.0.2 once; share between two groups.
        map.record_member_install(ipa("10.0.0.2"), 0x3000_0001);
        map.record_member_install(ipa("10.0.0.3"), 0x3000_0002);

        let mut members_a = BTreeSet::new();
        members_a.insert(ipa("10.0.0.2"));
        members_a.insert(ipa("10.0.0.3"));
        map.record_group_install(ka, 0x4000_0001, members_a);

        let mut members_b = BTreeSet::new();
        members_b.insert(ipa("10.0.0.2")); // shared VTEP
        map.record_group_install(kb, 0x4000_0002, members_b);

        map.record_mac_ref(ka, vni(100), mac(1));
        map.record_mac_ref(kb, vni(100), mac(2));

        // Unref MAC 1 → group A torn down.
        let delta = map.record_mac_unref(ka, vni(100), mac(1));
        assert!(matches!(delta, RefDelta::GroupShouldDelete { .. }));

        // 10.0.0.2 still ref'd by group B → NOT orphan.
        assert!(!map.vtep_nh_is_orphan(&ipa("10.0.0.2")));
        // 10.0.0.3 only ref'd by group A → IS orphan now.
        assert!(map.vtep_nh_is_orphan(&ipa("10.0.0.3")));

        // Now unref MAC 2 → group B torn down → 10.0.0.2 becomes orphan.
        let _ = map.record_mac_unref(kb, vni(100), mac(2));
        assert!(map.vtep_nh_is_orphan(&ipa("10.0.0.2")));
    }

    #[test]
    fn member_set_change_does_not_touch_unrelated_groups() {
        let mut map = GroupOwnedMap::new();
        let ka = install_one_mac_two_members(&mut map);
        let kb = key(200, 8, 0);

        // Install an unrelated group B.
        map.record_member_install(ipa("10.0.0.4"), 0x3000_0003);
        let mut members_b = BTreeSet::new();
        members_b.insert(ipa("10.0.0.4"));
        map.record_group_install(kb, 0x4000_0002, members_b);
        map.record_mac_ref(kb, vni(200), mac(5));

        // Shrink group A members.
        let mut new_a = BTreeSet::new();
        new_a.insert(ipa("10.0.0.2"));
        let _ = map.record_group_member_change(ka, new_a);

        // Group B untouched.
        let b = map.group(&kb).expect("group B still here");
        assert_eq!(
            b.members.iter().copied().collect::<Vec<_>>(),
            vec![ipa("10.0.0.4")]
        );
        assert_eq!(b.ref_macs.len(), 1);
    }

    #[test]
    fn record_mac_unref_on_missing_group_is_safe() {
        let mut map = GroupOwnedMap::new();
        let k = key(100, 99, 0);
        let delta = map.record_mac_unref(k, vni(100), mac(1));
        assert_eq!(delta, RefDelta::GroupStillReferenced);
    }

    #[test]
    fn record_member_unref_returns_id_when_last_ref() {
        let mut map = GroupOwnedMap::new();
        let k = install_one_mac_two_members(&mut map);

        // Manual unref of 10.0.0.3 from key k.
        let id = map.record_member_unref(ipa("10.0.0.3"), k);
        assert_eq!(id, Some(0x3000_0002));
        // VTEP NH removed from the map.
        assert!(map.vtep_nh(&ipa("10.0.0.3")).is_none());
    }
}
