//! Owned-state tracking for FDB nexthop groups (ADR-0059 slice 3).
//!
//! Three coordinating maps the reconcile actor maintains:
//!
//! 1. **Groups** keyed by `AliasGroupKey = (VNI, ESI, EthernetTag)`.
//!    Each group tracks its kernel `id`, the canonical member set
//!    last applied, the set of `(VNI, MAC)` rows referencing it, and
//!    (single-active groups, ADR-0083) the pre-created backup PE's
//!    VTEP IP.
//! 2. **Per-VTEP nexthops** keyed by `IpAddr`. Each one tracks its
//!    kernel `id` and two reference classes: the groups whose
//!    *membership* names it (`ref_groups`) and the single-active
//!    groups it is the pre-created *standby* for (`standby_groups`,
//!    ADR-0083 decision 1). The standby class exists because the
//!    backup NH is deliberately **not** a group member (the kernel
//!    hashes over all members; single-active means one egress
//!    forwards) — without it, the orphan reap would garbage-collect
//!    the very object the failover swap depends on.
//! 3. Refcount semantics: groups install on the first MAC that
//!    references them, tear down on the last unref. Per-VTEP NHs
//!    tear down only when **both** reference classes hit empty.
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
    /// ADR-0083: the single-active backup PE whose per-VTEP NH is
    /// pre-created and pinned by this group's standby ref class.
    /// `None` for all-active aliasing groups. The standby is never in
    /// `members`.
    pub standby: Option<IpAddr>,
}

/// One per-VTEP FDB nexthop installed in the kernel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VtepNh {
    /// Kernel nexthop ID (tagged via
    /// [`crate::nh_id_alloc::VTEP_NH_TAG`]).
    pub id: u32,
    /// Groups that reference this per-VTEP NH as a member.
    pub ref_groups: BTreeSet<AliasGroupKey>,
    /// ADR-0083 standby reference class: single-active groups whose
    /// pre-created backup NH this is. A NH pinned only by standby
    /// refs is *not* an orphan — it must survive the group-ref-zero
    /// reap while the `(ESI, EthTag)` intent lives, and is reaped
    /// when the last standby ref drops.
    pub standby_groups: BTreeSet<AliasGroupKey>,
}

impl VtepNh {
    /// `true` when no group references this NH through either class.
    #[must_use]
    pub fn is_unreferenced(&self) -> bool {
        self.ref_groups.is_empty() && self.standby_groups.is_empty()
    }
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
    /// should themselves be deleted. `standby` carries the ADR-0083
    /// pre-created backup NH's IP, if any — the caller follows up
    /// with [`GroupOwnedMap::record_standby_unref`] so a backup NH
    /// whose last standby ref dropped is deleted alongside the
    /// members (never-through-empty is preserved: the group itself
    /// is already gone by then, and the standby was never a member).
    GroupShouldDelete {
        id: u32,
        members: Vec<IpAddr>,
        standby: Option<IpAddr>,
    },
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
            standby_groups: BTreeSet::new(),
        });
    }

    /// Record a successful group install with its initial canonical
    /// members and (single-active, ADR-0083) pre-created standby.
    /// Each member's `ref_groups` set gets `group_key` added; the
    /// standby's `standby_groups` set likewise. The standby's
    /// per-VTEP NH must already be tracked (via
    /// [`Self::record_member_install`]) for the ref to land.
    pub fn record_group_install(
        &mut self,
        key: AliasGroupKey,
        id: u32,
        members: BTreeSet<IpAddr>,
        standby: Option<IpAddr>,
    ) {
        for ip in &members {
            if let Some(vtep) = self.vtep_nhs.get_mut(ip) {
                vtep.ref_groups.insert(key);
            }
        }
        if let Some(ip) = standby
            && let Some(vtep) = self.vtep_nhs.get_mut(&ip)
        {
            vtep.standby_groups.insert(key);
        }
        self.groups.insert(
            key,
            GroupOwned {
                id,
                members,
                ref_macs: BTreeSet::new(),
                standby,
            },
        );
    }

    /// Record a standby change for an existing group (the derived
    /// backup PE moved, e.g. the eligible set changed). Returns the
    /// *previous* standby IP when it differed and its ref was
    /// dropped — the caller checks [`Self::vtep_nh_is_orphan`] /
    /// [`Self::record_standby_unref`] to GC the old NH. The new
    /// standby's per-VTEP NH must already be tracked for the ref to
    /// land. No-op (returns `None`) when the group is untracked or
    /// the standby is unchanged.
    pub fn record_group_standby_change(
        &mut self,
        key: AliasGroupKey,
        new_standby: Option<IpAddr>,
    ) -> Option<IpAddr> {
        let group = self.groups.get_mut(&key)?;
        let old = group.standby;
        if old == new_standby {
            return None;
        }
        group.standby = new_standby;
        if let Some(ip) = new_standby
            && let Some(vtep) = self.vtep_nhs.get_mut(&ip)
        {
            vtep.standby_groups.insert(key);
        }
        let old_ip = old?;
        if let Some(vtep) = self.vtep_nhs.get_mut(&old_ip) {
            vtep.standby_groups.remove(&key);
        }
        Some(old_ip)
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
        let standby = group.standby;
        self.groups.remove(&key);
        // Unref each member's ref_groups set (the caller will follow up
        // with record_member_unref to discover which need kernel deletion).
        for ip in &members {
            if let Some(vtep) = self.vtep_nhs.get_mut(ip) {
                vtep.ref_groups.remove(&key);
            }
        }
        // ADR-0083: the group's standby ref dies with the group's
        // intent. The caller follows up with record_standby_unref.
        if let Some(ip) = standby
            && let Some(vtep) = self.vtep_nhs.get_mut(&ip)
        {
            vtep.standby_groups.remove(&key);
        }
        RefDelta::GroupShouldDelete {
            id,
            members,
            standby,
        }
    }

    /// Unref a per-VTEP NH from a group. Returns `Some(id)` if the
    /// VTEP NH became fully unreferenced — no group names it as a
    /// member *and* no single-active group pins it as standby —
    /// (caller must delete the NH from the kernel and release the
    /// allocator slot); returns `None` if anything still references
    /// it.
    ///
    /// Called after [`Self::record_mac_unref`] has already cleared
    /// the `group_key` from each member's `ref_groups` — this exists for
    /// **explicit** unref by callers that didn't go through
    /// [`Self::record_mac_unref`] (e.g., member-set shrink).
    pub fn record_member_unref(&mut self, ip: IpAddr, key: AliasGroupKey) -> Option<u32> {
        let vtep = self.vtep_nhs.get_mut(&ip)?;
        vtep.ref_groups.remove(&key);
        if vtep.is_unreferenced() {
            let id = vtep.id;
            self.vtep_nhs.remove(&ip);
            Some(id)
        } else {
            None
        }
    }

    /// Drop a standby ref (ADR-0083) from a per-VTEP NH. Returns
    /// `Some(id)` if the NH became fully unreferenced (caller deletes
    /// the kernel object + releases the allocator slot); `None` if a
    /// membership ref or another group's standby ref still pins it.
    pub fn record_standby_unref(&mut self, ip: IpAddr, key: AliasGroupKey) -> Option<u32> {
        let vtep = self.vtep_nhs.get_mut(&ip)?;
        vtep.standby_groups.remove(&key);
        if vtep.is_unreferenced() {
            let id = vtep.id;
            self.vtep_nhs.remove(&ip);
            Some(id)
        } else {
            None
        }
    }

    /// Check if a per-VTEP NH is currently fully unreferenced — no
    /// membership refs and no ADR-0083 standby refs (caller hasn't
    /// followed up with [`Self::record_member_unref`] /
    /// [`Self::record_standby_unref`]). Used by `record_mac_unref`
    /// callers to GC orphan NHs after a `GroupShouldDelete` decision.
    /// A backup NH pinned only by a live group's standby ref is NOT
    /// an orphan.
    #[must_use]
    pub fn vtep_nh_is_orphan(&self, ip: &IpAddr) -> bool {
        self.vtep_nhs.get(ip).is_some_and(VtepNh::is_unreferenced)
    }

    /// Remove an orphaned per-VTEP NH from tracking. Caller already
    /// deleted the kernel object and released the allocator slot.
    pub fn drop_vtep_nh(&mut self, ip: &IpAddr) -> Option<u32> {
        self.vtep_nhs.remove(ip).map(|v| v.id)
    }

    /// Roll back a group that has no live MAC refs (e.g., partial-
    /// install failure where the group was created but no
    /// `record_mac_ref` ran). Removes the group from tracking and
    /// clears each member's `ref_groups` (and the standby's
    /// `standby_groups`) for this key; returns the
    /// `(group_id, members, standby)` so the caller can delete the
    /// kernel object and release the allocator slot. Returns `None`
    /// if the group is not tracked or still has MAC refs (in which
    /// case the caller should use `record_mac_unref` instead).
    pub fn drop_unreferenced_group(
        &mut self,
        key: &AliasGroupKey,
    ) -> Option<(u32, Vec<IpAddr>, Option<IpAddr>)> {
        let group = self.groups.get(key)?;
        if !group.ref_macs.is_empty() {
            return None;
        }
        let id = group.id;
        let members: Vec<IpAddr> = group.members.iter().copied().collect();
        let standby = group.standby;
        for ip in &members {
            if let Some(vtep) = self.vtep_nhs.get_mut(ip) {
                vtep.ref_groups.remove(key);
            }
        }
        if let Some(ip) = standby
            && let Some(vtep) = self.vtep_nhs.get_mut(&ip)
        {
            vtep.standby_groups.remove(key);
        }
        self.groups.remove(key);
        Some((id, members, standby))
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
        map.record_group_install(k, 0x4000_0001, members, None);
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
            RefDelta::GroupShouldDelete {
                id,
                ref members,
                standby,
            } => {
                assert_eq!(id, 0x4000_0001);
                assert_eq!(members.len(), 2);
                assert_eq!(standby, None, "all-active group has no standby");
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
        map.record_group_install(ka, 0x4000_0001, members_a, None);

        let mut members_b = BTreeSet::new();
        members_b.insert(ipa("10.0.0.2")); // shared VTEP
        map.record_group_install(kb, 0x4000_0002, members_b, None);

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
        map.record_group_install(kb, 0x4000_0002, members_b, None);
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

    // ─── ADR-0083: standby reference class ──────────────────────────

    /// Helper mirroring the apply sequence for a single-active
    /// `InstallFdbNhg`: one member (the active PE), one pre-created
    /// standby NH (the backup PE, not a member), one MAC ref.
    fn install_single_active(map: &mut GroupOwnedMap) -> AliasGroupKey {
        let k = key(100, 7, 0);
        map.record_member_install(ipa("10.0.0.2"), 0x3000_0001); // active
        map.record_member_install(ipa("10.0.0.3"), 0x3000_0002); // backup (standby)
        let mut members = BTreeSet::new();
        members.insert(ipa("10.0.0.2"));
        map.record_group_install(k, 0x4000_0001, members, Some(ipa("10.0.0.3")));
        map.record_mac_ref(k, vni(100), mac(1));
        k
    }

    #[test]
    fn standby_nh_with_zero_group_refs_is_not_an_orphan() {
        // The recorded ADR-0083 composition bug: the backup NH is a
        // member of NO group, so the pre-standby orphan rule
        // (ref_groups empty ⇒ reap) would garbage-collect it. The
        // standby ref class must pin it while the group intent lives.
        let mut map = GroupOwnedMap::new();
        let k = install_single_active(&mut map);

        let standby = map.vtep_nh(&ipa("10.0.0.3")).expect("standby tracked");
        assert!(standby.ref_groups.is_empty(), "standby is never a member");
        assert_eq!(
            standby.standby_groups.iter().copied().collect::<Vec<_>>(),
            vec![k],
        );
        assert!(
            !map.vtep_nh_is_orphan(&ipa("10.0.0.3")),
            "standby ref must keep the backup NH out of the orphan reap"
        );
        // The active member is pinned by the membership ref as usual.
        assert!(!map.vtep_nh_is_orphan(&ipa("10.0.0.2")));
    }

    #[test]
    fn standby_nh_reaped_when_group_intent_disappears() {
        let mut map = GroupOwnedMap::new();
        let k = install_single_active(&mut map);

        let delta = map.record_mac_unref(k, vni(100), mac(1));
        let RefDelta::GroupShouldDelete {
            id,
            members,
            standby,
        } = delta
        else {
            panic!("expected GroupShouldDelete, got {delta:?}");
        };
        assert_eq!(id, 0x4000_0001);
        assert_eq!(members, vec![ipa("10.0.0.2")]);
        assert_eq!(standby, Some(ipa("10.0.0.3")));

        // Both the member and the standby are now fully unreferenced.
        assert!(map.vtep_nh_is_orphan(&ipa("10.0.0.2")));
        assert!(map.vtep_nh_is_orphan(&ipa("10.0.0.3")));
        assert_eq!(
            map.record_member_unref(ipa("10.0.0.2"), k),
            Some(0x3000_0001)
        );
        assert_eq!(
            map.record_standby_unref(ipa("10.0.0.3"), k),
            Some(0x3000_0002)
        );
        assert!(map.is_empty());
    }

    #[test]
    fn standby_ref_alone_keeps_nh_alive_through_member_unref() {
        // VTEP X is a member of group A (all-active) AND the standby
        // for group B (single-active). Tearing down group A must not
        // reap X — group B's standby ref still pins it.
        let mut map = GroupOwnedMap::new();
        let ka = key(100, 7, 0);
        let kb = key(100, 8, 0);
        map.record_member_install(ipa("10.0.0.5"), 0x3000_0001); // X
        map.record_member_install(ipa("10.0.0.6"), 0x3000_0002); // B's active PE

        let mut members_a = BTreeSet::new();
        members_a.insert(ipa("10.0.0.5"));
        map.record_group_install(ka, 0x4000_0001, members_a, None);
        map.record_mac_ref(ka, vni(100), mac(1));

        let mut members_b = BTreeSet::new();
        members_b.insert(ipa("10.0.0.6"));
        map.record_group_install(kb, 0x4000_0002, members_b, Some(ipa("10.0.0.5")));
        map.record_mac_ref(kb, vni(100), mac(2));

        // Tear down group A.
        let delta = map.record_mac_unref(ka, vni(100), mac(1));
        assert!(matches!(delta, RefDelta::GroupShouldDelete { .. }));
        assert!(
            !map.vtep_nh_is_orphan(&ipa("10.0.0.5")),
            "standby ref from group B must survive group A's teardown"
        );
        assert_eq!(
            map.record_member_unref(ipa("10.0.0.5"), ka),
            None,
            "member unref must not reap a NH still pinned as standby"
        );
        assert!(map.vtep_nh(&ipa("10.0.0.5")).is_some());

        // Now tear down group B — X finally becomes reapable.
        let delta = map.record_mac_unref(kb, vni(100), mac(2));
        assert!(matches!(
            delta,
            RefDelta::GroupShouldDelete {
                standby: Some(_),
                ..
            }
        ));
        assert!(map.vtep_nh_is_orphan(&ipa("10.0.0.5")));
        assert_eq!(
            map.record_standby_unref(ipa("10.0.0.5"), kb),
            Some(0x3000_0001)
        );
    }

    #[test]
    fn standby_change_returns_old_ip_for_gc() {
        let mut map = GroupOwnedMap::new();
        let k = install_single_active(&mut map);
        // New backup PE appears with a lower IP → derived standby
        // moves. Old standby (10.0.0.3) must be unpinned and
        // reported; new standby (10.0.0.1) pinned.
        map.record_member_install(ipa("10.0.0.1"), 0x3000_0003);
        let old = map.record_group_standby_change(k, Some(ipa("10.0.0.1")));
        assert_eq!(old, Some(ipa("10.0.0.3")));
        assert!(
            map.vtep_nh_is_orphan(&ipa("10.0.0.3")),
            "old standby loses its pin"
        );
        assert!(!map.vtep_nh_is_orphan(&ipa("10.0.0.1")));
        assert_eq!(map.group(&k).unwrap().standby, Some(ipa("10.0.0.1")));

        // Unchanged standby is a no-op.
        assert_eq!(
            map.record_group_standby_change(k, Some(ipa("10.0.0.1"))),
            None
        );
        // Untracked group is a no-op.
        assert_eq!(
            map.record_group_standby_change(key(100, 99, 0), Some(ipa("10.0.0.1"))),
            None,
        );
    }

    // ─── ADR-0083 slice 3: the swap bookkeeping sequence ───

    #[test]
    fn swap_sequence_promotes_standby_to_member_without_reap_window() {
        // The coordinator's post-REPLACE bookkeeping order for a swap
        // (standby re-pin FIRST, then member change, then GCs): the NH
        // being promoted standby→member (10.0.0.3) must never be
        // reapable at any GC step, and the withdrawn member (10.0.0.2)
        // must become reapable.
        let mut map = GroupOwnedMap::new();
        let k = install_single_active(&mut map); // member .2, standby .3

        // Step 1: standby re-pin. Sole survivor → new standby None;
        // the old standby (.3) is returned for the *deferred* GC.
        let old_standby = map.record_group_standby_change(k, None);
        assert_eq!(old_standby, Some(ipa("10.0.0.3")));

        // Step 2: member change {.2} → {.3} (the swap itself).
        let mut new_members = BTreeSet::new();
        new_members.insert(ipa("10.0.0.3"));
        let removed = map.record_group_member_change(k, new_members);
        assert_eq!(removed, vec![ipa("10.0.0.2")]);

        // Step 3: GC the removed member — .2 is reapable.
        assert_eq!(
            map.record_member_unref(ipa("10.0.0.2"), k),
            Some(0x3000_0001)
        );
        // Step 4: GC the old standby — .3 is now the member, so the
        // unref must NOT reap it (the member⇄standby transition is
        // never reaped in the bookkeeping window).
        assert_eq!(map.record_standby_unref(ipa("10.0.0.3"), k), None);
        assert!(!map.vtep_nh_is_orphan(&ipa("10.0.0.3")));
        assert_eq!(
            map.group(&k)
                .unwrap()
                .members
                .iter()
                .copied()
                .collect::<Vec<_>>(),
            vec![ipa("10.0.0.3")],
        );
        assert_eq!(map.group(&k).unwrap().standby, None);
    }

    #[test]
    fn swap_member_gc_spares_pe_pinned_as_standby_elsewhere() {
        // Group A swaps its member away from .2 while .2 is the
        // pre-created standby for group B: the post-swap member GC
        // must not cross-group-reap .2's NH.
        let mut map = GroupOwnedMap::new();
        let ka = key(100, 7, 0);
        let kb = key(100, 8, 0);
        map.record_member_install(ipa("10.0.0.2"), 0x3000_0001);
        map.record_member_install(ipa("10.0.0.3"), 0x3000_0002);
        map.record_member_install(ipa("10.0.0.6"), 0x3000_0003);

        let mut members_a = BTreeSet::new();
        members_a.insert(ipa("10.0.0.2"));
        map.record_group_install(ka, 0x4000_0001, members_a, Some(ipa("10.0.0.3")));
        map.record_mac_ref(ka, vni(100), mac(1));

        let mut members_b = BTreeSet::new();
        members_b.insert(ipa("10.0.0.6"));
        map.record_group_install(kb, 0x4000_0002, members_b, Some(ipa("10.0.0.2")));
        map.record_mac_ref(kb, vni(100), mac(2));

        // Swap group A: member {.2} → {.3}, standby → None.
        let old_standby = map.record_group_standby_change(ka, None);
        assert_eq!(old_standby, Some(ipa("10.0.0.3")));
        let mut new_members = BTreeSet::new();
        new_members.insert(ipa("10.0.0.3"));
        let removed = map.record_group_member_change(ka, new_members);
        assert_eq!(removed, vec![ipa("10.0.0.2")]);

        // .2 stays pinned by group B's standby ref — no reap.
        assert_eq!(map.record_member_unref(ipa("10.0.0.2"), ka), None);
        assert!(!map.vtep_nh_is_orphan(&ipa("10.0.0.2")));
        assert!(map.vtep_nh(&ipa("10.0.0.2")).is_some());
        // Group B's standby record is untouched.
        assert_eq!(map.group(&kb).unwrap().standby, Some(ipa("10.0.0.2")));
    }

    #[test]
    fn drop_unreferenced_group_releases_standby_pin() {
        let mut map = GroupOwnedMap::new();
        let k = key(100, 7, 0);
        map.record_member_install(ipa("10.0.0.2"), 0x3000_0001);
        map.record_member_install(ipa("10.0.0.3"), 0x3000_0002);
        let mut members = BTreeSet::new();
        members.insert(ipa("10.0.0.2"));
        map.record_group_install(k, 0x4000_0001, members, Some(ipa("10.0.0.3")));
        // No MAC ref recorded — partial-install rollback shape.
        let (id, members, standby) = map.drop_unreferenced_group(&k).expect("droppable");
        assert_eq!(id, 0x4000_0001);
        assert_eq!(members, vec![ipa("10.0.0.2")]);
        assert_eq!(standby, Some(ipa("10.0.0.3")));
        assert!(map.vtep_nh_is_orphan(&ipa("10.0.0.3")));
    }
}
