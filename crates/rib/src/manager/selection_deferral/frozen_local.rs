//! The member's ordinary local row before a group changes it during a GR hold.
//! Admission changes discard the witness. A missing witness keeps readback pending.

use std::collections::{BTreeMap, HashSet};
use std::mem::size_of;

use rustbgpd_policy::NextHopAction;
use rustbgpd_wire::{Afi, AsPathSegment, PathAttribute, Prefix, Safi};

use crate::PeerId;
use crate::adj_rib_out::LocalExportSource;
use crate::attr_set::AttrSet;
use crate::route::{NextHopScope, Route};

use super::super::RibManager;
use super::super::helpers::{LOCAL_PEER, prefix_family};

// Optional readback gets its own ceiling inside the deferral owner. Recovery
// and release can still spend their full budgets when this one is exhausted.
const MAX_KEYS: usize = 4096;
// All members share this many prefix probes for each newly held family.
const MAX_CAPTURE_VISITS: usize = 4096;
const MAX_BODY_BYTES: usize = 4 * 1024 * 1024;

#[derive(Debug)]
pub(in crate::manager) struct FrozenLocalRow {
    pub(in crate::manager) route: Route,
    pub(in crate::manager) source: LocalExportSource,
    pub(in crate::manager) action: Option<NextHopAction>,
    charge: usize,
}

#[derive(Debug, Default)]
struct Family {
    rows: BTreeMap<PeerId, BTreeMap<Prefix, FrozenLocalRow>>,
    entries: usize,
    bytes: usize,
}

impl Family {
    fn has_room(&self, byte_limit: usize) -> bool {
        self.entries < MAX_KEYS && self.bytes < byte_limit
    }

    fn retain(
        &mut self,
        peer: PeerId,
        route: Route,
        action: Option<NextHopAction>,
        source: LocalExportSource,
        byte_limit: usize,
    ) {
        let Some(charge) = body_charge(&route).filter(|n| *n <= byte_limit - self.bytes) else {
            return;
        };
        let rows = self.rows.entry(peer).or_default();
        if let std::collections::btree_map::Entry::Vacant(entry) = rows.entry(route.prefix) {
            entry.insert(FrozenLocalRow {
                route,
                source,
                action,
                charge,
            });
            self.bytes += charge;
            self.entries += 1;
        }
    }
}

#[derive(Debug, Default)]
pub(super) struct FrozenLocalRows {
    families: [Family; 2],
    #[cfg(test)]
    byte_limit: Option<usize>,
    #[cfg(test)]
    visit_limit: Option<usize>,
    #[cfg(test)]
    visits: [usize; 2],
}

impl FrozenLocalRows {
    #[cfg(any(test, feature = "bench-internals"))]
    pub(super) fn is_cleared(&self) -> bool {
        self.families
            .iter()
            .all(|family| family.rows.is_empty() && family.entries == 0 && family.bytes == 0)
    }

    pub(super) fn clear_family(&mut self, afi: Afi, checkpoint: &mut impl FnMut()) {
        let retired = std::mem::take(&mut self.families[usize::from(afi == Afi::Ipv6)]);
        for rows in retired.rows.into_values() {
            for row in rows.into_values() {
                checkpoint();
                drop(row);
            }
        }
    }
}

/// Charge the actual backing capacity, even when another member shares it.
/// Local injection and its export policy use the unicast attributes below.
/// A different attribute layout cannot be retained without a known charge.
fn body_charge(route: &Route) -> Option<usize> {
    if route.received_as_path.is_some() {
        return None;
    }
    let attrs = &route.attributes;
    let mut bytes = size_of::<FrozenLocalRow>()
        + 2 * size_of::<usize>()
        + size_of::<AttrSet>()
        + attrs.capacity() * size_of::<PathAttribute>();
    if let Some(scope) = &route.next_hop_scope {
        bytes += size_of::<NextHopScope>() + 2 * size_of::<usize>() + scope.interface.len();
    }
    for attr in attrs.iter() {
        bytes = bytes.checked_add(match attr {
            PathAttribute::Origin(_)
            | PathAttribute::Aggregator(_)
            | PathAttribute::AtomicAggregate
            | PathAttribute::NextHop(_)
            | PathAttribute::LocalPref(_)
            | PathAttribute::Med(_)
            | PathAttribute::OriginatorId(_)
            | PathAttribute::OnlyToCustomer(_)
            | PathAttribute::OnlyToCustomerPartial(_) => 0,
            PathAttribute::Communities(v) | PathAttribute::CommunitiesPartial(v) => {
                v.capacity() * size_of::<u32>()
            }
            PathAttribute::LargeCommunities(v) | PathAttribute::LargeCommunitiesPartial(v) => {
                v.capacity() * size_of::<rustbgpd_wire::LargeCommunity>()
            }
            PathAttribute::ExtendedCommunities(v)
            | PathAttribute::ExtendedCommunitiesPartial(v) => {
                v.capacity() * size_of::<rustbgpd_wire::ExtendedCommunity>()
            }
            PathAttribute::Ipv6ExtendedCommunities(v)
            | PathAttribute::Ipv6ExtendedCommunitiesPartial(v) => {
                v.capacity() * size_of::<rustbgpd_wire::Ipv6ExtendedCommunity>()
            }
            PathAttribute::ClusterList(v) => v.capacity() * size_of::<std::net::Ipv4Addr>(),
            PathAttribute::AsPath(path) => path.segments.iter().fold(
                path.segments.capacity() * size_of::<AsPathSegment>(),
                |size, segment| {
                    let (AsPathSegment::AsSequence(asns) | AsPathSegment::AsSet(asns)) = segment;
                    size.saturating_add(asns.capacity() * size_of::<u32>())
                },
            ),
            _ => return None,
        })?;
    }
    Some(bytes)
}

impl RibManager {
    #[cfg(test)]
    pub(in crate::manager) fn set_frozen_local_byte_limit(&mut self, bytes: usize) {
        self.deferred_selection_keys.frozen_locals.byte_limit = Some(bytes);
    }

    pub(in crate::manager) fn frozen_group_local_visit_budget(
        &self,
        families: &HashSet<(Afi, Safi)>,
    ) -> [usize; 2] {
        #[cfg(test)]
        let limit = self
            .deferred_selection_keys
            .frozen_locals
            .visit_limit
            .unwrap_or(MAX_CAPTURE_VISITS);
        #[cfg(not(test))]
        let limit = MAX_CAPTURE_VISITS;
        std::array::from_fn(|slot| {
            let afi = [Afi::Ipv4, Afi::Ipv6][slot];
            if families.contains(&(afi, Safi::Unicast))
                && self.deferred_selection_keys.frozen_locals.families[slot].entries < MAX_KEYS
            {
                limit
            } else {
                0
            }
        })
    }

    #[cfg(test)]
    pub(in crate::manager) fn set_frozen_local_visit_limit(&mut self, visits: usize) {
        self.deferred_selection_keys.frozen_locals.visit_limit = Some(visits);
    }

    #[cfg(test)]
    pub(in crate::manager) fn frozen_local_visits(&self) -> [usize; 2] {
        self.deferred_selection_keys.frozen_locals.visits
    }

    pub(in crate::manager) fn capture_frozen_group_locals(
        &mut self,
        peer: PeerId,
        remaining: &mut [usize; 2],
    ) {
        if *remaining == [0; 2] {
            return;
        }
        let Some(group) = self
            .grouped_member_of(peer)
            .and_then(|gid| self.group_ribs.get(&gid))
        else {
            return;
        };
        if self.dirty_peers.contains(&peer)
            || self.force_outbound_peers.contains(&peer)
            || self.outbound_channel_gone(peer)
            || self.pending_regroup_baseline.contains_key(&peer)
            || self.retain_initial_group_admitted(peer)
        {
            return;
        }
        let held = self.selection_receiver_held_families(peer);
        #[cfg(test)]
        let max_body_bytes = self
            .deferred_selection_keys
            .frozen_locals
            .byte_limit
            .unwrap_or(MAX_BODY_BYTES);
        #[cfg(not(test))]
        let max_body_bytes = MAX_BODY_BYTES;
        let Some(rib) = self
            .adj_ribs_out
            .get(&peer)
            .filter(|rib| rib.has_local_export_sources())
        else {
            return;
        };
        let Some(admitted) = self.pending_group_admitted.get(&peer) else {
            return;
        };
        let Some(local) = self.ribs.get(&LOCAL_PEER) else {
            return;
        };
        for (slot, afi) in [Afi::Ipv4, Afi::Ipv6].into_iter().enumerate() {
            if !held[slot]
                || remaining[slot] == 0
                || !self.deferred_selection_keys.frozen_locals.families[slot]
                    .has_room(max_body_bytes)
            {
                continue;
            }
            // Walk distinct local prefixes, without scanning hash capacity or
            // the paths behind a prefix. Every returned prefix costs a visit,
            // including a rejected projection and the first next-family key.
            let start = crate::update::route_query_start_prefix(None, Some(afi));
            let mut prefixes = local.release_prefixes_from(start);
            while remaining[slot] > 0
                && self.deferred_selection_keys.frozen_locals.families[slot]
                    .has_room(max_body_bytes)
            {
                let Some(prefix) = prefixes.next() else { break };
                remaining[slot] -= 1;
                #[cfg(test)]
                {
                    self.deferred_selection_keys.frozen_locals.visits[slot] += 1;
                }
                self.replacement_checkpoint(false);
                if prefix_family(&prefix).0 != afi {
                    break;
                }
                let Some(source) = rib.local_export_source(&prefix, 0) else {
                    continue;
                };
                if source.deferral_exempt
                    || !admitted.contains(&crate::update::ExactExportKey::Unicast(prefix, 0))
                {
                    continue;
                }
                let Some((route, action, admitted_source)) =
                    self.grouped_member_unicast_row(group, peer, &prefix, 0)
                else {
                    continue;
                };
                if admitted_source != Some(source) || route.peer != LOCAL_PEER {
                    continue;
                }
                self.deferred_selection_keys.frozen_locals.families[slot].retain(
                    peer,
                    route,
                    action,
                    source,
                    max_body_bytes,
                );
            }
        }
    }

    pub(in crate::manager) fn frozen_group_local_row(
        &self,
        peer: PeerId,
        prefix: &Prefix,
    ) -> Option<&FrozenLocalRow> {
        let family = prefix_family(prefix);
        if !self.selection_deferred(family) || self.outbound_channel_gone(peer) {
            return None;
        }
        let row = self.deferred_selection_keys.frozen_locals.families
            [usize::from(family.0 == Afi::Ipv6)]
        .rows
        .get(&peer)?
        .get(prefix)?;
        let source = self
            .ribs
            .get(&LOCAL_PEER)?
            .get(prefix, row.source.path_id)?;
        if super::super::helpers::unicast_deferral_exempt(source) {
            return None;
        }
        (self.adj_ribs_out.get(&peer)?.local_export_source(prefix, 0) == Some(row.source))
            .then_some(row)
    }

    pub(in crate::manager) fn has_frozen_group_locals(&self, peer: PeerId) -> bool {
        self.deferred_selection_keys
            .frozen_locals
            .families
            .iter()
            .any(|family| family.rows.contains_key(&peer))
    }

    /// Return true if the last witnessed key for this peer was retired.
    pub(in crate::manager) fn forget_frozen_group_local(
        &mut self,
        peer: PeerId,
        prefix: &Prefix,
    ) -> bool {
        let state = &mut self.deferred_selection_keys.frozen_locals.families
            [usize::from(matches!(prefix, Prefix::V6(_)))];
        if let Some(rows) = state.rows.get_mut(&peer) {
            if let Some(row) = rows.remove(prefix) {
                state.entries -= 1;
                state.bytes -= row.charge;
            }
            if rows.is_empty() {
                state.rows.remove(&peer);
                return !self.has_frozen_group_locals(peer);
            }
        }
        false
    }

    pub(in crate::manager) fn forget_peer_frozen_group_locals(&mut self, peer: PeerId) {
        for slot in 0..2 {
            let state = &mut self.deferred_selection_keys.frozen_locals.families[slot];
            if let Some(rows) = state.rows.remove(&peer) {
                state.entries -= rows.len();
                for row in rows.into_values() {
                    self.replacement_checkpoint(false);
                    self.deferred_selection_keys.frozen_locals.families[slot].bytes -= row.charge;
                }
            }
        }
    }
}
