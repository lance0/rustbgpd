use super::{
    BatchedMemberSupplement, BatchedTransitionCounters, BatchedTransitionInventory,
    CleanPolicyTransitionInventory, CleanPolicyTransitionInventoryBuilder, FastMap, GroupKey,
    GroupMembership, GroupRibOut, IpAddr, LargeCommunity, NextHopAction, PolicyAction, PolicyChain,
    PolicyTransitionGroupStart, Prefix, RibManager, Route, UpdateGroupClassification,
    classify_update_group, routes_equal, source_control_input,
};
use tracing::info;

use crate::fast_hash::FastSet;

/// One `None` arm of the clean-transition inventory walk. Every arm
/// degrades the WHOLE cohort back to the authoritative per-peer path,
/// so name the group pair and the term that fired: a degraded cohort
/// is otherwise indistinguishable in the log from one that never
/// qualified for the fast path at all.
fn inventory_degraded(source: usize, destination: usize, key: Option<(Prefix, u32)>, term: &str) {
    info!(
        source,
        destination,
        ?key,
        term,
        "clean transition inventory degraded"
    );
}

/// One destination entry's verdict in a clean-transition inventory walk.
enum InventoryEntry {
    Unchanged,
    /// Announced in the shared delta. `tagged` reports an RFC 7947
    /// control-form community for one of the walk's RS ASNs.
    Changed {
        next_hop: Option<NextHopAction>,
        tagged: bool,
    },
}

/// The per-key checks every clean-transition inventory walk applies to one
/// staged destination entry: the source group stages the same key (`Err`
/// "source table drift") from the same source peer (`Err` "source flip").
/// A changed entry is reported with its rs-control tag verdict, taken on
/// EITHER side of policy (see
/// [`RibManager::extend_clean_policy_transition_inventory`]).
fn inventory_entry(
    old: &GroupRibOut,
    new: &GroupRibOut,
    route: &Route,
    rs_asns: &[u32],
) -> Result<InventoryEntry, &'static str> {
    use crate::manager::distribution::rs_control::rs_control_route_tagged;
    let key = (route.prefix, route.path_id);
    let prior = old
        .table
        .get(&route.prefix, route.path_id)
        .ok_or("source table drift")?;
    if prior.peer != route.peer {
        return Err("source flip");
    }
    let next_hop = new.nh_override(key);
    if routes_equal(prior, route) && old.nh_override(key) == next_hop {
        return Ok(InventoryEntry::Unchanged);
    }
    let tagged = !rs_asns.is_empty() && {
        let (old_communities, old_large) = old.source_control(key);
        let (new_communities, new_large) = new.source_control(key);
        rs_asns.iter().any(|&rs_asn| {
            rs_control_route_tagged(route.communities(), route.large_communities(), rs_asn)
                || rs_control_route_tagged(old_communities, old_large, rs_asn)
                || rs_control_route_tagged(new_communities, new_large, rs_asn)
        })
    };
    Ok(InventoryEntry::Changed { next_hop, tagged })
}

/// A clean-transition inventory built outside the fence, right after the
/// unfenced destination prestage. From the walk's first slice on, both
/// groups log every key a table write touches
/// ([`GroupRibOut::inventory_log`]). Logged keys are reconciled before
/// sealing the payload, then again against the frozen tables during fenced
/// `BuildInventory`, so every drift check stays exact without a fenced full walk.
pub(in crate::manager) struct PrestagedTransitionInventory {
    source: usize,
    destination: usize,
    /// Every distinct RS ASN configured when the walk began; `tagged` is
    /// relative to this set.
    rs_asns: Vec<u32>,
    /// Next destination slab slot to visit.
    cursor: usize,
    complete: bool,
    /// Slab handles, reconciled against current slot identity before sealing.
    announce: Vec<u32>,
    next_hop_override: Vec<Option<NextHopAction>>,
    pub(in crate::manager) sealed: Option<CleanPolicyTransitionInventory>,
    pub(in crate::manager) probe: Option<crate::manager::distribution::PrestagedTransitionProbe>,
    /// Keys failing a drift check as of their last visit.
    failed: FastMap<(Prefix, u32), &'static str>,
    /// Changed keys tagged for an ASN in `rs_asns`.
    tagged: FastSet<(Prefix, u32)>,
}

/// What the fenced re-check made of a prestaged inventory.
pub(in crate::manager) enum PrestagedInventoryOutcome {
    /// Equal to a fenced full walk of the current tables.
    Ready(
        Box<CleanPolicyTransitionInventoryBuilder>,
        Option<crate::manager::distribution::PrestagedTransitionProbe>,
    ),
    /// A drift check fails on the current tables: degrade exactly as the
    /// fenced walk would.
    Degraded,
    /// The prestaged walk cannot vouch for the current tables (none, for
    /// another pair, unfinished, a group recreated, or an RS ASN outside
    /// the walk's set): run the fenced walk.
    Unusable,
}

/// Whether a source/destination pair is clean enough for the strict
/// transition inventory: dirty state, residue or private-family
/// participation rejects the optimization before a member is moved or an
/// envelope is emitted, and equal unicast table sizes (with every
/// destination key present in the source) prove equal key sets.
fn clean_inventory_pair(old: &GroupRibOut, new: &GroupRibOut) -> bool {
    let clean = |group: &GroupRibOut| {
        // Per-client-best groups are excluded from the ADR-0105 narrow
        // fast path outright — its clean predicate (zero
        // policy-filtered routes on both sides) contradicts the
        // mitigation's reason to exist. Re-inclusion is demand-gated
        // (ADR-0126 Decision 8).
        !group.per_client_best
            && group.dirty_members.is_empty()
            && group.tombstones.is_empty()
            && group.vpn_tombstones.is_empty()
            && group.table.vpn_len() == 0
            && group.policy_filtered.is_empty()
            && group.vpn_policy_denied.is_empty()
            && group.otc_blocked.is_empty()
    };
    clean(old) && clean(new) && old.table.len() == new.table.len()
}

impl RibManager {
    /// Snapshot route identities for the strict clean transition inventory.
    /// Dirty state or private-family participation rejects the optimization
    /// before a member is moved or an envelope is emitted.
    pub(in crate::manager) fn begin_clean_policy_transition_inventory(
        &self,
        source: usize,
        destination: usize,
    ) -> Option<Vec<(Prefix, u32)>> {
        let old = self.group_ribs.get(&source)?;
        let new = self.group_ribs.get(&destination)?;
        if !clean_inventory_pair(old, new) {
            return None;
        }
        self.replacement_checkpoint(true);
        let mut keys = Vec::with_capacity(new.table.len());
        self.replacement_checkpoint(true);
        for route in new.table.iter() {
            crate::manager::replacement_readiness_checkpoint_at(
                &self.replacement_readiness,
                "shared_inventory",
                false,
            );
            keys.push((route.prefix, route.path_id));
        }
        self.replacement_checkpoint(true);
        Some(keys)
    }

    /// Accumulate one bounded key chunk. A withdrawal, source flip, or table
    /// drift rejects the complete optimized plan before emission — and so
    /// does a control-form community (RFC 7947 §2.3.2) for any of the
    /// cohort's RS ASNs (`rs_asns`), on EITHER side of policy: the source
    /// residue drives per-target suppression/prepend even when policy
    /// strips the tag from the post-policy route, and a policy-added tag
    /// needs the per-target scrub. Untagged (the overwhelming case) is
    /// proven in this same single walk, so rs-control members ride the
    /// shared cohort at zero extra passes; a tagged inventory hands the
    /// whole cohort to the authoritative per-peer path, whose emit seams
    /// apply the per-target filter.
    pub(in crate::manager) fn extend_clean_policy_transition_inventory(
        &self,
        source: usize,
        destination: usize,
        keys: &[(Prefix, u32)],
        rs_asns: &[u32],
        inventory: &mut CleanPolicyTransitionInventoryBuilder,
    ) -> Option<()> {
        let Some(old) = self.group_ribs.get(&source) else {
            inventory_degraded(source, destination, None, "source group missing");
            return None;
        };
        let Some(new) = self.group_ribs.get(&destination) else {
            inventory_degraded(source, destination, None, "destination group missing");
            return None;
        };
        self.replacement_checkpoint(true);
        // Fold permit counts per chunk keyed by borrowed labels, then merge
        // into the owned builder maps once: the per-route path used to clone
        // the `Option<String>` label twice per route, which dominated this
        // walk at reload-stall scale. The merge clones one label per
        // distinct (label) / (source, label) pair per chunk instead.
        let mut chunk_totals: FastMap<Option<&str>, u64> = FastMap::default();
        let mut chunk_by_source: FastMap<IpAddr, FastMap<Option<&str>, u64>> = FastMap::default();
        // Run-length fold for the permit counters: tables interleave far
        // fewer (source, label) flips than routes (contiguous prefix blocks
        // from one source are the common shape), so accumulate runs and
        // touch the maps once per flip instead of twice per route.
        let mut run: Option<(IpAddr, Option<&str>, u64)> = None;
        for &(prefix, path_id) in keys {
            crate::manager::replacement_readiness_checkpoint_at(
                &self.replacement_readiness,
                "shared_inventory",
                false,
            );
            let key = (prefix, path_id);
            let Some(route) = new.table.get(&prefix, path_id) else {
                inventory_degraded(source, destination, Some(key), "destination table drift");
                return None;
            };
            match inventory_entry(old, new, route, rs_asns) {
                Err(term) => {
                    inventory_degraded(source, destination, Some(key), term);
                    return None;
                }
                Ok(InventoryEntry::Changed { tagged: true, .. }) => {
                    inventory_degraded(source, destination, Some(key), "rs-control tag");
                    return None;
                }
                Ok(InventoryEntry::Unchanged) => {}
                Ok(InventoryEntry::Changed { next_hop, .. }) => {
                    if inventory.announce.capacity() == 0 {
                        self.replacement_checkpoint(true);
                        inventory.announce.reserve_exact(new.table.len());
                        self.replacement_checkpoint(true);
                        inventory.next_hop_override.reserve_exact(new.table.len());
                        self.replacement_checkpoint(true);
                    }
                    inventory.announce.push(route.clone());
                    inventory.next_hop_override.push(next_hop);
                }
            }

            let label = new.permit_policy_label.as_deref();
            run = Some(match run {
                Some((peer, run_label, count)) if peer == route.peer && run_label == label => {
                    (peer, run_label, count + 1)
                }
                Some((peer, run_label, count)) => {
                    *chunk_totals.entry(run_label).or_default() += count;
                    *chunk_by_source
                        .entry(peer)
                        .or_default()
                        .entry(run_label)
                        .or_default() += count;
                    (route.peer, label, 1)
                }
                None => (route.peer, label, 1),
            });
        }
        if let Some((peer, run_label, count)) = run {
            *chunk_totals.entry(run_label).or_default() += count;
            *chunk_by_source
                .entry(peer)
                .or_default()
                .entry(run_label)
                .or_default() += count;
        }
        for (label, count) in chunk_totals {
            self.replacement_checkpoint(false);
            *inventory
                .permit_totals
                .entry(label.map(str::to_owned))
                .or_default() += count;
        }
        for (peer, counts) in chunk_by_source {
            self.replacement_checkpoint(false);
            let by_source = inventory.permit_by_source.entry(peer).or_default();
            for (label, count) in counts {
                self.replacement_checkpoint(false);
                *by_source.entry(label.map(str::to_owned)).or_default() += count;
            }
        }
        self.replacement_checkpoint(true);
        Some(())
    }

    /// Start the unfenced inventory walk for a just-prestaged destination.
    /// Skipped (the fence then walks as before) unless both groups exist
    /// and are clean now; the fenced re-check repeats every pair predicate.
    pub(in crate::manager) fn begin_prestaged_transition_inventory(
        &mut self,
        source: usize,
        destination: usize,
    ) {
        self.retire_prestaged_transition_inventory();
        let (Some(old), Some(new)) = (
            self.group_ribs.get(&source),
            self.group_ribs.get(&destination),
        ) else {
            return;
        };
        if source == destination || !clean_inventory_pair(old, new) {
            return;
        }
        let mut rs_asns = self.peer_rs_control.values().copied().collect::<Vec<_>>();
        rs_asns.sort_unstable();
        rs_asns.dedup();
        for gid in [source, destination] {
            if let Some(group) = self.group_ribs.get_mut(&gid) {
                group.inventory_log = Some(FastSet::default());
            }
        }
        self.prestaged_inventory = Some(PrestagedTransitionInventory {
            source,
            destination,
            rs_asns,
            cursor: 0,
            complete: false,
            announce: Vec::new(),
            next_hop_override: Vec::new(),
            sealed: None,
            probe: None,
            failed: FastMap::default(),
            tagged: FastSet::default(),
        });
    }

    /// Walk one bounded slice of destination slab slots into the prestaged
    /// inventory. Returns `true` once no walk remains (finished, never
    /// begun, or abandoned because a group disappeared).
    pub(in crate::manager) fn extend_prestaged_transition_inventory(&mut self) -> bool {
        let Some(mut prestaged) = self.prestaged_inventory.take() else {
            return true;
        };
        let Some(complete) = self.walk_prestaged_transition_slice(&mut prestaged) else {
            self.prestaged_inventory = Some(prestaged);
            self.retire_prestaged_transition_inventory();
            return true;
        };
        prestaged.complete = complete;
        if complete {
            self.seal_prestaged_transition_inventory(&mut prestaged);
        }
        self.prestaged_inventory = Some(prestaged);
        complete
    }

    /// `None` when a group disappeared or was recreated (its key log is
    /// gone), else whether the walk reached the last slab slot.
    fn walk_prestaged_transition_slice(
        &self,
        prestaged: &mut PrestagedTransitionInventory,
    ) -> Option<bool> {
        let old = self.group_ribs.get(&prestaged.source)?;
        let new = self.group_ribs.get(&prestaged.destination)?;
        if old.inventory_log.is_none() || new.inventory_log.is_none() {
            return None;
        }
        let slots = new.table.unicast_slot_count();
        let end = crate::manager::policy_transition_slice_end(
            prestaged.cursor,
            slots,
            crate::manager::POLICY_TRANSITION_ROUTE_SLICE,
        );
        for slot in prestaged.cursor..end {
            crate::manager::replacement_readiness_checkpoint_at(
                &self.replacement_readiness,
                "shared_inventory",
                false,
            );
            let Some(route) = new.table.unicast_slot(slot) else {
                continue;
            };
            let key = (route.prefix, route.path_id);
            match inventory_entry(old, new, route, &prestaged.rs_asns) {
                Err(term) => {
                    prestaged.failed.insert(key, term);
                }
                Ok(InventoryEntry::Unchanged) => {}
                Ok(InventoryEntry::Changed { next_hop, tagged }) => {
                    if prestaged.announce.capacity() == 0 {
                        self.replacement_checkpoint(true);
                        prestaged.announce.reserve_exact(new.table.len());
                        self.replacement_checkpoint(true);
                        prestaged.next_hop_override.reserve_exact(new.table.len());
                        self.replacement_checkpoint(true);
                    }
                    prestaged
                        .announce
                        .push(u32::try_from(slot).expect("route slab uses u32 handles"));
                    prestaged.next_hop_override.push(next_hop);
                    if tagged {
                        prestaged.tagged.insert(key);
                    }
                }
            }
        }
        prestaged.cursor = end;
        Some(end == slots)
    }

    /// Reconcile the walk before sealing. The actor owns this whole poll:
    /// drained logs are reset before mutation traffic can resume.
    fn seal_prestaged_transition_inventory(
        &mut self,
        prestaged: &mut PrestagedTransitionInventory,
    ) {
        let mut dirty = FastSet::default();
        for gid in [prestaged.source, prestaged.destination] {
            if let Some(log) = self
                .group_ribs
                .get_mut(&gid)
                .and_then(|group| group.inventory_log.as_mut())
            {
                dirty.extend(log.drain());
            }
        }
        let new = &self.group_ribs[&prestaged.destination];
        let old = &self.group_ribs[&prestaged.source];
        let mut kept = 0;
        for index in 0..prestaged.announce.len() {
            self.replacement_checkpoint(false);
            // Vacant slots and reused slots are discarded too: the inserted
            // route's current identity is logged, even if its prior slot was
            // visited under a different key earlier in the walk.
            if new
                .table
                .unicast_slot(prestaged.announce[index] as usize)
                .is_some_and(|route| !dirty.contains(&(route.prefix, route.path_id)))
            {
                prestaged.announce.swap(kept, index);
                prestaged.next_hop_override.swap(kept, index);
                kept += 1;
            }
        }
        prestaged.announce.truncate(kept);
        prestaged.next_hop_override.truncate(kept);
        prestaged.failed.retain(|key, _| !dirty.contains(key));
        prestaged.tagged.retain(|key| !dirty.contains(key));
        for &key in &dirty {
            self.replacement_checkpoint(false);
            let Some(route) = new.table.get(&key.0, key.1) else {
                continue;
            };
            match inventory_entry(old, new, route, &prestaged.rs_asns) {
                Err(term) => {
                    prestaged.failed.insert(key, term);
                }
                Ok(InventoryEntry::Unchanged) => {}
                Ok(InventoryEntry::Changed { next_hop, tagged }) => {
                    prestaged.announce.push(
                        new.table
                            .unicast_handle(&key.0, key.1)
                            .expect("staged dirty key exists"),
                    );
                    prestaged.next_hop_override.push(next_hop);
                    if tagged {
                        prestaged.tagged.insert(key);
                    }
                }
            }
        }
        // A slice-map is exact sized: Arc's FromIterator allocates its slice
        // directly, avoiding a full written Vec<Route> and its second copy.
        let announce = prestaged
            .announce
            .iter()
            .map(|&handle| {
                self.replacement_checkpoint(false);
                new.table
                    .unicast_slot(handle as usize)
                    .expect("reconciled staged key exists")
                    .clone()
            })
            .collect();
        let next_hop_override = prestaged
            .next_hop_override
            .iter()
            .map(|next_hop| {
                self.replacement_checkpoint(false);
                next_hop.clone()
            })
            .collect();
        prestaged.sealed = Some(CleanPolicyTransitionInventory {
            announce,
            next_hop_override,
            permit_totals: std::collections::HashMap::default(),
            permit_by_source: std::collections::HashMap::default(),
        });
        crate::manager::retire_vec(&mut prestaged.announce, &mut || {
            self.replacement_checkpoint(false);
        });
        crate::manager::retire_vec(&mut prestaged.next_hop_override, &mut || {
            self.replacement_checkpoint(false);
        });
        crate::manager::retire_hash_set(&mut dirty, &mut || self.replacement_checkpoint(false));
    }

    /// Under the fence: turn the prestaged inventory for `source` →
    /// `destination` into the exact inventory a fenced full walk of the
    /// current tables would build, re-checking only the keys churn touched
    /// since the walk began. Always consumes the prestaged inventory and
    /// stops both groups' key logs.
    pub(in crate::manager) fn take_prestaged_transition_inventory(
        &mut self,
        source: usize,
        destination: usize,
        rs_asns: &[u32],
    ) -> PrestagedInventoryOutcome {
        let Some(mut prestaged) = self.prestaged_inventory.take() else {
            return PrestagedInventoryOutcome::Unusable;
        };
        let logs = [prestaged.source, prestaged.destination].map(|gid| {
            self.group_ribs
                .get_mut(&gid)
                .and_then(|group| group.inventory_log.take())
        });
        let usable = (prestaged.source, prestaged.destination) == (source, destination)
            && prestaged.complete
            && logs.iter().all(Option::is_some)
            && rs_asns
                .iter()
                .all(|asn| prestaged.rs_asns.binary_search(asn).is_ok());
        let mut dirty = FastSet::default();
        for log in logs.into_iter().flatten() {
            dirty.extend(log);
        }
        let outcome = if usable {
            self.recheck_prestaged_transition_inventory(&mut prestaged, &dirty, rs_asns)
        } else {
            PrestagedInventoryOutcome::Unusable
        };
        crate::manager::retire_hash_set(&mut dirty, &mut || self.replacement_checkpoint(false));
        self.prestaged_inventory = Some(prestaged);
        self.retire_prestaged_transition_inventory();
        outcome
    }

    /// Reconcile only touched rows. The ordinary vector builder remains the
    /// resize fallback; equal cardinality retains the unpublished Arc slices.
    fn reconcile_sealed_transition_payload(
        &self,
        prestaged: &mut PrestagedTransitionInventory,
        dirty: &FastSet<(Prefix, u32)>,
        old: &GroupRibOut,
        new: &GroupRibOut,
    ) -> Option<CleanPolicyTransitionInventoryBuilder> {
        let checkpoint = || self.replacement_checkpoint(false);
        let mut sealed = prestaged.sealed.take()?;
        let mut inventory = CleanPolicyTransitionInventoryBuilder::default();
        if dirty.is_empty() {
            inventory.prebuilt = Some(sealed);
            return Some(inventory);
        }
        let touched_positions = sealed
            .announce
            .iter()
            .enumerate()
            .filter_map(|(index, route)| {
                checkpoint();
                dirty
                    .contains(&(route.prefix, route.path_id))
                    .then_some(index)
            })
            .collect::<Vec<_>>();
        prestaged.failed.retain(|key, _| !dirty.contains(key));
        prestaged.tagged.retain(|key| !dirty.contains(key));
        let mut changed = Vec::with_capacity(dirty.len());
        for &key in dirty {
            checkpoint();
            let Some(route) = new.table.get(&key.0, key.1) else {
                continue;
            };
            match inventory_entry(old, new, route, &prestaged.rs_asns) {
                Err(term) => {
                    prestaged.failed.insert(key, term);
                }
                Ok(InventoryEntry::Unchanged) => {}
                Ok(InventoryEntry::Changed { next_hop, tagged }) => {
                    changed.push((route.clone(), next_hop));
                    if tagged {
                        prestaged.tagged.insert(key);
                    }
                }
            }
        }
        if touched_positions.len() == changed.len() {
            // The sealed payload has no other Arc owners before the fence.
            // Replace the touched rows in place; order is not a contract.
            let routes = std::sync::Arc::get_mut(&mut sealed.announce)
                .expect("unpublished payload is uniquely owned");
            let next_hops = std::sync::Arc::get_mut(&mut sealed.next_hop_override)
                .expect("unpublished next hops are uniquely owned");
            for (&index, (route, next_hop)) in touched_positions.iter().zip(changed) {
                checkpoint();
                routes[index] = route;
                next_hops[index] = next_hop;
            }
            if let Some(mut probe) = prestaged.probe.take_if(|probe| {
                !crate::manager::distribution::reprobe_prestaged_transition_rows(
                    &sealed,
                    probe,
                    &touched_positions,
                    &mut || checkpoint(),
                )
            }) {
                probe.retire_with(&mut || checkpoint());
            }
            inventory.prebuilt = Some(sealed);
        } else {
            // Cardinality-changing churn cannot resize an Arc slice. Keep
            // the authoritative vector path for this uncommon case.
            let count = sealed.announce.len() - touched_positions.len() + changed.len();
            self.replacement_checkpoint(true);
            inventory.announce.reserve_exact(count);
            self.replacement_checkpoint(true);
            inventory.next_hop_override.reserve_exact(count);
            self.replacement_checkpoint(true);
            for (route, next_hop) in sealed.announce.iter().zip(sealed.next_hop_override.iter()) {
                checkpoint();
                if !dirty.contains(&(route.prefix, route.path_id)) {
                    inventory.announce.push(route.clone());
                    inventory.next_hop_override.push(next_hop.clone());
                }
            }
            for (route, next_hop) in changed {
                checkpoint();
                inventory.announce.push(route);
                inventory.next_hop_override.push(next_hop);
            }
            sealed.retire_with(&mut |force| self.replacement_checkpoint(force));
            if let Some(mut probe) = prestaged.probe.take() {
                probe.retire_with(&mut || checkpoint());
            }
        }
        Some(inventory)
    }

    fn recheck_prestaged_transition_inventory(
        &self,
        prestaged: &mut PrestagedTransitionInventory,
        dirty: &FastSet<(Prefix, u32)>,
        rs_asns: &[u32],
    ) -> PrestagedInventoryOutcome {
        let (source, destination) = (prestaged.source, prestaged.destination);
        let (Some(old), Some(new)) = (
            self.group_ribs.get(&source),
            self.group_ribs.get(&destination),
        ) else {
            return PrestagedInventoryOutcome::Degraded;
        };
        if !clean_inventory_pair(old, new) {
            return PrestagedInventoryOutcome::Degraded;
        }
        let checkpoint = || {
            crate::manager::replacement_readiness_checkpoint_at(
                &self.replacement_readiness,
                "shared_inventory",
                false,
            );
        };
        let Some(mut inventory) =
            self.reconcile_sealed_transition_payload(prestaged, dirty, old, new)
        else {
            return PrestagedInventoryOutcome::Unusable;
        };
        if let Some((&key, &term)) = prestaged.failed.iter().next() {
            inventory_degraded(source, destination, Some(key), term);
            inventory.retire_with(&mut |force| self.replacement_checkpoint(force));
            return PrestagedInventoryOutcome::Degraded;
        }
        // `tagged` is relative to the walk's ASN superset: re-ask each
        // tagged key about the cohort's own ASNs (none ⇒ no tag check).
        if !rs_asns.is_empty() {
            for &key in &prestaged.tagged {
                checkpoint();
                let tagged = new.table.get(&key.0, key.1).is_some_and(|route| {
                    matches!(
                        inventory_entry(old, new, route, rs_asns),
                        Ok(InventoryEntry::Changed { tagged: true, .. })
                    )
                });
                if tagged {
                    inventory_degraded(source, destination, Some(key), "rs-control tag");
                    inventory.retire_with(&mut |force| self.replacement_checkpoint(force));
                    return PrestagedInventoryOutcome::Degraded;
                }
            }
        }
        // Permit counts: one per staged entry under the group-uniform
        // label, so `source_counts` already holds the per-source fold
        // (VPN slots are empty: `clean_inventory_pair` proved it).
        let label = new.permit_policy_label.as_deref().map(str::to_owned);
        let mut total = 0;
        for (&peer, counts) in &new.source_counts {
            checkpoint();
            let count = u64::try_from(counts[0] + counts[1]).unwrap_or(u64::MAX);
            if count > 0 {
                total += count;
                inventory
                    .permit_by_source
                    .entry(peer)
                    .or_default()
                    .insert(label.clone(), count);
            }
        }
        if total > 0 {
            inventory.permit_totals.insert(label, total);
        }
        PrestagedInventoryOutcome::Ready(Box::new(inventory), prestaged.probe.take())
    }

    /// Drop any prestaged inventory and stop its groups' key logs. Every
    /// path that retires or hands off a prepared destination calls this.
    pub(in crate::manager) fn retire_prestaged_transition_inventory(&mut self) {
        let Some(mut prestaged) = self.prestaged_inventory.take() else {
            return;
        };
        for gid in [prestaged.source, prestaged.destination] {
            if let Some(mut log) = self
                .group_ribs
                .get_mut(&gid)
                .and_then(|group| group.inventory_log.take())
            {
                crate::manager::retire_hash_set(&mut log, &mut || {
                    self.replacement_checkpoint(false);
                });
            }
        }
        if let Some(mut sealed) = prestaged.sealed.take() {
            sealed.retire_with(&mut |force| self.replacement_checkpoint(force));
        }
        if let Some(mut probe) = prestaged.probe.take() {
            probe.retire_with(&mut || self.replacement_checkpoint(false));
        }
        self.replacement_checkpoint(true);
        crate::manager::retire_vec(&mut prestaged.announce, &mut || {
            self.replacement_checkpoint(false);
        });
        crate::manager::retire_vec(&mut prestaged.next_hop_override, &mut || {
            self.replacement_checkpoint(false);
        });
        self.replacement_checkpoint(true);
    }

    /// Apply the inventory's pre-aggregated permit counts to one member after
    /// its writer slot has been reserved. This preserves the existing grouped
    /// split-horizon counter semantics without another full-table walk.
    pub(in crate::manager) fn apply_clean_policy_transition_counters(
        &mut self,
        peer: IpAddr,
        inventory: &CleanPolicyTransitionInventory,
    ) {
        let own = inventory.permit_by_source.get(&peer);
        let rows = inventory
            .permit_totals
            .iter()
            .filter_map(|(label, total)| {
                self.replacement_checkpoint(false);
                let count = total.saturating_sub(
                    own.and_then(|counts| counts.get(label))
                        .copied()
                        .unwrap_or(0),
                );
                (count > 0).then_some((label.clone(), PolicyAction::Permit, count))
            })
            .collect::<Vec<_>>();
        self.bump_export_counters(peer, &rows);
    }

    /// Whether a source/destination group pair qualifies for the shared
    /// batched authoritative transition: unicast-only on both sides and
    /// differing only in export-chain content (the clean transition's
    /// narrow shape, checked on the interned keys).
    pub(in crate::manager) fn batched_transition_keys_qualify(
        &self,
        source: usize,
        destination: usize,
    ) -> bool {
        let (Some(source_key), Some(destination_key)) = (
            self.update_groups.group_key(source),
            self.update_groups.group_key(destination),
        ) else {
            return false;
        };
        source_key.is_unicast_only()
            && destination_key.is_unicast_only()
            && source_key.same_staging_profile_except_chain(destination_key)
    }

    /// The fingerprint itself: disqualifiers first (design §1), then
    /// the group key from RIB-staging inputs.
    pub(in crate::manager) fn compute_update_group_membership(
        &mut self,
        peer: IpAddr,
    ) -> GroupMembership {
        let chain = self.export_policy_for(peer).cloned();
        self.compute_update_group_membership_for_policy(peer, chain.as_ref(), None)
    }

    pub(in crate::manager) fn compute_update_group_membership_with_receipt(
        &mut self,
        peer: IpAddr,
        receipt: &mut crate::manager::AuthoritativeTransitionReceipt,
    ) -> GroupMembership {
        let chain = self.export_policy_for(peer).cloned();
        let membership =
            self.compute_update_group_membership_for_policy(peer, chain.as_ref(), Some(receipt));
        match membership {
            GroupMembership::Grouped(_) => receipt.membership_grouped += 1,
            _ => receipt.membership_ungrouped += 1,
        }
        membership
    }

    /// Classify a prospective policy without changing the peer's installed
    /// policy or runtime membership. Registry IDs are append-only; the
    /// enclosing operation retains prospective IDs until it commits or
    /// discards them. No group table or wire state is touched here.
    fn compute_update_group_membership_for_policy(
        &mut self,
        peer: IpAddr,
        chain: Option<&PolicyChain>,
        receipt: Option<&mut crate::manager::AuthoritativeTransitionReceipt>,
    ) -> GroupMembership {
        // Differential-oracle hook: force every peer onto the per-peer
        // fallback path so identical scenarios can be compared grouped
        // vs ungrouped. Reuses the policy-peer-context reason label.
        #[cfg(test)]
        if self.test_force_ungrouped {
            return GroupMembership::PolicyPeerContext;
        }
        // Slow-peer isolation (LAN-470): a transport-flagged slow peer
        // stays on the per-peer path so its backlog cannot drag the
        // shared staging pass. Checked before the classifier — it
        // overrides an otherwise-groupable fingerprint.
        if self.slow_isolated_peers.contains(&peer) {
            return GroupMembership::SlowPeer;
        }
        // ORF-receive negotiated ⇒ ungrouped from the start (the RFC
        // 5291 §6 gate never meets grouping). Read from the live
        // session record — `peer_orf_pending` drains as gates lift, so
        // it can't answer "was ORF negotiated" later in the session.
        let orf_negotiated = self
            .live_sessions
            .get(&peer)
            .and_then(|sessions| sessions.last())
            .is_some_and(|record| !record.negotiated_orf_recv.is_empty());
        let input = self.update_group_classifier_input(
            peer,
            chain,
            orf_negotiated || self.peer_orf_filters.contains_key(&peer),
            false,
        );
        let fingerprint = match classify_update_group(input) {
            UpdateGroupClassification::PolicyPeerContext => {
                return GroupMembership::PolicyPeerContext;
            }
            UpdateGroupClassification::AddPathSend => return GroupMembership::AddPathSend,
            UpdateGroupClassification::PerClientBest => return GroupMembership::PerClientBest,
            UpdateGroupClassification::OrrVantage => return GroupMembership::OrrVantage,
            UpdateGroupClassification::OrfInstalled => return GroupMembership::OrfInstalled,
            UpdateGroupClassification::Groupable(fingerprint) => fingerprint,
        };

        // Clone released before the &mut intern below; chains are small
        // and this runs at config/session-lifecycle frequency only.
        let chain_idx = chain.map(|chain| self.update_groups.intern_chain(chain, receipt));
        let key = GroupKey {
            chain: chain_idx,
            target_is_ebgp: fingerprint.target_is_ebgp,
            target_is_rr_client: fingerprint.target_is_rr_client,
            target_local_role: fingerprint.target_local_role,
            interpret_rfc1997: fingerprint.interpret_rfc1997,
            sendable_ipv4_unicast: fingerprint.sendable_ipv4_unicast,
            sendable_ipv6_unicast: fingerprint.sendable_ipv6_unicast,
            sendable_vpnv4: fingerprint.sendable_vpnv4,
            sendable_vpnv6: fingerprint.sendable_vpnv6,
            rtc_negotiated: fingerprint.rtc_negotiated,
            per_client_best: fingerprint.per_client_best,
            llgr_families: fingerprint.llgr_families,
        };
        GroupMembership::Grouped(self.update_groups.group_for(key))
    }

    /// Preflight the prospective group id for a clean unicast-only policy
    /// transition and prove that only the chain dimension changes.
    pub(in crate::manager) fn clean_policy_transition_destination(
        &mut self,
        peer: IpAddr,
        policy: Option<&PolicyChain>,
    ) -> Option<(usize, usize)> {
        let GroupMembership::Grouped(source) = self.update_groups.members.get(&peer)? else {
            return None;
        };
        let source = *source;
        // A per-client-best source group never takes the ADR-0105 fast
        // path — nor its unfenced destination prestage, whose only
        // preflight is this function. Checked on the source cell: the
        // ADR-0126 `per_client_best` key bit keeps source and
        // destination in agreement, so rejecting the source here also
        // keeps every destination cell the prestage creates plain.
        // Re-inclusion is demand-gated (ADR-0126 Decision 8).
        if self
            .group_ribs
            .get(&source)
            .is_some_and(|group| group.per_client_best)
        {
            return None;
        }
        let GroupMembership::Grouped(destination) =
            self.compute_update_group_membership_for_policy(peer, policy, None)
        else {
            return None;
        };
        let source_key = self.update_groups.group_key(source)?;
        let destination_key = self.update_groups.group_key(destination)?;
        (source != destination
            && source_key.is_unicast_only()
            && destination_key.is_unicast_only()
            && source_key.same_staging_profile_except_chain(destination_key))
        .then_some((source, destination))
    }

    /// Create an unowned prospective destination group and return its prefix
    /// staging snapshot. An existing destination is already maintained and
    /// therefore needs no staging (`None`).
    pub(in crate::manager) fn begin_policy_transition_group(
        &mut self,
        gid: usize,
        peer: IpAddr,
        export_policy: Option<&PolicyChain>,
    ) -> PolicyTransitionGroupStart {
        if self.group_ribs.contains_key(&gid) {
            return PolicyTransitionGroupStart::Maintained;
        }
        self.replacement_checkpoint(true);
        let group = GroupRibOut::new(
            export_policy.map(PolicyChain::share),
            self.peer_is_ebgp.get(&peer).copied().unwrap_or(false),
            self.peer_interpret_rfc1997.contains(&peer),
            self.peer_is_rr_client.get(&peer).copied().unwrap_or(false),
            self.peer_local_roles.get(&peer).copied().flatten(),
            self.peer_sendable_families
                .get(&peer)
                .cloned()
                .unwrap_or_default(),
            self.peer_advertised_llgr_families
                .get(&peer)
                .cloned()
                .unwrap_or_default(),
            // ADR-0126 Decision 1: derived from the key bit. In
            // practice always false here — per-client-best SOURCE
            // groups never pass the fast-path preflight (Decision 8),
            // and the key bit keeps source and destination in
            // agreement.
            self.update_groups
                .group_key(gid)
                .is_some_and(|key| key.per_client_best),
            self.loc_rib.len(),
        );
        self.replacement_checkpoint(true);
        self.group_ribs.insert(gid, group);
        // Loc-RIB keys are unique per prefix (Add-Path paths collapse to
        // one best before they get here), so the snapshot needs no dedup.
        let mut snapshot = Vec::with_capacity(self.loc_rib.len());
        self.replacement_checkpoint(true);
        for prefix in self.loc_rib.prefixes() {
            self.replacement_checkpoint(false);
            snapshot.push(prefix);
        }
        self.replacement_checkpoint(true);
        PolicyTransitionGroupStart::Created(snapshot)
    }

    /// Stage one bounded prefix chunk into an unowned destination group.
    pub(in crate::manager) fn stage_policy_transition_group_chunk(
        &mut self,
        gid: usize,
        prefixes: &[Prefix],
        memo: &mut crate::manager::distribution::ExportMemo,
    ) {
        self.replacement_checkpoint(true);
        let mut prefixes = prefixes
            .iter()
            .inspect(|_| self.replacement_checkpoint(false))
            .copied()
            .collect::<FastSet<_>>();
        self.replacement_checkpoint(true);
        let mut output = self.stage_group_prefixes(gid, &prefixes, memo);
        output.retire_with(&mut |force| self.replacement_checkpoint(force));
        crate::manager::retire_hash_set(&mut prefixes, &mut || self.replacement_checkpoint(false));
        self.replacement_checkpoint(true);
        drop(output);
        drop(prefixes);
        self.replacement_checkpoint(true);
    }

    /// Remove a partially or fully staged, still-unowned destination before
    /// the caller hands the transition back to the authoritative per-peer path.
    ///
    /// `false` means the group had members and was therefore KEPT — it is
    /// now an owned, maintained group, not a leak. Callers that can only
    /// reach this with a group they created must treat `false` as an error;
    /// callers cleaning up a possibly-adopted prestage discard it explicitly.
    #[must_use = "false leaves the group in place; a caller that created it must treat that as an error"]
    pub(in crate::manager) fn discard_uncommitted_policy_transition_group(
        &mut self,
        gid: usize,
    ) -> bool {
        let removable = self
            .group_ribs
            .get(&gid)
            .is_none_or(|group| group.members.is_empty());
        if removable {
            self.remove_group_with_readiness(gid);
        }
        removable
    }

    /// Commit a preflighted clean transition after every writer slot and exact
    /// snapshot has been validated. No regroup baseline is needed because the
    /// shared transition diff is already the authoritative old-to-new wire
    /// delta accepted by every target writer.
    pub(in crate::manager) fn commit_clean_policy_transition_member(
        &mut self,
        peer: IpAddr,
        source: usize,
        destination: usize,
    ) {
        self.leave_group_without_gauge_refresh(source, peer);
        self.update_groups
            .members
            .insert(peer, GroupMembership::Grouped(destination));
        self.install_group_member(destination, peer);
        self.metrics.record_update_group_regroup();
    }

    /// Publish cohort-wide gauges once after the synchronous membership commit.
    /// Refreshing them per member is both unobservable (queries cannot
    /// interleave in the commit section) and quadratic for large cohorts.
    /// The advertised page generation advances here as well: general queries
    /// are served from the pre-commit state between the earlier polls, so a
    /// continuation started there must not resume over the switched
    /// memberships.
    pub(in crate::manager) fn finish_clean_policy_transition_commit(&mut self) {
        self.refresh_update_group_gauges();
        self.refresh_group_residue_gauge();
        self.advance_advertised_pages();
    }

    /// Build the shared old→new inventory for one batched authoritative
    /// cohort transition ([`crate::update::RibUpdate::ReplacePeerExportPoliciesAuthoritatively`]):
    /// every batch member of `source` moves to the current staged
    /// `destination` (same staging profile except the chain — validated
    /// by the caller). Returns `None` when the delta carries an RFC 7947
    /// control-form community for one of the cohort's rs-control ASNs on
    /// either side of policy — per-target suppress/prepend/scrub cannot
    /// ride a shared payload, so the caller degrades the cohort to the
    /// ordinary per-member machinery (the clean transition's
    /// tagged-inventory posture).
    ///
    /// The shared announce carries each destination entry whose wire
    /// form differs from the source entry at the same key
    /// (equality-suppressed — O(actual policy diff), a content-equal
    /// restage emits nothing); the shared withdraw carries the keys the
    /// destination no longer stages (over-withdraw safe toward members
    /// whose wire never held them). Per-member divergence is exactly the
    /// ADR-0126 Decision 4 emit-time exception set: split horizon rides
    /// the envelope's `announce_source_exclusion`, and the lane
    /// substitution toward each winner's source rides the member-scoped
    /// supplements built here. Counter aggregates are folded once so the
    /// per-member replay is O(labels), not O(table) — the same rows
    /// [`RibManager::apply_group_join_counters`] would derive per member.
    #[expect(
        clippy::too_many_lines,
        reason = "one walk keeps the shared delta, the lane supplements, the \
                  OTC/rs-control degrade gates, and the counter fold aligned"
    )]
    pub(in crate::manager) fn batched_transition_inventory(
        source: &GroupRibOut,
        destination: &GroupRibOut,
        rs_asns: &[u32],
        checkpoint: &mut impl FnMut(bool),
    ) -> Option<BatchedTransitionInventory> {
        use crate::manager::distribution::rs_control::rs_control_route_tagged;
        // RFC 9234 OTC residue on either side means blocked staged
        // winners (or lane runner-ups) whose per-member diagnostics and
        // withdraw conversions belong to the pre-commit backstop this
        // shared emission does not run — the per-member path owns those.
        // A role-bearing fleet with no OTC-attributed routes (the
        // rendered route-server default) carries no residue and shares.
        if !source.otc_blocked.is_empty() || !destination.otc_blocked.is_empty() {
            return None;
        }
        let attrs_tagged = |attrs: (&[u32], &[LargeCommunity])| {
            rs_asns
                .iter()
                .any(|&rs_asn| rs_control_route_tagged(attrs.0, attrs.1, rs_asn))
        };
        let route_tagged = |route: &Route| {
            rs_asns.iter().any(|&rs_asn| {
                rs_control_route_tagged(route.communities(), route.large_communities(), rs_asn)
            })
        };
        // The pre-commit backstop strips an OTC-blocked route from every
        // emission; an emitted delta containing one cannot ride the
        // shared payload, so its cohort degrades to the per-member path
        // (which runs the backstop at its own seams).
        let blocked = |route: &Route| {
            crate::manager::distribution::otc_egress_blocked(route, destination.local_role)
        };
        checkpoint(true);
        let mut announce: Vec<Route> = Vec::with_capacity(destination.table.len());
        checkpoint(true);
        let mut next_hop_override: Vec<Option<NextHopAction>> =
            Vec::with_capacity(destination.table.len());
        checkpoint(true);
        let mut supplements: FastMap<IpAddr, BatchedMemberSupplement> = FastMap::default();
        let mut counters = BatchedTransitionCounters::default();
        let mut rejected = false;
        'destination: for route in destination.table.iter() {
            checkpoint(false);
            let key = (route.prefix, route.path_id);
            let next_hop = destination.nh_override(key);
            let prior = source.table.get(&route.prefix, route.path_id);
            let changed = match prior {
                None => true,
                Some(prior_route) => {
                    !routes_equal(prior_route, route) || source.nh_override(key) != next_hop
                }
            };
            if changed {
                if blocked(route)
                    || (!rs_asns.is_empty()
                        && (route_tagged(route)
                            || attrs_tagged(destination.source_control(key))
                            || attrs_tagged(source.source_control(key))))
                {
                    rejected = true;
                    break 'destination;
                }
                next_hop_override.push(next_hop);
                announce.push(route.clone());
            }
            // Counter fold: one permit per staged entry, labelled by its
            // retained decision attribution; per-source rows feed the
            // Decision 4 `totals − own + lane` synthesis below.
            let label = destination.permit_policy_label.clone();
            counters.record_permit(route.peer, label);
            // Member-scoped correction for the slot's own source — the
            // one member the shared exclusion silences at this key. Its
            // wire held `adv_source(m)` (the source group's lane
            // substitution when it also sourced the old winner, the old
            // entry otherwise); its target is the destination lane's
            // substitution or nothing (ADR-0126 Decision 4).
            let lane_new = destination.runner_up.get(&route.prefix);
            let prior_source = prior.map(|prior_route| prior_route.peer);
            let lane_old = source.runner_up.get(&route.prefix);
            if let Some(entry) = lane_new {
                let suppressed = prior_source == Some(route.peer)
                    && lane_old.is_some_and(|prev| {
                        routes_equal(&prev.route, &entry.route) && prev.nh == entry.nh
                    });
                if !suppressed {
                    if blocked(&entry.route)
                        || (!rs_asns.is_empty()
                            && (route_tagged(&entry.route)
                                || attrs_tagged(source_control_input(entry.source_attrs.as_ref()))
                                || lane_old.is_some_and(|prev| {
                                    attrs_tagged(source_control_input(prev.source_attrs.as_ref()))
                                })))
                    {
                        rejected = true;
                        break 'destination;
                    }
                    let supplement = supplements.entry(route.peer).or_default();
                    if supplement.announce.capacity() == 0 {
                        let source_count = destination
                            .source_counts
                            .get(&route.peer)
                            .map_or(0, |counts| counts[0] + counts[1]);
                        checkpoint(true);
                        supplement.announce.reserve_exact(source_count);
                        checkpoint(true);
                    }
                    supplement
                        .announce
                        .push((entry.route.clone(), entry.nh.clone()));
                }
            } else {
                // Over-withdraw-safe: emit whenever the source group
                // staged the key and the member's wire could hold
                // anything there (a displaced other-sourced entry — the
                // source-flip arm — or a retired substitution). A no-op
                // when the wire was already empty.
                let had_wire =
                    prior.is_some() && (prior_source != Some(route.peer) || lane_old.is_some());
                if had_wire {
                    let supplement = supplements.entry(route.peer).or_default();
                    if supplement.withdraw.capacity() == 0 {
                        let source_count = destination
                            .source_counts
                            .get(&route.peer)
                            .map_or(0, |counts| counts[0] + counts[1]);
                        checkpoint(true);
                        supplement.withdraw.reserve_exact(source_count);
                        checkpoint(true);
                    }
                    supplement.withdraw.push(key);
                }
            }
        }
        if rejected {
            checkpoint(true);
            crate::manager::retire_vec(&mut announce, &mut || checkpoint(false));
            crate::manager::retire_vec(&mut next_hop_override, &mut || checkpoint(false));
            for (_, mut supplement) in supplements.drain() {
                checkpoint(false);
                crate::manager::retire_vec(&mut supplement.announce, &mut || checkpoint(false));
                crate::manager::retire_vec(&mut supplement.withdraw, &mut || checkpoint(false));
            }
            checkpoint(true);
            drop(announce);
            drop(next_hop_override);
            drop(supplements);
            counters.retire_with(checkpoint);
            drop(counters);
            checkpoint(true);
            return None;
        }
        checkpoint(true);
        let mut withdraw: Vec<(Prefix, u32)> = Vec::with_capacity(source.table.len());
        checkpoint(true);
        for route in source.table.iter() {
            checkpoint(false);
            if destination
                .table
                .get(&route.prefix, route.path_id)
                .is_none()
            {
                withdraw.push((route.prefix, route.path_id));
            }
        }
        for entry in destination.runner_up.values() {
            checkpoint(false);
            counters.record_lane(entry.winner_source, entry.policy_label.clone());
        }
        for denials in destination.policy_filtered.values() {
            checkpoint(false);
            for (&(source_peer, _), label) in denials {
                checkpoint(false);
                counters.record_deny(source_peer, label.clone());
            }
        }
        checkpoint(true);
        let announce = announce.into();
        checkpoint(true);
        let next_hop_override = next_hop_override.into();
        checkpoint(true);
        Some(BatchedTransitionInventory {
            announce,
            next_hop_override,
            withdraw,
            supplements,
            counters,
        })
    }

    /// Replay one cohort member's export counters from the batched
    /// inventory's pre-aggregated rows — the exact rows
    /// [`Self::apply_group_join_counters`] would fold from a full table
    /// walk (`totals − own-sourced + lane substitutions` on the permit
    /// side, `totals − own-sourced` on the denial side), at O(labels)
    /// per member instead of O(table).
    pub(in crate::manager) fn apply_batched_transition_counters(
        &mut self,
        peer: IpAddr,
        inventory: &BatchedTransitionInventory,
    ) {
        let rows = inventory
            .counters
            .rows_for(peer, &mut || self.replacement_checkpoint(false));
        if !rows.is_empty() {
            self.bump_export_counters(peer, &rows);
        }
    }
}
