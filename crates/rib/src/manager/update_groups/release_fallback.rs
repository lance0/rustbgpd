//! A PCB fallback list keeps policy order. During a fenced release, prepare
//! large lists once per route-server/receiver ASN pair. Split horizon can
//! exclude one source, so the first two eligible, distinct sources suffice.

use std::collections::BTreeMap;
use std::ops::{Deref, Index};
use std::sync::Arc;

use super::{PeerId, PerClientBestPrefixStage, Prefix, RibManager, RunnerUp, source_control_input};
use crate::manager::distribution::rs_control::rs_control_suppressed;

pub(in crate::manager) const FALLBACK_PAGE: usize = 128;
type Control = (u32, u32);
type Slots = [Option<usize>; 2];
type Projections = BTreeMap<Control, Slots>;

/// Small fallbacks occupy one vector. Overflow pages grow independently so
/// no append moves a completed page of route payloads.
#[derive(Debug, Default)]
pub(in crate::manager) struct FallbackRows {
    first: Vec<RunnerUp>,
    rest: BTreeMap<usize, Vec<RunnerUp>>,
    len: usize,
    has_next_hop: bool,
}

impl FallbackRows {
    pub(in crate::manager) fn push(&mut self, entry: RunnerUp) {
        self.has_next_hop |= entry.nh.is_some();
        if self.len < FALLBACK_PAGE {
            self.first.push(entry);
        } else {
            self.rest
                .entry(self.len / FALLBACK_PAGE)
                .or_default()
                .push(entry);
        }
        self.len += 1;
    }

    pub(in crate::manager) fn len(&self) -> usize {
        self.len
    }

    pub(in crate::manager) fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub(super) fn iter(&self) -> impl Iterator<Item = &RunnerUp> {
        self.first.iter().chain(self.rest.values().flatten())
    }

    /// Drop at most one page. Payload destruction can release attributes,
    /// next-hop actions and policy labels.
    fn retire_page(&mut self) -> usize {
        if let Some((_, page)) = self.rest.pop_last() {
            self.len -= page.len();
            page.len()
        } else {
            let count = self.first.len();
            self.first.clear();
            self.len -= count;
            count
        }
    }
}

impl Index<usize> for FallbackRows {
    type Output = RunnerUp;
    fn index(&self, index: usize) -> &RunnerUp {
        if index < FALLBACK_PAGE {
            &self.first[index]
        } else {
            &self.rest[&(index / FALLBACK_PAGE)][index % FALLBACK_PAGE]
        }
    }
}

#[derive(Debug, Clone)]
pub(in crate::manager) struct RsFallback {
    rows: Arc<FallbackRows>,
    prepared: Option<Arc<Projections>>,
}

impl Deref for RsFallback {
    type Target = FallbackRows;

    fn deref(&self) -> &Self::Target {
        &self.rows
    }
}

impl RsFallback {
    pub(in crate::manager) fn new(rows: FallbackRows) -> Self {
        Self {
            rows: Arc::new(rows),
            prepared: None,
        }
    }

    pub(super) fn has_next_hop_actions(&self) -> bool {
        self.rows.has_next_hop
    }

    pub(super) fn prepared_slots(&self, context: Control) -> Option<Slots> {
        self.prepared.as_ref()?.get(&context).copied()
    }
}

#[derive(Default)]
struct Preparation {
    contexts: Projections,
    member: usize,
    #[cfg(test)]
    visits: usize,
    next: usize,
    slots: Slots,
}

impl Preparation {
    fn install(
        &mut self,
        list: Option<&mut RsFallback>,
        members: &[PeerId],
        context: impl Fn(PeerId) -> Option<Control>,
        budget: &mut usize,
    ) -> bool {
        let Some(list) = list.filter(|list| list.len() > FALLBACK_PAGE && list.prepared.is_none())
        else {
            return true;
        };
        if !self.poll(list, members, context, budget) {
            return false;
        }
        list.prepared = Some(Arc::new(std::mem::take(&mut self.contexts)));
        true
    }

    /// Each member lookup and candidate read spends a unit. A repeated
    /// control context reuses the same two indices regardless of source peer.
    fn poll(
        &mut self,
        entries: &RsFallback,
        members: &[PeerId],
        context: impl Fn(PeerId) -> Option<Control>,
        budget: &mut usize,
    ) -> bool {
        while let Some(&member) = members.get(self.member) {
            if *budget == 0 {
                return false;
            }
            *budget -= 1;
            let Some(context) = context(member).filter(|key| !self.contexts.contains_key(key))
            else {
                self.member += 1;
                continue;
            };
            while self.next < entries.len() && self.slots[1].is_none() {
                if *budget == 0 {
                    return false;
                }
                *budget -= 1;
                let index = self.next;
                self.next += 1;
                let entry = &entries[index];
                #[cfg(test)]
                {
                    self.visits += 1;
                }
                if self.slots[0].is_some_and(|first| entries[first].route.peer == entry.route.peer)
                {
                    continue;
                }
                let (communities, large) = source_control_input(entry.source_attrs.as_ref());
                if !rs_control_suppressed(communities, large, Some(context)) {
                    let slot = usize::from(self.slots[0].is_some());
                    self.slots[slot] = Some(index);
                }
            }
            self.contexts.insert(context, self.slots);
            self.slots = [None; 2];
            self.next = 0;
            self.member += 1;
        }
        true
    }
}

#[derive(Default)]
pub(in crate::manager) struct ReleaseFallback {
    compared: usize,
    old: Preparation,
    new: Preparation,
    // Own the displaced list through commit and delivery so the final
    // receiver cannot synchronously drop every indexed route.
    displaced: Option<Arc<FallbackRows>>,
    retired_rows: FallbackRows,
    old_contexts: Option<Arc<Projections>>,
    retired_contexts: [Projections; 2],
    retiring: bool,
}

impl RibManager {
    pub(in crate::manager) fn release_fallback_needs_pages(
        &self,
        gid: usize,
        prefix: Prefix,
        stage: &PerClientBestPrefixStage,
    ) -> bool {
        self.group_ribs[&gid]
            .rs_fallback
            .get(&prefix)
            .into_iter()
            .chain(stage.rs_fallback.iter())
            .any(|list| list.len() > FALLBACK_PAGE)
    }

    pub(in crate::manager) fn prepare_release_fallback(
        &mut self,
        gid: usize,
        prefix: Prefix,
        members: &[PeerId],
        stage: &mut PerClientBestPrefixStage,
        state: &mut ReleaseFallback,
    ) -> bool {
        let group = self.group_ribs.get_mut(&gid).expect("fenced PCB group");
        let mut old = group.rs_fallback.get_mut(&prefix);
        let mut new = stage.rs_fallback.as_mut();
        let mut budget = FALLBACK_PAGE;
        if stage.release_fallback_equal.is_none() {
            if let (Some(before), Some(after)) = (old.as_deref(), new.as_deref())
                && before.len() == after.len()
            {
                while state.compared < before.len() && budget > 0 {
                    let index = state.compared;
                    state.compared += 1;
                    budget -= 1;
                    if !super::payload::runner_up_equal(&before[index], &after[index]) {
                        stage.release_fallback_equal = Some(false);
                        break;
                    }
                }
                if stage.release_fallback_equal.is_none() {
                    if state.compared < before.len() {
                        return false;
                    }
                    stage.release_fallback_equal = Some(true);
                }
            } else {
                stage.release_fallback_equal = Some(false);
            }
        }
        let context = |peer| {
            self.peer_rs_control
                .get(&peer)
                .copied()
                .zip(self.peer_asn.get(&peer).copied())
        };
        if !state
            .old
            .install(old.as_deref_mut(), members, context, &mut budget)
        {
            return false;
        }
        if stage.release_fallback_equal == Some(true) {
            // Equality includes source peer and source control communities.
            // Every index prepared for the old list resolves the new one too.
            new.as_mut()
                .expect("equal large lists")
                .prepared
                .clone_from(&old.as_ref().expect("equal large lists").prepared);
        } else if !state.new.install(new, members, context, &mut budget) {
            return false;
        }
        if let Some(old) = old.filter(|list| list.len() > FALLBACK_PAGE) {
            state.displaced = Some(Arc::clone(&old.rows));
            state.old_contexts.clone_from(&old.prepared);
        }
        true
    }

    pub(in crate::manager) fn retire_release_fallback(
        &mut self,
        gid: usize,
        prefix: Prefix,
        state: &mut ReleaseFallback,
    ) -> bool {
        if !state.retiring {
            state.retiring = true;
            if let Some(rows) = state.displaced.take().and_then(Arc::into_inner) {
                state.retired_rows = rows;
            }
            let live = self
                .group_ribs
                .get_mut(&gid)
                .and_then(|group| group.rs_fallback.get_mut(&prefix));
            let new = live.and_then(|list| list.prepared.take());
            for (target, map) in state
                .retired_contexts
                .iter_mut()
                .zip([state.old_contexts.take(), new])
            {
                if let Some(map) = map.and_then(Arc::into_inner) {
                    *target = map;
                }
            }
        }
        let mut budget = FALLBACK_PAGE - state.retired_rows.retire_page();
        for map in &mut state.retired_contexts {
            while budget > 0 && map.pop_first().is_some() {
                budget -= 1;
            }
        }
        state.retired_rows.is_empty() && state.retired_contexts.iter().all(Projections::is_empty)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attr_set::AttrSet;
    use crate::manager::update_groups::payload::{capture_source_attrs, resolve_member_slot};
    use crate::test_support::{make_route_with_lp, peer_v4};
    use rustbgpd_wire::{Ipv4Prefix, PathAttribute};
    use std::cell::Cell;
    use std::net::Ipv4Addr;

    #[test]
    fn compare_old_and_new_fallbacks_through_the_last_page_before_staging() {
        use crate::manager::update_groups::GroupRibOut;
        use rustbgpd_telemetry::BgpMetrics;
        use tokio::sync::mpsc;

        let addr = Ipv4Addr::new(192, 0, 2, 1);
        let prefix = Ipv4Prefix::new(addr, 32);
        let key = Prefix::V4(prefix);
        let peer = peer_v4(addr);
        let list = |last_changed| {
            let mut rows = FallbackRows::default();
            for i in 0..=FALLBACK_PAGE * 2 {
                let mut route = make_route_with_lp(prefix, addr, 100);
                if last_changed && i == FALLBACK_PAGE * 2 {
                    route.next_hop = Ipv4Addr::LOCALHOST.into();
                }
                rows.push(RunnerUp {
                    route,
                    nh: None,
                    local_source: None,
                    source_attrs: None,
                    policy_label: None,
                    winner_source: peer,
                });
            }
            RsFallback::new(rows)
        };
        for changed in [false, true] {
            let mut manager = RibManager::new(
                mpsc::channel(1).1,
                mpsc::channel(1).1,
                None,
                None,
                BgpMetrics::new(),
            );
            manager.peer_rs_control.insert(peer, 65000);
            manager.peer_asn.insert(peer, 65100);
            let mut group =
                GroupRibOut::new(None, true, false, false, None, vec![], vec![], true, 0);
            group.apply_rs_fallback(key, Some(list(false)));
            manager.group_ribs.insert(0, group);
            let mut stage = PerClientBestPrefixStage {
                rs_fallback: Some(list(changed)),
                ..Default::default()
            };
            let mut state = ReleaseFallback::default();
            assert!(manager.release_fallback_needs_pages(0, key, &stage));
            loop {
                let before = state.compared + state.old.visits + state.new.visits;
                let ready =
                    manager.prepare_release_fallback(0, key, &[peer], &mut stage, &mut state);
                let checked = state.compared + state.old.visits + state.new.visits - before;
                assert!(checked <= FALLBACK_PAGE);
                if ready {
                    break;
                }
            }
            assert_eq!(stage.release_fallback_equal, Some(!changed));
            assert_eq!(state.compared, FALLBACK_PAGE * 2 + 1);
            assert_eq!(
                state.new.visits,
                if changed { FALLBACK_PAGE * 2 + 1 } else { 0 }
            );
            manager
                .group_ribs
                .get_mut(&0)
                .unwrap()
                .apply_rs_fallback(key, stage.rs_fallback);
            let mut drops = Vec::new();
            let mut remaining = FALLBACK_PAGE * 2 + 1;
            loop {
                let done = manager.retire_release_fallback(0, key, &mut state);
                drops.push(remaining - state.retired_rows.len());
                remaining = state.retired_rows.len();
                if done {
                    break;
                }
            }
            assert_eq!(drops, [1, FALLBACK_PAGE, FALLBACK_PAGE]);
            assert!(
                manager.group_ribs[&0]
                    .rs_fallback
                    .get(&key)
                    .unwrap()
                    .prepared
                    .is_none()
            );
        }
    }

    #[test]
    fn large_fallback_resolves_shared_context_once_and_retires_by_page() {
        let prefix = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 1), 32);
        let first = Ipv4Addr::new(192, 0, 2, 1);
        let second = Ipv4Addr::new(192, 0, 2, 2);
        let other = Ipv4Addr::new(192, 0, 2, 3);
        let context = (65000, 65100);
        let entry = |source, id, deny| {
            let mut route = make_route_with_lp(prefix, source, 100);
            route.path_id = id;
            if deny {
                AttrSet::edit(&mut route.attributes, |attrs| {
                    attrs.push(PathAttribute::Communities(vec![context.0]));
                });
            }
            RunnerUp {
                source_attrs: capture_source_attrs(&route),
                route,
                nh: None,
                local_source: None,
                policy_label: None,
                winner_source: peer_v4(other),
            }
        };
        let winner = entry(other, 0, true);
        let mut rows = FallbackRows::default();
        for id in 0..=u32::try_from(FALLBACK_PAGE * 2).unwrap() {
            rows.push(entry(first, id, true));
        }
        rows.push(entry(first, 1001, false));
        rows.push(entry(first, 1002, false));
        rows.push(entry(second, 1003, false));
        let mut list = RsFallback::new(rows);
        let members = [peer_v4(first), peer_v4(other), peer_v4(second)];
        let resolve = |list: &RsFallback, peer| {
            let checked = Cell::new(0);
            let route = resolve_member_slot(
                peer,
                Some(context),
                winner.adv_entry(),
                None,
                Some(list),
                |row| {
                    checked.set(checked.get() + 1);
                    source_control_input(row.source_attrs)
                },
            )
            .map(|row| row.route.path_id);
            (route, checked.get())
        };
        let expected = members.map(|peer| resolve(&list, peer).0);
        assert_eq!(expected, [Some(1003), Some(1001), Some(1001)]);
        assert!(resolve(&list, members[1]).1 > FALLBACK_PAGE);
        let mut prep = Preparation::default();
        let mut visits = 0;
        let mut polls = 0;
        loop {
            let mut budget = FALLBACK_PAGE;
            let before = prep.visits;
            let done = prep.poll(&list, &members, |_| Some(context), &mut budget);
            let read = prep.visits - before;
            assert!(read <= FALLBACK_PAGE - budget);
            visits += read;
            polls += 1;
            if done {
                break;
            }
        }
        assert!(polls >= 3);
        assert_eq!(
            visits,
            list.len(),
            "one walk for three members sharing an ASN pair"
        );
        list.prepared = Some(Arc::new(prep.contexts));
        for (peer, expected) in members.into_iter().zip(expected) {
            let (slot, checks) = resolve(&list, peer);
            assert_eq!(slot, expected);
            assert!(
                checks <= 1,
                "only the winner needs a live suppression check"
            );
        }
        let mut rows = Arc::into_inner(list.rows).unwrap();
        let mut retired = Vec::new();
        while !rows.is_empty() {
            let before = rows.len();
            rows.retire_page();
            retired.push(before - rows.len());
        }
        assert_eq!(retired, [4, FALLBACK_PAGE, FALLBACK_PAGE]);
    }
}
