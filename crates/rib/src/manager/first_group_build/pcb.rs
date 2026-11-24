//! A PCB founder ranks all paths for one prefix before installing that prefix's
//! winner, source-specific runner-up and RS fallback in its private group.
use std::collections::{HashMap, VecDeque};

use rustbgpd_wire::Prefix;

use super::super::distribution::release_pcb::{
    CANDIDATES_PER_POLL, FirstGroupSelection, PreparedPcb,
};
use super::super::update_groups::{FirstPcbCommit, GroupRibOut};
use super::RibManager;
use crate::manager::distribution::ExportMemo;

/// Partial ranks of one prefix that input may discard before the build ranks
/// it whole within one poll. Repairs coalesce to one key, so a prefix that
/// changes every poll never overflows the log; without this bound a crowded
/// prefix whose losing paths keep changing would hold the founder forever.
/// The forced rank costs that prefix's candidates once, not the table.
pub(in crate::manager) const RANK_DISCARDS_BEFORE_FORCED: u8 = 2;

#[derive(Default)]
pub(super) struct FirstGroupPcb {
    page: VecDeque<Prefix>,
    active: Option<Prefix>,
    selection: FirstGroupSelection,
    prepared: Option<PreparedPcb>,
    commit: FirstPcbCommit,
    // Partial ranks discarded per prefix, until that prefix commits.
    discarded: HashMap<Prefix, u8>,
    forced: bool,
}

impl FirstGroupPcb {
    /// Take at most one discovery/repair page and share one candidate budget
    /// across its prefixes, including the receiver's control-index preparation.
    pub(super) fn advance(
        &mut self,
        manager: &mut RibManager,
        group: &mut GroupRibOut,
        memo: &mut ExportMemo,
    ) -> bool {
        let mut budget = CANDIDATES_PER_POLL;
        let mut took_page = false;
        // Only a rank carried from an earlier poll is partial. Input that
        // changed its prefix since then discards it; count the discard.
        if let Some(prefix) = self.active
            && manager.loc_rib.registration_candidate_queued(&prefix)
        {
            let discards = self.discarded.entry(prefix).or_default();
            *discards = discards.saturating_add(1);
            self.discard();
        }
        loop {
            if self.active.is_none() {
                if !self.selection.retire(&mut budget) || !self.commit.retire(&mut budget) {
                    return false;
                }
                if self.page.is_empty() {
                    if took_page {
                        return true;
                    }
                    self.page = manager.take_first_group_page().keys.into();
                    took_page = true;
                }
                let Some(&prefix) = self.page.front() else {
                    return true;
                };
                if budget == 0 {
                    return false;
                }
                budget -= 1;
                self.page.pop_front();
                self.active = Some(prefix);
                self.selection = FirstGroupSelection::default();
                self.forced = self
                    .discarded
                    .get(&prefix)
                    .is_some_and(|&discards| discards >= RANK_DISCARDS_BEFORE_FORCED);
            }
            let prefix = self.active.expect("started prefix");
            // A queued repair owns a fresh pass over the current paths. Never
            // dereference a saved heap identity after the sender withdrew it.
            if manager.loc_rib.registration_candidate_queued(&prefix) {
                self.discard();
                continue;
            }
            // No input arrives within a poll, so a forced rank always completes.
            let mut unbounded = usize::MAX;
            let spend = if self.forced {
                &mut unbounded
            } else {
                &mut budget
            };
            if self.prepared.is_none() {
                #[cfg(test)]
                if self.forced {
                    crate::manager::slice_timing::record_work("pcb_forced_ranks", 1);
                }
                self.prepared =
                    manager.poll_first_group_pcb(group, prefix, &mut self.selection, memo, spend);
                if self.selection.stale {
                    manager
                        .loc_rib
                        .record_registration_candidate_changes(&std::iter::once(prefix).collect());
                    self.discard();
                    continue;
                }
            }
            let Some(prepared) = self.prepared.as_mut() else {
                return false;
            };
            if !self.commit.prepare(group, prefix, prepared, spend) {
                return false;
            }
            self.discarded.remove(&prefix);
            self.commit.commit(
                group,
                prefix,
                self.prepared.take().expect("prepared prefix"),
            );
            self.active = None;
        }
    }

    /// A single hot prefix can repeatedly invalidate a partial rank while
    /// the repair log stays short. Count those turns when another writer waits.
    pub(super) fn active_changed(&self, loc: &crate::loc_rib::LocRib) -> bool {
        self.active
            .is_some_and(|prefix| loc.registration_candidate_queued(&prefix))
    }

    fn discard(&mut self) {
        if let Some(prepared) = self.prepared.take() {
            self.commit.discard(prepared);
        }
        self.active = None;
    }

    pub(super) fn retire(&mut self, group: &mut GroupRibOut, mut budget: usize) -> bool {
        self.discard();
        self.selection.retire(&mut budget)
            && self.commit.retire(&mut budget)
            && group.retire_first_pcb_page(&mut self.commit, &mut budget)
    }
}
