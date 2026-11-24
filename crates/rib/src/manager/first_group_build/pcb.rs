//! A PCB founder ranks all paths for one prefix before installing that prefix's
//! winner, source-specific runner-up and RS fallback in its private group.
use std::collections::VecDeque;

use rustbgpd_wire::Prefix;

use super::super::distribution::release_pcb::{
    CANDIDATES_PER_POLL, FirstGroupSelection, PreparedPcb,
};
use super::super::update_groups::{FirstPcbCommit, GroupRibOut};
use super::RibManager;

#[derive(Default)]
pub(super) struct FirstGroupPcb {
    page: VecDeque<Prefix>,
    active: Option<Prefix>,
    selection: FirstGroupSelection,
    prepared: Option<PreparedPcb>,
    commit: FirstPcbCommit,
}

impl FirstGroupPcb {
    /// Take at most one discovery/repair page and share one candidate budget
    /// across its prefixes, including the receiver's control-index preparation.
    pub(super) fn advance(&mut self, manager: &mut RibManager, group: &mut GroupRibOut) -> bool {
        let mut budget = CANDIDATES_PER_POLL;
        let mut took_page = false;
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
            }
            let prefix = self.active.expect("started prefix");
            // A queued repair owns a fresh pass over the current paths. Never
            // dereference a saved heap identity after the sender withdrew it.
            if manager.loc_rib.registration_candidate_queued(&prefix) {
                self.discard();
                continue;
            }
            if self.prepared.is_none() {
                self.prepared =
                    manager.poll_first_group_pcb(group, prefix, &mut self.selection, &mut budget);
            }
            let Some(prepared) = self.prepared.as_mut() else {
                return false;
            };
            if !self.commit.prepare(group, prefix, prepared, &mut budget) {
                return false;
            }
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
