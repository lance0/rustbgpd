//! Group-wide PCB denials and the events for one admitted member.
//! The group release transaction owns the old and new single-prefix views.

use super::super::PolicyFilteredBucket;
use super::super::update_groups::{GroupEvalAccumulator, GroupRibOut, PolicyLabel};
use super::{HashSet, PeerId, PolicyFilteredRouteKey, Prefix, RibManager};
use crate::fast_hash::AddrMap;
use std::collections::{VecDeque, hash_map::IntoIter};

pub(super) const DENIALS_PER_POLL: usize = 128;

type LabelledKey = (PolicyFilteredRouteKey, Option<PolicyLabel>);
type DenialMap = AddrMap<(PeerId, u32), Option<PolicyLabel>>;

#[derive(Default, Clone, Copy)]
pub(super) struct MemberVerdicts {
    pub(super) counters: bool,
    pub(super) denials: bool,
}

pub(in crate::manager) struct ReleaseDenials {
    prefix: Prefix,
    rows: Vec<PolicyFilteredRouteKey>,
    labelled: std::vec::IntoIter<LabelledKey>,
    old_group: IntoIter<(PeerId, u32), Option<PolicyLabel>>,
    new_group: DenialMap,
    at: usize,
    member_keys: Option<PolicyFilteredBucket>,
    evals: VecDeque<GroupEvalAccumulator>,
    next_eval: usize,
}

impl ReleaseDenials {
    pub(in crate::manager) fn new(
        group: &mut GroupRibOut,
        prefix: Prefix,
        rows: Vec<LabelledKey>,
    ) -> Self {
        Self {
            prefix,
            rows: Vec::with_capacity(rows.len()),
            labelled: rows.into_iter(),
            old_group: group.take_release_denials(prefix).into_iter(),
            new_group: DenialMap::default(),
            at: 0,
            member_keys: None,
            evals: VecDeque::new(),
            next_eval: 0,
        }
    }

    pub(super) fn take_evals(&mut self, evals: &mut VecDeque<GroupEvalAccumulator>) {
        self.evals = std::mem::take(evals);
    }

    pub(super) fn retire_eval_page(&mut self) -> bool {
        self.evals.pop_front();
        self.evals.is_empty()
    }

    pub(super) fn poll_verdicts(
        &mut self,
        manager: &mut RibManager,
        peer: PeerId,
        receipt: MemberVerdicts,
    ) -> bool {
        if receipt.counters
            && let Some(page) = self.evals.get(self.next_eval)
        {
            manager.apply_group_policy_counters(peer, page);
            self.next_eval += 1;
            if self.next_eval < self.evals.len() {
                return false;
            }
        }
        let done = !receipt.denials || self.poll_member(manager, peer);
        if done {
            self.next_eval = 0;
        }
        done
    }

    pub(in crate::manager) fn poll_group(&mut self, group: &mut GroupRibOut) -> bool {
        let retired = self.old_group.by_ref().take(DENIALS_PER_POLL).count();
        for (key, label) in self.labelled.by_ref().take(DENIALS_PER_POLL - retired) {
            self.new_group.insert((key.source_peer, key.path_id), label);
            self.rows.push(key);
        }
        if self.old_group.len() != 0 || self.labelled.len() != 0 {
            return false;
        }
        group.set_release_denials(self.prefix, std::mem::take(&mut self.new_group));
        self.at = 0;
        true
    }

    pub(in crate::manager) fn poll_member(
        &mut self,
        manager: &mut RibManager,
        peer: PeerId,
    ) -> bool {
        let end = (self.at + DENIALS_PER_POLL).min(self.rows.len());
        let scope = manager.session_peer_scope(peer);
        for mut key in self.rows[self.at..end].iter().copied() {
            if key.source_peer == peer {
                continue;
            }
            key.target_peer = peer;
            let was_denied = manager
                .policy_filtered_routes
                .get(&peer)
                .and_then(|routes| routes.get(&self.prefix))
                .is_some_and(|bucket| match bucket {
                    PolicyFilteredBucket::One(old) => old == &key,
                    PolicyFilteredBucket::Many(old) => old.contains(&key),
                });
            match &mut self.member_keys {
                None => self.member_keys = Some(PolicyFilteredBucket::One(key)),
                Some(PolicyFilteredBucket::One(prior)) => {
                    self.member_keys =
                        Some(PolicyFilteredBucket::Many(HashSet::from([*prior, key])));
                }
                Some(PolicyFilteredBucket::Many(keys)) => {
                    keys.insert(key);
                }
            }
            if !was_denied {
                manager.publish_policy_filtered_key(key, scope);
            }
        }
        self.at = end;
        if end != self.rows.len() {
            return false;
        }
        // These keys are Copy: retiring the old bucket only frees its allocation.
        if let Some(bucket) = self.member_keys.take() {
            manager
                .policy_filtered_routes
                .entry(peer)
                .or_default()
                .insert(self.prefix, bucket);
        } else if let Some(routes) = manager.policy_filtered_routes.get_mut(&peer) {
            routes.remove(&self.prefix);
            if routes.is_empty() {
                manager.policy_filtered_routes.remove(&peer);
            }
        }
        self.at = 0;
        true
    }
}
