//! Install one ranked prefix into a private, policy-free PCB group. The
//! founder's RS count is maintained alongside the staged rows so publishing
//! the finished table does not seed it in a second pass.
use std::collections::BTreeMap;

use super::release_fallback::Preparation;
use super::{GroupDelta, GroupRibOut, PeerId, PolicyRows, Prefix, RsFallback};
use crate::manager::distribution::release_pcb::PreparedPcb;

#[derive(Default)]
pub(in crate::manager) struct FirstPcbCommit {
    old: Preparation,
    new: Preparation,
    displaced: Option<RsFallback>,
}

impl FirstPcbCommit {
    /// Prepare the two founder projections used to subtract the previous
    /// count and add its replacement. Either list can span many actor turns.
    pub(in crate::manager) fn prepare(
        &mut self,
        group: &mut GroupRibOut,
        prefix: Prefix,
        prepared: &mut PreparedPcb,
        budget: &mut usize,
    ) -> bool {
        // The commit can inspect a singleton inline. Longer lists share the
        // producer's candidate budget even when a poll commits many prefixes.
        if let Some((&peer, &rs)) = group.rs_members.iter().next()
            && (!self.old.install(
                group.rs_fallback.get_mut(&prefix),
                1,
                &[peer],
                |_| Some(rs),
                budget,
            ) || !self.new.install(
                prepared.stage.rs_fallback.as_mut(),
                1,
                &[peer],
                |_| Some(rs),
                budget,
            ))
        {
            return false;
        }
        if *budget == 0 {
            return false;
        }
        *budget -= 1;
        true
    }

    pub(in crate::manager) fn commit(
        &mut self,
        group: &mut GroupRibOut,
        prefix: Prefix,
        mut prepared: PreparedPcb,
    ) {
        #[cfg(test)]
        crate::manager::slice_timing::record_work("pcb_committed_prefixes", 1);
        debug_assert!(prepared.evals.is_empty() && prepared.otc_blocked.is_empty());
        debug_assert!(prepared.rows.policy_filtered.is_empty() && group.source_control_passthrough);
        let key = (prefix, 0);
        group.rs_adjust_before_commit(&[key], &mut || {});
        let new = prepared.rows.announce.pop().map(|route| {
            let nh = prepared
                .rows
                .next_hop_override
                .pop()
                .expect("winner next-hop slot");
            (route, nh)
        });
        if new.is_some() || !prepared.rows.withdraw.is_empty() {
            let local_source = prepared.rows.local_sources.remove(&key);
            if new.is_some() && group.table.get(&prefix, 0).is_none() {
                group.table.prepare_first_group_insert();
            }
            if local_source.is_some() {
                group.table.prepare_first_group_local_sources();
            }
            group.apply_delta(&GroupDelta {
                prefix,
                path_id: 0,
                local_source,
                new,
                lane: None,
                old_source: None,
                prior_source_attrs: None,
                prior: None,
                policy_label: None,
                source_attrs: None,
            });
        }
        group.apply_lane(prefix, prepared.stage.runner_up);
        debug_assert!(self.displaced.is_none());
        self.displaced = group.rs_fallback.remove(&prefix);
        group.apply_rs_fallback(prefix, prepared.stage.rs_fallback);
        group.rs_adjust_after_commit(&[key], &mut || {});
        // A fenced release prepares projections for every member by ASN pair.
        // The founder-only result has served its single count adjustment.
        if let Some(list) = group.rs_fallback.get_mut(&prefix) {
            list.clear_founder_projection();
        }
        self.old = Preparation::default();
        self.new = Preparation::default();
    }

    pub(in crate::manager) fn discard(&mut self, prepared: PreparedPcb) {
        debug_assert!(self.displaced.is_none());
        self.displaced = prepared.stage.rs_fallback;
        self.old = Preparation::default();
        self.new = Preparation::default();
    }

    pub(in crate::manager) fn retire(&mut self, budget: &mut usize) -> bool {
        if let Some(list) = &mut self.displaced {
            if !list.retire_first_pcb_rows(budget) {
                return false;
            }
            self.displaced = None;
        }
        true
    }
}

impl GroupRibOut {
    #[expect(
        clippy::zero_sized_map_values,
        reason = "the ordered announce-to-none key set keeps the PolicyRows representation"
    )]
    pub(in crate::manager) fn prepare_first_pcb_founder(
        &mut self,
        peer: PeerId,
        rs: Option<(u32, u32)>,
    ) {
        debug_assert!(self.table.is_empty() && self.members.is_empty() && self.per_client_best);
        self.runner_up = PolicyRows::Ordered(BTreeMap::default());
        self.rs_fallback = PolicyRows::Ordered(BTreeMap::default());
        if let Some(rs) = rs {
            self.rs_members.insert(peer, rs);
            self.rs_tagged = PolicyRows::Ordered(BTreeMap::default());
            self.rs_named = PolicyRows::Ordered(BTreeMap::default());
            self.rs_all = PolicyRows::Ordered(BTreeMap::default());
        }
    }

    pub(in crate::manager) fn first_pcb_founder_matches(
        &self,
        peer: PeerId,
        rs: Option<(u32, u32)>,
    ) -> bool {
        self.rs_members.get(&peer).copied() == rs
            && self.rs_members.len() == usize::from(rs.is_some())
    }

    pub(in crate::manager) fn retire_first_pcb_page(
        &mut self,
        pending: &mut FirstPcbCommit,
        budget: &mut usize,
    ) -> bool {
        debug_assert!(self.members.is_empty() && self.per_client_best);
        loop {
            if !pending.retire(budget) {
                return false;
            }
            if self.table.first_group_retirement_finished() {
                debug_assert!(self.runner_up.is_empty() && self.rs_fallback.is_empty());
                debug_assert!(
                    self.rs_tagged.is_empty() && self.rs_named.is_empty() && self.rs_all.is_empty()
                );
                return true;
            }
            if *budget == 0 {
                return false;
            }
            *budget -= 1;
            if let Some((source, prefix)) = self.table.retire_first_group_slot() {
                self.dec_source(source, &prefix);
                self.apply_lane(prefix, None);
                self.set_rs_targets((prefix, 0), None);
                pending.displaced = self.rs_fallback.remove(&prefix);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manager::slice_timing::group_work;
    use crate::manager::update_groups::release_fallback::FallbackRows;
    use crate::manager::update_groups::{PerClientBestPrefixStage, RunnerUp};
    use crate::test_support::make_route_with_path_id;
    use rustbgpd_wire::Ipv4Prefix;

    #[test]
    fn retiring_an_aborted_crowded_result_and_installed_prefix_shares_one_budget() {
        let prefix = Prefix::V4(Ipv4Prefix::new([203, 0, 113, 0].into(), 24));
        let winner = make_route_with_path_id(prefix, 0);
        let peer = winner.peer;
        let prepare = |count| {
            let mut rows = FallbackRows::default();
            let runner = RunnerUp {
                route: winner.clone(),
                nh: None,
                local_source: None,
                source_attrs: None,
                policy_label: None,
                winner_source: peer,
            };
            for _ in 0..count {
                rows.push(runner.clone());
            }
            let mut prepared = PreparedPcb {
                stage: PerClientBestPrefixStage {
                    rs_fallback: Some(RsFallback::new(rows)),
                    runner_up: Some(runner),
                    ..Default::default()
                },
                rows: crate::manager::distribution::UnicastDistributionResult::default(),
                otc_blocked: Vec::new(),
                evals: std::collections::VecDeque::default(),
            };
            prepared.rows.announce.push(winner.clone());
            prepared.rows.next_hop_override.push(None);
            prepared
        };

        let mut group = GroupRibOut::new(None, true, false, false, None, vec![], vec![], true, 0);
        group.prepare_first_pcb_founder(peer, None);
        let mut pending = FirstPcbCommit::default();
        let mut first = prepare(194);
        assert!(pending.prepare(&mut group, prefix, &mut first, &mut 128));
        pending.commit(&mut group, prefix, first);
        pending.discard(prepare(193));
        let retired = || {
            group_work()
                .get("pcb_fallback_retired_rows")
                .copied()
                .unwrap_or(0)
        };
        for (expected, finished) in [(128, false), (127, false), (128, false), (4, true)] {
            let before = retired();
            assert_eq!(
                group.retire_first_pcb_page(&mut pending, &mut 128),
                finished
            );
            assert_eq!(retired() - before, expected);
        }
        assert!(group.source_counts.is_empty() && group.lane_counts.is_empty());
        assert!(group.runner_up.is_empty() && group.rs_fallback.is_empty());
    }
}
