//! Rank and evaluate one per-client-best prefix over bounded candidate pages.
//! A release fences live candidates. A speculative first group invalidates
//! the partial rank on candidate mutation before resuming it.

use super::super::update_groups::{
    GroupEvalAccumulator, GroupRibOut, PerClientBestPrefixStage, PolicyLabel,
};
use super::pcb_rank::{PagedPaths, Path, RankedPaths};
use super::unicast::{PcbWalk, multipath_candidate_suppressed};
use super::{
    ExportMemo, HashMap, PolicyChain, PolicyFilteredRouteKey, Prefix, RibManager,
    UnicastDistributionResult, prefix_family, should_suppress_ibgp_inner,
};
use crate::route::Route;

use std::collections::VecDeque;

pub(in crate::manager) const CANDIDATES_PER_POLL: usize = 128;

pub(in crate::manager) struct PreparedPcb {
    pub(in crate::manager) stage: PerClientBestPrefixStage,
    pub(in crate::manager) rows:
        UnicastDistributionResult<(PolicyFilteredRouteKey, Option<PolicyLabel>)>,
    pub(in crate::manager) evals: VecDeque<GroupEvalAccumulator>,
    pub(in crate::manager) otc_blocked: Vec<Route>,
}

/// Ranked results one staging call consumes, by prefix.
pub(in crate::manager) struct PreparedPcbs {
    pub(in crate::manager) prefixes: HashMap<Prefix, PreparedPcb>,
    /// The release owner already replaced the group denials of its one prefix.
    pub(in crate::manager) paged_denials: bool,
}

#[derive(Default)]
pub(in crate::manager) struct ReleasePcb<S = Vec<Path>> {
    source: usize,
    after: Option<u32>,
    ranked: S,
    gathered: bool,
    walk_complete: bool,
    /// A first group found a ranked path gone; the owner requeues the prefix.
    pub(in crate::manager) stale: bool,
    walk: PcbWalk,
    rows: UnicastDistributionResult<(PolicyFilteredRouteKey, Option<PolicyLabel>)>,
    evals: VecDeque<GroupEvalAccumulator>,
    otc_blocked: Vec<Route>,
}

pub(in crate::manager) type FirstGroupSelection = ReleasePcb<PagedPaths>;

impl FirstGroupSelection {
    /// The owner invalidated a policy-free, role-free first group. Its only
    /// unbounded scratch is the ranked inventory and its partial fallback.
    pub(in crate::manager) fn retire(&mut self, budget: &mut usize) -> bool {
        debug_assert!(self.rows.policy_filtered.is_empty() && self.otc_blocked.is_empty());
        debug_assert!(self.evals.is_empty());
        self.ranked.retire(budget) && self.walk.retire_first_group_rows(budget)
    }
}

impl RibManager {
    /// Spend `budget` candidate units on one prefix. A poll shares one budget
    /// across the prefixes it ranks.
    pub(in crate::manager) fn poll_release_pcb(
        &self,
        gid: usize,
        prefix: Prefix,
        pcb: &mut ReleasePcb,
        budget: &mut usize,
    ) -> Option<PreparedPcb> {
        self.poll_pcb_prefix(self.group_ribs.get(&gid)?, prefix, pcb, budget)
    }

    pub(in crate::manager) fn poll_first_group_pcb(
        &self,
        group: &GroupRibOut,
        prefix: Prefix,
        pcb: &mut FirstGroupSelection,
        budget: &mut usize,
    ) -> Option<PreparedPcb> {
        debug_assert!(group.per_client_best && group.is_ebgp);
        debug_assert!(group.export_chain.is_none() && group.local_role.is_none());
        self.poll_pcb_prefix(group, prefix, pcb, budget)
    }

    fn poll_pcb_prefix<S: RankedPaths>(
        &self,
        group: &GroupRibOut,
        prefix: Prefix,
        pcb: &mut ReleasePcb<S>,
        budget: &mut usize,
    ) -> Option<PreparedPcb> {
        // A release fences its candidates. A first group's capture queues a
        // fresh rank before any changed path is read again, so a missing path
        // means a writer bypassed `recompute_best*`: requeue, never panic.
        let stale = std::cell::Cell::new(false);
        let route = |(source, path): Path| {
            let found = self
                .ribs
                .get(&source)
                .and_then(|rib| rib.get(&prefix, path));
            assert!(
                S::FIRST_GROUP || found.is_some(),
                "candidate source is fenced during group staging"
            );
            debug_assert!(
                found.is_some(),
                "an Adj-RIB-In write skipped candidate capture"
            );
            stale.set(stale.get() || found.is_none());
            found
        };
        let precedes = |a, b, budget: &mut usize| {
            if S::FIRST_GROUP {
                *budget -= 1;
                #[cfg(test)]
                super::super::slice_timing::record_work("first_pcb_comparisons", 1);
            }
            match (route(a), route(b)) {
                (Some(a), Some(b)) => crate::best_path::best_path_cmp(a, b).is_lt(),
                _ => false,
            }
        };
        let gathered =
            pcb.gathered || self.gather_pcb_candidates(group, prefix, pcb, budget, precedes);
        if stale.get() {
            pcb.stale = true;
            return None;
        }
        if !gathered {
            return None;
        }

        let export_pol = group.export_chain.as_ref();
        let needs_as_path_string = export_pol.is_some_and(PolicyChain::requires_as_path_string);
        let mut memo = ExportMemo::default();
        let mut evals = GroupEvalAccumulator::default();
        while !pcb.walk_complete && *budget > 0 {
            if S::FIRST_GROUP && *budget < pcb.ranked.pop_budget() {
                *budget = 0;
                break;
            }
            *budget -= 1;
            let Some(path) = pcb.ranked.pop_ranked(|a, b| precedes(a, b, budget)) else {
                pcb.walk_complete = true;
                break;
            };
            let Some(candidate) = route(path).filter(|_| !stale.get()) else {
                pcb.stale = true;
                return None;
            };
            if pcb.walk.consume(
                candidate,
                (!S::FIRST_GROUP).then_some(&group.table),
                &prefix,
                group.local_role,
                export_pol,
                needs_as_path_string,
                &mut memo,
                &mut evals,
                &mut pcb.rows,
                &mut pcb.otc_blocked,
                &mut || {},
            ) {
                pcb.walk_complete = true;
                break;
            }
        }
        // The synchronous first-group builder discards speculative pass
        // evaluations. Member counters come from the completed table on join.
        if !S::FIRST_GROUP && !evals.is_empty() {
            pcb.evals.push_back(evals);
        }
        if !pcb.walk_complete || (S::FIRST_GROUP && !pcb.ranked.retire(budget)) {
            return None;
        }
        Some(PreparedPcb {
            stage: std::mem::take(&mut pcb.walk).finish(
                &group.table,
                &prefix,
                &mut pcb.rows,
                &mut || {},
            ),
            rows: std::mem::take(&mut pcb.rows),
            evals: std::mem::take(&mut pcb.evals),
            otc_blocked: std::mem::take(&mut pcb.otc_blocked),
        })
    }

    fn gather_pcb_candidates<S: RankedPaths>(
        &self,
        group: &GroupRibOut,
        prefix: Prefix,
        pcb: &mut ReleasePcb<S>,
        budget: &mut usize,
        precedes: impl Fn(Path, Path, &mut usize) -> bool,
    ) -> bool {
        let family = prefix_family(&prefix);
        let local_only = self.selection_deferred(family);
        pcb.gathered |= !group.sendable.contains(&family);
        while !pcb.gathered && *budget > 0 {
            #[cfg(test)]
            if S::FIRST_GROUP {
                super::super::slice_timing::record_work("first_pcb_source_probes", 1);
            }
            let Some(epoch) = self.unicast_prefix_peers.epochs(&prefix).nth(pcb.source) else {
                pcb.gathered = true;
                break;
            };
            let source = self.unicast_prefix_peers.epoch_peers.get(&epoch).copied();
            let mut paths = source
                .and_then(|peer| self.ribs.get(&peer))
                .map(|rib| rib.iter_prefix_after(&prefix, pcb.after))
                .into_iter()
                .flatten();
            while *budget > 0 {
                // A sift never crosses a poll. Reserve its worst case, then
                // charge only the comparisons actually performed.
                if S::FIRST_GROUP && *budget < pcb.ranked.push_budget() {
                    *budget = 0;
                    return false;
                }
                *budget -= 1;
                let Some(candidate) = paths.next() else {
                    pcb.source += 1;
                    pcb.after = None;
                    break;
                };
                #[cfg(test)]
                if S::FIRST_GROUP {
                    super::super::slice_timing::record_work("first_pcb_gathered", 1);
                }
                pcb.after = Some(candidate.path_id);
                if (!local_only || super::unicast_deferral_exempt(candidate))
                    && crate::srv6::unicast_eligible(candidate)
                    && !should_suppress_ibgp_inner(
                        candidate,
                        group.is_ebgp,
                        group.is_rr_client,
                        self.cluster_id,
                        &self.peer_is_rr_client,
                    )
                    && !multipath_candidate_suppressed(
                        candidate,
                        group.is_ebgp,
                        group.interpret_rfc1997,
                        None,
                        family,
                        Some(&group.llgr),
                    )
                {
                    pcb.ranked.push_ranked(
                        (source.expect("candidate has source"), candidate.path_id),
                        |a, b| precedes(a, b, budget),
                    );
                }
            }
        }
        pcb.gathered
    }
}
