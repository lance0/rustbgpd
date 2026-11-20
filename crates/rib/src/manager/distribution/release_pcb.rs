//! Rank and evaluate one per-client-best prefix over bounded candidate pages.
//! The containing group's release transaction fences candidate mutations.

use super::super::update_groups::{GroupEvalAccumulator, PerClientBestPrefixStage, PolicyLabel};
use super::unicast::{PcbWalk, multipath_candidate_suppressed};
use super::{
    ExportMemo, HashMap, PeerId, PolicyChain, PolicyFilteredRouteKey, Prefix, RibManager,
    UnicastDistributionResult, prefix_family, should_suppress_ibgp_inner,
};
use crate::route::Route;

use std::collections::VecDeque;

pub(super) const CANDIDATES_PER_POLL: usize = 128;
type Path = (PeerId, u32);

/// A heap of identities, compared against the live Adj-RIB-In. The ordinary
/// comparator ends in the peer endpoint and path ID so distinct paths never tie.
#[derive(Default)]
struct RankedPaths(Vec<Path>);

impl RankedPaths {
    fn push(&mut self, path: Path, precedes: impl Fn(Path, Path) -> bool) {
        let mut index = self.0.len();
        self.0.push(path);
        while index > 0 {
            let parent = (index - 1) / 2;
            if !precedes(path, self.0[parent]) {
                break;
            }
            self.0[index] = self.0[parent];
            index = parent;
        }
        self.0[index] = path;
    }

    fn pop(&mut self, precedes: impl Fn(Path, Path) -> bool) -> Option<Path> {
        let first = *self.0.first()?;
        let last = self.0.pop().expect("nonempty ranked paths");
        if !self.0.is_empty() {
            let mut index = 0;
            while 2 * index + 1 < self.0.len() {
                let mut child = 2 * index + 1;
                if child + 1 < self.0.len() && precedes(self.0[child + 1], self.0[child]) {
                    child += 1;
                }
                if !precedes(self.0[child], last) {
                    break;
                }
                self.0[index] = self.0[child];
                index = child;
            }
            self.0[index] = last;
        }
        Some(first)
    }
}

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
pub(in crate::manager) struct ReleasePcb {
    source: usize,
    after: Option<u32>,
    ranked: RankedPaths,
    gathered: bool,
    walk: PcbWalk,
    rows: UnicastDistributionResult<(PolicyFilteredRouteKey, Option<PolicyLabel>)>,
    evals: VecDeque<GroupEvalAccumulator>,
    otc_blocked: Vec<Route>,
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
        let group = self.group_ribs.get(&gid)?;
        let family = prefix_family(&prefix);
        debug_assert!(!self.selection_deferred(family));
        let route = |(source, path): Path| {
            self.ribs[&source]
                .get(&prefix, path)
                .expect("candidate source is fenced during group staging")
        };
        let precedes = |a, b| crate::best_path::best_path_cmp(route(a), route(b)).is_lt();
        pcb.gathered |= !group.sendable.contains(&family);
        while !pcb.gathered && *budget > 0 {
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
                *budget -= 1;
                let Some(candidate) = paths.next() else {
                    pcb.source += 1;
                    pcb.after = None;
                    break;
                };
                pcb.after = Some(candidate.path_id);
                if crate::srv6::unicast_eligible(candidate)
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
                    pcb.ranked.push(
                        (source.expect("candidate has source"), candidate.path_id),
                        precedes,
                    );
                }
            }
        }
        if !pcb.gathered {
            return None;
        }

        let export_pol = group.export_chain.as_ref();
        let needs_as_path_string = export_pol.is_some_and(PolicyChain::requires_as_path_string);
        let mut memo = ExportMemo::default();
        let mut done = false;
        let mut evals = GroupEvalAccumulator::default();
        while *budget > 0 {
            *budget -= 1;
            let Some(path) = pcb.ranked.pop(precedes) else {
                done = true;
                break;
            };
            if pcb.walk.consume(
                route(path),
                &group.table,
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
                done = true;
                break;
            }
        }
        if !evals.is_empty() {
            pcb.evals.push_back(evals);
        }
        done.then(|| PreparedPcb {
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
}
