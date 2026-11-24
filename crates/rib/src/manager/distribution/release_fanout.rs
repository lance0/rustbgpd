//! One unicast release batch. The actor owns this transaction until every member
//! has received the staged delta or transferred it to corrective resync.

use super::super::outbound_owing::CursorFloors;
use super::super::source_departure::RECEIVER_ROWS_PER_POLL;
use super::super::update_groups::{GroupRibOut, GroupStageOutput, ReleaseFallback};
use super::release_denials::{DENIALS_PER_POLL, MemberVerdicts, ReleaseDenials};
use super::release_pcb::{CANDIDATES_PER_POLL, PreparedPcb, PreparedPcbs, ReleasePcb};
use super::{
    DistributionPass, ExactExportKey, ExportMemo, HashMap, HashSet, OutboundCommitBatch, PeerId,
    Prefix, RibManager, UnicastDistributionResult, rs_control,
};
use rustbgpd_wire::Afi;
use std::collections::BTreeMap;

const RELEASE_MEMBERS_PER_POLL: usize = 16;
/// Prefixes plus denial and fallback rows one per-client-best group stage may
/// carry. A clean batch of 1,024 prefixes fits; a member page stays within
/// about twice an ordinary group's.
const PCB_STAGE_WORK: usize = 2_048;

pub(super) struct ReleaseMembers<'a> {
    pub(super) afi: Afi,
    /// A source departure, whose stage carries only ordinary group deltas.
    pub(super) departure: bool,
    pub(super) peers: &'a [PeerId],
    pub(super) stage: &'a HashMap<usize, GroupStageOutput>,
    pub(super) rs_verdicts: Option<&'a mut HashMap<(usize, u32), bool>>,
    pub(super) denial_receipt: Option<&'a mut MemberVerdicts>,
}

enum Phase {
    Publish,
    Classify(Option<PeerId>),
    MemberlessGroups(usize),
    Stage,
    RankPcb(usize),
    GroupDenials(usize),
    PrepareFallback(usize, Prefix),
    RetireFallback(usize, Prefix),
    MemberDenials(PeerId, MemberVerdicts),
    RetireVerdicts(usize, Prefix),
    AdjustRejections {
        gid: usize,
        restore: bool,
    },
    RemoveRsCounts(usize),
    StageGroup(usize),
    Deliver,
    /// The RS counts of members `next_member..end` are restored; their
    /// emission must cover exactly that page whatever the FIFO does meanwhile.
    DeliverAfterRsRestore {
        end: usize,
    },
    Cap(Option<PeerId>, [Option<u64>; 2]),
    Finish,
}

struct DepartureKeys {
    // Per-ASN verdicts for the current immutable group stage, across member pages.
    rs_verdicts: HashMap<(usize, u32), bool>,
    shared: bool,
    // Neither per-client-best nor multipath exporters: a quiet delivery unit
    // can visit more members of this page.
    wide: bool,
    best: HashSet<Prefix>,
    held: HashSet<Prefix>,
}

pub(in crate::manager) struct ReleaseDistribution {
    afi: Afi,
    pub(in crate::manager) prefixes: HashSet<Prefix>,
    phase: Phase,
    // None names private receivers. At most one group owns staged route bodies.
    groups: BTreeMap<Option<usize>, Vec<PeerId>>,
    current: Vec<PeerId>,
    next_member: usize,
    pcb_keys: Vec<Prefix>,
    pcb: Option<(Prefix, Box<ReleasePcb>)>,
    // Ranked prefixes with at most one page of denial and fallback history.
    // They share one group stage and ordinary member pages.
    batch: HashMap<Prefix, PreparedPcb>,
    batch_work: usize,
    // A prefix with more history, staged alone under the paged owners below.
    prepared: Option<Box<PreparedPcb>>,
    denials: Option<Box<ReleaseDenials>>,
    fallback: Option<Box<ReleaseFallback>>,
    pcb_scope: HashSet<Prefix>,
    staged: HashMap<usize, GroupStageOutput>,
    lane_entries: usize,
    floors: CursorFloors,
    // A source departure distinguishes global-best changes from candidate changes.
    // Selection release revisits every prefix in both roles.
    departure: Option<Box<DepartureKeys>>,
    plain_group: bool,
}

impl ReleaseDistribution {
    pub(in crate::manager) fn for_departure(
        afi: Afi,
        affected: HashSet<Prefix>,
        best: HashSet<Prefix>,
        held: HashSet<Prefix>,
        shared: bool,
        wide: bool,
    ) -> Self {
        Self {
            departure: Some(Box::new(DepartureKeys {
                rs_verdicts: HashMap::new(),
                best,
                held,
                shared,
                wide,
            })),
            ..Self::new(afi, affected)
        }
    }

    #[cfg(test)]
    pub(in crate::manager) fn rs_restore_pinned(&self) -> bool {
        matches!(self.phase, Phase::DeliverAfterRsRestore { .. })
    }

    fn member_limit(&self, maximum: usize) -> usize {
        let Some(keys) = &self.departure else {
            return maximum;
        };
        let key_count = (self.prefixes.len() + keys.held.len()).max(1);
        maximum.min(super::super::source_departure::RECEIVER_ROWS_PER_POLL / key_count)
    }

    fn peer_batch(&self, manager: &RibManager, after: Option<PeerId>) -> Vec<PeerId> {
        if self.departure.is_some() {
            manager
                .source_departure
                .as_ref()
                .expect("departure owns the roster")
                .peer_batch(after, RELEASE_MEMBERS_PER_POLL)
        } else {
            manager.release_peer_batch(after, RELEASE_MEMBERS_PER_POLL)
        }
    }

    fn scope(&self) -> &HashSet<Prefix> {
        if self.plain_group
            && let Some(departure) = &self.departure
        {
            &departure.best
        } else if self.pcb_scope.is_empty() {
            &self.prefixes
        } else {
            &self.pcb_scope
        }
    }

    pub(in crate::manager) fn new(afi: Afi, prefixes: HashSet<Prefix>) -> Self {
        Self {
            afi,
            prefixes,
            phase: Phase::Publish,
            groups: BTreeMap::new(),
            current: Vec::new(),
            next_member: 0,
            pcb_keys: Vec::new(),
            pcb: None,
            batch: HashMap::new(),
            batch_work: 0,
            prepared: None,
            denials: None,
            fallback: None,
            pcb_scope: HashSet::new(),
            staged: HashMap::new(),
            lane_entries: 0,
            floors: CursorFloors::default(),
            departure: None,
            plain_group: false,
        }
    }
}

impl RibManager {
    /// Complete one member page or stage one group over the bounded prefix
    /// batch. No other mutation may run between the first and last poll.
    #[expect(
        clippy::too_many_lines,
        reason = "one match keeps the release phase, next owner and yield boundary together for each state"
    )]
    pub(in crate::manager) fn poll_unicast_release_distribution(
        &mut self,
        pass: &mut ReleaseDistribution,
        quiet_departure: bool,
    ) -> bool {
        match pass.phase {
            Phase::Publish => {
                debug_assert!(pass.departure.is_some() || self.unicast_release_partial());
                debug_assert!(
                    !pass.prefixes.is_empty()
                        || pass
                            .departure
                            .as_ref()
                            .is_some_and(|keys| !keys.held.is_empty())
                );
                if pass.departure.is_none() {
                    self.invalidate_flowspec_dependencies(&pass.prefixes);
                    self.fib_candidate_changes_tx
                        .send_modify(|generation| *generation = generation.wrapping_add(1));
                }
                self.advance_advertised_pages();
                pass.phase = Phase::Classify(None);
            }
            Phase::Classify(after) => {
                let peers = pass.peer_batch(self, after);
                let mut remaining = RECEIVER_ROWS_PER_POLL;
                let mut last = after;
                for &peer in &peers {
                    let gid = self.grouped_member_of(peer);
                    let missing_proof = !pass.prefixes.is_empty()
                        && gid.is_some()
                        && self.retain_initial_group_admitted(peer)
                        && !self.pending_group_admitted.contains_key(&peer)
                        && !self.dirty_peers.contains(&peer);
                    if let Some(departure) = &pass.departure {
                        // A settled carry probes the smaller side of each intersection.
                        // Isolate a missing-proof recovery from other row walks.
                        let cost = if missing_proof {
                            RECEIVER_ROWS_PER_POLL
                        } else {
                            self.helper_stale_exempt
                                .get(&peer)
                                .filter(|c| c.settled)
                                .map_or(0, |c| {
                                    c.keys.len().min(pass.prefixes.len())
                                        + c.keys.len().min(departure.held.len())
                                })
                        };
                        // The first peer of a poll always proceeds, so an
                        // expensive peer cannot stall the walk.
                        let left = match remaining.checked_sub(cost) {
                            Some(left) => left,
                            None if last == after => 0,
                            None => {
                                pass.phase = Phase::Classify(last);
                                return false;
                            }
                        };
                        remaining = left;
                        last = Some(peer);
                        self.flush_departure_helper_stale(peer, &pass.prefixes);
                        if !departure.held.is_empty() {
                            self.flush_departure_helper_stale(peer, &departure.held);
                        }
                        if pass.prefixes.is_empty() {
                            continue;
                        }
                    } else {
                        self.note_release_helper_stale_change(peer, &pass.prefixes);
                    }
                    if missing_proof {
                        // The held initial dump omitted rows and its proof was
                        // refused. Only corrective replay can certify this member.
                        self.set_group_recovery_fallback(
                            peer,
                            super::super::update_groups::RecoveryFallbackCause::MissingProof,
                        );
                        self.mark_outbound_dirty_inner(peer, false);
                    }
                    self.collect_owed_floors(peer, &mut pass.floors);
                    pass.groups.entry(gid).or_default().push(peer);
                }
                pass.phase = if peers.len() == RELEASE_MEMBERS_PER_POLL {
                    Phase::Classify(peers.last().copied())
                } else if pass.prefixes.is_empty() {
                    Phase::Finish
                } else {
                    self.log_release_owed_rows(&pass.prefixes, pass.floors);
                    if pass.groups.len() - usize::from(pass.groups.contains_key(&None))
                        == self.group_ribs.len()
                    {
                        Phase::Stage
                    } else {
                        Phase::MemberlessGroups(0)
                    }
                };
            }
            Phase::MemberlessGroups(mut gid) => {
                // Unowned prestaged policy destinations also track live deltas.
                // Historical registry slots count against the same work limit.
                for _ in 0..RELEASE_MEMBERS_PER_POLL {
                    if self.update_groups.group_key(gid).is_none() {
                        pass.phase = Phase::Stage;
                        return false;
                    }
                    if self.group_ribs.contains_key(&gid) {
                        pass.groups.entry(Some(gid)).or_default();
                    }
                    gid += 1;
                }
                pass.phase = Phase::MemberlessGroups(gid);
            }
            Phase::Stage => {
                let Some((gid, peers)) = pass.groups.pop_first() else {
                    self.metrics.set_update_group_runner_up_entries(
                        i64::try_from(pass.lane_entries).unwrap_or(i64::MAX),
                    );
                    let over = self.release_owed_over_cap();
                    pass.floors = Default::default();
                    pass.phase = if over.iter().any(Option::is_some) {
                        Phase::Cap(None, over)
                    } else {
                        Phase::Finish
                    };
                    return false;
                };
                pass.plain_group = gid.is_some_and(|gid| {
                    self.group_ribs
                        .get(&gid)
                        .is_some_and(|group| !group.per_client_best)
                });
                pass.current = peers;
                pass.next_member = 0;
                if let Some(gid) = gid {
                    if self
                        .group_ribs
                        .get(&gid)
                        .is_some_and(|group| group.per_client_best)
                    {
                        pass.pcb_keys.extend(pass.prefixes.iter().copied());
                        pass.phase = Phase::RankPcb(gid);
                        return false;
                    }
                    pass.phase = self.next_release_group_phase(gid);
                } else {
                    pass.phase = Phase::Deliver;
                }
            }
            Phase::Cap(after, over) => {
                let peers = pass.peer_batch(self, after);
                for &peer in &peers {
                    if self.cap_release_owed_peer(peer, over, &mut pass.floors)
                        && pass.departure.is_some()
                    {
                        // Cursor probes are fixed-size. Give an eviction its own
                        // recovery budget before continuing with the remaining peers.
                        self.settle_eor_after_pass();
                        pass.phase = Phase::Cap(Some(peer), over);
                        return false;
                    }
                }
                self.settle_eor_after_pass();
                if peers.len() == RELEASE_MEMBERS_PER_POLL {
                    pass.phase = Phase::Cap(peers.last().copied(), over);
                } else {
                    self.finish_release_owed_cap(over, pass.floors);
                    pass.phase = Phase::Finish;
                }
            }
            Phase::Finish => {
                self.settle_eor_after_pass();
                return true;
            }
            Phase::RankPcb(gid) => {
                // Ranking is paged by candidates: one prefix can hold thousands.
                // Delivery is not. Only a prefix with more than a page of denial
                // or fallback history keeps its own stage and member polls.
                let mut budget = CANDIDATES_PER_POLL;
                while budget > 0 {
                    if pass.pcb.is_none() {
                        if pass.pcb_keys.is_empty() || pass.batch_work >= PCB_STAGE_WORK {
                            debug_assert!(!pass.batch.is_empty());
                            pass.pcb_scope.clear();
                            pass.pcb_scope.extend(pass.batch.keys().copied());
                            pass.batch_work = 0;
                            pass.next_member = 0;
                            pass.phase = self.next_release_group_phase(gid);
                            return false;
                        }
                        let prefix = pass.pcb_keys.pop().expect("pending PCB prefix");
                        pass.pcb = Some((prefix, Box::default()));
                    }
                    let (prefix, pcb) = pass.pcb.as_mut().expect("pending PCB selection");
                    let prefix = *prefix;
                    let Some(mut prepared) = self.poll_release_pcb(gid, prefix, pcb, &mut budget)
                    else {
                        break;
                    };
                    pass.pcb = None;
                    let group = self.group_ribs.get_mut(&gid).expect("group being staged");
                    let history = prepared.rows.policy_filtered.len()
                        + group.release_history_len(&prefix)
                        + prepared
                            .stage
                            .rs_fallback
                            .as_ref()
                            .map_or(0, |list| list.len());
                    if history <= DENIALS_PER_POLL {
                        pass.batch_work += 1 + history;
                        pass.batch.insert(prefix, prepared);
                        continue;
                    }
                    pass.pcb_scope.clear();
                    pass.pcb_scope.insert(prefix);
                    pass.next_member = 0;
                    let rows = std::mem::take(&mut prepared.rows.policy_filtered);
                    pass.denials = Some(Box::new(ReleaseDenials::new(group, prefix, rows)));
                    if self.release_fallback_needs_pages(gid, prefix, &prepared.stage) {
                        pass.fallback = Some(Box::default());
                        pass.phase = Phase::PrepareFallback(gid, prefix);
                    } else {
                        pass.phase = Phase::GroupDenials(gid);
                    }
                    pass.denials
                        .as_deref_mut()
                        .expect("PCB denials")
                        .take_evals(&mut prepared.evals);
                    pass.prepared = Some(Box::new(prepared));
                    return false;
                }
            }
            Phase::PrepareFallback(gid, prefix) => {
                if self.prepare_release_fallback(
                    gid,
                    prefix,
                    &pass.current,
                    &mut pass
                        .prepared
                        .as_deref_mut()
                        .expect("pending PCB stage")
                        .stage,
                    pass.fallback.as_deref_mut().expect("large fallback list"),
                ) {
                    pass.phase = Phase::GroupDenials(gid);
                }
            }
            Phase::RetireFallback(gid, prefix) => {
                if self.retire_release_fallback(
                    gid,
                    prefix,
                    pass.fallback.as_deref_mut().expect("large fallback list"),
                ) {
                    pass.fallback = None;
                    self.finish_release_group(pass, Some(gid));
                }
            }
            Phase::GroupDenials(gid) => {
                let denials = pass.denials.as_deref_mut().expect("ranked PCB denials");
                if denials.poll_group(self.group_ribs.get_mut(&gid).expect("group being staged")) {
                    pass.phase = self.next_release_group_phase(gid);
                }
            }
            Phase::RetireVerdicts(gid, prefix) => {
                if pass
                    .denials
                    .as_deref_mut()
                    .expect("PCB verdicts")
                    .retire_eval_page()
                {
                    pass.denials = None;
                    if pass.fallback.is_some() {
                        pass.phase = Phase::RetireFallback(gid, prefix);
                    } else {
                        self.finish_release_group(pass, Some(gid));
                    }
                }
            }
            Phase::MemberDenials(peer, receipt) => {
                let denials = pass
                    .denials
                    .as_deref_mut()
                    .expect("member has ranked PCB denials");
                if denials.poll_verdicts(self, peer, receipt) {
                    pass.phase = Phase::Deliver;
                }
            }
            // Either correction can use a full departure row budget. Keep
            // refusal, RS-control and emission walks in separate polls.
            Phase::AdjustRejections { gid, restore } => {
                let end = (pass.next_member + pass.member_limit(RELEASE_MEMBERS_PER_POLL))
                    .min(pass.current.len());
                self.adjust_staged_unicast_rejections(
                    gid,
                    Some(&pass.current[pass.next_member..end]),
                    pass.scope(),
                    restore,
                );
                pass.next_member = end;
                if end == pass.current.len() {
                    pass.next_member = 0;
                    pass.phase = if restore {
                        Phase::Deliver
                    } else {
                        self.release_rs_count_phase(gid)
                    };
                }
            }
            Phase::RemoveRsCounts(gid) => {
                let end = (pass.next_member + pass.member_limit(RELEASE_MEMBERS_PER_POLL))
                    .min(pass.current.len());
                if let Some(group) = self.group_ribs.get_mut(&gid) {
                    group.adjust_release_rs_members(
                        &pass.current[pass.next_member..end],
                        pass.scope(),
                        -1,
                    );
                }
                pass.next_member = end;
                if end == pass.current.len() {
                    pass.next_member = 0;
                    pass.phase = Phase::StageGroup(gid);
                }
            }
            Phase::StageGroup(gid) => {
                let pcb = if let Some(prepared) = pass.prepared.take() {
                    let prefix = *pass.pcb_scope.iter().next().expect("staged prefix");
                    Some(PreparedPcbs {
                        prefixes: HashMap::from([(prefix, *prepared)]),
                        paged_denials: true,
                    })
                } else if pass.pcb_scope.is_empty() {
                    None
                } else {
                    Some(PreparedPcbs {
                        prefixes: std::mem::take(&mut pass.batch),
                        paged_denials: false,
                    })
                };
                let stage = self.stage_group_delivery(
                    gid,
                    pass.scope(),
                    &mut ExportMemo::default(),
                    true,
                    pcb,
                );
                pass.staged.insert(gid, stage);
                pass.phase = if self
                    .group_ribs
                    .get(&gid)
                    .is_some_and(GroupRibOut::has_member_rejections)
                {
                    Phase::AdjustRejections { gid, restore: true }
                } else {
                    Phase::Deliver
                };
            }
            Phase::Deliver | Phase::DeliverAfterRsRestore { .. } => {
                let pinned = match pass.phase {
                    Phase::DeliverAfterRsRestore { end } => Some(end),
                    _ => None,
                };
                let restored = pinned.is_some();
                let maximum = if pass.departure.as_ref().is_some_and(|keys| !keys.shared) {
                    super::super::source_departure::MEMBERS_PER_PAGE
                } else {
                    RELEASE_MEMBERS_PER_POLL
                };
                let group = pass.staged.keys().next().copied();
                // RS count restoration and the following emission cover the
                // page pinned in the phase, even if pressure changes between polls.
                // An UPDATE can arrive between them, so the restore takes the
                // pressured page size even while quiet.
                let rs_group = group
                    .and_then(|gid| self.group_ribs.get(&gid))
                    .is_some_and(GroupRibOut::has_rs_members);
                let members = if pass.denials.is_some() {
                    1
                } else if rs_group {
                    pass.member_limit(maximum)
                } else if quiet_departure
                    && let Some(keys) = pass.departure.as_ref().filter(|keys| keys.wide)
                {
                    super::super::source_departure::quiet_delivery_members(
                        pass.prefixes.len() + keys.held.len(),
                    )
                    .max(maximum)
                } else if quiet_departure {
                    maximum
                } else {
                    pass.member_limit(maximum)
                };
                let end =
                    pinned.unwrap_or_else(|| (pass.next_member + members).min(pass.current.len()));
                let peers = &pass.current[pass.next_member..end];
                if !peers.is_empty() {
                    if !restored
                        && let Some(group) = group.and_then(|gid| self.group_ribs.get_mut(&gid))
                        && group.has_rs_members()
                        && group.adjust_release_rs_members(peers, pass.scope(), 1)
                        && pass.departure.is_some()
                    {
                        // Count correction and divergent emission each visit the
                        // member's keys. Keep the same stage and member page
                        // pinned across the yield between those two visits.
                        pass.phase = Phase::DeliverAfterRsRestore { end };
                        return false;
                    }
                    let mut rs_verdicts = pass
                        .departure
                        .as_mut()
                        .map(|keys| std::mem::take(&mut keys.rs_verdicts));
                    let scope = pass.scope();
                    let mut receipt = MemberVerdicts::default();
                    let best = pass.departure.as_ref().map_or(scope, |keys| &keys.best);
                    let narrowed = (pass.departure.is_some() && !pass.pcb_scope.is_empty())
                        .then(|| scope.intersection(best).copied().collect::<HashSet<_>>());
                    self.distribute_changes_with_readiness::<false, true>(
                        narrowed.as_ref().unwrap_or(best),
                        scope,
                        DistributionPass::Change,
                        true,
                        HashMap::new(),
                        None,
                        true,
                        None,
                        Some(ReleaseMembers {
                            afi: pass.afi,
                            departure: pass.departure.is_some(),
                            peers,
                            stage: &pass.staged,
                            rs_verdicts: rs_verdicts.as_mut(),
                            denial_receipt: pass.denials.is_some().then_some(&mut receipt),
                        }),
                    );
                    if pass.departure.is_none() {
                        for &peer in peers {
                            self.admit_missing_release_rows(peer, scope);
                        }
                    }
                    if let (Some(keys), Some(verdicts)) = (&mut pass.departure, rs_verdicts) {
                        keys.rs_verdicts = verdicts;
                    }
                    self.settle_eor_after_pass();
                    let target = peers[0];
                    pass.next_member = end;
                    pass.phase = Phase::Deliver;
                    if receipt.counters || receipt.denials {
                        pass.phase = Phase::MemberDenials(target, receipt);
                        return false;
                    }
                }
                if end == pass.current.len() {
                    let staged_gid = pass.staged.keys().next().copied();
                    pass.staged.clear();
                    if let Some(keys) = &mut pass.departure {
                        keys.rs_verdicts.clear();
                    }
                    if pass.denials.is_some() {
                        pass.phase = Phase::RetireVerdicts(
                            staged_gid.expect("staged PCB group"),
                            *pass.pcb_scope.iter().next().expect("staged prefix"),
                        );
                    } else {
                        self.finish_release_group(pass, staged_gid);
                    }
                }
            }
        }
        false
    }

    fn finish_release_group(&self, pass: &mut ReleaseDistribution, staged_gid: Option<usize>) {
        if pass.pcb_keys.is_empty() && pass.batch.is_empty() {
            if let Some(group) = staged_gid.and_then(|gid| self.group_ribs.get(&gid)) {
                pass.lane_entries += group.runner_up_count();
            }
            pass.pcb_scope.clear();
            pass.phase = Phase::Stage;
        } else {
            pass.phase = Phase::RankPcb(staged_gid.expect("staged PCB group"));
        }
    }

    fn next_release_group_phase(&self, gid: usize) -> Phase {
        if self
            .group_ribs
            .get(&gid)
            .is_some_and(GroupRibOut::has_member_rejections)
        {
            Phase::AdjustRejections {
                gid,
                restore: false,
            }
        } else {
            self.release_rs_count_phase(gid)
        }
    }

    fn release_rs_count_phase(&self, gid: usize) -> Phase {
        if self
            .group_ribs
            .get(&gid)
            .is_some_and(GroupRibOut::has_rs_members)
        {
            Phase::RemoveRsCounts(gid)
        } else {
            Phase::StageGroup(gid)
        }
    }

    /// A frozen winner can produce no group delta while a session that
    /// joined during the hold still lacks it. Its admitted proof, updated
    /// by the ordinary delta above, identifies only the missing rows.
    fn admit_missing_release_rows(&mut self, peer: PeerId, prefixes: &HashSet<Prefix>) {
        if self.dirty_peers.contains(&peer) || self.force_outbound_peers.contains(&peer) {
            return;
        }
        let Some(gid) = self.grouped_member_of(peer) else {
            return;
        };
        let Some(proof) = self.initial_group_admitted(peer) else {
            return;
        };
        let Some(group) = self.group_ribs.get(&gid) else {
            return;
        };
        let rs = self
            .peer_rs_control
            .get(&peer)
            .copied()
            .zip(self.peer_asn.get(&peer).copied());
        let mut rows: UnicastDistributionResult = UnicastDistributionResult::default();
        for prefix in prefixes {
            for staged in group.table.iter_prefix(prefix) {
                if proof.contains(&ExactExportKey::Unicast(*prefix, staged.path_id)) {
                    continue;
                }
                let Some(entry) = group.adv_entry_for(peer, prefix, staged.path_id, rs) else {
                    continue;
                };
                let (_, large) = group.source_control_for_route(entry.route, entry.source_attrs);
                let mut route = entry.route.clone();
                rs_control::rs_control_route_rewrite(&mut route, large, rs);
                if let Some(source) = entry.local_source {
                    rows.local_sources
                        .insert((route.prefix, route.path_id), source);
                }
                rows.announce.push(route);
                rows.next_hop_override.push(entry.nh.cloned());
            }
        }
        if let Some(route) = rows.announce.first() {
            let v6 = usize::from(matches!(route.prefix, Prefix::V6(_)));
            let previous = self
                .initial_group_admitted_counts(peer)
                .map(|counts| counts[v6]);
            let batch = OutboundCommitBatch {
                local_sources: rows.local_sources,
                unicast_otc_prechecked: !group.per_client_best,
                ..OutboundCommitBatch::with_unicast(
                    rows.announce.into(),
                    rows.next_hop_override.into(),
                )
            };
            if self
                .try_send_and_commit_outbound_update(peer, batch)
                .is_err()
            {
                self.mark_outbound_dirty(peer);
            } else if self
                .initial_group_admitted_counts(peer)
                .map(|counts| counts[v6])
                > previous
                && let Some(session) = self.outbound_session_ids.get(&peer).copied()
                && let Some(record) = self.newest_live_session_mut(peer, session)
            {
                record.release_missing_admitted[v6] = true;
            }
        }
    }

    pub(in crate::manager) fn take_release_missing_admitted(
        &mut self,
        peer: PeerId,
        family: (rustbgpd_wire::Afi, rustbgpd_wire::Safi),
    ) -> bool {
        use rustbgpd_wire::{Afi, Safi};
        let index = match family {
            (Afi::Ipv4, Safi::Unicast) => 0,
            (Afi::Ipv6, Safi::Unicast) => 1,
            _ => return false,
        };
        let Some(session) = self.outbound_session_ids.get(&peer).copied() else {
            return false;
        };
        self.newest_live_session_mut(peer, session)
            .is_some_and(|record| std::mem::take(&mut record.release_missing_admitted[index]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manager::HelperStaleExempt;
    use crate::manager::outbound_owing::OwedFamily;
    use crate::manager::tests::register_test_peer;
    use crate::test_support::peer_v4;
    use rustbgpd_telemetry::BgpMetrics;
    use rustbgpd_wire::Ipv4Prefix;
    use std::net::Ipv4Addr;
    use tokio::sync::mpsc;

    #[test]
    fn departure_classifies_and_caps_cheap_peers_together_and_charges_row_walks() {
        let mut manager = RibManager::new(
            mpsc::channel(1).1,
            mpsc::channel(1).1,
            None,
            None,
            BgpMetrics::new(),
        );
        let peers: Vec<_> = (1..=32)
            .map(|n| peer_v4(Ipv4Addr::new(192, 0, 2, n)))
            .collect();
        for &peer in &peers {
            register_test_peer(&mut manager, peer, 1);
        }
        let prefix = |i| Prefix::V4(Ipv4Prefix::new(Ipv4Addr::from(i), 32));
        let changed: HashSet<_> = (0..256u32).map(prefix).collect();
        manager.start_source_departure(
            peer_v4(Ipv4Addr::LOCALHOST),
            changed.clone(),
            changed.clone(),
            &HashSet::new(),
        );
        let (ended, _) = mpsc::channel(1);
        // These disjoint intersections must inspect all 256 keys apiece.
        for &peer in &peers[16..18] {
            manager.helper_stale_exempt.insert(
                peer,
                HelperStaleExempt {
                    ended: ended.downgrade(),
                    keys: (256..512).map(|i| (prefix(i), 0)).collect(),
                    settled: true,
                    release_changed: [false; 2],
                    orf_blocked: vec![],
                    gate_blocked: vec![],
                },
            );
        }
        let mut pass = ReleaseDistribution::for_departure(
            Afi::Ipv4,
            changed.clone(),
            changed,
            HashSet::new(),
            true,
            true,
        );
        let visit = |manager: &mut RibManager, pass: &mut ReleaseDistribution| {
            let before = manager.adj_rib_out_commit_stats.owed_peer_scans;
            assert!(!manager.poll_unicast_release_distribution(pass, false));
            manager.adj_rib_out_commit_stats.owed_peer_scans - before
        };
        pass.phase = Phase::Classify(None);
        assert_eq!(visit(&mut manager, &mut pass), 16);
        assert_eq!(visit(&mut manager, &mut pass), 1);
        assert_eq!(visit(&mut manager, &mut pass), 15);
        assert_eq!(
            pass.groups.values().map(Vec::len).sum::<usize>(),
            peers.len()
        );

        for &peer in &peers[16..18] {
            manager.owe_whole_family(peer, OwedFamily::IPV4_UNICAST);
        }
        pass.phase = Phase::Cap(None, [Some(1), None]);
        assert_eq!(visit(&mut manager, &mut pass), 16);
        assert_eq!(visit(&mut manager, &mut pass), 1);
        assert_eq!(visit(&mut manager, &mut pass), 1);
        assert_eq!(visit(&mut manager, &mut pass), 14);
        assert!(matches!(pass.phase, Phase::Finish));
    }
}
