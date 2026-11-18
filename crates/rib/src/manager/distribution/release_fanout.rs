//! One unicast release batch. The actor owns this transaction until every member
//! has received the staged delta or transferred it to corrective resync.

use super::super::outbound_owing::CursorFloors;
use super::super::update_groups::{GroupRibOut, GroupStageOutput, ReleaseFallback};
use super::release_denials::{MemberVerdicts, ReleaseDenials};
use super::release_pcb::{PreparedPcb, ReleasePcb};
use super::{
    DistributionPass, ExactExportKey, ExportMemo, HashMap, HashSet, OutboundCommitBatch, PeerId,
    Prefix, RibManager, UnicastDistributionResult, rs_control,
};
use rustbgpd_wire::Afi;
use std::collections::BTreeMap;

const RELEASE_MEMBERS_PER_POLL: usize = 16;

pub(super) struct ReleaseMembers<'a> {
    pub(super) afi: Afi,
    pub(super) peers: &'a [PeerId],
    pub(super) stage: &'a HashMap<usize, GroupStageOutput>,
    pub(super) denial_receipt: Option<&'a mut MemberVerdicts>,
}

enum Phase {
    Publish,
    Classify(Option<PeerId>),
    MemberlessGroups(usize),
    Stage,
    StagePcb(usize),
    RankPcb(usize, Prefix),
    GroupDenials(usize),
    PrepareFallback(usize, Prefix),
    RetireFallback(usize, Prefix),
    MemberDenials(PeerId, MemberVerdicts),
    RetireVerdicts(usize, Prefix),
    RemoveRsCounts(usize),
    StageGroup(usize),
    Deliver,
    Cap(Option<PeerId>, [Option<u64>; 2]),
    Finish,
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
    pcb: Option<Box<ReleasePcb>>,
    prepared: Option<Box<PreparedPcb>>,
    denials: Option<Box<ReleaseDenials>>,
    fallback: Option<Box<ReleaseFallback>>,
    pcb_scope: HashSet<Prefix>,
    staged: HashMap<usize, GroupStageOutput>,
    lane_entries: usize,
    floors: CursorFloors,
}

impl ReleaseDistribution {
    fn scope(&self) -> &HashSet<Prefix> {
        if self.pcb_scope.is_empty() {
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
            prepared: None,
            denials: None,
            fallback: None,
            pcb_scope: HashSet::new(),
            staged: HashMap::new(),
            lane_entries: 0,
            floors: CursorFloors::default(),
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
    ) -> bool {
        match pass.phase {
            Phase::Publish => {
                debug_assert!(self.unicast_release_partial());
                debug_assert!(!pass.prefixes.is_empty());
                self.invalidate_flowspec_dependencies(&pass.prefixes);
                self.fib_candidate_changes_tx
                    .send_modify(|generation| *generation = generation.wrapping_add(1));
                self.advance_advertised_pages();
                pass.phase = Phase::Classify(None);
            }
            Phase::Classify(after) => {
                let peers = self.release_peer_batch(after, RELEASE_MEMBERS_PER_POLL);
                for &peer in &peers {
                    let gid = self.grouped_member_of(peer);
                    // A missed admission transfers exactly this stage's withdrawal
                    // residue to resync. Capturing the whole group speculatively
                    // here would reintroduce a table-sized release poll.
                    if gid.is_some()
                        && self.retain_initial_group_admitted(peer)
                        && !self.pending_group_admitted.contains_key(&peer)
                        && !self.dirty_peers.contains(&peer)
                    {
                        // The held initial dump omitted rows and its proof was
                        // refused. Only corrective replay can certify this member.
                        self.set_group_recovery_fallback(
                            peer,
                            super::super::update_groups::RecoveryFallbackCause::MissingProof,
                        );
                        self.mark_outbound_dirty_inner(peer, false);
                    }
                    self.note_release_helper_stale_change(peer, &pass.prefixes);
                    self.collect_owed_floors(peer, &mut pass.floors);
                    pass.groups.entry(gid).or_default().push(peer);
                }
                pass.phase = if peers.len() == RELEASE_MEMBERS_PER_POLL {
                    Phase::Classify(peers.last().copied())
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
                    pass.floors = [None; 3];
                    pass.phase = if over.iter().any(Option::is_some) {
                        Phase::Cap(None, over)
                    } else {
                        Phase::Finish
                    };
                    return false;
                };
                pass.current = peers;
                pass.next_member = 0;
                if let Some(gid) = gid {
                    if self
                        .group_ribs
                        .get(&gid)
                        .is_some_and(|group| group.per_client_best)
                    {
                        pass.pcb_keys.extend(pass.prefixes.iter().copied());
                        pass.phase = Phase::StagePcb(gid);
                        return false;
                    }
                    pass.phase = self.next_release_group_phase(gid);
                } else {
                    pass.phase = Phase::Deliver;
                }
            }
            Phase::Cap(after, over) => {
                let peers = self.release_peer_batch(after, RELEASE_MEMBERS_PER_POLL);
                for &peer in &peers {
                    self.cap_release_owed_peer(peer, over, &mut pass.floors);
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
            Phase::StagePcb(gid) => {
                // PCB ranks every eligible path, accounts for its denied
                // candidates, and can keep a runner-up list for this prefix.
                // Keep that work out of every other prefix's staging unit.
                let prefix = pass.pcb_keys.pop().expect("pending PCB prefix");
                pass.pcb_scope.clear();
                pass.pcb_scope.insert(prefix);
                pass.next_member = 0;
                pass.pcb = Some(Box::default());
                pass.phase = Phase::RankPcb(gid, prefix);
            }
            Phase::RankPcb(gid, prefix) => {
                if let Some(mut prepared) = self.poll_release_pcb(
                    gid,
                    prefix,
                    pass.pcb.as_deref_mut().expect("pending PCB selection"),
                ) {
                    let rows = std::mem::take(&mut prepared.rows.policy_filtered);
                    pass.denials = Some(Box::new(ReleaseDenials::new(
                        self.group_ribs.get_mut(&gid).expect("group being staged"),
                        prefix,
                        rows,
                    )));
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
                    pass.pcb = None;
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
            Phase::RemoveRsCounts(gid) => {
                let end = (pass.next_member + RELEASE_MEMBERS_PER_POLL).min(pass.current.len());
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
                let pcb = pass.prepared.take().map(|prepared| *prepared);
                let stage = self.stage_group_delivery(
                    gid,
                    pass.scope(),
                    &mut ExportMemo::default(),
                    true,
                    pcb,
                );
                pass.staged.insert(gid, stage);
                pass.phase = Phase::Deliver;
            }
            Phase::Deliver => {
                let members = if pass.denials.is_some() {
                    1
                } else {
                    RELEASE_MEMBERS_PER_POLL
                };
                let end = (pass.next_member + members).min(pass.current.len());
                let peers = &pass.current[pass.next_member..end];
                let scope = pass.scope();
                if !peers.is_empty() {
                    if let Some(group) = pass
                        .staged
                        .keys()
                        .next()
                        .and_then(|gid| self.group_ribs.get_mut(gid))
                        && group.has_rs_members()
                    {
                        group.adjust_release_rs_members(peers, scope, 1);
                    }
                    let mut receipt = MemberVerdicts::default();
                    self.distribute_changes_with_readiness::<false, true>(
                        scope,
                        scope,
                        DistributionPass::Ordinary,
                        true,
                        HashMap::new(),
                        None,
                        true,
                        None,
                        Some(ReleaseMembers {
                            afi: pass.afi,
                            peers,
                            stage: &pass.staged,
                            denial_receipt: pass.denials.is_some().then_some(&mut receipt),
                        }),
                    );
                    for &peer in peers {
                        self.admit_missing_release_rows(peer, scope);
                    }
                    self.settle_eor_after_pass();
                    let target = peers[0];
                    pass.next_member = end;
                    if receipt.counters || receipt.denials {
                        pass.phase = Phase::MemberDenials(target, receipt);
                        return false;
                    }
                }
                if end == pass.current.len() {
                    let staged_gid = pass.staged.keys().next().copied();
                    pass.staged.clear();
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
        if pass.pcb_keys.is_empty() {
            if let Some(group) = staged_gid.and_then(|gid| self.group_ribs.get(&gid)) {
                pass.lane_entries += group.runner_up_count();
            }
            pass.pcb_scope.clear();
            pass.phase = Phase::Stage;
        } else {
            pass.phase = Phase::StagePcb(staged_gid.expect("staged PCB group"));
        }
    }

    fn next_release_group_phase(&self, gid: usize) -> Phase {
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
