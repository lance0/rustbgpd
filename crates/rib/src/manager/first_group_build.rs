//! Build a cold registration's unicast table privately, one actor turn at a time.

use std::collections::{BTreeSet, VecDeque};

use rustbgpd_policy::{PolicyChain, PolicyHitCounters};
use rustbgpd_wire::Prefix;
use tokio::sync::mpsc;

use super::distribution::ExportMemo;
use super::update_groups::{
    GroupRibOut, OptionalGroupRetirement, OptionalInventoryRetirement, RejectedBatchedInventory,
};
use super::{OutboundRouteUpdate, PeerId, RibManager};
use crate::loc_rib::{REGISTRATION_PAGE_SIZE, RegistrationScanStatus};
use crate::update::RibUpdate;

/// Build turns in one attempt on which a build that keeps something waiting
/// may find its repair log more than half full. A claimed build with a
/// session end retained behind it then takes the actor's turns. A founder's
/// build whose slot another policy destination waits for gives the slot up,
/// as it does on overflow, and holds no input. The count is cumulative over
/// the attempt, because a steady feed of messages near two chunks holds the
/// log at half and dips under it every few turns. Separate bursts within one
/// attempt therefore add up. A larger budget lets a longer burst from
/// another peer pass without holding the other peers' input for the rest of
/// the build or discarding the founder's pages (the largest UPDATE, 16
/// chunks, keeps the log past half for 13 turns; four of them back to back
/// fit the budget, five spend it). A smaller one replays the session end or
/// the waiting command sooner under input that does not stop.
pub(super) const BEHIND_TURNS_BEFORE_SEAL: u16 = 64;

#[cfg(any(test, feature = "bench-internals"))]
thread_local! {
    static RELOAD_BUILD_PAGES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Private destination pages that accepted authoritative reloads staged on
/// this thread. A synchronous reload stages none.
#[cfg(feature = "bench-internals")]
#[must_use]
pub fn authoritative_reload_build_pages() -> usize {
    RELOAD_BUILD_PAGES.with(std::cell::Cell::get)
}

struct Waiter {
    session_id: u64,
    sender: mpsc::Sender<OutboundRouteUpdate>,
}

pub(super) struct FirstGroupBuild {
    pub(super) gid: usize,
    pub(super) peer: PeerId,
    phase: FirstGroupPhase,
    writer: Option<Box<RibUpdate>>,
    // An accepted reload retains ownership even if its acknowledgement closes.
    reload: Option<Box<ReloadSource>>,
    // The FIFO head needs a different cold table. The founder retains this
    // one until publication or the last physical retirement page.
    other_destination_waits: bool,
    // Optional prepare belongs to the exact source cohort and session that asked.
    prepare_source: Option<(usize, Waiter)>,
    // Turns this attempt found the repair log more than half full while its
    // writer kept a session end retained or another destination waited.
    behind_turns: u16,
    policy: Option<Box<FirstGroupPolicy>>,
    table: GroupRibOut,
    // Shares modified attributes across pages, as one synchronous build does.
    memo: ExportMemo,
}

/// Lives from acceptance to the terminal reply, even when the build must retire
/// before fallback. The destination leaves the scan slot only on the commit turn.
pub(super) struct AuthoritativeReload {
    pub(super) started: tokio::time::Instant,
    pub(super) summary: Option<super::replacement_summaries::SummaryProjection>,
    destination: Option<Box<FirstGroupBuild>>,
}

struct ReloadSource {
    gid: usize,
    sessions: Vec<(PeerId, Waiter)>,
    vrp: Option<std::sync::Weak<rustbgpd_rpki::VrpTable>>,
    aspa: Option<std::sync::Weak<rustbgpd_rpki::AspaTable>>,
}

pub(super) fn page_memo(memo: &mut ExportMemo) -> &mut ExportMemo {
    // Keep common modified attributes shared across discovery and repair.
    // Each single-best page can add at most one source and one outcome per
    // key. A reload policy yields at most two outcomes per source, but a
    // first-group policy can yield one per prefix-specific term. Resetting
    // above one page of sources or two pages of outcomes bounds retention,
    // the per-route outcome scan and the drop at three pages; it never
    // triggers before the source bound for a reload policy.
    if memo.len() > REGISTRATION_PAGE_SIZE || memo.outcomes() > 2 * REGISTRATION_PAGE_SIZE {
        *memo = ExportMemo::default();
    }
    memo
}

fn same_snapshot<T>(
    start: Option<&std::sync::Weak<T>>,
    current: Option<&std::sync::Arc<T>>,
) -> bool {
    match (start, current) {
        (Some(start), Some(current)) => {
            std::ptr::eq(start.as_ptr(), std::sync::Arc::as_ptr(current))
        }
        (None, None) => true,
        _ => false,
    }
}

fn authoritative_replacements(
    command: &RibUpdate,
) -> &[crate::update::PeerExportPolicyReplacement] {
    match command {
        RibUpdate::ReplacePeerExportPoliciesAuthoritatively { replacements, .. }
        | RibUpdate::RestorePeerExportPoliciesAuthoritatively { replacements, .. } => replacements,
        _ => unreachable!("accepted authoritative replacement"),
    }
}

/// Per-policy state is proportional to chain size and the existing repair
/// limit. The table and denied-prefix sidecar already identify evaluated rows.
struct FirstGroupPolicy {
    datasets: Vec<u64>,
    superseded: Option<PolicyHitCounters>,
    retiring: VecDeque<Option<crate::route::Route>>,
}

impl FirstGroupPolicy {
    fn start(chain: &PolicyChain, loc_rib: &mut crate::loc_rib::LocRib) -> Box<Self> {
        loc_rib.track_displaced_registration_winners();
        Box::new(Self {
            datasets: chain
                .compiled()
                .referenced_datasets()
                .map(|slot| slot.handle.pin().generation)
                .collect(),
            superseded: None,
            retiring: VecDeque::new(),
        })
    }

    fn prepare_page(
        &mut self,
        table: &GroupRibOut,
        page: &mut crate::loc_rib::RegistrationPage,
    ) -> bool {
        let chain = table.export_chain.as_ref().expect("private policy build");
        if page.repairs == 0 {
            // A bucket rewind or an earlier repair can rediscover an
            // already-staged prefix without a corresponding displaced input.
            page.keys
                .retain(|prefix| !table.first_group_policy_evaluated(prefix));
        } else {
            let mut memo = super::distribution::ExportMemo::default();
            for old in &page.displaced {
                if table.first_group_policy_evaluated(&old.prefix) {
                    let hits = self
                        .superseded
                        .get_or_insert_with(|| PolicyHitCounters::for_chain(chain.compiled()));
                    if !RibManager::count_displaced_first_group_winner(old, chain, hits, &mut memo)
                    {
                        return false;
                    }
                }
            }
        }
        true
    }

    fn finish(&self, chain: &mut PolicyChain) -> bool {
        // Generation numbers are monotonic, so this also detects a swap
        // during a page or between an original and its inverse evaluation.
        // Two surviving errors can have different diagnoses. Only the
        // authoritative traversal determines which becomes last_error.
        chain.hit_counters().eval_errors() <= 1
            && chain
                .compiled()
                .referenced_datasets()
                .map(|slot| slot.handle.pin().generation)
                .eq(self.datasets.iter().copied())
            && self
                .superseded
                .as_ref()
                .is_none_or(|hits| chain.exclude_staged_evaluations(hits))
    }
}

impl FirstGroupBuild {
    pub(super) fn founded_by(&self, peer: PeerId, record: &super::LiveSessionRecord) -> bool {
        self.peer == peer
            && matches!(&self.phase, FirstGroupPhase::Scanning(Some(waiter))
            if waiter.session_id == record.session_id && waiter.sender.same_channel(&record.outbound_tx))
    }

    fn stop_scan(&mut self, loc_rib: &mut crate::loc_rib::LocRib) {
        self.memo = ExportMemo::default();
        let displaced = loc_rib.stop_registration_scan();
        if let Some(policy) = &mut self.policy {
            policy.retiring = displaced;
        }
    }
}

/// Owns the build slot until every detached preparation allocation is released.
pub(super) struct OptionalDestinationRetirement {
    inventory: OptionalInventoryRetirement,
    /// Absent when the first member adopted the live table and only the
    /// preparation's inventory, encoder probe and change logs are retiring.
    pub(super) detached: Option<DetachedDestination>,
}

pub(super) struct DetachedDestination {
    pub(super) gid: usize,
    group: OptionalGroupRetirement,
    pub(super) interned_policy: Option<rustbgpd_policy::PolicyChain>,
    withdrawn: BTreeSet<(Prefix, u32)>,
}

enum FirstGroupPhase {
    // A policy claim can share a healthy scan. Keep the founding session
    // available if the claimant loses its authority before publication.
    Scanning(Option<Waiter>),
    Retiring,
}

impl RibManager {
    pub(super) fn start_first_group(
        &mut self,
        peer: PeerId,
        gid: usize,
        session_id: u64,
        sender: mpsc::Sender<OutboundRouteUpdate>,
    ) {
        let table = self.first_group_table(peer, gid);
        let job = self.open_first_group_scan(peer, gid, table);
        job.phase = FirstGroupPhase::Scanning(Some(Waiter { session_id, sender }));
    }

    fn open_first_group_scan(
        &mut self,
        peer: PeerId,
        gid: usize,
        table: GroupRibOut,
    ) -> &mut FirstGroupBuild {
        debug_assert!(self.first_group_slot_available());
        self.loc_rib.start_registration_scan();
        let policy = table
            .export_chain
            .as_ref()
            .map(|chain| FirstGroupPolicy::start(chain, &mut self.loc_rib));
        self.first_group_build.insert(Box::new(FirstGroupBuild {
            gid,
            peer,
            phase: FirstGroupPhase::Scanning(None),
            writer: None,
            reload: None,
            other_destination_waits: false,
            prepare_source: None,
            behind_turns: 0,
            table,
            policy,
            memo: ExportMemo::default(),
        }))
    }

    pub(super) fn accept_authoritative_replacement(&mut self, command: RibUpdate) {
        let accepted = tokio::time::Instant::now();
        let replacements = authoritative_replacements(&command);
        #[cfg(test)]
        let threshold = self.first_group_build_min_routes;
        #[cfg(not(test))]
        let threshold = super::INITIAL_DUMP_DEFER_MIN_ROUTES;
        if self.loc_rib.len() >= threshold
            && self.pending_clean_policy_transition.is_none()
            && !self.unicast_release_partial()
            && self.first_group_slot_available()
            && let Some((source, gid)) = self.reload_build_pair(replacements)
            && let Some(sessions) = replacements
                .iter()
                .map(|r| {
                    let sender = self.outbound_peers.get(&r.peer)?;
                    let &session_id = self.outbound_session_ids.get(&r.peer)?;
                    (!sender.is_closed()).then(|| {
                        (
                            r.peer,
                            Waiter {
                                session_id,
                                sender: sender.clone(),
                            },
                        )
                    })
                })
                .collect()
        {
            self.authoritative_reload = Some(Box::new(AuthoritativeReload {
                started: accepted,
                summary: None,
                destination: None,
            }));
            self.capture_reload_summaries(replacements.iter().map(|r| r.peer), gid);
            let first = &replacements[0];
            let table = self.reload_group_table(source, first.export_policy.as_ref());
            let source = Box::new(ReloadSource {
                gid: source,
                sessions,
                vrp: self.vrp_table.as_ref().map(std::sync::Arc::downgrade),
                aspa: self.aspa_table.as_ref().map(std::sync::Arc::downgrade),
            });
            let job = self.open_first_group_scan(first.peer, gid, table);
            job.writer = Some(Box::new(command));
            job.reload = Some(source);
        } else {
            self.finish_authoritative_replacement(command);
        }
    }

    pub(super) fn accepted_reload_build(&self) -> bool {
        self.authoritative_reload.is_some()
    }

    fn reload_source_is_current(&mut self, job: &FirstGroupBuild, source: &ReloadSource) -> bool {
        same_snapshot(source.vrp.as_ref(), self.vrp_table.as_ref())
            && same_snapshot(source.aspa.as_ref(), self.aspa_table.as_ref())
            && source.sessions.iter().all(|(peer, waiter)| {
                self.outbound_session_ids.get(peer) == Some(&waiter.session_id)
                    && self.outbound_peers.get(peer).is_some_and(|sender| {
                        !sender.is_closed() && waiter.sender.same_channel(sender)
                    })
            })
            && self.reload_build_pair(authoritative_replacements(
                job.writer.as_deref().expect("accepted reload"),
            )) == Some((source.gid, job.gid))
    }

    pub(super) fn take_authoritative_destination(&mut self, gid: usize) -> Option<GroupRibOut> {
        self.authoritative_reload
            .as_mut()?
            .destination
            .take_if(|job| job.gid == gid)
            .map(|job| job.table)
    }

    pub(super) fn registration_waits_for_first_group(&self, peer: PeerId) -> bool {
        self.first_group_build.as_ref().is_some_and(|job| {
            job.peer == peer
                || (!self.outbound_peers.contains_key(&peer)
                    && self.pending_registration_matches_group(
                        peer,
                        job.gid,
                        job.table.export_chain.as_ref(),
                    ))
        })
    }

    #[cfg(test)]
    pub(super) fn first_group_targets(&self, gid: usize) -> bool {
        self.first_group_build
            .as_ref()
            .is_some_and(|job| job.gid == gid)
    }

    pub(super) fn policy_build_slot_occupied(&self, destination: usize) -> bool {
        self.first_group_build.is_some()
            || self.optional_destination_retirement_active()
            || self
                .paced_policy_destination
                .is_some_and(|gid| gid != destination)
    }

    pub(super) fn first_group_pending_writer(&self) -> Option<&RibUpdate> {
        let job = self.first_group_build.as_ref()?;
        if job.other_destination_waits {
            self.first_group_deferred_intents.front()
        } else {
            job.writer.as_deref()
        }
    }

    fn writer_needs_group(&mut self, update: &RibUpdate, gid: usize) -> bool {
        if let RibUpdate::PrepareExportPolicyDestination {
            peer,
            export_policy,
            reply,
        } = update
        {
            return !reply.is_closed()
                && export_policy.is_none()
                && self
                    .clean_policy_transition_destination(*peer, None)
                    .is_some_and(|(_, destination)| destination == gid);
        }
        self.mutation_targets_first_group(update, gid)
    }

    /// Reserve the original command, including its reply, before changing an
    /// installed policy, membership, session projection or route-page version.
    pub(super) fn first_group_writer_claim(&mut self, update: &RibUpdate) -> bool {
        self.first_group_build
            .as_ref()
            .map(|job| job.gid)
            .is_some_and(|gid| self.writer_needs_group(update, gid))
    }

    pub(super) fn reserve_other_policy_destination(&mut self, update: &RibUpdate) -> bool {
        let Some(held) = self
            .first_group_build
            .as_ref()
            .map(|job| job.gid)
            .or(self.paced_policy_destination)
        else {
            return false;
        };
        if !self.policy_needs_other_build_slot(update, held) {
            return false;
        }
        if let Some(job) = self.first_group_build.as_mut() {
            debug_assert!(job.writer.is_none() && !job.other_destination_waits);
            job.other_destination_waits = true;
        } else if !self.retire_prepared_first_group(held) {
            return false;
        }
        true
    }

    pub(super) fn reserve_first_group_writer(&mut self, update: RibUpdate) {
        let prepare_source = match &update {
            RibUpdate::PrepareExportPolicyDestination { peer, .. } => self
                .grouped_member_of(*peer)
                .zip(self.outbound_session_ids.get(peer))
                .zip(self.outbound_peers.get(peer))
                .map(|((gid, &session_id), sender)| {
                    (
                        gid,
                        Waiter {
                            session_id,
                            sender: sender.clone(),
                        },
                    )
                }),
            _ => None,
        };
        let job = self
            .first_group_build
            .as_mut()
            .expect("checked private owner");
        assert!(
            job.writer.is_none(),
            "overlapping writer passed primary admission"
        );
        job.writer = Some(Box::new(update));
        job.prepare_source = prepare_source;
    }

    pub(super) fn first_group_slot_available(&self) -> bool {
        self.first_group_build.is_none()
            && self.paced_policy_destination.is_none()
            && self.pending_destination_prestage.is_none()
            && !self.optional_destination_retirement_active()
            && self.completed_memberless_optional().is_none()
    }

    fn completed_memberless_optional(&self) -> Option<usize> {
        self.prepared_destination.filter(|gid| {
            self.group_ribs
                .get(gid)
                .is_some_and(|group| group.members.is_empty())
        })
    }

    /// An acknowledged Prepare is an optimization with no caller lifetime
    /// attached. A concrete cold waiter can reclaim its slot. A later policy
    /// transaction will use its ordinary authoritative preparation.
    pub(super) fn claim_registration_slot(&mut self, gid: Option<usize>) -> bool {
        if self.first_group_slot_available() {
            return true;
        }
        if let Some(prepared) = self.completed_memberless_optional()
            && Some(prepared) != gid
            && self.pending_destination_prestage.is_none()
            && self.first_group_build.is_none()
            && !self.optional_destination_retirement_active()
        {
            self.retire_memberless_destination(prepared, None);
        }
        false
    }

    pub(super) fn optional_destination_retirement_active(&self) -> bool {
        self.optional_destination_retirement.is_some()
    }

    /// Charge all retained structures to the same physical page. Completing
    /// this page only releases the slot; another turn starts the next build.
    pub(super) fn advance_optional_destination_retirement(&mut self) -> usize {
        let retirement = self
            .optional_destination_retirement
            .as_mut()
            .expect("optional retirement");
        let mut budget = REGISTRATION_PAGE_SIZE;
        if let Some(table) = &mut retirement.detached {
            while budget > 0 && table.withdrawn.pop_last().is_some() {
                budget -= 1;
            }
            if !table.withdrawn.is_empty() {
                return REGISTRATION_PAGE_SIZE;
            }
        }
        if !retirement.inventory.retire_page(&mut budget) {
            return REGISTRATION_PAGE_SIZE - budget;
        }
        if let Some(table) = &mut retirement.detached {
            if !table.group.retire_page(&mut budget) {
                return REGISTRATION_PAGE_SIZE - budget;
            }
            if table.interned_policy.is_some() {
                if budget == 0 {
                    return REGISTRATION_PAGE_SIZE;
                }
                budget -= 1;
                drop(table.interned_policy.take());
            }
        }
        if budget > 0 {
            // Release the owner, including any remaining group policy handle.
            budget -= 1;
            self.optional_destination_retirement = None;
            self.clear_first_group_commit_frontier();
        }
        REGISTRATION_PAGE_SIZE - budget
    }

    pub(super) fn registration_waits_for_optional_destination(&self, peer: PeerId) -> bool {
        self.optional_destination_retirement
            .as_ref()
            .and_then(|retiring| retiring.detached.as_ref())
            .is_some_and(|retiring| {
                self.pending_registration_matches_group(
                    peer,
                    retiring.gid,
                    retiring.group.export_policy(),
                )
            })
    }

    pub(super) fn retire_prepared_first_group(&mut self, gid: usize) -> bool {
        if self.paced_policy_destination != Some(gid)
            || !self
                .group_ribs
                .get(&gid)
                .is_some_and(|group| group.members.is_empty())
        {
            return false;
        }
        self.retire_memberless_destination(gid, None);
        true
    }

    #[cfg(test)]
    pub(super) fn refused_inventory_rows_remaining(&self) -> Option<usize> {
        self.optional_destination_retirement
            .as_ref()?
            .detached
            .as_ref()?
            .group
            .refused_inventory_rows_remaining()
    }

    /// A joining member takes the completed table. Its optional cohort proof
    /// has no consumer now. Unlink both logs before the next group write.
    pub(super) fn adopt_prepared_destination(&mut self, gid: usize) {
        self.prepared_destination = None;
        let Some(inventory) = self.take_destination_inventory_retirement(gid) else {
            return;
        };
        debug_assert!(
            self.optional_destination_retirement.is_none() && self.first_group_build.is_none()
        );
        self.optional_destination_retirement = Some(Box::new(OptionalDestinationRetirement {
            inventory,
            detached: None,
        }));
    }

    pub(super) fn retire_cancelled_optional_destination(
        &mut self,
        gid: usize,
        staging: Option<Box<super::distribution::CancelledPrestage>>,
    ) {
        self.retire_memberless_destination(gid, None);
        self.optional_destination_retirement
            .as_mut()
            .expect("detached destination")
            .inventory
            .staging = staging;
    }

    pub(super) fn retire_refused_authoritative_destination(
        &mut self,
        gid: usize,
        rejected: Option<Box<RejectedBatchedInventory>>,
    ) {
        debug_assert_eq!(self.paced_policy_destination, Some(gid));
        self.retire_memberless_destination(gid, rejected);
    }

    fn retire_memberless_destination(
        &mut self,
        gid: usize,
        rejected: Option<Box<RejectedBatchedInventory>>,
    ) {
        debug_assert!(
            self.first_group_build.is_none() && !self.optional_destination_retirement_active()
        );
        let inventory = self
            .take_destination_inventory_retirement(gid)
            .unwrap_or_default();
        let table = self
            .group_ribs
            .remove(&gid)
            .expect("checked memberless destination");
        let withdrawn = self
            .hold_exempt_withdrawn
            .remove(&super::HoldWithdrawOwner::Group(gid))
            .unwrap_or_default();
        self.prepared_destination
            .take_if(|prepared| *prepared == gid);
        self.paced_policy_destination.take_if(|paced| *paced == gid);
        self.optional_destination_retirement = Some(Box::new(OptionalDestinationRetirement {
            inventory,
            detached: Some(DetachedDestination {
                gid,
                group: OptionalGroupRetirement::with_refusal(table, rejected),
                // A batch can create another live owner of this chain before
                // returning. Its final registry reconciliation decides exclusivity.
                interned_policy: if self.update_groups.reclamation_deferred {
                    None
                } else {
                    self.take_optional_registry_chain(gid)
                },
                withdrawn,
            }),
        }));
    }

    fn prepare_source_is_current(&self, job: &FirstGroupBuild) -> bool {
        let Some(RibUpdate::PrepareExportPolicyDestination { peer, .. }) = job.writer.as_deref()
        else {
            return true;
        };
        job.prepare_source.as_ref().is_some_and(|(source, waiter)| {
            self.grouped_member_of(*peer) == Some(*source)
                && self.outbound_session_ids.get(peer) == Some(&waiter.session_id)
                && self.outbound_peers.get(peer).is_some_and(|sender| {
                    !sender.is_closed() && sender.same_channel(&waiter.sender)
                })
        })
    }

    fn settle_obsolete_first_group_writer(&mut self, writer: RibUpdate) {
        // Optional preparation names a particular cohort. Authoritative
        // writes and mandatory restores resolve against current registration.
        if let RibUpdate::PrepareExportPolicyDestination { reply, .. } = writer {
            let _ = reply.send(Err(
                "source registration changed during destination preparation".into(),
            ));
        } else {
            self.handle_update(writer);
        }
    }

    /// Look at one waiter per busy turn. A second cold group, or a retry after
    /// overflow, can start under steady ingress without reordering warm joins.
    pub(super) fn advance_busy_first_group(&mut self, search: &mut usize) {
        if self.first_group_build.is_none() {
            // No cold build starts on a busy turn while any replay is due: a
            // retained intent or a held general head, with no writer and no
            // optional retirement pending. That covers a command the last
            // build made way for, which replays once the message in flight
            // has run. The founder's retry must not take the slot back
            // first: the command would wait for the retry again.
            if self.first_group_replay_due() {
                return;
            }
            let queue = &self.pending_initial_registrations;
            if *search >= queue.len() {
                *search = 0;
            }
            let Some(&peer) = queue.get(*search) else {
                return;
            };
            *search += 1;
            self.defer_first_group_registration(peer);
            if self.first_group_build.is_none() {
                return;
            }
        }
        self.advance_first_group_build();
    }

    // Keep the existing queue as the authority on pending registrations, even
    // while this job is building. GR and collision handling consult that queue.
    pub(super) fn advance_first_group_build(&mut self) {
        let mut job = self.first_group_build.take().expect("active first group");
        if job.reload.is_none()
            && job.writer.as_deref().is_some_and(|writer| match writer {
                RibUpdate::ReplacePeerExportPoliciesAuthoritatively { reply, .. } => {
                    reply.is_closed()
                }
                RibUpdate::ApplyPacedExportPolicies { reply, .. } => reply.is_closed(),
                RibUpdate::PrepareExportPolicyDestination { reply, .. } => {
                    reply.is_closed() || !self.prepare_source_is_current(&job)
                }
                _ => false,
            })
        {
            self.release_first_group_writer(job);
            return;
        }
        let FirstGroupPhase::Scanning(founder) = &job.phase else {
            self.retire_first_group_page(job);
            return;
        };
        let current = job.writer.is_some()
            || founder.as_ref().is_some_and(|waiter| {
                self.current_first_group_waiter(job.peer, job.gid, job.table.export_chain.as_ref())
                    .is_some_and(|(session, sender)| {
                        session == waiter.session_id && waiter.sender.same_channel(&sender)
                    })
            });
        self.release_abandoned_reservation(&mut job);
        // Input can keep discovery waiting behind repairs for as long as it
        // lasts. Count the turns on which it does so while a retained
        // session end or another destination's command waits for this build.
        let keeps_waiting = job.reload.is_some()
            || job.other_destination_waits
            || (job.writer.is_some() && self.session_end_retained());
        if keeps_waiting && self.loc_rib.registration_scan_behind() {
            job.behind_turns = job.behind_turns.saturating_add(1);
        }
        let outrun = job.behind_turns >= BEHIND_TURNS_BEFORE_SEAL;
        // Before repairs took every turn past half, such input overflowed
        // the log and the founder's build made way for the waiting command.
        // It still does once the attempt's budget is spent. Up to four
        // back-to-back UPDATEs of the largest size are over before that,
        // and no other peer's input is held.
        if !current
            || self.group_ribs.contains_key(&job.gid)
            || self.loc_rib.registration_scan_status() == RegistrationScanStatus::Overflow
            || (job.reload.is_some()
                && (outrun || self.loc_rib.registration_scan_rewinds() >= BEHIND_TURNS_BEFORE_SEAL))
            || (outrun && job.other_destination_waits)
        {
            if job.reload.is_some() {
                self.retire_reload_build(job);
                return;
            }
            self.clear_first_group_commit_frontier();
            // Input that passed a retained session end can overflow the
            // repair log on every attempt. Give the retry every turn so the
            // writer commits and the session end is not postponed again.
            if job.writer.is_some() && self.session_end_retained() {
                self.seal_first_group_commit_frontier();
            }
            job.stop_scan(&mut self.loc_rib);
            job.phase = FirstGroupPhase::Retiring;
            self.retire_first_group_page(job);
            return;
        }
        // A writer that input has outrun for the budget gets every turn, so
        // that it commits and the session end replays.
        if outrun {
            self.seal_first_group_commit_frontier();
        }
        self.advance_first_group_page(job);
    }

    /// Stage one bounded page. A completed scan can publish only after all
    /// admitted routes and their distribution have reached the commit frontier.
    fn advance_first_group_page(&mut self, mut job: Box<FirstGroupBuild>) {
        let mut page = self.loc_rib.take_registration_page();
        #[cfg(test)]
        {
            super::slice_timing::record_work("first_group_discovery", page.bucket_visits);
            super::slice_timing::record_work("first_group_repairs", page.repairs);
        }
        debug_assert!(page.bucket_visits + page.repairs <= REGISTRATION_PAGE_SIZE);
        if let Some(policy) = &mut job.policy
            && !policy.prepare_page(&job.table, &mut page)
        {
            self.fallback_policy_first_group(job);
            return;
        }
        if !page.keys.is_empty() {
            let prefixes = page.keys.into_iter().collect();
            let memo = page_memo(&mut job.memo);
            job.table = if job.reload.is_some() {
                #[cfg(any(test, feature = "bench-internals"))]
                RELOAD_BUILD_PAGES.with(|pages| pages.set(pages.get() + 1));
                self.stage_private_group_page(job.gid, job.table, &prefixes, true, memo)
            } else {
                self.stage_first_group_page(job.gid, job.table, &prefixes, memo)
            };
        }
        // Errors are never subtracted, so a second one already decides the
        // fallback at publication. Stop before staging the rest of the table.
        if job.policy.is_some()
            && job
                .table
                .export_chain
                .as_ref()
                .is_some_and(|chain| chain.hit_counters().eval_errors() > 1)
        {
            self.fallback_policy_first_group(job);
            return;
        }
        // Once discovery ends, drain a finite ingress frontier. A steady
        // stream can otherwise leave a small repair backlog on *every* page.
        if job.reload.is_some() && self.loc_rib.registration_discovery_finished() {
            self.capture_first_group_commit_frontier();
        }
        if self.loc_rib.registration_scan_status() != RegistrationScanStatus::Ready
            || !self.pending_route_batches.is_empty()
        {
            self.first_group_build = Some(job);
            return;
        }
        if let Some(writer) = job.writer.as_deref() {
            self.capture_first_group_commit_frontier();
            if !self.first_group_commit_frontier_reached() {
                self.first_group_build = Some(job);
                return;
            }
            self.clear_first_group_commit_frontier();
            // The command is still an intent. Classify against the *current*
            // registrations and effective inputs at this commit boundary.
            if let Some(source) = &job.reload {
                if !self.reload_source_is_current(&job, source) {
                    self.retire_reload_build(job);
                    return;
                }
            } else if !self.prepare_source_is_current(&job)
                || !self.writer_needs_group(writer, job.gid)
            {
                self.release_first_group_writer(job);
                return;
            }
        }
        self.finish_first_group_build(job);
    }

    fn commit_authoritative_reload(
        &mut self,
        command: RibUpdate,
        destination: Option<Box<FirstGroupBuild>>,
    ) {
        self.authoritative_reload
            .as_mut()
            .expect("accepted reload")
            .destination = destination;
        self.advance_advertised_pages();
        self.finish_authoritative_replacement(command);
        if let Some(unused) = self
            .authoritative_reload
            .take()
            .expect("accepted reload")
            .destination
        {
            // The terminal planner declined the ensure. The command is
            // finished; only physical retirement can own this table now.
            self.retire_declined_reload_destination(unused);
        }
    }

    /// Never drop a declined table in the commit turn. A retirement that the
    /// terminal command started keeps its owner; the scan slot, which this
    /// command emptied and which nothing refills inside it, retires the
    /// declined table by page instead.
    fn retire_declined_reload_destination(&mut self, mut unused: Box<FirstGroupBuild>) {
        if self.optional_destination_retirement.is_none() {
            self.optional_destination_retirement = Some(Box::new(OptionalDestinationRetirement {
                inventory: OptionalInventoryRetirement::default(),
                detached: Some(DetachedDestination {
                    gid: unused.gid,
                    group: OptionalGroupRetirement::with_refusal(unused.table, None),
                    interned_policy: None,
                    withdrawn: BTreeSet::new(),
                }),
            }));
            return;
        }
        debug_assert!(self.first_group_build.is_none());
        unused.reload = None;
        unused.writer = None;
        unused.phase = FirstGroupPhase::Retiring;
        self.first_group_build = Some(unused);
    }

    fn finish_first_group_build(&mut self, mut job: Box<FirstGroupBuild>) {
        if let Some(policy) = &job.policy
            && !policy.finish(
                job.table
                    .export_chain
                    .as_mut()
                    .expect("private policy build"),
            )
        {
            self.fallback_policy_first_group(job);
            return;
        }
        job.stop_scan(&mut self.loc_rib);
        if job.reload.is_some() {
            // Preserve the cold/uncertain inventory decision. Only the existing
            // cohort ensure may consume this table, in this exclusive turn.
            let writer = job.writer.take().expect("accepted reload");
            self.commit_authoritative_reload(*writer, Some(job));
            return;
        }
        let gid = job.gid;
        let peer = job.peer;
        if let Some(table) = self.publish_first_group(gid, job.table) {
            job.table = table;
            job.phase = FirstGroupPhase::Retiring;
            self.first_group_build = Some(job);
            return;
        }
        if let Some(writer) = job.writer.take() {
            self.paced_policy_destination = Some(gid);
            self.handle_update(*writer);
            if self.pending_clean_policy_transition.is_none()
                && !self.prestaging_destination(gid)
                && self.prepared_destination != Some(gid)
            {
                self.retire_prepared_first_group(gid);
            }
        } else {
            if job.other_destination_waits {
                self.clear_first_group_commit_frontier();
            }
            self.pending_initial_registrations
                .retain(|queued| *queued != peer);
            self.complete_deferred_registration(peer);
        }
    }

    /// An abandoned authoritative batch is skipped whole when it replays.
    /// Do not spend the budget or the partial table on it: release the
    /// reservation, as for a writer whose caller has gone. The replay is
    /// then due at once, in admission order: the batch is skipped, and a
    /// live command behind it reserves the slot again when it replays.
    /// A head held while the reservation stood sealed the frontier, and
    /// the build's exits clear it only for a standing reservation.
    fn release_abandoned_reservation(&mut self, job: &mut FirstGroupBuild) {
        if job.other_destination_waits
            && matches!(
                self.first_group_deferred_intents.front().map(RibUpdate::unmetered),
                Some(RibUpdate::ReplacePeerExportPoliciesAuthoritatively { reply, .. })
                    if reply.is_closed()
            )
        {
            job.other_destination_waits = false;
            job.behind_turns = 0;
            self.clear_first_group_commit_frontier();
        }
    }

    fn release_first_group_writer(&mut self, mut job: Box<FirstGroupBuild>) {
        self.clear_first_group_commit_frontier();
        let writer = job.writer.take().expect("reserved writer");
        job.prepare_source = None;
        job.behind_turns = 0;
        self.first_group_build = Some(job);
        self.settle_obsolete_first_group_writer(*writer);
    }

    /// The current policy inputs cannot reproduce a private evaluation.
    /// Retire its pages, then let the same session use ordinary registration.
    fn fallback_policy_first_group(&mut self, mut job: Box<FirstGroupBuild>) {
        if job.reload.is_some() {
            self.retire_reload_build(job);
            return;
        }
        debug_assert!(job.writer.is_none() && job.table.export_chain.is_some());
        if let FirstGroupPhase::Scanning(Some(founder)) = &job.phase
            && let Some(record) = self
                .live_sessions
                .get_mut(&job.peer)
                .and_then(|sessions| sessions.last_mut())
            && record.session_id == founder.session_id
            && record.outbound_tx.same_channel(&founder.sender)
        {
            record.registration_policy_fallback = true;
        }
        self.clear_first_group_commit_frontier();
        job.stop_scan(&mut self.loc_rib);
        job.phase = FirstGroupPhase::Retiring;
        self.retire_first_group_page(job);
    }

    /// One attempt per accepted command. Finish previously admitted route
    /// chunks, then dispose the uninstalled table before the exact fallback.
    fn retire_reload_build(&mut self, mut job: Box<FirstGroupBuild>) {
        self.seal_first_group_commit_frontier();
        job.stop_scan(&mut self.loc_rib);
        job.phase = FirstGroupPhase::Retiring;
        self.first_group_build = Some(job);
    }

    fn retire_first_group_page(&mut self, mut job: Box<FirstGroupBuild>) {
        let mut budget = REGISTRATION_PAGE_SIZE;
        if let Some(policy) = &mut job.policy {
            let count = budget.min(policy.retiring.len());
            let retired = policy.retiring.drain(..count);
            #[cfg(test)]
            super::slice_timing::record_work("first_group_retired_displaced", retired.len());
            drop(retired);
            budget -= count;
            if !policy.retiring.is_empty() {
                self.first_group_build = Some(job);
                return;
            }
        }
        if !job.table.retire_first_group_page(budget) {
            self.first_group_build = Some(job);
            return;
        }
        let Some(writer) = job.writer.as_deref() else {
            if job.table.export_chain.is_some() {
                self.reclaim_unused_update_group_policies();
            }
            if job.other_destination_waits {
                self.clear_first_group_commit_frontier();
            }
            return;
        };
        if job.reload.is_some() {
            if !self.first_group_commit_frontier_reached() {
                self.first_group_build = Some(job);
                return;
            }
            self.clear_first_group_commit_frontier();
            let writer = job.writer.take().expect("accepted reload");
            drop(job);
            self.commit_authoritative_reload(*writer, None);
            return;
        }
        if !self.prepare_source_is_current(&job)
            || !self.writer_needs_group(writer, job.gid)
            || self.group_ribs.contains_key(&job.gid)
        {
            self.clear_first_group_commit_frontier();
            self.settle_obsolete_first_group_writer(*job.writer.take().expect("reserved writer"));
            return;
        }
        // Retirement can discard slab handles and overflow can omit a
        // withdrawal. Restart with fresh storage even for the same group key.
        job.table = job.table.empty_first_group_table();
        job.behind_turns = 0;
        self.loc_rib.start_registration_scan();
        job.policy = job
            .table
            .export_chain
            .as_ref()
            .map(|chain| FirstGroupPolicy::start(chain, &mut self.loc_rib));
        let founder = self
            .current_first_group_waiter(job.peer, job.gid, job.table.export_chain.as_ref())
            .map(|(session_id, sender)| Waiter { session_id, sender });
        job.phase = FirstGroupPhase::Scanning(founder);
        self.first_group_build = Some(job);
    }

    #[cfg(test)]
    pub(super) fn reload_memo_sources(&self) -> Option<usize> {
        let job = self.first_group_build.as_ref()?;
        job.reload.as_ref()?;
        Some(job.memo.len())
    }

    #[cfg(test)]
    pub(super) fn first_group_behind_turns(&self) -> Option<u16> {
        self.first_group_build.as_ref().map(|job| job.behind_turns)
    }

    #[cfg(test)]
    pub(super) fn first_group_retiring_slots(&self) -> Option<usize> {
        let job = self.first_group_build.as_ref()?;
        matches!(job.phase, FirstGroupPhase::Retiring).then(|| job.table.table.unicast_slot_count())
    }

    #[cfg(test)]
    pub(super) fn first_group_contains(&self, prefix: rustbgpd_wire::Prefix) -> bool {
        self.first_group_build.as_ref().is_some_and(|job| {
            !matches!(job.phase, FirstGroupPhase::Retiring)
                && job.table.table.get(&prefix, 0).is_some()
        })
    }
}
