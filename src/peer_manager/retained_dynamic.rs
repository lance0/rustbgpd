//! An idle `[[dynamic_neighbors]]` member keeps its RIB identity while
//! Graceful Restart may still hold routes on either side: the GR or LLGR
//! routes the RIB retains for it, and, while it may be our helper, ours it
//! retains (RFC 4724 §4.2). A reconnect from the address in that window
//! resumes the same RIB peer once its OPEN validates. The member is deleted
//! once both retentions lapse, or at once when no range admits it.
//!
//! The retained member keeps its slot under `dynamic_neighbor_limit`. One
//! kept only for the window in which it may hold our routes gives way to a
//! new address at the limit; one whose routes the RIB retains never does.
//! Checks never wait in the actor: due members whose routes the RIB may
//! retain share one batched query on the RIB's primary lane, which is
//! ordered behind the ended sessions' teardown, and its answer is handled
//! as its own run-loop event.

use std::time::Duration;

use rustbgpd_api::peer_types::PeerKey;
use rustbgpd_rib::{PeerId, PeerRetention, RibUpdate};
use rustbgpd_transport::{NeighborCounters, RibPeerSlot, SessionEndRetention};
use tokio::time::Instant;
use tracing::{info, warn};

use super::ManagedPeerState;
use super::PeerManager;
use super::dynamic::AcceptedDynamicRange;

/// How long a retention query waits for the RIB before backing off.
const RETENTION_QUERY_TIMEOUT: Duration = Duration::from_secs(5);
/// The first retry after an unanswered retention query; it doubles up to
/// [`RETENTION_RECHECK`].
const RETENTION_RETRY: Duration = Duration::from_secs(1);
/// How soon retained routes with no RIB timer armed are checked again.
const RETENTION_RECHECK: Duration = Duration::from_secs(30);

/// A retained idle dynamic neighbor.
pub(super) struct RetainedDynamicPeer {
    /// The neighbor's resolved slot, handed back when a reconnect that never
    /// reached Established goes idle.
    pub(super) slot: RibPeerSlot,
    /// The neighbor's counter block. A reconnect counts in a fresh block,
    /// which continues this one only once it proves the same neighbor.
    pub(super) counters: NeighborCounters,
    pub(super) accepted: AcceptedDynamicRange,
    pub(super) remote_asn: u32,
    pub(super) retained_at: Instant,
    /// Whether the RIB may still retain the neighbor's routes: from its
    /// session's end, then from each check.
    pub(super) theirs: bool,
    /// The RIB's next GR or LLGR deadline for its routes, from the last
    /// check that found them retained.
    pub(super) theirs_until: Option<Instant>,
    /// The latest the neighbor, as our helper, can still hold our routes:
    /// the window its session reported, plus a hold time. `None` when it
    /// cannot hold them.
    pub(super) ours_until: Option<Instant>,
    /// When it is checked next; `None` while a reconnect's session is live.
    pub(super) check_at: Option<Instant>,
    pub(super) logged: bool,
    /// A collision candidate beside the live reconnect. It has its own
    /// identity slot and counter block, so whichever session wins is judged
    /// by its own OPEN; promotion installs the winner's.
    pub(super) candidate: Option<CandidateIdentity>,
}

/// A collision candidate's own identity, beside a retained reconnect.
pub(super) struct CandidateIdentity {
    pub(super) session_id: u64,
    pub(super) slot: RibPeerSlot,
    pub(super) counters: NeighborCounters,
}

/// The checks that end each retention.
pub(super) struct RetentionChecks {
    /// The one batched RIB retention query in flight.
    pub(super) pass: Option<RetentionPass>,
    /// The retry delay after an unanswered query; doubles to a cap.
    pub(super) backoff: Duration,
    /// The ranges changed: re-check which retained neighbors a range still
    /// admits, once no transaction snapshot is staged.
    pub(super) admission_dirty: bool,
    /// Identity slots of reconnects and collision candidates that no session
    /// owns any more. Read only from the run loop, after the handler that
    /// queued them has joined or aborted those sessions, since a session
    /// still resolves its slot while it stops; then a handle it resolved for
    /// itself is deleted and released.
    pub(super) orphaned: Vec<OrphanSlot>,
}

impl Default for RetentionChecks {
    fn default() -> Self {
        Self {
            pass: None,
            backoff: RETENTION_RETRY,
            admission_dirty: false,
            orphaned: Vec::new(),
        }
    }
}

/// An identity slot no session owns any more, at `peer`. `keep` is the
/// retained handle, which its own deletion releases.
pub(super) struct OrphanSlot {
    pub(super) peer: PeerKey,
    pub(super) slot: RibPeerSlot,
    pub(super) keep: Option<PeerId>,
}

/// The batched retention query in flight, for these neighbors in order,
/// each with the `retained_at` of the retention it asked about.
pub(super) struct RetentionPass {
    pub(super) peers: Vec<(PeerKey, Instant)>,
    pub(super) answer: tokio::task::JoinHandle<Option<Vec<PeerRetention>>>,
}

impl PeerManager {
    /// Keep an idle dynamic neighbor's identity when its session's end left
    /// routes retained on either side (`end`). `false` when there is nothing
    /// to keep: nothing retained, its OPEN never validated, or no current
    /// range admits it. Ranges a staged transaction provides do not reject
    /// it: the commit or rollback decides.
    pub(super) fn retain_dynamic_identity(
        &mut self,
        peer: &PeerKey,
        managed: &ManagedPeerState,
        end: SessionEndRetention,
    ) -> bool {
        let Some(accepted) = managed.accepted_dynamic_range.clone() else {
            return false;
        };
        if !(end.theirs || end.ours_for.is_some())
            || managed.transport_config.rib_peer.get().is_none()
        {
            return false;
        }
        if !self.dynamic_range_admits(&accepted, managed.remote_asn) {
            if !self.config_snapshot_staged {
                return false;
            }
            // The staged transaction's commit or rollback decides.
            self.retention.admission_dirty = true;
        }
        let now = Instant::now();
        let hold = Duration::from_secs(u64::from(managed.transport_config.peer.hold_time));
        let ours_until = end.ours_for.map(|window| now + window + hold);
        let mut retained = RetainedDynamicPeer {
            slot: managed.transport_config.rib_peer.clone(),
            counters: managed.transport_config.neighbor_counters.clone(),
            accepted,
            remote_asn: managed.remote_asn,
            retained_at: now,
            theirs: end.theirs,
            theirs_until: None,
            ours_until,
            // Its routes need the RIB's answer; its hold of ours ends at a
            // known time.
            check_at: if end.theirs { Some(now) } else { ours_until },
            logged: false,
            candidate: None,
        };
        if !end.theirs {
            log_retained(peer, &mut retained, None);
        }
        self.retained_dynamic.insert(peer.clone(), retained);
        self.publish_retained_dynamic(peer);
        true
    }

    /// Publish what an idle retained neighbor holds, and until when, for
    /// `rbgp doctor` and dashboards; nothing while its reconnect is live or
    /// once it is gone. Its routes carry the RIB's deadline from the last
    /// check that found them retained; until a check answers, their next
    /// check time.
    pub(super) fn publish_retained_dynamic(&self, peer: &PeerKey) {
        let Some(retained) = self.retained_dynamic.get(peer) else {
            return;
        };
        let (label, range) = (peer.label(), retained_range(retained));
        if retained.check_at.is_none() {
            self.metrics
                .clear_dynamic_neighbor_retention(&label, &range);
            return;
        }
        let now = Instant::now();
        let wall_now = std::time::SystemTime::now();
        // An overdue deadline stays in the past.
        let unix = |at: Instant| {
            let wall = if at >= now {
                wall_now + (at - now)
            } else {
                wall_now - (now - at)
            };
            wall.duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |since| since.as_secs())
        };
        self.metrics.set_dynamic_neighbor_retention(
            &label,
            &range,
            retained
                .theirs_until
                .or(retained.check_at)
                .filter(|_| retained.theirs)
                .map(unix),
            retained.ours_until.filter(|&until| now < until).map(unix),
        );
    }

    /// The slot for a reconnect from a retained neighbor's address: its
    /// session takes the retained handle once an OPEN from the same AS
    /// validates.
    pub(super) fn retained_dynamic_reconnect_slot(&self, peer: &PeerKey) -> Option<RibPeerSlot> {
        let retained = self.retained_dynamic.get(peer)?;
        retained
            .slot
            .get()
            .map(|handle| RibPeerSlot::resume_after_open(handle, retained.remote_asn))
    }

    /// The reconnect's OPEN came from `peer_asn`. From another AS it is
    /// another speaker, whose session took a new handle: what was retained
    /// for the last one is purged and its identity released, as for a
    /// deleted neighbor. The live neighbor keeps the slot.
    pub(super) fn retained_dynamic_open_from(&mut self, peer: &PeerKey, peer_asn: u32) {
        let Some(retained) = self
            .retained_dynamic
            .get_mut(peer)
            .filter(|retained| retained.check_at.is_none())
        else {
            return;
        };
        if retained.remote_asn == peer_asn {
            // The same neighbor: its fresh counter block continues the old.
            if let Some(live) = self.neighbor_counters.get(peer) {
                live.absorb(&retained.counters);
                retained.counters = live.clone();
            }
            return;
        }
        let previous_asn = retained.remote_asn;
        let handle = retained.slot.get();
        self.remove_retained_dynamic(peer);
        let Some(handle) = handle else {
            return;
        };
        info!(peer = %peer, previous_asn, peer_asn, "a reconnect from another AS is another speaker: releasing the retained identity");
        self.release_side_handle(handle);
    }

    /// Delete and release a handle the live neighbor does not use, keeping
    /// the series it shares their label with. Never waits for mailbox room:
    /// no session uses the handle, and the deletion reaps no label. The live
    /// neighbor may publish under the label before the RIB handles the
    /// deletion, so the handle is superseded at once and its teardown leaves
    /// the label's gauges to that neighbor.
    fn release_side_handle(&mut self, handle: PeerId) {
        handle.supersede();
        for update in [
            RibUpdate::PeerDeleted {
                peer: handle,
                label: None,
                keep_series: true,
            },
            RibUpdate::ReleasePeer { peer: handle },
        ] {
            let _ = self.defer_rib_update(None, update);
        }
    }

    /// The identity a collision candidate beside a retained reconnect starts
    /// with: its own resume slot and a fresh counter block. `None` when the
    /// address has no retention waiting on a reconnect.
    pub(super) fn retained_dynamic_candidate_identity(
        &self,
        peer: &PeerKey,
    ) -> Option<(RibPeerSlot, NeighborCounters)> {
        self.retained_dynamic
            .get(peer)
            .filter(|retained| retained.check_at.is_none())?;
        Some((
            self.retained_dynamic_reconnect_slot(peer)?,
            NeighborCounters::default(),
        ))
    }

    pub(super) fn note_retained_dynamic_candidate(
        &mut self,
        peer: &PeerKey,
        session_id: u64,
        slot: RibPeerSlot,
        counters: NeighborCounters,
    ) {
        if let Some(retained) = self.retained_dynamic.get_mut(peer) {
            retained.candidate = Some(CandidateIdentity {
                session_id,
                slot,
                counters,
            });
        }
    }

    /// The candidate `session_id` was promoted: the live neighbor now runs
    /// on its identity slot and counter block, and a handle the loser
    /// resolves for itself, as late as its own shutdown, is released.
    pub(super) fn promote_retained_dynamic_candidate(&mut self, peer: &PeerKey, session_id: u64) {
        let Some(retained) = self.retained_dynamic.get_mut(peer) else {
            return;
        };
        if retained
            .candidate
            .as_ref()
            .is_none_or(|candidate| candidate.session_id != session_id)
        {
            return;
        }
        let Some(candidate) = retained.candidate.take() else {
            return;
        };
        let keep = retained.slot.get();
        let Some(managed) = self.peers.get_mut(peer) else {
            return;
        };
        let loser = std::mem::replace(
            &mut managed.transport_config.rib_peer,
            candidate.slot.clone(),
        );
        managed.transport_config.neighbor_counters = candidate.counters.clone();
        self.rib_peers.insert(peer.clone(), candidate.slot.clone());
        self.neighbor_counters
            .insert(peer.clone(), candidate.counters);
        self.retention.orphaned.push(OrphanSlot {
            peer: peer.clone(),
            slot: loser,
            keep,
        });
    }

    /// A candidate that is neither pending nor the primary any more lost or
    /// went away: a handle it resolved for itself is released.
    pub(super) fn reconcile_retained_dynamic_candidates(&mut self) {
        let mut orphaned = Vec::new();
        for (peer, retained) in &mut self.retained_dynamic {
            let Some(candidate) = retained.candidate.as_ref() else {
                continue;
            };
            let live = self.peers.get(peer).is_some_and(|managed| {
                managed.session_id() == candidate.session_id
                    || managed
                        .pending_inbound
                        .as_ref()
                        .is_some_and(|pending| pending.session_id == candidate.session_id)
            });
            if live {
                continue;
            }
            orphaned.push(OrphanSlot {
                peer: peer.clone(),
                slot: candidate.slot.clone(),
                keep: retained.slot.get(),
            });
            retained.candidate = None;
        }
        self.retention.orphaned.extend(orphaned);
    }

    /// Release each handle an orphaned slot resolved for itself: not the
    /// retained handle, and not one the live neighbor at its address uses.
    pub(super) fn release_orphaned_retained_handles(&mut self) {
        let mut released = Vec::new();
        for orphan in std::mem::take(&mut self.retention.orphaned) {
            let Some(handle) = orphan.slot.get() else {
                continue;
            };
            if Some(handle) == orphan.keep
                || handle == self.rib_peer_of(&orphan.peer)
                || released.contains(&handle)
            {
                continue;
            }
            released.push(handle);
            self.release_side_handle(handle);
        }
    }

    /// A reconnect from a retained neighbor's address was installed: the
    /// retention waits, unchanged, for its session. `false` when the address
    /// has none.
    pub(super) fn retained_dynamic_reconnected(&mut self, peer: &PeerKey) -> bool {
        let reconnected = self
            .retained_dynamic
            .get_mut(peer)
            .map(|retained| retained.check_at = None)
            .is_some();
        self.publish_retained_dynamic(peer);
        reconnected
    }

    /// A reconnect from a retained neighbor's address went idle. If it never
    /// reached Established, as its session's own end report says, the
    /// retention it waited on stands unchanged and is checked again, and its
    /// counts join the neighbor's. If it did, its own end decides from here
    /// and the old retention is dropped. `false` when nothing was resumed.
    pub(super) fn resume_retained_dynamic(
        &mut self,
        peer: &PeerKey,
        end: SessionEndRetention,
    ) -> bool {
        let Some(retained) = self.retained_dynamic.get_mut(peer) else {
            return false;
        };
        if end.established {
            self.remove_retained_dynamic(peer);
            return false;
        }
        if let Some(live) = self.neighbor_counters.get(peer) {
            retained.counters.absorb(live);
        }
        self.neighbor_counters
            .insert(peer.clone(), retained.counters.clone());
        self.rib_peers.insert(peer.clone(), retained.slot.clone());
        retained.check_at = Some(Instant::now());
        self.publish_retained_dynamic(peer);
        true
    }

    /// The live reconnect itself is being deleted: give the retained slot
    /// back so its deletion releases the identity. The reconnect's slot
    /// (`live`) and a candidate's are queued: either session may still
    /// resolve a handle for itself, from another AS, until it has stopped.
    pub(super) fn take_dormant_retained_dynamic(&mut self, peer: &PeerKey, live: RibPeerSlot) {
        let Some(retained) = self.remove_retained_dynamic(peer) else {
            return;
        };
        self.retention.orphaned.push(OrphanSlot {
            peer: peer.clone(),
            slot: live,
            keep: retained.slot.get(),
        });
        self.rib_peers.insert(peer.clone(), retained.slot);
    }

    /// Remove a retention. Its collision candidate's slot is queued, since
    /// once the retention is gone nothing else would release a handle the
    /// candidate resolved for itself.
    fn remove_retained_dynamic(&mut self, peer: &PeerKey) -> Option<RetainedDynamicPeer> {
        let mut retained = self.retained_dynamic.remove(peer)?;
        self.metrics
            .clear_dynamic_neighbor_retention(&peer.label(), &retained_range(&retained));
        if let Some(candidate) = retained.candidate.take() {
            self.retention.orphaned.push(OrphanSlot {
                peer: peer.clone(),
                slot: candidate.slot,
                keep: retained.slot.get(),
            });
        }
        Some(retained)
    }

    pub(super) fn next_retained_dynamic_check(&self) -> Option<Instant> {
        if self.retention.pass.is_some() {
            return None;
        }
        self.retained_dynamic
            .values()
            .filter_map(|retained| retained.check_at)
            .min()
    }

    /// Run every due check without waiting: delete what no range admits or
    /// whose hold of ours lapsed, and send one RIB query for the rest.
    pub(super) fn check_due_retained_dynamic(&mut self) {
        if self.retention.pass.is_some() {
            return;
        }
        let now = Instant::now();
        let due: Vec<PeerKey> = self
            .retained_dynamic
            .iter()
            .filter(|(_, retained)| retained.check_at.is_some_and(|at| at <= now))
            .map(|(peer, _)| peer.clone())
            .collect();
        let mut delete = Vec::new();
        let mut ask = Vec::new();
        for peer in due {
            let retained = &self.retained_dynamic[&peer];
            let admitted = self.dynamic_range_admits(&retained.accepted, retained.remote_asn);
            let (theirs, ours_until) = (retained.theirs, retained.ours_until);
            if !admitted && self.config_snapshot_staged {
                // The staged transaction's commit or rollback decides.
                self.retention.admission_dirty = true;
                self.set_retained_check(&peer, Some(now + RETENTION_RECHECK));
            } else if !admitted {
                delete.push(peer);
            } else if theirs {
                ask.push(peer);
            } else if let Some(until) = ours_until.filter(|&until| now < until) {
                self.set_retained_check(&peer, Some(until));
            } else {
                delete.push(peer);
            }
        }
        for peer in delete {
            self.delete_retained_dynamic(&peer);
        }
        if ask.is_empty() {
            return;
        }
        let handles = ask
            .iter()
            .map(|peer| self.retained_dynamic[peer].slot.current(peer.address))
            .collect();
        let ask = ask
            .into_iter()
            .map(|peer| {
                let retained_at = self.retained_dynamic[&peer].retained_at;
                (peer, retained_at)
            })
            .collect();
        let rib_tx = self.rib_tx.clone();
        let answer = tokio::spawn(async move {
            let (reply, response) = tokio::sync::oneshot::channel();
            let request = RibUpdate::QueryPeerRetentions {
                peers: handles,
                reply,
            };
            tokio::time::timeout(RETENTION_QUERY_TIMEOUT, async move {
                rib_tx.send(request).await.ok()?;
                response.await.ok()
            })
            .await
            .ok()
            .flatten()
        });
        self.retention.pass = Some(RetentionPass { peers: ask, answer });
    }

    pub(super) async fn receive_retention_pass(
        pass: &mut Option<RetentionPass>,
    ) -> Option<Vec<PeerRetention>> {
        match pass {
            Some(pass) => (&mut pass.answer).await.ok().flatten(),
            None => std::future::pending().await,
        }
    }

    /// Apply a retention query's answer: re-arm at the RIB's next timer
    /// while it retains a neighbor's routes, then at the end of the hold of
    /// ours, and delete the neighbor once neither holds. No answer backs off.
    pub(super) fn finish_retention_pass(&mut self, answer: Option<Vec<PeerRetention>>) {
        let Some(pass) = self.retention.pass.take() else {
            return;
        };
        let now = Instant::now();
        let Some(answer) = answer.filter(|answer| answer.len() == pass.peers.len()) else {
            let retry = self.retention.backoff;
            self.retention.backoff = (retry * 2).min(RETENTION_RECHECK);
            warn!(
                neighbors = pass.peers.len(),
                retry_secs = retry.as_secs(),
                "the RIB did not answer a retained dynamic neighbor check; retrying"
            );
            for (peer, retained_at) in pass.peers {
                if self.retained_dynamic.get(&peer).is_some_and(|retained| {
                    retained.check_at.is_some() && retained.retained_at == retained_at
                }) {
                    self.set_retained_check(&peer, Some(now + retry));
                }
            }
            return;
        };
        self.retention.backoff = RETENTION_RETRY;
        let mut delete = Vec::new();
        let mut publish = Vec::new();
        for ((peer, retained_at), retention) in pass.peers.into_iter().zip(answer) {
            // Gone, live again, or retained anew while the query was out:
            // the answer was about an earlier retention.
            let Some(retained) = self.retained_dynamic.get_mut(&peer).filter(|retained| {
                retained.check_at.is_some() && retained.retained_at == retained_at
            }) else {
                continue;
            };
            retained.theirs = retention.stale_routes > 0;
            let theirs_until = retained.theirs.then(|| {
                retention
                    .next_deadline
                    .unwrap_or(now + RETENTION_RECHECK)
                    .max(now + RETENTION_RETRY)
            });
            retained.theirs_until = theirs_until;
            let next = theirs_until.or(retained.ours_until.filter(|&until| now < until));
            if next.is_some() {
                log_retained(&peer, retained, theirs_until);
            }
            retained.check_at = next;
            if next.is_none() {
                delete.push(peer);
            } else {
                publish.push(peer);
            }
        }
        for peer in delete {
            self.delete_retained_dynamic(&peer);
        }
        for peer in publish {
            self.publish_retained_dynamic(&peer);
        }
    }

    /// Delete every idle retained neighbor no current range admits.
    /// Returns how many went.
    pub(super) fn release_unadmitted_retained_dynamic(&mut self) -> usize {
        self.retention.admission_dirty = false;
        let unadmitted: Vec<PeerKey> = self
            .retained_dynamic
            .iter()
            .filter(|(_, retained)| {
                retained.check_at.is_some()
                    && !self.dynamic_range_admits(&retained.accepted, retained.remote_asn)
            })
            .map(|(peer, _)| peer.clone())
            .collect();
        for peer in &unadmitted {
            self.delete_retained_dynamic(peer);
        }
        unadmitted.len()
    }

    /// At the limit, give a new address the slot of the oldest neighbor kept
    /// only because it may hold our routes. `false` when there is none: a
    /// neighbor whose routes the RIB retains keeps its slot.
    pub(super) fn evict_retained_dynamic_for_slot(&mut self) -> bool {
        let Some(peer) = self.oldest_evictable_retained_dynamic() else {
            return false;
        };
        info!(peer = %peer, "dynamic neighbor limit reached: evicting the oldest idle neighbor kept only while it may hold our routes");
        self.delete_retained_dynamic(&peer);
        true
    }

    pub(super) fn has_evictable_retained_dynamic(&self) -> bool {
        self.oldest_evictable_retained_dynamic().is_some()
    }

    fn oldest_evictable_retained_dynamic(&self) -> Option<PeerKey> {
        self.retained_dynamic
            .iter()
            .filter(|(_, retained)| retained.check_at.is_some() && !retained.theirs)
            .min_by_key(|(_, retained)| retained.retained_at)
            .map(|(peer, _)| peer.clone())
    }

    /// Delete an idle retained neighbor now, releasing its RIB identity. A
    /// neighbor whose reconnect is live is left to that session.
    pub(super) fn delete_retained_dynamic(&mut self, peer: &PeerKey) {
        if self
            .retained_dynamic
            .get(peer)
            .is_none_or(|retained| retained.check_at.is_none())
        {
            return;
        }
        self.remove_retained_dynamic(peer);
        self.dynamic_peer_count = self.dynamic_peer_count.saturating_sub(1);
        self.refresh_dynamic_neighbor_capacity_metrics();
        self.reap_deleted_peer_metric_series_for_key(peer);
        info!(peer = %peer, "retained dynamic peer deleted");
    }

    /// A static neighbor at an idle retained member's address has started
    /// its session: delete the member and release its identity. The member's
    /// series were reaped before that session spawned, and the label's series
    /// are now the static neighbor's, so the member is retired the way a
    /// replaced speaker is (`release_side_handle`): its deletion keeps the
    /// label's series, and its teardown leaves the label's gauges to the new
    /// neighbor.
    pub(super) fn retire_replaced_retained_dynamic(&mut self, peer: &PeerKey) {
        if self
            .retained_dynamic
            .get(peer)
            .is_none_or(|retained| retained.check_at.is_none())
        {
            return;
        }
        let Some(retained) = self.remove_retained_dynamic(peer) else {
            return;
        };
        self.dynamic_peer_count = self.dynamic_peer_count.saturating_sub(1);
        self.refresh_dynamic_neighbor_capacity_metrics();
        self.publish_peer_lifecycle_event(
            peer,
            rustbgpd_api::peer_types::SessionLifecycleEventType::PeerRemoved,
            format!("peer {peer} removed"),
        );
        if let Some(handle) = retained.slot.get() {
            self.release_side_handle(handle);
        }
        info!(peer = %peer, "retained dynamic peer replaced by a static neighbor");
    }

    fn set_retained_check(&mut self, peer: &PeerKey, at: Option<Instant>) {
        if let Some(retained) = self.retained_dynamic.get_mut(peer) {
            retained.check_at = at;
        }
    }
}

/// The accepted range a retained neighbor's series name.
fn retained_range(retained: &RetainedDynamicPeer) -> String {
    format!(
        "{}/{}",
        retained.accepted.addr, retained.accepted.prefix_len
    )
}

/// Log a retention once, with what it holds and until when.
fn log_retained(peer: &PeerKey, retained: &mut RetainedDynamicPeer, theirs_until: Option<Instant>) {
    if retained.logged {
        return;
    }
    retained.logged = true;
    let now = Instant::now();
    let secs = |at: Option<Instant>| at.map(|at| at.saturating_duration_since(now).as_secs());
    info!(
        peer = %peer,
        retains_its_routes = retained.theirs,
        its_routes_next_timer_secs = secs(theirs_until),
        may_hold_ours_for_secs = secs(retained.ours_until),
        "idle dynamic neighbor keeps its identity while graceful restart retention lasts"
    );
}
