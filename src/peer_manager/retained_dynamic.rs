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
use rustbgpd_rib::{PeerRetention, RibUpdate};
use rustbgpd_transport::{RibPeerSlot, SessionEndRetention};
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
    pub(super) accepted: AcceptedDynamicRange,
    pub(super) remote_asn: u32,
    pub(super) retained_at: Instant,
    /// Whether the RIB may still retain the neighbor's routes: from its
    /// session's end, then from each check.
    pub(super) theirs: bool,
    /// The latest the neighbor, as our helper, can still hold our routes:
    /// the window its session reported, plus a hold time. `None` when it
    /// cannot hold them.
    pub(super) ours_until: Option<Instant>,
    /// When it is checked next; `None` while a reconnect's session is live.
    pub(super) check_at: Option<Instant>,
    pub(super) logged: bool,
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
}

impl Default for RetentionChecks {
    fn default() -> Self {
        Self {
            pass: None,
            backoff: RETENTION_RETRY,
            admission_dirty: false,
        }
    }
}

/// The batched retention query in flight, for these neighbors in order.
pub(super) struct RetentionPass {
    pub(super) peers: Vec<PeerKey>,
    pub(super) answer: tokio::task::JoinHandle<Option<Vec<PeerRetention>>>,
}

impl PeerManager {
    /// Keep an idle dynamic neighbor's identity when its session's end left
    /// routes retained on either side (`end`). `false` when there is nothing
    /// to keep: nothing retained, its OPEN never validated, or no current
    /// range admits it.
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
            || !self.dynamic_range_admits(&accepted, managed.remote_asn)
        {
            return false;
        }
        let now = Instant::now();
        let hold = Duration::from_secs(u64::from(managed.transport_config.peer.hold_time));
        let ours_until = end.ours_for.map(|window| now + window + hold);
        let mut retained = RetainedDynamicPeer {
            slot: managed.transport_config.rib_peer.clone(),
            accepted,
            remote_asn: managed.remote_asn,
            retained_at: now,
            theirs: end.theirs,
            ours_until,
            // Its routes need the RIB's answer; its hold of ours ends at a
            // known time.
            check_at: if end.theirs { Some(now) } else { ours_until },
            logged: false,
        };
        if !end.theirs {
            log_retained(peer, &mut retained, None);
        }
        self.retained_dynamic.insert(peer.clone(), retained);
        true
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
    pub(super) async fn retained_dynamic_open_from(&mut self, peer: &PeerKey, peer_asn: u32) {
        let Some(retained) = self
            .retained_dynamic
            .get(peer)
            .filter(|retained| retained.check_at.is_none() && retained.remote_asn != peer_asn)
        else {
            return;
        };
        let previous_asn = retained.remote_asn;
        let handle = retained.slot.get();
        self.retained_dynamic.remove(peer);
        let Some(handle) = handle else {
            return;
        };
        info!(peer = %peer, previous_asn, peer_asn, "a reconnect from another AS is another speaker: releasing the retained identity");
        // The live neighbor keeps the series: they share its label.
        for update in [
            RibUpdate::PeerDeleted {
                peer: handle,
                label: None,
                keep_series: true,
            },
            RibUpdate::ReleasePeer { peer: handle },
        ] {
            let _ = self
                .send_rib_update(
                    update,
                    super::OperatorReadAdmission::Fenced {
                        reason: "a retained identity is being released",
                    },
                )
                .await;
        }
    }

    /// A reconnect from a retained neighbor's address was installed: the
    /// retention waits, unchanged, for its session. `false` when the address
    /// has none.
    pub(super) fn retained_dynamic_reconnected(&mut self, peer: &PeerKey) -> bool {
        self.retained_dynamic
            .get_mut(peer)
            .map(|retained| retained.check_at = None)
            .is_some()
    }

    /// The reconnect reached Established: the live neighbor owns the
    /// identity from here.
    pub(super) fn retained_dynamic_established(&mut self, peer: &PeerKey) {
        self.retained_dynamic.remove(peer);
    }

    /// The reconnect went idle without reaching Established: the retention
    /// it waited on stands unchanged and is checked again. `false` when the
    /// address has none.
    pub(super) fn resume_retained_dynamic(&mut self, peer: &PeerKey) -> bool {
        let Some(retained) = self.retained_dynamic.get_mut(peer) else {
            return false;
        };
        self.rib_peers.insert(peer.clone(), retained.slot.clone());
        retained.check_at = Some(Instant::now());
        true
    }

    /// The live reconnect itself is being deleted: give the retained slot
    /// back so its deletion releases the identity.
    pub(super) fn take_dormant_retained_dynamic(&mut self, peer: &PeerKey) {
        if let Some(retained) = self.retained_dynamic.remove(peer) {
            self.rib_peers.insert(peer.clone(), retained.slot);
        }
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
    pub(super) async fn check_due_retained_dynamic(&mut self) {
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
            self.delete_retained_dynamic(&peer).await;
        }
        if ask.is_empty() {
            return;
        }
        let handles = ask
            .iter()
            .map(|peer| self.retained_dynamic[peer].slot.current(peer.address))
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
    pub(super) async fn finish_retention_pass(&mut self, answer: Option<Vec<PeerRetention>>) {
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
            for peer in pass.peers {
                if self
                    .retained_dynamic
                    .get(&peer)
                    .is_some_and(|retained| retained.check_at.is_some())
                {
                    self.set_retained_check(&peer, Some(now + retry));
                }
            }
            return;
        };
        self.retention.backoff = RETENTION_RETRY;
        let mut delete = Vec::new();
        for (peer, retention) in pass.peers.into_iter().zip(answer) {
            // Gone, or live again while the query was out.
            let Some(retained) = self
                .retained_dynamic
                .get_mut(&peer)
                .filter(|retained| retained.check_at.is_some())
            else {
                continue;
            };
            retained.theirs = retention.stale_routes > 0;
            let theirs_until = retained.theirs.then(|| {
                retention
                    .next_deadline
                    .unwrap_or(now + RETENTION_RECHECK)
                    .max(now + RETENTION_RETRY)
            });
            let next = theirs_until.or(retained.ours_until.filter(|&until| now < until));
            if next.is_some() {
                log_retained(&peer, retained, theirs_until);
            }
            retained.check_at = next;
            if next.is_none() {
                delete.push(peer);
            }
        }
        for peer in delete {
            self.delete_retained_dynamic(&peer).await;
        }
    }

    /// Delete every idle retained neighbor no current range admits.
    /// Returns how many went.
    pub(super) async fn release_unadmitted_retained_dynamic(&mut self) -> usize {
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
            self.delete_retained_dynamic(peer).await;
        }
        unadmitted.len()
    }

    /// At the limit, give a new address the slot of the oldest neighbor kept
    /// only because it may hold our routes. `false` when there is none: a
    /// neighbor whose routes the RIB retains keeps its slot.
    pub(super) async fn evict_retained_dynamic_for_slot(&mut self) -> bool {
        let Some(peer) = self
            .retained_dynamic
            .iter()
            .filter(|(_, retained)| retained.check_at.is_some() && !retained.theirs)
            .min_by_key(|(_, retained)| retained.retained_at)
            .map(|(peer, _)| peer.clone())
        else {
            return false;
        };
        info!(peer = %peer, "dynamic neighbor limit reached: evicting the oldest idle neighbor kept only while it may hold our routes");
        self.delete_retained_dynamic(&peer).await;
        true
    }

    /// Delete an idle retained neighbor now, releasing its RIB identity. A
    /// neighbor whose reconnect is live is left to that session.
    pub(super) async fn delete_retained_dynamic(&mut self, peer: &PeerKey) {
        if self
            .retained_dynamic
            .get(peer)
            .is_none_or(|retained| retained.check_at.is_none())
        {
            return;
        }
        self.retained_dynamic.remove(peer);
        self.dynamic_peer_count = self.dynamic_peer_count.saturating_sub(1);
        self.refresh_dynamic_neighbor_capacity_metrics();
        self.reap_deleted_peer_metric_series_for_key(peer).await;
        info!(peer = %peer, "retained dynamic peer deleted");
    }

    fn set_retained_check(&mut self, peer: &PeerKey, at: Option<Instant>) {
        if let Some(retained) = self.retained_dynamic.get_mut(peer) {
            retained.check_at = at;
        }
    }
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
