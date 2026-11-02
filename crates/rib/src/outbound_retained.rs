//! Each registered session receives decoded [`OutboundRouteUpdate`]s through
//! a channel bounded by update count. A count does not bound memory: an
//! update can hold one route or a whole table, so receivers that stop reading
//! while sources churn could otherwise hold every queued route version until
//! the process runs out of memory.
//!
//! Every update the RIB sends goes through a reserved channel slot and
//! carries an [`OutboundRetainedCharge`] for its estimated retained bytes,
//! counted against its session's account and the daemon-wide total. The charge
//! travels inside the update, so it follows ownership: it is released exactly
//! once, when the update is dropped, whether the session finishes sending it,
//! retires it after a teardown, or the channel is dropped with the update
//! still queued. An update built ahead of its send (a policy transition's
//! prepared member) is charged from construction.
//!
//! Route payload is reserved only while the session has credit
//! (`OutboundRetainedAccount::has_credit`); a refusal is handled exactly
//! like a full channel (the peer is marked dirty and resyncs once it drains).
//! The RIB never waits for credit.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use rustbgpd_telemetry::OutboundRetainedGauges;
use tokio::sync::mpsc::OwnedPermit;

use crate::update::OutboundRouteUpdate;

/// Per-session budget for retained route updates.
///
/// A full Internet table resync is about 1.25M unicast rows; at 121 bytes a
/// row (the route plus its next-hop override slot) that is about 150 MB, so
/// this budget holds more than three of them. A session below
/// [`PEER_OUTBOUND_RETAINED_FLOOR`] is always admitted, so a single resync
/// larger than the budget still goes out.
pub(crate) const PEER_OUTBOUND_RETAINED_BUDGET: usize = 512 << 20;

/// Daemon-wide budget for retained route updates.
///
/// Healthy sessions drain their updates within moments, so the total stays
/// far below this; it is reached only when receivers stall while sources
/// churn. A session above the floor is then refused, and that peer resyncs
/// once it drains.
pub(crate) const OUTBOUND_RETAINED_BUDGET: usize = 2 << 30;

/// Retained bytes below which a session is admitted whatever the daemon-wide
/// total. A draining session holds a few deltas at a time, far below this, so
/// receivers stalled elsewhere do not refuse it and send it into a full-table
/// resync. The daemon-wide bound is therefore the budget plus, per session,
/// this floor and one update.
pub(crate) const PEER_OUTBOUND_RETAINED_FLOOR: usize = 1 << 20;

/// Daemon-wide retained bytes and the budgets admission checks against.
#[derive(Debug)]
pub(crate) struct OutboundRetainedTotal {
    bytes: AtomicUsize,
    peer_floor: usize,
    peer_budget: usize,
    budget: usize,
}

impl OutboundRetainedTotal {
    pub(crate) fn new(peer_floor: usize, peer_budget: usize, budget: usize) -> Arc<Self> {
        Arc::new(Self {
            bytes: AtomicUsize::new(0),
            peer_floor,
            peer_budget,
            budget,
        })
    }

    /// Estimated bytes retained across every session.
    pub(crate) fn bytes(&self) -> usize {
        self.bytes.load(Ordering::Relaxed)
    }
}

/// The retained route updates of one registered session.
#[derive(Debug)]
pub(crate) struct OutboundRetainedAccount {
    bytes: AtomicUsize,
    complete_feeds: AtomicUsize,
    total: Arc<OutboundRetainedTotal>,
    gauges: OutboundRetainedGauges,
}

impl OutboundRetainedAccount {
    pub(crate) fn new(
        total: Arc<OutboundRetainedTotal>,
        gauges: OutboundRetainedGauges,
    ) -> Arc<Self> {
        Arc::new(Self {
            bytes: AtomicUsize::new(0),
            complete_feeds: AtomicUsize::new(0),
            total,
            gauges,
        })
    }

    /// Whether route payload may be admitted for this session now.
    ///
    /// Only the RIB charges and sessions only release, so credit seen here
    /// cannot shrink before this actor's own send. A session below the
    /// floor always has credit, so one update larger than either budget
    /// still goes out.
    pub(crate) fn has_credit(&self) -> bool {
        let own = self.bytes();
        own < self.total.peer_floor
            || (own < self.total.peer_budget && self.total.bytes() < self.total.budget)
    }

    /// Estimated bytes this session retains.
    pub(crate) fn bytes(&self) -> usize {
        self.bytes.load(Ordering::Relaxed)
    }

    /// Whether an update carrying a complete EVPN feed is still queued for,
    /// or being sent by, this session.
    pub(crate) fn complete_feed_in_flight(&self) -> bool {
        self.complete_feeds.load(Ordering::Relaxed) != 0
    }

    /// Charge `update` to this session; the charge is released when the
    /// update is dropped. O(1): the estimate reads vector capacities only.
    pub(crate) fn charge(self: &Arc<Self>, update: &mut OutboundRouteUpdate, complete_feed: bool) {
        let bytes = update.retained_bytes_estimate();
        let own = self.bytes.fetch_add(bytes, Ordering::Relaxed) + bytes;
        let total = self.total.bytes.fetch_add(bytes, Ordering::Relaxed) + bytes;
        if complete_feed {
            self.complete_feeds.fetch_add(1, Ordering::Relaxed);
        }
        let gauge = |value: usize| i64::try_from(value).unwrap_or(i64::MAX);
        self.gauges.charge(gauge(bytes), gauge(own), gauge(total));
        // Replacing an earlier charge releases it.
        update.retained = OutboundRetainedCharge {
            account: Some(Arc::clone(self)),
            bytes,
            complete_feed,
            stage: Stage::Pending,
        };
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum Stage {
    /// Built, not yet in the channel.
    #[default]
    Pending,
    /// In the channel.
    Queued,
    /// Taken from the channel by the session.
    Dequeued,
}

/// The retained-byte charge an [`OutboundRouteUpdate`] holds against its
/// session's outbound budget. Dropping it releases the charge, and counts the
/// update as discarded when it was still queued. An update built outside the
/// RIB's send paths holds the default, empty charge.
#[derive(Debug, Default)]
pub struct OutboundRetainedCharge {
    account: Option<Arc<OutboundRetainedAccount>>,
    bytes: usize,
    complete_feed: bool,
    stage: Stage,
}

impl OutboundRetainedCharge {
    /// Estimated bytes charged; 0 for an uncharged update.
    #[must_use]
    pub fn bytes(&self) -> usize {
        self.bytes
    }

    /// Record that the session has taken this update from its channel to
    /// send. The charge itself stays until the update is dropped.
    pub fn dequeued(&mut self) {
        if self.stage == Stage::Queued {
            self.stage = Stage::Dequeued;
            if let Some(account) = &self.account {
                account.gauges.dequeue();
            }
        }
    }

    /// Whether this charge counts a complete EVPN feed as in flight.
    #[cfg(test)]
    pub(crate) fn complete_feed(&self) -> bool {
        self.complete_feed
    }
}

impl Drop for OutboundRetainedCharge {
    fn drop(&mut self) {
        let Some(account) = self.account.take() else {
            return;
        };
        if self.stage == Stage::Queued {
            account.gauges.discard();
        }
        account.bytes.fetch_sub(self.bytes, Ordering::Relaxed);
        account.total.bytes.fetch_sub(self.bytes, Ordering::Relaxed);
        if self.complete_feed {
            account.complete_feeds.fetch_sub(1, Ordering::Relaxed);
        }
        account
            .gauges
            .release(i64::try_from(self.bytes).unwrap_or(i64::MAX));
    }
}

/// One reserved slot of a session's channel, counted as reserved until it is
/// filled by [`Self::send`] or dropped.
pub(crate) struct OutboundSlot {
    permit: Option<OwnedPermit<OutboundRouteUpdate>>,
    account: Option<Arc<OutboundRetainedAccount>>,
}

impl OutboundSlot {
    pub(crate) fn new(
        permit: OwnedPermit<OutboundRouteUpdate>,
        account: Option<&Arc<OutboundRetainedAccount>>,
    ) -> Self {
        if let Some(account) = account {
            account.gauges.reserve();
        }
        Self {
            permit: Some(permit),
            account: account.cloned(),
        }
    }

    /// Fill the slot. An update not already charged is charged to the
    /// slot's session here, before it becomes visible to the session.
    pub(crate) fn send(mut self, mut update: OutboundRouteUpdate, complete_feed: bool) {
        let permit = self.permit.take().expect("an unsent slot holds its permit");
        if let Some(account) = self.account.take() {
            if update.retained.account.is_none() {
                account.charge(&mut update, complete_feed);
            }
            update.retained.stage = Stage::Queued;
            account.gauges.unreserve();
            account.gauges.enqueue();
        }
        permit.send(update);
    }
}

impl Drop for OutboundSlot {
    fn drop(&mut self) {
        if let Some(account) = self.account.take() {
            account.gauges.unreserve();
        }
    }
}

impl OutboundRouteUpdate {
    /// Conservative O(1) estimate of the heap bytes this update retains:
    /// the allocated capacity (not the length) of every payload vector times
    /// its row size, so a grown vector's unused tail is charged too.
    ///
    /// A vector shared with other updates (`Arc`) is charged its size divided
    /// by its holders at charge time, so one group fanout is charged a
    /// harmonic multiple of the shared table rather than once per member.
    /// Heap owned under a row is not walked, which would make the charge
    /// linear: attribute sets sit behind an `Arc` that is shared or interned
    /// in the common case, and policy-rewritten sets were about a tenth of
    /// the retained bytes in a profiled receiver stall. The budgets leave
    /// room for that.
    pub(crate) fn retained_bytes_estimate(&self) -> usize {
        fn owned<T>(rows: &Vec<T>) -> usize {
            rows.capacity().saturating_mul(std::mem::size_of::<T>())
        }
        fn shared<T>(rows: &Arc<Vec<T>>) -> usize {
            owned(rows) / Arc::strong_count(rows)
        }
        // Exhaustive, so a new payload field does not compile until it is
        // classified here.
        let Self {
            exact_export_snapshot: _,
            announce_source_exclusion: _,
            announce,
            withdraw,
            end_of_rib,
            replay: _,
            refresh_markers,
            next_hop_override,
            flowspec_announce,
            flowspec_withdraw,
            evpn_announce,
            evpn_withdraw,
            bgpls_announce,
            bgpls_withdraw,
            vpn_announce,
            vpn_withdraw,
            labeled_announce,
            labeled_withdraw,
            rtc_announce,
            rtc_withdraw,
            otc_blocked,
            request_refresh_all_negotiated: _,
            shared_group_encode: _,
            exempt_announce: _,
            retained: _,
        } = self;
        [
            shared(announce),
            shared(next_hop_override),
            shared(evpn_announce),
            shared(vpn_announce),
            owned(withdraw),
            owned(end_of_rib),
            owned(refresh_markers),
            owned(flowspec_announce),
            owned(flowspec_withdraw),
            owned(evpn_withdraw),
            owned(bgpls_announce),
            owned(bgpls_withdraw),
            owned(vpn_withdraw),
            owned(labeled_announce),
            owned(labeled_withdraw),
            owned(rtc_announce),
            owned(rtc_withdraw),
            owned(otc_blocked),
        ]
        .into_iter()
        .fold(0, usize::saturating_add)
    }
}
