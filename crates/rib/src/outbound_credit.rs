//! Payload-lifetime credit for the route updates the RIB hands to sessions.
//!
//! The RIB-to-session channel is bounded by envelope count, and a count does
//! not bound memory: receivers that stop reading while sources churn would
//! hold every queued route version. Two mechanisms bound what one peer can
//! pin, both carried inside the envelope so they follow its ownership through
//! the queue, the session's active payload, paced retirement and a dropped
//! channel, across every session generation of the peer:
//!
//! - **Row credit** for private families (rows held in the peer's own
//!   Adj-RIB-Out). Each ordinary envelope carries an [`OutboundCharge`] for
//!   its private rows, released when the envelope drops. A new ordinary
//!   envelope is admitted only while the peer's live rows are below its row
//!   credit, so a peer with no live rows is always admitted; a refusal marks
//!   the peer dirty, exactly like a full channel, and the resync timer
//!   retries from current state.
//! - **One whole-table operation per peer** (initial dump, refresh or replay
//!   response, dirty or forced resync, complete EVPN feed, operator replay).
//!   Every envelope of one operation holds a clone of its [`OperationLatch`];
//!   the RIB keeps only a weak reference, and a second operation is refused
//!   while the first is live. An operation reserves every envelope it needs,
//!   nested markers included, before it sends anything, and charges no rows:
//!   it is bounded by the latch, so a whole table never exhausts credit.
//!
//! Markers and control-only envelopes take channel capacity only.

use std::hash::Hash;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use tokio::sync::mpsc::{OwnedPermit, Sender};

use crate::update::OutboundRouteUpdate;

/// Daemon-wide ordinary private rows, divided among the peers with a
/// private family.
///
/// The RIB stages private rows at about 0.6 µs per row per peer (measured
/// with every private peer in each pass), so a peer receives at most about
/// `1 / (P · 0.6 µs)` rows per second, and a credit of `D / P` rows
/// tolerates a receiver that drains nothing for about `D · 0.6 µs`, about
/// 10 s at 16M rows, wherever the credit is unclamped: P = 16 to 2,048.
/// Below that [`MAX_ROW_CREDIT`] applies (about 0.6 s of stall at P = 1);
/// above it [`MIN_ROW_CREDIT`] tolerates longer. Sparse fanout spreads less
/// of the RIB's work over each peer, so these are not universal stall
/// times. 16M rows is 2.2× the 50,000 rows a receiver queued when 150 peers
/// restarted during a 100,000-route source dump, and about 2 GiB of
/// ordinary private rows daemon-wide at saturation (about 121 bytes a row).
/// The per-peer limit is read from the current peer count at each
/// admission; envelopes admitted under an earlier, larger limit are held
/// until they drop. Re-tune by measuring the staging cost and choosing the
/// tolerated stall.
pub(crate) const DAEMON_ROW_CREDIT: usize = 16_777_216;
/// Smallest per-peer credit, whatever the number of private peers.
pub(crate) const MIN_ROW_CREDIT: usize = 8_192;
/// Largest per-peer credit, whatever the number of private peers.
pub(crate) const MAX_ROW_CREDIT: usize = 1_048_576;
/// Rows per ordinary private envelope once a larger pass is chunked.
pub(crate) const CHUNK_ROWS: usize = 1_024;

/// Per-peer row credit when `private_peers` peers have a private family.
pub(crate) fn row_credit_for(private_peers: usize) -> usize {
    (DAEMON_ROW_CREDIT / private_peers.max(1)).clamp(MIN_ROW_CREDIT, MAX_ROW_CREDIT)
}

/// Live private-family rows owed to one peer, across every session
/// generation.
#[derive(Debug, Default)]
pub struct OutboundCredit {
    rows: AtomicUsize,
}

impl OutboundCredit {
    /// Rows held by envelopes not yet dropped.
    #[must_use]
    pub fn rows(&self) -> usize {
        self.rows.load(Ordering::Acquire)
    }
}

/// Rows charged by one envelope; released exactly once, when the envelope
/// drops.
#[derive(Debug)]
pub struct OutboundCharge {
    credit: Arc<OutboundCredit>,
    rows: usize,
}

impl OutboundCharge {
    /// Charge `rows` to `credit` until the returned charge drops.
    #[must_use]
    pub fn new(credit: &Arc<OutboundCredit>, rows: usize) -> Self {
        credit.rows.fetch_add(rows, Ordering::Relaxed);
        Self {
            credit: Arc::clone(credit),
            rows,
        }
    }

    /// Rows this envelope holds against its peer's credit.
    #[must_use]
    pub fn rows(&self) -> usize {
        self.rows
    }
}

impl Drop for OutboundCharge {
    fn drop(&mut self) {
        let before = self.credit.rows.fetch_sub(self.rows, Ordering::Release);
        debug_assert!(before >= self.rows, "outbound credit released twice");
    }
}

/// One whole-table operation for one peer. Every envelope of the operation
/// holds a clone; the operation is live until the last one drops.
#[derive(Debug)]
pub struct OperationLatch(());

/// One reserved channel slot of a whole-table operation.
pub(crate) struct OutboundSlot {
    permit: OwnedPermit<OutboundRouteUpdate>,
    latch: Arc<OperationLatch>,
}

impl OutboundSlot {
    /// Fill the slot with an envelope of the operation.
    pub(crate) fn send(self, mut update: OutboundRouteUpdate) {
        update.latch = Some(self.latch);
        self.permit.send(update);
    }
}

/// A whole-table operation admitted for one peer: its latch and the slots it
/// reserved.
pub(crate) struct OutboundOperation {
    sender: Sender<OutboundRouteUpdate>,
    latch: Arc<OperationLatch>,
    permits: Vec<OwnedPermit<OutboundRouteUpdate>>,
}

impl OutboundOperation {
    /// Reserve up to `envelopes` slots on `sender` for a new operation, or
    /// `None` when the channel has no room at all. Only the RIB actor
    /// sends, so the room seen here is still there at each send. With less
    /// room than the operation's nested markers need, the data goes in what
    /// was reserved and a marker takes channel capacity alone when it is
    /// sent ([`Self::slot`]), as before; an operation that must be accepted
    /// whole checks [`Self::reserved`].
    pub(crate) fn reserve(sender: &Sender<OutboundRouteUpdate>, envelopes: usize) -> Option<Self> {
        let mut permits = Vec::with_capacity(envelopes);
        while permits.len() < envelopes {
            match sender.clone().try_reserve_owned() {
                Ok(permit) => permits.push(permit),
                Err(_) => break,
            }
        }
        if permits.is_empty() {
            return None;
        }
        Some(Self {
            sender: sender.clone(),
            latch: Arc::new(OperationLatch(())),
            permits,
        })
    }

    /// The latch every envelope of this operation holds.
    pub(crate) fn latch(&self) -> &Arc<OperationLatch> {
        &self.latch
    }

    /// The next reserved slot, or one more reserved now against channel
    /// capacity alone for an envelope that joins the operation.
    pub(crate) fn slot(&mut self) -> Option<OutboundSlot> {
        let permit = match self.permits.pop() {
            Some(permit) => permit,
            None => self.sender.clone().try_reserve_owned().ok()?,
        };
        Some(OutboundSlot {
            permit,
            latch: Arc::clone(&self.latch),
        })
    }

    /// Slots reserved and not yet filled.
    pub(crate) fn reserved(&self) -> usize {
        self.permits.len()
    }
}

/// Send a marker or control-only envelope (End-of-RIB, route-refresh
/// markers, a refresh request): it needs channel capacity only.
pub(crate) fn send_marker(
    sender: &Sender<OutboundRouteUpdate>,
    update: OutboundRouteUpdate,
) -> Result<(), tokio::sync::mpsc::error::TrySendError<()>> {
    use tokio::sync::mpsc::error::TrySendError;
    sender.try_send(update).map_err(|error| match error {
        TrySendError::Full(_) => TrySendError::Full(()),
        TrySendError::Closed(_) => TrySendError::Closed(()),
    })
}

/// Which of an envelope's families a peer holds privately (in its own
/// Adj-RIB-Out); `FlowSpec`, BGP-LS, labeled unicast and RT-Constrain always
/// are.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct PrivateFamilies {
    pub(crate) unicast: bool,
    pub(crate) vpn: bool,
    pub(crate) evpn: bool,
}

impl PrivateFamilies {
    /// Rows of `update` in private families.
    pub(crate) fn rows(self, update: &OutboundRouteUpdate) -> usize {
        let mut rows = update.flowspec_announce.len()
            + update.flowspec_withdraw.len()
            + update.bgpls_announce.len()
            + update.bgpls_withdraw.len()
            + update.labeled_announce.len()
            + update.labeled_withdraw.len()
            + update.rtc_announce.len()
            + update.rtc_withdraw.len()
            // OTC-blocked diagnostics retain full route bodies until the
            // session publishes them: one row each.
            + update.otc_blocked.len();
        if self.unicast {
            rows += update.announce.len() + update.shared_withdraw.len() + update.withdraw.len();
        }
        if self.vpn {
            rows += update.vpn_announce.len() + update.vpn_withdraw.len();
        }
        if self.evpn {
            rows += update.evpn_announce.len() + update.evpn_withdraw.len();
        }
        rows
    }
}

/// Whether every announcement in `announce` names a key that `withdraw`
/// also withdraws: an Add-Path move of that key within one envelope.
pub(crate) fn announces_only_withdrawn_keys<A, W, K: Hash + Eq>(
    announce: &[A],
    announce_key: impl Fn(&A) -> K,
    withdraw: &[W],
    withdraw_key: impl Fn(&W) -> K,
) -> bool {
    if announce.is_empty() {
        return true;
    }
    let withdrawn: std::collections::HashSet<K> = withdraw.iter().map(withdraw_key).collect();
    announce
        .iter()
        .all(|row| withdrawn.contains(&announce_key(row)))
}

/// Every row of `update`, private or group-owned.
fn total_rows(update: &OutboundRouteUpdate) -> usize {
    PrivateFamilies {
        unicast: true,
        vpn: true,
        evpn: true,
    }
    .rows(update)
}

/// Whether an ordinary envelope may be cut into `CHUNK_ROWS`-row pieces:
/// it carries no marker, request, replay terminal or shared group payload.
pub(crate) fn chunkable(update: &OutboundRouteUpdate) -> bool {
    update.end_of_rib.is_empty()
        && update.refresh_markers.is_empty()
        && update.replay.is_none()
        && !update.request_refresh_all_negotiated
        && update.shared_group_encode.is_none()
        && update.announce_source_exclusion.is_none()
        && update.shared_withdraw.is_empty()
        && (update.next_hop_override.is_empty()
            || update.next_hop_override.len() == update.announce.len())
        && total_rows(update) > CHUNK_ROWS
}

/// Row counts of the chunks `update` is cut into: its OTC diagnostics, then
/// its rows in transport phase order (unicast withdraw, unicast announce
/// with the blackholing rows first, the other families' withdrawals, then
/// their announcements, `FlowSpec` announce last), `max_rows` to a chunk. A
/// key's rows may span consecutive chunks; sent in order, the chunks
/// reproduce the single envelope's order exactly.
pub(crate) fn chunk_plan(update: &OutboundRouteUpdate, max_rows: usize) -> Vec<usize> {
    let mut left = total_rows(update);
    let mut plan = Vec::with_capacity(left.div_ceil(max_rows.max(1)));
    while left > 0 {
        let rows = left.min(max_rows.max(1));
        plan.push(rows);
        left -= rows;
    }
    plan
}

fn owned<T: Clone>(rows: Arc<Vec<T>>) -> Vec<T> {
    Arc::try_unwrap(rows).unwrap_or_else(|rows| rows.as_ref().clone())
}

/// Cut `update` into envelopes of `plan`'s row counts, in phase order, so
/// that sending them in order reproduces the single envelope's rows exactly.
/// Each piece reuses the export snapshot; the leading blackholing rows and
/// next-hop overrides follow their announcements; OTC diagnostics go with
/// the first piece.
pub(crate) fn split_by_plan(
    mut update: OutboundRouteUpdate,
    plan: &[usize],
) -> Vec<OutboundRouteUpdate> {
    let aligned = !update.next_hop_override.is_empty();
    let mut exempt_left = update.exempt_announce;
    let mut otc_blocked = std::mem::take(&mut update.otc_blocked).into_iter();
    let mut withdraw = std::mem::take(&mut update.withdraw).into_iter();
    let mut announce = owned(std::mem::take(&mut update.announce)).into_iter();
    let mut next_hop = owned(std::mem::take(&mut update.next_hop_override)).into_iter();
    let mut flowspec_withdraw = std::mem::take(&mut update.flowspec_withdraw).into_iter();
    let mut evpn_withdraw = std::mem::take(&mut update.evpn_withdraw).into_iter();
    let mut bgpls_withdraw = std::mem::take(&mut update.bgpls_withdraw).into_iter();
    let mut vpn_withdraw = std::mem::take(&mut update.vpn_withdraw).into_iter();
    let mut labeled_withdraw = std::mem::take(&mut update.labeled_withdraw).into_iter();
    let mut rtc_withdraw = std::mem::take(&mut update.rtc_withdraw).into_iter();
    let mut evpn_announce = owned(std::mem::take(&mut update.evpn_announce)).into_iter();
    let mut bgpls_announce = std::mem::take(&mut update.bgpls_announce).into_iter();
    let mut vpn_announce = owned(std::mem::take(&mut update.vpn_announce)).into_iter();
    let mut labeled_announce = std::mem::take(&mut update.labeled_announce).into_iter();
    let mut rtc_announce = std::mem::take(&mut update.rtc_announce).into_iter();
    let mut flowspec_announce = std::mem::take(&mut update.flowspec_announce).into_iter();
    plan.iter()
        .map(|&rows| {
            let mut left = rows;
            let mut chunk = OutboundRouteUpdate {
                exact_export_snapshot: update.exact_export_snapshot.clone(),
                ..OutboundRouteUpdate::default()
            };
            macro_rules! take {
                ($rows:ident) => {{
                    let taken: Vec<_> = $rows.by_ref().take(left).collect();
                    left -= taken.len();
                    taken
                }};
            }
            chunk.otc_blocked = take!(otc_blocked);
            chunk.withdraw = take!(withdraw);
            let announced = take!(announce);
            if aligned {
                chunk.next_hop_override = next_hop
                    .by_ref()
                    .take(announced.len())
                    .collect::<Vec<_>>()
                    .into();
            }
            chunk.exempt_announce = exempt_left.min(announced.len());
            exempt_left -= chunk.exempt_announce;
            chunk.announce = announced.into();
            chunk.flowspec_withdraw = take!(flowspec_withdraw);
            chunk.evpn_withdraw = take!(evpn_withdraw);
            chunk.bgpls_withdraw = take!(bgpls_withdraw);
            chunk.vpn_withdraw = take!(vpn_withdraw);
            chunk.labeled_withdraw = take!(labeled_withdraw);
            chunk.rtc_withdraw = take!(rtc_withdraw);
            chunk.evpn_announce = take!(evpn_announce).into();
            chunk.bgpls_announce = take!(bgpls_announce);
            chunk.vpn_announce = take!(vpn_announce).into();
            chunk.labeled_announce = take!(labeled_announce);
            chunk.rtc_announce = take!(rtc_announce);
            chunk.flowspec_announce = take!(flowspec_announce);
            debug_assert_eq!(left, 0, "a chunk plan covers exactly the envelope's rows");
            chunk
        })
        .collect()
}
