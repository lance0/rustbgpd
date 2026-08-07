//! Acknowledgement-aware EVPN origination toward the RIB (ADR-0102).
//!
//! Shared by the local Type 2 MAC/MAC+IP originator
//! ([`crate::evpn_originator`]), the Ethernet Segment orchestrator's
//! Type 1/4 publication ([`crate::evpn_segment`]), and — for the
//! bounded [`send_and_ack`] wait only, without the pending-op tracker —
//! the Type 3 IMET controller ([`crate::evpn_imet`]), whose converge
//! callers hold a mutex across the ack await and therefore must never
//! wait unboundedly. The two tracker-backed actors keep a
//! [`PendingRibOps`] tracker: every inject/withdraw sent to the RIB is
//! recorded as *pending* under `(route identity, generation)` and only
//! forgotten once the RIB's reply oneshot acknowledges it. A dropped
//! reply, an ack timeout, or a closed channel keeps the operation
//! pending; the owning actor's retry arm re-attempts it with bounded
//! exponential backoff. New intent for the same route identity
//! supersedes older pending work (fresh generation), and
//! acknowledgement handling is generation-checked so a stale ack can
//! never confirm a superseded operation.
//!
//! Correctness leans on three properties recorded in ADR-0102:
//!
//! 1. RIB inject/withdraw are idempotent per key (`insert_evpn` is
//!    last-write-wins; `withdraw_evpn` of an absent key is a no-op
//!    reported as `NotFound`), so a retry of an operation whose first
//!    attempt actually applied is harmless.
//! 2. The RIB command channel is FIFO, so a superseding operation sent
//!    after a possibly-applied predecessor always lands after it.
//! 3. Nothing here is persisted: on restart, intent is rebuilt from
//!    kernel/config observation and reconciled idempotently.

use std::collections::HashMap;
use std::time::Duration;

use rustbgpd_evpn::{EvpnInstanceId, OriginationAction};
use rustbgpd_rib::{RibCommandError, RibUpdate};
use rustbgpd_wire::EvpnRouteKey;
use tokio::sync::{mpsc, oneshot};
use tokio::time::Instant;

/// How long an inject/withdraw waits for the RIB's reply before the
/// attempt counts as unacknowledged. The RIB actor replies inline while
/// processing the command, so this only trips when the RIB is wedged or
/// severely backlogged.
pub(crate) const RIB_ACK_TIMEOUT: Duration = Duration::from_secs(5);

/// First retry delay after a failed attempt.
pub(crate) const RETRY_BACKOFF_BASE: Duration = Duration::from_secs(1);

/// Backoff ceiling: 1s → 2s → 4s → 8s → 16s → 30s, then 30s forever.
/// Retries never give up — a withdraw must not be forgotten until the
/// RIB acknowledges it — but the interval is bounded so a persistent
/// failure costs one attempt per 30s per route, not a hot loop.
pub(crate) const RETRY_BACKOFF_MAX: Duration = Duration::from_secs(30);

/// `NoAck` reason for a reply oneshot the RIB dropped without
/// answering. A const (rather than an inline literal) so
/// [`crate::evpn_imet`] can pattern-match it when mapping ack
/// outcomes onto its caller-visible outcome enums.
pub(crate) const NOACK_REPLY_DROPPED: &str = "reply dropped";

/// Outcome of one inject/withdraw attempt against the RIB.
#[derive(Debug)]
pub(crate) enum RibAckOutcome {
    /// The RIB applied the operation.
    Acked,
    /// The RIB actively rejected the operation.
    Rejected(RibCommandError),
    /// No acknowledgement: channel closed, reply dropped, or timeout.
    /// The operation may or may not have been applied.
    NoAck(&'static str),
}

impl RibAckOutcome {
    /// A withdraw rejected with `NotFound` means the route is already
    /// absent — exactly the state the withdraw wanted. Callers treat
    /// it as confirmation (e.g. the paired inject was lost earlier).
    pub(crate) fn is_not_found(&self) -> bool {
        matches!(self, Self::Rejected(RibCommandError::NotFound(_)))
    }
}

/// Send one RIB command carrying a reply oneshot and await the
/// acknowledgement, bounded by [`RIB_ACK_TIMEOUT`].
pub(crate) async fn send_and_ack(
    rib_tx: &mpsc::Sender<RibUpdate>,
    update: impl FnOnce(oneshot::Sender<Result<(), RibCommandError>>) -> RibUpdate,
) -> RibAckOutcome {
    let (reply_tx, reply_rx) = oneshot::channel();
    if rib_tx.send(update(reply_tx)).await.is_err() {
        return RibAckOutcome::NoAck("RIB channel closed");
    }
    match tokio::time::timeout(RIB_ACK_TIMEOUT, reply_rx).await {
        Ok(Ok(Ok(()))) => RibAckOutcome::Acked,
        Ok(Ok(Err(e))) => RibAckOutcome::Rejected(e),
        Ok(Err(_)) => RibAckOutcome::NoAck(NOACK_REPLY_DROPPED),
        Err(_) => RibAckOutcome::NoAck("ack timeout"),
    }
}

/// One unacknowledged origination operation.
#[derive(Debug, Clone)]
pub(crate) struct PendingOp {
    /// EVPN instance the operation was built against. Inject retries
    /// rebuild their route from the *current* model for this VNI (and
    /// are dropped if it disappeared); withdraw retries only need the
    /// key.
    pub vni: EvpnInstanceId,
    /// The originating state machine's action, replayed on retry.
    pub action: OriginationAction,
    /// Supersession stamp: only an ack carrying the current generation
    /// confirms the operation.
    pub generation: u64,
    /// Failed attempts so far (drives the backoff schedule).
    pub attempts: u32,
    /// Earliest time the next attempt may run.
    pub next_attempt: Instant,
}

/// Generation-stamped pending-operation tracker (ADR-0102).
///
/// Keyed by route identity ([`EvpnRouteKey`]): at most one operation is
/// pending per route, and submitting a new one supersedes the old.
#[derive(Debug, Default)]
pub(crate) struct PendingRibOps {
    ops: HashMap<EvpnRouteKey, PendingOp>,
    next_generation: u64,
}

impl PendingRibOps {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Record a new operation as pending, superseding any older
    /// pending operation for the same route identity. Returns the
    /// generation the caller must present to [`Self::confirm`] /
    /// [`Self::defer`].
    pub(crate) fn submit(
        &mut self,
        key: EvpnRouteKey,
        vni: EvpnInstanceId,
        action: OriginationAction,
    ) -> u64 {
        self.next_generation += 1;
        let generation = self.next_generation;
        self.ops.insert(
            key,
            PendingOp {
                vni,
                action,
                generation,
                attempts: 0,
                next_attempt: Instant::now(),
            },
        );
        generation
    }

    /// Acknowledge an operation. Returns `true` and forgets the entry
    /// only when `generation` matches the currently-pending one; a
    /// stale ack (the operation was superseded) is ignored.
    pub(crate) fn confirm(&mut self, key: EvpnRouteKey, generation: u64) -> bool {
        if self
            .ops
            .get(&key)
            .is_some_and(|op| op.generation == generation)
        {
            self.ops.remove(&key);
            return true;
        }
        false
    }

    /// Record a failed attempt: keep the operation pending and push its
    /// next attempt out on the bounded backoff schedule. No-op if the
    /// operation was superseded meanwhile.
    pub(crate) fn defer(&mut self, key: EvpnRouteKey, generation: u64) {
        if let Some(op) = self.ops.get_mut(&key)
            && op.generation == generation
        {
            op.attempts = op.attempts.saturating_add(1);
            op.next_attempt = Instant::now() + backoff_after(op.attempts);
        }
    }

    /// Drop a pending operation without acknowledgement — used when a
    /// retry can no longer rebuild an inject (its VNI/segment left the
    /// model; the lifecycle drain that removed it already superseded
    /// the route's state with withdraws). Generation-checked like
    /// [`Self::confirm`].
    pub(crate) fn forget(&mut self, key: EvpnRouteKey, generation: u64) {
        if self
            .ops
            .get(&key)
            .is_some_and(|op| op.generation == generation)
        {
            self.ops.remove(&key);
        }
    }

    /// Snapshot of the operations whose backoff has elapsed.
    pub(crate) fn due(&self, now: Instant) -> Vec<(EvpnRouteKey, PendingOp)> {
        self.ops
            .iter()
            .filter(|(_, op)| op.next_attempt <= now)
            .map(|(key, op)| (*key, op.clone()))
            .collect()
    }

    /// Earliest scheduled attempt, if anything is pending. Drives the
    /// owning actor's retry `select!` arm.
    pub(crate) fn next_deadline(&self) -> Option<Instant> {
        self.ops.values().map(|op| op.next_attempt).min()
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.ops.len()
    }

    #[cfg(test)]
    pub(crate) fn is_empty(&self) -> bool {
        self.ops.is_empty()
    }

    /// The pending operation for a route identity, if any.
    #[cfg(test)]
    pub(crate) fn get(&self, key: &EvpnRouteKey) -> Option<&PendingOp> {
        self.ops.get(key)
    }
}

/// Bounded exponential backoff: `BASE * 2^(attempts-1)` capped at
/// [`RETRY_BACKOFF_MAX`].
fn backoff_after(attempts: u32) -> Duration {
    let exp = attempts.saturating_sub(1).min(5);
    RETRY_BACKOFF_BASE
        .saturating_mul(1 << exp)
        .min(RETRY_BACKOFF_MAX)
}

/// Sleep until the tracker's next deadline, or forever when nothing is
/// pending (so the owning `select!` services its other arms).
pub(crate) async fn retry_delay(deadline: Option<Instant>) {
    match deadline {
        Some(deadline) => tokio::time::sleep_until(deadline).await,
        None => std::future::pending().await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{mac, rd, vni as make_vni};
    use rustbgpd_wire::EthernetTagId;

    fn key(mac_byte: u8) -> EvpnRouteKey {
        EvpnRouteKey::MacIp {
            rd: rd(65000, 100),
            ethernet_tag: EthernetTagId(0),
            mac: mac(mac_byte),
            ip: None,
        }
    }

    fn inject(mac_byte: u8) -> OriginationAction {
        OriginationAction::Inject {
            mac: mac(mac_byte),
            mobility_seq: None,
            sticky: false,
            key: key(mac_byte),
        }
    }

    fn withdraw(mac_byte: u8) -> OriginationAction {
        OriginationAction::Withdraw {
            mac: mac(mac_byte),
            key: key(mac_byte),
        }
    }

    fn vni() -> EvpnInstanceId {
        make_vni(100)
    }

    #[tokio::test]
    async fn supersession_ignores_stale_ack_and_new_generation_wins() {
        let mut pending = PendingRibOps::new();
        let g1 = pending.submit(key(1), vni(), inject(1));
        // New intent for the same route identity supersedes the
        // pending inject with a withdraw.
        let g2 = pending.submit(key(1), vni(), withdraw(1));
        assert!(g2 > g1);
        assert_eq!(pending.len(), 1);
        assert!(matches!(
            pending.get(&key(1)).unwrap().action,
            OriginationAction::Withdraw { .. }
        ));

        // A stale ack for the superseded generation must not confirm.
        assert!(!pending.confirm(key(1), g1));
        assert_eq!(pending.len(), 1, "stale ack must not clear the op");
        // Stale defer is equally inert.
        pending.defer(key(1), g1);
        assert_eq!(pending.get(&key(1)).unwrap().attempts, 0);

        // The current generation confirms.
        assert!(pending.confirm(key(1), g2));
        assert!(pending.is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn backoff_doubles_from_base_and_caps_at_max() {
        let mut pending = PendingRibOps::new();
        let generation = pending.submit(key(1), vni(), inject(1));

        let mut expected = vec![];
        for attempt in 1..=8u32 {
            let before = Instant::now();
            pending.defer(key(1), generation);
            let deadline = pending.next_deadline().expect("op pending");
            expected.push((attempt, deadline - before));
        }
        assert_eq!(
            expected
                .iter()
                .map(|(_, d)| d.as_secs())
                .collect::<Vec<_>>(),
            vec![1, 2, 4, 8, 16, 30, 30, 30],
            "backoff must double from 1s and stay capped at 30s"
        );

        // Nothing is due before the deadline; everything after.
        assert!(pending.due(Instant::now()).is_empty());
        assert_eq!(
            pending.due(Instant::now() + Duration::from_secs(31)).len(),
            1
        );
    }

    #[tokio::test]
    async fn forget_is_generation_checked() {
        let mut pending = PendingRibOps::new();
        let g1 = pending.submit(key(1), vni(), inject(1));
        let g2 = pending.submit(key(1), vni(), inject(1));
        pending.forget(key(1), g1);
        assert_eq!(pending.len(), 1, "stale forget must not clear the op");
        pending.forget(key(1), g2);
        assert!(pending.is_empty());
    }
}
