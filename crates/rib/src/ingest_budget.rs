//! Per-session bound on route input the RIB has not finished.
//!
//! The RIB serves one shared input queue in arrival order, so a session that
//! reads its socket as fast as the peer writes can queue a whole burst ahead
//! of every other session's updates. A session therefore charges each
//! route-bearing message to its own `IngestBudget` and stops reading its
//! socket while the budget is spent. The charge is an `IngestPermit` that
//! travels with the message and returns the routes when it is dropped, so
//! every path that discards a message (a drained batch, a peer-down purge, a
//! superseded session, a closed channel) returns budget without a release
//! call.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

/// Unfinished routes at which a session stops reading its socket: one
/// distribution window of affected prefixes, so the shared queue holds about
/// one distribution pass per source.
// ponytail: one fixed budget for every session and family. Make it a
// per-neighbor setting if a source needs a deeper pipeline than one window.
pub const INGEST_BUDGET_ROUTES: usize = 1024;
/// Unfinished routes at which a stopped session reads again. Resuming at
/// half the budget keeps a stream of small messages from stopping and
/// resuming once per message.
pub const INGEST_RESUME_ROUTES: usize = INGEST_BUDGET_ROUTES / 2;

/// One session's count of routes sent to the RIB and not yet finished there.
#[derive(Debug, Default)]
pub struct IngestBudget {
    unfinished: AtomicUsize,
    resumed: tokio::sync::Notify,
}

impl IngestBudget {
    /// A budget with nothing charged.
    #[must_use]
    pub fn new() -> Arc<Self> {
        Arc::default()
    }

    /// Routes charged and not yet returned.
    #[must_use]
    pub fn unfinished(&self) -> usize {
        self.unfinished.load(Ordering::Acquire)
    }

    /// Whether the session's input gate is closed, given whether it was
    /// `closed` before: it closes at [`INGEST_BUDGET_ROUTES`] and stays
    /// closed until [`INGEST_RESUME_ROUTES`]. Input is never held for
    /// budget once read, so a message larger than the whole budget is
    /// admitted whenever the gate is open.
    #[must_use]
    pub fn gate_closed(&self, closed: bool) -> bool {
        let unfinished = self.unfinished();
        if closed {
            unfinished > INGEST_RESUME_ROUTES
        } else {
            unfinished >= INGEST_BUDGET_ROUTES
        }
    }

    /// Completes after returned permits take the budget down to
    /// [`INGEST_RESUME_ROUTES`]. A wake-up may be stale; re-check
    /// [`Self::gate_closed`].
    pub async fn resumed(&self) {
        self.resumed.notified().await;
    }

    /// Charge `routes` until the returned permit is dropped.
    #[must_use]
    pub fn charge(self: &Arc<Self>, routes: usize) -> IngestPermit {
        self.unfinished.fetch_add(routes, Ordering::AcqRel);
        IngestPermit {
            budget: Arc::clone(self),
            routes,
        }
    }
}

/// Routes charged to a session's [`IngestBudget`]; dropping it returns them.
#[derive(Debug)]
pub struct IngestPermit {
    budget: Arc<IngestBudget>,
    routes: usize,
}

impl Drop for IngestPermit {
    fn drop(&mut self) {
        let before = self
            .budget
            .unfinished
            .fetch_sub(self.routes, Ordering::AcqRel);
        // Wake the session once, when this return crosses the resume mark.
        if before > INGEST_RESUME_ROUTES && before - self.routes <= INGEST_RESUME_ROUTES {
            self.budget.resumed.notify_one();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gate_closes_at_the_budget_and_reopens_at_half() {
        let budget = IngestBudget::new();
        let small = budget.charge(INGEST_BUDGET_ROUTES - 1);
        assert!(!budget.gate_closed(false));
        let one = budget.charge(1);
        assert!(budget.gate_closed(false));
        drop(one);
        assert!(
            budget.gate_closed(true),
            "stays closed above the resume mark"
        );
        assert!(!budget.gate_closed(false));
        drop(small);
        assert!(!budget.gate_closed(true));
        assert_eq!(budget.unfinished(), 0);
    }

    /// A message larger than the whole budget is charged in full, and the
    /// session is woken when it returns: the gate cannot stay closed.
    #[tokio::test]
    async fn an_oversized_permit_wakes_the_session_when_it_returns() {
        let budget = IngestBudget::new();
        let oversized = budget.charge(10 * INGEST_BUDGET_ROUTES);
        assert!(budget.gate_closed(false));
        drop(oversized);
        // The wake-up is stored, so a session that starts waiting only now
        // still sees it.
        tokio::time::timeout(std::time::Duration::from_secs(5), budget.resumed())
            .await
            .expect("returning the budget wakes the session");
        assert!(!budget.gate_closed(true));
    }

    /// Boundary: a return that lands exactly on the resume mark wakes the
    /// session and reopens the gate.
    #[tokio::test]
    async fn a_return_to_exactly_the_resume_mark_wakes_and_reopens() {
        let budget = IngestBudget::new();
        let kept = budget.charge(INGEST_RESUME_ROUTES);
        drop(budget.charge(INGEST_BUDGET_ROUTES - INGEST_RESUME_ROUTES));
        assert_eq!(budget.unfinished(), INGEST_RESUME_ROUTES);
        tokio::time::timeout(std::time::Duration::ZERO, budget.resumed())
            .await
            .expect("a return to the resume mark wakes the session");
        assert!(!budget.gate_closed(true));
        drop(kept);
    }

    #[tokio::test]
    async fn a_return_above_the_resume_mark_does_not_wake() {
        let budget = IngestBudget::new();
        let kept = budget.charge(INGEST_RESUME_ROUTES + 1);
        drop(budget.charge(INGEST_BUDGET_ROUTES));
        let woke = tokio::time::timeout(std::time::Duration::ZERO, budget.resumed()).await;
        assert!(woke.is_err(), "the gate is still closed");
        drop(kept);
    }
}
