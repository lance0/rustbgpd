//! Temporary operator projections held only while synchronous replacement owns
//! canonical RIB state. These contain values, never routes or shared counters.

use super::update_groups::{GroupKey, GroupMembership, compare_update_groups};
use super::{QUERY_BUDGET_PER_CHUNK, RibManager};
use crate::update::{
    EffectiveDistributionMode, NeighborPolicyStats, NeighborRibSnapshot, PeerOutboundState,
    RibSummaryQuery,
};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::task::{Context, Poll};
use tokio::sync::mpsc;

pub(super) struct ReplacementSummaries {
    pub(super) rx: mpsc::Receiver<RibSummaryQuery>,
    post_commit_query_trace: Option<super::PostCommitQueryTrace>,
    view: SummaryProjection,
}

struct SummaryProjection {
    neighbors: HashMap<IpAddr, NeighborRibSnapshot>,
    unknown_outbound: PeerOutboundState,
    memberships: HashMap<IpAddr, GroupMembership>,
    group_keys: HashMap<usize, GroupKey>,
}

impl ReplacementSummaries {
    pub(super) fn drain(&mut self, cx: &mut Context<'_>) -> usize {
        let mut received = 0;
        for _ in 0..QUERY_BUDGET_PER_CHUNK {
            let Poll::Ready(Some(query)) = super::poll_readiness_query(&mut self.rx, cx) else {
                break;
            };
            received += 1;
            if let Some(trace) = self.post_commit_query_trace.take() {
                trace.emit("summary");
            }
            match query {
                // The frozen view captured no stale counts.
                RibSummaryQuery::NeighborRibSnapshots {
                    peers,
                    comparison,
                    stale_counts: _,
                    include_retained,
                    reply,
                } => {
                    // The capture includes every retained peer, so its
                    // non-empty retention rows are the retained roster.
                    let retained_candidates = if include_retained {
                        self.view
                            .neighbors
                            .iter()
                            .filter(|(_, row)| !row.gr_retention.is_empty())
                            .map(|(peer, _)| *peer)
                            .collect()
                    } else {
                        std::collections::BTreeSet::new()
                    };
                    super::queries::send_neighbor_rib_snapshot(
                        reply,
                        peers,
                        comparison,
                        retained_candidates,
                        |peer| {
                            self.view.neighbors.get(&peer).cloned().unwrap_or_else(|| {
                                NeighborRibSnapshot {
                                    peer,
                                    advertised_count: 0,
                                    policy_stats: NeighborPolicyStats::default(),
                                    outbound: self.view.unknown_outbound.clone(),
                                    remote_asn: None,
                                    gr_retention: Vec::new(),
                                }
                            })
                        },
                        |primary, comparison| {
                            compare_update_groups(
                                &self.view.memberships,
                                primary,
                                comparison,
                                |id| self.view.group_keys.get(&id),
                            )
                        },
                    );
                }
            }
        }
        received
    }
}

impl RibManager {
    /// Install the bounded, type-narrow operator-summary receiver.
    #[must_use]
    pub fn with_summary_queries(mut self, rx: mpsc::Receiver<RibSummaryQuery>) -> Self {
        self.summary_rx = Some(rx);
        self
    }

    pub(super) fn serve_summary_query(&mut self, query: RibSummaryQuery) {
        if let Some(trace) = self.post_commit_query_trace.take() {
            trace.emit("summary");
        }
        self.handle_update(query.into());
    }

    pub(super) fn drain_summary_queries(&mut self) {
        for _ in 0..QUERY_BUDGET_PER_CHUNK {
            let query = match self.summary_rx.as_mut() {
                Some(rx) => match rx.try_recv() {
                    Ok(query) => query,
                    Err(mpsc::error::TryRecvError::Empty) => break,
                    Err(mpsc::error::TryRecvError::Disconnected) => {
                        self.summary_rx = None;
                        break;
                    }
                },
                None => break,
            };
            self.serve_summary_query(query);
        }
    }

    pub(super) async fn receive_summary_query(
        rx: &mut Option<mpsc::Receiver<RibSummaryQuery>>,
    ) -> Option<RibSummaryQuery> {
        match rx {
            Some(rx) => rx.recv().await,
            None => std::future::pending().await,
        }
    }

    /// Capture before the first mutation and reuse that view in nested helpers.
    /// The general queue stays fenced, including queries preceding a summary.
    pub(super) fn with_replacement_summary_reads<T>(
        &mut self,
        operation: &'static str,
        work: impl FnOnce(&mut Self) -> T,
    ) -> T {
        // A nested scope has already moved the receiver into the shared context.
        // Embedders without the new lane retain their original queue behavior.
        if self.summary_rx.is_none() {
            return self.with_replacement_readiness(work);
        }
        let run = || {
            self.with_replacement_readiness(|manager| {
            #[cfg(feature = "bench-internals")]
            tracing::info!(target: "replacement_summary", operation, phase = "enter", "replacement summary scope");
            let started = std::time::Instant::now();
            let view = manager.capture_replacement_summaries();
            let capture_us = started.elapsed().as_micros();
            let peer_count = view.neighbors.len();
            #[cfg(feature = "bench-internals")]
            tracing::info!(target: "replacement_summary", operation, phase = "captured", capture_us,
                peer_count, group_count = view.group_keys.len(), "replacement summary scope");
            let context = manager
                .replacement_readiness
                .as_ref()
                .expect("summary capture owns the replacement scope")
                .clone();
            context
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .summaries = Some(ReplacementSummaries {
                rx: manager
                    .summary_rx
                    .take()
                    .expect("outer summary scope owns the receiver"),
                post_commit_query_trace: manager.post_commit_query_trace.take(),
                view,
            });
            manager.replacement_checkpoint_at("summary_capture", true);
            let result = work(manager);
            manager.replacement_checkpoint_at("summary_terminal", true);
            let summaries = context
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .summaries
                .take()
                .expect("outer summary scope retains its view");
            manager.summary_rx = Some(summaries.rx);
            // A frozen dispatch consumes the pending trace. Otherwise return
            // it before retirement's current-state dispatch can consume it.
            manager.post_commit_query_trace = summaries.post_commit_query_trace;
            // Canonical state is complete now. Retire incrementally while fresh
            // summaries and readiness remain serviceable, without retaining a
            // second projection or exposing a partially destroyed old view.
            #[cfg(feature = "bench-internals")]
            tracing::info!(target: "replacement_summary", operation, phase = "retirement_begin", "replacement summary scope");
            let started = std::time::Instant::now();
            summaries.view.retire(&mut || {
                manager.replacement_checkpoint(false);
                manager.drain_summary_queries();
            });
            let retirement_us = started.elapsed().as_micros();
            tracing::debug!(target: "replacement_summary", operation, capture_us, retirement_us, peer_count,
                "replacement summary view retired");
            #[cfg(feature = "bench-internals")]
            tracing::info!(target: "replacement_summary", operation, phase = "exit", retirement_us,
                "replacement summary scope");
            result
        })
        };
        // A reply sent while this synchronous actor retains its worker can
        // strand the woken RPC in Tokio's non-stealable local scheduling slot.
        // Hand off the executor once, retaining exclusive canonical ownership.
        // Current-thread embedders keep their existing synchronous contract.
        super::with_executor_handoff(run)
    }

    fn capture_replacement_summaries(&self) -> SummaryProjection {
        let mut peers = HashSet::new();
        // Outbound registration covers mode/limit inputs. Other maps may outlive
        // it, and startup selection waiters may precede registration entirely.
        for peer in self
            .outbound_peers
            .keys()
            .chain(self.adj_ribs_out.keys())
            .chain(self.export_policy_stats.keys())
            .chain(self.update_groups.members.keys())
            // A peer in GR/LLGR retention may have no outbound registration
            // while its session is down; its retention row must survive.
            .chain(self.gr_peers.keys())
            .chain(self.llgr_peers.keys())
            .chain(self.llgr_stale_deadlines.keys().map(|(peer, _, _)| peer))
        {
            peers.insert(*peer);
            self.replacement_checkpoint(false);
        }
        if let Some(selection) = &self.selection_deferral {
            for peer in selection.snapshot_peers() {
                peers.insert(peer);
                self.replacement_checkpoint(false);
            }
        }
        let mut neighbors = HashMap::with_capacity(peers.len());
        for peer in peers {
            neighbors.insert(peer, self.neighbor_rib_snapshot(peer, false));
            self.replacement_checkpoint(false);
        }
        let unknown_outbound = PeerOutboundState {
            update_group: String::new(),
            effective_distribution_mode: EffectiveDistributionMode::Unknown,
            selection_deferral: self.selection_deferral.as_ref().map_or_else(
                Vec::new,
                super::selection_deferral::SelectionDeferral::unknown_peer_snapshot,
            ),
            outbound_prefix_limits: Vec::new(),
        };
        let mut memberships = HashMap::with_capacity(self.update_groups.members.len());
        let mut group_keys = HashMap::new();
        for (&peer, membership) in &self.update_groups.members {
            memberships.insert(peer, membership.clone());
            if let GroupMembership::Grouped(id) = membership
                && let Some(key) = self.update_groups.group_key(*id)
            {
                group_keys.entry(*id).or_insert_with(|| key.clone());
            }
            self.replacement_checkpoint(false);
        }
        SummaryProjection {
            neighbors,
            unknown_outbound,
            memberships,
            group_keys,
        }
    }
}

impl SummaryProjection {
    fn retire(mut self, checkpoint: &mut impl FnMut()) {
        for (_, mut row) in self.neighbors.drain() {
            super::retire_vec(&mut row.outbound.selection_deferral, checkpoint);
            super::retire_vec(&mut row.outbound.outbound_prefix_limits, checkpoint);
            drop(row);
            checkpoint();
        }
        for (_, key) in self.group_keys.drain() {
            drop(key);
            checkpoint();
        }
        // Memberships contain only scalar IDs/reasons; no policy or route owner
        // is retained by this projection.
        drop(self);
        checkpoint();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{SelectionDeferralConfig, SelectionDeferralWaiterConfig};
    use rustbgpd_telemetry::BgpMetrics;
    use rustbgpd_wire::{Afi, Safi};
    use tokio::sync::oneshot;

    #[test]
    fn replacement_summaries_transfer_post_commit_trace_once() {
        use super::super::{PostCommitQueryTrace, PostCommitWork};

        let (_tx, rx) = mpsc::channel(1);
        let (_general_tx, general_rx) = mpsc::channel(1);
        let (tx, summary_rx) = mpsc::channel(2);
        let mut manager = RibManager::new(rx, general_rx, None, None, BgpMetrics::new())
            .with_summary_queries(summary_rx);
        let since = std::time::Instant::now();
        let fresh_trace = || PostCommitQueryTrace {
            since,
            member_count: 1,
            terminal_poll: std::time::Duration::ZERO,
            queued_general_queries: 0,
            queued_summary_queries: 0,
            ingest_backlog: 0,
            busy: std::time::Duration::ZERO,
            route_chunks: 0,
            primary_updates: 0,
            resync_ticks: 0,
        };
        let enqueue = || {
            let (reply, response) = oneshot::channel();
            tx.try_send(RibSummaryQuery::NeighborRibSnapshots {
                peers: Vec::new(),
                comparison: None,
                reply,
                stale_counts: false,
                include_retained: false,
            })
            .unwrap();
            response
        };
        let pending_in_scope = |manager: &RibManager| {
            manager
                .replacement_readiness
                .as_ref()
                .unwrap()
                .state
                .lock()
                .unwrap()
                .summaries
                .as_ref()
                .unwrap()
                .post_commit_query_trace
                .is_some()
        };

        manager.post_commit_query_trace = Some(fresh_trace());
        manager.traced(PostCommitWork::PrimaryUpdate, |manager| {
            manager.with_replacement_summary_reads("restore", |manager| {
                assert!(manager.post_commit_query_trace.is_none());
                assert!(pending_in_scope(manager));
            });
        });
        let trace = manager.post_commit_query_trace.as_ref().unwrap();
        assert_eq!(trace.since, since, "a no-query scope preserves the trace");
        assert_eq!(trace.primary_updates, 1, "completed owner work is counted");
        let mut response = enqueue();
        manager.drain_summary_queries();
        assert_eq!(response.try_recv().unwrap().snapshots.len(), 0);
        assert!(manager.post_commit_query_trace.is_none());

        // Exercise the first checkpoint after capture and an interior one.
        for queued_before_capture in [true, false] {
            manager.post_commit_query_trace = Some(fresh_trace());
            let queued = queued_before_capture.then(enqueue);
            manager.traced(PostCommitWork::PrimaryUpdate, |manager| {
                manager.with_replacement_summary_reads("restore", |manager| {
                    assert!(manager.post_commit_query_trace.is_none());
                    assert_eq!(pending_in_scope(manager), !queued_before_capture);
                    let mut response = queued.unwrap_or_else(enqueue);
                    manager.replacement_checkpoint(true);
                    assert_eq!(response.try_recv().unwrap().snapshots.len(), 0);
                    assert!(!pending_in_scope(manager));
                    let mut second = enqueue();
                    manager.replacement_checkpoint(true);
                    assert_eq!(second.try_recv().unwrap().snapshots.len(), 0);
                    assert!(!pending_in_scope(manager), "the trace stays consumed");
                });
            });
            assert!(
                manager.post_commit_query_trace.is_none(),
                "the unfinished owner cannot rearm a consumed trace at completion"
            );
        }
    }

    #[tokio::test(start_paused = true)]
    async fn replacement_summaries_preserve_unknown_roster_and_cancellation() {
        let unknown: IpAddr = "192.0.2.3".parse().unwrap();
        let waiter: IpAddr = "192.0.2.4".parse().unwrap();
        let (_tx, rx) = mpsc::channel(1);
        let (_general_tx, general_rx) = mpsc::channel(1);
        let (tx, rx_summary) = mpsc::channel(16);
        let mut manager = RibManager::new(rx, general_rx, None, None, BgpMetrics::new())
            .with_summary_queries(rx_summary)
            .with_selection_deferral(SelectionDeferralConfig {
                timeout: std::time::Duration::from_secs(30),
                waiters: vec![SelectionDeferralWaiterConfig {
                    peer: waiter,
                    families: vec![(Afi::Ipv4, Safi::Unicast)],
                }],
            });
        let expected_neighbors =
            [unknown, waiter, unknown].map(|peer| manager.neighbor_rib_snapshot(peer, false));
        manager.with_replacement_summary_reads("restore", |manager| {
            // Mutating these canonical inputs cannot change the captured values.
            manager.selection_deferral = None;
            let (reply, mut response) = oneshot::channel();
            tx.try_send(RibSummaryQuery::NeighborRibSnapshots {
                peers: vec![unknown, waiter, unknown],
                comparison: Some((unknown, waiter)),
                reply,
                stale_counts: false,
                include_retained: false,
            })
            .unwrap();
            let (canceled_reply, canceled_response) = oneshot::channel();
            drop(canceled_response);
            tx.try_send(RibSummaryQuery::NeighborRibSnapshots {
                peers: vec![unknown],
                comparison: None,
                reply: canceled_reply,
                stale_counts: false,
                include_retained: false,
            })
            .unwrap();
            manager.with_replacement_summary_reads("apply", |manager| {
                manager.replacement_checkpoint(true);
            });
            let response = response.try_recv().unwrap();
            assert_eq!(response.snapshots, expected_neighbors);
            assert_eq!(
                response.comparison.unwrap().verdict,
                crate::UpdateGroupComparisonVerdict::Unknown
            );
            assert_eq!(tx.capacity(), 16);
        });
        let (reply, mut response) = oneshot::channel();
        tx.try_send(RibSummaryQuery::NeighborRibSnapshots {
            peers: Vec::new(),
            comparison: None,
            reply,
            stale_counts: false,
            include_retained: false,
        })
        .unwrap();
        manager.drain_summary_queries();
        assert!(
            response.try_recv().unwrap().snapshots.is_empty(),
            "terminal queries use current values"
        );
        assert!(manager.replacement_readiness.is_none());
        assert!(manager.summary_rx.is_some());
    }

    #[test]
    fn replacement_readiness_idle_dispatch_does_not_lock_owner() {
        use std::sync::Arc;
        use std::time::Duration;

        let (_tx, rx) = mpsc::channel(1);
        let (_general_tx, general_rx) = mpsc::channel(1);
        let (_readiness_tx, readiness_rx) = mpsc::channel(1);
        let (_summary_tx, summary_rx) = mpsc::channel(1);
        let mut manager = RibManager::new(rx, general_rx, None, None, BgpMetrics::new())
            .with_readiness_queries(readiness_rx)
            .with_summary_queries(summary_rx);
        manager.with_replacement_summary_reads("apply", |manager| {
            let context = Arc::clone(manager.replacement_readiness.as_ref().unwrap());
            let guard = context.state.lock().unwrap();
            std::thread::scope(|scope| {
                let (done, completed) = std::sync::mpsc::channel();
                let context = &context;
                let worker = scope.spawn(move || {
                    // This is the production dispatch, without test-only gap
                    // instrumentation, while the owner mutex is held elsewhere.
                    super::super::service_replacement_readiness(context, false);
                    done.send(()).unwrap();
                });
                let result = completed.recv_timeout(Duration::from_secs(1));
                // Release and join even for the deliberately broken control.
                drop(guard);
                worker.join().unwrap();
                result.expect("idle dispatch must finish before the owner mutex is released");
            });
        });
    }

    #[tokio::test(start_paused = true)]
    async fn replacement_readiness_retains_enqueue_after_lane_empty_poll() {
        use std::future::Future;
        use std::sync::{Arc, Mutex};
        use std::task::{Wake, Waker};

        use crate::{RibReadinessError, RibReadinessQuery};

        struct EnqueueReadiness {
            tx: mpsc::Sender<RibReadinessQuery>,
            reply: Mutex<Option<oneshot::Sender<Result<usize, RibReadinessError>>>>,
        }
        impl Wake for EnqueueReadiness {
            fn wake(self: Arc<Self>) {
                self.wake_by_ref();
            }

            fn wake_by_ref(self: &Arc<Self>) {
                if let Some(reply) = self.reply.lock().unwrap().take() {
                    self.tx
                        .try_send(RibReadinessQuery::LocRibCount {
                            reply,
                            enqueued: std::time::Instant::now(),
                        })
                        .unwrap();
                }
            }
        }

        let (_tx, rx) = mpsc::channel(1);
        let (_general_tx, general_rx) = mpsc::channel(1);
        let (readiness_tx, readiness_rx) = mpsc::channel(1);
        let (summary_tx, summary_rx) = mpsc::channel(1);
        let mut manager = RibManager::new(rx, general_rx, None, None, BgpMetrics::new())
            .with_readiness_queries(readiness_rx)
            .with_summary_queries(summary_rx);
        let budget = std::time::Duration::from_millis(25);
        manager.with_replacement_summary_reads("apply", |manager| {
            let context = manager.replacement_readiness.as_ref().unwrap().clone();
            let (reply, mut readiness_response) = oneshot::channel();
            let waker = Waker::from(Arc::new(EnqueueReadiness {
                tx: readiness_tx,
                reply: Mutex::new(Some(reply)),
            }));
            let mut cx = Context::from_waker(&waker);
            let (reply, mut summary_response) = oneshot::channel();
            assert!(
                std::pin::Pin::new(&mut summary_response)
                    .poll(&mut cx)
                    .is_pending()
            );
            summary_tx
                .try_send(RibSummaryQuery::NeighborRibSnapshots {
                    peers: Vec::new(),
                    comparison: None,
                    reply,
                    stale_counts: false,
                    include_retained: false,
                })
                .unwrap();
            context.state.lock().unwrap().last_service -= budget;
            // Readiness first polls empty. Sending the summary reply then
            // synchronously enqueues readiness through the registered waker.
            manager.replacement_checkpoint(false);
            assert!(summary_response.try_recv().is_ok());
            assert!(matches!(
                readiness_response.try_recv(),
                Err(oneshot::error::TryRecvError::Empty)
            ));
            manager.replacement_checkpoint(false);
            assert!(
                matches!(
                    readiness_response.try_recv(),
                    Err(oneshot::error::TryRecvError::Empty)
                ),
                "the wake does not bypass the existing service budget"
            );
            context.state.lock().unwrap().last_service -= budget;
            manager.replacement_checkpoint(false);
            assert_eq!(readiness_response.try_recv().unwrap(), Ok(0));
        });
    }

    #[tokio::test(start_paused = true)]
    async fn replacement_readiness_wake_caps_drain_without_tokio_budget_throttling() {
        use std::future::Future;

        let (_tx, rx) = mpsc::channel(1);
        let (_general_tx, general_rx) = mpsc::channel(1);
        let (readiness_tx, readiness_rx) = mpsc::channel(QUERY_BUDGET_PER_CHUNK + 1);
        let (summary_tx, summary_rx) = mpsc::channel(QUERY_BUDGET_PER_CHUNK + 1);
        let mut manager = RibManager::new(rx, general_rx, None, None, BgpMetrics::new())
            .with_readiness_queries(readiness_rx)
            .with_summary_queries(summary_rx);
        let budget = std::time::Duration::from_millis(25);
        std::future::poll_fn(|cx| {
            // Establish an exhausted cooperative budget without yielding or
            // sleeping. Readiness still owes its existing eight-query pass.
            for _ in 0..1024 {
                if std::pin::pin!(tokio::task::consume_budget())
                    .poll(cx)
                    .is_pending()
                {
                    break;
                }
            }
            assert!(!tokio::task::coop::has_budget_remaining());
            manager.with_replacement_summary_reads("apply", |manager| {
                let context = manager.replacement_readiness.as_ref().unwrap().clone();
                let mut counts = Vec::new();
                let mut snapshots = Vec::new();
                for _ in 0..=QUERY_BUDGET_PER_CHUNK {
                    let (reply, response) = oneshot::channel();
                    readiness_tx
                        .try_send(crate::RibReadinessQuery::LocRibCount {
                            reply,
                            enqueued: std::time::Instant::now(),
                        })
                        .unwrap();
                    counts.push(response);
                    let (reply, response) = oneshot::channel();
                    summary_tx
                        .try_send(RibSummaryQuery::NeighborRibSnapshots {
                            peers: Vec::new(),
                            comparison: None,
                            reply,
                            stale_counts: false,
                            include_retained: false,
                        })
                        .unwrap();
                    snapshots.push(response);
                }
                // Canceled replies still occupy and release their queued slot.
                drop(counts.remove(0));
                drop(snapshots.remove(0));
                context.state.lock().unwrap().last_service -= budget;
                manager.replacement_checkpoint(false);
                for response in &mut counts[..QUERY_BUDGET_PER_CHUNK - 1] {
                    assert_eq!(response.try_recv().unwrap(), Ok(0));
                }
                for response in &mut snapshots[..QUERY_BUDGET_PER_CHUNK - 1] {
                    assert!(response.try_recv().is_ok());
                }
                assert!(matches!(
                    counts.last_mut().unwrap().try_recv(),
                    Err(oneshot::error::TryRecvError::Empty)
                ));
                assert!(matches!(
                    snapshots.last_mut().unwrap().try_recv(),
                    Err(oneshot::error::TryRecvError::Empty)
                ));
                context.state.lock().unwrap().last_service -= budget;
                manager.replacement_checkpoint(false);
                assert_eq!(counts.last_mut().unwrap().try_recv().unwrap(), Ok(0));
                assert!(snapshots.last_mut().unwrap().try_recv().is_ok());
                assert_eq!(readiness_tx.capacity(), QUERY_BUDGET_PER_CHUNK + 1);
                assert_eq!(summary_tx.capacity(), QUERY_BUDGET_PER_CHUNK + 1);
                assert!(!tokio::task::coop::has_budget_remaining());
            });
            Poll::Ready(())
        })
        .await;
    }

    #[tokio::test(start_paused = true)]
    async fn replacement_readiness_wake_enqueues_inside_owner_and_restores_actor_wakers() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::task::{Wake, Waker};

        struct ActorWake(AtomicUsize);
        impl Wake for ActorWake {
            fn wake(self: Arc<Self>) {
                self.0.fetch_add(1, Ordering::Relaxed);
            }
        }

        let (_tx, rx) = mpsc::channel(1);
        let (_general_tx, general_rx) = mpsc::channel(1);
        let (readiness_tx, readiness_rx) = mpsc::channel(1);
        let (summary_tx, summary_rx) = mpsc::channel(1);
        let mut manager = RibManager::new(rx, general_rx, None, None, BgpMetrics::new())
            .with_readiness_queries(readiness_rx)
            .with_summary_queries(summary_rx);
        let enqueue = || {
            let (reply, count) = oneshot::channel();
            readiness_tx
                .try_send(crate::RibReadinessQuery::LocRibCount {
                    reply,
                    enqueued: std::time::Instant::now(),
                })
                .unwrap();
            let (reply, snapshot) = oneshot::channel();
            summary_tx
                .try_send(RibSummaryQuery::NeighborRibSnapshots {
                    peers: Vec::new(),
                    comparison: None,
                    reply,
                    stale_counts: false,
                    include_retained: false,
                })
                .unwrap();
            (count, snapshot)
        };
        let retired = manager.with_replacement_summary_reads("apply", |manager| {
            let context = manager.replacement_readiness.as_ref().unwrap().clone();
            std::thread::scope(|scope| {
                let (begin, ready) = std::sync::mpsc::channel();
                let worker = scope.spawn(move || {
                    ready.recv().unwrap();
                    enqueue()
                });
                // Both empty receivers are registered by the owner's forced
                // entry. Only after this idle checkpoint may the sender run.
                manager.replacement_checkpoint(false);
                begin.send(()).unwrap();
                let (mut count, mut snapshot) = worker.join().unwrap();
                context.state.lock().unwrap().last_service -= std::time::Duration::from_millis(25);
                manager.replacement_checkpoint(false);
                assert_eq!(count.try_recv().unwrap(), Ok(0));
                assert!(snapshot.try_recv().is_ok());
            });
            Arc::downgrade(&context)
        });
        assert!(
            retired.upgrade().is_none(),
            "receiver wakers must not retain their owner"
        );

        // Back in the ordinary actor, poll both returned receivers with the
        // actor's waker. New messages must wake that actor and remain FIFO.
        let actor = Arc::new(ActorWake(AtomicUsize::new(0)));
        let waker = Waker::from(Arc::clone(&actor));
        let mut cx = Context::from_waker(&waker);
        assert!(
            manager
                .readiness_rx
                .as_mut()
                .unwrap()
                .poll_recv(&mut cx)
                .is_pending()
        );
        assert!(
            manager
                .summary_rx
                .as_mut()
                .unwrap()
                .poll_recv(&mut cx)
                .is_pending()
        );
        let (mut count, mut snapshot) = enqueue();
        assert_eq!(actor.0.load(Ordering::Relaxed), 2);
        manager.drain_readiness_queries(None);
        manager.drain_summary_queries();
        assert_eq!(count.try_recv().unwrap(), Ok(0));
        assert!(snapshot.try_recv().is_ok());
        drop(readiness_tx);
        drop(summary_tx);
        manager.drain_readiness_queries(None);
        manager.drain_summary_queries();
        assert!(manager.readiness_rx.is_none());
        assert!(manager.summary_rx.is_none());
    }

    /// Unforced checkpoints skip the clock while both lanes are empty. A query
    /// queued during that idle staging must still be served by the next
    /// unforced checkpoint once the budget has passed, on either lane.
    #[test]
    fn replacement_readiness_idle_checkpoints_still_serve_queued_queries() {
        let (_tx, rx) = mpsc::channel(1);
        let (_general_tx, general_rx) = mpsc::channel(1);
        let (summary_tx, summary_rx) = mpsc::channel(2);
        let (readiness_tx, readiness_rx) = mpsc::channel(2);
        let mut manager = RibManager::new(rx, general_rx, None, None, BgpMetrics::new())
            .with_summary_queries(summary_rx);
        manager.readiness_rx = Some(readiness_rx);
        let budget = std::time::Duration::from_millis(10);
        manager.flush_poll_budget = budget;
        let readiness = || {
            let (reply, response) = oneshot::channel();
            readiness_tx
                .try_send(crate::update::RibReadinessQuery::LocRibCount {
                    reply,
                    enqueued: std::time::Instant::now(),
                })
                .unwrap();
            response
        };
        let summary = || {
            let (reply, response) = oneshot::channel();
            summary_tx
                .try_send(RibSummaryQuery::NeighborRibSnapshots {
                    peers: Vec::new(),
                    comparison: None,
                    reply,
                    stale_counts: false,
                    include_retained: false,
                })
                .unwrap();
            response
        };
        manager.with_replacement_summary_reads("apply", |manager| {
            for queue in [0, 1] {
                // Idle staging past the budget, then one queued query: the
                // first unforced checkpoint serves it.
                let idle = std::time::Instant::now();
                while idle.elapsed() < budget * 2 {
                    manager.replacement_checkpoint(false);
                }
                let (mut count, mut snapshot) = (None, None);
                if queue == 0 {
                    count = Some(readiness());
                } else {
                    snapshot = Some(summary());
                }
                manager.replacement_checkpoint(false);
                if let Some(count) = count.as_mut() {
                    assert_eq!(count.try_recv().unwrap(), Ok(0));
                }
                if let Some(snapshot) = snapshot.as_mut() {
                    assert_eq!(snapshot.try_recv().unwrap().snapshots.len(), 0);
                }

                // Queued right after a pass: any checkpoint starting a full
                // budget after that pass must serve it.
                let served = std::time::Instant::now();
                let mut count = readiness();
                let mut snapshot = summary();
                loop {
                    let started = std::time::Instant::now();
                    manager.replacement_checkpoint(false);
                    let answered = count.try_recv().is_ok();
                    assert_eq!(answered, snapshot.try_recv().is_ok());
                    if answered {
                        break;
                    }
                    assert!(
                        started.duration_since(served) < budget,
                        "an unforced checkpoint past the budget left a query queued"
                    );
                }
            }
        });
        let receipt = &manager.replacement_readiness_receipts[0];
        assert_eq!(receipt.serviced, 3, "readiness queries only");
        assert!(
            receipt.max_gap >= budget,
            "a wait after a pass spans the budget"
        );
    }

    /// The gap receipt counts a checkpoint only when service is eligible. With
    /// an idle opportunity at 25 ms and a service pass at 30 ms, a checkpoint
    /// at 50 ms is not an opportunity; the one at 60 ms records the 30 ms gap
    /// a query queued at 50 ms actually waited. The clock is paused and time
    /// is simulated by moving the recorded instants back, so no step sleeps
    /// and host scheduling cannot carry a checkpoint across the budget.
    #[tokio::test(start_paused = true)]
    async fn replacement_readiness_gap_receipt_follows_service_eligibility() {
        let (_tx, rx) = mpsc::channel(1);
        let (_general_tx, general_rx) = mpsc::channel(1);
        let (readiness_tx, readiness_rx) = mpsc::channel(2);
        let mut manager = RibManager::new(rx, general_rx, None, None, BgpMetrics::new());
        manager.readiness_rx = Some(readiness_rx);
        let ms = std::time::Duration::from_millis;
        manager.flush_poll_budget = ms(25);
        let queue = || {
            let (reply, response) = oneshot::channel();
            readiness_tx
                .try_send(crate::update::RibReadinessQuery::LocRibCount {
                    reply,
                    enqueued: std::time::Instant::now(),
                })
                .unwrap();
            response
        };
        manager.with_replacement_readiness(|manager| {
            let context = manager.replacement_readiness.clone().unwrap();
            let advance = |by: std::time::Duration| {
                let mut readiness = context.state.lock().unwrap();
                readiness.last_service = readiness.last_service.checked_sub(by).unwrap();
                readiness.last_opportunity = readiness.last_opportunity.checked_sub(by).unwrap();
            };
            let max_gap = || context.state.lock().unwrap().max_gap;
            // t=0 is the scope's forced entry checkpoint.
            context.state.lock().unwrap().max_gap = std::time::Duration::ZERO;

            advance(ms(25));
            manager.replacement_checkpoint(false);
            assert!(
                max_gap() >= ms(25),
                "the idle checkpoint at 25 ms is an opportunity"
            );

            advance(ms(5));
            let mut first = queue();
            manager.replacement_checkpoint(false);
            assert_eq!(first.try_recv().unwrap(), Ok(0), "served at 30 ms");

            advance(ms(20));
            let mut second = queue();
            manager.replacement_checkpoint(false);
            assert!(
                matches!(second.try_recv(), Err(oneshot::error::TryRecvError::Empty)),
                "50 ms is within the budget of the 30 ms pass"
            );

            advance(ms(10));
            manager.replacement_checkpoint(false);
            assert_eq!(second.try_recv().unwrap(), Ok(0), "served at 60 ms");
            assert!(
                max_gap() >= ms(30),
                "the receipt spans 30 ms to 60 ms, not 50 ms to 60 ms"
            );
        });
    }

    #[test]
    fn replacement_summaries_drain_only_the_bounded_lane_budget() {
        let (_tx, rx) = mpsc::channel(1);
        let (_general_tx, general_rx) = mpsc::channel(1);
        let (tx, summary_rx) = mpsc::channel(QUERY_BUDGET_PER_CHUNK + 1);
        let mut manager = RibManager::new(rx, general_rx, None, None, BgpMetrics::new())
            .with_summary_queries(summary_rx);
        manager.with_replacement_summary_reads("apply", |manager| {
            let mut replies = Vec::new();
            for _ in 0..=QUERY_BUDGET_PER_CHUNK {
                let (reply, response) = oneshot::channel();
                tx.try_send(RibSummaryQuery::NeighborRibSnapshots {
                    peers: Vec::new(),
                    comparison: None,
                    reply,
                    stale_counts: false,
                    include_retained: false,
                })
                .unwrap();
                replies.push(response);
            }
            manager.replacement_checkpoint(true);
            for response in replies.iter_mut().take(QUERY_BUDGET_PER_CHUNK) {
                assert_eq!(response.try_recv().unwrap().snapshots.len(), 0);
            }
            assert!(matches!(
                replies.last_mut().unwrap().try_recv(),
                Err(oneshot::error::TryRecvError::Empty)
            ));
            manager.replacement_checkpoint(true);
            assert_eq!(
                replies
                    .last_mut()
                    .unwrap()
                    .try_recv()
                    .unwrap()
                    .snapshots
                    .len(),
                0
            );
        });
    }
}
