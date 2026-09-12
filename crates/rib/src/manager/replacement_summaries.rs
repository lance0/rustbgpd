//! Temporary operator projections held only while synchronous replacement owns
//! canonical RIB state. These contain values, never routes or shared counters.

use super::update_groups::{GroupKey, GroupMembership, compare_update_groups};
use super::{QUERY_BUDGET_PER_CHUNK, RibManager};
use crate::update::{
    EffectiveDistributionMode, ExportPolicyTermHits, NeighborPolicyStats, NeighborRibSnapshot,
    PeerOutboundState, RibSummaryQuery,
};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::IpAddr;
use tokio::sync::mpsc;

pub(super) struct ReplacementSummaries {
    pub(super) rx: mpsc::Receiver<RibSummaryQuery>,
    post_commit_query_trace: Option<super::PostCommitQueryTrace>,
    view: SummaryProjection,
}

struct SummaryProjection {
    neighbors: HashMap<IpAddr, NeighborRibSnapshot>,
    unknown_outbound: PeerOutboundState,
    // An explicit None disables the global fallback for that peer.
    policies: BTreeMap<IpAddr, Option<ExportPolicyTermHits>>,
    global_policy: Option<ExportPolicyTermHits>,
    memberships: HashMap<IpAddr, GroupMembership>,
    group_keys: HashMap<usize, GroupKey>,
}

impl ReplacementSummaries {
    pub(super) fn drain(&mut self) {
        for _ in 0..QUERY_BUDGET_PER_CHUNK {
            let Ok(query) = self.rx.try_recv() else { break };
            if let Some(trace) = self.post_commit_query_trace.take() {
                trace.emit("summary");
            }
            match query {
                RibSummaryQuery::ExportPolicyTermHits { peer, reply } => {
                    if reply.is_closed() {
                        continue;
                    }
                    let mut rows = Vec::new();
                    if let Some(peer) = peer {
                        if let Some(mut row) = self
                            .view
                            .policies
                            .get(&peer)
                            .unwrap_or(&self.view.global_policy)
                            .clone()
                        {
                            row.peer = Some(peer);
                            rows.push(row);
                        }
                    } else {
                        for row in self.view.policies.values().flatten() {
                            if reply.is_closed() {
                                break;
                            }
                            rows.push(row.clone());
                        }
                        if let Some(row) = &self.view.global_policy {
                            rows.push(row.clone());
                        }
                    }
                    let _ = reply.send(rows);
                }
                RibSummaryQuery::NeighborRibSnapshots {
                    peers,
                    comparison,
                    reply,
                } => {
                    super::queries::send_neighbor_rib_snapshot(
                        reply,
                        peers,
                        comparison,
                        |peer| {
                            self.view.neighbors.get(&peer).cloned().unwrap_or_else(|| {
                                NeighborRibSnapshot {
                                    peer,
                                    advertised_count: 0,
                                    policy_stats: NeighborPolicyStats::default(),
                                    outbound: self.view.unknown_outbound.clone(),
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
                peer_count, policy_count = view.policies.len(), group_count = view.group_keys.len(),
                term_count = view.policies.values().flatten().chain(view.global_policy.iter()).map(|row| row.terms.len()).sum::<usize>(),
                "replacement summary scope");
            let context = manager
                .replacement_readiness
                .as_ref()
                .expect("summary capture owns the replacement scope")
                .clone();
            context
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
        if tokio::runtime::Handle::try_current().is_ok_and(|handle| {
            matches!(
                handle.runtime_flavor(),
                tokio::runtime::RuntimeFlavor::MultiThread
            )
        }) {
            tokio::task::block_in_place(run)
        } else {
            run()
        }
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
            neighbors.insert(peer, self.neighbor_rib_snapshot(peer));
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
        let mut policies = BTreeMap::new();
        for (&peer, chain) in &self.peer_export_policies {
            policies.insert(
                peer,
                chain
                    .as_ref()
                    .map(|chain| super::queries::snapshot_export_chain(Some(peer), chain)),
            );
            self.replacement_checkpoint(false);
        }
        let global_policy = self
            .export_policy
            .as_ref()
            .map(|chain| super::queries::snapshot_export_chain(None, chain));
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
            policies,
            global_policy,
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
        while let Some((_, row)) = self.policies.pop_first() {
            if let Some(mut row) = row {
                super::retire_vec(&mut row.terms, checkpoint);
            }
            checkpoint();
        }
        if let Some(mut row) = self.global_policy.take() {
            super::retire_vec(&mut row.terms, checkpoint);
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
    use rustbgpd_policy::{Policy, PolicyAction, PolicyChain};
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
            tx.try_send(RibSummaryQuery::ExportPolicyTermHits { peer: None, reply })
                .unwrap();
            response
        };
        let pending_in_scope = |manager: &RibManager| {
            manager
                .replacement_readiness
                .as_ref()
                .unwrap()
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
        assert!(response.try_recv().unwrap().is_empty());
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
                    assert!(response.try_recv().unwrap().is_empty());
                    assert!(!pending_in_scope(manager));
                    let mut second = enqueue();
                    manager.replacement_checkpoint(true);
                    assert!(second.try_recv().unwrap().is_empty());
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
    async fn replacement_summaries_preserve_fallback_unknown_roster_and_cancellation() {
        let known: IpAddr = "192.0.2.1".parse().unwrap();
        let disabled: IpAddr = "192.0.2.2".parse().unwrap();
        let unknown: IpAddr = "192.0.2.3".parse().unwrap();
        let waiter: IpAddr = "192.0.2.4".parse().unwrap();
        let chain = PolicyChain::new(vec![Policy {
            entries: vec![],
            default_action: PolicyAction::Permit,
        }]);
        let (_tx, rx) = mpsc::channel(1);
        let (_general_tx, general_rx) = mpsc::channel(1);
        let (tx, rx_summary) = mpsc::channel(16);
        let mut manager =
            RibManager::new(rx, general_rx, Some(chain.clone()), None, BgpMetrics::new())
                .with_summary_queries(rx_summary)
                .with_selection_deferral(SelectionDeferralConfig {
                    timeout: std::time::Duration::from_secs(30),
                    waiters: vec![SelectionDeferralWaiterConfig {
                        peer: waiter,
                        families: vec![(Afi::Ipv4, Safi::Unicast)],
                    }],
                });
        manager.peer_export_policies.insert(known, Some(chain));
        manager.peer_export_policies.insert(disabled, None);
        let expected_neighbors =
            [unknown, waiter, unknown].map(|peer| manager.neighbor_rib_snapshot(peer));
        let expected_all = format!("{:?}", manager.export_policy_term_hits(None));
        let expected_unknown = format!("{:?}", manager.export_policy_term_hits(Some(unknown)));
        manager.with_replacement_summary_reads("restore", |manager| {
            // Mutating these canonical inputs cannot change the captured values.
            manager.peer_export_policies.clear();
            manager.export_policy = None;
            manager.selection_deferral = None;
            let (reply, mut response) = oneshot::channel();
            tx.try_send(RibSummaryQuery::NeighborRibSnapshots {
                peers: vec![unknown, waiter, unknown],
                comparison: Some((unknown, waiter)),
                reply,
            })
            .unwrap();
            let (all_reply, mut all_response) = oneshot::channel();
            tx.try_send(RibSummaryQuery::ExportPolicyTermHits {
                peer: None,
                reply: all_reply,
            })
            .unwrap();
            let (fallback_reply, mut fallback_response) = oneshot::channel();
            tx.try_send(RibSummaryQuery::ExportPolicyTermHits {
                peer: Some(unknown),
                reply: fallback_reply,
            })
            .unwrap();
            let (disabled_reply, mut disabled_response) = oneshot::channel();
            tx.try_send(RibSummaryQuery::ExportPolicyTermHits {
                peer: Some(disabled),
                reply: disabled_reply,
            })
            .unwrap();
            let (canceled_reply, canceled_response) = oneshot::channel();
            drop(canceled_response);
            tx.try_send(RibSummaryQuery::NeighborRibSnapshots {
                peers: vec![unknown],
                comparison: None,
                reply: canceled_reply,
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
            assert_eq!(
                format!("{:?}", all_response.try_recv().unwrap()),
                expected_all
            );
            assert_eq!(
                format!("{:?}", fallback_response.try_recv().unwrap()),
                expected_unknown
            );
            assert!(disabled_response.try_recv().unwrap().is_empty());
            assert_eq!(tx.capacity(), 16);
        });
        let (reply, mut response) = oneshot::channel();
        tx.try_send(RibSummaryQuery::ExportPolicyTermHits { peer: None, reply })
            .unwrap();
        manager.drain_summary_queries();
        assert!(
            response.try_recv().unwrap().is_empty(),
            "terminal queries use current values"
        );
        assert!(manager.replacement_readiness.is_none());
        assert!(manager.summary_rx.is_some());
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
                tx.try_send(RibSummaryQuery::ExportPolicyTermHits { peer: None, reply })
                    .unwrap();
                replies.push(response);
            }
            manager.replacement_checkpoint(true);
            for response in replies.iter_mut().take(QUERY_BUDGET_PER_CHUNK) {
                assert!(response.try_recv().unwrap().is_empty());
            }
            assert!(matches!(
                replies.last_mut().unwrap().try_recv(),
                Err(oneshot::error::TryRecvError::Empty)
            ));
            manager.replacement_checkpoint(true);
            assert!(replies.last_mut().unwrap().try_recv().unwrap().is_empty());
        });
    }
}
