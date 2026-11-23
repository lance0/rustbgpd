//! Operator reads during real synchronous single-mover commands.

use super::*;
use crate::update::RibSummaryQuery;

#[test]
fn distinct_chain_summary_rows_are_flat_per_command() {
    let counts = [8, 32, 128].map(|size| {
        let (mut manager, mut members, expected, _) = fixture(size);
        let (_summary_tx, summary_rx) = mpsc::channel(1);
        manager.summary_rx = Some(summary_rx);
        let rows = Arc::new(AtomicUsize::new(0));
        manager.replacement_readiness_test_hook = Some(Arc::new({
            let rows = Arc::clone(&rows);
            move |stage| {
                if stage == "summary_neighbor_row" {
                    rows.fetch_add(1, Ordering::Relaxed);
                }
            }
        }));
        [false, true].map(|restore| {
            let mut counts = Vec::new();
            for (member, expected) in members.iter_mut().zip(&expected) {
                let tag = if restore {
                    member.old_tag
                } else {
                    member.new_tag
                };
                replace(&mut manager, peer_v4(member.addr), tag, restore);
                counts.push(rows.swap(0, Ordering::Relaxed));
                let mut advertised = Inventory::new();
                drain_inventory(&mut member.output, tag, &mut advertised);
                assert_eq!(&advertised, expected);
            }
            (
                *counts.iter().min().unwrap(),
                *counts.iter().max().unwrap(),
                counts.iter().sum::<usize>(),
            )
        })
    });
    assert_eq!(counts, [[(1, 1, 8); 2], [(1, 1, 32); 2], [(1, 1, 128); 2]]);
}

/// Make an occupied source and destination plus an unrelated singleton.
/// A restore returns to a destination the mover previously occupied.
fn occupied_groups(restore: bool) -> (RibManager, [Member; 4]) {
    let (mut manager, members, expected, _) = fixture(4);
    let mut members: [Member; 4] = members
        .try_into()
        .unwrap_or_else(|_| unreachable!("four-peer fixture"));
    let ids = members.each_ref().map(|member| peer_v4(member.addr));
    let source_tag = members[1].old_tag;
    let destination_tag = members[2].old_tag;
    let mut move_to = |tag| {
        replace(&mut manager, ids[0], tag, false);
        let mut advertised = Inventory::new();
        drain_inventory(&mut members[0].output, tag, &mut advertised);
        assert_eq!(advertised, expected[0]);
    };
    if restore {
        move_to(destination_tag);
    }
    move_to(source_tag);
    let [mover, survivor, incumbent, outside] = ids;
    for (peer, roster) in [
        (mover, HashSet::from([mover, survivor])),
        (incumbent, HashSet::from([incumbent])),
        (outside, HashSet::from([outside])),
    ] {
        assert_eq!(
            manager.group_ribs[&manager.grouped_member_of(peer).unwrap()].members,
            roster
        );
    }
    (manager, members)
}

fn assert_scoped_writers(restore: bool) {
    let (mut manager, members) = occupied_groups(restore);
    let requested = members.each_ref().map(|member| peer_v4(member.addr));
    let [mover, _, incumbent, outside] = requested;
    let destination_tag = members[2].old_tag;
    let mut expected = requested.map(|peer| manager.neighbor_rib_snapshot(peer));
    assert!(
        expected
            .iter()
            .all(|row| !row.outbound_resync.advertised_count_pending)
    );
    expected[3].outbound_resync.advertised_count_pending = true;
    let expected_outside = expected[3].clone();
    let (summary_tx, summary_rx) = mpsc::channel(1);
    manager.summary_rx = Some(summary_rx);
    manager.flush_poll_budget = std::time::Duration::ZERO;
    let (reply, response) = oneshot::channel();
    let receivers = Mutex::new(Some((members, reply)));
    let response = Mutex::new(Some(response));
    let observed = Arc::new(AtomicBool::new(false));
    manager.replacement_readiness_test_hook = Some(Arc::new({
        let observed = Arc::clone(&observed);
        move |stage| {
            if stage != "shared_inventory" {
                return;
            }
            if let Some((members, reply)) = receivers.lock().unwrap().take() {
                // Closing the four real writers at one forced interleaving
                // distinguishes each row's source before any actor mutation.
                drop(members);
                summary_tx
                    .try_send(RibSummaryQuery::NeighborRibSnapshots {
                        peers: requested.to_vec(),
                        comparison: None,
                        include_retained: false,
                        reply,
                    })
                    .unwrap();
            } else if let Some(mut response) = response.lock().unwrap().take() {
                let rows = response
                    .try_recv()
                    .expect("served during shared inventory")
                    .snapshots;
                assert_eq!(
                    rows, expected,
                    "mover and both groups frozen, outside peer live"
                );
                observed.store(true, Ordering::Relaxed);
            }
        }
    }));
    replace(&mut manager, mover, destination_tag, restore);
    assert!(
        observed.load(Ordering::Relaxed),
        "must reach the interior assertion"
    );
    assert_eq!(
        manager.grouped_member_of(mover),
        manager.grouped_member_of(incumbent)
    );
    assert_eq!(manager.neighbor_rib_snapshot(outside), expected_outside);
    assert!(
        manager
            .neighbor_rib_snapshot(mover)
            .outbound_resync
            .advertised_count_pending
    );
}

#[test]
fn apply_freezes_mover_and_both_groups_while_unrelated_writer_is_live() {
    assert_scoped_writers(false);
}

#[test]
fn restore_freezes_mover_and_both_groups_while_unrelated_writer_is_live() {
    assert_scoped_writers(true);
}

#[test]
fn terminal_comparisons_use_consistent_memberships_and_group_keys() {
    let (mut manager, members) = occupied_groups(false);
    let [mover, survivor, incumbent, outside] =
        members.each_ref().map(|member| peer_v4(member.addr));
    let pairs = [
        (mover, survivor),
        (mover, incumbent),
        (mover, outside),
        (outside, mover),
    ];
    let before = pairs.map(|(left, right)| manager.update_group_comparison(left, right));
    let (summary_tx, summary_rx) = mpsc::channel(pairs.len());
    manager.summary_rx = Some(summary_rx);
    let (requests, mut responses): (Vec<_>, Vec<_>) = pairs
        .into_iter()
        .map(|(left, right)| {
            let (reply, response) = oneshot::channel();
            (
                RibSummaryQuery::NeighborRibSnapshots {
                    peers: vec![left],
                    comparison: Some((left, right)),
                    include_retained: false,
                    reply,
                },
                response,
            )
        })
        .unzip();
    let requests = Mutex::new(requests);
    manager.replacement_readiness_test_hook = Some(Arc::new(move |stage| {
        if stage == "summary_terminal" {
            for request in requests.lock().unwrap().drain(..) {
                summary_tx.try_send(request).unwrap();
            }
        }
    }));
    replace(&mut manager, mover, members[2].old_tag, false);
    let after = pairs.map(|(left, right)| manager.update_group_comparison(left, right));
    assert_ne!(before[0], after[0], "mover leaves survivor");
    assert_ne!(before[1], after[1], "mover joins incumbent");
    for (index, response) in responses.iter_mut().enumerate() {
        let reply = response
            .try_recv()
            .expect("terminal checkpoint served comparison");
        let comparison = reply.comparison.unwrap();
        assert_eq!(
            reply.snapshots[0].outbound.update_group,
            before[index].primary_update_group
        );
        if index < 2 {
            assert_eq!(
                comparison, before[index],
                "both peers belong to affected groups"
            );
        } else {
            assert_eq!(
                comparison, after[index],
                "mixed comparisons read both live operands"
            );
            if index == 2 {
                assert_ne!(
                    comparison.primary_update_group, before[index].primary_update_group,
                    "mover changed its group after capture"
                );
            }
        }
    }
}

fn assert_unrelated_read_between_rows(
    manager: &mut RibManager,
    peer: PeerId,
    output: mpsc::Receiver<OutboundRouteUpdate>,
    stage_name: &'static str,
    command: impl FnOnce(&mut RibManager),
) {
    let mut expected = manager.neighbor_rib_snapshot(peer);
    assert!(!expected.outbound_resync.advertised_count_pending);
    expected.outbound_resync.advertised_count_pending = true;
    manager.flush_poll_budget = std::time::Duration::ZERO;
    let (tx, rx) = mpsc::channel(1);
    manager.summary_rx = Some(rx);
    let (reply, response) = oneshot::channel();
    let request = Mutex::new(Some((
        output,
        RibSummaryQuery::NeighborRibSnapshots {
            peers: vec![peer],
            comparison: None,
            include_retained: false,
            reply,
        },
    )));
    let response = Mutex::new(Some(response));
    let seen = Arc::new(AtomicBool::new(false));
    manager.replacement_readiness_test_hook = Some(Arc::new({
        let seen = Arc::clone(&seen);
        move |stage| {
            if stage != stage_name {
                return;
            }
            if let Some((output, query)) = request.lock().unwrap().take() {
                drop(output);
                tx.try_send(query).unwrap();
            } else if let Some(mut response) = response.lock().unwrap().take() {
                let rows = response
                    .try_recv()
                    .expect("served before the next row")
                    .snapshots;
                assert_eq!(rows.as_slice(), std::slice::from_ref(&expected));
                seen.store(true, Ordering::Relaxed);
            }
        }
    }));
    command(manager);
    assert!(seen.load(Ordering::Relaxed), "{stage_name} was exercised");
}

/// A table commit holds the destination group mutably over its delta walk.
#[test]
fn cold_table_commit_serves_unrelated_peer_between_deltas() {
    let (mut manager, mut members, _, _) = fixture(2);
    let outside = members.pop().unwrap();
    let mover = &members[0];
    assert_unrelated_read_between_rows(
        &mut manager,
        peer_v4(outside.addr),
        outside.output,
        "staged_table_commit",
        |manager| {
            replace(manager, peer_v4(mover.addr), mover.new_tag, false);
        },
    );
}

/// Paced regroup and rollback both rebuild the changed peer from the Loc-RIB.
#[test]
fn paced_policy_resync_serves_unrelated_peer_between_loc_rib_keys() {
    for restore in [false, true] {
        let (mut manager, mut members, expected, _) = fixture(2);
        let outside = members.pop().unwrap();
        let mover = &mut members[0];
        let id = peer_v4(mover.addr);
        let tag = if restore {
            replace(&mut manager, id, mover.new_tag, false);
            let mut advertised = Inventory::new();
            drain_inventory(&mut mover.output, mover.new_tag, &mut advertised);
            assert_eq!(advertised, expected[0]);
            mover.old_tag
        } else {
            mover.new_tag
        };
        assert_unrelated_read_between_rows(
            &mut manager,
            peer_v4(outside.addr),
            outside.output,
            "resync_loc_rib_key",
            |manager| {
                let replacements = batch_replacements(&[id], &community_chain(tag));
                let (reply, mut response) = oneshot::channel();
                manager.handle_update(if restore {
                    RibUpdate::RestorePacedExportPolicies {
                        replacements,
                        cost: None,
                        reply,
                    }
                } else {
                    RibUpdate::ApplyPacedExportPolicies {
                        replacements,
                        cost: None,
                        reply,
                    }
                });
                let result = response.try_recv().unwrap().unwrap();
                assert_eq!(result.applied, 1);
                assert!(result.pending.is_empty() && result.skipped.is_empty());
            },
        );
    }
}

#[test]
fn limited_paced_policy_resync_serves_unrelated_peer_during_verdict_and_commit() {
    for stage in ["outbound_limits", "outbound_limit_commit"] {
        let deny = PolicyChain::new(vec![Policy {
            entries: vec![],
            default_action: PolicyAction::Deny,
        }]);
        let mut fleet = replacement_readiness_fleet(&deny);
        let mover = fleet.members[0];
        let outside = *fleet.members.last().unwrap();
        replace(&mut fleet.manager, outside, 42, false);
        let mut output = fleet.receivers.pop().unwrap();
        assert_ne!(
            fleet.manager.grouped_member_of(mover),
            fleet.manager.grouped_member_of(outside)
        );
        for (peer, limit) in [(mover, 1), (outside, 2)] {
            for afi in [Afi::Ipv4, Afi::Ipv6] {
                fleet
                    .manager
                    .outbound_prefix_limits
                    .entry(peer)
                    .or_default()
                    .family_mut(afi)
                    .unwrap()
                    .limit = std::num::NonZeroU32::new(limit);
            }
        }
        let outside_limits = fleet
            .manager
            .outbound_prefix_limits
            .get_mut(&outside)
            .unwrap();
        while let Ok(update) = output.try_recv().map(delivered) {
            for route in &*update.announce {
                outside_limits.grouped_extend(prefix_family(&route.prefix).0, [route.prefix]);
            }
        }
        for afi in [Afi::Ipv4, Afi::Ipv6] {
            assert_eq!(outside_limits.grouped_len(afi), 2);
        }
        assert_unrelated_read_between_rows(&mut fleet.manager, outside, output, stage, |manager| {
            let (reply, mut response) = oneshot::channel();
            manager.handle_update(RibUpdate::ApplyPacedExportPolicies {
                replacements: batch_replacements(&[mover], &peer_context_chain()),
                cost: None,
                reply,
            });
            let result = response.try_recv().unwrap().unwrap();
            assert_eq!(result.applied, 1);
            assert!(result.pending.is_empty() && result.skipped.is_empty());
        });
        for afi in [Afi::Ipv4, Afi::Ipv6] {
            assert!(
                fleet.manager.outbound_prefix_limits[&mover]
                    .family(afi)
                    .unwrap()
                    .blocking
            );
        }
    }
}

/// Keep the receiver open while making every reservation fail.
fn hold_writer_capacity(
    manager: &RibManager,
    peer: PeerId,
) -> Vec<mpsc::OwnedPermit<OutboundRouteUpdate>> {
    let sender = &manager.outbound_peers[&peer];
    assert!(sender.capacity() > 0);
    (0..sender.capacity())
        .map(|_| sender.clone().try_reserve_owned().unwrap())
        .collect()
}

#[test]
fn failed_authoritative_prepare_serves_unrelated_peer_between_old_keys() {
    let (mut manager, mut members, _, _) = fixture(2);
    let outside = members.pop().unwrap();
    let mover = peer_v4(members[0].addr);
    let held = hold_writer_capacity(&manager, mover);
    let captures = manager.adj_rib_out_commit_stats.group_table_captures;
    assert_unrelated_read_between_rows(
        &mut manager,
        peer_v4(outside.addr),
        outside.output,
        "capture_old_peer_key",
        |manager| replace(manager, mover, members[0].new_tag, false),
    );
    let receipt = manager.authoritative_transition_receipts.last().unwrap();
    assert_eq!((receipt.emits_attempted, receipt.emits_degraded), (1, 1));
    assert_eq!(
        manager.adj_rib_out_commit_stats.group_table_captures,
        captures + 1
    );
    assert!(manager.dirty_peers.contains(&mover));
    drop(held);
}

#[test]
fn group_reevaluation_serves_unrelated_peer_between_shared_old_keys() {
    let (mut manager, [first, second, _incumbent, outside]) = occupied_groups(false);
    let affected = [peer_v4(first.addr), peer_v4(second.addr)];
    let held = affected.map(|peer| hold_writer_capacity(&manager, peer));
    let captures = manager.adj_rib_out_commit_stats.group_table_captures;
    assert_unrelated_read_between_rows(
        &mut manager,
        peer_v4(outside.addr),
        outside.output,
        "capture_old_cohort_key",
        |manager| {
            let (reply, mut response) = oneshot::channel();
            // A dataset change for one member re-evaluates its whole group.
            manager.handle_update(RibUpdate::ReevaluatePeerExportPolicies {
                peers: vec![affected[0]],
                swaps: None,
                reply,
            });
            assert_eq!(response.try_recv().unwrap(), Ok(()));
        },
    );
    assert_eq!(
        manager.adj_rib_out_commit_stats.group_table_captures,
        captures + 2
    );
    drop(held);
}

/// A dataset reevaluation freezes the reevaluated group's
/// members while an unrelated writer stays live.
#[test]
fn reevaluation_freezes_target_group_while_unrelated_writer_is_live() {
    let (mut manager, members) = occupied_groups(false);
    let [first, second, _incumbent, outside] = members;
    let requested = [&first, &second, &outside].map(|member| peer_v4(member.addr));
    let held = [requested[0], requested[1]].map(|peer| hold_writer_capacity(&manager, peer));
    let mut expected = requested.map(|peer| manager.neighbor_rib_snapshot(peer));
    assert!(
        expected
            .iter()
            .all(|row| !row.outbound_resync.advertised_count_pending)
    );
    expected[2].outbound_resync.advertised_count_pending = true;
    let (summary_tx, summary_rx) = mpsc::channel(1);
    manager.summary_rx = Some(summary_rx);
    manager.flush_poll_budget = std::time::Duration::ZERO;
    let (reply, response) = oneshot::channel();
    let writers = Mutex::new(Some(([first.output, second.output, outside.output], reply)));
    let response = Mutex::new(Some(response));
    let observed = Arc::new(AtomicBool::new(false));
    manager.replacement_readiness_test_hook = Some(Arc::new({
        let observed = Arc::clone(&observed);
        move |stage| {
            if stage != "capture_old_cohort_key" {
                return;
            }
            if let Some((outputs, reply)) = writers.lock().unwrap().take() {
                drop(outputs);
                summary_tx
                    .try_send(RibSummaryQuery::NeighborRibSnapshots {
                        peers: requested.to_vec(),
                        comparison: None,
                        include_retained: false,
                        reply,
                    })
                    .unwrap();
            } else if let Some(mut pending) = response.lock().unwrap().take() {
                let rows = pending
                    .try_recv()
                    .expect("served during reevaluation capture")
                    .snapshots;
                assert_eq!(
                    rows, expected,
                    "reevaluated group frozen, outside peer live"
                );
                observed.store(true, Ordering::Relaxed);
            }
        }
    }));
    let (reply, mut result) = oneshot::channel();
    manager.handle_update(RibUpdate::ReevaluatePeerExportPolicies {
        peers: vec![requested[0]],
        swaps: None,
        reply,
    });
    assert_eq!(result.try_recv().unwrap(), Ok(()));
    assert!(
        observed.load(Ordering::Relaxed),
        "must reach the interior assertion"
    );
    drop(held);
}
