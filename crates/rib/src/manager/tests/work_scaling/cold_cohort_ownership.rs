//! An uncertain cold single-best inventory can commit, or retire with its table.

use super::*;
use crate::loc_rib::REGISTRATION_PAGE_SIZE;
use rustbgpd_policy::{NextHopAction, PolicyChain};

const OLD: u32 = 0xfc00_0311;
const NEW: u32 = 0xfc00_0322;
const MOVED: u32 = 0xfc00_0333;

fn tagged(tag: u32) -> PolicyChain {
    super::super::update_groups::community_chain(tag)
}

fn next_hop_policy(tag: u32) -> PolicyChain {
    let mut policy = tagged(tag);
    policy.policies[0].policy.entries[0]
        .modifications
        .set_next_hop = Some(NextHopAction::Self_);
    policy
}

// All routes gain NEW, except the last prefix, which retains its exact OLD
// attributes and differs only in its next-hop action. The latter is a real
// batched-inventory refusal, independent of encoder or channel availability.
fn late_refusal(last: Prefix) -> PolicyChain {
    let mut policy = tagged(NEW);
    let mut action_only = next_hop_policy(OLD).policies[0].policy.entries[0].clone();
    action_only.prefix = Some(last);
    policy.policies[0].policy.entries.insert(0, action_only);
    policy
}

fn replacements(peers: &[PeerId], policy: &PolicyChain) -> Vec<crate::PeerExportPolicyReplacement> {
    peers
        .iter()
        .map(|&peer| crate::PeerExportPolicyReplacement {
            peer,
            export_policy: Some(policy.clone()),
        })
        .collect()
}

fn apply(manager: &mut RibManager, input: Vec<crate::PeerExportPolicyReplacement>) -> Vec<PeerId> {
    let (reply, mut response) = oneshot::channel();
    manager.handle_update(RibUpdate::ReplacePeerExportPoliciesAuthoritatively {
        replacements: input,
        reply,
    });
    response.try_recv().unwrap().unwrap()
}

fn assert_wire(
    rx: &mut mpsc::Receiver<OutboundRouteUpdate>,
    expected: &BTreeSet<Prefix>,
    tag: Option<u32>,
    action: Option<&NextHopAction>,
    expected_eors: usize,
) {
    let mut prefixes = BTreeSet::new();
    let mut eors = 0;
    while let Ok(update) = rx.try_recv() {
        assert!(update.unicast_withdrawals().next().is_none());
        for (i, row) in update.announce.iter().enumerate() {
            assert_eq!(eors, 0, "a replay row followed its End-of-RIB");
            assert_eq!(row.peer, external());
            assert_eq!(row.path_id, 0);
            assert_eq!(row.communities(), tag.as_slice());
            assert_eq!(
                update.next_hop_override.get(i).and_then(Option::as_ref),
                action
            );
            assert!(prefixes.insert(row.prefix), "duplicate row {}", row.prefix);
        }
        if !update.end_of_rib.is_empty() {
            assert_eq!(update.end_of_rib, ipv4_sendable());
            eors += 1;
        }
    }
    assert_eq!(&prefixes, expected);
    assert_eq!(eors, expected_eors);
}

fn population(rows: usize) -> BTreeSet<Prefix> {
    (0..rows).map(|i| Prefix::V4(prefix(1, i))).collect()
}

#[test]
fn uncertain_single_best_cold_cohort_commits_its_exact_shared_inventory() {
    let rows = population(384);
    for rs_control in [false, true] {
        let (_tx, mut manager) = manager();
        let old = tagged(OLD);
        let mut outputs = members(&mut manager, 5, rs_control, Some(&old));
        for rx in &mut outputs {
            assert_wire(rx, &BTreeSet::new(), None, None, 1);
        }
        manager.handle_update(routes_from(external(), 0, 1, rows.len()));
        drain_route_chunks(&mut manager);
        for rx in &mut outputs {
            assert_wire(rx, &rows, Some(OLD), None, 0);
        }
        let source = manager.grouped_member_of(member(0)).unwrap();
        let next = if rs_control {
            tagged(NEW)
        } else {
            next_hop_policy(NEW)
        };
        let movers = [member(0), member(1), member(2), member(3)];
        let deferred = apply(&mut manager, replacements(&movers, &next));
        let receipt = manager.authoritative_transition_receipts.last().unwrap();
        assert_eq!(
            (
                receipt.destination_builds,
                receipt.shared_members,
                deferred.len()
            ),
            (1, 4, 0),
            "fresh builds, shared movers, returned movers, rs_control={rs_control}"
        );
        assert_eq!(
            (receipt.inventory_announces, receipt.deferred_members),
            (rows.len(), 0)
        );
        let gid = manager.grouped_member_of(member(0)).unwrap();
        assert_ne!(gid, source);
        for (index, output) in outputs.iter_mut().take(4).enumerate() {
            assert_eq!(manager.grouped_member_of(member(index)), Some(gid));
            assert_eq!(manager.export_policy_for(member(index)), Some(&next));
            assert_wire(
                output,
                &rows,
                Some(NEW),
                (!rs_control).then_some(&NextHopAction::Self_),
                0,
            );
        }
        assert!(outputs[4].is_empty());
        assert_eq!(manager.grouped_member_of(member(4)), Some(source));
        assert_eq!(manager.export_policy_for(member(4)), Some(&old));
        assert_eq!(memberless_groups(&manager), 0);
        assert!(!manager.optional_destination_retirement_active());
    }
}

#[test]
fn abandoned_late_cold_refusal_preserves_old_updates_and_mandatory_restore() {
    let (tx, mut manager) = manager();
    let old = tagged(OLD);
    let moved = tagged(MOVED);
    let mut outputs = members(&mut manager, 2, false, Some(&old));
    let mut restoring = join(&mut manager, 2, false, Some(moved.clone())).0;
    for rx in &mut outputs {
        assert_wire(rx, &BTreeSet::new(), None, None, 1);
    }
    assert_wire(&mut restoring, &BTreeSet::new(), None, None, 1);
    let count = 2 * REGISTRATION_PAGE_SIZE + 1;
    let rows = population(count);
    manager.handle_update(routes_from(external(), 0, 1, count));
    drain_route_chunks(&mut manager);
    for rx in &mut outputs {
        assert_wire(rx, &rows, Some(OLD), None, 0);
    }
    assert_wire(&mut restoring, &rows, Some(MOVED), None, 0);

    let last = *rows.last().unwrap();
    manager.cold_build_last_prefix = Some(last);
    let pending = [member(0), member(1)];
    let source = manager.grouped_member_of(member(0)).unwrap();
    let target = late_refusal(last);
    assert_eq!(
        apply(&mut manager, replacements(&pending, &target)),
        pending
    );
    // Its forward caller abandons the returned walk. No command adopts this
    // table, and its accumulated cloned routes must still have a charged owner.
    assert_eq!(manager.refused_inventory_rows_remaining(), Some(count - 1));
    assert!(manager.optional_destination_retirement_active());
    assert_eq!(memberless_groups(&manager), 0);
    assert!(outputs.iter().all(mpsc::Receiver::is_empty));
    assert!(
        pending
            .iter()
            .all(|&peer| manager.grouped_member_of(peer) == Some(source)
                && manager.export_policy_for(peer) == Some(&old))
    );

    manager.first_group_build_min_routes = 1;
    let mut founder = join(&mut manager, 3, false, None).0;
    assert!(manager.pending_initial_registrations.contains(&member(3)));
    assert!(manager.first_group_build.is_none());
    let (reply, response) = oneshot::channel();
    tx.try_send(RibUpdate::RestorePeerExportPoliciesAuthoritatively {
        replacements: replacements(&[member(2)], &old),
        reply,
    })
    .unwrap();
    drop(response);
    assert!(manager.try_recv_primary().is_none());
    assert_eq!(manager.first_group_deferred_intents.len(), 1);
    tx.try_send(routes_from(external(), 0, 9, 1)).unwrap();
    let update = manager
        .try_recv_primary()
        .expect("an unrelated UPDATE passes the parked restore");
    manager.handle_update(update);
    drain_route_chunks(&mut manager);
    let marker = Prefix::V4(prefix(9, 0));
    let marker_rows = BTreeSet::from([marker]);
    for output in &mut outputs {
        assert_wire(output, &marker_rows, Some(OLD), None, 0);
    }
    assert_wire(&mut restoring, &marker_rows, Some(MOVED), None, 0);
    assert!(manager.optional_destination_retirement_active());
    assert!(manager.loc_rib.get(&marker).is_some());
    let mut charged = 0;
    for _ in 0..128 {
        if !manager.optional_destination_retirement_active() {
            break;
        }
        assert!(!manager.first_group_slot_available());
        assert!(manager.first_group_build.is_none() && founder.is_empty());
        assert!(manager.take_first_group_deferred_intent().is_none());
        assert_eq!(manager.export_policy_for(member(2)), Some(&moved));
        let physical = manager.advance_optional_destination_retirement();
        assert!((1..=REGISTRATION_PAGE_SIZE).contains(&physical));
        charged += physical;
    }
    assert!(
        !manager.optional_destination_retirement_active(),
        "retirement made no terminal progress"
    );
    assert!(
        charged >= 2 * count - 1,
        "every staged slot and each retained inventory route is charged"
    );
    let restore = manager
        .take_first_group_deferred_intent()
        .expect("original restore retains its FIFO position");
    manager.handle_update(restore);
    assert_eq!(manager.export_policy_for(member(2)), Some(&old));
    assert_eq!(manager.grouped_member_of(member(2)), Some(source));
    let mut latest = rows;
    latest.insert(marker);
    assert_wire(&mut restoring, &latest, Some(OLD), None, 0);
    for _ in 0..128 {
        if !manager.pending_initial_registrations.contains(&member(3)) {
            break;
        }
        manager.advance_pending_initial_registration();
    }
    assert!(manager.grouped_member_of(member(3)).is_some());
    assert_wire(&mut founder, &latest, None, None, 1);
    assert_eq!(memberless_groups(&manager), 0);
}

#[test]
fn mixed_batch_can_adopt_a_warm_destination_after_its_first_cold_refusal() {
    let (_tx, mut manager) = manager();
    let policies = [tagged(OLD), tagged(MOVED), tagged(NEW + 1), tagged(NEW + 2)];
    let mut outputs: Vec<_> = policies
        .iter()
        .enumerate()
        .map(|(i, policy)| join(&mut manager, i, false, Some(policy.clone())).0)
        .collect();
    let sources: Vec<_> = (0..policies.len())
        .map(|i| manager.grouped_member_of(member(i)).unwrap())
        .collect();
    assert!(
        sources.windows(2).all(|pair| pair[0] < pair[1]),
        "the batch visits source gids in order"
    );
    manager.handle_update(routes_from(external(), 0, 1, 17));
    drain_route_chunks(&mut manager);
    assert_eq!(drain(&mut outputs), (4 * 17, 0));
    let first = next_hop_policy(OLD);
    let second = next_hop_policy(NEW);
    let mut batch = replacements(&[member(0)], &first);
    batch.extend(replacements(&[member(1)], &second));
    batch.extend(replacements(&[member(2)], &policies[3]));
    assert_eq!(apply(&mut manager, batch), vec![member(0), member(1)]);
    let r = manager.authoritative_transition_receipts.last().unwrap();
    assert_eq!(
        (r.destination_builds, r.shared_members, r.deferred_members),
        (1, 1, 2)
    );
    assert!(manager.optional_destination_retirement_active());
    assert_eq!(memberless_groups(&manager), 0);
    assert_eq!(manager.grouped_member_of(member(0)), Some(sources[0]));
    assert_eq!(manager.grouped_member_of(member(1)), Some(sources[1]));
    assert_eq!(manager.grouped_member_of(member(2)), Some(sources[3]));
    assert_eq!(manager.grouped_member_of(member(3)), Some(sources[3]));
    for i in [0, 1, 3] {
        assert!(outputs[i].is_empty());
    }
    assert_wire(&mut outputs[2], &population(17), Some(NEW + 2), None, 0);
    assert_eq!(manager.export_policy_for(member(0)), Some(&policies[0]));
    assert_eq!(manager.export_policy_for(member(1)), Some(&policies[1]));
    assert_eq!(manager.export_policy_for(member(2)), Some(&policies[3]));
}

#[test]
fn uncertain_pcb_and_mixed_family_cold_cohorts_do_not_take_the_scratch_slot() {
    let old = tagged(OLD);
    let next = next_hop_policy(NEW);
    for pcb in [false, true] {
        let (_tx, mut manager) = manager();
        let (out, mut receiver) = mpsc::channel(16);
        let mut up = test_peer_up(member(0), 1, out);
        if let RibUpdate::PeerUp {
            export_policy,
            per_client_best,
            sendable_families,
            ..
        } = &mut up
        {
            *export_policy = Some(old.clone());
            *per_client_best = pcb;
            if !pcb {
                sendable_families.push((Afi::Ipv4, Safi::MplsVpn));
            }
        }
        manager.handle_update(up);
        manager.handle_update(routes_from(external(), 0, 1, 1));
        drain_route_chunks(&mut manager);
        assert_eq!(drain(std::slice::from_mut(&mut receiver)), (1, 0));
        let original = manager.grouped_member_of(member(0)).unwrap();
        assert_eq!(manager.group_ribs[&original].per_client_best, pcb);
        assert_eq!(
            apply(&mut manager, replacements(&[member(0)], &next)),
            vec![member(0)]
        );
        let receipt = manager.authoritative_transition_receipts.last().unwrap();
        assert_eq!((receipt.destination_builds, receipt.shared_members), (0, 0));
        assert!(receiver.is_empty());
        assert_eq!(manager.grouped_member_of(member(0)), Some(original));
        assert_eq!(manager.export_policy_for(member(0)), Some(&old));
        assert!(!manager.optional_destination_retirement_active());
        assert!(manager.first_group_slot_available());
    }
}

#[test]
fn refused_cold_restore_reports_each_prior_member_in_reverse_order() {
    use crate::update::PeerExportPolicyRestoreReceipt::{Deferred, NotFound, Restored};
    let (_tx, mut manager) = manager();
    let old = tagged(OLD);
    let next = next_hop_policy(OLD);
    let mut receivers = members(&mut manager, 3, false, Some(&old));
    manager.handle_update(routes_from(external(), 0, 1, 13));
    drain_route_chunks(&mut manager);
    assert_eq!(drain(&mut receivers), (3 * 13, 0));
    let source = manager.grouped_member_of(member(0)).unwrap();
    let absent = member(9);
    let mut input = replacements(&[member(0), absent, member(1)], &next);
    input.extend(replacements(&[member(2)], &old));
    let (reply, mut response) = oneshot::channel();
    manager.handle_update(RibUpdate::RestorePeerExportPoliciesAuthoritatively {
        replacements: input,
        reply,
    });
    assert_eq!(
        response.try_recv().unwrap().unwrap(),
        [
            Restored { peer: member(2) },
            Deferred { peer: member(1) },
            NotFound { peer: absent },
            Deferred { peer: member(0) },
        ]
    );
    assert!(manager.optional_destination_retirement_active());
    assert!(receivers.iter().all(mpsc::Receiver::is_empty));
    for peer in (0..3).map(member) {
        assert_eq!(manager.grouped_member_of(peer), Some(source));
        assert_eq!(manager.export_policy_for(peer), Some(&old));
    }
}
