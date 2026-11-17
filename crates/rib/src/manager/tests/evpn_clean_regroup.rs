//! A clean member moving between two owned EVPN groups takes no
//! recovery-proof cycle: nothing is captured before the move, and the commit
//! reserves, counts and releases nothing. Its feed carries the basis of
//! actual OLD instead, and the pass that was handed the feed captures the
//! proof from that basis only when the admission was missed.

use super::evpn_complete_feed::{assert_proof_only_while_owed, proof_keys};
use super::evpn_group_storage::{received, stage};
use super::evpn_policy_pacing::{Fleet, evpn_fleet, evpn_row};
use super::exportability::MockExactExportEncoder;
use super::update_groups::{community_chain, deny_statement};
use super::*;
use crate::PeerId;
use crate::manager::distribution::{OutboundCommitBatch, OutboundCommitFailure};
use crate::manager::update_groups::GroupMembership;
use crate::update::{
    EvpnRecoveryExhaustionCause, EvpnRecoveryReset, EvpnRecoveryResetOutcome, ExactExportKey,
};
use rustbgpd_policy::{Policy, PolicyAction};
use rustbgpd_telemetry::reason_labels::OutboundCommitRefusal;
use rustbgpd_wire::{EthernetTagId, EvpnRouteKey};

const EVPN: (Afi, Safi) = (Afi::L2Vpn, Safi::Evpn);

fn key(tag: u32) -> EvpnRouteKey {
    evpn_row(tag).key()
}

fn keys(tags: &[u32]) -> Vec<EvpnRouteKey> {
    let mut keys: Vec<_> = tags.iter().map(|&tag| key(tag)).collect();
    keys.sort_unstable();
    keys
}

/// `tag`'s row with another route target: the same key, a changed value.
fn changed_row(tag: u32) -> EvpnRibRoute {
    let mut route = received(200);
    let EvpnRoute::Imet(ref mut imet) = route.route else {
        panic!("IMET fixture");
    };
    imet.ethernet_tag = EthernetTagId(tag);
    route
}

/// A chain that permits every route unmodified: a different group key from
/// no chain at all, with the same exported values.
fn permit_all() -> PolicyChain {
    let mut statement = deny_statement(Ipv4Prefix::new(Ipv4Addr::UNSPECIFIED, 0));
    statement.prefix = None;
    statement.action = PolicyAction::Permit;
    PolicyChain::new(vec![Policy {
        entries: vec![statement],
        default_action: PolicyAction::Deny,
    }])
}

/// The member's Ready proof, or `None` also behind a pending reset.
fn held_proof(manager: &RibManager, peer: PeerId) -> Option<Vec<EvpnRouteKey>> {
    manager
        .evpn_recovery
        .proof_keys(manager.evpn_recovery_handle(peer)?)
        .ok()
        .flatten()
}

fn drain(output: &mut mpsc::Receiver<OutboundRouteUpdate>) -> Vec<OutboundRouteUpdate> {
    std::iter::from_fn(|| output.try_recv().ok()).collect()
}

/// The recovery-proof work each clean mover's paced command did: `capture_evpn`
/// checkpoints passed, complete feeds built, and whether its ledger charge
/// and peak, and the daemon's, stayed where they were.
fn clean_regroup_proof_work(members: usize) -> Vec<(usize, usize, bool)> {
    let mut fleet = evpn_fleet(members, 6, true);
    let old = fleet.manager.grouped_member_of(fleet.members[0]).unwrap();
    let pending = fleet.batch();
    assert_eq!(pending, fleet.members);
    let mut work = Vec::new();
    for &peer in &pending {
        let usage = (
            fleet.manager.evpn_recovery.peer_usage(peer),
            fleet.manager.evpn_recovery.daemon_usage(),
        );
        let builds = fleet.manager.evpn_complete_feed_builds;
        let counts = super::work_scaling::checkpoints_in(|| {
            assert_eq!(fleet.paced(&[peer], None).applied, 1);
        });
        let ledger_unmoved = (
            fleet.manager.evpn_recovery.peer_usage(peer),
            fleet.manager.evpn_recovery.daemon_usage(),
        ) == usage;
        assert_ne!(fleet.manager.grouped_member_of(peer), Some(old));
        assert!(!fleet.manager.dirty_peers.contains(&peer));
        assert!(!fleet.manager.has_evpn_feed_completion(peer));
        assert_eq!(proof_keys(&fleet.manager, peer), None);
        work.push((
            counts.get("capture_evpn").copied().unwrap_or(0),
            fleet.manager.evpn_complete_feed_builds - builds,
            ledger_unmoved,
        ));
    }
    assert!(
        !fleet.manager.group_ribs.contains_key(&old),
        "the last mover retired OLD"
    );
    for output in &mut fleet.outputs {
        let rows: Vec<_> = drain(output)
            .iter()
            .flat_map(|update| update.evpn_announce.iter().cloned())
            .collect();
        assert_eq!(rows.len(), 6);
        assert!(
            rows.iter()
                .all(|row| row.communities().contains(&0xFC00_0001))
        );
    }
    work
}

/// Per clean mover: zero capture checkpoints, one feed build and a ledger
/// whose charge and peak never move, whatever the fleet size. The proof
/// cycle passes capture checkpoints for every table row and raises the
/// member's ledger peak. Each paced command here applies one mover; several
/// movers in one pass are covered by
/// `several_movers_in_one_pass_settle_each_missed_admission`.
#[test]
fn clean_owned_regroup_takes_no_proof_cycle() {
    assert_eq!(clean_regroup_proof_work(8), vec![(0, 1, true); 8]);
    assert_eq!(clean_regroup_proof_work(32), vec![(0, 1, true); 32]);
}

/// Three members whose OLD and NEW projections differ in every way a feed
/// can express. NEW exports the same values as OLD, and was prepared by hand
/// before the source moved on, so against each member's OLD it holds:
/// unchanged rows, a changed row (3), a row OLD no longer has (5, fresh), and
/// lacks a row OLD gained (6, withdrawn). Member 0's exact probe rejected
/// row 2 in OLD (fresh for it alone); member 2 sourced row 8 (never its own).
struct Divergent {
    fleet: Fleet,
    old: usize,
    new: usize,
}

/// Each member's admitted set in OLD.
fn expected_old() -> [Vec<EvpnRouteKey>; 3] {
    [
        keys(&[1, 3, 4, 6, 8]),
        keys(&[1, 2, 3, 4, 6, 8]),
        keys(&[1, 2, 3, 4, 6]),
    ]
}

/// Each member's admitted set once it converged on NEW. Member 1's exact
/// probe rejects rows 3 and 5 at the regroup; member 0's accepts row 2 again.
fn expected_new() -> [Vec<EvpnRouteKey>; 3] {
    [
        keys(&[1, 2, 3, 4, 5, 8]),
        keys(&[1, 2, 4, 8]),
        keys(&[1, 2, 3, 4, 5]),
    ]
}

/// Make `next` the fleet's target policy and prepare its owned destination
/// by hand, holding `rows`, the way the fleet fixture prepares its own.
fn prepare_destination(fleet: &mut Fleet, next: PolicyChain, rows: &[u32]) -> usize {
    let first = fleet.members[0];
    let previous = fleet.manager.export_chains.get(&first).cloned();
    fleet
        .manager
        .export_chains
        .insert(first, Some(next.clone()));
    let GroupMembership::Grouped(new) = fleet.manager.compute_update_group_membership(first) else {
        panic!("groupable destination");
    };
    fleet.manager.ensure_group_table(new, first);
    fleet
        .manager
        .group_ribs
        .get_mut(&new)
        .unwrap()
        .set_evpn_ownership_for_test(true);
    let staged: HashSet<_> = keys(rows).into_iter().collect();
    fleet.manager.stage_group_evpn_keys(new, &staged);
    match previous {
        Some(previous) => fleet.manager.export_chains.insert(first, previous),
        None => fleet.manager.export_chains.remove(&first),
    }
    fleet.next = next;
    new
}

fn divergent() -> Divergent {
    let mut fleet = evpn_fleet(3, 5, true);
    let members = fleet.members.clone();
    let old = fleet.manager.grouped_member_of(members[0]).unwrap();
    let encoders: Vec<_> = members
        .iter()
        .map(|&peer| {
            let encoder = MockExactExportEncoder::accepting(1);
            fleet
                .manager
                .peer_export_encoders
                .insert(peer, encoder.clone());
            encoder
        })
        .collect();
    // Member 0 loses row 2 to its exact probe; the others take its new value.
    encoders[0].set_profile(2, [ExactExportKey::Evpn(key(2))]);
    fleet
        .manager
        .process_evpn_announce_chunk(fleet.source, vec![changed_row(2)]);
    let mut sourced = evpn_row(8);
    sourced.peer = members[2];
    fleet
        .manager
        .ribs
        .entry(members[2])
        .or_insert_with(|| AdjRibIn::new(members[2]));
    fleet
        .manager
        .process_evpn_announce_chunk(members[2], vec![sourced]);

    let new = prepare_destination(&mut fleet, permit_all(), &[1, 2, 3, 4, 5, 8]);

    // The memberless destination is not maintained from here on.
    fleet
        .manager
        .process_evpn_announce_chunk(fleet.source, vec![evpn_row(6), changed_row(3)]);
    fleet
        .manager
        .process_evpn_withdraw_chunk(fleet.source, vec![key(5)]);
    let table = |gid: usize| {
        let mut keys: Vec<_> = fleet.manager.group_ribs[&gid]
            .table
            .iter_evpn()
            .map(EvpnRibRoute::key)
            .collect();
        keys.sort_unstable();
        keys
    };
    assert_eq!(table(old), keys(&[1, 2, 3, 4, 6, 8]));
    assert_eq!(table(new), keys(&[1, 2, 3, 4, 5, 8]));
    for (index, &peer) in members.iter().enumerate() {
        drain(&mut fleet.outputs[index]);
        assert_eq!(proof_keys(&fleet.manager, peer), None);
        assert!(!fleet.manager.dirty_peers.contains(&peer));
        assert_eq!(
            fleet.manager.evpn_admitted_count(peer),
            expected_old()[index].len()
        );
        assert!(fleet.manager.clean_evpn_regroup_eligible(peer, new));
    }
    // What each member's exact probe decides at the regroup.
    encoders[0].set_profile(3, []);
    encoders[1].set_profile(
        2,
        [ExactExportKey::Evpn(key(3)), ExactExportKey::Evpn(key(5))],
    );
    Divergent { fleet, old, new }
}

type Envelope = (
    Vec<(EvpnRouteKey, Arc<AttrSet>)>,
    Vec<EvpnRouteKey>,
    Vec<(Afi, Safi)>,
);

fn envelope(update: &OutboundRouteUpdate) -> Envelope {
    (
        update
            .evpn_announce
            .iter()
            .map(|route| (route.key(), route.attributes.clone()))
            .collect(),
        update.evpn_withdraw.clone(),
        update.end_of_rib.clone(),
    )
}

/// A clean regroup puts on the wire what the proof cycle does for the same
/// member: the same envelopes in the same order, the same admitted count and
/// the same exact-rejection overlay. The feeds hold a changed row, a fresh
/// key, a withdrawn key, a row the probe rejects that the member held (it is
/// withdrawn) and one it did not hold (it is dropped).
#[test]
fn clean_regroup_envelopes_equal_the_proof_cycle() {
    let regroup = |proof_cycle: bool| {
        let Divergent {
            mut fleet,
            old,
            new,
            ..
        } = divergent();
        let mut result = Vec::new();
        for (index, peer) in fleet.members.clone().into_iter().enumerate() {
            if proof_cycle {
                // The capture the regroup seam takes on its own: an existing
                // proof is what it finds.
                assert!(fleet.manager.capture_shared_evpn_admitted(peer));
                assert_eq!(
                    proof_keys(&fleet.manager, peer),
                    Some(expected_old()[index].clone())
                );
            }
            assert_eq!(
                fleet.manager.clean_evpn_regroup_eligible(peer, new),
                !proof_cycle
            );
            let work = super::work_scaling::checkpoints_in(|| fleet.step(peer).unwrap());
            assert_eq!(work.get("capture_evpn"), None);
            assert_eq!(fleet.manager.evpn_grouped_member_of(peer), Some(new));
            assert_eq!(proof_keys(&fleet.manager, peer), None);
            assert!(!fleet.manager.dirty_peers.contains(&peer));
            assert!(!fleet.manager.has_evpn_feed_completion(peer));
            assert!(!fleet.manager.evpn_recovery_reset_pending(peer));
            let mut rejected: Vec<_> = fleet
                .manager
                .peer_unexportable
                .get(&peer)
                .into_iter()
                .flatten()
                .map(|key| match key {
                    ExactExportKey::Evpn(key) => *key,
                    other => panic!("unexpected rejection {other:?}"),
                })
                .collect();
            rejected.sort_unstable();
            result.push((
                drain(&mut fleet.outputs[index])
                    .iter()
                    .map(envelope)
                    .collect::<Vec<_>>(),
                fleet.manager.evpn_admitted_count(peer),
                rejected,
            ));
        }
        assert!(!fleet.manager.group_ribs.contains_key(&old));
        result
    };
    let clean = regroup(false);
    let announced = |index: usize| -> Vec<_> {
        let mut keys: Vec<_> = clean[index].0[0].0.iter().map(|(key, _)| *key).collect();
        keys.sort_unstable();
        keys
    };
    // Member 0: row 2 (fresh, accepted again), 3 (changed), 5 (fresh).
    assert_eq!(announced(0), keys(&[2, 3, 5]));
    assert_eq!(clean[0].0[0].1, keys(&[6]));
    // Member 1: both candidates rejected. It held row 3, so that is
    // withdrawn; it never held row 5, so that is only dropped.
    assert_eq!(announced(1), keys(&[]));
    assert_eq!(clean[1].0[0].1, keys(&[3, 6]));
    assert_eq!(clean[1].2, keys(&[3, 5]));
    assert_eq!(announced(2), keys(&[3, 5]));
    assert_eq!(clean[2].0[0].1, keys(&[6]));
    for (index, (envelopes, count, _)) in clean.iter().enumerate() {
        assert_eq!(envelopes.len(), 1, "one envelope per mover");
        assert_eq!(*count, expected_new()[index].len());
    }
    // The proof cycle re-bases the admitted count on its proof at the
    // regroup; the proofless commit adds a delta to the count it had. The
    // two agree because a clean member's count is its admitted set.
    let proof_cycle = regroup(true);
    for (clean, proof_cycle) in clean.iter().zip(&proof_cycle) {
        assert_eq!(clean.1, proof_cycle.1, "admitted count");
    }
    assert_eq!(clean, proof_cycle);
}

/// A regroup between two groups that export the same values has nothing to
/// send. Its empty feed still completes and settles: no envelope, no proof,
/// the admitted count unchanged, as the proof cycle leaves it.
#[test]
fn clean_regroup_with_nothing_to_send_settles_without_an_envelope() {
    let regroup = |proof_cycle: bool| {
        let mut fleet = evpn_fleet(2, 4, true);
        let new = prepare_destination(&mut fleet, permit_all(), &[1, 2, 3, 4]);
        let peer = fleet.members[0];
        if proof_cycle {
            assert!(fleet.manager.capture_shared_evpn_admitted(peer));
        }
        let usage = fleet.manager.evpn_recovery.peer_usage(peer).retained;
        fleet.step(peer).unwrap();
        assert_eq!(fleet.manager.evpn_grouped_member_of(peer), Some(new));
        assert_eq!(proof_keys(&fleet.manager, peer), None);
        assert!(!fleet.manager.dirty_peers.contains(&peer));
        assert!(!fleet.manager.has_evpn_feed_completion(peer));
        assert_eq!(fleet.manager.evpn_admitted_count(peer), 4);
        if !proof_cycle {
            assert_eq!(fleet.manager.evpn_recovery.peer_usage(peer).retained, usage);
        }
        drain(&mut fleet.outputs[0])
            .iter()
            .map(envelope)
            .collect::<Vec<_>>()
    };
    let clean = regroup(false);
    assert!(
        clean
            .iter()
            .all(|(announce, withdraw, _)| announce.is_empty() && withdraw.is_empty())
    );
    assert_eq!(clean, regroup(true));
}

/// The policy-replacement seam for one member, with `fault` run between the
/// regroup and the distribution pass it hands its feed to.
fn regroup_with(
    fleet: &mut Fleet,
    peer: PeerId,
    fault: impl FnOnce(
        &mut RibManager,
        PeerId,
        &mut Option<crate::manager::evpn_recovery::EvpnCompleteFeed>,
    ),
) {
    let manager = &mut fleet.manager;
    manager.export_chains.insert(peer, Some(fleet.next.clone()));
    let mut feed = manager.recompute_update_group_for_pass(peer);
    manager.create_installed_export_counters([peer]);
    manager.mark_outbound_dirty_with_evpn_feed(peer, &mut feed);
    fault(manager, peer, &mut feed);
    manager.distribute_changes_with_evpn_feeds(
        feed.into_iter().map(|feed| (peer, feed)).collect(),
        false,
    );
}

fn fill(manager: &RibManager, peer: PeerId) {
    let sender = manager.outbound_peers[&peer].clone();
    while sender.try_send(OutboundRouteUpdate::default()).is_ok() {}
}

fn record_resets(manager: &mut RibManager) -> Arc<std::sync::Mutex<Vec<EvpnRecoveryReset>>> {
    let requests = Arc::new(std::sync::Mutex::new(Vec::new()));
    let seen = Arc::clone(&requests);
    manager.evpn_recovery_reset = Some(Arc::new(move |request, reply| {
        seen.lock().unwrap().push(request);
        let _ = reply.send(EvpnRecoveryResetOutcome::Executed);
        true
    }));
    requests
}

/// How a mover's admission is missed after it has left OLD.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Miss {
    /// The writer has no room: the pass skips the member, feed unattempted.
    Skipped,
    /// The feed's seal lost its receipt revision: the commit refuses it.
    StaleSeal,
    /// EVPN selection is deferred when the commit runs: the gate refuses it.
    SelectionGate,
}

fn arm_selection_gate(fleet: Fleet) -> Fleet {
    arm_selection_gate_for(fleet, EVPN)
}

fn arm_selection_gate_for(fleet: Fleet, family: (Afi, Safi)) -> Fleet {
    let Fleet {
        manager,
        members,
        outputs,
        source,
        next,
    } = fleet;
    let manager = manager.with_selection_deferral(crate::SelectionDeferralConfig {
        timeout: Duration::from_secs(60),
        waiters: vec![crate::SelectionDeferralWaiterConfig {
            peer: source.into(),
            families: vec![family],
        }],
    });
    Fleet {
        manager,
        members,
        outputs,
        source,
        next,
    }
}

fn defer_evpn_selection(manager: &mut RibManager, source: PeerId) {
    let metrics = manager.metrics.clone();
    manager
        .selection_deferral
        .as_mut()
        .unwrap()
        .classify_session(source, 12, false, &HashSet::from([EVPN]), &metrics);
    assert!(manager.selection_deferred(EVPN));
}

/// Whatever misses a clean mover's admission, the proof captured from its
/// feed's basis is its actual OLD: the keys a capture of OLD taken before
/// the move holds, for a member with an exact-rejection overlay, a plain
/// member and one that sourced a row, also when the mover was the last to
/// leave and OLD is gone. Nothing was sent, no reset is requested, and the
/// resync that follows withdraws exactly what OLD held and NEW does not.
#[test]
fn missed_admission_captures_actual_old_from_the_feed_basis() {
    for miss in [Miss::Skipped, Miss::StaleSeal, Miss::SelectionGate] {
        for index in 0..3 {
            for last in [false, true] {
                let context = format!("{miss:?} member {index} last={last}");
                let reference = {
                    let Divergent { mut fleet, .. } = divergent();
                    let peer = fleet.members[index];
                    assert!(fleet.manager.capture_shared_evpn_admitted(peer));
                    proof_keys(&fleet.manager, peer).unwrap()
                };
                assert_eq!(reference, expected_old()[index], "{context}");

                let Divergent {
                    mut fleet,
                    old,
                    new,
                    ..
                } = divergent();
                if miss == Miss::SelectionGate {
                    fleet = arm_selection_gate(fleet);
                }
                let peer = fleet.members[index];
                if last {
                    for other in fleet.members.clone() {
                        if other != peer {
                            fleet.step(other).unwrap();
                        }
                    }
                }
                drain(&mut fleet.outputs[index]);
                let resets = record_resets(&mut fleet.manager);
                let source = fleet.source;
                let work = super::work_scaling::checkpoints_in(|| {
                    regroup_with(&mut fleet, peer, |manager, peer, feed| {
                        assert!(
                            feed.as_ref().unwrap().seal.clean_regroup().is_some(),
                            "{context}: the proofless path"
                        );
                        assert_eq!(proof_keys(manager, peer), None);
                        assert_eq!(manager.group_ribs.contains_key(&old), !last);
                        match miss {
                            Miss::Skipped => fill(manager, peer),
                            Miss::StaleSeal => manager.invalidate_evpn_feed_completion(peer),
                            Miss::SelectionGate => defer_evpn_selection(manager, source),
                        }
                    });
                });
                assert!(work.get("capture_evpn").is_some_and(|&count| count > 0));
                let manager = &mut fleet.manager;
                assert_eq!(manager.evpn_grouped_member_of(peer), Some(new), "{context}");
                assert_eq!(
                    proof_keys(manager, peer),
                    Some(reference.clone()),
                    "{context}"
                );
                assert!(manager.dirty_peers.contains(&peer), "{context}");
                assert!(!manager.evpn_recovery_reset_pending(peer), "{context}");
                assert_eq!(
                    manager.evpn_admitted_count(peer),
                    reference.len(),
                    "{context}"
                );
                assert_proof_only_while_owed(manager, peer);
                for update in drain(&mut fleet.outputs[index]) {
                    assert!(
                        update.evpn_announce.is_empty() && update.evpn_withdraw.is_empty(),
                        "{context}: nothing was sent"
                    );
                }

                // The ordinary resync heals the member from that proof.
                if miss == Miss::SelectionGate {
                    fleet.manager.selection_deferral = None;
                }
                fleet.manager.resync_dirty_peers_bounded();
                let mut wire: HashSet<_> = reference.iter().copied().collect();
                for update in drain(&mut fleet.outputs[index]) {
                    for key in &update.evpn_withdraw {
                        assert!(wire.remove(key), "{context}: withdrew {key:?} unheld");
                    }
                    wire.extend(update.evpn_announce.iter().map(EvpnRibRoute::key));
                }
                let mut wire: Vec<_> = wire.into_iter().collect();
                wire.sort_unstable();
                assert_eq!(wire, expected_new()[index], "{context}");
                let manager = &fleet.manager;
                assert_eq!(proof_keys(manager, peer), None, "{context}");
                assert!(!manager.dirty_peers.contains(&peer), "{context}");
                assert!(!manager.has_evpn_feed_completion(peer), "{context}");
                assert_eq!(manager.evpn_admitted_count(peer), wire.len(), "{context}");
                assert!(resets.lock().unwrap().is_empty(), "{context}");
            }
        }
    }
}

/// The basis is usable only while NEW is the table the feed walked. Nothing
/// stages a table between a regroup and its pass, so this is a defensive
/// path: a moved stamp refuses the commit, and with no trustworthy
/// withdrawal set the member is handed to the session reset, with the
/// request an admission-invariant failure always sends. No proof is captured
/// and no EVPN marker or route follows.
#[test]
fn moved_destination_table_resets_instead_of_guessing_withdrawals() {
    let Divergent { mut fleet, new, .. } = divergent();
    let peer = fleet.members[1];
    let resets = record_resets(&mut fleet.manager);
    let usage = (
        fleet.manager.evpn_recovery.peer_usage(peer).retained,
        fleet.manager.evpn_recovery.daemon_usage().retained,
    );
    let work = super::work_scaling::checkpoints_in(|| {
        regroup_with(&mut fleet, peer, |manager, _, _| {
            // The stamp alone, as a staging leaves it. A real staging also
            // captures its dirty members first, which the next test pins.
            let stamp = manager.next_evpn_table_stamp().unwrap();
            manager.group_ribs.get_mut(&new).unwrap().evpn_table_stamp = stamp;
        });
    });
    assert_eq!(work.get("capture_evpn"), None);
    let manager = &mut fleet.manager;
    assert!(manager.evpn_recovery_reset_pending(peer));
    assert_eq!(held_proof(manager, peer), None);
    assert!(manager.dirty_peers.contains(&peer));
    assert!(!manager.evpn_feed_is_current(peer));
    let (peer_limit_bytes, daemon_limit_bytes) = manager.evpn_recovery.limits();
    {
        let requests = resets.lock().unwrap();
        assert_eq!(requests.len(), 1);
        let request = &requests[0];
        assert_eq!((request.peer, request.session_id), (peer, 7));
        assert!(
            request
                .outbound
                .same_channel(&manager.outbound_peers[&peer])
        );
        assert_eq!(
            request.cause,
            EvpnRecoveryExhaustionCause::AdmissionInvariant
        );
        assert_eq!(request.limiting_peer, None);
        assert_eq!(
            (request.attempted_peer_bytes, request.attempted_daemon_bytes),
            usage
        );
        assert_eq!(
            (request.peer_limit_bytes, request.daemon_limit_bytes),
            (peer_limit_bytes, daemon_limit_bytes)
        );
    }
    manager.resync_dirty_peers_bounded();
    manager.retry_eor_markers_bounded();
    for update in drain(&mut fleet.outputs[1]) {
        assert!(update.evpn_announce.is_empty() && update.evpn_withdraw.is_empty());
        assert!(!update.end_of_rib.contains(&EVPN));
    }
    assert_eq!(resets.lock().unwrap().len(), 1, "one request per episode");
}

/// The ledger refuses the capture a missed admission owes. The member takes
/// the reset a refused capture always takes; no route or marker is sent on
/// a receipt with no proof behind it.
#[test]
fn ledger_refusal_at_the_basis_capture_resets_and_sends_no_marker() {
    let Divergent { mut fleet, .. } = divergent();
    let peer = fleet.members[0];
    let resets = record_resets(&mut fleet.manager);
    regroup_with(&mut fleet, peer, |manager, peer, _| {
        fill(manager, peer);
        manager
            .evpn_recovery
            .fail_allocation_after_for_test(Some(0));
        manager.evpn_recovery.fail_next_allocation_for_test();
    });
    let manager = &mut fleet.manager;
    assert!(manager.evpn_recovery_reset_pending(peer));
    assert_eq!(held_proof(manager, peer), None);
    assert!(manager.dirty_peers.contains(&peer));
    assert!(!manager.evpn_feed_is_current(peer));
    assert_eq!(manager.evpn_feed_owed_markers(peer), (false, false));
    assert_eq!(resets.lock().unwrap().len(), 1);
    drain(&mut fleet.outputs[0]);
    manager.resync_dirty_peers_bounded();
    manager.retry_eor_markers_bounded();
    for update in drain(&mut fleet.outputs[0]) {
        assert!(update.evpn_announce.is_empty() && update.evpn_withdraw.is_empty());
        assert!(!update.end_of_rib.contains(&EVPN));
    }
}

/// A fleet of two with a prepared owned destination, and its mover.
fn pair() -> (Fleet, PeerId, usize) {
    let mut fleet = evpn_fleet(2, 4, true);
    let peer = fleet.members[1];
    let old = fleet.manager.grouped_member_of(peer).unwrap();
    let new = *fleet
        .manager
        .group_ribs
        .keys()
        .find(|&&gid| gid != old)
        .unwrap();
    assert!(fleet.manager.clean_evpn_regroup_eligible(peer, new));
    fleet
        .manager
        .export_chains
        .insert(peer, Some(fleet.next.clone()));
    (fleet, peer, new)
}

/// What a regroup left behind, for comparing the two seams.
fn regroup_state(
    manager: &RibManager,
    peer: PeerId,
    feed: Option<&crate::manager::evpn_recovery::EvpnCompleteFeed>,
) -> impl PartialEq + std::fmt::Debug {
    let mut announce: Option<Vec<_>> =
        feed.map(|feed| feed.announce.iter().map(EvpnRibRoute::key).collect());
    if let Some(announce) = &mut announce {
        announce.sort_unstable();
    }
    (
        announce,
        feed.map(|feed| feed.withdraw.clone()),
        held_proof(manager, peer),
        manager.dirty_peers.contains(&peer),
        manager.has_evpn_feed_completion(peer),
        manager.evpn_recovery_reset_pending(peer),
        manager.evpn_grouped_member_of(peer),
        manager.evpn_recovery.peer_usage(peer),
    )
}

/// Every condition of eligibility refuses the proofless path on its own,
/// and the member then takes exactly the path the registration seam takes:
/// the same feed, proof, receipt and dirty state.
///
/// This pins the predicate and the fallback's state, not what each clause
/// prevents. The clean-member clauses (dirty, proof, reset, End-of-RIB,
/// private row) guard the basis itself: without them the feed would diff
/// against a projection the member does not hold. The destination clauses
/// keep the feed on a table a join cannot replace. The selection-held clause
/// keeps the gate's salvage of exempt withdrawals in the turn it runs today.
/// The remaining writer and selection clauses only avoid a feed whose commit
/// is certain to be refused: relaxing one costs a capture after the pass
/// instead of before the move, and nothing on the wire. The clean member's
/// open-writer clause is shared with the clean refresh and is equally benign
/// here, so it has no case of its own.
#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one case per eligibility condition, in one table"
)]
fn every_ineligible_member_keeps_the_proof_cycle() {
    type Spoil = fn(&mut Fleet, PeerId, usize);
    let conditions: [(&str, Spoil); 13] = [
        ("dirty", |fleet, peer, _| {
            assert!(fleet.manager.mark_outbound_dirty(peer));
        }),
        ("holds a proof", |fleet, peer, _| {
            assert!(fleet.manager.capture_shared_evpn_admitted(peer));
        }),
        ("reset pending", |fleet, peer, _| {
            let handle = fleet.manager.evpn_recovery_handle(peer).unwrap();
            assert!(fleet.manager.evpn_recovery.fail_admission(handle));
        }),
        ("owes End-of-RIB", |fleet, peer, _| {
            fleet.manager.owe_eor(peer, EVPN);
        }),
        ("holds a private EVPN row", |fleet, peer, _| {
            fleet
                .manager
                .adj_ribs_out
                .get_mut(&peer)
                .unwrap()
                .insert_evpn(evpn_row(1));
        }),
        ("selection deferred", |fleet, _, _| {
            let source = fleet.source;
            let armed = arm_selection_gate(std::mem::replace(fleet, evpn_fleet(1, 1, false)));
            *fleet = armed;
            defer_evpn_selection(&mut fleet.manager, source);
        }),
        ("selection resync held", |fleet, peer, _| {
            let unicast = (Afi::Ipv4, Safi::Unicast);
            let source = fleet.source;
            let armed =
                arm_selection_gate_for(std::mem::replace(fleet, evpn_fleet(1, 1, false)), unicast);
            *fleet = armed;
            let metrics = fleet.manager.metrics.clone();
            fleet
                .manager
                .selection_deferral
                .as_mut()
                .unwrap()
                .classify_session(source, 12, false, &HashSet::from([unicast]), &metrics);
            fleet
                .manager
                .live_sessions
                .get_mut(&peer)
                .unwrap()
                .last_mut()
                .unwrap()
                .selection_partial_pending[0] = true;
            assert!(fleet.manager.selection_resync_held(peer));
            assert!(!fleet.manager.selection_deferred(EVPN));
        }),
        ("writer full", |fleet, peer, _| fill(&fleet.manager, peer)),
        ("whole-table operation live", |fleet, peer, _| {
            std::mem::forget(fleet.manager.begin_outbound_operation(peer, 1).unwrap());
        }),
        ("no export encoder", |fleet, peer, _| {
            fleet.manager.peer_export_encoders.remove(&peer);
        }),
        ("destination absent", |fleet, peer, _| {
            fleet.next = community_chain(0xFC00_0003);
            fleet
                .manager
                .export_chains
                .insert(peer, Some(fleet.next.clone()));
        }),
        ("destination not owned", |fleet, _, new| {
            fleet
                .manager
                .group_ribs
                .get_mut(&new)
                .unwrap()
                .set_evpn_ownership_for_test(false);
        }),
        ("destination has no stamp", |fleet, _, new| {
            fleet
                .manager
                .group_ribs
                .get_mut(&new)
                .unwrap()
                .evpn_table_stamp = 0;
        }),
    ];
    for (name, spoil) in conditions {
        let run = |for_pass: bool| {
            let (mut fleet, peer, new) = pair();
            spoil(&mut fleet, peer, new);
            let GroupMembership::Grouped(destination) =
                fleet.manager.compute_update_group_membership(peer)
            else {
                panic!("groupable");
            };
            assert!(
                !fleet.manager.clean_evpn_regroup_eligible(peer, destination),
                "{name}"
            );
            let feed = if for_pass {
                fleet.manager.recompute_update_group_for_pass(peer)
            } else {
                fleet.manager.recompute_update_group(peer)
            };
            assert!(
                feed.as_ref()
                    .is_none_or(|feed| feed.seal.clean_regroup().is_none()),
                "{name}: no proofless feed"
            );
            format!("{:?}", regroup_state(&fleet.manager, peer, feed.as_ref()))
        };
        assert_eq!(run(true), run(false), "{name}");
    }
}

/// An eligible member whose feed cannot be built, because one of the two
/// projections is incomplete, has no basis to fall back on. OLD is still
/// installed at that point, so it is captured as the capturing seam captures
/// it, and the member is left in the same state.
#[test]
fn eligible_member_without_a_feed_captures_old_before_it_moves() {
    for incomplete_old in [false, true] {
        let run = |for_pass: bool| {
            let (mut fleet, peer, new) = pair();
            let old = fleet.manager.grouped_member_of(peer).unwrap();
            let gid = if incomplete_old { old } else { new };
            fleet
                .manager
                .group_ribs
                .get_mut(&gid)
                .unwrap()
                .evpn_inputs
                .remove(&key(1));
            assert!(fleet.manager.clean_evpn_regroup_eligible(peer, new));
            let feed = if for_pass {
                fleet.manager.recompute_update_group_for_pass(peer)
            } else {
                fleet.manager.recompute_update_group(peer)
            };
            assert!(feed.is_none());
            format!("{:?}", regroup_state(&fleet.manager, peer, None))
        };
        let state = run(true);
        assert_eq!(state, run(false), "incomplete_old={incomplete_old}");
        // A capture of an incomplete OLD is refused; a complete one is held.
        assert_eq!(
            state.contains("EthernetTagId(4)"),
            !incomplete_old,
            "{state}"
        );
    }
}

/// The registration seam drops the feed a regroup returns, so it never
/// takes the proofless path: an eligible member is captured before it moves.
#[test]
fn registration_seam_captures_an_eligible_member() {
    let (mut fleet, peer, new) = pair();
    let held: Vec<_> = (1..=4).map(key).collect();
    let work = super::work_scaling::checkpoints_in(|| {
        let feed = fleet.manager.recompute_update_group(peer).unwrap();
        assert!(feed.seal.clean_regroup().is_none());
    });
    assert!(work.get("capture_evpn").is_some_and(|&count| count > 0));
    assert_eq!(fleet.manager.evpn_grouped_member_of(peer), Some(new));
    let mut held = held;
    held.sort_unstable();
    assert_eq!(proof_keys(&fleet.manager, peer), Some(held));
}

/// No capture may begin for a mover between its regroup and the end of its
/// pass: the table it would walk is NEW. A staging of NEW, which captures
/// its dirty members first, and a capture run by hand are both refused and
/// reset the member with nothing captured. A proof written straight into
/// the ledger makes the seal stale, so the commit is refused and the pass
/// resets the member rather than trust either record.
#[test]
fn capture_under_a_proofless_feed_is_refused_and_resets() {
    #[derive(Clone, Copy, Debug)]
    enum Capture {
        Staging,
        ByHand,
        Ledger,
    }
    for capture in [Capture::Staging, Capture::ByHand, Capture::Ledger] {
        let (mut fleet, peer, new) = pair();
        let resets = record_resets(&mut fleet.manager);
        let work = super::work_scaling::checkpoints_in(|| {
            regroup_with(&mut fleet, peer, |manager, peer, feed| {
                let seal = &feed.as_ref().unwrap().seal;
                match capture {
                    Capture::Staging => {
                        stage(manager, new, &changed_row(1));
                        assert!(manager.evpn_recovery_reset_pending(peer));
                    }
                    Capture::ByHand => {
                        assert!(!manager.capture_shared_evpn_admitted(peer));
                        assert!(manager.evpn_recovery_reset_pending(peer));
                    }
                    Capture::Ledger => {
                        let handle = manager.evpn_recovery_handle(peer).unwrap();
                        assert_eq!(manager.evpn_recovery.begin_capture(handle), Ok(true));
                        assert_eq!(manager.evpn_recovery.seal_capture(handle), Ok(true));
                        assert!(held_proof(manager, peer).is_some());
                        assert!(!manager.evpn_recovery_reset_pending(peer));
                    }
                }
                assert!(!manager.evpn_feed_seal_is_current(peer, seal));
            });
        });
        assert_eq!(work.get("capture_evpn"), None, "{capture:?}");
        assert!(fleet.manager.evpn_recovery_reset_pending(peer));
        assert_eq!(held_proof(&fleet.manager, peer), None);
        assert_eq!(resets.lock().unwrap().len(), 1, "{capture:?}");
        for update in drain(&mut fleet.outputs[1]) {
            assert!(update.evpn_announce.is_empty() && update.evpn_withdraw.is_empty());
        }
    }
}

/// A proofless feed that never reaches a pass leaves its mover dirty with
/// neither a proof nor a reset. Debug builds refuse to drop such a feed;
/// should one be lost anyway, the next capture for that member (a staging
/// of its table, another regroup, a refresh answer) would walk NEW as
/// though it were what the member holds. It resets the member instead:
/// nothing is captured, and no EVPN route or marker follows.
#[test]
fn lost_proofless_feed_resets_at_the_next_capture() {
    #[derive(Clone, Copy, Debug)]
    enum Site {
        Staging,
        Regroup,
        Refresh,
    }
    for site in [Site::Staging, Site::Regroup, Site::Refresh] {
        let (mut fleet, peer, new) = pair();
        let resets = record_resets(&mut fleet.manager);
        let manager = &mut fleet.manager;
        let mut feed = manager.recompute_update_group_for_pass(peer);
        manager.mark_outbound_dirty_with_evpn_feed(peer, &mut feed);
        feed.unwrap()
            .seal
            .clean_regroup()
            .unwrap()
            .abandon_for_test();
        assert!(manager.dirty_peers.contains(&peer));
        assert_eq!(held_proof(manager, peer), None);
        assert!(!manager.evpn_recovery_reset_pending(peer));
        drain(&mut fleet.outputs[1]);

        let work = super::work_scaling::checkpoints_in(|| match site {
            Site::Staging => {
                stage(manager, new, &changed_row(1));
            }
            Site::Regroup => {
                manager
                    .export_chains
                    .insert(peer, Some(community_chain(0xFC00_0003)));
                assert!(manager.recompute_update_group(peer).is_none());
                assert_eq!(manager.evpn_grouped_member_of(peer), Some(new));
            }
            Site::Refresh => manager.send_route_refresh_response(peer, EVPN.0, EVPN.1),
        });
        assert_eq!(work.get("capture_evpn"), None, "{site:?}");
        assert!(manager.evpn_recovery_reset_pending(peer), "{site:?}");
        assert_eq!(held_proof(manager, peer), None, "{site:?}");
        assert!(manager.dirty_peers.contains(&peer), "{site:?}");
        {
            let requests = resets.lock().unwrap();
            assert_eq!(requests.len(), 1, "{site:?}");
            assert_eq!(
                requests[0].cause,
                EvpnRecoveryExhaustionCause::AdmissionInvariant
            );
        }
        manager.resync_dirty_peers_bounded();
        manager.retry_eor_markers_bounded();
        for update in drain(&mut fleet.outputs[1]) {
            assert!(
                update.evpn_announce.is_empty() && update.evpn_withdraw.is_empty(),
                "{site:?}"
            );
            assert!(!update.end_of_rib.contains(&EVPN), "{site:?}");
            assert!(update.refresh_markers.is_empty(), "{site:?}");
        }
    }
}

/// An exact-export encoder that closes the receiver's end of the channel
/// when the commit takes its snapshot: after the commit checked its seal and
/// reserved its slot, before the envelope is enqueued.
struct CloseOnSnapshot {
    encoder: Arc<dyn crate::update::ExactExportEncoder>,
    receiver: std::sync::Mutex<Option<mpsc::Receiver<OutboundRouteUpdate>>>,
}

impl crate::update::ExactExportEncoder for CloseOnSnapshot {
    fn owner_id(&self) -> u64 {
        self.encoder.owner_id()
    }

    fn snapshot(&self) -> Arc<dyn crate::update::ExactExportSnapshot> {
        self.receiver.lock().unwrap().take();
        self.encoder.snapshot()
    }
}

/// Completion checks the seal again, after the enqueue. A channel that
/// closes inside the commit leaves an admitted envelope the completion
/// cannot vouch for: the member is reset, and the pass does not capture OLD
/// over a wire that may have left it.
#[test]
fn seal_that_goes_stale_inside_the_commit_resets_at_completion() {
    let (mut fleet, peer, _new) = pair();
    let resets = record_resets(&mut fleet.manager);
    let (_sender, idle) = mpsc::channel(1);
    let receiver = std::mem::replace(&mut fleet.outputs[1], idle);
    let closing = Arc::new(CloseOnSnapshot {
        encoder: Arc::clone(&fleet.manager.peer_export_encoders[&peer]),
        receiver: std::sync::Mutex::new(Some(receiver)),
    });
    fleet
        .manager
        .peer_export_encoders
        .insert(peer, closing.clone());
    let work = super::work_scaling::checkpoints_in(|| {
        regroup_with(&mut fleet, peer, |manager, peer, feed| {
            assert!(manager.evpn_feed_seal_is_current(peer, &feed.as_ref().unwrap().seal));
        });
    });
    assert!(closing.receiver.lock().unwrap().is_none(), "the commit ran");
    assert!(fleet.manager.outbound_peers[&peer].is_closed());
    assert_eq!(work.get("capture_evpn"), None);
    assert!(fleet.manager.evpn_recovery_reset_pending(peer));
    assert_eq!(held_proof(&fleet.manager, peer), None);
    assert!(
        !fleet.manager.has_evpn_feed_completion(peer) || !fleet.manager.evpn_feed_is_current(peer)
    );
    assert_eq!(
        resets.lock().unwrap()[0].cause,
        EvpnRecoveryExhaustionCause::AdmissionInvariant
    );
}

/// The paced loop's shape by hand: every member regroups, then one pass
/// takes all the feeds. `missed` movers have their writer filled between
/// the loop and the pass; with `gate`, the pass skips every dirty member
/// instead (a selection release is staging). Each basis is settled after
/// the other movers joined NEW and the last of them retired OLD.
fn fleet_pass(missed: &[usize], gate: bool) {
    let context = format!("missed={missed:?} gate={gate}");
    let Divergent {
        mut fleet,
        old,
        new,
    } = divergent();
    let members = fleet.members.clone();
    let resets = record_resets(&mut fleet.manager);
    let mut feeds = HashMap::new();
    for &peer in &members {
        let manager = &mut fleet.manager;
        manager.export_chains.insert(peer, Some(fleet.next.clone()));
        let mut feed = manager.recompute_update_group_for_pass(peer);
        manager.mark_outbound_dirty_with_evpn_feed(peer, &mut feed);
        let feed = feed.expect("a feed per mover");
        assert!(feed.seal.clean_regroup().is_some(), "{context}");
        feeds.insert(peer, feed);
    }
    assert!(!fleet.manager.group_ribs.contains_key(&old), "{context}");
    for &index in missed {
        fill(&fleet.manager, members[index]);
    }
    fleet.manager.selection_release_staging = gate;
    fleet
        .manager
        .distribute_changes_with_evpn_feeds(feeds, false);
    fleet.manager.selection_release_staging = false;
    let wire_after = |updates: &[OutboundRouteUpdate], index: usize, context: &str| {
        let mut wire: HashSet<_> = expected_old()[index].iter().copied().collect();
        for update in updates {
            for key in &update.evpn_withdraw {
                assert!(wire.remove(key), "{context}: withdrew {key:?} unheld");
            }
            wire.extend(update.evpn_announce.iter().map(EvpnRibRoute::key));
        }
        let mut wire: Vec<_> = wire.into_iter().collect();
        wire.sort_unstable();
        wire
    };
    for (index, &peer) in members.iter().enumerate() {
        let context = format!("{context} member={index}");
        let manager = &fleet.manager;
        assert_eq!(manager.evpn_grouped_member_of(peer), Some(new), "{context}");
        let updates = drain(&mut fleet.outputs[index]);
        if gate || missed.contains(&index) {
            assert_eq!(
                proof_keys(manager, peer),
                Some(expected_old()[index].clone()),
                "{context}"
            );
            assert!(manager.dirty_peers.contains(&peer), "{context}");
            assert_eq!(
                manager.evpn_admitted_count(peer),
                expected_old()[index].len(),
                "{context}"
            );
            assert_eq!(
                wire_after(&updates, index, &context),
                expected_old()[index],
                "{context}: nothing was sent"
            );
        } else {
            assert_eq!(proof_keys(manager, peer), None, "{context}");
            assert!(!manager.dirty_peers.contains(&peer), "{context}");
            assert_eq!(
                wire_after(&updates, index, &context),
                expected_new()[index],
                "{context}"
            );
            assert_eq!(
                manager.evpn_admitted_count(peer),
                expected_new()[index].len(),
                "{context}"
            );
        }
        assert_proof_only_while_owed(manager, peer);
    }
    fleet.manager.resync_dirty_peers_bounded();
    for (index, &peer) in members.iter().enumerate() {
        if !(gate || missed.contains(&index)) {
            continue;
        }
        let context = format!("{context} member={index} healed");
        let updates = drain(&mut fleet.outputs[index]);
        assert_eq!(
            wire_after(&updates, index, &context),
            expected_new()[index],
            "{context}"
        );
        assert_eq!(proof_keys(&fleet.manager, peer), None, "{context}");
        assert!(!fleet.manager.dirty_peers.contains(&peer), "{context}");
        assert_eq!(
            fleet.manager.evpn_admitted_count(peer),
            expected_new()[index].len(),
            "{context}"
        );
    }
    assert!(resets.lock().unwrap().is_empty(), "{context}");
}

/// Three movers in one pass, for every subset whose admission is missed and
/// for a pass that skips them all: each missed mover's proof is its own
/// actual OLD, each admitted mover is clean on NEW, the resync heals the
/// missed ones onto NEW with no unheld withdrawal, and nothing resets.
#[test]
fn several_movers_in_one_pass_settle_each_missed_admission() {
    for missed in [&[0][..], &[1], &[2], &[0, 1], &[1, 2], &[0, 2], &[0, 1, 2]] {
        fleet_pass(missed, false);
    }
    fleet_pass(&[], true);
}

/// A basis with many fresh keys. The group table iterates in hash order,
/// and the basis is searched by key, so it must be kept in key order: an
/// unsorted one would count fresh keys as held and capture them as OLD.
#[test]
fn basis_with_many_fresh_keys_reconstructs_actual_old() {
    let mut fleet = evpn_fleet(2, 40, true);
    let peer = fleet.members[1];
    // OLD loses rows 5..=40; the memberless prepared destination keeps them.
    fleet
        .manager
        .process_evpn_withdraw_chunk(fleet.source, (5..=40).map(key).collect());
    drain(&mut fleet.outputs[1]);
    assert_eq!(fleet.manager.evpn_admitted_count(peer), 4);
    regroup_with(&mut fleet, peer, |manager, peer, feed| {
        assert!(feed.as_ref().unwrap().seal.clean_regroup().is_some());
        fill(manager, peer);
    });
    assert_eq!(proof_keys(&fleet.manager, peer), Some(keys(&[1, 2, 3, 4])));
}

/// An admitted envelope whose completion then fails cannot be undone, and
/// no proof records what it admitted: the member is reset, and the pass
/// does not capture OLD over a wire that has left it.
#[test]
fn admitted_regroup_that_fails_completion_resets() {
    let (mut fleet, peer, _new) = pair();
    let resets = record_resets(&mut fleet.manager);
    let work = super::work_scaling::checkpoints_in(|| {
        regroup_with(&mut fleet, peer, |manager, _, _| {
            manager.adj_rib_out_commit_stats.fail_evpn_feed_completion = true;
        });
    });
    assert_eq!(work.get("capture_evpn"), None);
    let sent: usize = drain(&mut fleet.outputs[1])
        .iter()
        .map(|update| update.evpn_announce.len())
        .sum();
    assert_eq!(sent, 4, "the envelope was admitted");
    assert!(fleet.manager.evpn_recovery_reset_pending(peer));
    assert_eq!(held_proof(&fleet.manager, peer), None);
    assert!(fleet.manager.dirty_peers.contains(&peer));
    assert_eq!(
        resets.lock().unwrap()[0].cause,
        EvpnRecoveryExhaustionCause::AdmissionInvariant
    );
}

/// A terminal marker the admitted regroup leaves owed outlives the turn, so
/// its proof is captured at completion from the member's NEW projection,
/// exact rejection included, and held until the marker leaves.
#[test]
fn regroup_that_leaves_a_marker_owed_captures_the_admitted_set() {
    let (mut fleet, peer, new) = pair();
    let encoder = MockExactExportEncoder::accepting(1);
    encoder.set_profile(2, [ExactExportKey::Evpn(key(2))]);
    fleet.manager.peer_export_encoders.insert(peer, encoder);
    let mut feed = fleet.manager.recompute_update_group_for_pass(peer);
    fleet
        .manager
        .mark_outbound_dirty_with_evpn_feed(peer, &mut feed);
    let mut feed = feed.unwrap();
    let basis = feed.seal.clean_regroup().unwrap().clone();
    feed.seal.required_markers = RibManager::evpn_admitted_marker_bits(&[EVPN], &[]);
    assert_eq!(
        fleet.manager.try_send_and_commit_outbound_update(
            peer,
            OutboundCommitBatch {
                evpn_announce: feed.announce.into(),
                evpn_withdraw: feed.withdraw,
                evpn_complete_feed: Some(feed.seal),
                ..OutboundCommitBatch::default()
            }
        ),
        Ok(())
    );
    fleet.manager.settle_clean_evpn_regroup(peer, &basis);
    assert_eq!(fleet.manager.evpn_grouped_member_of(peer), Some(new));
    assert!(fleet.manager.evpn_feed_is_current(peer));
    assert_eq!(fleet.manager.evpn_feed_owed_markers(peer), (true, false));
    assert_eq!(
        proof_keys(&fleet.manager, peer),
        Some(keys(&[1, 3, 4])),
        "the admitted set, less the row the probe rejected"
    );
    assert!(!fleet.manager.evpn_recovery_reset_pending(peer));
}

/// A commit that carries no clean-regroup seal cannot ride the proofless
/// admission: a dirty grouped member with a dormant handle is refused, as
/// before, even inside the regroup's own turn.
#[test]
fn unsealed_commit_of_a_proofless_mover_is_refused() {
    let (mut fleet, peer, _new) = pair();
    regroup_with(&mut fleet, peer, |manager, peer, feed| {
        let seal_free = OutboundCommitBatch {
            evpn_announce: feed.as_ref().unwrap().announce.clone().into(),
            ..OutboundCommitBatch::default()
        };
        assert_eq!(
            manager.try_send_and_commit_outbound_update(peer, seal_free),
            Err(OutboundCommitFailure::Refused(
                OutboundCommitRefusal::EvpnRecovery
            ))
        );
    });
    assert_eq!(proof_keys(&fleet.manager, peer), None);
    assert!(!fleet.manager.dirty_peers.contains(&peer));
}
