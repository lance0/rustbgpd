use std::sync::atomic::{AtomicUsize, Ordering};

use super::exportability::MockExactExportEncoder;
use super::*;
use crate::manager::distribution::OutboundCommitBatch;
use crate::manager::update_groups::recovery_provenance::{
    EvpnRecoveryProvenance, FinalAdmissionFault,
};
use crate::update::ExactExportKey;
use crate::update::{
    EvpnRecoveryExhaustionCause, EvpnRecoveryReset, EvpnRecoveryResetOutcome, RoutePageError,
};

type ResetRequests =
    Arc<std::sync::Mutex<Vec<(EvpnRecoveryReset, oneshot::Sender<EvpnRecoveryResetOutcome>)>>>;

fn capture_reset_requests(manager: &mut RibManager) -> ResetRequests {
    let requests = Arc::new(std::sync::Mutex::new(Vec::new()));
    let captured = requests.clone();
    manager.evpn_recovery_reset = Some(Arc::new(move |request, reply| {
        captured.lock().unwrap().push((request, reply));
        true
    }));
    requests
}

fn fixture(capacity: usize) -> (RibManager, IpAddr, mpsc::Receiver<OutboundRouteUpdate>) {
    let (_tx, rx) = mpsc::channel(8);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let peer: IpAddr = "192.0.2.30".parse().unwrap();
    let (sender, mut output) = mpsc::channel(capacity);
    register(&mut manager, peer, sender);
    while output.try_recv().is_ok() {}
    // Settle any ordinary registration deferral before enabling ownership.
    for _ in 0..3 {
        if !manager.dirty_peers.contains(&peer) {
            break;
        }
        manager.resync_dirty_peers_bounded();
        while output.try_recv().is_ok() {}
    }
    assert!(!manager.dirty_peers.contains(&peer));
    assert!(manager.grouped_member_of(peer).is_some());
    (manager, peer, output)
}

fn register(manager: &mut RibManager, peer: IpAddr, sender: mpsc::Sender<OutboundRouteUpdate>) {
    register_session(manager, peer, sender, 7);
}

fn register_session(
    manager: &mut RibManager,
    peer: IpAddr,
    sender: mpsc::Sender<OutboundRouteUpdate>,
    session_id: u64,
) {
    manager.handle_update(RibUpdate::PeerUp {
        peer,
        session_id,
        peer_asn: 65000,
        peer_router_id: "192.0.2.30".parse().unwrap(),
        outbound_tx: sender,
        export_policy: None,
        sendable_families: vec![(Afi::Ipv4, Safi::Unicast), (Afi::L2Vpn, Safi::Evpn)],
        is_ebgp: false,
        route_reflector_client: false,
        orr_vantage: None,
        per_client_best: false,
        interpret_rfc1997: true,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: vec![],
        negotiated_llgr_families: vec![],
    });
}

fn own(manager: &mut RibManager, peer: IpAddr, fresh: bool) {
    let gid = manager.grouped_member_of(peer).unwrap();
    manager.group_ribs.get_mut(&gid).unwrap().owns_evpn = true;
    assert!(manager.register_evpn_recovery(peer, fresh));
}

fn route(tag: u32) -> EvpnRibRoute {
    make_evpn_imet("192.0.2.10".parse().unwrap(), tag)
}

#[test]
fn negotiated_evpn_and_unicast_grouping_do_not_own_evpn() {
    let (mut manager, peer, _output) = fixture(8);
    let gid = manager.grouped_member_of(peer).unwrap();
    assert!(
        manager.group_ribs[&gid]
            .sendable
            .contains(&(Afi::L2Vpn, Safi::Evpn))
    );
    manager.mark_outbound_dirty(peer);
    assert!(manager.evpn_grouped_member_of(peer).is_none());
    assert!(manager.evpn_recovery_handle(peer).is_none());
    assert!(!manager.evpn_advertised_resync_in_progress(peer));
    assert!(!manager.capture_evpn_recovery_before_projection(peer, [route(1).key()].into_iter()));
}

#[test]
fn owned_capture_is_retained_across_stale_membership_changes_and_generic_cleanup() {
    let (mut manager, peer, _output) = fixture(8);
    own(&mut manager, peer, false);
    let old = route(1).key();
    assert!(manager.capture_evpn_recovery_before_projection(peer, [old].into_iter()));
    let handle = manager.evpn_recovery_handle(peer).unwrap();
    manager.mark_outbound_dirty(peer);
    manager.set_rt_membership(
        peer,
        Some(RtcMembership {
            has_default: true,
            entries: vec![],
        }),
    );
    manager.set_rt_membership(peer, Some(RtcMembership::default()));
    assert_eq!(
        manager.evpn_recovery.proof_keys(handle).unwrap(),
        Some([old].to_vec())
    );
    // A new desired iterator must not overwrite an already-owned prior proof.
    assert!(manager.capture_evpn_recovery_before_projection(peer, [route(2).key()].into_iter()));
    assert_eq!(
        manager.evpn_recovery.proof_keys(handle).unwrap(),
        Some([old].to_vec())
    );
    let prior_uc = manager.pending_group_admitted.owned_proof(&peer);
    manager.dirty_peers.remove(&peer);
    manager.clear_grouped_member_synced(peer);
    assert!(manager.dirty_peers.contains(&peer));
    assert_eq!(manager.pending_group_admitted.owned_proof(&peer), prior_uc);
    assert_eq!(
        manager.evpn_recovery.proof_keys(handle).unwrap(),
        Some([old].to_vec())
    );
    assert!(!manager.settle_evpn_recovery(peer, [route(2).key()].into_iter()));
    assert!(manager.settle_evpn_recovery(peer, [old].into_iter()));
    manager.dirty_peers.remove(&peer);
    manager.clear_grouped_member_synced(peer);
    assert!(manager.evpn_recovery.is_dormant(handle));
    assert!(!manager.evpn_advertised_resync_in_progress(peer));
}

#[test]
fn outbound_queue_credit_precedes_provenance_growth_and_reset_handoff() {
    let (mut manager, peer, mut output) = fixture(1);
    own(&mut manager, peer, true);
    let calls = Arc::new(AtomicUsize::new(0));
    let seen = calls.clone();
    manager.evpn_recovery_reset = Some(Arc::new(move |_, _reply| {
        seen.fetch_add(1, Ordering::SeqCst);
        false
    }));
    let unicast = make_route(
        Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 1), 32),
        Ipv4Addr::new(192, 0, 2, 10),
    );
    manager
        .outbound_prefix_limits
        .entry(peer)
        .or_default()
        .family_mut(Afi::Ipv4)
        .unwrap()
        .limit = std::num::NonZeroU32::new(1);
    let gid = manager.grouped_member_of(peer).unwrap();
    manager
        .group_ribs
        .get_mut(&gid)
        .unwrap()
        .table
        .insert(unicast.clone());
    manager
        .pending_group_admitted
        .remove_with_checkpoint(&peer, &mut |_| {});
    assert!(!manager.pending_group_admitted.contains_record(peer));
    let admitted_before = (
        manager.pending_group_admitted.owned_proof(&peer),
        manager.pending_group_admitted.bytes(),
        manager.pending_group_admitted.peak_bytes(),
        manager.group_ribs[&gid].recovery_snapshot_for_test(),
    );
    let batch = || OutboundCommitBatch {
        evpn_announce: vec![route(1)],
        ..OutboundCommitBatch::with_unicast(Arc::new(vec![unicast.clone()]), Arc::new(vec![None]))
    };
    manager.outbound_peers[&peer]
        .try_send(OutboundRouteUpdate::default())
        .unwrap();
    let before = manager.evpn_recovery.daemon_usage();
    manager.evpn_recovery.fail_next_allocation_for_test();
    assert!(
        manager
            .try_send_and_commit_outbound_update(peer, batch())
            .is_err()
    );
    assert_eq!(manager.evpn_recovery.daemon_usage(), before);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    output.try_recv().unwrap();
    assert!(
        manager
            .try_send_and_commit_outbound_update(peer, batch())
            .is_err()
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert!(manager.evpn_recovery_reset_pending(peer));
    assert!(output.try_recv().is_err());
    assert_eq!(
        (
            manager.pending_group_admitted.owned_proof(&peer),
            manager.pending_group_admitted.bytes(),
            manager.pending_group_admitted.peak_bytes(),
            manager.group_ribs[&gid].recovery_snapshot_for_test()
        ),
        admitted_before
    );
    assert!(
        manager.adj_ribs_out[&peer]
            .get(&unicast.prefix, unicast.path_id)
            .is_none()
    );
    let limits = &manager.outbound_prefix_limits[&peer];
    assert_eq!(limits.grouped_len(Afi::Ipv4), 0);
    assert!(!limits.grouped_contains(&unicast.prefix));
    assert!(!limits.family(Afi::Ipv4).unwrap().blocking);
    assert!(!manager.finish_evpn_recovery(peer));
    assert!(manager.dirty_peers.contains(&peer));
}

#[test]
fn incomplete_owned_capture_requests_one_fenced_reset_before_mixed_family_admission() {
    let (mut manager, peer, mut output) = fixture(8);
    own(&mut manager, peer, true);
    let handle = manager.evpn_recovery_handle(peer).unwrap();
    assert!(manager.evpn_recovery.finish_recovery(handle).unwrap());
    assert!(manager.evpn_recovery.begin_capture(handle).unwrap());
    assert!(manager.evpn_recovery.proof(handle).unwrap().is_none());
    // Inject an unfinished producer. Ordinary capture completes synchronously;
    // this control pins the refusal if that internal invariant is ever broken.
    let requests = capture_reset_requests(&mut manager);
    let unicast = make_route(
        Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 1), 32),
        Ipv4Addr::new(192, 0, 2, 10),
    );
    let gid = manager.grouped_member_of(peer).unwrap();
    manager
        .group_ribs
        .get_mut(&gid)
        .unwrap()
        .table
        .insert(unicast.clone());
    manager
        .pending_group_admitted
        .remove_with_checkpoint(&peer, &mut |_| {});
    assert!(!manager.pending_group_admitted.contains_record(peer));
    let common_before = (
        manager.pending_group_admitted.owned_proof(&peer),
        manager.pending_group_admitted.bytes(),
        manager.pending_group_admitted.peak_bytes(),
        manager.group_ribs[&gid].recovery_snapshot_for_test(),
    );
    let batch = || OutboundCommitBatch {
        evpn_announce: vec![route(1)],
        ..OutboundCommitBatch::with_unicast(Arc::new(vec![unicast.clone()]), Arc::new(vec![None]))
    };
    assert!(
        manager
            .try_send_and_commit_outbound_update(peer, batch())
            .is_err()
    );
    {
        let requests = requests.lock().unwrap();
        assert_eq!(
            requests.len(),
            1,
            "incomplete proof must produce a real reset handoff, not a silent refusal"
        );
        let request = &requests[0].0;
        assert_eq!(request.peer, peer);
        assert_eq!(request.session_id, 7);
        assert_eq!(request.session_id, manager.outbound_session_ids[&peer]);
        assert!(
            request
                .outbound
                .same_channel(&manager.outbound_peers[&peer])
        );
        assert_eq!(
            request.cause,
            EvpnRecoveryExhaustionCause::AdmissionInvariant
        );
    }
    for _ in 0..5 {
        assert!(
            manager
                .try_send_and_commit_outbound_update(peer, batch())
                .is_err()
        );
        manager.retry_evpn_recovery_reset(peer);
        assert_eq!(requests.lock().unwrap().len(), 1, "one inflight receipt");
        assert!(manager.dirty_peers.contains(&peer));
        assert!(output.try_recv().is_err(), "no UC or EVPN batch admitted");
    }
    assert!(
        manager.adj_ribs_out[&peer]
            .get(&unicast.prefix, unicast.path_id)
            .is_none()
    );
    assert_eq!(
        manager.evpn_recovery.exhaustion(handle).unwrap().cause,
        EvpnRecoveryExhaustionCause::AdmissionInvariant
    );
    let (_, reply) = requests.lock().unwrap().pop().unwrap();
    reply.send(EvpnRecoveryResetOutcome::Executed).unwrap();
    manager.retry_evpn_recovery_reset(peer);
    assert!(manager.evpn_recovery.reset_admitted(handle));
    manager.retry_evpn_recovery_reset(peer);
    assert!(requests.lock().unwrap().is_empty());
    assert!(output.try_recv().is_err());
    assert_eq!(
        (
            manager.pending_group_admitted.owned_proof(&peer),
            manager.pending_group_admitted.bytes(),
            manager.pending_group_admitted.peak_bytes(),
            manager.group_ribs[&gid].recovery_snapshot_for_test()
        ),
        common_before
    );
}

#[test]
fn reset_refusal_retries_once_accepted_and_stays_exhausted_until_teardown() {
    let (mut manager, peer, _output) = fixture(8);
    own(&mut manager, peer, true);
    let requests = Arc::new(std::sync::Mutex::new(Vec::<EvpnRecoveryReset>::new()));
    let captured = requests.clone();
    manager.evpn_recovery_reset = Some(Arc::new(move |request, reply| {
        let mut requests = captured.lock().unwrap();
        requests.push(request);
        if requests.len() >= 2 {
            reply.send(EvpnRecoveryResetOutcome::Executed).unwrap();
            true
        } else {
            false
        }
    }));
    manager.evpn_recovery.fail_next_allocation_for_test();
    assert!(
        manager
            .try_send_and_commit_outbound_update(
                peer,
                OutboundCommitBatch {
                    evpn_announce: vec![route(1)],
                    ..OutboundCommitBatch::default()
                }
            )
            .is_err()
    );
    manager.resync_dirty_peers_bounded();
    manager.resync_dirty_peers_bounded();
    let handle = manager.evpn_recovery_handle(peer).unwrap();
    assert!(manager.evpn_recovery.reset_admitted(handle));
    assert_eq!(requests.lock().unwrap().len(), 2);
    assert_eq!(requests.lock().unwrap()[0].session_id, 7);
    assert!(
        requests.lock().unwrap()[0]
            .outbound
            .same_channel(&manager.outbound_peers[&peer])
    );
    assert!(manager.evpn_recovery_reset_pending(peer));
    assert!(!manager.settle_evpn_recovery(peer, [].into_iter()));
    manager.clear_outbound_peer_state(peer);
    assert!(manager.evpn_recovery.proof_keys(handle).unwrap().is_none());
}

#[test]
fn reset_execution_receipt_bounds_inflight_and_retries_rejection_and_drop() {
    let (mut manager, peer, mut output) = fixture(8);
    own(&mut manager, peer, true);
    let requests = capture_reset_requests(&mut manager);
    let handle = manager.evpn_recovery_handle(peer).unwrap();
    manager.evpn_recovery.fail_next_allocation_for_test();
    assert!(
        manager
            .try_send_and_commit_outbound_update(
                peer,
                OutboundCommitBatch {
                    evpn_announce: vec![route(1)],
                    ..OutboundCommitBatch::default()
                }
            )
            .is_err()
    );
    assert!(!manager.evpn_recovery.reset_admitted(handle));
    manager.retry_evpn_recovery_reset(peer);
    assert_eq!(requests.lock().unwrap().len(), 1, "one inflight receipt");
    let (_, reply) = requests.lock().unwrap().pop().unwrap();
    reply.send(EvpnRecoveryResetOutcome::Rejected).unwrap();
    manager.retry_evpn_recovery_reset(peer);
    assert!(!manager.evpn_recovery.reset_admitted(handle));
    assert_eq!(requests.lock().unwrap().len(), 1);
    let (_, reply) = requests.lock().unwrap().pop().unwrap();
    drop(reply);
    manager.retry_evpn_recovery_reset(peer);
    assert!(!manager.evpn_recovery.reset_admitted(handle));
    assert_eq!(requests.lock().unwrap().len(), 1);
    let (_, reply) = requests.lock().unwrap().pop().unwrap();
    reply.send(EvpnRecoveryResetOutcome::Executed).unwrap();
    manager.retry_evpn_recovery_reset(peer);
    assert!(manager.evpn_recovery.reset_admitted(handle));
    for _ in 0..5 {
        manager.retry_evpn_recovery_reset(peer);
    }
    assert!(requests.lock().unwrap().is_empty());
    assert!(
        output.try_recv().is_err(),
        "no route admission while exhausted"
    );
    assert!(
        manager.live_sessions[&peer]
            .last()
            .unwrap()
            .evpn_recovery_reset_retry_reported
    );
}

#[test]
fn exact_replay_moves_the_pending_execution_receipt_without_a_second_attempt() {
    let (mut manager, peer, _output) = fixture(8);
    manager.evpn_recovery = EvpnRecoveryProvenance::with_test_limits(0, 1024 * 1024);
    let gid = manager.grouped_member_of(peer).unwrap();
    manager.group_ribs.get_mut(&gid).unwrap().owns_evpn = true;
    let requests = capture_reset_requests(&mut manager);
    assert!(!manager.register_evpn_recovery(peer, true));
    let (_, reply) = requests.lock().unwrap().pop().unwrap();
    let same_sender = manager.outbound_peers[&peer].clone();
    register(&mut manager, peer, same_sender);
    manager.retry_evpn_recovery_reset(peer);
    assert!(requests.lock().unwrap().is_empty());
    reply.send(EvpnRecoveryResetOutcome::Executed).unwrap();
    manager.retry_evpn_recovery_reset(peer);
    let record = manager.live_sessions[&peer].last().unwrap();
    assert!(record.evpn_recovery_reset.is_some());
    assert!(record.evpn_recovery_reset_receipt.is_none());
    manager.retry_evpn_recovery_reset(peer);
    assert!(
        requests.lock().unwrap().is_empty(),
        "executed receipt suppresses retry"
    );
}

#[test]
fn replaced_connection_discards_old_execution_receipt_with_the_same_actor_id() {
    let (mut manager, peer, _output) = fixture(8);
    manager.evpn_recovery = EvpnRecoveryProvenance::with_test_limits(0, 1024 * 1024);
    let gid = manager.grouped_member_of(peer).unwrap();
    manager.group_ribs.get_mut(&gid).unwrap().owns_evpn = true;
    let requests = capture_reset_requests(&mut manager);
    assert!(!manager.register_evpn_recovery(peer, true));
    let (old, old_reply) = requests.lock().unwrap().pop().unwrap();
    let (replacement, _replacement_output) = mpsc::channel(8);
    register(&mut manager, peer, replacement);
    assert!(!old.outbound.same_channel(&manager.outbound_peers[&peer]));
    assert_eq!(
        old_reply.send(EvpnRecoveryResetOutcome::Executed),
        Err(EvpnRecoveryResetOutcome::Executed)
    );
    let gid = manager.grouped_member_of(peer).unwrap();
    manager.group_ribs.get_mut(&gid).unwrap().owns_evpn = true;
    assert!(!manager.register_evpn_recovery(peer, true));
    manager.retry_evpn_recovery_reset(peer);
    let record = manager.live_sessions[&peer].last().unwrap();
    assert!(record.evpn_recovery_reset.is_some());
    assert!(record.evpn_recovery_reset_receipt.is_some());
    assert_eq!(
        requests.lock().unwrap().len(),
        1,
        "fresh token owns its own attempt"
    );
}

#[test]
fn final_admission_filters_unknown_withdrawals_and_releases_only_after_settlement() {
    let (mut manager, peer, mut output) = fixture(8);
    own(&mut manager, peer, true);
    let known = route(1);
    assert!(
        manager
            .try_send_and_commit_outbound_update(
                peer,
                OutboundCommitBatch {
                    evpn_announce: vec![known.clone()],
                    ..OutboundCommitBatch::default()
                }
            )
            .is_ok()
    );
    output.try_recv().unwrap();
    let handle = manager.evpn_recovery_handle(peer).unwrap();
    assert_eq!(
        manager.evpn_recovery.proof_keys(handle).unwrap(),
        Some([known.key()].to_vec())
    );
    assert!(
        manager
            .try_send_and_commit_outbound_update(
                peer,
                OutboundCommitBatch {
                    evpn_withdraw: vec![route(2).key(), known.key(), known.key()],
                    ..OutboundCommitBatch::default()
                }
            )
            .is_ok()
    );
    assert_eq!(output.try_recv().unwrap().evpn_withdraw, vec![known.key()]);
    let retained = manager.evpn_recovery.daemon_usage().retained;
    assert!(manager.settle_evpn_recovery(peer, [].into_iter()));
    assert!(manager.evpn_recovery.daemon_usage().retained < retained);
    assert!(manager.evpn_recovery_handle(peer).is_some());
}

#[test]
fn reconnect_reuses_actor_id_but_retires_the_old_channel_owner() {
    let (mut manager, peer, _old_output) = fixture(8);
    own(&mut manager, peer, false);
    assert!(manager.capture_evpn_recovery_before_projection(peer, [route(1).key()].into_iter()));
    let old = manager.evpn_recovery_handle(peer).unwrap();
    let old_sender = manager.outbound_peers[&peer].clone();
    let (replacement, mut output) = mpsc::channel(8);
    register(&mut manager, peer, replacement.clone());
    while output.try_recv().is_ok() {}
    assert!(manager.evpn_recovery.proof_keys(old).unwrap().is_none());
    assert!(!old_sender.same_channel(&replacement));
    own(&mut manager, peer, true);
    let new = manager.evpn_recovery_handle(peer).unwrap();
    assert_ne!(old, new);
    assert_eq!(
        manager.evpn_recovery.proof_keys(new).unwrap(),
        Some([].to_vec())
    );
}

#[test]
fn same_connection_capture_refusal_resets_instead_of_stalling_across_five_resync_rounds() {
    let (mut manager, peer, mut output) = fixture(8);
    own(&mut manager, peer, true);
    let owner = manager.evpn_recovery_handle(peer).unwrap();
    assert!(manager.settle_evpn_recovery(peer, [].into_iter()));
    assert!(manager.evpn_recovery.is_dormant(owner));
    manager
        .adj_ribs_out
        .get_mut(&peer)
        .unwrap()
        .insert_evpn(route(1));
    let requests = capture_reset_requests(&mut manager);
    let same_sender = manager.outbound_peers[&peer].clone();
    register(&mut manager, peer, same_sender);
    assert_eq!(manager.evpn_recovery_handle(peer), Some(owner));
    let error = manager.evpn_recovery.exhaustion(owner).unwrap();
    assert_eq!(
        error.cause,
        crate::update::EvpnRecoveryExhaustionCause::CaptureUnavailable
    );
    assert_eq!(manager.evpn_recovery.proof_keys(owner), Err(error));
    for _ in 0..5 {
        manager.resync_dirty_peers_bounded();
        assert!(manager.dirty_peers.contains(&peer));
        assert!(manager.evpn_recovery_reset_pending(peer));
        assert_eq!(
            requests.lock().unwrap().len(),
            1,
            "one execution receipt remains owned"
        );
        assert_eq!(manager.evpn_recovery.exhaustion(owner), Some(error));
        assert!(!manager.evpn_recovery.reset_admitted(owner));
        let families = manager.metrics.registry().gather();
        let resets = families
            .iter()
            .find(|family| family.name() == "bgp_evpn_recovery_provenance_exhausted_total")
            .expect("reset counter is precreated");
        assert_eq!(
            resets.get_metric().len(),
            crate::update::EvpnRecoveryExhaustionCause::ALL.len()
        );
        assert!(
            resets
                .get_metric()
                .iter()
                .all(|metric| metric.get_counter().get_value().abs() < f64::EPSILON),
            "queue admission never counts executed resets"
        );
        while let Ok(update) = output.try_recv() {
            assert!(update.evpn_announce.is_empty() && update.evpn_withdraw.is_empty());
        }
    }
    let (request, reply) = requests.lock().unwrap().pop().unwrap();
    assert_eq!(request.session_id, 7);
    assert!(
        request
            .outbound
            .same_channel(&manager.outbound_peers[&peer])
    );
    reply.send(EvpnRecoveryResetOutcome::Executed).unwrap();
    manager.resync_dirty_peers_bounded();
    assert!(manager.evpn_recovery.reset_admitted(owner));
    assert!(requests.lock().unwrap().is_empty());
    assert!(!manager.finish_evpn_recovery(peer));
    assert!(!manager.settle_evpn_recovery(peer, [].into_iter()));
    // The executed reset stays fail-closed until actual owner teardown.
    manager.handle_update(RibUpdate::PeerDown {
        peer,
        session_id: 7,
    });
    assert_eq!(manager.evpn_recovery.proof_keys(owner).unwrap(), None);
    let (replacement, _replacement_output) = mpsc::channel(8);
    register_session(&mut manager, peer, replacement, 8);
    own(&mut manager, peer, true);
    let fresh = manager.evpn_recovery_handle(peer).unwrap();
    assert_ne!(fresh, owner);
    assert_eq!(
        manager.evpn_recovery.proof_keys(fresh).unwrap(),
        Some([].to_vec())
    );
    assert!(!manager.evpn_recovery.reset_admitted(fresh));
}

#[test]
fn missing_shared_received_input_retains_capture_reset_duty_without_guessing_empty_proof() {
    let (mut manager, peer, gid, _output) = super::evpn_group_storage::fixture();
    let owner = manager.evpn_recovery_handle(peer).unwrap();
    assert!(manager.evpn_recovery.is_dormant(owner));
    manager
        .group_ribs
        .get_mut(&gid)
        .unwrap()
        .table
        .insert_evpn(route(1));
    let requests = capture_reset_requests(&mut manager);
    assert!(!manager.capture_shared_evpn_admitted(peer));
    let error = manager.evpn_recovery.exhaustion(owner).unwrap();
    assert_eq!(
        error.cause,
        crate::update::EvpnRecoveryExhaustionCause::CaptureUnavailable
    );
    assert_eq!(manager.evpn_recovery.proof_keys(owner), Err(error));
    for _ in 0..5 {
        assert!(!manager.capture_shared_evpn_admitted(peer));
        manager.resync_dirty_peers_bounded();
        assert_eq!(manager.evpn_recovery.exhaustion(owner), Some(error));
        assert_eq!(requests.lock().unwrap().len(), 1);
    }
    let (request, _) = requests.lock().unwrap().pop().unwrap();
    assert_eq!(
        request.cause,
        crate::update::EvpnRecoveryExhaustionCause::CaptureUnavailable
    );
}

#[test]
fn duplicate_candidate_announcements_refuse_the_whole_mixed_family_batch_without_panic() {
    let (mut manager, peer, mut output) = fixture(8);
    own(&mut manager, peer, true);
    let handle = manager.evpn_recovery_handle(peer).unwrap();
    let requests = capture_reset_requests(&mut manager);
    let unicast = make_route(
        Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 1), 32),
        Ipv4Addr::new(192, 0, 2, 10),
    );
    assert!(
        manager
            .try_send_and_commit_outbound_update(
                peer,
                OutboundCommitBatch {
                    evpn_announce: vec![route(1), route(1)],
                    ..OutboundCommitBatch::with_unicast(
                        Arc::new(vec![unicast.clone()]),
                        Arc::new(vec![None])
                    )
                }
            )
            .is_err()
    );
    let error = manager.evpn_recovery.exhaustion(handle).unwrap();
    assert_eq!(
        error.cause,
        crate::update::EvpnRecoveryExhaustionCause::AdmissionInvariant
    );
    assert!(
        manager.adj_ribs_out[&peer]
            .get(&unicast.prefix, unicast.path_id)
            .is_none()
    );
    assert_eq!(manager.adj_ribs_out[&peer].evpn_len(), 0);
    assert!(output.try_recv().is_err());
    assert_eq!(requests.lock().unwrap().len(), 1);
}

#[test]
fn evpn_page_guard_requires_real_owned_unsettled_state_and_preserves_cursor_precedence() {
    let (mut manager, peer, _output) = fixture(8);
    manager.mark_outbound_dirty(peer);
    let (reply, mut response) = oneshot::channel();
    manager.handle_query_evpn_routes_page(
        RouteQueryScope::Advertised { peer },
        None,
        None,
        None,
        1,
        reply,
    );
    assert!(response.try_recv().unwrap().is_ok());
    own(&mut manager, peer, true);
    let (reply, mut response) = oneshot::channel();
    manager.handle_query_evpn_routes_page(
        RouteQueryScope::Advertised { peer },
        None,
        None,
        None,
        1,
        reply,
    );
    assert!(matches!(
        response.try_recv().unwrap(),
        Err(RoutePageError::ResyncInProgress)
    ));
    let (reply, mut response) = oneshot::channel();
    manager.handle_query_evpn_routes_page(
        RouteQueryScope::Advertised { peer },
        None,
        Some((route(1).key(), peer)),
        None,
        1,
        reply,
    );
    assert!(matches!(
        response.try_recv().unwrap(),
        Err(RoutePageError::Invalidated)
    ));
}

#[test]
fn ownership_registration_refusal_has_bounded_session_reset_control() {
    let (mut manager, peer, _output) = fixture(8);
    manager.evpn_recovery = EvpnRecoveryProvenance::with_test_limits(0, 1024 * 1024);
    let gid = manager.grouped_member_of(peer).unwrap();
    manager.group_ribs.get_mut(&gid).unwrap().owns_evpn = true;
    let calls = Arc::new(AtomicUsize::new(0));
    let seen = calls.clone();
    manager.evpn_recovery_reset = Some(Arc::new(move |request, reply| {
        assert_eq!(
            request.cause,
            crate::update::EvpnRecoveryExhaustionCause::PeerLimit
        );
        seen.fetch_add(1, Ordering::SeqCst);
        reply.send(EvpnRecoveryResetOutcome::Executed).unwrap();
        true
    }));
    assert!(!manager.register_evpn_recovery(peer, true));
    assert!(manager.evpn_recovery_handle(peer).is_none());
    manager.resync_dirty_peers_bounded();
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert!(manager.evpn_recovery_reset_pending(peer));
    let same_sender = manager.outbound_peers[&peer].clone();
    register(&mut manager, peer, same_sender);
    manager.resync_dirty_peers_bounded();
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert!(manager.evpn_recovery_reset_pending(peer));
    assert!(manager.evpn_advertised_resync_in_progress(peer));
    let (replacement, _replacement_output) = mpsc::channel(8);
    register_session(&mut manager, peer, replacement, 8);
    assert!(
        manager.live_sessions[&peer]
            .iter()
            .find(|record| record.session_id == 7)
            .unwrap()
            .evpn_recovery_reset
            .is_none()
    );
    // The preparatory classifier stays off after a fresh registration;
    // explicitly commit the synthetic G2 owner for the replacement.
    let gid = manager.grouped_member_of(peer).unwrap();
    manager.group_ribs.get_mut(&gid).unwrap().owns_evpn = true;
    assert!(!manager.register_evpn_recovery(peer, true));
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    manager.clear_outbound_peer_state(peer);
    assert!(!manager.evpn_recovery_reset_pending(peer));
}

struct FinalTransactionFixture {
    manager: RibManager,
    peer: IpAddr,
    gid: usize,
    output: mpsc::Receiver<OutboundRouteUpdate>,
    encoder: Arc<MockExactExportEncoder>,
    unicast: Route,
    rejected: Route,
    otc: Route,
}

impl FinalTransactionFixture {
    fn new(deferred_capture: bool) -> Self {
        let (mut manager, peer, mut output) = fixture(8);
        own(&mut manager, peer, true);
        let encoder = MockExactExportEncoder::accepting(1);
        manager.peer_export_encoders.insert(peer, encoder.clone());
        assert!(
            manager
                .try_send_and_commit_outbound_update(
                    peer,
                    OutboundCommitBatch {
                        evpn_announce: vec![route(1)],
                        ..OutboundCommitBatch::default()
                    }
                )
                .is_ok()
        );
        let first = output.try_recv().unwrap();
        assert_eq!(first.evpn_announce.len(), 1);
        assert_eq!(first.evpn_announce[0].key(), route(1).key());
        assert!(output.try_recv().is_err());

        let unicast = make_route(
            Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 1), 32),
            Ipv4Addr::new(192, 0, 2, 10),
        );
        let mut rejected = unicast.clone();
        rejected.prefix = Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 2), 32));
        let rejected_key = ExactExportKey::Unicast(rejected.prefix, rejected.path_id);
        encoder.set_profile(2, [rejected_key.clone()]);
        assert!(
            manager
                .try_send_and_commit_outbound_update(
                    peer,
                    OutboundCommitBatch::with_unicast(
                        Arc::new(vec![rejected.clone()]),
                        Arc::new(vec![None])
                    )
                )
                .is_ok()
        );
        let rejection = output.try_recv().unwrap();
        assert!(rejection.announce.is_empty() && rejection.withdraw.is_empty());
        assert_eq!(
            manager.peer_unexportable[&peer],
            HashSet::from([rejected_key])
        );
        assert!(output.try_recv().is_err());

        let gid = manager.grouped_member_of(peer).unwrap();
        manager
            .group_ribs
            .get_mut(&gid)
            .unwrap()
            .table
            .insert(unicast.clone());
        manager.pending_regroup_baseline.insert(
            peer,
            super::super::update_groups::RegroupBaseline::default(),
        );
        if !deferred_capture {
            manager
                .pending_group_admitted
                .insert_empty_with_checkpoint(peer, &mut |_| {})
                .unwrap();
        }
        manager
            .outbound_prefix_limits
            .entry(peer)
            .or_default()
            .family_mut(Afi::Ipv4)
            .unwrap()
            .limit = std::num::NonZeroU32::new(1);
        let mut otc = unicast.clone();
        otc.prefix = Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 3), 32));
        crate::attr_set::AttrSet::edit(&mut otc.attributes, |attrs| {
            attrs.push(rustbgpd_wire::PathAttribute::OnlyToCustomer(64_512));
        });
        manager.reconcile_peer_otc_blocked(peer, &HashSet::from([otc.prefix]), vec![otc.clone()]);
        assert!(manager.pending_otc_blocked[&peer].contains_key(&(otc.prefix, otc.path_id)));
        encoder.set_profile(3, [ExactExportKey::Evpn(route(1).key())]);
        manager.adj_rib_out_commit_stats = AdjRibOutCommitStats::default();
        Self {
            manager,
            peer,
            gid,
            output,
            encoder,
            unicast,
            rejected,
            otc,
        }
    }

    fn commit(&mut self) -> bool {
        let scope = HashSet::from([self.unicast.prefix, self.otc.prefix]);
        self.manager
            .try_send_and_commit_outbound_update_with_group_prior_and_otc_scope(
                self.peer,
                OutboundCommitBatch {
                    evpn_announce: vec![route(1), route(2)],
                    withdraw: vec![(self.rejected.prefix, self.rejected.path_id)],
                    end_of_rib: vec![(Afi::L2Vpn, Safi::Evpn)],
                    defer_grouped_refresh_prior: true,
                    ..OutboundCommitBatch::with_unicast(
                        Arc::new(vec![self.unicast.clone()]),
                        Arc::new(vec![None]),
                    )
                },
                HashSet::new(),
                None,
                Some(&scope),
                None,
            )
            .is_ok()
    }
}

fn exact_rejection_count(manager: &RibManager) -> f64 {
    manager
        .metrics
        .registry()
        .gather()
        .iter()
        .filter(|family| family.name() == "bgp_exact_export_rejections_total")
        .flat_map(|family| family.get_metric().iter())
        .map(|metric| metric.get_counter().get_value())
        .sum()
}

#[expect(
    clippy::too_many_lines,
    reason = "pin the complete late-refusal transaction before and after the controlled final ledger failure"
)]
fn assert_final_transaction_refusal(fault: FinalAdmissionFault, deferred_capture: bool) {
    let mut fixture = FinalTransactionFixture::new(deferred_capture);
    let manager = &mut fixture.manager;
    let peer = fixture.peer;
    let handle = manager.evpn_recovery_handle(peer).unwrap();
    assert_eq!(
        manager.evpn_recovery.proof_keys(handle).unwrap(),
        Some(vec![route(1).key()])
    );
    let overlay = manager.peer_unexportable[&peer].clone();
    let rejections = exact_rejection_count(manager);
    let common = (
        manager.pending_group_admitted.owned_proof(&peer),
        manager.pending_group_admitted.bytes(),
        manager.pending_group_admitted.peak_bytes(),
        manager.group_ribs[&fixture.gid].recovery_snapshot_for_test(),
    );
    let otc_current = manager.peer_otc_blocked[&peer].clone();
    let otc_pending = format!("{:?}", manager.pending_otc_blocked[&peer]);
    let baseline = format!("{:?}", manager.pending_regroup_baseline[&peer]);
    let limits = format!("{:?}", manager.outbound_prefix_limits[&peer]);
    let requests = capture_reset_requests(manager);
    let peer_label = peer.to_string();
    let refusal_labels = [("peer", peer_label.as_str()), ("reason", "evpn_recovery")];
    let refusals_before = super::counter_metric_value(
        &manager.metrics,
        "bgp_outbound_commit_refusals_total",
        &refusal_labels,
    );
    let drops_before = super::counter_metric_value(
        &manager.metrics,
        "bgp_outbound_route_drops_total",
        &[("peer", peer_label.as_str())],
    );
    manager.evpn_recovery.fail_final_admission_for_test(fault);
    let probes_before = fixture.encoder.probed().len();

    assert!(
        !fixture.commit(),
        "the final refusal must abort the entire mixed-family envelope"
    );
    let manager = &fixture.manager;
    // The late refusal is counted once as an EVPN recovery refusal, never as
    // writer-channel loss.
    let refusals = super::counter_metric_value(
        &manager.metrics,
        "bgp_outbound_commit_refusals_total",
        &refusal_labels,
    );
    assert!((refusals - refusals_before - 1.0).abs() < f64::EPSILON);
    let drops = super::counter_metric_value(
        &manager.metrics,
        "bgp_outbound_route_drops_total",
        &[("peer", peer_label.as_str())],
    );
    assert!((drops - drops_before).abs() < f64::EPSILON);
    assert!(
        !manager.evpn_recovery.final_admission_fault_pending(),
        "the test must reach the FINAL ledger check after ordinary candidate reservation"
    );
    let probed = fixture.encoder.probed();
    assert_eq!(probed.len() - probes_before, 3);
    assert_eq!(
        HashSet::from_iter(probed[probes_before..].iter().cloned()),
        HashSet::from([
            ExactExportKey::Unicast(fixture.unicast.prefix, fixture.unicast.path_id),
            ExactExportKey::Evpn(route(1).key()),
            ExactExportKey::Evpn(route(2).key())
        ])
    );
    assert_eq!(manager.adj_rib_out_commit_stats.exact_probe_batches, 1);
    assert_eq!(manager.adj_rib_out_commit_stats.exact_probe_candidates, 3);
    assert_eq!(manager.adj_rib_out_commit_stats.successful_commits, 0);
    assert_eq!(manager.adj_rib_out_commit_stats.successful_enqueues, 0);
    assert_eq!(manager.adj_rib_out_commit_stats.family_gauge_writes, 0);
    assert!(
        fixture.output.try_recv().is_err(),
        "no ANN, WD or EoR may escape refusal"
    );
    assert_eq!(manager.adj_ribs_out[&peer].evpn_len(), 1);
    let retained = manager.adj_ribs_out[&peer]
        .get_evpn(&route(1).key())
        .unwrap();
    assert_eq!(retained.next_hop, route(1).next_hop);
    assert!(
        manager.adj_ribs_out[&peer]
            .get_evpn(&route(2).key())
            .is_none()
    );
    assert_eq!(
        manager.peer_unexportable[&peer], overlay,
        "neither new EVPN rejection nor old rejected-unicast withdrawal may publish"
    );
    assert!((exact_rejection_count(manager) - rejections).abs() < f64::EPSILON);
    assert_eq!(
        (
            manager.pending_group_admitted.owned_proof(&peer),
            manager.pending_group_admitted.bytes(),
            manager.pending_group_admitted.peak_bytes(),
            manager.group_ribs[&fixture.gid].recovery_snapshot_for_test()
        ),
        common
    );
    assert_eq!(manager.peer_otc_blocked[&peer], otc_current);
    assert_eq!(
        format!("{:?}", manager.pending_otc_blocked[&peer]),
        otc_pending
    );
    assert_eq!(
        format!("{:?}", manager.pending_regroup_baseline[&peer]),
        baseline
    );
    assert_eq!(
        format!("{:?}", manager.outbound_prefix_limits[&peer]),
        limits
    );
    assert!(!manager.outbound_prefix_limits[&peer].grouped_contains(&fixture.unicast.prefix));
    assert_eq!(
        manager.evpn_recovery.exhaustion(handle).unwrap().cause,
        EvpnRecoveryExhaustionCause::AdmissionInvariant
    );
    assert!(manager.dirty_peers.contains(&peer));
    let requests = requests.lock().unwrap();
    assert_eq!(
        requests.len(),
        1,
        "a real generation-fenced reset handoff remains owned"
    );
    let request = &requests[0].0;
    assert_eq!(
        (request.peer, request.session_id, request.cause),
        (
            peer,
            manager.outbound_session_ids[&peer],
            EvpnRecoveryExhaustionCause::AdmissionInvariant
        )
    );
    assert!(
        request
            .outbound
            .same_channel(&manager.outbound_peers[&peer])
    );
    assert!(
        !requests[0].1.is_closed(),
        "execution receipt remains owned by the RIB"
    );
    assert!(!manager.evpn_recovery.reset_admitted(handle));
}

#[test]
fn final_evpn_preflight_refusal_preserves_all_precommit_state() {
    for deferred_capture in [false, true] {
        assert_final_transaction_refusal(FinalAdmissionFault::Preflight, deferred_capture);
    }
}

#[test]
fn final_evpn_apply_refusal_preserves_all_precommit_state() {
    for deferred_capture in [false, true] {
        assert_final_transaction_refusal(FinalAdmissionFault::Apply, deferred_capture);
    }
}

#[test]
fn final_evpn_admission_publishes_one_mixed_family_transaction_after_validation() {
    for deferred_capture in [false, true] {
        let mut fixture = FinalTransactionFixture::new(deferred_capture);
        let common_before = fixture.manager.pending_group_admitted.bytes();
        let rejections = exact_rejection_count(&fixture.manager);
        let requests = capture_reset_requests(&mut fixture.manager);
        assert!(fixture.commit());
        let update = fixture.output.try_recv().expect("one committed envelope");
        assert_eq!(update.announce.len(), 1);
        assert_eq!(update.announce[0].prefix, fixture.unicast.prefix);
        assert!(
            update.withdraw.is_empty(),
            "the previously rejected unicast identity was never admitted"
        );
        assert_eq!(update.evpn_announce.len(), 1);
        assert_eq!(update.evpn_announce[0].key(), route(2).key());
        assert_eq!(update.evpn_withdraw, vec![route(1).key()]);
        assert_eq!(update.end_of_rib, vec![(Afi::L2Vpn, Safi::Evpn)]);
        assert!(update.otc_blocked.is_empty());
        assert!(fixture.output.try_recv().is_err(), "exactly one enqueue");
        let manager = &fixture.manager;
        let peer = fixture.peer;
        assert_eq!(
            manager.peer_unexportable[&peer],
            HashSet::from([ExactExportKey::Evpn(route(1).key())])
        );
        assert!((exact_rejection_count(manager) - rejections - 1.0).abs() < f64::EPSILON);
        assert!(
            manager.adj_ribs_out[&peer]
                .get_evpn(&route(1).key())
                .is_none()
        );
        assert!(
            manager.adj_ribs_out[&peer]
                .get_evpn(&route(2).key())
                .is_some()
        );
        let handle = manager.evpn_recovery_handle(peer).unwrap();
        assert_eq!(
            manager.evpn_recovery.proof_keys(handle).unwrap(),
            Some(vec![route(2).key()])
        );
        assert!(manager.pending_group_admitted.get(&peer).unwrap().contains(
            &ExactExportKey::Unicast(fixture.unicast.prefix, fixture.unicast.path_id)
        ));
        assert!(manager.pending_group_admitted.bytes() > common_before);
        assert!(
            manager.group_ribs[&fixture.gid]
                .recovery_snapshot_for_test()
                .is_some()
        );
        assert!(!manager.pending_otc_blocked.contains_key(&peer));
        assert!(!manager.peer_otc_blocked.contains_key(&peer));
        assert!(manager.outbound_prefix_limits[&peer].grouped_contains(&fixture.unicast.prefix));
        assert_eq!(manager.adj_rib_out_commit_stats.successful_commits, 1);
        assert_eq!(manager.adj_rib_out_commit_stats.successful_enqueues, 1);
        assert!(requests.lock().unwrap().is_empty());
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "one real PCB caller control keeps OTC fallback, same-key verdict ordering and wire assertions together"
)]
fn assert_pcb_otc_overlay_order(reserve_refused: bool, later_accepts: Option<bool>) {
    let (_tx, rx) = mpsc::channel(8);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let peer: IpAddr = "192.0.2.30".parse().unwrap();
    manager.handle_update(RibUpdate::SetPeerExportContext {
        peer,
        session_id: 0,
        local_role: Some(rustbgpd_wire::BgpRole::Customer),
    });
    let (outbound, mut output) = mpsc::channel(8);
    let mut registration = super::update_groups_recovery::peer_up(peer, outbound, None);
    if let RibUpdate::PeerUp {
        per_client_best,
        is_ebgp,
        ..
    } = &mut registration
    {
        *per_client_best = true;
        *is_ebgp = true;
    }
    manager.handle_update(registration);
    output.try_recv().unwrap();
    assert!(output.try_recv().is_err());
    let gid = manager
        .grouped_member_of(peer)
        .expect("real PCB group registration");
    assert!(manager.group_ribs[&gid].per_client_best);
    let route = make_route(
        Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 20), 32),
        Ipv4Addr::new(192, 0, 2, 10),
    );
    let key = ExactExportKey::Unicast(route.prefix, route.path_id);
    let encoder = MockExactExportEncoder::accepting(1);
    encoder.set_profile(2, [key.clone()]);
    manager.peer_export_encoders.insert(peer, encoder.clone());
    assert!(
        manager
            .try_send_and_commit_outbound_update(
                peer,
                OutboundCommitBatch::with_unicast(
                    Arc::new(vec![route.clone()]),
                    Arc::new(vec![None])
                )
            )
            .is_ok()
    );
    let rejected = output.try_recv().unwrap();
    assert!(rejected.announce.is_empty() && rejected.withdraw.is_empty());
    assert_eq!(
        manager.peer_unexportable[&peer],
        HashSet::from([key.clone()])
    );
    assert!(output.try_recv().is_err());
    manager
        .pending_group_admitted
        .remove_with_checkpoint(&peer, &mut |_| {});
    manager
        .pending_group_admitted
        .insert_empty_with_checkpoint(peer, &mut |_| {})
        .unwrap();
    assert!(
        manager
            .pending_group_admitted
            .get(&peer)
            .unwrap()
            .is_empty()
    );
    let rejections = exact_rejection_count(&manager);
    let probes = encoder.probed().len();
    if later_accepts == Some(true) {
        encoder.set_profile(3, []);
    }
    let mut blocked = route.clone();
    crate::attr_set::AttrSet::edit(&mut blocked.attributes, |attrs| {
        attrs.push(rustbgpd_wire::PathAttribute::OnlyToCustomer(64_512));
    });
    let mut announce = vec![blocked];
    if later_accepts.is_some() {
        announce.push(route.clone());
    }
    let next_hops = vec![None; announce.len()];
    if reserve_refused {
        manager
            .pending_group_admitted
            .fail_next_allocation_for_test();
    }
    let requests = capture_reset_requests(&mut manager);
    assert!(
        manager
            .try_send_and_commit_outbound_update(
                peer,
                OutboundCommitBatch {
                    withdraw: vec![(route.prefix, route.path_id)],
                    ..OutboundCommitBatch::with_unicast(Arc::new(announce), Arc::new(next_hops))
                }
            )
            .is_ok()
    );
    let update = output
        .try_recv()
        .expect("one committed live-unicast envelope");
    assert!(output.try_recv().is_err());
    let expected_withdraw = if reserve_refused && later_accepts == Some(false) {
        vec![(route.prefix, route.path_id)]
    } else {
        vec![]
    };
    assert_eq!(
        update.withdraw, expected_withdraw,
        "OTC fallback must not reinterpret retirement of an old rejection as admission"
    );
    assert_eq!(
        update.announce.len(),
        usize::from(later_accepts == Some(true))
    );
    assert_eq!(
        encoder.probed().len() - probes,
        usize::from(later_accepts.is_some()),
        "the blocked candidate is not probed and later exact candidate is probed once"
    );
    let overlay_rejected = manager
        .peer_unexportable
        .get(&peer)
        .is_some_and(|keys| keys.contains(&key));
    assert_eq!(
        overlay_rejected,
        later_accepts == Some(false),
        "OTC pruning precedes the later same-key exact verdict"
    );
    let increment = if later_accepts == Some(false) {
        1.0
    } else {
        0.0
    };
    assert!((exact_rejection_count(&manager) - rejections - increment).abs() < f64::EPSILON);
    assert_eq!(
        manager.group_recovery_fallback(peer).is_some(),
        reserve_refused
    );
    assert!(
        requests.lock().unwrap().is_empty(),
        "common refusal never requests an EVPN reset"
    );
}

#[test]
fn pcb_late_common_refusal_preserves_rejected_otc_withdrawal_suppression() {
    for refused in [false, true] {
        assert_pcb_otc_overlay_order(refused, None);
    }
}

#[test]
fn pcb_late_common_refusal_preserves_later_same_key_exact_rejection() {
    for refused in [false, true] {
        assert_pcb_otc_overlay_order(refused, Some(false));
    }
}

#[test]
fn pcb_late_common_refusal_preserves_later_same_key_exact_acceptance() {
    for refused in [false, true] {
        assert_pcb_otc_overlay_order(refused, Some(true));
    }
}
