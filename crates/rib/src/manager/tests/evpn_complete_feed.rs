use super::evpn_group_storage::{fixture, received, register, stage};
use super::exportability::MockExactExportEncoder;
use super::*;
use crate::manager::distribution::OutboundCommitBatch;
use rustbgpd_wire::RouteRefreshSubtype;
use std::sync::atomic::{AtomicUsize, Ordering};

const EVPN: (Afi, Safi) = (Afi::L2Vpn, Safi::Evpn);

fn admit_waiting_for_eor(manager: &mut RibManager, peer: IpAddr, gid: usize, route: &EvpnRibRoute) {
    admit_waiting_for_marker(manager, peer, gid, route, false);
}

fn admit_waiting_for_marker(
    manager: &mut RibManager,
    peer: IpAddr,
    gid: usize,
    route: &EvpnRibRoute,
    eorr: bool,
) {
    stage(manager, gid, route);
    assert!(manager.capture_private_evpn_admitted(peer));
    let mut feed = manager
        .prepare_complete_evpn_feed(peer, gid, None, true)
        .unwrap();
    assert_eq!(feed.announce.len(), 1);
    feed.seal.required_markers = if eorr {
        RibManager::evpn_admitted_marker_bits(&[], &[(EVPN.0, EVPN.1, RouteRefreshSubtype::EoRR)])
    } else {
        manager.pending_eor.insert(peer, HashSet::from([EVPN]));
        RibManager::evpn_admitted_marker_bits(&[EVPN], &[])
    };
    assert!(manager.try_send_and_commit_outbound_update(
        peer,
        OutboundCommitBatch {
            evpn_announce: feed.announce,
            evpn_withdraw: feed.withdraw,
            evpn_complete_feed: Some(feed.seal),
            ..OutboundCommitBatch::default()
        }
    ));
    assert!(manager.evpn_feed_is_current(peer));
    assert!(
        !manager
            .evpn_recovery
            .is_dormant(manager.evpn_recovery_handle(peer).unwrap())
    );
    assert_eq!(manager.adj_ribs_out[&peer].evpn_len(), 0);
}

#[test]
fn admitted_feed_keeps_proof_until_actual_ordered_marker_admission() {
    let (mut manager, peer, gid, mut output) = fixture();
    let route = received(1);
    admit_waiting_for_eor(&mut manager, peer, gid, &route);
    let data = output.try_recv().unwrap();
    assert_eq!(data.evpn_announce.len(), 1);
    assert_eq!(data.evpn_announce[0].key(), route.key());
    assert_eq!(data.end_of_rib, [] as [(Afi, Safi); 0]);
    assert!(output.try_recv().is_err());
    assert!(manager.evpn_advertised_resync_in_progress(peer));
    manager.flush_pending_eor(peer);
    let marker = output.try_recv().unwrap();
    assert_eq!(marker.end_of_rib, [EVPN]);
    assert!(marker.evpn_announce.is_empty());
    assert_eq!(marker.evpn_withdraw, [] as [rustbgpd_wire::EvpnRouteKey; 0]);
    assert!(
        manager
            .evpn_recovery
            .is_dormant(manager.evpn_recovery_handle(peer).unwrap())
    );
    assert!(!manager.evpn_advertised_resync_in_progress(peer));
}

#[test]
fn held_marker_survives_polls_without_data_replay_or_reset() {
    let (mut manager, peer, gid, mut output) = fixture();
    admit_waiting_for_eor(&mut manager, peer, gid, &received(1));
    output.try_recv().unwrap();
    // Controlled internal hold, released explicitly; no wall-clock race.
    manager
        .rtc_eor_hold
        .insert(peer, tokio::time::Instant::now() + Duration::from_secs(60));
    for _ in 0..3 {
        manager.flush_pending_eor(peer);
        manager.retry_evpn_feed_markers_bounded();
        assert!(output.try_recv().is_err());
        assert!(manager.evpn_feed_is_current(peer));
        assert!(!manager.evpn_recovery_reset_pending(peer));
        assert!(!manager.dirty_peers.contains(&peer));
        assert!(!manager.resync_tick_pending());
    }
    manager.rtc_eor_hold.remove(&peer);
    manager.flush_pending_eor(peer);
    let marker = output.try_recv().unwrap();
    assert_eq!(marker.end_of_rib, [EVPN]);
    assert!(marker.evpn_announce.is_empty() && marker.evpn_withdraw.is_empty());
}

#[test]
fn refused_marker_retries_on_existing_timer_without_data_dirty() {
    let (mut manager, peer, gid, mut output) = fixture();
    admit_waiting_for_eor(&mut manager, peer, gid, &received(1));
    output.try_recv().unwrap();
    let sender = manager.outbound_peers[&peer].clone();
    while sender.try_send(OutboundRouteUpdate::default()).is_ok() {}
    manager.flush_pending_eor(peer);
    assert!(manager.pending_eor[&peer].contains(&EVPN));
    assert!(manager.evpn_feed_is_current(peer));
    assert!(!manager.dirty_peers.contains(&peer));
    assert!(!manager.evpn_recovery_reset_pending(peer));
    assert!(manager.resync_tick_pending());
    while output.try_recv().is_ok() {}
    manager.resync_dirty_peers_bounded();
    let marker = output.try_recv().unwrap();
    assert_eq!(marker.end_of_rib, [EVPN]);
    assert!(marker.evpn_announce.is_empty() && marker.evpn_withdraw.is_empty());
    assert!(output.try_recv().is_err());
    assert!(!manager.resync_tick_pending());
}

#[test]
fn invalidated_coverage_cannot_send_or_settle_a_pending_marker() {
    let (mut manager, peer, gid, mut output) = fixture();
    admit_waiting_for_eor(&mut manager, peer, gid, &received(1));
    output.try_recv().unwrap();
    manager.invalidate_evpn_feed_completion(peer);
    for _ in 0..3 {
        manager.flush_pending_eor(peer);
        manager.retry_evpn_feed_markers_bounded();
        assert!(output.try_recv().is_err());
        assert!(manager.pending_eor[&peer].contains(&EVPN));
        assert!(!manager.evpn_feed_is_current(peer));
        assert!(!manager.dirty_peers.contains(&peer));
        assert!(!manager.evpn_recovery_reset_pending(peer));
        assert!(manager.evpn_advertised_resync_in_progress(peer));
    }
}

#[test]
fn stale_completion_cannot_invalidate_a_newer_complete_feed() {
    let (mut manager, peer, gid, mut output) = fixture();
    admit_waiting_for_eor(&mut manager, peer, gid, &received(1));
    output.try_recv().unwrap();
    let old = manager
        .prepare_complete_evpn_feed(peer, gid, Some(gid), true)
        .unwrap();
    // A new group incarnation with identical values still has a fresh fence.
    let stamp = manager.next_evpn_table_stamp().unwrap();
    manager.group_ribs.get_mut(&gid).unwrap().evpn_table_stamp = stamp;
    let current = manager
        .prepare_complete_evpn_feed(peer, gid, Some(gid), true)
        .unwrap();
    assert!(current.announce.is_empty() && current.withdraw.is_empty());
    assert!(manager.try_send_and_commit_outbound_update(
        peer,
        OutboundCommitBatch {
            evpn_complete_feed: Some(current.seal),
            ..OutboundCommitBatch::default()
        }
    ));
    assert!(manager.evpn_feed_is_current(peer));
    assert!(!manager.complete_evpn_feed_admitted(peer, old.seal, 0));
    assert!(manager.evpn_feed_is_current(peer));
    assert!(manager.pending_eor[&peer].contains(&EVPN));
    manager.flush_pending_eor(peer);
    while let Ok(update) = output.try_recv() {
        assert!(update.evpn_announce.is_empty() && update.evpn_withdraw.is_empty());
    }
    assert!(!manager.evpn_advertised_resync_in_progress(peer));
}

#[test]
fn retiring_provenance_drops_its_fixed_completion_receipt() {
    let (mut manager, peer, gid, mut output) = fixture();
    admit_waiting_for_eor(&mut manager, peer, gid, &received(1));
    output.try_recv().unwrap();
    manager.retire_evpn_recovery(peer);
    assert!(
        manager.live_sessions[&peer]
            .iter()
            .all(|record| record.evpn_feed_completion.is_none())
    );
    manager.flush_pending_eor(peer);
    assert!(output.try_recv().is_err());
}

#[test]
fn full_producer_reads_displaced_attributes_instead_of_current_values_as_old() {
    let (mut manager, peer, gid, _output) = fixture();
    let old = received(100);
    stage(&mut manager, gid, &old);
    let new = received(200);
    let changed = stage(&mut manager, gid, &new);
    assert_eq!(old.key(), new.key());
    let feed = manager
        .prepare_complete_evpn_feed_before_deltas(peer, gid, Some(gid), true, &changed.deltas)
        .unwrap();
    assert_eq!(feed.announce.len(), 1);
    assert_eq!(
        feed.announce[0].extended_communities(),
        new.extended_communities()
    );
    assert_eq!(feed.withdraw, [] as [rustbgpd_wire::EvpnRouteKey; 0]);
    let no_op = stage(&mut manager, gid, &new);
    assert!(no_op.deltas.is_empty());
    let feed = manager
        .prepare_complete_evpn_feed_before_deltas(peer, gid, Some(gid), true, &no_op.deltas)
        .unwrap();
    assert!(feed.announce.is_empty() && feed.withdraw.is_empty());
}

#[test]
fn displaced_projection_preserves_removed_old_rows_without_including_new_rows() {
    let (mut manager, peer, gid, _output) = fixture();
    let old = received(100);
    stage(&mut manager, gid, &old);
    let new = make_evpn_imet(Ipv4Addr::new(192, 0, 2, 11), 2);
    manager
        .loc_rib
        .recompute_evpn(old.key(), std::iter::empty());
    manager
        .loc_rib
        .recompute_evpn(new.key(), [&new].into_iter());
    let changed = manager.stage_group_evpn_keys(gid, &HashSet::from([old.key(), new.key()]));
    assert_eq!(changed.deltas.len(), 2);
    let mut visits = 0;
    let projection: Vec<_> = manager.group_ribs[&gid]
        .evpn_member_projection_before_deltas(
            &changed.deltas,
            peer,
            manager.cluster_id,
            None,
            None,
            || visits += 1,
        )
        .map(EvpnRibRoute::key)
        .collect();
    assert_eq!(projection, [old.key()]);
    assert_eq!(visits, 3, "one current row plus both displaced-row records");
    let feed = manager
        .prepare_complete_evpn_feed_before_deltas(peer, gid, Some(gid), true, &changed.deltas)
        .unwrap();
    assert_eq!(feed.announce.len(), 1);
    assert_eq!(feed.announce[0].key(), new.key());
    assert_eq!(feed.withdraw, [old.key()]);
}

#[test]
fn late_capture_uses_displaced_admitted_keys_instead_of_advanced_group_rows() {
    let (mut manager, peer, gid, _output) = fixture();
    let old = received(100);
    stage(&mut manager, gid, &old);
    let new = make_evpn_imet(Ipv4Addr::new(192, 0, 2, 11), 2);
    manager
        .loc_rib
        .recompute_evpn(old.key(), std::iter::empty());
    manager
        .loc_rib
        .recompute_evpn(new.key(), [&new].into_iter());
    let changed = manager.stage_group_evpn_keys(gid, &HashSet::from([old.key(), new.key()]));
    assert!(manager.capture_shared_evpn_before_deltas(peer, &changed.deltas));
    let proof = manager
        .evpn_recovery
        .proof(manager.evpn_recovery_handle(peer).unwrap())
        .unwrap()
        .unwrap();
    assert_eq!(proof.len(), 1);
    assert!(proof.contains(&old.key()));
    assert!(!proof.contains(&new.key()));
    assert!(!manager.evpn_recovery_reset_pending(peer));
}

#[test]
fn owned_initial_missing_full_producer_cannot_emit_private_data_or_terminal() {
    for missing_input in [false, true] {
        let (mut manager, peer, gid, mut output) = fixture();
        let route = received(100);
        stage(&mut manager, gid, &route);
        assert!(manager.capture_private_evpn_admitted(peer));
        let group = manager.group_ribs.get_mut(&gid).unwrap();
        if missing_input {
            group.evpn_inputs.clear();
        } else {
            group.evpn_table_stamp = 0;
        }
        manager.send_initial_table(peer);
        assert!(
            output.try_recv().is_err(),
            "owned refusal aborts the mixed initial dump"
        );
        assert_eq!(manager.adj_ribs_out[&peer].evpn_len(), 0);
        assert!(manager.pending_eor[&peer].contains(&EVPN));
        assert!(!manager.evpn_feed_is_current(peer));
        assert!(manager.dirty_peers.contains(&peer));
        assert!(manager.evpn_recovery_reset_pending(peer));
        manager.flush_pending_eor(peer);
        assert!(output.try_recv().is_err());
        assert!(manager.pending_eor[&peer].contains(&EVPN));
    }
}

#[test]
fn owned_initial_postadmission_mismatch_keeps_enqueue_truth_but_holds_terminal() {
    let (mut manager, peer, gid, mut output) = fixture();
    let route = received(100);
    stage(&mut manager, gid, &route);
    assert!(manager.capture_private_evpn_admitted(peer));
    // This hook is consumed only after the actual mixed enqueue and proof
    // application; it cannot make the pre-admission caller vacuously fail.
    manager.adj_rib_out_commit_stats = AdjRibOutCommitStats::default();
    manager.adj_rib_out_commit_stats.fail_evpn_feed_completion = true;
    manager.send_initial_table(peer);
    let mut data = Vec::new();
    while let Ok(update) = output.try_recv() {
        assert!(!update.end_of_rib.contains(&EVPN));
        assert_eq!(update.evpn_withdraw, [] as [rustbgpd_wire::EvpnRouteKey; 0]);
        data.extend(update.evpn_announce);
    }
    assert_eq!(
        data.len(),
        1,
        "the already-admitted batch did not roll back"
    );
    assert_eq!(data[0].key(), route.key());
    assert_eq!(manager.adj_rib_out_commit_stats.successful_enqueues, 1);
    assert!(manager.pending_eor[&peer].contains(&EVPN));
    assert!(!manager.evpn_feed_is_current(peer));
    assert!(manager.evpn_recovery_reset_pending(peer));
    for _ in 0..3 {
        manager.flush_pending_eor(peer);
        assert!(
            output.try_recv().is_err(),
            "marker polling must not replay data"
        );
        assert!(manager.pending_eor[&peer].contains(&EVPN));
    }
}

fn admit_converged_owned(
    manager: &mut RibManager,
    peer: IpAddr,
    gid: usize,
    output: &mut mpsc::Receiver<OutboundRouteUpdate>,
    route: &EvpnRibRoute,
) -> EvpnRibRoute {
    assert_eq!(manager.evpn_grouped_member_of(peer), Some(gid));
    manager
        .ribs
        .entry(route.peer)
        .or_insert_with(|| AdjRibIn::new(route.peer));
    manager.process_evpn_announce_chunk(route.peer, vec![route.clone()]);
    let mut update = output.try_recv().unwrap();
    assert_eq!(update.evpn_announce.len(), 1);
    let admitted = update.evpn_announce.pop().unwrap();
    assert!(matches!(
        output.try_recv(),
        Err(mpsc::error::TryRecvError::Empty)
    ));
    assert!(
        manager
            .evpn_recovery
            .is_dormant(manager.evpn_recovery_handle(peer).unwrap())
    );
    admitted
}

fn count_reset_attempts(manager: &mut RibManager) -> Arc<AtomicUsize> {
    let calls = Arc::new(AtomicUsize::new(0));
    let seen = Arc::clone(&calls);
    manager.evpn_recovery_reset = Some(Arc::new(move |_, _reply| {
        seen.fetch_add(1, Ordering::SeqCst);
        false
    }));
    calls
}

#[test]
fn clean_last_owned_member_seeds_actual_private_routes_before_full_queue_fallback() {
    let (mut manager, peer, gid, mut output) = fixture();
    let route = received(100);
    let admitted = admit_converged_owned(&mut manager, peer, gid, &mut output, &route);
    let handle = manager.evpn_recovery_handle(peer).unwrap();
    let resets = count_reset_attempts(&mut manager);
    let sender = manager.outbound_peers[&peer].clone();
    let mut filled = 0;
    while sender.try_send(OutboundRouteUpdate::default()).is_ok() {
        filled += 1;
    }
    assert!(filled > 0);
    manager.handle_update(RibUpdate::PeerSlowState {
        peer,
        session_id: 7,
        slow: true,
    });
    assert!(manager.grouped_member_of(peer).is_none());
    assert!(
        !manager.group_ribs.contains_key(&gid),
        "last OLD table retired"
    );
    let private = manager.adj_ribs_out[&peer].get_evpn(&route.key()).unwrap();
    assert!(crate::manager::helpers::evpn_routes_equal(
        private, &admitted
    ));
    assert_eq!(manager.evpn_recovery_handle(peer), Some(handle));
    assert!(!manager.evpn_recovery_reset_pending(peer));
    while let Ok(update) = output.try_recv() {
        assert!(update.evpn_announce.is_empty() && update.evpn_withdraw.is_empty());
    }
    manager.resync_dirty_peers_bounded();
    assert!(matches!(
        output.try_recv(),
        Err(mpsc::error::TryRecvError::Empty)
    ));
    assert!(manager.adj_ribs_out[&peer].get_evpn(&route.key()).is_some());
    assert!(manager.evpn_recovery.is_dormant(handle));
    assert!(!manager.dirty_peers.contains(&peer));
    assert_eq!(resets.load(Ordering::SeqCst), 0);

    manager
        .loc_rib
        .recompute_evpn(route.key(), std::iter::empty());
    manager.distribute_evpn_keys_to_peer(peer, &HashSet::from([route.key()]), &mut || {});
    let withdrawal = output.try_recv().unwrap();
    assert!(withdrawal.evpn_announce.is_empty());
    assert_eq!(withdrawal.evpn_withdraw, [route.key()]);
    assert_eq!(manager.adj_ribs_out[&peer].evpn_len(), 0);
    assert!(matches!(
        output.try_recv(),
        Err(mpsc::error::TryRecvError::Empty)
    ));
    assert_eq!(resets.load(Ordering::SeqCst), 0);
}

#[test]
fn dirty_private_handoff_heals_old_only_proof_key_once_without_route_bodies_or_reset() {
    let (mut manager, peer, gid, mut output) = fixture();
    let route = received(100);
    admit_converged_owned(&mut manager, peer, gid, &mut output, &route);
    assert!(manager.capture_shared_evpn_admitted(peer));
    let handle = manager.evpn_recovery_handle(peer).unwrap();
    let retained = manager.evpn_recovery.peer_usage(peer).retained;
    manager
        .loc_rib
        .recompute_evpn(route.key(), std::iter::empty());
    let changed = manager.stage_group_evpn_keys(gid, &HashSet::from([route.key()]));
    assert_eq!(changed.deltas.len(), 1);
    assert_eq!(manager.group_ribs[&gid].table.evpn_len(), 0);
    manager.mark_outbound_dirty_inner(peer, false);
    let resets = count_reset_attempts(&mut manager);
    let sender = manager.outbound_peers[&peer].clone();
    while sender.try_send(OutboundRouteUpdate::default()).is_ok() {}
    manager.handle_update(RibUpdate::PeerSlowState {
        peer,
        session_id: 7,
        slow: true,
    });
    assert!(manager.grouped_member_of(peer).is_none());
    assert!(!manager.group_ribs.contains_key(&gid));
    assert!(manager.loc_rib.get_evpn(&route.key()).is_none());
    assert_eq!(manager.adj_ribs_out[&peer].evpn_len(), 0);
    assert!(
        manager
            .evpn_recovery
            .proof(handle)
            .unwrap()
            .unwrap()
            .contains(&route.key())
    );
    assert!(!manager.evpn_recovery_reset_pending(peer));
    assert_eq!(resets.load(Ordering::SeqCst), 0);
    while let Ok(update) = output.try_recv() {
        assert!(update.evpn_announce.is_empty() && update.evpn_withdraw.is_empty());
    }
    manager.resync_dirty_peers_bounded();
    let update = output.try_recv().expect("one targeted private heal");
    assert!(update.evpn_announce.is_empty());
    assert_eq!(update.evpn_withdraw, [route.key()]);
    assert!(matches!(
        output.try_recv(),
        Err(mpsc::error::TryRecvError::Empty)
    ));
    assert_eq!(manager.adj_ribs_out[&peer].evpn_len(), 0);
    assert!(manager.evpn_recovery.is_dormant(handle));
    assert!(manager.evpn_recovery.peer_usage(peer).retained < retained);
    assert!(!manager.dirty_peers.contains(&peer));
    assert!(!manager.evpn_recovery_reset_pending(peer));
    assert_eq!(resets.load(Ordering::SeqCst), 0);
}

#[test]
fn incomplete_old_capture_retains_owned_membership_and_fenced_reset_duty() {
    let (mut manager, peer, gid, mut output) = fixture();
    let route = received(100);
    admit_converged_owned(&mut manager, peer, gid, &mut output, &route);
    manager
        .group_ribs
        .get_mut(&gid)
        .unwrap()
        .evpn_inputs
        .clear();
    let resets = count_reset_attempts(&mut manager);
    manager.handle_update(RibUpdate::PeerSlowState {
        peer,
        session_id: 7,
        slow: true,
    });
    assert_eq!(manager.evpn_grouped_member_of(peer), Some(gid));
    assert!(manager.group_ribs[&gid].members.contains(&peer));
    assert!(
        manager.group_ribs[&gid]
            .table
            .get_evpn(&route.key())
            .is_some()
    );
    assert_eq!(manager.adj_ribs_out[&peer].evpn_len(), 0);
    assert!(manager.evpn_recovery_reset_pending(peer));
    assert!(resets.load(Ordering::SeqCst) > 0);
    assert!(matches!(
        output.try_recv(),
        Err(mpsc::error::TryRecvError::Empty)
    ));
}

#[test]
fn dirty_private_rejected_replacement_withdraws_actual_proof_without_private_old_body() {
    let (mut manager, peer, gid, mut output) = fixture();
    let route = received(100);
    admit_converged_owned(&mut manager, peer, gid, &mut output, &route);
    assert!(manager.capture_shared_evpn_admitted(peer));
    let handle = manager.evpn_recovery_handle(peer).unwrap();
    manager.mark_outbound_dirty_inner(peer, false);
    let encoder = MockExactExportEncoder::accepting(10);
    encoder.set_profile(11, [crate::update::ExactExportKey::Evpn(route.key())]);
    manager.peer_export_encoders.insert(peer, encoder);
    let resets = count_reset_attempts(&mut manager);
    assert_eq!(manager.adj_ribs_out[&peer].evpn_len(), 0);
    manager.handle_update(RibUpdate::PeerSlowState {
        peer,
        session_id: 7,
        slow: true,
    });
    assert!(manager.grouped_member_of(peer).is_none());
    assert!(!manager.group_ribs.contains_key(&gid));
    let update = output.try_recv().expect("one exact-rejection withdrawal");
    assert!(update.evpn_announce.is_empty());
    assert_eq!(update.evpn_withdraw, [route.key()]);
    assert!(matches!(
        output.try_recv(),
        Err(mpsc::error::TryRecvError::Empty)
    ));
    assert_eq!(manager.adj_ribs_out[&peer].evpn_len(), 0);
    assert!(
        manager.peer_unexportable[&peer]
            .contains(&crate::update::ExactExportKey::Evpn(route.key()))
    );
    assert!(manager.evpn_recovery.is_dormant(handle));
    assert!(!manager.evpn_recovery_reset_pending(peer));
    assert_eq!(resets.load(Ordering::SeqCst), 0);
}

#[test]
fn private_handoff_keeps_held_eor_and_eorr_then_rejoins_without_inherited_debt() {
    for eorr in [false, true] {
        let (mut manager, peer, gid, mut output) = fixture();
        let route = received(100);
        admit_waiting_for_marker(&mut manager, peer, gid, &route, eorr);
        output.try_recv().unwrap();
        let resets = count_reset_attempts(&mut manager);
        manager
            .rtc_eor_hold
            .insert(peer, tokio::time::Instant::now() + Duration::from_secs(60));
        manager.handle_update(RibUpdate::PeerSlowState {
            peer,
            session_id: 7,
            slow: true,
        });
        assert!(manager.grouped_member_of(peer).is_none());
        assert!(!manager.group_ribs.contains_key(&gid));
        assert!(manager.adj_ribs_out[&peer].get_evpn(&route.key()).is_some());
        assert!(manager.has_private_evpn_handoff(peer));
        assert!(manager.evpn_feed_is_current(peer));
        let handle = manager.evpn_recovery_handle(peer).unwrap();
        assert!(!manager.evpn_recovery.is_dormant(handle));
        for _ in 0..2 {
            manager.retry_evpn_feed_markers_bounded();
            assert!(output.try_recv().is_err());
            assert!(!manager.dirty_peers.contains(&peer));
        }
        manager.rtc_eor_hold.remove(&peer);
        let builds = manager.adj_rib_out_commit_stats.resync_builds;
        manager.retry_evpn_feed_markers_bounded();
        let marker = output.try_recv().unwrap();
        assert_eq!(marker.end_of_rib, if eorr { vec![] } else { vec![EVPN] });
        assert_eq!(
            marker.refresh_markers,
            if eorr {
                vec![(EVPN.0, EVPN.1, RouteRefreshSubtype::EoRR)]
            } else {
                vec![]
            }
        );
        assert!(marker.evpn_announce.is_empty() && marker.evpn_withdraw.is_empty());
        assert_eq!(manager.adj_rib_out_commit_stats.resync_builds, builds);
        assert!(manager.evpn_recovery.is_dormant(handle));
        assert!(!manager.has_evpn_feed_completion(peer));

        // Recreate an occupied destination, then join using the actual private
        // OLD. Identical R must transfer storage without another ANN/marker.
        let keeper = Ipv4Addr::new(192, 0, 2, 31).into();
        let (sender, mut keeper_output) = mpsc::channel(8);
        register(&mut manager, keeper, sender);
        while keeper_output.try_recv().is_ok() {}
        let destination = manager.grouped_member_of(keeper).unwrap();
        manager.group_ribs.get_mut(&destination).unwrap().owns_evpn = true;
        stage(&mut manager, destination, &route);
        manager.handle_update(RibUpdate::PeerSlowState {
            peer,
            session_id: 7,
            slow: false,
        });
        assert_eq!(manager.evpn_grouped_member_of(peer), Some(destination));
        assert_eq!(manager.adj_ribs_out[&peer].evpn_len(), 0);
        while let Ok(update) = output.try_recv() {
            assert!(update.evpn_announce.is_empty() && update.evpn_withdraw.is_empty());
            assert!(!update.end_of_rib.contains(&EVPN));
            assert!(
                !update
                    .refresh_markers
                    .iter()
                    .any(|&(afi, safi, _)| (afi, safi) == EVPN)
            );
        }
        assert!(!manager.has_evpn_feed_completion(peer));
        manager.retry_evpn_feed_markers_bounded();
        assert!(output.try_recv().is_err());
        assert_eq!(resets.load(Ordering::SeqCst), 0);
    }
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one controlled handoff pins actual OLD retention through refusal, changed and removed routes, then successful storage release"
)]
fn private_join_refusal_retains_old_values_until_changed_and_removed_routes_are_admitted() {
    let (mut manager, peer, gid, mut output) = fixture();
    let old = received(100);
    let mut removed = received(200);
    if let EvpnRoute::Imet(ref mut imet) = removed.route {
        imet.ethernet_tag = EthernetTagId(2);
    } else {
        panic!("IMET fixture");
    }
    stage(&mut manager, gid, &old);
    stage(&mut manager, gid, &removed);
    assert!(manager.capture_private_evpn_admitted(peer));
    let feed = manager
        .prepare_complete_evpn_feed(peer, gid, None, true)
        .unwrap();
    assert_eq!(feed.announce.len(), 2);
    assert!(manager.try_send_and_commit_outbound_update(
        peer,
        OutboundCommitBatch {
            evpn_announce: feed.announce,
            evpn_withdraw: feed.withdraw,
            evpn_complete_feed: Some(feed.seal),
            ..OutboundCommitBatch::default()
        }
    ));
    while output.try_recv().is_ok() {}
    manager.handle_update(RibUpdate::PeerSlowState {
        peer,
        session_id: 7,
        slow: true,
    });
    while output.try_recv().is_ok() {}
    assert_eq!(manager.adj_ribs_out[&peer].evpn_len(), 2);
    let actual_old = manager.adj_ribs_out[&peer]
        .get_evpn(&old.key())
        .unwrap()
        .clone();
    let actual_removed = manager.adj_ribs_out[&peer]
        .get_evpn(&removed.key())
        .unwrap()
        .clone();
    manager
        .loc_rib
        .recompute_evpn(removed.key(), std::iter::empty());
    let changed = received(300);
    manager
        .loc_rib
        .recompute_evpn(changed.key(), [&changed].into_iter());
    let keeper = Ipv4Addr::new(192, 0, 2, 31).into();
    let (sender, mut keeper_output) = mpsc::channel(8);
    register(&mut manager, keeper, sender);
    while keeper_output.try_recv().is_ok() {}
    let destination = manager.grouped_member_of(keeper).unwrap();
    manager.group_ribs.get_mut(&destination).unwrap().owns_evpn = true;
    stage(&mut manager, destination, &changed);
    let resets = count_reset_attempts(&mut manager);
    let sender = manager.outbound_peers[&peer].clone();
    while sender.try_send(OutboundRouteUpdate::default()).is_ok() {}
    manager.handle_update(RibUpdate::PeerSlowState {
        peer,
        session_id: 7,
        slow: false,
    });
    assert_eq!(manager.evpn_grouped_member_of(peer), Some(destination));
    assert!(crate::manager::helpers::evpn_routes_equal(
        manager.adj_ribs_out[&peer].get_evpn(&old.key()).unwrap(),
        &actual_old
    ));
    assert!(crate::manager::helpers::evpn_routes_equal(
        manager.adj_ribs_out[&peer]
            .get_evpn(&removed.key())
            .unwrap(),
        &actual_removed
    ));
    assert!(manager.dirty_peers.contains(&peer));
    let handle = manager.evpn_recovery_handle(peer).unwrap();
    assert_eq!(
        manager.evpn_recovery.proof(handle).unwrap().unwrap().len(),
        2
    );
    while let Ok(update) = output.try_recv() {
        assert!(update.evpn_announce.is_empty() && update.evpn_withdraw.is_empty());
    }
    // These other-family actual stores are intentionally present at the
    // family-specific release point; successful EVPN ownership keeps them.
    let unicast = make_route(
        Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24),
        Ipv4Addr::new(192, 0, 2, 10),
    );
    let vpn = make_vpn_rib_route(Ipv4Addr::new(192, 0, 2, 10), 1, 100, 100);
    manager
        .adj_ribs_out
        .get_mut(&peer)
        .unwrap()
        .insert(unicast.clone());
    manager
        .adj_ribs_out
        .get_mut(&peer)
        .unwrap()
        .insert_vpn(vpn.clone());
    let feed = manager
        .prepare_complete_evpn_feed(peer, destination, None, false)
        .unwrap();
    assert_eq!(feed.announce.len(), 1);
    assert_eq!(feed.withdraw, [removed.key()]);
    assert!(manager.try_send_and_commit_outbound_update(
        peer,
        OutboundCommitBatch {
            evpn_announce: feed.announce,
            evpn_withdraw: feed.withdraw,
            evpn_complete_feed: Some(feed.seal),
            ..OutboundCommitBatch::default()
        }
    ));
    let update = output.try_recv().unwrap();
    assert_eq!(update.evpn_announce.len(), 1);
    assert_eq!(update.evpn_announce[0].key(), changed.key());
    assert_eq!(update.evpn_withdraw, [removed.key()]);
    assert_eq!(manager.adj_ribs_out[&peer].evpn_len(), 0);
    assert!(
        manager.adj_ribs_out[&peer]
            .get(&unicast.prefix, unicast.path_id)
            .is_some()
    );
    assert!(manager.adj_ribs_out[&peer].get_vpn(&vpn.key()).is_some());
    assert!(manager.evpn_recovery.is_dormant(handle));
    assert_eq!(resets.load(Ordering::SeqCst), 0);
}

#[test]
fn marker_retry_rotates_past_thirty_two_full_receivers_without_rebuilding_routes() {
    let (mut manager, original, gid, mut original_output) = fixture();
    manager.group_ribs.get_mut(&gid).unwrap().owns_evpn = false;
    let route = received(100);
    manager
        .loc_rib
        .recompute_evpn(route.key(), [&route].into_iter());
    let mut outputs = Vec::new();
    let resets = count_reset_attempts(&mut manager);
    for host in 40..73 {
        let peer = Ipv4Addr::new(192, 0, 2, host).into();
        let (sender, mut output) = mpsc::channel(8);
        register(&mut manager, peer, sender);
        while output.try_recv().is_ok() {}
        let group = manager.grouped_member_of(peer).unwrap();
        manager.group_ribs.get_mut(&group).unwrap().owns_evpn = true;
        assert!(manager.capture_private_evpn_admitted(peer));
        assert!(manager.begin_private_evpn_handoff(peer));
        manager.group_ribs.get_mut(&group).unwrap().owns_evpn = false;
        manager.pending_eor.insert(peer, HashSet::from([EVPN]));
        manager
            .rtc_eor_hold
            .insert(peer, tokio::time::Instant::now() + Duration::from_secs(60));
        manager.mark_outbound_dirty_inner(peer, false);
        manager.resync_dirty_peers_bounded();
        while let Ok(update) = output.try_recv() {
            assert!(update.evpn_announce.is_empty() && update.evpn_withdraw.is_empty());
        }
        assert!(manager.evpn_feed_is_current(peer));
        assert!(!manager.dirty_peers.contains(&peer));
        manager.rtc_eor_hold.remove(&peer);
        if host < 72 {
            while manager.outbound_peers[&peer]
                .try_send(OutboundRouteUpdate::default())
                .is_ok()
            {}
        }
        outputs.push((peer, output));
    }
    while original_output.try_recv().is_ok() {}
    assert!(!manager.has_evpn_feed_completion(original));
    let builds = manager.adj_rib_out_commit_stats.resync_builds;
    manager.evpn_marker_cursor = None;
    for _ in 0..32_usize.div_ceil(crate::manager::RESYNC_PEERS_PER_TICK) {
        manager.retry_evpn_feed_markers_bounded();
        assert!(outputs.last_mut().unwrap().1.try_recv().is_err());
    }
    manager.retry_evpn_feed_markers_bounded();
    let marker = outputs.last_mut().unwrap().1.try_recv().unwrap();
    assert_eq!(marker.end_of_rib, [EVPN]);
    assert!(marker.evpn_announce.is_empty() && marker.evpn_withdraw.is_empty());
    assert_eq!(manager.adj_rib_out_commit_stats.resync_builds, builds);
    assert!(!manager.has_evpn_feed_completion(outputs.last().unwrap().0));
    assert_eq!(resets.load(Ordering::SeqCst), 0);
}

#[test]
fn same_channel_private_replay_keeps_old_only_duties_and_held_eorr_until_full_heal() {
    let (mut manager, peer, gid, mut output) = fixture();
    let route = received(100);
    admit_waiting_for_marker(&mut manager, peer, gid, &route, true);
    output.try_recv().unwrap();
    manager
        .rtc_eor_hold
        .insert(peer, tokio::time::Instant::now() + Duration::from_secs(60));
    manager.handle_update(RibUpdate::PeerSlowState {
        peer,
        session_id: 7,
        slow: true,
    });
    assert!(manager.has_private_evpn_handoff(peer));
    assert!(manager.evpn_feed_is_current(peer));
    assert!(output.try_recv().is_err());
    manager
        .loc_rib
        .recompute_evpn(route.key(), std::iter::empty());
    let sender = manager.outbound_peers[&peer].clone();
    let handle = manager.evpn_recovery_handle(peer).unwrap();
    let resets = count_reset_attempts(&mut manager);
    while sender.try_send(OutboundRouteUpdate::default()).is_ok() {}
    register(&mut manager, peer, sender);
    assert_eq!(manager.evpn_recovery_handle(peer), Some(handle));
    assert!(manager.has_private_evpn_handoff(peer));
    assert!(!manager.evpn_feed_is_current(peer));
    assert!(manager.pending_eor[&peer].contains(&EVPN));
    assert_eq!(manager.adj_ribs_out[&peer].evpn_len(), 0);
    assert!(
        manager
            .evpn_recovery
            .proof(handle)
            .unwrap()
            .unwrap()
            .contains(&route.key())
    );
    while let Ok(update) = output.try_recv() {
        assert!(update.evpn_announce.is_empty() && update.evpn_withdraw.is_empty());
    }
    manager.resync_dirty_peers_bounded();
    let mut withdrawals = Vec::new();
    let mut eorrs = 0;
    while let Ok(update) = output.try_recv() {
        assert!(update.evpn_announce.is_empty());
        withdrawals.extend(update.evpn_withdraw);
        eorrs += update
            .refresh_markers
            .iter()
            .filter(|&&(afi, safi, subtype)| {
                (afi, safi) == EVPN && subtype == RouteRefreshSubtype::EoRR
            })
            .count();
    }
    assert_eq!(withdrawals, [route.key()]);
    if manager.has_evpn_feed_completion(peer) {
        let builds = manager.adj_rib_out_commit_stats.resync_builds;
        manager.retry_evpn_feed_markers_bounded();
        while let Ok(update) = output.try_recv() {
            assert!(update.evpn_announce.is_empty() && update.evpn_withdraw.is_empty());
            eorrs += update
                .refresh_markers
                .iter()
                .filter(|&&(afi, safi, subtype)| {
                    (afi, safi) == EVPN && subtype == RouteRefreshSubtype::EoRR
                })
                .count();
        }
        assert_eq!(manager.adj_rib_out_commit_stats.resync_builds, builds);
    }
    assert_eq!(eorrs, 1);
    assert!(!manager.has_evpn_feed_completion(peer));
    assert!(manager.evpn_recovery.is_dormant(handle));
    assert!(!manager.dirty_peers.contains(&peer));
    assert_eq!(resets.load(Ordering::SeqCst), 0);
}

#[test]
fn same_channel_owned_replay_withdraws_retained_old_only_key_without_reset() {
    let (mut manager, peer, gid, mut output) = fixture();
    let route = received(100);
    admit_converged_owned(&mut manager, peer, gid, &mut output, &route);
    manager.group_ribs.get_mut(&gid).unwrap().owns_evpn = false;
    let keeper = Ipv4Addr::new(192, 0, 2, 31).into();
    let (keeper_sender, mut keeper_output) = mpsc::channel(8);
    register(&mut manager, keeper, keeper_sender);
    while keeper_output.try_recv().is_ok() {}
    manager.group_ribs.get_mut(&gid).unwrap().owns_evpn = true;
    assert!(manager.capture_shared_evpn_admitted(peer));
    let handle = manager.evpn_recovery_handle(peer).unwrap();
    manager
        .loc_rib
        .recompute_evpn(route.key(), std::iter::empty());
    manager.stage_group_evpn_keys(gid, &HashSet::from([route.key()]));
    manager.mark_outbound_dirty_inner(peer, false);
    let resets = count_reset_attempts(&mut manager);
    let sender = manager.outbound_peers[&peer].clone();
    register(&mut manager, peer, sender);
    let mut withdrawals = Vec::new();
    let mut terminal_seen = false;
    while let Ok(update) = output.try_recv() {
        assert!(update.evpn_announce.is_empty());
        assert!(!terminal_seen || update.evpn_withdraw.is_empty());
        withdrawals.extend(update.evpn_withdraw);
        terminal_seen |= update.end_of_rib.contains(&EVPN);
    }
    assert_eq!(withdrawals, [route.key()]);
    assert!(terminal_seen);
    assert_eq!(manager.evpn_grouped_member_of(peer), Some(gid));
    assert_eq!(manager.evpn_recovery_handle(peer), Some(handle));
    assert!(manager.evpn_recovery.is_dormant(handle));
    assert_eq!(resets.load(Ordering::SeqCst), 0);
}

#[test]
fn settled_private_handoff_does_not_gate_ordinary_dirty_private_admission() {
    let (mut manager, peer, gid, mut output) = fixture();
    let route = received(100);
    admit_converged_owned(&mut manager, peer, gid, &mut output, &route);
    manager.handle_update(RibUpdate::PeerSlowState {
        peer,
        session_id: 7,
        slow: true,
    });
    while output.try_recv().is_ok() {}
    assert!(!manager.has_evpn_feed_completion(peer));
    let handle = manager.evpn_recovery_handle(peer).unwrap();
    assert!(manager.evpn_recovery.is_dormant(handle));
    let resets = count_reset_attempts(&mut manager);
    let changed = received(200);
    manager
        .loc_rib
        .recompute_evpn(changed.key(), [&changed].into_iter());
    manager.mark_outbound_dirty_inner(peer, false);
    manager.resync_dirty_peers_bounded();
    let mut announced = Vec::new();
    while let Ok(update) = output.try_recv() {
        announced.extend(update.evpn_announce);
    }
    assert_eq!(announced.len(), 1);
    assert_eq!(announced[0].key(), changed.key());
    assert!(manager.evpn_recovery.is_dormant(handle));
    assert!(!manager.dirty_peers.contains(&peer));
    assert_eq!(resets.load(Ordering::SeqCst), 0);
}

#[test]
fn settled_private_replay_captures_refused_old_withdrawal_before_clearing_actual_rows() {
    let (mut manager, peer, gid, mut output) = fixture();
    let route = received(100);
    admit_converged_owned(&mut manager, peer, gid, &mut output, &route);
    manager.handle_update(RibUpdate::PeerSlowState {
        peer,
        session_id: 7,
        slow: true,
    });
    while output.try_recv().is_ok() {}
    let handle = manager.evpn_recovery_handle(peer).unwrap();
    assert!(manager.evpn_recovery.is_dormant(handle));
    assert!(!manager.has_evpn_feed_completion(peer));
    assert!(manager.adj_ribs_out[&peer].get_evpn(&route.key()).is_some());
    manager
        .ribs
        .entry(route.peer)
        .or_insert_with(|| AdjRibIn::new(route.peer))
        .insert_evpn(route.clone());
    let sender = manager.outbound_peers[&peer].clone();
    while sender.try_send(OutboundRouteUpdate::default()).is_ok() {}
    let resets = count_reset_attempts(&mut manager);
    // Real withdrawal removes the received/selected route, but the refused
    // private send leaves actual OLD R and its dormant prior-owner handle.
    manager.process_evpn_withdraw_chunk(route.peer, vec![route.key()]);
    assert!(manager.loc_rib.get_evpn(&route.key()).is_none());
    assert!(manager.adj_ribs_out[&peer].get_evpn(&route.key()).is_some());
    assert!(manager.dirty_peers.contains(&peer));
    assert!(manager.evpn_recovery.is_dormant(handle));
    register(&mut manager, peer, sender);
    assert_eq!(manager.evpn_recovery_handle(peer), Some(handle));
    assert_eq!(manager.adj_ribs_out[&peer].evpn_len(), 0);
    assert!(
        manager
            .evpn_recovery
            .proof(handle)
            .unwrap()
            .unwrap()
            .contains(&route.key())
    );
    assert!(manager.has_private_evpn_handoff(peer));
    while let Ok(update) = output.try_recv() {
        assert!(update.evpn_announce.is_empty() && update.evpn_withdraw.is_empty());
    }
    manager.resync_dirty_peers_bounded();
    let mut withdrawals = Vec::new();
    while let Ok(update) = output.try_recv() {
        assert!(update.evpn_announce.is_empty());
        withdrawals.extend(update.evpn_withdraw);
    }
    assert_eq!(withdrawals, [route.key()]);
    assert!(manager.evpn_recovery.is_dormant(handle));
    assert!(!manager.has_evpn_feed_completion(peer));
    assert!(!manager.dirty_peers.contains(&peer));
    assert_eq!(resets.load(Ordering::SeqCst), 0);
}

#[test]
fn absent_destination_is_built_before_private_handoff_and_keeps_actual_old() {
    let (mut manager, peer, gid, mut output) = fixture();
    let route = received(100);
    let admitted = admit_converged_owned(&mut manager, peer, gid, &mut output, &route);
    let old_policy = manager.export_policy_for(peer).cloned();
    let policy = deny_default_prefix_chain();
    manager.export_chains.insert(peer, Some(policy));
    let crate::manager::update_groups::GroupMembership::Grouped(destination) =
        manager.compute_update_group_membership(peer)
    else {
        panic!("groupable replacement");
    };
    assert_ne!(destination, gid);
    assert!(!manager.group_ribs.contains_key(&destination));
    let sender = manager.outbound_peers[&peer].clone();
    while sender.try_send(OutboundRouteUpdate::default()).is_ok() {}
    let resets = count_reset_attempts(&mut manager);
    let feed = manager.recompute_update_group(peer);
    assert!(
        feed.is_none(),
        "the current constructor remains EVPN-private"
    );
    assert_eq!(manager.grouped_member_of(peer), Some(destination));
    assert!(!manager.group_ribs[&destination].owns_evpn);
    assert!(!manager.group_ribs.contains_key(&gid));
    assert!(crate::manager::helpers::evpn_routes_equal(
        manager.adj_ribs_out[&peer].get_evpn(&route.key()).unwrap(),
        &admitted
    ));
    assert!(manager.has_private_evpn_handoff(peer));
    assert!(!manager.evpn_recovery_reset_pending(peer));
    assert_eq!(resets.load(Ordering::SeqCst), 0);
    assert!(old_policy.is_none());
}

#[test]
fn ordinary_owned_fanout_preserves_exact_rejection_withdrawals_and_actual_counts() {
    let (mut manager, first, gid, mut first_output) = fixture();
    manager.group_ribs.get_mut(&gid).unwrap().owns_evpn = false;
    let second = Ipv4Addr::new(192, 0, 2, 31).into();
    let (sender, mut second_output) = mpsc::channel(8);
    register(&mut manager, second, sender);
    while second_output.try_recv().is_ok() {}
    manager.group_ribs.get_mut(&gid).unwrap().owns_evpn = true;
    assert!(manager.register_evpn_recovery(second, false));
    let route = received(100);
    manager.ribs.insert(route.peer, AdjRibIn::new(route.peer));
    let resets = count_reset_attempts(&mut manager);
    manager.process_evpn_announce_chunk(route.peer, vec![route.clone()]);
    for (peer, output) in [(first, &mut first_output), (second, &mut second_output)] {
        let update = output.try_recv().unwrap();
        assert_eq!(update.evpn_announce.len(), 1);
        assert_eq!(update.evpn_withdraw, [] as [rustbgpd_wire::EvpnRouteKey; 0]);
        assert_eq!(manager.evpn_admitted_count(peer), 1);
        assert_eq!(manager.adj_ribs_out[&peer].evpn_len(), 0);
        assert!(output.try_recv().is_err());
    }
    manager.process_evpn_announce_chunk(route.peer, vec![route.clone()]);
    assert!(first_output.try_recv().is_err() && second_output.try_recv().is_err());
    let encoder = MockExactExportEncoder::accepting(11);
    encoder.set_profile(12, [crate::update::ExactExportKey::Evpn(route.key())]);
    manager.peer_export_encoders.insert(first, encoder.clone());
    let changed = received(200);
    manager.process_evpn_announce_chunk(changed.peer, vec![changed.clone()]);
    let rejected = first_output.try_recv().unwrap();
    assert!(rejected.evpn_announce.is_empty());
    assert_eq!(rejected.evpn_withdraw, [route.key()]);
    assert_eq!(manager.evpn_admitted_count(first), 0);
    let accepted = second_output.try_recv().unwrap();
    assert_eq!(accepted.evpn_announce.len(), 1);
    assert_eq!(
        accepted.evpn_withdraw,
        [] as [rustbgpd_wire::EvpnRouteKey; 0]
    );
    assert_eq!(
        manager.evpn_admitted_count(second),
        1,
        "same-key replacement"
    );
    assert!(
        manager
            .evpn_recovery
            .is_dormant(manager.evpn_recovery_handle(first).unwrap())
    );
    encoder.set_profile(13, []);
    let replacement = received(300);
    manager.process_evpn_announce_chunk(replacement.peer, vec![replacement]);
    assert_eq!(first_output.try_recv().unwrap().evpn_announce.len(), 1);
    assert_eq!(second_output.try_recv().unwrap().evpn_announce.len(), 1);
    assert_eq!(manager.evpn_admitted_count(first), 1);
    assert_eq!(manager.evpn_admitted_count(second), 1);
    manager.process_evpn_withdraw_chunk(route.peer, vec![route.key()]);
    assert_eq!(
        first_output.try_recv().unwrap().evpn_withdraw,
        [route.key()]
    );
    assert_eq!(
        second_output.try_recv().unwrap().evpn_withdraw,
        [route.key()]
    );
    assert_eq!(manager.evpn_admitted_count(first), 0);
    assert_eq!(manager.evpn_admitted_count(second), 0);
    assert_eq!(resets.load(Ordering::SeqCst), 0);
}

#[test]
fn owned_late_full_queue_captures_actual_displaced_old_before_delta_retirement() {
    let (mut manager, peer, gid, mut output) = fixture();
    let old = received(100);
    admit_converged_owned(&mut manager, peer, gid, &mut output, &old);
    assert_eq!(manager.evpn_admitted_count(peer), 1);
    let changed = received(200);
    manager
        .loc_rib
        .recompute_evpn(changed.key(), [&changed].into_iter());
    let sender = manager.outbound_peers[&peer].clone();
    let resets = count_reset_attempts(&mut manager);
    let mut checkpoints = 0;
    manager.distribute_evpn_keys_to_peer(peer, &HashSet::from([changed.key()]), &mut || {
        checkpoints += 1;
        // The injected existing member checkpoint runs AFTER shared staging
        // has passed its opportunistic full probe and retained displaced OLD.
        while sender.try_send(OutboundRouteUpdate::default()).is_ok() {}
    });
    assert!(checkpoints > 0);
    assert!(manager.dirty_peers.contains(&peer));
    assert_eq!(
        manager.evpn_admitted_count(peer),
        1,
        "refusal keeps actual count"
    );
    let handle = manager.evpn_recovery_handle(peer).unwrap();
    assert_eq!(
        manager.evpn_recovery.proof(handle).unwrap().unwrap().len(),
        1
    );
    assert!(
        manager
            .evpn_recovery
            .proof(handle)
            .unwrap()
            .unwrap()
            .contains(&old.key())
    );
    while let Ok(update) = output.try_recv() {
        assert!(update.evpn_announce.is_empty() && update.evpn_withdraw.is_empty());
    }
    manager.resync_dirty_peers_bounded();
    let update = output.try_recv().unwrap();
    assert_eq!(update.evpn_announce.len(), 1);
    assert_eq!(
        update.evpn_announce[0].attributes,
        manager.group_ribs[&gid]
            .table
            .get_evpn(&changed.key())
            .unwrap()
            .attributes
    );
    assert_eq!(update.evpn_withdraw, [] as [rustbgpd_wire::EvpnRouteKey; 0]);
    assert_eq!(manager.evpn_admitted_count(peer), 1);
    assert!(manager.evpn_recovery.is_dormant(handle));
    assert!(!manager.dirty_peers.contains(&peer));
    assert_eq!(resets.load(Ordering::SeqCst), 0);
}

#[test]
fn owned_refresh_replays_announcements_but_terminal_waits_for_current_completion() {
    for late_fault in [false, true] {
        let (mut manager, peer, gid, mut output) = fixture();
        let route = received(100);
        admit_converged_owned(&mut manager, peer, gid, &mut output, &route);
        manager.adj_rib_out_commit_stats.fail_evpn_feed_completion = late_fault;
        manager.send_route_refresh_response(peer, EVPN.0, EVPN.1);
        let data = output.try_recv().unwrap();
        assert_eq!(
            data.evpn_announce.len(),
            1,
            "a requested refresh replays full ANN"
        );
        assert_eq!(data.evpn_announce[0].key(), route.key());
        assert_eq!(data.evpn_withdraw, [] as [rustbgpd_wire::EvpnRouteKey; 0]);
        assert_eq!(
            data.refresh_markers,
            [(EVPN.0, EVPN.1, RouteRefreshSubtype::BoRR)]
        );
        assert!(!data.end_of_rib.contains(&EVPN));
        assert!(output.try_recv().is_err());
        assert_eq!(manager.evpn_admitted_count(peer), 1);
        let builds = manager.adj_rib_out_commit_stats.resync_builds;
        manager.retry_evpn_feed_markers_bounded();
        if late_fault {
            assert!(output.try_recv().is_err());
            assert!(manager.evpn_recovery_reset_pending(peer));
        } else {
            let marker = output.try_recv().unwrap();
            assert!(marker.evpn_announce.is_empty() && marker.evpn_withdraw.is_empty());
            assert_eq!(marker.end_of_rib, [EVPN]);
            assert_eq!(
                marker.refresh_markers,
                [(EVPN.0, EVPN.1, RouteRefreshSubtype::EoRR)]
            );
            assert!(!manager.has_evpn_feed_completion(peer));
        }
        assert_eq!(manager.adj_rib_out_commit_stats.resync_builds, builds);
    }
}

#[test]
fn full_mutable_input_reevaluation_proves_noop_without_reannouncing_owned_routes() {
    let (mut manager, peer, gid, mut output) = fixture();
    let route = received(100);
    admit_converged_owned(&mut manager, peer, gid, &mut output, &route);
    let handle = manager.evpn_recovery_handle(peer).unwrap();
    let stamp = manager.group_ribs[&gid].evpn_table_stamp;
    let resets = count_reset_attempts(&mut manager);
    let (reply, mut receipt) = oneshot::channel();
    manager.handle_reevaluate_peer_export_policies(&[peer], reply);
    assert!(receipt.try_recv().unwrap().is_ok());
    assert_eq!(manager.group_ribs[&gid].evpn_table_stamp, stamp);
    assert!(output.try_recv().is_err());
    assert_eq!(manager.evpn_admitted_count(peer), 1);
    assert!(manager.evpn_recovery.is_dormant(handle));
    assert!(!manager.has_evpn_feed_completion(peer));
    assert!(!manager.dirty_peers.contains(&peer));
    assert_eq!(resets.load(Ordering::SeqCst), 0);
}

#[test]
fn successful_replacement_during_held_eor_or_eorr_preserves_sparse_sequence() {
    for eorr in [false, true] {
        let (mut manager, peer, gid, mut output) = fixture();
        let route = received(100);
        let mut untouched = received(300);
        if let EvpnRoute::Imet(ref mut imet) = untouched.route {
            imet.ethernet_tag = EthernetTagId(2);
        } else {
            panic!("IMET fixture");
        }
        manager.ribs.insert(route.peer, AdjRibIn::new(route.peer));
        manager.process_evpn_announce_chunk(route.peer, vec![route.clone(), untouched.clone()]);
        assert_eq!(output.try_recv().unwrap().evpn_announce.len(), 2);
        assert!(manager.capture_shared_evpn_admitted(peer));
        let mut feed = manager
            .prepare_complete_evpn_feed(peer, gid, Some(gid), true)
            .unwrap();
        assert!(feed.announce.is_empty() && feed.withdraw.is_empty());
        feed.seal.required_markers = if eorr {
            RibManager::evpn_admitted_marker_bits(
                &[],
                &[(EVPN.0, EVPN.1, RouteRefreshSubtype::EoRR)],
            )
        } else {
            manager.pending_eor.insert(peer, HashSet::from([EVPN]));
            RibManager::evpn_admitted_marker_bits(&[EVPN], &[])
        };
        assert!(manager.try_send_and_commit_outbound_update(
            peer,
            OutboundCommitBatch {
                evpn_announce: feed.announce,
                evpn_withdraw: feed.withdraw,
                evpn_complete_feed: Some(feed.seal),
                ..OutboundCommitBatch::default()
            }
        ));
        assert!(output.try_recv().is_err());
        manager
            .rtc_eor_hold
            .insert(peer, tokio::time::Instant::now() + Duration::from_secs(60));
        let rib = manager
            .ribs
            .entry(route.peer)
            .or_insert_with(|| AdjRibIn::new(route.peer));
        rib.insert_evpn(route.clone());
        rib.insert_evpn(untouched.clone());
        let resets = count_reset_attempts(&mut manager);
        let builds = manager.adj_rib_out_commit_stats.resync_builds;
        let changed = received(200);
        manager.process_evpn_announce_chunk(changed.peer, vec![changed.clone()]);
        let update = output.try_recv().unwrap();
        assert_eq!(update.evpn_announce.len(), 1);
        assert_eq!(update.evpn_announce[0].key(), changed.key());
        assert_eq!(update.evpn_withdraw, [] as [rustbgpd_wire::EvpnRouteKey; 0]);
        assert!(!update.end_of_rib.contains(&EVPN));
        assert_eq!(
            update.refresh_markers,
            [] as [(Afi, Safi, RouteRefreshSubtype); 0]
        );
        assert!(
            output.try_recv().is_err(),
            "no duplicate or unchanged-key ANN"
        );
        assert_eq!(manager.evpn_admitted_count(peer), 2);
        assert!(manager.evpn_feed_is_current(peer));
        assert!(!manager.dirty_peers.contains(&peer));
        assert_eq!(manager.adj_rib_out_commit_stats.resync_builds, builds);
        manager.rtc_eor_hold.remove(&peer);
        manager.retry_evpn_feed_markers_bounded();
        let marker = output.try_recv().unwrap();
        assert!(marker.evpn_announce.is_empty() && marker.evpn_withdraw.is_empty());
        assert_eq!(marker.end_of_rib, if eorr { vec![] } else { vec![EVPN] });
        assert_eq!(
            marker.refresh_markers,
            if eorr {
                vec![(EVPN.0, EVPN.1, RouteRefreshSubtype::EoRR)]
            } else {
                vec![]
            }
        );
        assert_eq!(manager.adj_rib_out_commit_stats.resync_builds, builds);
        assert_eq!(resets.load(Ordering::SeqCst), 0);
    }
}
