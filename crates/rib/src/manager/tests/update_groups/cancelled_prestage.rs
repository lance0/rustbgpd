use super::*;

const ROWS: u32 = 2_050;

fn seed_cancelled_walk(
    manager: &mut RibManager,
    receivers: &mut [mpsc::Receiver<OutboundRouteUpdate>],
) {
    for first in (0..ROWS).step_by(256) {
        let routes = (first..(first + 256).min(ROWS))
            .map(|i| make_route_with_lp(overlap_prefix(i), OVERLAP_SOURCE, i + 100))
            .collect();
        churn_fixture_source(manager, routes, vec![]);
        for rx in &mut *receivers {
            while rx.try_recv().map(delivered).is_ok() {}
        }
    }
}

async fn check_founder_after_cleanup(
    founder: &mut mpsc::Receiver<OutboundRouteUpdate>,
    marker: Ipv4Prefix,
) {
    let mut observed = BTreeMap::new();
    loop {
        let update = fixture_update(founder.recv()).await;
        for r in update.announce.iter() {
            assert_ne!(update.announce_source_exclusion, Some(r.peer));
            assert_eq!(r.peer, peer_v4(OVERLAP_SOURCE));
            assert!(r.communities().is_empty());
            assert!(observed.insert(r.prefix, r.local_pref()).is_none());
        }
        if !update.end_of_rib.is_empty() {
            assert_eq!(update.end_of_rib, ipv4_sendable());
            break;
        }
    }
    assert_eq!(observed.remove(&Prefix::V4(marker)), Some(180));
    assert_eq!(observed.len(), ROWS as usize);
    for i in 0..ROWS {
        assert_eq!(observed[&Prefix::V4(overlap_prefix(i))], i + 100);
    }
}

#[tokio::test]
async fn abandoned_optional_walk_retires_while_updates_and_a_cold_join_progress() {
    use std::future::Future;
    use std::task::{Context, Waker};

    for phase in ["stage", "inventory", "probe"] {
        let (mut manager, peers, mut receivers) = direct_clean_transition_manager(2, 0, None);
        manager.outbound_row_credit_override = None;
        seed_cancelled_walk(&mut manager, &mut receivers);
        let source = manager.grouped_member_of(peers[0]).unwrap();
        let policy = rpol_community_chain(0xFDE8_0001);
        let retained = Arc::downgrade(policy.policies[0].rpol.as_ref().unwrap());
        let (reply, response) = oneshot::channel();
        manager.begin_destination_prestage(peers[0], Some(&policy), reply);
        let gid = manager
            .pending_destination_prestage
            .as_ref()
            .unwrap()
            .destination;
        loop {
            manager.advance_destination_prestage();
            assert!(manager.pending_destination_prestage.is_some());
            let inventory = manager.prestaged_inventory.as_ref();
            if match phase {
                "stage" => manager.group_ribs[&gid].table.len() >= 1_100,
                "inventory" => inventory.is_some_and(|state| state.announce.len() >= 1_100),
                _ => inventory.is_some_and(|state| state.probe.is_some()),
            } {
                break;
            }
        }
        manager.first_group_build_min_routes = 1;
        let mut founder = join_overlap_founder(&mut manager, 1);
        assert!(manager.first_group_build.is_none());
        drop(response);
        if phase == "inventory" {
            // A discard arriving before the next cancellation poll uses the same owner.
            manager.handle_update(RibUpdate::DiscardPreparedExportPolicyDestination {
                peer: peers[0],
                export_policy: Some(policy.clone()),
            });
        } else {
            manager.advance_destination_prestage();
        }
        drop(policy);
        assert!(manager.pending_destination_prestage.is_none());
        assert!(manager.prepared_destination.is_none());
        assert!(manager.prestaged_inventory.is_none());
        assert!(manager.group_ribs[&source].inventory_log.is_none());
        assert!(!manager.group_ribs.contains_key(&gid));
        assert!(manager.optional_destination_retirement_active(), "{phase}");
        assert_eq!(
            manager.advance_optional_destination_retirement(),
            crate::loc_rib::REGISTRATION_PAGE_SIZE
        );
        assert!(manager.optional_destination_retirement_active());
        // Restore a live flush budget after the deterministic single-row setup.
        manager.flush_poll_budget = std::time::Duration::from_millis(20);
        let marker = overlap_prefix(ROWS);
        let (tx, rx) = mpsc::channel(8);
        let (query, query_rx) = mpsc::channel(8);
        manager.rx = rx;
        manager.query_rx = query_rx;
        tx.try_send(super::super::lifecycle::test_routes_received(
            peer_v4(OVERLAP_SOURCE),
            vec![make_route_with_lp(marker, OVERLAP_SOURCE, 180)],
        ))
        .unwrap();
        let mut actor = Box::pin(manager.run_actor());
        let mut saw_marker = false;
        for _ in 0..16 {
            assert!(
                actor
                    .as_mut()
                    .poll(&mut Context::from_waker(Waker::noop()))
                    .is_pending()
            );
            while let Ok(update) = receivers[0].try_recv().map(delivered) {
                saw_marker |= update.announce.iter().any(|r| {
                    r.prefix == Prefix::V4(marker)
                        && r.peer == peer_v4(OVERLAP_SOURCE)
                        && r.local_pref() == 180
                        && r.communities().contains(&OVERLAP_TAG)
                });
            }
            if saw_marker {
                break;
            }
        }
        assert!(
            saw_marker && retained.upgrade().is_some(),
            "{phase}: established peer must receive marker during cleanup"
        );
        let handle = tokio::spawn(actor);
        check_founder_after_cleanup(&mut founder, marker).await;
        drop(tx);
        drop(query);
        let manager = handle.await.unwrap();
        assert!(retained.upgrade().is_none());
        assert!(!manager.optional_destination_retirement_active());
    }
}

struct CloseOnSnapshot {
    inner: Arc<dyn crate::update::ExactExportEncoder>,
    receiver: Mutex<Option<oneshot::Receiver<Result<(), String>>>>,
}

impl crate::update::ExactExportEncoder for CloseOnSnapshot {
    fn owner_id(&self) -> u64 {
        self.inner.owner_id()
    }
    fn snapshot(&self) -> Arc<dyn crate::update::ExactExportSnapshot> {
        drop(self.receiver.lock().unwrap().take());
        self.inner.snapshot()
    }
}

#[test]
fn failed_final_prepare_ack_detaches_the_completed_table_and_proof() {
    let (mut manager, peers, _rx) = direct_clean_transition_manager(2, 1, None);
    let policy = community_chain(0xFDE8_0001);
    let (reply, receiver) = oneshot::channel();
    manager.begin_destination_prestage(peers[0], Some(&policy), reply);
    let gid = manager
        .pending_destination_prestage
        .as_ref()
        .unwrap()
        .destination;
    let encoder = Arc::new(CloseOnSnapshot {
        inner: manager.peer_export_encoders[&peers[0]].clone(),
        receiver: Mutex::new(Some(receiver)),
    });
    manager
        .peer_export_encoders
        .insert(peers[0], encoder.clone());
    while manager.pending_destination_prestage.is_some() {
        manager.advance_destination_prestage();
    }
    assert!(encoder.receiver.lock().unwrap().is_none());
    assert!(
        manager.prepared_destination.is_none(),
        "unacknowledged optional preparation"
    );
    assert!(manager.prestaged_inventory.is_none());
    assert!(!manager.group_ribs.contains_key(&gid));
    assert!(manager.optional_destination_retirement_active());
    while manager.optional_destination_retirement_active() {
        manager.advance_optional_destination_retirement();
    }
    assert!(manager.first_group_slot_available());
}

#[tokio::test]
async fn queued_cohort_observes_prepare_timeout_before_its_first_staging_turn() {
    for abandoned in [true, false] {
        let (mut manager, peers, _rx) = direct_clean_transition_manager(2, 4, None);
        let policy = community_chain(0xFDE8_0001);
        let (reply, response) = oneshot::channel();
        manager.begin_destination_prestage(peers[0], Some(&policy), reply);
        manager.advance_destination_prestage();
        let gid = manager
            .pending_destination_prestage
            .as_ref()
            .unwrap()
            .destination;
        assert_eq!(manager.group_ribs[&gid].table.len(), 1);
        let live = (!abandoned).then_some(response);
        let (tx, rx) = mpsc::channel(8);
        manager.rx = rx;
        let (reply, applied) = oneshot::channel();
        tx.try_send(RibUpdate::ReplacePeerExportPolicies {
            replacements: batch_replacements(&peers, &policy),
            reply,
        })
        .unwrap();
        // Run the real primary drain before the next idle Prepare step.
        assert!(manager.drain_ready_updates().await);
        assert!(manager.pending_destination_prestage.is_none());
        if abandoned {
            assert!(manager.optional_destination_retirement_active());
            assert!(!manager.group_ribs.contains_key(&gid));
            assert!(manager.pending_clean_policy_transition.is_none());
            assert_eq!(manager.first_group_deferred_intents.len(), 1);
        } else {
            assert!(manager.pending_clean_policy_transition.is_some());
            assert!(!manager.optional_destination_retirement_active());
            assert!(manager.first_group_deferred_intents.is_empty());
        }
        drop(live);
        let actor = tokio::spawn(manager.run_actor());
        assert_eq!(
            applied.await.unwrap(),
            Ok(crate::update::ExportPolicyCohortOutcome::Committed)
        );
        drop(tx);
        let manager = actor.await.unwrap();
        let installed = manager.grouped_member_of(peers[0]).unwrap();
        assert_eq!(manager.grouped_member_of(peers[1]), Some(installed));
        assert_eq!(manager.group_ribs[&installed].table.len(), 4);
        assert_eq!(manager.export_policy_for(peers[0]), Some(&policy));
    }
}

#[tokio::test]
async fn same_policy_registration_waits_for_a_closed_legacy_preparation_below_threshold() {
    let (mut manager, peers, _rx) = direct_clean_transition_manager(2, 4, None);
    let policy = community_chain(0xFDE8_0001);
    let (reply, response) = oneshot::channel();
    manager.begin_destination_prestage(peers[0], Some(&policy), reply);
    manager.advance_destination_prestage();
    let gid = manager
        .pending_destination_prestage
        .as_ref()
        .unwrap()
        .destination;
    drop(response);
    let newcomer = peer_v4(Ipv4Addr::new(10, 43, 0, 9));
    let (tx, mut output) = mpsc::channel(8);
    let mut join = super::super::lifecycle::test_peer_up(newcomer, 17, tx);
    if let RibUpdate::PeerUp {
        export_policy,
        is_ebgp,
        route_reflector_client,
        ..
    } = &mut join
    {
        *export_policy = Some(policy);
        *is_ebgp = false;
        *route_reflector_client = true;
    }
    let (tx, rx) = mpsc::channel(8);
    manager.rx = rx;
    tx.try_send(join).unwrap();
    assert!(manager.drain_ready_updates().await);
    assert!(manager.optional_destination_retirement_active());
    assert!(manager.pending_initial_registrations.contains(&newcomer));
    assert!(!manager.group_ribs.contains_key(&gid));
    assert!(output.try_recv().is_err());
    let actor = tokio::spawn(manager.run_actor());
    let mut rows = BTreeSet::new();
    loop {
        let update = fixture_update(output.recv()).await;
        for row in update.announce.iter() {
            assert_eq!(row.communities(), &[0xFDE8_0001]);
            assert!(rows.insert(row.prefix));
        }
        if !update.end_of_rib.is_empty() {
            assert_eq!(update.end_of_rib, ipv4_sendable());
            break;
        }
    }
    assert_eq!(
        rows,
        (0..4).map(|i| Prefix::V4(fixture_prefix(i))).collect()
    );
    drop(tx);
    let manager = actor.await.unwrap();
    let gid = manager.grouped_member_of(newcomer).unwrap();
    assert_eq!(manager.group_ribs[&gid].table.len(), 4);
}
