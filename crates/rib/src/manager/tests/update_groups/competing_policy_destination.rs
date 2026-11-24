//! A different policy destination competes with a private or prepared table.

use super::*;

#[derive(Clone, Copy)]
enum Command {
    Clean,
    Batch,
    Restore,
}

impl Command {
    fn submit(
        self,
        manager: &mut RibManager,
        members: &[PeerId],
        target: &PolicyChain,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()>>> {
        let replacements = members
            .iter()
            .map(|&peer| crate::update::PeerExportPolicyReplacement {
                peer,
                export_policy: Some(target.clone()),
            })
            .collect();
        match self {
            Self::Clean => {
                let (reply, response) = oneshot::channel();
                manager.handle_update(RibUpdate::ReplacePeerExportPolicies {
                    replacements,
                    reply,
                });
                Box::pin(async move {
                    assert_eq!(
                        response.await.unwrap(),
                        Ok(crate::update::ExportPolicyCohortOutcome::Committed)
                    );
                })
            }
            Self::Batch => {
                let (reply, response) = oneshot::channel();
                manager.handle_update(RibUpdate::ReplacePeerExportPoliciesAuthoritatively {
                    replacements,
                    reply,
                });
                Box::pin(async move {
                    assert_eq!(response.await.unwrap(), Ok(Vec::new()));
                })
            }
            Self::Restore => {
                let (reply, response) = oneshot::channel();
                manager.handle_update(RibUpdate::RestorePeerExportPoliciesAuthoritatively {
                    replacements,
                    reply,
                });
                Box::pin(async move {
                    let receipts = response.await.unwrap().unwrap();
                    assert_eq!(receipts.len(), 2);
                    assert!(receipts.iter().all(|r| matches!(
                        r,
                        crate::update::PeerExportPolicyRestoreReceipt::Restored { .. }
                    )));
                })
            }
        }
    }
}

fn acknowledge_founders_destination(manager: &mut RibManager, peer: PeerId) {
    let (reply, mut response) = oneshot::channel();
    manager.handle_update(RibUpdate::PrepareExportPolicyDestination {
        peer,
        export_policy: None,
        reply,
    });
    while manager.first_group_build.is_some() {
        manager.advance_first_group_build();
    }
    assert_eq!(response.try_recv().unwrap(), Ok(()));
    assert!(manager.paced_policy_destination.is_some());
    assert_eq!(
        manager.paced_policy_destination,
        manager.prepared_destination
    );
}

// These direct fixtures own the actor and must drive any accepted build
// after the preceding founder releases its slot.
fn finish_replayed_reload(manager: &mut RibManager, member: PeerId, source: usize) {
    assert!(manager.accepted_reload_build());
    for _ in 0..32 {
        assert_eq!(manager.grouped_member_of(member), Some(source));
        manager.advance_first_group_build();
        if !manager.accepted_reload_build() {
            return;
        }
    }
    panic!("replayed authoritative reload did not settle");
}

async fn distinct_cold_destination(command: Command, acknowledge: bool) {
    let (mut manager, members, mut receivers) = direct_clean_transition_manager(2, 0, None);
    manager.outbound_row_credit_override = None;
    distribute_direct_routes(&mut manager, OVERLAP_SOURCE, (0..2050).map(overlap_prefix));
    for receiver in &mut receivers {
        while receiver.try_recv().map(delivered).is_ok() {}
    }
    manager.first_group_build_min_routes = 1;
    let mut founder = join_overlap_founder(&mut manager, 1);
    manager.advance_first_group_build();
    assert!(manager.first_group_build.is_some());
    if acknowledge {
        acknowledge_founders_destination(&mut manager, members[0]);
    }
    let old = manager.grouped_member_of(members[0]).unwrap();
    let policy = community_chain(0xfde8_2415);
    let has_target = |manager: &RibManager| {
        manager
            .group_ribs
            .values()
            .any(|group| group.export_chain.as_ref() == Some(&policy))
    };
    let response = command.submit(&mut manager, &members, &policy);
    assert!(
        manager.pending_clean_policy_transition.is_none(),
        "a competing clean fence would block ordinary UPDATEs"
    );
    assert!(
        !has_target(&manager),
        "a second provisional table was created"
    );
    assert_eq!(manager.grouped_member_of(members[0]), Some(old));
    assert_eq!(
        manager.optional_destination_retirement_active(),
        acknowledge
    );

    let marker = overlap_prefix(2050);
    distribute_direct_route(&mut manager, OVERLAP_SOURCE, marker);
    for receiver in &mut receivers {
        let update = delivered(receiver.try_recv().unwrap());
        assert!(
            update
                .announce
                .iter()
                .any(|route| route.prefix == Prefix::V4(marker)
                    && route.communities().contains(&OVERLAP_TAG))
        );
    }
    while manager.first_group_build.is_some() || manager.optional_destination_retirement_active() {
        assert!(!has_target(&manager));
        assert!(manager.take_first_group_deferred_intent().is_none());
        if acknowledge {
            assert!(
                manager.advance_optional_destination_retirement()
                    <= crate::loc_rib::REGISTRATION_PAGE_SIZE
            );
        } else {
            manager.advance_first_group_build();
        }
    }
    if !acknowledge {
        assert!(
            std::iter::from_fn(|| founder.try_recv().ok().map(delivered))
                .any(|update| update.end_of_rib == ipv4_sendable())
        );
    }
    let intent = manager
        .take_first_group_deferred_intent()
        .expect("oldest command released");
    manager.handle_update(intent);
    if matches!(command, Command::Batch | Command::Restore) {
        finish_replayed_reload(&mut manager, members[0], old);
    }
    while manager.pending_clean_policy_transition.is_some() {
        step_parked_transition(&mut manager);
    }
    response.await;
    let target = manager.grouped_member_of(members[0]).unwrap();
    assert_ne!(old, target);
    for member in members {
        assert_eq!(manager.grouped_member_of(member), Some(target));
        assert_eq!(manager.export_policy_for(member), Some(&policy));
    }
    assert_eq!(manager.group_ribs[&target].table.len(), 2051);
}

fn marker_from(peer: PeerId, prefix: Ipv4Prefix) -> RibUpdate {
    let IpAddr::V4(address) = peer.addr() else {
        unreachable!()
    };
    super::super::lifecycle::test_routes_received(
        peer,
        vec![make_route_with_lp(prefix, address, 170)],
    )
}

fn assert_replayed_marker_delivery(
    receiver: &mut mpsc::Receiver<OutboundRouteUpdate>,
    independent: Ipv4Prefix,
    stale: Ipv4Prefix,
    tag: Option<u32>,
) {
    let mut seen = false;
    while let Ok(update) = receiver.try_recv() {
        for row in update.announce.iter() {
            assert_ne!(row.prefix, Prefix::V4(stale), "route from ended session");
            if row.prefix == Prefix::V4(independent) {
                assert_eq!(row.communities(), tag.as_slice());
                seen = true;
            }
        }
    }
    assert!(
        seen,
        "surviving receiver did not receive the unrelated marker"
    );
}

#[tokio::test]
async fn replayed_reload_keeps_later_routes_behind_retained_session_and_policy_changes() {
    for (late_end, older_policy) in [(false, false), (true, false), (false, true)] {
        let (mut manager, members, mut receivers) = direct_clean_transition_manager(2, 0, None);
        let (primary, rx) = mpsc::channel(8);
        manager.rx = rx;
        manager.outbound_row_credit_override = None;
        distribute_direct_routes(&mut manager, OVERLAP_SOURCE, (0..2050).map(overlap_prefix));
        for rx in &mut receivers {
            while rx.try_recv().is_ok() {}
        }
        manager.first_group_build_min_routes = 1;
        let _founder = join_overlap_founder(&mut manager, 1);
        let target = community_chain(0xfde8_2415);
        let applied = Command::Batch.submit(&mut manager, &members, &target);
        let down = RibUpdate::PeerDown {
            peer: members[0],
            session_id: 0,
        };
        primary
            .try_send(if late_end {
                RibUpdate::LateSessionEnd(Box::new(down))
            } else {
                down
            })
            .unwrap();
        assert!(manager.drain_ready_updates().await);
        let (reply, mut policy_response) = oneshot::channel();
        if older_policy {
            // The surviving receiver must remove its tag before it sees new input.
            primary
                .try_send(RibUpdate::ReplacePeerExportPolicy {
                    peer: members[1],
                    export_policy: None,
                    reply,
                })
                .unwrap();
            assert!(manager.drain_ready_updates().await);
        }
        assert!(manager.session_end_retained());
        while manager.first_group_build.is_some() {
            manager.advance_first_group_build();
        }
        let accepted = manager.take_first_group_deferred_intent().unwrap();
        assert!(matches!(
            accepted,
            RibUpdate::ReplacePeerExportPoliciesAuthoritatively { .. }
        ));
        manager.handle_update(accepted);
        manager.advance_first_group_build();
        assert!(manager.accepted_reload_build() && manager.session_end_retained());
        assert_eq!(manager.current_session_id(members[0]), Some(0));

        let independent = overlap_prefix(2050);
        let stale = overlap_prefix(2051);
        let source = peer_v4(OVERLAP_SOURCE);
        primary.try_send(marker_from(source, independent)).unwrap();
        if !older_policy {
            assert!(manager.drain_ready_updates().await);
            drain_route_chunks(&mut manager);
            assert_eq!(
                manager.loc_rib.get(&Prefix::V4(independent)).unwrap().peer,
                source
            );
            let old = receivers[1]
                .try_recv()
                .expect("unrelated marker before reload commit");
            assert!(old.announce.iter().any(|row| {
                row.prefix == Prefix::V4(independent) && row.communities() == [OVERLAP_TAG]
            }));
        }
        primary.try_send(marker_from(members[0], stale)).unwrap();
        // Exercise admission and normal chunk application while the old session
        // still exists: a later teardown could hide the bad transient installation.
        while manager.drain_ready_updates().await {}
        assert!(manager.accepted_reload_build() && manager.session_end_retained());
        assert!(manager.loc_rib.get(&Prefix::V4(stale)).is_none());
        if older_policy {
            assert!(manager.loc_rib.get(&Prefix::V4(independent)).is_none());
        }
        assert!(manager.primary_lookahead.as_ref().is_some_and(|head| {
            head.session_peer() == Some(if older_policy { source } else { members[0] })
        }));

        drop(primary);
        let manager = Box::pin(manager.run_actor()).await;
        applied.await;
        assert!(manager.current_session_id(members[0]).is_none());
        assert!(manager.loc_rib.get(&Prefix::V4(stale)).is_none());
        assert_eq!(
            manager.loc_rib.get(&Prefix::V4(independent)).unwrap().peer,
            source
        );
        if older_policy {
            assert_eq!(policy_response.try_recv().unwrap(), Ok(()));
        }
        assert_replayed_marker_delivery(
            &mut receivers[1],
            independent,
            stale,
            (!older_policy).then_some(0xfde8_2415),
        );
    }
}

#[tokio::test]
async fn distinct_clean_destination_waits_for_founder_and_paced_prepare() {
    for acknowledged in [false, true] {
        distinct_cold_destination(Command::Clean, acknowledged).await;
    }
}

#[tokio::test]
async fn distinct_authoritative_destination_waits_for_founder_and_paced_prepare() {
    for acknowledged in [false, true] {
        distinct_cold_destination(Command::Batch, acknowledged).await;
        distinct_cold_destination(Command::Restore, acknowledged).await;
    }
}

#[test]
fn refused_cold_batch_replies_without_displacing_founder_or_prepared_destination() {
    for acknowledged in [false, true] {
        let (mut manager, members, mut receivers) = direct_clean_transition_manager(2, 0, None);
        distribute_direct_route(&mut manager, OVERLAP_SOURCE, overlap_prefix(0));
        for rx in &mut receivers {
            assert_eq!(delivered(rx.try_recv().unwrap()).announce.len(), 1);
        }
        let mut target = community_chain(OVERLAP_TAG);
        target.policies[0].policy.entries[0]
            .modifications
            .set_next_hop = Some(rustbgpd_policy::NextHopAction::Self_);
        manager.first_group_build_min_routes = 1;
        let mut founder = join_overlap_founder(&mut manager, 1);
        assert!(manager.first_group_build.is_some());
        if acknowledged {
            acknowledge_founders_destination(&mut manager, members[0]);
        }
        let held = manager.paced_policy_destination;
        let replacements = || batch_replacements(&members, &target);
        let (reply, mut forward) = oneshot::channel();
        manager.handle_update(RibUpdate::ReplacePeerExportPoliciesAuthoritatively {
            replacements: replacements(),
            reply,
        });
        assert_eq!(forward.try_recv().unwrap(), Ok(members.clone()));
        let (reply, mut restore) = oneshot::channel();
        manager.handle_update(RibUpdate::RestorePeerExportPoliciesAuthoritatively {
            replacements: replacements(),
            reply,
        });
        let receipts = restore.try_recv().unwrap().unwrap();
        assert_eq!(
            receipts,
            members
                .iter()
                .rev()
                .map(|&peer| crate::update::PeerExportPolicyRestoreReceipt::Deferred { peer })
                .collect::<Vec<_>>()
        );
        assert!(manager.first_group_pending_writer().is_none());
        assert!(manager.first_group_deferred_intents.is_empty());
        assert!(!manager.optional_destination_retirement_active());
        assert_eq!(manager.paced_policy_destination, held);
        assert_eq!(manager.prepared_destination, held);
        assert_eq!(manager.first_group_build.is_some(), !acknowledged);
        assert!(
            manager
                .group_ribs
                .values()
                .all(|group| group.export_chain.as_ref() != Some(&target))
        );
        assert_eq!(manager.authoritative_transition_receipts.len(), 2);
        for receipt in &manager.authoritative_transition_receipts {
            assert_eq!(
                (receipt.destination_builds, receipt.destination_ensures),
                (0, 0)
            );
        }
        let marker = overlap_prefix(1);
        distribute_direct_route(&mut manager, OVERLAP_SOURCE, marker);
        for rx in &mut receivers {
            let update = delivered(rx.try_recv().unwrap());
            assert!(
                update
                    .announce
                    .iter()
                    .any(|row| row.prefix == Prefix::V4(marker)
                        && row.communities().contains(&OVERLAP_TAG))
            );
        }
        for _ in 0..64 {
            if manager.first_group_build.is_none()
                && manager.pending_initial_registrations.is_empty()
            {
                break;
            }
            manager.advance_pending_initial_registration();
        }
        let mut expected = HashSet::from([Prefix::V4(overlap_prefix(0)), Prefix::V4(marker)]);
        let mut eors = 0;
        while let Ok(update) = founder.try_recv().map(delivered) {
            for row in update.announce.iter() {
                assert_eq!(eors, 0);
                assert!(expected.remove(&row.prefix));
            }
            if !update.end_of_rib.is_empty() {
                assert_eq!(update.end_of_rib, ipv4_sendable());
                eors += 1;
            }
        }
        assert!(expected.is_empty());
        assert_eq!(eors, 1);
    }
}

#[tokio::test]
async fn occupied_policy_destination_can_commit_while_an_unrelated_founder_scans() {
    let (mut manager, members, _receivers) = direct_clean_transition_manager(3, 1, None);
    let policy = community_chain(0xfde8_2416);
    let (reply, mut applied) = oneshot::channel();
    manager.handle_update(RibUpdate::ReplacePeerExportPolicy {
        peer: members[2],
        export_policy: Some(policy.clone()),
        reply,
    });
    assert_eq!(applied.try_recv().unwrap(), Ok(()));
    let warm = manager.grouped_member_of(members[2]).unwrap();
    manager.first_group_build_min_routes = 1;
    let _founder = join_overlap_founder(&mut manager, 1);
    assert!(manager.first_group_build.is_some());
    Command::Batch
        .submit(&mut manager, &members[..2], &policy)
        .await;
    assert!(manager.first_group_build.is_some());
    assert!(manager.first_group_pending_writer().is_none());
    assert!(
        members
            .iter()
            .all(|peer| manager.grouped_member_of(*peer) == Some(warm))
    );
}

#[tokio::test]
async fn policy_removal_waits_for_a_different_plain_registration_profile() {
    let (mut manager, members, _receivers) = direct_clean_transition_manager(2, 1, None);
    manager.first_group_build_min_routes = 1;
    let (out, _founder) = mpsc::channel(16);
    let peer = peer_v4(Ipv4Addr::new(10, 43, 0, 55));
    let mut up = super::super::lifecycle::test_peer_up(peer, 18, out);
    if let RibUpdate::PeerUp {
        sendable_families,
        is_ebgp,
        route_reflector_client,
        ..
    } = &mut up
    {
        *is_ebgp = false;
        *route_reflector_client = true;
        sendable_families.push((Afi::Ipv6, Safi::Unicast));
    }
    manager.handle_update(up);
    assert!(manager.first_group_build.is_some());
    let (reply, mut result) = oneshot::channel();
    manager.handle_update(RibUpdate::ReplacePeerExportPoliciesAuthoritatively {
        replacements: members
            .iter()
            .map(|&peer| crate::update::PeerExportPolicyReplacement {
                peer,
                export_policy: None,
            })
            .collect(),
        reply,
    });
    assert_eq!(
        result.try_recv().unwrap_err(),
        oneshot::error::TryRecvError::Empty
    );
    while manager.first_group_build.is_some() {
        manager.advance_first_group_build();
    }
    let intent = manager
        .take_first_group_deferred_intent()
        .expect("single-stack cohort waits for the dual-stack founder");
    let source = manager.grouped_member_of(members[0]).unwrap();
    manager.handle_update(intent);
    finish_replayed_reload(&mut manager, members[0], source);
    assert_eq!(result.try_recv().unwrap(), Ok(Vec::new()));
    assert_ne!(
        manager.grouped_member_of(peer),
        manager.grouped_member_of(members[0])
    );
    assert!(manager.export_policy_for(members[0]).is_none());
}

#[tokio::test]
async fn queued_distinct_policy_allows_old_policy_update_during_paced_prepare_retirement() {
    const ROWS: u32 = 10_240;
    let (mut manager, members, mut receivers) = direct_clean_transition_manager(3, 0, None);
    manager.outbound_row_credit_override = None;
    for start in (0..ROWS).step_by(512) {
        distribute_direct_routes(
            &mut manager,
            OVERLAP_SOURCE,
            (start..start + 512).map(overlap_prefix),
        );
        for receiver in &mut receivers {
            while receiver.try_recv().map(delivered).is_ok() {}
        }
    }
    manager.first_group_build_min_routes = 1;
    let _founder = join_overlap_founder(&mut manager, 1);
    let (reply, mut prepared) = oneshot::channel();
    manager.handle_update(RibUpdate::PrepareExportPolicyDestination {
        peer: members[0],
        export_policy: None,
        reply,
    });
    while manager.first_group_build.is_some() {
        manager.advance_first_group_build();
    }
    assert_eq!(prepared.try_recv().unwrap(), Ok(()));
    let held = manager.paced_policy_destination.unwrap();
    assert_eq!(manager.group_ribs[&held].table.len(), ROWS as usize);
    let old = manager.grouped_member_of(members[0]).unwrap();
    manager.flush_poll_budget = std::time::Duration::MAX;
    let (primary, rx) = mpsc::channel(8);
    manager.rx = rx;
    let (queries, rx) = mpsc::channel(4);
    manager.query_rx = rx;
    let policy = community_chain(0xfde8_2421);
    let (reply, mut applied) = oneshot::channel();
    primary
        .try_send(RibUpdate::ReplacePeerExportPoliciesAuthoritatively {
            replacements: members[..2]
                .iter()
                .map(|&peer| crate::update::PeerExportPolicyReplacement {
                    peer,
                    export_policy: Some(policy.clone()),
                })
                .collect(),
            reply,
        })
        .unwrap();
    let prefix = overlap_prefix(ROWS);
    primary
        .try_send(super::super::lifecycle::test_routes_received(
            peer_v4(OVERLAP_SOURCE),
            vec![make_route_with_lp(prefix, OVERLAP_SOURCE, 170)],
        ))
        .unwrap();
    let mut actor = Box::pin(manager.run_actor());
    let wire = observe_policy_during_retirement(
        actor.as_mut(),
        ROWS as usize,
        &mut receivers,
        query_update_group(&queries, members[0]),
        old,
    );
    assert!(matches!(
        applied.try_recv(),
        Err(oneshot::error::TryRecvError::Empty)
    ));
    for witness in &wire {
        assert!(witness.iter().any(|update| {
            update.announce.iter().any(|row| {
                row.prefix == Prefix::V4(prefix)
                    && row.local_pref() == 170
                    && row.communities().contains(&OVERLAP_TAG)
            })
        }));
    }
    let actor = tokio::spawn(actor);
    assert_eq!(applied.await.unwrap(), Ok(Vec::new()));
    drop(primary);
    drop(queries);
    let manager = actor.await.unwrap();
    for peer in &members[..2] {
        assert_eq!(manager.export_policy_for(*peer), Some(&policy));
        assert_ne!(manager.grouped_member_of(*peer), Some(old));
    }
    assert_eq!(manager.grouped_member_of(members[2]), Some(old));
}
