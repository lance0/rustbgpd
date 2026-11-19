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
        let (reply, mut response) = oneshot::channel();
        manager.handle_update(RibUpdate::PrepareExportPolicyDestination {
            peer: members[0],
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
    let old = manager.grouped_member_of(members[0]).unwrap();
    let policy = community_chain(0xfde8_2415);
    let (_, target) = manager
        .clean_policy_transition_destination(members[0], Some(&policy))
        .unwrap();
    let response = command.submit(&mut manager, &members, &policy);
    assert!(
        manager.pending_clean_policy_transition.is_none(),
        "a competing clean fence would block ordinary UPDATEs"
    );
    assert!(
        !manager.group_ribs.contains_key(&target),
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
        assert!(!manager.group_ribs.contains_key(&target));
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
    while manager.pending_clean_policy_transition.is_some() {
        step_parked_transition(&mut manager);
    }
    response.await;
    for member in members {
        assert_eq!(manager.grouped_member_of(member), Some(target));
        assert_eq!(manager.export_policy_for(member), Some(&policy));
    }
    assert_eq!(manager.group_ribs[&target].table.len(), 2051);
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
