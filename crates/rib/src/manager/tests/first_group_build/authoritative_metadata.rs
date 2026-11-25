use super::*;
use crate::PeerExportPolicyReplacement;
use crate::manager::tests::cursor_presize::rpol_chain;
use crate::manager::tests::exportability::MockExactExportEncoder;
use crate::manager::tests::update_groups::{community_chain, queue_replacement_readiness};
use rustbgpd_policy::PolicyChain;

fn installed(rows: u16, chain: PolicyChain) -> (RibManager, mpsc::Receiver<OutboundRouteUpdate>) {
    let peer = receiver(1);
    let (mut manager, _primary, _) = fixture(rows);
    manager.first_group_build_min_routes = usize::MAX;
    manager.handle_update(RibUpdate::SetPeerExportContext {
        peer,
        session_id: 1,
        local_role: Some(rustbgpd_wire::BgpRole::RouteServer),
    });
    manager.handle_update(RibUpdate::SetPeerRsControl {
        peer,
        session_id: 1,
        rs_control_asn: Some(65500),
    });
    manager.handle_update(RibUpdate::SetPeerExportEncoder {
        peer,
        session_id: 1,
        encoder: MockExactExportEncoder::accepting(1),
    });
    let (out, mut rx) = mpsc::channel(64);
    let mut up = test_peer_up(peer, 1, out);
    let RibUpdate::PeerUp { export_policy, .. } = &mut up else {
        unreachable!()
    };
    *export_policy = Some(chain);
    manager.handle_update(up);
    finish(&mut manager);
    assert!(rx.try_recv().is_ok());
    while rx.try_recv().is_ok() {}
    (manager, rx)
}

fn replace(
    manager: &mut RibManager,
    export_policy: Option<PolicyChain>,
) -> oneshot::Receiver<Result<Vec<PeerId>, crate::RibCommandError>> {
    let (reply, response) = oneshot::channel();
    manager.handle_update(RibUpdate::ReplacePeerExportPoliciesAuthoritatively {
        replacements: vec![PeerExportPolicyReplacement {
            peer: receiver(1),
            export_policy,
        }],
        reply,
    });
    response
}

#[test]
fn regex_export_policy_uses_the_synchronous_authoritative_path() {
    let (mut manager, _out) = installed(4, community_chain(64512));
    manager.first_group_build_min_routes = 1;
    let chain = rpol_chain(
        r#"policy p { term t { if route.as-path matches "65200$" { reject } } term rest { accept } }"#,
        &rustbgpd_policy::datasets::DatasetBindings::new(),
    );
    assert!(chain.requires_as_path_string());
    assert!(!chain.requires_peer_context());
    assert!(chain.compiled().referenced_datasets().next().is_none());
    let mut reply = replace(&mut manager, Some(chain.clone()));
    assert!(manager.first_group_build.is_none());
    assert_eq!(reply.try_recv().unwrap().unwrap(), Vec::<PeerId>::new());
    assert_eq!(manager.export_policy_for(receiver(1)), Some(&chain));
}

#[test]
fn generated_route_server_tag_policies_build_private_forward_and_restore_destinations() {
    for pair_action in ["", "add community 65401:1;"] {
        let generation = |tag| {
            rpol_chain(
                &format!(
                    "policy p {{ term tag {{ add community 65400:{tag}; {pair_action} accept }} }}"
                ),
                &rustbgpd_policy::datasets::DatasetBindings::new(),
            )
        };
        let a = generation(1000);
        let b = generation(2000);
        let (mut manager, _out) = installed(4, a.clone());
        manager.first_group_build_min_routes = 1;
        let mut forward = replace(&mut manager, Some(b.clone()));
        assert!(manager.accepted_reload_build());
        finish(&mut manager);
        assert_eq!(forward.try_recv().unwrap().unwrap(), Vec::<PeerId>::new());
        let peer = receiver(1);
        assert_eq!(manager.export_policy_for(peer), Some(&b));
        let (reply, mut restore) = oneshot::channel();
        manager.handle_update(RibUpdate::RestorePeerExportPoliciesAuthoritatively {
            replacements: vec![PeerExportPolicyReplacement {
                peer,
                export_policy: Some(a.clone()),
            }],
            reply,
        });
        assert!(manager.accepted_reload_build());
        finish(&mut manager);
        assert_eq!(
            restore.try_recv().unwrap().unwrap(),
            [crate::PeerExportPolicyRestoreReceipt::Restored { peer }]
        );
        assert_eq!(manager.export_policy_for(peer), Some(&a));
    }
}

async fn check_reload_readiness(close_destination: bool) {
    use crate::update::RibReadinessError::PolicyTransitionStalled;

    let (manager, mut out) = installed(2048, community_chain(64512));
    let (tx, rx) = mpsc::channel(8);
    let mut manager = manager.with_readiness_queries(rx);
    manager.first_group_build_min_routes = 1;
    let mut ack = replace(&mut manager, None);
    manager.advance_first_group_build();
    assert!(manager.accepted_reload_build());
    let mut healthy = queue_replacement_readiness(&tx);
    manager.drain_readiness_queries(None);
    assert_eq!(healthy.try_recv().unwrap().unwrap(), manager.loc_rib.len());

    tokio::time::advance(crate::manager::MAX_HEALTHY_POLICY_TRANSITION_AGE).await;
    let mut during = queue_replacement_readiness(&tx);
    manager.drain_readiness_queries(None);
    assert_eq!(during.try_recv().unwrap(), Err(PolicyTransitionStalled));
    if close_destination {
        out.close();
        for _ in 0..64 {
            manager.advance_first_group_build();
            if manager.first_group_retiring_slots().is_some() {
                break;
            }
        }
        assert!(
            manager
                .first_group_retiring_slots()
                .is_some_and(|slots| slots > 0)
        );
        let mut retiring = queue_replacement_readiness(&tx);
        manager.drain_readiness_queries(None);
        assert_eq!(retiring.try_recv().unwrap(), Err(PolicyTransitionStalled));
    }
    // A closed destination session retires the accepted build.
    let expected: &[_] = if close_destination {
        &[("reload_build", "source_changed", 1.0)]
    } else {
        &[]
    };
    crate::manager::tests::assert_paced_fallbacks(&manager.metrics, expected);
    let terminal = Arc::new(std::sync::Mutex::new(None));
    let captured = Arc::clone(&terminal);
    let terminal_tx = tx.clone();
    manager.replacement_readiness_test_hook = Some(Arc::new(move |stage| {
        if stage == "shared_inventory" {
            captured
                .lock()
                .unwrap()
                .get_or_insert_with(|| queue_replacement_readiness(&terminal_tx));
        }
    }));
    finish(&mut manager);
    assert_eq!(ack.try_recv().unwrap().unwrap(), Vec::<PeerId>::new());
    let mut at_commit = terminal
        .lock()
        .unwrap()
        .take()
        .expect("terminal inventory checkpoint");
    assert_eq!(at_commit.try_recv().unwrap(), Err(PolicyTransitionStalled));
    let mut after = queue_replacement_readiness(&tx);
    manager.drain_readiness_queries(None);
    assert_eq!(after.try_recv().unwrap().unwrap(), manager.loc_rib.len());
}

#[tokio::test(start_paused = true)]
async fn accepted_reload_readiness_keeps_its_age_through_terminal_inventory() {
    check_reload_readiness(false).await;
}

#[tokio::test(start_paused = true)]
async fn accepted_reload_readiness_keeps_its_age_through_retirement_and_fallback() {
    check_reload_readiness(true).await;
}

#[test]
fn removing_policy_repairs_wire_equal_router_id_for_table_and_delivery() {
    let peer = receiver(1);
    let (mut paced, mut paced_out) = installed(2048, community_chain(64512));
    let (mut synchronous, mut synchronous_out) = installed(2048, community_chain(64512));
    paced.first_group_build_min_routes = 1;
    let mut ack = replace(&mut paced, None);
    let changed = (0..32)
        .find_map(|_| {
            assert!(paced.first_group_build.is_some());
            paced.advance_first_group_build();
            (0..2048)
                .map(|i| prefixes(i)[0])
                .find(|&prefix| paced.first_group_contains(prefix))
        })
        .expect("a private no-policy destination staged an IPv4 winner");
    let new_id = Ipv4Addr::new(203, 0, 113, 91);
    for (manager, out) in [
        (&mut paced, &mut paced_out),
        (&mut synchronous, &mut synchronous_out),
    ] {
        let before = manager.loc_rib.get(&changed).unwrap().clone();
        assert_ne!(before.peer_router_id, new_id);
        // Two accepted updates restore the staged attributes before one repair.
        for pref in [150, 100] {
            let mut next = route(changed, SOURCE, pref);
            next.peer_router_id = new_id;
            manager.handle_update(test_routes_received(peer_v4(SOURCE), vec![next]));
            drain_route_chunks(manager);
        }
        let live = manager.loc_rib.get(&changed).unwrap();
        assert_eq!(live.peer_router_id, new_id);
        assert!(crate::manager::helpers::routes_equal(&before, live));
        while out.try_recv().is_ok() {}
    }
    assert!(matches!(
        ack.try_recv(),
        Err(oneshot::error::TryRecvError::Empty)
    ));
    let mut immediate = replace(&mut synchronous, None);
    assert_eq!(immediate.try_recv().unwrap().unwrap(), Vec::<PeerId>::new());
    finish(&mut paced);
    assert_eq!(ack.try_recv().unwrap().unwrap(), Vec::<PeerId>::new());
    for (manager, out) in [
        (&synchronous, &mut synchronous_out),
        (&paced, &mut paced_out),
    ] {
        assert!(manager.export_policy_for(peer).is_none());
        let group = &manager.group_ribs[&manager.grouped_member_of(peer).unwrap()];
        assert_eq!(group.table.get(&changed, 0).unwrap().peer_router_id, new_id);
        let mut delivered_ids = Vec::new();
        while let Ok(update) = out.try_recv() {
            delivered_ids.extend(
                update
                    .announce
                    .iter()
                    .filter(|r| r.prefix == changed)
                    .map(|r| r.peer_router_id),
            );
        }
        assert_eq!(delivered_ids, [new_id]);
    }
}
