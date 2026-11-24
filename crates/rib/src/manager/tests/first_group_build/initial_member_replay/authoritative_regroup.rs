//! Authoritative policy changes while an initial group replay is incomplete.
use super::*;
use crate::manager::tests::exportability::MockExactExportEncoder;
use crate::manager::tests::update_groups::deny_statement;
use crate::update::PeerExportPolicyReplacement;
use rustbgpd_policy::PolicyChain;

fn destination() -> PolicyChain {
    let mut policies = community_chain(TAG).policies;
    let mut deny = deny_statement(Ipv4Prefix::new(Ipv4Addr::UNSPECIFIED, 0));
    deny.prefix = None;
    deny.match_local_pref_ge = Some(200);
    policies[0].policy.entries.insert(0, deny);
    PolicyChain::from_named(policies)
}

fn replacement(peer: PeerId) -> Vec<PeerExportPolicyReplacement> {
    vec![PeerExportPolicyReplacement {
        peer,
        export_policy: Some(destination()),
    }]
}

fn reload(
    manager: &mut RibManager,
    peer: PeerId,
) -> oneshot::Receiver<Result<Vec<PeerId>, crate::update::RibCommandError>> {
    let (reply, response) = oneshot::channel();
    manager.handle_update(RibUpdate::ReplacePeerExportPoliciesAuthoritatively {
        replacements: replacement(peer),
        reply,
    });
    response
}

fn finish_reload(
    manager: &mut RibManager,
    mut response: oneshot::Receiver<Result<Vec<PeerId>, crate::update::RibCommandError>>,
) -> Vec<PeerId> {
    for _ in 0..128 {
        if let Ok(result) = response.try_recv() {
            return result.unwrap();
        }
        manager.advance_first_group_build();
    }
    panic!("authoritative reload did not reply");
}

#[tokio::test(start_paused = true)]
async fn partial_mover_withdraws_only_its_admitted_rows_before_the_initial_eor() {
    let (mut manager, tx, mut expected) = replay_fixture();
    let peer = receiver(1);
    let high: Vec<_> = (0..V4_ROWS).step_by(2).map(|i| prefixes(i)[0]).collect();
    manager.handle_update(test_routes_received(
        peer_v4(SOURCE),
        high.iter().map(|&key| route(key, SOURCE, 220)).collect(),
    ));
    drain_route_chunks(&mut manager);
    for key in &high {
        expected.remove(key);
    }
    manager.handle_update(RibUpdate::SetPeerExportEncoder {
        peer,
        session_id: 7,
        encoder: MockExactExportEncoder::accepting(1),
    });
    let mut rx = member(&mut manager, peer, 64, false, false);
    let first = first_page(&mut manager, &mut rx);
    assert!(manager.is_initial_member_replay(peer));
    let mut wire = BTreeMap::new();
    for row in first.announce.iter() {
        assert_eq!(row.communities(), &[] as &[u32]);
        wire.insert(row.prefix, (row.peer, row.local_pref(), Vec::new()));
    }
    let owed: BTreeSet<_> = high
        .iter()
        .copied()
        .filter(|p| wire.contains_key(p))
        .collect();
    assert!(!owed.is_empty() && owed.len() < high.len());

    let response = reload(&mut manager, peer);
    // A partial replay never takes the private build or the shared delta.
    assert!(!manager.accepted_reload_build());
    let residual = finish_reload(&mut manager, response);
    if !residual.is_empty() {
        assert_eq!(residual, [peer]);
        let (reply, response) = oneshot::channel();
        manager.handle_update(RibUpdate::ApplyPacedExportPolicies {
            replacements: replacement(peer),
            cost: None,
            reply,
        });
        let applied = response.await.unwrap().unwrap();
        assert_eq!(applied.applied, 1);
        assert!(applied.pending.is_empty() && applied.skipped.is_empty());
    }
    // Transport kept its first page's operation live through both commands.
    drop(first);
    let actor = tokio::spawn(manager.run_actor());
    let mut withdrawn = BTreeSet::new();
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            let page = delivered(rx.recv().await.unwrap());
            for &(prefix, path_id) in page.unicast_withdrawals() {
                assert_eq!(path_id, 0);
                assert!(
                    wire.remove(&prefix).is_some(),
                    "withdrew never-admitted {prefix}"
                );
                assert!(withdrawn.insert(prefix), "duplicate withdrawal of {prefix}");
            }
            for row in page.announce.iter() {
                assert_eq!(row.communities(), [TAG]);
                wire.insert(
                    row.prefix,
                    (row.peer, row.local_pref(), row.communities().to_vec()),
                );
            }
            if !page.end_of_rib.is_empty() {
                assert_eq!(page.end_of_rib, [FAMILY]);
                break;
            }
        }
    })
    .await
    .expect("initial End-of-RIB");
    assert_eq!(withdrawn, owed);
    assert_eq!(wire.len(), expected.len());
    for (prefix, (source, pref)) in expected {
        assert_eq!(wire[&prefix], (source, pref, vec![TAG]));
    }
    drop(tx);
    let manager = actor.await.unwrap();
    assert!(!manager.is_initial_member_replay(peer));
    assert!(rx.is_empty());
}

#[tokio::test(start_paused = true)]
async fn sibling_reload_restages_a_replacement_while_the_joiner_owes_its_initial_eor() {
    let (mut manager, tx, mut expected) = replay_fixture();
    let mover = receiver(1);
    manager.initial_member_replays.min_routes = Some(usize::MAX);
    let mut established = member(&mut manager, mover, 64, false, false);
    finish(&mut manager);
    assert_initial(&mut established, &expected, &[FAMILY]).await;
    manager.initial_member_replays.min_routes = Some(1);
    let joiner = receiver(2);
    let mut joining = member(&mut manager, joiner, 64, false, false);
    let first = first_page(&mut manager, &mut joining);
    let source = manager.grouped_member_of(joiner).unwrap();
    assert_eq!(manager.grouped_member_of(mover), Some(source));
    let mut wire = Inventory::new();
    for row in first.announce.iter() {
        assert_eq!(row.communities(), &[] as &[u32]);
        wire.insert(row.prefix, (row.peer, row.local_pref()));
    }

    let response = reload(&mut manager, mover);
    assert!(manager.accepted_reload_build());
    let staged = (0..32)
        .find_map(|_| {
            manager.advance_first_group_build();
            wire.keys()
                .copied()
                .find(|&key| manager.first_group_contains(key))
        })
        .expect("the private destination staged an already admitted joiner row");
    assert!(manager.is_initial_member_replay(joiner));
    manager.handle_update(test_routes_received(
        peer_v4(OTHER),
        vec![route(staged, OTHER, 130)],
    ));
    drain_route_chunks(&mut manager);
    expected.insert(staged, (peer_v4(OTHER), 130));

    // The established mover gets the selection change under its old policy,
    // followed by the rebuilt row under its new one at commit.
    let mut old_replacements = Vec::new();
    while let Ok(page) = established.try_recv().map(delivered) {
        assert_eq!(page.end_of_rib, Vec::<(Afi, Safi)>::new());
        old_replacements.extend(page.announce.iter().map(|row| {
            assert_eq!(row.communities(), &[] as &[u32]);
            (row.prefix, row.peer, row.local_pref())
        }));
    }
    assert_eq!(old_replacements, [(staged, peer_v4(OTHER), 130)]);
    assert_eq!(finish_reload(&mut manager, response), Vec::<PeerId>::new());
    assert_ne!(manager.grouped_member_of(mover), Some(source));
    assert_eq!(manager.grouped_member_of(joiner), Some(source));
    let mut target = Inventory::new();
    while let Ok(page) = established.try_recv().map(delivered) {
        assert_eq!(page.end_of_rib, Vec::<(Afi, Safi)>::new());
        assert_eq!(page.unicast_withdrawals().count(), 0);
        for row in page.announce.iter() {
            assert_eq!(row.communities(), [TAG]);
            assert!(
                target
                    .insert(row.prefix, (row.peer, row.local_pref()))
                    .is_none()
            );
        }
    }
    assert_eq!(target, expected);

    drop(first);
    let actor = tokio::spawn(manager.run_actor());
    let mut repaired = Vec::new();
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            let page = delivered(joining.recv().await.unwrap());
            assert_eq!(page.unicast_withdrawals().count(), 0);
            for row in page.announce.iter() {
                assert_eq!(row.communities(), &[] as &[u32]);
                let value = (row.peer, row.local_pref());
                if let Some(old) = wire.insert(row.prefix, value) {
                    repaired.push((row.prefix, old, value));
                }
            }
            if !page.end_of_rib.is_empty() {
                assert_eq!(page.end_of_rib, [FAMILY]);
                break;
            }
        }
    })
    .await
    .expect("sibling initial End-of-RIB");
    assert_eq!(
        repaired,
        [(staged, (peer_v4(SOURCE), 100), (peer_v4(OTHER), 130))]
    );
    assert_eq!(wire, expected);
    drop(tx);
    let _ = actor.await.unwrap();
    assert!(joining.is_empty() && established.is_empty());
}
