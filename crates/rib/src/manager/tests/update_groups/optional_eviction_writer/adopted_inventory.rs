//! An ordinary first adopter owns the live table while its unused proof retires.

use super::*;

fn observe_adoption_update(
    mut actor: std::pin::Pin<&mut impl std::future::Future>,
    mut receivers: [(&mut mpsc::Receiver<OutboundRouteUpdate>, u32); 3],
    marker: Ipv4Prefix,
) {
    use std::task::{Context, Waker};

    let mut reached = [false; 3];
    for _ in 0..4 {
        let mut cx = Context::from_waker(Waker::noop());
        assert!(actor.as_mut().poll(&mut cx).is_pending());
        for (i, (rx, tag)) in receivers.iter_mut().enumerate() {
            while let Ok(update) = rx.try_recv().map(delivered) {
                for row in update.announce.iter() {
                    assert_eq!(
                        (row.prefix, row.local_pref(), row.communities()),
                        (Prefix::V4(marker), 177, &[*tag][..])
                    );
                    assert!(!std::mem::replace(&mut reached[i], true));
                }
            }
        }
        if reached == [true; 3] {
            break;
        }
    }
    assert_eq!(
        reached, [true; 3],
        "ordinary UPDATE reaches both live groups during disposal"
    );
}

async fn receive_cold_inventory(
    cold: &mut mpsc::Receiver<OutboundRouteUpdate>,
    expected: &BTreeMap<Prefix, u32>,
) {
    let mut state = Received::default();
    while state.ends == 0 {
        let update = delivered(cold.recv().await.unwrap());
        let before = state.rows.len();
        state.apply(&update);
        assert_eq!(state.rows.len() - before, update.announce.len());
    }
    assert_eq!(state.ends, 1);
    state.check(expected, &[]);
}

#[tokio::test]
async fn ordinary_adopter_retires_the_acknowledged_inventory_and_unlocks_cold_registration() {
    use crate::loc_rib::REGISTRATION_PAGE_SIZE;
    let (mut manager, members, mut witnesses) = direct_clean_transition_manager(2, 0, None);
    manager.outbound_row_credit_override = None;
    let (_, mut expected) = seed_old_inventory(&mut manager, &mut witnesses);
    let target = community_chain(NEXT_TAG);
    let source = manager.grouped_member_of(members[0]).unwrap();
    let destination = completed_preparation(&mut manager, members[0], &target);
    let scratch = manager.prestaged_inventory.as_ref().unwrap();
    assert_eq!(scratch.announce.len(), ROWS as usize);
    assert!(scratch.probe.is_some());
    // Populate both real change logs after the caller has received its reply.
    let logged = overlap_prefix(ROWS);
    distribute_direct_route(&mut manager, OVERLAP_SOURCE, logged);
    expected.insert(Prefix::V4(logged), 100);
    for gid in [source, destination] {
        let log = manager.group_ribs[&gid].inventory_log.as_ref().unwrap();
        assert!(log.contains_key(&(Prefix::V4(logged), 0)));
    }
    for witness in &mut witnesses {
        while witness.try_recv().is_ok() {}
    }

    manager.initial_dump_defer_min_routes = usize::MAX;
    manager.flush_poll_budget = std::time::Duration::MAX;
    let (primary, rx) = mpsc::channel(16);
    manager.rx = rx;
    let (query, qrx) = mpsc::channel(8);
    manager.query_rx = qrx;
    let adopter = peer_v4(Ipv4Addr::new(10, 43, 2, 1));
    let mut joined = queue_late_registration(&primary, adopter, target.clone());
    assert!(manager.drain_ready_updates().await);
    assert_eq!(manager.grouped_member_of(adopter), Some(destination));
    Received::initial(&mut joined, &expected, &[NEXT_TAG]);
    assert_eq!(manager.prepared_destination, None);
    assert!(
        manager.prestaged_inventory.is_none(),
        "first adopter must detach the unused inventory"
    );
    for gid in [source, destination] {
        assert!(
            manager.group_ribs[&gid].inventory_log.is_none(),
            "group {gid} still logs churn"
        );
    }
    assert!(manager.optional_destination_retirement_active());
    assert_eq!(
        manager.advance_optional_destination_retirement(),
        REGISTRATION_PAGE_SIZE
    );
    assert!(!manager.first_group_slot_available());

    // Cold work must wait, but this second ordinary join has a live destination.
    manager.first_group_build_min_routes = 1;
    let mut cold = join_overlap_founder(&mut manager, 3);
    assert!(manager.first_group_build.is_none() && cold.is_empty());
    let warm = peer_v4(Ipv4Addr::new(10, 43, 2, 2));
    let mut second = queue_late_registration(&primary, warm, target);
    assert!(manager.drain_ready_updates().await);
    assert_eq!(manager.grouped_member_of(warm), Some(destination));
    Received::initial(&mut second, &expected, &[NEXT_TAG]);

    let marker = overlap_prefix(ROWS + 1);
    primary
        .try_send(crate::manager::tests::lifecycle::test_routes_received(
            peer_v4(OVERLAP_SOURCE),
            vec![make_route_with_lp(marker, OVERLAP_SOURCE, 177)],
        ))
        .unwrap();
    let mut actor = Box::pin(manager.run_actor());
    observe_adoption_update(
        actor.as_mut(),
        [
            (&mut witnesses[0], OVERLAP_TAG),
            (&mut joined, NEXT_TAG),
            (&mut second, NEXT_TAG),
        ],
        marker,
    );
    assert!(
        cold.is_empty(),
        "four polls cannot release the remaining inventory"
    );
    expected.insert(Prefix::V4(marker), 177);

    let actor = tokio::spawn(actor);
    tokio::time::timeout(
        Duration::from_secs(30),
        receive_cold_inventory(&mut cold, &expected),
    )
    .await
    .expect("cold replay after inventory retirement");
    drop(primary);
    drop(query);
    let manager = actor.await.unwrap();
    assert!(manager.first_group_slot_available());
    assert_eq!(manager.grouped_member_of(adopter), Some(destination));
    assert_eq!(manager.grouped_member_of(warm), Some(destination));
    assert!(
        manager.group_ribs[&destination]
            .table
            .get(&Prefix::V4(marker), 0)
            .is_some()
    );
}
