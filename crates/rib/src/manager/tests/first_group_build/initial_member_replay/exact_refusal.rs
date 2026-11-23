use super::*;
use crate::manager::slice_timing;
use crate::manager::tests::exportability::MockExactExportEncoder;
use crate::update::ExactExportKey;

fn replace_admitted_route(
    manager: &mut RibManager,
    rx: &mut mpsc::Receiver<OutboundRouteUpdate>,
    held: OutboundRouteUpdate,
    prefix: Prefix,
) -> OutboundRouteUpdate {
    manager.handle_update(test_routes_received(
        peer_v4(SOURCE),
        vec![route(prefix, SOURCE, 200)],
    ));
    drain_route_chunks(manager);
    drop(held);
    manager.wake_initial_member_replay();
    manager.advance_pending_initial_registration();
    rx.try_recv().expect("ordered replay change")
}

fn retained_refusal_prior_visits(rows: u16) -> usize {
    let (mut manager, _tx, _) = fixture(rows);
    manager.initial_member_replays.min_routes = Some(1);
    let peer = receiver(1);
    let mut rx = member(&mut manager, peer, 1, false, false);
    let first = first_page(&mut manager, &mut rx);
    let refused = first.announce[0].prefix;
    let accepted = first.announce[1].prefix;
    let refused_key = ExactExportKey::Unicast(refused, 0);
    let encoder = MockExactExportEncoder::accepting(1);
    encoder.set_profile(2, [refused_key.clone()]);
    manager.peer_export_encoders.insert(peer, encoder.clone());

    let withdrawal = replace_admitted_route(&mut manager, &mut rx, first, refused);
    assert!(withdrawal.announce.is_empty());
    assert_eq!(
        withdrawal
            .unicast_withdrawals()
            .copied()
            .collect::<Vec<_>>(),
        [(refused, 0)]
    );
    assert!(manager.peer_unexportable[&peer].contains(&refused_key));

    let visits = || {
        slice_timing::group_work()
            .get("exact_export_prior_visits")
            .copied()
            .unwrap_or(0)
    };
    let before = visits();
    let announcement = replace_admitted_route(&mut manager, &mut rx, withdrawal, accepted);
    assert_eq!(announcement.unicast_withdrawals().count(), 0);
    assert_eq!(announcement.announce.len(), 1);
    assert_eq!(announcement.announce[0].prefix, accepted);
    assert_eq!(announcement.announce[0].local_pref(), 200);
    assert_eq!(
        encoder.probed(),
        [refused_key.clone(), ExactExportKey::Unicast(accepted, 0)]
    );
    assert!(manager.peer_unexportable[&peer].contains(&refused_key));
    assert!(manager.is_initial_member_replay(peer));
    visits() - before
}

#[tokio::test(start_paused = true)]
async fn retained_exact_refusal_only_reconciles_the_current_replay_candidate() {
    let small = retained_refusal_prior_visits(1024);
    let large = retained_refusal_prior_visits(4096);
    eprintln!("prior visits for one candidate: 1024 routes={small}, 4096 routes={large}");
    assert_eq!(
        small, large,
        "one candidate must cost the same at both table sizes"
    );
    assert!(
        (1..=8).contains(&large),
        "visited {large} keys for one replay candidate"
    );
}
