//! A session's ingest permit travels with its route-bearing message and
//! returns when the RIB has finished the message, whatever path finishes or
//! discards it. Every assertion reads the budget's count, never a clock.

use super::evpn::{evpn_update, zero_budget_evpn_fanout};
use super::timer_cutoffs::{
    connect_peer, followed, followed_trace, received, restart, run_until, trace_of,
};
use super::*;
use crate::ingest_budget::{INGEST_BUDGET_ROUTES, IngestBudget};
use crate::test_support::peer_v4;
use std::future::Future;
use std::task::{Context, Waker};

const SOURCE: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
const OBSERVER: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 4);

fn test_manager() -> (mpsc::Sender<RibUpdate>, RibManager) {
    let (tx, rx) = mpsc::channel(16);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    (tx, manager)
}

/// `count` distinct host routes from `address`, numbered from `first`.
fn host_routes(address: Ipv4Addr, first: u32, count: usize) -> Vec<Route> {
    (0..count)
        .map(|i| {
            let host = Ipv4Addr::from(0xc612_0000 + first + u32::try_from(i).unwrap());
            make_route(Ipv4Prefix::new(host, 32), address)
        })
        .collect()
}

/// The message a session sends: `update` charged to `budget`.
fn metered(update: RibUpdate, budget: &Arc<IngestBudget>) -> RibUpdate {
    let update = update.metered(budget);
    assert!(matches!(update, RibUpdate::SessionRoutes { .. }));
    update
}

fn typed_family_messages(peer: PeerId) -> Vec<(&'static str, RibUpdate, usize)> {
    vec![
        (
            "bgp-ls",
            RibUpdate::BgpLsRoutesReceived {
                peer,
                session_id: 1,
                announced: vec![make_bgpls_route(SOURCE, 7, 100)],
                withdrawn: vec![make_bgpls_route(SOURCE, 8, 100).key()],
            },
            2,
        ),
        (
            "vpn",
            RibUpdate::VpnRoutesReceived {
                peer,
                session_id: 1,
                announced: vec![make_vpn_rib_route(SOURCE, 1, 100, 100)],
                withdrawn: vec![make_vpn_rib_route(SOURCE, 2, 100, 100).key()],
            },
            2,
        ),
        (
            "labeled",
            RibUpdate::LabeledRoutesReceived {
                peer,
                session_id: 1,
                announced: vec![make_labeled_rib_route(SOURCE, 1, 100, 100)],
                withdrawn: vec![make_labeled_rib_route(SOURCE, 2, 100, 100).key()],
            },
            2,
        ),
        (
            "rtc",
            RibUpdate::RtcRoutesReceived {
                peer,
                session_id: 1,
                announced: vec![make_rtc_rib_route(SOURCE, 100, 100)],
                withdrawn: vec![make_rtc_rib_route(SOURCE, 200, 100).key()],
            },
            2,
        ),
    ]
}

/// Every route-bearing variant is charged one route per announced or
/// withdrawn entry, and anything else passes uncharged: a family that went
/// around the budget would let a mixed-family peer starve the others.
/// Red proof: dropping a variant from `RibUpdate::metered` leaves its
/// message without a permit.
#[test]
fn every_route_bearing_variant_is_charged() {
    let peer = peer_v4(SOURCE);
    let mut with_withdrawals = received(SOURCE, 1, host_routes(SOURCE, 0, 3));
    if let RibUpdate::RoutesReceived { withdrawn, .. } = &mut with_withdrawals {
        withdrawn.extend([
            (Prefix::V4(followed()), 0),
            (
                Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, 0), 24)),
                0,
            ),
        ]);
    }
    let mut cases = vec![
        ("unicast", received(SOURCE, 1, host_routes(SOURCE, 0, 3)), 3),
        ("unicast with withdrawals", with_withdrawals, 5),
        (
            "wire",
            RibUpdate::WireRoutesReceived(crate::update::WireRoutesReceived::new(
                received(SOURCE, 1, host_routes(SOURCE, 0, 4)),
                0,
            )),
            4,
        ),
        (
            "evpn",
            evpn_update(
                SOURCE,
                vec![make_evpn_imet(SOURCE, 1), make_evpn_imet(SOURCE, 2)],
                vec![make_evpn_imet(SOURCE, 3).key()],
            ),
            3,
        ),
    ];
    cases.extend(typed_family_messages(peer));
    for (family, update, routes) in cases {
        let budget = IngestBudget::new();
        let update = update.metered(&budget);
        assert!(
            matches!(update, RibUpdate::SessionRoutes { .. }),
            "{family} carries a permit"
        );
        assert_eq!(budget.unfinished(), routes, "{family}");
        assert_eq!(update.session_peer(), Some(peer), "{family}");
        drop(update);
        assert_eq!(budget.unfinished(), 0, "{family}");
    }
    let budget = IngestBudget::new();
    let end_of_rib = RibUpdate::EndOfRib {
        peer,
        session_id: 1,
        afi: Afi::Ipv4,
        safi: Safi::Unicast,
    }
    .metered(&budget);
    assert!(matches!(end_of_rib, RibUpdate::EndOfRib { .. }));
    assert_eq!(budget.unfinished(), 0);
}

/// A queued batch keeps its permit through every chunk and returns it only
/// with the pass that distributes its routes.
/// Red proof: a permit left behind at dispatch returns before the first
/// chunk runs.
#[test]
fn queued_batch_holds_its_permit_until_its_last_chunk() {
    let (_tx, mut manager) = test_manager();
    let _source_rx = connect_peer(&mut manager, SOURCE, 1, false, false);
    let budget = IngestBudget::new();
    let routes = 2 * ROUTES_RECEIVED_CHUNK_SIZE + 1;
    manager.handle_update(metered(
        received(SOURCE, 1, host_routes(SOURCE, 0, routes)),
        &budget,
    ));
    assert_eq!(budget.unfinished(), routes, "queued, nothing ingested");
    assert!(manager.process_next_route_chunk());
    assert!(manager.process_next_route_chunk());
    assert_eq!(budget.unfinished(), routes, "two of three chunks ingested");
    while manager.process_next_route_chunk() {}
    assert_eq!(budget.unfinished(), 0);
}

/// A message that joins an open distribution window is not finished when its
/// chunks are ingested: its permit returns with the window's one pass.
/// Red proof: without the window holding permits, the first message's budget
/// returns while its routes still wait for the pass.
#[test]
fn coalesced_message_holds_its_permit_until_the_window_settles() {
    let (tx, mut manager) = test_manager();
    super::distribution_window::untimed_window(&mut manager);
    let _source_rx = connect_peer(&mut manager, SOURCE, 1, false, false);
    let mut observer_rx = connect_peer(&mut manager, OBSERVER, 1, false, false);
    while observer_rx.try_recv().is_ok() {}
    let budget = IngestBudget::new();
    manager.handle_update(metered(
        received(SOURCE, 1, host_routes(SOURCE, 0, 2)),
        &budget,
    ));
    tx.try_send(metered(
        received(SOURCE, 1, host_routes(SOURCE, 2, 3)),
        &budget,
    ))
    .unwrap();
    assert!(
        manager.process_next_route_chunk(),
        "the first message drains and the window admits the second"
    );
    assert!(observer_rx.try_recv().is_err(), "nothing distributed yet");
    assert_eq!(budget.unfinished(), 5, "both messages wait for the pass");
    while manager.process_next_route_chunk() {}
    assert!(observer_rx.try_recv().is_ok(), "the window's pass ran");
    assert_eq!(budget.unfinished(), 0);
}

/// A batch whose EVPN fan-out is parked across actor turns is unfinished
/// until the last receiver has its rows.
/// Red proof: returning the permit when a chunk is ingested reads 0 while
/// the fan-out is parked.
#[test]
fn parked_evpn_fanout_holds_the_permit_until_it_drains() {
    let (mut manager, _peers) = zero_budget_evpn_fanout(3);
    let source = Ipv4Addr::new(10, 0, 3, 1);
    register_test_peer(&mut manager, peer_v4(source), 0);
    let budget = IngestBudget::new();
    manager.handle_update(metered(
        evpn_update(source, vec![make_evpn_imet(source, 1)], vec![]),
        &budget,
    ));
    let mut parked_steps = 0;
    while manager.process_next_route_chunk() {
        if manager.pending_evpn_fanout.is_some() {
            parked_steps += 1;
            assert_eq!(budget.unfinished(), 1, "parked: receivers still owed");
        }
    }
    assert!(parked_steps > 0, "the fan-out parked at least once");
    assert_eq!(budget.unfinished(), 0);
}

/// Selection deferral does not hold a permit: the routes are ingested and
/// the batch finished, so a restarting peer's End-of-RIB, which ends the
/// deferral, can always be read.
#[tokio::test]
async fn selection_deferral_returns_the_permit_at_ingest() {
    let (_tx, rx) = mpsc::channel(16);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new())
        .with_selection_deferral(SelectionDeferralConfig {
            timeout: Duration::from_secs(60),
            waiters: vec![SelectionDeferralWaiterConfig {
                peer: peer_v4(SOURCE).into(),
                families: vec![(Afi::Ipv4, Safi::Unicast)],
            }],
        });
    let _source_rx = connect_peer(&mut manager, SOURCE, 1, false, false);
    assert!(manager.selection_deferred((Afi::Ipv4, Safi::Unicast)));
    let budget = IngestBudget::new();
    manager.handle_update(metered(
        received(SOURCE, 1, host_routes(SOURCE, 0, INGEST_BUDGET_ROUTES)),
        &budget,
    ));
    while manager.process_next_route_chunk() {}
    assert!(manager.selection_deferred((Afi::Ipv4, Safi::Unicast)));
    assert_eq!(budget.unfinished(), 0);
}

/// Every path that discards a session's message returns its budget.
/// Red proof: a permit kept in a slot the discard does not clear (for
/// example one never cleared after dispatch) leaves the count above zero.
#[test]
fn every_drop_path_returns_the_budget() {
    let peer = peer_v4(SOURCE);
    let batch = || received(SOURCE, 1, host_routes(SOURCE, 0, 8));

    // The peer goes down with its batch queued: the purge drops it.
    let (_tx, mut manager) = test_manager();
    let _rx = connect_peer(&mut manager, SOURCE, 1, false, false);
    let budget = IngestBudget::new();
    manager.handle_update(metered(batch(), &budget));
    assert_eq!(budget.unfinished(), 8);
    manager.handle_update(RibUpdate::PeerDown {
        peer,
        session_id: 1,
    });
    assert!(manager.pending_route_batches.is_empty());
    assert_eq!(budget.unfinished(), 0, "peer-down purge");

    // The peer restarts gracefully with its batch queued.
    let (_tx, mut manager) = test_manager();
    let _rx = connect_peer(&mut manager, SOURCE, 1, false, false);
    let budget = IngestBudget::new();
    manager.handle_update(metered(batch(), &budget));
    manager.handle_update(restart(SOURCE, 1, 120, 360));
    while manager.process_next_route_chunk() {}
    assert_eq!(budget.unfinished(), 0, "graceful restart");

    // A message from a replaced session is discarded at dispatch.
    let (_tx, mut manager) = test_manager();
    let _old_rx = connect_peer(&mut manager, SOURCE, 1, false, false);
    let _new_rx = connect_peer(&mut manager, SOURCE, 2, false, false);
    let budget = IngestBudget::new();
    manager.handle_update(metered(batch(), &budget));
    assert!(
        manager.pending_route_batches.is_empty(),
        "stale: not queued"
    );
    assert_eq!(budget.unfinished(), 0, "replaced session");

    // A message from a session that never registered.
    let (_tx, mut manager) = test_manager();
    let budget = IngestBudget::new();
    manager.handle_update(metered(batch(), &budget));
    assert_eq!(budget.unfinished(), 0, "unregistered session");

    // Typed families are applied within their own turn.
    let (_tx, mut manager) = test_manager();
    let _rx = connect_peer(&mut manager, SOURCE, 1, false, false);
    for (family, update, routes) in typed_family_messages(peer) {
        let budget = IngestBudget::new();
        let update = metered(update, &budget);
        assert_eq!(budget.unfinished(), routes, "{family}");
        manager.handle_update(update);
        assert_eq!(budget.unfinished(), 0, "{family} applied in its turn");
    }

    // The RIB shuts down with one batch queued and one message unread.
    let (tx, mut manager) = test_manager();
    let _rx = connect_peer(&mut manager, SOURCE, 1, false, false);
    let budget = IngestBudget::new();
    manager.handle_update(metered(batch(), &budget));
    tx.try_send(metered(batch(), &budget)).unwrap();
    assert_eq!(budget.unfinished(), 16);
    drop(manager);
    assert_eq!(budget.unfinished(), 0, "shutdown and channel close");
}

/// One source's messages keep their order through the wrapper and the
/// queue: announce then withdraw leaves no route, withdraw then announce
/// leaves one.
#[tokio::test]
async fn metered_stream_is_applied_in_order() {
    let prefix = followed();
    let announce = || received(SOURCE, 1, vec![make_route(prefix, SOURCE)]);
    let withdraw = || {
        let mut update = received(SOURCE, 1, vec![]);
        if let RibUpdate::RoutesReceived { withdrawn, .. } = &mut update {
            withdrawn.push((Prefix::V4(prefix), 0));
        }
        update
    };
    for (stream, routes) in [
        (vec![announce(), withdraw()], 0),
        (vec![withdraw(), announce()], 1),
        (vec![announce(), withdraw(), announce()], 1),
    ] {
        let (tx, mut manager) = test_manager();
        let _rx = connect_peer(&mut manager, SOURCE, 1, false, false);
        let budget = IngestBudget::new();
        for update in stream {
            tx.try_send(metered(update, &budget)).unwrap();
        }
        let (reply, mut barrier) = oneshot::channel();
        tx.try_send(RibUpdate::QueryLocRibCount { reply }).unwrap();
        let mut actor = Box::pin(manager.run());
        let mut count = None;
        for _ in 0..100 {
            assert!(
                actor
                    .as_mut()
                    .poll(&mut Context::from_waker(Waker::noop()))
                    .is_pending()
            );
            if let Ok(reply) = barrier.try_recv() {
                count = Some(reply);
                break;
            }
        }
        assert_eq!(count, Some(routes));
        assert_eq!(budget.unfinished(), 0);
    }
}

/// The stale-route sweep is bounded by admitted input only. A restarted peer
/// whose ingest budget is spent has later input unread in its socket; the
/// graceful-restart stale timer does not wait for it. Input admitted before
/// the deadline is applied first, and a route the peer re-advertised only in
/// the unread input is swept, then announced again when that input arrives.
///
/// This pins the default. Deferring a peer's sweep while its budget is spent
/// would leave the first trace below empty.
#[tokio::test(start_paused = true)]
async fn stale_sweep_does_not_wait_for_input_behind_a_spent_budget() {
    let admitted = Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, 0), 24);
    let (tx, rx) = mpsc::channel(16);
    let metrics = BgpMetrics::new();
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, metrics.clone());
    let _source_rx = connect_peer(&mut manager, SOURCE, 1, false, false);
    let mut observer_rx = connect_peer(&mut manager, OBSERVER, 1, false, false);
    manager.handle_update(received(
        SOURCE,
        1,
        vec![make_route(admitted, SOURCE), make_route(followed(), SOURCE)],
    ));
    while manager.process_next_route_chunk() {}
    // The peer restarts and returns at once; its stale routes are kept for
    // the 3 s stale timer.
    manager.handle_update(restart(SOURCE, 1, 2, 3));
    let _restarted_rx = connect_peer(&mut manager, SOURCE, 2, true, false);
    while observer_rx.try_recv().is_ok() {}

    // The restarted session spends its whole budget on one message, which
    // re-advertises `admitted`. Its next UPDATE re-advertises `followed`,
    // but the session no longer reads its socket.
    let budget = IngestBudget::new();
    let mut burst = host_routes(SOURCE, 0, INGEST_BUDGET_ROUTES);
    burst.push(make_route(admitted, SOURCE));
    tx.try_send(metered(received(SOURCE, 2, burst), &budget))
        .unwrap();
    assert!(budget.gate_closed(false), "the session stops reading");
    // Keep the budget spent across the sweep, as a second message still on
    // its way to the RIB would.
    let in_flight = budget.charge(INGEST_BUDGET_ROUTES);

    tokio::time::advance(Duration::from_secs(4)).await;
    let (reply, mut barrier) = oneshot::channel();
    tx.try_send(RibUpdate::QueryLocRibCount { reply }).unwrap();
    let mut actor = Box::pin(manager.run());
    run_until(&mut actor, &mut barrier);
    // The expiry follows the admitted backlog; nothing else is queued.
    let expired = || {
        counter_metric_value(
            &metrics,
            "bgp_gr_timer_expired_total",
            &[("peer", SOURCE.to_string().as_str())],
        )
    };
    for _ in 0..100 {
        if expired() >= 1.0 {
            break;
        }
        assert!(
            actor
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
    }

    assert!(budget.gate_closed(true), "the budget is still spent");
    assert!((expired() - 1.0).abs() < f64::EPSILON, "the sweep ran");
    let updates: Vec<_> = std::iter::from_fn(|| observer_rx.try_recv().ok()).collect();
    assert_eq!(
        trace_of(&updates, followed()),
        vec!["withdraw"],
        "the route re-advertised only in unread input is swept"
    );
    assert_eq!(
        trace_of(&updates, admitted),
        Vec::<&str>::new(),
        "input admitted before the deadline is applied before the sweep"
    );

    // The budget returns, the session reads on, and the route comes back.
    drop(in_flight);
    assert!(!budget.gate_closed(true));
    tx.try_send(metered(
        received(SOURCE, 2, vec![make_route(followed(), SOURCE)]),
        &budget,
    ))
    .unwrap();
    let (reply, mut barrier) = oneshot::channel();
    tx.try_send(RibUpdate::QueryLocRibCount { reply }).unwrap();
    run_until(&mut actor, &mut barrier);
    assert_eq!(followed_trace(&mut observer_rx), vec!["announce"]);
}
