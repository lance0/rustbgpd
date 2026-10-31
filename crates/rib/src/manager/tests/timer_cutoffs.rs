//! Retention and deferral timers stay bounded under sustained ingress: each
//! expiry waits only for the primary backlog queued when it first fell due
//! (the ADR-0137 admission cutoff), not for the queue to go empty.

use crate::PeerId;
use crate::test_support::peer_v4;
use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Waker};

use super::*;

const SOURCE: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);

fn source() -> PeerId {
    peer_v4(SOURCE)
}

fn one_route() -> RibUpdate {
    RibUpdate::RoutesReceived {
        session_id: 0,
        peer: source(),
        announced: vec![make_route(
            Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24),
            SOURCE,
        )],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
        validated_with: None,
    }
}

fn graceful_restart(llgr_stale_time: u32) -> RibUpdate {
    RibUpdate::PeerGracefulRestart {
        session_id: 0,
        peer: source(),
        restart_time: 2,
        stale_routes_time: 360,
        gr_families: vec![(Afi::Ipv4, Safi::Unicast)],
        peer_llgr_capable: llgr_stale_time > 0,
        peer_llgr_families: if llgr_stale_time > 0 {
            vec![rustbgpd_wire::LlgrFamily {
                afi: Afi::Ipv4,
                safi: Safi::Unicast,
                forwarding_preserved: false,
                stale_time: llgr_stale_time,
            }]
        } else {
            vec![]
        },
        llgr_stale_time,
    }
}

async fn barrier(tx: &mpsc::Sender<RibUpdate>) {
    let (reply, response) = oneshot::channel();
    tx.send(RibUpdate::QueryLocRibCount { reply })
        .await
        .unwrap();
    response.await.unwrap();
}

fn gr_timer_expirations(metrics: &BgpMetrics) -> f64 {
    counter_metric_value(
        metrics,
        "bgp_gr_timer_expired_total",
        &[("peer", "10.0.0.1")],
    )
}

fn retained_stale_routes(metrics: &BgpMetrics) -> f64 {
    gauge_metric_value(metrics, "bgp_gr_stale_routes", &[("peer", "10.0.0.1")])
}

fn refresh_in_progress(metrics: &BgpMetrics) -> f64 {
    gauge_metric_value(
        metrics,
        "bgp_route_refresh_in_progress",
        &[("peer", "10.0.0.1"), ("family", "ipv4_unicast")],
    )
}

fn selection_deferral_timeouts(metrics: &BgpMetrics) -> f64 {
    counter_metric_value(
        metrics,
        "bgp_selection_deferral_timeouts_total",
        &[("family", "ipv4_unicast")],
    )
}

/// Keep the primary queue refilled (each send waits for the slot the actor
/// frees), move the clock by `advance_by`, and report whether `fired`
/// becomes true within a bounded number of turns: far more than the 64-slot
/// backlog any cutoff admits.
async fn fires_under_sustained_ingress(
    tx: &mpsc::Sender<RibUpdate>,
    advance_by: Duration,
    fired: impl Fn() -> bool,
) -> bool {
    let stop = Arc::new(AtomicBool::new(false));
    let feeder = tokio::spawn({
        let tx = tx.clone();
        let stop = Arc::clone(&stop);
        async move {
            while !stop.load(Ordering::Relaxed) {
                let (reply, _ignored) = oneshot::channel();
                if tx
                    .send(RibUpdate::QueryLocRibCount { reply })
                    .await
                    .is_err()
                {
                    break;
                }
            }
        }
    });
    tokio::task::yield_now().await;
    tokio::time::advance(advance_by).await;
    let mut observed = false;
    for turn in 0..20_000 {
        if turn % 64 == 0 && fired() {
            observed = true;
            break;
        }
        tokio::task::yield_now().await;
    }
    stop.store(true, Ordering::Relaxed);
    feeder.await.unwrap();
    observed
}

fn spawn(metrics: &BgpMetrics) -> (mpsc::Sender<RibUpdate>, tokio::task::JoinHandle<()>) {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, metrics.clone());
    (tx, tokio::spawn(manager.run()))
}

/// RFC 4724 restart timer: a peer that never returns has its stale routes
/// swept at the deadline, however busy the RIB is.
#[tokio::test(start_paused = true)]
async fn gr_stale_timer_fires_under_sustained_ingress() {
    let metrics = BgpMetrics::new();
    let (tx, handle) = spawn(&metrics);
    tx.send(one_route()).await.unwrap();
    tx.send(graceful_restart(0)).await.unwrap();
    barrier(&tx).await;
    assert!(gr_timer_expirations(&metrics) < 0.5);

    assert!(
        fires_under_sustained_ingress(&tx, Duration::from_secs(3), || {
            gr_timer_expirations(&metrics) > 0.5
        })
        .await,
        "the GR stale timer was postponed by sustained ingress"
    );

    drop(tx);
    handle.await.unwrap();
}

/// RFC 9494 Long-Lived Stale Time: LLGR-stale routes are swept at their
/// deadline under sustained ingress.
#[tokio::test(start_paused = true)]
async fn llgr_stale_timer_fires_under_sustained_ingress() {
    let metrics = BgpMetrics::new();
    let (tx, handle) = spawn(&metrics);
    tx.send(one_route()).await.unwrap();
    tx.send(graceful_restart(10)).await.unwrap();
    barrier(&tx).await;
    // The GR timer (no traffic) promotes the route to LLGR-stale.
    tokio::time::advance(Duration::from_secs(3)).await;
    barrier(&tx).await;
    assert!((retained_stale_routes(&metrics) - 1.0).abs() < f64::EPSILON);

    assert!(
        fires_under_sustained_ingress(&tx, Duration::from_secs(11), || {
            retained_stale_routes(&metrics) < 0.5
        })
        .await,
        "the LLGR stale timer was postponed by sustained ingress"
    );

    drop(tx);
    handle.await.unwrap();
}

/// RFC 7313 refresh window: a peer that sends `BoRR` but never `EoRR` has
/// the window closed at its cap under sustained ingress.
#[tokio::test(start_paused = true)]
async fn refresh_window_timer_fires_under_sustained_ingress() {
    let metrics = BgpMetrics::new();
    let (tx, handle) = spawn(&metrics);
    tx.send(one_route()).await.unwrap();
    tx.send(RibUpdate::BeginRouteRefresh {
        session_id: 0,
        peer: source(),
        afi: Afi::Ipv4,
        safi: Safi::Unicast,
    })
    .await
    .unwrap();
    barrier(&tx).await;
    assert!((refresh_in_progress(&metrics) - 1.0).abs() < f64::EPSILON);

    assert!(
        fires_under_sustained_ingress(
            &tx,
            crate::ERR_REFRESH_TIMEOUT + Duration::from_secs(1),
            || refresh_in_progress(&metrics) < 0.5,
        )
        .await,
        "the refresh window timer was postponed by sustained ingress"
    );

    drop(tx);
    handle.await.unwrap();
}

/// RFC 4724 §4.1 `Selection_Deferral_Timer`: a waiter that never sends
/// End-of-RIB cannot hold selection past the timer under sustained ingress.
#[tokio::test(start_paused = true)]
async fn selection_deferral_timer_fires_under_sustained_ingress() {
    let metrics = BgpMetrics::new();
    let (tx, rx) = mpsc::channel(64);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, metrics.clone())
        .with_selection_deferral(crate::SelectionDeferralConfig {
            timeout: Duration::from_secs(10),
            waiters: vec![crate::SelectionDeferralWaiterConfig {
                peer: peer_v4(Ipv4Addr::new(10, 0, 0, 99)),
                families: vec![(Afi::Ipv4, Safi::Unicast)],
            }],
        });
    super::arm_selection_waiter(
        &mut manager,
        peer_v4(Ipv4Addr::new(10, 0, 0, 99)),
        &[(Afi::Ipv4, Safi::Unicast)],
    );
    let handle = tokio::spawn(manager.run());
    barrier(&tx).await;
    assert!(selection_deferral_timeouts(&metrics) < 0.5);

    assert!(
        fires_under_sustained_ingress(&tx, Duration::from_secs(11), || {
            selection_deferral_timeouts(&metrics) > 0.5
        })
        .await,
        "the selection-deferral timer was postponed by sustained ingress"
    );

    drop(tx);
    handle.await.unwrap();
}

/// Several timers due at once share the same admissions: each one is
/// charged for every update admitted after it fell due, so all of them fire
/// within the backlog bound, in the run loop's fixed order.
#[tokio::test(start_paused = true)]
async fn coincident_timers_all_fire_under_sustained_ingress() {
    let metrics = BgpMetrics::new();
    let (tx, rx) = mpsc::channel(64);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, metrics.clone())
        .with_selection_deferral(crate::SelectionDeferralConfig {
            timeout: Duration::from_secs(10),
            waiters: vec![crate::SelectionDeferralWaiterConfig {
                peer: peer_v4(Ipv4Addr::new(10, 0, 0, 99)),
                families: vec![(Afi::Ipv6, Safi::Unicast)],
            }],
        });
    super::arm_selection_waiter(
        &mut manager,
        peer_v4(Ipv4Addr::new(10, 0, 0, 99)),
        &[(Afi::Ipv6, Safi::Unicast)],
    );
    let handle = tokio::spawn(manager.run());
    tx.send(one_route()).await.unwrap();
    tx.send(RibUpdate::BeginRouteRefresh {
        session_id: 0,
        peer: source(),
        afi: Afi::Ipv4,
        safi: Safi::Unicast,
    })
    .await
    .unwrap();
    barrier(&tx).await;
    let other = Ipv4Addr::new(10, 0, 0, 2);
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: peer_v4(other),
        announced: vec![make_route(
            Ipv4Prefix::new(Ipv4Addr::new(192, 168, 2, 0), 24),
            other,
        )],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
        validated_with: None,
    })
    .await
    .unwrap();
    tx.send(RibUpdate::PeerGracefulRestart {
        session_id: 0,
        peer: peer_v4(other),
        restart_time: 2,
        stale_routes_time: 360,
        gr_families: vec![(Afi::Ipv4, Safi::Unicast)],
        peer_llgr_capable: false,
        peer_llgr_families: vec![],
        llgr_stale_time: 0,
    })
    .await
    .unwrap();
    barrier(&tx).await;

    let gr_expired = || {
        counter_metric_value(
            &metrics,
            "bgp_gr_timer_expired_total",
            &[("peer", "10.0.0.2")],
        ) > 0.5
    };
    let deferral_expired = || {
        counter_metric_value(
            &metrics,
            "bgp_selection_deferral_timeouts_total",
            &[("family", "ipv6_unicast")],
        ) > 0.5
    };
    // GR (2 s), selection deferral (10 s) and the refresh window (5 min)
    // all fall due in the same actor turn.
    assert!(
        fires_under_sustained_ingress(
            &tx,
            crate::ERR_REFRESH_TIMEOUT + Duration::from_secs(1),
            || gr_expired() && deferral_expired() && refresh_in_progress(&metrics) < 0.5,
        )
        .await,
        "coincident timers were postponed by sustained ingress (GR {}, deferral {}, refresh open {})",
        gr_expired(),
        deferral_expired(),
        refresh_in_progress(&metrics),
    );

    drop(tx);
    handle.await.unwrap();
}

/// A timer whose cutoff is exhausted fires before any other due timer
/// admits another update. Selection deferral falls due with a small backlog
/// and, while it is still draining, the GR timer (an earlier branch) falls
/// due with a much larger one. The GR branch may admit only until the
/// deferral's cutoff runs out; the deferral then expires before any update
/// queued after its deadline is processed.
#[tokio::test(start_paused = true)]
async fn exhausted_timer_fires_before_an_earlier_branch_keeps_draining() {
    const BEFORE_DEFERRAL: usize = 4;
    const AFTER_DEFERRAL: usize = 64;
    let metrics = BgpMetrics::new();
    let (tx, rx) = mpsc::channel(128);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, metrics.clone())
        .with_selection_deferral(crate::SelectionDeferralConfig {
            timeout: Duration::from_secs(10),
            waiters: vec![crate::SelectionDeferralWaiterConfig {
                peer: peer_v4(Ipv4Addr::new(10, 0, 0, 99)),
                families: vec![(Afi::Ipv6, Safi::Unicast)],
            }],
        });
    super::arm_selection_waiter(
        &mut manager,
        peer_v4(Ipv4Addr::new(10, 0, 0, 99)),
        &[(Afi::Ipv6, Safi::Unicast)],
    );
    manager.handle_update(one_route());
    manager.handle_update(RibUpdate::PeerGracefulRestart {
        session_id: 0,
        peer: source(),
        restart_time: 11,
        stale_routes_time: 360,
        gr_families: vec![(Afi::Ipv4, Safi::Unicast)],
        peer_llgr_capable: false,
        peer_llgr_families: vec![],
        llgr_stale_time: 0,
    });
    let query = |tx: &mpsc::Sender<RibUpdate>| {
        let (reply, response) = oneshot::channel();
        tx.try_send(RibUpdate::QueryLocRibCount { reply }).unwrap();
        response
    };
    let deferral_expired = || {
        counter_metric_value(
            &metrics,
            "bgp_selection_deferral_timeouts_total",
            &[("family", "ipv6_unicast")],
        ) > 0.5
    };
    let mut actor = Box::pin(manager.run());
    let mut poll = || {
        assert!(
            actor
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
    };

    let _before: Vec<_> = (0..BEFORE_DEFERRAL).map(|_| query(&tx)).collect();
    tokio::time::advance(Duration::from_secs(10)).await;
    // One actor turn: the deferral is seen due with a 4-update cutoff and
    // admits the first of them.
    poll();
    assert!(!deferral_expired());

    let mut after: Vec<_> = (0..AFTER_DEFERRAL).map(|_| query(&tx)).collect();
    tokio::time::advance(Duration::from_secs(1)).await;
    // Each poll admits at most one update before the drain yields. The poll
    // that fires the deferral may go on to admit one post-deadline update
    // for the GR branch, so count what had run before that poll.
    let mut answered_after = 0;
    let mut answered_at_expiry = None;
    for _ in 0..4 * (BEFORE_DEFERRAL + AFTER_DEFERRAL) {
        let answered_before_poll = answered_after;
        poll();
        answered_after += after
            .iter_mut()
            .flat_map(oneshot::Receiver::try_recv)
            .count();
        if deferral_expired() {
            answered_at_expiry = Some(answered_before_poll);
            break;
        }
    }
    let answered = answered_at_expiry.expect("the selection deferral never expired");
    assert_eq!(
        answered, 0,
        "{answered} updates queued after the deferral deadline ran before it expired"
    );
}

/// Idle time between runs is not poll time. A lone update after the actor
/// suspended through a gap longer than the budget must not yield: a yield
/// there lets a caller act before the run loop's own due-timer check, so a
/// timer that fell due during the gap would trail a message that arrived
/// after it.
#[test]
fn primary_run_budget_does_not_charge_a_suspended_gap_to_the_next_run() {
    let budget = Duration::from_millis(25);
    let t0 = std::time::Instant::now();
    let suspended = std::sync::atomic::AtomicBool::new(true);
    let mut run = PrimaryRunBudget::default();

    let started = run.start(t0, &suspended);
    assert!(!run.should_yield(started, t0 + Duration::from_millis(1), budget));

    // The actor suspends for 40 ms, then one more update arrives.
    suspended.store(true, Ordering::Relaxed);
    let next = t0 + Duration::from_millis(40);
    let started = run.start(next, &suspended);
    assert_eq!(started, next, "the suspension ended the previous run");
    assert!(
        !suspended.load(Ordering::Relaxed),
        "the suspension is consumed"
    );
    assert!(!run.should_yield(started, next + Duration::from_millis(1), budget));
}

/// A backlog that refills before the receive is polled never suspends the
/// actor, even when it was sampled empty after the previous update. Such
/// updates stay one run, so four 10 ms updates still yield at 25 ms.
#[test]
fn primary_run_budget_bounds_a_backlog_refilled_before_each_receive() {
    let budget = Duration::from_millis(25);
    let t0 = std::time::Instant::now();
    let suspended = std::sync::atomic::AtomicBool::new(true);
    let mut run = PrimaryRunBudget::default();

    let started = run.start(t0, &suspended);
    let mut yielded_at = None;
    for update in 1..=4u32 {
        let done = t0 + Duration::from_millis(10 * u64::from(update));
        if run.should_yield(started, done, budget) {
            yielded_at = Some(update);
            break;
        }
        // Each refill is ready on the first poll: the actor never suspends.
        assert_eq!(
            run.start(done, &suspended),
            t0,
            "update {update} continues the run"
        );
    }
    assert_eq!(
        yielded_at,
        Some(3),
        "the third 10 ms update spends the budget"
    );
    let after = t0 + Duration::from_millis(31);
    assert_eq!(run.start(after, &suspended), after, "a yield ends the run");
}

/// The suspension is observed on the whole actor future, not one branch.
/// After an idle gap, a non-primary branch can win the wakeup and the next
/// primary update can then be ready at once; that update must still start a
/// new run, because the actor did suspend in between.
#[tokio::test]
async fn primary_run_budget_ends_on_a_suspension_another_branch_woke() {
    let metrics = BgpMetrics::new();
    let budget = Duration::from_millis(25);
    let t0 = std::time::Instant::now();
    let suspended = Arc::new(AtomicBool::new(true));
    let mut run = PrimaryRunBudget::default();
    let started = run.start(t0, &suspended);
    assert!(!run.should_yield(started, t0 + Duration::from_millis(1), budget));

    // One actor turn: the wait suspends, another branch (here a query
    // channel) wins, and its handler finishes without touching the run.
    let (query_tx, mut query_rx) = mpsc::channel::<()>(1);
    let mut actor = Box::pin(super::super::slice_timing::TimedActor::new(
        async move { query_rx.recv().await },
        metrics.rib_actor_slice_recorder(),
        Arc::clone(&suspended),
    ));
    let mut cx = Context::from_waker(Waker::noop());
    assert!(
        actor.as_mut().poll(&mut cx).is_pending(),
        "the wait suspends"
    );
    query_tx.try_send(()).unwrap();
    assert!(
        actor.as_mut().poll(&mut cx).is_ready(),
        "the query branch wins"
    );

    // The next primary update is ready on its first poll.
    let next = t0 + Duration::from_millis(40);
    assert_eq!(
        run.start(next, &suspended),
        next,
        "the suspension another branch woke ended the previous run"
    );
    assert!(!run.should_yield(next, next + Duration::from_millis(1), budget));

    // A turn that never suspends records nothing and continues the run.
    super::super::slice_timing::TimedActor::new(
        async {},
        metrics.rib_actor_slice_recorder(),
        Arc::clone(&suspended),
    )
    .await;
    let later = next + Duration::from_millis(2);
    assert_eq!(
        run.start(later, &suspended),
        next,
        "a ready turn continues the run"
    );
}

/// Registers a session; `restarting` sets the OPEN's Restart State bit and
/// `orf` negotiates Address Prefix ORF receive for IPv4 unicast.
fn connect_peer(
    manager: &mut RibManager,
    address: Ipv4Addr,
    session_id: u64,
    restarting: bool,
    orf: bool,
) -> mpsc::Receiver<OutboundRouteUpdate> {
    let peer = peer_v4(address);
    manager.handle_update(RibUpdate::SetPeerGracefulRestartContext {
        peer,
        session_id,
        peer_restart_state: restarting,
        peer_gr_helper: true,
        peer_gr_families: ipv4_sendable(),
        peer_enhanced_refresh: true,
        peer_llgr_families: Vec::new(),
        local_llgr_stale_time: 0,
    });
    let (tx, rx) = mpsc::channel(16384);
    let mut up = super::lifecycle::test_peer_up(peer, session_id, tx);
    if orf
        && let RibUpdate::PeerUp {
            negotiated_orf_recv,
            ..
        } = &mut up
    {
        *negotiated_orf_recv = ipv4_sendable();
    }
    manager.handle_update(up);
    rx
}

fn received(address: Ipv4Addr, session_id: u64, announced: Vec<Route>) -> RibUpdate {
    RibUpdate::RoutesReceived {
        peer: peer_v4(address),
        session_id,
        announced,
        withdrawn: Vec::new(),
        flowspec_announced: Vec::new(),
        flowspec_withdrawn: Vec::new(),
        evpn_announced: Vec::new(),
        evpn_withdrawn: Vec::new(),
        validated_with: None,
    }
}

fn restart(
    address: Ipv4Addr,
    session_id: u64,
    restart_time: u16,
    stale_routes_time: u64,
) -> RibUpdate {
    RibUpdate::PeerGracefulRestart {
        peer: peer_v4(address),
        session_id,
        restart_time,
        stale_routes_time,
        gr_families: ipv4_sendable(),
        peer_llgr_capable: false,
        peer_llgr_families: Vec::new(),
        llgr_stale_time: 0,
    }
}

/// The prefix whose wire history the overtake tests follow.
fn followed() -> Ipv4Prefix {
    Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 0), 24)
}

/// One UPDATE's worth of host routes from `address` (3072 /32 NLRIs fit an
/// extended message), so draining it takes several actor turns.
fn long_batch(address: Ipv4Addr) -> RibUpdate {
    received(
        address,
        1,
        (0..3 * ROUTES_RECEIVED_CHUNK_SIZE)
            .map(|i| {
                let host = Ipv4Addr::from(0xc000_1000 + u32::try_from(i).unwrap());
                make_route(Ipv4Prefix::new(host, 32), address)
            })
            .collect(),
    )
}

/// Polls the actor without letting it sleep until it has answered the
/// barrier queued behind the updates under test.
fn run_until(
    actor: &mut std::pin::Pin<Box<impl Future<Output = ()>>>,
    barrier: &mut oneshot::Receiver<usize>,
) {
    for _ in 0..100 {
        assert!(
            actor
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
        if barrier.try_recv().is_ok() {
            return;
        }
    }
    panic!("the actor never reached the barrier");
}

/// `withdraw` / `announce` for every update on `rx` touching the followed
/// prefix, and `eor` for each IPv4 unicast End-of-RIB.
fn followed_trace(rx: &mut mpsc::Receiver<OutboundRouteUpdate>) -> Vec<&'static str> {
    let prefix = Prefix::V4(followed());
    let mut trace = Vec::new();
    while let Ok(update) = rx.try_recv() {
        if update.withdraw.iter().any(|(p, _)| *p == prefix) {
            trace.push("withdraw");
        }
        if update.announce.iter().any(|route| route.prefix == prefix) {
            trace.push("announce");
        }
        if update.end_of_rib.contains(&(Afi::Ipv4, Safi::Unicast)) {
            trace.push("eor");
        }
    }
    trace
}

/// Peer A's GR deadline falls due with a long batch queued, and its drain
/// runs past peer B's later deadline. B's UPDATE and End-of-RIB, queued
/// after A's cutoff but before B's own deadline, must be admitted before
/// B's expiry: A's turn sweeps only A. Red proof: sweeping every deadline
/// up to the current time at A's turn withdraws B's re-advertised route
/// and announces it again.
#[tokio::test(start_paused = true)]
async fn later_gr_deadline_waits_for_its_own_backlog() {
    let a = Ipv4Addr::new(10, 0, 0, 1);
    let b = Ipv4Addr::new(10, 0, 0, 2);
    let c = Ipv4Addr::new(10, 0, 0, 3);
    let observer = Ipv4Addr::new(10, 0, 0, 4);
    let (tx, rx) = mpsc::channel(16);
    let metrics = BgpMetrics::new();
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, metrics.clone());
    let _a_rx = connect_peer(&mut manager, a, 1, false, false);
    let _b_rx = connect_peer(&mut manager, b, 1, false, false);
    let _c_rx = connect_peer(&mut manager, c, 1, false, false);
    let mut out_rx = connect_peer(&mut manager, observer, 1, false, false);
    let a_prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, 0), 24);
    manager.handle_update(received(a, 1, vec![make_route(a_prefix, a)]));
    manager.handle_update(received(b, 1, vec![make_route(followed(), b)]));
    while manager.process_next_route_chunk() {}
    // A never returns: its routes go at the 2 s restart time. B returns
    // at once, and its stale routes are kept for the 3 s stale timer.
    manager.handle_update(restart(a, 1, 2, 3));
    manager.handle_update(restart(b, 1, 2, 3));
    let _new_b_rx = connect_peer(&mut manager, b, 2, true, false);
    let start = tokio::time::Instant::now();
    assert_eq!(
        manager.gr_stale_deadlines[&peer_v4(a)],
        start + Duration::from_secs(2)
    );
    assert_eq!(
        manager.gr_stale_deadlines[&peer_v4(b)],
        start + Duration::from_secs(3)
    );
    while out_rx.try_recv().is_ok() {}

    tx.try_send(long_batch(c)).unwrap();
    tokio::time::advance(Duration::from_secs(2)).await;
    let mut actor = Box::pin(manager.run());
    assert!(
        actor
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending(),
        "A's cutoff captures the long batch and its drain starts"
    );
    // After A's cutoff, one second before B's own deadline.
    tx.try_send(received(b, 2, vec![make_route(followed(), b)]))
        .unwrap();
    tx.try_send(RibUpdate::EndOfRib {
        peer: peer_v4(b),
        session_id: 2,
        afi: Afi::Ipv4,
        safi: Safi::Unicast,
    })
    .unwrap();
    let (reply, mut barrier) = oneshot::channel();
    tx.try_send(RibUpdate::QueryLocRibCount { reply }).unwrap();
    tokio::time::advance(Duration::from_secs(2)).await;
    run_until(&mut actor, &mut barrier);

    assert_eq!(
        followed_trace(&mut out_rx),
        Vec::<&str>::new(),
        "B's re-advertised route never leaves the observer"
    );
    let label = |address: Ipv4Addr| address.to_string();
    let expired = |address| {
        counter_metric_value(
            &metrics,
            "bgp_gr_timer_expired_total",
            &[("peer", label(address).as_str())],
        )
    };
    assert!(
        (expired(a) - 1.0).abs() < f64::EPSILON,
        "A's deadline fired"
    );
    assert!(
        expired(b) < 0.5,
        "B's End-of-RIB closed its window before its deadline"
    );
}

/// The earliest ORF End-of-RIB cap (peer A's) falls due with a long batch
/// queued, and A's session ends inside that drain, retiring A's cap. Peer
/// B's later cap, already past, must capture its own backlog, so B's
/// ROUTE-REFRESH queued before B's cap sends the table before the
/// End-of-RIB. Red proof: a cutoff that outlives its deadline hands B A's
/// exhausted count, and B's End-of-RIB goes out ahead of its table.
#[tokio::test(start_paused = true)]
async fn retired_earliest_orf_cap_does_not_lend_its_cutoff() {
    let a = Ipv4Addr::new(10, 0, 0, 11);
    let b = Ipv4Addr::new(10, 0, 0, 12);
    let c = Ipv4Addr::new(10, 0, 0, 13);
    let (tx, rx) = mpsc::channel(16);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let _a_rx = connect_peer(&mut manager, a, 1, false, false);
    let mut old_b_rx = connect_peer(&mut manager, b, 1, false, false);
    let _c_rx = connect_peer(&mut manager, c, 1, false, false);
    manager.handle_update(received(c, 1, vec![make_route(followed(), c)]));
    while manager.process_next_route_chunk() {}
    assert!(followed_trace(&mut old_b_rx).contains(&"announce"));
    // Clean GR ends: both peers keep our routes stale, so each new
    // ORF-gated session holds its End-of-RIB behind the gated table.
    manager.handle_update(restart(a, 1, 120, 360));
    let _new_a_rx = connect_peer(&mut manager, a, 2, false, true);
    tokio::time::advance(Duration::from_secs(1)).await;
    manager.handle_update(restart(b, 1, 120, 360));
    let mut new_b_rx = connect_peer(&mut manager, b, 2, false, true);
    let now = tokio::time::Instant::now();
    assert_eq!(
        manager.orf_eor_hold[&peer_v4(a)],
        now + Duration::from_secs(59)
    );
    assert_eq!(
        manager.orf_eor_hold[&peer_v4(b)],
        now + Duration::from_secs(60)
    );
    assert_eq!(followed_trace(&mut new_b_rx), Vec::<&str>::new());

    tx.try_send(long_batch(c)).unwrap();
    tx.try_send(RibUpdate::PeerDown {
        peer: peer_v4(a),
        session_id: 2,
    })
    .unwrap();
    tokio::time::advance(Duration::from_secs(59)).await;
    let mut actor = Box::pin(manager.run());
    assert!(
        actor
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending(),
        "A's cap captures the long batch and A's teardown"
    );
    // After A's cutoff, one second before B's own cap.
    tx.try_send(RibUpdate::RouteRefreshRequest {
        peer: peer_v4(b),
        session_id: 2,
        afi: Afi::Ipv4,
        safi: Safi::Unicast,
        queued: Arc::new(AtomicBool::new(true)),
    })
    .unwrap();
    let (reply, mut barrier) = oneshot::channel();
    tx.try_send(RibUpdate::QueryLocRibCount { reply }).unwrap();
    tokio::time::advance(Duration::from_secs(2)).await;
    run_until(&mut actor, &mut barrier);

    assert_eq!(
        followed_trace(&mut new_b_rx).first(),
        Some(&"announce"),
        "B's refresh delivers its table before the End-of-RIB"
    );
}

/// Peer A's RFC 7313 refresh window times out with a long batch queued, and
/// the drain runs past peer B's later window. B's re-advertisement and
/// End-of-Route-Refresh, queued before B's own deadline, must close B's
/// window normally. Red proof: expiring every window up to the current time
/// at A's turn sweeps B's refresh-stale route and announces it again.
#[tokio::test(start_paused = true)]
async fn later_refresh_window_waits_for_its_own_backlog() {
    let a = Ipv4Addr::new(10, 0, 0, 21);
    let b = Ipv4Addr::new(10, 0, 0, 22);
    let c = Ipv4Addr::new(10, 0, 0, 23);
    let observer = Ipv4Addr::new(10, 0, 0, 24);
    let (tx, rx) = mpsc::channel(16);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let _a_rx = connect_peer(&mut manager, a, 1, false, false);
    let _b_rx = connect_peer(&mut manager, b, 1, false, false);
    let _c_rx = connect_peer(&mut manager, c, 1, false, false);
    let mut out_rx = connect_peer(&mut manager, observer, 1, false, false);
    manager.handle_update(received(b, 1, vec![make_route(followed(), b)]));
    while manager.process_next_route_chunk() {}
    let begin = |address| RibUpdate::BeginRouteRefresh {
        peer: peer_v4(address),
        session_id: 1,
        afi: Afi::Ipv4,
        safi: Safi::Unicast,
    };
    manager.handle_update(begin(a));
    tokio::time::advance(Duration::from_secs(1)).await;
    manager.handle_update(begin(b));
    while out_rx.try_recv().is_ok() {}

    tx.try_send(long_batch(c)).unwrap();
    tokio::time::advance(crate::ERR_REFRESH_TIMEOUT.saturating_sub(Duration::from_secs(1))).await;
    let mut actor = Box::pin(manager.run());
    assert!(
        actor
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending(),
        "A's window captures the long batch and its drain starts"
    );
    // After A's cutoff, one second before B's own deadline.
    tx.try_send(received(b, 1, vec![make_route(followed(), b)]))
        .unwrap();
    tx.try_send(RibUpdate::EndRouteRefresh {
        peer: peer_v4(b),
        session_id: 1,
        afi: Afi::Ipv4,
        safi: Safi::Unicast,
    })
    .unwrap();
    let (reply, mut barrier) = oneshot::channel();
    tx.try_send(RibUpdate::QueryLocRibCount { reply }).unwrap();
    tokio::time::advance(Duration::from_secs(2)).await;
    run_until(&mut actor, &mut barrier);

    assert_eq!(
        followed_trace(&mut out_rx),
        Vec::<&str>::new(),
        "B's refreshed route never leaves the observer"
    );
}

/// Registers a session that negotiated LLGR for IPv4 unicast (RFC 9494), so
/// it is sent LLGR-stale routes and keeps its own LLGR-stale routes across
/// a reconnect.
fn connect_llgr_peer(
    manager: &mut RibManager,
    address: Ipv4Addr,
    session_id: u64,
) -> mpsc::Receiver<OutboundRouteUpdate> {
    let peer = peer_v4(address);
    manager.handle_update(RibUpdate::SetPeerGracefulRestartContext {
        peer,
        session_id,
        peer_restart_state: false,
        peer_gr_helper: true,
        peer_gr_families: Vec::new(),
        peer_enhanced_refresh: true,
        peer_llgr_families: vec![rustbgpd_wire::LlgrFamily {
            afi: Afi::Ipv4,
            safi: Safi::Unicast,
            forwarding_preserved: false,
            stale_time: 10,
        }],
        local_llgr_stale_time: 10,
    });
    let (tx, rx) = mpsc::channel(16384);
    let mut up = super::lifecycle::test_peer_up(peer, session_id, tx);
    if let RibUpdate::PeerUp {
        negotiated_llgr_families,
        ..
    } = &mut up
    {
        *negotiated_llgr_families = ipv4_sendable();
    }
    manager.handle_update(up);
    rx
}

/// An LLGR-only session end: the family enters LLGR at once, with a 10 s
/// Long-Lived Stale Time.
fn llgr_end(address: Ipv4Addr) -> RibUpdate {
    RibUpdate::PeerGracefulRestart {
        peer: peer_v4(address),
        session_id: 1,
        restart_time: 0,
        stale_routes_time: 360,
        gr_families: Vec::new(),
        peer_llgr_capable: true,
        peer_llgr_families: vec![rustbgpd_wire::LlgrFamily {
            afi: Afi::Ipv4,
            safi: Safi::Unicast,
            forwarding_preserved: false,
            stale_time: 10,
        }],
        llgr_stale_time: 10,
    }
}

/// Peer A's LLGR stale deadline falls due with a long batch queued, and the
/// drain runs past peer B's later deadline. B has re-established, and its
/// UPDATE and End-of-RIB, queued before B's own deadline, must replace its
/// LLGR-stale route before B's expiry. Red proof: sweeping every LLGR
/// deadline up to the current time at A's turn withdraws B's route from an
/// LLGR-capable observer and announces it again.
#[tokio::test(start_paused = true)]
async fn later_llgr_deadline_waits_for_its_own_backlog() {
    let a = Ipv4Addr::new(10, 0, 0, 31);
    let b = Ipv4Addr::new(10, 0, 0, 32);
    let c = Ipv4Addr::new(10, 0, 0, 33);
    let observer = Ipv4Addr::new(10, 0, 0, 34);
    let (tx, rx) = mpsc::channel(16);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let _a_rx = connect_llgr_peer(&mut manager, a, 1);
    let _b_rx = connect_llgr_peer(&mut manager, b, 1);
    let _c_rx = connect_peer(&mut manager, c, 1, false, false);
    let mut out_rx = connect_llgr_peer(&mut manager, observer, 1);
    let a_prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, 0), 24);
    manager.handle_update(received(a, 1, vec![make_route(a_prefix, a)]));
    manager.handle_update(received(b, 1, vec![make_route(followed(), b)]));
    while manager.process_next_route_chunk() {}
    manager.handle_update(llgr_end(a));
    tokio::time::advance(Duration::from_secs(1)).await;
    manager.handle_update(llgr_end(b));
    let _new_b_rx = connect_llgr_peer(&mut manager, b, 2);
    let now = tokio::time::Instant::now();
    let deadline =
        |address| manager.llgr_stale_deadlines[&(peer_v4(address), Afi::Ipv4, Safi::Unicast)];
    assert_eq!(deadline(a), now + Duration::from_secs(9));
    assert_eq!(deadline(b), now + Duration::from_secs(10));
    while out_rx.try_recv().is_ok() {}

    tx.try_send(long_batch(c)).unwrap();
    tokio::time::advance(Duration::from_secs(9)).await;
    let mut actor = Box::pin(manager.run());
    assert!(
        actor
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending(),
        "A's deadline captures the long batch and its drain starts"
    );
    // After A's cutoff, one second before B's own deadline.
    tx.try_send(received(b, 2, vec![make_route(followed(), b)]))
        .unwrap();
    tx.try_send(RibUpdate::EndOfRib {
        peer: peer_v4(b),
        session_id: 2,
        afi: Afi::Ipv4,
        safi: Safi::Unicast,
    })
    .unwrap();
    let (reply, mut barrier) = oneshot::channel();
    tx.try_send(RibUpdate::QueryLocRibCount { reply }).unwrap();
    tokio::time::advance(Duration::from_secs(2)).await;
    run_until(&mut actor, &mut barrier);

    let trace = followed_trace(&mut out_rx);
    assert!(
        !trace.contains(&"withdraw"),
        "B's fresh route replaces its LLGR-stale one in place: {trace:?}"
    );
}
