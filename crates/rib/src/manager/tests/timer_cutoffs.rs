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
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, metrics.clone())
        .with_selection_deferral(crate::SelectionDeferralConfig {
            timeout: Duration::from_secs(10),
            waiters: vec![crate::SelectionDeferralWaiterConfig {
                peer: peer_v4(Ipv4Addr::new(10, 0, 0, 99)),
                families: vec![(Afi::Ipv4, Safi::Unicast)],
            }],
        });
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
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, metrics.clone())
        .with_selection_deferral(crate::SelectionDeferralConfig {
            timeout: Duration::from_secs(10),
            waiters: vec![crate::SelectionDeferralWaiterConfig {
                peer: peer_v4(Ipv4Addr::new(10, 0, 0, 99)),
                families: vec![(Afi::Ipv6, Safi::Unicast)],
            }],
        });
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
