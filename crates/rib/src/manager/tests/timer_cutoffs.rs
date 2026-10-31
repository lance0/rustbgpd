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
    trace_of(
        &std::iter::from_fn(|| rx.try_recv().ok()).collect::<Vec<_>>(),
        followed(),
    )
}

/// [`followed_trace`] over already drained `updates`, for `prefix`.
fn trace_of(updates: &[OutboundRouteUpdate], prefix: Ipv4Prefix) -> Vec<&'static str> {
    let prefix = Prefix::V4(prefix);
    let mut trace = Vec::new();
    for update in updates {
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
/// B's cap, later than that capture and past by now, must capture its own
/// backlog, so B's ROUTE-REFRESH queued before B's cap sends the table
/// before the End-of-RIB. Red proof: a count-only cutoff that outlives A's
/// cap hands B A's exhausted count, and B's End-of-RIB goes out ahead of its
/// table.
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
        followed_trace(&mut new_b_rx),
        vec!["announce", "eor"],
        "B's refresh delivers its table, then its End-of-RIB"
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

    let updates: Vec<_> = std::iter::from_fn(|| out_rx.try_recv().ok()).collect();
    assert_eq!(
        trace_of(&updates, followed()),
        Vec::<&str>::new(),
        "B's refreshed route never leaves the observer"
    );
    assert_eq!(
        trace_of(&updates, a_prefix),
        vec!["withdraw"],
        "A's window timed out and swept the route it never refreshed"
    );
    let in_progress = |address: Ipv4Addr| {
        gauge_metric_value(
            &metrics,
            "bgp_route_refresh_in_progress",
            &[
                ("peer", address.to_string().as_str()),
                ("family", "ipv4_unicast"),
            ],
        )
    };
    assert!(in_progress(a) < 0.5 && in_progress(b) < 0.5);
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

    let updates: Vec<_> = std::iter::from_fn(|| out_rx.try_recv().ok()).collect();
    let trace = trace_of(&updates, followed());
    assert!(
        !trace.contains(&"withdraw"),
        "B's fresh route replaces its LLGR-stale one in place: {trace:?}"
    );
    assert_eq!(
        trace_of(&updates, a_prefix),
        vec!["withdraw"],
        "A's LLGR deadline fired and swept its stale route"
    );
}

/// An advertise-if-absent definition over one exact condition prefix with a
/// 5 s settle time.
fn absent_if(name: &str, condition: Ipv4Prefix) -> crate::ConditionalAdvertisement {
    crate::ConditionalAdvertisement {
        name: Arc::from(name),
        advertise_policy: rustbgpd_policy::PolicyChain::default(),
        advertise_if: crate::ConditionalAdvertiseIf::Absent,
        condition_prefixes: vec![rustbgpd_policy::sets::PrefixSetEntry::exact(Prefix::V4(
            condition,
        ))],
        condition_policy: None,
        settle_time: Duration::from_secs(5),
        retiring: false,
    }
}

/// Definition X's settle deadline falls due with a long batch queued, and
/// the drain runs past definition Y's later deadline. Y's condition, which
/// appeared one second after X's, is withdrawn again before Y's deadline,
/// so Y must keep its applied state: X's turn applies only X. Red proof:
/// firing every settle deadline up to the current time at X's turn applies
/// Y's transient observation and suppresses its advertisement.
#[tokio::test(start_paused = true)]
async fn later_conditional_settle_waits_for_its_own_backlog() {
    let c = Ipv4Addr::new(10, 0, 0, 41);
    let x_condition = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 1), 32);
    let y_condition = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 2), 32);
    let (tx, rx) = mpsc::channel(16);
    let metrics = BgpMetrics::new();
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, metrics.clone());
    let _c_rx = connect_peer(&mut manager, c, 1, false, false);
    let _ = manager.install_conditional_advertisements(vec![
        absent_if("x", x_condition),
        absent_if("y", y_condition),
    ]);
    tokio::time::advance(Duration::from_secs(5)).await;
    let _ = manager.fire_conditional_advertisement_timers(tokio::time::Instant::now());
    let transitions = |name: &str| {
        counter_metric_value(
            &metrics,
            "bgp_conditional_advertisement_transitions_total",
            &[("name", name)],
        )
    };
    assert!(
        (transitions("x") - 1.0).abs() < f64::EPSILON,
        "X advertises"
    );
    assert!(
        (transitions("y") - 1.0).abs() < f64::EPSILON,
        "Y advertises"
    );

    manager.handle_update(received(c, 1, vec![make_route(x_condition, c)]));
    while manager.process_next_route_chunk() {}
    tokio::time::advance(Duration::from_secs(1)).await;
    manager.handle_update(received(c, 1, vec![make_route(y_condition, c)]));
    while manager.process_next_route_chunk() {}
    let start = tokio::time::Instant::now();
    let deadline = |manager: &RibManager, name| {
        manager
            .conditional_advertisement_state(name)
            .and_then(|(_, _, deadline)| deadline)
    };
    assert_eq!(
        deadline(&manager, "x"),
        Some(start + Duration::from_secs(4))
    );
    assert_eq!(
        deadline(&manager, "y"),
        Some(start + Duration::from_secs(5))
    );

    tx.try_send(long_batch(c)).unwrap();
    tokio::time::advance(Duration::from_secs(4)).await;
    let mut actor = Box::pin(manager.run());
    assert!(
        actor
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending(),
        "X's deadline captures the long batch and its drain starts"
    );
    // After X's cutoff, one second before Y's own deadline.
    tx.try_send(RibUpdate::RoutesReceived {
        peer: peer_v4(c),
        session_id: 1,
        announced: Vec::new(),
        withdrawn: vec![(Prefix::V4(y_condition), 0)],
        flowspec_announced: Vec::new(),
        flowspec_withdrawn: Vec::new(),
        evpn_announced: Vec::new(),
        evpn_withdrawn: Vec::new(),
        validated_with: None,
    })
    .unwrap();
    let (reply, mut barrier) = oneshot::channel();
    tx.try_send(RibUpdate::QueryLocRibCount { reply }).unwrap();
    tokio::time::advance(Duration::from_secs(2)).await;
    run_until(&mut actor, &mut barrier);

    assert!(
        (transitions("y") - 1.0).abs() < f64::EPSILON,
        "Y's condition settled back before its deadline; transitions={}",
        transitions("y")
    );
    assert!(
        (transitions("x") - 2.0).abs() < f64::EPSILON,
        "X's deadline fired and suppressed it"
    );
}

/// K peers' GR restart deadlines, 1 ms apart, under a primary channel of
/// `CAP` kept full by queries. With `first_look_at_earliest`, the actor first
/// looks at the earliest deadline and the rest pass during that drain;
/// otherwise every deadline has passed before the actor first looks.
/// Returns, per peer, the queries answered before its sweep.
async fn staggered_gr_sweeps(first_look_at_earliest: bool) -> Vec<usize> {
    const K: u8 = 8;
    let (tx, rx) = mpsc::channel(STAGGER_CAP);
    let metrics = BgpMetrics::new();
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, metrics.clone());
    let peers: Vec<Ipv4Addr> = (0..K).map(|k| Ipv4Addr::new(10, 9, 0, k + 1)).collect();
    for (k, &address) in (0u8..).zip(&peers) {
        let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, k * 4), 30);
        manager.handle_update(received(address, 0, vec![make_route(prefix, address)]));
        while manager.process_next_route_chunk() {}
        manager.handle_update(restart(address, 0, 2, 360));
        tokio::time::advance(Duration::from_millis(1)).await;
    }
    let expired = |address: Ipv4Addr| {
        counter_metric_value(
            &metrics,
            "bgp_gr_timer_expired_total",
            &[("peer", address.to_string().as_str())],
        ) > 0.5
    };
    let fill = |tx: &mpsc::Sender<RibUpdate>, pending: &mut Vec<oneshot::Receiver<usize>>| loop {
        let (reply, response) = oneshot::channel();
        if tx.try_send(RibUpdate::QueryLocRibCount { reply }).is_err() {
            break;
        }
        pending.push(response);
    };
    let mut pending = Vec::new();
    fill(&tx, &mut pending);
    let mut actor = Box::pin(manager.run());
    let mut poll = || {
        assert!(
            actor
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
    };
    let spread = Duration::from_millis(u64::from(K));
    if first_look_at_earliest {
        // The earliest deadline is t0 + 2 s; the clock reads t0 + K ms.
        tokio::time::advance(Duration::from_secs(2).saturating_sub(spread)).await;
        poll();
        tokio::time::advance(spread).await;
    } else {
        tokio::time::advance(Duration::from_secs(2)).await;
    }
    let mut answered = 0;
    let mut swept_after = vec![None; peers.len()];
    for _ in 0..100_000 {
        let before = answered;
        poll();
        pending.retain_mut(|response| {
            let done = response.try_recv().is_ok();
            answered += usize::from(done);
            !done
        });
        for (swept, &address) in swept_after.iter_mut().zip(&peers) {
            if swept.is_none() && expired(address) {
                *swept = Some(before);
            }
        }
        if swept_after.iter().all(Option::is_some) {
            break;
        }
        fill(&tx, &mut pending);
    }
    swept_after
        .into_iter()
        .map(|swept| swept.expect("every peer's deadline fires"))
        .collect()
}

/// The primary channel capacity of the staggered-deadline fixture.
const STAGGER_CAP: usize = 32;

/// ADR-0137 / RFC 4724 §4.2 bound: deadlines of one timer that have all
/// passed when it is first seen due fire together after one backlog; ones
/// that pass during that drain wait for at most one more. Red proof:
/// bounding each expiry by the timer's earliest deadline alone gives the
/// K-th peer K backlogs.
#[tokio::test(start_paused = true)]
async fn staggered_gr_deadlines_fire_within_two_backlogs() {
    let all_passed = staggered_gr_sweeps(false).await;
    assert!(
        all_passed.iter().all(|&answered| answered <= STAGGER_CAP),
        "deadlines passed at the first look share one backlog: {all_passed:?}"
    );
    let during_drain = staggered_gr_sweeps(true).await;
    assert!(
        during_drain
            .iter()
            .all(|&answered| answered <= 2 * STAGGER_CAP),
        "deadlines passing during the first drain wait at most one more backlog: {during_drain:?}"
    );
}

/// RFC 4724 §4.2: a session not re-established within the Restart Time has
/// its stale routes deleted. Peer A's and B's restart deadlines have both
/// passed when the actor first looks; B's context, `PeerUp`, UPDATE and
/// End-of-RIB arrive only after that capture, so B's stale routes are swept
/// with A's. Red proof: bounding the expiry by the earliest deadline alone
/// lets B's late `PeerUp` replace its restart deadline, and its stale routes
/// are never swept.
#[tokio::test(start_paused = true)]
async fn gr_deadline_passed_at_capture_is_not_saved_by_a_late_reconnect() {
    let a = Ipv4Addr::new(10, 0, 0, 51);
    let b = Ipv4Addr::new(10, 0, 0, 52);
    let c = Ipv4Addr::new(10, 0, 0, 53);
    let observer = Ipv4Addr::new(10, 0, 0, 54);
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
    manager.handle_update(restart(a, 1, 2, 360));
    tokio::time::advance(Duration::from_millis(500)).await;
    manager.handle_update(restart(b, 1, 2, 360));
    while out_rx.try_recv().is_ok() {}

    tx.try_send(long_batch(c)).unwrap();
    // Both restart deadlines pass before the first look.
    tokio::time::advance(Duration::from_secs(3)).await;
    let mut actor = Box::pin(manager.run());
    assert!(
        actor
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending(),
        "the cutoff captures the long batch with both deadlines passed"
    );
    // B returns after its restart time, after the capture.
    let peer = peer_v4(b);
    tx.try_send(RibUpdate::SetPeerGracefulRestartContext {
        peer,
        session_id: 2,
        peer_restart_state: true,
        peer_gr_helper: true,
        peer_gr_families: ipv4_sendable(),
        peer_enhanced_refresh: true,
        peer_llgr_families: Vec::new(),
        local_llgr_stale_time: 0,
    })
    .unwrap();
    let (new_b_tx, _new_b_rx) = mpsc::channel(16384);
    tx.try_send(super::lifecycle::test_peer_up(peer, 2, new_b_tx))
        .unwrap();
    tx.try_send(received(b, 2, vec![make_route(followed(), b)]))
        .unwrap();
    tx.try_send(RibUpdate::EndOfRib {
        peer,
        session_id: 2,
        afi: Afi::Ipv4,
        safi: Safi::Unicast,
    })
    .unwrap();
    let (reply, mut barrier) = oneshot::channel();
    tx.try_send(RibUpdate::QueryLocRibCount { reply }).unwrap();
    run_until(&mut actor, &mut barrier);

    let expired = |address: Ipv4Addr| {
        counter_metric_value(
            &metrics,
            "bgp_gr_timer_expired_total",
            &[("peer", address.to_string().as_str())],
        )
    };
    assert!((expired(a) - 1.0).abs() < f64::EPSILON, "A's routes swept");
    assert!(
        (expired(b) - 1.0).abs() < f64::EPSILON,
        "B missed its restart time, so its stale routes are swept"
    );
    assert_eq!(
        followed_trace(&mut out_rx),
        vec!["withdraw", "announce"],
        "B's stale route goes, and the new session announces it again"
    );
}

/// ADR-0137: a condition that held for its whole settle time applies, even
/// when it changes after its deadline. X's and Y's settle deadlines have
/// both passed when the actor first looks; Y's condition is withdrawn only
/// after that capture. Y's transition applies with X's, and the withdrawal
/// starts a new settle. Red proof: bounding the expiry by the earliest
/// deadline alone fires only X; the withdrawal is then admitted first and
/// re-arms Y, and Y's settled transition is lost.
#[tokio::test(start_paused = true)]
async fn conditional_settle_passed_at_capture_applies_before_a_later_flip() {
    let c = Ipv4Addr::new(10, 0, 0, 41);
    let x_condition = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 1), 32);
    let y_condition = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 2), 32);
    let (tx, rx) = mpsc::channel(16);
    let metrics = BgpMetrics::new();
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, metrics.clone());
    let _c_rx = connect_peer(&mut manager, c, 1, false, false);
    let _ = manager.install_conditional_advertisements(vec![
        absent_if("x", x_condition),
        absent_if("y", y_condition),
    ]);
    tokio::time::advance(Duration::from_secs(5)).await;
    let _ = manager.fire_conditional_advertisement_timers(tokio::time::Instant::now());
    let transitions = |name: &str| {
        counter_metric_value(
            &metrics,
            "bgp_conditional_advertisement_transitions_total",
            &[("name", name)],
        )
    };
    manager.handle_update(received(c, 1, vec![make_route(x_condition, c)]));
    while manager.process_next_route_chunk() {}
    tokio::time::advance(Duration::from_secs(1)).await;
    manager.handle_update(received(c, 1, vec![make_route(y_condition, c)]));
    while manager.process_next_route_chunk() {}

    tx.try_send(long_batch(c)).unwrap();
    // Both settle deadlines (4 s and 5 s from now) pass before the first look.
    tokio::time::advance(Duration::from_secs(6)).await;
    let mut actor = Box::pin(manager.run());
    assert!(
        actor
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending(),
        "the cutoff captures the long batch with both deadlines passed"
    );
    // After the capture and after Y's deadline.
    tx.try_send(RibUpdate::RoutesReceived {
        peer: peer_v4(c),
        session_id: 1,
        announced: Vec::new(),
        withdrawn: vec![(Prefix::V4(y_condition), 0)],
        flowspec_announced: Vec::new(),
        flowspec_withdrawn: Vec::new(),
        evpn_announced: Vec::new(),
        evpn_withdrawn: Vec::new(),
        validated_with: None,
    })
    .unwrap();
    let (reply, mut barrier) = oneshot::channel();
    tx.try_send(RibUpdate::QueryLocRibCount { reply }).unwrap();
    run_until(&mut actor, &mut barrier);

    assert!(
        (transitions("x") - 2.0).abs() < f64::EPSILON,
        "X's settled condition applies"
    );
    assert!(
        (transitions("y") - 2.0).abs() < f64::EPSILON,
        "Y's settled condition applies before its later withdrawal; transitions={}",
        transitions("y")
    );
}
