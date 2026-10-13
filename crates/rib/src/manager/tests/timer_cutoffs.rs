//! Retention and deferral timers stay bounded under sustained ingress: each
//! expiry waits only for the primary backlog queued when it first fell due
//! (the ADR-0137 admission cutoff), not for the queue to go empty.

use std::sync::atomic::{AtomicBool, Ordering};

use super::*;

const SOURCE: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);

fn source() -> IpAddr {
    IpAddr::V4(SOURCE)
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
        &[("peer", "10.0.0.1"), ("afi_safi", "ipv4_unicast")],
    )
}

fn selection_deferral_timeouts(metrics: &BgpMetrics) -> f64 {
    counter_metric_value(
        metrics,
        "bgp_selection_deferral_timeouts_total",
        &[("afi_safi", "ipv4_unicast")],
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
                peer: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 99)),
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
                peer: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 99)),
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
        peer: IpAddr::V4(other),
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
        peer: IpAddr::V4(other),
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
            &[("afi_safi", "ipv6_unicast")],
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
