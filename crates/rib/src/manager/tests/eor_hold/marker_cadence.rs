//! Delivery cadence through the actor's actual timer arms and rearms.

use super::*;
use crate::route::RtcRibRouteKey;
use tokio::time::{Instant, sleep, sleep_until, timeout_at};

const WAITER: PeerId = peer_v4(Ipv4Addr::new(192, 0, 2, 240));
const RETRY_PEER: PeerId = peer_v4(Ipv4Addr::new(203, 0, 113, 1));

type Output = mpsc::Receiver<OutboundRouteUpdate>;

fn release_waiter(family: (Afi, Safi)) -> RibUpdate {
    RibUpdate::EndOfRib {
        peer: WAITER,
        session_id: 1,
        afi: family.0,
        safi: family.1,
    }
}

struct Cohort {
    manager: RibManager,
    input: mpsc::Sender<RibUpdate>,
    outputs: Vec<Output>,
    _waiter_output: Output,
}

fn held_cohort(size: u16, family: (Afi, Safi)) -> Cohort {
    let (input, rx) = mpsc::channel(16);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new())
        .with_selection_deferral(SelectionDeferralConfig {
            timeout: Duration::from_mins(5),
            waiters: vec![SelectionDeferralWaiterConfig {
                peer: WAITER.into(),
                families: vec![family],
            }],
        });
    let waiter = connect(&mut manager, WAITER, 1, family);
    let mut outputs = Vec::new();
    for n in 0..size {
        let [hi, lo] = n.to_be_bytes();
        let peer = peer_v4(Ipv4Addr::new(198, 18, hi, lo));
        let mut output = if family == FAMILY {
            connect(&mut manager, peer, 2, FAMILY)
        } else {
            let output = connect_with(&mut manager, peer, 2, vec![family, FAMILY]);
            // The receiver has finished its RTC feed. Its membership cannot
            // release the VPN marker until the waiter's RTC selection opens.
            manager.handle_update(RibUpdate::EndOfRib {
                peer,
                session_id: 2,
                afi: family.0,
                safi: family.1,
            });
            output
        };
        assert_eq!(markers(&mut output), 0, "early VPN marker for {peer}");
        outputs.push(output);
    }
    assert!(manager.selection_deferred(family));
    Cohort {
        manager,
        input,
        outputs,
        _waiter_output: waiter,
    }
}

async fn barrier(input: &mpsc::Sender<RibUpdate>) {
    let (reply, response) = oneshot::channel();
    input
        .send(RibUpdate::QueryLocRibCount { reply })
        .await
        .unwrap();
    response.await.unwrap();
}

async fn check_release(size: u16, family: (Afi, Safi), expected_ticks: u64) {
    let Cohort {
        manager,
        input,
        outputs,
        _waiter_output,
    } = held_cohort(size, family);
    let actor = tokio::spawn(manager.run());
    barrier(&input).await;
    let mut collectors = tokio::task::JoinSet::new();
    for mut output in outputs {
        assert_eq!(markers(&mut output), 0, "VPN marker before release");
        collectors.spawn(async move {
            while let Some(update) = output.recv().await {
                let count = update.end_of_rib.iter().filter(|f| **f == FAMILY).count();
                if count != 0 {
                    assert_eq!(count, 1, "duplicate VPN marker in one envelope");
                    return (Instant::now(), output);
                }
            }
            panic!("receiver closed before its VPN marker");
        });
    }

    let released = Instant::now();
    input.send(release_waiter(family)).await.unwrap();
    let mut first = Duration::MAX;
    let mut last = Duration::ZERO;
    let mut outputs = Vec::new();
    // Keep the actual last marker for a cadence regression; the RTC cap can
    // take over at 60 s if the membership releases get stuck on the slow tick.
    let deadline = released + Duration::from_secs(65);
    while let Some(result) = timeout_at(deadline, collectors.join_next()).await.unwrap() {
        let (at, output) = result.unwrap();
        let elapsed = at - released;
        first = first.min(elapsed);
        last = last.max(elapsed);
        outputs.push(output);
    }
    assert_eq!(outputs.len(), usize::from(size));
    let expected = Duration::from_millis(expected_ticks * 10);
    let window = expected..=expected + Duration::from_millis(1);
    eprintln!("{family:?} release to {size} receivers: first VPN marker {first:?}, last {last:?}");
    assert!(
        window.contains(&last),
        "{size} receivers: last VPN marker at {last:?}, expected {expected_ticks} ticks ({window:?})"
    );
    sleep(Duration::from_secs(2)).await;
    barrier(&input).await;
    for mut output in outputs {
        assert_eq!(
            markers(&mut output),
            0,
            "duplicate VPN marker after release"
        );
    }
    drop(input);
    actor.await.unwrap();
}

// VPN selection visits the waiter and seven receivers inline, then eight per tick.
#[tokio::test(start_paused = true)]
async fn vpn_release_64() {
    check_release(64, FAMILY, 8).await;
}

#[tokio::test(start_paused = true)]
async fn vpn_release_448() {
    check_release(448, FAMILY, 56).await;
}

// The receivers already have the unicast table when an empty VPN release
// finds their writers full. Count both table builds and actual envelopes.
#[tokio::test(start_paused = true)]
async fn refused_vpn_release_retries_only_the_marker() {
    const ROWS: u16 = 1_000;
    let mut results = Vec::new();
    for size in [8_u16, 64] {
        let Cohort {
            mut manager,
            input,
            _waiter_output,
            ..
        } = held_cohort(0, FAMILY);
        let (source_tx, _source_output) = mpsc::channel(16);
        manager.handle_update(super::super::lifecycle::test_peer_up(SOURCE, 3, source_tx));
        let routes = (0..u32::from(ROWS))
            .map(|n| make_indexed_route(n, Ipv4Addr::new(10, 0, 0, 1)))
            .collect();
        manager.handle_update(super::super::lifecycle::test_session_routes_received(
            SOURCE, 3, routes,
        ));
        drain_route_chunks(&mut manager);
        let mut outputs = Vec::new();
        for n in 0..size {
            let [hi, lo] = n.to_be_bytes();
            let peer = peer_v4(Ipv4Addr::new(198, 18, hi, lo));
            let mut output = connect_with(&mut manager, peer, 2, vec![V4, FAMILY]);
            let admitted: usize = std::iter::from_fn(|| output.try_recv().ok())
                .map(delivered)
                .map(|update| {
                    assert!(!update.end_of_rib.contains(&FAMILY));
                    update.announce.len()
                })
                .sum();
            assert_eq!(admitted, usize::from(ROWS));
            let writer = &manager.outbound_peers[&peer];
            while writer.try_send(OutboundRouteUpdate::default()).is_ok() {}
            outputs.push(output);
        }

        let builds = manager.adj_rib_out_commit_stats.resync_builds;
        let start = Instant::now();
        let actor = tokio::spawn(manager.run_actor());
        input.send(release_waiter(FAMILY)).await.unwrap();
        barrier(&input).await;
        sleep_until(start + Duration::from_millis(999)).await;
        for output in &mut outputs {
            while let Ok(update) = output.try_recv() {
                assert!(update.end_of_rib.is_empty() && update.announce.is_empty());
            }
        }
        let mut rows = 0;
        let mut markers = vec![0; usize::from(size)];
        let mut by_deadline = 0;
        // Also observe a later retry interval to count duplicate deliveries
        // and any table rebuild that the marker deadline would miss.
        for elapsed in [1_001 + 10 * u64::from(size / 8 - 1), 5_000] {
            sleep_until(start + Duration::from_millis(elapsed)).await;
            barrier(&input).await;
            for (output, count) in outputs.iter_mut().zip(&mut markers) {
                while let Ok(update) = output.try_recv().map(delivered) {
                    rows += update.announce.len() + update.unicast_withdrawals().count();
                    *count += update.end_of_rib.iter().filter(|&&f| f == FAMILY).count();
                }
            }
            if elapsed != 5_000 {
                by_deadline = markers.iter().sum::<usize>();
            }
        }
        drop(input);
        let manager = actor.await.unwrap();
        results.push((
            manager.adj_rib_out_commit_stats.resync_builds - builds,
            rows,
            by_deadline,
            markers,
        ));
    }
    assert_eq!(results, [(0, 0, 8, vec![1; 8]), (0, 0, 64, vec![1; 64])]);
}

// The RTC rebuild releases four membership holds inline, then two per tick.
#[tokio::test(start_paused = true)]
async fn rebuilt_rtc_memberships_64() {
    check_release(64, RtcRibRouteKey::afi_safi(), 30).await;
}

#[tokio::test(start_paused = true)]
async fn rebuilt_rtc_memberships_448() {
    check_release(448, RtcRibRouteKey::afi_safi(), 222).await;
}

#[tokio::test(start_paused = true)]
async fn release_preempts_an_armed_slow_tick_without_retrying_a_refused_writer_early() {
    let Cohort {
        mut manager,
        input,
        mut outputs,
        _waiter_output,
    } = held_cohort(64, FAMILY);
    // An eBGP source's VPN row feeds the receiver's deferred refresh when the
    // waiter releases selection. Sending its nonempty table returns a latch.
    let addr = Ipv4Addr::new(192, 0, 2, 9);
    let advertiser = peer_v4(addr);
    let (tx, _advertiser_output) = mpsc::channel(8);
    let mut registration = super::super::lifecycle::test_peer_up(advertiser, 4, tx);
    if let RibUpdate::PeerUp {
        sendable_families, ..
    } = &mut registration
    {
        *sendable_families = vec![FAMILY];
    }
    manager.handle_update(registration);
    let mut route = make_vpn_rib_route(addr, 31, 100, 100);
    route.origin_type = crate::route::RouteOrigin::Ebgp;
    let key = route.key();
    manager.handle_update(RibUpdate::VpnRoutesReceived {
        peer: advertiser,
        session_id: 4,
        announced: vec![route],
        withdrawn: vec![],
    });
    drain_route_chunks(&mut manager);
    let target = peer_v4(Ipv4Addr::new(198, 18, 0, 63));
    manager.handle_update(RibUpdate::RouteRefreshRequest {
        peer: target,
        session_id: 2,
        afi: FAMILY.0,
        safi: FAMILY.1,
        queued: Arc::default(),
    });
    assert!(manager.orf_refresh_queued(target, FAMILY));
    let mut refused = connect(&mut manager, RETRY_PEER, 3, V4);
    assert_eq!(markers_of(&mut refused, V4), 1);
    refuse_final_marker(&mut manager, RETRY_PEER, &mut refused);

    let start = Instant::now();
    let actor = tokio::spawn(manager.run());
    barrier(&input).await;
    sleep_until(start + Duration::from_millis(500)).await;
    input.send(release_waiter(FAMILY)).await.unwrap();
    barrier(&input).await;
    let mut target_output = outputs.pop().unwrap();
    let mut latched_data = false;
    let mut target_eors = 0;
    let mut refresh_complete = false;
    timeout_at(start + Duration::from_millis(700), async {
        while !refresh_complete || target_eors == 0 {
            let update = target_output.recv().await.unwrap();
            for row in update.vpn_announce.iter() {
                assert_eq!(row.key(), key);
                latched_data |= update.latch.is_some();
            }
            target_eors += update.end_of_rib.iter().filter(|&&f| f == FAMILY).count();
            refresh_complete |= update.refresh_markers.contains(&(
                FAMILY.0,
                FAMILY.1,
                rustbgpd_wire::RouteRefreshSubtype::EoRR,
            ));
            drop(delivered(update));
        }
    })
    .await
    .expect("the nonempty deferred refresh must finish at the release cadence");
    assert!(latched_data);
    assert_eq!(target_eors, 1);
    sleep_until(start + Duration::from_millis(700)).await;
    barrier(&input).await;
    for output in &mut outputs {
        assert_eq!(markers(output), 1, "release waited for the slow tick");
    }
    sleep_until(start + Duration::from_millis(999)).await;
    assert_eq!(
        markers_of(&mut refused, V4),
        0,
        "fast release retried a refused writer"
    );
    let update = timeout_at(start + Duration::from_millis(1_002), refused.recv())
        .await
        .expect("ordinary retry deadline slipped")
        .unwrap();
    assert_eq!(update.end_of_rib, [V4]);
    let elapsed = start.elapsed();
    eprintln!("refused writer retried after {elapsed:?} with a concurrent VPN release");
    assert!((Duration::from_secs(1)..=Duration::from_millis(1_001)).contains(&elapsed));
    drop(input);
    actor.await.unwrap();
}

fn count_ring_visits(manager: &mut RibManager) -> Arc<std::sync::atomic::AtomicUsize> {
    let visits = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    manager.marker_retry_test_hook = Some(Arc::new({
        let visits = Arc::clone(&visits);
        move |seam| {
            if seam == "evpn_marker_candidate" {
                visits.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
        }
    }));
    visits
}

/// Receivers whose unicast release marker a full writer refused, on a
/// manager with nothing else to do: the retry deadline is the only wake.
/// The refusing helper reads its writer empty again; `full` refills it.
fn refused_ring(size: u16, full: bool) -> (RibManager, mpsc::Sender<RibUpdate>, Vec<Output>) {
    let Cohort {
        mut manager,
        input,
        outputs: _,
        _waiter_output,
    } = held_cohort(0, FAMILY);
    let mut refused = Vec::new();
    for n in 0..size {
        let [hi, lo] = n.to_be_bytes();
        let peer = peer_v4(Ipv4Addr::new(203, 1, hi, lo));
        let mut output = connect(&mut manager, peer, 3, V4);
        assert_eq!(markers_of(&mut output, V4), 1);
        refuse_final_marker(&mut manager, peer, &mut output);
        let sender = &manager.outbound_peers[&peer];
        while full && sender.try_send(OutboundRouteUpdate::default()).is_ok() {}
        refused.push(output);
    }
    (manager, input, refused)
}

/// Empty every writer now and return when each retried marker arrived.
async fn drain_and_time(refused: Vec<Output>) -> (Vec<Duration>, Vec<Output>) {
    let drained = Instant::now();
    let mut collectors = tokio::task::JoinSet::new();
    for mut output in refused {
        collectors.spawn(async move {
            while let Some(update) = output.recv().await {
                if update.end_of_rib.contains(&V4) {
                    assert_eq!(update.end_of_rib, [V4]);
                    return (Instant::now(), output);
                }
            }
            panic!("receiver closed before its retried marker");
        });
    }
    let mut times = Vec::new();
    let mut outputs = Vec::new();
    let deadline = drained + Duration::from_secs(65);
    while let Some(result) = timeout_at(deadline, collectors.join_next())
        .await
        .expect("a refused marker was never retried")
    {
        let (at, output) = result.unwrap();
        times.push(at - drained);
        outputs.push(output);
    }
    times.sort();
    (times, outputs)
}

// No refused marker is retried before its deadline. Once retries are due the
// ring drains eight peers per backlog tick, not eight per retry interval.
async fn check_retry_ring(size: u16) {
    let (manager, input, refused) = refused_ring(size, false);
    let actor = tokio::spawn(manager.run());
    barrier(&input).await;
    let (times, outputs) = drain_and_time(refused).await;
    assert_eq!(times.len(), usize::from(size));
    eprintln!(
        "{size} refused markers after their writers drained: first retry {:?}, last {:?}",
        times[0],
        times[times.len() - 1]
    );
    for (slice, at) in (0_u32..).zip(times.chunks(8)) {
        let expected = Duration::from_secs(1) + Duration::from_millis(10) * slice;
        let window = expected..=expected + Duration::from_millis(1);
        assert!(
            at.iter().all(|at| window.contains(at)),
            "slice {slice} of {size} retried at {at:?}, expected {window:?}"
        );
    }
    sleep(Duration::from_secs(3)).await;
    barrier(&input).await;
    for mut output in outputs {
        assert_eq!(markers_of(&mut output, V4), 0, "duplicate retried marker");
    }
    drop(input);
    actor.await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn refused_release_markers_64_drain_at_the_backlog_cadence_once_due() {
    check_retry_ring(64).await;
}

#[tokio::test(start_paused = true)]
async fn refused_release_markers_448_drain_at_the_backlog_cadence_once_due() {
    check_retry_ring(448).await;
}

// A writer that stays full costs one offer per pass, and a pass starts one
// retry interval after the last one ended: never a backlog-cadence loop.
#[tokio::test(start_paused = true)]
async fn writers_full_for_30_s_cost_one_offer_per_peer_per_pass() {
    const SIZE: u16 = 64;
    let (mut manager, input, refused) = refused_ring(SIZE, true);
    let visits = count_ring_visits(&mut manager);
    let start = Instant::now();
    let actor = tokio::spawn(manager.run());
    barrier(&input).await;
    sleep_until(start + Duration::from_secs(30)).await;
    barrier(&input).await;
    // Each pass takes eight slices 10 ms apart and the next begins 1 s after
    // it ends: passes start at 1.00 s, 2.07 s, ... and 28 fit in 30 s.
    let offers = visits.load(std::sync::atomic::Ordering::Relaxed);
    eprintln!("{SIZE} writers full for 30 s: {offers} retry offers");
    assert_eq!(offers, 28 * usize::from(SIZE));
    let (times, outputs) = drain_and_time(refused).await;
    let bound = Duration::from_secs(1) + Duration::from_millis(10) * u32::from(SIZE / 8);
    eprintln!(
        "writers drained at 30 s: first retry {:?}, last {:?}",
        times[0],
        times[times.len() - 1]
    );
    assert_eq!(times.len(), usize::from(SIZE));
    assert!(
        times[times.len() - 1] <= bound,
        "last retry at {:?}",
        times.last()
    );
    drop(outputs);
    drop(input);
    actor.await.unwrap();
}

// A resync tick pulled forward by a drained whole-table operation runs the
// data lanes only. `busy` keeps route chunks queued, so the loop finds the
// tick due between work units instead of in its timer select.
async fn check_resync_tick_leaves_a_refused_marker_to_its_deadline(busy: bool) {
    let (input, rx) = mpsc::channel(16);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let _source = connect(&mut manager, SOURCE, 1, V4);
    // The refusing helper reads this writer empty: an early retry would land.
    let mut refused = connect(&mut manager, RETRY_PEER, 3, V4);
    assert_eq!(markers_of(&mut refused, V4), 1);
    refuse_final_marker(&mut manager, RETRY_PEER, &mut refused);
    // A dirty peer behind a full writer keeps the resync timer armed.
    let _dirty = connect(&mut manager, OTHER, 4, V4);
    let sender = &manager.outbound_peers[&OTHER];
    while sender.try_send(OutboundRouteUpdate::default()).is_ok() {}
    manager.mark_outbound_dirty(OTHER);
    let latch = Arc::clone(&manager.outbound_latch_released);

    let start = Instant::now();
    let actor = tokio::spawn(manager.run());
    barrier(&input).await;
    if busy {
        // Routes from an iBGP source reach no iBGP receiver: Loc-RIB work only.
        let announced = (0..16 * 1024_u32)
            .map(|n| {
                let [_, b, c, d] = n.to_be_bytes();
                let mut route = make_route(
                    Ipv4Prefix::new(Ipv4Addr::new(100, b, c, d), 32),
                    Ipv4Addr::new(10, 0, 0, 1),
                );
                route.peer = SOURCE;
                route
            })
            .collect();
        input
            .send(RibUpdate::RoutesReceived {
                session_id: 1,
                peer: SOURCE,
                announced,
                withdrawn: vec![],
                flowspec_announced: vec![],
                flowspec_withdrawn: vec![],
                evpn_announced: vec![],
                evpn_withdrawn: vec![],
                validated_with: None,
            })
            .await
            .unwrap();
        tokio::task::yield_now().await;
    }
    latch.notify_one();
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_millis(10)).await;
    for _ in 0..4 {
        tokio::task::yield_now().await;
    }
    assert_eq!(
        markers_of(&mut refused, V4),
        0,
        "the resync tick retried a refused marker {:?} after its refusal",
        start.elapsed()
    );
    assert!(start.elapsed() < Duration::from_millis(20));
    sleep_until(start + Duration::from_millis(999)).await;
    barrier(&input).await;
    assert_eq!(markers_of(&mut refused, V4), 0);
    sleep_until(start + Duration::from_millis(1_001)).await;
    barrier(&input).await;
    assert_eq!(markers_of(&mut refused, V4), 1);
    drop(input);
    actor.await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn a_resync_tick_from_the_timer_select_leaves_a_refused_marker_to_its_deadline() {
    check_resync_tick_leaves_a_refused_marker_to_its_deadline(false).await;
}

#[tokio::test(start_paused = true)]
async fn a_resync_tick_between_route_chunks_leaves_a_refused_marker_to_its_deadline() {
    check_resync_tick_leaves_a_refused_marker_to_its_deadline(true).await;
}

// A pass whose remaining peers all went away never reaches its end. The
// next armed deadline must start a new pass at the lowest peer, not after
// the abandoned cursor, or a lower peer waits a second retry interval.
#[tokio::test(start_paused = true)]
async fn a_retry_pass_armed_after_an_abandoned_one_starts_at_the_lowest_peer() {
    let (input, rx) = mpsc::channel(16);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let mut abandoned = Vec::new();
    for host in 10..=18 {
        let peer = peer_v4(Ipv4Addr::new(203, 0, 113, host));
        let mut output = connect(&mut manager, peer, 3, V4);
        assert_eq!(markers_of(&mut output, V4), 1);
        refuse_final_marker(&mut manager, peer, &mut output);
        let sender = &manager.outbound_peers[&peer];
        while sender.try_send(OutboundRouteUpdate::default()).is_ok() {}
        abandoned.push((peer, output));
    }
    assert!(
        manager.retry_eor_markers_bounded(),
        "one peer left in the pass"
    );
    for (peer, _) in &abandoned {
        manager.handle_update(RibUpdate::PeerDown {
            peer: *peer,
            session_id: 3,
        });
    }
    assert!(!manager.marker_retry_pending());
    assert!(
        manager
            .evpn_marker_cursor
            .is_some_and(|cursor| RETRY_PEER < cursor)
    );
    let mut refused = connect(&mut manager, RETRY_PEER, 3, V4);
    assert_eq!(markers_of(&mut refused, V4), 1);
    refuse_final_marker(&mut manager, RETRY_PEER, &mut refused);

    let start = Instant::now();
    let actor = tokio::spawn(manager.run());
    barrier(&input).await;
    sleep_until(start + Duration::from_millis(999)).await;
    assert_eq!(markers_of(&mut refused, V4), 0);
    let update = timeout_at(start + Duration::from_millis(1_001), refused.recv())
        .await
        .expect("the new pass skipped a peer below the abandoned cursor")
        .unwrap();
    assert_eq!(update.end_of_rib, [V4]);
    drop(input);
    actor.await.unwrap();
}
