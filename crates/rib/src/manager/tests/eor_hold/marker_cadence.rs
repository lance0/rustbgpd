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
