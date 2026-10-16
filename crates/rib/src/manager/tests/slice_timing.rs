use std::sync::atomic::{AtomicBool, Ordering};

use super::*;

const STALL: Duration = Duration::from_millis(70);
const ROUTES: u32 = 200;

/// Samples of one stage above `le` and at or below 2 s, the top bucket.
fn slice_samples_above(metrics: &BgpMetrics, stage: &str, le: f64) -> u64 {
    let families = metrics.registry().gather();
    let histogram = families
        .iter()
        .find(|family| family.name() == "bgp_rib_actor_slice_seconds")
        .and_then(|family| {
            family.get_metric().iter().find(|metric| {
                metric
                    .get_label()
                    .iter()
                    .any(|label| label.name() == "stage" && label.value() == stage)
            })
        })
        .expect("pre-initialised stage series")
        .get_histogram();
    let at = |bound: f64| {
        histogram
            .get_bucket()
            .iter()
            .find(|bucket| (bucket.upper_bound() - bound).abs() < 1e-9)
            .expect("configured bucket edge")
            .cumulative_count()
    };
    at(2.0) - at(le)
}

/// A synchronous stall inside peer teardown key collection holds the actor:
/// both the whole poll and the checkpoint slice it ends land above the
/// stall's bucket edge, and the since-render maximum reports it once.
#[tokio::test]
async fn seeded_actor_stall_lands_in_its_bucket_and_moves_the_max() {
    let metrics = BgpMetrics::new();
    let (tx, rx) = mpsc::channel(64);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, metrics.clone());
    let stalled = Arc::new(AtomicBool::new(false));
    manager.replacement_readiness_test_hook = Some(Arc::new({
        let stalled = Arc::clone(&stalled);
        move |stage| {
            if stage == "peer_down_collect_unicast" && !stalled.swap(true, Ordering::SeqCst) {
                std::thread::sleep(STALL);
            }
        }
    }));
    let handle = tokio::spawn(manager.run());

    // Enough routes that the sampled cut after the stall still falls inside
    // key collection.
    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer,
        announced: (0..ROUTES)
            .map(|index| make_indexed_route(index, Ipv4Addr::new(10, 0, 0, 1)))
            .collect(),
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
        validated_with: None,
    })
    .await
    .unwrap();
    assert_eq!(query_best_routes(&tx).await.len(), ROUTES as usize);
    metrics.publish_render_window_maxima();
    let edge = 0.06;
    assert_eq!(slice_samples_above(&metrics, "actor_poll", edge), 0);
    assert_eq!(slice_samples_above(&metrics, "retirement", edge), 0);

    tx.send(RibUpdate::PeerDown {
        peer,
        session_id: 0,
    })
    .await
    .unwrap();
    assert!(query_best_routes(&tx).await.is_empty());
    assert!(stalled.load(Ordering::SeqCst), "the stall hook must run");

    metrics.publish_render_window_maxima();
    assert_eq!(slice_samples_above(&metrics, "actor_poll", edge), 1);
    assert_eq!(slice_samples_above(&metrics, "retirement", edge), 1);
    for stage in ["actor_poll", "retirement"] {
        let max = gauge_metric_value(
            &metrics,
            "bgp_rib_actor_slice_max_microseconds",
            &[("stage", stage)],
        ) / 1e6;
        assert!(
            (STALL.as_secs_f64()..2.0).contains(&max),
            "{stage} max {max} must report the {STALL:?} stall"
        );
    }

    // The next render window saw no teardown slice.
    metrics.publish_render_window_maxima();
    let retirement = gauge_metric_value(
        &metrics,
        "bgp_rib_actor_slice_max_microseconds",
        &[("stage", "retirement")],
    );
    assert!(
        retirement.abs() < f64::EPSILON,
        "retirement max reset to {retirement}"
    );

    drop(tx);
    handle.await.unwrap();
}
