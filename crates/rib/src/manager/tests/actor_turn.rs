use super::*;
use crate::manager::actor_turn::{ActorTurn, SLOW_ACTOR_TURN, SLOW_ACTOR_TURN_LOG_INTERVAL};

const TURN_METRIC: &str = "bgp_rib_actor_turn_duration_seconds";

/// Cumulative `le="0.2"` bucket count of the `kind` turn series.
fn turns_within_slow_threshold(metrics: &BgpMetrics, kind: &str) -> u64 {
    metrics
        .registry()
        .gather()
        .iter()
        .find(|family| family.name() == TURN_METRIC)
        .and_then(|family| {
            family
                .get_metric()
                .iter()
                .find(|metric| metric.get_label().iter().any(|label| label.value() == kind))
        })
        .and_then(|metric| {
            let edge = metric.get_histogram().get_bucket().iter().find(|bucket| {
                bucket.upper_bound().to_bits() == SLOW_ACTOR_TURN.as_secs_f64().to_bits()
            })?;
            Some(edge.cumulative_count())
        })
        .expect("turn series has a bucket edge at the slow-turn threshold")
}

fn routes_received(peer: PeerId) -> RibUpdate {
    RibUpdate::RoutesReceived {
        session_id: 0,
        peer,
        announced: vec![make_route(
            Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, 0), 24),
            Ipv4Addr::new(10, 0, 0, 1),
        )],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
        validated_with: None,
    }
}

#[test]
fn each_message_turn_is_observed_under_its_kind() {
    let metrics = BgpMetrics::new();
    let (_tx, rx) = mpsc::channel(8);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, metrics.clone());
    let peer = peer_v4(Ipv4Addr::new(10, 0, 0, 1));
    manager.ribs.insert(peer, AdjRibIn::new(peer));

    manager.handle_update(routes_received(peer));
    // Chunk processing is deferred work outside the message's turn.
    drain_route_chunks(&mut manager);
    let (reply, _count) = oneshot::channel();
    manager.serve_general_query(RibUpdate::QueryLocRibCount { reply });
    manager.handle_update(RibUpdate::PeerDown {
        peer,
        session_id: 0,
    });

    let counts = histogram_sample_counts_by_label(&metrics, TURN_METRIC, "kind");
    let observed: BTreeMap<_, _> = counts.into_iter().filter(|(_, count)| *count > 0).collect();
    assert_eq!(
        observed,
        BTreeMap::from([
            ("peer_down".to_owned(), 1),
            ("query".to_owned(), 1),
            ("routes".to_owned(), 1),
        ]),
        "one turn per handled message, under its own kind"
    );
}

/// A test hook holds the turn for exactly the threshold, so the turn is slow
/// by construction rather than by racing a sleep against the actor.
#[test]
fn slow_turn_warns_once_per_interval() {
    let metrics = BgpMetrics::new();
    let (_tx, rx) = mpsc::channel(8);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, metrics.clone());
    let peer = peer_v4(Ipv4Addr::new(10, 0, 0, 1));
    manager.ribs.insert(peer, AdjRibIn::new(peer));

    // A fast turn does not touch the warning state.
    manager.handle_update(RibUpdate::PeerDown {
        peer,
        session_id: 0,
    });
    assert!(manager.slow_actor_turn_log.last.is_none());

    manager.test_primary_update_hook = Some(Arc::new(|update: &RibUpdate| {
        if matches!(update, RibUpdate::QueryLocRibCount { .. }) {
            std::thread::sleep(SLOW_ACTOR_TURN);
        }
    }));
    let (reply, _count) = oneshot::channel();
    manager.handle_update(RibUpdate::QueryLocRibCount { reply });

    assert_eq!(
        turns_within_slow_threshold(&metrics, "query"),
        0,
        "the held query turn lands above the threshold edge"
    );
    let warned_at = manager
        .slow_actor_turn_log
        .last
        .expect("the first slow turn warns");
    assert_eq!(manager.slow_actor_turn_log.suppressed, 0);

    // A second slow turn inside the interval is counted, not logged.
    let turn = ActorTurn::new(
        &RibUpdate::PeerDown {
            peer,
            session_id: 0,
        },
        &manager.ribs,
    );
    manager.finish_actor_turn(turn, SLOW_ACTOR_TURN);
    assert_eq!(manager.slow_actor_turn_log.last, Some(warned_at));
    assert_eq!(manager.slow_actor_turn_log.suppressed, 1);

    // Once the interval has passed, the next slow turn logs again and
    // reports the suppressed count.
    manager.slow_actor_turn_log.last = Instant::now().checked_sub(SLOW_ACTOR_TURN_LOG_INTERVAL);
    manager.finish_actor_turn(turn, SLOW_ACTOR_TURN);
    assert!(manager.slow_actor_turn_log.last > Some(warned_at));
    assert_eq!(manager.slow_actor_turn_log.suppressed, 0);

    assert_eq!(
        histogram_sample_counts_by_label(&metrics, TURN_METRIC, "kind")["peer_down"],
        3,
        "every turn is observed whether or not it logs"
    );
}
