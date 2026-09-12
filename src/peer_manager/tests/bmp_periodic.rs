use super::*;
use rustbgpd_api::peer_types::{PeerManagerOperatorQuery, PeerManagerReadinessQuery};

fn enable_loc_rib_stats(manager: &mut PeerManager) {
    manager.current_config.bmp = Some(crate::config::BmpConfig {
        sys_name: "periodic-stats-test".into(),
        sys_descr: String::new(),
        collectors: vec![crate::config::BmpCollector {
            address: "192.0.2.254:11019".into(),
            reconnect_interval: 30,
            monitor: vec![crate::config::BmpMonitorView::LocRib],
            version: 3,
        }],
    });
}

async fn start_periodic_timer(commands: &mpsc::Sender<PeerManagerCommand>) {
    let (reply, started) = oneshot::channel();
    commands
        .send(PeerManagerCommand::Ping { reply })
        .await
        .unwrap();
    started.await.unwrap();
    // run() has consumed the immediate tick before it can acknowledge Ping.
    tokio::time::advance(Duration::from_secs(BMP_STATS_INTERVAL_SECS)).await;
    tokio::task::yield_now().await;
}

#[tokio::test(start_paused = true)]
async fn periodic_full_rib_queue_does_not_hold_reads_or_shutdown() {
    let (commands, command_rx) = mpsc::channel(4);
    let (operator, operator_rx) = mpsc::channel(4);
    let (readiness, readiness_rx) = mpsc::channel(4);
    let (rib_tx, mut rib_rx) = mpsc::channel(1);
    let (bmp_tx, mut bmp_rx) = mpsc::channel(4);
    let (reply, _blocker) = oneshot::channel();
    rib_tx
        .try_send(RibUpdate::QueryLocRibCount { reply })
        .unwrap();
    let mut manager = PeerManager::new(
        command_rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        BgpMetrics::new(),
        rib_tx,
        Some(bmp_tx),
    )
    .with_operator_queries(operator_rx)
    .with_readiness_queries(readiness_rx);
    enable_loc_rib_stats(&mut manager);
    let mut actor = tokio::spawn(manager.run());
    start_periodic_timer(&commands).await;
    // Even with no peers the old peer-RIB stage spends 100 ms first, then
    // the Loc-RIB admission waits indefinitely on the still-full mailbox.
    tokio::time::advance(Duration::from_millis(125)).await;
    let (reply, ping) = oneshot::channel();
    readiness
        .send(PeerManagerReadinessQuery::Ping { reply })
        .await
        .unwrap();
    let (reply, read) = oneshot::channel();
    operator
        .send(PeerManagerOperatorQuery::ListPeers { reply }.into())
        .await
        .unwrap();
    let (ping, read) = tokio::join!(
        tokio::time::timeout(Duration::from_millis(200), ping),
        tokio::time::timeout(Duration::from_secs(2), read),
    );
    let readiness_returned = matches!(ping, Ok(Ok(())));
    let operator_returned = matches!(read, Ok(Ok(peers)) if peers.is_empty());
    commands.send(PeerManagerCommand::Shutdown).await.unwrap();
    let shutdown = tokio::time::timeout(Duration::from_millis(200), &mut actor).await;
    let shutdown_returned = matches!(shutdown, Ok(Ok(())));
    assert!(matches!(
        rib_rx.recv().await,
        Some(RibUpdate::QueryLocRibCount { .. })
    ));
    let late_query = match tokio::time::timeout(Duration::from_millis(1), rib_rx.recv()).await {
        Ok(Some(RibUpdate::QueryBmpLocRibStats { reply })) => {
            drop(reply);
            true
        }
        Ok(None) | Err(_) => false,
        _ => panic!("unexpected RIB query after sampling expired"),
    };
    if !shutdown_returned {
        tokio::time::timeout(Duration::from_secs(1), actor)
            .await
            .unwrap()
            .unwrap();
    }
    assert!(
        bmp_rx.try_recv().is_err(),
        "failed sampling must omit the Loc-RIB event"
    );
    println!(
        "full RIB: readiness={readiness_returned}, operator={operator_returned}, shutdown={shutdown_returned}, late_query={late_query}"
    );
    assert!(
        readiness_returned && operator_returned && shutdown_returned,
        "periodic sampling held actor dispatch until the RIB queue was released"
    );
    assert!(
        !late_query,
        "expired sampling must not enter newly available RIB capacity"
    );
}

#[tokio::test(start_paused = true)]
async fn periodic_independent_inputs_do_not_stack_readiness_waits() {
    let peer = "192.0.2.1".parse().unwrap();
    let (session_tx, mut session_rx) = mpsc::channel(4);
    let (sample_started, sample_started_rx) = oneshot::channel();
    let session = tokio::spawn(async move {
        let mut sample_started = Some(sample_started);
        let mut held = Vec::new();
        while let Some(command) = session_rx.recv().await {
            match command {
                PeerCommand::QueryState { .. } => {
                    if let Some(started) = sample_started.take() {
                        let _ = started.send(());
                    }
                    held.push(command);
                }
                PeerCommand::Shutdown => break,
                _ => {}
            }
        }
        Ok(())
    });
    let (commands, command_rx) = mpsc::channel(4);
    let (operator, operator_rx) = mpsc::channel(4);
    let (readiness, readiness_rx) = mpsc::channel(4);
    let (rib_tx, mut rib_rx) = mpsc::channel(4);
    let (bmp_tx, mut bmp_rx) = mpsc::channel(4);
    let rib = tokio::spawn(async move {
        let mut held = Vec::new();
        while let Some(update) = rib_rx.recv().await {
            held.push(update);
        }
        assert_eq!(held.len(), 2, "one peer and one Loc-RIB sample per tick");
    });
    let mut manager = PeerManager::new(
        command_rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        BgpMetrics::new(),
        rib_tx,
        Some(bmp_tx),
    )
    .with_operator_queries(operator_rx)
    .with_readiness_queries(readiness_rx);
    enable_loc_rib_stats(&mut manager);
    insert_test_managed_peer(
        &mut manager,
        peer,
        PeerHandle::from_parts(session_tx, session),
        false,
    );
    let actor = tokio::spawn(manager.run());
    start_periodic_timer(&commands).await;
    sample_started_rx.await.unwrap();
    let started = tokio::time::Instant::now();
    let (reply, ping) = oneshot::channel();
    readiness
        .send(PeerManagerReadinessQuery::Ping { reply })
        .await
        .unwrap();
    let (reply, read) = oneshot::channel();
    operator
        .send(
            PeerManagerOperatorQuery::HasPeerAddress {
                address: peer,
                reply,
            }
            .into(),
        )
        .await
        .unwrap();
    let (ping, read) = tokio::join!(
        tokio::time::timeout(Duration::from_millis(200), ping),
        tokio::time::timeout(Duration::from_millis(200), read),
    );
    let readiness_returned = matches!(ping, Ok(Ok(())));
    let operator_returned = matches!(read, Ok(Ok(true)));
    let elapsed = started.elapsed();
    // Reap the old implementation after its three bounded waits too, so
    // a red assertion measures dispatch rather than leaving tasks behind.
    commands.send(PeerManagerCommand::Shutdown).await.unwrap();
    tokio::time::timeout(Duration::from_secs(1), actor)
        .await
        .unwrap()
        .unwrap();
    rib.await.unwrap();
    assert!(
        bmp_rx.try_recv().is_err(),
        "held inputs must not manufacture reports"
    );
    println!(
        "held inputs: readiness={readiness_returned}, operator={operator_returned}, wait={elapsed:?}"
    );
    assert!(
        readiness_returned && operator_returned,
        "three independent sampling inputs stacked beyond the 200 ms readiness budget"
    );
    assert_eq!(
        elapsed, PEER_QUERY_TIMEOUT,
        "sampling input waits must overlap"
    );
}

#[tokio::test(start_paused = true)]
async fn loc_rib_admission_and_reply_share_one_sampling_deadline() {
    let (rib_tx, mut rib_rx) = mpsc::channel(1);
    let (reply, _blocker) = oneshot::channel();
    rib_tx
        .try_send(RibUpdate::QueryLocRibCount { reply })
        .unwrap();
    let mut manager = test_peer_manager();
    manager.rib_tx = rib_tx;
    enable_loc_rib_stats(&mut manager);
    let rib = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(60)).await;
        assert!(matches!(
            rib_rx.recv().await,
            Some(RibUpdate::QueryLocRibCount { .. })
        ));
        let Some(RibUpdate::QueryBmpLocRibStats { reply }) = rib_rx.recv().await else {
            panic!("Loc-RIB query must be admitted with 40 ms remaining");
        };
        tokio::time::sleep(Duration::from_millis(100)).await;
        drop(reply);
    });
    let started = tokio::time::Instant::now();
    assert!(manager.query_bmp_loc_rib_stats().await.is_none());
    assert_eq!(
        started.elapsed(),
        PEER_QUERY_TIMEOUT,
        "Loc-RIB reply may use only the admission deadline remainder"
    );
    rib.abort();
    assert!(rib.await.unwrap_err().is_cancelled());
}

#[tokio::test(start_paused = true)]
async fn loc_rib_sampling_preserves_disabled_and_unavailable_omission() {
    let (rib_tx, mut rib_rx) = mpsc::channel(1);
    let mut manager = test_peer_manager();
    manager.rib_tx = rib_tx;
    assert!(manager.query_bmp_loc_rib_stats().await.is_none());
    enable_loc_rib_stats(&mut manager);
    manager.current_config.bmp.as_mut().unwrap().collectors[0].monitor =
        vec![crate::config::BmpMonitorView::RibInPre];
    assert!(manager.query_bmp_loc_rib_stats().await.is_none());
    assert!(
        matches!(rib_rx.try_recv(), Err(mpsc::error::TryRecvError::Empty)),
        "disabled Loc-RIB monitoring must not query the RIB"
    );
    enable_loc_rib_stats(&mut manager);
    let rib = tokio::spawn(async move {
        let Some(RibUpdate::QueryBmpLocRibStats { reply }) = rib_rx.recv().await else {
            panic!("enabled monitoring must query the RIB");
        };
        drop(reply);
    });
    assert!(
        manager.query_bmp_loc_rib_stats().await.is_none(),
        "dropped reply is unavailable"
    );
    rib.await.unwrap();
    assert!(
        manager.query_bmp_loc_rib_stats().await.is_none(),
        "closed channel is unavailable"
    );
}

fn bmp_drop_count(metrics: &BgpMetrics, family_name: &str, labels: &[(&str, &str)]) -> f64 {
    for family in metrics.registry().gather() {
        if family.name() != family_name {
            continue;
        }
        for metric in family.get_metric() {
            if labels.iter().all(|(name, value)| {
                metric
                    .get_label()
                    .iter()
                    .any(|label| label.name() == *name && label.value() == *value)
            }) {
                return metric.get_counter().value();
            }
        }
    }
    0.0
}

#[expect(
    clippy::too_many_lines,
    reason = "one output matrix keeps sampling inputs, report order, drop counters, and cleanup together"
)]
#[tokio::test(start_paused = true)]
async fn periodic_reports_preserve_order_selection_and_output_drop_counters() {
    for output in ["open", "full", "closed"] {
        let peer: IpAddr = "192.0.2.1".parse().unwrap();
        let idle: IpAddr = "192.0.2.2".parse().unwrap();
        let (rib_tx, mut rib_rx) = mpsc::channel(4);
        let (bmp_tx, bmp_rx) = mpsc::channel(if output == "open" { 4 } else { 1 });
        let mut bmp_rx = Some(bmp_rx);
        if output == "full" {
            bmp_tx
                .try_send(BmpEvent::LocRibStats {
                    per_family: vec![(1, 1, 999)],
                })
                .unwrap();
        } else if output == "closed" {
            drop(bmp_rx.take());
        }
        let mut manager = test_peer_manager();
        manager.rib_tx = rib_tx;
        manager.bmp_tx = Some(bmp_tx);
        enable_loc_rib_stats(&mut manager);
        let established_queries = Arc::new(FakePeerCounters::default());
        let idle_queries = Arc::new(FakePeerCounters::default());
        insert_test_managed_peer(
            &mut manager,
            peer,
            fake_peer_handle(
                peer,
                SessionState::Established,
                None,
                Arc::clone(&established_queries),
            ),
            false,
        );
        insert_test_managed_peer(
            &mut manager,
            idle,
            fake_peer_handle(idle, SessionState::Idle, None, Arc::clone(&idle_queries)),
            false,
        );
        let rib = tokio::spawn(async move {
            let mut peer_queries = 0;
            let mut loc_queries = 0;
            while let Some(update) = rib_rx.recv().await {
                match update {
                    RibUpdate::QueryBmpPeerStats { reply } => {
                        peer_queries += 1;
                        let _ = reply.send(rustbgpd_rib::BmpPeerStats {
                            adj_rib_out_post: HashMap::from([(
                                peer,
                                vec![((Afi::Ipv4, Safi::Unicast), 7)],
                            )]),
                            rpki_adj_rib_in_post: None,
                        });
                    }
                    RibUpdate::QueryBmpLocRibStats { reply } => {
                        loc_queries += 1;
                        let _ = reply.send(vec![(1, 1, 42)]);
                    }
                    _ => panic!("unexpected RIB input during statistics sampling"),
                }
            }
            assert_eq!((peer_queries, loc_queries), (1, 1));
        });
        tokio::time::timeout(PEER_QUERY_TIMEOUT, manager.emit_periodic_bmp_stats())
            .await
            .expect("BMP output backpressure must not await capacity");
        assert_eq!(established_queries.query_state.load(Ordering::SeqCst), 1);
        assert_eq!(idle_queries.query_state.load(Ordering::SeqCst), 1);
        if output == "open" {
            let receiver = bmp_rx.as_mut().unwrap();
            assert!(
                matches!(receiver.try_recv(), Ok(BmpEvent::LocRibStats { per_family })
                if per_family == vec![(1, 1, 42)]),
                "Loc-RIB report precedes per-peer reports"
            );
            assert!(matches!(receiver.try_recv(), Ok(BmpEvent::StatsReport {
                peer_info, adj_rib_in_routes: 0, adj_rib_out_post: Some(counts), ..
            }) if peer_info.peer_addr == peer && counts == vec![(1, 1, 7)]));
            assert!(
                receiver.try_recv().is_err(),
                "Idle peers do not emit a report"
            );
        } else {
            let reason = if output == "full" {
                "channel_full"
            } else {
                "channel_closed"
            };
            assert!(
                (bmp_drop_count(
                    &manager.metrics,
                    "bmp_loc_rib_source_drops_total",
                    &[("event", "stats"), ("reason", reason)]
                ) - 1.0)
                    .abs()
                    < f64::EPSILON
            );
            assert!(
                (bmp_drop_count(
                    &manager.metrics,
                    "bmp_source_drops_total",
                    &[("peer", "192.0.2.1"), ("reason", reason)]
                ) - 1.0)
                    .abs()
                    < f64::EPSILON
            );
            assert!(
                bmp_drop_count(
                    &manager.metrics,
                    "bmp_source_drops_total",
                    &[("peer", "192.0.2.2"), ("reason", reason)]
                )
                .abs()
                    < f64::EPSILON
            );
            if let Some(receiver) = bmp_rx.as_mut() {
                assert!(
                    matches!(receiver.try_recv(), Ok(BmpEvent::LocRibStats { per_family })
                    if per_family == vec![(1, 1, 999)])
                );
                assert!(
                    receiver.try_recv().is_err(),
                    "failed sends must leave output untouched"
                );
            }
        }
        for (_, managed) in manager.peers.drain() {
            managed.handle.shutdown().await.unwrap().unwrap();
        }
        drop(manager);
        rib.await.unwrap();
    }
}
