use std::time::Duration;

use super::tests::{collector_addr, sample_peer_info};
use super::*;
use crate::{BmpPeerInfo, BmpReplay};

fn outbound_filter() -> BmpMonitorFilter {
    BmpMonitorFilter {
        rib_in_pre: false,
        rib_out_post: true,
        loc_rib: false,
    }
}

fn manager(filters: &[(BmpMonitorFilter, BmpVersion)]) -> (BmpManager, Vec<mpsc::Receiver<Bytes>>) {
    let (_event_tx, event_rx) = mpsc::channel(8);
    let (_control_tx, control_rx) = mpsc::channel(8);
    let mut receivers = Vec::new();
    let collectors = filters
        .iter()
        .enumerate()
        .map(|(index, &(filter, version))| {
            let (sender, receiver) = mpsc::channel(16);
            receivers.push(receiver);
            (
                collector_addr(u16::try_from(index).unwrap()),
                sender,
                filter,
                version,
            )
        })
        .collect();
    (
        BmpManager::new_connected_for_test(event_rx, control_rx, collectors, BgpMetrics::new()),
        receivers,
    )
}

fn peer_up() -> BmpEvent {
    BmpEvent::PeerUp {
        peer_info: sample_peer_info(),
        local_open: Bytes::from_static(&[0xFF; 29]),
        remote_open: Bytes::from_static(&[0xFE; 29]),
        local_addr: "10.0.0.1".parse().unwrap(),
        local_port: 179,
        remote_port: 54321,
    }
}

fn outbound_info() -> BmpPeerInfo {
    let mut info = sample_peer_info();
    info.is_rib_out = true;
    info.is_post_policy = true;
    info
}

fn eor() -> Bytes {
    let mut bytes = vec![0xff; 16];
    bytes.extend_from_slice(&[0, 23, 2, 0, 0, 0, 0]);
    bytes.into()
}

async fn begin(manager: &mut BmpManager, replay: &Arc<BmpReplay>) {
    manager
        .handle_event(&BmpEvent::OutboundReplayBegin {
            peer_info: outbound_info(),
            replay: Arc::clone(replay),
        })
        .await;
}

async fn complete(manager: &mut BmpManager, replay: &Arc<BmpReplay>) {
    manager
        .handle_event(&BmpEvent::OutboundReplayComplete {
            peer_info: outbound_info(),
            replay: Arc::clone(replay),
            end_of_rib: vec![eor()],
        })
        .await;
}

#[tokio::test]
async fn explicit_replay_resets_only_outbound_collectors_and_preserves_v3_v4_framing() {
    let mixed = BmpMonitorFilter {
        rib_in_pre: true,
        ..outbound_filter()
    };
    let (mut manager, mut receivers) = manager(&[
        (outbound_filter(), BmpVersion::V3),
        (mixed, BmpVersion::V3),
        (outbound_filter(), BmpVersion::V4),
    ]);
    manager.handle_event(&peer_up()).await;
    let cached: Vec<_> = receivers
        .iter_mut()
        .map(|rx| rx.try_recv().unwrap())
        .collect();
    let (replay, enrolled) = BmpReplay::new(Duration::from_secs(5));
    begin(&mut manager, &replay).await;
    assert!(enrolled.await.unwrap());
    for index in [0, 2] {
        let reset = receivers[index].try_recv().unwrap();
        assert_eq!(reset[0], if index == 0 { 3 } else { 4 });
        assert_eq!(reset[5], 2, "Peer Down precedes cached Peer Up");
        assert_eq!(
            reset[48], 5,
            "Monitoring Stopped reason resets the baseline"
        );
        assert_eq!(
            reset[7] & 0x50,
            0,
            "synthetic session reset has no O/L flags"
        );
        assert_eq!(receivers[index].try_recv().unwrap(), cached[index]);
        assert!(
            receivers[index].try_recv().is_err(),
            "begin cannot claim completion"
        );
    }
    assert!(
        receivers[1].try_recv().is_err(),
        "mixed input/output baseline must not reset"
    );
    complete(&mut manager, &replay).await;
    let v3 = receivers[0].try_recv().unwrap();
    let v4 = receivers[2].try_recv().unwrap();
    assert_eq!((v3[0], v3[5], v3[7] & 0x50), (3, 0, 0x50));
    assert_eq!(&v3[48..], eor().as_ref());
    assert_eq!((v4[0], v4[5], v4[7] & 0x50), (4, 0, 0x50));
    assert_eq!(&v4[48..54], &[0, 4, 0, 23, 0, 0], "v4 BGP Message TLV");
    assert_eq!(&v4[54..], eor().as_ref());
    assert!(
        receivers[1].try_recv().is_err(),
        "mixed collector was never enrolled"
    );
}

#[tokio::test]
async fn explicit_replay_mixed_only_or_expired_request_has_no_reset_or_terminal() {
    for expired in [false, true] {
        let filter = if expired {
            outbound_filter()
        } else {
            BmpMonitorFilter {
                rib_in_pre: true,
                ..outbound_filter()
            }
        };
        let (mut manager, mut receivers) = manager(&[(filter, BmpVersion::V3)]);
        manager.handle_event(&peer_up()).await;
        receivers[0].try_recv().unwrap();
        let (replay, enrolled) = BmpReplay::new(if expired {
            Duration::ZERO
        } else {
            Duration::from_secs(5)
        });
        begin(&mut manager, &replay).await;
        assert!(!enrolled.await.unwrap());
        assert!(!replay.is_valid());
        complete(&mut manager, &replay).await;
        assert!(receivers[0].try_recv().is_err());
    }
}

#[tokio::test]
async fn explicit_replay_cancel_or_replaced_peer_up_suppresses_completion() {
    for replace_peer in [false, true] {
        let (mut manager, mut receivers) = manager(&[(outbound_filter(), BmpVersion::V3)]);
        manager.handle_event(&peer_up()).await;
        receivers[0].try_recv().unwrap();
        let (replay, enrolled) = BmpReplay::new(Duration::from_secs(5));
        begin(&mut manager, &replay).await;
        assert!(enrolled.await.unwrap());
        receivers[0].try_recv().unwrap();
        receivers[0].try_recv().unwrap();
        if replace_peer {
            manager.handle_event(&peer_up()).await;
            assert_eq!(receivers[0].try_recv().unwrap()[5], 3);
        } else {
            replay.cancel();
        }
        assert!(!replay.is_valid());
        complete(&mut manager, &replay).await;
        assert!(receivers[0].try_recv().is_err());
    }
}

#[tokio::test]
async fn explicit_replay_reconnect_suppresses_only_replaced_collector_generation() {
    let (mut manager, mut receivers) = manager(&[
        (outbound_filter(), BmpVersion::V3),
        (outbound_filter(), BmpVersion::V4),
    ]);
    manager.handle_event(&peer_up()).await;
    for receiver in &mut receivers {
        receiver.try_recv().unwrap();
    }
    let (replay, enrolled) = BmpReplay::new(Duration::from_secs(5));
    begin(&mut manager, &replay).await;
    assert!(enrolled.await.unwrap());
    for receiver in &mut receivers {
        receiver.try_recv().unwrap();
        receiver.try_recv().unwrap();
    }
    let (replacement_tx, mut replacement_rx) = mpsc::channel(16);
    let (bootstrap_tx, bootstrap_rx) = tokio::sync::oneshot::channel();
    manager.handle_collector_connected(0, collector_addr(0), replacement_tx, bootstrap_tx);
    let bootstrap = bootstrap_rx.await.unwrap();
    assert_eq!(bootstrap.messages.len(), 1);
    assert_eq!(
        bootstrap.messages[0][5], 3,
        "replacement gets current Peer Up only"
    );
    manager.handle_bootstrap_complete(0, bootstrap.generation);
    assert!(replay.is_valid(), "healthy sibling retains its enrollment");
    complete(&mut manager, &replay).await;
    assert!(
        replacement_rx.try_recv().is_err(),
        "new generation joined after replay began"
    );
    assert!(receivers[0].try_recv().is_err());
    let healthy = receivers[1].try_recv().unwrap();
    assert_eq!((healthy[0], healthy[5]), (4, 0));
    assert_eq!(&healthy[54..], eor().as_ref());
    assert!(receivers[1].try_recv().is_err());
}

#[tokio::test]
async fn explicit_replay_expiry_after_enrollment_suppresses_terminal() {
    let (mut manager, mut receivers) = manager(&[(outbound_filter(), BmpVersion::V3)]);
    manager.handle_event(&peer_up()).await;
    receivers[0].try_recv().unwrap();
    let (replay, enrolled) = BmpReplay::new(Duration::from_millis(100));
    begin(&mut manager, &replay).await;
    assert!(enrolled.await.unwrap());
    receivers[0].try_recv().unwrap();
    receivers[0].try_recv().unwrap();
    // BmpReplay deliberately uses a wall-clock deadline, independently of Tokio time.
    tokio::time::sleep(Duration::from_millis(120)).await;
    assert!(!replay.is_valid());
    complete(&mut manager, &replay).await;
    assert!(receivers[0].try_recv().is_err());
}

#[tokio::test]
async fn explicit_replay_reset_failure_rejects_without_survivors_and_keeps_healthy_collector() {
    for healthy in [false, true] {
        let filters = vec![(outbound_filter(), BmpVersion::V3); if healthy { 2 } else { 1 }];
        let (mut manager, mut receivers) = manager(&filters);
        manager.handle_event(&peer_up()).await;
        for receiver in &mut receivers {
            receiver.try_recv().unwrap();
        }
        // Down fits, but the matching Up does not: this generation is incomplete.
        let (sender, mut failed) = mpsc::channel(1);
        manager.collectors[0].phase = CollectorPhase::Active {
            generation: 1,
            sender,
            loc_rib_peer_up: false,
        };
        let (replay, enrolled) = BmpReplay::new(Duration::from_secs(5));
        begin(&mut manager, &replay).await;
        assert_eq!(enrolled.await.unwrap(), healthy);
        assert!(failed.try_recv().is_ok());
        assert!(failed.try_recv().is_err());
        complete(&mut manager, &replay).await;
        if healthy {
            let survivor = &mut receivers[1];
            assert_eq!(survivor.try_recv().unwrap()[5], 2);
            assert_eq!(survivor.try_recv().unwrap()[5], 3);
            assert_eq!(survivor.try_recv().unwrap()[5], 0);
            assert!(survivor.try_recv().is_err());
        } else {
            assert!(!replay.is_valid());
        }
    }
}
