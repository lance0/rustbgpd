//! A session task that ends without a shutdown request is restarted, and a
//! peer whose task keeps crashing is latched disabled.

use super::collision::{read_bgp_message, send_bgp_message};
use super::*;

use rustbgpd_rib::RibManager;
use rustbgpd_transport::{SessionIdentity, SessionTaskExitNotice, TransportError};
use rustbgpd_wire::{Afi, Safi};

use crate::peer_manager::notifications::{SESSION_CRASH_LATCH, SESSION_CRASH_WINDOW};

const PEER: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

fn injected_panic() -> Result<(), TransportError> {
    panic!("injected session panic")
}

/// A primary for `session_id` whose task panics when the returned sender
/// fires. Its exit notice is the one real session tasks carry.
fn crashing_primary(mgr: &PeerManager, session_id: u64) -> (PeerHandle, oneshot::Sender<()>) {
    let (command_tx, command_rx) = mpsc::channel(8);
    let (crash, crashed) = oneshot::channel::<()>();
    let exit = SessionTaskExitNotice::new(
        Some(mgr.session_notify_tx.clone()),
        SessionIdentity::primary(session_id),
        PEER,
    );
    let task = tokio::spawn(async move {
        let _exit = exit;
        let _commands = command_rx;
        let _ = crashed.await;
        injected_panic()
    });
    (PeerHandle::from_parts(command_tx, task), crash)
}

/// Make a crashing task `PEER`'s current primary and return its trigger.
fn install_crashing_primary(mgr: &mut PeerManager) -> oneshot::Sender<()> {
    let session_id = mgr.allocate_session_id();
    let (handle, crash) = crashing_primary(mgr, session_id);
    let (previous, previous_id) = mgr
        .peers
        .replace_handle(&key(PEER), handle, session_id)
        .unwrap();
    mgr.unregister_session(previous_id);
    mgr.register_session(session_id, &key(PEER));
    drop(previous);
    crash
}

/// Crash the current primary and handle its exit notice as the run loop does.
async fn crash_primary(mgr: &mut PeerManager, crash: oneshot::Sender<()>) {
    crash.send(()).unwrap();
    let notification = tokio::time::timeout(Duration::from_secs(5), mgr.session_notify_rx.recv())
        .await
        .expect("the crashed task reports its exit")
        .unwrap();
    assert!(
        matches!(&notification, SessionNotification::TaskExited { cause, .. } if cause == "panicked")
    );
    mgr.handle_session_notification(notification).await;
}

fn crash_count(mgr: &PeerManager) -> Option<f64> {
    mgr.metrics
        .registry()
        .gather()
        .into_iter()
        .find(|family| family.name() == "bgp_session_task_crashes_total")
        .and_then(|family| {
            family.get_metric().iter().find_map(|metric| {
                let labels: Vec<_> = metric
                    .get_label()
                    .iter()
                    .map(|label| (label.name(), label.value()))
                    .collect();
                (labels == [("interface", ""), ("peer", "127.0.0.1")])
                    .then(|| metric.get_counter().get_value())
            })
        })
}

/// Session starts and ends as the RIB receives them, in order.
#[derive(Debug, PartialEq, Eq)]
enum RibEvent {
    Up(u64),
    Down(u64),
}

/// A manager whose RIB lane is tapped in front of a running RIB.
fn manager_with_tapped_rib() -> (PeerManager, mpsc::UnboundedReceiver<RibEvent>) {
    let (tap_tx, mut tap_rx) = mpsc::channel::<RibUpdate>(64);
    let (rib_tx, rib_rx) = mpsc::channel(64);
    let (_query_tx, query_rx) = mpsc::channel(4);
    tokio::spawn(RibManager::new(rib_rx, query_rx, None, None, BgpMetrics::new()).run());
    let (events_tx, events_rx) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        while let Some(update) = tap_rx.recv().await {
            match &update {
                RibUpdate::PeerUp { session_id, .. } => {
                    let _ = events_tx.send(RibEvent::Up(*session_id));
                }
                RibUpdate::PeerDown { session_id, .. } => {
                    let _ = events_tx.send(RibEvent::Down(*session_id));
                }
                _ => {}
            }
            if rib_tx.send(update).await.is_err() {
                return;
            }
        }
    });
    let mgr = PeerManager::new(
        mpsc::channel(16).1,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        BgpMetrics::new(),
        tap_tx,
        None,
    );
    (mgr, events_rx)
}

/// A panicked primary is replaced and restarted: the replacement connects
/// and reaches Established, the RIB sees the dead session's `PeerDown`
/// before the new session's `PeerUp`, and the neighbor reports the crash.
/// Red proof: without the restart the replacement never connects; starting
/// the replacement before its predecessor's `PeerDown` is published lets
/// the new `PeerUp` overtake it.
#[tokio::test]
async fn panicked_primary_restarts_and_establishes_after_its_peer_down() {
    let (mut mgr, mut rib_events) = manager_with_tapped_rib();
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    insert_test_managed_peer(&mut mgr, PEER, closed_peer_handle(), false);
    mgr.peers
        .get_mut(&key(PEER))
        .unwrap()
        .transport_config
        .remote_addr = listener.local_addr().unwrap();
    mgr.next_session_id = 2;
    let crash = install_crashing_primary(&mut mgr);
    let crashed_id = mgr.peers[&key(PEER)].session_id();

    crash_primary(&mut mgr, crash).await;

    let managed = &mgr.peers[&key(PEER)];
    let restarted_id = managed.session_id();
    assert_ne!(restarted_id, crashed_id);
    assert!(managed.enabled);
    assert_eq!(crash_count(&mgr), Some(1.0));
    let info = mgr.get_peer_info(&key(PEER)).await.unwrap();
    assert!(
        info.last_error.contains("session task crashed")
            && info.last_error.contains("panicked: injected session panic")
            && info.last_error.contains("restarted"),
        "{}",
        info.last_error
    );

    let (mut client, _) = tokio::time::timeout(Duration::from_secs(5), listener.accept())
        .await
        .expect("the restarted session connects")
        .unwrap();
    let mut buf = BytesMut::new();
    assert!(matches!(
        read_bgp_message(&mut client, &mut buf).await,
        Message::Open(_)
    ));
    let open = OpenMessage {
        version: 4,
        my_as: 65002,
        hold_time: 90,
        bgp_identifier: Ipv4Addr::new(10, 0, 0, 2),
        capabilities: vec![
            Capability::MultiProtocol {
                afi: Afi::Ipv4,
                safi: Safi::Unicast,
            },
            Capability::FourOctetAs { asn: 65002 },
        ],
    };
    send_bgp_message(&mut client, &Message::Open(open)).await;
    assert!(matches!(
        read_bgp_message(&mut client, &mut buf).await,
        Message::Keepalive
    ));
    send_bgp_message(&mut client, &Message::Keepalive).await;

    let mut seen = Vec::new();
    while !seen.contains(&RibEvent::Up(restarted_id)) {
        let event = tokio::time::timeout(Duration::from_secs(5), rib_events.recv())
            .await
            .expect("the restarted session comes up")
            .unwrap();
        seen.push(event);
    }
    let down = seen
        .iter()
        .position(|event| *event == RibEvent::Down(crashed_id));
    let up = seen
        .iter()
        .position(|event| *event == RibEvent::Up(restarted_id));
    assert!(
        down.is_some_and(|down| Some(down) < up),
        "the dead session's PeerDown precedes the new PeerUp: {seen:?}"
    );
    assert!(mgr.peers[&key(PEER)].handle().is_established());
}

/// The third crash within the window latches the peer disabled instead of
/// restarting it, with a `last_error` naming the latch and its recovery.
/// Explicit enable clears the crash record.
/// Red proof: without the latch the third crash restarts the peer, so a
/// task that crashes on every session restarts forever.
#[tokio::test(start_paused = true)]
async fn repeated_crashes_latch_the_peer_until_enable() {
    let mut mgr = test_peer_manager();
    insert_test_managed_peer(&mut mgr, PEER, closed_peer_handle(), false);
    // Nothing listens on the restarted sessions' port.
    mgr.peers
        .get_mut(&key(PEER))
        .unwrap()
        .transport_config
        .remote_addr = SocketAddr::new(PEER, 9);
    mgr.next_session_id = 2;

    for crash in 1..SESSION_CRASH_LATCH {
        let trigger = install_crashing_primary(&mut mgr);
        crash_primary(&mut mgr, trigger).await;
        assert!(mgr.peers[&key(PEER)].enabled, "crash {crash} restarts");
        tokio::time::advance(Duration::from_secs(60)).await;
    }
    let trigger = install_crashing_primary(&mut mgr);
    crash_primary(&mut mgr, trigger).await;

    assert!(!mgr.peers[&key(PEER)].enabled, "the last crash latches");
    assert_eq!(
        crash_count(&mgr),
        Some(f64::from(u32::try_from(SESSION_CRASH_LATCH).unwrap()))
    );
    assert_eq!(
        peer_identity_gauge(&mgr.metrics, "bgp_peer_admin_enabled", "127.0.0.1", ""),
        Some(0.0)
    );
    let info = mgr.get_peer_info(&key(PEER)).await.unwrap();
    assert!(
        info.last_error.contains("latched disabled")
            && info.last_error.contains("rbgp neighbor 127.0.0.1 enable"),
        "{}",
        info.last_error
    );

    mgr.enable_peer(key(PEER)).await.unwrap();
    assert!(mgr.peers[&key(PEER)].enabled);
    assert!(mgr.peers[&key(PEER)].session_crashes().recent.is_empty());
    let info = mgr.get_peer_info(&key(PEER)).await.unwrap();
    assert!(!info.last_error.contains("session task crashed"));
}

/// A crash older than the window no longer counts toward the latch.
/// Red proof: never pruning the record latches on the third crash.
#[tokio::test(start_paused = true)]
async fn crashes_outside_the_window_do_not_latch() {
    let mut mgr = test_peer_manager();
    insert_test_managed_peer(&mut mgr, PEER, closed_peer_handle(), false);
    mgr.peers
        .get_mut(&key(PEER))
        .unwrap()
        .transport_config
        .remote_addr = SocketAddr::new(PEER, 9);
    mgr.next_session_id = 2;

    for _ in 0..=SESSION_CRASH_LATCH {
        let trigger = install_crashing_primary(&mut mgr);
        crash_primary(&mut mgr, trigger).await;
        assert!(mgr.peers[&key(PEER)].enabled);
        tokio::time::advance(SESSION_CRASH_WINDOW).await;
    }
}
