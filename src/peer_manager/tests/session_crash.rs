//! A session task that ends without a shutdown request is restarted, and a
//! peer whose task keeps crashing is latched disabled.

use super::collision::{read_bgp_message, send_bgp_message};
use super::*;

use rustbgpd_api::peer_types::{AdminDownReason, PeerInfo};
use rustbgpd_rib::RibManager;
use rustbgpd_transport::{SessionIdentity, SessionTaskExitNotice, TransportError};
use rustbgpd_wire::{Afi, Safi};

pub(super) use crate::peer_manager::notifications::SESSION_CRASH_LATCH;
use crate::peer_manager::notifications::SESSION_CRASH_WINDOW;

const PEER: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

fn injected_panic() -> Result<(), TransportError> {
    panic!("injected session panic")
}

/// A primary for `session_id` whose task panics when the returned sender
/// fires. Its exit notice is the one real session tasks carry.
fn crashing_primary(
    mgr: &PeerManager,
    session_id: u64,
    peer: IpAddr,
) -> (PeerHandle, oneshot::Sender<()>) {
    let (command_tx, command_rx) = mpsc::channel(8);
    let (crash, crashed) = oneshot::channel::<()>();
    let exit = SessionTaskExitNotice::new(
        Some(mgr.session_notify_tx.clone()),
        SessionIdentity::primary(session_id),
        peer,
    );
    let task = tokio::spawn(async move {
        let _exit = exit;
        let _commands = command_rx;
        let _ = crashed.await;
        injected_panic()
    });
    (PeerHandle::from_parts(command_tx, task), crash)
}

/// Make a crashing task `peer`'s current primary and return its trigger.
pub(super) fn install_crashing_primary(
    mgr: &mut PeerManager,
    peer: &PeerKey,
) -> oneshot::Sender<()> {
    let session_id = mgr.allocate_session_id();
    let (handle, crash) = crashing_primary(mgr, session_id, peer.address);
    let (previous, previous_id) = mgr.peers.replace_handle(peer, handle, session_id).unwrap();
    mgr.unregister_session(previous_id);
    mgr.register_session(session_id, peer);
    drop(previous);
    crash
}

/// Crash the current primary and return its exit notice.
async fn next_task_exit(mgr: &mut PeerManager, crash: oneshot::Sender<()>) -> SessionNotification {
    crash.send(()).unwrap();
    let notification = tokio::time::timeout(Duration::from_secs(5), mgr.session_notify_rx.recv())
        .await
        .expect("the crashed task reports its exit")
        .unwrap();
    assert!(
        matches!(&notification, SessionNotification::TaskExited { cause, .. } if cause == "panicked")
    );
    notification
}

/// Crash the current primary and handle its exit notice as the run loop does.
pub(super) async fn crash_primary(mgr: &mut PeerManager, crash: oneshot::Sender<()>) {
    let notification = next_task_exit(mgr, crash).await;
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

/// A test peer at `PEER` whose restarted sessions dial a closed port.
pub(super) fn manager_with_peer() -> PeerManager {
    let mut mgr = test_peer_manager();
    insert_test_managed_peer(&mut mgr, PEER, closed_peer_handle(), false);
    mgr.peers
        .get_mut(&key(PEER))
        .unwrap()
        .transport_config
        .remote_addr = SocketAddr::new(PEER, 9);
    mgr.next_session_id = 2;
    mgr
}

/// Session starts and ends as the RIB receives them, in order.
#[derive(Debug, PartialEq, Eq)]
enum RibEvent {
    Up(u64),
    Down(u64),
    LateDown(u64),
}

/// A manager whose one-slot RIB mailbox feeds a tap in front of the running
/// RIB, which forwards nothing until `release` fires. With `full`, the slot
/// already holds a query.
fn manager_with_rib_tap(
    full: bool,
) -> (
    PeerManager,
    mpsc::UnboundedReceiver<RibEvent>,
    oneshot::Sender<()>,
) {
    let (tap_tx, mut tap_rx) = mpsc::channel::<RibUpdate>(1);
    if full {
        let (reply, _) = oneshot::channel();
        tap_tx
            .try_send(RibUpdate::QueryLocRibCount { reply })
            .unwrap();
        assert_eq!(tap_tx.capacity(), 0);
    }
    let (release, released) = oneshot::channel::<()>();
    let (rib_tx, rib_rx) = mpsc::channel(64);
    let (_query_tx, query_rx) = mpsc::channel(4);
    tokio::spawn(RibManager::new(rib_rx, query_rx, None, None, BgpMetrics::new()).run());
    let (events_tx, events_rx) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        let _ = released.await;
        while let Some(update) = tap_rx.recv().await {
            match &update {
                RibUpdate::PeerUp { session_id, .. } => {
                    let _ = events_tx.send(RibEvent::Up(*session_id));
                }
                RibUpdate::PeerDown { session_id, .. } => {
                    let _ = events_tx.send(RibEvent::Down(*session_id));
                }
                RibUpdate::LateSessionEnd(end) => {
                    if let RibUpdate::PeerDown { session_id, .. } = end.as_ref() {
                        let _ = events_tx.send(RibEvent::LateDown(*session_id));
                    }
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
    (mgr, events_rx, release)
}

/// Bring the session that dialed `listener` to Established.
pub(super) async fn accept_and_establish(listener: &TcpListener) -> tokio::net::TcpStream {
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
    client
}

/// A panicked primary is replaced and restarted: the replacement connects
/// and reaches Established, the RIB receives the dead session's end, and the
/// neighbor reports the crash.
///
/// The RIB mailbox is full when the crash is handled, so the dead session's
/// `PeerDown` is deferred as a late end instead of waiting for room: a policy
/// walk serves this handler where its stall detector is not polled. The
/// replacement's `PeerUp` can then reach the RIB first.
/// Red proof: a `PeerDown` that waits for room keeps the handler from
/// returning while the RIB holds its mailbox.
#[tokio::test]
async fn panicked_primary_restarts_without_waiting_for_rib_mailbox_room() {
    let (mut mgr, mut rib_events, release) = manager_with_rib_tap(true);
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    insert_test_managed_peer(&mut mgr, PEER, closed_peer_handle(), false);
    mgr.peers
        .get_mut(&key(PEER))
        .unwrap()
        .transport_config
        .remote_addr = listener.local_addr().unwrap();
    mgr.next_session_id = 2;
    let crash = install_crashing_primary(&mut mgr, &key(PEER));
    let crashed_id = mgr.peers[&key(PEER)].session_id();
    let notification = next_task_exit(&mut mgr, crash).await;

    tokio::time::timeout(
        Duration::from_secs(5),
        mgr.handle_session_notification(notification),
    )
    .await
    .expect("the handler does not wait for mailbox room");
    assert!(
        matches!(
            mgr.deferred_rib.queue.back(),
            Some((_, RibUpdate::LateSessionEnd(end))) if matches!(
                end.as_ref(),
                RibUpdate::PeerDown { session_id, .. } if *session_id == crashed_id
            )
        ),
        "the dead session's PeerDown waits as a late end"
    );

    let restarted_id = mgr.peers[&key(PEER)].session_id();
    assert_ne!(restarted_id, crashed_id);
    assert!(mgr.peers[&key(PEER)].enabled);
    assert_eq!(crash_count(&mgr), Some(1.0));
    let info = mgr.get_peer_info(&key(PEER)).await.unwrap();
    assert!(
        info.last_error.contains("session task crashed")
            && info.last_error.contains("panicked: injected session panic")
            && info.last_error.contains("restarted"),
        "{}",
        info.last_error
    );

    release.send(()).unwrap();
    let _client = accept_and_establish(&listener).await;
    mgr.flush_deferred_rib_updates(OperatorReadAdmission::Served)
        .await
        .unwrap();
    let mut seen = Vec::new();
    while !(seen.contains(&RibEvent::Up(restarted_id))
        && seen.contains(&RibEvent::LateDown(crashed_id)))
    {
        let event = tokio::time::timeout(Duration::from_secs(5), rib_events.recv())
            .await
            .expect("the restarted session comes up and the dead one ends")
            .unwrap();
        seen.push(event);
    }
    assert!(
        !seen.contains(&RibEvent::Down(crashed_id)),
        "the dead session ends once, late: {seen:?}"
    );
    assert!(mgr.peers[&key(PEER)].handle().is_established());
}

/// With room in the RIB mailbox and nothing deferred, the dead session's
/// `PeerDown` is sent at once and plain, not marked late, so the RIB closes
/// that epoch authoritatively before the replacement's `PeerUp`.
/// Red proof: deferring it as a late end unconditionally gives
/// `[LateDown(2), Up(3)]`.
#[tokio::test]
async fn panicked_primary_with_mailbox_room_sends_a_plain_peer_down_first() {
    let (mut mgr, mut rib_events, release) = manager_with_rib_tap(false);
    release.send(()).unwrap();
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    insert_test_managed_peer(&mut mgr, PEER, closed_peer_handle(), false);
    mgr.peers
        .get_mut(&key(PEER))
        .unwrap()
        .transport_config
        .remote_addr = listener.local_addr().unwrap();
    mgr.next_session_id = 2;
    let crash = install_crashing_primary(&mut mgr, &key(PEER));
    let crashed_id = mgr.peers[&key(PEER)].session_id();
    let notification = next_task_exit(&mut mgr, crash).await;
    mgr.handle_session_notification(notification).await;
    assert!(mgr.deferred_rib.queue.is_empty());

    let restarted_id = mgr.peers[&key(PEER)].session_id();
    assert_ne!(restarted_id, crashed_id);
    let _client = accept_and_establish(&listener).await;
    let mut seen = Vec::new();
    while !seen.contains(&RibEvent::Up(restarted_id)) {
        let event = tokio::time::timeout(Duration::from_secs(5), rib_events.recv())
            .await
            .expect("the restarted session comes up")
            .unwrap();
        seen.push(event);
    }
    assert_eq!(
        seen,
        [RibEvent::Down(crashed_id), RibEvent::Up(restarted_id)]
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
    let mut mgr = manager_with_peer();

    for crash in 1..SESSION_CRASH_LATCH {
        let trigger = install_crashing_primary(&mut mgr, &key(PEER));
        crash_primary(&mut mgr, trigger).await;
        assert!(mgr.peers[&key(PEER)].enabled, "crash {crash} restarts");
        tokio::time::advance(Duration::from_secs(60)).await;
    }
    let trigger = install_crashing_primary(&mut mgr, &key(PEER));
    crash_primary(&mut mgr, trigger).await;

    assert!(!mgr.peers[&key(PEER)].enabled, "the last crash latches");
    assert!(mgr.session_crash_latched(&key(PEER)));
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
    assert!(!mgr.session_crash_latched(&key(PEER)));
    let info = mgr.get_peer_info(&key(PEER)).await.unwrap();
    assert!(!info.last_error.contains("session task crashed"));
}

/// A crash older than the window no longer counts toward the latch, and no
/// longer shows as the neighbor's error.
/// Red proof: never pruning the record latches on the third crash.
#[tokio::test(start_paused = true)]
async fn crashes_outside_the_window_do_not_latch() {
    let mut mgr = manager_with_peer();

    for _ in 0..=SESSION_CRASH_LATCH {
        let trigger = install_crashing_primary(&mut mgr, &key(PEER));
        crash_primary(&mut mgr, trigger).await;
        assert!(mgr.peers[&key(PEER)].enabled);
        tokio::time::advance(SESSION_CRASH_WINDOW).await;
    }
    assert_eq!(mgr.session_crash_error(&key(PEER)), None);
}

/// A new peer exports its crash counter at 0, so the first crash is an
/// `increase()`.
/// Red proof: without the seed the series is absent until the first crash.
#[tokio::test]
async fn new_peers_export_a_zero_crash_counter() {
    let mut mgr = test_peer_manager();
    mgr.add_peer(make_config(PEER, 65002), false).await.unwrap();
    assert_eq!(crash_count(&mgr), Some(0.0));
}

/// A reconfigure deletes and re-adds the peer: a latched peer stays
/// disabled and keeps the error that says why.
/// Red proof: dropping the crash record with the peer on a reconfigure
/// loses the error (and the latch).
#[tokio::test(start_paused = true)]
async fn a_reconfigure_keeps_the_crash_latch_and_its_error() {
    let mut mgr = test_peer_manager();
    let mut config = make_config(PEER, 65002);
    mgr.add_peer(config.clone(), false).await.unwrap();
    mgr.peers
        .get_mut(&key(PEER))
        .unwrap()
        .transport_config
        .remote_addr = SocketAddr::new(PEER, 9);
    for _ in 0..SESSION_CRASH_LATCH {
        let trigger = install_crashing_primary(&mut mgr, &key(PEER));
        crash_primary(&mut mgr, trigger).await;
    }
    assert!(!mgr.peers[&key(PEER)].enabled);

    config.hold_time = Some(45);
    mgr.reconfigure_peer(config).await.unwrap();

    assert_eq!(mgr.peers[&key(PEER)].hold_time, Some(45));
    assert!(!mgr.peers[&key(PEER)].enabled);
    assert!(mgr.session_crash_latched(&key(PEER)));
    let info = mgr.get_peer_info(&key(PEER)).await.unwrap();
    assert!(
        info.last_error.contains("latched disabled"),
        "{}",
        info.last_error
    );
}

/// A reconfigure that clears the configured `admin_down` asks for the peer
/// enabled; a crash latch still keeps it down, with its error.
/// Red proof: without the latch check in `add_peer_impl` the reconfigured
/// peer comes up enabled.
#[tokio::test(start_paused = true)]
async fn a_reconfigure_clearing_admin_down_keeps_a_crash_latched_peer_down() {
    let mut mgr = test_peer_manager();
    let mut config = make_config(PEER, 65002);
    config.admin_down = Some("maintenance".to_string());
    mgr.add_peer(config.clone(), false).await.unwrap();
    assert!(!mgr.peers[&key(PEER)].enabled);
    for _ in 0..SESSION_CRASH_LATCH {
        let trigger = install_crashing_primary(&mut mgr, &key(PEER));
        crash_primary(&mut mgr, trigger).await;
    }
    assert!(mgr.session_crash_latched(&key(PEER)));

    config.admin_down = None;
    mgr.reconfigure_peer(config).await.unwrap();

    assert!(mgr.peers[&key(PEER)].admin_down.is_none());
    assert!(!mgr.peers[&key(PEER)].enabled, "the crash latch holds");
    let info = mgr.get_peer_info(&key(PEER)).await.unwrap();
    assert!(
        info.last_error.contains("latched disabled"),
        "{}",
        info.last_error
    );
}

/// A dynamic peer is removed when its session ends and comes back as a new
/// peer on reconnect. Its crash record is the manager's, so the third crash
/// across reconnects latches it, and its retirement keeps it, disabled,
/// so the next accept from that address is refused.
/// Red proof: forgetting the record when the dynamic peer is retired lets
/// it reconnect and crash forever.
#[tokio::test(start_paused = true)]
async fn a_dynamic_peer_that_crashes_on_every_reconnect_is_latched() {
    let mut mgr = test_peer_manager();
    for crash in 1..=SESSION_CRASH_LATCH {
        // The remote reconnects: a new dynamic peer at the same address.
        insert_test_managed_peer(&mut mgr, PEER, closed_peer_handle(), false);
        mgr.peers.get_mut(&key(PEER)).unwrap().is_dynamic = true;
        mgr.dynamic_peer_count = 1;
        let trigger = install_crashing_primary(&mut mgr, &key(PEER));
        crash_primary(&mut mgr, trigger).await;
        if crash < SESSION_CRASH_LATCH {
            assert!(!mgr.peers.contains_key(&key(PEER)), "crash {crash} retires");
        }
        tokio::time::advance(Duration::from_secs(60)).await;
    }
    assert!(mgr.session_crash_latched(&key(PEER)));
    let managed = &mgr.peers[&key(PEER)];
    assert!(managed.is_dynamic && !managed.enabled, "kept, disabled");
    let kept_id = managed.session_id();
    assert_eq!(crash_count(&mgr), Some(1.0), "the retained peer's series");

    // The remote dials again: the retained, disabled peer refuses it.
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let listener_addr = listener.local_addr().unwrap();
    let client = tokio::spawn(async move { TcpStream::connect(listener_addr).await.unwrap() });
    let (server, remote) = listener.accept().await.unwrap();
    let mut client = client.await.unwrap();
    mgr.accept_inbound(server, remote, None, None).await;
    let mut buf = [0_u8; 64];
    let read = tokio::time::timeout(Duration::from_secs(2), client.read(&mut buf))
        .await
        .expect("the refused connection closes");
    assert!(matches!(read, Ok(0) | Err(_)), "{read:?}");
    let managed = &mgr.peers[&key(PEER)];
    assert!(!managed.enabled && managed.pending_inbound.is_none());
    assert_eq!(managed.session_id(), kept_id);
}

/// The crash latch is final until enable: it retires a pending inbound
/// candidate instead of leaving it for promotion, and cancels an armed
/// max-prefix restart that would otherwise enable the peer.
/// Red proof: leaving the candidate attached keeps `pending_inbound`;
/// leaving the restart armed keeps its deadline.
#[tokio::test(start_paused = true)]
async fn the_crash_latch_retires_a_candidate_and_cancels_a_max_prefix_restart() {
    let mut mgr = manager_with_peer();
    for _ in 1..SESSION_CRASH_LATCH {
        let trigger = install_crashing_primary(&mut mgr, &key(PEER));
        crash_primary(&mut mgr, trigger).await;
    }
    mgr.install_max_prefix_latch(key(PEER), 0, "max-prefix limit exceeded".into(), Some(30));
    let candidate = Arc::new(FakePeerCounters::default());
    let candidate_id = mgr.allocate_session_id();
    mgr.peers.get_mut(&key(PEER)).unwrap().pending_inbound = Some(PendingInbound {
        recovery_reset: None,
        handle: fake_peer_handle(PEER, SessionState::OpenConfirm, None, candidate.clone()),
        session_id: candidate_id,
    });
    mgr.register_session(candidate_id, &key(PEER));

    let trigger = install_crashing_primary(&mut mgr, &key(PEER));
    crash_primary(&mut mgr, trigger).await;

    let managed = &mgr.peers[&key(PEER)];
    assert!(!managed.enabled);
    assert!(managed.pending_inbound.is_none(), "candidate retired");
    assert_eq!(candidate.shutdown.load(Ordering::SeqCst), 1);
    assert!(mgr.peer_key_for_session(candidate_id).is_none());
    assert!(
        mgr.max_prefix_latches[&key(PEER)].deadline.is_none(),
        "the max-prefix restart is canceled"
    );
}

/// A disabled dynamic peer is kept idle when its session ends. A crashed
/// one gets a live replacement, so a later enable has a session to start.
/// Red proof: handling it as `BackToIdle` keeps the dead handle.
#[tokio::test]
async fn a_crashed_disabled_dynamic_peer_keeps_a_live_session() {
    let mut mgr = manager_with_peer();
    let managed = mgr.peers.get_mut(&key(PEER)).unwrap();
    managed.is_dynamic = true;
    managed.enabled = false;
    let trigger = install_crashing_primary(&mut mgr, &key(PEER));
    let crashed_id = mgr.peers[&key(PEER)].session_id();
    crash_primary(&mut mgr, trigger).await;

    let managed = &mgr.peers[&key(PEER)];
    assert_ne!(managed.session_id(), crashed_id);
    assert!(!managed.enabled);
    assert!(!managed.handle().commands_sender().is_closed());
}

/// A max-prefix hold-down armed after the crash latch, for example by the
/// breach notice of the primary the latch is stopping, expires into
/// nothing: the crash latch holds until explicit enable.
/// Red proof: without the crash-latch check the hold-down's expiry
/// re-enables and restarts the peer.
#[tokio::test(start_paused = true)]
async fn a_max_prefix_restart_leaves_a_crash_latched_peer_down() {
    let mut mgr = manager_with_peer();
    mgr.peers
        .get_mut(&key(PEER))
        .unwrap()
        .max_prefix_restart_seconds = Some(30);
    for _ in 0..SESSION_CRASH_LATCH {
        let trigger = install_crashing_primary(&mut mgr, &key(PEER));
        crash_primary(&mut mgr, trigger).await;
    }
    assert!(mgr.session_crash_latched(&key(PEER)));
    mgr.install_max_prefix_latch(key(PEER), 0, "max-prefix limit exceeded".into(), Some(30));
    // The crash latch's error names the recovery the neighbor waits for,
    // and the admin state names the same owner.
    // Mutation-red: applying the max-prefix owner last reads MaxPrefixLatched.
    let info = mgr.get_peer_info(&key(PEER)).await.unwrap();
    assert!(
        info.last_error.contains("latched disabled"),
        "{}",
        info.last_error
    );
    assert_eq!(
        info.admin_down_reason,
        Some(rustbgpd_api::peer_types::AdminDownReason::SessionCrashLatched)
    );
    // Nothing promises the restart the crash latch refuses.
    // Mutation-red: keeping the countdown reports Some(..) and "restart".
    assert_eq!(
        (
            info.max_prefix_restart_remaining_millis,
            info.max_prefix_action.as_str()
        ),
        (None, "shutdown")
    );

    tokio::time::advance(Duration::from_secs(31)).await;
    mgr.handle_due_max_prefix_restarts().await;

    assert!(!mgr.peers[&key(PEER)].enabled, "the crash latch holds");
    assert!(mgr.session_crash_latched(&key(PEER)));
}

/// `PEER`'s administrative owner as each neighbor read reports it:
/// `GetNeighborState`, the in-place `ListNeighbors` and the detached one.
async fn admin_owners(mgr: &mut PeerManager) -> [Option<AdminDownReason>; 3] {
    let single = mgr.get_peer_info(&key(PEER)).await.unwrap();
    let listed = mgr.list_peers().await;
    if mgr.operator_rx.is_none() {
        let (_operator_tx, operator_rx) = mpsc::channel(4);
        mgr.operator_rx = Some(operator_rx);
    }
    let (reply, detached) = oneshot::channel();
    assert!(mgr.detach_list_peers(reply).is_ok(), "detached");
    let detached = detached.await.unwrap();
    let row = |infos: &[PeerInfo]| {
        infos
            .iter()
            .find(|info| info.address == PEER)
            .unwrap()
            .admin_down_reason
    };
    [single.admin_down_reason, row(&listed), row(&detached)]
}

/// The crash latch is its own administrative owner on every neighbor read:
/// set by the latching crash, kept through an explicit disable, cleared by
/// enable. Crashes that have not latched leave an operator disable as the
/// owner.
/// Red proof: without the overlay's owner the latched reads say Operator.
#[tokio::test(start_paused = true)]
async fn a_crash_latched_peer_reports_its_own_admin_state() {
    use AdminDownReason::{Operator, SessionCrashLatched};
    let mut mgr = manager_with_peer();
    for _ in 1..SESSION_CRASH_LATCH {
        let trigger = install_crashing_primary(&mut mgr, &key(PEER));
        crash_primary(&mut mgr, trigger).await;
    }
    assert_eq!(admin_owners(&mut mgr).await, [None; 3]);
    mgr.disable_peer(key(PEER), None).await.unwrap();
    assert_eq!(
        admin_owners(&mut mgr).await,
        [Some(Operator); 3],
        "unlatched crashes do not own the hold"
    );

    let mut mgr = manager_with_peer();
    for _ in 0..SESSION_CRASH_LATCH {
        let trigger = install_crashing_primary(&mut mgr, &key(PEER));
        crash_primary(&mut mgr, trigger).await;
    }
    assert!(mgr.session_crash_latched(&key(PEER)));
    assert_eq!(admin_owners(&mut mgr).await, [Some(SessionCrashLatched); 3]);
    mgr.disable_peer(key(PEER), None).await.unwrap();
    assert_eq!(
        admin_owners(&mut mgr).await,
        [Some(SessionCrashLatched); 3],
        "an explicit disable keeps the latch"
    );

    mgr.enable_peer(key(PEER)).await.unwrap();
    assert_eq!(admin_owners(&mut mgr).await, [None; 3]);
}
