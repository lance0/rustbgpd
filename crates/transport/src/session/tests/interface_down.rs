//! Fast external failover: `PeerCommand::CheckLinks` judges the session's own
//! connections against the current link snapshot.

use super::*;
use crate::link::{InterfaceAddress, LinkDownCause, LinkSnapshot, LinkState, LinkStateFeed};
use std::collections::BTreeMap;
use tokio::sync::watch;

/// Interface `ifindex` with the given flags, holding each local address in
/// 127.0.0.0/8 (so a loopback peer is "directly connected" through it).
fn iface(ifindex: u32, admin_up: bool, lower_up: bool, locals: &[&str]) -> LinkSnapshot {
    LinkSnapshot {
        valid: true,
        links: BTreeMap::from([(
            ifindex,
            LinkState {
                name: format!("test{ifindex}"),
                admin_up,
                lower_up,
            },
        )]),
        addresses: BTreeMap::from([(
            ifindex,
            locals
                .iter()
                .map(|local| InterfaceAddress {
                    local: local.parse().unwrap(),
                    prefix: "127.0.0.0".parse().unwrap(),
                    prefix_len: 8,
                })
                .collect(),
        )]),
    }
}

fn merge(a: LinkSnapshot, b: LinkSnapshot) -> LinkSnapshot {
    let mut out = a;
    out.links.extend(b.links);
    out.addresses.extend(b.addresses);
    out
}

fn healthy() -> LinkSnapshot {
    iface(1, true, true, &["127.0.0.1"])
}

fn feed(initial: LinkSnapshot) -> (watch::Sender<Arc<LinkSnapshot>>, LinkStateFeed) {
    let (tx, rx) = watch::channel(Arc::new(initial));
    (tx, LinkStateFeed::new(rx, true))
}

async fn check(session: &mut PeerSession) {
    assert_eq!(
        session.handle_command(PeerCommand::CheckLinks).await,
        ControlFlow::Continue(())
    );
}

/// A client stream from `local` to a listener on 127.0.0.1.
async fn stream_from(local: &str) -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let socket = tokio::net::TcpSocket::new_v4().unwrap();
    socket.bind(format!("{local}:0").parse().unwrap()).unwrap();
    let (client, server) = tokio::join!(socket.connect(addr), listener.accept());
    (client.unwrap(), server.unwrap().0)
}

fn retain_gr(session: &mut PeerSession) {
    let negotiated = Arc::make_mut(session.negotiated.as_mut().expect("negotiated"));
    negotiated.peer_gr_capable = true;
    negotiated.peer_restart_time = 120;
    negotiated.peer_gr_families = vec![rustbgpd_wire::GracefulRestartFamily {
        afi: Afi::Ipv4,
        safi: Safi::Unicast,
        forwarding_preserved: false,
    }];
}

/// An Established eBGP session from 127.0.0.1 whose peer advertised Graceful
/// Restart, so an ordinary transport loss would retain its routes.
async fn established_gr_session(
    initial: LinkSnapshot,
) -> (
    PeerSession,
    TcpStream,
    mpsc::Receiver<RibUpdate>,
    watch::Sender<Arc<LinkSnapshot>>,
) {
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    let (tx, feed) = feed(initial);
    session.config.link_state = feed;
    session.config.peer.graceful_restart = true;
    let (client, server) = connected_stream_pair().await;
    session.test_install_stream(client);
    establish_test_session(&mut session, 65002).await;
    retain_gr(&mut session);
    while rib_rx.try_recv().is_ok() {}
    (session, server, rib_rx, tx)
}

fn set(tx: &watch::Sender<Arc<LinkSnapshot>>, snapshot: LinkSnapshot) {
    tx.send_replace(Arc::new(snapshot));
}

#[tokio::test]
async fn each_down_cause_in_the_current_state_tears_down() {
    let removed = LinkSnapshot {
        valid: true,
        ..LinkSnapshot::default()
    };
    for (cause, state) in [
        (
            LinkDownCause::CarrierLost,
            iface(1, true, false, &["127.0.0.1"]),
        ),
        (
            LinkDownCause::AdminDown,
            iface(1, false, false, &["127.0.0.1"]),
        ),
        (LinkDownCause::InterfaceRemoved, removed),
        (LinkDownCause::AddressRemoved, iface(1, true, true, &[])),
    ] {
        let (mut session, mut server, mut rib_rx, tx) = established_gr_session(healthy()).await;
        set(&tx, state);
        check(&mut session).await;

        assert_eq!(session.fsm.state(), SessionState::Idle, "{cause:?}");
        match rib_rx.try_recv() {
            Ok(RibUpdate::PeerDown { peer, .. }) => assert_eq!(peer, session.rib_peer()),
            Ok(RibUpdate::PeerGracefulRestart { .. }) => {
                panic!("{cause:?}: routes retained under GR after an interface down")
            }
            _ => panic!("{cause:?}: expected PeerDown"),
        }
        assert!(
            session.reconnect_timer.is_some(),
            "{cause:?}: a failover stop is not an operator stop; the session must reconnect"
        );
        assert!(
            session
                .last_error
                .starts_with("fast external failover: interface ")
                && session.last_error.ends_with(cause.as_str()),
            "{cause:?}: distinct teardown cause, got {:?}",
            session.last_error
        );
        assert!(!session.suppress_gr_retention, "latch is per teardown");

        // No NOTIFICATION reaches the wire: the peer sees only the close.
        let mut rest = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(2), server.read_to_end(&mut rest)).await;
        let mut types = Vec::new();
        let mut at = 0;
        while at + 19 <= rest.len() {
            types.push(rest[at + 18]);
            at += usize::from(u16::from_be_bytes([rest[at + 16], rest[at + 17]])).max(19);
        }
        assert!(
            !types.contains(&3),
            "{cause:?}: fast external failover must not send a NOTIFICATION; saw types {types:?}"
        );
    }
}

#[tokio::test]
async fn interface_down_records_local_no_notification_down_reason() {
    let (mut session, _server, _rib_rx, tx) = established_gr_session(healthy()).await;
    set(&tx, iface(1, true, false, &["127.0.0.1"]));
    check(&mut session).await;
    let samples = counter_samples(&session.metrics, "bgp_session_down_total");
    assert!(
        samples.iter().any(|(labels, value)| {
            labels.get("reason").map(String::as_str) == Some("local_no_notification")
                && (*value - 1.0).abs() < f64::EPSILON
        }),
        "{samples:?}"
    );
}

/// Unknown is not down: an invalid snapshot (before the first dump, after an
/// overrun, or after a failed re-dump) never stops a session, even when its
/// stale contents look down or empty.
#[tokio::test]
async fn an_invalid_snapshot_never_tears_down() {
    let (mut session, _server, mut rib_rx, tx) = established_gr_session(healthy()).await;
    let mut stale = iface(1, true, false, &[]);
    stale.valid = false;
    set(&tx, stale);
    check(&mut session).await;
    set(&tx, LinkSnapshot::default());
    check(&mut session).await;
    assert_eq!(session.fsm.state(), SessionState::Established);
    assert!(rib_rx.try_recv().is_err());
}

/// Level-triggered: a carrier bounce, or an address removed and re-added,
/// that completed before the check leaves the surviving session alone.
#[tokio::test]
async fn a_bounce_that_completed_before_the_check_is_not_down() {
    let (mut session, _server, mut rib_rx, tx) = established_gr_session(healthy()).await;
    set(&tx, iface(1, true, false, &["127.0.0.1"]));
    set(&tx, healthy());
    check(&mut session).await;
    set(&tx, iface(1, true, true, &[]));
    set(&tx, healthy());
    check(&mut session).await;
    assert_eq!(session.fsm.state(), SessionState::Established);
    assert!(rib_rx.try_recv().is_err());
}

#[tokio::test]
async fn a_down_interface_that_does_not_carry_the_session_is_ignored() {
    let (mut session, _server, mut rib_rx, tx) = established_gr_session(healthy()).await;
    set(&tx, merge(healthy(), iface(9, true, false, &["127.0.0.2"])));
    check(&mut session).await;
    assert_eq!(session.fsm.state(), SessionState::Established);
    assert!(rib_rx.try_recv().is_err());
    assert_eq!(session.last_error, "");
}

#[tokio::test]
async fn check_without_a_connection_is_a_no_op() {
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    session.config.link_state = feed(iface(1, true, false, &["127.0.0.1"])).1;
    check(&mut session).await;
    assert_eq!(session.fsm.state(), SessionState::Idle);
    assert!(rib_rx.try_recv().is_err());
    assert_eq!(session.last_error, "");
}

/// Control for the purge assertions: an ordinary transport loss keeps the GR
/// helper behavior.
#[tokio::test]
async fn ordinary_transport_loss_still_retains_under_gr() {
    let (mut session, _server, mut rib_rx, _tx) = established_gr_session(healthy()).await;
    session.handle_tcp_disconnect();
    session.drive_fsm(Event::TcpConnectionFails).await;
    assert!(matches!(
        rib_rx.try_recv(),
        Ok(RibUpdate::PeerGracefulRestart { .. })
    ));
}

/// TCP loss first (for example ENETUNREACH after the address goes), then the
/// check: routes already retained under GR are purged when the lost
/// connection's interface is down now, and only then.
#[tokio::test]
async fn retained_routes_are_purged_when_the_lost_connection_is_down() {
    let (mut session, _server, mut rib_rx, tx) = established_gr_session(healthy()).await;
    session.handle_tcp_disconnect();
    session.drive_fsm(Event::TcpConnectionFails).await;
    assert!(matches!(
        rib_rx.try_recv(),
        Ok(RibUpdate::PeerGracefulRestart { .. })
    ));
    check(&mut session).await;
    assert!(rib_rx.try_recv().is_err(), "link still up: keep retaining");

    set(&tx, iface(1, true, true, &[]));
    check(&mut session).await;
    match rib_rx.try_recv() {
        Ok(RibUpdate::PeerDown { peer, .. }) => assert_eq!(peer, session.rib_peer()),
        _ => panic!("expected the retained routes to be purged"),
    }
    assert!(session.gr_retained_connection.get().is_none());
    assert!(session.last_error.ends_with("local address removed"));
}

/// Failover during reconnect: the lost connection ran over interface 7, the
/// replacement (mid-handshake, `OpenSent`) over healthy interface 1. The
/// retained routes are purged and the replacement is untouched.
#[tokio::test]
async fn a_healthy_replacement_survives_while_retained_routes_are_purged() {
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    let both_up = merge(healthy(), iface(7, true, true, &["127.0.0.3"]));
    let (tx, feed) = feed(both_up);
    session.config.link_state = feed;
    session.config.peer.graceful_restart = true;
    let (lost, _lost_server) = stream_from("127.0.0.3").await;
    session.test_install_stream(lost);
    establish_test_session(&mut session, 65002).await;
    retain_gr(&mut session);
    while rib_rx.try_recv().is_ok() {}
    session.handle_tcp_disconnect();
    session.drive_fsm(Event::TcpConnectionFails).await;
    assert!(matches!(
        rib_rx.try_recv(),
        Ok(RibUpdate::PeerGracefulRestart { .. })
    ));

    let (replacement, _replacement_server) = stream_from("127.0.0.1").await;
    session.test_install_stream(replacement);
    session.drive_fsm(Event::ManualStart).await;
    assert_eq!(session.fsm.state(), SessionState::OpenSent);

    set(&tx, merge(healthy(), iface(7, true, false, &["127.0.0.3"])));
    check(&mut session).await;
    match rib_rx.try_recv() {
        Ok(RibUpdate::PeerDown { peer, .. }) => assert_eq!(peer, session.rib_peer()),
        _ => panic!("the retained routes must be purged while a replacement handshakes"),
    }
    assert!(session.read_half.is_some(), "the healthy replacement stays");
    assert_eq!(session.fsm.state(), SessionState::OpenSent);

    // A replacement on a link that is down now closes as well.
    set(&tx, iface(1, true, false, &["127.0.0.1"]));
    check(&mut session).await;
    assert!(session.read_half.is_none());
}

/// iBGP over a directly connected link is untouched, as is an accept-any
/// peer whose OPEN has not identified it yet or that negotiated the local
/// ASN; transport decides from the negotiated ASN.
#[tokio::test]
async fn ibgp_and_unidentified_peers_are_untouched() {
    let down = || feed(iface(1, true, false, &["127.0.0.1"])).1;

    let (mut ibgp, _rib_rx) = make_test_session_with_rib(65001, 65001);
    let (client, _server) = connected_stream_pair().await;
    ibgp.test_install_stream(client);
    establish_test_session(&mut ibgp, 65001).await;
    ibgp.config.link_state = down();
    check(&mut ibgp).await;
    assert_eq!(ibgp.fsm.state(), SessionState::Established);

    let (mut accept_any, _rib_rx) = make_test_session_with_rib(65001, 0);
    let (client, _server) = connected_stream_pair().await;
    accept_any.test_install_stream(client);
    accept_any.drive_fsm(Event::ManualStart).await;
    accept_any.config.link_state = down();
    check(&mut accept_any).await;
    assert!(
        accept_any.read_half.is_some(),
        "an unidentified peer is not provably eBGP; its connection stays"
    );

    let (mut learned, _rib_rx) = make_test_session_with_rib(65001, 0);
    let (client, _server) = connected_stream_pair().await;
    learned.test_install_stream(client);
    establish_test_session(&mut learned, 65001).await;
    learned.config.link_state = down();
    check(&mut learned).await;
    assert_eq!(learned.fsm.state(), SessionState::Established);
}

/// A writer blocked on a dead link is aborted with its backlog: nothing queued
/// reaches the wire after the failover, and the socket is reset.
#[tokio::test]
async fn a_blocked_writer_backlog_is_discarded() {
    const FRAMES: usize = 512;
    const FRAME_LEN: usize = 4096;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let connect = tokio::spawn(async move {
        let socket = tokio::net::TcpSocket::new_v4().unwrap();
        socket.set_recv_buffer_size(4096).unwrap();
        socket.connect(addr).await.unwrap()
    });
    let (stream, _) = listener.accept().await.unwrap();
    socket2::SockRef::from(&stream)
        .set_send_buffer_size(4096)
        .unwrap();
    let mut peer = connect.await.unwrap();
    let (mut session, _rib_rx) = make_test_session_with_rib(65001, 65002);
    let (tx, feed) = feed(healthy());
    session.config.link_state = feed;
    session.test_install_stream(stream);
    establish_test_session(&mut session, 65002).await;
    let bulk_tx = session.writer_bulk_tx.clone().unwrap();
    for _ in 0..FRAMES {
        bulk_tx
            .send(Bytes::from(vec![0u8; FRAME_LEN]))
            .await
            .unwrap();
    }
    drop(bulk_tx);

    set(&tx, iface(1, true, false, &["127.0.0.1"]));
    check(&mut session).await;
    assert!(
        session.writer_join.is_none(),
        "the writer is aborted and joined, not left draining"
    );

    let mut received = 0;
    let mut buf = vec![0u8; 65536];
    let drained = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match peer.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => received += n,
            }
        }
    })
    .await;
    assert!(drained.is_ok(), "the old socket must close promptly");
    assert!(
        received < FRAMES * FRAME_LEN,
        "the queued backlog must not reach the peer ({received} bytes did)"
    );
}

fn open_from(asn: u32) -> rustbgpd_wire::OpenMessage {
    rustbgpd_wire::OpenMessage {
        version: 4,
        my_as: u16::try_from(asn).unwrap_or(23_456),
        hold_time: 90,
        bgp_identifier: Ipv4Addr::new(10, 0, 0, 2),
        capabilities: vec![
            Capability::MultiProtocol {
                afi: Afi::Ipv4,
                safi: Safi::Unicast,
            },
            Capability::FourOctetAs { asn },
        ],
    }
}

/// Accept-any ordering: the carrier is already down while the peer is
/// unidentified, so the check leaves it alone; once its OPEN shows an
/// external AS, the session judges the current state itself and closes,
/// with no manager round trip.
#[tokio::test]
async fn an_accept_any_peer_is_checked_once_its_open_shows_ebgp() {
    let (mut session, _rib_rx) = make_test_session_with_rib(65001, 0);
    session.config.link_state = feed(iface(1, true, false, &["127.0.0.1"])).1;
    let (client, _server) = connected_stream_pair().await;
    session.test_install_stream(client);
    session.drive_fsm(Event::ManualStart).await;
    check(&mut session).await;
    assert!(
        session.read_half.is_some(),
        "unidentified: not provably eBGP"
    );

    session
        .drive_fsm(Event::OpenReceived(open_from(65002)))
        .await;
    assert_eq!(session.fsm.state(), SessionState::OpenConfirm);
    session.run_due_link_check().await;
    assert!(
        session.read_half.is_none(),
        "the OPEN identified an eBGP peer on a link that is down now"
    );
    assert!(session.last_error.ends_with("carrier lost"));
}

/// The neighbor's live setting, shared through the feed, is honored by the
/// session itself: a hot-applied opt-out stops the check without a rebuild.
#[tokio::test]
async fn a_hot_applied_opt_out_is_honored_by_the_session() {
    let (mut session, _server, mut rib_rx, tx) = established_gr_session(healthy()).await;
    session.config.link_state.set_enabled(false);
    set(&tx, iface(1, true, false, &["127.0.0.1"]));
    check(&mut session).await;
    assert_eq!(session.fsm.state(), SessionState::Established);
    assert!(rib_rx.try_recv().is_err());
}

/// The retained connection learns its carrier from the first valid snapshot
/// that proves it, so a later address removal still purges its routes even
/// though the snapshot was invalid when the connection started.
#[tokio::test]
async fn a_retained_connection_learns_its_carrier_from_a_later_valid_snapshot() {
    let mut invalid = healthy();
    invalid.valid = false;
    let (mut session, _server, mut rib_rx, tx) = established_gr_session(invalid).await;
    session.handle_tcp_disconnect();
    session.drive_fsm(Event::TcpConnectionFails).await;
    assert!(matches!(
        rib_rx.try_recv(),
        Ok(RibUpdate::PeerGracefulRestart { .. })
    ));
    assert_eq!(
        session
            .gr_retained_connection
            .get()
            .unwrap()
            .connection
            .carrier,
        None
    );

    set(&tx, healthy());
    check(&mut session).await;
    assert!(rib_rx.try_recv().is_err(), "healthy: keep retaining");
    set(&tx, iface(1, true, true, &[]));
    check(&mut session).await;
    assert!(
        matches!(rib_rx.try_recv(), Ok(RibUpdate::PeerDown { .. })),
        "the learned carrier ties the removed address to the lost connection"
    );
}

/// Retained routes of an iBGP session are never purged by this check.
#[tokio::test]
async fn retained_ibgp_routes_are_not_purged() {
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65001);
    let (tx, feed) = feed(healthy());
    session.config.link_state = feed;
    session.config.peer.graceful_restart = true;
    let (client, _server) = connected_stream_pair().await;
    session.test_install_stream(client);
    establish_test_session(&mut session, 65001).await;
    retain_gr(&mut session);
    while rib_rx.try_recv().is_ok() {}
    session.handle_tcp_disconnect();
    session.drive_fsm(Event::TcpConnectionFails).await;
    assert!(matches!(
        rib_rx.try_recv(),
        Ok(RibUpdate::PeerGracefulRestart { .. })
    ));
    set(&tx, iface(1, true, false, &["127.0.0.1"]));
    check(&mut session).await;
    assert!(rib_rx.try_recv().is_err());
}

/// A fresh actor keeps the previous retention owner during its handshake;
/// reaching Established retires that stamp without changing the old actor's cell.
#[tokio::test]
async fn a_fresh_actor_preserves_the_retention_owner_until_established() {
    for establish in [false, true] {
        let both_up = merge(healthy(), iface(7, true, true, &["127.0.0.3"]));
        let (mut old, _old_remote, mut old_rib, tx) = established_gr_session(both_up).await;
        old.session_identity = crate::SessionIdentity::primary(17);
        old.handle_tcp_disconnect();
        old.drive_fsm(Event::TcpConnectionFails).await;
        assert!(matches!(
            old_rib.try_recv(),
            Ok(RibUpdate::PeerGracefulRestart { session_id: 17, .. })
        ));

        let (mut fresh, mut rib_rx) = make_test_session_with_rib(65001, 65002);
        fresh.session_identity = crate::SessionIdentity::primary(29);
        fresh.config.link_state = old.config.link_state.clone();
        fresh
            .gr_retained_connection
            .set(old.gr_retained_connection.get());
        let (replacement, _replacement_remote) = stream_from("127.0.0.3").await;
        fresh.test_install_stream(replacement);
        if establish {
            establish_test_session(&mut fresh, 65002).await;
            assert!(fresh.gr_retained_connection.get().is_none());
        } else {
            fresh.drive_fsm(Event::ManualStart).await;
        }
        while rib_rx.try_recv().is_ok() {}
        set(
            &tx,
            merge(
                iface(1, true, false, &["127.0.0.1"]),
                iface(7, true, true, &["127.0.0.3"]),
            ),
        );
        check(&mut fresh).await;
        if establish {
            assert!(
                rib_rx.try_recv().is_err(),
                "old retention no longer belongs to the Established replacement"
            );
        } else {
            assert!(
                matches!(
                    rib_rx.try_recv(),
                    Ok(RibUpdate::PeerDown { session_id: 17, .. })
                ),
                "purge keeps the retained route's owner, not the new actor's id"
            );
        }
        assert!(
            old.gr_retained_connection.get().is_some(),
            "actor snapshots are independent"
        );
        assert!(
            fresh.read_half.is_some(),
            "replacement on the healthy link stays connected"
        );
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "the claimed candidate fallback, route receipt, GR loss and delayed inheritance must be ordered in one regression"
)]
async fn released_candidate_keeps_own_retention(previous_retains: bool) {
    let both_up = merge(healthy(), iface(7, true, true, &["127.0.0.3"]));
    let (mut old, _old_remote, _old_rib, links) = established_gr_session(both_up).await;
    old.session_identity = SessionIdentity::primary(17);
    old.config.peer.graceful_restart = previous_retains;
    old.handle_tcp_disconnect();
    old.drive_fsm(Event::TcpConnectionFails).await;
    let previous = old.gr_retained_connection.clone();
    assert_eq!(previous.get().is_some(), previous_retains);

    let (mut candidate, mut rib_rx) = make_test_session_with_metrics_and_identity(
        BgpMetrics::new(),
        SessionIdentity::inbound_candidate(29),
    );
    candidate.config.link_state = old.config.link_state.clone();
    candidate.config.peer.graceful_restart = true;
    let (commands, _receiver) = mpsc::channel(1);
    let handle = crate::PeerHandle::from_parts(commands, tokio::spawn(async { Ok(()) }));
    candidate.gr_retained_connection = handle.retained_connection_state();
    let (local, remote) = stream_from("127.0.0.3").await;
    candidate.test_install_stream(local);
    candidate.drive_fsm(Event::ManualStart).await;
    for message in [
        Message::Open(notification_gr_open(false)),
        Message::Keepalive,
    ] {
        candidate
            .read_buf
            .buf
            .extend_from_slice(&rustbgpd_wire::encode_message(&message).unwrap());
    }
    candidate.process_read_buffer().await;
    assert_eq!(candidate.fsm.state(), SessionState::OpenConfirm);
    let (reply, claimed) = oneshot::channel();
    assert_eq!(
        candidate
            .handle_command(PeerCommand::ClaimCollisionPromotion { reply })
            .await,
        ControlFlow::Continue(())
    );
    assert!(claimed.await.unwrap());
    // The fallback may run while the manager still retires the old actor.
    // Expiring it explicitly orders that interleaving without a sleep.
    candidate.expire_collision_verdict_wait().await;
    assert_eq!(candidate.fsm.state(), SessionState::Established);
    let registered = std::iter::from_fn(|| rib_rx.try_recv().ok())
        .any(|update| matches!(update, RibUpdate::PeerUp { session_id: 29, .. }));
    assert!(
        registered,
        "fallback registered the candidate's own session"
    );
    while rib_rx.try_recv().is_ok() {}
    let update = Message::Update(rfc7606_update(
        rfc7606_attr_bytes(&[]),
        &[Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24)],
    ));
    candidate
        .read_buf
        .buf
        .extend_from_slice(&rustbgpd_wire::encode_message(&update).unwrap());
    candidate.process_read_buffer().await;
    assert!(std::iter::from_fn(|| rib_rx.try_recv().ok()).any(|update| {
        matches!(update, RibUpdate::RoutesReceived { session_id: 29, announced, .. } if announced.len() == 1)
    }));
    drop(remote);
    candidate.handle_tcp_disconnect();
    candidate.drive_fsm(Event::TcpConnectionFails).await;
    assert_eq!(candidate.fsm.state(), SessionState::Idle);
    assert!(matches!(
        rib_rx.try_recv(),
        Ok(RibUpdate::PeerGracefulRestart { session_id: 29, .. })
    ));

    handle.inherit_retained_connection(&previous);
    assert_eq!(
        candidate
            .gr_retained_connection
            .get()
            .map(|stamp| stamp.session_id),
        Some(29),
        "late inheritance preserves the candidate's own GR owner"
    );
    assert_eq!(
        candidate
            .gr_retained_connection
            .get()
            .unwrap()
            .connection
            .carrier,
        Some(7)
    );
    set(
        &links,
        merge(
            iface(1, true, false, &["127.0.0.1"]),
            iface(7, true, true, &["127.0.0.3"]),
        ),
    );
    check(&mut candidate).await;
    assert!(rib_rx.try_recv().is_err(), "the old carrier is unrelated");
    set(
        &links,
        merge(healthy(), iface(7, true, false, &["127.0.0.3"])),
    );
    check(&mut candidate).await;
    assert!(
        matches!(
            rib_rx.try_recv(),
            Ok(RibUpdate::PeerDown { session_id: 29, .. })
        ),
        "the owning carrier purges the candidate's retained routes"
    );
    handle.inherit_retained_connection(&previous);
    assert!(
        candidate.gr_retained_connection.get().is_none(),
        "late inheritance does not resurrect completed purge state"
    );
    handle.abort_for_transport_safety_and_wait().await;
}

#[tokio::test]
async fn released_candidate_retention_survives_an_empty_predecessor() {
    Box::pin(released_candidate_keeps_own_retention(false)).await;
}

#[tokio::test]
async fn released_candidate_retention_survives_a_retaining_predecessor() {
    Box::pin(released_candidate_keeps_own_retention(true)).await;
}
