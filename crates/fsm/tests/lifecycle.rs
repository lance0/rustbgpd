use std::net::Ipv4Addr;

use bytes::Bytes;

use rustbgpd_wire::notification::NotificationCode;
use rustbgpd_wire::{Afi, Capability, OpenMessage, Safi};

use rustbgpd_fsm::{Action, Event, PeerConfig, Session, SessionState, TimerType};

fn test_config() -> PeerConfig {
    PeerConfig {
        local_asn: 65001,
        remote_asn: 65002,
        local_router_id: Ipv4Addr::new(10, 0, 0, 1),
        hold_time: 90,
        connect_retry_secs: 30,
        families: vec![(Afi::Ipv4, Safi::Unicast)],
        graceful_restart: false,
        gr_restart_time: 120,
        add_path_receive: false,
        add_path_send: false,
        add_path_send_max: 0,
    }
}

fn peer_open() -> OpenMessage {
    OpenMessage {
        version: 4,
        my_as: 65002,
        hold_time: 180,
        bgp_identifier: Ipv4Addr::new(10, 0, 0, 2),
        capabilities: vec![
            Capability::MultiProtocol {
                afi: Afi::Ipv4,
                safi: Safi::Unicast,
            },
            Capability::FourOctetAs { asn: 65002 },
        ],
    }
}

fn has_action(actions: &[Action], pred: impl Fn(&Action) -> bool) -> bool {
    actions.iter().any(pred)
}

/// Full lifecycle: Idle → Connect → OpenSent → OpenConfirm → Established → Idle
#[test]
fn full_lifecycle_idle_to_established_to_idle() {
    let mut s = Session::new(test_config());
    assert_eq!(s.state(), SessionState::Idle);

    // ── Idle → Connect: ManualStart ────────────────────────────────
    let actions = s.handle_event(Event::ManualStart);
    assert_eq!(s.state(), SessionState::Connect);
    assert!(has_action(&actions, |a| matches!(
        a,
        Action::InitiateTcpConnection
    )));
    assert!(has_action(&actions, |a| matches!(
        a,
        Action::StartTimer(TimerType::ConnectRetry, 30)
    )));

    // ── Connect → OpenSent: TCP succeeds ───────────────────────────
    let actions = s.handle_event(Event::TcpConnectionConfirmed);
    assert_eq!(s.state(), SessionState::OpenSent);
    assert!(has_action(&actions, |a| matches!(a, Action::SendOpen(_))));
    assert!(has_action(&actions, |a| matches!(
        a,
        Action::StartTimer(TimerType::Hold, 240) // initial hold timer
    )));
    assert!(has_action(&actions, |a| matches!(
        a,
        Action::StopTimer(TimerType::ConnectRetry)
    )));

    // ── OpenSent → OpenConfirm: valid OPEN received ────────────────
    let actions = s.handle_event(Event::OpenReceived(peer_open()));
    assert_eq!(s.state(), SessionState::OpenConfirm);
    assert!(has_action(&actions, |a| matches!(a, Action::SendKeepalive)));
    // Negotiated hold = min(90, 180) = 90
    assert!(has_action(&actions, |a| matches!(
        a,
        Action::StartTimer(TimerType::Hold, 90)
    )));
    assert!(has_action(&actions, |a| matches!(
        a,
        Action::StartTimer(TimerType::Keepalive, 30) // 90/3
    )));

    // ── OpenConfirm → Established: KEEPALIVE received ──────────────
    let actions = s.handle_event(Event::KeepaliveReceived);
    assert_eq!(s.state(), SessionState::Established);
    assert!(has_action(&actions, |a| matches!(
        a,
        Action::SessionEstablished(_)
    )));

    // Verify negotiated parameters
    let neg = s.negotiated().unwrap();
    assert_eq!(neg.peer_asn, 65002);
    assert_eq!(neg.peer_router_id, Ipv4Addr::new(10, 0, 0, 2));
    assert_eq!(neg.hold_time, 90);
    assert_eq!(neg.keepalive_interval, 30);
    assert!(neg.four_octet_as);

    // ── Established: process a KEEPALIVE (stays Established) ───────
    let actions = s.handle_event(Event::KeepaliveReceived);
    assert_eq!(s.state(), SessionState::Established);
    assert!(has_action(&actions, |a| matches!(
        a,
        Action::StartTimer(TimerType::Hold, 90)
    )));

    // ── Established → Idle: ManualStop ─────────────────────────────
    let actions = s.handle_event(Event::ManualStop);
    assert_eq!(s.state(), SessionState::Idle);
    assert!(has_action(&actions, |a| matches!(a, Action::SessionDown)));
    assert!(has_action(&actions, |a| matches!(
        a,
        Action::SendNotification(n) if n.code == NotificationCode::Cease
    )));
}

/// Connect failure → Active → retry → Connect → full handshake
#[test]
fn connect_failure_recovery_lifecycle() {
    let mut s = Session::new(test_config());

    s.handle_event(Event::ManualStart);
    assert_eq!(s.state(), SessionState::Connect);

    // TCP fails → Active
    s.handle_event(Event::TcpConnectionFails);
    assert_eq!(s.state(), SessionState::Active);
    assert!(s.connect_retry_counter() > 0);

    // Retry timer → Connect
    s.handle_event(Event::ConnectRetryTimerExpires);
    assert_eq!(s.state(), SessionState::Connect);

    // This time TCP succeeds
    s.handle_event(Event::TcpConnectionConfirmed);
    assert_eq!(s.state(), SessionState::OpenSent);

    // Complete handshake
    s.handle_event(Event::OpenReceived(peer_open()));
    assert_eq!(s.state(), SessionState::OpenConfirm);

    s.handle_event(Event::KeepaliveReceived);
    assert_eq!(s.state(), SessionState::Established);
}

/// Established session disrupted by hold timer expiry
#[test]
fn established_hold_timer_expiry() {
    let mut s = Session::new(test_config());

    // Reach Established
    s.handle_event(Event::ManualStart);
    s.handle_event(Event::TcpConnectionConfirmed);
    s.handle_event(Event::OpenReceived(peer_open()));
    s.handle_event(Event::KeepaliveReceived);
    assert_eq!(s.state(), SessionState::Established);

    // Hold timer expires
    let actions = s.handle_event(Event::HoldTimerExpires);
    assert_eq!(s.state(), SessionState::Idle);
    assert!(has_action(&actions, |a| matches!(a, Action::SessionDown)));
    assert!(has_action(&actions, |a| matches!(
        a,
        Action::SendNotification(n) if n.code == NotificationCode::HoldTimerExpired
    )));
}

/// Peer sends NOTIFICATION during Established
#[test]
fn established_notification_tears_down() {
    let mut s = Session::new(test_config());

    s.handle_event(Event::ManualStart);
    s.handle_event(Event::TcpConnectionConfirmed);
    s.handle_event(Event::OpenReceived(peer_open()));
    s.handle_event(Event::KeepaliveReceived);
    assert_eq!(s.state(), SessionState::Established);

    let notif = rustbgpd_wire::NotificationMessage::new(
        NotificationCode::Cease,
        2, // Administrative Shutdown
        Bytes::new(),
    );
    let actions = s.handle_event(Event::NotificationReceived(notif));
    assert_eq!(s.state(), SessionState::Idle);
    assert!(has_action(&actions, |a| matches!(a, Action::SessionDown)));
    assert!(has_action(&actions, |a| matches!(
        a,
        Action::CloseTcpConnection
    )));
}

/// OPEN validation failure during handshake
#[test]
fn open_validation_failure_in_opensent() {
    let mut s = Session::new(test_config());

    s.handle_event(Event::ManualStart);
    s.handle_event(Event::TcpConnectionConfirmed);
    assert_eq!(s.state(), SessionState::OpenSent);

    // Send OPEN with wrong ASN
    let mut bad_open = peer_open();
    bad_open.my_as = 65099;
    bad_open.capabilities = vec![Capability::FourOctetAs { asn: 65099 }];

    let actions = s.handle_event(Event::OpenReceived(bad_open));
    assert_eq!(s.state(), SessionState::Idle);
    assert!(has_action(&actions, |a| matches!(
        a,
        Action::SendNotification(_)
    )));
    assert!(has_action(&actions, |a| matches!(
        a,
        Action::CloseTcpConnection
    )));
}
