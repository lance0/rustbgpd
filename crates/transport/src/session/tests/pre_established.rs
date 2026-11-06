//! Input received before Established, and what a pre-Established exit may
//! leave behind for the next session on the same actor.

use super::*;
use rustbgpd_policy::RouteType;

fn announce_192_0_2() -> Vec<u8> {
    rustbgpd_wire::encode_message(&Message::Update(ipv4_announce(
        Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, 0), 24),
        0,
        false,
    )))
    .unwrap()
    .to_vec()
}

/// A two-octet `AS_PATH` UPDATE, valid without a negotiated four-octet AS, so
/// it would import if it ever reached inbound processing before Established.
fn announce_192_0_2_two_octet() -> Vec<u8> {
    vec![
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x00, 45, 2, 0x00, 0x00, 0x00, 18, 0x40, 0x01, 0x01, 0x00, 0x40, 0x02, 0x04, 0x02,
        0x01, 0xfd, 0xea, 0x40, 0x03, 0x04, 10, 0, 0, 2, 24, 192, 0, 2,
    ]
}

fn plain_open() -> rustbgpd_wire::OpenMessage {
    rustbgpd_wire::OpenMessage {
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
    }
}

/// Drive a fresh connection to `OpenConfirm`; the returned peer end keeps it open.
async fn to_open_confirm(session: &mut PeerSession, open: rustbgpd_wire::OpenMessage) -> TcpStream {
    session.reconnect_timer = None;
    let (client, server) = connected_stream_pair().await;
    session.test_install_stream(client);
    session.drive_fsm(Event::ManualStart).await;
    assert_eq!(session.fsm.state(), SessionState::OpenSent);
    session.drive_fsm(Event::OpenReceived(open)).await;
    assert_eq!(session.fsm.state(), SessionState::OpenConfirm);
    server
}

fn is_peer_input(update: &RibUpdate) -> bool {
    matches!(
        update,
        RibUpdate::RoutesReceived { .. }
            | RibUpdate::WireRoutesReceived(_)
            | RibUpdate::EndOfRib { .. }
    )
}

fn deny_import(remote_asn: Option<u32>, route_type: Option<RouteType>) -> PolicyChain {
    PolicyChain::new(vec![Policy {
        entries: vec![PolicyStatement {
            prefix: None,
            ge: None,
            le: None,
            action: PolicyAction::Deny,
            match_community: vec![],
            match_as_path: None,
            match_neighbor_set: remote_asn.map(|asn| NeighborSetMatch {
                addresses: vec![],
                remote_asns: vec![asn],
                peer_groups: vec![],
            }),
            match_route_type: route_type,
            match_evpn_route_type: None,
            match_rpki_validation: None,
            match_aspa_validation: None,
            match_as_path_length_ge: None,
            match_as_path_length_le: None,
            match_local_pref_ge: None,
            match_local_pref_le: None,
            match_med_ge: None,
            match_med_le: None,
            match_next_hop: None,
            modifications: RouteModifications::default(),
        }],
        default_action: PolicyAction::Permit,
    }])
}

/// The known-prefix count and import policy (permitted, denied) totals after
/// one UPDATE on an Established eBGP session with `policy`.
async fn established_import_outcome(policy: PolicyChain) -> (usize, (u64, u64)) {
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    session.import_policy = Some(policy);
    let _peer = to_open_confirm(&mut session, plain_open()).await;
    session.drive_fsm(Event::KeepaliveReceived).await;
    assert_eq!(session.fsm.state(), SessionState::Established);
    session.read_buf.buf.extend_from_slice(&announce_192_0_2());
    session.process_read_buffer().await;
    while rib_rx.try_recv().is_ok() {}
    (session.known_prefix_count(), import_policy_counts(&session))
}

/// The pre-Established gate must not weaken eBGP import policy once the
/// session is Established: a deny on the remote ASN denies.
#[tokio::test]
async fn established_import_deny_by_remote_asn_applies() {
    assert_eq!(
        established_import_outcome(deny_import(Some(65002), None)).await,
        (0, (0, 1))
    );
}

/// The same for a deny on external routes.
#[tokio::test]
async fn established_import_deny_of_external_routes_applies() {
    assert_eq!(
        established_import_outcome(deny_import(None, Some(RouteType::External))).await,
        (0, (0, 1))
    );
}

/// The state check runs per PDU: an UPDATE behind the KEEPALIVE that
/// establishes the session, in the same read, is imported.
#[tokio::test]
async fn update_behind_the_establishing_keepalive_in_one_read_is_imported() {
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    let _peer = to_open_confirm(&mut session, plain_open()).await;
    while rib_rx.try_recv().is_ok() {}
    let mut bytes = rustbgpd_wire::encode_message(&Message::Keepalive)
        .unwrap()
        .to_vec();
    bytes.extend_from_slice(&announce_192_0_2());
    session.read_buf.buf.extend_from_slice(&bytes);
    session.process_read_buffer().await;
    assert_eq!(session.fsm.state(), SessionState::Established);
    let mut imported = false;
    while let Ok(update) = rib_rx.try_recv() {
        imported |= is_peer_input(&update);
    }
    assert!(
        imported,
        "the UPDATE behind the establishing KEEPALIVE was dropped"
    );
    assert_eq!(session.known_prefix_count(), 1);
}

/// A pre-Established UPDATE emits no BMP event: the collector has seen no
/// Peer Up, and nothing would ever retract a mirrored route.
#[tokio::test]
async fn pre_established_update_emits_no_bmp_route_monitoring() {
    let (mut session, mut rib_rx, mut bmp_rx) = make_test_session_with_rib_and_bmp(65001, 65002);
    let _peer = to_open_confirm(&mut session, plain_open()).await;
    session.read_buf.buf.extend_from_slice(&announce_192_0_2());
    session.process_read_buffer().await;
    assert_eq!(session.fsm.state(), SessionState::Idle);
    let mut events = Vec::new();
    while let Ok(event) = bmp_rx.try_recv() {
        events.push(format!("{event:?}").chars().take(40).collect::<String>());
    }
    assert!(
        events.is_empty(),
        "BMP events for an unestablished peer: {events:?}"
    );
    while let Ok(update) = rib_rx.try_recv() {
        assert!(!is_peer_input(&update), "peer input reached the RIB");
    }
}

/// A pre-Established UPDATE leaves no prefix accounting for the next session.
#[tokio::test]
async fn pre_established_update_leaves_no_accounting_for_the_next_session() {
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    let _peer = to_open_confirm(&mut session, plain_open()).await;
    session
        .read_buf
        .buf
        .extend_from_slice(&announce_192_0_2_two_octet());
    session.process_read_buffer().await;
    assert_eq!(session.fsm.state(), SessionState::Idle);
    assert_eq!(session.known_prefix_count(), 0);
    let _peer2 = to_open_confirm(&mut session, plain_open()).await;
    session.drive_fsm(Event::KeepaliveReceived).await;
    assert_eq!(session.fsm.state(), SessionState::Established);
    assert_eq!(session.known_prefix_count(), 0);
    assert_eq!(session.known_unicast_v4, 0);
    while rib_rx.try_recv().is_ok() {}
}

fn gr_session() -> (PeerSession, mpsc::Receiver<RibUpdate>) {
    let (mut session, rib_rx) = make_test_session_with_rib(65001, 65002);
    session.config.peer.graceful_restart = true;
    session.fsm = rustbgpd_fsm::Session::new(session.config.peer.clone());
    (session, rib_rx)
}

/// Establish a Graceful Restart session, lose TCP, and report whether the
/// RIB was told to retain (`PeerGracefulRestart`) or drop (`PeerDown`).
async fn establish_gr_then_tcp_loss(
    session: &mut PeerSession,
    rib_rx: &mut mpsc::Receiver<RibUpdate>,
) -> &'static str {
    let _peer = to_open_confirm(session, notification_gr_open(false)).await;
    session.drive_fsm(Event::KeepaliveReceived).await;
    assert_eq!(session.fsm.state(), SessionState::Established);
    while rib_rx.try_recv().is_ok() {}
    session.handle_tcp_read_result(Ok(0)).await;
    assert_eq!(session.fsm.state(), SessionState::Idle);
    let mut outcome = "none";
    while let Ok(update) = rib_rx.try_recv() {
        match update {
            RibUpdate::PeerGracefulRestart { .. } => outcome = "PeerGracefulRestart",
            RibUpdate::PeerDown { .. } => outcome = "PeerDown",
            _ => {}
        }
    }
    outcome
}

/// Control for the hard-reset latch test: a GR peer's TCP loss retains.
#[tokio::test]
async fn gr_session_tcp_loss_retains_routes() {
    let (mut session, mut rib_rx) = gr_session();
    assert_eq!(
        establish_gr_then_tcp_loss(&mut session, &mut rib_rx).await,
        "PeerGracefulRestart"
    );
}

/// A NOTIFICATION Cease/Hard Reset received in `OpenConfirm` ends that
/// connection only: it must not disable Graceful Restart retention for the
/// next Established session.
#[tokio::test]
async fn pre_established_hard_reset_does_not_disable_gr_on_the_next_session() {
    let (mut session, mut rib_rx) = gr_session();
    let _peer = to_open_confirm(&mut session, notification_gr_open(false)).await;
    let notification = NotificationMessage::new(
        NotificationCode::Cease,
        cease_subcode::HARD_RESET,
        Bytes::from(vec![6, 2]),
    );
    session.read_buf.buf.extend_from_slice(
        &rustbgpd_wire::encode_message(&Message::Notification(notification)).unwrap(),
    );
    session.process_read_buffer().await;
    assert_eq!(session.fsm.state(), SessionState::Idle);
    let latched = session.received_hard_reset;
    let outcome = establish_gr_then_tcp_loss(&mut session, &mut rib_rx).await;
    assert_eq!(
        (latched, outcome),
        (false, "PeerGracefulRestart"),
        "a pre-Established Cease/9 latched received_hard_reset into the next session"
    );
}

/// BMP Peer Down for the next Established session after a plain TCP loss
/// reports that loss, not the NOTIFICATION of an earlier pre-Established
/// attempt.
#[tokio::test]
async fn pre_established_notification_does_not_become_the_next_bmp_down_reason() {
    let (mut session, mut rib_rx, mut bmp_rx) = make_test_session_with_rib_and_bmp(65001, 65002);
    let _peer = to_open_confirm(&mut session, plain_open()).await;
    session.read_buf.buf.extend_from_slice(&announce_192_0_2());
    session.process_read_buffer().await;
    assert_eq!(session.fsm.state(), SessionState::Idle);
    let stale = session.last_down_reason.is_some();
    let _peer2 = to_open_confirm(&mut session, plain_open()).await;
    session.drive_fsm(Event::KeepaliveReceived).await;
    assert_eq!(session.fsm.state(), SessionState::Established);
    while rib_rx.try_recv().is_ok() {}
    session.handle_tcp_read_result(Ok(0)).await;
    let mut reason = None;
    while let Ok(event) = bmp_rx.try_recv() {
        if let BmpEvent::PeerDown { reason: r, .. } = event {
            reason = Some(format!("{r:?}").chars().take(60).collect::<String>());
        }
    }
    assert_eq!(
        (stale, reason.as_deref()),
        (false, Some("RemoteNoNotification")),
        "a pre-Established NOTIFICATION became the next session's down reason"
    );
}
