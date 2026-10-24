use super::*;
use rustbgpd_transport::PeerCommand;

fn recording_handle() -> (PeerHandle, mpsc::Receiver<PeerCommand>) {
    let (tx, rx) = mpsc::channel(8);
    let task = tokio::spawn(async { Ok(()) });
    (PeerHandle::from_parts(tx, task), rx)
}

/// A mailbox that is already full, as for a session busy with other work.
fn full_handle() -> (PeerHandle, mpsc::Receiver<PeerCommand>) {
    let (tx, rx) = mpsc::channel(1);
    tx.try_send(PeerCommand::Start).unwrap();
    let task = tokio::spawn(async { Ok(()) });
    (PeerHandle::from_parts(tx, task), rx)
}

fn got_check(rx: &mut mpsc::Receiver<PeerCommand>) -> bool {
    matches!(rx.try_recv(), Ok(PeerCommand::CheckLinks))
}

/// Eligibility is knob + not-known-iBGP + enabled; whether the interface
/// carries the connection is the session's call against current state.
#[tokio::test]
async fn link_change_reaches_only_eligible_sessions() {
    let mut mgr = test_peer_manager();
    let ebgp: IpAddr = "10.0.0.2".parse().unwrap();
    let ibgp: IpAddr = "10.0.0.3".parse().unwrap();
    let opted_out: IpAddr = "10.0.0.4".parse().unwrap();
    let disabled: IpAddr = "10.0.0.5".parse().unwrap();
    let unlearned: IpAddr = "10.0.0.6".parse().unwrap();
    let (handle, mut ebgp_rx) = recording_handle();
    insert_test_managed_peer_with_asn(&mut mgr, ebgp, 65002, handle, false);
    let (handle, mut ibgp_rx) = recording_handle();
    insert_test_managed_peer_with_asn(&mut mgr, ibgp, 65001, handle, false);
    let (handle, mut opted_out_rx) = recording_handle();
    insert_test_managed_peer_with_asn(&mut mgr, opted_out, 65002, handle, false);
    mgr.peers
        .get_mut(&key(opted_out))
        .unwrap()
        .transport_config
        .fast_external_failover = false;
    let (handle, mut disabled_rx) = recording_handle();
    insert_test_managed_peer_with_asn(&mut mgr, disabled, 65002, handle, false);
    mgr.peers.get_mut(&key(disabled)).unwrap().enabled = false;
    let (handle, mut unlearned_rx) = recording_handle();
    insert_test_managed_peer_with_asn(&mut mgr, unlearned, 0, handle, false);

    mgr.handle_links_changed();

    assert!(got_check(&mut ebgp_rx), "eBGP peer is asked to check");
    assert!(!got_check(&mut ibgp_rx), "iBGP is untouched");
    assert!(!got_check(&mut opted_out_rx), "opt-out honored");
    assert!(!got_check(&mut disabled_rx), "disabled peer untouched");
    assert!(
        got_check(&mut unlearned_rx),
        "an unlearned ASN is deferred to the session's negotiated-ASN check"
    );
}

#[tokio::test]
async fn link_change_also_reaches_a_pending_inbound_collision_candidate() {
    let mut mgr = test_peer_manager();
    let peer: IpAddr = "10.0.0.2".parse().unwrap();
    let (handle, mut primary_rx) = recording_handle();
    insert_test_managed_peer_with_asn(&mut mgr, peer, 65002, handle, false);
    let (candidate, mut candidate_rx) = recording_handle();
    mgr.peers.get_mut(&key(peer)).unwrap().pending_inbound = Some(PendingInbound {
        recovery_reset: None,
        handle: candidate,
        session_id: 99,
    });
    mgr.handle_links_changed();
    assert!(got_check(&mut primary_rx));
    assert!(got_check(&mut candidate_rx));
}

/// The opt-out is read when the change arrives, so a hot-applied change takes
/// effect without rebuilding the session.
#[tokio::test]
async fn hot_applied_opt_out_takes_effect_on_the_next_change() {
    let mut mgr = test_peer_manager();
    let peer: IpAddr = "10.0.0.2".parse().unwrap();
    let (handle, mut rx) = recording_handle();
    insert_test_managed_peer_with_asn(&mut mgr, peer, 65002, handle, false);
    let mut config = make_config(peer, 65002);
    config.fast_external_failover = false;
    mgr.hot_update_peer(config).await.expect("hot update");
    while rx.try_recv().is_ok() {}
    mgr.handle_links_changed();
    assert!(!got_check(&mut rx));
}

/// A full mailbox keeps the session's single pending flag; the retry
/// delivers once there is room, and any number of further changes neither
/// grows the pending state nor postpones the armed retry.
#[tokio::test(start_paused = true)]
async fn a_full_mailbox_keeps_one_flag_and_the_retry_delivers() {
    let mut mgr = test_peer_manager();
    let (handle, mut rx) = full_handle();
    insert_test_managed_peer_with_asn(&mut mgr, "10.0.0.2".parse().unwrap(), 65002, handle, false);
    mgr.handle_links_changed();
    let armed = mgr.link_check.retry_at.expect("retry armed");
    for _ in 0..10 {
        tokio::time::advance(Duration::from_millis(50)).await;
        mgr.handle_links_changed();
        assert_eq!(
            mgr.link_check.retry_at,
            Some(armed),
            "deadline must not slide"
        );
    }
    assert_eq!(mgr.link_check.pending.len(), 1);
    assert!(matches!(rx.try_recv(), Ok(PeerCommand::Start)));
    mgr.retry_link_checks();
    assert!(got_check(&mut rx));
    assert!(mgr.link_check.pending.is_empty());
    assert!(mgr.link_check.retry_at.is_none());
}

/// Per-session state stays O(1): 1000 flaps against blocked mailboxes leave
/// one pending entry per session.
#[tokio::test]
async fn pending_state_is_one_entry_per_session_under_flapping() {
    let mut mgr = test_peer_manager();
    let mut held = Vec::new();
    for host in 1..=5_u8 {
        let (handle, rx) = full_handle();
        let peer = IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 1, host));
        insert_test_managed_peer_with_asn(&mut mgr, peer, 65002, handle, false);
        held.push(rx);
    }
    for _ in 0..1000 {
        mgr.handle_links_changed();
    }
    assert_eq!(mgr.link_check.pending.len(), 5);
}

/// Sessions get the monitor's read handle through their transport config.
#[tokio::test]
async fn transport_config_carries_the_link_state_feed() {
    let (tx, rx) = tokio::sync::watch::channel(Arc::new(rustbgpd_transport::LinkSnapshot {
        valid: true,
        ..Default::default()
    }));
    let mgr = test_peer_manager().with_link_failover(rx);
    let transport = mgr.build_transport_config(&make_config("10.0.0.2".parse().unwrap(), 65002));
    assert!(transport.link_state.current().valid);
    tx.send_replace(Arc::default());
    assert!(
        !transport.link_state.current().valid,
        "reads the current snapshot"
    );
}

/// An opt-out hot-applied while a check waits for mailbox space drops the
/// pending entry, collision candidate included: the retry delivers nothing.
#[tokio::test]
async fn a_pending_check_is_dropped_after_a_hot_applied_opt_out() {
    let mut mgr = test_peer_manager();
    let peer: IpAddr = "10.0.0.2".parse().unwrap();
    let (handle, mut primary_rx) = full_handle();
    insert_test_managed_peer_with_asn(&mut mgr, peer, 65002, handle, false);
    let (candidate, mut candidate_rx) = full_handle();
    mgr.peers.get_mut(&key(peer)).unwrap().pending_inbound = Some(PendingInbound {
        recovery_reset: None,
        handle: candidate,
        session_id: 99,
    });
    mgr.handle_links_changed();
    assert_eq!(mgr.link_check.pending.len(), 2);

    let mut config = make_config(peer, 65002);
    config.fast_external_failover = false;
    mgr.hot_update_peer(config).await.expect("hot update");
    assert!(
        !mgr.peers[&key(peer)].transport_config.link_state.enabled(),
        "the session's shared setting follows the hot apply"
    );
    for rx in [&mut primary_rx, &mut candidate_rx] {
        assert!(matches!(rx.try_recv(), Ok(PeerCommand::Start)));
    }
    mgr.retry_link_checks();
    assert!(mgr.link_check.pending.is_empty());
    assert!(!got_check(&mut primary_rx));
    assert!(!got_check(&mut candidate_rx));
}

fn snapshot_with(name: &str, ifindex: u32) -> Arc<rustbgpd_transport::LinkSnapshot> {
    Arc::new(rustbgpd_transport::LinkSnapshot {
        valid: true,
        links: std::collections::BTreeMap::from([(
            ifindex,
            rustbgpd_transport::LinkState {
                name: name.into(),
                admin_up: true,
                lower_up: true,
            },
        )]),
        addresses: std::collections::BTreeMap::new(),
    })
}

/// A static link-local neighbor on `interface`, last dialed at index 4, with
/// the link monitor reporting `interface` at index 9 now.
pub(super) fn insert_recreated_link_local_peer(
    mgr: &mut PeerManager,
    interface: &str,
    handle: PeerHandle,
) -> (
    PeerKey,
    tokio::sync::watch::Sender<Arc<rustbgpd_transport::LinkSnapshot>>,
) {
    let key = PeerKey::new("fe80::2".parse().unwrap(), Some(interface.to_owned()));
    insert_test_managed_peer_for_key(mgr, &key, 65002, handle, false);
    let (tx, rx) = tokio::sync::watch::channel(snapshot_with("eth1", 9));
    let transport = &mut mgr.peers.get_mut(&key).unwrap().transport_config;
    transport.remote_addr = "[fe80::2%4]:179".parse().unwrap();
    transport.peer_interface = Some(interface.to_owned());
    transport.peer_scope_id = Some(4);
    transport.link_state = rustbgpd_transport::LinkStateFeed::new(rx, true);
    (key, tx)
}

/// Inbound matching follows the interface's current index, not the index the
/// neighbor was resolved at; the accepted arrival's scope is adopted.
#[tokio::test]
async fn inbound_link_local_matches_the_current_interface_index() {
    let mut mgr = test_peer_manager();
    let (handle, _rx) = recording_handle();
    let (key, _tx) = insert_recreated_link_local_peer(&mut mgr, "eth1", handle);
    let new: SocketAddr = "[fe80::2%9]:40000".parse().unwrap();
    let stale: SocketAddr = "[fe80::2%4]:40000".parse().unwrap();
    assert_eq!(mgr.inbound_peer_key(new), Some(key.clone()));
    assert_eq!(mgr.inbound_peer_key(stale), None, "the old index is gone");

    mgr.adopt_inbound_link_local_scope(&key, new);
    let transport = &mgr.peers[&key].transport_config;
    assert_eq!(transport.peer_scope_id, Some(9));
    assert_eq!(transport.remote_addr, "[fe80::2%9]:179".parse().unwrap());
}

/// A configured interface name that resolves to nothing now matches no
/// arrival, whatever its scope.
#[tokio::test]
async fn inbound_link_local_does_not_match_a_missing_interface() {
    let mut mgr = test_peer_manager();
    let (handle, _rx) = recording_handle();
    let (_key, _tx) = insert_recreated_link_local_peer(&mut mgr, "rbgp-ll-missing0", handle);
    for scope in [4, 9] {
        let addr = SocketAddr::V6(std::net::SocketAddrV6::new(
            "fe80::2".parse().unwrap(),
            40000,
            0,
            scope,
        ));
        assert_eq!(mgr.inbound_peer_key(addr), None);
    }
}

async fn retained_routes(
    rib: &mpsc::Sender<RibUpdate>,
    peer: rustbgpd_rib::PeerId,
) -> Vec<rustbgpd_rib::Route> {
    let (reply, response) = oneshot::channel();
    rib.send(RibUpdate::QueryRoutesPage {
        scope: rustbgpd_rib::update::RouteQueryScope::Received { peer: Some(peer) },
        filter: None,
        after: None,
        expected_version: None,
        page_size: 10,
        reply,
    })
    .await
    .unwrap();
    response.await.unwrap().unwrap().routes
}

fn loopback_links(primary_up: bool, other_up: bool) -> rustbgpd_transport::LinkSnapshot {
    use rustbgpd_transport::{InterfaceAddress, LinkSnapshot, LinkState};
    use std::collections::BTreeMap;
    LinkSnapshot {
        valid: true,
        links: BTreeMap::from([
            (
                1,
                LinkState {
                    name: "test1".into(),
                    admin_up: true,
                    lower_up: primary_up,
                },
            ),
            (
                2,
                LinkState {
                    name: "test2".into(),
                    admin_up: true,
                    lower_up: other_up,
                },
            ),
        ]),
        addresses: BTreeMap::from([(
            1,
            vec![InterfaceAddress {
                local: "127.0.0.1".parse().unwrap(),
                prefix: "127.0.0.0".parse().unwrap(),
                prefix_len: 8,
            }],
        )]),
    }
}

/// The manager replaces the Idle actor while the RIB holds its route. A
/// link check during the fresh actor's handshake must still purge that route.
#[expect(
    clippy::too_many_lines,
    reason = "one end-to-end scenario orders real route retention, actor replacement, and the owning carrier-loss purge"
)]
async fn retained_route_replacement(promote_candidate: bool) {
    use super::collision::{mock_open, read_bgp_message, send_bgp_message};
    use bytes::Bytes;

    let (rib_tx, rib_rx) = mpsc::channel(64);
    let rib = tokio::spawn(
        rustbgpd_rib::RibManager::new(rib_rx, mpsc::channel(1).1, None, None, BgpMetrics::new())
            .run(),
    );
    let (links_tx, links_rx) = tokio::sync::watch::channel(Arc::new(loopback_links(true, true)));
    let mut mgr = test_peer_manager().with_link_failover(links_rx);
    mgr.rib_tx = rib_tx.clone();
    let peer_addr = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let original_id = mgr.allocate_session_id();
    let (server, mut client) = super::inbound_admission::localhost_inbound_stream().await;
    let mut config = mgr.build_transport_config(&make_config(peer_addr, 65002));
    let unused = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    config.remote_addr = unused.local_addr().unwrap();
    drop(unused);
    let retained_config = config.clone();
    let handle = PeerHandle::spawn_inbound_with_identity(
        config,
        BgpMetrics::new(),
        rib_tx.clone(),
        None,
        None,
        server,
        None,
        None,
        None,
        None,
        false,
        rustbgpd_transport::SessionIdentity::primary(original_id),
    );
    insert_test_managed_peer(&mut mgr, peer_addr, handle, false);
    mgr.peers.get_mut(&key(peer_addr)).unwrap().transport_config = retained_config;
    mgr.peers[&key(peer_addr)]
        .handle()
        .start_inbound_timeout(0, Duration::from_secs(2))
        .await
        .unwrap();
    let mut buf = BytesMut::new();
    assert!(matches!(
        read_bgp_message(&mut client, &mut buf).await,
        Message::Open(_)
    ));
    let mut open = mock_open(Ipv4Addr::new(10, 0, 0, 2));
    open.capabilities.push(Capability::GracefulRestart {
        restart_state: false,
        notification: false,
        restart_time: 120,
        families: vec![rustbgpd_wire::GracefulRestartFamily {
            afi: Afi::Ipv4,
            safi: Safi::Unicast,
            forwarding_preserved: false,
        }],
    });
    send_bgp_message(&mut client, &Message::Open(open)).await;
    assert!(matches!(
        read_bgp_message(&mut client, &mut buf).await,
        Message::Keepalive
    ));
    send_bgp_message(&mut client, &Message::Keepalive).await;
    let handle = mgr.peers[&key(peer_addr)].handle();
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if handle.query_state().await.unwrap().fsm_state == SessionState::Established {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    send_bgp_message(
        &mut client,
        &Message::Update(rustbgpd_wire::UpdateMessage {
            withdrawn_routes: Bytes::new(),
            path_attributes: Bytes::from_static(&[
                0x40, 1, 1, 0, 0x40, 2, 6, 2, 1, 0, 0, 0xfd, 0xea, 0x40, 3, 4, 10, 0, 0, 2,
            ]),
            nlri: Bytes::from_static(&[24, 203, 0, 113]),
        }),
    )
    .await;
    let peer = mgr.rib_peer_of(&key(peer_addr));
    tokio::time::timeout(Duration::from_secs(5), async {
        while retained_routes(&rib_tx, peer).await.len() != 1 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    drop(client);
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if handle.query_state().await.unwrap().fsm_state == SessionState::Idle {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(
        retained_routes(&rib_tx, peer).await[0].is_stale,
        "ordinary TCP loss retains the route"
    );

    if promote_candidate {
        handle.start_timeout(Duration::from_secs(2)).await.unwrap();
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if matches!(
                    handle.query_state().await.unwrap().fsm_state,
                    SessionState::Connect | SessionState::Active
                ) {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }
    while mgr.session_notify_rx.try_recv().is_ok() {}
    let (server, mut replacement) = super::inbound_admission::localhost_inbound_stream().await;
    mgr.handle_inbound(server, sock(peer_addr), None, None)
        .await;
    if promote_candidate {
        assert!(mgr.peers[&key(peer_addr)].pending_inbound.is_some());
        let mut buf = BytesMut::new();
        assert!(matches!(
            read_bgp_message(&mut replacement, &mut buf).await,
            Message::Open(_)
        ));
        send_bgp_message(
            &mut replacement,
            &Message::Open(mock_open(Ipv4Addr::new(10, 0, 0, 2))),
        )
        .await;
        let notification =
            tokio::time::timeout(Duration::from_secs(5), mgr.session_notify_rx.recv())
                .await
                .unwrap()
                .unwrap();
        assert!(matches!(
            notification,
            SessionNotification::OpenReceived {
                role: rustbgpd_transport::SessionRole::InboundCandidate,
                ..
            }
        ));
        mgr.handle_session_notification(notification).await;
    }
    assert_ne!(mgr.peers[&key(peer_addr)].session_id(), original_id);
    assert_eq!(
        mgr.peers[&key(peer_addr)]
            .handle()
            .query_state()
            .await
            .unwrap()
            .fsm_state,
        if promote_candidate {
            SessionState::OpenConfirm
        } else {
            SessionState::OpenSent
        }
    );
    for snapshot in [
        rustbgpd_transport::LinkSnapshot::default(),
        loopback_links(true, false),
    ] {
        links_tx.send_replace(Arc::new(snapshot));
        mgr.handle_links_changed();
        // The command round trip orders the RIB read after CheckLinks.
        let _ = mgr.peers[&key(peer_addr)]
            .handle()
            .query_state()
            .await
            .unwrap();
        assert_eq!(
            retained_routes(&rib_tx, peer).await.len(),
            1,
            "unknown or unrelated link state does not purge retention"
        );
    }
    links_tx.send_replace(Arc::new(loopback_links(false, true)));
    mgr.handle_links_changed();
    let _ = mgr.peers[&key(peer_addr)]
        .handle()
        .query_state()
        .await
        .unwrap();
    assert!(
        retained_routes(&rib_tx, peer).await.is_empty(),
        "carrier loss during the replacement handshake purges immediately"
    );
    for (_, managed) in mgr.peers.drain() {
        let (handle, _, _) = managed.into_parts();
        let _ = handle.shutdown().await;
    }
    drop(mgr);
    drop(rib_tx);
    rib.await.unwrap();
}

#[tokio::test]
async fn inbound_replacement_keeps_gr_retained_route_link_provenance() {
    retained_route_replacement(false).await;
}

#[tokio::test]
async fn promoted_inbound_keeps_gr_retained_route_link_provenance() {
    retained_route_replacement(true).await;
}
