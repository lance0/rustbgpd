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

    mgr.handle_links_changed().await;

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
    mgr.handle_links_changed().await;
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
    mgr.handle_links_changed().await;
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
    mgr.handle_links_changed().await;
    let armed = mgr.link_check.retry_at.expect("retry armed");
    for _ in 0..10 {
        tokio::time::advance(Duration::from_millis(50)).await;
        mgr.handle_links_changed().await;
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
        mgr.handle_links_changed().await;
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
    mgr.handle_links_changed().await;
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
