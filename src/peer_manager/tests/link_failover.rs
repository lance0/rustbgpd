use super::*;
use rustbgpd_transport::{InterfaceAddress, LinkDownCause, LinkDownEvent, PeerCommand};

fn recording_handle() -> (PeerHandle, mpsc::Receiver<PeerCommand>) {
    let (tx, rx) = mpsc::channel(8);
    let task = tokio::spawn(async { Ok(()) });
    (PeerHandle::from_parts(tx, task), rx)
}

fn event() -> Arc<LinkDownEvent> {
    event_on(4)
}

fn event_on(ifindex: u32) -> Arc<LinkDownEvent> {
    Arc::new(LinkDownEvent {
        ifindex,
        ifname: "eth0".into(),
        cause: LinkDownCause::CarrierLost,
        observed_at: std::time::Instant::now(),
        addresses: vec![InterfaceAddress {
            local: "10.0.0.1".parse().unwrap(),
            prefix: "10.0.0.0".parse().unwrap(),
            prefix_len: 30,
        }],
    })
}

fn got_interface_down(rx: &mut mpsc::Receiver<PeerCommand>) -> bool {
    matches!(rx.try_recv(), Ok(PeerCommand::InterfaceDown(_)))
}

/// Eligibility is knob + eBGP + enabled; the interface match itself is the
/// session's job, so every eligible session is a candidate.
#[tokio::test]
async fn link_down_reaches_only_eligible_sessions() {
    let mut mgr = test_peer_manager();
    let ebgp: IpAddr = "10.0.0.2".parse().unwrap();
    let ibgp: IpAddr = "10.0.0.3".parse().unwrap();
    let opted_out: IpAddr = "10.0.0.4".parse().unwrap();
    let disabled: IpAddr = "10.0.0.5".parse().unwrap();
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

    mgr.handle_link_down(&event());

    assert!(got_interface_down(&mut ebgp_rx), "eBGP peer is a candidate");
    assert!(!got_interface_down(&mut ibgp_rx), "iBGP is untouched");
    assert!(!got_interface_down(&mut opted_out_rx), "opt-out honored");
    assert!(
        !got_interface_down(&mut disabled_rx),
        "disabled peer untouched"
    );
}

#[tokio::test]
async fn link_down_also_reaches_a_pending_inbound_collision_candidate() {
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

    mgr.handle_link_down(&event());

    assert!(got_interface_down(&mut primary_rx));
    assert!(got_interface_down(&mut candidate_rx));
}

/// The opt-out is read when the event arrives, so a hot-applied change takes
/// effect without rebuilding the session.
#[tokio::test]
async fn hot_applied_opt_out_takes_effect_on_the_next_event() {
    let mut mgr = test_peer_manager();
    let peer: IpAddr = "10.0.0.2".parse().unwrap();
    let (handle, mut rx) = recording_handle();
    insert_test_managed_peer_with_asn(&mut mgr, peer, 65002, handle, false);
    let mut config = make_config(peer, 65002);
    config.fast_external_failover = false;
    mgr.hot_update_peer(config).await.expect("hot update");
    while rx.try_recv().is_ok() {}

    mgr.handle_link_down(&event());
    assert!(!got_interface_down(&mut rx));
}

/// A mailbox that is already full, as for a session busy with other work.
fn full_handle() -> (PeerHandle, mpsc::Receiver<PeerCommand>) {
    let (tx, rx) = mpsc::channel(1);
    tx.try_send(PeerCommand::Start).unwrap();
    let task = tokio::spawn(async { Ok(()) });
    (PeerHandle::from_parts(tx, task), rx)
}

/// An accept-any child whose ASN the manager has not learned is forwarded;
/// the session decides from its negotiated ASN.
#[tokio::test]
async fn link_down_defers_unlearned_asn_to_the_session() {
    let mut mgr = test_peer_manager();
    let peer: IpAddr = "10.0.0.2".parse().unwrap();
    let (handle, mut rx) = recording_handle();
    insert_test_managed_peer_with_asn(&mut mgr, peer, 0, handle, false);
    mgr.handle_link_down(&event());
    assert!(got_interface_down(&mut rx));
}

/// A flapping link against blocked mailboxes coalesces to one pending entry
/// per (session, interface), keeps distinct interfaces distinct, never exceeds
/// the bound, and delivers once the mailbox frees.
#[tokio::test]
async fn link_down_pending_is_coalesced_and_bounded() {
    let mut mgr = test_peer_manager();
    let mut mailboxes = Vec::new();
    for host in 0..3_u8 {
        let (handle, rx) = full_handle();
        let peer = IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 1, host));
        insert_test_managed_peer_with_asn(&mut mgr, peer, 65002, handle, false);
        mailboxes.push(rx);
    }
    for _ in 0..100 {
        mgr.handle_link_down(&event_on(4));
    }
    assert_eq!(
        mgr.link_down.pending.len(),
        3,
        "one per session for one link"
    );
    mgr.handle_link_down(&event_on(5));
    assert_eq!(
        mgr.link_down.pending.len(),
        6,
        "a second link stays distinct"
    );
    assert!(mgr.link_down.retry_at.is_some());

    // Free one mailbox: the retry delivers its two pending events in turn.
    let mailbox = &mut mailboxes[0];
    assert!(matches!(mailbox.try_recv(), Ok(PeerCommand::Start)));
    mgr.retry_link_down();
    assert!(got_interface_down(mailbox));
    assert_eq!(mgr.link_down.pending.len(), 5);

    // Saturation: far more blocked sessions than the bound.
    let mut mgr = test_peer_manager();
    let mut held = Vec::new();
    for index in 0..(super::super::link_failover::LINK_DOWN_PENDING_MAX + 50) {
        let (handle, rx) = full_handle();
        let index = u32::try_from(index).unwrap();
        let peer = IpAddr::V4(std::net::Ipv4Addr::from(0x0a00_0000 + index + 1));
        insert_test_managed_peer_with_asn(&mut mgr, peer, 65002, handle, false);
        held.push(rx);
    }
    for _ in 0..3 {
        mgr.handle_link_down(&event_on(4));
    }
    assert_eq!(
        mgr.link_down.pending.len(),
        super::super::link_failover::LINK_DOWN_PENDING_MAX
    );
}

fn address_removed(ifindex: u32, local: &str) -> Arc<LinkDownEvent> {
    Arc::new(LinkDownEvent {
        ifindex,
        ifname: "eth0".into(),
        cause: LinkDownCause::AddressRemoved,
        observed_at: std::time::Instant::now(),
        addresses: vec![InterfaceAddress {
            local: local.parse().unwrap(),
            prefix: local.parse().unwrap(),
            prefix_len: 32,
        }],
    })
}

fn delivered(rx: &mut mpsc::Receiver<PeerCommand>) -> Option<Arc<LinkDownEvent>> {
    match rx.try_recv() {
        Ok(PeerCommand::InterfaceDown(event)) => Some(event),
        _ => None,
    }
}

/// Events arriving faster than the retry interval must not keep pushing the
/// retry deadline out: the first armed deadline stands.
#[tokio::test(start_paused = true)]
async fn link_down_retry_is_not_starved_by_frequent_events() {
    let mut mgr = test_peer_manager();
    let (handle, mut rx) = full_handle();
    insert_test_managed_peer_with_asn(&mut mgr, "10.0.0.2".parse().unwrap(), 65002, handle, false);
    mgr.handle_link_down(&event_on(4));
    let armed = mgr.link_down.retry_at.expect("retry armed");
    for ifindex in 5..12 {
        tokio::time::advance(Duration::from_millis(50)).await;
        mgr.handle_link_down(&event_on(ifindex));
        assert_eq!(
            mgr.link_down.retry_at,
            Some(armed),
            "deadline must not slide"
        );
    }
    // The mailbox frees while events keep arriving; the retry delivers.
    assert!(matches!(rx.try_recv(), Ok(PeerCommand::Start)));
    mgr.retry_link_down();
    assert!(delivered(&mut rx).is_some());
}

/// Two address removals on one interface while the mailbox is blocked: both
/// are delivered, each with its own observation time, so the removal of the
/// session's source address is not overwritten by a later, unrelated one.
#[tokio::test]
async fn link_down_pending_keeps_distinct_address_removals() {
    let mut mgr = test_peer_manager();
    let (handle, mut rx) = full_handle();
    insert_test_managed_peer_with_asn(&mut mgr, "10.0.0.2".parse().unwrap(), 65002, handle, false);
    let source = address_removed(4, "10.0.0.1");
    let other = address_removed(4, "10.0.9.1");
    mgr.handle_link_down(&source);
    // A repeat of the same removal keeps the original observation time.
    mgr.handle_link_down(&address_removed(4, "10.0.0.1"));
    mgr.handle_link_down(&other);
    assert_eq!(mgr.link_down.pending.len(), 1);

    assert!(matches!(rx.try_recv(), Ok(PeerCommand::Start)));
    mgr.retry_link_down();
    let first = delivered(&mut rx).expect("source-address removal delivered");
    assert_eq!(first.addresses, source.addresses);
    assert_eq!(first.observed_at, source.observed_at);
    mgr.retry_link_down();
    let second = delivered(&mut rx).expect("second removal delivered");
    assert_eq!(second.addresses, other.addresses);
    mgr.retry_link_down();
    assert!(mgr.link_down.pending.is_empty());
    assert!(mgr.link_down.retry_at.is_none());
}

/// Past the per-entry cap, a further removal folds into the oldest one
/// rather than being dropped.
#[tokio::test]
async fn link_down_pending_address_overflow_folds_instead_of_dropping() {
    let mut mgr = test_peer_manager();
    let (handle, _rx) = full_handle();
    insert_test_managed_peer_with_asn(&mut mgr, "10.0.0.2".parse().unwrap(), 65002, handle, false);
    let max = super::super::link_failover::LINK_DOWN_PENDING_ADDRESSES_MAX;
    for host in 0..=max {
        let host = u8::try_from(host).unwrap();
        mgr.handle_link_down(&address_removed(4, &format!("10.0.0.{}", host + 1)));
    }
    let pending = mgr.link_down.pending.values().next().unwrap();
    assert_eq!(pending.addresses.len(), max);
    let overflow: IpAddr = format!("10.0.0.{}", max + 1).parse().unwrap();
    assert!(
        pending.addresses[0]
            .addresses
            .iter()
            .any(|address| address.local == overflow)
    );
}
