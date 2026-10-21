use super::*;
use rustbgpd_transport::{InterfaceAddress, LinkDownCause, LinkDownEvent, PeerCommand};

fn recording_handle() -> (PeerHandle, mpsc::Receiver<PeerCommand>) {
    let (tx, rx) = mpsc::channel(8);
    let task = tokio::spawn(async { Ok(()) });
    (PeerHandle::from_parts(tx, task), rx)
}

fn event() -> Arc<LinkDownEvent> {
    Arc::new(LinkDownEvent {
        ifindex: 4,
        ifname: "eth0".into(),
        cause: LinkDownCause::CarrierLost,
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
