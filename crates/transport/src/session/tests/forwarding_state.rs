use super::*;
use std::sync::{
    Arc, RwLock,
    atomic::{AtomicUsize, Ordering},
};

#[derive(Debug, Default)]
struct CommittedRoles {
    kernel: RwLock<Vec<(Afi, Safi)>>,
    reads: AtomicUsize,
}

impl crate::LocalForwardingState for CommittedRoles {
    fn kernel_families(&self) -> Vec<(Afi, Safi)> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        self.kernel.read().unwrap().clone()
    }
}

fn forwarding_session() -> PeerSession {
    let mut config = PeerConfig::new(65001, 65002, Ipv4Addr::new(10, 0, 0, 1));
    config.families = vec![
        (Afi::Ipv4, Safi::Unicast),
        (Afi::Ipv6, Safi::Unicast),
        (Afi::Ipv4, Safi::FlowSpec),
        (Afi::L2Vpn, Safi::Evpn),
    ];
    config.llgr_stale_time = 120;
    config.graceful_restart = true;
    make_test_session_with_peer_config(config)
}

async fn outgoing_open(session: &mut PeerSession) -> rustbgpd_wire::OpenMessage {
    let (local, mut remote) = connected_stream_pair().await;
    session.test_install_stream(local);
    session.drive_fsm(Event::ManualStart).await;
    let Message::Open(open) =
        tokio::time::timeout(Duration::from_secs(2), read_single_bgp_message(&mut remote))
            .await
            .expect("OPEN must be emitted")
            .clone()
    else {
        panic!("expected OPEN");
    };
    open
}

fn assert_forwarding(
    open: &rustbgpd_wire::OpenMessage,
    expected: &[(Afi, Safi, bool)],
    restart: bool,
) {
    let mut gr = None;
    let mut llgr = None;
    for capability in &open.capabilities {
        match capability {
            Capability::GracefulRestart {
                restart_state,
                families,
                ..
            } => {
                assert_eq!(*restart_state, restart);
                gr = Some(
                    families
                        .iter()
                        .map(|f| (f.afi, f.safi, f.forwarding_preserved))
                        .collect::<Vec<_>>(),
                );
            }
            Capability::LongLivedGracefulRestart(families) => {
                llgr = Some(
                    families
                        .iter()
                        .map(|f| (f.afi, f.safi, f.forwarding_preserved))
                        .collect::<Vec<_>>(),
                );
            }
            _ => {}
        }
    }
    assert_eq!(gr.as_deref(), Some(expected));
    assert_eq!(llgr, gr, "both F bits use the same committed snapshot");
}

#[tokio::test]
async fn forwarding_state_serialized_gr_llgr_is_family_specific_and_independent_of_r() {
    for restart in [false, true] {
        let mut session = forwarding_session();
        session.config.local_forwarding_state =
            Some(crate::ForwardingStateSource::Configured(vec![
                (Afi::Ipv4, Safi::Unicast),
                (Afi::L2Vpn, Safi::Evpn),
            ]));
        session.config.gr_restart_until = restart.then(|| Instant::now() + Duration::from_secs(60));
        let open = outgoing_open(&mut session).await;
        assert_forwarding(
            &open,
            &[
                (Afi::Ipv4, Safi::Unicast, false),
                (Afi::Ipv6, Safi::Unicast, true),
                (Afi::Ipv4, Safi::FlowSpec, true),
                (Afi::L2Vpn, Safi::Evpn, false),
            ],
            restart,
        );
    }
}

#[tokio::test]
async fn forwarding_state_default_remains_conservative() {
    let mut session = forwarding_session();
    let open = outgoing_open(&mut session).await;
    assert_forwarding(
        &open,
        &[
            (Afi::Ipv4, Safi::Unicast, false),
            (Afi::Ipv6, Safi::Unicast, false),
            (Afi::Ipv4, Safi::FlowSpec, false),
            (Afi::L2Vpn, Safi::Evpn, false),
        ],
        false,
    );
}

#[tokio::test]
async fn forwarding_state_running_reconnect_samples_committed_roles_once() {
    let roles = Arc::new(CommittedRoles::default());
    let mut session = forwarding_session();
    session.config.local_forwarding_state = Some(crate::ForwardingStateSource::Live(roles.clone()));
    let first = outgoing_open(&mut session).await;
    assert_forwarding(
        &first,
        &[
            (Afi::Ipv4, Safi::Unicast, true),
            (Afi::Ipv6, Safi::Unicast, true),
            (Afi::Ipv4, Safi::FlowSpec, true),
            (Afi::L2Vpn, Safi::Evpn, true),
        ],
        false,
    );
    session.drive_fsm(Event::ManualStop { reason: None }).await;
    *roles.kernel.write().unwrap() = vec![(Afi::Ipv6, Safi::Unicast)];
    let second = outgoing_open(&mut session).await;
    assert_forwarding(
        &second,
        &[
            (Afi::Ipv4, Safi::Unicast, true),
            (Afi::Ipv6, Safi::Unicast, false),
            (Afi::Ipv4, Safi::FlowSpec, true),
            (Afi::L2Vpn, Safi::Evpn, true),
        ],
        false,
    );
    assert_eq!(roles.reads.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn forwarding_state_preconstructed_candidate_uses_latest_commit() {
    let roles = Arc::new(CommittedRoles::default());
    let mut peer = PeerConfig::new(65001, 65002, Ipv4Addr::new(10, 0, 0, 1));
    peer.graceful_restart = true;
    peer.families = vec![(Afi::Ipv4, Safi::Unicast)];
    let mut config = TransportConfig::new(peer, "127.0.0.1:179".parse().unwrap());
    config.local_forwarding_state = Some(crate::ForwardingStateSource::Live(roles.clone()));
    let (local, mut remote) = connected_stream_pair().await;
    let (_command_tx, command_rx) = mpsc::channel(8);
    let (rib_tx, _rib_rx) = mpsc::channel(8);
    let mut candidate = PeerSession::new_inbound_with_identity_and_lifecycle(
        config,
        BgpMetrics::new(),
        command_rx,
        rib_tx,
        None,
        None,
        local,
        None,
        None,
        None,
        None,
        None,
        false,
        SessionIdentity::inbound_candidate(2),
        None,
        None,
        crate::TcpAoRotationGeneration::STARTUP,
    );
    *roles.kernel.write().unwrap() = vec![(Afi::Ipv4, Safi::Unicast)];
    candidate.drive_fsm(Event::ManualStart).await;
    let Message::Open(open) =
        tokio::time::timeout(Duration::from_secs(2), read_single_bgp_message(&mut remote))
            .await
            .expect("candidate must emit OPEN")
    else {
        panic!("expected OPEN");
    };
    assert!(open.capabilities.iter().any(|cap| matches!(cap,
        Capability::GracefulRestart { families, .. } if families.len() == 1 && !families[0].forwarding_preserved)));
    assert_eq!(roles.reads.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn forwarding_state_does_not_add_disabled_capabilities_or_families() {
    let mut config = PeerConfig::new(65001, 65002, Ipv4Addr::new(10, 0, 0, 1));
    config.graceful_restart = false;
    config.llgr_stale_time = 120;
    let mut session = make_test_session_with_peer_config(config.clone());
    session.config.local_forwarding_state = Some(crate::ForwardingStateSource::Configured(vec![]));
    let open = outgoing_open(&mut session).await;
    assert!(!open.capabilities.iter().any(|cap| matches!(
        cap,
        Capability::GracefulRestart { .. } | Capability::LongLivedGracefulRestart(_)
    )));

    config.graceful_restart = true;
    config.disable_ipv4_unicast = true;
    config.families = vec![(Afi::Ipv6, Safi::Unicast)];
    let mut session = make_test_session_with_peer_config(config);
    session.config.local_forwarding_state = Some(crate::ForwardingStateSource::Configured(vec![]));
    let open = outgoing_open(&mut session).await;
    assert_forwarding(&open, &[(Afi::Ipv6, Safi::Unicast, true)], false);
}
