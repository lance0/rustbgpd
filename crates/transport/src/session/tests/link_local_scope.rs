//! A scoped link-local peer follows its interface by name: each connect
//! attempt re-resolves the scope, so a deleted and recreated interface (same
//! name, new index) is dialed at its new index.

use super::*;
use crate::link::{LinkSnapshot, LinkState, LinkStateFeed};
use std::collections::BTreeMap;
use tokio::sync::watch;

const MISSING: &str = "rbgp-ll-missing0";

fn snapshot_with(name: &str, ifindex: u32) -> LinkSnapshot {
    LinkSnapshot {
        valid: true,
        links: BTreeMap::from([(
            ifindex,
            LinkState {
                name: name.into(),
                admin_up: true,
                lower_up: true,
            },
        )]),
        addresses: BTreeMap::new(),
    }
}

fn scoped_config(interface: &str, scope: u32, snapshot: LinkSnapshot) -> TransportConfig {
    let mut peer_config = PeerConfig::new(65001, 65002, Ipv4Addr::new(10, 0, 0, 1));
    peer_config.families = vec![(Afi::Ipv6, Safi::Unicast)];
    let mut config = TransportConfig::new(
        peer_config,
        SocketAddr::V6(std::net::SocketAddrV6::new(
            "fe80::2".parse().unwrap(),
            179,
            0,
            scope,
        )),
    );
    config.peer_interface = Some(interface.to_owned());
    config.peer_scope_id = Some(scope);
    let (_tx, rx) = watch::channel(Arc::new(snapshot));
    config.link_state = LinkStateFeed::new(rx, true);
    config
}

fn scope_of(config: &TransportConfig) -> Option<u32> {
    match config.remote_addr {
        SocketAddr::V6(addr) => Some(addr.scope_id()),
        SocketAddr::V4(_) => None,
    }
}

#[test]
fn refresh_follows_the_current_index_by_name() {
    let mut config = scoped_config("eth1", 4, snapshot_with("eth1", 9));
    assert_eq!(config.refresh_link_local_scope(), Ok(true));
    assert_eq!(config.peer_scope_id, Some(9));
    assert_eq!(scope_of(&config), Some(9));
    assert_eq!(config.refresh_link_local_scope(), Ok(false), "unchanged");
}

#[test]
fn refresh_reports_a_missing_interface_and_keeps_the_old_scope() {
    let mut config = scoped_config(MISSING, 4, snapshot_with("eth1", 9));
    assert_eq!(config.refresh_link_local_scope(), Err(MISSING.to_owned()));
    assert_eq!(config.peer_scope_id, Some(4));
}

/// With no valid snapshot (monitor absent, or between dumps) the kernel is
/// asked directly.
#[test]
fn refresh_falls_back_to_the_kernel_without_a_valid_snapshot() {
    let mut invalid = snapshot_with("lo", 77);
    invalid.valid = false;
    let mut config = scoped_config("lo", 4, invalid);
    let lo = crate::socket_opts::interface_index("lo").expect("loopback exists");
    assert_eq!(config.refresh_link_local_scope(), Ok(lo != 4));
    assert_eq!(config.peer_scope_id, Some(lo));
}

#[test]
fn numbered_peers_are_not_rescoped() {
    let mut config = TransportConfig::new(
        PeerConfig::new(65001, 65002, Ipv4Addr::new(10, 0, 0, 1)),
        "10.0.0.2:179".parse().unwrap(),
    );
    config.peer_interface = Some("eth1".into());
    assert_eq!(config.refresh_link_local_scope(), Ok(false));
    assert_eq!(config.peer_scope_id, None);
}

fn scoped_session(config: TransportConfig) -> PeerSession {
    let metrics = BgpMetrics::new();
    let (_cmd_tx, cmd_rx) = mpsc::channel(8);
    let (rib_tx, _rib_rx) = mpsc::channel(64);
    PeerSession::new(
        config, metrics, cmd_rx, rib_tx, None, None, None, None, None, false,
    )
}

/// The connect attempt dials the recreated interface's index and carries it
/// into the next-hop scope of routes learned on the new session.
#[tokio::test]
async fn a_connect_attempt_dials_the_recreated_interface_index() {
    let mut session = scoped_session(scoped_config("eth1", 4, snapshot_with("eth1", 9)));
    assert_eq!(
        session.link_local_next_hop_scope.as_ref().unwrap().ifindex,
        4
    );
    session.start_connect_attempt();
    assert_eq!(scope_of(&session.config), Some(9));
    assert_eq!(session.config.peer_scope_id, Some(9));
    assert_eq!(
        session.link_local_next_hop_scope.as_ref().unwrap().ifindex,
        9
    );
    if let Some(task) = session.connect_task.take() {
        task.abort();
    }
}

/// No interface by that name now: "cannot dial yet", reported as a failed
/// connect attempt (so the retry timer runs), never a stale index.
#[tokio::test]
async fn a_missing_interface_fails_the_attempt_without_dialing() {
    let mut session = scoped_session(scoped_config(MISSING, 4, snapshot_with("eth1", 9)));
    session.start_connect_attempt();
    let task = session.connect_task.take().expect("attempt recorded");
    let error = task.await.unwrap().expect_err("cannot dial yet");
    assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
    assert!(error.to_string().contains(MISSING), "{error}");
    assert_eq!(session.config.peer_scope_id, Some(4));
}

/// Acceptance: two sessions on one link-local address, on different
/// interfaces, label their series with their own scoped `peer` value, so
/// their message counters (`messages_received`/`messages_sent` in neighbor
/// state) and every other session series stay per neighbor.
#[tokio::test]
async fn same_address_sessions_label_their_series_by_interface() {
    let metrics = BgpMetrics::new();
    let session = |interface: &str, scope: u32| {
        let (_cmd_tx, cmd_rx) = mpsc::channel(8);
        let (rib_tx, _rib_rx) = mpsc::channel(8);
        PeerSession::new_with_identity_and_lifecycle(
            scoped_config(interface, scope, snapshot_with(interface, scope)),
            metrics.clone(),
            cmd_rx,
            rib_tx,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            false,
            SessionIdentity::default(),
        )
    };
    let (eth0, eth1) = (session("eth0", 2), session("eth1", 3));
    assert_eq!(eth0.peer_label, "fe80::2%eth0");
    assert_eq!(eth1.peer_label, "fe80::2%eth1");
    metrics.record_message_received(&eth0.peer_label, "update");
    metrics.record_message_sent(&eth1.peer_label, "keepalive");
    assert_eq!(metrics.peer_message_totals(&eth0.peer_label), (1, 0));
    assert_eq!(metrics.peer_message_totals(&eth1.peer_label), (0, 1));
}
