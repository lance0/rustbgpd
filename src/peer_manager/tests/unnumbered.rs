//! ADR-0142 interface-only neighbors: binding, address change, carrier loss
//! and the duplicate-address admission guard, driven through the discovery
//! event stream and the link snapshot.

use std::net::Ipv6Addr;

use rustbgpd_fsm::SessionState;
use rustbgpd_rib::PeerId;
use rustbgpd_transport::{LinkSnapshot, LinkState as KernelLink};
use tokio::sync::watch;

use super::*;
use crate::ra_discovery::{Command, DiscoveryEvent, Endpoint, LinkEvent, LinkState, RaDiscovery};

fn ll(last: u16) -> Ipv6Addr {
    Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, last)
}

/// Interfaces by (name, ifindex, carrier up).
fn snapshot(valid: bool, links: &[(&str, u32, bool)]) -> Arc<LinkSnapshot> {
    Arc::new(LinkSnapshot {
        valid,
        links: links
            .iter()
            .map(|&(name, ifindex, up)| {
                (
                    ifindex,
                    KernelLink {
                        name: name.into(),
                        admin_up: true,
                        lower_up: up,
                    },
                )
            })
            .collect(),
        addresses: std::collections::BTreeMap::new(),
    })
}

struct Harness {
    mgr: PeerManager,
    commands: mpsc::UnboundedReceiver<Command>,
    links: watch::Sender<Arc<LinkSnapshot>>,
    rib_rx: mpsc::Receiver<RibUpdate>,
}

/// A manager with one interface-only neighbor per name in `interfaces`
/// (`remote_asn = "external"`), discovery recorded, and `links` reported by
/// the link monitor.
fn harness(interfaces: &[&str], links: &[(&str, u32, bool)]) -> Harness {
    let (_tx, rx) = mpsc::channel(16);
    let (rib_tx, rib_rx) = mpsc::channel(64);
    let mut mgr = PeerManager::new(
        rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        BgpMetrics::new(),
        rib_tx,
        None,
    );
    let neighbors = interfaces
        .iter()
        .map(|name| {
            format!(
                "[[neighbors]]\ninterface = \"{name}\"\nremote_asn = \"external\"\nfamilies = [\"ipv6_unicast\"]\n"
            )
        })
        .collect::<Vec<_>>()
        .concat();
    let config: crate::config::Config = toml::from_str(&format!(
        "[global]\nasn = 65001\nrouter_id = \"10.0.0.1\"\nlisten_port = 179\n\
         [global.telemetry]\nlog_format = \"json\"\n{neighbors}"
    ))
    .unwrap();
    mgr.current_config = config;
    let (links_tx, links_rx) = watch::channel(snapshot(true, links));
    let (discovery, commands) = RaDiscovery::recording();
    let (_events_tx, events_rx) = mpsc::unbounded_channel();
    let mgr = mgr
        .with_link_failover(links_rx)
        .with_unnumbered(Unnumbered::new(discovery, events_rx));
    Harness {
        mgr,
        commands,
        links: links_tx,
        rib_rx,
    }
}

impl Harness {
    fn drain(&mut self) -> Vec<Command> {
        std::iter::from_fn(|| self.commands.try_recv().ok()).collect()
    }

    async fn bind(&mut self, interface: &str, current: Option<Endpoint>) {
        self.mgr
            .handle_discovery_event(DiscoveryEvent::BindingChanged {
                interface: interface.into(),
                previous: None,
                current,
            });
        self.reconcile().await;
    }

    async fn reconcile(&mut self) {
        if self.mgr.unnumbered_reconcile_due() {
            self.mgr.reconcile_unnumbered().await;
        }
    }

    fn links_changed(&mut self, snapshot: Arc<LinkSnapshot>) {
        self.links.send_replace(snapshot);
        self.mgr.handle_links_changed();
    }

    /// Swap the bound peer's session for `handle`, keeping its scope.
    fn replace_session(&mut self, key: &PeerKey, handle: PeerHandle) {
        let scope = self.mgr.peers[key].transport_config.peer_scope_id;
        insert_test_managed_peer_for_key(&mut self.mgr, key, 0, handle, false);
        self.mgr
            .peers
            .get_mut(key)
            .unwrap()
            .transport_config
            .set_link_local_scope(scope.unwrap());
    }

    fn peers_at(&self, address: Ipv6Addr) -> Vec<PeerKey> {
        self.mgr.peer_keys_for_address(IpAddr::V6(address))
    }
}

fn endpoint(last: u16, ifindex: u32) -> Endpoint {
    Endpoint {
        address: ll(last),
        ifindex,
    }
}

fn swp1_key(last: u16) -> PeerKey {
    PeerKey::new(IpAddr::V6(ll(last)), Some("swp1".into()))
}

#[tokio::test]
async fn a_binding_becomes_a_scoped_peer_and_session_state_reaches_discovery() {
    let mut h = harness(&["swp1"], &[("swp1", 7, true)]);
    assert_eq!(
        h.drain(),
        [
            Command::Start("swp1".into()),
            Command::Link(LinkEvent {
                ifindex: 7,
                name: "swp1".into(),
                state: LinkState::Up,
            }),
        ]
    );

    h.bind("swp1", Some(endpoint(2, 7))).await;
    let key = swp1_key(2);
    let managed = h.mgr.peers.get(&key).expect("bound peer added");
    assert_eq!(managed.transport_config.peer_scope_id, Some(7));
    assert!(managed.transport_config.peer.remote_asn_external);
    assert!(managed.transport_config.fast_external_failover);

    h.mgr
        .note_unnumbered_session_state(&key, SessionState::OpenConfirm, SessionState::Established);
    assert_eq!(h.drain(), [Command::SessionEstablished("swp1".into())]);
    h.mgr
        .note_unnumbered_session_state(&key, SessionState::Established, SessionState::Idle);
    assert_eq!(h.drain(), [Command::SessionFailed("swp1".into())]);
}

#[tokio::test]
async fn an_address_change_replaces_the_peer_only_once_the_session_is_down() {
    let mut h = harness(&["swp1"], &[("swp1", 7, true)]);
    h.bind("swp1", Some(endpoint(2, 7))).await;
    h.mgr.note_unnumbered_session_state(
        &swp1_key(2),
        SessionState::OpenConfirm,
        SessionState::Established,
    );

    // Mutation-red: dropping the Established guard ends the healthy session.
    h.bind("swp1", Some(endpoint(3, 7))).await;
    assert!(
        h.mgr.peers.contains_key(&swp1_key(2)),
        "never displaced while Established"
    );
    assert!(!h.mgr.peers.contains_key(&swp1_key(3)));

    h.mgr.note_unnumbered_session_state(
        &swp1_key(2),
        SessionState::Established,
        SessionState::Idle,
    );
    h.reconcile().await;
    assert!(
        !h.mgr.peers.contains_key(&swp1_key(2)),
        "old endpoint purged"
    );
    assert!(
        h.mgr.peers.contains_key(&swp1_key(3)),
        "same neighbor, new endpoint"
    );
}

/// An address change is a session down then up under the same RIB
/// identity: the old endpoint's peer is deleted without releasing the
/// handle, and the RIB moves the handle to the new endpoint before the new
/// session starts.
#[tokio::test]
async fn an_address_change_keeps_the_neighbors_rib_identity() {
    let mut h = harness(&["swp1"], &[("swp1", 7, true)]);
    h.bind("swp1", Some(endpoint(2, 7))).await;
    let first = h.mgr.rib_peer_of(&swp1_key(2));
    assert_ne!(
        first,
        PeerId::from_addr(IpAddr::V6(ll(2))),
        "an allocated handle"
    );
    assert_eq!(first.interface().as_deref(), Some("swp1"));
    while h.rib_rx.try_recv().is_ok() {}

    h.bind("swp1", Some(endpoint(3, 7))).await;
    assert!(h.mgr.peers.contains_key(&swp1_key(3)));
    assert_eq!(
        h.mgr.rib_peer_of(&swp1_key(3)),
        first,
        "same neighbor, same handle"
    );
    let sent: Vec<RibUpdate> = std::iter::from_fn(|| h.rib_rx.try_recv().ok()).collect();
    let deleted = sent
        .iter()
        .position(|update| matches!(update, RibUpdate::PeerDeleted { peer, .. } if *peer == first))
        .expect("the old endpoint's state is deleted");
    let rebound = sent
        .iter()
        .position(|update| {
            matches!(update, RibUpdate::RebindPeer { peer, endpoint }
                if *peer == first && endpoint.addr == IpAddr::V6(ll(3))
                    && endpoint.interface.as_deref() == Some("swp1"))
        })
        .expect("the handle moves to the new endpoint");
    assert!(deleted < rebound);
    assert!(
        !sent
            .iter()
            .any(|update| matches!(update, RibUpdate::ReleasePeer { .. })),
        "the handle is never released"
    );
    assert!(first.is_live());
}

/// The RIB applies rebinds in its own message order, so the peer manager
/// cannot skip one by reading the handle's current endpoint: with A → B
/// still queued, the move back to A must be queued too, or the RIB lands
/// on B while the session runs at A.
#[tokio::test]
async fn a_change_back_to_the_previous_endpoint_is_queued_behind_a_pending_rebind() {
    let mut h = harness(&["swp1"], &[("swp1", 7, true)]);
    h.bind("swp1", Some(endpoint(2, 7))).await;
    let handle = h.mgr.rib_peer_of(&swp1_key(2));
    while h.rib_rx.try_recv().is_ok() {}

    // Nothing drains the RIB channel, so the table still says ll(2).
    h.bind("swp1", Some(endpoint(3, 7))).await;
    h.bind("swp1", Some(endpoint(2, 7))).await;
    assert_eq!(h.mgr.rib_peer_of(&swp1_key(2)), handle);
    let rebinds: Vec<IpAddr> = std::iter::from_fn(|| h.rib_rx.try_recv().ok())
        .filter_map(|update| match update {
            RibUpdate::RebindPeer { peer, endpoint } if peer == handle => Some(endpoint.addr),
            _ => None,
        })
        .collect();
    assert_eq!(rebinds, [IpAddr::V6(ll(3)), IpAddr::V6(ll(2))]);
}

#[tokio::test]
async fn a_lost_binding_keeps_the_peer_while_the_link_is_up() {
    let mut h = harness(&["swp1"], &[("swp1", 7, true)]);
    h.bind("swp1", Some(endpoint(2, 7))).await;
    // Mutation-red: treating a lost binding as an unbind removes the peer.
    h.bind("swp1", None).await;
    assert!(h.mgr.peers.contains_key(&swp1_key(2)));
}

#[tokio::test]
async fn confirmed_carrier_loss_removes_the_peer_and_an_invalid_snapshot_does_nothing() {
    let mut h = harness(&["swp1"], &[("swp1", 7, true)]);
    h.bind("swp1", Some(endpoint(2, 7))).await;
    h.drain();

    // Unknown is never down: a snapshot that cannot be trusted, even one
    // that shows the carrier gone, passes nothing on and removes nothing.
    h.links_changed(snapshot(false, &[("swp1", 7, false)]));
    assert_eq!(h.drain(), [], "nothing replayed from an invalid snapshot");
    h.reconcile().await;
    assert!(h.mgr.peers.contains_key(&swp1_key(2)));

    // Mutation-red: ignoring a confirmed Down keeps the peer and its routes.
    h.links_changed(snapshot(true, &[("swp1", 7, false)]));
    assert_eq!(
        h.drain(),
        [Command::Link(LinkEvent {
            ifindex: 7,
            name: "swp1".into(),
            state: LinkState::Down,
        })]
    );
    h.reconcile().await;
    assert!(
        !h.mgr.peers.contains_key(&swp1_key(2)),
        "carrier loss purges"
    );
    assert_eq!(h.drain(), [Command::SessionFailed("swp1".into())]);

    // The level is passed on once, not per publication.
    h.links_changed(snapshot(true, &[("swp1", 7, false)]));
    assert_eq!(h.drain(), []);

    // Removal of the interface is passed on with its last index.
    h.links_changed(snapshot(true, &[]));
    assert_eq!(
        h.drain(),
        [Command::Link(LinkEvent {
            ifindex: 7,
            name: "swp1".into(),
            state: LinkState::Removed,
        })]
    );
}

#[tokio::test]
async fn two_links_discovering_one_address_admit_exactly_one() {
    let mut h = harness(&["swp1", "swp2"], &[("swp1", 7, true), ("swp2", 8, true)]);
    h.mgr
        .handle_discovery_event(DiscoveryEvent::BindingChanged {
            interface: "swp1".into(),
            previous: None,
            current: Some(endpoint(2, 7)),
        });
    h.mgr
        .handle_discovery_event(DiscoveryEvent::BindingChanged {
            interface: "swp2".into(),
            previous: None,
            current: Some(endpoint(2, 8)),
        });
    h.reconcile().await;
    // Mutation-red: removing the admission check admits both.
    assert_eq!(h.peers_at(ll(2)), [swp1_key(2)]);

    // No sticky refusal: once the admitted link loses carrier, the other is
    // admitted.
    h.links_changed(snapshot(true, &[("swp1", 7, false), ("swp2", 8, true)]));
    h.reconcile().await;
    assert_eq!(
        h.peers_at(ll(2)),
        [PeerKey::new(IpAddr::V6(ll(2)), Some("swp2".into()))]
    );
}

#[tokio::test]
async fn learned_and_static_admission_refuse_each_other_duplicate_link_local_address() {
    let mut h = harness(&["swp1", "swp2"], &[("swp1", 7, true), ("swp2", 8, true)]);
    h.bind("swp1", Some(endpoint(2, 7))).await;

    // Static admission against a bound learned address.
    let mut static_peer = make_config(IpAddr::V6(ll(2)), 65002);
    static_peer.interface = Some("eth9".into());
    static_peer.scope_id = Some(9);
    let error = h.mgr.add_peer(static_peer, false).await.unwrap_err();
    assert!(
        error.to_string().contains("duplicate_link_local_address"),
        "{error}"
    );

    // Learned admission against a static neighbor's address.
    let mut static_peer = make_config(IpAddr::V6(ll(5)), 65002);
    static_peer.interface = Some("eth9".into());
    static_peer.scope_id = Some(9);
    h.mgr.add_peer(static_peer, false).await.unwrap();
    h.bind("swp2", Some(endpoint(5, 8))).await;
    assert_eq!(
        h.peers_at(ll(5)),
        [PeerKey::new(IpAddr::V6(ll(5)), Some("eth9".into()))]
    );
}

#[tokio::test]
async fn operator_deletion_of_a_discovery_owned_peer_is_refused() {
    let mut h = harness(&["swp1"], &[("swp1", 7, true)]);
    h.bind("swp1", Some(endpoint(2, 7))).await;
    // Mutation-red: without the ownership check the RPC deletes the peer and
    // discovery stays bound to nothing.
    let Err(error) = h.mgr.delete_peer_runtime(swp1_key(2), true).await else {
        panic!("deletion of a discovery-owned peer must be refused");
    };
    assert!(
        matches!(
            error,
            rustbgpd_api::peer_types::PeerLifecycleError::RestartRequired(_)
        ),
        "{error}"
    );
    assert!(
        error.to_string().contains("interface = \"swp1\""),
        "{error}"
    );
    assert!(h.mgr.peers.contains_key(&swp1_key(2)));
}

#[tokio::test]
async fn a_bound_peer_already_gone_is_cleared_on_reconcile() {
    let mut h = harness(&["swp1"], &[("swp1", 7, true)]);
    h.bind("swp1", Some(endpoint(2, 7))).await;
    // The peer leaves the table without discovery's reconcile.
    h.mgr.delete_peer(swp1_key(2), false).await.unwrap();
    // Mutation-red: treating NotFound as a failed removal keeps `bound` set
    // and the new address is never admitted.
    h.bind("swp1", Some(endpoint(3, 7))).await;
    assert!(h.mgr.peers.contains_key(&swp1_key(3)));
}

#[tokio::test]
async fn an_external_peers_identity_series_shows_the_open_asn() {
    let mut mgr = test_peer_manager();
    let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let peer = key(addr);
    insert_test_managed_peer_with_asn(
        &mut mgr,
        addr,
        0,
        fake_peer_handle(
            addr,
            SessionState::OpenSent,
            None,
            Arc::new(FakePeerCounters::default()),
        ),
        false,
    );
    mgr.peers
        .get_mut(&peer)
        .unwrap()
        .transport_config
        .peer
        .remote_asn_external = true;
    mgr.publish_peer_info_metric(&peer);
    let session_id = mgr.peers[&peer].session_id();
    mgr.handle_session_notification(SessionNotification::OpenReceived {
        session_id,
        role: rustbgpd_transport::SessionRole::Primary,
        peer_addr: addr,
        remote_router_id: Ipv4Addr::new(10, 0, 0, 2),
        peer_asn: 65002,
    })
    .await;

    // Mutation-red: learning only for dynamic peers leaves the label at 0.
    let label = mgr
        .metrics
        .registry()
        .gather()
        .into_iter()
        .find(|family| family.name() == "bgp_peer_info")
        .and_then(|family| {
            family.get_metric().iter().find_map(|metric| {
                let labels = metric.get_label();
                labels
                    .iter()
                    .any(|l| l.name() == "peer" && l.value() == "10.0.0.2")
                    .then(|| {
                        labels
                            .iter()
                            .find(|l| l.name() == "remote_asn")
                            .map(|l| l.value().to_string())
                    })
                    .flatten()
            })
        });
    assert_eq!(label.as_deref(), Some("65002"));
    // The configured mode is untouched: any other ASN still matches.
    let transport = &mgr.peers[&peer].transport_config.peer;
    assert!(transport.remote_asn_external);
    assert_eq!(transport.remote_asn, 0);
}

/// The lossy `StateChanged` stream may drop Established→Idle. The lossless
/// `BackToIdle` notification still releases discovery, so the port converges
/// on the new address.
#[tokio::test]
async fn a_dropped_established_to_idle_transition_still_converges() {
    let mut h = harness(&["swp1"], &[("swp1", 7, true)]);
    h.bind("swp1", Some(endpoint(2, 7))).await;
    h.mgr.note_unnumbered_session_state(
        &swp1_key(2),
        SessionState::OpenConfirm,
        SessionState::Established,
    );
    h.drain();
    // Established -> Idle is never delivered; only BackToIdle arrives.
    let session_id = h.mgr.peers[&swp1_key(2)].session_id();
    h.mgr
        .handle_session_notification(SessionNotification::BackToIdle {
            session_id,
            role: rustbgpd_transport::SessionRole::Primary,
            peer_addr: IpAddr::V6(ll(2)),
        })
        .await;
    // Mutation-red: without the BackToIdle hook discovery stays frozen and
    // the bound session counts as Established forever.
    assert_eq!(h.drain(), [Command::SessionFailed("swp1".into())]);
    h.bind("swp1", Some(endpoint(3, 7))).await;
    assert!(h.mgr.peers.contains_key(&swp1_key(3)));
    assert!(!h.mgr.peers.contains_key(&swp1_key(2)));
}

/// A dropped Idle→Established transition leaves the port believing the
/// session is down. Reconciliation reads the session's state before
/// replacing it, so a healthy session is never displaced.
#[tokio::test]
async fn a_dropped_transition_to_established_never_displaces_the_session() {
    let mut h = harness(&["swp1"], &[("swp1", 7, true)]);
    h.bind("swp1", Some(endpoint(2, 7))).await;
    h.drain();
    // The bound session is Established, but no transition said so.
    h.replace_session(
        &swp1_key(2),
        fake_peer_handle(
            IpAddr::V6(ll(2)),
            SessionState::Established,
            None,
            Arc::new(FakePeerCounters::default()),
        ),
    );
    // Mutation-red: trusting the edge-event flag alone replaces it.
    h.bind("swp1", Some(endpoint(3, 7))).await;
    assert!(h.mgr.peers.contains_key(&swp1_key(2)), "kept");
    assert!(!h.mgr.peers.contains_key(&swp1_key(3)));
    assert_eq!(h.drain(), [Command::SessionEstablished("swp1".into())]);
}

/// A bound session that does not answer its state query is kept, nothing is
/// claimed to discovery, and reconciliation is retried.
#[tokio::test(start_paused = true)]
async fn an_unanswered_state_query_keeps_the_session_and_retries() {
    let mut h = harness(&["swp1"], &[("swp1", 7, true)]);
    h.bind("swp1", Some(endpoint(2, 7))).await;
    h.drain();
    // A session task that never answers.
    let (commands, _held) = mpsc::channel(8);
    let silent = PeerHandle::from_parts(commands, tokio::spawn(async { Ok(()) }));
    h.replace_session(&swp1_key(2), silent);

    h.bind("swp1", Some(endpoint(3, 7))).await;
    assert!(h.mgr.peers.contains_key(&swp1_key(2)), "kept on doubt");
    assert!(!h.mgr.peers.contains_key(&swp1_key(3)));
    // Mutation-red: asserting Established to discovery on a timeout freezes
    // the binding until the next BackToIdle, and no retry is armed.
    assert_eq!(h.drain(), []);
    assert!(h.mgr.unnumbered_retry_at().is_some(), "retry armed");
    h.mgr.unnumbered_retry_due();
    assert!(h.mgr.unnumbered_reconcile_due());
}

/// A peer-group edit that changes an interface-only neighbor's session
/// settings is reported restart-required for it.
#[test]
fn a_group_session_edit_is_restart_required_for_its_interface_only_neighbor() {
    let config = |hold: u16| -> crate::config::Config {
        toml::from_str(&format!(
            "[global]\nasn = 65001\nrouter_id = \"10.0.0.1\"\nlisten_port = 179\n\
             [global.telemetry]\nlog_format = \"json\"\n\
             [peer_groups.fabric]\nhold_time = {hold}\n\
             [peer_groups.other]\nhold_time = 90\n\
             [[neighbors]]\ninterface = \"swp1\"\nremote_asn = \"external\"\npeer_group = \"fabric\"\n"
        ))
        .unwrap()
    };
    let (old, new) = (config(9), config(30));
    // Mutation-red: comparing only the neighbor records misses the edit.
    assert_eq!(
        crate::config::interface_only_session_changes(&old, &new),
        ["swp1"]
    );
    assert!(crate::config::diff_config(&old, &new).interface_only_neighbors_changed);
    // Group-inherited settings the manager owns, outside the transport
    // config. Mutation-red: comparing the transport config alone misses both.
    let with_group = |group: &str| {
        let mut config = old.clone();
        config.peer_groups.insert(
            "fabric".to_string(),
            toml::from_str::<crate::config::PeerGroupConfig>(group).unwrap(),
        );
        config
    };
    for (before, after) in [
        ("hold_time = 9", "hold_time = 9\nadmin_down = true"),
        (
            "hold_time = 9\nmax_prefixes = 10",
            "hold_time = 9\nmax_prefixes = 10\nmax_prefix_restart_seconds = 60",
        ),
    ] {
        assert_eq!(
            crate::config::interface_only_session_changes(&with_group(before), &with_group(after)),
            ["swp1"],
            "{after}"
        );
    }
    let mut unrelated: crate::config::Config = old.clone();
    unrelated.peer_groups.get_mut("other").unwrap().hold_time = Some(60);
    assert_eq!(
        crate::config::interface_only_session_changes(&old, &unrelated),
        Vec::<&str>::new()
    );
}

/// A max-prefix shutdown and an operator disable belong to the neighbor:
/// carrier loss and a new learned address do not lift them.
#[tokio::test(start_paused = true)]
async fn operator_and_max_prefix_state_survive_endpoint_retirement() {
    let mut h = harness(&["swp1"], &[("swp1", 7, true)]);
    h.bind("swp1", Some(endpoint(2, 7))).await;
    let old = swp1_key(2);
    let session = h.mgr.peers[&old].session_id();
    h.mgr
        .install_max_prefix_latch(old.clone(), session, "max-prefix".into(), Some(60));
    if let Some(managed) = h.mgr.peers.get_mut(&old) {
        managed.enabled = false;
    }
    let deadline = h.mgr.max_prefix_latches[&old].deadline;

    // Carrier flap, then the same address again.
    h.links_changed(snapshot(true, &[("swp1", 7, false)]));
    h.reconcile().await;
    assert!(!h.mgr.peers.contains_key(&old));
    h.links_changed(snapshot(true, &[("swp1", 7, true)]));
    h.bind("swp1", Some(endpoint(2, 7))).await;
    // Mutation-red: a fresh peer comes back enabled with no latch.
    assert!(!h.mgr.peers[&old].enabled, "still disabled");
    assert_eq!(
        h.mgr.max_prefix_latches[&old].deadline, deadline,
        "same deadline"
    );

    // A new learned address: the latch and its deadline migrate.
    h.links_changed(snapshot(true, &[("swp1", 7, false)]));
    h.reconcile().await;
    h.links_changed(snapshot(true, &[("swp1", 7, true)]));
    h.bind("swp1", Some(endpoint(3, 7))).await;
    let new = swp1_key(3);
    assert!(!h.mgr.peers[&new].enabled);
    assert_eq!(h.mgr.max_prefix_latches[&new].deadline, deadline);
    assert!(!h.mgr.max_prefix_latches.contains_key(&old));

    // An explicit enable still lifts it.
    h.mgr.enable_peer(new.clone()).await.unwrap();
    assert!(h.mgr.peers[&new].enabled);
    assert!(!h.mgr.max_prefix_latches.contains_key(&new));
}

/// An operator disable alone (no latch) also survives a carrier flap.
#[tokio::test]
async fn an_operator_disable_survives_a_carrier_flap() {
    let mut h = harness(&["swp1"], &[("swp1", 7, true)]);
    h.bind("swp1", Some(endpoint(2, 7))).await;
    h.mgr.disable_peer(swp1_key(2), None).await.unwrap();
    h.links_changed(snapshot(true, &[("swp1", 7, false)]));
    h.reconcile().await;
    h.links_changed(snapshot(true, &[("swp1", 7, true)]));
    h.bind("swp1", Some(endpoint(2, 7))).await;
    // Mutation-red: re-adding with the config's default enables it.
    assert!(!h.mgr.peers[&swp1_key(2)].enabled);
}

/// The monitor may report a same-name recreation as Up on the old index,
/// then Up on the new one, with no Down between them. The old scoped peer
/// is retired at once even though discovery never cleared its binding.
#[tokio::test]
async fn an_up_to_up_index_change_retires_the_old_scoped_peer() {
    let mut h = harness(&["swp1"], &[("swp1", 7, true)]);
    h.bind("swp1", Some(endpoint(2, 7))).await;
    h.mgr.note_unnumbered_session_state(
        &swp1_key(2),
        SessionState::OpenConfirm,
        SessionState::Established,
    );
    h.links_changed(snapshot(true, &[("swp1", 9, true)]));
    h.reconcile().await;
    // Mutation-red: judging only Up/Down keeps the peer on the dead index.
    assert!(!h.mgr.peers.contains_key(&swp1_key(2)), "old index retired");
    // A late binding event for the old index is stale and binds nothing.
    h.bind("swp1", Some(endpoint(2, 7))).await;
    assert!(!h.mgr.peers.contains_key(&swp1_key(2)));
    // The binding on the new index is taken.
    h.bind("swp1", Some(endpoint(2, 9))).await;
    assert_eq!(
        h.mgr.peers[&swp1_key(2)].transport_config.peer_scope_id,
        Some(9)
    );
}

/// A peer rediscovered inside a planned restart's window advertises the
/// Restart State bit like configured neighbors (RFC 4724), so helpers keep
/// the routes they retained; after the window it does not.
#[tokio::test]
async fn a_rediscovered_peer_carries_the_restart_state_only_within_the_window() {
    let mut h = harness(&["swp1"], &[("swp1", 7, true)]);
    h.mgr.local_gr_restart_until = Some(std::time::Instant::now() + Duration::from_secs(60));
    h.bind("swp1", Some(endpoint(2, 7))).await;
    // Mutation-red: binding as not restart-eligible clears the deadline.
    assert!(
        h.mgr.peers[&swp1_key(2)]
            .transport_config
            .gr_restart_until
            .is_some(),
        "R=1 inside the window"
    );

    h.mgr.local_gr_restart_until = std::time::Instant::now().checked_sub(Duration::from_secs(1));
    h.links_changed(snapshot(true, &[("swp1", 7, false)]));
    h.reconcile().await;
    h.links_changed(snapshot(true, &[("swp1", 7, true)]));
    h.bind("swp1", Some(endpoint(3, 7))).await;
    assert_eq!(
        h.mgr.peers[&swp1_key(3)].transport_config.gr_restart_until,
        None,
        "R=0 after the window"
    );
}

/// A bind that fails once is retried on the reconcile timer: refreshed RAs
/// and an unchanged link raise no new event to retry it.
#[tokio::test]
async fn a_failed_bind_is_retried_without_a_new_event() {
    let mut h = harness(&["swp1"], &[("swp1", 7, true)]);
    // The first attempt fails: the neighbor's record is briefly unavailable.
    let config = h.mgr.current_config.clone();
    let mut moved = config.neighbors.interface_only()[0].clone();
    moved.interface = Some("swp9".into());
    h.mgr
        .current_config
        .neighbors
        .set_interface_only_for_test(vec![moved]);
    h.bind("swp1", Some(endpoint(2, 7))).await;
    assert!(!h.mgr.peers.contains_key(&swp1_key(2)));
    // Mutation-red: without arming the retry nothing ever re-attempts it.
    assert!(h.mgr.unnumbered_retry_at().is_some(), "retry armed");

    h.mgr.current_config = config;
    h.mgr.unnumbered_retry_due();
    h.reconcile().await;
    assert!(
        h.mgr.peers.contains_key(&swp1_key(2)),
        "recovered on the retry"
    );
}

/// Carrier loss can win the race with a queued Established report: the
/// report reaches discovery after the Down. Retirement then releases
/// discovery last, so the neighbor can rebind.
#[tokio::test]
async fn a_late_established_report_is_released_by_retirement() {
    let mut h = harness(&["swp1"], &[("swp1", 7, true)]);
    h.bind("swp1", Some(endpoint(2, 7))).await;
    h.drain();
    h.links_changed(snapshot(true, &[("swp1", 7, false)]));
    // Drained while the retiring session is still registered.
    h.mgr.note_unnumbered_session_state(
        &swp1_key(2),
        SessionState::OpenConfirm,
        SessionState::Established,
    );
    h.reconcile().await;
    assert!(!h.mgr.peers.contains_key(&swp1_key(2)));
    // Mutation-red: without the release, Established is discovery's last word.
    assert_eq!(
        h.drain().last(),
        Some(&Command::SessionFailed("swp1".into()))
    );
}

/// An inbound connection from `fe80::<last>` arriving on interface index
/// `scope`, as the listener reports it.
async fn inbound(h: &mut Harness, last: u16, scope: u32) -> TcpStream {
    let (server, client) = super::inbound_admission::localhost_inbound_stream().await;
    let source = std::net::SocketAddrV6::new(ll(last), 50179, 0, scope);
    h.mgr
        .handle_inbound(server, SocketAddr::V6(source), None, None)
        .await;
    client
}

/// ADR-0142 secondary discovery: a peer that sends no RAs dials us, and its
/// connection is matched by arrival scope to the interface-only neighbor on
/// that interface, which binds its source address and takes the connection
/// through the ordinary collision path.
#[tokio::test]
async fn an_inbound_connection_binds_the_neighbor_on_its_arrival_interface() {
    let mut h = harness(&["swp1", "swp2"], &[("swp1", 7, true), ("swp2", 8, true)]);
    // Mutation-red: without inbound learning the arrival is dropped as
    // unconfigured and nothing is bound.
    let _client = inbound(&mut h, 9, 8).await;
    let swp2 = PeerKey::new(IpAddr::V6(ll(9)), Some("swp2".into()));
    assert_eq!(
        h.peers_at(ll(9)),
        std::slice::from_ref(&swp2),
        "bound on swp2 only"
    );
    let managed = &h.mgr.peers[&swp2];
    assert_eq!(managed.transport_config.peer_scope_id, Some(8));
    assert!(managed.transport_config.peer.remote_asn_external);
    assert!(
        managed.pending_inbound.is_some(),
        "the connection enters the ordinary collision path"
    );
    assert_eq!(
        h.mgr.unnumbered_owner_of(&swp2),
        Some("swp2"),
        "discovery owns the learned peer"
    );

    // An arrival scope that belongs to no interface-only neighbor still
    // drops, whatever the address.
    let _client = inbound(&mut h, 10, 99).await;
    assert_eq!(h.peers_at(ll(10)), []);
}

/// Accepted only while the neighbor has no Established session: an
/// Established session drops a connection from a new address, and a session
/// that is down lets the new address replace the old binding.
#[tokio::test]
async fn an_inbound_connection_rebinds_only_while_the_neighbor_is_not_established() {
    let mut h = harness(&["swp1"], &[("swp1", 7, true)]);
    let _client = inbound(&mut h, 2, 7).await;
    assert!(h.mgr.peers.contains_key(&swp1_key(2)));
    h.replace_session(
        &swp1_key(2),
        fake_peer_handle(
            IpAddr::V6(ll(2)),
            SessionState::Established,
            None,
            Arc::new(FakePeerCounters::default()),
        ),
    );
    // Mutation-red: without the Established refusal the healthy session is
    // retired for the new address.
    let _client = inbound(&mut h, 3, 7).await;
    assert!(h.mgr.peers.contains_key(&swp1_key(2)), "kept");
    assert!(!h.mgr.peers.contains_key(&swp1_key(3)));

    // The peer moved address and its session is down: the new source binds.
    h.replace_session(
        &swp1_key(2),
        fake_peer_handle(
            IpAddr::V6(ll(2)),
            SessionState::Active,
            None,
            Arc::new(FakePeerCounters::default()),
        ),
    );
    let _client = inbound(&mut h, 3, 7).await;
    assert!(
        !h.mgr.peers.contains_key(&swp1_key(2)),
        "old endpoint retired"
    );
    assert!(h.mgr.peers.contains_key(&swp1_key(3)));
    assert_eq!(h.mgr.unnumbered_owner_of(&swp1_key(3)), Some("swp1"));
}

/// A live RA binding or a bound session past TCP establishment is a second
/// router on the link, and NOTIFICATION backoff on the bound session holds
/// the neighbor's inbound connections whatever their source.
#[tokio::test]
async fn an_inbound_connection_keeps_the_existing_gates() {
    let mut h = harness(&["swp1"], &[("swp1", 7, true)]);
    h.bind("swp1", Some(endpoint(2, 7))).await;
    let _client = inbound(&mut h, 3, 7).await;
    assert_eq!(h.peers_at(ll(3)), [], "RA binding to another router holds");

    // The RA binding expired; the session to it is opening.
    h.bind("swp1", None).await;
    h.replace_session(
        &swp1_key(2),
        fake_peer_handle(
            IpAddr::V6(ll(2)),
            SessionState::OpenConfirm,
            None,
            Arc::new(FakePeerCounters::default()),
        ),
    );
    let _client = inbound(&mut h, 3, 7).await;
    assert_eq!(h.peers_at(ll(3)), [], "opening session holds");

    // Idle in an escalated NOTIFICATION reconnect wait.
    h.replace_session(
        &swp1_key(2),
        super::inbound_admission::backoff_session_handle(
            IpAddr::V6(ll(2)),
            SessionState::Idle,
            2,
            60,
            Arc::default(),
        ),
    );
    let _client = inbound(&mut h, 3, 7).await;
    assert_eq!(h.peers_at(ll(3)), [], "NOTIFICATION backoff holds");
    assert_eq!(h.peers_at(ll(2)), [swp1_key(2)]);
}

/// Inbound learning admits an address through the same atomic check as an
/// RA binding: one held by a static neighbor or by another interface-only
/// neighbor is refused with `duplicate_link_local_address`.
#[tokio::test]
async fn an_inbound_connection_from_a_held_address_is_refused() {
    let mut h = harness(&["swp1", "swp2"], &[("swp1", 7, true), ("swp2", 8, true)]);
    let mut static_peer = make_config(IpAddr::V6(ll(5)), 65002);
    static_peer.interface = Some("eth9".into());
    static_peer.scope_id = Some(9);
    h.mgr.add_peer(static_peer, false).await.unwrap();
    // Mutation-red: without the admission check the static neighbor's
    // address is admitted a second time on swp1.
    let _client = inbound(&mut h, 5, 7).await;
    assert_eq!(
        h.peers_at(ll(5)),
        [PeerKey::new(IpAddr::V6(ll(5)), Some("eth9".into()))]
    );

    let _client = inbound(&mut h, 2, 7).await;
    let _client = inbound(&mut h, 2, 8).await;
    assert_eq!(
        h.peers_at(ll(2)),
        [swp1_key(2)],
        "exactly one link admitted"
    );
}
