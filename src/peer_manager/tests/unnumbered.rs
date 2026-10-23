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
/// settings is detected for it, so the owner rebinds it.
#[test]
fn a_group_session_edit_is_detected_for_its_interface_only_neighbor() {
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

/// `bgp_inbound_connections_dropped_total` for `reason`.
fn dropped(h: &Harness, reason: &str) -> f64 {
    inbound_drop_metric(&h.mgr.metrics, reason).expect("exported from startup")
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

    assert_eq!(dropped(&h, "unconfigured"), 0.0, "an accepted arrival");

    // A second router dials while that candidate is opening: the primary
    // is not, but the bound address is live.
    // Mutation-red: checking only the primary retires both sessions.
    let _second = inbound(&mut h, 12, 8).await;
    assert_eq!(h.peers_at(ll(9)), std::slice::from_ref(&swp2), "kept");
    assert_eq!(h.peers_at(ll(12)), []);
    assert_eq!(dropped(&h, "unconfigured"), 1.0);

    // An arrival scope that belongs to no interface-only neighbor still
    // drops, whatever the address.
    let _client = inbound(&mut h, 10, 99).await;
    assert_eq!(h.peers_at(ll(10)), []);
    assert_eq!(dropped(&h, "unconfigured"), 2.0);

    // A confirmed-down link refuses learning, and the refusal is counted.
    h.links_changed(snapshot(true, &[("swp1", 7, true), ("swp2", 8, false)]));
    h.reconcile().await;
    // Mutation-red: a refusal that is only logged leaves the count at 2.
    let _client = inbound(&mut h, 11, 8).await;
    assert_eq!(h.peers_at(ll(11)), []);
    assert_eq!(
        dropped(&h, "unconfigured"),
        3.0,
        "link-down refusal counted"
    );
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
    assert_eq!(
        dropped(&h, "unconfigured"),
        1.0,
        "Established refusal counted"
    );

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
    assert_eq!(dropped(&h, "unconfigured"), 1.0, "a rebind is not a drop");
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
    assert_eq!(dropped(&h, "unconfigured"), 1.0);

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
    assert_eq!(dropped(&h, "unconfigured"), 2.0);

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
    // Counted once, under the existing backoff reason.
    assert_eq!(dropped(&h, "notification_backoff"), 1.0);
    assert_eq!(dropped(&h, "unconfigured"), 2.0);
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
    assert_eq!(
        dropped(&h, "unconfigured"),
        1.0,
        "held-address refusal counted"
    );

    let _client = inbound(&mut h, 2, 7).await;
    let _client = inbound(&mut h, 2, 8).await;
    assert_eq!(
        h.peers_at(ll(2)),
        [swp1_key(2)],
        "exactly one link admitted"
    );
    assert_eq!(dropped(&h, "unconfigured"), 2.0);

    // The bound session is down and a held address dials: the refusal
    // leaves the current endpoint bound.
    h.replace_session(
        &swp1_key(2),
        fake_peer_handle(
            IpAddr::V6(ll(2)),
            SessionState::Active,
            None,
            Arc::new(FakePeerCounters::default()),
        ),
    );
    // Mutation-red: checking the holder only after retirement unbinds swp1.
    let _client = inbound(&mut h, 5, 7).await;
    assert_eq!(h.peers_at(ll(2)), [swp1_key(2)], "still bound");
    assert_eq!(dropped(&h, "unconfigured"), 3.0);
}

/// A max-prefix shutdown the old session reported as it went Idle is applied
/// before that session is retired for an inbound-learned address, so the
/// replacement starts latched instead of enabled.
#[tokio::test]
async fn an_inbound_rebind_keeps_a_max_prefix_shutdown_queued_by_the_old_session() {
    let mut h = harness(&["swp1"], &[("swp1", 7, true)]);
    let _client = inbound(&mut h, 2, 7).await;
    h.replace_session(
        &swp1_key(2),
        fake_peer_handle(
            IpAddr::V6(ll(2)),
            SessionState::Idle,
            None,
            Arc::new(FakePeerCounters::default()),
        ),
    );
    let session_id = h.mgr.peers[&swp1_key(2)].session_id();
    h.mgr
        .session_notify_tx
        .send(SessionNotification::MaxPrefixExceeded {
            session_id,
            role: rustbgpd_transport::SessionRole::Primary,
            peer_addr: IpAddr::V6(ll(2)),
            count: 501,
            bound: 500,
            family: None,
            received: false,
            path_limit: false,
        })
        .unwrap();

    let _client = inbound(&mut h, 3, 7).await;
    assert!(
        !h.mgr.peers.contains_key(&swp1_key(2)),
        "old endpoint retired"
    );
    // Mutation-red: capturing the state before draining loses the latch, and
    // the replacement starts enabled.
    assert!(
        h.mgr.max_prefix_latches.contains_key(&swp1_key(3)),
        "latch carried"
    );
    assert!(!h.mgr.peers[&swp1_key(3)].enabled, "replacement held down");
}

/// While a config transaction snapshot is staged, `current_config` is
/// provisional and a rollback would not undo a new peer's installed
/// policies. An inbound connection then neither binds an unbound neighbor
/// nor replaces a bound endpoint; learning resumes once the commit or
/// rollback clears the stage (both clear `config_snapshot_staged`).
#[tokio::test]
async fn a_staged_transaction_holds_inbound_learning_for_an_unbound_neighbor() {
    let mut h = harness(&["swp1"], &[("swp1", 7, true)]);
    h.mgr.config_snapshot_staged = true;
    // Mutation-red: learning ahead of the staged guard binds from the
    // provisional config.
    let _client = inbound(&mut h, 9, 7).await;
    assert_eq!(h.peers_at(ll(9)), [], "no bind while staged");
    h.mgr.config_snapshot_staged = false;
    let _client = inbound(&mut h, 9, 7).await;
    assert_eq!(h.peers_at(ll(9)), [swp1_key(9)], "learning resumes");
}

/// The same hold for an endpoint replacement on a bound neighbor whose
/// session is down.
#[tokio::test]
async fn a_staged_transaction_holds_an_inbound_endpoint_replacement() {
    let mut h = harness(&["swp1"], &[("swp1", 7, true)]);
    let _client = inbound(&mut h, 9, 7).await;
    h.replace_session(
        &swp1_key(9),
        fake_peer_handle(
            IpAddr::V6(ll(9)),
            SessionState::Active,
            None,
            Arc::new(FakePeerCounters::default()),
        ),
    );
    h.mgr.config_snapshot_staged = true;
    // Mutation-red: learning ahead of the staged guard retires the bound
    // endpoint and binds the new one from the provisional config.
    let _client = inbound(&mut h, 3, 7).await;
    assert_eq!(h.peers_at(ll(9)), [swp1_key(9)], "kept while staged");
    assert_eq!(h.peers_at(ll(3)), []);
    h.mgr.config_snapshot_staged = false;
    let _client = inbound(&mut h, 3, 7).await;
    assert_eq!(h.peers_at(ll(9)), [], "replaced after the stage clears");
    assert_eq!(h.peers_at(ll(3)), [swp1_key(3)]);
}

/// The RA path binds from the same `current_config`: a binding or an
/// endpoint replacement waits out a staged transaction, and reconciliation
/// stays due so the next loop pass after the commit or rollback applies it.
#[tokio::test]
async fn a_staged_transaction_defers_an_ra_binding() {
    let mut h = harness(&["swp1"], &[("swp1", 7, true)]);
    h.mgr.config_snapshot_staged = true;
    // Mutation-red: binding while staged resolves the provisional config.
    h.bind("swp1", Some(endpoint(2, 7))).await;
    assert_eq!(h.peers_at(ll(2)), [], "no bind while staged");
    assert!(h.mgr.unnumbered_reconcile_due(), "still due");
    h.mgr.config_snapshot_staged = false;
    h.reconcile().await;
    assert_eq!(
        h.peers_at(ll(2)),
        [swp1_key(2)],
        "bound after the stage clears"
    );

    h.mgr.config_snapshot_staged = true;
    h.bind("swp1", Some(endpoint(3, 7))).await;
    assert_eq!(h.peers_at(ll(2)), [swp1_key(2)], "kept while staged");
    assert_eq!(h.peers_at(ll(3)), []);
    h.mgr.config_snapshot_staged = false;
    h.reconcile().await;
    assert_eq!(h.peers_at(ll(2)), []);
    assert_eq!(h.peers_at(ll(3)), [swp1_key(3)]);
}

// ---------------------------------------------------------------------------
// Live configuration of interface-only neighbors: reload, transactions and
// the RPCs all replace `current_config`; the owner reconciles its ports to it.
// ---------------------------------------------------------------------------

/// An interface-only neighbor stanza (`remote_asn = "external"` unless
/// `extra` sets it).
fn port_stanza(name: &str, extra: &str) -> String {
    let asn = if extra.contains("remote_asn") {
        ""
    } else {
        "remote_asn = \"external\"\n"
    };
    format!("[[neighbors]]\ninterface = \"{name}\"\n{asn}families = [\"ipv6_unicast\"]\n{extra}")
}

fn config_with(body: &str) -> crate::config::Config {
    toml::from_str(&format!(
        "[global]\nasn = 65001\nrouter_id = \"10.0.0.1\"\nlisten_port = 179\n\
         [global.telemetry]\nlog_format = \"json\"\n{body}"
    ))
    .unwrap()
}

type Launched = Arc<std::sync::Mutex<Vec<mpsc::UnboundedReceiver<Command>>>>;

/// A launcher that records every discovery it opens.
fn recording_launcher(mgr: &mut PeerManager) -> Launched {
    let launched: Launched = Arc::default();
    let sink = Arc::clone(&launched);
    mgr.unnumbered_runtime.spawn = Box::new(move |_| {
        let (discovery, commands) = RaDiscovery::recording();
        sink.lock().unwrap().push(commands);
        Ok((discovery, mpsc::unbounded_channel().1))
    });
    launched
}

impl Harness {
    /// The startup harness with a recording launcher: no interface-only
    /// neighbor configured, discovery not running.
    fn without_discovery(links: &[(&str, u32, bool)]) -> (Self, Launched) {
        let mut h = harness(&[], links);
        h.mgr.unnumbered = None;
        let launched = recording_launcher(&mut h.mgr);
        (h, launched)
    }

    /// Install `config` the way every runtime config path does, then run the
    /// owner loop's reconcile pass.
    async fn reload(&mut self, config: crate::config::Config) {
        self.mgr.replace_current_config(config);
        self.reconcile().await;
    }

    fn session(&self, key: &PeerKey) -> u64 {
        self.mgr.peers[key].session_id()
    }

    fn rib_sent(&mut self) -> Vec<RibUpdate> {
        std::iter::from_fn(|| self.rib_rx.try_recv().ok()).collect()
    }
}

fn drain_launched(launched: &Launched) -> Vec<Command> {
    launched
        .lock()
        .unwrap()
        .iter_mut()
        .flat_map(|commands| std::iter::from_fn(|| commands.try_recv().ok()).collect::<Vec<_>>())
        .collect()
}

#[tokio::test]
async fn a_reload_adds_the_first_interface_only_neighbor_and_starts_discovery() {
    let (mut h, launched) = Harness::without_discovery(&[("swp1", 7, true), ("swp2", 8, true)]);
    // Mutation-red: without the port-set pass the added neighbor never
    // reaches discovery and no peer can bind.
    h.reload(config_with(&port_stanza("swp1", ""))).await;
    assert_eq!(launched.lock().unwrap().len(), 1, "discovery started");
    assert_eq!(
        drain_launched(&launched),
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
    let session = h.session(&swp1_key(2));

    // A second neighbor joins the running discovery; the first keeps its
    // session.
    h.reload(config_with(&format!(
        "{}{}",
        port_stanza("swp1", ""),
        port_stanza("swp2", "")
    )))
    .await;
    assert_eq!(launched.lock().unwrap().len(), 1, "no second actor");
    assert_eq!(
        drain_launched(&launched),
        [
            Command::Start("swp2".into()),
            Command::Link(LinkEvent {
                ifindex: 8,
                name: "swp2".into(),
                state: LinkState::Up,
            }),
        ]
    );
    assert_eq!(h.session(&swp1_key(2)), session, "unchanged neighbor kept");
}

#[tokio::test]
async fn deleting_an_interface_only_neighbor_ends_its_session_and_releases_its_identity() {
    let mut h = harness(&["swp1", "swp2"], &[("swp1", 7, true), ("swp2", 8, true)]);
    h.bind("swp1", Some(endpoint(2, 7))).await;
    h.bind("swp2", Some(endpoint(3, 8))).await;
    let swp2 = PeerKey::new(IpAddr::V6(ll(3)), Some("swp2".into()));
    let swp2_session = h.session(&swp2);
    let identity = h.mgr.rib_peer_of(&swp1_key(2));
    h.drain();
    h.rib_sent();

    h.reload(config_with(&port_stanza("swp2", ""))).await;
    assert!(!h.mgr.peers.contains_key(&swp1_key(2)), "session ended");
    assert_eq!(h.session(&swp2), swp2_session, "the other neighbor is kept");
    assert_eq!(h.drain(), [Command::Stop("swp1".into())]);
    let sent = h.rib_sent();
    let deleted = sent
        .iter()
        .position(
            |update| matches!(update, RibUpdate::PeerDeleted { peer, .. } if *peer == identity),
        )
        .expect("its RIB state is purged");
    // The port leaves first, so the deletion releases the identity instead
    // of keeping it as an endpoint change does.
    let released = sent
        .iter()
        .position(|update| matches!(update, RibUpdate::ReleasePeer { peer } if *peer == identity))
        .expect("its RIB identity is released");
    assert!(deleted < released);

    // The address is no longer reserved: a static neighbor may take it.
    let mut static_peer = make_config(IpAddr::V6(ll(2)), 65002);
    static_peer.interface = Some("eth9".into());
    static_peer.scope_id = Some(9);
    h.mgr.add_peer(static_peer, false).await.unwrap();

    // Deleting the last one stops discovery and closes its sockets.
    h.reload(config_with("")).await;
    assert!(!h.mgr.peers.contains_key(&swp2));
    assert_eq!(h.drain(), [Command::Stop("swp2".into())]);
    assert!(h.mgr.unnumbered.is_none(), "discovery shut down");
}

/// A neighbor deleted while unbound still releases the identity its earlier
/// bindings held.
#[tokio::test]
async fn deleting_an_unbound_neighbor_releases_its_earlier_identity() {
    let mut h = harness(&["swp1"], &[("swp1", 7, true)]);
    h.bind("swp1", Some(endpoint(2, 7))).await;
    let identity = h.mgr.rib_peer_of(&swp1_key(2));
    // Carrier loss retires the peer but keeps the neighbor's identity.
    h.links_changed(snapshot(true, &[("swp1", 7, false)]));
    h.reconcile().await;
    assert!(!h.mgr.peers.contains_key(&swp1_key(2)));
    h.rib_sent();

    h.reload(config_with("")).await;
    // Mutation-red: releasing only through a peer deletion leaks it.
    assert!(
        h.rib_sent()
            .iter()
            .any(|update| matches!(update, RibUpdate::ReleasePeer { peer } if *peer == identity)),
        "identity released"
    );
}

#[tokio::test]
async fn a_reconfigured_neighbor_is_rebound_under_its_identity() {
    let mut h = harness(&["swp1", "swp2"], &[("swp1", 7, true), ("swp2", 8, true)]);
    h.bind("swp1", Some(endpoint(2, 7))).await;
    h.bind("swp2", Some(endpoint(3, 8))).await;
    let swp2 = PeerKey::new(IpAddr::V6(ll(3)), Some("swp2".into()));
    let (swp1_session, swp2_session) = (h.session(&swp1_key(2)), h.session(&swp2));
    let identity = h.mgr.rib_peer_of(&swp1_key(2));
    h.rib_sent();

    // `remote_asn` mode changes from "external" to a number.
    h.reload(config_with(&format!(
        "{}{}",
        port_stanza("swp1", "remote_asn = 65002\n"),
        port_stanza("swp2", "")
    )))
    .await;
    // Mutation-red: comparing only the port set keeps the old session.
    let rebound = &h.mgr.peers[&swp1_key(2)];
    assert_ne!(rebound.session_id(), swp1_session, "rebound");
    assert_eq!(rebound.transport_config.peer.remote_asn, 65002);
    assert!(!rebound.transport_config.peer.remote_asn_external);
    assert_eq!(h.mgr.rib_peer_of(&swp1_key(2)), identity, "same identity");
    assert!(
        !h.rib_sent()
            .iter()
            .any(|update| matches!(update, RibUpdate::ReleasePeer { .. })),
        "the identity is kept"
    );
    assert_eq!(h.session(&swp2), swp2_session, "unchanged neighbor kept");

    // Reloading the same configuration again rebinds nothing.
    let session = h.session(&swp1_key(2));
    h.reload(config_with(&format!(
        "{}{}",
        port_stanza("swp1", "remote_asn = 65002\n"),
        port_stanza("swp2", "")
    )))
    .await;
    assert_eq!(h.session(&swp1_key(2)), session);
}

#[tokio::test]
async fn a_peer_group_edit_rebinds_only_its_interface_only_members() {
    let groups = |fabric_hold: u16, swp2_group: &str| {
        config_with(&format!(
            "[peer_groups.fabric]\nhold_time = {fabric_hold}\n\
             [peer_groups.other]\nhold_time = 90\n{}{}",
            port_stanza("swp1", "peer_group = \"fabric\"\n"),
            port_stanza("swp2", &format!("peer_group = \"{swp2_group}\"\n"))
        ))
    };
    let mut h = harness(&[], &[("swp1", 7, true), ("swp2", 8, true)]);
    h.reload(groups(9, "other")).await;
    h.bind("swp1", Some(endpoint(2, 7))).await;
    h.bind("swp2", Some(endpoint(3, 8))).await;
    let swp2 = PeerKey::new(IpAddr::V6(ll(3)), Some("swp2".into()));
    let (swp1_session, swp2_session) = (h.session(&swp1_key(2)), h.session(&swp2));

    // Mutation-red: comparing neighbor records alone misses a group edit.
    h.reload(groups(30, "other")).await;
    assert_ne!(
        h.session(&swp1_key(2)),
        swp1_session,
        "fabric member rebound"
    );
    assert_eq!(h.mgr.peers[&swp1_key(2)].hold_time, Some(30));
    assert_eq!(h.session(&swp2), swp2_session, "other group untouched");

    // Moving swp2 into the group rebinds it.
    h.reload(groups(30, "fabric")).await;
    assert_ne!(h.session(&swp2), swp2_session);
    assert_eq!(h.mgr.peers[&swp2].hold_time, Some(30));
}

/// A staged transaction snapshot is provisional: the port set follows it
/// only once the commit clears the stage.
#[tokio::test]
async fn a_staged_snapshot_changes_no_port_until_the_commit() {
    let (mut h, launched) = Harness::without_discovery(&[("swp1", 7, true)]);
    h.mgr.config_snapshot_staged = true;
    // Mutation-red: syncing ports under the stage starts discovery that a
    // rollback could not undo.
    h.reload(config_with(&port_stanza("swp1", ""))).await;
    assert!(launched.lock().unwrap().is_empty(), "nothing while staged");
    assert!(h.mgr.unnumbered_reconcile_due(), "still due");
    h.mgr.config_snapshot_staged = false;
    h.reconcile().await;
    assert_eq!(
        launched.lock().unwrap().len(),
        1,
        "applied after the commit"
    );
}

#[tokio::test]
async fn the_first_interface_only_neighbor_needs_cap_net_raw_and_the_link_monitor() {
    let (mut h, launched) = Harness::without_discovery(&[("swp1", 7, true)]);
    let candidate = config_with(&port_stanza("swp1", ""));
    h.mgr.unnumbered_runtime.probe = || {
        Err(
            "interface-only neighbor discovery needs CAP_NET_RAW to open a raw ICMPv6 socket"
                .into(),
        )
    };
    let before = h.mgr.current_config.clone();
    // Mutation-red: without the preflight the generation applies.
    let outcome = Box::pin(h.mgr.apply_reload_generation(
        candidate.clone(),
        Vec::new(),
        crate::config::PreparedDatasetGeneration::default(),
    ))
    .await;
    let crate::peer_manager::generation::ReloadGenerationOutcome::RejectedNoEffect(error) = outcome
    else {
        panic!("{outcome:?}");
    };
    assert!(error.contains("CAP_NET_RAW"), "{error}");
    assert_eq!(h.mgr.current_config, before, "running config untouched");
    h.reconcile().await;
    assert!(launched.lock().unwrap().is_empty(), "no discovery");
    assert!(h.mgr.unnumbered.is_none());

    // Without the link monitor the same change is refused by name.
    h.mgr.link_check.state = None;
    let error = h.mgr.unnumbered_preflight(&candidate).unwrap_err();
    assert!(error.contains("link monitor"), "{error}");

    // A running interface-only neighbor already holds the capability.
    let h = harness(&["swp1"], &[("swp1", 7, true)]);
    let mut mgr = h.mgr;
    mgr.unnumbered_runtime.probe = || Err("CAP_NET_RAW".into());
    let more = config_with(&format!(
        "{}{}",
        port_stanza("swp1", ""),
        port_stanza("swp2", "")
    ));
    assert_eq!(mgr.unnumbered_preflight(&more), Ok(()));
}

/// A static link-local neighbor added by reload is checked against learned
/// endpoints before any effect, whether the endpoint is bound or reserved
/// by a neighbor whose binding was lost.
#[tokio::test]
async fn a_static_add_is_refused_against_a_learned_endpoint_before_any_effect() {
    let mut h = harness(&["swp1"], &[("swp1", 7, true)]);
    h.bind("swp1", Some(endpoint(2, 7))).await;
    let mut candidate = h.mgr.current_config.clone();
    candidate.neighbors.push(
        toml::from_str::<crate::config::Neighbor>(
            "address = \"fe80::2\"\ninterface = \"eth9\"\nremote_asn = 65002\n",
        )
        .unwrap(),
    );
    for state in ["bound", "reserved"] {
        if state == "reserved" {
            // The binding is lost while the link stays up: the peer, and its
            // address, are kept.
            h.bind("swp1", None).await;
            assert!(h.mgr.peers.contains_key(&swp1_key(2)));
        }
        let before = h.mgr.current_config.clone();
        // Mutation-red: without the static check the generation adds it.
        let outcome = Box::pin(h.mgr.apply_reload_generation(
            candidate.clone(),
            Vec::new(),
            crate::config::PreparedDatasetGeneration::default(),
        ))
        .await;
        let crate::peer_manager::generation::ReloadGenerationOutcome::RejectedNoEffect(error) =
            outcome
        else {
            panic!("{state}: {outcome:?}");
        };
        assert!(
            error.contains("duplicate_link_local_address"),
            "{state}: {error}"
        );
        assert!(error.contains("swp1"), "{state}: names the holder: {error}");
        assert_eq!(h.mgr.current_config, before, "{state}");
        assert_eq!(h.peers_at(ll(2)), [swp1_key(2)], "{state}");
    }
}

/// SIGHUP deletes a bound interface-only neighbor through the real
/// generation executor: the generation skips the bound peer whose neighbor
/// the candidate no longer has, and the port reconcile ends it after the
/// commit.
#[tokio::test]
async fn a_reload_generation_deletes_a_bound_interface_only_neighbor() {
    let mut h = harness(&["swp1", "swp2"], &[("swp1", 7, true), ("swp2", 8, true)]);
    h.bind("swp1", Some(endpoint(2, 7))).await;
    h.bind("swp2", Some(endpoint(3, 8))).await;
    let swp2 = PeerKey::new(IpAddr::V6(ll(3)), Some("swp2".into()));
    let swp2_session = h.session(&swp2);
    let candidate = config_with(&port_stanza("swp2", ""));
    let actions =
        crate::config::plan_reload_peer_actions(&h.mgr.current_config, &candidate).unwrap();
    // Mutation-red: without the skip the generation is rejected for the
    // bound peer that has no record in the candidate.
    let outcome = Box::pin(h.mgr.apply_reload_generation(
        candidate,
        actions,
        crate::config::PreparedDatasetGeneration::default(),
    ))
    .await;
    assert!(
        matches!(
            outcome,
            crate::peer_manager::generation::ReloadGenerationOutcome::Applied(_)
        ),
        "{outcome:?}"
    );
    h.reconcile().await;
    assert!(
        !h.mgr.peers.contains_key(&swp1_key(2)),
        "deleted after commit"
    );
    assert_eq!(h.session(&swp2), swp2_session, "the other neighbor is kept");
}

/// A transaction's policy-only edit reaches a bound interface-only peer
/// live: the target names the interface, the peer manager applies it to the
/// bound peer, and the session is kept.
#[tokio::test]
async fn a_policy_impact_target_reaches_the_bound_interface_only_peer() {
    let mut h = harness(&["swp1"], &[("swp1", 7, true)]);
    h.bind("swp1", Some(endpoint(2, 7))).await;
    let session = h.session(&swp1_key(2));
    let deny = rustbgpd_policy::PolicyChain::new(vec![rustbgpd_policy::Policy {
        entries: vec![],
        default_action: rustbgpd_policy::PolicyAction::Deny,
    }]);
    let target = rustbgpd_api::peer_types::ResolvedPeerPolicy {
        address: IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
        interface: Some("swp1".into()),
        import_policy: Some(deny.clone()),
        export_policy: None,
    };
    // Mutation-red: without the interface mapping the target names no peer.
    let priors = h
        .mgr
        .apply_policy_impact_snapshot(vec![target], Vec::new())
        .await
        .unwrap();
    assert_eq!(priors.len(), 1);
    assert_eq!(
        priors[0].address,
        IpAddr::V6(ll(2)),
        "prior is the bound peer"
    );
    assert_eq!(
        h.mgr.peers[&swp1_key(2)].import_policy.as_ref(),
        Some(&deny)
    );
    assert_eq!(h.session(&swp1_key(2)), session, "session kept");
}

/// A rebind follows the configured admin state only when it changed, and
/// otherwise keeps the operator's toggle.
#[tokio::test]
async fn a_rebind_follows_a_changed_admin_down_and_keeps_an_operator_toggle() {
    let config = |admin_down: bool, hold: u16| {
        config_with(&port_stanza(
            "swp1",
            &format!(
                "hold_time = {hold}\n{}",
                if admin_down {
                    "admin_down = true\n"
                } else {
                    ""
                }
            ),
        ))
    };
    let mut h = harness(&[], &[("swp1", 7, true)]);
    h.reload(config(true, 90)).await;
    h.bind("swp1", Some(endpoint(2, 7))).await;
    assert!(!h.mgr.peers[&swp1_key(2)].enabled, "configured down");

    // Mutation-red (AND of the old toggle): clearing admin_down left the
    // replacement disabled.
    h.reload(config(false, 90)).await;
    assert!(
        h.mgr.peers[&swp1_key(2)].enabled,
        "a cleared admin_down enables"
    );

    // An operator disable survives an unrelated edit.
    h.mgr.disable_peer(swp1_key(2), None).await.unwrap();
    h.reload(config(false, 60)).await;
    assert_eq!(h.mgr.peers[&swp1_key(2)].hold_time, Some(60), "rebound");
    assert!(!h.mgr.peers[&swp1_key(2)].enabled, "operator disable kept");
}

/// A config rebind keeps the endpoint the peer ran on when discovery holds
/// no binding for it (an expired RA, or an inbound-learned endpoint).
#[tokio::test]
async fn a_rebind_keeps_the_endpoint_without_a_discovery_binding() {
    let mut h = harness(&["swp1"], &[("swp1", 7, true)]);
    h.bind("swp1", Some(endpoint(2, 7))).await;
    h.bind("swp1", None).await;
    assert!(
        h.mgr.peers.contains_key(&swp1_key(2)),
        "lost binding keeps the peer"
    );
    // Mutation-red: retiring without keeping the endpoint leaves no peer.
    h.reload(config_with(&port_stanza("swp1", "remote_asn = 65002\n")))
        .await;
    let rebound = &h.mgr.peers[&swp1_key(2)];
    assert_eq!(rebound.transport_config.peer.remote_asn, 65002);
    assert_eq!(rebound.transport_config.peer_scope_id, Some(7));

    // A link that went down in between invalidates it.
    h.links_changed(snapshot(true, &[("swp1", 7, false)]));
    h.reconcile().await;
    assert!(!h.mgr.peers.contains_key(&swp1_key(2)));
}

/// The first discovery actor that fails to start is retried until it starts.
#[tokio::test]
async fn a_discovery_actor_that_fails_to_start_is_retried() {
    let (mut h, launched) = Harness::without_discovery(&[("swp1", 7, true)]);
    let attempts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let sink = Arc::clone(&launched);
    let counter = Arc::clone(&attempts);
    h.mgr.unnumbered_runtime.spawn = Box::new(move |_| {
        if counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0 {
            return Err("transient".to_string());
        }
        let (discovery, commands) = RaDiscovery::recording();
        sink.lock().unwrap().push(commands);
        Ok((discovery, mpsc::unbounded_channel().1))
    });
    h.reload(config_with(&port_stanza("swp1", ""))).await;
    assert!(launched.lock().unwrap().is_empty());
    // Mutation-red: with no deadline outside the actor nothing retries.
    assert!(h.mgr.unnumbered_retry_at().is_some(), "retry armed");
    h.mgr.unnumbered_retry_due();
    h.reconcile().await;
    assert_eq!(launched.lock().unwrap().len(), 1, "started on retry");
    assert_eq!(attempts.load(std::sync::atomic::Ordering::SeqCst), 2);
}

/// A settings rebind keeps the address the session ran on, even when
/// discovery has meanwhile bound another router's address.
#[tokio::test]
async fn a_settings_rebind_keeps_the_working_address_over_a_new_discovery_binding() {
    let mut h = harness(&["swp1"], &[("swp1", 7, true)]);
    h.bind("swp1", Some(endpoint(2, 7))).await;
    h.mgr.note_unnumbered_session_state(
        &swp1_key(2),
        SessionState::OpenConfirm,
        SessionState::Established,
    );
    h.bind("swp1", Some(endpoint(3, 7))).await;
    assert!(h.mgr.peers.contains_key(&swp1_key(2)), "Established kept");
    // Mutation-red (get_or_insert): the rebind moves the peer to fe80::3.
    h.reload(config_with(&port_stanza("swp1", "hold_time = 60\n")))
        .await;
    assert_eq!(h.mgr.peers[&swp1_key(2)].hold_time, Some(60));
    assert!(!h.mgr.peers.contains_key(&swp1_key(3)));
}

/// An operator's graceful-shutdown advertisement outlives a settings
/// rebind, as it does a static neighbor's reconfigure.
#[tokio::test(start_paused = true)]
async fn a_settings_rebind_keeps_graceful_shutdown() {
    let mut h = harness(&["swp1"], &[("swp1", 7, true)]);
    h.bind("swp1", Some(endpoint(2, 7))).await;
    // The session is not Established, so its outbound refresh times out;
    // the intent is stored regardless.
    let _ = h.mgr.set_graceful_shutdown(Some(swp1_key(2)), true).await;
    assert!(h.mgr.peers[&swp1_key(2)].advertise_graceful_shutdown);
    let session = h.session(&swp1_key(2));
    h.reload(config_with(&port_stanza("swp1", "hold_time = 60\n")))
        .await;
    assert_ne!(h.session(&swp1_key(2)), session, "rebound");
    // Mutation-red: without the held flag the new peer advertises nothing.
    assert!(h.mgr.peers[&swp1_key(2)].advertise_graceful_shutdown);
}

/// A bound session that answers its state query with `reported`, and then,
/// before it handles its next command, processes a KEEPALIVE and becomes
/// Established: the actor's own command order pins the race between the
/// manager's state read and its retirement.
fn establishes_after_its_state_query(
    peer_addr: IpAddr,
    reported: SessionState,
    shutdowns: Arc<std::sync::atomic::AtomicU32>,
) -> PeerHandle {
    let (tx, mut rx) = mpsc::channel::<PeerCommand>(8);
    let task = tokio::spawn(async move {
        let mut state = reported;
        while let Some(command) = rx.recv().await {
            match command {
                PeerCommand::QueryState { reply } => {
                    let _ = reply.send(policy_test_peer_state(peer_addr, state));
                    state = SessionState::Established;
                }
                PeerCommand::ShutdownUnlessEstablished { reply } => {
                    let shut_down = state != SessionState::Established;
                    let _ = reply.send(shut_down);
                    if shut_down {
                        shutdowns.fetch_add(1, Ordering::SeqCst);
                        break;
                    }
                }
                PeerCommand::Shutdown => {
                    shutdowns.fetch_add(1, Ordering::SeqCst);
                    break;
                }
                _ => {}
            }
        }
        Ok(())
    });
    PeerHandle::from_parts(tx, task)
}

/// An address change read the bound session as `OpenConfirm`, and the
/// session reached Established before the retirement: the Established
/// session survives and discovery is told it is Established.
#[tokio::test]
async fn an_address_change_never_retires_a_session_established_after_the_state_read() {
    let mut h = harness(&["swp1"], &[("swp1", 7, true)]);
    h.bind("swp1", Some(endpoint(2, 7))).await;
    let shutdowns = Arc::new(std::sync::atomic::AtomicU32::new(0));
    h.replace_session(
        &swp1_key(2),
        establishes_after_its_state_query(
            IpAddr::V6(ll(2)),
            SessionState::OpenConfirm,
            shutdowns.clone(),
        ),
    );
    h.drain();

    // Mutation-red: retiring on the state read alone shuts it down.
    h.bind("swp1", Some(endpoint(3, 7))).await;
    assert_eq!(shutdowns.load(Ordering::SeqCst), 0, "never shut down");
    assert_eq!(h.peers_at(ll(2)), [swp1_key(2)], "Established session kept");
    assert_eq!(h.peers_at(ll(3)), []);
    assert_eq!(h.drain(), [Command::SessionEstablished("swp1".into())]);
}

/// The same guarantee on the inbound-learning path, which retires a bound
/// session it read as down for a connection from a new address.
#[tokio::test]
async fn an_inbound_address_change_never_retires_a_session_established_after_the_state_read() {
    let mut h = harness(&["swp1"], &[("swp1", 7, true)]);
    let _client = inbound(&mut h, 2, 7).await;
    let shutdowns = Arc::new(std::sync::atomic::AtomicU32::new(0));
    h.replace_session(
        &swp1_key(2),
        establishes_after_its_state_query(
            IpAddr::V6(ll(2)),
            SessionState::Active,
            shutdowns.clone(),
        ),
    );

    // Mutation-red: retiring on the state read alone shuts it down.
    let _client = inbound(&mut h, 3, 7).await;
    assert_eq!(shutdowns.load(Ordering::SeqCst), 0, "never shut down");
    assert_eq!(h.peers_at(ll(2)), [swp1_key(2)], "Established session kept");
    assert_eq!(h.peers_at(ll(3)), []);
    assert_eq!(dropped(&h, "unconfigured"), 1.0, "the refusal is counted");
}

/// Confirmed carrier loss and interface recreation stay unconditional: an
/// Established session on the lost link is retired.
#[tokio::test]
async fn carrier_loss_and_recreation_retire_an_established_session() {
    for recreated in [false, true] {
        let mut h = harness(&["swp1"], &[("swp1", 7, true)]);
        h.bind("swp1", Some(endpoint(2, 7))).await;
        h.replace_session(
            &swp1_key(2),
            fake_peer_handle(
                IpAddr::V6(ll(2)),
                SessionState::Established,
                None,
                Arc::new(FakePeerCounters::default()),
            ),
        );
        // Mutation-red: making these retirements conditional keeps the
        // session on a link that is gone.
        let links = if recreated {
            [("swp1", 9, true)]
        } else {
            [("swp1", 7, false)]
        };
        h.links_changed(snapshot(true, &links));
        h.reconcile().await;
        assert_eq!(h.peers_at(ll(2)), [], "retired (recreated: {recreated})");
    }
}

/// A bound session that reports Active, then admits a conditional retirement
/// and holds its answer until `release`: the manager's wait times out with
/// the command admitted. Released, it shuts down as the real session would,
/// reporting nothing, and closes its command channel before `exited`.
fn retirement_answered_after_release(
    peer_addr: IpAddr,
    release: oneshot::Receiver<()>,
    exited: oneshot::Sender<()>,
) -> PeerHandle {
    let (tx, mut rx) = mpsc::channel::<PeerCommand>(8);
    let task = tokio::spawn(async move {
        let mut release = Some(release);
        while let Some(command) = rx.recv().await {
            match command {
                PeerCommand::QueryState { reply } => {
                    let _ = reply.send(policy_test_peer_state(peer_addr, SessionState::Active));
                }
                PeerCommand::ShutdownUnlessEstablished { reply } => {
                    if let Some(release) = release.take() {
                        let _ = release.await;
                    }
                    let _ = reply.send(true);
                    break;
                }
                _ => {}
            }
        }
        drop(rx);
        let _ = exited.send(());
        Ok(())
    });
    PeerHandle::from_parts(tx, task)
}

/// An admitted retirement whose answer came too late ended the session
/// afterwards. Whether discovery then expires the new address or reverts to
/// the old one, the binding is not trusted on its face: the session is read,
/// found gone, and recreated at the endpoint the neighbor keeps.
async fn settle_an_unanswered_retirement(reverted: bool) {
    {
        let mut h = harness(&["swp1"], &[("swp1", 7, true)]);
        h.bind("swp1", Some(endpoint(2, 7))).await;
        let (release, released) = oneshot::channel();
        let (exited_tx, exited) = oneshot::channel();
        h.replace_session(
            &swp1_key(2),
            retirement_answered_after_release(IpAddr::V6(ll(2)), released, exited_tx),
        );
        h.bind("swp1", Some(endpoint(3, 7))).await;
        assert_eq!(h.peers_at(ll(2)), [swp1_key(2)], "kept on doubt");
        assert!(h.mgr.unnumbered_retry_at().is_some(), "retry armed");

        // The late command ends the session.
        release.send(()).unwrap();
        exited.await.unwrap();

        // Mutation-red: trusting the keep shortcut leaves the binding on an
        // exited session that never reconnects.
        let back = reverted.then(|| endpoint(2, 7));
        h.bind("swp1", back).await;
        assert_eq!(h.peers_at(ll(2)), [swp1_key(2)], "reverted: {reverted}");
        assert!(
            matches!(
                h.mgr.peers[&swp1_key(2)]
                    .handle()
                    .query_state_outcome(Duration::from_secs(1))
                    .await,
                rustbgpd_transport::StateQueryOutcome::State(_)
            ),
            "a live session replaces the exited one (reverted: {reverted})"
        );
    }
}

#[tokio::test(start_paused = true)]
async fn an_unanswered_retirement_then_an_expired_endpoint_recreates_the_session() {
    settle_an_unanswered_retirement(false).await;
}

#[tokio::test(start_paused = true)]
async fn an_unanswered_retirement_then_a_reverted_endpoint_recreates_the_session() {
    settle_an_unanswered_retirement(true).await;
}

/// A pending inbound connection from the bound address has reported its OPEN
/// and holds the peer's KEEPALIVE. Retiring the primary would let the
/// retirement's own notification drain promote that candidate, which then
/// establishes only to be deleted: the binding is kept instead.
#[tokio::test]
async fn an_address_change_never_promotes_a_pending_candidate_into_a_retired_peer() {
    let mut h = harness(&["swp1"], &[("swp1", 7, true)]);
    h.bind("swp1", Some(endpoint(2, 7))).await;
    let primary = Arc::new(FakePeerCounters::default());
    h.replace_session(
        &swp1_key(2),
        fake_peer_handle(
            IpAddr::V6(ll(2)),
            SessionState::Active,
            None,
            primary.clone(),
        ),
    );
    let mut client = inbound(&mut h, 2, 7).await;
    assert!(h.mgr.peers[&swp1_key(2)].pending_inbound.is_some());
    let mut buf = BytesMut::with_capacity(4096);
    // The candidate has the peer's OPEN and KEEPALIVE and reported the OPEN;
    // it stays queued for the next drain.
    let open_received =
        super::collision::candidate_open_exchange(&mut h.mgr, &mut client, &mut buf).await;
    h.mgr.session_notify_tx.send(open_received).unwrap();

    // Mutation-red: retiring with a candidate pending shuts the primary down,
    // and the drain promotes the candidate before the deletion.
    h.bind("swp1", Some(endpoint(3, 7))).await;
    assert_eq!(primary.shutdown.load(Ordering::SeqCst), 0, "primary kept");
    assert_eq!(h.peers_at(ll(2)), [swp1_key(2)]);
    assert!(
        h.mgr.peers[&swp1_key(2)].pending_inbound.is_some(),
        "candidate still pending"
    );
    assert_eq!(h.peers_at(ll(3)), []);
}

/// Confirmed carrier loss and interface recreation stay unconditional while
/// a retirement is unsettled: the unresponsive session is not read first,
/// and a session that has exited is not rebound at the vanished index.
async fn a_lost_link_overrides_an_unsettled_retirement(recreated: bool, exits: bool) {
    let mut h = harness(&["swp1"], &[("swp1", 7, true)]);
    h.bind("swp1", Some(endpoint(2, 7))).await;
    let (release, released) = oneshot::channel();
    let (exited_tx, exited) = oneshot::channel();
    h.replace_session(
        &swp1_key(2),
        retirement_answered_after_release(IpAddr::V6(ll(2)), released, exited_tx),
    );
    h.bind("swp1", Some(endpoint(3, 7))).await;
    assert_eq!(h.peers_at(ll(2)), [swp1_key(2)], "unsettled");
    // Unreleased, the session answers nothing more.
    let _held = if exits {
        release.send(()).unwrap();
        exited.await.unwrap();
        None
    } else {
        Some(release)
    };

    let links = if recreated {
        [("swp1", 9, true)]
    } else {
        [("swp1", 7, false)]
    };
    // Mutation-red: settling first blocks on the unresponsive session, or
    // rebinds an exited one at the old index.
    h.links_changed(snapshot(true, &links));
    h.reconcile().await;
    assert_eq!(
        h.peers_at(ll(2)),
        [],
        "retired (recreated: {recreated}, exits: {exits})"
    );
}

#[tokio::test(start_paused = true)]
async fn carrier_loss_retires_an_unresponsive_session_with_an_unsettled_retirement() {
    a_lost_link_overrides_an_unsettled_retirement(false, false).await;
}

#[tokio::test(start_paused = true)]
async fn recreation_retires_an_unresponsive_session_with_an_unsettled_retirement() {
    a_lost_link_overrides_an_unsettled_retirement(true, false).await;
}

#[tokio::test(start_paused = true)]
async fn recreation_never_rebinds_an_exited_session_at_the_old_index() {
    a_lost_link_overrides_an_unsettled_retirement(true, true).await;
}

/// The endpoint recovered for an exited session outlives a rebind that a
/// staged transaction defers: the next pass, with no discovery binding,
/// still recreates the session there.
#[tokio::test(start_paused = true)]
async fn a_recovered_endpoint_survives_a_deferred_rebind() {
    let mut h = harness(&["swp1"], &[("swp1", 7, true)]);
    h.bind("swp1", Some(endpoint(2, 7))).await;
    let (release, released) = oneshot::channel();
    let (exited_tx, exited) = oneshot::channel();
    h.replace_session(
        &swp1_key(2),
        retirement_answered_after_release(IpAddr::V6(ll(2)), released, exited_tx),
    );
    h.bind("swp1", Some(endpoint(3, 7))).await;
    release.send(()).unwrap();
    exited.await.unwrap();

    h.mgr.config_snapshot_staged = true;
    h.bind("swp1", None).await;
    assert_eq!(
        h.peers_at(ll(2)),
        [],
        "exited peer retired; rebind deferred"
    );
    h.mgr.config_snapshot_staged = false;
    // Mutation-red: a recovery endpoint held only for one pass is gone.
    h.reconcile().await;
    assert_eq!(h.peers_at(ll(2)), [swp1_key(2)], "recreated on retry");
    assert!(matches!(
        h.mgr.peers[&swp1_key(2)]
            .handle()
            .query_state_outcome(Duration::from_secs(1))
            .await,
        rustbgpd_transport::StateQueryOutcome::State(_)
    ));
}
