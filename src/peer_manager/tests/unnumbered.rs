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
    harness_with(interfaces, links, "", "")
}

/// A configured BMP collector: admission then refuses a shared address.
const BMP_COLLECTOR: &str = "[bmp]\n[[bmp.collectors]]\naddress = \"127.0.0.1:11019\"\n";

/// [`harness`] with `neighbor_extra` added to every interface-only stanza and
/// `extra` appended to the configuration.
fn harness_with(
    interfaces: &[&str],
    links: &[(&str, u32, bool)],
    neighbor_extra: &str,
    extra: &str,
) -> Harness {
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
                "[[neighbors]]\ninterface = \"{name}\"\nremote_asn = \"external\"\nfamilies = [\"ipv6_unicast\"]\n{neighbor_extra}"
            )
        })
        .collect::<Vec<_>>()
        .concat();
    let config: crate::config::Config = toml::from_str(&format!(
        "[global]\nasn = 65001\nrouter_id = \"10.0.0.1\"\nlisten_port = 179\n\
         [global.telemetry]\nlog_format = \"json\"\n{neighbors}{extra}"
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

    /// The peers at `address`, in key order.
    fn peers_at(&self, address: Ipv6Addr) -> Vec<PeerKey> {
        let mut keys = self.mgr.peer_keys_for_address(IpAddr::V6(address));
        keys.sort();
        keys
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

/// Without BMP, two links that discover one address each bind their own
/// neighbor: the RIB keys each by its own identity.
#[tokio::test]
async fn two_links_discovering_one_address_admit_both_without_bmp() {
    let mut h = harness(&["swp1", "swp2"], &[("swp1", 7, true), ("swp2", 8, true)]);
    h.bind("swp1", Some(endpoint(2, 7))).await;
    h.bind("swp2", Some(endpoint(2, 8))).await;
    let swp2 = PeerKey::new(IpAddr::V6(ll(2)), Some("swp2".into()));
    assert_eq!(h.peers_at(ll(2)), [swp1_key(2), swp2.clone()]);

    // Carrier loss on one link removes only that neighbor's peer.
    h.links_changed(snapshot(true, &[("swp1", 7, false), ("swp2", 8, true)]));
    h.reconcile().await;
    assert_eq!(h.peers_at(ll(2)), [swp2]);
}

/// While BMP collectors are configured, a collector could not tell two
/// sessions at one address apart: exactly one link is admitted.
#[tokio::test]
async fn two_links_discovering_one_address_admit_exactly_one_while_bmp_monitors() {
    let mut h = harness_with(
        &["swp1", "swp2"],
        &[("swp1", 7, true), ("swp2", 8, true)],
        "",
        BMP_COLLECTOR,
    );
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

/// Without BMP, a static neighbor and an interface-only neighbor on other
/// interfaces may share an address in either order.
#[tokio::test]
async fn learned_and_static_neighbors_share_an_address_without_bmp() {
    let mut h = harness(&["swp1", "swp2"], &[("swp1", 7, true), ("swp2", 8, true)]);
    h.bind("swp1", Some(endpoint(2, 7))).await;
    let mut static_peer = make_config(IpAddr::V6(ll(2)), 65002);
    static_peer.interface = Some("eth9".into());
    static_peer.scope_id = Some(9);
    h.mgr.add_peer(static_peer, false).await.unwrap();
    assert_eq!(
        h.peers_at(ll(2)),
        [
            PeerKey::new(IpAddr::V6(ll(2)), Some("eth9".into())),
            swp1_key(2)
        ]
    );

    let mut static_peer = make_config(IpAddr::V6(ll(5)), 65002);
    static_peer.interface = Some("eth9".into());
    static_peer.scope_id = Some(9);
    h.mgr.add_peer(static_peer, false).await.unwrap();
    h.bind("swp2", Some(endpoint(5, 8))).await;
    assert_eq!(
        h.peers_at(ll(5)),
        [
            PeerKey::new(IpAddr::V6(ll(5)), Some("eth9".into())),
            PeerKey::new(IpAddr::V6(ll(5)), Some("swp2".into()))
        ]
    );
}

/// A static link-local neighbor with BFD (keyed by the bare address).
const STATIC_BFD_NEIGHBOR: &str = "[[bfd_profiles]]\nname = \"fast\"\n\
    [[neighbors]]\naddress = \"fe80::2\"\ninterface = \"eth9\"\nremote_asn = 65002\n\
    bfd = { profile = \"fast\" }\n";

/// Whatever BMP does, a neighbor whose BFD session is keyed by its bare
/// address cannot share it: an interface-only neighbor learning that
/// address is refused, with no retry storm, as is the static neighbor
/// added at runtime beside a learned one.
#[tokio::test]
async fn a_shared_address_refuses_an_address_keyed_feature_without_bmp() {
    let mut h = harness_with(&["swp1"], &[("swp1", 7, true)], "", STATIC_BFD_NEIGHBOR);
    h.bind("swp1", Some(endpoint(2, 7))).await;
    assert_eq!(h.peers_at(ll(2)), [], "the learned address is refused");
    assert!(
        h.mgr.unnumbered_retry_at().is_none(),
        "a refusal is not retried"
    );

    let mut h = harness_with(&["swp1"], &[("swp1", 7, true)], "", STATIC_BFD_NEIGHBOR);
    h.bind("swp1", Some(endpoint(3, 7))).await;
    let mut static_peer = make_config(IpAddr::V6(ll(3)), 65002);
    static_peer.interface = Some("eth9".into());
    static_peer.scope_id = Some(9);
    // Move the configured BFD neighbor to the learned fe80::3, as a
    // runtime add would record it.
    h.mgr
        .current_config
        .neighbors
        .iter_mut()
        .find(|neighbor| neighbor.interface.as_deref() == Some("eth9"))
        .unwrap()
        .address = ll(3).to_string();
    let error = h.mgr.add_peer(static_peer, false).await.unwrap_err();
    assert!(error.to_string().contains("BFD"), "{error}");
    assert_eq!(h.peers_at(ll(3)), [swp1_key(3)]);
}

/// A static link-local neighbor without BFD, and the BFD profile a reload
/// may attach to it.
const STATIC_PLAIN_NEIGHBOR: &str = "[[bfd_profiles]]\nname = \"fast\"\n\
    [[neighbors]]\naddress = \"fe80::2\"\ninterface = \"eth9\"\nremote_asn = 65002\n";

/// The static `fe80::2%eth9` record in `config`.
fn eth9_record(config: &mut crate::config::Config) -> &mut crate::config::Neighbor {
    config
        .neighbors
        .iter_mut()
        .find(|neighbor| neighbor.interface.as_deref() == Some("eth9"))
        .unwrap()
}

/// A reload that would enable BFD on a static neighbor already sharing a
/// learned address is refused before any effect: the live pair would leave
/// BFD unable to select a unique peer.
#[tokio::test]
async fn a_reload_enabling_bfd_on_a_shared_address_is_refused_with_no_effect() {
    let mut h = harness_with(&["swp1"], &[("swp1", 7, true)], "", STATIC_PLAIN_NEIGHBOR);
    let mut static_peer = make_config(IpAddr::V6(ll(2)), 65002);
    static_peer.interface = Some("eth9".into());
    static_peer.scope_id = Some(9);
    h.mgr.add_peer(static_peer, false).await.unwrap();
    h.bind("swp1", Some(endpoint(2, 7))).await;
    assert_eq!(h.peers_at(ll(2)).len(), 2, "the pair shares fe80::2");

    let before = h.mgr.current_config.clone();
    let mut candidate = before.clone();
    eth9_record(&mut candidate).bfd = Some(crate::config::BfdConfig {
        profile: "fast".into(),
        enabled: true,
        strict: false,
        multihop: false,
    });
    let outcome = Box::pin(h.mgr.apply_reload_generation(
        candidate,
        Vec::new(),
        crate::config::PreparedDatasetGeneration::default(),
    ))
    .await;
    // Mutation-red: without the live check the generation applies.
    let ReloadGenerationOutcome::RejectedNoEffect(error) = outcome else {
        panic!("expected a refusal with no effect: {outcome:?}");
    };
    assert!(error.contains("BFD"), "{error}");
    assert_eq!(h.mgr.current_config, before, "nothing changed");
    assert_eq!(h.peers_at(ll(2)).len(), 2);
}

/// A learned address refused for a static neighbor's BFD binds once a
/// reload removes that BFD: the configuration swap rechecks refused ports.
#[tokio::test]
async fn removing_bfd_by_reload_admits_a_refused_learned_address() {
    let mut h = harness_with(&["swp1"], &[("swp1", 7, true)], "", STATIC_BFD_NEIGHBOR);
    h.bind("swp1", Some(endpoint(2, 7))).await;
    assert_eq!(h.peers_at(ll(2)), [], "refused while eth9 runs BFD");

    let mut candidate = h.mgr.current_config.clone();
    eth9_record(&mut candidate).bfd = None;
    h.mgr.replace_current_config(candidate);
    // Mutation-red: without the recheck no reconcile is due and the port
    // stays unbound, since unchanged RAs raise no new binding.
    h.reconcile().await;
    assert_eq!(h.peers_at(ll(2)), [swp1_key(2)]);
}

/// Two BMP collectors, both set to exclude identity conflicts.
const BMP_EXCLUDING_COLLECTORS: &str = "[bmp]\n\
    [[bmp.collectors]]\naddress = \"127.0.0.1:11019\"\non_identity_conflict = \"exclude\"\n\
    [[bmp.collectors]]\naddress = \"127.0.0.1:11020\"\non_identity_conflict = \"exclude\"\n";

/// When every collector excludes identity conflicts, the second link to
/// learn an address establishes with its session left out of BMP, and the
/// first keeps its monitoring. The exclusion is reported in neighbor state
/// and metrics, survives the first link losing and regaining carrier, and ends with
/// the excluded neighbor's peer.
#[tokio::test]
async fn a_shared_learned_address_is_excluded_from_bmp_when_every_collector_excludes() {
    let mut h = harness_with(
        &["swp1", "swp2"],
        &[("swp1", 7, true), ("swp2", 8, true)],
        "",
        BMP_EXCLUDING_COLLECTORS,
    );
    let (bmp_tx, _bmp_rx) = mpsc::channel(8);
    h.mgr.bmp_tx = Some(bmp_tx);
    let swp2 = PeerKey::new(IpAddr::V6(ll(2)), Some("swp2".into()));
    h.bind("swp1", Some(endpoint(2, 7))).await;
    h.bind("swp2", Some(endpoint(2, 8))).await;
    assert_eq!(h.peers_at(ll(2)), [swp1_key(2), swp2.clone()]);

    assert!(
        h.mgr.session_bmp_tx(&swp1_key(2)).is_some(),
        "first link monitored"
    );
    assert!(
        h.mgr.session_bmp_tx(&swp2).is_none(),
        "second link excluded"
    );
    assert!(
        !h.mgr
            .get_peer_info(&swp1_key(2))
            .await
            .unwrap()
            .bmp_identity_excluded
    );
    assert!(
        h.mgr
            .get_peer_info(&swp2)
            .await
            .unwrap()
            .bmp_identity_excluded
    );
    assert!(
        h.mgr
            .list_peers()
            .await
            .iter()
            .any(|info| info.interface.as_deref() == Some("swp2") && info.bmp_identity_excluded)
    );
    assert_eq!(
        bmp_identity_conflict_metric(&h.mgr.metrics, "excluded"),
        Some(1.0)
    );
    assert_eq!(
        bmp_identity_conflict_metric(&h.mgr.metrics, "refused"),
        Some(0.0)
    );
    assert_eq!(
        process_global_metric(&h.mgr.metrics, "bgp_bmp_identity_excluded_neighbors"),
        Some(1.0)
    );

    // An excluded neighbor is not a monitored holder: carrier loss and
    // recovery of the first link readmits it with its monitoring.
    h.links_changed(snapshot(true, &[("swp1", 7, false), ("swp2", 8, true)]));
    h.reconcile().await;
    h.links_changed(snapshot(true, &[("swp1", 7, true), ("swp2", 8, true)]));
    h.bind("swp1", Some(endpoint(2, 7))).await;
    assert!(h.mgr.session_bmp_tx(&swp1_key(2)).is_some());
    assert!(h.mgr.session_bmp_tx(&swp2).is_none());

    // The exclusion ends with the excluded neighbor's peer.
    h.links_changed(snapshot(true, &[("swp1", 7, true), ("swp2", 8, false)]));
    h.reconcile().await;
    assert_eq!(h.peers_at(ll(2)), [swp1_key(2)]);
    assert!(h.mgr.bmp_excluded.is_empty());
    assert_eq!(
        process_global_metric(&h.mgr.metrics, "bgp_bmp_identity_excluded_neighbors"),
        Some(0.0)
    );
}

/// Collector modes combine strictly: one refusing collector refuses the
/// conflict even when another excludes.
#[tokio::test]
async fn one_refusing_collector_refuses_a_shared_learned_address() {
    let mixed = "[bmp]\n\
        [[bmp.collectors]]\naddress = \"127.0.0.1:11019\"\non_identity_conflict = \"exclude\"\n\
        [[bmp.collectors]]\naddress = \"127.0.0.1:11020\"\n";
    let mut h = harness_with(
        &["swp1", "swp2"],
        &[("swp1", 7, true), ("swp2", 8, true)],
        "",
        mixed,
    );
    h.bind("swp1", Some(endpoint(2, 7))).await;
    h.bind("swp2", Some(endpoint(2, 8))).await;
    assert_eq!(h.peers_at(ll(2)), [swp1_key(2)]);
    assert_eq!(
        bmp_identity_conflict_metric(&h.mgr.metrics, "refused"),
        Some(1.0)
    );
    assert!(h.mgr.bmp_excluded.is_empty());
}

/// A static neighbor added at runtime at a learned address follows the
/// same rule: excluded when every collector excludes.
#[tokio::test]
async fn a_static_neighbor_at_a_learned_address_is_excluded_when_every_collector_excludes() {
    let mut h = harness_with(
        &["swp1"],
        &[("swp1", 7, true)],
        "",
        BMP_EXCLUDING_COLLECTORS,
    );
    h.bind("swp1", Some(endpoint(2, 7))).await;
    let mut static_peer = make_config(IpAddr::V6(ll(2)), 65002);
    static_peer.interface = Some("eth9".into());
    static_peer.scope_id = Some(9);
    h.mgr.add_peer(static_peer, false).await.unwrap();
    let eth9 = PeerKey::new(IpAddr::V6(ll(2)), Some("eth9".into()));
    assert!(h.mgr.bmp_excluded.contains(&eth9));
    assert!(!h.mgr.bmp_excluded.contains(&swp1_key(2)));
}

#[tokio::test]
async fn learned_and_static_admission_refuse_each_other_while_bmp_monitors() {
    let mut h = harness_with(
        &["swp1", "swp2"],
        &[("swp1", 7, true), ("swp2", 8, true)],
        "",
        BMP_COLLECTOR,
    );
    h.bind("swp1", Some(endpoint(2, 7))).await;

    // Static admission against a bound learned address.
    let mut static_peer = make_config(IpAddr::V6(ll(2)), 65002);
    static_peer.interface = Some("eth9".into());
    static_peer.scope_id = Some(9);
    let error = h.mgr.add_peer(static_peer, false).await.unwrap_err();
    assert!(
        error.to_string().contains("bmp_identity_conflict"),
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
    // Unbound, the row still reports the shutdown and its countdown.
    // Mutation-red: projecting only `held.enabled` drops both.
    let rows = h.mgr.list_peers().await;
    let unbound = rows
        .iter()
        .find(|info| info.interface.as_deref() == Some("swp1"))
        .expect("the unbound row");
    assert!(!unbound.enabled);
    assert_eq!(unbound.last_error, "max-prefix");
    assert_eq!(unbound.max_prefix_action, "restart");
    assert!(unbound.max_prefix_restart_remaining_millis.is_some());
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

/// Without BMP, inbound learning binds an address another neighbor on
/// another interface holds.
#[tokio::test]
async fn an_inbound_connection_from_a_shared_address_binds_without_bmp() {
    let mut h = harness(&["swp1", "swp2"], &[("swp1", 7, true), ("swp2", 8, true)]);
    let mut static_peer = make_config(IpAddr::V6(ll(5)), 65002);
    static_peer.interface = Some("eth9".into());
    static_peer.scope_id = Some(9);
    h.mgr.add_peer(static_peer, false).await.unwrap();
    let _client = inbound(&mut h, 5, 7).await;
    assert_eq!(
        h.peers_at(ll(5)),
        [
            PeerKey::new(IpAddr::V6(ll(5)), Some("eth9".into())),
            swp1_key(5)
        ]
    );
    assert_eq!(dropped(&h, "unconfigured"), 0.0);
}

/// Inbound learning admits an address through the same atomic check as an
/// RA binding: while BMP collectors are configured, one held by a static
/// neighbor or by another interface-only neighbor is refused with
/// `bmp_identity_conflict`.
#[tokio::test]
async fn an_inbound_connection_from_a_held_address_is_refused_while_bmp_monitors() {
    let mut h = harness_with(
        &["swp1", "swp2"],
        &[("swp1", 7, true), ("swp2", 8, true)],
        "",
        BMP_COLLECTOR,
    );
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

/// Neighbor listings report an interface-only neighbor by its interface:
/// a bound one through its peer with the learned address, an unbound one
/// as a row of its own with where discovery stands, both with the
/// configured `remote_asn` mode.
#[tokio::test]
async fn listed_rows_report_discovery_state_learned_address_and_mode() {
    use rustbgpd_api::peer_types::{NeighborDiscoveryState, RemoteAsnMode};
    let mut h = harness(
        &["swp1", "swp2", "swp3"],
        &[("swp1", 7, true), ("swp2", 8, false)],
    );
    h.bind("swp1", Some(endpoint(2, 7))).await;
    let rows = h.mgr.list_peers().await;
    let row = |interface: &str| {
        rows.iter()
            .find(|info| info.interface.as_deref() == Some(interface))
            .unwrap_or_else(|| panic!("no row for {interface}"))
    };
    // Mutation-red: without the unbound rows, swp2 and swp3 are absent.
    assert_eq!(rows.len(), 3);
    let bound = row("swp1");
    let state = bound.interface_only.as_ref().expect("interface-only");
    assert_eq!(state.discovery, NeighborDiscoveryState::Bound);
    assert_eq!(state.learned_address, Some(ll(2)));
    assert_eq!(bound.remote_asn_mode, RemoteAsnMode::External);
    for (interface, discovery) in [
        ("swp2", NeighborDiscoveryState::LinkDown),
        ("swp3", NeighborDiscoveryState::InterfaceMissing),
    ] {
        let unbound = row(interface);
        let state = unbound.interface_only.as_ref().expect("interface-only");
        assert_eq!(state.discovery, discovery, "{interface}");
        assert_eq!(state.learned_address, None);
        assert_eq!(unbound.remote_asn_mode, RemoteAsnMode::External);
        assert!(!unbound.stale);
    }
    // A link that comes up without a binding is awaiting discovery.
    h.links_changed(snapshot(true, &[("swp1", 7, true), ("swp2", 8, true)]));
    let rows = h.mgr.list_peers().await;
    let swp2 = rows
        .iter()
        .find(|info| info.interface.as_deref() == Some("swp2"))
        .unwrap();
    assert_eq!(
        swp2.interface_only.as_ref().unwrap().discovery,
        NeighborDiscoveryState::AwaitingDiscovery
    );
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

// ---------------------------------------------------------------------------
// ADR-0142 "Lifecycle", BFD: an interface-only neighbor's binding registers
// its single-hop session at runtime through the acknowledged replacement
// path; rebinding replaces it and unbinding removes it.
// ---------------------------------------------------------------------------

/// The BFD runtime side of a [`Harness`]: every acknowledged membership the
/// manager asks for, and the state the fake actor reports for each session.
struct BfdSide {
    applied: mpsc::UnboundedReceiver<crate::bfd_runtime::BfdRuntimeConfig>,
    state: Arc<std::sync::Mutex<rustbgpd_bfd::SessionState>>,
}

impl BfdSide {
    fn next_applied(&mut self) -> crate::bfd_runtime::BfdRuntimeConfig {
        self.applied
            .try_recv()
            .expect("a membership change was acknowledged")
    }

    fn sessions(config: &crate::bfd_runtime::BfdRuntimeConfig) -> Vec<(IpAddr, Option<u32>)> {
        let mut sessions: Vec<_> = config
            .sessions
            .iter()
            .map(|params| (params.peer, params.scope_id))
            .collect();
        sessions.sort();
        sessions
    }
}

/// A harness whose interface-only neighbors run BFD (`strict` or not) with a
/// fake BFD actor acknowledging every membership change.
fn bfd_harness(
    interfaces: &[&str],
    links: &[(&str, u32, bool)],
    strict: bool,
) -> (Harness, BfdSide) {
    attach_bfd(
        harness_with(
            interfaces,
            links,
            &format!("bfd = {{ profile = \"fast\", strict = {strict} }}\n"),
            "[[bfd_profiles]]\nname = \"fast\"\n",
        ),
        &[],
    )
}

/// A BFD session parameter set for `peer` (scoped when link-local).
fn session_params(peer: IpAddr, scope: Option<u32>) -> crate::bfd_runtime::BfdSessionParams {
    crate::bfd_runtime::BfdSessionParams {
        revision: 1,
        peer,
        peer_label: peer.to_string(),
        scope_id: scope,
        destination: crate::bfd_runtime::bfd_destination(peer, scope, false).unwrap(),
        desired_min_tx_us: 300_000,
        required_min_rx_us: 300_000,
        detect_mult: 3,
        strict: false,
        enabled: true,
        multihop: false,
        source: None,
    }
}

/// Attach BFD coupling with a fake actor acknowledging every membership
/// change, plus configured single-hop members at `statics` (IPv4). The IPv6
/// and IPv4 single-hop sockets count as already open, so tests bind none.
fn attach_bfd(h: Harness, statics: &[IpAddr]) -> (Harness, BfdSide) {
    let Harness {
        mgr,
        commands,
        links,
        rib_rx,
    } = h;
    let opened: IpAddr = "fe80::ffff".parse().unwrap();
    let mut configured = HashMap::from([(opened, session_params(opened, Some(1)))]);
    for peer in statics {
        configured.insert(*peer, session_params(*peer, None));
    }
    configured
        .entry("192.0.2.255".parse().unwrap())
        .or_insert_with(|| session_params("192.0.2.255".parse().unwrap(), None));
    let (desired_tx, _desired_rx) = watch::channel(crate::bfd_runtime::BfdRuntimeConfig::default());
    let (_state_tx, state_rx) = crate::bfd_runtime::state_change_channel();
    let (reload_tx, mut reload_rx) = mpsc::channel::<crate::bfd_runtime::BfdReloadCommand>(1);
    let mut mgr = mgr
        .with_bfd_coupling(desired_tx, state_rx, configured)
        .with_bfd_reload(reload_tx);
    mgr.bfd_coupling
        .as_mut()
        .unwrap()
        .configured
        .retain(|peer, _| statics.contains(peer));
    let state = Arc::new(std::sync::Mutex::new(rustbgpd_bfd::SessionState::Down));
    let (applied_tx, applied) = mpsc::unbounded_channel();
    let reported = state.clone();
    let metrics = mgr.metrics.clone();
    tokio::spawn(async move {
        while let Some(command) = reload_rx.recv().await {
            let state = *reported.lock().unwrap();
            // As the actor does, seed each running session's gauge before
            // acknowledging.
            for params in command
                .desired
                .sessions
                .iter()
                .filter(|params| params.enabled)
            {
                let up = state == rustbgpd_bfd::SessionState::Up;
                metrics.record_bfd_state(&params.peer_label, up, up);
            }
            let acks = command
                .desired
                .sessions
                .iter()
                .filter(|params| params.enabled)
                .map(|params| crate::bfd_runtime::BfdStateChange {
                    revision: params.revision,
                    peer: params.peer,
                    state,
                    diagnostic: rustbgpd_bfd::Diagnostic::None,
                    remote_admin_down: false,
                    resync: true,
                })
                .collect();
            let _ = applied_tx.send(command.desired);
            let _ = command.reply.send(acks);
        }
    });
    (
        Harness {
            mgr,
            commands,
            links,
            rib_rx,
        },
        BfdSide { applied, state },
    )
}

fn bfd_revision(h: &Harness, peer: Ipv6Addr) -> u64 {
    h.mgr.bfd_coupling.as_ref().unwrap().configured[&IpAddr::V6(peer)].revision
}

/// No session exists before a binding; binding registers the single-hop
/// session to the learned address on the binding's index; an address change
/// removes it and registers the new endpoint under a fresh revision; carrier
/// loss removes it. Every change goes through the acknowledged path.
#[tokio::test]
async fn a_binding_registers_replaces_and_removes_its_bfd_session() {
    let (mut h, mut bfd) = bfd_harness(&["swp1"], &[("swp1", 7, true)], false);
    assert!(h.mgr.bfd_coupling.as_ref().unwrap().configured.is_empty());

    // Mutation-red: without registration the bound peer runs no BFD.
    h.bind("swp1", Some(endpoint(2, 7))).await;
    assert_eq!(
        BfdSide::sessions(&bfd.next_applied()),
        [(IpAddr::V6(ll(2)), Some(7))]
    );
    let first = bfd_revision(&h, ll(2));

    h.bind("swp1", Some(endpoint(3, 7))).await;
    assert_eq!(BfdSide::sessions(&bfd.next_applied()), []);
    assert_eq!(
        BfdSide::sessions(&bfd.next_applied()),
        [(IpAddr::V6(ll(3)), Some(7))]
    );
    assert!(bfd_revision(&h, ll(3)) > first, "a fresh revision");

    h.links_changed(snapshot(true, &[("swp1", 7, false)]));
    h.reconcile().await;
    assert_eq!(BfdSide::sessions(&bfd.next_applied()), []);
    assert!(h.mgr.bfd_coupling.as_ref().unwrap().configured.is_empty());
    assert!(h.mgr.bfd_coupling.as_ref().unwrap().bound.is_empty());
}

/// A strict neighbor is added withheld and released only by BFD Up for the
/// current binding's revision; an Up for a retired binding never releases
/// the new one.
#[tokio::test]
async fn a_strict_binding_waits_for_bfd_up_on_its_own_session() {
    let (mut h, mut bfd) = bfd_harness(&["swp1"], &[("swp1", 7, true)], true);
    h.bind("swp1", Some(endpoint(2, 7))).await;
    bfd.next_applied();
    let peer = IpAddr::V6(ll(2));
    // Mutation-red: registering after the peer is added starts it unheld.
    assert!(h.mgr.bfd_withholding(&peer), "held until BFD is Up");
    let old = bfd_revision(&h, ll(2));

    // The address changes before BFD came up.
    h.bind("swp1", Some(endpoint(3, 7))).await;
    bfd.next_applied();
    bfd.next_applied();
    let new_peer = IpAddr::V6(ll(3));
    assert!(h.mgr.bfd_withholding(&new_peer));
    let up = |peer, revision| crate::bfd_runtime::BfdStateChange {
        revision,
        peer,
        state: rustbgpd_bfd::SessionState::Up,
        diagnostic: rustbgpd_bfd::Diagnostic::None,
        remote_admin_down: false,
        resync: false,
    };
    h.mgr.handle_bfd_state_change(up(new_peer, old)).await;
    assert!(
        h.mgr.bfd_withholding(&new_peer),
        "a stale revision never releases"
    );
    h.mgr
        .handle_bfd_state_change(up(new_peer, bfd_revision(&h, ll(3))))
        .await;
    assert!(!h.mgr.bfd_withholding(&new_peer), "released by its own Up");
}

/// BFD down is a session-down input for a bound peer: its BGP session gets
/// `BfdDown` and is held until BFD permits BGP again.
#[tokio::test]
async fn bfd_down_tears_down_a_bound_session() {
    let (mut h, mut bfd) = bfd_harness(&["swp1"], &[("swp1", 7, true)], false);
    *bfd.state.lock().unwrap() = rustbgpd_bfd::SessionState::Up;
    h.bind("swp1", Some(endpoint(2, 7))).await;
    bfd.next_applied();
    let (tx, mut rx) = mpsc::channel::<PeerCommand>(8);
    h.replace_session(
        &swp1_key(2),
        PeerHandle::from_parts(tx, tokio::spawn(std::future::pending())),
    );
    let peer = IpAddr::V6(ll(2));
    h.mgr
        .handle_bfd_state_change(crate::bfd_runtime::BfdStateChange {
            revision: bfd_revision(&h, ll(2)),
            peer,
            state: rustbgpd_bfd::SessionState::Down,
            diagnostic: rustbgpd_bfd::Diagnostic::ControlDetectionTimeExpired,
            remote_admin_down: false,
            resync: false,
        })
        .await;
    assert!(matches!(rx.try_recv(), Ok(PeerCommand::BfdDown)));
    assert!(h.mgr.bfd_withholding(&peer));
}

/// A reload rebuilds BFD membership from configuration, which has no
/// address for an interface-only neighbor: the binding's session is carried
/// over unchanged.
#[tokio::test]
async fn a_reload_keeps_a_bindings_bfd_session() {
    let (mut h, mut bfd) = bfd_harness(&["swp1"], &[("swp1", 7, true)], false);
    h.bind("swp1", Some(endpoint(2, 7))).await;
    bfd.next_applied();
    let revision = bfd_revision(&h, ll(2));
    let candidate = h.mgr.current_config.clone();
    // Mutation-red: without the carry-over the reload drops the session.
    let prepared = h.mgr.prepare_bfd_reload(&candidate).unwrap();
    h.mgr.commit_bfd_reload(prepared).await.unwrap();
    assert_eq!(
        BfdSide::sessions(&bfd.next_applied()),
        [(IpAddr::V6(ll(2)), Some(7))]
    );
    assert_eq!(bfd_revision(&h, ll(2)), revision, "unchanged");

    // A profile edit applies to the binding's session on reload.
    let mut candidate = h.mgr.current_config.clone();
    candidate.bfd_profiles[0].multiplier = 5;
    // Mutation-red: carrying the old session over ignores the edit.
    let prepared = h.mgr.prepare_bfd_reload(&candidate).unwrap();
    h.mgr.commit_bfd_reload(prepared).await.unwrap();
    bfd.next_applied();
    let session = &h.mgr.bfd_coupling.as_ref().unwrap().configured[&IpAddr::V6(ll(2))];
    assert_eq!((session.detect_mult, session.scope_id), (5, Some(7)));
    assert_ne!(session.revision, revision, "replaced");
}

/// A recreated interface moves a binding's session only by rebinding it,
/// never through the configured link-local scope refresh: one mechanism
/// owns each session.
#[tokio::test]
async fn a_recreated_interface_moves_a_bindings_bfd_session_only_by_rebinding() {
    let (mut h, mut bfd) = bfd_harness(&["swp1"], &[("swp1", 7, true)], false);
    h.bind("swp1", Some(endpoint(2, 7))).await;
    bfd.next_applied();

    h.links_changed(snapshot(true, &[("swp1", 9, true)]));
    h.mgr.run_due_bfd_scope_refresh().await;
    // Mutation-red: the scope refresh would move it to index 9 itself.
    assert!(bfd.applied.try_recv().is_err(), "no refresh replacement");
    assert_eq!(
        h.mgr.bfd_coupling.as_ref().unwrap().configured[&IpAddr::V6(ll(2))].scope_id,
        Some(7)
    );

    h.reconcile().await;
    assert_eq!(BfdSide::sessions(&bfd.next_applied()), [], "retired");
    h.bind("swp1", Some(endpoint(2, 9))).await;
    assert_eq!(
        BfdSide::sessions(&bfd.next_applied()),
        [(IpAddr::V6(ll(2)), Some(9))],
        "rebound on the new index"
    );
}

/// The same recovery when discovery still points at the new address as the
/// exited peer is retired: the replacement is deferred by a staged
/// transaction, discovery's binding then expires before it clears, and the
/// retry still recreates the session at the recovered endpoint.
#[tokio::test(start_paused = true)]
async fn a_recovered_endpoint_outlives_an_expired_discovery_binding() {
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
    h.bind("swp1", Some(endpoint(3, 7))).await;
    assert_eq!(h.peers_at(ll(2)), [], "exited peer retired");
    assert_eq!(h.peers_at(ll(3)), [], "replacement deferred");
    h.bind("swp1", None).await;
    h.mgr.config_snapshot_staged = false;
    // Mutation-red: recovering only when discovery has no binding leaves
    // nothing to reconnect to once that binding expires.
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

/// A neighbor deleted through the runtime API leaves its BFD member
/// drained. A binding's membership change must not publish it enabled again,
/// on bind or on unbind.
#[tokio::test]
async fn a_binding_change_never_restarts_a_deleted_neighbors_bfd_session() {
    let deleted: IpAddr = "192.0.2.9".parse().unwrap();
    let (mut h, mut bfd) = attach_bfd(
        harness_with(
            &["swp1"],
            &[("swp1", 7, true)],
            "bfd = { profile = \"fast\" }\n",
            "[[bfd_profiles]]\nname = \"fast\"\n",
        ),
        &[deleted],
    );
    insert_test_managed_peer(
        &mut h.mgr,
        deleted,
        fake_peer_handle(
            deleted,
            SessionState::Established,
            None,
            Arc::new(FakePeerCounters::default()),
        ),
        false,
    );
    h.mgr
        .delete_peer_runtime(PeerKey::new(deleted, None), false)
        .await
        .unwrap();
    let drained = |config: &crate::bfd_runtime::BfdRuntimeConfig| {
        config
            .sessions
            .iter()
            .find(|params| params.peer == deleted)
            .is_some_and(|params| !params.enabled)
    };

    // Mutation-red: rebuilding the disabled set from live peers only
    // re-enables the deleted neighbor's session.
    h.bind("swp1", Some(endpoint(2, 7))).await;
    assert!(drained(&bfd.next_applied()), "still drained after a bind");
    h.links_changed(snapshot(true, &[("swp1", 7, false)]));
    h.reconcile().await;
    assert!(
        drained(&bfd.next_applied()),
        "still drained after an unbind"
    );
}

/// Prepare and commit the BFD side of a reload to `candidate`, then adopt it.
async fn reload(h: &mut Harness, candidate: crate::config::Config) {
    let prepared = h.mgr.prepare_bfd_reload(&candidate).unwrap();
    h.mgr.commit_bfd_reload(prepared).await.unwrap();
    h.mgr.current_config = candidate;
}

/// Inherited BFD enabled, disabled and enabled again by peer-group reloads
/// reaches an interface-only neighbor that is already bound, without a
/// rebind: the session is registered (and a strict one holds BGP until Up),
/// removed, and registered again.
#[tokio::test]
async fn a_reload_enables_disables_and_reenables_bfd_on_a_bound_neighbor() {
    let (mut h, mut bfd) = attach_bfd(
        harness_with(
            &["swp1"],
            &[("swp1", 7, true)],
            "peer_group = \"fabric\"\n",
            "[[bfd_profiles]]\nname = \"fast\"\n[peer_groups.fabric]\n",
        ),
        &[],
    );
    h.bind("swp1", Some(endpoint(2, 7))).await;
    assert!(bfd.applied.try_recv().is_err(), "no BFD configured yet");
    let peer = IpAddr::V6(ll(2));
    let with_bfd = |h: &Harness, bfd: Option<&str>| {
        let mut candidate = h.mgr.current_config.clone();
        candidate.peer_groups.get_mut("fabric").unwrap().bfd =
            bfd.map(|bfd| toml::from_str::<crate::config::BfdConfig>(bfd).unwrap());
        candidate
    };

    // Mutation-red: rebuilding only existing sessions never adds one.
    let enabled = with_bfd(&h, Some("profile = \"fast\"\nstrict = true"));
    reload(&mut h, enabled).await;
    assert_eq!(BfdSide::sessions(&bfd.next_applied()), [(peer, Some(7))]);
    assert!(h.mgr.bfd_withholding(&peer), "strict holds BGP until Up");

    let disabled = with_bfd(&h, None);
    reload(&mut h, disabled).await;
    assert_eq!(BfdSide::sessions(&bfd.next_applied()), []);
    assert!(!h.mgr.bfd_withholding(&peer), "released with its session");
    assert!(!h.mgr.bfd_coupling.as_ref().unwrap().bound.contains(&peer));

    let enabled = with_bfd(&h, Some("profile = \"fast\""));
    reload(&mut h, enabled).await;
    assert_eq!(BfdSide::sessions(&bfd.next_applied()), [(peer, Some(7))]);
    assert!(h.mgr.bfd_coupling.as_ref().unwrap().bound.contains(&peer));
}

/// With no link monitor, the scope poll re-resolves configured link-local
/// BFD sessions only: it is not armed for binding-owned sessions alone, and
/// when it runs it moves a configured session to its interface's current
/// index while a binding-owned session keeps its binding's index.
#[tokio::test(start_paused = true)]
async fn the_no_monitor_scope_poll_never_moves_a_bindings_bfd_session() {
    let (mut h, mut bfd) = bfd_harness(&["swp1"], &[("swp1", 7, true)], false);
    h.bind("swp1", Some(endpoint(2, 7))).await;
    bfd.next_applied();
    h.mgr.link_check.changes = None;
    // Mutation-red: arming for any link-local member polls for nothing.
    assert_eq!(h.mgr.bfd_scope_deadline(), None, "binding-owned only");

    // A configured link-local neighbor on `lo`, at a stale index.
    let configured: IpAddr = "fe80::9".parse().unwrap();
    let key = PeerKey::new(configured, Some("lo".to_owned()));
    insert_test_managed_peer_for_key(
        &mut h.mgr,
        &key,
        65002,
        fake_peer_handle(
            configured,
            SessionState::Active,
            None,
            Arc::new(FakePeerCounters::default()),
        ),
        false,
    );
    let transport = &mut h.mgr.peers.get_mut(&key).unwrap().transport_config;
    transport.peer_interface = Some("lo".to_owned());
    transport.peer_scope_id = Some(4242);
    h.mgr
        .bfd_coupling
        .as_mut()
        .unwrap()
        .configured
        .insert(configured, session_params(configured, Some(4242)));
    // The binding's interface now resolves elsewhere, unreported.
    h.links.send_replace(snapshot(true, &[("swp1", 9, true)]));

    let due = h
        .mgr
        .bfd_scope_deadline()
        .expect("polled for the configured one");
    tokio::time::sleep_until(due).await;
    h.mgr.bfd_scope_retry_due();
    h.mgr.run_due_bfd_scope_refresh().await;
    let lo = nix::net::if_::if_nametoindex("lo").unwrap();
    // Mutation-red: without the refresh skip the binding's session moves too.
    assert_eq!(
        BfdSide::sessions(&bfd.next_applied()),
        [(IpAddr::V6(ll(2)), Some(7)), (configured, Some(lo))]
    );
}

fn bfd_session_up(h: &Harness, peer: &str) -> Option<f64> {
    h.mgr
        .metrics
        .registry()
        .gather()
        .into_iter()
        .find(|family| family.name() == "bfd_session_up")
        .and_then(|family| {
            family.get_metric().iter().find_map(|metric| {
                metric
                    .get_label()
                    .iter()
                    .any(|label| label.name() == "peer" && label.value() == peer)
                    .then(|| metric.get_gauge().get_value())
            })
        })
}

/// A non-strict binding whose remote never answers BFD keeps its
/// `bfd_session_up 0` series: the registration's own Down acknowledgement,
/// which arrives before the bound peer exists, is not a deletion, and the
/// series survives a reconcile.
#[tokio::test]
async fn an_unanswered_bindings_bfd_gauge_stays_at_zero() {
    let (mut h, mut bfd) = bfd_harness(&["swp1"], &[("swp1", 7, true)], false);
    // Mutation-red: reaping for a peer that is only awaiting insertion
    // drops the series the actor just seeded.
    h.bind("swp1", Some(endpoint(2, 7))).await;
    bfd.next_applied();
    let label = format!("{}%swp1", ll(2));
    assert_eq!(bfd_session_up(&h, &label), Some(0.0));
    h.bind("swp1", Some(endpoint(2, 7))).await;
    assert_eq!(bfd_session_up(&h, &label), Some(0.0), "after a reconcile");
}

/// A rejected reload preparation stages nothing: the next unrelated
/// membership commit must not publish a stale binding-owned set.
#[tokio::test]
async fn a_rejected_reload_preparation_leaves_no_staged_bindings() {
    let (mut h, mut bfd) = bfd_harness(
        &["swp1", "swp2"],
        &[("swp1", 7, true), ("swp2", 8, true)],
        false,
    );
    h.bind("swp1", Some(endpoint(2, 7))).await;
    bfd.next_applied();
    // A candidate without BFD on the interface-only neighbors, with an
    // addressed neighbor naming a missing profile: preparation fails after
    // the binding sessions are rebuilt.
    let candidate: crate::config::Config = toml::from_str(
        "[global]\nasn = 65001\nrouter_id = \"10.0.0.1\"\nlisten_port = 179\n\
         [global.telemetry]\nlog_format = \"json\"\n\
         [[neighbors]]\ninterface = \"swp1\"\nremote_asn = \"external\"\nfamilies = [\"ipv6_unicast\"]\n\
         [[neighbors]]\ninterface = \"swp2\"\nremote_asn = \"external\"\nfamilies = [\"ipv6_unicast\"]\n\
         [[neighbors]]\naddress = \"192.0.2.7\"\nremote_asn = 65002\nbfd = { profile = \"missing\" }\n",
    )
    .unwrap();
    assert!(h.mgr.prepare_bfd_reload(&candidate).is_err());

    // Mutation-red: a stage left by the rejection overwrites this commit's
    // binding-owned set.
    h.bind("swp2", Some(endpoint(3, 8))).await;
    bfd.next_applied();
    let bound = &h.mgr.bfd_coupling.as_ref().unwrap().bound;
    assert!(bound.contains(&IpAddr::V6(ll(2))) && bound.contains(&IpAddr::V6(ll(3))));
}
