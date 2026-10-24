//! ADR-0142 interface-only neighbors: binding, address change, carrier loss
//! and the duplicate-address admission guard, driven through the discovery
//! event stream and the link snapshot.

use std::net::Ipv6Addr;

use rustbgpd_fsm::SessionState;
use rustbgpd_rib::{PeerId, PeerRetention};
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
    /// Retention queries [`Harness::answer_retention`] answered.
    retention_queries: Arc<AtomicU32>,
}

/// A manager with one interface-only neighbor per name in `interfaces`
/// (`remote_asn = "external"`), discovery recorded, and `links` reported by
/// the link monitor.
fn harness(interfaces: &[&str], links: &[(&str, u32, bool)]) -> Harness {
    harness_with(interfaces, links, "", "", None)
}

/// [`harness`] with `neighbor_extra` added to every interface-only stanza,
/// `extra` appended to the configuration, and `gtsm` standing in for the
/// listener's learned-selector update.
fn harness_with(
    interfaces: &[&str],
    links: &[(&str, u32, bool)],
    neighbor_extra: &str,
    extra: &str,
    gtsm: Option<LearnedGtsmUpdate>,
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
    let mgr = match gtsm {
        Some(update) => mgr.with_gtsm_update(update),
        None => mgr,
    };
    let mgr = mgr
        .with_link_failover(links_rx)
        .with_unnumbered(Unnumbered::new(discovery, events_rx));
    Harness {
        mgr,
        commands,
        links: links_tx,
        rib_rx,
        retention_queries: Arc::default(),
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

    /// Answer the RIB's retention queries with the returned value, as it
    /// stands when each query arrives. Every other RIB message is dropped.
    fn answer_retention(&mut self) -> Arc<std::sync::Mutex<PeerRetention>> {
        let retention = Arc::new(std::sync::Mutex::new(PeerRetention {
            stale_routes: 0,
            next_deadline: None,
        }));
        let (_tx, rx) = mpsc::channel(1);
        let mut rib_rx = std::mem::replace(&mut self.rib_rx, rx);
        let answer = Arc::clone(&retention);
        let queries = Arc::clone(&self.retention_queries);
        tokio::spawn(async move {
            while let Some(update) = rib_rx.recv().await {
                if let RibUpdate::QueryPeerRetention { reply, .. } = update {
                    queries.fetch_add(1, Ordering::SeqCst);
                    let _ = reply.send(*answer.lock().unwrap());
                }
            }
        });
        retention
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
async fn a_lost_binding_keeps_an_established_peer_while_the_link_is_up() {
    let mut h = harness(&["swp1"], &[("swp1", 7, true)]);
    h.answer_retention();
    h.bind("swp1", Some(endpoint(2, 7))).await;
    h.mgr.note_unnumbered_session_state(
        &swp1_key(2),
        SessionState::OpenConfirm,
        SessionState::Established,
    );
    // Mutation-red: treating a lost binding as an unbind removes the peer.
    h.bind("swp1", None).await;
    assert!(h.mgr.peers.contains_key(&swp1_key(2)));
}

/// ADR-0142: the binding expires under an Established session, which then
/// fails with Graceful Restart. The neighbor keeps redialing its last
/// address, reserved against every other link, until the stale timer
/// retires the routes; then the peer is removed and the address released.
#[tokio::test(start_paused = true)]
async fn an_unbound_neighbors_address_is_reserved_until_its_gr_routes_retire() {
    let mut h = harness(&["swp1", "swp2"], &[("swp1", 7, true), ("swp2", 8, true)]);
    let retention = h.answer_retention();
    h.bind("swp1", Some(endpoint(2, 7))).await;
    let key = swp1_key(2);
    h.mgr
        .note_unnumbered_session_state(&key, SessionState::OpenConfirm, SessionState::Established);
    h.bind("swp1", None).await;

    let deadline = tokio::time::Instant::now() + Duration::from_secs(120);
    *retention.lock().unwrap() = PeerRetention {
        stale_routes: 3,
        next_deadline: Some(deadline),
    };
    h.mgr.note_unnumbered_session_idle(&key);
    h.reconcile().await;
    // Mutation-red: releasing without reading the retention removes it here.
    assert_eq!(
        h.peers_at(ll(2)),
        std::slice::from_ref(&key),
        "reserved while retained"
    );
    assert_eq!(
        h.mgr.unnumbered_retry_at(),
        Some(deadline),
        "checked again at the RIB's timer"
    );
    let swp2 = PeerKey::new(IpAddr::V6(ll(2)), Some("swp2".into()));
    h.bind("swp2", Some(endpoint(2, 8))).await;
    assert_eq!(
        h.peers_at(ll(2)),
        std::slice::from_ref(&key),
        "another link is refused"
    );

    // The stale timer sweeps the routes.
    tokio::time::sleep_until(deadline).await;
    *retention.lock().unwrap() = PeerRetention {
        stale_routes: 0,
        next_deadline: None,
    };
    h.mgr.unnumbered_retry_due();
    h.reconcile().await;
    h.reconcile().await;
    // Mutation-red: keeping every unbound peer leaves swp1 holding it.
    assert_eq!(h.peers_at(ll(2)), [swp2], "released, then admitted on swp2");
}

/// The session establishes and fails with GR after the retention check but
/// before the conditional shutdown, which then succeeds on a down session.
/// The retention that failure left keeps the stopped peer, and its address.
async fn retention_left_after_the_check() -> (
    Harness,
    Arc<std::sync::Mutex<PeerRetention>>,
    tokio::time::Instant,
) {
    let mut h = harness(&["swp1"], &[("swp1", 7, true)]);
    let retention = h.answer_retention();
    h.bind("swp1", Some(endpoint(2, 7))).await;
    let key = swp1_key(2);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(120);
    let (tx, mut rx) = mpsc::channel::<PeerCommand>(8);
    let flip = Arc::clone(&retention);
    let task = tokio::spawn(async move {
        while let Some(command) = rx.recv().await {
            match command {
                PeerCommand::QueryState { reply } => {
                    let _ = reply.send(policy_test_peer_state(
                        IpAddr::V6(ll(2)),
                        SessionState::Active,
                    ));
                }
                PeerCommand::ShutdownUnlessConnected { reply } => {
                    *flip.lock().unwrap() = PeerRetention {
                        stale_routes: 3,
                        next_deadline: Some(deadline),
                    };
                    let _ = reply.send(true);
                    break;
                }
                _ => {}
            }
        }
        Ok(())
    });
    h.replace_session(&key, PeerHandle::from_parts(tx, task));

    // Mutation-red: deciding on the first query alone purges that retention.
    h.bind("swp1", None).await;
    assert_eq!(
        h.peers_at(ll(2)),
        std::slice::from_ref(&key),
        "kept, stopped"
    );
    assert_eq!(h.mgr.unnumbered_retry_at(), Some(deadline));
    (h, retention, deadline)
}

#[tokio::test(start_paused = true)]
async fn retention_left_after_the_check_keeps_the_stopped_peer_until_it_retires() {
    let (mut h, retention, deadline) = retention_left_after_the_check().await;
    tokio::time::sleep_until(deadline).await;
    *retention.lock().unwrap() = PeerRetention {
        stale_routes: 0,
        next_deadline: None,
    };
    h.mgr.unnumbered_retry_due();
    h.reconcile().await;
    assert_eq!(h.peers_at(ll(2)), []);
}

/// A binding that returns to the stopped peer's address replaces it with a
/// live session instead of keeping the stopped one.
#[tokio::test(start_paused = true)]
async fn a_returning_binding_replaces_a_stopped_retained_peer() {
    let (mut h, _retention, _) = retention_left_after_the_check().await;
    // Mutation-red: keeping the same endpoint leaves the stopped session.
    h.bind("swp1", Some(endpoint(2, 7))).await;
    assert_eq!(h.peers_at(ll(2)), [swp1_key(2)]);
    assert!(matches!(
        h.mgr.peers[&swp1_key(2)]
            .handle()
            .query_state_outcome(Duration::from_secs(1))
            .await,
        rustbgpd_transport::StateQueryOutcome::State(_)
    ));
}

/// An inbound reconnect installs a new session for the stopped peer before
/// the RA binding returns: the stop no longer describes the peer, so neither
/// a reconcile nor the returning binding ends that session.
#[tokio::test(start_paused = true)]
async fn an_inbound_reconnect_clears_the_stop_of_a_retained_peer() {
    let (mut h, retention, _) = retention_left_after_the_check().await;
    *retention.lock().unwrap() = PeerRetention {
        stale_routes: 0,
        next_deadline: None,
    };
    let counters = Arc::new(FakePeerCounters::default());
    h.replace_session(
        &swp1_key(2),
        fake_peer_handle(
            IpAddr::V6(ll(2)),
            SessionState::Established,
            None,
            Arc::clone(&counters),
        ),
    );
    // Mutation-red: a mark kept across the new session deletes it here,
    // or at the returning binding.
    h.mgr.unnumbered_retry_due();
    h.reconcile().await;
    h.bind("swp1", Some(endpoint(2, 7))).await;
    assert_eq!(h.peers_at(ll(2)), [swp1_key(2)]);
    assert_eq!(counters.shutdown.load(Ordering::SeqCst), 0);
    assert_eq!(counters.stop.load(Ordering::SeqCst), 0);
}

/// A release's conditional shutdown goes unanswered, then runs after the
/// session established and failed with GR. The settled exit leaves no
/// binding, so the stopped peer waits on that retention like any other.
#[tokio::test(start_paused = true)]
async fn a_late_release_shutdown_after_a_gr_teardown_keeps_the_retention() {
    let mut h = harness(&["swp1"], &[("swp1", 7, true)]);
    let retention = h.answer_retention();
    h.bind("swp1", Some(endpoint(2, 7))).await;
    let key = swp1_key(2);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(120);
    let (release, released) = oneshot::channel::<()>();
    let (exited_tx, exited) = oneshot::channel::<()>();
    let (tx, mut rx) = mpsc::channel::<PeerCommand>(8);
    let flip = Arc::clone(&retention);
    let task = tokio::spawn(async move {
        let mut released = Some(released);
        while let Some(command) = rx.recv().await {
            match command {
                PeerCommand::QueryState { reply } => {
                    let _ = reply.send(policy_test_peer_state(
                        IpAddr::V6(ll(2)),
                        SessionState::Active,
                    ));
                }
                PeerCommand::ShutdownUnlessConnected { reply } => {
                    if let Some(released) = released.take() {
                        let _ = released.await;
                    }
                    *flip.lock().unwrap() = PeerRetention {
                        stale_routes: 3,
                        next_deadline: Some(deadline),
                    };
                    let _ = reply.send(true);
                    break;
                }
                _ => {}
            }
        }
        drop(rx);
        let _ = exited_tx.send(());
        Ok(())
    });
    h.replace_session(&key, PeerHandle::from_parts(tx, task));

    h.bind("swp1", None).await;
    assert_eq!(h.peers_at(ll(2)), std::slice::from_ref(&key), "unanswered");
    release.send(()).unwrap();
    exited.await.unwrap();

    // Mutation-red: deleting the settled exit purges the new retention.
    h.mgr.unnumbered_retry_due();
    h.reconcile().await;
    assert_eq!(h.peers_at(ll(2)), std::slice::from_ref(&key), "retained");
    assert_eq!(h.mgr.unnumbered_retry_at(), Some(deadline));

    tokio::time::sleep_until(deadline).await;
    *retention.lock().unwrap() = PeerRetention {
        stale_routes: 0,
        next_deadline: None,
    };
    h.mgr.unnumbered_retry_due();
    h.reconcile().await;
    assert_eq!(h.peers_at(ll(2)), []);
}

/// An inbound connection learned without an RA is mid-handshake when a
/// reconcile runs for another port: the router is live, so it is kept.
#[tokio::test(start_paused = true)]
async fn an_inbound_handshake_without_an_ra_is_not_released() {
    let mut h = harness(&["swp1", "swp2"], &[("swp1", 7, true), ("swp2", 8, true)]);
    h.answer_retention();
    let _client = inbound(&mut h, 2, 7).await;
    let key = swp1_key(2);
    assert_eq!(h.peers_at(ll(2)), std::slice::from_ref(&key));
    let counters = Arc::new(FakePeerCounters::default());
    h.replace_session(
        &key,
        fake_peer_handle(
            IpAddr::V6(ll(2)),
            SessionState::OpenConfirm,
            None,
            Arc::clone(&counters),
        ),
    );
    h.mgr.peers.get_mut(&key).unwrap().pending_inbound = None;

    // Mutation-red: treating any state short of Established as down shuts
    // the handshake down.
    h.bind("swp2", Some(endpoint(5, 8))).await;
    h.mgr.unnumbered_retry_due();
    h.reconcile().await;
    assert_eq!(h.peers_at(ll(2)), std::slice::from_ref(&key));
    assert_eq!(counters.shutdown.load(Ordering::SeqCst), 0);
}

/// The session starts a handshake while the release waits on the RIB's
/// retention reply. The release's shutdown is decided by the session in its
/// own turn, so the now-connected session is kept.
#[tokio::test(start_paused = true)]
async fn a_handshake_that_starts_during_the_retention_query_is_kept() {
    let mut h = harness(&["swp1"], &[("swp1", 7, true)]);
    h.bind("swp1", Some(endpoint(2, 7))).await;
    let key = swp1_key(2);

    // The RIB answers the first retention query only once released.
    let (asked_tx, asked) = oneshot::channel::<()>();
    let (answer, answered) = oneshot::channel::<()>();
    let (_tx, rx) = mpsc::channel(1);
    let mut rib_rx = std::mem::replace(&mut h.rib_rx, rx);
    tokio::spawn(async move {
        let (mut asked_tx, mut answered) = (Some(asked_tx), Some(answered));
        while let Some(update) = rib_rx.recv().await {
            if let RibUpdate::QueryPeerRetention { reply, .. } = update {
                if let (Some(asked_tx), Some(answered)) = (asked_tx.take(), answered.take()) {
                    let _ = asked_tx.send(());
                    let _ = answered.await;
                }
                let _ = reply.send(PeerRetention {
                    stale_routes: 0,
                    next_deadline: None,
                });
            }
        }
    });

    let state = Arc::new(std::sync::Mutex::new(SessionState::Active));
    let shut_down = Arc::new(AtomicU32::new(0));
    let (tx, mut rx) = mpsc::channel::<PeerCommand>(8);
    let (session_state, session_shut_down) = (Arc::clone(&state), Arc::clone(&shut_down));
    let task = tokio::spawn(async move {
        while let Some(command) = rx.recv().await {
            let now = *session_state.lock().unwrap();
            let (reply, spared) = match command {
                PeerCommand::QueryState { reply } => {
                    let _ = reply.send(policy_test_peer_state(IpAddr::V6(ll(2)), now));
                    continue;
                }
                PeerCommand::ShutdownUnlessEstablished { reply } => {
                    (reply, now == SessionState::Established)
                }
                PeerCommand::ShutdownUnlessConnected { reply } => (
                    reply,
                    matches!(
                        now,
                        SessionState::OpenSent
                            | SessionState::OpenConfirm
                            | SessionState::Established
                    ),
                ),
                _ => continue,
            };
            let _ = reply.send(!spared);
            if !spared {
                session_shut_down.fetch_add(1, Ordering::SeqCst);
                break;
            }
        }
        Ok(())
    });
    h.replace_session(&key, PeerHandle::from_parts(tx, task));

    // Mutation-red: the Established-only shutdown closes the handshake.
    let handshake = async {
        asked.await.unwrap();
        *state.lock().unwrap() = SessionState::OpenSent;
        answer.send(()).unwrap();
    };
    tokio::join!(h.bind("swp1", None), handshake);
    assert_eq!(shut_down.load(Ordering::SeqCst), 0, "the handshake is kept");
    assert_eq!(h.peers_at(ll(2)), std::slice::from_ref(&key));

    // The handshake then fails in OpenSent, back to Active, which reports
    // nothing. Mutation-red: with no retry armed the address stays held.
    assert!(h.mgr.unnumbered_retry_at().is_some(), "checked again");
    *state.lock().unwrap() = SessionState::Active;
    h.mgr.unnumbered_retry_due();
    h.reconcile().await;
    assert_eq!(h.peers_at(ll(2)), [], "released after the failed handshake");
}

/// A session found mid-handshake by the release's state read is kept and
/// checked again: a failure in `OpenSent` falls back to Active silently, and
/// the next check releases the address.
#[tokio::test(start_paused = true)]
async fn a_handshake_that_fails_after_the_state_read_releases_the_address() {
    let mut h = harness(&["swp1"], &[("swp1", 7, true)]);
    h.answer_retention();
    h.bind("swp1", Some(endpoint(2, 7))).await;
    let key = swp1_key(2);
    let state = Arc::new(std::sync::Mutex::new(SessionState::OpenSent));
    let (tx, mut rx) = mpsc::channel::<PeerCommand>(8);
    let session_state = Arc::clone(&state);
    let task = tokio::spawn(async move {
        while let Some(command) = rx.recv().await {
            let now = *session_state.lock().unwrap();
            match command {
                PeerCommand::QueryState { reply } => {
                    let _ = reply.send(policy_test_peer_state(IpAddr::V6(ll(2)), now));
                }
                PeerCommand::ShutdownUnlessConnected { reply } => {
                    let quiet = !matches!(
                        now,
                        SessionState::OpenSent
                            | SessionState::OpenConfirm
                            | SessionState::Established
                    );
                    let _ = reply.send(quiet);
                    if quiet {
                        break;
                    }
                }
                _ => {}
            }
        }
        Ok(())
    });
    h.replace_session(&key, PeerHandle::from_parts(tx, task));

    h.bind("swp1", None).await;
    assert_eq!(
        h.peers_at(ll(2)),
        std::slice::from_ref(&key),
        "kept mid-handshake"
    );
    // Mutation-red: with no retry armed nothing checks the session again.
    assert!(h.mgr.unnumbered_retry_at().is_some(), "checked again");
    *state.lock().unwrap() = SessionState::Active;
    h.mgr.unnumbered_retry_due();
    h.reconcile().await;
    assert_eq!(h.peers_at(ll(2)), [], "released after the failed handshake");
}

/// A stopped peer kept for its retention has no session task: disable and
/// enable still apply, and a binding that returns carries the state to the
/// peer that replaces it.
#[tokio::test(start_paused = true)]
async fn disable_and_enable_apply_to_a_stopped_retained_peer() {
    let (mut h, _retention, _) = retention_left_after_the_check().await;
    let key = swp1_key(2);
    // Mutation-red: requiring the exited task to answer Stop or Start fails
    // both and leaves the neighbor disabled.
    h.mgr.disable_peer(key.clone(), None).await.unwrap();
    assert!(!h.mgr.peers[&key].enabled);
    h.mgr.enable_peer(key.clone()).await.unwrap();
    assert!(h.mgr.peers[&key].enabled);
    h.mgr.disable_peer(key.clone(), None).await.unwrap();

    h.bind("swp1", Some(endpoint(2, 7))).await;
    assert_eq!(h.peers_at(ll(2)), std::slice::from_ref(&key));
    assert!(
        !h.mgr.peers[&key].enabled,
        "the disable carries to the replacement"
    );
}

/// Without retained routes the address is released as soon as the session
/// is down.
#[tokio::test(start_paused = true)]
async fn an_unbound_neighbor_without_retained_routes_is_released_at_once() {
    let mut h = harness(&["swp1"], &[("swp1", 7, true)]);
    h.answer_retention();
    h.bind("swp1", Some(endpoint(2, 7))).await;
    let key = swp1_key(2);
    h.mgr
        .note_unnumbered_session_state(&key, SessionState::OpenConfirm, SessionState::Established);
    h.bind("swp1", None).await;
    assert_eq!(h.peers_at(ll(2)), std::slice::from_ref(&key));

    h.mgr.note_unnumbered_session_idle(&key);
    h.reconcile().await;
    assert_eq!(h.peers_at(ll(2)), []);
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
            rustbgpd_api::peer_types::PeerLifecycleError::Precondition(_)
        ),
        "{error}"
    );
    assert!(
        error.to_string().contains("by its interface") && error.to_string().contains("swp1"),
        "names the interface selector: {error}"
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
    mgr.unnumbered_runtime.spawn = Box::new(move |_, _| {
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
    h.mgr.unnumbered_runtime.spawn = Box::new(move |_, _| {
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

/// Unbound interface-only rows are projected from configured settings: a
/// listing compiles no policy chain, and each row's RFC 8212 status is the
/// one the neighbor's compiled chains give.
#[tokio::test]
async fn unbound_rows_compile_no_policy_and_keep_the_compiled_rfc8212_status() {
    use rustbgpd_api::peer_types::Rfc8212PolicyStatus as Status;
    let mut h = harness(&["swp1", "swp2", "swp3"], &[("swp1", 7, true)]);
    h.mgr.current_config = toml::from_str(
        r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179
ebgp_requires_policy = true

[global.telemetry]
log_format = "json"

[policy.definitions.permit-all]
default_action = "permit"

[peer_groups.edge]
export_policy_chain = ["permit-all"]

[[neighbors]]
interface = "swp1"
remote_asn = "external"
import_policy_chain = ["permit-all"]
export_policy_chain = ["permit-all"]

[[neighbors]]
interface = "swp2"
remote_asn = "external"
peer_group = "edge"

[[neighbors]]
interface = "swp3"
remote_asn = "internal"
"#,
    )
    .unwrap();

    let before = crate::config::POLICY_RESOLUTIONS.with(std::cell::Cell::get);
    let rows = h.mgr.list_peers().await;
    // Mutation-red: resolving each unbound row's chains counts here.
    assert_eq!(
        crate::config::POLICY_RESOLUTIONS.with(std::cell::Cell::get),
        before,
        "no policy compiled for unbound rows"
    );
    assert_eq!(rows.len(), 3);
    let enforced_by = h.mgr.current_config.rfc8212_posture().policy_effective;
    for (interface, expected) in [
        ("swp1", (Status::Present, Status::Present)),
        ("swp2", (Status::Missing, Status::Present)),
        ("swp3", (Status::NotRequired, Status::NotRequired)),
    ] {
        let row = rows
            .iter()
            .find(|info| info.interface.as_deref() == Some(interface))
            .unwrap();
        let reported = (row.rfc8212_import_policy, row.rfc8212_export_policy);
        assert_eq!(reported, expected, "{interface}");
        let neighbor = h
            .mgr
            .current_config
            .neighbors
            .interface_only_on(interface)
            .unwrap();
        let compiled = h
            .mgr
            .current_config
            .resolve_bound_interface_neighbor(neighbor, ll(1), 0)
            .unwrap();
        let enforced = enforced_by && compiled.rfc8212_external;
        assert_eq!(
            reported,
            (
                super::snapshot::rfc8212_status(
                    enforced,
                    compiled.import_policy.as_ref(),
                    crate::config::RFC8212_MISSING_IMPORT_POLICY,
                ),
                super::snapshot::rfc8212_status(
                    enforced,
                    compiled.export_policy.as_ref(),
                    crate::config::RFC8212_MISSING_EXPORT_POLICY,
                ),
            ),
            "{interface}: as the compiled chains report"
        );
    }
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
/// the old one, the binding is not trusted on its face: the session is read
/// and found gone. A reverted binding recreates it; an expired one leaves
/// nothing retained, so the address is released.
async fn settle_an_unanswered_retirement(reverted: bool) {
    {
        let mut h = harness(&["swp1"], &[("swp1", 7, true)]);
        h.answer_retention();
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
        if !reverted {
            assert_eq!(h.peers_at(ll(2)), [], "released");
            return;
        }
        assert_eq!(h.peers_at(ll(2)), [swp1_key(2)]);
        assert!(
            matches!(
                h.mgr.peers[&swp1_key(2)]
                    .handle()
                    .query_state_outcome(Duration::from_secs(1))
                    .await,
                rustbgpd_transport::StateQueryOutcome::State(_)
            ),
            "a live session replaces the exited one"
        );
    }
}

#[tokio::test(start_paused = true)]
async fn an_unanswered_retirement_then_an_expired_endpoint_releases_the_address() {
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

/// A late conditional retirement settles while a transaction is staged:
/// the replacement at the new endpoint is deferred, and discovery's binding
/// then expires before the stage clears. The exited peer is kept, with any
/// retention its replacement would purge, while the replacement is deferred;
/// with no binding left it is released only once nothing is retained.
async fn an_exited_peer_whose_deferred_replacement_expired(
    retained: bool,
) -> (Harness, Arc<std::sync::Mutex<PeerRetention>>) {
    let mut h = harness(&["swp1"], &[("swp1", 7, true)]);
    let retention = h.answer_retention();
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
    if retained {
        *retention.lock().unwrap() = PeerRetention {
            stale_routes: 3,
            next_deadline: Some(tokio::time::Instant::now() + Duration::from_secs(120)),
        };
    }

    h.mgr.config_snapshot_staged = true;
    h.bind("swp1", Some(endpoint(3, 7))).await;
    assert_eq!(h.peers_at(ll(2)), [swp1_key(2)], "kept while staged");
    assert_eq!(h.peers_at(ll(3)), [], "replacement deferred");
    // The expiry leaves the stopped peer to its retention at once: a
    // release binds nothing, so it does not wait for the stage.
    let asked = h.retention_queries.load(Ordering::SeqCst);
    h.bind("swp1", None).await;
    assert!(
        h.retention_queries.load(Ordering::SeqCst) > asked,
        "decided by the retention"
    );
    h.mgr.config_snapshot_staged = false;
    h.mgr.unnumbered_retry_due();
    h.reconcile().await;
    (h, retention)
}

/// Nothing retained: the exited peer is released, leaving no stale peer,
/// and a fresh RA at the new endpoint then creates the session normally.
#[tokio::test(start_paused = true)]
async fn an_exited_peer_whose_deferred_replacement_expired_is_released() {
    let (mut h, _) = an_exited_peer_whose_deferred_replacement_expired(false).await;
    // Mutation-red: the old recovery rebinds the exited endpoint instead.
    assert_eq!(h.peers_at(ll(2)), [], "released");
    assert_eq!(h.peers_at(ll(3)), []);
    assert!(h.mgr.peers.is_empty(), "no stale peer");
    assert_eq!(
        h.mgr.unnumbered_owner_of(&swp1_key(2)),
        None,
        "port unbound"
    );

    h.bind("swp1", Some(endpoint(3, 7))).await;
    assert_eq!(h.peers_at(ll(3)), [swp1_key(3)]);
    assert_eq!(h.mgr.unnumbered_owner_of(&swp1_key(3)), Some("swp1"));
    assert!(matches!(
        h.mgr.peers[&swp1_key(3)]
            .handle()
            .query_state_outcome(Duration::from_secs(1))
            .await,
        rustbgpd_transport::StateQueryOutcome::State(_)
    ));
}

/// Routes still retained from the exited session: the peer and its address
/// are kept until the retention ends, then released, and an inbound
/// connection from the new endpoint creates the session normally.
#[tokio::test(start_paused = true)]
async fn an_exited_peer_whose_deferred_replacement_expired_waits_on_its_retention() {
    let (mut h, retention) = an_exited_peer_whose_deferred_replacement_expired(true).await;
    // Mutation-red: deleting the exited peer in the staged pass purges it.
    assert_eq!(h.peers_at(ll(2)), [swp1_key(2)], "kept while retained");
    let deadline = h
        .mgr
        .unnumbered_retry_at()
        .expect("checked again at the RIB's timer");

    tokio::time::sleep_until(deadline).await;
    *retention.lock().unwrap() = PeerRetention {
        stale_routes: 0,
        next_deadline: None,
    };
    h.mgr.unnumbered_retry_due();
    h.reconcile().await;
    assert_eq!(h.peers_at(ll(2)), [], "released once nothing is retained");
    assert!(h.mgr.peers.is_empty());

    let _client = inbound(&mut h, 3, 7).await;
    assert_eq!(h.peers_at(ll(3)), [swp1_key(3)]);
    assert_eq!(h.mgr.unnumbered_owner_of(&swp1_key(3)), Some("swp1"));
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
            None,
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
        peer_interface: String::new(),
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
        retention_queries,
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
            retention_queries,
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
            None,
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
            None,
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
    // The neighbor's series name its interface (ADR-0142 metrics).
    let label = "interface:swp1";
    assert_eq!(bfd_session_up(&h, label), Some(0.0));
    h.bind("swp1", Some(endpoint(2, 7))).await;
    assert_eq!(bfd_session_up(&h, label), Some(0.0), "after a reconcile");
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

/// A static link-local neighbor on `lo`, which every host has, so a
/// generation can add it.
fn static_on_lo(last: u16) -> crate::config::Neighbor {
    toml::from_str(&format!(
        "address = \"fe80::{last:x}\"\ninterface = \"lo\"\nremote_asn = 65002\n"
    ))
    .unwrap()
}

/// A SIGHUP generation whose preflight passed holds its static link-local
/// address closed to discovery until it applies: the reload route makes
/// effects outside the peer manager in between, and the generation's own
/// check must not fail after them. The generation then adds its static
/// neighbor; a route that ends without dispatching lets the hold lapse.
#[tokio::test]
async fn a_preflighted_generation_holds_its_static_address_from_discovery() {
    let mut h = harness(&["swp1"], &[("swp1", 7, true)]);
    let mut candidate = h.mgr.current_config.clone();
    candidate.neighbors.push(static_on_lo(2));
    let route = Arc::new(());
    h.mgr
        .preflight_reload_generation(&candidate, Arc::downgrade(&route))
        .unwrap();
    // Mutation-red: without the hold discovery binds the address here and
    // the generation is refused after the route's effects.
    h.bind("swp1", Some(endpoint(2, 7))).await;
    assert_eq!(h.peers_at(ll(2)), [], "held for the pending generation");
    assert!(h.mgr.unnumbered_retry_at().is_some(), "asked again later");
    let actions =
        crate::config::plan_reload_peer_actions(&h.mgr.current_config, &candidate).unwrap();
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
    let static_key = PeerKey::new(IpAddr::V6(ll(2)), Some("lo".into()));
    assert_eq!(h.peers_at(ll(2)), [static_key]);
    drop(route);

    // The route returned before dispatching: the hold lapses with it.
    let mut h = harness(&["swp1"], &[("swp1", 7, true)]);
    let mut candidate = h.mgr.current_config.clone();
    candidate.neighbors.push(static_on_lo(2));
    let route = Arc::new(());
    h.mgr
        .preflight_reload_generation(&candidate, Arc::downgrade(&route))
        .unwrap();
    h.bind("swp1", Some(endpoint(2, 7))).await;
    assert_eq!(h.peers_at(ll(2)), []);
    drop(route);
    h.mgr.unnumbered_retry_due();
    h.reconcile().await;
    assert_eq!(
        h.peers_at(ll(2)),
        [swp1_key(2)],
        "bound once the hold lapsed"
    );
}

/// Answer the RIB requests a running manager awaits; drop the rest.
fn answer_rib(mut rib_rx: mpsc::Receiver<RibUpdate>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        while let Some(update) = rib_rx.recv().await {
            match update {
                RibUpdate::PublishDampeningOwners { reply, .. } => {
                    let _ = reply.send(Ok(()));
                }
                RibUpdate::QueryUpdateGroupSnapshot { reply } => {
                    let _ = reply.send(rustbgpd_rib::UpdateGroupSnapshot::default());
                }
                _ => {}
            }
        }
    })
}

/// Discovery binds an address after a transaction's plan accepted a static
/// add of the same address and before the snapshot is staged. The owner
/// rechecks while staging, so the transaction is refused with nothing
/// installed instead of starting earlier static peers first.
#[tokio::test]
async fn a_binding_between_plan_and_stage_refuses_the_static_add() {
    let (tx, rx) = mpsc::channel(16);
    let (internal_tx, internal_rx) = mpsc::channel(1);
    let (rib_tx, rib_rx) = mpsc::channel(64);
    let config = harness(&["swp1"], &[]).mgr.current_config.clone();
    let (links_tx, links_rx) = watch::channel(snapshot(true, &[("swp1", 7, true)]));
    let (discovery, _commands) = RaDiscovery::recording();
    let (events_tx, events_rx) = mpsc::unbounded_channel();
    let mgr = PeerManager::new_with_config(
        rx,
        internal_rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        BgpMetrics::new(),
        rib_tx,
        None,
        None,
        config.clone(),
    )
    .with_link_failover(links_rx)
    .with_unnumbered(Unnumbered::new(discovery, events_rx));
    let rib = answer_rib(rib_rx);
    let task = tokio::spawn(mgr.run());

    let mut candidate = config;
    candidate.neighbors.push(static_on_lo(2));
    let (reply_tx, reply_rx) = oneshot::channel();
    internal_tx
        .send(InternalCommand::PlanTransactionConfig {
            candidate: Box::new(candidate),
            expected_runtime_snapshot_token: None,
            reply: reply_tx,
        })
        .await
        .unwrap();
    let planned = reply_rx.await.unwrap().unwrap();
    assert_eq!(
        planned.plan.status,
        rustbgpd_api::peer_types::RuntimeConfigTransactionStatus::Committable,
        "{:?}",
        planned.plan
    );

    // Handshake: the owner reports the bound peer before the stage is sent.
    events_tx
        .send(DiscoveryEvent::BindingChanged {
            interface: "swp1".into(),
            previous: None,
            current: Some(endpoint(2, 7)),
        })
        .unwrap();
    let peers = || async {
        let (list_tx, list_rx) = oneshot::channel();
        tx.send(PeerManagerCommand::ListPeers { reply: list_tx })
            .await
            .unwrap();
        list_rx.await.unwrap()
    };
    let mut bound = false;
    for _ in 0..1000 {
        if peers()
            .await
            .iter()
            .any(|peer| peer.address == IpAddr::V6(ll(2)))
        {
            bound = true;
            break;
        }
        tokio::task::yield_now().await;
    }
    assert!(bound, "discovery bound swp1");

    let (stage_tx, stage_rx) = oneshot::channel();
    internal_tx
        .send(InternalCommand::StageTransactionConfig {
            candidate: planned.candidate,
            scope: TransactionConfigScope::Full,
            reply: stage_tx,
        })
        .await
        .unwrap();
    // Mutation-red: without the recheck the stage installs the candidate.
    let Err(error) = stage_rx.await.unwrap() else {
        panic!("the stage installed a duplicate address");
    };
    assert!(error.contains("duplicate_link_local_address"), "{error}");
    assert!(error.contains("swp1"), "names the holder: {error}");
    let peers = peers().await;
    assert_eq!(peers.len(), 1, "only the learned peer: {peers:?}");

    tx.send(PeerManagerCommand::Shutdown).await.unwrap();
    task.await.unwrap();
    drop(links_tx);
    rib.abort();
}

// ---------------------------------------------------------------------------
// The neighbor and peer-group RPCs: an owned mutation of `current_config`,
// then the same port reconcile as a reload.
// ---------------------------------------------------------------------------

/// An `AddNeighbor` create for the interface-only neighbor on `interface`.
fn interface_only_create(
    interface: &str,
    mode: rustbgpd_api::peer_types::RemoteAsnMode,
) -> Box<rustbgpd_api::peer_types::PresenceAwareNeighborCreate> {
    Box::new(rustbgpd_api::peer_types::PresenceAwareNeighborCreate {
        address: None,
        interface: Some(interface.into()),
        remote_asn: 0,
        remote_asn_mode: mode,
        description: None,
        peer_group: None,
        hold_time: None,
        min_hold_time: None,
        send_hold_time: None,
        max_prefixes: None,
        max_prefix_restart_seconds: None,
        remove_private_as: None,
        discard_path_attributes: None,
        local_role: None,
        families: Some(vec![(
            rustbgpd_wire::Afi::Ipv6,
            rustbgpd_wire::Safi::Unicast,
        )]),
        required_families: None,
        route_server_client: None,
        per_client_best: None,
        strict_role: None,
        add_path: None,
    })
}

impl Harness {
    async fn owned_neighbor(
        &mut self,
        mutation: rustbgpd_api::peer_types::OwnedNeighborMutation,
    ) -> rustbgpd_api::peer_types::OwnedNeighborMutationOutcome {
        let (reply, outcome) = oneshot::channel();
        let _ = Box::pin(
            self.mgr
                .dispatch_command(PeerManagerCommand::OwnedNeighborMutation { mutation, reply }),
        )
        .await;
        outcome.await.unwrap()
    }
}

fn refused(
    outcome: rustbgpd_api::peer_types::OwnedNeighborMutationOutcome,
) -> rustbgpd_api::peer_types::PeerLifecycleError {
    match outcome {
        rustbgpd_api::peer_types::OwnedNeighborMutationOutcome::RejectedNoEffect(
            rustbgpd_api::peer_types::OwnedNeighborMutationError::Peer(error),
        ) => error,
        other => panic!("expected a refusal with no effect, got {other:?}"),
    }
}

/// `AddNeighbor` of an interface-only neighbor installs it in the running
/// configuration with its `remote_asn` mode; the reconcile starts discovery
/// and a binding creates its peer. A second add on the interface exists.
#[tokio::test]
async fn an_rpc_add_starts_discovery_and_carries_the_remote_asn_mode() {
    use rustbgpd_api::peer_types::{OwnedNeighborMutation, OwnedNeighborMutationOutcome};
    let (mut h, launched) = Harness::without_discovery(&[("swp1", 7, true)]);
    h.mgr.unnumbered_runtime.probe = || Ok(());
    let internal = rustbgpd_api::peer_types::RemoteAsnMode::Internal;
    let outcome = h
        .owned_neighbor(OwnedNeighborMutation::Add(interface_only_create(
            "swp1", internal,
        )))
        .await;
    assert!(
        matches!(outcome, OwnedNeighborMutationOutcome::Success),
        "{outcome:?}"
    );
    let neighbor = h
        .mgr
        .current_config
        .neighbors
        .interface_only_on("swp1")
        .expect("configured");
    assert_eq!(neighbor.remote_asn, crate::config::RemoteAsn::Internal);
    // Mutation-red: without installing the neighbor no discovery starts.
    h.reconcile().await;
    assert_eq!(launched.lock().unwrap().len(), 1, "discovery started");
    assert_eq!(
        drain_launched(&launched).first(),
        Some(&Command::Start("swp1".into()))
    );
    h.bind("swp1", Some(endpoint(2, 7))).await;
    assert_eq!(h.peers_at(ll(2)), [swp1_key(2)]);

    let again = h
        .owned_neighbor(OwnedNeighborMutation::Add(interface_only_create(
            "swp1", internal,
        )))
        .await;
    assert!(
        matches!(
            refused(again),
            rustbgpd_api::peer_types::PeerLifecycleError::InterfaceOnlyExists(_)
        ),
        "already configured"
    );
}

/// The first interface-only neighbor added without `CAP_NET_RAW` is
/// refused as a failed precondition naming it, with nothing changed: no
/// configuration, port, discovery actor or peer.
#[tokio::test]
async fn a_refused_rpc_add_changes_nothing() {
    use rustbgpd_api::peer_types::OwnedNeighborMutation;
    let (mut h, launched) = Harness::without_discovery(&[("swp1", 7, true)]);
    h.mgr.unnumbered_runtime.probe = || {
        Err(
            "interface-only neighbor discovery needs CAP_NET_RAW to open a raw ICMPv6 socket"
                .into(),
        )
    };
    let before = h.mgr.current_config.clone();
    // Mutation-red: without the preflight the add is installed.
    let error = refused(
        h.owned_neighbor(OwnedNeighborMutation::Add(interface_only_create(
            "swp1",
            rustbgpd_api::peer_types::RemoteAsnMode::External,
        )))
        .await,
    );
    let rustbgpd_api::peer_types::PeerLifecycleError::Precondition(message) = &error else {
        panic!("{error:?}");
    };
    assert!(message.contains("CAP_NET_RAW"), "{message}");
    assert_eq!(h.mgr.current_config, before, "running config untouched");
    h.reconcile().await;
    assert!(launched.lock().unwrap().is_empty(), "no discovery");
    assert!(h.mgr.unnumbered.is_none(), "no port");
    assert!(h.mgr.peers.is_empty(), "no peer");
}

/// A static link-local `AddNeighbor` whose address a learned endpoint
/// holds, bound or reserved, is a failed precondition with nothing changed.
#[tokio::test]
async fn an_rpc_static_add_against_a_learned_address_changes_nothing() {
    use rustbgpd_api::peer_types::OwnedNeighborMutation;
    let mut h = harness(&["swp1"], &[("swp1", 7, true)]);
    h.bind("swp1", Some(endpoint(2, 7))).await;
    let mut create = interface_only_create("lo", rustbgpd_api::peer_types::RemoteAsnMode::Numeric);
    create.address = Some(IpAddr::V6(ll(2)));
    create.remote_asn = 65002;
    for state in ["bound", "reserved"] {
        if state == "reserved" {
            h.bind("swp1", None).await;
        }
        let before = h.mgr.current_config.clone();
        // Mutation-red: without the preflight the add replaces the config,
        // fails admission and is reported as compensated.
        let error = refused(
            h.owned_neighbor(OwnedNeighborMutation::Add(create.clone()))
                .await,
        );
        let rustbgpd_api::peer_types::PeerLifecycleError::Precondition(message) = &error else {
            panic!("{state}: {error:?}");
        };
        assert!(
            message.contains("duplicate_link_local_address"),
            "{state}: {message}"
        );
        assert!(
            message.contains("swp1"),
            "{state}: names the holder: {message}"
        );
        assert_eq!(h.mgr.current_config, before, "{state}");
        assert_eq!(h.peers_at(ll(2)), [swp1_key(2)], "{state}");
    }
}

/// `DeleteNeighbor` by interface ends a bound interface-only neighbor's
/// session through the reconcile, stops discovery on it, keeps the other
/// neighbor's session, and refuses an interface with no such neighbor.
#[tokio::test]
async fn an_rpc_delete_ends_a_bound_interface_only_neighbor() {
    use rustbgpd_api::peer_types::{OwnedNeighborMutation, OwnedNeighborMutationOutcome};
    let mut h = harness(&["swp1", "swp2"], &[("swp1", 7, true), ("swp2", 8, true)]);
    h.bind("swp1", Some(endpoint(2, 7))).await;
    h.bind("swp2", Some(endpoint(3, 8))).await;
    let swp2 = PeerKey::new(IpAddr::V6(ll(3)), Some("swp2".into()));
    let swp2_session = h.session(&swp2);
    h.drain();
    let outcome = h
        .owned_neighbor(OwnedNeighborMutation::DeleteInterfaceOnly("swp1".into()))
        .await;
    assert!(
        matches!(outcome, OwnedNeighborMutationOutcome::Success),
        "{outcome:?}"
    );
    assert!(
        h.mgr
            .current_config
            .neighbors
            .interface_only_on("swp1")
            .is_none()
    );
    // Mutation-red: without removing the stanza the session survives.
    h.reconcile().await;
    assert!(!h.mgr.peers.contains_key(&swp1_key(2)), "session ended");
    assert_eq!(h.drain(), [Command::Stop("swp1".into())]);
    assert_eq!(h.session(&swp2), swp2_session, "the other neighbor is kept");

    let missing = refused(
        h.owned_neighbor(OwnedNeighborMutation::DeleteInterfaceOnly("swp9".into()))
            .await,
    );
    assert!(
        matches!(
            missing,
            rustbgpd_api::peer_types::PeerLifecycleError::InterfaceOnlyNotFound(_)
        ),
        "{missing:?}"
    );
}

/// A `SetPeerGroup` session edit that reaches an interface-only member is
/// applied: the member rebinds under the new settings on the reconcile,
/// and a neighbor of another group keeps its session.
#[tokio::test]
async fn a_peer_group_rpc_rebinds_only_the_changed_members() {
    let groups = config_with(&format!(
        "[peer_groups.fabric]\nhold_time = 9\n[peer_groups.other]\nhold_time = 90\n{}{}",
        port_stanza("swp1", "peer_group = \"fabric\"\n"),
        port_stanza("swp2", "peer_group = \"other\"\n")
    ));
    let mut h = harness(&[], &[("swp1", 7, true), ("swp2", 8, true)]);
    h.reload(groups).await;
    h.bind("swp1", Some(endpoint(2, 7))).await;
    h.bind("swp2", Some(endpoint(3, 8))).await;
    let swp2 = PeerKey::new(IpAddr::V6(ll(3)), Some("swp2".into()));
    let (swp1_session, swp2_session) = (h.session(&swp1_key(2)), h.session(&swp2));

    let mut definition =
        crate::policy_admin::config_peer_group_to_api(&h.mgr.current_config.peer_groups["fabric"]);
    definition.hold_time = Some(30);
    let (reply, outcome) = oneshot::channel();
    let _ = Box::pin(
        h.mgr
            .dispatch_command(PeerManagerCommand::OwnedCatalogMutation {
                mutation: rustbgpd_api::peer_types::OwnedCatalogMutation::SetPeerGroup {
                    name: "fabric".to_string(),
                    definition: Box::new(definition),
                },
                reply,
            }),
    )
    .await;
    // Mutation-red: with the old refusal the edit is rejected.
    let outcome = outcome.await.unwrap();
    assert!(
        matches!(
            outcome,
            rustbgpd_api::peer_types::OwnedCatalogMutationOutcome::Success
        ),
        "{outcome:?}"
    );
    h.reconcile().await;
    assert_ne!(
        h.session(&swp1_key(2)),
        swp1_session,
        "fabric member rebound"
    );
    assert_eq!(h.mgr.peers[&swp1_key(2)].hold_time, Some(30));
    assert_eq!(h.session(&swp2), swp2_session, "other group untouched");
}

/// A static neighbor that replaces an interface-only stanza at its learned
/// address on the same interface collides with the still-bound peer, whose
/// key it shares. The preflight refuses it before any effect.
#[tokio::test]
async fn a_static_neighbor_at_the_bound_key_is_refused_before_any_effect() {
    let mut h = harness(&["swp1"], &[("swp1", 7, true)]);
    h.bind("swp1", Some(endpoint(2, 7))).await;
    let mut candidate = config_with("");
    candidate.neighbors.push(
        toml::from_str::<crate::config::Neighbor>(
            "address = \"fe80::2\"\ninterface = \"swp1\"\nremote_asn = 65002\n",
        )
        .unwrap(),
    );
    // Mutation-red: excluding the identical key passes the preflight.
    let error = h.mgr.unnumbered_preflight(&candidate).unwrap_err();
    assert!(error.contains("duplicate_link_local_address"), "{error}");
    assert!(error.contains("swp1"), "names the holder: {error}");
    // The reload route's preflight command refuses it the same way, before
    // either executor runs.
    let before = h.mgr.current_config.clone();
    let route = Arc::new(());
    let error = h
        .mgr
        .preflight_reload_generation(&candidate, Arc::downgrade(&route))
        .unwrap_err();
    assert!(error.contains("duplicate_link_local_address"), "{error}");
    assert_eq!(h.mgr.current_config, before);
    assert_eq!(h.peers_at(ll(2)), [swp1_key(2)]);
}

/// `[policy.explain]` and `[policy.reject_retention]` apply to sessions
/// created later and leave a bound interface-only session in place, as for
/// a static neighbor.
#[tokio::test]
async fn an_explain_or_retention_edit_keeps_bound_interface_only_sessions() {
    let mut h = harness(&["swp1"], &[("swp1", 7, true)]);
    h.bind("swp1", Some(endpoint(2, 7))).await;
    let session = h.session(&swp1_key(2));
    let stanza = port_stanza("swp1", "");
    for policy in [
        "[policy.explain]\nenabled = true\ncache_size = 64\n",
        "[policy.reject_retention]\nenabled = false\n",
    ] {
        // Mutation-red: projecting these transport fields rebinds swp1.
        h.reload(config_with(&format!("{stanza}{policy}"))).await;
        assert_eq!(h.session(&swp1_key(2)), session, "kept: {policy}");
    }
}

/// The listener's learned-selector updates, in order, each with whether the
/// RIB had already been told the previous endpoint was deleted.
use crate::peer_manager::unnumbered::{LearnedGtsmOutcome, LearnedGtsmUpdate, ListenerGtsmRequest};

type GtsmLog = Arc<std::sync::Mutex<Vec<(String, Option<Ipv6Addr>, bool)>>>;

/// A GTSM neighbor's harness whose listener answers `outcome` and logs
/// each update; the harness's RIB receiver is shared with the log so an
/// update can record what the RIB had seen when it arrived.
fn gtsm_harness(outcome: Arc<std::sync::Mutex<LearnedGtsmOutcome>>) -> (Harness, GtsmLog) {
    let log: GtsmLog = Arc::default();
    let rib: Arc<std::sync::Mutex<Option<mpsc::Receiver<RibUpdate>>>> = Arc::default();
    let update: LearnedGtsmUpdate = {
        let (log, rib) = (Arc::clone(&log), Arc::clone(&rib));
        Arc::new(move |request| {
            let ListenerGtsmRequest::Selector {
                interface,
                selector,
            } = request
            else {
                return Box::pin(async { LearnedGtsmOutcome::Applied });
            };
            let deleted = rib.lock().unwrap().as_mut().is_some_and(|rib| {
                std::iter::from_fn(|| rib.try_recv().ok())
                    .any(|update| matches!(update, RibUpdate::PeerDeleted { .. }))
            });
            log.lock().unwrap().push((
                interface,
                selector.map(|selector| selector.address),
                deleted,
            ));
            let outcome = outcome.lock().unwrap().clone();
            Box::pin(async move { outcome })
        })
    };
    let mut h = harness_with(
        &["swp1"],
        &[("swp1", 7, true)],
        "ttl_security = true\n",
        "",
        Some(update),
    );
    let (_tx, placeholder) = mpsc::channel(1);
    *rib.lock().unwrap() = Some(std::mem::replace(&mut h.rib_rx, placeholder));
    (h, log)
}

/// ADR-0142 GTSM: the learned endpoint's selector is installed before the
/// peer exists, so no inbound connection is matched without it, and a
/// selector the listener did not apply leaves the neighbor unbound.
#[tokio::test]
async fn a_gtsm_neighbor_binds_only_once_the_listener_has_its_selector() {
    let outcome = Arc::new(std::sync::Mutex::new(LearnedGtsmOutcome::Failed(
        "listener gone".into(),
    )));
    let (mut h, log) = gtsm_harness(Arc::clone(&outcome));
    h.bind("swp1", Some(endpoint(2, 7))).await;
    // Mutation-red: adding the peer first admits it without the selector.
    assert_eq!(h.peers_at(ll(2)), [], "refused while unapplied");
    assert_eq!(
        log.lock().unwrap().as_slice(),
        [("swp1".into(), Some(ll(2)), false)]
    );

    *outcome.lock().unwrap() = LearnedGtsmOutcome::Applied;
    h.mgr.unnumbered_retry_due();
    h.reconcile().await;
    assert_eq!(h.peers_at(ll(2)), [swp1_key(2)]);
    let hops = h.mgr.peers[&swp1_key(2)].transport_config.ttl_security_hops;
    assert_eq!(
        hops,
        Some(std::num::NonZeroU8::MIN),
        "active opens use TTL 255"
    );
}

/// A rebind removes the old endpoint's selector only after that peer is
/// deleted, then installs the new one before the new peer; a carrier loss
/// removes it after the peer is gone.
#[tokio::test]
async fn a_rebind_replaces_the_gtsm_selector_after_the_old_peer_is_retired() {
    let (mut h, log) = gtsm_harness(Arc::new(std::sync::Mutex::new(LearnedGtsmOutcome::Applied)));
    h.bind("swp1", Some(endpoint(2, 7))).await;
    h.bind("swp1", Some(endpoint(3, 7))).await;
    assert_eq!(h.peers_at(ll(3)), [swp1_key(3)]);
    h.links_changed(snapshot(true, &[("swp1", 7, false)]));
    h.reconcile().await;
    assert_eq!(h.peers_at(ll(3)), []);
    // Mutation-red: removing before the deletion leaves the old peer
    // matchable without its selector (`false` in the third field).
    assert_eq!(
        log.lock().unwrap().as_slice(),
        [
            ("swp1".into(), Some(ll(2)), false),
            ("swp1".into(), None, true),
            ("swp1".into(), Some(ll(3)), false),
            ("swp1".into(), None, true),
        ]
    );
}

/// Deleting a bound GTSM neighbor removes its selector only once its peer
/// is gone, and a removal the listener did not apply is retried: a later
/// neighbor at that address on that interface must not inherit GTSM.
#[tokio::test(start_paused = true)]
async fn deleting_a_gtsm_neighbor_removes_its_selector_after_its_peer() {
    let outcome = Arc::new(std::sync::Mutex::new(LearnedGtsmOutcome::Applied));
    let (mut h, log) = gtsm_harness(Arc::clone(&outcome));
    h.bind("swp1", Some(endpoint(2, 7))).await;
    *outcome.lock().unwrap() = LearnedGtsmOutcome::Failed("listener busy".into());
    // Mutation-red: a deletion that skips the selector leaves it enforced.
    h.reload(config_with("")).await;
    assert!(!h.mgr.peers.contains_key(&swp1_key(2)), "session ended");
    let removal = ("swp1".to_owned(), None, true);
    assert_eq!(log.lock().unwrap()[1..], *std::slice::from_ref(&removal));

    *outcome.lock().unwrap() = LearnedGtsmOutcome::Applied;
    let retry = h
        .mgr
        .unnumbered_retry_at()
        .expect("a failed removal is retried");
    tokio::time::sleep_until(retry).await;
    h.mgr.unnumbered_retry_due();
    h.reconcile().await;
    h.mgr.unnumbered_retry_due();
    h.reconcile().await;
    assert_eq!(
        log.lock().unwrap()[1..],
        [removal, ("swp1".to_owned(), None, false)],
        "retried once, then settled"
    );
}

/// A connection the listener accepted under a GTSM selector that a reload
/// has since turned off: it was queued with the old Hop Limit minimum, and
/// the replacement non-GTSM session must not inherit it, or a peer sending
/// a lower Hop Limit stalls. The minimum is cleared before the session gets
/// the connection.
#[tokio::test]
async fn an_accept_queued_under_a_gtsm_selector_a_reload_turned_off_is_cleared() {
    use tokio::io::AsyncWriteExt as _;
    let (mut h, _log) = gtsm_harness(Arc::new(std::sync::Mutex::new(LearnedGtsmOutcome::Applied)));
    h.bind("swp1", Some(endpoint(2, 7))).await;
    h.reload(config_with(&port_stanza("swp1", ""))).await;
    h.reconcile().await;
    assert_eq!(
        h.mgr.peers[&swp1_key(2)].transport_config.ttl_security_hops,
        None,
        "rebound without GTSM"
    );

    let listener = tokio::net::TcpListener::bind((Ipv6Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let addr = listener.local_addr().unwrap();
    let (client, accepted) = tokio::join!(TcpStream::connect(addr), listener.accept());
    let (mut client, server) = (client.unwrap(), accepted.unwrap().0);
    // As the listener's old selector set it at accept.
    rustbgpd_transport::set_gtsm(
        &socket2::SockRef::from(&server),
        addr,
        std::num::NonZeroU8::MIN,
    )
    .unwrap();
    let probe = std::net::TcpStream::from(
        std::os::fd::AsFd::as_fd(&server)
            .try_clone_to_owned()
            .unwrap(),
    );
    let source = std::net::SocketAddrV6::new(ll(2), 50179, 0, 7);
    h.mgr
        .handle_inbound(server, SocketAddr::V6(source), None, None)
        .await;

    // Mutation-red: with the stale minimum kept, the client's Hop Limit 64
    // segment is dropped and never reaches the socket. The runtime is held
    // here, so the session cannot read it first.
    client.write_all(b"x").await.unwrap();
    let mut byte = [0u8; 1];
    let delivered = (0..200).any(|_| {
        let peeked = probe.peek(&mut byte).is_ok_and(|n| n == 1);
        if !peeked {
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        peeked
    });
    assert!(delivered, "a lower Hop Limit reaches the non-GTSM session");
}

/// A neighbor without `ttl_security` never touches the listener.
#[tokio::test]
async fn a_neighbor_without_gtsm_installs_no_selector() {
    let log: GtsmLog = Arc::default();
    let update: LearnedGtsmUpdate = {
        let log = Arc::clone(&log);
        Arc::new(move |request| {
            let ListenerGtsmRequest::Selector {
                interface,
                selector,
            } = request
            else {
                panic!("no Hop Limit raise without GTSM");
            };
            log.lock()
                .unwrap()
                .push((interface, selector.map(|selector| selector.address), false));
            Box::pin(async { LearnedGtsmOutcome::Applied })
        })
    };
    let mut h = harness_with(&["swp1"], &[("swp1", 7, true)], "", "", Some(update));
    h.bind("swp1", Some(endpoint(2, 7))).await;
    h.links_changed(snapshot(true, &[("swp1", 7, false)]));
    h.reconcile().await;
    assert_eq!(log.lock().unwrap().as_slice(), []);
}

/// Listener GTSM requests: a raise of the IPv6 Hop Limit (with the number of
/// discovery actors launched when it arrived, answered from `outcome`) or a
/// selector update (applied).
type RaiseLog = Arc<std::sync::Mutex<Vec<String>>>;

fn raise_recorder(
    launched: &Launched,
    outcome: Arc<std::sync::Mutex<LearnedGtsmOutcome>>,
) -> (LearnedGtsmUpdate, RaiseLog) {
    let raises: RaiseLog = Arc::default();
    let (log, launched) = (Arc::clone(&raises), Arc::clone(launched));
    let update: LearnedGtsmUpdate = Arc::new(move |request| {
        let ListenerGtsmRequest::Selector { interface, .. } = request else {
            let count = launched.lock().unwrap().len();
            log.lock().unwrap().push(format!("raise, {count} launched"));
            let outcome = outcome.lock().unwrap().clone();
            return Box::pin(async move { outcome });
        };
        log.lock().unwrap().push(format!("selector {interface}"));
        Box::pin(async { LearnedGtsmOutcome::Applied })
    });
    (update, raises)
}

/// A reload that adds an interface-only GTSM neighbor raises the listener's
/// IPv6 Hop Limit before discovery starts for it, so an RA-silent GTSM peer
/// can complete an inbound handshake and be learned; a failed raise is
/// retried, and a confirmed one is not repeated.
#[tokio::test(start_paused = true)]
async fn a_reload_that_adds_interface_only_gtsm_raises_the_listener_hop_limit() {
    let launched: Launched = Arc::default();
    let outcome = Arc::new(std::sync::Mutex::new(LearnedGtsmOutcome::Failed(
        "listener busy".into(),
    )));
    let (update, raises) = raise_recorder(&launched, Arc::clone(&outcome));
    let mut h = harness_with(&[], &[("swp1", 7, true)], "", "", Some(update));
    h.mgr.unnumbered = None;
    let sink = Arc::clone(&launched);
    h.mgr.unnumbered_runtime.spawn = Box::new(move |_, _| {
        let (discovery, commands) = RaDiscovery::recording();
        sink.lock().unwrap().push(commands);
        Ok((discovery, mpsc::unbounded_channel().1))
    });

    // Mutation-red: without the raise in the port-set pass the listener
    // keeps the default Hop Limit until an RA installs a selector.
    h.reload(config_with(&port_stanza("swp1", "ttl_security = true\n")))
        .await;
    assert_eq!(
        raises.lock().unwrap().as_slice(),
        ["raise, 0 launched"],
        "before discovery starts"
    );
    assert_eq!(
        drain_launched(&launched)[0],
        Command::Start("swp1".into()),
        "a failed raise still adds the neighbor"
    );

    *outcome.lock().unwrap() = LearnedGtsmOutcome::Applied;
    let retry = h
        .mgr
        .unnumbered_retry_at()
        .expect("a failed raise is retried");
    tokio::time::sleep_until(retry).await;
    h.mgr.unnumbered_retry_due();
    h.reconcile().await;
    assert_eq!(raises.lock().unwrap().len(), 2, "retried");
    h.reload(config_with(&port_stanza("swp1", "ttl_security = true\n")))
        .await;
    assert_eq!(
        raises.lock().unwrap().len(),
        2,
        "not repeated once confirmed"
    );

    // Discovery started by the reload still reaches the listener: the
    // binding installs its selector before the peer is added.
    h.bind("swp1", Some(endpoint(2, 7))).await;
    assert_eq!(h.peers_at(ll(2)), [swp1_key(2)]);
    assert_eq!(raises.lock().unwrap()[2], "selector swp1");
}

/// A config transaction that turns on GTSM for a configured interface-only
/// neighbor raises the listener's IPv6 Hop Limit once the stage commits,
/// before the neighbor can bind under the committed settings.
#[tokio::test]
async fn a_committed_transaction_that_enables_interface_only_gtsm_raises_the_listener_hop_limit() {
    let outcome = Arc::new(std::sync::Mutex::new(LearnedGtsmOutcome::Applied));
    let (update, raises) = raise_recorder(&Launched::default(), outcome);
    let mut h = harness_with(&["swp1"], &[("swp1", 7, true)], "", "", Some(update));
    h.mgr.unnumbered_retry_due();
    h.reconcile().await;
    assert!(raises.lock().unwrap().is_empty(), "no GTSM, no raise");
    let mut candidate = h.mgr.current_config.clone();
    candidate.neighbors = config_with(&port_stanza("swp1", "ttl_security = true\n")).neighbors;

    // As `StageTransactionConfig` installs a full-scope candidate.
    h.mgr.replace_current_config(candidate);
    h.mgr.config_snapshot_staged = true;
    h.reconcile().await;
    assert!(raises.lock().unwrap().is_empty(), "held while staged");

    // Mutation-red: without the raise the committed neighbor waits for an
    // RA while its RA-silent GTSM peer's handshakes fail.
    let (reply, committed) = oneshot::channel();
    let _ = Box::pin(
        h.mgr
            .dispatch_command(PeerManagerCommand::CommitConfigSnapshotStage { reply }),
    )
    .await;
    committed.await.unwrap();
    h.reconcile().await;
    assert_eq!(raises.lock().unwrap().len(), 1, "raised at commit");
}

/// Every `peer` value exported for `interface`'s neighbor family `name`.
fn peer_values(h: &Harness, name: &str) -> Vec<String> {
    let mut values: Vec<String> = h
        .mgr
        .metrics
        .registry()
        .gather()
        .into_iter()
        .filter(|family| family.name() == name)
        .flat_map(|family| family.get_metric().to_vec())
        .filter_map(|metric| {
            metric
                .get_label()
                .iter()
                .find(|label| label.name() == "peer")
                .map(|label| label.value().to_owned())
        })
        .collect();
    values.sort();
    values.dedup();
    values
}

/// One `family` sample's value for `labels`, if exported.
fn sample(h: &Harness, family: &str, labels: &[(&str, &str)]) -> Option<f64> {
    h.mgr
        .metrics
        .registry()
        .gather()
        .into_iter()
        .filter(|candidate| candidate.name() == family)
        .flat_map(|candidate| candidate.get_metric().to_vec())
        .find(|metric| {
            labels.iter().all(|(name, value)| {
                metric
                    .get_label()
                    .iter()
                    .any(|label| label.name() == *name && label.value() == *value)
            })
        })
        // A family is one type; the other reads 0.
        .map(|metric| metric.get_counter().get_value() + metric.get_gauge().get_value())
}

/// ADR-0142 metrics: an interface-only neighbor's series are labelled
/// `peer="interface:swp1"` at every endpoint and survive an address change,
/// which is counted once, while the address metadata follows the binding.
#[tokio::test]
async fn an_interface_only_neighbors_series_follow_the_interface_across_endpoints() {
    let mut h = harness(&["swp1"], &[("swp1", 7, true)]);
    h.bind("swp1", Some(endpoint(2, 7))).await;
    // Mutation-red: labelling from the key emits `fe80::2%swp1`.
    assert_eq!(
        peer_values(&h, "bgp_peer_admin_enabled"),
        ["interface:swp1"]
    );
    assert_eq!(peer_values(&h, "bgp_peer_info"), ["interface:swp1"]);
    assert_eq!(
        h.mgr.rib_peer_of(&swp1_key(2)).label(),
        "interface:swp1",
        "the RIB emits the same value"
    );
    assert_eq!(
        h.mgr.peers[&swp1_key(2)].transport_config.peer_label(),
        "interface:swp1",
        "and so does the session"
    );
    let info = [("peer", "interface:swp1"), ("interface", "swp1")];
    assert_eq!(
        sample(
            &h,
            "bgp_unnumbered_peer_address_info",
            &[info[0], ("address", "fe80::2")]
        ),
        Some(1.0)
    );
    assert_eq!(
        sample(&h, "bgp_unnumbered_address_changes_total", &info[..1]),
        None
    );
    while h.rib_rx.try_recv().is_ok() {}

    h.bind("swp1", Some(endpoint(3, 7))).await;
    assert!(h.mgr.peers.contains_key(&swp1_key(3)));
    // Mutation-red: reaping on retirement drops the identity series.
    assert_eq!(
        peer_values(&h, "bgp_peer_admin_enabled"),
        ["interface:swp1"]
    );
    assert_eq!(
        sample(&h, "bgp_unnumbered_address_changes_total", &info[..1]),
        Some(1.0)
    );
    assert_eq!(
        sample(
            &h,
            "bgp_unnumbered_peer_address_info",
            &[info[0], ("address", "fe80::2")]
        ),
        None,
        "the old address is gone"
    );
    assert_eq!(
        sample(
            &h,
            "bgp_unnumbered_peer_address_info",
            &[info[0], ("address", "fe80::3")]
        ),
        Some(1.0)
    );
    let deleted: Vec<bool> = std::iter::from_fn(|| h.rib_rx.try_recv().ok())
        .filter_map(|update| match update {
            RibUpdate::PeerDeleted { keep_series, .. } => Some(keep_series),
            _ => None,
        })
        .collect();
    assert_eq!(deleted, [true], "the RIB keeps the series too");

    // Carrier loss unbinds: no address series, the identity stays.
    h.links_changed(snapshot(true, &[("swp1", 7, false)]));
    h.reconcile().await;
    assert_eq!(h.peers_at(ll(3)), []);
    assert!(!h.mgr.metrics.registry().gather().iter().any(|family| {
        family.name() == "bgp_unnumbered_peer_address_info" && !family.get_metric().is_empty()
    }));
    assert_eq!(
        peer_values(&h, "bgp_peer_admin_enabled"),
        ["interface:swp1"]
    );
}

/// A second router on the link is counted for the neighbor, from a Router
/// Advertisement and from an inbound connection alike.
#[tokio::test]
async fn second_routers_on_the_link_are_counted_for_the_neighbor() {
    let mut h = harness(&["swp1"], &[("swp1", 7, true)]);
    h.bind("swp1", Some(endpoint(2, 7))).await;
    h.mgr.handle_discovery_event(DiscoveryEvent::Conflict {
        interface: "swp1".into(),
        bound: ll(2),
        other: ll(9),
    });
    let _client = inbound(&mut h, 9, 7).await;
    assert_eq!(
        sample(
            &h,
            "bgp_unnumbered_ra_conflicts_total",
            &[("peer", "interface:swp1")]
        ),
        Some(2.0)
    );
}

/// The presence events of an interface-only neighbor's endpoints carry why
/// the endpoint changed: learned, address changed, link down, interface
/// removed.
#[tokio::test]
async fn endpoint_presence_events_carry_the_reason() {
    let mut h = harness(&["swp1"], &[("swp1", 7, true)]);
    h.bind("swp1", Some(endpoint(2, 7))).await;
    h.bind("swp1", Some(endpoint(3, 7))).await;
    h.links_changed(snapshot(true, &[("swp1", 7, false)]));
    h.reconcile().await;
    h.links_changed(snapshot(true, &[("swp1", 7, true)]));
    h.bind("swp1", Some(endpoint(3, 7))).await;
    h.links_changed(snapshot(true, &[]));
    h.reconcile().await;
    let events = query_session_event_history(
        &h.mgr,
        None,
        [
            SessionLifecycleEventType::PeerAdded,
            SessionLifecycleEventType::PeerRemoved,
        ]
        .into_iter()
        .collect(),
        0,
    )
    .await;
    let reasons: Vec<&str> = events.iter().map(|event| event.reason.as_str()).collect();
    // Mutation-red: without the port's reason the events read "added".
    assert_eq!(
        reasons,
        [
            "peer fe80::2%swp1 added: peer_address_learned",
            "peer fe80::2%swp1 removed: peer_address_changed",
            "peer fe80::3%swp1 added: peer_address_changed",
            "peer fe80::3%swp1 removed: link_down",
            "peer fe80::3%swp1 added: peer_address_learned",
            "peer fe80::3%swp1 removed: interface_removed",
        ]
    );
}

/// A failed start of an interface-only neighbor's replacement endpoint
/// keeps the neighbor's identity series, its down history included; the
/// retry's peer reports under the same series.
#[tokio::test]
async fn a_failed_endpoint_start_keeps_the_neighbors_identity_series() {
    let mut h = harness(&["swp1"], &[("swp1", 7, true)]);
    h.bind("swp1", Some(endpoint(2, 7))).await;
    h.mgr.metrics.record_session_down(
        "interface:swp1",
        "swp1",
        rustbgpd_telemetry::reason_labels::SessionDownReason::TransportError,
    );
    let down = |h: &Harness| {
        sample(
            h,
            "bgp_session_down_total",
            &[("peer", "interface:swp1"), ("reason", "transport_error")],
        )
    };
    assert_eq!(down(&h), Some(1.0));
    let failed = h
        .mgr
        .provision_new_peer_session(&swp1_key(3), true, true, closed_peer_handle(), "test start")
        .await;
    assert!(failed.is_err(), "the closed session cannot start");
    // Mutation-red: reaping on this path drops the down counter.
    assert_eq!(down(&h), Some(1.0));
    h.bind("swp1", Some(endpoint(3, 7))).await;
    assert_eq!(h.peers_at(ll(3)), [swp1_key(3)], "the retry binds");
    assert_eq!(down(&h), Some(1.0));
}

/// A neighbor learned from an inbound connection is unknown to discovery,
/// so a second router seen only by RA, or only by another inbound
/// connection, is still counted once each.
#[tokio::test]
async fn second_routers_beside_an_inbound_learned_session_are_counted() {
    let conflicts = |h: &Harness| {
        sample(
            h,
            "bgp_unnumbered_ra_conflicts_total",
            &[("peer", "interface:swp1")],
        )
    };
    let mut h = harness(&["swp1"], &[("swp1", 7, true)]);
    let _client = inbound(&mut h, 2, 7).await;
    h.replace_session(
        &swp1_key(2),
        fake_peer_handle(
            IpAddr::V6(ll(2)),
            SessionState::Established,
            None,
            Arc::new(FakePeerCounters::default()),
        ),
    );
    h.mgr.note_unnumbered_session_state(
        &swp1_key(2),
        SessionState::OpenConfirm,
        SessionState::Established,
    );
    // No RA binding: an inbound connection from another address while
    // Established. Mutation-red: refusing it as `unconfigured` alone leaves
    // the counter empty.
    let _client = inbound(&mut h, 3, 7).await;
    assert_eq!(conflicts(&h), Some(1.0));
    assert!(h.mgr.peers.contains_key(&swp1_key(2)), "kept");

    // The second router's first RA: discovery had no binding, so it raises
    // no conflict of its own. Mutation-red: without the manager's check the
    // counter stays at 1.
    h.bind("swp1", Some(endpoint(9, 7))).await;
    assert_eq!(conflicts(&h), Some(2.0));
    assert!(h.mgr.peers.contains_key(&swp1_key(2)), "still kept");
}

/// One SIGHUP generation to `candidate`, through the real executor, then
/// the owner loop's port reconcile.
async fn sighup(h: &mut Harness, candidate: crate::config::Config) {
    let actions =
        crate::config::plan_reload_peer_actions(&h.mgr.current_config, &candidate).unwrap();
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
}

/// SIGHUP enables BFD on a bound interface-only neighbor, moves it to
/// another profile, toggles strict mode and disables it. Each generation
/// creates, updates, holds, releases and finally removes the single-hop
/// session for the binding's `fe80::2%7`, and the BGP session is kept
/// throughout: BFD membership is not a bind-time setting. Strict mode
/// (ADR-0067) withholds BGP while BFD is not Up and releases it when strict
/// is turned off.
#[tokio::test]
async fn sighup_bfd_edits_on_a_bound_interface_only_neighbor_keep_its_session() {
    let profiles = "[[bfd_profiles]]\nname = \"fast\"\n\
                    [[bfd_profiles]]\nname = \"slow\"\nmultiplier = 5\n";
    let (mut h, mut bfd) = attach_bfd(
        harness_with(&["swp1"], &[("swp1", 7, true)], "", profiles, None),
        &[],
    );
    h.bind("swp1", Some(endpoint(2, 7))).await;
    assert!(bfd.applied.try_recv().is_err(), "no BFD configured yet");
    let key = swp1_key(2);
    let peer = IpAddr::V6(ll(2));
    let session = h.session(&key);
    let with_bfd = |h: &Harness, bfd: Option<&str>| {
        let mut candidate = h.mgr.current_config.clone();
        let mut neighbor = candidate
            .neighbors
            .interface_only_on("swp1")
            .unwrap()
            .clone();
        neighbor.bfd = bfd.map(|bfd| toml::from_str::<crate::config::BfdConfig>(bfd).unwrap());
        candidate
            .neighbors
            .set_interface_only("swp1", Some(neighbor));
        candidate
    };
    let detect_mult =
        |h: &Harness| h.mgr.bfd_coupling.as_ref().unwrap().configured[&peer].detect_mult;

    // Mutation-red: a bind-time BFD setting rebinds the neighbor instead.
    let enabled = with_bfd(&h, Some("profile = \"fast\""));
    sighup(&mut h, enabled).await;
    assert_eq!(
        BfdSide::sessions(&bfd.next_applied()),
        [(peer, Some(7))],
        "created"
    );
    assert_eq!(h.session(&key), session, "kept on enable");
    assert!(!h.mgr.bfd_withholding(&peer));
    let created = bfd_revision(&h, ll(2));

    let moved = with_bfd(&h, Some("profile = \"slow\""));
    sighup(&mut h, moved).await;
    assert_eq!(BfdSide::sessions(&bfd.next_applied()), [(peer, Some(7))]);
    assert_eq!(detect_mult(&h), 5, "updated to the new profile");
    assert_ne!(bfd_revision(&h, ll(2)), created, "a replaced session");
    assert_eq!(h.session(&key), session, "kept on a profile change");

    let strict = with_bfd(&h, Some("profile = \"slow\"\nstrict = true"));
    sighup(&mut h, strict).await;
    bfd.next_applied();
    assert!(
        h.mgr.bfd_withholding(&peer),
        "strict holds BGP until BFD is Up"
    );
    assert_eq!(h.session(&key), session, "kept when strict is enabled");

    let relaxed = with_bfd(&h, Some("profile = \"slow\""));
    sighup(&mut h, relaxed).await;
    bfd.next_applied();
    assert!(!h.mgr.bfd_withholding(&peer), "released when strict is off");
    assert_eq!(h.session(&key), session, "kept when strict is disabled");

    let disabled = with_bfd(&h, None);
    sighup(&mut h, disabled).await;
    assert_eq!(BfdSide::sessions(&bfd.next_applied()), [], "removed");
    assert!(!h.mgr.bfd_coupling.as_ref().unwrap().bound.contains(&peer));
    assert_eq!(h.session(&key), session, "kept on disable");
}

/// Every exported series whose `peer` label is `label`, by family.
fn series_for(h: &Harness, label: &str) -> Vec<String> {
    let mut families: Vec<String> = h
        .mgr
        .metrics
        .registry()
        .gather()
        .into_iter()
        .filter(|family| {
            family.get_metric().iter().any(|metric| {
                metric
                    .get_label()
                    .iter()
                    .any(|pair| pair.name() == "peer" && pair.value() == label)
            })
        })
        .map(|family| family.name().to_owned())
        .collect();
    families.sort();
    families
}

/// Deleting an interface-only neighbor through `DeleteNeighbor` ends every
/// series labelled `peer="interface:<name>"`, including `bgp_unnumbered_*`,
/// for a bound neighbor and for one whose binding was lost, which has no
/// peer to delete. The deletion of the bound one tells the RIB the same
/// label, so its teardown emissions are reaped after them.
#[tokio::test]
async fn an_rpc_delete_reaps_the_neighbors_interface_labelled_series() {
    use rustbgpd_api::peer_types::OwnedNeighborMutation;
    let mut h = harness(&["swp1", "swp2"], &[("swp1", 7, true), ("swp2", 8, true)]);
    h.bind("swp1", Some(endpoint(2, 7))).await;
    h.bind("swp2", Some(endpoint(3, 8))).await;
    // swp2 is then unbound: its identity series stay with the neighbor.
    h.links_changed(snapshot(true, &[("swp1", 7, true), ("swp2", 8, false)]));
    h.reconcile().await;
    h.mgr.handle_discovery_event(DiscoveryEvent::Conflict {
        interface: "swp1".into(),
        bound: ll(2),
        other: ll(9),
    });
    for label in ["interface:swp1", "interface:swp2"] {
        assert!(
            series_for(&h, label)
                .iter()
                .any(|family| family == "bgp_peer_admin_enabled"),
            "{label} exported before the delete: {:?}",
            series_for(&h, label)
        );
    }
    assert!(
        series_for(&h, "interface:swp1")
            .iter()
            .any(|family| family.starts_with("bgp_unnumbered_"))
    );
    while h.rib_rx.try_recv().is_ok() {}

    for interface in ["swp1", "swp2"] {
        let outcome = h
            .owned_neighbor(OwnedNeighborMutation::DeleteInterfaceOnly(interface.into()))
            .await;
        assert!(
            matches!(
                outcome,
                rustbgpd_api::peer_types::OwnedNeighborMutationOutcome::Success
            ),
            "{outcome:?}"
        );
    }
    h.reconcile().await;
    // Mutation-red: without the reap both neighbors' series survive.
    assert_eq!(series_for(&h, "interface:swp1"), Vec::<String>::new());
    assert_eq!(series_for(&h, "interface:swp2"), Vec::<String>::new());
    let reaped_in_rib: Vec<_> = std::iter::from_fn(|| h.rib_rx.try_recv().ok())
        .filter_map(|update| match update {
            RibUpdate::PeerDeleted {
                label, keep_series, ..
            } => Some((label.map(|label| label.to_string()), keep_series)),
            _ => None,
        })
        .collect();
    assert_eq!(
        reaped_in_rib,
        [
            (Some("interface:swp1".to_string()), false),
            (Some("interface:swp2".to_string()), false)
        ],
        "the RIB reaps each neighbor's series under its interface label"
    );
}

/// `SetNeighborPeerGroup` and `ClearNeighborPeerGroup` select an
/// interface-only neighbor by interface: the member rebinds into and out of
/// the group on the reconcile, and the other neighbor keeps its session.
#[tokio::test]
async fn a_membership_rpc_moves_an_interface_only_neighbor_between_groups() {
    use rustbgpd_api::peer_types::{OwnedCatalogMutation, OwnedCatalogMutationOutcome};
    let config = config_with(&format!(
        "[peer_groups.fabric]\nhold_time = 30\n{}{}",
        port_stanza("swp1", ""),
        port_stanza("swp2", "")
    ));
    let mut h = harness(&[], &[("swp1", 7, true), ("swp2", 8, true)]);
    h.reload(config).await;
    h.bind("swp1", Some(endpoint(2, 7))).await;
    h.bind("swp2", Some(endpoint(3, 8))).await;
    let swp2 = PeerKey::new(IpAddr::V6(ll(3)), Some("swp2".into()));
    let swp1_session = h.session(&swp1_key(2));
    let selector = IpAddr::V6(Ipv6Addr::UNSPECIFIED);
    for (mutation, hold) in [
        (
            OwnedCatalogMutation::SetNeighborPeerGroup {
                address: selector,
                interface: Some("swp2".into()),
                peer_group: "fabric".into(),
            },
            Some(30),
        ),
        (
            OwnedCatalogMutation::ClearNeighborPeerGroup {
                address: selector,
                interface: Some("swp2".into()),
            },
            Some(90),
        ),
    ] {
        let session = h.session(&swp2);
        let (reply, outcome) = oneshot::channel();
        let _ = Box::pin(
            h.mgr
                .dispatch_command(PeerManagerCommand::OwnedCatalogMutation { mutation, reply }),
        )
        .await;
        let outcome = outcome.await.unwrap();
        assert!(
            matches!(outcome, OwnedCatalogMutationOutcome::Success),
            "{outcome:?}"
        );
        h.reconcile().await;
        assert_ne!(h.session(&swp2), session, "swp2 rebound");
        assert_eq!(h.mgr.peers[&swp2].hold_time, hold);
        assert_eq!(h.session(&swp1_key(2)), swp1_session, "swp1 kept");
    }
}

/// A group edit that changes a session knob and the export chain: a member
/// that overrides the knob keeps its bind-time settings, so it is not
/// rebound, and takes the new chain live on both peer-group paths, keeping
/// its session.
#[tokio::test]
async fn a_combined_group_edit_applies_the_policy_to_a_member_that_does_not_rebind() {
    use rustbgpd_api::peer_types::{OwnedCatalogMutation, OwnedCatalogMutationOutcome};
    let config = config_with(&format!(
        "[policy.definitions.alt]\ndefault_action = \"permit\"\n\
         [peer_groups.fabric]\nhold_time = 30\n{}",
        port_stanza("swp1", "peer_group = \"fabric\"\nhold_time = 60\n")
    ));
    let mut h = harness(&[], &[("swp1", 7, true)]);
    h.reload(config).await;
    h.bind("swp1", Some(endpoint(2, 7))).await;
    let key = swp1_key(2);
    let session = h.session(&key);
    assert!(h.mgr.peers[&key].export_policy.is_none());
    let mut definition =
        crate::policy_admin::config_peer_group_to_api(&h.mgr.current_config.peer_groups["fabric"]);
    definition.hold_time = Some(45);
    definition.export_policy_chain = vec!["alt".to_string()];

    // Mutation-red: without the live delta the member keeps no chain.
    let (reply, outcome) = oneshot::channel();
    let _ = Box::pin(
        h.mgr
            .dispatch_command(PeerManagerCommand::OwnedCatalogMutation {
                mutation: OwnedCatalogMutation::SetPeerGroup {
                    name: "fabric".to_string(),
                    definition: Box::new(definition.clone()),
                },
                reply,
            }),
    )
    .await;
    let outcome = outcome.await.unwrap();
    assert!(
        matches!(outcome, OwnedCatalogMutationOutcome::Success),
        "{outcome:?}"
    );
    h.reconcile().await;
    assert_eq!(h.session(&key), session, "not rebound");
    assert!(
        h.mgr.peers[&key].export_policy.is_some(),
        "new chain installed"
    );

    // The legacy path: back to no chain, with another knob.
    definition.hold_time = Some(50);
    definition.export_policy_chain = Vec::new();
    let (reply, outcome) = oneshot::channel();
    let _ = Box::pin(h.mgr.dispatch_command(PeerManagerCommand::SetPeerGroup {
        name: "fabric".to_string(),
        definition,
        reply,
    }))
    .await;
    outcome.await.unwrap().expect("applied");
    h.reconcile().await;
    assert_eq!(h.session(&key), session, "not rebound");
    assert!(h.mgr.peers[&key].export_policy.is_none(), "chain removed");
}

/// The live chain of a member that does not rebind fails and so does its
/// restore: the group edit is ambiguous, so settlement keeps mutations
/// fenced, and the candidate config is not adopted.
#[tokio::test]
async fn a_failed_member_policy_restore_reports_the_group_edit_ambiguous() {
    use rustbgpd_api::peer_types::{OwnedCatalogMutation, OwnedCatalogMutationOutcome};
    let config = config_with(&format!(
        "[policy.definitions.alt]\ndefault_action = \"permit\"\n\
         [peer_groups.fabric]\nhold_time = 30\n{}",
        port_stanza("swp1", "peer_group = \"fabric\"\nhold_time = 60\n")
    ));
    let mut h = harness(&[], &[("swp1", 7, true)]);
    h.reload(config).await;
    h.bind("swp1", Some(endpoint(2, 7))).await;
    let key = swp1_key(2);
    let session = h.session(&key);
    // The session can take neither the new chain nor the restore.
    let _ = h
        .mgr
        .peers
        .replace_handle(&key, closed_peer_handle(), session);
    let mut definition =
        crate::policy_admin::config_peer_group_to_api(&h.mgr.current_config.peer_groups["fabric"]);
    definition.hold_time = Some(45);
    definition.export_policy_chain = vec!["alt".to_string()];
    let (reply, outcome) = oneshot::channel();
    let _ = Box::pin(
        h.mgr
            .dispatch_command(PeerManagerCommand::OwnedCatalogMutation {
                mutation: OwnedCatalogMutation::SetPeerGroup {
                    name: "fabric".to_string(),
                    definition: Box::new(definition),
                },
                reply,
            }),
    )
    .await;
    // Mutation-red: flattening the failure reports it compensated.
    let outcome = outcome.await.unwrap();
    let OwnedCatalogMutationOutcome::CompensationAmbiguous(error) = &outcome else {
        panic!("an unrestored member must fence: {outcome:?}");
    };
    assert_eq!(
        error.to_string(),
        rustbgpd_api::runtime_config_settlement::RuntimeConfigPolicyFailureCode::RollbackSessionRejected
            .as_str()
    );
    assert_eq!(
        h.mgr.current_config.peer_groups["fabric"].hold_time,
        Some(30),
        "the candidate is not adopted"
    );
}

/// Deleting a bound BFD neighbor removes its binding's registration before
/// the address is released, so nothing at that address inherits the session
/// or a strict hold.
#[tokio::test]
async fn deleting_a_bound_bfd_neighbor_removes_its_registration() {
    let (mut h, mut bfd) = bfd_harness(&["swp1"], &[("swp1", 7, true)], true);
    h.bind("swp1", Some(endpoint(2, 7))).await;
    bfd.next_applied();
    let peer = IpAddr::V6(ll(2));
    assert!(h.mgr.bfd_withholding(&peer), "strict, held until Up");
    let outcome = h
        .owned_neighbor(
            rustbgpd_api::peer_types::OwnedNeighborMutation::DeleteInterfaceOnly("swp1".into()),
        )
        .await;
    assert!(
        matches!(
            outcome,
            rustbgpd_api::peer_types::OwnedNeighborMutationOutcome::Success
        ),
        "{outcome:?}"
    );
    h.reconcile().await;
    // Mutation-red: the deletion only disables it; the registration stays.
    let coupling = h.mgr.bfd_coupling.as_ref().unwrap();
    assert!(
        !coupling.configured.contains_key(&peer),
        "registration removed"
    );
    assert!(!coupling.bound.contains(&peer));
    assert!(!h.mgr.bfd_withholding(&peer), "no strict hold left");
    let mut last = None;
    while let Ok(applied) = bfd.applied.try_recv() {
        last = Some(applied);
    }
    assert_eq!(
        BfdSide::sessions(&last.expect("the removal was acknowledged")),
        []
    );
}

/// A binding lost before the delete left a `PeerDeleted { keep_series }`
/// queued for the RIB. The removal queues a final deletion behind it under
/// the interface label, so nothing that one emits outlives the neighbor.
#[tokio::test]
async fn an_unbound_neighbors_removal_queues_a_final_rib_deletion() {
    let mut h = harness(&["swp1"], &[("swp1", 7, true)]);
    h.bind("swp1", Some(endpoint(2, 7))).await;
    while h.rib_rx.try_recv().is_ok() {}
    h.links_changed(snapshot(true, &[("swp1", 7, false)]));
    h.reconcile().await;
    // The RIB has not processed the retirement yet: the delete runs behind it.
    let outcome = h
        .owned_neighbor(
            rustbgpd_api::peer_types::OwnedNeighborMutation::DeleteInterfaceOnly("swp1".into()),
        )
        .await;
    assert!(
        matches!(
            outcome,
            rustbgpd_api::peer_types::OwnedNeighborMutationOutcome::Success
        ),
        "{outcome:?}"
    );
    h.reconcile().await;
    let queued: Vec<_> = std::iter::from_fn(|| h.rib_rx.try_recv().ok())
        .filter_map(|update| match update {
            RibUpdate::PeerDeleted {
                label, keep_series, ..
            } => Some(format!(
                "deleted({}, keep={keep_series})",
                label.as_deref().unwrap_or("-")
            )),
            RibUpdate::ReleasePeer { .. } => Some("released".to_string()),
            _ => None,
        })
        .collect();
    // Mutation-red: without the final deletion the retirement's kept
    // series are the last word.
    assert_eq!(
        queued,
        [
            "deleted(interface:swp1, keep=true)",
            "deleted(interface:swp1, keep=false)",
            "released"
        ]
    );
}

/// A discovery conflict queued before the neighbor's deletion arrives
/// after it, while another neighbor's port keeps discovery running: it is
/// ignored and recreates no series for the deleted neighbor.
#[tokio::test]
async fn a_late_conflict_for_a_deleted_neighbor_recreates_no_series() {
    let mut h = harness(&["swp1", "swp2"], &[("swp1", 7, true), ("swp2", 8, true)]);
    h.bind("swp1", Some(endpoint(2, 7))).await;
    h.bind("swp2", Some(endpoint(3, 8))).await;
    let outcome = h
        .owned_neighbor(
            rustbgpd_api::peer_types::OwnedNeighborMutation::DeleteInterfaceOnly("swp1".into()),
        )
        .await;
    assert!(
        matches!(
            outcome,
            rustbgpd_api::peer_types::OwnedNeighborMutationOutcome::Success
        ),
        "{outcome:?}"
    );
    h.reconcile().await;
    h.mgr.handle_discovery_event(DiscoveryEvent::Conflict {
        interface: "swp1".into(),
        bound: ll(2),
        other: ll(9),
    });
    // Mutation-red: counting it recreates `ra_conflicts{peer="interface:swp1"}`.
    assert_eq!(series_for(&h, "interface:swp1"), Vec::<String>::new());
    h.mgr.handle_discovery_event(DiscoveryEvent::Conflict {
        interface: "swp2".into(),
        bound: ll(3),
        other: ll(9),
    });
    assert_eq!(
        sample(
            &h,
            "bgp_unnumbered_ra_conflicts_total",
            &[("peer", "interface:swp2")]
        ),
        Some(1.0),
        "the remaining neighbor is still counted"
    );
}
