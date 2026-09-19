use super::*;

// ---------------------------------------------------------------------------
// ADR-0067 step 4 — RFC 5882 BFD/BGP coupling (non-strict). Adversarial around
// stale state changes and lifecycle drops: a deliberate disable/delete drains
// the BFD session (AdminDown) and must NOT look like a failure.
// ---------------------------------------------------------------------------

#[derive(Default)]
struct BfdCouplingCounters {
    stop: AtomicU32,
    bfd_down: AtomicU32,
    start: AtomicU32,
}

/// Fake peer handle that counts Stop/Start without exiting (unlike
/// `fake_peer_handle`, which breaks on Stop) so a down→up cycle is observable.
fn fake_bfd_peer_handle(counters: Arc<BfdCouplingCounters>) -> PeerHandle {
    use rustbgpd_transport::PeerCommand;
    let (tx, mut rx) = mpsc::channel::<PeerCommand>(8);
    let task = tokio::spawn(async move {
        while let Some(cmd) = rx.recv().await {
            match cmd {
                PeerCommand::Stop { .. } => {
                    counters.stop.fetch_add(1, Ordering::SeqCst);
                }
                PeerCommand::BfdDown => {
                    counters.stop.fetch_add(1, Ordering::SeqCst);
                    counters.bfd_down.fetch_add(1, Ordering::SeqCst);
                }
                PeerCommand::Start => {
                    counters.start.fetch_add(1, Ordering::SeqCst);
                }
                _ => {}
            }
        }
        Ok(())
    });
    PeerHandle::from_parts(tx, task)
}

fn bfd_params(peer: IpAddr, strict: bool) -> crate::bfd_runtime::BfdSessionParams {
    crate::bfd_runtime::BfdSessionParams {
        revision: 0,
        peer,
        scope_id: None,
        destination: crate::bfd_runtime::bfd_destination(peer, None, false)
            .expect("global test peer destination"),
        desired_min_tx_us: 300_000,
        required_min_rx_us: 300_000,
        detect_mult: 3,
        strict,
        enabled: true,
        multihop: false,
        source: None,
    }
}

/// Build a coupled `PeerManager` with one managed peer, returning the
/// desired-set receiver so tests can inspect what `PeerManager` publishes.
fn coupled_mgr(
    peer: IpAddr,
    strict: bool,
    handle: PeerHandle,
) -> (
    PeerManager,
    watch::Receiver<crate::bfd_runtime::BfdRuntimeConfig>,
) {
    let mut mgr = test_peer_manager();
    insert_test_managed_peer(&mut mgr, peer, handle, false);
    let configured = std::collections::HashMap::from([(peer, bfd_params(peer, strict))]);
    let (desired_tx, desired_rx) = watch::channel(crate::bfd_runtime::BfdRuntimeConfig::default());
    let (_state_tx, state_rx) = crate::bfd_runtime::state_change_channel();
    let mgr = mgr.with_bfd_coupling(desired_tx, state_rx, configured);
    (mgr, desired_rx)
}

/// The actor draining our own session to `AdminDown` on a local disable/delete
/// (`remote_admin_down = false`) — distinct from a remote `AdminDown`.
fn local_admin_down(peer: IpAddr) -> crate::bfd_runtime::BfdStateChange {
    crate::bfd_runtime::BfdStateChange {
        revision: 0,
        peer,
        state: rustbgpd_bfd::SessionState::AdminDown,
        diagnostic: rustbgpd_bfd::Diagnostic::AdministrativelyDown,
        remote_admin_down: false,
        resync: false,
    }
}

/// A reconcile "ack" (resync) re-reporting a session that is currently Up.
fn up_ack(peer: IpAddr) -> crate::bfd_runtime::BfdStateChange {
    crate::bfd_runtime::BfdStateChange {
        revision: 0,
        peer,
        state: rustbgpd_bfd::SessionState::Up,
        diagnostic: rustbgpd_bfd::Diagnostic::None,
        remote_admin_down: false,
        resync: true,
    }
}

/// A reconcile "ack" (resync) re-reporting a session that is currently Down
/// (e.g. a freshly (re)started session) — must never tear BGP down.
fn down_ack(peer: IpAddr) -> crate::bfd_runtime::BfdStateChange {
    crate::bfd_runtime::BfdStateChange {
        revision: 0,
        peer,
        state: rustbgpd_bfd::SessionState::Down,
        diagnostic: rustbgpd_bfd::Diagnostic::ControlDetectionTimeExpired,
        remote_admin_down: false,
        resync: true,
    }
}

#[tokio::test]
async fn bfd_down_then_up_tears_down_and_restores_enabled_peer() {
    let peer: IpAddr = "10.0.0.2".parse().unwrap();
    let counters = Arc::new(BfdCouplingCounters::default());
    let (mut mgr, _rx) = coupled_mgr(peer, false, fake_bfd_peer_handle(counters.clone()));

    mgr.handle_bfd_state_change(down(peer)).await;
    wait_counter(&counters.stop, 1).await; // BFD down must stop BGP
    assert_eq!(counters.bfd_down.load(Ordering::SeqCst), 1);
    // A duplicate Down while already held must not re-stop.
    mgr.handle_bfd_state_change(down(peer)).await;
    assert_eq!(counters.stop.load(Ordering::SeqCst), 1);

    mgr.handle_bfd_state_change(up(peer)).await;
    wait_counter(&counters.start, 1).await; // BFD up must restart BGP
}

#[tokio::test]
async fn bfd_up_without_prior_down_is_noop() {
    let peer: IpAddr = "10.0.0.2".parse().unwrap();
    let counters = Arc::new(BfdCouplingCounters::default());
    let (mut mgr, _rx) = coupled_mgr(peer, false, fake_bfd_peer_handle(counters.clone()));

    // Not held down → an Up must not spuriously (re)start the session.
    mgr.handle_bfd_state_change(up(peer)).await;
    assert_eq!(counters.start.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn bfd_down_ignored_for_disabled_peer() {
    let peer: IpAddr = "10.0.0.2".parse().unwrap();
    let counters = Arc::new(BfdCouplingCounters::default());
    let (mut mgr, _rx) = coupled_mgr(peer, false, fake_bfd_peer_handle(counters.clone()));
    // Operator disabled the peer; the actor's resulting AdminDown/Down must not
    // be treated as a failure.
    mgr.peers.get_mut(&key(peer)).unwrap().enabled = false;

    mgr.handle_bfd_state_change(down(peer)).await;
    assert_eq!(
        counters.stop.load(Ordering::SeqCst),
        0,
        "disabled peer Down ignored"
    );
}

#[tokio::test]
async fn bfd_change_ignored_for_absent_peer() {
    let peer: IpAddr = "10.0.0.2".parse().unwrap();
    let counters = Arc::new(BfdCouplingCounters::default());
    let (mut mgr, _rx) = coupled_mgr(peer, false, fake_bfd_peer_handle(counters.clone()));
    // Peer deleted; a stale state change from the draining session is ignored.
    mgr.peers.remove(&key(peer));

    mgr.handle_bfd_state_change(down(peer)).await;
    assert_eq!(counters.stop.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn nonstrict_remote_admin_down_does_not_tear_down_bgp() {
    // RFC 5882 §4.2: a remote-signaled BFD AdminDown is administrative, not a
    // liveness failure. A non-strict peer keeps its BGP session (BGP carries its
    // own hold-timer liveness).
    let peer: IpAddr = "10.0.0.2".parse().unwrap();
    let counters = Arc::new(BfdCouplingCounters::default());
    let (mut mgr, _rx) = coupled_mgr(peer, false, fake_bfd_peer_handle(counters.clone()));

    mgr.handle_bfd_state_change(remote_admin_down(peer)).await;
    assert_eq!(
        counters.stop.load(Ordering::SeqCst),
        0,
        "remote AdminDown must not tear down a non-strict BGP session"
    );

    // A genuine detection-timeout Down still tears it down (the coupling still
    // reacts to real liveness failures).
    mgr.handle_bfd_state_change(down(peer)).await;
    wait_counter(&counters.stop, 1).await;
}

#[tokio::test]
async fn strict_remote_admin_down_releases_withheld_bgp() {
    // RFC 5882 §4.1: when the remote BFD is AdminDown the adjacency MUST be
    // allowed — even in strict mode. A strict peer withheld pending BFD Up is
    // released (BGP started), never torn down, on a remote AdminDown.
    let peer: IpAddr = "10.0.0.2".parse().unwrap();
    let counters = Arc::new(BfdCouplingCounters::default());
    let (mut mgr, _rx) = coupled_mgr(peer, true, fake_bfd_peer_handle(counters.clone()));
    mgr.mark_bfd_withheld(peer);

    mgr.handle_bfd_state_change(remote_admin_down(peer)).await;
    wait_counter(&counters.start, 1).await; // released → BGP started
    assert_eq!(
        counters.stop.load(Ordering::SeqCst),
        0,
        "strict remote AdminDown must not stop BGP"
    );
    // The hold was released (RFC 5882 §4.1 — AdminDown permits BGP).
    assert!(
        !mgr.bfd_withholding(&peer),
        "remote AdminDown released the withhold"
    );
}

#[tokio::test]
async fn strict_disable_drain_reenable_does_not_leak_bgp_before_fresh_up() {
    // #2 lifecycle: a strict peer that was Up, then disabled (the actor drains
    // its session to a *local* AdminDown), then re-enabled, must NOT establish
    // BGP until a fresh BFD Up. The local drain must not be mistaken for a remote
    // AdminDown (which would permit BGP per RFC 5882 §4.1). This proves the
    // in-order lifecycle does not leak establishment before the fresh state.
    let peer: IpAddr = "10.0.0.2".parse().unwrap();
    let counters = Arc::new(BfdCouplingCounters::default());
    let (mut mgr, _rx) = coupled_mgr(peer, true, fake_bfd_peer_handle(counters.clone()));

    // Strict peer reaches Up and establishes.
    mgr.mark_bfd_withheld(peer);
    mgr.handle_bfd_state_change(up(peer)).await;
    wait_counter(&counters.start, 1).await;

    // Operator disables; the actor drains the session to a local AdminDown.
    mgr.peers.get_mut(&key(peer)).unwrap().enabled = false;
    mgr.set_bfd_peer_disabled(peer, true);
    mgr.handle_bfd_state_change(local_admin_down(peer)).await; // drained, ignored

    // Re-enable: BFD has not come Up again, so strict must withhold — the local
    // drain's AdminDown must not be read as "permits BGP".
    mgr.peers.get_mut(&key(peer)).unwrap().enabled = true;
    mgr.set_bfd_peer_disabled(peer, false);
    assert!(
        mgr.bfd_should_withhold(&peer),
        "strict re-enable after a local drain must withhold until fresh BFD Up"
    );
    mgr.enable_peer(key(peer)).await.unwrap();
    assert_eq!(
        peer_identity_gauge(&mgr.metrics, "bgp_peer_admin_enabled", "10.0.0.2", ""),
        Some(1.0)
    );
    assert_eq!(
        counters.start.load(Ordering::SeqCst),
        1,
        "no BGP (re)start before a fresh BFD Up"
    );

    // The fresh session comes Up → BGP is released.
    mgr.handle_bfd_state_change(up(peer)).await;
    wait_counter(&counters.start, 2).await;
}

#[tokio::test]
async fn strict_remote_admin_down_keeps_established_bgp() {
    // A strict peer that is up and established (not held) is left alone on a
    // remote AdminDown — no stop, no spurious restart.
    let peer: IpAddr = "10.0.0.2".parse().unwrap();
    let counters = Arc::new(BfdCouplingCounters::default());
    let (mut mgr, _rx) = coupled_mgr(peer, true, fake_bfd_peer_handle(counters.clone()));
    mgr.mark_bfd_withheld(peer);
    mgr.handle_bfd_state_change(up(peer)).await; // established
    wait_counter(&counters.start, 1).await;

    mgr.handle_bfd_state_change(remote_admin_down(peer)).await;
    assert_eq!(counters.stop.load(Ordering::SeqCst), 0, "no teardown");
    assert_eq!(
        counters.start.load(Ordering::SeqCst),
        1,
        "no spurious restart of an established session"
    );
}

#[tokio::test]
async fn strict_peer_started_on_first_bfd_up_then_coupled() {
    let peer: IpAddr = "10.0.0.2".parse().unwrap();
    let counters = Arc::new(BfdCouplingCounters::default());
    let (mut mgr, _rx) = coupled_mgr(peer, true, fake_bfd_peer_handle(counters.clone()));
    assert!(mgr.is_strict_bfd_peer(&peer));
    // add_peer marks strict peers pre-held (withheld); simulate that here.
    mgr.mark_bfd_withheld(peer);

    // First BFD Up releases the withhold → BGP starts.
    mgr.handle_bfd_state_change(up(peer)).await;
    wait_counter(&counters.start, 1).await;

    // Once up, a later BFD down couples like non-strict → teardown.
    mgr.handle_bfd_state_change(down(peer)).await;
    wait_counter(&counters.stop, 1).await;
}

#[tokio::test]
async fn strict_peer_stays_withheld_without_bfd_up() {
    let peer: IpAddr = "10.0.0.2".parse().unwrap();
    let counters = Arc::new(BfdCouplingCounters::default());
    let (mut mgr, _rx) = coupled_mgr(peer, true, fake_bfd_peer_handle(counters.clone()));
    mgr.mark_bfd_withheld(peer);

    // While withheld, a Down (or anything but Up) must not start BGP, and the
    // already-held guard means no spurious stop either.
    mgr.handle_bfd_state_change(down(peer)).await;
    assert_eq!(
        counters.start.load(Ordering::SeqCst),
        0,
        "withheld peer not started"
    );
    assert_eq!(
        counters.stop.load(Ordering::SeqCst),
        0,
        "already-held peer not re-stopped"
    );
}

#[tokio::test]
async fn strict_ack_releases_withhold_when_bfd_already_up() {
    // "BFD already Up before the peer was added" case: a strict peer is always
    // added withheld, and the actor's reconcile ack (re-reporting the session
    // already Up) releases it — no transition needed, no deadlock, and no
    // trusting of a cached state.
    let peer: IpAddr = "10.0.0.2".parse().unwrap();
    let counters = Arc::new(BfdCouplingCounters::default());
    let (mut mgr, _rx) = coupled_mgr(peer, true, fake_bfd_peer_handle(counters.clone()));
    assert!(
        mgr.bfd_should_withhold(&peer),
        "strict always withholds at add/enable"
    );
    mgr.mark_bfd_withheld(peer);
    assert!(mgr.bfd_withholding(&peer));

    mgr.handle_bfd_state_change(up_ack(peer)).await;
    wait_counter(&counters.start, 1).await;
    assert!(!mgr.bfd_withholding(&peer), "ack of an Up session releases");
}

#[tokio::test]
async fn strict_enable_withholds_then_ack_or_edge_releases() {
    let peer: IpAddr = "10.0.0.2".parse().unwrap();
    let counters = Arc::new(BfdCouplingCounters::default());
    let (mut mgr, _rx) = coupled_mgr(peer, true, fake_bfd_peer_handle(counters.clone()));

    // enable_peer always withholds a strict peer; a fresh Up (edge) releases it.
    mgr.enable_peer(key(peer)).await.unwrap();
    assert_eq!(
        counters.start.load(Ordering::SeqCst),
        0,
        "withheld at enable"
    );
    assert!(mgr.bfd_withholding(&peer));
    mgr.handle_bfd_state_change(up(peer)).await;
    wait_counter(&counters.start, 1).await; // released on the Up edge

    // Re-enabling after release withholds again — never trusting a stale state —
    // and the reconcile ack (BFD still Up) releases it.
    mgr.enable_peer(key(peer)).await.unwrap();
    assert!(
        mgr.bfd_withholding(&peer),
        "re-enable re-withholds (no stale trust)"
    );
    assert_eq!(
        counters.start.load(Ordering::SeqCst),
        1,
        "not started before the ack confirms BFD"
    );
    mgr.handle_bfd_state_change(up_ack(peer)).await;
    wait_counter(&counters.start, 2).await;
}

#[tokio::test]
async fn ack_is_release_only_never_tears_down() {
    // A reconcile ack re-reporting Down (e.g. a freshly (re)started session)
    // must NOT tear BGP down — only a real Up→Down transition does.
    let peer: IpAddr = "10.0.0.2".parse().unwrap();
    let counters = Arc::new(BfdCouplingCounters::default());
    let (mut mgr, _rx) = coupled_mgr(peer, false, fake_bfd_peer_handle(counters.clone()));

    mgr.handle_bfd_state_change(down_ack(peer)).await;
    assert_eq!(
        counters.stop.load(Ordering::SeqCst),
        0,
        "ack-Down must not tear down BGP"
    );

    // A real Down transition still does.
    mgr.handle_bfd_state_change(down(peer)).await;
    wait_counter(&counters.stop, 1).await;
}

#[tokio::test]
async fn genuine_init_transition_does_not_tear_bgp_down() {
    let peer: IpAddr = "10.0.0.2".parse().unwrap();
    let counters = Arc::new(BfdCouplingCounters::default());
    let (mut mgr, _rx) = coupled_mgr(peer, false, fake_bfd_peer_handle(counters.clone()));
    mgr.handle_bfd_state_change(crate::bfd_runtime::BfdStateChange {
        revision: 0,
        peer,
        state: rustbgpd_bfd::SessionState::Init,
        diagnostic: rustbgpd_bfd::Diagnostic::None,
        remote_admin_down: false,
        resync: false,
    })
    .await;
    assert_eq!(counters.stop.load(Ordering::SeqCst), 0);
    assert_eq!(counters.bfd_down.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn strict_reenable_withholds_until_ack_no_leak_no_deadlock() {
    // The #2 tight-race fix: a strict re-enable always withholds (never trusts a
    // possibly-stale Up), so it cannot leak BGP before the fresh state; and the
    // reconcile ack re-reporting the still-Up session (the coalesced case, where
    // no fresh edge will come) releases it — so it does not deadlock either.
    let peer: IpAddr = "10.0.0.2".parse().unwrap();
    let counters = Arc::new(BfdCouplingCounters::default());
    let (mut mgr, _rx) = coupled_mgr(peer, true, fake_bfd_peer_handle(counters.clone()));

    // Established.
    mgr.mark_bfd_withheld(peer);
    mgr.handle_bfd_state_change(up(peer)).await;
    wait_counter(&counters.start, 1).await;

    // Disable then re-enable, coalesced: the actor never drained, the session
    // stays Up, and no fresh edge will arrive.
    mgr.peers.get_mut(&key(peer)).unwrap().enabled = false;
    mgr.set_bfd_peer_disabled(peer, true);
    mgr.peers.get_mut(&key(peer)).unwrap().enabled = true;
    mgr.set_bfd_peer_disabled(peer, false);
    mgr.enable_peer(key(peer)).await.unwrap();
    assert!(
        mgr.bfd_withholding(&peer),
        "re-enable withholds — no premature start"
    );
    assert_eq!(
        counters.start.load(Ordering::SeqCst),
        1,
        "did not leak a start trusting the old Up"
    );

    // The reconcile ack re-reports the still-Up session → release (no deadlock).
    mgr.handle_bfd_state_change(up_ack(peer)).await;
    wait_counter(&counters.start, 2).await;
}

#[tokio::test]
async fn strict_bfd_drops_inbound_until_up() {
    // Regression: strict withholding must cover the passive path. A strict peer
    // whose BFD is not Up must not accept an inbound connection — accepting it
    // would start a session and establish BGP, bypassing the withhold the
    // active-open path (`add_peer` / `enable_peer`) enforces.
    let peer: IpAddr = "10.0.0.2".parse().unwrap();
    let counters = Arc::new(BfdCouplingCounters::default());
    let (mut mgr, _rx) = coupled_mgr(peer, true, fake_bfd_peer_handle(counters));
    mgr.mark_bfd_withheld(peer);
    assert!(
        mgr.bfd_should_withhold(&peer),
        "strict + BFD down → withhold"
    );

    let session_id_before = mgr.peers.get(&key(peer)).unwrap().session_id;

    // A real inbound socket; the address we drive `handle_inbound` with is the
    // configured strict peer's, not the loopback the socket actually came from.
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let listener_addr = listener.local_addr().unwrap();
    let client = tokio::spawn(async move { TcpStream::connect(listener_addr).await.unwrap() });
    let (server_stream, _real_addr) = listener.accept().await.unwrap();
    let _client_stream = client.await.unwrap();

    mgr.handle_inbound(server_stream, sock(peer), None, None)
        .await;

    // The inbound was dropped: the managed session was neither replaced nor
    // given a pending collision candidate, so no BGP session started.
    let managed = mgr.peers.get(&key(peer)).unwrap();
    assert_eq!(
        managed.session_id, session_id_before,
        "strict peer's session must not be replaced by an inbound while BFD is down"
    );
    assert!(
        managed.pending_inbound.is_none(),
        "no inbound collision candidate should start for a withheld strict peer"
    );
}

#[tokio::test]
async fn nonstrict_bfd_down_drops_inbound_while_held() {
    // A non-strict peer torn down by a BFD-down is held; an inbound connection
    // must be dropped while held — re-establishing BGP over a presumed-dead path
    // would undo the BFD-driven teardown. (The hold releases on the BFD-up edge,
    // which reconnects via the normal active-open path.)
    let peer: IpAddr = "10.0.0.2".parse().unwrap();
    let counters = Arc::new(BfdCouplingCounters::default());
    let (mut mgr, _rx) = coupled_mgr(peer, false, fake_bfd_peer_handle(counters.clone()));

    // BFD goes down → BGP torn down and held.
    mgr.handle_bfd_state_change(down(peer)).await;
    wait_counter(&counters.stop, 1).await;
    assert!(
        mgr.bfd_withholding(&peer),
        "non-strict peer is held while BFD is down"
    );

    let session_id_before = mgr.peers.get(&key(peer)).unwrap().session_id;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let listener_addr = listener.local_addr().unwrap();
    let client = tokio::spawn(async move { TcpStream::connect(listener_addr).await.unwrap() });
    let (server_stream, _real_addr) = listener.accept().await.unwrap();
    let _client_stream = client.await.unwrap();

    mgr.handle_inbound(server_stream, sock(peer), None, None)
        .await;

    let managed = mgr.peers.get(&key(peer)).unwrap();
    assert_eq!(
        managed.session_id, session_id_before,
        "inbound must be dropped while a non-strict peer is BFD-held"
    );
    assert!(managed.pending_inbound.is_none());
}

#[tokio::test]
async fn republish_reflects_disable_and_readd() {
    let peer: IpAddr = "10.0.0.2".parse().unwrap();
    let counters = Arc::new(BfdCouplingCounters::default());
    let (mut mgr, rx) = coupled_mgr(peer, false, fake_bfd_peer_handle(counters));

    let enabled_now = |rx: &watch::Receiver<crate::bfd_runtime::BfdRuntimeConfig>| {
        rx.borrow()
            .sessions
            .iter()
            .find(|s| s.peer == peer)
            .map(|s| s.enabled)
    };

    // A configured peer is enabled by default (disabled set empty) — crucially
    // even before it is added to `self.peers`, since static peers arrive async.
    mgr.republish_bfd_desired();
    assert_eq!(
        enabled_now(&rx),
        Some(true),
        "configured peer enabled by default"
    );

    // Disable / delete → published disabled (actor drains to AdminDown).
    mgr.set_bfd_peer_disabled(peer, true);
    assert_eq!(
        enabled_now(&rx),
        Some(false),
        "disabled/deleted peer published disabled"
    );

    // Re-add (reconfigure delete→add) → re-enabled so the actor restarts it.
    mgr.set_bfd_peer_disabled(peer, false);
    assert_eq!(enabled_now(&rx), Some(true), "re-added peer re-enabled");
}

#[tokio::test]
async fn republish_preserves_link_local_scope_across_reconcile() {
    let peer: IpAddr = "fe80::2".parse().unwrap();
    let params = crate::bfd_runtime::BfdSessionParams {
        revision: 0,
        peer,
        scope_id: Some(71),
        destination: crate::bfd_runtime::bfd_destination(peer, Some(71), false)
            .expect("scoped test peer destination"),
        desired_min_tx_us: 300_000,
        required_min_rx_us: 300_000,
        detect_mult: 3,
        strict: false,
        enabled: true,
        multihop: false,
        source: None,
    };
    let configured = std::collections::HashMap::from([(peer, params)]);
    let (desired_tx, desired_rx) = watch::channel(crate::bfd_runtime::BfdRuntimeConfig::default());
    let (_state_tx, state_rx) = crate::bfd_runtime::state_change_channel();
    let mut mgr = test_peer_manager().with_bfd_coupling(desired_tx, state_rx, configured);

    mgr.republish_bfd_desired();
    let session = desired_rx
        .borrow()
        .sessions
        .iter()
        .find(|session| session.peer == peer)
        .cloned()
        .expect("configured link-local BFD session");
    assert!(session.enabled);
    assert_eq!(session.scope_id, Some(71));

    mgr.set_bfd_peer_disabled(peer, true);
    let session = desired_rx
        .borrow()
        .sessions
        .iter()
        .find(|session| session.peer == peer)
        .cloned()
        .expect("disabled session remains in desired set for actor drain");
    assert!(!session.enabled);
    assert_eq!(
        session.scope_id,
        Some(71),
        "PeerManager clone/reconcile must not erase the startup-resolved scope"
    );
}

/// Regression: a genuine BFD Down must tear down a pending inbound collision
/// candidate alongside the primary session. The candidate is a live,
/// already-started session; previously only the primary was stopped, so
/// `BackToIdle` promotion re-established BGP over the BFD-down path moments
/// after the teardown.
#[tokio::test]
async fn bfd_down_tears_down_pending_inbound_candidate() {
    let peer: IpAddr = "10.0.0.2".parse().unwrap();
    let counters = Arc::new(BfdCouplingCounters::default());
    let (mut mgr, _rx) = coupled_mgr(peer, false, fake_bfd_peer_handle(counters.clone()));
    let pending = Arc::new(FakePeerCounters::default());
    attach_test_pending_inbound(
        &mut mgr,
        peer,
        fake_peer_handle(peer, SessionState::OpenConfirm, None, pending.clone()),
        2,
    );

    mgr.handle_bfd_state_change(down(peer)).await;

    wait_counter(&pending.shutdown, 1).await;
    wait_counter(&counters.stop, 1).await;
    assert!(
        mgr.peers
            .get(&key(peer))
            .is_some_and(|m| m.pending_inbound.is_none()),
        "pending candidate must be gone after BFD down"
    );
    assert!(mgr.peer_key_for_session(2).is_none());
}

/// Load-bearing BFD retirement proof: the pending actor emits max-prefix only
/// while consuming BFD Down's Shutdown. Removing the retirement barrier loses
/// the latch; restarting an administratively disabled peer on BFD Up bypasses
/// the explicit-Enable contract.
#[tokio::test]
async fn bfd_pending_terminal_breach_blocks_later_automatic_restart() {
    let peer: IpAddr = "10.0.0.43".parse().unwrap();
    let primary = Arc::new(BfdCouplingCounters::default());
    let (mut mgr, _rx) = coupled_mgr(peer, false, fake_bfd_peer_handle(primary.clone()));
    let pending = Arc::new(FakePeerCounters::default());
    let notify_tx = mgr.session_notify_tx.clone();
    attach_test_pending_inbound(
        &mut mgr,
        peer,
        max_prefix_on_command_peer_handle(
            peer,
            2,
            rustbgpd_transport::SessionRole::InboundCandidate,
            MaxPrefixTrigger::Shutdown,
            notify_tx,
            pending.clone(),
        ),
        2,
    );

    mgr.handle_bfd_state_change(down(peer)).await;

    assert_eq!(pending.shutdown.load(Ordering::SeqCst), 1);
    let managed = mgr.peers.get(&key(peer)).unwrap();
    assert!(!managed.enabled);
    assert!(managed.pending_inbound.is_none());
    assert!(mgr.max_prefix_latches.contains_key(&key(peer)));
    assert!(mgr.retiring_sessions.is_empty());
    assert!(mgr.peer_key_for_session(2).is_none());
    let starts_before_up = primary.start.load(Ordering::SeqCst);

    mgr.handle_bfd_state_change(up(peer)).await;
    for _ in 0..3 {
        tokio::task::yield_now().await;
    }
    assert_eq!(
        primary.start.load(Ordering::SeqCst),
        starts_before_up,
        "BFD Up must not restart an administratively disabled max-prefix peer"
    );
}

/// Regression: `BackToIdle` must not promote a pending inbound collision
/// candidate while BFD is withholding the peer — the primary usually went
/// idle BECAUSE BFD tore it down, and promotion would re-establish BGP over
/// the BFD-down path. The candidate is dropped instead.
#[tokio::test]
async fn back_to_idle_drops_candidate_while_bfd_withholding() {
    let peer: IpAddr = "10.0.0.2".parse().unwrap();
    let counters = Arc::new(BfdCouplingCounters::default());
    let (mut mgr, _rx) = coupled_mgr(peer, false, fake_bfd_peer_handle(counters.clone()));

    // Enter the hold first (no candidate exists yet), then attach one —
    // exercising the promotion-time gate rather than the BFD-down teardown.
    mgr.handle_bfd_state_change(down(peer)).await;
    let pending = Arc::new(FakePeerCounters::default());
    attach_test_pending_inbound(
        &mut mgr,
        peer,
        fake_peer_handle(peer, SessionState::OpenConfirm, None, pending.clone()),
        2,
    );

    mgr.handle_session_notification(SessionNotification::BackToIdle {
        session_id: 1,
        role: rustbgpd_transport::SessionRole::Primary,
        peer_addr: peer,
    })
    .await;

    wait_counter(&pending.shutdown, 1).await;
    assert!(
        mgr.peers
            .get(&key(peer))
            .is_some_and(|m| m.pending_inbound.is_none()),
        "candidate must be dropped, not promoted, while BFD withholds"
    );
    assert!(mgr.peer_key_for_session(2).is_none());
}

#[tokio::test]
async fn bfd_reload_abort_restores_nonstrict_admission_without_publishing_candidate() {
    let peer: IpAddr = "10.0.0.2".parse().unwrap();
    let counters = Arc::new(BfdCouplingCounters::default());
    let (mut mgr, mut desired) = coupled_mgr(peer, false, fake_bfd_peer_handle(counters.clone()));
    mgr.republish_bfd_desired();
    let before = desired.borrow_and_update().clone();
    let coupling = mgr.bfd_coupling.as_mut().unwrap();
    coupling.prior_held.clone_from(&coupling.held_down);
    coupling.pending = Some(HashMap::from([(peer, bfd_params(peer, true))]));
    coupling.reloading = true;
    assert!(mgr.bfd_should_withhold(&peer));
    mgr.mark_bfd_withheld(peer);
    mgr.set_bfd_peer_disabled(peer, true);
    assert!(
        !desired.has_changed().unwrap(),
        "candidate must not drain live BFD"
    );
    mgr.restore_bfd_reload_lookup();
    mgr.abort_bfd_reload();
    assert!(!mgr.bfd_should_withhold(&peer));
    assert!(!mgr.bfd_withholding(&peer));
    assert_eq!(*desired.borrow(), before);
    assert_eq!(counters.stop.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn bfd_reload_ignores_retired_session_notifications() {
    let peer: IpAddr = "10.0.0.2".parse().unwrap();
    let counters = Arc::new(BfdCouplingCounters::default());
    let (mut mgr, _) = coupled_mgr(peer, true, fake_bfd_peer_handle(counters.clone()));
    mgr.bfd_coupling
        .as_mut()
        .unwrap()
        .configured
        .get_mut(&peer)
        .unwrap()
        .revision = 1;
    mgr.mark_bfd_withheld(peer);
    mgr.handle_bfd_state_change(up_ack(peer)).await;
    assert!(
        mgr.bfd_withholding(&peer),
        "retired Up must not release replacement"
    );
    let mut current = up_ack(peer);
    current.revision = 1;
    mgr.handle_bfd_state_change(current).await;
    wait_counter(&counters.start, 1).await;
    mgr.handle_bfd_state_change(down(peer)).await;
    assert!(
        !mgr.bfd_withholding(&peer),
        "retired Down must not stop replacement"
    );
    assert_eq!(counters.stop.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn bfd_reload_commit_preserves_nonstrict_and_releases_removed_hold() {
    let peer: IpAddr = "10.0.0.2".parse().unwrap();
    let counters = Arc::new(BfdCouplingCounters::default());
    let (mut mgr, desired) = coupled_mgr(peer, false, fake_bfd_peer_handle(counters.clone()));
    let (reload_tx, mut reload_rx) = mpsc::channel::<crate::bfd_runtime::BfdReloadCommand>(1);
    mgr = mgr.with_bfd_reload(reload_tx);
    let actor = tokio::spawn(async move {
        while let Some(command) = reload_rx.recv().await {
            let states = command
                .desired
                .sessions
                .iter()
                .map(|params| {
                    let mut ack = down_ack(params.peer);
                    ack.revision = params.revision;
                    ack
                })
                .collect();
            command.reply.send(states).unwrap();
        }
    });
    let mut replacement = bfd_params(peer, false);
    replacement.revision = 1;
    let coupling = mgr.bfd_coupling.as_mut().unwrap();
    coupling.pending = Some(HashMap::from([(peer, replacement)]));
    coupling.reloading = true;
    mgr.commit_bfd_reload(None).await.unwrap();
    assert_eq!(desired.borrow().sessions[0].revision, 1);
    assert_eq!(
        counters.stop.load(Ordering::SeqCst),
        0,
        "new non-strict Down is bootstrap"
    );
    mgr.mark_bfd_withheld(peer);
    let coupling = mgr.bfd_coupling.as_mut().unwrap();
    coupling.pending = Some(HashMap::new());
    coupling.reloading = true;
    mgr.commit_bfd_reload(None).await.unwrap();
    wait_counter(&counters.start, 1).await;
    assert!(!mgr.bfd_withholding(&peer));
    assert!(desired.borrow().sessions.is_empty());
    actor.abort();
}

#[tokio::test]
async fn bfd_reload_strict_down_retains_gate_after_failed_bgp_stop() {
    let peer: IpAddr = "10.0.0.2".parse().unwrap();
    let (commands, commands_rx) = mpsc::channel(1);
    drop(commands_rx);
    let handle = PeerHandle::from_parts(commands, tokio::spawn(async { Ok(()) }));
    let (mut mgr, _) = coupled_mgr(peer, false, handle);
    let (reload_tx, mut reload_rx) = mpsc::channel::<crate::bfd_runtime::BfdReloadCommand>(1);
    mgr = mgr.with_bfd_reload(reload_tx);
    let actor = tokio::spawn(async move {
        let command = reload_rx.recv().await.unwrap();
        command.reply.send(vec![down_ack(peer)]).unwrap();
    });
    let coupling = mgr.bfd_coupling.as_mut().unwrap();
    coupling.pending = Some(HashMap::from([(peer, bfd_params(peer, true))]));
    coupling.reloading = true;
    mgr.commit_bfd_reload(None).await.unwrap();
    assert!(
        mgr.bfd_withholding(&peer),
        "failure must retain strict inbound gate"
    );
    actor.await.unwrap();
}

#[tokio::test]
async fn bfd_reload_strict_toggle_releases_bootstrap_but_preserves_failure_hold() {
    let peer: IpAddr = "10.0.0.2".parse().unwrap();
    let counters = Arc::new(BfdCouplingCounters::default());
    let (mut mgr, _) = coupled_mgr(peer, false, fake_bfd_peer_handle(counters.clone()));
    let (reload_tx, mut reload_rx) = mpsc::channel::<crate::bfd_runtime::BfdReloadCommand>(1);
    mgr = mgr.with_bfd_reload(reload_tx);
    let actor = tokio::spawn(async move {
        while let Some(command) = reload_rx.recv().await {
            command.reply.send(vec![down_ack(peer)]).unwrap();
        }
    });
    for strict in [true, false] {
        let coupling = mgr.bfd_coupling.as_mut().unwrap();
        coupling.pending = Some(HashMap::from([(peer, bfd_params(peer, strict))]));
        coupling.reloading = true;
        mgr.commit_bfd_reload(None).await.unwrap();
        assert_eq!(mgr.bfd_withholding(&peer), strict);
    }
    wait_counter(&counters.start, 1).await;
    // A genuine failure is a different hold reason, even when strict is toggled.
    for strict in [true, false] {
        let coupling = mgr.bfd_coupling.as_mut().unwrap();
        coupling.pending = Some(HashMap::from([(peer, bfd_params(peer, strict))]));
        coupling.reloading = true;
        mgr.commit_bfd_reload(None).await.unwrap();
        if strict {
            mgr.handle_bfd_state_change(down(peer)).await;
        }
        assert!(mgr.bfd_withholding(&peer));
    }
    assert_eq!(counters.start.load(Ordering::SeqCst), 1);
    actor.abort();
}

#[tokio::test]
async fn bfd_reload_rejects_incomplete_actor_acknowledgement() {
    let peer: IpAddr = "10.0.0.2".parse().unwrap();
    let counters = Arc::new(BfdCouplingCounters::default());
    let (mut mgr, _) = coupled_mgr(peer, false, fake_bfd_peer_handle(counters.clone()));
    let (reload_tx, mut reload_rx) = mpsc::channel::<crate::bfd_runtime::BfdReloadCommand>(1);
    mgr = mgr.with_bfd_reload(reload_tx);
    let actor = tokio::spawn(async move {
        reload_rx
            .recv()
            .await
            .unwrap()
            .reply
            .send(Vec::new())
            .unwrap();
    });
    let coupling = mgr.bfd_coupling.as_mut().unwrap();
    coupling.pending = Some(HashMap::from([(peer, bfd_params(peer, true))]));
    coupling.reloading = true;
    assert!(
        mgr.commit_bfd_reload(None)
            .await
            .unwrap_err()
            .contains("desired session set")
    );
    mgr.fence_bfd_reload().await;
    assert!(mgr.bfd_withholding(&peer));
    wait_counter(&counters.stop, 1).await;
    actor.await.unwrap();
}

#[tokio::test]
async fn bfd_reload_abort_preserves_prior_failure_hold_reason() {
    let peer: IpAddr = "10.0.0.2".parse().unwrap();
    let counters = Arc::new(BfdCouplingCounters::default());
    let (mut mgr, _) = coupled_mgr(peer, true, fake_bfd_peer_handle(counters));
    mgr.handle_bfd_state_change(down(peer)).await;
    let coupling = mgr.bfd_coupling.as_mut().unwrap();
    coupling.prior_held.clone_from(&coupling.held_down);
    coupling.reloading = true;
    mgr.mark_bfd_withheld(peer); // Candidate/rollback replacement starts withheld.
    mgr.abort_bfd_reload();
    let (reload_tx, mut reload_rx) = mpsc::channel::<crate::bfd_runtime::BfdReloadCommand>(1);
    mgr = mgr.with_bfd_reload(reload_tx);
    let actor = tokio::spawn(async move {
        reload_rx
            .recv()
            .await
            .unwrap()
            .reply
            .send(vec![down_ack(peer)])
            .unwrap();
    });
    let coupling = mgr.bfd_coupling.as_mut().unwrap();
    coupling.pending = Some(HashMap::from([(peer, bfd_params(peer, false))]));
    coupling.reloading = true;
    mgr.commit_bfd_reload(None).await.unwrap();
    assert!(
        mgr.bfd_withholding(&peer),
        "rollback must preserve the real failure reason"
    );
    actor.await.unwrap();
}

#[tokio::test]
async fn bfd_reload_up_ack_retains_hold_after_failed_peer_start() {
    let peer: IpAddr = "10.0.0.2".parse().unwrap();
    let (commands, commands_rx) = mpsc::channel(1);
    drop(commands_rx);
    let handle = PeerHandle::from_parts(commands, tokio::spawn(async { Ok(()) }));
    let (mut mgr, _) = coupled_mgr(peer, true, handle);
    mgr.mark_bfd_withheld(peer);
    let (reload_tx, mut reload_rx) = mpsc::channel::<crate::bfd_runtime::BfdReloadCommand>(1);
    mgr = mgr.with_bfd_reload(reload_tx);
    let actor = tokio::spawn(async move {
        let command = reload_rx.recv().await.unwrap();
        let mut ack = up_ack(peer);
        ack.revision = 1;
        command.reply.send(vec![ack]).unwrap();
    });
    let mut replacement = bfd_params(peer, true);
    replacement.revision = 1;
    let coupling = mgr.bfd_coupling.as_mut().unwrap();
    coupling.pending = Some(HashMap::from([(peer, replacement)]));
    coupling.reloading = true;
    mgr.commit_bfd_reload(None).await.unwrap();
    assert!(mgr.bfd_withholding(&peer));
    actor.await.unwrap();
}

#[tokio::test]
async fn bfd_reload_uncertain_fence_stops_pending_collision_and_ignores_old_up() {
    let peer: IpAddr = "10.0.0.2".parse().unwrap();
    let counters = Arc::new(BfdCouplingCounters::default());
    let (mut mgr, _) = coupled_mgr(peer, true, fake_bfd_peer_handle(counters.clone()));
    let pending = Arc::new(FakePeerCounters::default());
    attach_test_pending_inbound(
        &mut mgr,
        peer,
        fake_peer_handle(peer, SessionState::OpenConfirm, None, pending.clone()),
        2,
    );
    mgr.fence_bfd_reload().await;
    wait_counter(&pending.shutdown, 1).await;
    wait_counter(&counters.stop, 1).await;
    assert!(mgr.peers[&key(peer)].pending_inbound.is_none());
    mgr.handle_bfd_state_change(up_ack(peer)).await;
    assert!(mgr.bfd_withholding(&peer));
    assert_eq!(counters.start.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn bfd_reload_ack_wait_serves_readiness_and_operator_reads() {
    let peer: IpAddr = "10.0.0.2".parse().unwrap();
    let counters = Arc::new(BfdCouplingCounters::default());
    let (mut mgr, _) = coupled_mgr(peer, false, fake_bfd_peer_handle(counters));
    let (reload_tx, mut reload_rx) = mpsc::channel::<crate::bfd_runtime::BfdReloadCommand>(1);
    let (readiness_tx, readiness_rx) = mpsc::channel(1);
    let (operator_tx, operator_rx) = mpsc::channel(1);
    mgr = mgr
        .with_bfd_reload(reload_tx)
        .with_readiness_queries(readiness_rx)
        .with_operator_queries(operator_rx);
    let coupling = mgr.bfd_coupling.as_mut().unwrap();
    coupling.pending = Some(HashMap::from([(peer, bfd_params(peer, true))]));
    coupling.reloading = true;
    let commit = tokio::spawn(async move { mgr.commit_bfd_reload(None).await });
    let command = reload_rx.recv().await.unwrap(); // Hold the actor acknowledgement.
    let (reply, ping) = oneshot::channel();
    readiness_tx
        .send(PeerManagerReadinessQuery::Ping { reply })
        .await
        .unwrap();
    let (reply, read) = oneshot::channel();
    operator_tx
        .send(
            PeerManagerOperatorQuery::HasPeerAddress {
                address: peer,
                reply,
            }
            .into(),
        )
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_millis(250), ping)
        .await
        .unwrap()
        .unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(250), read)
            .await
            .unwrap()
            .unwrap()
    );
    assert!(
        !commit.is_finished(),
        "reads must complete while actor acknowledgement remains held"
    );
    command.reply.send(vec![down_ack(peer)]).unwrap();
    commit.await.unwrap().unwrap();
}

#[tokio::test]
async fn bfd_reload_strict_relaxation_preserves_failure_pending_during_commit() {
    let peer: IpAddr = "10.0.0.2".parse().unwrap();
    let counters = Arc::new(BfdCouplingCounters::default());
    let (mut mgr, _) = coupled_mgr(peer, true, fake_bfd_peer_handle(counters.clone()));
    mgr.mark_bfd_withheld(peer);
    let (reload_tx, mut reload_rx) = mpsc::channel::<crate::bfd_runtime::BfdReloadCommand>(1);
    mgr = mgr.with_bfd_reload(reload_tx);
    let actor = tokio::spawn(async move {
        // The genuine Down has not reached the manager's normal receive loop yet.
        reload_rx
            .recv()
            .await
            .unwrap()
            .reply
            .send(vec![down(peer)])
            .unwrap();
    });
    let coupling = mgr.bfd_coupling.as_mut().unwrap();
    coupling.pending = Some(HashMap::from([(peer, bfd_params(peer, false))]));
    coupling.reloading = true;
    mgr.commit_bfd_reload(None).await.unwrap();
    assert!(mgr.bfd_withholding(&peer));
    assert_eq!(counters.start.load(Ordering::SeqCst), 0);
    actor.await.unwrap();
}

#[tokio::test]
async fn bfd_reload_unchanged_strict_replacement_waits_for_actor_ack() {
    let peer: IpAddr = "10.0.0.2".parse().unwrap();
    let counters = Arc::new(BfdCouplingCounters::default());
    let (mut mgr, _) = coupled_mgr(peer, true, fake_bfd_peer_handle(counters.clone()));
    // Replacing only the BGP transport withholds the new peer even though its
    // BFD session parameters and incarnation have not changed.
    mgr.mark_bfd_withheld(peer);
    let (reload_tx, mut reload_rx) = mpsc::channel::<crate::bfd_runtime::BfdReloadCommand>(1);
    mgr = mgr.with_bfd_reload(reload_tx);
    let coupling = mgr.bfd_coupling.as_mut().unwrap();
    coupling.pending = Some(coupling.configured.clone());
    coupling.reloading = true;
    let commit = tokio::spawn(async move {
        let result = mgr.commit_bfd_reload(None).await;
        (mgr, result)
    });
    let command = tokio::time::timeout(Duration::from_millis(250), reload_rx.recv())
        .await
        .expect("unchanged BFD members still require actor acknowledgement")
        .expect("reload command");
    assert!(!commit.is_finished());
    assert_eq!(counters.start.load(Ordering::SeqCst), 0);
    command.reply.send(vec![up_ack(peer)]).unwrap();
    let (mgr, result) = commit.await.unwrap();
    result.unwrap();
    wait_counter(&counters.start, 1).await;
    assert!(!mgr.bfd_withholding(&peer));
}

#[tokio::test]
async fn bfd_reload_unchanged_members_reject_dead_actor() {
    let peer: IpAddr = "10.0.0.2".parse().unwrap();
    for strict in [false, true] {
        let counters = Arc::new(BfdCouplingCounters::default());
        let (mut mgr, _) = coupled_mgr(peer, strict, fake_bfd_peer_handle(counters.clone()));
        if strict {
            mgr.mark_bfd_withheld(peer);
        }
        let (reload_tx, reload_rx) = mpsc::channel::<crate::bfd_runtime::BfdReloadCommand>(1);
        drop(reload_rx);
        mgr = mgr.with_bfd_reload(reload_tx);
        let coupling = mgr.bfd_coupling.as_mut().unwrap();
        coupling.pending = Some(coupling.configured.clone());
        coupling.reloading = true;
        assert!(
            mgr.commit_bfd_reload(None)
                .await
                .unwrap_err()
                .contains("BFD actor stopped before reload")
        );
        assert_eq!(mgr.bfd_withholding(&peer), strict);
        assert_eq!(counters.start.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test(start_paused = true)]
async fn bfd_reload_ack_budget_excludes_admitted_operator_read_time() {
    let peer: IpAddr = "10.0.0.2".parse().unwrap();
    let (commands, mut commands_rx) = mpsc::channel(4);
    let (state_queries, mut state_queries_rx) = mpsc::channel(1);
    let session = tokio::spawn(async move {
        while let Some(command) = commands_rx.recv().await {
            if let PeerCommand::QueryState { reply } = command {
                state_queries.send(reply).await.unwrap();
            }
        }
        Ok(())
    });
    let (mut mgr, _) = coupled_mgr(peer, false, PeerHandle::from_parts(commands, session));
    let (reload_tx, mut reload_rx) = mpsc::channel::<crate::bfd_runtime::BfdReloadCommand>(1);
    let (operator_tx, operator_rx) = mpsc::channel(1);
    mgr = mgr
        .with_bfd_reload(reload_tx)
        .with_operator_queries(operator_rx);
    let coupling = mgr.bfd_coupling.as_mut().unwrap();
    coupling.pending = Some(coupling.configured.clone());
    coupling.reloading = true;
    let commit = tokio::spawn(async move { mgr.commit_bfd_reload(None).await });
    let command = reload_rx.recv().await.unwrap();
    tokio::time::advance(Duration::from_millis(4_950)).await;
    let (reply, read) = oneshot::channel();
    operator_tx
        .send(
            PeerManagerOperatorQuery::GetPeerState {
                peer: key(peer),
                reply,
            }
            .into(),
        )
        .await
        .unwrap();
    let state_reply = state_queries_rx.recv().await.unwrap();
    // Cross the wall-clock 5 s limit while the admitted read still has
    // 25 ms remaining in its independent 100 ms session-query budget.
    tokio::time::advance(Duration::from_millis(75)).await;
    state_reply
        .send(policy_test_peer_state(peer, SessionState::Established))
        .unwrap();
    read.await.unwrap().unwrap();
    for _ in 0..3 {
        tokio::task::yield_now().await;
    }
    assert!(
        !commit.is_finished(),
        "operator servicing must not consume the actor acknowledgement budget"
    );
    command.reply.send(vec![down_ack(peer)]).unwrap();
    commit.await.unwrap().unwrap();
}

#[tokio::test(start_paused = true)]
async fn bfd_reload_busy_peer_does_not_prevent_other_peers_coupling() {
    let busy: IpAddr = "10.0.0.2".parse().unwrap();
    let healthy: IpAddr = "10.0.0.3".parse().unwrap();
    for permits_bgp in [false, true] {
        let (commands, mut commands_rx) = mpsc::channel(1);
        commands.try_send(PeerCommand::Start).unwrap();
        let task = tokio::spawn(std::future::pending());
        let (mut mgr, _) = coupled_mgr(busy, permits_bgp, PeerHandle::from_parts(commands, task));
        let counters = Arc::new(BfdCouplingCounters::default());
        insert_test_managed_peer(
            &mut mgr,
            healthy,
            fake_bfd_peer_handle(counters.clone()),
            false,
        );
        let coupling = mgr.bfd_coupling.as_mut().unwrap();
        coupling
            .configured
            .insert(healthy, bfd_params(healthy, permits_bgp));
        coupling.pending = Some(HashMap::from([
            (busy, bfd_params(busy, true)),
            (healthy, bfd_params(healthy, true)),
        ]));
        coupling.reloading = true;
        if permits_bgp {
            mgr.mark_bfd_withheld(busy);
            mgr.mark_bfd_withheld(healthy);
        }
        let (reload_tx, mut reload_rx) = mpsc::channel::<crate::bfd_runtime::BfdReloadCommand>(1);
        mgr = mgr.with_bfd_reload(reload_tx);
        let actor = tokio::spawn(async move {
            let command = reload_rx.recv().await.unwrap();
            // Busy first proves a full queue does not prevent the remaining
            // peer from receiving its lifecycle command.
            command
                .reply
                .send(if permits_bgp {
                    vec![up_ack(busy), up_ack(healthy)]
                } else {
                    vec![down_ack(busy), down_ack(healthy)]
                })
                .unwrap();
        });
        mgr.commit_bfd_reload(None)
            .await
            .expect("settled actor set remains accepted");
        assert!(mgr.bfd_withholding(&busy));
        assert!(!mgr.bfd_coupling.as_ref().unwrap().reloading);
        if permits_bgp {
            wait_counter(&counters.start, 1).await;
            assert!(!mgr.bfd_withholding(&healthy));
        } else {
            wait_counter(&counters.bfd_down, 1).await;
            assert!(mgr.bfd_withholding(&healthy));
        }
        actor.await.unwrap();
        assert!(matches!(commands_rx.recv().await, Some(PeerCommand::Start)));
        let (manager_tx, manager_rx) = mpsc::channel(4);
        mgr.rx = manager_rx;
        let manager = tokio::spawn(mgr.run());
        let retried = tokio::time::timeout(Duration::from_secs(1), commands_rx.recv())
            .await
            .expect("automatic retry deadline")
            .expect("automatic retry after queue drains");
        assert!(matches!(
            (&retried, permits_bgp),
            (PeerCommand::Start, true) | (PeerCommand::BfdDown, false)
        ));
        let (reply, ping) = oneshot::channel();
        manager_tx
            .send(PeerManagerCommand::Ping { reply })
            .await
            .unwrap();
        ping.await.unwrap();
        manager_tx.send(PeerManagerCommand::Shutdown).await.unwrap();
        manager.await.unwrap();
    }
}

#[tokio::test]
async fn bfd_reload_ack_applies_queued_genuine_down_before_returning() {
    let peer: IpAddr = "10.0.0.2".parse().unwrap();
    let counters = Arc::new(BfdCouplingCounters::default());
    let (mut mgr, _) = coupled_mgr(peer, false, fake_bfd_peer_handle(counters.clone()));
    let (reload_tx, mut reload_rx) = mpsc::channel::<crate::bfd_runtime::BfdReloadCommand>(1);
    mgr = mgr.with_bfd_reload(reload_tx);
    let coupling = mgr.bfd_coupling.as_mut().unwrap();
    coupling.pending = Some(coupling.configured.clone());
    coupling.reloading = true;
    let actor = tokio::spawn(async move {
        reload_rx
            .recv()
            .await
            .unwrap()
            .reply
            .send(vec![down(peer)])
            .unwrap();
    });
    mgr.commit_bfd_reload(None).await.unwrap();
    wait_counter(&counters.bfd_down, 1).await;
    assert!(mgr.bfd_withholding(&peer));
    // The normal notification remains queued too; consuming it later must
    // not enqueue a second stop after the acknowledgement handled the edge.
    mgr.handle_bfd_state_change(down(peer)).await;
    assert_eq!(counters.bfd_down.load(Ordering::SeqCst), 1);
    actor.await.unwrap();
}

#[tokio::test]
async fn bfd_retry_cancels_on_opposite_state_admin_and_replacement() {
    let peer: IpAddr = "10.0.0.2".parse().unwrap();
    for cancellation in ["down", "disable", "replacement", "bfd replacement"] {
        let counters = Arc::new(BfdCouplingCounters::default());
        let (mut mgr, _) = coupled_mgr(peer, true, fake_bfd_peer_handle(counters.clone()));
        mgr.mark_bfd_withheld(peer);
        mgr.schedule_bfd_retry(peer, true);
        match cancellation {
            "down" => mgr.handle_bfd_state_change(down(peer)).await,
            "disable" => mgr.set_bfd_peer_disabled(peer, true),
            "replacement" => mgr.peers.get_mut(&key(peer)).unwrap().session_id += 1,
            _ => {
                mgr.bfd_coupling
                    .as_mut()
                    .unwrap()
                    .configured
                    .get_mut(&peer)
                    .unwrap()
                    .revision += 1;
            }
        }
        mgr.retry_bfd_commands(None);
        tokio::task::yield_now().await;
        assert_eq!(counters.start.load(Ordering::SeqCst), 0, "{cancellation}");
        assert!(mgr.bfd_retry_deadline().is_none(), "{cancellation}");
        if cancellation != "disable" {
            assert!(
                mgr.bfd_withholding(&peer),
                "stale retry must not clear replacement/failure hold"
            );
        }
    }
}

#[tokio::test]
async fn bfd_retry_round_robin_reaches_peer_after_full_first_batch() {
    let first: IpAddr = "10.0.0.1".parse().unwrap();
    let (first_tx, first_rx) = mpsc::channel(1);
    first_tx.try_send(PeerCommand::Start).unwrap();
    let (mut mgr, _) = coupled_mgr(
        first,
        true,
        PeerHandle::from_parts(first_tx, tokio::spawn(std::future::pending())),
    );
    let mut full_queues = vec![first_rx];
    for suffix in 1..=32 {
        let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, suffix));
        if suffix != 1 {
            let (commands, receiver) = mpsc::channel(1);
            commands.try_send(PeerCommand::Start).unwrap();
            full_queues.push(receiver);
            insert_test_managed_peer(
                &mut mgr,
                peer,
                PeerHandle::from_parts(commands, tokio::spawn(std::future::pending())),
                false,
            );
            mgr.bfd_coupling
                .as_mut()
                .unwrap()
                .configured
                .insert(peer, bfd_params(peer, true));
        }
        mgr.mark_bfd_withheld(peer);
        mgr.schedule_bfd_retry(peer, true);
    }
    let healthy = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 33));
    let counters = Arc::new(BfdCouplingCounters::default());
    insert_test_managed_peer(
        &mut mgr,
        healthy,
        fake_bfd_peer_handle(counters.clone()),
        false,
    );
    // A detached member still needs its previously failed Start retried.
    mgr.mark_bfd_withheld(healthy);
    mgr.schedule_bfd_retry(healthy, true);
    mgr.retry_bfd_commands(None);
    assert!(
        mgr.bfd_withholding(&healthy),
        "one turn is limited to 32 attempts"
    );
    mgr.retry_bfd_commands(None);
    wait_counter(&counters.start, 1).await;
    assert!(
        !mgr.bfd_withholding(&healthy),
        "permanently full first batch cannot starve later peers"
    );
    assert_eq!(full_queues.len(), 32);
}

#[tokio::test(start_paused = true)]
async fn bfd_busy_lifecycle_enqueue_defers_without_delaying_readiness() {
    let peer: IpAddr = "10.0.0.2".parse().unwrap();
    let (commands, _receiver) = mpsc::channel(1);
    commands.try_send(PeerCommand::Start).unwrap();
    let (mut mgr, _) = coupled_mgr(
        peer,
        false,
        PeerHandle::from_parts(commands, tokio::spawn(std::future::pending())),
    );
    let (reload_tx, mut reload_rx) = mpsc::channel::<crate::bfd_runtime::BfdReloadCommand>(1);
    let (readiness_tx, readiness_rx) = mpsc::channel(1);
    mgr = mgr
        .with_bfd_reload(reload_tx)
        .with_readiness_queries(readiness_rx);
    let coupling = mgr.bfd_coupling.as_mut().unwrap();
    coupling.pending = Some(HashMap::from([(peer, bfd_params(peer, true))]));
    coupling.reloading = true;
    let began = tokio::time::Instant::now();
    let commit = tokio::spawn(async move {
        mgr.commit_bfd_reload(None).await.unwrap();
        mgr
    });
    reload_rx
        .recv()
        .await
        .unwrap()
        .reply
        .send(vec![down_ack(peer)])
        .unwrap();
    let mut mgr = commit.await.unwrap();
    assert_eq!(
        began.elapsed(),
        Duration::ZERO,
        "full lifecycle queue must not delay the settled reload"
    );
    assert!(mgr.bfd_retry_deadline().is_some());
    let (manager_tx, manager_rx) = mpsc::channel(1);
    mgr.rx = manager_rx;
    let manager = tokio::spawn(mgr.run());
    let (reply, ping) = oneshot::channel();
    readiness_tx
        .send(PeerManagerReadinessQuery::Ping { reply })
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_millis(100), ping)
        .await
        .unwrap()
        .unwrap();
    manager_tx.send(PeerManagerCommand::Shutdown).await.unwrap();
    manager.await.unwrap();
}

#[tokio::test]
async fn bfd_retry_defers_to_queued_opposite_state() {
    let peer: IpAddr = "10.0.0.2".parse().unwrap();
    let counters = Arc::new(BfdCouplingCounters::default());
    let (mut mgr, _) = coupled_mgr(peer, true, fake_bfd_peer_handle(counters.clone()));
    mgr.mark_bfd_withheld(peer);
    mgr.schedule_bfd_retry(peer, true);
    let (changes, mut events) = crate::bfd_runtime::state_change_channel();
    changes.send(down(peer));
    mgr.retry_bfd_commands(Some(&events));
    tokio::task::yield_now().await;
    assert_eq!(counters.start.load(Ordering::SeqCst), 0);
    assert!(mgr.bfd_withholding(&peer));
    mgr.handle_bfd_state_change(events.recv().await.unwrap())
        .await;
    mgr.retry_bfd_commands(Some(&events));
    assert!(mgr.bfd_retry_deadline().is_none());
    assert_eq!(counters.start.load(Ordering::SeqCst), 0);
}

#[tokio::test(start_paused = true)]
async fn bfd_busy_strict_relaxation_retries_initial_start_unless_real_failure() {
    let peer: IpAddr = "10.0.0.2".parse().unwrap();
    for real_failure in [false, true] {
        let (commands, mut receiver) = mpsc::channel(1);
        commands.try_send(PeerCommand::Start).unwrap();
        let (mut mgr, _) = coupled_mgr(
            peer,
            true,
            PeerHandle::from_parts(commands, tokio::spawn(std::future::pending())),
        );
        mgr.mark_bfd_withheld(peer);
        let (reload_tx, mut reload_rx) = mpsc::channel::<crate::bfd_runtime::BfdReloadCommand>(1);
        mgr = mgr.with_bfd_reload(reload_tx);
        let coupling = mgr.bfd_coupling.as_mut().unwrap();
        coupling.pending = Some(HashMap::from([(peer, bfd_params(peer, false))]));
        coupling.reloading = true;
        let actor = tokio::spawn(async move {
            reload_rx
                .recv()
                .await
                .unwrap()
                .reply
                .send(vec![down_ack(peer)])
                .unwrap();
        });
        mgr.commit_bfd_reload(None).await.unwrap();
        actor.await.unwrap();
        // The commit ack and a later unchanged level ack both leave the
        // initial non-strict Start eligible after the busy queue drains.
        mgr.handle_bfd_state_change(down_ack(peer)).await;
        assert!(mgr.bfd_retry_deadline().is_some());
        if real_failure {
            mgr.handle_bfd_state_change(down(peer)).await;
        }
        assert!(matches!(receiver.recv().await, Some(PeerCommand::Start)));
        mgr.retry_bfd_commands(None);
        if real_failure {
            assert!(matches!(receiver.try_recv(), Ok(PeerCommand::BfdDown)));
            assert!(mgr.bfd_withholding(&peer));
        } else {
            assert!(matches!(receiver.try_recv(), Ok(PeerCommand::Start)));
            assert!(!mgr.bfd_withholding(&peer));
        }
    }
}

#[tokio::test(start_paused = true)]
async fn bfd_pending_stop_survives_bfd_revision_change_until_permitted() {
    let peer: IpAddr = "10.0.0.2".parse().unwrap();
    for permits_bgp in [false, true] {
        let (commands, mut receiver) = mpsc::channel(1);
        commands.try_send(PeerCommand::Start).unwrap();
        let (mut mgr, _) = coupled_mgr(
            peer,
            false,
            PeerHandle::from_parts(commands, tokio::spawn(std::future::pending())),
        );
        mgr.handle_bfd_state_change(down(peer)).await;
        assert!(mgr.bfd_retry_deadline().is_some());
        let mut replacement = bfd_params(peer, false);
        replacement.revision = 1;
        replacement.desired_min_tx_us = 500_000;
        let coupling = mgr.bfd_coupling.as_mut().unwrap();
        coupling.pending = Some(HashMap::from([(peer, replacement)]));
        coupling.reloading = true;
        let (reload_tx, mut reload_rx) = mpsc::channel::<crate::bfd_runtime::BfdReloadCommand>(1);
        mgr = mgr.with_bfd_reload(reload_tx);
        let actor = tokio::spawn(async move {
            let mut ack = if permits_bgp {
                up_ack(peer)
            } else {
                down_ack(peer)
            };
            ack.revision = 1;
            reload_rx
                .recv()
                .await
                .unwrap()
                .reply
                .send(vec![ack])
                .unwrap();
        });
        mgr.commit_bfd_reload(None).await.unwrap();
        actor.await.unwrap();
        assert!(matches!(receiver.recv().await, Some(PeerCommand::Start)));
        mgr.retry_bfd_commands(None);
        if permits_bgp {
            assert!(matches!(receiver.try_recv(), Ok(PeerCommand::Start)));
            assert!(!mgr.bfd_withholding(&peer));
        } else {
            assert!(matches!(receiver.try_recv(), Ok(PeerCommand::BfdDown)));
            assert!(mgr.bfd_withholding(&peer));
        }
    }
}

#[tokio::test(start_paused = true)]
async fn bfd_busy_down_up_down_retries_final_stop() {
    let peer: IpAddr = "10.0.0.2".parse().unwrap();
    let (commands, mut receiver) = mpsc::channel(1);
    commands.try_send(PeerCommand::Start).unwrap();
    let (mut mgr, _) = coupled_mgr(
        peer,
        false,
        PeerHandle::from_parts(commands, tokio::spawn(std::future::pending())),
    );
    mgr.handle_bfd_state_change(down(peer)).await;
    mgr.handle_bfd_state_change(up_ack(peer)).await;
    mgr.handle_bfd_state_change(down(peer)).await;
    assert!(matches!(receiver.recv().await, Some(PeerCommand::Start)));
    mgr.retry_bfd_commands(None);
    assert!(matches!(receiver.try_recv(), Ok(PeerCommand::BfdDown)));
    assert!(mgr.bfd_withholding(&peer));
}
