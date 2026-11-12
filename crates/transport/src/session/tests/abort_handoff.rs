//! A session task that is cancelled (a bounded shutdown that ran out its
//! deadline, a transport-safety abort) still retires its session in the RIB:
//! the RIB-bound messages it held, then a `PeerDown` for an Established
//! epoch it never closed, in session order.
//!
//! The RIB here is a real `RibManager` behind a relay the test forwards by
//! hand, so "the RIB mailbox is full" is a state the test holds rather than
//! a race, and the clock is paused, so the shutdown deadline is exact.
use super::run_loop::negotiate_graceful_restart;
use super::*;
use crate::{PeerHandle, PeerShutdownError};

const RELAY: usize = 64;
const SHUTDOWN_BOUND: Duration = Duration::from_millis(500);

fn first() -> Ipv4Prefix {
    Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 0), 24)
}
fn second() -> Ipv4Prefix {
    Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24)
}

struct GatedRib {
    relay_tx: mpsc::Sender<RibUpdate>,
    relay_rx: mpsc::Receiver<RibUpdate>,
    rib_tx: mpsc::Sender<RibUpdate>,
    metrics: BgpMetrics,
    /// Session-end messages forwarded to the RIB so far, in order.
    ends: Vec<(&'static str, u64)>,
    /// Every forwarded message from a session, as `(kind, session id)`.
    forwarded: Vec<(&'static str, u64)>,
    /// Every message forwarded through the relay other than its fillers.
    from_sessions: usize,
    /// Session ends forwarded as `LateSessionEnd`.
    late_ends: usize,
}

impl GatedRib {
    fn spawn() -> Self {
        let (relay_tx, relay_rx) = mpsc::channel(RELAY);
        let (rib_tx, rib_rx) = mpsc::channel(RELAY);
        let (_query_tx, query_rx) = mpsc::channel(8);
        let metrics = BgpMetrics::new();
        tokio::spawn(
            rustbgpd_rib::RibManager::new(rib_rx, query_rx, None, None, metrics.clone()).run(),
        );
        Self {
            relay_tx,
            relay_rx,
            rib_tx,
            metrics,
            ends: Vec::new(),
            forwarded: Vec::new(),
            from_sessions: 0,
            late_ends: 0,
        }
    }

    /// Stop draining: every relay slot is taken, as when the RIB actor is
    /// inside one long turn.
    fn hold_full(&self) {
        while self
            .relay_tx
            .try_send(placeholder_routes_received())
            .is_ok()
        {}
    }

    /// Forward everything the senders can deliver. The paused clock only
    /// advances once every task is idle, so the timeout is the handshake
    /// for "nothing further is coming", not a wall-clock wait.
    async fn release(&mut self) {
        while let Ok(Some(update)) =
            tokio::time::timeout(Duration::from_millis(10), self.relay_rx.recv()).await
        {
            let late = matches!(&update, RibUpdate::LateSessionEnd(_));
            self.late_ends += usize::from(late);
            let seen = match match &update {
                RibUpdate::LateSessionEnd(end) => end.as_ref(),
                update => update,
            } {
                RibUpdate::PeerUp { session_id, .. } => Some(("PeerUp", *session_id)),
                RibUpdate::PeerDown { session_id, .. } => Some(("PeerDown", *session_id)),
                RibUpdate::PeerGracefulRestart { session_id, .. } => {
                    Some(("PeerGracefulRestart", *session_id))
                }
                RibUpdate::RoutesReceived { session_id, .. } if *session_id != 0 => {
                    Some(("RoutesReceived", *session_id))
                }
                _ => None,
            };
            self.from_sessions += usize::from(!matches!(
                &update,
                RibUpdate::RoutesReceived { session_id: 0, .. }
            ));
            if let Some(seen) = seen {
                self.forwarded.push(seen);
                if seen.0 == "PeerDown" || seen.0 == "PeerGracefulRestart" {
                    self.ends.push(seen);
                }
            }
            self.rib_tx.send(update).await.unwrap();
        }
    }

    /// Free one relay slot, as a RIB that handles one message and stalls
    /// again.
    async fn forward_one(&mut self) {
        let update = self.relay_rx.recv().await.unwrap();
        self.rib_tx.send(update).await.unwrap();
    }

    /// What the sessions delivered since `mark`, as `(kind, session id)`.
    fn forwarded_since(&self, mark: usize) -> &[(&'static str, u64)] {
        &self.forwarded[mark..]
    }

    fn stale_teardowns_ignored(&self, peer: PeerId) -> f64 {
        counter_value(
            &self.metrics,
            "bgp_rib_stale_peer_down_ignored_total",
            &peer.label(),
        )
    }

    /// Loc-RIB size once the RIB has handled everything forwarded so far.
    async fn loc_rib_count(&self) -> usize {
        let (reply, count) = oneshot::channel();
        self.rib_tx
            .send(RibUpdate::QueryLocRibCount { reply })
            .await
            .unwrap();
        count.await.unwrap()
    }

    async fn retained_stale(&self, peer: PeerId) -> usize {
        let (reply, count) = oneshot::channel();
        self.rib_tx
            .send(RibUpdate::QueryPeerRetainedStale { peer, reply })
            .await
            .unwrap();
        count.await.unwrap()
    }

    fn failovers(&self, peer: PeerId) -> f64 {
        counter_value(
            &self.metrics,
            "bgp_rib_outbound_registration_failover_total",
            &peer.label(),
        )
    }
}

/// An Established session `id` for the one test peer, delivering to `rib`
/// through the relay.
async fn established(
    rib: &GatedRib,
    id: u64,
) -> (PeerSession, mpsc::Sender<PeerCommand>, TcpStream) {
    established_on(rib.relay_tx.clone(), id, None).await
}

/// An Established session `id` delivering to `rib_tx`, under the neighbor's
/// allocated RIB handle when it has one.
async fn established_on(
    rib_tx: mpsc::Sender<RibUpdate>,
    id: u64,
    rib_peer: Option<PeerId>,
) -> (PeerSession, mpsc::Sender<PeerCommand>, TcpStream) {
    established_superseding(rib_tx, id, rib_peer, None).await
}

/// As [`established_on`], spawned as the replacement of the retired
/// session `supersedes`.
async fn established_superseding(
    rib_tx: mpsc::Sender<RibUpdate>,
    id: u64,
    rib_peer: Option<PeerId>,
    supersedes: Option<u64>,
) -> (PeerSession, mpsc::Sender<PeerCommand>, TcpStream) {
    let mut peer_config = PeerConfig::new(65001, 65002, Ipv4Addr::new(10, 0, 0, 1));
    peer_config.connect_retry_secs = 30;
    peer_config.families = vec![(Afi::Ipv4, Safi::Unicast)];
    peer_config.gr_restart_time = 120;
    let mut config = TransportConfig::new(peer_config, "10.0.0.2:179".parse().unwrap());
    config.supersedes_session = supersedes;
    if let Some(peer) = rib_peer {
        config.rib_peer = crate::RibPeerSlot::assigned(peer);
    }
    let (commands, command_rx) = mpsc::channel(8);
    let mut session = PeerSession::new_with_identity_and_lifecycle(
        config,
        BgpMetrics::new(),
        command_rx,
        rib_tx,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        false,
        SessionIdentity::primary(id),
    );
    let (client, server) = connected_stream_pair().await;
    session.test_install_stream(client);
    establish_test_session(&mut session, 65002).await;
    (session, commands, server)
}

/// Graceful restart for IPv4 unicast with a restart time the test's clock
/// never reaches, so retention ends only by a message.
fn negotiate_restart(session: &mut PeerSession) {
    negotiate_graceful_restart(session, false);
    let mut negotiated = (*session.negotiated.clone().unwrap()).clone();
    negotiated.peer_restart_time = 120;
    session.negotiated = Some(Arc::new(negotiated));
}

fn receive(session: &mut PeerSession, prefix: Ipv4Prefix) {
    session.read_buf.buf.extend_from_slice(
        &rustbgpd_wire::encode_message(&Message::Update(ipv4_announce(prefix, 0, false))).unwrap(),
    );
}

async fn tcp_fails(session: &mut PeerSession) {
    session.handle_tcp_disconnect();
    session.drive_fsm(Event::TcpConnectionFails).await;
}

/// Own the session as production does: a task that runs it and drops it.
fn owned(session: PeerSession, commands: mpsc::Sender<PeerCommand>) -> PeerHandle {
    PeerHandle::from_parts(
        commands,
        tokio::spawn(async move {
            let mut session = session;
            session.run().await
        }),
    )
}

/// The bounded shutdown runs out its whole deadline, then aborts the task.
async fn shutdown_times_out(handle: PeerHandle) {
    let started = tokio::time::Instant::now();
    let outcome = handle.shutdown_timeout(SHUTDOWN_BOUND).await;
    assert!(
        matches!(outcome, Err(PeerShutdownError::TimedOut { .. })),
        "the shutdown must run out its deadline behind the full RIB: {outcome:?}"
    );
    assert_eq!(started.elapsed(), SHUTDOWN_BOUND);
}

/// The reported sequence. The RIB mailbox is full when S1's TCP fails, so
/// S1's `PeerDown` is held; the replacement path shuts S1 down within the
/// 500 ms bound, which expires and aborts the task. The RIB must still see
/// S1 end: its route is withdrawn although no replacement has established,
/// and once S2 establishes and later goes down under graceful restart, S2's
/// routes are retained as stale instead of the registration failing over to
/// the dead S1.
/// Mutation-red: with the aborted task's held messages dropped, no
/// `PeerDown{1}` arrives, S1's route stays installed, and S2's teardown
/// fails over (one failover, nothing retained).
#[tokio::test(start_paused = true)]
async fn aborted_shutdown_behind_a_full_rib_still_retires_the_session() {
    let mut rib = GatedRib::spawn();
    let (mut s1, s1_commands, _s1_peer) = established(&rib, 1).await;
    let peer = s1.rib_peer();
    receive(&mut s1, first());
    s1.process_read_buffer().await;
    rib.release().await;
    assert_eq!(rib.loc_rib_count().await, 1, "S1's route is installed");

    rib.hold_full();
    tcp_fails(&mut s1).await;
    assert!(
        matches!(
            s1.rib_backlog.back(),
            Some((RibUpdate::PeerDown { session_id: 1, .. }, _))
        ),
        "S1's PeerDown is held for the full RIB"
    );
    shutdown_times_out(owned(s1, s1_commands)).await;

    rib.release().await;
    let s1_ends = rib.ends.clone();
    assert_eq!(rib.late_ends, 1, "the hand-off marks the held end as late");
    let routes_after_s1 = rib.loc_rib_count().await;

    let (mut s2, _s2_commands, _s2_peer) = established(&rib, 2).await;
    negotiate_restart(&mut s2);
    receive(&mut s2, second());
    s2.process_read_buffer().await;
    rib.release().await;
    assert_eq!(rib.loc_rib_count().await, 1, "only S2's route is installed");
    tcp_fails(&mut s2).await;
    rib.release().await;

    assert_eq!(
        (
            s1_ends,
            routes_after_s1,
            rib.failovers(peer),
            rib.retained_stale(peer).await,
        ),
        (vec![("PeerDown", 1)], 0, 0.0, 1),
        "(S1 session ends delivered, routes left after S1 ended, \
         failovers on S2's teardown, S2 routes retained as stale)"
    );
}

/// Held route updates with no session end behind them: the session is
/// Established and parked on an UPDATE when its task is aborted without a
/// command, as the TCP-AO fail-closed path does. The held UPDATE is
/// delivered first, then the `PeerDown` the session never got to queue.
/// Mutation-red: without the hand-off neither arrives and the session stays
/// registered; a `PeerDown` delivered ahead of the held UPDATE breaks the
/// session order asserted here.
#[tokio::test(start_paused = true)]
async fn abort_while_parked_delivers_held_routes_then_closes_the_epoch() {
    let mut rib = GatedRib::spawn();
    let (mut s1, s1_commands, _s1_peer) = established(&rib, 1).await;
    rib.release().await;
    rib.hold_full();
    receive(&mut s1, first());
    s1.process_read_buffer().await;
    assert_eq!(s1.rib_backlog.len(), 1, "the UPDATE is held");
    let mark = rib.forwarded.len();

    owned(s1, s1_commands)
        .abort_for_transport_safety_and_wait()
        .await;
    rib.release().await;

    assert_eq!(
        rib.forwarded_since(mark),
        [("RoutesReceived", 1), ("PeerDown", 1)]
    );
    assert_eq!(rib.loc_rib_count().await, 0);
}

/// Nothing held at the abort: an idle Established session aborted with the
/// non-waiting call the TCP-AO rotation uses still closes its epoch, and
/// with room in the RIB channel it does so in the drop itself.
/// Mutation-red: without the `PeerDown` for the open epoch the aborted
/// session's route stays installed.
#[tokio::test(start_paused = true)]
async fn abort_of_an_idle_established_session_closes_its_epoch() {
    let mut rib = GatedRib::spawn();
    let (mut s1, s1_commands, _s1_peer) = established(&rib, 1).await;
    receive(&mut s1, first());
    s1.process_read_buffer().await;
    rib.release().await;
    assert_eq!(rib.loc_rib_count().await, 1);

    let handle = owned(s1, s1_commands);
    handle.abort_for_transport_safety();
    rib.release().await;

    assert_eq!(rib.ends, [("PeerDown", 1)]);
    assert_eq!(rib.late_ends, 1, "the drop's own PeerDown is marked late");
    assert_eq!(rib.loc_rib_count().await, 0);
}

/// A graceful-restart end held at the abort is delivered as it was queued:
/// the routes are retained as the session's capabilities say, and no
/// `PeerDown` follows it to purge them.
/// Mutation-red: without the hand-off nothing is retained as stale;
/// closing the epoch again after the held end purges the retained route.
#[tokio::test(start_paused = true)]
async fn held_graceful_restart_end_is_delivered_and_retains_the_routes() {
    let mut rib = GatedRib::spawn();
    let (mut s1, s1_commands, _s1_peer) = established(&rib, 1).await;
    let peer = s1.rib_peer();
    negotiate_restart(&mut s1);
    receive(&mut s1, first());
    s1.process_read_buffer().await;
    rib.release().await;

    rib.hold_full();
    tcp_fails(&mut s1).await;
    shutdown_times_out(owned(s1, s1_commands)).await;
    rib.release().await;

    assert_eq!(rib.ends, [("PeerGracefulRestart", 1)]);
    assert_eq!(rib.retained_stale(peer).await, 1);
}

/// A session that already ended in the RIB adds nothing when its task is
/// aborted later: its retained routes stay retained.
/// Mutation-red: a `PeerDown` on every drop, whether or not an epoch is
/// open, purges the routes graceful restart retained.
#[tokio::test(start_paused = true)]
async fn abort_after_the_session_ended_adds_no_second_end() {
    let mut rib = GatedRib::spawn();
    let (mut s1, s1_commands, _s1_peer) = established(&rib, 1).await;
    let peer = s1.rib_peer();
    negotiate_restart(&mut s1);
    receive(&mut s1, first());
    s1.process_read_buffer().await;
    tcp_fails(&mut s1).await;
    rib.release().await;
    assert_eq!(rib.retained_stale(peer).await, 1);

    owned(s1, s1_commands)
        .abort_for_transport_safety_and_wait()
        .await;
    rib.release().await;

    assert_eq!(rib.ends, [("PeerGracefulRestart", 1)]);
    assert_eq!(rib.retained_stale(peer).await, 1);
}

/// An orderly shutdown that the RIB admits in time delivers its session end
/// once: the drop that follows a returned run loop has no epoch to close.
/// Mutation-red: a `PeerDown` on every drop delivers two.
#[tokio::test(start_paused = true)]
async fn orderly_shutdown_delivers_one_session_end() {
    let mut rib = GatedRib::spawn();
    let (s1, s1_commands, _s1_peer) = established(&rib, 1).await;
    rib.release().await;

    let outcome = owned(s1, s1_commands)
        .shutdown_timeout(Duration::from_secs(5))
        .await;
    assert!(matches!(outcome, Ok(Ok(()))), "{outcome:?}");
    rib.release().await;

    assert_eq!(rib.ends, [("PeerDown", 1)]);
    assert_eq!(rib.late_ends, 0, "a session's own end is not marked late");
}

/// The replacement registers before the aborted session's held `PeerDown`
/// is admitted. The RIB prunes the old session and discards its teardown:
/// the replacement keeps its route, and its own graceful-restart end later
/// retains it instead of failing over to the dead session.
/// Mutation-red: without the hand-off the old session is never pruned, so
/// the replacement's teardown fails over and retains nothing.
#[tokio::test(start_paused = true)]
async fn late_teardown_after_the_replacement_registered_leaves_it_untouched() {
    let mut rib = GatedRib::spawn();
    let (mut s1, s1_commands, _s1_peer) = established(&rib, 1).await;
    let peer = s1.rib_peer();
    receive(&mut s1, first());
    s1.process_read_buffer().await;
    rib.release().await;
    rib.hold_full();
    tcp_fails(&mut s1).await;
    shutdown_times_out(owned(s1, s1_commands)).await;

    // The replacement's messages reach the RIB ahead of the held tail.
    let (mut s2, _s2_commands, _s2_peer) = established_on(rib.rib_tx.clone(), 2, None).await;
    negotiate_restart(&mut s2);
    receive(&mut s2, second());
    s2.process_read_buffer().await;
    assert_eq!(rib.loc_rib_count().await, 1, "only S2's route is installed");

    rib.release().await;
    assert_eq!(rib.ends, [("PeerDown", 1)]);
    assert_eq!(rib.loc_rib_count().await, 1, "S2's route is untouched");
    tcp_fails(&mut s2).await;
    assert_eq!(
        (
            rib.stale_teardowns_ignored(peer),
            rib.retained_stale(peer).await,
            rib.failovers(peer),
        ),
        (1.0, 1, 0.0),
        "(stale teardowns discarded, S2 routes retained as stale, failovers)"
    );
}

/// The neighbor is deleted and re-added while the aborted session's tail is
/// still held. The tail names the deleted neighbor's released handle, so
/// the re-added neighbor's session keeps its route and is not told of a
/// stale teardown. This pins the RIB contract the late delivery relies on;
/// on its own the hand-off cannot break it, so it is red without the
/// hand-off only at "the held tail was delivered".
#[tokio::test(start_paused = true)]
async fn late_teardown_after_the_neighbor_was_deleted_is_dropped() {
    let endpoint = || rustbgpd_rib::PeerEndpoint::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), None);
    let mut rib = GatedRib::spawn();
    let deleted = PeerId::allocate(endpoint());
    let (mut s1, s1_commands, _s1_peer) =
        established_on(rib.relay_tx.clone(), 1, Some(deleted)).await;
    receive(&mut s1, first());
    s1.process_read_buffer().await;
    rib.release().await;
    assert_eq!(rib.loc_rib_count().await, 1);
    rib.hold_full();
    tcp_fails(&mut s1).await;
    shutdown_times_out(owned(s1, s1_commands)).await;

    // The delete path's own messages, then the re-added neighbor.
    for update in [
        RibUpdate::PeerDeleted {
            peer: deleted,
            label: None,
            keep_series: false,
        },
        RibUpdate::ReleasePeer { peer: deleted },
    ] {
        rib.rib_tx.send(update).await.unwrap();
    }
    assert_eq!(
        rib.loc_rib_count().await,
        0,
        "the deletion clears the route"
    );
    let readded = PeerId::allocate(endpoint());
    let (mut s3, _s3_commands, _s3_peer) =
        established_on(rib.rib_tx.clone(), 3, Some(readded)).await;
    receive(&mut s3, second());
    s3.process_read_buffer().await;
    assert_eq!(rib.loc_rib_count().await, 1);

    rib.release().await;
    assert_eq!(rib.ends, [("PeerDown", 1)], "the held tail was delivered");
    assert_eq!(rib.loc_rib_count().await, 1, "S3's route is untouched");
    assert_eq!(rib.stale_teardowns_ignored(readded), 0.0);
}

/// One RIB slot frees while the closing session flushes, then the RIB
/// stalls again: the held UPDATE is admitted and the `PeerDown` behind it is
/// waiting for its own slot when the shutdown bound aborts the task. It is
/// still held, not lost with the cancelled wait.
/// Mutation-red: a flush that takes a message out of the backlog before its
/// slot is reserved drops the `PeerDown` with the cancelled send.
#[tokio::test(start_paused = true)]
async fn slot_freed_mid_flush_keeps_the_session_end_held() {
    let mut rib = GatedRib::spawn();
    let (mut s1, s1_commands, _s1_peer) = established(&rib, 1).await;
    rib.release().await;
    rib.hold_full();
    receive(&mut s1, first());
    s1.process_read_buffer().await;
    tcp_fails(&mut s1).await;
    assert_eq!(s1.rib_backlog.len(), 2, "the UPDATE, then PeerDown");
    let mark = rib.forwarded.len();

    let handle = owned(s1, s1_commands);
    tokio::join!(shutdown_times_out(handle), rib.forward_one());
    rib.release().await;

    assert_eq!(
        rib.forwarded_since(mark),
        [("RoutesReceived", 1), ("PeerDown", 1)]
    );
    assert_eq!(rib.loc_rib_count().await, 0);
}

/// Daemon shutdown while a hand-off is pending: once the RIB actor is gone
/// the hand-off task ends and releases its sender, instead of holding the
/// channel open behind messages nothing will read.
/// Mutation-red: a hand-off that keeps waiting after the channel closes
/// keeps its sender alive.
#[tokio::test(start_paused = true)]
async fn pending_hand_off_ends_when_the_rib_is_gone() {
    let (rib_tx, rib_rx) = mpsc::channel(RELAY);
    let (mut s1, s1_commands, _s1_peer) = established_on(rib_tx.clone(), 1, None).await;
    assert!(s1.rib_backlog.is_empty(), "PeerUp was admitted");
    while rib_tx.try_send(placeholder_routes_received()).is_ok() {}
    receive(&mut s1, first());
    s1.process_read_buffer().await;
    assert_eq!(s1.rib_backlog.len(), 1, "the UPDATE is held");
    let senders = rib_tx.downgrade();
    drop(rib_tx);

    owned(s1, s1_commands)
        .abort_for_transport_safety_and_wait()
        .await;
    assert!(
        senders.upgrade().is_some(),
        "the hand-off holds the aborted session's messages"
    );
    drop(rib_rx);
    // Paused clock: this elapses only once every task is idle.
    tokio::time::sleep(Duration::from_millis(10)).await;
    assert!(senders.upgrade().is_none(), "the hand-off task has ended");
}

/// The session established while the RIB mailbox was full, so its `PeerUp`
/// was never admitted, and a successor registered before the task was
/// aborted. Nothing of the unseen epoch is delivered, neither the context
/// staged ahead of the `PeerUp` nor the epoch's end: a late `PeerUp` would
/// replace the successor's registration and reset the route it installed.
/// Mutation-red: delivering the whole backlog replaces the successor's
/// registration, and the `PeerDown` behind it then fails over.
#[tokio::test(start_paused = true)]
async fn held_peer_up_is_dropped_with_everything_behind_it() {
    let mut rib = GatedRib::spawn();
    let (mut s2, _s2_commands, _s2_peer) = established_on(rib.rib_tx.clone(), 2, None).await;
    let peer = s2.rib_peer();
    receive(&mut s2, second());
    s2.process_read_buffer().await;
    assert_eq!(rib.loc_rib_count().await, 1, "S2's route is installed");

    rib.hold_full();
    let (s1, s1_commands, _s1_peer) = established(&rib, 1).await;
    assert!(
        s1.rib_backlog
            .iter()
            .any(|(update, _)| matches!(update, RibUpdate::PeerUp { .. })),
        "S1 holds its PeerUp, with its staged context ahead of it"
    );
    assert!(
        s2.established.registered() && !s1.established.registered(),
        "only a PeerUp the RIB admitted marks its session registered"
    );
    owned(s1, s1_commands)
        .abort_for_transport_safety_and_wait()
        .await;
    rib.release().await;

    assert_eq!(
        (
            rib.from_sessions,
            rib.loc_rib_count().await,
            rib.failovers(peer),
            counter_value(
                &rib.metrics,
                "bgp_rib_outbound_registration_replaced_total",
                &peer.label(),
            ),
        ),
        (0, 1, 0.0, 0.0),
        "(messages from S1 delivered, routes installed, failovers, replaced registrations)"
    );
}

/// An earlier epoch's end held ahead of a held `PeerUp` is still delivered:
/// only the epoch the RIB never saw is dropped.
/// Mutation-red: dropping the whole backlog when it holds a `PeerUp` loses
/// the earlier epoch's `PeerDown` and leaves its route installed.
#[tokio::test(start_paused = true)]
async fn end_of_an_earlier_epoch_ahead_of_a_held_peer_up_is_delivered() {
    let mut rib = GatedRib::spawn();
    let (mut s1, s1_commands, _s1_peer) = established(&rib, 1).await;
    receive(&mut s1, first());
    s1.process_read_buffer().await;
    rib.release().await;
    assert_eq!(rib.loc_rib_count().await, 1);

    rib.hold_full();
    tcp_fails(&mut s1).await;
    let (client, _s1_peer_again) = connected_stream_pair().await;
    s1.test_install_stream(client);
    establish_test_session(&mut s1, 65002).await;
    let mark = rib.forwarded.len();
    owned(s1, s1_commands)
        .abort_for_transport_safety_and_wait()
        .await;
    rib.release().await;

    assert_eq!(rib.forwarded_since(mark), [("PeerDown", 1)]);
    assert_eq!(rib.loc_rib_count().await, 0);
}

/// A BMP channel that never drains does not hold the teardown: the TCP fails
/// and the session end reaches the RIB without waiting for BMP room. A
/// transport-safety abort (an unacknowledged TCP-AO reset) afterwards finds
/// no open epoch and adds no second end.
/// Mutation-red: a teardown that waits for BMP room before queueing its
/// session end reaches the RIB only through the abort's drop.
#[tokio::test(start_paused = true)]
async fn full_bmp_channel_does_not_hold_the_teardown() {
    let mut rib = GatedRib::spawn();
    let (mut s1, s1_commands, _s1_peer) = established(&rib, 1).await;
    receive(&mut s1, first());
    s1.process_read_buffer().await;
    rib.release().await;
    assert_eq!(rib.loc_rib_count().await, 1);

    let (bmp_tx, _bmp_rx) = mpsc::channel(1);
    bmp_tx.try_send(s1.build_bmp_peer_up_event()).unwrap();
    s1.bmp_tx = Some(bmp_tx);
    let handle = PeerHandle::from_parts(
        s1_commands,
        tokio::spawn(async move {
            tcp_fails(&mut s1).await;
            s1.run().await
        }),
    );
    rib.release().await;
    assert_eq!(rib.ends, [("PeerDown", 1)], "the teardown reached the RIB");
    assert_eq!(rib.loc_rib_count().await, 0);

    handle.abort_for_transport_safety();
    rib.release().await;
    assert_eq!(rib.ends, [("PeerDown", 1)], "no second end");
}

/// The aborted session's end is still behind the full relay when its
/// replacement establishes and goes down under graceful restart. `named`
/// is whether the replacement was spawned naming the session it replaces.
/// Returns `(failovers, replacement routes retained after its restart end,
/// retained once the old session's late end has drained)`.
async fn replacement_ends_before_the_aborted_sessions_end(named: bool) -> (f64, usize, usize) {
    let mut rib = GatedRib::spawn();
    let (mut s1, s1_commands, _s1_peer) = established(&rib, 1).await;
    let peer = s1.rib_peer();
    receive(&mut s1, first());
    s1.process_read_buffer().await;
    rib.release().await;
    assert_eq!(rib.loc_rib_count().await, 1, "S1's route is installed");

    rib.hold_full();
    tcp_fails(&mut s1).await;
    shutdown_times_out(owned(s1, s1_commands)).await;

    // The replacement reaches the RIB while S1's end is still held.
    let (mut s2, _s2_commands, _s2_peer) =
        established_superseding(rib.rib_tx.clone(), 2, Some(peer), named.then_some(1)).await;
    negotiate_restart(&mut s2);
    receive(&mut s2, second());
    s2.process_read_buffer().await;
    assert_eq!(rib.loc_rib_count().await, 1, "only S2's route is installed");
    tcp_fails(&mut s2).await;
    let retained = rib.retained_stale(peer).await;

    rib.release().await;
    assert_eq!(rib.ends, [("PeerDown", 1)]);
    assert_eq!(rib.late_ends, 1);
    (
        rib.failovers(peer),
        retained,
        rib.retained_stale(peer).await,
    )
}

/// A replacement that names the session it supersedes is not failed over
/// to it: its routes are retained under graceful restart, and the aborted
/// session's late `PeerDown` leaves them retained.
/// Mutation-red: with the session not sending the id it was spawned with,
/// this is the unnamed case below.
#[tokio::test(start_paused = true)]
async fn named_replacement_retains_ahead_of_the_aborted_sessions_end() {
    assert_eq!(
        Box::pin(replacement_ends_before_the_aborted_sessions_end(true)).await,
        (0.0, 1, 1)
    );
}

/// Without the name the RIB cannot tell the replacement from a collision
/// and keeps the collision handling: the restart end fails over to the
/// session that is already gone and nothing is retained.
#[tokio::test(start_paused = true)]
async fn unnamed_second_session_keeps_the_collision_failover() {
    assert_eq!(
        Box::pin(replacement_ends_before_the_aborted_sessions_end(false)).await,
        (1.0, 0, 0)
    );
}

/// A `PeerUp` held behind a full RIB channel outlives the session's own
/// teardown: the session goes down while it is held, and the RIB admits it
/// afterwards, with the `PeerDown` behind it. The session did register, so
/// a replacement must name it.
/// Mutation-red: with every held admission action cleared at teardown the
/// session is never marked registered and a replacement names nothing.
#[tokio::test(start_paused = true)]
async fn peer_up_admitted_after_the_sessions_teardown_still_marks_it_registered() {
    let mut rib = GatedRib::spawn();
    rib.hold_full();
    let (mut s1, _s1_commands, _s1_peer) = established(&rib, 1).await;
    assert!(
        s1.rib_backlog
            .iter()
            .any(|(update, _)| matches!(update, RibUpdate::PeerUp { .. })),
        "S1 holds its PeerUp"
    );
    tcp_fails(&mut s1).await;
    assert!(!s1.established.registered());
    assert_eq!(s1.established.rib_registration_owner(1), None);
    let mark = rib.forwarded.len();

    tokio::join!(s1.flush_rib_backlog(), rib.release());
    assert_eq!(rib.forwarded_since(mark), [("PeerUp", 1), ("PeerDown", 1)]);
    assert!(s1.established.registered());
    assert_eq!(s1.established.rib_registration_owner(1), Some(1));
}
