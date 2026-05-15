mod commands;
mod fsm;
mod inbound;
mod io;
mod outbound;
mod writer;

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ops::ControlFlow;
use std::pin::Pin;
use std::time::{Duration, Instant, SystemTime};

use bytes::Bytes;
use rustbgpd_bmp::{BmpEvent, BmpPeerInfo, BmpPeerType, PeerDownReason};
use rustbgpd_fsm::{Action, Event, NegotiatedSession, Session, SessionState};
use rustbgpd_policy::PolicyChain;
use rustbgpd_rib::{EvpnRibRoute, FlowSpecRoute, OutboundRouteUpdate, RibUpdate, Route};
use rustbgpd_telemetry::BgpMetrics;
use rustbgpd_wire::notification::{NotificationCode, cease_subcode};
use rustbgpd_wire::{
    AddPathMode, Afi, AsPath, AsPathSegment, Capability, EvpnRoute, EvpnRouteKey, FlowSpecRule,
    Ipv4NlriEntry, Ipv4UnicastMode, Message, MpReachNlri, MpUnreachNlri, NlriEntry,
    NotificationMessage, PathAttribute, Prefix, RouteRefreshMessage, RouteRefreshSubtype, Safi,
    UpdateMessage, is_private_asn,
};
use tokio::net::TcpStream;
use tokio::net::tcp::OwnedReadHalf;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use tokio::time::Sleep;
use tracing::{debug, error, info, warn};

use crate::config::{RemovePrivateAs, TransportConfig};
use crate::error::TransportError;
use crate::framing::ReadBuffer;
use crate::handle::{PeerCommand, PeerSessionState, SessionIdentity, SessionNotification};
use crate::timer::{Timers, poll_timer};

use self::io::read_tcp;

#[cfg(test)]
use self::fsm::{hard_reset_notification_in_actions, notification_teardown_event};
#[cfg(test)]
use self::outbound::remove_private_asns;

/// Runtime for a single BGP peer session.
///
/// Owns the FSM, TCP stream, timers, and read buffer. Runs as a single
/// tokio task driven by `select!` over TCP reads, timer expirations,
/// and external commands.
#[expect(clippy::struct_excessive_bools)] // Per-session protocol flags are intentionally explicit.
pub(crate) struct PeerSession {
    config: TransportConfig,
    fsm: Session,
    /// Owned read half of the TCP stream — `Some` when the session has
    /// an active TCP connection. The matching write half lives inside
    /// the per-peer writer task, reachable via `writer_bulk_tx` /
    /// `writer_priority_tx`.
    ///
    /// **Lifecycle invariants** (subtle — these three groups are
    /// distinct, see `close_tcp` / `handle_tcp_disconnect` /
    /// `trigger_outbound_saturation_teardown`):
    ///
    /// - **At connect**: `read_half`, both writer senders, and
    ///   `writer_join` are all set together.
    /// - **At teardown**: `read_half` and both writer senders are
    ///   dropped synchronously. `writer_join` is **intentionally
    ///   retained** so the run-loop's writer-exit `select!` arm can
    ///   observe the writer task draining its priority queue (e.g. a
    ///   `Cease/8` we just enqueued) and exiting cleanly. The arm body
    ///   clears `writer_join = None` after `JoinHandle::await` resolves
    ///   exactly once — polling a completed `JoinHandle` again panics.
    /// - **Steady state**: `read_half.is_some() ==
    ///   writer_bulk_tx.is_some() == writer_priority_tx.is_some()`.
    ///   `writer_join` may be `Some` while the others are `None`
    ///   during the brief window between teardown and observed exit.
    read_half: Option<OwnedReadHalf>,
    /// Bounded outbound message channel handed to the writer task.
    /// Bounded by `OUTBOUND_BUFFER`; `try_send` returning `Full` is the
    /// saturation signal that triggers `Cease/8` (Out of Resources,
    /// RFC 4486 §4 subcode 8) + session teardown.
    writer_bulk_tx: Option<mpsc::Sender<Bytes>>,
    /// Unbounded priority channel handed to the writer task. Carries
    /// OPEN, KEEPALIVE, NOTIFICATION, operator ROUTE-REFRESH commands,
    /// and the `Cease/8` we emit on bulk saturation.
    writer_priority_tx: Option<mpsc::UnboundedSender<Bytes>>,
    /// `JoinHandle` of the writer task. Polled by the session's
    /// `select!` so writer-exit (clean shutdown or TCP error) surfaces
    /// as a TCP-disconnect event.
    writer_join: Option<JoinHandle<std::io::Result<()>>>,
    read_buf: ReadBuffer,
    timers: Timers,
    metrics: BgpMetrics,
    commands: mpsc::Receiver<PeerCommand>,
    rib_tx: mpsc::Sender<RibUpdate>,
    peer_label: String,
    peer_ip: IpAddr,
    /// Negotiated session parameters (set when `SessionEstablished`).
    negotiated: Option<NegotiatedSession>,
    /// Address families negotiated via MP-BGP capabilities. Used to filter
    /// inbound `MP_REACH_NLRI` and outbound route advertisements.
    negotiated_families: Vec<(Afi, Safi)>,
    /// Suppresses automatic restart when the FSM transitions to Idle.
    /// Set when the operator sends `ManualStop` or `Shutdown`.
    stop_requested: bool,
    /// Deferred reconnect timer. When the FSM falls to Idle unexpectedly,
    /// this timer fires after the connect-retry interval to avoid a hot
    /// reconnect loop (e.g., persistent OPEN validation failures).
    reconnect_timer: Option<Pin<Box<Sleep>>>,
    /// In-flight outbound TCP connect attempt. Polled by the main event loop
    /// so control commands remain responsive during connection establishment.
    connect_task: Option<JoinHandle<std::io::Result<TcpStream>>>,
    /// Receiver for outbound route updates from the RIB manager.
    outbound_rx: mpsc::Receiver<OutboundRouteUpdate>,
    /// Sender clone held to give to RIB manager on `PeerUp`.
    outbound_tx: mpsc::Sender<OutboundRouteUpdate>,
    /// Import policy (prefix filter applied to inbound UPDATEs).
    import_policy: Option<PolicyChain>,
    /// Export policy (sent to RIB manager on `PeerUp` for per-peer filtering).
    export_policy: Option<PolicyChain>,
    /// RFC 8326 graceful-shutdown initiator toggle: when `true`, every
    /// outbound update gets `COMMUNITY_GRACEFUL_SHUTDOWN` (`0xFFFF_0000`)
    /// added to its Communities attribute (creating one if absent).
    /// Operator-runtime state (set via gRPC, not policy).
    ///
    /// **Authority lives on `ManagedPeer` in `PeerManager`.** This
    /// per-session bool is a mirror — `PeerSession::new` /
    /// `new_inbound` take the desired value as a constructor arg, so
    /// a session restart (collision-replace, inbound-accept,
    /// reconnect after flap) replays the toggle from `ManagedPeer`
    /// and the new session comes up with the correct state. The
    /// daemon-restart case is the only documented loss class
    /// (`KNOWN_ISSUES.md`): operators re-issue `rustbgpctl gshut` after
    /// daemon restart if the maintenance window is still active.
    advertise_graceful_shutdown: bool,
    /// Channel to notify `PeerManager` of session state changes (collision detection).
    /// Unbounded so notifications are never dropped and never block (avoids
    /// deadlock with `QueryState`). Rate is naturally bounded by FSM transitions.
    session_notify_tx: Option<mpsc::UnboundedSender<SessionNotification>>,
    session_identity: SessionIdentity,
    /// Optional BMP event sender (None when BMP not configured).
    bmp_tx: Option<mpsc::Sender<BmpEvent>>,
    /// RPKI/ASPA validation snapshot for import policy evaluation.
    /// `None` when RPKI not configured or in tests.
    validation_rx: Option<watch::Receiver<rustbgpd_rpki::ValidationSnapshot>>,
    /// Cached local OPEN PDU bytes for BMP Peer Up.
    local_open_pdu: Option<Bytes>,
    /// Cached remote OPEN PDU bytes for BMP Peer Up.
    remote_open_pdu: Option<Bytes>,
    /// Last session-down cause for BMP Peer Down reason classification.
    /// Set by `SendNotification` (local) or inbound Notification (remote).
    last_down_reason: Option<PeerDownReason>,
    /// Accepted unicast paths keyed by `(prefix, path_id)`.
    ///
    /// Max-prefix enforcement still counts unique prefixes, so callers must
    /// derive that count from this set instead of using `len()` directly.
    known_paths: HashSet<(Prefix, u32)>,
    /// Accepted `FlowSpec` rules from this peer. Counted toward
    /// max-prefix enforcement so a peer can't bypass the cap by
    /// flooding `FlowSpec` rules.
    known_flowspec: HashSet<FlowSpecRule>,
    /// Accepted EVPN routes from this peer (RFC 7432 keys). Counted
    /// toward max-prefix enforcement for the same reason.
    known_evpn: HashSet<EvpnRouteKey>,
    /// Session counters
    updates_received: u64,
    updates_sent: u64,
    notifications_received: u64,
    notifications_sent: u64,
    flap_count: u64,
    established_at: Option<Instant>,
    last_error: String,
    /// Teardown was triggered by NOTIFICATION semantics (inbound or outbound).
    /// RFC 8538: only preserves routes when Notification GR was negotiated.
    notification_teardown: bool,
    /// RFC 8538: peer sent Cease/Hard Reset — skip GR on this teardown.
    received_hard_reset: bool,
    /// RFC 8538: we sent Cease/Hard Reset — skip GR on this teardown.
    sent_hard_reset: bool,
}

/// Outbound channel buffer size.
const OUTBOUND_BUFFER: usize = 4096;

/// Resolve next-hop for import policy modifications.
///
/// `NextHopAction::Self_` uses the local TCP address (or router-id as fallback).
/// `NextHopAction::Specific` uses the given address.
/// `None` keeps the original next-hop from the UPDATE.
fn resolve_import_nexthop(
    nh_action: Option<&rustbgpd_policy::NextHopAction>,
    original: IpAddr,
    read_half: Option<&OwnedReadHalf>,
    config: &TransportConfig,
) -> IpAddr {
    match nh_action {
        Some(rustbgpd_policy::NextHopAction::Self_) => read_half
            .and_then(|h| h.local_addr().ok())
            .map_or(IpAddr::V4(config.peer.local_router_id), |a| a.ip()),
        Some(rustbgpd_policy::NextHopAction::Specific(addr)) => *addr,
        None => original,
    }
}

impl PeerSession {
    fn local_gr_restart_active(&mut self) -> bool {
        if let Some(deadline) = self.config.gr_restart_until {
            if Instant::now() < deadline {
                return true;
            }
            self.config.gr_restart_until = None;
        }
        false
    }

    fn apply_local_gr_restart_state(&mut self, open: &mut rustbgpd_wire::OpenMessage) {
        let restart_state = self.local_gr_restart_active();
        for capability in &mut open.capabilities {
            if let Capability::GracefulRestart {
                restart_state: r, ..
            } = capability
            {
                *r = restart_state;
            }
        }
    }

    /// Total accepted route count across all negotiated families: unicast
    /// (unique prefixes, ignoring Add-Path multiplicity), `FlowSpec` rules,
    /// and EVPN keys. Used by max-prefix enforcement so a peer can't slip
    /// past the cap by flooding non-unicast NLRI.
    pub(super) fn known_prefix_count(&self) -> usize {
        let unicast: HashSet<Prefix> = self.known_paths.iter().map(|(p, _)| *p).collect();
        unicast.len() + self.known_flowspec.len() + self.known_evpn.len()
    }

    #[cfg(test)]
    #[expect(clippy::too_many_arguments)]
    pub(crate) fn new(
        config: TransportConfig,
        metrics: BgpMetrics,
        commands: mpsc::Receiver<PeerCommand>,
        rib_tx: mpsc::Sender<RibUpdate>,
        import_policy: Option<PolicyChain>,
        export_policy: Option<PolicyChain>,
        session_notify_tx: Option<mpsc::UnboundedSender<SessionNotification>>,
        bmp_tx: Option<mpsc::Sender<BmpEvent>>,
        validation_rx: Option<watch::Receiver<rustbgpd_rpki::ValidationSnapshot>>,
        advertise_graceful_shutdown: bool,
    ) -> Self {
        Self::new_with_identity(
            config,
            metrics,
            commands,
            rib_tx,
            import_policy,
            export_policy,
            session_notify_tx,
            bmp_tx,
            validation_rx,
            advertise_graceful_shutdown,
            SessionIdentity::default(),
        )
    }

    #[expect(clippy::too_many_arguments)]
    pub(crate) fn new_with_identity(
        config: TransportConfig,
        metrics: BgpMetrics,
        commands: mpsc::Receiver<PeerCommand>,
        rib_tx: mpsc::Sender<RibUpdate>,
        import_policy: Option<PolicyChain>,
        export_policy: Option<PolicyChain>,
        session_notify_tx: Option<mpsc::UnboundedSender<SessionNotification>>,
        bmp_tx: Option<mpsc::Sender<BmpEvent>>,
        validation_rx: Option<watch::Receiver<rustbgpd_rpki::ValidationSnapshot>>,
        advertise_graceful_shutdown: bool,
        session_identity: SessionIdentity,
    ) -> Self {
        let peer_label = config.remote_addr.to_string();
        let peer_ip = config.remote_addr.ip();
        let fsm = Session::new(config.peer.clone());
        let (outbound_tx, outbound_rx) = mpsc::channel(OUTBOUND_BUFFER);
        Self {
            config,
            fsm,
            read_half: None,
            writer_bulk_tx: None,
            writer_priority_tx: None,
            writer_join: None,
            read_buf: ReadBuffer::new(),
            timers: Timers::default(),
            metrics,
            commands,
            rib_tx,
            peer_label,
            peer_ip,
            negotiated: None,
            negotiated_families: Vec::new(),
            stop_requested: false,
            reconnect_timer: None,
            connect_task: None,
            outbound_rx,
            outbound_tx,
            import_policy,
            export_policy,
            advertise_graceful_shutdown,
            session_notify_tx,
            session_identity,
            bmp_tx,
            validation_rx,
            local_open_pdu: None,
            remote_open_pdu: None,
            last_down_reason: None,
            known_paths: HashSet::new(),
            known_flowspec: HashSet::new(),
            known_evpn: HashSet::new(),
            updates_received: 0,
            updates_sent: 0,
            notifications_received: 0,
            notifications_sent: 0,
            flap_count: 0,
            established_at: None,
            last_error: String::new(),
            notification_teardown: false,
            received_hard_reset: false,
            sent_hard_reset: false,
        }
    }

    #[expect(clippy::too_many_arguments)]
    pub(crate) fn new_inbound_with_identity(
        config: TransportConfig,
        metrics: BgpMetrics,
        commands: mpsc::Receiver<PeerCommand>,
        rib_tx: mpsc::Sender<RibUpdate>,
        import_policy: Option<PolicyChain>,
        export_policy: Option<PolicyChain>,
        stream: TcpStream,
        session_notify_tx: Option<mpsc::UnboundedSender<SessionNotification>>,
        bmp_tx: Option<mpsc::Sender<BmpEvent>>,
        validation_rx: Option<watch::Receiver<rustbgpd_rpki::ValidationSnapshot>>,
        advertise_graceful_shutdown: bool,
        session_identity: SessionIdentity,
    ) -> Self {
        let peer_label = config.remote_addr.to_string();
        let peer_ip = config.remote_addr.ip();
        let fsm = Session::new(config.peer.clone());
        let (outbound_tx, outbound_rx) = mpsc::channel(OUTBOUND_BUFFER);
        // Split the inbound stream and spawn the writer immediately —
        // we're in async context here (inside `tokio::spawn` from
        // `PeerHandle::spawn_inbound`), so `tokio::spawn` inside
        // `writer::spawn` works.
        let (read_half, write_half) = stream.into_split();
        let writer_handle = writer::spawn(write_half, OUTBOUND_BUFFER);
        Self {
            config,
            fsm,
            read_half: Some(read_half),
            writer_bulk_tx: Some(writer_handle.bulk_tx),
            writer_priority_tx: Some(writer_handle.priority_tx),
            writer_join: Some(writer_handle.join),
            read_buf: ReadBuffer::new(),
            timers: Timers::default(),
            metrics,
            commands,
            rib_tx,
            peer_label,
            peer_ip,
            negotiated: None,
            negotiated_families: Vec::new(),
            stop_requested: false,
            reconnect_timer: None,
            connect_task: None,
            outbound_rx,
            outbound_tx,
            import_policy,
            export_policy,
            advertise_graceful_shutdown,
            session_notify_tx,
            session_identity,
            bmp_tx,
            validation_rx,
            local_open_pdu: None,
            remote_open_pdu: None,
            last_down_reason: None,
            known_paths: HashSet::new(),
            known_flowspec: HashSet::new(),
            known_evpn: HashSet::new(),
            updates_received: 0,
            updates_sent: 0,
            notifications_received: 0,
            notifications_sent: 0,
            flap_count: 0,
            established_at: None,
            last_error: String::new(),
            notification_teardown: false,
            received_hard_reset: false,
            sent_hard_reset: false,
        }
    }

    fn build_bmp_peer_info(&self) -> BmpPeerInfo {
        let is_as4 = self.negotiated.as_ref().is_some_and(|n| n.four_octet_as);
        let peer_bgp_id = self
            .negotiated
            .as_ref()
            .map_or(Ipv4Addr::UNSPECIFIED, |n| n.peer_router_id);
        BmpPeerInfo {
            peer_addr: self.peer_ip,
            peer_asn: self.config.peer.remote_asn,
            peer_bgp_id,
            peer_type: BmpPeerType::Global,
            is_ipv6: self.peer_ip.is_ipv6(),
            is_post_policy: false,
            is_as4,
            timestamp: SystemTime::now(),
        }
    }

    fn emit_bmp_event(&self, event: BmpEvent) {
        if let Some(ref tx) = self.bmp_tx
            && let Err(e) = tx.try_send(event)
        {
            let reason = match e {
                tokio::sync::mpsc::error::TrySendError::Full(_) => "channel_full",
                tokio::sync::mpsc::error::TrySendError::Closed(_) => "channel_closed",
            };
            self.metrics
                .record_bmp_source_drop(&self.peer_label, reason);
            debug!(peer = %self.peer_label, reason, "BMP event channel full or closed");
        }
    }

    /// Main event loop. Runs until Shutdown command or fatal error.
    #[expect(
        clippy::too_many_lines,
        reason = "single select! over 9 arms — splitting hides the dispatch shape"
    )]
    pub(crate) async fn run(&mut self) -> Result<(), TransportError> {
        loop {
            // Destructure to split borrows for tokio::select!
            let Self {
                read_half,
                read_buf,
                timers,
                commands,
                reconnect_timer,
                connect_task,
                outbound_rx,
                writer_join,
                ..
            } = self;

            tokio::select! {
                // TCP read — only when connected
                result = read_tcp(read_half, &mut read_buf.buf), if read_half.is_some() => {
                    match result {
                        Ok(0) => {
                            self.handle_tcp_disconnect();
                            self.drive_fsm(Event::TcpConnectionFails).await;
                        }
                        Ok(_n) => self.process_read_buffer().await,
                        Err(e) => {
                            debug!(peer = %self.peer_label, error = %e, "TCP read error");
                            self.handle_tcp_disconnect();
                            self.drive_fsm(Event::TcpConnectionFails).await;
                        }
                    }
                }

                // External command
                cmd = commands.recv() => {
                    match cmd {
                        Some(cmd) => {
                            if self.handle_command(cmd).await == ControlFlow::Break(()) {
                                return Ok(());
                            }
                        }
                        None => {
                            // All senders dropped — shut down
                            return Ok(());
                        }
                    }
                }

                // Timer fires
                () = poll_timer(&mut timers.connect_retry) => {
                    timers.connect_retry = None;
                    self.drive_fsm(Event::ConnectRetryTimerExpires).await;
                }
                () = poll_timer(&mut timers.hold) => {
                    timers.hold = None;
                    self.drive_fsm(Event::HoldTimerExpires).await;
                }
                () = poll_timer(&mut timers.keepalive) => {
                    timers.keepalive = None;
                    self.drive_fsm(Event::KeepaliveTimerExpires).await;
                }

                // Deferred reconnect after unexpected Idle
                () = poll_timer(reconnect_timer) => {
                    self.reconnect_timer = None;
                    debug!(peer = %self.peer_label, "reconnect timer fired");
                    self.drive_fsm(Event::ManualStart).await;
                }

                // In-flight outbound TCP connect completion
                result = io::poll_connect(connect_task), if connect_task.is_some() => {
                    self.connect_task = None;
                    match result {
                        Ok(Ok(stream)) => {
                            info!(peer = %self.peer_label, "TCP connected");
                            // Split the stream and spawn the writer task.
                            // Read half stays here for the read_tcp arm; the
                            // write half lives inside the writer task,
                            // reachable via the cached bulk_tx/priority_tx
                            // senders.
                            let (rh, wh) = stream.into_split();
                            let handle = writer::spawn(wh, OUTBOUND_BUFFER);
                            self.read_half = Some(rh);
                            self.writer_bulk_tx = Some(handle.bulk_tx);
                            self.writer_priority_tx = Some(handle.priority_tx);
                            self.writer_join = Some(handle.join);
                            self.drive_fsm(Event::TcpConnectionConfirmed).await;
                        }
                        Ok(Err(e)) => {
                            debug!(peer = %self.peer_label, error = %e, "TCP connect failed");
                            self.drive_fsm(Event::TcpConnectionFails).await;
                        }
                        Err(e) => {
                            debug!(peer = %self.peer_label, error = %e, "TCP connect task failed");
                            self.drive_fsm(Event::TcpConnectionFails).await;
                        }
                    }
                }

                // Writer task exit — clean shutdown when both senders
                // dropped (close_tcp / handle_tcp_disconnect did their
                // job), or `Err(io::Error)` when TCP write/flush failed.
                // Either way, treat as TCP-disconnect from the session's
                // perspective. The arm clears `writer_join = None` to
                // prevent the second-poll panic.
                join_result = io::await_writer_join(writer_join), if writer_join.is_some() => {
                    self.writer_join = None;
                    match join_result {
                        Ok(Ok(())) => {
                            debug!(peer = %self.peer_label, "writer task exited cleanly");
                        }
                        Ok(Err(e)) => {
                            debug!(peer = %self.peer_label, error = %e, "writer task TCP error");
                            self.handle_tcp_disconnect();
                            self.drive_fsm(Event::TcpConnectionFails).await;
                        }
                        Err(e) => {
                            warn!(peer = %self.peer_label, error = %e, "writer task panicked");
                            self.handle_tcp_disconnect();
                            self.drive_fsm(Event::TcpConnectionFails).await;
                        }
                    }
                }

                // Outbound route updates from RIB manager
                Some(update) = outbound_rx.recv(),
                    if self.fsm.state() == SessionState::Established => {
                    self.send_route_update(update);
                }
            }
        }
    }
}

#[cfg(test)]
impl PeerSession {
    /// Test-only: install an already-connected `TcpStream` by splitting
    /// it into halves and spawning the writer task. Replaces direct
    /// `session.stream = Some(client)` assignments from the
    /// pre-writer-split test scaffolding.
    pub(super) fn test_install_stream(&mut self, stream: TcpStream) {
        let (rh, wh) = stream.into_split();
        let handle = writer::spawn(wh, OUTBOUND_BUFFER);
        self.read_half = Some(rh);
        self.writer_bulk_tx = Some(handle.bulk_tx);
        self.writer_priority_tx = Some(handle.priority_tx);
        self.writer_join = Some(handle.join);
    }
}

#[cfg(test)]
mod tests;
