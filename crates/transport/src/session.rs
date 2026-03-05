use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ops::ControlFlow;
use std::pin::Pin;
use std::time::{Duration, Instant, SystemTime};

use bytes::Bytes;
use rustbgpd_bmp::{BmpEvent, BmpPeerInfo, BmpPeerType, PeerDownReason};
use rustbgpd_fsm::{Action, Event, NegotiatedSession, Session, SessionState};
use rustbgpd_policy::PolicyChain;
use rustbgpd_rib::{FlowSpecRoute, OutboundRouteUpdate, RibUpdate, Route};
use rustbgpd_telemetry::BgpMetrics;
use rustbgpd_wire::notification::{NotificationCode, cease_subcode};
use rustbgpd_wire::{
    AddPathMode, Afi, AsPath, AsPathSegment, Capability, FlowSpecRule, Ipv4NlriEntry,
    Ipv4UnicastMode, Message, MpReachNlri, MpUnreachNlri, NlriEntry, NotificationMessage,
    PathAttribute, Prefix, RouteRefreshMessage, RouteRefreshSubtype, Safi, UpdateMessage,
};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::time::Sleep;
use tracing::{debug, error, info, warn};

use crate::config::TransportConfig;
use crate::error::TransportError;
use crate::framing::ReadBuffer;
use crate::handle::{PeerCommand, PeerSessionState, SessionNotification};
use crate::timer::{Timers, poll_timer};

/// Runtime for a single BGP peer session.
///
/// Owns the FSM, TCP stream, timers, and read buffer. Runs as a single
/// tokio task driven by `select!` over TCP reads, timer expirations,
/// and external commands.
pub(crate) struct PeerSession {
    config: TransportConfig,
    fsm: Session,
    stream: Option<TcpStream>,
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
    /// Receiver for outbound route updates from the RIB manager.
    outbound_rx: mpsc::Receiver<OutboundRouteUpdate>,
    /// Sender clone held to give to RIB manager on `PeerUp`.
    outbound_tx: mpsc::Sender<OutboundRouteUpdate>,
    /// Import policy (prefix filter applied to inbound UPDATEs).
    import_policy: Option<PolicyChain>,
    /// Export policy (sent to RIB manager on `PeerUp` for per-peer filtering).
    export_policy: Option<PolicyChain>,
    /// Channel to notify `PeerManager` of session state changes (collision detection).
    /// Unbounded so notifications are never dropped and never block (avoids
    /// deadlock with `QueryState`). Rate is naturally bounded by FSM transitions.
    session_notify_tx: Option<mpsc::UnboundedSender<SessionNotification>>,
    /// Optional BMP event sender (None when BMP not configured).
    bmp_tx: Option<mpsc::Sender<BmpEvent>>,
    /// Cached local OPEN PDU bytes for BMP Peer Up.
    local_open_pdu: Option<Bytes>,
    /// Cached remote OPEN PDU bytes for BMP Peer Up.
    remote_open_pdu: Option<Bytes>,
    /// Last session-down cause for BMP Peer Down reason classification.
    /// Set by `SendNotification` (local) or inbound Notification (remote).
    last_down_reason: Option<PeerDownReason>,
    /// Accepted paths keyed by `(prefix, path_id)`.
    ///
    /// Max-prefix enforcement still counts unique prefixes, so callers must
    /// derive that count from this set instead of using `len()` directly.
    known_paths: HashSet<(Prefix, u32)>,
    /// Session counters
    updates_received: u64,
    updates_sent: u64,
    notifications_received: u64,
    notifications_sent: u64,
    flap_count: u64,
    established_at: Option<Instant>,
    last_error: String,
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
    stream: Option<&TcpStream>,
    config: &TransportConfig,
) -> IpAddr {
    match nh_action {
        Some(rustbgpd_policy::NextHopAction::Self_) => stream
            .and_then(|s| s.local_addr().ok())
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

    fn known_prefix_count(&self) -> usize {
        self.known_paths
            .iter()
            .map(|(prefix, _)| *prefix)
            .collect::<HashSet<_>>()
            .len()
    }

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
    ) -> Self {
        let peer_label = config.remote_addr.to_string();
        let peer_ip = config.remote_addr.ip();
        let fsm = Session::new(config.peer.clone());
        let (outbound_tx, outbound_rx) = mpsc::channel(OUTBOUND_BUFFER);
        Self {
            config,
            fsm,
            stream: None,
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
            outbound_rx,
            outbound_tx,
            import_policy,
            export_policy,
            session_notify_tx,
            bmp_tx,
            local_open_pdu: None,
            remote_open_pdu: None,
            last_down_reason: None,
            known_paths: HashSet::new(),
            updates_received: 0,
            updates_sent: 0,
            notifications_received: 0,
            notifications_sent: 0,
            flap_count: 0,
            established_at: None,
            last_error: String::new(),
        }
    }

    /// Create a session for an inbound (already-connected) TCP stream.
    #[expect(clippy::too_many_arguments)]
    pub(crate) fn new_inbound(
        config: TransportConfig,
        metrics: BgpMetrics,
        commands: mpsc::Receiver<PeerCommand>,
        rib_tx: mpsc::Sender<RibUpdate>,
        import_policy: Option<PolicyChain>,
        export_policy: Option<PolicyChain>,
        stream: TcpStream,
        session_notify_tx: Option<mpsc::UnboundedSender<SessionNotification>>,
        bmp_tx: Option<mpsc::Sender<BmpEvent>>,
    ) -> Self {
        let peer_label = config.remote_addr.to_string();
        let peer_ip = config.remote_addr.ip();
        let fsm = Session::new(config.peer.clone());
        let (outbound_tx, outbound_rx) = mpsc::channel(OUTBOUND_BUFFER);
        Self {
            config,
            fsm,
            stream: Some(stream),
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
            outbound_rx,
            outbound_tx,
            import_policy,
            export_policy,
            session_notify_tx,
            bmp_tx,
            local_open_pdu: None,
            remote_open_pdu: None,
            last_down_reason: None,
            known_paths: HashSet::new(),
            updates_received: 0,
            updates_sent: 0,
            notifications_received: 0,
            notifications_sent: 0,
            flap_count: 0,
            established_at: None,
            last_error: String::new(),
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
            debug!(peer = %self.peer_label, error = %e, "BMP event channel full or closed");
        }
    }

    /// Main event loop. Runs until Shutdown command or fatal error.
    pub(crate) async fn run(&mut self) -> Result<(), TransportError> {
        loop {
            // Destructure to split borrows for tokio::select!
            let Self {
                stream,
                read_buf,
                timers,
                commands,
                reconnect_timer,
                outbound_rx,
                ..
            } = self;

            tokio::select! {
                // TCP read — only when connected
                result = read_tcp(stream, &mut read_buf.buf), if stream.is_some() => {
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

                // Outbound route updates from RIB manager
                Some(update) = outbound_rx.recv(),
                    if self.fsm.state() == SessionState::Established => {
                    self.send_route_update(update).await;
                }
            }
        }
    }

    /// Feed an event into the FSM and execute the resulting actions.
    ///
    /// Uses an iterative loop to avoid async recursion: actions that
    /// produce follow-up events (like TCP connect or send failure)
    /// queue them for the next iteration.
    async fn drive_fsm(&mut self, initial_event: Event) {
        let mut pending = vec![initial_event];

        while let Some(event) = pending.pop() {
            debug!(
                peer = %self.peer_label,
                state = %self.fsm.state(),
                event = event.name(),
                "FSM event"
            );
            let actions = self.fsm.handle_event(event);
            let follow_up = self.execute_actions(actions).await;
            pending.extend(follow_up);
        }
    }

    /// Execute a batch of FSM actions, returning any follow-up events.
    ///
    /// Follow-up events arise from TCP connect results and send failures.
    #[expect(clippy::too_many_lines)]
    async fn execute_actions(&mut self, actions: Vec<Action>) -> Vec<Event> {
        let mut follow_up = Vec::new();

        for action in actions {
            match action {
                Action::SendOpen(mut open) => {
                    self.apply_local_gr_restart_state(&mut open);
                    let msg = Message::Open(open);
                    // Cache raw OPEN PDU for BMP Peer Up
                    if self.bmp_tx.is_some()
                        && let Ok(encoded) = rustbgpd_wire::encode_message(&msg)
                    {
                        self.local_open_pdu = Some(Bytes::from(encoded));
                    }
                    if let Err(e) = self.send_message(&msg).await {
                        warn!(peer = %self.peer_label, error = %e, "failed to send OPEN");
                        self.handle_tcp_disconnect();
                        follow_up.push(Event::TcpConnectionFails);
                        return follow_up;
                    }
                    self.metrics.record_message_sent(&self.peer_label, "open");
                }
                Action::SendKeepalive => {
                    if let Err(e) = self.send_message(&Message::Keepalive).await {
                        warn!(peer = %self.peer_label, error = %e, "failed to send KEEPALIVE");
                        self.handle_tcp_disconnect();
                        follow_up.push(Event::TcpConnectionFails);
                        return follow_up;
                    }
                    self.metrics
                        .record_message_sent(&self.peer_label, "keepalive");
                }
                Action::SendNotification(notif) => {
                    let code = notif.code;
                    let subcode = notif.subcode;
                    let msg = Message::Notification(notif);
                    // Cache raw NOTIFICATION PDU for BMP Peer Down (reason 1: local sent NOTIFICATION)
                    if self.bmp_tx.is_some()
                        && let Ok(encoded) = rustbgpd_wire::encode_message(&msg)
                    {
                        self.last_down_reason =
                            Some(PeerDownReason::LocalNotification(Bytes::from(encoded)));
                    }
                    if let Err(e) = self.send_message(&msg).await {
                        warn!(peer = %self.peer_label, error = %e, "failed to send NOTIFICATION");
                        // Continue — we're tearing down anyway
                    }
                    self.notifications_sent += 1;
                    self.metrics.record_notification_sent(
                        &self.peer_label,
                        &code.as_u8().to_string(),
                        &subcode.to_string(),
                    );
                    self.metrics
                        .record_message_sent(&self.peer_label, "notification");
                }
                Action::StartTimer(timer_type, secs) => {
                    debug!(
                        peer = %self.peer_label,
                        timer = ?timer_type,
                        secs,
                        "start timer"
                    );
                    self.timers.start(timer_type, secs);
                }
                Action::StopTimer(timer_type) => {
                    debug!(peer = %self.peer_label, timer = ?timer_type, "stop timer");
                    self.timers.stop(timer_type);
                }
                Action::InitiateTcpConnection => {
                    if let Some(event) = self.attempt_connect().await {
                        follow_up.push(event);
                    }
                }
                Action::CloseTcpConnection => {
                    self.close_tcp();
                }
                Action::StateChanged { old, new } => {
                    info!(
                        peer = %self.peer_label,
                        from = old.as_str(),
                        to = new.as_str(),
                        "session state changed"
                    );
                    self.metrics.record_state_transition(
                        &self.peer_label,
                        old.as_str(),
                        new.as_str(),
                    );

                    // Notify PeerManager for collision detection.
                    // Read from the FSM's negotiated (set at OpenConfirm),
                    // not self.negotiated (set later at SessionEstablished).
                    // Uses unbounded channel so notifications are never dropped
                    // and never block (avoids deadlock with QueryState).
                    if let Some(ref notify_tx) = self.session_notify_tx {
                        if new == SessionState::OpenConfirm
                            && let Some(neg) = self.fsm.negotiated()
                            && let Err(e) = notify_tx.send(SessionNotification::OpenReceived {
                                peer_addr: self.peer_ip,
                                remote_router_id: neg.peer_router_id,
                            })
                        {
                            warn!(
                                peer = %self.peer_label,
                                error = %e,
                                "failed to send OpenReceived notification"
                            );
                        } else if new == SessionState::Idle
                            && let Err(e) = notify_tx.send(SessionNotification::BackToIdle {
                                peer_addr: self.peer_ip,
                            })
                        {
                            warn!(
                                peer = %self.peer_label,
                                error = %e,
                                "failed to send BackToIdle notification"
                            );
                        }
                    }

                    // Auto-restart: when the FSM falls back to Idle after
                    // a connection failure (not operator-initiated), start
                    // a deferred reconnect timer. This avoids a hot loop
                    // when the peer persistently fails (e.g., ASN mismatch).
                    if new == SessionState::Idle && !self.stop_requested {
                        let delay = self.config.peer.connect_retry_secs;
                        debug!(peer = %self.peer_label, delay_secs = delay, "scheduling reconnect");
                        self.reconnect_timer = Some(Box::pin(tokio::time::sleep(
                            Duration::from_secs(u64::from(delay)),
                        )));
                    }
                }
                Action::SessionEstablished(neg) => {
                    info!(
                        peer = %self.peer_label,
                        peer_asn = neg.peer_asn,
                        hold_time = neg.hold_time,
                        keepalive_interval = neg.keepalive_interval,
                        four_octet_as = neg.four_octet_as,
                        "session established"
                    );
                    self.negotiated_families
                        .clone_from(&neg.negotiated_families);

                    // Compute sendable families: start from negotiated,
                    // then for eBGP remove IPv6 unicast if no valid
                    // IPv6 next-hop is available.
                    let is_ebgp = neg.peer_asn != self.config.peer.local_asn;
                    let sendable_families = if is_ebgp {
                        let local_ipv6 = self
                            .stream
                            .as_ref()
                            .and_then(|s| s.local_addr().ok())
                            .and_then(|a| match a.ip() {
                                IpAddr::V6(v6) => Some(v6),
                                IpAddr::V4(_) => None,
                            });
                        let has_v6_nh = self
                            .config
                            .local_ipv6_nexthop
                            .or(local_ipv6)
                            .filter(rustbgpd_wire::is_valid_ipv6_nexthop)
                            .is_some();
                        neg.negotiated_families
                            .iter()
                            .filter(|f| {
                                **f != (Afi::Ipv6, Safi::Unicast)
                                    || has_v6_nh
                                    || self.config.route_server_client
                            })
                            .copied()
                            .collect()
                    } else {
                        neg.negotiated_families.clone()
                    };

                    // If Extended Messages was negotiated, increase the
                    // framing buffer limit from 4096 to 65535 (RFC 8654).
                    if neg.peer_extended_message {
                        self.read_buf
                            .set_max_message_len(rustbgpd_wire::EXTENDED_MAX_MESSAGE_LEN);
                    }

                    // Compute the families for which we may send Add-Path.
                    // The wire layer handles Add-Path per family; the RIB
                    // receives the negotiated family set and applies the
                    // configured send_max only to those families.
                    let add_path_send_families: Vec<(Afi, Safi)> = neg
                        .add_path_families
                        .iter()
                        .filter_map(|(family, mode)| {
                            if matches!(mode, AddPathMode::Send | AddPathMode::Both) {
                                Some(*family)
                            } else {
                                None
                            }
                        })
                        .filter(|family| sendable_families.contains(family))
                        .collect();
                    let add_path_send_max =
                        if self.config.peer.add_path_send && !add_path_send_families.is_empty() {
                            let max = self.config.peer.add_path_send_max;
                            if max == 0 { u32::MAX } else { max }
                        } else {
                            0
                        };

                    self.negotiated = Some(neg);
                    self.established_at = Some(Instant::now());

                    // Emit BMP Peer Up event
                    if self.bmp_tx.is_some() {
                        let (local_addr, local_port, remote_port) = self.stream.as_ref().map_or(
                            (IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0, 0),
                            |s| {
                                let local = s.local_addr().ok();
                                let remote = s.peer_addr().ok();
                                (
                                    local.map_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED), |a| a.ip()),
                                    local.map_or(0, |a| a.port()),
                                    remote.map_or(0, |a| a.port()),
                                )
                            },
                        );
                        self.emit_bmp_event(BmpEvent::PeerUp {
                            peer_info: self.build_bmp_peer_info(),
                            local_open: self.local_open_pdu.clone().unwrap_or_default(),
                            remote_open: self.remote_open_pdu.clone().unwrap_or_default(),
                            local_addr,
                            local_port,
                            remote_port,
                        });
                    }

                    // Register with RIB manager for outbound updates
                    let _ = self.rib_tx.try_send(RibUpdate::PeerUp {
                        peer: self.peer_ip,
                        outbound_tx: self.outbound_tx.clone(),
                        export_policy: self.export_policy.clone(),
                        sendable_families,
                        is_ebgp,
                        route_reflector_client: self.config.route_reflector_client,
                        add_path_send_families,
                        add_path_send_max,
                    });
                }
                Action::SessionDown => {
                    info!(peer = %self.peer_label, "session down");

                    // Emit BMP Peer Down event before clearing state
                    if self.bmp_tx.is_some() && self.established_at.is_some() {
                        let reason = self
                            .last_down_reason
                            .take()
                            .unwrap_or(PeerDownReason::RemoteNoNotification);
                        self.emit_bmp_event(BmpEvent::PeerDown {
                            peer_info: self.build_bmp_peer_info(),
                            reason,
                        });
                    }

                    // Check GR state before clearing negotiated info.
                    // RFC 4724 §4.2: retain routes if the peer previously
                    // advertised Graceful Restart capability and our config
                    // enables GR.  The R-bit is NOT checked here — it
                    // indicates restart state in the NEW OPEN, not the dying
                    // session.  All families from the peer's GR capability
                    // are retained (not just forwarding-preserved ones).
                    let gr_update = self.negotiated.as_ref().and_then(|neg| {
                        if neg.peer_gr_capable && self.config.peer.graceful_restart {
                            let gr_families: Vec<(Afi, Safi)> = neg
                                .peer_gr_families
                                .iter()
                                .map(|f| (f.afi, f.safi))
                                .collect();
                            Some(RibUpdate::PeerGracefulRestart {
                                peer: self.peer_ip,
                                restart_time: neg.peer_restart_time,
                                stale_routes_time: self.config.gr_stale_routes_time,
                                gr_families,
                                peer_llgr_capable: neg.peer_llgr_capable,
                                peer_llgr_families: neg.peer_llgr_families.clone(),
                                llgr_stale_time: self.config.llgr_stale_time,
                            })
                        } else {
                            None
                        }
                    });

                    self.negotiated = None;
                    self.negotiated_families.clear();
                    self.known_paths.clear();
                    self.local_open_pdu = None;
                    self.remote_open_pdu = None;
                    self.last_down_reason = None;
                    // Reset framing limit for the next session (RFC 8654 §2:
                    // extended messages are per-session, not persistent).
                    self.read_buf
                        .set_max_message_len(rustbgpd_wire::MAX_MESSAGE_LEN);
                    if self.established_at.take().is_some() {
                        self.flap_count += 1;
                    }

                    // Recreate outbound channel to discard stale updates
                    // from the dying session. The old sender held by RIB
                    // manager is already invalidated by PeerDown/PeerGR.
                    let (new_tx, new_rx) = mpsc::channel(OUTBOUND_BUFFER);
                    self.outbound_tx = new_tx;
                    self.outbound_rx = new_rx;

                    let rib_msg = gr_update.unwrap_or(RibUpdate::PeerDown { peer: self.peer_ip });
                    let _ = self.rib_tx.try_send(rib_msg);
                }
            }
        }

        follow_up
    }

    /// Encode and send a BGP message to the peer.
    async fn send_message(&mut self, msg: &Message) -> Result<(), TransportError> {
        let max_len = self.max_message_len();
        let encoded = rustbgpd_wire::encode_message_with_limit(msg, max_len)?;
        if let Some(stream) = self.stream.as_mut() {
            stream.write_all(&encoded).await?;
            stream.flush().await?;
            Ok(())
        } else {
            debug!(
                peer = %self.peer_label,
                msg_type = %msg.message_type(),
                "cannot send — not connected"
            );
            Ok(())
        }
    }

    /// Attempt an outbound TCP connection with timeout.
    ///
    /// If a stream is already connected (inbound session), return
    /// `TcpConnectionConfirmed` immediately without connecting.
    ///
    /// Uses `socket2` to create the socket so that MD5 and GTSM options can be
    /// applied before connecting.
    async fn attempt_connect(&mut self) -> Option<Event> {
        // Inbound session: stream already connected
        if self.stream.is_some() {
            debug!(peer = %self.peer_label, "already connected (inbound)");
            return Some(Event::TcpConnectionConfirmed);
        }

        debug!(peer = %self.peer_label, addr = %self.config.remote_addr, "connecting");

        match tokio::time::timeout(self.config.connect_timeout, self.create_and_connect()).await {
            Ok(Ok(stream)) => {
                info!(peer = %self.peer_label, "TCP connected");
                self.stream = Some(stream);
                Some(Event::TcpConnectionConfirmed)
            }
            Ok(Err(e)) => {
                debug!(peer = %self.peer_label, error = %e, "TCP connect failed");
                Some(Event::TcpConnectionFails)
            }
            Err(_elapsed) => {
                debug!(peer = %self.peer_label, "TCP connect timed out");
                Some(Event::TcpConnectionFails)
            }
        }
    }

    /// Create a socket with MD5/GTSM options and connect to the peer.
    async fn create_and_connect(&self) -> std::io::Result<TcpStream> {
        use socket2::{Domain, Protocol, SockAddr, Type};

        let domain = if self.config.remote_addr.is_ipv4() {
            Domain::IPV4
        } else {
            Domain::IPV6
        };

        let socket = socket2::Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;

        // Apply MD5 authentication before connect
        if let Some(ref password) = self.config.md5_password {
            crate::socket_opts::set_tcp_md5sig(&socket, self.config.remote_addr, password)?;
            debug!(peer = %self.peer_label, "TCP MD5 authentication configured");
        }

        // Apply GTSM / TTL security before connect
        if self.config.ttl_security {
            crate::socket_opts::set_gtsm(&socket)?;
            debug!(peer = %self.peer_label, "GTSM / TTL security configured");
        }

        socket.set_nonblocking(true)?;

        let addr = SockAddr::from(self.config.remote_addr);
        match socket.connect(&addr) {
            Ok(()) => {}
            Err(e) if e.raw_os_error() == Some(libc::EINPROGRESS) => {}
            Err(e) => return Err(e),
        }

        let std_stream: std::net::TcpStream = socket.into();
        let stream = TcpStream::from_std(std_stream)?;

        // Wait for connection to complete
        stream.writable().await?;

        // Check for connection errors
        if let Some(err) = stream.take_error()? {
            return Err(err);
        }

        Ok(stream)
    }

    /// Drop the TCP stream and clear the read buffer.
    fn close_tcp(&mut self) {
        if self.stream.take().is_some() {
            debug!(peer = %self.peer_label, "TCP connection closed");
        }
        self.read_buf.clear();
    }

    /// Clear TCP state after disconnect or error.
    fn handle_tcp_disconnect(&mut self) {
        debug!(peer = %self.peer_label, "TCP disconnected");
        self.stream = None;
        self.read_buf.clear();
    }

    /// Drain complete messages from the read buffer and feed to FSM.
    #[expect(clippy::too_many_lines)]
    async fn process_read_buffer(&mut self) {
        loop {
            match self.read_buf.try_decode() {
                Ok(Some((msg, raw_pdu))) => {
                    let event = match msg {
                        Message::Open(open) => {
                            // Cache raw OPEN PDU for BMP Peer Up
                            if self.bmp_tx.is_some() {
                                self.remote_open_pdu = Some(raw_pdu);
                            }
                            self.metrics
                                .record_message_received(&self.peer_label, "open");
                            let gr_cap_count = open
                                .capabilities
                                .iter()
                                .filter(|c| {
                                    matches!(c, rustbgpd_wire::Capability::GracefulRestart { .. })
                                })
                                .count();
                            if gr_cap_count > 1 {
                                warn!(
                                    peer = %self.peer_label,
                                    count = gr_cap_count,
                                    "peer sent multiple Graceful Restart capabilities, using first"
                                );
                            }
                            Event::OpenReceived(open)
                        }
                        Message::Keepalive => {
                            self.metrics
                                .record_message_received(&self.peer_label, "keepalive");
                            Event::KeepaliveReceived
                        }
                        Message::Notification(notif) => {
                            // Cache raw NOTIFICATION PDU for BMP Peer Down (reason 3: remote sent NOTIFICATION)
                            if self.bmp_tx.is_some() {
                                self.last_down_reason =
                                    Some(PeerDownReason::RemoteNotification(raw_pdu.clone()));
                            }
                            self.notifications_received += 1;
                            self.last_error = format!("{}/{}", notif.code.as_u8(), notif.subcode);
                            self.metrics.record_notification_received(
                                &self.peer_label,
                                &notif.code.as_u8().to_string(),
                                &notif.subcode.to_string(),
                            );
                            self.metrics
                                .record_message_received(&self.peer_label, "notification");
                            // Log shutdown communication reason (RFC 8203)
                            if notif.code == NotificationCode::Cease
                                && (notif.subcode == cease_subcode::ADMINISTRATIVE_SHUTDOWN
                                    || notif.subcode == cease_subcode::ADMINISTRATIVE_RESET)
                                && let Some(reason) =
                                    rustbgpd_wire::notification::decode_shutdown_communication(
                                        &notif.data,
                                    )
                            {
                                info!(
                                    peer = %self.peer_label,
                                    reason = %reason,
                                    "peer sent shutdown communication"
                                );
                            }
                            Event::NotificationReceived(notif)
                        }
                        Message::Update(update) => {
                            self.updates_received += 1;
                            self.metrics
                                .record_message_received(&self.peer_label, "update");
                            // Emit BMP RouteMonitoring with raw UPDATE PDU
                            if self.bmp_tx.is_some() {
                                self.emit_bmp_event(BmpEvent::RouteMonitoring {
                                    peer_info: self.build_bmp_peer_info(),
                                    update_pdu: raw_pdu,
                                });
                            }
                            self.process_update(update).await;
                            continue;
                        }
                        Message::RouteRefresh(rr) => {
                            self.metrics
                                .record_message_received(&self.peer_label, "route_refresh");
                            // Check peer advertised Route Refresh capability
                            let peer_rr = self
                                .negotiated
                                .as_ref()
                                .is_some_and(|n| n.peer_route_refresh);
                            if !peer_rr {
                                warn!(
                                    peer = %self.peer_label,
                                    "ignoring ROUTE-REFRESH from peer without capability"
                                );
                                continue;
                            }
                            // Resolve typed AFI/SAFI — ignore unknown families
                            let (Some(afi), Some(safi)) = (rr.afi(), rr.safi()) else {
                                warn!(
                                    peer = %self.peer_label,
                                    afi_raw = rr.afi_raw,
                                    safi_raw = rr.safi_raw,
                                    "ignoring ROUTE-REFRESH for unknown AFI/SAFI"
                                );
                                continue;
                            };
                            // Ignore requests for unnegotiated families
                            if !self.negotiated_families.contains(&(afi, safi)) {
                                warn!(
                                    peer = %self.peer_label,
                                    ?afi, ?safi,
                                    "ignoring ROUTE-REFRESH for unnegotiated family"
                                );
                                continue;
                            }
                            match rr.subtype() {
                                RouteRefreshSubtype::Normal => {
                                    info!(
                                        peer = %self.peer_label,
                                        ?afi, ?safi,
                                        "received ROUTE-REFRESH"
                                    );
                                    if self
                                        .rib_tx
                                        .try_send(RibUpdate::RouteRefreshRequest {
                                            peer: self.peer_ip,
                                            afi,
                                            safi,
                                        })
                                        .is_err()
                                    {
                                        warn!(
                                            peer = %self.peer_label,
                                            "RIB channel full — route refresh request dropped"
                                        );
                                    }
                                }
                                RouteRefreshSubtype::BoRR => {
                                    let peer_err_capable = self
                                        .negotiated
                                        .as_ref()
                                        .is_some_and(|n| n.peer_enhanced_route_refresh);
                                    if !peer_err_capable {
                                        warn!(
                                            peer = %self.peer_label,
                                            ?afi, ?safi,
                                            "ignoring BoRR from peer without Enhanced Route Refresh"
                                        );
                                    } else if self
                                        .rib_tx
                                        .try_send(RibUpdate::BeginRouteRefresh {
                                            peer: self.peer_ip,
                                            afi,
                                            safi,
                                        })
                                        .is_err()
                                    {
                                        warn!(
                                            peer = %self.peer_label,
                                            "RIB channel full — BeginRouteRefresh dropped"
                                        );
                                    } else {
                                        info!(
                                            peer = %self.peer_label,
                                            ?afi, ?safi,
                                            "received Beginning-of-RIB-Refresh"
                                        );
                                    }
                                }
                                RouteRefreshSubtype::EoRR => {
                                    let peer_err_capable = self
                                        .negotiated
                                        .as_ref()
                                        .is_some_and(|n| n.peer_enhanced_route_refresh);
                                    if !peer_err_capable {
                                        warn!(
                                            peer = %self.peer_label,
                                            ?afi, ?safi,
                                            "ignoring EoRR from peer without Enhanced Route Refresh"
                                        );
                                    } else if self
                                        .rib_tx
                                        .try_send(RibUpdate::EndRouteRefresh {
                                            peer: self.peer_ip,
                                            afi,
                                            safi,
                                        })
                                        .is_err()
                                    {
                                        warn!(
                                            peer = %self.peer_label,
                                            "RIB channel full — EndRouteRefresh dropped"
                                        );
                                    } else {
                                        info!(
                                            peer = %self.peer_label,
                                            ?afi, ?safi,
                                            "received End-of-RIB-Refresh"
                                        );
                                    }
                                }
                                RouteRefreshSubtype::Unknown(subtype) => {
                                    warn!(
                                        peer = %self.peer_label,
                                        ?afi,
                                        ?safi,
                                        subtype,
                                        "ignoring ROUTE-REFRESH with unknown subtype"
                                    );
                                }
                            }
                            Event::RouteRefreshReceived { afi, safi }
                        }
                    };
                    self.drive_fsm(event).await;
                }
                Ok(None) => break, // need more data
                Err(e) => {
                    error!(
                        peer = %self.peer_label,
                        error = %e,
                        "decode error"
                    );
                    self.drive_fsm(Event::DecodeError(e)).await;
                    break;
                }
            }
        }
    }

    /// Check whether a prefix's address family is among the negotiated families.
    /// Negotiated maximum message length: 65535 if Extended Messages was
    /// negotiated, otherwise 4096.
    fn max_message_len(&self) -> u16 {
        if self
            .negotiated
            .as_ref()
            .is_some_and(|n| n.peer_extended_message)
        {
            rustbgpd_wire::EXTENDED_MAX_MESSAGE_LEN
        } else {
            rustbgpd_wire::MAX_MESSAGE_LEN
        }
    }

    fn is_family_negotiated(&self, prefix: &Prefix) -> bool {
        let family = match prefix {
            Prefix::V4(_) => (Afi::Ipv4, Safi::Unicast),
            Prefix::V6(_) => (Afi::Ipv6, Safi::Unicast),
        };
        self.negotiated_families.contains(&family)
    }

    fn use_extended_nexthop_ipv4(&self) -> bool {
        self.negotiated.as_ref().is_some_and(|n| {
            n.extended_nexthop_families
                .get(&(Afi::Ipv4, Safi::Unicast))
                .is_some_and(|afi| *afi == Afi::Ipv6)
        })
    }

    /// Parse an UPDATE message, validate attributes, apply import policy,
    /// enforce max-prefix limit, send routes to RIB, and feed the
    /// appropriate event to the FSM.
    #[expect(clippy::too_many_lines)]
    async fn process_update(&mut self, update: rustbgpd_wire::UpdateMessage) {
        let four_octet_as = self.negotiated.as_ref().is_some_and(|n| n.four_octet_as);

        // Build Add-Path receive families for MP attribute decode context.
        let add_path_recv_families: Vec<(Afi, Safi)> = self
            .negotiated
            .as_ref()
            .map(|n| {
                n.add_path_families
                    .iter()
                    .filter(|(_, m)| {
                        matches!(
                            m,
                            rustbgpd_wire::AddPathMode::Receive | rustbgpd_wire::AddPathMode::Both
                        )
                    })
                    .map(|(&family, _)| family)
                    .collect()
            })
            .unwrap_or_default();

        // Check if Add-Path receive is negotiated for IPv4 unicast (body NLRI)
        let add_path_ipv4 = add_path_recv_families.contains(&(Afi::Ipv4, Safi::Unicast));

        // 1. Structural decode
        let parsed = match update.parse(four_octet_as, add_path_ipv4, &add_path_recv_families) {
            Ok(p) => p,
            Err(e) => {
                warn!(peer = %self.peer_label, error = %e, "UPDATE decode error");
                self.drive_fsm(Event::DecodeError(e)).await;
                return;
            }
        };

        // 2. Semantic validation
        let has_mp_nlri = parsed
            .attributes
            .iter()
            .any(|a| matches!(a, PathAttribute::MpReachNlri(_)));
        let has_body_nlri = !parsed.announced.is_empty();
        let has_nlri = has_body_nlri || has_mp_nlri;
        let is_ebgp = self
            .negotiated
            .as_ref()
            .is_some_and(|n| n.peer_asn != self.config.peer.local_asn);

        if let Err(update_err) = rustbgpd_wire::validate::validate_update_attributes(
            &parsed.attributes,
            has_nlri,
            has_body_nlri,
            is_ebgp,
        ) {
            warn!(
                peer = %self.peer_label,
                subcode = update_err.subcode,
                "UPDATE validation error"
            );
            let notif = NotificationMessage::new(
                NotificationCode::UpdateMessage,
                update_err.subcode,
                bytes::Bytes::from(update_err.data),
            );
            self.drive_fsm(Event::UpdateValidationError(notif)).await;
            return;
        }

        // 3. End-of-RIB detection (RFC 4724 §2)
        if parsed.announced.is_empty() && parsed.withdrawn.is_empty() {
            // IPv4 EoR: empty UPDATE (no NLRI, no withdrawn, no attributes)
            if parsed.attributes.is_empty() {
                info!(peer = %self.peer_label, family = "ipv4_unicast", "received End-of-RIB");
                let _ = self.rib_tx.try_send(RibUpdate::EndOfRib {
                    peer: self.peer_ip,
                    afi: Afi::Ipv4,
                    safi: Safi::Unicast,
                });
                self.drive_fsm(Event::UpdateReceived).await;
                return;
            }
            // MP EoR: UPDATE with only an empty MP_UNREACH_NLRI (IPv6 unicast, FlowSpec, etc.)
            if parsed.attributes.len() == 1
                && let Some(PathAttribute::MpUnreachNlri(mp)) = parsed.attributes.first()
                && mp.withdrawn.is_empty()
                && mp.flowspec_withdrawn.is_empty()
            {
                info!(
                    peer = %self.peer_label,
                    afi = ?mp.afi,
                    safi = ?mp.safi,
                    "received End-of-RIB"
                );
                let _ = self.rib_tx.try_send(RibUpdate::EndOfRib {
                    peer: self.peer_ip,
                    afi: mp.afi,
                    safi: mp.safi,
                });
                self.drive_fsm(Event::UpdateReceived).await;
                return;
            }
        }

        // 4. Build routes from body NLRI (IPv4) and MP-BGP NLRI
        let body_next_hop: IpAddr = parsed
            .attributes
            .iter()
            .find_map(|a| {
                if let PathAttribute::NextHop(nh) = a {
                    Some(IpAddr::V4(*nh))
                } else {
                    None
                }
            })
            .unwrap_or(match self.peer_ip {
                IpAddr::V4(v4) => IpAddr::V4(v4),
                IpAddr::V6(_) => IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
            });

        let now = Instant::now();
        let route_origin = if is_ebgp {
            rustbgpd_rib::RouteOrigin::Ebgp
        } else {
            rustbgpd_rib::RouteOrigin::Ibgp
        };

        // AS_PATH loop detection (RFC 4271 §9.1.2): discard all
        // announcements if our local ASN appears in the AS_PATH.
        // Withdrawals are still processed normally.
        let as_path_loop = parsed.attributes.iter().any(|a| {
            if let PathAttribute::AsPath(as_path) = a {
                as_path.contains_asn(self.config.peer.local_asn)
            } else {
                false
            }
        });
        if as_path_loop {
            // Count rejected announced prefixes (body NLRI + MP_REACH_NLRI)
            let rejected_count = parsed.announced.len()
                + parsed
                    .attributes
                    .iter()
                    .filter_map(|a| match a {
                        PathAttribute::MpReachNlri(mp) => Some(mp.announced.len()),
                        _ => None,
                    })
                    .sum::<usize>();
            debug!(
                peer = %self.peer_label,
                local_asn = self.config.peer.local_asn,
                rejected = rejected_count,
                "AS_PATH loop detected — discarding announcements"
            );
            self.metrics
                .record_as_path_loop_detected(&self.peer_label, rejected_count as u64);

            // Still process withdrawals (body + MP_UNREACH with negotiated-family check)
            let mut loop_withdrawn: Vec<(Prefix, u32)> = parsed
                .withdrawn
                .iter()
                .map(|e| (Prefix::V4(e.prefix), e.path_id))
                .collect();
            let mut loop_fs_withdrawn: Vec<FlowSpecRule> = Vec::new();
            for attr in &parsed.attributes {
                if let PathAttribute::MpUnreachNlri(mp) = attr {
                    let family = (mp.afi, mp.safi);
                    if self.negotiated_families.contains(&family) {
                        loop_withdrawn.extend(mp.withdrawn.iter().map(|e| (e.prefix, e.path_id)));
                        loop_fs_withdrawn.extend(mp.flowspec_withdrawn.iter().cloned());
                    }
                }
            }
            for &(prefix, path_id) in &loop_withdrawn {
                self.known_paths.remove(&(prefix, path_id));
            }
            if !loop_withdrawn.is_empty() || !loop_fs_withdrawn.is_empty() {
                let _ = self.rib_tx.try_send(RibUpdate::RoutesReceived {
                    peer: self.peer_ip,
                    announced: vec![],
                    withdrawn: loop_withdrawn,
                    flowspec_announced: vec![],
                    flowspec_withdrawn: loop_fs_withdrawn,
                });
            }
            self.drive_fsm(Event::UpdateReceived).await;
            return;
        }

        // Route reflector loop detection (RFC 4456 §8):
        // - ORIGINATOR_ID matching our own router-id → loop
        // - Our cluster_id already in CLUSTER_LIST → loop
        //
        // ORIGINATOR_ID must be checked even when we are not operating as an
        // RR ourselves: a non-RR speaker can still receive reflected routes
        // from some other RR in the AS.
        let originator_loop = parsed.attributes.iter().any(|a| {
            matches!(a, PathAttribute::OriginatorId(id) if *id == self.config.peer.local_router_id)
        });
        let cluster_loop = self.config.cluster_id.is_some_and(|cluster_id| {
            parsed
                .attributes
                .iter()
                .any(|a| matches!(a, PathAttribute::ClusterList(ids) if ids.contains(&cluster_id)))
        });
        if originator_loop || cluster_loop {
            let reason = if originator_loop {
                "ORIGINATOR_ID"
            } else {
                "CLUSTER_LIST"
            };
            debug!(
                peer = %self.peer_label,
                reason,
                "Route reflector loop detected — discarding announcements"
            );
            self.metrics.record_rr_loop_detected(&self.peer_label);

            // Still process withdrawals (same pattern as AS_PATH loop)
            let mut loop_withdrawn: Vec<(Prefix, u32)> = parsed
                .withdrawn
                .iter()
                .map(|e| (Prefix::V4(e.prefix), e.path_id))
                .collect();
            let mut loop_fs_withdrawn: Vec<FlowSpecRule> = Vec::new();
            for attr in &parsed.attributes {
                if let PathAttribute::MpUnreachNlri(mp) = attr {
                    let family = (mp.afi, mp.safi);
                    if self.negotiated_families.contains(&family) {
                        loop_withdrawn.extend(mp.withdrawn.iter().map(|e| (e.prefix, e.path_id)));
                        loop_fs_withdrawn.extend(mp.flowspec_withdrawn.iter().cloned());
                    }
                }
            }
            for &(prefix, path_id) in &loop_withdrawn {
                self.known_paths.remove(&(prefix, path_id));
            }
            if !loop_withdrawn.is_empty() || !loop_fs_withdrawn.is_empty() {
                let _ = self.rib_tx.try_send(RibUpdate::RoutesReceived {
                    peer: self.peer_ip,
                    announced: vec![],
                    withdrawn: loop_withdrawn,
                    flowspec_announced: vec![],
                    flowspec_withdrawn: loop_fs_withdrawn,
                });
            }
            self.drive_fsm(Event::UpdateReceived).await;
            return;
        }

        // Filter attributes: strip MP_REACH/MP_UNREACH before storing on routes
        // (they are per-UPDATE framing, not per-route attributes)
        let route_attrs: Vec<PathAttribute> = parsed
            .attributes
            .iter()
            .filter(|a| {
                !matches!(
                    a,
                    PathAttribute::MpReachNlri(_) | PathAttribute::MpUnreachNlri(_)
                )
            })
            .cloned()
            .collect();

        // Extract communities for policy matching
        let update_ecs: &[rustbgpd_wire::ExtendedCommunity] = route_attrs
            .iter()
            .find_map(|a| match a {
                PathAttribute::ExtendedCommunities(c) => Some(c.as_slice()),
                _ => None,
            })
            .unwrap_or(&[]);
        let update_communities: &[u32] = route_attrs
            .iter()
            .find_map(|a| match a {
                PathAttribute::Communities(c) => Some(c.as_slice()),
                _ => None,
            })
            .unwrap_or(&[]);

        // Compute AS_PATH string for policy matching
        let update_large_communities: &[rustbgpd_wire::LargeCommunity] = route_attrs
            .iter()
            .find_map(|a| match a {
                PathAttribute::LargeCommunities(c) => Some(c.as_slice()),
                _ => None,
            })
            .unwrap_or(&[]);
        let aspath_str: String = route_attrs
            .iter()
            .find_map(|a| match a {
                PathAttribute::AsPath(p) => Some(p.to_aspath_string()),
                _ => None,
            })
            .unwrap_or_default();

        // Body NLRI routes (IPv4)
        let mut announced: Vec<Route> = parsed
            .announced
            .iter()
            .filter_map(|entry| {
                let prefix = Prefix::V4(entry.prefix);
                let result = rustbgpd_policy::evaluate_chain(
                    self.import_policy.as_ref(),
                    prefix,
                    update_ecs,
                    update_communities,
                    update_large_communities,
                    &aspath_str,
                    rustbgpd_wire::RpkiValidation::NotFound,
                );
                if result.action != rustbgpd_policy::PolicyAction::Permit {
                    return None;
                }
                let mut attrs = route_attrs.clone();
                let nh_action =
                    rustbgpd_policy::apply_modifications(&mut attrs, &result.modifications);
                let next_hop = resolve_import_nexthop(
                    nh_action.as_ref(),
                    body_next_hop,
                    self.stream.as_ref(),
                    &self.config,
                );
                Some(Route {
                    prefix,
                    next_hop,
                    peer: self.peer_ip,
                    attributes: attrs,
                    received_at: now,
                    origin_type: route_origin,
                    peer_router_id: self
                        .negotiated
                        .as_ref()
                        .map_or(Ipv4Addr::UNSPECIFIED, |n| n.peer_router_id),
                    is_stale: false,
                    is_llgr_stale: false,
                    path_id: entry.path_id,
                    validation_state: rustbgpd_wire::RpkiValidation::NotFound,
                })
            })
            .collect();

        // Body withdrawn routes (IPv4) — carry path_id for Add-Path peers
        let mut withdrawn: Vec<(Prefix, u32)> = parsed
            .withdrawn
            .iter()
            .map(|e| (Prefix::V4(e.prefix), e.path_id))
            .collect();

        // MP-BGP NLRI from attributes
        // For IPv6 routes, also strip body NEXT_HOP — it's IPv4-specific and
        // would contaminate IPv6 route attributes in mixed UPDATEs.
        let mp_route_attrs: Vec<PathAttribute> = route_attrs
            .iter()
            .filter(|a| !matches!(a, PathAttribute::NextHop(_)))
            .cloned()
            .collect();

        let mut flowspec_announced: Vec<FlowSpecRoute> = Vec::new();
        let mut flowspec_withdrawn: Vec<FlowSpecRule> = Vec::new();

        for attr in &parsed.attributes {
            match attr {
                PathAttribute::MpReachNlri(mp) => {
                    let family = (mp.afi, mp.safi);
                    if !self.negotiated_families.contains(&family) {
                        warn!(
                            peer = %self.peer_label,
                            afi = ?mp.afi,
                            safi = ?mp.safi,
                            "Ignoring MP_REACH_NLRI for non-negotiated family"
                        );
                        continue;
                    }

                    if family == (Afi::Ipv4, Safi::Unicast) && !self.use_extended_nexthop_ipv4() {
                        warn!(
                            peer = %self.peer_label,
                            "Ignoring IPv4 MP_REACH_NLRI without negotiated Extended Next Hop"
                        );
                        continue;
                    }

                    if mp.safi == Safi::FlowSpec {
                        // FlowSpec announced routes — no next-hop (NH len = 0)
                        for rule in &mp.flowspec_announced {
                            // Apply import policy using the destination prefix
                            // component (if present) for prefix matching
                            let dest_prefix = rule.destination_prefix();
                            let result = rustbgpd_policy::evaluate_chain(
                                self.import_policy.as_ref(),
                                dest_prefix.unwrap_or(Prefix::V4(rustbgpd_wire::Ipv4Prefix::new(
                                    Ipv4Addr::UNSPECIFIED,
                                    0,
                                ))),
                                update_ecs,
                                update_communities,
                                update_large_communities,
                                &aspath_str,
                                rustbgpd_wire::RpkiValidation::NotFound,
                            );
                            if result.action == rustbgpd_policy::PolicyAction::Permit {
                                let mut attrs = mp_route_attrs.clone();
                                let _nh_action = rustbgpd_policy::apply_modifications(
                                    &mut attrs,
                                    &result.modifications,
                                );
                                flowspec_announced.push(FlowSpecRoute {
                                    rule: rule.clone(),
                                    afi: mp.afi,
                                    peer: self.peer_ip,
                                    attributes: attrs,
                                    received_at: now,
                                    origin_type: route_origin,
                                    peer_router_id: self
                                        .negotiated
                                        .as_ref()
                                        .map_or(Ipv4Addr::UNSPECIFIED, |n| n.peer_router_id),
                                    is_stale: false,
                                    is_llgr_stale: false,
                                    path_id: 0,
                                });
                            }
                        }
                        continue;
                    }

                    // Unicast routes
                    for entry in &mp.announced {
                        let result = rustbgpd_policy::evaluate_chain(
                            self.import_policy.as_ref(),
                            entry.prefix,
                            update_ecs,
                            update_communities,
                            update_large_communities,
                            &aspath_str,
                            rustbgpd_wire::RpkiValidation::NotFound,
                        );
                        if result.action == rustbgpd_policy::PolicyAction::Permit {
                            let mut attrs = mp_route_attrs.clone();
                            let nh_action = rustbgpd_policy::apply_modifications(
                                &mut attrs,
                                &result.modifications,
                            );
                            let next_hop = resolve_import_nexthop(
                                nh_action.as_ref(),
                                mp.next_hop,
                                self.stream.as_ref(),
                                &self.config,
                            );
                            announced.push(Route {
                                prefix: entry.prefix,
                                next_hop,
                                peer: self.peer_ip,
                                attributes: attrs,
                                received_at: now,
                                origin_type: route_origin,
                                peer_router_id: self
                                    .negotiated
                                    .as_ref()
                                    .map_or(Ipv4Addr::UNSPECIFIED, |n| n.peer_router_id),
                                is_stale: false,
                                is_llgr_stale: false,
                                path_id: entry.path_id,
                                validation_state: rustbgpd_wire::RpkiValidation::NotFound,
                            });
                        }
                    }
                }
                PathAttribute::MpUnreachNlri(mp) => {
                    let family = (mp.afi, mp.safi);
                    if !self.negotiated_families.contains(&family) {
                        continue;
                    }
                    if family == (Afi::Ipv4, Safi::Unicast) && !self.use_extended_nexthop_ipv4() {
                        warn!(
                            peer = %self.peer_label,
                            "Ignoring IPv4 MP_UNREACH_NLRI without negotiated Extended Next Hop"
                        );
                        continue;
                    }
                    withdrawn.extend(mp.withdrawn.iter().map(|e| (e.prefix, e.path_id)));
                    flowspec_withdrawn.extend(mp.flowspec_withdrawn.iter().cloned());
                }
                _ => {}
            }
        }

        // 4. Max-prefix enforcement — track via HashSet for accuracy
        for &(prefix, path_id) in &withdrawn {
            self.known_paths.remove(&(prefix, path_id));
        }
        for route in &announced {
            self.known_paths.insert((route.prefix, route.path_id));
        }

        let prefix_count = self.known_prefix_count();
        if let Some(max) = self.config.max_prefixes
            && prefix_count > max as usize
        {
            warn!(
                peer = %self.peer_label,
                count = prefix_count,
                max,
                "max prefix exceeded"
            );
            self.metrics.record_max_prefix_exceeded(&self.peer_label);
            let notif = NotificationMessage::new(
                NotificationCode::Cease,
                cease_subcode::MAX_PREFIXES,
                bytes::Bytes::new(),
            );
            self.drive_fsm(Event::UpdateValidationError(notif)).await;
            return;
        }

        if !announced.is_empty()
            || !withdrawn.is_empty()
            || !flowspec_announced.is_empty()
            || !flowspec_withdrawn.is_empty()
        {
            let _ = self.rib_tx.try_send(RibUpdate::RoutesReceived {
                peer: self.peer_ip,
                announced,
                withdrawn,
                flowspec_announced,
                flowspec_withdrawn,
            });
        }

        // 5. Tell FSM about the update (restarts hold timer)
        self.drive_fsm(Event::UpdateReceived).await;
    }

    /// Map external commands to FSM events.
    async fn handle_command(&mut self, cmd: PeerCommand) -> ControlFlow<()> {
        match cmd {
            PeerCommand::Start => {
                self.stop_requested = false;
                self.reconnect_timer = None;
                self.drive_fsm(Event::ManualStart).await;
                ControlFlow::Continue(())
            }
            PeerCommand::Stop { reason } => {
                self.stop_requested = true;
                self.reconnect_timer = None;
                self.drive_fsm(Event::ManualStop { reason }).await;
                ControlFlow::Continue(())
            }
            PeerCommand::Shutdown => {
                self.stop_requested = true;
                self.reconnect_timer = None;
                info!(peer = %self.peer_label, "shutdown requested");
                if self.fsm.state() == SessionState::Established {
                    self.drive_fsm(Event::ManualStop { reason: None }).await;
                }
                self.close_tcp();
                self.timers.stop_all();
                ControlFlow::Break(())
            }
            PeerCommand::QueryState { reply } => {
                let uptime_secs = self.established_at.map_or(0, |t| t.elapsed().as_secs());
                // Prefer FSM's negotiated (available at OpenConfirm) over
                // self.negotiated (set later at SessionEstablished). This is
                // critical for collision detection: handle_inbound() reads
                // remote_router_id via QueryState when the session is in
                // OpenConfirm.
                let neg = self.fsm.negotiated().or(self.negotiated.as_ref());
                let state = PeerSessionState {
                    fsm_state: self.fsm.state(),
                    peer_ip: self.peer_ip,
                    prefix_count: self.known_prefix_count(),
                    negotiated_hold_time: neg.map(|n| n.hold_time),
                    four_octet_as: neg.map(|n| n.four_octet_as),
                    remote_router_id: neg.map(|n| n.peer_router_id),
                    updates_received: self.updates_received,
                    updates_sent: self.updates_sent,
                    notifications_received: self.notifications_received,
                    notifications_sent: self.notifications_sent,
                    flap_count: self.flap_count,
                    uptime_secs,
                    last_error: self.last_error.clone(),
                };
                let _ = reply.send(state);
                ControlFlow::Continue(())
            }
            PeerCommand::SendRouteRefresh { afi, safi, reply } => {
                if self.fsm.state() != SessionState::Established {
                    let _ = reply.send(Err("session not Established".into()));
                    return ControlFlow::Continue(());
                }
                if !self
                    .negotiated
                    .as_ref()
                    .is_some_and(|n| n.peer_route_refresh)
                {
                    let _ = reply.send(Err("peer lacks Route Refresh capability".into()));
                    return ControlFlow::Continue(());
                }
                if !self.negotiated_families.contains(&(afi, safi)) {
                    let _ = reply.send(Err(format!("{afi:?}/{safi:?} not negotiated")));
                    return ControlFlow::Continue(());
                }
                let msg = Message::RouteRefresh(RouteRefreshMessage::new(afi, safi));
                if let Err(e) = self.send_message(&msg).await {
                    let _ = reply.send(Err(format!("send failed: {e}")));
                } else {
                    info!(peer = %self.peer_label, ?afi, ?safi, "sent ROUTE-REFRESH");
                    self.metrics
                        .record_message_sent(&self.peer_label, "route_refresh");
                    let _ = reply.send(Ok(()));
                }
                ControlFlow::Continue(())
            }
            PeerCommand::CollisionDump => {
                info!(peer = %self.peer_label, "collision dump: sending Cease/7");
                self.stop_requested = true;
                self.reconnect_timer = None;
                // Send Cease/7 NOTIFICATION
                let notif = rustbgpd_wire::NotificationMessage::new(
                    NotificationCode::Cease,
                    cease_subcode::CONNECTION_COLLISION_RESOLUTION,
                    bytes::Bytes::new(),
                );
                let _ = self.send_message(&Message::Notification(notif)).await;
                self.notifications_sent += 1;
                // Clean up RIB if Established
                if self.fsm.state() == SessionState::Established {
                    let _ = self
                        .rib_tx
                        .try_send(RibUpdate::PeerDown { peer: self.peer_ip });
                }
                self.close_tcp();
                self.timers.stop_all();
                ControlFlow::Break(())
            }
        }
    }

    /// Send an outbound route update as wire UPDATE messages.
    #[expect(clippy::too_many_lines)]
    async fn send_route_update(&mut self, update: OutboundRouteUpdate) {
        let four_octet_as = self.negotiated.as_ref().is_some_and(|n| n.four_octet_as);
        let is_ebgp = self
            .negotiated
            .as_ref()
            .is_some_and(|n| n.peer_asn != self.config.peer.local_asn);
        let peer_err = self
            .negotiated
            .as_ref()
            .is_some_and(|n| n.peer_enhanced_route_refresh);

        // Check if Add-Path send is negotiated (we can send path IDs to this peer)
        let add_path_ipv4_send = self.negotiated.as_ref().is_some_and(|n| {
            n.add_path_families
                .get(&(Afi::Ipv4, Safi::Unicast))
                .is_some_and(|m| {
                    matches!(
                        m,
                        rustbgpd_wire::AddPathMode::Send | rustbgpd_wire::AddPathMode::Both
                    )
                })
        });
        let add_path_ipv6_send = self.negotiated.as_ref().is_some_and(|n| {
            n.add_path_families
                .get(&(Afi::Ipv6, Safi::Unicast))
                .is_some_and(|m| {
                    matches!(
                        m,
                        rustbgpd_wire::AddPathMode::Send | rustbgpd_wire::AddPathMode::Both
                    )
                })
        });

        if peer_err {
            for (afi, safi, subtype) in update
                .refresh_markers
                .iter()
                .copied()
                .filter(|(_, _, subtype)| matches!(subtype, RouteRefreshSubtype::BoRR))
            {
                let msg = Message::RouteRefresh(RouteRefreshMessage::new_with_subtype(
                    afi, safi, subtype,
                ));
                if let Err(e) = self.send_message(&msg).await {
                    warn!(
                        peer = %self.peer_label,
                        error = %e,
                        "failed to send Beginning-of-RIB-Refresh"
                    );
                    return;
                }
                self.metrics
                    .record_message_sent(&self.peer_label, "route_refresh");
            }
        }
        let use_extended_nexthop_ipv4 = self.use_extended_nexthop_ipv4();

        // Extract TCP local addresses for NEXT_HOP rewrite
        let local_addr = self
            .stream
            .as_ref()
            .and_then(|s| s.local_addr().ok())
            .map(|a| a.ip());
        let local_ipv4 = local_addr
            .and_then(|a| match a {
                IpAddr::V4(v4) => Some(v4),
                IpAddr::V6(_) => None,
            })
            .unwrap_or(self.config.peer.local_router_id);
        let local_ipv6 = local_addr.and_then(|a| match a {
            IpAddr::V6(v6) => Some(v6),
            IpAddr::V4(_) => None,
        });

        // Split withdrawals by address family, filtering by negotiated families
        let mut v4_withdraw: Vec<Ipv4NlriEntry> = Vec::new();
        let mut v6_withdraw: Vec<NlriEntry> = Vec::new();
        for &(ref prefix, path_id) in &update.withdraw {
            if !self.is_family_negotiated(prefix) {
                continue;
            }
            match prefix {
                Prefix::V4(v4) => v4_withdraw.push(Ipv4NlriEntry {
                    path_id,
                    prefix: *v4,
                }),
                v6 @ Prefix::V6(_) => v6_withdraw.push(NlriEntry {
                    path_id,
                    prefix: *v6,
                }),
            }
        }

        // Send IPv4 withdrawals via body NLRI or IPv4 MP_UNREACH_NLRI,
        // depending on Extended Next Hop negotiation.
        if !v4_withdraw.is_empty() {
            let msg = if use_extended_nexthop_ipv4 {
                let attrs = vec![PathAttribute::MpUnreachNlri(MpUnreachNlri {
                    afi: Afi::Ipv4,
                    safi: Safi::Unicast,
                    withdrawn: v4_withdraw
                        .iter()
                        .map(|entry| NlriEntry {
                            path_id: entry.path_id,
                            prefix: Prefix::V4(entry.prefix),
                        })
                        .collect(),
                    flowspec_withdrawn: vec![],
                })];
                UpdateMessage::build(
                    &[],
                    &[],
                    &attrs,
                    four_octet_as,
                    add_path_ipv4_send,
                    Ipv4UnicastMode::MpReach,
                )
            } else {
                UpdateMessage::build(
                    &[],
                    &v4_withdraw,
                    &[],
                    four_octet_as,
                    add_path_ipv4_send,
                    Ipv4UnicastMode::Body,
                )
            };
            let wire_msg = Message::Update(msg);
            if let Err(e) = self.send_message(&wire_msg).await {
                warn!(peer = %self.peer_label, error = %e, "failed to send withdrawal UPDATE");
                return;
            }
            self.updates_sent += 1;
            self.metrics.record_message_sent(&self.peer_label, "update");
        }

        // Send IPv6 withdrawals via `MP_UNREACH_NLRI`
        if !v6_withdraw.is_empty() {
            let attrs = vec![PathAttribute::MpUnreachNlri(MpUnreachNlri {
                afi: Afi::Ipv6,
                safi: Safi::Unicast,
                withdrawn: v6_withdraw,
                flowspec_withdrawn: vec![],
            })];
            let msg = UpdateMessage::build(
                &[],
                &[],
                &attrs,
                four_octet_as,
                add_path_ipv6_send,
                Ipv4UnicastMode::Body,
            );
            let wire_msg = Message::Update(msg);
            if let Err(e) = self.send_message(&wire_msg).await {
                warn!(peer = %self.peer_label, error = %e, "failed to send v6 withdrawal UPDATE");
                return;
            }
            self.updates_sent += 1;
            self.metrics.record_message_sent(&self.peer_label, "update");
        }

        // Split announcements by address family, filtering by negotiated families
        let mut v4_routes: Vec<(&Route, Option<&rustbgpd_policy::NextHopAction>)> = Vec::new();
        let mut v6_routes: Vec<(&Route, Option<&rustbgpd_policy::NextHopAction>)> = Vec::new();
        for (i, route) in update.announce.iter().enumerate() {
            if !self.is_family_negotiated(&route.prefix) {
                continue;
            }
            let nh_override = update.next_hop_override.get(i).and_then(|o| o.as_ref());
            match route.prefix {
                Prefix::V4(_) => v4_routes.push((route, nh_override)),
                Prefix::V6(_) => v6_routes.push((route, nh_override)),
            }
        }

        // Send IPv4 announcements via body NLRI or IPv4 MP_REACH_NLRI,
        // depending on Extended Next Hop negotiation.
        if use_extended_nexthop_ipv4 {
            let ebgp_ipv6_nh = self
                .config
                .local_ipv6_nexthop
                .or(local_ipv6)
                .filter(rustbgpd_wire::is_valid_ipv6_nexthop);
            let mut v4_groups: Vec<(Vec<PathAttribute>, IpAddr, Vec<NlriEntry>)> = Vec::new();
            for (route, nh_override) in &v4_routes {
                let attrs_with_next_hop =
                    self.prepare_outbound_attributes(route, is_ebgp, local_ipv4, *nh_override);
                let attrs: Vec<PathAttribute> = attrs_with_next_hop
                    .into_iter()
                    .filter(|attr| !matches!(attr, PathAttribute::NextHop(_)))
                    .collect();
                let force_nh_self =
                    matches!(nh_override, Some(rustbgpd_policy::NextHopAction::Self_));
                let next_hop = match nh_override {
                    Some(rustbgpd_policy::NextHopAction::Specific(addr)) => *addr,
                    _ if force_nh_self => local_addr.unwrap_or(IpAddr::V4(local_ipv4)),
                    _ if is_ebgp && !self.config.route_server_client => {
                        let Some(v6) = ebgp_ipv6_nh else {
                            warn!(
                                peer = %self.peer_label,
                                prefix = %route.prefix,
                                "cannot send IPv4 route with Extended Next Hop: no usable local IPv6 next-hop"
                            );
                            continue;
                        };
                        IpAddr::V6(v6)
                    }
                    _ => route.next_hop,
                };
                let entry = NlriEntry {
                    path_id: route.path_id,
                    prefix: route.prefix,
                };
                if let Some(group) =
                    v4_groups
                        .iter_mut()
                        .find(|(existing_attrs, existing_nh, _)| {
                            *existing_attrs == attrs && *existing_nh == next_hop
                        })
                {
                    group.2.push(entry);
                } else {
                    v4_groups.push((attrs, next_hop, vec![entry]));
                }
            }

            for (mut attrs, next_hop, prefixes) in v4_groups {
                attrs.push(PathAttribute::MpReachNlri(MpReachNlri {
                    afi: Afi::Ipv4,
                    safi: Safi::Unicast,
                    next_hop,
                    announced: prefixes,
                    flowspec_announced: vec![],
                }));
                let msg = UpdateMessage::build(
                    &[],
                    &[],
                    &attrs,
                    four_octet_as,
                    add_path_ipv4_send,
                    Ipv4UnicastMode::MpReach,
                );
                let wire_msg = Message::Update(msg);
                if let Err(e) = self.send_message(&wire_msg).await {
                    warn!(peer = %self.peer_label, error = %e, "failed to send announce UPDATE");
                    return;
                }
                self.updates_sent += 1;
                self.metrics.record_message_sent(&self.peer_label, "update");
            }
        } else {
            let mut v4_groups: Vec<(Vec<PathAttribute>, Vec<Ipv4NlriEntry>)> = Vec::new();
            for (route, nh_override) in &v4_routes {
                let attrs =
                    self.prepare_outbound_attributes(route, is_ebgp, local_ipv4, *nh_override);
                if let Prefix::V4(v4) = route.prefix {
                    let entry = Ipv4NlriEntry {
                        path_id: route.path_id,
                        prefix: v4,
                    };
                    if let Some(group) = v4_groups.iter_mut().find(|(a, _)| *a == attrs) {
                        group.1.push(entry);
                    } else {
                        v4_groups.push((attrs, vec![entry]));
                    }
                }
            }

            for (attrs, prefixes) in &v4_groups {
                let msg = UpdateMessage::build(
                    prefixes,
                    &[],
                    attrs,
                    four_octet_as,
                    add_path_ipv4_send,
                    Ipv4UnicastMode::Body,
                );
                let wire_msg = Message::Update(msg);
                if let Err(e) = self.send_message(&wire_msg).await {
                    warn!(peer = %self.peer_label, error = %e, "failed to send announce UPDATE");
                    return;
                }
                self.updates_sent += 1;
                self.metrics.record_message_sent(&self.peer_label, "update");
            }
        }

        // Resolve IPv6 eBGP next-hop: config override > socket address > suppress.
        // The RIB already filters unsendable families via sendable_families, so
        // v6_routes should be empty here for eBGP peers without a valid IPv6 NH.
        // The is_family_negotiated filter above is retained as a safety net.
        let ebgp_ipv6_nh: Option<Ipv6Addr> = self
            .config
            .local_ipv6_nexthop
            .or(local_ipv6)
            .filter(rustbgpd_wire::is_valid_ipv6_nexthop);

        // Guard: if eBGP has no valid IPv6 NH, skip all v6 routes. The RIB's
        // sendable_families filter should prevent this, but defend in depth.
        if is_ebgp
            && !self.config.route_server_client
            && ebgp_ipv6_nh.is_none()
            && !v6_routes.is_empty()
        {
            debug_assert!(
                false,
                "RIB sent {} IPv6 routes to eBGP peer with no valid IPv6 next-hop",
                v6_routes.len()
            );
            warn!(
                peer = %self.peer_label,
                count = v6_routes.len(),
                "BUG: IPv6 routes reached transport for eBGP peer with no valid next-hop; dropping"
            );
            v6_routes.clear();
        }

        // Group by (attributes, next-hop) so routes with different next-hops
        // get separate UPDATEs with correct MP_REACH_NLRI next-hop values.
        let mut v6_groups: Vec<(Vec<PathAttribute>, IpAddr, Vec<NlriEntry>)> = Vec::new();
        for (route, nh_override) in &v6_routes {
            let attrs = self.prepare_outbound_attributes(route, is_ebgp, local_ipv4, *nh_override);
            let force_nh_self = matches!(nh_override, Some(rustbgpd_policy::NextHopAction::Self_));
            let nh = if let Some(rustbgpd_policy::NextHopAction::Specific(addr)) = nh_override {
                // Policy explicitly set a next-hop — use it
                *addr
            } else if force_nh_self {
                // For next-hop-self, use local IPv6 address when available.
                if let Some(v6) = ebgp_ipv6_nh {
                    IpAddr::V6(v6)
                } else {
                    route.next_hop
                }
            } else if is_ebgp && !self.config.route_server_client {
                // Non-transparent eBGP uses next-hop-self.
                if let Some(v6) = ebgp_ipv6_nh {
                    IpAddr::V6(v6)
                } else {
                    route.next_hop
                }
            } else {
                route.next_hop
            };
            let nlri_entry = NlriEntry {
                path_id: route.path_id,
                prefix: route.prefix,
            };
            if let Some(group) = v6_groups
                .iter_mut()
                .find(|(a, h, _)| *a == attrs && *h == nh)
            {
                group.2.push(nlri_entry);
            } else {
                v6_groups.push((attrs, nh, vec![nlri_entry]));
            }
        }

        for (mut attrs, nh, prefixes) in v6_groups {
            attrs.push(PathAttribute::MpReachNlri(MpReachNlri {
                afi: Afi::Ipv6,
                safi: Safi::Unicast,
                next_hop: nh,
                announced: prefixes,
                flowspec_announced: vec![],
            }));
            let msg = UpdateMessage::build(
                &[],
                &[],
                &attrs,
                four_octet_as,
                add_path_ipv6_send,
                Ipv4UnicastMode::Body,
            );
            let wire_msg = Message::Update(msg);
            if let Err(e) = self.send_message(&wire_msg).await {
                warn!(peer = %self.peer_label, error = %e, "failed to send v6 announce UPDATE");
                return;
            }
            self.updates_sent += 1;
            self.metrics.record_message_sent(&self.peer_label, "update");
        }

        // Send FlowSpec withdrawals via MP_UNREACH_NLRI, grouped by AFI
        if !update.flowspec_withdraw.is_empty() {
            let mut v4_fs_withdraw: Vec<FlowSpecRule> = Vec::new();
            let mut v6_fs_withdraw: Vec<FlowSpecRule> = Vec::new();
            for rule in &update.flowspec_withdraw {
                // Determine AFI from the rule's destination prefix component
                let afi = if rule
                    .destination_prefix()
                    .is_some_and(|p| matches!(p, Prefix::V6(_)))
                {
                    Afi::Ipv6
                } else {
                    Afi::Ipv4
                };
                match afi {
                    Afi::Ipv4 => v4_fs_withdraw.push(rule.clone()),
                    Afi::Ipv6 => v6_fs_withdraw.push(rule.clone()),
                }
            }
            for (afi, rules) in [(Afi::Ipv4, v4_fs_withdraw), (Afi::Ipv6, v6_fs_withdraw)] {
                if rules.is_empty() {
                    continue;
                }
                let attrs = vec![PathAttribute::MpUnreachNlri(MpUnreachNlri {
                    afi,
                    safi: Safi::FlowSpec,
                    withdrawn: vec![],
                    flowspec_withdrawn: rules,
                })];
                let msg = UpdateMessage::build(
                    &[],
                    &[],
                    &attrs,
                    four_octet_as,
                    false,
                    Ipv4UnicastMode::Body,
                );
                let wire_msg = Message::Update(msg);
                if let Err(e) = self.send_message(&wire_msg).await {
                    warn!(peer = %self.peer_label, error = %e, "failed to send FlowSpec withdrawal UPDATE");
                    return;
                }
                self.updates_sent += 1;
                self.metrics.record_message_sent(&self.peer_label, "update");
            }
        }

        // Send FlowSpec announcements via MP_REACH_NLRI, grouped by (AFI, attributes)
        if !update.flowspec_announce.is_empty() {
            let mut fs_groups: Vec<(Afi, Vec<PathAttribute>, Vec<FlowSpecRule>)> = Vec::new();
            for fs_route in &update.flowspec_announce {
                let attrs = self.prepare_outbound_attributes_flowspec(fs_route, is_ebgp);
                if let Some(group) = fs_groups
                    .iter_mut()
                    .find(|(a, ga, _)| *a == fs_route.afi && *ga == attrs)
                {
                    group.2.push(fs_route.rule.clone());
                } else {
                    fs_groups.push((fs_route.afi, attrs, vec![fs_route.rule.clone()]));
                }
            }
            for (afi, mut attrs, rules) in fs_groups {
                attrs.push(PathAttribute::MpReachNlri(MpReachNlri {
                    afi,
                    safi: Safi::FlowSpec,
                    next_hop: IpAddr::V4(Ipv4Addr::UNSPECIFIED), // NH len = 0 for FlowSpec
                    announced: vec![],
                    flowspec_announced: rules,
                }));
                let msg = UpdateMessage::build(
                    &[],
                    &[],
                    &attrs,
                    four_octet_as,
                    false,
                    Ipv4UnicastMode::Body,
                );
                let wire_msg = Message::Update(msg);
                if let Err(e) = self.send_message(&wire_msg).await {
                    warn!(peer = %self.peer_label, error = %e, "failed to send FlowSpec announce UPDATE");
                    return;
                }
                self.updates_sent += 1;
                self.metrics.record_message_sent(&self.peer_label, "update");
            }
        }

        if peer_err {
            for (afi, safi, subtype) in update
                .refresh_markers
                .iter()
                .copied()
                .filter(|(_, _, subtype)| matches!(subtype, RouteRefreshSubtype::EoRR))
            {
                let msg = Message::RouteRefresh(RouteRefreshMessage::new_with_subtype(
                    afi, safi, subtype,
                ));
                if let Err(e) = self.send_message(&msg).await {
                    warn!(
                        peer = %self.peer_label,
                        error = %e,
                        "failed to send End-of-RIB-Refresh"
                    );
                    return;
                }
                self.metrics
                    .record_message_sent(&self.peer_label, "route_refresh");
            }
        }

        // Send End-of-RIB markers
        for (afi, safi) in &update.end_of_rib {
            if peer_err
                && update
                    .refresh_markers
                    .iter()
                    .any(|(m_afi, m_safi, subtype)| {
                        *m_afi == *afi
                            && *m_safi == *safi
                            && matches!(
                                subtype,
                                RouteRefreshSubtype::BoRR | RouteRefreshSubtype::EoRR
                            )
                    })
            {
                continue;
            }
            let msg = if let (Afi::Ipv4, Safi::Unicast) = (afi, safi) {
                // IPv4 Unicast EoR: empty UPDATE (no NLRI, no withdrawn, no attrs)
                UpdateMessage::build(&[], &[], &[], four_octet_as, false, Ipv4UnicastMode::Body)
            } else {
                // MP EoR: UPDATE with empty MP_UNREACH_NLRI (IPv6 unicast, FlowSpec, etc.)
                let attrs = vec![PathAttribute::MpUnreachNlri(MpUnreachNlri {
                    afi: *afi,
                    safi: *safi,
                    withdrawn: vec![],
                    flowspec_withdrawn: vec![],
                })];
                UpdateMessage::build(
                    &[],
                    &[],
                    &attrs,
                    four_octet_as,
                    false,
                    Ipv4UnicastMode::Body,
                )
            };
            let wire_msg = Message::Update(msg);
            if let Err(e) = self.send_message(&wire_msg).await {
                warn!(peer = %self.peer_label, error = %e, "failed to send End-of-RIB for {afi:?}/{safi:?}");
                return;
            }
            info!(peer = %self.peer_label, afi = ?afi, safi = ?safi, "sent End-of-RIB");
            self.updates_sent += 1;
            self.metrics.record_message_sent(&self.peer_label, "update");
        }
    }

    /// Prepare path attributes for outbound advertisement.
    ///
    /// For standard eBGP: prepend our ASN, set `NEXT_HOP` to local addr, strip
    /// `LOCAL_PREF`. For route-server clients, preserve `AS_PATH` and
    /// `NEXT_HOP` by default. For iBGP: ensure `LOCAL_PREF` present (default
    /// 100), pass `NEXT_HOP` through.
    #[expect(clippy::too_many_lines)]
    fn prepare_outbound_attributes(
        &self,
        route: &Route,
        is_ebgp: bool,
        local_ipv4: Ipv4Addr,
        nh_override: Option<&rustbgpd_policy::NextHopAction>,
    ) -> Vec<PathAttribute> {
        let force_next_hop_self =
            matches!(nh_override, Some(rustbgpd_policy::NextHopAction::Self_));
        let policy_set_specific = matches!(
            nh_override,
            Some(rustbgpd_policy::NextHopAction::Specific(_))
        );
        let route_server_client = self.config.route_server_client;
        let mut attrs = Vec::new();

        for attr in &route.attributes {
            match attr {
                PathAttribute::AsPath(as_path) => {
                    if is_ebgp && !route_server_client {
                        // Prepend our ASN
                        let mut new_segments =
                            vec![AsPathSegment::AsSequence(vec![self.config.peer.local_asn])];
                        for seg in &as_path.segments {
                            match seg {
                                AsPathSegment::AsSequence(asns) => {
                                    // Merge into first sequence if possible
                                    if let Some(AsPathSegment::AsSequence(first)) =
                                        new_segments.first_mut()
                                    {
                                        first.extend(asns);
                                    }
                                }
                                AsPathSegment::AsSet(asns) => {
                                    new_segments.push(AsPathSegment::AsSet(asns.clone()));
                                }
                            }
                        }
                        attrs.push(PathAttribute::AsPath(AsPath {
                            segments: new_segments,
                        }));
                    } else {
                        attrs.push(attr.clone());
                    }
                }
                PathAttribute::NextHop(_) => {
                    if policy_set_specific {
                        // Policy explicitly set a next-hop — preserve it
                        attrs.push(attr.clone());
                    } else if force_next_hop_self || (is_ebgp && !route_server_client) {
                        attrs.push(PathAttribute::NextHop(local_ipv4));
                    } else {
                        attrs.push(attr.clone());
                    }
                }
                PathAttribute::LocalPref(_) => {
                    if !is_ebgp {
                        attrs.push(attr.clone());
                    }
                    // Strip LOCAL_PREF for eBGP
                }
                // Strip MP_REACH/MP_UNREACH — rebuilt per-UPDATE, not copied
                PathAttribute::MpReachNlri(_) | PathAttribute::MpUnreachNlri(_) => {}
                // Strip ORIGINATOR_ID and CLUSTER_LIST on eBGP outbound
                // (optional non-transitive, must not leave the AS)
                PathAttribute::OriginatorId(_) | PathAttribute::ClusterList(_) if is_ebgp => {}
                _ => {
                    attrs.push(attr.clone());
                }
            }
        }

        // For iBGP, ensure LOCAL_PREF is present (default 100)
        if !is_ebgp
            && !attrs
                .iter()
                .any(|a| matches!(a, PathAttribute::LocalPref(_)))
        {
            attrs.push(PathAttribute::LocalPref(100));
        }

        // Ensure classic IPv4 body-NLRI exports carry a NEXT_HOP. This also
        // preserves the route's original next hop for transparent route-server
        // clients when the attribute was absent on the stored route.
        if matches!(route.prefix, Prefix::V4(_))
            && !attrs.iter().any(|a| matches!(a, PathAttribute::NextHop(_)))
        {
            let next_hop = match nh_override {
                Some(rustbgpd_policy::NextHopAction::Specific(IpAddr::V4(nh))) => Some(*nh),
                Some(rustbgpd_policy::NextHopAction::Specific(IpAddr::V6(_))) => {
                    // IPv6 next-hop is not encodable in classic IPv4 NEXT_HOP
                    // attribute. Requires RFC 8950 Extended Next Hop negotiation.
                    // Fall through to default next-hop selection.
                    tracing::warn!(
                        prefix = %route.prefix,
                        "export policy set IPv6 next-hop for classic IPv4 NLRI; \
                         requires Extended Next Hop (RFC 8950) — using default next-hop instead"
                    );
                    if is_ebgp && !route_server_client {
                        Some(local_ipv4)
                    } else {
                        match route.next_hop {
                            IpAddr::V4(nh) => Some(nh),
                            IpAddr::V6(_) => None,
                        }
                    }
                }
                Some(rustbgpd_policy::NextHopAction::Self_) => Some(local_ipv4),
                _ if is_ebgp && !route_server_client => Some(local_ipv4),
                _ => match route.next_hop {
                    IpAddr::V4(nh) => Some(nh),
                    IpAddr::V6(_) => None,
                },
            };
            if let Some(next_hop) = next_hop {
                attrs.push(PathAttribute::NextHop(next_hop));
            }
        }

        // For standard eBGP, ensure AS_PATH is present (even if empty).
        if is_ebgp
            && !route_server_client
            && !attrs.iter().any(|a| matches!(a, PathAttribute::AsPath(_)))
        {
            attrs.push(PathAttribute::AsPath(AsPath {
                segments: vec![AsPathSegment::AsSequence(vec![self.config.peer.local_asn])],
            }));
        }

        // Route reflector attribute manipulation (RFC 4456 §8):
        // Only when reflecting an iBGP-learned route to an iBGP target do we
        // set ORIGINATOR_ID and prepend CLUSTER_LIST. Locally originated and
        // eBGP-learned routes are advertised normally and are not "reflected"
        // in the RFC 4456 sense.
        if !is_ebgp
            && route.origin_type == rustbgpd_rib::RouteOrigin::Ibgp
            && let Some(cluster_id) = self.config.cluster_id
        {
            // ORIGINATOR_ID: set to source peer's router-id if not already present
            if !attrs
                .iter()
                .any(|a| matches!(a, PathAttribute::OriginatorId(_)))
            {
                attrs.push(PathAttribute::OriginatorId(route.peer_router_id));
            }

            // CLUSTER_LIST: prepend our cluster_id
            let mut found = false;
            for attr in &mut attrs {
                if let PathAttribute::ClusterList(ids) = attr {
                    ids.insert(0, cluster_id);
                    found = true;
                    break;
                }
            }
            if !found {
                attrs.push(PathAttribute::ClusterList(vec![cluster_id]));
            }
        }

        attrs
    }

    /// Prepare path attributes for outbound `FlowSpec` advertisement.
    ///
    /// `FlowSpec` has no `NEXT_HOP`. For eBGP: prepend ASN, strip `LOCAL_PREF`.
    /// For iBGP: ensure `LOCAL_PREF`. Route reflector attributes handled same
    /// as unicast. Transparent route-server behavior is deferred for `FlowSpec`.
    fn prepare_outbound_attributes_flowspec(
        &self,
        route: &FlowSpecRoute,
        is_ebgp: bool,
    ) -> Vec<PathAttribute> {
        let mut attrs = Vec::new();

        for attr in &route.attributes {
            match attr {
                PathAttribute::AsPath(as_path) => {
                    if is_ebgp {
                        let mut new_segments =
                            vec![AsPathSegment::AsSequence(vec![self.config.peer.local_asn])];
                        for seg in &as_path.segments {
                            match seg {
                                AsPathSegment::AsSequence(asns) => {
                                    if let Some(AsPathSegment::AsSequence(first)) =
                                        new_segments.first_mut()
                                    {
                                        first.extend(asns);
                                    }
                                }
                                AsPathSegment::AsSet(asns) => {
                                    new_segments.push(AsPathSegment::AsSet(asns.clone()));
                                }
                            }
                        }
                        attrs.push(PathAttribute::AsPath(AsPath {
                            segments: new_segments,
                        }));
                    } else {
                        attrs.push(attr.clone());
                    }
                }
                // No NEXT_HOP for FlowSpec — skip; also skip MP framing attrs
                PathAttribute::NextHop(_)
                | PathAttribute::MpReachNlri(_)
                | PathAttribute::MpUnreachNlri(_) => {}
                PathAttribute::LocalPref(_) => {
                    if !is_ebgp {
                        attrs.push(attr.clone());
                    }
                }
                PathAttribute::OriginatorId(_) | PathAttribute::ClusterList(_) if is_ebgp => {}
                _ => {
                    attrs.push(attr.clone());
                }
            }
        }

        if !is_ebgp
            && !attrs
                .iter()
                .any(|a| matches!(a, PathAttribute::LocalPref(_)))
        {
            attrs.push(PathAttribute::LocalPref(100));
        }

        if is_ebgp && !attrs.iter().any(|a| matches!(a, PathAttribute::AsPath(_))) {
            attrs.push(PathAttribute::AsPath(AsPath {
                segments: vec![AsPathSegment::AsSequence(vec![self.config.peer.local_asn])],
            }));
        }

        // Route reflector attribute manipulation for FlowSpec (same as unicast)
        if !is_ebgp
            && route.origin_type == rustbgpd_rib::RouteOrigin::Ibgp
            && let Some(cluster_id) = self.config.cluster_id
        {
            if !attrs
                .iter()
                .any(|a| matches!(a, PathAttribute::OriginatorId(_)))
            {
                attrs.push(PathAttribute::OriginatorId(route.peer_router_id));
            }
            let mut found = false;
            for attr in &mut attrs {
                if let PathAttribute::ClusterList(ids) = attr {
                    ids.insert(0, cluster_id);
                    found = true;
                    break;
                }
            }
            if !found {
                attrs.push(PathAttribute::ClusterList(vec![cluster_id]));
            }
        }

        attrs
    }
}

/// Read from TCP into the buffer. Extracted as a freestanding async fn
/// so that `tokio::select!` can borrow the stream and buffer independently
/// from other `self` fields.
async fn read_tcp(
    stream: &mut Option<TcpStream>,
    buf: &mut bytes::BytesMut,
) -> std::io::Result<usize> {
    use tokio::io::AsyncReadExt;
    let stream = stream.as_mut().expect("read_tcp called without stream");
    stream.read_buf(buf).await
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use std::collections::HashMap;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::time::Instant;

    use rustbgpd_fsm::PeerConfig;
    use rustbgpd_policy::{Policy, PolicyAction, PolicyStatement, RouteModifications};
    use rustbgpd_wire::{
        AsPath, AsPathSegment, Ipv4NlriEntry, Ipv4Prefix, Ipv6Prefix, Message, Origin,
        PathAttribute,
    };
    use tokio::io::AsyncReadExt;
    use tokio::net::TcpListener;
    use tokio::sync::oneshot;

    use super::*;

    fn make_test_session(local_asn: u32, remote_asn: u32) -> PeerSession {
        let peer_config = PeerConfig {
            local_asn,
            remote_asn,
            local_router_id: Ipv4Addr::new(10, 0, 0, 1),
            hold_time: 90,
            connect_retry_secs: 30,
            families: vec![(Afi::Ipv4, Safi::Unicast)],
            graceful_restart: false,
            gr_restart_time: 120,
            llgr_stale_time: 0,
            add_path_receive: false,
            add_path_send: false,
            add_path_send_max: 0,
        };
        let config = TransportConfig::new(peer_config, "10.0.0.2:179".parse().unwrap());
        let metrics = BgpMetrics::new();
        let (_cmd_tx, cmd_rx) = mpsc::channel(8);
        let (rib_tx, _rib_rx) = mpsc::channel(64);

        PeerSession::new(config, metrics, cmd_rx, rib_tx, None, None, None, None)
    }

    fn make_test_session_with_rib(
        local_asn: u32,
        remote_asn: u32,
    ) -> (PeerSession, mpsc::Receiver<RibUpdate>) {
        let peer_config = PeerConfig {
            local_asn,
            remote_asn,
            local_router_id: Ipv4Addr::new(10, 0, 0, 1),
            hold_time: 90,
            connect_retry_secs: 30,
            families: vec![(Afi::Ipv4, Safi::Unicast)],
            graceful_restart: false,
            gr_restart_time: 120,
            llgr_stale_time: 0,
            add_path_receive: false,
            add_path_send: false,
            add_path_send_max: 0,
        };
        let config = TransportConfig::new(peer_config, "10.0.0.2:179".parse().unwrap());
        let metrics = BgpMetrics::new();
        let (_cmd_tx, cmd_rx) = mpsc::channel(8);
        let (rib_tx, rib_rx) = mpsc::channel(64);

        (
            PeerSession::new(config, metrics, cmd_rx, rib_tx, None, None, None, None),
            rib_rx,
        )
    }

    fn negotiated_session(remote_asn: u32, extended_nexthop: bool) -> NegotiatedSession {
        let mut extended_nexthop_families = HashMap::new();
        if extended_nexthop {
            extended_nexthop_families.insert((Afi::Ipv4, Safi::Unicast), Afi::Ipv6);
        }
        NegotiatedSession {
            peer_asn: remote_asn,
            peer_router_id: Ipv4Addr::new(10, 0, 0, 2),
            hold_time: 90,
            keepalive_interval: 30,
            peer_capabilities: vec![],
            four_octet_as: true,
            negotiated_families: vec![(Afi::Ipv4, Safi::Unicast)],
            peer_gr_capable: false,
            peer_restart_state: false,
            peer_restart_time: 0,
            peer_gr_families: vec![],
            peer_llgr_capable: false,
            peer_llgr_families: vec![],
            peer_route_refresh: false,
            peer_enhanced_route_refresh: false,
            peer_extended_message: false,
            extended_nexthop_families,
            add_path_families: HashMap::new(),
        }
    }

    fn make_route(local_pref: u32) -> Route {
        Route {
            prefix: Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24)),
            next_hop: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            peer: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            attributes: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath {
                    segments: vec![AsPathSegment::AsSequence(vec![65002])],
                }),
                PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
                PathAttribute::LocalPref(local_pref),
            ],
            received_at: Instant::now(),
            origin_type: rustbgpd_rib::RouteOrigin::Ebgp,
            peer_router_id: Ipv4Addr::UNSPECIFIED,
            is_stale: false,
            is_llgr_stale: false,
            path_id: 0,
            validation_state: rustbgpd_wire::RpkiValidation::NotFound,
        }
    }

    async fn connected_stream_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (client, server) = tokio::join!(TcpStream::connect(addr), listener.accept());
        (client.unwrap(), server.unwrap().0)
    }

    async fn read_single_bgp_message(stream: &mut TcpStream) -> Message {
        let mut header = [0_u8; 19];
        stream.read_exact(&mut header).await.unwrap();
        let msg_len = usize::from(u16::from_be_bytes([header[16], header[17]]));
        let mut body = vec![0_u8; msg_len - header.len()];
        stream.read_exact(&mut body).await.unwrap();

        let mut raw = header.to_vec();
        raw.extend_from_slice(&body);
        let mut buf = Bytes::from(raw);
        rustbgpd_wire::decode_message(&mut buf, rustbgpd_wire::MAX_MESSAGE_LEN).unwrap()
    }

    #[test]
    fn ebgp_prepends_asn() {
        let session = make_test_session(65001, 65002);
        let route = make_route(100);
        let attrs =
            session.prepare_outbound_attributes(&route, true, Ipv4Addr::new(10, 0, 0, 1), None);

        let as_path = attrs
            .iter()
            .find_map(|a| match a {
                PathAttribute::AsPath(p) => Some(p),
                _ => None,
            })
            .unwrap();

        // Should have our ASN prepended
        if let AsPathSegment::AsSequence(asns) = &as_path.segments[0] {
            assert_eq!(asns[0], 65001);
            assert_eq!(asns[1], 65002);
        } else {
            panic!("expected AS_SEQUENCE");
        }
    }

    #[test]
    fn route_server_client_ebgp_does_not_prepend_asn() {
        let mut session = make_test_session(65001, 65002);
        session.config.route_server_client = true;
        let route = make_route(100);
        let attrs =
            session.prepare_outbound_attributes(&route, true, Ipv4Addr::new(10, 0, 0, 1), None);

        let as_path = attrs
            .iter()
            .find_map(|a| match a {
                PathAttribute::AsPath(p) => Some(p),
                _ => None,
            })
            .unwrap();

        assert_eq!(
            as_path.segments,
            vec![AsPathSegment::AsSequence(vec![65002])],
        );
    }

    #[test]
    fn route_server_client_ebgp_does_not_synthesize_as_path() {
        let mut session = make_test_session(65001, 65002);
        session.config.route_server_client = true;
        let route = Route {
            prefix: Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24)),
            next_hop: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            peer: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            attributes: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
            ],
            received_at: Instant::now(),
            origin_type: rustbgpd_rib::RouteOrigin::Local,
            peer_router_id: Ipv4Addr::UNSPECIFIED,
            is_stale: false,
            is_llgr_stale: false,
            path_id: 0,
            validation_state: rustbgpd_wire::RpkiValidation::NotFound,
        };
        let attrs =
            session.prepare_outbound_attributes(&route, true, Ipv4Addr::new(10, 0, 0, 1), None);

        assert!(!attrs.iter().any(|a| matches!(a, PathAttribute::AsPath(_))));
        assert!(attrs.iter().any(|a| matches!(
            a,
            PathAttribute::NextHop(nh) if *nh == Ipv4Addr::new(10, 0, 0, 2)
        )));
    }

    #[test]
    fn known_prefix_count_deduplicates_multiple_paths() {
        let mut session = make_test_session(65001, 65002);
        let prefix = Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24));

        session.known_paths.insert((prefix, 1));
        session.known_paths.insert((prefix, 2));

        assert_eq!(session.known_prefix_count(), 1);
    }

    #[test]
    fn ebgp_strips_local_pref() {
        let session = make_test_session(65001, 65002);
        let route = make_route(200);
        let attrs =
            session.prepare_outbound_attributes(&route, true, Ipv4Addr::new(10, 0, 0, 1), None);

        assert!(
            !attrs
                .iter()
                .any(|a| matches!(a, PathAttribute::LocalPref(_)))
        );
    }

    #[test]
    fn ibgp_preserves_local_pref() {
        let session = make_test_session(65001, 65001);
        let route = make_route(200);
        let attrs =
            session.prepare_outbound_attributes(&route, false, Ipv4Addr::new(10, 0, 0, 1), None);
        let lp = attrs.iter().find_map(|a| match a {
            PathAttribute::LocalPref(lp) => Some(*lp),
            _ => None,
        });
        assert_eq!(lp, Some(200));
    }

    #[test]
    fn ebgp_sets_next_hop() {
        let session = make_test_session(65001, 65002);
        let route = make_route(100);
        // In production, local_ipv4 is extracted from the TCP stream's local
        // address. Test sessions have no real stream, so the caller provides
        // the address directly. Here we simulate a real local address.
        let local_ipv4 = Ipv4Addr::new(172, 16, 0, 1);
        let attrs = session.prepare_outbound_attributes(&route, true, local_ipv4, None);

        let nh = attrs
            .iter()
            .find_map(|a| match a {
                PathAttribute::NextHop(nh) => Some(*nh),
                _ => None,
            })
            .unwrap();

        assert_eq!(nh, local_ipv4);
    }

    #[test]
    fn route_server_client_ebgp_preserves_next_hop() {
        let mut session = make_test_session(65001, 65002);
        session.config.route_server_client = true;
        let route = make_route(100);
        let attrs =
            session.prepare_outbound_attributes(&route, true, Ipv4Addr::new(172, 16, 0, 1), None);

        let nh = attrs
            .iter()
            .find_map(|a| match a {
                PathAttribute::NextHop(nh) => Some(*nh),
                _ => None,
            })
            .unwrap();

        assert_eq!(nh, Ipv4Addr::new(10, 0, 0, 2));
    }

    #[test]
    fn route_server_client_force_next_hop_self_still_wins() {
        let mut session = make_test_session(65001, 65002);
        session.config.route_server_client = true;
        let route = make_route(100);
        let local_ipv4 = Ipv4Addr::new(172, 16, 0, 1);
        let attrs = session.prepare_outbound_attributes(
            &route,
            true,
            local_ipv4,
            Some(&rustbgpd_policy::NextHopAction::Self_),
        );

        let nh = attrs
            .iter()
            .find_map(|a| match a {
                PathAttribute::NextHop(nh) => Some(*nh),
                _ => None,
            })
            .unwrap();

        assert_eq!(nh, local_ipv4);
    }

    #[test]
    fn route_server_client_still_strips_local_pref() {
        let mut session = make_test_session(65001, 65002);
        session.config.route_server_client = true;
        let route = make_route(200);
        let attrs =
            session.prepare_outbound_attributes(&route, true, Ipv4Addr::new(10, 0, 0, 1), None);

        assert!(
            !attrs
                .iter()
                .any(|a| matches!(a, PathAttribute::LocalPref(_)))
        );
    }

    #[test]
    fn ibgp_default_local_pref_when_missing() {
        let session = make_test_session(65001, 65001);
        let route = Route {
            prefix: Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24)),
            next_hop: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            peer: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            attributes: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath {
                    segments: vec![AsPathSegment::AsSequence(vec![65002])],
                }),
                PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
            ],
            received_at: Instant::now(),
            origin_type: rustbgpd_rib::RouteOrigin::Ibgp,
            peer_router_id: Ipv4Addr::UNSPECIFIED,
            is_stale: false,
            is_llgr_stale: false,
            path_id: 0,
            validation_state: rustbgpd_wire::RpkiValidation::NotFound,
        };
        let attrs =
            session.prepare_outbound_attributes(&route, false, Ipv4Addr::new(10, 0, 0, 1), None);

        let lp = attrs.iter().find_map(|a| match a {
            PathAttribute::LocalPref(lp) => Some(*lp),
            _ => None,
        });
        assert_eq!(lp, Some(100));
    }

    #[test]
    fn rr_does_not_add_originator_or_cluster_for_local_route() {
        let mut session = make_test_session(65001, 65001);
        session.config.cluster_id = Some(Ipv4Addr::new(10, 0, 0, 9));

        let route = Route {
            prefix: Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24)),
            next_hop: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            peer: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            attributes: vec![PathAttribute::Origin(Origin::Igp)],
            received_at: Instant::now(),
            origin_type: rustbgpd_rib::RouteOrigin::Local,
            peer_router_id: Ipv4Addr::UNSPECIFIED,
            is_stale: false,
            is_llgr_stale: false,
            path_id: 0,
            validation_state: rustbgpd_wire::RpkiValidation::NotFound,
        };

        let attrs =
            session.prepare_outbound_attributes(&route, false, Ipv4Addr::new(10, 0, 0, 1), None);

        assert!(!attrs.iter().any(|a| matches!(
            a,
            PathAttribute::OriginatorId(_) | PathAttribute::ClusterList(_)
        )));
    }

    #[test]
    fn rr_does_not_add_originator_or_cluster_for_ebgp_route() {
        let mut session = make_test_session(65001, 65001);
        session.config.cluster_id = Some(Ipv4Addr::new(10, 0, 0, 9));

        let route = make_route(100);
        let attrs =
            session.prepare_outbound_attributes(&route, false, Ipv4Addr::new(10, 0, 0, 1), None);

        assert!(!attrs.iter().any(|a| matches!(
            a,
            PathAttribute::OriginatorId(_) | PathAttribute::ClusterList(_)
        )));
    }

    #[test]
    fn rr_adds_originator_and_cluster_for_ibgp_route() {
        let mut session = make_test_session(65001, 65001);
        let cluster_id = Ipv4Addr::new(10, 0, 0, 9);
        let source_id = Ipv4Addr::new(10, 0, 0, 42);
        session.config.cluster_id = Some(cluster_id);

        let route = Route {
            prefix: Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24)),
            next_hop: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            peer: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            attributes: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath { segments: vec![] }),
            ],
            received_at: Instant::now(),
            origin_type: rustbgpd_rib::RouteOrigin::Ibgp,
            peer_router_id: source_id,
            is_stale: false,
            is_llgr_stale: false,
            path_id: 0,
            validation_state: rustbgpd_wire::RpkiValidation::NotFound,
        };

        let attrs =
            session.prepare_outbound_attributes(&route, false, Ipv4Addr::new(10, 0, 0, 1), None);

        assert!(
            attrs
                .iter()
                .any(|a| matches!(a, PathAttribute::OriginatorId(id) if *id == source_id))
        );
        assert!(attrs.iter().any(
            |a| matches!(a, PathAttribute::ClusterList(ids) if ids.as_slice() == [cluster_id])
        ));
    }

    #[tokio::test]
    async fn process_update_ignores_ipv4_mp_without_extended_nexthop() {
        let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
        let negotiated = negotiated_session(65002, false);
        session
            .negotiated_families
            .clone_from(&negotiated.negotiated_families);
        session.negotiated = Some(negotiated);

        let attrs = vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath {
                segments: vec![AsPathSegment::AsSequence(vec![65002])],
            }),
            PathAttribute::MpReachNlri(MpReachNlri {
                afi: Afi::Ipv4,
                safi: Safi::Unicast,
                next_hop: IpAddr::V6("2001:db8::1".parse().unwrap()),
                announced: vec![NlriEntry {
                    path_id: 0,
                    prefix: Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24)),
                }],
                flowspec_announced: vec![],
            }),
        ];
        let update = UpdateMessage::build(&[], &[], &attrs, true, false, Ipv4UnicastMode::MpReach);

        session.process_update(update).await;

        assert!(rib_rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn process_update_accepts_ipv4_mp_with_extended_nexthop() {
        let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
        let negotiated = negotiated_session(65002, true);
        session
            .negotiated_families
            .clone_from(&negotiated.negotiated_families);
        session.negotiated = Some(negotiated);

        let attrs = vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath {
                segments: vec![AsPathSegment::AsSequence(vec![65002])],
            }),
            PathAttribute::MpReachNlri(MpReachNlri {
                afi: Afi::Ipv4,
                safi: Safi::Unicast,
                next_hop: IpAddr::V6("2001:db8::1".parse().unwrap()),
                announced: vec![NlriEntry {
                    path_id: 0,
                    prefix: Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24)),
                }],
                flowspec_announced: vec![],
            }),
        ];
        let update = UpdateMessage::build(&[], &[], &attrs, true, false, Ipv4UnicastMode::MpReach);

        session.process_update(update).await;

        let RibUpdate::RoutesReceived { announced, .. } = rib_rx.try_recv().unwrap() else {
            panic!("expected RoutesReceived");
        };
        assert_eq!(announced.len(), 1);
        assert_eq!(
            announced[0].prefix,
            Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24))
        );
        assert_eq!(
            announced[0].next_hop,
            IpAddr::V6("2001:db8::1".parse().unwrap())
        );
    }

    #[tokio::test]
    async fn route_server_client_extended_nexthop_preserves_ipv6_next_hop() {
        let (mut session, _rib_rx) = make_test_session_with_rib(65001, 65002);
        let (client, mut server) = connected_stream_pair().await;
        session.stream = Some(client);
        session.config.route_server_client = true;

        let negotiated = negotiated_session(65002, true);
        session
            .negotiated_families
            .clone_from(&negotiated.negotiated_families);
        session.negotiated = Some(negotiated);

        let v6_nh: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let update = OutboundRouteUpdate {
            announce: vec![Route {
                prefix: Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24)),
                next_hop: IpAddr::V6(v6_nh),
                peer: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
                attributes: vec![
                    PathAttribute::Origin(Origin::Igp),
                    PathAttribute::AsPath(AsPath {
                        segments: vec![AsPathSegment::AsSequence(vec![65002])],
                    }),
                ],
                received_at: Instant::now(),
                origin_type: rustbgpd_rib::RouteOrigin::Ebgp,
                peer_router_id: Ipv4Addr::UNSPECIFIED,
                is_stale: false,
                is_llgr_stale: false,
                path_id: 0,
                validation_state: rustbgpd_wire::RpkiValidation::NotFound,
            }],
            withdraw: vec![],
            end_of_rib: vec![],
            refresh_markers: vec![],
            next_hop_override: vec![None],
            flowspec_announce: vec![],
            flowspec_withdraw: vec![],
        };

        session.send_route_update(update).await;

        let Message::Update(msg) = read_single_bgp_message(&mut server).await else {
            panic!("expected UPDATE");
        };
        let parsed = msg.parse(true, false, &[]).unwrap();
        let mp = parsed
            .attributes
            .iter()
            .find_map(|a| match a {
                PathAttribute::MpReachNlri(mp) => Some(mp),
                _ => None,
            })
            .unwrap();

        assert_eq!(mp.afi, Afi::Ipv4);
        assert_eq!(mp.safi, Safi::Unicast);
        assert_eq!(mp.next_hop, IpAddr::V6(v6_nh));
    }

    #[tokio::test]
    async fn route_server_client_ipv6_preserves_next_hop() {
        let (mut session, _rib_rx) = make_test_session_with_rib(65001, 65002);
        let (client, mut server) = connected_stream_pair().await;
        session.stream = Some(client);
        session.config.route_server_client = true;

        let mut negotiated = negotiated_session(65002, false);
        negotiated.negotiated_families = vec![(Afi::Ipv6, Safi::Unicast)];
        session
            .negotiated_families
            .clone_from(&negotiated.negotiated_families);
        session.negotiated = Some(negotiated);

        let v6_nh: Ipv6Addr = "2001:db8::2".parse().unwrap();
        let update = OutboundRouteUpdate {
            announce: vec![Route {
                prefix: Prefix::V6(Ipv6Prefix::new(v6_nh, 64)),
                next_hop: IpAddr::V6(v6_nh),
                peer: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
                attributes: vec![
                    PathAttribute::Origin(Origin::Igp),
                    PathAttribute::AsPath(AsPath {
                        segments: vec![AsPathSegment::AsSequence(vec![65002])],
                    }),
                ],
                received_at: Instant::now(),
                origin_type: rustbgpd_rib::RouteOrigin::Ebgp,
                peer_router_id: Ipv4Addr::UNSPECIFIED,
                is_stale: false,
                is_llgr_stale: false,
                path_id: 0,
                validation_state: rustbgpd_wire::RpkiValidation::NotFound,
            }],
            withdraw: vec![],
            end_of_rib: vec![],
            refresh_markers: vec![],
            next_hop_override: vec![None],
            flowspec_announce: vec![],
            flowspec_withdraw: vec![],
        };

        session.send_route_update(update).await;

        let Message::Update(msg) = read_single_bgp_message(&mut server).await else {
            panic!("expected UPDATE");
        };
        let parsed = msg.parse(true, false, &[]).unwrap();
        let mp = parsed
            .attributes
            .iter()
            .find_map(|a| match a {
                PathAttribute::MpReachNlri(mp) => Some(mp),
                _ => None,
            })
            .unwrap();

        assert_eq!(mp.afi, Afi::Ipv6);
        assert_eq!(mp.safi, Safi::Unicast);
        assert_eq!(mp.next_hop, IpAddr::V6(v6_nh));
    }

    /// Import policy is applied before `RoutesReceived` reaches the RIB.
    /// Denied routes are filtered locally in transport and never forwarded.
    #[tokio::test]
    async fn import_policy_denied_routes_do_not_reach_rib() {
        // Create a session with import policy that denies 198.51.100.0/24
        let peer_config = PeerConfig {
            local_asn: 65001,
            remote_asn: 65002,
            local_router_id: Ipv4Addr::new(10, 0, 0, 1),
            hold_time: 90,
            connect_retry_secs: 30,
            families: vec![(Afi::Ipv4, Safi::Unicast)],
            graceful_restart: false,
            gr_restart_time: 120,
            llgr_stale_time: 0,
            add_path_receive: false,
            add_path_send: false,
            add_path_send_max: 0,
        };
        let config = TransportConfig::new(peer_config, "10.0.0.2:179".parse().unwrap());
        let metrics = BgpMetrics::new();
        let (_cmd_tx, cmd_rx) = mpsc::channel(8);
        let (rib_tx, mut rib_rx) = mpsc::channel(64);

        let deny_policy = PolicyChain::new(vec![Policy {
            entries: vec![PolicyStatement {
                prefix: Some(Prefix::V4(Ipv4Prefix::new(
                    Ipv4Addr::new(198, 51, 100, 0),
                    24,
                ))),
                ge: None,
                le: None,
                action: PolicyAction::Deny,
                match_community: vec![],
                match_as_path: None,
                match_rpki_validation: None,
                modifications: RouteModifications::default(),
            }],
            default_action: PolicyAction::Permit,
        }]);

        let mut session = PeerSession::new(
            config,
            metrics,
            cmd_rx,
            rib_tx,
            Some(deny_policy),
            None,
            None,
            None,
        );
        let mut negotiated = negotiated_session(65002, false);
        negotiated.peer_enhanced_route_refresh = true;
        session
            .negotiated_families
            .clone_from(&negotiated.negotiated_families);
        session.negotiated = Some(negotiated);

        // Send an UPDATE with 198.51.100.0/24 — should be denied by import policy
        let denied_prefix = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 0), 24);
        let permitted_prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, 0), 24);

        let attrs = vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath {
                segments: vec![AsPathSegment::AsSequence(vec![65002])],
            }),
            PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
        ];

        // Both prefixes in one UPDATE: one permitted, one denied
        let denied_nlri = Ipv4NlriEntry {
            path_id: 0,
            prefix: denied_prefix,
        };
        let permitted_nlri = Ipv4NlriEntry {
            path_id: 0,
            prefix: permitted_prefix,
        };
        let update = UpdateMessage::build(
            &[denied_nlri, permitted_nlri],
            &[],
            &attrs,
            true,
            false,
            Ipv4UnicastMode::Body,
        );
        session.process_update(update).await;

        // Drain any messages — there may be zero or one RoutesReceived
        let mut all_announced = vec![];
        while let Ok(msg) = rib_rx.try_recv() {
            if let RibUpdate::RoutesReceived { announced, .. } = msg {
                all_announced.extend(announced);
            }
        }
        // Only the permitted prefix should reach the RIB; denied prefix filtered
        assert_eq!(
            all_announced.len(),
            1,
            "expected exactly 1 announced route, got {}: {all_announced:?}",
            all_announced.len()
        );
        assert_eq!(all_announced[0].prefix, Prefix::V4(permitted_prefix));
    }

    /// End-to-end ERR + import policy interaction:
    /// a stale route that is "replaced" by an inbound UPDATE denied by import
    /// policy is not reinstalled, so the stale entry is swept at `EoRR`.
    #[expect(clippy::too_many_lines)]
    #[tokio::test]
    async fn err_denied_replacement_is_swept_at_eorr() {
        let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let (rib_tx, rib_rx) = mpsc::channel(64);
        let manager = rustbgpd_rib::RibManager::new(rib_rx, None, None, BgpMetrics::new());
        let manager_handle = tokio::spawn(manager.run());

        let denied_prefix = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 0), 24);
        let permitted_prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, 0), 24);

        // Seed the RIB with an existing route that will become refresh-stale.
        rib_tx
            .send(RibUpdate::RoutesReceived {
                peer,
                announced: vec![Route {
                    prefix: Prefix::V4(denied_prefix),
                    next_hop: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
                    peer,
                    attributes: vec![
                        PathAttribute::Origin(Origin::Igp),
                        PathAttribute::AsPath(AsPath {
                            segments: vec![AsPathSegment::AsSequence(vec![65002])],
                        }),
                        PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
                    ],
                    received_at: Instant::now(),
                    origin_type: rustbgpd_rib::RouteOrigin::Ebgp,
                    peer_router_id: Ipv4Addr::UNSPECIFIED,
                    is_stale: false,
                    is_llgr_stale: false,
                    path_id: 0,
                    validation_state: rustbgpd_wire::RpkiValidation::NotFound,
                }],
                withdrawn: vec![],
                flowspec_announced: vec![],
                flowspec_withdrawn: vec![],
            })
            .await
            .unwrap();

        // Start the ERR refresh window for IPv4 unicast.
        rib_tx
            .send(RibUpdate::BeginRouteRefresh {
                peer,
                afi: Afi::Ipv4,
                safi: Safi::Unicast,
            })
            .await
            .unwrap();

        // Session import policy denies the stale prefix, but permits the new one.
        let peer_config = PeerConfig {
            local_asn: 65001,
            remote_asn: 65002,
            local_router_id: Ipv4Addr::new(10, 0, 0, 1),
            hold_time: 90,
            connect_retry_secs: 30,
            families: vec![(Afi::Ipv4, Safi::Unicast)],
            graceful_restart: false,
            gr_restart_time: 120,
            llgr_stale_time: 0,
            add_path_receive: false,
            add_path_send: false,
            add_path_send_max: 0,
        };
        let config = TransportConfig::new(peer_config, "10.0.0.2:179".parse().unwrap());
        let metrics = BgpMetrics::new();
        let (_cmd_tx, cmd_rx) = mpsc::channel(8);

        let deny_policy = PolicyChain::new(vec![Policy {
            entries: vec![PolicyStatement {
                prefix: Some(Prefix::V4(denied_prefix)),
                ge: None,
                le: None,
                action: PolicyAction::Deny,
                match_community: vec![],
                match_as_path: None,
                match_rpki_validation: None,
                modifications: RouteModifications::default(),
            }],
            default_action: PolicyAction::Permit,
        }]);

        let mut session = PeerSession::new(
            config,
            metrics,
            cmd_rx,
            rib_tx.clone(),
            Some(deny_policy),
            None,
            None,
            None,
        );
        let mut negotiated = negotiated_session(65002, false);
        negotiated.peer_enhanced_route_refresh = true;
        session
            .negotiated_families
            .clone_from(&negotiated.negotiated_families);
        session.negotiated = Some(negotiated);

        let attrs = vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath {
                segments: vec![AsPathSegment::AsSequence(vec![65002])],
            }),
            PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
        ];

        // The denied prefix is filtered by import policy, so only the permitted
        // replacement reaches the RIB during the refresh window.
        let update = UpdateMessage::build(
            &[
                Ipv4NlriEntry {
                    path_id: 0,
                    prefix: denied_prefix,
                },
                Ipv4NlriEntry {
                    path_id: 0,
                    prefix: permitted_prefix,
                },
            ],
            &[],
            &attrs,
            true,
            false,
            Ipv4UnicastMode::Body,
        );
        session.process_update(update).await;

        // Close the refresh window; the unreplaced stale route should be swept.
        rib_tx
            .send(RibUpdate::EndRouteRefresh {
                peer,
                afi: Afi::Ipv4,
                safi: Safi::Unicast,
            })
            .await
            .unwrap();

        let (reply_tx, reply_rx) = oneshot::channel();
        rib_tx
            .send(RibUpdate::QueryReceivedRoutes {
                peer: Some(peer),
                reply: reply_tx,
            })
            .await
            .unwrap();
        let received = reply_rx.await.unwrap();

        assert_eq!(received.len(), 1);
        assert_eq!(received[0].prefix, Prefix::V4(permitted_prefix));

        drop(session);
        drop(rib_tx);
        manager_handle.await.unwrap();
    }

    #[tokio::test]
    async fn process_update_accepts_ipv4_mp_with_extended_nexthop_and_add_path() {
        let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
        let mut negotiated = negotiated_session(65002, true);
        // Enable Add-Path receive for IPv4 unicast
        negotiated
            .add_path_families
            .insert((Afi::Ipv4, Safi::Unicast), AddPathMode::Both);
        session
            .negotiated_families
            .clone_from(&negotiated.negotiated_families);
        session.negotiated = Some(negotiated);

        let attrs = vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath {
                segments: vec![AsPathSegment::AsSequence(vec![65002])],
            }),
            PathAttribute::MpReachNlri(MpReachNlri {
                afi: Afi::Ipv4,
                safi: Safi::Unicast,
                next_hop: IpAddr::V6("2001:db8::1".parse().unwrap()),
                announced: vec![NlriEntry {
                    path_id: 42,
                    prefix: Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24)),
                }],
                flowspec_announced: vec![],
            }),
        ];
        // Build with Add-Path enabled and MP encoding
        let update = UpdateMessage::build(&[], &[], &attrs, true, true, Ipv4UnicastMode::MpReach);

        session.process_update(update).await;

        let RibUpdate::RoutesReceived { announced, .. } = rib_rx.try_recv().unwrap() else {
            panic!("expected RoutesReceived");
        };
        assert_eq!(announced.len(), 1);
        assert_eq!(
            announced[0].prefix,
            Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24))
        );
        assert_eq!(
            announced[0].next_hop,
            IpAddr::V6("2001:db8::1".parse().unwrap())
        );
        assert_eq!(announced[0].path_id, 42);
    }
}
