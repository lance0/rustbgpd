use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ops::ControlFlow;
use std::pin::Pin;
use std::time::{Duration, Instant};

use rustbgpd_fsm::{Action, Event, NegotiatedSession, Session, SessionState};
use rustbgpd_policy::PrefixList;
use rustbgpd_rib::{OutboundRouteUpdate, RibUpdate, Route};
use rustbgpd_telemetry::BgpMetrics;
use rustbgpd_wire::notification::{NotificationCode, cease_subcode};
use rustbgpd_wire::{
    Afi, AsPath, AsPathSegment, Ipv4Prefix, Message, MpReachNlri, MpUnreachNlri,
    NotificationMessage, PathAttribute, Prefix, Safi, UpdateMessage, encode_message,
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
    import_policy: Option<PrefixList>,
    /// Export policy (sent to RIB manager on `PeerUp` for per-peer filtering).
    export_policy: Option<PrefixList>,
    /// Channel to notify `PeerManager` of session state changes (collision detection).
    /// Unbounded so notifications are never dropped and never block (avoids
    /// deadlock with `QueryState`). Rate is naturally bounded by FSM transitions.
    session_notify_tx: Option<mpsc::UnboundedSender<SessionNotification>>,
    /// Accepted prefixes for accurate count and dedup.
    known_prefixes: HashSet<Prefix>,
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

impl PeerSession {
    pub(crate) fn new(
        config: TransportConfig,
        metrics: BgpMetrics,
        commands: mpsc::Receiver<PeerCommand>,
        rib_tx: mpsc::Sender<RibUpdate>,
        import_policy: Option<PrefixList>,
        export_policy: Option<PrefixList>,
        session_notify_tx: Option<mpsc::UnboundedSender<SessionNotification>>,
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
            known_prefixes: HashSet::new(),
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
        import_policy: Option<PrefixList>,
        export_policy: Option<PrefixList>,
        stream: TcpStream,
        session_notify_tx: Option<mpsc::UnboundedSender<SessionNotification>>,
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
            known_prefixes: HashSet::new(),
            updates_received: 0,
            updates_sent: 0,
            notifications_received: 0,
            notifications_sent: 0,
            flap_count: 0,
            established_at: None,
            last_error: String::new(),
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
                Action::SendOpen(open) => {
                    let msg = Message::Open(open);
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
                            .filter(|f| **f != (Afi::Ipv6, Safi::Unicast) || has_v6_nh)
                            .copied()
                            .collect()
                    } else {
                        neg.negotiated_families.clone()
                    };

                    self.negotiated = Some(neg);
                    self.established_at = Some(Instant::now());
                    // Register with RIB manager for outbound updates
                    let _ = self.rib_tx.try_send(RibUpdate::PeerUp {
                        peer: self.peer_ip,
                        outbound_tx: self.outbound_tx.clone(),
                        export_policy: self.export_policy.clone(),
                        sendable_families,
                    });
                }
                Action::SessionDown => {
                    info!(peer = %self.peer_label, "session down");
                    // Check GR state before clearing negotiated info
                    let gr_update = self.negotiated.as_ref().and_then(|neg| {
                        if neg.peer_gr_capable && neg.peer_restart_state {
                            let preserved: Vec<(Afi, Safi)> = neg
                                .peer_gr_families
                                .iter()
                                .filter(|f| f.forwarding_preserved)
                                .map(|f| (f.afi, f.safi))
                                .collect();
                            Some(RibUpdate::PeerGracefulRestart {
                                peer: self.peer_ip,
                                restart_time: neg.peer_restart_time,
                                stale_routes_time: self.config.gr_stale_routes_time,
                                preserved_families: preserved,
                            })
                        } else {
                            None
                        }
                    });

                    self.negotiated = None;
                    self.negotiated_families.clear();
                    self.known_prefixes.clear();
                    if self.established_at.take().is_some() {
                        self.flap_count += 1;
                    }

                    let rib_msg = gr_update.unwrap_or(RibUpdate::PeerDown { peer: self.peer_ip });
                    let _ = self.rib_tx.try_send(rib_msg);
                }
            }
        }

        follow_up
    }

    /// Encode and send a BGP message to the peer.
    async fn send_message(&mut self, msg: &Message) -> Result<(), TransportError> {
        let encoded = encode_message(msg)?;
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
    async fn process_read_buffer(&mut self) {
        loop {
            match self.read_buf.try_decode() {
                Ok(Some(msg)) => {
                    let event = match msg {
                        Message::Open(open) => {
                            self.metrics
                                .record_message_received(&self.peer_label, "open");
                            Event::OpenReceived(open)
                        }
                        Message::Keepalive => {
                            self.metrics
                                .record_message_received(&self.peer_label, "keepalive");
                            Event::KeepaliveReceived
                        }
                        Message::Notification(notif) => {
                            self.notifications_received += 1;
                            self.last_error = format!("{}/{}", notif.code.as_u8(), notif.subcode);
                            self.metrics.record_notification_received(
                                &self.peer_label,
                                &notif.code.as_u8().to_string(),
                                &notif.subcode.to_string(),
                            );
                            self.metrics
                                .record_message_received(&self.peer_label, "notification");
                            Event::NotificationReceived(notif)
                        }
                        Message::Update(update) => {
                            self.updates_received += 1;
                            self.metrics
                                .record_message_received(&self.peer_label, "update");
                            self.process_update(update).await;
                            continue;
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
    fn is_family_negotiated(&self, prefix: &Prefix) -> bool {
        let family = match prefix {
            Prefix::V4(_) => (Afi::Ipv4, Safi::Unicast),
            Prefix::V6(_) => (Afi::Ipv6, Safi::Unicast),
        };
        self.negotiated_families.contains(&family)
    }

    /// Parse an UPDATE message, validate attributes, apply import policy,
    /// enforce max-prefix limit, send routes to RIB, and feed the
    /// appropriate event to the FSM.
    #[expect(clippy::too_many_lines)]
    async fn process_update(&mut self, update: rustbgpd_wire::UpdateMessage) {
        let four_octet_as = self.negotiated.as_ref().is_some_and(|n| n.four_octet_as);

        // 1. Structural decode
        let parsed = match update.parse(four_octet_as) {
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
            // IPv6 EoR: UPDATE with only an empty MP_UNREACH_NLRI
            if parsed.attributes.len() == 1
                && let Some(PathAttribute::MpUnreachNlri(mp)) = parsed.attributes.first()
                && mp.withdrawn.is_empty()
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

        // Body NLRI routes (IPv4)
        let mut announced: Vec<Route> = parsed
            .announced
            .iter()
            .filter(|prefix| {
                rustbgpd_policy::check_prefix_list(
                    self.import_policy.as_ref(),
                    Prefix::V4(**prefix),
                ) == rustbgpd_policy::PolicyAction::Permit
            })
            .map(|prefix| Route {
                prefix: Prefix::V4(*prefix),
                next_hop: body_next_hop,
                peer: self.peer_ip,
                attributes: route_attrs.clone(),
                received_at: now,
                is_ebgp,
                is_stale: false,
            })
            .collect();

        // Body withdrawn routes (IPv4)
        let mut withdrawn: Vec<Prefix> = parsed.withdrawn.iter().map(|p| Prefix::V4(*p)).collect();

        // MP-BGP NLRI from attributes
        // For IPv6 routes, also strip body NEXT_HOP — it's IPv4-specific and
        // would contaminate IPv6 route attributes in mixed UPDATEs.
        let mp_route_attrs: Vec<PathAttribute> = route_attrs
            .iter()
            .filter(|a| !matches!(a, PathAttribute::NextHop(_)))
            .cloned()
            .collect();

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
                    for prefix in &mp.announced {
                        if rustbgpd_policy::check_prefix_list(self.import_policy.as_ref(), *prefix)
                            == rustbgpd_policy::PolicyAction::Permit
                        {
                            announced.push(Route {
                                prefix: *prefix,
                                next_hop: mp.next_hop,
                                peer: self.peer_ip,
                                attributes: mp_route_attrs.clone(),
                                received_at: now,
                                is_ebgp,
                                is_stale: false,
                            });
                        }
                    }
                }
                PathAttribute::MpUnreachNlri(mp) => {
                    let family = (mp.afi, mp.safi);
                    if !self.negotiated_families.contains(&family) {
                        continue;
                    }
                    withdrawn.extend_from_slice(&mp.withdrawn);
                }
                _ => {}
            }
        }

        // 4. Max-prefix enforcement — track via HashSet for accuracy
        for prefix in &withdrawn {
            self.known_prefixes.remove(prefix);
        }
        for route in &announced {
            self.known_prefixes.insert(route.prefix);
        }

        if let Some(max) = self.config.max_prefixes
            && self.known_prefixes.len() > max as usize
        {
            warn!(
                peer = %self.peer_label,
                count = self.known_prefixes.len(),
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

        if !announced.is_empty() || !withdrawn.is_empty() {
            let _ = self.rib_tx.try_send(RibUpdate::RoutesReceived {
                peer: self.peer_ip,
                announced,
                withdrawn,
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
            PeerCommand::Stop => {
                self.stop_requested = true;
                self.reconnect_timer = None;
                self.drive_fsm(Event::ManualStop).await;
                ControlFlow::Continue(())
            }
            PeerCommand::Shutdown => {
                self.stop_requested = true;
                self.reconnect_timer = None;
                info!(peer = %self.peer_label, "shutdown requested");
                if self.fsm.state() == SessionState::Established {
                    self.drive_fsm(Event::ManualStop).await;
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
                    prefix_count: self.known_prefixes.len(),
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
        let mut v4_withdraw: Vec<Ipv4Prefix> = Vec::new();
        let mut v6_withdraw: Vec<Prefix> = Vec::new();
        for prefix in &update.withdraw {
            if !self.is_family_negotiated(prefix) {
                continue;
            }
            match prefix {
                Prefix::V4(v4) => v4_withdraw.push(*v4),
                Prefix::V6(_) => v6_withdraw.push(*prefix),
            }
        }

        // Send IPv4 withdrawals via body NLRI
        if !v4_withdraw.is_empty() {
            let msg = UpdateMessage::build(&[], &v4_withdraw, &[], four_octet_as);
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
            })];
            let msg = UpdateMessage::build(&[], &[], &attrs, four_octet_as);
            let wire_msg = Message::Update(msg);
            if let Err(e) = self.send_message(&wire_msg).await {
                warn!(peer = %self.peer_label, error = %e, "failed to send v6 withdrawal UPDATE");
                return;
            }
            self.updates_sent += 1;
            self.metrics.record_message_sent(&self.peer_label, "update");
        }

        // Split announcements by address family, filtering by negotiated families
        let mut v4_routes: Vec<&Route> = Vec::new();
        let mut v6_routes: Vec<&Route> = Vec::new();
        for route in &update.announce {
            if !self.is_family_negotiated(&route.prefix) {
                continue;
            }
            match route.prefix {
                Prefix::V4(_) => v4_routes.push(route),
                Prefix::V6(_) => v6_routes.push(route),
            }
        }

        // Send IPv4 announcements via body NLRI — batch by identical attributes
        let mut v4_groups: Vec<(Vec<PathAttribute>, Vec<Ipv4Prefix>)> = Vec::new();
        for route in &v4_routes {
            let attrs = self.prepare_outbound_attributes(route, is_ebgp, local_ipv4);
            if let Prefix::V4(v4) = route.prefix {
                if let Some(group) = v4_groups.iter_mut().find(|(a, _)| *a == attrs) {
                    group.1.push(v4);
                } else {
                    v4_groups.push((attrs, vec![v4]));
                }
            }
        }

        for (attrs, prefixes) in &v4_groups {
            let msg = UpdateMessage::build(prefixes, &[], attrs, four_octet_as);
            let wire_msg = Message::Update(msg);
            if let Err(e) = self.send_message(&wire_msg).await {
                warn!(peer = %self.peer_label, error = %e, "failed to send announce UPDATE");
                return;
            }
            self.updates_sent += 1;
            self.metrics.record_message_sent(&self.peer_label, "update");
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
        if is_ebgp && ebgp_ipv6_nh.is_none() && !v6_routes.is_empty() {
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
        let mut v6_groups: Vec<(Vec<PathAttribute>, IpAddr, Vec<Prefix>)> = Vec::new();
        for route in &v6_routes {
            let attrs = self.prepare_outbound_attributes(route, is_ebgp, local_ipv4);
            let nh = if is_ebgp {
                // Safe: guarded above — ebgp_ipv6_nh is Some if we reach here
                IpAddr::V6(ebgp_ipv6_nh.unwrap_or(Ipv6Addr::UNSPECIFIED))
            } else {
                route.next_hop
            };
            if let Some(group) = v6_groups
                .iter_mut()
                .find(|(a, h, _)| *a == attrs && *h == nh)
            {
                group.2.push(route.prefix);
            } else {
                v6_groups.push((attrs, nh, vec![route.prefix]));
            }
        }

        for (mut attrs, nh, prefixes) in v6_groups {
            attrs.push(PathAttribute::MpReachNlri(MpReachNlri {
                afi: Afi::Ipv6,
                safi: Safi::Unicast,
                next_hop: nh,
                announced: prefixes,
            }));
            let msg = UpdateMessage::build(&[], &[], &attrs, four_octet_as);
            let wire_msg = Message::Update(msg);
            if let Err(e) = self.send_message(&wire_msg).await {
                warn!(peer = %self.peer_label, error = %e, "failed to send v6 announce UPDATE");
                return;
            }
            self.updates_sent += 1;
            self.metrics.record_message_sent(&self.peer_label, "update");
        }

        // Send End-of-RIB markers
        for (afi, safi) in &update.end_of_rib {
            let msg = match (afi, safi) {
                // IPv4 Unicast EoR: empty UPDATE (no NLRI, no withdrawn, no attrs)
                (Afi::Ipv4, Safi::Unicast) => UpdateMessage::build(&[], &[], &[], four_octet_as),
                // IPv6 Unicast EoR: UPDATE with empty MP_UNREACH_NLRI
                (Afi::Ipv6, Safi::Unicast) => {
                    let attrs = vec![PathAttribute::MpUnreachNlri(MpUnreachNlri {
                        afi: Afi::Ipv6,
                        safi: Safi::Unicast,
                        withdrawn: vec![],
                    })];
                    UpdateMessage::build(&[], &[], &attrs, four_octet_as)
                }
                _ => continue,
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
    /// For eBGP: prepend our ASN, set `NEXT_HOP` to local addr, strip `LOCAL_PREF`.
    /// For iBGP: ensure `LOCAL_PREF` present (default 100), pass `NEXT_HOP` through.
    fn prepare_outbound_attributes(
        &self,
        route: &Route,
        is_ebgp: bool,
        local_ipv4: Ipv4Addr,
    ) -> Vec<PathAttribute> {
        let mut attrs = Vec::new();

        for attr in &route.attributes {
            match attr {
                PathAttribute::AsPath(as_path) => {
                    if is_ebgp {
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
                    if is_ebgp {
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

        // For eBGP, ensure AS_PATH is present (even if empty)
        if is_ebgp && !attrs.iter().any(|a| matches!(a, PathAttribute::AsPath(_))) {
            attrs.push(PathAttribute::AsPath(AsPath {
                segments: vec![AsPathSegment::AsSequence(vec![self.config.peer.local_asn])],
            }));
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
    use std::net::Ipv4Addr;
    use std::time::Instant;

    use rustbgpd_fsm::PeerConfig;
    use rustbgpd_wire::{AsPath, AsPathSegment, Origin, PathAttribute};

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
        };
        let config = TransportConfig::new(peer_config, "10.0.0.2:179".parse().unwrap());
        let metrics = BgpMetrics::new();
        let (_cmd_tx, cmd_rx) = mpsc::channel(8);
        let (rib_tx, _rib_rx) = mpsc::channel(64);

        PeerSession::new(config, metrics, cmd_rx, rib_tx, None, None, None)
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
            is_ebgp: true,
            is_stale: false,
        }
    }

    #[test]
    fn ebgp_prepends_asn() {
        let session = make_test_session(65001, 65002);
        let route = make_route(100);
        let attrs = session.prepare_outbound_attributes(&route, true, Ipv4Addr::new(10, 0, 0, 1));

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
    fn ebgp_strips_local_pref() {
        let session = make_test_session(65001, 65002);
        let route = make_route(200);
        let attrs = session.prepare_outbound_attributes(&route, true, Ipv4Addr::new(10, 0, 0, 1));

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
        let attrs = session.prepare_outbound_attributes(&route, false, Ipv4Addr::new(10, 0, 0, 1));
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
        let attrs = session.prepare_outbound_attributes(&route, true, local_ipv4);

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
            is_ebgp: false,
            is_stale: false,
        };
        let attrs = session.prepare_outbound_attributes(&route, false, Ipv4Addr::new(10, 0, 0, 1));

        let lp = attrs.iter().find_map(|a| match a {
            PathAttribute::LocalPref(lp) => Some(*lp),
            _ => None,
        });
        assert_eq!(lp, Some(100));
    }
}
