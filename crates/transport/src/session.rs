use std::net::IpAddr;
use std::ops::ControlFlow;
use std::pin::Pin;
use std::time::{Duration, Instant};

use rustbgpd_fsm::{Action, Event, NegotiatedSession, Session, SessionState};
use rustbgpd_rib::{RibUpdate, Route};
use rustbgpd_telemetry::BgpMetrics;
use rustbgpd_wire::notification::NotificationCode;
use rustbgpd_wire::{Message, NotificationMessage, encode_message};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::time::Sleep;
use tracing::{debug, error, info, warn};

use crate::config::TransportConfig;
use crate::error::TransportError;
use crate::framing::ReadBuffer;
use crate::handle::PeerCommand;
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
    /// Negotiated session parameters (set when Established).
    negotiated: Option<NegotiatedSession>,
    /// Suppresses automatic restart when the FSM transitions to Idle.
    /// Set when the operator sends `ManualStop` or `Shutdown`.
    stop_requested: bool,
    /// Deferred reconnect timer. When the FSM falls to Idle unexpectedly,
    /// this timer fires after the connect-retry interval to avoid a hot
    /// reconnect loop (e.g., persistent OPEN validation failures).
    reconnect_timer: Option<Pin<Box<Sleep>>>,
}

impl PeerSession {
    pub(crate) fn new(
        config: TransportConfig,
        metrics: BgpMetrics,
        commands: mpsc::Receiver<PeerCommand>,
        rib_tx: mpsc::Sender<RibUpdate>,
    ) -> Self {
        let peer_label = config.remote_addr.to_string();
        let peer_ip = config.remote_addr.ip();
        let fsm = Session::new(config.peer.clone());
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
            stop_requested: false,
            reconnect_timer: None,
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
                    self.negotiated = Some(neg);
                }
                Action::SessionDown => {
                    info!(peer = %self.peer_label, "session down");
                    self.negotiated = None;
                    let _ = self
                        .rib_tx
                        .try_send(RibUpdate::PeerDown { peer: self.peer_ip });
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
    /// Returns the FSM event to fire (connected or failed).
    async fn attempt_connect(&mut self) -> Option<Event> {
        debug!(peer = %self.peer_label, addr = %self.config.remote_addr, "connecting");

        match tokio::time::timeout(
            self.config.connect_timeout,
            TcpStream::connect(self.config.remote_addr),
        )
        .await
        {
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

    /// Parse an UPDATE message, validate attributes, send routes to RIB,
    /// and feed the appropriate event to the FSM.
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
        let has_nlri = !parsed.announced.is_empty();
        let is_ebgp = self
            .negotiated
            .as_ref()
            .is_some_and(|n| n.peer_asn != self.config.peer.local_asn);

        if let Err(update_err) = rustbgpd_wire::validate::validate_update_attributes(
            &parsed.attributes,
            has_nlri,
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

        // 3. Build routes and send to RIB
        let next_hop = parsed
            .attributes
            .iter()
            .find_map(|a| {
                if let rustbgpd_wire::PathAttribute::NextHop(nh) = a {
                    Some(*nh)
                } else {
                    None
                }
            })
            .unwrap_or(match self.peer_ip {
                IpAddr::V4(v4) => v4,
                IpAddr::V6(_) => std::net::Ipv4Addr::UNSPECIFIED,
            });

        let now = Instant::now();
        let announced: Vec<Route> = parsed
            .announced
            .iter()
            .map(|prefix| Route {
                prefix: *prefix,
                next_hop,
                attributes: parsed.attributes.clone(),
                received_at: now,
            })
            .collect();

        if !announced.is_empty() || !parsed.withdrawn.is_empty() {
            let _ = self.rib_tx.try_send(RibUpdate::RoutesReceived {
                peer: self.peer_ip,
                announced,
                withdrawn: parsed.withdrawn,
            });
        }

        // 4. Tell FSM about the update (restarts hold timer)
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
        }
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
