use super::{
    BmpEvent, Bytes, Event, Message, NotificationCode, OwnedReadHalf, PeerDownReason, PeerSession,
    RibUpdate, RouteRefreshSubtype, SessionNotificationDirection, TcpStream, TransportError,
    cease_subcode, debug, error, info, warn,
};
use crate::config::TransportConfig;
use rustbgpd_wire::{AddressPrefixOrf, OrfAction, OrfEntries, OrfMatch, OrfType};
use tokio::sync::{mpsc, oneshot};
use tokio::task::{JoinError, JoinHandle};

impl PeerSession {
    /// Handle the ORF section of an inbound ROUTE-REFRESH (RFC 5291/5292).
    ///
    /// Returns `true` if at least one Address-Prefix ORF group of a negotiated
    /// type was forwarded to the RIB — its `PeerOrfUpdate` handler installs the
    /// filter, lifts the §6 initial-advertisement gate, and re-floods. Returns
    /// `false` for a plain refresh, or an ORF whose groups are all
    /// un-negotiated types (incl. the legacy type 128, which rustbgpd never
    /// advertises); the caller then takes the normal re-advertise path.
    pub(super) async fn process_inbound_orf(
        &mut self,
        afi: rustbgpd_wire::Afi,
        safi: rustbgpd_wire::Safi,
        rr: &rustbgpd_wire::RouteRefreshMessage,
    ) -> bool {
        let Some(orf) = &rr.orf else {
            return false;
        };
        let negotiated = self
            .negotiated
            .as_ref()
            .is_some_and(|n| n.negotiated_orf_recv.contains(&(afi, safi)));
        if !negotiated {
            warn!(
                peer = %self.peer_label,
                ?afi, ?safi,
                "ignoring ORF entries — ORF not negotiated for this family"
            );
            return false;
        }
        let mut handled = false;
        for group in &orf.groups {
            // rustbgpd only negotiates/advertises the standard type 64.
            if group.orf_type != OrfType::AddressPrefix {
                continue;
            }
            let entries = match &group.entries {
                OrfEntries::AddressPrefix(entries) => entries.clone(),
                // RFC 5291 §5.2: a malformed entry of a negotiated type removes
                // the previously installed list of that type — emit a reset.
                OrfEntries::Malformed(_) => vec![AddressPrefixOrf {
                    action: OrfAction::RemoveAll,
                    match_: OrfMatch::Permit,
                    sequence: 0,
                    min_len: 0,
                    max_len: 0,
                    prefix: None,
                }],
                OrfEntries::Raw(_) => continue,
            };
            let (reply, _rx) = oneshot::channel();
            if self
                .rib_tx
                .send(RibUpdate::PeerOrfUpdate {
                    peer: self.peer_ip,
                    session_id: self.session_identity.id,
                    afi,
                    safi,
                    when: orf.when_to_refresh,
                    entries,
                    reply,
                })
                .await
                .is_err()
            {
                warn!(peer = %self.peer_label, "RIB manager unavailable — ORF update dropped");
            } else {
                handled = true;
            }
        }
        handled
    }

    /// Encode `msg` and enqueue it on the writer's **priority** channel
    /// (OPEN, KEEPALIVE, NOTIFICATION, operator ROUTE-REFRESH command,
    /// collision-dump Cease, saturation Cease/8). The priority channel
    /// is unbounded so this only ever reports `WriterClosed` when the
    /// session has no active TCP connection — same effect as today's
    /// "no stream" branch, just at a different layer.
    pub(super) fn enqueue_priority(&mut self, msg: &Message) -> Result<(), TransportError> {
        let max_len = self.max_message_len();
        let encoded = rustbgpd_wire::encode_message_with_limit(msg, max_len)?;
        let Some(tx) = self.writer_priority_tx.as_ref() else {
            debug!(
                peer = %self.peer_label,
                msg_type = %msg.message_type(),
                "cannot send — not connected (priority)"
            );
            return Ok(());
        };
        tx.send(Bytes::from(encoded))
            .map_err(|_| TransportError::WriterClosed)
    }

    /// Encode `msg` and enqueue it on the writer's **bulk** channel
    /// (`UPDATE`, `RouteRefresh` `BoRR`/`EoRR` markers, `EoR` markers). Returns
    /// `OutboundChannelFull` when the writer hasn't drained the bounded
    /// queue — callers should pair this with [`Self::trigger_outbound_saturation_teardown`]
    /// rather than just logging and continuing. `WriterClosed` if there
    /// is no active TCP connection.
    pub(super) fn enqueue_bulk(&mut self, msg: &Message) -> Result<(), TransportError> {
        let max_len = self.max_message_len();
        let encoded = rustbgpd_wire::encode_message_with_limit(msg, max_len)?;
        // Clone the sender so the caller's mutable borrow of self is
        // free for the saturation handler if try_send returns Full.
        let Some(tx) = self.writer_bulk_tx.clone() else {
            debug!(
                peer = %self.peer_label,
                msg_type = %msg.message_type(),
                "cannot send — not connected (bulk)"
            );
            return Ok(());
        };
        match tx.try_send(Bytes::from(encoded)) {
            Ok(()) => Ok(()),
            Err(mpsc::error::TrySendError::Full(_)) => {
                // Centralize the saturation policy here so all 13+
                // bulk callers in `outbound.rs` get the same behavior:
                // send `Cease/Out-of-Resources`, drop writer senders,
                // let the run-loop's writer-exit arm drive teardown.
                // Caller still receives `Err(OutboundChannelFull)` so
                // it knows to abort the rest of the batch.
                self.trigger_outbound_saturation_teardown();
                Err(TransportError::OutboundChannelFull)
            }
            Err(mpsc::error::TrySendError::Closed(_)) => Err(TransportError::WriterClosed),
        }
    }

    /// Start an outbound TCP connection in the background so the main session
    /// loop can continue servicing commands while connect is in flight.
    pub(super) fn start_connect_attempt(&mut self) {
        if self.read_half.is_some() || self.connect_task.is_some() {
            return;
        }

        let config = self.config.clone();
        let peer_label = self.peer_label.clone();
        debug!(peer = %peer_label, addr = %config.remote_addr, "connecting");
        self.connect_task = Some(tokio::spawn(async move {
            match tokio::time::timeout(
                config.connect_timeout,
                create_and_connect(config.clone(), peer_label.clone()),
            )
            .await
            {
                Ok(result) => result,
                Err(_elapsed) => Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    format!("TCP connect to {} timed out", config.remote_addr),
                )),
            }
        }));
    }

    /// Tear the session down because the writer's bulk channel
    /// saturated — the peer hasn't drained `OUTBOUND_BUFFER` BGP
    /// messages, so we send a `Cease` / `Out of Resources` (RFC 4486
    /// §4 subcode 8) NOTIFICATION on the priority channel ahead of
    /// any pending bulk traffic, then drop the writer channels.
    ///
    /// The writer's biased `select!` picks the priority NOTIFICATION
    /// before falling through to the `else` arm, so the peer sees a
    /// clean `Cease/8` if its TCP receive buffer ever drains. The
    /// session's own writer-exit arm observes the resulting
    /// `JoinHandle` resolution and drives the FSM through
    /// `TcpConnectionFails` from there — no need to await an FSM
    /// transition synchronously here, which keeps the bulk caller
    /// chain (`send_route_update`) sync.
    pub(super) fn trigger_outbound_saturation_teardown(&mut self) {
        warn!(
            peer = %self.peer_label,
            "outbound writer channel saturated — sending Cease/Out-of-Resources and tearing down"
        );
        let notif = rustbgpd_wire::NotificationMessage::new(
            NotificationCode::Cease,
            cease_subcode::OUT_OF_RESOURCES,
            bytes::Bytes::new(),
        );
        // Best-effort: the writer's priority channel is unbounded, so
        // this only fails if we already dropped the writer (e.g. a
        // double-trigger race). Either way, proceed with teardown.
        self.emit_notification_event(SessionNotificationDirection::Sent, &notif, None);
        let _ = self.enqueue_priority(&Message::Notification(notif));
        self.notifications_sent += 1;
        self.metrics.record_notification_sent(
            &self.peer_label,
            &NotificationCode::Cease.as_u8().to_string(),
            &cease_subcode::OUT_OF_RESOURCES.to_string(),
        );
        self.metrics
            .record_message_sent(&self.peer_label, "notification");
        self.handle_tcp_disconnect();
    }

    /// Drop the TCP read half + writer channels and clear the read
    /// buffer. Dropping the writer's `Sender` halves causes the writer
    /// task's biased `select!` to fall through to its `else` arm and
    /// exit cleanly; the `JoinHandle` then resolves and the session's
    /// own select observes it via the writer-exit arm.
    pub(super) fn close_tcp(&mut self) {
        if let Some(task) = self.connect_task.take() {
            task.abort();
        }
        if self.read_half.take().is_some() {
            debug!(peer = %self.peer_label, "TCP connection closed");
        }
        // Dropping these signals the writer task to exit. The
        // JoinHandle is intentionally not cleared here — the session's
        // writer-exit select arm needs it to observe the exit.
        self.writer_bulk_tx = None;
        self.writer_priority_tx = None;
        self.writer_keepalive_tx = None;
        self.read_buf.clear();
    }

    /// Clear TCP state after disconnect or error. Same writer-channel
    /// drop pattern as `close_tcp`.
    pub(super) fn handle_tcp_disconnect(&mut self) {
        debug!(peer = %self.peer_label, "TCP disconnected");
        if let Some(task) = self.connect_task.take() {
            task.abort();
        }
        self.read_half = None;
        self.writer_bulk_tx = None;
        self.writer_priority_tx = None;
        self.writer_keepalive_tx = None;
        self.read_buf.clear();
    }

    /// Drain complete messages from the read buffer and feed to FSM.
    #[expect(clippy::too_many_lines)]
    pub(super) async fn process_read_buffer(&mut self) {
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
                            let shutdown_reason = if notif.code == NotificationCode::Cease
                                && (notif.subcode == cease_subcode::ADMINISTRATIVE_SHUTDOWN
                                    || notif.subcode == cease_subcode::ADMINISTRATIVE_RESET)
                            {
                                rustbgpd_wire::notification::decode_shutdown_communication(
                                    &notif.data,
                                )
                            } else {
                                None
                            };
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
                            self.emit_notification_event(
                                SessionNotificationDirection::Received,
                                &notif,
                                shutdown_reason.clone(),
                            );
                            // RFC 8538: detect Cease/Hard Reset to bypass GR
                            if notif.code == NotificationCode::Cease
                                && notif.subcode == cease_subcode::HARD_RESET
                            {
                                info!(
                                    peer = %self.peer_label,
                                    "peer sent Cease/Hard Reset, GR will be skipped"
                                );
                                self.received_hard_reset = true;
                            }
                            // Log shutdown communication reason (RFC 8203)
                            if let Some(reason) = shutdown_reason {
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
                                        has_orf = rr.orf.is_some(),
                                        "received ROUTE-REFRESH"
                                    );
                                    // RFC 5291: an ORF-carrying refresh installs
                                    // the peer's prefix filter (which also lifts
                                    // the §6 initial-advert gate and re-floods).
                                    // A plain refresh, or an ORF for an
                                    // un-negotiated family/type, falls through to
                                    // the normal re-advertise path.
                                    let handled_orf =
                                        self.process_inbound_orf(afi, safi, &rr).await;
                                    if !handled_orf
                                        && self
                                            .rib_tx
                                            .send(RibUpdate::RouteRefreshRequest {
                                                peer: self.peer_ip,
                                                session_id: self.session_identity.id,
                                                afi,
                                                safi,
                                            })
                                            .await
                                            .is_err()
                                    {
                                        warn!(
                                            peer = %self.peer_label,
                                            "RIB manager unavailable — route refresh request dropped"
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
                                        .send(RibUpdate::BeginRouteRefresh {
                                            peer: self.peer_ip,
                                            session_id: self.session_identity.id,
                                            afi,
                                            safi,
                                        })
                                        .await
                                        .is_err()
                                    {
                                        warn!(
                                            peer = %self.peer_label,
                                            "RIB manager unavailable — BeginRouteRefresh dropped"
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
                                        .send(RibUpdate::EndRouteRefresh {
                                            peer: self.peer_ip,
                                            session_id: self.session_identity.id,
                                            afi,
                                            safi,
                                        })
                                        .await
                                        .is_err()
                                    {
                                        warn!(
                                            peer = %self.peer_label,
                                            "RIB manager unavailable — EndRouteRefresh dropped"
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
}

pub(super) async fn poll_connect(
    connect_task: &mut Option<JoinHandle<std::io::Result<TcpStream>>>,
) -> Result<std::io::Result<TcpStream>, JoinError> {
    let Some(task) = connect_task.as_mut() else {
        unreachable!("poll_connect called without an active connect task");
    };
    task.await
}

async fn create_and_connect(
    config: TransportConfig,
    peer_label: String,
) -> std::io::Result<TcpStream> {
    use socket2::{Domain, Protocol, SockAddr, Type};

    let domain = if config.remote_addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };

    let socket = socket2::Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;

    if let Some(ref password) = config.md5_password {
        crate::socket_opts::set_tcp_md5sig(&socket, config.remote_addr, password)?;
        debug!(peer = %peer_label, "TCP MD5 authentication configured");
    }

    if let Some(ref tcp_ao) = config.tcp_ao {
        // Active-open sockets install one exact peer MKT as current/rnext; the
        // Linux connect path rejects TCP-AO sockets without a matching MKT,
        // signs the initial SYN with the selected current key, and
        // tcp_inbound_hash() rejects unsigned replies from matching peers.
        crate::socket_opts::set_tcp_ao_config(
            &socket,
            config.remote_addr.ip(),
            tcp_ao,
            crate::socket_opts::TcpAoSocketRole::ActiveOpen,
        )
        .map_err(|err| {
            warn!(
                peer = %peer_label,
                addr = %config.remote_addr,
                send_id = tcp_ao.send_id,
                recv_id = tcp_ao.recv_id,
                algorithm = tcp_ao.algorithm.linux_name(),
                error = %err,
                "failed to configure TCP-AO authentication before active connect; protected session will retry without unauthenticated fallback"
            );
            std::io::Error::new(
                err.kind(),
                format!(
                    "failed to install TCP-AO key for peer {peer_label} at {} \
                     (send_id={}, recv_id={}, algorithm={}): {err}",
                    config.remote_addr,
                    tcp_ao.send_id,
                    tcp_ao.recv_id,
                    tcp_ao.algorithm.linux_name()
                ),
            )
        })?;
        debug!(peer = %peer_label, "TCP-AO authentication configured");
    }

    if config.ttl_security {
        crate::socket_opts::set_gtsm(&socket, config.remote_addr)?;
        debug!(peer = %peer_label, "GTSM / TTL security configured");
    }

    socket.set_nonblocking(true)?;

    let addr = SockAddr::from(config.remote_addr);
    match socket.connect(&addr) {
        Ok(()) => {}
        Err(e) if e.raw_os_error() == Some(libc::EINPROGRESS) => {}
        Err(e) => return Err(e),
    }

    let std_stream: std::net::TcpStream = socket.into();
    let stream = TcpStream::from_std(std_stream)?;
    stream.writable().await?;

    if let Some(err) = stream.take_error()? {
        return Err(err);
    }

    if config.tcp_ao.is_some() {
        match crate::socket_opts::get_tcp_ao_info(&stream) {
            Ok(info) => {
                info!(
                    peer = %peer_label,
                    addr = %config.remote_addr,
                    current_key = info.current_key,
                    rnext_key = info.rnext_key,
                    has_current_key = info.has_current_key,
                    has_rnext_key = info.has_rnext_key,
                    ao_required = info.ao_required,
                    accept_icmps = info.accept_icmps,
                    pkt_good = info.pkt_good,
                    pkt_bad = info.pkt_bad,
                    pkt_key_not_found = info.pkt_key_not_found,
                    pkt_ao_required = info.pkt_ao_required,
                    pkt_dropped_icmp = info.pkt_dropped_icmp,
                    "TCP-AO active-open socket inspected"
                );
            }
            Err(err) => {
                warn!(
                    peer = %peer_label,
                    addr = %config.remote_addr,
                    error = %err,
                    "failed to inspect TCP-AO active-open socket"
                );
            }
        }
    }

    Ok(stream)
}

/// Read from the TCP read half into the buffer. Extracted as a
/// freestanding async fn so that `tokio::select!` can borrow the read
/// half and buffer independently from other `self` fields.
pub(super) async fn read_tcp(
    read_half: &mut Option<OwnedReadHalf>,
    buf: &mut bytes::BytesMut,
) -> std::io::Result<usize> {
    use tokio::io::AsyncReadExt;
    let read_half = read_half
        .as_mut()
        .expect("read_tcp called without read_half");
    read_half.read_buf(buf).await
}

/// Awaitable view of the writer task's `JoinHandle`. The select arm
/// that drives this is guarded by `self.writer_join.is_some()`, so the
/// `expect` only fires on a programming error (guard out of sync).
/// After the `JoinHandle` resolves once, the session must clear
/// `writer_join = None` before the next select iteration — polling a
/// completed `JoinHandle` a second time panics per tokio semantics.
pub(super) async fn await_writer_join(
    handle: &mut Option<JoinHandle<std::io::Result<()>>>,
) -> Result<std::io::Result<()>, JoinError> {
    let join = handle
        .as_mut()
        .expect("await_writer_join called without handle");
    join.await
}
