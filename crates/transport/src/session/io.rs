use super::{
    AsyncWriteExt, BmpEvent, Event, Message, NotificationCode, PeerDownReason, PeerSession,
    RibUpdate, RouteRefreshSubtype, TcpStream, TransportError, cease_subcode, debug, error, info,
    warn,
};

impl PeerSession {
    /// Encode and send a BGP message to the peer.
    pub(super) async fn send_message(&mut self, msg: &Message) -> Result<(), TransportError> {
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
    pub(super) async fn attempt_connect(&mut self) -> Option<Event> {
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
    pub(super) fn close_tcp(&mut self) {
        if self.stream.take().is_some() {
            debug!(peer = %self.peer_label, "TCP connection closed");
        }
        self.read_buf.clear();
    }

    /// Clear TCP state after disconnect or error.
    pub(super) fn handle_tcp_disconnect(&mut self) {
        debug!(peer = %self.peer_label, "TCP disconnected");
        self.stream = None;
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
}

/// Read from TCP into the buffer. Extracted as a freestanding async fn
/// so that `tokio::select!` can borrow the stream and buffer independently
/// from other `self` fields.
pub(super) async fn read_tcp(
    stream: &mut Option<TcpStream>,
    buf: &mut bytes::BytesMut,
) -> std::io::Result<usize> {
    use tokio::io::AsyncReadExt;
    let stream = stream.as_mut().expect("read_tcp called without stream");
    stream.read_buf(buf).await
}
