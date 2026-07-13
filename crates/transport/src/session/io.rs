use super::{
    BmpEvent, Bytes, Event, Message, NotificationCode, OwnedReadHalf, PeerDownReason, PeerSession,
    RibUpdate, RouteRefreshSubtype, SessionNotificationDirection, TcpStream, TransportError,
    cease_subcode, debug, error, info, warn,
};
use crate::config::TransportConfig;
use rustbgpd_wire::{AddressPrefixOrf, OrfAction, OrfEntries, OrfMatch, OrfType};
use std::net::IpAddr;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};
use tokio::task::{JoinError, JoinHandle};

const ORF_RIB_REPLY_TIMEOUT: Duration = Duration::from_millis(500);

impl PeerSession {
    pub(super) fn record_connect_failure(&mut self, error: &impl std::fmt::Display) {
        self.last_error = error.to_string();
    }

    /// Handle the ORF section of an inbound ROUTE-REFRESH (RFC 5291/5292).
    ///
    /// Returns `true` if every emitted Address-Prefix ORF group of a negotiated
    /// type was accepted by the RIB — its `PeerOrfUpdate` handler installs the
    /// filter, lifts the §6 initial-advertisement gate, and re-floods. Returns
    /// `false` for a plain refresh, an ORF whose groups are all un-negotiated
    /// types (incl. the legacy type 128, which rustbgpd never advertises), or
    /// any RIB-side rejection/drop/timeout; the caller then takes the normal
    /// re-advertise path.
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
        let mut accepted = false;
        let mut failed = false;
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
            let (reply, rx) = oneshot::channel();
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
                failed = true;
                break;
            }
            match tokio::time::timeout(ORF_RIB_REPLY_TIMEOUT, rx).await {
                Ok(Ok(Ok(()))) => {
                    accepted = true;
                }
                Ok(Ok(Err(err))) => {
                    failed = true;
                    warn!(
                        peer = %self.peer_label,
                        ?afi, ?safi,
                        error = %err,
                        "RIB rejected ORF update — falling back to plain route refresh"
                    );
                }
                Ok(Err(_)) => {
                    failed = true;
                    warn!(
                        peer = %self.peer_label,
                        ?afi, ?safi,
                        "RIB dropped ORF update reply — falling back to plain route refresh"
                    );
                }
                Err(_) => {
                    failed = true;
                    warn!(
                        peer = %self.peer_label,
                        ?afi, ?safi,
                        timeout_ms = %ORF_RIB_REPLY_TIMEOUT.as_millis(),
                        "RIB ORF update reply timed out — falling back to plain route refresh"
                    );
                }
            }
        }
        accepted && !failed
    }

    /// Encode `msg` and enqueue it on the writer's **priority** channel
    /// (OPEN, KEEPALIVE, NOTIFICATION, operator ROUTE-REFRESH command,
    /// collision-dump Cease, saturation Cease/8). The priority channel
    /// is unbounded so this only ever reports `WriterClosed` when the
    /// session has no active TCP connection — same effect as today's
    /// "no stream" branch, just at a different layer.
    pub(super) fn enqueue_priority(&mut self, msg: &Message) -> Result<(), TransportError> {
        let max_len = self.outbound_max_message_len();
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
        let max_len = self.outbound_max_message_len();
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
        let encoded = Bytes::from(encoded);
        // RFC 8671 post-policy Adj-RIB-Out tap: every outbound UPDATE
        // (announcements, withdraws, EoR markers — all families) funnels
        // through here as final wire bytes, so the BMP mirror is
        // byte-exact post-policy. Non-UPDATE bulk traffic (BoRR/EoRR
        // ROUTE-REFRESH markers) is not route monitoring and is skipped.
        //
        // Loss semantics under saturation (both directions are covered):
        // - writer channel Full → the UPDATE never reaches the wire, so
        //   NOT mirroring it is correct (RFC 8671 mirrors what was
        //   sent); the saturation teardown below ends in a reliable BMP
        //   PeerDown ordered after the last mirrored UPDATE, and the
        //   re-established session re-floods the view.
        // - wire send Ok but the BMP channel Full → `emit_bmp_event`
        //   latches `bmp_stream_diverged` and forces a PeerDown/PeerUp
        //   peer-state reset once the channel drains, so collectors
        //   never keep a silently incomplete rib-out view.
        let bmp_rib_out_pdu =
            (self.config.bmp_rib_out && self.bmp_tx.is_some() && matches!(msg, Message::Update(_)))
                .then(|| encoded.clone());
        match tx.try_send(encoded) {
            Ok(()) => {
                if let Some(update_pdu) = bmp_rib_out_pdu {
                    // Peer identity stays the REMOTE peer's; only the
                    // direction flips (O=1), and L=1 marks post-policy.
                    // Timestamp inside is the advertise time (now).
                    let mut peer_info = self.build_bmp_peer_info();
                    peer_info.is_rib_out = true;
                    peer_info.is_post_policy = true;
                    self.emit_bmp_event(BmpEvent::RouteMonitoring {
                        peer_info,
                        update_pdu,
                    });
                }
                Ok(())
            }
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
    /// §4 subcode 8) NOTIFICATION on the priority channel, signal the
    /// writer's hard-teardown watch, then drop the writer channels.
    ///
    /// The teardown signal makes the writer **discard the queued bulk
    /// backlog instead of draining it** — the Cease must be the final
    /// frame the peer ever sees, and flushing a saturated queue would
    /// delay the close indefinitely — flush the Cease best-effort
    /// within a short bound (a saturated TCP window may never accept
    /// it), and exit with `WriterExit::TornDown`. The session's
    /// writer-exit arm observes that exit and drives the FSM through
    /// `TcpConnectionFails` (→ `SessionDown` → RIB `PeerDown` /
    /// deregistration) exactly as a real TCP failure would — no need
    /// to await an FSM transition synchronously here, which keeps the
    /// bulk caller chain (`send_route_update`) sync.
    pub(super) fn trigger_outbound_saturation_teardown(&mut self) {
        warn!(
            peer = %self.peer_label,
            "outbound writer channel saturated — sending Cease/Out-of-Resources and tearing down"
        );
        self.trigger_outbound_out_of_resources_teardown();
    }

    /// Emit Cease/8 and hard-close the writer without assigning a cause.
    /// Callers must log their own truthful cause before entering this common
    /// primitive (writer saturation, exact-snapshot invariant breach, etc.).
    pub(super) fn trigger_outbound_out_of_resources_teardown(&mut self) {
        let notif = rustbgpd_wire::NotificationMessage::new(
            NotificationCode::Cease,
            cease_subcode::OUT_OF_RESOURCES,
            bytes::Bytes::new(),
        );
        // Classify the upcoming BMP Peer Down truthfully: reason 1
        // (local system sent NOTIFICATION) carrying the Cease/8 PDU,
        // instead of the reason-4 "remote closed" default.
        if self.bmp_tx.is_some()
            && let Ok(pdu) = rustbgpd_wire::encode_message(&Message::Notification(notif.clone()))
        {
            self.last_down_reason = Some(PeerDownReason::LocalNotification(pdu.freeze()));
        }
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
        // Signal the hard close BEFORE dropping the senders: the writer
        // races this watch against any in-flight (wedged) write, so the
        // teardown is never gated on the peer draining its window.
        if let Some(tx) = &self.writer_teardown_tx {
            let _ = tx.send(true);
        }
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
        self.writer_teardown_tx = None;
        self.read_buf.clear();
        self.tcp_ao_info = None;
        self.tcp_ao_stream_was_accepted = false;
        self.clear_bmp_stream_repair();
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
        self.writer_teardown_tx = None;
        self.read_buf.clear();
        self.tcp_ao_info = None;
        self.tcp_ao_stream_was_accepted = false;
        self.clear_bmp_stream_repair();
    }

    /// Abandon any pending BMP divergence repair (LAN-200). Once the TCP
    /// session is gone the repair is meaningless: the reconnect re-floods
    /// both views and the FSM's `SessionDown` emits the collector-visible
    /// `PeerDown`. Clearing the latch and disarming its retry timer here
    /// keeps the run loop's `bmp_repair_timer` arm from firing a spurious
    /// synthetic `PeerDown`/`PeerUp` for a dead session (which a reconnect
    /// would then stack a real `PeerUp` on top of).
    fn clear_bmp_stream_repair(&mut self) {
        self.bmp_stream_diverged = false;
        self.bmp_repair_timer = None;
    }

    /// Drain complete messages from the read buffer and feed to FSM.
    #[expect(
        clippy::too_many_lines,
        reason = "message ingestion keeps decode, BMP accounting, FSM dispatch, and buffer ordering explicit"
    )]
    pub(super) async fn process_read_buffer(&mut self) {
        loop {
            // Reconcile a due refresh window before *each* buffered PDU, not
            // merely once per socket read. One read can contain several UPDATEs
            // and the first may park on RIB backpressure until after the shared
            // deadline; the next one must see the corrected max-prefix count.
            if self.expire_refresh_accounting_windows().await.is_err() {
                return;
            }
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
                                    } else if self.negotiated.as_ref().is_some_and(|n| {
                                        n.peer_capabilities.iter().any(|capability| {
                                            matches!(
                                                capability,
                                                rustbgpd_wire::Capability::GracefulRestart { .. }
                                            )
                                        })
                                    }) && !self
                                        .received_eor_families
                                        .contains(&(afi, safi))
                                    {
                                        warn!(
                                            peer = %self.peer_label,
                                            ?afi, ?safi,
                                            "ignoring BoRR before End-of-RIB from Graceful Restart peer"
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
                                        // The channel acceptance orders the RIB's
                                        // snapshot ahead of all later UPDATEs from
                                        // this session. Only now mirror that window
                                        // in transport-owned max-prefix state.
                                        self.begin_refresh_accounting(afi, safi);
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
                                        // Consume before sweeping so a re-entrant
                                        // observation can never see an active
                                        // window whose stale identities are gone.
                                        self.end_refresh_accounting(afi, safi);
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
    connect_task: &mut Option<super::ConnectTask>,
) -> Result<super::ConnectResult, JoinError> {
    let Some(task) = connect_task.as_mut() else {
        unreachable!("poll_connect called without an active connect task");
    };
    task.await
}

fn install_active_tcp_ao_with<F>(
    socket: &socket2::Socket,
    config: &TransportConfig,
    peer_label: &str,
    mut install_key: F,
) -> std::io::Result<Option<crate::socket_opts::TcpAoMktReceipt>>
where
    F: FnMut(
        &socket2::Socket,
        IpAddr,
        u8,
        &crate::TcpAoConfig,
        crate::socket_opts::TcpAoSocketRole,
    ) -> std::io::Result<()>,
{
    let Some(tcp_ao) = config.tcp_ao.as_ref() else {
        return Ok(None);
    };
    tcp_ao.selected().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "TCP-AO keyring has no selectable non-deprecated key",
        )
    })?;
    let prefix_len = if config.remote_addr.is_ipv4() {
        32
    } else {
        128
    };
    for (index, key) in tcp_ao.startup_order().into_iter().enumerate() {
        let role = if index == 0 {
            crate::socket_opts::TcpAoSocketRole::ActiveOpen
        } else {
            crate::socket_opts::TcpAoSocketRole::Listener
        };
        install_key(
            socket,
            config.remote_addr.ip(),
            prefix_len,
            key,
            role,
        )
        .map_err(|err| {
            warn!(
                peer = %peer_label,
                addr = %config.remote_addr,
                send_id = key.send_id,
                recv_id = key.recv_id,
                algorithm = key.algorithm.linux_name(),
                error = %err,
                "failed to configure TCP-AO authentication before active connect; protected session will retry without unauthenticated fallback"
            );
            std::io::Error::new(
                err.kind(),
                format!(
                    "failed to install TCP-AO key for peer {peer_label} at {} \
                     (send_id={}, recv_id={}, algorithm={}): {err}",
                    config.remote_addr,
                    key.send_id,
                    key.recv_id,
                    key.algorithm.linux_name()
                ),
            )
        })?;
    }
    let receipt = crate::socket_opts::capture_tcp_ao_keyring_receipt(
        socket,
        config.remote_addr.ip(),
        prefix_len,
        tcp_ao,
        true,
    )
    .map_err(|err| {
        warn!(
            peer = %peer_label,
            addr = %config.remote_addr,
            error = %err,
            "failed to capture TCP-AO pre-connect kernel receipt; protected session will retry without unauthenticated fallback"
        );
        err
    })?;
    debug!(peer = %peer_label, "TCP-AO authentication configured");
    Ok(Some(receipt))
}

fn prepare_active_socket_with<I, C>(
    socket: socket2::Socket,
    config: &TransportConfig,
    peer_label: &str,
    install_key: I,
    connect_socket: C,
) -> std::io::Result<(socket2::Socket, Option<crate::socket_opts::TcpAoMktReceipt>)>
where
    I: FnMut(
        &socket2::Socket,
        IpAddr,
        u8,
        &crate::TcpAoConfig,
        crate::socket_opts::TcpAoSocketRole,
    ) -> std::io::Result<()>,
    C: FnOnce(&socket2::Socket, &socket2::SockAddr) -> std::io::Result<()>,
{
    if let Some(ref password) = config.md5_password {
        crate::socket_opts::set_tcp_md5sig(&socket, config.remote_addr, password)?;
        debug!(peer = %peer_label, "TCP MD5 authentication configured");
    }

    // Install the selected exact MKT as Current/RNext, then every remaining
    // key in declaration order before connect. This helper owns the fresh
    // socket, so any partial installation failure closes it before returning
    // and cannot reach the connect operation or fall back to plaintext.
    let tcp_ao_receipt = install_active_tcp_ao_with(&socket, config, peer_label, install_key)?;

    if config.ttl_security {
        crate::socket_opts::set_gtsm(&socket, config.remote_addr)?;
        debug!(peer = %peer_label, "GTSM / TTL security configured");
    }

    socket.set_nonblocking(true)?;
    let addr = socket2::SockAddr::from(config.remote_addr);
    connect_socket(&socket, &addr)?;
    Ok((socket, tcp_ao_receipt))
}

#[cfg(test)]
pub(super) fn prepare_active_socket_for_test<I, C>(
    socket: socket2::Socket,
    config: &TransportConfig,
    peer_label: &str,
    install_key: I,
    connect_socket: C,
) -> std::io::Result<(socket2::Socket, Option<crate::socket_opts::TcpAoMktReceipt>)>
where
    I: FnMut(
        &socket2::Socket,
        IpAddr,
        u8,
        &crate::TcpAoConfig,
        crate::socket_opts::TcpAoSocketRole,
    ) -> std::io::Result<()>,
    C: FnOnce(&socket2::Socket, &socket2::SockAddr) -> std::io::Result<()>,
{
    prepare_active_socket_with(socket, config, peer_label, install_key, connect_socket)
}

async fn create_and_connect(
    config: TransportConfig,
    peer_label: String,
) -> std::io::Result<(TcpStream, Option<crate::TcpAoInfoSnapshot>)> {
    use socket2::{Domain, Protocol, Type};

    let domain = if config.remote_addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };

    let socket = socket2::Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    let (socket, tcp_ao_receipt) = prepare_active_socket_with(
        socket,
        &config,
        &peer_label,
        crate::socket_opts::set_tcp_ao_config,
        |socket, addr| match socket.connect(addr) {
            Ok(()) => Ok(()),
            Err(e) if e.raw_os_error() == Some(libc::EINPROGRESS) => Ok(()),
            Err(e) => Err(e),
        },
    )?;

    let std_stream: std::net::TcpStream = socket.into();
    let stream = TcpStream::from_std(std_stream)?;
    stream.writable().await?;

    if let Some(err) = stream.take_error()? {
        return Err(err);
    }

    let tcp_ao_info =
        inspect_active_tcp_ao(&stream, &config, &peer_label, tcp_ao_receipt.as_ref())?;

    Ok((stream, tcp_ao_info))
}

fn inspect_active_tcp_ao(
    stream: &TcpStream,
    config: &TransportConfig,
    peer_label: &str,
    receipt: Option<&crate::socket_opts::TcpAoMktReceipt>,
) -> std::io::Result<Option<crate::TcpAoInfoSnapshot>> {
    if config.tcp_ao.is_none() {
        return Ok(None);
    }
    let receipt = receipt.ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "TCP-AO active-open inspection lacks its pre-connect kernel receipt",
        )
    })?;
    match crate::socket_opts::get_tcp_ao_info_for_receipt(stream, receipt, config.remote_addr.ip())
    {
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
            Ok(Some(info))
        }
        Err(err) => {
            warn!(
                peer = %peer_label,
                addr = %config.remote_addr,
                error = %err,
                "failed to inspect TCP-AO active-open socket"
            );
            Err(std::io::Error::new(
                err.kind(),
                format!(
                    "failed to reconcile TCP-AO post-connect inventory for peer {peer_label} at {}: {err}",
                    config.remote_addr
                ),
            ))
        }
    }
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
    handle: &mut Option<JoinHandle<Result<(), super::writer::WriterExit>>>,
) -> Result<Result<(), super::writer::WriterExit>, JoinError> {
    let join = handle
        .as_mut()
        .expect("await_writer_join called without handle");
    join.await
}
