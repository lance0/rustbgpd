use super::{
    Action, AddPathMode, Afi, BmpEvent, Bytes, Duration, Event, Instant, IpAddr, Ipv4Addr, Message,
    NotificationCode, OUTBOUND_BUFFER, PeerDownReason, PeerSession, RibUpdate, Safi,
    SessionNotification, SessionState, cease_subcode, debug, info, mpsc, warn,
};

impl PeerSession {
    /// Feed an event into the FSM and execute the resulting actions.
    ///
    /// Uses an iterative loop to avoid async recursion: actions that
    /// produce follow-up events (like TCP connect or send failure)
    /// queue them for the next iteration.
    pub(super) async fn drive_fsm(&mut self, initial_event: Event) {
        let mut pending = vec![initial_event];

        while let Some(event) = pending.pop() {
            debug!(
                peer = %self.peer_label,
                state = %self.fsm.state(),
                event = event.name(),
                "FSM event"
            );
            let actions = self.fsm.handle_event(event.clone());
            if notification_teardown_event(&event, &actions) {
                self.notification_teardown = true;
            }
            if hard_reset_notification_in_actions(&actions) {
                self.sent_hard_reset = true;
            }
            let follow_up = self.execute_actions(actions).await;
            pending.extend(follow_up);
        }
    }

    /// Execute a batch of FSM actions, returning any follow-up events.
    ///
    /// Follow-up events arise from TCP connect results and send failures.
    #[expect(clippy::too_many_lines)]
    pub(super) async fn execute_actions(&mut self, actions: Vec<Action>) -> Vec<Event> {
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
                    // RFC 8538: track outbound Hard Reset to bypass GR
                    if code == NotificationCode::Cease && subcode == cease_subcode::HARD_RESET {
                        self.sent_hard_reset = true;
                    }
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
                    if self.stream.is_some() {
                        debug!(peer = %self.peer_label, "already connected (inbound)");
                        follow_up.push(Event::TcpConnectionConfirmed);
                    } else {
                        self.start_connect_attempt();
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
                        peer_asn: self.config.peer.remote_asn,
                        peer_router_id: self
                            .negotiated
                            .as_ref()
                            .map_or(Ipv4Addr::UNSPECIFIED, |n| n.peer_router_id),
                        outbound_tx: self.outbound_tx.clone(),
                        export_policy: self.export_policy.clone(),
                        sendable_families,
                        is_ebgp,
                        route_reflector_client: self.config.route_reflector_client,
                        add_path_send_families,
                        add_path_send_max,
                    });
                    let _ = self.rib_tx.try_send(RibUpdate::SetPeerPolicyContext {
                        peer: self.peer_ip,
                        peer_group: self.config.peer_group.clone(),
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
                    // RFC 8538: Cease/Hard Reset bypasses GR unconditionally.
                    let gr_update = self.negotiated.as_ref().and_then(|neg| {
                        if neg.peer_gr_capable
                            && self.config.peer.graceful_restart
                            && (!self.notification_teardown || neg.peer_notification_gr)
                            && !self.received_hard_reset
                            && !self.sent_hard_reset
                        {
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
                    self.notification_teardown = false;
                    self.received_hard_reset = false;
                    self.sent_hard_reset = false;
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
}

/// Return true when this event/action batch represents a
/// NOTIFICATION-triggered teardown path.
///
/// RFC 8538: when teardown is triggered by NOTIFICATION semantics, route
/// preservation requires negotiated Notification GR (N-bit).
pub(super) fn notification_teardown_event(event: &Event, actions: &[Action]) -> bool {
    let has_session_down = actions.iter().any(|a| matches!(a, Action::SessionDown));
    if !has_session_down {
        return false;
    }
    matches!(event, Event::NotificationReceived(_))
        || actions
            .iter()
            .any(|a| matches!(a, Action::SendNotification(_)))
}

/// Return true when this action batch contains Cease/Hard Reset (subcode 9).
///
/// Some FSM paths emit `SessionDown` before `SendNotification`, so this is
/// checked before action execution.
pub(super) fn hard_reset_notification_in_actions(actions: &[Action]) -> bool {
    actions.iter().any(|a| {
        matches!(
            a,
            Action::SendNotification(notif)
                if notif.code == NotificationCode::Cease
                    && notif.subcode == cease_subcode::HARD_RESET
        )
    })
}
