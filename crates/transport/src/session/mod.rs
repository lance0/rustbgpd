mod commands;
mod fsm;
mod inbound;
mod io;
mod outbound;

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
    is_private_asn,
};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::time::Sleep;
use tracing::{debug, error, info, warn};

use crate::config::{RemovePrivateAs, TransportConfig};
use crate::error::TransportError;
use crate::framing::ReadBuffer;
use crate::handle::{PeerCommand, PeerSessionState, SessionNotification};
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

    pub(super) fn known_prefix_count(&self) -> usize {
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
            notification_teardown: false,
            received_hard_reset: false,
            sent_hard_reset: false,
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
}

#[cfg(test)]
mod tests;
