mod commands;
mod fsm;
pub mod import_decision_cache;
pub(crate) mod inbound;
mod io;
mod outbound;
mod writer;

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ops::ControlFlow;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use bytes::Bytes;
use rustbgpd_bmp::{BmpEvent, BmpPeerInfo, BmpPeerType, PeerDownReason};
use rustbgpd_fsm::{Action, Event, NegotiatedSession, Session, SessionState};
use rustbgpd_policy::PolicyChain;
use rustbgpd_rib::{
    BgpLsFamily, BgpLsRibRoute, BgpLsRouteKey, EvpnRibRoute, FlowSpecRoute, NextHopScope,
    OutboundRouteUpdate, RibUpdate, Route,
};
use rustbgpd_telemetry::BgpMetrics;
use rustbgpd_wire::notification::{NotificationCode, cease_subcode};
use rustbgpd_wire::{
    AddPathMode, Afi, AsPath, AsPathSegment, BgpRole, Capability, EvpnRoute, EvpnRouteKey,
    FlowSpecRule, Ipv4NlriEntry, Ipv4UnicastMode, Message, MpReachNlri, MpUnreachNlri, NlriEntry,
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
use crate::event_sink::{NoopTransportEventSink, TransportEventSink};
use crate::framing::ReadBuffer;
use crate::handle::{
    PeerCommand, PeerSessionState, SessionIdentity, SessionLifecycleNotification,
    SessionNotification, SessionNotificationDirection, SessionNotificationEvent,
};
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
#[expect(
    clippy::struct_excessive_bools,
    reason = "per-session protocol flags are intentionally explicit state-machine latches"
)]
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
    /// KEEPALIVE cadence control for the writer task (ADR-0078). The
    /// session sends `Some(interval)` when the FSM starts the keepalive
    /// timer and `None` when it stops it; dropping the sender (TCP
    /// teardown) also stops the cadence.
    writer_keepalive_tx: Option<tokio::sync::watch::Sender<Option<std::time::Duration>>>,
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
    /// Cached scope for IPv6 link-local next-hop recursion on static
    /// interface-bound peers. Built once from immutable transport config.
    link_local_next_hop_scope: Option<NextHopScope>,
    /// Negotiated session parameters (set when `SessionEstablished`).
    negotiated: Option<NegotiatedSession>,
    /// Address families negotiated via MP-BGP capabilities. Used to filter
    /// inbound `MP_REACH_NLRI` and outbound route advertisements.
    negotiated_families: Vec<(Afi, Safi)>,
    /// Families for which Add-Path receive was negotiated. Built once at
    /// `SessionEstablished` and reused by inbound UPDATE decode instead of
    /// rebuilding from `NegotiatedSession::add_path_families` per UPDATE.
    add_path_receive_families: Vec<(Afi, Safi)>,
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
    /// (`KNOWN_ISSUES.md`): operators re-issue `rbgp gshut` after
    /// daemon restart if the maintenance window is still active.
    advertise_graceful_shutdown: bool,
    /// Channel to notify `PeerManager` of lossless collision-coordination events.
    /// Unbounded so notifications are never dropped and never block (avoids
    /// deadlock with `QueryState`).
    session_notify_tx: Option<mpsc::UnboundedSender<SessionNotification>>,
    /// Bounded operator-facing lifecycle event channel.
    ///
    /// This carries ordinary FSM `StateChanged` observations used by
    /// `EventService.WatchEvents`. It is intentionally lossy under sustained
    /// churn so observability cannot grow the collision-coordination channel.
    session_lifecycle_tx: Option<mpsc::Sender<SessionLifecycleNotification>>,
    /// Bounded metadata channel for operator-facing NOTIFICATION events.
    /// Dropping from this path is acceptable; protocol counters and teardown
    /// behavior remain authoritative.
    session_event_tx: Option<mpsc::Sender<SessionNotificationEvent>>,
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
    /// This remains the authoritative Add-Path identity set; the unique-prefix
    /// max-prefix count is maintained in `known_prefix_refcounts`.
    known_paths: HashSet<(Prefix, u32)>,
    /// Reference count of accepted unicast paths per prefix.
    ///
    /// Kept in sync with `known_paths` so max-prefix enforcement can count
    /// unique prefixes without rebuilding a temporary set on every UPDATE.
    known_prefix_refcounts: HashMap<Prefix, usize>,
    /// Accepted `FlowSpec` rules from this peer. Counted toward
    /// max-prefix enforcement so a peer can't bypass the cap by
    /// flooding `FlowSpec` rules.
    known_flowspec: HashSet<FlowSpecRule>,
    /// Accepted EVPN routes from this peer (RFC 7432 keys). Counted
    /// toward max-prefix enforcement for the same reason.
    known_evpn: HashSet<EvpnRouteKey>,
    /// Accepted BGP-LS routes from this peer (RFC 9552 opaque keys). Counted
    /// toward max-prefix enforcement for the same reason.
    known_bgpls: HashSet<BgpLsRouteKey>,
    /// Session counters
    updates_received: u64,
    updates_sent: u64,
    notifications_received: u64,
    notifications_sent: u64,
    otc_routes_blocked: u64,
    import_policy_routes_permitted: u64,
    import_policy_routes_denied: u64,
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
    /// Out-of-crate sink for structured transport-policy events
    /// (ADR-0072 follow-up). Defaults to
    /// [`NoopTransportEventSink`]; the binary plugs in an EHM-backed
    /// implementation via [`PeerSession::set_event_sink`] before
    /// the session task runs when `[event_history]` is enabled.
    event_sink: Arc<dyn TransportEventSink>,
    /// Whether the import-decision cache is populated (ADR-0073
    /// `[policy.explain].enabled`). Read on the inbound UPDATE hot path
    /// to skip the decision snapshot build/clone entirely when explain
    /// is disabled.
    import_explain_enabled: bool,
    /// Per-session import-policy decision cache (ADR-0073). Records
    /// every import evaluation — permit and deny — so
    /// `PolicyService.ExplainImportPolicy` can answer "why didn't this
    /// prefix come in?". Owned outright by the session, but a peer flap
    /// does NOT reconstruct the `PeerSession` task, so the ADR-0073
    /// "resets on peer session reset" contract is enforced **explicitly**:
    /// the cache is cleared in the `Action::SessionDown` handler alongside
    /// the per-session import counters (see `fsm.rs`). A daemon restart
    /// drops it with the process.
    import_decision_cache: import_decision_cache::ImportDecisionCache,
    /// Session-local import-policy generation. Bumped whenever the
    /// effective import chain is hot-applied
    /// ([`PeerCommand::UpdateImportPolicy`]). Cache entries stamp the
    /// value current at evaluation time; an explain lookup compares it
    /// to this counter and reports `STALE` when they disagree. Local
    /// rather than a global registry counter so a policy edit to an
    /// unrelated peer can't false-`STALE` this peer's decisions.
    import_policy_generation: u64,
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

fn is_ipv6_link_local(addr: &Ipv6Addr) -> bool {
    (addr.segments()[0] & 0xffc0) == 0xfe80
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
    /// EVPN keys, and BGP-LS objects. Used by max-prefix enforcement so a peer can't slip
    /// past the cap by flooding non-unicast NLRI.
    pub(super) fn known_prefix_count(&self) -> usize {
        self.known_prefix_refcounts.len()
            + self.known_flowspec.len()
            + self.known_evpn.len()
            + self.known_bgpls.len()
    }

    fn remember_known_path(&mut self, prefix: Prefix, path_id: u32) -> bool {
        if !self.known_paths.insert((prefix, path_id)) {
            return false;
        }
        *self.known_prefix_refcounts.entry(prefix).or_insert(0) += 1;
        true
    }

    fn forget_known_path(&mut self, prefix: Prefix, path_id: u32) -> bool {
        if !self.known_paths.remove(&(prefix, path_id)) {
            return false;
        }
        // Invariant: every `(prefix, path_id)` in `known_paths` added a refcount
        // via `remember_known_path`, so once the remove above succeeds a matching
        // refcount entry must exist. The `else` is therefore unreachable; assert
        // it in debug builds so a future refactor that desyncs the two structures
        // (which would undercount unique prefixes and could weaken max-prefix
        // enforcement) is caught by the test suite instead of failing silently.
        if let Some(count) = self.known_prefix_refcounts.get_mut(&prefix) {
            if *count > 1 {
                *count -= 1;
            } else {
                self.known_prefix_refcounts.remove(&prefix);
            }
        } else {
            debug_assert!(
                false,
                "known_prefix_refcounts missing an entry for a prefix still in known_paths — \
                 max-prefix accounting desync"
            );
        }
        true
    }

    fn clear_known_routes(&mut self) {
        self.known_paths.clear();
        self.known_prefix_refcounts.clear();
        self.known_flowspec.clear();
        self.known_evpn.clear();
        self.known_bgpls.clear();
    }

    fn link_local_next_hop_scope_from_config(config: &TransportConfig) -> Option<NextHopScope> {
        Some(NextHopScope {
            interface: Arc::from(config.peer_interface.as_deref()?),
            ifindex: config.peer_scope_id?,
        })
    }

    #[cfg(test)]
    #[expect(
        clippy::too_many_arguments,
        reason = "test constructor mirrors production dependency wiring for focused harnesses"
    )]
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
        Self::new_with_identity_and_lifecycle(
            config,
            metrics,
            commands,
            rib_tx,
            import_policy,
            export_policy,
            session_notify_tx,
            None,
            None,
            bmp_tx,
            validation_rx,
            advertise_graceful_shutdown,
            SessionIdentity::default(),
        )
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "session constructor owns the transport dependency boundary explicitly"
    )]
    pub(crate) fn new_with_identity_and_lifecycle(
        config: TransportConfig,
        metrics: BgpMetrics,
        commands: mpsc::Receiver<PeerCommand>,
        rib_tx: mpsc::Sender<RibUpdate>,
        import_policy: Option<PolicyChain>,
        export_policy: Option<PolicyChain>,
        session_notify_tx: Option<mpsc::UnboundedSender<SessionNotification>>,
        session_event_tx: Option<mpsc::Sender<SessionNotificationEvent>>,
        session_lifecycle_tx: Option<mpsc::Sender<SessionLifecycleNotification>>,
        bmp_tx: Option<mpsc::Sender<BmpEvent>>,
        validation_rx: Option<watch::Receiver<rustbgpd_rpki::ValidationSnapshot>>,
        advertise_graceful_shutdown: bool,
        session_identity: SessionIdentity,
    ) -> Self {
        let peer_label = config.remote_addr.to_string();
        let peer_ip = config.remote_addr.ip();
        let link_local_next_hop_scope = Self::link_local_next_hop_scope_from_config(&config);
        let fsm = Session::new(config.peer.clone());
        let explain_enabled = config.explain_enabled;
        let explain_cache_size = config.explain_cache_size;
        let (outbound_tx, outbound_rx) = mpsc::channel(OUTBOUND_BUFFER);
        Self {
            config,
            fsm,
            read_half: None,
            writer_bulk_tx: None,
            writer_priority_tx: None,
            writer_keepalive_tx: None,
            writer_join: None,
            read_buf: ReadBuffer::new(),
            timers: Timers::default(),
            metrics,
            commands,
            rib_tx,
            peer_label,
            peer_ip,
            link_local_next_hop_scope,
            negotiated: None,
            negotiated_families: Vec::new(),
            add_path_receive_families: Vec::new(),
            stop_requested: false,
            reconnect_timer: None,
            connect_task: None,
            outbound_rx,
            outbound_tx,
            import_policy,
            export_policy,
            advertise_graceful_shutdown,
            session_notify_tx,
            session_lifecycle_tx,
            session_event_tx,
            session_identity,
            bmp_tx,
            validation_rx,
            local_open_pdu: None,
            remote_open_pdu: None,
            last_down_reason: None,
            known_paths: HashSet::new(),
            known_prefix_refcounts: HashMap::new(),
            known_flowspec: HashSet::new(),
            known_evpn: HashSet::new(),
            known_bgpls: HashSet::new(),
            updates_received: 0,
            updates_sent: 0,
            notifications_received: 0,
            notifications_sent: 0,
            otc_routes_blocked: 0,
            import_policy_routes_permitted: 0,
            import_policy_routes_denied: 0,
            flap_count: 0,
            established_at: None,
            last_error: String::new(),
            notification_teardown: false,
            received_hard_reset: false,
            sent_hard_reset: false,
            event_sink: Arc::new(NoopTransportEventSink),
            import_explain_enabled: explain_enabled,
            import_decision_cache: import_decision_cache::ImportDecisionCache::with_capacity(
                explain_cache_size,
            ),
            import_policy_generation: 0,
        }
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "inbound constructor carries the same dependency boundary plus accepted stream"
    )]
    pub(crate) fn new_inbound_with_identity_and_lifecycle(
        config: TransportConfig,
        metrics: BgpMetrics,
        commands: mpsc::Receiver<PeerCommand>,
        rib_tx: mpsc::Sender<RibUpdate>,
        import_policy: Option<PolicyChain>,
        export_policy: Option<PolicyChain>,
        stream: TcpStream,
        session_notify_tx: Option<mpsc::UnboundedSender<SessionNotification>>,
        session_event_tx: Option<mpsc::Sender<SessionNotificationEvent>>,
        session_lifecycle_tx: Option<mpsc::Sender<SessionLifecycleNotification>>,
        bmp_tx: Option<mpsc::Sender<BmpEvent>>,
        validation_rx: Option<watch::Receiver<rustbgpd_rpki::ValidationSnapshot>>,
        advertise_graceful_shutdown: bool,
        session_identity: SessionIdentity,
    ) -> Self {
        let peer_label = config.remote_addr.to_string();
        let peer_ip = config.remote_addr.ip();
        let link_local_next_hop_scope = Self::link_local_next_hop_scope_from_config(&config);
        let fsm = Session::new(config.peer.clone());
        let explain_enabled = config.explain_enabled;
        let explain_cache_size = config.explain_cache_size;
        let (outbound_tx, outbound_rx) = mpsc::channel(OUTBOUND_BUFFER);
        // Split the inbound stream and spawn the writer immediately —
        // we're in async context here (inside `tokio::spawn` from
        // `PeerHandle::spawn_inbound`), so `tokio::spawn` inside
        // `writer::spawn` works.
        let (read_half, write_half) = stream.into_split();
        let writer_handle = writer::spawn(
            write_half,
            OUTBOUND_BUFFER,
            metrics.clone(),
            peer_label.clone(),
        );
        Self {
            config,
            fsm,
            read_half: Some(read_half),
            writer_bulk_tx: Some(writer_handle.bulk_tx),
            writer_priority_tx: Some(writer_handle.priority_tx),
            writer_keepalive_tx: Some(writer_handle.keepalive_tx),
            writer_join: Some(writer_handle.join),
            read_buf: ReadBuffer::new(),
            timers: Timers::default(),
            metrics,
            commands,
            rib_tx,
            peer_label,
            peer_ip,
            link_local_next_hop_scope,
            negotiated: None,
            negotiated_families: Vec::new(),
            add_path_receive_families: Vec::new(),
            stop_requested: false,
            reconnect_timer: None,
            connect_task: None,
            outbound_rx,
            outbound_tx,
            import_policy,
            export_policy,
            advertise_graceful_shutdown,
            session_notify_tx,
            session_lifecycle_tx,
            session_event_tx,
            session_identity,
            bmp_tx,
            validation_rx,
            local_open_pdu: None,
            remote_open_pdu: None,
            last_down_reason: None,
            known_paths: HashSet::new(),
            known_prefix_refcounts: HashMap::new(),
            known_flowspec: HashSet::new(),
            known_evpn: HashSet::new(),
            known_bgpls: HashSet::new(),
            updates_received: 0,
            updates_sent: 0,
            notifications_received: 0,
            notifications_sent: 0,
            otc_routes_blocked: 0,
            import_policy_routes_permitted: 0,
            import_policy_routes_denied: 0,
            flap_count: 0,
            established_at: None,
            last_error: String::new(),
            notification_teardown: false,
            received_hard_reset: false,
            sent_hard_reset: false,
            event_sink: Arc::new(NoopTransportEventSink),
            import_explain_enabled: explain_enabled,
            import_decision_cache: import_decision_cache::ImportDecisionCache::with_capacity(
                explain_cache_size,
            ),
            import_policy_generation: 0,
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
            peer_asn: self
                .negotiated
                .as_ref()
                .map_or(self.config.peer.remote_asn, |n| n.peer_asn),
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

    pub(super) fn emit_notification_event(
        &self,
        direction: SessionNotificationDirection,
        notification: &NotificationMessage,
        shutdown_reason: Option<String>,
    ) {
        let Some(ref tx) = self.session_event_tx else {
            return;
        };

        let event = SessionNotificationEvent {
            session_id: self.session_identity.id,
            role: self.session_identity.role,
            peer_addr: self.peer_ip,
            direction,
            code: notification.code.as_u8(),
            subcode: notification.subcode,
            description: rustbgpd_wire::notification::description(
                notification.code,
                notification.subcode,
            )
            .to_string(),
            shutdown_reason,
        };

        if let Err(e) = tx.try_send(event) {
            let reason = match e {
                tokio::sync::mpsc::error::TrySendError::Full(_) => "channel_full",
                tokio::sync::mpsc::error::TrySendError::Closed(_) => "channel_closed",
            };
            debug!(
                peer = %self.peer_label,
                reason,
                "session notification-event channel full or closed"
            );
        }
    }

    pub(super) fn record_otc_routes_blocked(
        &mut self,
        reason: rustbgpd_telemetry::reason_labels::OtcBlockReason,
        count: u64,
    ) {
        self.otc_routes_blocked = self.otc_routes_blocked.saturating_add(count);
        self.metrics
            .record_otc_routes_blocked(&self.peer_label, reason, count);
    }

    /// Install a transport event sink for ADR-0072 structured event
    /// publishing. Called by [`crate::handle::PeerHandle::spawn_with_event_sink`]
    /// (and its inbound counterpart) before [`Self::run`] starts; the
    /// session task runs single-threaded so this `&mut` cannot race
    /// with publishes. Tests can also call this to install a
    /// recording sink before driving fixture UPDATEs.
    pub(crate) fn set_event_sink(&mut self, sink: Arc<dyn TransportEventSink>) {
        self.event_sink = sink;
    }

    pub(super) fn event_sink(&self) -> &Arc<dyn TransportEventSink> {
        &self.event_sink
    }

    /// Main event loop. Runs until Shutdown command or fatal error.
    #[expect(
        clippy::too_many_lines,
        reason = "single select! over 9 arms — splitting hides the dispatch shape"
    )]
    pub(crate) async fn run(&mut self) -> Result<(), TransportError> {
        loop {
            // Gate the TCP read arm closed while the FSM is still in `Idle`.
            // An inbound session is constructed with `read_half` already set
            // (the peer connected to us), so without this guard the `read_tcp`
            // arm is live on the very first `select!` iteration and can win the
            // race against the queued `ManualStart` command. If a peer that
            // does simultaneous-open (e.g. BIRD) has already pushed its OPEN
            // into the socket, that OPEN would be consumed in `Idle` (ignored),
            // the bootstrap `ManualStart` would then drive us to `OpenSent`, and
            // the peer's following KEEPALIVE would hit the generic
            // "unexpected event" arm → `FsmError`, leaving the session stuck.
            // `ManualStart` drives the whole inbound bootstrap synchronously in
            // one `drive_fsm` call: Idle → Connect, and because
            // `InitiateTcpConnection` sees `read_half` already set it emits a
            // `TcpConnectionConfirmed` follow-up (instead of dialing out),
            // taking the FSM to `OpenSent` + `SendOpen`. So once the FSM has
            // left `Idle` our OPEN has been sent and the buffered peer OPEN is
            // processed in `OpenSent` — the handshake completes. Outbound
            // sessions have `read_half = None` until connect completes (and that
            // same arm immediately drives `TcpConnectionConfirmed`, so the FSM
            // is past `Idle` before the next read), so this never gates a live
            // outbound read.
            let read_active = self.read_half.is_some() && self.fsm.state() != SessionState::Idle;

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
                // TCP read — only when connected and past the Idle bootstrap
                result = read_tcp(read_half, &mut read_buf.buf), if read_active => {
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
                    self.handle_hold_timer_expiry().await;
                }
                // No keepalive arm: the KEEPALIVE cadence is owned by the
                // writer task (ADR-0078), so it keeps running even while
                // this loop is parked on a blocking RIB delivery. The
                // FSM's `StartTimer(Keepalive)` is routed to the writer in
                // `execute_actions`; `timers.keepalive` is never armed.

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
                            let handle = writer::spawn(
                                wh,
                                OUTBOUND_BUFFER,
                                self.metrics.clone(),
                                self.peer_label.clone(),
                            );
                            self.read_half = Some(rh);
                            self.writer_bulk_tx = Some(handle.bulk_tx);
                            self.writer_priority_tx = Some(handle.priority_tx);
                            self.writer_keepalive_tx = Some(handle.keepalive_tx);
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
        let handle = writer::spawn(
            wh,
            OUTBOUND_BUFFER,
            self.metrics.clone(),
            self.peer_label.clone(),
        );
        self.read_half = Some(rh);
        self.writer_bulk_tx = Some(handle.bulk_tx);
        self.writer_priority_tx = Some(handle.priority_tx);
        self.writer_keepalive_tx = Some(handle.keepalive_tx);
        self.writer_join = Some(handle.join);
    }
}

#[cfg(test)]
mod tests;
