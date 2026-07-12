mod commands;
pub(crate) mod export;
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
    BgpLsFamily, BgpLsRibRoute, BgpLsRouteKey, EvpnRibRoute, FlowSpecKey, FlowSpecRoute,
    LabeledRibRoute, LabeledRibRouteKey, NextHopScope, OutboundRouteUpdate, RibUpdate, Route,
    RtcRibRoute, RtcRibRouteKey, VpnRibRoute, VpnRibRouteKey,
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
use self::export::remove_private_asns;
use self::export::{SessionExportEncoder, SessionExportProfile};
#[cfg(test)]
use self::fsm::{hard_reset_notification_in_actions, notification_teardown_event};

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
    /// `trigger_outbound_out_of_resources_teardown`):
    ///
    /// - **At connect**: `read_half`, both writer senders, and
    ///   `writer_join` are all set together.
    /// - **At teardown**: `read_half` and both writer senders are
    ///   dropped synchronously. `writer_join` is **intentionally
    ///   retained** so the run-loop's writer-exit `select!` arm can
    ///   observe the writer task exiting — cleanly after draining its
    ///   priority queue on ordinary closes, or with
    ///   `WriterExit::TornDown` after the saturation hard close (bulk
    ///   backlog discarded, `Cease/8` flushed best-effort). The arm body
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
    /// Hard-teardown signal for the writer task. Signalled (before the
    /// senders are dropped) by the Cease/Out-of-Resources teardown path:
    /// the writer discards its bulk backlog so the `Cease/8` is the final
    /// frame on the wire, then exits `WriterExit::TornDown`, which the
    /// writer-exit arm maps to `TcpConnectionFails`. Ordinary close paths
    /// drop it unsignalled (drain semantics preserved).
    writer_teardown_tx: Option<watch::Sender<bool>>,
    /// `JoinHandle` of the writer task. Polled by the session's
    /// `select!` so writer-exit (clean shutdown, TCP error, or RFC 9687
    /// send-hold expiry) surfaces as a TCP-disconnect event.
    writer_join: Option<JoinHandle<Result<(), writer::WriterExit>>>,
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
    connect_task: Option<ConnectTask>,
    /// Receiver for outbound route updates from the RIB manager.
    outbound_rx: mpsc::Receiver<OutboundRouteUpdate>,
    /// Sender clone held to give to RIB manager on `PeerUp`.
    outbound_tx: mpsc::Sender<OutboundRouteUpdate>,
    /// Import policy (prefix filter applied to inbound UPDATEs).
    import_policy: Option<PolicyChain>,
    /// Whether the inbound hot path must build the per-UPDATE `AS_PATH`
    /// match string (`PolicyAttrSummary::as_path_str`). Derived from
    /// the import chain via `PolicyChain::requires_as_path_string`
    /// (mirroring the export-side gate in the RIB distribution
    /// modules) plus the explain toggle — cached decisions store the
    /// evaluation-time context verbatim. Recomputed once per chain
    /// install (`install_import_policy`), not per UPDATE.
    import_needs_as_path_string: bool,
    /// Export policy (sent to RIB manager on `PeerUp` for per-peer filtering).
    export_policy: Option<PolicyChain>,
    /// Authoritative immutable snapshot owner for outbound wire encoding.
    /// Each RIB envelope captures one snapshot before any preparation/build.
    export_encoder: Arc<SessionExportEncoder>,
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
    /// A `RouteMonitoring` event for this session was dropped on a full
    /// BMP channel while the mirrored traffic *did* flow (the outbound
    /// UPDATE reached the writer, or the inbound UPDATE reached the
    /// RIB): the collectors' view of this peer has silently diverged
    /// and — rib-in/rib-out being live-only streams with no dump — will
    /// never self-correct. Repaired by forcing a synthetic
    /// PeerDown/PeerUp pair ahead of the next BMP event for this peer
    /// (an RFC 7854 peer-state reset collectors can detect), retried on
    /// `bmp_repair_timer` so a session that goes quiet right after the
    /// drop cannot stay diverged indefinitely.
    bmp_stream_diverged: bool,
    /// Bounded-latency retry for the forced peer-state reset above.
    /// Armed whenever `bmp_stream_diverged` is set and the reset could
    /// not be emitted yet (BMP channel still full).
    bmp_repair_timer: Option<Pin<Box<Sleep>>>,
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
    known_flowspec: HashSet<FlowSpecKey>,
    /// Accepted EVPN routes from this peer (RFC 7432 keys). Counted
    /// toward max-prefix enforcement for the same reason.
    known_evpn: HashSet<EvpnRouteKey>,
    /// Accepted BGP-LS routes from this peer (RFC 9552 opaque keys). Counted
    /// toward max-prefix enforcement for the same reason.
    known_bgpls: HashSet<BgpLsRouteKey>,
    /// Accepted VPNv4/VPNv6 routes from this peer (RFC 4364 / RFC 4659 keys).
    /// Counted toward max-prefix enforcement for the same reason.
    known_vpn: HashSet<VpnRibRouteKey>,
    /// Labeled-unicast route keys received from this peer (max-prefix
    /// accounting, keyed by prefix + `path_id` like the VPN sibling).
    known_labeled: HashSet<LabeledRibRouteKey>,
    /// Accepted RT-Constrain routes from this peer (RFC 4684 keys). Counted
    /// toward max-prefix enforcement for the same reason.
    known_rtc: HashSet<RtcRibRouteKey>,
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
    /// Latest query-time TCP-AO inspection for the currently owned stream.
    tcp_ao_info: Option<crate::TcpAoInfoSnapshot>,
    /// Secret-free configured MKT identity/rollover metadata. This survives
    /// inspection failures so recovered snapshots retain their annotations.
    tcp_ao_key_metadata: Vec<TcpAoKeyMetadata>,
    /// Durable protection identity for this session. Unlike `tcp_ao_info`,
    /// inspection failure never clears this bit, so a protected accepted
    /// session keeps retrying read-only inspection on later queries.
    tcp_ao_protected: bool,
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

#[derive(Clone)]
struct TcpAoKeyMetadata {
    peer: IpAddr,
    prefix_len: u8,
    send_id: u8,
    recv_id: u8,
    algorithm: crate::TcpAoAlgorithm,
    preferred: bool,
    deprecated: bool,
}

fn tcp_ao_key_metadata(
    config: &TransportConfig,
    initial: Option<&crate::TcpAoInfoSnapshot>,
) -> Vec<TcpAoKeyMetadata> {
    if let Some(key) = config.tcp_ao.as_ref() {
        return vec![TcpAoKeyMetadata {
            peer: config.remote_addr.ip(),
            prefix_len: if config.remote_addr.is_ipv4() {
                32
            } else {
                128
            },
            send_id: key.send_id,
            recv_id: key.recv_id,
            algorithm: key.algorithm,
            preferred: key.preferred,
            deprecated: key.deprecated,
        }];
    }
    initial
        .into_iter()
        .flat_map(|snapshot| &snapshot.keys)
        .map(|key| TcpAoKeyMetadata {
            peer: key.peer,
            prefix_len: key.prefix_len,
            send_id: key.send_id,
            recv_id: key.recv_id,
            algorithm: key.algorithm,
            preferred: key.preferred,
            deprecated: key.deprecated,
        })
        .collect()
}

/// Outbound channel buffer size.
const OUTBOUND_BUFFER: usize = 4096;

/// Retry cadence for the forced BMP peer-state reset after a dropped
/// `RouteMonitoring` event (see `PeerSession::bmp_stream_diverged`).
/// Short enough that a diverged-then-quiet session is repaired promptly;
/// long enough not to spin while the BMP channel stays saturated.
const BMP_STREAM_REPAIR_RETRY: Duration = Duration::from_secs(1);

/// FSM event code carried in the BMP Peer Down reason-2 body when the
/// send hold timer expires: Event 29, `SendHoldTimer_Expires` (RFC 9687
/// §4.2, extending the RFC 4271 §8.1 event numbering that RFC 7854 §4.9
/// references for "Local system closed, no NOTIFICATION").
const SEND_HOLD_TIMER_EXPIRES_FSM_EVENT: u16 = 29;

/// The writer's RFC 9687 `SendHoldTime` for this session, as a
/// `Duration`. `0` in config means disabled (`None`).
fn send_hold_duration(config: &TransportConfig) -> Option<Duration> {
    (config.peer.send_hold_time > 0)
        .then(|| Duration::from_secs(u64::from(config.peer.send_hold_time)))
}

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
            + self.known_vpn.len()
            + self.known_labeled.len()
            + self.known_rtc.len()
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
        self.known_vpn.clear();
        self.known_labeled.clear();
        self.known_rtc.clear();
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
        let tcp_ao_protected = config.tcp_ao.is_some();
        let tcp_ao_key_metadata = tcp_ao_key_metadata(&config, None);
        let import_needs_as_path_string =
            Self::import_chain_needs_as_path_string(import_policy.as_ref(), explain_enabled);
        let (outbound_tx, outbound_rx) = mpsc::channel(OUTBOUND_BUFFER);
        let export_encoder = Arc::new(SessionExportEncoder::new(SessionExportProfile::initial(
            &config,
            None,
            advertise_graceful_shutdown,
        )));
        Self {
            config,
            fsm,
            read_half: None,
            writer_bulk_tx: None,
            writer_priority_tx: None,
            writer_keepalive_tx: None,
            writer_teardown_tx: None,
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
            import_needs_as_path_string,
            export_policy,
            export_encoder,
            advertise_graceful_shutdown,
            session_notify_tx,
            session_lifecycle_tx,
            session_event_tx,
            session_identity,
            bmp_tx,
            bmp_stream_diverged: false,
            bmp_repair_timer: None,
            validation_rx,
            local_open_pdu: None,
            remote_open_pdu: None,
            last_down_reason: None,
            known_paths: HashSet::new(),
            known_prefix_refcounts: HashMap::new(),
            known_flowspec: HashSet::new(),
            known_evpn: HashSet::new(),
            known_bgpls: HashSet::new(),
            known_vpn: HashSet::new(),
            known_labeled: HashSet::new(),
            known_rtc: HashSet::new(),
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
            tcp_ao_info: None,
            tcp_ao_key_metadata,
            tcp_ao_protected,
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
        tcp_ao_info: Option<crate::TcpAoInfoSnapshot>,
    ) -> Self {
        let peer_label = config.remote_addr.to_string();
        let peer_ip = config.remote_addr.ip();
        let link_local_next_hop_scope = Self::link_local_next_hop_scope_from_config(&config);
        let fsm = Session::new(config.peer.clone());
        let explain_enabled = config.explain_enabled;
        let explain_cache_size = config.explain_cache_size;
        let tcp_ao_protected = config.tcp_ao.is_some() || tcp_ao_info.is_some();
        let tcp_ao_key_metadata = tcp_ao_key_metadata(&config, tcp_ao_info.as_ref());
        let import_needs_as_path_string =
            Self::import_chain_needs_as_path_string(import_policy.as_ref(), explain_enabled);
        let (outbound_tx, outbound_rx) = mpsc::channel(OUTBOUND_BUFFER);
        let export_encoder = Arc::new(SessionExportEncoder::new(SessionExportProfile::initial(
            &config,
            stream.local_addr().ok().map(|addr| addr.ip()),
            advertise_graceful_shutdown,
        )));
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
            send_hold_duration(&config),
        );
        Self {
            config,
            fsm,
            read_half: Some(read_half),
            writer_bulk_tx: Some(writer_handle.bulk_tx),
            writer_priority_tx: Some(writer_handle.priority_tx),
            writer_keepalive_tx: Some(writer_handle.keepalive_tx),
            writer_teardown_tx: Some(writer_handle.teardown_tx),
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
            import_needs_as_path_string,
            export_policy,
            export_encoder,
            advertise_graceful_shutdown,
            session_notify_tx,
            session_lifecycle_tx,
            session_event_tx,
            session_identity,
            bmp_tx,
            bmp_stream_diverged: false,
            bmp_repair_timer: None,
            validation_rx,
            local_open_pdu: None,
            remote_open_pdu: None,
            last_down_reason: None,
            known_paths: HashSet::new(),
            known_prefix_refcounts: HashMap::new(),
            known_flowspec: HashSet::new(),
            known_evpn: HashSet::new(),
            known_bgpls: HashSet::new(),
            known_vpn: HashSet::new(),
            known_labeled: HashSet::new(),
            known_rtc: HashSet::new(),
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
            tcp_ao_info,
            tcp_ao_key_metadata,
            tcp_ao_protected,
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

    /// Whether an import chain (plus the explain toggle) needs the
    /// per-UPDATE `AS_PATH` match string. See
    /// [`Self::install_import_policy`].
    fn import_chain_needs_as_path_string(
        import_policy: Option<&PolicyChain>,
        explain_enabled: bool,
    ) -> bool {
        explain_enabled || import_policy.is_some_and(PolicyChain::requires_as_path_string)
    }

    /// Install (or clear) the import chain, recomputing the cached
    /// `as_path_str` gate. The single mutation point for
    /// `import_policy` after construction — assigning the field
    /// directly would desynchronize the gate.
    pub(super) fn install_import_policy(&mut self, policy: Option<PolicyChain>) {
        self.import_needs_as_path_string =
            Self::import_chain_needs_as_path_string(policy.as_ref(), self.import_explain_enabled);
        self.import_policy = policy;
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
            is_rib_out: false,
            is_as4,
            timestamp: SystemTime::now(),
        }
    }

    /// Build the BMP `PeerUp` event for this session (RFC 7854 §4.10).
    /// Used at `SessionEstablished` and by the forced peer-state reset
    /// after a dropped `RouteMonitoring` event.
    fn build_bmp_peer_up_event(&self) -> BmpEvent {
        let (local_addr, local_port, remote_port) =
            self.read_half
                .as_ref()
                .map_or((IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0, 0), |h| {
                    let local = h.local_addr().ok();
                    let remote = h.peer_addr().ok();
                    (
                        local.map_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED), |a| a.ip()),
                        local.map_or(0, |a| a.port()),
                        remote.map_or(0, |a| a.port()),
                    )
                });
        BmpEvent::PeerUp {
            peer_info: self.build_bmp_peer_info(),
            local_open: self.local_open_pdu.clone().unwrap_or_default(),
            remote_open: self.remote_open_pdu.clone().unwrap_or_default(),
            local_addr,
            local_port,
            remote_port,
        }
    }

    /// Lossy BMP emission for the high-rate mirror events
    /// (`RouteMonitoring`, `StatsReport`): never blocks and never
    /// backpressures the session (ADR-0041/0097 posture). A full
    /// channel drops the event and bumps `bmp_source_drops_total` —
    /// but a dropped `RouteMonitoring` additionally latches
    /// `bmp_stream_diverged`, because the mirrored traffic did flow and
    /// the collectors' live-only rib-in/rib-out views would otherwise
    /// be silently wrong forever. The pending divergence is repaired
    /// (forced PeerDown/PeerUp reset) ahead of the next emission, or
    /// from the run loop's `bmp_repair_timer` arm if the session goes
    /// quiet first. Lifecycle events must use
    /// [`Self::emit_bmp_event_reliable`] instead.
    fn emit_bmp_event(&mut self, event: BmpEvent) {
        let Some(tx) = self.bmp_tx.clone() else {
            return;
        };
        if self.bmp_stream_diverged && !self.repair_bmp_stream(&tx) {
            // The channel is still saturated: this event cannot be
            // emitted ahead of the pending peer-state reset without
            // presenting the collector a diverged stream as healthy.
            self.metrics
                .record_bmp_source_drop(&self.peer_label, "channel_full");
            return;
        }
        let is_route_monitoring = matches!(event, BmpEvent::RouteMonitoring { .. });
        if let Err(e) = tx.try_send(event) {
            let reason = match e {
                tokio::sync::mpsc::error::TrySendError::Full(_) => "channel_full",
                tokio::sync::mpsc::error::TrySendError::Closed(_) => "channel_closed",
            };
            self.metrics
                .record_bmp_source_drop(&self.peer_label, reason);
            debug!(peer = %self.peer_label, reason, "BMP event channel full or closed");
            if is_route_monitoring && matches!(e, tokio::sync::mpsc::error::TrySendError::Full(_)) {
                self.mark_bmp_stream_diverged();
            }
        }
    }

    /// Reliable BMP emission for the per-peer lifecycle events
    /// (`PeerUp`, `PeerDown`). These are the collectors' state-reset
    /// signals — losing one leaves every collector permanently wrong
    /// about the peer — so instead of the lossy `try_send` this awaits
    /// channel space. Bounded: the `BmpManager` loop never blocks
    /// (sync encode + per-collector `try_send`), so the wait is at most
    /// one channel drain, and a dead manager surfaces as an immediate
    /// send error (counted, session unaffected).
    ///
    /// A real `PeerDown` also supersedes any pending divergence repair:
    /// it resets collector state, and the re-established session
    /// re-floods both rib-in (peer resends) and rib-out (initial-table
    /// walk re-enters the tap).
    async fn emit_bmp_event_reliable(&mut self, event: BmpEvent) {
        let Some(tx) = self.bmp_tx.clone() else {
            return;
        };
        if matches!(event, BmpEvent::PeerDown { .. }) {
            self.bmp_stream_diverged = false;
            self.bmp_repair_timer = None;
        }
        if tx.send(event).await.is_err() {
            self.metrics
                .record_bmp_source_drop(&self.peer_label, "channel_closed");
            debug!(peer = %self.peer_label, "BMP event channel closed");
        }
    }

    /// Latch the divergence flag after a dropped `RouteMonitoring` and
    /// arm the bounded-latency repair timer.
    fn mark_bmp_stream_diverged(&mut self) {
        if !self.bmp_stream_diverged {
            warn!(
                peer = %self.peer_label,
                "BMP RouteMonitoring dropped on a full channel while the mirrored \
                 traffic flowed — collector view diverged; forcing a BMP peer-state \
                 reset once the channel drains"
            );
        }
        self.bmp_stream_diverged = true;
        self.bmp_repair_timer = Some(Box::pin(tokio::time::sleep(BMP_STREAM_REPAIR_RETRY)));
    }

    /// Attempt the pending RFC 7854 peer-state reset: a synthetic
    /// `PeerDown` (reason 2 — local close, no NOTIFICATION, FSM event
    /// code 0) followed by a fresh `PeerUp`, making the earlier
    /// divergence collector-detectable (the collector discards its
    /// state for this peer and rebuilds from subsequent monitoring).
    /// Returns `true` when the pair was enqueued and the flag cleared;
    /// `false` when the channel is still saturated (flag and retry
    /// timer stay armed; a duplicate `PeerDown` from a partial attempt
    /// is harmless).
    fn repair_bmp_stream(&mut self, tx: &mpsc::Sender<BmpEvent>) -> bool {
        let down = BmpEvent::PeerDown {
            peer_info: self.build_bmp_peer_info(),
            reason: PeerDownReason::LocalNoNotification(0),
        };
        if tx.try_send(down).is_err() {
            return false;
        }
        if tx.try_send(self.build_bmp_peer_up_event()).is_err() {
            return false;
        }
        self.bmp_stream_diverged = false;
        self.bmp_repair_timer = None;
        info!(
            peer = %self.peer_label,
            "BMP peer-state reset emitted after earlier RouteMonitoring drop — \
             collector view resynchronized via PeerDown/PeerUp"
        );
        true
    }

    /// Run-loop timer entry for the deferred divergence repair: retry
    /// the forced peer-state reset, re-arming the timer while the BMP
    /// channel remains saturated.
    fn retry_bmp_stream_repair(&mut self) {
        if !self.bmp_stream_diverged {
            return;
        }
        let Some(tx) = self.bmp_tx.clone() else {
            return;
        };
        if !self.repair_bmp_stream(&tx) {
            self.bmp_repair_timer = Some(Box::pin(tokio::time::sleep(BMP_STREAM_REPAIR_RETRY)));
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

    /// Handle the writer task's exit as observed by the run-loop
    /// `select!`. Clean exits (both senders dropped) are the tail end
    /// of a teardown already in progress; everything else is treated as
    /// a TCP disconnect. A send-hold expiry (RFC 9687 §4.3) additionally
    /// records the local no-NOTIFICATION cause before tearing down:
    ///
    /// - counter `bgp_send_hold_expirations_total{peer}`;
    /// - BMP Peer Down reason 2 (local close, no NOTIFICATION) with FSM
    ///   event code 29 (`SendHoldTimer_Expires`, RFC 9687 §4.2);
    /// - an operator event carrying BGP error code 8 / subcode 0
    ///   ("Send Hold Timer Expired", RFC 9687 §5) — the §4.3 required
    ///   error log in event-history form. No NOTIFICATION is put on the
    ///   wire: the socket is not draining and §4.3 only permits one when
    ///   it cannot delay the teardown.
    ///
    /// The subsequent `TcpConnectionFails` drive performs exactly the
    /// §4.3 expiry actions: session down, TCP close, `ConnectRetryCounter`
    /// increment, transition to Idle.
    async fn handle_writer_exit(
        &mut self,
        join_result: Result<Result<(), writer::WriterExit>, tokio::task::JoinError>,
    ) {
        match join_result {
            Ok(Ok(())) => {
                debug!(peer = %self.peer_label, "writer task exited cleanly");
                return;
            }
            Ok(Err(writer::WriterExit::SendHoldExpired { limit })) => {
                // The writer already logged the expiry at `warn`.
                self.metrics.record_send_hold_expiration(&self.peer_label);
                self.last_down_reason = Some(PeerDownReason::LocalNoNotification(
                    SEND_HOLD_TIMER_EXPIRES_FSM_EVENT,
                ));
                self.last_error = format!(
                    "send hold timer expired after {}s (RFC 9687)",
                    limit.as_secs()
                );
                self.emit_notification_event(
                    SessionNotificationDirection::Sent,
                    &NotificationMessage {
                        code: NotificationCode::SendHoldTimerExpired,
                        subcode: 0,
                        data: Bytes::new(),
                    },
                    Some(format!(
                        "send hold timer ({}s) expired; session terminated locally without \
                         sending a NOTIFICATION (RFC 9687 §4.3)",
                        limit.as_secs()
                    )),
                );
            }
            Ok(Err(writer::WriterExit::TornDown)) => {
                // Saturation teardown: the writer discarded the bulk
                // backlog, put the Cease/8 on the wire best-effort, and
                // hard-closed. Fall through so the FSM sees
                // `TcpConnectionFails` and the RIB gets its
                // PeerDown/deregistration from this run-loop path.
                debug!(peer = %self.peer_label, "writer task hard-closed by saturation teardown");
            }
            Ok(Err(writer::WriterExit::Io(e))) => {
                debug!(peer = %self.peer_label, error = %e, "writer task TCP error");
            }
            Err(e) => {
                warn!(peer = %self.peer_label, error = %e, "writer task panicked");
            }
        }
        self.handle_tcp_disconnect();
        self.drive_fsm(Event::TcpConnectionFails).await;
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
        reason = "the run loop keeps every select! arm and its state wiring in one place"
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
                bmp_repair_timer,
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

                // Deferred BMP peer-state reset after a dropped
                // RouteMonitoring event (`bmp_stream_diverged`): retry
                // on a short timer so a session that goes quiet right
                // after the drop cannot leave collectors silently
                // diverged until its next update.
                () = poll_timer(bmp_repair_timer) => {
                    self.bmp_repair_timer = None;
                    self.retry_bmp_stream_repair();
                }

                // In-flight outbound TCP connect completion
                result = io::poll_connect(connect_task), if connect_task.is_some() => {
                    self.connect_task = None;
                    match result {
                        Ok(Ok((stream, tcp_ao_info))) => {
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
                                send_hold_duration(&self.config),
                            );
                            self.read_half = Some(rh);
                            self.tcp_ao_info = tcp_ao_info;
                            self.writer_bulk_tx = Some(handle.bulk_tx);
                            self.writer_priority_tx = Some(handle.priority_tx);
                            self.writer_keepalive_tx = Some(handle.keepalive_tx);
                            self.writer_teardown_tx = Some(handle.teardown_tx);
                            self.writer_join = Some(handle.join);
                            self.drive_fsm(Event::TcpConnectionConfirmed).await;
                        }
                        Ok(Err(e)) => {
                            debug!(peer = %self.peer_label, error = %e, "TCP connect failed");
                            self.record_connect_failure(&e);
                            self.drive_fsm(Event::TcpConnectionFails).await;
                        }
                        Err(e) => {
                            debug!(peer = %self.peer_label, error = %e, "TCP connect task failed");
                            self.record_connect_failure(&e);
                            self.drive_fsm(Event::TcpConnectionFails).await;
                        }
                    }
                }

                // Writer task exit — clean shutdown when both senders
                // dropped (close_tcp / handle_tcp_disconnect did their
                // job), or `Err(WriterExit)` when TCP write/flush failed
                // or the RFC 9687 send hold timer expired. Either way,
                // treat as TCP-disconnect from the session's
                // perspective. The arm clears `writer_join = None` to
                // prevent the second-poll panic.
                join_result = io::await_writer_join(writer_join), if writer_join.is_some() => {
                    self.writer_join = None;
                    self.handle_writer_exit(join_result).await;
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
            send_hold_duration(&self.config),
        );
        self.read_half = Some(rh);
        self.writer_bulk_tx = Some(handle.bulk_tx);
        self.writer_priority_tx = Some(handle.priority_tx);
        self.writer_keepalive_tx = Some(handle.keepalive_tx);
        self.writer_teardown_tx = Some(handle.teardown_tx);
        self.writer_join = Some(handle.join);
    }
}

#[cfg(test)]
mod tests;
pub(super) type ConnectResult = std::io::Result<(TcpStream, Option<crate::TcpAoInfoSnapshot>)>;
pub(super) type ConnectTask = JoinHandle<ConnectResult>;
