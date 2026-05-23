use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use rustbgpd_api::peer_types::{
    ConfigEvent, DynamicNeighborInfo, POLICY_EVENT_HISTORY_CAPACITY, PeerManagerCommand,
    PeerManagerNeighborConfig, PolicyEvent, SESSION_EVENT_HISTORY_CAPACITY, SessionEvent,
    SessionLifecycleEvent,
};
use rustbgpd_bmp::BmpEvent;
use rustbgpd_fsm::PeerConfig;
use rustbgpd_policy::PolicyChain;
use rustbgpd_rib::RibUpdate;
use rustbgpd_telemetry::BgpMetrics;
use rustbgpd_transport::{
    PeerHandle, SessionLifecycleNotification, SessionNotification,
    SessionNotificationEvent as TransportNotificationEvent, TransportConfig,
};
use rustbgpd_wire::{Afi, Safi};
use tokio::sync::{broadcast, mpsc, watch};
use tracing::{debug, error, info, warn};

use crate::config::Config;
use crate::policy_admin::{
    global_policy_chains_from_config, named_neighbor_set_from_config,
    named_neighbor_sets_from_config, named_peer_group_from_config, named_peer_groups_from_config,
    named_policies_from_config, named_policy_from_config, neighbor_policy_chains_from_config,
};

mod dynamic;
mod events;
mod inbound;
mod lifecycle;
mod notifications;
mod policy;
mod reconcile;
mod snapshot;

use dynamic::{DeadLetteredPending, DynamicRange};

const DEFAULT_HOLD_TIME: u16 = 90;
const DEFAULT_CONNECT_RETRY_SECS: u32 = 5;
const BGP_PORT: u16 = 179;
const BMP_STATS_INTERVAL_SECS: u64 = 60;

/// Hard deadline for any single per-peer `query_state` request. Bounded so a
/// session task that's parked on TCP write back-pressure can't hang an admin
/// path (`ListPeers`, `GetPeerState`, periodic BMP stats). 100ms is well
/// above any healthy session-task command latency (typically <1ms) and well
/// below the 5-minute soak-harness gRPC health-check cadence, so a single
/// stalled peer surfaces as `stale = true` instead of as a wedged RPC.
const PEER_QUERY_TIMEOUT: Duration = Duration::from_millis(100);

/// Hard deadline for any single peer-session policy hot-apply (import or
/// export). Larger than [`PEER_QUERY_TIMEOUT`] because applying a policy
/// chain involves more session-side work than a state read, but still
/// bounded so a stalled peer can't park the peer-manager actor mid-reload.
/// If a policy update fails this deadline, the new policy still applies on
/// the peer's next session restart — the warn! is just a heads-up.
const PEER_POLICY_UPDATE_TIMEOUT: Duration = Duration::from_millis(500);

pub(crate) enum InternalCommand {
    ReplaceConfigSnapshot(Box<Config>),
}

#[allow(clippy::struct_excessive_bools)]
struct ManagedPeer {
    handle: PeerHandle,
    session_id: u64,
    remote_asn: u32,
    description: String,
    peer_group: Option<String>,
    enabled: bool,
    hold_time: Option<u16>,
    max_prefixes: Option<u32>,
    transport_config: TransportConfig,
    import_policy: Option<PolicyChain>,
    export_policy: Option<PolicyChain>,
    /// Live inbound session waiting for collision resolution.
    pending_inbound: Option<PendingInbound>,
    /// True for peers auto-created from a `[[dynamic_neighbors]]` range.
    /// Dynamic peers are ephemeral: removed when session falls to Idle.
    is_dynamic: bool,
    /// Tracks unfired Route Refresh intent across calls. Set in any
    /// of three places that can leave a refresh undelivered:
    /// (1) `soft_reset_in` returned Err (session not reachable for
    /// `send_route_refresh` despite Established state); (2) the
    /// function bailed before reaching `soft_reset_in` because some
    /// downstream step failed (session-side hot-apply, RIB update),
    /// and `needs_refresh` was true at bail time — covers the
    /// cross-side carry case where import succeeded (advancing
    /// bookkeeping) but export bailed; (3) the peer wasn't
    /// Established at the time of an inherited
    /// `had_pending_refresh`, so no refresh was sendable. Drained
    /// at the start of every `update_runtime_policies` call and
    /// folded into `needs_refresh` alongside `import_changed`.
    /// Without this, a transient failure would leave the new policy
    /// applied to *future* UPDATEs while routes already in
    /// `AdjRibIn` — accepted under the prior policy — keep flowing
    /// until the operator reissues a `SetPolicy`.
    pending_refresh: bool,
    /// Symmetric counterpart for the export side. Set when
    /// `update_export_policy_timeout` failed for an export-changing
    /// edit, OR when the function bailed before completing the
    /// export-side pipeline with `needs_export_apply` true (the
    /// cross-side carry case). Drained by the next
    /// `update_runtime_policies` call and folded into
    /// `needs_export_apply` alongside `export_changed`. Without
    /// this, a transient session-side export-policy update failure
    /// would leave the peer announcing under the prior policy while
    /// the daemon's config snapshot has already advanced —
    /// permit→deny export edits would silently keep leaking routes,
    /// and the symmetry with the import side guarantees both halves
    /// of a `SetPolicy` carry the same all-or-nothing semantics.
    pending_export_apply: bool,
    /// RFC 8326 graceful-shutdown initiator toggle — operator-driven
    /// desired state. When true, every outbound update gets
    /// `COMMUNITY_GRACEFUL_SHUTDOWN` (`0xFFFF_0000`) attached.
    ///
    /// `PeerManager` is the authority; the per-session bool in
    /// `PeerSession` mirrors this value and gets re-seeded on every
    /// session spawn (collision-replace, dynamic peer re-establish,
    /// flap-and-reconnect). Without this lift, an operator who
    /// runs `rustbgpctl gshut --peer X` and then experiences a peer
    /// flap would have the toggle silently lost — the new session
    /// would come up advertising untagged routes during the very
    /// maintenance window the toggle was supposed to cover.
    advertise_graceful_shutdown: bool,
}

struct PendingInbound {
    handle: PeerHandle,
    session_id: u64,
}

/// Manages the lifecycle of all peer sessions.
///
/// Runs as a single tokio task, receiving commands via an mpsc channel.
/// Same single-task ownership pattern as `RibManager`.
pub struct PeerManager {
    peers: HashMap<IpAddr, ManagedPeer>,
    rx: mpsc::Receiver<PeerManagerCommand>,
    internal_rx: mpsc::UnboundedReceiver<InternalCommand>,
    local_asn: u32,
    router_id: Ipv4Addr,
    /// Local cluster ID for route reflection (RFC 4456). `None` when not an RR.
    cluster_id: Option<Ipv4Addr>,
    /// Process-wide local restarting-speaker GR deadline. Static peers
    /// restored during this window advertise `restart_state = true`.
    local_gr_restart_until: Option<Instant>,
    metrics: BgpMetrics,
    rib_tx: mpsc::Sender<RibUpdate>,
    /// Optional BMP event sender (None when BMP not configured).
    bmp_tx: Option<mpsc::Sender<BmpEvent>>,
    /// RPKI/ASPA validation snapshot receiver, cloned to each peer session.
    validation_rx: Option<watch::Receiver<rustbgpd_rpki::ValidationSnapshot>>,
    session_notify_tx: mpsc::UnboundedSender<SessionNotification>,
    session_notify_rx: mpsc::UnboundedReceiver<SessionNotification>,
    session_lifecycle_tx: mpsc::Sender<SessionLifecycleNotification>,
    session_lifecycle_rx: mpsc::Receiver<SessionLifecycleNotification>,
    session_notification_event_tx: mpsc::Sender<TransportNotificationEvent>,
    session_notification_event_rx: mpsc::Receiver<TransportNotificationEvent>,
    session_events_tx: broadcast::Sender<SessionEvent>,
    session_event_history: VecDeque<SessionLifecycleEvent>,
    policy_events_tx: broadcast::Sender<PolicyEvent>,
    policy_event_history: VecDeque<PolicyEvent>,
    current_config: Config,
    /// Resolved dynamic neighbor ranges for prefix-based auto-accept.
    dynamic_ranges: Vec<DynamicRange>,
    /// Current number of active dynamic peers (for limit enforcement).
    dynamic_peer_count: usize,
    /// Maximum dynamic peers allowed. Default 100.
    dynamic_neighbor_limit: u32,
    /// Dead-lettered hot-apply / Route Refresh / `GShut` intent from dynamic
    /// peers auto-removed by `BackToIdle`. Restored on the next inbound
    /// from the same address. Bounded at `dynamic_neighbor_limit` so a
    /// pathological churn pattern can't grow it without bound; an over-
    /// cap insert evicts an arbitrary existing entry with a `warn!`.
    dead_lettered_pending: HashMap<IpAddr, DeadLetteredPending>,
    next_session_id: u64,
}

impl PeerManager {
    #[cfg(test)]
    #[expect(clippy::too_many_arguments)]
    pub fn new(
        rx: mpsc::Receiver<PeerManagerCommand>,
        local_asn: u32,
        router_id: Ipv4Addr,
        cluster_id: Option<Ipv4Addr>,
        local_gr_restart_until: Option<Instant>,
        metrics: BgpMetrics,
        rib_tx: mpsc::Sender<RibUpdate>,
        bmp_tx: Option<mpsc::Sender<BmpEvent>>,
    ) -> Self {
        let (_internal_tx, internal_rx) = mpsc::unbounded_channel();
        Self::new_with_config(
            rx,
            internal_rx,
            local_asn,
            router_id,
            cluster_id,
            local_gr_restart_until,
            metrics,
            rib_tx,
            bmp_tx,
            None, // no RPKI validation in tests
            Config {
                global: crate::config::Global {
                    asn: local_asn,
                    router_id: router_id.to_string(),
                    listen_port: BGP_PORT,
                    cluster_id: cluster_id.map(|id| id.to_string()),
                    runtime_state_dir: "/tmp/rustbgpd-tests".to_string(),
                    telemetry: crate::config::TelemetryConfig {
                        prometheus_addr: Some("127.0.0.1:9179".to_string()),
                        log_format: "json".to_string(),
                        grpc_tcp: None,
                        grpc_uds: None,
                        looking_glass: None,
                    },
                    dynamic_neighbor_limit: None,
                    honor_graceful_shutdown: false,
                    honor_blackhole: false,
                    install_blackhole_discard: false,
                    allow_blackhole_broad_prefixes: false,
                },
                // PeerManager::new constructs an in-memory baseline
                // Config before the operator's TOML is applied. The
                // schema default is `enforcement = "tier"` after the
                // v0.24.0 flip, but a defaulted Config has no
                // [security.grpc.roles], which would fail
                // post-apply validation in `apply_config_event`.
                // Use the explicit legacy posture here so the
                // baseline is internally consistent; the real
                // config arrives via reload / config-bridge with
                // its own [security.grpc] block.
                security: crate::config::SecurityConfig {
                    grpc: crate::config::GrpcSecurityConfig {
                        enforcement: crate::config::GrpcEnforcementConfig::Legacy,
                        roles: std::collections::HashMap::new(),
                    },
                },
                neighbors: Vec::new(),
                peer_groups: HashMap::new(),
                policy: crate::config::PolicyConfig::default(),
                rpki: None,
                bmp: None,
                mrt: None,
                file_path: None,
                dynamic_neighbors: Vec::new(),
                evpn_instances: Vec::new(),
                ethernet_segments: Vec::new(),
                evpn_ip_vrfs: Vec::new(),
                fib_tables: Vec::new(),
                apply_bum_enforcement: false,
            },
        )
    }

    #[expect(clippy::too_many_arguments)]
    pub fn new_with_config(
        rx: mpsc::Receiver<PeerManagerCommand>,
        internal_rx: mpsc::UnboundedReceiver<InternalCommand>,
        local_asn: u32,
        router_id: Ipv4Addr,
        cluster_id: Option<Ipv4Addr>,
        local_gr_restart_until: Option<Instant>,
        metrics: BgpMetrics,
        rib_tx: mpsc::Sender<RibUpdate>,
        bmp_tx: Option<mpsc::Sender<BmpEvent>>,
        validation_rx: Option<watch::Receiver<rustbgpd_rpki::ValidationSnapshot>>,
        current_config: Config,
    ) -> Self {
        let (session_notify_tx, session_notify_rx) = mpsc::unbounded_channel();
        let (session_lifecycle_tx, session_lifecycle_rx) = mpsc::channel(4096);
        let (session_notification_event_tx, session_notification_event_rx) = mpsc::channel(4096);
        let (session_events_tx, _) = broadcast::channel(4096);
        let (policy_events_tx, _) = broadcast::channel(4096);
        Self {
            peers: HashMap::new(),
            rx,
            internal_rx,
            local_asn,
            router_id,
            cluster_id,
            local_gr_restart_until,
            metrics,
            rib_tx,
            bmp_tx,
            validation_rx,
            session_notify_tx,
            session_notify_rx,
            session_lifecycle_tx,
            session_lifecycle_rx,
            session_notification_event_tx,
            session_notification_event_rx,
            session_events_tx,
            session_event_history: VecDeque::with_capacity(SESSION_EVENT_HISTORY_CAPACITY),
            policy_events_tx,
            policy_event_history: VecDeque::with_capacity(POLICY_EVENT_HISTORY_CAPACITY),
            dynamic_ranges: Self::parse_dynamic_ranges(&current_config),
            dynamic_peer_count: 0,
            dynamic_neighbor_limit: current_config.global.dynamic_neighbor_limit.unwrap_or(100),
            dead_lettered_pending: HashMap::new(),
            next_session_id: 1,
            current_config,
        }
    }

    fn allocate_session_id(&mut self) -> u64 {
        let id = self.next_session_id;
        // Session IDs are a stale-notification discriminator, not a durable
        // protocol identifier. Wrapping would require 2^64 session spawns in
        // one process lifetime; skip zero so `SessionIdentity::default()`
        // remains visibly outside the peer-manager allocated range.
        self.next_session_id = self.next_session_id.wrapping_add(1).max(1);
        id
    }

    fn build_transport_config(&self, config: &PeerManagerNeighborConfig) -> TransportConfig {
        let families = if config.families.is_empty() {
            vec![(Afi::Ipv4, Safi::Unicast)]
        } else {
            config.families.clone()
        };
        let peer = PeerConfig {
            local_asn: self.local_asn,
            remote_asn: config.remote_asn,
            local_router_id: self.router_id,
            hold_time: config.hold_time.unwrap_or(DEFAULT_HOLD_TIME),
            connect_retry_secs: DEFAULT_CONNECT_RETRY_SECS,
            families,
            graceful_restart: config.graceful_restart,
            gr_restart_time: config.gr_restart_time,
            llgr_stale_time: config.llgr_stale_time,
            add_path_receive: config.add_path_receive,
            add_path_send: config.add_path_send,
            add_path_send_max: config.add_path_send_max,
        };
        let remote_addr = SocketAddr::new(config.address, BGP_PORT);
        let mut transport = TransportConfig::new(peer, remote_addr);
        transport.max_prefixes = config.max_prefixes;
        transport.peer_group.clone_from(&config.peer_group);
        transport.md5_password.clone_from(&config.md5_password);
        transport.tcp_ao.clone_from(&config.tcp_ao);
        transport.ttl_security = config.ttl_security;
        transport.local_ipv6_nexthop = config.local_ipv6_nexthop;
        transport.gr_stale_routes_time = config.gr_stale_routes_time;
        transport.llgr_stale_time = config.llgr_stale_time;
        transport.gr_restart_until = if config.gr_restart_eligible && config.graceful_restart {
            self.local_gr_restart_until
                .filter(|deadline| *deadline > Instant::now())
        } else {
            None
        };
        transport.route_reflector_client = config.route_reflector_client;
        transport.route_server_client = config.route_server_client;
        transport.remove_private_as = config.remove_private_as;
        transport.cluster_id = self.cluster_id;
        transport
    }

    /// Run the `PeerManager` event loop until shutdown or channel close.
    #[expect(
        clippy::too_many_lines,
        reason = "peer manager run loop centralizes command, notification, and reload orchestration"
    )]
    pub async fn run(mut self) {
        let mut bmp_stats_interval = self.bmp_tx.as_ref().map(|_| {
            let mut interval =
                tokio::time::interval(std::time::Duration::from_secs(BMP_STATS_INTERVAL_SECS));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            interval
        });
        // Consume the immediate first tick so the first report is emitted
        // after one full interval.
        if let Some(interval) = bmp_stats_interval.as_mut() {
            interval.tick().await;
        }

        loop {
            tokio::select! {
                cmd = self.rx.recv() => {
                    let Some(cmd) = cmd else {
                        debug!("peer manager channel closed");
                        return;
                    };
                    match cmd {
                        PeerManagerCommand::AddPeer { config, sync_config_snapshot, reply } => {
                            let result = self.add_peer(config, sync_config_snapshot).await;
                            let _ = reply.send(result);
                        }
                        PeerManagerCommand::DeletePeer { address, sync_config_snapshot, reply } => {
                            let result = self.delete_peer(address, sync_config_snapshot).await;
                            let _ = reply.send(result);
                        }
                        PeerManagerCommand::ListPeers { reply } => {
                            let infos = self.list_peers().await;
                            let _ = reply.send(infos);
                        }
                        PeerManagerCommand::SubscribeSessionEvents { reply } => {
                            let _ = reply.send(self.session_events_tx.subscribe());
                        }
                        PeerManagerCommand::SubscribePolicyEvents { reply } => {
                            let _ = reply.send(self.policy_events_tx.subscribe());
                        }
                        PeerManagerCommand::QueryPolicyEventHistory { peer, limit, reply } => {
                            self.handle_query_policy_event_history(peer, limit, reply);
                        }
                        PeerManagerCommand::QuerySessionEventHistory {
                            peer,
                            event_types,
                            limit,
                            reply,
                        } => {
                            self.handle_query_session_event_history(
                                peer,
                                &event_types,
                                limit,
                                reply,
                            );
                        }
                        PeerManagerCommand::DiffRuntimeConfig { candidate_toml, reply } => {
                            let result = self.diff_runtime_config(&candidate_toml);
                            let _ = reply.send(result);
                        }
                        PeerManagerCommand::GetPeerState { address, reply } => {
                            let info = self.get_peer_info(address).await;
                            let _ = reply.send(info);
                        }
                        PeerManagerCommand::EnablePeer { address, reply } => {
                            let result = self.enable_peer(address).await;
                            let _ = reply.send(result);
                        }
                        PeerManagerCommand::DisablePeer { address, reason, reply } => {
                            let result = self.disable_peer(address, reason).await;
                            let _ = reply.send(result);
                        }
                        PeerManagerCommand::SoftResetIn { address, families, reply } => {
                            let result = self.soft_reset_in(address, families).await;
                            let _ = reply.send(result);
                        }
                        PeerManagerCommand::SetGracefulShutdown { address, enabled, reply } => {
                            let result = self.set_graceful_shutdown(address, enabled).await;
                            let _ = reply.send(result);
                        }
                        PeerManagerCommand::AcceptInbound { stream, peer_addr } => {
                            self.handle_inbound(stream, peer_addr).await;
                        }
                        PeerManagerCommand::ReconcilePeers { added, removed, changed, reply } => {
                            let result = self.reconcile_peers(added, removed, changed).await;
                            let _ = reply.send(result);
                        }
                        PeerManagerCommand::ListPolicies { reply } => {
                            let _ = reply.send(named_policies_from_config(&self.current_config));
                        }
                        PeerManagerCommand::GetPolicy { name, reply } => {
                            let _ = reply.send(named_policy_from_config(&self.current_config, &name));
                        }
                        PeerManagerCommand::SetPolicy { name, definition, reply } => {
                            let result = self.apply_policy_change(
                                ConfigEvent::SetPolicy { name, definition },
                                None,
                            ).await;
                            let _ = reply.send(result);
                        }
                        PeerManagerCommand::DeletePolicy { name, reply } => {
                            let result = self.apply_policy_change(
                                ConfigEvent::DeletePolicy { name },
                                None,
                            ).await;
                            let _ = reply.send(result);
                        }
                        PeerManagerCommand::ListNeighborSets { reply } => {
                            let _ = reply.send(named_neighbor_sets_from_config(&self.current_config));
                        }
                        PeerManagerCommand::GetNeighborSet { name, reply } => {
                            let _ = reply.send(named_neighbor_set_from_config(&self.current_config, &name));
                        }
                        PeerManagerCommand::SetNeighborSet { name, definition, reply } => {
                            let result = self.apply_policy_change(
                                ConfigEvent::SetNeighborSet { name, definition },
                                None,
                            ).await;
                            let _ = reply.send(result);
                        }
                        PeerManagerCommand::DeleteNeighborSet { name, reply } => {
                            let result = self.apply_policy_change(
                                ConfigEvent::DeleteNeighborSet { name },
                                None,
                            ).await;
                            let _ = reply.send(result);
                        }
                        PeerManagerCommand::GetGlobalPolicyChains { reply } => {
                            let _ = reply.send(global_policy_chains_from_config(&self.current_config));
                        }
                        PeerManagerCommand::SetGlobalImportChain { policy_names, reply } => {
                            let result = self.apply_policy_change(
                                ConfigEvent::SetGlobalImportChain { policy_names },
                                None,
                            ).await;
                            let _ = reply.send(result);
                        }
                        PeerManagerCommand::SetGlobalExportChain { policy_names, reply } => {
                            let result = self.apply_policy_change(
                                ConfigEvent::SetGlobalExportChain { policy_names },
                                None,
                            ).await;
                            let _ = reply.send(result);
                        }
                        PeerManagerCommand::ClearGlobalImportChain { reply } => {
                            let result = self.apply_policy_change(
                                ConfigEvent::ClearGlobalImportChain,
                                None,
                            ).await;
                            let _ = reply.send(result);
                        }
                        PeerManagerCommand::ClearGlobalExportChain { reply } => {
                            let result = self.apply_policy_change(
                                ConfigEvent::ClearGlobalExportChain,
                                None,
                            ).await;
                            let _ = reply.send(result);
                        }
                        PeerManagerCommand::SetHonorGracefulShutdown { enabled, reply } => {
                            let result = self.set_honor_graceful_shutdown(enabled).await;
                            let _ = reply.send(result);
                        }
                        PeerManagerCommand::SetHonorBlackhole { enabled, reply } => {
                            let result = self.set_honor_blackhole(enabled).await;
                            let _ = reply.send(result);
                        }
                        PeerManagerCommand::GetNeighborPolicyChains { address, reply } => {
                            let _ = reply.send(neighbor_policy_chains_from_config(&self.current_config, address));
                        }
                        PeerManagerCommand::SetNeighborImportChain { address, policy_names, reply } => {
                            let result = self.apply_policy_change(
                                ConfigEvent::SetNeighborImportChain { address, policy_names },
                                Some(vec![address]),
                            ).await;
                            let _ = reply.send(result);
                        }
                        PeerManagerCommand::SetNeighborExportChain { address, policy_names, reply } => {
                            let result = self.apply_policy_change(
                                ConfigEvent::SetNeighborExportChain { address, policy_names },
                                Some(vec![address]),
                            ).await;
                            let _ = reply.send(result);
                        }
                        PeerManagerCommand::ClearNeighborImportChain { address, reply } => {
                            let result = self.apply_policy_change(
                                ConfigEvent::ClearNeighborImportChain { address },
                                Some(vec![address]),
                            ).await;
                            let _ = reply.send(result);
                        }
                        PeerManagerCommand::ClearNeighborExportChain { address, reply } => {
                            let result = self.apply_policy_change(
                                ConfigEvent::ClearNeighborExportChain { address },
                                Some(vec![address]),
                            ).await;
                            let _ = reply.send(result);
                        }
                        PeerManagerCommand::ListPeerGroups { reply } => {
                            let _ = reply.send(named_peer_groups_from_config(&self.current_config));
                        }
                        PeerManagerCommand::GetPeerGroup { name, reply } => {
                            let _ = reply.send(named_peer_group_from_config(&self.current_config, &name));
                        }
                        PeerManagerCommand::SetPeerGroup { name, definition, reply } => {
                            let affected: Vec<IpAddr> = self.current_config
                                .neighbors
                                .iter()
                                .filter(|neighbor| neighbor.peer_group.as_deref() == Some(name.as_str()))
                                .filter_map(|neighbor| neighbor.address.parse().ok())
                                .collect();
                            let result = self.apply_peer_group_change(
                                ConfigEvent::SetPeerGroup { name, definition },
                                affected,
                            ).await;
                            let _ = reply.send(result);
                        }
                        PeerManagerCommand::SetPeerGroupPreserveMd5 { name, mut definition, reply } => {
                            let affected: Vec<IpAddr> = self.current_config
                                .neighbors
                                .iter()
                                .filter(|neighbor| neighbor.peer_group.as_deref() == Some(name.as_str()))
                                .filter_map(|neighbor| neighbor.address.parse().ok())
                                .collect();
                            let result = match named_peer_group_from_config(&self.current_config, &name) {
                                Some(existing) => {
                                    definition.md5_password = existing.md5_password;
                                    let applied_definition = definition.clone();
                                    self.apply_peer_group_change(
                                        ConfigEvent::SetPeerGroup { name, definition },
                                        affected,
                                    )
                                    .await
                                    .map(|()| applied_definition)
                                }
                                None => Err(
                                    "has_md5_password cannot preserve a missing peer-group secret"
                                        .to_string(),
                                ),
                            };
                            let _ = reply.send(result);
                        }
                        PeerManagerCommand::DeletePeerGroup { name, reply } => {
                            let result = self.apply_peer_group_change(
                                ConfigEvent::DeletePeerGroup { name },
                                Vec::new(),
                            ).await;
                            let _ = reply.send(result);
                        }
                        PeerManagerCommand::SetNeighborPeerGroup { address, peer_group, reply } => {
                            let result = self.apply_peer_group_change(
                                ConfigEvent::SetNeighborPeerGroup { address, peer_group },
                                vec![address],
                            ).await;
                            let _ = reply.send(result);
                        }
                        PeerManagerCommand::ClearNeighborPeerGroup { address, reply } => {
                            let result = self.apply_peer_group_change(
                                ConfigEvent::ClearNeighborPeerGroup { address },
                                vec![address],
                            ).await;
                            let _ = reply.send(result);
                        }
                        PeerManagerCommand::ListDynamicRanges { reply } => {
                            let ranges = self.dynamic_ranges.iter().map(|r| {
                                DynamicNeighborInfo {
                                    prefix: format!("{}/{}", r.addr, r.prefix_len),
                                    peer_group: r.peer_group.clone(),
                                    remote_asn: r.remote_asn,
                                    description: r.description.clone().unwrap_or_default(),
                                }
                            }).collect();
                            let _ = reply.send(ranges);
                        }
                            PeerManagerCommand::Shutdown => {
                                info!("peer manager shutting down {} peers", self.peers.len());
                                for (addr, mut managed) in self.peers.drain() {
                                    debug!(%addr, "shutting down peer");
                                    if let Some(pending) = managed.pending_inbound.take() {
                                        let _ = pending.handle.shutdown().await;
                                    }
                                    match managed.handle.shutdown().await {
                                    Ok(Ok(())) => debug!(%addr, "peer shut down"),
                                    Ok(Err(e)) => warn!(%addr, error = %e, "peer shutdown error"),
                                    Err(e) => error!(%addr, error = %e, "peer task join error"),
                                }
                            }
                            return;
                        }
                    }
                }
                internal = self.internal_rx.recv() => {
                    if let Some(InternalCommand::ReplaceConfigSnapshot(config)) = internal {
                        self.current_config = *config;
                    }
                }
                notification = self.session_notify_rx.recv() => {
                    if let Some(notification) = notification {
                        self.drain_ready_session_lifecycle_notifications();
                        self.handle_session_notification(notification).await;
                    }
                }
                lifecycle = self.session_lifecycle_rx.recv() => {
                    if let Some(notification) = lifecycle {
                        self.handle_session_lifecycle_notification(&notification);
                    }
                }
                event = self.session_notification_event_rx.recv() => {
                    if let Some(event) = event {
                        self.publish_notification_event(event);
                    }
                }
                () = async {
                    if let Some(interval) = bmp_stats_interval.as_mut() {
                        interval.tick().await;
                    } else {
                        std::future::pending::<()>().await;
                    }
                } => {
                    self.emit_periodic_bmp_stats().await;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests;
