use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use rustbgpd_api::peer_types::{
    ConfigEvent, DynamicNeighborInfo, PeerInfo, PeerManagerCommand, PeerManagerNeighborConfig,
    ReconcileFailure, ReconcileFailureKind, ReconcileResult, SetGshutError,
};
use rustbgpd_bmp::{BmpEvent, BmpPeerInfo, BmpPeerType};
use rustbgpd_fsm::{PeerConfig, SessionState};
use rustbgpd_policy::PolicyChain;
use rustbgpd_rib::RibUpdate;
use rustbgpd_telemetry::BgpMetrics;
use rustbgpd_transport::{PeerHandle, PeerSessionState, SessionNotification, TransportConfig};
use rustbgpd_wire::{Afi, Safi};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot, watch};
use tracing::{debug, error, info, warn};

use crate::config::Config;
use crate::policy_admin::{
    apply_config_event, global_policy_chains_from_config, named_neighbor_set_from_config,
    named_neighbor_sets_from_config, named_peer_group_from_config, named_peer_groups_from_config,
    named_policies_from_config, named_policy_from_config, neighbor_policy_chains_from_config,
    neighbor_set_references, peer_group_references, policy_references,
};

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
    remote_asn: u32,
    description: String,
    peer_group: Option<String>,
    enabled: bool,
    hold_time: Option<u16>,
    max_prefixes: Option<u32>,
    transport_config: TransportConfig,
    import_policy: Option<PolicyChain>,
    export_policy: Option<PolicyChain>,
    /// Pending inbound TCP stream waiting for collision resolution.
    pending_inbound: Option<TcpStream>,
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

/// Resolved dynamic neighbor range used for prefix matching at connection time.
struct DynamicRange {
    addr: std::net::IpAddr,
    prefix_len: u8,
    peer_group: String,
    remote_asn: u32,
    description: Option<String>,
}

/// Snapshot of a removed dynamic peer's unfired hot-apply intent. Carried
/// across the auto-removal that fires when a dynamic peer goes back to
/// Idle so a re-establishing peer at the same address inherits the retry.
/// Without this, a transient TCP drop on a `[[dynamic_neighbors]]` peer
/// that was mid-`pending_refresh` would silently drop the unfired Route
/// Refresh / export-apply — same correctness risk that
/// `ManagedPeer::pending_refresh` / `pending_export_apply` exist to close.
/// The RFC 8326 initiator toggle lives here too: dynamic auto-removal drops
/// the whole `ManagedPeer`, so this side table is the only place to preserve
/// an operator's maintenance-window `GShut` toggle across re-establishment.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct DeadLetteredPending {
    refresh: bool,
    export_apply: bool,
    graceful_shutdown: bool,
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
}

/// Build a `PeerInfo` snapshot from config + an optional fresh
/// `PeerSessionState`. `session_state = None` means the bounded
/// `query_state` either timed out (peer parked on TCP write) or its task
/// has already exited; in both cases we surface `state = Idle, stale =
/// true` so consumers know the field isn't authoritative.
fn build_peer_info(
    address: IpAddr,
    managed: &ManagedPeer,
    session_state: Option<&PeerSessionState>,
) -> PeerInfo {
    let stale = session_state.is_none();
    PeerInfo {
        address,
        remote_asn: managed.remote_asn,
        description: managed.description.clone(),
        peer_group: managed.peer_group.clone(),
        state: session_state.map_or(SessionState::Idle, |s| s.fsm_state),
        enabled: managed.enabled,
        prefix_count: session_state.map_or(0, |s| s.prefix_count),
        hold_time: managed.hold_time,
        max_prefixes: managed.max_prefixes,
        families: managed.transport_config.peer.families.clone(),
        remove_private_as: managed.transport_config.remove_private_as,
        route_server_client: managed.transport_config.route_server_client,
        add_path_receive: managed.transport_config.peer.add_path_receive,
        add_path_send: managed.transport_config.peer.add_path_send,
        add_path_send_max: managed.transport_config.peer.add_path_send_max,
        updates_received: session_state.map_or(0, |s| s.updates_received),
        updates_sent: session_state.map_or(0, |s| s.updates_sent),
        notifications_received: session_state.map_or(0, |s| s.notifications_received),
        notifications_sent: session_state.map_or(0, |s| s.notifications_sent),
        flap_count: session_state.map_or(0, |s| s.flap_count),
        uptime_secs: session_state.map_or(0, |s| s.uptime_secs),
        last_error: session_state.map_or_else(String::new, |s| s.last_error.clone()),
        is_dynamic: managed.is_dynamic,
        stale,
    }
}

/// Run a bounded `query_state` against every peer concurrently.
///
/// Each query is bounded by [`PEER_QUERY_TIMEOUT`]; a peer whose session
/// task is parked on TCP write (or whose command channel is full) lands
/// in the result map as `Some(addr) -> None`. A peer whose task spawn
/// failed entirely is absent from the map. Both cases are treated as
/// `stale = true` by [`build_peer_info`].
async fn collect_session_states(
    peers: &HashMap<IpAddr, ManagedPeer>,
) -> HashMap<IpAddr, Option<PeerSessionState>> {
    let mut tasks: Vec<tokio::task::JoinHandle<(IpAddr, Option<PeerSessionState>)>> =
        Vec::with_capacity(peers.len());
    for (&addr, managed) in peers {
        let commands = managed.handle.commands_sender();
        tasks.push(tokio::spawn(async move {
            let state = PeerHandle::query_state_with(commands, PEER_QUERY_TIMEOUT).await;
            (addr, state)
        }));
    }

    let mut out = HashMap::with_capacity(tasks.len());
    for task in tasks {
        match task.await {
            Ok((addr, state)) => {
                out.insert(addr, state);
            }
            Err(e) => {
                warn!(error = %e, "query_state task join failed");
            }
        }
    }
    out
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
            dynamic_ranges: Self::parse_dynamic_ranges(&current_config),
            dynamic_peer_count: 0,
            dynamic_neighbor_limit: current_config.global.dynamic_neighbor_limit.unwrap_or(100),
            dead_lettered_pending: HashMap::new(),
            current_config,
        }
    }

    fn parse_dynamic_ranges(config: &Config) -> Vec<DynamicRange> {
        config
            .dynamic_neighbors
            .iter()
            .filter_map(|dn| {
                let parts: Vec<&str> = dn.prefix.split('/').collect();
                let addr: std::net::IpAddr = parts.first()?.parse().ok()?;
                let prefix_len: u8 = parts.get(1)?.parse().ok()?;
                Some(DynamicRange {
                    addr,
                    prefix_len,
                    peer_group: dn.peer_group.clone(),
                    remote_asn: dn.remote_asn,
                    description: dn.description.clone(),
                })
            })
            .collect()
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

    #[allow(clippy::too_many_lines)]
    async fn update_runtime_policies(
        &mut self,
        address: IpAddr,
        import_policy: Option<PolicyChain>,
        export_policy: Option<PolicyChain>,
    ) -> Result<(), String> {
        use std::fmt::Write as _;
        let Some(managed) = self.peers.get_mut(&address) else {
            return Ok(());
        };

        // Capture the *prior* import policy before clobbering so we
        // can decide at the end whether to issue a Route Refresh.
        // `update_import_policy_timeout` only swaps the policy
        // reference for *future* inbound UPDATEs — routes already in
        // AdjRibIn were accepted under the old policy and stay there
        // until the peer re-advertises. Without an automatic refresh
        // here, a permit→deny edit silently leaves forbidden routes
        // flowing. PolicyChain doesn't derive PartialEq (would
        // require touching nested types in other crates); the Debug
        // representation is deterministic for this comparison since
        // both sides come from the same `effective_policy_chains_for_neighbor`
        // resolver and `PolicyChain.policies` is a `Vec` (stable order).
        let import_changed = format!("{:?}", managed.import_policy) != format!("{import_policy:?}");
        let export_changed = format!("{:?}", managed.export_policy) != format!("{export_policy:?}");

        // Drain any pending refresh / pending export-apply from a
        // prior call. If a previous round wanted to retry but the
        // session-side update failed (or the peer wasn't Established
        // yet for the import refresh), we re-arm so this call retries
        // in lockstep with whatever new edits the current call brings.
        let had_pending_refresh = std::mem::take(&mut managed.pending_refresh);
        let had_pending_export_apply = std::mem::take(&mut managed.pending_export_apply);

        // Bounded deadlines on the per-peer session round-trips. Without
        // them a back-pressured peer parks the peer-manager actor here,
        // which then can't service `ListPeers` (or any other command), so
        // a `GetHealth` RPC issued during the reload would wedge for as
        // long as the back-pressure lasts. Same wedge class fixed by
        // `query_state_timeout` for the read path; this closes the
        // hot-apply path.
        //
        // Hot-apply to the session FIRST and defer advancing
        // `managed.import_policy` / `managed.export_policy` until the
        // session acknowledges. If the session-side update fails (task
        // back-pressured past the deadline, task exited, mpsc full),
        // leaving the daemon's bookkeeping at the prior value lets the
        // next call's `import_changed` / `export_changed` comparisons
        // still see a delta and retry. The previous "advance
        // bookkeeping then warn-and-continue on session error" pattern
        // allowed the daemon to believe the new policy was live while
        // the session task still held the old one — and worse, would
        // then fire Route Refresh against the session, which would
        // re-evaluate AdjRibIn against the *old* policy and silently
        // keep forbidden routes flowing.
        let import_apply_result = managed
            .handle
            .update_import_policy_timeout(import_policy.clone(), PEER_POLICY_UPDATE_TIMEOUT)
            .await;
        let import_apply_failed = if let Err(error) = &import_apply_result {
            warn!(
                %address,
                error = %error,
                "failed to hot-apply import policy to peer session; retaining prior policy in daemon bookkeeping for retry"
            );
            true
        } else {
            managed.import_policy = import_policy;
            false
        };

        let export_apply_result = managed
            .handle
            .update_export_policy_timeout(export_policy.clone(), PEER_POLICY_UPDATE_TIMEOUT)
            .await;
        let export_apply_failed = if let Err(error) = &export_apply_result {
            warn!(
                %address,
                error = %error,
                "failed to hot-apply export policy to peer session; retaining prior policy in daemon bookkeeping for retry"
            );
            true
        } else {
            managed.export_policy.clone_from(&export_policy);
            false
        };

        let session_state = managed.handle.query_state_timeout(PEER_QUERY_TIMEOUT).await;
        let is_established = session_state
            .as_ref()
            .is_some_and(|s| s.fsm_state == SessionState::Established);

        let needs_refresh = import_changed || had_pending_refresh;
        let needs_export_apply = export_changed || had_pending_export_apply;

        // Bail before the RIB update and Route Refresh if either side
        // failed under an apply-changing intent. The bail decision is
        // not gated on `is_established` for either side: Route Refresh
        // is gated separately by `soft_reset_in`'s own Established
        // check, but the *failure-surfacing* decision is independent.
        // For non-Established peers the same staleness exists — the
        // session task may eventually drop the queued command (task
        // dies before processing) and reach Established holding the
        // prior policy. Without bailing, `apply_policy_change` would
        // advance `current_config`, leaving no signal that the edit
        // didn't actually land.
        //
        //   - Import bail: session didn't acknowledge the new import
        //     policy under refresh intent. For Established peers this
        //     also prevents firing Route Refresh against a session
        //     that still holds the prior policy, which would
        //     re-evaluate AdjRibIn against the *old* policy.
        //
        //   - Export bail: session didn't acknowledge the new export
        //     policy under export-apply intent. Letting bookkeeping
        //     advance here would (a) leave the peer announcing under
        //     the prior export policy until something else triggered
        //     a re-apply, and (b) drift the RIB's view
        //     (`ReplacePeerExportPolicy`) away from the session's
        //     view if we proceeded to the RIB update step.
        //
        // Set the matching pending flag(s) so the next call retries,
        // then return Err so the caller (gRPC reply, SIGHUP reload
        // halt path) surfaces the failure rather than logging-and-
        // forgetting.
        let import_bail = import_apply_failed && needs_refresh;
        let export_bail = export_apply_failed && needs_export_apply;
        if import_bail || export_bail {
            if let Some(managed) = self.peers.get_mut(&address) {
                // Carry forward *all* unfired apply / refresh intent
                // across the bail, not just the side that triggered
                // the bail. Critical cross-side case: import-apply
                // succeeded (so `managed.import_policy` already
                // advanced) but the export bail stops us before
                // `soft_reset_in`. If we only set the bail-triggering
                // flag, the next retry would see `import_changed =
                // false` (bookkeeping already advanced) and
                // `had_pending_refresh = false`, compute
                // `needs_refresh = false`, and silently skip Route
                // Refresh — leaving AdjRibIn routes accepted under
                // the prior import policy stuck against a session
                // that now has the new policy. Setting both flags
                // whenever the corresponding intent was present
                // makes the retry pipeline pick up *every* unfired
                // step regardless of which side bailed.
                if needs_refresh {
                    managed.pending_refresh = true;
                }
                if needs_export_apply {
                    managed.pending_export_apply = true;
                }
            }
            let mut detail = String::new();
            if import_bail {
                let import_err = import_apply_result.err().unwrap_or_default();
                let _ = write!(detail, "import: {import_err}");
            }
            if export_bail {
                if !detail.is_empty() {
                    detail.push_str("; ");
                }
                let export_err = export_apply_result.err().unwrap_or_default();
                let _ = write!(detail, "export: {export_err}");
            }
            return Err(format!(
                "policy hot-apply to peer {address} failed; retry deferred to next \
                 update_runtime_policies call: {detail}"
            ));
        }

        if is_established {
            // The RIB step sits between session-side hot-apply (already
            // succeeded if we reached here) and Route Refresh. If it
            // fails, we still need to preserve any unfired refresh
            // intent: bookkeeping has already advanced (because session
            // ACKed), so on the next call `import_changed` would be
            // false and `needs_refresh` would compute false without a
            // `pending_refresh` carry — the same silent-skip class as
            // the cross-side bail bug. Use explicit match so the Err
            // arms can re-arm `pending_refresh` before returning.
            let (reply_tx, reply_rx) = oneshot::channel();
            let send_outcome = self
                .rib_tx
                .send(RibUpdate::ReplacePeerExportPolicy {
                    peer: address,
                    export_policy,
                    reply: reply_tx,
                })
                .await;
            let rib_outcome: Result<(), String> = match send_outcome {
                Err(_) => Err("RIB manager unavailable".to_string()),
                Ok(()) => match reply_rx.await {
                    Err(_) => Err("RIB manager dropped reply".to_string()),
                    Ok(Err(e)) => Err(format!("failed to update export policy: {e}")),
                    Ok(Ok(())) => Ok(()),
                },
            };
            if let Err(error) = rib_outcome {
                if needs_refresh && let Some(managed) = self.peers.get_mut(&address) {
                    managed.pending_refresh = true;
                }
                return Err(error);
            }
        }

        // Issue Route Refresh (RFC 2918) to re-evaluate routes already
        // in this peer's AdjRibIn against the new import policy.
        // Driven from here rather than from the SIGHUP-only reload
        // path so dynamic peers, gRPC mutations, and any other call
        // site that goes through `apply_policy_change` get the same
        // correctness guarantee — the loop above iterates
        // `self.peers`, which includes dynamic peers.
        //
        // Gated on (a) the import policy materially changing — re-
        // applying the same chain (no-op edits, redundant mutations)
        // shouldn't trigger Route Refresh storms — and (b) the
        // session being Established. Idle / Connect-state peers
        // have nothing in AdjRibIn yet; they'll receive routes
        // under the new policy when the session reaches
        // Established naturally. Without the Established gate,
        // `send_route_refresh` would error for any non-Established
        // peer ("session not Established"), and an operator gRPC
        // `SetPolicy` issued while one of N peers is mid-reconnect
        // would fail.
        //
        // Failure for an Established peer bubbles up to
        // `apply_policy_change`'s caller — for SIGHUP reloads, that
        // halts the reload via `halt_partial` so the failure is
        // surfaced rather than logged-and-forgotten. Before bubbling
        // up, set `pending_refresh` so the next operator action
        // retries the refresh — otherwise a single transient send
        // failure (peer task mid-restart, mpsc backpressure) would
        // leave the new policy applied to *future* UPDATEs while
        // routes already in AdjRibIn keep flowing under the prior
        // policy until the operator reissues a SetPolicy.
        if needs_refresh && is_established {
            if let Err(error) = self.soft_reset_in(address, Vec::new()).await {
                if let Some(managed) = self.peers.get_mut(&address) {
                    managed.pending_refresh = true;
                }
                return Err(error);
            }
        } else if needs_refresh {
            // `!is_established` here means one of: the peer really is
            // Idle / Connect / OpenSent (no AdjRibIn to refresh — the
            // refresh next call would be a no-op), OR
            // `query_state_timeout` returned None for an
            // actually-Established peer (back-pressured session task
            // missed the deadline) and we cannot distinguish the two
            // from this side. Re-arm `pending_refresh` unconditionally
            // so that a subsequent call — once the session unblocks
            // or the peer reaches Established — fires the refresh.
            // Without this, a fresh `import_changed = true` in this
            // call combined with a stale state query would silently
            // drop refresh intent: bookkeeping advances, the retry
            // sees `import_changed = false`, and AdjRibIn routes
            // accepted under the prior policy stay stuck. The
            // wasted-refresh cost on a genuinely Idle peer (next call
            // sends Route Refresh against an empty / freshly-populated
            // AdjRibIn) is small and acceptable next to silent
            // staleness.
            if let Some(managed) = self.peers.get_mut(&address) {
                managed.pending_refresh = true;
            }
        }

        Ok(())
    }
    async fn add_peer(
        &mut self,
        config: PeerManagerNeighborConfig,
        sync_config_snapshot: bool,
    ) -> Result<(), String> {
        if self.peers.contains_key(&config.address) {
            return Err(format!("peer {} already exists", config.address));
        }

        let (transport, label, peer_group, import_policy, export_policy, next_config) =
            if sync_config_snapshot {
                let mut next_config = self.current_config.clone();
                apply_config_event(
                    &mut next_config,
                    &ConfigEvent::NeighborAdded(config.clone()),
                )
                .map_err(|e| e.to_string())?;
                let neighbor = next_config
                    .neighbors
                    .iter()
                    .find(|neighbor| neighbor.address == config.address.to_string())
                    .ok_or_else(|| {
                        format!(
                            "neighbor {} missing after config snapshot update",
                            config.address
                        )
                    })?;
                let resolved = next_config
                    .resolve_neighbor(neighbor)
                    .map_err(|e| e.to_string())?;
                (
                    resolved.transport_config,
                    resolved.label,
                    resolved.peer_group,
                    resolved.import_policy,
                    resolved.export_policy,
                    Some(next_config),
                )
            } else {
                (
                    self.build_transport_config(&config),
                    config.description.clone(),
                    config.peer_group.clone(),
                    config.import_policy.clone(),
                    config.export_policy.clone(),
                    None,
                )
            };

        let address = config.address;
        let remote_asn = config.remote_asn;
        let description = label;
        let hold_time = Some(transport.peer.hold_time);
        let max_prefixes = transport.max_prefixes;

        let handle = PeerHandle::spawn(
            transport.clone(),
            self.metrics.clone(),
            self.rib_tx.clone(),
            import_policy.clone(),
            export_policy.clone(),
            Some(self.session_notify_tx.clone()),
            self.bmp_tx.clone(),
            self.validation_rx.clone(),
            false,
        );

        if let Err(e) = handle.start().await {
            warn!(%address, error = %e, "failed to start peer session");
            return Err(format!("failed to start peer: {e}"));
        }

        info!(%address, %remote_asn, "peer added dynamically");
        self.peers.insert(
            address,
            ManagedPeer {
                handle,
                remote_asn,
                description,
                peer_group,
                enabled: true,
                hold_time,
                max_prefixes,
                transport_config: transport,
                import_policy,
                export_policy,
                pending_inbound: None,
                is_dynamic: false,
                pending_refresh: false,
                pending_export_apply: false,
                advertise_graceful_shutdown: false,
            },
        );

        if let Some(next_config) = next_config {
            self.current_config = next_config;
        }

        Ok(())
    }

    async fn delete_peer(
        &mut self,
        address: IpAddr,
        sync_config_snapshot: bool,
    ) -> Result<(), String> {
        let managed = self
            .peers
            .remove(&address)
            .ok_or_else(|| format!("peer {address} not found"))?;

        match managed.handle.shutdown().await {
            Ok(Ok(())) => info!(%address, "peer deleted"),
            Ok(Err(e)) => warn!(%address, error = %e, "peer shutdown error during delete"),
            Err(e) => error!(%address, error = %e, "peer task join error during delete"),
        }

        if sync_config_snapshot {
            apply_config_event(
                &mut self.current_config,
                &ConfigEvent::NeighborDeleted(address),
            )
            .map_err(|e| e.to_string())?;
        }

        Ok(())
    }

    async fn get_peer_info(&self, address: IpAddr) -> Option<PeerInfo> {
        let managed = self.peers.get(&address)?;
        let session_state = managed.handle.query_state_timeout(PEER_QUERY_TIMEOUT).await;
        Some(build_peer_info(address, managed, session_state.as_ref()))
    }

    async fn list_peers(&self) -> Vec<PeerInfo> {
        // Concurrent fan-out: one bounded `query_state` per peer in parallel.
        // Sequential `.await` per peer was the GetHealth wedge — a session
        // task parked on TCP write back-pressure couldn't service its
        // QueryState command, and the loop hung on the first such peer.
        // Spawning per-peer tasks needs `'static` futures, so we drive the
        // query through `PeerHandle::query_state_with` over a cloned command
        // sender (the sender is `Clone`; the handle proper is not).
        let states = collect_session_states(&self.peers).await;

        let mut infos = Vec::with_capacity(self.peers.len());
        for (&addr, managed) in &self.peers {
            let session_state = states.get(&addr).and_then(Option::as_ref);
            infos.push(build_peer_info(addr, managed, session_state));
        }
        infos
    }

    async fn enable_peer(&mut self, address: IpAddr) -> Result<(), String> {
        let managed = self
            .peers
            .get_mut(&address)
            .ok_or_else(|| format!("peer {address} not found"))?;
        managed.enabled = true;
        managed
            .handle
            .start()
            .await
            .map_err(|e| format!("failed to start peer: {e}"))?;
        info!(%address, "peer enabled");
        Ok(())
    }

    async fn disable_peer(
        &mut self,
        address: IpAddr,
        reason: Option<bytes::Bytes>,
    ) -> Result<(), String> {
        let managed = self
            .peers
            .get_mut(&address)
            .ok_or_else(|| format!("peer {address} not found"))?;
        managed.enabled = false;
        managed.pending_inbound = None;
        managed
            .handle
            .stop(reason)
            .await
            .map_err(|e| format!("failed to stop peer: {e}"))?;
        info!(%address, "peer disabled");
        Ok(())
    }

    /// RFC 8326 graceful-shutdown initiator: toggle `GRACEFUL_SHUTDOWN`
    /// community attachment for one peer (`Some(addr)`) or every
    /// currently-managed peer (`None`).
    ///
    /// Three-step per-peer sequence so the toggle is observable on the
    /// wire AND survives session restart:
    ///
    /// 1. **Update desired state on `ManagedPeer`** — survives session
    ///    restart so a flap mid-maintenance doesn't silently drop the
    ///    toggle.
    /// 2. **Send the live-session command** — flips the per-session
    ///    bool; the next outbound advertise carries (or stops carrying)
    ///    the community.
    /// 3. **Issue `RibUpdate::RefreshPeerOutbound`** — forces re-emission
    ///    of routes already in `AdjRibOut` so the wire form updates
    ///    immediately. Without this, an operator running
    ///    `rustbgpctl gshut` against an Established session with active
    ///    routes would see no change until something else triggered a
    ///    re-advertise.
    ///
    /// `Some(addr)` for a missing peer surfaces as `SetGshutError::PeerNotFound`
    /// so callers can distinguish that from a session/RIB failure.
    /// Per-peer dispatch failures aggregate into `Internal`. The
    /// authoritative state is updated even when the live-session
    /// command or refresh fails — the toggle takes effect on the next
    /// session spawn regardless.
    async fn set_graceful_shutdown(
        &mut self,
        address: Option<IpAddr>,
        enabled: bool,
    ) -> Result<(), SetGshutError> {
        let targets: Vec<IpAddr> = match address {
            Some(addr) => {
                if !self.peers.contains_key(&addr) {
                    return Err(SetGshutError::PeerNotFound(addr));
                }
                vec![addr]
            }
            None => self.peers.keys().copied().collect(),
        };

        let mut failures: Vec<String> = Vec::new();
        for addr in &targets {
            // (1) Update authoritative state on ManagedPeer so it
            // survives session restart.
            if let Some(managed) = self.peers.get_mut(addr) {
                managed.advertise_graceful_shutdown = enabled;
            } else {
                // Peer disappeared between snapshot and dispatch; rare
                // (would require concurrent removal in this same
                // task). Skip silently.
                continue;
            }

            // (2) Tell the live session — best-effort. If the session
            // task is wedged or already restarting, the new session
            // will pick up the toggle from ManagedPeer at spawn time.
            if let Some(managed) = self.peers.get(addr)
                && let Err(e) = managed
                    .handle
                    .update_graceful_shutdown_timeout(enabled, PEER_POLICY_UPDATE_TIMEOUT)
                    .await
            {
                warn!(
                    %addr,
                    enabled,
                    error = %e,
                    "failed to toggle graceful-shutdown on live peer session — \
                     desired state stored, will apply on next session"
                );
                failures.push(format!("{addr}: session: {e}"));
                continue;
            }

            // (3) Force re-emission of already-advertised routes so
            // the toggle is visible on the wire without waiting for
            // an unrelated RIB event. RIB ignores peers not yet
            // registered for outbound (newly added, not Established
            // yet) — that's fine, the next PeerUp will emit fresh.
            let (reply_tx, reply_rx) = oneshot::channel();
            if let Err(e) = self
                .rib_tx
                .send(RibUpdate::RefreshPeerOutbound {
                    peer: *addr,
                    reply: reply_tx,
                })
                .await
            {
                warn!(%addr, error = %e, "failed to send RIB refresh after gshut toggle");
                failures.push(format!("{addr}: rib send: {e}"));
                continue;
            }
            match reply_rx.await {
                Err(_) => {
                    warn!(%addr, "RIB dropped reply for gshut refresh");
                    failures.push(format!("{addr}: rib reply dropped"));
                }
                Ok(Err(e)) => {
                    // "peer X not registered for outbound updates" is
                    // expected for peers not yet Established — log at
                    // debug, not as a failure.
                    debug!(
                        %addr, error = %e,
                        "RIB declined refresh (peer likely not yet Established) — \
                         desired state stored, will apply on next PeerUp"
                    );
                }
                Ok(Ok(())) => {}
            }
        }

        if failures.is_empty() {
            info!(
                count = targets.len(),
                enabled, "RFC 8326 graceful-shutdown toggled on peer set"
            );
            Ok(())
        } else {
            Err(SetGshutError::Internal(format!(
                "graceful-shutdown toggle had failures on {} of {} peers (desired \
                 state stored regardless): {}",
                failures.len(),
                targets.len(),
                failures.join("; ")
            )))
        }
    }

    async fn soft_reset_in(
        &self,
        address: IpAddr,
        families: Vec<(Afi, Safi)>,
    ) -> Result<(), String> {
        let managed = self
            .peers
            .get(&address)
            .ok_or_else(|| format!("not found: peer {address}"))?;

        // Determine which families to request refresh for
        let target_families = if families.is_empty() {
            // All configured families for this peer
            managed.transport_config.peer.families.clone()
        } else {
            families
        };

        for (afi, safi) in &target_families {
            if let Err(e) = managed.handle.send_route_refresh(*afi, *safi).await {
                warn!(%address, error = %e, "failed to send route refresh");
                return Err(format!("send failed: route refresh to {address}: {e}"));
            }
        }

        info!(%address, families = ?target_families, "soft reset in requested");
        Ok(())
    }

    async fn apply_policy_change(
        &mut self,
        event: ConfigEvent,
        affected_peers: Option<Vec<IpAddr>>,
    ) -> Result<(), String> {
        if let ConfigEvent::DeletePolicy { name } = &event {
            let refs = policy_references(&self.current_config, name);
            if !refs.is_empty() {
                return Err(format!(
                    "policy {name} is still referenced by {}",
                    refs.join(", ")
                ));
            }
        }
        if let ConfigEvent::DeleteNeighborSet { name } = &event {
            let refs = neighbor_set_references(&self.current_config, name);
            if !refs.is_empty() {
                return Err(format!(
                    "neighbor set {name} is still referenced by {}",
                    refs.join(", ")
                ));
            }
        }

        let mut next_config = self.current_config.clone();
        apply_config_event(&mut next_config, &event).map_err(|e| e.to_string())?;

        let peers: Vec<IpAddr> =
            affected_peers.unwrap_or_else(|| self.peers.keys().copied().collect());
        for address in peers {
            if !self.peers.contains_key(&address) {
                continue;
            }
            let Some(neighbor) = next_config
                .neighbors
                .iter()
                .find(|neighbor| neighbor.address == address.to_string())
            else {
                continue;
            };
            let (import_policy, export_policy) = next_config
                .effective_policy_chains_for_neighbor(neighbor)
                .map_err(|e| e.to_string())?;
            self.update_runtime_policies(address, import_policy, export_policy)
                .await?;
        }

        self.current_config = next_config;
        Ok(())
    }

    fn policy_resolution_neighbor(
        config: &Config,
        address: IpAddr,
        managed: &ManagedPeer,
    ) -> crate::config::Neighbor {
        config
            .neighbors
            .iter()
            .find(|neighbor| neighbor.address == address.to_string())
            .cloned()
            .unwrap_or_else(|| crate::config::Neighbor {
                address: address.to_string(),
                remote_asn: managed.remote_asn,
                description: None,
                peer_group: managed.peer_group.clone(),
                hold_time: None,
                max_prefixes: None,
                md5_password: None,
                ttl_security: None,
                families: Vec::new(),
                graceful_restart: None,
                gr_restart_time: None,
                gr_stale_routes_time: None,
                llgr_stale_time: None,
                local_ipv6_nexthop: None,
                route_reflector_client: None,
                route_server_client: None,
                remove_private_as: None,
                add_path: None,
                log_level: None,
                import_policy: Vec::new(),
                export_policy: Vec::new(),
                import_policy_chain: Vec::new(),
                export_policy_chain: Vec::new(),
            })
    }

    async fn set_honor_graceful_shutdown(&mut self, enabled: bool) -> Result<(), String> {
        if self.current_config.global.honor_graceful_shutdown == enabled {
            return Ok(());
        }

        // Best-effort fan-out: precompute every EBGP peer's resolved chains
        // against the *new* snapshot, advance the snapshot unconditionally,
        // then iterate applying. A failure on peer B must not leave peer A
        // running with the new effective policy while `current_config`
        // still shows the old knob value — that drift is what the prior
        // `?`-shortcircuit shape produced and is hard to debug
        // operationally. Failed peers will pick up the stale state on
        // their next `update_runtime_policies` call thanks to the
        // existing bail-and-carry plumbing (`pending_refresh` /
        // `pending_export_apply` flags retry on the next policy edit).
        //
        // Resolution failures are also non-fatal at the per-peer scope:
        // if a single neighbor's effective chain can't be resolved
        // (e.g. peer-group reference broken mid-flight), other peers
        // shouldn't be punished for it.
        let mut next_config = self.current_config.clone();
        next_config.global.honor_graceful_shutdown = enabled;

        let targets: Vec<IpAddr> = self
            .peers
            .iter()
            .filter_map(|(&address, managed)| {
                (managed.remote_asn != self.local_asn).then_some(address)
            })
            .collect();

        let mut failures: Vec<String> = Vec::new();
        for address in targets {
            let Some(managed) = self.peers.get(&address) else {
                continue;
            };
            let neighbor = Self::policy_resolution_neighbor(&next_config, address, managed);
            let chains = next_config.effective_policy_chains_for_neighbor(&neighbor);
            let (import_policy, export_policy) = match chains {
                Ok(c) => c,
                Err(e) => {
                    warn!(
                        %address,
                        error = %e,
                        "honor_graceful_shutdown: failed to resolve effective chain — skipping peer"
                    );
                    failures.push(format!("{address}: chain-resolve: {e}"));
                    continue;
                }
            };
            if let Err(e) = self
                .update_runtime_policies(address, import_policy, export_policy)
                .await
            {
                warn!(
                    %address,
                    error = %e,
                    "honor_graceful_shutdown: failed to hot-apply on peer — desired snapshot \
                     advances anyway; bail-and-carry will retry on next policy edit"
                );
                failures.push(format!("{address}: hot-apply: {e}"));
            }
        }

        // Snapshot advances regardless of per-peer outcomes — the
        // authoritative knob value matches the operator's intent. The
        // alternative (shortcircuit on first failure with no rollback)
        // leaves successfully-updated peers running ahead of the
        // snapshot, which is the worse drift.
        self.current_config = next_config;

        if failures.is_empty() {
            info!(
                enabled,
                "hot-applied [global] honor_graceful_shutdown to EBGP peers"
            );
            Ok(())
        } else {
            Err(format!(
                "honor_graceful_shutdown applied with {} of {} EBGP peers failing \
                 (snapshot advanced anyway): {}",
                failures.len(),
                self.peers
                    .values()
                    .filter(|m| m.remote_asn != self.local_asn)
                    .count(),
                failures.join("; ")
            ))
        }
    }

    fn peer_manager_config_from_resolved(
        resolved: crate::config::ResolvedNeighbor,
        gr_restart_eligible: bool,
    ) -> PeerManagerNeighborConfig {
        let tc = resolved.transport_config;
        PeerManagerNeighborConfig {
            address: tc.remote_addr.ip(),
            remote_asn: tc.peer.remote_asn,
            description: resolved.label,
            peer_group: resolved.peer_group,
            hold_time: Some(tc.peer.hold_time),
            max_prefixes: tc.max_prefixes,
            md5_password: tc.md5_password.clone(),
            ttl_security: tc.ttl_security,
            families: tc.peer.families.clone(),
            graceful_restart: tc.peer.graceful_restart,
            gr_restart_time: tc.peer.gr_restart_time,
            gr_stale_routes_time: tc.gr_stale_routes_time,
            llgr_stale_time: tc.llgr_stale_time,
            gr_restart_eligible,
            local_ipv6_nexthop: tc.local_ipv6_nexthop,
            route_reflector_client: tc.route_reflector_client,
            route_server_client: tc.route_server_client,
            remove_private_as: tc.remove_private_as,
            add_path_receive: tc.peer.add_path_receive,
            add_path_send: tc.peer.add_path_send,
            add_path_send_max: tc.peer.add_path_send_max,
            import_policy: resolved.import_policy,
            export_policy: resolved.export_policy,
        }
    }

    async fn apply_peer_group_change(
        &mut self,
        event: ConfigEvent,
        affected_peers: Vec<IpAddr>,
    ) -> Result<(), String> {
        if let ConfigEvent::DeletePeerGroup { name } = &event {
            let refs = peer_group_references(&self.current_config, name);
            if !refs.is_empty() {
                return Err(format!(
                    "peer group {name} is still referenced by {}",
                    refs.join(", ")
                ));
            }
        }

        let mut next_config = self.current_config.clone();
        apply_config_event(&mut next_config, &event).map_err(|e| e.to_string())?;

        for address in affected_peers {
            let was_enabled = self
                .peers
                .get(&address)
                .is_none_or(|managed| managed.enabled);
            if self.peers.contains_key(&address) {
                self.delete_peer(address, false).await?;
            }

            if let Some(neighbor) = next_config
                .neighbors
                .iter()
                .find(|neighbor| neighbor.address == address.to_string())
            {
                let resolved = next_config
                    .resolve_neighbor(neighbor)
                    .map_err(|e| e.to_string())?;
                let cfg = Self::peer_manager_config_from_resolved(resolved, false);
                self.add_peer(cfg, false).await?;
                if !was_enabled {
                    self.disable_peer(address, None).await?;
                }
            }
        }

        self.current_config = next_config;
        Ok(())
    }

    /// Check whether a peer IP falls within any configured dynamic neighbor range.
    fn match_dynamic_range(&self, addr: IpAddr) -> Option<&DynamicRange> {
        self.dynamic_ranges.iter().find(|r| {
            match (addr, r.addr) {
                (IpAddr::V4(peer), IpAddr::V4(net)) => {
                    if r.prefix_len > 32 {
                        return false;
                    }
                    let mask = if r.prefix_len == 0 {
                        0u32
                    } else {
                        u32::MAX << (32 - r.prefix_len)
                    };
                    (u32::from(peer) & mask) == (u32::from(net) & mask)
                }
                (IpAddr::V6(peer), IpAddr::V6(net)) => {
                    if r.prefix_len > 128 {
                        return false;
                    }
                    let mask = if r.prefix_len == 0 {
                        0u128
                    } else {
                        u128::MAX << (128 - r.prefix_len)
                    };
                    (u128::from(peer) & mask) == (u128::from(net) & mask)
                }
                _ => false, // IPv4/IPv6 mismatch
            }
        })
    }

    #[expect(clippy::too_many_lines)]
    async fn handle_inbound(&mut self, stream: TcpStream, peer_addr: IpAddr) {
        // If peer is not statically configured, try dynamic range matching.
        if !self.peers.contains_key(&peer_addr) {
            if let Some(range) = self.match_dynamic_range(peer_addr) {
                // Check dynamic peer limit
                if self.dynamic_peer_count >= self.dynamic_neighbor_limit as usize {
                    warn!(
                        %peer_addr,
                        limit = self.dynamic_neighbor_limit,
                        "dynamic neighbor limit reached, dropping inbound connection"
                    );
                    return;
                }

                // Look up the peer group to build the config
                let Some(group) = self.current_config.peer_groups.get(&range.peer_group) else {
                    warn!(
                        %peer_addr,
                        peer_group = %range.peer_group,
                        "dynamic neighbor peer_group not found, dropping"
                    );
                    return;
                };

                let remote_asn = range.remote_asn;
                let description = range
                    .description
                    .clone()
                    .unwrap_or_else(|| format!("dynamic:{}", range.peer_group));
                let peer_group_name = range.peer_group.clone();

                // Resolve the dynamic neighbor config from the peer group
                let resolved = match self.current_config.resolve_dynamic_neighbor(
                    peer_addr,
                    remote_asn,
                    &description,
                    group,
                    &peer_group_name,
                ) {
                    Ok(r) => r,
                    Err(e) => {
                        warn!(
                            %peer_addr,
                            error = %e,
                            "failed to resolve dynamic neighbor config, dropping"
                        );
                        return;
                    }
                };

                let cfg = Self::peer_manager_config_from_resolved(resolved, false);
                let transport = self.build_transport_config(&cfg);
                let import_policy = cfg.import_policy.clone();
                let export_policy = cfg.export_policy.clone();
                let advertise_graceful_shutdown = self
                    .dead_lettered_pending
                    .get(&peer_addr)
                    .is_some_and(|pending| pending.graceful_shutdown);

                let handle = PeerHandle::spawn_inbound(
                    transport.clone(),
                    self.metrics.clone(),
                    self.rib_tx.clone(),
                    import_policy.clone(),
                    export_policy.clone(),
                    stream,
                    Some(self.session_notify_tx.clone()),
                    self.bmp_tx.clone(),
                    self.validation_rx.clone(),
                    advertise_graceful_shutdown,
                );

                if let Err(e) = handle.start().await {
                    warn!(%peer_addr, error = %e, "failed to start dynamic peer session");
                    return;
                }

                let managed = ManagedPeer {
                    handle,
                    remote_asn,
                    description,
                    peer_group: Some(peer_group_name),
                    enabled: true,
                    hold_time: cfg.hold_time,
                    max_prefixes: cfg.max_prefixes,
                    transport_config: transport,
                    import_policy,
                    export_policy,
                    pending_inbound: None,
                    is_dynamic: true,
                    pending_refresh: false,
                    pending_export_apply: false,
                    advertise_graceful_shutdown,
                };
                self.peers.insert(peer_addr, managed);
                self.dynamic_peer_count += 1;

                // Restore any dead-lettered hot-apply / Route Refresh
                // intent left behind by a prior dynamic-peer auto-
                // removal at this address. Carries the retry across
                // the brief drop-and-recreate window so a transient
                // TCP flap doesn't silently lose a SetPolicy edit.
                self.restore_dead_lettered_pending(peer_addr);

                info!(
                    %peer_addr,
                    "accepted dynamic neighbor from configured range"
                );
                return;
            }

            // No dynamic range match either — drop with hint
            warn!(
                %peer_addr,
                hint = %format_args!(
                    "to accept: rustbgpctl neighbor {peer_addr} add --asn <REMOTE_ASN>"
                ),
                "inbound connection from unknown peer, dropping"
            );
            return;
        }

        let Some(managed) = self.peers.get_mut(&peer_addr) else {
            return;
        };

        if !managed.enabled {
            info!(%peer_addr, "inbound connection for disabled peer, dropping");
            return;
        }

        // Bounded so an inbound TCP arriving during a TCP-back-pressure
        // wedge on the existing session can't park the peer-manager actor
        // mid-collision-resolution. A timeout falls back to `Idle` here,
        // which sends us through the "accept immediately" arm — equivalent
        // to the existing "no session yet" path, with the same
        // `replace_with_inbound` outcome.
        let current_state = managed.handle.query_state_timeout(PEER_QUERY_TIMEOUT).await;
        let fsm_state = current_state
            .as_ref()
            .map_or(SessionState::Idle, |s| s.fsm_state);

        match fsm_state {
            SessionState::Idle => {
                // Accept immediately — no collision possible
                self.replace_with_inbound(peer_addr, stream).await;
            }
            SessionState::Established => {
                // Already established — drop inbound (no collision)
                info!(%peer_addr, "inbound connection for established peer, dropping");
            }
            SessionState::Connect | SessionState::Active | SessionState::OpenSent => {
                // Store pending inbound, wait for OpenReceived notification
                info!(%peer_addr, state = fsm_state.as_str(), "storing pending inbound for collision resolution");
                if let Some(managed) = self.peers.get_mut(&peer_addr) {
                    managed.pending_inbound = Some(stream);
                }
            }
            SessionState::OpenConfirm => {
                // We already have router-id from negotiation — resolve now
                let remote_router_id = current_state.and_then(|s| s.remote_router_id);
                if let Some(rid) = remote_router_id {
                    self.resolve_collision(peer_addr, rid, stream).await;
                } else {
                    // Shouldn't happen, but accept inbound as fallback
                    warn!(%peer_addr, "OpenConfirm but no remote_router_id, accepting inbound");
                    self.replace_with_inbound(peer_addr, stream).await;
                }
            }
        }
    }

    /// Snapshot any unfired hot-apply / Route Refresh intent for a peer
    /// about to be auto-removed, so a re-establishing peer at the same
    /// address inherits the retry. No-op if neither flag is set.
    /// Bounded at `dynamic_neighbor_limit` — over-cap evicts an
    /// arbitrary entry with `warn!` to surface pathological churn.
    fn dead_letter_pending_for(&mut self, peer_addr: IpAddr) {
        let Some(managed) = self.peers.get(&peer_addr) else {
            return;
        };
        if !managed.pending_refresh
            && !managed.pending_export_apply
            && !managed.advertise_graceful_shutdown
        {
            return;
        }
        let entry = DeadLetteredPending {
            refresh: managed.pending_refresh,
            export_apply: managed.pending_export_apply,
            graceful_shutdown: managed.advertise_graceful_shutdown,
        };
        let cap = self.dynamic_neighbor_limit as usize;
        if cap > 0
            && !self.dead_lettered_pending.contains_key(&peer_addr)
            && self.dead_lettered_pending.len() >= cap
            && let Some(victim) = self.dead_lettered_pending.keys().next().copied()
        {
            warn!(
                %peer_addr,
                evicted = %victim,
                cap,
                "dead-letter pending table at cap, evicting an existing entry — \
                 dynamic peers churning faster than they re-establish"
            );
            self.dead_lettered_pending.remove(&victim);
        }
        self.dead_lettered_pending.insert(peer_addr, entry);
    }

    /// Drain any dead-lettered hot-apply / Route Refresh intent for a
    /// freshly accepted dynamic peer at this address and apply it to the
    /// new `ManagedPeer`. No-op if no entry exists.
    fn restore_dead_lettered_pending(&mut self, peer_addr: IpAddr) {
        let Some(prev) = self.dead_lettered_pending.remove(&peer_addr) else {
            return;
        };
        let Some(managed) = self.peers.get_mut(&peer_addr) else {
            return;
        };
        managed.pending_refresh = prev.refresh;
        managed.pending_export_apply = prev.export_apply;
        managed.advertise_graceful_shutdown = prev.graceful_shutdown;
        info!(
            %peer_addr,
            pending_refresh = prev.refresh,
            pending_export_apply = prev.export_apply,
            advertise_graceful_shutdown = prev.graceful_shutdown,
            "restored dead-lettered hot-apply intent on dynamic peer re-establishment"
        );
    }

    async fn handle_session_notification(&mut self, notification: SessionNotification) {
        match notification {
            SessionNotification::OpenReceived {
                peer_addr,
                remote_router_id,
            } => {
                let pending = self
                    .peers
                    .get_mut(&peer_addr)
                    .and_then(|m| m.pending_inbound.take());
                if let Some(stream) = pending {
                    self.resolve_collision(peer_addr, remote_router_id, stream)
                        .await;
                }
            }
            SessionNotification::BackToIdle { peer_addr } => {
                // Auto-remove dynamic peers when they go idle (no reconnect).
                if self
                    .peers
                    .get(&peer_addr)
                    .is_some_and(|m| m.is_dynamic && !m.enabled)
                {
                    // Operator explicitly disabled — don't remove, just let it stay idle.
                } else if self.peers.get(&peer_addr).is_some_and(|m| m.is_dynamic) {
                    // Snapshot any unfired hot-apply / Route Refresh
                    // intent before we drop the ManagedPeer. A
                    // re-establishing dynamic peer at the same address
                    // (typical for a transient TCP drop on a
                    // [[dynamic_neighbors]] range) inherits the retry
                    // when handle_inbound recreates the ManagedPeer.
                    self.dead_letter_pending_for(peer_addr);
                    info!(%peer_addr, "dynamic peer session went idle, removing");
                    self.peers.remove(&peer_addr);
                    self.dynamic_peer_count = self.dynamic_peer_count.saturating_sub(1);
                    // Skip pending inbound logic for removed dynamic peers
                } else {
                    let pending = self.peers.get_mut(&peer_addr).and_then(|m| {
                        if m.enabled {
                            m.pending_inbound.take()
                        } else {
                            // Peer is disabled — drop pending inbound
                            m.pending_inbound = None;
                            None
                        }
                    });
                    if let Some(stream) = pending {
                        // Existing session failed — accept pending inbound
                        info!(%peer_addr, "existing session went idle, accepting pending inbound");
                        self.replace_with_inbound(peer_addr, stream).await;
                    }
                }
            }
        }
    }

    async fn resolve_collision(
        &mut self,
        peer_addr: IpAddr,
        remote_router_id: Ipv4Addr,
        inbound_stream: TcpStream,
    ) {
        let local_id = u32::from(self.router_id);
        let remote_id = u32::from(remote_router_id);

        match local_id.cmp(&remote_id) {
            std::cmp::Ordering::Greater => {
                // We win — keep existing session, drop inbound
                info!(
                    %peer_addr,
                    local_id = %self.router_id,
                    remote_id = %remote_router_id,
                    "collision: local wins, dropping inbound"
                );
                drop(inbound_stream);
            }
            std::cmp::Ordering::Less => {
                // Remote wins — dump existing, accept inbound
                info!(
                    %peer_addr,
                    local_id = %self.router_id,
                    remote_id = %remote_router_id,
                    "collision: remote wins, replacing with inbound"
                );
                if let Some(managed) = self.peers.get(&peer_addr) {
                    let _ = managed.handle.collision_dump().await;
                }
                self.replace_with_inbound(peer_addr, inbound_stream).await;
            }
            std::cmp::Ordering::Equal => {
                // Equal router-ids — should not happen; drop inbound
                warn!(
                    %peer_addr,
                    router_id = %self.router_id,
                    "collision: equal router-ids, dropping inbound"
                );
                drop(inbound_stream);
            }
        }
    }

    async fn replace_with_inbound(&mut self, peer_addr: IpAddr, stream: TcpStream) {
        let Some(managed) = self.peers.get_mut(&peer_addr) else {
            return;
        };

        // Replay the operator-driven RFC 8326 toggle on the new
        // session so a flap or collision-replace doesn't silently
        // drop the GShut state mid-maintenance.
        let advertise_graceful_shutdown = managed.advertise_graceful_shutdown;
        let old_handle = std::mem::replace(
            &mut managed.handle,
            PeerHandle::spawn_inbound(
                managed.transport_config.clone(),
                self.metrics.clone(),
                self.rib_tx.clone(),
                managed.import_policy.clone(),
                managed.export_policy.clone(),
                stream,
                Some(self.session_notify_tx.clone()),
                self.bmp_tx.clone(),
                self.validation_rx.clone(),
                advertise_graceful_shutdown,
            ),
        );

        // Shut down the old session
        let _ = old_handle.shutdown().await;

        // Start the new inbound session — trigger TcpConnectionConfirmed
        if let Err(e) = managed.handle.start().await {
            warn!(%peer_addr, error = %e, "failed to start inbound session");
        } else {
            info!(%peer_addr, "inbound session started");
        }
    }

    async fn reconcile_peers(
        &mut self,
        added: Vec<PeerManagerNeighborConfig>,
        removed: Vec<IpAddr>,
        changed: Vec<PeerManagerNeighborConfig>,
    ) -> ReconcileResult {
        let mut result = ReconcileResult::default();
        let added_count = added.len();
        let removed_count = removed.len();
        let changed_count = changed.len();

        // Capture per-peer operator-runtime state that should survive
        // a delete-then-readd cycle. RFC 8326 graceful-shutdown
        // toggle: a static-peer config edit (e.g. `description` change)
        // triggers a delete+readd in this reconcile path; without
        // capturing the desired state by address, the freshly added
        // ManagedPeer would come up with `advertise_graceful_shutdown
        // = false`, silently dropping the toggle mid-maintenance and
        // re-emitting untagged routes on the next outbound tick.
        let preserved_gshut: HashMap<IpAddr, bool> = changed
            .iter()
            .filter_map(|cfg| {
                self.peers
                    .get(&cfg.address)
                    .filter(|m| m.advertise_graceful_shutdown)
                    .map(|_| (cfg.address, true))
            })
            .collect();

        // Remove peers
        for addr in &removed {
            if let Err(e) = self.delete_peer(*addr, false).await {
                warn!(%addr, error = %e, "reconcile: failed to remove peer");
                result.failures.push(ReconcileFailure {
                    kind: ReconcileFailureKind::Remove,
                    address: *addr,
                    error: e,
                });
            }
        }
        // Changed peers: delete then re-add
        for cfg in &changed {
            let addr = cfg.address;
            if let Err(e) = self.delete_peer(addr, false).await {
                warn!(%addr, error = %e, "reconcile: failed to remove changed peer");
                result.failures.push(ReconcileFailure {
                    kind: ReconcileFailureKind::ChangeRemove,
                    address: addr,
                    error: e,
                });
            }
            if let Err(e) = self.add_peer(cfg.clone(), false).await {
                warn!(%addr, error = %e, "reconcile: failed to re-add changed peer");
                result.failures.push(ReconcileFailure {
                    kind: ReconcileFailureKind::ChangeAdd,
                    address: addr,
                    error: e,
                });
            }
        }
        // Replay preserved RFC 8326 toggles onto the freshly added
        // peers. This goes through the same path as the operator's
        // `rustbgpctl gshut` so the live session bool, ManagedPeer
        // desired state, AND RIB refresh all advance in lockstep —
        // even though the new session is mid-bring-up, the desired
        // state is in place and the bool will be applied to the
        // session's first emission once it reaches Established.
        for (addr, enabled) in preserved_gshut {
            if let Err(e) = self.set_graceful_shutdown(Some(addr), enabled).await {
                warn!(
                    %addr,
                    error = %e,
                    "reconcile: failed to replay graceful-shutdown toggle on changed peer"
                );
            }
        }
        // Add new peers
        for cfg in added {
            let addr = cfg.address;
            if let Err(e) = self.add_peer(cfg, false).await {
                warn!(%addr, error = %e, "reconcile: failed to add new peer");
                result.failures.push(ReconcileFailure {
                    kind: ReconcileFailureKind::Add,
                    address: addr,
                    error: e,
                });
            }
        }
        info!(
            added = added_count,
            removed = removed_count,
            changed = changed_count,
            failures = result.failures.len(),
            "peer reconciliation complete"
        );
        result
    }

    fn bmp_peer_info(
        peer_addr: IpAddr,
        remote_asn: u32,
        remote_router_id: Option<Ipv4Addr>,
        four_octet_as: Option<bool>,
    ) -> BmpPeerInfo {
        BmpPeerInfo {
            peer_addr,
            peer_asn: remote_asn,
            peer_bgp_id: remote_router_id.unwrap_or(Ipv4Addr::UNSPECIFIED),
            peer_type: BmpPeerType::Global,
            is_ipv6: peer_addr.is_ipv6(),
            is_post_policy: false,
            is_as4: four_octet_as.unwrap_or(true),
            timestamp: std::time::SystemTime::now(),
        }
    }

    async fn emit_periodic_bmp_stats(&self) {
        let Some(ref bmp_tx) = self.bmp_tx else {
            return;
        };

        // Same fan-out pattern as `list_peers` — sequential awaits would let
        // any one TCP-back-pressured peer block the per-minute BMP tick and,
        // through it, every other admin command queued behind the BMP arm.
        let states = collect_session_states(&self.peers).await;
        for (&peer_addr, managed) in &self.peers {
            let Some(Some(state)) = states.get(&peer_addr) else {
                continue;
            };
            if state.fsm_state != SessionState::Established {
                continue;
            }

            let prefix_count = u64::try_from(state.prefix_count).unwrap_or(u64::MAX);
            let event = BmpEvent::StatsReport {
                peer_info: Self::bmp_peer_info(
                    peer_addr,
                    managed.remote_asn,
                    state.remote_router_id,
                    state.four_octet_as,
                ),
                adj_rib_in_routes: prefix_count,
            };

            if let Err(e) = bmp_tx.try_send(event) {
                warn!(
                    peer = %peer_addr,
                    error = %e,
                    "BMP event channel full or closed, dropping periodic stats report"
                );
            }
        }
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
                            for (addr, managed) in self.peers.drain() {
                                debug!(%addr, "shutting down peer");
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
                        self.handle_session_notification(notification).await;
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
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::net::TcpListener;
    use tokio::sync::oneshot;

    fn make_config(addr: IpAddr, asn: u32) -> PeerManagerNeighborConfig {
        PeerManagerNeighborConfig {
            address: addr,
            remote_asn: asn,
            description: format!("test-peer-{addr}"),
            peer_group: None,
            hold_time: None,
            max_prefixes: None,
            md5_password: None,
            ttl_security: false,
            families: vec![(Afi::Ipv4, Safi::Unicast)],
            graceful_restart: true,
            gr_restart_time: 120,
            gr_stale_routes_time: 360,
            llgr_stale_time: 0,
            gr_restart_eligible: false,
            local_ipv6_nexthop: None,
            route_reflector_client: false,
            route_server_client: false,
            remove_private_as: rustbgpd_transport::RemovePrivateAs::Disabled,
            add_path_receive: false,
            add_path_send: false,
            add_path_send_max: 0,
            import_policy: None,
            export_policy: None,
        }
    }

    fn make_dynamic_manager_config() -> Config {
        let mut peer_groups = HashMap::new();
        peer_groups.insert(
            "ix-members".to_string(),
            crate::config::PeerGroupConfig {
                families: vec!["ipv4_unicast".to_string()],
                ..Default::default()
            },
        );

        Config {
            global: crate::config::Global {
                asn: 65001,
                router_id: "10.0.0.1".to_string(),
                listen_port: BGP_PORT,
                cluster_id: None,
                runtime_state_dir: "/tmp/rustbgpd-tests".to_string(),
                telemetry: crate::config::TelemetryConfig {
                    prometheus_addr: Some("127.0.0.1:9179".to_string()),
                    log_format: "json".to_string(),
                    grpc_tcp: None,
                    grpc_uds: None,
                    looking_glass: None,
                },
                dynamic_neighbor_limit: Some(100),
                honor_graceful_shutdown: false,
            },
            neighbors: Vec::new(),
            peer_groups,
            policy: crate::config::PolicyConfig::default(),
            dynamic_neighbors: vec![crate::config::DynamicNeighborConfig {
                prefix: "127.0.0.0/8".to_string(),
                peer_group: "ix-members".to_string(),
                remote_asn: 0,
                description: Some("ix-auto".to_string()),
            }],
            rpki: None,
            bmp: None,
            mrt: None,
            file_path: None,
            evpn_instances: Vec::new(),
        }
    }

    fn deny_policy_chain() -> PolicyChain {
        use rustbgpd_policy::{Policy, PolicyAction};

        PolicyChain::new(vec![Policy {
            entries: Vec::new(),
            default_action: PolicyAction::Deny,
        }])
    }

    fn insert_test_managed_peer(
        mgr: &mut PeerManager,
        addr: IpAddr,
        handle: PeerHandle,
        pending_refresh: bool,
    ) {
        insert_test_managed_peer_with_asn(mgr, addr, 65002, handle, pending_refresh);
    }

    fn insert_test_managed_peer_with_asn(
        mgr: &mut PeerManager,
        addr: IpAddr,
        remote_asn: u32,
        handle: PeerHandle,
        pending_refresh: bool,
    ) {
        let peer_config = make_config(addr, remote_asn);
        let transport = mgr.build_transport_config(&peer_config);
        let hold = transport.peer.hold_time;
        mgr.peers.insert(
            addr,
            ManagedPeer {
                handle,
                remote_asn,
                description: "test".to_string(),
                peer_group: None,
                enabled: true,
                hold_time: Some(hold),
                max_prefixes: None,
                transport_config: transport,
                import_policy: None,
                export_policy: None,
                pending_inbound: None,
                is_dynamic: false,
                pending_refresh,
                pending_export_apply: false,
                advertise_graceful_shutdown: false,
            },
        );
    }

    fn config_neighbor(addr: IpAddr, remote_asn: u32) -> crate::config::Neighbor {
        crate::config::Neighbor {
            address: addr.to_string(),
            remote_asn,
            description: None,
            peer_group: None,
            hold_time: None,
            max_prefixes: None,
            md5_password: None,
            ttl_security: None,
            families: Vec::new(),
            graceful_restart: None,
            gr_restart_time: None,
            gr_stale_routes_time: None,
            llgr_stale_time: None,
            local_ipv6_nexthop: None,
            route_reflector_client: None,
            route_server_client: None,
            remove_private_as: None,
            add_path: None,
            log_level: None,
            import_policy: Vec::new(),
            export_policy: Vec::new(),
            import_policy_chain: Vec::new(),
            export_policy_chain: Vec::new(),
        }
    }

    #[tokio::test]
    async fn add_peer_and_list() {
        let (tx, rx) = mpsc::channel(16);
        let (rib_tx, _rib_rx) = mpsc::channel(64);
        let metrics = BgpMetrics::new();
        let mgr = PeerManager::new(
            rx,
            65001,
            Ipv4Addr::new(10, 0, 0, 1),
            None,
            None,
            metrics,
            rib_tx,
            None,
        );
        let handle = tokio::spawn(mgr.run());

        let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(PeerManagerCommand::AddPeer {
            config: make_config(addr, 65002),
            sync_config_snapshot: false,
            reply: reply_tx,
        })
        .await
        .unwrap();
        assert!(reply_rx.await.unwrap().is_ok());

        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(PeerManagerCommand::ListPeers { reply: reply_tx })
            .await
            .unwrap();
        let peers = reply_rx.await.unwrap();
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].address, addr);
        assert_eq!(peers[0].remote_asn, 65002);

        tx.send(PeerManagerCommand::Shutdown).await.unwrap();
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn add_duplicate_returns_error() {
        let (tx, rx) = mpsc::channel(16);
        let (rib_tx, _rib_rx) = mpsc::channel(64);
        let metrics = BgpMetrics::new();
        let mgr = PeerManager::new(
            rx,
            65001,
            Ipv4Addr::new(10, 0, 0, 1),
            None,
            None,
            metrics,
            rib_tx,
            None,
        );
        let handle = tokio::spawn(mgr.run());

        let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(PeerManagerCommand::AddPeer {
            config: make_config(addr, 65002),
            sync_config_snapshot: false,
            reply: reply_tx,
        })
        .await
        .unwrap();
        assert!(reply_rx.await.unwrap().is_ok());

        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(PeerManagerCommand::AddPeer {
            config: make_config(addr, 65002),
            sync_config_snapshot: false,
            reply: reply_tx,
        })
        .await
        .unwrap();
        assert!(reply_rx.await.unwrap().is_err());

        tx.send(PeerManagerCommand::Shutdown).await.unwrap();
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn delete_peer_removes() {
        let (tx, rx) = mpsc::channel(16);
        let (rib_tx, _rib_rx) = mpsc::channel(64);
        let metrics = BgpMetrics::new();
        let mgr = PeerManager::new(
            rx,
            65001,
            Ipv4Addr::new(10, 0, 0, 1),
            None,
            None,
            metrics,
            rib_tx,
            None,
        );
        let handle = tokio::spawn(mgr.run());

        let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(PeerManagerCommand::AddPeer {
            config: make_config(addr, 65002),
            sync_config_snapshot: false,
            reply: reply_tx,
        })
        .await
        .unwrap();
        assert!(reply_rx.await.unwrap().is_ok());

        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(PeerManagerCommand::DeletePeer {
            address: addr,
            sync_config_snapshot: false,
            reply: reply_tx,
        })
        .await
        .unwrap();
        assert!(reply_rx.await.unwrap().is_ok());

        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(PeerManagerCommand::ListPeers { reply: reply_tx })
            .await
            .unwrap();
        let peers = reply_rx.await.unwrap();
        assert!(peers.is_empty());

        tx.send(PeerManagerCommand::Shutdown).await.unwrap();
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn delete_nonexistent_returns_error() {
        let (tx, rx) = mpsc::channel(16);
        let (rib_tx, _rib_rx) = mpsc::channel(64);
        let metrics = BgpMetrics::new();
        let mgr = PeerManager::new(
            rx,
            65001,
            Ipv4Addr::new(10, 0, 0, 1),
            None,
            None,
            metrics,
            rib_tx,
            None,
        );
        let handle = tokio::spawn(mgr.run());

        let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 99));
        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(PeerManagerCommand::DeletePeer {
            address: addr,
            sync_config_snapshot: false,
            reply: reply_tx,
        })
        .await
        .unwrap();
        assert!(reply_rx.await.unwrap().is_err());

        tx.send(PeerManagerCommand::Shutdown).await.unwrap();
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn get_peer_state_existing() {
        let (tx, rx) = mpsc::channel(16);
        let (rib_tx, _rib_rx) = mpsc::channel(64);
        let metrics = BgpMetrics::new();
        let mgr = PeerManager::new(
            rx,
            65001,
            Ipv4Addr::new(10, 0, 0, 1),
            None,
            None,
            metrics,
            rib_tx,
            None,
        );
        let handle = tokio::spawn(mgr.run());

        let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(PeerManagerCommand::AddPeer {
            config: make_config(addr, 65002),
            sync_config_snapshot: false,
            reply: reply_tx,
        })
        .await
        .unwrap();
        let _ = reply_rx.await;

        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(PeerManagerCommand::GetPeerState {
            address: addr,
            reply: reply_tx,
        })
        .await
        .unwrap();
        let info = reply_rx.await.unwrap();
        assert!(info.is_some());
        assert_eq!(info.unwrap().address, addr);

        tx.send(PeerManagerCommand::Shutdown).await.unwrap();
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn get_peer_state_nonexistent_returns_none() {
        let (tx, rx) = mpsc::channel(16);
        let (rib_tx, _rib_rx) = mpsc::channel(64);
        let metrics = BgpMetrics::new();
        let mgr = PeerManager::new(
            rx,
            65001,
            Ipv4Addr::new(10, 0, 0, 1),
            None,
            None,
            metrics,
            rib_tx,
            None,
        );
        let handle = tokio::spawn(mgr.run());

        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(PeerManagerCommand::GetPeerState {
            address: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 99)),
            reply: reply_tx,
        })
        .await
        .unwrap();
        assert!(reply_rx.await.unwrap().is_none());

        tx.send(PeerManagerCommand::Shutdown).await.unwrap();
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn shutdown_stops_all_peers() {
        let (tx, rx) = mpsc::channel(16);
        let (rib_tx, _rib_rx) = mpsc::channel(64);
        let metrics = BgpMetrics::new();
        let mgr = PeerManager::new(
            rx,
            65001,
            Ipv4Addr::new(10, 0, 0, 1),
            None,
            None,
            metrics,
            rib_tx,
            None,
        );
        let handle = tokio::spawn(mgr.run());

        for i in 2..=3 {
            let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, i));
            let (reply_tx, reply_rx) = oneshot::channel();
            tx.send(PeerManagerCommand::AddPeer {
                config: make_config(addr, 65000 + u32::from(i)),
                sync_config_snapshot: false,
                reply: reply_tx,
            })
            .await
            .unwrap();
            let _ = reply_rx.await;
        }

        tx.send(PeerManagerCommand::Shutdown).await.unwrap();
        handle.await.unwrap();
    }

    #[test]
    fn build_transport_config_preserves_local_ipv6_nexthop() {
        let (_, rx) = mpsc::channel(16);
        let (rib_tx, _rib_rx) = mpsc::channel(64);
        let metrics = BgpMetrics::new();
        let mgr = PeerManager::new(
            rx,
            65001,
            Ipv4Addr::new(10, 0, 0, 1),
            None,
            None,
            metrics,
            rib_tx,
            None,
        );

        let nh: std::net::Ipv6Addr = "2001:db8::1".parse().unwrap();
        let mut config = make_config(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 65002);
        config.local_ipv6_nexthop = Some(nh);

        let transport = mgr.build_transport_config(&config);
        assert_eq!(transport.local_ipv6_nexthop, Some(nh));
    }

    #[test]
    fn build_transport_config_preserves_route_server_client() {
        let (_, rx) = mpsc::channel(16);
        let (rib_tx, _rib_rx) = mpsc::channel(64);
        let metrics = BgpMetrics::new();
        let mgr = PeerManager::new(
            rx,
            65001,
            Ipv4Addr::new(10, 0, 0, 1),
            None,
            None,
            metrics,
            rib_tx,
            None,
        );

        let mut config = make_config(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 65002);
        config.route_server_client = true;

        let transport = mgr.build_transport_config(&config);
        assert!(transport.route_server_client);
    }

    /// Regression: when a policy mutation actually changes the
    /// effective import policy for an Idle peer (so
    /// `import_changed` flips true inside
    /// `update_runtime_policies`), the route-refresh trigger must
    /// be gated on Established and the mutation must still return
    /// Ok. Without the gate, `send_route_refresh` returns "session
    /// not Established" for any peer mid-reconnect, which would
    /// propagate through `apply_policy_change` and fail the gRPC
    /// call. Operators with even one peer mid-reconnect would see
    /// every `SetPolicy` / `SetGlobalImportChain` fail.
    ///
    /// The test deliberately wires up a chain reference to the
    /// policy so `import_changed` actually fires. Earlier shape
    /// (`SetPolicy` with no chain reference) didn't exercise the
    /// gate at all — `import_changed` stayed false and the test
    /// would pass even with the gate removed.
    ///
    /// Companion (Established-side) coverage — that the auto-refresh
    /// actually fires when a peer IS Established — is M34 in the
    /// interop suite (needs a real FRR session).
    #[tokio::test]
    async fn set_policy_does_not_error_on_idle_peers_when_import_changes() {
        use rustbgpd_api::peer_types::{NamedPolicyDefinition, PolicyStatementDefinition};
        let (tx, rx) = mpsc::channel(16);
        let (rib_tx, _rib_rx) = mpsc::channel(64);
        let metrics = BgpMetrics::new();
        let mgr = PeerManager::new(
            rx,
            65001,
            Ipv4Addr::new(10, 0, 0, 1),
            None,
            None,
            metrics,
            rib_tx,
            None,
        );
        let handle = tokio::spawn(mgr.run());

        // sync_config_snapshot = true so PM's current_config tracks
        // the new neighbor. Otherwise apply_policy_change's per-peer
        // loop skips it (the neighbor wouldn't be present in
        // next_config) and update_runtime_policies never runs —
        // making the gate untestable.
        let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(PeerManagerCommand::AddPeer {
            config: make_config(addr, 65002),
            sync_config_snapshot: true,
            reply: reply_tx,
        })
        .await
        .unwrap();
        assert!(reply_rx.await.unwrap().is_ok(), "AddPeer must succeed");

        // Step 1: install a named policy that the peer's resolved
        // chain will pick up once we attach it via the global
        // import_chain. This call alone doesn't move
        // `import_changed` (no chain references the new policy
        // yet); it's just setup.
        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(PeerManagerCommand::SetPolicy {
            name: "test-policy".to_string(),
            definition: NamedPolicyDefinition {
                default_action: "deny".to_string(),
                statements: Vec::<PolicyStatementDefinition>::new(),
            },
            reply: reply_tx,
        })
        .await
        .unwrap();
        assert!(
            reply_rx.await.unwrap().is_ok(),
            "SetPolicy setup step must succeed"
        );

        // Step 2: this is the call that actually flips
        // `import_changed = true`. Setting the global chain to
        // ["test-policy"] makes the peer's resolved import chain
        // move from "empty / inline" to "single-policy chain
        // (deny-default)" — `update_runtime_policies` sees the
        // change and tries to fire `soft_reset_in`. The peer is
        // Idle (unreachable address, no session), so without the
        // Established gate the route-refresh would error and the
        // reply would be Err.
        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(PeerManagerCommand::SetGlobalImportChain {
            policy_names: vec!["test-policy".to_string()],
            reply: reply_tx,
        })
        .await
        .unwrap();
        let result = reply_rx.await.unwrap();
        assert!(
            result.is_ok(),
            "SetGlobalImportChain with import-changing chain must succeed when the only \
             affected peer is Idle — the auto Route Refresh trigger must be gated on \
             Established or operator gRPC calls would fail every time a peer is mid-reconnect. \
             Got: {result:?}",
        );

        tx.send(PeerManagerCommand::Shutdown).await.unwrap();
        handle.await.unwrap();
    }

    /// Auto-retry semantics for `pending_refresh`: if a prior call set
    /// the flag (because an Established refresh send failed), the next
    /// call to `update_runtime_policies` must drain it. When the peer
    /// still isn't Established at the time of the next call, the flag
    /// must be re-armed so a future call retries — without this, a
    /// transient send failure would silently leave the new policy
    /// applied to *future* UPDATEs while routes already in `AdjRibIn`
    /// keep flowing under the prior policy.
    ///
    /// Construct `ManagedPeer` directly with `pending_refresh = true`
    /// to simulate inheriting the flag. Driving the natural failure
    /// path (Established → `send_route_refresh` Err) requires a real
    /// session, which is what M34 (interop) covers; the unit test
    /// focuses on the in-process drain/re-arm bookkeeping.
    #[tokio::test]
    async fn pending_refresh_re_arms_when_peer_still_not_established() {
        let (_cmd_tx, cmd_rx) = mpsc::channel(16);
        let (rib_tx, _rib_rx) = mpsc::channel::<RibUpdate>(64);
        let metrics = BgpMetrics::new();
        let mut mgr = PeerManager::new(
            cmd_rx,
            65001,
            Ipv4Addr::new(10, 0, 0, 1),
            None,
            None,
            metrics.clone(),
            rib_tx.clone(),
            None,
        );

        let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let peer_config = make_config(addr, 65002);
        let transport = mgr.build_transport_config(&peer_config);
        // Spawn a peer session handle but never call `start()` — the
        // session stays in Idle, so QueryState returns Some(Idle) and
        // is_established == false inside update_runtime_policies.
        let handle = rustbgpd_transport::PeerHandle::spawn(
            transport.clone(),
            metrics,
            rib_tx.clone(),
            None,
            None,
            None,
            None,
            None,
            false,
        );
        let hold = transport.peer.hold_time;
        mgr.peers.insert(
            addr,
            ManagedPeer {
                handle,
                remote_asn: 65002,
                description: "test".to_string(),
                peer_group: None,
                enabled: true,
                hold_time: Some(hold),
                max_prefixes: None,
                transport_config: transport,
                import_policy: None,
                export_policy: None,
                pending_inbound: None,
                is_dynamic: false,
                pending_refresh: true,
                pending_export_apply: false,
                advertise_graceful_shutdown: false,
            },
        );

        // Same (None) policies — `import_changed = false` here. The
        // refresh intent is carried only by `pending_refresh`; if the
        // drain logic forgot to honor the flag, this call would no-op
        // and pending_refresh would clear silently.
        let result = mgr.update_runtime_policies(addr, None, None).await;
        assert!(
            result.is_ok(),
            "update_runtime_policies on Idle peer must return Ok even when retrying a \
             pending refresh — refresh is gated on Established, so 'not Established yet' \
             is not an error condition. Got: {result:?}"
        );

        let pending = mgr.peers.get(&addr).unwrap().pending_refresh;
        assert!(
            pending,
            "pending_refresh must be re-armed after an update where the peer is still \
             not Established. Without this, a transient Err on the original Established \
             refresh would leave routes in AdjRibIn flowing under the prior policy until \
             an operator manually reissues SetPolicy."
        );
    }

    #[tokio::test]
    async fn channel_full_policy_update_bails_and_preserves_pending_refresh() {
        use rustbgpd_transport::PeerCommand;

        let (session_tx, session_rx) = mpsc::channel::<PeerCommand>(1);
        let (queued_reply, _queued_rx) = oneshot::channel();
        assert!(
            session_tx
                .try_send(PeerCommand::QueryState {
                    reply: queued_reply,
                })
                .is_ok(),
            "pre-fill the session command channel so policy hot-apply send blocks"
        );
        let (finish_tx, finish_rx) = oneshot::channel::<()>();
        let task = tokio::spawn(async move {
            let _session_rx = session_rx;
            let _ = finish_rx.await;
            Ok(())
        });
        let handle = PeerHandle::from_parts(session_tx, task);

        let (_cmd_tx, cmd_rx) = mpsc::channel(16);
        let (rib_tx, _rib_rx) = mpsc::channel::<RibUpdate>(64);
        let mut mgr = PeerManager::new(
            cmd_rx,
            65001,
            Ipv4Addr::new(10, 0, 0, 1),
            None,
            None,
            BgpMetrics::new(),
            rib_tx,
            None,
        );
        let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        insert_test_managed_peer(&mut mgr, addr, handle, false);

        let result = mgr
            .update_runtime_policies(addr, Some(deny_policy_chain()), None)
            .await;

        assert!(
            result.is_err(),
            "full session command channel must surface as a failed hot-apply, not a \
             silent policy success. Got: {result:?}"
        );
        let err = result.unwrap_err();
        assert!(
            err.contains("timed out") && err.contains("import:"),
            "error should preserve the channel-full timeout detail: {err}"
        );
        let managed = mgr.peers.get(&addr).expect("peer remains managed");
        assert!(
            managed.pending_refresh,
            "pending_refresh must be set so a later policy update retries after the \
             session command channel drains"
        );
        assert!(
            managed.import_policy.is_none(),
            "daemon bookkeeping must not advance when the session command never accepted \
             the import-policy update"
        );

        let _ = finish_tx.send(());
    }

    #[allow(clippy::too_many_lines)]
    #[tokio::test]
    async fn back_to_back_updates_do_not_lose_pending_refresh() {
        use rustbgpd_transport::PeerCommand;
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

        let (session_tx, mut session_rx) = mpsc::channel::<PeerCommand>(8);
        let established = Arc::new(AtomicBool::new(false));
        let refresh_calls = Arc::new(AtomicU32::new(0));
        let established_in_task = established.clone();
        let refresh_calls_in_task = refresh_calls.clone();
        let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let task = tokio::spawn(async move {
            while let Some(cmd) = session_rx.recv().await {
                match cmd {
                    PeerCommand::UpdateImportPolicy { reply, .. }
                    | PeerCommand::UpdateExportPolicy { reply, .. } => {
                        let _ = reply.send(Ok(()));
                    }
                    PeerCommand::QueryState { reply } => {
                        let state = if established_in_task.load(Ordering::SeqCst) {
                            SessionState::Established
                        } else {
                            SessionState::Idle
                        };
                        let _ = reply.send(PeerSessionState {
                            fsm_state: state,
                            peer_ip: addr,
                            prefix_count: 0,
                            negotiated_hold_time: Some(90),
                            four_octet_as: Some(true),
                            remote_router_id: Some(Ipv4Addr::new(10, 0, 0, 2)),
                            updates_received: 0,
                            updates_sent: 0,
                            notifications_received: 0,
                            notifications_sent: 0,
                            flap_count: 0,
                            uptime_secs: u64::from(state == SessionState::Established),
                            last_error: String::new(),
                        });
                    }
                    PeerCommand::SendRouteRefresh { reply, .. } => {
                        refresh_calls_in_task.fetch_add(1, Ordering::SeqCst);
                        let _ = reply.send(Ok(()));
                    }
                    PeerCommand::Shutdown => break,
                    _ => {}
                }
            }
            Ok(())
        });
        let handle = PeerHandle::from_parts(session_tx, task);

        let (_cmd_tx, cmd_rx) = mpsc::channel(16);
        let (rib_tx, mut rib_rx) = mpsc::channel::<RibUpdate>(64);
        let rib_drainer = tokio::spawn(async move {
            while let Some(update) = rib_rx.recv().await {
                if let RibUpdate::ReplacePeerExportPolicy { reply, .. } = update {
                    let _ = reply.send(Ok(()));
                }
            }
        });
        let mut mgr = PeerManager::new(
            cmd_rx,
            65001,
            Ipv4Addr::new(10, 0, 0, 1),
            None,
            None,
            BgpMetrics::new(),
            rib_tx,
            None,
        );
        insert_test_managed_peer(&mut mgr, addr, handle, true);

        let first = mgr.update_runtime_policies(addr, None, None).await;
        assert!(
            first.is_ok(),
            "first update should re-arm the pending refresh while the peer is idle: {first:?}"
        );
        assert!(
            mgr.peers.get(&addr).unwrap().pending_refresh,
            "pending_refresh must survive the first back-to-back update while the peer is idle"
        );
        assert_eq!(
            refresh_calls.load(Ordering::SeqCst),
            0,
            "idle peer must not receive route refresh yet"
        );

        established.store(true, Ordering::SeqCst);
        let second = mgr.update_runtime_policies(addr, None, None).await;
        assert!(
            second.is_ok(),
            "second update should consume the carried refresh once the peer is Established: {second:?}"
        );
        assert!(
            !mgr.peers.get(&addr).unwrap().pending_refresh,
            "pending_refresh must clear after the retry successfully sends Route Refresh"
        );
        assert_eq!(
            refresh_calls.load(Ordering::SeqCst),
            1,
            "second update must fire the previously carried Route Refresh exactly once"
        );

        mgr.delete_peer(addr, false).await.unwrap();
        drop(mgr);
        let _ = rib_drainer.await;
    }

    #[tokio::test]
    async fn peer_deletion_after_failed_update_drops_pending_retry_cleanly() {
        use rustbgpd_transport::PeerCommand;

        let (session_tx, mut session_rx) = mpsc::channel::<PeerCommand>(8);
        let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let task = tokio::spawn(async move {
            while let Some(cmd) = session_rx.recv().await {
                match cmd {
                    PeerCommand::UpdateImportPolicy { reply, .. } => {
                        drop(reply);
                    }
                    PeerCommand::UpdateExportPolicy { reply, .. } => {
                        let _ = reply.send(Ok(()));
                    }
                    PeerCommand::QueryState { reply } => {
                        let _ = reply.send(PeerSessionState {
                            fsm_state: SessionState::Established,
                            peer_ip: addr,
                            prefix_count: 0,
                            negotiated_hold_time: Some(90),
                            four_octet_as: Some(true),
                            remote_router_id: Some(Ipv4Addr::new(10, 0, 0, 2)),
                            updates_received: 0,
                            updates_sent: 0,
                            notifications_received: 0,
                            notifications_sent: 0,
                            flap_count: 0,
                            uptime_secs: 1,
                            last_error: String::new(),
                        });
                    }
                    PeerCommand::Shutdown => break,
                    _ => {}
                }
            }
            Ok(())
        });
        let handle = PeerHandle::from_parts(session_tx, task);

        let (_cmd_tx, cmd_rx) = mpsc::channel(16);
        let (rib_tx, _rib_rx) = mpsc::channel::<RibUpdate>(64);
        let mut mgr = PeerManager::new(
            cmd_rx,
            65001,
            Ipv4Addr::new(10, 0, 0, 1),
            None,
            None,
            BgpMetrics::new(),
            rib_tx,
            None,
        );
        insert_test_managed_peer(&mut mgr, addr, handle, false);

        let failed = mgr
            .update_runtime_policies(addr, Some(deny_policy_chain()), None)
            .await;
        assert!(
            failed.is_err(),
            "first update should fail and leave pending retry intent: {failed:?}"
        );
        assert!(
            mgr.peers.get(&addr).unwrap().pending_refresh,
            "failed update must set pending_refresh before deletion"
        );

        mgr.delete_peer(addr, false)
            .await
            .expect("peer deletion after failed update must complete");
        assert!(
            mgr.peers.is_empty(),
            "deleting the peer must drop the ManagedPeer that held pending retry state"
        );

        let retry_after_delete = mgr
            .update_runtime_policies(addr, Some(deny_policy_chain()), None)
            .await;
        assert!(
            retry_after_delete.is_ok(),
            "a queued or follow-up policy update for a peer deleted during the failure window \
             must no-op cleanly, not resurrect stale pending state: {retry_after_delete:?}"
        );
    }

    #[allow(clippy::too_many_lines)]
    #[tokio::test]
    async fn honor_graceful_shutdown_hot_apply_targets_ebgp_only() {
        use rustbgpd_transport::PeerCommand;
        use std::sync::Arc;
        use std::sync::atomic::{AtomicU32, Ordering};

        fn fake_established_peer(
            addr: IpAddr,
            import_updates: Arc<AtomicU32>,
            refresh_calls: Arc<AtomicU32>,
        ) -> PeerHandle {
            let (session_tx, mut session_rx) = mpsc::channel::<PeerCommand>(8);
            let task = tokio::spawn(async move {
                while let Some(cmd) = session_rx.recv().await {
                    match cmd {
                        PeerCommand::UpdateImportPolicy { reply, .. } => {
                            import_updates.fetch_add(1, Ordering::SeqCst);
                            let _ = reply.send(Ok(()));
                        }
                        PeerCommand::UpdateExportPolicy { reply, .. } => {
                            let _ = reply.send(Ok(()));
                        }
                        PeerCommand::QueryState { reply } => {
                            let _ = reply.send(PeerSessionState {
                                fsm_state: SessionState::Established,
                                peer_ip: addr,
                                prefix_count: 0,
                                negotiated_hold_time: Some(90),
                                four_octet_as: Some(true),
                                remote_router_id: Some(Ipv4Addr::new(10, 0, 0, 2)),
                                updates_received: 0,
                                updates_sent: 0,
                                notifications_received: 0,
                                notifications_sent: 0,
                                flap_count: 0,
                                uptime_secs: 1,
                                last_error: String::new(),
                            });
                        }
                        PeerCommand::SendRouteRefresh { reply, .. } => {
                            refresh_calls.fetch_add(1, Ordering::SeqCst);
                            let _ = reply.send(Ok(()));
                        }
                        PeerCommand::Shutdown => break,
                        _ => {}
                    }
                }
                Ok(())
            });
            PeerHandle::from_parts(session_tx, task)
        }

        let (_cmd_tx, cmd_rx) = mpsc::channel(16);
        let (rib_tx, mut rib_rx) = mpsc::channel::<RibUpdate>(64);
        let rib_drainer = tokio::spawn(async move {
            while let Some(update) = rib_rx.recv().await {
                if let RibUpdate::ReplacePeerExportPolicy { reply, .. } = update {
                    let _ = reply.send(Ok(()));
                }
            }
        });
        let mut mgr = PeerManager::new(
            cmd_rx,
            65001,
            Ipv4Addr::new(10, 0, 0, 1),
            None,
            None,
            BgpMetrics::new(),
            rib_tx,
            None,
        );

        let ebgp = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let ibgp = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
        mgr.current_config.neighbors =
            vec![config_neighbor(ebgp, 65002), config_neighbor(ibgp, 65001)];

        let ebgp_import_updates = Arc::new(AtomicU32::new(0));
        let ebgp_refresh_calls = Arc::new(AtomicU32::new(0));
        let ibgp_import_updates = Arc::new(AtomicU32::new(0));
        let ibgp_refresh_calls = Arc::new(AtomicU32::new(0));
        insert_test_managed_peer_with_asn(
            &mut mgr,
            ebgp,
            65002,
            fake_established_peer(
                ebgp,
                ebgp_import_updates.clone(),
                ebgp_refresh_calls.clone(),
            ),
            false,
        );
        insert_test_managed_peer_with_asn(
            &mut mgr,
            ibgp,
            65001,
            fake_established_peer(
                ibgp,
                ibgp_import_updates.clone(),
                ibgp_refresh_calls.clone(),
            ),
            false,
        );

        let result = mgr.set_honor_graceful_shutdown(true).await;
        assert!(result.is_ok(), "hot-apply must succeed: {result:?}");
        assert!(mgr.current_config.global.honor_graceful_shutdown);
        assert_eq!(
            ebgp_import_updates.load(Ordering::SeqCst),
            1,
            "EBGP peer must receive recomputed import policy with the implicit GShut rule"
        );
        assert_eq!(
            ebgp_refresh_calls.load(Ordering::SeqCst),
            1,
            "Established EBGP peer must get route refresh after the import chain changes"
        );
        assert_eq!(
            ibgp_import_updates.load(Ordering::SeqCst),
            0,
            "iBGP peer must be exempt from RFC 8326 receiver hot-apply"
        );
        assert_eq!(
            ibgp_refresh_calls.load(Ordering::SeqCst),
            0,
            "iBGP exemption also means no route refresh"
        );

        mgr.delete_peer(ebgp, false).await.unwrap();
        mgr.delete_peer(ibgp, false).await.unwrap();
        drop(mgr);
        let _ = rib_drainer.await;
    }

    /// Regression for a high-severity gap in the prior code: when
    /// `update_import_policy_timeout` failed against an Established
    /// peer, the warn-and-continue path then fired `soft_reset_in`
    /// regardless. The session task still held the *old* import
    /// policy, so Route Refresh would re-evaluate `AdjRibIn` against
    /// the old policy — silently keeping forbidden routes flowing
    /// on a permit→deny edit, with the daemon believing
    /// the new policy was live and clearing any retry intent.
    ///
    /// Fix and assertion: when the session-side import-policy update
    /// fails AND the peer is Established AND there's a refresh
    /// intent, the function must (a) leave `managed.import_policy`
    /// at the prior value (so the next call's `import_changed` still
    /// fires), (b) set `pending_refresh` for retry, (c) NOT call
    /// `soft_reset_in`, and (d) return Err so the caller surfaces
    /// the failure. The fake session here drops the import-policy
    /// reply oneshot (sender side gets "session task dropped reply")
    /// but answers `QueryState` with Established. This reproduces
    /// the production race: the session task can drop a reply
    /// mid-shutdown while the FSM is still reporting Established
    /// for one more poll.
    #[allow(clippy::too_many_lines)]
    #[tokio::test]
    async fn import_apply_failure_on_established_peer_bails_without_refresh() {
        use rustbgpd_policy::{Policy, PolicyAction};
        use rustbgpd_transport::PeerCommand;
        use std::sync::Arc;
        use std::sync::atomic::{AtomicU32, Ordering};

        // Fake session task: drops UpdateImportPolicy replies (induces
        // "session task dropped reply" Err on the caller side), replies
        // OK to UpdateExportPolicy, replies Established to QueryState,
        // and counts SendRouteRefresh invocations so the test can
        // assert refresh was NOT issued. Subsequent commands process
        // sequentially after the dropped import reply because we drop
        // the reply oneshot inside the same arm — no parking.
        let (tx, mut rx) = mpsc::channel::<PeerCommand>(8);
        let route_refresh_calls = Arc::new(AtomicU32::new(0));
        let route_refresh_calls_in_task = route_refresh_calls.clone();
        let task_addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let task = tokio::spawn(async move {
            while let Some(cmd) = rx.recv().await {
                match cmd {
                    PeerCommand::UpdateImportPolicy { reply, .. } => {
                        // Drop reply without responding → caller's
                        // reply_rx.await yields RecvError → the
                        // bounded variant maps that to "session task
                        // dropped reply".
                        drop(reply);
                    }
                    PeerCommand::UpdateExportPolicy { reply, .. } => {
                        let _ = reply.send(Ok(()));
                    }
                    PeerCommand::QueryState { reply } => {
                        let _ = reply.send(PeerSessionState {
                            fsm_state: SessionState::Established,
                            peer_ip: task_addr,
                            prefix_count: 0,
                            negotiated_hold_time: Some(90),
                            four_octet_as: Some(true),
                            remote_router_id: Some(Ipv4Addr::new(10, 0, 0, 2)),
                            updates_received: 0,
                            updates_sent: 0,
                            notifications_received: 0,
                            notifications_sent: 0,
                            flap_count: 0,
                            uptime_secs: 1,
                            last_error: String::new(),
                        });
                    }
                    PeerCommand::SendRouteRefresh { reply, .. } => {
                        route_refresh_calls_in_task.fetch_add(1, Ordering::SeqCst);
                        let _ = reply.send(Ok(()));
                    }
                    PeerCommand::Shutdown => break,
                    _ => {}
                }
            }
            Ok(())
        });
        let handle = PeerHandle::from_parts(tx, task);

        let (_cmd_tx, cmd_rx) = mpsc::channel(16);
        // RIB receiver is held but never expected to receive: the bail
        // path returns Err *before* the `ReplacePeerExportPolicy`
        // send. Holding rib_rx alive prevents the
        // `RibUpdate::ReplacePeerExportPolicy` send from failing
        // spuriously if the bail logic ever regresses.
        let (rib_tx, _rib_rx) = mpsc::channel::<RibUpdate>(64);
        let metrics = BgpMetrics::new();
        let mut mgr = PeerManager::new(
            cmd_rx,
            65001,
            Ipv4Addr::new(10, 0, 0, 1),
            None,
            None,
            metrics,
            rib_tx,
            None,
        );
        let peer_config = make_config(task_addr, 65002);
        let transport = mgr.build_transport_config(&peer_config);
        let hold = transport.peer.hold_time;
        mgr.peers.insert(
            task_addr,
            ManagedPeer {
                handle,
                remote_asn: 65002,
                description: "test".to_string(),
                peer_group: None,
                enabled: true,
                hold_time: Some(hold),
                max_prefixes: None,
                transport_config: transport,
                import_policy: None,
                export_policy: None,
                pending_inbound: None,
                is_dynamic: false,
                pending_refresh: false,
                pending_export_apply: false,
                advertise_graceful_shutdown: false,
            },
        );

        // Build a non-empty PolicyChain so import_changed flips true
        // (None → Some(...)). The chain content doesn't matter for
        // the test — only that it's distinct from the prior None.
        let chain = PolicyChain::new(vec![Policy {
            entries: Vec::new(),
            default_action: PolicyAction::Deny,
        }]);

        let result = mgr
            .update_runtime_policies(task_addr, Some(chain), None)
            .await;

        assert!(
            result.is_err(),
            "Established peer with import-changing intent must surface session-side \
             import-apply failure as Err — silently logging-and-continuing would let \
             the daemon believe the new policy is live while the session still has the \
             old one. Got: {result:?}"
        );
        let err_msg = result.unwrap_err();
        assert!(
            err_msg.contains("policy hot-apply") && err_msg.contains("import:"),
            "error message must explain the failure mode for the operator: {err_msg}"
        );

        let managed = mgr.peers.get(&task_addr).expect("peer present");
        assert!(
            managed.pending_refresh,
            "pending_refresh must be set so the next update_runtime_policies call \
             retries the session-side update + Route Refresh as a unit."
        );
        assert!(
            managed.import_policy.is_none(),
            "managed.import_policy must remain at the prior value when the \
             session-side update failed — advancing it would mask the delta from \
             the next call's import_changed comparison and skip the retry. \
             Got: {:?}",
            managed.import_policy
        );

        assert_eq!(
            route_refresh_calls.load(Ordering::SeqCst),
            0,
            "soft_reset_in must NOT have run: firing Route Refresh against a session \
             that still holds the prior import policy would re-evaluate AdjRibIn \
             against the OLD policy — the silent-stale-routes regression this test pins."
        );
    }

    /// Non-Established variant of the import-apply failure regression.
    /// The prior bail condition
    /// (`is_established && import_apply_failed && needs_refresh`)
    /// gated the failure surface on Established, which let an Idle /
    /// Connect peer with a dropped `UpdateImportPolicy` command
    /// silently return Ok. The caller (`apply_policy_change`) then
    /// advanced `current_config`, leaving no retry signal — if the
    /// session task subsequently died before processing the queued
    /// command, the peer would reach Established holding the prior
    /// import policy with no record that the edit didn't land.
    ///
    /// The fix dropped the `is_established` gate from `import_bail`
    /// (Route Refresh stays gated by `soft_reset_in`'s own check —
    /// the gates serve different purposes). This test pins that
    /// behavior: an Idle peer with a session that drops the
    /// `UpdateImportPolicy` reply must bail with Err, set
    /// `pending_refresh = true`, leave `managed.import_policy` at
    /// the prior value, and (because peer is Idle) NOT fire Route
    /// Refresh.
    #[allow(clippy::too_many_lines)]
    #[tokio::test]
    async fn import_apply_failure_on_idle_peer_bails_and_sets_pending_refresh() {
        use rustbgpd_policy::{Policy, PolicyAction};
        use rustbgpd_transport::PeerCommand;
        use std::sync::Arc;
        use std::sync::atomic::{AtomicU32, Ordering};

        let (tx, mut rx) = mpsc::channel::<PeerCommand>(8);
        let route_refresh_calls = Arc::new(AtomicU32::new(0));
        let route_refresh_calls_in_task = route_refresh_calls.clone();
        let task_addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let task = tokio::spawn(async move {
            while let Some(cmd) = rx.recv().await {
                match cmd {
                    PeerCommand::UpdateImportPolicy { reply, .. } => {
                        // Drop without replying — caller observes
                        // "session task dropped reply".
                        drop(reply);
                    }
                    PeerCommand::UpdateExportPolicy { reply, .. } => {
                        let _ = reply.send(Ok(()));
                    }
                    PeerCommand::QueryState { reply } => {
                        let _ = reply.send(PeerSessionState {
                            fsm_state: SessionState::Idle,
                            peer_ip: task_addr,
                            prefix_count: 0,
                            negotiated_hold_time: None,
                            four_octet_as: None,
                            remote_router_id: None,
                            updates_received: 0,
                            updates_sent: 0,
                            notifications_received: 0,
                            notifications_sent: 0,
                            flap_count: 0,
                            uptime_secs: 0,
                            last_error: String::new(),
                        });
                    }
                    PeerCommand::SendRouteRefresh { reply, .. } => {
                        route_refresh_calls_in_task.fetch_add(1, Ordering::SeqCst);
                        let _ = reply.send(Ok(()));
                    }
                    PeerCommand::Shutdown => break,
                    _ => {}
                }
            }
            Ok(())
        });
        let handle = PeerHandle::from_parts(tx, task);

        let (_cmd_tx, cmd_rx) = mpsc::channel(16);
        let (rib_tx, _rib_rx) = mpsc::channel::<RibUpdate>(64);
        let metrics = BgpMetrics::new();
        let mut mgr = PeerManager::new(
            cmd_rx,
            65001,
            Ipv4Addr::new(10, 0, 0, 1),
            None,
            None,
            metrics,
            rib_tx,
            None,
        );
        let peer_config = make_config(task_addr, 65002);
        let transport = mgr.build_transport_config(&peer_config);
        let hold = transport.peer.hold_time;
        mgr.peers.insert(
            task_addr,
            ManagedPeer {
                handle,
                remote_asn: 65002,
                description: "test".to_string(),
                peer_group: None,
                enabled: true,
                hold_time: Some(hold),
                max_prefixes: None,
                transport_config: transport,
                import_policy: None,
                export_policy: None,
                pending_inbound: None,
                is_dynamic: false,
                pending_refresh: false,
                pending_export_apply: false,
                advertise_graceful_shutdown: false,
            },
        );

        let chain = PolicyChain::new(vec![Policy {
            entries: Vec::new(),
            default_action: PolicyAction::Deny,
        }]);

        let result = mgr
            .update_runtime_policies(task_addr, Some(chain), None)
            .await;

        assert!(
            result.is_err(),
            "Idle peer with import-changing intent and session-side apply failure must \
             surface as Err — silently returning Ok would let `apply_policy_change` \
             advance current_config with no retry signal, so a subsequently dying \
             session task would leak the stale import policy when the peer establishes. \
             Got: {result:?}"
        );
        let err_msg = result.unwrap_err();
        assert!(
            err_msg.contains("policy hot-apply") && err_msg.contains("import:"),
            "error message must call out the import side specifically: {err_msg}"
        );

        let managed = mgr.peers.get(&task_addr).expect("peer present");
        assert!(
            managed.pending_refresh,
            "pending_refresh must be set so the next update_runtime_policies call \
             retries the session-side import update."
        );
        assert!(
            managed.import_policy.is_none(),
            "managed.import_policy must remain at the prior value when the session-side \
             update failed — advancing it would mask the delta from the next call's \
             import_changed comparison and skip the retry. Got: {:?}",
            managed.import_policy
        );

        assert_eq!(
            route_refresh_calls.load(Ordering::SeqCst),
            0,
            "Route Refresh must NOT fire for an Idle peer regardless of the bail \
             outcome — that's `soft_reset_in`'s own Established gate, which is a \
             separate concern from the failure-surfacing decision."
        );
    }

    /// Symmetric counterpart for the export side: the prior code
    /// swallowed `update_export_policy_timeout` failures, logging a
    /// warning and returning Ok. That left the peer announcing
    /// under the old export policy even though the daemon's
    /// bookkeeping had no record that the edit didn't land.
    /// Different blast radius from the import gap
    /// (no Route Refresh involved), but the same silent-stale-policy
    /// class — and crucially, no `is_established` gate: a session
    /// that's mid-handshake can still drop policy commands, and once
    /// it reaches Established the registration with the RIB
    /// (`PeerUp` path) uses whatever export policy the session task
    /// holds. Failure must propagate, the bookkeeping must not
    /// advance, and `pending_export_apply` must be set so the next
    /// call retries.
    #[allow(clippy::too_many_lines)]
    #[tokio::test]
    async fn export_apply_failure_bails_without_advancing_bookkeeping() {
        use rustbgpd_policy::{Policy, PolicyAction};
        use rustbgpd_transport::PeerCommand;
        use std::sync::Arc;
        use std::sync::atomic::{AtomicU32, Ordering};

        let (tx, mut rx) = mpsc::channel::<PeerCommand>(8);
        let rib_replace_calls = Arc::new(AtomicU32::new(0));
        let route_refresh_calls = Arc::new(AtomicU32::new(0));
        let route_refresh_calls_in_task = route_refresh_calls.clone();
        let task_addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let task = tokio::spawn(async move {
            while let Some(cmd) = rx.recv().await {
                match cmd {
                    PeerCommand::UpdateImportPolicy { reply, .. } => {
                        let _ = reply.send(Ok(()));
                    }
                    PeerCommand::UpdateExportPolicy { reply, .. } => {
                        // Drop without replying — caller observes
                        // "session task dropped reply".
                        drop(reply);
                    }
                    PeerCommand::QueryState { reply } => {
                        // Idle is enough: the export-side bail does
                        // not require Established. Using Idle here
                        // proves the export gap fires regardless of
                        // session state, which the prior code's
                        // warn-and-continue would have masked for
                        // every non-Established peer.
                        let _ = reply.send(PeerSessionState {
                            fsm_state: SessionState::Idle,
                            peer_ip: task_addr,
                            prefix_count: 0,
                            negotiated_hold_time: None,
                            four_octet_as: None,
                            remote_router_id: None,
                            updates_received: 0,
                            updates_sent: 0,
                            notifications_received: 0,
                            notifications_sent: 0,
                            flap_count: 0,
                            uptime_secs: 0,
                            last_error: String::new(),
                        });
                    }
                    PeerCommand::SendRouteRefresh { reply, .. } => {
                        route_refresh_calls_in_task.fetch_add(1, Ordering::SeqCst);
                        let _ = reply.send(Ok(()));
                    }
                    PeerCommand::Shutdown => break,
                    _ => {}
                }
            }
            Ok(())
        });
        let handle = PeerHandle::from_parts(tx, task);

        let (_cmd_tx, cmd_rx) = mpsc::channel(16);
        // Hold rib_rx but spawn a task to assert ReplacePeerExportPolicy
        // is never received: the bail must run *before* the RIB step.
        let (rib_tx, mut rib_rx) = mpsc::channel::<RibUpdate>(64);
        let rib_replace_calls_clone = rib_replace_calls.clone();
        let rib_drainer = tokio::spawn(async move {
            while let Some(update) = rib_rx.recv().await {
                if matches!(update, RibUpdate::ReplacePeerExportPolicy { .. }) {
                    rib_replace_calls_clone.fetch_add(1, Ordering::SeqCst);
                }
            }
        });

        let metrics = BgpMetrics::new();
        let mut mgr = PeerManager::new(
            cmd_rx,
            65001,
            Ipv4Addr::new(10, 0, 0, 1),
            None,
            None,
            metrics,
            rib_tx,
            None,
        );
        let peer_config = make_config(task_addr, 65002);
        let transport = mgr.build_transport_config(&peer_config);
        let hold = transport.peer.hold_time;
        mgr.peers.insert(
            task_addr,
            ManagedPeer {
                handle,
                remote_asn: 65002,
                description: "test".to_string(),
                peer_group: None,
                enabled: true,
                hold_time: Some(hold),
                max_prefixes: None,
                transport_config: transport,
                import_policy: None,
                export_policy: None,
                pending_inbound: None,
                is_dynamic: false,
                pending_refresh: false,
                pending_export_apply: false,
                advertise_graceful_shutdown: false,
            },
        );

        let chain = PolicyChain::new(vec![Policy {
            entries: Vec::new(),
            default_action: PolicyAction::Deny,
        }]);

        // Pass the chain on the export side; import stays None so
        // import_apply succeeds and only the export path drives the
        // bail. This isolates the export-side regression from the
        // import-side coverage already in place.
        let result = mgr
            .update_runtime_policies(task_addr, None, Some(chain))
            .await;

        assert!(
            result.is_err(),
            "Export-changing intent with session-side apply failure must propagate as \
             Err — silently logging-and-continuing would let the daemon believe the \
             new export policy is live while the session keeps announcing under the \
             prior one. Got: {result:?}"
        );
        let err_msg = result.unwrap_err();
        assert!(
            err_msg.contains("policy hot-apply") && err_msg.contains("export:"),
            "error message must call out the export side specifically so the operator \
             can diagnose: {err_msg}"
        );

        let managed = mgr.peers.get(&task_addr).expect("peer present");
        assert!(
            managed.pending_export_apply,
            "pending_export_apply must be set so the next update_runtime_policies call \
             retries the session-side export update."
        );
        assert!(
            managed.export_policy.is_none(),
            "managed.export_policy must remain at the prior value when the session-side \
             update failed — advancing it would mask the delta from the next call's \
             export_changed comparison and skip the retry. Got: {:?}",
            managed.export_policy
        );

        assert_eq!(
            rib_replace_calls.load(Ordering::SeqCst),
            0,
            "RIB ReplacePeerExportPolicy must NOT fire when the session-side export \
             update failed: the RIB and session would otherwise diverge, with the RIB \
             computing routes against the new policy and the session re-applying the \
             old one on outbound."
        );
        assert_eq!(
            route_refresh_calls.load(Ordering::SeqCst),
            0,
            "Export-only failure must not trigger Route Refresh — that is import-side \
             machinery and has no business firing on an export edit."
        );

        // Drain rib_rx so the spawned task can exit cleanly when mgr drops.
        drop(mgr);
        let _ = rib_drainer.await;
    }

    /// Cross-side regression: import apply succeeds (advancing
    /// `managed.import_policy`) but export apply fails on the same
    /// call. The bail must carry forward the unfired Route Refresh
    /// intent so a subsequent retry — even one that finds
    /// `import_changed = false` because bookkeeping already advanced
    /// — still fires `soft_reset_in`. Without this, an operator
    /// applying a policy referenced by both import and export chains
    /// would land the new import policy for *future* UPDATEs but
    /// leave `AdjRibIn` routes accepted under the prior import
    /// policy stuck, with no signal that the refresh ever needed
    /// to run.
    ///
    /// First call: fake session ACKs `UpdateImportPolicy`, drops
    /// `UpdateExportPolicy` reply → bail with both `pending_refresh`
    /// and `pending_export_apply` set.
    ///
    /// Second call (same target policies): fake session ACKs both →
    /// no bail, `had_pending_refresh = true` carries
    /// `needs_refresh = true`, `soft_reset_in` fires.
    ///
    /// Asserts: first call returns Err with both flags set; second
    /// call returns Ok with `route_refresh_calls > 0`.
    #[allow(clippy::too_many_lines)]
    #[tokio::test]
    async fn import_succeeds_export_fails_then_retry_fires_refresh() {
        use rustbgpd_policy::{Policy, PolicyAction};
        use rustbgpd_transport::PeerCommand;
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

        let (tx, mut rx) = mpsc::channel::<PeerCommand>(8);
        let drop_export_replies = Arc::new(AtomicBool::new(true));
        let route_refresh_calls = Arc::new(AtomicU32::new(0));
        let drop_export_replies_in_task = drop_export_replies.clone();
        let route_refresh_calls_in_task = route_refresh_calls.clone();
        let task_addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let task = tokio::spawn(async move {
            while let Some(cmd) = rx.recv().await {
                match cmd {
                    PeerCommand::UpdateImportPolicy { reply, .. } => {
                        let _ = reply.send(Ok(()));
                    }
                    PeerCommand::UpdateExportPolicy { reply, .. } => {
                        if drop_export_replies_in_task.load(Ordering::SeqCst) {
                            drop(reply);
                        } else {
                            let _ = reply.send(Ok(()));
                        }
                    }
                    PeerCommand::QueryState { reply } => {
                        let _ = reply.send(PeerSessionState {
                            fsm_state: SessionState::Established,
                            peer_ip: task_addr,
                            prefix_count: 0,
                            negotiated_hold_time: Some(90),
                            four_octet_as: Some(true),
                            remote_router_id: Some(Ipv4Addr::new(10, 0, 0, 2)),
                            updates_received: 0,
                            updates_sent: 0,
                            notifications_received: 0,
                            notifications_sent: 0,
                            flap_count: 0,
                            uptime_secs: 1,
                            last_error: String::new(),
                        });
                    }
                    PeerCommand::SendRouteRefresh { reply, .. } => {
                        route_refresh_calls_in_task.fetch_add(1, Ordering::SeqCst);
                        let _ = reply.send(Ok(()));
                    }
                    PeerCommand::Shutdown => break,
                    _ => {}
                }
            }
            Ok(())
        });
        let handle = PeerHandle::from_parts(tx, task);

        let (_cmd_tx, cmd_rx) = mpsc::channel(16);
        // Drain RIB so the second call's ReplacePeerExportPolicy doesn't
        // wedge waiting for a reply.
        let (rib_tx, mut rib_rx) = mpsc::channel::<RibUpdate>(64);
        let rib_drainer = tokio::spawn(async move {
            while let Some(update) = rib_rx.recv().await {
                if let RibUpdate::ReplacePeerExportPolicy { reply, .. } = update {
                    let _ = reply.send(Ok(()));
                }
            }
        });

        let metrics = BgpMetrics::new();
        let mut mgr = PeerManager::new(
            cmd_rx,
            65001,
            Ipv4Addr::new(10, 0, 0, 1),
            None,
            None,
            metrics,
            rib_tx,
            None,
        );
        let peer_config = make_config(task_addr, 65002);
        let transport = mgr.build_transport_config(&peer_config);
        let hold = transport.peer.hold_time;
        mgr.peers.insert(
            task_addr,
            ManagedPeer {
                handle,
                remote_asn: 65002,
                description: "test".to_string(),
                peer_group: None,
                enabled: true,
                hold_time: Some(hold),
                max_prefixes: None,
                transport_config: transport,
                import_policy: None,
                export_policy: None,
                pending_inbound: None,
                is_dynamic: false,
                pending_refresh: false,
                pending_export_apply: false,
                advertise_graceful_shutdown: false,
            },
        );

        let import_chain = PolicyChain::new(vec![Policy {
            entries: Vec::new(),
            default_action: PolicyAction::Deny,
        }]);
        let export_chain = PolicyChain::new(vec![Policy {
            entries: Vec::new(),
            default_action: PolicyAction::Deny,
        }]);

        // First call: import succeeds, export drops reply → bail.
        let result_1 = mgr
            .update_runtime_policies(
                task_addr,
                Some(import_chain.clone()),
                Some(export_chain.clone()),
            )
            .await;

        assert!(
            result_1.is_err(),
            "First call must fail: export apply dropped reply. Got: {result_1:?}"
        );

        let managed = mgr.peers.get(&task_addr).expect("peer present");
        assert!(
            managed.import_policy.is_some(),
            "managed.import_policy must have advanced — import apply succeeded. Got: {:?}",
            managed.import_policy
        );
        assert!(
            managed.export_policy.is_none(),
            "managed.export_policy must NOT have advanced — export apply failed. Got: {:?}",
            managed.export_policy
        );
        assert!(
            managed.pending_refresh,
            "pending_refresh MUST be set even though import_bail did not trigger — \
             the refresh intent (import_changed) survives across an export-side bail. \
             Without this, the retry would see import_changed=false, no pending refresh, \
             and silently skip Route Refresh, leaving AdjRibIn stuck on prior policy."
        );
        assert!(
            managed.pending_export_apply,
            "pending_export_apply must be set so the next retry attempts export again."
        );
        assert_eq!(
            route_refresh_calls.load(Ordering::SeqCst),
            0,
            "First call must NOT have fired Route Refresh — it bailed before that step."
        );

        // Flip the fake to ACK export replies, then retry with the
        // SAME target policies. import_changed will be false on the
        // retry (bookkeeping already advanced), so the retry must
        // rely on had_pending_refresh to decide to fire refresh.
        drop_export_replies.store(false, Ordering::SeqCst);

        let result_2 = mgr
            .update_runtime_policies(task_addr, Some(import_chain), Some(export_chain))
            .await;

        assert!(
            result_2.is_ok(),
            "Second call (export now succeeds) must return Ok. Got: {result_2:?}"
        );

        let managed = mgr.peers.get(&task_addr).expect("peer present");
        assert!(
            managed.export_policy.is_some(),
            "managed.export_policy must now be advanced after the successful retry."
        );
        assert!(
            !managed.pending_refresh,
            "pending_refresh must be cleared after the retry's soft_reset_in succeeded."
        );
        assert!(
            !managed.pending_export_apply,
            "pending_export_apply must be cleared after the retry's export apply succeeded."
        );

        assert!(
            route_refresh_calls.load(Ordering::SeqCst) >= 1,
            "Retry MUST have fired Route Refresh: this is the regression — without \
             carrying pending_refresh across the export bail on the first call, \
             needs_refresh would be false on retry and refresh would silently never \
             fire, leaving AdjRibIn stuck on prior import policy. \
             Got: {} refresh calls",
            route_refresh_calls.load(Ordering::SeqCst)
        );

        drop(mgr);
        let _ = rib_drainer.await;
    }

    /// Multi-agent quality audit caught a third partial-success
    /// failure mode: session-side hot-apply succeeds (advancing
    /// `managed.import_policy` AND `managed.export_policy`), the
    /// peer is Established, then the RIB step fails — `rib_tx.send`
    /// hits a closed channel, the reply oneshot is dropped, or the
    /// RIB returns Err. The prior code returned Err via `?` without
    /// re-arming `pending_refresh`, so a retry with the same target
    /// would see `import_changed = false` (bookkeeping advanced)
    /// and `had_pending_refresh = false`, compute `needs_refresh =
    /// false`, and silently never fire `soft_reset_in`. `AdjRibIn`
    /// routes accepted under the prior import policy would stay
    /// stuck against a session that now had the new policy — same
    /// silent-stale-routes class as the cross-side bail bug, just
    /// at a different downstream step.
    ///
    /// Fix: in the RIB-failure path, re-arm `pending_refresh` if
    /// `needs_refresh` was true, then return Err. This test pins
    /// it: a fake RIB drainer that replies Err to the
    /// `ReplacePeerExportPolicy` causes the call to return Err,
    /// but `pending_refresh` is set so the next call retries the
    /// refresh.
    #[allow(clippy::too_many_lines)]
    #[tokio::test]
    async fn rib_failure_preserves_pending_refresh_for_retry() {
        use rustbgpd_policy::{Policy, PolicyAction};
        use rustbgpd_transport::PeerCommand;
        use std::sync::Arc;
        use std::sync::atomic::{AtomicU32, Ordering};

        let (tx, mut rx) = mpsc::channel::<PeerCommand>(8);
        let route_refresh_calls = Arc::new(AtomicU32::new(0));
        let route_refresh_calls_in_task = route_refresh_calls.clone();
        let task_addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let task = tokio::spawn(async move {
            while let Some(cmd) = rx.recv().await {
                match cmd {
                    PeerCommand::UpdateImportPolicy { reply, .. }
                    | PeerCommand::UpdateExportPolicy { reply, .. } => {
                        let _ = reply.send(Ok(()));
                    }
                    PeerCommand::QueryState { reply } => {
                        let _ = reply.send(PeerSessionState {
                            fsm_state: SessionState::Established,
                            peer_ip: task_addr,
                            prefix_count: 0,
                            negotiated_hold_time: Some(90),
                            four_octet_as: Some(true),
                            remote_router_id: Some(Ipv4Addr::new(10, 0, 0, 2)),
                            updates_received: 0,
                            updates_sent: 0,
                            notifications_received: 0,
                            notifications_sent: 0,
                            flap_count: 0,
                            uptime_secs: 1,
                            last_error: String::new(),
                        });
                    }
                    PeerCommand::SendRouteRefresh { reply, .. } => {
                        route_refresh_calls_in_task.fetch_add(1, Ordering::SeqCst);
                        let _ = reply.send(Ok(()));
                    }
                    PeerCommand::Shutdown => break,
                    _ => {}
                }
            }
            Ok(())
        });
        let handle = PeerHandle::from_parts(tx, task);

        let (_cmd_tx, cmd_rx) = mpsc::channel(16);
        // RIB drainer that replies Err to ReplacePeerExportPolicy —
        // simulates the RIB rejecting the update. Other RibUpdate
        // variants get Ok so unrelated codepaths don't tangle.
        let (rib_tx, mut rib_rx) = mpsc::channel::<RibUpdate>(64);
        let rib_drainer = tokio::spawn(async move {
            while let Some(update) = rib_rx.recv().await {
                if let RibUpdate::ReplacePeerExportPolicy { reply, .. } = update {
                    let _ = reply.send(Err("simulated RIB failure".to_string()));
                }
            }
        });

        let metrics = BgpMetrics::new();
        let mut mgr = PeerManager::new(
            cmd_rx,
            65001,
            Ipv4Addr::new(10, 0, 0, 1),
            None,
            None,
            metrics,
            rib_tx,
            None,
        );
        let peer_config = make_config(task_addr, 65002);
        let transport = mgr.build_transport_config(&peer_config);
        let hold = transport.peer.hold_time;
        mgr.peers.insert(
            task_addr,
            ManagedPeer {
                handle,
                remote_asn: 65002,
                description: "test".to_string(),
                peer_group: None,
                enabled: true,
                hold_time: Some(hold),
                max_prefixes: None,
                transport_config: transport,
                import_policy: None,
                export_policy: None,
                pending_inbound: None,
                is_dynamic: false,
                pending_refresh: false,
                pending_export_apply: false,
                advertise_graceful_shutdown: false,
            },
        );

        let chain = PolicyChain::new(vec![Policy {
            entries: Vec::new(),
            default_action: PolicyAction::Deny,
        }]);

        // Both sides changed; both session-side applies succeed
        // (advancing bookkeeping); RIB step fails; before fix this
        // would return Err with no `pending_refresh` set, leaving
        // the next retry to silently skip Route Refresh.
        let result = mgr
            .update_runtime_policies(task_addr, Some(chain.clone()), Some(chain))
            .await;

        assert!(
            result.is_err(),
            "RIB failure must propagate as Err. Got: {result:?}"
        );
        let err_msg = result.unwrap_err();
        assert!(
            err_msg.contains("simulated RIB failure")
                || err_msg.contains("failed to update export policy"),
            "error message must surface the RIB failure for the operator: {err_msg}"
        );

        let managed = mgr.peers.get(&task_addr).expect("peer present");
        assert!(
            managed.pending_refresh,
            "pending_refresh MUST be set: bookkeeping already advanced (session-side \
             apply succeeded) so the next retry would see import_changed=false; \
             without pending_refresh the retry's needs_refresh would be false and \
             soft_reset_in would silently never fire, leaving AdjRibIn stuck on \
             the prior import policy."
        );
        assert!(
            managed.import_policy.is_some(),
            "managed.import_policy correctly advanced — session ACKed the new policy."
        );
        assert!(
            managed.export_policy.is_some(),
            "managed.export_policy correctly advanced — session ACKed the new policy."
        );
        assert_eq!(
            route_refresh_calls.load(Ordering::SeqCst),
            0,
            "Route Refresh must NOT have run — the RIB-failure bail returned Err \
             before reaching the soft_reset_in step."
        );

        drop(mgr);
        let _ = rib_drainer.await;
    }

    /// Stale-state-query regression: when
    /// `query_state_timeout` returns None — because the session task
    /// is back-pressured past the deadline and missed answering
    /// `QueryState` — `is_established` reads false even for a peer
    /// that is genuinely Established. With a fresh
    /// `import_changed = true`, the prior code (`else if
    /// had_pending_refresh && !is_established`) wouldn't re-arm
    /// `pending_refresh` because nothing was inherited; the function
    /// would advance bookkeeping, return Ok, and the next call would
    /// see `import_changed = false` and silently never fire refresh.
    /// `AdjRibIn` routes accepted under the prior import policy
    /// would stay stuck against a session that now had the new
    /// policy.
    ///
    /// Fix: re-arm `pending_refresh` whenever
    /// `needs_refresh && !is_established`, regardless of whether
    /// the intent was inherited or freshly generated. This subsumes
    /// the prior `had_pending_refresh && !is_established` branch and
    /// covers the stale-query case that's indistinguishable from
    /// genuine Idle from this side.
    ///
    /// The "wasted refresh on truly-Idle peer" cost is real but
    /// small (Route Refresh against an empty `AdjRibIn` is a no-op
    /// on the wire) and is the right tradeoff against silent
    /// stale-routes.
    #[allow(clippy::too_many_lines)]
    #[tokio::test]
    async fn stale_query_state_re_arms_pending_refresh() {
        use rustbgpd_policy::{Policy, PolicyAction};
        use rustbgpd_transport::PeerCommand;
        use std::sync::Arc;
        use std::sync::atomic::{AtomicU32, Ordering};

        let (tx, mut rx) = mpsc::channel::<PeerCommand>(8);
        let route_refresh_calls = Arc::new(AtomicU32::new(0));
        let route_refresh_calls_in_task = route_refresh_calls.clone();
        let task = tokio::spawn(async move {
            while let Some(cmd) = rx.recv().await {
                match cmd {
                    PeerCommand::UpdateImportPolicy { reply, .. }
                    | PeerCommand::UpdateExportPolicy { reply, .. } => {
                        let _ = reply.send(Ok(()));
                    }
                    PeerCommand::QueryState { reply } => {
                        // Drop the reply — caller observes None,
                        // simulating a back-pressured session that
                        // missed the deadline. From `update_runtime_policies`'s
                        // perspective this is indistinguishable from
                        // a genuinely Idle peer; the fix must re-arm
                        // pending_refresh regardless.
                        drop(reply);
                    }
                    PeerCommand::SendRouteRefresh { reply, .. } => {
                        route_refresh_calls_in_task.fetch_add(1, Ordering::SeqCst);
                        let _ = reply.send(Ok(()));
                    }
                    PeerCommand::Shutdown => break,
                    _ => {}
                }
            }
            Ok(())
        });
        let handle = PeerHandle::from_parts(tx, task);

        let (_cmd_tx, cmd_rx) = mpsc::channel(16);
        let (rib_tx, _rib_rx) = mpsc::channel::<RibUpdate>(64);
        let metrics = BgpMetrics::new();
        let mut mgr = PeerManager::new(
            cmd_rx,
            65001,
            Ipv4Addr::new(10, 0, 0, 1),
            None,
            None,
            metrics,
            rib_tx,
            None,
        );
        let task_addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let peer_config = make_config(task_addr, 65002);
        let transport = mgr.build_transport_config(&peer_config);
        let hold = transport.peer.hold_time;
        mgr.peers.insert(
            task_addr,
            ManagedPeer {
                handle,
                remote_asn: 65002,
                description: "test".to_string(),
                peer_group: None,
                enabled: true,
                hold_time: Some(hold),
                max_prefixes: None,
                transport_config: transport,
                import_policy: None,
                export_policy: None,
                pending_inbound: None,
                is_dynamic: false,
                pending_refresh: false,
                pending_export_apply: false,
                advertise_graceful_shutdown: false,
            },
        );

        let chain = PolicyChain::new(vec![Policy {
            entries: Vec::new(),
            default_action: PolicyAction::Deny,
        }]);

        // Fresh import_changed=true; both apply paths succeed; query
        // returns None (stale). Without the fix, this call returns
        // Ok and silently loses refresh intent.
        let result = mgr
            .update_runtime_policies(task_addr, Some(chain), None)
            .await;

        assert!(
            result.is_ok(),
            "Stale query state must NOT be treated as a failure — the call should \
             succeed (apply paths did) and just defer the refresh via pending_refresh. \
             Got: {result:?}"
        );

        let managed = mgr.peers.get(&task_addr).expect("peer present");
        assert!(
            managed.pending_refresh,
            "pending_refresh MUST be re-armed when query_state_timeout returned None \
             with a fresh import_changed=true. The prior code only re-armed when the \
             pending flag was *inherited*; a fresh refresh intent under a stale query \
             was silently lost. Without this re-arm, the retry would see \
             import_changed=false (bookkeeping advanced) and never fire refresh, \
             leaving AdjRibIn stuck on the prior import policy."
        );
        assert!(
            managed.import_policy.is_some(),
            "managed.import_policy correctly advanced — session ACKed the new policy. \
             The query was stale, but the apply itself succeeded."
        );
        assert_eq!(
            route_refresh_calls.load(Ordering::SeqCst),
            0,
            "Route Refresh must NOT have fired in this call — soft_reset_in is gated \
             on Established (via query_state_timeout result), and the query was stale. \
             The retry-on-next-call path is what fires refresh once the query unblocks."
        );
    }

    #[test]
    fn collision_local_wins() {
        // Local router-id 10.0.0.10 (higher) vs remote 10.0.0.2 (lower)
        // → local wins, inbound should be dropped
        let local_id = u32::from(Ipv4Addr::new(10, 0, 0, 10));
        let remote_id = u32::from(Ipv4Addr::new(10, 0, 0, 2));
        assert!(local_id > remote_id, "local should win collision");
    }

    #[test]
    fn collision_remote_wins() {
        // Local router-id 10.0.0.1 (lower) vs remote 10.0.0.10 (higher)
        // → remote wins, existing session should be dumped
        let local_id = u32::from(Ipv4Addr::new(10, 0, 0, 1));
        let remote_id = u32::from(Ipv4Addr::new(10, 0, 0, 10));
        assert!(local_id < remote_id, "remote should win collision");
    }

    #[tokio::test]
    async fn collision_existing_goes_idle_accepts_pending() {
        // Verify the PeerManager correctly handles notifications via its
        // select! loop (session_notify channel is wired).
        let (tx, rx) = mpsc::channel(16);
        let (rib_tx, _rib_rx) = mpsc::channel(64);
        let metrics = BgpMetrics::new();
        let mgr = PeerManager::new(
            rx,
            65001,
            Ipv4Addr::new(10, 0, 0, 1),
            None,
            None,
            metrics,
            rib_tx,
            None,
        );
        let handle = tokio::spawn(mgr.run());

        let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

        // Add peer
        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(PeerManagerCommand::AddPeer {
            config: make_config(addr, 65002),
            sync_config_snapshot: false,
            reply: reply_tx,
        })
        .await
        .unwrap();
        assert!(reply_rx.await.unwrap().is_ok());

        // Verify the peer exists
        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(PeerManagerCommand::GetPeerState {
            address: addr,
            reply: reply_tx,
        })
        .await
        .unwrap();
        let info = reply_rx.await.unwrap();
        assert!(info.is_some());

        tx.send(PeerManagerCommand::Shutdown).await.unwrap();
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn disable_peer_stays_disabled() {
        // Verify that disabling a peer keeps it disabled even after
        // the session goes idle (BackToIdle should not re-enable).
        let (tx, rx) = mpsc::channel(16);
        let (rib_tx, _rib_rx) = mpsc::channel(64);
        let metrics = BgpMetrics::new();
        let mgr = PeerManager::new(
            rx,
            65001,
            Ipv4Addr::new(10, 0, 0, 1),
            None,
            None,
            metrics,
            rib_tx,
            None,
        );
        let handle = tokio::spawn(mgr.run());

        let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

        // Add peer
        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(PeerManagerCommand::AddPeer {
            config: make_config(addr, 65002),
            sync_config_snapshot: false,
            reply: reply_tx,
        })
        .await
        .unwrap();
        assert!(reply_rx.await.unwrap().is_ok());

        // Disable peer
        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(PeerManagerCommand::DisablePeer {
            address: addr,
            reason: None,
            reply: reply_tx,
        })
        .await
        .unwrap();
        assert!(reply_rx.await.unwrap().is_ok());

        // Give time for the session to process Stop and go Idle
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Verify the peer is still disabled
        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(PeerManagerCommand::GetPeerState {
            address: addr,
            reply: reply_tx,
        })
        .await
        .unwrap();
        let info = reply_rx.await.unwrap().unwrap();
        assert!(!info.enabled, "peer should remain disabled");

        tx.send(PeerManagerCommand::Shutdown).await.unwrap();
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn inbound_during_established_dropped() {
        // Verify the handle_inbound match arm for Established works.
        let (tx, rx) = mpsc::channel(16);
        let (rib_tx, _rib_rx) = mpsc::channel(64);
        let metrics = BgpMetrics::new();
        let mgr = PeerManager::new(
            rx,
            65001,
            Ipv4Addr::new(10, 0, 0, 1),
            None,
            None,
            metrics,
            rib_tx,
            None,
        );
        let handle = tokio::spawn(mgr.run());

        let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

        // Add peer
        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(PeerManagerCommand::AddPeer {
            config: make_config(addr, 65002),
            sync_config_snapshot: false,
            reply: reply_tx,
        })
        .await
        .unwrap();
        assert!(reply_rx.await.unwrap().is_ok());

        tx.send(PeerManagerCommand::Shutdown).await.unwrap();
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn dynamic_inbound_peer_is_created_and_removed_on_back_to_idle() {
        let (_tx, rx) = mpsc::channel(16);
        let (rib_tx, _rib_rx) = mpsc::channel(64);
        let metrics = BgpMetrics::new();
        let mut mgr = PeerManager::new_with_config(
            rx,
            mpsc::unbounded_channel().1,
            65001,
            Ipv4Addr::new(10, 0, 0, 1),
            None,
            None,
            metrics,
            rib_tx,
            None,
            None,
            make_dynamic_manager_config(),
        );

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let listener_addr = listener.local_addr().unwrap();
        let client = tokio::spawn(async move { TcpStream::connect(listener_addr).await.unwrap() });
        let (server_stream, remote_addr) = listener.accept().await.unwrap();
        let client_stream = client.await.unwrap();
        let peer_addr = remote_addr.ip();

        mgr.handle_inbound(server_stream, peer_addr).await;

        assert_eq!(
            mgr.dynamic_peer_count, 1,
            "dynamic peer count should increment"
        );
        let info = mgr.get_peer_info(peer_addr).await.unwrap();
        assert!(info.is_dynamic, "peer should be marked dynamic");
        assert_eq!(info.peer_group.as_deref(), Some("ix-members"));
        assert_eq!(info.description, "ix-auto");

        let peers = mgr.list_peers().await;
        assert_eq!(peers.len(), 1);
        assert!(peers[0].is_dynamic);

        mgr.handle_session_notification(SessionNotification::BackToIdle { peer_addr })
            .await;

        assert_eq!(
            mgr.dynamic_peer_count, 0,
            "dynamic peer count should decrement"
        );
        assert!(
            mgr.get_peer_info(peer_addr).await.is_none(),
            "dynamic peer should be removed when it goes idle"
        );
        assert!(mgr.peers.is_empty(), "dynamic peer table should be empty");

        drop(client_stream);
    }

    #[tokio::test]
    async fn dead_lettered_pending_survives_dynamic_peer_auto_removal_and_re_establish() {
        let (_tx, rx) = mpsc::channel(16);
        let (rib_tx, _rib_rx) = mpsc::channel(64);
        let metrics = BgpMetrics::new();
        let mut mgr = PeerManager::new_with_config(
            rx,
            mpsc::unbounded_channel().1,
            65001,
            Ipv4Addr::new(10, 0, 0, 1),
            None,
            None,
            metrics,
            rib_tx,
            None,
            None,
            make_dynamic_manager_config(),
        );

        // First incarnation: accept the dynamic peer, then mark it as
        // carrying both unfired hot-apply flags. We set the flags
        // directly on the ManagedPeer rather than driving a path that
        // sets them — the regression covered here is the BackToIdle
        // → handle_inbound carry, not the flag-setting paths (which
        // are covered by `pending_refresh_re_arms_when_peer_still_not_established`).
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let listener_addr = listener.local_addr().unwrap();
        let client = tokio::spawn(async move { TcpStream::connect(listener_addr).await.unwrap() });
        let (server_stream, remote_addr) = listener.accept().await.unwrap();
        let client_stream = client.await.unwrap();
        let peer_addr = remote_addr.ip();

        mgr.handle_inbound(server_stream, peer_addr).await;
        assert_eq!(mgr.dynamic_peer_count, 1);

        let managed = mgr.peers.get_mut(&peer_addr).unwrap();
        managed.pending_refresh = true;
        managed.pending_export_apply = true;

        // Tear down — peer auto-removes, flags should land in the
        // dead-letter side table rather than evaporating.
        mgr.handle_session_notification(SessionNotification::BackToIdle { peer_addr })
            .await;
        assert_eq!(mgr.dynamic_peer_count, 0);
        assert!(mgr.peers.is_empty());
        let dead = mgr
            .dead_lettered_pending
            .get(&peer_addr)
            .copied()
            .expect("dead-lettered pending entry should exist after auto-removal");
        assert!(dead.refresh, "pending_refresh should be carried");
        assert!(dead.export_apply, "pending_export_apply should be carried");
        drop(client_stream);

        // Second incarnation at the same address: the new ManagedPeer
        // must inherit the dead-lettered flags, and the side-table
        // entry must drain.
        let next_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let next_listener_addr = next_listener.local_addr().unwrap();
        let next_client =
            tokio::spawn(async move { TcpStream::connect(next_listener_addr).await.unwrap() });
        let (server2, remote_addr2) = next_listener.accept().await.unwrap();
        let next_client_stream = next_client.await.unwrap();
        let peer_addr2 = remote_addr2.ip();
        // Both incarnations bind LOCALHOST so the IpAddr key (the unit
        // we dead-letter on) is identical even though the ephemeral
        // TCP port differs. Pin the precondition explicitly so any
        // future change that diverges the bind address gets caught.
        assert_eq!(
            peer_addr2, peer_addr,
            "test relies on both incarnations sharing an IpAddr key"
        );

        mgr.handle_inbound(server2, peer_addr2).await;

        let managed2 = mgr.peers.get(&peer_addr2).expect("re-established");
        assert!(
            managed2.pending_refresh,
            "new ManagedPeer must inherit pending_refresh from dead-letter table"
        );
        assert!(
            managed2.pending_export_apply,
            "new ManagedPeer must inherit pending_export_apply from dead-letter table"
        );
        assert!(
            !mgr.dead_lettered_pending.contains_key(&peer_addr2),
            "dead-letter entry must drain on restore"
        );
        drop(next_client_stream);
    }

    #[tokio::test]
    async fn dead_lettered_gshut_survives_dynamic_peer_auto_removal_and_re_establish() {
        let (_tx, rx) = mpsc::channel(16);
        let (rib_tx, _rib_rx) = mpsc::channel(64);
        let metrics = BgpMetrics::new();
        let mut mgr = PeerManager::new_with_config(
            rx,
            mpsc::unbounded_channel().1,
            65001,
            Ipv4Addr::new(10, 0, 0, 1),
            None,
            None,
            metrics,
            rib_tx,
            None,
            None,
            make_dynamic_manager_config(),
        );

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let listener_addr = listener.local_addr().unwrap();
        let client = tokio::spawn(async move { TcpStream::connect(listener_addr).await.unwrap() });
        let (server_stream, remote_addr) = listener.accept().await.unwrap();
        let client_stream = client.await.unwrap();
        let peer_addr = remote_addr.ip();

        mgr.handle_inbound(server_stream, peer_addr).await;
        assert_eq!(mgr.dynamic_peer_count, 1);
        mgr.peers
            .get_mut(&peer_addr)
            .expect("dynamic peer present")
            .advertise_graceful_shutdown = true;

        mgr.handle_session_notification(SessionNotification::BackToIdle { peer_addr })
            .await;
        assert!(mgr.peers.is_empty());
        let dead = mgr
            .dead_lettered_pending
            .get(&peer_addr)
            .copied()
            .expect("GShut-only dead-letter entry should be preserved");
        assert!(
            dead.graceful_shutdown,
            "GShut toggle should be carried even when no pending policy flags exist"
        );
        assert!(!dead.refresh);
        assert!(!dead.export_apply);
        drop(client_stream);

        let next_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let next_listener_addr = next_listener.local_addr().unwrap();
        let next_client =
            tokio::spawn(async move { TcpStream::connect(next_listener_addr).await.unwrap() });
        let (server2, remote_addr2) = next_listener.accept().await.unwrap();
        let next_client_stream = next_client.await.unwrap();
        let peer_addr2 = remote_addr2.ip();
        assert_eq!(
            peer_addr2, peer_addr,
            "test relies on both incarnations sharing an IpAddr key"
        );

        mgr.handle_inbound(server2, peer_addr2).await;

        let managed2 = mgr.peers.get(&peer_addr2).expect("re-established");
        assert!(
            managed2.advertise_graceful_shutdown,
            "new dynamic ManagedPeer must inherit advertise_graceful_shutdown"
        );
        assert!(
            !managed2.pending_refresh && !managed2.pending_export_apply,
            "GShut-only restore must not synthesize policy retry flags"
        );
        assert!(
            !mgr.dead_lettered_pending.contains_key(&peer_addr2),
            "dead-letter entry must drain on restore"
        );
        drop(next_client_stream);
    }

    #[test]
    fn build_transport_config_sets_restart_window_for_eligible_static_peer() {
        let (_tx, rx) = mpsc::channel(1);
        let (rib_tx, _rib_rx) = mpsc::channel(1);
        let mgr = PeerManager::new(
            rx,
            65001,
            Ipv4Addr::new(10, 0, 0, 1),
            None,
            Some(Instant::now() + Duration::from_secs(30)),
            BgpMetrics::new(),
            rib_tx,
            None,
        );
        let mut cfg = make_config(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 65002);
        cfg.gr_restart_eligible = true;

        let transport = mgr.build_transport_config(&cfg);
        assert!(transport.gr_restart_until.is_some());
    }

    #[test]
    fn build_transport_config_omits_restart_window_for_dynamic_peer() {
        let (_tx, rx) = mpsc::channel(1);
        let (rib_tx, _rib_rx) = mpsc::channel(1);
        let mgr = PeerManager::new(
            rx,
            65001,
            Ipv4Addr::new(10, 0, 0, 1),
            None,
            Some(Instant::now() + Duration::from_secs(30)),
            BgpMetrics::new(),
            rib_tx,
            None,
        );
        let cfg = make_config(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 65002);

        let transport = mgr.build_transport_config(&cfg);
        assert!(transport.gr_restart_until.is_none());
    }
}
