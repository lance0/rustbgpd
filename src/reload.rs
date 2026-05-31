//! SIGHUP reload and config-persistence bridge support.
//!
//! This module owns the runtime config reload pipeline that used to live in
//! `main.rs`: gRPC config-event persistence, restart-required field pinning,
//! and ordered peer-manager reconciliation.

use std::ops::Deref;

use rustbgpd_api::peer_types::{ConfigEvent, PeerManagerCommand, PeerManagerNeighborConfig};
use rustbgpd_policy::PolicyChain;
use tokio::sync::{mpsc, oneshot};
use tracing::{error, info, warn};

use crate::config::{self, Config};
use crate::config_persister::ConfigMutation;
use crate::fib_runtime::FibRuntimeCommand;
use crate::peer_manager::InternalCommand;
use crate::policy_admin::{self, apply_config_event};

/// Build a `PeerManagerNeighborConfig` from transport config components.
fn build_peer_mgr_config(
    tc: &rustbgpd_transport::TransportConfig,
    label: &str,
    import: Option<&PolicyChain>,
    export: Option<&PolicyChain>,
    peer_group: Option<String>,
) -> PeerManagerNeighborConfig {
    PeerManagerNeighborConfig {
        address: tc.remote_addr.ip(),
        interface: tc.peer_interface.clone(),
        scope_id: tc.peer_scope_id,
        remote_asn: tc.peer.remote_asn,
        description: label.to_string(),
        peer_group,
        hold_time: Some(tc.peer.hold_time),
        max_prefixes: tc.max_prefixes,
        md5_password: tc.md5_password.clone(),
        tcp_ao: tc.tcp_ao.clone(),
        ttl_security: tc.ttl_security,
        families: tc.peer.families.clone(),
        graceful_restart: tc.peer.graceful_restart,
        gr_restart_time: tc.peer.gr_restart_time,
        gr_stale_routes_time: tc.gr_stale_routes_time,
        llgr_stale_time: tc.llgr_stale_time,
        gr_restart_eligible: false,
        local_ipv6_nexthop: tc.local_ipv6_nexthop,
        route_reflector_client: tc.route_reflector_client,
        route_server_client: tc.route_server_client,
        remove_private_as: tc.remove_private_as,
        add_path_receive: tc.peer.add_path_receive,
        add_path_send: tc.peer.add_path_send,
        add_path_send_max: tc.peer.add_path_send_max,
        local_role: tc.peer.local_role,
        strict_role: tc.peer.strict_role,
        import_policy: import.cloned(),
        export_policy: export.cloned(),
    }
}

/// One reconcile-step failure during a SIGHUP reload, surfaced in
/// the structured failure log when the new config is rejected.
#[derive(Debug)]
struct ReloadStepFailure {
    /// Which delta bucket the command came from
    /// (e.g., `"policy.set"`, `"peer_group.delete"`).
    bucket: &'static str,
    /// Identifier of the affected object (policy / peer-group / set name,
    /// or neighbor address). Empty for global-chain operations.
    target: String,
    /// Human-readable failure reason.
    error: String,
}

#[derive(Clone)]
pub(crate) struct ReloadedConfig {
    runtime: Config,
    desired: Config,
}

impl ReloadedConfig {
    fn new(runtime: Config, desired: Config) -> Self {
        Self { runtime, desired }
    }
}

impl Deref for ReloadedConfig {
    type Target = Config;

    fn deref(&self) -> &Self::Target {
        &self.runtime
    }
}

/// Send a single `PeerManagerCommand` and await its `Result<(), String>`
/// reply. Maps both channel-send and dropped-reply errors to a single
/// `String` so callers can record one structured failure per step.
async fn send_pm_step(
    peer_mgr_tx: &mpsc::Sender<PeerManagerCommand>,
    build: impl FnOnce(oneshot::Sender<Result<(), String>>) -> PeerManagerCommand,
) -> Result<(), String> {
    let (reply_tx, reply_rx) = oneshot::channel();
    if let Err(e) = peer_mgr_tx.send(build(reply_tx)).await {
        return Err(format!("send to peer manager failed: {e}"));
    }
    match reply_rx.await {
        Ok(result) => result,
        Err(e) => Err(format!("peer manager dropped reply: {e}")),
    }
}

/// Bridge between gRPC config events, SIGHUP-driven snapshot
/// replacements, and the on-disk persister. The bridge owns the
/// authoritative pre-persist snapshot — both inputs route through
/// here so the snapshot, the persister, and downstream consumers
/// stay consistent.
///
/// Two inputs:
///   * `event_rx` — per-mutation events from the gRPC layer. Each
///     event is folded onto the bridge-held snapshot via
///     `apply_config_event`, then the full result is forwarded to
///     the persister as `ReplaceConfig`.
///   * `bridge_replace_rx` — SIGHUP-reloaded desired snapshots. The
///     bridge swaps its held snapshot and forwards a no-persist
///     refresh to the persister so future gRPC mutations apply on top
///     of the operator's edited TOML without writing a pinned runtime
///     snapshot back to disk.
///
/// Replacement is `biased` over events so a backlog of events
/// cannot delay reload visibility — without this, an operator who
/// SIGHUPs while gRPC is hammering policy mutations would see the
/// reload sit behind the queue and the next mutation would still
/// apply to the stale pre-reload base.
///
/// Persister send failure (`mutation_tx` closed or full past the
/// task's tolerance) terminates the bridge — the persister task is
/// dead, the daemon is shutting down, and there's nothing useful
/// left to do here.
pub(crate) async fn run_config_bridge(
    mut event_rx: mpsc::Receiver<rustbgpd_api::peer_types::ConfigEvent>,
    mut bridge_replace_rx: mpsc::UnboundedReceiver<Box<Config>>,
    mutation_tx: mpsc::Sender<ConfigMutation>,
    initial: Config,
) {
    let mut current_config = initial;
    let mut event_rx_open = true;
    let mut bridge_replace_rx_open = true;
    loop {
        if !event_rx_open && !bridge_replace_rx_open {
            break;
        }

        tokio::select! {
            biased;
            replace = bridge_replace_rx.recv(), if bridge_replace_rx_open => {
                match replace {
                    Some(new_snapshot) => {
                        current_config = *new_snapshot;
                        if mutation_tx
                            .send(ConfigMutation::RefreshSnapshotNoPersist(Box::new(
                                current_config.clone(),
                            )))
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                    None => bridge_replace_rx_open = false,
                }
            }
            event = event_rx.recv(), if event_rx_open => {
                match event {
                    Some(event) => {
                        if let Err(error) = apply_config_event(&mut current_config, &event) {
                            error!(error = %error, "failed to apply config event before persistence");
                            continue;
                        }
                        if mutation_tx
                            .send(ConfigMutation::ReplaceConfig(Box::new(current_config.clone())))
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                    None => event_rx_open = false,
                }
            }
        }
    }
}

/// Forward a freshly reloaded config to the peer manager and the
/// config bridge, in that order. Returns the runtime `Config` on success
/// so the caller can advance its in-memory snapshot in one step
/// (`config = apply_reload_outcome(...).await?;`).
///
/// Order matters. `peer_mgr_internal_tx` is unbounded and can only fail
/// on receiver-drop (peer manager task is dead — fatal anyway). The
/// bridge channel is also unbounded; it can only fail on receiver-drop
/// (bridge task is dead — same fatality class as a dead persister, since
/// the bridge owns the persister-facing channel). Sending the peer
/// manager first means the authoritative runtime view always advances
/// first.
///
/// The bridge — not a direct persister send — is the right
/// destination for the reloaded desired snapshot. `reload_config`
/// may pin restart-required fields back in the runtime snapshot, but
/// the bridge/persister must refresh their base from the operator's
/// edited TOML without writing the pinned runtime view back to disk.
/// Otherwise an edit-then-restart workflow gets destroyed by SIGHUP
/// and the next gRPC mutation applies to the wrong base.
///
/// Both `Err` returns name the failing stage (`peer_mgr_snapshot` or
/// `config_bridge`) so the caller's log line carries actionable
/// context. The "in-memory config not advanced" decision is the
/// caller's — leaving it explicit at the call site keeps the SIGHUP
/// retry semantics readable.
///
/// Async only because the SIGHUP-arm caller awaits in the same
/// position; both internal sends are unbounded and never block.
pub(crate) async fn apply_reload_outcome(
    reloaded: ReloadedConfig,
    peer_mgr_internal_tx: &mpsc::UnboundedSender<InternalCommand>,
    bridge_replace_tx: Option<&mpsc::UnboundedSender<Box<Config>>>,
) -> Result<Config, &'static str> {
    if peer_mgr_internal_tx
        .send(InternalCommand::ReplaceConfigSnapshot(Box::new(
            reloaded.runtime.clone(),
        )))
        .is_err()
    {
        return Err("peer_mgr_snapshot");
    }
    if let Some(tx) = bridge_replace_tx
        && tx.send(Box::new(reloaded.desired.clone())).is_err()
    {
        return Err("config_bridge");
    }
    Ok(reloaded.runtime)
}

/// Reload configuration from disk and reconcile runtime state.
///
/// Applies in dependency order:
/// 1. Add or change neighbor sets, named policies, peer groups, then
///    global chain references — additions and edits first so later
///    referrers resolve cleanly.
/// 2. Reconcile `[[neighbors]]` (existing path).
/// 3. Hot-apply implicit receiver-behavior knobs if they changed.
/// 4. Remove obsolete peer groups, named policies, and neighbor sets
///    in reverse-dependency order so a `still referenced` rejection
///    doesn't fire transiently.
///
/// Most `[global]` fields, `[rpki]`, `[bmp]`, `[mrt]`, and
/// `[global.telemetry.grpc_*]` sections still require a full restart;
/// this function logs them and pins the in-memory snapshot back to the
/// live listener state for the gRPC sections (so the next reload keeps
/// comparing against what the listener actually serves).
///
/// Inline `policy.import` / `policy.export` statements (the
/// non-named global-fallback statements) are detected and warned but
/// not applied — operators should migrate to named definitions plus
/// `import_chain` / `export_chain` for hot-reload support, or restart.
#[expect(
    clippy::too_many_lines,
    reason = "reload threads validation, three diff buckets, ordered reconcile steps, and failure aggregation through a single function"
)]
pub(crate) async fn reload_config(
    config_path: &str,
    current: &Config,
    live_grpc_tcp: Option<&config::GrpcTcpListenerConfig>,
    live_grpc_uds: Option<&config::GrpcUdsListenerConfig>,
    peer_mgr_tx: &mpsc::Sender<PeerManagerCommand>,
    fib_cmd_tx: Option<&mpsc::Sender<FibRuntimeCommand>>,
) -> Option<ReloadedConfig> {
    let desired_config = match Config::load_with_diagnostics(config_path) {
        Ok(c) => c,
        Err(diagnostic) => {
            error!("{diagnostic}");
            return None;
        }
    };
    let mut new_config = desired_config.clone();

    let honor_graceful_shutdown_changed =
        new_config.global.honor_graceful_shutdown != current.global.honor_graceful_shutdown;
    let mut honor_blackhole_changed =
        new_config.global.honor_blackhole != current.global.honor_blackhole;
    let blackhole_fib_reload_touches_spawn_gate =
        current.global.install_blackhole_discard || new_config.global.install_blackhole_discard;

    // Warn about sections that require restart. The implicit receiver
    // honor knobs are hot-applied below, so ignore them for this broad
    // restart warning.
    let mut restart_new_global = new_config.global.clone();
    let restart_current_global = current.global.clone();
    restart_new_global.honor_graceful_shutdown = restart_current_global.honor_graceful_shutdown;
    restart_new_global.honor_blackhole = restart_current_global.honor_blackhole;
    if restart_new_global != restart_current_global {
        warn!("[global] changed — requires full restart to take effect");
    }
    if new_config.rpki != current.rpki {
        warn!("[rpki] changed — requires full restart to take effect");
    }
    if new_config.bmp != current.bmp {
        warn!("[bmp] changed — requires full restart to take effect");
    }
    if new_config.mrt != current.mrt {
        warn!("[mrt] changed — requires full restart to take effect");
    }

    // Surface gRPC listener / TLS changes specifically and pin the
    // returned snapshot's listener fields back to what the live
    // listener is actually serving. Two reasons we don't just warn
    // and let the snapshot advance:
    //   1. Without pinning, a SIGHUP that only touches grpc_tcp
    //      moves the in-memory config to the new declared state.
    //      The next reload then compares against the already-
    //      updated snapshot and stops warning, even though the live
    //      listener is still on the prior security mode (cert
    //      rotation, plaintext-to-mTLS migration, etc.).
    //   2. Drift detection should remain observable across every
    //      reload until the daemon is actually restarted.
    if new_config.global.telemetry.grpc_tcp.as_ref() != live_grpc_tcp {
        error!(
            "[global.telemetry.grpc_tcp] differs from the live listener \
             (address / token / TLS): live listener is unchanged. \
             Restart rustbgpd to apply. Adding, removing, or rotating \
             tls_cert_file / tls_key_file / tls_client_ca_file does NOT \
             take effect on SIGHUP."
        );
        new_config.global.telemetry.grpc_tcp = live_grpc_tcp.cloned();
    }
    if new_config.global.telemetry.grpc_uds.as_ref() != live_grpc_uds {
        error!(
            "[global.telemetry.grpc_uds] differs from the live listener \
             (path / mode / token): live listener is unchanged. Restart \
             rustbgpd to apply."
        );
        new_config.global.telemetry.grpc_uds = live_grpc_uds.cloned();
    }

    // [[evpn_instances]] follows the gRPC-listener pinning pattern.
    // The Phase-2 foundation slice (ADR-0052) shares the resolved
    // `EvpnInstanceTable` to gRPC via an `Arc` built once at startup;
    // there is no swap surface yet, so a SIGHUP can't apply edits.
    // Without pinning, the in-memory `current` config would silently
    // advance to the new declaration on reload, the next reload would
    // see "no change", and drift would become invisible. Pin
    // new_config.evpn_instances back to current.evpn_instances so
    // (a) the gRPC `EvpnInstanceTable` stays consistent with the
    // returned snapshot and (b) drift detection remains observable
    // across every reload until the daemon is actually restarted.
    if new_config.evpn_instances != current.evpn_instances {
        error!(
            "[[evpn_instances]] differs from the live config: the \
             gRPC EvpnService is still serving the startup snapshot. \
             Restart rustbgpd to apply EVPN instance edits. Reload-time \
             mutation lands with the kernel-reconciliation slice (Gate 7b \
             — see docs/evpn-enablement.md)."
        );
        new_config
            .evpn_instances
            .clone_from(&current.evpn_instances);
    }
    if new_config.evpn_ip_vrfs != current.evpn_ip_vrfs {
        error!(
            "[[evpn_ip_vrfs]] differs from the live config: Gate 9 \
             IP-VRF/L3VNI state is resolved from the startup snapshot. \
             Restart rustbgpd to apply EVPN IP-VRF edits."
        );
        new_config.evpn_ip_vrfs.clone_from(&current.evpn_ip_vrfs);
    }
    if new_config.ethernet_segments != current.ethernet_segments {
        error!(
            "[[ethernet_segments]] differs from the live config: the \
             EVPN segment orchestrator resolved the startup snapshot. \
             Restart rustbgpd to apply Ethernet Segment edits."
        );
        new_config
            .ethernet_segments
            .clone_from(&current.ethernet_segments);
    }
    if new_config.apply_bum_enforcement != current.apply_bum_enforcement {
        error!(
            "apply_bum_enforcement differs from the live config: the \
             EVPN dataplane reconciler read this startup-only setting \
             when it was spawned. Restart rustbgpd to apply the Gate 8b \
             kernel-enforcement opt-in."
        );
        new_config.apply_bum_enforcement = current.apply_bum_enforcement;
    }
    // `[[fib_tables]]` is hot-applied to the running FIB reconciler below
    // (after the honor knobs), ack-gated on the actor accepting the new set —
    // see the FIB hot-apply step.
    if new_config.global.install_blackhole_discard != current.global.install_blackhole_discard
        || new_config.global.allow_blackhole_broad_prefixes
            != current.global.allow_blackhole_broad_prefixes
    {
        error!(
            "[global] BLACKHOLE FIB discard settings differ from the live config: \
             the RFC 7999 kernel-discard reconciler is spawned only at startup. \
             Restart rustbgpd to apply install_blackhole_discard or \
             allow_blackhole_broad_prefixes edits."
        );
        new_config.global.install_blackhole_discard = current.global.install_blackhole_discard;
        new_config.global.allow_blackhole_broad_prefixes =
            current.global.allow_blackhole_broad_prefixes;
    }
    if blackhole_fib_reload_touches_spawn_gate && honor_blackhole_changed {
        error!(
            "[global] honor_blackhole differs from the live config while \
             BLACKHOLE FIB discard is configured: the RFC 7999 \
             kernel-discard reconciler is spawned only at startup from \
             honor_blackhole && install_blackhole_discard. Restart \
             rustbgpd to apply this edit."
        );
        new_config.global.honor_blackhole = current.global.honor_blackhole;
        honor_blackhole_changed = false;
    }
    let tcp_ao_pinned_neighbors = config::pin_tcp_ao_startup_only_runtime(&mut new_config, current);
    if tcp_ao_pinned_neighbors > 0 {
        error!(
            neighbors = tcp_ao_pinned_neighbors,
            "[[neighbors]].tcp_ao differs from the live listener/session startup keys: \
             TCP-AO MKTs are installed only when sockets are created. Restart rustbgpd \
             to add, remove, or rotate TCP-AO keys. Peer-group and policy dependencies \
             referenced by pinned TCP-AO neighbors, plus restart-required global fields \
             that affect neighbor validation, are also kept at their live startup values \
             for this reload."
        );
    }

    if config::pin_bfd_startup_only_runtime(&mut new_config, current) {
        error!(
            "BFD config differs from the live session set: the ADR-0067 BFD actor \
             resolves [[bfd_profiles]] and neighbor/peer-group bfd once at startup. \
             Restart rustbgpd to add, remove, or retune BFD sessions. The profiles \
             and per-neighbor/peer-group bfd fields are kept at their live startup \
             values for this reload."
        );
    }

    let policy_diff = config::diff_policy(&current.policy, &new_config.policy);
    let peer_group_diff = config::diff_peer_groups(&current.peer_groups, &new_config.peer_groups);
    let diff = config::diff_neighbors(&current.neighbors, &new_config.neighbors);

    let neighbors_unchanged =
        diff.added.is_empty() && diff.removed.is_empty() && diff.changed.is_empty();
    let peer_groups_unchanged = peer_group_diff.added.is_empty()
        && peer_group_diff.removed.is_empty()
        && peer_group_diff.changed.is_empty();
    // ADR-0073: `[policy.explain]` (enabled / cache_size) is read when a
    // session is constructed (`build_transport_config`), so a reload of
    // those fields is restart-required per peer — the new snapshot is
    // adopted (new sessions honour it) but live sessions keep their
    // current behaviour until they re-establish. The diff machinery
    // tracks neighbors / policy chains / peer-groups, not this
    // diagnostic-retention knob, so detect it explicitly rather than
    // letting an explain-only reload report "no changes detected".
    let explain_changed = current.policy.explain != new_config.policy.explain;
    let fib_tables_changed = new_config.fib_tables != current.fib_tables;
    if !policy_diff.has_changes()
        && peer_groups_unchanged
        && neighbors_unchanged
        && !honor_graceful_shutdown_changed
        && !honor_blackhole_changed
        && !fib_tables_changed
    {
        if explain_changed {
            warn!(
                "config reloaded — only [policy.explain] changed; the new \
                 enabled/cache_size apply to sessions established after this reload \
                 (restart-required per peer). Existing sessions keep their current \
                 import-explain behaviour until they re-establish."
            );
        } else {
            info!("config reloaded — no neighbor / policy / peer-group changes detected");
        }
        return Some(ReloadedConfig::new(new_config, desired_config));
    }

    if explain_changed {
        warn!(
            "[policy.explain] changed — the new enabled/cache_size apply to sessions \
             established after this reload (restart-required per peer); existing \
             sessions are unaffected until they re-establish."
        );
    }

    if policy_diff.import_changed || policy_diff.export_changed {
        warn!(
            "[policy.import] / [policy.export] inline statements changed — these \
             are evaluated at session start and require a full restart to apply. \
             Migrate to named definitions plus import_chain/export_chain for \
             hot-reload support."
        );
    }

    // working_config is the honest snapshot of runtime state. We
    // start from `current` and apply each ConfigEvent locally as the
    // matching peer-manager command succeeds. On any failure we
    // halt and return Some(working_config) — the caller's in-memory
    // config then matches what's actually live on the peer manager,
    // instead of pretending the prior config is in effect when half
    // of it has already been mutated. Returning the partial state is
    // honest at the cost of leaving the operator with a half-applied
    // reload; they re-edit the failing TOML and reload again to
    // converge. Captured under "SIGHUP reconcile is not transactional"
    // in KNOWN_ISSUES — this fix moves the snapshot from "lying about
    // prior state" to "matching live state", which is the practical
    // step short of true rollback.
    let mut working_config = current.clone();

    // ADR-0073: `working_config` starts from `current` and only absorbs
    // the reconciled (hot-applied) ConfigEvents, none of which touch
    // `[policy.explain]`. So on a mixed reload — explain changed
    // alongside neighbor/policy/peer-group edits — the returned snapshot
    // would otherwise keep the *old* explain settings, contradicting the
    // restart-required-per-peer warning (new sessions read the snapshot
    // and must see the new values). Copy the new explain block in
    // explicitly. Safe: no ConfigEvent mutates `policy.explain`, and the
    // explain-only reload already returns `new_config` directly above.
    if explain_changed {
        working_config.policy.explain = new_config.policy.explain.clone();

        // Push the new explain snapshot to the peer manager *before* any
        // reconcile step below constructs a session. `build_transport_config`
        // reads `[policy.explain]` from the peer manager's `current_config`,
        // which is otherwise replaced only after this whole reload completes
        // (`apply_reload_outcome`). Without this, a peer re-added by a
        // neighbor reconcile or peer-group change in *this same* reload would
        // be built with the stale explain settings. Sent on the same FIFO
        // command channel and awaited, so it is applied before every
        // subsequent step. A send failure means the peer manager is gone —
        // halt with the honest partial snapshot like any other step.
        let (ack_tx, ack_rx) = oneshot::channel();
        if peer_mgr_tx
            .send(PeerManagerCommand::SyncExplainConfig {
                enabled: new_config.policy.explain.enabled,
                cache_size: new_config.policy.explain.cache_size,
                reply: ack_tx,
            })
            .await
            .is_err()
            || ack_rx.await.is_err()
        {
            return halt_partial(
                working_config,
                &desired_config,
                ReloadStepFailure {
                    bucket: "policy.explain.sync",
                    target: "[policy.explain]".to_string(),
                    error: "peer manager unavailable while syncing explain snapshot".to_string(),
                },
            );
        }
    }

    // 1. Neighbor sets (no upstream dependencies) — add and change.
    for name in policy_diff
        .neighbor_sets_added
        .iter()
        .chain(policy_diff.neighbor_sets_changed.iter())
    {
        let bucket = if policy_diff.neighbor_sets_added.contains(name) {
            "neighbor_set.add"
        } else {
            "neighbor_set.change"
        };
        // The diff said this neighbor_set is added/changed, so the
        // new config must contain it. A `None` here means the
        // diff and the config snapshot disagree — treat as halt.
        let Some(definition) = policy_admin::named_neighbor_set_from_config(&new_config, name)
        else {
            return halt_partial(
                working_config,
                &desired_config,
                ReloadStepFailure {
                    bucket,
                    target: name.clone(),
                    error: format!(
                        "internal: neighbor_set {name:?} present in diff but not resolvable from new config"
                    ),
                },
            );
        };
        let event = ConfigEvent::SetNeighborSet {
            name: name.clone(),
            definition: definition.clone(),
        };
        let cmd_name = name.clone();
        match send_pm_step(peer_mgr_tx, |reply| PeerManagerCommand::SetNeighborSet {
            name: cmd_name,
            definition,
            reply,
        })
        .await
        {
            Ok(()) => {
                if let Err(error) = apply_config_event(&mut working_config, &event) {
                    return halt_partial(
                        working_config,
                        &desired_config,
                        ReloadStepFailure {
                            bucket,
                            target: name.clone(),
                            error: format!(
                                "applied at peer manager but local snapshot rejected the event: {error}"
                            ),
                        },
                    );
                }
                info!(name = %name, %bucket, "reload: neighbor_set applied");
            }
            Err(error) => {
                return halt_partial(
                    working_config,
                    &desired_config,
                    ReloadStepFailure {
                        bucket,
                        target: name.clone(),
                        error,
                    },
                );
            }
        }
    }

    // 2. Named policy definitions (may reference neighbor_sets).
    for name in policy_diff
        .definitions_added
        .iter()
        .chain(policy_diff.definitions_changed.iter())
    {
        let bucket = if policy_diff.definitions_added.contains(name) {
            "policy.add"
        } else {
            "policy.change"
        };
        let Some(definition) = policy_admin::named_policy_from_config(&new_config, name) else {
            return halt_partial(
                working_config,
                &desired_config,
                ReloadStepFailure {
                    bucket,
                    target: name.clone(),
                    error: format!(
                        "internal: policy {name:?} present in diff but not resolvable from new config"
                    ),
                },
            );
        };
        let event = ConfigEvent::SetPolicy {
            name: name.clone(),
            definition: definition.clone(),
        };
        let cmd_name = name.clone();
        match send_pm_step(peer_mgr_tx, |reply| PeerManagerCommand::SetPolicy {
            name: cmd_name,
            definition,
            reply,
        })
        .await
        {
            Ok(()) => {
                if let Err(error) = apply_config_event(&mut working_config, &event) {
                    return halt_partial(
                        working_config,
                        &desired_config,
                        ReloadStepFailure {
                            bucket,
                            target: name.clone(),
                            error: format!(
                                "applied at peer manager but local snapshot rejected the event: {error}"
                            ),
                        },
                    );
                }
                info!(name = %name, %bucket, "reload: policy applied");
            }
            Err(error) => {
                return halt_partial(
                    working_config,
                    &desired_config,
                    ReloadStepFailure {
                        bucket,
                        target: name.clone(),
                        error,
                    },
                );
            }
        }
    }

    // 3. Peer groups (may reference policies).
    for name in peer_group_diff
        .added
        .iter()
        .chain(peer_group_diff.changed.iter())
    {
        let bucket = if peer_group_diff.added.contains(name) {
            "peer_group.add"
        } else {
            "peer_group.change"
        };
        let Some(definition) = policy_admin::named_peer_group_from_config(&new_config, name) else {
            return halt_partial(
                working_config,
                &desired_config,
                ReloadStepFailure {
                    bucket,
                    target: name.clone(),
                    error: format!(
                        "internal: peer_group {name:?} present in diff but not resolvable from new config"
                    ),
                },
            );
        };
        let event = ConfigEvent::SetPeerGroup {
            name: name.clone(),
            definition: definition.clone(),
        };
        let cmd_name = name.clone();
        match send_pm_step(peer_mgr_tx, |reply| PeerManagerCommand::SetPeerGroup {
            name: cmd_name,
            definition,
            reply,
        })
        .await
        {
            Ok(()) => {
                if let Err(error) = apply_config_event(&mut working_config, &event) {
                    return halt_partial(
                        working_config,
                        &desired_config,
                        ReloadStepFailure {
                            bucket,
                            target: name.clone(),
                            error: format!(
                                "applied at peer manager but local snapshot rejected the event: {error}"
                            ),
                        },
                    );
                }
                info!(name = %name, %bucket, "reload: peer_group applied");
            }
            Err(error) => {
                return halt_partial(
                    working_config,
                    &desired_config,
                    ReloadStepFailure {
                        bucket,
                        target: name.clone(),
                        error,
                    },
                );
            }
        }
    }

    // 4. Global named chains (reference named policies — must come
    //    after any new definitions are registered).
    if policy_diff.import_chain_changed {
        let chain = new_config.policy.import_chain.clone();
        let event = if chain.is_empty() {
            ConfigEvent::ClearGlobalImportChain
        } else {
            ConfigEvent::SetGlobalImportChain {
                policy_names: chain.clone(),
            }
        };
        let res = if chain.is_empty() {
            send_pm_step(peer_mgr_tx, |reply| {
                PeerManagerCommand::ClearGlobalImportChain { reply }
            })
            .await
        } else {
            send_pm_step(peer_mgr_tx, |reply| {
                PeerManagerCommand::SetGlobalImportChain {
                    policy_names: chain,
                    reply,
                }
            })
            .await
        };
        match res {
            Ok(()) => {
                if let Err(error) = apply_config_event(&mut working_config, &event) {
                    return halt_partial(
                        working_config,
                        &desired_config,
                        ReloadStepFailure {
                            bucket: "global_chain.import",
                            target: String::new(),
                            error: format!(
                                "applied at peer manager but local snapshot rejected the event: {error}"
                            ),
                        },
                    );
                }
                info!("reload: global import_chain applied");
            }
            Err(error) => {
                return halt_partial(
                    working_config,
                    &desired_config,
                    ReloadStepFailure {
                        bucket: "global_chain.import",
                        target: String::new(),
                        error,
                    },
                );
            }
        }
    }
    if policy_diff.export_chain_changed {
        let chain = new_config.policy.export_chain.clone();
        let event = if chain.is_empty() {
            ConfigEvent::ClearGlobalExportChain
        } else {
            ConfigEvent::SetGlobalExportChain {
                policy_names: chain.clone(),
            }
        };
        let res = if chain.is_empty() {
            send_pm_step(peer_mgr_tx, |reply| {
                PeerManagerCommand::ClearGlobalExportChain { reply }
            })
            .await
        } else {
            send_pm_step(peer_mgr_tx, |reply| {
                PeerManagerCommand::SetGlobalExportChain {
                    policy_names: chain,
                    reply,
                }
            })
            .await
        };
        match res {
            Ok(()) => {
                if let Err(error) = apply_config_event(&mut working_config, &event) {
                    return halt_partial(
                        working_config,
                        &desired_config,
                        ReloadStepFailure {
                            bucket: "global_chain.export",
                            target: String::new(),
                            error: format!(
                                "applied at peer manager but local snapshot rejected the event: {error}"
                            ),
                        },
                    );
                }
                info!("reload: global export_chain applied");
            }
            Err(error) => {
                return halt_partial(
                    working_config,
                    &desired_config,
                    ReloadStepFailure {
                        bucket: "global_chain.export",
                        target: String::new(),
                        error,
                    },
                );
            }
        }
    }

    // 5. Neighbor reconciliation. Only fires when the neighbor list
    //    itself moved; steps 1–4 already reshaped runtime state for
    //    inheritance-driven impact on existing neighbors.
    if !neighbors_unchanged {
        info!(
            added = diff.added.len(),
            removed = diff.removed.len(),
            changed = diff.changed.len(),
            "reconciling neighbors after config reload"
        );
        for n in &diff.added {
            info!(address = %n.address, asn = n.remote_asn, "neighbor added");
        }
        for addr in &diff.removed {
            info!(address = %addr, "neighbor removed");
        }
        let old_map: std::collections::HashMap<&str, &config::Neighbor> = current
            .neighbors
            .iter()
            .map(|n| (n.address.as_str(), n))
            .collect();
        for n in &diff.changed {
            if let Some(old_n) = old_map.get(n.address.as_str()) {
                let changes = config::describe_neighbor_changes(old_n, n);
                info!(
                    address = %n.address,
                    changes = %changes.join(", "),
                    "neighbor changed"
                );
            }
        }

        let peer_configs = match new_config.resolved_neighbors() {
            Ok(p) => p,
            Err(e) => {
                return halt_partial(
                    working_config,
                    &desired_config,
                    ReloadStepFailure {
                        bucket: "neighbors.resolve",
                        target: "new_config.resolved_neighbors".to_string(),
                        error: e.to_string(),
                    },
                );
            }
        };
        let peer_map: std::collections::HashMap<(String, Option<String>), _> = peer_configs
            .into_iter()
            .map(|neighbor| {
                (
                    (
                        neighbor.transport_config.remote_addr.ip().to_string(),
                        neighbor.transport_config.peer_interface.clone(),
                    ),
                    neighbor,
                )
            })
            .collect();
        let resolve = |neighbors: &[config::Neighbor]| -> Vec<PeerManagerNeighborConfig> {
            neighbors
                .iter()
                .filter_map(|n| {
                    peer_map
                        .get(&(n.address.clone(), n.interface.clone()))
                        .map(|neighbor| {
                            build_peer_mgr_config(
                                &neighbor.transport_config,
                                &neighbor.label,
                                neighbor.import_policy.as_ref(),
                                neighbor.export_policy.as_ref(),
                                neighbor.peer_group.clone(),
                            )
                        })
                })
                .collect()
        };

        let (reply_tx, reply_rx) = oneshot::channel();
        if let Err(e) = peer_mgr_tx
            .send(PeerManagerCommand::ReconcilePeers {
                added: resolve(&diff.added),
                removed: diff.removed.clone(),
                changed: resolve(&diff.changed),
                reply: reply_tx,
            })
            .await
        {
            return halt_partial(
                working_config,
                &desired_config,
                ReloadStepFailure {
                    bucket: "neighbors.reconcile",
                    target: String::new(),
                    error: format!("send: {e}"),
                },
            );
        }
        match reply_rx.await {
            Ok(reconcile) if reconcile.is_success() => {
                working_config.neighbors = new_config.neighbors.clone();
            }
            Ok(reconcile) => {
                // Reconcile is the one step where partial failure
                // leaves the live state genuinely ambiguous: it
                // sequences delete-then-readd for changed peers,
                // independent removes, and adds — any subset can
                // succeed before the failure point, the manager
                // doesn't update its own `current_config` during the
                // run, and `delete_peer` / `add_peer` of the wrong
                // ordering can leave orphaned `PeerHandle`s. Returning
                // a guessed snapshot here would let the next reload
                // diff against state that doesn't match live, which is
                // worse than just bailing.
                //
                // Instead: return `None` so the daemon's in-memory
                // config stays at `current` and log clearly that live
                // state may differ. Operators investigate via
                // `rustbgpctl neighbor list`, fix the failing TOML,
                // and reload again. The retry-succeeded-operations
                // concern is bounded by the underlying ops being
                // mostly idempotent (`delete_peer` of a missing peer
                // returns Ok, `add_peer` of an existing peer returns
                // a visible error rather than silent corruption); the
                // operator gets surfaced errors on the retry rather
                // than hidden drift.
                for failure in &reconcile.failures {
                    warn!(
                        bucket = "neighbors.reconcile",
                        target = %failure.peer,
                        kind = ?failure.kind,
                        error = %failure.error,
                        "config reload step failed"
                    );
                }
                error!(
                    failures = reconcile.failures.len(),
                    "config reload halted at neighbor reconcile — live peer-manager state \
                     may differ from the in-memory config snapshot. Inspect live state via \
                     `rustbgpctl neighbor list` and re-edit the failing TOML before \
                     reloading again. Earlier reload steps (policy / peer-group / chain \
                     edits) DID land at the manager and remain in effect."
                );
                return None;
            }
            Err(e) => {
                error!(
                    error = %e,
                    "config reload halted: peer manager dropped reconcile reply — live \
                     state may differ from the in-memory config snapshot. Inspect via \
                     `rustbgpctl neighbor list` before reloading again. Earlier reload \
                     steps (policy / peer-group / chain edits) DID land at the manager \
                     and remain in effect."
                );
                return None;
            }
        }
    }

    // 6. Hot-apply implicit receiver behavior. This must run after
    //    policy/peer-group/global-chain edits and neighbor reconcile
    //    so the peer manager recomputes effective chains from the
    //    same live snapshot the rest of this reload has just shaped.
    if honor_graceful_shutdown_changed {
        let enabled = new_config.global.honor_graceful_shutdown;
        match send_pm_step(peer_mgr_tx, |reply| {
            PeerManagerCommand::SetHonorGracefulShutdown { enabled, reply }
        })
        .await
        {
            Ok(()) => {
                working_config.global.honor_graceful_shutdown = enabled;
                info!(
                    enabled,
                    "reload: [global] honor_graceful_shutdown hot-applied"
                );
            }
            Err(error) => {
                // `set_honor_graceful_shutdown` is intentionally best-
                // effort: on the peer-manager side it advances its own
                // `current_config` *unconditionally* and applies to as
                // many EBGP peers as it can, returning Err only to
                // surface which peers failed. Halting the reload here
                // would roll the daemon's `working_config` back to the
                // old value while the peer manager's snapshot stays
                // advanced — the same hard-to-debug drift the
                // best-effort design exists to avoid. Mirror the
                // peer-manager's snapshot advance in the daemon view,
                // and surface the failure list as a warn rather than
                // a halt. Failed peers retry on their next
                // `update_runtime_policies` call via the existing
                // bail-and-carry plumbing (`pending_refresh` /
                // `pending_export_apply`).
                warn!(
                    enabled,
                    error,
                    "reload: [global] honor_graceful_shutdown partial-apply — snapshot \
                     advanced anyway; bail-and-carry will retry failed peers on next \
                     policy edit"
                );
                working_config.global.honor_graceful_shutdown = enabled;
            }
        }
    }
    if honor_blackhole_changed {
        let enabled = new_config.global.honor_blackhole;
        match send_pm_step(peer_mgr_tx, |reply| PeerManagerCommand::SetHonorBlackhole {
            enabled,
            reply,
        })
        .await
        {
            Ok(()) => {
                working_config.global.honor_blackhole = enabled;
                info!(enabled, "reload: [global] honor_blackhole hot-applied");
            }
            Err(error) => {
                warn!(
                    enabled,
                    error,
                    "reload: [global] honor_blackhole partial-apply — snapshot \
                     advanced anyway; bail-and-carry will retry failed peers on next \
                     policy edit"
                );
                working_config.global.honor_blackhole = enabled;
            }
        }
    }

    // 6b. [[fib_tables]] hot-apply. Unlike the honor knobs above, FIB programs
    //     kernel state, so the snapshot advances ONLY after the actor
    //     acknowledges the new desired set — no best-effort advance on failure.
    if new_config.fib_tables != current.fib_tables {
        match fib_cmd_tx {
            Some(tx) => {
                let (reply_tx, reply_rx) = oneshot::channel();
                match tx
                    .send(FibRuntimeCommand::ReplaceTables {
                        tables: new_config.fib_tables.clone(),
                        reply: reply_tx,
                    })
                    .await
                {
                    Ok(()) => match reply_rx.await {
                        Ok(Ok(())) => {
                            working_config.fib_tables.clone_from(&new_config.fib_tables);
                            info!(
                                tables = new_config.fib_tables.len(),
                                "reload: [[fib_tables]] hot-applied"
                            );
                        }
                        Ok(Err(reason)) => {
                            error!(
                                %reason,
                                "reload: FIB runtime could not apply the [[fib_tables]] update \
                                 (reverted); runtime unchanged"
                            );
                        }
                        Err(error) => {
                            error!(
                                %error,
                                "reload: FIB runtime did not acknowledge the [[fib_tables]] \
                                 update; reverting (runtime unchanged)"
                            );
                        }
                    },
                    Err(error) => {
                        error!(
                            %error,
                            "reload: FIB runtime command channel closed; [[fib_tables]] not \
                             applied, reverting (runtime unchanged)"
                        );
                    }
                }
            }
            None if current.fib_tables.is_empty() => {
                error!(
                    "[[fib_tables]] added from an empty config: the FIB reconciler is not \
                     running (it is spawned only when at least one table is present at \
                     startup). Restart rustbgpd to start the FIB runtime."
                );
            }
            None => {
                error!(
                    "[[fib_tables]] differs but the FIB runtime is unavailable (it did not \
                     spawn at startup — non-Linux platform or netlink setup failure). \
                     Restart rustbgpd to apply [[fib_tables]] edits."
                );
            }
        }
    }

    // 7. Removals in reverse-dependency order so `still referenced`
    //    rejections don't fire transiently. Peer-group deletes have
    //    to happen after neighbor reconcile if any obsolete neighbors
    //    were members; same for policy / neighbor-set deletes vs
    //    peer-group deletes.
    for name in &peer_group_diff.removed {
        let event = ConfigEvent::DeletePeerGroup { name: name.clone() };
        let cmd_name = name.clone();
        match send_pm_step(peer_mgr_tx, |reply| PeerManagerCommand::DeletePeerGroup {
            name: cmd_name,
            reply,
        })
        .await
        {
            Ok(()) => {
                if let Err(error) = apply_config_event(&mut working_config, &event) {
                    return halt_partial(
                        working_config,
                        &desired_config,
                        ReloadStepFailure {
                            bucket: "peer_group.delete",
                            target: name.clone(),
                            error: format!(
                                "applied at peer manager but local snapshot rejected the event: {error}"
                            ),
                        },
                    );
                }
                info!(name = %name, "reload: peer_group removed");
            }
            Err(error) => {
                return halt_partial(
                    working_config,
                    &desired_config,
                    ReloadStepFailure {
                        bucket: "peer_group.delete",
                        target: name.clone(),
                        error,
                    },
                );
            }
        }
    }
    for name in &policy_diff.definitions_removed {
        let event = ConfigEvent::DeletePolicy { name: name.clone() };
        let cmd_name = name.clone();
        match send_pm_step(peer_mgr_tx, |reply| PeerManagerCommand::DeletePolicy {
            name: cmd_name,
            reply,
        })
        .await
        {
            Ok(()) => {
                if let Err(error) = apply_config_event(&mut working_config, &event) {
                    return halt_partial(
                        working_config,
                        &desired_config,
                        ReloadStepFailure {
                            bucket: "policy.delete",
                            target: name.clone(),
                            error: format!(
                                "applied at peer manager but local snapshot rejected the event: {error}"
                            ),
                        },
                    );
                }
                info!(name = %name, "reload: policy removed");
            }
            Err(error) => {
                return halt_partial(
                    working_config,
                    &desired_config,
                    ReloadStepFailure {
                        bucket: "policy.delete",
                        target: name.clone(),
                        error,
                    },
                );
            }
        }
    }
    for name in &policy_diff.neighbor_sets_removed {
        let event = ConfigEvent::DeleteNeighborSet { name: name.clone() };
        let cmd_name = name.clone();
        match send_pm_step(peer_mgr_tx, |reply| PeerManagerCommand::DeleteNeighborSet {
            name: cmd_name,
            reply,
        })
        .await
        {
            Ok(()) => {
                if let Err(error) = apply_config_event(&mut working_config, &event) {
                    return halt_partial(
                        working_config,
                        &desired_config,
                        ReloadStepFailure {
                            bucket: "neighbor_set.delete",
                            target: name.clone(),
                            error: format!(
                                "applied at peer manager but local snapshot rejected the event: {error}"
                            ),
                        },
                    );
                }
                info!(name = %name, "reload: neighbor_set removed");
            }
            Err(error) => {
                return halt_partial(
                    working_config,
                    &desired_config,
                    ReloadStepFailure {
                        bucket: "neighbor_set.delete",
                        target: name.clone(),
                        error,
                    },
                );
            }
        }
    }

    // Route Refresh for peers whose import policy moved fires
    // automatically inside `PeerManager::update_runtime_policies`
    // for any peer (static or dynamic) on policy / peer-group /
    // chain edits — the SetPolicy / SetPeerGroup / chain commands
    // above land at `apply_policy_change`, which calls
    // `update_runtime_policies` per affected peer, which now issues
    // `soft_reset_in` when the import policy materially changed.
    // That covers gRPC mutations and SIGHUP with one mechanism, and
    // reaches dynamic peers (which live only in the manager's
    // runtime table, not in `[[neighbors]]`). A soft-reset failure
    // there bubbles up through the SetPolicy / etc command result
    // handled above, halting this reload via `halt_partial` so the
    // failure is surfaced rather than logged-and-forgotten.

    info!("config reload complete");
    Some(ReloadedConfig::new(working_config, desired_config))
}

/// Halt a SIGHUP reload at the first failed step. Logs the failure
/// at error level and returns the partially-applied config snapshot
/// so the caller's in-memory config tracks live runtime state
/// instead of lying that the prior config is still in effect. The
/// daemon converges by the operator fixing the failing TOML and
/// reloading again — at that point the diff runs against the
/// half-applied state and only the remaining steps fire.
///
/// Returned wrapped in `Option<ReloadedConfig>` so the call sites can use
/// `return halt_partial(...)` directly inside `reload_config`,
/// matching its `Option<ReloadedConfig>` return shape.
#[expect(
    clippy::needless_pass_by_value,
    clippy::unnecessary_wraps,
    reason = "owned ReloadStepFailure simplifies call sites that build the value inline; Option<ReloadedConfig> return matches reload_config's signature so call sites can `return halt_partial(...)` directly"
)]
fn halt_partial(
    working_config: Config,
    desired_config: &Config,
    failure: ReloadStepFailure,
) -> Option<ReloadedConfig> {
    error!(
        bucket = failure.bucket,
        target = %failure.target,
        error = %failure.error,
        "config reload halted at this step — runtime state matches the in-memory snapshot returned by reload (partial). Re-edit TOML and reload again to converge."
    );
    Some(ReloadedConfig::new(working_config, desired_config.clone()))
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;
    use crate::config_persister::ConfigPersister;

    fn unique_temp_path(name: &str) -> PathBuf {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("rustbgpd-{name}-{suffix}.toml"))
    }

    /// SIGHUP that adds mTLS to `grpc_tcp` must NOT advance the
    /// in-memory config's `grpc_tcp` field — the live listener is
    /// still serving the prior config (no listener rebind on
    /// reload), so the runtime snapshot has to keep pointing at the
    /// live state. Without this, future reloads compare against the
    /// already-mutated snapshot and the drift error stops firing.
    #[tokio::test]
    async fn reload_pins_grpc_tcp_to_live_listener_snapshot() {
        let path = unique_temp_path("reload-grpc-tcp-pin");

        // Initial config: grpc_tcp present but plaintext (no TLS).
        std::fs::write(
            &path,
            r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
log_format = "json"

[global.telemetry.grpc_tcp]
address = "0.0.0.0:50051"

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
hold_time = 90
"#,
        )
        .unwrap();

        let initial = Config::load_with_diagnostics(path.to_str().unwrap()).unwrap();
        let live_grpc_tcp = initial.global.telemetry.grpc_tcp.clone();
        let live_grpc_uds = initial.global.telemetry.grpc_uds.clone();
        assert!(
            live_grpc_tcp
                .as_ref()
                .is_some_and(|cfg| cfg.tls_cert_file.is_none()),
            "initial listener must be plaintext"
        );

        // Operator overwrites the file with an mTLS-enabled config.
        // Validation now reads PEM material at config load, so the
        // paths must point at real PEM-shaped files.
        let cert = unique_temp_path("reload-pin-cert.pem");
        let key = unique_temp_path("reload-pin-key.pem");
        let ca = unique_temp_path("reload-pin-ca.pem");
        std::fs::write(
            &cert,
            "-----BEGIN CERTIFICATE-----\nMIIBstub\n-----END CERTIFICATE-----\n",
        )
        .unwrap();
        std::fs::write(
            &key,
            "-----BEGIN PRIVATE KEY-----\nMIIBstub\n-----END PRIVATE KEY-----\n",
        )
        .unwrap();
        std::fs::write(
            &ca,
            "-----BEGIN CERTIFICATE-----\nMIIBstub\n-----END CERTIFICATE-----\n",
        )
        .unwrap();
        let mtls_toml = format!(
            r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
log_format = "json"

[global.telemetry.grpc_tcp]
address = "0.0.0.0:50051"
tls_cert_file = {cert:?}
tls_key_file = {key:?}
tls_client_ca_file = {ca:?}

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
hold_time = 90
"#,
            cert = cert.to_str().unwrap(),
            key = key.to_str().unwrap(),
            ca = ca.to_str().unwrap(),
        );
        std::fs::write(&path, mtls_toml).unwrap();

        let (peer_mgr_tx, _peer_mgr_rx) = mpsc::channel(8);
        let returned = reload_config(
            path.to_str().unwrap(),
            &initial,
            live_grpc_tcp.as_ref(),
            live_grpc_uds.as_ref(),
            &peer_mgr_tx,
            None,
        )
        .await
        .expect("reload should return a config even when grpc_tcp drifts");

        // The returned config's grpc_tcp MUST equal the live listener
        // snapshot, NOT the new declared mTLS config. Otherwise a
        // second reload would compare new declared vs already-updated
        // snapshot and stop warning.
        assert_eq!(
            returned.global.telemetry.grpc_tcp, live_grpc_tcp,
            "reload must pin grpc_tcp to the live listener snapshot until the daemon restarts"
        );
        assert!(
            returned
                .global
                .telemetry
                .grpc_tcp
                .as_ref()
                .is_some_and(|cfg| cfg.tls_cert_file.is_none()),
            "returned grpc_tcp must NOT carry the newly declared TLS material"
        );

        std::fs::remove_file(&path).ok();
        std::fs::remove_file(&cert).ok();
        std::fs::remove_file(&key).ok();
        std::fs::remove_file(&ca).ok();
    }

    /// SIGHUP that edits `[[evpn_instances]]` must NOT advance the
    /// in-memory config's `evpn_instances` field — the gRPC
    /// `EvpnService` is still serving the startup `Arc<EvpnInstanceTable>`
    /// (no swap surface yet, ADR-0052). Without pinning, the next
    /// reload would compare against the already-mutated snapshot and
    /// the drift error would silently stop firing — operators would
    /// believe their edits had taken effect when in fact the gRPC
    /// surface is still on the prior instance set.
    #[tokio::test]
    async fn reload_pins_evpn_instances_to_startup_snapshot() {
        let path = unique_temp_path("reload-evpn-pin");

        // Initial config: one EVPN instance.
        std::fs::write(
            &path,
            r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
log_format = "json"

[[evpn_instances]]
vni = 100
rd = "65000:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.1"
"#,
        )
        .unwrap();

        let initial = Config::load_with_diagnostics(path.to_str().unwrap()).unwrap();
        let live_grpc_tcp = initial.global.telemetry.grpc_tcp.clone();
        let live_grpc_uds = initial.global.telemetry.grpc_uds.clone();
        assert_eq!(initial.evpn_instances.len(), 1);
        assert_eq!(initial.evpn_instances[0].vni, 100);

        // Operator rewrites the file: VNI changes, RTs expand, a new
        // instance appears. None of this can take effect on a SIGHUP
        // in the foundation slice, but the reload path must surface
        // the drift and pin the snapshot.
        std::fs::write(
            &path,
            r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
log_format = "json"

[[evpn_instances]]
vni = 100
rd = "65000:100"
route_targets = ["65000:100", "65000:200"]
local_vtep_ip = "10.0.0.1"

[[evpn_instances]]
vni = 200
rd = "65000:200"
route_targets = ["65000:200"]
local_vtep_ip = "10.0.0.1"
"#,
        )
        .unwrap();

        let (peer_mgr_tx, _peer_mgr_rx) = mpsc::channel(8);
        let returned = reload_config(
            path.to_str().unwrap(),
            &initial,
            live_grpc_tcp.as_ref(),
            live_grpc_uds.as_ref(),
            &peer_mgr_tx,
            None,
        )
        .await
        .expect("reload should return a config even when only evpn_instances drift");

        // The returned config's evpn_instances MUST equal the startup
        // snapshot, NOT the new declared block. Otherwise a second
        // reload would compare new declared vs already-updated snapshot
        // and stop warning.
        assert_eq!(
            returned.evpn_instances, initial.evpn_instances,
            "reload must pin evpn_instances to the startup snapshot until the daemon restarts"
        );
        assert_eq!(
            returned.evpn_instances.len(),
            1,
            "second instance must NOT have advanced into the runtime snapshot"
        );
        assert_eq!(
            returned.evpn_instances[0].route_targets.len(),
            1,
            "RT-list expansion must NOT have advanced into the runtime snapshot"
        );

        std::fs::remove_file(&path).ok();
    }

    /// SIGHUP that edits `[[evpn_ip_vrfs]]` must not advance the
    /// in-memory snapshot. Gate 9 currently validates IP-VRF schema
    /// at startup only; letting reload adopt the new table would make
    /// the next reload stop reporting drift even though no Type 5 /
    /// L3VNI runtime state changed.
    #[tokio::test]
    async fn reload_pins_evpn_ip_vrfs_to_startup_snapshot() {
        let path = unique_temp_path("reload-evpn-ip-vrf-pin");

        std::fs::write(
            &path,
            r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
log_format = "json"

[[evpn_ip_vrfs]]
name = "tenant-blue"
vni = 5000
rd = "65000:5000"
route_targets = ["65000:5000"]
local_vtep_ip = "10.0.0.1"
router_mac = "02:00:00:00:00:01"
vrf_device = "vrf-blue"
l3vxlan_device = "vni5000"
table_id = 5000
"#,
        )
        .unwrap();

        let initial = Config::load_with_diagnostics(path.to_str().unwrap()).unwrap();
        let live_grpc_tcp = initial.global.telemetry.grpc_tcp.clone();
        let live_grpc_uds = initial.global.telemetry.grpc_uds.clone();
        assert_eq!(initial.evpn_ip_vrfs.len(), 1);
        assert_eq!(initial.evpn_ip_vrfs[0].name, "tenant-blue");

        std::fs::write(
            &path,
            r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
log_format = "json"

[[evpn_ip_vrfs]]
name = "tenant-blue"
vni = 5000
rd = "65000:5000"
route_targets = ["65000:5000", "65000:6000"]
local_vtep_ip = "10.0.0.1"
router_mac = "02:00:00:00:00:01"
vrf_device = "vrf-blue"
l3vxlan_device = "vni5000"
table_id = 5000

[[evpn_ip_vrfs]]
name = "tenant-red"
vni = 5001
rd = "65000:5001"
route_targets = ["65000:5001"]
local_vtep_ip = "10.0.0.1"
router_mac = "02:00:00:00:00:02"
vrf_device = "vrf-red"
l3vxlan_device = "vni5001"
table_id = 5001
"#,
        )
        .unwrap();

        let (peer_mgr_tx, _peer_mgr_rx) = mpsc::channel(8);
        let returned = reload_config(
            path.to_str().unwrap(),
            &initial,
            live_grpc_tcp.as_ref(),
            live_grpc_uds.as_ref(),
            &peer_mgr_tx,
            None,
        )
        .await
        .expect("reload should return a config even when only evpn_ip_vrfs drift");

        assert_eq!(
            returned.evpn_ip_vrfs, initial.evpn_ip_vrfs,
            "reload must pin evpn_ip_vrfs to the startup snapshot until restart"
        );
        assert_eq!(
            returned.evpn_ip_vrfs.len(),
            1,
            "new IP-VRF must not advance into the runtime snapshot"
        );
        assert_eq!(
            returned.evpn_ip_vrfs[0].route_targets.len(),
            1,
            "RT-list expansion must not advance into the runtime snapshot"
        );

        std::fs::remove_file(&path).ok();
    }

    /// SIGHUP must also pin Gate 8 startup-only EVPN surfaces that
    /// feed long-lived actors: the Ethernet Segment table and the
    /// kernel-enforcement opt-in. Otherwise a reload would advance
    /// `current`, the actor would still be on its startup state, and
    /// the next reload would stop reporting drift.
    ///
    /// Drives the diff by flipping `apply_bum_enforcement` from
    /// explicit `false` (operator opt-out) to the v0.23.0 default
    /// `true`, which is the upgrade-path scenario operators on the
    /// older posture hit after the production-default flip.
    #[tokio::test]
    async fn reload_pins_ethernet_segments_and_bum_enforcement_to_startup_snapshot() {
        let path = unique_temp_path("reload-evpn-gate8-pin");

        std::fs::write(
            &path,
            r#"
apply_bum_enforcement = false

[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
log_format = "json"

[[evpn_instances]]
vni = 100
rd = "65000:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.1"
"#,
        )
        .unwrap();

        let initial = Config::load_with_diagnostics(path.to_str().unwrap()).unwrap();
        let live_grpc_tcp = initial.global.telemetry.grpc_tcp.clone();
        let live_grpc_uds = initial.global.telemetry.grpc_uds.clone();
        assert!(initial.ethernet_segments.is_empty());
        assert!(
            !initial.apply_bum_enforcement,
            "explicit `apply_bum_enforcement = false` must override the v0.23.0 default"
        );

        std::fs::write(
            &path,
            r#"
apply_bum_enforcement = true

[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
log_format = "json"

[[evpn_instances]]
vni = 100
rd = "65000:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.1"

[[ethernet_segments]]
esi = "00:00:00:00:00:00:00:00:00:01"
member_vnis = [100]
originator_ip = "10.0.0.1"
"#,
        )
        .unwrap();

        let (peer_mgr_tx, _peer_mgr_rx) = mpsc::channel(8);
        let returned = reload_config(
            path.to_str().unwrap(),
            &initial,
            live_grpc_tcp.as_ref(),
            live_grpc_uds.as_ref(),
            &peer_mgr_tx,
            None,
        )
        .await
        .expect("reload should return a config even when only Gate 8 surfaces drift");

        assert_eq!(
            returned.ethernet_segments, initial.ethernet_segments,
            "reload must pin ethernet_segments to the startup snapshot until restart"
        );
        assert_eq!(
            returned.apply_bum_enforcement, initial.apply_bum_enforcement,
            "reload must pin apply_bum_enforcement to the startup snapshot until restart"
        );

        std::fs::remove_file(&path).ok();
    }

    #[tokio::test]
    async fn reload_hot_applies_honor_graceful_shutdown() {
        let path = unique_temp_path("reload-honor-gshut-hot-apply");

        // Initial: honor knob OFF (default).
        std::fs::write(
            &path,
            r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
log_format = "json"

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
hold_time = 90
"#,
        )
        .unwrap();
        let initial = Config::load_with_diagnostics(path.to_str().unwrap()).unwrap();
        let live_grpc_tcp = initial.global.telemetry.grpc_tcp.clone();
        let live_grpc_uds = initial.global.telemetry.grpc_uds.clone();
        assert!(!initial.global.honor_graceful_shutdown);

        // Operator rewrites: turns the knob ON. Reload must advance
        // the runtime snapshot and ask the peer manager to recompute
        // EBGP runtime policies so the implicit chain-tail rule lands
        // on already-running sessions.
        std::fs::write(
            &path,
            r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179
honor_graceful_shutdown = true

[global.telemetry]
log_format = "json"

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
hold_time = 90
"#,
        )
        .unwrap();

        let (peer_mgr_tx, mut peer_mgr_rx) = mpsc::channel(8);
        let peer_mgr = tokio::spawn(async move {
            match peer_mgr_rx.recv().await {
                Some(PeerManagerCommand::SetHonorGracefulShutdown { enabled, reply }) => {
                    let _ = reply.send(Ok(()));
                    enabled
                }
                _ => panic!("expected SetHonorGracefulShutdown command"),
            }
        });
        let returned = reload_config(
            path.to_str().unwrap(),
            &initial,
            live_grpc_tcp.as_ref(),
            live_grpc_uds.as_ref(),
            &peer_mgr_tx,
            None,
        )
        .await
        .expect("reload should hot-apply honor_graceful_shutdown");

        assert!(
            returned.global.honor_graceful_shutdown,
            "reload must advance honor_graceful_shutdown after peer manager hot-apply succeeds"
        );
        assert!(
            peer_mgr.await.unwrap(),
            "peer manager command must carry enabled=true"
        );

        std::fs::remove_file(&path).ok();
    }

    #[tokio::test]
    async fn reload_hot_applies_honor_blackhole() {
        let path = unique_temp_path("reload-honor-blackhole-hot-apply");

        std::fs::write(
            &path,
            r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
log_format = "json"

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
hold_time = 90
"#,
        )
        .unwrap();
        let initial = Config::load_with_diagnostics(path.to_str().unwrap()).unwrap();
        let live_grpc_tcp = initial.global.telemetry.grpc_tcp.clone();
        let live_grpc_uds = initial.global.telemetry.grpc_uds.clone();
        assert!(!initial.global.honor_blackhole);

        std::fs::write(
            &path,
            r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179
honor_blackhole = true

[global.telemetry]
log_format = "json"

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
hold_time = 90
"#,
        )
        .unwrap();

        let (peer_mgr_tx, mut peer_mgr_rx) = mpsc::channel(8);
        let peer_mgr = tokio::spawn(async move {
            match peer_mgr_rx.recv().await {
                Some(PeerManagerCommand::SetHonorBlackhole { enabled, reply }) => {
                    let _ = reply.send(Ok(()));
                    enabled
                }
                _ => panic!("expected SetHonorBlackhole command"),
            }
        });
        let returned = reload_config(
            path.to_str().unwrap(),
            &initial,
            live_grpc_tcp.as_ref(),
            live_grpc_uds.as_ref(),
            &peer_mgr_tx,
            None,
        )
        .await
        .expect("reload should hot-apply honor_blackhole");

        assert!(
            returned.global.honor_blackhole,
            "reload must advance honor_blackhole after peer manager hot-apply succeeds"
        );
        assert!(
            peer_mgr.await.unwrap(),
            "peer manager command must carry enabled=true"
        );

        std::fs::remove_file(&path).ok();
    }

    const FIB_ONE_TABLE_TOML: &str = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
log_format = "json"

[[fib_tables]]
name = "edge"
table_id = 100
metric = 200
"#;

    const FIB_TWO_TABLES_TOML: &str = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
log_format = "json"

[[fib_tables]]
name = "edge"
table_id = 100
metric = 200

[[fib_tables]]
name = "edge2"
table_id = 101
metric = 200
"#;

    #[tokio::test]
    async fn reload_hot_applies_fib_tables_when_actor_present() {
        let path = unique_temp_path("reload-fib-tables-hot-apply");
        std::fs::write(&path, FIB_ONE_TABLE_TOML).unwrap();
        let initial = Config::load_with_diagnostics(path.to_str().unwrap()).unwrap();
        let tcp = initial.global.telemetry.grpc_tcp.clone();
        let uds = initial.global.telemetry.grpc_uds.clone();
        assert_eq!(initial.fib_tables.len(), 1);

        std::fs::write(&path, FIB_TWO_TABLES_TOML).unwrap();

        let (peer_mgr_tx, _peer_mgr_rx) = mpsc::channel(8);
        let (fib_tx, mut fib_rx) = mpsc::channel(8);
        let actor = tokio::spawn(async move {
            match fib_rx.recv().await {
                Some(FibRuntimeCommand::ReplaceTables { tables, reply }) => {
                    let _ = reply.send(Ok(()));
                    tables.len()
                }
                None => panic!("expected ReplaceTables"),
            }
        });

        let returned = reload_config(
            path.to_str().unwrap(),
            &initial,
            tcp.as_ref(),
            uds.as_ref(),
            &peer_mgr_tx,
            Some(&fib_tx),
        )
        .await
        .expect("reload should hot-apply fib_tables");

        assert_eq!(
            returned.fib_tables.len(),
            2,
            "snapshot advances only after the actor acks the new table set"
        );
        assert_eq!(actor.await.unwrap(), 2, "actor received the new table set");
        std::fs::remove_file(&path).ok();
    }

    #[tokio::test]
    async fn reload_does_not_advance_fib_tables_when_actor_unreachable() {
        let path = unique_temp_path("reload-fib-tables-actor-gone");
        std::fs::write(&path, FIB_ONE_TABLE_TOML).unwrap();
        let initial = Config::load_with_diagnostics(path.to_str().unwrap()).unwrap();
        let tcp = initial.global.telemetry.grpc_tcp.clone();
        let uds = initial.global.telemetry.grpc_uds.clone();
        std::fs::write(&path, FIB_TWO_TABLES_TOML).unwrap();

        let (peer_mgr_tx, _peer_mgr_rx) = mpsc::channel(8);
        let (fib_tx, fib_rx) = mpsc::channel::<FibRuntimeCommand>(8);
        drop(fib_rx); // actor gone — the send fails, so the snapshot must not advance

        let returned = reload_config(
            path.to_str().unwrap(),
            &initial,
            tcp.as_ref(),
            uds.as_ref(),
            &peer_mgr_tx,
            Some(&fib_tx),
        )
        .await
        .expect("reload returns a config even when the FIB actor is unreachable");

        assert_eq!(
            returned.fib_tables.len(),
            1,
            "no ack ⇒ snapshot must stay on the live table set"
        );
        std::fs::remove_file(&path).ok();
    }

    #[tokio::test]
    async fn reload_does_not_advance_fib_tables_when_runtime_absent() {
        let path = unique_temp_path("reload-fib-tables-absent");
        std::fs::write(&path, FIB_ONE_TABLE_TOML).unwrap();
        let initial = Config::load_with_diagnostics(path.to_str().unwrap()).unwrap();
        let tcp = initial.global.telemetry.grpc_tcp.clone();
        let uds = initial.global.telemetry.grpc_uds.clone();
        std::fs::write(&path, FIB_TWO_TABLES_TOML).unwrap();

        let (peer_mgr_tx, _peer_mgr_rx) = mpsc::channel(8);
        // fib_cmd_tx = None: the FIB runtime never spawned. `current` already has
        // tables, so this hits the "runtime unavailable; restart required" branch
        // — it must log + revert, never advance the snapshot.
        let returned = reload_config(
            path.to_str().unwrap(),
            &initial,
            tcp.as_ref(),
            uds.as_ref(),
            &peer_mgr_tx,
            None,
        )
        .await
        .expect("reload returns a config when the FIB runtime is absent");

        assert_eq!(
            returned.fib_tables.len(),
            1,
            "absent FIB runtime must not advance the snapshot"
        );
        std::fs::remove_file(&path).ok();
    }

    const FIB_NO_TABLES_TOML: &str = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
log_format = "json"
"#;

    #[tokio::test]
    async fn reload_fib_tables_from_empty_config_requires_restart() {
        // 0→N with no FIB runtime running (started empty): the explicit
        // restart-required-to-start branch. The snapshot must not advance.
        let path = unique_temp_path("reload-fib-tables-from-empty");
        std::fs::write(&path, FIB_NO_TABLES_TOML).unwrap();
        let initial = Config::load_with_diagnostics(path.to_str().unwrap()).unwrap();
        let tcp = initial.global.telemetry.grpc_tcp.clone();
        let uds = initial.global.telemetry.grpc_uds.clone();
        assert!(initial.fib_tables.is_empty());

        std::fs::write(&path, FIB_ONE_TABLE_TOML).unwrap();

        let (peer_mgr_tx, _peer_mgr_rx) = mpsc::channel(8);
        let returned = reload_config(
            path.to_str().unwrap(),
            &initial,
            tcp.as_ref(),
            uds.as_ref(),
            &peer_mgr_tx,
            None,
        )
        .await
        .expect("reload returns a config when FIB must be started from empty");

        assert!(
            returned.fib_tables.is_empty(),
            "0→N from an empty config is restart-required; snapshot must not advance"
        );
        std::fs::remove_file(&path).ok();
    }

    #[tokio::test]
    async fn reload_does_not_advance_fib_tables_when_actor_reports_failure() {
        // The actor acks Err (e.g. a removed table's withdraw failed, or a
        // pre-plan RIB/dump bail) → reload must NOT advance the snapshot.
        let path = unique_temp_path("reload-fib-tables-actor-err");
        std::fs::write(&path, FIB_ONE_TABLE_TOML).unwrap();
        let initial = Config::load_with_diagnostics(path.to_str().unwrap()).unwrap();
        let tcp = initial.global.telemetry.grpc_tcp.clone();
        let uds = initial.global.telemetry.grpc_uds.clone();
        std::fs::write(&path, FIB_TWO_TABLES_TOML).unwrap();

        let (peer_mgr_tx, _peer_mgr_rx) = mpsc::channel(8);
        let (fib_tx, mut fib_rx) = mpsc::channel(8);
        let actor = tokio::spawn(async move {
            if let Some(FibRuntimeCommand::ReplaceTables { reply, .. }) = fib_rx.recv().await {
                let _ = reply.send(Err("simulated reconcile failure".to_string()));
            }
        });

        let returned = reload_config(
            path.to_str().unwrap(),
            &initial,
            tcp.as_ref(),
            uds.as_ref(),
            &peer_mgr_tx,
            Some(&fib_tx),
        )
        .await
        .expect("reload returns a config even when the actor reports failure");

        assert_eq!(
            returned.fib_tables.len(),
            1,
            "an Err ack must not advance the snapshot"
        );
        let _ = actor.await;
        std::fs::remove_file(&path).ok();
    }

    #[tokio::test]
    async fn reload_pins_honor_blackhole_when_fib_discard_enabled() {
        let path = unique_temp_path("reload-pins-honor-blackhole-with-fib");

        std::fs::write(
            &path,
            r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179
honor_blackhole = true
install_blackhole_discard = true

[global.telemetry]
log_format = "json"

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
hold_time = 90
"#,
        )
        .unwrap();
        let initial = Config::load_with_diagnostics(path.to_str().unwrap()).unwrap();
        let live_grpc_tcp = initial.global.telemetry.grpc_tcp.clone();
        let live_grpc_uds = initial.global.telemetry.grpc_uds.clone();

        std::fs::write(
            &path,
            r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179
honor_blackhole = false
install_blackhole_discard = true

[global.telemetry]
log_format = "json"

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
hold_time = 90
"#,
        )
        .unwrap();

        let (peer_mgr_tx, _peer_mgr_rx) = mpsc::channel(8);
        let returned = reload_config(
            path.to_str().unwrap(),
            &initial,
            live_grpc_tcp.as_ref(),
            live_grpc_uds.as_ref(),
            &peer_mgr_tx,
            None,
        )
        .await
        .expect("reload should pin honor_blackhole to the startup FIB snapshot");

        assert!(
            returned.global.honor_blackhole,
            "honor_blackhole must stay pinned while the FIB reconciler is running"
        );
        assert!(returned.global.install_blackhole_discard);

        std::fs::remove_file(&path).ok();
    }

    #[tokio::test]
    async fn reload_hot_applies_graceful_shutdown_and_blackhole_together() {
        let path = unique_temp_path("reload-honor-gshut-blackhole-hot-apply");

        std::fs::write(
            &path,
            r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
log_format = "json"

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
hold_time = 90
"#,
        )
        .unwrap();
        let initial = Config::load_with_diagnostics(path.to_str().unwrap()).unwrap();
        let live_grpc_tcp = initial.global.telemetry.grpc_tcp.clone();
        let live_grpc_uds = initial.global.telemetry.grpc_uds.clone();
        assert!(!initial.global.honor_graceful_shutdown);
        assert!(!initial.global.honor_blackhole);

        std::fs::write(
            &path,
            r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179
honor_graceful_shutdown = true
honor_blackhole = true

[global.telemetry]
log_format = "json"

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
hold_time = 90
"#,
        )
        .unwrap();

        let (peer_mgr_tx, mut peer_mgr_rx) = mpsc::channel(8);
        let peer_mgr = tokio::spawn(async move {
            let mut commands = Vec::new();
            for _ in 0..2 {
                match peer_mgr_rx.recv().await {
                    Some(PeerManagerCommand::SetHonorGracefulShutdown { enabled, reply }) => {
                        let _ = reply.send(Ok(()));
                        commands.push(("gshut", enabled));
                    }
                    Some(PeerManagerCommand::SetHonorBlackhole { enabled, reply }) => {
                        let _ = reply.send(Ok(()));
                        commands.push(("blackhole", enabled));
                    }
                    _ => panic!("unexpected peer manager command"),
                }
            }
            commands
        });
        let returned = reload_config(
            path.to_str().unwrap(),
            &initial,
            live_grpc_tcp.as_ref(),
            live_grpc_uds.as_ref(),
            &peer_mgr_tx,
            None,
        )
        .await
        .expect("reload should hot-apply both honor knobs");

        assert!(returned.global.honor_graceful_shutdown);
        assert!(returned.global.honor_blackhole);
        assert_eq!(
            peer_mgr.await.unwrap(),
            vec![("gshut", true), ("blackhole", true)]
        );

        std::fs::remove_file(&path).ok();
    }

    /// Tag string identifying the kind of `PeerManagerCommand` the
    /// mock observed during a reload — used by reload tests to
    /// assert the right sequence of commands fired without coupling
    /// to the full command struct.
    fn cmd_tag(cmd: &PeerManagerCommand) -> String {
        match cmd {
            PeerManagerCommand::SetPolicy { name, .. } => format!("SetPolicy({name})"),
            PeerManagerCommand::DeletePolicy { name, .. } => format!("DeletePolicy({name})"),
            PeerManagerCommand::SetNeighborSet { name, .. } => format!("SetNeighborSet({name})"),
            PeerManagerCommand::DeleteNeighborSet { name, .. } => {
                format!("DeleteNeighborSet({name})")
            }
            PeerManagerCommand::SetPeerGroup { name, .. } => format!("SetPeerGroup({name})"),
            PeerManagerCommand::DeletePeerGroup { name, .. } => format!("DeletePeerGroup({name})"),
            PeerManagerCommand::SetGlobalImportChain { policy_names, .. } => {
                format!("SetGlobalImportChain({})", policy_names.join(","))
            }
            PeerManagerCommand::SetGlobalExportChain { policy_names, .. } => {
                format!("SetGlobalExportChain({})", policy_names.join(","))
            }
            PeerManagerCommand::ClearGlobalImportChain { .. } => {
                "ClearGlobalImportChain".to_string()
            }
            PeerManagerCommand::ClearGlobalExportChain { .. } => {
                "ClearGlobalExportChain".to_string()
            }
            PeerManagerCommand::ReconcilePeers {
                added,
                removed,
                changed,
                ..
            } => {
                format!(
                    "ReconcilePeers(+{},-{},~{})",
                    added.len(),
                    removed.len(),
                    changed.len(),
                )
            }
            PeerManagerCommand::SoftResetIn { peer, .. } => {
                format!("SoftResetIn({peer})")
            }
            PeerManagerCommand::SyncExplainConfig {
                enabled,
                cache_size,
                ..
            } => {
                format!("SyncExplainConfig(enabled={enabled},cache_size={cache_size})")
            }
            _ => "Other".to_string(),
        }
    }

    /// Drive a reload against the given initial+next TOML and return
    /// the commands the mock peer manager observed, in order.
    /// Replies `Ok(())` to every command that carries a reply channel.
    async fn drive_reload(
        initial_toml: &str,
        new_toml: &str,
    ) -> (Option<ReloadedConfig>, Vec<String>) {
        let path = unique_temp_path("reload-driver");
        std::fs::write(&path, initial_toml).unwrap();
        let initial = Config::load_with_diagnostics(path.to_str().unwrap()).unwrap();
        let live_grpc_tcp = initial.global.telemetry.grpc_tcp.clone();
        let live_grpc_uds = initial.global.telemetry.grpc_uds.clone();

        std::fs::write(&path, new_toml).unwrap();

        let (peer_mgr_tx, mut peer_mgr_rx) = mpsc::channel::<PeerManagerCommand>(64);
        let mock = tokio::spawn(async move {
            use rustbgpd_api::peer_types::ReconcileResult;
            let mut tags = Vec::new();
            while let Some(cmd) = peer_mgr_rx.recv().await {
                tags.push(cmd_tag(&cmd));
                // Respond Ok(()) to every command that has a reply
                // channel so reload_config doesn't hang.
                match cmd {
                    PeerManagerCommand::SetPolicy { reply, .. }
                    | PeerManagerCommand::DeletePolicy { reply, .. }
                    | PeerManagerCommand::SetNeighborSet { reply, .. }
                    | PeerManagerCommand::DeleteNeighborSet { reply, .. }
                    | PeerManagerCommand::SetPeerGroup { reply, .. }
                    | PeerManagerCommand::DeletePeerGroup { reply, .. }
                    | PeerManagerCommand::SetGlobalImportChain { reply, .. }
                    | PeerManagerCommand::SetGlobalExportChain { reply, .. }
                    | PeerManagerCommand::ClearGlobalImportChain { reply }
                    | PeerManagerCommand::ClearGlobalExportChain { reply }
                    | PeerManagerCommand::SoftResetIn { reply, .. } => {
                        let _ = reply.send(Ok(()));
                    }
                    PeerManagerCommand::ReconcilePeers { reply, .. } => {
                        let _ = reply.send(ReconcileResult::default());
                    }
                    PeerManagerCommand::SyncExplainConfig { reply, .. } => {
                        let _ = reply.send(());
                    }
                    _ => {}
                }
            }
            tags
        });

        let returned = reload_config(
            path.to_str().unwrap(),
            &initial,
            live_grpc_tcp.as_ref(),
            live_grpc_uds.as_ref(),
            &peer_mgr_tx,
            None,
        )
        .await;
        drop(peer_mgr_tx);
        let tags = mock.await.unwrap();
        std::fs::remove_file(&path).ok();
        (returned, tags)
    }

    fn baseline_toml() -> &'static str {
        // Shared test fixture: opts into `enforcement = "legacy"`
        // explicitly so reload tests exercise pre-v0.24.0 gRPC
        // authorization behavior (matching the `parse()` test helper
        // pattern in src/config/tests.rs). Reload-mode tier-mode
        // semantics are not the focus here.
        r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
log_format = "json"

[security.grpc]
enforcement = "legacy"

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
hold_time = 90
"#
    }

    fn load_config_from_toml(name: &str, toml: &str) -> Config {
        let path = unique_temp_path(name);
        std::fs::write(&path, toml).unwrap();
        let config = Config::load_with_diagnostics(path.to_str().unwrap()).unwrap();
        std::fs::remove_file(&path).ok();
        config
    }

    #[test]
    fn config_diff_json_includes_hot_applied_global_flags() {
        let old = load_config_from_toml("diff-json-old", baseline_toml());
        let new_toml = baseline_toml().replace(
            "listen_port = 179",
            "listen_port = 179\nhonor_graceful_shutdown = true\nhonor_blackhole = true",
        );
        let new = load_config_from_toml("diff-json-new", &new_toml);
        let diff = config::diff_config(&old, &new);
        let value = config::config_diff_json_value(&diff);

        assert_eq!(
            value["reload_applied"]["honor_graceful_shutdown_changed"],
            true
        );
        assert_eq!(value["reload_applied"]["honor_blackhole_changed"], true);
        assert_eq!(value["restart_required"]["global_changed"], false);
        assert_eq!(value["has_actionable_changes"], true);
    }

    #[test]
    fn config_diff_human_bucket_lists_hot_applied_global_flags() {
        let old = load_config_from_toml("diff-human-old", baseline_toml());
        let new_toml = baseline_toml().replace(
            "listen_port = 179",
            "listen_port = 179\nhonor_graceful_shutdown = true\nhonor_blackhole = true",
        );
        let new = load_config_from_toml("diff-human-new", &new_toml);
        let diff = config::diff_config(&old, &new);

        assert!(
            diff.has_reload_applied_changes(),
            "hot-applied global flags must keep the diff in the reload-applied bucket"
        );
        let rendered = config::format_config_diff(&diff);
        assert!(
            rendered.contains("Global hot-applied flags:"),
            "rendered diff should include the hot-applied flags bucket: {rendered}"
        );
        assert!(rendered.contains("honor_graceful_shutdown"), "{rendered}");
        assert!(rendered.contains("honor_blackhole"), "{rendered}");
    }

    #[tokio::test]
    async fn reload_pins_bfd_edits_to_startup_snapshot() {
        // Adding a profile + a neighbor bfd block is restart-required (the
        // ADR-0067 actor resolves its sessions once at startup), so a SIGHUP
        // must pin the BFD config back to the live snapshot — but preserve the
        // operator's edit in the desired TOML for the next restart.
        let initial = baseline_toml();
        let new_toml = format!(
            "{}\n[[bfd_profiles]]\nname = \"fast\"\n",
            baseline_toml().replace(
                "hold_time = 90",
                "hold_time = 90\nbfd = { profile = \"fast\", strict = true }",
            )
        );

        let (returned, tags) = drive_reload(initial, &new_toml).await;
        let returned = returned.expect("reload should return pinned runtime config");

        assert!(
            tags.is_empty(),
            "bfd-only edits are restart-required and must not reconcile peers: {tags:?}"
        );
        assert!(
            returned.neighbors[0].bfd.is_none(),
            "runtime snapshot must keep the (empty) startup BFD config"
        );
        assert!(
            returned.bfd_profiles.is_empty(),
            "runtime snapshot must keep the startup profile set"
        );
        assert_eq!(
            returned.desired.neighbors[0].bfd.as_ref().unwrap().profile,
            "fast",
            "desired TOML must preserve the operator's BFD edit for restart"
        );
    }

    #[tokio::test]
    async fn reload_pins_tcp_ao_key_edits_to_startup_snapshot() {
        let initial = baseline_toml().replace(
            "hold_time = 90",
            "hold_time = 90\ntcp_ao = { key = \"old-secret\", send_id = 1, recv_id = 1, algorithm = \"hmac(sha256)\" }",
        );
        let new_toml = baseline_toml().replace(
            "hold_time = 90",
            "hold_time = 90\ntcp_ao = { key = \"new-secret\", send_id = 1, recv_id = 1, algorithm = \"hmac(sha256)\" }",
        );

        let (returned, tags) = drive_reload(&initial, &new_toml).await;
        let returned = returned.expect("reload should return pinned runtime config");

        assert!(
            tags.is_empty(),
            "tcp_ao-only edits are restart-required and must not reconcile peers: {tags:?}"
        );
        assert_eq!(
            returned.neighbors[0].tcp_ao.as_ref().unwrap().key,
            "old-secret",
            "runtime snapshot must keep the startup listener/session key"
        );
        assert_eq!(
            returned.desired.neighbors[0].tcp_ao.as_ref().unwrap().key,
            "new-secret",
            "desired TOML must preserve the operator's edit for restart"
        );
    }

    #[tokio::test]
    async fn reload_pins_tcp_ao_dependency_edits_to_startup_snapshot() {
        let initial = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
log_format = "json"

[peer_groups.secure]
hold_time = 90
import_policy_chain = ["keep"]

[policy.definitions.keep]
default_action = "permit"

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
peer_group = "secure"
tcp_ao = { key = "old-secret", send_id = 1, recv_id = 1, algorithm = "hmac(sha256)" }
"#;
        let new_toml = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
log_format = "json"

[peer_groups.secure]
hold_time = 90
md5_password = "md5-secret"
import_policy_chain = ["keep"]

[policy.definitions.keep]
default_action = "deny"

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
peer_group = "secure"
"#;

        let (returned, tags) = drive_reload(initial, new_toml).await;
        let returned = returned.expect("reload should return pinned runtime config");

        assert!(
            tags.is_empty(),
            "tcp_ao dependency edits must be restart-required and must not hot-apply: {tags:?}"
        );
        assert!(
            returned.peer_groups["secure"].md5_password.is_none(),
            "runtime peer-group dependency snapshot must stay compatible with the live TCP-AO neighbor"
        );
        assert!(
            returned.policy.definitions["keep"].default_action == "permit",
            "runtime policy dependencies must be pinned with the live TCP-AO neighbor"
        );
        assert_eq!(
            returned.desired.peer_groups["secure"]
                .md5_password
                .as_deref(),
            Some("md5-secret"),
            "desired TOML must keep the operator's peer-group edit for restart"
        );
        assert!(
            returned
                .desired
                .policy
                .definitions
                .get("keep")
                .is_some_and(|definition| definition.default_action == "deny"),
            "desired TOML must keep the operator's policy edit for restart"
        );
    }

    /// Adding a named policy definition on reload must surface as a
    /// `SetPolicy` command to the peer manager — proving the reload
    /// path no longer silently ignores `[policy.definitions.*]` edits.
    #[tokio::test]
    async fn reload_applies_named_policy_addition() {
        let new_toml = format!(
            "{}\n[policy.definitions.block-private]\ndefault_action = \"deny\"\n",
            baseline_toml()
        );
        let (returned, tags) = drive_reload(baseline_toml(), &new_toml).await;
        assert!(returned.is_some(), "reload must succeed");
        assert!(
            tags.contains(&"SetPolicy(block-private)".to_string()),
            "expected SetPolicy(block-private) — saw {tags:?}"
        );
    }

    /// ADR-0073: an explain-only reload must adopt the new
    /// `[policy.explain]` into the returned snapshot (so sessions
    /// established after the reload honour it) even though it takes the
    /// "no neighbor/policy/peer-group changes" early-return path.
    #[tokio::test]
    async fn reload_explain_only_adopts_new_snapshot() {
        let new_toml = format!(
            "{}\n[policy.explain]\nenabled = false\ncache_size = 512\n",
            baseline_toml()
        );
        let (returned, _tags) = drive_reload(baseline_toml(), &new_toml).await;
        let reloaded = returned.expect("reload must succeed");
        assert!(!reloaded.policy.explain.enabled);
        assert_eq!(reloaded.policy.explain.cache_size, 512);
    }

    /// ADR-0073 (mixed reload): when `[policy.explain]` changes alongside
    /// a hot-applied edit, the returned snapshot must still carry the new
    /// explain block. The reconcile path builds `working_config` from
    /// `current`, so without the explicit copy the new explain would be
    /// lost despite the warning promising new sessions honour it.
    #[tokio::test]
    async fn reload_mixed_change_preserves_new_explain() {
        let new_toml = format!(
            "{}\n[policy.definitions.block-private]\ndefault_action = \"deny\"\n\n[policy.explain]\nenabled = false\ncache_size = 333\n",
            baseline_toml()
        );
        let (returned, tags) = drive_reload(baseline_toml(), &new_toml).await;
        let reloaded = returned.expect("reload must succeed");
        // The hot-applied policy addition still reconciled...
        assert!(
            tags.contains(&"SetPolicy(block-private)".to_string()),
            "expected SetPolicy(block-private) — saw {tags:?}"
        );
        // ...and the restart-required explain block is in the snapshot.
        assert!(
            !reloaded.policy.explain.enabled,
            "mixed reload must adopt the new explain.enabled"
        );
        assert_eq!(
            reloaded.policy.explain.cache_size, 333,
            "mixed reload must adopt the new explain.cache_size"
        );
    }

    /// ADR-0073 (mid-reload race): when explain changes alongside a
    /// neighbor edit that re-adds the peer, the peer manager's explain
    /// snapshot must be refreshed *before* the reconcile constructs the
    /// session — otherwise the re-added peer reads stale explain via
    /// `build_transport_config`. Proven by command ordering on the FIFO
    /// channel: `SyncExplainConfig` must precede `ReconcilePeers`.
    #[tokio::test]
    async fn reload_syncs_explain_before_peer_reconcile() {
        // Change the neighbor (hold_time) → ReconcilePeers(changed); and
        // flip [policy.explain] in the same reload.
        let new_toml = format!(
            "{}\n[policy.explain]\nenabled = false\n",
            baseline_toml().replace("hold_time = 90", "hold_time = 120")
        );
        let (returned, tags) = drive_reload(baseline_toml(), &new_toml).await;
        assert!(returned.is_some(), "reload must succeed");

        let sync_idx = tags
            .iter()
            .position(|t| t.starts_with("SyncExplainConfig"))
            .unwrap_or_else(|| panic!("expected SyncExplainConfig — saw {tags:?}"));
        let reconcile_idx = tags
            .iter()
            .position(|t| t.starts_with("ReconcilePeers"))
            .unwrap_or_else(|| panic!("expected ReconcilePeers — saw {tags:?}"));
        assert!(
            sync_idx < reconcile_idx,
            "explain snapshot must sync before peer reconcile — saw {tags:?}"
        );
        assert!(
            tags[sync_idx].contains("enabled=false"),
            "sync must carry the new explain value — saw {tags:?}"
        );
    }

    /// Adding a peer-group definition on reload must surface as a
    /// `SetPeerGroup` command. Catches the silent-ignore failure mode
    /// where peer-group edits would only be detected, not applied.
    #[tokio::test]
    async fn reload_applies_peer_group_addition() {
        let new_toml = format!(
            "{}\n[peer_groups.external]\nhold_time = 60\n",
            baseline_toml()
        );
        let (returned, tags) = drive_reload(baseline_toml(), &new_toml).await;
        assert!(returned.is_some(), "reload must succeed");
        assert!(
            tags.contains(&"SetPeerGroup(external)".to_string()),
            "expected SetPeerGroup(external) — saw {tags:?}"
        );
    }

    /// Changing the global `import_chain` on reload must surface as
    /// `SetGlobalImportChain` (or `ClearGlobalImportChain` when empty).
    #[tokio::test]
    async fn reload_applies_global_import_chain_change() {
        let initial = format!(
            "{}\n[policy.definitions.foo]\ndefault_action = \"permit\"\n",
            baseline_toml()
        );
        let new_toml = format!(
            "{}\n[policy.definitions.foo]\ndefault_action = \"permit\"\n[policy]\nimport_chain = [\"foo\"]\n",
            baseline_toml()
        );
        let (returned, tags) = drive_reload(&initial, &new_toml).await;
        assert!(returned.is_some(), "reload must succeed");
        assert!(
            tags.iter().any(|t| t.starts_with("SetGlobalImportChain")),
            "expected SetGlobalImportChain — saw {tags:?}"
        );
    }

    /// Removing a policy definition must surface as `DeletePolicy`
    /// AFTER any neighbor reconciliation, so the still-referenced
    /// rejection path doesn't fire transiently.
    #[tokio::test]
    async fn reload_applies_policy_removal_after_neighbor_reconcile() {
        let initial = format!(
            "{}\n[policy.definitions.old]\ndefault_action = \"permit\"\n",
            baseline_toml()
        );
        let (returned, tags) = drive_reload(&initial, baseline_toml()).await;
        assert!(returned.is_some(), "reload must succeed");
        assert!(
            tags.contains(&"DeletePolicy(old)".to_string()),
            "expected DeletePolicy(old) — saw {tags:?}"
        );
    }

    /// When a step early in the reload sequence succeeds and a later
    /// step fails, reload returns a partial-state snapshot so the
    /// daemon's in-memory config matches what the peer manager
    /// actually applied — instead of the previous behaviour where it
    /// returned `None` ("kept current") while the manager already had
    /// half the new state in effect. `SetPolicy` lands, then
    /// `ReconcilePeers` fails; the returned config must contain the
    /// new policy but not the new neighbors.
    #[tokio::test]
    async fn reload_halts_on_failure_with_honest_partial_snapshot() {
        use rustbgpd_api::peer_types::{ReconcileFailure, ReconcileFailureKind, ReconcileResult};

        let initial_toml = baseline_toml().to_string();
        let new_toml = format!(
            "{baseline}\n[policy.definitions.block-private]\ndefault_action = \"deny\"\n\n[[neighbors]]\naddress = \"10.0.0.99\"\nremote_asn = 65099\nhold_time = 90\n",
            baseline = baseline_toml()
        );

        let path = unique_temp_path("reload-halt-partial");
        std::fs::write(&path, &initial_toml).unwrap();
        let initial = Config::load_with_diagnostics(path.to_str().unwrap()).unwrap();
        let live_grpc_tcp = initial.global.telemetry.grpc_tcp.clone();
        let live_grpc_uds = initial.global.telemetry.grpc_uds.clone();
        std::fs::write(&path, &new_toml).unwrap();

        let (peer_mgr_tx, mut peer_mgr_rx) = mpsc::channel::<PeerManagerCommand>(32);
        let mock = tokio::spawn(async move {
            // Reply Ok to every non-reconcile command; reply with a
            // reconcile failure to simulate a runtime rejection from
            // the peer manager. Models a valid TOML that fails for
            // an operational reason at the manager (port bind, TCP
            // setup, MD5 key push, etc.). Track command tags so the
            // test can assert which earlier steps successfully fired.
            let mut tags: Vec<String> = Vec::new();
            while let Some(cmd) = peer_mgr_rx.recv().await {
                tags.push(cmd_tag(&cmd));
                match cmd {
                    PeerManagerCommand::SetPolicy { reply, .. }
                    | PeerManagerCommand::DeletePolicy { reply, .. }
                    | PeerManagerCommand::SetNeighborSet { reply, .. }
                    | PeerManagerCommand::DeleteNeighborSet { reply, .. }
                    | PeerManagerCommand::SetPeerGroup { reply, .. }
                    | PeerManagerCommand::DeletePeerGroup { reply, .. }
                    | PeerManagerCommand::SetGlobalImportChain { reply, .. }
                    | PeerManagerCommand::SetGlobalExportChain { reply, .. }
                    | PeerManagerCommand::ClearGlobalImportChain { reply }
                    | PeerManagerCommand::ClearGlobalExportChain { reply } => {
                        let _ = reply.send(Ok(()));
                    }
                    PeerManagerCommand::ReconcilePeers { reply, .. } => {
                        let result = ReconcileResult {
                            failures: vec![ReconcileFailure {
                                kind: ReconcileFailureKind::Add,
                                peer: rustbgpd_api::peer_types::PeerKey::new(
                                    "10.0.0.99".parse().unwrap(),
                                    None,
                                ),
                                error: "simulated reconcile failure".to_string(),
                            }],
                        };
                        let _ = reply.send(result);
                    }
                    PeerManagerCommand::SyncExplainConfig { reply, .. } => {
                        let _ = reply.send(());
                    }
                    _ => {}
                }
            }
            tags
        });

        let returned = reload_config(
            path.to_str().unwrap(),
            &initial,
            live_grpc_tcp.as_ref(),
            live_grpc_uds.as_ref(),
            &peer_mgr_tx,
            None,
        )
        .await;
        drop(peer_mgr_tx);
        let tags = mock.await.unwrap();
        std::fs::remove_file(&path).ok();

        // Reconcile partial failure returns None: live peer-manager
        // state is ambiguous (delete-then-readd ordering, independent
        // adds/removes), so guessing a snapshot would let the next
        // reload diff against a config that doesn't match reality.
        // Operators investigate live state via `rustbgpctl neighbor
        // list`. Earlier reload steps (the SetPolicy here) DID land
        // at the manager and remain in effect — assert via the mock's
        // command log, since the in-memory config doesn't advance for
        // this failure class.
        assert!(
            returned.is_none(),
            "reconcile partial failure must return None — guessing a snapshot \
             when live state is ambiguous would let the next reload diff against \
             a fictional config"
        );
        assert!(
            tags.contains(&"SetPolicy(block-private)".to_string()),
            "earlier reload steps must still have fired before the reconcile failure — saw {tags:?}"
        );
    }

    /// `apply_reload_outcome` must send to the peer manager FIRST, so
    /// the authoritative runtime view always advances even if the
    /// optional bridge channel later fails. Drives the helper directly
    /// with a closed bridge channel to assert the failure stage name
    /// matches and the peer manager already received the snapshot
    /// before the bridge send was attempted.
    #[tokio::test]
    async fn apply_reload_outcome_bridge_failure_after_peer_mgr_snapshot() {
        let (peer_mgr_internal_tx, mut peer_mgr_internal_rx) =
            mpsc::unbounded_channel::<InternalCommand>();
        let (bridge_tx, bridge_rx) = mpsc::unbounded_channel::<Box<Config>>();
        // Drop the bridge rx so the helper's send fails immediately
        // with a closed-channel error.
        drop(bridge_rx);

        let path = unique_temp_path("apply-reload-outcome");
        std::fs::write(&path, baseline_toml()).unwrap();
        let cfg = Config::load_with_diagnostics(path.to_str().unwrap()).unwrap();
        std::fs::remove_file(&path).ok();

        let result = apply_reload_outcome(
            ReloadedConfig::new(cfg.clone(), cfg.clone()),
            &peer_mgr_internal_tx,
            Some(&bridge_tx),
        )
        .await;

        assert_eq!(
            result.err(),
            Some("config_bridge"),
            "bridge failure must surface as the named stage so the caller's log line is actionable"
        );
        let snapshot = peer_mgr_internal_rx
            .try_recv()
            .expect("peer manager must receive the snapshot before the bridge send is attempted");
        match snapshot {
            InternalCommand::ReplaceConfigSnapshot(received) => {
                assert_eq!(received.global.asn, cfg.global.asn);
            }
        }
    }

    /// Bridge-disabled mode (no `file_path`, so no persister and no
    /// bridge) must succeed: the helper takes `Option<&Sender>`, and a
    /// `None` bridge is the runtime configuration when rustbgpd starts
    /// without a `--config` file (gRPC mutations are non-persistent in
    /// that mode by design).
    #[tokio::test]
    async fn apply_reload_outcome_succeeds_without_bridge() {
        let (peer_mgr_internal_tx, mut peer_mgr_internal_rx) =
            mpsc::unbounded_channel::<InternalCommand>();

        let path = unique_temp_path("apply-reload-outcome-nobridge");
        std::fs::write(&path, baseline_toml()).unwrap();
        let cfg = Config::load_with_diagnostics(path.to_str().unwrap()).unwrap();
        std::fs::remove_file(&path).ok();

        let advanced = apply_reload_outcome(
            ReloadedConfig::new(cfg.clone(), cfg.clone()),
            &peer_mgr_internal_tx,
            None,
        )
        .await
        .expect("no-bridge mode must succeed");
        assert_eq!(advanced.global.asn, cfg.global.asn);
        assert!(peer_mgr_internal_rx.try_recv().is_ok());
    }

    /// Regression test for the bridge stale-snapshot bug. The bridge
    /// owns the pre-persist snapshot used by gRPC mutations. A
    /// SIGHUP-driven refresh must update that snapshot without writing
    /// the reloaded file back out, otherwise restart-required pinning
    /// would destroy an operator's edit-then-restart TOML.
    /// This test drives the bridge directly: send a snapshot
    /// replacement, then a `ConfigEvent` that adds a named policy,
    /// and assert the resulting persisted `ReplaceConfig` was computed
    /// against the *replacement* base — i.e. the bridge's internal
    /// snapshot was successfully swapped.
    #[tokio::test]
    async fn config_bridge_replacement_makes_subsequent_events_apply_to_new_snapshot() {
        use rustbgpd_api::peer_types::{ConfigEvent, NamedPolicyDefinition};

        let stale_path = unique_temp_path("bridge-replace-stale");
        std::fs::write(&stale_path, baseline_toml()).unwrap();
        let stale = Config::load_with_diagnostics(stale_path.to_str().unwrap()).unwrap();
        std::fs::remove_file(&stale_path).ok();

        let new_toml = format!(
            "{baseline}\n[peer_groups.upstream]\nhold_time = 90\n",
            baseline = baseline_toml()
        );
        let new_path = unique_temp_path("bridge-replace-new");
        std::fs::write(&new_path, &new_toml).unwrap();
        let reloaded = Config::load_with_diagnostics(new_path.to_str().unwrap()).unwrap();
        std::fs::remove_file(&new_path).ok();

        assert!(
            stale.peer_groups.is_empty(),
            "stale baseline must not have peer groups (preconditions)"
        );
        assert!(
            reloaded.peer_groups.contains_key("upstream"),
            "reloaded baseline must have the new peer_groups.upstream (preconditions)"
        );

        let (event_tx, event_rx) = mpsc::channel::<ConfigEvent>(8);
        let (replace_tx, replace_rx) = mpsc::unbounded_channel::<Box<Config>>();
        let (mutation_tx, mut mutation_rx) = mpsc::channel::<ConfigMutation>(8);

        let bridge = tokio::spawn(run_config_bridge(event_rx, replace_rx, mutation_tx, stale));

        // Push the SIGHUP-style replacement first.
        replace_tx.send(Box::new(reloaded.clone())).unwrap();
        // Then a gRPC mutation that adds a policy definition. If the
        // bridge missed the swap, this would compute against `stale`
        // and the resulting ReplaceConfig wouldn't carry the new
        // peer_groups.upstream entry.
        event_tx
            .send(ConfigEvent::SetPolicy {
                name: "block-private".to_string(),
                definition: NamedPolicyDefinition {
                    default_action: "deny".to_string(),
                    statements: Vec::new(),
                },
            })
            .await
            .unwrap();

        // First persister message is the replacement itself, but as a
        // no-persist refresh. The on-disk TOML is already the
        // operator's desired snapshot; rewriting it here would clobber
        // restart-required edits that runtime intentionally pinned.
        let replace_msg = mutation_rx.recv().await.expect("replacement forwarded");
        let ConfigMutation::RefreshSnapshotNoPersist(received_replace) = replace_msg else {
            panic!("bridge must forward replacement as RefreshSnapshotNoPersist");
        };
        assert!(
            received_replace.peer_groups.contains_key("upstream"),
            "replacement message must carry the new peer_groups.upstream"
        );

        // Second persister message is the post-event snapshot — must
        // contain BOTH the replacement-supplied peer_groups.upstream
        // AND the event-applied policy. If the bridge had missed the
        // swap, peer_groups.upstream would be absent (proving the
        // event applied to stale).
        let event_msg = mutation_rx.recv().await.expect("event forwarded");
        let ConfigMutation::ReplaceConfig(received_event) = event_msg else {
            panic!("bridge must forward event-derived snapshot as ReplaceConfig");
        };
        assert!(
            received_event.peer_groups.contains_key("upstream"),
            "post-event snapshot must still carry the replacement-supplied peer group — \
             absence here would mean the bridge applied the event to a stale snapshot"
        );
        assert!(
            received_event
                .policy
                .definitions
                .contains_key("block-private"),
            "post-event snapshot must carry the event-applied policy"
        );

        drop(replace_tx);
        drop(event_tx);
        bridge.await.unwrap();
    }

    async fn reload_then_persist_policy_after_desired_refresh(new_toml: &str) -> (Config, Config) {
        use rustbgpd_api::peer_types::{ConfigEvent, NamedPolicyDefinition};

        let path = unique_temp_path("reload-desired-refresh");
        std::fs::write(&path, baseline_toml()).unwrap();
        let initial = Config::load_with_diagnostics(path.to_str().unwrap()).unwrap();
        let live_grpc_tcp = initial.global.telemetry.grpc_tcp.clone();
        let live_grpc_uds = initial.global.telemetry.grpc_uds.clone();

        let (event_tx, event_rx) = mpsc::channel::<ConfigEvent>(8);
        let (replace_tx, replace_rx) = mpsc::unbounded_channel::<Box<Config>>();
        let (mutation_tx, mutation_rx) = mpsc::channel::<ConfigMutation>(8);
        let persister =
            tokio::spawn(ConfigPersister::new(mutation_rx, path.clone(), initial.clone()).run());
        let bridge = tokio::spawn(run_config_bridge(
            event_rx,
            replace_rx,
            mutation_tx,
            initial.clone(),
        ));

        std::fs::write(&path, new_toml).unwrap();
        let (peer_mgr_tx, _peer_mgr_rx) = mpsc::channel(8);
        let reloaded = reload_config(
            path.to_str().unwrap(),
            &initial,
            live_grpc_tcp.as_ref(),
            live_grpc_uds.as_ref(),
            &peer_mgr_tx,
            None,
        )
        .await
        .expect("reload should return pinned runtime plus desired config");

        let (peer_mgr_internal_tx, mut peer_mgr_internal_rx) =
            mpsc::unbounded_channel::<InternalCommand>();
        let runtime = apply_reload_outcome(reloaded, &peer_mgr_internal_tx, Some(&replace_tx))
            .await
            .expect("post-reload sync should succeed");
        assert!(
            peer_mgr_internal_rx.try_recv().is_ok(),
            "peer manager snapshot must be refreshed"
        );

        event_tx
            .send(ConfigEvent::SetPolicy {
                name: "after-reload".to_string(),
                definition: NamedPolicyDefinition {
                    default_action: "deny".to_string(),
                    statements: Vec::new(),
                },
            })
            .await
            .unwrap();

        drop(event_tx);
        drop(replace_tx);
        bridge.await.unwrap();
        persister.await.unwrap();

        let disk = Config::load_with_diagnostics(path.to_str().unwrap()).unwrap();
        std::fs::remove_file(&path).ok();
        assert!(
            disk.policy.definitions.contains_key("after-reload"),
            "gRPC-style mutation after SIGHUP must persist on top of refreshed desired base"
        );
        (runtime, disk)
    }

    #[tokio::test]
    async fn reload_pin_grpc_uds_preserves_desired_toml_for_later_persistence() {
        let new_toml = format!(
            "{}\n[global.telemetry.grpc_uds]\npath = \"/tmp/rustbgpd-edited.sock\"\n",
            baseline_toml()
        );
        let (runtime, disk) = reload_then_persist_policy_after_desired_refresh(&new_toml).await;

        assert_ne!(
            runtime.global.telemetry.grpc_uds, disk.global.telemetry.grpc_uds,
            "runtime must stay pinned to the live listener while disk keeps the operator edit"
        );
        assert_eq!(
            disk.global
                .telemetry
                .grpc_uds
                .as_ref()
                .unwrap()
                .path
                .as_deref(),
            Some("/tmp/rustbgpd-edited.sock")
        );
    }

    #[tokio::test]
    async fn reload_pin_apply_bum_preserves_desired_toml_for_later_persistence() {
        // Default is now true (v0.23.0 production-default flip); drive
        // the diff by opting out on the new side instead.
        let new_toml = format!("apply_bum_enforcement = false\n{}", baseline_toml());
        let (runtime, disk) = reload_then_persist_policy_after_desired_refresh(&new_toml).await;

        assert!(
            runtime.apply_bum_enforcement,
            "runtime must stay pinned to the live startup value (default true)"
        );
        assert!(
            !disk.apply_bum_enforcement,
            "desired/disk snapshot must reflect the new explicit opt-out"
        );
    }

    #[tokio::test]
    async fn reload_pin_evpn_instances_preserves_desired_toml_for_later_persistence() {
        let new_toml = format!(
            "{}\n[[evpn_instances]]\nvni = 100\nrd = \"65000:100\"\nroute_targets = [\"65000:100\"]\nlocal_vtep_ip = \"10.0.0.1\"\n",
            baseline_toml()
        );
        let (runtime, disk) = reload_then_persist_policy_after_desired_refresh(&new_toml).await;

        assert!(runtime.evpn_instances.is_empty());
        assert_eq!(disk.evpn_instances.len(), 1);
    }

    #[tokio::test]
    async fn reload_pin_blackhole_fib_preserves_desired_toml_for_later_persistence() {
        let new_toml = baseline_toml().replace(
            "listen_port = 179",
            "listen_port = 179\nhonor_blackhole = true\ninstall_blackhole_discard = true",
        );
        let (runtime, disk) = reload_then_persist_policy_after_desired_refresh(&new_toml).await;

        assert!(!runtime.global.honor_blackhole);
        assert!(!runtime.global.install_blackhole_discard);
        assert!(disk.global.honor_blackhole);
        assert!(disk.global.install_blackhole_discard);
    }

    // SoftResetIn-on-import-policy-change coverage is now PM-side:
    // `update_runtime_policies` fires `soft_reset_in` automatically
    // when import policy materially changes, for any peer in
    // `self.peers` (which includes dynamic peers — the original
    // motivation for moving this out of the binary's reload loop).
    // Asserting that behavior at this layer would require a real
    // `PeerManager` task with established peers; that level of
    // integration coverage belongs in `peer_manager::tests`. The
    // reload tests above already prove the SetPolicy / SetPeerGroup
    // / chain commands fire on the right edits — that's the seam
    // this layer can exercise without a real peer.

    /// Effective-impact must catch a *changed policy definition*
    /// referenced via the global `import_chain`, even when the chain
    /// list itself is unchanged. Regression for the reviewer's
    /// transitive-reference finding: prior heuristic only flagged
    /// changes when the chain list moved, missing the common edit
    /// shape where operators tweak a definition in place.
    #[test]
    fn effective_impact_flags_global_chain_policy_definition_change() {
        let old_toml = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179
[global.telemetry]
log_format = "json"

[policy.definitions.block-private]
default_action = "permit"

[policy]
import_chain = ["block-private"]

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
"#;
        let new_toml = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179
[global.telemetry]
log_format = "json"

[policy.definitions.block-private]
default_action = "deny"

[policy]
import_chain = ["block-private"]

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
"#;
        let path_a = unique_temp_path("eff-impact-global-old");
        let path_b = unique_temp_path("eff-impact-global-new");
        std::fs::write(&path_a, old_toml).unwrap();
        std::fs::write(&path_b, new_toml).unwrap();
        let old = Config::load_with_diagnostics(path_a.to_str().unwrap()).unwrap();
        let new = Config::load_with_diagnostics(path_b.to_str().unwrap()).unwrap();
        let diff = config::diff_config(&old, &new);
        let impacted: Vec<_> = diff
            .effective_neighbor_impact
            .iter()
            .map(|i| i.address.as_str())
            .collect();
        assert!(
            impacted.contains(&"10.0.0.2"),
            "neighbor must be flagged when a definition referenced via the unchanged global \
             import_chain changes — got {impacted:?}"
        );
        std::fs::remove_file(&path_a).ok();
        std::fs::remove_file(&path_b).ok();
    }

    /// Same shape but for a peer-group chain reference: a definition
    /// changes; the peer-group's chain list is unchanged; the
    /// peer-group record is unchanged. Members must still be flagged.
    #[test]
    fn effective_impact_flags_peer_group_chain_policy_definition_change() {
        let old_toml = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179
[global.telemetry]
log_format = "json"

[policy.definitions.block-private]
default_action = "permit"

[peer_groups.ix]
hold_time = 90
import_policy_chain = ["block-private"]

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
peer_group = "ix"
"#;
        let new_toml = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179
[global.telemetry]
log_format = "json"

[policy.definitions.block-private]
default_action = "deny"

[peer_groups.ix]
hold_time = 90
import_policy_chain = ["block-private"]

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
peer_group = "ix"
"#;
        let path_a = unique_temp_path("eff-impact-pg-chain-old");
        let path_b = unique_temp_path("eff-impact-pg-chain-new");
        std::fs::write(&path_a, old_toml).unwrap();
        std::fs::write(&path_b, new_toml).unwrap();
        let old = Config::load_with_diagnostics(path_a.to_str().unwrap()).unwrap();
        let new = Config::load_with_diagnostics(path_b.to_str().unwrap()).unwrap();
        let diff = config::diff_config(&old, &new);
        let impacted: Vec<_> = diff
            .effective_neighbor_impact
            .iter()
            .map(|i| i.address.as_str())
            .collect();
        assert!(
            impacted.contains(&"10.0.0.2"),
            "neighbor must be flagged when a definition referenced via its peer-group's \
             import_policy_chain changes — got {impacted:?}"
        );
        std::fs::remove_file(&path_a).ok();
        std::fs::remove_file(&path_b).ok();
    }

    /// Effective neighbor impact view: when only a peer-group field
    /// changes, the diff must flag every member neighbor as
    /// effectively impacted (cascade via inheritance) even though
    /// their direct neighbor records are unchanged.
    #[test]
    fn effective_impact_flags_peer_group_members() {
        let old_toml = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179
[global.telemetry]
log_format = "json"

[peer_groups.ix]
hold_time = 90

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
peer_group = "ix"

[[neighbors]]
address = "10.0.0.3"
remote_asn = 65003
peer_group = "ix"
"#;
        let new_toml = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179
[global.telemetry]
log_format = "json"

[peer_groups.ix]
hold_time = 60

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
peer_group = "ix"

[[neighbors]]
address = "10.0.0.3"
remote_asn = 65003
peer_group = "ix"
"#;
        let path_a = unique_temp_path("eff-impact-old");
        let path_b = unique_temp_path("eff-impact-new");
        std::fs::write(&path_a, old_toml).unwrap();
        std::fs::write(&path_b, new_toml).unwrap();
        let old = Config::load_with_diagnostics(path_a.to_str().unwrap()).unwrap();
        let new = Config::load_with_diagnostics(path_b.to_str().unwrap()).unwrap();
        let diff = config::diff_config(&old, &new);
        let impacted: Vec<_> = diff
            .effective_neighbor_impact
            .iter()
            .map(|i| i.address.as_str())
            .collect();
        assert!(
            impacted.contains(&"10.0.0.2") && impacted.contains(&"10.0.0.3"),
            "both ix members must be flagged as effectively impacted — got {impacted:?}"
        );
        std::fs::remove_file(&path_a).ok();
        std::fs::remove_file(&path_b).ok();
    }
}
