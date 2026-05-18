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
        remote_asn: tc.peer.remote_asn,
        description: label.to_string(),
        peer_group,
        hold_time: Some(tc.peer.hold_time),
        max_prefixes: tc.max_prefixes,
        md5_password: tc.md5_password.clone(),
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
    pub(crate) fn new(runtime: Config, desired: Config) -> Self {
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
    if new_config.fib_tables != current.fib_tables {
        error!(
            "[[fib_tables]] differs from the live config: the ADR-0061 \
             general unicast FIB reconciler is spawned only at startup. \
             Restart rustbgpd to apply [[fib_tables]] edits."
        );
        new_config.fib_tables.clone_from(&current.fib_tables);
    }
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

    let policy_diff = config::diff_policy(&current.policy, &new_config.policy);
    let peer_group_diff = config::diff_peer_groups(&current.peer_groups, &new_config.peer_groups);
    let diff = config::diff_neighbors(&current.neighbors, &new_config.neighbors);

    let neighbors_unchanged =
        diff.added.is_empty() && diff.removed.is_empty() && diff.changed.is_empty();
    let peer_groups_unchanged = peer_group_diff.added.is_empty()
        && peer_group_diff.removed.is_empty()
        && peer_group_diff.changed.is_empty();
    if !policy_diff.has_changes()
        && peer_groups_unchanged
        && neighbors_unchanged
        && !honor_graceful_shutdown_changed
        && !honor_blackhole_changed
    {
        info!("config reloaded — no neighbor / policy / peer-group changes detected");
        return Some(ReloadedConfig::new(new_config, desired_config));
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
        let peer_map: std::collections::HashMap<String, _> = peer_configs
            .into_iter()
            .map(|neighbor| {
                (
                    neighbor.transport_config.remote_addr.ip().to_string(),
                    neighbor,
                )
            })
            .collect();
        let resolve = |neighbors: &[config::Neighbor]| -> Vec<PeerManagerNeighborConfig> {
            neighbors
                .iter()
                .filter_map(|n| {
                    peer_map.get(&n.address).map(|neighbor| {
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
                        target = %failure.address,
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
