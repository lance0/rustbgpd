//! SIGHUP reload and config-persistence bridge support.
//!
//! This module owns the runtime config reload pipeline that used to live in
//! `main.rs`: gRPC config-event persistence, restart-required field pinning,
//! and ordered peer-manager reconciliation.

use std::collections::BTreeMap;
use std::fmt::Display;
use std::net::IpAddr;
use std::ops::Deref;

use rustbgpd_api::peer_types::{
    CatalogMutationError, ConfigEvent, ConfigPersistAck, ConfigPersistError, FibTableSnapshot,
    PeerManagerCommand, PeerManagerNeighborConfig,
};
use rustbgpd_policy::PolicyChain;
use tokio::sync::{mpsc, oneshot};
use tracing::{error, info, warn};

use rustbgpd_transport::{
    TcpAoKeyring, TcpAoListenerGeneration, TcpAoListenerHandle, TcpAoListenerKey,
    TcpAoListenerOwnerKind, TcpAoRotationGeneration, TcpAoRotationOperation, TcpAoRotationPhase,
    TcpAoRotationStatus,
};

use crate::config::{self, Config};
use crate::config_persister::ConfigMutation;
use crate::evpn_runtime_converger::EvpnRuntimeReloadApply;
use crate::fib_runtime::FibRuntimeCommand;
use crate::peer_manager::InternalCommand;
use crate::policy_admin::{self, apply_config_event, catalog_config_error};

/// Monotonic identity for one outbound prefix-limit transaction. Activation
/// is idempotent by it, so a retry cannot apply two recovery transitions.
pub(crate) fn next_outbound_prefix_limit_txn() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT: AtomicU64 = AtomicU64::new(1);
    NEXT.fetch_add(1, Ordering::Relaxed)
}

/// Preflight `config`'s outbound prefix maxima across every live peer and
/// hold them as an inactive prepared transaction (ADR-0113).
///
/// Nothing is applied: the running maxima, admission state, Adj-RIB-Out, and
/// wire state are untouched whether this succeeds or not. Failure names every
/// peer, family, current usage, and requested maximum that blocks the edit.
pub(crate) async fn prepare_outbound_prefix_limits(
    rib_tx: &mpsc::Sender<rustbgpd_rib::RibUpdate>,
    txn: u64,
    config: &Config,
) -> Result<(), String> {
    let (reply, rx) = oneshot::channel();
    rib_tx
        .send(rustbgpd_rib::RibUpdate::PrepareOutboundPrefixLimits {
            txn,
            config: config.outbound_prefix_limits(),
            reply,
        })
        .await
        .map_err(|_| "RIB manager unavailable".to_string())?;
    match rx.await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(violations)) => Err(format!(
            "outbound prefix limit rejected: {}",
            violations
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join("; ")
        )),
        Err(_) => Err("RIB manager dropped the outbound prefix-limit preflight".to_string()),
    }
}

/// Activate (or discard) a prepared outbound prefix-limit transaction.
pub(crate) async fn finish_outbound_prefix_limits(
    rib_tx: &mpsc::Sender<rustbgpd_rib::RibUpdate>,
    txn: u64,
    activate: bool,
) -> Result<(), String> {
    let (reply, rx) = oneshot::channel();
    rib_tx
        .send(rustbgpd_rib::RibUpdate::ApplyOutboundPrefixLimits {
            txn,
            activate,
            reply,
        })
        .await
        .map_err(|_| "RIB manager unavailable".to_string())?;
    rx.await
        .map_err(|_| "RIB manager dropped the outbound prefix-limit activation".to_string())?
}

/// Preflight and activate `config`'s outbound prefix maxima as one
/// transaction.
///
/// Startup and SIGHUP take this path: the operator's file is already the
/// desired state, so there is no persistence acknowledgement to wait for
/// between the two phases. The persisted v1 transaction path drives the same
/// pair around its own acknowledgement instead.
pub(crate) async fn apply_outbound_prefix_limits(
    rib_tx: &mpsc::Sender<rustbgpd_rib::RibUpdate>,
    config: &Config,
) -> Result<(), String> {
    let txn = next_outbound_prefix_limit_txn();
    match prepare_outbound_prefix_limits(rib_tx, txn, config).await {
        Ok(()) => finish_outbound_prefix_limits(rib_tx, txn, true).await,
        Err(error) => {
            let _ = finish_outbound_prefix_limits(rib_tx, txn, false).await;
            Err(error)
        }
    }
}

/// Build a `PeerManagerNeighborConfig` from transport config components.
pub(crate) fn build_peer_mgr_config(
    tc: &rustbgpd_transport::TransportConfig,
    max_prefix_restart_seconds: Option<u32>,
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
        min_hold_time: tc.peer.min_hold_time,
        send_hold_time: Some(tc.peer.send_hold_time),
        max_prefixes: tc.max_prefixes,
        max_prefixes_ipv4: tc.max_prefixes_ipv4,
        max_prefixes_ipv6: tc.max_prefixes_ipv6,
        max_prefix_restart_seconds,
        md5_password: tc.md5_password.clone(),
        tcp_ao: tc.tcp_ao.clone(),
        ttl_security: tc.ttl_security,
        families: tc.peer.families.clone(),
        required_families: tc.peer.required_families.clone(),
        graceful_restart: tc.peer.graceful_restart,
        gr_restart_time: tc.peer.gr_restart_time,
        gr_peer_restart_time_max: tc.gr_peer_restart_time_max,
        gr_stale_routes_time: tc.gr_stale_routes_time,
        llgr_stale_time: tc.llgr_stale_time,
        gr_restart_eligible: false,
        local_ipv6_nexthop: tc.local_ipv6_nexthop,
        route_reflector_client: tc.route_reflector_client,
        orr_vantage: tc.orr_vantage,
        route_server_client: tc.route_server_client,
        per_client_best: tc.per_client_best,
        next_hop_ownership_strict_peer: tc.next_hop_ownership_strict_peer,
        slow_peer_threshold_pct: tc.slow_peer_threshold_pct,
        slow_peer_duration: tc.slow_peer_duration,
        slow_peer_isolation: tc.slow_peer_isolation,
        interpret_rfc1997: tc.interpret_rfc1997,
        rs_control_communities: tc.rs_control_communities,
        remove_private_as: tc.remove_private_as,
        add_path_receive: tc.peer.add_path_receive,
        add_path_send: tc.peer.add_path_send,
        add_path_send_max: tc.peer.add_path_send_max,
        paths_limit_receive_max: tc.peer.paths_limit_receive_max,
        local_role: tc.peer.local_role,
        strict_role: tc.peer.strict_role,
        prefix_orf_receive: tc.peer.prefix_orf_receive,
        disable_ipv4_unicast: tc.peer.disable_ipv4_unicast,
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

struct TcpAoRotationPlan {
    generation: TcpAoRotationGeneration,
    operation: TcpAoRotationOperation,
    current_listener_keys: Vec<TcpAoListenerKey>,
    listener_keys: Vec<TcpAoListenerKey>,
    current_static_keyrings: Vec<(rustbgpd_api::peer_types::PeerKey, TcpAoKeyring)>,
    static_keyrings: Vec<(rustbgpd_api::peer_types::PeerKey, TcpAoKeyring)>,
}

enum TcpAoReloadPlan {
    Unchanged,
    Rotation(TcpAoRotationPlan),
    Unsupported(String),
}

fn keyring_is_append_only<T: PartialEq>(
    current: &[T],
    desired: &[T],
    current_selected: Option<usize>,
    desired_selected: Option<usize>,
) -> bool {
    desired.starts_with(current) && current_selected == desired_selected
}

fn selected_config_key_index(keyring: &config::TcpAoKeyringConfig) -> Option<usize> {
    keyring
        .0
        .iter()
        .position(|key| key.preferred)
        .or_else(|| keyring.0.iter().position(|key| !key.deprecated))
}

fn selected_transport_key_index(keyring: &TcpAoKeyring) -> Option<usize> {
    keyring
        .0
        .iter()
        .position(|key| key.preferred)
        .or_else(|| keyring.0.iter().position(|key| !key.deprecated))
}

fn transport_key_core_eq(
    current: &rustbgpd_transport::TcpAoConfig,
    desired: &rustbgpd_transport::TcpAoConfig,
) -> bool {
    current.key == desired.key
        && current.send_id == desired.send_id
        && current.recv_id == desired.recv_id
        && current.algorithm == desired.algorithm
}

fn config_key_core_eq(current: &config::TcpAoConfig, desired: &config::TcpAoConfig) -> bool {
    current.key == desired.key
        && current.send_id == desired.send_id
        && current.recv_id == desired.recv_id
        && current.algorithm == desired.algorithm
}

fn transport_keyring_is_selection(current: &TcpAoKeyring, desired: &TcpAoKeyring) -> bool {
    let desired_selected = selected_transport_key_index(desired);
    current.0.len() == desired.0.len()
        && current.0.iter().zip(&desired.0).all(|(current, desired)| {
            transport_key_core_eq(current, desired) && (!current.deprecated || desired.deprecated)
        })
        && selected_transport_key_index(current) != desired_selected
        && desired_selected.is_some_and(|index| desired.0[index].preferred)
}

fn config_keyring_is_selection(
    current: &config::TcpAoKeyringConfig,
    desired: &config::TcpAoKeyringConfig,
) -> bool {
    let desired_selected = selected_config_key_index(desired);
    current.0.len() == desired.0.len()
        && current.0.iter().zip(&desired.0).all(|(current, desired)| {
            config_key_core_eq(current, desired) && (!current.deprecated || desired.deprecated)
        })
        && selected_config_key_index(current) != desired_selected
        && desired_selected.is_some_and(|index| desired.0[index].preferred)
}

fn ordered_survivor_indices<T: PartialEq>(current: &[T], desired: &[T]) -> Option<Vec<usize>> {
    if desired.is_empty() || desired.len() >= current.len() {
        return None;
    }
    let mut survivors = Vec::with_capacity(desired.len());
    let mut search_from = 0;
    for desired_entry in desired {
        let matches = current
            .iter()
            .enumerate()
            .skip(search_from)
            .filter(|(_, current_entry)| *current_entry == desired_entry)
            .map(|(index, _)| index)
            .collect::<Vec<_>>();
        if matches.len() != 1 {
            return None;
        }
        survivors.push(matches[0]);
        search_from = matches[0] + 1;
    }
    Some(survivors)
}

fn transport_keyring_is_deletion(current: &TcpAoKeyring, desired: &TcpAoKeyring) -> bool {
    let Some(survivors) = ordered_survivor_indices(&current.0, &desired.0) else {
        return false;
    };
    current.selected() == desired.selected()
        && current
            .0
            .iter()
            .enumerate()
            .all(|(index, key)| survivors.contains(&index) || key.deprecated)
}

fn config_keyring_is_deletion(
    current: &config::TcpAoKeyringConfig,
    desired: &config::TcpAoKeyringConfig,
) -> bool {
    let Some(survivors) = ordered_survivor_indices(&current.0, &desired.0) else {
        return false;
    };
    selected_config_key_index(current)
        .zip(selected_config_key_index(desired))
        .is_some_and(|(current_index, desired_index)| {
            current.0[current_index] == desired.0[desired_index]
        })
        && current
            .0
            .iter()
            .enumerate()
            .all(|(index, key)| survivors.contains(&index) || key.deprecated)
}

#[expect(
    clippy::too_many_lines,
    reason = "the compiler must validate static and dynamic owner inventories together before issuing one immutable generation plan"
)]
fn prepare_tcp_ao_rotation_plan(
    current: &Config,
    desired: &Config,
    listener_status: &TcpAoRotationStatus,
) -> Result<TcpAoReloadPlan, String> {
    let current_resolved = current
        .resolved_neighbors()
        .map_err(|error| error.to_string())?;
    let desired_resolved = desired
        .resolved_neighbors()
        .map_err(|error| error.to_string())?;
    let static_map = |neighbors: &[config::ResolvedNeighbor]| {
        neighbors
            .iter()
            .filter_map(|neighbor| {
                let keyring = neighbor.transport_config.tcp_ao.clone()?;
                Some((
                    rustbgpd_api::peer_types::PeerKey::new(
                        neighbor.transport_config.remote_addr.ip(),
                        neighbor.transport_config.peer_interface.clone(),
                    ),
                    keyring,
                ))
            })
            .collect::<BTreeMap<_, _>>()
    };
    let current_static = static_map(&current_resolved);
    let desired_static = static_map(&desired_resolved);
    if current_static.keys().collect::<Vec<_>>() != desired_static.keys().collect::<Vec<_>>() {
        return Ok(TcpAoReloadPlan::Unsupported(
            "live TCP-AO rotation may not add or remove a protected static owner".to_string(),
        ));
    }

    let dynamic_map = |source: &Config| {
        source
            .dynamic_neighbors
            .iter()
            .filter_map(|range| {
                let keyring = range.tcp_ao.as_ref()?;
                let selector = config::effective_prefix_str(&range.prefix)?;
                Some((selector, keyring.clone()))
            })
            .collect::<BTreeMap<(IpAddr, u8), config::TcpAoKeyringConfig>>()
    };
    let current_dynamic = dynamic_map(current);
    let desired_dynamic = dynamic_map(desired);
    if current_dynamic.keys().collect::<Vec<_>>() != desired_dynamic.keys().collect::<Vec<_>>() {
        return Ok(TcpAoReloadPlan::Unsupported(
            "live TCP-AO rotation may not add, remove, or move a protected dynamic owner"
                .to_string(),
        ));
    }

    let mut saw_add_only = false;
    let mut saw_selection = false;
    let mut saw_delete = false;
    for (peer, old) in &current_static {
        let new = &desired_static[peer];
        if old == new {
            continue;
        }
        if keyring_is_append_only(
            &old.0,
            &new.0,
            selected_transport_key_index(old),
            selected_transport_key_index(new),
        ) && !new.0[old.0.len()..].iter().any(|key| key.preferred)
        {
            saw_add_only = true;
        } else if transport_keyring_is_selection(old, new) {
            saw_selection = true;
        } else if transport_keyring_is_deletion(old, new) {
            saw_delete = true;
        } else {
            return Ok(TcpAoReloadPlan::Unsupported(format!(
                "protected static peer {peer} changes an existing key, order, removal, or unsupported metadata"
            )));
        }
    }
    for (selector, old) in &current_dynamic {
        let new = &desired_dynamic[selector];
        if old == new {
            continue;
        }
        if keyring_is_append_only(
            &old.0,
            &new.0,
            selected_config_key_index(old),
            selected_config_key_index(new),
        ) && !new.0[old.0.len()..].iter().any(|key| key.preferred)
        {
            saw_add_only = true;
        } else if config_keyring_is_selection(old, new) {
            saw_selection = true;
        } else if config_keyring_is_deletion(old, new) {
            saw_delete = true;
        } else {
            return Ok(TcpAoReloadPlan::Unsupported(format!(
                "protected dynamic owner {}/{} changes an existing key, order, removal, or unsupported metadata",
                selector.0, selector.1
            )));
        }
    }
    if usize::from(saw_add_only) + usize::from(saw_selection) + usize::from(saw_delete) > 1 {
        return Ok(TcpAoReloadPlan::Unsupported(
            "one TCP-AO generation may perform only one of add, select, or delete".to_string(),
        ));
    }
    let recovering_operation = match listener_status.phase {
        TcpAoRotationPhase::AddOnly | TcpAoRotationPhase::AddOnlyFailed => {
            Some(TcpAoRotationOperation::AddOnly)
        }
        TcpAoRotationPhase::Selecting
        | TcpAoRotationPhase::AwaitingPeer
        | TcpAoRotationPhase::SelectionFailed => Some(TcpAoRotationOperation::Selection),
        TcpAoRotationPhase::Deleting | TcpAoRotationPhase::DeleteFailed => {
            Some(TcpAoRotationOperation::Delete)
        }
        TcpAoRotationPhase::Idle => None,
    };
    let operation = if saw_delete {
        Some(TcpAoRotationOperation::Delete)
    } else if saw_selection {
        Some(TcpAoRotationOperation::Selection)
    } else if saw_add_only {
        Some(TcpAoRotationOperation::AddOnly)
    } else {
        recovering_operation
    };
    let Some(operation) = operation else {
        return Ok(TcpAoReloadPlan::Unchanged);
    };
    if recovering_operation.is_some_and(|retained| retained != operation) {
        return Ok(TcpAoReloadPlan::Unsupported(
            "TCP-AO retry changed the retained generation operation or full desired inventory"
                .to_string(),
        ));
    }

    let generation = if recovering_operation.is_some() {
        listener_status.desired
    } else {
        listener_status
            .applied
            .next()
            .ok_or_else(|| "TCP-AO rotation generation exhausted".to_string())?
    };
    let listen_addr = current.listen_addr();
    let mut listener_keys: Vec<TcpAoListenerKey> =
        desired_resolved
            .iter()
            .filter_map(|neighbor| crate::tcp_ao_listener_key_for_neighbor(listen_addr, neighbor))
            .chain(desired.dynamic_neighbors.iter().filter_map(|range| {
                crate::tcp_ao_listener_key_for_dynamic_range(listen_addr, range)
            }))
            .collect();
    listener_keys.sort_by_key(|key| {
        let owner = match key.owner {
            TcpAoListenerOwnerKind::Static => 0_u8,
            TcpAoListenerOwnerKind::Dynamic => 1_u8,
        };
        (key.peer, key.prefix_len, owner)
    });
    let mut current_listener_keys =
        current_resolved
            .iter()
            .filter_map(|neighbor| crate::tcp_ao_listener_key_for_neighbor(listen_addr, neighbor))
            .chain(current.dynamic_neighbors.iter().filter_map(|range| {
                crate::tcp_ao_listener_key_for_dynamic_range(listen_addr, range)
            }))
            .collect::<Vec<_>>();
    current_listener_keys.sort_by_key(|key| {
        let owner = match key.owner {
            TcpAoListenerOwnerKind::Static => 0_u8,
            TcpAoListenerOwnerKind::Dynamic => 1_u8,
        };
        (key.peer, key.prefix_len, owner)
    });
    let current_static_keyrings = current_static.into_iter().collect();
    let static_keyrings = desired_static.into_iter().collect();
    Ok(TcpAoReloadPlan::Rotation(TcpAoRotationPlan {
        generation,
        operation,
        current_listener_keys,
        listener_keys,
        current_static_keyrings,
        static_keyrings,
    }))
}

async fn send_tcp_ao_preflight(
    peer_mgr_tx: &mpsc::Sender<PeerManagerCommand>,
    plan: &TcpAoRotationPlan,
) -> Result<(), String> {
    send_pm_step(peer_mgr_tx, |reply| {
        PeerManagerCommand::PreflightTcpAoRotation {
            generation: plan.generation,
            operation: plan.operation,
            listener_keys: plan.listener_keys.clone(),
            current_listener_keys: plan.current_listener_keys.clone(),
            static_keyrings: plan.static_keyrings.clone(),
            current_static_keyrings: plan.current_static_keyrings.clone(),
            reply,
        }
    })
    .await
}

async fn send_tcp_ao_apply(
    peer_mgr_tx: &mpsc::Sender<PeerManagerCommand>,
    plan: &TcpAoRotationPlan,
) -> Result<(), String> {
    send_pm_step(peer_mgr_tx, |reply| {
        PeerManagerCommand::ApplyTcpAoRotation {
            generation: plan.generation,
            operation: plan.operation,
            listener_keys: plan.listener_keys.clone(),
            current_listener_keys: plan.current_listener_keys.clone(),
            static_keyrings: plan.static_keyrings.clone(),
            current_static_keyrings: plan.current_static_keyrings.clone(),
            reply,
        }
    })
    .await
}

async fn mark_tcp_ao_failed(
    peer_mgr_tx: &mpsc::Sender<PeerManagerCommand>,
    generation: TcpAoRotationGeneration,
    operation: TcpAoRotationOperation,
    error: String,
) {
    let result = send_pm_step(peer_mgr_tx, |reply| {
        PeerManagerCommand::MarkTcpAoRotationFailed {
            generation,
            operation,
            error,
            reply,
        }
    })
    .await;
    if let Err(mark_error) = result {
        warn!(%mark_error, "failed to publish TCP-AO rotation failure to peer status");
    }
}

fn copy_tcp_ao_runtime_fields(target: &mut Config, source: &Config) {
    for neighbor in &mut target.neighbors {
        if let Some(desired) = source.neighbors.iter().find(|candidate| {
            candidate.address == neighbor.address && candidate.interface == neighbor.interface
        }) {
            neighbor.tcp_ao.clone_from(&desired.tcp_ao);
        }
    }
    for range in &mut target.dynamic_neighbors {
        let selector = config::effective_prefix_str(&range.prefix);
        if let Some(desired) = source
            .dynamic_neighbors
            .iter()
            .find(|candidate| config::effective_prefix_str(&candidate.prefix) == selector)
        {
            range.tcp_ao.clone_from(&desired.tcp_ao);
        }
    }
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

fn evpn_runtime_changed(new_config: &Config, current: &Config) -> bool {
    new_config.evpn_instances != current.evpn_instances
        || new_config.evpn_ip_vrfs != current.evpn_ip_vrfs
        || new_config.ethernet_segments != current.ethernet_segments
}

fn copy_evpn_runtime_fields(target: &mut Config, source: &Config) {
    target.evpn_instances.clone_from(&source.evpn_instances);
    target.evpn_ip_vrfs.clone_from(&source.evpn_ip_vrfs);
    target
        .ethernet_segments
        .clone_from(&source.ethernet_segments);
}

async fn send_pm_result_step<E: Display>(
    peer_mgr_tx: &mpsc::Sender<PeerManagerCommand>,
    build: impl FnOnce(oneshot::Sender<Result<(), E>>) -> PeerManagerCommand,
) -> Result<(), String> {
    let (reply_tx, reply_rx) = oneshot::channel();
    if let Err(e) = peer_mgr_tx.send(build(reply_tx)).await {
        return Err(format!("send to peer manager failed: {e}"));
    }
    match reply_rx.await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) => Err(error.to_string()),
        Err(e) => Err(format!("peer manager dropped reply: {e}")),
    }
}

/// Send a single `PeerManagerCommand` and await its `Result<(), String>`
/// reply. Maps both channel-send and dropped-reply errors to a single
/// `String` so callers can record one structured failure per step.
async fn send_pm_step(
    peer_mgr_tx: &mpsc::Sender<PeerManagerCommand>,
    build: impl FnOnce(oneshot::Sender<Result<(), String>>) -> PeerManagerCommand,
) -> Result<(), String> {
    send_pm_result_step(peer_mgr_tx, build).await
}

/// Send a catalog mutation command and convert its typed error to reload's
/// existing string-shaped step failure.
async fn send_catalog_pm_step(
    peer_mgr_tx: &mpsc::Sender<PeerManagerCommand>,
    build: impl FnOnce(oneshot::Sender<Result<(), CatalogMutationError>>) -> PeerManagerCommand,
) -> Result<(), String> {
    send_pm_result_step(peer_mgr_tx, build).await
}

/// Read the peer manager's current runtime config snapshot.
///
/// SIGHUP callers take the shared runtime-config coordinator before calling
/// this helper, so any transaction that acquired the same lock first has
/// already staged its accepted snapshot. That makes the returned config the
/// correct live baseline for reload diffing.
pub(crate) async fn runtime_config_snapshot(
    peer_mgr_tx: &mpsc::Sender<PeerManagerCommand>,
) -> Result<Config, String> {
    let (reply_tx, reply_rx) = oneshot::channel();
    peer_mgr_tx
        .send(PeerManagerCommand::RuntimeConfigSnapshot { reply: reply_tx })
        .await
        .map_err(|e| format!("send to peer manager failed: {e}"))?;
    let snapshot = reply_rx
        .await
        .map_err(|e| format!("peer manager dropped runtime snapshot reply: {e}"))??;
    let mut config = Config::load_toml_with_diagnostics(&snapshot.toml, "runtime config snapshot")?;
    // Overlay the LIVE compiled `.rpol` registry (ADR-0096): loading
    // the TOML recompiled the `.rpol` files from disk, which would
    // mask exactly the disk edits a reload diff must detect (both
    // sides would see the new content). The registry the daemon is
    // actually running is the one the snapshot reply carries.
    config.policy.rpol_files = snapshot.rpol_files;
    config.policy.rpol = snapshot.rpol;
    Ok(config)
}

fn fib_table_snapshots(tables: &[config::FibTableConfig]) -> Vec<FibTableSnapshot> {
    tables
        .iter()
        .map(|table| FibTableSnapshot {
            name: table.name.clone(),
            table_id: table.table_id,
            metric: table.metric,
            families: table.families.clone(),
            allowed_peer_groups: table.allowed_peer_groups.clone(),
            allowed_neighbors: table.allowed_neighbors.clone(),
            max_routes: table.max_routes,
            maximum_paths: table.maximum_paths,
            maximum_paths_ebgp: table.maximum_paths_ebgp,
            maximum_paths_ibgp: table.maximum_paths_ibgp,
        })
        .collect()
}

fn take_config_event_ack(event: &mut ConfigEvent) -> Option<ConfigPersistAck> {
    match event {
        ConfigEvent::FibTablesReplaced { ack, .. }
        | ConfigEvent::NeighborAdded { ack, .. }
        | ConfigEvent::NeighborDeleted { ack, .. }
        | ConfigEvent::DynamicNeighborAdded { ack, .. }
        | ConfigEvent::DynamicNeighborDeleted { ack, .. }
        | ConfigEvent::ConfigTransactionCommitted { ack, .. }
        | ConfigEvent::SetPolicy { ack, .. }
        | ConfigEvent::DeletePolicy { ack, .. }
        | ConfigEvent::SetNeighborSet { ack, .. }
        | ConfigEvent::DeleteNeighborSet { ack, .. }
        | ConfigEvent::SetGlobalImportChain { ack, .. }
        | ConfigEvent::SetGlobalExportChain { ack, .. }
        | ConfigEvent::ClearGlobalImportChain { ack, .. }
        | ConfigEvent::ClearGlobalExportChain { ack, .. }
        | ConfigEvent::SetNeighborImportChain { ack, .. }
        | ConfigEvent::SetNeighborExportChain { ack, .. }
        | ConfigEvent::ClearNeighborImportChain { ack, .. }
        | ConfigEvent::ClearNeighborExportChain { ack, .. }
        | ConfigEvent::SetPeerGroup { ack, .. }
        | ConfigEvent::DeletePeerGroup { ack, .. }
        | ConfigEvent::SetNeighborPeerGroup { ack, .. }
        | ConfigEvent::ClearNeighborPeerGroup { ack, .. } => ack.take(),
    }
}

async fn set_pm_fib_tables_snapshot(
    peer_mgr_tx: &mpsc::Sender<PeerManagerCommand>,
    tables: &[config::FibTableConfig],
) -> Result<(), String> {
    let (reply_tx, reply_rx) = oneshot::channel();
    peer_mgr_tx
        .send(PeerManagerCommand::SetFibTablesSnapshot {
            tables: fib_table_snapshots(tables),
            reply: reply_tx,
        })
        .await
        .map_err(|e| format!("send to peer manager failed: {e}"))?;
    reply_rx
        .await
        .map_err(|e| format!("peer manager dropped reply: {e}"))
}

/// What the bridge should do with its held snapshot after an acknowledged
/// config event.
enum AckedPersistOutcome {
    /// The candidate is on disk; adopt it as the bridge snapshot.
    Applied,
    /// Nothing was written; keep the previous snapshot.
    Rejected,
    /// The persister is gone; the bridge has nothing left to do.
    PersisterLost,
}

async fn persister_round_trip(rx: oneshot::Receiver<Result<(), String>>) -> Result<(), String> {
    rx.await
        .map_err(|_| "config persister dropped persistence acknowledgement".to_string())
        .and_then(|result| result)
}

/// Drive one acknowledged config event through the persister.
///
/// The two-phase form is the contract that makes a rejected mutation
/// invisible: the candidate is durably staged and acknowledged *before* the
/// caller touches runtime state, so a persistence failure is reported while
/// the live sessions, their counters, and their metric series are still
/// untouched. The caller then either returns its commit channel — publishing
/// the staged write — or drops it, discarding the stage.
async fn persist_acknowledged(
    mutation_tx: &mpsc::Sender<ConfigMutation>,
    candidate: Config,
    ack: ConfigPersistAck,
) -> AckedPersistOutcome {
    let ConfigPersistAck { staged, commit } = ack;
    let Some(commit) = commit else {
        // Single-phase: the caller owns its own apply/rollback executor and
        // asked for one durable write with one acknowledgement.
        let (persist_ack_tx, persist_ack_rx) = oneshot::channel();
        if mutation_tx
            .send(ConfigMutation::ReplaceConfigAck(
                Box::new(candidate),
                persist_ack_tx,
            ))
            .await
            .is_err()
        {
            let _ = staged.send(Err(ConfigPersistError::Write(
                "config persister unavailable".to_string(),
            )));
            return AckedPersistOutcome::PersisterLost;
        }
        let result = persister_round_trip(persist_ack_rx).await;
        let applied = result.is_ok();
        let _ = staged.send(result.map_err(ConfigPersistError::Write));
        return if applied {
            AckedPersistOutcome::Applied
        } else {
            AckedPersistOutcome::Rejected
        };
    };

    let (stage_ack_tx, stage_ack_rx) = oneshot::channel();
    if mutation_tx
        .send(ConfigMutation::StageConfigAck(
            Box::new(candidate),
            stage_ack_tx,
        ))
        .await
        .is_err()
    {
        let _ = staged.send(Err(ConfigPersistError::Write(
            "config persister unavailable".to_string(),
        )));
        return AckedPersistOutcome::PersisterLost;
    }
    let stage_result = persister_round_trip(stage_ack_rx).await;
    let stage_ok = stage_result.is_ok();
    let _ = staged.send(stage_result.map_err(ConfigPersistError::Write));
    if !stage_ok {
        return AckedPersistOutcome::Rejected;
    }

    // The caller is applying its runtime change. A dropped commit channel
    // means that apply failed, or the caller is gone: either way the staged
    // write must not land.
    let Ok(commit_reply) = commit.await else {
        let _ = mutation_tx.send(ConfigMutation::DiscardStagedConfig).await;
        return AckedPersistOutcome::Rejected;
    };
    let (commit_ack_tx, commit_ack_rx) = oneshot::channel();
    if mutation_tx
        .send(ConfigMutation::CommitStagedConfig(commit_ack_tx))
        .await
        .is_err()
    {
        let _ = commit_reply.send(Err("config persister unavailable".to_string()));
        return AckedPersistOutcome::PersisterLost;
    }
    let result = persister_round_trip(commit_ack_rx).await;
    let applied = result.is_ok();
    let _ = commit_reply.send(result);
    if applied {
        AckedPersistOutcome::Applied
    } else {
        AckedPersistOutcome::Rejected
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
                    Some(mut event) => {
                        let event_ack = take_config_event_ack(&mut event);
                        // Apply to a candidate clone and commit only on success,
                        // so a validation failure can't leave the live snapshot
                        // partially mutated (poisoned) for the next event.
                        let candidate_result = if let ConfigEvent::ConfigTransactionCommitted {
                            candidate_toml,
                            ..
                        } = &event
                        {
                            Config::load_toml_with_diagnostics(
                                candidate_toml,
                                "committed config transaction",
                            )
                            .map_err(|error| CatalogMutationError::invalid(error.clone()))
                        } else {
                            let mut candidate = current_config.clone();
                            match apply_config_event(&mut candidate, &event) {
                                Ok(()) => Ok(candidate),
                                // Staging now runs before the caller's runtime
                                // change, so this is where a bad request is
                                // caught. Carry the same typed error the
                                // runtime apply would have produced so the
                                // caller keeps its NOT_FOUND / INVALID_ARGUMENT
                                // answer instead of reporting a persistence
                                // fault for a request that was simply wrong.
                                Err(error) => Err(catalog_config_error(error)),
                            }
                        };
                        let candidate = match candidate_result {
                            Ok(candidate) => candidate,
                            Err(error) => {
                            error!(error = %error, "rejected config event before persistence");
                            if let Some(ack) = event_ack {
                                let _ = ack.staged.send(Err(ConfigPersistError::Rejected(error)));
                            }
                            continue;
                            }
                        };
                        if let Some(ack) = event_ack {
                            match persist_acknowledged(&mutation_tx, candidate.clone(), ack).await {
                                AckedPersistOutcome::Applied => current_config = candidate,
                                AckedPersistOutcome::Rejected => {}
                                AckedPersistOutcome::PersisterLost => break,
                            }
                        } else {
                            current_config = candidate;
                            if mutation_tx
                                .send(ConfigMutation::ReplaceConfig(Box::new(current_config.clone())))
                                .await
                                .is_err()
                            {
                                break;
                            }
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
    // Acknowledge the snapshot so the caller (holding the FIB coordinator lock)
    // doesn't release the lock until the peer manager has actually assigned
    // `current_config`. Otherwise a following gRPC FIB-table CRUD could enqueue
    // its own snapshot on the separate peer-manager channel and have it
    // overtaken by this one, reverting the just-applied table set.
    let (ack_tx, ack_rx) = oneshot::channel();
    if peer_mgr_internal_tx
        .send(InternalCommand::ReplaceConfigSnapshot {
            config: Box::new(reloaded.runtime.clone()),
            ack: Some(ack_tx),
        })
        .is_err()
    {
        return Err("peer_mgr_snapshot");
    }
    if ack_rx.await.is_err() {
        return Err("peer_mgr_snapshot");
    }
    if let Some(tx) = bridge_replace_tx
        && tx.send(Box::new(reloaded.desired.clone())).is_err()
    {
        return Err("config_bridge");
    }

    // Per-peer `log_level` is a LIVE field (reload matrix): re-apply the
    // tracing filter so level edits take effect without a restart. This is
    // the single choke point every successful reload flows through, so it
    // catches a log_level change regardless of which diff bucket carried it.
    // Directives come from the operator's on-disk `desired` config (the
    // live intent for this live field); the telemetry layer rebuilds the
    // full filter (RUST_LOG base + all per-peer directives), so the global
    // base level always survives. Reapplying identical directives is a
    // no-op; a malformed directive leaves the live filter untouched. A
    // failure here is non-fatal — the config is already committed — so warn
    // rather than unwind the reload.
    if let Err(error) =
        rustbgpd_telemetry::reload_per_peer_directives(&reloaded.desired.per_peer_log_directives())
    {
        warn!(error = %error, "failed to re-apply per-peer log_level filter on config reload");
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
#[cfg(test)]
fn explicit_tier_test_toml(source: &str) -> String {
    if source.contains("[security.grpc") {
        source.to_string()
    } else {
        crate::test_support::tier_authorized_uds_test_config(source)
    }
}

#[cfg(test)]
fn write_tier_test_config(path: &std::path::Path, source: &str) {
    std::fs::write(path, explicit_tier_test_toml(source)).unwrap();
}

#[cfg(test)]
fn load_tier_test_config(path: &std::path::Path) -> Config {
    let source = std::fs::read_to_string(path).unwrap();
    write_tier_test_config(path, &source);
    let config = Config::load_with_diagnostics(path.to_str().unwrap()).unwrap();
    crate::test_support::assert_tier_authorized_test_config(&config);
    config
}

#[cfg(test)]
fn load_tier_test_toml(source: &str, source_name: &str) -> Config {
    let source = explicit_tier_test_toml(source);
    let config = Config::load_toml_with_diagnostics(&source, source_name).unwrap();
    crate::test_support::assert_tier_authorized_test_config(&config);
    config
}

#[cfg(test)]
pub(crate) async fn reload_config(
    config_path: &str,
    current: &Config,
    live_grpc_tcp: Option<&config::GrpcTcpListenerConfig>,
    live_grpc_uds: Option<&config::GrpcUdsListenerConfig>,
    peer_mgr_tx: &mpsc::Sender<PeerManagerCommand>,
    fib_cmd_tx: Option<&mpsc::Sender<FibRuntimeCommand>>,
    evpn_runtime_apply: Option<&EvpnRuntimeReloadApply>,
) -> Option<ReloadedConfig> {
    let config_path = std::path::Path::new(config_path);
    let source = std::fs::read_to_string(config_path).unwrap();
    write_tier_test_config(config_path, &source);
    reload_config_with_tcp_ao(
        config_path.to_str().unwrap(),
        current,
        live_grpc_tcp,
        live_grpc_uds,
        peer_mgr_tx,
        fib_cmd_tx,
        evpn_runtime_apply,
        None,
    )
    .await
}

#[expect(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "reload threads live subsystem handles, ordered reconciliation, and failure aggregation through one transaction coordinator"
)]
pub(crate) async fn reload_config_with_tcp_ao(
    config_path: &str,
    current: &Config,
    live_grpc_tcp: Option<&config::GrpcTcpListenerConfig>,
    live_grpc_uds: Option<&config::GrpcUdsListenerConfig>,
    peer_mgr_tx: &mpsc::Sender<PeerManagerCommand>,
    fib_cmd_tx: Option<&mpsc::Sender<FibRuntimeCommand>>,
    evpn_runtime_apply: Option<&EvpnRuntimeReloadApply>,
    tcp_ao_listener: Option<&TcpAoListenerHandle>,
) -> Option<ReloadedConfig> {
    // LAN-305: parse dataset contents against the running binding schema, but
    // stage changed data and refresh errors on detached candidate handles.
    // Shared live handles are committed only after the complete no-side-effect
    // preflight below, so a rejected authentication-boundary reload cannot
    // leak new policy data into running chains.
    let mut desired_config = match Config::load_with_diagnostics_and_staged_datasets(
        config_path,
        &current.policy.dataset_bindings,
    ) {
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
             Restart rustbgpd to apply path/auth-mode changes. Credential \
             bytes behind unchanged token/TLS paths rotate independently \
             on SIGHUP."
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

    // Compile the immutable TCP-AO candidate before pinning, but do not touch
    // a socket or session yet. The fully pinned runtime candidate must pass
    // validation below before the first external mutation.
    let tcp_ao_rotation_plan = if let Some(listener) = tcp_ao_listener {
        match prepare_tcp_ao_rotation_plan(current, &new_config, &listener.status()) {
            Ok(plan) => plan,
            Err(error) => {
                error!(%error, "failed to compile TCP-AO rotation generation");
                return None;
            }
        }
    } else {
        TcpAoReloadPlan::Unchanged
    };
    if let TcpAoReloadPlan::Unsupported(reason) = &tcp_ao_rotation_plan {
        let retained = tcp_ao_listener.is_some_and(|listener| {
            matches!(
                listener.status().phase,
                TcpAoRotationPhase::AddOnly
                    | TcpAoRotationPhase::AddOnlyFailed
                    | TcpAoRotationPhase::Selecting
                    | TcpAoRotationPhase::AwaitingPeer
                    | TcpAoRotationPhase::SelectionFailed
                    | TcpAoRotationPhase::Deleting
                    | TcpAoRotationPhase::DeleteFailed
            )
        });
        if retained {
            error!(%reason, "TCP-AO reload changed a retained immutable generation; halting before unrelated reload work");
            return None;
        }
        error!(%reason, "TCP-AO reload is outside the ordered live-rotation phases; retaining restart-pinned runtime inventory");
    }
    let tcp_ao_rotation_candidate = matches!(&tcp_ao_rotation_plan, TcpAoReloadPlan::Rotation(_));

    // TCP-AO edits outside the successfully committed ordered rotation shapes remain
    // pinned. Static and dynamic pinning run in separate passes, so their
    // combination can synthesize a new authentication-boundary conflict.
    // For example, a desired reload may remove a protected dynamic range and
    // add a plaintext static peer inside it; restoring the live range must
    // not then hot-add that peer without AO. Reject before EVPN or any other
    // runtime actor can mutate so a rejected reload leaves no partial state.
    let tcp_ao_pinned_neighbors = if tcp_ao_rotation_candidate {
        0
    } else {
        config::pin_tcp_ao_startup_only_runtime(&mut new_config, current)
    };
    if tcp_ao_pinned_neighbors > 0 {
        error!(
            neighbors = tcp_ao_pinned_neighbors,
            "[[neighbors]].tcp_ao is outside the live ordered rotation shapes: \
             restart rustbgpd to add/remove owners or edit/reorder keys. Only deprecated, \
             unselected keys can be deleted live, and add/select/delete cannot be combined. Peer-group and policy dependencies \
             referenced by pinned TCP-AO neighbors, plus restart-required global fields \
             that affect neighbor validation, are also kept at their live startup values \
             for this reload."
        );
    }

    let pinned_dynamic_tcp_ao = if tcp_ao_rotation_candidate {
        0
    } else {
        config::pin_dynamic_tcp_ao_startup_only(&mut new_config, current)
    };
    if pinned_dynamic_tcp_ao > 0 {
        error!(
            ranges = pinned_dynamic_tcp_ao,
            "[[dynamic_neighbors]].tcp_ao is outside the live ordered rotation shapes: \
             protected range CRUD and overlapping replacements remain pinned to the live \
             snapshot. Restart rustbgpd to add, remove, move, edit, or reorder \
             dynamic TCP-AO keys; only deprecated, unselected keys can be deleted live, \
             and add/select/delete cannot be combined."
        );
    }

    if let Err(error) = new_config.validate() {
        error!(
            error = %error,
            "reload pinning produced an invalid runtime configuration; refusing reload before any runtime actor mutation. Restart rustbgpd to change TCP-AO authentication boundaries"
        );
        return None;
    }

    // TCP-AO rotation is the first fallible external apply. The
    // complete pinned candidate is valid now; preflight every managed session,
    // then commit listener and session inventories in that order.
    let mut tcp_ao_rotation_applied = false;
    if let TcpAoReloadPlan::Rotation(plan) = &tcp_ao_rotation_plan {
        let listener = tcp_ao_listener.expect("TCP-AO plan requires a listener handle");
        let desired_listener =
            TcpAoListenerGeneration::new(plan.generation, plan.listener_keys.clone());
        let listener_preflight = match plan.operation {
            TcpAoRotationOperation::AddOnly => {
                listener.preflight_add_only(desired_listener.clone()).await
            }
            TcpAoRotationOperation::Selection => {
                listener.preflight_selection(desired_listener.clone()).await
            }
            TcpAoRotationOperation::Delete => {
                listener.preflight_delete(desired_listener.clone()).await
            }
        };
        if let Err(error) = listener_preflight {
            mark_tcp_ao_failed(
                peer_mgr_tx,
                plan.generation,
                plan.operation,
                error.to_string(),
            )
            .await;
            error!(error = %error, "TCP-AO generation rejected during complete listener kernel preflight");
            return None;
        }
        if let Err(error) = send_tcp_ao_preflight(peer_mgr_tx, plan).await {
            error!(error = %error, "TCP-AO generation rejected during global session preflight");
            return None;
        }
        let listener_apply = match plan.operation {
            TcpAoRotationOperation::AddOnly => listener.apply_add_only(desired_listener).await,
            TcpAoRotationOperation::Selection => listener.begin_selection(desired_listener).await,
            TcpAoRotationOperation::Delete => listener.apply_delete(desired_listener).await,
        };
        if let Err(error) = listener_apply {
            mark_tcp_ao_failed(
                peer_mgr_tx,
                plan.generation,
                plan.operation,
                error.to_string(),
            )
            .await;
            error!(error = %error, "TCP-AO generation failed on listener; retry the identical generation unless the error reports failed exact prior-inventory restoration, in which case restart rustbgpd");
            return None;
        }
        if let Err(error) = send_tcp_ao_apply(peer_mgr_tx, plan).await {
            if plan.operation == TcpAoRotationOperation::Selection
                && error.starts_with(crate::peer_manager::TCP_AO_AWAITING_PEER_PREFIX)
            {
                if let Err(marker_error) = listener
                    .mark_awaiting_peer(plan.generation, error.clone())
                    .await
                {
                    warn!(error = %marker_error, "TCP-AO listener awaiting-peer marker was not acknowledged");
                }
                info!(error = %error, generation = plan.generation.as_u64(), "TCP-AO successor selected; peer-use observation remains pending until a later identical SIGHUP");
                return None;
            }
            if let Err(marker_error) = listener
                .mark_dependent_failure(plan.generation, error.clone())
                .await
            {
                warn!(error = %marker_error, "TCP-AO listener dependent-failure marker was not acknowledged; staged generation remains globally uncommitted");
            }
            error!(error = %error, "TCP-AO generation failed on an established session; listener accepts remain generation-fenced until retry");
            return None;
        }
        if plan.operation == TcpAoRotationOperation::Selection
            && let Err(error) = listener.finalize_selection(plan.generation).await
        {
            mark_tcp_ao_failed(
                peer_mgr_tx,
                plan.generation,
                plan.operation,
                error.to_string(),
            )
            .await;
            error!(error = %error, "TCP-AO session cohort observed successor use, but listener metadata commit failed; retrying the identical generation is required");
            return None;
        }
        if let Err(error) = listener.acknowledge_global_commit(plan.generation).await {
            mark_tcp_ao_failed(
                peer_mgr_tx,
                plan.generation,
                plan.operation,
                error.to_string(),
            )
            .await;
            error!(error = %error, "TCP-AO generation reached sessions but listener global commit acknowledgement failed; retrying the same immutable generation is required");
            return None;
        }
        tcp_ao_rotation_applied = true;
        info!(
            generation = plan.generation.as_u64(),
            operation = ?plan.operation,
            "TCP-AO generation applied to listener and established sessions"
        );
    }

    let dataset_commit = desired_config.prepare_staged_datasets(&current.policy.dataset_bindings);
    let dataset_commit_pending = !dataset_commit.is_empty();
    new_config.policy.dataset_bindings = desired_config.policy.dataset_bindings.clone();
    new_config.policy.dataset_events = desired_config.policy.dataset_events.clone();

    if let Some(apply) = evpn_runtime_apply {
        let attempt = apply
            .apply_config_if_changed(&desired_config, evpn_runtime_changed)
            .await;
        match attempt.result {
            Ok(Some(result)) => {
                info!(
                    outcome = ?result.outcome,
                    message = %result.message,
                    "reload: EVPN runtime model hot-applied through ADR-0063 coordinator"
                );
            }
            Ok(None) => {}
            Err(error) => {
                error!(
                    error = ?error,
                    "reload: EVPN runtime model differs but the ADR-0063 coordinator \
                     rejected the candidate; runtime EVPN snapshot unchanged. \
                     Split unsupported mixed edits or restart rustbgpd for \
                     restart-required EVPN identity changes."
                );
                copy_evpn_runtime_fields(&mut new_config, &attempt.baseline);
            }
        }
    } else if evpn_runtime_changed(&new_config, current) {
        error!(
            "EVPN runtime config differs but the ADR-0063 coordinator is unavailable; \
             restart rustbgpd to apply [[evpn_instances]], [[evpn_ip_vrfs]], or \
             [[ethernet_segments]] edits."
        );
        copy_evpn_runtime_fields(&mut new_config, current);
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
    // Restart-required sections resolved once at startup: without an
    // explicit pin, a SIGHUP would silently advance the in-memory
    // snapshot to the new declared state while the running subsystem
    // keeps the startup values — the next reload then stops warning
    // even though nothing was applied. Pin each back to the live
    // startup snapshot (the operator's edit survives in the desired
    // on-disk config for the next restart).
    if new_config.security != current.security {
        error!(
            "[security.grpc] changed — gRPC authorization enforcement and roles \
             are resolved once at startup when listeners are built. Restart \
             rustbgpd to apply; the live listeners keep their startup \
             authorization until then."
        );
        new_config.security = current.security.clone();
    }
    if new_config.event_history != current.event_history {
        error!(
            "[event_history] changed — the ADR-0072 durable event outbox is \
             configured once at startup. Restart rustbgpd to apply; the running \
             outbox keeps its startup configuration until then."
        );
        new_config.event_history = current.event_history.clone();
    }
    if new_config.managed_netdevs != current.managed_netdevs {
        error!(
            "[managed_netdevs] changed — the ADR-0091 managed-netdev lifecycle \
             reads this table once at startup. Restart rustbgpd to apply; the \
             dataplane keeps reconciling the startup netdev set until then."
        );
        new_config.managed_netdevs = current.managed_netdevs.clone();
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
    if config::pin_ebgp_requires_policy_startup_only(&mut new_config, current) {
        error!(
            "[global].ebgp_requires_policy differs from the live config: the ADR-0112 \
             RFC 8212 enforcement mode is read once at startup. Restart rustbgpd to \
             change it. The running import/export treatment of every EBGP session is \
             kept at its startup value for this reload."
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
    let explain_changed = current.policy.explain != new_config.policy.explain
        || current.policy.reject_retention != new_config.policy.reject_retention;
    let fib_tables_changed = new_config.fib_tables != current.fib_tables;
    let dynamic_neighbors_changed = new_config.dynamic_neighbors != current.dynamic_neighbors;
    if !policy_diff.has_changes()
        && peer_groups_unchanged
        && neighbors_unchanged
        && !honor_graceful_shutdown_changed
        && !honor_blackhole_changed
        && !dynamic_neighbors_changed
        && !fib_tables_changed
        && !dataset_commit_pending
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
    if tcp_ao_rotation_applied {
        copy_tcp_ao_runtime_fields(&mut working_config, &new_config);
    }
    // `current` came from the runtime snapshot round-trip
    // (`load_toml_with_diagnostics`), which never carries a
    // `file_path`. The advanced in-memory config main.rs keeps after
    // this reload must still know where the config file lives, or the
    // NEXT SIGHUP reloads from an empty path and fails ("failed to
    // read : No such file or directory"). Stamp it from the
    // just-loaded desired config (which was read from `config_path`).
    working_config
        .file_path
        .clone_from(&desired_config.file_path);
    // EVPN runtime edits are applied before the staged peer-manager/FIB
    // sequence. Carry their accepted-or-pinned state into partial snapshots
    // returned by halt_partial paths.
    copy_evpn_runtime_fields(&mut working_config, &new_config);

    // `[[dynamic_neighbors]]` edits are applied by the peer manager's
    // accept-matcher rebuild when the returned snapshot is swapped in
    // (`ReplaceConfigSnapshot` re-parses the ranges; see #338) — there is
    // no per-range reconcile step below that can fail. Carry the new
    // range set into the snapshot here; without this the swap re-parses
    // the OLD ranges, the edit silently never takes effect, and every
    // subsequent SIGHUP re-detects (and re-drops) the same diff.
    if dynamic_neighbors_changed {
        working_config
            .dynamic_neighbors
            .clone_from(&new_config.dynamic_neighbors);
        info!(
            ranges = new_config.dynamic_neighbors.len(),
            "reload: [[dynamic_neighbors]] updated; accept-matcher rebuilds on the \
             config snapshot swap"
        );
    }

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
        working_config.policy.reject_retention = new_config.policy.reject_retention.clone();

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
                reject_retention_enabled: new_config.policy.reject_retention.enabled,
                reject_retention_capacity: new_config.policy.reject_retention.capacity,
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

    // ADR-0096: sync the compiled `.rpol` registry BEFORE any chain /
    // neighbor / peer-group step below resolves policies — those
    // resolve inside the peer manager against its `current_config`,
    // which must already carry the new registry for chains that
    // reference (new or edited) rpol policies. The command itself
    // re-resolves every live peer's chains and Route-Refreshes the
    // materially changed ones, so an rpol-content-only reload is fully
    // applied by this single step.
    if policy_diff.rpol_changed {
        let (ack_tx, ack_rx) = oneshot::channel();
        let send_failed = peer_mgr_tx
            .send(PeerManagerCommand::SyncRpolPolicies {
                rpol_files: new_config.policy.rpol_files.clone(),
                rpol: new_config.policy.rpol.clone(),
                dataset_bindings: new_config.policy.dataset_bindings.clone(),
                reply: ack_tx,
            })
            .await
            .is_err();
        let result = if send_failed {
            Err("peer manager unavailable while syncing rpol policies".to_string())
        } else {
            match ack_rx.await {
                Ok(Ok(())) => Ok(()),
                Ok(Err(error)) => Err(error.to_string()),
                Err(_) => Err("peer manager dropped rpol sync reply".to_string()),
            }
        };
        match result {
            // LAN-284: adopt the candidate registry into the runtime
            // snapshot ONLY after the peer manager committed it. The
            // manager's own sync is two-phase (a rejected sync leaves
            // its `current_config` and every live chain on the old
            // registry), so absorbing the candidate before the ack
            // would ship the REJECTED registry to the runtime snapshot
            // via halt_partial → ReplaceConfigSnapshot — new sessions
            // would then resolve against a registry no live session
            // runs. On failure the candidate survives only as on-disk
            // `.rpol` intent; the next successful reload adopts it.
            Ok(()) => {
                working_config
                    .policy
                    .rpol_files
                    .clone_from(&new_config.policy.rpol_files);
                working_config.policy.rpol = new_config.policy.rpol.clone();
                info!("reload: rpol policy registry synced");
            }
            Err(error) => {
                return halt_partial(
                    working_config,
                    &desired_config,
                    ReloadStepFailure {
                        bucket: "policy.rpol.sync",
                        target: "[policy] rpol_files".to_string(),
                        error,
                    },
                );
            }
        }
    }

    // LAN-305: this is the first point after preflight where every earlier
    // fallible peer-manager registry/snapshot step has succeeded. Commit the
    // staged contents/errors now, then publish honest snapshot bookkeeping and
    // dependency-scoped refreshes. A refresh failure is warned, not halted:
    // an accepted swap is durable, and stale evaluations converge on the next
    // churn or refresh.
    dataset_commit.commit();
    working_config
        .policy
        .datasets
        .clone_from(&new_config.policy.datasets);
    working_config.policy.dataset_bindings = new_config.policy.dataset_bindings.clone();
    let dataset_events = &new_config.policy.dataset_events;
    if !dataset_events.swapped.is_empty() || !dataset_events.failed.is_empty() {
        let (ack_tx, ack_rx) = oneshot::channel();
        let send_failed = peer_mgr_tx
            .send(PeerManagerCommand::RefreshDatasetDependents {
                swapped: dataset_events.swapped.clone(),
                failed: dataset_events.failed.clone(),
                reply: ack_tx,
            })
            .await
            .is_err();
        let outcome = if send_failed {
            Err("peer manager unavailable".to_string())
        } else {
            match ack_rx.await {
                Ok(result) => result,
                Err(_) => Err("peer manager dropped dataset refresh reply".to_string()),
            }
        };
        if let Err(error) = outcome {
            warn!(
                error = %error,
                "dataset-swap dependency-scoped refresh incomplete; affected peers converge on next churn or manual refresh"
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
            ack: None,
        };
        let cmd_name = name.clone();
        match send_catalog_pm_step(peer_mgr_tx, |reply| PeerManagerCommand::SetNeighborSet {
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
            ack: None,
        };
        let cmd_name = name.clone();
        match send_catalog_pm_step(peer_mgr_tx, |reply| PeerManagerCommand::SetPolicy {
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
            ack: None,
        };
        let cmd_name = name.clone();
        match send_catalog_pm_step(peer_mgr_tx, |reply| PeerManagerCommand::SetPeerGroup {
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
            ConfigEvent::ClearGlobalImportChain { ack: None }
        } else {
            ConfigEvent::SetGlobalImportChain {
                policy_names: chain.clone(),
                ack: None,
            }
        };
        let res = if chain.is_empty() {
            send_catalog_pm_step(peer_mgr_tx, |reply| {
                PeerManagerCommand::ClearGlobalImportChain { reply }
            })
            .await
        } else {
            send_catalog_pm_step(peer_mgr_tx, |reply| {
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
            ConfigEvent::ClearGlobalExportChain { ack: None }
        } else {
            ConfigEvent::SetGlobalExportChain {
                policy_names: chain.clone(),
                ack: None,
            }
        };
        let res = if chain.is_empty() {
            send_catalog_pm_step(peer_mgr_tx, |reply| {
                PeerManagerCommand::ClearGlobalExportChain { reply }
            })
            .await
        } else {
            send_catalog_pm_step(peer_mgr_tx, |reply| {
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
    //
    //    LAN-341: changed neighbors are partitioned by the reload-matrix
    //    impact of their changed-field set. A neighbor whose every
    //    changed field is `live` (hot-applied) is updated in place via
    //    `HotUpdatePeer` — no session-task delete/re-add, no flap. Any
    //    session-reset or unknown-impact field keeps the neighbor on the
    //    existing `ReconcilePeers` rebuild path.
    if !neighbors_unchanged {
        let old_map: std::collections::HashMap<(&str, Option<&str>), &config::Neighbor> = current
            .neighbors
            .iter()
            .map(|n| ((n.address.as_str(), n.interface.as_deref()), n))
            .collect();
        let mut hot_changed: Vec<&config::Neighbor> = Vec::new();
        let mut rebuild_changed: Vec<config::Neighbor> = Vec::new();
        for n in &diff.changed {
            let old_n = old_map
                .get(&(n.address.as_str(), n.interface.as_deref()))
                .copied();
            let hot = old_n.is_some_and(|old_n| config::neighbor_change_hot_applicable(old_n, n));
            if let Some(old_n) = old_n {
                let changes: Vec<String> = config::describe_neighbor_changes(old_n, n)
                    .iter()
                    .map(config::FieldChange::render)
                    .collect();
                info!(
                    address = %n.address,
                    changes = %changes.join(", "),
                    apply = if hot { "hot-apply in place" } else { "session rebuild" },
                    "neighbor changed"
                );
            }
            if hot {
                hot_changed.push(n);
            } else {
                rebuild_changed.push(n.clone());
            }
        }
        info!(
            added = diff.added.len(),
            removed = diff.removed.len(),
            hot_applied = hot_changed.len(),
            rebuilt = rebuild_changed.len(),
            "reconciling neighbors after config reload"
        );
        for n in &diff.added {
            info!(address = %n.address, asn = n.remote_asn, "neighbor added");
        }
        for addr in &diff.removed {
            info!(address = %addr, "neighbor removed");
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
                                neighbor.max_prefix_restart_seconds,
                                &neighbor.label,
                                neighbor.import_policy.as_ref(),
                                neighbor.export_policy.as_ref(),
                                neighbor.peer_group.clone(),
                            )
                        })
                })
                .collect()
        };

        // Hot-applicable-only changes first: each peer is updated in
        // place (session task untouched), and its entry in the honest
        // working snapshot advances per peer on success. A failure halts
        // like any other reload step — safe, because a hot update never
        // deletes anything, and the stale snapshot entry makes the next
        // SIGHUP re-detect and retry the same in-place update.
        for n in hot_changed {
            let Some(cfg) = resolve(std::slice::from_ref(n)).pop() else {
                warn!(
                    address = %n.address,
                    "reload: hot-applicable neighbor missing from resolved set; skipping"
                );
                continue;
            };
            if let Err(error) = send_pm_result_step(peer_mgr_tx, |reply| {
                PeerManagerCommand::HotUpdatePeer { config: cfg, reply }
            })
            .await
            {
                return halt_partial(
                    working_config,
                    &desired_config,
                    ReloadStepFailure {
                        bucket: "neighbors.hot_update",
                        target: n.address.clone(),
                        error,
                    },
                );
            }
            if let Some(entry) = working_config
                .neighbors
                .iter_mut()
                .find(|w| w.address == n.address && w.interface == n.interface)
            {
                *entry = n.clone();
            }
            info!(address = %n.address, "reload: neighbor hot-applied in place");
        }

        let needs_rebuild_pass =
            !diff.added.is_empty() || !diff.removed.is_empty() || !rebuild_changed.is_empty();
        if needs_rebuild_pass {
            let (reply_tx, reply_rx) = oneshot::channel();
            if let Err(e) = peer_mgr_tx
                .send(PeerManagerCommand::ReconcilePeers {
                    added: resolve(&diff.added),
                    removed: diff.removed.clone(),
                    changed: resolve(&rebuild_changed),
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
                    // Preserve the last-known neighbor config in the honest
                    // partial snapshot while retaining every earlier step
                    // that definitely landed (including dataset generations,
                    // policy, and EVPN state). The live peer table remains
                    // explicitly ambiguous either way; discarding the partial
                    // snapshot would additionally make all known-successful
                    // state look unapplied and corrupt the next reload's diff.
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
                     `rbgp neighbor list` and re-edit the failing TOML before \
                     reloading again. Earlier reload steps (policy / peer-group / chain \
                     edits) DID land at the manager and remain in effect."
                    );
                    return Some(ReloadedConfig::new(working_config, desired_config));
                }
                Err(e) => {
                    error!(
                        error = %e,
                        "config reload halted: peer manager dropped reconcile reply — live \
                         state may differ from the in-memory config snapshot. Inspect via \
                         `rbgp neighbor list` before reloading again. Earlier reload \
                         steps (policy / peer-group / chain edits) DID land at the manager \
                         and remain in effect."
                    );
                    return Some(ReloadedConfig::new(working_config, desired_config));
                }
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
                            if let Err(error) =
                                set_pm_fib_tables_snapshot(peer_mgr_tx, &new_config.fib_tables)
                                    .await
                            {
                                working_config.fib_tables.clone_from(&new_config.fib_tables);
                                return halt_partial(
                                    working_config,
                                    &desired_config,
                                    ReloadStepFailure {
                                        bucket: "fib_tables.snapshot",
                                        target: "[[fib_tables]]".to_string(),
                                        error,
                                    },
                                );
                            }
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
        let event = ConfigEvent::DeletePeerGroup {
            name: name.clone(),
            ack: None,
        };
        let cmd_name = name.clone();
        match send_catalog_pm_step(peer_mgr_tx, |reply| PeerManagerCommand::DeletePeerGroup {
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
        let event = ConfigEvent::DeletePolicy {
            name: name.clone(),
            ack: None,
        };
        let cmd_name = name.clone();
        match send_catalog_pm_step(peer_mgr_tx, |reply| PeerManagerCommand::DeletePolicy {
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
        let event = ConfigEvent::DeleteNeighborSet {
            name: name.clone(),
            ack: None,
        };
        let cmd_name = name.clone();
        match send_catalog_pm_step(peer_mgr_tx, |reply| PeerManagerCommand::DeleteNeighborSet {
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
    use std::fmt::Write as _;
    use std::path::PathBuf;

    use super::*;
    use crate::config_persister::ConfigPersister;
    use crate::peer_manager::PeerManager;
    use crate::test_support::{
        assert_tier_authorized_test_config, tier_authorized_uds_test_config,
    };
    use rustbgpd_telemetry::BgpMetrics;

    fn unique_temp_path(name: &str) -> PathBuf {
        // A timestamp suffix is not unique under parallel test load (two
        // tests can share a clock tick and then race truncating writes, so
        // one parses the other's half-written file as empty). tempfile
        // creates the file with a random name and O_EXCL; keep() hands the
        // path to the callers, which write and remove it themselves.
        tempfile::Builder::new()
            .prefix(&format!("rustbgpd-{name}-"))
            .suffix(".toml")
            .tempfile()
            .unwrap()
            .into_temp_path()
            .keep()
            .unwrap()
    }

    #[test]
    fn reload_fixtures_keep_every_explicit_tier_preparation_seam() {
        let source = include_str!("reload.rs");
        let legacy_toml = concat!("enforcement = \"", "legacy\"");
        let legacy_variant = concat!("GrpcEnforcementConfig::", "Legacy");
        let expected_seams = [
            (concat!("explicit_tier", "_test_toml("), 3),
            (concat!("write_tier", "_test_config("), 12),
            (concat!("load_tier", "_test_config("), 29),
            (concat!("load_tier", "_test_toml("), 6),
            (concat!("tier_authorized_uds", "_test_config("), 2),
            (concat!("assert_tier_authorized", "_test_config("), 17),
        ];

        assert!(!source.contains(legacy_toml));
        assert!(!source.contains(legacy_variant));
        for (seam, expected) in expected_seams {
            assert_eq!(
                source.matches(seam).count(),
                expected,
                "reload fixture preparation seam {seam} drifted"
            );
        }
    }

    fn dataset_reload_dir(config_toml: &str, dataset: &str) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("policies")).unwrap();
        std::fs::create_dir(dir.path().join("datasets")).unwrap();
        std::fs::write(
            dir.path().join("policies/core.rpol"),
            r"
dataset asn-set customers
policy origin-guard {
    term customers { if route.origin-as in customers { accept } }
    term rest { reject }
}
",
        )
        .unwrap();
        std::fs::write(dir.path().join("datasets/customers.list"), dataset).unwrap();
        let config_path = dir.path().join("config.toml");
        write_tier_test_config(&config_path, config_toml);
        let config = Config::load_with_diagnostics(config_path.to_str().unwrap()).unwrap();
        assert_tier_authorized_test_config(&config);
        dir
    }

    #[derive(Clone)]
    struct TestEvpnRuntimeConverger {
        results: std::sync::Arc<
            std::sync::Mutex<
                std::collections::VecDeque<
                    Result<(), crate::evpn_runtime_converger::DaemonEvpnRuntimeConvergeError>,
                >,
            >,
        >,
    }

    impl crate::evpn_runtime_converger::DaemonEvpnRuntimeConverger for TestEvpnRuntimeConverger {
        fn converge<'a>(
            &'a self,
            _current: &'a rustbgpd_evpn::EvpnRuntimeModel,
            _candidate: &'a rustbgpd_evpn::EvpnRuntimeCandidate,
            _plan: &'a rustbgpd_evpn::EvpnRuntimePlan,
        ) -> crate::evpn_runtime_converger::DaemonEvpnRuntimeConvergeFuture<'a> {
            let result = self.results.lock().unwrap().pop_front().unwrap_or(Ok(()));
            Box::pin(async move { result })
        }
    }

    fn evpn_reload_apply(
        initial: &Config,
        result: Result<(), crate::evpn_runtime_converger::DaemonEvpnRuntimeConvergeError>,
    ) -> (
        crate::evpn_runtime_converger::EvpnRuntimeReloadApply,
        std::sync::Arc<std::sync::Mutex<rustbgpd_evpn::EvpnRuntimeCoordinator>>,
    ) {
        evpn_reload_apply_sequence(initial, vec![result])
    }

    fn evpn_reload_apply_sequence(
        initial: &Config,
        results: Vec<Result<(), crate::evpn_runtime_converger::DaemonEvpnRuntimeConvergeError>>,
    ) -> (
        crate::evpn_runtime_converger::EvpnRuntimeReloadApply,
        std::sync::Arc<std::sync::Mutex<rustbgpd_evpn::EvpnRuntimeCoordinator>>,
    ) {
        let coordinator = std::sync::Arc::new(std::sync::Mutex::new(
            rustbgpd_evpn::EvpnRuntimeCoordinator::new(
                initial.resolve_evpn_instances().unwrap(),
                initial.resolve_evpn_ip_vrfs().unwrap(),
                initial.resolve_ethernet_segments().unwrap(),
            ),
        ));
        let apply_lock = std::sync::Arc::new(tokio::sync::Mutex::new(()));
        let converger = std::sync::Arc::new(TestEvpnRuntimeConverger {
            results: std::sync::Arc::new(std::sync::Mutex::new(results.into())),
        });
        (
            crate::evpn_runtime_converger::EvpnRuntimeReloadApply::new(
                coordinator.clone(),
                apply_lock,
                converger,
                initial.clone(),
            ),
            coordinator,
        )
    }

    const EVPN_VNI_100_TOML: &str = r#"
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
"#;

    const EVPN_VNI_100_200_TOML: &str = r#"
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

[[evpn_instances]]
vni = 200
rd = "65000:200"
route_targets = ["65000:200"]
local_vtep_ip = "10.0.0.1"
"#;

    const EVPN_VNI_100_200_300_TOML: &str = r#"
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

[[evpn_instances]]
vni = 200
rd = "65000:200"
route_targets = ["65000:200"]
local_vtep_ip = "10.0.0.1"

[[evpn_instances]]
vni = 300
rd = "65000:300"
route_targets = ["65000:300"]
local_vtep_ip = "10.0.0.1"
"#;

    #[tokio::test]
    async fn sighup_runtime_baseline_reads_peer_manager_snapshot_after_stage() {
        let initial = load_config_from_toml("runtime-baseline-initial", baseline_toml());
        let mut candidate = initial.clone();
        candidate.neighbors[0].hold_time = Some(45);
        let candidate_toml = toml::to_string_pretty(&candidate).unwrap();

        let (tx, rx) = mpsc::channel(16);
        let (_internal_tx, internal_rx) = mpsc::unbounded_channel();
        let (rib_tx, _rib_rx) = mpsc::channel(64);
        let manager = PeerManager::new_with_config(
            rx,
            internal_rx,
            65001,
            "10.0.0.1".parse().unwrap(),
            None,
            None,
            BgpMetrics::new(),
            rib_tx,
            None,
            None,
            initial,
        );
        let handle = tokio::spawn(manager.run());

        let (stage_tx, stage_rx) = oneshot::channel();
        tx.send(PeerManagerCommand::StageConfigSnapshot {
            candidate_toml,
            reply: stage_tx,
        })
        .await
        .unwrap();
        stage_rx.await.unwrap().unwrap();

        let snapshot = runtime_config_snapshot(&tx).await.unwrap();
        assert_eq!(snapshot.neighbors[0].hold_time, Some(45));

        tx.send(PeerManagerCommand::Shutdown).await.unwrap();
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn runtime_config_snapshot_errors_when_peer_manager_is_gone() {
        let (tx, rx) = mpsc::channel(1);
        drop(rx);

        let error = runtime_config_snapshot(&tx).await.unwrap_err();
        assert!(error.contains("send to peer manager failed"), "{error}");
    }

    /// SIGHUP that adds mTLS to `grpc_tcp` must NOT advance the
    /// in-memory config's `grpc_tcp` field — the live listener is
    /// still serving the prior config (no listener rebind on
    /// reload), so the runtime snapshot has to keep pointing at the
    /// live state. Without this, future reloads compare against the
    /// already-mutated snapshot and the drift error stops firing.
    #[expect(
        clippy::too_many_lines,
        reason = "one fixture proves plaintext bearer startup and later mTLS drift pinning"
    )]
    #[tokio::test]
    async fn reload_pins_grpc_tcp_to_live_listener_snapshot() {
        let path = unique_temp_path("reload-grpc-tcp-pin");
        let token = unique_temp_path("reload-grpc-token");
        std::fs::write(&token, "test-bearer-token\n").unwrap();

        // Initial config: grpc_tcp present but plaintext (no TLS).
        std::fs::write(
            &path,
            format!(
                r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
log_format = "json"

[global.telemetry.grpc_tcp]
address = "0.0.0.0:50051"
token_file = {token:?}
principal = "rustbgpd://operator/test-only"

[security.grpc]
enforcement = "tier"

[security.grpc.roles]
"rustbgpd://operator/test-only" = "operator"

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
hold_time = 90
"#,
                token = token.to_str().unwrap(),
            ),
        )
        .unwrap();

        let initial = load_tier_test_config(&path);
        assert_tier_authorized_test_config(&initial);
        let live_grpc_tcp = initial.global.telemetry.grpc_tcp.clone();
        let live_grpc_uds = initial.global.telemetry.grpc_uds.clone();
        let live_tcp = live_grpc_tcp.as_ref().unwrap();
        assert!(
            live_tcp.tls_cert_file.is_none()
                && live_tcp.tls_key_file.is_none()
                && live_tcp.tls_client_ca_file.is_none(),
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
token_file = {token:?}
tls_cert_file = {cert:?}
tls_key_file = {key:?}
tls_client_ca_file = {ca:?}

[security.grpc]
enforcement = "tier"

[security.grpc.roles]
"rustbgpd://operator/test-only" = "operator"

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
hold_time = 90
"#,
            cert = cert.to_str().unwrap(),
            key = key.to_str().unwrap(),
            ca = ca.to_str().unwrap(),
            token = token.to_str().unwrap(),
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
            None,
        )
        .await
        .expect("reload should return a config even when grpc_tcp drifts");
        assert_tier_authorized_test_config(&returned);
        assert_eq!(
            returned.desired.security.grpc.enforcement,
            crate::config::GrpcEnforcementConfig::Tier
        );
        assert_eq!(
            returned
                .desired
                .security
                .grpc
                .roles
                .get("rustbgpd://operator/test-only"),
            Some(&crate::config::GrpcRoleConfig::Operator)
        );

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
        std::fs::remove_file(&token).ok();
    }

    /// Regression: `[[dynamic_neighbors]]` edits must be carried into the
    /// runtime snapshot returned by `reload_config`. The accept-matcher is
    /// rebuilt from that snapshot when `apply_reload_outcome` swaps it into
    /// the peer manager (#338) — previously the main reload path never
    /// copied the new range set into `working_config`, so the swap
    /// re-parsed the OLD ranges, the SIGHUP edit silently never took
    /// effect, and every later SIGHUP re-detected (and re-dropped) the
    /// same diff.
    #[tokio::test]
    async fn reload_carries_dynamic_neighbor_edits_into_runtime_snapshot() {
        let path = unique_temp_path("reload-dynamic-neighbors");

        let base = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
log_format = "json"

[peer_groups.fabric]
hold_time = 90
"#;
        std::fs::write(
            &path,
            format!(
                r#"{base}
[[dynamic_neighbors]]
prefix = "192.0.2.0/24"
peer_group = "fabric"
remote_asn = 65002
"#
            ),
        )
        .unwrap();
        let initial = load_tier_test_config(&path);
        let live_grpc_tcp = initial.global.telemetry.grpc_tcp.clone();
        let live_grpc_uds = initial.global.telemetry.grpc_uds.clone();
        assert_eq!(initial.dynamic_neighbors.len(), 1);

        // Edit the existing range and add a second one.
        std::fs::write(
            &path,
            format!(
                r#"{base}
[[dynamic_neighbors]]
prefix = "192.0.3.0/24"
peer_group = "fabric"
remote_asn = 65002

[[dynamic_neighbors]]
prefix = "198.51.100.0/24"
peer_group = "fabric"
remote_asn = 65003
"#
            ),
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
            None,
        )
        .await
        .expect("reload should produce a runtime snapshot");

        assert_eq!(
            returned.dynamic_neighbors.len(),
            2,
            "runtime snapshot must carry the edited [[dynamic_neighbors]] set"
        );
        assert_eq!(returned.dynamic_neighbors[0].prefix, "192.0.3.0/24");
        assert_eq!(returned.dynamic_neighbors[1].prefix, "198.51.100.0/24");
        // Convergence: a second reload diffing against the returned
        // snapshot must see no remaining [[dynamic_neighbors]] delta.
        let second = reload_config(
            path.to_str().unwrap(),
            &returned,
            live_grpc_tcp.as_ref(),
            live_grpc_uds.as_ref(),
            &peer_mgr_tx,
            None,
            None,
        )
        .await
        .expect("second reload should succeed");
        assert_eq!(
            second.dynamic_neighbors, returned.dynamic_neighbors,
            "second reload must converge with no dynamic-neighbor delta"
        );

        std::fs::remove_file(&path).ok();
    }

    /// If the ADR-0063 coordinator is not available to SIGHUP, edits to
    /// `[[evpn_instances]]` must NOT advance the in-memory config's
    /// `evpn_instances` field. Without pinning, the next reload would
    /// compare against the already-mutated snapshot and the drift error
    /// would silently stop firing — operators would believe their edits
    /// had taken effect when the EVPN runtime stayed on the prior set.
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

        let initial = load_tier_test_config(&path);
        let live_grpc_tcp = initial.global.telemetry.grpc_tcp.clone();
        let live_grpc_uds = initial.global.telemetry.grpc_uds.clone();
        assert_eq!(initial.evpn_instances.len(), 1);
        assert_eq!(initial.evpn_instances[0].vni, 100);

        // Operator rewrites the file: VNI changes, RTs expand, a new
        // instance appears. With no coordinator hook supplied to
        // `reload_config`, the reload path must surface the drift and pin
        // the snapshot.
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

    #[tokio::test]
    async fn reload_hot_applies_evpn_runtime_when_coordinator_accepts() {
        let path = unique_temp_path("reload-evpn-hot-apply");
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
        let initial = load_tier_test_config(&path);
        let live_grpc_tcp = initial.global.telemetry.grpc_tcp.clone();
        let live_grpc_uds = initial.global.telemetry.grpc_uds.clone();
        let (apply, coordinator) = evpn_reload_apply(&initial, Ok(()));

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
            Some(&apply),
        )
        .await
        .expect("reload should hot-apply coordinator-supported EVPN runtime edits");

        let added = rustbgpd_evpn::EvpnInstanceId::new(200).unwrap();
        assert_eq!(
            returned.evpn_instances.len(),
            2,
            "accepted EVPN runtime apply should advance the returned runtime snapshot"
        );
        assert!(
            coordinator
                .lock()
                .unwrap()
                .model()
                .instances()
                .get(added)
                .is_some(),
            "EVPN coordinator should commit the SIGHUP candidate"
        );
        std::fs::remove_file(&path).ok();
    }

    #[tokio::test]
    #[expect(
        clippy::too_many_lines,
        reason = "reload hot-apply test keeps initial/candidate EVPN TOML fixtures inline"
    )]
    async fn reload_hot_applies_additive_evpn_runtime_build_up() {
        let path = unique_temp_path("reload-evpn-additive-hot-apply");
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
ip_vrf = "tenant-blue"
advertise_svi_mac = true

[[evpn_ip_vrfs]]
name = "tenant-blue"
vni = 5000
rd = "65000:5000"
route_targets = ["65000:5000"]
local_vtep_ip = "10.0.0.100"
router_mac = "02:00:00:00:00:01"
vrf_device = "vrf-blue"
l3vxlan_device = "vni5000"
table_id = 5000

[[ethernet_segments]]
esi = "00:00:00:00:00:00:00:00:00:01"
member_vnis = [100]
originator_ip = "10.0.0.1"
"#,
        )
        .unwrap();
        let initial = load_tier_test_config(&path);
        let live_grpc_tcp = initial.global.telemetry.grpc_tcp.clone();
        let live_grpc_uds = initial.global.telemetry.grpc_uds.clone();
        let (apply, coordinator) = evpn_reload_apply(&initial, Ok(()));

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
ip_vrf = "tenant-blue"
advertise_svi_mac = true

[[evpn_instances]]
vni = 200
rd = "65000:200"
route_targets = ["65000:200"]
local_vtep_ip = "10.0.0.1"
ip_vrf = "tenant-green"
advertise_svi_mac = true

[[evpn_ip_vrfs]]
name = "tenant-blue"
vni = 5000
rd = "65000:5000"
route_targets = ["65000:5000"]
local_vtep_ip = "10.0.0.100"
router_mac = "02:00:00:00:00:01"
vrf_device = "vrf-blue"
l3vxlan_device = "vni5000"
table_id = 5000

[[evpn_ip_vrfs]]
name = "tenant-green"
vni = 6000
rd = "65000:6000"
route_targets = ["65000:6000"]
local_vtep_ip = "10.0.0.101"
router_mac = "02:00:00:00:00:02"
vrf_device = "vrf-green"
l3vxlan_device = "vni6000"
table_id = 6000

[[ethernet_segments]]
esi = "00:00:00:00:00:00:00:00:00:01"
member_vnis = [100]
originator_ip = "10.0.0.1"

[[ethernet_segments]]
esi = "00:00:00:00:00:00:00:00:00:02"
member_vnis = [200]
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
            Some(&apply),
        )
        .await
        .expect("reload should hot-apply additive EVPN runtime build-up");

        let added = rustbgpd_evpn::EvpnInstanceId::new(200).unwrap();
        assert_eq!(returned.evpn_instances.len(), 2);
        assert_eq!(returned.evpn_ip_vrfs.len(), 2);
        assert_eq!(returned.ethernet_segments.len(), 2);
        let guard = coordinator.lock().unwrap();
        assert!(guard.model().instances().get(added).is_some());
        assert!(guard.model().ip_vrfs().get("tenant-green").is_some());
        assert_eq!(guard.model().ethernet_segments().len(), 2);
        std::fs::remove_file(&path).ok();
    }

    #[tokio::test]
    #[expect(
        clippy::too_many_lines,
        reason = "reload hot-apply test keeps initial/candidate EVPN TOML fixtures inline"
    )]
    async fn reload_decomposes_mixed_evpn_runtime_edit_across_generations() {
        // #268: an ES delete + its (surviving) member L2VNI redefine + a new
        // L2VNI add in ONE SIGHUP. The converge of the mixed whole rejects it
        // (scripted `Unsupported`, as the real dispatch would), and the
        // decomposer then applies deletes → redefine → add as three
        // primitive steps — three committed generations for one SIGHUP.
        let path = unique_temp_path("reload-evpn-decomposed-mixed");
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

[[ethernet_segments]]
esi = "00:00:00:00:00:00:00:00:00:01"
member_vnis = [100]
originator_ip = "10.0.0.1"
"#,
        )
        .unwrap();
        let initial = load_tier_test_config(&path);
        let live_grpc_tcp = initial.global.telemetry.grpc_tcp.clone();
        let live_grpc_uds = initial.global.telemetry.grpc_uds.clone();
        let (apply, coordinator) = evpn_reload_apply_sequence(
            &initial,
            vec![
                Err(
                    crate::evpn_runtime_converger::DaemonEvpnRuntimeConvergeError::Unsupported(
                        "mixed shape rejected by the dispatch".to_string(),
                    ),
                ),
                Ok(()),
                Ok(()),
                Ok(()),
            ],
        );

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
rd = "65000:101"
route_targets = ["65000:101"]
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
            Some(&apply),
        )
        .await
        .expect("reload should hot-apply the decomposed mixed EVPN edit");

        assert_eq!(
            returned.evpn_instances.len(),
            2,
            "the reload snapshot must advance to the mixed candidate"
        );
        assert!(returned.ethernet_segments.is_empty());
        let guard = coordinator.lock().unwrap();
        assert_eq!(
            guard.model().generation().as_u64(),
            4,
            "one SIGHUP must commit three generations (deletes, redefine, add)"
        );
        assert!(guard.model().ethernet_segments().is_empty());
        assert_eq!(
            guard
                .model()
                .instances()
                .get(rustbgpd_evpn::EvpnInstanceId::new(100).unwrap())
                .unwrap()
                .rd
                .to_string(),
            "65000:101"
        );
        assert!(
            guard
                .model()
                .instances()
                .get(rustbgpd_evpn::EvpnInstanceId::new(200).unwrap())
                .is_some()
        );
        std::fs::remove_file(&path).ok();
    }

    #[tokio::test]
    async fn reload_retains_hot_applied_evpn_runtime_with_later_steps() {
        let path = unique_temp_path("reload-evpn-hot-apply-plus-honor");
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
        let initial = load_tier_test_config(&path);
        let live_grpc_tcp = initial.global.telemetry.grpc_tcp.clone();
        let live_grpc_uds = initial.global.telemetry.grpc_uds.clone();
        let (apply, coordinator) = evpn_reload_apply(&initial, Ok(()));

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

[[evpn_instances]]
vni = 100
rd = "65000:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.1"

[[evpn_instances]]
vni = 200
rd = "65000:200"
route_targets = ["65000:200"]
local_vtep_ip = "10.0.0.1"
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
            Some(&apply),
        )
        .await
        .expect("reload should keep earlier EVPN runtime apply in the final snapshot");

        let added = rustbgpd_evpn::EvpnInstanceId::new(200).unwrap();
        assert!(
            returned.global.honor_graceful_shutdown,
            "later hot-applied reload steps should still advance"
        );
        assert_eq!(
            returned.evpn_instances.len(),
            2,
            "final reload snapshot must retain the already-committed EVPN runtime apply"
        );
        assert!(
            coordinator
                .lock()
                .unwrap()
                .model()
                .instances()
                .get(added)
                .is_some(),
            "coordinator should commit the EVPN candidate"
        );
        assert!(
            peer_mgr.await.unwrap(),
            "peer manager command must carry enabled=true"
        );
        std::fs::remove_file(&path).ok();
    }

    #[tokio::test]
    async fn reload_pins_evpn_runtime_when_coordinator_rejects() {
        let path = unique_temp_path("reload-evpn-hot-apply-reject");
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
        let initial = load_tier_test_config(&path);
        let live_grpc_tcp = initial.global.telemetry.grpc_tcp.clone();
        let live_grpc_uds = initial.global.telemetry.grpc_uds.clone();
        let (apply, coordinator) = evpn_reload_apply(
            &initial,
            Err(
                crate::evpn_runtime_converger::DaemonEvpnRuntimeConvergeError::Unsupported(
                    "split unsupported mixed edits".to_string(),
                ),
            ),
        );

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
            Some(&apply),
        )
        .await
        .expect("reload returns a config even when EVPN runtime apply is rejected");

        let added = rustbgpd_evpn::EvpnInstanceId::new(200).unwrap();
        assert_eq!(
            returned.evpn_instances, initial.evpn_instances,
            "rejected EVPN runtime apply must keep the returned runtime snapshot pinned"
        );
        assert!(
            coordinator
                .lock()
                .unwrap()
                .model()
                .instances()
                .get(added)
                .is_none(),
            "EVPN coordinator must not commit the rejected SIGHUP candidate"
        );
        std::fs::remove_file(&path).ok();
    }

    #[tokio::test]
    async fn reload_compares_evpn_against_committed_runtime_baseline() {
        let path = unique_temp_path("reload-evpn-committed-baseline");
        std::fs::write(&path, EVPN_VNI_100_TOML).unwrap();
        let initial = load_tier_test_config(&path);
        let live_grpc_tcp = initial.global.telemetry.grpc_tcp.clone();
        let live_grpc_uds = initial.global.telemetry.grpc_uds.clone();
        let (apply, coordinator) = evpn_reload_apply(&initial, Ok(()));
        let runtime_config = load_config_from_toml("runtime-evpn-add", EVPN_VNI_100_200_TOML);
        apply
            .apply_config(&runtime_config)
            .await
            .expect("test runtime apply should commit VNI 200");

        std::fs::write(&path, EVPN_VNI_100_TOML).unwrap();
        let (peer_mgr_tx, _peer_mgr_rx) = mpsc::channel(8);
        let returned = reload_config(
            path.to_str().unwrap(),
            &initial,
            live_grpc_tcp.as_ref(),
            live_grpc_uds.as_ref(),
            &peer_mgr_tx,
            None,
            Some(&apply),
        )
        .await
        .expect("reload should compare against the accepted EVPN runtime baseline");

        let removed = rustbgpd_evpn::EvpnInstanceId::new(200).unwrap();
        assert_eq!(
            returned.evpn_instances, initial.evpn_instances,
            "SIGHUP should not skip EVPN reconciliation just because the peer-manager snapshot is stale"
        );
        assert!(
            coordinator
                .lock()
                .unwrap()
                .model()
                .instances()
                .get(removed)
                .is_none(),
            "SIGHUP file state should converge the committed EVPN runtime model"
        );
        std::fs::remove_file(&path).ok();
    }

    #[tokio::test]
    async fn reload_rejected_evpn_candidate_pins_to_committed_runtime_baseline() {
        let path = unique_temp_path("reload-evpn-reject-committed-baseline");
        std::fs::write(&path, EVPN_VNI_100_TOML).unwrap();
        let initial = load_tier_test_config(&path);
        let live_grpc_tcp = initial.global.telemetry.grpc_tcp.clone();
        let live_grpc_uds = initial.global.telemetry.grpc_uds.clone();
        let (apply, coordinator) = evpn_reload_apply_sequence(
            &initial,
            vec![
                Ok(()),
                Err(
                    crate::evpn_runtime_converger::DaemonEvpnRuntimeConvergeError::Failed(
                        rustbgpd_evpn::EvpnRuntimeConvergeError::new(
                            "test convergence failure after committed baseline",
                        ),
                    ),
                ),
            ],
        );
        let runtime_config =
            load_config_from_toml("runtime-evpn-add-for-reject", EVPN_VNI_100_200_TOML);
        apply
            .apply_config(&runtime_config)
            .await
            .expect("test runtime apply should commit VNI 200");

        std::fs::write(&path, EVPN_VNI_100_200_300_TOML).unwrap();
        let (peer_mgr_tx, _peer_mgr_rx) = mpsc::channel(8);
        let returned = reload_config(
            path.to_str().unwrap(),
            &initial,
            live_grpc_tcp.as_ref(),
            live_grpc_uds.as_ref(),
            &peer_mgr_tx,
            None,
            Some(&apply),
        )
        .await
        .expect("reload should pin when the committed-baseline candidate fails to converge");

        let committed = rustbgpd_evpn::EvpnInstanceId::new(200).unwrap();
        let rejected = rustbgpd_evpn::EvpnInstanceId::new(300).unwrap();
        assert_eq!(
            returned.evpn_instances, runtime_config.evpn_instances,
            "rejected EVPN reload must pin to the coordinator's committed config, not stale startup tables"
        );
        assert!(
            coordinator
                .lock()
                .unwrap()
                .model()
                .instances()
                .get(committed)
                .is_some(),
            "previously committed EVPN runtime state should stay committed"
        );
        assert!(
            coordinator
                .lock()
                .unwrap()
                .model()
                .instances()
                .get(rejected)
                .is_none(),
            "failed EVPN reload candidate must not commit"
        );
        std::fs::remove_file(&path).ok();
    }

    /// SIGHUP that edits `[[evpn_ip_vrfs]]` must not advance the
    /// in-memory snapshot when the ADR-0063 coordinator hook is absent.
    /// Letting reload adopt the new table would make the next reload stop
    /// reporting drift even though no Type 5 / L3VNI runtime state changed.
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

        let initial = load_tier_test_config(&path);
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

    /// SIGHUP must still pin EVPN surfaces that remain startup-only or
    /// lack an ADR-0063 coordinator hook: the Ethernet Segment table in
    /// this test and the kernel-enforcement opt-in. Otherwise a reload
    /// would advance `current`, the actor would still be on its startup
    /// state, and the next reload would stop reporting drift.
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

        let initial = load_tier_test_config(&path);
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
        let initial = load_tier_test_config(&path);
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
        let initial = load_tier_test_config(&path);
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
        let initial = load_tier_test_config(&path);
        let tcp = initial.global.telemetry.grpc_tcp.clone();
        let uds = initial.global.telemetry.grpc_uds.clone();
        assert_eq!(initial.fib_tables.len(), 1);

        std::fs::write(&path, FIB_TWO_TABLES_TOML).unwrap();

        let (peer_mgr_tx, mut peer_mgr_rx) = mpsc::channel(8);
        let peer_mgr = tokio::spawn(async move {
            match peer_mgr_rx.recv().await {
                Some(PeerManagerCommand::SetFibTablesSnapshot { tables, reply }) => {
                    let len = tables.len();
                    let _ = reply.send(());
                    len
                }
                _ => panic!("expected SetFibTablesSnapshot"),
            }
        });
        let (fib_tx, mut fib_rx) = mpsc::channel(8);
        let actor = tokio::spawn(async move {
            match fib_rx.recv().await {
                Some(FibRuntimeCommand::ReplaceTables { tables, reply }) => {
                    let _ = reply.send(Ok(()));
                    tables.len()
                }
                Some(FibRuntimeCommand::GetTables { .. }) => panic!("unexpected GetTables"),
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
            None,
        )
        .await
        .expect("reload should hot-apply fib_tables");

        assert_eq!(
            returned.fib_tables.len(),
            2,
            "snapshot advances only after the actor acks the new table set"
        );
        assert_eq!(actor.await.unwrap(), 2, "actor received the new table set");
        assert_eq!(
            peer_mgr.await.unwrap(),
            2,
            "peer-manager snapshot is refreshed before reload continues"
        );
        std::fs::remove_file(&path).ok();
    }

    #[tokio::test]
    async fn reload_syncs_fib_snapshot_before_peer_group_delete() {
        let initial_toml = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
log_format = "json"

[peer_groups.fabric]
hold_time = 90

[[fib_tables]]
name = "edge"
table_id = 100
metric = 200
allowed_peer_groups = ["fabric"]
"#;
        let next_toml = r#"
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
        let path = unique_temp_path("reload-fib-before-pg-delete");
        std::fs::write(&path, initial_toml).unwrap();
        let initial = load_tier_test_config(&path);
        let tcp = initial.global.telemetry.grpc_tcp.clone();
        let uds = initial.global.telemetry.grpc_uds.clone();
        std::fs::write(&path, next_toml).unwrap();

        let (peer_mgr_tx, mut peer_mgr_rx) = mpsc::channel::<PeerManagerCommand>(8);
        let peer_mgr = tokio::spawn(async move {
            let mut tags = Vec::new();
            for _ in 0..2 {
                let Some(cmd) = peer_mgr_rx.recv().await else {
                    break;
                };
                tags.push(cmd_tag(&cmd));
                match cmd {
                    PeerManagerCommand::SetFibTablesSnapshot { reply, .. } => {
                        let _ = reply.send(());
                    }
                    PeerManagerCommand::DeletePeerGroup { reply, .. } => {
                        let _ = reply.send(Ok(()));
                    }
                    _ => panic!("unexpected peer manager command"),
                }
            }
            tags
        });
        let (fib_tx, mut fib_rx) = mpsc::channel(8);
        let actor = tokio::spawn(async move {
            match fib_rx.recv().await {
                Some(FibRuntimeCommand::ReplaceTables { tables, reply }) => {
                    assert!(tables[0].allowed_peer_groups.is_empty());
                    let _ = reply.send(Ok(()));
                }
                _ => panic!("expected ReplaceTables"),
            }
        });

        let returned = reload_config(
            path.to_str().unwrap(),
            &initial,
            tcp.as_ref(),
            uds.as_ref(),
            &peer_mgr_tx,
            Some(&fib_tx),
            None,
        )
        .await
        .expect("reload should remove the FIB reference and then delete the peer group");

        assert!(
            !returned.peer_groups.contains_key("fabric"),
            "peer group should be removed in the returned runtime snapshot"
        );
        assert!(
            returned.fib_tables[0].allowed_peer_groups.is_empty(),
            "FIB allow-list removal should be reflected in the returned runtime snapshot"
        );
        assert_eq!(
            peer_mgr.await.unwrap(),
            vec![
                "SetFibTablesSnapshot(1)".to_string(),
                "DeletePeerGroup(fabric)".to_string(),
            ],
            "peer manager must see the FIB reference removed before peer-group deletion"
        );
        actor.await.unwrap();
        std::fs::remove_file(&path).ok();
    }

    #[tokio::test]
    async fn reload_does_not_advance_fib_tables_when_actor_unreachable() {
        let path = unique_temp_path("reload-fib-tables-actor-gone");
        std::fs::write(&path, FIB_ONE_TABLE_TOML).unwrap();
        let initial = load_tier_test_config(&path);
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
            None,
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
        let initial = load_tier_test_config(&path);
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
        let initial = load_tier_test_config(&path);
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
        let initial = load_tier_test_config(&path);
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
            None,
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
        let initial = load_tier_test_config(&path);
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
        let initial = load_tier_test_config(&path);
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
            PeerManagerCommand::SyncRpolPolicies { rpol, .. } => {
                format!("SyncRpolPolicies({})", rpol.policies.len())
            }
            PeerManagerCommand::SetFibTablesSnapshot { tables, .. } => {
                format!("SetFibTablesSnapshot({})", tables.len())
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
        write_tier_test_config(&path, initial_toml);
        let initial = Config::load_with_diagnostics(path.to_str().unwrap()).unwrap();
        assert_tier_authorized_test_config(&initial);
        let live_grpc_tcp = initial.global.telemetry.grpc_tcp.clone();
        let live_grpc_uds = initial.global.telemetry.grpc_uds.clone();

        write_tier_test_config(&path, new_toml);

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
                    | PeerManagerCommand::SyncRpolPolicies { reply, .. } => {
                        let _ = reply.send(Ok(()));
                    }
                    PeerManagerCommand::SoftResetIn { reply, .. } => {
                        let _ = reply.send(Ok(()));
                    }
                    PeerManagerCommand::ReconcilePeers { reply, .. } => {
                        let _ = reply.send(ReconcileResult::default());
                    }
                    PeerManagerCommand::SetFibTablesSnapshot { reply, .. }
                    | PeerManagerCommand::SyncExplainConfig { reply, .. } => {
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
            None,
        )
        .await;
        if let Some(config) = returned.as_ref() {
            assert_tier_authorized_test_config(config);
            assert_tier_authorized_test_config(&config.desired);
        }
        drop(peer_mgr_tx);
        let tags = mock.await.unwrap();
        std::fs::remove_file(&path).ok();
        (returned, tags)
    }

    /// ADR-0096: an rpol-content-only reload sends `SyncRpolPolicies`
    /// (which re-resolves live chains in the manager) and adopts the
    /// new registry into the returned snapshot; the TOML itself is
    /// byte-identical, so no other command fires.
    #[tokio::test]
    async fn reload_rpol_content_change_syncs_registry() {
        let rpol_path = unique_temp_path("reload-rpol-file");
        std::fs::write(
            &rpol_path,
            "policy edge-in { term all { set local-pref 150; accept } }",
        )
        .unwrap();
        let toml = format!(
            "{}\n[policy]\nrpol_files = [{:?}]\nimport_chain = [\"edge-in\"]\n",
            baseline_toml(),
            rpol_path.to_str().unwrap(),
        );

        let path = unique_temp_path("reload-rpol-config");
        std::fs::write(&path, &toml).unwrap();
        let initial = Config::load_with_diagnostics(path.to_str().unwrap()).unwrap();
        let live_grpc_tcp = initial.global.telemetry.grpc_tcp.clone();
        let live_grpc_uds = initial.global.telemetry.grpc_uds.clone();

        // Edit ONLY the .rpol file; the TOML is unchanged.
        std::fs::write(
            &rpol_path,
            "policy edge-in { term all { set local-pref 250; accept } }",
        )
        .unwrap();

        let (peer_mgr_tx, mut peer_mgr_rx) = mpsc::channel::<PeerManagerCommand>(64);
        let mock = tokio::spawn(async move {
            let mut tags = Vec::new();
            while let Some(cmd) = peer_mgr_rx.recv().await {
                tags.push(cmd_tag(&cmd));
                if let PeerManagerCommand::SyncRpolPolicies { reply, .. } = cmd {
                    let _ = reply.send(Ok(()));
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
            None,
        )
        .await;
        drop(peer_mgr_tx);
        let tags = mock.await.unwrap();
        assert_eq!(tags, vec!["SyncRpolPolicies(1)".to_string()]);

        // The returned snapshot resolves chains against the NEW
        // compiled registry: the edited local-pref value evaluates.
        let reloaded = returned.expect("reload completes");
        let chain = reloaded
            .import_chain()
            .expect("chain resolves")
            .expect("chain configured");
        let ctx = rustbgpd_policy::RouteContext {
            prefix: None,
            next_hop: None,
            extended_communities: &[],
            communities: &[],
            large_communities: &[],
            as_path_str: "",
            as_path: None,
            as_path_len: 0,
            origin_asn: None,
            validation_state: rustbgpd_wire::RpkiValidation::NotFound,
            aspa_state: rustbgpd_wire::AspaValidation::Unknown,
            peer_address: None,
            peer_asn: None,
            peer_group: None,
            route_type: None,
            family: None,
            evpn_route_type: None,
            local_pref: None,
            med: None,
        };
        let result = chain.evaluate(&ctx);
        assert_eq!(result.modifications.set_local_pref, Some(250));

        std::fs::remove_file(&path).ok();
        std::fs::remove_file(&rpol_path).ok();
    }

    /// LAN-300: the rpol reload identity covers the whole resolved
    /// module graph. Editing ONLY an imported leaf (main file and TOML
    /// byte-identical) reads as an rpol content change — the reload
    /// sends `SyncRpolPolicies` and the returned snapshot evaluates
    /// the new leaf content. Reloading again with nothing touched is
    /// content-equal: no command fires (the #775 skip's input).
    #[expect(
        clippy::too_many_lines,
        reason = "one scenario drives two full reload rounds (leaf edit, then no-op) end to end"
    )]
    #[tokio::test]
    async fn reload_rpol_imported_leaf_edit_syncs_and_untouched_graph_is_a_noop() {
        let dir = tempfile::tempdir().unwrap();
        let dir = dir.path();
        let leaf_path = dir.join("leaf.rpol");
        std::fs::write(&leaf_path, "prefix-set drop-list { 127.0.0.0/8 le 32 }").unwrap();
        let main_path = dir.join("main.rpol");
        std::fs::write(
            &main_path,
            "import \"leaf.rpol\"\n\
             policy edge-in { term drop { if route.prefix in drop-list { reject } } }",
        )
        .unwrap();
        let toml = format!(
            "{}\n[policy]\nrpol_files = [{:?}]\nimport_chain = [\"edge-in\"]\n",
            baseline_toml(),
            main_path.to_str().unwrap(),
        );
        let path = dir.join("config.toml");
        std::fs::write(&path, &toml).unwrap();
        let initial = Config::load_with_diagnostics(path.to_str().unwrap()).unwrap();
        let live_grpc_tcp = initial.global.telemetry.grpc_tcp.clone();
        let live_grpc_uds = initial.global.telemetry.grpc_uds.clone();

        // Edit ONLY the imported leaf; main.rpol and the TOML are
        // byte-identical.
        std::fs::write(&leaf_path, "prefix-set drop-list { 192.0.2.0/24 le 32 }").unwrap();

        let run = |initial: Config| {
            let live_grpc_tcp = live_grpc_tcp.clone();
            let live_grpc_uds = live_grpc_uds.clone();
            let path = path.clone();
            async move {
                let (peer_mgr_tx, mut peer_mgr_rx) = mpsc::channel::<PeerManagerCommand>(64);
                let mock = tokio::spawn(async move {
                    let mut tags = Vec::new();
                    while let Some(cmd) = peer_mgr_rx.recv().await {
                        tags.push(cmd_tag(&cmd));
                        if let PeerManagerCommand::SyncRpolPolicies { reply, .. } = cmd {
                            let _ = reply.send(Ok(()));
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
                    None,
                )
                .await;
                drop(peer_mgr_tx);
                (returned, mock.await.unwrap())
            }
        };

        let (returned, tags) = run(initial).await;
        assert_eq!(
            tags,
            vec!["SyncRpolPolicies(1)".to_string()],
            "a leaf-module edit is an rpol content change"
        );
        let reloaded = returned.expect("reload completes");
        let chain = reloaded
            .import_chain()
            .expect("chain resolves")
            .expect("chain configured");
        let ctx = |addr: &str, len: u8| rustbgpd_policy::RouteContext {
            prefix: Some(rustbgpd_wire::Prefix::V4(rustbgpd_wire::Ipv4Prefix::new(
                addr.parse().unwrap(),
                len,
            ))),
            next_hop: None,
            extended_communities: &[],
            communities: &[],
            large_communities: &[],
            as_path_str: "",
            as_path: None,
            as_path_len: 0,
            origin_asn: None,
            validation_state: rustbgpd_wire::RpkiValidation::NotFound,
            aspa_state: rustbgpd_wire::AspaValidation::Unknown,
            peer_address: None,
            peer_asn: None,
            peer_group: None,
            route_type: None,
            family: None,
            evpn_route_type: None,
            local_pref: None,
            med: None,
        };
        // The NEW leaf content decides: 192.0.2.0/24 now rejects,
        // 127.0.0.0/8 no longer does.
        assert_eq!(
            chain.evaluate(&ctx("192.0.2.0", 24)).action,
            rustbgpd_policy::PolicyAction::Deny
        );
        assert_eq!(
            chain.evaluate(&ctx("127.0.0.0", 8)).action,
            rustbgpd_policy::PolicyAction::Permit
        );

        // Round 2: nothing touched — the resolved graph is
        // content-equal, so no rpol sync (or any other command) fires.
        let (returned, tags) = run(reloaded.runtime.clone()).await;
        assert!(returned.is_some(), "no-op reload completes");
        assert!(
            tags.is_empty(),
            "untouched module graph is a no-op: {tags:?}"
        );
    }

    /// LAN-284: a REJECTED rpol sync must not publish the candidate
    /// registry to the runtime snapshot. Sessions created after the
    /// failed reload resolve chains from that snapshot, so it has to
    /// keep evaluating the OLD policy decision; the candidate survives
    /// only as on-disk intent and a subsequent successful reload adopts
    /// it. Asserted at decision level (evaluated local-pref), not
    /// registry-pointer level.
    #[expect(
        clippy::too_many_lines,
        reason = "one scenario drives two full reload rounds (rejected, then adopted) end to end"
    )]
    #[tokio::test]
    async fn reload_rpol_sync_failure_keeps_old_registry_until_a_successful_retry() {
        let rpol_path = unique_temp_path("reload-rpol-fail-file");
        std::fs::write(
            &rpol_path,
            "policy edge-in { term all { set local-pref 150; accept } }",
        )
        .unwrap();
        let toml = format!(
            "{}\n[policy]\nrpol_files = [{:?}]\nimport_chain = [\"edge-in\"]\n",
            baseline_toml(),
            rpol_path.to_str().unwrap(),
        );
        let path = unique_temp_path("reload-rpol-fail-config");
        std::fs::write(&path, &toml).unwrap();
        let initial = Config::load_with_diagnostics(path.to_str().unwrap()).unwrap();
        let live_grpc_tcp = initial.global.telemetry.grpc_tcp.clone();
        let live_grpc_uds = initial.global.telemetry.grpc_uds.clone();

        // Operator edits ONLY the .rpol file; the TOML is unchanged.
        std::fs::write(
            &rpol_path,
            "policy edge-in { term all { set local-pref 250; accept } }",
        )
        .unwrap();

        let ctx = rustbgpd_policy::RouteContext {
            prefix: None,
            next_hop: None,
            extended_communities: &[],
            communities: &[],
            large_communities: &[],
            as_path_str: "",
            as_path: None,
            as_path_len: 0,
            origin_asn: None,
            validation_state: rustbgpd_wire::RpkiValidation::NotFound,
            aspa_state: rustbgpd_wire::AspaValidation::Unknown,
            peer_address: None,
            peer_asn: None,
            peer_group: None,
            route_type: None,
            family: None,
            evpn_route_type: None,
            local_pref: None,
            med: None,
        };

        // Reload 1: the peer manager REJECTS the sync (its own two-phase
        // apply rolled back, so live sessions keep the old chains).
        let (peer_mgr_tx, mut peer_mgr_rx) = mpsc::channel::<PeerManagerCommand>(64);
        let mock = tokio::spawn(async move {
            while let Some(cmd) = peer_mgr_rx.recv().await {
                if let PeerManagerCommand::SyncRpolPolicies { reply, .. } = cmd {
                    let _ = reply.send(Err(CatalogMutationError::internal(
                        "mid-apply chain resolution failed",
                    )));
                }
            }
        });
        let rejected = reload_config(
            path.to_str().unwrap(),
            &initial,
            live_grpc_tcp.as_ref(),
            live_grpc_uds.as_ref(),
            &peer_mgr_tx,
            None,
            None,
        )
        .await
        .expect("halted reload still returns the honest partial snapshot");
        drop(peer_mgr_tx);
        mock.await.unwrap();

        // The runtime snapshot — what a session created after the failed
        // reload resolves against — still evaluates the OLD decision.
        let chain = rejected
            .import_chain()
            .expect("chain resolves")
            .expect("chain configured");
        assert_eq!(chain.evaluate(&ctx).modifications.set_local_pref, Some(150));

        // Reload 2 (operator retries; peer manager now accepts): the
        // diff re-detects the on-disk candidate against the reverted
        // runtime snapshot and adopts it for everyone.
        let current: Config = (*rejected).clone();
        let (peer_mgr_tx, mut peer_mgr_rx) = mpsc::channel::<PeerManagerCommand>(64);
        let mock = tokio::spawn(async move {
            let mut synced = 0_u32;
            while let Some(cmd) = peer_mgr_rx.recv().await {
                if let PeerManagerCommand::SyncRpolPolicies { reply, .. } = cmd {
                    synced += 1;
                    let _ = reply.send(Ok(()));
                }
            }
            synced
        });
        let adopted = reload_config(
            path.to_str().unwrap(),
            &current,
            live_grpc_tcp.as_ref(),
            live_grpc_uds.as_ref(),
            &peer_mgr_tx,
            None,
            None,
        )
        .await
        .expect("retry reload completes");
        drop(peer_mgr_tx);
        assert_eq!(
            mock.await.unwrap(),
            1,
            "retry must re-detect the rpol change and sync it"
        );
        let chain = adopted
            .import_chain()
            .expect("chain resolves")
            .expect("chain configured");
        assert_eq!(chain.evaluate(&ctx).modifications.set_local_pref, Some(250));

        std::fs::remove_file(&path).ok();
        std::fs::remove_file(&rpol_path).ok();
    }

    fn baseline_toml() -> &'static str {
        static BASELINE: std::sync::OnceLock<String> = std::sync::OnceLock::new();
        BASELINE.get_or_init(|| {
            tier_authorized_uds_test_config(
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
        })
    }

    fn load_config_from_toml(name: &str, toml: &str) -> Config {
        let path = unique_temp_path(name);
        write_tier_test_config(&path, toml);
        let config = Config::load_with_diagnostics(path.to_str().unwrap()).unwrap();
        assert_tier_authorized_test_config(&config);
        std::fs::remove_file(&path).ok();
        config
    }

    #[test]
    fn tcp_ao_plan_accepts_only_append_only_nonpreferred_successor() {
        let initial = baseline_toml().replace(
            "hold_time = 90",
            "hold_time = 90\ntcp_ao = { key = \"old\", send_id = 1, recv_id = 11, algorithm = \"hmac(sha256)\" }",
        );
        let candidate = baseline_toml().replace(
            "hold_time = 90",
            r#"hold_time = 90
tcp_ao = [
  { key = "old", send_id = 1, recv_id = 11, algorithm = "hmac(sha256)" },
  { key = "successor", send_id = 2, recv_id = 12, algorithm = "hmac(sha256)" }
]"#,
        );
        let current = Config::load_toml_with_diagnostics(&initial, "current").unwrap();
        let desired = Config::load_toml_with_diagnostics(&candidate, "desired").unwrap();
        let plan =
            prepare_tcp_ao_rotation_plan(&current, &desired, &TcpAoRotationStatus::default())
                .unwrap();
        let TcpAoReloadPlan::Rotation(plan) = plan else {
            panic!("append-only successor should compile as a live generation");
        };
        assert_eq!(plan.generation.as_u64(), 2);
        assert_eq!(plan.static_keyrings.len(), 1);
        assert_eq!(plan.static_keyrings[0].1.0.len(), 2);
    }

    #[test]
    fn tcp_ao_plan_selects_installed_successor_and_reuses_awaiting_generation() {
        let current_toml = baseline_toml().replace(
            "hold_time = 90",
            r#"hold_time = 90
tcp_ao = [
  { key = "old", send_id = 1, recv_id = 11, algorithm = "hmac(sha256)" },
  { key = "successor", send_id = 2, recv_id = 12, algorithm = "hmac(sha256)" }
]"#,
        );
        let desired_toml = baseline_toml().replace(
            "hold_time = 90",
            r#"hold_time = 90
tcp_ao = [
  { key = "old", send_id = 1, recv_id = 11, algorithm = "hmac(sha256)", deprecated = true },
  { key = "successor", send_id = 2, recv_id = 12, algorithm = "hmac(sha256)", preferred = true }
]"#,
        );
        let current = Config::load_toml_with_diagnostics(&current_toml, "current").unwrap();
        let desired = Config::load_toml_with_diagnostics(&desired_toml, "desired").unwrap();
        let TcpAoReloadPlan::Rotation(plan) =
            prepare_tcp_ao_rotation_plan(&current, &desired, &TcpAoRotationStatus::default())
                .unwrap()
        else {
            panic!("installed successor selection should compile as a live generation");
        };
        assert_eq!(plan.operation, TcpAoRotationOperation::Selection);
        assert_eq!(plan.generation, TcpAoRotationGeneration::new(2).unwrap());

        let awaiting = TcpAoRotationStatus {
            desired: plan.generation,
            applied: TcpAoRotationGeneration::STARTUP,
            phase: TcpAoRotationPhase::AwaitingPeer,
            last_error: Some("awaiting successor traffic".to_string()),
        };
        let TcpAoReloadPlan::Rotation(retry) =
            prepare_tcp_ao_rotation_plan(&current, &desired, &awaiting).unwrap()
        else {
            panic!("awaiting selection should retain the same generation");
        };
        assert_eq!(retry.operation, TcpAoRotationOperation::Selection);
        assert_eq!(retry.generation, plan.generation);
        assert_eq!(retry.listener_keys, plan.listener_keys);
        assert_eq!(retry.static_keyrings, plan.static_keyrings);
    }

    #[test]
    fn tcp_ao_plan_deletes_only_deprecated_unselected_keys_and_reuses_failure_generation() {
        let current_toml = baseline_toml().replace(
            "hold_time = 90",
            r#"hold_time = 90
tcp_ao = [
  { key = "old", send_id = 1, recv_id = 11, algorithm = "hmac(sha256)", deprecated = true },
  { key = "successor", send_id = 2, recv_id = 12, algorithm = "hmac(sha256)", preferred = true }
]"#,
        );
        let desired_toml = baseline_toml().replace(
            "hold_time = 90",
            r#"hold_time = 90
tcp_ao = [
  { key = "successor", send_id = 2, recv_id = 12, algorithm = "hmac(sha256)", preferred = true }
]"#,
        );
        let current = Config::load_toml_with_diagnostics(&current_toml, "current").unwrap();
        let desired = Config::load_toml_with_diagnostics(&desired_toml, "desired").unwrap();
        let TcpAoReloadPlan::Rotation(plan) =
            prepare_tcp_ao_rotation_plan(&current, &desired, &TcpAoRotationStatus::default())
                .unwrap()
        else {
            panic!("deprecated predecessor deletion should compile as a live generation");
        };
        assert_eq!(plan.operation, TcpAoRotationOperation::Delete);
        assert_eq!(plan.current_static_keyrings[0].1.0.len(), 2);
        assert_eq!(plan.static_keyrings[0].1.0.len(), 1);

        let failed = TcpAoRotationStatus {
            desired: plan.generation,
            applied: TcpAoRotationGeneration::STARTUP,
            phase: TcpAoRotationPhase::DeleteFailed,
            last_error: Some("injected session failure".to_string()),
        };
        let TcpAoReloadPlan::Rotation(retry) =
            prepare_tcp_ao_rotation_plan(&current, &desired, &failed).unwrap()
        else {
            panic!("failed deletion should retain its exact generation");
        };
        assert_eq!(retry.operation, TcpAoRotationOperation::Delete);
        assert_eq!(retry.generation, plan.generation);
        assert_eq!(retry.current_listener_keys, plan.current_listener_keys);
        assert_eq!(retry.listener_keys, plan.listener_keys);

        let unsafe_current = current_toml.replace("deprecated = true", "deprecated = false");
        let unsafe_current =
            Config::load_toml_with_diagnostics(&unsafe_current, "unsafe-current").unwrap();
        assert!(matches!(
            prepare_tcp_ao_rotation_plan(
                &unsafe_current,
                &desired,
                &TcpAoRotationStatus::default()
            )
            .unwrap(),
            TcpAoReloadPlan::Unsupported(_)
        ));

        let current_v6 = Config::load_toml_with_diagnostics(
            &current_toml.replace("10.0.0.2", "2001:db8::2"),
            "current-v6",
        )
        .unwrap();
        let desired_v6 = Config::load_toml_with_diagnostics(
            &desired_toml.replace("10.0.0.2", "2001:db8::2"),
            "desired-v6",
        )
        .unwrap();
        let TcpAoReloadPlan::Rotation(opposite_family) =
            prepare_tcp_ao_rotation_plan(&current_v6, &desired_v6, &TcpAoRotationStatus::default())
                .unwrap()
        else {
            panic!("opposite-family static deletion must still compile as a live generation");
        };
        assert_eq!(opposite_family.operation, TcpAoRotationOperation::Delete);
        assert!(opposite_family.current_listener_keys.is_empty());
        assert!(opposite_family.listener_keys.is_empty());
        assert_eq!(opposite_family.current_static_keyrings[0].1.0.len(), 2);
        assert_eq!(opposite_family.static_keyrings[0].1.0.len(), 1);
    }

    #[test]
    fn tcp_ao_plan_reuses_failed_generation_and_rejects_selection_change() {
        let initial = baseline_toml().replace(
            "hold_time = 90",
            "hold_time = 90\ntcp_ao = { key = \"old\", send_id = 1, recv_id = 11, algorithm = \"hmac(sha256)\" }",
        );
        let candidate = baseline_toml().replace(
            "hold_time = 90",
            r#"hold_time = 90
tcp_ao = [
  { key = "old", send_id = 1, recv_id = 11, algorithm = "hmac(sha256)" },
  { key = "successor", send_id = 2, recv_id = 12, algorithm = "hmac(sha256)" }
]"#,
        );
        let current = Config::load_toml_with_diagnostics(&initial, "current").unwrap();
        let desired = Config::load_toml_with_diagnostics(&candidate, "desired").unwrap();
        let failed_generation = TcpAoRotationGeneration::new(2).unwrap();
        let status = TcpAoRotationStatus {
            desired: failed_generation,
            applied: TcpAoRotationGeneration::STARTUP,
            phase: TcpAoRotationPhase::AddOnlyFailed,
            last_error: Some("session apply failed".to_string()),
        };
        let TcpAoReloadPlan::Rotation(retry) =
            prepare_tcp_ao_rotation_plan(&current, &desired, &status).unwrap()
        else {
            panic!("failed add-only generation should remain retryable");
        };
        assert_eq!(retry.generation, failed_generation);

        let lost_marker_status = TcpAoRotationStatus {
            desired: failed_generation,
            applied: TcpAoRotationGeneration::STARTUP,
            phase: TcpAoRotationPhase::AddOnly,
            last_error: None,
        };
        let TcpAoReloadPlan::Rotation(retry) =
            prepare_tcp_ao_rotation_plan(&current, &desired, &lost_marker_status).unwrap()
        else {
            panic!("unacknowledged listener generation should remain retryable");
        };
        assert_eq!(retry.generation, failed_generation);

        let selected = candidate.replace(
            "algorithm = \"hmac(sha256)\" }\n]",
            "algorithm = \"hmac(sha256)\", preferred = true }\n]",
        );
        let selected = Config::load_toml_with_diagnostics(&selected, "selected").unwrap();
        assert!(matches!(
            prepare_tcp_ao_rotation_plan(&current, &selected, &TcpAoRotationStatus::default())
                .unwrap(),
            TcpAoReloadPlan::Unsupported(_)
        ));
    }

    #[test]
    fn tcp_ao_equal_config_recovers_unacknowledged_commit_then_allows_later_append() {
        let two_keys = baseline_toml().replace(
            "hold_time = 90",
            r#"hold_time = 90
tcp_ao = [
  { key = "old", send_id = 1, recv_id = 11, algorithm = "hmac(sha256)" },
  { key = "successor", send_id = 2, recv_id = 12, algorithm = "hmac(sha256)" }
]"#,
        );
        let current = Config::load_toml_with_diagnostics(&two_keys, "current").unwrap();
        let desired = Config::load_toml_with_diagnostics(&two_keys, "desired").unwrap();
        let generation_two = TcpAoRotationGeneration::new(2).unwrap();
        for phase in [
            TcpAoRotationPhase::AddOnly,
            TcpAoRotationPhase::AddOnlyFailed,
        ] {
            let unacknowledged = TcpAoRotationStatus {
                desired: generation_two,
                applied: TcpAoRotationGeneration::STARTUP,
                phase,
                last_error: (phase == TcpAoRotationPhase::AddOnlyFailed)
                    .then(|| "injected commit rejection".to_string()),
            };
            let TcpAoReloadPlan::Rotation(recovery) =
                prepare_tcp_ao_rotation_plan(&current, &desired, &unacknowledged).unwrap()
            else {
                panic!("equal config must recover the staged listener generation");
            };
            assert_eq!(recovery.generation, generation_two);
            assert_eq!(recovery.static_keyrings[0].1.0.len(), 2);
        }

        let three_keys = two_keys.replace(
            "  { key = \"successor\", send_id = 2, recv_id = 12, algorithm = \"hmac(sha256)\" }\n]",
            "  { key = \"successor\", send_id = 2, recv_id = 12, algorithm = \"hmac(sha256)\" },\n  { key = \"later\", send_id = 3, recv_id = 13, algorithm = \"hmac(sha256)\" }\n]",
        );
        let later = Config::load_toml_with_diagnostics(&three_keys, "later").unwrap();
        let committed = TcpAoRotationStatus {
            desired: generation_two,
            applied: generation_two,
            phase: TcpAoRotationPhase::Idle,
            last_error: None,
        };
        let TcpAoReloadPlan::Rotation(next) =
            prepare_tcp_ao_rotation_plan(&current, &later, &committed).unwrap()
        else {
            panic!("later append should not remain fenced after recovery");
        };
        assert_eq!(next.generation, TcpAoRotationGeneration::new(3).unwrap());
        assert_eq!(next.static_keyrings[0].1.0.len(), 3);
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
    async fn reload_pins_security_grpc_edits_to_startup_snapshot() {
        // LAN-286: [security.grpc] is resolved once at startup when the
        // gRPC listeners are built. A SIGHUP must pin the runtime
        // snapshot back to the startup authorization config — but keep
        // the operator's edit in the desired TOML for the next restart.
        let initial = baseline_toml();
        let new_toml = baseline_toml().replace(
            "\"rustbgpd://operator/test-only\" = \"operator\"",
            "\"rustbgpd://operator/test-only\" = \"operator\"\n\"observer-readonly\" = \"observer\"",
        );

        let (returned, tags) = drive_reload(initial, &new_toml).await;
        let returned = returned.expect("reload should return pinned runtime config");

        assert!(
            tags.is_empty(),
            "security-only edits are restart-required and must not reconcile peers: {tags:?}"
        );
        assert!(
            returned.security.grpc.roles.len() == 1,
            "runtime snapshot must keep the startup gRPC authorization config"
        );
        assert_eq!(
            returned.desired.security.grpc.roles.len(),
            2,
            "desired TOML must preserve the operator's edit for restart"
        );
    }

    #[tokio::test]
    async fn reload_pins_event_history_edits_to_startup_snapshot() {
        // LAN-286: every [event_history] field is restart-required (the
        // ADR-0072 outbox is configured once at startup). A SIGHUP must
        // pin the runtime snapshot back to the startup outbox config —
        // but keep the operator's edit in the desired TOML.
        let initial = baseline_toml();
        let new_toml = format!("{}\n[event_history]\nenabled = true\n", baseline_toml());

        let (returned, tags) = drive_reload(initial, &new_toml).await;
        let returned = returned.expect("reload should return pinned runtime config");

        assert!(
            tags.is_empty(),
            "event-history-only edits are restart-required and must not reconcile peers: {tags:?}"
        );
        assert!(
            !returned.event_history.enabled,
            "runtime snapshot must keep the startup (disabled) outbox config"
        );
        assert!(
            returned.desired.event_history.enabled,
            "desired TOML must preserve the operator's edit for restart"
        );
    }

    #[tokio::test]
    async fn reload_pins_managed_netdevs_edits_to_startup_snapshot() {
        // LAN-286: [managed_netdevs] is read once at startup by the
        // ADR-0091 lifecycle. A SIGHUP must pin the runtime snapshot
        // back to the startup netdev table — but keep the operator's
        // edit in the desired TOML for the next restart.
        let initial = baseline_toml();
        let new_toml = format!(
            "{}\n[managed_netdevs]\nowner_token = \"leaf-1\"\n",
            baseline_toml()
        );

        let (returned, tags) = drive_reload(initial, &new_toml).await;
        let returned = returned.expect("reload should return pinned runtime config");

        assert!(
            tags.is_empty(),
            "managed-netdev-only edits are restart-required and must not reconcile peers: {tags:?}"
        );
        assert!(
            returned.managed_netdevs.owner_token.is_empty(),
            "runtime snapshot must keep the startup managed-netdev table"
        );
        assert_eq!(
            returned.desired.managed_netdevs.owner_token, "leaf-1",
            "desired TOML must preserve the operator's edit for restart"
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
            returned.neighbors[0].tcp_ao.as_ref().unwrap().0[0].key,
            "old-secret",
            "runtime snapshot must keep the startup listener/session key"
        );
        assert_eq!(
            returned.desired.neighbors[0].tcp_ao.as_ref().unwrap().0[0].key,
            "new-secret",
            "desired TOML must preserve the operator's edit for restart"
        );
    }

    #[tokio::test]
    async fn reload_pins_tcp_ao_keyring_reordering_and_preserves_desired_order() {
        let old_ring = r#"tcp_ao = [
  { key = "old", send_id = 1, recv_id = 11, algorithm = "hmac(sha256)" },
  { key = "next", send_id = 2, recv_id = 12, algorithm = "hmac(sha256)", preferred = true }
]"#;
        let new_ring = r#"tcp_ao = [
  { key = "next", send_id = 2, recv_id = 12, algorithm = "hmac(sha256)", preferred = true },
  { key = "old", send_id = 1, recv_id = 11, algorithm = "hmac(sha256)" }
]"#;
        let initial =
            baseline_toml().replace("hold_time = 90", &format!("hold_time = 90\n{old_ring}"));
        let new_toml =
            baseline_toml().replace("hold_time = 90", &format!("hold_time = 90\n{new_ring}"));

        let (returned, tags) = drive_reload(&initial, &new_toml).await;
        let returned = returned.expect("reload should pin reordered startup keyring");
        assert!(
            tags.is_empty(),
            "reordering must not reach live reconciliation"
        );
        let runtime = returned.neighbors[0].tcp_ao.as_ref().unwrap();
        let desired = returned.desired.neighbors[0].tcp_ao.as_ref().unwrap();
        assert_eq!(
            runtime.0.iter().map(|key| key.send_id).collect::<Vec<_>>(),
            [1, 2]
        );
        assert_eq!(
            desired.0.iter().map(|key| key.send_id).collect::<Vec<_>>(),
            [2, 1]
        );
    }

    #[test]
    fn reload_pins_dynamic_tcp_ao_range_and_allows_disjoint_unprotected_edit() {
        let base = |key: &str, extra: &str| {
            format!(
                r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179
[global.telemetry]
log_format = "json"
[peer_groups.dynamic]
hold_time = 90
[[dynamic_neighbors]]
prefix = "10.0.0.0/24"
peer_group = "dynamic"
tcp_ao = {{ key = "{key}", send_id = 1, recv_id = 1, algorithm = "hmac(sha256)" }}
{extra}
"#
            )
        };
        let current = load_tier_test_toml(&base("old", ""), "old");
        let mut candidate = load_tier_test_toml(
            &base(
                "new",
                "[[dynamic_neighbors]]\nprefix = \"192.0.2.0/24\"\npeer_group = \"dynamic\"",
            ),
            "new",
        );

        assert_eq!(
            config::pin_dynamic_tcp_ao_startup_only(&mut candidate, &current),
            1
        );
        assert_eq!(candidate.dynamic_neighbors.len(), 2);
        let protected = candidate
            .dynamic_neighbors
            .iter()
            .find(|range| range.tcp_ao.is_some())
            .unwrap();
        assert_eq!(protected.tcp_ao.as_ref().unwrap().0[0].key, "old");
        assert!(
            candidate
                .dynamic_neighbors
                .iter()
                .any(|range| range.prefix == "192.0.2.0/24")
        );
    }

    #[test]
    fn reload_pins_dynamic_tcp_ao_range_without_reordering_unchanged_ranges() {
        let config = |key: &str| {
            format!(
                r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179
[global.telemetry]
log_format = "json"
[peer_groups.dynamic]
hold_time = 90
[[dynamic_neighbors]]
prefix = "192.0.2.0/24"
peer_group = "dynamic"
[[dynamic_neighbors]]
prefix = "10.0.0.0/24"
peer_group = "dynamic"
tcp_ao = {{ key = "{key}", send_id = 1, recv_id = 1, algorithm = "hmac(sha256)" }}
[[dynamic_neighbors]]
prefix = "198.51.100.0/24"
peer_group = "dynamic"
"#
            )
        };
        let current = load_tier_test_toml(&config("old"), "old");
        let mut candidate = load_tier_test_toml(&config("new"), "new");

        assert_eq!(
            config::pin_dynamic_tcp_ao_startup_only(&mut candidate, &current),
            1
        );
        assert_eq!(candidate.dynamic_neighbors, current.dynamic_neighbors);
    }

    #[tokio::test]
    async fn reload_rejects_unprotected_static_peer_inside_restored_dynamic_tcp_ao_boundary() {
        let initial = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179
[global.telemetry]
log_format = "json"
[peer_groups.dynamic]
hold_time = 90
[[dynamic_neighbors]]
prefix = "10.0.0.0/8"
peer_group = "dynamic"
tcp_ao = { key = "startup", send_id = 1, recv_id = 2, algorithm = "hmac(sha256)" }
"#;

        for (label, authentication) in [("plaintext", ""), ("MD5", "md5_password = \"new-md5\"")] {
            let desired = format!(
                r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179
[global.telemetry]
log_format = "json"
[peer_groups.dynamic]
hold_time = 90
[[neighbors]]
address = "10.1.1.1"
remote_asn = 65002
{authentication}
"#
            );
            let (returned, tags) = drive_reload(initial, &desired).await;
            assert!(
                returned.is_none(),
                "{label} peer must not cross the restored TCP-AO boundary"
            );
            assert!(
                tags.is_empty(),
                "{label} boundary rejection must precede peer-manager mutation: {tags:?}"
            );
        }
    }

    #[tokio::test]
    async fn reload_pins_new_static_tcp_ao_peer_inside_restored_dynamic_boundary() {
        let initial = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179
[global.telemetry]
log_format = "json"
[peer_groups.dynamic]
hold_time = 90
[[dynamic_neighbors]]
prefix = "10.0.0.0/8"
peer_group = "dynamic"
tcp_ao = { key = "dynamic-startup", send_id = 1, recv_id = 2, algorithm = "hmac(sha256)" }
"#;
        let desired = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179
[global.telemetry]
log_format = "json"
[peer_groups.dynamic]
hold_time = 90
[[neighbors]]
address = "10.1.1.1"
remote_asn = 65002
tcp_ao = { key = "static-next-start", send_id = 3, recv_id = 4, algorithm = "hmac(sha256)" }
"#;

        let (returned, tags) = drive_reload(initial, desired).await;
        let returned = returned.expect("valid startup-only AO edits are pinned");
        assert!(tags.is_empty(), "pinned AO addition must not mutate peers");
        assert!(returned.neighbors.is_empty());
        assert_eq!(returned.dynamic_neighbors.len(), 1);
        assert_eq!(
            returned.dynamic_neighbors[0].tcp_ao.as_ref().unwrap().0[0].key,
            "dynamic-startup"
        );
        assert_eq!(returned.desired.neighbors.len(), 1);
        assert!(returned.desired.dynamic_neighbors.is_empty());
    }

    #[tokio::test]
    async fn reload_rejects_tcp_ao_pin_conflict_before_evpn_runtime_apply() {
        let initial_toml = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179
[global.telemetry]
log_format = "json"
[peer_groups.dynamic]
hold_time = 90
[[dynamic_neighbors]]
prefix = "10.0.0.0/8"
peer_group = "dynamic"
tcp_ao = { key = "startup", send_id = 1, recv_id = 2, algorithm = "hmac(sha256)" }
"#;
        let desired_toml = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179
[global.telemetry]
log_format = "json"
[peer_groups.dynamic]
hold_time = 90
[[neighbors]]
address = "10.1.1.1"
remote_asn = 65002
[[evpn_instances]]
vni = 100
rd = "65000:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.1"
"#;
        let path = unique_temp_path("reload-ao-conflict-before-evpn");
        write_tier_test_config(&path, initial_toml);
        let initial = Config::load_with_diagnostics(path.to_str().unwrap()).unwrap();
        assert_tier_authorized_test_config(&initial);
        let live_grpc_tcp = initial.global.telemetry.grpc_tcp.clone();
        let live_grpc_uds = initial.global.telemetry.grpc_uds.clone();
        let (apply, coordinator) = evpn_reload_apply(&initial, Ok(()));
        write_tier_test_config(&path, desired_toml);
        let (peer_mgr_tx, _peer_mgr_rx) = mpsc::channel(8);

        let returned = reload_config(
            path.to_str().unwrap(),
            &initial,
            live_grpc_tcp.as_ref(),
            live_grpc_uds.as_ref(),
            &peer_mgr_tx,
            None,
            Some(&apply),
        )
        .await;

        assert!(returned.is_none());
        let guard = coordinator.lock().unwrap();
        assert!(
            guard.model().instances().is_empty(),
            "AO boundary rejection must precede EVPN coordinator mutation"
        );
        std::fs::remove_file(&path).ok();
    }

    #[tokio::test]
    async fn reload_content_only_dataset_swap_refreshes_dependents_before_return() {
        let config_toml = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179
[global.telemetry]
log_format = "json"
[policy]
rpol_files = ["policies/core.rpol"]
[policy.datasets.customers]
path = "datasets/customers.list"
[[neighbors]]
address = "192.0.2.1"
remote_asn = 65002
import_policy_chain = ["origin-guard"]
"#;
        let dir = dataset_reload_dir(config_toml, "64500\n");
        let config_path = dir.path().join("config.toml");
        let initial = Config::load_with_diagnostics(config_path.to_str().unwrap()).unwrap();
        let live = std::sync::Arc::clone(initial.policy.dataset_bindings.get("customers").unwrap());
        std::fs::write(dir.path().join("datasets/customers.list"), "64500\n64999\n").unwrap();
        let (peer_mgr_tx, mut peer_mgr_rx) = mpsc::channel(4);
        let refresh = tokio::spawn(async move {
            let command = peer_mgr_rx.recv().await.expect("dataset refresh command");
            match command {
                PeerManagerCommand::RefreshDatasetDependents {
                    swapped,
                    failed,
                    reply,
                } => {
                    assert_eq!(swapped, vec!["customers"]);
                    assert!(failed.is_empty());
                    let _ = reply.send(Ok(()));
                }
                other => panic!("expected dataset refresh, got {}", cmd_tag(&other)),
            }
        });

        let returned = reload_config(
            config_path.to_str().unwrap(),
            &initial,
            initial.global.telemetry.grpc_tcp.as_ref(),
            initial.global.telemetry.grpc_uds.as_ref(),
            &peer_mgr_tx,
            None,
            None,
        )
        .await
        .expect("content-only dataset reload succeeds");
        assert_tier_authorized_test_config(&returned);
        assert_tier_authorized_test_config(&returned.desired);
        refresh.await.unwrap();

        assert_eq!(live.pin().generation, 2);
        assert_eq!(live.pin().data.records(), 2);
        assert!(std::sync::Arc::ptr_eq(
            &live,
            returned.policy.dataset_bindings.get("customers").unwrap()
        ));
    }

    #[tokio::test]
    async fn reload_halt_before_dataset_step_leaves_live_snapshot_unmodified() {
        let config_toml = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179
[global.telemetry]
log_format = "json"
[policy]
rpol_files = ["policies/core.rpol"]
[policy.datasets.customers]
path = "datasets/customers.list"
[[neighbors]]
address = "192.0.2.1"
remote_asn = 65002
import_policy_chain = ["origin-guard"]
"#;
        let dir = dataset_reload_dir(config_toml, "64500\n");
        let config_path = dir.path().join("config.toml");
        let initial = Config::load_with_diagnostics(config_path.to_str().unwrap()).unwrap();
        let live = std::sync::Arc::clone(initial.policy.dataset_bindings.get("customers").unwrap());
        std::fs::write(dir.path().join("datasets/customers.list"), "64500\n64999\n").unwrap();
        // Explain is opt-in, so `enabled = true` is the value that
        // differs from the live snapshot and forces the explain-sync
        // step this test halts at.
        write_tier_test_config(
            &config_path,
            &format!("{config_toml}\n[policy.explain]\nenabled = true\n"),
        );
        let (peer_mgr_tx, peer_mgr_rx) = mpsc::channel(1);
        drop(peer_mgr_rx);

        let returned = reload_config(
            config_path.to_str().unwrap(),
            &initial,
            initial.global.telemetry.grpc_tcp.as_ref(),
            initial.global.telemetry.grpc_uds.as_ref(),
            &peer_mgr_tx,
            None,
            None,
        )
        .await
        .expect("explain-sync failure returns the honest partial snapshot");
        assert_tier_authorized_test_config(&returned);
        assert_tier_authorized_test_config(&returned.desired);

        assert_eq!(live.pin().generation, 1);
        assert_eq!(live.pin().data.records(), 1);
        assert!(std::sync::Arc::ptr_eq(
            &live,
            returned.policy.dataset_bindings.get("customers").unwrap()
        ));
    }

    #[tokio::test]
    async fn reload_neighbor_reconcile_failure_retains_committed_dataset_snapshot() {
        use rustbgpd_api::peer_types::{ReconcileFailure, ReconcileFailureKind, ReconcileResult};

        let initial_toml = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179
[global.telemetry]
log_format = "json"
[policy]
rpol_files = ["policies/core.rpol"]
[policy.datasets.customers]
path = "datasets/customers.list"
[[neighbors]]
address = "192.0.2.1"
remote_asn = 65002
import_policy_chain = ["origin-guard"]
"#;
        let desired_toml = initial_toml
            .replace("datasets/customers.list", "datasets/customers-next.list")
            + r#"
[[neighbors]]
address = "192.0.2.99"
remote_asn = 65099
"#;
        let dir = dataset_reload_dir(initial_toml, "64500\n");
        std::fs::write(
            dir.path().join("datasets/customers-next.list"),
            "64500\n64999\n",
        )
        .unwrap();
        let config_path = dir.path().join("config.toml");
        let initial = Config::load_with_diagnostics(config_path.to_str().unwrap()).unwrap();
        let live = std::sync::Arc::clone(initial.policy.dataset_bindings.get("customers").unwrap());
        write_tier_test_config(&config_path, &desired_toml);
        let (peer_mgr_tx, mut peer_mgr_rx) = mpsc::channel(8);
        let mock = tokio::spawn(async move {
            while let Some(command) = peer_mgr_rx.recv().await {
                match command {
                    PeerManagerCommand::RefreshDatasetDependents { reply, .. } => {
                        let _ = reply.send(Ok(()));
                    }
                    PeerManagerCommand::ReconcilePeers { reply, .. } => {
                        let _ = reply.send(ReconcileResult {
                            failures: vec![ReconcileFailure {
                                kind: ReconcileFailureKind::Add,
                                peer: rustbgpd_api::peer_types::PeerKey::new(
                                    "192.0.2.99".parse().unwrap(),
                                    None,
                                ),
                                error: "injected add failure".to_string(),
                            }],
                        });
                    }
                    other => panic!("unexpected command: {}", cmd_tag(&other)),
                }
            }
        });

        let returned = reload_config(
            config_path.to_str().unwrap(),
            &initial,
            initial.global.telemetry.grpc_tcp.as_ref(),
            initial.global.telemetry.grpc_uds.as_ref(),
            &peer_mgr_tx,
            None,
            None,
        )
        .await
        .expect("failed neighbor reconcile returns a partial snapshot");
        assert_tier_authorized_test_config(&returned);
        assert_tier_authorized_test_config(&returned.desired);
        drop(peer_mgr_tx);
        mock.await.unwrap();

        assert_eq!(live.pin().generation, 2);
        assert_eq!(live.pin().data.records(), 2);
        assert!(std::sync::Arc::ptr_eq(
            &live,
            returned.policy.dataset_bindings.get("customers").unwrap()
        ));
        assert!(
            returned.policy.datasets["customers"]
                .path
                .ends_with("datasets/customers-next.list")
        );
        assert_eq!(returned.neighbors, initial.neighbors);
    }

    #[tokio::test]
    async fn reload_rejects_tcp_ao_pin_conflict_without_committing_staged_datasets() {
        let initial_toml = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179
[global.telemetry]
log_format = "json"
[policy]
rpol_files = ["policies/core.rpol"]
[policy.datasets.customers]
path = "datasets/customers.list"
[peer_groups.dynamic]
hold_time = 90
[[dynamic_neighbors]]
prefix = "10.0.0.0/8"
peer_group = "dynamic"
tcp_ao = { key = "startup", send_id = 1, recv_id = 2, algorithm = "hmac(sha256)" }
"#;
        let desired_toml = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179
[global.telemetry]
log_format = "json"
[policy]
rpol_files = ["policies/core.rpol"]
[policy.datasets.customers]
path = "datasets/customers.list"
[peer_groups.dynamic]
hold_time = 90
[[neighbors]]
address = "10.1.1.1"
remote_asn = 65002
"#;
        let dir = dataset_reload_dir(initial_toml, "64500\n");
        let config_path = dir.path().join("config.toml");
        let initial = Config::load_with_diagnostics(config_path.to_str().unwrap()).unwrap();
        let live = std::sync::Arc::clone(initial.policy.dataset_bindings.get("customers").unwrap());
        std::fs::write(dir.path().join("datasets/customers.list"), "64500\n64999\n").unwrap();
        write_tier_test_config(&config_path, desired_toml);
        let (peer_mgr_tx, _peer_mgr_rx) = mpsc::channel(8);

        let returned = reload_config(
            config_path.to_str().unwrap(),
            &initial,
            initial.global.telemetry.grpc_tcp.as_ref(),
            initial.global.telemetry.grpc_uds.as_ref(),
            &peer_mgr_tx,
            None,
            None,
        )
        .await;

        assert!(returned.is_none());
        assert_eq!(live.pin().generation, 1);
        assert_eq!(live.pin().data.records(), 1);
        assert!(live.status().last_error.is_none());
    }

    #[test]
    fn dynamic_tcp_ao_pin_count_reports_only_affected_ranges() {
        let config = |ranges: &[(&str, &str)]| {
            let ranges = ranges.iter().fold(String::new(), |mut output, (prefix, key)| {
                write!(
                    output,
                    "[[dynamic_neighbors]]\nprefix = \"{prefix}\"\npeer_group = \"dynamic\"\ntcp_ao = {{ key = \"{key}\", send_id = 1, recv_id = 2, algorithm = \"hmac(sha256)\" }}\n"
                )
                .expect("writing to a String cannot fail");
                output
            });
            format!(
                "[global]\nasn = 65001\nrouter_id = \"10.0.0.1\"\nlisten_port = 179\n[global.telemetry]\nlog_format = \"json\"\n[peer_groups.dynamic]\nhold_time = 90\n{ranges}"
            )
        };
        let load = |ranges: &[(&str, &str)]| load_tier_test_toml(&config(ranges), "test");
        let current = load(&[
            ("192.0.2.0/24", "one"),
            ("198.51.100.0/24", "two"),
            ("203.0.113.0/24", "three"),
        ]);

        for (label, ranges, expected) in [
            (
                "equivalent host bits",
                vec![
                    ("192.0.2.1/24", "one"),
                    ("198.51.100.0/24", "two"),
                    ("203.0.113.0/24", "three"),
                ],
                0,
            ),
            (
                "reorder",
                vec![
                    ("203.0.113.0/24", "three"),
                    ("192.0.2.0/24", "one"),
                    ("198.51.100.0/24", "two"),
                ],
                0,
            ),
            (
                "rotate subset",
                vec![
                    ("192.0.2.0/24", "one"),
                    ("198.51.100.0/24", "changed"),
                    ("203.0.113.0/24", "three"),
                ],
                1,
            ),
            (
                "remove",
                vec![("192.0.2.0/24", "one"), ("198.51.100.0/24", "two")],
                1,
            ),
            (
                "add",
                vec![
                    ("192.0.2.0/24", "one"),
                    ("198.51.100.0/24", "two"),
                    ("203.0.113.0/24", "three"),
                    ("10.0.0.0/24", "four"),
                ],
                1,
            ),
        ] {
            let mut candidate = load(&ranges);
            assert_eq!(
                config::pin_dynamic_tcp_ao_startup_only(&mut candidate, &current),
                expected,
                "{label}"
            );
            if expected > 0 {
                assert_eq!(
                    candidate.dynamic_neighbors, current.dynamic_neighbors,
                    "{label}"
                );
            } else if label == "equivalent host bits" {
                assert_eq!(candidate.dynamic_neighbors[0].prefix, "192.0.2.1/24");
            }
        }
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
        // flip [policy.explain] in the same reload. Explain is opt-in,
        // so the flip that differs from the baseline is off → on.
        let new_toml = format!(
            "{}\n[policy.explain]\nenabled = true\n",
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
            tags[sync_idx].contains("enabled=true"),
            "sync must carry the new explain value — saw {tags:?}"
        );
    }

    /// Load-bearing peer-group reload proof: adding a definition must surface
    /// as `SetPeerGroup`, and the timed max-prefix policy must survive the
    /// config -> API -> config round trip. Dropping the field from either
    /// policy-admin conversion makes the final value assertion red.
    #[tokio::test]
    async fn reload_applies_peer_group_addition_with_max_prefix_restart() {
        let new_toml = format!(
            "{}\n[peer_groups.external]\nhold_time = 60\nmax_prefix_restart_seconds = 300\n",
            baseline_toml()
        );
        let (returned, tags) = drive_reload(baseline_toml(), &new_toml).await;
        let returned = returned.expect("reload must succeed");
        assert!(
            tags.contains(&"SetPeerGroup(external)".to_string()),
            "expected SetPeerGroup(external) — saw {tags:?}"
        );
        assert_eq!(
            returned.peer_groups["external"]
                .max_prefix_restart_seconds
                .map(std::num::NonZeroU32::get),
            Some(300),
            "SIGHUP must preserve the peer-group timed-restart policy"
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
            None,
        )
        .await;
        drop(peer_mgr_tx);
        let tags = mock.await.unwrap();
        std::fs::remove_file(&path).ok();

        // Live peers are ambiguous, so the partial snapshot keeps the prior
        // neighbor set. Earlier steps are known to have landed and must remain
        // represented; otherwise the next reload would retry them against a
        // fictional all-old snapshot.
        let returned = returned.expect("reconcile failure returns an honest partial snapshot");
        assert!(
            returned.policy.definitions.contains_key("block-private"),
            "the successfully applied policy must survive the partial snapshot"
        );
        assert_eq!(returned.neighbors, initial.neighbors);
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

        // Stand in for the peer manager: receive the snapshot and ack it so
        // apply_reload_outcome proceeds to the (failing) bridge send.
        let expected_asn = cfg.global.asn;
        let pm = tokio::spawn(async move {
            match peer_mgr_internal_rx.recv().await {
                Some(InternalCommand::ReplaceConfigSnapshot { config, ack }) => {
                    if let Some(ack) = ack {
                        let _ = ack.send(());
                    }
                    config.global.asn
                }
                None => panic!("peer manager must receive the snapshot"),
            }
        });

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
        assert_eq!(
            pm.await.unwrap(),
            expected_asn,
            "peer manager must receive the snapshot before the bridge send is attempted"
        );
    }

    /// Bridge-disabled mode (no persister, so no bridge) must succeed: the
    /// helper takes `Option<&Sender>`, and a `None` bridge is the shape an
    /// embedder or a unit test wires when nothing persists gRPC mutations.
    /// The daemon itself always has a bridge.
    #[tokio::test]
    async fn apply_reload_outcome_succeeds_without_bridge() {
        let (peer_mgr_internal_tx, mut peer_mgr_internal_rx) =
            mpsc::unbounded_channel::<InternalCommand>();

        let path = unique_temp_path("apply-reload-outcome-nobridge");
        std::fs::write(&path, baseline_toml()).unwrap();
        let cfg = Config::load_with_diagnostics(path.to_str().unwrap()).unwrap();
        std::fs::remove_file(&path).ok();

        // Stand in for the peer manager: receive the snapshot and ack it.
        let pm = tokio::spawn(async move {
            match peer_mgr_internal_rx.recv().await {
                Some(InternalCommand::ReplaceConfigSnapshot { ack: Some(ack), .. }) => {
                    ack.send(()).is_ok()
                }
                _ => false,
            }
        });

        let advanced = apply_reload_outcome(
            ReloadedConfig::new(cfg.clone(), cfg.clone()),
            &peer_mgr_internal_tx,
            None,
        )
        .await
        .expect("no-bridge mode must succeed");
        assert_eq!(advanced.global.asn, cfg.global.asn);
        assert!(pm.await.unwrap(), "peer manager must receive the snapshot");
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
        use tokio::time::{Duration, timeout};

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
                ack: None,
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
        let event_msg = timeout(Duration::from_secs(1), mutation_rx.recv())
            .await
            .expect("bridge should forward event to persister")
            .expect("event forwarded");
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
        timeout(Duration::from_secs(1), bridge)
            .await
            .expect("bridge should exit after both inputs close")
            .unwrap();
    }

    #[tokio::test]
    async fn config_bridge_acks_fib_table_event_after_persister_ack() {
        use rustbgpd_api::peer_types::{ConfigEvent, FibTableSnapshot};
        use tokio::sync::oneshot::error::TryRecvError;
        use tokio::time::{Duration, timeout};

        let stale_path = unique_temp_path("bridge-fib-ack-stale");
        std::fs::write(&stale_path, baseline_toml()).unwrap();
        let stale = Config::load_with_diagnostics(stale_path.to_str().unwrap()).unwrap();
        std::fs::remove_file(&stale_path).ok();

        let (event_tx, event_rx) = mpsc::channel::<ConfigEvent>(8);
        let (replace_tx, replace_rx) = mpsc::unbounded_channel::<Box<Config>>();
        let (mutation_tx, mut mutation_rx) = mpsc::channel::<ConfigMutation>(8);
        let bridge = tokio::spawn(run_config_bridge(event_rx, replace_rx, mutation_tx, stale));

        let (ack_tx, mut ack_rx) = oneshot::channel();
        event_tx
            .send(ConfigEvent::FibTablesReplaced {
                tables: vec![FibTableSnapshot {
                    name: "edge".to_string(),
                    table_id: 100,
                    metric: 200,
                    families: vec!["ipv4_unicast".to_string()],
                    allowed_peer_groups: Vec::new(),
                    allowed_neighbors: Vec::new(),
                    max_routes: None,
                    maximum_paths: None,
                    maximum_paths_ebgp: None,
                    maximum_paths_ibgp: None,
                }],
                ack: Some(ConfigPersistAck::immediate(ack_tx)),
            })
            .await
            .unwrap();

        let event_msg = timeout(Duration::from_secs(1), mutation_rx.recv())
            .await
            .expect("bridge should forward FIB event to persister")
            .expect("event forwarded");
        let ConfigMutation::ReplaceConfigAck(received_event, persist_ack) = event_msg else {
            panic!("fib-table events with an ack must request an acknowledged persist");
        };
        assert_eq!(received_event.fib_tables.len(), 1);
        assert!(
            matches!(ack_rx.try_recv(), Err(TryRecvError::Empty),),
            "bridge must not acknowledge the FIB event before the persister replies"
        );
        let _ = persist_ack.send(Ok(()));
        assert!(
            timeout(Duration::from_secs(1), ack_rx)
                .await
                .unwrap()
                .unwrap()
                .is_ok(),
            "FIB event ack should reflect the persister result"
        );

        drop(replace_tx);
        drop(event_tx);
        timeout(Duration::from_secs(1), bridge)
            .await
            .expect("bridge should exit after both inputs close")
            .unwrap();
    }

    #[tokio::test]
    async fn config_bridge_acks_config_transaction_after_persister_ack() {
        use rustbgpd_api::peer_types::ConfigEvent;
        use tokio::sync::oneshot::error::TryRecvError;
        use tokio::time::{Duration, timeout};

        let stale_path = unique_temp_path("bridge-transaction-ack-stale");
        std::fs::write(&stale_path, baseline_toml()).unwrap();
        let stale = Config::load_with_diagnostics(stale_path.to_str().unwrap()).unwrap();
        std::fs::remove_file(&stale_path).ok();

        let candidate_toml = format!(
            r#"{}

[peer_groups.fabric]
hold_time = 90

[[dynamic_neighbors]]
prefix = "192.0.2.0/24"
peer_group = "fabric"
remote_asn = 65002
"#,
            baseline_toml()
        );

        let (event_tx, event_rx) = mpsc::channel::<ConfigEvent>(8);
        let (replace_tx, replace_rx) = mpsc::unbounded_channel::<Box<Config>>();
        let (mutation_tx, mut mutation_rx) = mpsc::channel::<ConfigMutation>(8);
        let bridge = tokio::spawn(run_config_bridge(event_rx, replace_rx, mutation_tx, stale));

        let (ack_tx, mut ack_rx) = oneshot::channel();
        event_tx
            .send(ConfigEvent::ConfigTransactionCommitted {
                candidate_toml,
                ack: Some(ConfigPersistAck::immediate(ack_tx)),
            })
            .await
            .unwrap();

        let event_msg = timeout(Duration::from_secs(1), mutation_rx.recv())
            .await
            .expect("bridge should forward config transaction to persister")
            .expect("event forwarded");
        let ConfigMutation::ReplaceConfigAck(received_event, persist_ack) = event_msg else {
            panic!("config transaction events with an ack must request acknowledged persist");
        };
        assert!(received_event.peer_groups.contains_key("fabric"));
        assert_eq!(received_event.dynamic_neighbors.len(), 1);
        assert!(
            matches!(ack_rx.try_recv(), Err(TryRecvError::Empty),),
            "bridge must not acknowledge the config transaction before the persister replies"
        );
        let _ = persist_ack.send(Ok(()));
        assert!(
            timeout(Duration::from_secs(1), ack_rx)
                .await
                .unwrap()
                .unwrap()
                .is_ok(),
            "config transaction ack should reflect the persister result"
        );

        drop(replace_tx);
        drop(event_tx);
        timeout(Duration::from_secs(1), bridge)
            .await
            .expect("bridge should exit after both inputs close")
            .unwrap();
    }

    #[tokio::test]
    async fn config_bridge_acks_static_neighbor_event_after_persister_ack() {
        use rustbgpd_api::peer_types::{ConfigEvent, PeerManagerNeighborConfig};
        use rustbgpd_transport::RemovePrivateAs;
        use rustbgpd_wire::{Afi, Safi};
        use tokio::sync::oneshot::error::TryRecvError;
        use tokio::time::{Duration, timeout};

        let stale_path = unique_temp_path("bridge-static-ack-stale");
        std::fs::write(&stale_path, baseline_toml()).unwrap();
        let stale = Config::load_with_diagnostics(stale_path.to_str().unwrap()).unwrap();
        std::fs::remove_file(&stale_path).ok();

        let (event_tx, event_rx) = mpsc::channel::<ConfigEvent>(8);
        let (replace_tx, replace_rx) = mpsc::unbounded_channel::<Box<Config>>();
        let (mutation_tx, mut mutation_rx) = mpsc::channel::<ConfigMutation>(8);
        let bridge = tokio::spawn(run_config_bridge(event_rx, replace_rx, mutation_tx, stale));

        let (ack_tx, mut ack_rx) = oneshot::channel();
        event_tx
            .send(ConfigEvent::NeighborAdded {
                config: PeerManagerNeighborConfig {
                    min_hold_time: None,
                    address: "10.0.0.9".parse().unwrap(),
                    interface: None,
                    scope_id: None,
                    remote_asn: 65009,
                    description: "runtime peer".to_string(),
                    peer_group: None,
                    hold_time: Some(90),
                    send_hold_time: None,
                    max_prefixes: None,
                    max_prefixes_ipv4: None,
                    max_prefixes_ipv6: None,
                    max_prefix_restart_seconds: None,
                    md5_password: None,
                    tcp_ao: None,
                    ttl_security: false,
                    families: vec![(Afi::Ipv4, Safi::Unicast)],
                    required_families: Vec::new(),
                    graceful_restart: true,
                    gr_restart_time: 120,
                    gr_peer_restart_time_max: 4095,
                    gr_stale_routes_time: 360,
                    llgr_stale_time: 0,
                    gr_restart_eligible: false,
                    local_ipv6_nexthop: None,
                    route_reflector_client: false,
                    orr_vantage: None,
                    route_server_client: false,
                    per_client_best: false,
                    next_hop_ownership_strict_peer: false,
                    slow_peer_threshold_pct: rustbgpd_transport::DEFAULT_SLOW_PEER_THRESHOLD_PCT,
                    slow_peer_duration: rustbgpd_transport::DEFAULT_SLOW_PEER_DURATION_SECS,
                    slow_peer_isolation: false,
                    interpret_rfc1997: true,
                    rs_control_communities: false,
                    remove_private_as: RemovePrivateAs::Disabled,
                    add_path_receive: false,
                    add_path_send: false,
                    add_path_send_max: 0,
                    paths_limit_receive_max: 0,
                    local_role: None,
                    strict_role: false,
                    prefix_orf_receive: false,
                    disable_ipv4_unicast: false,
                    import_policy: None,
                    export_policy: None,
                },
                ack: Some(ConfigPersistAck::immediate(ack_tx)),
            })
            .await
            .unwrap();

        let event_msg = timeout(Duration::from_secs(1), mutation_rx.recv())
            .await
            .expect("bridge should forward static-neighbor event to persister")
            .expect("event forwarded");
        let ConfigMutation::ReplaceConfigAck(received_event, persist_ack) = event_msg else {
            panic!("static-neighbor events with an ack must request an acknowledged persist");
        };
        assert!(
            received_event
                .neighbors
                .iter()
                .any(|neighbor| neighbor.address == "10.0.0.9")
        );
        assert!(
            matches!(ack_rx.try_recv(), Err(TryRecvError::Empty),),
            "bridge must not acknowledge the static-neighbor event before the persister replies"
        );
        let _ = persist_ack.send(Ok(()));
        assert!(
            timeout(Duration::from_secs(1), ack_rx)
                .await
                .unwrap()
                .unwrap()
                .is_ok(),
            "static-neighbor event ack should reflect the persister result"
        );

        drop(replace_tx);
        drop(event_tx);
        timeout(Duration::from_secs(1), bridge)
            .await
            .expect("bridge should exit after both inputs close")
            .unwrap();
    }

    #[tokio::test]
    #[expect(
        clippy::too_many_lines,
        reason = "the regression keeps persistence failure and snapshot-fence assertions together"
    )]
    async fn config_bridge_does_not_advance_snapshot_on_acked_static_neighbor_persist_failure() {
        use rustbgpd_api::peer_types::{ConfigEvent, PeerManagerNeighborConfig};
        use rustbgpd_transport::RemovePrivateAs;
        use rustbgpd_wire::{Afi, Safi};
        use tokio::time::{Duration, timeout};

        let stale_path = unique_temp_path("bridge-static-ack-failure");
        std::fs::write(&stale_path, baseline_toml()).unwrap();
        let stale = Config::load_with_diagnostics(stale_path.to_str().unwrap()).unwrap();
        std::fs::remove_file(&stale_path).ok();

        let (event_tx, event_rx) = mpsc::channel::<ConfigEvent>(8);
        let (replace_tx, replace_rx) = mpsc::unbounded_channel::<Box<Config>>();
        let (mutation_tx, mut mutation_rx) = mpsc::channel::<ConfigMutation>(8);
        let bridge = tokio::spawn(run_config_bridge(event_rx, replace_rx, mutation_tx, stale));

        let (ack_tx, ack_rx) = oneshot::channel();
        event_tx
            .send(ConfigEvent::NeighborAdded {
                config: PeerManagerNeighborConfig {
                    min_hold_time: None,
                    address: "10.0.0.9".parse().unwrap(),
                    interface: None,
                    scope_id: None,
                    remote_asn: 65009,
                    description: "runtime peer".to_string(),
                    peer_group: None,
                    hold_time: Some(90),
                    send_hold_time: None,
                    max_prefixes: None,
                    max_prefixes_ipv4: None,
                    max_prefixes_ipv6: None,
                    max_prefix_restart_seconds: None,
                    md5_password: None,
                    tcp_ao: None,
                    ttl_security: false,
                    families: vec![(Afi::Ipv4, Safi::Unicast)],
                    required_families: Vec::new(),
                    graceful_restart: true,
                    gr_restart_time: 120,
                    gr_peer_restart_time_max: 4095,
                    gr_stale_routes_time: 360,
                    llgr_stale_time: 0,
                    gr_restart_eligible: false,
                    local_ipv6_nexthop: None,
                    route_reflector_client: false,
                    orr_vantage: None,
                    route_server_client: false,
                    per_client_best: false,
                    next_hop_ownership_strict_peer: false,
                    slow_peer_threshold_pct: rustbgpd_transport::DEFAULT_SLOW_PEER_THRESHOLD_PCT,
                    slow_peer_duration: rustbgpd_transport::DEFAULT_SLOW_PEER_DURATION_SECS,
                    slow_peer_isolation: false,
                    interpret_rfc1997: true,
                    rs_control_communities: false,
                    remove_private_as: RemovePrivateAs::Disabled,
                    add_path_receive: false,
                    add_path_send: false,
                    add_path_send_max: 0,
                    paths_limit_receive_max: 0,
                    local_role: None,
                    strict_role: false,
                    prefix_orf_receive: false,
                    disable_ipv4_unicast: false,
                    import_policy: None,
                    export_policy: None,
                },
                ack: Some(ConfigPersistAck::immediate(ack_tx)),
            })
            .await
            .unwrap();
        let first_msg = timeout(Duration::from_secs(1), mutation_rx.recv())
            .await
            .expect("bridge should forward acked event")
            .expect("event forwarded");
        let ConfigMutation::ReplaceConfigAck(first_candidate, persist_ack) = first_msg else {
            panic!("acked event must request acknowledged persist");
        };
        assert!(
            first_candidate
                .neighbors
                .iter()
                .any(|neighbor| neighbor.address == "10.0.0.9")
        );
        let _ = persist_ack.send(Err("disk full".to_string()));
        assert_eq!(
            timeout(Duration::from_secs(1), ack_rx)
                .await
                .unwrap()
                .unwrap()
                .unwrap_err()
                .to_string(),
            "disk full"
        );

        event_tx
            .send(ConfigEvent::NeighborDeleted {
                peer: rustbgpd_api::peer_types::PeerKey {
                    address: "10.0.0.2".parse().unwrap(),
                    interface: None,
                },
                ack: None,
            })
            .await
            .unwrap();
        let second_msg = timeout(Duration::from_secs(1), mutation_rx.recv())
            .await
            .expect("bridge should forward second event")
            .expect("event forwarded");
        let ConfigMutation::ReplaceConfig(second_candidate) = second_msg else {
            panic!("non-acked event should request normal persist");
        };
        assert!(
            second_candidate
                .neighbors
                .iter()
                .all(|neighbor| neighbor.address != "10.0.0.9"),
            "failed acked event must not remain in bridge snapshot"
        );

        drop(replace_tx);
        drop(event_tx);
        timeout(Duration::from_secs(1), bridge)
            .await
            .expect("bridge should exit after both inputs close")
            .unwrap();
    }

    #[tokio::test]
    async fn config_bridge_acks_dynamic_neighbor_event_after_persister_ack() {
        use rustbgpd_api::peer_types::ConfigEvent;
        use tokio::sync::oneshot::error::TryRecvError;
        use tokio::time::{Duration, timeout};

        let stale_path = unique_temp_path("bridge-dynamic-ack-stale");
        let stale_toml = format!(
            r"
{}

[peer_groups.fabric]
",
            baseline_toml()
        );
        std::fs::write(&stale_path, stale_toml).unwrap();
        let stale = Config::load_with_diagnostics(stale_path.to_str().unwrap()).unwrap();
        std::fs::remove_file(&stale_path).ok();

        let (event_tx, event_rx) = mpsc::channel::<ConfigEvent>(8);
        let (replace_tx, replace_rx) = mpsc::unbounded_channel::<Box<Config>>();
        let (mutation_tx, mut mutation_rx) = mpsc::channel::<ConfigMutation>(8);
        let bridge = tokio::spawn(run_config_bridge(event_rx, replace_rx, mutation_tx, stale));

        let (ack_tx, mut ack_rx) = oneshot::channel();
        event_tx
            .send(ConfigEvent::DynamicNeighborAdded {
                prefix: "192.0.2.0/24".to_string(),
                peer_group: "fabric".to_string(),
                remote_asn: 65002,
                description: Some("lab range".to_string()),
                ack: Some(ConfigPersistAck::immediate(ack_tx)),
            })
            .await
            .unwrap();

        let event_msg = timeout(Duration::from_secs(1), mutation_rx.recv())
            .await
            .expect("bridge should forward dynamic-neighbor event to persister")
            .expect("event forwarded");
        let ConfigMutation::ReplaceConfigAck(received_event, persist_ack) = event_msg else {
            panic!("dynamic-neighbor events with an ack must request an acknowledged persist");
        };
        assert_eq!(received_event.dynamic_neighbors.len(), 1);
        assert!(
            matches!(ack_rx.try_recv(), Err(TryRecvError::Empty),),
            "bridge must not acknowledge the dynamic-neighbor event before the persister replies"
        );
        let _ = persist_ack.send(Ok(()));
        assert!(
            timeout(Duration::from_secs(1), ack_rx)
                .await
                .unwrap()
                .unwrap()
                .is_ok(),
            "dynamic-neighbor event ack should reflect the persister result"
        );

        drop(replace_tx);
        drop(event_tx);
        timeout(Duration::from_secs(1), bridge)
            .await
            .expect("bridge should exit after both inputs close")
            .unwrap();
    }

    #[tokio::test]
    async fn config_bridge_does_not_advance_snapshot_on_acked_persist_failure() {
        use rustbgpd_api::peer_types::ConfigEvent;
        use tokio::time::{Duration, timeout};

        let stale_path = unique_temp_path("bridge-dynamic-ack-failure");
        let stale_toml = format!(
            r"
{}

[peer_groups.fabric]
",
            baseline_toml()
        );
        std::fs::write(&stale_path, stale_toml).unwrap();
        let stale = Config::load_with_diagnostics(stale_path.to_str().unwrap()).unwrap();
        std::fs::remove_file(&stale_path).ok();

        let (event_tx, event_rx) = mpsc::channel::<ConfigEvent>(8);
        let (replace_tx, replace_rx) = mpsc::unbounded_channel::<Box<Config>>();
        let (mutation_tx, mut mutation_rx) = mpsc::channel::<ConfigMutation>(8);
        let bridge = tokio::spawn(run_config_bridge(event_rx, replace_rx, mutation_tx, stale));

        let (ack_tx, ack_rx) = oneshot::channel();
        event_tx
            .send(ConfigEvent::DynamicNeighborAdded {
                prefix: "192.0.2.0/24".to_string(),
                peer_group: "fabric".to_string(),
                remote_asn: 65002,
                description: None,
                ack: Some(ConfigPersistAck::immediate(ack_tx)),
            })
            .await
            .unwrap();
        let first_msg = timeout(Duration::from_secs(1), mutation_rx.recv())
            .await
            .expect("bridge should forward acked event")
            .expect("event forwarded");
        let ConfigMutation::ReplaceConfigAck(first_candidate, persist_ack) = first_msg else {
            panic!("acked event must request acknowledged persist");
        };
        assert_eq!(first_candidate.dynamic_neighbors.len(), 1);
        let _ = persist_ack.send(Err("disk full".to_string()));
        assert_eq!(
            timeout(Duration::from_secs(1), ack_rx)
                .await
                .unwrap()
                .unwrap()
                .unwrap_err()
                .to_string(),
            "disk full"
        );

        event_tx
            .send(ConfigEvent::DynamicNeighborAdded {
                prefix: "192.0.3.0/24".to_string(),
                peer_group: "fabric".to_string(),
                remote_asn: 65003,
                description: None,
                ack: None,
            })
            .await
            .unwrap();
        let second_msg = timeout(Duration::from_secs(1), mutation_rx.recv())
            .await
            .expect("bridge should forward second event")
            .expect("event forwarded");
        let ConfigMutation::ReplaceConfig(second_candidate) = second_msg else {
            panic!("non-acked event should request normal persist");
        };
        assert_eq!(
            second_candidate.dynamic_neighbors.len(),
            1,
            "failed acked event must not remain in bridge snapshot"
        );
        assert_eq!(second_candidate.dynamic_neighbors[0].prefix, "192.0.3.0/24");

        drop(replace_tx);
        drop(event_tx);
        timeout(Duration::from_secs(1), bridge)
            .await
            .expect("bridge should exit after both inputs close")
            .unwrap();
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
        let persister = tokio::spawn(
            ConfigPersister::new(mutation_rx, path.clone(), initial.clone(), None).run(),
        );
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
            None,
        )
        .await
        .expect("reload should return pinned runtime plus desired config");

        let (peer_mgr_internal_tx, mut peer_mgr_internal_rx) =
            mpsc::unbounded_channel::<InternalCommand>();
        let pm = tokio::spawn(async move {
            match peer_mgr_internal_rx.recv().await {
                Some(InternalCommand::ReplaceConfigSnapshot { ack: Some(ack), .. }) => {
                    ack.send(()).is_ok()
                }
                _ => false,
            }
        });
        let runtime = apply_reload_outcome(reloaded, &peer_mgr_internal_tx, Some(&replace_tx))
            .await
            .expect("post-reload sync should succeed");
        assert!(pm.await.unwrap(), "peer manager snapshot must be refreshed");

        event_tx
            .send(ConfigEvent::SetPolicy {
                name: "after-reload".to_string(),
                definition: NamedPolicyDefinition {
                    default_action: "deny".to_string(),
                    statements: Vec::new(),
                },
                ack: None,
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
        assert_tier_authorized_test_config(&runtime);
        assert_eq!(
            disk.security.grpc.enforcement,
            crate::config::GrpcEnforcementConfig::Tier
        );
        let disk_uds = disk
            .global
            .telemetry
            .grpc_uds
            .as_ref()
            .expect("persisted Tier config must keep its UDS listener");
        assert!(
            disk_uds.path.is_some(),
            "persisted UDS path must remain set"
        );
        let disk_principal = disk_uds
            .principal
            .as_deref()
            .expect("persisted UDS principal must remain set");
        assert_eq!(
            disk.security.grpc.roles.get(disk_principal),
            Some(&crate::config::GrpcRoleConfig::Operator)
        );
        (runtime, disk)
    }

    #[tokio::test]
    async fn reload_pin_grpc_uds_preserves_desired_toml_for_later_persistence() {
        let new_toml =
            baseline_toml().replace("/tmp/rustbgpd-test.sock", "/tmp/rustbgpd-edited.sock");
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

    /// ADR-0112: the RFC 8212 enforcement mode is restart-required. A SIGHUP
    /// must keep the running snapshot on the startup value while the desired /
    /// on-disk snapshot carries the operator's edit forward for persistence.
    /// Hot-applying it would flip import and export on every EBGP session at
    /// once, inside a reload.
    #[tokio::test]
    async fn reload_pin_ebgp_requires_policy_preserves_desired_toml_for_later_persistence() {
        let new_toml = baseline_toml().replace(
            "listen_port = 179",
            "listen_port = 179\nebgp_requires_policy = true",
        );
        let (runtime, disk) = reload_then_persist_policy_after_desired_refresh(&new_toml).await;

        assert!(
            !runtime.global.ebgp_requires_policy,
            "runtime must stay pinned to the live startup value"
        );
        assert!(
            disk.global.ebgp_requires_policy,
            "desired/disk snapshot must reflect the operator's opt-in"
        );
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
        let old = load_tier_test_config(&path_a);
        let new = load_tier_test_config(&path_b);
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
        let old = load_tier_test_config(&path_a);
        let new = load_tier_test_config(&path_b);
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
        let old = load_tier_test_config(&path_a);
        let new = load_tier_test_config(&path_b);
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
