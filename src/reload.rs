//! SIGHUP reload and config-persistence bridge support.
//!
//! This module owns the runtime config reload pipeline that used to live in
//! `main.rs`: gRPC config-event persistence, restart-required field pinning,
//! and ordered peer-manager reconciliation.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Instant;

use rustbgpd_api::peer_types::ConfigPersistCommitOutcome;
use rustbgpd_api::peer_types::{
    CatalogMutationError, ConfigEvent, ConfigPersistAck, ConfigPersistError, FibTableSnapshot,
    OwnedCatalogMutation, OwnedCatalogMutationOutcome, OwnedHotUpdatePeerOutcome,
    PeerManagerCommand, PeerManagerNeighborConfig, PeerReconcileAuthority, PeerReconcileEffect,
};
use rustbgpd_policy::PolicyChain;
use tokio::sync::{mpsc, oneshot, watch};
use tracing::{error, info, warn};

use rustbgpd_api::gnmi_dialout::DialoutTarget;
use rustbgpd_api::runtime_config_settlement::{
    OwnedRuntimeConfigOperation, OwnedRuntimeConfigOutcome, RuntimeConfigFenceReason,
    RuntimeConfigSettlementPhase,
};
use rustbgpd_transport::listener::ReloadDispatch;
use rustbgpd_transport::{
    TcpAoKeyring, TcpAoListenerGeneration, TcpAoListenerHandle, TcpAoListenerKey,
    TcpAoListenerOwnerKind, TcpAoRotationGeneration, TcpAoRotationOperation, TcpAoRotationPhase,
    TcpAoRotationStatus,
};

use crate::config::{self, AcceptedConfigSnapshot, Config};
use crate::config_persister::ConfigMutation;
use crate::evpn_runtime_converger::{EvpnRuntimeReloadApply, EvpnRuntimeReloadTerminal};
use crate::fib_runtime::{FibRuntimeCommand, OwnedFibReplaceOutcome};
use crate::peer_manager::InternalCommand;
use crate::policy_admin::{self, apply_config_event, catalog_config_error};

#[cfg(debug_assertions)]
fn sighup_ack_fault(point: &str) -> bool {
    std::env::var("RUSTBGPD_TEST_SIGHUP_ACK_LOSS").is_ok_and(|value| value == point)
}

#[cfg(not(debug_assertions))]
fn sighup_ack_fault(_point: &str) -> bool {
    false
}

/// Monotonic identity for one outbound prefix-limit transaction. Activation
/// is idempotent by it, so a retry cannot apply two recovery transitions.
pub(crate) fn next_outbound_prefix_limit_txn() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT: AtomicU64 = AtomicU64::new(1);
    NEXT.fetch_add(1, Ordering::Relaxed)
}

async fn dispatch_rib_step<T, E>(
    rib_tx: &mpsc::Sender<rustbgpd_rib::RibUpdate>,
    build: impl FnOnce(oneshot::Sender<Result<T, E>>) -> rustbgpd_rib::RibUpdate,
) -> ReloadDispatch<Result<T, E>, String> {
    let (reply_tx, reply_rx) = oneshot::channel();
    let permit = match rib_tx.reserve().await {
        Ok(permit) => permit,
        Err(error) => return ReloadDispatch::NotAccepted(error.to_string()),
    };
    permit.send(build(reply_tx));
    match reply_rx.await {
        Ok(result) => ReloadDispatch::Replied(result),
        Err(_) => ReloadDispatch::AcknowledgementLost,
    }
}

async fn dispatch_rib_mutation_step<T, E>(
    rib_tx: &mpsc::Sender<rustbgpd_rib::RibUpdate>,
    progress: &SighupMutationProgress<'_>,
    build: impl FnOnce(oneshot::Sender<Result<T, E>>) -> rustbgpd_rib::RibUpdate,
) -> ReloadDispatch<Result<T, E>, String> {
    let (reply_tx, reply_rx) = oneshot::channel();
    let permit = match rib_tx.reserve().await {
        Ok(permit) => permit,
        Err(error) => return ReloadDispatch::NotAccepted(error.to_string()),
    };
    progress.begin_mutation();
    permit.send(build(reply_tx));
    match reply_rx.await {
        Ok(result) => ReloadDispatch::Replied(result),
        Err(_) => ReloadDispatch::AcknowledgementLost,
    }
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
    match dispatch_rib_step(rib_tx, |reply| {
        rustbgpd_rib::RibUpdate::PrepareOutboundPrefixLimits {
            txn,
            config: config.outbound_prefix_limits(),
            reply,
        }
    })
    .await
    {
        ReloadDispatch::Replied(Ok(())) => Ok(()),
        ReloadDispatch::Replied(Err(violations)) => Err(format!(
            "outbound prefix limit rejected: {}",
            violations
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join("; ")
        )),
        ReloadDispatch::NotAccepted(_) => Err("RIB manager unavailable".to_string()),
        ReloadDispatch::AcknowledgementLost => {
            Err("RIB manager dropped the outbound prefix-limit preflight".to_string())
        }
    }
}

/// Activate (or discard) a prepared outbound prefix-limit transaction.
pub(crate) async fn finish_outbound_prefix_limits(
    rib_tx: &mpsc::Sender<rustbgpd_rib::RibUpdate>,
    txn: u64,
    activate: bool,
) -> Result<(), String> {
    match dispatch_rib_step(rib_tx, |reply| {
        rustbgpd_rib::RibUpdate::ApplyOutboundPrefixLimits {
            txn,
            activate,
            reply,
        }
    })
    .await
    {
        ReloadDispatch::NotAccepted(_) => Err("RIB manager unavailable".to_string()),
        ReloadDispatch::Replied(result) => result,
        ReloadDispatch::AcknowledgementLost => {
            Err("RIB manager dropped the outbound prefix-limit activation".to_string())
        }
    }
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

/// SIGHUP wrapper around [`apply_outbound_prefix_limits`]: skip the RIB
/// round-trips entirely when the desired maxima equal the live ones.
///
/// LAN-888: the preflight is two awaited sends through the RIB manager's
/// update channel, FIFO behind any in-flight redistribution backlog — on
/// repeat IRR-scale reloads in per-client-best mode that queue wait
/// dominated the whole SIGHUP→snapshot window (~78 s of a ~79 s reload).
/// The ADR-0113 check only ever rejects a *lowering* below current
/// advertised usage, so an unchanged limit set cannot be rejected and the
/// preflight is a no-op by construction; activation would re-install the
/// identical set. The common rpol-content-only reload therefore never
/// touches the RIB here.
#[cfg(test)]
pub(crate) async fn apply_outbound_prefix_limits_if_changed(
    rib_tx: &mpsc::Sender<rustbgpd_rib::RibUpdate>,
    live: &Config,
    desired: &Config,
) -> Result<(), String> {
    if live.outbound_prefix_limits() == desired.outbound_prefix_limits() {
        info!("outbound prefix maxima unchanged; skipping RIB preflight");
        return Ok(());
    }
    apply_outbound_prefix_limits(rib_tx, desired).await
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
        ttl_security_hops: tc.ttl_security_hops,
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
        send_non_transitive_extended_communities: tc.send_non_transitive_extended_communities,
        per_client_best: tc.per_client_best,
        next_hop_ownership_strict_peer: tc.next_hop_ownership_strict_peer,
        slow_peer_threshold_pct: tc.slow_peer_threshold_pct,
        slow_peer_duration: tc.slow_peer_duration,
        slow_peer_isolation: tc.slow_peer_isolation,
        interpret_rfc1997: tc.interpret_rfc1997,
        rs_control_communities: tc.rs_control_communities,
        remove_private_as: tc.remove_private_as,
        discard_path_attributes: tc.discard_path_attributes.clone(),
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
#[derive(Clone, Debug)]
pub(crate) struct ReloadStepFailure {
    /// Which delta bucket the command came from
    /// (e.g., `"policy.set"`, `"peer_group.delete"`).
    bucket: &'static str,
    /// Identifier of the affected object (policy / peer-group / set name,
    /// or neighbor address). Empty for global-chain operations.
    target: String,
    /// Human-readable failure reason.
    error: ReloadStepError,
}

#[derive(Clone, Debug)]
pub(crate) enum ReloadStepError {
    NotAccepted(String),
    Rejected(String),
    AcknowledgementLost,
}

impl From<String> for ReloadStepError {
    fn from(error: String) -> Self {
        Self::Rejected(error)
    }
}

impl std::fmt::Display for ReloadStepError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotAccepted(error) | Self::Rejected(error) => formatter.write_str(error),
            Self::AcknowledgementLost => formatter.write_str("acknowledgement lost"),
        }
    }
}

#[derive(Clone)]
pub(crate) struct SighupReloadPlan {
    pub(crate) baseline_runtime: Config,
    pub(crate) desired: Arc<AcceptedConfigSnapshot>,
    pub(crate) accepted_effect: bool,
}

#[derive(Clone)]
pub(crate) struct SighupAuthority {
    pub(crate) runtime: Config,
    pub(crate) desired: Arc<AcceptedConfigSnapshot>,
    pub(crate) dialout_targets: Vec<DialoutTarget>,
    pub(crate) completion: SighupCompletion,
}

#[derive(Clone, Debug)]
pub(crate) enum SighupCompletion {
    Complete,
    KnownPartial { failures: Vec<ReloadStepFailure> },
}

#[derive(Clone, Debug)]
pub(crate) enum SighupReloadError {
    CoordinatorClosed,
    Failed(ReloadStepFailure),
}

impl From<rustbgpd_api::server::RuntimeConfigCoordinatorClosed> for SighupReloadError {
    fn from(_: rustbgpd_api::server::RuntimeConfigCoordinatorClosed) -> Self {
        Self::CoordinatorClosed
    }
}

impl std::fmt::Display for SighupReloadError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CoordinatorClosed => formatter.write_str("runtime config coordinator is closed"),
            Self::Failed(failure) => write!(
                formatter,
                "{} {}: {}",
                failure.bucket, failure.target, failure.error
            ),
        }
    }
}

impl SighupReloadError {
    pub(crate) fn preflight(bucket: &'static str, error: impl Into<String>) -> Self {
        sighup_error(
            bucket,
            String::new(),
            ReloadStepError::Rejected(error.into()),
        )
    }

    pub(crate) fn step(bucket: &'static str, error: ReloadStepError) -> Self {
        sighup_error(bucket, String::new(), error)
    }
}

#[expect(clippy::large_enum_variant, reason = "T288 keeps authority unboxed")]
pub(crate) enum SighupReloadOutcome {
    CleanNoEffect(SighupReloadError),
    Acknowledged(SighupAuthority),
    RecoveryFenced {
        error: SighupReloadError,
        reason: RuntimeConfigFenceReason,
    },
}

struct SighupMutationProgress<'a> {
    operation: Option<&'a OwnedRuntimeConfigOperation>,
    accepted_effect: bool,
}

impl<'a> SighupMutationProgress<'a> {
    fn new(operation: Option<&'a OwnedRuntimeConfigOperation>, accepted_effect: bool) -> Self {
        let progress = Self {
            operation,
            accepted_effect,
        };
        if accepted_effect && let Some(operation) = operation {
            operation.mark_sighup_accepted_effect();
        }
        progress
    }

    fn begin_mutation(&self) {
        if let Some(operation) = self.operation {
            operation.advance_phase(RuntimeConfigSettlementPhase::Mutating);
        }
    }

    fn mark_accepted_effect(&mut self) {
        self.accepted_effect = true;
        if let Some(operation) = self.operation {
            operation.mark_sighup_accepted_effect();
        }
    }

    fn record_recovery_step(&self, reload_step: &'static str) {
        if let Some(operation) = self.operation {
            operation.record_sighup_recovery_step(reload_step);
        }
    }
}

#[cfg(test)]
impl SighupReloadOutcome {
    fn as_ref(&self) -> Option<&SighupAuthority> {
        match self {
            Self::Acknowledged(authority) => Some(authority),
            Self::CleanNoEffect(_) | Self::RecoveryFenced { .. } => None,
        }
    }
    fn expect(self, message: &str) -> SighupAuthority {
        match self {
            Self::Acknowledged(authority) => authority,
            Self::CleanNoEffect(error) | Self::RecoveryFenced { error, .. } => {
                panic!("{message}: {error}")
            }
        }
    }

    fn is_some(&self) -> bool {
        matches!(self, Self::Acknowledged(_))
    }

    fn is_none(&self) -> bool {
        matches!(self, Self::CleanNoEffect(_))
    }
}

#[cfg(test)]
impl std::ops::Deref for SighupAuthority {
    type Target = Config;

    fn deref(&self) -> &Self::Target {
        &self.runtime
    }
}

fn sighup_error(
    bucket: &'static str,
    target: impl Into<String>,
    error: ReloadStepError,
) -> SighupReloadError {
    SighupReloadError::Failed(ReloadStepFailure {
        bucket,
        target: target.into(),
        error,
    })
}

fn clean_reload_failure(bucket: &'static str, error: impl Into<String>) -> SighupReloadOutcome {
    SighupReloadOutcome::CleanNoEffect(sighup_error(
        bucket,
        String::new(),
        ReloadStepError::Rejected(error.into()),
    ))
}

fn fenced_reload_failure(
    progress: &SighupMutationProgress<'_>,
    bucket: &'static str,
    error: ReloadStepError,
    reason: RuntimeConfigFenceReason,
) -> SighupReloadOutcome {
    progress.record_recovery_step(bucket);
    SighupReloadOutcome::RecoveryFenced {
        error: sighup_error(bucket, String::new(), error),
        reason,
    }
}

fn preflight_dispatch_failure(bucket: &'static str, error: ReloadStepError) -> SighupReloadOutcome {
    SighupReloadOutcome::CleanNoEffect(sighup_error(bucket, String::new(), error))
}

fn tcp_ao_awaiting_peer_outcome(
    progress: &SighupMutationProgress<'_>,
    mut runtime: Config,
    desired: &Arc<AcceptedConfigSnapshot>,
    desired_file_path: Option<&std::path::PathBuf>,
    awaiting_error: ReloadStepError,
    marker: ReloadDispatch<std::io::Result<()>, std::io::Error>,
) -> SighupReloadOutcome {
    match marker {
        ReloadDispatch::Replied(Ok(())) => {
            runtime.file_path = desired_file_path.cloned();
            acknowledge_partial(
                progress,
                runtime,
                desired,
                ReloadStepFailure {
                    bucket: "tcp_ao.awaiting_peer",
                    target: String::new(),
                    error: awaiting_error,
                },
            )
        }
        ReloadDispatch::AcknowledgementLost => fenced_reload_failure(
            progress,
            "tcp_ao.awaiting_peer_marker",
            ReloadStepError::AcknowledgementLost,
            RuntimeConfigFenceReason::AcknowledgementLost,
        ),
        ReloadDispatch::NotAccepted(error) => fenced_reload_failure(
            progress,
            "tcp_ao.awaiting_peer_marker",
            ReloadStepError::NotAccepted(error.to_string()),
            RuntimeConfigFenceReason::KnownDivergence,
        ),
        ReloadDispatch::Replied(Err(error)) => fenced_reload_failure(
            progress,
            "tcp_ao.awaiting_peer_marker",
            ReloadStepError::Rejected(error.to_string()),
            RuntimeConfigFenceReason::KnownDivergence,
        ),
    }
}

fn acknowledged_reload(
    runtime: Config,
    desired: Arc<AcceptedConfigSnapshot>,
    dialout_targets: Vec<DialoutTarget>,
    completion: SighupCompletion,
) -> SighupReloadOutcome {
    SighupReloadOutcome::Acknowledged(SighupAuthority {
        runtime,
        desired,
        dialout_targets,
        completion,
    })
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

/// Complete listener inbound-auth inventory (TCP MD5 keys + GTSM selectors)
/// for one config snapshot, built from the same per-neighbor / per-range
/// builders the startup bind path uses.
fn listener_inbound_auth_inventory(
    config: &Config,
) -> Result<
    (
        Vec<rustbgpd_transport::Md5ListenerKey>,
        Vec<rustbgpd_transport::TtlSecurityListenerPolicy>,
    ),
    String,
> {
    let resolved = config
        .resolved_neighbors()
        .map_err(|error| error.to_string())?;
    let md5_keys = resolved
        .iter()
        .filter_map(crate::md5_listener_key_for_neighbor)
        .chain(config.dynamic_neighbors.iter().filter_map(|range| {
            crate::md5_listener_key_for_dynamic_range(range, &config.peer_groups)
        }))
        .collect();
    let ttl_security = resolved
        .iter()
        .map(crate::ttl_security_listener_policy_for_neighbor)
        .chain(config.dynamic_neighbors.iter().filter_map(|range| {
            crate::ttl_security_listener_policy_for_dynamic_range(range, &config.peer_groups)
        }))
        .collect();
    Ok((md5_keys, ttl_security))
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
    // The generation carries the complete both-family listener inventory;
    // the transport layer routes each key to the family socket it can
    // actually protect.
    let mut listener_keys: Vec<TcpAoListenerKey> = desired_resolved
        .iter()
        .filter_map(crate::tcp_ao_listener_key_for_neighbor)
        .chain(
            desired
                .dynamic_neighbors
                .iter()
                .filter_map(crate::tcp_ao_listener_key_for_dynamic_range),
        )
        .collect();
    listener_keys.sort_by_key(|key| {
        let owner = match key.owner {
            TcpAoListenerOwnerKind::Static => 0_u8,
            TcpAoListenerOwnerKind::Dynamic => 1_u8,
        };
        (key.peer, key.prefix_len, owner)
    });
    let mut current_listener_keys = current_resolved
        .iter()
        .filter_map(crate::tcp_ao_listener_key_for_neighbor)
        .chain(
            current
                .dynamic_neighbors
                .iter()
                .filter_map(crate::tcp_ao_listener_key_for_dynamic_range),
        )
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
) -> Result<(), ReloadStepError> {
    step_result(
        dispatch_peer_step(peer_mgr_tx, |reply| {
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
        .await,
    )
}

async fn send_tcp_ao_apply(
    peer_mgr_tx: &mpsc::Sender<PeerManagerCommand>,
    plan: &TcpAoRotationPlan,
    progress: &mut SighupMutationProgress<'_>,
) -> Result<(), ReloadStepError> {
    peer_step(peer_mgr_tx, progress, |reply| {
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
    progress: &SighupMutationProgress<'_>,
) {
    let result = step_result(
        dispatch_actor_mutation_step(peer_mgr_tx, progress, |reply| {
            PeerManagerCommand::MarkTcpAoRotationFailed {
                generation,
                operation,
                error,
                reply,
            }
        })
        .await,
    );
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

fn copy_outbound_prefix_limit_fields(target: &mut Config, source: &Config) {
    for neighbor in &mut target.neighbors {
        if let Some(desired) = source.neighbors.iter().find(|desired| {
            desired.address == neighbor.address && desired.interface == neighbor.interface
        }) {
            neighbor.max_prefixes_out_ipv4 = desired.max_prefixes_out_ipv4;
            neighbor.max_prefixes_out_ipv6 = desired.max_prefixes_out_ipv6;
        }
    }
    for (name, group) in &mut target.peer_groups {
        if let Some(desired) = source.peer_groups.get(name) {
            group.max_prefixes_out_ipv4 = desired.max_prefixes_out_ipv4;
            group.max_prefixes_out_ipv6 = desired.max_prefixes_out_ipv6;
        }
    }
}

async fn dispatch_actor_step<T>(
    peer_mgr_tx: &mpsc::Sender<PeerManagerCommand>,
    build: impl FnOnce(oneshot::Sender<T>) -> PeerManagerCommand,
) -> ReloadDispatch<T, String> {
    let (reply_tx, reply_rx) = oneshot::channel();
    let permit = match peer_mgr_tx.reserve().await {
        Ok(permit) => permit,
        Err(error) => return ReloadDispatch::NotAccepted(error.to_string()),
    };
    permit.send(build(reply_tx));
    match reply_rx.await {
        Ok(result) => ReloadDispatch::Replied(result),
        Err(_) => ReloadDispatch::AcknowledgementLost,
    }
}

async fn dispatch_peer_step<E>(
    peer_mgr_tx: &mpsc::Sender<PeerManagerCommand>,
    build: impl FnOnce(oneshot::Sender<Result<(), E>>) -> PeerManagerCommand,
) -> ReloadDispatch<Result<(), E>, String> {
    dispatch_actor_step(peer_mgr_tx, build).await
}

async fn dispatch_actor_mutation_step<T>(
    peer_mgr_tx: &mpsc::Sender<PeerManagerCommand>,
    progress: &SighupMutationProgress<'_>,
    build: impl FnOnce(oneshot::Sender<T>) -> PeerManagerCommand,
) -> ReloadDispatch<T, String> {
    let (reply_tx, reply_rx) = oneshot::channel();
    let permit = match peer_mgr_tx.reserve().await {
        Ok(permit) => permit,
        Err(error) => return ReloadDispatch::NotAccepted(error.to_string()),
    };
    progress.begin_mutation();
    permit.send(build(reply_tx));
    match reply_rx.await {
        Ok(result) => ReloadDispatch::Replied(result),
        Err(_) => ReloadDispatch::AcknowledgementLost,
    }
}

fn step_result<E: std::fmt::Display>(
    dispatch: ReloadDispatch<Result<(), E>, String>,
) -> Result<(), ReloadStepError> {
    match dispatch {
        ReloadDispatch::NotAccepted(error) => Err(ReloadStepError::NotAccepted(error)),
        ReloadDispatch::Replied(Ok(())) => Ok(()),
        ReloadDispatch::Replied(Err(error)) => Err(ReloadStepError::Rejected(error.to_string())),
        ReloadDispatch::AcknowledgementLost => Err(ReloadStepError::AcknowledgementLost),
    }
}

async fn peer_step<E: std::fmt::Display>(
    peer_mgr_tx: &mpsc::Sender<PeerManagerCommand>,
    progress: &mut SighupMutationProgress<'_>,
    build: impl FnOnce(oneshot::Sender<Result<(), E>>) -> PeerManagerCommand,
) -> Result<(), ReloadStepError> {
    let dispatch = dispatch_actor_mutation_step(peer_mgr_tx, progress, build).await;
    if matches!(dispatch, ReloadDispatch::Replied(Ok(()))) {
        progress.mark_accepted_effect();
    }
    step_result(dispatch)
}

enum OwnedStepFailure {
    Partial(ReloadStepError),
    Fenced {
        error: ReloadStepError,
        reason: RuntimeConfigFenceReason,
    },
}

async fn catalog_step(
    peer_mgr_tx: &mpsc::Sender<PeerManagerCommand>,
    progress: &mut SighupMutationProgress<'_>,
    mutation: OwnedCatalogMutation,
) -> Result<(), OwnedStepFailure> {
    match dispatch_actor_mutation_step(peer_mgr_tx, progress, |reply| {
        PeerManagerCommand::OwnedCatalogMutation { mutation, reply }
    })
    .await
    {
        ReloadDispatch::NotAccepted(error) => Err(OwnedStepFailure::Partial(
            ReloadStepError::NotAccepted(error),
        )),
        ReloadDispatch::Replied(OwnedCatalogMutationOutcome::Success) => {
            progress.mark_accepted_effect();
            Ok(())
        }
        ReloadDispatch::Replied(
            OwnedCatalogMutationOutcome::RejectedNoEffect(error)
            | OwnedCatalogMutationOutcome::FullyCompensated(error),
        ) => Err(OwnedStepFailure::Partial(ReloadStepError::Rejected(
            error.to_string(),
        ))),
        ReloadDispatch::Replied(OwnedCatalogMutationOutcome::CompensationAmbiguous(error)) => {
            Err(OwnedStepFailure::Fenced {
                error: ReloadStepError::Rejected(error.to_string()),
                reason: RuntimeConfigFenceReason::KnownDivergence,
            })
        }
        ReloadDispatch::AcknowledgementLost => Err(OwnedStepFailure::Fenced {
            error: ReloadStepError::AcknowledgementLost,
            reason: RuntimeConfigFenceReason::AcknowledgementLost,
        }),
    }
}

fn owned_step_failure(
    progress: &SighupMutationProgress<'_>,
    working_config: Config,
    desired: &Arc<AcceptedConfigSnapshot>,
    bucket: &'static str,
    target: String,
    failure: OwnedStepFailure,
) -> SighupReloadOutcome {
    match failure {
        OwnedStepFailure::Partial(error) => acknowledge_partial(
            progress,
            working_config,
            desired,
            ReloadStepFailure {
                bucket,
                target,
                error,
            },
        ),
        OwnedStepFailure::Fenced { error, reason } => {
            fenced_reload_failure(progress, bucket, error, reason)
        }
    }
}

async fn hot_peer_step(
    peer_mgr_tx: &mpsc::Sender<PeerManagerCommand>,
    progress: &mut SighupMutationProgress<'_>,
    config: PeerManagerNeighborConfig,
) -> Result<(), OwnedStepFailure> {
    match dispatch_actor_mutation_step(peer_mgr_tx, progress, |reply| {
        PeerManagerCommand::HotUpdatePeer { config, reply }
    })
    .await
    {
        ReloadDispatch::NotAccepted(error) => Err(OwnedStepFailure::Partial(
            ReloadStepError::NotAccepted(error),
        )),
        ReloadDispatch::Replied(OwnedHotUpdatePeerOutcome::Success) => {
            progress.mark_accepted_effect();
            Ok(())
        }
        ReloadDispatch::Replied(OwnedHotUpdatePeerOutcome::RejectedNoEffect(error)) => Err(
            OwnedStepFailure::Partial(ReloadStepError::Rejected(error.to_string())),
        ),
        ReloadDispatch::Replied(OwnedHotUpdatePeerOutcome::KnownDivergence(error)) => {
            Err(OwnedStepFailure::Fenced {
                error: ReloadStepError::Rejected(error.to_string()),
                reason: RuntimeConfigFenceReason::KnownDivergence,
            })
        }
        ReloadDispatch::AcknowledgementLost => Err(OwnedStepFailure::Fenced {
            error: ReloadStepError::AcknowledgementLost,
            reason: RuntimeConfigFenceReason::AcknowledgementLost,
        }),
    }
}

fn listener_step<T>(
    dispatch: ReloadDispatch<std::io::Result<T>, std::io::Error>,
) -> Result<T, ReloadStepError> {
    match dispatch {
        ReloadDispatch::NotAccepted(error) => Err(ReloadStepError::NotAccepted(error.to_string())),
        ReloadDispatch::Replied(Ok(value)) => Ok(value),
        ReloadDispatch::Replied(Err(error)) => Err(ReloadStepError::Rejected(error.to_string())),
        ReloadDispatch::AcknowledgementLost => Err(ReloadStepError::AcknowledgementLost),
    }
}

fn listener_mutation_step<T>(
    dispatch: ReloadDispatch<std::io::Result<T>, std::io::Error>,
    progress: &mut SighupMutationProgress<'_>,
) -> Result<T, ReloadStepError> {
    if matches!(dispatch, ReloadDispatch::Replied(Ok(_))) {
        progress.mark_accepted_effect();
    }
    listener_step(dispatch)
}

/// Read the peer manager's current runtime config snapshot.
///
/// SIGHUP callers take the shared runtime-config coordinator before calling
/// this helper, so any transaction that acquired the same lock first has
/// already staged its accepted snapshot. That makes the returned config the
/// correct live baseline for reload diffing.
#[cfg(test)]
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
    config.policy.rpol_files = snapshot.rpol_files;
    config.policy.rpol = snapshot.rpol;
    Ok(config)
}

/// Reconstruct the SIGHUP runtime baseline without rereading external sources.
pub(crate) async fn runtime_config_snapshot_accepted(
    peer_mgr_tx: &mpsc::Sender<PeerManagerCommand>,
    accepted: &AcceptedConfigSnapshot,
    live_bindings: &rustbgpd_policy::datasets::DatasetBindings,
) -> ReloadDispatch<Result<Config, String>, String> {
    let (reply_tx, reply_rx) = oneshot::channel();
    let permit = match peer_mgr_tx.reserve().await {
        Ok(permit) => permit,
        Err(error) => return ReloadDispatch::NotAccepted(error.to_string()),
    };
    permit.send(PeerManagerCommand::RuntimeConfigSnapshot { reply: reply_tx });
    match reply_rx.await {
        Ok(Ok(snapshot)) => ReloadDispatch::Replied(accepted.runtime_config_without_sources(
            &snapshot.toml,
            &snapshot.rpol_files,
            snapshot.rpol,
            live_bindings,
        )),
        Ok(Err(error)) => ReloadDispatch::Replied(Err(error)),
        Err(_) => ReloadDispatch::AcknowledgementLost,
    }
}

/// Reconstruct the transaction-editing document without external-source reads
/// or policy resolution. Unlike the SIGHUP baseline above, this value is only
/// serialized or edited before the executor performs its normal validation.
pub(crate) async fn transaction_config_snapshot_accepted(
    peer_mgr_tx: &mpsc::Sender<PeerManagerCommand>,
    accepted: &AcceptedConfigSnapshot,
) -> Result<Config, String> {
    let (reply_tx, reply_rx) = oneshot::channel();
    peer_mgr_tx
        .send(PeerManagerCommand::RuntimeConfigSnapshot { reply: reply_tx })
        .await
        .map_err(|e| format!("send to peer manager failed: {e}"))?;
    let snapshot = reply_rx
        .await
        .map_err(|e| format!("peer manager dropped runtime snapshot reply: {e}"))??;
    accepted.transaction_config_without_sources(&snapshot.toml, &snapshot.rpol_files)
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
        | ConfigEvent::PresenceAwareNeighborAdded { ack, .. }
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
) -> ReloadDispatch<(), String> {
    dispatch_actor_step(peer_mgr_tx, |reply| {
        PeerManagerCommand::SetFibTablesSnapshot {
            tables: fib_table_snapshots(tables),
            reply,
        }
    })
    .await
}

/// What the bridge should do with its held snapshot after an acknowledged
/// config event.
enum AckedPersistOutcome {
    /// Publication settled. Authority adoption must precede the reply.
    /// The candidate is on disk; adopt it as the bridge snapshot.
    Settled {
        outcome: ConfigPersistCommitOutcome,
        reply: oneshot::Sender<ConfigPersistCommitOutcome>,
    },
    /// Staging was rejected or the runtime owner discarded its stage.
    /// Nothing was written; keep the previous snapshot.
    Rejected,
    /// The persister is gone; the bridge has nothing left to do.
    PersisterLost,
}

async fn persister_round_trip(
    rx: oneshot::Receiver<ConfigPersistCommitOutcome>,
) -> Result<ConfigPersistCommitOutcome, ()> {
    rx.await.map_err(|_| ())
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
    candidate: Arc<AcceptedConfigSnapshot>,
    ack: ConfigPersistAck,
) -> AckedPersistOutcome {
    let (reply, staged_commit) = match ack {
        ConfigPersistAck::Immediate(reply) => (reply, false),
        ConfigPersistAck::Staged { staged, commit } => {
            let (stage_ack_tx, stage_ack_rx) = oneshot::channel();
            if mutation_tx
                .send(ConfigMutation::StageConfigAck(
                    Arc::clone(&candidate),
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
            let stage_result = stage_ack_rx
                .await
                .map_err(|_| "config persister dropped staging acknowledgement".to_string())
                .and_then(|result| result);
            let stage_ok = stage_result.is_ok();
            let _ = staged.send(stage_result.map_err(ConfigPersistError::Write));
            if !stage_ok {
                return AckedPersistOutcome::Rejected;
            }

            // The caller is applying its runtime change. A dropped commit channel
            // means that apply failed, or the caller is gone: either way the staged
            // write must not land.
            // A dropped commit channel proves the runtime owner never asked
            // the persister to publish this stage.
            let Ok(reply) = commit.await else {
                let _ = mutation_tx.send(ConfigMutation::DiscardStagedConfig).await;
                return AckedPersistOutcome::Rejected;
            };
            (reply, true)
        }
    };

    if !staged_commit {
        // Single-phase: the caller owns its own apply/rollback executor and
        // asked for one durable write with one acknowledgement.
        let (persist_ack_tx, persist_ack_rx) = oneshot::channel();
        if let Err(error) = mutation_tx
            .send(ConfigMutation::ReplaceConfigAck(candidate, persist_ack_tx))
            .await
        {
            let ConfigMutation::ReplaceConfigAck(_, persist_ack) = error.0 else {
                unreachable!("rejected mutation must be ReplaceConfigAck")
            };
            let _ = persist_ack.send(ConfigPersistCommitOutcome::NotPublished(
                "persister rejected replacement pre-publication".to_string(),
            ));
        }
        return match persister_round_trip(persist_ack_rx).await {
            Ok(outcome) => AckedPersistOutcome::Settled { outcome, reply },
            Err(()) => AckedPersistOutcome::PersisterLost,
        };
    }

    let (commit_ack_tx, commit_ack_rx) = oneshot::channel();
    if let Err(error) = mutation_tx
        .send(ConfigMutation::CommitStagedConfig(commit_ack_tx))
        .await
    {
        let ConfigMutation::CommitStagedConfig(commit_ack) = error.0 else {
            unreachable!("rejected mutation must be CommitStagedConfig")
        };
        let _ = commit_ack.send(ConfigPersistCommitOutcome::NotPublished(
            "persister rejected staged commit pre-publication".to_string(),
        ));
    }
    match persister_round_trip(commit_ack_rx).await {
        Ok(outcome) => AckedPersistOutcome::Settled { outcome, reply },
        Err(()) => AckedPersistOutcome::PersisterLost,
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
pub(crate) struct AcceptedBridgeReplacement {
    snapshot: Arc<AcceptedConfigSnapshot>,
    adopted: oneshot::Sender<ReloadDispatch<(), String>>,
}

#[expect(
    clippy::too_many_lines,
    reason = "single serialized bridge loop makes authority adoption ordering explicit"
)]
pub(crate) async fn run_config_bridge_accepted(
    mut event_rx: mpsc::Receiver<rustbgpd_api::peer_types::ConfigEvent>,
    mut bridge_replace_rx: mpsc::Receiver<AcceptedBridgeReplacement>,
    mutation_tx: mpsc::Sender<ConfigMutation>,
    accepted_tx: watch::Sender<Arc<AcceptedConfigSnapshot>>,
) {
    let mut current = accepted_tx.borrow().clone();
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
                    Some(replacement) => {
                        let new_snapshot = replacement.snapshot;
                        let permit = match mutation_tx.reserve().await {
                            Ok(permit) => permit,
                            Err(error) => {
                                let _ = replacement.adopted.send(ReloadDispatch::NotAccepted(error.to_string()));
                                break;
                            }
                        };
                        let (persister_adopted, persister_adopted_rx) = oneshot::channel();
                        permit.send(ConfigMutation::AdoptReloadSnapshot {
                            snapshot: Arc::clone(&new_snapshot),
                            adopted: persister_adopted,
                        });
                        if persister_adopted_rx.await.is_err() {
                            let _ = replacement.adopted.send(ReloadDispatch::AcknowledgementLost);
                            break;
                        }
                        current = new_snapshot;
                        accepted_tx.send_replace(Arc::clone(&current));
                        if sighup_ack_fault("bridge") {
                            drop(replacement.adopted);
                            continue;
                        }
                        let _ = replacement.adopted.send(ReloadDispatch::Replied(()));
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
                            current.derive_toml_without_sources(
                                candidate_toml,
                                "committed config transaction",
                            )
                            .map_err(CatalogMutationError::invalid)
                        } else {
                            let mut candidate = current.config();
                            match apply_config_event(&mut candidate, &event) {
                                Ok(()) => current
                                    .derive_config(candidate)
                                    .map_err(CatalogMutationError::invalid),
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
                                match ack {
                                    ConfigPersistAck::Staged { staged, .. } => {
                                        let _ = staged.send(Err(ConfigPersistError::Rejected(error)));
                                    }
                                    ConfigPersistAck::Immediate(reply) => {
                                        let _ = reply.send(ConfigPersistCommitOutcome::NotPublished(
                                            error.to_string(),
                                        ));
                                    }
                                }
                            }
                            continue;
                            }
                        };
                        if let Some(ack) = event_ack {
                            match persist_acknowledged(&mutation_tx, Arc::clone(&candidate), ack).await {
                                AckedPersistOutcome::Settled { outcome, reply } => {
                                    // The candidate is on disk; adopt it as the bridge snapshot.
                                    if matches!(
                                        outcome,
                                        ConfigPersistCommitOutcome::PublishedDurable
                                            | ConfigPersistCommitOutcome::PublicationAmbiguous(_)
                                    ) {
                                        current = candidate;
                                        accepted_tx.send_replace(Arc::clone(&current));
                                    }
                                    // Both bridge and persister authority are
                                    // updated before the owner can observe the
                                    // terminal publication result.
                                    let _ = reply.send(outcome);
                                }
                                // Nothing was written; keep the previous snapshot.
                                AckedPersistOutcome::Rejected => {}
                                AckedPersistOutcome::PersisterLost => break,
                            }
                        } else {
                            if mutation_tx
                                .send(ConfigMutation::ReplaceConfig(Arc::clone(&candidate)))
                                .await
                                .is_err()
                            {
                                break;
                            }
                            current = candidate;
                            accepted_tx.send_replace(Arc::clone(&current));
                        }
                    }
                    None => event_rx_open = false,
                }
            }
        }
    }
}

#[cfg(test)]
pub(crate) async fn run_config_bridge(
    event_rx: mpsc::Receiver<rustbgpd_api::peer_types::ConfigEvent>,
    bridge_replace_rx: mpsc::UnboundedReceiver<Box<Config>>,
    mutation_tx: mpsc::Sender<ConfigMutation>,
    initial: Config,
) {
    let initial = AcceptedConfigSnapshot::from_config_for_test(initial);
    let (accepted_tx, _accepted_rx) = watch::channel(Arc::clone(&initial));
    let (replace_tx, accepted_replace_rx) = mpsc::channel(1);
    tokio::spawn(async move {
        let mut bridge_replace_rx = bridge_replace_rx;
        while let Some(config) = bridge_replace_rx.recv().await {
            let (adopted, _adopted_rx) = oneshot::channel();
            if replace_tx
                .send(AcceptedBridgeReplacement {
                    snapshot: initial
                        .derive_config(*config)
                        .expect("test config serializes"),
                    adopted,
                })
                .await
                .is_err()
            {
                break;
            }
        }
    });
    run_config_bridge_accepted(event_rx, accepted_replace_rx, mutation_tx, accepted_tx).await;
}

/// Acknowledge a freshly reloaded authority across every runtime consumer.
///
/// Order matters. Both private control lanes are lossless capacity-one
/// channels; a send can fail only on receiver-drop (the owning peer-manager
/// or bridge task is dead). Sending the peer
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
/// This remains async because it waits for both the peer-manager snapshot
/// assignment and the bridge's accepted-snapshot adoption acknowledgements.
pub(crate) async fn finalize_sighup_authority(
    operation: &OwnedRuntimeConfigOperation,
    authority: SighupAuthority,
    peer_mgr_internal_tx: &mpsc::Sender<InternalCommand>,
    bridge_replace_tx: &mpsc::Sender<AcceptedBridgeReplacement>,
    dialout_manager: &Arc<tokio::sync::Mutex<rustbgpd_api::gnmi_dialout::DialoutManager>>,
) -> OwnedRuntimeConfigOutcome<SighupAuthority, SighupReloadError> {
    operation.advance_phase(RuntimeConfigSettlementPhase::SettlingRollback);
    let fenced = |bucket, reason, fence_reason| {
        operation.record_sighup_recovery_step(bucket);
        OwnedRuntimeConfigOutcome::Fenced {
            error: SighupReloadError::Failed(ReloadStepFailure {
                bucket,
                target: String::new(),
                error: reason,
            }),
            reason: fence_reason,
        }
    };
    // Acknowledge the snapshot so the caller (holding the FIB coordinator lock)
    // doesn't release the lock until the peer manager has actually assigned
    // `current_config`. Otherwise a following gRPC FIB-table CRUD could enqueue
    // its own snapshot on the separate peer-manager channel and have it
    // overtaken by this one, reverting the just-applied table set.
    let (ack_tx, ack_rx) = oneshot::channel();
    if peer_mgr_internal_tx
        .send(InternalCommand::ReplaceConfigSnapshot {
            config: Box::new(authority.runtime.clone()),
            ack: Some(ack_tx),
        })
        .await
        .is_err()
    {
        return fenced(
            "peer_mgr_snapshot",
            ReloadStepError::NotAccepted("peer manager snapshot command was not accepted".into()),
            RuntimeConfigFenceReason::KnownDivergence,
        );
    }
    if ack_rx.await.is_err() {
        return fenced(
            "peer_mgr_snapshot",
            ReloadStepError::AcknowledgementLost,
            RuntimeConfigFenceReason::AcknowledgementLost,
        );
    }
    operation.mark_sighup_accepted_effect();
    let (adopted, adopted_rx) = oneshot::channel();
    if bridge_replace_tx
        .send(AcceptedBridgeReplacement {
            snapshot: Arc::clone(&authority.desired),
            adopted,
        })
        .await
        .is_err()
    {
        return fenced(
            "config_bridge",
            ReloadStepError::NotAccepted("config bridge adoption was not accepted".into()),
            RuntimeConfigFenceReason::KnownDivergence,
        );
    }
    match adopted_rx.await {
        Ok(ReloadDispatch::Replied(())) => operation.mark_sighup_accepted_effect(),
        Ok(ReloadDispatch::NotAccepted(error)) => {
            return fenced(
                "config_persister",
                ReloadStepError::NotAccepted(error),
                RuntimeConfigFenceReason::KnownDivergence,
            );
        }
        Ok(ReloadDispatch::AcknowledgementLost) | Err(_) => {
            return fenced(
                "config_bridge",
                ReloadStepError::AcknowledgementLost,
                RuntimeConfigFenceReason::AcknowledgementLost,
            );
        }
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
    // failure here leaves the adopted config and tracing projection divergent,
    // so the owner fences rather than claiming acknowledged authority.
    if let Err(error) =
        rustbgpd_telemetry::reload_per_peer_directives(&authority.desired.per_peer_log_directives())
    {
        return fenced(
            "peer_tracing",
            ReloadStepError::Rejected(error.to_string()),
            RuntimeConfigFenceReason::KnownDivergence,
        );
    }

    dialout_manager
        .lock()
        .await
        .apply(&authority.dialout_targets);
    OwnedRuntimeConfigOutcome::AcknowledgedAuthority(authority)
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

/// Keep daemon-wide, startup-owned state honest across SIGHUP.
///
/// These fields have no live reconciler. Advancing any of them in the runtime
/// snapshot would make later consumers (notably a runtime-added peer resolved
/// from that snapshot) observe an identity or subsystem configuration that the
/// running daemon never adopted. Fields with dedicated pinning or hot-apply
/// paths remain owned by those paths below.
fn pin_unreconciled_daemon_runtime_fields(new_config: &mut Config, current: &Config) {
    new_config.global.asn = current.global.asn;
    new_config
        .global
        .router_id
        .clone_from(&current.global.router_id);
    new_config.global.listen_port = current.global.listen_port;
    new_config
        .global
        .listen_addresses
        .clone_from(&current.global.listen_addresses);
    new_config
        .global
        .cluster_id
        .clone_from(&current.global.cluster_id);
    new_config.global.worker_threads = current.global.worker_threads;
    new_config.global.multipath_relax = current.global.multipath_relax;
    new_config.global.link_bandwidth_weighted = current.global.link_bandwidth_weighted;
    new_config.global.warm_cache_checkpoint_on_shutdown =
        current.global.warm_cache_checkpoint_on_shutdown;
    new_config
        .global
        .runtime_state_dir
        .clone_from(&current.global.runtime_state_dir);
    new_config
        .global
        .telemetry
        .prometheus_addr
        .clone_from(&current.global.telemetry.prometheus_addr);
    new_config
        .global
        .telemetry
        .log_format
        .clone_from(&current.global.telemetry.log_format);
    new_config.rpki.clone_from(&current.rpki);
    new_config.bmp.clone_from(&current.bmp);
    new_config.mrt.clone_from(&current.mrt);
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
) -> SighupReloadOutcome {
    let config_path = std::path::Path::new(config_path);
    let source = std::fs::read_to_string(config_path).unwrap();
    write_tier_test_config(config_path, &source);
    let prior = AcceptedConfigSnapshot::from_config_for_test(current.clone());
    let desired = Arc::new(
        AcceptedConfigSnapshot::load_for_reload(
            config_path,
            &prior,
            &current.policy.dataset_bindings,
        )
        .expect("test reload config must parse"),
    );
    reload_config_with_tcp_ao(
        SighupReloadPlan {
            baseline_runtime: current.clone(),
            desired,
            accepted_effect: false,
        },
        live_grpc_tcp,
        live_grpc_uds,
        peer_mgr_tx,
        None,
        fib_cmd_tx,
        evpn_runtime_apply,
        None,
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
    plan: SighupReloadPlan,
    live_grpc_tcp: Option<&config::GrpcTcpListenerConfig>,
    live_grpc_uds: Option<&config::GrpcUdsListenerConfig>,
    peer_mgr_tx: &mpsc::Sender<PeerManagerCommand>,
    rib_tx: Option<&mpsc::Sender<rustbgpd_rib::RibUpdate>>,
    fib_cmd_tx: Option<&mpsc::Sender<FibRuntimeCommand>>,
    evpn_runtime_apply: Option<&EvpnRuntimeReloadApply>,
    tcp_ao_listener: Option<&TcpAoListenerHandle>,
    operation: Option<&OwnedRuntimeConfigOperation>,
) -> SighupReloadOutcome {
    let current = &plan.baseline_runtime;
    let desired_snapshot = plan.desired;
    let mut progress = SighupMutationProgress::new(operation, plan.accepted_effect);
    // LAN-305: parse dataset contents against the running binding schema, but
    // stage changed data and refresh errors on detached candidate handles.
    // Shared live handles are committed only after the complete no-side-effect
    // preflight below, so a rejected authentication-boundary reload cannot
    // leak new policy data into running chains.
    let mut desired_config = desired_snapshot.config();
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

    // Pin the remaining startup-owned daemon inventory before validation or
    // any external apply. The desired snapshot still carries the edited TOML
    // so restart intent is preserved and the same drift remains visible on
    // every reload.
    pin_unreconciled_daemon_runtime_fields(&mut new_config, current);

    // Compile the immutable TCP-AO candidate before TCP-AO inventory pinning,
    // but do not touch a socket or session yet. The fully pinned runtime
    // candidate must pass validation below before the first external mutation.
    let tcp_ao_rotation_plan = if let Some(listener) = tcp_ao_listener {
        match prepare_tcp_ao_rotation_plan(current, &new_config, &listener.status()) {
            Ok(plan) => plan,
            Err(error) => {
                error!(%error, "failed to compile TCP-AO rotation generation");
                return clean_reload_failure("tcp_ao.plan", error);
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
            return clean_reload_failure("tcp_ao.plan", reason.clone());
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
        return clean_reload_failure("reload.validate", error.to_string());
    }

    let dialout_targets = match config::gnmi_dialout_targets(&new_config) {
        Ok(targets) => targets,
        Err(error) => return clean_reload_failure("gnmi_dialout.plan", error),
    };

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
        if let Err(error) = listener_step(listener_preflight) {
            mark_tcp_ao_failed(
                peer_mgr_tx,
                plan.generation,
                plan.operation,
                error.to_string(),
                &progress,
            )
            .await;
            error!(error = %error, "TCP-AO generation rejected during complete listener kernel preflight");
            return preflight_dispatch_failure("tcp_ao.listener_preflight", error);
        }
        if let Err(error) = send_tcp_ao_preflight(peer_mgr_tx, plan).await {
            error!(error = %error, "TCP-AO generation rejected during global session preflight");
            return preflight_dispatch_failure("tcp_ao.peer_preflight", error);
        }
        let listener_apply = match plan.operation {
            TcpAoRotationOperation::AddOnly => {
                listener
                    .apply_add_only(desired_listener, || progress.begin_mutation())
                    .await
            }
            TcpAoRotationOperation::Selection => {
                listener
                    .begin_selection(desired_listener, || progress.begin_mutation())
                    .await
            }
            TcpAoRotationOperation::Delete => {
                listener
                    .apply_delete(desired_listener, || progress.begin_mutation())
                    .await
            }
        };
        if let Err(error) = listener_mutation_step(listener_apply, &mut progress) {
            mark_tcp_ao_failed(
                peer_mgr_tx,
                plan.generation,
                plan.operation,
                error.to_string(),
                &progress,
            )
            .await;
            error!(error = %error, "TCP-AO generation failed on listener; retry the identical generation unless the error reports failed exact prior-inventory restoration, in which case restart rustbgpd");
            let reason = if matches!(error, ReloadStepError::AcknowledgementLost) {
                RuntimeConfigFenceReason::AcknowledgementLost
            } else {
                RuntimeConfigFenceReason::KnownDivergence
            };
            return fenced_reload_failure(&progress, "tcp_ao.listener_apply", error, reason);
        }
        if let Err(error) = send_tcp_ao_apply(peer_mgr_tx, plan, &mut progress).await {
            if plan.operation == TcpAoRotationOperation::Selection
                && matches!(&error, ReloadStepError::Rejected(message) if message.starts_with(crate::peer_manager::TCP_AO_AWAITING_PEER_PREFIX))
            {
                let marker = listener
                    .mark_awaiting_peer(plan.generation, error.to_string(), || {
                        progress.begin_mutation();
                    })
                    .await;
                if matches!(&marker, ReloadDispatch::Replied(Ok(()))) {
                    info!(error = %error, generation = plan.generation.as_u64(), "TCP-AO successor selected; peer-use observation remains pending until a later identical SIGHUP");
                } else {
                    warn!(
                        awaiting_error = %error,
                        marker = ?marker,
                        generation = plan.generation.as_u64(),
                        "TCP-AO listener awaiting-peer marker was not authoritatively acknowledged"
                    );
                }
                return tcp_ao_awaiting_peer_outcome(
                    &progress,
                    current.clone(),
                    &desired_snapshot,
                    desired_config.file_path.as_ref(),
                    error,
                    marker,
                );
            }
            if let Err(marker_error) = listener_step(
                listener
                    .mark_dependent_failure(plan.generation, error.to_string(), || {
                        progress.begin_mutation();
                    })
                    .await,
            ) {
                warn!(error = %marker_error, "TCP-AO listener dependent-failure marker was not acknowledged; staged generation remains globally uncommitted");
            }
            error!(error = %error, "TCP-AO generation failed on an established session; listener accepts remain generation-fenced until retry");
            let reason = if matches!(error, ReloadStepError::AcknowledgementLost) {
                RuntimeConfigFenceReason::AcknowledgementLost
            } else {
                RuntimeConfigFenceReason::KnownDivergence
            };
            return fenced_reload_failure(&progress, "tcp_ao.peer_apply", error, reason);
        }
        if plan.operation == TcpAoRotationOperation::Selection
            && let Err(error) = listener_step(
                listener
                    .finalize_selection(plan.generation, || progress.begin_mutation())
                    .await,
            )
        {
            mark_tcp_ao_failed(
                peer_mgr_tx,
                plan.generation,
                plan.operation,
                error.to_string(),
                &progress,
            )
            .await;
            error!(error = %error, "TCP-AO session cohort observed successor use, but listener metadata commit failed; retrying the identical generation is required");
            let reason = if matches!(error, ReloadStepError::AcknowledgementLost) {
                RuntimeConfigFenceReason::AcknowledgementLost
            } else {
                RuntimeConfigFenceReason::KnownDivergence
            };
            return fenced_reload_failure(&progress, "tcp_ao.listener_finalize", error, reason);
        }
        if let Err(error) = listener_step(
            listener
                .acknowledge_global_commit(plan.generation, || progress.begin_mutation())
                .await,
        ) {
            mark_tcp_ao_failed(
                peer_mgr_tx,
                plan.generation,
                plan.operation,
                error.to_string(),
                &progress,
            )
            .await;
            error!(error = %error, "TCP-AO generation reached sessions but listener global commit acknowledgement failed; retrying the same immutable generation is required");
            let reason = if matches!(error, ReloadStepError::AcknowledgementLost) {
                RuntimeConfigFenceReason::AcknowledgementLost
            } else {
                RuntimeConfigFenceReason::KnownDivergence
            };
            return fenced_reload_failure(&progress, "tcp_ao.listener_commit", error, reason);
        }
        tcp_ao_rotation_applied = true;
        info!(
            generation = plan.generation.as_u64(),
            operation = ?plan.operation,
            "TCP-AO generation applied to listener and established sessions"
        );
    }

    // Listener inbound MD5/GTSM inventory follows the same config → listener
    // flow as the TCP-AO keys above, but as a plain converging replacement:
    // an MD5 password change is inherently session-disruptive, so there is no
    // multi-generation rotation to preserve. The listener is updated before
    // sessions reconcile so a bounced peer's inbound reconnect already meets
    // the new inventory.
    if let Some(listener) = tcp_ao_listener {
        let current_inventory = match listener_inbound_auth_inventory(current) {
            Ok(inventory) => inventory,
            Err(error) => {
                error!(%error, "failed to compute the live listener inbound-auth inventory");
                return clean_reload_failure("listener_auth.plan", error);
            }
        };
        let desired_inventory = match listener_inbound_auth_inventory(&new_config) {
            Ok(inventory) => inventory,
            Err(error) => {
                error!(%error, "failed to compute the desired listener inbound-auth inventory");
                return clean_reload_failure("listener_auth.plan", error);
            }
        };
        if current_inventory != desired_inventory {
            let (md5_keys, ttl_security) = desired_inventory;
            if let Err(error) = listener_mutation_step(
                listener
                    .replace_inbound_auth(md5_keys, ttl_security, || progress.begin_mutation())
                    .await,
                &mut progress,
            ) {
                error!(
                    error = %error,
                    "listener inbound MD5/GTSM inventory replacement failed; \
                     refusing reload (retrying the identical reload converges)"
                );
                let reason = if matches!(error, ReloadStepError::AcknowledgementLost) {
                    RuntimeConfigFenceReason::AcknowledgementLost
                } else {
                    RuntimeConfigFenceReason::KnownDivergence
                };
                return fenced_reload_failure(&progress, "listener_auth.apply", error, reason);
            }
            info!("listener inbound MD5/GTSM inventory replaced");
        }
    }

    let dataset_commit = desired_config.prepare_staged_datasets(&current.policy.dataset_bindings);
    let dataset_commit_pending = !dataset_commit.is_empty();
    new_config.policy.dataset_bindings = desired_config.policy.dataset_bindings.clone();
    new_config.policy.dataset_events = desired_config.policy.dataset_events.clone();

    if let Some(apply) = evpn_runtime_apply {
        let evpn_operation = operation.cloned();
        let attempt = apply
            .apply_config_if_changed(&new_config, evpn_runtime_changed, move || {
                if let Some(operation) = evpn_operation.as_ref() {
                    operation.advance_phase(RuntimeConfigSettlementPhase::Mutating);
                }
            })
            .await;
        match attempt.terminal {
            EvpnRuntimeReloadTerminal::Applied(result) => {
                progress.mark_accepted_effect();
                info!(
                    outcome = ?result.outcome,
                    message = %result.message,
                    "reload: EVPN runtime model hot-applied through ADR-0063 coordinator"
                );
            }
            EvpnRuntimeReloadTerminal::Unchanged => {}
            EvpnRuntimeReloadTerminal::RejectedNoEffect(error) => {
                error!(
                    error = ?error,
                    "reload: EVPN runtime model differs but the ADR-0063 coordinator \
                     rejected the candidate; runtime EVPN snapshot unchanged. \
                     Split unsupported mixed edits or restart rustbgpd for \
                     restart-required EVPN identity changes."
                );
                copy_evpn_runtime_fields(&mut new_config, &attempt.baseline);
            }
            EvpnRuntimeReloadTerminal::KnownPartial(error)
            | EvpnRuntimeReloadTerminal::KnownDivergence(error) => {
                error!(
                    error = ?error,
                    "reload: EVPN runtime apply changed or degraded coordinator authority; \
                     fencing before later reload mutations"
                );
                return fenced_reload_failure(
                    &progress,
                    "evpn_runtime.apply",
                    ReloadStepError::Rejected(format!("{error:?}")),
                    RuntimeConfigFenceReason::KnownDivergence,
                );
            }
            EvpnRuntimeReloadTerminal::PublicationAmbiguous(error) => {
                error!(
                    error = ?error,
                    "reload: EVPN runtime apply publication is ambiguous; \
                     fencing before later reload mutations"
                );
                return fenced_reload_failure(
                    &progress,
                    "evpn_runtime.apply",
                    ReloadStepError::Rejected(format!("{error:?}")),
                    RuntimeConfigFenceReason::PublicationAmbiguous,
                );
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
    if new_config.inbound_admission != current.inbound_admission {
        error!(
            "[inbound_admission] changed — the ADR-0120 accept-path limiter is \
             built once at startup. Restart rustbgpd to apply; inbound admission \
             keeps its startup configuration until then."
        );
        new_config.inbound_admission = current.inbound_admission.clone();
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
        || new_config.global.blackhole_discard_max_active
            != current.global.blackhole_discard_max_active
        || new_config.global.blackhole_discard_install_rate_per_minute
            != current.global.blackhole_discard_install_rate_per_minute
        || new_config.global.blackhole_discard_install_burst
            != current.global.blackhole_discard_install_burst
    {
        error!(
            "[global] BLACKHOLE FIB discard settings differ from the live config: \
             the RFC 7999 kernel-discard reconciler is spawned only at startup. \
             Restart rustbgpd to apply install_blackhole_discard, \
             allow_blackhole_broad_prefixes, blackhole_discard_max_active, \
             blackhole_discard_install_rate_per_minute, or \
             blackhole_discard_install_burst edits."
        );
        new_config.global.install_blackhole_discard = current.global.install_blackhole_discard;
        new_config.global.allow_blackhole_broad_prefixes =
            current.global.allow_blackhole_broad_prefixes;
        new_config.global.blackhole_discard_max_active =
            current.global.blackhole_discard_max_active;
        new_config.global.blackhole_discard_install_rate_per_minute =
            current.global.blackhole_discard_install_rate_per_minute;
        new_config.global.blackhole_discard_install_burst =
            current.global.blackhole_discard_install_burst;
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
    if new_config.global.dynamic_neighbor_limit != current.global.dynamic_neighbor_limit {
        error!(
            "[global].dynamic_neighbor_limit differs from the live config: dynamic-neighbor \
             admission capacity is allocated once at startup. Restart rustbgpd to change it. \
             The runtime snapshot keeps the startup limit for this reload."
        );
        new_config.global.dynamic_neighbor_limit = current.global.dynamic_neighbor_limit;
    }
    if config::pin_rfc8212_posture_startup_only(&mut new_config, current) {
        error!(
            "config_epoch or [global].ebgp_requires_policy differs from the live config: \
             the ADR-0112/0119 RFC 8212 posture is read once at startup. Restart rustbgpd \
             to change it. The complete running epoch/policy tuple is kept at its startup \
             value for this reload."
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
        return acknowledged_reload(
            new_config,
            desired_snapshot,
            dialout_targets,
            SighupCompletion::Complete,
        );
    }

    if explain_changed {
        warn!(
            "[policy.explain] changed — the new enabled/cache_size apply to sessions \
             established after this reload (restart-required per peer); existing \
             sessions are unaffected until they re-establish."
        );
    }

    // `working_config` is the authoritative runtime projection. Each
    // acknowledged actor effect advances it. A known failure returns that
    // explicit known-partial authority for composite finalization; a lost
    // acknowledgement or non-authoritative reconcile fences instead.
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
    // returned by authoritative partial receipts.
    copy_evpn_runtime_fields(&mut working_config, &new_config);

    if let Some(rib_tx) = rib_tx
        && current.outbound_prefix_limits() != new_config.outbound_prefix_limits()
    {
        let txn = next_outbound_prefix_limit_txn();
        let preparation = dispatch_rib_step(rib_tx, |reply| {
            rustbgpd_rib::RibUpdate::PrepareOutboundPrefixLimits {
                txn,
                config: new_config.outbound_prefix_limits(),
                reply,
            }
        })
        .await;
        let preparation = match preparation {
            ReloadDispatch::NotAccepted(error) => Err(ReloadStepError::NotAccepted(error)),
            ReloadDispatch::Replied(Ok(())) => Ok(()),
            ReloadDispatch::Replied(Err(violations)) => Err(ReloadStepError::Rejected(format!(
                "outbound prefix limit rejected: {}",
                violations
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join("; ")
            ))),
            ReloadDispatch::AcknowledgementLost => Err(ReloadStepError::AcknowledgementLost),
        };
        if let Err(error) = preparation {
            return acknowledge_partial(
                &progress,
                working_config,
                &desired_snapshot,
                ReloadStepFailure {
                    bucket: "prefix_limit.prepare",
                    target: String::new(),
                    error,
                },
            );
        }

        let activation = dispatch_rib_mutation_step(rib_tx, &progress, |reply| {
            rustbgpd_rib::RibUpdate::ApplyOutboundPrefixLimits {
                txn,
                activate: true,
                reply,
            }
        })
        .await;
        let activation = match activation {
            ReloadDispatch::NotAccepted(error) => Err(ReloadStepError::NotAccepted(error)),
            ReloadDispatch::Replied(Ok(())) => {
                progress.mark_accepted_effect();
                Ok(())
            }
            ReloadDispatch::Replied(Err(error)) => Err(ReloadStepError::Rejected(error)),
            ReloadDispatch::AcknowledgementLost => Err(ReloadStepError::AcknowledgementLost),
        };
        if let Err(error) = activation {
            return acknowledge_partial(
                &progress,
                working_config,
                &desired_snapshot,
                ReloadStepFailure {
                    bucket: "prefix_limit.activate",
                    target: String::new(),
                    error,
                },
            );
        }
        copy_outbound_prefix_limit_fields(&mut working_config, &new_config);
    }

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
        // Push the new explain snapshot to the peer manager *before* any
        // reconcile step below constructs a session. `build_transport_config`
        // reads `[policy.explain]` from the peer manager's `current_config`,
        // which is otherwise replaced only after this whole reload completes.
        // Without this, a peer re-added by a
        // neighbor reconcile or peer-group change in *this same* reload would
        // be built with the stale explain settings. Sent on the same FIFO
        // command channel and awaited, so it is applied before every
        // subsequent step. A send failure means the peer manager is gone and
        // returns the authority accumulated before this step.
        let outcome = dispatch_actor_mutation_step(peer_mgr_tx, &progress, |reply| {
            PeerManagerCommand::SyncExplainConfig {
                enabled: new_config.policy.explain.enabled,
                cache_size: new_config.policy.explain.cache_size,
                reject_retention_enabled: new_config.policy.reject_retention.enabled,
                reject_retention_capacity: new_config.policy.reject_retention.capacity,
                reply,
            }
        })
        .await;
        match outcome {
            ReloadDispatch::Replied(()) => {
                progress.mark_accepted_effect();
                working_config.policy.explain = new_config.policy.explain.clone();
                working_config.policy.reject_retention = new_config.policy.reject_retention.clone();
            }
            ReloadDispatch::NotAccepted(error) => {
                return acknowledge_partial(
                    &progress,
                    working_config,
                    &desired_snapshot,
                    ReloadStepFailure {
                        bucket: "policy.explain.sync",
                        target: "[policy.explain]".to_string(),
                        error: ReloadStepError::NotAccepted(error),
                    },
                );
            }
            ReloadDispatch::AcknowledgementLost => {
                return acknowledge_partial(
                    &progress,
                    working_config,
                    &desired_snapshot,
                    ReloadStepFailure {
                        bucket: "policy.explain.sync",
                        target: "[policy.explain]".to_string(),
                        error: ReloadStepError::AcknowledgementLost,
                    },
                );
            }
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
        // LAN-888: stamp the registry-clone cost and the dispatch moment.
        // The gap between this line and the peer manager's receipt log is
        // pure command-channel queue wait — the only piece of the
        let clone_started = Instant::now();
        let rpol_files = new_config.policy.rpol_files.clone();
        let rpol = new_config.policy.rpol.clone();
        let dataset_bindings = new_config.policy.dataset_bindings.clone();
        info!(
            clone_ms = u64::try_from(clone_started.elapsed().as_millis()).unwrap_or(u64::MAX),
            "rpol policy sync dispatched"
        );
        let result = catalog_step(
            peer_mgr_tx,
            &mut progress,
            OwnedCatalogMutation::SyncRpolPolicies {
                rpol_files,
                rpol,
                dataset_bindings,
            },
        )
        .await;
        match result {
            // LAN-284: adopt the candidate registry into the runtime
            // snapshot ONLY after the peer manager committed it. The
            // manager's own sync is two-phase (a rejected sync leaves
            // its `current_config` and every live chain on the old
            // registry), so absorbing the candidate before the ack
            // would ship the REJECTED registry to the runtime snapshot
            // via the authoritative partial receipt — new sessions
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
            Err(failure) => {
                return owned_step_failure(
                    &progress,
                    working_config,
                    &desired_snapshot,
                    "policy.rpol.sync",
                    "[policy] rpol_files".to_string(),
                    failure,
                );
            }
        }
    }

    // LAN-305: this is the first point after preflight where every earlier
    // fallible peer-manager registry/snapshot step has succeeded. Commit the
    // staged contents/errors now, then publish honest snapshot bookkeeping and
    // dependency-scoped refreshes. Its acknowledgement is part of the owner.
    if dataset_commit_pending {
        progress.begin_mutation();
    }
    dataset_commit.commit();
    if dataset_commit_pending {
        progress.mark_accepted_effect();
    }
    working_config
        .policy
        .datasets
        .clone_from(&new_config.policy.datasets);
    working_config.policy.dataset_bindings = new_config.policy.dataset_bindings.clone();
    let dataset_events = &new_config.policy.dataset_events;
    if !dataset_events.swapped.is_empty() || !dataset_events.failed.is_empty() {
        let outcome = dispatch_actor_mutation_step(peer_mgr_tx, &progress, |reply| {
            PeerManagerCommand::RefreshDatasetDependents {
                swapped: dataset_events.swapped.clone(),
                failed: dataset_events.failed.clone(),
                reply,
            }
        })
        .await;
        match outcome {
            ReloadDispatch::Replied(Ok(())) => progress.mark_accepted_effect(),
            ReloadDispatch::NotAccepted(error) => {
                return acknowledge_partial(
                    &progress,
                    working_config,
                    &desired_snapshot,
                    ReloadStepFailure {
                        bucket: "policy.dataset.refresh",
                        target: "[policy.datasets]".to_string(),
                        error: ReloadStepError::NotAccepted(error),
                    },
                );
            }
            ReloadDispatch::Replied(Err(error)) => {
                return acknowledge_partial(
                    &progress,
                    working_config,
                    &desired_snapshot,
                    ReloadStepFailure {
                        bucket: "policy.dataset.refresh",
                        target: "[policy.datasets]".to_string(),
                        error: ReloadStepError::Rejected(error),
                    },
                );
            }
            ReloadDispatch::AcknowledgementLost => {
                progress.mark_accepted_effect();
                return acknowledge_partial(
                    &progress,
                    working_config,
                    &desired_snapshot,
                    ReloadStepFailure {
                        bucket: "policy.dataset.refresh",
                        target: "[policy.datasets]".to_string(),
                        error: ReloadStepError::AcknowledgementLost,
                    },
                );
            }
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
            return acknowledge_partial(
                &progress,
                working_config,
                &desired_snapshot,
                ReloadStepFailure {
                    bucket,
                    target: name.clone(),
                    error: format!(
                        "internal: neighbor_set {name:?} present in diff but not resolvable from new config"
                    ).into(),
                },
            );
        };
        let event = ConfigEvent::SetNeighborSet {
            name: name.clone(),
            definition: definition.clone(),
            ack: None,
        };
        match catalog_step(
            peer_mgr_tx,
            &mut progress,
            OwnedCatalogMutation::SetNeighborSet {
                name: name.clone(),
                definition,
            },
        )
        .await
        {
            Ok(()) => {
                if let Err(error) = apply_config_event(&mut working_config, &event) {
                    return acknowledge_partial(
                        &progress,
                        working_config,
                        &desired_snapshot,
                        ReloadStepFailure {
                            bucket,
                            target: name.clone(),
                            error: format!(
                                "applied at peer manager but local snapshot rejected the event: {error}"
                            ).into(),
                        },
                    );
                }
                info!(name = %name, %bucket, "reload: neighbor_set applied");
            }
            Err(failure) => {
                return owned_step_failure(
                    &progress,
                    working_config,
                    &desired_snapshot,
                    bucket,
                    name.clone(),
                    failure,
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
            return acknowledge_partial(
                &progress,
                working_config,
                &desired_snapshot,
                ReloadStepFailure {
                    bucket,
                    target: name.clone(),
                    error: format!(
                        "internal: policy {name:?} present in diff but not resolvable from new config"
                    ).into(),
                },
            );
        };
        let event = ConfigEvent::SetPolicy {
            name: name.clone(),
            definition: definition.clone(),
            ack: None,
        };
        match catalog_step(
            peer_mgr_tx,
            &mut progress,
            OwnedCatalogMutation::SetPolicy {
                name: name.clone(),
                definition: Box::new(definition),
            },
        )
        .await
        {
            Ok(()) => {
                if let Err(error) = apply_config_event(&mut working_config, &event) {
                    return acknowledge_partial(
                        &progress,
                        working_config,
                        &desired_snapshot,
                        ReloadStepFailure {
                            bucket,
                            target: name.clone(),
                            error: format!(
                                "applied at peer manager but local snapshot rejected the event: {error}"
                            ).into(),
                        },
                    );
                }
                info!(name = %name, %bucket, "reload: policy applied");
            }
            Err(failure) => {
                return owned_step_failure(
                    &progress,
                    working_config,
                    &desired_snapshot,
                    bucket,
                    name.clone(),
                    failure,
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
            return acknowledge_partial(
                &progress,
                working_config,
                &desired_snapshot,
                ReloadStepFailure {
                    bucket,
                    target: name.clone(),
                    error: format!(
                        "internal: peer_group {name:?} present in diff but not resolvable from new config"
                    ).into(),
                },
            );
        };
        let event = ConfigEvent::SetPeerGroup {
            name: name.clone(),
            definition: definition.clone(),
            ack: None,
        };
        match catalog_step(
            peer_mgr_tx,
            &mut progress,
            OwnedCatalogMutation::SetPeerGroup {
                name: name.clone(),
                definition: Box::new(definition),
            },
        )
        .await
        {
            Ok(()) => {
                if let Err(error) = apply_config_event(&mut working_config, &event) {
                    return acknowledge_partial(
                        &progress,
                        working_config,
                        &desired_snapshot,
                        ReloadStepFailure {
                            bucket,
                            target: name.clone(),
                            error: format!(
                                "applied at peer manager but local snapshot rejected the event: {error}"
                            ).into(),
                        },
                    );
                }
                info!(name = %name, %bucket, "reload: peer_group applied");
            }
            Err(failure) => {
                return owned_step_failure(
                    &progress,
                    working_config,
                    &desired_snapshot,
                    bucket,
                    name.clone(),
                    failure,
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
            catalog_step(
                peer_mgr_tx,
                &mut progress,
                OwnedCatalogMutation::ClearGlobalImportChain,
            )
            .await
        } else {
            catalog_step(
                peer_mgr_tx,
                &mut progress,
                OwnedCatalogMutation::SetGlobalImportChain {
                    policy_names: chain,
                },
            )
            .await
        };
        match res {
            Ok(()) => {
                if let Err(error) = apply_config_event(&mut working_config, &event) {
                    return acknowledge_partial(
                        &progress,
                        working_config,
                        &desired_snapshot,
                        ReloadStepFailure {
                            bucket: "global_chain.import",
                            target: String::new(),
                            error: format!(
                                "applied at peer manager but local snapshot rejected the event: {error}"
                            ).into(),
                        },
                    );
                }
                info!("reload: global import_chain applied");
            }
            Err(failure) => {
                return owned_step_failure(
                    &progress,
                    working_config,
                    &desired_snapshot,
                    "global_chain.import",
                    String::new(),
                    failure,
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
            catalog_step(
                peer_mgr_tx,
                &mut progress,
                OwnedCatalogMutation::ClearGlobalExportChain,
            )
            .await
        } else {
            catalog_step(
                peer_mgr_tx,
                &mut progress,
                OwnedCatalogMutation::SetGlobalExportChain {
                    policy_names: chain,
                },
            )
            .await
        };
        match res {
            Ok(()) => {
                if let Err(error) = apply_config_event(&mut working_config, &event) {
                    return acknowledge_partial(
                        &progress,
                        working_config,
                        &desired_snapshot,
                        ReloadStepFailure {
                            bucket: "global_chain.export",
                            target: String::new(),
                            error: format!(
                                "applied at peer manager but local snapshot rejected the event: {error}"
                            ).into(),
                        },
                    );
                }
                info!("reload: global export_chain applied");
            }
            Err(failure) => {
                return owned_step_failure(
                    &progress,
                    working_config,
                    &desired_snapshot,
                    "global_chain.export",
                    String::new(),
                    failure,
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
                return acknowledge_partial(
                    &progress,
                    working_config,
                    &desired_snapshot,
                    ReloadStepFailure {
                        bucket: "neighbors.resolve",
                        target: "new_config.resolved_neighbors".to_string(),
                        error: ReloadStepError::Rejected(e.to_string()),
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
            if let Err(failure) = hot_peer_step(peer_mgr_tx, &mut progress, cfg).await {
                return owned_step_failure(
                    &progress,
                    working_config,
                    &desired_snapshot,
                    "neighbors.hot_update",
                    n.address.clone(),
                    failure,
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
            let permit = match peer_mgr_tx.reserve().await {
                Ok(permit) => permit,
                Err(error) => {
                    return acknowledge_partial(
                        &progress,
                        working_config,
                        &desired_snapshot,
                        ReloadStepFailure {
                            bucket: "neighbors.reconcile",
                            target: String::new(),
                            error: ReloadStepError::NotAccepted(error.to_string()),
                        },
                    );
                }
            };
            progress.begin_mutation();
            permit.send(PeerManagerCommand::ReconcilePeers {
                added: resolve(&diff.added),
                removed: diff.removed.clone(),
                changed: resolve(&rebuild_changed),
                reply: reply_tx,
            });
            if sighup_ack_fault("reconcile") {
                drop(reply_rx);
                return fenced_reload_failure(
                    &progress,
                    "neighbors.reconcile",
                    ReloadStepError::AcknowledgementLost,
                    RuntimeConfigFenceReason::AcknowledgementLost,
                );
            }
            match reply_rx.await {
                Ok(reconcile) => {
                    if reconcile.authority == PeerReconcileAuthority::Diverged {
                        return fenced_reload_failure(
                            &progress,
                            "neighbors.reconcile",
                            ReloadStepError::Rejected(
                                "peer reconcile returned non-authoritative state".into(),
                            ),
                            RuntimeConfigFenceReason::KnownDivergence,
                        );
                    }
                    for effect in &reconcile.effects {
                        progress.mark_accepted_effect();
                        let key = match effect {
                            PeerReconcileEffect::Added(key)
                            | PeerReconcileEffect::Removed(key)
                            | PeerReconcileEffect::Replaced(key)
                            | PeerReconcileEffect::RemovedForFailedReplacement(key) => key,
                        };
                        working_config.neighbors.retain(|neighbor| {
                            rustbgpd_api::peer_types::PeerKey::new(
                                neighbor
                                    .address
                                    .parse()
                                    .expect("validated neighbor address"),
                                neighbor.interface.clone(),
                            ) != *key
                        });
                        if matches!(
                            effect,
                            PeerReconcileEffect::Added(_) | PeerReconcileEffect::Replaced(_)
                        ) && let Some(neighbor) = new_config.neighbors.iter().find(|neighbor| {
                            rustbgpd_api::peer_types::PeerKey::new(
                                neighbor
                                    .address
                                    .parse()
                                    .expect("validated neighbor address"),
                                neighbor.interface.clone(),
                            ) == *key
                        }) {
                            working_config.neighbors.push(neighbor.clone());
                        }
                    }
                    for failure in &reconcile.failures {
                        warn!(
                            bucket = "neighbors.reconcile",
                            target = %failure.peer,
                            kind = ?failure.kind,
                            error = %failure.error,
                            "config reload step failed"
                        );
                    }
                    if let Some(failure) = reconcile.failures.first() {
                        return acknowledge_partial(
                            &progress,
                            working_config,
                            &desired_snapshot,
                            ReloadStepFailure {
                                bucket: "neighbors.reconcile",
                                target: failure.peer.to_string(),
                                error: ReloadStepError::Rejected(failure.error.clone()),
                            },
                        );
                    }
                }
                Err(_) => {
                    return fenced_reload_failure(
                        &progress,
                        "neighbors.reconcile",
                        ReloadStepError::AcknowledgementLost,
                        RuntimeConfigFenceReason::AcknowledgementLost,
                    );
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
        match peer_step(peer_mgr_tx, &mut progress, |reply| {
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
            Err(error @ ReloadStepError::AcknowledgementLost) => {
                return fenced_reload_failure(
                    &progress,
                    "honor_graceful_shutdown.apply",
                    error,
                    RuntimeConfigFenceReason::AcknowledgementLost,
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
                    error = %error,
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
        match peer_step(peer_mgr_tx, &mut progress, |reply| {
            PeerManagerCommand::SetHonorBlackhole { enabled, reply }
        })
        .await
        {
            Ok(()) => {
                working_config.global.honor_blackhole = enabled;
                info!(enabled, "reload: [global] honor_blackhole hot-applied");
            }
            Err(error @ ReloadStepError::AcknowledgementLost) => {
                return fenced_reload_failure(
                    &progress,
                    "honor_blackhole.apply",
                    error,
                    RuntimeConfigFenceReason::AcknowledgementLost,
                );
            }
            Err(error) => {
                warn!(
                    enabled,
                    error = %error,
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
                let permit = match tx.reserve().await {
                    Ok(permit) => permit,
                    Err(error) => {
                        return acknowledge_partial(
                            &progress,
                            working_config,
                            &desired_snapshot,
                            ReloadStepFailure {
                                bucket: "fib_tables.apply",
                                target: "[[fib_tables]]".to_string(),
                                error: ReloadStepError::NotAccepted(error.to_string()),
                            },
                        );
                    }
                };
                progress.begin_mutation();
                permit.send(FibRuntimeCommand::OwnedReplaceTables {
                    tables: new_config.fib_tables.clone(),
                    reply: reply_tx,
                });
                match reply_rx.await {
                    Ok(OwnedFibReplaceOutcome::Applied) => {
                        progress.mark_accepted_effect();
                        working_config.fib_tables.clone_from(&new_config.fib_tables);
                        match set_pm_fib_tables_snapshot(peer_mgr_tx, &new_config.fib_tables).await
                        {
                            ReloadDispatch::Replied(()) => {
                                progress.mark_accepted_effect();
                                info!(
                                    tables = new_config.fib_tables.len(),
                                    "reload: [[fib_tables]] hot-applied"
                                );
                            }
                            ReloadDispatch::NotAccepted(error) => {
                                return acknowledge_partial(
                                    &progress,
                                    working_config,
                                    &desired_snapshot,
                                    ReloadStepFailure {
                                        bucket: "fib_tables.snapshot",
                                        target: "[[fib_tables]]".to_string(),
                                        error: ReloadStepError::NotAccepted(error),
                                    },
                                );
                            }
                            ReloadDispatch::AcknowledgementLost => {
                                return acknowledge_partial(
                                    &progress,
                                    working_config,
                                    &desired_snapshot,
                                    ReloadStepFailure {
                                        bucket: "fib_tables.snapshot",
                                        target: "[[fib_tables]]".to_string(),
                                        error: ReloadStepError::AcknowledgementLost,
                                    },
                                );
                            }
                        }
                    }
                    Ok(OwnedFibReplaceOutcome::RejectedNoEffect(error)) => {
                        return acknowledge_partial(
                            &progress,
                            working_config,
                            &desired_snapshot,
                            ReloadStepFailure {
                                bucket: "fib_tables.apply",
                                target: "[[fib_tables]]".to_string(),
                                error: ReloadStepError::Rejected(error),
                            },
                        );
                    }
                    Ok(OwnedFibReplaceOutcome::CompensationAmbiguous(error)) => {
                        return fenced_reload_failure(
                            &progress,
                            "fib_tables.apply",
                            ReloadStepError::Rejected(error),
                            RuntimeConfigFenceReason::KnownDivergence,
                        );
                    }
                    Err(_) => {
                        return fenced_reload_failure(
                            &progress,
                            "fib_tables.apply",
                            ReloadStepError::AcknowledgementLost,
                            RuntimeConfigFenceReason::AcknowledgementLost,
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
        match catalog_step(
            peer_mgr_tx,
            &mut progress,
            OwnedCatalogMutation::DeletePeerGroup { name: name.clone() },
        )
        .await
        {
            Ok(()) => {
                if let Err(error) = apply_config_event(&mut working_config, &event) {
                    return acknowledge_partial(
                        &progress,
                        working_config,
                        &desired_snapshot,
                        ReloadStepFailure {
                            bucket: "peer_group.delete",
                            target: name.clone(),
                            error: format!(
                                "applied at peer manager but local snapshot rejected the event: {error}"
                            ).into(),
                        },
                    );
                }
                info!(name = %name, "reload: peer_group removed");
            }
            Err(failure) => {
                return owned_step_failure(
                    &progress,
                    working_config,
                    &desired_snapshot,
                    "peer_group.delete",
                    name.clone(),
                    failure,
                );
            }
        }
    }
    for name in &policy_diff.definitions_removed {
        let event = ConfigEvent::DeletePolicy {
            name: name.clone(),
            ack: None,
        };
        match catalog_step(
            peer_mgr_tx,
            &mut progress,
            OwnedCatalogMutation::DeletePolicy { name: name.clone() },
        )
        .await
        {
            Ok(()) => {
                if let Err(error) = apply_config_event(&mut working_config, &event) {
                    return acknowledge_partial(
                        &progress,
                        working_config,
                        &desired_snapshot,
                        ReloadStepFailure {
                            bucket: "policy.delete",
                            target: name.clone(),
                            error: format!(
                                "applied at peer manager but local snapshot rejected the event: {error}"
                            ).into(),
                        },
                    );
                }
                info!(name = %name, "reload: policy removed");
            }
            Err(failure) => {
                return owned_step_failure(
                    &progress,
                    working_config,
                    &desired_snapshot,
                    "policy.delete",
                    name.clone(),
                    failure,
                );
            }
        }
    }
    for name in &policy_diff.neighbor_sets_removed {
        let event = ConfigEvent::DeleteNeighborSet {
            name: name.clone(),
            ack: None,
        };
        match catalog_step(
            peer_mgr_tx,
            &mut progress,
            OwnedCatalogMutation::DeleteNeighborSet { name: name.clone() },
        )
        .await
        {
            Ok(()) => {
                if let Err(error) = apply_config_event(&mut working_config, &event) {
                    return acknowledge_partial(
                        &progress,
                        working_config,
                        &desired_snapshot,
                        ReloadStepFailure {
                            bucket: "neighbor_set.delete",
                            target: name.clone(),
                            error: format!(
                                "applied at peer manager but local snapshot rejected the event: {error}"
                            ).into(),
                        },
                    );
                }
                info!(name = %name, "reload: neighbor_set removed");
            }
            Err(failure) => {
                return owned_step_failure(
                    &progress,
                    working_config,
                    &desired_snapshot,
                    "neighbor_set.delete",
                    name.clone(),
                    failure,
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
    // handled above, returning an authoritative partial receipt so the
    // failure is surfaced rather than logged-and-forgotten.

    info!("config reload complete");
    acknowledged_reload(
        working_config,
        desired_snapshot,
        dialout_targets,
        SighupCompletion::Complete,
    )
}

/// Record the first known SIGHUP step failure and return its explicit
/// known-partial authority. Composite finalization must acknowledge the same
/// peer-manager snapshot, bridge/persister snapshot, tracing projection, and
/// dial-out targets before the owner can settle.
///
fn acknowledge_partial(
    progress: &SighupMutationProgress<'_>,
    working_config: Config,
    desired_config: &Arc<AcceptedConfigSnapshot>,
    failure: ReloadStepFailure,
) -> SighupReloadOutcome {
    error!(
        bucket = failure.bucket,
        target = %failure.target,
        error = %failure.error,
        "config reload stopped at this step; settling the acknowledged partial runtime authority before another reload may begin"
    );
    if matches!(failure.error, ReloadStepError::AcknowledgementLost) {
        progress.record_recovery_step(failure.bucket);
        return SighupReloadOutcome::RecoveryFenced {
            error: SighupReloadError::Failed(failure),
            reason: RuntimeConfigFenceReason::AcknowledgementLost,
        };
    }
    if !progress.accepted_effect {
        return SighupReloadOutcome::CleanNoEffect(SighupReloadError::Failed(failure));
    }
    let dialout_targets = config::gnmi_dialout_targets(&working_config).unwrap_or_default();
    acknowledged_reload(
        working_config,
        Arc::clone(desired_config),
        dialout_targets,
        SighupCompletion::KnownPartial {
            failures: vec![failure],
        },
    )
}

#[cfg(test)]
mod tests {
    #![expect(clippy::large_futures, reason = "T288 keeps authority unboxed")]

    use std::fmt::Write as _;
    use std::path::PathBuf;

    use super::*;
    use crate::config_persister::ConfigPersister;
    use crate::peer_manager::{PeerManager, TransactionConfigScope};
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

    macro_rules! assert_not_published {
        ($outcome:expr $(,)?) => {
            assert!(matches!(
                $outcome,
                AckedPersistOutcome::Settled {
                    outcome: ConfigPersistCommitOutcome::NotPublished(_),
                    ..
                }
            ))
        };
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
            (concat!("load_tier", "_test_toml("), 9),
            (concat!("tier_authorized_uds", "_test_config("), 2),
            (concat!("assert_tier_authorized", "_test_config("), 15),
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
    async fn bounded_control_lanes_apply_capacity_one_fifo_backpressure() {
        use tokio::time::{Duration, timeout};

        let config = load_config_from_toml("bounded-control-lane", baseline_toml());
        let (internal_tx, mut internal_rx) = mpsc::channel(1);
        let (first_ack, first_ack_rx) = oneshot::channel();
        internal_tx
            .send(InternalCommand::ReplaceConfigSnapshot {
                config: Box::new(config.clone()),
                ack: Some(first_ack),
            })
            .await
            .unwrap();
        let (second_ack, second_ack_rx) = oneshot::channel();
        let mut second = Box::pin(internal_tx.send(InternalCommand::ReplaceConfigSnapshot {
            config: Box::new(config.clone()),
            ack: Some(second_ack),
        }));
        assert!(
            timeout(Duration::from_millis(10), &mut second)
                .await
                .is_err()
        );
        let InternalCommand::ReplaceConfigSnapshot { ack, .. } = internal_rx.recv().await.unwrap()
        else {
            panic!("first internal command must retain its identity");
        };
        ack.unwrap().send(()).unwrap();
        second.await.unwrap();
        let InternalCommand::ReplaceConfigSnapshot { ack, .. } = internal_rx.recv().await.unwrap()
        else {
            panic!("second internal command must retain its identity");
        };
        ack.unwrap().send(()).unwrap();
        first_ack_rx.await.unwrap();
        second_ack_rx.await.unwrap();

        let snapshot = AcceptedConfigSnapshot::from_config_for_test(config);
        let (replace_tx, mut replace_rx) = mpsc::channel(1);
        let (first_adopted, first_adopted_rx) = oneshot::channel();
        replace_tx
            .send(AcceptedBridgeReplacement {
                snapshot: Arc::clone(&snapshot),
                adopted: first_adopted,
            })
            .await
            .unwrap();
        let (second_adopted, second_adopted_rx) = oneshot::channel();
        let mut second = Box::pin(replace_tx.send(AcceptedBridgeReplacement {
            snapshot,
            adopted: second_adopted,
        }));
        assert!(
            timeout(Duration::from_millis(10), &mut second)
                .await
                .is_err()
        );
        let first = replace_rx.recv().await.unwrap();
        first.adopted.send(ReloadDispatch::Replied(())).unwrap();
        second.await.unwrap();
        let second = replace_rx.recv().await.unwrap();
        second.adopted.send(ReloadDispatch::Replied(())).unwrap();
        assert!(matches!(
            first_adopted_rx.await.unwrap(),
            ReloadDispatch::Replied(())
        ));
        assert!(matches!(
            second_adopted_rx.await.unwrap(),
            ReloadDispatch::Replied(())
        ));
    }

    #[test]
    fn bounded_control_lane_source_inventory_is_closed() {
        let main = include_str!("main.rs");
        let reload = include_str!("reload.rs");
        let transaction = include_str!("config_transaction_control.rs");
        assert!(
            main.contains("let (peer_mgr_internal_tx, peer_mgr_internal_rx) = mpsc::channel(1)")
        );
        assert!(main.contains("let (bridge_replace_tx, bridge_replace_rx) = mpsc::channel(1)"));
        assert!(reload.contains("mpsc::Receiver<AcceptedBridgeReplacement>"));
        assert!(reload.contains("mpsc::Sender<AcceptedBridgeReplacement>"));
        assert!(!reload.contains(concat!(
            "mpsc::Unbounded",
            "Sender<AcceptedBridgeReplacement>"
        )));
        assert!(!reload.contains(concat!(
            "mpsc::Unbounded",
            "Receiver<AcceptedBridgeReplacement>"
        )));
        assert!(!transaction.contains(concat!("mpsc::Unbounded", "Sender<InternalCommand>")));
        assert!(!transaction.contains(concat!("mpsc::Unbounded", "Receiver<InternalCommand>")));
        assert!(!reload.contains(concat!("try_", "send(AcceptedBridgeReplacement")));
        assert!(!transaction.contains(concat!("try_", "send(InternalCommand")));
        assert!(reload.contains(concat!("mpsc::Unbounded", "Receiver<Box<Config>>")));
    }

    #[tokio::test]
    async fn sighup_runtime_baseline_reads_peer_manager_snapshot_after_typed_stage() {
        let initial = load_config_from_toml("runtime-baseline-initial", baseline_toml());
        let mut candidate = initial.clone();
        candidate.neighbors[0].hold_time = Some(45);

        let (tx, rx) = mpsc::channel(16);
        let (internal_tx, internal_rx) = mpsc::channel(1);
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
        internal_tx
            .send(InternalCommand::StageTransactionConfig {
                candidate: Box::new(candidate),
                scope: TransactionConfigScope::Full,
                reply: stage_tx,
            })
            .await
            .unwrap();
        let rollback_token = stage_rx.await.unwrap().unwrap();
        drop(rollback_token);

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
    /// rebuilt from that snapshot when finalization swaps it into
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

    /// A restart-required daemon identity edit must not leak into a concurrent
    /// hot EVPN apply. Auto-derived route targets consume the local ASN, so the
    /// coordinator must resolve the candidate from the pinned runtime snapshot
    /// while the raw edit remains visible in the desired snapshot.
    #[tokio::test]
    async fn reload_evpn_auto_derived_rt_uses_pinned_runtime_asn() {
        let path = unique_temp_path("reload-evpn-pinned-asn");
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
        let initial = load_config_from_toml(
            "reload-evpn-pinned-asn-startup",
            &std::fs::read_to_string(&path).unwrap(),
        );
        let live_grpc_tcp = initial.global.telemetry.grpc_tcp.clone();
        let live_grpc_uds = initial.global.telemetry.grpc_uds.clone();
        let (apply, coordinator) = evpn_reload_apply(&initial, Ok(()));

        std::fs::write(
            &path,
            r#"
[global]
asn = 65100
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
auto_derive_route_target = true
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
        .expect("combined ASN and EVPN edit should retain both snapshots");

        assert_eq!(
            returned.global.asn, 65001,
            "runtime identity must retain the startup ASN"
        );
        assert_eq!(
            returned.desired.global.asn, 65100,
            "the restart-required ASN edit must remain visible as desired drift"
        );

        let added = rustbgpd_evpn::EvpnInstanceId::new(200).unwrap();
        let coordinator = coordinator.lock().unwrap();
        let instance = coordinator
            .model()
            .instances()
            .get(added)
            .expect("the concurrent hot EVPN addition must commit");
        let route_targets = instance
            .route_targets
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        assert_eq!(
            route_targets,
            ["65001:268435656"],
            "auto-derived route targets must use the pinned startup ASN"
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
    async fn reload_fences_decomposed_evpn_failure_before_later_command() {
        // #268: an ES delete + its (surviving) member L2VNI redefine + a new
        // L2VNI add in ONE SIGHUP. Pure shape planning decomposes the mixed
        // whole before mutation begins; the delete commits, then the redefine
        // fails after effects and pins the coordinator. The reload must fence
        // without dispatching the later honor-graceful-shutdown mutation.
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
                Ok(()),
                Err(
                    crate::evpn_runtime_converger::DaemonEvpnRuntimeConvergeError::Failed(
                        rustbgpd_evpn::EvpnRuntimeConvergeError::new(
                            "decomposed redefine failed after effects",
                        ),
                    ),
                ),
            ],
        );

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

        let (peer_mgr_tx, mut peer_mgr_rx) = mpsc::channel(8);
        let outcome = reload_config(
            path.to_str().unwrap(),
            &initial,
            live_grpc_tcp.as_ref(),
            live_grpc_uds.as_ref(),
            &peer_mgr_tx,
            None,
            Some(&apply),
        )
        .await;

        assert!(matches!(
            outcome,
            SighupReloadOutcome::RecoveryFenced {
                reason: RuntimeConfigFenceReason::KnownDivergence,
                ..
            }
        ));
        assert!(matches!(
            peer_mgr_rx.try_recv(),
            Err(tokio::sync::mpsc::error::TryRecvError::Empty)
        ));
        let guard = coordinator.lock().unwrap();
        assert_eq!(
            guard.model().generation().as_u64(),
            2,
            "the committed delete remains authoritative after the later step fails"
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
            "65000:100"
        );
        assert!(
            guard
                .model()
                .instances()
                .get(rustbgpd_evpn::EvpnInstanceId::new(200).unwrap())
                .is_none()
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
    async fn reload_failed_evpn_candidate_fences_at_committed_runtime_baseline() {
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
        let outcome = reload_config(
            path.to_str().unwrap(),
            &initial,
            live_grpc_tcp.as_ref(),
            live_grpc_uds.as_ref(),
            &peer_mgr_tx,
            None,
            Some(&apply),
        )
        .await;

        assert!(matches!(
            outcome,
            SighupReloadOutcome::RecoveryFenced {
                reason: RuntimeConfigFenceReason::KnownDivergence,
                ..
            }
        ));

        let committed = rustbgpd_evpn::EvpnInstanceId::new(200).unwrap();
        let rejected = rustbgpd_evpn::EvpnInstanceId::new(300).unwrap();
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

    async fn assert_honor_reply_loss_fences(graceful: bool, bucket: &'static str) {
        let current = load_config_from_toml("honor-reply-loss", baseline_toml());
        let mut desired = current.clone();
        if graceful {
            desired.global.honor_graceful_shutdown = true;
        } else {
            desired.global.honor_blackhole = true;
        }
        let (peer_mgr_tx, mut peer_mgr_rx) = mpsc::channel(1);
        let actor = tokio::spawn(async move {
            match (graceful, peer_mgr_rx.recv().await.expect("honor command")) {
                (true, PeerManagerCommand::SetHonorGracefulShutdown { reply, .. })
                | (false, PeerManagerCommand::SetHonorBlackhole { reply, .. }) => drop(reply),
                _ => panic!("unexpected honor command"),
            }
        });
        let outcome = reload_config_with_tcp_ao(
            SighupReloadPlan {
                baseline_runtime: current,
                desired: AcceptedConfigSnapshot::from_config_for_test(desired),
                accepted_effect: false,
            },
            None,
            None,
            &peer_mgr_tx,
            None,
            None,
            None,
            None,
            None,
        )
        .await;
        actor.await.unwrap();
        assert!(matches!(
            outcome,
            SighupReloadOutcome::RecoveryFenced {
                error: SighupReloadError::Failed(ReloadStepFailure {
                    bucket: actual,
                    error: ReloadStepError::AcknowledgementLost,
                    ..
                }),
                reason: RuntimeConfigFenceReason::AcknowledgementLost,
            } if actual == bucket
        ));
    }

    #[tokio::test]
    async fn honor_graceful_shutdown_reply_loss_recovery_fences() {
        assert_honor_reply_loss_fences(true, "honor_graceful_shutdown.apply").await;
    }

    #[tokio::test]
    async fn honor_blackhole_reply_loss_recovery_fences() {
        assert_honor_reply_loss_fences(false, "honor_blackhole.apply").await;
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
                Some(FibRuntimeCommand::OwnedReplaceTables { tables, reply }) => {
                    let _ = reply.send(OwnedFibReplaceOutcome::Applied);
                    tables.len()
                }
                Some(FibRuntimeCommand::GetTables { .. }) => panic!("unexpected GetTables"),
                None => panic!("expected OwnedReplaceTables"),
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
                    PeerManagerCommand::OwnedCatalogMutation { reply, .. } => {
                        let _ = reply.send(OwnedCatalogMutationOutcome::Success);
                    }
                    _ => panic!("unexpected peer manager command"),
                }
            }
            tags
        });
        let (fib_tx, mut fib_rx) = mpsc::channel(8);
        let actor = tokio::spawn(async move {
            match fib_rx.recv().await {
                Some(FibRuntimeCommand::OwnedReplaceTables { tables, reply }) => {
                    assert!(tables[0].allowed_peer_groups.is_empty());
                    let _ = reply.send(OwnedFibReplaceOutcome::Applied);
                }
                _ => panic!("expected OwnedReplaceTables"),
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

        let outcome = reload_config(
            path.to_str().unwrap(),
            &initial,
            tcp.as_ref(),
            uds.as_ref(),
            &peer_mgr_tx,
            Some(&fib_tx),
            None,
        )
        .await;
        assert!(matches!(outcome, SighupReloadOutcome::CleanNoEffect(_)));
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
            if let Some(FibRuntimeCommand::OwnedReplaceTables { reply, .. }) = fib_rx.recv().await {
                let _ = reply.send(OwnedFibReplaceOutcome::RejectedNoEffect(
                    "simulated reconcile failure".to_string(),
                ));
            }
        });

        let outcome = reload_config(
            path.to_str().unwrap(),
            &initial,
            tcp.as_ref(),
            uds.as_ref(),
            &peer_mgr_tx,
            Some(&fib_tx),
            None,
        )
        .await;
        assert!(matches!(outcome, SighupReloadOutcome::CleanNoEffect(_)));
        let _ = actor.await;
        std::fs::remove_file(&path).ok();
    }

    #[tokio::test]
    async fn reload_pins_blackhole() {
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
blackhole_discard_max_active = 10
blackhole_discard_install_rate_per_minute = 20
blackhole_discard_install_burst = 5

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
blackhole_discard_max_active = 11
blackhole_discard_install_rate_per_minute = 21
blackhole_discard_install_burst = 6

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
        assert_eq!(returned.global.blackhole_discard_max_active, Some(10));
        assert_eq!(
            returned.global.blackhole_discard_install_rate_per_minute,
            Some(20)
        );
        assert_eq!(returned.global.blackhole_discard_install_burst, Some(5));

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
            PeerManagerCommand::OwnedCatalogMutation { mutation, .. } => match mutation {
                OwnedCatalogMutation::SetPolicy { name, .. } => format!("SetPolicy({name})"),
                OwnedCatalogMutation::DeletePolicy { name } => format!("DeletePolicy({name})"),
                OwnedCatalogMutation::SetNeighborSet { name, .. } => {
                    format!("SetNeighborSet({name})")
                }
                OwnedCatalogMutation::DeleteNeighborSet { name } => {
                    format!("DeleteNeighborSet({name})")
                }
                OwnedCatalogMutation::SetPeerGroup { name, .. } => {
                    format!("SetPeerGroup({name})")
                }
                OwnedCatalogMutation::DeletePeerGroup { name } => {
                    format!("DeletePeerGroup({name})")
                }
                OwnedCatalogMutation::SetGlobalImportChain { policy_names } => {
                    format!("SetGlobalImportChain({})", policy_names.join(","))
                }
                OwnedCatalogMutation::SetGlobalExportChain { policy_names } => {
                    format!("SetGlobalExportChain({})", policy_names.join(","))
                }
                OwnedCatalogMutation::ClearGlobalImportChain => {
                    "ClearGlobalImportChain".to_string()
                }
                OwnedCatalogMutation::ClearGlobalExportChain => {
                    "ClearGlobalExportChain".to_string()
                }
                OwnedCatalogMutation::SyncRpolPolicies { rpol, .. } => {
                    format!("SyncRpolPolicies({})", rpol.policies.len())
                }
                _ => "OwnedCatalogMutation".to_string(),
            },
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
            PeerManagerCommand::SetFibTablesSnapshot { tables, .. } => {
                format!("SetFibTablesSnapshot({})", tables.len())
            }
            PeerManagerCommand::SetHonorGracefulShutdown { enabled, .. } => {
                format!("SetHonorGracefulShutdown({enabled})")
            }
            PeerManagerCommand::SetHonorBlackhole { enabled, .. } => {
                format!("SetHonorBlackhole({enabled})")
            }
            _ => "Other".to_string(),
        }
    }

    #[tokio::test]
    async fn owned_catalog_ambiguity_and_accepted_reply_loss_fence() {
        let mutations = [
            OwnedCatalogMutation::DeletePolicy {
                name: "policy".to_string(),
            },
            OwnedCatalogMutation::DeleteNeighborSet {
                name: "set".to_string(),
            },
            OwnedCatalogMutation::DeletePeerGroup {
                name: "group".to_string(),
            },
            OwnedCatalogMutation::ClearGlobalImportChain,
        ];
        for mutation in mutations {
            let (tx, mut rx) = mpsc::channel(1);
            tokio::spawn(async move {
                let Some(PeerManagerCommand::OwnedCatalogMutation { reply, .. }) = rx.recv().await
                else {
                    panic!("expected owned catalog mutation");
                };
                let _ = reply.send(OwnedCatalogMutationOutcome::CompensationAmbiguous(
                    CatalogMutationError::internal("injected ambiguous compensation"),
                ));
            });
            let mut progress = SighupMutationProgress::new(None, false);
            assert!(matches!(
                catalog_step(&tx, &mut progress, mutation).await,
                Err(OwnedStepFailure::Fenced {
                    reason: RuntimeConfigFenceReason::KnownDivergence,
                    ..
                })
            ));
        }

        for mutation in [
            OwnedCatalogMutation::DeletePolicy {
                name: "reply-loss".to_string(),
            },
            OwnedCatalogMutation::SyncRpolPolicies {
                rpol_files: Vec::new(),
                rpol: rustbgpd_policy::rpol::RpolPolicySet::default(),
                dataset_bindings: rustbgpd_policy::datasets::DatasetBindings::default(),
            },
        ] {
            let (tx, mut rx) = mpsc::channel(1);
            tokio::spawn(async move {
                let Some(PeerManagerCommand::OwnedCatalogMutation { reply, .. }) = rx.recv().await
                else {
                    panic!("expected owned catalog mutation");
                };
                drop(reply);
            });
            let mut progress = SighupMutationProgress::new(None, false);
            assert!(matches!(
                catalog_step(&tx, &mut progress, mutation).await,
                Err(OwnedStepFailure::Fenced {
                    reason: RuntimeConfigFenceReason::AcknowledgementLost,
                    ..
                })
            ));
        }
    }

    #[tokio::test]
    async fn rejected_and_compensated_catalog_outcomes_do_not_claim_authority() {
        for outcome in [
            OwnedCatalogMutationOutcome::RejectedNoEffect(CatalogMutationError::internal(
                "injected rejection",
            )),
            OwnedCatalogMutationOutcome::FullyCompensated(CatalogMutationError::internal(
                "injected compensation",
            )),
        ] {
            let (tx, mut rx) = mpsc::channel(1);
            tokio::spawn(async move {
                let Some(PeerManagerCommand::OwnedCatalogMutation { reply, .. }) = rx.recv().await
                else {
                    panic!("expected owned catalog mutation");
                };
                let _ = reply.send(outcome);
            });
            let mut progress = SighupMutationProgress::new(None, false);
            assert!(matches!(
                catalog_step(
                    &tx,
                    &mut progress,
                    OwnedCatalogMutation::DeletePolicy {
                        name: "rejected".to_string(),
                    },
                )
                .await,
                Err(OwnedStepFailure::Partial(_))
            ));
            assert!(!progress.accepted_effect);
        }
    }

    #[tokio::test]
    async fn owned_hot_update_reply_loss_fences() {
        let (tx, mut rx) = mpsc::channel(1);
        tokio::spawn(async move {
            let Some(PeerManagerCommand::HotUpdatePeer { reply, .. }) = rx.recv().await else {
                panic!("expected hot update");
            };
            drop(reply);
        });
        let mut progress = SighupMutationProgress::new(None, false);
        let config = load_config_from_toml("hot-reply-loss", baseline_toml());
        let resolved = config.resolved_neighbors().unwrap().remove(0);
        assert!(matches!(
            hot_peer_step(
                &tx,
                &mut progress,
                build_peer_mgr_config(
                    &resolved.transport_config,
                    None,
                    &resolved.label,
                    resolved.import_policy.as_ref(),
                    resolved.export_policy.as_ref(),
                    None,
                ),
            )
            .await,
            Err(OwnedStepFailure::Fenced {
                reason: RuntimeConfigFenceReason::AcknowledgementLost,
                ..
            })
        ));
    }

    #[tokio::test]
    async fn preflight_ack_loss_is_clean_and_runtime_snapshot_retries() {
        for bucket in ["tcp_ao.listener_preflight", "tcp_ao.peer_preflight"] {
            assert!(matches!(
                preflight_dispatch_failure(bucket, ReloadStepError::AcknowledgementLost),
                SighupReloadOutcome::CleanNoEffect(_)
            ));
        }
        let progress = SighupMutationProgress::new(None, false);
        assert!(matches!(
            fenced_reload_failure(
                &progress,
                "tcp_ao.peer_apply",
                ReloadStepError::AcknowledgementLost,
                RuntimeConfigFenceReason::AcknowledgementLost,
            ),
            SighupReloadOutcome::RecoveryFenced {
                reason: RuntimeConfigFenceReason::AcknowledgementLost,
                ..
            }
        ));

        let config = load_config_from_toml("snapshot-retry", baseline_toml());
        let accepted = AcceptedConfigSnapshot::from_config_for_test(config.clone());
        let bindings = config.policy.dataset_bindings.clone();
        let (tx, mut rx) = mpsc::channel(1);
        tokio::spawn(async move {
            if let Some(PeerManagerCommand::RuntimeConfigSnapshot { reply }) = rx.recv().await {
                drop(reply);
            }
            if let Some(PeerManagerCommand::RuntimeConfigSnapshot { reply }) = rx.recv().await {
                let _ = reply.send(Ok(rustbgpd_api::peer_types::RuntimeConfigSnapshotReply {
                    toml: toml::to_string(&config).unwrap(),
                    rpol_files: Vec::new(),
                    rpol: rustbgpd_policy::rpol::RpolPolicySet::default(),
                }));
            }
        });
        assert!(matches!(
            runtime_config_snapshot_accepted(&tx, &accepted, &bindings).await,
            ReloadDispatch::AcknowledgementLost
        ));
        assert!(matches!(
            runtime_config_snapshot_accepted(&tx, &accepted, &bindings).await,
            ReloadDispatch::Replied(Ok(_))
        ));
    }

    /// Drive sequential reloads against the given initial+next TOML and return
    /// the outcomes plus commands the mock peer manager observed, in order.
    /// Replies `Ok(())` to every command that carries a reply channel.
    async fn drive_reloads(
        initial_toml: &str,
        new_toml: &str,
        reloads: usize,
    ) -> (Vec<SighupReloadOutcome>, Vec<String>) {
        let path = unique_temp_path("reload-driver");
        write_tier_test_config(&path, initial_toml);
        let mut current = Config::load_with_diagnostics(path.to_str().unwrap()).unwrap();
        assert_tier_authorized_test_config(&current);
        let live_grpc_tcp = current.global.telemetry.grpc_tcp.clone();
        let live_grpc_uds = current.global.telemetry.grpc_uds.clone();

        write_tier_test_config(&path, new_toml);

        let (peer_mgr_tx, mut peer_mgr_rx) = mpsc::channel::<PeerManagerCommand>(64);
        let mock = tokio::spawn(async move {
            use rustbgpd_api::peer_types::PeerReconcileOutcome;
            let mut tags = Vec::new();
            while let Some(cmd) = peer_mgr_rx.recv().await {
                tags.push(cmd_tag(&cmd));
                // Respond Ok(()) to every command that has a reply
                // channel so reload_config doesn't hang.
                match cmd {
                    PeerManagerCommand::OwnedCatalogMutation { reply, .. } => {
                        let _ = reply.send(OwnedCatalogMutationOutcome::Success);
                    }
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
                    PeerManagerCommand::SoftResetIn { reply, .. } => {
                        let _ = reply.send(Ok(()));
                    }
                    PeerManagerCommand::ReconcilePeers {
                        added,
                        removed,
                        changed,
                        reply,
                    } => {
                        let effects = removed
                            .into_iter()
                            .map(PeerReconcileEffect::Removed)
                            .chain(added.into_iter().map(|peer| {
                                PeerReconcileEffect::Added(rustbgpd_api::peer_types::PeerKey::new(
                                    peer.address,
                                    peer.interface,
                                ))
                            }))
                            .chain(changed.into_iter().map(|peer| {
                                PeerReconcileEffect::Replaced(
                                    rustbgpd_api::peer_types::PeerKey::new(
                                        peer.address,
                                        peer.interface,
                                    ),
                                )
                            }))
                            .collect();
                        let _ = reply.send(PeerReconcileOutcome {
                            effects,
                            ..PeerReconcileOutcome::default()
                        });
                    }
                    PeerManagerCommand::SetFibTablesSnapshot { reply, .. }
                    | PeerManagerCommand::SyncExplainConfig { reply, .. } => {
                        let _ = reply.send(());
                    }
                    PeerManagerCommand::SetHonorGracefulShutdown { reply, .. }
                    | PeerManagerCommand::SetHonorBlackhole { reply, .. } => {
                        let _ = reply.send(Ok(()));
                    }
                    _ => {}
                }
            }
            tags
        });

        let mut outcomes = Vec::with_capacity(reloads);
        for _ in 0..reloads {
            let returned = reload_config(
                path.to_str().unwrap(),
                &current,
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
                current = config.runtime.clone();
            }
            outcomes.push(returned);
        }
        drop(peer_mgr_tx);
        let tags = mock.await.unwrap();
        std::fs::remove_file(&path).ok();
        (outcomes, tags)
    }

    async fn drive_reload(
        initial_toml: &str,
        new_toml: &str,
    ) -> (SighupReloadOutcome, Vec<String>) {
        let (mut outcomes, tags) = drive_reloads(initial_toml, new_toml, 1).await;
        (outcomes.pop().unwrap(), tags)
    }

    /// LAN-888: a reload whose outbound prefix maxima equal the live
    /// ones must not touch the RIB at all — the closed channel here
    /// fails any attempted round-trip. A changed maximum must reach
    /// for the RIB and surface its unavailability.
    #[tokio::test]
    async fn unchanged_outbound_prefix_limits_skip_the_rib_preflight() {
        let (rib_tx, rib_rx) = mpsc::channel::<rustbgpd_rib::RibUpdate>(1);
        drop(rib_rx);
        let live =
            Config::load_toml_with_diagnostics(baseline_toml(), "limits-preflight-live").unwrap();
        let desired_same =
            Config::load_toml_with_diagnostics(baseline_toml(), "limits-preflight-same").unwrap();
        apply_outbound_prefix_limits_if_changed(&rib_tx, &live, &desired_same)
            .await
            .expect("unchanged maxima must skip the RIB preflight entirely");

        let raised = baseline_toml().replace(
            "hold_time = 90",
            "hold_time = 90\nmax_prefixes_out_ipv4 = 100",
        );
        let desired_raised =
            Config::load_toml_with_diagnostics(&raised, "limits-preflight-raised").unwrap();
        let error = apply_outbound_prefix_limits_if_changed(&rib_tx, &live, &desired_raised)
            .await
            .expect_err("changed maxima must attempt the RIB preflight");
        assert!(error.contains("RIB manager unavailable"), "{error}");
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
                if let PeerManagerCommand::OwnedCatalogMutation { reply, .. } = cmd {
                    let _ = reply.send(OwnedCatalogMutationOutcome::Success);
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
                        if let PeerManagerCommand::OwnedCatalogMutation { reply, .. } = cmd {
                            let _ = reply.send(OwnedCatalogMutationOutcome::Success);
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
                if let PeerManagerCommand::OwnedCatalogMutation { reply, .. } = cmd {
                    let _ = reply.send(OwnedCatalogMutationOutcome::RejectedNoEffect(
                        CatalogMutationError::internal("mid-apply chain resolution failed"),
                    ));
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
        .await;
        drop(peer_mgr_tx);
        mock.await.unwrap();
        assert!(matches!(
            rejected,
            SighupReloadOutcome::CleanNoEffect(SighupReloadError::Failed(ReloadStepFailure {
                bucket: "policy.rpol.sync",
                error: ReloadStepError::Rejected(_),
                ..
            }))
        ));

        // A session created after the rejected no-effect reload still resolves
        // the OLD decision.
        let chain = initial
            .import_chain()
            .expect("chain resolves")
            .expect("chain configured");
        assert_eq!(chain.evaluate(&ctx).modifications.set_local_pref, Some(150));

        // Reload 2 (operator retries; peer manager now accepts): the
        // diff re-detects the on-disk candidate against the reverted
        // runtime snapshot and adopts it for everyone.
        let current = initial.clone();
        let (peer_mgr_tx, mut peer_mgr_rx) = mpsc::channel::<PeerManagerCommand>(64);
        let mock = tokio::spawn(async move {
            let mut synced = 0_u32;
            while let Some(cmd) = peer_mgr_rx.recv().await {
                if let PeerManagerCommand::OwnedCatalogMutation { reply, .. } = cmd {
                    synced += 1;
                    let _ = reply.send(OwnedCatalogMutationOutcome::Success);
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
    fn tcp_ao_awaiting_peer_acknowledges_baseline_authority_for_identical_retry() {
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
        let mut current = Config::load_toml_with_diagnostics(&current_toml, "current").unwrap();
        current.file_path = Some(PathBuf::from("/runtime/baseline.toml"));
        let mut desired = Config::load_toml_with_diagnostics(&desired_toml, "desired").unwrap();
        desired.file_path = Some(PathBuf::from("/operator/candidate.toml"));
        let desired_snapshot = AcceptedConfigSnapshot::from_config_for_test(desired.clone());
        let mut progress = SighupMutationProgress::new(None, false);
        progress.mark_accepted_effect();
        let detail = format!(
            "{} peer 10.0.0.2 has not observed successor traffic",
            crate::peer_manager::TCP_AO_AWAITING_PEER_PREFIX
        );

        let outcome = tcp_ao_awaiting_peer_outcome(
            &progress,
            current.clone(),
            &desired_snapshot,
            desired.file_path.as_ref(),
            ReloadStepError::Rejected(detail.clone()),
            ReloadDispatch::Replied(Ok(())),
        );
        let SighupReloadOutcome::Acknowledged(authority) = outcome else {
            panic!("acknowledged awaiting-peer marker must not recovery-fence");
        };
        assert_eq!(authority.runtime.neighbors, current.neighbors);
        assert_eq!(authority.runtime.file_path, desired.file_path);
        assert_eq!(authority.desired.config().neighbors, desired.neighbors);
        let SighupCompletion::KnownPartial { failures } = &authority.completion else {
            panic!("awaiting-peer must retain a known-partial receipt");
        };
        assert_eq!(failures.len(), 1);
        assert_eq!(failures[0].bucket, "tcp_ao.awaiting_peer");
        assert_eq!(failures[0].error.to_string(), detail);

        let awaiting = TcpAoRotationStatus {
            desired: TcpAoRotationGeneration::new(2).unwrap(),
            applied: TcpAoRotationGeneration::STARTUP,
            phase: TcpAoRotationPhase::AwaitingPeer,
            last_error: Some("awaiting successor traffic".to_string()),
        };
        let TcpAoReloadPlan::Rotation(retry) = prepare_tcp_ao_rotation_plan(
            &authority.runtime,
            &authority.desired.config(),
            &awaiting,
        )
        .unwrap() else {
            panic!("acknowledged awaiting authority must retry the retained selection");
        };
        assert_eq!(retry.operation, TcpAoRotationOperation::Selection);
        assert_eq!(retry.generation, awaiting.desired);
    }

    #[test]
    fn tcp_ao_awaiting_peer_marker_uncertainty_still_recovery_fences() {
        let current = Config::load_toml_with_diagnostics(baseline_toml(), "current").unwrap();
        let desired = AcceptedConfigSnapshot::from_config_for_test(current.clone());
        let mut progress = SighupMutationProgress::new(None, false);
        progress.mark_accepted_effect();
        let awaiting = || {
            ReloadStepError::Rejected(format!(
                "{} waiting",
                crate::peer_manager::TCP_AO_AWAITING_PEER_PREFIX
            ))
        };

        let lost = tcp_ao_awaiting_peer_outcome(
            &progress,
            current.clone(),
            &desired,
            current.file_path.as_ref(),
            awaiting(),
            ReloadDispatch::AcknowledgementLost,
        );
        assert!(matches!(
            lost,
            SighupReloadOutcome::RecoveryFenced {
                reason: RuntimeConfigFenceReason::AcknowledgementLost,
                ..
            }
        ));
        for marker in [
            ReloadDispatch::NotAccepted(std::io::Error::other("listener stopped")),
            ReloadDispatch::Replied(Err(std::io::Error::other("generation rejected"))),
        ] {
            assert!(matches!(
                tcp_ao_awaiting_peer_outcome(
                    &progress,
                    current.clone(),
                    &desired,
                    current.file_path.as_ref(),
                    awaiting(),
                    marker,
                ),
                SighupReloadOutcome::RecoveryFenced {
                    reason: RuntimeConfigFenceReason::KnownDivergence,
                    ..
                }
            ));
        }
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
        // LAN-907: the generation carries the complete both-family listener
        // inventory; the transport layer routes the IPv6 owner to the IPv6
        // family socket instead of silently dropping it.
        assert_eq!(opposite_family.current_listener_keys.len(), 1);
        assert_eq!(
            opposite_family.current_listener_keys[0].peer.to_string(),
            "2001:db8::2"
        );
        assert_eq!(opposite_family.current_listener_keys[0].config.0.len(), 2);
        assert_eq!(opposite_family.listener_keys.len(), 1);
        assert_eq!(opposite_family.listener_keys[0].config.0.len(), 1);
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
    async fn reload_pins_dynamic_neighbor_limit_and_preserves_desired_value() {
        let desired = baseline_toml().replace(
            "listen_port = 179",
            "listen_port = 179\ndynamic_neighbor_limit = 17",
        );

        let (returned, tags) = drive_reload(baseline_toml(), &desired).await;
        let returned = returned.expect("limit-only reload should return a config");

        assert!(
            tags.is_empty(),
            "restart-required limit edit must not send peer-manager commands: {tags:?}"
        );
        assert_eq!(
            returned.global.dynamic_neighbor_limit, None,
            "runtime snapshot must preserve the omitted startup value exactly"
        );
        assert_eq!(
            returned.effective_dynamic_neighbor_limit(),
            100,
            "pinning must not materialize the effective default into runtime config"
        );
        assert_eq!(
            returned.desired.global.dynamic_neighbor_limit,
            Some(17),
            "desired snapshot must preserve the edited value for restart"
        );
    }

    #[tokio::test]
    async fn mixed_reload_applies_neighbor_edit_but_pins_dynamic_neighbor_limit() {
        let initial = baseline_toml().replace(
            "listen_port = 179",
            "listen_port = 179\ndynamic_neighbor_limit = 100",
        );
        let desired = initial
            .replace(
                "dynamic_neighbor_limit = 100",
                "dynamic_neighbor_limit = 17",
            )
            .replace("hold_time = 90", "hold_time = 45");

        let (returned, tags) = drive_reloads(&initial, &desired, 2).await;

        assert_eq!(
            tags,
            vec!["ReconcilePeers(+0,-0,~1)"],
            "the independently reloadable neighbor edit must still reconcile"
        );
        for returned in returned {
            let returned = returned.expect("mixed reload should return a config");
            assert_eq!(returned.neighbors[0].hold_time, Some(45));
            assert_eq!(
                returned.global.dynamic_neighbor_limit,
                Some(100),
                "mixed reload must not advance the startup-pinned admission limit"
            );
            assert_eq!(
                returned.desired.global.dynamic_neighbor_limit,
                Some(17),
                "mixed reload must retain the edited limit as desired state"
            );
        }
    }

    #[tokio::test]
    async fn repeated_identical_reload_keeps_dynamic_neighbor_limit_delta_observable() {
        let initial = baseline_toml().replace(
            "listen_port = 179",
            "listen_port = 179\ndynamic_neighbor_limit = 100",
        );
        let desired = initial.replace(
            "dynamic_neighbor_limit = 100",
            "dynamic_neighbor_limit = 17",
        );
        let (returned, tags) = drive_reloads(&initial, &desired, 2).await;

        assert!(tags.is_empty(), "limit-only reloads must have no live work");
        for returned in returned {
            let returned = returned.expect("limit-only reload should return a config");
            assert_eq!(
                returned.global.dynamic_neighbor_limit,
                Some(100),
                "each runtime snapshot must retain the startup admission limit"
            );
            assert_eq!(
                returned.desired.global.dynamic_neighbor_limit,
                Some(17),
                "the unapplied edit must remain observable as desired drift"
            );
        }
    }

    /// Daemon-wide identity and subsystem owners are created once at startup.
    /// A reload must retain that runtime identity while preserving the edited
    /// desired snapshot, including on a repeated identical SIGHUP. The
    /// runtime-added-neighbor assertion exercises the later consumer that made
    /// an unpinned ASN/router ID a live split-brain rather than mere metadata.
    #[tokio::test]
    async fn reload_pins_daemon_wide_inventory_but_hot_applies_honor_knobs() {
        let desired = r#"
[global]
asn = 65100
router_id = "10.0.0.9"
listen_port = 1179
listen_addresses = ["127.0.0.2"]
cluster_id = "10.0.0.8"
worker_threads = 2
honor_graceful_shutdown = true
honor_blackhole = true
multipath_relax = true
link_bandwidth_weighted = true
warm_cache_checkpoint_on_shutdown = true
runtime_state_dir = "/tmp/rustbgpd-reload-edited"

[global.telemetry]
prometheus_addr = "127.0.0.1:19179"
log_format = "plain"

[rpki]
[[rpki.cache_servers]]
address = "127.0.0.1:3323"

[bmp]
sys_name = "reload-edited"
[[bmp.collectors]]
address = "127.0.0.1:5000"

[mrt]
output_dir = "/tmp/rustbgpd-reload-mrt"
dump_interval = 60
compress = true
file_prefix = "edited"

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
hold_time = 90
"#;
        let startup = load_config_from_toml("daemon-pin-startup", baseline_toml());
        let declared = load_config_from_toml("daemon-pin-desired", desired);
        let (outcomes, tags) = drive_reloads(baseline_toml(), desired, 2).await;

        assert_eq!(
            tags,
            vec!["SetHonorGracefulShutdown(true)", "SetHonorBlackhole(true)"],
            "the two explicitly hot-applied global knobs must remain live while startup-owned \
             fields are pinned"
        );

        for outcome in outcomes {
            let reloaded = outcome.expect("daemon-wide restart-only reload must return snapshots");
            let runtime = &reloaded.runtime;
            assert_eq!(runtime.global.asn, startup.global.asn);
            assert_eq!(runtime.global.router_id, startup.global.router_id);
            assert_eq!(runtime.global.listen_port, startup.global.listen_port);
            assert_eq!(runtime.global.cluster_id, startup.global.cluster_id);
            assert_eq!(runtime.global.worker_threads, startup.global.worker_threads);
            assert_eq!(
                runtime.global.multipath_relax,
                startup.global.multipath_relax
            );
            assert_eq!(
                runtime.global.link_bandwidth_weighted,
                startup.global.link_bandwidth_weighted
            );
            assert_eq!(
                runtime.global.warm_cache_checkpoint_on_shutdown,
                startup.global.warm_cache_checkpoint_on_shutdown
            );
            assert_eq!(
                runtime.global.runtime_state_dir,
                startup.global.runtime_state_dir
            );
            assert_eq!(
                runtime.global.telemetry.prometheus_addr,
                startup.global.telemetry.prometheus_addr
            );
            assert_eq!(
                runtime.global.telemetry.log_format,
                startup.global.telemetry.log_format
            );
            assert_eq!(runtime.rpki, startup.rpki);
            assert_eq!(runtime.bmp, startup.bmp);
            assert_eq!(runtime.mrt, startup.mrt);
            assert!(runtime.global.honor_graceful_shutdown);
            assert!(runtime.global.honor_blackhole);

            assert_eq!(reloaded.desired.global, declared.global);
            assert_eq!(reloaded.desired.rpki, declared.rpki);
            assert_eq!(reloaded.desired.bmp, declared.bmp);
            assert_eq!(reloaded.desired.mrt, declared.mrt);

            let mut runtime_added = runtime.neighbors[0].clone();
            runtime_added.address = "10.0.0.3".to_string();
            runtime_added.remote_asn = 65003;
            let resolved = runtime
                .resolve_neighbor(&runtime_added)
                .expect("runtime-added peer must resolve from the pinned snapshot");
            assert_eq!(resolved.transport_config.peer.local_asn, startup.global.asn);
            assert_eq!(
                resolved.transport_config.peer.local_router_id,
                startup
                    .global
                    .router_id
                    .parse::<std::net::Ipv4Addr>()
                    .unwrap()
            );
        }
    }

    #[tokio::test]
    async fn reload_rejects_peer_in_desired_only_listen_family_before_runtime_mutation() {
        let initial = baseline_toml().replace(
            "listen_port = 179",
            "listen_port = 179\nlisten_addresses = [\"127.0.0.2\"]",
        );
        let desired = initial.replace(
            "listen_addresses = [\"127.0.0.2\"]",
            "listen_addresses = [\"127.0.0.2\", \"::1\"]",
        ) + "\n[[neighbors]]\naddress = \"2001:db8::2\"\nremote_asn = 65003\n";
        let (returned, tags) = drive_reloads(&initial, &desired, 2).await;

        assert!(
            returned
                .iter()
                .all(|outcome| matches!(outcome, SighupReloadOutcome::CleanNoEffect(_))),
            "pinned runtime candidate omits IPv6"
        );
        assert!(
            tags.is_empty(),
            "invalid post-pin candidate must fail before actor mutation: {tags:?}"
        );
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
    async fn reload_pins_inbound_admission_edits_to_startup_snapshot() {
        // ADR-0120: every [inbound_admission] field is restart-required
        // (the accept-path limiter is built once at startup). A SIGHUP
        // must pin the runtime snapshot back to the startup admission
        // config — but keep the operator's edit in the desired TOML.
        let initial = baseline_toml();
        let new_toml = format!(
            "{}\n[inbound_admission]\nenabled = true\nrate_per_minute = 6\n",
            baseline_toml()
        );

        let (returned, tags) = drive_reload(initial, &new_toml).await;
        let returned = returned.expect("reload should return pinned runtime config");

        assert!(
            tags.is_empty(),
            "inbound-admission-only edits are restart-required and must not reconcile peers: {tags:?}"
        );
        assert!(
            !returned.inbound_admission.enabled,
            "runtime snapshot must keep the startup (disabled) admission config"
        );
        assert!(
            returned.desired.inbound_admission.enabled,
            "desired TOML must preserve the operator's edit for restart"
        );
        assert_eq!(
            returned.desired.inbound_admission.rate_per_minute, 6,
            "desired TOML must carry the edited rate"
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
    fn listener_inbound_auth_inventory_covers_ipv6_neighbors() {
        let config = load_tier_test_toml(
            r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179
[global.telemetry]
log_format = "json"
[[neighbors]]
address = "2001:db8::2"
remote_asn = 65002
md5_password = "v6-secret"
ttl_security = true
"#,
            "inbound-auth-v6-probe",
        );
        let (md5_keys, ttl_security) = listener_inbound_auth_inventory(&config).unwrap();
        assert!(
            md5_keys
                .iter()
                .any(|key| key.peer.to_string() == "2001:db8::2"),
            "IPv6 md5_password must appear in the reload listener inventory"
        );
        assert!(
            ttl_security
                .iter()
                .any(|policy| policy.peer.to_string() == "2001:db8::2" && policy.hops.is_some()),
            "IPv6 ttl_security must appear in the reload listener inventory"
        );
    }

    #[test]
    fn listener_inbound_auth_inventory_tracks_md5_and_gtsm_changes() {
        let base = |group_auth: &str| {
            format!(
                r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179
[global.telemetry]
log_format = "json"
[peer_groups.members]
{group_auth}
[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
md5_password = "static-secret"
[[dynamic_neighbors]]
prefix = "192.0.2.0/24"
peer_group = "members"
"#
            )
        };
        let current = load_tier_test_toml(&base("md5_password = \"old\""), "inbound-auth-old");
        let desired = load_tier_test_toml(
            &base("md5_password = \"new\"\nttl_security = true"),
            "inbound-auth-new",
        );

        let current_inventory = listener_inbound_auth_inventory(&current).unwrap();
        // Identical config → identical inventory: no spurious replacement.
        assert_eq!(
            current_inventory,
            listener_inbound_auth_inventory(&current).unwrap()
        );
        let desired_inventory = listener_inbound_auth_inventory(&desired).unwrap();
        assert_ne!(current_inventory, desired_inventory);

        // The desired inventory carries the static host key, the group's
        // range prefix key, and the enforcing range GTSM selector.
        let (md5_keys, ttl_security) = desired_inventory;
        let selectors: Vec<(String, u8)> = md5_keys
            .iter()
            .map(|key| (key.peer.to_string(), key.prefix_len))
            .collect();
        assert!(selectors.contains(&("10.0.0.2".to_string(), 32)));
        assert!(selectors.contains(&("192.0.2.0".to_string(), 24)));
        assert!(
            ttl_security
                .iter()
                .any(|policy| policy.hops.is_some() && policy.prefix_len == 24)
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

        let outcome = reload_config(
            config_path.to_str().unwrap(),
            &initial,
            initial.global.telemetry.grpc_tcp.as_ref(),
            initial.global.telemetry.grpc_uds.as_ref(),
            &peer_mgr_tx,
            None,
            None,
        )
        .await;
        assert!(matches!(outcome, SighupReloadOutcome::CleanNoEffect(_)));

        assert_eq!(live.pin().generation, 1);
        assert_eq!(live.pin().data.records(), 1);
        assert!(std::sync::Arc::ptr_eq(
            &live,
            initial.policy.dataset_bindings.get("customers").unwrap()
        ));
    }

    #[tokio::test]
    async fn reload_neighbor_reconcile_failure_retains_committed_dataset_snapshot() {
        use rustbgpd_api::peer_types::{
            PeerReconcileAuthority, PeerReconcileOutcome, ReconcileFailure, ReconcileFailureKind,
        };

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
                        let _ = reply.send(PeerReconcileOutcome {
                            effects: Vec::new(),
                            failures: vec![ReconcileFailure {
                                kind: ReconcileFailureKind::Add,
                                peer: rustbgpd_api::peer_types::PeerKey::new(
                                    "192.0.2.99".parse().unwrap(),
                                    None,
                                ),
                                error: "injected add failure".to_string(),
                            }],
                            authority: PeerReconcileAuthority::Known,
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
        use rustbgpd_api::peer_types::{
            PeerReconcileAuthority, PeerReconcileOutcome, ReconcileFailure, ReconcileFailureKind,
        };

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
                    PeerManagerCommand::OwnedCatalogMutation { reply, .. } => {
                        let _ = reply.send(OwnedCatalogMutationOutcome::Success);
                    }
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
                        let result = PeerReconcileOutcome {
                            effects: Vec::new(),
                            failures: vec![ReconcileFailure {
                                kind: ReconcileFailureKind::Add,
                                peer: rustbgpd_api::peer_types::PeerKey::new(
                                    "10.0.0.99".parse().unwrap(),
                                    None,
                                ),
                                error: "simulated reconcile failure".to_string(),
                            }],
                            authority: PeerReconcileAuthority::Known,
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
        let (replace_tx, replace_rx) = mpsc::channel(1);
        let (mutation_tx, mut mutation_rx) = mpsc::channel::<ConfigMutation>(8);
        let initial = AcceptedConfigSnapshot::from_config_for_test(stale);
        let (accepted_tx, _accepted_rx) = watch::channel(initial);

        let bridge = tokio::spawn(run_config_bridge_accepted(
            event_rx,
            replace_rx,
            mutation_tx,
            accepted_tx,
        ));

        // Push the SIGHUP-style replacement first.
        let (adopted, adopted_rx) = oneshot::channel();
        replace_tx
            .send(AcceptedBridgeReplacement {
                snapshot: AcceptedConfigSnapshot::from_config_for_test(reloaded.clone()),
                adopted,
            })
            .await
            .unwrap();
        let replace_msg = mutation_rx.recv().await.expect("replacement forwarded");
        let ConfigMutation::AdoptReloadSnapshot {
            snapshot: received_replace,
            adopted: persister_ack,
        } = replace_msg
        else {
            panic!("bridge must forward replacement as AdoptReloadSnapshot");
        };
        assert!(received_replace.peer_groups.contains_key("upstream"));
        persister_ack.send(()).unwrap();
        assert!(matches!(
            adopted_rx.await.unwrap(),
            ReloadDispatch::Replied(())
        ));
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
        let _ = persist_ack.send(ConfigPersistCommitOutcome::PublishedDurable);
        assert!(
            timeout(Duration::from_secs(1), ack_rx)
                .await
                .unwrap()
                .unwrap()
                == ConfigPersistCommitOutcome::PublishedDurable,
            "FIB event ack should reflect the persister result"
        );

        let (closed_tx, closed_rx) = mpsc::channel(1);
        drop(closed_rx);
        assert_not_published!(
            persist_acknowledged(
                &closed_tx,
                Arc::clone(&received_event),
                ConfigPersistAck::immediate(oneshot::channel().0),
            )
            .await,
        );

        let (staged_tx, mut staged_rx) = mpsc::channel(1);
        let (commit, commit_rx) = oneshot::channel();
        let task = tokio::spawn(async move {
            persist_acknowledged(
                &staged_tx,
                received_event,
                ConfigPersistAck::Staged {
                    staged: oneshot::channel().0,
                    commit: commit_rx,
                },
            )
            .await
        });
        let ConfigMutation::StageConfigAck(_, stage_reply) = staged_rx.recv().await.unwrap() else {
            panic!("staged persistence must stage first")
        };
        stage_reply.send(Ok(())).unwrap();
        drop(staged_rx);
        commit.send(oneshot::channel().0).unwrap();
        assert_not_published!(task.await.unwrap());

        drop(replace_tx);
        drop(event_tx);
        timeout(Duration::from_secs(1), bridge)
            .await
            .expect("bridge should exit after both inputs close")
            .unwrap();
    }

    #[expect(
        clippy::too_many_lines,
        reason = "one authority-adoption sequence covers durable, not-published, and ambiguous"
    )]
    #[tokio::test]
    async fn config_bridge_watch_publishes_only_the_successfully_persisted_arc() {
        use rustbgpd_api::peer_types::{ConfigEvent, FibTableSnapshot};
        use tokio::time::{Duration, timeout};

        let path = unique_temp_path("bridge-accepted-watch");
        std::fs::write(&path, baseline_toml()).unwrap();
        let initial = Arc::new(AcceptedConfigSnapshot::load(&path, None).unwrap());
        std::fs::remove_file(&path).ok();
        let (event_tx, event_rx) = mpsc::channel(4);
        let (replace_tx, replace_rx) = mpsc::channel(1);
        let (mutation_tx, mut mutation_rx) = mpsc::channel(4);
        let (accepted_tx, mut accepted_rx) = watch::channel(Arc::clone(&initial));
        let bridge = tokio::spawn(run_config_bridge_accepted(
            event_rx,
            replace_rx,
            mutation_tx,
            accepted_tx,
        ));

        let event = |name: &str, ack| ConfigEvent::FibTablesReplaced {
            tables: vec![FibTableSnapshot {
                name: name.to_string(),
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
            ack: Some(ConfigPersistAck::immediate(ack)),
        };

        let (ack_tx, ack_rx) = oneshot::channel();
        event_tx.send(event("accepted", ack_tx)).await.unwrap();
        let ConfigMutation::ReplaceConfigAck(candidate, persist_ack) =
            mutation_rx.recv().await.unwrap()
        else {
            panic!("acknowledged event must carry its accepted Arc");
        };
        assert!(Arc::ptr_eq(&accepted_rx.borrow(), &initial));
        persist_ack
            .send(ConfigPersistCommitOutcome::PublishedDurable)
            .unwrap();
        assert_eq!(
            ack_rx.await.unwrap(),
            ConfigPersistCommitOutcome::PublishedDurable
        );
        timeout(Duration::from_secs(1), accepted_rx.changed())
            .await
            .unwrap()
            .unwrap();
        assert!(Arc::ptr_eq(&accepted_rx.borrow(), &candidate));

        let (failed_ack_tx, failed_ack_rx) = oneshot::channel();
        event_tx
            .send(event("rejected", failed_ack_tx))
            .await
            .unwrap();
        let ConfigMutation::ReplaceConfigAck(rejected, failed_persist_ack) =
            mutation_rx.recv().await.unwrap()
        else {
            panic!("second acknowledged event must carry its accepted Arc");
        };
        assert!(!Arc::ptr_eq(&candidate, &rejected));
        failed_persist_ack
            .send(ConfigPersistCommitOutcome::NotPublished(
                "injected".to_string(),
            ))
            .unwrap();
        assert!(matches!(
            failed_ack_rx.await.unwrap(),
            ConfigPersistCommitOutcome::NotPublished(_)
        ));
        assert!(Arc::ptr_eq(&accepted_rx.borrow(), &candidate));
        assert!(!accepted_rx.has_changed().unwrap());

        let (ambiguous_ack_tx, ambiguous_ack_rx) = oneshot::channel();
        event_tx
            .send(event("visible-candidate", ambiguous_ack_tx))
            .await
            .unwrap();
        let ConfigMutation::ReplaceConfigAck(ambiguous, ambiguous_persist_ack) =
            mutation_rx.recv().await.unwrap()
        else {
            panic!("ambiguous event must carry its candidate Arc");
        };
        ambiguous_persist_ack
            .send(ConfigPersistCommitOutcome::PublicationAmbiguous(
                "directory sync failed".to_string(),
            ))
            .unwrap();
        assert!(matches!(
            ambiguous_ack_rx.await.unwrap(),
            ConfigPersistCommitOutcome::PublicationAmbiguous(_)
        ));
        timeout(Duration::from_secs(1), accepted_rx.changed())
            .await
            .unwrap()
            .unwrap();
        assert!(Arc::ptr_eq(&accepted_rx.borrow(), &ambiguous));

        drop(replace_tx);
        drop(event_tx);
        timeout(Duration::from_secs(1), bridge)
            .await
            .unwrap()
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
        let _ = persist_ack.send(ConfigPersistCommitOutcome::PublishedDurable);
        assert!(
            timeout(Duration::from_secs(1), ack_rx)
                .await
                .unwrap()
                .unwrap()
                == ConfigPersistCommitOutcome::PublishedDurable,
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
        let stale = load_config_from_toml("bridge-static-ack-stale", baseline_toml());

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
                    ttl_security_hops: None,
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
                    send_non_transitive_extended_communities: false,
                    per_client_best: false,
                    next_hop_ownership_strict_peer: false,
                    slow_peer_threshold_pct: rustbgpd_transport::DEFAULT_SLOW_PEER_THRESHOLD_PCT,
                    slow_peer_duration: rustbgpd_transport::DEFAULT_SLOW_PEER_DURATION_SECS,
                    slow_peer_isolation: false,
                    interpret_rfc1997: true,
                    rs_control_communities: false,
                    remove_private_as: RemovePrivateAs::Disabled,
                    discard_path_attributes: std::sync::Arc::from([]),
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
        let _ = persist_ack.send(ConfigPersistCommitOutcome::PublishedDurable);
        assert!(
            timeout(Duration::from_secs(1), ack_rx)
                .await
                .unwrap()
                .unwrap()
                == ConfigPersistCommitOutcome::PublishedDurable,
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
                    ttl_security_hops: None,
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
                    send_non_transitive_extended_communities: false,
                    per_client_best: false,
                    next_hop_ownership_strict_peer: false,
                    slow_peer_threshold_pct: rustbgpd_transport::DEFAULT_SLOW_PEER_THRESHOLD_PCT,
                    slow_peer_duration: rustbgpd_transport::DEFAULT_SLOW_PEER_DURATION_SECS,
                    slow_peer_isolation: false,
                    interpret_rfc1997: true,
                    rs_control_communities: false,
                    remove_private_as: RemovePrivateAs::Disabled,
                    discard_path_attributes: std::sync::Arc::from([]),
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
        let _ = persist_ack.send(ConfigPersistCommitOutcome::NotPublished(
            "disk full".to_string(),
        ));
        assert!(matches!(
            timeout(Duration::from_secs(1), ack_rx)
                .await
                .unwrap()
                .unwrap(),
            ConfigPersistCommitOutcome::NotPublished(ref error) if error == "disk full"
        ));

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
        let _ = persist_ack.send(ConfigPersistCommitOutcome::PublishedDurable);
        assert!(
            timeout(Duration::from_secs(1), ack_rx)
                .await
                .unwrap()
                .unwrap()
                == ConfigPersistCommitOutcome::PublishedDurable,
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
        let _ = persist_ack.send(ConfigPersistCommitOutcome::NotPublished(
            "disk full".to_string(),
        ));
        assert!(matches!(
            timeout(Duration::from_secs(1), ack_rx)
                .await
                .unwrap()
                .unwrap(),
            ConfigPersistCommitOutcome::NotPublished(ref error) if error == "disk full"
        ));

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
        reload_then_persist_policy_after_desired_refresh_from(baseline_toml(), new_toml).await
    }

    async fn reload_then_persist_policy_after_desired_refresh_from(
        initial_toml: &str,
        new_toml: &str,
    ) -> (Config, Config) {
        use rustbgpd_api::peer_types::{ConfigEvent, NamedPolicyDefinition};

        let path = unique_temp_path("reload-desired-refresh");
        std::fs::write(&path, initial_toml).unwrap();
        let initial = Config::load_with_diagnostics(path.to_str().unwrap()).unwrap();
        let live_grpc_tcp = initial.global.telemetry.grpc_tcp.clone();
        let live_grpc_uds = initial.global.telemetry.grpc_uds.clone();
        let initial_accepted = AcceptedConfigSnapshot::from_config_for_test(initial.clone());

        let (event_tx, event_rx) = mpsc::channel::<ConfigEvent>(8);
        let (replace_tx, replace_rx) = mpsc::channel(1);
        let (mutation_tx, mutation_rx) = mpsc::channel::<ConfigMutation>(8);
        let persister = tokio::spawn(
            ConfigPersister::new_accepted(
                mutation_rx,
                path.clone(),
                Arc::clone(&initial_accepted),
                None,
            )
            .run(),
        );
        let (accepted_tx, _accepted_rx) = watch::channel(initial_accepted);
        let bridge = tokio::spawn(run_config_bridge_accepted(
            event_rx,
            replace_rx,
            mutation_tx,
            accepted_tx,
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

        let runtime = reloaded.runtime.clone();
        let (adopted, adopted_rx) = oneshot::channel();
        replace_tx
            .send(AcceptedBridgeReplacement {
                snapshot: Arc::clone(&reloaded.desired),
                adopted,
            })
            .await
            .unwrap();
        assert!(matches!(
            adopted_rx.await.unwrap(),
            ReloadDispatch::Replied(())
        ));

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
            !runtime.rfc8212_posture().policy_effective,
            "runtime must stay pinned to the live startup value"
        );
        assert!(
            disk.rfc8212_posture().policy_effective,
            "desired/disk snapshot must reflect the operator's opt-in"
        );
    }

    /// ADR-0119 activated cell through the SIGHUP seam: a daemon running on
    /// `config_epoch = 2` with the boolean omitted (effective `true`, source
    /// `epoch_2_default`) must stay pinned on that startup posture when the
    /// on-disk file drifts to explicit `false`. Hot-applying the drift would
    /// silently disable enforcement on every EBGP session inside a reload.
    /// Reverting the reload-time posture pin makes the runtime assertion red.
    #[tokio::test]
    async fn reload_pin_epoch_two_omission_keeps_runtime_secure_default() {
        let initial_toml = format!("config_epoch = 2\n{}", baseline_toml());
        let new_toml = format!(
            "config_epoch = 2\n{}",
            baseline_toml().replace(
                "listen_port = 179",
                "listen_port = 179\nebgp_requires_policy = false",
            )
        );
        let (runtime, disk) =
            reload_then_persist_policy_after_desired_refresh_from(&initial_toml, &new_toml).await;

        let runtime_posture = runtime.rfc8212_posture();
        assert!(
            runtime_posture.policy_effective,
            "runtime must stay pinned to the activated secure default"
        );
        assert_eq!(
            runtime_posture.policy_source,
            crate::config::Rfc8212PolicySource::Epoch2Default,
            "the pin must retain the complete startup tuple, not just the value"
        );
        assert!(
            !disk.rfc8212_posture().policy_effective,
            "desired/disk snapshot must carry the operator's explicit opt-out \
             forward for a restart to adopt"
        );
    }

    /// ADR-0119 activated cell through the runtime CRUD persistence seam: a
    /// gRPC-style mutation on an epoch-2/omitted daemon rewrites the main
    /// file canonically — explicit `config_epoch = 2` plus explicit
    /// `ebgp_requires_policy = true` — never dropping the activated cell back
    /// to omission or to a legacy epoch. Bypassing the canonical writer for
    /// the durable sink makes the raw-presence assertions red.
    #[tokio::test]
    async fn crud_persist_on_epoch_two_omission_materializes_secure_default() {
        let cell_toml = format!("config_epoch = 2\n{}", baseline_toml());
        let (runtime, disk) =
            reload_then_persist_policy_after_desired_refresh_from(&cell_toml, &cell_toml).await;

        let runtime_posture = runtime.rfc8212_posture();
        assert!(runtime_posture.policy_effective);
        assert_eq!(
            runtime_posture.policy_source,
            crate::config::Rfc8212PolicySource::Epoch2Default
        );
        assert_eq!(disk.config_epoch, Some(crate::config::ConfigEpoch::V2));
        assert_eq!(disk.global.ebgp_requires_policy, Some(true));
        assert_eq!(
            disk.rfc8212_posture().policy_source,
            crate::config::Rfc8212PolicySource::ExplicitTrue
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
