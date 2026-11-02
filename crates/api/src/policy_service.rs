//! gRPC policy service — named policy definitions and chain assignment.

use rustbgpd_rib::PeerId;
use std::net::IpAddr;
use std::time::{Duration, UNIX_EPOCH};

use rustbgpd_transport::{
    CachedOutcome, ImportExplainReply, LookupResult, RejectedRoutesReply, ResolvedMatch,
    SessionQueryOutcome,
};
use rustbgpd_wire::{Afi, Ipv4Prefix, Ipv6Prefix, Prefix, Safi};
use tokio::sync::mpsc;
use tonic::{Request, Response, Status};

use crate::actor_read::{peer_manager_operator_read, peer_manager_read, rib_manager_read};
use crate::audit::{GrpcAuditHandle, GrpcRequestSummary};
use crate::health_probe::DaemonGate;
use crate::import_roster::{
    DatasetCaptureError, ImportCaptureProgress, ImportRosterReader, capture_datasets,
    capture_import_allow_partial,
};
use rustbgpd_rib::export_roster::{ExportCaptureError, ExportRosterReader, capture_export};

use crate::peer_types::{
    ConfigEvent, EnqueuedOperatorQuery, NamedPolicyDefinition, OwnedCatalogMutation,
    OwnedCatalogMutationOutcome, PeerKey, PeerManagerCommand, PeerManagerOperatorQuery,
    PolicyStatementDefinition, ValidationPolicyDimensionSnapshot, ValidationPolicyDisposition,
    ValidationPolicyScopeSnapshot,
};
use crate::policy_helpers::{proto_statement_to_input, validate_policy_action};
use crate::proto;
use crate::runtime_config_settlement::{
    OwnedRuntimeConfigOperation, OwnedRuntimeConfigOutcome, OwnedRuntimeConfigRequestContext,
    RuntimeConfigOperationKind, RuntimeConfigSettlementPhase, RuntimeConfigSettlementWatchdog,
};
use crate::server::{
    AccessMode, ConfigMutationGateFn, OwnedCatalogDispatch, RuntimeConfigCoordinator,
    catalog_mutation_error_to_status, check_config_mutation_gate, dispatch_owned_catalog_mutation,
    fully_compensated_status, read_only_rejection, reserve_config_event_slot,
    stage_runtime_config_event_typed, with_catalog_persist_ack,
};

const OWNED_POLICY_ACTOR_TIMEOUT: Duration = Duration::from_mins(10);
/// Absolute budget shared by every backend wait of one `GetPolicyStats`.
///
/// Matches the daemon's other operator-read bounds (`PEER_MANAGER_READ_TIMEOUT`,
/// the neighbor service's `RIB_SNAPSHOT_TIMEOUT`). A shorter budget cannot
/// distinguish a wedged backend from a `.rpol` reload: an atomic export-policy
/// transition deliberately fences general RIB queries for the length of the
/// swap, so a sub-second bound turns normal bounded reload work into a hard
/// `DEADLINE_EXCEEDED` for an operator polling live counters.
const POLICY_STATS_AGGREGATE_TIMEOUT: Duration = Duration::from_secs(2);
/// Bound on `ListConditionalAdvertisements`, covering admission and reply:
/// the neighbor service's `RIB_SNAPSHOT_TIMEOUT` class for a cheap RIB read.
const CONDITIONAL_STATUS_TIMEOUT: Duration = Duration::from_secs(2);
// Match tonic's default decoded-message limit without narrowing valid requests.
const TEST_POLICY_MAX_REQUEST_BYTES: usize = 4 * 1024 * 1024;
const TEST_POLICY_MAX_REJECTED_SAMPLES: u32 = 1000;
/// Whole-chain `ComparePolicy` candidates name at most this many members.
const COMPARE_POLICY_MAX_MEMBERS: usize = 64;

/// Run one policy-stats backend send and reply within the RPC's shared
/// absolute deadline. A saturated bounded channel is part of the same budget
/// as the reply wait; no sequential stage receives a fresh timeout.
async fn policy_stats_request<T>(
    deadline: tokio::time::Instant,
    stage: &'static str,
    audit: Option<&GrpcAuditHandle>,
    request: impl std::future::Future<Output = Result<T, Status>>,
) -> Result<T, Status> {
    let started = tokio::time::Instant::now();
    let budget_ms = deadline.saturating_duration_since(started).as_millis();
    let previous = audit.and_then(GrpcAuditHandle::summary);
    let previous = previous.as_ref().map_or("", GrpcRequestSummary::as_str);
    let separator = if previous.is_empty() { "" } else { "; " };
    if let Some(audit) = audit {
        audit.set_summary(GrpcRequestSummary::new(format!(
            "{previous}{separator}stage={stage} budget_ms={budget_ms} state=waiting"
        )));
    }
    let result = if deadline <= tokio::time::Instant::now() {
        Err(Status::deadline_exceeded(
            "policy stats aggregate deadline exceeded",
        ))
    } else {
        tokio::time::timeout_at(deadline, request)
            .await
            .unwrap_or_else(|_| {
                Err(Status::deadline_exceeded(
                    "policy stats aggregate deadline exceeded",
                ))
            })
    };
    let finished = tokio::time::Instant::now();
    // Tokio polls a ready backend before its timer, including when a pending
    // request resumes after expiry. Normalize the backend observation before
    // recording its status; synchronous response shaping is outside this wait.
    let result = if deadline <= finished {
        Err(Status::deadline_exceeded(
            "policy stats aggregate deadline exceeded",
        ))
    } else {
        result
    };
    let elapsed_ms = finished.duration_since(started).as_millis();
    let rpc_elapsed_ms = finished
        .saturating_duration_since(deadline - POLICY_STATS_AGGREGATE_TIMEOUT)
        .as_millis();
    let code = result.as_ref().err().map_or(tonic::Code::Ok, Status::code);
    tracing::debug!(
        target: "policy_stats",
        stage, elapsed_ms, budget_ms, rpc_elapsed_ms, ?code, ?deadline,
        "policy stats stage completed"
    );
    // Keep the bounded stage history in this request's existing audit record,
    // including failures when debug tracing is disabled or requests overlap.
    if let Some(audit) = audit {
        audit.set_summary(GrpcRequestSummary::new(format!(
            "{previous}{separator}stage={stage} elapsed_ms={elapsed_ms} budget_ms={budget_ms} rpc_elapsed_ms={rpc_elapsed_ms} code={code:?}"
        )));
    }
    result
}

/// Append the import capture's counts to its completed audit record:
/// publications read of those selected, and waits taken (Pending
/// publications awaited and busy error-mutex retries).
fn append_import_progress(audit: &GrpcAuditHandle, progress: &ImportCaptureProgress) {
    let detail = format!(
        "publications={}/{} yields={}",
        progress.read,
        progress.selected,
        progress.yields.load(std::sync::atomic::Ordering::Relaxed),
    );
    let summary = audit.summary();
    let summary = summary.as_ref().map_or("", GrpcRequestSummary::as_str);
    audit.set_summary(GrpcRequestSummary::new(format!("{summary} {detail}")));
}

/// Map the v1-supported `AddressFamily` proto values to `(Afi, Safi)`.
/// ADR-0073 scopes `ExplainImportPolicy` to IPv4 / IPv6 unicast; anything
/// else is an explicit `invalid_argument` rather than a silent miss.
fn explain_afi_safi(afi_safi: i32) -> Result<(Afi, Safi), Status> {
    match proto::AddressFamily::try_from(afi_safi) {
        Ok(proto::AddressFamily::Ipv4Unicast) => Ok((Afi::Ipv4, Safi::Unicast)),
        Ok(proto::AddressFamily::Ipv6Unicast) => Ok((Afi::Ipv6, Safi::Unicast)),
        _ => Err(Status::invalid_argument(
            "ExplainImportPolicy v1 supports IPv4-unicast and IPv6-unicast only",
        )),
    }
}

/// Parse the request prefix string + length into a typed [`Prefix`],
/// validating it against the requested address family.
fn explain_prefix(afi: Afi, prefix: &str, prefix_length: u32) -> Result<Prefix, Status> {
    let addr: IpAddr = prefix
        .parse()
        .map_err(|e| Status::invalid_argument(format!("invalid prefix: {e}")))?;
    let len = u8::try_from(prefix_length)
        .map_err(|_| Status::invalid_argument("prefix_length out of range"))?;
    match (afi, addr) {
        (Afi::Ipv4, IpAddr::V4(v4)) if len <= 32 => Ok(Prefix::V4(Ipv4Prefix::new(v4, len))),
        (Afi::Ipv6, IpAddr::V6(v6)) if len <= 128 => Ok(Prefix::V6(Ipv6Prefix::new(v6, len))),
        _ => Err(Status::invalid_argument(
            "prefix does not match the requested address family / length",
        )),
    }
}

fn cached_outcome_to_proto(outcome: CachedOutcome) -> proto::ImportExplainOutcome {
    match outcome {
        CachedOutcome::Permit => proto::ImportExplainOutcome::Permit,
        CachedOutcome::Deny => proto::ImportExplainOutcome::Deny,
        CachedOutcome::Withdrawn => proto::ImportExplainOutcome::Withdrawn,
    }
}

fn explain_modifications_to_proto(
    modifications: &rustbgpd_policy::RouteModifications,
) -> proto::ExplainModifications {
    let (as_path_prepend_asn, as_path_prepend_count) = modifications
        .as_path_prepend
        .map_or((None, None), |(asn, count)| {
            (Some(asn), Some(u32::from(count)))
        });
    proto::ExplainModifications {
        set_local_pref: modifications.set_local_pref,
        set_med: modifications.set_med,
        set_next_hop: modifications
            .set_next_hop
            .as_ref()
            .map_or_else(String::new, |nh| match nh {
                rustbgpd_policy::NextHopAction::Self_ => "self".to_string(),
                rustbgpd_policy::NextHopAction::Specific(addr) => addr.to_string(),
            }),
        communities_add: modifications.communities_add.clone(),
        communities_remove: modifications.communities_remove.clone(),
        extended_communities_add: modifications
            .extended_communities_add
            .iter()
            .map(|ec| ec.as_u64())
            .collect(),
        extended_communities_remove: modifications
            .extended_communities_remove
            .iter()
            .map(|ec| ec.as_u64())
            .collect(),
        large_communities_add: modifications
            .large_communities_add
            .iter()
            .map(ToString::to_string)
            .collect(),
        large_communities_remove: modifications
            .large_communities_remove
            .iter()
            .map(ToString::to_string)
            .collect(),
        as_path_prepend_asn,
        as_path_prepend_count,
    }
}

/// Map one statement-level trace step into its proto form. Indices and
/// the action label are machine-stable; the rendered condition /
/// modification strings carry stable leading labels with human detail
/// (the policy crate owns that contract).
fn statement_step_to_proto(
    step: &rustbgpd_policy::StatementAttribution,
) -> proto::ImportExplainStatementStep {
    proto::ImportExplainStatementStep {
        policy_index: u32::try_from(step.policy_index).unwrap_or(u32::MAX),
        policy_name: step.policy_name.clone().unwrap_or_default(),
        default_action: step.statement_index.is_none(),
        statement_index: step
            .statement_index
            .and_then(|i| u32::try_from(i).ok())
            .unwrap_or(0),
        action: match step.action {
            rustbgpd_policy::PolicyAction::Permit => "permit".to_string(),
            rustbgpd_policy::PolicyAction::Deny => "deny".to_string(),
        },
        matched_conditions: step.matched_conditions.clone(),
        modifications: step.modifications.clone(),
        term: step.term_name.clone().unwrap_or_default(),
        term_traces: step.term_traces.clone(),
    }
}

/// Render one resolved cache entry into the proto match. The echoed
/// scope (`peer_address`, `prefix`, `prefix_length`, `afi_safi`) is
/// stamped on every match; decision-specific fields are populated only
/// for `Hit` / `Stale` (an `Evicted` / `NotSeen` entry has no recorded
/// decision to render). Statement steps arrive pre-gated from the
/// session (current-generation PERMIT / DENY hits only).
fn resolved_match_to_proto(
    peer_address: &str,
    peer: &PeerKey,
    prefix: &str,
    prefix_length: u32,
    afi_safi: i32,
    resolved: ResolvedMatch,
) -> proto::ImportExplainMatch {
    let mut m = proto::ImportExplainMatch {
        outcome: proto::ImportExplainOutcome::Unspecified as i32,
        peer_address: peer_address.to_string(),
        peer_interface: crate::peer_selector::interface_of(Some(peer)),
        prefix: prefix.to_string(),
        prefix_length,
        path_id: resolved.path_id,
        afi_safi,
        matched_policy: String::new(),
        rpki_validation: String::new(),
        aspa_validation: String::new(),
        modifications: None,
        evaluated_at_unix_ns: 0,
        policy_generation: 0,
        statements: resolved
            .statements
            .iter()
            .map(statement_step_to_proto)
            .collect(),
    };
    // `Hit` reports the recorded permit/deny/withdrawn outcome; `Stale`
    // keeps the same historical decision fields but overrides the
    // outcome to STALE so the operator knows the policy has since moved.
    let fill = |m: &mut proto::ImportExplainMatch, d: rustbgpd_transport::CachedDecision| {
        m.matched_policy = d.matched_policy.as_deref().unwrap_or_default().to_string();
        m.rpki_validation = d.rpki.to_string();
        m.aspa_validation = d.aspa.to_string();
        m.modifications = Some(explain_modifications_to_proto(&d.modifications));
        m.evaluated_at_unix_ns = d
            .evaluated_at
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|dur| i64::try_from(dur.as_nanos()).ok())
            .unwrap_or(0);
        m.policy_generation = d.policy_generation;
    };
    match resolved.result {
        LookupResult::Hit(d) => {
            m.outcome = cached_outcome_to_proto(d.outcome) as i32;
            fill(&mut m, d);
        }
        LookupResult::Stale(d) => {
            m.outcome = proto::ImportExplainOutcome::Stale as i32;
            fill(&mut m, d);
        }
        LookupResult::Evicted => m.outcome = proto::ImportExplainOutcome::Evicted as i32,
        LookupResult::NotSeen => m.outcome = proto::ImportExplainOutcome::NotSeen as i32,
    }
    m
}

fn input_statement_to_proto(statement: &PolicyStatementDefinition) -> proto::PolicyStatement {
    proto::PolicyStatement {
        action: statement.action.clone(),
        prefix: statement.prefix.clone(),
        ge: statement.ge.map(u32::from),
        le: statement.le.map(u32::from),
        match_community: statement.match_community.clone(),
        match_as_path: statement.match_as_path.clone(),
        match_neighbor_set: statement.match_neighbor_set.clone(),
        match_route_type: statement.match_route_type.clone(),
        match_evpn_route_type: statement.match_evpn_route_type.map(u32::from),
        match_as_path_length_ge: statement.match_as_path_length_ge,
        match_as_path_length_le: statement.match_as_path_length_le,
        match_local_pref_ge: statement.match_local_pref_ge,
        match_local_pref_le: statement.match_local_pref_le,
        match_med_ge: statement.match_med_ge,
        match_med_le: statement.match_med_le,
        match_next_hop: statement.match_next_hop.clone(),
        match_rpki_validation: statement.match_rpki_validation.clone(),
        match_aspa_validation: statement.match_aspa_validation.clone(),
        set_local_pref: statement.set_local_pref,
        set_med: statement.set_med,
        set_next_hop: statement.set_next_hop.clone(),
        set_community_add: statement.set_community_add.clone(),
        set_community_remove: statement.set_community_remove.clone(),
        set_as_path_prepend: statement.set_as_path_prepend.as_ref().map(|prepend| {
            proto::AsPathPrepend {
                asn: prepend.asn,
                count: u32::from(prepend.count),
            }
        }),
    }
}

fn proto_definition_to_input(
    definition: proto::PolicyDefinition,
) -> Result<NamedPolicyDefinition, Status> {
    validate_policy_action(&definition.default_action)?;
    let statements = definition
        .statements
        .into_iter()
        .map(proto_statement_to_input)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(NamedPolicyDefinition {
        default_action: definition.default_action,
        statements,
    })
}

fn input_definition_to_proto(definition: &NamedPolicyDefinition) -> proto::PolicyDefinition {
    proto::PolicyDefinition {
        default_action: definition.default_action.clone(),
        statements: definition
            .statements
            .iter()
            .map(input_statement_to_proto)
            .collect(),
    }
}

/// gRPC service for named policy CRUD and chain assignment.
pub struct PolicyService {
    access_mode: AccessMode,
    peer_mgr_tx: mpsc::Sender<PeerManagerCommand>,
    operator_tx: Option<mpsc::Sender<EnqueuedOperatorQuery>>,
    config_tx: Option<mpsc::Sender<ConfigEvent>>,
    runtime_config_lock: RuntimeConfigCoordinator,
    config_mutation_gate: Option<ConfigMutationGateFn>,
    /// RIB query channel backing `TestPolicy`'s read-only snapshot
    /// (ADR-0096 Decision 6). `None` when the service was built
    /// without it — `TestPolicy` then reports `FAILED_PRECONDITION`.
    rib_tx: Option<mpsc::Sender<rustbgpd_rib::RibUpdate>>,
    /// The peer manager's published import roster, backing `GetPolicyStats`
    /// peer validation, import counters and dataset status (ADR-0136).
    /// `None` makes `GetPolicyStats` report `FAILED_PRECONDITION`.
    import_roster: Option<ImportRosterReader>,
    /// The RIB manager's published export roster, backing `GetPolicyStats`
    /// export counters (ADR-0136). `None` makes an export read report
    /// `FAILED_PRECONDITION`.
    export_roster: Option<ExportRosterReader>,
    settlement: Option<(RuntimeConfigSettlementWatchdog, DaemonGate)>,
    owned_actor_timeout: Duration,
    /// The daemon's `[global] asn` (restart-only), which config resolution
    /// stamps into `.rpol` chain members for `prepend as self`.
    local_asn: Option<u32>,
}

impl PolicyService {
    /// Create a new policy service with the given channels and a private
    /// runtime-config lock (tests / embedded use).
    #[cfg(test)]
    #[must_use]
    pub fn new(
        access_mode: AccessMode,
        peer_mgr_tx: mpsc::Sender<PeerManagerCommand>,
        config_tx: Option<mpsc::Sender<ConfigEvent>>,
        config_mutation_gate: Option<ConfigMutationGateFn>,
    ) -> Self {
        Self::with_runtime_config_coordinator(
            access_mode,
            peer_mgr_tx,
            config_tx,
            config_mutation_gate,
            RuntimeConfigCoordinator::new(),
        )
    }

    /// Create a policy service sharing the daemon-wide runtime-config
    /// coordinator lock, so catalog mutations serialize with SIGHUP
    /// reload, neighbor / FIB-table CRUD, and config transactions.
    #[must_use]
    pub fn with_runtime_config_coordinator(
        access_mode: AccessMode,
        peer_mgr_tx: mpsc::Sender<PeerManagerCommand>,
        config_tx: Option<mpsc::Sender<ConfigEvent>>,
        config_mutation_gate: Option<ConfigMutationGateFn>,
        runtime_config_lock: RuntimeConfigCoordinator,
    ) -> Self {
        Self {
            access_mode,
            peer_mgr_tx,
            operator_tx: None,
            config_tx,
            runtime_config_lock,
            config_mutation_gate,
            rib_tx: None,
            import_roster: None,
            export_roster: None,
            settlement: None,
            owned_actor_timeout: OWNED_POLICY_ACTOR_TIMEOUT,
            local_asn: None,
        }
    }

    /// Attach the daemon's local ASN, which `ComparePolicy` stamps into
    /// candidate members as configuration resolution does.
    #[must_use]
    pub fn with_local_asn(mut self, asn: u32) -> Self {
        self.local_asn = Some(asn);
        self
    }

    /// Attach the operator query lane served at explicit actor admission points.
    #[must_use]
    pub fn with_operator_queries(mut self, tx: mpsc::Sender<EnqueuedOperatorQuery>) -> Self {
        self.operator_tx = Some(tx);
        self
    }

    /// Arm policy catalog mutations with the process-wide fail-stop owner.
    #[must_use]
    pub fn with_runtime_config_settlement(
        mut self,
        watchdog: RuntimeConfigSettlementWatchdog,
        daemon_gate: DaemonGate,
    ) -> Self {
        self.settlement = Some((watchdog, daemon_gate));
        self
    }

    /// Attach the RIB query channel that backs `TestPolicy`'s
    /// read-only route snapshot.
    #[must_use]
    pub fn with_rib_query(mut self, rib_tx: mpsc::Sender<rustbgpd_rib::RibUpdate>) -> Self {
        self.rib_tx = Some(rib_tx);
        self
    }

    /// Attach the peer manager's published import roster.
    #[must_use]
    pub fn with_import_roster(mut self, roster: ImportRosterReader) -> Self {
        self.import_roster = Some(roster);
        self
    }

    /// Attach the RIB manager's published export roster.
    #[must_use]
    pub fn with_export_roster(mut self, roster: ExportRosterReader) -> Self {
        self.export_roster = Some(roster);
        self
    }

    async fn execute_owned_policy_mutation(
        &self,
        kind: RuntimeConfigOperationKind,
        operation_name: &'static str,
        mutation: OwnedCatalogMutation,
        event: ConfigEvent,
        persist_permit: Option<mpsc::OwnedPermit<ConfigEvent>>,
    ) -> Result<(), Status> {
        let peer_mgr_tx = self.peer_mgr_tx.clone();
        let gate = self.config_mutation_gate.clone();
        let timeout = self.owned_actor_timeout;
        let settlement = self.settlement.clone();
        let daemon_gate = settlement.as_ref().map(|(_, gate)| gate.clone());
        let body = move |owned| async move {
            owned_policy_mutation_body(
                owned,
                daemon_gate,
                gate,
                operation_name,
                peer_mgr_tx,
                timeout,
                mutation,
                event,
                persist_permit,
            )
            .await
        };
        let (context, attachment) = OwnedRuntimeConfigRequestContext::unary();
        let result = if let Some((watchdog, daemon_gate)) = settlement {
            watchdog
                .execute_owned(
                    kind,
                    self.runtime_config_lock.clone(),
                    daemon_gate,
                    context.response_attached(),
                    move |operation| body(Some(operation)),
                )
                .await
        } else {
            let coordinator = self.runtime_config_lock.clone();
            tokio::spawn(async move {
                let _permit = coordinator.acquire().await?;
                match body(None).await {
                    OwnedRuntimeConfigOutcome::CleanNoEffect(result) => result,
                    OwnedRuntimeConfigOutcome::PublishedDurable(())
                    | OwnedRuntimeConfigOutcome::AcknowledgedAuthority(()) => Ok(()),
                    OwnedRuntimeConfigOutcome::Fenced { error, .. } => {
                        let _ = error;
                        std::future::pending().await
                    }
                }
            })
            .await
            .map_err(|_| Status::internal("owned policy mutation task did not complete"))?
        };
        drop(attachment);
        result
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "the owned catalog body exposes every settlement dependency"
)]
async fn owned_policy_mutation_body(
    owned: Option<OwnedRuntimeConfigOperation>,
    daemon_gate: Option<DaemonGate>,
    config_mutation_gate: Option<ConfigMutationGateFn>,
    operation_name: &'static str,
    peer_mgr_tx: mpsc::Sender<PeerManagerCommand>,
    actor_timeout: Duration,
    mutation: OwnedCatalogMutation,
    event: ConfigEvent,
    persist_permit: Option<mpsc::OwnedPermit<ConfigEvent>>,
) -> OwnedRuntimeConfigOutcome<(), Status> {
    let pre_effect_deadline = owned
        .as_ref()
        .map(OwnedRuntimeConfigOperation::pre_effect_deadline);
    if daemon_gate.is_some_and(|gate| gate.is_shutting_down()) {
        return OwnedRuntimeConfigOutcome::CleanNoEffect(Err(Status::unavailable(format!(
            "{operation_name} rejected: daemon is shutting down"
        ))));
    }
    if let Err(error) = check_config_mutation_gate(&config_mutation_gate, operation_name).await {
        return OwnedRuntimeConfigOutcome::CleanNoEffect(Err(error));
    }
    if let Some(operation) = &owned {
        operation.advance_phase(RuntimeConfigSettlementPhase::Mutating);
    }
    let staged = if let Some(permit) = persist_permit {
        match stage_runtime_config_event_typed(permit, pre_effect_deadline, |ack| {
            with_catalog_persist_ack(event, ack)
        })
        .await
        {
            Ok(staged) => Some(staged),
            Err(error) => {
                return OwnedRuntimeConfigOutcome::CleanNoEffect(Err(error.into_status()));
            }
        }
    } else {
        None
    };
    let dispatch =
        dispatch_owned_catalog_mutation(peer_mgr_tx, actor_timeout, pre_effect_deadline, mutation)
            .await;
    match dispatch {
        OwnedCatalogDispatch::NotAccepted(error) => {
            drop(staged);
            OwnedRuntimeConfigOutcome::CleanNoEffect(Err(error))
        }
        OwnedCatalogDispatch::AcceptedReplyLost(error) => OwnedRuntimeConfigOutcome::Fenced {
            error,
            reason: crate::runtime_config_settlement::RuntimeConfigFenceReason::AcknowledgementLost,
        },
        OwnedCatalogDispatch::Replied(OwnedCatalogMutationOutcome::RejectedNoEffect(error)) => {
            drop(staged);
            OwnedRuntimeConfigOutcome::CleanNoEffect(Err(catalog_mutation_error_to_status(&error)))
        }
        OwnedCatalogDispatch::Replied(OwnedCatalogMutationOutcome::FullyCompensated(error)) => {
            drop(staged);
            OwnedRuntimeConfigOutcome::CleanNoEffect(Err(fully_compensated_status(
                &catalog_mutation_error_to_status(&error),
            )))
        }
        OwnedCatalogDispatch::Replied(OwnedCatalogMutationOutcome::CompensationAmbiguous(
            error,
        )) => OwnedRuntimeConfigOutcome::Fenced {
            error: catalog_mutation_error_to_status(&error),
            reason: crate::runtime_config_settlement::RuntimeConfigFenceReason::KnownDivergence,
        },
        OwnedCatalogDispatch::Replied(OwnedCatalogMutationOutcome::Success) => {
            let Some(staged) = staged else {
                return OwnedRuntimeConfigOutcome::PublishedDurable(());
            };
            if let Some(operation) = &owned {
                operation.advance_phase(RuntimeConfigSettlementPhase::SettlingRollback);
            }
            match staged.commit_typed().await {
                Ok(()) => OwnedRuntimeConfigOutcome::PublishedDurable(()),
                Err(error) => {
                    let reason = error.fence_reason();
                    OwnedRuntimeConfigOutcome::Fenced {
                        error: error.into_status(),
                        reason,
                    }
                }
            }
        }
    }
}

#[tonic::async_trait]
impl proto::policy_service_server::PolicyService for PolicyService {
    async fn get_validation_policy_posture(
        &self,
        _request: Request<proto::GetValidationPolicyPostureRequest>,
    ) -> Result<Response<proto::GetValidationPolicyPostureResponse>, Status> {
        let snapshot = peer_manager_read(&self.peer_mgr_tx, |reply| {
            PeerManagerCommand::GetValidationPolicyPosture { reply }
        })
        .await?;
        Ok(Response::new(proto::GetValidationPolicyPostureResponse {
            scopes: snapshot
                .scopes
                .into_iter()
                .map(posture_scope_to_proto)
                .collect(),
            rpki_invalid: Some(posture_dimension_to_proto(&snapshot.rpki_invalid)),
            aspa_invalid: Some(posture_dimension_to_proto(&snapshot.aspa_invalid)),
            complete: snapshot.complete,
            omitted: snapshot.omitted,
        }))
    }

    async fn list_conditional_advertisements(
        &self,
        _request: Request<proto::ListConditionalAdvertisementsRequest>,
    ) -> Result<Response<proto::ListConditionalAdvertisementsResponse>, Status> {
        let rib_tx = self.rib_tx.as_ref().ok_or_else(|| {
            Status::failed_precondition("RIB query runtime unavailable on this listener")
        })?;
        let definitions = tokio::time::timeout(
            CONDITIONAL_STATUS_TIMEOUT,
            rib_manager_read(rib_tx, |reply| {
                rustbgpd_rib::RibUpdate::QueryConditionalAdvertisements { reply }
            }),
        )
        .await
        .map_err(|_| Status::deadline_exceeded("conditional advertisement status timed out"))??;
        Ok(Response::new(
            proto::ListConditionalAdvertisementsResponse {
                definitions: definitions
                    .into_iter()
                    .map(conditional_status_to_proto)
                    .collect(),
            },
        ))
    }

    async fn list_policies(
        &self,
        _request: Request<proto::ListPoliciesRequest>,
    ) -> Result<Response<proto::ListPoliciesResponse>, Status> {
        let policies = peer_manager_read(&self.peer_mgr_tx, |reply| {
            PeerManagerCommand::ListPolicies { reply }
        })
        .await?;
        Ok(Response::new(proto::ListPoliciesResponse {
            policies: policies
                .into_iter()
                .map(|policy| proto::NamedPolicy {
                    name: policy.name,
                    definition: Some(input_definition_to_proto(&policy.definition)),
                })
                .collect(),
        }))
    }

    async fn get_policy(
        &self,
        request: Request<proto::GetPolicyRequest>,
    ) -> Result<Response<proto::GetPolicyResponse>, Status> {
        let req = request.into_inner();
        if req.name.trim().is_empty() {
            return Err(Status::invalid_argument("name is required"));
        }
        let definition =
            peer_manager_read(&self.peer_mgr_tx, |reply| PeerManagerCommand::GetPolicy {
                name: req.name.clone(),
                reply,
            })
            .await?
            .ok_or_else(|| Status::not_found("policy not found"))?;
        Ok(Response::new(proto::GetPolicyResponse {
            name: req.name,
            definition: Some(input_definition_to_proto(&definition)),
        }))
    }

    async fn set_policy(
        &self,
        request: Request<proto::SetPolicyRequest>,
    ) -> Result<Response<proto::SetPolicyResponse>, Status> {
        if let Some(status) = read_only_rejection(self.access_mode) {
            return Err(status);
        }
        let req = request.into_inner();
        if req.name.trim().is_empty() {
            return Err(Status::invalid_argument("name is required"));
        }
        let definition = req
            .definition
            .ok_or_else(|| Status::invalid_argument("definition is required"))?;
        let definition = proto_definition_to_input(definition)?;

        let persist_permit = reserve_config_event_slot(self.config_tx.clone()).await?;
        let name = req.name;
        self.execute_owned_policy_mutation(
            RuntimeConfigOperationKind::PolicySet,
            "PolicyService.SetPolicy",
            OwnedCatalogMutation::SetPolicy {
                name: name.clone(),
                definition: Box::new(definition.clone()),
            },
            ConfigEvent::SetPolicy {
                name,
                definition,
                ack: None,
            },
            persist_permit,
        )
        .await?;

        Ok(Response::new(proto::SetPolicyResponse {}))
    }

    async fn delete_policy(
        &self,
        request: Request<proto::DeletePolicyRequest>,
    ) -> Result<Response<proto::DeletePolicyResponse>, Status> {
        if let Some(status) = read_only_rejection(self.access_mode) {
            return Err(status);
        }
        let req = request.into_inner();
        if req.name.trim().is_empty() {
            return Err(Status::invalid_argument("name is required"));
        }

        let persist_permit = reserve_config_event_slot(self.config_tx.clone()).await?;
        let name = req.name;
        self.execute_owned_policy_mutation(
            RuntimeConfigOperationKind::PolicyDelete,
            "PolicyService.DeletePolicy",
            OwnedCatalogMutation::DeletePolicy { name: name.clone() },
            ConfigEvent::DeletePolicy { name, ack: None },
            persist_permit,
        )
        .await?;

        Ok(Response::new(proto::DeletePolicyResponse {}))
    }

    async fn list_neighbor_sets(
        &self,
        _request: Request<proto::ListNeighborSetsRequest>,
    ) -> Result<Response<proto::ListNeighborSetsResponse>, Status> {
        let neighbor_sets = peer_manager_read(&self.peer_mgr_tx, |reply| {
            PeerManagerCommand::ListNeighborSets { reply }
        })
        .await?;
        Ok(Response::new(proto::ListNeighborSetsResponse {
            neighbor_sets: neighbor_sets
                .into_iter()
                .map(|neighbor_set| proto::NamedNeighborSet {
                    name: neighbor_set.name,
                    definition: Some(proto::NeighborSetDefinition {
                        addresses: neighbor_set.definition.addresses,
                        remote_asns: neighbor_set.definition.remote_asns,
                        peer_groups: neighbor_set.definition.peer_groups,
                    }),
                })
                .collect(),
        }))
    }

    async fn get_neighbor_set(
        &self,
        request: Request<proto::GetNeighborSetRequest>,
    ) -> Result<Response<proto::GetNeighborSetResponse>, Status> {
        let req = request.into_inner();
        if req.name.trim().is_empty() {
            return Err(Status::invalid_argument("name is required"));
        }
        let definition = peer_manager_read(&self.peer_mgr_tx, |reply| {
            PeerManagerCommand::GetNeighborSet {
                name: req.name.clone(),
                reply,
            }
        })
        .await?
        .ok_or_else(|| Status::not_found("neighbor set not found"))?;
        Ok(Response::new(proto::GetNeighborSetResponse {
            name: req.name,
            definition: Some(proto::NeighborSetDefinition {
                addresses: definition.addresses,
                remote_asns: definition.remote_asns,
                peer_groups: definition.peer_groups,
            }),
        }))
    }

    async fn set_neighbor_set(
        &self,
        request: Request<proto::SetNeighborSetRequest>,
    ) -> Result<Response<proto::SetNeighborSetResponse>, Status> {
        if let Some(status) = read_only_rejection(self.access_mode) {
            return Err(status);
        }
        let req = request.into_inner();
        if req.name.trim().is_empty() {
            return Err(Status::invalid_argument("name is required"));
        }
        let definition = req
            .definition
            .ok_or_else(|| Status::invalid_argument("definition is required"))?;
        let definition = crate::peer_types::NeighborSetDefinition {
            addresses: definition.addresses,
            remote_asns: definition.remote_asns,
            peer_groups: definition.peer_groups,
        };

        let persist_permit = reserve_config_event_slot(self.config_tx.clone()).await?;
        let name = req.name;
        self.execute_owned_policy_mutation(
            RuntimeConfigOperationKind::NeighborSetSet,
            "PolicyService.SetNeighborSet",
            OwnedCatalogMutation::SetNeighborSet {
                name: name.clone(),
                definition: definition.clone(),
            },
            ConfigEvent::SetNeighborSet {
                name,
                definition,
                ack: None,
            },
            persist_permit,
        )
        .await?;

        Ok(Response::new(proto::SetNeighborSetResponse {}))
    }

    async fn delete_neighbor_set(
        &self,
        request: Request<proto::DeleteNeighborSetRequest>,
    ) -> Result<Response<proto::DeleteNeighborSetResponse>, Status> {
        if let Some(status) = read_only_rejection(self.access_mode) {
            return Err(status);
        }
        let req = request.into_inner();
        if req.name.trim().is_empty() {
            return Err(Status::invalid_argument("name is required"));
        }

        let persist_permit = reserve_config_event_slot(self.config_tx.clone()).await?;
        let name = req.name;
        self.execute_owned_policy_mutation(
            RuntimeConfigOperationKind::NeighborSetDelete,
            "PolicyService.DeleteNeighborSet",
            OwnedCatalogMutation::DeleteNeighborSet { name: name.clone() },
            ConfigEvent::DeleteNeighborSet { name, ack: None },
            persist_permit,
        )
        .await?;

        Ok(Response::new(proto::DeleteNeighborSetResponse {}))
    }

    async fn get_global_policy_chains(
        &self,
        _request: Request<proto::GetGlobalPolicyChainsRequest>,
    ) -> Result<Response<proto::GlobalPolicyChains>, Status> {
        let chains = peer_manager_read(&self.peer_mgr_tx, |reply| {
            PeerManagerCommand::GetGlobalPolicyChains { reply }
        })
        .await?;
        Ok(Response::new(proto::GlobalPolicyChains {
            import_policy_names: chains.import_policy_names,
            export_policy_names: chains.export_policy_names,
        }))
    }

    async fn set_global_import_chain(
        &self,
        request: Request<proto::SetGlobalImportChainRequest>,
    ) -> Result<Response<proto::SetGlobalImportChainResponse>, Status> {
        if let Some(status) = read_only_rejection(self.access_mode) {
            return Err(status);
        }
        let req = request.into_inner();
        let persist_permit = reserve_config_event_slot(self.config_tx.clone()).await?;
        let policy_names = req.policy_names;
        self.execute_owned_policy_mutation(
            RuntimeConfigOperationKind::GlobalImportChainSet,
            "PolicyService.SetGlobalImportChain",
            OwnedCatalogMutation::SetGlobalImportChain {
                policy_names: policy_names.clone(),
            },
            ConfigEvent::SetGlobalImportChain {
                policy_names,
                ack: None,
            },
            persist_permit,
        )
        .await?;

        Ok(Response::new(proto::SetGlobalImportChainResponse {}))
    }

    async fn set_global_export_chain(
        &self,
        request: Request<proto::SetGlobalExportChainRequest>,
    ) -> Result<Response<proto::SetGlobalExportChainResponse>, Status> {
        if let Some(status) = read_only_rejection(self.access_mode) {
            return Err(status);
        }
        let req = request.into_inner();
        let persist_permit = reserve_config_event_slot(self.config_tx.clone()).await?;
        let policy_names = req.policy_names;
        self.execute_owned_policy_mutation(
            RuntimeConfigOperationKind::GlobalExportChainSet,
            "PolicyService.SetGlobalExportChain",
            OwnedCatalogMutation::SetGlobalExportChain {
                policy_names: policy_names.clone(),
            },
            ConfigEvent::SetGlobalExportChain {
                policy_names,
                ack: None,
            },
            persist_permit,
        )
        .await?;

        Ok(Response::new(proto::SetGlobalExportChainResponse {}))
    }

    async fn clear_global_import_chain(
        &self,
        _request: Request<proto::ClearGlobalImportChainRequest>,
    ) -> Result<Response<proto::ClearGlobalImportChainResponse>, Status> {
        if let Some(status) = read_only_rejection(self.access_mode) {
            return Err(status);
        }
        let persist_permit = reserve_config_event_slot(self.config_tx.clone()).await?;
        self.execute_owned_policy_mutation(
            RuntimeConfigOperationKind::GlobalImportChainClear,
            "PolicyService.ClearGlobalImportChain",
            OwnedCatalogMutation::ClearGlobalImportChain,
            ConfigEvent::ClearGlobalImportChain { ack: None },
            persist_permit,
        )
        .await?;

        Ok(Response::new(proto::ClearGlobalImportChainResponse {}))
    }

    async fn clear_global_export_chain(
        &self,
        _request: Request<proto::ClearGlobalExportChainRequest>,
    ) -> Result<Response<proto::ClearGlobalExportChainResponse>, Status> {
        if let Some(status) = read_only_rejection(self.access_mode) {
            return Err(status);
        }
        let persist_permit = reserve_config_event_slot(self.config_tx.clone()).await?;
        self.execute_owned_policy_mutation(
            RuntimeConfigOperationKind::GlobalExportChainClear,
            "PolicyService.ClearGlobalExportChain",
            OwnedCatalogMutation::ClearGlobalExportChain,
            ConfigEvent::ClearGlobalExportChain { ack: None },
            persist_permit,
        )
        .await?;

        Ok(Response::new(proto::ClearGlobalExportChainResponse {}))
    }

    async fn get_neighbor_policy_chains(
        &self,
        request: Request<proto::GetNeighborPolicyChainsRequest>,
    ) -> Result<Response<proto::NeighborPolicyChains>, Status> {
        let req = request.into_inner();
        // The peer manager matches the scope against its own configuration.
        let peer = crate::peer_selector::require_neighbor(
            "address",
            &req.address,
            "",
            self.import_roster.as_ref(),
        )?;
        // Capture before the peer-manager read; registration may finish while it waits.
        let initial_roster_pending = self
            .settlement
            .as_ref()
            .is_some_and(|(_, gate)| gate.initial_roster_pending());
        let chains = peer_manager_read(&self.peer_mgr_tx, |reply| {
            PeerManagerCommand::GetNeighborPolicyChains { peer, reply }
        })
        .await?
        .ok_or_else(|| {
            if initial_roster_pending {
                Status::unavailable("initial configured-peer roster not installed")
            } else {
                Status::not_found("neighbor not found")
            }
        })?;
        Ok(Response::new(proto::NeighborPolicyChains {
            address: req.address,
            import_policy_names: chains.import_policy_names,
            export_policy_names: chains.export_policy_names,
        }))
    }

    async fn set_neighbor_import_chain(
        &self,
        request: Request<proto::SetNeighborImportChainRequest>,
    ) -> Result<Response<proto::SetNeighborImportChainResponse>, Status> {
        if let Some(status) = read_only_rejection(self.access_mode) {
            return Err(status);
        }
        let req = request.into_inner();
        let key = crate::peer_selector::require_neighbor(
            "address",
            &req.address,
            "",
            self.import_roster.as_ref(),
        )?;
        let (address, interface) = (key.address, key.interface);
        let persist_permit = reserve_config_event_slot(self.config_tx.clone()).await?;
        let policy_names = req.policy_names;
        self.execute_owned_policy_mutation(
            RuntimeConfigOperationKind::NeighborImportChainSet,
            "PolicyService.SetNeighborImportChain",
            OwnedCatalogMutation::SetNeighborImportChain {
                address,
                interface: interface.clone(),
                policy_names: policy_names.clone(),
            },
            ConfigEvent::SetNeighborImportChain {
                address,
                interface,
                policy_names,
                ack: None,
            },
            persist_permit,
        )
        .await?;

        Ok(Response::new(proto::SetNeighborImportChainResponse {}))
    }

    async fn set_neighbor_export_chain(
        &self,
        request: Request<proto::SetNeighborExportChainRequest>,
    ) -> Result<Response<proto::SetNeighborExportChainResponse>, Status> {
        if let Some(status) = read_only_rejection(self.access_mode) {
            return Err(status);
        }
        let req = request.into_inner();
        let key = crate::peer_selector::require_neighbor(
            "address",
            &req.address,
            "",
            self.import_roster.as_ref(),
        )?;
        let (address, interface) = (key.address, key.interface);
        let persist_permit = reserve_config_event_slot(self.config_tx.clone()).await?;
        let policy_names = req.policy_names;
        self.execute_owned_policy_mutation(
            RuntimeConfigOperationKind::NeighborExportChainSet,
            "PolicyService.SetNeighborExportChain",
            OwnedCatalogMutation::SetNeighborExportChain {
                address,
                interface: interface.clone(),
                policy_names: policy_names.clone(),
            },
            ConfigEvent::SetNeighborExportChain {
                address,
                interface,
                policy_names,
                ack: None,
            },
            persist_permit,
        )
        .await?;

        Ok(Response::new(proto::SetNeighborExportChainResponse {}))
    }

    async fn clear_neighbor_import_chain(
        &self,
        request: Request<proto::ClearNeighborImportChainRequest>,
    ) -> Result<Response<proto::ClearNeighborImportChainResponse>, Status> {
        if let Some(status) = read_only_rejection(self.access_mode) {
            return Err(status);
        }
        let req = request.into_inner();
        let key = crate::peer_selector::require_neighbor(
            "address",
            &req.address,
            "",
            self.import_roster.as_ref(),
        )?;
        let (address, interface) = (key.address, key.interface);
        let persist_permit = reserve_config_event_slot(self.config_tx.clone()).await?;
        self.execute_owned_policy_mutation(
            RuntimeConfigOperationKind::NeighborImportChainClear,
            "PolicyService.ClearNeighborImportChain",
            OwnedCatalogMutation::ClearNeighborImportChain {
                address,
                interface: interface.clone(),
            },
            ConfigEvent::ClearNeighborImportChain {
                address,
                interface,
                ack: None,
            },
            persist_permit,
        )
        .await?;

        Ok(Response::new(proto::ClearNeighborImportChainResponse {}))
    }

    async fn clear_neighbor_export_chain(
        &self,
        request: Request<proto::ClearNeighborExportChainRequest>,
    ) -> Result<Response<proto::ClearNeighborExportChainResponse>, Status> {
        if let Some(status) = read_only_rejection(self.access_mode) {
            return Err(status);
        }
        let req = request.into_inner();
        let key = crate::peer_selector::require_neighbor(
            "address",
            &req.address,
            "",
            self.import_roster.as_ref(),
        )?;
        let (address, interface) = (key.address, key.interface);
        let persist_permit = reserve_config_event_slot(self.config_tx.clone()).await?;
        self.execute_owned_policy_mutation(
            RuntimeConfigOperationKind::NeighborExportChainClear,
            "PolicyService.ClearNeighborExportChain",
            OwnedCatalogMutation::ClearNeighborExportChain {
                address,
                interface: interface.clone(),
            },
            ConfigEvent::ClearNeighborExportChain {
                address,
                interface,
                ack: None,
            },
            persist_permit,
        )
        .await?;

        Ok(Response::new(proto::ClearNeighborExportChainResponse {}))
    }

    async fn explain_import_policy(
        &self,
        request: Request<proto::ExplainImportPolicyRequest>,
    ) -> Result<Response<proto::ExplainImportPolicyResponse>, Status> {
        let req = request.into_inner();
        let peer = crate::peer_selector::require_neighbor(
            "peer_address",
            &req.peer_address,
            "",
            self.import_roster.as_ref(),
        )?;
        let address = peer.address;
        let echo = crate::peer_selector::address_echo(&req.peer_address, &peer);
        let (afi, safi) = explain_afi_safi(req.afi_safi)?;
        let prefix = explain_prefix(afi, &req.prefix, req.prefix_length)?;

        let reply = peer_manager_read(&self.peer_mgr_tx, |reply| {
            PeerManagerCommand::ExplainImportPolicy {
                peer: peer.clone(),
                afi,
                safi,
                prefix,
                path_id: req.path_id,
                reply,
            }
        })
        .await?
        .ok_or_else(|| Status::not_found(format!("neighbor {peer} not found")))?;
        let reply: Option<ImportExplainReply> = match reply {
            SessionQueryOutcome::Reply(Ok(reply)) => Some(reply),
            SessionQueryOutcome::Reply(Err(_)) => {
                return Err(Status::resource_exhausted(
                    "import-policy explain has more than 4096 paths; specify --path-id",
                ));
            }
            SessionQueryOutcome::SessionGone => None,
            SessionQueryOutcome::TimedOut => {
                return Err(Status::deadline_exceeded(format!(
                    "peer {address} did not answer the import-policy explain query in time"
                )));
            }
        };

        // LAN-320 tri-state: the operator always gets a definite answer,
        // and it is the *honest* one. `None` (no live session for the
        // address) renders as NO_SESSION; a live session whose cache
        // never records decisions renders as CACHE_DISABLED; only an
        // enabled cache with no record is a genuine NOT_SEEN.
        let no_session = reply.is_none();
        let cache_enabled = reply.as_ref().is_some_and(|r| r.cache_enabled);
        let (cache_size, evictions_since_reset) = match &reply {
            Some(r) if r.cache_enabled => (
                Some(u64::try_from(r.cache_size).unwrap_or(u64::MAX)),
                Some(r.evictions_since_reset),
            ),
            _ => (None, None),
        };
        let (current_generation, mut matches) = match reply {
            Some(r) => {
                let proto_matches: Vec<proto::ImportExplainMatch> = r
                    .matches
                    .into_iter()
                    .map(|resolved| {
                        resolved_match_to_proto(
                            &echo,
                            &peer,
                            &req.prefix,
                            req.prefix_length,
                            req.afi_safi,
                            resolved,
                        )
                    })
                    .collect();
                (r.current_generation, proto_matches)
            }
            None => (0, Vec::new()),
        };
        if matches.is_empty() {
            let outcome = if no_session {
                proto::ImportExplainOutcome::NoSession
            } else if cache_enabled {
                proto::ImportExplainOutcome::NotSeen
            } else {
                proto::ImportExplainOutcome::CacheDisabled
            };
            // Same synthetic empty-field shape as NOT_SEEN, differing
            // only in the outcome value.
            let mut synthetic = resolved_match_to_proto(
                &echo,
                &peer,
                &req.prefix,
                req.prefix_length,
                req.afi_safi,
                ResolvedMatch {
                    path_id: req.path_id.unwrap_or(0),
                    result: LookupResult::NotSeen,
                    statements: Vec::new(),
                },
            );
            synthetic.outcome = outcome as i32;
            matches.push(synthetic);
        }

        Ok(Response::new(proto::ExplainImportPolicyResponse {
            peer_address: echo,
            peer_interface: crate::peer_selector::interface_of(Some(&peer)),
            prefix: req.prefix,
            prefix_length: req.prefix_length,
            afi_safi: req.afi_safi,
            current_policy_generation: current_generation,
            matches,
            cache_size,
            evictions_since_reset,
        }))
    }

    async fn list_rejected_routes(
        &self,
        request: Request<proto::ListRejectedRoutesRequest>,
    ) -> Result<Response<proto::ListRejectedRoutesResponse>, Status> {
        let req = request.into_inner();
        let peer = crate::peer_selector::require_neighbor(
            "peer_address",
            &req.peer_address,
            "",
            self.import_roster.as_ref(),
        )?;
        let address = peer.address;

        let reply = peer_manager_read(&self.peer_mgr_tx, |reply| {
            PeerManagerCommand::ListRejectedRoutes {
                peer: peer.clone(),
                reply,
            }
        })
        .await?
        .ok_or_else(|| Status::not_found(format!("neighbor {peer} not found")))?;
        let reply: Option<RejectedRoutesReply> = match reply {
            SessionQueryOutcome::Reply(reply) => Some(reply),
            SessionQueryOutcome::SessionGone => None,
            SessionQueryOutcome::TimedOut => {
                return Err(Status::deadline_exceeded(format!(
                    "peer {address} did not answer the rejected-route query in time"
                )));
            }
        };

        // LAN-472: no live session means the session-local retention
        // store is gone — honestly distinct from "nothing rejected",
        // so it is an error, not an empty listing.
        let Some(reply) = reply else {
            return Err(Status::not_found(format!(
                "no live session for peer {address}"
            )));
        };

        let routes = reply
            .entries
            .into_iter()
            .map(|(key, mut entry)| {
                let (prefix, prefix_length) = match key.prefix {
                    Prefix::V4(p) => (p.addr.to_string(), u32::from(p.len)),
                    Prefix::V6(p) => (p.addr.to_string(), u32::from(p.len)),
                };
                let afi_safi = match (key.afi, key.safi) {
                    (Afi::Ipv4, Safi::Unicast) => proto::AddressFamily::Ipv4Unicast,
                    (Afi::Ipv6, Safi::Unicast) => proto::AddressFamily::Ipv6Unicast,
                    _ => proto::AddressFamily::Unspecified,
                } as i32;
                proto::RejectedRoute {
                    prefix,
                    prefix_length,
                    path_id: key.path_id,
                    afi_safi,
                    reason: entry.reason.as_str().to_string(),
                    reason_detail: entry.take_rendered_reason_detail(),
                    next_hop: entry.next_hop.map(|nh| nh.to_string()).unwrap_or_default(),
                    as_path: entry.as_path,
                    communities: entry.communities,
                    communities_dropped: entry.communities_dropped,
                    large_communities: entry
                        .large_communities
                        .iter()
                        .map(ToString::to_string)
                        .collect(),
                    large_communities_dropped: entry.large_communities_dropped,
                    rpki_validation: entry.rpki.to_string(),
                    aspa_validation: entry.aspa.to_string(),
                    rejected_at_unix_ns: entry
                        .rejected_at
                        .duration_since(UNIX_EPOCH)
                        .ok()
                        .and_then(|dur| i64::try_from(dur.as_nanos()).ok())
                        .unwrap_or(0),
                }
            })
            .collect();

        Ok(Response::new(proto::ListRejectedRoutesResponse {
            peer_address: crate::peer_selector::address_echo(&req.peer_address, &peer),
            peer_interface: crate::peer_selector::interface_of(Some(&peer)),
            retention_enabled: reply.enabled,
            capacity: u32::try_from(reply.capacity).unwrap_or(u32::MAX),
            routes,
            evictions_since_reset: Some(reply.evictions_since_reset),
        }))
    }

    #[expect(
        clippy::too_many_lines,
        reason = "linear request-validate, compile, snapshot, evaluate pipeline; splitting would scatter the dry-run contract"
    )]
    async fn test_policy(
        &self,
        request: Request<proto::TestPolicyRequest>,
    ) -> Result<Response<proto::TestPolicyResponse>, Status> {
        use prost::Message;
        use rustbgpd_policy::rpol::RpolFile;
        use rustbgpd_policy::sets::SetStore;
        use rustbgpd_rib::{RouteQueryScope, route_query_key_in};

        let req = request.into_inner();
        if req.encoded_len() > TEST_POLICY_MAX_REQUEST_BYTES {
            return Err(Status::invalid_argument(
                "TestPolicy candidate input exceeds the request size limit",
            ));
        }
        if req.show_rejected > TEST_POLICY_MAX_REJECTED_SAMPLES {
            return Err(Status::invalid_argument(format!(
                "show_rejected exceeds {TEST_POLICY_MAX_REJECTED_SAMPLES}"
            )));
        }
        if req.datasets.len() > rustbgpd_policy::datasets::MAX_UNIT_DATASETS {
            return Err(Status::invalid_argument("too many candidate datasets"));
        }
        let import = match req.direction.as_str() {
            "import" => true,
            "export" => false,
            other => {
                return Err(Status::invalid_argument(format!(
                    "direction must be \"import\" or \"export\", got {other:?}"
                )));
            }
        };
        let family_filter = match proto::AddressFamily::try_from(req.afi_safi) {
            Ok(proto::AddressFamily::Unspecified) => None,
            Ok(proto::AddressFamily::Ipv4Unicast) => Some(true),
            Ok(proto::AddressFamily::Ipv6Unicast) => Some(false),
            _ => {
                return Err(Status::invalid_argument(
                    "TestPolicy v1 supports IPv4-unicast and IPv6-unicast only",
                ));
            }
        };
        let peer_key = crate::peer_selector::parse_neighbor(
            "peer",
            &req.peer,
            "",
            self.import_roster.as_ref(),
        )?;

        // Compile the candidate source server-side. Diagnostics are a
        // successful RPC with compiled=false — the dry run's answer.
        let file = match RpolFile::parse(&req.rpol_source) {
            Ok(file) => file,
            Err(diagnostics) => {
                return Ok(Response::new(proto::TestPolicyResponse {
                    compiled: false,
                    diagnostics: diagnostics.render("candidate.rpol", &req.rpol_source, false),
                    ..Default::default()
                }));
            }
        };
        let (base, args) = candidate_call(&file, &req.policy)?;
        let bindings = bind_candidate_datasets(&file, &req.datasets)?;
        let chain = compile_candidate(&file, base, &args, &mut SetStore::new(), &bindings, false)?;

        // Start the version-fenced route walk before reading peer context.
        // Import evaluates Adj-RIB-In (optionally one peer's); export
        // evaluates Loc-RIB best routes.
        let rib_tx = self.rib_tx.as_ref().ok_or_else(|| {
            Status::failed_precondition("route snapshot runtime unavailable on this listener")
        })?;
        let query_scope = if import {
            RouteQueryScope::Received {
                peer: peer_key.as_ref().map(|key| {
                    crate::peer_selector::rib_peer(
                        self.import_roster.as_ref(),
                        key.address,
                        key.interface.as_deref(),
                    )
                }),
            }
        } else {
            RouteQueryScope::Best
        };
        let row_scope = if import { peer_key.as_ref() } else { None };
        let mut page = query_test_policy_page(rib_tx, query_scope, None, None).await?;
        require_row_scope(row_scope, &page.routes)?;
        let snapshot_version = page.version;

        // Peer context (ASN / peer-group) so guards on peer.* fields
        // see real values.
        let peer_context = dry_run_peer_context(
            &self.peer_mgr_tx,
            self.operator_tx.as_ref(),
            peer_key.as_ref(),
        )
        .await?;

        let scope = TestPolicyScope {
            import,
            target_peer: peer_key.clone(),
            family_filter,
            limit: req.limit as usize,
            show_changes: req.show_changes as usize,
            show_rejected: req.show_rejected as usize,
        };
        let mut hits = chain.zero_term_hits();
        let mut response = proto::TestPolicyResponse {
            compiled: true,
            ..Default::default()
        };
        loop {
            run_test_policy_page(
                &chain,
                &page,
                &scope,
                &peer_context,
                &mut response,
                &mut hits,
            );
            if (scope.limit != 0 && response.routes_evaluated >= req.limit.into()) || !page.has_more
            {
                break;
            }
            let after = page
                .routes
                .last()
                .map(|route| route_query_key_in(route, &page.peer_scope))
                .ok_or_else(|| {
                    Status::unavailable("route pagination returned an empty continuation page")
                })?;
            drop(page);
            page = query_test_policy_page(rib_tx, query_scope, Some(after), Some(snapshot_version))
                .await?;
            require_row_scope(row_scope, &page.routes)?;
        }
        response.term_hits = render_test_policy_term_hits(&chain, &hits);
        Ok(Response::new(response))
    }

    #[expect(
        clippy::too_many_lines,
        reason = "linear validate, compile, baseline, splice, evaluate pipeline mirroring TestPolicy"
    )]
    async fn compare_policy(
        &self,
        request: Request<proto::ComparePolicyRequest>,
    ) -> Result<Response<proto::ComparePolicyResponse>, Status> {
        use prost::Message;
        use rustbgpd_policy::rpol::RpolFile;
        use rustbgpd_policy::sets::SetStore;
        use rustbgpd_rib::{RibUpdate, RouteQueryScope, route_query_key_in};

        let req = request.into_inner();
        if req.encoded_len() > TEST_POLICY_MAX_REQUEST_BYTES {
            return Err(Status::invalid_argument(
                "ComparePolicy candidate input exceeds the request size limit",
            ));
        }
        if req.max_samples > TEST_POLICY_MAX_REJECTED_SAMPLES {
            return Err(Status::invalid_argument(format!(
                "max_samples exceeds {TEST_POLICY_MAX_REJECTED_SAMPLES}"
            )));
        }
        if req.datasets.len() > rustbgpd_policy::datasets::MAX_UNIT_DATASETS {
            return Err(Status::invalid_argument("too many candidate datasets"));
        }
        if req.policies.is_empty() || req.policies.len() > COMPARE_POLICY_MAX_MEMBERS {
            return Err(Status::invalid_argument(format!(
                "policies must name 1 to {COMPARE_POLICY_MAX_MEMBERS} candidate members"
            )));
        }
        if !req.replace_member.is_empty() && req.policies.len() != 1 {
            return Err(Status::invalid_argument(
                "replace_member takes exactly one candidate policy",
            ));
        }
        let family_filter = match proto::AddressFamily::try_from(req.afi_safi) {
            Ok(proto::AddressFamily::Unspecified) => None,
            Ok(proto::AddressFamily::Ipv4Unicast) => Some(true),
            Ok(proto::AddressFamily::Ipv6Unicast) => Some(false),
            _ => {
                return Err(Status::invalid_argument(
                    "ComparePolicy supports IPv4-unicast and IPv6-unicast only",
                ));
            }
        };
        let target_key = crate::peer_selector::require_neighbor(
            "peer",
            &req.peer,
            "",
            self.import_roster.as_ref(),
        )?;
        let target = crate::peer_selector::rib_peer(
            self.import_roster.as_ref(),
            target_key.address,
            target_key.interface.as_deref(),
        );

        let file = match RpolFile::parse(&req.rpol_source) {
            Ok(file) => file,
            Err(diagnostics) => {
                return Ok(Response::new(proto::ComparePolicyResponse {
                    compiled: false,
                    diagnostics: diagnostics.render("candidate.rpol", &req.rpol_source, false),
                    ..Default::default()
                }));
            }
        };
        let calls = req
            .policies
            .iter()
            .map(|call| candidate_call(&file, call))
            .collect::<Result<Vec<_>, _>>()?;
        let bindings = bind_candidate_datasets(&file, &req.datasets)?;
        let mut store = SetStore::new();
        // The structural bound configuration resolution enforces, charged as
        // each member is retained (installed members join it below).
        let mut budget = rustbgpd_policy::compile::ChainNodeBudget::default();
        let mut charge = |policy: &rustbgpd_policy::ir::CompiledPolicy| {
            budget
                .add_policy(policy)
                .map_err(|reason| Status::invalid_argument(format!("candidate chain: {reason}")))
        };
        let mut compiled =
            compile_compare_candidates(&file, &calls, &bindings, &mut store, &mut charge)?;

        // The baseline is the chain the live distribution path evaluates
        // for this peer, read before the walk starts.
        let rib_tx = self.rib_tx.as_ref().ok_or_else(|| {
            Status::failed_precondition("route snapshot runtime unavailable on this listener")
        })?;
        let installed = rib_manager_read(rib_tx, |reply| RibUpdate::QueryInstalledExportChain {
            peer: target,
            reply,
        })
        .await?
        .ok_or_else(|| {
            Status::failed_precondition(format!(
                "peer {target} has no live outbound registration; its export chain is installed per session"
            ))
        })?;
        // The chain belongs to the registered session's neighbor, which a
        // reload may have moved to another interface since the selector was
        // parsed.
        if installed.peer_interface.as_deref() != target_key.interface.as_deref() {
            return Err(Status::not_found(format!(
                "neighbor {target_key} not found"
            )));
        }
        let installed = installed.chain;
        let local_asn = self
            .local_asn
            .or_else(|| installed.as_ref().and_then(|chain| chain.local_asn));
        for chain in &mut compiled {
            chain.local_asn = local_asn;
        }
        let candidate = if req.replace_member.is_empty() {
            let members: Vec<_> = req
                .policies
                .iter()
                .zip(&compiled)
                .flat_map(|(call, chain)| {
                    (0..chain.policies.len())
                        .map(move |index| (Some(std::sync::Arc::from(call.as_str())), chain, index))
                })
                .collect();
            rustbgpd_policy::compile::splice_compiled(&members)
        } else {
            let installed = installed.as_deref().ok_or_else(|| {
                Status::failed_precondition(format!(
                    "peer {target} has no installed export chain to replace a member of"
                ))
            })?;
            let names = chain_member_names(installed);
            let mut positions = names
                .iter()
                .enumerate()
                .filter(|(_, name)| **name == req.replace_member)
                .map(|(index, _)| index);
            let (Some(replaced), None) = (positions.next(), positions.next()) else {
                return Err(Status::invalid_argument(format!(
                    "replace_member {:?} must name exactly one installed member (installed: {names:?})",
                    req.replace_member
                )));
            };
            // Retained members are spliced by index from the borrowed
            // installed chain, never copied into per-member donors.
            let replacement = &compiled[0];
            let mut members = Vec::with_capacity(installed.policies.len());
            for (index, policy) in installed.policies.iter().enumerate() {
                if index == replaced {
                    members.extend((0..replacement.policies.len()).map(|candidate_index| {
                        (
                            Some(std::sync::Arc::from(req.policies[0].as_str())),
                            replacement,
                            candidate_index,
                        )
                    }));
                } else {
                    charge(policy)?;
                    members.push((policy.name.clone(), installed, index));
                }
            }
            rustbgpd_policy::compile::splice_compiled(&members)
        };
        // A walk pins at most this many dataset slots; a probe of an unpinned
        // slot would fail closed and read as a rejection.
        if candidate.datasets.len() > rustbgpd_policy::datasets::MAX_UNIT_DATASETS {
            return Err(Status::invalid_argument(format!(
                "candidate chain references {} datasets; at most {} fit one evaluation",
                candidate.datasets.len(),
                rustbgpd_policy::datasets::MAX_UNIT_DATASETS
            )));
        }
        let installed = installed
            .unwrap_or_else(|| std::sync::Arc::new(rustbgpd_policy::ir::CompiledChain::empty()));
        // One dataset generation for the whole comparison: a retained member
        // shares its live handle with the installed chain, so both sides must
        // read the same snapshot or a refresh mid-walk reads as a difference.
        let mut pins = rustbgpd_policy::DatasetPins::default();
        let frames = ComparePolicyFrames {
            installed: pins.frame(&installed),
            candidate: pins.frame(&candidate),
        };

        let mut page = query_test_policy_page(rib_tx, RouteQueryScope::Best, None, None).await?;
        let snapshot_version = page.version;
        let peer_context = dry_run_peer_context(
            &self.peer_mgr_tx,
            self.operator_tx.as_ref(),
            Some(&target_key),
        )
        .await?;

        let scope = ComparePolicyScope {
            target: target_key.clone(),
            family_filter,
            limit: req.limit as usize,
            max_samples: req.max_samples as usize,
        };
        let mut response = proto::ComparePolicyResponse {
            compiled: true,
            installed_chain: chain_member_names(&installed),
            candidate_chain: chain_member_names(&candidate),
            ..Default::default()
        };
        loop {
            run_compare_policy_page(
                &installed,
                &candidate,
                &frames,
                &page,
                &scope,
                &peer_context,
                &mut response,
            );
            if (scope.limit != 0 && response.routes_evaluated >= req.limit.into()) || !page.has_more
            {
                break;
            }
            let after = page
                .routes
                .last()
                .map(|route| route_query_key_in(route, &page.peer_scope))
                .ok_or_else(|| {
                    Status::unavailable("route pagination returned an empty continuation page")
                })?;
            drop(page);
            page = query_test_policy_page(
                rib_tx,
                RouteQueryScope::Best,
                Some(after),
                Some(snapshot_version),
            )
            .await?;
        }
        Ok(Response::new(response))
    }

    #[expect(
        clippy::too_many_lines,
        reason = "sequential stages (peer validation, export, import, datasets) with shared shaping"
    )]
    async fn get_policy_stats(
        &self,
        request: Request<proto::GetPolicyStatsRequest>,
    ) -> Result<Response<proto::GetPolicyStatsResponse>, Status> {
        use rustbgpd_transport::handle::ImportPolicyStatsError;

        let deadline = tokio::time::Instant::now() + POLICY_STATS_AGGREGATE_TIMEOUT;
        let audit = request.extensions().get::<GrpcAuditHandle>().cloned();
        let req = request.into_inner();
        let (want_export, want_import) = match req.direction.as_str() {
            "" | "export" => (true, false),
            "import" => (false, true),
            "both" => (true, true),
            other => {
                return Err(Status::invalid_argument(format!(
                    "direction must be \"import\", \"export\", or \"both\", got {other:?}"
                )));
            }
        };
        if req.allow_partial && (!req.peer_address.is_empty() || !want_import) {
            return Err(Status::invalid_argument(
                "allow_partial requires an unfiltered import or both query",
            ));
        }
        // Snapshot before loading the roster: completion publishes it first.
        let initial_roster_pending = self
            .settlement
            .as_ref()
            .is_some_and(|(_, gate)| gate.initial_roster_pending());
        // One load per roster per request (ADR-0136): selector parsing, peer
        // selection, import and datasets read this roster, held across the
        // awaits below.
        let roster = self.import_roster.as_ref().map(ImportRosterReader::load);
        let key = crate::peer_selector::parse_neighbor_in(
            "peer_address",
            &req.peer_address,
            "",
            roster.as_deref(),
        )?;
        let rib_peer = key.as_ref().map(|key| {
            roster.as_deref().map_or_else(
                || PeerId::from_addr(key.address),
                |roster| roster.rib_peer(key.address, key.interface.as_deref()),
            )
        });
        let unavailable =
            || Status::failed_precondition("policy stats runtime unavailable on this listener");
        let roster_cell = self.import_roster.as_ref().ok_or_else(unavailable)?;
        let roster = roster.ok_or_else(unavailable)?;
        let export_cell = if want_export {
            Some(self.export_roster.as_ref().ok_or_else(unavailable)?)
        } else {
            None
        };
        let selected = match &key {
            Some(key) => {
                let selected =
                    policy_stats_request(deadline, "peer_validation", audit.as_ref(), async {
                        policy_stats_peer(&roster, key).ok_or_else(|| {
                            if initial_roster_pending {
                                Status::unavailable("initial configured-peer roster not installed")
                            } else {
                                Status::not_found(format!("neighbor {key} not found"))
                            }
                        })
                    })
                    .await?;
                std::slice::from_ref(selected)
            }
            None => roster.peers(),
        };
        let term_stats = |terms: Vec<rustbgpd_policy::TermHitRow>| -> Vec<proto::PolicyTermStat> {
            terms
                .into_iter()
                .map(|row| proto::PolicyTermStat {
                    policy_index: u32::try_from(row.policy_index).unwrap_or(u32::MAX),
                    policy: row.policy.unwrap_or_default(),
                    term_index: u32::try_from(row.term_index).unwrap_or(u32::MAX),
                    term: row.term.unwrap_or_default(),
                    hits: row.hits,
                })
                .collect()
        };

        // "both" reports export chains first, then import chains, each
        // block sorted by peer address (deterministic output).
        let mut out = Vec::new();
        let mut incomplete_peer_addresses = Vec::new();
        if let Some(export_cell) = export_cell {
            // The RIB's published export roster, held across the awaits below.
            let export_roster = export_cell.load();
            let chains = policy_stats_request(deadline, "export", audit.as_ref(), async {
                capture_export(&export_roster, rib_peer, deadline)
                    .await
                    .map_err(|error| match error {
                        ExportCaptureError::TimedOut => {
                            Status::deadline_exceeded("policy stats aggregate deadline exceeded")
                        }
                        ExportCaptureError::Unavailable => {
                            Status::unavailable("installed export policy counters unavailable")
                        }
                    })
            })
            .await?;
            out.extend(chains.into_iter().map(|chain| {
                proto::PolicyChainStats {
                    peer_address: chain
                        .peer
                        .map_or_else(|| "global".to_string(), |peer| peer.to_string()),
                    // The chain's own neighbor handle supplies the scope, so
                    // neighbors sharing a link-local address stay apart.
                    peer_interface: chain
                        .peer
                        .and_then(rustbgpd_rib::PeerId::endpoint)
                        .and_then(|endpoint| endpoint.interface)
                        .map(|interface| interface.to_string())
                        .unwrap_or_default(),
                    direction: "export".to_string(),
                    routes_evaluated: chain.evals,
                    eval_errors: chain.eval_errors,
                    last_error: chain.last_error.unwrap_or_default(),
                    terms: term_stats(chain.terms),
                    // The counter-instance id: a new id means the counters
                    // restarted.
                    policy_generation: chain.counter_instance,
                }
            }));
        }
        if want_import {
            let mut progress = ImportCaptureProgress::default();
            let chains = policy_stats_request(deadline, "import", audit.as_ref(), async {
                capture_import_allow_partial(selected, deadline, &mut progress, req.allow_partial)
                    .await
                    .map_err(|error| match error {
                        ImportPolicyStatsError::TimedOut => Status::deadline_exceeded(
                            "one or more installed import policy counter observations did not complete in time",
                        ),
                        ImportPolicyStatsError::SessionGone => Status::unavailable(
                            "one or more peer sessions exited during the import policy stats query",
                        ),
                        ImportPolicyStatsError::CountersUnavailable => {
                            Status::unavailable("installed import policy counters unavailable")
                        }
                    })
            })
            .await;
            if let Some(audit) = &audit {
                append_import_progress(audit, &progress);
            }
            let capture = chains?;
            incomplete_peer_addresses = capture
                .incomplete_peer_addresses
                .into_iter()
                .map(|peer| peer.to_string())
                .collect();
            out.extend(
                capture
                    .rows
                    .into_iter()
                    .map(|(peer, snapshot)| proto::PolicyChainStats {
                        peer_address: peer.address.to_string(),
                        peer_interface: peer.interface.unwrap_or_default(),
                        direction: "import".to_string(),
                        routes_evaluated: snapshot.evals,
                        eval_errors: snapshot.eval_errors,
                        last_error: snapshot.last_error.unwrap_or_default(),
                        terms: term_stats(snapshot.terms),
                        policy_generation: snapshot.generation,
                    }),
            );
        }

        // LAN-305: dataset status rides the stats surface — the
        // operator-visible half of "failed refresh keeps the prior
        // snapshot" (name, kind, generation, records, last error).
        let datasets = policy_stats_request(deadline, "datasets", audit.as_ref(), async {
            capture_datasets(roster.datasets(), deadline)
                .await
                .map_err(|error| match error {
                    DatasetCaptureError::TimedOut => {
                        Status::deadline_exceeded("policy stats aggregate deadline exceeded")
                    }
                    DatasetCaptureError::Unavailable => {
                        Status::unavailable("policy dataset status unavailable")
                    }
                })
        })
        .await?
        .into_iter()
        .map(|(status, path)| proto::PolicyDatasetStatus {
            name: status.name,
            kind: status.kind.as_str().to_string(),
            generation: status.generation,
            records: u64::try_from(status.records).unwrap_or(u64::MAX),
            path: path.to_string(),
            last_error: status.last_error.unwrap_or_default(),
        })
        .collect();

        // Checked after capture, not only before it: a roster loaded before
        // its owner stopped must not report its values as success.
        if roster_cell.is_closed() {
            return Err(Status::unavailable("peer manager stopped"));
        }
        if export_cell.is_some_and(ExportRosterReader::is_closed) {
            return Err(Status::unavailable("RIB manager stopped"));
        }

        Ok(Response::new(proto::GetPolicyStatsResponse {
            incomplete_peer_addresses,
            chains: out,
            datasets,
        }))
    }
}

/// The roster row `key` selects: the same address and interface scope, so a
/// neighbor replaced on another interface is not reported under this key.
fn policy_stats_peer<'a>(
    roster: &'a crate::import_roster::ImportRoster,
    key: &PeerKey,
) -> Option<&'a crate::import_roster::ImportRosterPeer> {
    roster.peers().iter().find(|peer| peer.key == *key)
}

/// `NOT_FOUND` when a received-route page for a scoped selector holds
/// another interface's routes: the neighbor on that address was replaced
/// after the selector was parsed. Same rule as `ListReceivedRoutes`.
fn require_row_scope(key: Option<&PeerKey>, routes: &[rustbgpd_rib::Route]) -> Result<(), Status> {
    match key {
        Some(key)
            if routes
                .iter()
                .any(|route| route.peer_interface().as_deref() != key.interface.as_deref()) =>
        {
            Err(Status::not_found(format!("neighbor {key} not found")))
        }
        _ => Ok(()),
    }
}

/// Dry-run peer context (ASN and peer group) from the peer manager's
/// inventory, checked against the selector's scope in that same inventory.
async fn dry_run_peer_context(
    peer_mgr_tx: &mpsc::Sender<PeerManagerCommand>,
    operator_tx: Option<&mpsc::Sender<EnqueuedOperatorQuery>>,
    key: Option<&PeerKey>,
) -> Result<DryRunPeerContext, Status> {
    let peers = peer_manager_operator_read(peer_mgr_tx, operator_tx, |reply| {
        PeerManagerOperatorQuery::ListPeers { reply }
    })
    .await?;
    if let Some(key) = key {
        crate::peer_selector::require_current_scope(
            key,
            peers
                .iter()
                .map(|info| (info.address, info.interface.as_deref())),
        )?;
    }
    Ok(peers
        .into_iter()
        .map(|info| {
            (
                PeerKey::new(info.address, info.interface),
                (info.remote_asn, info.peer_group),
            )
        })
        .collect())
}

fn posture_dimension_to_proto(
    snapshot: &ValidationPolicyDimensionSnapshot,
) -> proto::ValidationPolicyDimensionPosture {
    let disposition = match snapshot.disposition {
        ValidationPolicyDisposition::Enforced => proto::ValidationPolicyDisposition::Enforced,
        ValidationPolicyDisposition::Unenforced => proto::ValidationPolicyDisposition::Unenforced,
        ValidationPolicyDisposition::Unknown => proto::ValidationPolicyDisposition::Unknown,
    };
    proto::ValidationPolicyDimensionPosture {
        disposition: disposition.into(),
        reason: snapshot.reason.to_string(),
    }
}

fn conditional_status_to_proto(
    status: rustbgpd_rib::ConditionalAdvertisementStatus,
) -> proto::ConditionalAdvertisementStatus {
    let millis = |duration: Duration| u64::try_from(duration.as_millis()).unwrap_or(u64::MAX);
    proto::ConditionalAdvertisementStatus {
        name: status.name.to_string(),
        advertise_if: status.advertise_if.label().to_string(),
        conditions: status
            .conditions
            .into_iter()
            .map(|condition| proto::ConditionalAdvertisementCondition {
                prefix: condition.entry.prefix.to_string(),
                state: condition.state.to_string(),
                ge: condition.entry.ge.map(u32::from),
                le: condition.entry.le.map(u32::from),
                present_prefix_count: u64::try_from(condition.present_count).unwrap_or(u64::MAX),
                present_prefixes: condition
                    .present_sample
                    .iter()
                    .map(ToString::to_string)
                    .collect(),
            })
            .collect(),
        observed: status.observed.to_string(),
        observed_for_ms: millis(status.observed_for),
        applied: status.applied.to_string(),
        settle_time_seconds: u32::try_from(status.settle_time.as_secs()).unwrap_or(u32::MAX),
        settle_pending: status.settle_remaining.is_some(),
        settle_remaining_ms: status.settle_remaining.map_or(0, millis),
        selection_deferred: status.selection_deferred,
        attached_peers: status
            .attached_peers
            .iter()
            .map(ToString::to_string)
            .collect(),
        attached_neighbors: status
            .attached_neighbors
            .iter()
            .map(|neighbor| proto::ConditionalAdvertisementNeighbor {
                peer_address: neighbor.addr.to_string(),
                peer_interface: neighbor
                    .interface
                    .as_deref()
                    .unwrap_or_default()
                    .to_string(),
            })
            .collect(),
    }
}

fn posture_scope_to_proto(
    snapshot: ValidationPolicyScopeSnapshot,
) -> proto::ValidationPolicyScopePosture {
    proto::ValidationPolicyScopePosture {
        scope: snapshot.scope,
        kind: snapshot.kind.to_string(),
        rpki_invalid: Some(posture_dimension_to_proto(&snapshot.rpki_invalid)),
        aspa_invalid: Some(posture_dimension_to_proto(&snapshot.aspa_invalid)),
    }
}

const TEST_POLICY_PAGE_SIZE: usize = 1000;

/// Resolve a candidate policy reference (`name` or `name(u32, ...)`)
/// against the submitted source.
fn candidate_call<'a>(
    file: &rustbgpd_policy::rpol::RpolFile,
    call: &'a str,
) -> Result<(&'a str, Vec<u32>), Status> {
    let (base, args) =
        rustbgpd_policy::rpol::parse_call_form(call).map_err(Status::invalid_argument)?;
    let Some((_, params)) = file.policies().find(|(name, _)| *name == base) else {
        let available: Vec<&str> = file.policies().map(|(name, _)| name).collect();
        return Err(Status::invalid_argument(format!(
            "policy {base:?} is not defined in the submitted source (available: {available:?})"
        )));
    };
    if params != args.len() {
        return Err(Status::invalid_argument(format!(
            "policy {base:?} takes {params} parameter(s), {} given",
            args.len()
        )));
    }
    Ok((base, args))
}

/// Bind client-supplied candidate datasets to the source's declarations.
fn bind_candidate_datasets(
    file: &rustbgpd_policy::rpol::RpolFile,
    datasets: &[proto::TestPolicyDataset],
) -> Result<rustbgpd_policy::datasets::DatasetBindings, Status> {
    let declared: std::collections::HashMap<_, _> = file.dataset_decls().collect();
    let mut bindings = rustbgpd_policy::datasets::DatasetBindings::new();
    for dataset in datasets {
        let Some(&kind) = declared.get(dataset.name.as_str()) else {
            return Err(Status::invalid_argument(format!(
                "candidate dataset {:?} is not declared in the submitted source",
                dataset.name
            )));
        };
        if bindings.get(&dataset.name).is_some() {
            return Err(Status::invalid_argument(format!(
                "duplicate candidate dataset {:?}",
                dataset.name
            )));
        }
        let data =
            rustbgpd_policy::rpol::parse_dataset_text(&dataset.entries, kind).map_err(|error| {
                Status::invalid_argument(format!("candidate dataset {:?}: {error}", dataset.name))
            })?;
        bindings.insert(std::sync::Arc::new(
            rustbgpd_policy::datasets::DatasetHandle::new(&dataset.name, kind, data),
        ));
    }
    Ok(bindings)
}

/// Compile one resolved candidate policy reference. `cached_tables` reuses
/// the file's literal set tables, built once per file, for a caller that
/// compiles several policies from one submitted source.
fn compile_candidate(
    file: &rustbgpd_policy::rpol::RpolFile,
    base: &str,
    args: &[u32],
    store: &mut rustbgpd_policy::sets::SetStore,
    bindings: &rustbgpd_policy::datasets::DatasetBindings,
    cached_tables: bool,
) -> Result<rustbgpd_policy::ir::CompiledChain, Status> {
    let compiled = if cached_tables {
        file.compile_policy_bound_cached_tables(base, args, store, bindings)
    } else {
        file.compile_policy_bound(base, args, store, bindings)
    };
    compiled
        .expect("candidate_call checked existence")
        .map_err(|missing| {
            Status::invalid_argument(format!(
                "policy {base:?} probes an unbound candidate dataset: {missing}"
            ))
        })
}

async fn query_test_policy_page(
    rib_tx: &mpsc::Sender<rustbgpd_rib::RibUpdate>,
    scope: rustbgpd_rib::RouteQueryScope,
    after: Option<rustbgpd_rib::RouteQueryKey>,
    expected_version: Option<rustbgpd_rib::RoutePageVersion>,
) -> Result<rustbgpd_rib::RoutePage, Status> {
    use rustbgpd_rib::{RibUpdate, RoutePageError};

    rib_manager_read(rib_tx, |reply| RibUpdate::QueryRoutesPage {
        scope,
        filter: None,
        after,
        expected_version,
        page_size: TEST_POLICY_PAGE_SIZE,
        reply,
    })
    .await?
    .map_err(|error| match error {
        RoutePageError::ResyncInProgress => Status::failed_precondition(
            "TestPolicy advertised routes are unavailable until outbound resynchronization completes",
        ),
        RoutePageError::Invalidated => Status::aborted(
            "route table changed during TestPolicy; retry the whole RPC from the beginning",
        ),
        RoutePageError::GenerationExhausted => Status::unavailable(
            "TestPolicy route pagination unavailable because its generation is exhausted",
        ),
    })
}

/// Route selection scope for one `TestPolicy` dry run.
struct TestPolicyScope {
    /// Import (Adj-RIB-In snapshot, peer context from each route's
    /// source peer) vs export (Loc-RIB snapshot, peer context from
    /// `target_peer`).
    import: bool,
    /// Export evaluation target (also the import snapshot filter,
    /// applied upstream by the RIB query).
    target_peer: Option<PeerKey>,
    /// `Some(true)` = IPv4 only, `Some(false)` = IPv6 only.
    family_filter: Option<bool>,
    /// Max routes evaluated; 0 = all.
    limit: usize,
    /// Max before/after diff samples returned.
    show_changes: usize,
    /// Max rejected route samples returned.
    show_rejected: usize,
}

/// Evaluate the compiled candidate policy read-only over the route
/// snapshot: counts, per-term hit counters, and up to
/// `scope.show_changes` before/after diff samples. Pure function of
/// its inputs — no daemon state is touched (ADR-0096 Decision 6).
fn run_test_policy_page(
    chain: &rustbgpd_policy::ir::CompiledChain,
    page: &rustbgpd_rib::RoutePage,
    scope: &TestPolicyScope,
    peer_context: &DryRunPeerContext,
    response: &mut proto::TestPolicyResponse,
    hits: &mut [Vec<u64>],
) {
    use rustbgpd_policy::PolicyAction;
    let (routes, peers) = (&page.routes, &page.peer_scope);

    let needs_as_path_string = chain.requires_as_path_string();
    let remaining = if scope.limit == 0 {
        usize::MAX
    } else {
        let routes_evaluated = usize::try_from(response.routes_evaluated).unwrap_or(usize::MAX);
        scope.limit.saturating_sub(routes_evaluated)
    };
    for route in routes
        .iter()
        .filter(|route| {
            scope
                .family_filter
                .is_none_or(|v4| matches!(route.prefix, Prefix::V4(_)) == v4)
        })
        .take(remaining)
    {
        let source;
        let ctx_peer = if scope.import {
            source = route_source_key(route, peers);
            Some(&source)
        } else {
            scope.target_peer.as_ref()
        };
        let as_path_str = dry_run_as_path_string(route, needs_as_path_string);
        let ctx = dry_run_route_context(route, &as_path_str, ctx_peer, peer_context);
        response.routes_evaluated += 1;
        let result = chain.evaluate_recording_hits(&ctx, hits);
        if result.action == PolicyAction::Permit {
            response.accepted += 1;
            if !result.modifications.is_empty() {
                response.modified += 1;
                if response.diffs.len() < scope.show_changes {
                    response.diffs.push(proto::TestPolicyDiff {
                        prefix: route.prefix.addr_string(),
                        prefix_length: u32::from(route.prefix.prefix_len()),
                        peer: peers.display(route.peer),
                        peer_interface: route
                            .peer_interface()
                            .as_deref()
                            .unwrap_or_default()
                            .to_string(),
                        changes: render_modification_changes(route, &result.modifications),
                    });
                }
            }
        } else {
            response.rejected += 1;
            if response.rejected_routes.len() < scope.show_rejected {
                response
                    .rejected_routes
                    .push(proto::TestPolicyRejectedRoute {
                        prefix: route.prefix.addr_string(),
                        prefix_length: u32::from(route.prefix.prefix_len()),
                        peer: peers.display(route.peer),
                        peer_interface: route
                            .peer_interface()
                            .as_deref()
                            .unwrap_or_default()
                            .to_string(),
                    });
            }
        }
    }
}

/// The neighbor a route was learned from: its address as of the page's RIB
/// turn and the interface its receiving session recorded.
fn route_source_key(route: &rustbgpd_rib::Route, peers: &rustbgpd_rib::PeerScope) -> PeerKey {
    PeerKey::new(
        peers.addr(route.peer),
        route.peer_interface().map(|name| name.to_string()),
    )
}

/// Peer context for dry runs: neighbor -> (remote ASN, peer group). Keyed by
/// the scoped neighbor, so two neighbors on one link-local address keep
/// their own ASN and group.
type DryRunPeerContext = std::collections::HashMap<PeerKey, (u32, Option<String>)>;

/// The rendered `AS_PATH` string, only when some guard needs it.
fn dry_run_as_path_string(route: &rustbgpd_rib::Route, needed: bool) -> String {
    if needed {
        route
            .as_path()
            .map_or_else(String::new, rustbgpd_wire::AsPath::to_aspath_string)
    } else {
        String::new()
    }
}

/// The policy context a dry run evaluates `route` with, as seen from
/// `ctx_peer` (the source peer on import, the target peer on export).
fn dry_run_route_context<'a>(
    route: &'a rustbgpd_rib::Route,
    as_path_str: &'a str,
    ctx_peer: Option<&PeerKey>,
    peer_context: &'a DryRunPeerContext,
) -> rustbgpd_policy::RouteContext<'a> {
    use rustbgpd_policy::{RouteContext, RouteType};
    use rustbgpd_rib::RouteOrigin;

    let (peer_asn, peer_group) = ctx_peer
        .and_then(|key| peer_context.get(key))
        .map_or((None, None), |(asn, group)| (Some(*asn), group.as_deref()));
    RouteContext {
        prefix: Some(route.prefix),
        next_hop: Some(route.next_hop),
        extended_communities: route.extended_communities(),
        communities: route.communities(),
        large_communities: route.large_communities(),
        as_path_str,
        as_path: route.as_path(),
        as_path_len: route.as_path().map_or(0, rustbgpd_wire::AsPath::len),
        origin_asn: route.as_path().and_then(rustbgpd_wire::AsPath::origin_asn),
        validation_state: route.validation_state,
        aspa_state: route.aspa_state,
        peer_address: ctx_peer.map(|key| key.address),
        peer_asn,
        peer_group,
        route_type: Some(match route.origin_type {
            RouteOrigin::Ebgp => RouteType::External,
            RouteOrigin::Ibgp => RouteType::Internal,
            RouteOrigin::Local => RouteType::Local,
        }),
        // `rbgp policy test` evaluates the unicast RIB snapshot;
        // a unicast NLRI *is* its prefix, so the prefix's address
        // family is the route's typed family (LAN-295).
        family: Some(match route.prefix {
            Prefix::V4(_) => rustbgpd_policy::RouteFamily::Ipv4Unicast,
            Prefix::V6(_) => rustbgpd_policy::RouteFamily::Ipv6Unicast,
        }),
        evpn_route_type: None,
        local_pref: route.local_pref_attr(),
        med: route.med_attr(),
    }
}

/// Compile every candidate member of one comparison from the submitted file,
/// charging each against the chain budget as it is retained. The file's
/// literal set tables are built once and shared by every member; candidate
/// dataset bindings stay per request.
fn compile_compare_candidates(
    file: &rustbgpd_policy::rpol::RpolFile,
    calls: &[(&str, Vec<u32>)],
    bindings: &rustbgpd_policy::datasets::DatasetBindings,
    store: &mut rustbgpd_policy::sets::SetStore,
    charge: &mut impl FnMut(&rustbgpd_policy::ir::CompiledPolicy) -> Result<(), Status>,
) -> Result<Vec<rustbgpd_policy::ir::CompiledChain>, Status> {
    let mut compiled = Vec::with_capacity(calls.len());
    for (base, args) in calls {
        let chain = compile_candidate(file, base, args, store, bindings, true)?;
        chain.policies.iter().try_for_each(&mut *charge)?;
        compiled.push(chain);
    }
    Ok(compiled)
}

/// Route selection scope for one `ComparePolicy` run.
struct ComparePolicyScope {
    /// Export target: its address and peer context are the evaluation context.
    target: PeerKey,
    /// `Some(true)` = IPv4 only, `Some(false)` = IPv6 only.
    family_filter: Option<bool>,
    /// Max routes evaluated; 0 = all.
    limit: usize,
    /// Max samples per class.
    max_samples: usize,
}

/// Member names of a compiled chain, in evaluation order.
fn chain_member_names(chain: &rustbgpd_policy::ir::CompiledChain) -> Vec<String> {
    chain
        .policies
        .iter()
        .map(|policy| policy.name.as_deref().unwrap_or("(unnamed)").to_string())
        .collect()
}

/// What an accepted route leaves a chain with, in canonical form: attributes
/// in type-code order with community sets sorted and deduplicated (`AS_PATH`
/// and Partial flags kept as they are), and the effective next hop, where
/// `None` is next-hop self.
fn exported_attributes(
    route: &rustbgpd_rib::Route,
    mods: &rustbgpd_policy::RouteModifications,
) -> (Vec<rustbgpd_wire::PathAttribute>, Option<IpAddr>) {
    use rustbgpd_policy::NextHopAction;
    use rustbgpd_wire::PathAttribute;

    let mut attributes: Vec<_> = route.attributes_except_next_hop().cloned().collect();
    let next_hop = match rustbgpd_policy::apply_modifications(&mut attributes, mods) {
        // An injected route's unspecified next hop is next-hop self at export.
        None if route.origin_type == rustbgpd_rib::RouteOrigin::Local
            && route.next_hop.is_unspecified() =>
        {
            None
        }
        None => Some(route.next_hop),
        Some(NextHopAction::Specific(address)) => Some(address),
        Some(NextHopAction::Self_) => None,
    };
    // An IPv4 rewrite is also written into a NEXT_HOP attribute; `next_hop`
    // already carries it.
    attributes.retain(|attribute| !matches!(attribute, PathAttribute::NextHop(_)));
    for attribute in &mut attributes {
        match attribute {
            PathAttribute::Communities(values) | PathAttribute::CommunitiesPartial(values) => {
                values.sort_unstable();
                values.dedup();
            }
            PathAttribute::ExtendedCommunities(values)
            | PathAttribute::ExtendedCommunitiesPartial(values) => {
                values.sort_unstable_by_key(|value| value.as_u64());
                values.dedup();
            }
            PathAttribute::LargeCommunities(values)
            | PathAttribute::LargeCommunitiesPartial(values) => {
                values.sort_unstable_by_key(|value| {
                    (value.global_admin, value.local_data1, value.local_data2)
                });
                values.dedup();
            }
            _ => {}
        }
    }
    attributes.sort_by_key(PathAttribute::type_code);
    (attributes, next_hop)
}

/// Dataset snapshots each side of one comparison reads.
struct ComparePolicyFrames {
    installed: rustbgpd_policy::PinnedFrame,
    candidate: rustbgpd_policy::PinnedFrame,
}

/// Evaluate the installed and candidate chains over one page and count the
/// routes they treat differently. Both run through the dry-run evaluator
/// without coverage grids, so no live counter moves, no evaluation-error
/// WARN is logged and nothing is allocated per route for coverage; both
/// read datasets from `frames`, pinned once per run.
fn run_compare_policy_page(
    installed: &rustbgpd_policy::ir::CompiledChain,
    candidate: &rustbgpd_policy::ir::CompiledChain,
    frames: &ComparePolicyFrames,
    page: &rustbgpd_rib::RoutePage,
    scope: &ComparePolicyScope,
    peer_context: &DryRunPeerContext,
    response: &mut proto::ComparePolicyResponse,
) {
    use rustbgpd_policy::PolicyAction;
    let (routes, peers) = (&page.routes, &page.peer_scope);

    let needs_as_path_string =
        installed.requires_as_path_string() || candidate.requires_as_path_string();
    let remaining = if scope.limit == 0 {
        usize::MAX
    } else {
        let routes_evaluated = usize::try_from(response.routes_evaluated).unwrap_or(usize::MAX);
        scope.limit.saturating_sub(routes_evaluated)
    };
    for route in routes
        .iter()
        .filter(|route| {
            scope
                .family_filter
                .is_none_or(|v4| matches!(route.prefix, Prefix::V4(_)) == v4)
        })
        .take(remaining)
    {
        let as_path_str = dry_run_as_path_string(route, needs_as_path_string);
        let ctx = dry_run_route_context(route, &as_path_str, Some(&scope.target), peer_context);
        response.routes_evaluated += 1;
        let before = installed.evaluate_pinned(&ctx, &frames.installed);
        let after = candidate.evaluate_pinned(&ctx, &frames.candidate);
        let (count, samples) = match (before.action, after.action) {
            (PolicyAction::Permit, PolicyAction::Deny) => (
                &mut response.newly_rejected,
                &mut response.newly_rejected_routes,
            ),
            (PolicyAction::Deny, PolicyAction::Permit) => (
                &mut response.newly_accepted,
                &mut response.newly_accepted_routes,
            ),
            (PolicyAction::Permit, PolicyAction::Permit)
                if before.modifications != after.modifications
                    && exported_attributes(route, &before.modifications)
                        != exported_attributes(route, &after.modifications) =>
            {
                (
                    &mut response.attributes_changed,
                    &mut response.attributes_changed_routes,
                )
            }
            _ => continue,
        };
        *count += 1;
        if samples.len() < scope.max_samples {
            let changes = |result: &rustbgpd_policy::PolicyResult| {
                if result.action == PolicyAction::Permit {
                    render_modification_changes(route, &result.modifications)
                } else {
                    Vec::new()
                }
            };
            samples.push(proto::ComparePolicyRoute {
                prefix: route.prefix.addr_string(),
                prefix_length: u32::from(route.prefix.prefix_len()),
                peer: peers.display(route.peer),
                installed_changes: changes(&before),
                candidate_changes: changes(&after),
            });
        }
    }
}

fn render_test_policy_term_hits(
    chain: &rustbgpd_policy::ir::CompiledChain,
    hits: &[Vec<u64>],
) -> Vec<proto::TestPolicyTermHits> {
    chain
        .policies
        .iter()
        .zip(hits)
        .flat_map(|(policy, policy_hits)| {
            policy
                .terms
                .iter()
                .zip(policy_hits)
                .enumerate()
                .map(|(index, (term, count))| proto::TestPolicyTermHits {
                    term: term.name.clone().unwrap_or_else(|| format!("term {index}")),
                    hits: *count,
                })
        })
        .collect()
}

/// Render one modified route's attribute changes as human-readable
/// before/after lines (the `TestPolicyDiff.changes` contract).
fn render_modification_changes(
    route: &rustbgpd_rib::Route,
    mods: &rustbgpd_policy::RouteModifications,
) -> Vec<String> {
    let fmt_community = |value: u32| format!("{}:{}", value >> 16, value & 0xFFFF);
    let fmt_opt = |value: Option<u32>| value.map_or_else(|| "unset".to_string(), |v| v.to_string());
    let mut changes = Vec::new();
    if let Some(after) = mods.set_local_pref {
        changes.push(format!(
            "local_pref {} -> {after}",
            fmt_opt(route.local_pref_attr())
        ));
    }
    if let Some(after) = mods.set_med {
        changes.push(format!("med {} -> {after}", fmt_opt(route.med_attr())));
    }
    if let Some(next_hop) = mods.set_next_hop.as_ref() {
        let after = match next_hop {
            rustbgpd_policy::NextHopAction::Self_ => "self".to_string(),
            rustbgpd_policy::NextHopAction::Specific(addr) => addr.to_string(),
        };
        changes.push(format!("next_hop {} -> {after}", route.next_hop));
    }
    for value in &mods.communities_add {
        changes.push(format!("communities + {}", fmt_community(*value)));
    }
    for value in &mods.communities_remove {
        changes.push(format!("communities - {}", fmt_community(*value)));
    }
    for lc in &mods.large_communities_add {
        changes.push(format!("large_communities + {lc}"));
    }
    for lc in &mods.large_communities_remove {
        changes.push(format!("large_communities - {lc}"));
    }
    for ec in &mods.extended_communities_add {
        changes.push(format!("extended_communities + 0x{:016x}", ec.as_u64()));
    }
    for ec in &mods.extended_communities_remove {
        changes.push(format!("extended_communities - 0x{:016x}", ec.as_u64()));
    }
    if let Some((asn, count)) = mods.as_path_prepend {
        changes.push(format!("as_path prepend {asn} x{count}"));
    }
    changes
}

#[cfg(test)]
mod tests {
    use rustbgpd_rib::PeerId;
    use std::sync::{Arc, Mutex};

    use super::*;
    use crate::import_roster::ImportRosterPublisher;
    use crate::peer_types::{CatalogMutationError, PolicyAsPathPrependConfig};
    use crate::proto::policy_service_server::PolicyService as PolicyServiceRpc;
    use rustbgpd_rib::AttrSet;
    use tokio::sync::mpsc::error::TryRecvError;
    use tokio::sync::oneshot;

    #[tokio::test(start_paused = true)]
    async fn config_persistence_admission_failures_are_unavailable() {
        let (tx, rx) = mpsc::channel(1);
        drop(rx);
        let error = reserve_config_event_slot(Some(tx)).await.unwrap_err();
        assert_eq!(error.code(), tonic::Code::Unavailable);
        assert_eq!(error.message(), "config persistence unavailable");

        let (tx, _rx) = mpsc::channel(1);
        let _permit = tx.clone().reserve_owned().await.unwrap();
        let error = reserve_config_event_slot(Some(tx)).await.unwrap_err();
        assert_eq!(error.code(), tonic::Code::Unavailable);
        assert_eq!(
            error.message(),
            "config persistence queue busy — refusing mutation to avoid drift"
        );
    }
    fn sample_proto_definition() -> proto::PolicyDefinition {
        proto::PolicyDefinition {
            default_action: "permit".into(),
            statements: vec![proto::PolicyStatement {
                action: "permit".into(),
                prefix: Some("10.0.0.0/8".into()),
                set_local_pref: Some(200),
                ..Default::default()
            }],
        }
    }

    #[derive(Clone, Copy, Debug)]
    enum PolicyRead {
        ListPolicies,
        GetPolicy,
        ListNeighborSets,
        GetNeighborSet,
        GetGlobalPolicyChains,
        GetNeighborPolicyChains,
        ExplainImportPolicy,
        ListRejectedRoutes,
        TestPolicy,
        ComparePolicy,
        GetValidationPolicyPosture,
    }

    /// `GetPolicyStats` reads only published rosters (ADR-0136), so it sends
    /// to no actor and has no row here.
    const POLICY_READS: [PolicyRead; 11] = [
        PolicyRead::ListPolicies,
        PolicyRead::GetPolicy,
        PolicyRead::ListNeighborSets,
        PolicyRead::GetNeighborSet,
        PolicyRead::GetGlobalPolicyChains,
        PolicyRead::GetNeighborPolicyChains,
        PolicyRead::ExplainImportPolicy,
        PolicyRead::ListRejectedRoutes,
        PolicyRead::TestPolicy,
        PolicyRead::ComparePolicy,
        PolicyRead::GetValidationPolicyPosture,
    ];

    impl PolicyRead {
        const fn rib_first(self) -> bool {
            matches!(self, Self::TestPolicy | Self::ComparePolicy)
        }
    }

    fn test_policy_request() -> proto::TestPolicyRequest {
        proto::TestPolicyRequest {
            rpol_source: TEST_RPOL.to_string(),
            policy: "customer-in(200)".to_string(),
            direction: "import".to_string(),
            peer: String::new(),
            afi_safi: proto::AddressFamily::Unspecified as i32,
            limit: 0,
            show_changes: 0,
            ..Default::default()
        }
    }

    fn policy_stats_rpc_request(
        peer_address: &str,
        direction: &str,
    ) -> proto::GetPolicyStatsRequest {
        proto::GetPolicyStatsRequest {
            allow_partial: false,
            peer_address: peer_address.to_string(),
            direction: direction.to_string(),
        }
    }

    async fn invoke_policy_read(service: &PolicyService, rpc: PolicyRead) -> Result<(), Status> {
        match rpc {
            PolicyRead::ListPolicies => PolicyServiceRpc::list_policies(
                service,
                Request::new(proto::ListPoliciesRequest {}),
            )
            .await
            .map(|_| ()),
            PolicyRead::GetPolicy => PolicyServiceRpc::get_policy(
                service,
                Request::new(proto::GetPolicyRequest { name: "p".into() }),
            )
            .await
            .map(|_| ()),
            PolicyRead::ListNeighborSets => PolicyServiceRpc::list_neighbor_sets(
                service,
                Request::new(proto::ListNeighborSetsRequest {}),
            )
            .await
            .map(|_| ()),
            PolicyRead::GetNeighborSet => PolicyServiceRpc::get_neighbor_set(
                service,
                Request::new(proto::GetNeighborSetRequest { name: "s".into() }),
            )
            .await
            .map(|_| ()),
            PolicyRead::GetGlobalPolicyChains => PolicyServiceRpc::get_global_policy_chains(
                service,
                Request::new(proto::GetGlobalPolicyChainsRequest {}),
            )
            .await
            .map(|_| ()),
            PolicyRead::GetNeighborPolicyChains => PolicyServiceRpc::get_neighbor_policy_chains(
                service,
                Request::new(proto::GetNeighborPolicyChainsRequest {
                    address: "192.0.2.1".into(),
                }),
            )
            .await
            .map(|_| ()),
            PolicyRead::ExplainImportPolicy => {
                PolicyServiceRpc::explain_import_policy(service, Request::new(explain_request()))
                    .await
                    .map(|_| ())
            }
            PolicyRead::ListRejectedRoutes => PolicyServiceRpc::list_rejected_routes(
                service,
                Request::new(proto::ListRejectedRoutesRequest {
                    peer_address: "192.0.2.1".into(),
                }),
            )
            .await
            .map(|_| ()),
            PolicyRead::TestPolicy => {
                PolicyServiceRpc::test_policy(service, Request::new(test_policy_request()))
                    .await
                    .map(|_| ())
            }
            PolicyRead::ComparePolicy => PolicyServiceRpc::compare_policy(
                service,
                Request::new(proto::ComparePolicyRequest {
                    rpol_source: TEST_RPOL.to_string(),
                    policies: vec!["customer-in(200)".to_string()],
                    peer: "192.0.2.1".to_string(),
                    ..Default::default()
                }),
            )
            .await
            .map(|_| ()),
            PolicyRead::GetValidationPolicyPosture => {
                PolicyServiceRpc::get_validation_policy_posture(
                    service,
                    Request::new(proto::GetValidationPolicyPostureRequest {}),
                )
                .await
                .map(|_| ())
            }
        }
    }

    #[test]
    fn validation_posture_mapping_never_emits_unspecified() {
        for disposition in [
            ValidationPolicyDisposition::Enforced,
            ValidationPolicyDisposition::Unenforced,
            ValidationPolicyDisposition::Unknown,
        ] {
            let proto = posture_dimension_to_proto(&ValidationPolicyDimensionSnapshot {
                disposition,
                reason: "stable_reason",
            });
            assert_ne!(
                proto.disposition,
                proto::ValidationPolicyDisposition::Unspecified as i32
            );
            assert_eq!(proto.reason, "stable_reason");
        }
    }

    /// Load-bearing: restoring any included RPC's first actor-send mapping to
    /// `INTERNAL` makes its row red. `TestPolicy` starts at the RIB.
    #[tokio::test]
    async fn policy_read_send_failures_are_unavailable() {
        for rpc in POLICY_READS {
            let (peer_tx, peer_rx) = mpsc::channel(1);
            let (rib_tx, rib_rx) = mpsc::channel(1);
            let roster = ImportRosterPublisher::new();
            let service = PolicyService::new(AccessMode::ReadOnly, peer_tx, None, None)
                .with_rib_query(rib_tx)
                .with_import_roster(roster.reader());
            let expected = if rpc.rib_first() {
                drop(rib_rx);
                let _peer_rx = peer_rx;
                "RIB manager unavailable"
            } else {
                drop(peer_rx);
                let _rib_rx = rib_rx;
                "peer manager unavailable"
            };
            let error = invoke_policy_read(&service, rpc).await.unwrap_err();
            assert_eq!(error.code(), tonic::Code::Unavailable, "{rpc:?}");
            assert_eq!(error.message(), expected, "{rpc:?}");
        }
    }

    /// Load-bearing: restoring any included RPC's first reply-await mapping to
    /// `INTERNAL` makes its accepted-then-dropped row red.
    #[tokio::test]
    async fn policy_read_reply_drops_are_unavailable() {
        for rpc in POLICY_READS {
            let (peer_tx, mut peer_rx) = mpsc::channel(1);
            let (rib_tx, mut rib_rx) = mpsc::channel(1);
            let roster = ImportRosterPublisher::new();
            let service = PolicyService::new(AccessMode::ReadOnly, peer_tx, None, None)
                .with_rib_query(rib_tx)
                .with_import_roster(roster.reader());
            let (actor, expected) = if rpc.rib_first() {
                (
                    tokio::spawn(async move {
                        drop(rib_rx.recv().await.expect("policy RIB read"));
                    }),
                    "RIB manager dropped reply",
                )
            } else {
                (
                    tokio::spawn(async move {
                        drop(peer_rx.recv().await.expect("policy peer read"));
                    }),
                    "peer manager dropped reply",
                )
            };
            let error = invoke_policy_read(&service, rpc).await.unwrap_err();
            actor.await.unwrap();
            assert_eq!(error.code(), tonic::Code::Unavailable, "{rpc:?}");
            assert_eq!(error.message(), expected, "{rpc:?}");
        }
    }

    #[derive(Clone, Copy, Debug)]
    enum PolicyReadExtraStage {
        TestPolicyPeerContext,
    }

    /// `GetPolicyStats` reads published rosters, not an actor lane, so only
    /// `TestPolicy`'s peer context remains.
    const POLICY_READ_EXTRA_STAGES: [PolicyReadExtraStage; 1] =
        [PolicyReadExtraStage::TestPolicyPeerContext];

    async fn invoke_policy_extra_stage(
        service: &PolicyService,
        stage: PolicyReadExtraStage,
    ) -> Result<(), Status> {
        match stage {
            PolicyReadExtraStage::TestPolicyPeerContext => {
                PolicyServiceRpc::test_policy(service, Request::new(test_policy_request()))
                    .await
                    .map(|_| ())
            }
        }
    }

    async fn answer_policy_stage_rib(mut rib_rx: mpsc::Receiver<rustbgpd_rib::RibUpdate>) {
        let Some(update) = rib_rx.recv().await else {
            return;
        };
        match update {
            rustbgpd_rib::RibUpdate::QueryRoutesPage { reply, .. } => {
                let _ = reply.send(Ok(rustbgpd_rib::RoutePage::default()));
            }
            _ => panic!("unexpected policy-stage RIB query"),
        }
    }

    /// Load-bearing: bypassing the shared peer helper at any post-RIB or
    /// stats-only peer stage makes that stage's send-closed row red.
    #[tokio::test]
    async fn policy_extra_stage_send_failures_are_unavailable() {
        for stage in POLICY_READ_EXTRA_STAGES {
            let (peer_tx, peer_rx) = mpsc::channel(1);
            drop(peer_rx);
            let (rib_tx, rib_rx) = mpsc::channel(1);
            let rib = tokio::spawn(answer_policy_stage_rib(rib_rx));
            let service = PolicyService::new(AccessMode::ReadOnly, peer_tx, None, None)
                .with_rib_query(rib_tx);
            let error = invoke_policy_extra_stage(&service, stage)
                .await
                .unwrap_err();
            drop(service);
            rib.await.unwrap();
            assert_eq!(error.code(), tonic::Code::Unavailable, "{stage:?}");
            assert_eq!(error.message(), "peer manager unavailable", "{stage:?}");
        }
    }

    /// Load-bearing: bypassing the shared peer helper at any post-RIB or
    /// stats-only peer stage makes that accepted/dropped row red.
    #[tokio::test]
    async fn policy_extra_stage_reply_drops_are_unavailable() {
        for stage in POLICY_READ_EXTRA_STAGES {
            let (peer_tx, mut peer_rx) = mpsc::channel(1);
            let peer = tokio::spawn(async move {
                drop(peer_rx.recv().await.expect("policy-stage peer read"));
            });
            let (rib_tx, rib_rx) = mpsc::channel(1);
            let rib = tokio::spawn(answer_policy_stage_rib(rib_rx));
            let service = PolicyService::new(AccessMode::ReadOnly, peer_tx, None, None)
                .with_rib_query(rib_tx);
            let error = invoke_policy_extra_stage(&service, stage)
                .await
                .unwrap_err();
            drop(service);
            peer.await.unwrap();
            rib.await.unwrap();
            assert_eq!(error.code(), tonic::Code::Unavailable, "{stage:?}");
            assert_eq!(error.message(), "peer manager dropped reply", "{stage:?}");
        }
    }

    /// Negative control: request validation still precedes actor I/O, while
    /// successfully delivered typed `None` replies retain `NOT_FOUND`.
    #[tokio::test]
    async fn policy_reads_preserve_invalid_and_not_found() {
        let (peer_tx, mut peer_rx) = mpsc::channel(3);
        let service = PolicyService::new(AccessMode::ReadOnly, peer_tx, None, None);

        let invalid = PolicyServiceRpc::get_policy(
            &service,
            Request::new(proto::GetPolicyRequest {
                name: String::new(),
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(invalid.code(), tonic::Code::InvalidArgument);
        assert!(matches!(peer_rx.try_recv(), Err(TryRecvError::Empty)));

        let actor = tokio::spawn(async move {
            for _ in 0..3 {
                match peer_rx.recv().await.expect("policy read") {
                    PeerManagerCommand::GetPolicy { reply, .. } => {
                        let _ = reply.send(None);
                    }
                    PeerManagerCommand::GetNeighborSet { reply, .. } => {
                        let _ = reply.send(None);
                    }
                    PeerManagerCommand::GetNeighborPolicyChains { reply, .. } => {
                        let _ = reply.send(None);
                    }
                    _ => panic!("unexpected policy read"),
                }
            }
        });

        let policy = PolicyServiceRpc::get_policy(
            &service,
            Request::new(proto::GetPolicyRequest { name: "p".into() }),
        )
        .await
        .unwrap_err();
        assert_eq!(policy.code(), tonic::Code::NotFound);
        let neighbor_set = PolicyServiceRpc::get_neighbor_set(
            &service,
            Request::new(proto::GetNeighborSetRequest { name: "s".into() }),
        )
        .await
        .unwrap_err();
        assert_eq!(neighbor_set.code(), tonic::Code::NotFound);
        let chains = PolicyServiceRpc::get_neighbor_policy_chains(
            &service,
            Request::new(proto::GetNeighborPolicyChainsRequest {
                address: "192.0.2.1".into(),
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(chains.code(), tonic::Code::NotFound);
        actor.await.unwrap();
    }

    #[test]
    fn proto_statement_roundtrip_preserves_optionals() {
        let input = PolicyStatementDefinition {
            action: "permit".into(),
            prefix: Some("10.0.0.0/8".into()),
            ge: Some(16),
            le: Some(24),
            match_community: vec!["65001:100".into()],
            match_as_path: Some("_65002_".into()),
            match_neighbor_set: None,
            match_route_type: None,
            match_evpn_route_type: None,
            match_as_path_length_ge: Some(1),
            match_as_path_length_le: Some(5),
            match_local_pref_ge: None,
            match_local_pref_le: None,
            match_med_ge: None,
            match_med_le: None,
            match_next_hop: Some("2001:db8::1".into()),
            match_rpki_validation: Some("valid".into()),
            match_aspa_validation: Some("valid".into()),
            set_local_pref: Some(200),
            set_med: Some(50),
            set_next_hop: Some("self".into()),
            set_community_add: vec!["65001:200".into()],
            set_community_remove: vec!["65001:300".into()],
            set_as_path_prepend: Some(PolicyAsPathPrependConfig {
                asn: 65001,
                count: 3,
            }),
        };
        let proto = input_statement_to_proto(&input);
        let roundtrip = proto_statement_to_input(proto).unwrap();
        assert_eq!(roundtrip, input);
    }

    #[test]
    fn resolved_match_maps_statement_trace_to_proto_steps() {
        use rustbgpd_policy::{PolicyAction, StatementAttribution};
        use rustbgpd_transport::{CachedDecision, CachedOutcome, CachedPolicyContext};
        use rustbgpd_wire::{AspaValidation, RpkiValidation};
        use std::time::SystemTime;

        let resolved = ResolvedMatch {
            path_id: 0,
            result: LookupResult::Hit(CachedDecision {
                outcome: CachedOutcome::Permit,
                matched_policy: Some("edge-import".into()),
                rpki: RpkiValidation::NotFound,
                aspa: AspaValidation::Unknown,
                policy_context: CachedPolicyContext::default(),
                next_hop: None,
                modifications: rustbgpd_policy::RouteModifications::default(),
                evaluated_at: SystemTime::UNIX_EPOCH,
                policy_generation: 1,
            }),
            statements: vec![
                StatementAttribution {
                    policy_index: 0,
                    policy_name: Some("edge-import".into()),
                    statement_index: Some(2),
                    action: PolicyAction::Permit,
                    matched_conditions: vec!["community 65001:100".into()],
                    modifications: vec!["local_pref 100 -> 200".into()],
                    term_name: Some("customer-routes".into()),
                    term_traces: vec![
                        "term customer-routes: route.communities has 65001:100 => accept [matched]"
                            .into(),
                    ],
                },
                StatementAttribution {
                    policy_index: 1,
                    policy_name: None,
                    statement_index: None,
                    action: PolicyAction::Permit,
                    matched_conditions: vec![],
                    modifications: vec![],
                    term_name: None,
                    term_traces: vec![],
                },
            ],
        };
        let m = resolved_match_to_proto(
            "10.0.0.2",
            &PeerKey::new("10.0.0.2".parse().unwrap(), None),
            "192.0.2.0",
            24,
            proto::AddressFamily::Ipv4Unicast as i32,
            resolved,
        );
        assert_eq!(m.matched_policy, "edge-import");
        assert_eq!(m.statements.len(), 2);
        let matched = &m.statements[0];
        assert_eq!(matched.policy_index, 0);
        assert_eq!(matched.policy_name, "edge-import");
        assert!(!matched.default_action);
        assert_eq!(matched.statement_index, 2);
        assert_eq!(matched.action, "permit");
        assert_eq!(matched.matched_conditions, vec!["community 65001:100"]);
        assert_eq!(matched.modifications, vec!["local_pref 100 -> 200"]);
        // Default-action fallthrough on an anonymous policy: the flag
        // is set, the index is the 0 placeholder, the name is empty
        // (operators read "inline").
        let fallthrough = &m.statements[1];
        assert_eq!(fallthrough.policy_index, 1);
        assert_eq!(fallthrough.policy_name.len(), 0);
        assert!(fallthrough.default_action);
        assert_eq!(fallthrough.statement_index, 0);
        assert_eq!(fallthrough.action, "permit");
    }

    #[test]
    fn proto_statement_rejects_large_u8_fields() {
        let proto = proto::PolicyStatement {
            ge: Some(300),
            ..Default::default()
        };
        assert!(proto_statement_to_input(proto).is_err());
    }

    fn explain_request() -> proto::ExplainImportPolicyRequest {
        proto::ExplainImportPolicyRequest {
            peer_address: "10.0.0.2".to_string(),
            afi_safi: proto::AddressFamily::Ipv4Unicast as i32,
            prefix: "10.0.0.0".to_string(),
            prefix_length: 24,
            path_id: None,
        }
    }

    /// Drive `ExplainImportPolicy` against a fake peer manager that
    /// answers with `reply`, returning the single synthetic match's
    /// outcome (LAN-320 tri-state pins).
    async fn explain_outcome_for(reply: Option<ImportExplainReply>) -> i32 {
        let resp = explain_response_for(reply).await;
        assert_eq!(resp.matches.len(), 1, "one synthetic match expected");
        resp.matches[0].outcome
    }

    async fn explain_response_for(
        reply: Option<ImportExplainReply>,
    ) -> proto::ExplainImportPolicyResponse {
        let (peer_tx, mut peer_rx) = mpsc::channel(8);
        let svc = PolicyService::new(AccessMode::ReadOnly, peer_tx, None, None);
        tokio::spawn(async move {
            while let Some(cmd) = peer_rx.recv().await {
                match cmd {
                    PeerManagerCommand::ExplainImportPolicy { reply: tx, .. } => {
                        let outcome = reply
                            .clone()
                            .map_or(SessionQueryOutcome::SessionGone, |reply| {
                                SessionQueryOutcome::Reply(Ok(reply))
                            });
                        let _ = tx.send(Some(outcome));
                    }
                    _ => panic!("unexpected peer-manager command"),
                }
            }
        });
        PolicyServiceRpc::explain_import_policy(&svc, Request::new(explain_request()))
            .await
            .expect("explain succeeds")
            .into_inner()
    }

    #[tokio::test]
    async fn explain_all_path_limit_is_resource_exhausted() {
        let (peer_tx, mut peer_rx) = mpsc::channel(8);
        let svc = PolicyService::new(AccessMode::ReadOnly, peer_tx, None, None);
        tokio::spawn(async move {
            if let Some(PeerManagerCommand::ExplainImportPolicy { reply, .. }) =
                peer_rx.recv().await
            {
                let _ = reply.send(Some(SessionQueryOutcome::Reply(Err(
                    rustbgpd_transport::AllPathMatchLimitExceeded,
                ))));
            }
        });
        let error = PolicyServiceRpc::explain_import_policy(&svc, Request::new(explain_request()))
            .await
            .expect_err("oversized all-path answer must fail");
        assert_eq!(error.code(), tonic::Code::ResourceExhausted);
        assert!(error.message().contains("--path-id"));
    }

    /// Drive `ListRejectedRoutes` against a fake peer manager that
    /// answers with `reply` (LAN-472).
    async fn list_rejected_routes_response(
        reply: Option<RejectedRoutesReply>,
    ) -> Result<proto::ListRejectedRoutesResponse, Status> {
        let (peer_tx, mut peer_rx) = mpsc::channel(8);
        let svc = PolicyService::new(AccessMode::ReadOnly, peer_tx, None, None);
        tokio::spawn(async move {
            while let Some(cmd) = peer_rx.recv().await {
                match cmd {
                    PeerManagerCommand::ListRejectedRoutes { reply: tx, .. } => {
                        let outcome = reply
                            .clone()
                            .map_or(SessionQueryOutcome::SessionGone, SessionQueryOutcome::Reply);
                        let _ = tx.send(Some(outcome));
                    }
                    _ => panic!("unexpected peer-manager command"),
                }
            }
        });
        let req = proto::ListRejectedRoutesRequest {
            peer_address: "10.0.0.2".to_string(),
        };
        PolicyServiceRpc::list_rejected_routes(&svc, Request::new(req))
            .await
            .map(tonic::Response::into_inner)
    }

    /// LAN-472: no live session is NOT an empty listing — the
    /// session-local store is gone, so the RPC reports `NOT_FOUND`.
    #[tokio::test]
    async fn list_rejected_routes_no_session_is_not_found() {
        let err = list_rejected_routes_response(None)
            .await
            .expect_err("no session must be an error");
        assert_eq!(err.code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn list_rejected_routes_zero_evictions_is_present() {
        let response = list_rejected_routes_response(Some(RejectedRoutesReply {
            enabled: true,
            capacity: 2,
            evictions_since_reset: 0,
            entries: vec![],
        }))
        .await
        .expect("listing succeeds");
        assert_eq!(response.evictions_since_reset, Some(0));
    }

    /// LAN-661 red proof: mapping a stalled live session back onto either
    /// absence branch changes these statuses to `success/NO_SESSION` and
    /// `NOT_FOUND`, respectively.
    #[tokio::test]
    async fn policy_query_timeouts_are_deadlines_not_absence() {
        let (peer_tx, mut peer_rx) = mpsc::channel(8);
        let svc = PolicyService::new(AccessMode::ReadOnly, peer_tx, None, None);
        tokio::spawn(async move {
            while let Some(cmd) = peer_rx.recv().await {
                match cmd {
                    PeerManagerCommand::ExplainImportPolicy { reply, .. } => {
                        let _ = reply.send(Some(SessionQueryOutcome::TimedOut));
                    }
                    PeerManagerCommand::ListRejectedRoutes { reply, .. } => {
                        let _ = reply.send(Some(SessionQueryOutcome::TimedOut));
                    }
                    _ => panic!("unexpected peer-manager command"),
                }
            }
        });

        let explain =
            PolicyServiceRpc::explain_import_policy(&svc, Request::new(explain_request()))
                .await
                .expect_err("stalled explain must fail");
        assert_eq!(explain.code(), tonic::Code::DeadlineExceeded);

        let rejected = PolicyServiceRpc::list_rejected_routes(
            &svc,
            Request::new(proto::ListRejectedRoutesRequest {
                peer_address: "10.0.0.2".to_string(),
            }),
        )
        .await
        .expect_err("stalled rejected-route query must fail");
        assert_eq!(rejected.code(), tonic::Code::DeadlineExceeded);
    }

    /// LAN-472: entries come back with the canonical reason token, the
    /// detail, the rendered prefix/next-hop, and the enabled/capacity
    /// facts the CLI renders.
    #[tokio::test]
    async fn list_rejected_routes_maps_entries_to_proto() {
        use rustbgpd_telemetry::reason_labels::ImportRejectReason;
        use rustbgpd_transport::{ImportDecisionKey, RejectedRouteEntry};
        let key = ImportDecisionKey {
            afi: Afi::Ipv4,
            safi: Safi::Unicast,
            prefix: Prefix::V4(Ipv4Prefix::new(
                std::net::Ipv4Addr::new(198, 51, 100, 0),
                24,
            )),
            path_id: 0,
        };
        let mut entry = RejectedRouteEntry {
            reason: ImportRejectReason::PolicyReject,
            detail: Some("member-import".to_string()),
            next_hop: Some(std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 2))),
            as_path: "65002 65010".to_string(),
            communities: vec![999],
            communities_dropped: 3,
            large_communities: Vec::new(),
            large_communities_dropped: 0,
            rpki: rustbgpd_wire::RpkiValidation::Invalid,
            aspa: rustbgpd_wire::AspaValidation::Unknown,
            aspa_invalid_hop: None,
            rejected_at: std::time::UNIX_EPOCH + Duration::from_secs(1),
        };
        entry.set_aspa_invalid_hop(65010, 65002);
        let resp = list_rejected_routes_response(Some(RejectedRoutesReply {
            enabled: true,
            capacity: 1024,
            evictions_since_reset: 3,
            entries: vec![(key, entry)],
        }))
        .await
        .expect("listing succeeds");
        assert!(resp.retention_enabled);
        assert_eq!(resp.capacity, 1024);
        assert_eq!(resp.evictions_since_reset, Some(3));
        assert_eq!(resp.routes.len(), 1);
        let r = &resp.routes[0];
        assert_eq!(r.prefix, "198.51.100.0");
        assert_eq!(r.prefix_length, 24);
        assert_eq!(r.afi_safi, proto::AddressFamily::Ipv4Unicast as i32);
        assert_eq!(r.reason, "policy_reject");
        assert_eq!(
            r.reason_detail,
            "member-import | aspa_not_provider customer=65010 provider=65002"
        );
        assert_eq!(r.next_hop, "10.0.0.2");
        assert_eq!(r.as_path, "65002 65010");
        assert_eq!(r.communities, vec![999]);
        assert_eq!(r.communities_dropped, 3);
        assert_eq!(r.large_communities_dropped, 0);
        assert_eq!(r.rpki_validation, "invalid");
        assert_eq!(r.aspa_validation, "unknown");
        assert_eq!(r.rejected_at_unix_ns, 1_000_000_000);
    }

    /// LAN-320: no live session must NOT read as `not_seen` — during an
    /// incident that sends the operator down a false path.
    #[tokio::test]
    async fn explain_no_session_reports_no_session() {
        assert_eq!(
            explain_outcome_for(None).await,
            proto::ImportExplainOutcome::NoSession as i32
        );
    }

    /// LAN-320: a live session whose cache never records decisions
    /// (`[policy.explain] enabled = false`) must report `CACHE_DISABLED`,
    /// not `not_seen`.
    #[tokio::test]
    async fn explain_cache_disabled_reports_cache_disabled() {
        assert_eq!(
            explain_outcome_for(Some(ImportExplainReply {
                current_generation: 0,
                cache_enabled: false,
                cache_size: 4096,
                evictions_since_reset: 0,
                matches: Vec::new(),
            }))
            .await,
            proto::ImportExplainOutcome::CacheDisabled as i32
        );
    }

    /// LAN-320: with the cache enabled and a live session, an unseen
    /// prefix is the genuine evaluated `not_seen` answer.
    #[tokio::test]
    async fn explain_enabled_unseen_prefix_reports_not_seen() {
        assert_eq!(
            explain_outcome_for(Some(ImportExplainReply {
                current_generation: 0,
                cache_enabled: true,
                cache_size: 4096,
                evictions_since_reset: 0,
                matches: Vec::new(),
            }))
            .await,
            proto::ImportExplainOutcome::NotSeen as i32
        );
    }

    /// The reply carries the cache cap and eviction count only when an
    /// enabled cache answered; otherwise they are absent, not zero.
    #[tokio::test]
    async fn explain_reports_cache_size_and_evictions() {
        let reply = |cache_enabled| {
            Some(ImportExplainReply {
                current_generation: 0,
                cache_enabled,
                cache_size: 4096,
                evictions_since_reset: 995_000,
                matches: vec![ResolvedMatch {
                    path_id: 0,
                    result: LookupResult::Evicted,
                    statements: Vec::new(),
                }],
            })
        };
        let resp = explain_response_for(reply(true)).await;
        assert_eq!(resp.cache_size, Some(4096));
        assert_eq!(resp.evictions_since_reset, Some(995_000));
        assert_eq!(
            resp.matches[0].outcome,
            proto::ImportExplainOutcome::Evicted as i32
        );

        let disabled = explain_response_for(reply(false)).await;
        assert_eq!(disabled.cache_size, None);
        assert_eq!(disabled.evictions_since_reset, None);
        let gone = explain_response_for(None).await;
        assert_eq!(gone.cache_size, None);
        assert_eq!(gone.evictions_since_reset, None);
    }

    #[tokio::test]
    async fn set_policy_emits_config_event_after_runtime_success() {
        let (peer_tx, mut peer_rx) = mpsc::channel(8);
        let (config_tx, mut config_rx) = mpsc::channel(4);
        let svc = PolicyService::new(AccessMode::ReadWrite, peer_tx, Some(config_tx), None);

        tokio::spawn(async move {
            while let Some(cmd) = peer_rx.recv().await {
                match cmd {
                    PeerManagerCommand::OwnedCatalogMutation {
                        mutation: OwnedCatalogMutation::SetPolicy { name, definition },
                        reply,
                    } => {
                        assert_eq!(name, "tag-internal");
                        assert_eq!(definition.default_action, "permit");
                        assert_eq!(definition.statements.len(), 1);
                        let _ = reply.send(OwnedCatalogMutationOutcome::Success);
                    }
                    _ => panic!("unexpected peer-manager command"),
                }
            }
        });

        let call = tokio::spawn(async move {
            PolicyServiceRpc::set_policy(
                &svc,
                Request::new(proto::SetPolicyRequest {
                    name: "tag-internal".into(),
                    definition: Some(sample_proto_definition()),
                }),
            )
            .await
        });

        match config_rx.recv().await {
            Some(ConfigEvent::SetPolicy {
                name,
                definition,
                ack,
            }) => {
                assert_eq!(name, "tag-internal");
                assert_eq!(definition.default_action, "permit");
                assert_eq!(definition.statements.len(), 1);
                ack.expect("persisted mutation must carry an ack")
                    .accept()
                    .await;
            }
            Some(_) => panic!("unexpected config event"),
            None => panic!("missing config event"),
        }

        let response = call.await.expect("call task must not panic");
        assert!(response.is_ok());
    }

    /// ADR-0076 contract: a `NACKed` persist rolls the runtime mutation
    /// back to the captured prior definition, so the RPC failure means
    /// "nothing changed" instead of leaving runtime ahead of disk.
    #[tokio::test]
    async fn set_policy_persist_failure_leaves_the_catalog_alone() {
        let (peer_tx, mut peer_rx) = mpsc::channel(8);
        let (config_tx, mut config_rx) = mpsc::channel(4);
        let svc = PolicyService::new(AccessMode::ReadWrite, peer_tx, Some(config_tx), None);

        let prior = NamedPolicyDefinition {
            default_action: "deny".to_string(),
            statements: Vec::new(),
        };
        let prior_for_pm = prior.clone();
        let set_definitions = std::sync::Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let set_definitions_pm = set_definitions.clone();
        tokio::spawn(async move {
            while let Some(cmd) = peer_rx.recv().await {
                match cmd {
                    PeerManagerCommand::GetPolicy { reply, .. } => {
                        let _ = reply.send(Some(prior_for_pm.clone()));
                    }
                    PeerManagerCommand::SetPolicy {
                        definition, reply, ..
                    } => {
                        set_definitions_pm.lock().await.push(definition);
                        let _ = reply.send(Ok(()));
                    }
                    _ => panic!("unexpected peer-manager command"),
                }
            }
        });

        let call = tokio::spawn(async move {
            PolicyServiceRpc::set_policy(
                &svc,
                Request::new(proto::SetPolicyRequest {
                    name: "tag-internal".into(),
                    definition: Some(sample_proto_definition()),
                }),
            )
            .await
        });

        match config_rx.recv().await {
            Some(ConfigEvent::SetPolicy { ack, .. }) => {
                ack.expect("persisted mutation must carry an ack")
                    .fail_write("disk full");
            }
            Some(_) => panic!("unexpected config event"),
            None => panic!("missing config event"),
        }

        let error = call
            .await
            .expect("call task must not panic")
            .expect_err("set_policy must fail when persistence fails");
        assert_eq!(error.code(), tonic::Code::FailedPrecondition);
        assert!(error.message().contains("config persistence failed"));

        // The old ordering applied the policy — re-evaluating live sessions
        // and driving a Route Refresh — and then applied the prior definition
        // as "rollback", so peers saw two rounds of churn for a request that
        // was rejected. The candidate is never applied now.
        assert!(
            set_definitions.lock().await.is_empty(),
            "a rejected policy set must not reach any live session"
        );
    }

    #[tokio::test]
    async fn set_policy_rejected_on_read_only_listener() {
        let (peer_tx, mut peer_rx) = mpsc::channel(4);
        let (config_tx, mut config_rx) = mpsc::channel(4);
        let svc = PolicyService::new(AccessMode::ReadOnly, peer_tx, Some(config_tx), None);

        let err = PolicyServiceRpc::set_policy(
            &svc,
            Request::new(proto::SetPolicyRequest {
                name: "tag-internal".into(),
                definition: Some(sample_proto_definition()),
            }),
        )
        .await
        .unwrap_err();

        assert_eq!(err.code(), tonic::Code::PermissionDenied);
        assert!(matches!(peer_rx.try_recv(), Err(TryRecvError::Empty)));
        assert!(matches!(config_rx.try_recv(), Err(TryRecvError::Empty)));
    }

    #[tokio::test]
    async fn policy_and_neighbor_set_mutations_rejected_on_read_only_listener() {
        let (peer_tx, mut peer_rx) = mpsc::channel(4);
        let (config_tx, mut config_rx) = mpsc::channel(4);
        let svc = PolicyService::new(AccessMode::ReadOnly, peer_tx, Some(config_tx), None);

        let err = PolicyServiceRpc::delete_policy(
            &svc,
            Request::new(proto::DeletePolicyRequest {
                name: "tag-internal".into(),
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);

        let err = PolicyServiceRpc::set_neighbor_set(
            &svc,
            Request::new(proto::SetNeighborSetRequest {
                name: "ix-clients".into(),
                definition: Some(proto::NeighborSetDefinition::default()),
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);

        let err = PolicyServiceRpc::delete_neighbor_set(
            &svc,
            Request::new(proto::DeleteNeighborSetRequest {
                name: "ix-clients".into(),
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);

        assert!(matches!(peer_rx.try_recv(), Err(TryRecvError::Empty)));
        assert!(matches!(config_rx.try_recv(), Err(TryRecvError::Empty)));
    }

    #[tokio::test]
    async fn global_chain_mutations_rejected_on_read_only_listener() {
        let (peer_tx, mut peer_rx) = mpsc::channel(4);
        let (config_tx, mut config_rx) = mpsc::channel(4);
        let svc = PolicyService::new(AccessMode::ReadOnly, peer_tx, Some(config_tx), None);

        let err = PolicyServiceRpc::set_global_import_chain(
            &svc,
            Request::new(proto::SetGlobalImportChainRequest {
                policy_names: vec!["tag-internal".into()],
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);

        let err = PolicyServiceRpc::set_global_export_chain(
            &svc,
            Request::new(proto::SetGlobalExportChainRequest {
                policy_names: vec!["tag-internal".into()],
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);

        let err = PolicyServiceRpc::clear_global_import_chain(
            &svc,
            Request::new(proto::ClearGlobalImportChainRequest {}),
        )
        .await
        .unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);

        let err = PolicyServiceRpc::clear_global_export_chain(
            &svc,
            Request::new(proto::ClearGlobalExportChainRequest {}),
        )
        .await
        .unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);

        assert!(matches!(peer_rx.try_recv(), Err(TryRecvError::Empty)));
        assert!(matches!(config_rx.try_recv(), Err(TryRecvError::Empty)));
    }

    #[tokio::test]
    async fn neighbor_chain_mutations_rejected_on_read_only_listener() {
        let (peer_tx, mut peer_rx) = mpsc::channel(4);
        let (config_tx, mut config_rx) = mpsc::channel(4);
        let svc = PolicyService::new(AccessMode::ReadOnly, peer_tx, Some(config_tx), None);

        let err = PolicyServiceRpc::set_neighbor_import_chain(
            &svc,
            Request::new(proto::SetNeighborImportChainRequest {
                address: "10.0.0.2".into(),
                policy_names: vec!["tag-internal".into()],
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);

        let err = PolicyServiceRpc::set_neighbor_export_chain(
            &svc,
            Request::new(proto::SetNeighborExportChainRequest {
                address: "10.0.0.2".into(),
                policy_names: vec!["tag-internal".into()],
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);

        let err = PolicyServiceRpc::clear_neighbor_import_chain(
            &svc,
            Request::new(proto::ClearNeighborImportChainRequest {
                address: "10.0.0.2".into(),
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);

        let err = PolicyServiceRpc::clear_neighbor_export_chain(
            &svc,
            Request::new(proto::ClearNeighborExportChainRequest {
                address: "10.0.0.2".into(),
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);

        assert!(matches!(peer_rx.try_recv(), Err(TryRecvError::Empty)));
        assert!(matches!(config_rx.try_recv(), Err(TryRecvError::Empty)));
    }

    #[tokio::test]
    async fn delete_policy_in_use_maps_to_failed_precondition() {
        let (peer_tx, mut peer_rx) = mpsc::channel(4);
        let (config_tx, mut config_rx) = mpsc::channel(4);
        let svc = PolicyService::new(AccessMode::ReadWrite, peer_tx, Some(config_tx), None);

        tokio::spawn(async move {
            while let Some(cmd) = peer_rx.recv().await {
                match cmd {
                    PeerManagerCommand::OwnedCatalogMutation {
                        mutation: OwnedCatalogMutation::DeletePolicy { name },
                        reply,
                    } => {
                        assert_eq!(name, "tag-internal");
                        let _ = reply.send(OwnedCatalogMutationOutcome::RejectedNoEffect(
                            CatalogMutationError::StillReferenced {
                                kind: "policy",
                                name: "tag-internal".into(),
                                references: vec!["global import_chain".into()],
                            },
                        ));
                    }
                    _ => panic!("unexpected peer-manager command"),
                }
            }
        });

        // The write is staged first, so this also proves the other half of
        // the handshake: a runtime mutation the peer manager refuses discards
        // the staged write instead of publishing it.
        let staged = tokio::spawn(async move {
            match config_rx.recv().await {
                Some(ConfigEvent::DeletePolicy { ack, .. }) => {
                    ack.expect("persisted mutation must carry an ack")
                        .accept()
                        .await
                }
                Some(_) => panic!("unexpected config event"),
                None => panic!("missing config event"),
            }
        });

        let error = PolicyServiceRpc::delete_policy(
            &svc,
            Request::new(proto::DeletePolicyRequest {
                name: "tag-internal".into(),
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(error.code(), tonic::Code::FailedPrecondition);
        assert!(
            !staged.await.expect("config task must not panic"),
            "a refused runtime delete must discard the staged write"
        );
    }

    #[tokio::test]
    async fn delete_policy_persist_failure_leaves_the_catalog_alone() {
        let (peer_tx, mut peer_rx) = mpsc::channel(8);
        let (config_tx, mut config_rx) = mpsc::channel(4);
        let svc = PolicyService::new(AccessMode::ReadWrite, peer_tx, Some(config_tx), None);

        let prior = NamedPolicyDefinition {
            default_action: "deny".to_string(),
            statements: Vec::new(),
        };
        let prior_for_pm = prior.clone();
        let set_definitions = std::sync::Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let set_definitions_pm = set_definitions.clone();
        tokio::spawn(async move {
            while let Some(cmd) = peer_rx.recv().await {
                match cmd {
                    PeerManagerCommand::GetPolicy { reply, .. } => {
                        let _ = reply.send(Some(prior_for_pm.clone()));
                    }
                    PeerManagerCommand::DeletePolicy { reply, .. } => {
                        let _ = reply.send(Ok(()));
                    }
                    PeerManagerCommand::SetPolicy {
                        definition, reply, ..
                    } => {
                        set_definitions_pm.lock().await.push(definition);
                        let _ = reply.send(Ok(()));
                    }
                    _ => panic!("unexpected peer-manager command"),
                }
            }
        });

        let call = tokio::spawn(async move {
            PolicyServiceRpc::delete_policy(
                &svc,
                Request::new(proto::DeletePolicyRequest {
                    name: "tag-internal".into(),
                }),
            )
            .await
        });

        match config_rx.recv().await {
            Some(ConfigEvent::DeletePolicy { ack, .. }) => {
                ack.expect("persisted mutation must carry an ack")
                    .fail_write("disk full");
            }
            Some(_) => panic!("unexpected config event"),
            None => panic!("missing config event"),
        }

        let error = call
            .await
            .expect("call task must not panic")
            .expect_err("delete_policy must fail when persistence fails");
        assert_eq!(error.code(), tonic::Code::FailedPrecondition);

        assert!(
            set_definitions.lock().await.is_empty(),
            "a rejected policy delete must not re-create anything, because it \
             never deleted anything"
        );
        drop(prior);
    }

    #[tokio::test]
    async fn set_global_import_chain_persist_failure_leaves_the_chain_alone() {
        let (peer_tx, mut peer_rx) = mpsc::channel(8);
        let (config_tx, mut config_rx) = mpsc::channel(4);
        let svc = PolicyService::new(AccessMode::ReadWrite, peer_tx, Some(config_tx), None);

        let set_chains = std::sync::Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let set_chains_pm = set_chains.clone();
        tokio::spawn(async move {
            while let Some(cmd) = peer_rx.recv().await {
                match cmd {
                    PeerManagerCommand::GetGlobalPolicyChains { reply } => {
                        let _ = reply.send(crate::peer_types::PolicyChainAssignment {
                            import_policy_names: vec!["prior-import".to_string()],
                            export_policy_names: Vec::new(),
                        });
                    }
                    PeerManagerCommand::SetGlobalImportChain {
                        policy_names,
                        reply,
                    } => {
                        set_chains_pm.lock().await.push(policy_names);
                        let _ = reply.send(Ok(()));
                    }
                    _ => panic!("unexpected peer-manager command"),
                }
            }
        });

        let call = tokio::spawn(async move {
            PolicyServiceRpc::set_global_import_chain(
                &svc,
                Request::new(proto::SetGlobalImportChainRequest {
                    policy_names: vec!["tag-internal".into()],
                }),
            )
            .await
        });

        match config_rx.recv().await {
            Some(ConfigEvent::SetGlobalImportChain { policy_names, ack }) => {
                assert_eq!(policy_names, vec!["tag-internal".to_string()]);
                ack.expect("persisted mutation must carry an ack")
                    .fail_write("disk full");
            }
            Some(_) => panic!("unexpected config event"),
            None => panic!("missing config event"),
        }

        let error = call
            .await
            .expect("call task must not panic")
            .expect_err("set_global_import_chain must fail when persistence fails");
        assert_eq!(error.code(), tonic::Code::FailedPrecondition);

        assert!(
            set_chains.lock().await.is_empty(),
            "a rejected chain set must not reach any live session"
        );
    }

    /// The staged write is discarded rather than compensated, so an empty
    /// prior chain needs no clear command to restore it.
    #[tokio::test]
    async fn set_global_import_chain_persist_failure_issues_no_clear() {
        let (peer_tx, mut peer_rx) = mpsc::channel(8);
        let (config_tx, mut config_rx) = mpsc::channel(4);
        let svc = PolicyService::new(AccessMode::ReadWrite, peer_tx, Some(config_tx), None);

        let cleared = std::sync::Arc::new(tokio::sync::Mutex::new(0_u32));
        let cleared_pm = cleared.clone();
        tokio::spawn(async move {
            while let Some(cmd) = peer_rx.recv().await {
                match cmd {
                    PeerManagerCommand::GetGlobalPolicyChains { reply } => {
                        let _ = reply.send(crate::peer_types::PolicyChainAssignment::default());
                    }
                    PeerManagerCommand::SetGlobalImportChain { reply, .. } => {
                        let _ = reply.send(Ok(()));
                    }
                    PeerManagerCommand::ClearGlobalImportChain { reply } => {
                        *cleared_pm.lock().await += 1;
                        let _ = reply.send(Ok(()));
                    }
                    _ => panic!("unexpected peer-manager command"),
                }
            }
        });

        let call = tokio::spawn(async move {
            PolicyServiceRpc::set_global_import_chain(
                &svc,
                Request::new(proto::SetGlobalImportChainRequest {
                    policy_names: vec!["tag-internal".into()],
                }),
            )
            .await
        });

        match config_rx.recv().await {
            Some(ConfigEvent::SetGlobalImportChain { ack, .. }) => {
                ack.expect("persisted mutation must carry an ack")
                    .fail_write("disk full");
            }
            Some(_) => panic!("unexpected config event"),
            None => panic!("missing config event"),
        }

        let error = call
            .await
            .expect("call task must not panic")
            .expect_err("set_global_import_chain must fail when persistence fails");
        assert_eq!(error.code(), tonic::Code::FailedPrecondition);
        assert_eq!(
            *cleared.lock().await,
            0,
            "nothing was applied, so nothing needs clearing"
        );
    }

    #[tokio::test]
    async fn set_neighbor_import_chain_persist_failure_leaves_the_chain_alone() {
        let (peer_tx, mut peer_rx) = mpsc::channel(8);
        let (config_tx, mut config_rx) = mpsc::channel(4);
        let svc = PolicyService::new(AccessMode::ReadWrite, peer_tx, Some(config_tx), None);

        let set_chains = std::sync::Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let set_chains_pm = set_chains.clone();
        tokio::spawn(async move {
            while let Some(cmd) = peer_rx.recv().await {
                match cmd {
                    PeerManagerCommand::GetNeighborPolicyChains { reply, .. } => {
                        let _ = reply.send(Some(crate::peer_types::PolicyChainAssignment {
                            import_policy_names: vec!["prior-import".to_string()],
                            export_policy_names: vec!["prior-export".to_string()],
                        }));
                    }
                    PeerManagerCommand::SetNeighborImportChain {
                        address,
                        policy_names,
                        reply,
                    } => {
                        assert_eq!(address.to_string(), "10.0.0.2");
                        set_chains_pm.lock().await.push(policy_names);
                        let _ = reply.send(Ok(()));
                    }
                    _ => panic!("unexpected peer-manager command"),
                }
            }
        });

        let call = tokio::spawn(async move {
            PolicyServiceRpc::set_neighbor_import_chain(
                &svc,
                Request::new(proto::SetNeighborImportChainRequest {
                    address: "10.0.0.2".into(),
                    policy_names: vec!["tag-internal".into()],
                }),
            )
            .await
        });

        match config_rx.recv().await {
            Some(ConfigEvent::SetNeighborImportChain {
                address,
                interface,
                policy_names,
                ack,
            }) => {
                assert_eq!(address.to_string(), "10.0.0.2");
                assert_eq!(interface, None);
                assert_eq!(policy_names, vec!["tag-internal".to_string()]);
                ack.expect("persisted mutation must carry an ack")
                    .fail_write("disk full");
            }
            Some(_) => panic!("unexpected config event"),
            None => panic!("missing config event"),
        }

        let error = call
            .await
            .expect("call task must not panic")
            .expect_err("set_neighbor_import_chain must fail when persistence fails");
        assert_eq!(error.code(), tonic::Code::FailedPrecondition);

        assert!(
            set_chains.lock().await.is_empty(),
            "a rejected per-neighbor chain set must not reach the session"
        );
    }

    // ── TestPolicy (ADR-0096 Decision 6) ────────────────────────────

    const TEST_RPOL: &str = r"
prefix-set customers { 10.10.0.0/16 ge 24 le 28 }

policy customer-in(peer_lp: u32) {
    term customer-routes {
        if route.prefix in customers { set local-pref peer_lp; accept }
    }
    term everything-else { reject }
}
";

    fn test_route(prefix: &str, len: u8) -> rustbgpd_rib::Route {
        let addr: std::net::Ipv4Addr = prefix.parse().unwrap();
        test_route_prefix(Prefix::V4(Ipv4Prefix::new(addr, len)))
    }

    fn test_route_prefix(prefix: Prefix) -> rustbgpd_rib::Route {
        rustbgpd_rib::Route {
            prefix,
            next_hop: "10.0.0.9".parse().unwrap(),
            link_local_next_hop: None,
            next_hop_scope: None,
            peer: PeerId::from_addr("10.0.0.9".parse().unwrap()),
            attributes: AttrSet::new(Vec::new()),
            received_at: rustbgpd_rib::route::ReceivedAt::now(),
            origin_type: rustbgpd_rib::RouteOrigin::Ebgp,
            peer_router_id: std::net::Ipv4Addr::UNSPECIFIED,
            is_stale: false,
            is_llgr_stale: false,
            path_id: 0,
            validation_state: rustbgpd_wire::RpkiValidation::NotFound,
            aspa_state: rustbgpd_wire::AspaValidation::Unknown,
            received_as_path: None,
            aspa_context: rustbgpd_rib::route::AspaContextId::DEFAULT,
        }
    }

    /// An injected route's unspecified next hop is already next-hop self, so
    /// adding `set next-hop self` does not change what it exports; a received
    /// route keeps the distinction.
    #[test]
    fn exported_attributes_treat_injected_unspecified_next_hop_as_self() {
        let self_mods = rustbgpd_policy::RouteModifications {
            set_next_hop: Some(rustbgpd_policy::NextHopAction::Self_),
            ..Default::default()
        };
        let mut route = test_route("203.0.113.0", 24);
        route.next_hop = std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED);
        assert_ne!(
            exported_attributes(&route, &rustbgpd_policy::RouteModifications::default()),
            exported_attributes(&route, &self_mods)
        );
        route.origin_type = rustbgpd_rib::RouteOrigin::Local;
        assert_eq!(
            exported_attributes(&route, &rustbgpd_policy::RouteModifications::default()),
            exported_attributes(&route, &self_mods)
        );
    }

    fn customer_route(index: u32) -> rustbgpd_rib::Route {
        let base = u32::from(std::net::Ipv4Addr::new(10, 10, 0, 0));
        test_route_prefix(Prefix::V4(Ipv4Prefix::new((base + index * 16).into(), 28)))
    }

    fn ipv6_route(index: u16) -> rustbgpd_rib::Route {
        test_route_prefix(Prefix::V6(Ipv6Prefix::new(
            std::net::Ipv6Addr::new(0x2001, 0xdb8, index, 0, 0, 0, 0, 0),
            64,
        )))
    }

    /// Fake paged RIB plus peer-context backends. The RIB side enforces the
    /// production page cap, unfiltered request, fixed first-page version, and
    /// strict canonical cursor while recording cross-actor command order.
    fn test_policy_service_with(
        routes: Vec<rustbgpd_rib::Route>,
        failure: Option<(usize, rustbgpd_rib::RoutePageError)>,
    ) -> (PolicyService, Arc<Mutex<Vec<String>>>) {
        policy_dry_run_service(routes, failure, None)
    }

    /// [`test_policy_service_with`] whose RIB also answers the installed
    /// export-chain query (`None` = the peer has no outbound registration).
    fn policy_dry_run_service(
        routes: Vec<rustbgpd_rib::Route>,
        failure: Option<(usize, rustbgpd_rib::RoutePageError)>,
        installed: Option<rustbgpd_rib::InstalledExportChain>,
    ) -> (PolicyService, Arc<Mutex<Vec<String>>>) {
        policy_dry_run_service_with_peers(routes, failure, installed, Vec::new())
    }

    /// [`policy_dry_run_service`] whose peer manager lists `peers`.
    fn policy_dry_run_service_with_peers(
        mut routes: Vec<rustbgpd_rib::Route>,
        failure: Option<(usize, rustbgpd_rib::RoutePageError)>,
        installed: Option<rustbgpd_rib::InstalledExportChain>,
        peers: Vec<crate::peer_types::PeerInfo>,
    ) -> (PolicyService, Arc<Mutex<Vec<String>>>) {
        routes.sort_unstable_by_key(rustbgpd_rib::route_query_key);
        let commands = Arc::new(Mutex::new(Vec::new()));
        let (peer_tx, mut peer_rx) = mpsc::channel(8);
        let (rib_tx, mut rib_rx) = mpsc::channel::<rustbgpd_rib::RibUpdate>(8);
        let peer_commands = Arc::clone(&commands);
        tokio::spawn(async move {
            while let Some(cmd) = peer_rx.recv().await {
                match cmd {
                    PeerManagerCommand::ListPeers { reply } => {
                        peer_commands.lock().unwrap().push("peers".to_string());
                        let _ = reply.send(peers.clone());
                    }
                    _ => panic!("unexpected peer-manager command"),
                }
            }
        });
        let rib_commands = Arc::clone(&commands);
        tokio::spawn(async move {
            let version = rustbgpd_rib::RoutePageVersion {
                epoch: 7,
                generation: 11,
            };
            let mut query_index = 0;
            let mut last_cursor = None;
            while let Some(update) = rib_rx.recv().await {
                match update {
                    rustbgpd_rib::RibUpdate::QueryRoutesPage {
                        scope,
                        filter,
                        after,
                        expected_version,
                        page_size,
                        reply,
                    } => {
                        assert!(filter.is_none());
                        assert_eq!(page_size, TEST_POLICY_PAGE_SIZE);
                        assert_eq!(after, last_cursor);
                        assert_eq!(expected_version, (query_index != 0).then_some(version));
                        rib_commands
                            .lock()
                            .unwrap()
                            .push(format!("page:{query_index}"));
                        if failure.is_some_and(|(at, _)| at == query_index) {
                            let _ = reply.send(Err(failure.unwrap().1));
                            continue;
                        }
                        let scoped: Vec<_> = routes
                            .iter()
                            .filter(|route| match scope {
                                rustbgpd_rib::RouteQueryScope::Received { peer } => {
                                    peer.is_none_or(|peer| route.peer == peer)
                                }
                                rustbgpd_rib::RouteQueryScope::Best => true,
                                rustbgpd_rib::RouteQueryScope::Advertised { .. } => false,
                            })
                            .filter(|route| {
                                after.is_none_or(|cursor| {
                                    rustbgpd_rib::route_query_key(route) > cursor
                                })
                            })
                            .collect();
                        let page_routes: Vec<_> = scoped
                            .iter()
                            .take(page_size)
                            .map(|route| (*route).clone())
                            .collect();
                        let has_more = scoped.len() > page_routes.len();
                        last_cursor = page_routes.last().map(rustbgpd_rib::route_query_key);
                        query_index += 1;
                        let _ = reply.send(Ok(rustbgpd_rib::RoutePage {
                            peer_scope: rustbgpd_rib::PeerScope::default(),
                            routes: page_routes,
                            total: scoped.len() as u64,
                            has_more,
                            version,
                            injection: Vec::new(),
                        }));
                    }
                    rustbgpd_rib::RibUpdate::QueryInstalledExportChain { reply, .. } => {
                        rib_commands.lock().unwrap().push("chain".to_string());
                        let _ = reply.send(installed.clone());
                    }
                    _ => panic!("unexpected RIB query"),
                }
            }
        });
        (
            PolicyService::new(AccessMode::ReadOnly, peer_tx, None, None).with_rib_query(rib_tx),
            commands,
        )
    }

    fn conditional_status(name: &str) -> rustbgpd_rib::ConditionalAdvertisementStatus {
        rustbgpd_rib::ConditionalAdvertisementStatus {
            name: Arc::from(name),
            advertise_if: rustbgpd_rib::ConditionalAdvertiseIf::Absent,
            conditions: vec![
                rustbgpd_rib::ConditionEntryStatus {
                    entry: rustbgpd_policy::sets::PrefixSetEntry::exact(rustbgpd_wire::Prefix::V4(
                        rustbgpd_wire::Ipv4Prefix::new(std::net::Ipv4Addr::UNSPECIFIED, 0),
                    )),
                    state: "present",
                    present_count: 1,
                    present_sample: vec![rustbgpd_wire::Prefix::V4(
                        rustbgpd_wire::Ipv4Prefix::new(std::net::Ipv4Addr::UNSPECIFIED, 0),
                    )],
                },
                rustbgpd_rib::ConditionEntryStatus {
                    entry: rustbgpd_policy::sets::PrefixSetEntry {
                        prefix: rustbgpd_wire::Prefix::V6(rustbgpd_wire::Ipv6Prefix::new(
                            "2001:db8::".parse().unwrap(),
                            32,
                        )),
                        ge: Some(48),
                        le: Some(64),
                    },
                    state: "absent",
                    present_count: 0,
                    present_sample: vec![],
                },
            ],
            observed: "present",
            observed_for: Duration::from_millis(1_250),
            applied: "advertise",
            settle_time: Duration::from_secs(5),
            settle_remaining: Some(Duration::from_millis(3_750)),
            selection_deferred: false,
            attached_peers: vec!["192.0.2.1".parse().unwrap(), "fe80::2".parse().unwrap()],
            attached_neighbors: vec![
                rustbgpd_rib::PeerEndpoint::new("192.0.2.1".parse().unwrap(), None),
                rustbgpd_rib::PeerEndpoint::new("fe80::2".parse().unwrap(), Some("eth0")),
            ],
        }
    }

    /// The RIB reply maps field for field; an unarmed timer reports zero.
    #[tokio::test]
    async fn list_conditional_advertisements_maps_the_rib_status() {
        let (peer_tx, _peer_rx) = mpsc::channel(1);
        let (rib_tx, mut rib_rx) = mpsc::channel(1);
        let service =
            PolicyService::new(AccessMode::ReadOnly, peer_tx, None, None).with_rib_query(rib_tx);
        tokio::spawn(async move {
            let Some(rustbgpd_rib::RibUpdate::QueryConditionalAdvertisements { reply }) =
                rib_rx.recv().await
            else {
                panic!("expected the conditional status query");
            };
            let mut settled = conditional_status("core");
            settled.settle_remaining = None;
            let _ = reply.send(vec![conditional_status("backup"), settled]);
        });
        let response = PolicyServiceRpc::list_conditional_advertisements(
            &service,
            Request::new(proto::ListConditionalAdvertisementsRequest {}),
        )
        .await
        .unwrap()
        .into_inner();
        assert_eq!(
            response.definitions[0],
            proto::ConditionalAdvertisementStatus {
                name: "backup".to_string(),
                advertise_if: "absent".to_string(),
                conditions: vec![
                    proto::ConditionalAdvertisementCondition {
                        prefix: "0.0.0.0/0".to_string(),
                        state: "present".to_string(),
                        ge: None,
                        le: None,
                        present_prefix_count: 1,
                        present_prefixes: vec!["0.0.0.0/0".to_string()],
                    },
                    proto::ConditionalAdvertisementCondition {
                        prefix: "2001:db8::/32".to_string(),
                        state: "absent".to_string(),
                        ge: Some(48),
                        le: Some(64),
                        present_prefix_count: 0,
                        present_prefixes: vec![],
                    },
                ],
                observed: "present".to_string(),
                observed_for_ms: 1_250,
                applied: "advertise".to_string(),
                settle_time_seconds: 5,
                settle_pending: true,
                settle_remaining_ms: 3_750,
                selection_deferred: false,
                attached_peers: vec!["192.0.2.1".to_string(), "fe80::2".to_string()],
                attached_neighbors: vec![
                    proto::ConditionalAdvertisementNeighbor {
                        peer_address: "192.0.2.1".to_string(),
                        peer_interface: String::new(),
                    },
                    proto::ConditionalAdvertisementNeighbor {
                        peer_address: "fe80::2".to_string(),
                        peer_interface: "eth0".to_string(),
                    },
                ],
            }
        );
        assert_eq!(response.definitions[1].name, "core");
        assert!(!response.definitions[1].settle_pending);
        assert_eq!(response.definitions[1].settle_remaining_ms, 0);
    }

    /// A RIB that admits the query but never replies fails the read at its
    /// 2 s deadline instead of holding the RPC until client cancel.
    #[tokio::test(start_paused = true)]
    async fn list_conditional_advertisements_stops_at_its_deadline() {
        let (peer_tx, _peer_rx) = mpsc::channel(1);
        let (rib_tx, mut rib_rx) = mpsc::channel(1);
        let service =
            PolicyService::new(AccessMode::ReadOnly, peer_tx, None, None).with_rib_query(rib_tx);
        let held = tokio::spawn(async move { rib_rx.recv().await });
        let started = tokio::time::Instant::now();
        let error = PolicyServiceRpc::list_conditional_advertisements(
            &service,
            Request::new(proto::ListConditionalAdvertisementsRequest {}),
        )
        .await
        .unwrap_err();
        assert_eq!(error.code(), tonic::Code::DeadlineExceeded);
        assert_eq!(started.elapsed(), CONDITIONAL_STATUS_TIMEOUT);
        assert!(matches!(
            held.await.unwrap(),
            Some(rustbgpd_rib::RibUpdate::QueryConditionalAdvertisements { .. })
        ));
    }

    fn test_policy_service(routes: Vec<rustbgpd_rib::Route>) -> PolicyService {
        test_policy_service_with(routes, None).0
    }

    #[tokio::test(start_paused = true)]
    async fn test_policy_uses_operator_peer_context_while_plain_commands_are_parked() {
        let (peer_tx, mut peer_rx) = mpsc::channel(1);
        let (operator_tx, mut operator_rx) = mpsc::channel(1);
        let (rib_tx, mut rib_rx) = mpsc::channel(1);
        let service = PolicyService::new(AccessMode::ReadOnly, peer_tx, None, None)
            .with_operator_queries(operator_tx)
            .with_rib_query(rib_tx);
        let rib = tokio::spawn(async move {
            let rustbgpd_rib::RibUpdate::QueryRoutesPage { reply, .. } =
                rib_rx.recv().await.unwrap()
            else {
                panic!("the dry run starts its versioned route snapshot first");
            };
            reply
                .send(Ok(rustbgpd_rib::RoutePage {
                    routes: vec![test_route("10.10.1.0", 24)],
                    total: 1,
                    ..Default::default()
                }))
                .unwrap();
        });
        let operator = tokio::spawn(async move {
            let PeerManagerOperatorQuery::ListPeers { reply } =
                operator_rx.recv().await.unwrap().query
            else {
                panic!("peer context must use the operator lane");
            };
            let mut info = crate::test_support::peer_info("10.0.0.9".parse().unwrap());
            info.remote_asn = 65042;
            info.peer_group = Some("customers".to_string());
            reply.send(vec![info]).unwrap();
        });
        let response = tokio::time::timeout(
            Duration::from_secs(1),
            PolicyServiceRpc::test_policy(
                &service,
                Request::new(proto::TestPolicyRequest {
                    rpol_source: r#"policy candidate {
                        term member {
                            if peer.asn == 65042 && peer.group == "customers" { accept }
                        }
                        term other { reject }
                    }"#
                    .to_string(),
                    policy: "candidate".to_string(),
                    ..test_policy_request()
                }),
            ),
        )
        .await
        .expect("the peer-context read does not wait for ordinary commands")
        .unwrap()
        .into_inner();
        assert_eq!((response.routes_evaluated, response.accepted), (1, 1));
        assert!(matches!(
            peer_rx.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
        operator.await.unwrap();
        rib.await.unwrap();
    }

    #[tokio::test]
    async fn test_policy_reports_counts_term_hits_and_diffs() {
        let svc = test_policy_service(vec![
            test_route("10.10.1.0", 24),
            test_route("10.10.2.0", 24),
            test_route("203.0.113.0", 24),
        ]);
        let resp = PolicyServiceRpc::test_policy(
            &svc,
            Request::new(proto::TestPolicyRequest {
                rpol_source: TEST_RPOL.to_string(),
                policy: "customer-in(200)".to_string(),
                direction: "import".to_string(),
                peer: String::new(),
                afi_safi: proto::AddressFamily::Unspecified as i32,
                limit: 0,
                show_changes: 1,
                ..Default::default()
            }),
        )
        .await
        .expect("dry run succeeds")
        .into_inner();

        assert!(resp.compiled, "{}", resp.diagnostics);
        assert_eq!(resp.routes_evaluated, 3);
        assert_eq!(resp.accepted, 2);
        assert_eq!(resp.rejected, 1);
        assert_eq!(resp.modified, 2);
        // Per-term hit counters, named from the source.
        assert_eq!(resp.term_hits.len(), 2);
        assert_eq!(resp.term_hits[0].term, "customer-routes");
        assert_eq!(resp.term_hits[0].hits, 2);
        assert_eq!(resp.term_hits[1].term, "everything-else");
        assert_eq!(resp.term_hits[1].hits, 1);
        // Diff samples are capped by show_changes and render
        // before/after values (LOCAL_PREF absent on the route).
        assert_eq!(resp.diffs.len(), 1);
        assert_eq!(resp.diffs[0].prefix, "10.10.1.0");
        assert_eq!(resp.diffs[0].prefix_length, 24);
        assert_eq!(resp.diffs[0].changes, vec!["local_pref unset -> 200"]);
    }

    /// Diff and rejected samples name a link-local source as a bare address
    /// plus the interface recorded with the route; numbered sources carry
    /// no interface.
    #[tokio::test]
    async fn test_policy_samples_carry_the_source_interface() {
        let svc = test_policy_service(vec![
            scoped_route("10.10.1.0", "eth0"),
            test_route("10.10.2.0", 24),
            scoped_route("203.0.113.0", "eth1"),
            test_route("203.0.114.0", 24),
        ]);
        let resp = PolicyServiceRpc::test_policy(
            &svc,
            Request::new(proto::TestPolicyRequest {
                show_changes: 2,
                show_rejected: 2,
                ..test_policy_request()
            }),
        )
        .await
        .expect("dry run succeeds")
        .into_inner();
        let diffs: Vec<(&str, &str, &str)> = resp
            .diffs
            .iter()
            .map(|d| {
                (
                    d.prefix.as_str(),
                    d.peer.as_str(),
                    d.peer_interface.as_str(),
                )
            })
            .collect();
        let numbered = test_route("10.10.2.0", 24).peer.to_string();
        assert_eq!(
            diffs,
            [
                ("10.10.1.0", LINK_LOCAL, "eth0"),
                ("10.10.2.0", numbered.as_str(), "")
            ]
        );
        let rejected: Vec<(&str, &str, &str)> = resp
            .rejected_routes
            .iter()
            .map(|r| {
                (
                    r.prefix.as_str(),
                    r.peer.as_str(),
                    r.peer_interface.as_str(),
                )
            })
            .collect();
        assert_eq!(
            rejected,
            [
                ("203.0.113.0", LINK_LOCAL, "eth1"),
                ("203.0.114.0", numbered.as_str(), "")
            ]
        );
    }

    #[tokio::test]
    async fn test_policy_compile_diagnostics_come_back_in_response() {
        let svc = test_policy_service(Vec::new());
        let resp = PolicyServiceRpc::test_policy(
            &svc,
            Request::new(proto::TestPolicyRequest {
                rpol_source: "policy p { term t { if route.nosuch == 1 { reject } } }".to_string(),
                policy: "p".to_string(),
                direction: "import".to_string(),
                peer: String::new(),
                afi_safi: 0,
                limit: 0,
                show_changes: 0,
                ..Default::default()
            }),
        )
        .await
        .expect("compile failure is a successful RPC")
        .into_inner();
        assert!(!resp.compiled);
        assert!(
            resp.diagnostics.contains("candidate.rpol"),
            "{}",
            resp.diagnostics
        );
        assert_eq!(resp.routes_evaluated, 0);
    }

    /// A candidate source that references a dataset compiles per the
    /// language (LAN-305) but has no file bindings in a dry run — the
    /// RPC must reject it, not panic in `compile_policy`.
    #[tokio::test]
    async fn test_policy_rejects_dataset_referencing_source() {
        let svc = test_policy_service(Vec::new());
        let source = "dataset asn-set customers\n\n\
                      policy origin-guard {\n\
                          term members { if route.origin-as in customers { accept } }\n\
                          term rest { reject }\n\
                      }\n";
        let status = PolicyServiceRpc::test_policy(
            &svc,
            Request::new(proto::TestPolicyRequest {
                rpol_source: source.to_string(),
                policy: "origin-guard".to_string(),
                direction: "import".to_string(),
                peer: String::new(),
                afi_safi: 0,
                limit: 0,
                show_changes: 0,
                ..Default::default()
            }),
        )
        .await
        .expect_err("dataset-referencing source must be rejected");
        assert_eq!(status.code(), tonic::Code::InvalidArgument);
        assert!(
            status.message().contains("customers"),
            "{}",
            status.message()
        );
    }

    fn golden_candidate_dataset(name: &str, entries: &str) -> proto::TestPolicyDataset {
        proto::TestPolicyDataset {
            name: format!("client-as4242-1-{name}"),
            entries: entries.to_string(),
        }
    }

    fn golden_candidate_request(prefixes: &str) -> proto::TestPolicyRequest {
        proto::TestPolicyRequest {
            rpol_source: include_str!(
                "../../../tools/rs-config-render/tests/golden/client-as4242-1.rpol"
            )
            .to_string(),
            policy: "client-as4242-1".to_string(),
            peer: "10.0.0.9".to_string(),
            datasets: vec![
                golden_candidate_dataset("origins", "64496\n"),
                golden_candidate_dataset("prefixes", prefixes),
            ],
            show_rejected: 1,
            ..test_policy_request()
        }
    }

    #[tokio::test]
    async fn test_policy_golden_candidate_prefix_drop_names_exact_route() {
        let mut carried = vec![test_route("192.0.2.0", 24), test_route("192.0.2.128", 25)];
        for route in &mut carried {
            route.attributes = AttrSet::new(vec![rustbgpd_wire::PathAttribute::AsPath(
                rustbgpd_wire::AsPath {
                    segments: vec![rustbgpd_wire::AsPathSegment::AsSequence(vec![64496])],
                },
            )]);
        }
        let svc = test_policy_service(carried.clone());
        let full = PolicyServiceRpc::test_policy(
            &svc,
            Request::new(golden_candidate_request("192.0.2.0/24\n192.0.2.128/25\n")),
        )
        .await
        .unwrap()
        .into_inner();
        assert_eq!(
            (full.routes_evaluated, full.accepted, full.rejected),
            (2, 2, 0)
        );
        assert_eq!(full.rejected_routes.len(), 0);

        let svc = test_policy_service(carried);
        let removed = PolicyServiceRpc::test_policy(
            &svc,
            Request::new(golden_candidate_request("192.0.2.0/24\n")),
        )
        .await
        .unwrap()
        .into_inner();
        assert_eq!(
            (removed.routes_evaluated, removed.accepted, removed.rejected),
            (2, 1, 1)
        );
        assert_eq!(removed.rejected_routes.len(), 1);
        assert_eq!(removed.rejected_routes[0].prefix, "192.0.2.128");
        assert_eq!(removed.rejected_routes[0].prefix_length, 25);
        assert_eq!(removed.rejected_routes[0].peer, "10.0.0.9");
    }

    #[tokio::test]
    async fn test_policy_rejects_invalid_candidate_bindings() {
        let svc = test_policy_service(Vec::new());
        for (datasets, expected) in [
            (
                vec![golden_candidate_dataset("prefixes", "192.0.2.0/24\n")],
                "client-as4242-1-origins",
            ),
            (
                vec![
                    golden_candidate_dataset("origins", "64496\n"),
                    golden_candidate_dataset("origins", "64496\n"),
                ],
                "duplicate candidate dataset",
            ),
            (
                vec![golden_candidate_dataset("prefixes", "bogus\n")],
                "line 1",
            ),
            (
                vec![golden_candidate_dataset("unknown", "64496\n")],
                "not declared",
            ),
        ] {
            let status = PolicyServiceRpc::test_policy(
                &svc,
                Request::new(proto::TestPolicyRequest {
                    datasets,
                    ..golden_candidate_request("192.0.2.0/24\n")
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(status.code(), tonic::Code::InvalidArgument);
            assert!(status.message().contains(expected), "{status}");
        }
    }

    #[tokio::test]
    async fn test_policy_candidate_size_and_sample_bounds() {
        use prost::Message;

        let svc = test_policy_service(Vec::new());
        let mut admitted = test_policy_request();
        admitted.rpol_source.push_str("\n#");
        admitted.rpol_source.push_str(
            &"x".repeat(TEST_POLICY_MAX_REQUEST_BYTES - 256 - admitted.rpol_source.len()),
        );
        assert!(admitted.encoded_len() > TEST_POLICY_MAX_REQUEST_BYTES - 4096);
        assert!(admitted.encoded_len() < TEST_POLICY_MAX_REQUEST_BYTES);
        assert!(
            PolicyServiceRpc::test_policy(&svc, Request::new(admitted))
                .await
                .unwrap()
                .into_inner()
                .compiled
        );
        for (request, expected) in [
            (
                proto::TestPolicyRequest {
                    rpol_source: "x".repeat(TEST_POLICY_MAX_REQUEST_BYTES + 1),
                    ..test_policy_request()
                },
                "size limit",
            ),
            (
                proto::TestPolicyRequest {
                    show_rejected: TEST_POLICY_MAX_REJECTED_SAMPLES + 1,
                    ..test_policy_request()
                },
                "show_rejected",
            ),
        ] {
            let status = PolicyServiceRpc::test_policy(&svc, Request::new(request))
                .await
                .unwrap_err();
            assert_eq!(status.code(), tonic::Code::InvalidArgument);
            assert!(status.message().contains(expected), "{status}");
        }
    }

    #[tokio::test]
    async fn test_policy_rejected_samples_are_capped_across_pages() {
        let svc = test_policy_service((0..1001).map(customer_route).collect());
        let response = PolicyServiceRpc::test_policy(
            &svc,
            Request::new(proto::TestPolicyRequest {
                rpol_source: "policy p { term t { reject } }".to_string(),
                policy: "p".to_string(),
                show_rejected: 2,
                ..test_policy_request()
            }),
        )
        .await
        .unwrap()
        .into_inner();
        assert_eq!(response.rejected, 1001);
        assert_eq!(response.rejected_routes.len(), 2);
        assert_eq!(
            response.rejected_routes[0].prefix,
            customer_route(0).prefix.addr_string()
        );
        assert_eq!(
            response.rejected_routes[1].prefix,
            customer_route(1).prefix.addr_string()
        );
    }

    // ── ComparePolicy ───────────────────────────────────────────────

    /// The installed source: hygiene in front of one client policy.
    const COMPARE_INSTALLED_RPOL: &str = r"
prefix-set bogons { 10.0.0.0/8 le 32 }
prefix-set customers { 192.0.2.0/24 }
prefix-set blocked { 203.0.113.0/24 }

policy rs-hygiene {
    term no-bogons { if route.prefix in bogons { reject } }
    term rest { accept }
}

policy client-x {
    term customers { if route.prefix in customers { set local-pref 200; accept } }
    term block { if route.prefix in blocked { reject } }
    term other { accept }
}
";

    const COMPARE_PEER: &str = "198.51.100.77";

    /// The chain a config resolve installs from `source`: each member an
    /// `.rpol`-backed `NamedPolicy`, compiled with live hit counters.
    fn installed_rpol_chain(source: &str, members: &[&str]) -> rustbgpd_policy::PolicyChain {
        installed_rpol_chain_bound(source, members, &[])
    }

    /// [`installed_rpol_chain`] with live dataset bindings `(name, entries)`.
    fn installed_rpol_chain_bound(
        source: &str,
        members: &[&str],
        datasets: &[(&str, &str)],
    ) -> rustbgpd_policy::PolicyChain {
        let file = rustbgpd_policy::rpol::RpolFile::parse(source).unwrap();
        let declared: std::collections::HashMap<_, _> = file.dataset_decls().collect();
        let mut bindings = rustbgpd_policy::datasets::DatasetBindings::new();
        for (name, entries) in datasets {
            let kind = declared[name];
            bindings.insert(Arc::new(rustbgpd_policy::datasets::DatasetHandle::new(
                name,
                kind,
                rustbgpd_policy::rpol::parse_dataset_text(entries, kind).unwrap(),
            )));
        }
        let mut store = rustbgpd_policy::sets::SetStore::new();
        let chain = rustbgpd_policy::PolicyChain::from_named(
            members
                .iter()
                .map(|name| {
                    let mut compiled = file
                        .compile_policy_bound(name, &[], &mut store, &bindings)
                        .unwrap()
                        .unwrap();
                    compiled.local_asn = Some(COMPARE_LOCAL_ASN);
                    rustbgpd_policy::NamedPolicy::from_rpol((*name).to_string(), Arc::new(compiled))
                })
                .collect(),
        );
        let _ = chain.hit_counters();
        chain
    }

    const COMPARE_LOCAL_ASN: u32 = 64_500;

    /// One route per class the fixture separates: a bogon, a customer
    /// route, a blocked route and an ordinary route.
    fn compare_routes() -> Vec<rustbgpd_rib::Route> {
        vec![
            test_route("10.1.0.0", 16),
            test_route("192.0.2.0", 24),
            test_route("203.0.113.0", 24),
            test_route("198.18.0.0", 15),
        ]
    }

    fn compare_request(
        source: &str,
        policies: &[&str],
        replace: &str,
    ) -> proto::ComparePolicyRequest {
        proto::ComparePolicyRequest {
            rpol_source: source.to_string(),
            policies: policies.iter().map(ToString::to_string).collect(),
            replace_member: replace.to_string(),
            peer: COMPARE_PEER.to_string(),
            max_samples: 10,
            ..Default::default()
        }
    }

    async fn run_compare(
        routes: Vec<rustbgpd_rib::Route>,
        installed: Option<&rustbgpd_policy::PolicyChain>,
        request: proto::ComparePolicyRequest,
    ) -> Result<proto::ComparePolicyResponse, Status> {
        let (svc, _) = policy_dry_run_service(
            routes,
            None,
            Some(rustbgpd_rib::InstalledExportChain {
                peer_interface: None,
                chain: installed.map(rustbgpd_policy::PolicyChain::compiled_shared),
            }),
        );
        let svc = svc.with_local_asn(COMPARE_LOCAL_ASN);
        PolicyServiceRpc::compare_policy(&svc, Request::new(request))
            .await
            .map(Response::into_inner)
    }

    fn sampled(routes: &[proto::ComparePolicyRoute]) -> Vec<String> {
        routes
            .iter()
            .map(|route| format!("{}/{}", route.prefix, route.prefix_length))
            .collect()
    }

    /// `(routes, newly rejected, newly accepted, attributes changed)`.
    fn compare_counts(response: &proto::ComparePolicyResponse) -> (u64, u64, u64, u64) {
        (
            response.routes_evaluated,
            response.newly_rejected,
            response.newly_accepted,
            response.attributes_changed,
        )
    }

    /// Golden: each candidate edits exactly one term of the installed
    /// `client-x`, and only the routes that term decides flip, in the right
    /// class. The bogon is rejected by `rs-hygiene` on both sides, so the
    /// edited member's `accept` never surfaces it.
    #[tokio::test]
    async fn compare_policy_one_term_edits_flip_exactly_their_routes() {
        let installed = installed_rpol_chain(COMPARE_INSTALLED_RPOL, &["rs-hygiene", "client-x"]);
        let edit = |from: &str, to: &str| {
            assert_eq!(COMPARE_INSTALLED_RPOL.matches(from).count(), 1);
            COMPARE_INSTALLED_RPOL.replace(from, to)
        };

        let source = edit("set local-pref 200", "set local-pref 300");
        let response = run_compare(
            compare_routes(),
            Some(&installed),
            compare_request(&source, &["client-x"], "client-x"),
        )
        .await
        .unwrap();
        assert!(response.compiled, "{}", response.diagnostics);
        assert_eq!(response.installed_chain, ["rs-hygiene", "client-x"]);
        assert_eq!(response.candidate_chain, ["rs-hygiene", "client-x"]);
        assert_eq!(compare_counts(&response), (4, 0, 0, 1));
        assert_eq!(
            sampled(&response.attributes_changed_routes),
            ["192.0.2.0/24"]
        );
        let changed = &response.attributes_changed_routes[0];
        assert_eq!(changed.peer, "10.0.0.9");
        assert_eq!(changed.installed_changes, ["local_pref unset -> 200"]);
        assert_eq!(changed.candidate_changes, ["local_pref unset -> 300"]);

        let source = edit("term other { accept }", "term other { reject }");
        let response = run_compare(
            compare_routes(),
            Some(&installed),
            compare_request(&source, &["client-x"], "client-x"),
        )
        .await
        .unwrap();
        assert_eq!(compare_counts(&response), (4, 1, 0, 0));
        assert_eq!(sampled(&response.newly_rejected_routes), ["198.18.0.0/15"]);
        assert_eq!(
            response.newly_rejected_routes[0].candidate_changes,
            Vec::<String>::new()
        );

        let source = edit(
            "term block { if route.prefix in blocked { reject } }",
            "term block { if route.prefix in blocked { accept } }",
        );
        let response = run_compare(
            compare_routes(),
            Some(&installed),
            compare_request(&source, &["client-x"], "client-x"),
        )
        .await
        .unwrap();
        assert_eq!(compare_counts(&response), (4, 0, 1, 0));
        assert_eq!(sampled(&response.newly_accepted_routes), ["203.0.113.0/24"]);
        assert_eq!(
            response.newly_accepted_routes[0].installed_changes,
            Vec::<String>::new()
        );
    }

    /// Control: the installed source compared with itself, as a replaced
    /// member or as the whole chain, flips nothing. The installed chain's
    /// live hit counters do not move.
    #[tokio::test]
    async fn compare_policy_identical_candidate_has_an_empty_diff() {
        let installed = installed_rpol_chain(COMPARE_INSTALLED_RPOL, &["rs-hygiene", "client-x"]);
        for request in [
            compare_request(COMPARE_INSTALLED_RPOL, &["client-x"], "client-x"),
            compare_request(COMPARE_INSTALLED_RPOL, &["rs-hygiene"], "rs-hygiene"),
            compare_request(COMPARE_INSTALLED_RPOL, &["rs-hygiene", "client-x"], ""),
        ] {
            let response = run_compare(compare_routes(), Some(&installed), request)
                .await
                .unwrap();
            assert_eq!(compare_counts(&response), (4, 0, 0, 0));
            assert_eq!(response.newly_rejected_routes, []);
            assert_eq!(response.newly_accepted_routes, []);
            assert_eq!(response.attributes_changed_routes, []);
        }
        assert!(installed.term_hit_rows().iter().all(|row| row.hits == 0));
    }

    /// A route `rs-hygiene` rejects is not a candidate accept when only the
    /// client member is replaced; dropping hygiene from a whole-chain
    /// candidate does surface it.
    #[tokio::test]
    async fn compare_policy_replacing_a_member_keeps_chain_context() {
        let installed = installed_rpol_chain(COMPARE_INSTALLED_RPOL, &["rs-hygiene", "client-x"]);
        let replaced = run_compare(
            compare_routes(),
            Some(&installed),
            compare_request(COMPARE_INSTALLED_RPOL, &["client-x"], "client-x"),
        )
        .await
        .unwrap();
        assert_eq!(replaced.newly_accepted, 0);

        let whole = run_compare(
            compare_routes(),
            Some(&installed),
            compare_request(COMPARE_INSTALLED_RPOL, &["client-x"], ""),
        )
        .await
        .unwrap();
        assert_eq!(whole.candidate_chain, ["client-x"]);
        assert_eq!(compare_counts(&whole), (4, 0, 1, 0));
        assert_eq!(sampled(&whole.newly_accepted_routes), ["10.1.0.0/16"]);
    }

    /// Counts stay exact past the per-class sample cap, across pages, and
    /// samples keep canonical order. A peer with no export chain accepts
    /// every route unmodified.
    #[tokio::test]
    async fn compare_policy_truncates_samples_at_the_cap() {
        let response = run_compare(
            (0..1001).map(customer_route).collect(),
            None,
            proto::ComparePolicyRequest {
                max_samples: 2,
                ..compare_request("policy p { term t { reject } }", &["p"], "")
            },
        )
        .await
        .unwrap();
        assert_eq!(response.installed_chain, Vec::<String>::new());
        assert_eq!(compare_counts(&response), (1001, 1001, 0, 0));
        assert_eq!(
            response
                .newly_rejected_routes
                .iter()
                .map(|route| route.prefix.clone())
                .collect::<Vec<_>>(),
            [
                customer_route(0).prefix.addr_string(),
                customer_route(1).prefix.addr_string()
            ]
        );
    }

    /// A replacement's candidate dataset and a retained member's live dataset
    /// share a name but not content: each member keeps its own binding.
    #[tokio::test]
    async fn compare_policy_keeps_each_members_dataset_binding() {
        const SOURCE: &str = r"
dataset prefix-set customers

policy rs-hygiene {
    term known { if route.prefix in customers { accept } }
    term rest { accept }
}

policy client-x {
    term customers { if route.prefix in customers { accept } }
    term rest { reject }
}
";
        let installed = installed_rpol_chain_bound(
            SOURCE,
            &["rs-hygiene", "client-x"],
            &[("customers", "192.0.2.0/24\n")],
        );
        let response = run_compare(
            compare_routes(),
            Some(&installed),
            proto::ComparePolicyRequest {
                datasets: vec![proto::TestPolicyDataset {
                    name: "customers".to_string(),
                    entries: "198.18.0.0/15\n".to_string(),
                }],
                ..compare_request(SOURCE, &["client-x"], "client-x")
            },
        )
        .await
        .unwrap();
        assert_eq!(compare_counts(&response), (4, 1, 1, 0));
        assert_eq!(sampled(&response.newly_rejected_routes), ["192.0.2.0/24"]);
        assert_eq!(sampled(&response.newly_accepted_routes), ["198.18.0.0/15"]);
    }

    /// A retained member shares its live dataset handle with the installed
    /// chain. A refresh after the installed side pinned it must not reach the
    /// candidate side of the same comparison, or an identical replacement
    /// reads as a difference.
    #[tokio::test]
    async fn compare_policy_reads_one_dataset_generation_on_both_sides() {
        const SOURCE: &str = r"
dataset prefix-set bogons
dataset prefix-set customers

policy rs-hygiene {
    term bogon { if route.prefix in bogons { reject } }
    term rest { accept }
}

policy client-x {
    term customers { if route.prefix in customers { accept } }
    term rest { reject }
}
";
        const CUSTOMERS: &str = "10.1.0.0/16\n192.0.2.0/24\n";
        let installed = installed_rpol_chain_bound(
            SOURCE,
            &["rs-hygiene", "client-x"],
            &[("bogons", "10.0.0.0/8 le 32\n"), ("customers", CUSTOMERS)],
        )
        .compiled_shared();
        let file = rustbgpd_policy::rpol::RpolFile::parse(SOURCE).unwrap();
        let bindings = bind_candidate_datasets(
            &file,
            &[proto::TestPolicyDataset {
                name: "customers".to_string(),
                entries: CUSTOMERS.to_string(),
            }],
        )
        .unwrap();
        let replacement = compile_candidate(
            &file,
            "client-x",
            &[],
            &mut rustbgpd_policy::sets::SetStore::new(),
            &bindings,
            true,
        )
        .unwrap();
        let candidate = rustbgpd_policy::compile::splice_compiled(&[
            (installed.policies[0].name.clone(), &installed, 0),
            (Some(Arc::from("client-x")), &replacement, 0),
        ]);

        let mut pins = rustbgpd_policy::DatasetPins::default();
        let installed_frame = pins.frame(&installed);
        let bogons = installed
            .datasets
            .iter()
            .find(|slot| &*slot.name == "bogons")
            .unwrap();
        assert!(
            bogons
                .handle
                .refresh(rustbgpd_policy::rpol::parse_dataset_text("", bogons.kind).unwrap())
                .is_some()
        );
        let frames = ComparePolicyFrames {
            installed: installed_frame,
            candidate: pins.frame(&candidate),
        };
        let mut response = proto::ComparePolicyResponse::default();
        run_compare_policy_page(
            &installed,
            &candidate,
            &frames,
            &rustbgpd_rib::RoutePage {
                routes: compare_routes(),
                ..Default::default()
            },
            &ComparePolicyScope {
                target: PeerKey::new(COMPARE_PEER.parse().unwrap(), None),
                family_filter: None,
                limit: 0,
                max_samples: 10,
            },
            &DryRunPeerContext::new(),
            &mut response,
        );
        assert_eq!(compare_counts(&response), (4, 0, 0, 0));
    }

    /// Comparison members compile from the submitted file's literal tables,
    /// built once for the file, and match a per-member table build exactly.
    #[test]
    fn compare_candidates_share_the_files_literal_tables() {
        let file = rustbgpd_policy::rpol::RpolFile::parse(COMPARE_INSTALLED_RPOL).unwrap();
        let calls = [("rs-hygiene", Vec::new()), ("client-x", Vec::new())];
        let bindings = rustbgpd_policy::datasets::DatasetBindings::new();
        assert!(!file.literal_tables_built());
        let mut budget = rustbgpd_policy::compile::ChainNodeBudget::default();
        let compiled = compile_compare_candidates(
            &file,
            &calls,
            &bindings,
            &mut rustbgpd_policy::sets::SetStore::new(),
            &mut |policy| budget.add_policy(policy).map_err(Status::invalid_argument),
        )
        .unwrap();
        assert!(file.literal_tables_built());
        let fresh = rustbgpd_policy::rpol::RpolFile::parse(COMPARE_INSTALLED_RPOL).unwrap();
        let mut store = rustbgpd_policy::sets::SetStore::new();
        for ((name, _), chain) in calls.iter().zip(&compiled) {
            assert_eq!(chain, &fresh.compile_policy(name, &[], &mut store).unwrap());
        }
    }

    /// A composed chain whose dataset table exceeds the per-walk pin frame is
    /// refused instead of failing its extra probes closed as rejections.
    #[tokio::test]
    async fn compare_policy_refuses_a_composed_dataset_table_over_the_pin_frame() {
        use std::fmt::Write as _;

        let limit = rustbgpd_policy::datasets::MAX_UNIT_DATASETS;
        let mut installed_source = String::new();
        let mut hygiene = String::from("policy rs-hygiene {\n");
        let mut bindings = Vec::new();
        let names: Vec<String> = (0..limit).map(|index| format!("d{index}")).collect();
        for name in &names {
            writeln!(installed_source, "dataset prefix-set {name}").unwrap();
            writeln!(
                hygiene,
                "    term t-{name} {{ if route.prefix in {name} {{ reject }} }}"
            )
            .unwrap();
        }
        for name in &names {
            bindings.push((name.as_str(), "10.255.0.0/16\n"));
        }
        installed_source.push_str(&hygiene);
        installed_source
            .push_str("    term rest { accept }\n}\npolicy client-x { term t { accept } }\n");
        let installed =
            installed_rpol_chain_bound(&installed_source, &["rs-hygiene", "client-x"], &bindings);
        let candidate = "dataset prefix-set extra\n\
            policy client-y { term t { if route.prefix in extra { reject } } term rest { accept } }";
        let error = run_compare(
            compare_routes(),
            Some(&installed),
            proto::ComparePolicyRequest {
                datasets: vec![proto::TestPolicyDataset {
                    name: "extra".to_string(),
                    entries: "203.0.113.0/24\n".to_string(),
                }],
                ..compare_request(candidate, &["client-y"], "client-x")
            },
        )
        .await
        .unwrap_err();
        assert_eq!(error.code(), tonic::Code::InvalidArgument);
        assert!(error.message().contains("datasets"), "{}", error.message());
    }

    /// Repeating a large valid policy cannot exceed the structural chain bound
    /// that configuration resolution enforces.
    #[tokio::test]
    async fn compare_policy_charges_the_chain_node_budget() {
        use std::fmt::Write as _;

        let mut source = String::from("prefix-set s { 192.0.2.0/24 }\npolicy big {\n");
        for index in 0..4000 {
            writeln!(
                source,
                "    term t{index} {{ if route.prefix in s && route.prefix in s {{ accept }} }}"
            )
            .unwrap();
        }
        source.push_str("}\n");
        let policies = vec!["big"; COMPARE_POLICY_MAX_MEMBERS];
        let error = run_compare(Vec::new(), None, compare_request(&source, &policies, ""))
            .await
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::InvalidArgument);
        assert!(
            error.message().contains("MAX_CHAIN_NODES"),
            "{}",
            error.message()
        );
    }

    /// `prepend as self` resolves to the daemon's ASN even when the peer has
    /// no export chain to carry one.
    #[tokio::test]
    async fn compare_policy_resolves_prepend_as_self_without_a_baseline_asn() {
        let response = run_compare(
            vec![test_route("192.0.2.0", 24)],
            None,
            compare_request(
                "policy p { term t { prepend as self 1; accept } }",
                &["p"],
                "",
            ),
        )
        .await
        .unwrap();
        assert_eq!(compare_counts(&response), (1, 0, 0, 1));
        assert_eq!(
            response.attributes_changed_routes[0].candidate_changes,
            [format!("as_path prepend {COMPARE_LOCAL_ASN} x1")]
        );
    }

    /// Rewriting the next hop to the address the route already carries is
    /// not an attribute change; rewriting it elsewhere is.
    #[tokio::test]
    async fn compare_policy_ignores_a_no_op_next_hop_rewrite() {
        for (address, changed) in [("10.0.0.9", 0), ("10.0.0.10", 1)] {
            let source = format!("policy p {{ term t {{ set next-hop {address}; accept }} }}");
            let response = run_compare(
                vec![test_route("192.0.2.0", 24)],
                None,
                compare_request(&source, &["p"], ""),
            )
            .await
            .unwrap();
            assert_eq!(compare_counts(&response), (1, 0, 0, changed), "{address}");
        }
    }

    /// Re-adding a present community, or adding the same communities in a
    /// different order, leaves the exported attributes unchanged.
    #[tokio::test]
    async fn compare_policy_ignores_attribute_and_community_order() {
        let mut route = test_route("192.0.2.0", 24);
        route.attributes = AttrSet::new(vec![
            rustbgpd_wire::PathAttribute::Communities(vec![(65000 << 16) | 1]),
            rustbgpd_wire::PathAttribute::Med(5),
        ]);
        let response = run_compare(
            vec![route.clone()],
            None,
            compare_request(
                "policy p { term t { add community 65000:1; accept } }",
                &["p"],
                "",
            ),
        )
        .await
        .unwrap();
        assert_eq!(compare_counts(&response), (1, 0, 0, 0));

        let installed = installed_rpol_chain(
            "policy p { term t { add community 65000:2; add community 65000:3; accept } }",
            &["p"],
        );
        for (candidate, changed) in [
            ("add community 65000:3; add community 65000:2;", 0),
            ("add community 65000:3; add community 65000:4;", 1),
        ] {
            let source = format!("policy p {{ term t {{ {candidate} accept }} }}");
            let response = run_compare(
                vec![route.clone()],
                Some(&installed),
                compare_request(&source, &["p"], "p"),
            )
            .await
            .unwrap();
            assert_eq!(compare_counts(&response), (1, 0, 0, changed), "{candidate}");
        }
    }

    #[tokio::test]
    async fn compare_policy_rejects_unusable_baselines_and_selections() {
        let installed = installed_rpol_chain(COMPARE_INSTALLED_RPOL, &["rs-hygiene", "client-x"]);
        let error = run_compare(
            Vec::new(),
            Some(&installed),
            compare_request(COMPARE_INSTALLED_RPOL, &["client-x"], "client-y"),
        )
        .await
        .unwrap_err();
        assert_eq!(error.code(), tonic::Code::InvalidArgument);
        assert!(error.message().contains("client-y"), "{}", error.message());

        let error = run_compare(
            Vec::new(),
            None,
            compare_request(COMPARE_INSTALLED_RPOL, &["client-x"], "client-x"),
        )
        .await
        .unwrap_err();
        assert_eq!(error.code(), tonic::Code::FailedPrecondition);

        let (svc, _) = policy_dry_run_service(Vec::new(), None, None);
        let error = PolicyServiceRpc::compare_policy(
            &svc,
            Request::new(compare_request(COMPARE_INSTALLED_RPOL, &["client-x"], "")),
        )
        .await
        .unwrap_err();
        assert_eq!(error.code(), tonic::Code::FailedPrecondition);
        assert!(error.message().contains("outbound registration"));

        for request in [
            compare_request(COMPARE_INSTALLED_RPOL, &[], ""),
            compare_request(
                COMPARE_INSTALLED_RPOL,
                &["rs-hygiene", "client-x"],
                "client-x",
            ),
            proto::ComparePolicyRequest {
                max_samples: TEST_POLICY_MAX_REJECTED_SAMPLES + 1,
                ..compare_request(COMPARE_INSTALLED_RPOL, &["client-x"], "")
            },
        ] {
            let error = run_compare(Vec::new(), Some(&installed), request)
                .await
                .unwrap_err();
            assert_eq!(error.code(), tonic::Code::InvalidArgument);
        }
    }

    #[tokio::test]
    async fn test_policy_rejects_bad_selection_and_direction() {
        let svc = test_policy_service(Vec::new());
        let request = |policy: &str, direction: &str| proto::TestPolicyRequest {
            rpol_source: TEST_RPOL.to_string(),
            policy: policy.to_string(),
            direction: direction.to_string(),
            peer: String::new(),
            afi_safi: 0,
            limit: 0,
            show_changes: 0,
            ..Default::default()
        };
        for (policy, direction) in [
            ("customer-in", "import"),  // arity
            ("nope", "import"),         // unknown policy
            ("customer-in(200)", "up"), // bad direction
        ] {
            let status =
                PolicyServiceRpc::test_policy(&svc, Request::new(request(policy, direction)))
                    .await
                    .expect_err("must reject");
            assert_eq!(status.code(), tonic::Code::InvalidArgument, "{policy}");
        }
    }

    /// Export direction with a limit and an IPv4 family filter walks
    /// Loc-RIB best routes.
    #[tokio::test]
    async fn test_policy_export_respects_limit() {
        let svc = test_policy_service(vec![
            test_route("10.10.1.0", 24),
            test_route("10.10.2.0", 24),
            test_route("10.10.3.0", 24),
        ]);
        let resp = PolicyServiceRpc::test_policy(
            &svc,
            Request::new(proto::TestPolicyRequest {
                rpol_source: TEST_RPOL.to_string(),
                policy: "customer-in(50)".to_string(),
                direction: "export".to_string(),
                peer: String::new(),
                afi_safi: proto::AddressFamily::Ipv4Unicast as i32,
                limit: 2,
                show_changes: 0,
                ..Default::default()
            }),
        )
        .await
        .expect("dry run succeeds")
        .into_inner();
        assert_eq!(resp.routes_evaluated, 2);
        assert_eq!(resp.accepted, 2);
        assert_eq!(resp.diffs.len(), 0);
    }

    async fn assert_test_policy_page_count(route_count: u32) {
        let (svc, commands) =
            test_policy_service_with((0..route_count).rev().map(customer_route).collect(), None);
        let resp = PolicyServiceRpc::test_policy(
            &svc,
            Request::new(proto::TestPolicyRequest {
                limit: 0,
                show_changes: 0,
                ..test_policy_request()
            }),
        )
        .await
        .expect("paged dry run succeeds")
        .into_inner();
        assert_eq!(resp.routes_evaluated, u64::from(route_count));
        assert_eq!(resp.accepted, u64::from(route_count));
        let page_count = route_count
            .div_ceil(u32::try_from(TEST_POLICY_PAGE_SIZE).expect("test page size fits in u32"));
        let mut expected = vec!["page:0".to_string(), "peers".to_string()];
        expected.extend((1..page_count).map(|page| format!("page:{page}")));
        assert_eq!(*commands.lock().unwrap(), expected);
    }

    #[tokio::test]
    async fn test_policy_pages_1000_routes() {
        assert_test_policy_page_count(1000).await;
    }

    #[tokio::test]
    async fn test_policy_pages_1001_routes() {
        assert_test_policy_page_count(1001).await;
    }

    #[tokio::test]
    async fn test_policy_pages_2000_routes() {
        assert_test_policy_page_count(2000).await;
    }

    #[tokio::test]
    async fn test_policy_pages_2001_use_fixed_version_strict_cursor_and_no_filter() {
        assert_test_policy_page_count(2001).await;
    }

    #[tokio::test]
    async fn test_policy_mixed_family_filter_and_limit_are_global() {
        let mut routes: Vec<_> = (0..1001).map(customer_route).collect();
        routes.extend((0..5).map(ipv6_route));
        let svc = test_policy_service(routes);
        let resp = PolicyServiceRpc::test_policy(
            &svc,
            Request::new(proto::TestPolicyRequest {
                afi_safi: proto::AddressFamily::Ipv6Unicast as i32,
                limit: 3,
                ..test_policy_request()
            }),
        )
        .await
        .unwrap()
        .into_inner();
        assert_eq!(resp.routes_evaluated, 3);
        assert_eq!(resp.rejected, 3);
        assert_eq!(resp.term_hits[0].hits, 0);
        assert_eq!(resp.term_hits[1].hits, 3);
    }

    #[tokio::test]
    async fn test_policy_import_one_peer_uses_received_scope_filter() {
        let selected = PeerId::from_addr("10.0.0.9".parse().unwrap());
        let other = PeerId::from_addr("10.0.0.10".parse().unwrap());
        let routes = (0..1001)
            .map(|index| {
                let mut route = customer_route(index);
                route.peer = if index % 2 == 0 { selected } else { other };
                route
            })
            .collect();
        let svc = test_policy_service(routes);
        let resp = PolicyServiceRpc::test_policy(
            &svc,
            Request::new(proto::TestPolicyRequest {
                peer: selected.to_string(),
                ..test_policy_request()
            }),
        )
        .await
        .unwrap()
        .into_inner();
        assert_eq!(resp.routes_evaluated, 501);
        assert_eq!(resp.accepted, 501);
    }

    #[tokio::test]
    async fn test_policy_family_filtered_limit_boundaries_999_1000_1001() {
        for limit in [999, 1000, 1001] {
            let mut routes: Vec<_> = (0..1001).map(customer_route).collect();
            routes.extend((0..1001).map(ipv6_route));
            let svc = test_policy_service(routes);
            let resp = PolicyServiceRpc::test_policy(
                &svc,
                Request::new(proto::TestPolicyRequest {
                    afi_safi: proto::AddressFamily::Ipv6Unicast as i32,
                    limit,
                    ..test_policy_request()
                }),
            )
            .await
            .unwrap()
            .into_inner();
            assert_eq!(resp.routes_evaluated, u64::from(limit));
            assert_eq!(resp.rejected, u64::from(limit));
        }
    }

    #[tokio::test]
    async fn test_policy_reverse_insertion_keeps_global_changes_counts_and_hits() {
        let svc = test_policy_service((0..1001).rev().map(customer_route).collect());
        let resp = PolicyServiceRpc::test_policy(
            &svc,
            Request::new(proto::TestPolicyRequest {
                show_changes: 3,
                ..test_policy_request()
            }),
        )
        .await
        .unwrap()
        .into_inner();
        assert_eq!(resp.routes_evaluated, 1001);
        assert_eq!(resp.modified, 1001);
        assert_eq!(resp.term_hits[0].hits, 1001);
        assert_eq!(resp.diffs.len(), 3);
        let expected: Vec<_> = (0..3)
            .map(|index| customer_route(index).prefix.addr_string())
            .collect();
        assert_eq!(
            resp.diffs
                .iter()
                .map(|diff| &diff.prefix)
                .collect::<Vec<_>>(),
            expected.iter().collect::<Vec<_>>()
        );
    }

    #[tokio::test]
    async fn test_policy_canonical_order_covers_families_peers_and_path_ids() {
        let peers: [IpAddr; 2] = ["10.0.0.8".parse().unwrap(), "10.0.0.9".parse().unwrap()];
        let mut routes = vec![
            customer_route(2),
            ipv6_route(1),
            customer_route(1),
            ipv6_route(0),
            customer_route(1),
        ];
        for (index, route) in routes.iter_mut().enumerate() {
            route.peer = PeerId::from_addr(peers[index % 2]);
            route.path_id = u32::try_from(4 - index).expect("fixture path ID fits in u32");
            route.next_hop = format!("192.0.2.{}", index + 1).parse().unwrap();
        }
        let mut expected = routes.clone();
        expected.sort_unstable_by_key(rustbgpd_rib::route_query_key);
        let expected: Vec<_> = expected
            .iter()
            .map(|route| {
                (
                    route.prefix.addr_string(),
                    route.peer.to_string(),
                    vec![format!("next_hop {} -> self", route.next_hop)],
                )
            })
            .collect();
        routes.reverse();
        let svc = test_policy_service(routes);
        let resp = PolicyServiceRpc::test_policy(
            &svc,
            Request::new(proto::TestPolicyRequest {
                rpol_source: "policy all { term all { set next-hop self; accept } }".to_string(),
                policy: "all".to_string(),
                show_changes: 10,
                ..test_policy_request()
            }),
        )
        .await
        .unwrap()
        .into_inner();
        let actual: Vec<_> = resp
            .diffs
            .into_iter()
            .map(|diff| (diff.prefix, diff.peer, diff.changes))
            .collect();
        assert_eq!(actual, expected);
    }

    #[tokio::test]
    async fn test_policy_limit_stops_without_an_extra_continuation() {
        let (svc, commands) =
            test_policy_service_with((0..2001).map(customer_route).collect(), None);
        let resp = PolicyServiceRpc::test_policy(
            &svc,
            Request::new(proto::TestPolicyRequest {
                limit: 1000,
                ..test_policy_request()
            }),
        )
        .await
        .unwrap()
        .into_inner();
        assert_eq!(resp.routes_evaluated, 1000);
        assert_eq!(*commands.lock().unwrap(), ["page:0", "peers"]);
    }

    #[tokio::test]
    async fn test_policy_conservative_invalidation_aborts_without_partial_response() {
        let (svc, commands) = test_policy_service_with(
            (0..1001).map(customer_route).collect(),
            Some((1, rustbgpd_rib::RoutePageError::Invalidated)),
        );
        let status = PolicyServiceRpc::test_policy(&svc, Request::new(test_policy_request()))
            .await
            .unwrap_err();
        assert_eq!(status.code(), tonic::Code::Aborted);
        assert!(status.message().contains("whole RPC"));
        assert_eq!(*commands.lock().unwrap(), ["page:0", "peers", "page:1"]);
    }

    #[tokio::test]
    async fn test_policy_generation_exhaustion_is_unavailable_before_peer_read() {
        let (svc, commands) = test_policy_service_with(
            vec![customer_route(0)],
            Some((0, rustbgpd_rib::RoutePageError::GenerationExhausted)),
        );
        let status = PolicyServiceRpc::test_policy(&svc, Request::new(test_policy_request()))
            .await
            .unwrap_err();
        assert_eq!(status.code(), tonic::Code::Unavailable);
        assert!(status.message().contains("generation is exhausted"));
        assert_eq!(*commands.lock().unwrap(), ["page:0"]);
    }

    // -- GetPolicyStats (ADR-0096 Decision 3.3, ADR-0136) ---------------

    use crate::import_roster::test_support as roster_support;
    use rustbgpd_rib::export_roster::ExportRosterPublisher;

    type Publication =
        tokio::sync::watch::Sender<Option<Arc<rustbgpd_transport::handle::InstalledImportPolicy>>>;

    /// A roster with one peer, `10.0.0.2`, whose installed import chain has
    /// evaluated 9 routes at generation 3, and one dataset with a recorded
    /// refresh error. The returned sender keeps the session publication open.
    fn stats_roster() -> (ImportRosterPublisher, Publication) {
        let chain = roster_support::chain("customer-in(200)", 1);
        for _ in 0..9 {
            let _ = chain.evaluate(&roster_support::route_context());
        }
        let (publication, receiver) =
            tokio::sync::watch::channel(Some(roster_support::installed(3, Some(&chain))));
        let dataset =
            roster_support::dataset("customers", "/var/lib/rustbgpd/datasets/customers.list");
        dataset.handle.record_error("line 3: bad");
        (
            roster_support::publisher(
                vec![roster_support::peer("10.0.0.2", receiver)],
                vec![dataset],
            ),
            publication,
        )
    }

    /// An installed `.rpol` export chain, `customer-in`, that has evaluated 7
    /// routes, all matching `customer-routes`: 2 had no origin AS for its
    /// computed `set` value (a condition never fails, so the error sits in
    /// the action).
    fn stats_export_chain() -> rustbgpd_policy::PolicyChain {
        use rustbgpd_policy::rpol::compile_rpol;
        use rustbgpd_policy::sets::SetStore;
        use rustbgpd_policy::{NamedPolicy, PolicyChain};

        let compiled = compile_rpol(
            "policy customer-in {\n\
             term customer-routes { set med route.origin-as; accept }\n\
             term rest { accept }\n\
             }",
            &mut SetStore::new(),
        )
        .unwrap();
        let chain = PolicyChain::from_named(vec![NamedPolicy::from_rpol(
            "customer-in".to_string(),
            Arc::new(compiled),
        )]);
        let mut context = roster_support::route_context();
        for origin in [64500, 64500, 64500, 64500, 64500, 0, 0] {
            context.origin_asn = (origin != 0).then_some(origin);
            let _ = chain.evaluate(&context);
        }
        chain
    }

    /// The RIB's export roster designating `chain`'s instance for `10.0.0.2`.
    fn stats_export_roster(chain: &rustbgpd_policy::PolicyChain) -> ExportRosterPublisher {
        let mut publisher = ExportRosterPublisher::new();
        publisher.publish(
            vec![(
                PeerId::from_addr("10.0.0.2".parse().unwrap()),
                Some(Arc::clone(chain.hit_counters())),
            )],
            None,
        );
        publisher
    }

    /// Both published rosters: import as [`stats_roster`], export with
    /// [`stats_export_chain`] installed for `10.0.0.2`, whose counter-instance
    /// id is returned. Keep the returned values alive for the service.
    fn stats_service() -> (
        PolicyService,
        ImportRosterPublisher,
        Publication,
        ExportRosterPublisher,
        u64,
    ) {
        let (peer_tx, _) = mpsc::channel::<PeerManagerCommand>(1);
        let chain = stats_export_chain();
        let export = stats_export_roster(&chain);
        let (roster, publication) = stats_roster();
        let svc = PolicyService::new(AccessMode::ReadOnly, peer_tx, None, None)
            .with_import_roster(roster.reader())
            .with_export_roster(export.reader());
        (svc, roster, publication, export, chain.hit_counters().id())
    }

    /// Export rows come from the RIB's published roster: live counters of the
    /// designated instance, whose id is the row's `policy_generation`.
    #[tokio::test]
    async fn get_policy_stats_round_trips_term_rows() {
        let (svc, _roster, _publication, _export, instance) = stats_service();
        let resp = PolicyServiceRpc::get_policy_stats(
            &svc,
            Request::new(proto::GetPolicyStatsRequest {
                allow_partial: false,
                peer_address: "10.0.0.2".to_string(),
                direction: String::new(),
            }),
        )
        .await
        .expect("stats query succeeds")
        .into_inner();
        assert_eq!(resp.chains.len(), 1);
        let chain = &resp.chains[0];
        assert_eq!(chain.peer_address, "10.0.0.2");
        assert_eq!(chain.direction, "export");
        assert_eq!(chain.routes_evaluated, 7);
        assert_eq!(chain.terms.len(), 2);
        assert_eq!(chain.terms[0].policy, "customer-in");
        assert_eq!(chain.terms[0].term, "customer-routes");
        assert_eq!(chain.terms[0].hits, 7);
        assert_eq!(chain.terms[1].term, "rest");
        assert_eq!(chain.terms[1].term_index, 1);
        assert_eq!(chain.terms[1].hits, 0);
        assert_ne!(instance, 0);
        assert_eq!(
            chain.policy_generation, instance,
            "export rows report the counter-instance id"
        );
        // LAN-301: eval-error counters and the rendered last error
        // ride the chain rows.
        assert_eq!(chain.eval_errors, 2);
        assert_eq!(
            chain.last_error,
            "absent-operand in policy customer-in term customer-routes"
        );
        // LAN-305: dataset status rides the same response.
        assert_eq!(resp.datasets.len(), 1);
        let dataset = &resp.datasets[0];
        assert_eq!(dataset.name, "customers");
        assert_eq!(dataset.kind, "asn-set");
        assert_eq!(dataset.generation, 1);
        assert_eq!(dataset.records, 2);
        assert_eq!(dataset.last_error, "line 3: bad");
        assert_eq!(dataset.path, "/var/lib/rustbgpd/datasets/customers.list");
    }

    /// Export rows of neighbors that share a link-local address name each
    /// neighbor's interface from the chain's own handle.
    #[tokio::test]
    async fn get_policy_stats_scopes_same_address_export_rows() {
        let chain = stats_export_chain();
        let link_local = "fe80::1".parse().unwrap();
        let handles = ["eth0", "eth1"].map(|interface| {
            PeerId::allocate(rustbgpd_rib::PeerEndpoint::new(link_local, Some(interface)))
        });
        let mut export = ExportRosterPublisher::new();
        export.publish(
            handles
                .iter()
                .map(|&peer| (peer, Some(Arc::clone(chain.hit_counters()))))
                .collect(),
            None,
        );
        let (roster, _publication) = stats_roster();
        let (peer_tx, _) = mpsc::channel::<PeerManagerCommand>(1);
        let svc = PolicyService::new(AccessMode::ReadOnly, peer_tx, None, None)
            .with_import_roster(roster.reader())
            .with_export_roster(export.reader());
        let resp = PolicyServiceRpc::get_policy_stats(
            &svc,
            Request::new(proto::GetPolicyStatsRequest {
                allow_partial: false,
                peer_address: String::new(),
                direction: "export".to_string(),
            }),
        )
        .await
        .expect("stats query succeeds")
        .into_inner();
        let mut rows = resp
            .chains
            .iter()
            .map(|chain| (chain.peer_address.as_str(), chain.peer_interface.as_str()))
            .collect::<Vec<_>>();
        rows.sort_unstable();
        assert_eq!(rows, [("fe80::1", "eth0"), ("fe80::1", "eth1")]);
        for handle in handles {
            assert!(handle.release());
        }
    }

    /// The import direction reads the session's published counters and
    /// reports the install generation, so a replaced chain (counters back to
    /// zero, generation advanced) is never presented as continuous history.
    #[tokio::test]
    async fn get_policy_stats_reports_import_chains_with_generation() {
        let (svc, _roster, _publication, _export, _) = stats_service();
        let resp = PolicyServiceRpc::get_policy_stats(
            &svc,
            Request::new(proto::GetPolicyStatsRequest {
                allow_partial: false,
                peer_address: "10.0.0.2".to_string(),
                direction: "import".to_string(),
            }),
        )
        .await
        .expect("import stats query succeeds")
        .into_inner();
        assert_eq!(resp.chains.len(), 1);
        let chain = &resp.chains[0];
        assert_eq!(chain.peer_address, "10.0.0.2");
        assert_eq!(chain.direction, "import");
        assert_eq!(chain.routes_evaluated, 9);
        assert_eq!(chain.policy_generation, 3);
        assert_eq!(chain.terms.len(), 1);
        assert_eq!(chain.terms[0].policy, "customer-in(200)");
        assert_eq!(chain.terms[0].term, "", "TOML statements are unnamed");
        assert_eq!(chain.terms[0].hits, 9);
        assert_eq!(chain.eval_errors, 0);
        assert_eq!(chain.last_error, "", "no error since install");
    }

    /// A deadline or a session exit must fail the whole RPC, with a distinct
    /// message, rather than return empty success; the audit keeps the
    /// capture's counts.
    #[tokio::test(start_paused = true)]
    async fn get_policy_stats_import_failures_are_not_empty_successes() {
        for (closed, code, message, detail) in [
            (
                false,
                tonic::Code::DeadlineExceeded,
                "policy stats aggregate deadline exceeded",
                "publications=0/1 yields=1",
            ),
            (
                true,
                tonic::Code::Unavailable,
                "one or more peer sessions exited during the import policy stats query",
                "publications=0/1 yields=0",
            ),
        ] {
            let (publication, receiver) = tokio::sync::watch::channel(None);
            let _open = (!closed).then_some(publication);
            let roster = roster_support::publisher(
                vec![roster_support::peer("10.0.0.2", receiver)],
                Vec::new(),
            );
            let (peer_tx, _) = mpsc::channel(1);
            let svc = PolicyService::new(AccessMode::ReadOnly, peer_tx, None, None)
                .with_import_roster(roster.reader());
            let audit = GrpcAuditHandle::default();
            let mut request = Request::new(policy_stats_rpc_request("10.0.0.2", "import"));
            request.extensions_mut().insert(audit.clone());
            let error = PolicyServiceRpc::get_policy_stats(&svc, request)
                .await
                .unwrap_err();
            assert_eq!(error.code(), code);
            assert_eq!(error.message(), message);
            let summary = audit.summary().unwrap();
            let import = summary.as_str().split("; ").last().unwrap();
            assert!(import.starts_with("stage=import "), "{summary:?}");
            assert!(
                import.ends_with(&format!("code={code:?} {detail}")),
                "{summary:?}"
            );
            assert!(!summary.as_str().contains("datasets"));
        }
    }

    /// `direction = "both"` returns the export block first, then the
    /// import block — one deterministic response, not two commands.
    #[tokio::test]
    async fn get_policy_stats_both_orders_export_then_import() {
        let (svc, _roster, _publication, _export, _) = stats_service();
        let resp = PolicyServiceRpc::get_policy_stats(
            &svc,
            Request::new(proto::GetPolicyStatsRequest {
                allow_partial: false,
                peer_address: "10.0.0.2".to_string(),
                direction: "both".to_string(),
            }),
        )
        .await
        .expect("both-directions stats query succeeds")
        .into_inner();
        let directions: Vec<&str> = resp
            .chains
            .iter()
            .map(|chain| chain.direction.as_str())
            .collect();
        assert_eq!(directions, ["export", "import"]);
    }

    /// Every round closes an admitted publication after the read is pending,
    /// then replaces the roster. The read must keep the selected session set.
    #[tokio::test]
    async fn get_policy_stats_partial_fleet_survives_sustained_churn() {
        use std::future::{Future, poll_fn};
        use std::task::Poll;

        let chain = roster_support::chain("live-in", 1);
        let (healthy_tx, healthy_rx) =
            tokio::sync::watch::channel(Some(roster_support::installed(7, Some(&chain))));
        let (_chainless_tx, chainless_rx) =
            tokio::sync::watch::channel(Some(roster_support::installed(0, None)));
        let mut roster = ImportRosterPublisher::new();
        let export = stats_export_roster(&stats_export_chain());
        let svc = PolicyService::new(AccessMode::ReadOnly, mpsc::channel(1).0, None, None)
            .with_import_roster(roster.reader())
            .with_export_roster(export.reader());
        for generation in 1..=4 {
            for direction in ["import", "both"] {
                for allow_partial in [false, true] {
                    let (closing_tx, closing_rx) = tokio::sync::watch::channel(None);
                    roster.publish(
                        vec![
                            roster_support::peer("10.0.0.1", healthy_rx.clone()),
                            roster_support::peer("10.0.0.2", closing_rx),
                            roster_support::peer("10.0.0.3", chainless_rx.clone()),
                        ],
                        Vec::new().into(),
                    );
                    let request = proto::GetPolicyStatsRequest {
                        allow_partial,
                        ..policy_stats_rpc_request("", direction)
                    };
                    let read = PolicyServiceRpc::get_policy_stats(&svc, Request::new(request));
                    tokio::pin!(read);
                    assert!(
                        poll_fn(|cx| Poll::Ready(read.as_mut().poll(cx)))
                            .await
                            .is_pending()
                    );
                    assert_eq!(
                        closing_tx.receiver_count(),
                        2,
                        "capture admitted the old publication"
                    );
                    let (_replacement_tx, replacement_rx) = tokio::sync::watch::channel(Some(
                        roster_support::installed(generation, Some(&chain)),
                    ));
                    roster.publish(
                        vec![
                            roster_support::peer("10.0.0.2", replacement_rx.clone()),
                            roster_support::peer("10.0.0.4", replacement_rx),
                        ],
                        Vec::new().into(),
                    );
                    drop(closing_tx);
                    let result = read.await;
                    if allow_partial {
                        let response = result.unwrap().into_inner();
                        assert_eq!(response.incomplete_peer_addresses, ["10.0.0.2"]);
                        let rows: Vec<_> = response
                            .chains
                            .iter()
                            .map(|row| (row.peer_address.as_str(), row.direction.as_str()))
                            .collect();
                        let mut expected = Vec::new();
                        if direction == "both" {
                            expected.push(("10.0.0.2", "export"));
                        }
                        expected.push(("10.0.0.1", "import"));
                        assert_eq!(rows, expected, "no replacement or newly admitted rows");
                        assert_eq!(response.chains.last().unwrap().policy_generation, 7);
                    } else {
                        assert_eq!(result.unwrap_err().code(), tonic::Code::Unavailable);
                    }
                }
            }
        }
        drop(healthy_tx);
    }

    #[tokio::test]
    async fn get_policy_stats_partial_rejects_filtered_and_export_before_backend_work() {
        let svc = PolicyService::new(AccessMode::ReadOnly, mpsc::channel(1).0, None, None);
        for (peer, direction) in [
            ("", ""),
            ("", "export"),
            ("10.0.0.1", "import"),
            ("10.0.0.1", "both"),
        ] {
            let request = proto::GetPolicyStatsRequest {
                allow_partial: true,
                ..policy_stats_rpc_request(peer, direction)
            };
            assert_eq!(
                PolicyServiceRpc::get_policy_stats(&svc, Request::new(request))
                    .await
                    .unwrap_err()
                    .code(),
                tonic::Code::InvalidArgument
            );
        }
    }

    #[tokio::test]
    async fn get_policy_stats_partial_all_gone_is_sorted_unique_and_empty_fleet_is_complete() {
        let (tx, rx) = tokio::sync::watch::channel(None);
        let mut scoped = roster_support::peer("192.0.2.2", rx.clone());
        scoped.key.interface = Some("eth0".into());
        let mut roster = roster_support::publisher(
            vec![
                scoped,
                roster_support::peer("192.0.2.2", rx.clone()),
                roster_support::peer("192.0.2.1", rx),
            ],
            Vec::new(),
        );
        drop(tx);
        let svc = PolicyService::new(AccessMode::ReadOnly, mpsc::channel(1).0, None, None)
            .with_import_roster(roster.reader());
        for expected in [vec!["192.0.2.1", "192.0.2.2"], Vec::new()] {
            let request = proto::GetPolicyStatsRequest {
                allow_partial: true,
                ..policy_stats_rpc_request("", "import")
            };
            let response = PolicyServiceRpc::get_policy_stats(&svc, Request::new(request))
                .await
                .unwrap()
                .into_inner();
            assert_eq!(response.chains, [] as [proto::PolicyChainStats; 0]);
            assert_eq!(response.incomplete_peer_addresses, expected);
            roster.publish(Vec::new(), Vec::new().into());
        }
    }

    /// Skipping a closed session cannot hide a later Pending or dataset
    /// timeout, and stopping either roster owner still fails the whole read.
    #[tokio::test(start_paused = true)]
    async fn get_policy_stats_partial_retains_deadline_and_owner_errors() {
        use std::future::{Future, poll_fn};
        use std::task::Poll;

        for failure in [
            "import_timeout",
            "dataset_timeout",
            "peer_owner",
            "rib_owner",
        ] {
            let (closed_tx, closed_rx) = tokio::sync::watch::channel(None);
            drop(closed_tx);
            let (pending_tx, pending_rx) = tokio::sync::watch::channel(None);
            let dataset = roster_support::dataset("held", "held.list");
            let handle = Arc::clone(&dataset.handle);
            let roster = roster_support::publisher(
                vec![
                    roster_support::peer("10.0.0.1", closed_rx),
                    roster_support::peer("10.0.0.2", pending_rx),
                ],
                vec![dataset],
            );
            let export = stats_export_roster(&stats_export_chain());
            let svc = PolicyService::new(AccessMode::ReadOnly, mpsc::channel(1).0, None, None)
                .with_import_roster(roster.reader())
                .with_export_roster(export.reader());
            let request = proto::GetPolicyStatsRequest {
                allow_partial: true,
                ..policy_stats_rpc_request("", "both")
            };
            let read = PolicyServiceRpc::get_policy_stats(&svc, Request::new(request));
            tokio::pin!(read);
            assert!(
                poll_fn(|cx| Poll::Ready(read.as_mut().poll(cx)))
                    .await
                    .is_pending()
            );
            let mut dataset_lock = None;
            if failure == "import_timeout" {
                tokio::time::advance(POLICY_STATS_AGGREGATE_TIMEOUT).await;
            } else {
                pending_tx.send_replace(Some(roster_support::installed(0, None)));
                if failure == "dataset_timeout" {
                    dataset_lock = Some(handle.hold_error_lock_for_test());
                    assert!(
                        poll_fn(|cx| Poll::Ready(read.as_mut().poll(cx)))
                            .await
                            .is_pending()
                    );
                    tokio::time::advance(POLICY_STATS_AGGREGATE_TIMEOUT).await;
                }
            }
            if failure == "peer_owner" {
                drop(roster);
            }
            if failure == "rib_owner" {
                drop(export);
            }
            let error = read.await.unwrap_err();
            assert_eq!(
                error.code(),
                if failure.ends_with("timeout") {
                    tonic::Code::DeadlineExceeded
                } else {
                    tonic::Code::Unavailable
                },
                "{failure}"
            );
            drop(dataset_lock);
        }
    }

    /// Only a closed session may be skipped: poisoned counters on a live
    /// session still fail the whole opt-in read, even beside a skipped peer.
    #[tokio::test]
    async fn get_policy_stats_partial_still_fails_on_unavailable_counters() {
        let chain = roster_support::chain("poisoned-in", 1);
        let counters = Arc::clone(chain.hit_counters());
        let poison = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _held = counters.hold_error_lock_for_test();
            panic!("poison the import counter error lock");
        }));
        assert!(poison.is_err());
        let (closed_tx, closed_rx) = tokio::sync::watch::channel(None);
        drop(closed_tx);
        let (_poisoned_tx, poisoned_rx) =
            tokio::sync::watch::channel(Some(roster_support::installed(3, Some(&chain))));
        let roster = roster_support::publisher(
            vec![
                roster_support::peer("10.0.0.1", closed_rx),
                roster_support::peer("10.0.0.2", poisoned_rx),
            ],
            Vec::new(),
        );
        let export = stats_export_roster(&stats_export_chain());
        let svc = PolicyService::new(AccessMode::ReadOnly, mpsc::channel(1).0, None, None)
            .with_import_roster(roster.reader())
            .with_export_roster(export.reader());
        for direction in ["import", "both"] {
            let request = proto::GetPolicyStatsRequest {
                allow_partial: true,
                ..policy_stats_rpc_request("", direction)
            };
            let error = PolicyServiceRpc::get_policy_stats(&svc, Request::new(request))
                .await
                .unwrap_err();
            assert_eq!(error.code(), tonic::Code::Unavailable, "{direction}");
            assert_eq!(
                error.message(),
                "installed import policy counters unavailable",
                "{direction}"
            );
        }
    }

    /// A listener built without the peer manager's roster cannot answer, and
    /// one without the RIB's roster cannot answer an export read.
    #[tokio::test]
    async fn get_policy_stats_without_a_roster_is_failed_precondition() {
        let (peer_tx, mut peer_rx) = mpsc::channel(1);
        let (rib_tx, mut rib_rx) = mpsc::channel(1);
        let svc =
            PolicyService::new(AccessMode::ReadOnly, peer_tx, None, None).with_rib_query(rib_tx);
        let import = ImportRosterPublisher::new();
        let export_only = PolicyService::new(AccessMode::ReadOnly, mpsc::channel(1).0, None, None)
            .with_export_roster(ExportRosterPublisher::new().reader());
        let import_only = PolicyService::new(AccessMode::ReadOnly, mpsc::channel(1).0, None, None)
            .with_import_roster(import.reader());
        for direction in ["export", "import", "both"] {
            for (svc, answers) in [
                (&svc, false),
                (&export_only, false),
                (&import_only, direction == "import"),
            ] {
                let result = PolicyServiceRpc::get_policy_stats(
                    svc,
                    Request::new(policy_stats_rpc_request("", direction)),
                )
                .await;
                if answers {
                    assert!(result.is_ok(), "{direction}");
                } else {
                    assert_eq!(
                        result.unwrap_err().code(),
                        tonic::Code::FailedPrecondition,
                        "{direction}"
                    );
                }
            }
        }
        assert!(matches!(peer_rx.try_recv(), Err(TryRecvError::Empty)));
        assert!(matches!(rib_rx.try_recv(), Err(TryRecvError::Empty)));
    }

    /// ADR-0136 closure: a request that loaded the roster, is held in its
    /// capture while the peer manager stops, and then resumes must not
    /// return what it captured as success. Checking the flag only before
    /// capture turns this into `Ok`.
    #[tokio::test]
    async fn get_policy_stats_fails_when_the_owner_stopped_during_capture() {
        let (publication, receiver) = tokio::sync::watch::channel(None);
        let roster =
            roster_support::publisher(vec![roster_support::peer("10.0.0.2", receiver)], Vec::new());
        let (peer_tx, _) = mpsc::channel(1);
        let svc = PolicyService::new(AccessMode::ReadOnly, peer_tx, None, None)
            .with_import_roster(roster.reader());
        let read = tokio::spawn(async move {
            PolicyServiceRpc::get_policy_stats(
                &svc,
                Request::new(policy_stats_rpc_request("", "import")),
            )
            .await
        });
        // The capture holds the loaded roster while it awaits the Pending
        // publication on a cursor of its own.
        while publication.receiver_count() < 2 {
            tokio::task::yield_now().await;
        }
        drop(roster);
        publication.send_replace(Some(roster_support::installed(0, None)));
        let error = read.await.unwrap().unwrap_err();
        assert_eq!(error.code(), tonic::Code::Unavailable);
        assert_eq!(error.message(), "peer manager stopped");
    }

    /// ADR-0136 closure, export side: a `both` request that captured the
    /// RIB's roster and is then held in its import capture while the RIB
    /// manager is dropped returns `UNAVAILABLE` when it resumes. Checking the
    /// export flag only before capture turns this into `Ok`.
    #[tokio::test]
    async fn get_policy_stats_fails_when_the_rib_stopped_during_capture() {
        let (publication, receiver) = tokio::sync::watch::channel(None);
        let roster =
            roster_support::publisher(vec![roster_support::peer("10.0.0.2", receiver)], Vec::new());
        let export = stats_export_roster(&stats_export_chain());
        let (peer_tx, _) = mpsc::channel(1);
        let svc = PolicyService::new(AccessMode::ReadOnly, peer_tx, None, None)
            .with_import_roster(roster.reader())
            .with_export_roster(export.reader());
        let read = tokio::spawn(async move {
            PolicyServiceRpc::get_policy_stats(
                &svc,
                Request::new(policy_stats_rpc_request("", "both")),
            )
            .await
        });
        // Export capture is done; the import capture awaits the Pending
        // publication on a cursor of its own.
        while publication.receiver_count() < 2 {
            tokio::task::yield_now().await;
        }
        drop(export);
        publication.send_replace(Some(roster_support::installed(0, None)));
        let error = read.await.unwrap().unwrap_err();
        assert_eq!(error.code(), tonic::Code::Unavailable);
        assert_eq!(error.message(), "RIB manager stopped");
        drop(roster);
    }

    /// ADR-0136 held owner: export and `both` requests succeed from the RIB's
    /// published roster while a real RIB manager is never polled, with its
    /// primary mailbox, query lane and summary lane full. Before the export
    /// roster the export stage queued there and returned `DEADLINE_EXCEEDED`.
    #[tokio::test(start_paused = true)]
    async fn get_policy_stats_succeeds_while_a_real_rib_is_never_polled() {
        let (rib_mailbox, rib_rx) = mpsc::channel(1);
        let (query_tx, query_rx) = mpsc::channel(1);
        let (summary_tx, summary_rx) = mpsc::channel(1);
        let rib = rustbgpd_rib::RibManager::new(
            rib_rx,
            query_rx,
            Some(stats_export_chain()),
            None,
            rustbgpd_telemetry::BgpMetrics::new(),
        )
        .with_summary_queries(summary_rx);
        for lane in [&rib_mailbox, &query_tx] {
            let (reply, _) = oneshot::channel();
            lane.try_send(rustbgpd_rib::RibUpdate::QueryLocRibCount { reply })
                .unwrap();
        }
        let (reply, _) = oneshot::channel();
        summary_tx
            .try_send(rustbgpd_rib::RibSummaryQuery::NeighborRibSnapshots {
                peers: Vec::new(),
                comparison: None,
                reply,
                include_retained: false,
            })
            .unwrap();
        let (roster, _publication) = stats_roster();
        let (peer_tx, _) = mpsc::channel(1);
        let svc = PolicyService::new(AccessMode::ReadOnly, peer_tx, None, None)
            .with_rib_query(query_tx.clone())
            .with_import_roster(roster.reader())
            .with_export_roster(rib.export_roster());
        let started = tokio::time::Instant::now();
        for (peer, direction, expected) in [
            ("", "export", vec![("global", "export")]),
            (
                "10.0.0.2",
                "both",
                vec![("10.0.0.2", "export"), ("10.0.0.2", "import")],
            ),
        ] {
            let audit = GrpcAuditHandle::default();
            let mut request = Request::new(policy_stats_rpc_request(peer, direction));
            request.extensions_mut().insert(audit.clone());
            let response = PolicyServiceRpc::get_policy_stats(&svc, request)
                .await
                .expect("a held RIB must not fail an export read")
                .into_inner();
            let rows: Vec<_> = response
                .chains
                .iter()
                .map(|chain| (chain.peer_address.as_str(), chain.direction.as_str()))
                .collect();
            assert_eq!(rows, expected);
            assert_eq!(response.chains[0].routes_evaluated, 7, "live counters");
            assert!(
                audit
                    .summary()
                    .unwrap()
                    .as_str()
                    .contains("stage=export elapsed_ms=0 budget_ms=2000 rpc_elapsed_ms=0 code=Ok"),
                "{:?}",
                audit.summary()
            );
        }
        assert_eq!(started.elapsed(), Duration::ZERO);
        assert_eq!(
            (
                rib_mailbox.capacity(),
                query_tx.capacity(),
                summary_tx.capacity()
            ),
            (0, 0, 0),
            "no RIB lane was used"
        );
        drop(rib);
    }

    /// A capture that becomes ready only at or after the aggregate deadline
    /// discards every row, even though Tokio polls the ready capture first.
    /// Export capture never waits, so the import capture's Pending
    /// publication is the backend here.
    #[tokio::test(start_paused = true)]
    async fn get_policy_stats_ready_reply_obeys_aggregate_deadline() {
        use std::future::{Future, poll_fn};
        use std::task::Poll;

        let chain = roster_support::chain("late-in", 1);
        for (elapsed_ms, close_publication) in [
            (1_900, false),
            (2_000, false),
            (2_001, false),
            (2_001, true),
        ] {
            let (publication, receiver) = tokio::sync::watch::channel(None);
            let roster = roster_support::publisher(
                vec![roster_support::peer("10.0.0.2", receiver)],
                Vec::new(),
            );
            let (peer_tx, _peer_rx) = mpsc::channel(1);
            let svc = PolicyService::new(AccessMode::ReadOnly, peer_tx, None, None)
                .with_import_roster(roster.reader());
            let started = tokio::time::Instant::now();
            let audit = GrpcAuditHandle::default();
            let mut request = Request::new(policy_stats_rpc_request("", "import"));
            request.extensions_mut().insert(audit.clone());
            let read = PolicyServiceRpc::get_policy_stats(&svc, request);
            tokio::pin!(read);
            assert!(
                poll_fn(|cx| Poll::Ready(read.as_mut().poll(cx)))
                    .await
                    .is_pending()
            );
            // Keep the RPC unpolled until the chosen observation time. In the
            // expiry cases, both capture and timer are ready on resume.
            tokio::time::advance(Duration::from_millis(elapsed_ms)).await;
            if close_publication {
                drop(publication);
            } else {
                publication.send_replace(Some(roster_support::installed(0, Some(&chain))));
            }
            let result = read.await;
            let code = if elapsed_ms < 2_000 {
                let response = result.unwrap().into_inner();
                assert_eq!(response.chains.len(), 1);
                tonic::Code::Ok
            } else {
                let error = result.expect_err("an expired capture must discard all rows");
                assert_eq!(error.code(), tonic::Code::DeadlineExceeded);
                assert_eq!(error.message(), "policy stats aggregate deadline exceeded");
                error.code()
            };
            assert_eq!(started.elapsed(), Duration::from_millis(elapsed_ms));
            let summary = audit.summary().unwrap();
            assert!(
                summary.as_str().starts_with(&format!(
                    "stage=import elapsed_ms={elapsed_ms} budget_ms=2000 rpc_elapsed_ms={elapsed_ms} code={code:?} "
                )),
                "{summary:?}"
            );
            assert_eq!(
                summary.as_str().contains("stage=datasets"),
                code == tonic::Code::Ok,
                "{summary:?}"
            );
        }
    }

    /// LAN-661: explicit-peer validation, export, import, and dataset reads
    /// are sequential but spend one shared RPC budget rather than receiving
    /// independent timeouts: the dataset stage gets what the import capture
    /// left.
    #[tokio::test(start_paused = true)]
    async fn get_policy_stats_sequential_stages_share_one_budget() {
        const PENDING: Duration = Duration::from_millis(700);

        let chain = roster_support::chain("late-in", 1);
        let (publication, receiver) = tokio::sync::watch::channel(None);
        let roster = roster_support::publisher(
            vec![roster_support::peer("10.0.0.2", receiver)],
            vec![roster_support::dataset("customers", "c.list")],
        );
        let publish = roster_support::installed(0, Some(&chain));
        tokio::spawn(async move {
            tokio::time::sleep(PENDING).await;
            publication.send_replace(Some(publish));
            std::future::pending::<()>().await;
        });
        let export = stats_export_roster(&stats_export_chain());
        let (peer_tx, _) = mpsc::channel::<PeerManagerCommand>(1);
        let svc = PolicyService::new(AccessMode::ReadOnly, peer_tx, None, None)
            .with_import_roster(roster.reader())
            .with_export_roster(export.reader());

        let audit = GrpcAuditHandle::default();
        audit.set_summary(GrpcRequestSummary::new("existing=safe"));
        let mut request = Request::new(policy_stats_rpc_request("10.0.0.2", "both"));
        request.extensions_mut().insert(audit.clone());
        let response = PolicyServiceRpc::get_policy_stats(&svc, request)
            .await
            .expect("every stage completes within the one budget")
            .into_inner();
        assert_eq!(response.chains.len(), 2);
        assert_eq!(
            audit.summary().unwrap().as_str(),
            concat!(
                "existing=safe; ",
                "stage=peer_validation elapsed_ms=0 budget_ms=2000 rpc_elapsed_ms=0 code=Ok; ",
                "stage=export elapsed_ms=0 budget_ms=2000 rpc_elapsed_ms=0 code=Ok; ",
                "stage=import elapsed_ms=700 budget_ms=2000 rpc_elapsed_ms=700 code=Ok ",
                "publications=1/1 yields=1; ",
                "stage=datasets elapsed_ms=0 budget_ms=1300 rpc_elapsed_ms=700 code=Ok",
            )
        );
    }

    /// The import stage's audit record carries the publications read and the
    /// waits taken; an installed publication adds no wait, a Pending one
    /// adds one. There is no peer-manager admission to record.
    #[tokio::test(start_paused = true)]
    async fn get_policy_stats_audit_records_import_capture() {
        const PENDING: Duration = Duration::from_millis(300);

        let chain = roster_support::chain("audit-in", 1);
        let (first, first_rx) =
            tokio::sync::watch::channel(Some(roster_support::installed(0, Some(&chain))));
        let (third, third_rx) =
            tokio::sync::watch::channel(Some(roster_support::installed(0, Some(&chain))));
        let (pending, receiver) = tokio::sync::watch::channel(None);
        let roster = roster_support::publisher(
            vec![
                roster_support::peer("10.0.0.1", first_rx),
                roster_support::peer("10.0.0.2", receiver),
                roster_support::peer("10.0.0.3", third_rx),
            ],
            Vec::new(),
        );
        let publish = roster_support::installed(0, Some(&chain));
        tokio::spawn(async move {
            tokio::time::sleep(PENDING).await;
            pending.send_replace(Some(publish));
            std::future::pending::<()>().await;
        });
        let (peer_tx, _) = mpsc::channel(1);
        let svc = PolicyService::new(AccessMode::ReadOnly, peer_tx, None, None)
            .with_import_roster(roster.reader());

        let audit = GrpcAuditHandle::default();
        let mut request = Request::new(policy_stats_rpc_request("", "import"));
        request.extensions_mut().insert(audit.clone());
        let response = PolicyServiceRpc::get_policy_stats(&svc, request)
            .await
            .expect("import stats complete within the budget")
            .into_inner();
        assert_eq!(response.chains.len(), 3);
        drop((first, third));

        assert_eq!(
            audit.summary().unwrap().as_str(),
            concat!(
                "stage=import elapsed_ms=300 budget_ms=2000 rpc_elapsed_ms=300 code=Ok ",
                "publications=3/3 yields=1; ",
                "stage=datasets elapsed_ms=0 budget_ms=1700 rpc_elapsed_ms=300 code=Ok",
            )
        );
    }

    /// LAN-661: Tokio may poll a ready failed send before an expired
    /// `timeout_at`; policy stats must preserve deadline precedence instead of
    /// leaking backend closure as INTERNAL.
    #[tokio::test(start_paused = true)]
    async fn policy_stats_expired_deadline_precedes_immediately_closed_backend() {
        let closed_backend =
            std::future::ready(Err::<(), _>(Status::unavailable("backend unavailable")));
        let error =
            policy_stats_request(tokio::time::Instant::now(), "export", None, closed_backend)
                .await
                .expect_err("already-expired request must fail");

        assert_eq!(error.code(), tonic::Code::DeadlineExceeded);
    }

    /// Cancelling the RPC mid-capture keeps the waiting stage in the audit
    /// record and releases the capture's publication cursor.
    #[tokio::test(start_paused = true)]
    async fn get_policy_stats_cancellation_retains_waiting_stage_and_releases_capture() {
        let (publication, receiver) = tokio::sync::watch::channel(None);
        let roster =
            roster_support::publisher(vec![roster_support::peer("10.0.0.2", receiver)], Vec::new());
        let (peer_tx, _) = mpsc::channel(1);
        let svc = PolicyService::new(AccessMode::ReadOnly, peer_tx, None, None)
            .with_import_roster(roster.reader());
        let audit = GrpcAuditHandle::default();
        let mut request = Request::new(policy_stats_rpc_request("", "import"));
        request.extensions_mut().insert(audit.clone());
        let read =
            tokio::spawn(async move { PolicyServiceRpc::get_policy_stats(&svc, request).await });
        while publication.receiver_count() < 2 {
            tokio::task::yield_now().await;
        }
        read.abort();
        assert!(read.await.unwrap_err().is_cancelled());
        assert_eq!(
            publication.receiver_count(),
            1,
            "only the roster keeps a receiver"
        );
        assert_eq!(
            audit.summary().unwrap().as_str(),
            "stage=import budget_ms=2000 state=waiting"
        );
    }

    #[tokio::test]
    async fn get_policy_stats_rejects_bad_direction() {
        let (svc, _roster, _publication, _export, _) = stats_service();
        let err = PolicyServiceRpc::get_policy_stats(
            &svc,
            Request::new(proto::GetPolicyStatsRequest {
                allow_partial: false,
                peer_address: String::new(),
                direction: "sideways".to_string(),
            }),
        )
        .await
        .expect_err("unknown direction is invalid");
        assert_eq!(err.code(), tonic::Code::InvalidArgument);

        let err = PolicyServiceRpc::get_policy_stats(
            &svc,
            Request::new(proto::GetPolicyStatsRequest {
                allow_partial: false,
                peer_address: "not-an-ip".to_string(),
                direction: String::new(),
            }),
        )
        .await
        .expect_err("bad peer literal is invalid");
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    /// LAN-661 red proof: deleting the managed-peer validation lets the export
    /// capture return the global fallback labeled as the nonexistent peer and
    /// makes this call succeed.
    #[tokio::test]
    async fn get_policy_stats_rejects_unknown_peer_before_the_global_fallback() {
        let mut export = ExportRosterPublisher::new();
        export.publish(
            Vec::new(),
            Some(Arc::clone(stats_export_chain().hit_counters())),
        );
        let (roster, _publication) = stats_roster();
        let (peer_tx, _) = mpsc::channel::<PeerManagerCommand>(1);
        let svc = PolicyService::new(AccessMode::ReadOnly, peer_tx, None, None)
            .with_import_roster(roster.reader())
            .with_export_roster(export.reader());
        let err = PolicyServiceRpc::get_policy_stats(
            &svc,
            Request::new(proto::GetPolicyStatsRequest {
                allow_partial: false,
                peer_address: "192.0.2.99".to_string(),
                direction: "export".to_string(),
            }),
        )
        .await
        .expect_err("unknown peer must not inherit the global export chain");
        assert_eq!(err.code(), tonic::Code::NotFound);
        assert_eq!(err.message(), "neighbor 192.0.2.99 not found");
    }

    async fn staged_policy_delete(
        svc: PolicyService,
        config_rx: &mut mpsc::Receiver<ConfigEvent>,
    ) -> (
        tokio::task::JoinHandle<Result<Response<proto::DeletePolicyResponse>, Status>>,
        crate::peer_types::ConfigPersistAck,
    ) {
        let call = tokio::spawn(async move {
            PolicyServiceRpc::delete_policy(
                &svc,
                Request::new(proto::DeletePolicyRequest {
                    name: "edge-policy".into(),
                }),
            )
            .await
        });
        let ack = match config_rx
            .recv()
            .await
            .expect("expected staged policy delete")
        {
            ConfigEvent::DeletePolicy { name, ack } => {
                assert_eq!(name, "edge-policy");
                ack.expect("owned policy delete must use two-phase persistence")
            }
            _ => panic!("expected DeletePolicy"),
        };
        (call, ack)
    }

    #[tokio::test]
    async fn owned_policy_fully_compensated_discards_stage_and_returns_marker() {
        let (peer_tx, mut peer_rx) = mpsc::channel(4);
        let (config_tx, mut config_rx) = mpsc::channel(4);
        let coordinator = RuntimeConfigCoordinator::new();
        let svc = PolicyService::with_runtime_config_coordinator(
            AccessMode::ReadWrite,
            peer_tx,
            Some(config_tx),
            None,
            coordinator.clone(),
        );
        let (call, ack) = staged_policy_delete(svc, &mut config_rx).await;
        let staged = tokio::spawn(ack.accept());
        match peer_rx.recv().await.expect("expected owned policy delete") {
            PeerManagerCommand::OwnedCatalogMutation {
                mutation: OwnedCatalogMutation::DeletePolicy { name },
                reply,
            } => {
                assert_eq!(name, "edge-policy");
                reply
                    .send(OwnedCatalogMutationOutcome::FullyCompensated(
                        CatalogMutationError::failed_precondition(
                            "policy fan-out failed; prior runtime restored",
                        ),
                    ))
                    .unwrap();
            }
            _ => panic!("expected owned policy delete"),
        }
        assert!(
            !staged.await.unwrap(),
            "compensation must discard the stage"
        );
        let error = call.await.unwrap().unwrap_err();
        assert_eq!(error.code(), tonic::Code::FailedPrecondition);
        assert_eq!(
            error
                .metadata()
                .get("rustbgpd-runtime-config-outcome")
                .unwrap(),
            "fully-compensated"
        );
        assert_eq!(
            error.message(),
            "runtime effects were fully compensated; retry may repeat transient runtime changes: policy fan-out failed; prior runtime restored"
        );
        let _released = tokio::time::timeout(Duration::from_secs(1), coordinator.acquire())
            .await
            .expect("compensated policy mutation must release the coordinator")
            .expect("coordinator must remain open");
    }

    #[tokio::test(start_paused = true)]
    async fn owned_policy_stalled_stage_acknowledgement_is_clean_unavailable() {
        let (watchdog, terminal) =
            crate::runtime_config_settlement::RuntimeConfigSettlementWatchdog::for_crate_test(
                Duration::from_secs(60),
            );
        let (peer_tx, mut peer_rx) = mpsc::channel(4);
        let (config_tx, mut config_rx) = mpsc::channel(4);
        let coordinator = RuntimeConfigCoordinator::new();
        let svc = PolicyService::with_runtime_config_coordinator(
            AccessMode::ReadWrite,
            peer_tx,
            Some(config_tx),
            None,
            coordinator.clone(),
        )
        .with_runtime_config_settlement(watchdog.clone(), DaemonGate::new());
        // Handshake: the persister received the stage and never answers it.
        let (call, ack) = staged_policy_delete(svc, &mut config_rx).await;
        let crate::peer_types::ConfigPersistAck::Staged { staged, commit } = ack else {
            panic!("expected staged persistence")
        };
        // The 60 s budget leaves a 6 s margin; the bound here is only a
        // hang guard for a regression, which would otherwise wait forever.
        let error = tokio::time::timeout(Duration::from_secs(120), call)
            .await
            .expect("a stalled stage acknowledgement must end the owner cleanly")
            .unwrap()
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::Unavailable);
        assert_eq!(
            error.message(),
            "config persistence did not stage the candidate in time; nothing was applied"
        );
        assert!(commit.await.is_err(), "commit channel must be dropped");
        assert!(staged.send(Ok(())).is_err());
        assert!(peer_rx.try_recv().is_err(), "no actor command may follow");
        assert!(terminal.try_recv().is_err(), "a clean owner never fences");
        let _released = tokio::time::timeout(Duration::from_secs(1), coordinator.acquire())
            .await
            .expect("a clean stage timeout must release the coordinator")
            .expect("coordinator must remain open");
    }

    #[tokio::test]
    async fn owned_policy_actor_reply_loss_parks_without_response() {
        let (peer_tx, mut peer_rx) = mpsc::channel(4);
        let (config_tx, mut config_rx) = mpsc::channel(4);
        let svc = PolicyService::new(AccessMode::ReadWrite, peer_tx, Some(config_tx), None);
        let (mut call, ack) = staged_policy_delete(svc, &mut config_rx).await;
        let staged = tokio::spawn(ack.accept());
        match peer_rx.recv().await.expect("expected owned policy delete") {
            PeerManagerCommand::OwnedCatalogMutation {
                mutation: OwnedCatalogMutation::DeletePolicy { name },
                reply,
            } => {
                assert_eq!(name, "edge-policy");
                drop(reply);
            }
            _ => panic!("expected owned policy delete"),
        }
        assert!(!staged.await.unwrap(), "reply loss must discard the stage");
        assert!(
            tokio::time::timeout(Duration::from_millis(20), &mut call)
                .await
                .is_err(),
            "accepted actor reply loss must never produce an RPC response"
        );
        call.abort();
    }

    #[tokio::test]
    async fn owned_policy_commit_ack_loss_parks_without_response() {
        let (peer_tx, mut peer_rx) = mpsc::channel(4);
        let (config_tx, mut config_rx) = mpsc::channel(4);
        let svc = PolicyService::new(AccessMode::ReadWrite, peer_tx, Some(config_tx), None);
        let (mut call, ack) = staged_policy_delete(svc, &mut config_rx).await;
        let crate::peer_types::ConfigPersistAck::Staged { staged, commit } = ack else {
            panic!("expected staged persistence")
        };
        staged.send(Ok(())).unwrap();
        match peer_rx.recv().await.expect("expected owned policy delete") {
            PeerManagerCommand::OwnedCatalogMutation { reply, .. } => {
                reply.send(OwnedCatalogMutationOutcome::Success).unwrap();
            }
            _ => panic!("expected owned policy delete"),
        }
        let reply = commit
            .await
            .expect("runtime owner must hand off commit acknowledgement");
        drop(reply);
        assert!(
            tokio::time::timeout(Duration::from_millis(20), &mut call)
                .await
                .is_err(),
            "lost commit acknowledgement must never produce an RPC response"
        );
        call.abort();
    }

    fn owned_policy_delete_body(
        peer_tx: mpsc::Sender<PeerManagerCommand>,
        persist_permit: Option<mpsc::OwnedPermit<ConfigEvent>>,
    ) -> impl FnOnce(
        OwnedRuntimeConfigOperation,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = OwnedRuntimeConfigOutcome<(), Status>> + Send>,
    > {
        move |operation| {
            Box::pin(owned_policy_mutation_body(
                Some(operation),
                None,
                None,
                "test policy delete",
                peer_tx,
                OWNED_POLICY_ACTOR_TIMEOUT,
                OwnedCatalogMutation::DeletePolicy {
                    name: "edge-policy".to_string(),
                },
                ConfigEvent::DeletePolicy {
                    name: "edge-policy".to_string(),
                    ack: None,
                },
                persist_permit,
            ))
        }
    }

    #[tokio::test(start_paused = true)]
    async fn owned_policy_blocked_actor_send_ends_clean_at_the_pre_effect_deadline() {
        use crate::test_support::{
            assert_only_filler_delivered, full_peer_manager_queue, settle_exactly_at,
            spawn_owned_body,
        };
        let (peer_tx, mut peer_rx) = full_peer_manager_queue();
        let (config_tx, mut config_rx) = mpsc::channel(1);
        let permit = config_tx.reserve_owned().await.unwrap();
        let (join, operation, _watchdog, terminal) = spawn_owned_body(
            RuntimeConfigOperationKind::PolicyDelete,
            owned_policy_delete_body(peer_tx, Some(permit)),
        )
        .await;
        // Handshake: the stage is acknowledged, so the owner's remaining
        // pre-effect wait is the send into the full peer-manager queue.
        let Some(ConfigEvent::DeletePolicy {
            ack: Some(crate::peer_types::ConfigPersistAck::Staged { staged, commit }),
            ..
        }) = config_rx.recv().await
        else {
            panic!("expected a staged policy delete")
        };
        staged.send(Ok(())).unwrap();

        let error = settle_exactly_at(join, operation.pre_effect_deadline())
            .await
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::Unavailable);
        assert_eq!(
            error.message(),
            "peer manager mutation queue timed out before accepting command"
        );
        assert!(commit.await.is_err(), "the stage must be discarded");
        assert_only_filler_delivered(&mut peer_rx);
        assert!(terminal.try_recv().is_err(), "a clean owner never fences");
    }

    #[tokio::test(start_paused = true)]
    async fn owned_policy_accepted_reply_outlives_the_pre_effect_deadline() {
        let (peer_tx, mut peer_rx) = mpsc::channel(1);
        let (join, operation, _watchdog, terminal) = crate::test_support::spawn_owned_body(
            RuntimeConfigOperationKind::PolicyDelete,
            owned_policy_delete_body(peer_tx, None),
        )
        .await;
        // Handshake: the actor accepted the command, so it may have had an
        // effect and its reply must keep the actor bound, not the cap.
        let Some(PeerManagerCommand::OwnedCatalogMutation { reply, .. }) = peer_rx.recv().await
        else {
            panic!("expected the owned policy delete")
        };
        tokio::time::sleep_until(operation.pre_effect_deadline() + Duration::from_secs(1)).await;
        assert!(
            !reply.is_closed(),
            "the owner must still await the accepted reply past the pre-effect deadline"
        );
        assert!(
            !join.is_finished(),
            "an accepted reply must not end at the pre-effect deadline"
        );
        reply.send(OwnedCatalogMutationOutcome::Success).unwrap();
        tokio::time::timeout(Duration::from_secs(1), join)
            .await
            .expect("the owner finishes once the actor replies")
            .unwrap()
            .expect("an accepted, answered mutation succeeds");
        assert!(
            terminal.try_recv().is_err(),
            "a successful owner never fences"
        );
    }

    // ── Scoped selectors on read paths ──────────────────────────────
    //
    // Each read takes `fe80::1%eth0` while the import roster still lists
    // that neighbor, and the actor that supplies the data has meanwhile
    // reloaded it onto eth1: the controlled interleaving of a reload that
    // lands while the request is queued. The read must be NOT_FOUND, never
    // eth1's data under the eth0 selector.

    const LINK_LOCAL: &str = "fe80::1";

    fn link_local() -> IpAddr {
        LINK_LOCAL.parse().unwrap()
    }

    fn eth0_key() -> PeerKey {
        PeerKey::new(link_local(), Some("eth0".to_string()))
    }

    /// An import roster publishing `fe80::1%eth0`, so the API edge accepts
    /// the eth0 selector.
    fn eth0_roster() -> (ImportRosterPublisher, ImportRosterReader) {
        let publisher = crate::import_roster::test_support::publisher(
            vec![crate::import_roster::ImportRosterPeer {
                key: eth0_key(),
                session_id: 1,
                publication: tokio::sync::watch::channel(None).1,
                rib_peer: rustbgpd_transport::RibPeerSlot::default(),
            }],
            Vec::new(),
        );
        let reader = publisher.reader();
        (publisher, reader)
    }

    fn scoped_peer_info(interface: &str) -> crate::peer_types::PeerInfo {
        let mut info = crate::test_support::peer_info(link_local());
        info.interface = Some(interface.to_string());
        info
    }

    fn scoped_route(prefix: &str, interface: &str) -> rustbgpd_rib::Route {
        let mut route = test_route(prefix, 24);
        route.peer = PeerId::from_addr(link_local());
        route.aspa_context = rustbgpd_rib::route::AspaContextId::intern_scoped(
            rustbgpd_wire::AspaValidationContext::default(),
            Some(interface),
        );
        route
    }

    /// A dry-run page evaluated after its source neighbor learned a new
    /// address still reads that neighbor's context under the address the
    /// page's RIB turn had, and reports it in its samples.
    #[test]
    fn dry_run_source_follows_the_page_scope_across_a_rebind() {
        let moving = PeerId::allocate(rustbgpd_rib::PeerEndpoint::new(link_local(), Some("eth1")));
        let mut route = scoped_route("192.0.2.0", "eth1");
        route.peer = moving;
        let peers = rustbgpd_rib::PeerScope::capture();
        assert!(moving.rebind(rustbgpd_rib::PeerEndpoint::new(
            "fe80::99".parse().unwrap(),
            Some("eth1")
        )));
        assert_eq!(
            route_source_key(&route, &peers),
            PeerKey::new(link_local(), Some("eth1".to_string()))
        );
        assert!(moving.release());
    }

    /// Dry runs read a route's peer ASN and group from the neighbor that
    /// sent it: two neighbors on one link-local address keep their own.
    #[test]
    fn dry_run_peer_context_keeps_same_address_neighbors_apart() {
        let scoped = |name: &str| PeerKey::new(link_local(), Some(name.to_string()));
        let context: DryRunPeerContext = [
            (scoped("eth0"), (65_000, None)),
            (scoped("eth1"), (65_001, Some("fabric".to_string()))),
        ]
        .into_iter()
        .collect();
        let route = scoped_route("192.0.2.0", "eth1");
        let source = route_source_key(&route, &rustbgpd_rib::PeerScope::default());
        let ctx = dry_run_route_context(&route, "", Some(&source), &context);
        assert_eq!(ctx.peer_address, Some(link_local()));
        assert_eq!(ctx.peer_asn, Some(65_001));
        assert_eq!(ctx.peer_group, Some("fabric"));
    }

    /// Peer-manager reads carry the whole key to the actor, which answers
    /// `None` for a scope it no longer manages; the API maps that to
    /// `NOT_FOUND`. Numbered selectors reach it with no interface, as before.
    #[tokio::test]
    async fn peer_manager_policy_reads_carry_the_scope_and_map_a_stale_one_to_not_found() {
        let (peer_tx, mut peer_rx) = mpsc::channel(8);
        let (_roster, reader) = eth0_roster();
        let svc = PolicyService::new(AccessMode::ReadOnly, peer_tx, None, None)
            .with_import_roster(reader);
        let seen = Arc::new(Mutex::new(Vec::new()));
        let actor_seen = Arc::clone(&seen);
        tokio::spawn(async move {
            while let Some(cmd) = peer_rx.recv().await {
                match cmd {
                    PeerManagerCommand::GetNeighborPolicyChains { peer, reply } => {
                        actor_seen.lock().unwrap().push(peer);
                        let _ = reply.send(None);
                    }
                    PeerManagerCommand::ExplainImportPolicy { peer, reply, .. } => {
                        actor_seen.lock().unwrap().push(peer);
                        let _ = reply.send(None);
                    }
                    PeerManagerCommand::ListRejectedRoutes { peer, reply } => {
                        actor_seen.lock().unwrap().push(peer);
                        let _ = reply.send(None);
                    }
                    _ => panic!("unexpected peer-manager command"),
                }
            }
        });
        for selector in ["fe80::1%eth0", "192.0.2.1"] {
            let chains = PolicyServiceRpc::get_neighbor_policy_chains(
                &svc,
                Request::new(proto::GetNeighborPolicyChainsRequest {
                    address: selector.into(),
                }),
            )
            .await
            .unwrap_err();
            let explain = PolicyServiceRpc::explain_import_policy(
                &svc,
                Request::new(proto::ExplainImportPolicyRequest {
                    peer_address: selector.into(),
                    ..explain_request()
                }),
            )
            .await
            .unwrap_err();
            let rejected = PolicyServiceRpc::list_rejected_routes(
                &svc,
                Request::new(proto::ListRejectedRoutesRequest {
                    peer_address: selector.into(),
                }),
            )
            .await
            .unwrap_err();
            for error in [chains, explain, rejected] {
                assert_eq!(error.code(), tonic::Code::NotFound, "{selector}: {error:?}");
            }
        }
        let numbered = PeerKey::new("192.0.2.1".parse().unwrap(), None);
        assert_eq!(
            *seen.lock().unwrap(),
            [
                eth0_key(),
                eth0_key(),
                eth0_key(),
                numbered.clone(),
                numbered.clone(),
                numbered
            ]
        );
    }

    /// `TestPolicy`'s received-route page comes back with eth1's routes for
    /// the eth0 selector: `NOT_FOUND`, as `ListReceivedRoutes` answers.
    #[tokio::test]
    async fn test_policy_import_refuses_routes_from_a_replaced_scope() {
        let routes = vec![scoped_route("10.10.1.0", "eth1")];
        let (_roster, reader) = eth0_roster();
        let (svc, _) = policy_dry_run_service_with_peers(
            routes.clone(),
            None,
            None,
            vec![scoped_peer_info("eth0")],
        );
        let svc = svc.with_import_roster(reader.clone());
        let request = || proto::TestPolicyRequest {
            peer: "fe80::1%eth0".into(),
            ..test_policy_request()
        };
        let error = PolicyServiceRpc::test_policy(&svc, Request::new(request()))
            .await
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::NotFound, "{error:?}");
        assert_eq!(error.message(), "neighbor fe80::1%eth0 not found");

        // The same neighbor still on eth0 is evaluated.
        let (svc, _) = policy_dry_run_service_with_peers(
            vec![scoped_route("10.10.1.0", "eth0")],
            None,
            None,
            vec![scoped_peer_info("eth0")],
        );
        let svc = svc.with_import_roster(reader);
        let response = PolicyServiceRpc::test_policy(&svc, Request::new(request()))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(response.routes_evaluated, 1);
    }

    /// The dry-run peer context (ASN and peer group) comes from the peer
    /// manager's inventory, which now lists the neighbor on eth1: `TestPolicy`
    /// export and `ComparePolicy` are `NOT_FOUND` rather than evaluating with
    /// eth1's context.
    #[tokio::test]
    async fn dry_run_peer_context_refuses_a_replaced_scope() {
        let (_roster, reader) = eth0_roster();
        // One service per RPC: the fake RIB serves one paged walk.
        let service = || {
            let (svc, _) = policy_dry_run_service_with_peers(
                vec![test_route("10.10.1.0", 24)],
                None,
                Some(rustbgpd_rib::InstalledExportChain {
                    chain: None,
                    peer_interface: Some("eth0".into()),
                }),
                vec![scoped_peer_info("eth1")],
            );
            svc.with_import_roster(reader.clone())
        };
        let error = PolicyServiceRpc::test_policy(
            &service(),
            Request::new(proto::TestPolicyRequest {
                peer: "fe80::1%eth0".into(),
                direction: "export".into(),
                ..test_policy_request()
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(error.code(), tonic::Code::NotFound, "{error:?}");
        let error = PolicyServiceRpc::compare_policy(
            &service(),
            Request::new(proto::ComparePolicyRequest {
                peer: "fe80::1%eth0".into(),
                ..compare_request(COMPARE_INSTALLED_RPOL, &["client-x"], "")
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(error.code(), tonic::Code::NotFound, "{error:?}");
    }

    /// `ComparePolicy`'s baseline is the registered session's chain; the RIB
    /// reports that session's interface, and eth1's chain is not compared
    /// under the eth0 selector.
    #[tokio::test]
    async fn compare_policy_refuses_an_installed_chain_from_a_replaced_scope() {
        let (_roster, reader) = eth0_roster();
        let installed = |interface: &str| rustbgpd_rib::InstalledExportChain {
            chain: None,
            peer_interface: Some(interface.into()),
        };
        let request = || proto::ComparePolicyRequest {
            peer: "fe80::1%eth0".into(),
            ..compare_request(COMPARE_INSTALLED_RPOL, &["client-x"], "")
        };
        let (svc, commands) = policy_dry_run_service_with_peers(
            compare_routes(),
            None,
            Some(installed("eth1")),
            vec![scoped_peer_info("eth0")],
        );
        let svc = svc.with_import_roster(reader.clone());
        let error = PolicyServiceRpc::compare_policy(&svc, Request::new(request()))
            .await
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::NotFound, "{error:?}");
        assert_eq!(error.message(), "neighbor fe80::1%eth0 not found");
        assert_eq!(*commands.lock().unwrap(), ["chain"]);

        let (svc, _) = policy_dry_run_service_with_peers(
            compare_routes(),
            None,
            Some(installed("eth0")),
            vec![scoped_peer_info("eth0")],
        );
        let svc = svc.with_import_roster(reader);
        let response = PolicyServiceRpc::compare_policy(&svc, Request::new(request()))
            .await
            .unwrap()
            .into_inner();
        assert!(response.compiled);
    }

    /// Policy stats rows name a link-local neighbor as a bare address plus
    /// its interface: import rows from the roster key, export rows (keyed by
    /// bare address in the RIB) from the roster's unique peer at that
    /// address. Numbered and global rows carry no interface.
    #[tokio::test]
    async fn get_policy_stats_rows_carry_a_scoped_neighbor_interface() {
        let chain = roster_support::chain("customer-in(200)", 1);
        let (_scoped_publication, scoped_rx) =
            tokio::sync::watch::channel(Some(roster_support::installed(1, Some(&chain))));
        let (_numbered_publication, numbered_rx) =
            tokio::sync::watch::channel(Some(roster_support::installed(1, Some(&chain))));
        let import = roster_support::publisher(
            vec![
                crate::import_roster::ImportRosterPeer {
                    key: eth0_key(),
                    session_id: 1,
                    publication: scoped_rx,
                    rib_peer: rustbgpd_transport::RibPeerSlot::default(),
                },
                roster_support::peer("10.0.0.2", numbered_rx),
            ],
            Vec::new(),
        );
        let export_chain = stats_export_chain();
        // The RIB publishes a scoped neighbor's chain under its own handle.
        let scoped = PeerId::allocate(rustbgpd_rib::PeerEndpoint::new(link_local(), Some("eth0")));
        let mut export = ExportRosterPublisher::new();
        export.publish(
            vec![
                (scoped, Some(Arc::clone(export_chain.hit_counters()))),
                (
                    PeerId::from_addr("10.0.0.2".parse().unwrap()),
                    Some(Arc::clone(export_chain.hit_counters())),
                ),
            ],
            Some(Arc::clone(export_chain.hit_counters())),
        );
        let (peer_tx, _) = mpsc::channel::<PeerManagerCommand>(1);
        let svc = PolicyService::new(AccessMode::ReadOnly, peer_tx, None, None)
            .with_import_roster(import.reader())
            .with_export_roster(export.reader());
        let resp = PolicyServiceRpc::get_policy_stats(
            &svc,
            Request::new(policy_stats_rpc_request("", "both")),
        )
        .await
        .expect("stats query succeeds")
        .into_inner();
        let rows: Vec<(&str, &str, &str)> = resp
            .chains
            .iter()
            .map(|chain| {
                (
                    chain.direction.as_str(),
                    chain.peer_address.as_str(),
                    chain.peer_interface.as_str(),
                )
            })
            .collect();
        assert_eq!(
            rows,
            [
                ("export", "10.0.0.2", ""),
                ("export", LINK_LOCAL, "eth0"),
                ("export", "global", ""),
                ("import", "10.0.0.2", ""),
                ("import", LINK_LOCAL, "eth0"),
            ]
        );
        assert!(scoped.release());
    }

    /// `GetPolicyStats` selects from the one roster snapshot it parsed the
    /// selector against, by address and interface: a snapshot holding the
    /// address only on eth1 never yields eth1's row for eth0.
    #[test]
    fn policy_stats_selects_by_address_and_scope_from_one_snapshot() {
        let peer =
            |address: &str, interface: Option<&str>| crate::import_roster::ImportRosterPeer {
                key: PeerKey::new(address.parse().unwrap(), interface.map(str::to_string)),
                session_id: 1,
                publication: tokio::sync::watch::channel(None).1,
                rib_peer: rustbgpd_transport::RibPeerSlot::default(),
            };
        let publisher = crate::import_roster::test_support::publisher(
            vec![peer(LINK_LOCAL, Some("eth1")), peer("192.0.2.1", None)],
            Vec::new(),
        );
        let roster = publisher.reader().load();
        assert!(policy_stats_peer(&roster, &eth0_key()).is_none());
        let eth1 = PeerKey::new(link_local(), Some("eth1".to_string()));
        assert_eq!(policy_stats_peer(&roster, &eth1).unwrap().key, eth1);
        let numbered = PeerKey::new("192.0.2.1".parse().unwrap(), None);
        assert_eq!(policy_stats_peer(&roster, &numbered).unwrap().key, numbered);
    }
}
