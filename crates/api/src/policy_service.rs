//! gRPC policy service — named policy definitions and chain assignment.

use std::net::IpAddr;
use std::time::{Duration, UNIX_EPOCH};

use rustbgpd_transport::{CachedOutcome, ImportExplainReply, LookupResult, ResolvedMatch};
use rustbgpd_wire::{Afi, Ipv4Prefix, Ipv6Prefix, Prefix, Safi};
use tokio::sync::{mpsc, oneshot};
use tonic::{Request, Response, Status};

use crate::peer_types::{
    ConfigEvent, NamedPolicyDefinition, PeerManagerCommand, PolicyStatementDefinition,
};
use crate::policy_helpers::{proto_statement_to_input, validate_policy_action};
use crate::proto;
use crate::server::{
    AccessMode, ConfigMutationGateFn, apply_catalog_mutation, catalog_mutation_error_to_status,
    peer_manager_request, persist_rollback_error, persist_runtime_config_event,
    read_only_rejection, run_shielded_catalog_mutation,
};
use std::sync::Arc;

const CONFIG_PERSIST_RESERVE_TIMEOUT: Duration = Duration::from_secs(2);

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
    prefix: &str,
    prefix_length: u32,
    afi_safi: i32,
    resolved: ResolvedMatch,
) -> proto::ImportExplainMatch {
    let mut m = proto::ImportExplainMatch {
        outcome: proto::ImportExplainOutcome::Unspecified as i32,
        peer_address: peer_address.to_string(),
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
        m.matched_policy = d.matched_policy.unwrap_or_default();
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

#[allow(
    clippy::result_large_err,
    reason = "tonic::Status is the standard gRPC error type"
)]
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

async fn reserve_config_event_slot(
    config_tx: Option<mpsc::Sender<ConfigEvent>>,
) -> Result<Option<mpsc::OwnedPermit<ConfigEvent>>, Status> {
    let Some(tx) = config_tx else {
        return Ok(None);
    };

    let permit = tokio::time::timeout(CONFIG_PERSIST_RESERVE_TIMEOUT, tx.reserve_owned())
        .await
        .map_err(|_| {
            Status::internal("config persistence queue busy — refusing mutation to avoid drift")
        })?
        .map_err(|_| Status::internal("config persistence unavailable"))?;

    Ok(Some(permit))
}

/// gRPC service for named policy CRUD and chain assignment.
pub struct PolicyService {
    access_mode: AccessMode,
    peer_mgr_tx: mpsc::Sender<PeerManagerCommand>,
    config_tx: Option<mpsc::Sender<ConfigEvent>>,
    runtime_config_lock: Arc<tokio::sync::Mutex<()>>,
    config_mutation_gate: Option<ConfigMutationGateFn>,
    /// RIB query channel backing `TestPolicy`'s read-only snapshot
    /// (ADR-0096 Decision 6). `None` when the service was built
    /// without it — `TestPolicy` then reports `FAILED_PRECONDITION`.
    rib_tx: Option<mpsc::Sender<rustbgpd_rib::RibUpdate>>,
}

impl PolicyService {
    /// Create a new policy service with the given channels and a private
    /// runtime-config lock (tests / embedded use).
    #[cfg(test)]
    pub fn new(
        access_mode: AccessMode,
        peer_mgr_tx: mpsc::Sender<PeerManagerCommand>,
        config_tx: Option<mpsc::Sender<ConfigEvent>>,
        config_mutation_gate: Option<ConfigMutationGateFn>,
    ) -> Self {
        Self::with_runtime_config_lock(
            access_mode,
            peer_mgr_tx,
            config_tx,
            config_mutation_gate,
            Arc::new(tokio::sync::Mutex::new(())),
        )
    }

    /// Create a policy service sharing the daemon-wide runtime-config
    /// coordinator lock, so catalog mutations serialize with SIGHUP
    /// reload, neighbor / FIB-table CRUD, and config transactions.
    pub fn with_runtime_config_lock(
        access_mode: AccessMode,
        peer_mgr_tx: mpsc::Sender<PeerManagerCommand>,
        config_tx: Option<mpsc::Sender<ConfigEvent>>,
        config_mutation_gate: Option<ConfigMutationGateFn>,
        runtime_config_lock: Arc<tokio::sync::Mutex<()>>,
    ) -> Self {
        Self {
            access_mode,
            peer_mgr_tx,
            config_tx,
            runtime_config_lock,
            config_mutation_gate,
            rib_tx: None,
        }
    }

    /// Attach the RIB query channel that backs `TestPolicy`'s
    /// read-only route snapshot.
    #[must_use]
    pub fn with_rib_query(mut self, rib_tx: mpsc::Sender<rustbgpd_rib::RibUpdate>) -> Self {
        self.rib_tx = Some(rib_tx);
        self
    }

    /// Run `body` under the ADR-0080 detached-task shield with the
    /// runtime-config lock held and the transaction gate checked inside
    /// it (see `server::run_shielded_catalog_mutation`).
    async fn run_mutation<F, Fut>(&self, operation: &'static str, body: F) -> Result<(), Status>
    where
        F: FnOnce() -> Fut + Send + 'static,
        Fut: std::future::Future<Output = Result<(), Status>> + Send,
    {
        run_shielded_catalog_mutation(
            self.runtime_config_lock.clone(),
            self.config_mutation_gate.clone(),
            operation,
            body,
        )
        .await
    }
}

async fn get_policy_definition(
    peer_mgr_tx: &mpsc::Sender<PeerManagerCommand>,
    name: String,
) -> Result<Option<NamedPolicyDefinition>, Status> {
    let (reply_tx, reply_rx) = oneshot::channel();
    peer_mgr_tx
        .send(PeerManagerCommand::GetPolicy {
            name,
            reply: reply_tx,
        })
        .await
        .map_err(|_| Status::internal("peer manager unavailable"))?;
    reply_rx
        .await
        .map_err(|_| Status::internal("peer manager dropped reply"))
}

async fn set_policy_definition(
    peer_mgr_tx: &mpsc::Sender<PeerManagerCommand>,
    name: String,
    definition: NamedPolicyDefinition,
) -> Result<(), Status> {
    let (reply_tx, reply_rx) = oneshot::channel();
    peer_mgr_tx
        .send(PeerManagerCommand::SetPolicy {
            name,
            definition,
            reply: reply_tx,
        })
        .await
        .map_err(|_| Status::internal("peer manager unavailable"))?;
    reply_rx
        .await
        .map_err(|_| Status::internal("peer manager dropped reply"))?
        .map_err(|error| catalog_mutation_error_to_status(&error))
}

async fn delete_policy_definition(
    peer_mgr_tx: &mpsc::Sender<PeerManagerCommand>,
    name: String,
) -> Result<(), Status> {
    let (reply_tx, reply_rx) = oneshot::channel();
    peer_mgr_tx
        .send(PeerManagerCommand::DeletePolicy {
            name,
            reply: reply_tx,
        })
        .await
        .map_err(|_| Status::internal("peer manager unavailable"))?;
    reply_rx
        .await
        .map_err(|_| Status::internal("peer manager dropped reply"))?
        .map_err(|error| catalog_mutation_error_to_status(&error))
}

/// Restore a prior global import chain. An empty prior chain and a
/// cleared chain are the same config state (`policy.import_chain`), so
/// an empty restore issues the clear command.
async fn restore_global_import_chain(
    peer_mgr_tx: &mpsc::Sender<PeerManagerCommand>,
    prior: Vec<String>,
) -> Result<(), Status> {
    if prior.is_empty() {
        apply_catalog_mutation(peer_mgr_tx, |reply| {
            PeerManagerCommand::ClearGlobalImportChain { reply }
        })
        .await
    } else {
        apply_catalog_mutation(peer_mgr_tx, |reply| {
            PeerManagerCommand::SetGlobalImportChain {
                policy_names: prior,
                reply,
            }
        })
        .await
    }
}

/// Restore a prior global export chain (see `restore_global_import_chain`
/// for the empty-chain equivalence).
async fn restore_global_export_chain(
    peer_mgr_tx: &mpsc::Sender<PeerManagerCommand>,
    prior: Vec<String>,
) -> Result<(), Status> {
    if prior.is_empty() {
        apply_catalog_mutation(peer_mgr_tx, |reply| {
            PeerManagerCommand::ClearGlobalExportChain { reply }
        })
        .await
    } else {
        apply_catalog_mutation(peer_mgr_tx, |reply| {
            PeerManagerCommand::SetGlobalExportChain {
                policy_names: prior,
                reply,
            }
        })
        .await
    }
}

/// Restore a prior per-neighbor import chain (see
/// `restore_global_import_chain` for the empty-chain equivalence).
async fn restore_neighbor_import_chain(
    peer_mgr_tx: &mpsc::Sender<PeerManagerCommand>,
    address: IpAddr,
    prior: Vec<String>,
) -> Result<(), Status> {
    if prior.is_empty() {
        apply_catalog_mutation(peer_mgr_tx, |reply| {
            PeerManagerCommand::ClearNeighborImportChain { address, reply }
        })
        .await
    } else {
        apply_catalog_mutation(peer_mgr_tx, |reply| {
            PeerManagerCommand::SetNeighborImportChain {
                address,
                policy_names: prior,
                reply,
            }
        })
        .await
    }
}

/// Restore a prior per-neighbor export chain (see
/// `restore_global_import_chain` for the empty-chain equivalence).
async fn restore_neighbor_export_chain(
    peer_mgr_tx: &mpsc::Sender<PeerManagerCommand>,
    address: IpAddr,
    prior: Vec<String>,
) -> Result<(), Status> {
    if prior.is_empty() {
        apply_catalog_mutation(peer_mgr_tx, |reply| {
            PeerManagerCommand::ClearNeighborExportChain { address, reply }
        })
        .await
    } else {
        apply_catalog_mutation(peer_mgr_tx, |reply| {
            PeerManagerCommand::SetNeighborExportChain {
                address,
                policy_names: prior,
                reply,
            }
        })
        .await
    }
}

#[tonic::async_trait]
impl proto::policy_service_server::PolicyService for PolicyService {
    async fn list_policies(
        &self,
        _request: Request<proto::ListPoliciesRequest>,
    ) -> Result<Response<proto::ListPoliciesResponse>, Status> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.peer_mgr_tx
            .send(PeerManagerCommand::ListPolicies { reply: reply_tx })
            .await
            .map_err(|_| Status::internal("peer manager unavailable"))?;
        let policies = reply_rx
            .await
            .map_err(|_| Status::internal("peer manager dropped reply"))?;
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
        let (reply_tx, reply_rx) = oneshot::channel();
        self.peer_mgr_tx
            .send(PeerManagerCommand::GetPolicy {
                name: req.name.clone(),
                reply: reply_tx,
            })
            .await
            .map_err(|_| Status::internal("peer manager unavailable"))?;
        let definition = reply_rx
            .await
            .map_err(|_| Status::internal("peer manager dropped reply"))?
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
        let peer_mgr_tx = self.peer_mgr_tx.clone();
        let name = req.name;
        self.run_mutation("PolicyService.SetPolicy", move || async move {
            // Prior state is read inside the runtime-config lock, so it
            // cannot race another catalog writer (all of them take this
            // lock); it becomes the rollback target if persistence fails.
            let prior = get_policy_definition(&peer_mgr_tx, name.clone()).await?;
            set_policy_definition(&peer_mgr_tx, name.clone(), definition.clone()).await?;

            if let Some(permit) = persist_permit
                && let Err(error) =
                    persist_runtime_config_event(permit, |ack| ConfigEvent::SetPolicy {
                        name: name.clone(),
                        definition: definition.clone(),
                        ack: Some(ack),
                    })
                    .await
            {
                let rollback = match prior {
                    Some(prior) => set_policy_definition(&peer_mgr_tx, name.clone(), prior).await,
                    None => delete_policy_definition(&peer_mgr_tx, name.clone()).await,
                };
                return Err(persist_rollback_error("policy set", error, rollback));
            }
            Ok(())
        })
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
        let peer_mgr_tx = self.peer_mgr_tx.clone();
        let name = req.name;
        self.run_mutation("PolicyService.DeletePolicy", move || async move {
            let prior = get_policy_definition(&peer_mgr_tx, name.clone()).await?;
            delete_policy_definition(&peer_mgr_tx, name.clone()).await?;

            if let Some(permit) = persist_permit
                && let Err(error) =
                    persist_runtime_config_event(permit, |ack| ConfigEvent::DeletePolicy {
                        name: name.clone(),
                        ack: Some(ack),
                    })
                    .await
            {
                let rollback = match prior {
                    Some(prior) => set_policy_definition(&peer_mgr_tx, name.clone(), prior).await,
                    // Deletes are idempotent (a missing policy is not an
                    // error), so a `None` prior leaves nothing to restore.
                    None => Ok(()),
                };
                return Err(persist_rollback_error("policy delete", error, rollback));
            }
            Ok(())
        })
        .await?;

        Ok(Response::new(proto::DeletePolicyResponse {}))
    }

    async fn list_neighbor_sets(
        &self,
        _request: Request<proto::ListNeighborSetsRequest>,
    ) -> Result<Response<proto::ListNeighborSetsResponse>, Status> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.peer_mgr_tx
            .send(PeerManagerCommand::ListNeighborSets { reply: reply_tx })
            .await
            .map_err(|_| Status::internal("peer manager unavailable"))?;
        let neighbor_sets = reply_rx
            .await
            .map_err(|_| Status::internal("peer manager dropped reply"))?;
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
        let (reply_tx, reply_rx) = oneshot::channel();
        self.peer_mgr_tx
            .send(PeerManagerCommand::GetNeighborSet {
                name: req.name.clone(),
                reply: reply_tx,
            })
            .await
            .map_err(|_| Status::internal("peer manager unavailable"))?;
        let definition = reply_rx
            .await
            .map_err(|_| Status::internal("peer manager dropped reply"))?
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
        let peer_mgr_tx = self.peer_mgr_tx.clone();
        let name = req.name;
        self.run_mutation("PolicyService.SetNeighborSet", move || async move {
            let prior =
                peer_manager_request(&peer_mgr_tx, |reply| PeerManagerCommand::GetNeighborSet {
                    name: name.clone(),
                    reply,
                })
                .await?;
            apply_catalog_mutation(&peer_mgr_tx, |reply| PeerManagerCommand::SetNeighborSet {
                name: name.clone(),
                definition: definition.clone(),
                reply,
            })
            .await?;

            if let Some(permit) = persist_permit
                && let Err(error) =
                    persist_runtime_config_event(permit, |ack| ConfigEvent::SetNeighborSet {
                        name: name.clone(),
                        definition: definition.clone(),
                        ack: Some(ack),
                    })
                    .await
            {
                let rollback = match prior {
                    Some(prior) => {
                        apply_catalog_mutation(&peer_mgr_tx, |reply| {
                            PeerManagerCommand::SetNeighborSet {
                                name: name.clone(),
                                definition: prior,
                                reply,
                            }
                        })
                        .await
                    }
                    None => {
                        apply_catalog_mutation(&peer_mgr_tx, |reply| {
                            PeerManagerCommand::DeleteNeighborSet {
                                name: name.clone(),
                                reply,
                            }
                        })
                        .await
                    }
                };
                return Err(persist_rollback_error("neighbor-set set", error, rollback));
            }
            Ok(())
        })
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
        let peer_mgr_tx = self.peer_mgr_tx.clone();
        let name = req.name;
        self.run_mutation("PolicyService.DeleteNeighborSet", move || async move {
            let prior =
                peer_manager_request(&peer_mgr_tx, |reply| PeerManagerCommand::GetNeighborSet {
                    name: name.clone(),
                    reply,
                })
                .await?;
            apply_catalog_mutation(&peer_mgr_tx, |reply| {
                PeerManagerCommand::DeleteNeighborSet {
                    name: name.clone(),
                    reply,
                }
            })
            .await?;

            if let Some(permit) = persist_permit
                && let Err(error) =
                    persist_runtime_config_event(permit, |ack| ConfigEvent::DeleteNeighborSet {
                        name: name.clone(),
                        ack: Some(ack),
                    })
                    .await
            {
                let rollback = match prior {
                    Some(prior) => {
                        apply_catalog_mutation(&peer_mgr_tx, |reply| {
                            PeerManagerCommand::SetNeighborSet {
                                name: name.clone(),
                                definition: prior,
                                reply,
                            }
                        })
                        .await
                    }
                    // Deletes are idempotent (a missing set is not an
                    // error), so a `None` prior leaves nothing to restore.
                    None => Ok(()),
                };
                return Err(persist_rollback_error(
                    "neighbor-set delete",
                    error,
                    rollback,
                ));
            }
            Ok(())
        })
        .await?;

        Ok(Response::new(proto::DeleteNeighborSetResponse {}))
    }

    async fn get_global_policy_chains(
        &self,
        _request: Request<proto::GetGlobalPolicyChainsRequest>,
    ) -> Result<Response<proto::GlobalPolicyChains>, Status> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.peer_mgr_tx
            .send(PeerManagerCommand::GetGlobalPolicyChains { reply: reply_tx })
            .await
            .map_err(|_| Status::internal("peer manager unavailable"))?;
        let chains = reply_rx
            .await
            .map_err(|_| Status::internal("peer manager dropped reply"))?;
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
        let peer_mgr_tx = self.peer_mgr_tx.clone();
        let policy_names = req.policy_names;
        self.run_mutation("PolicyService.SetGlobalImportChain", move || async move {
            let prior = peer_manager_request(&peer_mgr_tx, |reply| {
                PeerManagerCommand::GetGlobalPolicyChains { reply }
            })
            .await?;
            apply_catalog_mutation(&peer_mgr_tx, |reply| {
                PeerManagerCommand::SetGlobalImportChain {
                    policy_names: policy_names.clone(),
                    reply,
                }
            })
            .await?;

            if let Some(permit) = persist_permit
                && let Err(error) =
                    persist_runtime_config_event(permit, |ack| ConfigEvent::SetGlobalImportChain {
                        policy_names: policy_names.clone(),
                        ack: Some(ack),
                    })
                    .await
            {
                let rollback =
                    restore_global_import_chain(&peer_mgr_tx, prior.import_policy_names).await;
                return Err(persist_rollback_error(
                    "global import-chain set",
                    error,
                    rollback,
                ));
            }
            Ok(())
        })
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
        let peer_mgr_tx = self.peer_mgr_tx.clone();
        let policy_names = req.policy_names;
        self.run_mutation("PolicyService.SetGlobalExportChain", move || async move {
            let prior = peer_manager_request(&peer_mgr_tx, |reply| {
                PeerManagerCommand::GetGlobalPolicyChains { reply }
            })
            .await?;
            apply_catalog_mutation(&peer_mgr_tx, |reply| {
                PeerManagerCommand::SetGlobalExportChain {
                    policy_names: policy_names.clone(),
                    reply,
                }
            })
            .await?;

            if let Some(permit) = persist_permit
                && let Err(error) =
                    persist_runtime_config_event(permit, |ack| ConfigEvent::SetGlobalExportChain {
                        policy_names: policy_names.clone(),
                        ack: Some(ack),
                    })
                    .await
            {
                let rollback =
                    restore_global_export_chain(&peer_mgr_tx, prior.export_policy_names).await;
                return Err(persist_rollback_error(
                    "global export-chain set",
                    error,
                    rollback,
                ));
            }
            Ok(())
        })
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
        let peer_mgr_tx = self.peer_mgr_tx.clone();
        self.run_mutation("PolicyService.ClearGlobalImportChain", move || async move {
            let prior = peer_manager_request(&peer_mgr_tx, |reply| {
                PeerManagerCommand::GetGlobalPolicyChains { reply }
            })
            .await?;
            apply_catalog_mutation(&peer_mgr_tx, |reply| {
                PeerManagerCommand::ClearGlobalImportChain { reply }
            })
            .await?;

            if let Some(permit) = persist_permit
                && let Err(error) = persist_runtime_config_event(permit, |ack| {
                    ConfigEvent::ClearGlobalImportChain { ack: Some(ack) }
                })
                .await
            {
                let rollback =
                    restore_global_import_chain(&peer_mgr_tx, prior.import_policy_names).await;
                return Err(persist_rollback_error(
                    "global import-chain clear",
                    error,
                    rollback,
                ));
            }
            Ok(())
        })
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
        let peer_mgr_tx = self.peer_mgr_tx.clone();
        self.run_mutation("PolicyService.ClearGlobalExportChain", move || async move {
            let prior = peer_manager_request(&peer_mgr_tx, |reply| {
                PeerManagerCommand::GetGlobalPolicyChains { reply }
            })
            .await?;
            apply_catalog_mutation(&peer_mgr_tx, |reply| {
                PeerManagerCommand::ClearGlobalExportChain { reply }
            })
            .await?;

            if let Some(permit) = persist_permit
                && let Err(error) = persist_runtime_config_event(permit, |ack| {
                    ConfigEvent::ClearGlobalExportChain { ack: Some(ack) }
                })
                .await
            {
                let rollback =
                    restore_global_export_chain(&peer_mgr_tx, prior.export_policy_names).await;
                return Err(persist_rollback_error(
                    "global export-chain clear",
                    error,
                    rollback,
                ));
            }
            Ok(())
        })
        .await?;

        Ok(Response::new(proto::ClearGlobalExportChainResponse {}))
    }

    async fn get_neighbor_policy_chains(
        &self,
        request: Request<proto::GetNeighborPolicyChainsRequest>,
    ) -> Result<Response<proto::NeighborPolicyChains>, Status> {
        let req = request.into_inner();
        let address: IpAddr = req
            .address
            .parse()
            .map_err(|e| Status::invalid_argument(format!("invalid address: {e}")))?;
        let (reply_tx, reply_rx) = oneshot::channel();
        self.peer_mgr_tx
            .send(PeerManagerCommand::GetNeighborPolicyChains {
                address,
                reply: reply_tx,
            })
            .await
            .map_err(|_| Status::internal("peer manager unavailable"))?;
        let chains = reply_rx
            .await
            .map_err(|_| Status::internal("peer manager dropped reply"))?
            .ok_or_else(|| Status::not_found("neighbor not found"))?;
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
        let address: IpAddr = req
            .address
            .parse()
            .map_err(|e| Status::invalid_argument(format!("invalid address: {e}")))?;
        let persist_permit = reserve_config_event_slot(self.config_tx.clone()).await?;
        let peer_mgr_tx = self.peer_mgr_tx.clone();
        let policy_names = req.policy_names;
        self.run_mutation("PolicyService.SetNeighborImportChain", move || async move {
            let prior = peer_manager_request(&peer_mgr_tx, |reply| {
                PeerManagerCommand::GetNeighborPolicyChains { address, reply }
            })
            .await?;
            apply_catalog_mutation(&peer_mgr_tx, |reply| {
                PeerManagerCommand::SetNeighborImportChain {
                    address,
                    policy_names: policy_names.clone(),
                    reply,
                }
            })
            .await?;

            if let Some(permit) = persist_permit
                && let Err(error) = persist_runtime_config_event(permit, |ack| {
                    ConfigEvent::SetNeighborImportChain {
                        address,
                        policy_names: policy_names.clone(),
                        ack: Some(ack),
                    }
                })
                .await
            {
                let rollback = match prior {
                    Some(prior) => {
                        restore_neighbor_import_chain(
                            &peer_mgr_tx,
                            address,
                            prior.import_policy_names,
                        )
                        .await
                    }
                    // The mutation succeeded, so the neighbor was
                    // configured; an unexpectedly missing prior leaves
                    // nothing to restore.
                    None => Ok(()),
                };
                return Err(persist_rollback_error(
                    "neighbor import-chain set",
                    error,
                    rollback,
                ));
            }
            Ok(())
        })
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
        let address: IpAddr = req
            .address
            .parse()
            .map_err(|e| Status::invalid_argument(format!("invalid address: {e}")))?;
        let persist_permit = reserve_config_event_slot(self.config_tx.clone()).await?;
        let peer_mgr_tx = self.peer_mgr_tx.clone();
        let policy_names = req.policy_names;
        self.run_mutation("PolicyService.SetNeighborExportChain", move || async move {
            let prior = peer_manager_request(&peer_mgr_tx, |reply| {
                PeerManagerCommand::GetNeighborPolicyChains { address, reply }
            })
            .await?;
            apply_catalog_mutation(&peer_mgr_tx, |reply| {
                PeerManagerCommand::SetNeighborExportChain {
                    address,
                    policy_names: policy_names.clone(),
                    reply,
                }
            })
            .await?;

            if let Some(permit) = persist_permit
                && let Err(error) = persist_runtime_config_event(permit, |ack| {
                    ConfigEvent::SetNeighborExportChain {
                        address,
                        policy_names: policy_names.clone(),
                        ack: Some(ack),
                    }
                })
                .await
            {
                let rollback = match prior {
                    Some(prior) => {
                        restore_neighbor_export_chain(
                            &peer_mgr_tx,
                            address,
                            prior.export_policy_names,
                        )
                        .await
                    }
                    None => Ok(()),
                };
                return Err(persist_rollback_error(
                    "neighbor export-chain set",
                    error,
                    rollback,
                ));
            }
            Ok(())
        })
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
        let address: IpAddr = req
            .address
            .parse()
            .map_err(|e| Status::invalid_argument(format!("invalid address: {e}")))?;
        let persist_permit = reserve_config_event_slot(self.config_tx.clone()).await?;
        let peer_mgr_tx = self.peer_mgr_tx.clone();
        self.run_mutation(
            "PolicyService.ClearNeighborImportChain",
            move || async move {
                let prior = peer_manager_request(&peer_mgr_tx, |reply| {
                    PeerManagerCommand::GetNeighborPolicyChains { address, reply }
                })
                .await?;
                apply_catalog_mutation(&peer_mgr_tx, |reply| {
                    PeerManagerCommand::ClearNeighborImportChain { address, reply }
                })
                .await?;

                if let Some(permit) = persist_permit
                    && let Err(error) = persist_runtime_config_event(permit, |ack| {
                        ConfigEvent::ClearNeighborImportChain {
                            address,
                            ack: Some(ack),
                        }
                    })
                    .await
                {
                    let rollback = match prior {
                        Some(prior) => {
                            restore_neighbor_import_chain(
                                &peer_mgr_tx,
                                address,
                                prior.import_policy_names,
                            )
                            .await
                        }
                        None => Ok(()),
                    };
                    return Err(persist_rollback_error(
                        "neighbor import-chain clear",
                        error,
                        rollback,
                    ));
                }
                Ok(())
            },
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
        let address: IpAddr = req
            .address
            .parse()
            .map_err(|e| Status::invalid_argument(format!("invalid address: {e}")))?;
        let persist_permit = reserve_config_event_slot(self.config_tx.clone()).await?;
        let peer_mgr_tx = self.peer_mgr_tx.clone();
        self.run_mutation(
            "PolicyService.ClearNeighborExportChain",
            move || async move {
                let prior = peer_manager_request(&peer_mgr_tx, |reply| {
                    PeerManagerCommand::GetNeighborPolicyChains { address, reply }
                })
                .await?;
                apply_catalog_mutation(&peer_mgr_tx, |reply| {
                    PeerManagerCommand::ClearNeighborExportChain { address, reply }
                })
                .await?;

                if let Some(permit) = persist_permit
                    && let Err(error) = persist_runtime_config_event(permit, |ack| {
                        ConfigEvent::ClearNeighborExportChain {
                            address,
                            ack: Some(ack),
                        }
                    })
                    .await
                {
                    let rollback = match prior {
                        Some(prior) => {
                            restore_neighbor_export_chain(
                                &peer_mgr_tx,
                                address,
                                prior.export_policy_names,
                            )
                            .await
                        }
                        None => Ok(()),
                    };
                    return Err(persist_rollback_error(
                        "neighbor export-chain clear",
                        error,
                        rollback,
                    ));
                }
                Ok(())
            },
        )
        .await?;

        Ok(Response::new(proto::ClearNeighborExportChainResponse {}))
    }

    async fn explain_import_policy(
        &self,
        request: Request<proto::ExplainImportPolicyRequest>,
    ) -> Result<Response<proto::ExplainImportPolicyResponse>, Status> {
        let req = request.into_inner();
        let address: IpAddr = req
            .peer_address
            .parse()
            .map_err(|e| Status::invalid_argument(format!("invalid peer_address: {e}")))?;
        let (afi, safi) = explain_afi_safi(req.afi_safi)?;
        let prefix = explain_prefix(afi, &req.prefix, req.prefix_length)?;

        let (reply_tx, reply_rx) = oneshot::channel();
        self.peer_mgr_tx
            .send(PeerManagerCommand::ExplainImportPolicy {
                address,
                afi,
                safi,
                prefix,
                path_id: req.path_id,
                reply: reply_tx,
            })
            .await
            .map_err(|_| Status::internal("peer manager unavailable"))?;
        let reply: Option<ImportExplainReply> = reply_rx
            .await
            .map_err(|_| Status::internal("peer manager dropped reply"))?;

        // `None` (no live session) and an empty match set (never seen)
        // both render as a single synthetic NOT_SEEN so the operator
        // always gets a definite answer rather than an empty list.
        let (current_generation, mut matches) = match reply {
            Some(r) => {
                let proto_matches: Vec<proto::ImportExplainMatch> = r
                    .matches
                    .into_iter()
                    .map(|resolved| {
                        resolved_match_to_proto(
                            &req.peer_address,
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
            matches.push(resolved_match_to_proto(
                &req.peer_address,
                &req.prefix,
                req.prefix_length,
                req.afi_safi,
                ResolvedMatch {
                    path_id: req.path_id.unwrap_or(0),
                    result: LookupResult::NotSeen,
                    statements: Vec::new(),
                },
            ));
        }

        Ok(Response::new(proto::ExplainImportPolicyResponse {
            peer_address: req.peer_address,
            prefix: req.prefix,
            prefix_length: req.prefix_length,
            afi_safi: req.afi_safi,
            current_policy_generation: current_generation,
            matches,
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
        use rustbgpd_policy::rpol::{RpolFile, parse_call_form};
        use rustbgpd_policy::sets::SetStore;
        use rustbgpd_rib::RibUpdate;

        let req = request.into_inner();
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
        let peer_filter: Option<IpAddr> = if req.peer.is_empty() {
            None
        } else {
            Some(
                req.peer
                    .parse()
                    .map_err(|e| Status::invalid_argument(format!("invalid peer: {e}")))?,
            )
        };

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
        let (base, args) = parse_call_form(&req.policy).map_err(Status::invalid_argument)?;
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
        let mut store = SetStore::new();
        let chain = file
            .compile_policy(base, &args, &mut store)
            .expect("existence checked above");

        // Read-only route snapshot via the existing RIB query
        // machinery. Import evaluates Adj-RIB-In (optionally one
        // peer's); export evaluates Loc-RIB best routes.
        let rib_tx = self.rib_tx.as_ref().ok_or_else(|| {
            Status::failed_precondition("route snapshot runtime unavailable on this listener")
        })?;
        let (reply_tx, reply_rx) = oneshot::channel();
        let query = if import {
            RibUpdate::QueryReceivedRoutes {
                peer: peer_filter,
                reply: reply_tx,
            }
        } else {
            RibUpdate::QueryBestRoutes { reply: reply_tx }
        };
        rib_tx
            .send(query)
            .await
            .map_err(|_| Status::internal("RIB manager unavailable"))?;
        let routes = reply_rx
            .await
            .map_err(|_| Status::internal("RIB manager dropped reply"))?;

        // Peer context (ASN / peer-group) so guards on peer.* fields
        // see real values.
        let (peers_tx, peers_rx) = oneshot::channel();
        self.peer_mgr_tx
            .send(PeerManagerCommand::ListPeers { reply: peers_tx })
            .await
            .map_err(|_| Status::internal("peer manager unavailable"))?;
        let peer_context: std::collections::HashMap<IpAddr, (u32, Option<String>)> = peers_rx
            .await
            .map_err(|_| Status::internal("peer manager dropped reply"))?
            .into_iter()
            .map(|info| (info.address, (info.remote_asn, info.peer_group)))
            .collect();

        Ok(Response::new(run_test_policy(
            &chain,
            &routes,
            &TestPolicyScope {
                import,
                target_peer: peer_filter,
                family_filter,
                limit: req.limit as usize,
                show_changes: req.show_changes as usize,
            },
            &peer_context,
        )))
    }

    async fn get_policy_stats(
        &self,
        request: Request<proto::GetPolicyStatsRequest>,
    ) -> Result<Response<proto::GetPolicyStatsResponse>, Status> {
        use rustbgpd_rib::RibUpdate;

        let req = request.into_inner();
        match req.direction.as_str() {
            "" | "export" => {}
            "import" => {
                return Err(Status::unimplemented(
                    "import-side hit counters have no read surface yet; \
                     counters accumulate and the query arrives in a later slice",
                ));
            }
            other => {
                return Err(Status::invalid_argument(format!(
                    "direction must be \"import\" or \"export\", got {other:?}"
                )));
            }
        }
        let peer: Option<IpAddr> = if req.peer_address.is_empty() {
            None
        } else {
            Some(req.peer_address.parse().map_err(|_| {
                Status::invalid_argument(format!("invalid peer address {:?}", req.peer_address))
            })?)
        };
        let rib_tx = self.rib_tx.as_ref().ok_or_else(|| {
            Status::failed_precondition("policy stats runtime unavailable on this listener")
        })?;
        let (reply_tx, reply_rx) = oneshot::channel();
        rib_tx
            .send(RibUpdate::QueryExportPolicyTermHits {
                peer,
                reply: reply_tx,
            })
            .await
            .map_err(|_| Status::internal("RIB manager unavailable"))?;
        let chains = reply_rx
            .await
            .map_err(|_| Status::internal("RIB manager dropped reply"))?;

        Ok(Response::new(proto::GetPolicyStatsResponse {
            chains: chains
                .into_iter()
                .map(|chain| proto::PolicyChainStats {
                    peer_address: chain
                        .peer
                        .map_or_else(|| "global".to_string(), |peer| peer.to_string()),
                    direction: "export".to_string(),
                    routes_evaluated: chain.evals,
                    terms: chain
                        .terms
                        .into_iter()
                        .map(|row| proto::PolicyTermStat {
                            policy_index: u32::try_from(row.policy_index).unwrap_or(u32::MAX),
                            policy: row.policy.unwrap_or_default(),
                            term_index: u32::try_from(row.term_index).unwrap_or(u32::MAX),
                            term: row.term.unwrap_or_default(),
                            hits: row.hits,
                        })
                        .collect(),
                })
                .collect(),
        }))
    }
}

/// Route selection scope for one `TestPolicy` dry run.
struct TestPolicyScope {
    /// Import (Adj-RIB-In snapshot, peer context from each route's
    /// source peer) vs export (Loc-RIB snapshot, peer context from
    /// `target_peer`).
    import: bool,
    /// Export evaluation target (also the import snapshot filter,
    /// applied upstream by the RIB query).
    target_peer: Option<IpAddr>,
    /// `Some(true)` = IPv4 only, `Some(false)` = IPv6 only.
    family_filter: Option<bool>,
    /// Max routes evaluated; 0 = all.
    limit: usize,
    /// Max before/after diff samples returned.
    show_changes: usize,
}

/// Evaluate the compiled candidate policy read-only over the route
/// snapshot: counts, per-term hit counters, and up to
/// `scope.show_changes` before/after diff samples. Pure function of
/// its inputs — no daemon state is touched (ADR-0096 Decision 6).
fn run_test_policy(
    chain: &rustbgpd_policy::ir::CompiledChain,
    routes: &[rustbgpd_rib::Route],
    scope: &TestPolicyScope,
    peer_context: &std::collections::HashMap<IpAddr, (u32, Option<String>)>,
) -> proto::TestPolicyResponse {
    use rustbgpd_policy::{PolicyAction, RouteContext, RouteType};
    use rustbgpd_rib::RouteOrigin;

    let needs_as_path_string = chain.requires_as_path_string();
    let mut hits = chain.zero_term_hits();
    let mut response = proto::TestPolicyResponse {
        compiled: true,
        ..Default::default()
    };
    for route in routes
        .iter()
        .filter(|route| {
            scope
                .family_filter
                .is_none_or(|v4| matches!(route.prefix, Prefix::V4(_)) == v4)
        })
        .take(if scope.limit == 0 {
            usize::MAX
        } else {
            scope.limit
        })
    {
        let ctx_peer = if scope.import {
            Some(route.peer)
        } else {
            scope.target_peer
        };
        let (peer_asn, peer_group) = ctx_peer
            .and_then(|addr| peer_context.get(&addr))
            .map_or((None, None), |(asn, group)| (Some(*asn), group.as_deref()));
        let as_path_str = if needs_as_path_string {
            route
                .as_path()
                .map_or_else(String::new, rustbgpd_wire::AsPath::to_aspath_string)
        } else {
            String::new()
        };
        let ctx = RouteContext {
            prefix: Some(route.prefix),
            next_hop: Some(route.next_hop),
            extended_communities: route.extended_communities(),
            communities: route.communities(),
            large_communities: route.large_communities(),
            as_path_str: &as_path_str,
            as_path_len: route.as_path().map_or(0, rustbgpd_wire::AsPath::len),
            origin_asn: route.as_path().and_then(rustbgpd_wire::AsPath::origin_asn),
            validation_state: route.validation_state,
            aspa_state: route.aspa_state,
            peer_address: ctx_peer,
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
        };
        response.routes_evaluated += 1;
        let result = chain.evaluate_recording_hits(&ctx, &mut hits);
        if result.action == PolicyAction::Permit {
            response.accepted += 1;
            if !result.modifications.is_empty() {
                response.modified += 1;
                if response.diffs.len() < scope.show_changes {
                    response.diffs.push(proto::TestPolicyDiff {
                        prefix: route.prefix.addr_string(),
                        prefix_length: u32::from(route.prefix.prefix_len()),
                        peer: route.peer.to_string(),
                        changes: render_modification_changes(route, &result.modifications),
                    });
                }
            }
        } else {
            response.rejected += 1;
        }
    }
    response.term_hits = chain
        .policies
        .iter()
        .zip(&hits)
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
        .collect();
    response
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
    use super::*;
    use crate::peer_types::{CatalogMutationError, PolicyAsPathPrependConfig};
    use crate::proto::policy_service_server::PolicyService as PolicyServiceRpc;
    use tokio::sync::mpsc::error::TryRecvError;

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
            "192.0.2.0",
            24,
            proto::AddressFamily::Ipv4Unicast as i32,
            resolved,
        );
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
        assert!(fallthrough.policy_name.is_empty());
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

    #[tokio::test]
    async fn set_policy_emits_config_event_after_runtime_success() {
        let (peer_tx, mut peer_rx) = mpsc::channel(8);
        let (config_tx, mut config_rx) = mpsc::channel(4);
        let svc = PolicyService::new(AccessMode::ReadWrite, peer_tx, Some(config_tx), None);

        tokio::spawn(async move {
            while let Some(cmd) = peer_rx.recv().await {
                match cmd {
                    PeerManagerCommand::GetPolicy { reply, .. } => {
                        let _ = reply.send(None);
                    }
                    PeerManagerCommand::SetPolicy {
                        name,
                        definition,
                        reply,
                    } => {
                        assert_eq!(name, "tag-internal");
                        assert_eq!(definition.default_action, "permit");
                        assert_eq!(definition.statements.len(), 1);
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
            Some(ConfigEvent::SetPolicy {
                name,
                definition,
                ack,
            }) => {
                assert_eq!(name, "tag-internal");
                assert_eq!(definition.default_action, "permit");
                assert_eq!(definition.statements.len(), 1);
                ack.expect("persisted mutation must carry an ack")
                    .send(Ok(()))
                    .expect("service should await the persistence ack");
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
    async fn set_policy_rolls_back_runtime_when_persist_fails() {
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
                    .send(Err("disk full".to_string()))
                    .expect("service should await the persistence ack");
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

        let sets = set_definitions.lock().await;
        assert_eq!(sets.len(), 2, "mutation then rollback");
        assert_eq!(sets[0].default_action, "permit");
        assert_eq!(
            sets[1].default_action, "deny",
            "rollback must restore the captured prior definition"
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
                    PeerManagerCommand::GetPolicy { reply, .. } => {
                        let _ = reply.send(Some(NamedPolicyDefinition {
                            default_action: "permit".to_string(),
                            statements: Vec::new(),
                        }));
                    }
                    PeerManagerCommand::DeletePolicy { name, reply } => {
                        assert_eq!(name, "tag-internal");
                        let _ = reply.send(Err(CatalogMutationError::StillReferenced {
                            kind: "policy",
                            name: "tag-internal".into(),
                            references: vec!["global import_chain".into()],
                        }));
                    }
                    _ => panic!("unexpected peer-manager command"),
                }
            }
        });

        // The runtime mutation fails before persistence, so the RPC
        // returns directly without an ack handshake.
        let error = PolicyServiceRpc::delete_policy(
            &svc,
            Request::new(proto::DeletePolicyRequest {
                name: "tag-internal".into(),
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(error.code(), tonic::Code::FailedPrecondition);
        assert!(matches!(config_rx.try_recv(), Err(TryRecvError::Empty)));
    }

    #[tokio::test]
    async fn delete_policy_rolls_back_runtime_when_persist_fails() {
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
                    .send(Err("disk full".to_string()))
                    .expect("service should await the persistence ack");
            }
            Some(_) => panic!("unexpected config event"),
            None => panic!("missing config event"),
        }

        let error = call
            .await
            .expect("call task must not panic")
            .expect_err("delete_policy must fail when persistence fails");
        assert_eq!(error.code(), tonic::Code::FailedPrecondition);

        let sets = set_definitions.lock().await;
        assert_eq!(
            sets.as_slice(),
            &[prior],
            "rollback must re-create the deleted policy"
        );
    }

    #[tokio::test]
    async fn set_global_import_chain_rolls_back_to_prior_chain_when_persist_fails() {
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
                    .send(Err("disk full".to_string()))
                    .expect("service should await the persistence ack");
            }
            Some(_) => panic!("unexpected config event"),
            None => panic!("missing config event"),
        }

        let error = call
            .await
            .expect("call task must not panic")
            .expect_err("set_global_import_chain must fail when persistence fails");
        assert_eq!(error.code(), tonic::Code::FailedPrecondition);

        let sets = set_chains.lock().await;
        assert_eq!(
            sets.as_slice(),
            &[
                vec!["tag-internal".to_string()],
                vec!["prior-import".to_string()]
            ],
            "rollback must re-set the prior chain"
        );
    }

    /// An empty prior chain and a cleared chain are the same config
    /// state, so rolling back from an empty prior issues the clear
    /// command rather than an empty set.
    #[tokio::test]
    async fn set_global_import_chain_rolls_back_via_clear_when_prior_empty() {
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
                    .send(Err("disk full".to_string()))
                    .expect("service should await the persistence ack");
            }
            Some(_) => panic!("unexpected config event"),
            None => panic!("missing config event"),
        }

        let error = call
            .await
            .expect("call task must not panic")
            .expect_err("set_global_import_chain must fail when persistence fails");
        assert_eq!(error.code(), tonic::Code::FailedPrecondition);
        assert_eq!(*cleared.lock().await, 1, "rollback must clear the chain");
    }

    #[tokio::test]
    async fn set_neighbor_import_chain_rolls_back_runtime_when_persist_fails() {
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
                policy_names,
                ack,
            }) => {
                assert_eq!(address.to_string(), "10.0.0.2");
                assert_eq!(policy_names, vec!["tag-internal".to_string()]);
                ack.expect("persisted mutation must carry an ack")
                    .send(Err("disk full".to_string()))
                    .expect("service should await the persistence ack");
            }
            Some(_) => panic!("unexpected config event"),
            None => panic!("missing config event"),
        }

        let error = call
            .await
            .expect("call task must not panic")
            .expect_err("set_neighbor_import_chain must fail when persistence fails");
        assert_eq!(error.code(), tonic::Code::FailedPrecondition);

        let sets = set_chains.lock().await;
        assert_eq!(
            sets.as_slice(),
            &[
                vec!["tag-internal".to_string()],
                vec!["prior-import".to_string()]
            ],
            "rollback must re-set the prior per-neighbor chain"
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
        rustbgpd_rib::Route {
            prefix: Prefix::V4(Ipv4Prefix::new(addr, len)),
            next_hop: "10.0.0.9".parse().unwrap(),
            link_local_next_hop: None,
            next_hop_scope: None,
            peer: "10.0.0.9".parse().unwrap(),
            attributes: std::sync::Arc::new(Vec::new()),
            received_at: std::time::Instant::now(),
            origin_type: rustbgpd_rib::RouteOrigin::Ebgp,
            peer_router_id: std::net::Ipv4Addr::UNSPECIFIED,
            is_stale: false,
            is_llgr_stale: false,
            path_id: 0,
            validation_state: rustbgpd_wire::RpkiValidation::NotFound,
            aspa_state: rustbgpd_wire::AspaValidation::Unknown,
            aspa_context: rustbgpd_wire::AspaValidationContext::default(),
        }
    }

    /// Fake daemon backends for `TestPolicy`: a RIB task answering
    /// received/best route queries with the given snapshot, and a
    /// peer manager answering `ListPeers` with an empty peer set.
    fn test_policy_service(routes: Vec<rustbgpd_rib::Route>) -> PolicyService {
        let (peer_tx, mut peer_rx) = mpsc::channel(8);
        let (rib_tx, mut rib_rx) = mpsc::channel::<rustbgpd_rib::RibUpdate>(8);
        tokio::spawn(async move {
            while let Some(cmd) = peer_rx.recv().await {
                match cmd {
                    PeerManagerCommand::ListPeers { reply } => {
                        let _ = reply.send(Vec::new());
                    }
                    _ => panic!("unexpected peer-manager command"),
                }
            }
        });
        tokio::spawn(async move {
            while let Some(update) = rib_rx.recv().await {
                match update {
                    rustbgpd_rib::RibUpdate::QueryReceivedRoutes { peer, reply } => {
                        let filtered = routes
                            .iter()
                            .filter(|route| peer.is_none_or(|p| route.peer == p))
                            .cloned()
                            .collect();
                        let _ = reply.send(filtered);
                    }
                    rustbgpd_rib::RibUpdate::QueryBestRoutes { reply } => {
                        let _ = reply.send(routes.clone());
                    }
                    _ => panic!("unexpected RIB query"),
                }
            }
        });
        PolicyService::new(AccessMode::ReadOnly, peer_tx, None, None).with_rib_query(rib_tx)
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
            }),
        )
        .await
        .expect("dry run succeeds")
        .into_inner();
        assert_eq!(resp.routes_evaluated, 2);
        assert_eq!(resp.accepted, 2);
        assert!(resp.diffs.is_empty());
    }

    // -- GetPolicyStats (ADR-0096 Decision 3.3) ---------------------

    /// Fake RIB backend answering the term-hits query with one
    /// installed chain snapshot.
    fn stats_service() -> PolicyService {
        let (peer_tx, _peer_rx) = mpsc::channel(8);
        let (rib_tx, mut rib_rx) = mpsc::channel::<rustbgpd_rib::RibUpdate>(8);
        tokio::spawn(async move {
            while let Some(update) = rib_rx.recv().await {
                match update {
                    rustbgpd_rib::RibUpdate::QueryExportPolicyTermHits { peer, reply } => {
                        assert_eq!(peer, Some("10.0.0.2".parse().unwrap()));
                        let _ = reply.send(vec![rustbgpd_rib::update::ExportPolicyTermHits {
                            peer,
                            evals: 7,
                            terms: vec![
                                rustbgpd_policy::TermHitRow {
                                    policy_index: 0,
                                    policy: Some("customer-in(200)".to_string()),
                                    term_index: 0,
                                    term: Some("customer-routes".to_string()),
                                    hits: 5,
                                },
                                rustbgpd_policy::TermHitRow {
                                    policy_index: 0,
                                    policy: Some("customer-in(200)".to_string()),
                                    term_index: 1,
                                    term: None,
                                    hits: 2,
                                },
                            ],
                        }]);
                    }
                    _ => panic!("unexpected RIB query"),
                }
            }
        });
        PolicyService::new(AccessMode::ReadOnly, peer_tx, None, None).with_rib_query(rib_tx)
    }

    #[tokio::test]
    async fn get_policy_stats_round_trips_term_rows() {
        let svc = stats_service();
        let resp = PolicyServiceRpc::get_policy_stats(
            &svc,
            Request::new(proto::GetPolicyStatsRequest {
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
        assert_eq!(chain.terms[0].policy, "customer-in(200)");
        assert_eq!(chain.terms[0].term, "customer-routes");
        assert_eq!(chain.terms[0].hits, 5);
        assert_eq!(chain.terms[1].term, "", "TOML statements are unnamed");
        assert_eq!(chain.terms[1].term_index, 1);
        assert_eq!(chain.terms[1].hits, 2);
    }

    #[tokio::test]
    async fn get_policy_stats_rejects_import_and_bad_direction() {
        let svc = stats_service();
        let err = PolicyServiceRpc::get_policy_stats(
            &svc,
            Request::new(proto::GetPolicyStatsRequest {
                peer_address: String::new(),
                direction: "import".to_string(),
            }),
        )
        .await
        .expect_err("import read surface is a follow-up");
        assert_eq!(err.code(), tonic::Code::Unimplemented);

        let err = PolicyServiceRpc::get_policy_stats(
            &svc,
            Request::new(proto::GetPolicyStatsRequest {
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
                peer_address: "not-an-ip".to_string(),
                direction: String::new(),
            }),
        )
        .await
        .expect_err("bad peer literal is invalid");
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }
}
