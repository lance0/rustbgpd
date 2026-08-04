//! gRPC policy service — named policy definitions and chain assignment.

use std::net::IpAddr;
use std::time::{Duration, UNIX_EPOCH};

use rustbgpd_transport::{
    CachedOutcome, ImportExplainReply, LookupResult, RejectedRoutesReply, ResolvedMatch,
    SessionQueryOutcome,
};
use rustbgpd_wire::{Afi, Ipv4Prefix, Ipv6Prefix, Prefix, Safi};
use tokio::sync::{mpsc, oneshot};
use tonic::{Request, Response, Status};

use crate::actor_read::{peer_manager_read, rib_manager_read};
use crate::peer_types::{
    ConfigEvent, NamedPolicyDefinition, PeerManagerCommand, PolicyStatementDefinition,
};
use crate::policy_helpers::{proto_statement_to_input, validate_policy_action};
use crate::proto;
use crate::server::{
    AccessMode, ConfigMutationGateFn, apply_catalog_mutation, catalog_mutation_error_to_status,
    peer_manager_request, persist_then_apply, read_only_rejection, run_shielded_catalog_mutation,
};
use std::sync::Arc;

const CONFIG_PERSIST_RESERVE_TIMEOUT: Duration = Duration::from_secs(2);
const POLICY_STATS_AGGREGATE_TIMEOUT: Duration = Duration::from_millis(500);

/// Run one policy-stats backend send and reply within the RPC's shared
/// absolute deadline. A saturated bounded channel is part of the same budget
/// as the reply wait; no sequential stage receives a fresh timeout.
async fn policy_stats_request<T>(
    deadline: tokio::time::Instant,
    request: impl std::future::Future<Output = Result<T, Status>>,
) -> Result<T, Status> {
    if deadline <= tokio::time::Instant::now() {
        return Err(Status::deadline_exceeded(
            "policy stats aggregate deadline exceeded",
        ));
    }
    tokio::time::timeout_at(deadline, request)
        .await
        .map_err(|_| Status::deadline_exceeded("policy stats aggregate deadline exceeded"))?
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

/// Reject a chain mutation for a neighbor that is not configured, without
/// mutating anything.
///
/// The mutators used to discover this from the runtime apply. Staging now
/// runs first, so the check has to run before it — a request naming an
/// unknown neighbor is `NOT_FOUND`, not a persistence failure.
async fn require_configured_neighbor(
    peer_mgr_tx: &mpsc::Sender<PeerManagerCommand>,
    address: IpAddr,
) -> Result<(), Status> {
    peer_manager_request(peer_mgr_tx, |reply| {
        PeerManagerCommand::GetNeighborPolicyChains { address, reply }
    })
    .await?
    .ok_or_else(|| Status::not_found(format!("neighbor {address} not found")))
    .map(|_| ())
}

/// Reject a policy read for an address that does not resolve to one unique
/// managed peer. Unlike the mutation validator above, this includes accepted
/// dynamic peers because their session-local policy state is queryable even
/// though they do not have a `[[neighbors]]` row.
async fn require_managed_peer_address(
    peer_mgr_tx: &mpsc::Sender<PeerManagerCommand>,
    address: IpAddr,
    deadline: tokio::time::Instant,
) -> Result<(), Status> {
    policy_stats_request(
        deadline,
        peer_manager_read(peer_mgr_tx, |reply| PeerManagerCommand::HasPeerAddress {
            address,
            reply,
        }),
    )
    .await?
    .then_some(())
    .ok_or_else(|| Status::not_found(format!("neighbor {address} not found")))
}

#[tonic::async_trait]
impl proto::policy_service_server::PolicyService for PolicyService {
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
        let peer_mgr_tx = self.peer_mgr_tx.clone();
        let name = req.name;
        self.run_mutation("PolicyService.SetPolicy", move || async move {
            // A policy edit re-evaluates live sessions: it rewrites
            // Adj-RIB-Out and drives a Route Refresh. Stage the write first
            // so a persistence failure does not put that churn on the wire
            // and then a second round of it as "rollback".
            persist_then_apply(
                persist_permit,
                |ack| ConfigEvent::SetPolicy {
                    name: name.clone(),
                    definition: definition.clone(),
                    ack: Some(ack),
                },
                || set_policy_definition(&peer_mgr_tx, name.clone(), definition.clone()),
            )
            .await
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
            persist_then_apply(
                persist_permit,
                |ack| ConfigEvent::DeletePolicy {
                    name: name.clone(),
                    ack: Some(ack),
                },
                || delete_policy_definition(&peer_mgr_tx, name.clone()),
            )
            .await
        })
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
        let peer_mgr_tx = self.peer_mgr_tx.clone();
        let name = req.name;
        self.run_mutation("PolicyService.SetNeighborSet", move || async move {
            persist_then_apply(
                persist_permit,
                |ack| ConfigEvent::SetNeighborSet {
                    name: name.clone(),
                    definition: definition.clone(),
                    ack: Some(ack),
                },
                || {
                    apply_catalog_mutation(&peer_mgr_tx, |reply| {
                        PeerManagerCommand::SetNeighborSet {
                            name: name.clone(),
                            definition: definition.clone(),
                            reply,
                        }
                    })
                },
            )
            .await
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
            persist_then_apply(
                persist_permit,
                |ack| ConfigEvent::DeleteNeighborSet {
                    name: name.clone(),
                    ack: Some(ack),
                },
                || {
                    apply_catalog_mutation(&peer_mgr_tx, |reply| {
                        PeerManagerCommand::DeleteNeighborSet {
                            name: name.clone(),
                            reply,
                        }
                    })
                },
            )
            .await
        })
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
        let peer_mgr_tx = self.peer_mgr_tx.clone();
        let policy_names = req.policy_names;
        self.run_mutation("PolicyService.SetGlobalImportChain", move || async move {
            persist_then_apply(
                persist_permit,
                |ack| ConfigEvent::SetGlobalImportChain {
                    policy_names: policy_names.clone(),
                    ack: Some(ack),
                },
                || {
                    apply_catalog_mutation(&peer_mgr_tx, |reply| {
                        PeerManagerCommand::SetGlobalImportChain {
                            policy_names: policy_names.clone(),
                            reply,
                        }
                    })
                },
            )
            .await
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
            persist_then_apply(
                persist_permit,
                |ack| ConfigEvent::SetGlobalExportChain {
                    policy_names: policy_names.clone(),
                    ack: Some(ack),
                },
                || {
                    apply_catalog_mutation(&peer_mgr_tx, |reply| {
                        PeerManagerCommand::SetGlobalExportChain {
                            policy_names: policy_names.clone(),
                            reply,
                        }
                    })
                },
            )
            .await
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
            persist_then_apply(
                persist_permit,
                |ack| ConfigEvent::ClearGlobalImportChain { ack: Some(ack) },
                || {
                    apply_catalog_mutation(&peer_mgr_tx, |reply| {
                        PeerManagerCommand::ClearGlobalImportChain { reply }
                    })
                },
            )
            .await
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
            persist_then_apply(
                persist_permit,
                |ack| ConfigEvent::ClearGlobalExportChain { ack: Some(ack) },
                || {
                    apply_catalog_mutation(&peer_mgr_tx, |reply| {
                        PeerManagerCommand::ClearGlobalExportChain { reply }
                    })
                },
            )
            .await
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
        let chains = peer_manager_read(&self.peer_mgr_tx, |reply| {
            PeerManagerCommand::GetNeighborPolicyChains { address, reply }
        })
        .await?
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
            require_configured_neighbor(&peer_mgr_tx, address).await?;
            persist_then_apply(
                persist_permit,
                |ack| ConfigEvent::SetNeighborImportChain {
                    address,
                    policy_names: policy_names.clone(),
                    ack: Some(ack),
                },
                || {
                    apply_catalog_mutation(&peer_mgr_tx, |reply| {
                        PeerManagerCommand::SetNeighborImportChain {
                            address,
                            policy_names: policy_names.clone(),
                            reply,
                        }
                    })
                },
            )
            .await
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
            require_configured_neighbor(&peer_mgr_tx, address).await?;
            persist_then_apply(
                persist_permit,
                |ack| ConfigEvent::SetNeighborExportChain {
                    address,
                    policy_names: policy_names.clone(),
                    ack: Some(ack),
                },
                || {
                    apply_catalog_mutation(&peer_mgr_tx, |reply| {
                        PeerManagerCommand::SetNeighborExportChain {
                            address,
                            policy_names: policy_names.clone(),
                            reply,
                        }
                    })
                },
            )
            .await
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
                require_configured_neighbor(&peer_mgr_tx, address).await?;
                persist_then_apply(
                    persist_permit,
                    |ack| ConfigEvent::ClearNeighborImportChain {
                        address,
                        ack: Some(ack),
                    },
                    || {
                        apply_catalog_mutation(&peer_mgr_tx, |reply| {
                            PeerManagerCommand::ClearNeighborImportChain { address, reply }
                        })
                    },
                )
                .await
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
                require_configured_neighbor(&peer_mgr_tx, address).await?;
                persist_then_apply(
                    persist_permit,
                    |ack| ConfigEvent::ClearNeighborExportChain {
                        address,
                        ack: Some(ack),
                    },
                    || {
                        apply_catalog_mutation(&peer_mgr_tx, |reply| {
                            PeerManagerCommand::ClearNeighborExportChain { address, reply }
                        })
                    },
                )
                .await
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

        let reply = peer_manager_read(&self.peer_mgr_tx, |reply| {
            PeerManagerCommand::ExplainImportPolicy {
                address,
                afi,
                safi,
                prefix,
                path_id: req.path_id,
                reply,
            }
        })
        .await?;
        let reply: Option<ImportExplainReply> = match reply {
            SessionQueryOutcome::Reply(reply) => Some(reply),
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
                &req.peer_address,
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
            peer_address: req.peer_address,
            prefix: req.prefix,
            prefix_length: req.prefix_length,
            afi_safi: req.afi_safi,
            current_policy_generation: current_generation,
            matches,
        }))
    }

    async fn list_rejected_routes(
        &self,
        request: Request<proto::ListRejectedRoutesRequest>,
    ) -> Result<Response<proto::ListRejectedRoutesResponse>, Status> {
        let req = request.into_inner();
        let address: IpAddr = req
            .peer_address
            .parse()
            .map_err(|e| Status::invalid_argument(format!("invalid peer_address: {e}")))?;

        let reply = peer_manager_read(&self.peer_mgr_tx, |reply| {
            PeerManagerCommand::ListRejectedRoutes { address, reply }
        })
        .await?;
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
            peer_address: req.peer_address,
            retention_enabled: reply.enabled,
            capacity: u32::try_from(reply.capacity).unwrap_or(u32::MAX),
            routes,
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
        // Dry runs have no dataset file bindings — a candidate source
        // referencing one is rejected, not panicked on (LAN-305).
        let chain = file
            .compile_policy_bound(
                base,
                &args,
                &mut store,
                &rustbgpd_policy::datasets::DatasetBindings::new(),
            )
            .expect("existence checked above")
            .map_err(|missing| {
                Status::invalid_argument(format!(
                    "policy {base:?} probes datasets, which TestPolicy cannot bind: {missing}"
                ))
            })?;

        // Read-only route snapshot via the existing RIB query
        // machinery. Import evaluates Adj-RIB-In (optionally one
        // peer's); export evaluates Loc-RIB best routes.
        let rib_tx = self.rib_tx.as_ref().ok_or_else(|| {
            Status::failed_precondition("route snapshot runtime unavailable on this listener")
        })?;
        let routes = rib_manager_read(rib_tx, |reply| {
            if import {
                RibUpdate::QueryReceivedRoutes {
                    peer: peer_filter,
                    reply,
                }
            } else {
                RibUpdate::QueryBestRoutes { reply }
            }
        })
        .await?;

        // Peer context (ASN / peer-group) so guards on peer.* fields
        // see real values.
        let peer_context: std::collections::HashMap<IpAddr, (u32, Option<String>)> =
            peer_manager_read(&self.peer_mgr_tx, |reply| PeerManagerCommand::ListPeers {
                reply,
            })
            .await?
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

    #[expect(
        clippy::too_many_lines,
        reason = "three sequential backend queries (export, import, datasets) with shared shaping"
    )]
    async fn get_policy_stats(
        &self,
        request: Request<proto::GetPolicyStatsRequest>,
    ) -> Result<Response<proto::GetPolicyStatsResponse>, Status> {
        use rustbgpd_rib::RibUpdate;

        let deadline = tokio::time::Instant::now() + POLICY_STATS_AGGREGATE_TIMEOUT;
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
        let peer: Option<IpAddr> = if req.peer_address.is_empty() {
            None
        } else {
            Some(req.peer_address.parse().map_err(|_| {
                Status::invalid_argument(format!("invalid peer address {:?}", req.peer_address))
            })?)
        };
        if let Some(peer) = peer {
            require_managed_peer_address(&self.peer_mgr_tx, peer, deadline).await?;
        }
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
        if want_export {
            let rib_tx = self.rib_tx.as_ref().ok_or_else(|| {
                Status::failed_precondition("policy stats runtime unavailable on this listener")
            })?;
            let chains = policy_stats_request(
                deadline,
                rib_manager_read(rib_tx, |reply| RibUpdate::QueryExportPolicyTermHits {
                    peer,
                    reply,
                }),
            )
            .await?;
            out.extend(chains.into_iter().map(|chain| {
                proto::PolicyChainStats {
                    peer_address: chain
                        .peer
                        .map_or_else(|| "global".to_string(), |peer| peer.to_string()),
                    direction: "export".to_string(),
                    routes_evaluated: chain.evals,
                    eval_errors: chain.eval_errors,
                    last_error: chain.last_error.unwrap_or_default(),
                    terms: term_stats(chain.terms),
                    // Export chains do not track an install generation yet
                    // (LAN-311); 0 = untracked, per the proto contract.
                    policy_generation: 0,
                }
            }));
        }
        if want_import {
            let chains = policy_stats_request(
                deadline,
                peer_manager_read(&self.peer_mgr_tx, |reply| {
                    PeerManagerCommand::QueryImportPolicyTermHits {
                        peer,
                        deadline,
                        reply,
                    }
                }),
            )
            .await?;
            let chains = match chains {
                SessionQueryOutcome::Reply(chains) => chains,
                SessionQueryOutcome::TimedOut => {
                    return Err(Status::deadline_exceeded(
                        "one or more peer sessions did not answer the import policy stats query in time",
                    ));
                }
                SessionQueryOutcome::SessionGone => {
                    return Err(Status::unavailable(
                        "one or more peer sessions exited during the import policy stats query",
                    ));
                }
            };
            out.extend(
                chains
                    .into_iter()
                    .map(|(peer, snapshot)| proto::PolicyChainStats {
                        peer_address: peer.to_string(),
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
        let datasets = policy_stats_request(
            deadline,
            peer_manager_read(&self.peer_mgr_tx, |reply| {
                PeerManagerCommand::QueryPolicyDatasets { reply }
            }),
        )
        .await?
        .into_iter()
        .map(|row| proto::PolicyDatasetStatus {
            name: row.status.name,
            kind: row.status.kind.as_str().to_string(),
            generation: row.status.generation,
            records: u64::try_from(row.status.records).unwrap_or(u64::MAX),
            path: row.path,
            last_error: row.status.last_error.unwrap_or_default(),
        })
        .collect();

        Ok(Response::new(proto::GetPolicyStatsResponse {
            chains: out,
            datasets,
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
            as_path: route.as_path(),
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
        GetPolicyStats,
    }

    const POLICY_READS: [PolicyRead; 10] = [
        PolicyRead::ListPolicies,
        PolicyRead::GetPolicy,
        PolicyRead::ListNeighborSets,
        PolicyRead::GetNeighborSet,
        PolicyRead::GetGlobalPolicyChains,
        PolicyRead::GetNeighborPolicyChains,
        PolicyRead::ExplainImportPolicy,
        PolicyRead::ListRejectedRoutes,
        PolicyRead::TestPolicy,
        PolicyRead::GetPolicyStats,
    ];

    impl PolicyRead {
        const fn rib_first(self) -> bool {
            matches!(self, Self::TestPolicy | Self::GetPolicyStats)
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
        }
    }

    fn policy_stats_rpc_request(
        peer_address: &str,
        direction: &str,
    ) -> proto::GetPolicyStatsRequest {
        proto::GetPolicyStatsRequest {
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
            PolicyRead::GetPolicyStats => PolicyServiceRpc::get_policy_stats(
                service,
                Request::new(policy_stats_rpc_request("", "export")),
            )
            .await
            .map(|_| ()),
        }
    }

    /// Load-bearing: restoring any included RPC's first actor-send mapping to
    /// `INTERNAL` makes its row red. The two multi-stage RPCs start at the RIB.
    #[tokio::test]
    async fn policy_read_send_failures_are_unavailable() {
        for rpc in POLICY_READS {
            let (peer_tx, peer_rx) = mpsc::channel(1);
            let (rib_tx, rib_rx) = mpsc::channel(1);
            let service = PolicyService::new(AccessMode::ReadOnly, peer_tx, None, None)
                .with_rib_query(rib_tx);
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
            let service = PolicyService::new(AccessMode::ReadOnly, peer_tx, None, None)
                .with_rib_query(rib_tx);
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
        PolicyStatsPeerValidation,
        PolicyStatsImport,
        PolicyStatsDatasets,
    }

    const POLICY_READ_EXTRA_STAGES: [PolicyReadExtraStage; 4] = [
        PolicyReadExtraStage::TestPolicyPeerContext,
        PolicyReadExtraStage::PolicyStatsPeerValidation,
        PolicyReadExtraStage::PolicyStatsImport,
        PolicyReadExtraStage::PolicyStatsDatasets,
    ];

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
            PolicyReadExtraStage::PolicyStatsPeerValidation => PolicyServiceRpc::get_policy_stats(
                service,
                Request::new(policy_stats_rpc_request("192.0.2.1", "export")),
            )
            .await
            .map(|_| ()),
            PolicyReadExtraStage::PolicyStatsImport => PolicyServiceRpc::get_policy_stats(
                service,
                Request::new(policy_stats_rpc_request("", "import")),
            )
            .await
            .map(|_| ()),
            PolicyReadExtraStage::PolicyStatsDatasets => PolicyServiceRpc::get_policy_stats(
                service,
                Request::new(policy_stats_rpc_request("", "export")),
            )
            .await
            .map(|_| ()),
        }
    }

    async fn answer_policy_stage_rib(mut rib_rx: mpsc::Receiver<rustbgpd_rib::RibUpdate>) {
        let Some(update) = rib_rx.recv().await else {
            return;
        };
        match update {
            rustbgpd_rib::RibUpdate::QueryReceivedRoutes { reply, .. }
            | rustbgpd_rib::RibUpdate::QueryBestRoutes { reply } => {
                let _ = reply.send(Vec::new());
            }
            rustbgpd_rib::RibUpdate::QueryExportPolicyTermHits { reply, .. } => {
                let _ = reply.send(Vec::new());
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
        let (peer_tx, mut peer_rx) = mpsc::channel(8);
        let svc = PolicyService::new(AccessMode::ReadOnly, peer_tx, None, None);
        tokio::spawn(async move {
            while let Some(cmd) = peer_rx.recv().await {
                match cmd {
                    PeerManagerCommand::ExplainImportPolicy { reply: tx, .. } => {
                        let outcome = reply
                            .clone()
                            .map_or(SessionQueryOutcome::SessionGone, SessionQueryOutcome::Reply);
                        let _ = tx.send(outcome);
                    }
                    _ => panic!("unexpected peer-manager command"),
                }
            }
        });
        let resp = PolicyServiceRpc::explain_import_policy(&svc, Request::new(explain_request()))
            .await
            .expect("explain succeeds")
            .into_inner();
        assert_eq!(resp.matches.len(), 1, "one synthetic match expected");
        resp.matches[0].outcome
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
                        let _ = tx.send(outcome);
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
                        let _ = reply.send(SessionQueryOutcome::TimedOut);
                    }
                    PeerManagerCommand::ListRejectedRoutes { reply, .. } => {
                        let _ = reply.send(SessionQueryOutcome::TimedOut);
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
            entries: vec![(key, entry)],
        }))
        .await
        .expect("listing succeeds");
        assert!(resp.retention_enabled);
        assert_eq!(resp.capacity, 1024);
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
                matches: Vec::new(),
            }))
            .await,
            proto::ImportExplainOutcome::NotSeen as i32
        );
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
                policy_names,
                ack,
            }) => {
                assert_eq!(address.to_string(), "10.0.0.2");
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

    /// Fake RIB + peer-manager backends answering the term-hits
    /// queries with one installed chain snapshot each.
    fn stats_service() -> PolicyService {
        let (peer_tx, mut peer_rx) = mpsc::channel::<PeerManagerCommand>(8);
        tokio::spawn(async move {
            while let Some(command) = peer_rx.recv().await {
                match command {
                    PeerManagerCommand::HasPeerAddress { address, reply } => {
                        assert_eq!(address, "10.0.0.2".parse::<IpAddr>().unwrap());
                        let _ = reply.send(true);
                    }
                    PeerManagerCommand::QueryImportPolicyTermHits {
                        peer,
                        deadline,
                        reply,
                    } => {
                        assert_eq!(peer, Some("10.0.0.2".parse().unwrap()));
                        assert!(
                            deadline
                                <= tokio::time::Instant::now() + POLICY_STATS_AGGREGATE_TIMEOUT,
                            "import collection must inherit the RPC aggregate deadline"
                        );
                        let _ = reply.send(SessionQueryOutcome::Reply(vec![(
                            "10.0.0.2".parse().unwrap(),
                            rustbgpd_transport::ImportPolicyTermHits {
                                generation: 3,
                                evals: 11,
                                eval_errors: 0,
                                last_error: None,
                                terms: vec![rustbgpd_policy::TermHitRow {
                                    policy_index: 0,
                                    policy: Some("customer-in(200)".to_string()),
                                    term_index: 0,
                                    term: Some("customer-routes".to_string()),
                                    hits: 9,
                                }],
                            },
                        )]));
                    }
                    PeerManagerCommand::QueryPolicyDatasets { reply } => {
                        let _ = reply.send(vec![crate::peer_types::PolicyDatasetStatusRow {
                            status: rustbgpd_policy::datasets::DatasetStatus {
                                name: "customers".to_string(),
                                kind: rustbgpd_policy::datasets::DatasetKind::Asn,
                                generation: 7,
                                records: 42,
                                last_error: Some("line 3: bad".to_string()),
                            },
                            path: "/var/lib/rustbgpd/datasets/customers.list".to_string(),
                        }]);
                    }
                    _ => panic!("unexpected peer-manager command"),
                }
            }
        });
        let (rib_tx, mut rib_rx) = mpsc::channel::<rustbgpd_rib::RibUpdate>(8);
        tokio::spawn(async move {
            while let Some(update) = rib_rx.recv().await {
                match update {
                    rustbgpd_rib::RibUpdate::QueryExportPolicyTermHits { peer, reply } => {
                        assert_eq!(peer, Some("10.0.0.2".parse().unwrap()));
                        let _ = reply.send(vec![rustbgpd_rib::update::ExportPolicyTermHits {
                            peer,
                            evals: 7,
                            eval_errors: 2,
                            last_error: Some(
                                "overflow in policy customer-in(200) term customer-routes"
                                    .to_string(),
                            ),
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
        assert_eq!(
            chain.policy_generation, 0,
            "export chains do not track an install generation yet (LAN-311)"
        );
        // LAN-301: eval-error counters and the rendered last error
        // ride the chain rows.
        assert_eq!(chain.eval_errors, 2);
        assert_eq!(
            chain.last_error,
            "overflow in policy customer-in(200) term customer-routes"
        );
        // LAN-305: dataset status rides the same response.
        assert_eq!(resp.datasets.len(), 1);
        let dataset = &resp.datasets[0];
        assert_eq!(dataset.name, "customers");
        assert_eq!(dataset.kind, "asn-set");
        assert_eq!(dataset.generation, 7);
        assert_eq!(dataset.records, 42);
        assert_eq!(dataset.last_error, "line 3: bad");
        assert_eq!(dataset.path, "/var/lib/rustbgpd/datasets/customers.list");
    }

    /// The import direction reads the session-side counters through
    /// the peer manager and reports the install generation, so a
    /// replaced chain (counters back to zero, generation advanced) is
    /// never presented as continuous history.
    #[tokio::test]
    async fn get_policy_stats_reports_import_chains_with_generation() {
        let svc = stats_service();
        let resp = PolicyServiceRpc::get_policy_stats(
            &svc,
            Request::new(proto::GetPolicyStatsRequest {
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
        assert_eq!(chain.routes_evaluated, 11);
        assert_eq!(chain.policy_generation, 3);
        assert_eq!(chain.terms.len(), 1);
        assert_eq!(chain.terms[0].term, "customer-routes");
        assert_eq!(chain.terms[0].hits, 9);
        assert_eq!(chain.eval_errors, 0);
        assert_eq!(chain.last_error, "", "no error since install");
    }

    async fn import_stats_outcome(
        outcome: SessionQueryOutcome<Vec<(IpAddr, rustbgpd_transport::ImportPolicyTermHits)>>,
    ) -> Result<Response<proto::GetPolicyStatsResponse>, Status> {
        let (peer_tx, mut peer_rx) = mpsc::channel::<PeerManagerCommand>(4);
        tokio::spawn(async move {
            let mut outcome = Some(outcome);
            while let Some(command) = peer_rx.recv().await {
                match command {
                    PeerManagerCommand::HasPeerAddress { reply, .. } => {
                        let _ = reply.send(true);
                    }
                    PeerManagerCommand::QueryImportPolicyTermHits { reply, .. } => {
                        let _ = reply.send(outcome.take().expect("one stats query"));
                    }
                    _ => panic!("unexpected peer-manager command"),
                }
            }
        });
        let svc = PolicyService::new(AccessMode::ReadOnly, peer_tx, None, None);
        PolicyServiceRpc::get_policy_stats(
            &svc,
            Request::new(proto::GetPolicyStatsRequest {
                peer_address: "10.0.0.2".to_string(),
                direction: "import".to_string(),
            }),
        )
        .await
    }

    /// LAN-661 red proof: treating timeout or task exit as a successful empty
    /// snapshot (or swapping the two status mappings) changes at least one
    /// asserted status. This pins the RPC half of the typed manager outcome.
    #[tokio::test]
    async fn get_policy_stats_import_failures_are_not_empty_successes() {
        let timeout = import_stats_outcome(SessionQueryOutcome::TimedOut)
            .await
            .expect_err("a stalled selected session must fail the RPC");
        assert_eq!(timeout.code(), tonic::Code::DeadlineExceeded);

        let gone = import_stats_outcome(SessionQueryOutcome::SessionGone)
            .await
            .expect_err("a selected session that exits must fail the RPC");
        assert_eq!(gone.code(), tonic::Code::Unavailable);
    }

    /// `direction = "both"` returns the export block first, then the
    /// import block — one deterministic response, not two commands.
    #[tokio::test]
    async fn get_policy_stats_both_orders_export_then_import() {
        let svc = stats_service();
        let resp = PolicyServiceRpc::get_policy_stats(
            &svc,
            Request::new(proto::GetPolicyStatsRequest {
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

    /// LAN-661: explicit-peer validation, export, import, and dataset reads
    /// are sequential but spend one 500 ms RPC budget rather than receiving
    /// independent timeouts.
    #[tokio::test(start_paused = true)]
    async fn get_policy_stats_sequential_stages_share_one_budget() {
        const STAGE_DELAY: Duration = Duration::from_millis(150);

        let (peer_tx, mut peer_rx) = mpsc::channel::<PeerManagerCommand>(4);
        tokio::spawn(async move {
            while let Some(command) = peer_rx.recv().await {
                tokio::time::sleep(STAGE_DELAY).await;
                match command {
                    PeerManagerCommand::HasPeerAddress { reply, .. } => {
                        let _ = reply.send(true);
                    }
                    PeerManagerCommand::QueryImportPolicyTermHits { reply, .. } => {
                        let _ = reply.send(SessionQueryOutcome::Reply(Vec::new()));
                    }
                    PeerManagerCommand::QueryPolicyDatasets { reply } => {
                        let _ = reply.send(Vec::new());
                    }
                    _ => panic!("unexpected peer-manager command"),
                }
            }
        });
        let (rib_tx, mut rib_rx) = mpsc::channel::<rustbgpd_rib::RibUpdate>(1);
        tokio::spawn(async move {
            while let Some(update) = rib_rx.recv().await {
                tokio::time::sleep(STAGE_DELAY).await;
                let rustbgpd_rib::RibUpdate::QueryExportPolicyTermHits { reply, .. } = update
                else {
                    panic!("unexpected RIB query");
                };
                let _ = reply.send(Vec::new());
            }
        });
        let svc =
            PolicyService::new(AccessMode::ReadOnly, peer_tx, None, None).with_rib_query(rib_tx);
        let started = tokio::time::Instant::now();

        let error = PolicyServiceRpc::get_policy_stats(
            &svc,
            Request::new(proto::GetPolicyStatsRequest {
                peer_address: "10.0.0.2".to_string(),
                direction: "both".to_string(),
            }),
        )
        .await
        .expect_err("four 150 ms stages must not receive four fresh budgets");

        assert_eq!(error.code(), tonic::Code::DeadlineExceeded);
        assert_eq!(
            tokio::time::Instant::now() - started,
            POLICY_STATS_AGGREGATE_TIMEOUT
        );
    }

    /// LAN-661: Tokio may poll a ready failed send before an expired
    /// `timeout_at`; policy stats must preserve deadline precedence instead of
    /// leaking backend closure as INTERNAL.
    #[tokio::test(start_paused = true)]
    async fn policy_stats_expired_deadline_precedes_immediately_closed_backend() {
        let closed_backend =
            std::future::ready(Err::<(), _>(Status::unavailable("backend unavailable")));
        let error = policy_stats_request(tokio::time::Instant::now(), closed_backend)
            .await
            .expect_err("already-expired request must fail");

        assert_eq!(error.code(), tonic::Code::DeadlineExceeded);
    }

    async fn assert_policy_stats_deadline(
        svc: &PolicyService,
        direction: &str,
        expected_stage: &str,
    ) {
        let started = tokio::time::Instant::now();
        let error = PolicyServiceRpc::get_policy_stats(
            svc,
            Request::new(proto::GetPolicyStatsRequest {
                peer_address: String::new(),
                direction: direction.to_string(),
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(
            error.code(),
            tonic::Code::DeadlineExceeded,
            "{expected_stage} must be bounded"
        );
        assert_eq!(
            tokio::time::Instant::now() - started,
            POLICY_STATS_AGGREGATE_TIMEOUT,
            "{expected_stage} must consume at most the one aggregate budget"
        );
    }

    /// LAN-661: both admission to a saturated RIB command channel and an
    /// admitted query whose reply is retained are bounded by the RPC deadline.
    #[tokio::test(start_paused = true)]
    async fn get_policy_stats_saturated_rib_send_and_reply_paths_remain_bounded() {
        for hold_reply in [false, true] {
            let (peer_tx, _peer_rx) = mpsc::channel::<PeerManagerCommand>(1);
            let (rib_tx, mut rib_rx) = mpsc::channel::<rustbgpd_rib::RibUpdate>(1);
            if hold_reply {
                tokio::spawn(async move {
                    let held = rib_rx.recv().await.expect("RIB query");
                    std::future::pending::<()>().await;
                    drop(held);
                });
            } else {
                let (reply, _response) = oneshot::channel();
                rib_tx
                    .send(rustbgpd_rib::RibUpdate::QueryExportPolicyTermHits { peer: None, reply })
                    .await
                    .unwrap();
            }
            let svc = PolicyService::new(AccessMode::ReadOnly, peer_tx, None, None)
                .with_rib_query(rib_tx);
            assert_policy_stats_deadline(
                &svc,
                "export",
                if hold_reply { "RIB reply" } else { "RIB send" },
            )
            .await;
        }
    }

    /// LAN-661: import stats cannot hang on either peer-manager channel
    /// admission or a retained manager reply.
    #[tokio::test(start_paused = true)]
    async fn get_policy_stats_saturated_import_send_and_reply_paths_remain_bounded() {
        for hold_reply in [false, true] {
            let (peer_tx, mut peer_rx) = mpsc::channel::<PeerManagerCommand>(1);
            if hold_reply {
                tokio::spawn(async move {
                    let held = peer_rx.recv().await.expect("import query");
                    assert!(matches!(
                        &held,
                        PeerManagerCommand::QueryImportPolicyTermHits { .. }
                    ));
                    std::future::pending::<()>().await;
                    drop(held);
                });
            } else {
                let (reply, _response) = oneshot::channel();
                peer_tx
                    .send(PeerManagerCommand::QueryPolicyDatasets { reply })
                    .await
                    .unwrap();
            }
            let svc = PolicyService::new(AccessMode::ReadOnly, peer_tx, None, None);
            assert_policy_stats_deadline(
                &svc,
                "import",
                if hold_reply {
                    "import reply"
                } else {
                    "import send"
                },
            )
            .await;
        }
    }

    /// LAN-661: the final dataset stage uses the remaining aggregate budget
    /// for both bounded-channel admission and its reply.
    #[tokio::test(start_paused = true)]
    async fn get_policy_stats_saturated_dataset_send_and_reply_paths_remain_bounded() {
        for hold_reply in [false, true] {
            let (peer_tx, mut peer_rx) = mpsc::channel::<PeerManagerCommand>(1);
            if hold_reply {
                tokio::spawn(async move {
                    let held = peer_rx.recv().await.expect("dataset query");
                    assert!(matches!(
                        &held,
                        PeerManagerCommand::QueryPolicyDatasets { .. }
                    ));
                    std::future::pending::<()>().await;
                    drop(held);
                });
            } else {
                let (reply, _response) = oneshot::channel();
                peer_tx
                    .send(PeerManagerCommand::QueryPolicyDatasets { reply })
                    .await
                    .unwrap();
            }
            let (rib_tx, mut rib_rx) = mpsc::channel::<rustbgpd_rib::RibUpdate>(1);
            tokio::spawn(async move {
                let rustbgpd_rib::RibUpdate::QueryExportPolicyTermHits { reply, .. } =
                    rib_rx.recv().await.expect("export query")
                else {
                    panic!("unexpected RIB query");
                };
                let _ = reply.send(Vec::new());
            });
            let svc = PolicyService::new(AccessMode::ReadOnly, peer_tx, None, None)
                .with_rib_query(rib_tx);
            assert_policy_stats_deadline(
                &svc,
                "export",
                if hold_reply {
                    "dataset reply"
                } else {
                    "dataset send"
                },
            )
            .await;
        }
    }

    #[tokio::test]
    async fn get_policy_stats_rejects_bad_direction() {
        let svc = stats_service();
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

    /// LAN-661 red proof: deleting the managed-peer validation sends the
    /// request to the RIB, which returns a global fallback labeled as the
    /// nonexistent peer and makes this call succeed.
    #[tokio::test]
    async fn get_policy_stats_rejects_unknown_peer_before_rib_fallback() {
        let (peer_tx, mut peer_rx) = mpsc::channel::<PeerManagerCommand>(4);
        tokio::spawn(async move {
            while let Some(command) = peer_rx.recv().await {
                match command {
                    PeerManagerCommand::HasPeerAddress { reply, .. } => {
                        let _ = reply.send(false);
                    }
                    PeerManagerCommand::QueryPolicyDatasets { reply } => {
                        let _ = reply.send(Vec::new());
                    }
                    _ => panic!("unexpected peer-manager command"),
                }
            }
        });

        let rib_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let rib_calls_task = Arc::clone(&rib_calls);
        let (rib_tx, mut rib_rx) = mpsc::channel::<rustbgpd_rib::RibUpdate>(4);
        tokio::spawn(async move {
            while let Some(update) = rib_rx.recv().await {
                let rustbgpd_rib::RibUpdate::QueryExportPolicyTermHits { peer, reply } = update
                else {
                    panic!("unexpected RIB query");
                };
                rib_calls_task.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let _ = reply.send(vec![rustbgpd_rib::update::ExportPolicyTermHits {
                    peer,
                    evals: 1,
                    eval_errors: 0,
                    last_error: None,
                    terms: Vec::new(),
                }]);
            }
        });

        let svc =
            PolicyService::new(AccessMode::ReadOnly, peer_tx, None, None).with_rib_query(rib_tx);
        let err = PolicyServiceRpc::get_policy_stats(
            &svc,
            Request::new(proto::GetPolicyStatsRequest {
                peer_address: "192.0.2.99".to_string(),
                direction: "export".to_string(),
            }),
        )
        .await
        .expect_err("unknown peer must not inherit the global export chain");
        assert_eq!(err.code(), tonic::Code::NotFound);
        assert_eq!(
            rib_calls.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "validation must reject before querying the RIB"
        );
    }
}
