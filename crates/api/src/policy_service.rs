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
use crate::server::{AccessMode, read_only_rejection};

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

/// Render one resolved cache entry into the proto match. The echoed
/// scope (`peer_address`, `prefix`, `prefix_length`, `afi_safi`) is
/// stamped on every match; decision-specific fields are populated only
/// for `Hit` / `Stale` (an `Evicted` / `NotSeen` entry has no recorded
/// decision to render).
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

#[allow(clippy::result_large_err)] // tonic::Status is the standard gRPC error type
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
}

impl PolicyService {
    /// Create a new policy service with the given channels.
    pub fn new(
        access_mode: AccessMode,
        peer_mgr_tx: mpsc::Sender<PeerManagerCommand>,
        config_tx: Option<mpsc::Sender<ConfigEvent>>,
    ) -> Self {
        Self {
            access_mode,
            peer_mgr_tx,
            config_tx,
        }
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
        let persisted = persist_permit.as_ref().map(|_| definition.clone());

        let (reply_tx, reply_rx) = oneshot::channel();
        self.peer_mgr_tx
            .send(PeerManagerCommand::SetPolicy {
                name: req.name.clone(),
                definition,
                reply: reply_tx,
            })
            .await
            .map_err(|_| Status::internal("peer manager unavailable"))?;
        reply_rx
            .await
            .map_err(|_| Status::internal("peer manager dropped reply"))?
            .map_err(Status::invalid_argument)?;

        if let (Some(permit), Some(definition)) = (persist_permit, persisted) {
            permit.send(ConfigEvent::SetPolicy {
                name: req.name,
                definition,
            });
        }

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

        let (reply_tx, reply_rx) = oneshot::channel();
        self.peer_mgr_tx
            .send(PeerManagerCommand::DeletePolicy {
                name: req.name.clone(),
                reply: reply_tx,
            })
            .await
            .map_err(|_| Status::internal("peer manager unavailable"))?;
        match reply_rx
            .await
            .map_err(|_| Status::internal("peer manager dropped reply"))?
        {
            Ok(()) => {}
            Err(error) if error.contains("still referenced") => {
                return Err(Status::failed_precondition(error));
            }
            Err(error) if error.contains("not found") => return Err(Status::not_found(error)),
            Err(error) => return Err(Status::invalid_argument(error)),
        }

        if let Some(permit) = persist_permit {
            permit.send(ConfigEvent::DeletePolicy { name: req.name });
        }

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
        let persisted = persist_permit.as_ref().map(|_| definition.clone());

        let (reply_tx, reply_rx) = oneshot::channel();
        self.peer_mgr_tx
            .send(PeerManagerCommand::SetNeighborSet {
                name: req.name.clone(),
                definition,
                reply: reply_tx,
            })
            .await
            .map_err(|_| Status::internal("peer manager unavailable"))?;
        reply_rx
            .await
            .map_err(|_| Status::internal("peer manager dropped reply"))?
            .map_err(Status::invalid_argument)?;

        if let (Some(permit), Some(definition)) = (persist_permit, persisted) {
            permit.send(ConfigEvent::SetNeighborSet {
                name: req.name,
                definition,
            });
        }

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
        let (reply_tx, reply_rx) = oneshot::channel();
        self.peer_mgr_tx
            .send(PeerManagerCommand::DeleteNeighborSet {
                name: req.name.clone(),
                reply: reply_tx,
            })
            .await
            .map_err(|_| Status::internal("peer manager unavailable"))?;
        match reply_rx
            .await
            .map_err(|_| Status::internal("peer manager dropped reply"))?
        {
            Ok(()) => {}
            Err(error) if error.contains("still referenced") => {
                return Err(Status::failed_precondition(error));
            }
            Err(error) if error.contains("not found") => {
                return Err(Status::not_found(error));
            }
            Err(error) => return Err(Status::invalid_argument(error)),
        }

        if let Some(permit) = persist_permit {
            permit.send(ConfigEvent::DeleteNeighborSet { name: req.name });
        }

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
        let persisted = persist_permit.as_ref().map(|_| req.policy_names.clone());

        let (reply_tx, reply_rx) = oneshot::channel();
        self.peer_mgr_tx
            .send(PeerManagerCommand::SetGlobalImportChain {
                policy_names: req.policy_names,
                reply: reply_tx,
            })
            .await
            .map_err(|_| Status::internal("peer manager unavailable"))?;
        reply_rx
            .await
            .map_err(|_| Status::internal("peer manager dropped reply"))?
            .map_err(Status::invalid_argument)?;

        if let (Some(permit), Some(policy_names)) = (persist_permit, persisted) {
            permit.send(ConfigEvent::SetGlobalImportChain { policy_names });
        }

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
        let persisted = persist_permit.as_ref().map(|_| req.policy_names.clone());

        let (reply_tx, reply_rx) = oneshot::channel();
        self.peer_mgr_tx
            .send(PeerManagerCommand::SetGlobalExportChain {
                policy_names: req.policy_names,
                reply: reply_tx,
            })
            .await
            .map_err(|_| Status::internal("peer manager unavailable"))?;
        reply_rx
            .await
            .map_err(|_| Status::internal("peer manager dropped reply"))?
            .map_err(Status::invalid_argument)?;

        if let (Some(permit), Some(policy_names)) = (persist_permit, persisted) {
            permit.send(ConfigEvent::SetGlobalExportChain { policy_names });
        }

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
        let (reply_tx, reply_rx) = oneshot::channel();
        self.peer_mgr_tx
            .send(PeerManagerCommand::ClearGlobalImportChain { reply: reply_tx })
            .await
            .map_err(|_| Status::internal("peer manager unavailable"))?;
        reply_rx
            .await
            .map_err(|_| Status::internal("peer manager dropped reply"))?
            .map_err(Status::invalid_argument)?;

        if let Some(permit) = persist_permit {
            permit.send(ConfigEvent::ClearGlobalImportChain);
        }

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
        let (reply_tx, reply_rx) = oneshot::channel();
        self.peer_mgr_tx
            .send(PeerManagerCommand::ClearGlobalExportChain { reply: reply_tx })
            .await
            .map_err(|_| Status::internal("peer manager unavailable"))?;
        reply_rx
            .await
            .map_err(|_| Status::internal("peer manager dropped reply"))?
            .map_err(Status::invalid_argument)?;

        if let Some(permit) = persist_permit {
            permit.send(ConfigEvent::ClearGlobalExportChain);
        }

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
        let persisted = persist_permit.as_ref().map(|_| req.policy_names.clone());

        let (reply_tx, reply_rx) = oneshot::channel();
        self.peer_mgr_tx
            .send(PeerManagerCommand::SetNeighborImportChain {
                address,
                policy_names: req.policy_names,
                reply: reply_tx,
            })
            .await
            .map_err(|_| Status::internal("peer manager unavailable"))?;
        match reply_rx
            .await
            .map_err(|_| Status::internal("peer manager dropped reply"))?
        {
            Ok(()) => {}
            Err(error) if error.contains("not found") => return Err(Status::not_found(error)),
            Err(error) => return Err(Status::invalid_argument(error)),
        }

        if let (Some(permit), Some(policy_names)) = (persist_permit, persisted) {
            permit.send(ConfigEvent::SetNeighborImportChain {
                address,
                policy_names,
            });
        }

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
        let persisted = persist_permit.as_ref().map(|_| req.policy_names.clone());

        let (reply_tx, reply_rx) = oneshot::channel();
        self.peer_mgr_tx
            .send(PeerManagerCommand::SetNeighborExportChain {
                address,
                policy_names: req.policy_names,
                reply: reply_tx,
            })
            .await
            .map_err(|_| Status::internal("peer manager unavailable"))?;
        match reply_rx
            .await
            .map_err(|_| Status::internal("peer manager dropped reply"))?
        {
            Ok(()) => {}
            Err(error) if error.contains("not found") => return Err(Status::not_found(error)),
            Err(error) => return Err(Status::invalid_argument(error)),
        }

        if let (Some(permit), Some(policy_names)) = (persist_permit, persisted) {
            permit.send(ConfigEvent::SetNeighborExportChain {
                address,
                policy_names,
            });
        }

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

        let (reply_tx, reply_rx) = oneshot::channel();
        self.peer_mgr_tx
            .send(PeerManagerCommand::ClearNeighborImportChain {
                address,
                reply: reply_tx,
            })
            .await
            .map_err(|_| Status::internal("peer manager unavailable"))?;
        match reply_rx
            .await
            .map_err(|_| Status::internal("peer manager dropped reply"))?
        {
            Ok(()) => {}
            Err(error) if error.contains("not found") => return Err(Status::not_found(error)),
            Err(error) => return Err(Status::invalid_argument(error)),
        }

        if let Some(permit) = persist_permit {
            permit.send(ConfigEvent::ClearNeighborImportChain { address });
        }

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

        let (reply_tx, reply_rx) = oneshot::channel();
        self.peer_mgr_tx
            .send(PeerManagerCommand::ClearNeighborExportChain {
                address,
                reply: reply_tx,
            })
            .await
            .map_err(|_| Status::internal("peer manager unavailable"))?;
        match reply_rx
            .await
            .map_err(|_| Status::internal("peer manager dropped reply"))?
        {
            Ok(()) => {}
            Err(error) if error.contains("not found") => return Err(Status::not_found(error)),
            Err(error) => return Err(Status::invalid_argument(error)),
        }

        if let Some(permit) = persist_permit {
            permit.send(ConfigEvent::ClearNeighborExportChain { address });
        }

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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::peer_types::PolicyAsPathPrependConfig;
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
    fn proto_statement_rejects_large_u8_fields() {
        let proto = proto::PolicyStatement {
            ge: Some(300),
            ..Default::default()
        };
        assert!(proto_statement_to_input(proto).is_err());
    }

    #[tokio::test]
    async fn set_policy_emits_config_event_after_runtime_success() {
        let (peer_tx, mut peer_rx) = mpsc::channel(4);
        let (config_tx, mut config_rx) = mpsc::channel(4);
        let svc = PolicyService::new(AccessMode::ReadWrite, peer_tx, Some(config_tx));

        tokio::spawn(async move {
            if let Some(PeerManagerCommand::SetPolicy {
                name,
                definition,
                reply,
            }) = peer_rx.recv().await
            {
                assert_eq!(name, "tag-internal");
                assert_eq!(definition.default_action, "permit");
                assert_eq!(definition.statements.len(), 1);
                let _ = reply.send(Ok(()));
            }
        });

        let response = PolicyServiceRpc::set_policy(
            &svc,
            Request::new(proto::SetPolicyRequest {
                name: "tag-internal".into(),
                definition: Some(sample_proto_definition()),
            }),
        )
        .await;
        assert!(response.is_ok());

        match config_rx.recv().await {
            Some(ConfigEvent::SetPolicy { name, definition }) => {
                assert_eq!(name, "tag-internal");
                assert_eq!(definition.default_action, "permit");
                assert_eq!(definition.statements.len(), 1);
            }
            Some(_) => panic!("unexpected config event"),
            None => panic!("missing config event"),
        }
    }

    #[tokio::test]
    async fn set_policy_rejected_on_read_only_listener() {
        let (peer_tx, mut peer_rx) = mpsc::channel(4);
        let (config_tx, mut config_rx) = mpsc::channel(4);
        let svc = PolicyService::new(AccessMode::ReadOnly, peer_tx, Some(config_tx));

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
        let svc = PolicyService::new(AccessMode::ReadOnly, peer_tx, Some(config_tx));

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
        let svc = PolicyService::new(AccessMode::ReadOnly, peer_tx, Some(config_tx));

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
        let svc = PolicyService::new(AccessMode::ReadOnly, peer_tx, Some(config_tx));

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
        let svc = PolicyService::new(AccessMode::ReadWrite, peer_tx, Some(config_tx));

        tokio::spawn(async move {
            if let Some(PeerManagerCommand::DeletePolicy { name, reply }) = peer_rx.recv().await {
                assert_eq!(name, "tag-internal");
                let _ = reply.send(Err(
                    "policy tag-internal is still referenced by global import_chain".into(),
                ));
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
        assert!(matches!(config_rx.try_recv(), Err(TryRecvError::Empty)));
    }
}
