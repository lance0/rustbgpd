//! gRPC policy service — named policy definitions and chain assignment.

use std::net::IpAddr;
use std::time::Duration;

use tokio::sync::{mpsc, oneshot};
use tonic::{Request, Response, Status};

use crate::peer_types::{
    ConfigEvent, NamedPolicyDefinition, PeerManagerCommand, PolicyAsPathPrependConfig,
    PolicyStatementDefinition,
};
use crate::proto;

const CONFIG_PERSIST_RESERVE_TIMEOUT: Duration = Duration::from_secs(2);

#[allow(clippy::result_large_err)] // tonic::Status is the standard gRPC error type
fn proto_statement_to_input(
    statement: proto::PolicyStatement,
) -> Result<PolicyStatementDefinition, Status> {
    let ge = statement
        .ge
        .map(u8::try_from)
        .transpose()
        .map_err(|_| Status::invalid_argument("ge exceeds u8 range"))?;
    let le = statement
        .le
        .map(u8::try_from)
        .transpose()
        .map_err(|_| Status::invalid_argument("le exceeds u8 range"))?;
    let set_as_path_prepend = if let Some(prepend) = statement.set_as_path_prepend {
        Some(PolicyAsPathPrependConfig {
            asn: prepend.asn,
            count: u8::try_from(prepend.count).map_err(|_| {
                Status::invalid_argument("set_as_path_prepend.count exceeds u8 range")
            })?,
        })
    } else {
        None
    };

    Ok(PolicyStatementDefinition {
        action: statement.action,
        prefix: statement.prefix,
        ge,
        le,
        match_community: statement.match_community,
        match_as_path: statement.match_as_path,
        match_neighbor_set: statement.match_neighbor_set,
        match_route_type: statement.match_route_type,
        match_as_path_length_ge: statement.match_as_path_length_ge,
        match_as_path_length_le: statement.match_as_path_length_le,
        match_local_pref_ge: statement.match_local_pref_ge,
        match_local_pref_le: statement.match_local_pref_le,
        match_med_ge: statement.match_med_ge,
        match_med_le: statement.match_med_le,
        match_next_hop: statement.match_next_hop,
        match_rpki_validation: statement.match_rpki_validation,
        set_local_pref: statement.set_local_pref,
        set_med: statement.set_med,
        set_next_hop: statement.set_next_hop,
        set_community_add: statement.set_community_add,
        set_community_remove: statement.set_community_remove,
        set_as_path_prepend,
    })
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
        match_as_path_length_ge: statement.match_as_path_length_ge,
        match_as_path_length_le: statement.match_as_path_length_le,
        match_local_pref_ge: statement.match_local_pref_ge,
        match_local_pref_le: statement.match_local_pref_le,
        match_med_ge: statement.match_med_ge,
        match_med_le: statement.match_med_le,
        match_next_hop: statement.match_next_hop.clone(),
        match_rpki_validation: statement.match_rpki_validation.clone(),
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
    peer_mgr_tx: mpsc::Sender<PeerManagerCommand>,
    config_tx: Option<mpsc::Sender<ConfigEvent>>,
}

impl PolicyService {
    /// Create a new policy service with the given channels.
    pub fn new(
        peer_mgr_tx: mpsc::Sender<PeerManagerCommand>,
        config_tx: Option<mpsc::Sender<ConfigEvent>>,
    ) -> Self {
        Self {
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
}

#[cfg(test)]
mod tests {
    use super::*;
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
            match_as_path_length_ge: Some(1),
            match_as_path_length_le: Some(5),
            match_local_pref_ge: None,
            match_local_pref_le: None,
            match_med_ge: None,
            match_med_le: None,
            match_next_hop: Some("2001:db8::1".into()),
            match_rpki_validation: Some("valid".into()),
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
        let svc = PolicyService::new(peer_tx, Some(config_tx));

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
    async fn delete_policy_in_use_maps_to_failed_precondition() {
        let (peer_tx, mut peer_rx) = mpsc::channel(4);
        let (config_tx, mut config_rx) = mpsc::channel(4);
        let svc = PolicyService::new(peer_tx, Some(config_tx));

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
