//! gRPC peer-group service — reusable neighbor defaults and membership.

use std::time::Duration;

use tokio::sync::{mpsc, oneshot};
use tonic::{Request, Response, Status};

use crate::neighbor_service::{
    family_to_string, parse_families_proto, parse_remove_private_as_proto,
};
use crate::peer_types::{
    AddPathDefinition, ConfigEvent, PeerGroupDefinition, PeerManagerCommand,
    PolicyAsPathPrependConfig, PolicyStatementDefinition,
};
use crate::proto;
use crate::server::{AccessMode, read_only_rejection};

const CONFIG_PERSIST_RESERVE_TIMEOUT: Duration = Duration::from_secs(2);

#[allow(clippy::result_large_err)]
fn validate_policy_action(action: &str) -> Result<(), Status> {
    match action {
        "permit" | "deny" => Ok(()),
        other => Err(Status::invalid_argument(format!(
            "invalid policy action {other:?}, expected \"permit\" or \"deny\""
        ))),
    }
}

#[allow(clippy::result_large_err)]
fn proto_statement_to_input(
    statement: proto::PolicyStatement,
) -> Result<PolicyStatementDefinition, Status> {
    validate_policy_action(&statement.action)?;
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
    let set_as_path_prepend = statement
        .set_as_path_prepend
        .map(|prepend| {
            u8::try_from(prepend.count)
                .map(|count| PolicyAsPathPrependConfig {
                    asn: prepend.asn,
                    count,
                })
                .map_err(|_| Status::invalid_argument("set_as_path_prepend.count exceeds u8 range"))
        })
        .transpose()?;

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
        match_aspa_validation: statement.match_aspa_validation,
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

#[allow(clippy::result_large_err)]
fn proto_definition_to_input(
    definition: proto::PeerGroupDefinition,
) -> Result<PeerGroupDefinition, Status> {
    let hold_time = definition
        .hold_time
        .map(u16::try_from)
        .transpose()
        .map_err(|_| Status::invalid_argument("hold_time exceeds u16 range"))?;
    let gr_restart_time = definition
        .gr_restart_time
        .map(u16::try_from)
        .transpose()
        .map_err(|_| Status::invalid_argument("gr_restart_time exceeds u16 range"))?;
    let import_policy = definition
        .import_policy
        .into_iter()
        .map(proto_statement_to_input)
        .collect::<Result<Vec<_>, _>>()?;
    let export_policy = definition
        .export_policy
        .into_iter()
        .map(proto_statement_to_input)
        .collect::<Result<Vec<_>, _>>()?;
    let families = parse_families_proto(&definition.families)?
        .into_iter()
        .map(|(afi, safi)| family_to_string(afi, safi))
        .collect();
    let remove_private_as = definition
        .remove_private_as
        .as_deref()
        .map(parse_remove_private_as_proto)
        .transpose()?
        .map_or_else(String::new, |mode| match mode {
            rustbgpd_transport::RemovePrivateAs::Disabled => String::new(),
            rustbgpd_transport::RemovePrivateAs::Remove => "remove".to_string(),
            rustbgpd_transport::RemovePrivateAs::All => "all".to_string(),
            rustbgpd_transport::RemovePrivateAs::Replace => "replace".to_string(),
        });

    Ok(PeerGroupDefinition {
        hold_time,
        max_prefixes: definition.max_prefixes,
        md5_password: definition.md5_password,
        ttl_security: definition.ttl_security,
        families,
        graceful_restart: definition.graceful_restart,
        gr_restart_time,
        gr_stale_routes_time: definition.gr_stale_routes_time,
        llgr_stale_time: definition.llgr_stale_time,
        local_ipv6_nexthop: definition.local_ipv6_nexthop,
        route_reflector_client: definition.route_reflector_client,
        route_server_client: definition.route_server_client,
        remove_private_as: if remove_private_as.is_empty() {
            None
        } else {
            Some(remove_private_as)
        },
        add_path: definition
            .add_path_receive
            .map(|receive| AddPathDefinition {
                receive,
                send: definition.add_path_send.unwrap_or(false),
                send_max: definition.add_path_send_max,
            })
            .or_else(|| {
                definition.add_path_send.map(|send| AddPathDefinition {
                    receive: false,
                    send,
                    send_max: definition.add_path_send_max,
                })
            }),
        import_policy,
        export_policy,
        import_policy_chain: definition.import_policy_chain,
        export_policy_chain: definition.export_policy_chain,
    })
}

fn input_definition_to_proto(definition: &PeerGroupDefinition) -> proto::PeerGroupDefinition {
    proto::PeerGroupDefinition {
        hold_time: definition.hold_time.map(u32::from),
        max_prefixes: definition.max_prefixes,
        md5_password: definition.md5_password.clone(),
        ttl_security: definition.ttl_security,
        families: definition.families.clone(),
        graceful_restart: definition.graceful_restart,
        gr_restart_time: definition.gr_restart_time.map(u32::from),
        gr_stale_routes_time: definition.gr_stale_routes_time,
        llgr_stale_time: definition.llgr_stale_time,
        local_ipv6_nexthop: definition.local_ipv6_nexthop.clone(),
        route_reflector_client: definition.route_reflector_client,
        route_server_client: definition.route_server_client,
        remove_private_as: definition.remove_private_as.clone(),
        add_path_receive: definition
            .add_path
            .as_ref()
            .map(|add_path| add_path.receive),
        add_path_send: definition.add_path.as_ref().map(|add_path| add_path.send),
        add_path_send_max: definition
            .add_path
            .as_ref()
            .and_then(|add_path| add_path.send_max),
        import_policy: definition
            .import_policy
            .iter()
            .map(input_statement_to_proto)
            .collect(),
        export_policy: definition
            .export_policy
            .iter()
            .map(input_statement_to_proto)
            .collect(),
        import_policy_chain: definition.import_policy_chain.clone(),
        export_policy_chain: definition.export_policy_chain.clone(),
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

/// gRPC service for peer-group CRUD and neighbor membership assignment.
pub struct PeerGroupService {
    access_mode: AccessMode,
    peer_mgr_tx: mpsc::Sender<PeerManagerCommand>,
    config_tx: Option<mpsc::Sender<ConfigEvent>>,
}

impl PeerGroupService {
    /// Create a new peer-group service with the given channels.
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
impl proto::peer_group_service_server::PeerGroupService for PeerGroupService {
    async fn list_peer_groups(
        &self,
        _request: Request<proto::ListPeerGroupsRequest>,
    ) -> Result<Response<proto::ListPeerGroupsResponse>, Status> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.peer_mgr_tx
            .send(PeerManagerCommand::ListPeerGroups { reply: reply_tx })
            .await
            .map_err(|_| Status::internal("peer manager unavailable"))?;
        let peer_groups = reply_rx
            .await
            .map_err(|_| Status::internal("peer manager dropped reply"))?;
        Ok(Response::new(proto::ListPeerGroupsResponse {
            peer_groups: peer_groups
                .into_iter()
                .map(|peer_group| proto::NamedPeerGroup {
                    name: peer_group.name,
                    definition: Some(input_definition_to_proto(&peer_group.definition)),
                })
                .collect(),
        }))
    }

    async fn get_peer_group(
        &self,
        request: Request<proto::GetPeerGroupRequest>,
    ) -> Result<Response<proto::GetPeerGroupResponse>, Status> {
        let req = request.into_inner();
        if req.name.trim().is_empty() {
            return Err(Status::invalid_argument("name is required"));
        }
        let (reply_tx, reply_rx) = oneshot::channel();
        self.peer_mgr_tx
            .send(PeerManagerCommand::GetPeerGroup {
                name: req.name.clone(),
                reply: reply_tx,
            })
            .await
            .map_err(|_| Status::internal("peer manager unavailable"))?;
        let definition = reply_rx
            .await
            .map_err(|_| Status::internal("peer manager dropped reply"))?
            .ok_or_else(|| Status::not_found("peer group not found"))?;
        Ok(Response::new(proto::GetPeerGroupResponse {
            name: req.name,
            definition: Some(input_definition_to_proto(&definition)),
        }))
    }

    async fn set_peer_group(
        &self,
        request: Request<proto::SetPeerGroupRequest>,
    ) -> Result<Response<proto::SetPeerGroupResponse>, Status> {
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
            .send(PeerManagerCommand::SetPeerGroup {
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
            permit.send(ConfigEvent::SetPeerGroup {
                name: req.name,
                definition,
            });
        }

        Ok(Response::new(proto::SetPeerGroupResponse {}))
    }

    async fn delete_peer_group(
        &self,
        request: Request<proto::DeletePeerGroupRequest>,
    ) -> Result<Response<proto::DeletePeerGroupResponse>, Status> {
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
            .send(PeerManagerCommand::DeletePeerGroup {
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
            permit.send(ConfigEvent::DeletePeerGroup { name: req.name });
        }

        Ok(Response::new(proto::DeletePeerGroupResponse {}))
    }

    async fn set_neighbor_peer_group(
        &self,
        request: Request<proto::SetNeighborPeerGroupRequest>,
    ) -> Result<Response<proto::SetNeighborPeerGroupResponse>, Status> {
        if let Some(status) = read_only_rejection(self.access_mode) {
            return Err(status);
        }
        let req = request.into_inner();
        let address = req
            .address
            .parse()
            .map_err(|e| Status::invalid_argument(format!("invalid address: {e}")))?;
        if req.peer_group.trim().is_empty() {
            return Err(Status::invalid_argument("peer_group is required"));
        }

        let persist_permit = reserve_config_event_slot(self.config_tx.clone()).await?;
        let (reply_tx, reply_rx) = oneshot::channel();
        self.peer_mgr_tx
            .send(PeerManagerCommand::SetNeighborPeerGroup {
                address,
                peer_group: req.peer_group.clone(),
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
            permit.send(ConfigEvent::SetNeighborPeerGroup {
                address,
                peer_group: req.peer_group,
            });
        }

        Ok(Response::new(proto::SetNeighborPeerGroupResponse {}))
    }

    async fn clear_neighbor_peer_group(
        &self,
        request: Request<proto::ClearNeighborPeerGroupRequest>,
    ) -> Result<Response<proto::ClearNeighborPeerGroupResponse>, Status> {
        if let Some(status) = read_only_rejection(self.access_mode) {
            return Err(status);
        }
        let req = request.into_inner();
        let address = req
            .address
            .parse()
            .map_err(|e| Status::invalid_argument(format!("invalid address: {e}")))?;

        let persist_permit = reserve_config_event_slot(self.config_tx.clone()).await?;
        let (reply_tx, reply_rx) = oneshot::channel();
        self.peer_mgr_tx
            .send(PeerManagerCommand::ClearNeighborPeerGroup {
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
            permit.send(ConfigEvent::ClearNeighborPeerGroup { address });
        }

        Ok(Response::new(proto::ClearNeighborPeerGroupResponse {}))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::peer_group_service_server::PeerGroupService as PeerGroupServiceRpc;
    use tokio::sync::mpsc::error::TryRecvError;

    fn sample_definition() -> proto::PeerGroupDefinition {
        proto::PeerGroupDefinition {
            families: vec!["ipv4_unicast".into()],
            route_server_client: Some(true),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn set_peer_group_rejected_on_read_only_listener() {
        let (peer_tx, mut peer_rx) = mpsc::channel(4);
        let (config_tx, mut config_rx) = mpsc::channel(4);
        let svc = PeerGroupService::new(AccessMode::ReadOnly, peer_tx, Some(config_tx));

        let err = PeerGroupServiceRpc::set_peer_group(
            &svc,
            Request::new(proto::SetPeerGroupRequest {
                name: "rs-clients".into(),
                definition: Some(sample_definition()),
            }),
        )
        .await
        .unwrap_err();

        assert_eq!(err.code(), tonic::Code::PermissionDenied);
        assert!(matches!(peer_rx.try_recv(), Err(TryRecvError::Empty)));
        assert!(matches!(config_rx.try_recv(), Err(TryRecvError::Empty)));
    }
}
