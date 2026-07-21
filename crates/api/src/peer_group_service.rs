//! gRPC peer-group service — reusable neighbor defaults and membership.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{mpsc, oneshot};
use tonic::{Request, Response, Status};

use crate::audit::{set_peer_group_summary, set_request_summary};
use crate::neighbor_service::{
    family_to_string, parse_families_proto, parse_remove_private_as_proto,
};
use crate::peer_types::{
    AddPathDefinition, ConfigEvent, PeerGroupDefinition, PeerManagerCommand,
    PolicyStatementDefinition,
};
use crate::policy_helpers::proto_statement_to_input;
use crate::proto;
use crate::server::{
    AccessMode, ConfigMutationGateFn, apply_catalog_mutation, catalog_mutation_error_to_status,
    peer_manager_request, persist_rollback_error, persist_runtime_config_event,
    read_only_rejection, run_shielded_catalog_mutation,
};

const CONFIG_PERSIST_RESERVE_TIMEOUT: Duration = Duration::from_secs(2);

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
    clippy::too_many_lines,
    reason = "peer-group conversion mirrors the complete protobuf definition"
)]
fn proto_definition_to_input(
    definition: proto::PeerGroupDefinition,
) -> Result<PeerGroupDefinition, Status> {
    if definition.max_prefix_restart_seconds == Some(0) {
        return Err(Status::invalid_argument(
            "max_prefix_restart_seconds must be greater than zero when set",
        ));
    }
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
    let gr_peer_restart_time_max = definition
        .gr_peer_restart_time_max
        .map(u16::try_from)
        .transpose()
        .map_err(|_| Status::invalid_argument("gr_peer_restart_time_max exceeds u16 range"))?;
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

    let orr_vantage = definition
        .orr_vantage
        .as_deref()
        .map(|raw| {
            raw.parse::<std::net::IpAddr>()
                .map_err(|e| Status::invalid_argument(format!("invalid orr_vantage {raw:?}: {e}")))
        })
        .transpose()?;
    let paths_limit_receive_max = definition
        .paths_limit_receive_max
        .map(|value| {
            u16::try_from(value)
                .map_err(|_| Status::invalid_argument("paths_limit_receive_max must be <= 65535"))
        })
        .transpose()?;

    Ok(PeerGroupDefinition {
        hold_time,
        send_hold_time: definition.send_hold_time,
        max_prefixes: definition.max_prefixes,
        max_prefix_restart_seconds: definition.max_prefix_restart_seconds,
        md5_password: definition.md5_password.map(Into::into),
        ttl_security: definition.ttl_security,
        families,
        graceful_restart: definition.graceful_restart,
        gr_restart_time,
        gr_peer_restart_time_max,
        gr_stale_routes_time: definition.gr_stale_routes_time,
        llgr_stale_time: definition.llgr_stale_time,
        local_ipv6_nexthop: definition.local_ipv6_nexthop,
        route_reflector_client: definition.route_reflector_client,
        orr_vantage,
        route_server_client: definition.route_server_client,
        per_client_best: definition.per_client_best,
        remove_private_as: if remove_private_as.is_empty() {
            None
        } else {
            Some(remove_private_as)
        },
        add_path: definition
            .add_path_receive
            .map(|receive| AddPathDefinition {
                receive_max: paths_limit_receive_max,
                receive,
                send: definition.add_path_send.unwrap_or(false),
                send_max: definition.add_path_send_max,
            })
            .or_else(|| {
                definition.add_path_send.map(|send| AddPathDefinition {
                    receive_max: paths_limit_receive_max,
                    receive: false,
                    send,
                    send_max: definition.add_path_send_max,
                })
            })
            .or_else(|| {
                paths_limit_receive_max.map(|receive_max| AddPathDefinition {
                    receive_max: Some(receive_max),
                    receive: false,
                    send: false,
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
        send_hold_time: definition.send_hold_time,
        max_prefixes: definition.max_prefixes,
        max_prefix_restart_seconds: definition.max_prefix_restart_seconds,
        // Read RPCs expose the group shape, not credential material.
        md5_password: None,
        has_md5_password: Some(definition.md5_password.is_some()),
        ttl_security: definition.ttl_security,
        families: definition.families.clone(),
        graceful_restart: definition.graceful_restart,
        gr_restart_time: definition.gr_restart_time.map(u32::from),
        gr_peer_restart_time_max: definition.gr_peer_restart_time_max.map(u32::from),
        gr_stale_routes_time: definition.gr_stale_routes_time,
        llgr_stale_time: definition.llgr_stale_time,
        local_ipv6_nexthop: definition.local_ipv6_nexthop.clone(),
        route_reflector_client: definition.route_reflector_client,
        orr_vantage: definition.orr_vantage.map(|addr| addr.to_string()),
        route_server_client: definition.route_server_client,
        per_client_best: definition.per_client_best,
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
        paths_limit_receive_max: definition
            .add_path
            .as_ref()
            .and_then(|add_path| add_path.receive_max)
            .map(u32::from),
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
    runtime_config_lock: Arc<tokio::sync::Mutex<()>>,
    config_mutation_gate: Option<ConfigMutationGateFn>,
}

impl PeerGroupService {
    /// Create a new peer-group service with the given channels and a
    /// private runtime-config lock (tests / embedded use).
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

    /// Create a peer-group service sharing the daemon-wide runtime-config
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
        }
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
        let summary = {
            let req = request.get_ref();
            let definition = req.definition.as_ref();
            set_peer_group_summary(
                &req.name,
                definition
                    .and_then(|definition| definition.md5_password.as_ref())
                    .is_some(),
                definition.and_then(|definition| definition.has_md5_password),
            )
        };
        set_request_summary(&request, summary);
        let req = request.into_inner();
        if req.name.trim().is_empty() {
            return Err(Status::invalid_argument("name is required"));
        }
        let definition = req
            .definition
            .ok_or_else(|| Status::invalid_argument("definition is required"))?;
        let preserve_md5_password =
            definition.md5_password.is_none() && definition.has_md5_password.unwrap_or(true);
        let definition = proto_definition_to_input(definition)?;
        let persist_permit = reserve_config_event_slot(self.config_tx.clone()).await?;

        let peer_mgr_tx = self.peer_mgr_tx.clone();
        let name = req.name;
        self.run_mutation("PeerGroupService.SetPeerGroup", move || async move {
            // Prior state is the unredacted stored definition (including
            // md5_password) so a rollback restores the secret intact.
            let prior =
                peer_manager_request(&peer_mgr_tx, |reply| PeerManagerCommand::GetPeerGroup {
                    name: name.clone(),
                    reply,
                })
                .await?;

            let persisted = if preserve_md5_password {
                peer_manager_request(&peer_mgr_tx, |reply| {
                    PeerManagerCommand::SetPeerGroupPreserveMd5 {
                        name: name.clone(),
                        definition,
                        reply,
                    }
                })
                .await?
                .map_err(|error| catalog_mutation_error_to_status(&error))?
            } else {
                let persisted = definition.clone();
                apply_catalog_mutation(&peer_mgr_tx, |reply| PeerManagerCommand::SetPeerGroup {
                    name: name.clone(),
                    definition,
                    reply,
                })
                .await?;
                persisted
            };

            if let Some(permit) = persist_permit
                && let Err(error) =
                    persist_runtime_config_event(permit, |ack| ConfigEvent::SetPeerGroup {
                        name: name.clone(),
                        definition: persisted,
                        ack: Some(ack),
                    })
                    .await
            {
                // Plain SetPeerGroup (not preserve-md5): the prior is the
                // full stored definition, secret included.
                let rollback = match prior {
                    Some(prior) => {
                        apply_catalog_mutation(&peer_mgr_tx, |reply| {
                            PeerManagerCommand::SetPeerGroup {
                                name: name.clone(),
                                definition: prior,
                                reply,
                            }
                        })
                        .await
                    }
                    None => {
                        apply_catalog_mutation(&peer_mgr_tx, |reply| {
                            PeerManagerCommand::DeletePeerGroup {
                                name: name.clone(),
                                reply,
                            }
                        })
                        .await
                    }
                };
                return Err(persist_rollback_error("peer-group set", error, rollback));
            }
            Ok(())
        })
        .await?;

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
        let peer_mgr_tx = self.peer_mgr_tx.clone();
        let name = req.name;
        self.run_mutation("PeerGroupService.DeletePeerGroup", move || async move {
            let prior =
                peer_manager_request(&peer_mgr_tx, |reply| PeerManagerCommand::GetPeerGroup {
                    name: name.clone(),
                    reply,
                })
                .await?;
            apply_catalog_mutation(&peer_mgr_tx, |reply| PeerManagerCommand::DeletePeerGroup {
                name: name.clone(),
                reply,
            })
            .await?;

            if let Some(permit) = persist_permit
                && let Err(error) =
                    persist_runtime_config_event(permit, |ack| ConfigEvent::DeletePeerGroup {
                        name: name.clone(),
                        ack: Some(ack),
                    })
                    .await
            {
                let rollback = match prior {
                    Some(prior) => {
                        apply_catalog_mutation(&peer_mgr_tx, |reply| {
                            PeerManagerCommand::SetPeerGroup {
                                name: name.clone(),
                                definition: prior,
                                reply,
                            }
                        })
                        .await
                    }
                    // Deletes are idempotent (a missing group is not an
                    // error), so a `None` prior leaves nothing to restore.
                    None => Ok(()),
                };
                return Err(persist_rollback_error("peer-group delete", error, rollback));
            }
            Ok(())
        })
        .await?;

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
        let peer_mgr_tx = self.peer_mgr_tx.clone();
        let peer_group = req.peer_group;
        self.run_mutation(
            "PeerGroupService.SetNeighborPeerGroup",
            move || async move {
                let prior = peer_manager_request(&peer_mgr_tx, |reply| {
                    PeerManagerCommand::GetNeighborPeerGroupMembership { address, reply }
                })
                .await?;
                apply_catalog_mutation(&peer_mgr_tx, |reply| {
                    PeerManagerCommand::SetNeighborPeerGroup {
                        address,
                        peer_group: peer_group.clone(),
                        reply,
                    }
                })
                .await?;

                if let Some(permit) = persist_permit
                    && let Err(error) = persist_runtime_config_event(permit, |ack| {
                        ConfigEvent::SetNeighborPeerGroup {
                            address,
                            peer_group: peer_group.clone(),
                            ack: Some(ack),
                        }
                    })
                    .await
                {
                    let rollback = match prior {
                        Some(Some(prior)) => {
                            apply_catalog_mutation(&peer_mgr_tx, |reply| {
                                PeerManagerCommand::SetNeighborPeerGroup {
                                    address,
                                    peer_group: prior,
                                    reply,
                                }
                            })
                            .await
                        }
                        Some(None) => {
                            apply_catalog_mutation(&peer_mgr_tx, |reply| {
                                PeerManagerCommand::ClearNeighborPeerGroup { address, reply }
                            })
                            .await
                        }
                        // The mutation succeeded, so the neighbor was
                        // configured; an unexpectedly missing prior leaves
                        // nothing to restore.
                        None => Ok(()),
                    };
                    return Err(persist_rollback_error(
                        "neighbor peer-group set",
                        error,
                        rollback,
                    ));
                }
                Ok(())
            },
        )
        .await?;

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
        let peer_mgr_tx = self.peer_mgr_tx.clone();
        self.run_mutation(
            "PeerGroupService.ClearNeighborPeerGroup",
            move || async move {
                let prior = peer_manager_request(&peer_mgr_tx, |reply| {
                    PeerManagerCommand::GetNeighborPeerGroupMembership { address, reply }
                })
                .await?;
                apply_catalog_mutation(&peer_mgr_tx, |reply| {
                    PeerManagerCommand::ClearNeighborPeerGroup { address, reply }
                })
                .await?;

                if let Some(permit) = persist_permit
                    && let Err(error) = persist_runtime_config_event(permit, |ack| {
                        ConfigEvent::ClearNeighborPeerGroup {
                            address,
                            ack: Some(ack),
                        }
                    })
                    .await
                {
                    let rollback = match prior {
                        Some(Some(prior)) => {
                            apply_catalog_mutation(&peer_mgr_tx, |reply| {
                                PeerManagerCommand::SetNeighborPeerGroup {
                                    address,
                                    peer_group: prior,
                                    reply,
                                }
                            })
                            .await
                        }
                        // No prior membership (or no neighbor) — the
                        // cleared state is already the prior state.
                        Some(None) | None => Ok(()),
                    };
                    return Err(persist_rollback_error(
                        "neighbor peer-group clear",
                        error,
                        rollback,
                    ));
                }
                Ok(())
            },
        )
        .await?;

        Ok(Response::new(proto::ClearNeighborPeerGroupResponse {}))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::GrpcAuditHandle;
    use crate::peer_types::NamedPeerGroupSnapshot;
    use crate::proto::peer_group_service_server::PeerGroupService as PeerGroupServiceRpc;
    use tokio::sync::mpsc::error::TryRecvError;

    fn sample_definition() -> proto::PeerGroupDefinition {
        proto::PeerGroupDefinition {
            families: vec!["ipv4_unicast".into()],
            md5_password: Some("secret".into()),
            route_server_client: Some(true),
            ..Default::default()
        }
    }

    /// `orr_vantage` round-trips proto string → typed `IpAddr` → proto
    /// string, and an unparseable vantage is rejected with
    /// `InvalidArgument` rather than silently dropped.
    #[test]
    fn orr_vantage_round_trips_and_rejects_invalid() {
        let mut definition = sample_definition();
        definition.orr_vantage = Some("192.0.2.7".into());
        let input = proto_definition_to_input(definition).unwrap();
        assert_eq!(input.orr_vantage, Some("192.0.2.7".parse().unwrap()));
        let back = input_definition_to_proto(&input);
        assert_eq!(back.orr_vantage.as_deref(), Some("192.0.2.7"));

        let mut invalid = sample_definition();
        invalid.orr_vantage = Some("not-an-ip".into());
        let err = proto_definition_to_input(invalid).unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("orr_vantage"));
    }

    /// Load-bearing: dropping either conversion assignment loses the cap on
    /// one side of the peer-group CRUD round trip.
    #[test]
    fn gr_peer_restart_time_max_round_trips() {
        let mut definition = sample_definition();
        definition.gr_peer_restart_time_max = Some(300);
        let input = proto_definition_to_input(definition).unwrap();
        assert_eq!(input.gr_peer_restart_time_max, Some(300));
        let back = input_definition_to_proto(&input);
        assert_eq!(back.gr_peer_restart_time_max, Some(300));
    }

    /// RFC 9687 `send_hold_time` round-trips proto -> input -> proto.
    /// (The `>hold_time` / 0=disabled rule is enforced by the config
    /// validation the `SetPeerGroup` apply path re-runs.)
    #[test]
    fn send_hold_time_round_trips() {
        let mut definition = sample_definition();
        definition.send_hold_time = Some(500);
        let input = proto_definition_to_input(definition).unwrap();
        assert_eq!(input.send_hold_time, Some(500));
        let back = input_definition_to_proto(&input);
        assert_eq!(back.send_hold_time, Some(500));
    }

    /// The timed max-prefix policy survives both peer-group API conversion
    /// directions, while zero is rejected rather than silently becoming the
    /// fail-closed default.
    #[test]
    fn max_prefix_restart_round_trips_and_rejects_zero() {
        let mut definition = sample_definition();
        definition.max_prefix_restart_seconds = Some(300);
        let input = proto_definition_to_input(definition).unwrap();
        assert_eq!(input.max_prefix_restart_seconds, Some(300));
        let back = input_definition_to_proto(&input);
        assert_eq!(back.max_prefix_restart_seconds, Some(300));

        let mut invalid = sample_definition();
        invalid.max_prefix_restart_seconds = Some(0);
        let err = proto_definition_to_input(invalid).unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("max_prefix_restart_seconds"));
    }

    /// `per_client_best` round-trips proto -> input -> proto.
    #[test]
    fn per_client_best_round_trips() {
        let mut definition = sample_definition();
        definition.per_client_best = Some(true);
        let input = proto_definition_to_input(definition).unwrap();
        assert_eq!(input.per_client_best, Some(true));
        let back = input_definition_to_proto(&input);
        assert_eq!(back.per_client_best, Some(true));
    }

    #[test]
    fn paths_limit_receive_max_round_trips_and_rejects_overflow() {
        let mut definition = sample_definition();
        definition.add_path_receive = Some(true);
        definition.paths_limit_receive_max = Some(7);
        let input = proto_definition_to_input(definition).unwrap();
        assert_eq!(input.add_path.as_ref().and_then(|a| a.receive_max), Some(7));
        let back = input_definition_to_proto(&input);
        assert_eq!(back.paths_limit_receive_max, Some(7));

        let mut invalid = sample_definition();
        invalid.paths_limit_receive_max = Some(65_536);
        let err = proto_definition_to_input(invalid).unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("paths_limit_receive_max"));
    }

    #[tokio::test]
    async fn read_peer_group_responses_redact_md5_password() {
        let definition = proto_definition_to_input(sample_definition()).unwrap();
        assert_eq!(
            definition
                .md5_password
                .as_ref()
                .map(std::convert::AsRef::as_ref),
            Some("secret")
        );

        let output = input_definition_to_proto(&definition);
        assert_eq!(output.md5_password, None);
        assert_eq!(output.has_md5_password, Some(true));

        let debug = format!("{definition:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("secret"));

        let (peer_tx, mut peer_rx) = mpsc::channel(4);
        let svc = PeerGroupService::new(AccessMode::ReadOnly, peer_tx, None, None);

        let task = tokio::spawn(async move {
            PeerGroupServiceRpc::list_peer_groups(
                &svc,
                Request::new(proto::ListPeerGroupsRequest {}),
            )
            .await
        });

        let command = peer_rx
            .recv()
            .await
            .expect("expected ListPeerGroups command");
        match command {
            PeerManagerCommand::ListPeerGroups { reply } => {
                reply
                    .send(vec![NamedPeerGroupSnapshot {
                        name: "rs-clients".into(),
                        definition,
                    }])
                    .expect("service dropped ListPeerGroups reply");
            }
            _ => panic!("unexpected command"),
        }

        let response = task
            .await
            .expect("ListPeerGroups task panicked")
            .expect("ListPeerGroups failed")
            .into_inner();
        let definition = response.peer_groups[0]
            .definition
            .as_ref()
            .expect("peer-group definition missing");
        assert_eq!(definition.md5_password, None);
        assert_eq!(definition.has_md5_password, Some(true));
    }

    #[tokio::test]
    async fn set_peer_group_preserves_redacted_md5_when_presence_flag_is_set() {
        let (peer_tx, mut peer_rx) = mpsc::channel(8);
        let (config_tx, mut config_rx) = mpsc::channel(4);
        let svc = PeerGroupService::new(AccessMode::ReadWrite, peer_tx, Some(config_tx), None);

        tokio::spawn(async move {
            while let Some(cmd) = peer_rx.recv().await {
                match cmd {
                    PeerManagerCommand::GetPeerGroup { reply, .. } => {
                        let _ = reply.send(None);
                    }
                    PeerManagerCommand::SetPeerGroupPreserveMd5 {
                        name,
                        mut definition,
                        reply,
                    } => {
                        assert_eq!(name, "rs-clients");
                        assert_eq!(definition.md5_password, None);
                        assert_eq!(definition.families, vec!["ipv6_unicast"]);
                        definition.md5_password = Some("secret".into());
                        let _ = reply.send(Ok(definition));
                    }
                    _ => panic!("unexpected peer-manager command"),
                }
            }
        });

        let task = tokio::spawn(async move {
            PeerGroupServiceRpc::set_peer_group(
                &svc,
                Request::new(proto::SetPeerGroupRequest {
                    name: "rs-clients".into(),
                    definition: Some(proto::PeerGroupDefinition {
                        has_md5_password: Some(true),
                        md5_password: None,
                        families: vec!["ipv6_unicast".into()],
                        ..Default::default()
                    }),
                }),
            )
            .await
        });

        match config_rx.recv().await {
            Some(ConfigEvent::SetPeerGroup {
                name,
                definition,
                ack,
            }) => {
                assert_eq!(name, "rs-clients");
                assert_eq!(
                    definition
                        .md5_password
                        .as_ref()
                        .map(std::convert::AsRef::as_ref),
                    Some("secret")
                );
                assert_eq!(definition.families, vec!["ipv6_unicast"]);
                ack.expect("persisted mutation must carry an ack")
                    .send(Ok(()))
                    .expect("service should await the persistence ack");
            }
            Some(_) => panic!("unexpected config event"),
            None => panic!("missing config event"),
        }

        task.await
            .expect("SetPeerGroup task panicked")
            .expect("SetPeerGroup failed");
    }

    #[tokio::test]
    async fn set_peer_group_audit_summary_redacts_md5_password() {
        let (peer_tx, mut peer_rx) = mpsc::channel(4);
        let svc = PeerGroupService::new(AccessMode::ReadWrite, peer_tx, None, None);
        let audit_handle = GrpcAuditHandle::default();
        let mut request = Request::new(proto::SetPeerGroupRequest {
            name: "rs-clients".into(),
            definition: Some(proto::PeerGroupDefinition {
                md5_password: Some("super-secret".into()),
                families: vec!["ipv6_unicast".into()],
                ..Default::default()
            }),
        });
        request.extensions_mut().insert(audit_handle.clone());

        let task =
            tokio::spawn(async move { PeerGroupServiceRpc::set_peer_group(&svc, request).await });

        tokio::spawn(async move {
            while let Some(cmd) = peer_rx.recv().await {
                match cmd {
                    PeerManagerCommand::GetPeerGroup { reply, .. } => {
                        let _ = reply.send(None);
                    }
                    PeerManagerCommand::SetPeerGroup {
                        definition, reply, ..
                    } => {
                        assert_eq!(
                            definition
                                .md5_password
                                .as_ref()
                                .map(std::convert::AsRef::as_ref),
                            Some("super-secret")
                        );
                        let _ = reply.send(Ok(()));
                    }
                    _ => panic!("unexpected peer-manager command"),
                }
            }
        });

        task.await
            .expect("SetPeerGroup task panicked")
            .expect("SetPeerGroup failed");

        let summary = audit_handle.summary().expect("audit summary missing");
        assert_eq!(
            summary.as_str(),
            "name=rs-clients md5_password=set_redacted"
        );
        assert!(!summary.as_str().contains("super-secret"));
    }

    #[tokio::test]
    async fn set_peer_group_omitted_md5_presence_preserves_by_default() {
        let (peer_tx, mut peer_rx) = mpsc::channel(4);
        let svc = PeerGroupService::new(AccessMode::ReadWrite, peer_tx, None, None);

        let task = tokio::spawn(async move {
            PeerGroupServiceRpc::set_peer_group(
                &svc,
                Request::new(proto::SetPeerGroupRequest {
                    name: "rs-clients".into(),
                    definition: Some(proto::PeerGroupDefinition {
                        md5_password: None,
                        families: vec!["ipv6_unicast".into()],
                        ..Default::default()
                    }),
                }),
            )
            .await
        });

        tokio::spawn(async move {
            while let Some(cmd) = peer_rx.recv().await {
                match cmd {
                    PeerManagerCommand::GetPeerGroup { reply, .. } => {
                        let _ = reply.send(None);
                    }
                    PeerManagerCommand::SetPeerGroupPreserveMd5 {
                        name,
                        mut definition,
                        reply,
                    } => {
                        assert_eq!(name, "rs-clients");
                        assert_eq!(definition.md5_password, None);
                        definition.md5_password = Some("secret".into());
                        let _ = reply.send(Ok(definition));
                    }
                    _ => panic!("unexpected peer-manager command"),
                }
            }
        });

        task.await
            .expect("SetPeerGroup task panicked")
            .expect("SetPeerGroup failed");
    }

    #[tokio::test]
    async fn set_peer_group_explicit_false_clears_redacted_md5() {
        let (peer_tx, mut peer_rx) = mpsc::channel(4);
        let svc = PeerGroupService::new(AccessMode::ReadWrite, peer_tx, None, None);

        let task = tokio::spawn(async move {
            PeerGroupServiceRpc::set_peer_group(
                &svc,
                Request::new(proto::SetPeerGroupRequest {
                    name: "rs-clients".into(),
                    definition: Some(proto::PeerGroupDefinition {
                        has_md5_password: Some(false),
                        md5_password: None,
                        families: vec!["ipv6_unicast".into()],
                        ..Default::default()
                    }),
                }),
            )
            .await
        });

        tokio::spawn(async move {
            while let Some(cmd) = peer_rx.recv().await {
                match cmd {
                    PeerManagerCommand::GetPeerGroup { reply, .. } => {
                        let _ = reply.send(None);
                    }
                    PeerManagerCommand::SetPeerGroup {
                        name,
                        definition,
                        reply,
                    } => {
                        assert_eq!(name, "rs-clients");
                        assert_eq!(definition.md5_password, None);
                        let _ = reply.send(Ok(()));
                    }
                    _ => panic!("unexpected peer-manager command"),
                }
            }
        });

        task.await
            .expect("SetPeerGroup task panicked")
            .expect("SetPeerGroup failed");
    }

    #[tokio::test]
    async fn set_peer_group_rejected_on_read_only_listener() {
        let (peer_tx, mut peer_rx) = mpsc::channel(4);
        let (config_tx, mut config_rx) = mpsc::channel(4);
        let svc = PeerGroupService::new(AccessMode::ReadOnly, peer_tx, Some(config_tx), None);

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

    #[tokio::test]
    async fn remaining_mutations_rejected_on_read_only_listener() {
        let (peer_tx, mut peer_rx) = mpsc::channel(4);
        let (config_tx, mut config_rx) = mpsc::channel(4);
        let svc = PeerGroupService::new(AccessMode::ReadOnly, peer_tx, Some(config_tx), None);

        let err = PeerGroupServiceRpc::delete_peer_group(
            &svc,
            Request::new(proto::DeletePeerGroupRequest {
                name: "rs-clients".into(),
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);

        let err = PeerGroupServiceRpc::set_neighbor_peer_group(
            &svc,
            Request::new(proto::SetNeighborPeerGroupRequest {
                address: "10.0.0.2".into(),
                peer_group: "rs-clients".into(),
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);

        let err = PeerGroupServiceRpc::clear_neighbor_peer_group(
            &svc,
            Request::new(proto::ClearNeighborPeerGroupRequest {
                address: "10.0.0.2".into(),
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);

        assert!(matches!(peer_rx.try_recv(), Err(TryRecvError::Empty)));
        assert!(matches!(config_rx.try_recv(), Err(TryRecvError::Empty)));
    }

    /// ADR-0076 contract: a `NACKed` persist restores the captured prior
    /// definition — including the stored MD5 secret, which read RPCs
    /// redact but the rollback must not lose.
    #[tokio::test]
    async fn set_peer_group_rolls_back_runtime_when_persist_fails() {
        let (peer_tx, mut peer_rx) = mpsc::channel(8);
        let (config_tx, mut config_rx) = mpsc::channel(4);
        let svc = PeerGroupService::new(AccessMode::ReadWrite, peer_tx, Some(config_tx), None);

        let mut prior = proto_definition_to_input(sample_definition()).unwrap();
        prior.md5_password = Some("old-secret".into());
        let prior_for_pm = prior.clone();
        let set_definitions = std::sync::Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let set_definitions_pm = set_definitions.clone();
        tokio::spawn(async move {
            while let Some(cmd) = peer_rx.recv().await {
                match cmd {
                    PeerManagerCommand::GetPeerGroup { reply, .. } => {
                        let _ = reply.send(Some(prior_for_pm.clone()));
                    }
                    PeerManagerCommand::SetPeerGroup {
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
            PeerGroupServiceRpc::set_peer_group(
                &svc,
                Request::new(proto::SetPeerGroupRequest {
                    name: "rs-clients".into(),
                    definition: Some(proto::PeerGroupDefinition {
                        md5_password: Some("new-secret".into()),
                        families: vec!["ipv6_unicast".into()],
                        ..Default::default()
                    }),
                }),
            )
            .await
        });

        match config_rx.recv().await {
            Some(ConfigEvent::SetPeerGroup { ack, .. }) => {
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
            .expect_err("set_peer_group must fail when persistence fails");
        assert_eq!(error.code(), tonic::Code::FailedPrecondition);
        assert!(error.message().contains("config persistence failed"));

        let sets = set_definitions.lock().await;
        assert_eq!(sets.len(), 2, "mutation then rollback");
        assert_eq!(
            sets[0]
                .md5_password
                .as_ref()
                .map(std::convert::AsRef::as_ref),
            Some("new-secret")
        );
        assert_eq!(
            sets[1]
                .md5_password
                .as_ref()
                .map(std::convert::AsRef::as_ref),
            Some("old-secret"),
            "rollback must restore the prior definition with its stored secret"
        );
        assert_eq!(sets[1], prior);
    }

    #[tokio::test]
    async fn delete_peer_group_rolls_back_runtime_when_persist_fails() {
        let (peer_tx, mut peer_rx) = mpsc::channel(8);
        let (config_tx, mut config_rx) = mpsc::channel(4);
        let svc = PeerGroupService::new(AccessMode::ReadWrite, peer_tx, Some(config_tx), None);

        let prior = proto_definition_to_input(sample_definition()).unwrap();
        let prior_for_pm = prior.clone();
        let set_definitions = std::sync::Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let set_definitions_pm = set_definitions.clone();
        tokio::spawn(async move {
            while let Some(cmd) = peer_rx.recv().await {
                match cmd {
                    PeerManagerCommand::GetPeerGroup { reply, .. } => {
                        let _ = reply.send(Some(prior_for_pm.clone()));
                    }
                    PeerManagerCommand::DeletePeerGroup { name, reply } => {
                        assert_eq!(name, "rs-clients");
                        let _ = reply.send(Ok(()));
                    }
                    PeerManagerCommand::SetPeerGroup {
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
            PeerGroupServiceRpc::delete_peer_group(
                &svc,
                Request::new(proto::DeletePeerGroupRequest {
                    name: "rs-clients".into(),
                }),
            )
            .await
        });

        match config_rx.recv().await {
            Some(ConfigEvent::DeletePeerGroup { ack, .. }) => {
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
            .expect_err("delete_peer_group must fail when persistence fails");
        assert_eq!(error.code(), tonic::Code::FailedPrecondition);

        let sets = set_definitions.lock().await;
        assert_eq!(
            sets.as_slice(),
            &[prior],
            "rollback must re-create the deleted peer group"
        );
    }

    #[tokio::test]
    async fn set_neighbor_peer_group_rolls_back_runtime_when_persist_fails() {
        let (peer_tx, mut peer_rx) = mpsc::channel(8);
        let (config_tx, mut config_rx) = mpsc::channel(4);
        let svc = PeerGroupService::new(AccessMode::ReadWrite, peer_tx, Some(config_tx), None);

        let memberships = std::sync::Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let memberships_pm = memberships.clone();
        tokio::spawn(async move {
            while let Some(cmd) = peer_rx.recv().await {
                match cmd {
                    PeerManagerCommand::GetNeighborPeerGroupMembership { reply, .. } => {
                        let _ = reply.send(Some(Some("old-group".to_string())));
                    }
                    PeerManagerCommand::SetNeighborPeerGroup {
                        peer_group, reply, ..
                    } => {
                        memberships_pm.lock().await.push(peer_group);
                        let _ = reply.send(Ok(()));
                    }
                    _ => panic!("unexpected peer-manager command"),
                }
            }
        });

        let call = tokio::spawn(async move {
            PeerGroupServiceRpc::set_neighbor_peer_group(
                &svc,
                Request::new(proto::SetNeighborPeerGroupRequest {
                    address: "10.0.0.2".into(),
                    peer_group: "rs-clients".into(),
                }),
            )
            .await
        });

        match config_rx.recv().await {
            Some(ConfigEvent::SetNeighborPeerGroup {
                address,
                peer_group,
                ack,
            }) => {
                assert_eq!(address.to_string(), "10.0.0.2");
                assert_eq!(peer_group, "rs-clients");
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
            .expect_err("set_neighbor_peer_group must fail when persistence fails");
        assert_eq!(error.code(), tonic::Code::FailedPrecondition);

        let sets = memberships.lock().await;
        assert_eq!(
            sets.as_slice(),
            &["rs-clients".to_string(), "old-group".to_string()],
            "rollback must restore the prior membership"
        );
    }
}
