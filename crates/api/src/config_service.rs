//! gRPC config diagnostics service.

use tokio::sync::{mpsc, oneshot};
use tonic::{Request, Response, Status};

use crate::peer_types::{PeerManagerCommand, RuntimeConfigDiff};
use crate::proto;

pub struct ConfigService {
    peer_mgr_tx: mpsc::Sender<PeerManagerCommand>,
}

impl ConfigService {
    pub fn new(peer_mgr_tx: mpsc::Sender<PeerManagerCommand>) -> Self {
        Self { peer_mgr_tx }
    }
}

fn diff_to_proto(diff: RuntimeConfigDiff) -> proto::DiffRuntimeConfigResponse {
    proto::DiffRuntimeConfigResponse {
        has_actionable_changes: diff.has_actionable_changes,
        has_reload_applied_changes: diff.has_reload_applied_changes,
        has_restart_required_changes: diff.has_restart_required_changes,
        has_informational_changes: diff.has_informational_changes,
        has_any_changes: diff.has_any_changes,
        human_text: diff.human_text,
        diff_json: diff.diff_json,
    }
}

#[tonic::async_trait]
impl proto::config_service_server::ConfigService for ConfigService {
    async fn diff_runtime_config(
        &self,
        request: Request<proto::DiffRuntimeConfigRequest>,
    ) -> Result<Response<proto::DiffRuntimeConfigResponse>, Status> {
        let candidate_toml = request.into_inner().candidate_toml;
        let (reply_tx, reply_rx) = oneshot::channel();
        self.peer_mgr_tx
            .send(PeerManagerCommand::DiffRuntimeConfig {
                candidate_toml,
                reply: reply_tx,
            })
            .await
            .map_err(|_| Status::unavailable("peer manager is unavailable"))?;

        match reply_rx
            .await
            .map_err(|_| Status::unavailable("peer manager dropped config diff reply"))?
        {
            Ok(diff) => Ok(Response::new(diff_to_proto(diff))),
            Err(error) => Err(Status::invalid_argument(error)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proto::config_service_server::ConfigService as _;

    #[tokio::test]
    async fn diff_runtime_config_forwards_candidate_to_peer_manager() {
        let (tx, mut rx) = mpsc::channel(1);
        let svc = ConfigService::new(tx);
        let server = tokio::spawn(async move {
            let Some(PeerManagerCommand::DiffRuntimeConfig {
                candidate_toml,
                reply,
            }) = rx.recv().await
            else {
                panic!("expected DiffRuntimeConfig command");
            };
            assert_eq!(
                candidate_toml,
                "[global]\nasn = 65001\nrouter_id = \"10.0.0.1\"\n"
            );
            let _ = reply.send(Ok(RuntimeConfigDiff {
                has_actionable_changes: true,
                has_reload_applied_changes: false,
                has_restart_required_changes: true,
                has_informational_changes: false,
                has_any_changes: true,
                human_text: "Restart-required changes:\n".to_string(),
                diff_json: "{\"has_any_changes\":true}".to_string(),
            }));
        });

        let resp = svc
            .diff_runtime_config(Request::new(proto::DiffRuntimeConfigRequest {
                candidate_toml: "[global]\nasn = 65001\nrouter_id = \"10.0.0.1\"\n".to_string(),
            }))
            .await
            .unwrap()
            .into_inner();

        server.await.unwrap();
        assert!(resp.has_actionable_changes);
        assert!(resp.has_restart_required_changes);
        assert_eq!(resp.human_text, "Restart-required changes:\n");
        assert_eq!(resp.diff_json, "{\"has_any_changes\":true}");
    }

    #[tokio::test]
    async fn diff_runtime_config_maps_peer_manager_error_to_invalid_argument() {
        let (tx, mut rx) = mpsc::channel(1);
        let svc = ConfigService::new(tx);
        tokio::spawn(async move {
            let Some(PeerManagerCommand::DiffRuntimeConfig { reply, .. }) = rx.recv().await else {
                panic!("expected DiffRuntimeConfig command");
            };
            let _ = reply.send(Err("error: invalid candidate".to_string()));
        });

        let err = svc
            .diff_runtime_config(Request::new(proto::DiffRuntimeConfigRequest {
                candidate_toml: "not toml".to_string(),
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("invalid candidate"));
    }
}
