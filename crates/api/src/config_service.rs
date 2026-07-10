//! gRPC config diagnostics service.

use tokio::sync::{mpsc, oneshot};
use tonic::{Request, Response, Status};

use crate::audit::{
    abort_config_transaction_summary, apply_config_transaction_summary,
    confirm_config_transaction_summary, diff_runtime_config_summary,
    get_config_transaction_status_summary, get_effective_config_summary,
    plan_config_transaction_summary, set_request_summary,
};
use crate::peer_types::{
    PeerManagerCommand, RuntimeConfigDiff, RuntimeConfigTransactionPlan,
    RuntimeConfigTransactionPlanError, RuntimeConfigTransactionStatus,
};
use crate::proto;
use crate::server::{
    ConfigTransactionAbortFn, ConfigTransactionApplyError, ConfigTransactionApplyFn,
    ConfigTransactionConfirmFn, ConfigTransactionStatusFn,
};

pub struct ConfigService {
    peer_mgr_tx: mpsc::Sender<PeerManagerCommand>,
    transaction_apply: Option<ConfigTransactionApplyFn>,
    transaction_confirm: Option<ConfigTransactionConfirmFn>,
    transaction_abort: Option<ConfigTransactionAbortFn>,
    transaction_status: Option<ConfigTransactionStatusFn>,
}

impl ConfigService {
    pub fn new(peer_mgr_tx: mpsc::Sender<PeerManagerCommand>) -> Self {
        Self {
            peer_mgr_tx,
            transaction_apply: None,
            transaction_confirm: None,
            transaction_abort: None,
            transaction_status: None,
        }
    }

    pub(crate) fn with_transaction_hooks(
        mut self,
        transaction_apply: Option<ConfigTransactionApplyFn>,
        transaction_confirm: Option<ConfigTransactionConfirmFn>,
        transaction_abort: Option<ConfigTransactionAbortFn>,
        transaction_status: Option<ConfigTransactionStatusFn>,
    ) -> Self {
        self.transaction_apply = transaction_apply;
        self.transaction_confirm = transaction_confirm;
        self.transaction_abort = transaction_abort;
        self.transaction_status = transaction_status;
        self
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

fn plan_status_to_proto(
    status: RuntimeConfigTransactionStatus,
) -> proto::ConfigTransactionPlanStatus {
    match status {
        RuntimeConfigTransactionStatus::Noop => proto::ConfigTransactionPlanStatus::Noop,
        RuntimeConfigTransactionStatus::Committable => {
            proto::ConfigTransactionPlanStatus::Committable
        }
        RuntimeConfigTransactionStatus::Rejected => proto::ConfigTransactionPlanStatus::Rejected,
    }
}

fn transaction_plan_to_proto(
    plan: RuntimeConfigTransactionPlan,
) -> proto::ConfigTransactionPlanResponse {
    proto::ConfigTransactionPlanResponse {
        status: plan_status_to_proto(plan.status).into(),
        runtime_snapshot_token: plan.runtime_snapshot_token,
        diff: Some(diff_to_proto(plan.diff)),
        supported_sections: plan.supported_sections,
        unsupported_sections: plan.unsupported_sections,
        restart_required_sections: plan.restart_required_sections,
        human_text: plan.human_text,
    }
}

/// Map a peer-manager plan error to a gRPC status. A runtime snapshot-token
/// mismatch is a stale-plan optimistic-concurrency failure
/// (`FAILED_PRECONDITION`) — consistent with the apply path — not a malformed
/// request. Candidate validation errors map to `INVALID_ARGUMENT`; internal
/// plan failures map to `INTERNAL`.
fn plan_error_to_status(error: RuntimeConfigTransactionPlanError) -> Status {
    match error {
        RuntimeConfigTransactionPlanError::StaleSnapshot { .. } => {
            Status::failed_precondition(error.message())
        }
        RuntimeConfigTransactionPlanError::InvalidCandidate(message) => {
            Status::invalid_argument(message)
        }
        RuntimeConfigTransactionPlanError::Internal(message) => Status::internal(message),
    }
}

#[tonic::async_trait]
impl proto::config_service_server::ConfigService for ConfigService {
    async fn diff_runtime_config(
        &self,
        request: Request<proto::DiffRuntimeConfigRequest>,
    ) -> Result<Response<proto::DiffRuntimeConfigResponse>, Status> {
        set_request_summary(
            &request,
            diff_runtime_config_summary(&request.get_ref().candidate_toml),
        );
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

    async fn plan_config_transaction(
        &self,
        request: Request<proto::PlanConfigTransactionRequest>,
    ) -> Result<Response<proto::ConfigTransactionPlanResponse>, Status> {
        set_request_summary(
            &request,
            plan_config_transaction_summary(
                &request.get_ref().candidate_toml,
                &request.get_ref().expected_runtime_snapshot_token,
            ),
        );
        let request = request.into_inner();
        let expected_runtime_snapshot_token = (!request.expected_runtime_snapshot_token.is_empty())
            .then_some(request.expected_runtime_snapshot_token);
        let (reply_tx, reply_rx) = oneshot::channel();
        self.peer_mgr_tx
            .send(PeerManagerCommand::PlanConfigTransaction {
                candidate_toml: request.candidate_toml,
                expected_runtime_snapshot_token,
                reply: reply_tx,
            })
            .await
            .map_err(|_| Status::unavailable("peer manager is unavailable"))?;

        match reply_rx.await.map_err(|_| {
            Status::unavailable("peer manager dropped config transaction plan reply")
        })? {
            Ok(plan) => Ok(Response::new(transaction_plan_to_proto(plan))),
            Err(error) => Err(plan_error_to_status(error)),
        }
    }

    async fn apply_config_transaction(
        &self,
        request: Request<proto::ApplyConfigTransactionRequest>,
    ) -> Result<Response<proto::ConfigTransactionApplyResponse>, Status> {
        set_request_summary(
            &request,
            apply_config_transaction_summary(
                &request.get_ref().candidate_toml,
                &request.get_ref().expected_runtime_snapshot_token,
                &request.get_ref().client_request_id,
                &request.get_ref().comment,
                &request.get_ref().confirm_id,
                request.get_ref().confirm_timeout_seconds,
            ),
        );
        let request = request.into_inner();
        let Some(transaction_apply) = &self.transaction_apply else {
            return Err(Status::failed_precondition(
                "ConfigService.ApplyConfigTransaction executor is unavailable",
            ));
        };
        transaction_apply(request)
            .await
            .map(Response::new)
            .map_err(ConfigTransactionApplyError::into_status)
    }

    async fn confirm_config_transaction(
        &self,
        request: Request<proto::ConfirmConfigTransactionRequest>,
    ) -> Result<Response<proto::ConfirmConfigTransactionResponse>, Status> {
        set_request_summary(
            &request,
            confirm_config_transaction_summary(&request.get_ref().confirm_id),
        );
        let request = request.into_inner();
        let Some(transaction_confirm) = &self.transaction_confirm else {
            return Err(Status::failed_precondition(
                "ConfigService.ConfirmConfigTransaction executor is unavailable",
            ));
        };
        transaction_confirm(request)
            .await
            .map(Response::new)
            .map_err(ConfigTransactionApplyError::into_status)
    }

    async fn abort_config_transaction(
        &self,
        request: Request<proto::AbortConfigTransactionRequest>,
    ) -> Result<Response<proto::AbortConfigTransactionResponse>, Status> {
        set_request_summary(
            &request,
            abort_config_transaction_summary(&request.get_ref().confirm_id),
        );
        let request = request.into_inner();
        let Some(transaction_abort) = &self.transaction_abort else {
            return Err(Status::failed_precondition(
                "ConfigService.AbortConfigTransaction executor is unavailable",
            ));
        };
        transaction_abort(request)
            .await
            .map(Response::new)
            .map_err(ConfigTransactionApplyError::into_status)
    }

    async fn get_config_transaction_status(
        &self,
        request: Request<proto::GetConfigTransactionStatusRequest>,
    ) -> Result<Response<proto::ConfigTransactionStatusResponse>, Status> {
        set_request_summary(&request, get_config_transaction_status_summary());
        let request = request.into_inner();
        let Some(transaction_status) = &self.transaction_status else {
            return Err(Status::failed_precondition(
                "ConfigService.GetConfigTransactionStatus executor is unavailable",
            ));
        };
        transaction_status(request)
            .await
            .map(Response::new)
            .map_err(ConfigTransactionApplyError::into_status)
    }

    async fn get_effective_config(
        &self,
        request: Request<proto::GetEffectiveConfigRequest>,
    ) -> Result<Response<proto::GetEffectiveConfigResponse>, Status> {
        set_request_summary(&request, get_effective_config_summary());
        let (reply_tx, reply_rx) = oneshot::channel();
        self.peer_mgr_tx
            .send(PeerManagerCommand::EffectiveRuntimeConfig { reply: reply_tx })
            .await
            .map_err(|_| Status::unavailable("peer manager is unavailable"))?;

        match reply_rx
            .await
            .map_err(|_| Status::unavailable("peer manager dropped effective config reply"))?
        {
            Ok(toml) => Ok(Response::new(proto::GetEffectiveConfigResponse { toml })),
            Err(error) => Err(Status::internal(error)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use crate::audit::GrpcAuditHandle;
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
    async fn get_effective_config_returns_peer_manager_toml() {
        let (tx, mut rx) = mpsc::channel(1);
        let svc = ConfigService::new(tx);
        let server = tokio::spawn(async move {
            let Some(PeerManagerCommand::EffectiveRuntimeConfig { reply }) = rx.recv().await else {
                panic!("expected EffectiveRuntimeConfig command");
            };
            let _ = reply.send(Ok(
                "[global]\nasn = 65001\nhold_time = 90\nrouter_id = \"10.0.0.1\"\n".to_string(),
            ));
        });

        let resp = svc
            .get_effective_config(Request::new(proto::GetEffectiveConfigRequest {}))
            .await
            .unwrap()
            .into_inner();

        server.await.unwrap();
        assert_eq!(
            resp.toml,
            "[global]\nasn = 65001\nhold_time = 90\nrouter_id = \"10.0.0.1\"\n"
        );
    }

    #[tokio::test]
    async fn get_effective_config_maps_serialization_failure_to_internal() {
        let (tx, mut rx) = mpsc::channel(1);
        let svc = ConfigService::new(tx);
        tokio::spawn(async move {
            let Some(PeerManagerCommand::EffectiveRuntimeConfig { reply }) = rx.recv().await else {
                panic!("expected EffectiveRuntimeConfig command");
            };
            let _ = reply.send(Err("failed to serialize effective config".to_string()));
        });

        let err = svc
            .get_effective_config(Request::new(proto::GetEffectiveConfigRequest {}))
            .await
            .unwrap_err();

        assert_eq!(err.code(), tonic::Code::Internal);
    }

    fn sample_runtime_diff() -> RuntimeConfigDiff {
        RuntimeConfigDiff {
            has_actionable_changes: true,
            has_reload_applied_changes: true,
            has_restart_required_changes: false,
            has_informational_changes: false,
            has_any_changes: true,
            human_text: "Reload-applied changes:\n".to_string(),
            diff_json: "{\"has_any_changes\":true}".to_string(),
        }
    }

    #[tokio::test]
    async fn plan_config_transaction_forwards_candidate_and_token() {
        let (tx, mut rx) = mpsc::channel(1);
        let svc = ConfigService::new(tx);
        let server = tokio::spawn(async move {
            let Some(PeerManagerCommand::PlanConfigTransaction {
                candidate_toml,
                expected_runtime_snapshot_token,
                reply,
            }) = rx.recv().await
            else {
                panic!("expected PlanConfigTransaction command");
            };
            assert_eq!(candidate_toml, "candidate");
            assert_eq!(
                expected_runtime_snapshot_token.as_deref(),
                Some("kv1:abc:9")
            );
            let _ = reply.send(Ok(RuntimeConfigTransactionPlan {
                status: RuntimeConfigTransactionStatus::Committable,
                runtime_snapshot_token: "kv1:abc:9".to_string(),
                post_commit_runtime_snapshot_token: "kv1:def:10".to_string(),
                diff: sample_runtime_diff(),
                supported_sections: vec!["[[fib_tables]]".to_string()],
                unsupported_sections: Vec::new(),
                restart_required_sections: Vec::new(),
                human_text: "Config transaction is committable by v1.\n".to_string(),
            }));
        });

        let resp = svc
            .plan_config_transaction(Request::new(proto::PlanConfigTransactionRequest {
                candidate_toml: "candidate".to_string(),
                expected_runtime_snapshot_token: "kv1:abc:9".to_string(),
            }))
            .await
            .unwrap()
            .into_inner();

        server.await.unwrap();
        assert_eq!(
            resp.status,
            proto::ConfigTransactionPlanStatus::Committable as i32
        );
        assert_eq!(resp.runtime_snapshot_token, "kv1:abc:9");
        assert_eq!(resp.supported_sections, vec!["[[fib_tables]]"]);
        assert!(resp.diff.unwrap().has_actionable_changes);
    }

    #[tokio::test]
    async fn plan_config_transaction_maps_token_mismatch_to_failed_precondition() {
        // A stale expected token is an optimistic-concurrency failure, not a
        // malformed request — same mapping as the apply path.
        let (tx, mut rx) = mpsc::channel(1);
        let svc = ConfigService::new(tx);
        tokio::spawn(async move {
            let Some(PeerManagerCommand::PlanConfigTransaction { reply, .. }) = rx.recv().await
            else {
                panic!("expected PlanConfigTransaction command");
            };
            let _ = reply.send(Err(RuntimeConfigTransactionPlanError::StaleSnapshot {
                expected: "stale".to_string(),
                current: "kv1:abc:9".to_string(),
            }));
        });

        let err = svc
            .plan_config_transaction(Request::new(proto::PlanConfigTransactionRequest {
                candidate_toml: "candidate".to_string(),
                expected_runtime_snapshot_token: "stale".to_string(),
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::FailedPrecondition);
        assert!(err.message().contains("runtime config snapshot changed"));
    }

    #[tokio::test]
    async fn plan_config_transaction_maps_validation_error_to_invalid_argument() {
        // A candidate validation error (not a token race) stays InvalidArgument.
        let (tx, mut rx) = mpsc::channel(1);
        let svc = ConfigService::new(tx);
        tokio::spawn(async move {
            let Some(PeerManagerCommand::PlanConfigTransaction { reply, .. }) = rx.recv().await
            else {
                panic!("expected PlanConfigTransaction command");
            };
            let _ = reply.send(Err(RuntimeConfigTransactionPlanError::InvalidCandidate(
                "invalid candidate: unknown field `bogus`".to_string(),
            )));
        });

        let err = svc
            .plan_config_transaction(Request::new(proto::PlanConfigTransactionRequest {
                candidate_toml: "candidate".to_string(),
                expected_runtime_snapshot_token: String::new(),
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn plan_config_transaction_audit_summary_redacts_candidate_toml() {
        let (tx, mut rx) = mpsc::channel(1);
        let svc = ConfigService::new(tx);
        tokio::spawn(async move {
            let Some(PeerManagerCommand::PlanConfigTransaction { reply, .. }) = rx.recv().await
            else {
                panic!("expected PlanConfigTransaction command");
            };
            let _ = reply.send(Ok(RuntimeConfigTransactionPlan {
                status: RuntimeConfigTransactionStatus::Noop,
                runtime_snapshot_token: "kv1:abc:9".to_string(),
                post_commit_runtime_snapshot_token: "kv1:abc:9".to_string(),
                diff: RuntimeConfigDiff {
                    has_actionable_changes: false,
                    has_reload_applied_changes: false,
                    has_restart_required_changes: false,
                    has_informational_changes: false,
                    has_any_changes: false,
                    human_text: String::new(),
                    diff_json: "{}".to_string(),
                },
                supported_sections: Vec::new(),
                unsupported_sections: Vec::new(),
                restart_required_sections: Vec::new(),
                human_text: "No changes.\n".to_string(),
            }));
        });

        let audit_handle = GrpcAuditHandle::default();
        let mut request = Request::new(proto::PlanConfigTransactionRequest {
            candidate_toml: "[global]\nmd5_password = \"secret\"\n".to_string(),
            expected_runtime_snapshot_token: "kv1:abc:9".to_string(),
        });
        request.extensions_mut().insert(audit_handle.clone());

        svc.plan_config_transaction(request).await.unwrap();

        let summary = audit_handle.summary().expect("audit summary missing");
        assert!(summary.as_str().contains("candidate_toml=<redacted>"));
        assert!(
            summary
                .as_str()
                .contains("expected_runtime_snapshot_token_present=true")
        );
        assert!(!summary.as_str().contains("secret"));
    }

    #[tokio::test]
    async fn apply_config_transaction_without_hook_fails_closed_but_audited() {
        let (tx, _rx) = mpsc::channel(1);
        let svc = ConfigService::new(tx);
        let audit_handle = GrpcAuditHandle::default();
        let mut request = Request::new(proto::ApplyConfigTransactionRequest {
            candidate_toml: "[global]\nmd5_password = \"secret\"\n".to_string(),
            expected_runtime_snapshot_token: "kv1:abc:9".to_string(),
            client_request_id: "deploy-42".to_string(),
            comment: "contains sensitive context".to_string(),
            confirm_id: String::new(),
            confirm_timeout_seconds: 0,
        });
        request.extensions_mut().insert(audit_handle.clone());

        let err = svc.apply_config_transaction(request).await.unwrap_err();

        assert_eq!(err.code(), tonic::Code::FailedPrecondition);
        let summary = audit_handle.summary().expect("audit summary missing");
        assert!(summary.as_str().contains("candidate_toml=<redacted>"));
        assert!(summary.as_str().contains("client_request_id=deploy-42"));
        assert!(summary.as_str().contains("comment_present=true"));
        assert!(!summary.as_str().contains("secret"));
        assert!(!summary.as_str().contains("sensitive context"));
    }

    #[tokio::test]
    async fn apply_config_transaction_forwards_to_hook() {
        let (tx, _rx) = mpsc::channel(1);
        let svc = ConfigService::new(tx).with_transaction_hooks(
            Some(Arc::new(|request| {
                Box::pin(async move {
                    assert_eq!(request.candidate_toml, "candidate");
                    assert_eq!(request.expected_runtime_snapshot_token, "kv1:abc:9");
                    assert_eq!(request.client_request_id, "deploy-42");
                    assert_eq!(request.comment, "change note");
                    assert!(request.confirm_id.is_empty());
                    assert_eq!(request.confirm_timeout_seconds, 0);
                    Ok(proto::ConfigTransactionApplyResponse {
                        status: proto::ConfigTransactionPlanStatus::Committable.into(),
                        runtime_snapshot_token: "kv1:def:10".to_string(),
                        committed_sections: vec!["[[fib_tables]]".to_string()],
                        human_text: "Committed [[fib_tables]] transaction.\n".to_string(),
                        confirmation: None,
                    })
                })
            })),
            None,
            None,
            None,
        );

        let resp = svc
            .apply_config_transaction(Request::new(proto::ApplyConfigTransactionRequest {
                candidate_toml: "candidate".to_string(),
                expected_runtime_snapshot_token: "kv1:abc:9".to_string(),
                client_request_id: "deploy-42".to_string(),
                comment: "change note".to_string(),
                confirm_id: String::new(),
                confirm_timeout_seconds: 0,
            }))
            .await
            .unwrap()
            .into_inner();

        assert_eq!(
            resp.status,
            proto::ConfigTransactionPlanStatus::Committable as i32
        );
        assert_eq!(resp.runtime_snapshot_token, "kv1:def:10");
        assert_eq!(resp.committed_sections, vec!["[[fib_tables]]"]);
    }

    #[tokio::test]
    async fn confirmed_transaction_control_hooks_forward_requests() {
        let (tx, _rx) = mpsc::channel(1);
        let svc = ConfigService::new(tx).with_transaction_hooks(
            None,
            Some(Arc::new(|request| {
                Box::pin(async move {
                    assert_eq!(request.confirm_id, "deploy-42");
                    Ok(proto::ConfirmConfigTransactionResponse {
                        confirmation: Some(proto::ConfigTransactionConfirmation {
                            status: proto::ConfigTransactionConfirmationStatus::Confirmed.into(),
                            confirm_id: request.confirm_id,
                            timeout_seconds: 60,
                            deadline_unix_seconds: 123,
                            committed_sections: vec!["[[neighbors]] modify".to_string()],
                            runtime_snapshot_token: "kv1:def:10".to_string(),
                            human_text: "confirmed".to_string(),
                        }),
                        human_text: "confirmed\n".to_string(),
                    })
                })
            })),
            Some(Arc::new(|request| {
                Box::pin(async move {
                    assert_eq!(request.confirm_id, "deploy-42");
                    Ok(proto::AbortConfigTransactionResponse {
                        confirmation: Some(proto::ConfigTransactionConfirmation {
                            status: proto::ConfigTransactionConfirmationStatus::Aborted.into(),
                            confirm_id: request.confirm_id,
                            timeout_seconds: 60,
                            deadline_unix_seconds: 123,
                            committed_sections: vec!["[[neighbors]] modify".to_string()],
                            runtime_snapshot_token: "kv1:rollback:11".to_string(),
                            human_text: "aborted".to_string(),
                        }),
                        runtime_snapshot_token: "kv1:rollback:11".to_string(),
                        human_text: "aborted\n".to_string(),
                    })
                })
            })),
            Some(Arc::new(|_request| {
                Box::pin(async move {
                    Ok(proto::ConfigTransactionStatusResponse {
                        confirmation: Some(proto::ConfigTransactionConfirmation {
                            status: proto::ConfigTransactionConfirmationStatus::Pending.into(),
                            confirm_id: "deploy-42".to_string(),
                            timeout_seconds: 60,
                            deadline_unix_seconds: 123,
                            committed_sections: vec!["[[neighbors]] modify".to_string()],
                            runtime_snapshot_token: "kv1:def:10".to_string(),
                            human_text: "pending".to_string(),
                        }),
                        human_text: "pending\n".to_string(),
                    })
                })
            })),
        );

        let confirmed = svc
            .confirm_config_transaction(Request::new(proto::ConfirmConfigTransactionRequest {
                confirm_id: "deploy-42".to_string(),
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(
            confirmed.confirmation.unwrap().status,
            proto::ConfigTransactionConfirmationStatus::Confirmed as i32
        );

        let aborted = svc
            .abort_config_transaction(Request::new(proto::AbortConfigTransactionRequest {
                confirm_id: "deploy-42".to_string(),
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(aborted.runtime_snapshot_token, "kv1:rollback:11");

        let status = svc
            .get_config_transaction_status(Request::new(
                proto::GetConfigTransactionStatusRequest {},
            ))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(
            status.confirmation.unwrap().status,
            proto::ConfigTransactionConfirmationStatus::Pending as i32
        );
    }

    #[tokio::test]
    async fn confirmed_transaction_control_hooks_fail_closed_without_executor() {
        let (tx, _rx) = mpsc::channel(1);
        let svc = ConfigService::new(tx);

        let err = svc
            .confirm_config_transaction(Request::new(proto::ConfirmConfigTransactionRequest {
                confirm_id: "deploy-42".to_string(),
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::FailedPrecondition);

        let err = svc
            .abort_config_transaction(Request::new(proto::AbortConfigTransactionRequest {
                confirm_id: "deploy-42".to_string(),
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::FailedPrecondition);

        let err = svc
            .get_config_transaction_status(Request::new(
                proto::GetConfigTransactionStatusRequest {},
            ))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::FailedPrecondition);
    }

    #[tokio::test]
    async fn diff_runtime_config_audit_summary_redacts_candidate_toml() {
        let (tx, mut rx) = mpsc::channel(1);
        let svc = ConfigService::new(tx);
        tokio::spawn(async move {
            let Some(PeerManagerCommand::DiffRuntimeConfig { reply, .. }) = rx.recv().await else {
                panic!("expected DiffRuntimeConfig command");
            };
            let _ = reply.send(Ok(RuntimeConfigDiff {
                has_actionable_changes: false,
                has_reload_applied_changes: false,
                has_restart_required_changes: false,
                has_informational_changes: false,
                has_any_changes: false,
                human_text: String::new(),
                diff_json: "{}".to_string(),
            }));
        });

        let audit_handle = GrpcAuditHandle::default();
        let mut request = Request::new(proto::DiffRuntimeConfigRequest {
            candidate_toml: "[global]\nmd5_password = \"secret\"\n".to_string(),
        });
        request.extensions_mut().insert(audit_handle.clone());

        svc.diff_runtime_config(request).await.unwrap();

        let summary = audit_handle.summary().expect("audit summary missing");
        assert!(summary.as_str().contains("candidate_toml=<redacted>"));
        assert!(summary.as_str().contains("candidate_toml_bytes="));
        assert!(!summary.as_str().contains("secret"));
    }

    #[tokio::test]
    async fn diff_runtime_config_audit_summary_redacts_tcp_ao_key() {
        let (tx, mut rx) = mpsc::channel(1);
        let svc = ConfigService::new(tx);
        tokio::spawn(async move {
            let Some(PeerManagerCommand::DiffRuntimeConfig { reply, .. }) = rx.recv().await else {
                panic!("expected DiffRuntimeConfig command");
            };
            let _ = reply.send(Ok(RuntimeConfigDiff {
                has_actionable_changes: false,
                has_reload_applied_changes: false,
                has_restart_required_changes: false,
                has_informational_changes: false,
                has_any_changes: false,
                human_text: String::new(),
                diff_json: "{}".to_string(),
            }));
        });

        let audit_handle = GrpcAuditHandle::default();
        let mut request = Request::new(proto::DiffRuntimeConfigRequest {
            candidate_toml: r#"
[[neighbors]]
address = "192.0.2.1"
tcp_ao = { key = "ao-secret", algorithm = "hmac-sha-1-96" }
"#
            .to_string(),
        });
        request.extensions_mut().insert(audit_handle.clone());

        svc.diff_runtime_config(request).await.unwrap();

        let summary = audit_handle.summary().expect("audit summary missing");
        assert!(summary.as_str().contains("candidate_toml=<redacted>"));
        assert!(!summary.as_str().contains("ao-secret"));
        assert!(!summary.as_str().contains("hmac-sha"));
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
