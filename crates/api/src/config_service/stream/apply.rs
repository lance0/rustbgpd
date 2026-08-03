//! Bounded streamed ingress for config transaction apply.

use std::sync::Arc;

use sha2::{Digest as _, Sha256};
use tokio::io::{AsyncReadExt as _, AsyncSeekExt as _, AsyncWriteExt as _};
use tokio::sync::{OwnedSemaphorePermit, oneshot};
use tokio::time::{Instant, timeout_at};
use tonic::{Request, Response, Status};

use super::{FRAME_VERSION, StreamPlanState};
use crate::audit::{GrpcAuditHandle, stream_apply_config_transaction_summary};
use crate::proto;
use crate::server::{ConfigTransactionApplyFn, validate_config_transaction_apply_metadata};

struct ApplyAudit {
    handle: Option<GrpcAuditHandle>,
    version: u32,
    chunk_count: u64,
    candidate_bytes: u64,
    expected_token_present: bool,
    confirm_id_present: bool,
    outcome: &'static str,
}

impl ApplyAudit {
    fn new(handle: Option<GrpcAuditHandle>) -> Self {
        let audit = Self {
            handle,
            version: 0,
            chunk_count: 0,
            candidate_bytes: 0,
            expected_token_present: false,
            confirm_id_present: false,
            outcome: "admitted",
        };
        audit.publish();
        audit
    }

    fn publish(&self) {
        if let Some(handle) = &self.handle {
            handle.set_summary(stream_apply_config_transaction_summary(
                self.version,
                self.chunk_count,
                self.candidate_bytes,
                self.expected_token_present,
                self.confirm_id_present,
                self.outcome,
            ));
        }
    }
}

impl Drop for ApplyAudit {
    fn drop(&mut self) {
        if matches!(self.outcome, "admitted" | "receiving" | "handed_off") {
            self.outcome = "failed";
        }
        self.publish();
    }
}

pub(crate) async fn stream_apply_config_transaction(
    state: Option<&Arc<StreamPlanState>>,
    authenticated_transport: bool,
    transaction_apply: Option<ConfigTransactionApplyFn>,
    request: Request<tonic::Streaming<proto::StreamApplyConfigTransactionRequest>>,
) -> Result<Response<proto::ConfigTransactionApplyResponse>, Status> {
    let mut audit = ApplyAudit::new(request.extensions().get::<GrpcAuditHandle>().cloned());
    if !authenticated_transport {
        audit.outcome = "unauthenticated_transport";
        return Err(Status::unauthenticated(
            "streamed config apply requires an authenticated listener",
        ));
    }
    let Some(state) = state.cloned() else {
        audit.outcome = "storage_unavailable";
        return Err(Status::failed_precondition(
            "streamed config apply storage is unavailable",
        ));
    };
    let Some(transaction_apply) = transaction_apply else {
        audit.outcome = "executor_unavailable";
        return Err(Status::failed_precondition(
            "ConfigService.StreamApplyConfigTransaction executor is unavailable",
        ));
    };
    let permit = state.try_admit()?;
    let deadline = Instant::now() + state.limits.total_timeout;
    let mut stream = request.into_inner();
    let metadata = receive_metadata(&mut stream, deadline, state.limits.idle_timeout).await?;
    let mut apply_request = metadata.request;
    audit.version = FRAME_VERSION;
    audit.expected_token_present = !apply_request.expected_runtime_snapshot_token.is_empty();
    audit.confirm_id_present = !apply_request.confirm_id.is_empty();
    audit.outcome = "receiving";
    audit.publish();
    let candidate = receive_candidate(&state, &mut stream, deadline, &mut audit).await?;
    apply_request.candidate_toml = candidate.candidate_toml;
    if Instant::now() >= deadline {
        return Err(Status::deadline_exceeded(
            "streamed config apply exceeded total deadline",
        ));
    }

    state.consume_token(
        &metadata.plan_token,
        &apply_request.expected_runtime_snapshot_token,
        &candidate.sha256,
        candidate.length,
    )?;
    audit.outcome = "handed_off";
    audit.publish();
    let (response_tx, response_rx) = oneshot::channel();
    tokio::spawn(run_detached_apply(
        transaction_apply,
        apply_request,
        permit,
        audit,
        response_tx,
    ));
    timeout_at(deadline, response_rx)
        .await
        .map_err(|_| {
            Status::deadline_exceeded(
                "streamed config apply response exceeded total deadline; apply continues to settlement",
            )
        })?
        .map_err(|_| Status::internal("streamed config apply task did not complete"))?
        .map(Response::new)
}

struct ApplyMetadata {
    plan_token: String,
    request: proto::ApplyConfigTransactionRequest,
}

struct ReceivedCandidate {
    candidate_toml: String,
    sha256: [u8; 32],
    length: u64,
}

async fn receive_metadata(
    stream: &mut tonic::Streaming<proto::StreamApplyConfigTransactionRequest>,
    deadline: Instant,
    idle_timeout: std::time::Duration,
) -> Result<ApplyMetadata, Status> {
    let first = next_frame(stream, deadline, idle_timeout)
        .await?
        .ok_or_else(|| Status::invalid_argument("metadata frame is required first"))?;
    let Some(proto::stream_apply_config_transaction_request::Frame::Metadata(metadata)) =
        first.frame
    else {
        return Err(Status::invalid_argument("metadata frame is required first"));
    };
    if metadata.version != FRAME_VERSION {
        return Err(Status::invalid_argument(
            "unsupported stream framing version",
        ));
    }
    if metadata.plan_token.is_empty() {
        return Err(Status::invalid_argument("plan_token is required"));
    }
    let request = proto::ApplyConfigTransactionRequest {
        candidate_toml: String::new(),
        expected_runtime_snapshot_token: metadata.expected_runtime_snapshot_token,
        client_request_id: metadata.client_request_id,
        comment: metadata.comment,
        confirm_id: metadata.confirm_id,
        confirm_timeout_seconds: metadata.confirm_timeout_seconds,
    };
    validate_config_transaction_apply_metadata(&request)
        .map_err(crate::server::ConfigTransactionApplyError::into_status)?;
    Ok(ApplyMetadata {
        plan_token: metadata.plan_token,
        request,
    })
}

async fn receive_candidate(
    state: &StreamPlanState,
    stream: &mut tonic::Streaming<proto::StreamApplyConfigTransactionRequest>,
    deadline: Instant,
    audit: &mut ApplyAudit,
) -> Result<ReceivedCandidate, Status> {
    let mut spool = state.create_spool()?;
    let mut digest = Sha256::new();
    let mut length = 0u64;
    let end = loop {
        let frame = next_frame(stream, deadline, state.limits.idle_timeout)
            .await?
            .ok_or_else(|| Status::invalid_argument("end frame is required"))?;
        match frame.frame {
            Some(proto::stream_apply_config_transaction_request::Frame::CandidateChunk(chunk)) => {
                receive_chunk(
                    state,
                    &mut spool,
                    deadline,
                    audit,
                    &mut digest,
                    &mut length,
                    chunk,
                )
                .await?;
            }
            Some(proto::stream_apply_config_transaction_request::Frame::End(end)) => break end,
            Some(proto::stream_apply_config_transaction_request::Frame::Metadata(_)) => {
                return Err(Status::invalid_argument(
                    "metadata frame may appear only once",
                ));
            }
            None => return Err(Status::invalid_argument("stream frame is empty")),
        }
    };
    if next_frame(stream, deadline, state.limits.idle_timeout)
        .await?
        .is_some()
    {
        return Err(Status::invalid_argument(
            "end frame must be followed by EOF",
        ));
    }
    let sha256 = verify_end(end, length, digest)?;
    let candidate_toml = read_candidate(&mut spool, length, &sha256, deadline).await?;
    drop(spool);
    Ok(ReceivedCandidate {
        candidate_toml,
        sha256,
        length,
    })
}

async fn receive_chunk(
    state: &StreamPlanState,
    spool: &mut super::Spool,
    deadline: Instant,
    audit: &mut ApplyAudit,
    digest: &mut Sha256,
    length: &mut u64,
    chunk: Vec<u8>,
) -> Result<(), Status> {
    if chunk.is_empty() {
        return Err(Status::invalid_argument(
            "candidate chunks must be non-empty",
        ));
    }
    if chunk.len() > state.limits.max_chunk_bytes {
        return Err(Status::resource_exhausted("candidate chunk exceeds limit"));
    }
    let chunk_len = u64::try_from(chunk.len())
        .map_err(|_| Status::resource_exhausted("candidate exceeds limit"))?;
    *length = length
        .checked_add(chunk_len)
        .filter(|value| *value <= state.limits.max_candidate_bytes)
        .ok_or_else(|| Status::resource_exhausted("candidate exceeds limit"))?;
    timeout_at(deadline, spool.file.write_all(&chunk))
        .await
        .map_err(|_| Status::deadline_exceeded("streamed config apply exceeded total deadline"))?
        .map_err(|_| Status::internal("failed to spool streamed config"))?;
    digest.update(&chunk);
    audit.chunk_count = audit.chunk_count.saturating_add(1);
    audit.candidate_bytes = *length;
    Ok(())
}

fn verify_end(
    end: proto::StreamPlanConfigEnd,
    length: u64,
    digest: Sha256,
) -> Result<[u8; 32], Status> {
    if end.candidate_length != length {
        return Err(Status::invalid_argument(
            "candidate length does not match end frame",
        ));
    }
    let sha256: [u8; 32] = end
        .candidate_sha256
        .try_into()
        .map_err(|_| Status::invalid_argument("candidate SHA-256 must be exactly 32 bytes"))?;
    if digest.finalize().as_slice() != sha256 {
        return Err(Status::invalid_argument("candidate SHA-256 does not match"));
    }
    Ok(sha256)
}

async fn read_candidate(
    spool: &mut super::Spool,
    length: u64,
    sha256: &[u8; 32],
    deadline: Instant,
) -> Result<String, Status> {
    let capacity = usize::try_from(length)
        .map_err(|_| Status::resource_exhausted("candidate exceeds platform capacity"))?;
    let mut candidate = Vec::new();
    candidate
        .try_reserve_exact(capacity.saturating_add(1))
        .map_err(|_| Status::resource_exhausted("candidate allocation failed"))?;
    timeout_at(deadline, async {
        spool.file.rewind().await?;
        let mut bounded = (&mut spool.file).take(length.saturating_add(1));
        bounded.read_to_end(&mut candidate).await
    })
    .await
    .map_err(|_| Status::deadline_exceeded("streamed config apply exceeded total deadline"))?
    .map_err(|_| Status::internal("failed to read streamed config"))?;
    if candidate.len() != capacity || Sha256::digest(&candidate).as_slice() != sha256 {
        return Err(Status::internal(
            "streamed config changed after framing validation",
        ));
    }
    String::from_utf8(candidate)
        .map_err(|_| Status::invalid_argument("candidate config is not valid UTF-8"))
}

async fn run_detached_apply(
    transaction_apply: ConfigTransactionApplyFn,
    request: proto::ApplyConfigTransactionRequest,
    _permit: OwnedSemaphorePermit,
    mut audit: ApplyAudit,
    response_tx: oneshot::Sender<Result<proto::ConfigTransactionApplyResponse, Status>>,
) {
    let response = transaction_apply(request)
        .await
        .map_err(crate::server::ConfigTransactionApplyError::into_status);
    audit.outcome = if response.is_ok() {
        "applied"
    } else {
        "failed"
    };
    audit.publish();
    let _ = response_tx.send(response);
}

async fn next_frame(
    stream: &mut tonic::Streaming<proto::StreamApplyConfigTransactionRequest>,
    total_deadline: Instant,
    idle_timeout: std::time::Duration,
) -> Result<Option<proto::StreamApplyConfigTransactionRequest>, Status> {
    let deadline = (Instant::now() + idle_timeout).min(total_deadline);
    timeout_at(deadline, stream.message()).await.map_err(|_| {
        if Instant::now() >= total_deadline {
            Status::deadline_exceeded("streamed config apply exceeded total deadline")
        } else {
            Status::deadline_exceeded("streamed config apply exceeded idle deadline")
        }
    })?
}
