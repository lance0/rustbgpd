//! Bounded client-streaming ingress for config transaction planning.

pub(super) mod apply;

use std::collections::VecDeque;
use std::fs::File;
use std::io;
use std::os::unix::fs::MetadataExt as _;
#[cfg(test)]
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use nix::errno::Errno;
use nix::fcntl::{OFlag, openat};
use nix::sys::stat::{Mode, mkdirat};
use nix::unistd::{UnlinkatFlags, geteuid, unlinkat};
use sha2::{Digest as _, Sha256};
use tokio::io::{AsyncReadExt as _, AsyncSeekExt as _, AsyncWriteExt as _};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc, oneshot};
use tokio::time::{Instant, timeout_at};
use tonic::{Request, Response, Status};
use uuid::Uuid;

use super::{plan_error_to_status, transaction_plan_to_proto};
use crate::audit::{GrpcAuditHandle, stream_plan_config_transaction_summary};
use crate::peer_types::{PeerManagerCommand, RuntimeConfigTransactionStatus};
use crate::proto;

const SPOOL_DIRECTORY: &str = "stream-plan-v1";
const SPOOL_PREFIX: &str = ".candidate-";
const FRAME_VERSION: u32 = 1;
const MAX_CHUNK_BYTES: usize = 1024 * 1024;
const MAX_CANDIDATE_BYTES: u64 = 384 * 1024 * 1024;
const IDLE_TIMEOUT: Duration = Duration::from_mins(1);
const TOTAL_TIMEOUT: Duration = Duration::from_mins(30);
const MAX_LIVE_PLAN_TOKENS: usize = 256;
const PLAN_TOKEN_TTL: Duration = Duration::from_mins(30);

#[derive(Clone, Copy)]
struct StreamLimits {
    max_chunk_bytes: usize,
    max_candidate_bytes: u64,
    idle_timeout: Duration,
    total_timeout: Duration,
}

impl Default for StreamLimits {
    fn default() -> Self {
        Self {
            max_chunk_bytes: MAX_CHUNK_BYTES,
            max_candidate_bytes: MAX_CANDIDATE_BYTES,
            idle_timeout: IDLE_TIMEOUT,
            total_timeout: TOTAL_TIMEOUT,
        }
    }
}

/// Process-wide state shared by every configured listener.
pub(crate) struct StreamPlanState {
    directory: Arc<File>,
    admission: Arc<Semaphore>,
    tokens: Mutex<VecDeque<PlanTokenBinding>>,
    limits: StreamLimits,
    #[cfg(test)]
    corrupt_before_read: AtomicBool,
}

struct PlanTokenBinding {
    token: Uuid,
    runtime_snapshot_token: String,
    candidate_sha256: [u8; 32],
    candidate_length: u64,
    expires_at: Instant,
}

impl StreamPlanState {
    /// Prepare the private descriptor-relative child beneath the already
    /// owner-verified runtime-state directory.
    pub(crate) fn prepare(runtime_state_directory: &File) -> Result<Arc<Self>, String> {
        Self::prepare_with_limits(runtime_state_directory, StreamLimits::default())
    }

    fn prepare_with_limits(
        runtime_state_directory: &File,
        limits: StreamLimits,
    ) -> Result<Arc<Self>, String> {
        match mkdirat(
            runtime_state_directory,
            SPOOL_DIRECTORY,
            Mode::from_bits_truncate(0o700),
        ) {
            Ok(()) | Err(Errno::EEXIST) => {}
            Err(error) => return Err(io_error(error).to_string()),
        }
        let fd = openat(
            runtime_state_directory,
            SPOOL_DIRECTORY,
            OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|error| io_error(error).to_string())?;
        let directory = File::from(fd);
        let metadata = directory.metadata().map_err(|error| error.to_string())?;
        if !metadata.is_dir()
            || metadata.uid() != geteuid().as_raw()
            || metadata.mode() & 0o777 != 0o700
        {
            return Err("stream-plan directory has unsafe type, owner, or mode".to_string());
        }
        Ok(Arc::new(Self {
            directory: Arc::new(directory),
            admission: Arc::new(Semaphore::new(1)),
            tokens: Mutex::new(VecDeque::new()),
            limits,
            #[cfg(test)]
            corrupt_before_read: AtomicBool::new(false),
        }))
    }

    fn try_admit(&self) -> Result<OwnedSemaphorePermit, Status> {
        Arc::clone(&self.admission)
            .try_acquire_owned()
            .map_err(|_| Status::resource_exhausted("another streamed config plan is active"))
    }

    fn issue_token(
        &self,
        runtime_snapshot_token: String,
        candidate_sha256: [u8; 32],
        candidate_length: u64,
    ) -> Result<Uuid, Status> {
        let now = Instant::now();
        let mut tokens = self
            .tokens
            .lock()
            .map_err(|_| Status::internal("streamed config plan-token state is unavailable"))?;
        tokens.retain(|binding| binding.expires_at > now);
        while tokens.len() >= MAX_LIVE_PLAN_TOKENS {
            tokens.pop_front();
        }
        let token = Uuid::new_v4();
        tokens.push_back(PlanTokenBinding {
            token,
            runtime_snapshot_token,
            candidate_sha256,
            candidate_length,
            expires_at: now + PLAN_TOKEN_TTL,
        });
        Ok(token)
    }

    fn revoke_token(&self, token: Uuid) {
        if let Ok(mut tokens) = self.tokens.lock() {
            tokens.retain(|binding| binding.token != token);
        }
    }

    fn consume_token(
        &self,
        token: &str,
        runtime_snapshot_token: &str,
        candidate_sha256: &[u8; 32],
        candidate_length: u64,
    ) -> Result<(), Status> {
        let token = Uuid::parse_str(token)
            .map_err(|_| Status::invalid_argument("plan_token is malformed"))?;
        let now = Instant::now();
        let mut tokens = self
            .tokens
            .lock()
            .map_err(|_| Status::internal("streamed config plan-token state is unavailable"))?;
        let Some(index) = tokens.iter().position(|binding| binding.token == token) else {
            return Err(Status::failed_precondition(
                "plan_token is unknown, expired, or evicted; plan again",
            ));
        };
        if tokens[index].expires_at <= now {
            tokens.remove(index);
            return Err(Status::failed_precondition(
                "plan_token is unknown, expired, or evicted; plan again",
            ));
        }
        let binding = &tokens[index];
        if binding.runtime_snapshot_token != runtime_snapshot_token
            || &binding.candidate_sha256 != candidate_sha256
            || binding.candidate_length != candidate_length
        {
            return Err(Status::failed_precondition(
                "plan_token does not match the runtime snapshot or candidate bytes",
            ));
        }
        tokens.remove(index);
        Ok(())
    }

    fn create_spool(&self) -> Result<Spool, Status> {
        for _ in 0..8 {
            let name = format!("{SPOOL_PREFIX}{}", Uuid::new_v4().simple());
            match openat(
                self.directory.as_ref(),
                name.as_str(),
                OFlag::O_RDWR
                    | OFlag::O_CREAT
                    | OFlag::O_EXCL
                    | OFlag::O_CLOEXEC
                    | OFlag::O_NOFOLLOW,
                Mode::from_bits_truncate(0o600),
            ) {
                Ok(fd) => {
                    let file = File::from(fd);
                    unlinkat(
                        self.directory.as_ref(),
                        name.as_str(),
                        UnlinkatFlags::NoRemoveDir,
                    )
                    .map_err(|_| Status::internal("failed to anonymize streamed config storage"))?;
                    let metadata = file.metadata().map_err(|_| {
                        Status::internal("failed to validate streamed config storage")
                    })?;
                    if !metadata.is_file()
                        || metadata.uid() != geteuid().as_raw()
                        || metadata.mode() & 0o777 != 0o600
                    {
                        return Err(Status::internal(
                            "streamed config storage has unsafe type, owner, or mode",
                        ));
                    }
                    return Ok(Spool {
                        file: tokio::fs::File::from_std(file),
                    });
                }
                Err(Errno::EEXIST) => {}
                Err(_) => {
                    return Err(Status::internal("failed to create streamed config storage"));
                }
            }
        }
        Err(Status::internal(
            "failed to allocate unique streamed config storage",
        ))
    }
}

struct Spool {
    file: tokio::fs::File,
}

struct StreamAudit {
    handle: Option<GrpcAuditHandle>,
    version: u32,
    chunk_count: u64,
    candidate_bytes: u64,
    expected_token_present: bool,
    outcome: &'static str,
}

impl StreamAudit {
    fn new(handle: Option<GrpcAuditHandle>) -> Self {
        let audit = Self {
            handle,
            version: 0,
            chunk_count: 0,
            candidate_bytes: 0,
            expected_token_present: false,
            outcome: "admitted",
        };
        audit.publish();
        audit
    }

    fn publish(&self) {
        if let Some(handle) = &self.handle {
            handle.set_summary(stream_plan_config_transaction_summary(
                self.version,
                self.chunk_count,
                self.candidate_bytes,
                self.expected_token_present,
                self.outcome,
            ));
        }
    }
}

impl Drop for StreamAudit {
    fn drop(&mut self) {
        if matches!(self.outcome, "admitted" | "receiving") {
            self.outcome = "failed";
        }
        self.publish();
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "the framing state machine and handoff boundary are reviewed together"
)]
pub(super) async fn stream_plan_config_transaction(
    state: Option<&Arc<StreamPlanState>>,
    authenticated_transport: bool,
    peer_mgr_tx: mpsc::Sender<PeerManagerCommand>,
    request: Request<tonic::Streaming<proto::StreamPlanConfigTransactionRequest>>,
) -> Result<Response<proto::StreamPlanConfigTransactionResponse>, Status> {
    let audit_handle = request.extensions().get::<GrpcAuditHandle>().cloned();
    let mut audit = StreamAudit::new(audit_handle);
    if !authenticated_transport {
        audit.outcome = "unauthenticated_transport";
        return Err(Status::unauthenticated(
            "streamed config planning requires an authenticated listener",
        ));
    }
    let Some(state) = state.cloned() else {
        audit.outcome = "storage_unavailable";
        return Err(Status::failed_precondition(
            "streamed config planning storage is unavailable",
        ));
    };
    let permit = state.try_admit()?;
    let deadline = Instant::now() + state.limits.total_timeout;
    let mut stream = request.into_inner();

    let first = next_frame(&mut stream, deadline, state.limits.idle_timeout)
        .await?
        .ok_or_else(|| Status::invalid_argument("metadata frame is required first"))?;
    let Some(proto::stream_plan_config_transaction_request::Frame::Metadata(metadata)) =
        first.frame
    else {
        return Err(Status::invalid_argument("metadata frame is required first"));
    };
    if metadata.version != FRAME_VERSION {
        return Err(Status::invalid_argument(
            "unsupported stream framing version",
        ));
    }
    audit.version = metadata.version;
    audit.expected_token_present = metadata
        .expected_runtime_snapshot_token
        .as_ref()
        .is_some_and(|token| !token.is_empty());
    audit.outcome = "receiving";
    audit.publish();

    let mut spool = state.create_spool()?;
    let mut digest = Sha256::new();
    let mut length = 0u64;
    let end = loop {
        let frame = next_frame(&mut stream, deadline, state.limits.idle_timeout)
            .await?
            .ok_or_else(|| Status::invalid_argument("end frame is required"))?;
        match frame.frame {
            Some(proto::stream_plan_config_transaction_request::Frame::CandidateChunk(chunk)) => {
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
                length = length
                    .checked_add(chunk_len)
                    .filter(|length| *length <= state.limits.max_candidate_bytes)
                    .ok_or_else(|| Status::resource_exhausted("candidate exceeds limit"))?;
                timeout_at(deadline, spool.file.write_all(&chunk))
                    .await
                    .map_err(|_| {
                        Status::deadline_exceeded("streamed config plan exceeded total deadline")
                    })?
                    .map_err(|_| Status::internal("failed to spool streamed config"))?;
                digest.update(&chunk);
                audit.chunk_count = audit.chunk_count.saturating_add(1);
                audit.candidate_bytes = length;
            }
            Some(proto::stream_plan_config_transaction_request::Frame::End(end)) => break end,
            Some(proto::stream_plan_config_transaction_request::Frame::Metadata(_)) => {
                return Err(Status::invalid_argument(
                    "metadata frame may appear only once",
                ));
            }
            None => return Err(Status::invalid_argument("stream frame is empty")),
        }
    };
    if next_frame(&mut stream, deadline, state.limits.idle_timeout)
        .await?
        .is_some()
    {
        return Err(Status::invalid_argument(
            "end frame must be followed by EOF",
        ));
    }
    if end.candidate_length != length {
        return Err(Status::invalid_argument(
            "candidate length does not match end frame",
        ));
    }
    let candidate_sha256: [u8; 32] = end
        .candidate_sha256
        .try_into()
        .map_err(|_| Status::invalid_argument("candidate SHA-256 must be exactly 32 bytes"))?;
    if digest.finalize().as_slice() != candidate_sha256 {
        return Err(Status::invalid_argument("candidate SHA-256 does not match"));
    }

    if Instant::now() >= deadline {
        return Err(Status::deadline_exceeded(
            "streamed config plan exceeded total deadline",
        ));
    }
    #[cfg(test)]
    if state.corrupt_before_read.swap(false, Ordering::SeqCst) {
        timeout_at(deadline, async {
            spool.file.rewind().await?;
            spool.file.write_all(b"!").await
        })
        .await
        .map_err(|_| Status::deadline_exceeded("streamed config plan exceeded total deadline"))?
        .map_err(|_| Status::internal("failed to inject streamed config test corruption"))?;
    }
    let capacity = usize::try_from(length)
        .map_err(|_| Status::resource_exhausted("candidate exceeds platform capacity"))?;
    let read_capacity = capacity
        .checked_add(1)
        .ok_or_else(|| Status::resource_exhausted("candidate exceeds platform capacity"))?;
    let mut candidate = Vec::new();
    candidate
        .try_reserve_exact(read_capacity)
        .map_err(|_| Status::resource_exhausted("candidate allocation failed"))?;
    timeout_at(deadline, async {
        spool.file.rewind().await?;
        let mut bounded = (&mut spool.file).take(length.saturating_add(1));
        bounded.read_to_end(&mut candidate).await
    })
    .await
    .map_err(|_| Status::deadline_exceeded("streamed config plan exceeded total deadline"))?
    .map_err(|_| Status::internal("failed to read streamed config"))?;
    if candidate.len() != capacity {
        return Err(Status::internal(
            "streamed config length changed during validation",
        ));
    }
    if Sha256::digest(&candidate).as_slice() != candidate_sha256 {
        return Err(Status::internal(
            "streamed config changed after framing validation",
        ));
    }
    let candidate_toml = String::from_utf8(candidate)
        .map_err(|_| Status::invalid_argument("candidate config is not valid UTF-8"))?;
    drop(spool);
    if Instant::now() >= deadline {
        return Err(Status::deadline_exceeded(
            "streamed config plan exceeded total deadline",
        ));
    }

    audit.outcome = "handed_off";
    audit.publish();
    let (response_tx, response_rx) = oneshot::channel();
    tokio::spawn(run_detached_plan(
        state,
        peer_mgr_tx,
        candidate_toml,
        metadata.expected_runtime_snapshot_token,
        candidate_sha256,
        length,
        deadline,
        permit,
        audit,
        response_tx,
    ));
    response_rx
        .await
        .map_err(|_| Status::internal("streamed config planner task did not complete"))?
        .map(Response::new)
}

#[expect(
    clippy::too_many_arguments,
    reason = "detached ownership boundary is explicit"
)]
async fn run_detached_plan(
    state: Arc<StreamPlanState>,
    peer_mgr_tx: mpsc::Sender<PeerManagerCommand>,
    candidate_toml: String,
    expected_runtime_snapshot_token: Option<String>,
    candidate_sha256: [u8; 32],
    candidate_length: u64,
    deadline: Instant,
    _permit: OwnedSemaphorePermit,
    mut audit: StreamAudit,
    response_tx: oneshot::Sender<Result<proto::StreamPlanConfigTransactionResponse, Status>>,
) {
    let result = timeout_at(deadline, async {
        let expected_runtime_snapshot_token =
            expected_runtime_snapshot_token.filter(|s| !s.is_empty());
        let (reply, receive) = oneshot::channel();
        peer_mgr_tx
            .send(PeerManagerCommand::PlanConfigTransaction {
                candidate_toml,
                expected_runtime_snapshot_token,
                reply,
            })
            .await
            .map_err(|_| Status::unavailable("peer manager is unavailable"))?;
        receive
            .await
            .map_err(|_| Status::unavailable("peer manager dropped config transaction plan reply"))?
            .map_err(plan_error_to_status)
    })
    .await
    .map_err(|_| Status::deadline_exceeded("streamed config plan exceeded total deadline"))
    .and_then(|result| result);

    let mut issued_token = None;
    let response = result.and_then(|plan| {
        let plan_token = if plan.status == RuntimeConfigTransactionStatus::Committable {
            let token = state.issue_token(
                plan.runtime_snapshot_token.clone(),
                candidate_sha256,
                candidate_length,
            )?;
            issued_token = Some(token);
            Some(token.to_string())
        } else {
            None
        };
        Ok(proto::StreamPlanConfigTransactionResponse {
            plan: Some(transaction_plan_to_proto(plan)),
            plan_token,
        })
    });
    audit.outcome = if response.is_ok() {
        "planned"
    } else {
        "failed"
    };
    audit.publish();
    if response_tx.send(response).is_err()
        && let Some(token) = issued_token
    {
        state.revoke_token(token);
    }
}

async fn next_frame(
    stream: &mut tonic::Streaming<proto::StreamPlanConfigTransactionRequest>,
    total_deadline: Instant,
    idle_timeout: Duration,
) -> Result<Option<proto::StreamPlanConfigTransactionRequest>, Status> {
    let deadline = (Instant::now() + idle_timeout).min(total_deadline);
    timeout_at(deadline, stream.message()).await.map_err(|_| {
        if Instant::now() >= total_deadline {
            Status::deadline_exceeded("streamed config plan exceeded total deadline")
        } else {
            Status::deadline_exceeded("streamed config plan exceeded idle deadline")
        }
    })?
}

fn io_error(error: Errno) -> io::Error {
    io::Error::from_raw_os_error(error as i32)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::path::Path;
    use std::sync::atomic::AtomicUsize;

    use sha2::{Digest as _, Sha256};
    use tempfile::TempDir;
    use tokio::net::TcpListener;
    use tokio_stream::wrappers::{ReceiverStream, TcpListenerStream};
    use tonic::Code::{InvalidArgument as Invalid, ResourceExhausted as Exhausted};
    use tonic::metadata::MetadataValue;
    use tonic::service::Interceptor;
    use tonic::service::interceptor::InterceptedService;
    use tonic::transport::{Channel, Endpoint, Server};

    use super::*;
    use crate::authz::{AuthTier, PrincipalRole};
    use crate::authz_runtime::{GrpcAuthAuditContext, GrpcAuthnKind, GrpcAuthzLayer};
    use crate::config_service::ConfigService;
    use crate::proto::config_service_client::ConfigServiceClient;
    use crate::proto::config_service_server::ConfigServiceServer;
    use crate::server::{AuthInterceptor, ConfigTransactionApplyFn};
    use rustbgpd_telemetry::BgpMetrics;

    type AuthClient = ConfigServiceClient<InterceptedService<Channel, ClientAuth>>;
    type HookReply = oneshot::Sender<
        Result<proto::ConfigTransactionApplyResponse, crate::server::ConfigTransactionApplyError>,
    >;

    #[derive(Clone)]
    struct ClientAuth;

    impl Interceptor for ClientAuth {
        fn call(&mut self, mut request: Request<()>) -> Result<Request<()>, Status> {
            request.metadata_mut().insert(
                "authorization",
                MetadataValue::from_static("Bearer stream-secret"),
            );
            Ok(request)
        }
    }

    struct ListenerHandle {
        client: AuthClient,
        unauthenticated: ConfigServiceClient<Channel>,
        audit_observer: Arc<Mutex<Option<GrpcAuditHandle>>>,
        shutdown: Option<oneshot::Sender<()>>,
        task: tokio::task::JoinHandle<()>,
    }

    impl Drop for ListenerHandle {
        fn drop(&mut self) {
            if let Some(shutdown) = self.shutdown.take() {
                let _ = shutdown.send(());
            }
            self.task.abort();
        }
    }

    fn limits(max_chunk: usize, max_candidate: u64) -> StreamLimits {
        StreamLimits {
            max_chunk_bytes: max_chunk,
            max_candidate_bytes: max_candidate,
            idle_timeout: Duration::from_mins(1),
            total_timeout: Duration::from_mins(30),
        }
    }

    fn state_at(path: &Path, limits: StreamLimits) -> Arc<StreamPlanState> {
        let directory = File::open(path).expect("open pinned runtime-state directory");
        StreamPlanState::prepare_with_limits(&directory, limits).expect("prepare stream state")
    }

    fn consume_error_code(result: Result<(), Status>) -> tonic::Code {
        result.unwrap_err().code()
    }

    async fn spawn_listener(
        state: Arc<StreamPlanState>,
        peer_mgr_tx: mpsc::Sender<PeerManagerCommand>,
        authenticated_transport: bool,
    ) -> ListenerHandle {
        spawn_listener_with_apply(
            state,
            peer_mgr_tx,
            authenticated_transport,
            None,
            AuthTier::SensitiveRead,
            PrincipalRole::Observer,
        )
        .await
    }

    async fn spawn_listener_with_apply(
        state: Arc<StreamPlanState>,
        peer_mgr_tx: mpsc::Sender<PeerManagerCommand>,
        authenticated_transport: bool,
        transaction_apply: Option<ConfigTransactionApplyFn>,
        max_tier: AuthTier,
        role: PrincipalRole,
    ) -> ListenerHandle {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let roles = Arc::new(BTreeMap::from([("stream-test".to_string(), role)]));
        let context = GrpcAuthAuditContext::new(
            format!("tcp://{addr}"),
            "read_write",
            max_tier,
            GrpcAuthnKind::BearerToken,
            "stream-test",
        )
        .with_roles(roles)
        .with_bearer_token(Some("stream-secret"));
        let service = ConfigService::new(peer_mgr_tx)
            .with_transaction_hooks(transaction_apply, None, None, None, None, None)
            .with_stream_plan(Some(state), authenticated_transport);
        let audit_observer = Arc::new(Mutex::new(None));
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let server_audit_observer = Arc::clone(&audit_observer);
        let task = tokio::spawn(async move {
            Server::builder()
                .layer(GrpcAuthzLayer::new(context, BgpMetrics::new()))
                .add_service(ConfigServiceServer::with_interceptor(
                    service,
                    AuthInterceptor::from_token(Some("stream-secret"))
                        .with_audit_observer(server_audit_observer),
                ))
                .serve_with_incoming_shutdown(TcpListenerStream::new(listener), async {
                    let _ = shutdown_rx.await;
                })
                .await
                .unwrap();
        });
        let channel = Endpoint::from_shared(format!("http://{addr}"))
            .unwrap()
            .connect()
            .await
            .unwrap();
        ListenerHandle {
            client: ConfigServiceClient::with_interceptor(channel.clone(), ClientAuth),
            unauthenticated: ConfigServiceClient::new(channel),
            audit_observer,
            shutdown: Some(shutdown_tx),
            task,
        }
    }

    fn metadata(token: Option<&str>) -> proto::StreamPlanConfigTransactionRequest {
        metadata_version(FRAME_VERSION, token)
    }

    fn metadata_version(
        version: u32,
        token: Option<&str>,
    ) -> proto::StreamPlanConfigTransactionRequest {
        proto::StreamPlanConfigTransactionRequest {
            frame: Some(
                proto::stream_plan_config_transaction_request::Frame::Metadata(
                    proto::StreamPlanConfigMetadata {
                        version,
                        expected_runtime_snapshot_token: token.map(str::to_string),
                    },
                ),
            ),
        }
    }

    fn chunk(bytes: Vec<u8>) -> proto::StreamPlanConfigTransactionRequest {
        proto::StreamPlanConfigTransactionRequest {
            frame: Some(
                proto::stream_plan_config_transaction_request::Frame::CandidateChunk(bytes),
            ),
        }
    }

    fn end(bytes: &[u8]) -> proto::StreamPlanConfigTransactionRequest {
        proto::StreamPlanConfigTransactionRequest {
            frame: Some(proto::stream_plan_config_transaction_request::Frame::End(
                proto::StreamPlanConfigEnd {
                    candidate_length: u64::try_from(bytes.len()).unwrap(),
                    candidate_sha256: Sha256::digest(bytes).to_vec(),
                },
            )),
        }
    }

    fn malformed_end(length: u64, digest: Vec<u8>) -> proto::StreamPlanConfigTransactionRequest {
        proto::StreamPlanConfigTransactionRequest {
            frame: Some(proto::stream_plan_config_transaction_request::Frame::End(
                proto::StreamPlanConfigEnd {
                    candidate_length: length,
                    candidate_sha256: digest,
                },
            )),
        }
    }

    fn complete_chunks(chunks: &[&[u8]]) -> Vec<proto::StreamPlanConfigTransactionRequest> {
        let bytes = chunks.concat();
        let mut frames = vec![metadata(None)];
        frames.extend(chunks.iter().map(|bytes| chunk(bytes.to_vec())));
        frames.push(end(&bytes));
        frames
    }

    fn candidate_end(
        bytes: &[u8],
        end: proto::StreamPlanConfigTransactionRequest,
    ) -> Vec<proto::StreamPlanConfigTransactionRequest> {
        vec![metadata(None), chunk(bytes.to_vec()), end]
    }

    fn frames(bytes: &[u8], token: Option<&str>) -> Vec<proto::StreamPlanConfigTransactionRequest> {
        let mut frames = vec![metadata(token)];
        frames.extend(
            bytes
                .chunks(MAX_CHUNK_BYTES)
                .map(|part| chunk(part.to_vec())),
        );
        frames.push(end(bytes));
        frames
    }

    fn apply_frames(
        bytes: &[u8],
        plan_token: &str,
        runtime_token: &str,
    ) -> Vec<proto::StreamApplyConfigTransactionRequest> {
        let mut frames = vec![apply_metadata_frame(plan_token, runtime_token)];
        frames.extend(
            bytes
                .chunks(MAX_CHUNK_BYTES)
                .map(|chunk| apply_chunk_frame(chunk.to_vec())),
        );
        frames.push(apply_end_frame(
            bytes.len() as u64,
            Sha256::digest(bytes).to_vec(),
        ));
        frames
    }

    fn apply_metadata_frame(
        plan_token: &str,
        runtime_token: &str,
    ) -> proto::StreamApplyConfigTransactionRequest {
        proto::StreamApplyConfigTransactionRequest {
            frame: Some(
                proto::stream_apply_config_transaction_request::Frame::Metadata(
                    proto::StreamApplyConfigMetadata {
                        version: FRAME_VERSION,
                        plan_token: plan_token.to_string(),
                        expected_runtime_snapshot_token: runtime_token.to_string(),
                        client_request_id: "stream-deploy".to_string(),
                        comment: "streamed apply".to_string(),
                        confirm_id: "stream-confirm".to_string(),
                        confirm_timeout_seconds: 120,
                    },
                ),
            ),
        }
    }

    fn apply_chunk_frame(bytes: Vec<u8>) -> proto::StreamApplyConfigTransactionRequest {
        proto::StreamApplyConfigTransactionRequest {
            frame: Some(
                proto::stream_apply_config_transaction_request::Frame::CandidateChunk(bytes),
            ),
        }
    }

    fn apply_end_frame(
        candidate_length: u64,
        candidate_sha256: Vec<u8>,
    ) -> proto::StreamApplyConfigTransactionRequest {
        proto::StreamApplyConfigTransactionRequest {
            frame: Some(proto::stream_apply_config_transaction_request::Frame::End(
                proto::StreamPlanConfigEnd {
                    candidate_length,
                    candidate_sha256,
                },
            )),
        }
    }

    fn sample_plan(
        status: RuntimeConfigTransactionStatus,
    ) -> crate::peer_types::RuntimeConfigTransactionPlan {
        crate::peer_types::RuntimeConfigTransactionPlan {
            status,
            runtime_snapshot_token: "kv1:runtime:7".to_string(),
            post_commit_runtime_snapshot_token: "kv1:runtime:8".to_string(),
            diff: crate::peer_types::RuntimeConfigDiff {
                has_actionable_changes: true,
                has_reload_applied_changes: true,
                has_restart_required_changes: false,
                has_informational_changes: false,
                has_any_changes: true,
                human_text: "candidate differs\n".to_string(),
                diff_json: "{}".to_string(),
            },
            supported_sections: vec!["[[neighbors]]".to_string()],
            unsupported_sections: Vec::new(),
            restart_required_sections: Vec::new(),
            human_text: "committable\n".to_string(),
            update_group_impact: rustbgpd_rib::UpdateGroupImpactPlan::default(),
        }
    }

    fn spool_is_anonymous(runtime: &Path) -> bool {
        std::fs::read_dir(runtime.join(SPOOL_DIRECTORY))
            .unwrap()
            .next()
            .is_none()
    }

    fn has_token(state: &StreamPlanState, token: Uuid) -> bool {
        state
            .tokens
            .lock()
            .unwrap()
            .iter()
            .any(|row| row.token == token)
    }

    async fn yield_until(mut predicate: impl FnMut() -> bool) {
        for _ in 0..10_000 {
            if predicate() {
                return;
            }
            tokio::task::yield_now().await;
        }
        panic!("condition did not become true");
    }

    #[tokio::test]
    async fn authenticated_real_tcp_hands_off_more_than_eight_mib_byte_identically() {
        let runtime = TempDir::new().unwrap();
        let state = state_at(runtime.path(), StreamLimits::default());
        let (peer_tx, mut peer_rx) = mpsc::channel(1);
        let mut listener = spawn_listener(Arc::clone(&state), peer_tx.clone(), true).await;
        let candidate_marker = b"CANDIDATE_SECRET_830";
        let expected_marker = "EXPECTED_RUNTIME_SECRET_830";
        let mut candidate = vec![b'a'; 8 * 1024 * 1024 + 17];
        candidate[..candidate_marker.len()].copy_from_slice(candidate_marker);

        let unauthenticated = tokio::time::timeout(
            Duration::from_secs(1),
            listener
                .unauthenticated
                .stream_plan_config_transaction(futures::stream::iter(frames(&candidate, None))),
        )
        .await
        .expect("unauthenticated RPC reached the peer manager")
        .unwrap_err();
        assert_eq!(unauthenticated.code(), tonic::Code::Unauthenticated);
        assert!(peer_rx.try_recv().is_err());

        let transport_unauthenticated = spawn_listener(Arc::clone(&state), peer_tx, false).await;
        let mut client = transport_unauthenticated.client.clone();
        let sent = candidate.clone();
        let request = tokio::spawn(async move {
            client
                .stream_plan_config_transaction(futures::stream::iter(frames(&sent, None)))
                .await
        });
        tokio::select! {
            result = request => {
                let unauthenticated = result.unwrap().unwrap_err();
                assert_eq!(unauthenticated.code(), tonic::Code::Unauthenticated);
            }
            command = peer_rx.recv() => {
                assert!(command.is_none(), "unauthenticated transport reached the peer manager");
            }
        }
        assert!(peer_rx.try_recv().is_err());

        let mut client = listener.client.clone();
        let sent = candidate.clone();
        let request = tokio::spawn(async move {
            client
                .stream_plan_config_transaction(futures::stream::iter(frames(
                    &sent,
                    Some(expected_marker),
                )))
                .await
        });
        let PeerManagerCommand::PlanConfigTransaction {
            candidate_toml,
            expected_runtime_snapshot_token,
            reply,
        } = peer_rx.recv().await.unwrap()
        else {
            panic!("unexpected peer-manager command");
        };
        assert_eq!(candidate_toml.as_bytes(), candidate);
        assert_eq!(
            expected_runtime_snapshot_token.as_deref(),
            Some(expected_marker)
        );
        reply
            .send(Ok(sample_plan(RuntimeConfigTransactionStatus::Committable)))
            .unwrap();
        let response = request.await.unwrap().unwrap().into_inner();
        assert_eq!(
            response.plan.as_ref().unwrap().runtime_snapshot_token,
            "kv1:runtime:7"
        );
        let token = Uuid::parse_str(response.plan_token.as_deref().unwrap()).unwrap();
        assert_eq!(token.get_version(), Some(uuid::Version::Random));
        let tokens = state.tokens.lock().unwrap();
        assert_eq!(tokens.len(), 1);
        assert_eq!(tokens[0].token, token);
        assert_eq!(tokens[0].runtime_snapshot_token, "kv1:runtime:7");
        assert_eq!(tokens[0].candidate_sha256, Sha256::digest(&candidate)[..]);
        assert_eq!(tokens[0].candidate_length, candidate.len() as u64);
        drop(tokens);
        let handle = listener.audit_observer.lock().unwrap().clone().unwrap();
        let summary = handle.summary().unwrap();
        assert_eq!(
            summary.as_str(),
            "version=1 chunk_count=9 candidate_bytes=8388625 expected_runtime_snapshot_token_present=true outcome=planned"
        );
        assert!(spool_is_anonymous(runtime.path()));
    }

    fn applied_response() -> proto::ConfigTransactionApplyResponse {
        proto::ConfigTransactionApplyResponse {
            status: proto::ConfigTransactionPlanStatus::Committable.into(),
            runtime_snapshot_token: "kv1:runtime:8".to_string(),
            committed_sections: vec!["[[neighbors]]".to_string()],
            human_text: "committed\n".to_string(),
            confirmation: None,
            update_group_impact: None,
        }
    }

    #[tokio::test]
    async fn authenticated_real_tcp_apply_above_eight_mib_is_exact_and_once_only() {
        let runtime = TempDir::new().unwrap();
        let state = state_at(runtime.path(), StreamLimits::default());
        let (peer_tx, _peer_rx) = mpsc::channel(1);
        let (hook_tx, mut hook_rx) =
            mpsc::channel::<(proto::ApplyConfigTransactionRequest, HookReply)>(2);
        let hook: ConfigTransactionApplyFn = Arc::new(move |request| {
            let hook_tx = hook_tx.clone();
            Box::pin(async move {
                let (reply, receive) = oneshot::channel();
                hook_tx.send((request, reply)).await.unwrap();
                receive.await.unwrap()
            })
        });
        let listener = spawn_listener_with_apply(
            Arc::clone(&state),
            peer_tx,
            true,
            Some(hook),
            AuthTier::OperatorOnly,
            PrincipalRole::Operator,
        )
        .await;
        let marker = b"STREAM_APPLY_CANDIDATE_MARKER";
        let mut candidate = vec![b'z'; 8 * 1024 * 1024 + 31];
        candidate[..marker.len()].copy_from_slice(marker);
        let digest: [u8; 32] = Sha256::digest(&candidate).into();
        let token = state
            .issue_token("kv1:runtime:7".to_string(), digest, candidate.len() as u64)
            .unwrap();
        let mut client = listener.client.clone();
        let sent = candidate.clone();
        let token_text = token.to_string();
        let apply = tokio::spawn(async move {
            client
                .stream_apply_config_transaction(futures::stream::iter(apply_frames(
                    &sent,
                    &token_text,
                    "kv1:runtime:7",
                )))
                .await
        });
        let (request, reply) = hook_rx.recv().await.unwrap();
        assert_eq!(request.candidate_toml.as_bytes(), candidate);
        assert_eq!(request.expected_runtime_snapshot_token, "kv1:runtime:7");
        assert_eq!(request.client_request_id, "stream-deploy");
        assert_eq!(request.comment, "streamed apply");
        assert_eq!(request.confirm_id, "stream-confirm");
        assert_eq!(request.confirm_timeout_seconds, 120);
        reply.send(Ok(applied_response())).unwrap();
        assert_eq!(
            apply
                .await
                .unwrap()
                .unwrap()
                .into_inner()
                .runtime_snapshot_token,
            "kv1:runtime:8"
        );
        assert!(!has_token(&state, token));

        let error = listener
            .client
            .clone()
            .stream_apply_config_transaction(futures::stream::iter(apply_frames(
                &candidate,
                &token.to_string(),
                "kv1:runtime:7",
            )))
            .await
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::FailedPrecondition);
        assert!(hook_rx.try_recv().is_err());
        assert!(spool_is_anonymous(runtime.path()));
    }

    type ApplyFailureCase = (
        Vec<proto::StreamApplyConfigTransactionRequest>,
        tonic::Code,
        &'static str,
    );

    fn apply_initial_failure_cases(candidate: &[u8], token_text: &str) -> Vec<ApplyFailureCase> {
        let mut wrong_version = apply_frames(candidate, token_text, "kv1:runtime:7");
        let Some(proto::stream_apply_config_transaction_request::Frame::Metadata(metadata)) =
            wrong_version[0].frame.as_mut()
        else {
            unreachable!()
        };
        metadata.version = 2;
        let mut duplicate_metadata = apply_frames(candidate, token_text, "kv1:runtime:7");
        duplicate_metadata.insert(1, apply_metadata_frame(token_text, "kv1:runtime:7"));
        vec![
            (
                Vec::new(),
                tonic::Code::InvalidArgument,
                "metadata frame is required first",
            ),
            (
                vec![apply_chunk_frame(b"a".to_vec())],
                tonic::Code::InvalidArgument,
                "metadata frame is required first",
            ),
            (
                wrong_version,
                tonic::Code::InvalidArgument,
                "unsupported stream framing version",
            ),
            (
                vec![
                    apply_metadata_frame(token_text, "kv1:runtime:7"),
                    apply_chunk_frame(Vec::new()),
                ],
                tonic::Code::InvalidArgument,
                "candidate chunks must be non-empty",
            ),
            (
                vec![
                    apply_metadata_frame(token_text, "kv1:runtime:7"),
                    apply_chunk_frame(b"abcde".to_vec()),
                ],
                tonic::Code::ResourceExhausted,
                "candidate chunk exceeds limit",
            ),
            (
                vec![
                    apply_metadata_frame(token_text, "kv1:runtime:7"),
                    apply_chunk_frame(b"abcd".to_vec()),
                    apply_chunk_frame(b"efgh".to_vec()),
                ],
                tonic::Code::ResourceExhausted,
                "candidate exceeds limit",
            ),
            (
                duplicate_metadata,
                tonic::Code::InvalidArgument,
                "metadata frame may appear only once",
            ),
            (
                vec![
                    apply_metadata_frame(token_text, "kv1:runtime:7"),
                    apply_chunk_frame(candidate.to_vec()),
                ],
                tonic::Code::InvalidArgument,
                "end frame is required",
            ),
        ]
    }

    fn apply_end_failure_cases(candidate: &[u8], token_text: &str) -> Vec<ApplyFailureCase> {
        let mut trailing = apply_frames(candidate, token_text, "kv1:runtime:7");
        trailing.push(apply_chunk_frame(b"d".to_vec()));
        let invalid_utf8 = vec![
            apply_metadata_frame(token_text, "kv1:runtime:7"),
            apply_chunk_frame(vec![0xff]),
            apply_end_frame(1, Sha256::digest([0xff]).to_vec()),
        ];
        vec![
            (
                vec![
                    apply_metadata_frame(token_text, "kv1:runtime:7"),
                    apply_chunk_frame(candidate.to_vec()),
                    apply_end_frame(3, vec![0; 31]),
                ],
                tonic::Code::InvalidArgument,
                "candidate SHA-256 must be exactly 32 bytes",
            ),
            (
                vec![
                    apply_metadata_frame(token_text, "kv1:runtime:7"),
                    apply_chunk_frame(candidate.to_vec()),
                    apply_end_frame(3, vec![0; 32]),
                ],
                tonic::Code::InvalidArgument,
                "candidate SHA-256 does not match",
            ),
            (
                vec![
                    apply_metadata_frame(token_text, "kv1:runtime:7"),
                    apply_chunk_frame(candidate.to_vec()),
                    apply_end_frame(2, Sha256::digest(candidate).to_vec()),
                ],
                tonic::Code::InvalidArgument,
                "candidate length does not match end frame",
            ),
            (
                invalid_utf8,
                tonic::Code::InvalidArgument,
                "candidate config is not valid UTF-8",
            ),
            (
                trailing,
                tonic::Code::InvalidArgument,
                "end frame must be followed by EOF",
            ),
            (
                vec![
                    apply_metadata_frame(token_text, "kv1:runtime:7"),
                    proto::StreamApplyConfigTransactionRequest { frame: None },
                ],
                tonic::Code::InvalidArgument,
                "stream frame is empty",
            ),
            (
                apply_frames(candidate, "not-a-uuid", "kv1:runtime:7"),
                tonic::Code::InvalidArgument,
                "plan_token is malformed",
            ),
        ]
    }

    fn apply_failure_cases(candidate: &[u8], token_text: &str) -> Vec<ApplyFailureCase> {
        let mut invalid_confirm = apply_frames(candidate, token_text, "kv1:runtime:7");
        let Some(proto::stream_apply_config_transaction_request::Frame::Metadata(metadata)) =
            invalid_confirm[0].frame.as_mut()
        else {
            unreachable!()
        };
        metadata.confirm_id.clear();
        let metadata_case = |mutate: fn(&mut proto::StreamApplyConfigMetadata)| {
            let mut frames = apply_frames(candidate, token_text, "kv1:runtime:7");
            let Some(proto::stream_apply_config_transaction_request::Frame::Metadata(metadata)) =
                frames[0].frame.as_mut()
            else {
                unreachable!()
            };
            mutate(metadata);
            frames
        };
        let mut cases = apply_initial_failure_cases(candidate, token_text);
        cases.extend(apply_end_failure_cases(candidate, token_text));
        cases.extend([
            (
                invalid_confirm,
                tonic::Code::InvalidArgument,
                "confirm_id is required when confirm_timeout_seconds is set",
            ),
            (
                metadata_case(|metadata| metadata.plan_token.clear()),
                tonic::Code::InvalidArgument,
                "plan_token is required",
            ),
            (
                metadata_case(|metadata| metadata.expected_runtime_snapshot_token.clear()),
                tonic::Code::InvalidArgument,
                "expected_runtime_snapshot_token is required for ApplyConfigTransaction",
            ),
            (
                metadata_case(|metadata| metadata.confirm_id = "   ".to_string()),
                tonic::Code::InvalidArgument,
                "confirm_id is required",
            ),
            (
                metadata_case(|metadata| metadata.confirm_id = "x".repeat(129)),
                tonic::Code::InvalidArgument,
                "confirm_id must be at most 128 characters",
            ),
            (
                metadata_case(|metadata| metadata.confirm_id = "bad\nid".to_string()),
                tonic::Code::InvalidArgument,
                "confirm_id must not contain control characters",
            ),
            (
                metadata_case(|metadata| metadata.confirm_timeout_seconds = 86_401),
                tonic::Code::InvalidArgument,
                "confirm_timeout_seconds must be <= 86400",
            ),
        ]);
        cases
    }

    #[tokio::test]
    async fn apply_framing_and_metadata_failures_preserve_token_and_never_call_hook() {
        let runtime = TempDir::new().unwrap();
        let state = state_at(runtime.path(), limits(4, 7));
        let candidate = b"abc";
        let token = state
            .issue_token(
                "kv1:runtime:7".to_string(),
                Sha256::digest(candidate).into(),
                candidate.len() as u64,
            )
            .unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let hook_calls = Arc::clone(&calls);
        let hook: ConfigTransactionApplyFn = Arc::new(move |_request| {
            hook_calls.fetch_add(1, Ordering::SeqCst);
            Box::pin(async { Ok(applied_response()) })
        });
        let (peer_tx, _peer_rx) = mpsc::channel(1);
        let listener = spawn_listener_with_apply(
            Arc::clone(&state),
            peer_tx,
            true,
            Some(hook),
            AuthTier::OperatorOnly,
            PrincipalRole::Operator,
        )
        .await;
        let token_text = token.to_string();
        for (frames, code, message) in apply_failure_cases(candidate, &token_text) {
            let error = listener
                .client
                .clone()
                .stream_apply_config_transaction(futures::stream::iter(frames))
                .await
                .unwrap_err();
            assert_eq!(error.code(), code);
            assert_eq!(error.message(), message);
            assert!(has_token(&state, token));
            assert_eq!(calls.load(Ordering::SeqCst), 0);
        }

        listener
            .client
            .clone()
            .stream_apply_config_transaction(futures::stream::iter(apply_frames(
                candidate,
                &token_text,
                "kv1:runtime:7",
            )))
            .await
            .unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(!has_token(&state, token));
        let summary = listener
            .audit_observer
            .lock()
            .unwrap()
            .clone()
            .unwrap()
            .summary()
            .unwrap();
        assert_eq!(
            summary.as_str(),
            "version=1 chunk_count=1 candidate_bytes=3 expected_runtime_snapshot_token_present=true confirm_id_present=true outcome=applied"
        );
        for secret in ["abc", token_text.as_str(), "streamed apply"] {
            assert!(!summary.as_str().contains(secret));
        }
    }

    #[tokio::test]
    async fn authenticated_client_on_unauthenticated_transport_preserves_token_and_hook() {
        let runtime = TempDir::new().unwrap();
        let state = state_at(runtime.path(), StreamLimits::default());
        let candidate = b"candidate";
        let token = state
            .issue_token(
                "kv1:runtime:7".to_string(),
                Sha256::digest(candidate).into(),
                candidate.len() as u64,
            )
            .unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let hook_calls = Arc::clone(&calls);
        let hook: ConfigTransactionApplyFn = Arc::new(move |_request| {
            hook_calls.fetch_add(1, Ordering::SeqCst);
            Box::pin(async { Ok(applied_response()) })
        });
        let (peer_tx, _peer_rx) = mpsc::channel(1);
        let listener = spawn_listener_with_apply(
            Arc::clone(&state),
            peer_tx,
            false,
            Some(hook),
            AuthTier::OperatorOnly,
            PrincipalRole::Operator,
        )
        .await;

        let error = listener
            .client
            .clone()
            .stream_apply_config_transaction(futures::stream::iter(apply_frames(
                candidate,
                &token.to_string(),
                "kv1:runtime:7",
            )))
            .await
            .unwrap_err();
        assert_eq!(
            (error.code(), error.message()),
            (
                tonic::Code::Unauthenticated,
                "streamed config apply requires an authenticated listener"
            )
        );
        assert!(has_token(&state, token));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert!(state.try_admit().is_ok());
    }

    #[tokio::test(start_paused = true)]
    async fn apply_idle_and_absolute_deadlines_preserve_token_before_handoff() {
        let runtime = TempDir::new().unwrap();
        let state = state_at(
            runtime.path(),
            StreamLimits {
                max_chunk_bytes: 4,
                max_candidate_bytes: 32,
                idle_timeout: Duration::from_secs(10),
                total_timeout: Duration::from_secs(30),
            },
        );
        let candidate = b"abc";
        let token = state
            .issue_token(
                "kv1:runtime:7".to_string(),
                Sha256::digest(candidate).into(),
                candidate.len() as u64,
            )
            .unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let hook_calls = Arc::clone(&calls);
        let hook: ConfigTransactionApplyFn = Arc::new(move |_request| {
            hook_calls.fetch_add(1, Ordering::SeqCst);
            Box::pin(async { Ok(applied_response()) })
        });
        let (peer_tx, _peer_rx) = mpsc::channel(1);
        let listener = spawn_listener_with_apply(
            Arc::clone(&state),
            peer_tx,
            true,
            Some(hook),
            AuthTier::OperatorOnly,
            PrincipalRole::Operator,
        )
        .await;
        let token_text = token.to_string();

        let (idle_tx, idle_rx) = mpsc::channel(2);
        idle_tx
            .send(apply_metadata_frame(&token_text, "kv1:runtime:7"))
            .await
            .unwrap();
        let mut idle_client = listener.client.clone();
        let idle = tokio::spawn(async move {
            idle_client
                .stream_apply_config_transaction(ReceiverStream::new(idle_rx))
                .await
        });
        yield_until(|| state.try_admit().is_err()).await;
        tokio::time::advance(Duration::from_secs(11)).await;
        drop(idle_tx);
        let error = idle.await.unwrap().unwrap_err();
        assert_eq!(
            (error.code(), error.message()),
            (
                tonic::Code::DeadlineExceeded,
                "streamed config apply exceeded idle deadline"
            )
        );

        let (total_tx, total_rx) = mpsc::channel(8);
        total_tx
            .send(apply_metadata_frame(&token_text, "kv1:runtime:7"))
            .await
            .unwrap();
        let mut total_client = listener.client.clone();
        let total = tokio::spawn(async move {
            total_client
                .stream_apply_config_transaction(ReceiverStream::new(total_rx))
                .await
        });
        yield_until(|| state.try_admit().is_err()).await;
        for byte in *candidate {
            tokio::time::advance(Duration::from_secs(9)).await;
            total_tx.send(apply_chunk_frame(vec![byte])).await.unwrap();
            tokio::task::yield_now().await;
        }
        tokio::time::advance(Duration::from_secs(4)).await;
        let error = total.await.unwrap().unwrap_err();
        assert_eq!(
            (error.code(), error.message()),
            (
                tonic::Code::DeadlineExceeded,
                "streamed config apply exceeded total deadline"
            )
        );
        assert!(has_token(&state, token));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn binding_mismatch_preserves_token_but_cancelled_handoff_never_restores_it() {
        let runtime = TempDir::new().unwrap();
        let state = state_at(runtime.path(), StreamLimits::default());
        let (peer_tx, _peer_rx) = mpsc::channel(1);
        let (hook_tx, mut hook_rx) =
            mpsc::channel::<(proto::ApplyConfigTransactionRequest, HookReply)>(1);
        let hook: ConfigTransactionApplyFn = Arc::new(move |request| {
            let hook_tx = hook_tx.clone();
            Box::pin(async move {
                let (reply, receive) = oneshot::channel();
                hook_tx.send((request, reply)).await.unwrap();
                receive.await.unwrap()
            })
        });
        let listener = spawn_listener_with_apply(
            Arc::clone(&state),
            peer_tx,
            true,
            Some(hook),
            AuthTier::OperatorOnly,
            PrincipalRole::Operator,
        )
        .await;
        let candidate = b"candidate";
        let token = state
            .issue_token(
                "kv1:runtime:7".to_string(),
                Sha256::digest(candidate).into(),
                candidate.len() as u64,
            )
            .unwrap();
        let mismatch = listener
            .client
            .clone()
            .stream_apply_config_transaction(futures::stream::iter(apply_frames(
                candidate,
                &token.to_string(),
                "kv1:wrong",
            )))
            .await
            .unwrap_err();
        assert_eq!(mismatch.code(), tonic::Code::FailedPrecondition);
        assert!(has_token(&state, token));
        assert!(hook_rx.try_recv().is_err());

        let same_length_other_candidate = b"candidaXe";
        assert_eq!(same_length_other_candidate.len(), candidate.len());
        let digest_mismatch = listener
            .client
            .clone()
            .stream_apply_config_transaction(futures::stream::iter(apply_frames(
                same_length_other_candidate,
                &token.to_string(),
                "kv1:runtime:7",
            )))
            .await
            .unwrap_err();
        assert_eq!(digest_mismatch.code(), tonic::Code::FailedPrecondition);
        assert!(has_token(&state, token));
        assert!(hook_rx.try_recv().is_err());

        let mut client = listener.client.clone();
        let token_text = token.to_string();
        let apply = tokio::spawn(async move {
            client
                .stream_apply_config_transaction(futures::stream::iter(apply_frames(
                    candidate,
                    &token_text,
                    "kv1:runtime:7",
                )))
                .await
        });
        let (_request, reply) = hook_rx.recv().await.unwrap();
        apply.abort();
        assert!(!has_token(&state, token));
        assert_eq!(
            state.try_admit().unwrap_err().code(),
            tonic::Code::ResourceExhausted
        );
        reply.send(Ok(applied_response())).unwrap();
        yield_until(|| state.try_admit().is_ok()).await;
        let replay_error = listener
            .client
            .clone()
            .stream_apply_config_transaction(futures::stream::iter(apply_frames(
                candidate,
                &token.to_string(),
                "kv1:runtime:7",
            )))
            .await
            .unwrap_err();
        assert_eq!(replay_error.code(), tonic::Code::FailedPrecondition);
        assert!(hook_rx.try_recv().is_err());
    }

    #[tokio::test(start_paused = true)]
    async fn response_deadline_keeps_apply_and_cross_method_admission_until_settlement() {
        let runtime = TempDir::new().unwrap();
        let state = state_at(
            runtime.path(),
            StreamLimits {
                max_chunk_bytes: 16,
                max_candidate_bytes: 64,
                idle_timeout: Duration::from_secs(10),
                total_timeout: Duration::from_secs(30),
            },
        );
        let (peer_tx, mut peer_rx) = mpsc::channel(1);
        let (hook_tx, mut hook_rx) =
            mpsc::channel::<(proto::ApplyConfigTransactionRequest, HookReply)>(1);
        let hook: ConfigTransactionApplyFn = Arc::new(move |request| {
            let hook_tx = hook_tx.clone();
            Box::pin(async move {
                let (reply, receive) = oneshot::channel();
                hook_tx.send((request, reply)).await.unwrap();
                receive.await.unwrap()
            })
        });
        let listener = spawn_listener_with_apply(
            Arc::clone(&state),
            peer_tx,
            true,
            Some(hook),
            AuthTier::OperatorOnly,
            PrincipalRole::Operator,
        )
        .await;
        let candidate = b"candidate";
        let token = state
            .issue_token(
                "kv1:runtime:7".to_string(),
                Sha256::digest(candidate).into(),
                candidate.len() as u64,
            )
            .unwrap();
        let mut client = listener.client.clone();
        let token_text = token.to_string();
        let apply = tokio::spawn(async move {
            client
                .stream_apply_config_transaction(futures::stream::iter(apply_frames(
                    candidate,
                    &token_text,
                    "kv1:runtime:7",
                )))
                .await
        });
        let (_request, reply) = hook_rx.recv().await.unwrap();
        assert!(!has_token(&state, token));

        let blocked_plan = listener
            .client
            .clone()
            .stream_plan_config_transaction(futures::stream::iter(frames(b"other", None)))
            .await
            .unwrap_err();
        assert_eq!(blocked_plan.code(), tonic::Code::ResourceExhausted);
        assert!(peer_rx.try_recv().is_err());
        tokio::time::advance(Duration::from_secs(31)).await;
        let deadline = apply.await.unwrap().unwrap_err();
        assert_eq!(deadline.code(), tonic::Code::DeadlineExceeded);
        assert!(deadline.message().contains("apply continues to settlement"));
        assert_eq!(
            state.try_admit().unwrap_err().code(),
            tonic::Code::ResourceExhausted
        );
        reply.send(Ok(applied_response())).unwrap();
        yield_until(|| state.try_admit().is_ok()).await;
        assert!(!has_token(&state, token));
    }

    #[tokio::test]
    async fn framing_failures_never_handoff_and_always_clean_spool() {
        let runtime = TempDir::new().unwrap();
        let state = state_at(runtime.path(), limits(4, 7));
        let (peer_tx, mut peer_rx) = mpsc::channel(1);
        let listener = spawn_listener(Arc::clone(&state), peer_tx, true).await;
        let no_metadata = Vec::new();
        let leading_chunk = vec![chunk(b"a".to_vec())];
        let mut wrong_version = complete_chunks(&[b"abc"]);
        wrong_version[0] = metadata_version(2, None);
        let empty_chunk = complete_chunks(&[b"", b"abc"]);
        let oversized_chunk = complete_chunks(&[b"abcde"]);
        let aggregate_overflow = complete_chunks(&[b"abcd", b"efgh"]);
        let mut duplicate_metadata = complete_chunks(&[b"abc"]);
        duplicate_metadata.insert(1, metadata(None));
        let missing_end = vec![metadata(None), chunk(b"abc".to_vec())];
        let bad_sha_size = candidate_end(b"abc", malformed_end(3, vec![0; 31]));
        let bad_sha = candidate_end(b"abc", malformed_end(3, vec![0; 32]));
        let bad_length = candidate_end(b"abc", malformed_end(2, Sha256::digest(b"abc").to_vec()));
        let invalid_utf8 = complete_chunks(&[&[0xff]]);
        let mut trailing = complete_chunks(&[b"abc"]);
        trailing.push(chunk(b"d".to_vec()));
        let empty_frame = vec![
            metadata(None),
            proto::StreamPlanConfigTransactionRequest { frame: None },
        ];
        #[rustfmt::skip]
        let cases = vec![
            (no_metadata, Invalid, "metadata frame is required first"),
            (leading_chunk, Invalid, "metadata frame is required first"),
            (wrong_version, Invalid, "unsupported stream framing version"),
            (empty_chunk, Invalid, "candidate chunks must be non-empty"),
            (oversized_chunk, Exhausted, "candidate chunk exceeds limit"),
            (aggregate_overflow, Exhausted, "candidate exceeds limit"),
            (duplicate_metadata, Invalid, "metadata frame may appear only once"),
            (missing_end, Invalid, "end frame is required"),
            (bad_sha_size, Invalid, "candidate SHA-256 must be exactly 32 bytes"),
            (bad_sha, Invalid, "candidate SHA-256 does not match"),
            (bad_length, Invalid, "candidate length does not match end frame"),
            (invalid_utf8, Invalid, "candidate config is not valid UTF-8"),
            (trailing, Invalid, "end frame must be followed by EOF"),
            (empty_frame, Invalid, "stream frame is empty"),
        ];
        for (case, code, message) in cases {
            let mut client = listener.client.clone();
            let rpc = client.stream_plan_config_transaction(futures::stream::iter(case));
            let error = tokio::time::timeout(Duration::from_secs(1), rpc)
                .await
                .expect("framing guard did not terminate")
                .unwrap_err();
            assert_eq!((error.code(), error.message()), (code, message));
            assert!(peer_rx.try_recv().is_err());
            assert!(spool_is_anonymous(runtime.path()));
        }
        state.corrupt_before_read.store(true, Ordering::SeqCst);
        let error = listener
            .client
            .clone()
            .stream_plan_config_transaction(futures::stream::iter(frames(b"same", None)))
            .await
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::Internal);
        assert!(peer_rx.try_recv().is_err());
        assert!(state.tokens.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn shared_admission_and_cancellation_keep_ownership_until_planner_finishes() {
        let runtime = TempDir::new().unwrap();
        let state = state_at(runtime.path(), StreamLimits::default());
        let (peer_tx, mut peer_rx) = mpsc::channel(2);
        let first_listener = spawn_listener(Arc::clone(&state), peer_tx.clone(), true).await;
        let second_listener = spawn_listener(Arc::clone(&state), peer_tx, true).await;

        let (frame_tx, frame_rx) = mpsc::channel(2);
        frame_tx.send(metadata(None)).await.unwrap();
        let mut first_client = first_listener.client.clone();
        let pre_handoff = tokio::spawn(async move {
            first_client
                .stream_plan_config_transaction(ReceiverStream::new(frame_rx))
                .await
        });
        yield_until(|| state.try_admit().is_err()).await;
        let busy = tokio::time::timeout(
            Duration::from_secs(1),
            second_listener
                .client
                .clone()
                .stream_plan_config_transaction(futures::stream::iter(frames(b"ok", None))),
        )
        .await
        .expect("busy RPC queued or reached the peer manager")
        .unwrap_err();
        assert_eq!(busy.code(), tonic::Code::ResourceExhausted);
        pre_handoff.abort();
        drop(frame_tx);
        yield_until(|| state.try_admit().is_ok()).await;

        let mut client = first_listener.client.clone();
        let post_handoff = tokio::spawn(async move {
            client
                .stream_plan_config_transaction(futures::stream::iter(frames(b"candidate", None)))
                .await
        });
        let PeerManagerCommand::PlanConfigTransaction { reply, .. } = peer_rx.recv().await.unwrap()
        else {
            panic!("unexpected peer-manager command");
        };
        post_handoff.abort();
        assert_eq!(
            state.try_admit().unwrap_err().code(),
            tonic::Code::ResourceExhausted
        );
        reply
            .send(Ok(sample_plan(RuntimeConfigTransactionStatus::Committable)))
            .unwrap();
        yield_until(|| state.try_admit().is_ok()).await;
    }

    #[tokio::test]
    async fn failed_response_delivery_revokes_the_new_plan_token() {
        let runtime = TempDir::new().unwrap();
        let state = state_at(runtime.path(), StreamLimits::default());
        let permit = state.try_admit().unwrap();
        let (peer_tx, mut peer_rx) = mpsc::channel(1);
        let (response_tx, response_rx) = oneshot::channel();
        drop(response_rx);
        let task = tokio::spawn(run_detached_plan(
            Arc::clone(&state),
            peer_tx,
            "candidate".to_string(),
            None,
            Sha256::digest(b"candidate").into(),
            9,
            Instant::now() + Duration::from_mins(1),
            permit,
            StreamAudit::new(None),
            response_tx,
        ));
        let PeerManagerCommand::PlanConfigTransaction { reply, .. } = peer_rx.recv().await.unwrap()
        else {
            panic!("unexpected peer-manager command");
        };
        reply
            .send(Ok(sample_plan(RuntimeConfigTransactionStatus::Committable)))
            .unwrap();
        task.await.unwrap();
        assert!(state.tokens.lock().unwrap().is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn cancelled_post_handoff_planner_keeps_slot_until_original_total_deadline() {
        let runtime = TempDir::new().unwrap();
        let state = state_at(runtime.path(), StreamLimits::default());
        let (peer_tx, mut peer_rx) = mpsc::channel(1);
        let listener = spawn_listener(Arc::clone(&state), peer_tx, true).await;
        let mut client = listener.client.clone();
        let request = tokio::spawn(async move {
            client
                .stream_plan_config_transaction(futures::stream::iter(frames(b"stalled", None)))
                .await
        });
        let PeerManagerCommand::PlanConfigTransaction { reply, .. } = peer_rx.recv().await.unwrap()
        else {
            panic!("unexpected peer-manager command");
        };
        request.abort();
        assert_eq!(
            state.try_admit().unwrap_err().code(),
            tonic::Code::ResourceExhausted
        );
        tokio::time::advance(Duration::from_secs(30 * 60 - 1)).await;
        assert!(state.try_admit().is_err());
        assert!(!reply.is_closed());
        tokio::time::advance(Duration::from_secs(2)).await;
        yield_until(|| state.try_admit().is_ok()).await;
        assert!(
            reply
                .send(Ok(sample_plan(RuntimeConfigTransactionStatus::Committable)))
                .is_err()
        );
        assert!(state.tokens.lock().unwrap().is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn idle_and_absolute_deadlines_are_enforced_from_original_admission() {
        let runtime = TempDir::new().unwrap();
        let state = state_at(
            runtime.path(),
            StreamLimits {
                max_chunk_bytes: 4,
                max_candidate_bytes: 32,
                idle_timeout: Duration::from_secs(10),
                total_timeout: Duration::from_secs(30),
            },
        );
        let (peer_tx, mut peer_rx) = mpsc::channel(1);
        let listener = spawn_listener(Arc::clone(&state), peer_tx, true).await;

        let (idle_tx, idle_rx) = mpsc::channel(2);
        idle_tx.send(metadata(None)).await.unwrap();
        let mut client = listener.client.clone();
        let idle = tokio::spawn(async move {
            client
                .stream_plan_config_transaction(ReceiverStream::new(idle_rx))
                .await
        });
        yield_until(|| state.try_admit().is_err()).await;
        tokio::time::advance(Duration::from_secs(11)).await;
        drop(idle_tx);
        let error = idle.await.unwrap().unwrap_err();
        assert_eq!(error.code(), tonic::Code::DeadlineExceeded);
        assert!(error.message().contains("idle deadline"));
        assert!(peer_rx.try_recv().is_err());

        let (total_tx, total_rx) = mpsc::channel(8);
        total_tx.send(metadata(None)).await.unwrap();
        let mut client = listener.client.clone();
        let total = tokio::spawn(async move {
            client
                .stream_plan_config_transaction(ReceiverStream::new(total_rx))
                .await
        });
        yield_until(|| state.try_admit().is_err()).await;
        for byte in *b"abc" {
            tokio::time::advance(Duration::from_secs(9)).await;
            total_tx.send(chunk(vec![byte])).await.unwrap();
            tokio::task::yield_now().await;
        }
        tokio::time::advance(Duration::from_secs(4)).await;
        drop(total_tx);
        let error = total.await.unwrap().unwrap_err();
        assert_eq!(error.code(), tonic::Code::DeadlineExceeded);
        assert!(error.message().contains("total deadline"));
        assert!(peer_rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn token_store_is_bounded_expires_and_noncommittable_plans_get_no_token() {
        tokio::time::pause();
        let runtime = TempDir::new().unwrap();
        let state = state_at(runtime.path(), StreamLimits::default());
        let first = state
            .issue_token("runtime".to_string(), [1; 32], 1)
            .unwrap();
        for n in 1_u64..=256 {
            state
                .issue_token("runtime".to_string(), [2; 32], n)
                .unwrap();
        }
        assert_eq!(state.tokens.lock().unwrap().len(), 256);
        assert!(!has_token(&state, first));
        let expiry_state = state_at(runtime.path(), StreamLimits::default());
        let expiring = expiry_state
            .issue_token("expiring".to_string(), [3; 32], 3)
            .unwrap();
        tokio::time::advance(Duration::from_secs(30 * 60 - 1)).await;
        expiry_state
            .issue_token("before".to_string(), [4; 32], 4)
            .unwrap();
        assert!(has_token(&expiry_state, expiring));
        tokio::time::advance(Duration::from_secs(2)).await;
        expiry_state
            .issue_token("after".to_string(), [5; 32], 5)
            .unwrap();
        assert!(!has_token(&expiry_state, expiring));

        let (peer_tx, mut peer_rx) = mpsc::channel(1);
        let listener = spawn_listener(Arc::clone(&state), peer_tx, true).await;
        let mut client = listener.client.clone();
        let request = tokio::spawn(async move {
            client
                .stream_plan_config_transaction(futures::stream::iter(frames(b"noop", None)))
                .await
        });
        let PeerManagerCommand::PlanConfigTransaction { reply, .. } = peer_rx.recv().await.unwrap()
        else {
            panic!("unexpected peer-manager command");
        };
        reply
            .send(Ok(sample_plan(RuntimeConfigTransactionStatus::Noop)))
            .unwrap();
        let response = request.await.unwrap().unwrap().into_inner();
        assert!(response.plan_token.is_none());
        assert_eq!(state.tokens.lock().unwrap().len(), 256);
    }

    #[tokio::test(start_paused = true)]
    async fn length_mismatch_preserves_token_but_expiry_removes_it() {
        let runtime = TempDir::new().unwrap();
        let state = state_at(runtime.path(), StreamLimits::default());
        let digest = [7; 32];
        let token = state
            .issue_token("kv1:runtime:7".to_string(), digest, 7)
            .unwrap();
        let token_text = token.to_string();
        assert_eq!(
            consume_error_code(state.consume_token(&token_text, "kv1:runtime:7", &digest, 8)),
            tonic::Code::FailedPrecondition
        );
        assert!(has_token(&state, token));
        tokio::time::advance(PLAN_TOKEN_TTL + Duration::from_secs(1)).await;
        assert_eq!(
            consume_error_code(state.consume_token(&token_text, "kv1:runtime:7", &digest, 7)),
            tonic::Code::FailedPrecondition
        );
        assert!(!has_token(&state, token));
    }
}
