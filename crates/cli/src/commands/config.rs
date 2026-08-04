use crate::connection::Connection;
use crate::error::CliError;
use crate::output;
use crate::proto::config_service_client::ConfigServiceClient;
use crate::proto::{
    AbortConfigTransactionRequest, ApplyConfigTransactionRequest, ConfigTransactionApplyResponse,
    ConfigTransactionConfirmation, ConfigTransactionConfirmationStatus,
    ConfigTransactionPlanResponse, ConfigTransactionPlanStatus, ConfigTransactionStatusResponse,
    ConfirmConfigTransactionRequest, DiffRuntimeConfigRequest, DiffRuntimeConfigResponse,
    GetConfigTransactionStatusRequest, GetEffectiveConfigRequest, ListConfigHistoryRequest,
    ListConfigHistoryResponse, PlanConfigTransactionRequest, RollbackConfigTransactionRequest,
    StreamApplyConfigMetadata, StreamApplyConfigTransactionRequest, StreamPlanConfigEnd,
    StreamPlanConfigMetadata, StreamPlanConfigTransactionRequest, UpdateGroupImpactPlan,
};
use prost::Message;
use sha2::{Digest as _, Sha256};
use std::pin::Pin;
use std::sync::Arc;
#[cfg(test)]
use std::sync::atomic::AtomicUsize;
use std::task::{Context, Poll};

const MAX_CONFIRM_ID_CHARS: usize = 128;
const MAX_CONFIRM_TIMEOUT_SECONDS: u32 = 86_400;
const MAX_UNARY_CONFIG_REQUEST_BYTES: usize = 4_194_304;
const STREAM_CONFIG_FRAME_VERSION: u32 = 1;
const STREAM_CONFIG_CHUNK_BYTES: usize = 1024 * 1024;
#[cfg(test)]
static PLAN_FRAME_POLLS: AtomicUsize = AtomicUsize::new(0);
#[cfg(test)]
static APPLY_FRAME_POLLS: AtomicUsize = AtomicUsize::new(0);
#[cfg(test)]
const LAZY_PULL_PROOF_MARKER: &str = "LAZY_PULL_PROOF";

pub struct ApplyOptions<'a> {
    pub from_file: &'a str,
    pub expected_runtime_snapshot_token: &'a str,
    pub plan_token: Option<&'a str>,
    pub client_request_id: Option<&'a str>,
    pub comment: Option<&'a str>,
    pub confirm_id: Option<&'a str>,
    pub confirm_timeout_seconds: Option<u32>,
}

pub struct RollbackOptions<'a> {
    pub index: u32,
    pub expected_runtime_snapshot_token: Option<&'a str>,
    pub client_request_id: Option<&'a str>,
    pub comment: Option<&'a str>,
    pub confirm_id: Option<&'a str>,
    pub confirm_timeout_seconds: Option<u32>,
}

/// Detailed exit code for `config diff` / `config plan`: 0 when the
/// candidate matches the runtime config, 2 when changes are present
/// (errors exit 1 through the generic CLI error path).
pub fn change_status_exit_code(has_changes: bool) -> i32 {
    if has_changes { 2 } else { 0 }
}

/// Returns whether the candidate differs from the runtime config, for the
/// 0 (no changes) / 2 (changes present) exit-code contract.
pub async fn diff(connection: Connection, from_file: &str, json: bool) -> Result<bool, CliError> {
    let candidate_toml = read_candidate_toml(from_file)?;
    let request = DiffRuntimeConfigRequest { candidate_toml };
    preflight_config_request(&request, from_file)?;
    let mut client =
        ConfigServiceClient::with_interceptor(connection.channel(), connection.interceptor());
    let resp = client.diff_runtime_config(request).await?.into_inner();

    if json {
        output::print_serialized_json_line(&resp.diff_json)?;
    } else {
        print!("{}", resp.human_text);
    }
    Ok(resp.has_any_changes)
}

/// Returns whether the plan contains changes (status other than noop),
/// for the 0 (no changes) / 2 (changes present) exit-code contract.
pub async fn plan(
    connection: Connection,
    from_file: &str,
    expected_runtime_snapshot_token: Option<&str>,
    json: bool,
) -> Result<bool, CliError> {
    let candidate_toml = Arc::new(read_candidate_toml(from_file)?);
    let mut client =
        ConfigServiceClient::with_interceptor(connection.channel(), connection.interceptor());
    let streamed = client
        .stream_plan_config_transaction(PlanFrameStream::new(
            Arc::clone(&candidate_toml),
            expected_runtime_snapshot_token,
        ))
        .await;
    let (resp, plan_token) = match streamed {
        Ok(response) => {
            let response = response.into_inner();
            let plan = response.plan.ok_or_else(|| {
                CliError::Argument("daemon returned streamed plan without a plan".to_string())
            })?;
            (plan, response.plan_token)
        }
        Err(status) if exact_missing_method(&status) => {
            let request = PlanConfigTransactionRequest {
                candidate_toml: candidate_toml.to_string(),
                expected_runtime_snapshot_token: expected_runtime_snapshot_token
                    .unwrap_or_default()
                    .to_string(),
            };
            preflight_config_request(&request, from_file)?;
            (
                client.plan_config_transaction(request).await?.into_inner(),
                None,
            )
        }
        Err(status) => return Err(status.into()),
    };

    if json {
        print_json(plan_to_json(&resp, plan_token.as_deref()))?;
    } else {
        print_plan_human(&resp);
        if let Some(line) = plan_token_human_line(plan_token.as_deref()) {
            println!("{line}");
        }
    }
    Ok(resp.status != ConfigTransactionPlanStatus::Noop as i32)
}

fn plan_token_human_line(plan_token: Option<&str>) -> Option<String> {
    plan_token.map(|token| format!("plan_token: {token}"))
}

pub async fn apply(
    connection: Connection,
    options: ApplyOptions<'_>,
    json: bool,
) -> Result<(), CliError> {
    let response = apply_response(connection, options).await?;
    print_apply_response(&response, json)
}

async fn apply_response(
    connection: Connection,
    options: ApplyOptions<'_>,
) -> Result<ConfigTransactionApplyResponse, CliError> {
    if options.expected_runtime_snapshot_token.is_empty() {
        return Err(CliError::Argument(
            "--expected-runtime-snapshot-token must not be empty".to_string(),
        ));
    }
    if matches!(options.plan_token, Some(token) if token.trim().is_empty()) {
        return Err(CliError::Argument("--plan-token must not be empty".into()));
    }
    if options.confirm_id.is_none() && options.confirm_timeout_seconds.is_some() {
        return Err(CliError::Argument(
            "--confirm-timeout requires --confirm-id".to_string(),
        ));
    }
    if let Some(confirm_id) = options.confirm_id {
        validate_confirm_id(confirm_id)?;
    }
    if matches!(
        options.confirm_timeout_seconds,
        Some(timeout_seconds) if timeout_seconds > MAX_CONFIRM_TIMEOUT_SECONDS
    ) {
        return Err(CliError::Argument(format!(
            "--confirm-timeout must be <= {MAX_CONFIRM_TIMEOUT_SECONDS}"
        )));
    }
    let candidate_toml = Arc::new(read_candidate_toml(options.from_file)?);
    let mut client =
        ConfigServiceClient::with_interceptor(connection.channel(), connection.interceptor());
    let plan_token = match options.plan_token {
        Some(token) => token.to_string(),
        None => {
            let plan = client
                .stream_plan_config_transaction(PlanFrameStream::new(
                    Arc::clone(&candidate_toml),
                    Some(options.expected_runtime_snapshot_token),
                ))
                .await;
            match plan {
                Ok(response) => {
                    let response = response.into_inner();
                    let plan = response.plan.ok_or_else(|| {
                        CliError::Argument(
                            "daemon returned streamed plan without a plan".to_string(),
                        )
                    })?;
                    match ConfigTransactionPlanStatus::try_from(plan.status) {
                        Ok(
                            ConfigTransactionPlanStatus::Noop
                            | ConfigTransactionPlanStatus::Rejected,
                        ) => {
                            return Ok(plan_as_apply_response(plan));
                        }
                        Ok(ConfigTransactionPlanStatus::Committable) => {}
                        Ok(ConfigTransactionPlanStatus::Unspecified) | Err(_) => {
                            return Err(CliError::Argument(
                                "daemon returned an invalid streamed plan status".to_string(),
                            ));
                        }
                    }
                    response.plan_token.ok_or_else(|| {
                        CliError::Argument(
                            "daemon returned a committable streamed plan without a plan token"
                                .to_string(),
                        )
                    })?
                }
                Err(status) if exact_missing_method(&status) => {
                    return unary_apply_response(
                        &mut client,
                        apply_request(&candidate_toml, &options),
                        options.from_file,
                    )
                    .await;
                }
                Err(status) => return Err(status.into()),
            }
        }
    };
    let metadata = StreamApplyConfigMetadata {
        version: STREAM_CONFIG_FRAME_VERSION,
        plan_token,
        expected_runtime_snapshot_token: options.expected_runtime_snapshot_token.to_string(),
        client_request_id: options.client_request_id.unwrap_or_default().to_string(),
        comment: options.comment.unwrap_or_default().to_string(),
        confirm_id: options.confirm_id.unwrap_or_default().to_string(),
        confirm_timeout_seconds: options.confirm_timeout_seconds.unwrap_or_default(),
    };
    let resp = match client
        .stream_apply_config_transaction(ApplyFrameStream::new(
            Arc::clone(&candidate_toml),
            metadata,
        ))
        .await
    {
        Ok(response) => response.into_inner(),
        Err(status) if options.plan_token.is_none() && exact_missing_method(&status) => {
            return unary_apply_response(
                &mut client,
                apply_request(&candidate_toml, &options),
                options.from_file,
            )
            .await;
        }
        Err(status) => return Err(status.into()),
    };

    Ok(resp)
}

fn plan_as_apply_response(plan: ConfigTransactionPlanResponse) -> ConfigTransactionApplyResponse {
    ConfigTransactionApplyResponse {
        status: plan.status,
        runtime_snapshot_token: plan.runtime_snapshot_token,
        committed_sections: Vec::new(),
        human_text: plan.human_text,
        confirmation: None,
        update_group_impact: plan.update_group_impact,
    }
}

fn apply_request(
    candidate_toml: &str,
    options: &ApplyOptions<'_>,
) -> ApplyConfigTransactionRequest {
    ApplyConfigTransactionRequest {
        candidate_toml: candidate_toml.to_string(),
        expected_runtime_snapshot_token: options.expected_runtime_snapshot_token.to_string(),
        client_request_id: options.client_request_id.unwrap_or_default().to_string(),
        comment: options.comment.unwrap_or_default().to_string(),
        confirm_id: options.confirm_id.unwrap_or_default().to_string(),
        confirm_timeout_seconds: options.confirm_timeout_seconds.unwrap_or_default(),
    }
}

async fn unary_apply_response<T>(
    client: &mut ConfigServiceClient<T>,
    request: ApplyConfigTransactionRequest,
    from_file: &str,
) -> Result<ConfigTransactionApplyResponse, CliError>
where
    T: tonic::client::GrpcService<tonic::body::Body>,
    T::ResponseBody: tonic::codegen::Body<Data = tonic::codegen::Bytes> + Send + 'static,
    T::Error: Into<tonic::codegen::StdError>,
    <T::ResponseBody as tonic::codegen::Body>::Error: Into<tonic::codegen::StdError> + Send,
{
    preflight_config_request(&request, from_file)?;
    Ok(client.apply_config_transaction(request).await?.into_inner())
}

fn print_apply_response(resp: &ConfigTransactionApplyResponse, json: bool) -> Result<(), CliError> {
    if json {
        print_json(apply_to_json(resp))?;
    } else {
        print_apply_human(resp);
    }
    if let Some(footer) = confirm_window_footer(resp.confirmation.as_ref()) {
        crate::output::print_next_step(json, &footer);
    }
    Ok(())
}

fn exact_missing_method(status: &tonic::Status) -> bool {
    status.code() == tonic::Code::Unimplemented
        && status.message().is_empty()
        && status.details().is_empty()
}

struct FrameCursor {
    candidate: Arc<String>,
    offset: usize,
    digest: [u8; 32],
    stage: u8,
    #[cfg(test)]
    delay: Option<Pin<Box<tokio::time::Sleep>>>,
}

impl FrameCursor {
    fn new(candidate: Arc<String>) -> Self {
        let digest = Sha256::digest(candidate.as_bytes()).into();
        Self {
            candidate,
            offset: 0,
            digest,
            stage: 0,
            #[cfg(test)]
            delay: None,
        }
    }

    #[cfg(test)]
    fn poll_proof_delay(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        use std::future::Future as _;

        if !self.candidate.starts_with(LAZY_PULL_PROOF_MARKER) {
            return Poll::Ready(());
        }
        let delay = self.delay.get_or_insert_with(|| {
            Box::pin(tokio::time::sleep(std::time::Duration::from_millis(1)))
        });
        match delay.as_mut().poll(cx) {
            Poll::Ready(()) => {
                self.delay = None;
                Poll::Ready(())
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn next_chunk(&mut self) -> Option<Vec<u8>> {
        let bytes = self.candidate.as_bytes();
        if self.offset >= bytes.len() {
            return None;
        }
        let end = self
            .offset
            .saturating_add(STREAM_CONFIG_CHUNK_BYTES)
            .min(bytes.len());
        let chunk = bytes[self.offset..end].to_vec();
        self.offset = end;
        Some(chunk)
    }

    fn end(&self) -> StreamPlanConfigEnd {
        StreamPlanConfigEnd {
            candidate_length: self.candidate.len() as u64,
            candidate_sha256: self.digest.to_vec(),
        }
    }
}

struct PlanFrameStream {
    cursor: FrameCursor,
    expected_runtime_snapshot_token: Option<String>,
}

impl PlanFrameStream {
    fn new(candidate: Arc<String>, expected_runtime_snapshot_token: Option<&str>) -> Self {
        Self {
            cursor: FrameCursor::new(candidate),
            expected_runtime_snapshot_token: expected_runtime_snapshot_token.map(str::to_string),
        }
    }
}

impl tonic::codegen::tokio_stream::Stream for PlanFrameStream {
    type Item = StreamPlanConfigTransactionRequest;

    fn poll_next(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        #[cfg(test)]
        if self.cursor.poll_proof_delay(_cx).is_pending() {
            return Poll::Pending;
        }
        let frame = match self.cursor.stage {
            0 => {
                self.cursor.stage = 1;
                crate::proto::stream_plan_config_transaction_request::Frame::Metadata(
                    StreamPlanConfigMetadata {
                        version: STREAM_CONFIG_FRAME_VERSION,
                        expected_runtime_snapshot_token: self
                            .expected_runtime_snapshot_token
                            .clone(),
                    },
                )
            }
            1 => match self.cursor.next_chunk() {
                Some(chunk) => {
                    crate::proto::stream_plan_config_transaction_request::Frame::CandidateChunk(
                        chunk,
                    )
                }
                None => {
                    self.cursor.stage = 2;
                    crate::proto::stream_plan_config_transaction_request::Frame::End(
                        self.cursor.end(),
                    )
                }
            },
            _ => return Poll::Ready(None),
        };
        if self.cursor.stage == 2 {
            self.cursor.stage = 3;
        }
        #[cfg(test)]
        if self.cursor.candidate.starts_with(LAZY_PULL_PROOF_MARKER) {
            PLAN_FRAME_POLLS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
        Poll::Ready(Some(StreamPlanConfigTransactionRequest {
            frame: Some(frame),
        }))
    }
}

struct ApplyFrameStream {
    cursor: FrameCursor,
    metadata: Option<StreamApplyConfigMetadata>,
}

impl ApplyFrameStream {
    fn new(candidate: Arc<String>, metadata: StreamApplyConfigMetadata) -> Self {
        Self {
            cursor: FrameCursor::new(candidate),
            metadata: Some(metadata),
        }
    }
}

impl tonic::codegen::tokio_stream::Stream for ApplyFrameStream {
    type Item = StreamApplyConfigTransactionRequest;

    fn poll_next(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        #[cfg(test)]
        if self.cursor.poll_proof_delay(_cx).is_pending() {
            return Poll::Pending;
        }
        let frame = match self.cursor.stage {
            0 => {
                self.cursor.stage = 1;
                crate::proto::stream_apply_config_transaction_request::Frame::Metadata(
                    self.metadata.take().expect("metadata stage owns metadata"),
                )
            }
            1 => match self.cursor.next_chunk() {
                Some(chunk) => {
                    crate::proto::stream_apply_config_transaction_request::Frame::CandidateChunk(
                        chunk,
                    )
                }
                None => {
                    self.cursor.stage = 2;
                    crate::proto::stream_apply_config_transaction_request::Frame::End(
                        self.cursor.end(),
                    )
                }
            },
            _ => return Poll::Ready(None),
        };
        if self.cursor.stage == 2 {
            self.cursor.stage = 3;
        }
        #[cfg(test)]
        if self.cursor.candidate.starts_with(LAZY_PULL_PROOF_MARKER) {
            APPLY_FRAME_POLLS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
        Poll::Ready(Some(StreamApplyConfigTransactionRequest {
            frame: Some(frame),
        }))
    }
}

/// "What next" footer for an apply that opened a confirmed-commit window:
/// the change auto-reverts unless the operator confirms in time.
fn confirm_window_footer(confirmation: Option<&ConfigTransactionConfirmation>) -> Option<String> {
    let confirmation = confirmation?;
    let pending = ConfigTransactionConfirmationStatus::Pending as i32;
    if confirmation.status != pending || confirmation.confirm_id.is_empty() {
        return None;
    }
    let id = &confirmation.confirm_id;
    Some(format!(
        "confirm within the window or the change auto-reverts: rbgp config confirm {id} (roll back now: rbgp config abort {id})"
    ))
}

pub async fn confirm(connection: Connection, confirm_id: &str, json: bool) -> Result<(), CliError> {
    validate_confirm_id(confirm_id)?;
    let mut client =
        ConfigServiceClient::with_interceptor(connection.channel(), connection.interceptor());
    let resp = client
        .confirm_config_transaction(ConfirmConfigTransactionRequest {
            confirm_id: confirm_id.to_string(),
        })
        .await?
        .into_inner();

    if json {
        print_json(serde_json::json!({
            "confirmation": confirmation_to_json(resp.confirmation.as_ref()),
            "human_text": resp.human_text,
        }))?;
    } else {
        print!("{}", resp.human_text);
        print_confirmation(resp.confirmation.as_ref());
    }
    crate::output::print_next_step(
        json,
        "the transaction is confirmed and permanent — verify with: rbgp config status",
    );
    Ok(())
}

pub async fn abort(connection: Connection, confirm_id: &str, json: bool) -> Result<(), CliError> {
    validate_confirm_id(confirm_id)?;
    let mut client =
        ConfigServiceClient::with_interceptor(connection.channel(), connection.interceptor());
    let resp = client
        .abort_config_transaction(AbortConfigTransactionRequest {
            confirm_id: confirm_id.to_string(),
        })
        .await?
        .into_inner();

    if json {
        print_json(serde_json::json!({
            "confirmation": confirmation_to_json(resp.confirmation.as_ref()),
            "runtime_snapshot_token": resp.runtime_snapshot_token,
            "human_text": resp.human_text,
        }))?;
    } else {
        print!("{}", resp.human_text);
        if !resp.runtime_snapshot_token.is_empty() {
            println!("runtime_snapshot_token: {}", resp.runtime_snapshot_token);
        }
        print_confirmation(resp.confirmation.as_ref());
    }
    crate::output::print_next_step(
        json,
        "the transaction was rolled back — re-plan against the new runtime_snapshot_token (rbgp config plan)",
    );
    Ok(())
}

pub async fn status(connection: Connection, json: bool) -> Result<(), CliError> {
    let mut client =
        ConfigServiceClient::with_interceptor(connection.channel(), connection.interceptor());
    let resp = client
        .get_config_transaction_status(GetConfigTransactionStatusRequest {})
        .await?
        .into_inner();

    if json {
        print_json(status_to_json(&resp))?;
    } else {
        print!("{}", resp.human_text);
        print_confirmation(resp.confirmation.as_ref());
    }
    Ok(())
}

/// List the daemon's bounded mixed-generation config history: index,
/// timestamp, content hash, provenance status, and a one-line summary per
/// retained row (never config document contents).
pub async fn history(connection: Connection, json: bool) -> Result<(), CliError> {
    let mut client =
        ConfigServiceClient::with_interceptor(connection.channel(), connection.interceptor());
    let resp = client
        .list_config_history(ListConfigHistoryRequest {})
        .await?
        .into_inner();

    if json {
        print_json(history_to_json(&resp))?;
    } else {
        print_history_human(&resp);
    }
    Ok(())
}

/// Junos-style `rollback N`: the daemon resolves an eligible legacy or
/// provenance-verified v2 history row and routes it through the same
/// transaction path as apply with the same receipts.
pub async fn rollback(
    connection: Connection,
    options: RollbackOptions<'_>,
    json: bool,
) -> Result<(), CliError> {
    if options.index == 0 {
        return Err(CliError::Argument(
            "rollback index must be >= 1 (index 0 is the newest config-history row)".to_string(),
        ));
    }
    if options.confirm_id.is_none() && options.confirm_timeout_seconds.is_some() {
        return Err(CliError::Argument(
            "--confirm-timeout requires --confirm-id".to_string(),
        ));
    }
    if let Some(confirm_id) = options.confirm_id {
        validate_confirm_id(confirm_id)?;
    }
    if matches!(
        options.confirm_timeout_seconds,
        Some(timeout_seconds) if timeout_seconds > MAX_CONFIRM_TIMEOUT_SECONDS
    ) {
        return Err(CliError::Argument(format!(
            "--confirm-timeout must be <= {MAX_CONFIRM_TIMEOUT_SECONDS}"
        )));
    }
    let mut client =
        ConfigServiceClient::with_interceptor(connection.channel(), connection.interceptor());
    let resp = client
        .rollback_config_transaction(RollbackConfigTransactionRequest {
            index: options.index,
            expected_runtime_snapshot_token: options
                .expected_runtime_snapshot_token
                .unwrap_or_default()
                .to_string(),
            client_request_id: options.client_request_id.unwrap_or_default().to_string(),
            comment: options.comment.unwrap_or_default().to_string(),
            confirm_id: options.confirm_id.unwrap_or_default().to_string(),
            confirm_timeout_seconds: options.confirm_timeout_seconds.unwrap_or_default(),
        })
        .await?
        .into_inner();

    // A rollback receipt is an apply receipt — same shape, same printers.
    if json {
        print_json(apply_to_json(&resp))?;
    } else {
        print_apply_human(&resp);
    }
    if let Some(footer) = confirm_window_footer(resp.confirmation.as_ref()) {
        crate::output::print_next_step(json, &footer);
    }
    Ok(())
}

fn history_to_json(resp: &ListConfigHistoryResponse) -> serde_json::Value {
    serde_json::json!({
        "entries": resp.entries.iter().map(|entry| serde_json::json!({
            "index": entry.index,
            "timestamp_unix_seconds": entry.timestamp_unix_seconds,
            "timestamp": format_unix_utc(entry.timestamp_unix_seconds),
            "sha256": entry.sha256,
            "summary": entry.summary,
            "source_sha256": entry.source_sha256,
            "provenance_status": history_provenance_label(entry.provenance_status),
        })).collect::<Vec<_>>(),
        "human_text": resp.human_text,
    })
}

fn print_history_human(resp: &ListConfigHistoryResponse) {
    for entry in &resp.entries {
        println!("{}", history_human_line(entry));
    }
    print!("{}", resp.human_text);
}

fn history_human_line(entry: &crate::proto::ConfigHistoryEntry) -> String {
    let short_hash = if entry.sha256.is_empty() {
        "-"
    } else {
        entry.sha256.get(..12).unwrap_or(&entry.sha256)
    };
    format!(
        "{:>3}  {}  {}  {}{}  provenance={} source_sha256={}",
        entry.index,
        format_unix_utc(entry.timestamp_unix_seconds),
        short_hash,
        entry.summary,
        history_index_marker(entry.index),
        history_provenance_label(entry.provenance_status),
        if entry.source_sha256.is_empty() {
            "-"
        } else {
            &entry.source_sha256
        },
    )
}

fn history_provenance_label(status: i32) -> &'static str {
    match crate::proto::ConfigHistoryProvenanceStatus::try_from(status) {
        Ok(crate::proto::ConfigHistoryProvenanceStatus::Recorded) => "recorded",
        Ok(crate::proto::ConfigHistoryProvenanceStatus::LegacyTomlOnly) => "legacy_toml_only",
        Ok(crate::proto::ConfigHistoryProvenanceStatus::Unreadable) => "unreadable",
        Ok(crate::proto::ConfigHistoryProvenanceStatus::Unspecified) | Err(_) => "unknown",
    }
}

fn history_index_marker(index: u32) -> &'static str {
    if index == 0 { " (latest)" } else { "" }
}

/// Render unix seconds as `YYYY-MM-DDTHH:MM:SSZ` without a date dependency
/// (Howard Hinnant's civil-from-days algorithm).
fn format_unix_utc(unix_seconds: u64) -> String {
    let days = i64::try_from(unix_seconds / 86_400).unwrap_or(i64::MAX);
    let secs_of_day = unix_seconds % 86_400;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if month <= 2 { year + 1 } else { year };
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        secs_of_day / 3_600,
        (secs_of_day % 3_600) / 60,
        secs_of_day % 60,
    )
}

/// Dump the daemon's effective running config: normalized TOML with
/// defaults resolved, selected default-empty policy lists omitted, and secrets
/// redacted server-side. `--json` re-renders the same document as JSON; the
/// daemon only ships TOML.
pub async fn effective(connection: Connection, json: bool) -> Result<(), CliError> {
    let mut client =
        ConfigServiceClient::with_interceptor(connection.channel(), connection.interceptor());
    let resp = client
        .get_effective_config(GetEffectiveConfigRequest {})
        .await?
        .into_inner();

    if json {
        print_json(effective_to_json(&resp.toml)?)?;
    } else {
        print!("{}", resp.toml);
    }
    Ok(())
}

/// Re-render the daemon's effective-config TOML document as JSON for `-j`.
fn effective_to_json(toml_text: &str) -> Result<serde_json::Value, CliError> {
    let value: toml::Value = toml::from_str(toml_text).map_err(|error| {
        CliError::Argument(format!(
            "daemon returned unparseable effective config TOML: {error}"
        ))
    })?;
    serde_json::to_value(value).map_err(|error| {
        CliError::Argument(format!(
            "failed to convert effective config to JSON: {error}"
        ))
    })
}

fn read_candidate_toml(from_file: &str) -> Result<String, CliError> {
    std::fs::read_to_string(from_file)
        .map_err(|error| CliError::Argument(format!("failed to read {from_file}: {error}")))
}

fn preflight_config_request(request: &impl Message, from_file: &str) -> Result<(), CliError> {
    let encoded_size = request.encoded_len();
    if encoded_size <= MAX_UNARY_CONFIG_REQUEST_BYTES {
        return Ok(());
    }

    Err(CliError::Argument(format!(
        "config request encoded size {encoded_size} bytes exceeds the {MAX_UNARY_CONFIG_REQUEST_BYTES}-byte gRPC unary request limit for candidate file {from_file}; run `rustbgpd --check` against that candidate, then coordinate replacement of the daemon config file and send SIGHUP. This fallback does not provide transactional apply or commit-confirm semantics"
    )))
}

fn validate_confirm_id(confirm_id: &str) -> Result<(), CliError> {
    if confirm_id.trim().is_empty() {
        return Err(CliError::Argument(
            "confirm_id must not be empty".to_string(),
        ));
    }
    if confirm_id.chars().count() > MAX_CONFIRM_ID_CHARS {
        return Err(CliError::Argument(format!(
            "confirm_id must be at most {MAX_CONFIRM_ID_CHARS} characters"
        )));
    }
    if confirm_id.chars().any(char::is_control) {
        return Err(CliError::Argument(
            "confirm_id must not contain control characters".to_string(),
        ));
    }
    Ok(())
}

fn print_json(value: serde_json::Value) -> Result<(), CliError> {
    output::print_json_pretty(&value)
}

fn status_label(status: i32) -> &'static str {
    match ConfigTransactionPlanStatus::try_from(status)
        .unwrap_or(ConfigTransactionPlanStatus::Unspecified)
    {
        ConfigTransactionPlanStatus::Unspecified => "unspecified",
        ConfigTransactionPlanStatus::Noop => "noop",
        ConfigTransactionPlanStatus::Committable => "committable",
        ConfigTransactionPlanStatus::Rejected => "rejected",
    }
}

fn confirmation_status_label(status: i32) -> &'static str {
    match ConfigTransactionConfirmationStatus::try_from(status)
        .unwrap_or(ConfigTransactionConfirmationStatus::Unspecified)
    {
        ConfigTransactionConfirmationStatus::Unspecified => "unspecified",
        ConfigTransactionConfirmationStatus::None => "none",
        ConfigTransactionConfirmationStatus::Pending => "pending",
        ConfigTransactionConfirmationStatus::Confirmed => "confirmed",
        ConfigTransactionConfirmationStatus::Aborted => "aborted",
        ConfigTransactionConfirmationStatus::AutoReverted => "auto_reverted",
        ConfigTransactionConfirmationStatus::AutoRevertFailed => "auto_revert_failed",
        ConfigTransactionConfirmationStatus::AbortFailed => "abort_failed",
    }
}

fn diff_to_json(diff: Option<&DiffRuntimeConfigResponse>) -> serde_json::Value {
    let Some(diff) = diff else {
        return serde_json::Value::Null;
    };
    let parsed_diff_json = serde_json::from_str(&diff.diff_json)
        .unwrap_or_else(|_| serde_json::Value::String(diff.diff_json.clone()));
    serde_json::json!({
        "has_actionable_changes": diff.has_actionable_changes,
        "has_reload_applied_changes": diff.has_reload_applied_changes,
        "has_restart_required_changes": diff.has_restart_required_changes,
        "has_informational_changes": diff.has_informational_changes,
        "has_any_changes": diff.has_any_changes,
        "human_text": diff.human_text,
        "diff_json": parsed_diff_json,
    })
}

fn plan_to_json(
    resp: &ConfigTransactionPlanResponse,
    plan_token: Option<&str>,
) -> serde_json::Value {
    serde_json::json!({
        "status": status_label(resp.status),
        "runtime_snapshot_token": resp.runtime_snapshot_token,
        "diff": diff_to_json(resp.diff.as_ref()),
        "supported_sections": resp.supported_sections,
        "unsupported_sections": resp.unsupported_sections,
        "restart_required_sections": resp.restart_required_sections,
        "human_text": resp.human_text,
        "update_group_impact": update_group_impact_to_json(resp.update_group_impact.as_ref()),
        "plan_token": plan_token,
    })
}

fn apply_to_json(resp: &ConfigTransactionApplyResponse) -> serde_json::Value {
    serde_json::json!({
        "status": status_label(resp.status),
        "runtime_snapshot_token": resp.runtime_snapshot_token,
        "committed_sections": resp.committed_sections,
        "human_text": resp.human_text,
        "confirmation": confirmation_to_json(resp.confirmation.as_ref()),
        "update_group_impact": update_group_impact_to_json(resp.update_group_impact.as_ref()),
    })
}

fn update_group_impact_to_json(plan: Option<&UpdateGroupImpactPlan>) -> serde_json::Value {
    let Some(plan) = plan else {
        return serde_json::Value::Null;
    };
    let rollup = plan.rollup.as_ref();
    serde_json::json!({
        "schema_version": plan.schema_version,
        "entries": plan.entries.iter().map(|row| serde_json::json!({
            "peer": row.peer, "afi": row.afi, "safi": row.safi,
            "current": row.current, "candidate": row.candidate,
            "transition": row.transition, "reason": row.reason,
            "provenance": row.provenance, "local_resync": row.local_resync,
            "remote_route_refresh": row.remote_route_refresh,
        })).collect::<Vec<_>>(),
        "rollup": rollup.map(|value| serde_json::json!({
            "affected_peers": value.affected_peers,
            "affected_families": value.affected_families,
            "no_op": value.no_op, "regroup": value.regroup,
            "shared_migration": value.shared_migration,
            "private_resync": value.private_resync,
            "indeterminate": value.indeterminate,
            "projected_shared_groups": value.projected_shared_groups,
            "projected_private_views": value.projected_private_views,
            "local_resyncs": value.local_resyncs,
            "remote_route_refreshes": value.remote_route_refreshes,
        })),
        "capacity_class": plan.capacity_class,
        "capacity_basis": plan.capacity_basis,
    })
}

fn print_update_group_impact(plan: Option<&UpdateGroupImpactPlan>) {
    let Some(plan) = plan else {
        return;
    };
    if let Some(rollup) = &plan.rollup {
        println!(
            "update_group_impact_v{}: affected_peers={} affected_families={} shared_groups={} private_views={} capacity={} ({})",
            plan.schema_version,
            rollup.affected_peers,
            rollup.affected_families,
            rollup.projected_shared_groups,
            rollup.projected_private_views,
            plan.capacity_class,
            plan.capacity_basis
        );
    }
    for row in &plan.entries {
        if row.transition != "no_op" {
            println!(
                "  {} afi/safi {}/{}: {} -> {} [{}; local_resync={}; route_refresh={}]",
                row.peer,
                row.afi,
                row.safi,
                row.current,
                row.candidate,
                row.transition,
                row.local_resync,
                row.remote_route_refresh
            );
        }
    }
}

fn confirmation_to_json(confirmation: Option<&ConfigTransactionConfirmation>) -> serde_json::Value {
    let Some(confirmation) = confirmation else {
        return serde_json::Value::Null;
    };
    serde_json::json!({
        "status": confirmation_status_label(confirmation.status),
        "confirm_id": confirmation.confirm_id,
        "timeout_seconds": confirmation.timeout_seconds,
        "deadline_unix_seconds": confirmation.deadline_unix_seconds,
        "committed_sections": confirmation.committed_sections,
        "runtime_snapshot_token": confirmation.runtime_snapshot_token,
        "human_text": confirmation.human_text,
    })
}

fn status_to_json(resp: &ConfigTransactionStatusResponse) -> serde_json::Value {
    serde_json::json!({
        "confirmation": confirmation_to_json(resp.confirmation.as_ref()),
        "human_text": resp.human_text,
    })
}

fn print_plan_human(resp: &ConfigTransactionPlanResponse) {
    print!("{}", resp.human_text);
    print_transaction_tail(
        resp.status,
        &resp.runtime_snapshot_token,
        &[
            ("supported_sections", &resp.supported_sections),
            ("unsupported_sections", &resp.unsupported_sections),
            ("restart_required_sections", &resp.restart_required_sections),
        ],
    );
    print_update_group_impact(resp.update_group_impact.as_ref());
}

fn print_apply_human(resp: &ConfigTransactionApplyResponse) {
    print!("{}", resp.human_text);
    print_transaction_tail(
        resp.status,
        &resp.runtime_snapshot_token,
        &[("committed_sections", &resp.committed_sections)],
    );
    print_confirmation(resp.confirmation.as_ref());
    print_update_group_impact(resp.update_group_impact.as_ref());
}

fn print_confirmation(confirmation: Option<&ConfigTransactionConfirmation>) {
    let Some(confirmation) = confirmation else {
        return;
    };
    println!(
        "confirmation_status: {}",
        confirmation_status_label(confirmation.status)
    );
    if !confirmation.confirm_id.is_empty() {
        println!("confirm_id: {}", confirmation.confirm_id);
    }
    if confirmation.timeout_seconds > 0 {
        println!("confirm_timeout_seconds: {}", confirmation.timeout_seconds);
    }
    if confirmation.deadline_unix_seconds > 0 {
        println!(
            "confirm_deadline_unix_seconds: {}",
            confirmation.deadline_unix_seconds
        );
    }
    if !confirmation.runtime_snapshot_token.is_empty() {
        println!(
            "confirmation_runtime_snapshot_token: {}",
            confirmation.runtime_snapshot_token
        );
    }
    if !confirmation.committed_sections.is_empty() {
        println!(
            "confirmation_committed_sections: {}",
            confirmation.committed_sections.join(", ")
        );
    }
}

fn print_transaction_tail(
    status: i32,
    runtime_snapshot_token: &str,
    sections: &[(&str, &Vec<String>)],
) {
    println!("status: {}", status_label(status));
    if !runtime_snapshot_token.is_empty() {
        println!("runtime_snapshot_token: {runtime_snapshot_token}");
    }
    for (label, values) in sections {
        if !values.is_empty() {
            println!("{label}: {}", values.join(", "));
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::Ordering;

    use super::*;
    use crate::connection::connect;
    use crate::test_support::spawn_mock_server;
    use tonic::codegen::tokio_stream::StreamExt as _;

    // Field 1's one-byte tag plus the four-byte length varint used by a
    // candidate whose encoded request reaches the 4 MiB boundary.
    const PROTOBUF_STRING_FIELD_OVERHEAD_AT_LIMIT: usize = 5;

    #[tokio::test]
    async fn frame_streams_share_candidate_and_materialize_one_bounded_chunk_at_a_time() {
        let candidate = Arc::new("x".repeat(8 * 1024 * 1024 + 17));
        let mut stream = PlanFrameStream::new(Arc::clone(&candidate), Some("kv1:old:1"));
        assert!(Arc::ptr_eq(&candidate, &stream.cursor.candidate));
        assert_eq!(Arc::strong_count(&candidate), 2);
        let metadata = stream.next().await.unwrap();
        assert!(matches!(
            metadata.frame,
            Some(crate::proto::stream_plan_config_transaction_request::Frame::Metadata(_))
        ));
        assert_eq!(stream.cursor.offset, 0);
        let chunk = stream.next().await.unwrap();
        let Some(crate::proto::stream_plan_config_transaction_request::Frame::CandidateChunk(
            chunk,
        )) = chunk.frame
        else {
            panic!("expected first candidate chunk");
        };
        assert_eq!(chunk.len(), STREAM_CONFIG_CHUNK_BYTES);
        assert_eq!(stream.cursor.offset, STREAM_CONFIG_CHUNK_BYTES);
        assert!(Arc::ptr_eq(&candidate, &stream.cursor.candidate));
        let mut streamed_bytes = chunk.len();
        drop(chunk);
        let mut end = None;
        while let Some(frame) = stream.next().await {
            match frame.frame.unwrap() {
                crate::proto::stream_plan_config_transaction_request::Frame::CandidateChunk(
                    chunk,
                ) => {
                    assert!(!chunk.is_empty());
                    assert!(chunk.len() <= STREAM_CONFIG_CHUNK_BYTES);
                    streamed_bytes += chunk.len();
                }
                crate::proto::stream_plan_config_transaction_request::Frame::End(value) => {
                    assert!(end.replace(value).is_none());
                }
                crate::proto::stream_plan_config_transaction_request::Frame::Metadata(_) => {
                    panic!("metadata repeated")
                }
            }
        }
        let end = end.expect("end frame");
        assert_eq!(streamed_bytes, candidate.len());
        assert_eq!(end.candidate_length, candidate.len() as u64);
        assert_eq!(
            end.candidate_sha256,
            Sha256::digest(candidate.as_bytes()).to_vec()
        );

        let metadata = StreamApplyConfigMetadata {
            version: STREAM_CONFIG_FRAME_VERSION,
            plan_token: "plan".to_string(),
            expected_runtime_snapshot_token: "runtime".to_string(),
            client_request_id: String::new(),
            comment: String::new(),
            confirm_id: String::new(),
            confirm_timeout_seconds: 0,
        };
        let mut apply_stream = ApplyFrameStream::new(Arc::clone(&candidate), metadata.clone());
        let first = apply_stream.next().await.unwrap();
        assert!(matches!(
            first.frame,
            Some(crate::proto::stream_apply_config_transaction_request::Frame::Metadata(value))
                if value == metadata
        ));
        assert!(Arc::ptr_eq(&candidate, &apply_stream.cursor.candidate));
        let mut apply_bytes = 0usize;
        let mut apply_end = None;
        while let Some(frame) = apply_stream.next().await {
            match frame.frame.unwrap() {
                crate::proto::stream_apply_config_transaction_request::Frame::CandidateChunk(
                    chunk,
                ) => {
                    assert!(!chunk.is_empty());
                    assert!(chunk.len() <= STREAM_CONFIG_CHUNK_BYTES);
                    apply_bytes += chunk.len();
                }
                crate::proto::stream_apply_config_transaction_request::Frame::End(value) => {
                    assert!(apply_end.replace(value).is_none());
                }
                crate::proto::stream_apply_config_transaction_request::Frame::Metadata(_) => {
                    panic!("apply metadata repeated")
                }
            }
        }
        let apply_end = apply_end.expect("apply end frame");
        assert_eq!(apply_bytes, candidate.len());
        assert_eq!(apply_end.candidate_length, candidate.len() as u64);
        assert_eq!(
            apply_end.candidate_sha256,
            Sha256::digest(candidate.as_bytes()).to_vec()
        );
    }

    #[tokio::test]
    async fn actual_rpcs_pull_plan_and_apply_frames_incrementally_under_backpressure() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("candidate.toml");
        let candidate_len = 16 * 1024 * 1024 + 17;
        let candidate = format!(
            "{LAZY_PULL_PROOF_MARKER}{}",
            "x".repeat(candidate_len - LAZY_PULL_PROOF_MARKER.len())
        );
        std::fs::write(&path, candidate).unwrap();
        let expected_frames = 1 + 17 + 1;
        let server = spawn_mock_server(None).await;
        server
            .state
            .config_streaming_enabled
            .store(true, Ordering::SeqCst);

        PLAN_FRAME_POLLS.store(0, Ordering::SeqCst);
        server
            .state
            .config_stream_plan_pause_after_metadata
            .store(true, Ordering::SeqCst);
        let connection = connect(&server.addr, None).await.unwrap();
        let plan_path = path.to_string_lossy().into_owned();
        let plan_task =
            tokio::spawn(
                async move { plan(connection, &plan_path, Some("kv1:planned:1"), true).await },
            );
        server
            .state
            .config_stream_plan_metadata_seen
            .notified()
            .await;
        tokio::task::yield_now().await;
        assert!(
            PLAN_FRAME_POLLS.load(Ordering::SeqCst) < expected_frames,
            "the Plan stream was fully materialized before the RPC accepted its first frame"
        );
        server.state.config_stream_plan_resume.notify_one();
        assert!(plan_task.await.unwrap().unwrap());
        assert_eq!(PLAN_FRAME_POLLS.load(Ordering::SeqCst), expected_frames);

        APPLY_FRAME_POLLS.store(0, Ordering::SeqCst);
        server
            .state
            .config_stream_apply_pause_after_metadata
            .store(true, Ordering::SeqCst);
        let connection = connect(&server.addr, None).await.unwrap();
        let apply_path = path.to_string_lossy().into_owned();
        let apply_task = tokio::spawn(async move {
            apply(
                connection,
                ApplyOptions {
                    from_file: &apply_path,
                    expected_runtime_snapshot_token: "kv1:planned:1",
                    plan_token: Some("stream-plan-token"),
                    client_request_id: None,
                    comment: None,
                    confirm_id: None,
                    confirm_timeout_seconds: None,
                },
                true,
            )
            .await
        });
        server
            .state
            .config_stream_apply_metadata_seen
            .notified()
            .await;
        tokio::task::yield_now().await;
        assert!(
            APPLY_FRAME_POLLS.load(Ordering::SeqCst) < expected_frames,
            "the Apply stream was fully materialized before the RPC accepted its first frame"
        );
        server.state.config_stream_apply_resume.notify_one();
        apply_task.await.unwrap().unwrap();
        assert_eq!(APPLY_FRAME_POLLS.load(Ordering::SeqCst), expected_frames);
    }

    fn candidate_at_diff_request_limit() -> String {
        "x".repeat(MAX_UNARY_CONFIG_REQUEST_BYTES - PROTOBUF_STRING_FIELD_OVERHEAD_AT_LIMIT)
    }

    #[tokio::test]
    async fn diff_sends_candidate_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("candidate.toml");
        std::fs::write(&path, "[global]\nasn = 65001\nrouter_id = \"10.0.0.1\"\n").unwrap();
        let server = spawn_mock_server(None).await;
        let connection = connect(&server.addr, None).await.unwrap();

        let has_changes = diff(connection, path.to_str().unwrap(), true)
            .await
            .unwrap();

        assert!(has_changes, "mock serves a changed diff → exit code 2");
        assert_eq!(server.state.config_diff_calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            server.state.last_config_diff.lock().await.as_deref(),
            Some("[global]\nasn = 65001\nrouter_id = \"10.0.0.1\"\n")
        );
    }

    #[tokio::test]
    async fn diff_accepts_request_at_exact_unary_limit() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("candidate.toml");
        let candidate = candidate_at_diff_request_limit();
        let request = DiffRuntimeConfigRequest {
            candidate_toml: candidate.clone(),
        };
        assert_eq!(request.encoded_len(), MAX_UNARY_CONFIG_REQUEST_BYTES);
        std::fs::write(&path, candidate).unwrap();
        let server = spawn_mock_server(None).await;
        let connection = connect(&server.addr, None).await.unwrap();

        diff(connection, path.to_str().unwrap(), true)
            .await
            .expect("an exactly-at-limit request must reach the RPC");

        assert_eq!(server.state.config_diff_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn diff_rejects_plus_one_before_rpc() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("candidate.toml");
        let mut candidate = candidate_at_diff_request_limit();
        candidate.push('x');
        let request = DiffRuntimeConfigRequest {
            candidate_toml: candidate.clone(),
        };
        assert_eq!(request.encoded_len(), MAX_UNARY_CONFIG_REQUEST_BYTES + 1);
        std::fs::write(&path, candidate).unwrap();
        let server = spawn_mock_server(None).await;
        let connection = connect(&server.addr, None).await.unwrap();

        let err = diff(connection, path.to_str().unwrap(), true)
            .await
            .expect_err("a plus-one request must fail before RPC");

        assert!(
            matches!(err, CliError::Argument(ref message)
                if message.contains("4194305 bytes")
                    && message.contains("4194304-byte")
                    && message.contains(path.to_str().unwrap())
                    && message.contains("rustbgpd --check")
                    && message.contains("replacement")
                    && message.contains("SIGHUP")
                    && message.contains("does not provide transactional apply or commit-confirm semantics")),
            "{err:?}"
        );
        assert_eq!(server.state.config_diff_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn diff_without_changes_reports_no_changes_for_exit_code_0() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("candidate.toml");
        std::fs::write(&path, "[global]\nasn = 65001\nrouter_id = \"10.0.0.1\"\n").unwrap();
        let server = spawn_mock_server(None).await;
        server
            .state
            .config_diff_no_changes
            .store(true, Ordering::SeqCst);
        let connection = connect(&server.addr, None).await.unwrap();

        let has_changes = diff(connection, path.to_str().unwrap(), true)
            .await
            .unwrap();

        assert!(!has_changes, "no-changes diff must map to exit code 0");
    }

    #[tokio::test]
    async fn diff_rpc_error_maps_to_cli_error_for_exit_code_1() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("candidate.toml");
        std::fs::write(&path, "[global]\nasn = 65001\nrouter_id = \"10.0.0.1\"\n").unwrap();
        let server = spawn_mock_server(None).await;
        *server.state.config_diff_error.lock().await = Some((
            tonic::Code::InvalidArgument,
            "candidate config invalid".to_string(),
        ));
        let connection = connect(&server.addr, None).await.unwrap();

        let result = diff(connection, path.to_str().unwrap(), true).await;

        assert!(result.is_err(), "daemon error must take the exit-1 path");
    }

    #[test]
    fn change_status_exit_codes_are_terraform_style() {
        assert_eq!(change_status_exit_code(false), 0);
        assert_eq!(change_status_exit_code(true), 2);
    }

    #[tokio::test]
    async fn effective_fetches_running_config() {
        let server = spawn_mock_server(None).await;
        let connection = connect(&server.addr, None).await.unwrap();

        effective(connection, false).await.unwrap();

        assert_eq!(
            server.state.config_effective_calls.load(Ordering::SeqCst),
            1
        );
    }

    #[tokio::test]
    async fn effective_json_renders_config_as_structured_json() {
        let server = spawn_mock_server(None).await;
        let connection = connect(&server.addr, None).await.unwrap();

        effective(connection, true).await.unwrap();

        assert_eq!(
            server.state.config_effective_calls.load(Ordering::SeqCst),
            1
        );
    }

    #[test]
    fn effective_to_json_produces_structured_config() {
        let value = effective_to_json(
            "[global]\nasn = 65000\nrouter_id = \"192.0.2.1\"\n\n[[neighbors]]\naddress = \"192.0.2.2\"\nhold_time = 90\nremote_asn = 65000\n",
        )
        .unwrap();
        assert_eq!(value["global"]["asn"], 65000);
        assert_eq!(value["neighbors"][0]["hold_time"], 90);
    }

    #[test]
    fn effective_to_json_rejects_unparseable_toml() {
        // A daemon reply that is not parseable TOML must error rather
        // than print garbage.
        assert!(effective_to_json("not = [valid").is_err());
    }

    #[tokio::test]
    async fn effective_rpc_error_maps_to_cli_error() {
        let server = spawn_mock_server(None).await;
        *server.state.config_effective_error.lock().await = Some((
            tonic::Code::PermissionDenied,
            "sensitive_read required".to_string(),
        ));
        let connection = connect(&server.addr, None).await.unwrap();

        let result = effective(connection, false).await;

        assert!(result.is_err(), "daemon error must take the exit-1 path");
    }

    #[tokio::test]
    async fn plan_sends_candidate_file_and_token() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("candidate.toml");
        std::fs::write(&path, "[global]\nasn = 65001\nrouter_id = \"10.0.0.1\"\n").unwrap();
        let server = spawn_mock_server(None).await;
        let connection = connect(&server.addr, None).await.unwrap();

        let has_changes = plan(connection, path.to_str().unwrap(), Some("kv1:old:1"), true)
            .await
            .unwrap();

        assert!(has_changes, "committable plan → exit code 2");
        assert_eq!(server.state.config_plan_calls.load(Ordering::SeqCst), 1);
        let request = server.state.last_config_plan.lock().await.clone().unwrap();
        assert_eq!(
            request.candidate_toml,
            "[global]\nasn = 65001\nrouter_id = \"10.0.0.1\"\n"
        );
        assert_eq!(request.expected_runtime_snapshot_token, "kv1:old:1");
    }

    #[tokio::test]
    async fn plan_rejects_oversized_populated_request_before_rpc() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("candidate.toml");
        std::fs::write(&path, candidate_at_diff_request_limit()).unwrap();
        let server = spawn_mock_server(None).await;
        let connection = connect(&server.addr, None).await.unwrap();

        let err = plan(
            connection,
            path.to_str().unwrap(),
            Some("plan-token-must-not-leak"),
            true,
        )
        .await
        .expect_err("an oversized plan request must fail before RPC");

        let CliError::Argument(message) = err else {
            panic!("expected a local argument error, got {err:?}");
        };
        assert!(!message.contains("plan-token-must-not-leak"));
        assert_eq!(server.state.config_plan_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn plan_noop_reports_no_changes_for_exit_code_0() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("candidate.toml");
        std::fs::write(&path, "[global]\nasn = 65001\nrouter_id = \"10.0.0.1\"\n").unwrap();
        let server = spawn_mock_server(None).await;
        server.state.config_plan_noop.store(true, Ordering::SeqCst);
        let connection = connect(&server.addr, None).await.unwrap();

        let has_changes = plan(connection, path.to_str().unwrap(), None, true)
            .await
            .unwrap();

        assert!(!has_changes, "noop plan must map to exit code 0");
    }

    #[tokio::test]
    async fn apply_sends_candidate_token_and_metadata() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("candidate.toml");
        std::fs::write(&path, "[global]\nasn = 65001\nrouter_id = \"10.0.0.1\"\n").unwrap();
        let server = spawn_mock_server(None).await;
        let connection = connect(&server.addr, None).await.unwrap();

        apply(
            connection,
            ApplyOptions {
                from_file: path.to_str().unwrap(),
                expected_runtime_snapshot_token: "kv1:old:1",
                plan_token: None,
                client_request_id: Some("deploy-123"),
                comment: Some("roll candidate"),
                confirm_id: Some("confirm-123"),
                confirm_timeout_seconds: Some(120),
            },
            true,
        )
        .await
        .unwrap();

        assert_eq!(server.state.config_apply_calls.load(Ordering::SeqCst), 1);
        let request = server.state.last_config_apply.lock().await.clone().unwrap();
        assert_eq!(
            request.candidate_toml,
            "[global]\nasn = 65001\nrouter_id = \"10.0.0.1\"\n"
        );
        assert_eq!(request.expected_runtime_snapshot_token, "kv1:old:1");
        assert_eq!(request.client_request_id, "deploy-123");
        assert_eq!(request.comment, "roll candidate");
        assert_eq!(request.confirm_id, "confirm-123");
        assert_eq!(request.confirm_timeout_seconds, 120);
    }

    #[tokio::test]
    async fn apply_auto_plans_and_streams_more_than_eight_mib_without_unary_calls() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("candidate.toml");
        let marker = b"STREAM_CLI_CANDIDATE_MARKER";
        let mut candidate = vec![b'x'; 8 * 1024 * 1024 + 19];
        candidate[..marker.len()].copy_from_slice(marker);
        std::fs::write(&path, &candidate).unwrap();
        let server = spawn_mock_server(None).await;
        server
            .state
            .config_streaming_enabled
            .store(true, Ordering::SeqCst);
        let connection = connect(&server.addr, None).await.unwrap();

        apply(
            connection,
            ApplyOptions {
                from_file: path.to_str().unwrap(),
                expected_runtime_snapshot_token: "kv1:planned:1",
                plan_token: None,
                client_request_id: None,
                comment: None,
                confirm_id: None,
                confirm_timeout_seconds: None,
            },
            true,
        )
        .await
        .unwrap();

        assert_eq!(
            server.state.config_stream_plan_calls.load(Ordering::SeqCst),
            1
        );
        assert_eq!(
            server
                .state
                .config_stream_apply_calls
                .load(Ordering::SeqCst),
            1
        );
        assert_eq!(server.state.config_plan_calls.load(Ordering::SeqCst), 0);
        assert_eq!(server.state.config_apply_calls.load(Ordering::SeqCst), 0);
        let metadata = server
            .state
            .last_stream_apply_metadata
            .lock()
            .await
            .clone()
            .unwrap();
        assert_eq!(metadata.plan_token, "stream-plan-token");
        assert_eq!(metadata.expected_runtime_snapshot_token, "kv1:planned:1");
        assert_eq!(
            server
                .state
                .last_stream_apply_candidate
                .lock()
                .await
                .as_deref(),
            Some(candidate.as_slice())
        );
    }

    #[tokio::test]
    async fn apply_with_explicit_plan_token_skips_plan_and_preserves_metadata() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("candidate.toml");
        std::fs::write(&path, "[global]\nasn = 65001\nrouter_id = \"10.0.0.1\"\n").unwrap();
        let server = spawn_mock_server(None).await;
        server
            .state
            .config_streaming_enabled
            .store(true, Ordering::SeqCst);
        let connection = connect(&server.addr, None).await.unwrap();

        apply(
            connection,
            ApplyOptions {
                from_file: path.to_str().unwrap(),
                expected_runtime_snapshot_token: "kv1:planned:1",
                plan_token: Some("manual-plan-token"),
                client_request_id: Some("stream-deploy"),
                comment: Some("safe rollout"),
                confirm_id: Some("stream-confirm"),
                confirm_timeout_seconds: Some(321),
            },
            true,
        )
        .await
        .unwrap();

        assert_eq!(
            server.state.config_stream_plan_calls.load(Ordering::SeqCst),
            0
        );
        assert_eq!(
            server
                .state
                .config_stream_apply_calls
                .load(Ordering::SeqCst),
            1
        );
        let metadata = server
            .state
            .last_stream_apply_metadata
            .lock()
            .await
            .clone()
            .unwrap();
        assert_eq!(metadata.plan_token, "manual-plan-token");
        assert_eq!(metadata.expected_runtime_snapshot_token, "kv1:planned:1");
        assert_eq!(metadata.client_request_id, "stream-deploy");
        assert_eq!(metadata.comment, "safe rollout");
        assert_eq!(metadata.confirm_id, "stream-confirm");
        assert_eq!(metadata.confirm_timeout_seconds, 321);
    }

    #[tokio::test]
    async fn implicit_plan_noop_or_rejected_returns_structured_success_without_apply() {
        for status in [
            ConfigTransactionPlanStatus::Noop,
            ConfigTransactionPlanStatus::Rejected,
        ] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("candidate.toml");
            std::fs::write(&path, "[global]\nasn = 65001\nrouter_id = \"10.0.0.1\"\n").unwrap();
            let server = spawn_mock_server(None).await;
            server
                .state
                .config_streaming_enabled
                .store(true, Ordering::SeqCst);
            server
                .state
                .config_stream_plan_status
                .store(status as usize, Ordering::SeqCst);
            let connection = connect(&server.addr, None).await.unwrap();

            let response = apply_response(
                connection,
                ApplyOptions {
                    from_file: path.to_str().unwrap(),
                    expected_runtime_snapshot_token: "kv1:planned:1",
                    plan_token: None,
                    client_request_id: None,
                    comment: None,
                    confirm_id: None,
                    confirm_timeout_seconds: None,
                },
            )
            .await
            .unwrap();

            assert_eq!(response.status, status as i32);
            assert_eq!(response.runtime_snapshot_token, "kv1:planned:1");
            assert!(response.committed_sections.is_empty());
            assert_eq!(
                response.human_text,
                "Config transaction is committable by v1.\n"
            );
            assert!(response.confirmation.is_none());
            assert!(response.update_group_impact.is_none());

            assert_eq!(
                server.state.config_stream_plan_calls.load(Ordering::SeqCst),
                1
            );
            assert_eq!(
                server
                    .state
                    .config_stream_apply_calls
                    .load(Ordering::SeqCst),
                0
            );
            assert_eq!(server.state.config_apply_calls.load(Ordering::SeqCst), 0);
        }
    }

    #[tokio::test]
    async fn implicit_plan_unknown_status_is_terminal_without_apply() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("candidate.toml");
        std::fs::write(&path, "[global]\nasn = 65001\nrouter_id = \"10.0.0.1\"\n").unwrap();
        let server = spawn_mock_server(None).await;
        server
            .state
            .config_streaming_enabled
            .store(true, Ordering::SeqCst);
        server
            .state
            .config_stream_plan_status
            .store(999, Ordering::SeqCst);
        let connection = connect(&server.addr, None).await.unwrap();

        let error = apply(
            connection,
            ApplyOptions {
                from_file: path.to_str().unwrap(),
                expected_runtime_snapshot_token: "kv1:planned:1",
                plan_token: None,
                client_request_id: None,
                comment: None,
                confirm_id: None,
                confirm_timeout_seconds: None,
            },
            true,
        )
        .await
        .unwrap_err();

        assert!(error.to_string().contains("invalid streamed plan status"));
        assert_eq!(
            server
                .state
                .config_stream_apply_calls
                .load(Ordering::SeqCst),
            0
        );
        assert_eq!(server.state.config_apply_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn streaming_call_sites_fallback_only_for_exact_empty_unimplemented() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("candidate.toml");
        std::fs::write(&path, "[global]\nasn = 65001\nrouter_id = \"10.0.0.1\"\n").unwrap();

        let exact = spawn_mock_server(None).await;
        exact
            .state
            .config_streaming_enabled
            .store(true, Ordering::SeqCst);
        *exact.state.config_stream_apply_error.lock().await =
            Some((tonic::Code::Unimplemented, String::new(), Vec::new()));
        let connection = connect(&exact.addr, None).await.unwrap();
        apply(
            connection,
            ApplyOptions {
                from_file: path.to_str().unwrap(),
                expected_runtime_snapshot_token: "kv1:planned:1",
                plan_token: None,
                client_request_id: None,
                comment: None,
                confirm_id: None,
                confirm_timeout_seconds: None,
            },
            true,
        )
        .await
        .unwrap();
        assert_eq!(
            exact.state.config_stream_plan_calls.load(Ordering::SeqCst),
            1
        );
        assert_eq!(exact.state.config_apply_calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            exact
                .state
                .last_config_apply
                .lock()
                .await
                .as_ref()
                .unwrap()
                .expected_runtime_snapshot_token,
            "kv1:planned:1"
        );

        for error in [
            (tonic::Code::Unimplemented, String::new(), Vec::new()),
            (
                tonic::Code::Unimplemented,
                "disabled".to_string(),
                Vec::new(),
            ),
            (tonic::Code::Unimplemented, String::new(), vec![1]),
            (tonic::Code::Unavailable, String::new(), Vec::new()),
        ] {
            let server = spawn_mock_server(None).await;
            *server.state.config_stream_apply_error.lock().await = Some(error);
            let connection = connect(&server.addr, None).await.unwrap();
            let result = apply(
                connection,
                ApplyOptions {
                    from_file: path.to_str().unwrap(),
                    expected_runtime_snapshot_token: "kv1:planned:1",
                    plan_token: Some("must-not-fallback"),
                    client_request_id: None,
                    comment: None,
                    confirm_id: None,
                    confirm_timeout_seconds: None,
                },
                true,
            )
            .await;
            assert!(result.is_err());
            assert_eq!(server.state.config_apply_calls.load(Ordering::SeqCst), 0);
        }

        for error in [
            (
                tonic::Code::Unimplemented,
                "disabled".to_string(),
                Vec::new(),
            ),
            (tonic::Code::Unimplemented, String::new(), vec![1]),
            (tonic::Code::Unavailable, String::new(), Vec::new()),
        ] {
            let server = spawn_mock_server(None).await;
            *server.state.config_stream_plan_error.lock().await = Some(error);
            let connection = connect(&server.addr, None).await.unwrap();
            let result = plan(
                connection,
                path.to_str().unwrap(),
                Some("kv1:planned:1"),
                true,
            )
            .await;
            assert!(result.is_err());
            assert_eq!(server.state.config_plan_calls.load(Ordering::SeqCst), 0);
        }
    }

    #[tokio::test]
    async fn apply_counts_metadata_and_redacts_oversize_error_before_rpc() {
        const CANDIDATE_SECRET: &str = "candidate-secret-must-not-leak";
        const TOKEN_SECRET: &str = "token-secret-must-not-leak";
        const COMMENT_SECRET: &str = "comment-secret-must-not-leak";

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("candidate.toml");
        let mut candidate = "x".repeat(
            MAX_UNARY_CONFIG_REQUEST_BYTES
                - PROTOBUF_STRING_FIELD_OVERHEAD_AT_LIMIT
                - CANDIDATE_SECRET.len(),
        );
        candidate.push_str(CANDIDATE_SECRET);
        assert_eq!(
            DiffRuntimeConfigRequest {
                candidate_toml: candidate.clone(),
            }
            .encoded_len(),
            MAX_UNARY_CONFIG_REQUEST_BYTES,
            "candidate-only arithmetic would admit this payload"
        );
        let populated_request = ApplyConfigTransactionRequest {
            candidate_toml: candidate.clone(),
            expected_runtime_snapshot_token: TOKEN_SECRET.to_string(),
            client_request_id: "deploy-secret-must-not-leak".to_string(),
            comment: COMMENT_SECRET.to_string(),
            confirm_id: "confirm-secret-must-not-leak".to_string(),
            confirm_timeout_seconds: 120,
        };
        let populated_size = populated_request.encoded_len();
        assert!(populated_size > MAX_UNARY_CONFIG_REQUEST_BYTES);
        std::fs::write(&path, candidate).unwrap();
        let server = spawn_mock_server(None).await;
        let connection = connect(&server.addr, None).await.unwrap();

        let err = apply(
            connection,
            ApplyOptions {
                from_file: path.to_str().unwrap(),
                expected_runtime_snapshot_token: TOKEN_SECRET,
                plan_token: None,
                client_request_id: Some("deploy-secret-must-not-leak"),
                comment: Some(COMMENT_SECRET),
                confirm_id: Some("confirm-secret-must-not-leak"),
                confirm_timeout_seconds: Some(120),
            },
            true,
        )
        .await
        .expect_err("metadata must push the populated apply request over the limit");

        let CliError::Argument(message) = err else {
            panic!("expected a local argument error, got {err:?}");
        };
        assert!(message.contains(&format!("{populated_size} bytes")));
        for secret in [
            CANDIDATE_SECRET,
            TOKEN_SECRET,
            "deploy-secret-must-not-leak",
            COMMENT_SECRET,
            "confirm-secret-must-not-leak",
        ] {
            assert!(!message.contains(secret), "error leaked {secret}");
        }
        assert_eq!(server.state.config_apply_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn apply_rejects_empty_local_metadata_before_rpc() {
        let server = spawn_mock_server(None).await;
        let connection = connect(&server.addr, None).await.unwrap();
        for (plan_token, confirm_id, timeout, expected) in [
            (Some(""), None, None, "--plan-token must not be empty"),
            (Some(" \t"), None, None, "--plan-token must not be empty"),
            (None, Some(""), Some(120), "confirm_id must not be empty"),
            (
                None,
                Some("bad\nid"),
                Some(120),
                "confirm_id must not contain control characters",
            ),
        ] {
            let err = apply(
                connection.clone(),
                ApplyOptions {
                    from_file: "/does/not/matter.toml",
                    expected_runtime_snapshot_token: "kv1:old:1",
                    plan_token,
                    client_request_id: None,
                    comment: None,
                    confirm_id,
                    confirm_timeout_seconds: timeout,
                },
                true,
            )
            .await
            .expect_err("empty local metadata must fail before file access or RPC");
            assert!(matches!(err, CliError::Argument(ref message) if message == expected));
        }
    }

    #[tokio::test]
    async fn apply_rejects_too_long_confirm_id_before_rpc() {
        let server = spawn_mock_server(None).await;
        let connection = connect(&server.addr, None).await.unwrap();
        let confirm_id = "x".repeat(MAX_CONFIRM_ID_CHARS + 1);

        let err = apply(
            connection,
            ApplyOptions {
                from_file: "/does/not/matter.toml",
                expected_runtime_snapshot_token: "kv1:old:1",
                plan_token: None,
                client_request_id: None,
                comment: None,
                confirm_id: Some(confirm_id.as_str()),
                confirm_timeout_seconds: Some(120),
            },
            true,
        )
        .await
        .expect_err("over-limit confirm_id must fail before RPC");

        assert!(
            matches!(err, CliError::Argument(ref message) if message == "confirm_id must be at most 128 characters"),
            "{err:?}"
        );
        assert_eq!(server.state.config_apply_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn apply_rejects_confirm_timeout_without_confirm_id_before_rpc() {
        let server = spawn_mock_server(None).await;
        let connection = connect(&server.addr, None).await.unwrap();

        let err = apply(
            connection,
            ApplyOptions {
                from_file: "/does/not/matter.toml",
                expected_runtime_snapshot_token: "kv1:old:1",
                plan_token: None,
                client_request_id: None,
                comment: None,
                confirm_id: None,
                confirm_timeout_seconds: Some(120),
            },
            true,
        )
        .await
        .expect_err("confirm timeout without confirm_id must fail before RPC");

        assert!(
            matches!(err, CliError::Argument(ref message) if message == "--confirm-timeout requires --confirm-id"),
            "{err:?}"
        );
        assert_eq!(server.state.config_apply_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn apply_rejects_too_large_confirm_timeout_before_rpc() {
        let server = spawn_mock_server(None).await;
        let connection = connect(&server.addr, None).await.unwrap();

        let err = apply(
            connection,
            ApplyOptions {
                from_file: "/does/not/matter.toml",
                expected_runtime_snapshot_token: "kv1:old:1",
                plan_token: None,
                client_request_id: None,
                comment: None,
                confirm_id: Some("deploy-123"),
                confirm_timeout_seconds: Some(MAX_CONFIRM_TIMEOUT_SECONDS + 1),
            },
            true,
        )
        .await
        .expect_err("over-limit confirm timeout must fail before RPC");

        assert!(
            matches!(err, CliError::Argument(ref message) if message == "--confirm-timeout must be <= 86400"),
            "{err:?}"
        );
        assert_eq!(server.state.config_apply_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn confirm_sends_confirm_id() {
        let server = spawn_mock_server(None).await;
        let connection = connect(&server.addr, None).await.unwrap();

        confirm(connection, "confirm-123", true).await.unwrap();

        assert_eq!(server.state.config_confirm_calls.load(Ordering::SeqCst), 1);
        let request = server
            .state
            .last_config_confirm
            .lock()
            .await
            .clone()
            .unwrap();
        assert_eq!(request.confirm_id, "confirm-123");
    }

    #[tokio::test]
    async fn confirm_rejects_empty_confirm_id_before_rpc() {
        let server = spawn_mock_server(None).await;
        let connection = connect(&server.addr, None).await.unwrap();

        let err = confirm(connection, "", true)
            .await
            .expect_err("empty confirm_id must fail before RPC");

        assert!(
            matches!(err, CliError::Argument(ref message) if message == "confirm_id must not be empty"),
            "{err:?}"
        );
        assert_eq!(server.state.config_confirm_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn confirm_rejects_invalid_confirm_id_before_rpc() {
        let server = spawn_mock_server(None).await;
        let connection = connect(&server.addr, None).await.unwrap();

        let err = confirm(connection, "   ", true)
            .await
            .expect_err("blank confirm_id must fail before RPC");
        assert!(
            matches!(err, CliError::Argument(ref message) if message == "confirm_id must not be empty"),
            "{err:?}"
        );

        let connection = connect(&server.addr, None).await.unwrap();
        let err = confirm(connection, "bad\nid", true)
            .await
            .expect_err("control-character confirm_id must fail before RPC");
        assert!(
            matches!(err, CliError::Argument(ref message) if message == "confirm_id must not contain control characters"),
            "{err:?}"
        );

        assert_eq!(server.state.config_confirm_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn confirm_rpc_error_maps_to_cli_error() {
        let server = spawn_mock_server(None).await;
        *server.state.config_confirm_error.lock().await =
            Some((tonic::Code::FailedPrecondition, "no pending".to_string()));
        let connection = connect(&server.addr, None).await.unwrap();

        let err = confirm(connection, "confirm-123", true)
            .await
            .expect_err("confirm RPC error must surface as CLI error");

        assert!(
            matches!(err, CliError::Rpc(ref message) if message.contains("no pending")),
            "{err:?}"
        );
        assert_eq!(server.state.config_confirm_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn abort_sends_confirm_id() {
        let server = spawn_mock_server(None).await;
        let connection = connect(&server.addr, None).await.unwrap();

        abort(connection, "confirm-123", true).await.unwrap();

        assert_eq!(server.state.config_abort_calls.load(Ordering::SeqCst), 1);
        let request = server.state.last_config_abort.lock().await.clone().unwrap();
        assert_eq!(request.confirm_id, "confirm-123");
    }

    #[tokio::test]
    async fn abort_rejects_empty_confirm_id_before_rpc() {
        let server = spawn_mock_server(None).await;
        let connection = connect(&server.addr, None).await.unwrap();

        let err = abort(connection, "", true)
            .await
            .expect_err("empty confirm_id must fail before RPC");

        assert!(
            matches!(err, CliError::Argument(ref message) if message == "confirm_id must not be empty"),
            "{err:?}"
        );
        assert_eq!(server.state.config_abort_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn abort_rejects_too_long_confirm_id_before_rpc() {
        let server = spawn_mock_server(None).await;
        let connection = connect(&server.addr, None).await.unwrap();
        let confirm_id = "x".repeat(MAX_CONFIRM_ID_CHARS + 1);

        let err = abort(connection, &confirm_id, true)
            .await
            .expect_err("over-limit confirm_id must fail before RPC");

        assert!(
            matches!(err, CliError::Argument(ref message) if message == "confirm_id must be at most 128 characters"),
            "{err:?}"
        );
        assert_eq!(server.state.config_abort_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn abort_rejects_control_char_confirm_id_before_rpc() {
        let server = spawn_mock_server(None).await;
        let connection = connect(&server.addr, None).await.unwrap();

        let err = abort(connection, "bad\nid", true)
            .await
            .expect_err("control-character confirm_id must fail before RPC");

        assert!(
            matches!(err, CliError::Argument(ref message) if message == "confirm_id must not contain control characters"),
            "{err:?}"
        );
        assert_eq!(server.state.config_abort_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn abort_rpc_error_maps_to_cli_error() {
        let server = spawn_mock_server(None).await;
        *server.state.config_abort_error.lock().await =
            Some((tonic::Code::Internal, "abort failed".to_string()));
        let connection = connect(&server.addr, None).await.unwrap();

        let err = abort(connection, "confirm-123", true)
            .await
            .expect_err("abort RPC error must surface as CLI error");

        assert!(
            matches!(err, CliError::Rpc(ref message) if message.contains("abort failed")),
            "{err:?}"
        );
        assert_eq!(server.state.config_abort_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn status_calls_config_status_rpc() {
        let server = spawn_mock_server(None).await;
        let connection = connect(&server.addr, None).await.unwrap();

        status(connection, true).await.unwrap();

        assert_eq!(server.state.config_status_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn status_rpc_error_maps_to_cli_error() {
        let server = spawn_mock_server(None).await;
        *server.state.config_status_error.lock().await =
            Some((tonic::Code::Internal, "status unavailable".to_string()));
        let connection = connect(&server.addr, None).await.unwrap();

        let err = status(connection, true)
            .await
            .expect_err("status RPC error must surface as CLI error");

        assert!(
            matches!(err, CliError::Rpc(ref message) if message.contains("status unavailable")),
            "{err:?}"
        );
        assert_eq!(server.state.config_status_calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn confirm_window_footer_only_for_pending_confirmations() {
        let pending = ConfigTransactionConfirmation {
            status: ConfigTransactionConfirmationStatus::Pending as i32,
            confirm_id: "deploy-1".to_string(),
            timeout_seconds: 120,
            deadline_unix_seconds: 0,
            committed_sections: Vec::new(),
            runtime_snapshot_token: String::new(),
            human_text: String::new(),
        };
        let footer = confirm_window_footer(Some(&pending)).unwrap();
        assert!(footer.contains("rbgp config confirm deploy-1"), "{footer}");
        assert!(footer.contains("rbgp config abort deploy-1"), "{footer}");

        let mut confirmed = pending.clone();
        confirmed.status = ConfigTransactionConfirmationStatus::Confirmed as i32;
        assert!(confirm_window_footer(Some(&confirmed)).is_none());
        assert!(confirm_window_footer(None).is_none());
    }

    #[test]
    fn confirmation_status_labels_include_abort_failed() {
        assert_eq!(
            confirmation_status_label(ConfigTransactionConfirmationStatus::AbortFailed as i32),
            "abort_failed"
        );
    }

    #[test]
    fn plan_json_shape_is_stable() {
        let value = plan_to_json(
            &ConfigTransactionPlanResponse {
                status: ConfigTransactionPlanStatus::Committable as i32,
                runtime_snapshot_token: "kv1:planned:1".to_string(),
                diff: Some(DiffRuntimeConfigResponse {
                    has_actionable_changes: true,
                    has_reload_applied_changes: true,
                    has_restart_required_changes: false,
                    has_informational_changes: false,
                    has_any_changes: true,
                    human_text: "Reload-applied changes:\n".to_string(),
                    diff_json: "{\"reload_applied\":{}}".to_string(),
                }),
                supported_sections: vec!["[[fib_tables]]".to_string()],
                unsupported_sections: vec!["[policy]".to_string()],
                restart_required_sections: vec!["[global]".to_string()],
                human_text: "Config transaction is rejected.\n".to_string(),
                update_group_impact: Some(UpdateGroupImpactPlan {
                    schema_version: 1,
                    entries: vec![crate::proto::UpdateGroupFamilyImpact {
                        peer: "192.0.2.1".to_string(),
                        afi: 1,
                        safi: 1,
                        current: "plan-group-001".to_string(),
                        candidate: "policy_peer_context".to_string(),
                        transition: "private_resync".to_string(),
                        reason: "policy_peer_context".to_string(),
                        provenance: "runtime_groupability_classifier".to_string(),
                        local_resync: true,
                        remote_route_refresh: false,
                    }],
                    rollup: Some(crate::proto::UpdateGroupImpactRollup {
                        affected_peers: 1,
                        affected_families: 1,
                        no_op: 0,
                        regroup: 0,
                        shared_migration: 0,
                        private_resync: 1,
                        indeterminate: 0,
                        projected_shared_groups: 0,
                        projected_private_views: 1,
                        local_resyncs: 1,
                        remote_route_refreshes: 0,
                    }),
                    capacity_class: "within_mixed".to_string(),
                    capacity_basis: "receipt envelope".to_string(),
                }),
            },
            None,
        );

        assert_eq!(value["status"], "committable");
        assert!(value["plan_token"].is_null());
        assert_eq!(value["runtime_snapshot_token"], "kv1:planned:1");
        assert_eq!(value["supported_sections"][0], "[[fib_tables]]");
        assert_eq!(value["unsupported_sections"][0], "[policy]");
        assert_eq!(value["update_group_impact"]["schema_version"], 1);
        assert_eq!(
            value["update_group_impact"]["entries"][0]["transition"],
            "private_resync"
        );
        assert_eq!(value["restart_required_sections"][0], "[global]");
        assert_eq!(
            value["diff"]["diff_json"]["reload_applied"],
            serde_json::json!({})
        );
    }

    #[test]
    fn apply_json_shape_is_stable() {
        let value = apply_to_json(&ConfigTransactionApplyResponse {
            status: ConfigTransactionPlanStatus::Committable as i32,
            runtime_snapshot_token: "kv1:committed:2".to_string(),
            committed_sections: vec!["[[dynamic_neighbors]]".to_string()],
            human_text: "Committed [[dynamic_neighbors]] transaction.\n".to_string(),
            confirmation: Some(ConfigTransactionConfirmation {
                status: ConfigTransactionConfirmationStatus::Pending as i32,
                confirm_id: "confirm-123".to_string(),
                timeout_seconds: 120,
                deadline_unix_seconds: 1_787_000_000,
                committed_sections: vec!["[[dynamic_neighbors]]".to_string()],
                runtime_snapshot_token: "kv1:committed:2".to_string(),
                human_text: "Confirmed config transaction is pending confirmation.".to_string(),
            }),
            update_group_impact: None,
        });

        assert_eq!(value["status"], "committable");
        assert_eq!(value["runtime_snapshot_token"], "kv1:committed:2");
        assert_eq!(value["committed_sections"][0], "[[dynamic_neighbors]]");
        assert_eq!(
            value["human_text"],
            "Committed [[dynamic_neighbors]] transaction.\n"
        );
        assert_eq!(value["confirmation"]["status"], "pending");
        assert_eq!(value["confirmation"]["confirm_id"], "confirm-123");
        assert_eq!(value["confirmation"]["timeout_seconds"], 120);
        assert_eq!(
            value["confirmation"]["committed_sections"][0],
            "[[dynamic_neighbors]]"
        );
    }

    #[test]
    fn status_json_shape_is_stable() {
        let value = status_to_json(&ConfigTransactionStatusResponse {
            confirmation: Some(ConfigTransactionConfirmation {
                status: ConfigTransactionConfirmationStatus::Pending as i32,
                confirm_id: "confirm-123".to_string(),
                timeout_seconds: 120,
                deadline_unix_seconds: 1_787_000_000,
                committed_sections: vec!["[[dynamic_neighbors]]".to_string()],
                runtime_snapshot_token: "kv1:committed:2".to_string(),
                human_text: "Confirmed config transaction is pending confirmation.".to_string(),
            }),
            human_text: "Confirmed config transaction pending.\n".to_string(),
        });

        assert_eq!(
            value["human_text"],
            "Confirmed config transaction pending.\n"
        );
        assert_eq!(value["confirmation"]["status"], "pending");
        assert_eq!(value["confirmation"]["confirm_id"], "confirm-123");
        assert_eq!(value["confirmation"]["timeout_seconds"], 120);
        assert_eq!(
            value["confirmation"]["deadline_unix_seconds"],
            1_787_000_000u64
        );
        assert_eq!(
            value["confirmation"]["committed_sections"][0],
            "[[dynamic_neighbors]]"
        );
        assert_eq!(
            value["confirmation"]["runtime_snapshot_token"],
            "kv1:committed:2"
        );
    }

    #[tokio::test]
    async fn history_calls_list_config_history_rpc() {
        let server = spawn_mock_server(None).await;
        let connection = connect(&server.addr, None).await.unwrap();

        history(connection, true).await.unwrap();

        assert_eq!(server.state.config_history_calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn history_json_shape_is_stable() {
        let value = history_to_json(&ListConfigHistoryResponse {
            entries: [
                crate::proto::ConfigHistoryProvenanceStatus::Recorded as i32,
                crate::proto::ConfigHistoryProvenanceStatus::LegacyTomlOnly as i32,
                crate::proto::ConfigHistoryProvenanceStatus::Unreadable as i32,
                crate::proto::ConfigHistoryProvenanceStatus::Unspecified as i32,
                999,
            ]
            .into_iter()
            .enumerate()
            .map(
                |(index, provenance_status)| crate::proto::ConfigHistoryEntry {
                    index: u32::try_from(index).unwrap(),
                    timestamp_unix_seconds: 1_787_000_000,
                    sha256: "ab".repeat(32),
                    summary: "asn 65001, router-id 10.0.0.1, 2 neighbor(s)".to_string(),
                    source_sha256: "cd".repeat(32),
                    provenance_status,
                },
            )
            .collect(),
            human_text: "5 recorded config snapshot(s) retained.\n".to_string(),
        });

        // Red proof: removing an old key, either additive key, or any exact
        // status mapping changes these assertions against rendered JSON.
        assert_eq!(value["entries"][0]["index"], 0);
        assert_eq!(value["entries"][0]["timestamp_unix_seconds"], 1_787_000_000);
        assert_eq!(value["entries"][0]["timestamp"], "2026-08-17T20:53:20Z");
        assert_eq!(value["entries"][0]["sha256"], "ab".repeat(32));
        assert_eq!(value["entries"][0]["source_sha256"], "cd".repeat(32));
        assert_eq!(value["entries"][0]["provenance_status"], "recorded");
        assert_eq!(value["entries"][1]["provenance_status"], "legacy_toml_only");
        assert_eq!(value["entries"][2]["provenance_status"], "unreadable");
        assert_eq!(value["entries"][3]["provenance_status"], "unknown");
        assert_eq!(value["entries"][4]["provenance_status"], "unknown");
        assert_eq!(
            value["entries"][0]["summary"],
            "asn 65001, router-id 10.0.0.1, 2 neighbor(s)"
        );
        assert_eq!(
            value["human_text"],
            "5 recorded config snapshot(s) retained.\n"
        );
    }

    #[test]
    fn history_human_line_retains_toml_hash_and_adds_provenance() {
        // Red proof: removing the old 12-character TOML hash or either new
        // human field changes these exact rendered lines.
        let recorded = crate::proto::ConfigHistoryEntry {
            index: 0,
            timestamp_unix_seconds: 1_787_000_000,
            sha256: "ab".repeat(32),
            summary: "asn 65001".to_string(),
            source_sha256: "cd".repeat(32),
            provenance_status: crate::proto::ConfigHistoryProvenanceStatus::Recorded.into(),
        };
        assert_eq!(
            history_human_line(&recorded),
            format!(
                "  0  2026-08-17T20:53:20Z  {}  asn 65001 (latest)  provenance=recorded source_sha256={}",
                "ab".repeat(6),
                "cd".repeat(32)
            )
        );

        let unreadable = crate::proto::ConfigHistoryEntry {
            index: 1,
            timestamp_unix_seconds: 0,
            sha256: String::new(),
            summary: "(unreadable config history entry)".to_string(),
            source_sha256: String::new(),
            provenance_status: crate::proto::ConfigHistoryProvenanceStatus::Unreadable.into(),
        };
        assert_eq!(
            history_human_line(&unreadable),
            "  1  1970-01-01T00:00:00Z  -  (unreadable config history entry)  provenance=unreadable source_sha256=-"
        );
    }

    #[test]
    fn history_index_zero_uses_latest_marker() {
        assert_eq!(history_index_marker(0), " (latest)");
        assert_eq!(history_index_marker(1), "");
    }

    #[test]
    fn format_unix_utc_renders_known_instants() {
        assert_eq!(format_unix_utc(0), "1970-01-01T00:00:00Z");
        assert_eq!(format_unix_utc(1_787_000_000), "2026-08-17T20:53:20Z");
        // Leap-year day.
        assert_eq!(format_unix_utc(1_709_164_800), "2024-02-29T00:00:00Z");
    }

    #[tokio::test]
    async fn rollback_sends_index_and_metadata() {
        let server = spawn_mock_server(None).await;
        let connection = connect(&server.addr, None).await.unwrap();

        rollback(
            connection,
            RollbackOptions {
                index: 2,
                expected_runtime_snapshot_token: Some("kv1:old:1"),
                client_request_id: Some("deploy-99"),
                comment: Some("undo bad change"),
                confirm_id: Some("rollback-1"),
                confirm_timeout_seconds: Some(120),
            },
            true,
        )
        .await
        .unwrap();

        assert_eq!(server.state.config_rollback_calls.load(Ordering::SeqCst), 1);
        let request = server
            .state
            .last_config_rollback
            .lock()
            .await
            .clone()
            .unwrap();
        assert_eq!(request.index, 2);
        assert_eq!(request.expected_runtime_snapshot_token, "kv1:old:1");
        assert_eq!(request.client_request_id, "deploy-99");
        assert_eq!(request.comment, "undo bad change");
        assert_eq!(request.confirm_id, "rollback-1");
        assert_eq!(request.confirm_timeout_seconds, 120);
    }

    #[tokio::test]
    async fn rollback_rejects_index_zero_before_rpc() {
        let server = spawn_mock_server(None).await;
        let connection = connect(&server.addr, None).await.unwrap();

        let err = rollback(
            connection,
            RollbackOptions {
                index: 0,
                expected_runtime_snapshot_token: None,
                client_request_id: None,
                comment: None,
                confirm_id: None,
                confirm_timeout_seconds: None,
            },
            true,
        )
        .await
        .expect_err("rollback 0 must fail before RPC");

        assert!(
            matches!(err, CliError::Argument(ref message)
                if message.contains("index must be >= 1")
                    && message.contains("newest config-history row")
                    && !message.contains("running")),
            "{err:?}"
        );
        assert_eq!(server.state.config_rollback_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn rollback_rejects_confirm_timeout_without_confirm_id_before_rpc() {
        let server = spawn_mock_server(None).await;
        let connection = connect(&server.addr, None).await.unwrap();

        let err = rollback(
            connection,
            RollbackOptions {
                index: 1,
                expected_runtime_snapshot_token: None,
                client_request_id: None,
                comment: None,
                confirm_id: None,
                confirm_timeout_seconds: Some(120),
            },
            true,
        )
        .await
        .expect_err("confirm timeout without confirm_id must fail before RPC");

        assert!(
            matches!(err, CliError::Argument(ref message) if message == "--confirm-timeout requires --confirm-id"),
            "{err:?}"
        );
        assert_eq!(server.state.config_rollback_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn rollback_rpc_error_maps_to_cli_error() {
        let server = spawn_mock_server(None).await;
        *server.state.config_rollback_error.lock().await = Some((
            tonic::Code::FailedPrecondition,
            "cannot roll back: config history has 1 retained entry".to_string(),
        ));
        let connection = connect(&server.addr, None).await.unwrap();

        let err = rollback(
            connection,
            RollbackOptions {
                index: 5,
                expected_runtime_snapshot_token: None,
                client_request_id: None,
                comment: None,
                confirm_id: None,
                confirm_timeout_seconds: None,
            },
            true,
        )
        .await
        .expect_err("daemon rejection must surface as CLI error");

        assert!(
            matches!(err, CliError::Rpc(ref message) if message.contains("cannot roll back")),
            "{err:?}"
        );
        assert_eq!(server.state.config_rollback_calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn status_json_confirmation_null_when_absent() {
        let value = status_to_json(&ConfigTransactionStatusResponse {
            confirmation: None,
            human_text: "No confirmed config transaction.\n".to_string(),
        });
        assert!(value["confirmation"].is_null());
        assert_eq!(value["human_text"], "No confirmed config transaction.\n");
    }
}
