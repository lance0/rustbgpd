//! Helpers for ADR-0064 gRPC audit request summaries.

use std::sync::{Arc, Mutex};

use tonic::Request;

const MAX_SUMMARY_VALUE_CHARS: usize = 128;
const REDACTED: &str = "<redacted>";

/// Shared per-request audit state inserted by the authz Tower layer.
#[derive(Clone, Debug, Default)]
pub(crate) struct GrpcAuditHandle {
    inner: Arc<Mutex<Option<GrpcRequestSummary>>>,
}

impl GrpcAuditHandle {
    /// Record the safe, already-redacted request summary for this RPC.
    pub(crate) fn set_summary(&self, summary: GrpcRequestSummary) {
        let mut guard = self.inner.lock().expect("audit summary mutex poisoned");
        *guard = Some(summary);
    }

    /// Return the current request summary, if a typed handler set one.
    pub(crate) fn summary(&self) -> Option<GrpcRequestSummary> {
        self.inner
            .lock()
            .expect("audit summary mutex poisoned")
            .clone()
    }
}

/// Safe request summary suitable for structured audit logs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct GrpcRequestSummary {
    value: String,
}

impl GrpcRequestSummary {
    /// Build a summary from already-safe text.
    pub(crate) fn new(value: impl Into<String>) -> Self {
        Self {
            value: value.into(),
        }
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.value
    }
}

/// Attach a typed service summary when the auth layer provided a handle.
pub(crate) fn set_request_summary<T>(request: &Request<T>, summary: GrpcRequestSummary) {
    if let Some(handle) = request.extensions().get::<GrpcAuditHandle>() {
        handle.set_summary(summary);
    }
}

/// Return a bounded, log-safe field value for non-secret identifiers.
pub(crate) fn safe_summary_value(value: &str) -> String {
    let mut output = String::new();
    let mut truncated = false;
    for (idx, ch) in value.chars().enumerate() {
        if idx >= MAX_SUMMARY_VALUE_CHARS {
            truncated = true;
            break;
        }
        if ch.is_control() {
            output.push('_');
        } else {
            output.push(ch);
        }
    }
    if truncated {
        output.push_str("...");
    }
    output
}

/// Summary for `DiffRuntimeConfig`. The candidate TOML can contain
/// `md5_password`, `tcp_ao.key`, and future credentials, so never log
/// any of its content.
pub(crate) fn diff_runtime_config_summary(candidate_toml: &str) -> GrpcRequestSummary {
    debug_assert!(CREDENTIAL_MASK_TABLE.contains(&"DiffRuntimeConfigRequest.candidate_toml"));
    GrpcRequestSummary::new(format!(
        "candidate_toml={REDACTED} candidate_toml_bytes={}",
        candidate_toml.len()
    ))
}

/// Summary for `PlanConfigTransaction`. Candidate TOML has the same
/// credential risk as `DiffRuntimeConfig`, so log only size and token state.
pub(crate) fn plan_config_transaction_summary(
    candidate_toml: &str,
    expected_runtime_snapshot_token: &str,
) -> GrpcRequestSummary {
    debug_assert!(CREDENTIAL_MASK_TABLE.contains(&"PlanConfigTransactionRequest.candidate_toml"));
    GrpcRequestSummary::new(format!(
        "candidate_toml={REDACTED} candidate_toml_bytes={} expected_runtime_snapshot_token_present={}",
        candidate_toml.len(),
        !expected_runtime_snapshot_token.is_empty()
    ))
}

/// Bounded summary for streaming config-plan ingress. Candidate bytes,
/// digests, plan tokens, and storage identifiers are intentionally absent.
pub(crate) fn stream_plan_config_transaction_summary(
    version: u32,
    chunk_count: u64,
    candidate_bytes: u64,
    expected_runtime_snapshot_token_present: bool,
    outcome: &'static str,
) -> GrpcRequestSummary {
    debug_assert!(
        CREDENTIAL_MASK_TABLE.contains(&"StreamPlanConfigTransactionRequest.candidate_chunk")
    );
    GrpcRequestSummary::new(format!(
        "version={version} chunk_count={chunk_count} candidate_bytes={candidate_bytes} expected_runtime_snapshot_token_present={expected_runtime_snapshot_token_present} outcome={outcome}"
    ))
}

/// Summary for `ApplyConfigTransaction`. Candidate TOML and free-form comments
/// are not logged verbatim.
pub(crate) fn apply_config_transaction_summary(
    candidate_toml: &str,
    expected_runtime_snapshot_token: &str,
    client_request_id: &str,
    comment: &str,
    confirm_id: &str,
    confirm_timeout_seconds: u32,
) -> GrpcRequestSummary {
    debug_assert!(CREDENTIAL_MASK_TABLE.contains(&"ApplyConfigTransactionRequest.candidate_toml"));
    GrpcRequestSummary::new(format!(
        "candidate_toml={REDACTED} candidate_toml_bytes={} expected_runtime_snapshot_token_present={} client_request_id={} comment_present={} confirm_id={} confirm_timeout_seconds={}",
        candidate_toml.len(),
        !expected_runtime_snapshot_token.is_empty(),
        safe_summary_value(client_request_id),
        !comment.is_empty(),
        safe_summary_value(confirm_id),
        confirm_timeout_seconds
    ))
}

/// Summary for `ConfirmConfigTransaction`. The confirmation id is an operator
/// correlation handle, not a secret, but still bounded before logging.
pub(crate) fn confirm_config_transaction_summary(confirm_id: &str) -> GrpcRequestSummary {
    GrpcRequestSummary::new(format!("confirm_id={}", safe_summary_value(confirm_id)))
}

/// Summary for `AbortConfigTransaction`. The confirmation id is an operator
/// correlation handle, not a secret, but still bounded before logging.
pub(crate) fn abort_config_transaction_summary(confirm_id: &str) -> GrpcRequestSummary {
    GrpcRequestSummary::new(format!("confirm_id={}", safe_summary_value(confirm_id)))
}

/// Summary for `GetConfigTransactionStatus`; there are no request fields.
pub(crate) fn get_config_transaction_status_summary() -> GrpcRequestSummary {
    GrpcRequestSummary::new("request=empty")
}

/// Summary for `GetEffectiveConfig`; there are no request fields. The
/// response TOML is redacted by the peer manager before it reaches the
/// service, so nothing response-side needs masking here either.
pub(crate) fn get_effective_config_summary() -> GrpcRequestSummary {
    GrpcRequestSummary::new("request=empty")
}

/// Summary for `ListConfigHistory`; there are no request fields, and the
/// response carries timestamps, hashes, and count summaries only — never
/// config document contents.
pub(crate) fn list_config_history_summary() -> GrpcRequestSummary {
    GrpcRequestSummary::new("request=empty")
}

/// Summary for `RollbackConfigTransaction`. The rollback candidate is
/// resolved server-side from retained history, so unlike apply there is no
/// candidate TOML to redact; the comment can carry sensitive context and is
/// logged as presence only, mirroring the apply summary.
pub(crate) fn rollback_config_transaction_summary(
    index: u32,
    expected_runtime_snapshot_token: &str,
    client_request_id: &str,
    comment: &str,
    confirm_id: &str,
    confirm_timeout_seconds: u32,
) -> GrpcRequestSummary {
    GrpcRequestSummary::new(format!(
        "index={index} expected_runtime_snapshot_token_present={} client_request_id={} comment_present={} confirm_id={} confirm_timeout_seconds={confirm_timeout_seconds}",
        !expected_runtime_snapshot_token.is_empty(),
        safe_summary_value(client_request_id),
        !comment.is_empty(),
        safe_summary_value(confirm_id),
    ))
}

/// Summary for `gnmi.gNMI/Set`. Set payloads can carry future secret-bearing
/// config values, so log only operation counts and extension count.
pub(crate) fn gnmi_set_summary(request: &crate::gnmi::SetRequest) -> GrpcRequestSummary {
    debug_assert!(CREDENTIAL_MASK_TABLE.contains(&"gnmi.SetRequest.values"));
    GrpcRequestSummary::new(format!(
        "delete_count={} replace_count={} update_count={} union_replace_count={} extension_count={} values={REDACTED}",
        request.delete.len(),
        request.replace.len(),
        request.update.len(),
        request.union_replace.len(),
        request.extension.len()
    ))
}

/// Summary for `ApplyEvpnRuntime`. Candidate TOML has the same
/// credential risk as `DiffRuntimeConfig`, so log only size and mode.
pub(crate) fn apply_evpn_runtime_summary(
    candidate_toml: &str,
    validate_only: bool,
) -> GrpcRequestSummary {
    debug_assert!(CREDENTIAL_MASK_TABLE.contains(&"ApplyEvpnRuntimeRequest.candidate_toml"));
    GrpcRequestSummary::new(format!(
        "candidate_toml={REDACTED} candidate_toml_bytes={} validate_only={validate_only}",
        candidate_toml.len()
    ))
}

/// Summary for `SetPeerGroup`. Peer-group name is safe after bounding;
/// MD5 material is represented only as state.
pub(crate) fn set_peer_group_summary(
    name: &str,
    md5_password_present: bool,
    has_md5_password: Option<bool>,
) -> GrpcRequestSummary {
    debug_assert!(CREDENTIAL_MASK_TABLE.contains(&"PeerGroupDefinition.md5_password"));
    let md5_state = if md5_password_present {
        "set_redacted"
    } else {
        match has_md5_password {
            Some(false) => "clear",
            Some(true) | None => "preserve",
        }
    };
    GrpcRequestSummary::new(format!(
        "name={} md5_password={md5_state}",
        safe_summary_value(name)
    ))
}

/// Explicit credential fields covered by this audit-summary layer.
pub(crate) const CREDENTIAL_MASK_TABLE: &[&str] = &[
    "DiffRuntimeConfigRequest.candidate_toml",
    "PlanConfigTransactionRequest.candidate_toml",
    "StreamPlanConfigTransactionRequest.candidate_chunk",
    "ApplyConfigTransactionRequest.candidate_toml",
    "ApplyEvpnRuntimeRequest.candidate_toml",
    "PeerGroupDefinition.md5_password",
    "candidate_toml:tcp_ao.key",
    "gnmi.SetRequest.values",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_summary_value_bounds_and_removes_control_chars() {
        let input = format!("peer\n{}", "a".repeat(140));
        let output = safe_summary_value(&input);
        assert!(output.starts_with("peer_"));
        assert!(output.ends_with("..."));
        assert!(!output.contains('\n'));
        assert!(output.len() < input.len());
    }

    #[test]
    fn diff_runtime_config_summary_redacts_candidate_toml() {
        let summary = diff_runtime_config_summary(
            "md5_password = \"secret\"\ntcp_ao = { key = \"ao-secret\" }\n",
        );
        assert!(summary.as_str().contains("candidate_toml=<redacted>"));
        assert!(summary.as_str().contains("candidate_toml_bytes="));
        assert!(!summary.as_str().contains("secret"));
        assert!(!summary.as_str().contains("ao-secret"));
    }

    #[test]
    fn plan_config_transaction_summary_redacts_candidate_toml() {
        let summary = plan_config_transaction_summary(
            "md5_password = \"secret\"\ntcp_ao = { key = \"ao-secret\" }\n",
            "kv1:abc:1",
        );
        assert!(summary.as_str().contains("candidate_toml=<redacted>"));
        assert!(summary.as_str().contains("candidate_toml_bytes="));
        assert!(
            summary
                .as_str()
                .contains("expected_runtime_snapshot_token_present=true")
        );
        assert!(!summary.as_str().contains("secret"));
        assert!(!summary.as_str().contains("ao-secret"));
    }

    #[test]
    fn apply_config_transaction_summary_redacts_candidate_and_comment() {
        let summary = apply_config_transaction_summary(
            "md5_password = \"secret\"\ntcp_ao = { key = \"ao-secret\" }\n",
            "kv1:abc:1",
            "deploy-42",
            "secret maintenance note",
            "deploy-confirm",
            120,
        );
        assert!(summary.as_str().contains("candidate_toml=<redacted>"));
        assert!(summary.as_str().contains("client_request_id=deploy-42"));
        assert!(summary.as_str().contains("comment_present=true"));
        assert!(summary.as_str().contains("confirm_id=deploy-confirm"));
        assert!(summary.as_str().contains("confirm_timeout_seconds=120"));
        assert!(!summary.as_str().contains("secret"));
        assert!(!summary.as_str().contains("ao-secret"));
        assert!(!summary.as_str().contains("maintenance"));
    }

    #[test]
    fn apply_evpn_runtime_summary_redacts_candidate_toml() {
        let summary = apply_evpn_runtime_summary(
            "md5_password = \"secret\"\ntcp_ao = { key = \"ao-secret\" }\n",
            true,
        );
        assert!(summary.as_str().contains("candidate_toml=<redacted>"));
        assert!(summary.as_str().contains("candidate_toml_bytes="));
        assert!(summary.as_str().contains("validate_only=true"));
        assert!(!summary.as_str().contains("secret"));
        assert!(!summary.as_str().contains("ao-secret"));
    }

    #[test]
    fn gnmi_set_summary_redacts_values() {
        let summary = gnmi_set_summary(&crate::gnmi::SetRequest {
            prefix: None,
            delete: vec![crate::gnmi::Path::default()],
            replace: vec![crate::gnmi::Update {
                path: Some(crate::gnmi::Path::default()),
                #[allow(deprecated)]
                value: None,
                val: Some(crate::gnmi::TypedValue {
                    value: Some(crate::gnmi::typed_value::Value::JsonIetfVal(
                        br#"{"md5_password":"secret"}"#.to_vec(),
                    )),
                }),
                duplicates: 0,
            }],
            update: Vec::new(),
            extension: Vec::new(),
            union_replace: Vec::new(),
        });
        assert!(summary.as_str().contains("delete_count=1"));
        assert!(summary.as_str().contains("replace_count=1"));
        assert!(summary.as_str().contains("values=<redacted>"));
        assert!(!summary.as_str().contains("secret"));
        assert!(!summary.as_str().contains("md5_password"));
    }

    #[test]
    fn set_peer_group_summary_never_contains_md5_secret() {
        let summary = set_peer_group_summary("rs-clients", true, None);
        assert_eq!(
            summary.as_str(),
            "name=rs-clients md5_password=set_redacted"
        );
        assert!(!summary.as_str().contains("secret"));
    }

    #[test]
    fn credential_mask_table_lists_current_secret_ingress() {
        assert!(CREDENTIAL_MASK_TABLE.contains(&"DiffRuntimeConfigRequest.candidate_toml"));
        assert!(CREDENTIAL_MASK_TABLE.contains(&"PlanConfigTransactionRequest.candidate_toml"));
        assert!(
            CREDENTIAL_MASK_TABLE.contains(&"StreamPlanConfigTransactionRequest.candidate_chunk")
        );
        assert!(CREDENTIAL_MASK_TABLE.contains(&"ApplyConfigTransactionRequest.candidate_toml"));
        assert!(CREDENTIAL_MASK_TABLE.contains(&"ApplyEvpnRuntimeRequest.candidate_toml"));
        assert!(CREDENTIAL_MASK_TABLE.contains(&"PeerGroupDefinition.md5_password"));
        assert!(CREDENTIAL_MASK_TABLE.contains(&"candidate_toml:tcp_ao.key"));
        assert!(CREDENTIAL_MASK_TABLE.contains(&"gnmi.SetRequest.values"));
    }
}
