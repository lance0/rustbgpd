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
    "PeerGroupDefinition.md5_password",
    "candidate_toml:tcp_ao.key",
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
        assert!(CREDENTIAL_MASK_TABLE.contains(&"PeerGroupDefinition.md5_password"));
        assert!(CREDENTIAL_MASK_TABLE.contains(&"candidate_toml:tcp_ao.key"));
    }
}
