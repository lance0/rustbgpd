use rustbgpd_telemetry::BgpMetrics;
use tonic::Status;
use tonic::body::Body;
use tonic::codegen::http;
use tracing::{info, warn};

use crate::audit::GrpcRequestSummary;
use crate::authz::{AuthTier, GrpcMethodAuthz, PrincipalRole, method_authz};

use super::context::GrpcAuthAuditContext;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum RoleDenial {
    PrincipalUnmapped,
    RoleTierDenied { role: PrincipalRole },
}

impl RoleDenial {
    pub(super) const fn result_label(self) -> &'static str {
        match self {
            Self::PrincipalUnmapped => "principal_unmapped",
            Self::RoleTierDenied { .. } => "role_tier_denied",
        }
    }

    pub(super) fn status(self, principal: &str, tier: AuthTier, path: &str) -> Status {
        // The principal is the client-supplied identity label (listener
        // `principal`, mTLS SAN, ...) and is safe to echo; never include
        // token or certificate material here.
        let required = minimal_sufficient_role(tier);
        match self {
            Self::PrincipalUnmapped => Status::permission_denied(format!(
                "principal \"{principal}\" has no [security.grpc.roles] entry; \
                 {path} is a {tier} RPC requiring at least role {required} — \
                 add \"{principal}\" = \"{required}\" under [security.grpc.roles] \
                 in the daemon config and restart the daemon",
                tier = tier.as_str(),
                required = required.as_str()
            )),
            Self::RoleTierDenied { role } => Status::permission_denied(format!(
                "principal \"{principal}\" has role {role}; \
                 {path} is a {tier} RPC requiring at least role {required} — \
                 raise the role in [security.grpc.roles] \
                 in the daemon config and restart the daemon",
                role = role.as_str(),
                tier = tier.as_str(),
                required = required.as_str()
            )),
        }
    }
}

/// Smallest role whose ceiling reaches `tier`, used to phrase the
/// exact fix in denial messages.
const fn minimal_sufficient_role(tier: AuthTier) -> PrincipalRole {
    match tier {
        AuthTier::Read | AuthTier::SensitiveRead => PrincipalRole::Observer,
        AuthTier::Mutating => PrincipalRole::Automation,
        AuthTier::OperatorOnly => PrincipalRole::Operator,
    }
}

/// Result of a method-tier lookup.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GrpcAuthAuditDecision {
    /// Authorization tier assigned to the method.
    pub tier: AuthTier,
    /// Whether the method path exists in the checked matrix.
    pub known_method: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct GrpcAuthAuditLookup {
    pub(super) decision: GrpcAuthAuditDecision,
    pub(super) method: Option<&'static GrpcMethodAuthz>,
}

/// Compute the method-tier decision for a gRPC HTTP/2 path.
#[must_use]
pub fn audit_decision_for_path(path: &str) -> GrpcAuthAuditDecision {
    audit_lookup_for_path(path).decision
}

pub(super) fn audit_lookup_for_path(path: &str) -> GrpcAuthAuditLookup {
    let method = method_authz(path);
    let decision = if let Some(method) = method {
        GrpcAuthAuditDecision {
            tier: method.tier,
            known_method: true,
        }
    } else {
        GrpcAuthAuditDecision {
            tier: AuthTier::OperatorOnly,
            known_method: false,
        }
    };
    GrpcAuthAuditLookup { decision, method }
}

pub(super) fn record_audit_decision(
    path: &str,
    lookup: &GrpcAuthAuditLookup,
    context: &GrpcAuthAuditContext,
    principal: &str,
    metrics: &BgpMetrics,
    result: &'static str,
    request_summary: Option<&GrpcRequestSummary>,
) {
    let decision = lookup.decision;
    metrics.record_grpc_authz_decision(
        decision.tier.as_str(),
        result,
        context.authn.as_str(),
        context.access_mode,
    );
    let method = lookup.method;
    let service = method.map_or("unknown", |m| m.service);
    let method_name = method.map_or("unknown", |m| m.method);
    let known_method = decision.known_method;
    let tier = decision.tier.as_str();
    let listener = context.listener.as_str();
    let access_mode = context.access_mode;
    let max_tier = context.max_tier.as_str();
    let authn = context.authn.as_str();
    let enforcement = context.enforcement.as_str();
    let role = context.role_label(principal);
    let request_summary = request_summary.map_or("", GrpcRequestSummary::as_str);

    if decision.tier == AuthTier::OperatorOnly {
        warn!(
            target: "grpc_authz",
            path,
            service,
            method = method_name,
            tier,
            known_method,
            result,
            listener,
            access_mode,
            max_tier,
            authn,
            enforcement,
            role,
            principal,
            request_summary,
            "gRPC authorization audit decision"
        );
    } else {
        info!(
            target: "grpc_authz",
            path,
            service,
            method = method_name,
            tier,
            known_method,
            result,
            listener,
            access_mode,
            max_tier,
            authn,
            enforcement,
            role,
            principal,
            request_summary,
            "gRPC authorization audit decision"
        );
    }
}

pub(super) fn audit_result_for_response(response: &http::Response<Body>) -> &'static str {
    if let Some(status) = Status::from_header_map(response.headers()) {
        return audit_result_for_code(status.code());
    }
    if response.status().is_success() {
        "handler_ok"
    } else {
        "handler_http_error"
    }
}

fn audit_result_for_code(code: tonic::Code) -> &'static str {
    match code {
        tonic::Code::Ok => "handler_ok",
        tonic::Code::Cancelled => "handler_cancelled",
        tonic::Code::Unknown => "handler_unknown",
        tonic::Code::InvalidArgument => "handler_invalid_argument",
        tonic::Code::DeadlineExceeded => "handler_deadline_exceeded",
        tonic::Code::NotFound => "handler_not_found",
        tonic::Code::AlreadyExists => "handler_already_exists",
        tonic::Code::PermissionDenied => "handler_permission_denied",
        tonic::Code::ResourceExhausted => "handler_resource_exhausted",
        tonic::Code::FailedPrecondition => "handler_failed_precondition",
        tonic::Code::Aborted => "handler_aborted",
        tonic::Code::OutOfRange => "handler_out_of_range",
        tonic::Code::Unimplemented => "handler_unimplemented",
        tonic::Code::Internal => "handler_internal",
        tonic::Code::Unavailable => "handler_unavailable",
        tonic::Code::DataLoss => "handler_data_loss",
        tonic::Code::Unauthenticated => "handler_unauthenticated",
    }
}
