//! Runtime ADR-0064 audit layer for gRPC method-tier decisions.
//!
//! This layer is intentionally audit-only: it records the method tier
//! that would feed future tier enforcement, then forwards every request
//! to the existing tonic services. Bearer-token authentication and
//! listener `AccessMode` checks remain in `server.rs` and the service
//! handlers.

use std::fmt;
use std::task::{Context, Poll};

use rustbgpd_telemetry::BgpMetrics;
use tonic::codegen::http;
use tower::{Layer, Service};
use tracing::{info, warn};

use crate::authz::{AuthTier, method_authz};

/// Bounded set of listener authentication surfaces for audit labels.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GrpcAuthnKind {
    /// TCP listener with mTLS enabled.
    Mtls,
    /// Listener protected by the existing bearer-token interceptor.
    BearerToken,
    /// Unix domain socket protected by filesystem permissions.
    Uds,
    /// No listener authentication configured.
    None,
}

impl GrpcAuthnKind {
    /// Stable metrics/log label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Mtls => "mtls",
            Self::BearerToken => "bearer_token",
            Self::Uds => "uds",
            Self::None => "none",
        }
    }
}

/// Per-listener audit context attached to every runtime decision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GrpcAuthAuditContext {
    listener: String,
    access_mode: &'static str,
    authn: GrpcAuthnKind,
    principal: String,
}

impl GrpcAuthAuditContext {
    /// Build a context for a single resolved listener.
    #[must_use]
    pub fn new(
        listener: impl Into<String>,
        access_mode: &'static str,
        authn: GrpcAuthnKind,
        principal: impl Into<String>,
    ) -> Self {
        Self {
            listener: listener.into(),
            access_mode,
            authn,
            principal: principal.into(),
        }
    }
}

/// Result of an audit-only tier lookup.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GrpcAuthAuditDecision {
    /// Authorization tier assigned to the method.
    pub tier: AuthTier,
    /// Whether the method path exists in the checked matrix.
    pub known_method: bool,
    /// Stable result label. Slice 2a never denies requests.
    pub result: &'static str,
}

/// Compute the audit-only decision for a gRPC HTTP/2 path.
#[must_use]
pub fn audit_decision_for_path(path: &str) -> GrpcAuthAuditDecision {
    if let Some(method) = method_authz(path) {
        GrpcAuthAuditDecision {
            tier: method.tier,
            known_method: true,
            result: "audit_forward",
        }
    } else {
        GrpcAuthAuditDecision {
            tier: AuthTier::OperatorOnly,
            known_method: false,
            result: "unknown_audit_forward",
        }
    }
}

/// Tower layer that records ADR-0064 runtime decisions.
#[derive(Clone)]
pub struct GrpcAuthAuditLayer {
    context: GrpcAuthAuditContext,
    metrics: BgpMetrics,
}

impl GrpcAuthAuditLayer {
    /// Create a new audit layer for one listener.
    #[must_use]
    pub fn new(context: GrpcAuthAuditContext, metrics: BgpMetrics) -> Self {
        Self { context, metrics }
    }
}

impl<S> Layer<S> for GrpcAuthAuditLayer {
    type Service = GrpcAuthAuditService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        GrpcAuthAuditService {
            inner,
            context: self.context.clone(),
            metrics: self.metrics.clone(),
        }
    }
}

/// Audit-only service wrapper.
#[derive(Clone)]
pub struct GrpcAuthAuditService<S> {
    inner: S,
    context: GrpcAuthAuditContext,
    metrics: BgpMetrics,
}

impl<S, B> Service<http::Request<B>> for GrpcAuthAuditService<S>
where
    S: Service<http::Request<B>> + Send + 'static,
    S::Future: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = S::Future;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: http::Request<B>) -> Self::Future {
        let path = req.uri().path();
        record_audit_decision(path, &self.context, &self.metrics);
        self.inner.call(req)
    }
}

fn record_audit_decision(path: &str, context: &GrpcAuthAuditContext, metrics: &BgpMetrics) {
    let decision = audit_decision_for_path(path);
    metrics.record_grpc_authz_decision(
        decision.tier.as_str(),
        decision.result,
        context.authn.as_str(),
        context.access_mode,
    );
    let method = method_authz(path);
    let service = method.map_or("unknown", |m| m.service);
    let method_name = method.map_or("unknown", |m| m.method);
    let known_method = decision.known_method;
    let tier = decision.tier.as_str();
    let result = decision.result;
    let listener = context.listener.as_str();
    let access_mode = context.access_mode;
    let authn = context.authn.as_str();
    let principal = context.principal.as_str();

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
            authn,
            principal,
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
            authn,
            principal,
            "gRPC authorization audit decision"
        );
    }
}

impl<S> fmt::Debug for GrpcAuthAuditService<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GrpcAuthAuditService")
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;
    use std::future::Future;
    use std::pin::Pin;

    use prometheus::Encoder;
    use tonic::body::Body;
    use tonic::codegen::http::{Request, Response};

    use super::*;

    #[derive(Clone)]
    struct EchoService;

    impl Service<Request<Body>> for EchoService {
        type Response = Response<Body>;
        type Error = Infallible;
        type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, _req: Request<Body>) -> Self::Future {
            Box::pin(async { Ok(Response::new(Body::empty())) })
        }
    }

    fn gather_text(metrics: &BgpMetrics) -> String {
        let encoder = prometheus::TextEncoder::new();
        let families = metrics.registry().gather();
        let mut buf = Vec::new();
        encoder.encode(&families, &mut buf).unwrap();
        String::from_utf8(buf).unwrap()
    }

    #[test]
    fn audit_decision_uses_static_method_tier() {
        let decision = audit_decision_for_path("/rustbgpd.v1.ControlService/Shutdown");
        assert_eq!(decision.tier, AuthTier::OperatorOnly);
        assert!(decision.known_method);
        assert_eq!(decision.result, "audit_forward");
    }

    #[test]
    fn audit_decision_treats_unknown_as_operator_only() {
        let decision = audit_decision_for_path("/rustbgpd.v1.Unknown/Nope");
        assert_eq!(decision.tier, AuthTier::OperatorOnly);
        assert!(!decision.known_method);
        assert_eq!(decision.result, "unknown_audit_forward");
    }

    #[tokio::test]
    async fn audit_layer_records_metric_and_forwards_request() {
        let metrics = BgpMetrics::new();
        let context = GrpcAuthAuditContext::new(
            "tcp://127.0.0.1:50051",
            "read_write",
            GrpcAuthnKind::BearerToken,
            "bearer-token",
        );
        let layer = GrpcAuthAuditLayer::new(context, metrics.clone());
        let mut service = layer.layer(EchoService);
        let request = Request::builder()
            .uri("/rustbgpd.v1.ControlService/GetHealth")
            .body(Body::empty())
            .unwrap();

        let response = service.call(request).await.unwrap();
        assert_eq!(response.status(), http::StatusCode::OK);

        let text = gather_text(&metrics);
        assert!(text.contains("bgp_grpc_authz_decisions_total"));
        assert!(text.contains("tier=\"sensitive_read\""));
        assert!(text.contains("result=\"audit_forward\""));
        assert!(text.contains("authn=\"bearer_token\""));
        assert!(text.contains("access_mode=\"read_write\""));
    }
}
