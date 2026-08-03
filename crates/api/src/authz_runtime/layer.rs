use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use rustbgpd_telemetry::BgpMetrics;
use tonic::Status;
use tonic::body::Body;
use tonic::codegen::http;
use tower::{Layer, Service};

use crate::audit::GrpcAuditHandle;

use super::context::GrpcAuthAuditContext;
use super::decision::{audit_lookup_for_path, audit_result_for_response, record_audit_decision};

/// Tower layer that records ADR-0064 runtime decisions and enforces
/// the listener's method-tier ceiling.
#[derive(Clone)]
pub struct GrpcAuthzLayer {
    context: GrpcAuthAuditContext,
    metrics: BgpMetrics,
}

impl GrpcAuthzLayer {
    /// Create a new authorization/audit layer for one listener.
    #[must_use]
    pub fn new(context: GrpcAuthAuditContext, metrics: BgpMetrics) -> Self {
        Self { context, metrics }
    }
}

impl<S> Layer<S> for GrpcAuthzLayer {
    type Service = GrpcAuthzService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        GrpcAuthzService {
            inner,
            context: self.context.clone(),
            metrics: self.metrics.clone(),
        }
    }
}

/// Audit and listener-cap service wrapper.
#[derive(Clone)]
pub struct GrpcAuthzService<S> {
    inner: S,
    context: GrpcAuthAuditContext,
    metrics: BgpMetrics,
}

impl<S, B> Service<http::Request<B>> for GrpcAuthzService<S>
where
    S: Service<http::Request<B>, Response = http::Response<Body>> + Send + 'static,
    S::Future: Send + 'static,
    S::Error: Send + 'static,
{
    type Response = http::Response<Body>;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: http::Request<B>) -> Self::Future {
        self.context.pin_credentials(req.extensions_mut());
        let path = req.uri().path().to_string();
        let lookup = audit_lookup_for_path(&path);
        let decision = lookup.decision;
        let principal = self.context.principal_for_extensions(req.extensions());
        if decision.tier > self.context.max_tier {
            // This layer wraps tonic's per-service interceptors. For an
            // over-cap bearer-token request, authenticate first so
            // invalid callers still receive UNAUTHENTICATED instead of
            // learning listener tier details via PERMISSION_DENIED.
            if let Some(status) = self
                .context
                .bearer_auth_error(req.headers(), req.extensions())
            {
                record_audit_decision(
                    &path,
                    &lookup,
                    &self.context,
                    principal.as_ref(),
                    &self.metrics,
                    "authn_failed",
                    None,
                );
                let response = status.into_http::<Body>();
                return Box::pin(async move { Ok(response) });
            }
            record_audit_decision(
                &path,
                &lookup,
                &self.context,
                principal.as_ref(),
                &self.metrics,
                "listener_tier_denied",
                None,
            );
            let max_tier = self.context.max_tier.as_str();
            let tier = decision.tier.as_str();
            let response = Status::permission_denied(format!(
                "listener max_tier {max_tier} does not permit {tier} RPC {path}; \
                 this cap is an intentional per-listener ceiling — raise max_tier \
                 on this listener in the daemon config and restart the daemon, \
                 or use a listener without the cap"
            ))
            .into_http::<Body>();
            return Box::pin(async move { Ok(response) });
        }
        if let Some(denial) = self.context.role_denial(principal.as_ref(), decision.tier) {
            if let Some(status) = self
                .context
                .bearer_auth_error(req.headers(), req.extensions())
            {
                record_audit_decision(
                    &path,
                    &lookup,
                    &self.context,
                    principal.as_ref(),
                    &self.metrics,
                    "authn_failed",
                    None,
                );
                let response = status.into_http::<Body>();
                return Box::pin(async move { Ok(response) });
            }
            record_audit_decision(
                &path,
                &lookup,
                &self.context,
                principal.as_ref(),
                &self.metrics,
                denial.result_label(),
                None,
            );
            let response = denial
                .status(principal.as_ref(), decision.tier, &path)
                .into_http::<Body>();
            return Box::pin(async move { Ok(response) });
        }
        let audit_handle = GrpcAuditHandle::default();
        req.extensions_mut().insert(audit_handle.clone());
        let context = self.context.clone();
        let metrics = self.metrics.clone();
        let principal = principal.into_owned();
        let fut = self.inner.call(req);
        Box::pin(async move {
            let response = fut.await;
            let result = match &response {
                Ok(response) => audit_result_for_response(response),
                Err(_) => "handler_service_error",
            };
            let summary = audit_handle.summary();
            record_audit_decision(
                &path,
                &lookup,
                &context,
                &principal,
                &metrics,
                result,
                summary.as_ref(),
            );
            response
        })
    }
}

impl<S> fmt::Debug for GrpcAuthzService<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GrpcAuthzService").finish_non_exhaustive()
    }
}
