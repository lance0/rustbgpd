//! Runtime ADR-0064 audit layer for gRPC method-tier decisions.
//!
//! This layer records the method tier that feeds ADR-0064 authorization,
//! enforces the per-listener method-tier cap, then forwards permitted
//! requests to the existing tonic services. Bearer-token authentication
//! and listener `AccessMode` checks remain in `server.rs` and the
//! service handlers.

use std::borrow::Cow;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use rustbgpd_telemetry::BgpMetrics;
use tonic::Status;
use tonic::body::Body;
use tonic::codegen::http;
use tonic::transport::server::{TcpConnectInfo, TlsConnectInfo};
use tower::{Layer, Service};
use tracing::{debug, info, warn};

use crate::authz::{AuthTier, GrpcMethodAuthz, method_authz};
use crate::authz_principal::{PrincipalExtractionError, principal_from_peer_certs};

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
    max_tier: AuthTier,
    authn: GrpcAuthnKind,
    principal: String,
    resolve_mtls_principal: bool,
    expected_bearer_header: Option<BearerAuthSecret>,
}

impl GrpcAuthAuditContext {
    /// Build a context for a single resolved listener.
    #[must_use]
    pub fn new(
        listener: impl Into<String>,
        access_mode: &'static str,
        max_tier: AuthTier,
        authn: GrpcAuthnKind,
        principal: impl Into<String>,
    ) -> Self {
        Self {
            listener: listener.into(),
            access_mode,
            max_tier,
            authn,
            principal: principal.into(),
            resolve_mtls_principal: false,
            expected_bearer_header: None,
        }
    }

    /// Mark this context as an mTLS listener whose per-request
    /// principal should be derived from the peer certificate.
    #[must_use]
    pub fn with_mtls_peer_principal(mut self) -> Self {
        self.resolve_mtls_principal = true;
        self
    }

    #[must_use]
    pub fn with_bearer_token(mut self, token: Option<&str>) -> Self {
        self.expected_bearer_header = token.map(BearerAuthSecret::from_token);
        self
    }

    #[cfg(test)]
    pub(crate) fn authn(&self) -> GrpcAuthnKind {
        self.authn
    }

    #[cfg(test)]
    pub(crate) fn principal(&self) -> &str {
        &self.principal
    }

    #[cfg(test)]
    pub(crate) fn max_tier(&self) -> AuthTier {
        self.max_tier
    }

    fn bearer_auth_error(&self, headers: &http::HeaderMap) -> Option<Status> {
        let expected = self.expected_bearer_header.as_ref()?;
        expected.auth_error_from_http_headers(headers)
    }

    fn principal_for_extensions<'a>(&'a self, extensions: &http::Extensions) -> Cow<'a, str> {
        if !self.resolve_mtls_principal {
            return Cow::Borrowed(self.principal.as_str());
        }
        match mtls_principal_from_extensions(extensions) {
            Ok(principal) => Cow::Owned(principal),
            Err(error) => {
                debug!(
                    target: "grpc_authz",
                    error = %error,
                    fallback = %self.principal,
                    "failed to extract mTLS peer principal for gRPC audit"
                );
                Cow::Borrowed(self.principal.as_str())
            }
        }
    }
}

fn mtls_principal_from_extensions(
    extensions: &http::Extensions,
) -> Result<String, PrincipalExtractionError> {
    let certs = extensions
        .get::<TlsConnectInfo<TcpConnectInfo>>()
        .and_then(TlsConnectInfo::peer_certs)
        .ok_or(PrincipalExtractionError::MissingPeerCertificate)?;
    principal_from_peer_certs(certs.as_ref())
}

/// Redacted bearer-token verifier shared by the audit layer and tonic interceptor.
#[derive(Clone, Eq, PartialEq)]
pub(crate) struct BearerAuthSecret {
    expected_header: Arc<String>,
}

impl BearerAuthSecret {
    pub(crate) fn from_token(token: &str) -> Self {
        Self {
            expected_header: Arc::new(format!("Bearer {token}")),
        }
    }

    pub(crate) fn authenticate_metadata(
        &self,
        metadata: &tonic::metadata::MetadataMap,
    ) -> Result<(), Status> {
        let value = metadata
            .get("authorization")
            .ok_or_else(|| Status::unauthenticated("missing authorization metadata"))?;
        let actual = value
            .to_str()
            .map_err(|_| Status::unauthenticated("authorization metadata must be ASCII"))?;
        self.authenticate_str(actual)
    }

    fn auth_error_from_http_headers(&self, headers: &http::HeaderMap) -> Option<Status> {
        let Some(value) = headers.get("authorization") else {
            return Some(Status::unauthenticated("missing authorization metadata"));
        };
        let actual = value
            .to_str()
            .map_err(|_| Status::unauthenticated("authorization metadata must be ASCII"))
            .and_then(|actual| self.authenticate_str(actual));
        actual.err()
    }

    fn authenticate_str(&self, actual: &str) -> Result<(), Status> {
        if constant_time_eq(actual.as_bytes(), self.expected_header.as_bytes()) {
            Ok(())
        } else {
            Err(Status::unauthenticated("invalid bearer token"))
        }
    }
}

impl fmt::Debug for BearerAuthSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("BearerAuthSecret(<redacted>)")
    }
}

/// Result of a method-tier lookup.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GrpcAuthAuditDecision {
    /// Authorization tier assigned to the method.
    pub tier: AuthTier,
    /// Whether the method path exists in the checked matrix.
    pub known_method: bool,
    /// Stable default result label before listener-cap enforcement is applied.
    pub result: &'static str,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct GrpcAuthAuditLookup {
    decision: GrpcAuthAuditDecision,
    method: Option<&'static GrpcMethodAuthz>,
}

/// Compute the method-tier decision for a gRPC HTTP/2 path.
#[must_use]
pub fn audit_decision_for_path(path: &str) -> GrpcAuthAuditDecision {
    audit_lookup_for_path(path).decision
}

fn audit_lookup_for_path(path: &str) -> GrpcAuthAuditLookup {
    let method = method_authz(path);
    let decision = if let Some(method) = method {
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
    };
    GrpcAuthAuditLookup { decision, method }
}

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

    fn call(&mut self, req: http::Request<B>) -> Self::Future {
        let path = req.uri().path();
        let lookup = audit_lookup_for_path(path);
        let decision = lookup.decision;
        let principal = self.context.principal_for_extensions(req.extensions());
        if decision.tier > self.context.max_tier {
            // This layer wraps tonic's per-service interceptors. For an
            // over-cap bearer-token request, authenticate first so
            // invalid callers still receive UNAUTHENTICATED instead of
            // learning listener tier details via PERMISSION_DENIED.
            if let Some(status) = self.context.bearer_auth_error(req.headers()) {
                record_audit_decision(
                    path,
                    &lookup,
                    &self.context,
                    principal.as_ref(),
                    &self.metrics,
                    "authn_failed",
                );
                let response = status.into_http::<Body>();
                return Box::pin(async move { Ok(response) });
            }
            record_audit_decision(
                path,
                &lookup,
                &self.context,
                principal.as_ref(),
                &self.metrics,
                "listener_tier_denied",
            );
            let max_tier = self.context.max_tier.as_str();
            let tier = decision.tier.as_str();
            let response = Status::permission_denied(format!(
                "listener max_tier {max_tier} does not permit {tier} RPC {path}"
            ))
            .into_http::<Body>();
            return Box::pin(async move { Ok(response) });
        }
        record_audit_decision(
            path,
            &lookup,
            &self.context,
            principal.as_ref(),
            &self.metrics,
            decision.result,
        );
        let fut = self.inner.call(req);
        Box::pin(fut)
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    let max_len = a.len().max(b.len());
    let mut diff = a.len() ^ b.len();
    for idx in 0..max_len {
        let lhs = a.get(idx).copied().unwrap_or(0);
        let rhs = b.get(idx).copied().unwrap_or(0);
        diff |= usize::from(lhs ^ rhs);
    }
    diff == 0
}

fn record_audit_decision(
    path: &str,
    lookup: &GrpcAuthAuditLookup,
    context: &GrpcAuthAuditContext,
    principal: &str,
    metrics: &BgpMetrics,
    result: &'static str,
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
            max_tier,
            authn,
            principal,
            "gRPC authorization audit decision"
        );
    }
}

impl<S> fmt::Debug for GrpcAuthzService<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GrpcAuthzService").finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::Arc;

    use prometheus::Encoder;
    use rcgen::{
        BasicConstraints, Certificate, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa,
        Issuer, KeyPair, KeyUsagePurpose, SanType,
    };
    use tokio::net::{TcpListener, TcpStream};
    use tokio_rustls::rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
    use tokio_rustls::rustls::server::WebPkiClientVerifier;
    use tokio_rustls::rustls::{ClientConfig, RootCertStore, ServerConfig};
    use tokio_rustls::{TlsAcceptor, TlsConnector};
    use tonic::body::Body;
    use tonic::codegen::http::{Request, Response};
    use tonic::transport::server::Connected;

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

    fn private_key(key: &KeyPair) -> PrivateKeyDer<'static> {
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()))
    }

    fn test_ca() -> (Certificate, Issuer<'static, KeyPair>) {
        let mut params =
            CertificateParams::new(Vec::new()).expect("empty SAN list is valid for CA");
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(DnType::CommonName, "rustbgpd test CA");
        params.key_usages.push(KeyUsagePurpose::DigitalSignature);
        params.key_usages.push(KeyUsagePurpose::KeyCertSign);
        params.key_usages.push(KeyUsagePurpose::CrlSign);

        let key = KeyPair::generate().unwrap();
        let cert = params.self_signed(&key).unwrap();
        (cert, Issuer::new(params, key))
    }

    fn signed_leaf(
        issuer: &Issuer<'static, KeyPair>,
        common_name: &str,
        sans: Vec<SanType>,
        eku: ExtendedKeyUsagePurpose,
    ) -> (Certificate, KeyPair) {
        let mut params = CertificateParams::new(Vec::new()).expect("empty SAN list is valid");
        params.subject_alt_names = sans;
        params
            .distinguished_name
            .push(DnType::CommonName, common_name);
        params.key_usages.push(KeyUsagePurpose::DigitalSignature);
        params.extended_key_usages.push(eku);

        let key = KeyPair::generate().unwrap();
        let cert = params.signed_by(&key, issuer).unwrap();
        (cert, key)
    }

    async fn tonic_tls_connect_info_with_client_cert(
        ca_cert: &Certificate,
        issuer: &Issuer<'static, KeyPair>,
        client_cert: Certificate,
        client_key: KeyPair,
    ) -> TlsConnectInfo<TcpConnectInfo> {
        let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
        let (server_cert, server_key) = signed_leaf(
            issuer,
            "localhost",
            vec![SanType::DnsName("localhost".try_into().unwrap())],
            ExtendedKeyUsagePurpose::ServerAuth,
        );

        let mut server_roots = RootCertStore::empty();
        server_roots.add(ca_cert.der().clone()).unwrap();
        let client_verifier = WebPkiClientVerifier::builder(Arc::new(server_roots))
            .build()
            .unwrap();
        let server_config = ServerConfig::builder()
            .with_client_cert_verifier(client_verifier)
            .with_single_cert(vec![server_cert.der().clone()], private_key(&server_key))
            .unwrap();

        let mut client_roots = RootCertStore::empty();
        client_roots.add(ca_cert.der().clone()).unwrap();
        let client_config = ClientConfig::builder()
            .with_root_certificates(client_roots)
            .with_client_auth_cert(vec![client_cert.der().clone()], private_key(&client_key))
            .unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            TlsAcceptor::from(Arc::new(server_config))
                .accept(stream)
                .await
                .unwrap()
        });

        let client_stream = TcpStream::connect(addr).await.unwrap();
        let connector = TlsConnector::from(Arc::new(client_config));
        let server_name = "localhost".to_string().try_into().unwrap();
        let client = connector.connect(server_name, client_stream).await.unwrap();
        let server = server.await.unwrap();
        let info = server.connect_info();
        drop(client);
        info
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
            AuthTier::OperatorOnly,
            GrpcAuthnKind::BearerToken,
            "bearer-token",
        );
        let layer = GrpcAuthzLayer::new(context, metrics.clone());
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

    #[tokio::test]
    async fn audit_layer_denies_method_above_listener_cap() {
        let metrics = BgpMetrics::new();
        let context = GrpcAuthAuditContext::new(
            "tcp://127.0.0.1:50051",
            "read_write",
            AuthTier::SensitiveRead,
            GrpcAuthnKind::BearerToken,
            "bearer-token",
        );
        let layer = GrpcAuthzLayer::new(context, metrics.clone());
        let mut service = layer.layer(EchoService);
        let request = Request::builder()
            .uri("/rustbgpd.v1.NeighborService/AddNeighbor")
            .body(Body::empty())
            .unwrap();

        let response = service.call(request).await.unwrap();
        let status = tonic::Status::from_header_map(response.headers()).unwrap();
        assert_eq!(status.code(), tonic::Code::PermissionDenied);

        let text = gather_text(&metrics);
        assert!(text.contains("tier=\"mutating\""));
        assert!(text.contains("result=\"listener_tier_denied\""));
    }

    #[tokio::test]
    async fn audit_layer_denies_unknown_path_below_operator_cap() {
        let metrics = BgpMetrics::new();
        let context = GrpcAuthAuditContext::new(
            "tcp://127.0.0.1:50051",
            "read_write",
            AuthTier::Mutating,
            GrpcAuthnKind::BearerToken,
            "bearer-token",
        );
        let layer = GrpcAuthzLayer::new(context, metrics);
        let mut service = layer.layer(EchoService);
        let request = Request::builder()
            .uri("/rustbgpd.v1.Unknown/Nope")
            .body(Body::empty())
            .unwrap();

        let response = service.call(request).await.unwrap();
        let status = tonic::Status::from_header_map(response.headers()).unwrap();
        assert_eq!(status.code(), tonic::Code::PermissionDenied);
    }

    #[tokio::test]
    async fn audit_layer_authenticates_bearer_token_before_listener_cap() {
        let metrics = BgpMetrics::new();
        let context = GrpcAuthAuditContext::new(
            "tcp://127.0.0.1:50051",
            "read_write",
            AuthTier::SensitiveRead,
            GrpcAuthnKind::BearerToken,
            "bearer-token",
        )
        .with_bearer_token(Some("secret"));
        let layer = GrpcAuthzLayer::new(context, metrics.clone());
        let mut service = layer.layer(EchoService);
        let request = Request::builder()
            .uri("/rustbgpd.v1.NeighborService/AddNeighbor")
            .body(Body::empty())
            .unwrap();

        let response = service.call(request).await.unwrap();
        let status = tonic::Status::from_header_map(response.headers()).unwrap();
        assert_eq!(status.code(), tonic::Code::Unauthenticated);

        let text = gather_text(&metrics);
        assert!(text.contains("result=\"authn_failed\""));
        assert!(!text.contains("listener_tier_denied"));
    }

    #[tokio::test]
    async fn audit_layer_denies_over_cap_request_after_valid_bearer_token() {
        let metrics = BgpMetrics::new();
        let context = GrpcAuthAuditContext::new(
            "tcp://127.0.0.1:50051",
            "read_write",
            AuthTier::SensitiveRead,
            GrpcAuthnKind::BearerToken,
            "bearer-token",
        )
        .with_bearer_token(Some("secret"));
        let layer = GrpcAuthzLayer::new(context, metrics.clone());
        let mut service = layer.layer(EchoService);
        let request = Request::builder()
            .uri("/rustbgpd.v1.NeighborService/AddNeighbor")
            .header("authorization", "Bearer secret")
            .body(Body::empty())
            .unwrap();

        let response = service.call(request).await.unwrap();
        let status = tonic::Status::from_header_map(response.headers()).unwrap();
        assert_eq!(status.code(), tonic::Code::PermissionDenied);

        let text = gather_text(&metrics);
        assert!(text.contains("result=\"listener_tier_denied\""));
        assert!(!text.contains("result=\"authn_failed\""));
    }

    #[test]
    fn audit_context_debug_redacts_bearer_secret() {
        let context = GrpcAuthAuditContext::new(
            "tcp://127.0.0.1:50051",
            "read_write",
            AuthTier::SensitiveRead,
            GrpcAuthnKind::BearerToken,
            "bearer-token",
        )
        .with_bearer_token(Some("secret"));

        let rendered = format!("{context:?}");
        assert!(rendered.contains("<redacted>"));
        assert!(!rendered.contains("secret"));
        assert!(!rendered.contains("Bearer secret"));
    }

    #[test]
    fn mtls_principal_resolution_falls_back_without_peer_certs() {
        let context = GrpcAuthAuditContext::new(
            "tcp://127.0.0.1:50051",
            "read_write",
            AuthTier::OperatorOnly,
            GrpcAuthnKind::Mtls,
            "mtls-unresolved",
        )
        .with_mtls_peer_principal();

        assert_eq!(
            context
                .principal_for_extensions(&http::Extensions::new())
                .as_ref(),
            "mtls-unresolved"
        );
    }

    #[tokio::test]
    async fn mtls_principal_resolution_uses_tonic_tls_connect_info_peer_certs() {
        let (ca_cert, issuer) = test_ca();
        let (client_cert, client_key) = signed_leaf(
            &issuer,
            "alice-cn",
            vec![
                SanType::URI("rustbgpd://operator/alice".try_into().unwrap()),
                SanType::Rfc822Name("alice@example.com".try_into().unwrap()),
            ],
            ExtendedKeyUsagePurpose::ClientAuth,
        );
        let connect_info =
            tonic_tls_connect_info_with_client_cert(&ca_cert, &issuer, client_cert, client_key)
                .await;
        let mut extensions = http::Extensions::new();
        extensions.insert(connect_info);
        let context = GrpcAuthAuditContext::new(
            "tcp://127.0.0.1:50051",
            "read_write",
            AuthTier::OperatorOnly,
            GrpcAuthnKind::Mtls,
            "mtls-unresolved",
        )
        .with_mtls_peer_principal();

        assert_eq!(
            context.principal_for_extensions(&extensions).as_ref(),
            "rustbgpd://operator/alice"
        );
    }
}
