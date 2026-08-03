use std::collections::BTreeMap;
use std::convert::Infallible;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose, SanType,
};
use rustbgpd_telemetry::BgpMetrics;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio_rustls::rustls::server::WebPkiClientVerifier;
use tokio_rustls::rustls::{ClientConfig, RootCertStore, ServerConfig};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tonic::Status;
use tonic::body::Body;
use tonic::codegen::http::{self, Request, Response};
use tonic::transport::server::{Connected, TcpConnectInfo, TlsConnectInfo};
use tower::{Layer, Service};

use super::*;
use crate::audit::{GrpcAuditHandle, GrpcRequestSummary};
use crate::authz::{AuthEnforcement, AuthTier, LOCAL_OPERATOR_PRINCIPAL, PrincipalRole};
use crate::connect_info::{RustbgpdTcpConnectInfo, RustbgpdTcpStream};
use crate::test_support::metrics_text as gather_text;

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

#[derive(Clone)]
struct InvalidArgumentService;

impl Service<Request<Body>> for InvalidArgumentService {
    type Response = Response<Body>;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _req: Request<Body>) -> Self::Future {
        Box::pin(async { Ok(Status::invalid_argument("bad request").into_http::<Body>()) })
    }
}

#[derive(Clone)]
struct SummaryService;

impl Service<Request<Body>> for SummaryService {
    type Response = Response<Body>;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        let handle = req
            .extensions()
            .get::<GrpcAuditHandle>()
            .expect("auth layer should attach audit handle")
            .clone();
        Box::pin(async move {
            handle.set_summary(GrpcRequestSummary::new("candidate_toml=<redacted>"));
            Ok(Response::new(Body::empty()))
        })
    }
}

fn roles(entries: &[(&str, PrincipalRole)]) -> Arc<BTreeMap<String, PrincipalRole>> {
    Arc::new(
        entries
            .iter()
            .map(|(principal, role)| ((*principal).to_string(), *role))
            .collect(),
    )
}

fn tier_test_context(
    listener: &str,
    access_mode: &'static str,
    max_tier: AuthTier,
    authn: GrpcAuthnKind,
    principal: &str,
    role: PrincipalRole,
) -> GrpcAuthAuditContext {
    GrpcAuthAuditContext::new(listener, access_mode, max_tier, authn, principal)
        .with_role_enforcement(AuthEnforcement::Tier, roles(&[(principal, role)]))
}

fn private_key(key: &KeyPair) -> PrivateKeyDer<'static> {
    PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()))
}

fn test_ca() -> (Certificate, Issuer<'static, KeyPair>) {
    let mut params = CertificateParams::new(Vec::new()).expect("empty SAN list is valid for CA");
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

async fn rustbgpd_tls_connect_info_with_client_cert(
    ca_cert: &Certificate,
    issuer: &Issuer<'static, KeyPair>,
    client_cert: Certificate,
    client_key: KeyPair,
) -> TlsConnectInfo<RustbgpdTcpConnectInfo> {
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
            .accept(RustbgpdTcpStream::new(stream))
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
}

#[test]
fn audit_decision_treats_unknown_as_operator_only() {
    let decision = audit_decision_for_path("/rustbgpd.v1.Unknown/Nope");
    assert_eq!(decision.tier, AuthTier::OperatorOnly);
    assert!(!decision.known_method);
}

#[tokio::test]
async fn audit_layer_records_metric_and_forwards_request() {
    let metrics = BgpMetrics::new();
    let context = tier_test_context(
        "tcp://127.0.0.1:50051",
        "read_write",
        AuthTier::OperatorOnly,
        GrpcAuthnKind::BearerToken,
        "bearer-token",
        PrincipalRole::Operator,
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
    assert!(text.contains("result=\"handler_ok\""));
    assert!(text.contains("authn=\"bearer_token\""));
    assert!(text.contains("access_mode=\"read_write\""));
}

#[tokio::test]
async fn audit_layer_records_handler_error_status() {
    let metrics = BgpMetrics::new();
    let context = tier_test_context(
        "tcp://127.0.0.1:50051",
        "read_write",
        AuthTier::OperatorOnly,
        GrpcAuthnKind::BearerToken,
        "bearer-token",
        PrincipalRole::Operator,
    );
    let layer = GrpcAuthzLayer::new(context, metrics.clone());
    let mut service = layer.layer(InvalidArgumentService);
    let request = Request::builder()
        .uri("/rustbgpd.v1.ConfigService/DiffRuntimeConfig")
        .body(Body::empty())
        .unwrap();

    let response = service.call(request).await.unwrap();
    let status = tonic::Status::from_header_map(response.headers()).unwrap();
    assert_eq!(status.code(), tonic::Code::InvalidArgument);

    let text = gather_text(&metrics);
    assert!(text.contains("tier=\"sensitive_read\""));
    assert!(text.contains("result=\"handler_invalid_argument\""));
}

#[tokio::test]
async fn audit_layer_attaches_request_summary_handle() {
    let metrics = BgpMetrics::new();
    let context = tier_test_context(
        "tcp://127.0.0.1:50051",
        "read_write",
        AuthTier::OperatorOnly,
        GrpcAuthnKind::BearerToken,
        "bearer-token",
        PrincipalRole::Operator,
    );
    let layer = GrpcAuthzLayer::new(context, metrics.clone());
    let mut service = layer.layer(SummaryService);
    let request = Request::builder()
        .uri("/rustbgpd.v1.ConfigService/DiffRuntimeConfig")
        .body(Body::empty())
        .unwrap();

    let response = service.call(request).await.unwrap();
    assert_eq!(response.status(), http::StatusCode::OK);

    let text = gather_text(&metrics);
    assert!(text.contains("result=\"handler_ok\""));
}

#[tokio::test]
async fn audit_layer_denies_method_above_listener_cap() {
    let metrics = BgpMetrics::new();
    let context = tier_test_context(
        "tcp://127.0.0.1:50051",
        "read_write",
        AuthTier::SensitiveRead,
        GrpcAuthnKind::BearerToken,
        "bearer-token",
        PrincipalRole::Operator,
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
    let context = tier_test_context(
        "tcp://127.0.0.1:50051",
        "read_write",
        AuthTier::Mutating,
        GrpcAuthnKind::BearerToken,
        "bearer-token",
        PrincipalRole::Operator,
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
    let context = tier_test_context(
        "tcp://127.0.0.1:50051",
        "read_write",
        AuthTier::SensitiveRead,
        GrpcAuthnKind::BearerToken,
        "bearer-token",
        PrincipalRole::Operator,
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
    let context = tier_test_context(
        "tcp://127.0.0.1:50051",
        "read_write",
        AuthTier::SensitiveRead,
        GrpcAuthnKind::BearerToken,
        "bearer-token",
        PrincipalRole::Operator,
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

#[tokio::test]
async fn tier_enforcement_allows_observer_sensitive_read() {
    let metrics = BgpMetrics::new();
    let context = GrpcAuthAuditContext::new(
        "tcp://127.0.0.1:50051",
        "read_write",
        AuthTier::OperatorOnly,
        GrpcAuthnKind::BearerToken,
        "observer.example",
    )
    .with_role_enforcement(
        AuthEnforcement::Tier,
        roles(&[("observer.example", PrincipalRole::Observer)]),
    )
    .with_bearer_token(Some("secret"));
    let layer = GrpcAuthzLayer::new(context, metrics.clone());
    let mut service = layer.layer(EchoService);
    let request = Request::builder()
        .uri("/rustbgpd.v1.ConfigService/DiffRuntimeConfig")
        .header("authorization", "Bearer secret")
        .body(Body::empty())
        .unwrap();

    let response = service.call(request).await.unwrap();
    assert_eq!(response.status(), http::StatusCode::OK);

    let text = gather_text(&metrics);
    assert!(text.contains("result=\"handler_ok\""));
}

/// Mutation proof: removing Tier enforcement from `tier_test_context` lets
/// the observer mutate and makes the `PermissionDenied` assertion red.
#[tokio::test]
async fn tier_enforcement_denies_mutating_for_observer() {
    let metrics = BgpMetrics::new();
    let context = tier_test_context(
        "tcp://127.0.0.1:50051",
        "read_write",
        AuthTier::OperatorOnly,
        GrpcAuthnKind::BearerToken,
        "observer.example",
        PrincipalRole::Observer,
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
    assert!(text.contains("result=\"role_tier_denied\""));
    assert!(text.contains("tier=\"mutating\""));
}

#[tokio::test]
async fn tier_enforcement_denies_operator_only_for_automation() {
    let metrics = BgpMetrics::new();
    let context = GrpcAuthAuditContext::new(
        "unix:///run/rustbgpd/grpc.sock",
        "read_write",
        AuthTier::OperatorOnly,
        GrpcAuthnKind::Uds,
        "automation.example",
    )
    .with_role_enforcement(
        AuthEnforcement::Tier,
        roles(&[("automation.example", PrincipalRole::Automation)]),
    );
    let layer = GrpcAuthzLayer::new(context, metrics.clone());
    let mut service = layer.layer(EchoService);
    let request = Request::builder()
        .uri("/rustbgpd.v1.ControlService/Shutdown")
        .body(Body::empty())
        .unwrap();

    let response = service.call(request).await.unwrap();
    let status = tonic::Status::from_header_map(response.headers()).unwrap();
    assert_eq!(status.code(), tonic::Code::PermissionDenied);

    let text = gather_text(&metrics);
    assert!(text.contains("result=\"role_tier_denied\""));
}

#[tokio::test]
async fn tier_enforcement_allows_operator_only_for_operator() {
    let metrics = BgpMetrics::new();
    let context = GrpcAuthAuditContext::new(
        "unix:///run/rustbgpd/grpc.sock",
        "read_write",
        AuthTier::OperatorOnly,
        GrpcAuthnKind::Uds,
        "operator.example",
    )
    .with_role_enforcement(
        AuthEnforcement::Tier,
        roles(&[("operator.example", PrincipalRole::Operator)]),
    );
    let layer = GrpcAuthzLayer::new(context, metrics.clone());
    let mut service = layer.layer(EchoService);
    let request = Request::builder()
        .uri("/rustbgpd.v1.ControlService/Shutdown")
        .body(Body::empty())
        .unwrap();

    let response = service.call(request).await.unwrap();
    assert_eq!(response.status(), http::StatusCode::OK);

    let text = gather_text(&metrics);
    assert!(text.contains("result=\"handler_ok\""));
}

#[tokio::test]
async fn tier_enforcement_denies_unmapped_principal() {
    let metrics = BgpMetrics::new();
    let context = GrpcAuthAuditContext::new(
        "unix:///run/rustbgpd/grpc.sock",
        "read_write",
        AuthTier::OperatorOnly,
        GrpcAuthnKind::Uds,
        "unmapped.example",
    )
    .with_role_enforcement(AuthEnforcement::Tier, roles(&[]));
    let layer = GrpcAuthzLayer::new(context, metrics.clone());
    let mut service = layer.layer(EchoService);
    let request = Request::builder()
        .uri("/rustbgpd.v1.ConfigService/DiffRuntimeConfig")
        .body(Body::empty())
        .unwrap();

    let response = service.call(request).await.unwrap();
    let status = tonic::Status::from_header_map(response.headers()).unwrap();
    assert_eq!(status.code(), tonic::Code::PermissionDenied);

    let text = gather_text(&metrics);
    assert!(text.contains("result=\"principal_unmapped\""));
}

#[tokio::test]
async fn tier_enforcement_authorizes_implicit_local_operator_with_empty_roles() {
    // Owner-only UDS listener with no declared principal: the implicit
    // `local-operator` identity is operator-tier without any
    // [security.grpc.roles] entry. Red proof: removing the implicit
    // resolution denies this as principal_unmapped.
    let metrics = BgpMetrics::new();
    let context = GrpcAuthAuditContext::new(
        "unix:///run/rustbgpd/grpc.sock",
        "read_write",
        AuthTier::OperatorOnly,
        GrpcAuthnKind::UdsOwner,
        LOCAL_OPERATOR_PRINCIPAL,
    )
    .with_role_enforcement(AuthEnforcement::Tier, roles(&[]))
    .with_implicit_local_operator();
    let layer = GrpcAuthzLayer::new(context, metrics.clone());
    let mut service = layer.layer(EchoService);
    let request = Request::builder()
        .uri("/rustbgpd.v1.ControlService/Shutdown")
        .body(Body::empty())
        .unwrap();

    let response = service.call(request).await.unwrap();
    assert_eq!(response.status(), http::StatusCode::OK);

    let text = gather_text(&metrics);
    assert!(text.contains("result=\"handler_ok\""));
    assert!(text.contains("authn=\"uds_owner\""));
}

#[tokio::test]
async fn tier_enforcement_still_caps_implicit_local_operator_by_listener_tier() {
    // The listener max_tier ceiling applies to the implicit identity
    // exactly as it does to declared principals.
    let metrics = BgpMetrics::new();
    let context = GrpcAuthAuditContext::new(
        "unix:///run/rustbgpd/grpc.sock",
        "read_write",
        AuthTier::SensitiveRead,
        GrpcAuthnKind::UdsOwner,
        LOCAL_OPERATOR_PRINCIPAL,
    )
    .with_role_enforcement(AuthEnforcement::Tier, roles(&[]))
    .with_implicit_local_operator();
    let layer = GrpcAuthzLayer::new(context, metrics.clone());
    let mut service = layer.layer(EchoService);
    let request = Request::builder()
        .uri("/rustbgpd.v1.ControlService/Shutdown")
        .body(Body::empty())
        .unwrap();

    let response = service.call(request).await.unwrap();
    let status = tonic::Status::from_header_map(response.headers()).unwrap();
    assert_eq!(status.code(), tonic::Code::PermissionDenied);

    let text = gather_text(&metrics);
    assert!(text.contains("result=\"listener_tier_denied\""));
}

#[tokio::test]
async fn tier_enforcement_authenticates_bearer_before_role_denial() {
    let metrics = BgpMetrics::new();
    let context = GrpcAuthAuditContext::new(
        "tcp://127.0.0.1:50051",
        "read_write",
        AuthTier::OperatorOnly,
        GrpcAuthnKind::BearerToken,
        "observer.example",
    )
    .with_role_enforcement(
        AuthEnforcement::Tier,
        roles(&[("observer.example", PrincipalRole::Observer)]),
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
    assert!(!text.contains("result=\"role_tier_denied\""));
}

#[tokio::test]
async fn listener_cap_remains_stricter_than_operator_role() {
    let metrics = BgpMetrics::new();
    let context = GrpcAuthAuditContext::new(
        "unix:///run/rustbgpd/grpc.sock",
        "read_write",
        AuthTier::SensitiveRead,
        GrpcAuthnKind::Uds,
        "operator.example",
    )
    .with_role_enforcement(
        AuthEnforcement::Tier,
        roles(&[("operator.example", PrincipalRole::Operator)]),
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
    assert!(text.contains("result=\"listener_tier_denied\""));
    assert!(!text.contains("result=\"role_tier_denied\""));
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
        tonic_tls_connect_info_with_client_cert(&ca_cert, &issuer, client_cert, client_key).await;
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

#[tokio::test]
async fn mtls_principal_resolution_uses_rustbgpd_connection_cache() {
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
        rustbgpd_tls_connect_info_with_client_cert(&ca_cert, &issuer, client_cert, client_key)
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
    assert_eq!(
        context.principal_for_extensions(&extensions).as_ref(),
        "rustbgpd://operator/alice"
    );
}
