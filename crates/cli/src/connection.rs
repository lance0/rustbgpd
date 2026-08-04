//! gRPC connection handling for `rbgp`.
//!
//! Supports both Unix domain socket (`unix:///path`) and TCP (`host:port` or
//! `http://host:port`) endpoints, with optional bearer-token authentication
//! loaded from a file.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use hyper_util::rt::TokioIo;
use tokio::net::UnixStream;
use tonic::metadata::AsciiMetadataValue;
use tonic::service::Interceptor;
use tonic::service::interceptor::InterceptedService;
use tonic::transport::{Channel, Endpoint, Uri};
use tonic::{Request, Status};
use tower::service_fn;

use crate::error::CliError;
use crate::proto::config_service_client::ConfigServiceClient;
use crate::proto::rib_service_client::RibServiceClient;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const AUTHORIZATION_HEADER: &str = "authorization";
const BEARER_PREFIX: &str = "Bearer ";

/// Decode ceiling for full unary listing responses, replacing tonic's
/// 4 MiB client default on the clients built by
/// [`Connection::rib_listing_client`].
///
/// Budget rationale: representative encoded listing rows are roughly
/// 52-101 bytes (the widest current fixture, a VPN route entry, encodes
/// to ~101 bytes), so 64 MiB holds at least 500,000 of the largest rows
/// (~50.5 MB) — roughly 0.7-1.3 million rows across the listing shapes —
/// with headroom for attribute variation. Deliberately finite, never
/// `usize::MAX`: a response above the ceiling still fails closed with
/// `out of range` instead of buffering without bound.
pub(crate) const LISTING_MAX_DECODE_BYTES: usize = 64 * 1024 * 1024;

/// Decode ceiling for the normalized TOML returned by
/// `ConfigService.GetEffectiveConfig`.
///
/// The document is deliberately a byte-exact full export rather than a
/// paged surface. Keep the allowance finite and method-specific: 384 MiB of
/// TOML plus the protobuf string field's one-byte tag and five-byte length
/// varint at that size. Other `ConfigService` RPCs retain tonic's 4 MiB
/// client default.
pub(crate) const EFFECTIVE_CONFIG_MAX_TOML_BYTES: usize = 384 * 1024 * 1024;
const EFFECTIVE_CONFIG_PROTOBUF_ENVELOPE_BYTES: usize =
    1 + prost::encoding::encoded_len_varint(EFFECTIVE_CONFIG_MAX_TOML_BYTES as u64);
pub(crate) const EFFECTIVE_CONFIG_MAX_DECODE_BYTES: usize =
    EFFECTIVE_CONFIG_MAX_TOML_BYTES + EFFECTIVE_CONFIG_PROTOBUF_ENVELOPE_BYTES;

#[derive(Clone)]
pub(crate) struct Connection {
    channel: Channel,
    token: Option<AsciiMetadataValue>,
}

impl Connection {
    pub(crate) const fn new(channel: Channel, token: Option<AsciiMetadataValue>) -> Self {
        Self { channel, token }
    }

    pub(crate) fn channel(&self) -> Channel {
        self.channel.clone()
    }

    pub(crate) fn interceptor(&self) -> AuthInterceptor {
        AuthInterceptor {
            token: self.token.clone(),
        }
    }

    /// A `RibService` client for the full unary listing RPCs (BGP-LS,
    /// VPN, labeled, RTC, FlowSpec, EVPN, blackhole discards, unpaged
    /// FIB, topology nodes/links, ORR status), with the decode ceiling
    /// raised to [`LISTING_MAX_DECODE_BYTES`]. Every other client keeps
    /// tonic's 4 MiB default.
    pub(crate) fn rib_listing_client(
        &self,
    ) -> RibServiceClient<InterceptedService<Channel, AuthInterceptor>> {
        self.rib_client_with_decode_limit(LISTING_MAX_DECODE_BYTES)
    }

    /// A `ConfigService` client only for `GetEffectiveConfig`, with room for
    /// one full bounded normalized-config document. Other config operations
    /// continue to use the generated client's default decode ceiling.
    pub(crate) fn effective_config_client(
        &self,
    ) -> ConfigServiceClient<InterceptedService<Channel, AuthInterceptor>> {
        self.config_client_with_decode_limit(EFFECTIVE_CONFIG_MAX_DECODE_BYTES)
    }

    /// Shared constructor core; tests drive it with a small cap to prove
    /// the ceiling is enforced rather than advisory.
    fn rib_client_with_decode_limit(
        &self,
        limit: usize,
    ) -> RibServiceClient<InterceptedService<Channel, AuthInterceptor>> {
        RibServiceClient::with_interceptor(self.channel(), self.interceptor())
            .max_decoding_message_size(limit)
    }

    /// Shared constructor core; tests inject a small cap to prove the limit
    /// is enforced rather than advisory.
    fn config_client_with_decode_limit(
        &self,
        limit: usize,
    ) -> ConfigServiceClient<InterceptedService<Channel, AuthInterceptor>> {
        ConfigServiceClient::with_interceptor(self.channel(), self.interceptor())
            .max_decoding_message_size(limit)
    }
}

#[derive(Clone, Debug, Default)]
pub(crate) struct AuthInterceptor {
    token: Option<AsciiMetadataValue>,
}

impl Interceptor for AuthInterceptor {
    fn call(&mut self, mut request: Request<()>) -> Result<Request<()>, Status> {
        if let Some(token) = self.token.clone() {
            request.metadata_mut().insert(AUTHORIZATION_HEADER, token);
        }
        Ok(request)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum EndpointTarget {
    Tcp(String),
    Uds(PathBuf),
}

pub(crate) async fn connect(addr: &str, token_file: Option<&str>) -> Result<Connection, CliError> {
    let token = load_bearer_token(token_file)?;
    let channel = match parse_endpoint_target(addr)? {
        EndpointTarget::Tcp(uri) => connect_tcp(&uri, addr).await?,
        EndpointTarget::Uds(path) => connect_uds(&path, addr).await?,
    };
    Ok(Connection::new(channel, token))
}

/// Map a connect-time transport error to a short human failure class,
/// suppressing tonic/hyper wrapper debris ("transport error").
///
/// The useful cause is the `io::Error` buried in the source chain (ENOENT
/// for a missing unix socket, ECONNREFUSED, ETIMEDOUT, EACCES, ...). When no
/// io error is present (TLS handshake, HTTP/2 setup, internal timeout), the
/// deepest source's own message is the honest fallback class.
fn connect_failure_class(error: &(dyn std::error::Error + 'static)) -> String {
    let mut deepest = error;
    let mut current = Some(error);
    while let Some(err) = current {
        if let Some(io) = err.downcast_ref::<std::io::Error>() {
            return match io.kind() {
                std::io::ErrorKind::NotFound => "socket does not exist".into(),
                std::io::ErrorKind::ConnectionRefused => "connection refused".into(),
                std::io::ErrorKind::PermissionDenied => "permission denied".into(),
                std::io::ErrorKind::TimedOut => "connection timed out".into(),
                _ => io.to_string(),
            };
        }
        deepest = err;
        current = err.source();
    }
    deepest.to_string()
}

fn connect_error(addr: &str, error: &tonic::transport::Error) -> CliError {
    CliError::Connect {
        addr: addr.to_string(),
        detail: connect_failure_class(error),
    }
}

fn parse_endpoint_target(addr: &str) -> Result<EndpointTarget, CliError> {
    if let Some(path) = addr.strip_prefix("unix://") {
        return parse_uds_target(path);
    }

    if addr.starts_with("http://") || addr.starts_with("https://") {
        return Ok(EndpointTarget::Tcp(addr.to_string()));
    }

    Ok(EndpointTarget::Tcp(format!("http://{addr}")))
}

fn parse_uds_target(path: &str) -> Result<EndpointTarget, CliError> {
    if path.is_empty() {
        return Err(CliError::Argument(
            "invalid address: unix:// path must not be empty".into(),
        ));
    }

    let path = PathBuf::from(path);
    if !path.is_absolute() {
        return Err(CliError::Argument(format!(
            "invalid address: unix socket path must be absolute: {}",
            path.display()
        )));
    }

    Ok(EndpointTarget::Uds(path))
}

fn load_bearer_token(token_file: Option<&str>) -> Result<Option<AsciiMetadataValue>, CliError> {
    let Some(token_file) = token_file else {
        return Ok(None);
    };

    let raw = fs::read_to_string(token_file)
        .map_err(|e| CliError::Argument(format!("failed to read token file {token_file}: {e}")))?;
    let token = raw.trim_end();
    if token.is_empty() {
        return Err(CliError::Argument(format!(
            "token file is empty: {token_file}"
        )));
    }

    let header = format!("{BEARER_PREFIX}{token}");
    let value = AsciiMetadataValue::try_from(header).map_err(|e| {
        CliError::Argument(format!(
            "invalid token file {token_file}: authorization value must be ASCII ({e})"
        ))
    })?;
    Ok(Some(value))
}

async fn connect_tcp(uri: &str, display_addr: &str) -> Result<Channel, CliError> {
    let endpoint = Endpoint::from_shared(uri.to_string())
        .map_err(|e| CliError::Argument(format!("invalid address: {e}")))?
        .connect_timeout(CONNECT_TIMEOUT);
    endpoint
        .connect()
        .await
        .map_err(|e| connect_error(display_addr, &e))
}

async fn connect_uds(path: &Path, display_addr: &str) -> Result<Channel, CliError> {
    let endpoint = Endpoint::try_from("http://[::]:50051")
        .map_err(|e| CliError::Argument(format!("invalid UDS endpoint: {e}")))?
        .connect_timeout(CONNECT_TIMEOUT);
    let path = path.to_path_buf();
    let connect = endpoint.connect_with_connector(service_fn(move |_: Uri| {
        let path = path.clone();
        async move {
            let stream = UnixStream::connect(path).await?;
            Ok::<_, std::io::Error>(TokioIo::new(stream))
        }
    }));
    let channel = tokio::time::timeout(CONNECT_TIMEOUT, connect)
        .await
        .map_err(|_| CliError::Connect {
            addr: display_addr.to_string(),
            detail: format!("connect timed out after {}s", CONNECT_TIMEOUT.as_secs()),
        })?
        .map_err(|e| connect_error(display_addr, &e))?;
    Ok(channel)
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tonic::metadata::MetadataValue;

    use super::*;

    #[test]
    fn parse_endpoint_target_accepts_plain_tcp_address() {
        assert_eq!(
            parse_endpoint_target("127.0.0.1:50051").unwrap(),
            EndpointTarget::Tcp("http://127.0.0.1:50051".into())
        );
    }

    #[test]
    fn parse_endpoint_target_preserves_http_uri() {
        assert_eq!(
            parse_endpoint_target("http://127.0.0.1:50051").unwrap(),
            EndpointTarget::Tcp("http://127.0.0.1:50051".into())
        );
    }

    #[test]
    fn parse_endpoint_target_accepts_unix_uri() {
        assert_eq!(
            parse_endpoint_target("unix:///tmp/rustbgpd.sock").unwrap(),
            EndpointTarget::Uds(PathBuf::from("/tmp/rustbgpd.sock"))
        );
    }

    #[test]
    fn parse_endpoint_target_rejects_relative_unix_uri() {
        let err = parse_endpoint_target("unix://tmp/rustbgpd.sock").unwrap_err();
        assert_eq!(
            err.to_string(),
            "invalid address: unix socket path must be absolute: tmp/rustbgpd.sock"
        );
    }

    #[test]
    fn parse_endpoint_target_rejects_empty_unix_uri() {
        let err = parse_endpoint_target("unix://").unwrap_err();
        assert_eq!(
            err.to_string(),
            "invalid address: unix:// path must not be empty"
        );
    }

    #[test]
    fn auth_interceptor_injects_bearer_token() {
        let mut interceptor = AuthInterceptor {
            token: Some(MetadataValue::try_from("Bearer secret").unwrap()),
        };
        let request = interceptor.call(Request::new(())).unwrap();

        assert_eq!(
            request.metadata().get(AUTHORIZATION_HEADER).unwrap(),
            "Bearer secret"
        );
    }

    #[test]
    fn auth_interceptor_leaves_request_untouched_without_token() {
        let mut interceptor = AuthInterceptor::default();
        let request = interceptor.call(Request::new(())).unwrap();

        assert!(request.metadata().get(AUTHORIZATION_HEADER).is_none());
    }

    #[test]
    fn load_bearer_token_trims_trailing_whitespace() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("token.txt");
        fs::write(&path, "secret-token\n").unwrap();

        let token = load_bearer_token(Some(path.to_str().unwrap())).unwrap();

        assert_eq!(token.unwrap(), "Bearer secret-token");
    }

    #[test]
    fn load_bearer_token_rejects_empty_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("token.txt");
        fs::write(&path, "\n").unwrap();

        let err = load_bearer_token(Some(path.to_str().unwrap())).unwrap_err();

        assert_eq!(
            err.to_string(),
            format!("token file is empty: {}", path.display())
        );
    }

    // Connecting to a socket nothing is listening on must surface the
    // target address and a human failure class — never raw transport/io
    // debris ("transport error: ..."). A nonexistent UDS path fails
    // immediately (ENOENT) so this stays fast and deterministic — no
    // dependence on the 5s connect timeout.
    #[tokio::test]
    async fn connect_to_absent_socket_reports_address_and_class() {
        let dir = tempfile::tempdir().unwrap();
        let absent = dir.path().join("not-listening.sock");
        let addr = format!("unix://{}", absent.display());

        // `Connection` is not `Debug`, so match instead of `expect_err`.
        let err = match connect(&addr, None).await {
            Ok(_) => panic!("connecting to an unbound socket must fail"),
            Err(err) => err,
        };

        assert_eq!(
            err.to_string(),
            format!(
                "cannot reach rustbgpd at {addr} (socket does not exist)\n  \
                 hint: is the daemon running? if it uses a different endpoint, pass -s or set RUSTBGPD_ADDR"
            )
        );
    }

    use prost::Message;
    use rustbgpd_api::proto as server_proto;

    /// A valid BGP-LS listing response whose encoded size is driven by
    /// `route_count` x `payload_len` — the loopback fixture for the
    /// decode-ceiling tests.
    fn bgpls_listing_fixture(
        route_count: usize,
        payload_len: usize,
    ) -> server_proto::ListBgpLsResponse {
        let route = server_proto::BgpLsRouteEntry {
            afi_safi: server_proto::AddressFamily::BgpLs as i32,
            family: "bgp_ls".to_string(),
            nlri_type: 1,
            nlri_type_name: "node".to_string(),
            payload: vec![0xab; payload_len],
            descriptor: vec![0x04, 0x05],
            next_hop: "192.0.2.1".to_string(),
            peer_address: "198.51.100.1".to_string(),
            as_path: vec![64512],
            ..Default::default()
        };
        server_proto::ListBgpLsResponse {
            routes: vec![route; route_count],
        }
    }

    // The production listing client must decode a full unary listing
    // response larger than tonic's 4 MiB client default, end to end over
    // a real TCP loopback server.
    #[tokio::test]
    async fn listing_client_decodes_response_over_default_ceiling() {
        let handle = crate::test_support::spawn_mock_server(None).await;
        let resp = bgpls_listing_fixture(2200, 2048);
        assert!(
            resp.encoded_len() > 4 * 1024 * 1024,
            "fixture must exceed the 4 MiB default: {} bytes",
            resp.encoded_len()
        );
        let count = resp.routes.len();
        *handle.state.list_bgpls_response.lock().await = Some(resp);

        let connection = connect(&handle.addr, None).await.unwrap();
        let got = connection
            .rib_listing_client()
            .list_bgp_ls_routes(crate::proto::ListBgpLsRequest::default())
            .await
            .expect("bounded listing client must decode a >4 MiB listing")
            .into_inner();
        assert_eq!(got.routes.len(), count);
    }

    // The raw generated constructor keeps tonic's 4 MiB default: the same
    // >4 MiB listing must fail with OutOfRange. This pins both the defect
    // and that non-listing clients (which all use this constructor) stay
    // at the default.
    #[tokio::test]
    async fn default_generated_client_fails_out_of_range_over_default_ceiling() {
        let handle = crate::test_support::spawn_mock_server(None).await;
        *handle.state.list_bgpls_response.lock().await = Some(bgpls_listing_fixture(2200, 2048));

        let connection = connect(&handle.addr, None).await.unwrap();
        let mut client = crate::proto::rib_service_client::RibServiceClient::with_interceptor(
            connection.channel(),
            connection.interceptor(),
        );
        let err = client
            .list_bgp_ls_routes(crate::proto::ListBgpLsRequest::default())
            .await
            .expect_err("default client must reject a >4 MiB listing");
        assert_eq!(err.code(), tonic::Code::OutOfRange, "{err}");
    }

    // The ceiling is enforced, not advisory: the same constructor core
    // with a 1 KiB cap must reject a response just over 1 KiB with
    // OutOfRange.
    #[tokio::test]
    async fn listing_client_ceiling_is_enforced() {
        let handle = crate::test_support::spawn_mock_server(None).await;
        let resp = bgpls_listing_fixture(2, 1024);
        assert!(resp.encoded_len() > 1024);
        *handle.state.list_bgpls_response.lock().await = Some(resp);

        let connection = connect(&handle.addr, None).await.unwrap();
        let err = connection
            .rib_client_with_decode_limit(1024)
            .list_bgp_ls_routes(crate::proto::ListBgpLsRequest::default())
            .await
            .expect_err("a 1 KiB cap must reject a >1 KiB listing");
        assert_eq!(err.code(), tonic::Code::OutOfRange, "{err}");
    }

    // Raising the decode ceiling must not drop the auth interceptor: the
    // bearer token still reaches a server that enforces it, and a
    // connection without the token is still rejected.
    #[tokio::test]
    async fn listing_client_carries_bearer_token() {
        let handle = crate::test_support::spawn_mock_server(Some("listing-secret")).await;
        let dir = tempfile::tempdir().unwrap();
        let token_path = dir.path().join("token.txt");
        fs::write(&token_path, "listing-secret\n").unwrap();

        let connection = connect(&handle.addr, Some(token_path.to_str().unwrap()))
            .await
            .unwrap();
        connection
            .rib_listing_client()
            .list_bgp_ls_routes(crate::proto::ListBgpLsRequest::default())
            .await
            .expect("authenticated listing call must succeed");

        let bare = connect(&handle.addr, None).await.unwrap();
        let err = bare
            .rib_listing_client()
            .list_bgp_ls_routes(crate::proto::ListBgpLsRequest::default())
            .await
            .expect_err("server must reject the tokenless client");
        assert_eq!(err.code(), tonic::Code::Unauthenticated, "{err}");
    }

    fn effective_config_fixture(payload_len: usize) -> String {
        "#".repeat(payload_len)
    }

    // Removing the production cap from `effective_config_client` makes this
    // real >4 MiB loopback response fail with OutOfRange.
    #[tokio::test]
    async fn effective_config_client_decodes_response_over_default_ceiling() {
        let handle = crate::test_support::spawn_mock_server(None).await;
        let toml = effective_config_fixture(5 * 1024 * 1024);
        let response = server_proto::GetEffectiveConfigResponse { toml };
        assert!(
            response.encoded_len() > 4 * 1024 * 1024,
            "fixture must exceed tonic's default decode ceiling"
        );
        let expected_len = response.toml.len();
        *handle.state.config_effective_toml.lock().await = Some(response.toml);

        let connection = connect(&handle.addr, None).await.unwrap();
        let got = connection
            .effective_config_client()
            .get_effective_config(crate::proto::GetEffectiveConfigRequest {})
            .await
            .expect("bounded effective-config client must decode a >4 MiB document")
            .into_inner();
        assert_eq!(got.toml.len(), expected_len);
    }

    // Replacing the finite cap with an unbounded/default-ignoring constructor
    // makes this injected 1 KiB ceiling stop rejecting the response.
    #[tokio::test]
    async fn effective_config_client_ceiling_is_enforced() {
        let handle = crate::test_support::spawn_mock_server(None).await;
        let toml = effective_config_fixture(2048);
        let response = server_proto::GetEffectiveConfigResponse { toml };
        assert!(response.encoded_len() > 1024);
        *handle.state.config_effective_toml.lock().await = Some(response.toml);

        let connection = connect(&handle.addr, None).await.unwrap();
        let err = connection
            .config_client_with_decode_limit(1024)
            .get_effective_config(crate::proto::GetEffectiveConfigRequest {})
            .await
            .expect_err("a 1 KiB cap must reject a >1 KiB effective config");
        assert_eq!(err.code(), tonic::Code::OutOfRange, "{err}");
    }

    // The method-specific constructor must preserve the ordinary auth
    // interceptor. Replacing it with an unintercepted client makes the
    // authenticated request fail; weakening server auth makes the bare
    // request stop returning Unauthenticated.
    #[tokio::test]
    async fn effective_config_client_carries_bearer_token() {
        let handle = crate::test_support::spawn_mock_server(Some("effective-secret")).await;
        let dir = tempfile::tempdir().unwrap();
        let token_path = dir.path().join("token.txt");
        fs::write(&token_path, "effective-secret\n").unwrap();

        let connection = connect(&handle.addr, Some(token_path.to_str().unwrap()))
            .await
            .unwrap();
        connection
            .effective_config_client()
            .get_effective_config(crate::proto::GetEffectiveConfigRequest {})
            .await
            .expect("authenticated effective-config call must succeed");

        let bare = connect(&handle.addr, None).await.unwrap();
        let err = bare
            .effective_config_client()
            .get_effective_config(crate::proto::GetEffectiveConfigRequest {})
            .await
            .expect_err("server must reject the tokenless client");
        assert_eq!(err.code(), tonic::Code::Unauthenticated, "{err}");
    }

    // The cap is 384 MiB of TOML plus exactly the protobuf string-field
    // envelope at that payload size (one-byte tag + five-byte varint). Any
    // global/unbounded replacement or omitted envelope makes this red.
    #[allow(
        clippy::assertions_on_constants,
        reason = "constant assertions are mutation fences for the finite protocol budget"
    )]
    #[test]
    fn effective_config_decode_ceiling_has_exact_finite_envelope() {
        assert_eq!(
            prost::encoding::encoded_len_varint(EFFECTIVE_CONFIG_MAX_TOML_BYTES as u64),
            5
        );
        assert_eq!(EFFECTIVE_CONFIG_PROTOBUF_ENVELOPE_BYTES, 6);
        assert_eq!(EFFECTIVE_CONFIG_MAX_DECODE_BYTES, 384 * 1024 * 1024 + 6);
        assert!(EFFECTIVE_CONFIG_MAX_DECODE_BYTES < usize::MAX);

        let production = include_str!("connection.rs")
            .split("#[cfg(test)]")
            .next()
            .unwrap();
        let constructors = production
            .split("pub(crate) fn effective_config_client")
            .nth(1)
            .unwrap();
        assert_eq!(
            constructors
                .matches("self.config_client_with_decode_limit(EFFECTIVE_CONFIG_MAX_DECODE_BYTES)")
                .count(),
            1,
            "production helper must consume the finite effective-config cap"
        );
        let config_constructor = constructors
            .split("fn config_client_with_decode_limit")
            .nth(1)
            .unwrap();
        assert_eq!(
            config_constructor
                .matches(".max_decoding_message_size(limit)")
                .count(),
            1,
            "ConfigService constructor must enforce its supplied limit"
        );
        assert!(!config_constructor.contains("usize::MAX"));
    }

    fn collect_production_rust_sources(dir: &Path, sources: &mut Vec<(PathBuf, String)>) {
        for entry in fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                collect_production_rust_sources(&path, sources);
                continue;
            }
            if path.extension().and_then(|ext| ext.to_str()) != Some("rs")
                || path.file_name().and_then(|name| name.to_str()) == Some("test_support.rs")
            {
                continue;
            }
            let mut source = fs::read_to_string(&path).unwrap();
            if let Some(test_module) = source.rfind("#[cfg(test)]\nmod tests {") {
                source.truncate(test_module);
            }
            sources.push((path, source));
        }
    }

    // Both and only the full-document consumers anywhere in the CLI source
    // tree must use the bounded helper. Reverting either command to a raw
    // generated client, or adding a third production callsite in any file,
    // changes these counts; test-only modules and test_support.rs are removed.
    #[test]
    fn effective_config_surface_inventory_uses_bounded_client() {
        let mut sources = Vec::new();
        collect_production_rust_sources(
            &Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
            &mut sources,
        );
        let constructors: usize = sources
            .iter()
            .map(|(_, source)| source.matches(".effective_config_client()").count())
            .sum();
        let calls: usize = sources
            .iter()
            .map(|(_, source)| source.matches(".get_effective_config(").count())
            .sum();
        assert_eq!(constructors, 2, "inventoried bounded constructor sites");
        assert_eq!(calls, 2, "inventoried effective-config RPC calls");

        let mut callsite_files: Vec<_> = sources
            .iter()
            .filter(|(_, source)| source.contains(".get_effective_config("))
            .map(|(path, _)| path.strip_prefix(env!("CARGO_MANIFEST_DIR")).unwrap())
            .collect();
        callsite_files.sort_unstable();
        assert_eq!(
            callsite_files,
            [
                Path::new("src/commands/config.rs"),
                Path::new("src/commands/doctor.rs")
            ]
        );
    }

    // Inventory fence over the full unary listing surfaces. Every listing
    // RPC invocation must be reachable only through the bounded
    // constructor: adding a new listing call on a raw generated client,
    // or reverting an inventoried command to one, changes a count and
    // fails here. Counts cover non-test code only.
    #[test]
    fn listing_surface_inventory_uses_bounded_client() {
        const LISTING_RPCS: &[&str] = &[
            ".list_evpn_routes(",
            ".list_bgp_ls_routes(",
            ".list_vpn_routes(",
            ".list_labeled_routes(",
            ".list_rtc_routes(",
            ".list_flow_spec_routes(",
            ".list_blackhole_discards(",
            ".list_fib_routes(",
            ".list_topology_nodes(",
            ".list_topology_links(",
            ".list_orr_status(",
        ];
        // (file, source, bounded constructor sites, listing RPC invocations)
        let surfaces = [
            ("commands/rib.rs", include_str!("commands/rib.rs"), 6, 6),
            ("commands/evpn.rs", include_str!("commands/evpn.rs"), 2, 3),
            (
                "commands/flowspec.rs",
                include_str!("commands/flowspec.rs"),
                1,
                1,
            ),
            (
                "commands/topology.rs",
                include_str!("commands/topology.rs"),
                2,
                2,
            ),
            ("commands/orr.rs", include_str!("commands/orr.rs"), 1, 1),
        ];

        let mut total_ctors = 0;
        let mut total_rpcs = 0;
        for (name, source, expect_ctors, expect_rpcs) in surfaces {
            let code = source.split("#[cfg(test)]").next().unwrap();
            let ctors = code.matches(".rib_listing_client()").count();
            let rpcs: usize = LISTING_RPCS
                .iter()
                .map(|rpc| code.matches(rpc).count())
                .sum();
            assert_eq!(ctors, expect_ctors, "{name}: bounded constructor sites");
            assert_eq!(rpcs, expect_rpcs, "{name}: listing RPC invocations");
            // The ceiling lives only in connection.rs — no per-command
            // decode-limit overrides, so non-listing clients keep the
            // tonic default.
            assert_eq!(
                code.matches("max_decoding_message_size").count(),
                0,
                "{name}: decode limits must come from Connection::rib_listing_client"
            );
            total_ctors += ctors;
            total_rpcs += rpcs;
        }
        assert_eq!(total_ctors, 12, "inventoried constructor sites");
        assert_eq!(total_rpcs, 13, "inventoried listing RPC invocations");
    }

    // Budget rationale for the 64 MiB ceiling: it must hold at least
    // 500,000 of the largest representative listing rows (the widest
    // current VPN fixture) while staying finite — never `usize::MAX`.
    // The upper-bound assertion is deliberately constant: it is the
    // fence that goes red if the ceiling is ever made unbounded.
    #[allow(
        clippy::assertions_on_constants,
        reason = "the constant upper-bound assert is the mutation fence that goes red if the ceiling is ever made unbounded"
    )]
    #[test]
    fn listing_decode_ceiling_budget_rationale() {
        let widest_row = crate::proto::VpnRouteEntry {
            afi_safi: "l3vpn_ipv4_unicast".to_string(),
            route_distinguisher: vec![0, 0, 0xfd, 0xe8, 0, 0, 0, 1],
            route_distinguisher_str: "65000:1".to_string(),
            prefix: "10.1.0.0/24".to_string(),
            labels: vec![24017],
            next_hop: "192.0.2.1".to_string(),
            peer_address: "198.51.100.1".to_string(),
            as_path: vec![64512],
            communities: vec![],
            extended_communities: vec!["RT:65000:1".to_string()],
            stale: false,
            llgr_stale: false,
            path_id: 0,
        };
        let row_len = widest_row.encoded_len();
        // Representative encoded-row band across the listing fixtures.
        assert!(
            (52..=101).contains(&row_len),
            "representative row drifted out of band: {row_len} bytes"
        );
        assert!(
            LISTING_MAX_DECODE_BYTES >= 500_000 * row_len,
            "ceiling no longer holds 500k of the largest rows: \
             {LISTING_MAX_DECODE_BYTES} < {}",
            500_000 * row_len
        );
        assert!(
            LISTING_MAX_DECODE_BYTES <= 64 * 1024 * 1024,
            "ceiling must stay finite by design"
        );
    }

    // A socket file that exists but has no listener behind it (daemon
    // crashed, stale socket) must be classified as "connection refused",
    // not "does not exist".
    #[tokio::test]
    async fn connect_to_dead_socket_reports_connection_refused() {
        let dir = tempfile::tempdir().unwrap();
        let stale = dir.path().join("stale.sock");
        // Bind then drop the listener: the socket file remains, ECONNREFUSED.
        drop(std::os::unix::net::UnixListener::bind(&stale).unwrap());
        let addr = format!("unix://{}", stale.display());

        let err = match connect(&addr, None).await {
            Ok(_) => panic!("connecting to a dead socket must fail"),
            Err(err) => err,
        };

        let rendered = err.to_string();
        assert!(
            rendered.contains(&format!(
                "cannot reach rustbgpd at {addr} (connection refused)"
            )),
            "{rendered}"
        );
    }
}
