//! gRPC connection handling for `rbgp`.
//!
//! Supports both Unix domain socket (`unix:///path`) and TCP (`host:port` or
//! `http://host:port`) endpoints, HTTPS with explicit CA trust and required
//! client identity, and orthogonal bearer-token authentication loaded from a file.

use std::fs;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hyper_util::rt::TokioIo;
use tokio::net::UnixStream;
use tonic::metadata::AsciiMetadataValue;
use tonic::service::Interceptor;
use tonic::service::interceptor::InterceptedService;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint, Identity, Uri};
use tonic::{Request, Status};
use tower::service_fn;

use crate::error::CliError;
use crate::proto::config_service_client::ConfigServiceClient;
use crate::proto::rib_service_client::RibServiceClient;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// Budget for one completed lightweight read, including the response body.
pub(crate) const READ_RPC_TIMEOUT: Duration = Duration::from_secs(30);
/// Allow the server's 30-minute effective-config operation plus response transfer.
pub(crate) const EFFECTIVE_CONFIG_RPC_TIMEOUT: Duration = Duration::from_secs(30 * 60 + 30);
const AUTHORIZATION_HEADER: &str = "authorization";
const BEARER_PREFIX: &str = "Bearer ";

/// Bound a generated unary read future through decoding its full response.
/// Connection and response-header timeouts alone do not bound a stalled body.
pub(crate) async fn read_rpc<T>(
    name: &str,
    future: impl Future<Output = Result<T, Status>>,
) -> Result<T, Status> {
    rpc_with_timeout(name, READ_RPC_TIMEOUT, future).await
}

/// Client wait for a runtime-only mutation: session control, graceful
/// shutdown, route injection, EVPN runtime controls and daemon shutdown.
/// The daemon bounds its own peer-manager mutation wait at 10 minutes
/// (`PEER_MANAGER_MUTATION_TIMEOUT`); the extra minute covers transfer.
pub(crate) const MUTATION_RPC_TIMEOUT: Duration = Duration::from_secs(11 * 60);
/// Client wait for a mutation the daemon persists to its configuration
/// (neighbors, dynamic ranges, policies, neighbor sets, chains, peer groups,
/// FIB tables). The settlement watchdog stops the daemon when such a change
/// has not settled within 30 minutes (`OWNED_SETTLEMENT_BUDGET`), so no reply
/// can arrive later; the extra minute covers the fence grace and transfer.
/// `mrt-dump` also uses it: the daemon does not bound a dump, which writes
/// the whole RIB.
pub(crate) const SETTLED_MUTATION_RPC_TIMEOUT: Duration = Duration::from_secs(31 * 60);
/// Client wait for each config-transaction RPC: diff, plan, apply, confirm,
/// abort and rollback, unary or streamed. The daemon bounds each operation at
/// 30 minutes (`CONFIG_OPERATION_TIMEOUT`); the extra minute covers the
/// candidate upload and response transfer. The commit-confirm window is a
/// daemon-side auto-revert timer, so the CLI has no other wait to stack on.
pub(crate) const CONFIG_TRANSACTION_RPC_TIMEOUT: Duration = Duration::from_secs(31 * 60);
/// Debug builds only: shortens every mutation and config-transaction budget
/// so process tests can observe expiry without waiting minutes.
#[cfg(debug_assertions)]
const TEST_MUTATION_RPC_TIMEOUT_MS_ENV: &str = "RBGP_TEST_MUTATION_RPC_TIMEOUT_MS";

/// `budget`, or the debug-build test override.
pub(crate) fn mutation_budget(budget: Duration) -> Duration {
    #[cfg(debug_assertions)]
    let budget = std::env::var(TEST_MUTATION_RPC_TIMEOUT_MS_ENV)
        .ok()
        .and_then(|ms| ms.parse().ok())
        .map_or(budget, Duration::from_millis);
    budget
}

/// Bound a mutation RPC. On expiry the change may still be applied, because
/// the daemon shields an accepted mutation from client cancellation: report
/// the outcome as unknown, point at `verify` (a command or place to check),
/// and never retry.
pub(crate) async fn mutation_rpc<T>(
    name: &str,
    budget: Duration,
    verify: &str,
    future: impl Future<Output = Result<T, Status>>,
) -> Result<T, Status> {
    unknown_outcome_rpc(
        name,
        budget,
        "the daemon may still apply this change",
        verify,
        future,
    )
    .await
}

/// Bound a config-transaction RPC that can change the runtime (apply,
/// confirm, abort, rollback), with the same unknown-outcome contract as
/// [`mutation_rpc`].
pub(crate) async fn config_transaction_rpc<T>(
    name: &str,
    verify: &str,
    future: impl Future<Output = Result<T, Status>>,
) -> Result<T, Status> {
    unknown_outcome_rpc(
        name,
        CONFIG_TRANSACTION_RPC_TIMEOUT,
        "the transaction may still commit or roll back",
        verify,
        future,
    )
    .await
}

async fn unknown_outcome_rpc<T>(
    name: &str,
    budget: Duration,
    outcome: &str,
    verify: &str,
    future: impl Future<Output = Result<T, Status>>,
) -> Result<T, Status> {
    rpc_with_timeout(name, mutation_budget(budget), future)
        .await
        .map_err(|status| {
            if status.code() == tonic::Code::DeadlineExceeded {
                Status::deadline_exceeded(format!(
                    "{}; outcome unknown: {outcome}; verify with {verify}",
                    status.message()
                ))
            } else {
                status
            }
        })
}

/// Bound a unary RPC by a method-specific budget.
pub(crate) async fn rpc_with_timeout<T>(
    name: &str,
    budget: Duration,
    future: impl Future<Output = Result<T, Status>>,
) -> Result<T, Status> {
    tokio::time::timeout(budget, future).await.map_err(|_| {
        Status::deadline_exceeded(format!(
            "{name} response timed out after {}s",
            budget.as_secs_f64()
        ))
    })?
}

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
    local_process: Arc<Mutex<Option<LocalProcess>>>,
    pub(crate) tls_client_identity: bool,
}

/// File paths only; certificate and private-key contents are never retained here.
#[derive(clap::Args, Default)]
pub(crate) struct TlsOptions {
    /// PEM CA bundle used to verify an HTTPS server (required for HTTPS)
    #[arg(long, env = "RUSTBGPD_TLS_CA", global = true, value_name = "FILE")]
    pub(crate) tls_ca: Option<PathBuf>,

    /// PEM client certificate chain for mTLS (requires --tls-key)
    #[arg(
        long,
        env = "RUSTBGPD_TLS_CERT",
        global = true,
        value_name = "FILE",
        requires = "tls_key"
    )]
    pub(crate) tls_cert: Option<PathBuf>,

    /// PEM client private key for mTLS (requires --tls-cert)
    #[arg(
        long,
        env = "RUSTBGPD_TLS_KEY",
        global = true,
        value_name = "FILE",
        requires = "tls_cert"
    )]
    pub(crate) tls_key: Option<PathBuf>,

    /// Server certificate name to verify instead of the HTTPS address host
    #[arg(
        long,
        env = "RUSTBGPD_TLS_SERVER_NAME",
        global = true,
        value_name = "NAME"
    )]
    pub(crate) tls_server_name: Option<String>,
}

impl TlsOptions {
    fn validate(&self, addr: &str) -> Result<(), CliError> {
        if self.tls_cert.is_some() != self.tls_key.is_some() {
            return Err(CliError::Argument(
                "--tls-cert and --tls-key must be supplied together".into(),
            ));
        }
        let configured = self.tls_ca.is_some()
            || self.tls_cert.is_some()
            || self.tls_key.is_some()
            || self.tls_server_name.is_some();
        if !addr.starts_with("https://") {
            if configured {
                return Err(CliError::Argument("TLS options require an https:// endpoint; plaintext TCP and Unix sockets do not use TLS".into()));
            }
        } else if self.tls_ca.is_none() {
            return Err(CliError::Argument("HTTPS requires --tls-ca FILE or RUSTBGPD_TLS_CA; system trust roots are not loaded".into()));
        } else if self.tls_cert.is_none() {
            return Err(CliError::Argument(
                "HTTPS client identity is not configured; the native mTLS listener requires --tls-cert FILE and --tls-key FILE"
                    .into(),
            ));
        }
        Ok(())
    }

    fn config(&self) -> Result<ClientTlsConfig, CliError> {
        let mut config = ClientTlsConfig::new().timeout(CONNECT_TIMEOUT);
        if let Some(ca) = &self.tls_ca {
            config = config.ca_certificate(Certificate::from_pem(read_tls_file(ca, "CA bundle")?));
        }
        if let (Some(cert), Some(key)) = (&self.tls_cert, &self.tls_key) {
            config = config.identity(Identity::from_pem(
                read_tls_file(cert, "client certificate")?,
                read_tls_file(key, "client private key")?,
            ));
        }
        if let Some(name) = &self.tls_server_name {
            config = config.domain_name(name);
        }
        Ok(config)
    }
}

fn read_tls_file(path: &Path, kind: &str) -> Result<Vec<u8>, CliError> {
    let bytes = fs::read(path).map_err(|error| {
        CliError::Argument(format!(
            "failed to read TLS {kind} {}: {error}",
            path.display()
        ))
    })?;
    if bytes.is_empty() {
        return Err(CliError::Argument(format!(
            "TLS {kind} file is empty: {}",
            path.display()
        )));
    }
    Ok(bytes)
}

/// Identity observed on the actual UDS transport, including Linux PID reuse evidence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct LocalProcess {
    pub(crate) pid: u32,
    start_ticks: u64,
}

pub(crate) fn proc_start_ticks(stat: &str) -> Option<u64> {
    stat.rsplit_once(')')?
        .1
        .split_whitespace()
        .nth(19)?
        .parse()
        .ok()
}

impl LocalProcess {
    fn capture(pid: u32) -> Option<Self> {
        if pid == 0 {
            return None;
        }
        let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
        Some(Self {
            pid,
            start_ticks: proc_start_ticks(&stat)?,
        })
    }

    /// Read only while the same process still occupies the observed PID.
    pub(crate) fn read_file(self, name: &str) -> Option<String> {
        String::from_utf8(self.read_bytes(name)?).ok()
    }

    pub(crate) fn read_bytes(self, name: &str) -> Option<Vec<u8>> {
        if Self::capture(self.pid)? != self {
            return None;
        }
        let bytes = fs::read(format!("/proc/{}/{name}", self.pid)).ok()?;
        (Self::capture(self.pid)? == self).then_some(bytes)
    }
}

impl Connection {
    pub(crate) fn local_process(&self) -> Option<LocalProcess> {
        let process = (*self.local_process.lock().ok()?)?;
        (LocalProcess::capture(process.pid)? == process).then_some(process)
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

#[cfg(test)]
pub(crate) async fn connect(addr: &str, token_file: Option<&str>) -> Result<Connection, CliError> {
    connect_with_tls(addr, token_file, &TlsOptions::default()).await
}

pub(crate) async fn connect_with_tls(
    addr: &str,
    token_file: Option<&str>,
    tls: &TlsOptions,
) -> Result<Connection, CliError> {
    tls.validate(addr)?;
    let token = load_bearer_token(token_file)?;
    let local_process = Arc::default();
    let channel = match parse_endpoint_target(addr)? {
        EndpointTarget::Tcp(uri) => connect_tcp(&uri, addr, tls).await?,
        EndpointTarget::Uds(path) => connect_uds(&path, addr, Arc::clone(&local_process)).await?,
    };
    Ok(Connection {
        channel,
        token,
        local_process,
        tls_client_identity: tls.tls_cert.is_some(),
    })
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
    if let Some((detail, hint)) = tls_failure_class(error) {
        return CliError::Tls {
            detail: format!("{addr}: {detail}"),
            hint,
        };
    }
    CliError::Connect {
        addr: addr.to_string(),
        detail: connect_failure_class(error),
    }
}

/// Follow typed transport causes; do not infer TLS failures from peer text.
pub(crate) fn tls_failure_class(
    error: &(dyn std::error::Error + 'static),
) -> Option<(&'static str, &'static str)> {
    use tokio_rustls::rustls::{AlertDescription, CertificateError, Error};
    let mut current = Some(error);
    while let Some(error) = current {
        if let Some(error) = error.downcast_ref::<Error>() {
            return Some(match error {
                Error::InvalidCertificate(CertificateError::UnknownIssuer) => (
                    "server certificate is not trusted",
                    "set --tls-ca to the CA bundle that signed the server certificate",
                ),
                Error::InvalidCertificate(
                    CertificateError::NotValidForName
                    | CertificateError::NotValidForNameContext { .. },
                ) => (
                    "server certificate name does not match",
                    "use the certificate's DNS name in the endpoint or set --tls-server-name to its verified name",
                ),
                Error::AlertReceived(AlertDescription::CertificateRequired) => (
                    "server requires a client certificate",
                    "supply --tls-cert and --tls-key for a client trusted by the daemon's tls_client_ca_file",
                ),
                Error::AlertReceived(
                    AlertDescription::UnknownCA
                    | AlertDescription::BadCertificate
                    | AlertDescription::CertificateExpired
                    | AlertDescription::CertificateRevoked
                    | AlertDescription::CertificateUnknown
                    | AlertDescription::UnsupportedCertificate,
                ) => (
                    "server rejected the client certificate",
                    "check the client certificate chain, validity and the daemon's tls_client_ca_file",
                ),
                Error::InconsistentKeys(_) => (
                    "client certificate and private key do not match",
                    "supply a matching --tls-cert and --tls-key pair",
                ),
                Error::InvalidCertificate(_) => (
                    "server certificate validation failed",
                    "check the server certificate's validity, usage, chain and the --tls-ca bundle",
                ),
                _ => (
                    "TLS handshake or protocol failure",
                    "check TLS configuration and the daemon's TLS logs",
                ),
            });
        }
        // io::Error::source can skip its immediate boxed cause; inspect it too.
        current = error
            .downcast_ref::<std::io::Error>()
            .and_then(std::io::Error::get_ref)
            .map(|error| error as &(dyn std::error::Error + 'static))
            .or_else(|| error.source());
    }
    None
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

async fn connect_tcp(uri: &str, display_addr: &str, tls: &TlsOptions) -> Result<Channel, CliError> {
    let mut endpoint = Endpoint::from_shared(uri.to_string())
        .map_err(|e| CliError::Argument(format!("invalid address: {e}")))?
        .connect_timeout(CONNECT_TIMEOUT);
    if uri.starts_with("https://") {
        endpoint = endpoint.tls_config(tls.config()?).map_err(|error| CliError::Tls {
            detail: format!("invalid TLS configuration: {}", connect_failure_class(&error)),
            hint: "check the CA bundle, client certificate/key pair and server name; files must contain valid PEM material",
        })?;
    }
    endpoint
        .connect()
        .await
        .map_err(|e| connect_error(display_addr, &e))
}

async fn connect_uds(
    path: &Path,
    display_addr: &str,
    local_process: Arc<Mutex<Option<LocalProcess>>>,
) -> Result<Channel, CliError> {
    let endpoint = Endpoint::try_from("http://[::]:50051")
        .map_err(|e| CliError::Argument(format!("invalid UDS endpoint: {e}")))?
        .connect_timeout(CONNECT_TIMEOUT);
    let path = path.to_path_buf();
    let connect = endpoint.connect_with_connector(service_fn(move |_: Uri| {
        let path = path.clone();
        let local_process = Arc::clone(&local_process);
        async move {
            // Reconnect attempts invalidate the previous transport's identity,
            // including attempts that fail before a replacement is available.
            if let Ok(mut identity) = local_process.lock() {
                *identity = None;
            }
            let stream = UnixStream::connect(path).await?;
            let process = stream
                .peer_cred()
                .ok()
                .and_then(|cred| cred.pid())
                .and_then(|pid| u32::try_from(pid).ok())
                .and_then(LocalProcess::capture);
            if let Ok(mut identity) = local_process.lock() {
                *identity = process;
            }
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

    #[tokio::test]
    async fn tls_argument_validation_precedes_file_reads_and_dialing() {
        for (addr, tls, expected) in [
            (
                "https://127.0.0.1:1",
                TlsOptions {
                    tls_cert: Some("missing-cert".into()),
                    ..TlsOptions::default()
                },
                "must be supplied together",
            ),
            (
                "https://127.0.0.1:1",
                TlsOptions::default(),
                "HTTPS requires --tls-ca",
            ),
            (
                "https://127.0.0.1:1",
                TlsOptions {
                    tls_ca: Some("missing-ca".into()),
                    ..TlsOptions::default()
                },
                "HTTPS client identity is not configured",
            ),
            (
                "http://127.0.0.1:1",
                TlsOptions {
                    tls_ca: Some("missing-ca".into()),
                    ..TlsOptions::default()
                },
                "require an https:// endpoint",
            ),
            (
                "unix:///missing.sock",
                TlsOptions {
                    tls_server_name: Some("router.example".into()),
                    ..TlsOptions::default()
                },
                "require an https:// endpoint",
            ),
        ] {
            let error = connect_with_tls(addr, Some("missing-token"), &tls)
                .await
                .err()
                .unwrap();
            assert!(error.to_string().contains(expected), "{error}");
            assert!(!error.to_string().contains("missing-token"));
        }
    }

    #[test]
    fn tls_errors_keep_typed_causes_through_io_and_status_wrappers() {
        use tokio_rustls::rustls::{AlertDescription, CertificateError, Error};
        for (cause, expected) in [
            (
                Error::InvalidCertificate(CertificateError::UnknownIssuer),
                "not trusted",
            ),
            (
                Error::InvalidCertificate(CertificateError::NotValidForName),
                "name does not match",
            ),
            (
                Error::AlertReceived(AlertDescription::CertificateRequired),
                "requires a client certificate",
            ),
            (
                Error::AlertReceived(AlertDescription::UnknownCA),
                "rejected the client certificate",
            ),
        ] {
            let error = std::io::Error::new(std::io::ErrorKind::InvalidData, cause);
            assert!(tls_failure_class(&error).unwrap().0.contains(expected));
            let mut status = Status::unavailable("transport error");
            status.set_source(Arc::new(error));
            let display = CliError::from(status).to_string();
            assert!(display.contains(expected), "{display}");
            assert!(!display.contains("is the daemon running"));
        }
        for error in [
            std::io::Error::from(std::io::ErrorKind::ConnectionReset),
            std::io::Error::other("CertificateRequired"),
        ] {
            assert!(tls_failure_class(&error).is_none());
        }
        assert!(matches!(
            CliError::from(Status::permission_denied("principal unmapped")),
            CliError::Rpc(_)
        ));
        assert!(matches!(
            CliError::from(Status::unauthenticated("token rejected")),
            CliError::Rpc(_)
        ));
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn uds_identity_comes_from_the_connected_stream_and_rejects_pid_reuse() {
        let dir = tempfile::tempdir().unwrap();
        let server =
            crate::test_support::spawn_mock_uds_server(&dir.path().join("grpc.sock"), None).await;
        let connection = connect(&server.addr, None).await.unwrap();
        let process = connection.local_process().unwrap();
        assert_eq!(process.pid, std::process::id());
        assert_eq!(
            process.read_file("limits").unwrap(),
            fs::read_to_string("/proc/self/limits").unwrap()
        );
        let reused_pid = LocalProcess {
            start_ticks: process.start_ticks + 1,
            ..process
        };
        assert!(reused_pid.read_file("limits").is_none());
        *connection.local_process.lock().unwrap() = Some(reused_pid);
        assert!(connection.local_process().is_none());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn proc_bytes_preserve_non_utf8_cmdline_and_check_process_identity() {
        use std::io::Read;
        use std::os::unix::{ffi::OsStringExt, process::CommandExt};

        struct Child(std::process::Child);
        impl Drop for Child {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }

        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("config.toml");
        let contents = b"[global]\nasn = 65001\n";
        fs::write(&config, contents).unwrap();
        // cat reads the config and then waits on its owned stdin pipe. Its
        // argv0 need not be UTF-8, unlike the Rust test harness's arguments.
        let mut child = Child(
            std::process::Command::new("cat")
                .arg0(std::ffi::OsString::from_vec(b"rustbgpd\xff".to_vec()))
                .arg(&config)
                .arg("-")
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .spawn()
                .unwrap(),
        );
        // Wait for cat to execute before inspecting its process arguments.
        let mut output = vec![0; contents.len()];
        child
            .0
            .stdout
            .as_mut()
            .unwrap()
            .read_exact(&mut output)
            .unwrap();
        assert_eq!(output, contents);
        let process = LocalProcess::capture(child.0.id()).unwrap();
        let cmdline = process.read_bytes("cmdline").unwrap();
        let mut args = cmdline.split(|byte| *byte == 0);
        assert_eq!(args.next().unwrap(), b"rustbgpd\xff");
        assert_eq!(args.next().unwrap(), config.as_os_str().as_encoded_bytes());
        assert!(process.read_file("cmdline").is_none());
        let reused_pid = LocalProcess {
            start_ticks: process.start_ticks + 1,
            ..process
        };
        assert!(reused_pid.read_bytes("cmdline").is_none());
    }

    #[tokio::test]
    async fn tcp_identity_is_unavailable_even_with_a_local_server() {
        let server = crate::test_support::spawn_mock_server(None).await;
        assert!(
            connect(&server.addr, None)
                .await
                .unwrap()
                .local_process()
                .is_none()
        );
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn failed_uds_reconnect_clears_previous_process_identity() {
        let dir = tempfile::tempdir().unwrap();
        let identity = Arc::new(Mutex::new(LocalProcess::capture(std::process::id())));
        assert!(
            connect_uds(
                &dir.path().join("missing.sock"),
                "missing",
                Arc::clone(&identity)
            )
            .await
            .is_err()
        );
        assert!(identity.lock().unwrap().is_none());
    }

    #[tokio::test]
    async fn read_deadline_cancels_pending_response_and_names_method_and_budget() {
        struct Cancelled<'a>(&'a std::sync::atomic::AtomicBool);
        impl Drop for Cancelled<'_> {
            fn drop(&mut self) {
                self.0.store(true, std::sync::atomic::Ordering::SeqCst);
            }
        }
        let cancelled = std::sync::atomic::AtomicBool::new(false);
        let error = rpc_with_timeout("GetGlobal", Duration::from_millis(20), async {
            let _guard = Cancelled(&cancelled);
            std::future::pending::<Result<(), Status>>().await
        })
        .await
        .unwrap_err();
        assert_eq!(error.code(), tonic::Code::DeadlineExceeded);
        assert_eq!(error.message(), "GetGlobal response timed out after 0.02s");
        assert!(cancelled.load(std::sync::atomic::Ordering::SeqCst));
    }

    #[tokio::test]
    async fn read_deadline_preserves_success_and_server_errors() {
        assert_eq!(read_rpc("GetGlobal", async { Ok(42) }).await.unwrap(), 42);
        let expected = Status::permission_denied("principal observer cannot perform this read");
        let error = read_rpc("GetGlobal", async { Err::<(), _>(expected.clone()) })
            .await
            .unwrap_err();
        assert_eq!(error.code(), expected.code());
        assert_eq!(error.message(), expected.message());
    }

    #[test]
    fn effective_config_keeps_its_supported_server_budget() {
        assert_eq!(READ_RPC_TIMEOUT, Duration::from_secs(30));
        assert!(EFFECTIVE_CONFIG_RPC_TIMEOUT > Duration::from_secs(30 * 60));
    }

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
            ".list_received_evpn_routes(",
            ".list_advertised_evpn_routes(",
            ".explain_evpn_route(",
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
            ("commands/evpn.rs", include_str!("commands/evpn.rs"), 4, 6),
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
        assert_eq!(total_ctors, 14, "inventoried constructor sites");
        assert_eq!(total_rpcs, 16, "inventoried listing RPC invocations");
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
            prefix_sid: None,
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
        // Bind without listen(), then close: the socket file remains and
        // connect gets ECONNREFUSED. A dropped listener is not enough: a
        // sibling test's fork holds a copy of every descriptor until its child
        // execs, so the listener can outlive `drop` and accept the connect.
        // A socket that never listened refuses regardless of who holds it.
        let socket = nix::sys::socket::socket(
            nix::sys::socket::AddressFamily::Unix,
            nix::sys::socket::SockType::Stream,
            nix::sys::socket::SockFlag::SOCK_CLOEXEC,
            None,
        )
        .unwrap();
        nix::sys::socket::bind(
            std::os::fd::AsRawFd::as_raw_fd(&socket),
            &nix::sys::socket::UnixAddr::new(&stale).unwrap(),
        )
        .unwrap();
        drop(socket);
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

    // A deadline the daemon reports (for example `peer manager mutation timed
    // out`) leaves the outcome as unknown as the CLI's own timer does; other
    // statuses pass through untouched.
    #[tokio::test]
    async fn daemon_reported_deadline_is_an_unknown_outcome() {
        let daemon =
            || async { Err::<(), _>(Status::deadline_exceeded("peer manager mutation timed out")) };
        let status = mutation_rpc(
            "ResetNeighbor",
            MUTATION_RPC_TIMEOUT,
            "`rbgp neighbor`",
            daemon(),
        )
        .await
        .unwrap_err();
        assert_eq!(status.code(), tonic::Code::DeadlineExceeded);
        assert_eq!(
            status.message(),
            "peer manager mutation timed out; outcome unknown: the daemon may still apply \
             this change; verify with `rbgp neighbor`"
        );
        let status =
            config_transaction_rpc("ConfirmConfigTransaction", "`rbgp config status`", async {
                Err::<(), _>(Status::deadline_exceeded(
                    "config operation exceeded deadline",
                ))
            })
            .await
            .unwrap_err();
        assert_eq!(
            status.message(),
            "config operation exceeded deadline; outcome unknown: the transaction may still \
             commit or roll back; verify with `rbgp config status`"
        );

        let status = mutation_rpc(
            "ResetNeighbor",
            MUTATION_RPC_TIMEOUT,
            "`rbgp neighbor`",
            async { Err::<(), _>(Status::not_found("peer 192.0.2.1 not found")) },
        )
        .await
        .unwrap_err();
        assert_eq!(status.code(), tonic::Code::NotFound);
        assert_eq!(status.message(), "peer 192.0.2.1 not found");
    }
}
