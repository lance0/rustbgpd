//! GoBGP v3 `AddPath` bridge for rustbgpd.
//!
//! RTBH detectors that drive GoBGP announce and withdraw blackholes through
//! one call, `apipb.GobgpApi/AddPath`, with binary NLRI and path attributes.
//! This process serves that one method and applies each request through
//! rustbgpd's `InjectionService` as an ordinary authenticated gRPC client.
//! Every other GoBGP method returns `UNIMPLEMENTED`.
//!
//! The bridge keeps no state. A request succeeds only after rustbgpd has
//! acknowledged the mutation, and daemon errors are returned as they arrive.

#![deny(unsafe_code)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]

pub mod decode;

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use hyper_util::rt::TokioIo;
use tonic::metadata::AsciiMetadataValue;
use tonic::service::Interceptor;
use tonic::service::interceptor::InterceptedService;
use tonic::transport::{Channel, Endpoint, Uri};
use tonic::{Request, Response, Status};
use tracing::{info, warn};

use decode::Mutation;

/// GoBGP v3 API (`apipb`), generated from the vendored `proto/gobgp.proto`.
#[allow(
    clippy::all,
    clippy::pedantic,
    reason = "generated protobuf and tonic code"
)]
pub mod gobgp {
    tonic::include_proto!("apipb");
}

/// rustbgpd API client bindings (`rustbgpd.v1`).
#[allow(
    clippy::all,
    clippy::pedantic,
    reason = "generated protobuf and tonic code"
)]
pub mod rustbgpd {
    tonic::include_proto!("rustbgpd.v1");
}

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Where the daemon's gRPC API listens.
#[derive(Debug, Clone)]
pub enum DaemonEndpoint {
    /// `unix:///absolute/path`
    Uds(PathBuf),
    /// `http://host:port`; the daemon requires a bearer token on TCP.
    Tcp(String),
}

impl std::str::FromStr for DaemonEndpoint {
    type Err = String;

    fn from_str(addr: &str) -> Result<Self, String> {
        if let Some(path) = addr.strip_prefix("unix://") {
            let path = PathBuf::from(path);
            if !path.is_absolute() {
                return Err("use unix:///absolute/path".into());
            }
            return Ok(Self::Uds(path));
        }
        if addr.starts_with("http://") {
            return Ok(Self::Tcp(addr.to_string()));
        }
        Err("expected unix:///absolute/path or http://host:port".into())
    }
}

/// Adds the bearer token, when one is configured, to every daemon call.
#[derive(Clone)]
pub struct Bearer(Option<AsciiMetadataValue>);

impl Interceptor for Bearer {
    fn call(&mut self, mut request: Request<()>) -> Result<Request<()>, Status> {
        if let Some(value) = &self.0 {
            request
                .metadata_mut()
                .insert("authorization", value.clone());
        }
        Ok(request)
    }
}

/// Read a bearer token file into an `authorization` metadata value.
///
/// # Errors
///
/// The file cannot be read, is empty, or is not valid ASCII metadata.
pub fn load_token(path: &Path) -> Result<Bearer, String> {
    let raw = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read token file {}: {e}", path.display()))?;
    let token = raw.trim_end();
    if token.is_empty() {
        return Err(format!("token file is empty: {}", path.display()));
    }
    let mut value = AsciiMetadataValue::try_from(format!("Bearer {token}"))
        .map_err(|_| format!("token in {} is not valid ASCII", path.display()))?;
    value.set_sensitive(true);
    Ok(Bearer(Some(value)))
}

type Injection =
    rustbgpd::injection_service_client::InjectionServiceClient<InterceptedService<Channel, Bearer>>;

/// A lazily connected channel: the bridge starts while the daemon is down
/// and reconnects on the next request after the daemon returns.
///
/// # Errors
///
/// The endpoint URI is invalid.
pub fn daemon_channel(endpoint: &DaemonEndpoint) -> Result<Channel, String> {
    match endpoint {
        DaemonEndpoint::Tcp(uri) => Ok(Endpoint::from_shared(uri.clone())
            .map_err(|e| format!("invalid daemon endpoint: {e}"))?
            .connect_timeout(CONNECT_TIMEOUT)
            .connect_lazy()),
        DaemonEndpoint::Uds(path) => {
            let path = path.clone();
            Ok(Endpoint::from_static("http://[::]:50051")
                .connect_timeout(CONNECT_TIMEOUT)
                .connect_with_connector_lazy(tower::service_fn(move |_: Uri| {
                    let path = path.clone();
                    async move {
                        Ok::<_, std::io::Error>(TokioIo::new(
                            tokio::net::UnixStream::connect(path).await?,
                        ))
                    }
                })))
        }
    }
}

/// The GoBGP API service backed by rustbgpd injection.
pub struct Bridge {
    injection: Injection,
}

impl Bridge {
    /// Build the service over a daemon channel and optional bearer token.
    #[must_use]
    pub fn new(channel: Channel, bearer: Option<Bearer>) -> Self {
        Self {
            injection: rustbgpd::injection_service_client::InjectionServiceClient::with_interceptor(
                channel,
                bearer.unwrap_or(Bearer(None)),
            ),
        }
    }
}

#[tonic::async_trait]
impl gobgp::gobgp_api_server::GobgpApi for Bridge {
    async fn add_path(
        &self,
        request: Request<gobgp::AddPathRequest>,
    ) -> Result<Response<gobgp::AddPathResponse>, Status> {
        let decoded = decode::decode(request.get_ref()).inspect_err(|status| {
            warn!(code = ?status.code(), error = status.message(), "rejected AddPath");
        })?;
        let mut injection = self.injection.clone();
        // The daemon's outcome goes to the log; GoBGP's response has no field
        // for it.
        let result = match &decoded.mutation {
            Mutation::Announce(req) => injection
                .add_path(req.clone())
                .await
                .map(|r| format!("{:?}", r.into_inner().outcome())),
            Mutation::Withdraw(req) => injection
                .delete_path(req.clone())
                .await
                .map(|r| format!("{:?}", r.into_inner().outcome())),
        };
        let (action, prefix, len) = match &decoded.mutation {
            Mutation::Announce(r) => ("announce", &r.prefix, r.prefix_length),
            Mutation::Withdraw(r) => ("withdraw", &r.prefix, r.prefix_length),
        };
        match &result {
            Ok(outcome) => info!(action, prefix = %format!("{prefix}/{len}"), outcome, "applied"),
            Err(status) => warn!(
                action,
                prefix = %format!("{prefix}/{len}"),
                code = ?status.code(),
                error = status.message(),
                "rustbgpd refused or unreachable"
            ),
        }
        // Keep the daemon's code and message; drop its response metadata,
        // which belongs to the daemon's HTTP/2 response, not this one.
        result.map_err(|status| Status::new(status.code(), status.message()))?;
        Ok(Response::new(gobgp::AddPathResponse {
            uuid: decoded.uuid.to_vec(),
        }))
    }
}

/// Check the listen address against the loopback rule.
///
/// # Errors
///
/// `listen` is not a loopback address and `allow_non_loopback` is false.
pub fn check_listen(listen: SocketAddr, allow_non_loopback: bool) -> Result<(), String> {
    if listen.ip().is_loopback() || allow_non_loopback {
        Ok(())
    } else {
        Err(format!(
            "refusing to serve the unauthenticated GoBGP API on non-loopback {listen}; \
             pass --allow-non-loopback to accept that any host that can reach it can announce blackholes"
        ))
    }
}

/// Serve the bridge on `listener` until `shutdown` resolves.
///
/// # Errors
///
/// The gRPC server fails.
pub async fn serve(
    listener: tokio::net::TcpListener,
    bridge: Bridge,
    shutdown: impl std::future::Future<Output = ()>,
) -> Result<(), tonic::transport::Error> {
    tonic::transport::Server::builder()
        .add_service(gobgp::gobgp_api_server::GobgpApiServer::new(bridge))
        .serve_with_incoming_shutdown(
            tonic::transport::server::TcpIncoming::from(listener),
            shutdown,
        )
        .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn listen_address_must_be_loopback_unless_allowed() {
        for addr in ["127.0.0.1:50051", "[::1]:50051"] {
            assert!(check_listen(addr.parse().unwrap(), false).is_ok(), "{addr}");
        }
        for addr in ["0.0.0.0:50051", "192.0.2.1:50051", "[::]:50051"] {
            assert!(
                check_listen(addr.parse().unwrap(), false).is_err(),
                "{addr}"
            );
            assert!(check_listen(addr.parse().unwrap(), true).is_ok(), "{addr}");
        }
    }

    #[test]
    fn daemon_endpoint_forms() {
        assert!(matches!(
            "unix:///run/rustbgpd/grpc.sock".parse(),
            Ok(DaemonEndpoint::Uds(_))
        ));
        assert!(matches!(
            "http://127.0.0.1:50051".parse(),
            Ok(DaemonEndpoint::Tcp(_))
        ));
        for bad in [
            "unix://relative.sock",
            "https://127.0.0.1:50051",
            "127.0.0.1:50051",
        ] {
            assert!(bad.parse::<DaemonEndpoint>().is_err(), "{bad}");
        }
    }
}
