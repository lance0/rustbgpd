//! GoBGP v3 `AddPath` bridge for rustbgpd.
//!
//! RTBH detectors that drive GoBGP announce and withdraw blackholes through
//! one call, `apipb.GobgpApi/AddPath`, with binary NLRI and path attributes.
//! This process serves that one method and applies each request through
//! rustbgpd's `InjectionService` as an ordinary authenticated gRPC client.
//! Every other GoBGP method returns `UNIMPLEMENTED`.
//!
//! The bridge keeps the announced bans in memory and re-adds them on each
//! reconcile pass, so a restarted daemon gets them back. A liveness probe
//! starts a pass as soon as the daemon answers again after a restart. A request succeeds
//! only after rustbgpd has acknowledged the mutation, and daemon errors are
//! returned as they arrive.

#![deny(unsafe_code)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]

pub mod decode;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use hyper_util::rt::TokioIo;
use tokio::sync::Mutex;
use tonic::metadata::AsciiMetadataValue;
use tonic::service::Interceptor;
use tonic::service::interceptor::InterceptedService;
use tonic::transport::{Channel, Endpoint, Uri};
use tonic::{Request, Response, Status};
use tracing::{info, warn};

use crate::rustbgpd as rbgp;
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

/// Deadline for each daemon RPC. Requests and reconcile passes share one
/// lock, so a daemon that accepts the connection but never answers would
/// otherwise block every later ban, unban and pass.
pub const DAEMON_RPC_TIMEOUT: Duration = Duration::from_secs(10);

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
    rbgp::injection_service_client::InjectionServiceClient<InterceptedService<Channel, Bearer>>;
type Control =
    rbgp::control_service_client::ControlServiceClient<InterceptedService<Channel, Bearer>>;

/// Default interval between daemon liveness probes.
pub const DEFAULT_LIVENESS_POLL: Duration = Duration::from_millis(500);

/// What the previous liveness probe saw.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Probe {
    /// No probe yet.
    Unknown,
    /// The daemon did not answer, or a pass after it answered did not finish.
    Down,
    /// The daemon answered.
    Up,
}

/// Whether a probe that did (`answered`) or did not answer, after `last`,
/// means the daemon came back: it answers after a failed probe. That is how a
/// restart shows, and a daemon that was unreachable for any other reason may
/// also have lost its routes. The first probe after the bridge starts is not
/// a restart.
fn came_back(last: Probe, answered: bool) -> bool {
    last == Probe::Down && answered
}

/// A lazily connected channel: the bridge starts while the daemon is down
/// and reconnects on the next request after the daemon returns. Every RPC on
/// it fails after `rpc_timeout` (normally [`DAEMON_RPC_TIMEOUT`]).
///
/// # Errors
///
/// The endpoint URI is invalid.
pub fn daemon_channel(endpoint: &DaemonEndpoint, rpc_timeout: Duration) -> Result<Channel, String> {
    match endpoint {
        DaemonEndpoint::Tcp(uri) => Ok(Endpoint::from_shared(uri.clone())
            .map_err(|e| format!("invalid daemon endpoint: {e}"))?
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(rpc_timeout)
            .connect_lazy()),
        DaemonEndpoint::Uds(path) => {
            let path = path.clone();
            Ok(Endpoint::from_static("http://[::]:50051")
                .connect_timeout(CONNECT_TIMEOUT)
                .timeout(rpc_timeout)
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

/// Default cap on tracked paths: announced bans plus pending withdrawals.
pub const DEFAULT_MAX_TRACKED: usize = 65_536;

/// Paths the detector wants, kept so a restarted daemon gets them back.
#[derive(Default)]
struct Desired {
    /// The last acknowledged announcement per path, replayed by `reconcile`.
    routes: HashMap<[u8; 16], rbgp::AddPathRequest>,
    /// Withdrawals the daemon has not acknowledged, retried by `reconcile`.
    pending_deletes: HashMap<[u8; 16], rbgp::DeletePathRequest>,
}

/// The GoBGP API service backed by rustbgpd injection.
///
/// It keeps the announced paths in memory and re-adds them on every
/// `reconcile`, so bans survive a daemon restart. A bridge restart loses them.
#[derive(Clone)]
pub struct Bridge {
    injection: Injection,
    control: Control,
    // ponytail: one lock serializes detector requests and reconcile passes,
    // which makes ordering trivial (a replay can never race a withdraw). A
    // pass over a very large set delays detector requests until it finishes.
    desired: Arc<Mutex<Desired>>,
    max_tracked: usize,
}

impl Bridge {
    /// Build the service over a daemon channel and optional bearer token,
    /// tracking at most `max_tracked` paths.
    #[must_use]
    pub fn new(channel: Channel, bearer: Option<Bearer>, max_tracked: usize) -> Self {
        let bearer = bearer.unwrap_or(Bearer(None));
        Self {
            injection: rbgp::injection_service_client::InjectionServiceClient::with_interceptor(
                channel.clone(),
                bearer.clone(),
            ),
            control: rbgp::control_service_client::ControlServiceClient::with_interceptor(
                channel, bearer,
            ),
            desired: Arc::default(),
            max_tracked,
        }
    }

    async fn apply(&self, decoded: &decode::Decoded) -> Result<(), Status> {
        let mut desired = self.desired.lock().await;
        let mut injection = self.injection.clone();
        let key = decoded.uuid;
        match &decoded.mutation {
            Mutation::Announce(req) => {
                // Reserve the slot before the daemon sees the route, so an
                // acknowledged ban is never left untracked.
                if !desired.routes.contains_key(&key)
                    && !desired.pending_deletes.contains_key(&key)
                    && desired.routes.len() + desired.pending_deletes.len() >= self.max_tracked
                {
                    return Err(Status::resource_exhausted(format!(
                        "the bridge already tracks {} paths; withdraw some first",
                        self.max_tracked
                    )));
                }
                let outcome = injection
                    .add_path(req.clone())
                    .await?
                    .into_inner()
                    .outcome();
                desired.pending_deletes.remove(&key);
                desired.routes.insert(key, req.clone());
                info!(action = "announce", prefix = %prefix_of(&req.prefix, req.prefix_length), outcome = ?outcome, "applied");
            }
            Mutation::Withdraw(req) => {
                // Stop replaying it first: whatever the daemon answers, the
                // detector no longer wants this path.
                desired.routes.remove(&key);
                // Record the retry before the daemon call: if this request is
                // cancelled while the call is pending, the next reconcile
                // pass still applies the withdrawal. A full tracker makes it
                // best effort.
                let retried = desired.pending_deletes.contains_key(&key)
                    || desired.routes.len() + desired.pending_deletes.len() < self.max_tracked;
                if retried {
                    desired.pending_deletes.insert(key, req.clone());
                }
                match injection.delete_path(req.clone()).await {
                    Ok(response) => {
                        // Deleted, or NOT_PRESENT under allow_missing.
                        desired.pending_deletes.remove(&key);
                        info!(action = "withdraw", prefix = %prefix_of(&req.prefix, req.prefix_length), outcome = ?response.into_inner().outcome(), "applied");
                    }
                    Err(status) => {
                        return Err(Status::new(
                            status.code(),
                            if retried {
                                format!("{}; the bridge retries this withdrawal", status.message())
                            } else {
                                status.message().to_string()
                            },
                        ));
                    }
                }
            }
        }
        Ok(())
    }

    /// Retry pending withdrawals, then re-add every tracked announcement. An
    /// unchanged re-add is a no-op in the daemon; after a daemon restart it
    /// restores the ban. Stops at the first daemon error and tries again on
    /// the next pass. Returns whether the pass finished.
    pub async fn reconcile(&self) -> bool {
        let mut desired = self.desired.lock().await;
        let mut injection = self.injection.clone();
        let deletes: Vec<_> = desired
            .pending_deletes
            .iter()
            .map(|(k, r)| (*k, r.clone()))
            .collect();
        for (key, req) in deletes {
            if let Err(status) = injection.delete_path(req.clone()).await {
                warn!(code = ?status.code(), error = status.message(), "reconcile paused");
                return false;
            }
            desired.pending_deletes.remove(&key);
            info!(action = "withdraw", prefix = %prefix_of(&req.prefix, req.prefix_length), "retried withdrawal applied");
        }
        for req in desired.routes.values() {
            match injection.add_path(req.clone()).await {
                Ok(response) => {
                    let outcome = response.into_inner().outcome();
                    if outcome != rbgp::PathInjectOutcome::Unchanged {
                        info!(action = "announce", prefix = %prefix_of(&req.prefix, req.prefix_length), outcome = ?outcome, "replayed");
                    }
                }
                Err(status) => {
                    warn!(code = ?status.code(), error = status.message(), "reconcile paused");
                    return false;
                }
            }
        }
        true
    }

    /// Run `reconcile` every `interval` for the life of the process.
    pub fn spawn_reconcile(&self, interval: Duration) {
        let bridge = self.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(interval);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tick.tick().await;
                bridge.reconcile().await;
            }
        });
    }

    /// Probe the daemon with `CheckLiveness` every `poll` for the life of the
    /// process, and run `reconcile` at once when the daemon answers after a
    /// failed probe. `CheckLiveness` is the daemon's cheapest call and is
    /// audited at DEBUG. A restart quicker than one probe goes unseen here;
    /// the periodic pass is the backstop.
    pub fn spawn_restart_watch(&self, poll: Duration) {
        let bridge = self.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(poll);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            let mut last = Probe::Unknown;
            loop {
                tick.tick().await;
                let answered = bridge
                    .control
                    .clone()
                    .check_liveness(rbgp::CheckLivenessRequest {})
                    .await
                    .is_ok();
                last = if !answered {
                    Probe::Down
                } else if came_back(last, answered) {
                    info!("rustbgpd answered again; reconciling now");
                    // An unfinished pass is retried on the next answer.
                    if bridge.reconcile().await {
                        Probe::Up
                    } else {
                        Probe::Down
                    }
                } else {
                    Probe::Up
                };
            }
        });
    }
}

fn prefix_of(prefix: &str, len: u32) -> String {
    format!("{prefix}/{len}")
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
        // Keep the daemon's code and message; drop its response metadata,
        // which belongs to the daemon's HTTP/2 response, not this one.
        self.apply(&decoded).await.map_err(|status| {
            warn!(code = ?status.code(), error = status.message(), "rustbgpd refused or unreachable");
            Status::new(status.code(), status.message())
        })?;
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
    fn the_daemon_comes_back_when_it_answers_after_a_failed_probe() {
        assert!(came_back(Probe::Down, true));
        // Bridge start, still down, or running.
        assert!(!came_back(Probe::Unknown, true));
        assert!(!came_back(Probe::Unknown, false));
        assert!(!came_back(Probe::Down, false));
        assert!(!came_back(Probe::Up, true));
        assert!(!came_back(Probe::Up, false));
    }

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
