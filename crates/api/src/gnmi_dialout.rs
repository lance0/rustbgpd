//! gNMI dial-out (LAN-471): device-initiated telemetry push to central
//! collectors.
//!
//! Dial-in gNMI has the collector connect to the device and drive
//! `gnmi.gNMI/Subscribe`. Large fleets ingest the other way around: every
//! device dials OUT to a central collector and pushes the same update
//! stream. This module implements that inversion as a thin transport shim
//! over the existing Subscribe machinery — each configured target gets a
//! persistent outbound gRPC connection carrying the
//! `rustbgpd.gnmi_dialout.v1.GnmiDialout/Publish` stream, whose payload is
//! the exact `SubscribeResponse` sequence a dial-in STREAM subscription
//! would have produced (initial snapshot, `sync_response`, then updates).
//! No update-generation code is duplicated:
//! `GnmiService::spawn_stream_subscription` (crate-internal) drives the
//! same `SAMPLE` / `ON_CHANGE` tasks the Subscribe server uses.
//!
//! Robustness contract: a collector being down never affects the daemon.
//! Each target runs an independent reconnect loop with capped exponential
//! backoff, logs at `warn` only on state transitions (first failure after
//! a success, disconnect) and at `debug` for repeated retries, and surfaces
//! its state as the `gnmi_dialout_connected{target}` gauge.

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;

use rustbgpd_telemetry::BgpMetrics;
use tokio_stream::{StreamExt, wrappers::ReceiverStream};
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint, Identity};
use tracing::{debug, error, info, warn};
use zeroize::Zeroizing;

use crate::gnmi;
use crate::gnmi_dialout_proto::gnmi_dialout_client::GnmiDialoutClient;
pub use crate::gnmi_service::GnmiService;
use crate::gnmi_service::validate_stream_subscription_list;

/// How long a single connection attempt may sit in TCP/TLS/HTTP-2
/// establishment before it counts as failed and enters backoff.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// One configured dial-out collector target, fully resolved from config.
/// `PartialEq` drives the reload diff: an unchanged target keeps its live
/// connection across SIGHUP; any field edit tears down and redials.
#[derive(Debug, Clone, PartialEq)]
pub struct DialoutTarget {
    /// Unique name — the `gnmi_dialout_connected{target}` label and log key.
    pub name: String,
    /// Full endpoint URI (`http://host:port` or `https://host:port`).
    pub endpoint: String,
    /// Outbound TLS material paths; `None` dials plaintext.
    pub tls: Option<DialoutTls>,
    /// The STREAM-mode subscription this target receives, pre-validated by
    /// [`build_subscription_list`].
    pub subscriptions: gnmi::SubscriptionList,
    /// First retry delay after a failure; doubles per consecutive failure.
    pub backoff_initial: Duration,
    /// Retry delay cap.
    pub backoff_max: Duration,
}

/// TLS material *paths* for one dial-out target. Only paths live here —
/// key bytes are read per connection attempt into a [`Zeroizing`] buffer
/// and handed straight to the transport, so no key material is ever held
/// on a long-lived or `Debug`-printable struct.
#[derive(Clone, PartialEq)]
pub struct DialoutTls {
    /// CA bundle (PEM) used to verify the collector's server certificate.
    pub ca_file: PathBuf,
    /// Optional client certificate (PEM) for mutual TLS.
    pub cert_file: Option<PathBuf>,
    /// Optional client private key (PEM); paired with `cert_file`.
    pub key_file: Option<PathBuf>,
    /// Override the expected TLS server name when dialing by IP address.
    pub server_name: Option<String>,
}

// Manual Debug: prints the configured *paths* (operator-supplied config,
// not secrets) and never any file contents. The redaction pin test below
// guards against a future refactor moving loaded key bytes onto this
// struct and deriving Debug over them.
impl std::fmt::Debug for DialoutTls {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DialoutTls")
            .field("ca_file", &self.ca_file)
            .field("cert_file", &self.cert_file)
            .field("key_file", &self.key_file)
            .field("server_name", &self.server_name)
            .finish()
    }
}

/// Delivery mode for a dial-out subscription (maps onto the same STREAM
/// sub-modes the dial-in Subscribe server implements).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DialoutMode {
    /// Periodic resample of the subscribed paths.
    Sample,
    /// Event-driven updates (v1: the `session-state` leaf only), sourced
    /// from the durable event outbox like dial-in `ON_CHANGE`.
    OnChange,
}

/// Parse an xpath-style gNMI path string (`a/b[name=x][k=v]/c`) into a
/// structured [`gnmi::Path`]. This is the config-file spelling of the
/// same paths a dial-in collector would put in a `SubscribeRequest`.
///
/// # Errors
/// Returns a human-readable message for empty elements, unterminated or
/// malformed `[key=value]` blocks, and text after a key block that is not
/// another key block.
pub fn parse_path(input: &str) -> Result<gnmi::Path, String> {
    let trimmed = input.strip_prefix('/').unwrap_or(input);
    if trimmed.is_empty() {
        return Err("empty gNMI path".to_string());
    }
    let mut elems = Vec::new();
    // Split on '/' outside [key=value] blocks (values may contain '/').
    let mut depth = 0usize;
    let mut start = 0usize;
    let mut parts = Vec::new();
    for (i, ch) in trimmed.char_indices() {
        match ch {
            '[' => depth += 1,
            ']' => {
                depth = depth
                    .checked_sub(1)
                    .ok_or_else(|| format!("unbalanced ']' in gNMI path {input:?}"))?;
            }
            '/' if depth == 0 => {
                parts.push(&trimmed[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    if depth != 0 {
        return Err(format!("unterminated '[' in gNMI path {input:?}"));
    }
    parts.push(&trimmed[start..]);

    for part in parts {
        let (name, mut rest) = match part.find('[') {
            Some(pos) => (&part[..pos], &part[pos..]),
            None => (part, ""),
        };
        if name.is_empty() {
            return Err(format!("empty path element in gNMI path {input:?}"));
        }
        let mut key = HashMap::new();
        while !rest.is_empty() {
            let Some(stripped) = rest.strip_prefix('[') else {
                return Err(format!(
                    "unexpected text {rest:?} after keys in gNMI path element {part:?}"
                ));
            };
            let Some(end) = stripped.find(']') else {
                return Err(format!("unterminated '[' in gNMI path element {part:?}"));
            };
            let pair = &stripped[..end];
            let Some((k, v)) = pair.split_once('=') else {
                return Err(format!(
                    "key block {pair:?} in gNMI path element {part:?} is not key=value"
                ));
            };
            if k.is_empty() {
                return Err(format!("empty key name in gNMI path element {part:?}"));
            }
            key.insert(k.to_string(), v.to_string());
            rest = &stripped[end + 1..];
        }
        elems.push(gnmi::PathElem {
            name: name.to_string(),
            key,
        });
    }

    Ok(gnmi::Path {
        elem: elems,
        ..Default::default()
    })
}

/// Build (and fully validate) the STREAM `SubscriptionList` for one
/// dial-out target from its config-file fields. Runs the same validation
/// a dial-in `Subscribe` request would, so a bad path or an
/// ON_CHANGE-unsupported leaf is rejected at config load, not at runtime.
///
/// # Errors
/// Returns a human-readable message for unparseable paths and for lists
/// the Subscribe server would reject.
pub fn build_subscription_list(
    paths: &[String],
    mode: DialoutMode,
    sample_interval: Duration,
) -> Result<gnmi::SubscriptionList, String> {
    let mode = match mode {
        DialoutMode::Sample => gnmi::SubscriptionMode::Sample,
        DialoutMode::OnChange => gnmi::SubscriptionMode::OnChange,
    };
    let interval_nanos = u64::try_from(sample_interval.as_nanos()).unwrap_or(u64::MAX);
    let subscription = paths
        .iter()
        .map(|path| {
            Ok(gnmi::Subscription {
                path: Some(parse_path(path)?),
                mode: mode as i32,
                sample_interval: interval_nanos,
                suppress_redundant: false,
                heartbeat_interval: 0,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    let list = gnmi::SubscriptionList {
        prefix: None,
        subscription,
        qos: None,
        mode: gnmi::subscription_list::Mode::Stream as i32,
        allow_aggregation: false,
        use_models: Vec::new(),
        encoding: gnmi::Encoding::JsonIetf as i32,
        updates_only: false,
    };
    validate_stream_subscription_list(&list).map_err(|status| status.message().to_string())?;
    Ok(list)
}

/// Build the endpoint URI for a collector `host:port` address.
#[must_use]
pub fn endpoint_uri(address: &str, tls: bool) -> String {
    if tls {
        format!("https://{address}")
    } else {
        format!("http://{address}")
    }
}

/// Owns the per-target dial-out tasks. The daemon holds one manager and
/// calls [`DialoutManager::apply`] at startup and after every successful
/// SIGHUP reload; the manager diffs the desired target set against the
/// running one so unchanged targets keep their live connections.
pub struct DialoutManager {
    service: GnmiService,
    metrics: BgpMetrics,
    tasks: HashMap<String, (DialoutTarget, tokio::task::JoinHandle<()>)>,
}

impl DialoutManager {
    /// Create a manager with no running targets.
    #[must_use]
    pub fn new(service: GnmiService, metrics: BgpMetrics) -> Self {
        Self {
            service,
            metrics,
            tasks: HashMap::new(),
        }
    }

    /// Reconcile the running dial-out tasks with `targets`: stop removed
    /// targets (reaping their `gnmi_dialout_connected` series), restart
    /// changed ones, start added ones, and leave unchanged targets — and
    /// their live collector connections — untouched.
    pub fn apply(&mut self, targets: &[DialoutTarget]) {
        let metrics = &self.metrics;
        self.tasks.retain(|name, (spec, handle)| {
            let keep = targets
                .iter()
                .any(|target| &target.name == name && target == spec);
            if !keep {
                handle.abort();
                metrics.remove_gnmi_dialout_target(name);
                info!(target = %name, "gNMI dial-out target stopped");
            }
            keep
        });
        for target in targets {
            if !self.tasks.contains_key(&target.name) {
                let handle = tokio::spawn(run_target(
                    self.service.clone(),
                    self.metrics.clone(),
                    target.clone(),
                ));
                self.tasks
                    .insert(target.name.clone(), (target.clone(), handle));
            }
        }
    }
}

/// One target's connect / stream / reconnect loop. Never returns under
/// normal operation; the manager aborts it on removal or shutdown.
async fn run_target(service: GnmiService, metrics: BgpMetrics, target: DialoutTarget) {
    // Materialize the series at 0 immediately so a collector that is down
    // at daemon startup is visible on /metrics before the first success.
    metrics.set_gnmi_dialout_connected(&target.name, false);
    let mut backoff = target.backoff_initial.max(Duration::from_millis(1));
    let mut failure_announced = false;
    loop {
        match publish_session(&service, &metrics, &target).await {
            Ok(()) => {
                // Connected and then cleanly/abruptly disconnected.
                metrics.set_gnmi_dialout_connected(&target.name, false);
                warn!(
                    target = %target.name,
                    endpoint = %target.endpoint,
                    "gNMI dial-out collector disconnected; reconnecting"
                );
                backoff = target.backoff_initial.max(Duration::from_millis(1));
                failure_announced = false;
            }
            Err(SessionError::Fatal(message)) => {
                // Subscription list rejected — config-shaped and validated at
                // load, so this is unreachable in practice; fail loud, once.
                error!(
                    target = %target.name,
                    error = %message,
                    "gNMI dial-out subscription rejected; target disabled until reload"
                );
                return;
            }
            Err(SessionError::Connect(message)) => {
                // Bounded log volume: one warn per outage, debug afterwards.
                if failure_announced {
                    debug!(
                        target = %target.name,
                        error = %message,
                        retry_in_secs = backoff.as_secs_f64(),
                        "gNMI dial-out connect retry failed"
                    );
                } else {
                    warn!(
                        target = %target.name,
                        endpoint = %target.endpoint,
                        error = %message,
                        retry_in_secs = backoff.as_secs_f64(),
                        "gNMI dial-out collector unreachable; retrying with backoff"
                    );
                    failure_announced = true;
                }
            }
        }
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(target.backoff_max.max(target.backoff_initial));
    }
}

enum SessionError {
    /// Connection-level failure (dial, TLS, or stream refusal) — retry.
    Connect(String),
    /// The subscription itself is invalid — do not retry.
    Fatal(String),
}

/// Dial the collector, run one Publish session to completion, and report
/// how it ended. `Ok(())` means the stream was established (the gauge was
/// raised) and later ended; the caller decides reconnect pacing.
async fn publish_session(
    service: &GnmiService,
    metrics: &BgpMetrics,
    target: &DialoutTarget,
) -> Result<(), SessionError> {
    let channel = connect(target).await.map_err(SessionError::Connect)?;
    let mut client = GnmiDialoutClient::new(channel);

    // Fresh subscription per connection: the spawned task ends when the
    // outbound stream (holding the receiver) is dropped, and a reconnecting
    // collector gets a fresh initial snapshot + sync_response — the same
    // resync contract a dial-in reconnect has.
    let rx = service
        .spawn_stream_subscription(&target.subscriptions)
        .map_err(|status| SessionError::Fatal(status.message().to_string()))?;
    let name = target.name.clone();
    let outbound = ReceiverStream::new(rx).map_while(move |item| match item {
        Ok(response) => Some(response),
        Err(status) => {
            // e.g. ON_CHANGE broadcast lag → DataLoss. End the stream so the
            // reconnect path resyncs from a fresh snapshot.
            debug!(
                target = %name,
                error = %status,
                "gNMI dial-out subscription ended; stream will resync on reconnect"
            );
            None
        }
    });
    // A compliant collector may never send a PublishResponse (the proto
    // reserves it for future flow control) and never close its response
    // stream, so the outbound stream ending must itself count as a
    // disconnect. Chain a terminal probe that trips a oneshot when the
    // stream completes — or drops it unfired if the transport tears the
    // stream down early, which resolves the receiver just the same — so
    // the drain loop below can return instead of waiting forever.
    let (ended_tx, mut ended_rx) = tokio::sync::oneshot::channel::<()>();
    let mut ended_tx = Some(ended_tx);
    let outbound = outbound.chain(tokio_stream::iter(std::iter::from_fn(move || {
        if let Some(ended) = ended_tx.take() {
            let _ = ended.send(());
        }
        None::<gnmi::SubscribeResponse>
    })));

    let mut inbound = client
        .publish(outbound)
        .await
        .map_err(|status| SessionError::Connect(status.message().to_string()))?
        .into_inner();

    info!(
        target = %target.name,
        endpoint = %target.endpoint,
        "gNMI dial-out collector connected"
    );
    metrics.set_gnmi_dialout_connected(&target.name, true);

    // Drain the collector's response stream. Nothing is expected on it
    // today (PublishResponse is reserved for future flow control); the
    // disconnect signal is its end or error — or the outbound stream
    // finishing (e.g. a subscription error above), on which returning
    // immediately hands control to the caller's reconnect loop for the
    // fresh-snapshot resync.
    loop {
        tokio::select! {
            _ = &mut ended_rx => {
                debug!(
                    target = %target.name,
                    "gNMI dial-out outbound stream ended; reconnecting to resync"
                );
                return Ok(());
            }
            message = inbound.message() => match message {
                Ok(Some(_flow_control)) => {}
                Ok(None) => return Ok(()),
                Err(status) => {
                    debug!(target = %target.name, error = %status, "gNMI dial-out stream error");
                    return Ok(());
                }
            },
        }
    }
}

/// Establish the (optionally TLS) channel for a target. Key material is
/// read per attempt into a zeroizing buffer and handed to the transport —
/// error strings carry file paths and IO error text only, never contents.
async fn connect(target: &DialoutTarget) -> Result<Channel, String> {
    let mut endpoint = Endpoint::from_shared(target.endpoint.clone())
        .map_err(|e| format!("invalid endpoint {}: {e}", target.endpoint))?
        .connect_timeout(CONNECT_TIMEOUT);
    if let Some(tls) = &target.tls {
        let ca = std::fs::read(&tls.ca_file)
            .map_err(|e| format!("read TLS CA file {}: {e}", tls.ca_file.display()))?;
        let mut config = ClientTlsConfig::new().ca_certificate(Certificate::from_pem(ca));
        if let (Some(cert_file), Some(key_file)) = (&tls.cert_file, &tls.key_file) {
            let cert = std::fs::read(cert_file)
                .map_err(|e| format!("read TLS cert file {}: {e}", cert_file.display()))?;
            let key = Zeroizing::new(
                std::fs::read(key_file)
                    .map_err(|e| format!("read TLS key file {}: {e}", key_file.display()))?,
            );
            config = config.identity(Identity::from_pem(cert, key.as_slice()));
        }
        if let Some(server_name) = &tls.server_name {
            config = config.domain_name(server_name.clone());
        }
        endpoint = endpoint
            .tls_config(config)
            .map_err(|e| format!("TLS config for {}: {e}", target.endpoint))?;
    }
    endpoint
        .connect()
        .await
        .map_err(|e| format!("connect {}: {e}", target.endpoint))
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::pin::Pin;
    use std::time::Duration;

    use tokio::net::TcpListener;
    use tokio::sync::mpsc;
    use tokio_stream::{Stream, wrappers::TcpListenerStream};
    use tonic::{Request, Response, Status, Streaming};

    use super::*;
    use crate::gnmi_dialout_proto::PublishResponse;
    use crate::gnmi_dialout_proto::gnmi_dialout_server::{GnmiDialout, GnmiDialoutServer};
    use crate::test_support::spawn_fake_peer_manager;

    const GLOBAL_AS_PATH: &str = "network-instances/network-instance[name=DEFAULT]/protocols/\
                                  protocol[identifier=BGP][name=BGP]/bgp/global/state/as";
    const SESSION_STATE_PATH: &str = "network-instances/network-instance[name=DEFAULT]/protocols/\
                                      protocol[identifier=BGP][name=BGP]/bgp/neighbors/\
                                      neighbor[neighbor-address=*]/state/session-state";

    // ── parse_path units ──────────────────────────────────────────────

    #[test]
    fn parse_path_parses_names_keys_and_wildcards() {
        let path = parse_path(SESSION_STATE_PATH).expect("valid path");
        assert_eq!(path.elem.len(), 9);
        assert_eq!(path.elem[1].name, "network-instance");
        assert_eq!(path.elem[1].key["name"], "DEFAULT");
        assert_eq!(path.elem[3].key.len(), 2);
        assert_eq!(path.elem[3].key["identifier"], "BGP");
        assert_eq!(path.elem[6].key["neighbor-address"], "*");
        assert_eq!(path.elem[8].name, "session-state");
    }

    #[test]
    fn parse_path_accepts_leading_slash() {
        let bare = parse_path(GLOBAL_AS_PATH).expect("valid");
        let slashed = parse_path(&format!("/{GLOBAL_AS_PATH}")).expect("valid");
        assert_eq!(bare, slashed);
    }

    #[test]
    fn parse_path_rejects_malformed_inputs() {
        for bad in [
            "",
            "/",
            "a//b",
            "a/b[unterminated",
            "a/b]c",
            "a/b[no-equals]",
            "a/b[=v]",
            "a/b[k=v]trailing",
        ] {
            assert!(parse_path(bad).is_err(), "expected error for {bad:?}");
        }
    }

    // ── build_subscription_list units ─────────────────────────────────

    #[test]
    fn build_subscription_list_validates_like_dial_in_subscribe() {
        let ok = build_subscription_list(
            &[GLOBAL_AS_PATH.to_string()],
            DialoutMode::Sample,
            Duration::from_secs(10),
        )
        .expect("valid sample subscription");
        assert_eq!(ok.mode, gnmi::subscription_list::Mode::Stream as i32);
        assert_eq!(ok.subscription.len(), 1);

        build_subscription_list(
            &[SESSION_STATE_PATH.to_string()],
            DialoutMode::OnChange,
            Duration::from_secs(10),
        )
        .expect("session-state supports ON_CHANGE");

        // ON_CHANGE is only supported on the session-state leaf.
        let err = build_subscription_list(
            &[GLOBAL_AS_PATH.to_string()],
            DialoutMode::OnChange,
            Duration::from_secs(10),
        )
        .expect_err("global leaf must reject ON_CHANGE");
        assert!(err.contains("ON_CHANGE"), "unexpected error: {err}");

        // Unsupported / unparseable paths and empty lists fail closed.
        assert!(
            build_subscription_list(
                &["interfaces/interface[name=eth0]/state".to_string()],
                DialoutMode::Sample,
                Duration::from_secs(10),
            )
            .is_err()
        );
        assert!(
            build_subscription_list(&[], DialoutMode::Sample, Duration::from_secs(10)).is_err()
        );
    }

    // ── zero-key-material pin ─────────────────────────────────────────

    #[test]
    fn dialout_debug_never_prints_key_material() {
        let dir = tempfile::tempdir().expect("tempdir");
        let key_path = dir.path().join("client.key");
        let key_material = "-----BEGIN PRIVATE KEY-----\nFAKEKEYMATERIALFAKEKEYMATERIAL\n";
        std::fs::write(&key_path, key_material).expect("write key");

        let target = DialoutTarget {
            name: "collector-a".to_string(),
            endpoint: "https://192.0.2.10:57400".to_string(),
            tls: Some(DialoutTls {
                ca_file: dir.path().join("ca.pem"),
                cert_file: Some(dir.path().join("client.pem")),
                key_file: Some(key_path),
                server_name: Some("collector.example".to_string()),
            }),
            subscriptions: gnmi::SubscriptionList::default(),
            backoff_initial: Duration::from_secs(1),
            backoff_max: Duration::from_secs(30),
        };
        let debug = format!("{target:?}");
        assert!(debug.contains("client.key"), "paths are config, keep them");
        assert!(
            !debug.contains("FAKEKEYMATERIAL") && !debug.contains("PRIVATE KEY"),
            "Debug output must never include key material: {debug}"
        );
    }

    // ── stub collector plumbing ───────────────────────────────────────

    struct StubCollector {
        received: mpsc::Sender<gnmi::SubscribeResponse>,
    }

    #[tonic::async_trait]
    impl GnmiDialout for StubCollector {
        type PublishStream =
            Pin<Box<dyn Stream<Item = Result<PublishResponse, Status>> + Send + 'static>>;

        async fn publish(
            &self,
            request: Request<Streaming<gnmi::SubscribeResponse>>,
        ) -> Result<Response<Self::PublishStream>, Status> {
            let mut inbound = request.into_inner();
            let received = self.received.clone();
            tokio::spawn(async move {
                while let Ok(Some(response)) = inbound.message().await {
                    let _ = received.send(response).await;
                }
            });
            // End the response stream when the test drops its receiver —
            // that is the "collector went away" signal for the client.
            // (Aborting the serve task alone is not enough: hyper detaches
            // per-connection tasks, so a live stream would survive it.)
            let done = self.received.clone();
            let stream = futures::stream::unfold(done, |tx| async move {
                tx.closed().await;
                None::<(Result<PublishResponse, Status>, _)>
            });
            Ok(Response::new(Box::pin(stream)))
        }
    }

    /// Bind (or rebind) a stub collector on `addr` (`None` = ephemeral) and
    /// return its address, the serve task handle, and the received-message
    /// channel.
    async fn spawn_stub_collector(
        addr: Option<SocketAddr>,
    ) -> (
        SocketAddr,
        tokio::task::JoinHandle<()>,
        mpsc::Receiver<gnmi::SubscribeResponse>,
    ) {
        let bind = addr.unwrap_or_else(|| "127.0.0.1:0".parse().expect("valid addr"));
        let listener = TcpListener::bind(bind).await.expect("bind stub collector");
        let addr = listener.local_addr().expect("local addr");
        let (tx, rx) = mpsc::channel(64);
        let handle = tokio::spawn(async move {
            let _ = tonic::transport::Server::builder()
                .add_service(GnmiDialoutServer::new(StubCollector { received: tx }))
                .serve_with_incoming(TcpListenerStream::new(listener))
                .await;
        });
        (addr, handle, rx)
    }

    fn test_service() -> GnmiService {
        let (peer_tx, _session_events, _policy_events) = spawn_fake_peer_manager();
        GnmiService::new(65000, "192.0.2.1".to_string(), peer_tx)
    }

    fn test_target(name: &str, addr: SocketAddr) -> DialoutTarget {
        DialoutTarget {
            name: name.to_string(),
            endpoint: endpoint_uri(&addr.to_string(), false),
            tls: None,
            subscriptions: build_subscription_list(
                &[GLOBAL_AS_PATH.to_string()],
                DialoutMode::Sample,
                Duration::from_secs(10),
            )
            .expect("valid subscription"),
            backoff_initial: Duration::from_millis(100),
            backoff_max: Duration::from_millis(400),
        }
    }

    #[expect(
        clippy::cast_possible_truncation,
        reason = "the connection gauge only ever holds 0 or 1"
    )]
    fn gauge_value(metrics: &BgpMetrics, target: &str) -> Option<i64> {
        metrics
            .registry()
            .gather()
            .iter()
            .find(|family| family.name() == "gnmi_dialout_connected")?
            .get_metric()
            .iter()
            .find(|metric| {
                metric
                    .get_label()
                    .iter()
                    .any(|label| label.name() == "target" && label.value() == target)
            })
            .map(|metric| metric.get_gauge().value() as i64)
    }

    async fn wait_for_gauge(metrics: &BgpMetrics, target: &str, expected: i64) {
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                if gauge_value(metrics, target) == Some(expected) {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .unwrap_or_else(|_| {
            panic!(
                "gauge gnmi_dialout_connected{{target={target}}} never reached {expected} \
                 (last: {:?})",
                gauge_value(metrics, target)
            )
        });
    }

    async fn expect_update_with_as(rx: &mut mpsc::Receiver<gnmi::SubscribeResponse>) {
        let deadline = Duration::from_secs(10);
        loop {
            let response = tokio::time::timeout(deadline, rx.recv())
                .await
                .expect("timed out waiting for a dial-out SubscribeResponse")
                .expect("stub collector channel closed");
            if let Some(gnmi::subscribe_response::Response::Update(notification)) =
                response.response
            {
                let update = &notification.update[0];
                let path = update.path.as_ref().expect("update path");
                assert_eq!(path.elem.last().expect("leaf").name, "as");
                return;
            }
        }
    }

    // A collector that reads the Publish stream but never sends a
    // PublishResponse and never closes its response stream. The proto
    // reserves PublishResponse for future flow control ("collectors need
    // not send anything"), so this is a fully compliant collector — the
    // client must not depend on inbound traffic to notice its own
    // outbound stream ending.
    struct SilentCollector {
        received: mpsc::Sender<gnmi::SubscribeResponse>,
    }

    #[tonic::async_trait]
    impl GnmiDialout for SilentCollector {
        type PublishStream =
            Pin<Box<dyn Stream<Item = Result<PublishResponse, Status>> + Send + 'static>>;

        async fn publish(
            &self,
            request: Request<Streaming<gnmi::SubscribeResponse>>,
        ) -> Result<Response<Self::PublishStream>, Status> {
            let mut inbound = request.into_inner();
            let received = self.received.clone();
            tokio::spawn(async move {
                while let Ok(Some(response)) = inbound.message().await {
                    let _ = received.send(response).await;
                }
            });
            Ok(Response::new(Box::pin(futures::stream::pending())))
        }
    }

    async fn expect_sync(rx: &mut mpsc::Receiver<gnmi::SubscribeResponse>) {
        let deadline = Duration::from_secs(10);
        loop {
            let response = tokio::time::timeout(deadline, rx.recv())
                .await
                .expect("timed out waiting for a dial-out sync_response")
                .expect("stub collector channel closed");
            if let Some(gnmi::subscribe_response::Response::SyncResponse(true)) = response.response
            {
                return;
            }
        }
    }

    // ── integration: dial out, stream, reconnect ──────────────────────

    #[tokio::test(flavor = "multi_thread")]
    async fn dial_out_streams_updates_and_reconnects_after_collector_restart() {
        let metrics = BgpMetrics::new();
        let (addr, server, mut received) = spawn_stub_collector(None).await;
        let mut manager = DialoutManager::new(test_service(), metrics.clone());
        manager.apply(&[test_target("collector-a", addr)]);

        // Initial snapshot arrives and the gauge rises.
        expect_update_with_as(&mut received).await;
        wait_for_gauge(&metrics, "collector-a", 1).await;

        // Kill the collector (stop accepting, then end the live stream):
        // the gauge must drop (disconnect transition).
        server.abort();
        drop(received);
        wait_for_gauge(&metrics, "collector-a", 0).await;

        // Restart the collector on the same address: the client reconnects
        // by itself and streams a fresh initial snapshot.
        let (_addr, server2, mut received2) = spawn_stub_collector(Some(addr)).await;
        expect_update_with_as(&mut received2).await;
        wait_for_gauge(&metrics, "collector-a", 1).await;

        server2.abort();
        manager.apply(&[]);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn subscription_error_reconnects_even_when_collector_stays_silent() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};

        use crate::peer_types::PeerManagerCommand;

        let metrics = BgpMetrics::new();

        // Serve the silent collector: accepts Publish, forwards what it
        // receives, never sends or closes its response stream.
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let (tx, mut received) = mpsc::channel(64);
        let server = tokio::spawn(async move {
            let _ = tonic::transport::Server::builder()
                .add_service(GnmiDialoutServer::new(SilentCollector { received: tx }))
                .serve_with_incoming(TcpListenerStream::new(listener))
                .await;
        });

        // Peer manager that drops the ListPeers reply exactly once on
        // demand: the next sample snapshot then fails with an internal
        // Status, ending the outbound stream mid-session — the same
        // stream-ending error shape as ON_CHANGE broadcast DataLoss.
        let fail_next = Arc::new(AtomicBool::new(false));
        let (peer_tx, mut peer_rx) = mpsc::channel(16);
        let fail = fail_next.clone();
        tokio::spawn(async move {
            while let Some(command) = peer_rx.recv().await {
                if let PeerManagerCommand::ListPeers { reply } = command {
                    if fail.swap(false, Ordering::SeqCst) {
                        drop(reply);
                    } else {
                        let _ = reply.send(Vec::new());
                    }
                }
            }
        });
        let service = GnmiService::new(65000, "192.0.2.1".to_string(), peer_tx);

        // Global + neighbor paths: the snapshot both carries a real leaf
        // update and requires the (failable) peer snapshot.
        let mut target = test_target("collector-silent", addr);
        target.subscriptions = build_subscription_list(
            &[GLOBAL_AS_PATH.to_string(), SESSION_STATE_PATH.to_string()],
            DialoutMode::Sample,
            Duration::from_secs(1),
        )
        .expect("valid subscription");

        let mut manager = DialoutManager::new(service, metrics.clone());
        manager.apply(&[target]);

        // First connection: initial snapshot + sync_response.
        expect_update_with_as(&mut received).await;
        expect_sync(&mut received).await;
        wait_for_gauge(&metrics, "collector-silent", 1).await;

        // Fail the next sample tick. The subscription errors and the
        // outbound stream ends; since the collector stays silent forever,
        // only outbound-end-as-disconnect gets the session torn down. The
        // client must reconnect and resync — a fresh initial snapshot and
        // a SECOND sync_response (sent once per subscription) prove it.
        fail_next.store(true, Ordering::SeqCst);
        expect_update_with_as(&mut received).await;
        expect_sync(&mut received).await;
        wait_for_gauge(&metrics, "collector-silent", 1).await;

        server.abort();
        manager.apply(&[]);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn manager_reaps_gauge_series_on_target_removal() {
        let metrics = BgpMetrics::new();
        let (addr, server, mut received) = spawn_stub_collector(None).await;
        let mut manager = DialoutManager::new(test_service(), metrics.clone());
        manager.apply(&[test_target("collector-reap", addr)]);
        expect_update_with_as(&mut received).await;
        wait_for_gauge(&metrics, "collector-reap", 1).await;

        // Removing the target from config reaps the series entirely —
        // not just sets it to 0 — so /metrics stops exporting it.
        manager.apply(&[]);
        assert_eq!(gauge_value(&metrics, "collector-reap"), None);
        server.abort();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn collector_down_at_startup_keeps_retrying_without_task_exit() {
        let metrics = BgpMetrics::new();
        // Reserve an address with nothing listening on it.
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        drop(listener);

        let mut manager = DialoutManager::new(test_service(), metrics.clone());
        manager.apply(&[test_target("collector-late", addr)]);

        // The series is materialized at 0 while the collector is down.
        wait_for_gauge(&metrics, "collector-late", 0).await;
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(gauge_value(&metrics, "collector-late"), Some(0));

        // The collector comes up later; the retry loop finds it.
        let (_addr, server, mut received) = spawn_stub_collector(Some(addr)).await;
        expect_update_with_as(&mut received).await;
        wait_for_gauge(&metrics, "collector-late", 1).await;
        server.abort();
        manager.apply(&[]);
    }
}
