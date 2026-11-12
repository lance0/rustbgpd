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
//! connection state, established-session loss, bounded response backlog, and
//! last transport handoff as per-target metrics.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError, RwLock};
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
/// Queue-depth sampling stays independent of transport polling, so a collector
/// that stops reading cannot leave the gauge at its last healthy value.
const QUEUE_OBSERVATION_INTERVAL: Duration = Duration::from_millis(250);

/// One configured dial-out collector target, fully resolved from config.
/// `PartialEq` drives the reload diff: an unchanged target keeps its live
/// connection across SIGHUP; any field edit tears down and redials.
#[derive(Debug, Clone, PartialEq)]
pub struct DialoutTarget {
    /// Unique name — the dial-out metric label and log key.
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
    /// from the live session-event stream like dial-in `ON_CHANGE`.
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
    tasks: HashMap<String, (DialoutTarget, tokio::task::JoinHandle<()>, TargetSeries)>,
}

/// One dial-out task's handle on its target's metric series. Removing a target
/// reaps through the same lock, so a write already past the liveness check
/// lands before the reap and any later write is dropped. Aborting the task is
/// not enough: the transport polls the outbound stream, whose per-response
/// writes would otherwise recreate a removed target's series.
#[derive(Clone)]
struct TargetSeries {
    metrics: BgpMetrics,
    target: String,
    live: Arc<RwLock<bool>>,
}

impl TargetSeries {
    fn new(metrics: BgpMetrics, target: &str) -> Self {
        Self {
            metrics,
            target: target.to_string(),
            live: Arc::new(RwLock::new(true)),
        }
    }

    fn write(&self, update: impl FnOnce(&BgpMetrics, &str)) {
        let live = self.live.read().unwrap_or_else(PoisonError::into_inner);
        if *live {
            update(&self.metrics, &self.target);
        }
    }

    fn reap(&self) {
        let mut live = self.live.write().unwrap_or_else(PoisonError::into_inner);
        *live = false;
        self.metrics.remove_gnmi_dialout_target(&self.target);
    }
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
    /// targets (reaping their connection and resync series), restart
    /// changed ones, start added ones, and leave unchanged targets — and
    /// their live collector connections — untouched.
    pub fn apply(&mut self, targets: &[DialoutTarget]) {
        self.tasks.retain(|name, (spec, handle, series)| {
            let keep = targets
                .iter()
                .any(|target| &target.name == name && target == spec);
            if !keep {
                handle.abort();
                series.reap();
                info!(target = %name, "gNMI dial-out target stopped");
            }
            keep
        });
        for target in targets {
            if !self.tasks.contains_key(&target.name) {
                let series = TargetSeries::new(self.metrics.clone(), &target.name);
                let handle = tokio::spawn(run_target(
                    self.service.clone(),
                    series.clone(),
                    target.clone(),
                ));
                self.tasks
                    .insert(target.name.clone(), (target.clone(), handle, series));
            }
        }
    }
}

/// One target's connect / stream / reconnect loop. Never returns under
/// normal operation; the manager aborts it on removal or shutdown.
async fn run_target(service: GnmiService, series: TargetSeries, target: DialoutTarget) {
    // Materialize both target series at 0 immediately so a collector that is
    // down at daemon startup is visible on /metrics before the first success.
    series.write(|metrics, name| metrics.set_gnmi_dialout_connected(name, false));
    let mut backoff = target.backoff_initial.max(Duration::from_millis(1));
    let mut failure_announced = false;
    let mut permission_warnings = Vec::new();
    loop {
        let outcome = publish_session(&service, &series, &target, &mut permission_warnings).await;
        if session_restarts_backoff(&outcome) {
            backoff = target.backoff_initial.max(Duration::from_millis(1));
            failure_announced = false;
        }
        match outcome {
            Ok(()) => {
                // Connected and then cleanly/abruptly disconnected.
                series.write(|metrics, name| {
                    metrics.record_gnmi_dialout_resync(name);
                    metrics.set_gnmi_dialout_connected(name, false);
                });
                warn!(
                    target = %target.name,
                    endpoint = %target.endpoint,
                    "gNMI dial-out collector disconnected; reconnecting"
                );
            }
            Err(SessionError::Ended { status, .. }) => {
                series.write(|metrics, name| {
                    metrics.record_gnmi_dialout_resync(name);
                    metrics.set_gnmi_dialout_connected(name, false);
                });
                // One warn per failure run, debug afterwards.
                if failure_announced {
                    debug!(
                        target = %target.name,
                        code = ?status.code(),
                        error = %status.message(),
                        retry_in_secs = backoff.as_secs_f64(),
                        "gNMI dial-out subscription ended again"
                    );
                } else {
                    warn!(
                        target = %target.name,
                        endpoint = %target.endpoint,
                        code = ?status.code(),
                        error = %status.message(),
                        retry_in_secs = backoff.as_secs_f64(),
                        "gNMI dial-out subscription ended with an error; retrying with backoff"
                    );
                    failure_announced = true;
                }
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

#[derive(Debug)]
enum SessionError {
    /// Connection-level failure (dial, TLS, or stream refusal) — retry.
    Connect(String),
    /// The subscription itself is invalid — do not retry.
    Fatal(String),
    /// Connected, then the subscription ended with an error status (a render
    /// over the update bound, a peer-snapshot outage, `ON_CHANGE` lag) —
    /// retry with backoff. `published` records whether any response reached
    /// the collector first.
    Ended {
        status: tonic::Status,
        published: bool,
    },
}

/// Whether a finished session restarts the reconnect schedule at
/// `backoff_initial`. A session that delivered data was healthy; one refused
/// before any data would otherwise reconnect, handshake and take a roster
/// snapshot every `backoff_initial`.
fn session_restarts_backoff(outcome: &Result<(), SessionError>) -> bool {
    matches!(
        outcome,
        Ok(())
            | Err(SessionError::Ended {
                published: true,
                ..
            })
    )
}

fn subscription_queue_depth(
    probe: &tokio::sync::mpsc::WeakSender<Result<gnmi::SubscribeResponse, tonic::Status>>,
) -> usize {
    probe.upgrade().map_or(0, |sender| {
        sender.max_capacity().saturating_sub(sender.capacity())
    })
}

fn refresh_queue_depth(
    metrics: &BgpMetrics,
    target: &str,
    probe: &tokio::sync::mpsc::WeakSender<Result<gnmi::SubscribeResponse, tonic::Status>>,
) {
    metrics.set_gnmi_dialout_queue_depth(target, subscription_queue_depth(probe));
}

/// Test-only hold on the outbound stream's per-response metric writes, keyed by
/// target so parallel tests never trip it. While armed for a target, the first
/// response poll reports its entry, waits for release, and drops its `entered`
/// sender only after the metric writes, so a test can place a reap between
/// the poll and its writes.
#[cfg(test)]
struct OutboundPollGate {
    target: String,
    entered: std::sync::mpsc::Sender<()>,
    release: std::sync::mpsc::Receiver<()>,
}

#[cfg(test)]
static OUTBOUND_POLL_GATE: std::sync::Mutex<Option<OutboundPollGate>> = std::sync::Mutex::new(None);

/// Hold here if the gate is armed for `target`; the returned sender is the
/// "writes finished" signal and must live until the writes are done.
#[cfg(test)]
fn outbound_poll_gate(target: &str) -> Option<std::sync::mpsc::Sender<()>> {
    let gate = {
        let mut armed = OUTBOUND_POLL_GATE
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if armed.as_ref().is_none_or(|gate| gate.target != target) {
            return None;
        }
        armed.take()?
    };
    let _ = gate.entered.send(());
    let _ = gate.release.recv();
    Some(gate.entered)
}

/// Dial the collector, run one Publish session to completion, and report
/// how it ended. `Ok(())` means the stream was established (the gauge was
/// raised) and later ended; the caller decides reconnect pacing.
async fn publish_session(
    service: &GnmiService,
    series: &TargetSeries,
    target: &DialoutTarget,
    permission_warnings: &mut Vec<String>,
) -> Result<(), SessionError> {
    let channel = connect(target, permission_warnings)
        .await
        .map_err(SessionError::Connect)?;
    let mut client = GnmiDialoutClient::new(channel);

    // Fresh subscription per connection: the spawned task ends when the
    // outbound stream (holding the receiver) is dropped, and a reconnecting
    // collector gets a fresh initial snapshot + sync_response — the same
    // resync contract a dial-in reconnect has.
    let subscription = service
        .spawn_stream_subscription(&target.subscriptions)
        .map_err(|status| SessionError::Fatal(status.message().to_string()))?;
    let queue_probe = subscription.queue_probe;
    let publish_series = series.clone();
    let dequeue_probe = queue_probe.clone();
    // How the subscription ended, read once the outbound stream finishes.
    let published = Arc::new(AtomicBool::new(false));
    let failure = Arc::new(Mutex::new(None::<tonic::Status>));
    let (published_flag, failure_slot) = (Arc::clone(&published), Arc::clone(&failure));
    let outbound = ReceiverStream::new(subscription.responses).map_while(move |item| match item {
        Ok(response) => {
            #[cfg(test)]
            let _writes_done = outbound_poll_gate(&publish_series.target);
            publish_series.write(|metrics, target| {
                refresh_queue_depth(metrics, target, &dequeue_probe);
                metrics.record_gnmi_dialout_publish(target);
            });
            published_flag.store(true, Ordering::Relaxed);
            Some(response)
        }
        Err(status) => {
            publish_series
                .write(|metrics, target| refresh_queue_depth(metrics, target, &dequeue_probe));
            // e.g. ON_CHANGE broadcast lag → DataLoss, or a render over the
            // update bound → RESOURCE_EXHAUSTED. End the stream; the reconnect
            // loop reports the status and backs off.
            *failure_slot.lock().unwrap_or_else(PoisonError::into_inner) = Some(status);
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
    // Re-arm: a permission problem still present on the next outage is
    // reported again.
    permission_warnings.clear();
    series.write(|metrics, name| metrics.set_gnmi_dialout_connected(name, true));

    let mut queue_observation = tokio::time::interval(QUEUE_OBSERVATION_INTERVAL);
    queue_observation.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    // Drain the collector's response stream. Nothing is expected on it
    // today (PublishResponse is reserved for future flow control); the
    // disconnect signal is its end or error — or the outbound stream
    // finishing (e.g. a subscription error above), on which returning
    // immediately hands control to the caller's reconnect loop for the
    // fresh-snapshot resync.
    //
    // Every ending reports a recorded subscription failure. A collector that
    // closes its response stream at request EOF makes the inbound end ready
    // alongside `ended_rx`, and either branch may win.
    let session_end = || match failure
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .take()
    {
        Some(status) => Err(SessionError::Ended {
            status,
            published: published.load(Ordering::Relaxed),
        }),
        None => Ok(()),
    };
    loop {
        tokio::select! {
            _ = queue_observation.tick() => {
                series.write(|metrics, name| refresh_queue_depth(metrics, name, &queue_probe));
            }
            _ = &mut ended_rx => {
                debug!(
                    target = %target.name,
                    "gNMI dial-out outbound stream ended; reconnecting to resync"
                );
                return session_end();
            }
            message = inbound.message() => match message {
                Ok(Some(_flow_control)) => {}
                Ok(None) => return session_end(),
                Err(status) => {
                    debug!(target = %target.name, error = %status, "gNMI dial-out stream error");
                    return session_end();
                }
            },
        }
    }
}

/// Establish the (optionally TLS) channel for a target. Key material is
/// read per attempt into a zeroizing buffer and handed to the transport —
/// error strings carry file paths and IO error text only, never contents.
async fn connect(
    target: &DialoutTarget,
    permission_warnings: &mut Vec<String>,
) -> Result<Channel, String> {
    let mut endpoint = Endpoint::from_shared(target.endpoint.clone())
        .map_err(|e| format!("invalid endpoint {}: {e}", target.endpoint))?
        .connect_timeout(CONNECT_TIMEOUT);
    if let Some(tls) = &target.tls {
        let tls_files = tls.clone();
        let config = tokio::task::spawn_blocking(move || {
            use crate::credential_file::{CredentialKind, DaemonIdentity, read_credential};
            let mut warnings = Vec::new();
            let mut read = |path: &std::path::Path, label, kind| {
                let mut bytes = Zeroizing::new(Vec::new());
                let warning =
                    read_credential(path, label, kind, DaemonIdentity::current(), &mut bytes)?;
                warnings.extend(warning);
                Ok::<_, String>(bytes)
            };
            let ca = read(&tls_files.ca_file, "dial-out CA", CredentialKind::Public)?;
            let mut config =
                ClientTlsConfig::new().ca_certificate(Certificate::from_pem(ca.as_slice()));
            if let (Some(cert_file), Some(key_file)) = (&tls_files.cert_file, &tls_files.key_file) {
                let cert = read(cert_file, "dial-out certificate", CredentialKind::Public)?;
                let key = read(key_file, "dial-out private key", CredentialKind::Secret)?;
                config = config.identity(Identity::from_pem(cert.as_slice(), key.as_slice()));
            }
            Ok::<_, String>((config, warnings))
        })
        .await
        .map_err(|error| format!("TLS credential reader failed: {error}"))??;
        let (mut config, warnings) = config;
        announce_permission_warnings(&target.name, permission_warnings, warnings);
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

/// Log each credential permission warning once per target until the target
/// next connects. A retry that reads the same files stays quiet; a changed
/// mode or owner yields a different message and is logged again.
fn announce_permission_warnings(target: &str, announced: &mut Vec<String>, current: Vec<String>) {
    for warning in &current {
        if !announced.contains(warning) {
            warn!(target = %target, %warning, "gNMI dial-out credential file permissions");
            #[cfg(test)]
            PERMISSION_WARNINGS_LOGGED.with(|count| count.set(count.get() + 1));
        }
    }
    *announced = current;
}

#[cfg(test)]
thread_local! {
    /// Permission warnings logged on this thread, counted instead of
    /// captured from the log because tracing interest is process-wide.
    static PERMISSION_WARNINGS_LOGGED: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::pin::Pin;
    use std::time::Duration;

    use tokio::net::{TcpListener, TcpSocket};
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

    #[tokio::test(flavor = "current_thread")]
    async fn fifo_tls_ca_does_not_stall_runtime() {
        let dir = tempfile::tempdir().unwrap();
        let fifo = dir.path().join("ca");
        nix::unistd::mkfifo(&fifo, nix::sys::stat::Mode::from_bits_truncate(0o600)).unwrap();
        let target = DialoutTarget {
            name: "fifo".into(),
            endpoint: "https://127.0.0.1:1".into(),
            tls: Some(DialoutTls {
                ca_file: fifo.clone(),
                cert_file: None,
                key_file: None,
                server_name: None,
            }),
            subscriptions: gnmi::SubscriptionList::default(),
            backoff_initial: Duration::from_secs(1),
            backoff_max: Duration::from_secs(1),
        };
        // A watchdog releases an old blocking open so the red proof cannot hang the suite.
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let watchdog = std::thread::spawn(move || {
            if done_rx.recv_timeout(Duration::from_secs(2)).is_err() {
                use std::os::unix::fs::OpenOptionsExt as _;
                let _writer = std::fs::OpenOptions::new()
                    .write(true)
                    .custom_flags(nix::fcntl::OFlag::O_NONBLOCK.bits())
                    .open(fifo);
            }
        });
        let started = std::time::Instant::now();
        let attempt = tokio::spawn(async move { connect(&target, &mut Vec::new()).await });
        let (reservation, addr) = reserve_port(None);
        let (server, mut received) = spawn_stub_collector(reservation);
        let mut manager = DialoutManager::new(test_service(), BgpMetrics::new());
        manager.apply(&[test_target("healthy", addr)]);
        expect_update_with_as(&mut received).await;
        let error = attempt.await.unwrap().unwrap_err();
        let elapsed = started.elapsed();
        let _ = done_tx.send(());
        watchdog.join().unwrap();
        manager.apply(&[]);
        server.abort();
        let _ = server.await;
        assert!(
            elapsed < Duration::from_secs(1),
            "runtime stalled for {elapsed:?}"
        );
        assert!(error.contains("not a regular file"), "{error}");
    }

    /// A collector outage with a world-readable key logs the permission
    /// warning on the first attempt only; a changed mode is reported again.
    #[tokio::test(flavor = "current_thread")]
    async fn dialout_permission_warning_logged_once_per_outage() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let file = |name: &str| {
            let path = dir.path().join(name);
            std::fs::write(&path, b"pem\n").unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
            path
        };
        let key = file("key");
        let target = DialoutTarget {
            name: "permissions".into(),
            endpoint: "https://127.0.0.1:1".into(),
            tls: Some(DialoutTls {
                ca_file: file("ca"),
                cert_file: Some(file("cert")),
                key_file: Some(key.clone()),
                server_name: None,
            }),
            subscriptions: gnmi::SubscriptionList::default(),
            backoff_initial: Duration::from_secs(1),
            backoff_max: Duration::from_secs(1),
        };
        let logged = || PERMISSION_WARNINGS_LOGGED.with(std::cell::Cell::get);
        let before = logged();
        let mut announced = Vec::new();
        for _ in 0..2 {
            connect(&target, &mut announced).await.unwrap_err();
        }
        assert_eq!(logged() - before, 1, "{announced:?}");
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o604)).unwrap();
        connect(&target, &mut announced).await.unwrap_err();
        assert_eq!(logged() - before, 2, "{announced:?}");
    }

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

    #[test]
    fn build_subscription_list_uses_dial_in_sample_interval_validation() {
        let paths = [GLOBAL_AS_PATH.to_string()];
        for interval in [
            Duration::from_secs(1),
            Duration::from_secs(10),
            Duration::from_hours(1),
        ] {
            build_subscription_list(&paths, DialoutMode::Sample, interval)
                .expect("an in-range SAMPLE interval must be accepted");
        }

        for (interval, raw_nanos) in [
            (Duration::from_nanos(999_999_999), 999_999_999_u64),
            (Duration::from_nanos(3_600_000_000_001), 3_600_000_000_001),
        ] {
            let err = build_subscription_list(&paths, DialoutMode::Sample, interval).unwrap_err();
            assert_eq!(
                err,
                format!(
                    "gNMI subscription 1 sample_interval {raw_nanos}ns is outside supported range \
                     [1000000000ns, 3600000000000ns]"
                )
            );
        }
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

    /// Hold a loopback port for the lifetime of the test without serving on
    /// it: bind a socket and never `listen` on it.
    ///
    /// Binding `127.0.0.1:0` and dropping the listener to "reserve" the
    /// address reserves nothing — the kernel hands that exact port to the
    /// next binder, and under parallel test execution a rebind of it then
    /// fails `EADDRINUSE` (LAN-941). A bound socket does hold the port, and
    /// while it is not listening the address still refuses connections,
    /// which is the "collector down" condition these tests need.
    ///
    /// `spawn_stub_collector` serves by calling `listen` on this same
    /// socket, so no address is ever bound a second time. Passing `Some`
    /// takes a second reservation of an already-reserved port (hence
    /// `SO_REUSEPORT`), which keeps it held across a collector restart.
    fn reserve_port(addr: Option<SocketAddr>) -> (TcpSocket, SocketAddr) {
        let socket = TcpSocket::new_v4().expect("reservation socket");
        socket.set_reuseport(true).expect("set SO_REUSEPORT");
        socket
            .bind(addr.unwrap_or_else(|| "127.0.0.1:0".parse().expect("valid addr")))
            .expect("bind reservation");
        let addr = socket.local_addr().expect("reservation addr");
        (socket, addr)
    }

    /// Serve a stub collector on a port reserved by [`reserve_port`], and
    /// return the serve task handle plus the received-message channel.
    fn spawn_stub_collector(
        reservation: TcpSocket,
    ) -> (
        tokio::task::JoinHandle<()>,
        mpsc::Receiver<gnmi::SubscribeResponse>,
    ) {
        let listener = reservation.listen(1024).expect("serve stub collector");
        let (tx, rx) = mpsc::channel(64);
        let handle = tokio::spawn(async move {
            let _ = tonic::transport::Server::builder()
                .add_service(GnmiDialoutServer::new(StubCollector { received: tx }))
                .serve_with_incoming(TcpListenerStream::new(listener))
                .await;
        });
        (handle, rx)
    }

    fn test_service() -> GnmiService {
        let (peer_tx, _session_events, _policy_events) = spawn_fake_peer_manager();
        GnmiService::new(
            65000,
            "192.0.2.1".to_string(),
            crate::authz::AuthTier::OperatorOnly,
            peer_tx,
        )
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
        reason = "test-only Prometheus gauges under inspection hold bounded integer values"
    )]
    fn labeled_gauge_value(metrics: &BgpMetrics, family_name: &str, target: &str) -> Option<i64> {
        metrics
            .registry()
            .gather()
            .iter()
            .find(|family| family.name() == family_name)?
            .get_metric()
            .iter()
            .find(|metric| {
                metric
                    .get_label()
                    .iter()
                    .any(|label| label.name() == "target" && label.value() == target)
            })
            .map(|metric| metric.get_gauge().get_value() as i64)
    }

    fn gauge_value(metrics: &BgpMetrics, target: &str) -> Option<i64> {
        labeled_gauge_value(metrics, "gnmi_dialout_connected", target)
    }

    fn queue_depth_value(metrics: &BgpMetrics, target: &str) -> Option<i64> {
        labeled_gauge_value(metrics, "gnmi_dialout_queue_depth", target)
    }

    fn last_publish_value(metrics: &BgpMetrics, target: &str) -> Option<i64> {
        labeled_gauge_value(
            metrics,
            "gnmi_dialout_last_publish_timestamp_seconds",
            target,
        )
    }

    fn counter_value(metrics: &BgpMetrics, target: &str) -> Option<f64> {
        metrics
            .registry()
            .gather()
            .iter()
            .find(|family| family.name() == "gnmi_dialout_resync_total")?
            .get_metric()
            .iter()
            .find(|metric| {
                metric
                    .get_label()
                    .iter()
                    .any(|label| label.name() == "target" && label.value() == target)
            })
            .map(|metric| metric.get_counter().get_value())
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

    async fn wait_for_first_publish(metrics: &BgpMetrics, target: &str) {
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                if last_publish_value(metrics, target).is_some_and(|value| value > 0) {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .unwrap_or_else(|_| {
            panic!(
                "gnmi_dialout_last_publish_timestamp_seconds{{target={target}}} remained {:?}",
                last_publish_value(metrics, target)
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

    #[test]
    fn only_a_session_that_delivered_data_restarts_backoff() {
        let ended = |published| {
            Err(SessionError::Ended {
                status: Status::resource_exhausted("over the render bound"),
                published,
            })
        };
        assert!(session_restarts_backoff(&Ok(())));
        assert!(session_restarts_backoff(&ended(true)));
        assert!(!session_restarts_backoff(&ended(false)));
        assert!(!session_restarts_backoff(&Err(SessionError::Connect(
            "refused".into()
        ))));
    }

    /// A service whose roster puts a full-state all-neighbors subscription
    /// over the render bound, and a target subscribing to exactly that.
    fn over_bound_service_and_target(addr: SocketAddr) -> (GnmiService, DialoutTarget) {
        let roster = (0..6_554_u32)
            .map(|index| {
                crate::test_support::peer_info(std::net::IpAddr::from(std::net::Ipv4Addr::from(
                    0x0a00_0000 + index,
                )))
            })
            .collect::<Vec<_>>();
        let service = GnmiService::with_peer_snapshot(65000, "192.0.2.1", move || {
            let peers = roster.clone();
            async move { Ok(peers) }
        });
        let mut target = test_target("collector-over-bound", addr);
        target.subscriptions = build_subscription_list(
            &[
                "network-instances/network-instance[name=DEFAULT]/protocols/\
               protocol[identifier=BGP][name=BGP]/bgp/neighbors"
                    .to_string(),
            ],
            DialoutMode::Sample,
            Duration::from_secs(10),
        )
        .expect("valid subscription");
        (service, target)
    }

    #[tokio::test]
    async fn over_bound_subscription_ends_the_session_as_a_failure() {
        // Load-bearing break: reporting the refused stream as a clean
        // disconnect (`Ok`) restarts backoff, so the target reconnects,
        // handshakes and snapshots the roster every `backoff_initial`.
        let (reservation, addr) = reserve_port(None);
        let (_server, mut received) = spawn_stub_collector(reservation);
        let (service, target) = over_bound_service_and_target(addr);
        let series = TargetSeries::new(BgpMetrics::new(), &target.name);

        let outcome = tokio::time::timeout(
            Duration::from_secs(10),
            publish_session(&service, &series, &target, &mut Vec::new()),
        )
        .await
        .expect("refused session ends");
        let Err(SessionError::Ended { status, published }) = &outcome else {
            panic!("expected a failed subscription, got {outcome:?}");
        };
        assert_eq!(status.code(), tonic::Code::ResourceExhausted);
        assert!(!published);
        assert!(!session_restarts_backoff(&outcome));
        assert!(received.try_recv().is_err());
    }

    /// Closes its response stream once the client's request stream ends,
    /// and reports when it accepted a session and when it closed.
    struct EofClosingCollector {
        events: mpsc::Sender<&'static str>,
    }

    #[tonic::async_trait]
    impl GnmiDialout for EofClosingCollector {
        type PublishStream =
            Pin<Box<dyn Stream<Item = Result<PublishResponse, Status>> + Send + 'static>>;

        async fn publish(
            &self,
            request: Request<Streaming<gnmi::SubscribeResponse>>,
        ) -> Result<Response<Self::PublishStream>, Status> {
            let inbound = request.into_inner();
            let events = self.events.clone();
            let _ = events.send("accepted").await;
            let stream = futures::stream::unfold(Some((inbound, events)), |state| async move {
                let (mut inbound, events) = state?;
                while let Ok(Some(_)) = inbound.message().await {}
                let _ = events.send("closed").await;
                None::<(Result<PublishResponse, Status>, _)>
            });
            Ok(Response::new(Box::pin(stream)))
        }
    }

    #[tokio::test]
    async fn refusal_is_a_failure_when_the_collector_closes_at_request_eof() {
        // Load-bearing break: ending the session `Ok` when the collector's
        // close wins the race against `ended_rx` restarts backoff and drops
        // the warning. Each round leaves the session unpolled until both
        // endings are ready, so `select!` picks between them at random; with
        // the break, sixteen rounds all pass with probability 2^-16.
        let (reservation, addr) = reserve_port(None);
        let listener = reservation.listen(1024).expect("serve collector");
        let (events_tx, mut events) = mpsc::channel(4);
        let _server = tokio::spawn(async move {
            let _ = tonic::transport::Server::builder()
                .add_service(GnmiDialoutServer::new(EofClosingCollector {
                    events: events_tx,
                }))
                .serve_with_incoming(TcpListenerStream::new(listener))
                .await;
        });
        let (service, target) = over_bound_service_and_target(addr);

        for _ in 0..16 {
            let series = TargetSeries::new(BgpMetrics::new(), &target.name);
            let mut warnings = Vec::new();
            let mut session =
                std::pin::pin!(publish_session(&service, &series, &target, &mut warnings));
            tokio::select! {
                outcome = &mut session => panic!("session ended before it was accepted: {outcome:?}"),
                event = events.recv() => assert_eq!(event, Some("accepted")),
            }
            // The refusal, the request EOF and the collector's close all run in
            // other tasks; the session is not polled until they are done.
            let closed = tokio::time::timeout(Duration::from_secs(10), events.recv()).await;
            assert_eq!(closed.expect("collector closes"), Some("closed"));
            tokio::time::sleep(Duration::from_millis(50)).await;
            let outcome = tokio::time::timeout(Duration::from_secs(10), session)
                .await
                .expect("refused session ends");
            assert!(
                matches!(
                    &outcome,
                    Err(SessionError::Ended {
                        published: false,
                        ..
                    })
                ),
                "expected a failed subscription, got {outcome:?}"
            );
        }
    }

    #[tokio::test]
    async fn queue_probe_tracks_bounded_subscription_backlog() {
        let metrics = BgpMetrics::new();
        metrics.set_gnmi_dialout_connected("collector-queue", false);
        let (tx, mut rx) = mpsc::channel(2);
        let probe = tx.downgrade();

        refresh_queue_depth(&metrics, "collector-queue", &probe);
        assert_eq!(queue_depth_value(&metrics, "collector-queue"), Some(0));

        tx.send(Ok(gnmi::SubscribeResponse::default()))
            .await
            .unwrap();
        tx.send(Ok(gnmi::SubscribeResponse::default()))
            .await
            .unwrap();
        refresh_queue_depth(&metrics, "collector-queue", &probe);
        assert_eq!(queue_depth_value(&metrics, "collector-queue"), Some(2));

        let _ = rx.recv().await;
        refresh_queue_depth(&metrics, "collector-queue", &probe);
        assert_eq!(queue_depth_value(&metrics, "collector-queue"), Some(1));

        drop(tx);
        let _ = rx.recv().await;
        refresh_queue_depth(&metrics, "collector-queue", &probe);
        assert_eq!(queue_depth_value(&metrics, "collector-queue"), Some(0));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn dial_out_streams_updates_and_reconnects_after_collector_restart() {
        let metrics = BgpMetrics::new();
        let (first, addr) = reserve_port(None);
        // Second reservation of the same port: it stays held while the
        // collector is down, so the restart below never rebinds.
        let (restart, _) = reserve_port(Some(addr));
        let (server, mut received) = spawn_stub_collector(first);
        let mut manager = DialoutManager::new(test_service(), metrics.clone());
        manager.apply(&[test_target("collector-a", addr)]);

        // Initial snapshot arrives and the gauge rises.
        expect_update_with_as(&mut received).await;
        expect_sync(&mut received).await;
        wait_for_gauge(&metrics, "collector-a", 1).await;
        wait_for_first_publish(&metrics, "collector-a").await;
        assert_eq!(queue_depth_value(&metrics, "collector-a"), Some(0));

        // Kill the collector (stop accepting, then end the live stream):
        // the gauge must drop (disconnect transition). Await the aborted
        // task so its listener is really closed before the restart takes
        // the port over — both sockets are in the same `SO_REUSEPORT`
        // group, and a listening corpse would keep drawing connections.
        server.abort();
        let _ = server.await;
        drop(received);
        wait_for_gauge(&metrics, "collector-a", 0).await;

        // Restart the collector on the same address: the client reconnects
        // by itself and streams a fresh initial snapshot.
        let (server2, mut received2) = spawn_stub_collector(restart);
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
        // demand: the next sample snapshot then fails with `UNAVAILABLE`
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
        let service = GnmiService::new(
            65000,
            "192.0.2.1".to_string(),
            crate::authz::AuthTier::OperatorOnly,
            peer_tx,
        );

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
        assert_eq!(counter_value(&metrics, "collector-silent"), Some(0.0));

        // Fail the next sample tick. The subscription errors and the
        // outbound stream ends; since the collector stays silent forever,
        // only outbound-end-as-disconnect gets the session torn down. The
        // client must reconnect and resync — a fresh initial snapshot and
        // a SECOND sync_response (sent once per subscription) prove it.
        fail_next.store(true, Ordering::SeqCst);
        expect_update_with_as(&mut received).await;
        expect_sync(&mut received).await;
        wait_for_gauge(&metrics, "collector-silent", 1).await;
        assert_eq!(counter_value(&metrics, "collector-silent"), Some(1.0));

        server.abort();
        manager.apply(&[]);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn manager_reaps_target_series_on_target_removal() {
        let metrics = BgpMetrics::new();
        let (reservation, addr) = reserve_port(None);
        let (server, mut received) = spawn_stub_collector(reservation);
        let mut manager = DialoutManager::new(test_service(), metrics.clone());
        manager.apply(&[test_target("collector-reap", addr)]);
        expect_update_with_as(&mut received).await;
        wait_for_gauge(&metrics, "collector-reap", 1).await;
        assert_eq!(counter_value(&metrics, "collector-reap"), Some(0.0));

        // Removing the target from config reaps both series entirely rather
        // than retaining stale per-target labels in /metrics.
        manager.apply(&[]);
        assert_eq!(gauge_value(&metrics, "collector-reap"), None);
        assert_eq!(counter_value(&metrics, "collector-reap"), None);
        assert_eq!(queue_depth_value(&metrics, "collector-reap"), None);
        assert_eq!(last_publish_value(&metrics, "collector-reap"), None);
        server.abort();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn removal_reap_is_final_across_an_in_flight_outbound_poll() {
        // Load-bearing break: without the reap retiring the task's metric
        // writes, the transport's outbound poll held across `apply(&[])`
        // recreates the removed target's queue-depth series.
        const TARGET: &str = "collector-reap-race";
        let metrics = BgpMetrics::new();
        let (reservation, addr) = reserve_port(None);
        let (server, _received) = spawn_stub_collector(reservation);
        let (entered_tx, entered_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        *OUTBOUND_POLL_GATE
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(OutboundPollGate {
            target: TARGET.to_string(),
            entered: entered_tx,
            release: release_rx,
        });
        let mut manager = DialoutManager::new(test_service(), metrics.clone());
        manager.apply(&[test_target(TARGET, addr)]);

        let entered_rx = tokio::task::spawn_blocking(move || {
            entered_rx
                .recv_timeout(Duration::from_secs(30))
                .expect("outbound poll never reached the gate");
            entered_rx
        })
        .await
        .unwrap();
        manager.apply(&[]);
        release_tx.send(()).unwrap();
        let finished =
            tokio::task::spawn_blocking(move || entered_rx.recv_timeout(Duration::from_secs(30)))
                .await
                .unwrap();
        assert_eq!(
            finished,
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected),
            "gated outbound poll never finished its metric writes"
        );

        assert_eq!(gauge_value(&metrics, TARGET), None);
        assert_eq!(counter_value(&metrics, TARGET), None);
        assert_eq!(queue_depth_value(&metrics, TARGET), None);
        assert_eq!(last_publish_value(&metrics, TARGET), None);
        server.abort();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn collector_down_at_startup_keeps_retrying_without_task_exit() {
        let metrics = BgpMetrics::new();
        // An address held by a bound socket that never listens: nothing
        // serves it, so connections are refused, and nothing else can take
        // the port before the collector comes up on it below.
        let (reservation, addr) = reserve_port(None);

        let mut manager = DialoutManager::new(test_service(), metrics.clone());
        manager.apply(&[test_target("collector-late", addr)]);

        // The series is materialized at 0 while the collector is down.
        wait_for_gauge(&metrics, "collector-late", 0).await;
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(gauge_value(&metrics, "collector-late"), Some(0));
        assert_eq!(counter_value(&metrics, "collector-late"), Some(0.0));
        assert_eq!(queue_depth_value(&metrics, "collector-late"), Some(0));
        assert_eq!(last_publish_value(&metrics, "collector-late"), Some(0));

        // The collector comes up later; the retry loop finds it.
        let (server, mut received) = spawn_stub_collector(reservation);
        expect_update_with_as(&mut received).await;
        wait_for_gauge(&metrics, "collector-late", 1).await;
        server.abort();
        manager.apply(&[]);
    }
}
